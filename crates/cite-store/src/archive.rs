use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::PoisonError;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cite_edge::model::LogEvent;
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use rusqlite::backup::{Backup, StepResult};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::limits::{DAY_MS, HOUR_MS};
use crate::queries::{self, Where, int};
use crate::retention::PruneReport;
use crate::store::Inner;

mod scrub;

pub use scrub::ArchiveScrub;

const PAGE: usize = 5000;
const MAX_NAME: usize = 120;
const MAX_LISTED: usize = 10_000;
const MAX_SEQ: u32 = 1000;
const TMP_SUFFIX: &str = ".tmp";
const MANIFEST_SUFFIX: &str = ".manifest.json";
const RESTORED_SUFFIX: &str = ".restored.json";
const ARCHIVE_PREFIX: &str = "requests-";
const ARCHIVE_EXT: &str = ".ndjson.gz";
const BACKUP_PREFIX: &str = "backup-";
const BACKUP_EXT: &str = ".db";
const BACKUP_ATTEMPTS: u32 = 600;
const BACKUP_RETRY: Duration = Duration::from_millis(100);
const HASH_BUF: usize = 64 * 1024;
// A real event is a few kilobytes; anything near this size is damage or an attack, not data.
const MAX_LINE: usize = 1 << 20;
// Decompressed bytes accepted from one archive, so a small file cannot expand without bound.
const MAX_DECODED: u64 = 32 << 30;
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// One archive or backup file with the manifest entry that vouches for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveItem {
    pub name: String,
    /// "archive" or "backup".
    pub kind: String,
    pub bytes: u64,
    pub created_ms: i64,
    pub sha256: String,
    pub rows: u64,
    /// Timestamps of the oldest and newest request in the file; null for an empty backup.
    pub from_ms: Option<i64>,
    pub to_ms: Option<i64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ArchiveList {
    pub items: Vec<ArchiveItem>,
    /// Everything in the archive directory, manifests included.
    pub dir_bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CutReport {
    pub dry_run: bool,
    pub cutoff_ms: i64,
    /// Raw rows older than the cutoff when the call started.
    pub rows: u64,
    pub oldest_ms: Option<i64>,
    pub archived_rows: u64,
    /// Names of the archive files written, oldest day first.
    pub files: Vec<String>,
    /// Whether the cut keeps a verified copy first.
    pub archive: bool,
}

/// Progress of one archive-then-delete run; done_to is the end of the last finished segment.
#[derive(Debug, Default)]
pub(crate) struct Cut {
    pub(crate) deleted: u64,
    pub(crate) archived: u64,
    pub(crate) files: Vec<String>,
    pub(crate) done_to: Option<i64>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Kind {
    Archive,
    Backup,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Archive => "archive",
            Kind::Backup => "backup",
        }
    }

    fn prefix(self) -> &'static str {
        match self {
            Kind::Archive => ARCHIVE_PREFIX,
            Kind::Backup => BACKUP_PREFIX,
        }
    }

    fn ext(self) -> &'static str {
        match self {
            Kind::Archive => ARCHIVE_EXT,
            Kind::Backup => BACKUP_EXT,
        }
    }
}

/// Accepts only names this module generates: plain characters, a known prefix and extension, no separators or dots that climb.
pub(crate) fn parse_name(name: &str) -> Result<Kind> {
    let plain = name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    if name.is_empty() || name.len() > MAX_NAME || !plain || name.contains("..") {
        return Err(Error::Rejected("invalid archive name".into()));
    }
    [Kind::Archive, Kind::Backup]
        .into_iter()
        .find(|k| name.starts_with(k.prefix()) && name.ends_with(k.ext()))
        .ok_or_else(|| Error::Rejected("invalid archive name".into()))
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[usize::from(b >> 4)] as char);
        out.push(DIGITS[usize::from(b & 0xf)] as char);
    }
    out
}

#[cfg(unix)]
fn make_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    DirBuilder::new().recursive(true).mode(0o700).create(dir)
}

#[cfg(not(unix))]
fn make_dir(dir: &Path) -> io::Result<()> {
    DirBuilder::new().recursive(true).create(dir)
}

#[cfg(unix)]
fn create_private(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_private(path: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

// A rename or create is only durable once the directory entry itself reaches the disk.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

fn exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

// Unique per call, so a stale file or a concurrent writer can never share a temp path.
fn unique_tmp(dir: &Path, name: &str) -> PathBuf {
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    dir.join(format!("{name}.{}.{seq}{TMP_SUFFIX}", std::process::id()))
}

fn marker_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}{RESTORED_SUFFIX}"))
}

fn manifest_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}{MANIFEST_SUFFIX}"))
}

// Never reuses a name: a second archive of the same day (late rows) must not overwrite the first.
fn free_name(dir: &Path, stem: &str, kind: Kind) -> Result<String> {
    for n in 1..=MAX_SEQ {
        let name = if n == 1 {
            format!("{stem}{}", kind.ext())
        } else {
            format!("{stem}-{n}{}", kind.ext())
        };
        if !exists(&dir.join(&name)) && !exists(&manifest_path(dir, &name)) {
            return Ok(name);
        }
    }
    Err(Error::Archive(format!(
        "too many files already named {stem}"
    )))
}

struct HashingWriter<W: Write> {
    inner: W,
    hasher: Sha256,
    bytes: u64,
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.bytes += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn handle_sha256(file: &mut impl Read) -> io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_BUF];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            return Ok(hex(&hasher.finalize()));
        }
        hasher.update(&buf[..n]);
    }
}

fn file_sha256(path: &Path) -> io::Result<String> {
    handle_sha256(&mut File::open(path)?)
}

// Decodes every line as an event, so a truncated or damaged file fails here rather than half-way through a restore.
fn read_events(src: impl Read, each: impl FnMut(LogEvent) -> Result<()>) -> Result<u64> {
    read_events_capped(src, MAX_LINE, MAX_DECODED, each)
}

// Reads lines through a take() so an endless line is cut off at max_line instead of being buffered whole.
pub(crate) fn read_events_capped(
    src: impl Read,
    max_line: usize,
    max_total: u64,
    mut each: impl FnMut(LogEvent) -> Result<()>,
) -> Result<u64> {
    let mut reader = BufReader::new(GzDecoder::new(BufReader::new(src)));
    let (mut count, mut total) = (0u64, 0u64);
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = (&mut reader)
            .take(max_line as u64 + 1)
            .read_until(b'\n', &mut line)?;
        if n == 0 {
            return Ok(count);
        }
        if n > max_line {
            return Err(Error::Archive(format!(
                "a line is longer than the {max_line} byte limit"
            )));
        }
        total += n as u64;
        if total > max_total {
            return Err(Error::Archive(format!(
                "the decompressed data is larger than the {max_total} byte limit"
            )));
        }
        let body = line.strip_suffix(b"\n").unwrap_or(&line);
        if body.is_empty() {
            continue;
        }
        each(serde_json::from_slice::<LogEvent>(body)?)?;
        count += 1;
    }
}

fn verify_archive(path: &Path, sha256: &str, rows: u64) -> Result<()> {
    let mut file =
        File::open(path).map_err(|e| Error::Archive(format!("verification failed: {e}")))?;
    verify_handle(&mut file, sha256, rows)
}

// Checks the open handle itself, so the bytes imported afterwards are the bytes that were verified.
fn verify_handle(file: &mut File, sha256: &str, rows: u64) -> Result<()> {
    let fail = |what: String| Error::Archive(format!("verification failed: {what}"));
    let got = handle_sha256(file).map_err(|e| fail(e.to_string()))?;
    if got != sha256 {
        return Err(fail("checksum does not match".into()));
    }
    file.rewind().map_err(|e| fail(e.to_string()))?;
    let counted = read_events(&mut *file, |_| Ok(())).map_err(|e| fail(e.to_string()))?;
    if counted != rows {
        return Err(fail(format!("{counted} rows read back, expected {rows}")));
    }
    Ok(())
}

// Atomic by temp file and rename, so a reader sees the old file or the whole new one.
fn write_atomic(dir: &Path, file_name: &str, bytes: &[u8]) -> Result<()> {
    let path = dir.join(file_name);
    let tmp = unique_tmp(dir, file_name);
    let outcome = (|| -> Result<()> {
        let mut file = create_private(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&tmp, &path)?;
        Ok(())
    })();
    if outcome.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    outcome
}

// The manifest is what makes a file listable, so it is written last and atomically.
fn write_manifest(dir: &Path, item: &ArchiveItem) -> Result<()> {
    write_atomic(
        dir,
        &format!("{}{MANIFEST_SUFFIX}", item.name),
        &serde_json::to_vec(item)?,
    )
}

/// Durable record that an archive was imported; restoring the same bytes again would duplicate its rows.
#[derive(Debug, Serialize, Deserialize)]
struct Restored {
    sha256: String,
    restored_ms: i64,
    rows: u64,
}

fn read_marker(dir: &Path, name: &str) -> Result<Option<Restored>> {
    match fs::read(marker_path(dir, name)) {
        Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|_| {
            Error::Archive(format!(
                "the restore marker of {name} is unreadable; restore with again set to override it"
            ))
        }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn write_marker(dir: &Path, name: &str, marker: &Restored) -> Result<()> {
    write_atomic(
        dir,
        &format!("{name}{RESTORED_SUFFIX}"),
        &serde_json::to_vec(marker)?,
    )?;
    sync_dir(dir)?;
    Ok(())
}

struct Written {
    rows: u64,
    sha256: String,
    bytes: u64,
    first_ms: Option<i64>,
    last_ms: Option<i64>,
}

type Encoder = GzEncoder<HashingWriter<BufWriter<File>>>;

// Finishes the gzip stream and syncs the file; returns the checksum and size of what reached the disk.
fn seal(enc: Encoder) -> Result<(String, u64)> {
    let HashingWriter {
        inner,
        hasher,
        bytes,
    } = enc.finish()?;
    let file = inner.into_inner().map_err(io::IntoInnerError::into_error)?;
    file.sync_all()?;
    Ok((hex(&hasher.finalize()), bytes))
}

struct Segment {
    item: ArchiveItem,
    max_id: i64,
}

impl Inner {
    fn archive_dir_required(&self) -> Result<&Path> {
        self.archive_dir
            .as_deref()
            .ok_or_else(|| Error::Rejected("no archive directory is configured".into()))
    }

    // Writes and verifies one day (or the part of it before a manual cutoff). Returns None when the range holds no rows.
    fn archive_segment(&self, dir: &Path, from: i64, to: i64) -> Result<Option<Segment>> {
        let (rows, max_id): (i64, Option<i64>) = self.read(|c| {
            Ok(c.query_row(
                "SELECT count(*), max(id) FROM requests WHERE ts >= ?1 AND ts < ?2",
                params![from, to],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?)
        })?;
        let Some(max_id) = max_id.filter(|_| rows > 0) else {
            return Ok(None);
        };
        make_dir(dir)?;
        let stem = format!("{ARCHIVE_PREFIX}{from:013}-{to:013}");
        let name = free_name(dir, &stem, Kind::Archive)?;
        let tmp = unique_tmp(dir, &name);
        let written = match self.write_rows(&tmp, from, to, max_id) {
            Ok(w) => w,
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                return Err(e);
            }
        };
        if i64::try_from(written.rows).ok() != Some(rows) {
            let _ = fs::remove_file(&tmp);
            return Err(Error::Archive(
                "rows changed while the day was being archived".into(),
            ));
        }
        let item = ArchiveItem {
            name: name.clone(),
            kind: Kind::Archive.label().into(),
            bytes: written.bytes,
            created_ms: now_ms(),
            sha256: written.sha256,
            rows: written.rows,
            from_ms: written.first_ms,
            to_ms: written.last_ms,
        };
        publish(dir, &tmp, &item)?;
        Ok(Some(Segment { item, max_id }))
    }

    // Streams the segment through gzip into tmp, syncs it and reads it back before reporting success.
    fn write_rows(&self, tmp: &Path, from: i64, to: i64, max_id: i64) -> Result<Written> {
        let file = create_private(tmp)?;
        let sink = HashingWriter {
            inner: BufWriter::new(file),
            hasher: Sha256::new(),
            bytes: 0,
        };
        let mut enc: Encoder = GzEncoder::new(sink, Compression::default());
        let (mut rows, mut first_ms, mut last_ms) = (0u64, None, None);
        let mut after = None;
        loop {
            let mut w = Where::default();
            w.and("ts >= ?", [int(from)])
                .and("ts < ?", [int(to)])
                .and("r.id <= ?", [int(max_id)]);
            let page = self.read_long(|c| queries::fetch_events(c, &w, false, PAGE, after))?;
            for (_, ev) in &page {
                serde_json::to_writer(&mut enc, ev)?;
                enc.write_all(b"\n")?;
                first_ms.get_or_insert(ev.ts_ms);
                last_ms = Some(ev.ts_ms);
                rows += 1;
            }
            match page.last() {
                Some((id, ev)) if page.len() == PAGE => after = Some((ev.ts_ms, *id)),
                _ => break,
            }
        }
        let (sha256, bytes) = seal(enc)?;
        self.inject_fault(tmp, bytes)?;
        verify_archive(tmp, &sha256, rows)?;
        Ok(Written {
            rows,
            sha256,
            bytes,
            first_ms,
            last_ms,
        })
    }

    #[cfg(test)]
    fn inject_fault(&self, tmp: &Path, bytes: u64) -> Result<()> {
        use std::sync::atomic::Ordering;
        if self.archive_fault.load(Ordering::Relaxed) {
            OpenOptions::new()
                .write(true)
                .open(tmp)?
                .set_len(bytes.saturating_sub(8))?;
        }
        Ok(())
    }

    #[cfg(not(test))]
    fn inject_fault(&self, _tmp: &Path, _bytes: u64) -> Result<()> {
        Ok(())
    }

    // Archives and then deletes every day of rows older than cutoff, oldest first. The first failure stops the run, so no row is ever deleted without a verified copy.
    pub(crate) fn archive_and_delete(&self, dir: &Path, cutoff: i64, cut: &mut Cut) -> Result<()> {
        let mut cursor = i64::MIN;
        loop {
            let first: Option<i64> = self.read(|c| {
                Ok(c.query_row(
                    "SELECT min(ts) FROM requests WHERE ts >= ?1 AND ts < ?2",
                    params![cursor, cutoff],
                    |r| r.get(0),
                )?)
            })?;
            let Some(first) = first else { break };
            let from = first.div_euclid(DAY_MS) * DAY_MS;
            let to = from.saturating_add(DAY_MS).min(cutoff);
            if let Some(seg) = self.archive_segment(dir, from, to)? {
                cut.archived += seg.item.rows;
                cut.files.push(seg.item.name.clone());
                cut.deleted += self.delete_segment(from, to, seg.max_id)?;
            }
            cursor = to;
            cut.done_to = Some(to);
        }
        cut.done_to = Some(cutoff);
        Ok(())
    }

    pub(crate) fn cut_before(
        &self,
        cutoff_ms: i64,
        archive: bool,
        dry_run: bool,
    ) -> Result<CutReport> {
        // Rollups are hourly, so a cutoff inside an hour would delete raw rows whose rollup stays and a restore would count that hour twice.
        let cutoff_ms = cutoff_ms.div_euclid(HOUR_MS) * HOUR_MS;
        let dir = if archive {
            Some(self.archive_dir_required()?)
        } else {
            None
        };
        let _turn = self
            .maintenance
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (rows, oldest_ms): (i64, Option<i64>) = self.read(|c| {
            Ok(c.query_row(
                "SELECT count(*), min(ts) FROM requests WHERE ts < ?1",
                params![cutoff_ms],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?)
        })?;
        let mut report = CutReport {
            dry_run,
            cutoff_ms,
            rows: u64::try_from(rows).unwrap_or(0),
            oldest_ms,
            archive,
            ..CutReport::default()
        };
        if dry_run || rows == 0 {
            return Ok(report);
        }
        let mut done = PruneReport::default();
        let outcome = match dir {
            Some(dir) => {
                let mut cut = Cut::default();
                let outcome = self.archive_and_delete(dir, cutoff_ms, &mut cut);
                done.expired_rows = cut.deleted;
                report.archived_rows = cut.archived;
                report.files = cut.files;
                if let Some(to) = cut.done_to {
                    self.expire_rollups(to, &mut done)?;
                }
                outcome
            }
            None => self.expire(cutoff_ms, &mut done),
        };
        self.settle(!done.is_empty(), &mut done)?;
        outcome?;
        Ok(report)
    }

    pub(crate) fn backup(&self) -> Result<ArchiveItem> {
        let dir = self.archive_dir_required()?;
        let _turn = self
            .maintenance
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        make_dir(dir)?;
        let created_ms = now_ms();
        let name = free_name(
            dir,
            &format!("{BACKUP_PREFIX}{created_ms:013}"),
            Kind::Backup,
        )?;
        let tmp = unique_tmp(dir, &name);
        let outcome = self.copy_database(dir, &tmp, &name, created_ms);
        if outcome.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        outcome
    }

    // A single step copies the whole database under one read snapshot, so ingest running meanwhile cannot tear the copy.
    fn copy_database(
        &self,
        dir: &Path,
        tmp: &Path,
        name: &str,
        created_ms: i64,
    ) -> Result<ArchiveItem> {
        drop(create_private(tmp)?);
        let mut dst = Connection::open(tmp)?;
        self.read_long(|src| {
            let backup = Backup::new(src, &mut dst)?;
            for _ in 0..BACKUP_ATTEMPTS {
                if matches!(backup.step(-1)?, StepResult::Done) {
                    return Ok(());
                }
                thread::sleep(BACKUP_RETRY);
            }
            Err(Error::Incomplete(
                "the database stayed busy, so the backup was abandoned".into(),
            ))
        })?;
        // The copy keeps the source's WAL mode; switching it back leaves one self-contained file.
        dst.execute_batch("PRAGMA journal_mode = DELETE")?;
        let base = ArchiveItem {
            name: name.to_string(),
            kind: Kind::Backup.label().into(),
            bytes: 0,
            created_ms,
            sha256: String::new(),
            rows: 0,
            from_ms: None,
            to_ms: None,
        };
        let item = seal_backup(dst, tmp, base)?;
        publish(dir, tmp, &item)?;
        Ok(item)
    }

    fn resolve(&self, name: &str) -> Result<(Kind, &Path, PathBuf)> {
        let kind = parse_name(name)?;
        let dir = self.archive_dir_required()?;
        let path = dir.join(name);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_file() => Ok((kind, dir, path)),
            Ok(_) => Err(Error::Rejected("not a regular file".into())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                Err(Error::NotFound(format!("archive {name}")))
            }
            Err(e) => Err(e.into()),
        }
    }

    fn read_item(&self, dir: &Path, name: &str, kind: Kind) -> Result<ArchiveItem> {
        let bytes = fs::read(manifest_path(dir, name)).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                Error::Archive(format!("{name} has no manifest entry"))
            } else {
                e.into()
            }
        })?;
        let mut item: ArchiveItem = serde_json::from_slice(&bytes)?;
        if item.name != name || item.kind != kind.label() {
            return Err(Error::Archive(format!(
                "manifest entry of {name} does not match it"
            )));
        }
        item.bytes = fs::metadata(dir.join(name))?.len();
        Ok(item)
    }

    pub(crate) fn list_archives(&self) -> Result<ArchiveList> {
        let dir = self.archive_dir_required()?;
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(ArchiveList::default()),
            Err(e) => return Err(e.into()),
        };
        let mut list = ArchiveList::default();
        for entry in entries {
            let entry = entry?;
            let meta = entry.metadata()?;
            if !meta.is_file() {
                continue;
            }
            list.dir_bytes += meta.len();
            let file_name = entry.file_name();
            let Some(name) = file_name
                .to_str()
                .and_then(|n| n.strip_suffix(MANIFEST_SUFFIX))
            else {
                continue;
            };
            let Ok(kind) = parse_name(name) else { continue };
            if list.items.len() >= MAX_LISTED {
                continue;
            }
            match self.read_item(dir, name, kind) {
                Ok(item) => list.items.push(item),
                Err(e) => {
                    tracing::warn!(error = %e, file = name, "skipping an archive that does not match its manifest")
                }
            }
        }
        list.items.sort_by(|a, b| {
            b.created_ms
                .cmp(&a.created_ms)
                .then_with(|| a.name.cmp(&b.name))
        });
        Ok(list)
    }

    // One restore at a time, and none while a cut, backup or scrub runs, so the file and its manifest cannot change under it.
    pub(crate) fn restore_archive(&self, name: &str, again: bool) -> Result<u64> {
        let _once = self
            .restoring
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let _turn = self
            .maintenance
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (kind, dir, path) = self.resolve(name)?;
        if kind != Kind::Archive {
            return Err(Error::Rejected(
                "a backup is a full database copy; restore it by replacing the database file while the connector is stopped".into(),
            ));
        }
        let item = self.read_item(dir, name, kind)?;
        if !again && read_marker(dir, name)?.is_some_and(|m| m.sha256 == item.sha256) {
            return Err(Error::Conflict(format!(
                "{name} was already restored; restoring it again would duplicate its rows, so send again set to true if that is intended"
            )));
        }
        let mut file = File::open(&path)?;
        verify_handle(&mut file, &item.sha256, item.rows)?;
        file.rewind()?;
        let mut chunk: Vec<LogEvent> = Vec::with_capacity(PAGE);
        let mut total = 0u64;
        read_events(&mut file, |ev| {
            chunk.push(ev);
            if chunk.len() >= PAGE {
                total += self.insert(&chunk)? as u64;
                chunk.clear();
            }
            Ok(())
        })?;
        total += self.insert(&chunk)? as u64;
        let marker = Restored {
            sha256: item.sha256,
            restored_ms: now_ms(),
            rows: total,
        };
        write_marker(dir, name, &marker).map_err(|e| {
            Error::Archive(format!(
                "{total} rows were restored but the restore marker could not be written ({e}); do not restore {name} again"
            ))
        })?;
        Ok(total)
    }

    pub(crate) fn delete_archive(&self, name: &str) -> Result<()> {
        let (_, dir, path) = self.resolve(name)?;
        fs::remove_file(&path)?;
        for side in [manifest_path(dir, name), marker_path(dir, name)] {
            match fs::remove_file(side) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        sync_dir(dir)?;
        Ok(())
    }

    pub(crate) fn open_archive(&self, name: &str) -> Result<(File, ArchiveItem)> {
        let (kind, dir, path) = self.resolve(name)?;
        let item = self.read_item(dir, name, kind)?;
        Ok((File::open(path)?, item))
    }
}

// Moves a verified temp file into place, then writes its manifest and syncs the directory; a file without a manifest is invisible and never counts as a copy.
fn publish(dir: &Path, tmp: &Path, item: &ArchiveItem) -> Result<()> {
    let target = dir.join(&item.name);
    fs::rename(tmp, &target)?;
    if let Err(e) = write_manifest(dir, item).and_then(|()| Ok(sync_dir(dir)?)) {
        let _ = fs::remove_file(manifest_path(dir, &item.name));
        let _ = fs::remove_file(&target);
        return Err(e);
    }
    Ok(())
}

// Checks, measures and syncs a finished backup copy, keeping the identity fields of base.
fn seal_backup(dst: Connection, tmp: &Path, base: ArchiveItem) -> Result<ArchiveItem> {
    let check: String = dst.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
    if check != "ok" {
        return Err(Error::Archive(format!("backup failed its check: {check}")));
    }
    let (rows, first_ms, last_ms): (i64, Option<i64>, Option<i64>) =
        dst.query_row("SELECT count(*), min(ts), max(ts) FROM requests", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?;
    dst.close().map_err(|(_, e)| e)?;
    File::open(tmp)?.sync_all()?;
    Ok(ArchiveItem {
        bytes: fs::metadata(tmp)?.len(),
        sha256: file_sha256(tmp)?,
        rows: u64::try_from(rows).unwrap_or(0),
        from_ms: first_ms,
        to_ms: last_ms,
        ..base
    })
}
