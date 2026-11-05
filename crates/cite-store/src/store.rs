use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError, Weak};
use std::time::Duration;

use cite_edge::analytics::{RequestFilter, Summary, Timeseries, TopItem};
use cite_edge::bot::BotSummary;
use cite_edge::model::LogEvent;
use rusqlite::Connection;
use serde::Serialize;

use crate::archive::{ArchiveItem, ArchiveList, CutReport};
use crate::error::{Error, Result};
use crate::export::{self, CsvSink, ExportFilter, ExportKind, NdjsonSink};
use crate::ingest::{Privacy, WriteConn};
use crate::queries::{self, TopKind};
use crate::retention::PruneReport;
use crate::schema::{self, Reader};
use crate::writer::{Writer, WriterCore};

const MAX_READERS: usize = 16;
const IMPORT_CHUNK: usize = 5000;
const NO_LIMIT: u64 = u64::MAX;
const CHECKPOINT_ATTEMPTS: usize = 3;
const CHECKPOINT_RETRY: Duration = Duration::from_millis(100);
// Longest one attempt waits for readers to leave the log; the writer lock is held meanwhile, so it stays short.
const CHECKPOINT_WAIT: Duration = Duration::from_millis(500);

#[derive(Debug, Clone)]
pub struct StoreOptions {
    /// 0 never deletes by age.
    pub retention_days: u32,
    /// Where archives and backups are written; without it nothing can be archived, so age deletion with archiving on is skipped.
    pub archive_dir: Option<PathBuf>,
    /// Complete days are archived and verified before age retention deletes them.
    pub archive_before_delete: bool,
    pub max_bytes: Option<u64>,
    /// Clamped to 1 to 16.
    pub read_connections: usize,
    pub batch_size: usize,
    pub flush_interval: Duration,
    /// Senders block when the queue is full.
    pub queue_capacity: usize,
    pub query_timeout: Duration,
    /// Each export page gets its own budget.
    pub export_timeout: Duration,
}

impl Default for StoreOptions {
    fn default() -> Self {
        Self {
            retention_days: 0,
            archive_dir: None,
            archive_before_delete: true,
            max_bytes: None,
            read_connections: 4,
            batch_size: 5000,
            flush_interval: Duration::from_millis(250),
            queue_capacity: 16_384,
            query_timeout: Duration::from_secs(20),
            export_timeout: Duration::from_secs(600),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct StoreStats {
    pub rows: u64,
    pub db_bytes: u64,
    pub oldest_ts_ms: Option<i64>,
    pub newest_ts_ms: Option<i64>,
    pub write_batches: u64,
    pub write_errors: u64,
}

pub(crate) struct Inner {
    pub(crate) writer: Mutex<WriteConn>,
    readers: Vec<Mutex<Reader>>,
    cursor: AtomicUsize,
    retention_days: AtomicU32,
    pub(crate) archive_dir: Option<PathBuf>,
    archive_before_delete: AtomicBool,
    #[cfg(test)]
    pub(crate) archive_fault: AtomicBool,
    max_bytes: AtomicU64,
    batches: AtomicU64,
    errors: AtomicU64,
    keep_client_ips: AtomicBool,
    keep_user_agents: AtomicBool,
    query_timeout: Duration,
    export_timeout: Duration,
    // Serialises prune passes so the scheduled one and a settings-triggered one never interleave.
    pub(crate) maintenance: Mutex<()>,
    // Set when a privacy scrub could not fold the WAL; the next prune pass retries.
    pub(crate) wal_dirty: AtomicBool,
}

impl Inner {
    pub(crate) fn lock_writer(&self) -> MutexGuard<'_, WriteConn> {
        self.writer.lock().unwrap_or_else(PoisonError::into_inner)
    }

    // Takes the first free pooled reader, else waits on one; the query is cancelled at the timeout.
    pub(crate) fn read<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        self.read_within(self.query_timeout, f)
    }

    #[cfg(test)]
    pub(crate) fn read_within_for_test<T>(
        &self,
        limit: Duration,
        f: impl FnOnce(&Connection) -> Result<T>,
    ) -> Result<T> {
        self.read_within(limit, f)
    }

    pub(crate) fn read_long<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        self.read_within(self.export_timeout, f)
    }

    fn read_within<T>(
        &self,
        limit: Duration,
        f: impl FnOnce(&Connection) -> Result<T>,
    ) -> Result<T> {
        let run = |r: &Reader| {
            r.arm(limit);
            let out = f(&r.conn);
            r.disarm();
            out
        };
        let n = self.readers.len();
        let start = self.cursor.fetch_add(1, Ordering::Relaxed);
        for i in 0..n {
            match self.readers[(start + i) % n].try_lock() {
                Ok(g) => return run(&g),
                Err(TryLockError::Poisoned(p)) => return run(&p.into_inner()),
                Err(TryLockError::WouldBlock) => {}
            }
        }
        let g = self.readers[start % n]
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        run(&g)
    }

    pub(crate) fn privacy(&self) -> Privacy {
        Privacy {
            client_ips: self.keep_client_ips.load(Ordering::Relaxed),
            user_agents: self.keep_user_agents.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn insert(&self, events: &[LogEvent]) -> Result<usize> {
        if events.is_empty() {
            return Ok(0);
        }
        let result = {
            let mut w = self.lock_writer();
            let privacy = self.privacy();
            w.insert_batch(events, privacy)
        };
        match &result {
            Ok(_) => self.batches.fetch_add(1, Ordering::Relaxed),
            Err(_) => self.errors.fetch_add(1, Ordering::Relaxed),
        };
        result
    }

    pub(crate) fn retention_days(&self) -> u32 {
        self.retention_days.load(Ordering::Relaxed)
    }

    pub(crate) fn archive_before_delete(&self) -> bool {
        self.archive_before_delete.load(Ordering::Relaxed)
    }

    pub(crate) fn max_bytes(&self) -> Option<u64> {
        match self.max_bytes.load(Ordering::Relaxed) {
            NO_LIMIT => None,
            n => Some(n),
        }
    }
}

pub struct Store {
    pub(crate) inner: Arc<Inner>,
    opts: StoreOptions,
    writer: Mutex<Weak<WriterCore>>,
}

impl Store {
    /// Opens or creates the database at path (its directory must exist), migrating the schema forward.
    pub fn open(path: &Path, opts: StoreOptions) -> Result<Store> {
        let conn = schema::open_writer(path)?;
        let readers = (0..opts.read_connections.clamp(1, MAX_READERS))
            .map(|_| schema::open_reader(path).map(Mutex::new))
            .collect::<Result<Vec<_>>>()?;
        let inner = Inner {
            writer: Mutex::new(WriteConn::new(conn)),
            readers,
            cursor: AtomicUsize::new(0),
            retention_days: AtomicU32::new(opts.retention_days),
            archive_dir: opts.archive_dir.clone(),
            archive_before_delete: AtomicBool::new(opts.archive_before_delete),
            #[cfg(test)]
            archive_fault: AtomicBool::new(false),
            max_bytes: AtomicU64::new(opts.max_bytes.unwrap_or(NO_LIMIT)),
            batches: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            keep_client_ips: AtomicBool::new(true),
            keep_user_agents: AtomicBool::new(true),
            query_timeout: opts.query_timeout,
            export_timeout: opts.export_timeout,
            maintenance: Mutex::new(()),
            wal_dirty: AtomicBool::new(false),
        };
        Ok(Store {
            inner: Arc::new(inner),
            opts,
            writer: Mutex::new(Weak::new()),
        })
    }

    pub fn insert(&self, events: &[LogEvent]) -> Result<usize> {
        self.inner.insert(events)
    }

    pub fn import_events(&self, events: impl Iterator<Item = LogEvent>) -> Result<usize> {
        let mut chunk = Vec::with_capacity(IMPORT_CHUNK);
        let mut total = 0;
        for ev in events {
            chunk.push(ev);
            if chunk.len() >= IMPORT_CHUNK {
                total += self.inner.insert(&chunk)?;
                chunk.clear();
            }
        }
        total += self.inner.insert(&chunk)?;
        Ok(total)
    }

    /// Returns a cloneable handle to the batching writer thread, starting it if no handle is alive.
    pub fn writer(&self) -> Writer {
        let mut slot = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(core) = slot.upgrade() {
            return Writer::from_core(core);
        }
        let core = Arc::new(WriterCore::spawn(self.inner.clone(), &self.opts));
        *slot = Arc::downgrade(&core);
        Writer::from_core(core)
    }

    pub fn summary(&self, window_secs: u64, site: Option<&str>, now_ms: i64) -> Result<Summary> {
        self.inner
            .read(|c| queries::summary(c, window_secs, site, now_ms))
    }

    pub fn timeseries(
        &self,
        window_secs: u64,
        site: Option<&str>,
        now_ms: i64,
    ) -> Result<Timeseries> {
        self.inner
            .read(|c| queries::timeseries(c, window_secs, site, now_ms))
    }

    /// Newest-first events matching the filter, at most limit and never more than 100000.
    pub fn requests(&self, filter: &RequestFilter, limit: usize) -> Result<Vec<LogEvent>> {
        self.inner.read(|c| queries::requests(c, filter, limit))
    }

    pub fn bots(&self, window_secs: u64, site: Option<&str>, now_ms: i64) -> Result<BotSummary> {
        self.inner
            .read(|c| queries::bots(c, window_secs, site, now_ms))
    }

    /// Highest-count values of one dimension in the window, at most limit and never more than 10000.
    pub fn top(
        &self,
        kind: TopKind,
        window_secs: u64,
        site: Option<&str>,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<TopItem>> {
        self.inner
            .read(|c| queries::top(c, kind, window_secs, site, now_ms, limit))
    }

    pub fn stats(&self) -> Result<StoreStats> {
        let (rows, oldest_ts_ms, newest_ts_ms) = self.inner.read(|c| {
            let rows: i64 = c.query_row("SELECT count(*) FROM requests", [], |r| r.get(0))?;
            let (min, max): (Option<i64>, Option<i64>) =
                c.query_row("SELECT min(ts), max(ts) FROM requests", [], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?;
            Ok((rows, min, max))
        })?;
        Ok(StoreStats {
            rows: u64::try_from(rows).unwrap_or(0),
            db_bytes: self.inner.file_bytes()?,
            oldest_ts_ms,
            newest_ts_ms,
            write_batches: self.inner.batches.load(Ordering::Relaxed),
            write_errors: self.inner.errors.load(Ordering::Relaxed),
        })
    }

    pub fn prune(&self, now_ms: i64) -> Result<PruneReport> {
        self.inner.prune(now_ms)
    }

    pub fn set_retention_days(&self, days: u32) {
        self.inner.retention_days.store(days, Ordering::Relaxed);
    }

    pub fn retention_days(&self) -> u32 {
        self.inner.retention_days()
    }

    pub fn set_archive_before_delete(&self, on: bool) {
        self.inner
            .archive_before_delete
            .store(on, Ordering::Relaxed);
    }

    pub fn archive_before_delete(&self) -> bool {
        self.inner.archive_before_delete()
    }

    pub fn archive_dir(&self) -> Option<&Path> {
        self.inner.archive_dir.as_deref()
    }

    /// Writes a checksummed, consistent copy of the live database into the archive directory.
    pub fn backup(&self) -> Result<ArchiveItem> {
        self.inner.backup()
    }

    /// Deletes every raw row older than cutoff_ms. With archive on, each UTC day is first written to a verified archive file and a failure deletes nothing further. A dry run only counts.
    pub fn cut_before(&self, cutoff_ms: i64, archive: bool, dry_run: bool) -> Result<CutReport> {
        self.inner.cut_before(cutoff_ms, archive, dry_run)
    }

    pub fn list_archives(&self) -> Result<ArchiveList> {
        self.inner.list_archives()
    }

    /// Re-imports an archive file and returns the rows added; backups are rejected.
    pub fn restore_archive(&self, name: &str) -> Result<u64> {
        self.inner.restore_archive(name)
    }

    pub fn delete_archive(&self, name: &str) -> Result<()> {
        self.inner.delete_archive(name)
    }

    /// Opens an archive or backup for download, with the manifest entry that describes it.
    pub fn open_archive(&self, name: &str) -> Result<(std::fs::File, ArchiveItem)> {
        self.inner.open_archive(name)
    }

    pub fn set_max_bytes(&self, max_bytes: Option<u64>) {
        self.inner
            .max_bytes
            .store(max_bytes.unwrap_or(NO_LIMIT), Ordering::Relaxed);
    }

    pub fn max_bytes(&self) -> Option<u64> {
        self.inner.max_bytes()
    }

    /// Flags are read at commit time, so already-queued events are stripped too; pair a switch-off with scrub_fields.
    pub fn set_privacy(&self, client_ips: bool, user_agents: bool) {
        self.inner
            .keep_client_ips
            .store(client_ips, Ordering::Relaxed);
        self.inner
            .keep_user_agents
            .store(user_agents, Ordering::Relaxed);
    }

    /// Error::Incomplete means the data is already unlinked from every row and only the WAL fold is left for the next prune.
    pub fn scrub_fields(&self, client_ips: bool, user_agents: bool) -> Result<u64> {
        let live = self
            .writer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .upgrade();
        if let Some(core) = live {
            Writer::from_core(core).flush()?;
        }
        self.inner.scrub(client_ips, user_agents)
    }

    /// Fails with Error::Incomplete if readers kept part of the log in use for the whole wait.
    pub fn checkpoint(&self) -> Result<()> {
        self.inner.truncate_wal()
    }

    pub fn integrity_check(&self) -> Result<()> {
        let findings = self.inner.read_long(|c| {
            let mut stmt = c.prepare("PRAGMA integrity_check")?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
            let out = rows.collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(out)
        })?;
        if findings.len() == 1 && findings[0] == "ok" {
            Ok(())
        } else {
            Err(Error::Integrity(findings.join("; ")))
        }
    }

    pub fn export_csv<W: Write>(
        &self,
        out: W,
        kind: ExportKind,
        filter: &ExportFilter,
    ) -> Result<u64> {
        let mut sink = CsvSink::new(BufWriter::new(out));
        let rows = export::run(&self.inner, &mut sink, kind, filter)?;
        sink.finish()?;
        Ok(rows)
    }

    pub fn export_ndjson<W: Write>(
        &self,
        out: W,
        kind: ExportKind,
        filter: &ExportFilter,
    ) -> Result<u64> {
        let mut sink = NdjsonSink::new(BufWriter::new(out));
        let rows = export::run(&self.inner, &mut sink, kind, filter)?;
        sink.finish()?;
        Ok(rows)
    }
}

impl Inner {
    // Readers can block a checkpoint (it reports busy, not an error), so retry briefly; wal_dirty makes the next prune retry.
    pub(crate) fn truncate_wal(&self) -> Result<()> {
        for attempt in 0..CHECKPOINT_ATTEMPTS {
            if attempt > 0 {
                std::thread::sleep(CHECKPOINT_RETRY);
            }
            let busy = {
                let w = self.lock_writer();
                w.conn.busy_timeout(CHECKPOINT_WAIT)?;
                let outcome = w
                    .conn
                    .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                        r.get::<_, i64>(0)
                    });
                w.conn.busy_timeout(schema::BUSY_TIMEOUT)?;
                match outcome {
                    Ok(b) => b,
                    Err(rusqlite::Error::SqliteFailure(e, _))
                        if e.code == rusqlite::ErrorCode::DatabaseBusy =>
                    {
                        1
                    }
                    Err(e) => return Err(e.into()),
                }
            };
            if busy == 0 {
                self.wal_dirty.store(false, Ordering::Relaxed);
                return Ok(());
            }
        }
        self.wal_dirty.store(true, Ordering::Relaxed);
        Err(Error::Incomplete(
            "readers kept the write-ahead log in use, so it was not folded away; it is retried on the next prune"
                .into(),
        ))
    }

    // Logical database size: every page including free ones, as the file would be after a checkpoint.
    pub(crate) fn file_bytes(&self) -> Result<u64> {
        self.read(|c| {
            let pages: i64 = c.query_row("PRAGMA page_count", [], |r| r.get(0))?;
            let size: i64 = c.query_row("PRAGMA page_size", [], |r| r.get(0))?;
            Ok(u64::try_from(pages.saturating_mul(size)).unwrap_or(0))
        })
    }

    // Size of the pages actually holding data, which is what a size budget should compare against.
    pub(crate) fn live_bytes(&self) -> Result<u64> {
        self.read(|c| {
            let pages: i64 = c.query_row("PRAGMA page_count", [], |r| r.get(0))?;
            let free: i64 = c.query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
            let size: i64 = c.query_row("PRAGMA page_size", [], |r| r.get(0))?;
            Ok(u64::try_from((pages - free).max(0).saturating_mul(size)).unwrap_or(0))
        })
    }
}
