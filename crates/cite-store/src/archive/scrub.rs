use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::sync::PoisonError;

use flate2::Compression;
use flate2::write::GzEncoder;
use rusqlite::{Connection, OpenFlags, params};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{
    ArchiveItem, Encoder, HashingWriter, Kind, Restored, create_private, parse_name, read_events,
    read_marker, seal, seal_backup, sync_dir, unique_tmp, verify_archive, write_manifest,
    write_marker,
};
use crate::error::Result;
use crate::schema::{dim, kind};
use crate::store::Inner;

/// What a privacy scrub of the archive directory changed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ArchiveScrub {
    /// Archive files rewritten without the fields.
    pub archives: u64,
    /// Backups rewritten without the fields.
    pub backups: u64,
    /// Events inside archives that had a field blanked.
    pub rows: u64,
    /// Files that could not be scrubbed and still hold the fields.
    pub failed: Vec<String>,
}

// What the scrub removes, as SQL fragments over the requests table plus the dictionary and rollup kinds that held the text.
struct Targets {
    set: String,
    cond: String,
    kinds: Vec<u8>,
    dims: Vec<u8>,
}

impl Targets {
    fn new(client_ips: bool, user_agents: bool) -> Self {
        let (mut cols, mut kinds, mut dims) = (Vec::new(), Vec::new(), Vec::new());
        if client_ips {
            cols.push("client_ip_id");
            kinds.push(kind::CLIENT_IP);
            dims.push(dim::CLIENT_IP);
        }
        if user_agents {
            cols.push("ua_id");
            kinds.push(kind::USER_AGENT);
            dims.push(dim::USER_AGENT);
            dims.push(dim::BOT_AGENT);
        }
        let set = cols
            .iter()
            .map(|c| format!("{c} = NULL"))
            .collect::<Vec<_>>()
            .join(", ");
        let cond = cols
            .iter()
            .map(|c| format!("{c} IS NOT NULL"))
            .collect::<Vec<_>>()
            .join(" OR ");
        Targets {
            set,
            cond,
            kinds,
            dims,
        }
    }

    fn list(ids: &[u8]) -> String {
        ids.iter().map(u8::to_string).collect::<Vec<_>>().join(", ")
    }

    // Tables a copy made by an older schema may lack are skipped rather than failing the whole backup.
    fn deletes(&self, conn: &Connection) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for (table, col, ids) in [
            ("dict", "kind", &self.kinds),
            ("rollup_dim", "dim", &self.dims),
            ("rollup_dim_min", "dim", &self.dims),
        ] {
            let found: i64 = conn.query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                params![table],
                |r| r.get(0),
            )?;
            if found > 0 {
                out.push(format!(
                    "DELETE FROM {table} WHERE {col} IN ({})",
                    Self::list(ids)
                ));
            }
        }
        Ok(out)
    }

    fn holds_text(&self, conn: &Connection) -> Result<bool> {
        let mut probes = vec![format!(
            "SELECT EXISTS(SELECT 1 FROM requests WHERE {})",
            self.cond
        )];
        for delete in self.deletes(conn)? {
            probes.push(format!(
                "SELECT EXISTS(SELECT 1 {})",
                delete.trim_start_matches("DELETE ")
            ));
        }
        for sql in probes {
            if conn.query_row(&sql, [], |r| r.get::<_, bool>(0))? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl Inner {
    // Serialised with cuts, backups and restores; each file is replaced only after its scrubbed copy verified.
    pub(crate) fn scrub_archived(
        &self,
        client_ips: bool,
        user_agents: bool,
    ) -> Result<ArchiveScrub> {
        let mut report = ArchiveScrub::default();
        if !(client_ips || user_agents) || self.archive_dir.is_none() {
            return Ok(report);
        }
        let dir = self.archive_dir_required()?;
        let _turn = self
            .maintenance
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let targets = Targets::new(client_ips, user_agents);
        for item in self.list_archives()?.items {
            let outcome = match parse_name(&item.name) {
                Ok(Kind::Archive) => scrub_archive_file(dir, &item, client_ips, user_agents)
                    .map(|n| n.inspect(|_| report.archives += 1)),
                Ok(Kind::Backup) => scrub_backup_file(dir, &item, &targets).map(|done| {
                    if done {
                        report.backups += 1;
                    }
                    None
                }),
                Err(e) => Err(e),
            };
            match outcome {
                Ok(rows) => report.rows += rows.unwrap_or(0),
                Err(e) => {
                    tracing::warn!(error = %e, file = %item.name, "could not scrub an archive file");
                    report.failed.push(item.name);
                }
            }
        }
        Ok(report)
    }
}

// Returns the events that had a field blanked when the file was rewritten, None when it held nothing to remove.
fn scrub_archive_file(
    dir: &Path,
    item: &ArchiveItem,
    client_ips: bool,
    user_agents: bool,
) -> Result<Option<u64>> {
    let path = dir.join(&item.name);
    let tmp = unique_tmp(dir, &item.name);
    let outcome = rewrite_archive(File::open(&path)?, &tmp, client_ips, user_agents);
    let (sha256, bytes, rows, blanked) = match outcome {
        Ok(Some(done)) => done,
        Ok(None) => {
            let _ = fs::remove_file(&tmp);
            return Ok(None);
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
    };
    let finish = (|| -> Result<()> {
        verify_archive(&tmp, &sha256, rows)?;
        let replaced = ArchiveItem {
            bytes,
            sha256: sha256.clone(),
            rows,
            ..item.clone()
        };
        fs::rename(&tmp, &path)?;
        write_manifest(dir, &replaced)?;
        sync_dir(dir)?;
        carry_marker(dir, item, &replaced)
    })();
    if finish.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    finish.map(|()| Some(blanked))
}

// The restored marker names the checksum it vouches for, so it follows the file to its new bytes.
fn carry_marker(dir: &Path, old: &ArchiveItem, new: &ArchiveItem) -> Result<()> {
    if let Some(marker) = read_marker(dir, &old.name)?
        && marker.sha256 == old.sha256
    {
        write_marker(
            dir,
            &new.name,
            &Restored {
                sha256: new.sha256.clone(),
                ..marker
            },
        )?;
    }
    Ok(())
}

// Streams the archive into tmp with the fields blanked; None when no event had anything to blank, so the file is left alone.
fn rewrite_archive(
    src: File,
    tmp: &Path,
    client_ips: bool,
    user_agents: bool,
) -> Result<Option<(String, u64, u64, u64)>> {
    let sink = HashingWriter {
        inner: BufWriter::new(create_private(tmp)?),
        hasher: Sha256::new(),
        bytes: 0,
    };
    let mut enc: Encoder = GzEncoder::new(sink, Compression::default());
    let (mut rows, mut blanked) = (0u64, 0u64);
    read_events(src, |mut ev| {
        let mut hit = false;
        if client_ips && !ev.client_ip.is_empty() {
            ev.client_ip.clear();
            hit = true;
        }
        if user_agents && !ev.user_agent.is_empty() {
            ev.user_agent.clear();
            hit = true;
        }
        serde_json::to_writer(&mut enc, &ev)?;
        enc.write_all(b"\n")?;
        rows += 1;
        blanked += u64::from(hit);
        Ok(())
    })?;
    if blanked == 0 {
        return Ok(None);
    }
    let (sha256, bytes) = seal(enc)?;
    Ok(Some((sha256, bytes, rows, blanked)))
}

// Works on a copy so the original stays intact until the scrubbed database passed its check; VACUUM with secure_delete leaves no old pages behind.
fn scrub_backup_file(dir: &Path, item: &ArchiveItem, targets: &Targets) -> Result<bool> {
    let path = dir.join(&item.name);
    {
        let probe = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        if !targets.holds_text(&probe)? {
            return Ok(false);
        }
    }
    let tmp = unique_tmp(dir, &item.name);
    let outcome = (|| -> Result<()> {
        let mut src = File::open(&path)?;
        let mut dst = create_private(&tmp)?;
        io::copy(&mut src, &mut dst)?;
        dst.sync_all()?;
        drop(dst);
        let conn = Connection::open(&tmp)?;
        conn.execute_batch("PRAGMA secure_delete = ON")?;
        let deletes = targets.deletes(&conn)?;
        conn.execute_batch("BEGIN IMMEDIATE")?;
        conn.execute(
            &format!("UPDATE requests SET {} WHERE {}", targets.set, targets.cond),
            [],
        )?;
        for sql in &deletes {
            conn.execute(sql, [])?;
        }
        conn.execute_batch("COMMIT")?;
        conn.execute_batch("VACUUM")?;
        let replaced = seal_backup(conn, &tmp, item.clone())?;
        fs::rename(&tmp, &path)?;
        write_manifest(dir, &replaced)?;
        sync_dir(dir)?;
        Ok(())
    })();
    if outcome.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    outcome.map(|()| true)
}
