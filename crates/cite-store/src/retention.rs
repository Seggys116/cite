use std::fmt;
use std::sync::PoisonError;
use std::thread;
use std::time::Duration;

use rusqlite::params;
use serde::Serialize;

use crate::archive::Cut;
use crate::error::Result;
use crate::fold;
use crate::limits::{DAY_MS, HOUR_MS, MINUTE_KEEP_MS, MINUTE_MS};
use crate::store::Inner;

// Each chunk is its own transaction so ingest can interleave between them.
const EXPIRE_CHUNK: i64 = 50_000;
const TRIM_CHUNK: i64 = 10_000;
// Chunks in a row that free no measurable space before trimming gives up for the pass.
const TRIM_STALLS: u32 = 3;
const VACUUM_PAGES: i64 = 4096;
const VACUUM_ROUNDS: usize = 1000;
// Per-pass share of raw rows a size-cap pass may remove, so a burst cannot erase all history at once.
const TRIM_PASS_PERCENT: i64 = 25;
// A database at least this many times over the cap is trimmed without the per-pass share limit.
const TRIM_WIDE_MARGIN: u64 = 2;
// Pause between chunks so the ingest thread, which waits on the same mutex, gets a turn.
const YIELD: Duration = Duration::from_millis(1);
const TRIM_OBJECTS: [&str; 6] = [
    "requests",
    "idx_requests_ts",
    "idx_requests_site_ts",
    "idx_requests_status_ts",
    "idx_requests_bot_ts",
    "idx_requests_ip_bucket",
];

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PruneReport {
    /// None when age retention is off.
    pub cutoff_ms: Option<i64>,
    pub expired_rows: u64,
    /// Rows written to verified archive files before they were deleted by age.
    pub archived_rows: u64,
    /// Why age deletion stopped early; the rows stay and the next pass retries.
    pub archive_error: Option<String>,
    pub trimmed_rows: u64,
    pub trimmed_from_ms: Option<i64>,
    pub trimmed_to_ms: Option<i64>,
    /// The budget is exceeded by data trimming cannot remove (rollups and dictionary), so no raw row was deleted.
    pub trim_blocked: bool,
    /// The pass stopped at its per-pass share of raw rows and the database is still over the budget.
    pub trim_limited: bool,
    pub rollup_rows_removed: u64,
    pub dict_rows_removed: u64,
    pub bytes_before: u64,
    pub bytes_after: u64,
}

impl PruneReport {
    pub fn is_empty(&self) -> bool {
        self.expired_rows == 0
            && self.trimmed_rows == 0
            && self.rollup_rows_removed == 0
            && self.dict_rows_removed == 0
    }
}

impl fmt::Display for PruneReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "pruned {} expired rows ({} archived, cutoff {:?}), trimmed {} oldest rows ({:?}..{:?}), removed {} rollup rows and \
             {} dictionary rows, live bytes {} -> {}",
            self.expired_rows,
            self.archived_rows,
            self.cutoff_ms,
            self.trimmed_rows,
            self.trimmed_from_ms,
            self.trimmed_to_ms,
            self.rollup_rows_removed,
            self.dict_rows_removed,
            self.bytes_before,
            self.bytes_after
        )
    }
}

impl Inner {
    // Single entry point for retention; the scheduled pass and a settings change take turns on the maintenance lock.
    pub(crate) fn prune(&self, now_ms: i64) -> Result<PruneReport> {
        let _turn = self
            .maintenance
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut report = PruneReport {
            bytes_before: self.live_bytes()?,
            ..PruneReport::default()
        };
        let minute_rows = self.expire_minutes(now_ms)?;
        let days = self.retention_days();
        if days > 0 {
            let cutoff = now_ms.saturating_sub(i64::from(days).saturating_mul(DAY_MS));
            report.cutoff_ms = Some(cutoff);
            self.expire_by_age(cutoff, &mut report)?;
        }
        if let Some(max) = self.max_bytes() {
            self.trim(max, &mut report)?;
        }
        // Under a size cap raw rows can go before their minute rollups, which may then be the last reference to a dictionary entry.
        let changed = !report.is_empty() || (minute_rows > 0 && self.max_bytes().is_some());
        self.settle(changed, &mut report)?;
        report.bytes_after = self.live_bytes()?;
        Ok(report)
    }

    // Age deletion that keeps a verified copy first; an archive failure is reported and retried on the next pass, never turned into a delete.
    fn expire_by_age(&self, cutoff: i64, report: &mut PruneReport) -> Result<()> {
        if !self.archive_before_delete() {
            return self.expire(cutoff, report);
        }
        let Some(dir) = self.archive_dir.as_deref() else {
            let msg = "age retention is on with archiving but no archive directory is configured";
            tracing::warn!("{msg}; nothing was deleted");
            report.archive_error = Some(msg.into());
            return Ok(());
        };
        // Only complete UTC days are archived, so a day is never split across files by the schedule.
        let whole_days = cutoff.div_euclid(DAY_MS) * DAY_MS;
        let mut cut = Cut::default();
        let outcome = self.archive_and_delete(dir, whole_days, &mut cut);
        report.expired_rows += cut.deleted;
        report.archived_rows += cut.archived;
        if let Some(done) = cut.done_to {
            self.expire_rollups(done, report)?;
        }
        if let Err(e) = outcome {
            tracing::warn!(error = %e, "archiving old analytics failed; nothing past the last verified archive was deleted and the next pass retries");
            report.archive_error = Some(e.to_string());
        }
        Ok(())
    }

    // Shared tail of every pass that deleted rows: free dictionary entries nothing references, give the pages back and fold the log if text was erased.
    pub(crate) fn settle(&self, changed: bool, report: &mut PruneReport) -> Result<()> {
        let mut sensitive = false;
        if changed {
            let swept = self.sweep_dict()?;
            report.dict_rows_removed = swept.removed;
            sensitive = swept.identifying > 0;
        }
        if changed {
            self.reclaim()?;
        }
        let retry = self.wal_dirty.load(std::sync::atomic::Ordering::Relaxed);
        if (sensitive || retry)
            && let Err(e) = self.truncate_wal()
        {
            tracing::warn!(error = %e, "write-ahead log still holds pages removed from the database");
        }
        Ok(())
    }

    pub(crate) fn expire(&self, cutoff: i64, report: &mut PruneReport) -> Result<()> {
        loop {
            let n = {
                let w = self.lock_writer();
                let tx = w.conn.unchecked_transaction()?;
                let n = tx.execute(
                    "DELETE FROM requests WHERE id IN (SELECT id FROM requests WHERE ts < ?1 LIMIT ?2)",
                    params![cutoff, EXPIRE_CHUNK],
                )?;
                fold::clamp(&tx)?;
                tx.commit()?;
                n
            };
            report.expired_rows += n as u64;
            if (n as i64) < EXPIRE_CHUNK {
                break;
            }
            thread::sleep(YIELD);
        }
        self.expire_rollups(cutoff, report)
    }

    // Rollups before the cutoff hour; the caller has already removed or archived the raw rows they summarise.
    pub(crate) fn expire_rollups(&self, cutoff: i64, report: &mut PruneReport) -> Result<()> {
        let hour = cutoff.div_euclid(HOUR_MS);
        let w = self.lock_writer();
        for sql in [
            "DELETE FROM rollup WHERE hour < ?1",
            "DELETE FROM rollup_hist WHERE hour < ?1",
            "DELETE FROM rollup_dim WHERE hour < ?1",
            "DELETE FROM rollup_path WHERE hour < ?1",
        ] {
            report.rollup_rows_removed += w.conn.execute(sql, params![hour])? as u64;
        }
        Ok(())
    }

    // Deletes the rows of one archived segment in chunks; the id bound keeps rows that arrived after the archive was read.
    pub(crate) fn delete_segment(&self, from: i64, to: i64, max_id: i64) -> Result<u64> {
        let mut total = 0u64;
        loop {
            let n = {
                let w = self.lock_writer();
                let tx = w.conn.unchecked_transaction()?;
                let n = tx.execute(
                    "DELETE FROM requests WHERE id IN (SELECT id FROM requests \
                     WHERE ts >= ?1 AND ts < ?2 AND id <= ?3 LIMIT ?4)",
                    params![from, to, max_id, EXPIRE_CHUNK],
                )?;
                fold::clamp(&tx)?;
                tx.commit()?;
                n
            };
            total += n as u64;
            if (n as i64) < EXPIRE_CHUNK {
                return Ok(total);
            }
            thread::sleep(YIELD);
        }
    }

    // The minute tables only serve windows of a few hours, so they are cut at a fixed age whatever the retention period.
    fn expire_minutes(&self, now_ms: i64) -> Result<u64> {
        let cutoff = now_ms.saturating_sub(MINUTE_KEEP_MS).div_euclid(MINUTE_MS);
        let w = self.lock_writer();
        fold::expire(&w.conn, cutoff)
    }

    fn removable_bytes(&self) -> Result<u64> {
        self.read_long(|c| {
            let mut total = 0i64;
            for name in TRIM_OBJECTS {
                total += c.query_row(
                    "SELECT coalesce(sum(pgsize), 0) FROM dbstat WHERE name = ?1",
                    params![name],
                    |r| r.get::<_, i64>(0),
                )?;
            }
            Ok(u64::try_from(total).unwrap_or(0))
        })
    }

    // Rollups survive trimming so history stays chartable; nothing is deleted if the data trimming cannot remove already exceeds the budget.
    fn trim(&self, max: u64, report: &mut PruneReport) -> Result<()> {
        let mut live = self.live_bytes()?;
        if live <= max {
            return Ok(());
        }
        // The minute tables only speed up recent windows and readers fall back to raw rows without them, so they go before any raw row does.
        report.rollup_rows_removed += fold::drop_all(&self.lock_writer().conn)?;
        self.reclaim()?;
        live = self.live_bytes()?;
        if live <= max {
            return Ok(());
        }
        let fixed = live.saturating_sub(self.removable_bytes()?);
        if fixed >= max {
            report.trim_blocked = true;
            tracing::warn!(
                budget = max,
                fixed_bytes = fixed,
                "analytics size budget is smaller than the rollups and dictionary, which trimming cannot shrink; no raw rows were deleted for it"
            );
            return Ok(());
        }
        let rows: i64 =
            self.read(|c| Ok(c.query_row("SELECT count(*) FROM requests", [], |r| r.get(0))?))?;
        let allowed = if live >= max.saturating_mul(TRIM_WIDE_MARGIN) {
            u64::MAX
        } else {
            u64::try_from((rows * TRIM_PASS_PERCENT / 100).max(1)).unwrap_or(1)
        };
        let mut stalls = 0;
        let mut measured = self.live_bytes()?;
        while measured > max {
            if report.trimmed_rows >= allowed {
                report.trim_limited = true;
                tracing::warn!(
                    budget = max,
                    trimmed = report.trimmed_rows,
                    "analytics is still over its size budget after the per-pass trim limit; the rest is trimmed on later passes"
                );
                break;
            }
            let left = rows - i64::try_from(report.trimmed_rows).unwrap_or(rows);
            if left <= 1 {
                report.trim_blocked = true;
                break;
            }
            let chunk = i64::try_from(allowed - report.trimmed_rows)
                .unwrap_or(TRIM_CHUNK)
                .min(TRIM_CHUNK)
                .min(left - 1);
            let w = self.lock_writer();
            let (min, top): (Option<i64>, Option<i64>) = w.conn.query_row(
                "SELECT min(ts), max(ts) FROM (SELECT ts FROM requests ORDER BY ts, id LIMIT ?1)",
                params![chunk],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let tx = w.conn.unchecked_transaction()?;
            let n = tx.execute(
                "DELETE FROM requests WHERE id IN (SELECT id FROM requests ORDER BY ts, id LIMIT ?1)",
                params![chunk],
            )?;
            fold::clamp(&tx)?;
            tx.commit()?;
            drop(w);
            if n == 0 {
                break;
            }
            report.trimmed_rows += n as u64;
            report.trimmed_from_ms = match (report.trimmed_from_ms, min) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            report.trimmed_to_ms = match (report.trimmed_to_ms, top) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            };
            thread::sleep(YIELD);
            let now = self.live_bytes()?;
            stalls = if now < measured { 0 } else { stalls + 1 };
            measured = now;
            if stalls >= TRIM_STALLS {
                report.trim_blocked = true;
                tracing::warn!(
                    budget = max,
                    "deleting raw rows no longer shrinks the analytics database; stopped for this pass"
                );
                break;
            }
        }
        Ok(())
    }

    pub(crate) fn reclaim(&self) -> Result<()> {
        for _ in 0..VACUUM_ROUNDS {
            let free = {
                let w = self.lock_writer();
                w.conn
                    .execute_batch(&format!("PRAGMA incremental_vacuum({VACUUM_PAGES})"))?;
                w.conn
                    .query_row("PRAGMA freelist_count", [], |r| r.get::<_, i64>(0))?
            };
            if free == 0 {
                break;
            }
            thread::sleep(YIELD);
        }
        Ok(())
    }
}
