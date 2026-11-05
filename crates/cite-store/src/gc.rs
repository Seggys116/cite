use std::thread;
use std::time::Duration;

use rusqlite::{Connection, params};

use crate::error::Result;
use crate::schema::{dim, kind};
use crate::store::Inner;

// Dictionary rows deleted per writer-lock hold, so ingest interleaves between chunks.
const SWEEP_CHUNK: usize = 2000;
// Dictionary rows examined per read while sweeping.
const SCAN_PAGE: usize = 50_000;
const YIELD: Duration = Duration::from_millis(1);

// Every column of requests that holds a dictionary id.
const REQUEST_ID_COLUMNS: &str = "client_ip_id, host_id, method_id, ua_id, referer_id, ctype_id, backend_id, \
    server_id, site_id, blocked_id, http_version_id, accept_id, accept_lang_id, accept_enc_id, sfs_id, sfm_id, \
    sfd_id, sec_ch_ua_id, tls_id, bot_class_id, bot_signals_id";

pub(crate) struct Swept {
    pub(crate) removed: u64,
    // Rows of kinds that identify a client (address, agent, referer), whose pages were overwritten on delete.
    pub(crate) identifying: u64,
}

// One bit per dictionary id up to the largest id at scan time, so memory scales with the id range and not with request cardinality.
pub(crate) struct UsedIds {
    bits: Vec<u64>,
    limit: i64,
}

impl UsedIds {
    fn new(limit: i64) -> Self {
        let words = usize::try_from(limit / 64 + 1).unwrap_or(0);
        Self {
            bits: vec![0; words],
            limit,
        }
    }

    fn mark(&mut self, id: i64) {
        if (0..=self.limit).contains(&id) {
            self.bits[(id / 64) as usize] |= 1 << (id % 64);
        }
    }

    // Ids past the scanned range were created after the scan, so they count as in use.
    fn contains(&self, id: i64) -> bool {
        !(0..=self.limit).contains(&id) || self.bits[(id / 64) as usize] & (1 << (id % 64)) != 0
    }
}

pub(crate) fn used_ids(conn: &Connection) -> Result<UsedIds> {
    let tx = conn.unchecked_transaction()?;
    let limit: i64 = tx.query_row("SELECT coalesce(max(id), 0) FROM dict", [], |r| r.get(0))?;
    let mut used = UsedIds::new(limit);
    {
        let mut stmt = tx.prepare(&format!("SELECT {REQUEST_ID_COLUMNS} FROM requests"))?;
        let width = stmt.column_count();
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            for i in 0..width {
                if let Some(id) = r.get::<_, Option<i64>>(i)? {
                    used.mark(id);
                }
            }
        }
    }
    {
        let mut stmt = tx.prepare(
            "SELECT key_id FROM rollup_dim WHERE dim NOT IN (?1, ?2) \
             UNION SELECT key_id FROM rollup_dim_min WHERE dim NOT IN (?1, ?2)",
        )?;
        let mut rows = stmt.query(params![dim::STATUS, dim::SCORE])?;
        while let Some(r) = rows.next()? {
            used.mark(r.get(0)?);
        }
    }
    Ok(used)
}

pub(crate) type Page = (Vec<(i64, u8)>, Option<i64>);

// Dictionary rows above `after`, in id order, that the bitmap shows unused; also returns the last id examined.
pub(crate) fn unreferenced_page(
    conn: &Connection,
    used: &UsedIds,
    after: i64,
    page: usize,
) -> Result<Page> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, kind FROM dict WHERE id > ?1 AND kind <> ?2 ORDER BY id LIMIT ?3",
    )?;
    let mut rows = stmt.query(params![after, kind::SITE, page as i64])?;
    let (mut out, mut last) = (Vec::new(), None);
    while let Some(r) = rows.next()? {
        let id: i64 = r.get(0)?;
        last = Some(id);
        if !used.contains(id) {
            out.push((id, r.get(1)?));
        }
    }
    Ok((out, last))
}

#[cfg(test)]
pub(crate) fn unreferenced(conn: &Connection) -> Result<Vec<(i64, u8)>> {
    let used = used_ids(conn)?;
    let (mut all, mut after) = (Vec::new(), 0);
    loop {
        let (page, last) = unreferenced_page(conn, &used, after, SCAN_PAGE)?;
        all.extend(page);
        match last {
            Some(id) => after = id,
            None => return Ok(all),
        }
    }
}

fn identifying(k: u8) -> bool {
    matches!(k, kind::CLIENT_IP | kind::USER_AGENT | kind::REFERER)
}

impl Inner {
    // Tracking starts before the scan and empties the id cache, so a concurrent insert can neither lose a row nor reuse a deleted id.
    pub(crate) fn sweep_dict(&self) -> Result<Swept> {
        self.lock_writer().track_ids();
        let outcome = self.sweep_tracked();
        self.lock_writer().finish_tracking();
        outcome
    }

    fn sweep_tracked(&self) -> Result<Swept> {
        let used = self.read_long(used_ids)?;
        let mut swept = Swept {
            removed: 0,
            identifying: 0,
        };
        let mut after = 0;
        loop {
            let (page, last) = self.read_long(|c| unreferenced_page(c, &used, after, SCAN_PAGE))?;
            let Some(last) = last else {
                return Ok(swept);
            };
            after = last;
            let part = self.delete_unreferenced(&page)?;
            swept.removed += part.removed;
            swept.identifying += part.identifying;
        }
    }

    pub(crate) fn delete_unreferenced(&self, candidates: &[(i64, u8)]) -> Result<Swept> {
        let mut swept = Swept {
            removed: 0,
            identifying: 0,
        };
        for chunk in candidates.chunks(SWEEP_CHUNK) {
            let w = self.lock_writer();
            if w.tracking_overflowed() {
                tracing::warn!(
                    "dictionary sweep stopped early: too many ids were in use; it resumes on the next pass"
                );
                break;
            }
            let Some(touched) = w.touched() else {
                break;
            };
            w.conn.execute_batch("PRAGMA secure_delete = ON")?;
            let deleted = (|| -> Result<(u64, u64)> {
                let tx = w.conn.unchecked_transaction()?;
                let (mut all, mut ident) = (0u64, 0u64);
                {
                    let mut del =
                        tx.prepare_cached("DELETE FROM dict WHERE id = ?1 AND kind = ?2")?;
                    for (id, k) in chunk.iter().filter(|(id, _)| !touched.contains(id)) {
                        let n = del.execute(params![id, k])? as u64;
                        all += n;
                        if identifying(*k) {
                            ident += n;
                        }
                    }
                }
                tx.commit()?;
                Ok((all, ident))
            })();
            let restored = w.conn.execute_batch("PRAGMA secure_delete = FAST");
            let (all, ident) = deleted?;
            restored?;
            swept.removed += all;
            swept.identifying += ident;
            drop(w);
            thread::sleep(YIELD);
        }
        Ok(swept)
    }
}
