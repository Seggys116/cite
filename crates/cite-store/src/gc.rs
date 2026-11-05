use std::collections::HashSet;
use std::thread;
use std::time::Duration;

use rusqlite::{Connection, params};

use crate::error::Result;
use crate::schema::{dim, kind};
use crate::store::Inner;

// Dictionary rows deleted per writer-lock hold, so ingest interleaves between chunks.
const SWEEP_CHUNK: usize = 2000;
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

pub(crate) fn unreferenced(conn: &Connection) -> Result<Vec<(i64, u8)>> {
    let tx = conn.unchecked_transaction()?;
    let mut used: HashSet<i64> = HashSet::new();
    {
        let mut stmt = tx.prepare(&format!("SELECT {REQUEST_ID_COLUMNS} FROM requests"))?;
        let width = stmt.column_count();
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            for i in 0..width {
                if let Some(id) = r.get::<_, Option<i64>>(i)? {
                    used.insert(id);
                }
            }
        }
    }
    {
        let mut stmt =
            tx.prepare("SELECT DISTINCT key_id FROM rollup_dim WHERE dim NOT IN (?1, ?2)")?;
        let mut rows = stmt.query(params![dim::STATUS, dim::SCORE])?;
        while let Some(r) = rows.next()? {
            used.insert(r.get(0)?);
        }
    }
    let mut stmt = tx.prepare("SELECT id, kind FROM dict WHERE kind <> ?1")?;
    let mut rows = stmt.query(params![kind::SITE])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        let id: i64 = r.get(0)?;
        if !used.contains(&id) {
            out.push((id, r.get(1)?));
        }
    }
    Ok(out)
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
        let candidates = self.read_long(unreferenced)?;
        self.delete_unreferenced(&candidates)
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
            let restored = w.conn.execute_batch("PRAGMA secure_delete = OFF");
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
