use rusqlite::{Connection, params};

use crate::error::Result;
use crate::schema::{dim, kind};
use crate::store::Inner;

// Request ids cleared per transaction, so ingest interleaves between chunks.
const SCRUB_CHUNK: i64 = 20_000;

fn fragments(client_ips: bool, user_agents: bool) -> Option<(&'static str, &'static str)> {
    match (client_ips, user_agents) {
        (false, false) => None,
        (true, false) => Some(("client_ip_id = NULL", "client_ip_id IS NOT NULL")),
        (false, true) => Some(("ua_id = NULL", "ua_id IS NOT NULL")),
        (true, true) => Some((
            "client_ip_id = NULL, ua_id = NULL",
            "(client_ip_id IS NOT NULL OR ua_id IS NOT NULL)",
        )),
    }
}

fn clear_range(conn: &Connection, set: &str, cond: &str, after: i64, upto: i64) -> Result<u64> {
    let sql = format!("UPDATE requests SET {set} WHERE id > ?1 AND id <= ?2 AND {cond}");
    Ok(conn.execute(&sql, params![after, upto])? as u64)
}

impl Inner {
    // Nulls the chosen columns, then removes the dictionary, rollup and cache entries that held their text.
    pub(crate) fn scrub(&self, client_ips: bool, user_agents: bool) -> Result<u64> {
        let Some((set, cond)) = fragments(client_ips, user_agents) else {
            return Ok(0);
        };
        // Shared with prune and cuts, so an archive pass can never read rows this scrub has not reached yet.
        let _turn = self
            .maintenance
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut touched = 0;
        let mut after = 0i64;
        loop {
            let w = self.lock_writer();
            let max: Option<i64> = w
                .conn
                .query_row("SELECT max(id) FROM requests", [], |r| r.get(0))?;
            let Some(max) = max.filter(|m| *m > after) else {
                break;
            };
            let upto = max.min(after.saturating_add(SCRUB_CHUNK));
            touched += clear_range(&w.conn, set, cond, after, upto)?;
            after = upto;
        }
        let mut kinds = Vec::new();
        let mut dims = Vec::new();
        if client_ips {
            kinds.push(kind::CLIENT_IP);
            dims.push(dim::CLIENT_IP);
        }
        if user_agents {
            kinds.push(kind::USER_AGENT);
            dims.push(dim::USER_AGENT);
            dims.push(dim::BOT_AGENT);
        }
        // Held for the rest so no insert can reuse an id that is about to disappear.
        let mut w = self.lock_writer();
        w.conn.execute_batch("PRAGMA secure_delete = ON")?;
        let result = (|| -> Result<u64> {
            let tail = clear_range(&w.conn, set, cond, after, i64::MAX)?;
            let tx = w.conn.unchecked_transaction()?;
            for k in &kinds {
                tx.execute("DELETE FROM dict WHERE kind = ?1", params![k])?;
            }
            for d in &dims {
                tx.execute("DELETE FROM rollup_dim WHERE dim = ?1", params![d])?;
                tx.execute("DELETE FROM rollup_dim_min WHERE dim = ?1", params![d])?;
            }
            tx.commit()?;
            Ok(tail)
        })();
        let restored = w.conn.execute_batch("PRAGMA secure_delete = FAST");
        w.forget(&kinds);
        touched += result?;
        restored?;
        drop(w);
        let folded = self.truncate_wal();
        self.reclaim()?;
        folded?;
        Ok(touched)
    }
}
