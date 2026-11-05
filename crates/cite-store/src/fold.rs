use std::collections::{HashMap, HashSet};
use std::time::Duration;

use rusqlite::types::ValueRef;
use rusqlite::{Connection, TransactionBehavior, params};

use crate::error::Result;
use crate::limits::MINUTE_MS;
use crate::schema::{ALL_SITES, dim, kind};
use crate::util::{IntMap, to_i64};

// How long inserts may leave heavy keys unfolded; readers cover the gap from raw rows.
pub(crate) const FOLD_EVERY: Duration = Duration::from_secs(5);
// Rows folded per pass, so catching up after a restart cannot hold the writer for long.
const FOLD_ROWS: i64 = 250_000;
// Distinct keys one minute may hold per dimension (and path bytes) before the minute is dropped from the tables and readers go back to raw rows.
pub(crate) const KEY_CAP: i64 = 30_000;
pub(crate) const PATH_BYTES_CAP: i64 = 16 * 1024 * 1024;

type Tally = (u64, u64);

const UPSERT_PATH: &str = "INSERT INTO rollup_path_min (site_id, minute, path, n, bytes) VALUES (?, ?, ?, ?, ?) \
    ON CONFLICT (site_id, minute, path) DO UPDATE SET n = n + excluded.n, bytes = bytes + excluded.bytes";
const UPSERT_KEY: &str = "INSERT INTO rollup_dim_min (dim, site_id, minute, key_id, n, bytes) VALUES (?, ?, ?, ?, ?, ?) \
    ON CONFLICT (dim, site_id, minute, key_id) DO UPDATE SET n = n + excluded.n, bytes = bytes + excluded.bytes";

// The dimensions the fold keeps, in the order used for per-minute flags.
const KEYED: [u8; 4] = [
    dim::CLIENT_IP,
    dim::USER_AGENT,
    dim::REFERER,
    dim::BOT_AGENT,
];

fn add(into: &mut Tally, bytes: u64) {
    into.0 += 1;
    into.1 += bytes;
}

#[derive(Default)]
struct Acc {
    paths: IntMap<(i64, i64), HashMap<String, Tally>>,
    keys: IntMap<(u8, i64, i64, i64), Tally>,
    minutes: HashSet<(u8, i64)>,
}

// Dimension and minute pairs that were dropped for exceeding the key cap, with the flags of the minute being read.
struct Flags {
    over: HashSet<(u8, i64)>,
    minute: i64,
    path: bool,
    keyed: [bool; 4],
}

impl Flags {
    fn load(conn: &Connection) -> Result<Self> {
        let mut stmt = conn.prepare_cached("SELECT dim, minute FROM rollup_over")?;
        let over = stmt
            .query_map([], |r| Ok((r.get::<_, u8>(0)?, r.get::<_, i64>(1)?)))?
            .collect::<std::result::Result<HashSet<_>, _>>()?;
        Ok(Self {
            over,
            minute: i64::MIN,
            path: false,
            keyed: [false; 4],
        })
    }

    fn at(&mut self, minute: i64) {
        if minute == self.minute {
            return;
        }
        self.minute = minute;
        let skipped = self.over.contains(&(dim::ANY, minute));
        self.path = skipped || self.over.contains(&(dim::PATH, minute));
        for (flag, d) in self.keyed.iter_mut().zip(KEYED) {
            *flag = skipped || self.over.contains(&(d, minute));
        }
    }
}

fn bot_classes(conn: &Connection) -> Result<HashSet<i64>> {
    let mut stmt = conn.prepare_cached("SELECT id FROM dict WHERE kind = ?1 AND val <> 'human'")?;
    let ids = stmt
        .query_map(params![kind::BOT_CLASS], |r| r.get::<_, i64>(0))?
        .collect::<std::result::Result<HashSet<_>, _>>()?;
    Ok(ids)
}

fn accumulate(conn: &Connection, after: i64, upto: i64) -> Result<Acc> {
    let bots = bot_classes(conn)?;
    let mut flags = Flags::load(conn)?;
    let mut acc = Acc::default();
    let mut stmt = conn.prepare_cached(
        "SELECT ts, site_id, path, client_ip_id, ua_id, referer_id, bytes_out, bot_class_id \
         FROM requests WHERE id > ?1 AND id <= ?2",
    )?;
    let mut rows = stmt.query(params![after, upto])?;
    while let Some(r) = rows.next()? {
        let minute = r.get::<_, i64>(0)?.div_euclid(MINUTE_MS);
        let site: i64 = r.get(1)?;
        let bytes = u64::try_from(r.get::<_, i64>(6)?).unwrap_or(0);
        flags.at(minute);
        if !flags.path
            && let ValueRef::Text(raw) = r.get_ref(2)?
            && !raw.is_empty()
        {
            let path = String::from_utf8_lossy(raw);
            let group = acc.paths.entry((site, minute)).or_default();
            if let Some(t) = group.get_mut(path.as_ref()) {
                add(t, bytes);
            } else {
                group.insert(path.into_owned(), (1, bytes));
            }
        }
        let ip: Option<i64> = r.get(3)?;
        let ua: Option<i64> = r.get(4)?;
        let referer: Option<i64> = r.get(5)?;
        let bot = r
            .get::<_, Option<i64>>(7)?
            .is_some_and(|c| bots.contains(&c));
        let keys = [ip, ua, referer, ua.filter(|_| bot)];
        for (i, key) in keys.into_iter().enumerate() {
            let Some(key) = key else {
                continue;
            };
            if flags.keyed[i] {
                continue;
            }
            add(
                acc.keys.entry((KEYED[i], site, minute, key)).or_default(),
                bytes,
            );
        }
    }
    Ok(acc)
}

fn write(conn: &Connection, acc: &mut Acc) -> Result<()> {
    let mut up = conn.prepare_cached(UPSERT_PATH)?;
    let mut all_paths: IntMap<i64, HashMap<&str, Tally>> = IntMap::default();
    let mut ordered: Vec<(i64, i64, &str, Tally)> = Vec::new();
    for ((site, minute), group) in &acc.paths {
        let merged = all_paths.entry(*minute).or_default();
        for (path, t) in group {
            ordered.push((*site, *minute, path.as_str(), *t));
            let m = merged.entry(path.as_str()).or_default();
            m.0 += t.0;
            m.1 += t.1;
        }
        acc.minutes.insert((dim::PATH, *minute));
    }
    for (minute, group) in &all_paths {
        for (path, t) in group {
            ordered.push((ALL_SITES, *minute, path, *t));
        }
    }
    ordered.sort_unstable_by(|a, b| (a.0, a.1, a.2).cmp(&(b.0, b.1, b.2)));
    for (site, minute, path, t) in ordered {
        up.execute(params![site, minute, path, to_i64(t.0), to_i64(t.1)])?;
    }
    let mut up = conn.prepare_cached(UPSERT_KEY)?;
    let mut all_keys: IntMap<(u8, i64, i64), Tally> = IntMap::default();
    let mut ordered: Vec<(u8, i64, i64, i64, Tally)> = Vec::with_capacity(acc.keys.len());
    for ((d, site, minute, key), t) in &acc.keys {
        ordered.push((*d, *site, *minute, *key, *t));
        let m = all_keys.entry((*d, *minute, *key)).or_default();
        m.0 += t.0;
        m.1 += t.1;
        acc.minutes.insert((*d, *minute));
    }
    for ((d, minute, key), t) in &all_keys {
        ordered.push((*d, ALL_SITES, *minute, *key, *t));
    }
    ordered.sort_unstable_by_key(|r| (r.0, r.1, r.2, r.3));
    for (d, site, minute, key, t) in ordered {
        up.execute(params![d, site, minute, key, to_i64(t.0), to_i64(t.1)])?;
    }
    Ok(())
}

fn exceeds_cap(conn: &Connection, d: u8, minute: i64) -> Result<bool> {
    if d == dim::PATH {
        let (n, bytes): (i64, i64) = conn
            .prepare_cached(
                "SELECT count(*), coalesce(sum(length(CAST(path AS BLOB))), 0) FROM \
                 (SELECT path FROM rollup_path_min WHERE site_id = ?1 AND minute = ?2 LIMIT ?3)",
            )?
            .query_row(params![ALL_SITES, minute, KEY_CAP + 1], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?;
        return Ok(n > KEY_CAP || bytes > PATH_BYTES_CAP);
    }
    let n: i64 = conn
        .prepare_cached(
            "SELECT count(*) FROM (SELECT 1 FROM rollup_dim_min \
             WHERE dim = ?1 AND site_id = ?2 AND minute = ?3 LIMIT ?4)",
        )?
        .query_row(params![d, ALL_SITES, minute, KEY_CAP + 1], |r| r.get(0))?;
    Ok(n > KEY_CAP)
}

// Drops every scope of one dimension and minute and records it, so readers use raw rows for any window containing it.
fn drop_minute(conn: &Connection, d: u8, minute: i64) -> Result<()> {
    let mut sites: Vec<i64> = conn
        .prepare_cached("SELECT site_id FROM rollup_min WHERE minute = ?1")?
        .query_map(params![minute], |r| r.get(0))?
        .collect::<std::result::Result<_, _>>()?;
    sites.push(ALL_SITES);
    for site in sites {
        if d == dim::PATH {
            conn.prepare_cached("DELETE FROM rollup_path_min WHERE site_id = ?1 AND minute = ?2")?
                .execute(params![site, minute])?;
        } else {
            conn.prepare_cached(
                "DELETE FROM rollup_dim_min WHERE dim = ?1 AND site_id = ?2 AND minute = ?3",
            )?
            .execute(params![d, site, minute])?;
        }
    }
    conn.prepare_cached("INSERT OR IGNORE INTO rollup_over (dim, minute) VALUES (?1, ?2)")?
        .execute(params![d, minute])?;
    Ok(())
}

// Folds the requests newer than the stored watermark into the minute tables for paths, client ips, agents and referers, in one transaction with the watermark. Returns true while rows remain beyond this pass.
pub(crate) fn fold(conn: &mut Connection) -> Result<bool> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (after, newest): (i64, i64) = tx.query_row(
        "SELECT folded_id, coalesce((SELECT max(id) FROM requests), 0) FROM rollup_state",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let after = after.min(newest);
    let upto = newest.min(after.saturating_add(FOLD_ROWS));
    if upto <= after {
        return Ok(false);
    }
    let mut acc = accumulate(&tx, after, upto)?;
    write(&tx, &mut acc)?;
    for (d, minute) in &acc.minutes {
        if exceeds_cap(&tx, *d, *minute)? {
            drop_minute(&tx, *d, *minute)?;
        }
    }
    tx.execute("UPDATE rollup_state SET folded_id = ?1", params![upto])?;
    tx.commit()?;
    Ok(upto < newest)
}

// Keeps the watermark at or below the newest request id, so ids freed by a delete and handed out again are folded.
pub(crate) fn clamp(conn: &Connection) -> Result<()> {
    conn.execute(
        "UPDATE rollup_state SET folded_id = min(folded_id, coalesce((SELECT max(id) FROM requests), 0))",
        [],
    )?;
    Ok(())
}

// Removes minute rollups older than the cutoff minute, ordered so every delete is a key range.
pub(crate) fn expire(conn: &Connection, cutoff_minute: i64) -> Result<u64> {
    let mut sites: Vec<i64> = conn
        .prepare_cached("SELECT DISTINCT site_id FROM rollup_min")?
        .query_map([], |r| r.get(0))?
        .collect::<std::result::Result<_, _>>()?;
    sites.push(ALL_SITES);
    let mut removed = 0u64;
    for site in &sites {
        removed += conn
            .prepare_cached("DELETE FROM rollup_path_min WHERE site_id = ?1 AND minute < ?2")?
            .execute(params![site, cutoff_minute])? as u64;
        for d in 1..=dim::PATH {
            removed += conn
                .prepare_cached(
                    "DELETE FROM rollup_dim_min WHERE dim = ?1 AND site_id = ?2 AND minute < ?3",
                )?
                .execute(params![d, site, cutoff_minute])? as u64;
        }
    }
    for sql in [
        "DELETE FROM rollup_hist_min WHERE minute < ?1",
        "DELETE FROM rollup_over WHERE minute < ?1",
        "DELETE FROM rollup_min WHERE minute < ?1",
    ] {
        removed += conn.execute(sql, params![cutoff_minute])? as u64;
    }
    Ok(removed)
}

// Empties every minute table and moves valid_from past the newest request, so readers use raw rows until the tables cover a window again.
pub(crate) fn drop_all(conn: &Connection) -> Result<u64> {
    let mut removed = 0u64;
    for table in [
        "rollup_path_min",
        "rollup_dim_min",
        "rollup_hist_min",
        "rollup_min",
        "rollup_over",
    ] {
        removed += conn.execute(&format!("DELETE FROM {table}"), [])? as u64;
    }
    conn.execute(
        "UPDATE rollup_state SET valid_from = max(valid_from, \
         coalesce((SELECT max(ts) FROM requests), 0) / 60000 + 1)",
        [],
    )?;
    Ok(removed)
}
