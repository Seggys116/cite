use std::collections::{HashMap, HashSet};

use cite_edge::model::LogEvent;
use rusqlite::{CachedStatement, Connection, OptionalExtension, TransactionBehavior, params};

use crate::error::Result;
use crate::limits::{BYTES_CLAMP, HOUR_MS};
use crate::rollup::Rollups;
use crate::schema::{dim, kind};
use crate::util::{ascii_upper, normalize_ctype, score_bucket, split_signals, to_i64};

const INSERT_REQUEST: &str = concat!(
    "INSERT INTO requests (ts, client_ip_id, host_id, method_id, path, query_len, status, bytes_in, bytes_out, ",
    "total_ms, ua_id, referer_id, ctype_id, backend_id, server_id, site_id, blocked_id, http_version_id, ",
    "accept_id, accept_lang_id, accept_enc_id, sfs_id, sfm_id, sfd_id, sec_ch_ua_id, tls_id, resp_ms, ",
    "bot_score, bot_class_id, bot_signals_id) VALUES (",
    "?,?,?,?,?,?,?,?,?,?,",
    "?,?,?,?,?,?,?,?,?,?,",
    "?,?,?,?,?,?,?,?,?,?)"
);

const INSERT_DICT: &str =
    "INSERT INTO dict (kind, val) VALUES (?1, ?2) ON CONFLICT (kind, val) DO NOTHING RETURNING id";
const LOOKUP: &str = "SELECT id FROM dict WHERE kind = ?1 AND val = ?2";

// Distinct values kept in memory across all kinds; a flood of unique values empties the largest map instead of growing.
const CACHE_CAP: usize = 750_000;
// Key bytes (plus a fixed per-entry overhead) kept across all kinds, so a flood of long values cannot grow the heap.
const CACHE_BYTES: usize = 64 * 1024 * 1024;
const ENTRY_OVERHEAD: usize = 56;
// Ids a dictionary sweep tracks before it gives up and tries again on a later pass.
const TOUCH_CAP: usize = 4_000_000;

fn entry_bytes(val: &str) -> usize {
    val.len() + ENTRY_OVERHEAD
}

pub(crate) struct DictCache {
    maps: Vec<HashMap<String, i64>>,
    bytes: Vec<usize>,
    total: usize,
    total_bytes: usize,
    touched: Option<HashSet<i64>>,
    touch_overflow: bool,
}

impl DictCache {
    fn new() -> Self {
        Self {
            maps: (0..kind::COUNT).map(|_| HashMap::new()).collect(),
            bytes: vec![0; kind::COUNT],
            total: 0,
            total_bytes: 0,
            touched: None,
            touch_overflow: false,
        }
    }

    fn drop_kind(&mut self, k: usize) {
        if let Some(m) = self.maps.get_mut(k) {
            self.total -= m.len();
            m.clear();
            self.total_bytes -= self.bytes[k];
            self.bytes[k] = 0;
        }
    }

    fn clear(&mut self) {
        for k in 0..self.maps.len() {
            self.drop_kind(k);
        }
    }

    fn forget(&mut self, kinds: &[u8]) {
        for &k in kinds {
            self.drop_kind(usize::from(k));
        }
    }

    fn over_budget(&self) -> bool {
        self.total >= CACHE_CAP || self.total_bytes >= CACHE_BYTES
    }

    fn evict_largest(&mut self) {
        let by_bytes = self.total_bytes >= CACHE_BYTES;
        let pick = (0..self.maps.len()).max_by_key(|&k| {
            if by_bytes {
                self.bytes[k]
            } else {
                self.maps[k].len()
            }
        });
        if let Some(k) = pick {
            self.drop_kind(k);
        }
    }

    fn touch(&mut self, id: i64) {
        if let Some(t) = &mut self.touched {
            if t.len() >= TOUCH_CAP {
                self.touch_overflow = true;
            } else {
                t.insert(id);
            }
        }
    }
}

// Which identity fields are written; an event's field is stored as absent when its flag is off.
#[derive(Clone, Copy)]
pub(crate) struct Privacy {
    pub(crate) client_ips: bool,
    pub(crate) user_agents: bool,
}

// The single write connection with its dictionary cache; always used under the store's writer mutex.
pub(crate) struct WriteConn {
    pub(crate) conn: Connection,
    cache: DictCache,
}

impl WriteConn {
    pub(crate) fn new(conn: Connection) -> Self {
        Self {
            conn,
            cache: DictCache::new(),
        }
    }

    pub(crate) fn forget(&mut self, kinds: &[u8]) {
        self.cache.forget(kinds);
    }

    // Starts recording every dictionary id an insert hands out. The cache is emptied first so each later use goes
    // through the dictionary and is seen, which lets a sweep delete only ids that no insert has touched since.
    pub(crate) fn track_ids(&mut self) {
        self.cache.clear();
        self.cache.touched = Some(HashSet::new());
        self.cache.touch_overflow = false;
    }

    pub(crate) fn finish_tracking(&mut self) {
        self.cache.touched = None;
        self.cache.touch_overflow = false;
    }

    pub(crate) fn touched(&self) -> Option<&HashSet<i64>> {
        self.cache.touched.as_ref()
    }

    pub(crate) fn tracking_overflowed(&self) -> bool {
        self.cache.touch_overflow
    }

    // One transaction for the whole slice; a failure rolls everything back and drops cached ids from the lost work.
    pub(crate) fn insert_batch(&mut self, events: &[LogEvent], privacy: Privacy) -> Result<usize> {
        let result = self.try_insert(events, privacy);
        if result.is_err() {
            self.cache.clear();
        }
        result
    }

    fn try_insert(&mut self, events: &[LogEvent], privacy: Privacy) -> Result<usize> {
        let Self { conn, cache } = self;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut roll = Rollups::default();
        warm(&tx, cache, events, privacy)?;
        {
            let mut ins = tx.prepare_cached(INSERT_REQUEST)?;
            for ev in events {
                add_event(&tx, cache, &mut ins, &mut roll, ev, privacy)?;
            }
        }
        roll.apply(&tx)?;
        tx.commit()?;
        Ok(events.len())
    }
}

// Adds the batch's unseen client ips, agents and referers to the dictionary in key order, which keeps the unique
// index writes of a high-cardinality batch close together instead of scattered.
fn warm(
    conn: &Connection,
    cache: &mut DictCache,
    events: &[LogEvent],
    privacy: Privacy,
) -> Result<()> {
    type Field = fn(&LogEvent) -> &str;
    let fields: [(u8, bool, Field); 3] = [
        (kind::CLIENT_IP, privacy.client_ips, |e| &e.client_ip),
        (kind::USER_AGENT, privacy.user_agents, |e| &e.user_agent),
        (kind::REFERER, true, |e| &e.referer),
    ];
    for (k, wanted, field) in fields {
        if !wanted {
            continue;
        }
        let Some(map) = cache.maps.get(usize::from(k)) else {
            continue;
        };
        let mut missing: Vec<&str> = events
            .iter()
            .map(field)
            .filter(|v| !v.is_empty() && !map.contains_key(*v))
            .collect();
        missing.sort_unstable();
        missing.dedup();
        for v in missing {
            intern(conn, cache, k, v)?;
        }
    }
    Ok(())
}

// Empty strings are stored as NULL rather than interned.
fn intern(conn: &Connection, cache: &mut DictCache, k: u8, val: &str) -> Result<Option<i64>> {
    if val.is_empty() {
        return Ok(None);
    }
    let cached = cache
        .maps
        .get(usize::from(k))
        .and_then(|m| m.get(val))
        .copied();
    if let Some(id) = cached {
        cache.touch(id);
        return Ok(Some(id));
    }
    // New values are the common miss, so insert first; a conflict returns no row and falls back to the lookup.
    let inserted: Option<i64> = conn
        .prepare_cached(INSERT_DICT)?
        .query_row(params![k, val], |r| r.get(0))
        .optional()?;
    let id = match inserted {
        Some(id) => id,
        None => conn
            .prepare_cached(LOOKUP)?
            .query_row(params![k, val], |r| r.get(0))?,
    };
    cache.touch(id);
    while cache.over_budget() && cache.total > 0 {
        cache.evict_largest();
    }
    let Some(map) = cache.maps.get_mut(usize::from(k)) else {
        return Ok(None);
    };
    map.insert(val.to_string(), id);
    cache.total += 1;
    cache.bytes[usize::from(k)] += entry_bytes(val);
    cache.total_bytes += entry_bytes(val);
    Ok(Some(id))
}

fn add_event(
    conn: &Connection,
    cache: &mut DictCache,
    ins: &mut CachedStatement<'_>,
    roll: &mut Rollups,
    ev: &LogEvent,
    privacy: Privacy,
) -> Result<()> {
    let mut id = |k: u8, v: &str| intern(conn, cache, k, v);
    let client_ip = if privacy.client_ips {
        id(kind::CLIENT_IP, &ev.client_ip)?
    } else {
        None
    };
    let host = id(kind::HOST, &ev.host)?;
    let method = id(kind::METHOD, &ev.method)?;
    let ua = if privacy.user_agents {
        id(kind::USER_AGENT, &ev.user_agent)?
    } else {
        None
    };
    let referer = id(kind::REFERER, &ev.referer)?;
    let ctype = id(kind::CONTENT_TYPE, &ev.content_type)?;
    let backend = id(kind::BACKEND, &ev.backend)?;
    let server = id(kind::SERVER, &ev.server)?;
    let site = id(kind::SITE, &ev.site)?;
    let rule = ev.blocked.as_deref().filter(|b| !b.is_empty());
    let blocked = match rule {
        Some(b) => id(kind::BLOCKED, b)?,
        None => None,
    };
    let http_version = id(kind::HTTP_VERSION, &ev.http_version)?;
    let accept = id(kind::ACCEPT, &ev.accept)?;
    let lang = id(kind::ACCEPT_LANGUAGE, &ev.accept_language)?;
    let enc = id(kind::ACCEPT_ENCODING, &ev.accept_encoding)?;
    let fetch_site = id(kind::SEC_FETCH_SITE, &ev.sec_fetch_site)?;
    let fetch_mode = id(kind::SEC_FETCH_MODE, &ev.sec_fetch_mode)?;
    let fetch_dest = id(kind::SEC_FETCH_DEST, &ev.sec_fetch_dest)?;
    let sec_ch_ua = id(kind::SEC_CH_UA, &ev.sec_ch_ua)?;
    let tls = id(kind::TLS_VERSION, &ev.tls_version)?;
    let bot_class = id(kind::BOT_CLASS, &ev.bot_class)?;
    let bot_signals = id(kind::BOT_SIGNALS, &ev.bot_signals)?;

    let bytes_in = ev.bytes_in.min(BYTES_CLAMP);
    let bytes_out = ev.bytes_out.min(BYTES_CLAMP);
    ins.execute(params![
        ev.ts_ms,
        client_ip,
        host,
        method,
        ev.path,
        ev.query_len,
        ev.status,
        to_i64(bytes_in),
        to_i64(bytes_out),
        ev.total_ms,
        ua,
        referer,
        ctype,
        backend,
        server,
        site.unwrap_or(0),
        blocked,
        http_version,
        accept,
        lang,
        enc,
        fetch_site,
        fetch_mode,
        fetch_dest,
        sec_ch_ua,
        tls,
        ev.resp_ms,
        ev.bot_score,
        bot_class,
        bot_signals,
    ])?;

    let hour = ev.ts_ms.div_euclid(HOUR_MS);
    let scope = site.unwrap_or(0);
    let classified = !ev.bot_class.is_empty();
    let bot = classified && ev.bot_class != "human";
    roll.event(
        hour,
        scope,
        ev.status,
        ev.total_ms,
        bytes_in,
        bytes_out,
        rule.is_some(),
        bot,
    );
    let upper = ascii_upper(&ev.method);
    roll.dim(
        hour,
        scope,
        dim::METHOD,
        id(kind::METHOD, &upper)?,
        bytes_out,
    );
    let ctype_norm = normalize_ctype(&ev.content_type);
    roll.dim(
        hour,
        scope,
        dim::CONTENT_TYPE,
        id(kind::CONTENT_TYPE_NORM, &ctype_norm)?,
        bytes_out,
    );
    roll.top(hour, scope, dim::CLIENT_IP, client_ip, bytes_out);
    roll.top(hour, scope, dim::USER_AGENT, ua, bytes_out);
    roll.top(hour, scope, dim::REFERER, referer, bytes_out);
    if bot {
        roll.top(hour, scope, dim::BOT_AGENT, ua, bytes_out);
    }
    roll.path(hour, scope, &ev.path, bytes_out);
    roll.dim(hour, scope, dim::HOST, host, bytes_out);
    roll.dim(hour, scope, dim::BLOCKED, blocked, bytes_out);
    roll.dim(
        hour,
        scope,
        dim::STATUS,
        Some(i64::from(ev.status)),
        bytes_out,
    );
    roll.dim(hour, scope, dim::LANGUAGE, lang, bytes_out);
    roll.dim(hour, scope, dim::BOT_CLASS, bot_class, bytes_out);
    for signal in split_signals(&ev.bot_signals) {
        roll.dim(
            hour,
            scope,
            dim::SIGNAL,
            id(kind::SIGNAL, signal)?,
            bytes_out,
        );
    }
    if classified {
        let bucket = score_bucket(ev.bot_score) as i64;
        roll.dim(hour, scope, dim::SCORE, Some(bucket), bytes_out);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{MIGRATIONS, migrate};

    #[test]
    fn cache_is_capped_by_bytes_as_well_as_entries() {
        let mut conn = Connection::open_in_memory().expect("open");
        migrate(&mut conn, MIGRATIONS).expect("migrate");
        let mut cache = DictCache::new();
        let big = "x".repeat(1024 * 1024);
        for i in 0..100 {
            let val = format!("{i}-{big}");
            intern(&conn, &mut cache, kind::USER_AGENT, &val).expect("intern");
            assert!(
                cache.total_bytes < CACHE_BYTES + 2 * 1024 * 1024,
                "cache grew to {} bytes",
                cache.total_bytes
            );
        }
        assert!(cache.total < 100, "{} entries kept", cache.total);
        let again =
            intern(&conn, &mut cache, kind::USER_AGENT, &format!("0-{big}")).expect("again");
        let stored: i64 = conn
            .query_row("SELECT id FROM dict WHERE val LIKE '0-x%'", [], |r| {
                r.get(0)
            })
            .expect("stored");
        assert_eq!(again, Some(stored));
    }
}
