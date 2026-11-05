use std::collections::HashMap;

use rusqlite::{Connection, params};

use crate::error::Result;
use crate::hist::{class_index, lat_index, size_index};
use crate::schema::{ALL_SITES, TOP_KEEP, series};
use crate::util::{IntMap, to_i64};

const UPSERT_ROLLUP: &str = "INSERT INTO rollup
    (hour, site_id, requests, bytes_in, bytes_out, s0, s1, s2, s3, s4, s5, blocked, bot_requests, ms_sum)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT (hour, site_id) DO UPDATE SET
        requests = requests + excluded.requests,
        bytes_in = bytes_in + excluded.bytes_in,
        bytes_out = bytes_out + excluded.bytes_out,
        s0 = s0 + excluded.s0, s1 = s1 + excluded.s1, s2 = s2 + excluded.s2,
        s3 = s3 + excluded.s3, s4 = s4 + excluded.s4, s5 = s5 + excluded.s5,
        blocked = blocked + excluded.blocked,
        bot_requests = bot_requests + excluded.bot_requests,
        ms_sum = ms_sum + excluded.ms_sum";

const UPSERT_HIST: &str = "INSERT INTO rollup_hist (hour, site_id, series, bucket, n)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT (hour, site_id, series, bucket) DO UPDATE SET n = n + excluded.n";

const UPSERT_DIM: &str = "INSERT INTO rollup_dim (dim, site_id, hour, key_id, n, bytes)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT (dim, site_id, hour, key_id) DO UPDATE SET
        n = n + excluded.n, bytes = bytes + excluded.bytes";

const UPSERT_PATH: &str = "INSERT INTO rollup_path (site_id, hour, path, n, bytes)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT (site_id, hour, path) DO UPDATE SET
        n = n + excluded.n, bytes = bytes + excluded.bytes";

type Tally = (u64, u64);

#[derive(Default)]
struct Row {
    requests: u64,
    bytes_in: u64,
    bytes_out: u64,
    classes: [u64; 6],
    blocked: u64,
    bot_requests: u64,
    ms_sum: u64,
}

// Per-batch accumulator: events are folded in memory and written as one upsert per touched key. Tallies are kept per site; the all-sites rows of rollup_dim and rollup_path are summed from them when the batch is applied.
#[derive(Default)]
pub(crate) struct Rollups {
    rows: IntMap<(i64, i64), Row>,
    hist: IntMap<(i64, i64, u8, u32), u64>,
    dims: IntMap<(i64, i64, u8, i64), Tally>,
    tops: IntMap<(i64, i64, u8), IntMap<i64, Tally>>,
    paths: IntMap<(i64, i64), HashMap<String, Tally>>,
}

// Keeps the TOP_KEEP heaviest entries, ties broken by key so the choice is deterministic; returned in key order so the upserts walk the index forward.
fn heaviest<K: Ord, S>(group: &HashMap<K, Tally, S>) -> Vec<(&K, Tally)> {
    let mut all: Vec<(&K, Tally)> = group.iter().map(|(k, t)| (k, *t)).collect();
    let order = |a: &(&K, Tally), b: &(&K, Tally)| b.1.0.cmp(&a.1.0).then_with(|| a.0.cmp(b.0));
    if all.len() > TOP_KEEP {
        all.select_nth_unstable_by(TOP_KEEP, order);
        all.truncate(TOP_KEEP);
    }
    all.sort_unstable_by(|a, b| a.0.cmp(b.0));
    all
}

fn add(into: &mut Tally, t: Tally) {
    into.0 += t.0;
    into.1 += t.1;
}

impl Rollups {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn event(
        &mut self,
        hour: i64,
        site: i64,
        status: u16,
        total_ms: u32,
        bytes_in: u64,
        bytes_out: u64,
        blocked: bool,
        bot: bool,
    ) {
        let row = self.rows.entry((hour, site)).or_default();
        row.requests += 1;
        row.bytes_in += bytes_in;
        row.bytes_out += bytes_out;
        row.ms_sum += u64::from(total_ms);
        row.classes[class_index(status)] += 1;
        row.blocked += u64::from(blocked);
        row.bot_requests += u64::from(bot);
        let lat = lat_index(total_ms) as u32;
        *self
            .hist
            .entry((hour, site, series::LATENCY, lat))
            .or_default() += 1;
        let size = size_index(bytes_out) as u32;
        *self
            .hist
            .entry((hour, site, series::SIZE, size))
            .or_default() += 1;
    }

    pub(crate) fn dim(&mut self, hour: i64, site: i64, dim: u8, key: Option<i64>, bytes: u64) {
        let Some(key) = key else {
            return;
        };
        add(
            self.dims.entry((hour, site, dim, key)).or_default(),
            (1, bytes),
        );
    }

    // Counts a high-cardinality dictionary key; only the heaviest keys per batch reach the database.
    pub(crate) fn top(&mut self, hour: i64, site: i64, dim: u8, key: Option<i64>, bytes: u64) {
        let Some(key) = key else {
            return;
        };
        let group = self.tops.entry((hour, site, dim)).or_default();
        add(group.entry(key).or_default(), (1, bytes));
    }

    pub(crate) fn path(&mut self, hour: i64, site: i64, path: &str, bytes: u64) {
        if path.is_empty() {
            return;
        }
        let group = self.paths.entry((hour, site)).or_default();
        if let Some(e) = group.get_mut(path) {
            add(e, (1, bytes));
        } else {
            group.insert(path.to_string(), (1, bytes));
        }
    }

    pub(crate) fn apply(&self, conn: &Connection) -> Result<()> {
        let mut up = conn.prepare_cached(UPSERT_ROLLUP)?;
        for ((hour, site), r) in &self.rows {
            up.execute(params![
                hour,
                site,
                to_i64(r.requests),
                to_i64(r.bytes_in),
                to_i64(r.bytes_out),
                to_i64(r.classes[0]),
                to_i64(r.classes[1]),
                to_i64(r.classes[2]),
                to_i64(r.classes[3]),
                to_i64(r.classes[4]),
                to_i64(r.classes[5]),
                to_i64(r.blocked),
                to_i64(r.bot_requests),
                to_i64(r.ms_sum),
            ])?;
        }
        let mut up = conn.prepare_cached(UPSERT_HIST)?;
        for ((hour, site, series, bucket), n) in &self.hist {
            up.execute(params![hour, site, series, bucket, to_i64(*n)])?;
        }
        self.apply_dims(conn)?;
        self.apply_tops(conn)?;
        self.apply_paths(conn)
    }

    fn apply_dims(&self, conn: &Connection) -> Result<()> {
        let mut up = conn.prepare_cached(UPSERT_DIM)?;
        let mut all: IntMap<(i64, u8, i64), Tally> = IntMap::default();
        let mut each: Vec<(u8, i64, i64, i64, Tally)> = Vec::with_capacity(self.dims.len());
        for ((hour, site, dim, key), t) in &self.dims {
            each.push((*dim, *site, *hour, *key, *t));
            add(all.entry((*hour, *dim, *key)).or_default(), *t);
        }
        each.extend(
            all.iter()
                .map(|((hour, dim, key), t)| (*dim, ALL_SITES, *hour, *key, *t)),
        );
        each.sort_unstable_by_key(|r| (r.0, r.1, r.2, r.3));
        for (dim, site, hour, key, t) in each {
            up.execute(params![dim, site, hour, key, to_i64(t.0), to_i64(t.1)])?;
        }
        Ok(())
    }

    fn apply_tops(&self, conn: &Connection) -> Result<()> {
        let mut up = conn.prepare_cached(UPSERT_DIM)?;
        let mut all: IntMap<(i64, u8), IntMap<i64, Tally>> = IntMap::default();
        for ((hour, site, dim), group) in &self.tops {
            for (key, t) in heaviest(group) {
                up.execute(params![dim, site, hour, key, to_i64(t.0), to_i64(t.1)])?;
            }
            let merged = all.entry((*hour, *dim)).or_default();
            for (key, t) in group {
                add(merged.entry(*key).or_default(), *t);
            }
        }
        for ((hour, dim), group) in &all {
            for (key, t) in heaviest(group) {
                up.execute(params![dim, ALL_SITES, hour, key, to_i64(t.0), to_i64(t.1)])?;
            }
        }
        Ok(())
    }

    fn apply_paths(&self, conn: &Connection) -> Result<()> {
        let mut up = conn.prepare_cached(UPSERT_PATH)?;
        let mut all: IntMap<i64, HashMap<&str, Tally>> = IntMap::default();
        for ((hour, site), group) in &self.paths {
            for (path, t) in heaviest(group) {
                up.execute(params![site, hour, path, to_i64(t.0), to_i64(t.1)])?;
            }
            let merged = all.entry(*hour).or_default();
            for (path, t) in group {
                add(merged.entry(path.as_str()).or_default(), *t);
            }
        }
        for (hour, group) in &all {
            for (path, t) in heaviest(group) {
                up.execute(params![ALL_SITES, hour, path, to_i64(t.0), to_i64(t.1)])?;
            }
        }
        Ok(())
    }
}
