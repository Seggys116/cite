use std::collections::{BTreeSet, HashMap};

use rusqlite::{Connection, params};

use crate::error::Result;
use crate::hist::{class_index, lat_index, size_index};
use crate::limits::{HOUR_MS, MINUTE_MS};
use crate::schema::{ALL_SITES, HOURLY, Level, MINUTELY, TOP_KEEP, dim, series};
use crate::util::{IntMap, to_i64};

fn upsert_rollup(l: &Level) -> String {
    format!(
        "INSERT INTO {} ({b}, site_id, requests, bytes_in, bytes_out, s0, s1, s2, s3, s4, s5, blocked, bot_requests, ms_sum) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT ({b}, site_id) DO UPDATE SET \
         requests = requests + excluded.requests, bytes_in = bytes_in + excluded.bytes_in, \
         bytes_out = bytes_out + excluded.bytes_out, \
         s0 = s0 + excluded.s0, s1 = s1 + excluded.s1, s2 = s2 + excluded.s2, \
         s3 = s3 + excluded.s3, s4 = s4 + excluded.s4, s5 = s5 + excluded.s5, \
         blocked = blocked + excluded.blocked, bot_requests = bot_requests + excluded.bot_requests, \
         ms_sum = ms_sum + excluded.ms_sum",
        l.rollup,
        b = l.bucket
    )
}

fn upsert_hist(l: &Level) -> String {
    format!(
        "INSERT INTO {} ({b}, site_id, series, bucket, n) VALUES (?, ?, ?, ?, ?) \
         ON CONFLICT ({b}, site_id, series, bucket) DO UPDATE SET n = n + excluded.n",
        l.hist,
        b = l.bucket
    )
}

fn upsert_dim(l: &Level) -> String {
    format!(
        "INSERT INTO {} (dim, site_id, {b}, key_id, n, bytes) VALUES (?, ?, ?, ?, ?, ?) \
         ON CONFLICT (dim, site_id, {b}, key_id) DO UPDATE SET n = n + excluded.n, bytes = bytes + excluded.bytes",
        l.dim,
        b = l.bucket
    )
}

fn upsert_path(l: &Level) -> String {
    format!(
        "INSERT INTO {} (site_id, {b}, path, n, bytes) VALUES (?, ?, ?, ?, ?) \
         ON CONFLICT (site_id, {b}, path) DO UPDATE SET n = n + excluded.n, bytes = bytes + excluded.bytes",
        l.path,
        b = l.bucket
    )
}

type Tally = (u64, u64);

#[derive(Default, Clone)]
struct Row {
    requests: u64,
    bytes_in: u64,
    bytes_out: u64,
    classes: [u64; 6],
    blocked: u64,
    bot_requests: u64,
    ms_sum: u64,
}

impl Row {
    fn merge(&mut self, o: &Row) {
        self.requests += o.requests;
        self.bytes_in += o.bytes_in;
        self.bytes_out += o.bytes_out;
        for (a, b) in self.classes.iter_mut().zip(o.classes) {
            *a += b;
        }
        self.blocked += o.blocked;
        self.bot_requests += o.bot_requests;
        self.ms_sum += o.ms_sum;
    }
}

// The low-cardinality tallies, keyed by the bucket they are written to.
#[derive(Default)]
struct Light {
    rows: IntMap<(i64, i64), Row>,
    hist: IntMap<(i64, i64, u8, u32), u64>,
    dims: IntMap<(i64, i64, u8, i64), Tally>,
}

impl Light {
    // The same tallies with each minute key folded into its hour.
    fn hourly(&self) -> Light {
        let hour = |minute: i64| minute.div_euclid(HOUR_MS / MINUTE_MS);
        let mut out = Light::default();
        for ((minute, site), r) in &self.rows {
            out.rows.entry((hour(*minute), *site)).or_default().merge(r);
        }
        for ((minute, site, series, bucket), n) in &self.hist {
            *out.hist
                .entry((hour(*minute), *site, *series, *bucket))
                .or_default() += n;
        }
        for ((minute, site, dim, key), t) in &self.dims {
            add(
                out.dims
                    .entry((hour(*minute), *site, *dim, *key))
                    .or_default(),
                *t,
            );
        }
        out
    }

    fn apply(&self, conn: &Connection, l: &Level) -> Result<()> {
        let mut up = conn.prepare_cached(&upsert_rollup(l))?;
        for ((bucket, site), r) in &self.rows {
            up.execute(params![
                bucket,
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
        let mut up = conn.prepare_cached(&upsert_hist(l))?;
        for ((bucket, site, series, slot), n) in &self.hist {
            up.execute(params![bucket, site, series, slot, to_i64(*n)])?;
        }
        let mut up = conn.prepare_cached(&upsert_dim(l))?;
        let mut all: IntMap<(i64, u8, i64), Tally> = IntMap::default();
        let mut each: Vec<(u8, i64, i64, i64, Tally)> = Vec::with_capacity(self.dims.len());
        for ((bucket, site, dim, key), t) in &self.dims {
            each.push((*dim, *site, *bucket, *key, *t));
            add(all.entry((*bucket, *dim, *key)).or_default(), *t);
        }
        each.extend(
            all.iter()
                .map(|((bucket, dim, key), t)| (*dim, ALL_SITES, *bucket, *key, *t)),
        );
        each.sort_unstable_by_key(|r| (r.0, r.1, r.2, r.3));
        for (dim, site, bucket, key, t) in each {
            up.execute(params![dim, site, bucket, key, to_i64(t.0), to_i64(t.1)])?;
        }
        Ok(())
    }
}

// Per-batch accumulator: events are folded in memory and written as one upsert per touched key. Tallies are kept per site; the all-sites rows of rollup_dim and rollup_path are summed from them when the batch is applied. The low-cardinality tallies are counted per minute and rolled up into hours when written; the heavy keys are counted per hour here and reach the minute tables through the fold.
#[derive(Default)]
pub(crate) struct Rollups {
    light: Light,
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
        ts_ms: i64,
        site: i64,
        status: u16,
        total_ms: u32,
        bytes_in: u64,
        bytes_out: u64,
        blocked: bool,
        bot: bool,
    ) {
        let minute = ts_ms.div_euclid(MINUTE_MS);
        let row = self.light.rows.entry((minute, site)).or_default();
        row.requests += 1;
        row.bytes_in += bytes_in;
        row.bytes_out += bytes_out;
        row.ms_sum += u64::from(total_ms);
        row.classes[class_index(status)] += 1;
        row.blocked += u64::from(blocked);
        row.bot_requests += u64::from(bot);
        let lat = lat_index(total_ms) as u32;
        *self
            .light
            .hist
            .entry((minute, site, series::LATENCY, lat))
            .or_default() += 1;
        let size = size_index(bytes_out) as u32;
        *self
            .light
            .hist
            .entry((minute, site, series::SIZE, size))
            .or_default() += 1;
    }

    pub(crate) fn dim(&mut self, ts_ms: i64, site: i64, dim: u8, key: Option<i64>, bytes: u64) {
        let Some(key) = key else {
            return;
        };
        add(
            self.light
                .dims
                .entry((ts_ms.div_euclid(MINUTE_MS), site, dim, key))
                .or_default(),
            (1, bytes),
        );
    }

    // Counts a high-cardinality dictionary key; only the heaviest keys per batch reach the hourly tables.
    pub(crate) fn top(&mut self, ts_ms: i64, site: i64, dim: u8, key: Option<i64>, bytes: u64) {
        let Some(key) = key else {
            return;
        };
        let group = self
            .tops
            .entry((ts_ms.div_euclid(HOUR_MS), site, dim))
            .or_default();
        add(group.entry(key).or_default(), (1, bytes));
    }

    pub(crate) fn path(&mut self, ts_ms: i64, site: i64, path: &str, bytes: u64) {
        if path.is_empty() {
            return;
        }
        let group = self
            .paths
            .entry((ts_ms.div_euclid(HOUR_MS), site))
            .or_default();
        if let Some(e) = group.get_mut(path) {
            add(e, (1, bytes));
        } else {
            group.insert(path.to_string(), (1, bytes));
        }
    }

    // Live batches also feed the minute tables. A backfill only flags the minutes it touches, so readers use raw rows for any window that contains one.
    pub(crate) fn apply(&self, conn: &Connection, minutes: bool) -> Result<()> {
        if minutes {
            self.light.apply(conn, &MINUTELY)?;
        } else {
            self.flag_minutes(conn)?;
        }
        self.light.hourly().apply(conn, &HOURLY)?;
        self.apply_tops(conn)?;
        self.apply_paths(conn)
    }

    fn flag_minutes(&self, conn: &Connection) -> Result<()> {
        let mut up =
            conn.prepare_cached("INSERT OR IGNORE INTO rollup_over (dim, minute) VALUES (?, ?)")?;
        let minutes: BTreeSet<i64> = self.light.rows.keys().map(|(minute, _)| *minute).collect();
        for minute in minutes {
            up.execute(params![dim::ANY, minute])?;
        }
        Ok(())
    }

    fn apply_tops(&self, conn: &Connection) -> Result<()> {
        let mut up = conn.prepare_cached(&upsert_dim(&HOURLY))?;
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
        let mut up = conn.prepare_cached(&upsert_path(&HOURLY))?;
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
