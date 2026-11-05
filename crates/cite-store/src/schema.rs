use std::io;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rusqlite::{Connection, OpenFlags};

use crate::error::{Error, Result};

/// Schema version this build writes; databases with a higher version are refused.
pub const SCHEMA_VERSION: i64 = 3;

// Dictionary kinds: each distinct (kind, value) pair gets one integer id in the dict table.
pub(crate) mod kind {
    pub const HOST: u8 = 0;
    pub const METHOD: u8 = 1;
    pub const USER_AGENT: u8 = 2;
    pub const REFERER: u8 = 3;
    pub const CONTENT_TYPE: u8 = 4;
    pub const BACKEND: u8 = 5;
    pub const SERVER: u8 = 6;
    pub const SITE: u8 = 7;
    pub const BLOCKED: u8 = 8;
    pub const HTTP_VERSION: u8 = 9;
    pub const ACCEPT: u8 = 10;
    pub const ACCEPT_LANGUAGE: u8 = 11;
    pub const ACCEPT_ENCODING: u8 = 12;
    pub const SEC_FETCH_SITE: u8 = 13;
    pub const SEC_FETCH_MODE: u8 = 14;
    pub const SEC_FETCH_DEST: u8 = 15;
    pub const SEC_CH_UA: u8 = 16;
    pub const TLS_VERSION: u8 = 17;
    pub const BOT_CLASS: u8 = 18;
    pub const BOT_SIGNALS: u8 = 19;
    pub const CLIENT_IP: u8 = 20;
    pub const CONTENT_TYPE_NORM: u8 = 21;
    pub const SIGNAL: u8 = 22;
    pub const COUNT: usize = 23;
}

// Dimensions kept in rollup_dim; key_id is a dict id except for STATUS and SCORE, which store the number itself.
pub(crate) mod dim {
    pub const METHOD: u8 = 1;
    pub const CONTENT_TYPE: u8 = 2;
    pub const HOST: u8 = 3;
    pub const BLOCKED: u8 = 4;
    pub const STATUS: u8 = 5;
    pub const LANGUAGE: u8 = 6;
    pub const BOT_CLASS: u8 = 7;
    pub const SIGNAL: u8 = 8;
    pub const SCORE: u8 = 9;
    pub const CLIENT_IP: u8 = 10;
    pub const USER_AGENT: u8 = 11;
    pub const REFERER: u8 = 12;
    pub const BOT_AGENT: u8 = 13;
    pub const PATH: u8 = 14;
    // In rollup_over: the minute was written without minute rollups at all.
    pub const ANY: u8 = 0;
}

// Site scope of rollup_dim and rollup_path rows that sum every site, so unfiltered queries read one narrow range.
pub(crate) const ALL_SITES: i64 = -1;
// Heaviest keys kept per (scope, hour, dimension) from each write batch; the rest of a batch's tail is not rolled up.
pub(crate) const TOP_KEEP: usize = 32;

// Table and column names of one rollup granularity; the minute tables hold the same shapes as the hourly ones.
pub(crate) struct Level {
    pub(crate) rollup: &'static str,
    pub(crate) hist: &'static str,
    pub(crate) dim: &'static str,
    pub(crate) path: &'static str,
    pub(crate) bucket: &'static str,
}

pub(crate) const HOURLY: Level = Level {
    rollup: "rollup",
    hist: "rollup_hist",
    dim: "rollup_dim",
    path: "rollup_path",
    bucket: "hour",
};

pub(crate) const MINUTELY: Level = Level {
    rollup: "rollup_min",
    hist: "rollup_hist_min",
    dim: "rollup_dim_min",
    path: "rollup_path_min",
    bucket: "minute",
};

pub(crate) mod series {
    pub const LATENCY: u8 = 0;
    pub const SIZE: u8 = 1;
}

const V1: &str = "
CREATE TABLE dict (
    id INTEGER PRIMARY KEY,
    kind INTEGER NOT NULL,
    val TEXT NOT NULL,
    UNIQUE (kind, val)
);
CREATE TABLE requests (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    client_ip_id INTEGER,
    host_id INTEGER,
    method_id INTEGER,
    path TEXT NOT NULL,
    query_len INTEGER NOT NULL,
    status INTEGER NOT NULL,
    bytes_in INTEGER NOT NULL,
    bytes_out INTEGER NOT NULL,
    total_ms INTEGER NOT NULL,
    ua_id INTEGER,
    referer_id INTEGER,
    ctype_id INTEGER,
    backend_id INTEGER,
    server_id INTEGER,
    site_id INTEGER NOT NULL DEFAULT 0,
    blocked_id INTEGER,
    http_version_id INTEGER,
    accept_id INTEGER,
    accept_lang_id INTEGER,
    accept_enc_id INTEGER,
    sfs_id INTEGER,
    sfm_id INTEGER,
    sfd_id INTEGER,
    sec_ch_ua_id INTEGER,
    tls_id INTEGER,
    resp_ms INTEGER NOT NULL,
    bot_score INTEGER NOT NULL,
    bot_class_id INTEGER,
    bot_signals_id INTEGER
);
CREATE INDEX idx_requests_ts ON requests (ts);
CREATE INDEX idx_requests_site_ts ON requests (site_id, ts);
CREATE INDEX idx_requests_status_ts ON requests (status, ts);
CREATE INDEX idx_requests_bot_ts ON requests (bot_class_id, ts);
CREATE INDEX idx_requests_ip_ts ON requests (client_ip_id, ts);
CREATE INDEX idx_requests_path ON requests (path);
CREATE TABLE rollup (
    hour INTEGER NOT NULL,
    site_id INTEGER NOT NULL,
    requests INTEGER NOT NULL,
    bytes_in INTEGER NOT NULL,
    bytes_out INTEGER NOT NULL,
    s0 INTEGER NOT NULL,
    s1 INTEGER NOT NULL,
    s2 INTEGER NOT NULL,
    s3 INTEGER NOT NULL,
    s4 INTEGER NOT NULL,
    s5 INTEGER NOT NULL,
    blocked INTEGER NOT NULL,
    bot_requests INTEGER NOT NULL,
    ms_sum INTEGER NOT NULL,
    PRIMARY KEY (hour, site_id)
) WITHOUT ROWID;
CREATE TABLE rollup_hist (
    hour INTEGER NOT NULL,
    site_id INTEGER NOT NULL,
    series INTEGER NOT NULL,
    bucket INTEGER NOT NULL,
    n INTEGER NOT NULL,
    PRIMARY KEY (hour, site_id, series, bucket)
) WITHOUT ROWID;
CREATE TABLE rollup_dim (
    hour INTEGER NOT NULL,
    site_id INTEGER NOT NULL,
    dim INTEGER NOT NULL,
    key_id INTEGER NOT NULL,
    n INTEGER NOT NULL,
    bytes INTEGER NOT NULL,
    PRIMARY KEY (hour, site_id, dim, key_id)
) WITHOUT ROWID;
";

// Backfills the top-key rollups from raw rows: the TOP_KEEP heaviest keys per hour, for each site and for all sites.
macro_rules! backfill {
    ($into:literal, $lead:literal, $key:literal, $filter:literal, $scope:literal, $by:literal) => {
        concat!(
            "INSERT INTO ",
            $into,
            " SELECT ",
            $lead,
            $scope,
            ", hour, k, n, b FROM (",
            "SELECT ",
            $by,
            "hour, k, n, b, row_number() OVER (PARTITION BY ",
            $by,
            "hour ",
            "ORDER BY n DESC, k) AS rn FROM (",
            "SELECT ",
            $by,
            "(ts - ((ts % 3600000) + 3600000) % 3600000) / 3600000 AS hour, ",
            $key,
            " AS k, count(*) AS n, coalesce(sum(bytes_out), 0) AS b FROM requests ",
            "WHERE ",
            $key,
            " IS NOT NULL ",
            $filter,
            " GROUP BY ",
            $by,
            "hour, k)) WHERE rn <= 32;\n"
        )
    };
}

macro_rules! backfill_both {
    ($into:literal, $lead:literal, $key:literal, $filter:literal) => {
        concat!(
            backfill!($into, $lead, $key, $filter, "site_id", "site_id, "),
            backfill!($into, $lead, $key, $filter, "-1", "")
        )
    };
}

const V2: &str = concat!(
    "
CREATE TABLE rollup_dim_v2 (
    dim INTEGER NOT NULL,
    site_id INTEGER NOT NULL,
    hour INTEGER NOT NULL,
    key_id INTEGER NOT NULL,
    n INTEGER NOT NULL,
    bytes INTEGER NOT NULL,
    PRIMARY KEY (dim, site_id, hour, key_id)
) WITHOUT ROWID;
INSERT INTO rollup_dim_v2 SELECT dim, site_id, hour, key_id, n, bytes FROM rollup_dim;
INSERT INTO rollup_dim_v2 SELECT dim, -1, hour, key_id, sum(n), sum(bytes) FROM rollup_dim GROUP BY dim, hour, key_id;
DROP TABLE rollup_dim;
ALTER TABLE rollup_dim_v2 RENAME TO rollup_dim;
-- Random keys dirty a leaf per row on every commit: ip is indexed by a 256-way bucket of its id and path not at all.
DROP INDEX idx_requests_ip_ts;
DROP INDEX idx_requests_path;
CREATE INDEX idx_requests_ip_bucket ON requests ((client_ip_id % 256), ts);
CREATE TABLE rollup_path (
    site_id INTEGER NOT NULL,
    hour INTEGER NOT NULL,
    path TEXT NOT NULL,
    n INTEGER NOT NULL,
    bytes INTEGER NOT NULL,
    PRIMARY KEY (site_id, hour, path)
) WITHOUT ROWID;
",
    backfill_both!("rollup_path", "", "path", "AND path <> ''"),
    backfill_both!("rollup_dim", "10, ", "client_ip_id", ""),
    backfill_both!("rollup_dim", "11, ", "ua_id", ""),
    backfill_both!("rollup_dim", "12, ", "referer_id", ""),
    backfill_both!(
        "rollup_dim",
        "13, ",
        "ua_id",
        "AND bot_class_id IN (SELECT id FROM dict WHERE kind = 18 AND val <> 'human')"
    ),
);

// Minute rollups for windows of up to six hours. rollup_state.folded_id marks the last request id whose heavy keys (paths, client ips, agents, referers) are in the minute tables; newer rows are read raw. valid_from is the first minute the tables cover completely, so windows reaching further back keep reading raw rows. idx_rollup_path_min_hot holds the paths seen at least twice in a minute, which lets the top path query skip the long tail. rollup_over lists minutes whose key count passed the cap and were dropped from the tables.
const V3: &str = "
CREATE TABLE rollup_min (
    minute INTEGER NOT NULL,
    site_id INTEGER NOT NULL,
    requests INTEGER NOT NULL,
    bytes_in INTEGER NOT NULL,
    bytes_out INTEGER NOT NULL,
    s0 INTEGER NOT NULL,
    s1 INTEGER NOT NULL,
    s2 INTEGER NOT NULL,
    s3 INTEGER NOT NULL,
    s4 INTEGER NOT NULL,
    s5 INTEGER NOT NULL,
    blocked INTEGER NOT NULL,
    bot_requests INTEGER NOT NULL,
    ms_sum INTEGER NOT NULL,
    PRIMARY KEY (minute, site_id)
) WITHOUT ROWID;
CREATE TABLE rollup_hist_min (
    minute INTEGER NOT NULL,
    site_id INTEGER NOT NULL,
    series INTEGER NOT NULL,
    bucket INTEGER NOT NULL,
    n INTEGER NOT NULL,
    PRIMARY KEY (minute, site_id, series, bucket)
) WITHOUT ROWID;
CREATE TABLE rollup_dim_min (
    dim INTEGER NOT NULL,
    site_id INTEGER NOT NULL,
    minute INTEGER NOT NULL,
    key_id INTEGER NOT NULL,
    n INTEGER NOT NULL,
    bytes INTEGER NOT NULL,
    PRIMARY KEY (dim, site_id, minute, key_id)
) WITHOUT ROWID;
CREATE TABLE rollup_path_min (
    site_id INTEGER NOT NULL,
    minute INTEGER NOT NULL,
    path TEXT NOT NULL,
    n INTEGER NOT NULL,
    bytes INTEGER NOT NULL,
    PRIMARY KEY (site_id, minute, path)
) WITHOUT ROWID;
CREATE INDEX idx_rollup_path_min_hot ON rollup_path_min (site_id, minute, path, n, bytes) WHERE n >= 2;
CREATE TABLE rollup_over (
    dim INTEGER NOT NULL,
    minute INTEGER NOT NULL,
    PRIMARY KEY (dim, minute)
) WITHOUT ROWID;
CREATE TABLE rollup_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    folded_id INTEGER NOT NULL,
    valid_from INTEGER NOT NULL
);
INSERT INTO rollup_state (id, folded_id, valid_from)
    SELECT 1, coalesce(max(id), 0), coalesce(max(ts) / 60000 + 1, 0) FROM requests;
";

// Forward-only: entry i upgrades user_version i to i + 1. Never edit a shipped entry, append a new one.
pub(crate) const MIGRATIONS: &[&str] = &[V1, V2, V3];

pub(crate) const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

// auto_vacuum only takes effect on a new file. WAL with synchronous=NORMAL fsyncs on checkpoint rather than on every commit, which is the right trade for an analytics log. The writer keeps temp_store=MEMORY because its sorts are tiny. A 64 MiB page cache and 256 MiB mmap let the hot index pages stay resident; the WAL is truncated to 128 MiB after a checkpoint and auto-checkpointed every 25000 pages (about 100 MiB) so it cannot grow without bound.
const WRITER_PRAGMAS: &str = "
PRAGMA auto_vacuum = INCREMENTAL;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA temp_store = MEMORY;
PRAGMA secure_delete = FAST;
PRAGMA cache_size = -65536;
PRAGMA mmap_size = 268435456;
PRAGMA wal_autocheckpoint = 25000;
PRAGMA journal_size_limit = 134217728;
";

// Readers are read-only and share the mmap; a smaller cache each keeps a pool of them cheap. temp_store=FILE lets a group-by over hostile cardinality spill its sorter to disk instead of growing the heap.
const READER_PRAGMAS: &str = "
PRAGMA temp_store = FILE;
PRAGMA cache_size = -16384;
PRAGMA mmap_size = 268435456;
PRAGMA query_only = ON;
";

// SQLite applies both limits to the whole process. The caches of a full pool are at most 64 MiB for the writer and 16 x 16 MiB for readers, so the soft limit leaves room for them and the hard limit makes a runaway query fail with an out-of-memory error rather than take the host down.
const SOFT_HEAP_LIMIT: u64 = 512 * 1024 * 1024;
const HARD_HEAP_LIMIT: u64 = 1024 * 1024 * 1024;

// Virtual-machine steps between deadline checks on a reader.
const PROGRESS_STEPS: i32 = 1000;

#[cfg(unix)]
fn create_private(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .map(|_| ())
}

#[cfg(not(unix))]
fn create_private(path: &Path) -> io::Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map(|_| ())
}

// Applies the file modes only when an existing path is looser than wanted, so a database created by an older build or restored from a backup stops being readable by other users.
#[cfg(unix)]
fn tighten(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(meta) if meta.permissions().mode() & 0o077 != 0 => {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        }
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(not(unix))]
fn tighten(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

fn sidecar(path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    name.into()
}

fn enforce_modes(path: &Path) -> io::Result<()> {
    if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        tighten(dir, 0o700)?;
    }
    tighten(path, 0o600)?;
    tighten(&sidecar(path, "-wal"), 0o600)?;
    tighten(&sidecar(path, "-shm"), 0o600)
}

fn limit_memory(conn: &Connection) -> Result<()> {
    conn.execute_batch(&format!(
        "PRAGMA soft_heap_limit = {SOFT_HEAP_LIMIT}; PRAGMA hard_heap_limit = {HARD_HEAP_LIMIT};"
    ))?;
    Ok(())
}

// A read connection whose running statement is interrupted once the armed deadline passes.
pub(crate) struct Reader {
    pub(crate) conn: Connection,
    base: Instant,
    deadline_ns: Arc<AtomicU64>,
}

impl Reader {
    pub(crate) fn arm(&self, limit: Duration) {
        let at = self.base.elapsed().saturating_add(limit);
        let ns = u64::try_from(at.as_nanos()).unwrap_or(u64::MAX).max(1);
        self.deadline_ns.store(ns, Ordering::Relaxed);
    }

    pub(crate) fn disarm(&self) {
        self.deadline_ns.store(0, Ordering::Relaxed);
    }
}

fn open_conn(path: &Path, flags: OpenFlags) -> Result<Connection> {
    Connection::open_with_flags(path, flags).map_err(|source| Error::Open {
        path: path.to_path_buf(),
        source,
    })
}

fn user_version(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("PRAGMA user_version", [], |r| r.get(0))
}

// Applies the steps after the database's current version, each in its own transaction.
pub(crate) fn migrate(conn: &mut Connection, steps: &[&str]) -> Result<()> {
    let found = user_version(conn)?;
    let supported = steps.len() as i64;
    if found > supported {
        return Err(Error::NewerSchema { found, supported });
    }
    let start = usize::try_from(found.max(0)).unwrap_or(0);
    for (i, sql) in steps.iter().enumerate().skip(start) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.execute_batch(&format!("PRAGMA user_version = {}", i + 1))?;
        tx.commit()?;
    }
    Ok(())
}

pub(crate) fn open_writer(path: &Path) -> Result<Connection> {
    if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty())
        && !dir.is_dir()
    {
        return Err(Error::MissingDir(dir.to_path_buf()));
    }
    create_private(path)?;
    enforce_modes(path)?;
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let mut conn = open_conn(path, flags)?;
    conn.busy_timeout(BUSY_TIMEOUT)?;
    let found = user_version(&conn).map_err(|source| Error::Open {
        path: path.to_path_buf(),
        source,
    })?;
    if found > SCHEMA_VERSION {
        return Err(Error::NewerSchema {
            found,
            supported: SCHEMA_VERSION,
        });
    }
    conn.execute_batch(WRITER_PRAGMAS)?;
    limit_memory(&conn)?;
    migrate(&mut conn, MIGRATIONS)?;
    conn.set_prepared_statement_cache_capacity(64);
    enforce_modes(path)?;
    Ok(conn)
}

pub(crate) fn open_reader(path: &Path) -> Result<Reader> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = open_conn(path, flags)?;
    conn.busy_timeout(BUSY_TIMEOUT)?;
    conn.execute_batch(READER_PRAGMAS)?;
    limit_memory(&conn)?;
    conn.set_prepared_statement_cache_capacity(64);
    let base = Instant::now();
    let deadline_ns = Arc::new(AtomicU64::new(0));
    let armed = Arc::clone(&deadline_ns);
    conn.progress_handler(
        PROGRESS_STEPS,
        Some(move || {
            let at = armed.load(Ordering::Relaxed);
            at != 0 && u64::try_from(base.elapsed().as_nanos()).unwrap_or(u64::MAX) >= at
        }),
    );
    Ok(Reader {
        conn,
        base,
        deadline_ns,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(conn: &Connection) -> i64 {
        user_version(conn).expect("version")
    }

    #[test]
    fn migrations_run_in_order_and_only_once() {
        let mut conn = Connection::open_in_memory().expect("open");
        let steps = [
            "CREATE TABLE a (x INTEGER);",
            "CREATE TABLE b (y INTEGER); INSERT INTO a VALUES (1);",
        ];
        migrate(&mut conn, &steps).expect("migrate");
        assert_eq!(version(&conn), 2);
        migrate(&mut conn, &steps).expect("rerun");
        let rows: i64 = conn
            .query_row("SELECT count(*) FROM a", [], |r| r.get(0))
            .expect("count");
        assert_eq!(rows, 1);
    }

    #[test]
    fn migration_resumes_from_the_stored_version() {
        let mut conn = Connection::open_in_memory().expect("open");
        migrate(&mut conn, &["CREATE TABLE a (x INTEGER);"]).expect("first");
        let steps = ["CREATE TABLE a (x INTEGER);", "CREATE TABLE b (y INTEGER);"];
        migrate(&mut conn, &steps).expect("second");
        assert_eq!(version(&conn), 2);
    }

    #[test]
    fn failed_migration_leaves_the_version_untouched() {
        let mut conn = Connection::open_in_memory().expect("open");
        let steps = ["CREATE TABLE a (x INTEGER);", "THIS IS NOT SQL"];
        assert!(migrate(&mut conn, &steps).is_err());
        assert_eq!(version(&conn), 1);
    }

    #[test]
    fn newer_database_is_refused() {
        let mut conn = Connection::open_in_memory().expect("open");
        conn.execute_batch("PRAGMA user_version = 7").expect("set");
        match migrate(&mut conn, MIGRATIONS) {
            Err(Error::NewerSchema {
                found: 7,
                supported,
            }) => {
                assert_eq!(supported, SCHEMA_VERSION);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn schema_declares_the_expected_indexes_only() {
        let mut conn = Connection::open_in_memory().expect("open");
        migrate(&mut conn, MIGRATIONS).expect("migrate");
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_%' ORDER BY name")
            .expect("prepare");
        let names: Vec<String> = stmt
            .query_map([], |r| r.get(0))
            .expect("query")
            .collect::<std::result::Result<_, _>>()
            .expect("rows");
        assert_eq!(
            names,
            [
                "idx_requests_bot_ts",
                "idx_requests_ip_bucket",
                "idx_requests_site_ts",
                "idx_requests_status_ts",
                "idx_requests_ts",
                "idx_rollup_path_min_hot",
            ]
        );
    }
}
