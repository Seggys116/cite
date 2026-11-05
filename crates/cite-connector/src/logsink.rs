use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cite_core::atomic::read_limited;
use cite_edge::analytics::{Analytics, RequestFilter, Snapshot};
use cite_edge::logparse::parse_datagram;
use cite_edge::model::{LogEvent, Retention};
use socket2::SockRef;
use tokio::net::{UdpSocket, UnixDatagram};
use tokio::sync::Notify;
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, interval, sleep, timeout};

use crate::config::{ConnectorConfig, LogListen};
use crate::store::Store;
use crate::{ConnectorError, Result};

const DATAGRAM_BUF: usize = 16 * 1024;
const BATCH: usize = 256;
// Batches queued between the socket reader and the writer thread; a full queue stops the reader.
const QUEUE_BATCHES: usize = 64;
const FLUSH_EVERY: Duration = Duration::from_millis(100);
const RECV_BACKOFF: Duration = Duration::from_millis(50);
// On shutdown the socket is read until it has been quiet this long, but never for longer than DRAIN_MAX.
const DRAIN_IDLE: Duration = Duration::from_millis(100);
const DRAIN_MAX: Duration = Duration::from_secs(2);
const MAINTENANCE_EVERY: Duration = Duration::from_secs(600);
const SNAPSHOT_FILE: &str = "analytics.json";
const MIGRATED_FILE: &str = "analytics.json.migrated";
// A snapshot is at most a few hundred MiB; anything larger is not one of ours.
const LEGACY_MAX_BYTES: u64 = 1 << 30;
// The largest recent-event list the old settings allowed.
const LEGACY_MAX_EVENTS: usize = 200_000;
const RECV_BUFFER: usize = 4 * 1024 * 1024;
const SOCKET_MODE: u32 = 0o600;
const DIR_MODE: u32 = 0o700;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

// Counters for the ingest path, shown next to the store statistics.
#[derive(Debug, Default)]
pub struct IngestStats {
    stalls: AtomicU64,
}

impl IngestStats {
    // Times the socket reader had to wait because the writer could not keep up.
    pub fn stalls(&self) -> u64 {
        self.stalls.load(Ordering::Relaxed)
    }

    fn record_stall(&self) {
        self.stalls.fetch_add(1, Ordering::Relaxed);
    }
}

// Age retention follows the longest-lived bucket setting, which is what the old collector kept longest.
pub fn retention_days(retention: &Retention) -> u32 {
    retention.hour_buckets_days
}

// The database directory is private to the connector user; the file inside inherits that protection.
pub fn open_store(cfg: &ConnectorConfig, retention_days: u32) -> Result<Arc<cite_store::Store>> {
    let path = &cfg.analytics_db;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        DirBuilder::new()
            .recursive(true)
            .mode(DIR_MODE)
            .create(dir)
            .map_err(|e| {
                ConnectorError::Internal(format!(
                    "cannot create analytics directory {}: {e}",
                    dir.display()
                ))
            })?;
    }
    let opts = cite_store::StoreOptions {
        retention_days,
        max_bytes: cfg.analytics_max_bytes,
        ..cite_store::StoreOptions::default()
    };
    cite_store::Store::open(path, opts)
        .map(Arc::new)
        .map_err(|e| {
            ConnectorError::Internal(format!(
                "cannot open analytics database {}: {e}",
                path.display()
            ))
        })
}

fn import_snapshot(
    path: &Path,
    store: &cite_store::Store,
    max_bytes: u64,
    retention: &Retention,
) -> std::result::Result<usize, String> {
    let bytes = read_limited(path, max_bytes).map_err(|e| e.to_string())?;
    let snapshot: Snapshot = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    // Only the recent-event list can be turned back into rows; the bucket counters have no per-request data.
    let keep_all = Retention {
        recent_events: LEGACY_MAX_EVENTS,
        store_client_ips: true,
        store_user_agents: true,
        ..Retention::default()
    };
    let restored = Analytics::restore_with_budget(keep_all, usize::MAX, snapshot);
    let mut events = restored.requests(&RequestFilter::default(), usize::MAX);
    events.reverse();
    // The old file always carried both fields; the live privacy settings decide what is kept.
    apply_privacy(&mut events, retention);
    store
        .import_events(events.into_iter())
        .map_err(|e| e.to_string())
}

// Runs once: a snapshot that imports is deleted, one that cannot be read is left in place.
pub fn migrate_snapshot(data_dir: &Path, store: &cite_store::Store, retention: &Retention) {
    migrate_from(data_dir, store, LEGACY_MAX_BYTES, retention);
}

fn migrate_from(data_dir: &Path, store: &cite_store::Store, max_bytes: u64, retention: &Retention) {
    let leftover = data_dir.join(MIGRATED_FILE);
    if leftover.exists() {
        match fs::remove_file(&leftover) {
            Ok(()) => tracing::info!(
                "removed {}, left by an earlier migration",
                leftover.display()
            ),
            Err(err) => tracing::warn!("could not remove {}: {err}", leftover.display()),
        }
    }
    let path = data_dir.join(SNAPSHOT_FILE);
    if !path.exists() {
        return;
    }
    match import_snapshot(&path, store, max_bytes, retention) {
        Ok(rows) => match fs::remove_file(&path) {
            Ok(()) => tracing::info!(
                "imported {rows} events from {} into the analytics database and deleted the file",
                path.display()
            ),
            Err(err) => tracing::error!(
                "imported {rows} events from {} but could not delete it, a restart will import them again: {err}",
                path.display()
            ),
        },
        Err(err) => tracing::warn!(
            "leaving unreadable analytics snapshot {} in place: {err}",
            path.display()
        ),
    }
}

fn apply_privacy(batch: &mut [LogEvent], retention: &Retention) {
    if retention.store_client_ips && retention.store_user_agents {
        return;
    }
    for event in batch {
        if !retention.store_client_ips {
            event.client_ip.clear();
        }
        if !retention.store_user_agents {
            event.user_agent.clear();
        }
    }
}

enum Sink {
    Udp(UdpSocket),
    Unix(UnixDatagram),
}

impl Sink {
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Sink::Udp(socket) => socket.recv_from(buf).await.map(|(len, _)| len),
            Sink::Unix(socket) => socket.recv(buf).await,
        }
    }

    fn try_recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Sink::Udp(socket) => socket.try_recv_from(buf).map(|(len, _)| len),
            Sink::Unix(socket) => socket.try_recv(buf),
        }
    }

    // The default kernel buffer drops bursts; failing to enlarge it only costs headroom.
    fn grow_receive_buffer(&self) {
        let grown = match self {
            Sink::Udp(socket) => SockRef::from(socket).set_recv_buffer_size(RECV_BUFFER),
            Sink::Unix(socket) => SockRef::from(socket).set_recv_buffer_size(RECV_BUFFER),
        };
        if let Err(err) = grown {
            tracing::warn!("log sink could not enlarge its receive buffer: {err}");
        }
    }
}

// A stale socket file from a previous run would make the bind fail.
fn bind_unix(path: &Path) -> io::Result<UnixDatagram> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let socket = UnixDatagram::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(SOCKET_MODE))?;
    Ok(socket)
}

async fn bind_sink(listen: &LogListen) -> io::Result<Sink> {
    match listen {
        LogListen::Udp(addr) => UdpSocket::bind(addr).await.map(Sink::Udp),
        LogListen::Unix(path) => bind_unix(path).map(Sink::Unix),
    }
}

// A full queue makes the reader wait instead of discarding, so overload shows up as kernel socket drops at worst.
async fn hand_off(
    tx: &mpsc::Sender<Vec<LogEvent>>,
    batch: &mut Vec<LogEvent>,
    stats: &IngestStats,
) -> bool {
    if batch.is_empty() {
        return true;
    }
    let full = std::mem::replace(batch, Vec::with_capacity(BATCH));
    match tx.try_send(full) {
        Ok(()) => true,
        Err(TrySendError::Full(full)) => {
            stats.record_stall();
            tx.send(full).await.is_ok()
        }
        Err(TrySendError::Closed(_)) => false,
    }
}

// Reads what peers already sent until the socket has been quiet for DRAIN_IDLE, or DRAIN_MAX has passed. try_recv is
// not enough here: it reports WouldBlock until the reactor has seen the readiness, which can lag behind the kernel.
async fn drain_socket(
    sink: &Sink,
    buf: &mut [u8],
    batch: &mut Vec<LogEvent>,
    tx: &mpsc::Sender<Vec<LogEvent>>,
    stats: &IngestStats,
) {
    let until = Instant::now() + DRAIN_MAX;
    while Instant::now() < until {
        let Ok(Ok(len)) = timeout(DRAIN_IDLE, sink.recv(buf)).await else {
            break;
        };
        if let Some(event) = parse_datagram(&buf[..len], now_ms()) {
            batch.push(event);
        }
        if batch.len() >= BATCH && !hand_off(tx, batch, stats).await {
            break;
        }
    }
}

// Runs until stop is notified, then takes what the kernel already queued and hands its last batch to the writer.
async fn receive_loop(
    sink: Sink,
    tx: mpsc::Sender<Vec<LogEvent>>,
    stats: Arc<IngestStats>,
    stop: Arc<Notify>,
) {
    sink.grow_receive_buffer();
    let mut buf = vec![0u8; DATAGRAM_BUF];
    let mut batch: Vec<LogEvent> = Vec::with_capacity(BATCH);
    let mut reported = 0u64;
    let mut tick = interval(FLUSH_EVERY);
    // Delayed ticks avoid a burst of back-to-back flushes after a busy stretch.
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = stop.notified() => {
                drain_socket(&sink, &mut buf, &mut batch, &tx, &stats).await;
                if !hand_off(&tx, &mut batch, &stats).await {
                    tracing::error!("analytics writer is gone; events received before shutdown were lost");
                }
                return;
            }
            received = sink.recv(&mut buf) => match received {
                Ok(len) => {
                    let now = now_ms();
                    if let Some(event) = parse_datagram(&buf[..len], now) {
                        batch.push(event);
                    }
                    // datagrams already queued in the kernel are taken without another trip through the scheduler
                    for _ in 0..BATCH {
                        let Ok(len) = sink.try_recv(&mut buf) else {
                            break;
                        };
                        if let Some(event) = parse_datagram(&buf[..len], now) {
                            batch.push(event);
                        }
                    }
                    if batch.len() >= BATCH && !hand_off(&tx, &mut batch, &stats).await {
                        tracing::error!("analytics writer is gone; the log sink is stopping");
                        return;
                    }
                }
                Err(err) => {
                    tracing::warn!("log sink receive failed: {err}");
                    sleep(RECV_BACKOFF).await;
                }
            },
            _ = tick.tick() => {
                if !hand_off(&tx, &mut batch, &stats).await {
                    tracing::error!("analytics writer is gone; the log sink is stopping");
                    return;
                }
                let stalls = stats.stalls();
                if stalls > reported {
                    tracing::warn!(
                        "log sink waited on the analytics writer {} times; datagrams may be dropped by the kernel",
                        stalls - reported
                    );
                    reported = stalls;
                }
            }
        }
    }
}

// Runs on a blocking thread because Writer::send waits when the writer queue is full.
fn forward(
    mut rx: mpsc::Receiver<Vec<LogEvent>>,
    writer: cite_store::Writer,
    retention: impl Fn() -> Retention,
) {
    while let Some(mut batch) = rx.blocking_recv() {
        apply_privacy(&mut batch, &retention());
        let total = batch.len();
        for (sent, event) in batch.into_iter().enumerate() {
            if let Err(err) = writer.send(event) {
                tracing::error!(
                    lost = total - sent,
                    "analytics writer stopped, events are being lost: {err}"
                );
                return;
            }
        }
    }
    if let Err(err) = writer.flush() {
        tracing::error!("analytics writer could not commit the last events: {err}");
    }
}

fn pipeline(
    writer: cite_store::Writer,
    retention: impl Fn() -> Retention + Send + 'static,
) -> (mpsc::Sender<Vec<LogEvent>>, JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(QUEUE_BATCHES);
    let forwarder = tokio::task::spawn_blocking(move || forward(rx, writer, retention));
    (tx, forwarder)
}

// The only scheduled owner of retention: it runs on a blocking thread, apart from the ingest path, and also covers an
// idle node. A settings change triggers an extra pass through the same store lock.
async fn maintenance_loop(store: Arc<cite_store::Store>) {
    let mut tick = interval(MAINTENANCE_EVERY);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let target = Arc::clone(&store);
        match tokio::task::spawn_blocking(move || target.prune(now_ms())).await {
            Ok(Ok(report)) => {
                if report.expired_rows > 0
                    || report.trimmed_rows > 0
                    || report.dict_rows_removed > 0
                {
                    tracing::info!(
                        expired = report.expired_rows,
                        trimmed = report.trimmed_rows,
                        dictionary = report.dict_rows_removed,
                        bytes_before = report.bytes_before,
                        bytes_after = report.bytes_after,
                        "analytics retention applied"
                    );
                }
            }
            Ok(Err(err)) => tracing::warn!("analytics retention failed: {err}"),
            Err(err) => tracing::warn!("analytics retention task failed: {err}"),
        }
    }
}

// Handles to the running log receiver, kept so shutdown can drain what is already queued.
pub struct LogSink {
    receiver: JoinHandle<()>,
    forwarder: JoinHandle<()>,
    stop: Arc<Notify>,
}

impl LogSink {
    // Tells the receiver to stop, which hands over its last batch and closes the queue; then waits until every
    // event has been committed to the database.
    pub async fn shutdown(self) {
        self.stop.notify_one();
        if let Err(err) = self.receiver.await {
            tracing::warn!("log receiver task failed: {err}");
        }
        if let Err(err) = self.forwarder.await {
            tracing::warn!("analytics drain task failed: {err}");
        }
    }
}

pub fn spawn(
    cfg: &ConnectorConfig,
    analytics: Arc<cite_store::Store>,
    settings: Arc<Store>,
    stats: Arc<IngestStats>,
) -> LogSink {
    let listen = cfg.log_listen.clone();
    let current = settings.config().settings.retention.clone();
    analytics.set_privacy(current.store_client_ips, current.store_user_agents);
    let (tx, forwarder) = pipeline(analytics.writer(), move || {
        settings.config().settings.retention.clone()
    });
    let stop = Arc::new(Notify::new());
    let halt = Arc::clone(&stop);
    let receiver = tokio::spawn(async move {
        let sink = match bind_sink(&listen).await {
            Ok(sink) => sink,
            Err(err) => {
                tracing::error!("log sink cannot bind {listen}: {err}");
                return;
            }
        };
        tracing::info!("log sink listening on {listen}");
        tokio::select! {
            () = receive_loop(sink, tx, stats, halt) => {}
            () = maintenance_loop(analytics) => {}
        }
    });
    LogSink {
        receiver,
        forwarder,
        stop,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testing::test_config;
    use cite_edge::analytics::write_snapshot;
    use cite_edge::logparse::LOG_FORMAT;
    use std::sync::Mutex;

    // Field values in LOG_FORMAT order; the count is asserted so a format change fails loudly.
    fn fields(ts: i64, backend: &str, path: &str, status: u16) -> Vec<String> {
        let list = vec![
            ts.to_string(),
            "203.0.113.9".into(),
            backend.into(),
            "t1".into(),
            "GET".into(),
            status.to_string(),
            "2048".into(),
            "300".into(),
            "12".into(),
            "0".into(),
            String::new(),
            String::new(),
            "HTTP/1.1".into(),
            String::new(),
            "5".into(),
            "shop.example.com".into(),
            path.into(),
            "curl%2F8".into(),
            "-".into(),
            "text%2Fhtml".into(),
            "*%2F*".into(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        ];
        assert_eq!(list.len(), LOG_FORMAT.split(' ').count());
        list
    }

    fn line(ts: i64, backend: &str, path: &str, status: u16) -> String {
        let body = fields(ts, backend, path, status).join(" ");
        format!("<134>Nov  4 12:00:00 edge haproxy[812]: {body}")
    }

    fn parsed(path: &str) -> LogEvent {
        let now = now_ms();
        parse_datagram(line(now, "be_shop_blue", path, 200).as_bytes(), now).unwrap()
    }

    fn open_test_store(dir: &Path) -> Arc<cite_store::Store> {
        let opts = cite_store::StoreOptions {
            flush_interval: Duration::from_millis(20),
            ..cite_store::StoreOptions::default()
        };
        Arc::new(cite_store::Store::open(&dir.join("test.db"), opts).unwrap())
    }

    fn rows(store: &cite_store::Store) -> u64 {
        store.stats().unwrap().rows
    }

    async fn wait_for(store: &cite_store::Store, want: u64) -> bool {
        for _ in 0..100 {
            if rows(store) >= want {
                return true;
            }
            sleep(Duration::from_millis(50)).await;
        }
        false
    }

    struct Rig {
        _dir: tempfile::TempDir,
        store: Arc<cite_store::Store>,
        stats: Arc<IngestStats>,
        receiver: JoinHandle<()>,
        _forwarder: JoinHandle<()>,
        _stop: Arc<Notify>,
    }

    fn rig(sink: Sink, dir: tempfile::TempDir) -> Rig {
        let store = open_test_store(dir.path());
        let stats = Arc::new(IngestStats::default());
        let (tx, forwarder) = pipeline(store.writer(), Retention::default);
        let stop = Arc::new(Notify::new());
        let receiver = tokio::spawn(receive_loop(sink, tx, stats.clone(), Arc::clone(&stop)));
        Rig {
            _dir: dir,
            store,
            stats,
            receiver,
            _forwarder: forwarder,
            _stop: stop,
        }
    }

    async fn udp_rig() -> (Rig, std::net::SocketAddr) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        (rig(Sink::Udp(socket), tempfile::tempdir().unwrap()), addr)
    }

    async fn sender() -> UdpSocket {
        UdpSocket::bind("127.0.0.1:0").await.unwrap()
    }

    #[tokio::test]
    async fn datagrams_reach_the_store() {
        let (r, addr) = udp_rig().await;
        let tx = sender().await;
        for i in 0..5 {
            let text = line(now_ms(), "be_shop_blue", &format!("/p{i}"), 200);
            tx.send_to(text.as_bytes(), addr).await.unwrap();
        }
        assert!(wait_for(&r.store, 5).await);
        let events = r.store.requests(&Default::default(), 10).unwrap();
        assert_eq!(events.len(), 5);
        assert!(events.iter().all(|e| e.site == "shop" && e.status == 200));
        assert_eq!(events[0].path, "/p4");
        assert_eq!(events[0].user_agent, "curl/8");
        r.receiver.abort();
    }

    // Run with: cargo test -p cite-connector --release perf_unix_receive -- --ignored --nocapture
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore]
    async fn perf_unix_receive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.sock");
        let sink = Sink::Unix(bind_unix(&path).unwrap());
        let r = rig(sink, dir);
        let total = 200_000u64;
        let target = path.clone();
        let texts: Vec<String> = (0..97)
            .map(|i| line(now_ms(), "be_shop_blue", &format!("/p{i}"), 200))
            .collect();
        let started = std::time::Instant::now();
        let sender = std::thread::spawn(move || {
            let tx = std::os::unix::net::UnixDatagram::unbound().unwrap();
            for i in 0..total as usize {
                // a full socket buffer rejects the send, so the sender waits for the sink to drain it
                while tx.send_to(texts[i % 97].as_bytes(), &target).is_err() {
                    std::thread::yield_now();
                }
            }
        });
        sender.join().unwrap();
        while rows(&r.store) < total {
            sleep(Duration::from_millis(5)).await;
        }
        let secs = started.elapsed().as_secs_f64();
        println!("unix receive: {:.0} events/s", total as f64 / secs);
        r.receiver.abort();
    }

    #[tokio::test]
    async fn garbage_datagrams_are_ignored() {
        let (r, addr) = udp_rig().await;
        let tx = sender().await;
        tx.send_to(b"hello world", addr).await.unwrap();
        tx.send_to(&[0xff, 0xfe, 0x00], addr).await.unwrap();
        tx.send_to(&vec![b'a'; 9000], addr).await.unwrap();
        let good = line(now_ms(), "be_shop_green", "/ok", 404);
        tx.send_to(good.as_bytes(), addr).await.unwrap();
        assert!(wait_for(&r.store, 1).await);
        sleep(Duration::from_millis(300)).await;
        let summary = r.store.summary(3600, None, now_ms()).unwrap();
        assert_eq!(summary.requests, 1);
        assert_eq!(summary.errors_4xx, 1);
        r.receiver.abort();
    }

    #[tokio::test]
    async fn per_site_scope_is_populated_from_the_backend_name() {
        let (r, addr) = udp_rig().await;
        let tx = sender().await;
        for backend in ["be_shop_blue", "be_blog_green", "be_blog_blue"] {
            let text = line(now_ms(), backend, "/", 200);
            tx.send_to(text.as_bytes(), addr).await.unwrap();
        }
        assert!(wait_for(&r.store, 3).await);
        let blog = r.store.summary(3600, Some("blog"), now_ms()).unwrap();
        assert_eq!(blog.requests, 2);
        r.receiver.abort();
    }

    #[tokio::test]
    async fn hand_off_waits_on_a_full_queue_and_counts_the_stall() {
        let (tx, mut rx) = mpsc::channel(1);
        let stats = Arc::new(IngestStats::default());
        let mut first = vec![parsed("/one")];
        assert!(hand_off(&tx, &mut first, &stats).await);
        assert!(first.is_empty());
        assert_eq!(stats.stalls(), 0);

        let (waiting_tx, waiting_stats) = (tx.clone(), stats.clone());
        let blocked = tokio::spawn(async move {
            let mut second = vec![parsed("/two")];
            hand_off(&waiting_tx, &mut second, &waiting_stats).await
        });
        sleep(Duration::from_millis(100)).await;
        assert!(!blocked.is_finished());
        assert_eq!(stats.stalls(), 1);

        assert_eq!(rx.recv().await.unwrap()[0].path, "/one");
        assert!(blocked.await.unwrap());
        assert_eq!(rx.recv().await.unwrap()[0].path, "/two");
    }

    #[tokio::test]
    async fn hand_off_reports_a_closed_queue() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let mut batch = vec![parsed("/gone")];
        assert!(!hand_off(&tx, &mut batch, &IngestStats::default()).await);
        assert!(hand_off(&tx, &mut Vec::new(), &IngestStats::default()).await);
    }

    #[tokio::test]
    async fn a_burst_through_a_tiny_writer_queue_loses_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let opts = cite_store::StoreOptions {
            queue_capacity: 4,
            batch_size: 50,
            flush_interval: Duration::from_millis(20),
            ..cite_store::StoreOptions::default()
        };
        let store = Arc::new(cite_store::Store::open(&dir.path().join("t.db"), opts).unwrap());
        let (tx, forwarder) = pipeline(store.writer(), Retention::default);
        let stats = IngestStats::default();
        let total = 5_000usize;
        let mut batch = Vec::new();
        for i in 0..total {
            batch.push(parsed(&format!("/b{i}")));
            if batch.len() == BATCH {
                assert!(hand_off(&tx, &mut batch, &stats).await);
            }
        }
        assert!(hand_off(&tx, &mut batch, &stats).await);
        drop(tx);
        forwarder.await.unwrap();
        assert_eq!(rows(&store), total as u64);
    }

    #[test]
    fn privacy_flags_clear_identities_before_storage() {
        let mut batch = vec![parsed("/p")];
        assert!(!batch[0].client_ip.is_empty() && !batch[0].user_agent.is_empty());
        apply_privacy(&mut batch, &Retention::default());
        assert!(!batch[0].client_ip.is_empty() && !batch[0].user_agent.is_empty());
        let no_ips = Retention {
            store_client_ips: false,
            ..Retention::default()
        };
        apply_privacy(&mut batch, &no_ips);
        assert!(batch[0].client_ip.is_empty());
        assert!(!batch[0].user_agent.is_empty());
        let nothing = Retention {
            store_client_ips: false,
            store_user_agents: false,
            ..Retention::default()
        };
        apply_privacy(&mut batch, &nothing);
        assert!(batch[0].user_agent.is_empty());
    }

    #[tokio::test]
    async fn the_forwarder_applies_the_live_privacy_settings() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_test_store(dir.path());
        let private = Retention {
            store_client_ips: false,
            ..Retention::default()
        };
        let (tx, forwarder) = pipeline(store.writer(), move || private.clone());
        tx.send(vec![parsed("/private")]).await.unwrap();
        drop(tx);
        forwarder.await.unwrap();
        let events = store.requests(&Default::default(), 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].client_ip, "");
        assert_eq!(events[0].user_agent, "curl/8");
    }

    #[test]
    fn retention_days_follow_the_hour_bucket_setting() {
        let r = Retention {
            hour_buckets_days: 12,
            ..Retention::default()
        };
        assert_eq!(retention_days(&r), 12);
    }

    fn snapshot_with(paths: &[&str]) -> Vec<u8> {
        let analytics = Mutex::new(Analytics::new(Retention::default()));
        for path in paths {
            analytics.lock().unwrap().record(parsed(path));
        }
        let mut out = Vec::new();
        write_snapshot(&analytics, &mut out).unwrap();
        out
    }

    #[test]
    fn an_old_snapshot_is_imported_once_and_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_test_store(dir.path());
        let file = dir.path().join(SNAPSHOT_FILE);
        std::fs::write(&file, snapshot_with(&["/a", "/b", "/c"])).unwrap();
        migrate_snapshot(dir.path(), &store, &Retention::default());
        assert!(!file.exists());
        assert!(!dir.path().join(MIGRATED_FILE).exists());
        assert_eq!(rows(&store), 3);
        let newest = store.requests(&Default::default(), 10).unwrap();
        assert_eq!(newest.len(), 3);
        assert!(
            newest
                .iter()
                .all(|e| e.site == "shop" && e.user_agent == "curl/8")
        );
        migrate_snapshot(dir.path(), &store, &Retention::default());
        assert_eq!(rows(&store), 3);
    }

    #[test]
    fn unreadable_snapshots_are_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_test_store(dir.path());
        let file = dir.path().join(SNAPSHOT_FILE);
        std::fs::write(&file, b"{ not json").unwrap();
        migrate_snapshot(dir.path(), &store, &Retention::default());
        assert!(file.exists());
        assert!(!dir.path().join(MIGRATED_FILE).exists());
        assert_eq!(rows(&store), 0);
    }

    #[test]
    fn oversized_snapshots_are_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_test_store(dir.path());
        let file = dir.path().join(SNAPSHOT_FILE);
        let bytes = snapshot_with(&["/a", "/b"]);
        std::fs::write(&file, &bytes).unwrap();
        migrate_from(
            dir.path(),
            &store,
            bytes.len() as u64 - 1,
            &Retention::default(),
        );
        assert!(file.exists());
        assert_eq!(rows(&store), 0);
        migrate_from(
            dir.path(),
            &store,
            bytes.len() as u64,
            &Retention::default(),
        );
        assert!(!file.exists());
        assert_eq!(rows(&store), 2);
    }

    #[test]
    fn the_import_applies_the_current_privacy_settings() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_test_store(dir.path());
        std::fs::write(dir.path().join(SNAPSHOT_FILE), snapshot_with(&["/a", "/b"])).unwrap();
        let private = Retention {
            store_client_ips: false,
            store_user_agents: false,
            ..Retention::default()
        };
        migrate_snapshot(dir.path(), &store, &private);
        let events = store.requests(&Default::default(), 10).unwrap();
        assert_eq!(events.len(), 2);
        assert!(
            events
                .iter()
                .all(|e| e.client_ip.is_empty() && e.user_agent.is_empty())
        );
    }

    #[test]
    fn a_leftover_migrated_copy_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_test_store(dir.path());
        let old = dir.path().join(MIGRATED_FILE);
        std::fs::write(&old, snapshot_with(&["/a"])).unwrap();
        migrate_snapshot(dir.path(), &store, &Retention::default());
        assert!(!old.exists());
        assert_eq!(rows(&store), 0);
    }

    #[tokio::test]
    async fn events_queued_under_old_settings_are_stripped_when_they_commit() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_test_store(dir.path());
        let stale = Retention::default();
        let (tx, forwarder) = pipeline(store.writer(), move || stale.clone());
        store.set_privacy(false, false);
        tx.send(vec![parsed("/late"), parsed("/later")])
            .await
            .unwrap();
        drop(tx);
        forwarder.await.unwrap();
        store.scrub_fields(true, true).unwrap();
        store.checkpoint().unwrap();
        let events = store.requests(&Default::default(), 10).unwrap();
        assert_eq!(events.len(), 2);
        assert!(
            events
                .iter()
                .all(|e| e.client_ip.is_empty() && e.user_agent.is_empty())
        );
        for name in ["test.db", "test.db-wal"] {
            let bytes = std::fs::read(dir.path().join(name)).unwrap_or_default();
            assert!(!bytes.windows(10).any(|w| w == b"203.0.113."));
            assert!(!bytes.windows(6).any(|w| w == b"curl/8"));
        }
    }

    #[test]
    fn a_missing_snapshot_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_test_store(dir.path());
        migrate_snapshot(dir.path(), &store, &Retention::default());
        assert_eq!(rows(&store), 0);
    }

    #[test]
    fn open_store_creates_a_private_directory_and_applies_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_config(dir.path());
        cfg.analytics_max_bytes = Some(64 * 1024 * 1024);
        let store = open_store(&cfg, 14).unwrap();
        let folder = cfg.analytics_db.parent().unwrap();
        let mode = std::fs::metadata(folder).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        assert!(cfg.analytics_db.exists());
        assert_eq!(store.retention_days(), 14);
        assert_eq!(store.max_bytes(), Some(64 * 1024 * 1024));
    }

    #[test]
    fn open_store_reports_an_unusable_location() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("file");
        std::fs::write(&blocker, b"x").unwrap();
        let mut cfg = test_config(dir.path());
        cfg.analytics_db = blocker.join("analytics.db");
        let err = open_store(&cfg, 30).err().expect("must fail");
        assert!(err.to_string().contains("analytics"));
    }

    #[tokio::test]
    async fn spawned_sink_binds_receives_shuts_down_and_survives_a_bad_bind() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_config(dir.path());
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let listen = probe.local_addr().unwrap();
        cfg.log_listen = LogListen::Udp(listen);
        drop(probe);
        let settings = Store::open(&cfg).await.unwrap();
        let analytics = open_store(&cfg, 30).unwrap();
        let sink = spawn(
            &cfg,
            analytics.clone(),
            settings.clone(),
            Arc::new(IngestStats::default()),
        );
        let tx = sender().await;
        let text = line(now_ms(), "be_shop_blue", "/spawned", 200);
        let mut seen = false;
        for _ in 0..60 {
            tx.send_to(text.as_bytes(), listen).await.unwrap();
            sleep(Duration::from_millis(50)).await;
            if !analytics
                .requests(&Default::default(), 1)
                .unwrap()
                .is_empty()
            {
                seen = true;
                break;
            }
        }
        assert!(seen, "events never arrived through spawn()");
        sink.shutdown().await;
        assert!(rows(&analytics) >= 1);

        let taken = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        cfg.log_listen = LogListen::Udp(taken.local_addr().unwrap());
        let failed = spawn(&cfg, analytics, settings, Arc::new(IngestStats::default()));
        let finished = tokio::time::timeout(Duration::from_secs(5), failed.receiver).await;
        assert!(finished.is_ok(), "spawn must return when bind fails");
    }

    #[tokio::test]
    async fn shutdown_commits_events_received_just_before_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_config(dir.path());
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let listen = probe.local_addr().unwrap();
        cfg.log_listen = LogListen::Udp(listen);
        drop(probe);
        let settings = Store::open(&cfg).await.unwrap();
        let analytics = open_store(&cfg, 30).unwrap();
        let sink = spawn(
            &cfg,
            analytics.clone(),
            settings,
            Arc::new(IngestStats::default()),
        );
        let tx = sender().await;
        let hello = line(now_ms(), "be_shop_blue", "/hello", 200);
        let mut up = false;
        for _ in 0..60 {
            tx.send_to(hello.as_bytes(), listen).await.unwrap();
            sleep(Duration::from_millis(50)).await;
            if rows(&analytics) > 0 {
                up = true;
                break;
            }
        }
        assert!(up, "the sink never started");
        let burst = 300;
        for i in 0..burst {
            let text = line(now_ms(), "be_shop_blue", &format!("/burst/{i}"), 200);
            tx.send_to(text.as_bytes(), listen).await.unwrap();
        }
        sink.shutdown().await;
        let filter = RequestFilter {
            path_contains: Some("/burst/".into()),
            ..RequestFilter::default()
        };
        let stored = analytics.requests(&filter, 1000).unwrap();
        assert_eq!(stored.len(), burst, "events were lost across shutdown");
    }

    #[tokio::test]
    async fn unix_datagrams_reach_the_store_and_the_socket_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.sock");
        std::fs::write(&path, b"stale").unwrap();
        let sink = bind_sink(&LogListen::Unix(path.clone())).await.unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let r = rig(sink, dir);
        let tx = UnixDatagram::unbound().unwrap();
        for i in 0..3 {
            let text = line(now_ms(), "be_shop_blue", &format!("/u{i}"), 200);
            tx.send_to(text.as_bytes(), &path).await.unwrap();
        }
        assert!(wait_for(&r.store, 3).await);
        assert_eq!(r.stats.stalls(), 0);
        r.receiver.abort();
    }

    #[tokio::test]
    async fn receive_buffer_is_never_made_smaller() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let before = SockRef::from(&socket).recv_buffer_size().unwrap();
        let sink = Sink::Udp(socket);
        sink.grow_receive_buffer();
        let Sink::Udp(socket) = &sink else { return };
        assert!(SockRef::from(socket).recv_buffer_size().unwrap() >= before);
    }
}
