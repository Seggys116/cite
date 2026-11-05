use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cite_core::atomic::{read_limited, write_atomic};
use cite_edge::analytics::{Analytics, Snapshot};
use cite_edge::logparse::parse_datagram;
use cite_edge::model::{LogEvent, Retention};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, interval, sleep};

use crate::config::ConnectorConfig;
use crate::store::Store;

const DATAGRAM_BUF: usize = 16 * 1024;
const BATCH: usize = 256;
const MAX_PENDING: usize = 4096;
const FLUSH_EVERY: Duration = Duration::from_millis(100);
const RECV_BACKOFF: Duration = Duration::from_millis(50);
const SNAPSHOT_FILE: &str = "analytics.json";
const SNAPSHOT_MODE: u32 = 0o600;
const MAX_SNAPSHOT_BYTES: u64 = 512 * 1024 * 1024;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

fn lock(analytics: &Mutex<Analytics>) -> MutexGuard<'_, Analytics> {
    analytics.lock().unwrap_or_else(|p| p.into_inner())
}

fn snapshot_path(cfg: &ConnectorConfig) -> PathBuf {
    cfg.data_dir.join(SNAPSHOT_FILE)
}

fn read_snapshot(path: &Path) -> Result<Snapshot, String> {
    let bytes = read_limited(path, MAX_SNAPSHOT_BYTES).map_err(|e| e.to_string())?;
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}

fn load_from(path: &Path, retention: Retention) -> Analytics {
    if !path.exists() {
        return Analytics::new(retention);
    }
    match read_snapshot(path) {
        Ok(snapshot) => Analytics::restore(retention, snapshot),
        Err(err) => {
            tracing::warn!(
                "ignoring unreadable analytics snapshot {}: {err}",
                path.display()
            );
            Analytics::new(retention)
        }
    }
}

pub fn load_snapshot(cfg: &ConnectorConfig, retention: Retention) -> Analytics {
    load_from(&snapshot_path(cfg), retention)
}

fn persist_once(
    path: &Path,
    analytics: &Mutex<Analytics>,
    retention: &Retention,
    now: i64,
) -> Result<(), String> {
    // The lock covers only the in-memory work; serialising and writing happen after it is released.
    let snapshot = {
        let mut guard = lock(analytics);
        guard.set_retention(retention.clone());
        guard.prune(now);
        guard.snapshot()
    };
    let bytes = serde_json::to_vec(&snapshot).map_err(|e| e.to_string())?;
    write_atomic(path, &bytes, SNAPSHOT_MODE).map_err(|e| e.to_string())
}

fn enqueue(batch: &mut Vec<LogEvent>, event: LogEvent, dropped: &mut u64) {
    if batch.len() >= MAX_PENDING {
        *dropped += 1;
    } else {
        batch.push(event);
    }
}

// A busy lock keeps the batch for the next attempt instead of stalling the receive loop.
fn flush(analytics: &Mutex<Analytics>, batch: &mut Vec<LogEvent>) -> bool {
    if batch.is_empty() {
        return true;
    }
    let mut guard = match analytics.try_lock() {
        Ok(guard) => guard,
        Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        Err(TryLockError::WouldBlock) => return false,
    };
    for event in batch.drain(..) {
        guard.record(event);
    }
    true
}

async fn receive_loop(socket: UdpSocket, analytics: Arc<Mutex<Analytics>>) {
    let mut buf = vec![0u8; DATAGRAM_BUF];
    let mut batch: Vec<LogEvent> = Vec::with_capacity(BATCH);
    let mut dropped = 0u64;
    let mut tick = interval(FLUSH_EVERY);
    // Delayed ticks avoid a burst of back-to-back flushes after a busy stretch.
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            received = socket.recv_from(&mut buf) => match received {
                Ok((len, _)) => {
                    if let Some(event) = parse_datagram(&buf[..len], now_ms()) {
                        enqueue(&mut batch, event, &mut dropped);
                    }
                    if batch.len() >= BATCH {
                        flush(&analytics, &mut batch);
                    }
                }
                Err(err) => {
                    tracing::warn!("log sink receive failed: {err}");
                    sleep(RECV_BACKOFF).await;
                }
            },
            _ = tick.tick() => {
                flush(&analytics, &mut batch);
                if dropped > 0 {
                    tracing::warn!("log sink dropped {dropped} events under load");
                    dropped = 0;
                }
            }
        }
    }
}

async fn persist_loop(path: PathBuf, analytics: Arc<Mutex<Analytics>>, store: Arc<Store>) {
    loop {
        let retention = store.config().settings.retention.clone();
        let secs = u64::from(retention.persist_interval_secs.max(1));
        sleep(Duration::from_secs(secs)).await;
        let (target, shared) = (path.clone(), analytics.clone());
        let task = tokio::task::spawn_blocking(move || {
            persist_once(&target, &shared, &retention, now_ms())
        });
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => tracing::warn!("analytics snapshot not written: {err}"),
            Err(err) => tracing::warn!("analytics snapshot task failed: {err}"),
        }
    }
}

pub fn spawn(
    cfg: &ConnectorConfig,
    analytics: Arc<Mutex<Analytics>>,
    store: Arc<Store>,
) -> JoinHandle<()> {
    let listen = cfg.log_listen;
    let path = snapshot_path(cfg);
    tokio::spawn(async move {
        let socket = match UdpSocket::bind(listen).await {
            Ok(socket) => socket,
            Err(err) => {
                tracing::error!("log sink cannot bind {listen}: {err}");
                return;
            }
        };
        tracing::info!("log sink listening on {listen}");
        tokio::join!(
            receive_loop(socket, analytics.clone()),
            persist_loop(path, analytics, store)
        );
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testing::test_config;
    use cite_edge::logparse::LOG_FORMAT;

    // Field values in LOG_FORMAT order; the count is asserted so a format change fails loudly.
    fn fields(ts: i64, backend: &str, path: &str, status: u16) -> Vec<String> {
        let list = vec![
            ts.to_string(),
            "203.0.113.9".into(),
            backend.into(),
            "t1".into(),
            "shop.example.com".into(),
            "GET".into(),
            path.into(),
            "0".into(),
            status.to_string(),
            "2048".into(),
            "300".into(),
            "12".into(),
            "curl%2F8".into(),
            "-".into(),
            "text%2Fhtml".into(),
            String::new(),
        ];
        assert_eq!(list.len(), LOG_FORMAT.split(' ').count());
        list
    }

    fn line(ts: i64, backend: &str, path: &str, status: u16) -> String {
        let body = fields(ts, backend, path, status).join(" ");
        format!("<134>Nov  4 12:00:00 edge haproxy[812]: {body}")
    }

    fn analytics() -> Arc<Mutex<Analytics>> {
        Arc::new(Mutex::new(Analytics::new(Retention::default())))
    }

    fn requests(a: &Mutex<Analytics>) -> u64 {
        lock(a).summary(3600, None, now_ms()).requests
    }

    async fn wait_for(a: &Mutex<Analytics>, want: u64) -> bool {
        for _ in 0..100 {
            if requests(a) >= want {
                return true;
            }
            sleep(Duration::from_millis(50)).await;
        }
        false
    }

    async fn bound_sink(a: &Arc<Mutex<Analytics>>) -> (std::net::SocketAddr, JoinHandle<()>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        (addr, tokio::spawn(receive_loop(socket, a.clone())))
    }

    async fn sender() -> UdpSocket {
        UdpSocket::bind("127.0.0.1:0").await.unwrap()
    }

    #[tokio::test]
    async fn datagrams_reach_analytics() {
        let a = analytics();
        let (addr, task) = bound_sink(&a).await;
        let tx = sender().await;
        for i in 0..5 {
            let text = line(now_ms(), "be_shop_blue", &format!("/p{i}"), 200);
            tx.send_to(text.as_bytes(), addr).await.unwrap();
        }
        assert!(wait_for(&a, 5).await);
        let events = lock(&a).requests(&Default::default(), 10);
        assert_eq!(events.len(), 5);
        assert!(events.iter().all(|e| e.site == "shop" && e.status == 200));
        assert_eq!(events[0].path, "/p4");
        assert_eq!(events[0].user_agent, "curl/8");
        task.abort();
    }

    #[tokio::test]
    async fn garbage_datagrams_are_ignored() {
        let a = analytics();
        let (addr, task) = bound_sink(&a).await;
        let tx = sender().await;
        tx.send_to(b"hello world", addr).await.unwrap();
        tx.send_to(&[0xff, 0xfe, 0x00], addr).await.unwrap();
        tx.send_to(&vec![b'a'; 9000], addr).await.unwrap();
        let good = line(now_ms(), "be_shop_green", "/ok", 404);
        tx.send_to(good.as_bytes(), addr).await.unwrap();
        assert!(wait_for(&a, 1).await);
        sleep(Duration::from_millis(300)).await;
        let summary = lock(&a).summary(3600, None, now_ms());
        assert_eq!(summary.requests, 1);
        assert_eq!(summary.errors_4xx, 1);
        task.abort();
    }

    #[tokio::test]
    async fn per_site_scope_is_populated_from_the_backend_name() {
        let a = analytics();
        let (addr, task) = bound_sink(&a).await;
        let tx = sender().await;
        for backend in ["be_shop_blue", "be_blog_green", "be_blog_blue"] {
            let text = line(now_ms(), backend, "/", 200);
            tx.send_to(text.as_bytes(), addr).await.unwrap();
        }
        assert!(wait_for(&a, 3).await);
        let blog = lock(&a).summary(3600, Some("blog"), now_ms());
        assert_eq!(blog.requests, 2);
        task.abort();
    }

    #[test]
    fn flush_keeps_the_batch_while_the_lock_is_busy() {
        let a = analytics();
        let event = parse_datagram(
            line(now_ms(), "be_shop_blue", "/", 200).as_bytes(),
            now_ms(),
        );
        let mut batch = vec![event.unwrap()];
        let held = a.lock().unwrap();
        assert!(!flush(&a, &mut batch));
        assert_eq!(batch.len(), 1);
        drop(held);
        assert!(flush(&a, &mut batch));
        assert!(batch.is_empty());
        assert_eq!(requests(&a), 1);
    }

    #[test]
    fn enqueue_drops_beyond_the_pending_cap() {
        let event = parse_datagram(
            line(now_ms(), "be_shop_blue", "/", 200).as_bytes(),
            now_ms(),
        );
        let event = event.unwrap();
        let mut batch = Vec::new();
        let mut dropped = 0;
        for _ in 0..MAX_PENDING + 10 {
            enqueue(&mut batch, event.clone(), &mut dropped);
        }
        assert_eq!(batch.len(), MAX_PENDING);
        assert_eq!(dropped, 10);
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn overload_with_a_held_lock_does_not_block_the_receiver() {
        let a = analytics();
        let (addr, task) = bound_sink(&a).await;
        let tx = sender().await;
        let held = a.lock().unwrap();
        let total = 1500u64;
        for i in 0..total {
            let text = line(now_ms(), "be_shop_blue", &format!("/o{i}"), 200);
            tx.send_to(text.as_bytes(), addr).await.unwrap();
            if i % 50 == 49 {
                sleep(Duration::from_millis(5)).await;
            }
        }
        sleep(Duration::from_millis(300)).await;
        assert!(!task.is_finished());
        drop(held);
        // a receiver stuck on the lock would have let the socket buffer overflow by now
        assert!(wait_for(&a, total).await, "recorded {}", requests(&a));
        task.abort();
    }

    #[test]
    fn snapshot_round_trip_restores_counts_and_recent_events() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(SNAPSHOT_FILE);
        let a = analytics();
        let now = now_ms();
        for i in 0..7 {
            let text = line(now, "be_shop_blue", &format!("/r{i}"), 500);
            lock(&a).record(parse_datagram(text.as_bytes(), now).unwrap());
        }
        persist_once(&path, &a, &Retention::default(), now).unwrap();
        let restored = load_from(&path, Retention::default());
        let summary = restored.summary(3600, None, now);
        assert_eq!(summary.requests, 7);
        assert_eq!(summary.errors_5xx, 7);
        assert_eq!(restored.summary(3600, Some("shop"), now).requests, 7);
        assert_eq!(restored.requests(&Default::default(), 100).len(), 7);
    }

    #[test]
    fn snapshot_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(SNAPSHOT_FILE);
        persist_once(&path, &analytics(), &Retention::default(), now_ms()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn corrupt_or_missing_snapshot_yields_empty_analytics() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(SNAPSHOT_FILE);
        let missing = load_from(&path, Retention::default());
        assert_eq!(missing.summary(3600, None, now_ms()).requests, 0);
        std::fs::write(&path, b"{ not json").unwrap();
        let loaded = load_from(&path, Retention::default());
        assert_eq!(loaded.summary(3600, None, now_ms()).requests, 0);
        assert!(loaded.requests(&Default::default(), 10).is_empty());
    }

    #[test]
    fn restore_honours_the_retention_it_is_given() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(SNAPSHOT_FILE);
        let a = analytics();
        let now = now_ms();
        for i in 0..6 {
            let text = line(now, "be_shop_blue", &format!("/k{i}"), 200);
            lock(&a).record(parse_datagram(text.as_bytes(), now).unwrap());
        }
        persist_once(&path, &a, &Retention::default(), now).unwrap();
        let tight = Retention {
            recent_events: 2,
            store_client_ips: false,
            ..Retention::default()
        };
        let restored = load_from(&path, tight);
        let recent = restored.requests(&Default::default(), 100);
        assert_eq!(recent.len(), 2);
        assert!(recent.iter().all(|e| e.client_ip.is_empty()));
    }

    #[tokio::test]
    async fn spawned_sink_binds_receives_and_survives_a_bad_bind() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_config(dir.path());
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        cfg.log_listen = probe.local_addr().unwrap();
        drop(probe);
        let store = Store::open(&cfg).await.unwrap();
        let a = analytics();
        let handle = spawn(&cfg, a.clone(), store.clone());
        let tx = sender().await;
        let text = line(now_ms(), "be_shop_blue", "/spawned", 200);
        let mut seen = false;
        for _ in 0..60 {
            tx.send_to(text.as_bytes(), cfg.log_listen).await.unwrap();
            sleep(Duration::from_millis(50)).await;
            if requests(&a) > 0 {
                seen = true;
                break;
            }
        }
        assert!(seen, "events never arrived through spawn()");
        handle.abort();

        let taken = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        cfg.log_listen = taken.local_addr().unwrap();
        let failed = spawn(&cfg, analytics(), store);
        let finished = tokio::time::timeout(Duration::from_secs(5), failed).await;
        assert!(finished.is_ok(), "spawn must return when bind fails");
    }
}
