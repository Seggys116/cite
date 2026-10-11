#![forbid(unsafe_code)]
#![allow(clippy::collapsible_if)]

//! Cite executor: HTTP listener, static server, reverse proxy, and blue-green supervisor.

mod control;
mod error_page;
mod limits;
mod proxy;
mod route;
mod server;
mod static_files;
mod supervisor;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use cite_core::{ExecutorConfig, ExecutorStatus, Redactor, Result, ensure_dir, write_status};
use tokio::sync::{Mutex, Notify, Semaphore, watch};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::control::SharedState;
use crate::proxy::Inflight;
use crate::route::RouteTarget;
use crate::supervisor::SlotManager;

pub struct RunningExecutor {
    pub addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    join: tokio::task::JoinHandle<()>,
    process_exit: watch::Receiver<bool>,
}

impl RunningExecutor {
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        let _ = self.join.await;
    }

    pub async fn exited(&mut self) {
        loop {
            if *self.process_exit.borrow() {
                return;
            }
            if self.process_exit.changed().await.is_err() {
                return;
            }
        }
    }
}

/// Raises the open-file soft limit to the hard limit (capped) so many connections do not hit EMFILE.
pub fn raise_nofile_limit() -> Option<u64> {
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
    const CAP: u64 = 1_048_576;
    let limit = getrlimit(Resource::Nofile);
    let target = limit.maximum.map_or(CAP, |max| max.min(CAP));
    if limit.current.is_some_and(|cur| cur >= target) {
        return limit.current;
    }
    let raised = Rlimit {
        current: Some(target),
        maximum: limit.maximum,
    };
    match setrlimit(Resource::Nofile, raised) {
        Ok(()) => Some(target),
        Err(_) => limit.current,
    }
}

pub async fn spawn(config: ExecutorConfig) -> Result<RunningExecutor> {
    ensure_dir(&config.releases_dir, 0o755)?;
    ensure_dir(&config.control_dir, 0o755)?;
    ensure_dir(&config.status_dir, 0o755)?;
    ensure_dir(&config.releases_dir.join("blue"), 0o755)?;
    ensure_dir(&config.releases_dir.join("green"), 0o755)?;

    let redactor = runtime_redactor(&config);
    let status = Arc::new(Mutex::new(ExecutorStatus::initial(&config.version)));
    {
        let guard = status.lock().await;
        let _ = write_status(&config.status_path(), &guard);
    }

    let routing = Arc::new(ArcSwap::from_pointee(RouteTarget::empty()));
    let connections = Arc::new(Semaphore::new(config.max_connections.max(1)));
    let draining = Arc::new(AtomicBool::new(false));
    let conn_count = Arc::new(AtomicU64::new(0));
    let requests = Arc::new(AtomicU64::new(0));
    let slot_mgr = Arc::new(SlotManager::new(config.clone(), redactor.clone()));
    let limiter = limits::Limiter::new(limits::LimitConfig::from_executor(&config));

    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    let addr = listener.local_addr()?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (process_exit_tx, process_exit_rx) = watch::channel(false);
    let wake = Arc::new(Notify::new());

    let state = SharedState {
        config: Arc::new(config),
        routing,
        status,
        connections,
        draining: draining.clone(),
        conn_count: conn_count.clone(),
        slot_mgr: slot_mgr.clone(),
        requests,
        inflight: Arc::new(Inflight::new()),
        limiter: limiter.clone(),
        redactor: Arc::new(redactor),
        process_exit: process_exit_tx,
    };

    let shutdown_for_exit = shutdown_tx.clone();
    let join = tokio::spawn(async move {
        let control = tokio::spawn(control::run(
            state.clone(),
            shutdown_rx.clone(),
            wake.clone(),
        ));
        let accept = tokio::spawn(server::accept_loop(
            listener,
            state.clone(),
            shutdown_rx.clone(),
        ));
        let reaper = tokio::spawn(reap_loop(shutdown_rx.clone()));
        let sweeper = tokio::spawn(sweep_loop(limiter, shutdown_rx.clone()));

        let mut shutdown_rx = shutdown_rx;
        let mut process_exit_rx = state.process_exit.subscribe();
        loop {
            if *shutdown_rx.borrow() || *process_exit_rx.borrow() {
                break;
            }
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                changed = process_exit_rx.changed() => {
                    if changed.is_err() || *process_exit_rx.borrow() {
                        let _ = shutdown_for_exit.send(true);
                        break;
                    }
                }
            }
        }

        draining.store(true, Ordering::SeqCst);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while conn_count.load(Ordering::SeqCst) > 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        slot_mgr.shutdown_all().await;
        wake.notify_waiters();
        let _ = accept.await;
        let _ = control.await;
        let _ = reaper.await;
        let _ = sweeper.await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    Ok(RunningExecutor {
        addr,
        shutdown: shutdown_tx,
        join,
        process_exit: process_exit_rx,
    })
}

pub fn runtime_redactor(config: &ExecutorConfig) -> Redactor {
    let mut redactor = Redactor::new();
    for value in config
        .runtime_env
        .resolve()
        .unwrap_or_default()
        .into_values()
    {
        redactor.push_secret(value);
    }
    redactor
}

async fn sweep_loop(limiter: Arc<limits::Limiter>, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(limits::SWEEP_INTERVAL);
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            _ = interval.tick() => limiter.sweep(std::time::Instant::now()),
        }
    }
}

async fn reap_loop(mut shutdown: watch::Receiver<bool>) {
    let mut child_signal =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child()).ok();
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            _ = interval.tick() => {
                reap_zombies();
            }
            _ = wait_child(&mut child_signal) => {
                reap_zombies();
            }
        }
    }
    reap_zombies();
}

async fn wait_child(signal: &mut Option<tokio::signal::unix::Signal>) {
    match signal.as_mut() {
        Some(sig) => {
            sig.recv().await;
        }
        None => std::future::pending::<()>().await,
    }
}

fn reap_zombies() {
    // Outside PID 1, waitpid(-1) would reap sibling build processes and make their waits fail with ECHILD.
    if std::process::id() != 1 {
        return;
    }
    reap_exited_children();
}

pub fn reap_exited_children() {
    while let Ok(Some(_)) = rustix::process::waitpid(None, rustix::process::WaitOptions::NOHANG) {}
}

pub fn reap_if_init() {
    reap_zombies();
}

pub fn init_logging(redactor: Redactor) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let (writer, _guard) = tracing_appender_stub(redactor);
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_current_span(false)
                .with_span_list(false)
                .with_writer(writer),
        )
        .try_init();
}

fn tracing_appender_stub(redactor: Redactor) -> (RedactingWriter, ()) {
    (RedactingWriter(Arc::new(redactor)), ())
}

#[derive(Clone)]
struct RedactingWriter(Arc<Redactor>);

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for RedactingWriter {
    type Writer = RedactingIo;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingIo {
            redactor: self.0.clone(),
            buf: Vec::new(),
        }
    }
}

struct RedactingIo {
    redactor: Arc<Redactor>,
    buf: Vec<u8>,
}

impl std::io::Write for RedactingIo {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(buf);
        while let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
            let mut line = self.buf.drain(..=pos).collect::<Vec<_>>();
            if let Ok(text) = std::str::from_utf8(&line) {
                let redacted = self.redactor.redact_line(text.trim_end_matches('\n'));
                let mut out = redacted.into_bytes();
                out.push(b'\n');
                std::io::stderr().write_all(&out)?;
            } else {
                std::io::stderr().write_all(&line)?;
            }
            let _ = &mut line;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.buf.is_empty() {
            let line = std::mem::take(&mut self.buf);
            if let Ok(text) = std::str::from_utf8(&line) {
                let redacted = self.redactor.redact_line(text);
                std::io::stderr().write_all(redacted.as_bytes())?;
            } else {
                std::io::stderr().write_all(&line)?;
            }
        }
        std::io::stderr().flush()
    }
}

#[cfg(test)]
mod tests;
