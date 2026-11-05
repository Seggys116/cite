use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use cite_edge::model::LogEvent;

use crate::error::{Error, Result};
use crate::store::{Inner, StoreOptions};

// After a failed commit the backlog may grow to this many batches before the thread stops reading and lets senders block.
const BACKLOG_BATCHES: usize = 8;
const SHUTDOWN_ATTEMPTS: usize = 3;

enum Msg {
    Event(Box<LogEvent>),
    Flush(SyncSender<Result<()>>),
    Stop,
}

pub(crate) struct WriterCore {
    tx: SyncSender<Msg>,
    handle: Option<JoinHandle<()>>,
}

impl WriterCore {
    pub(crate) fn spawn(inner: Arc<Inner>, opts: &StoreOptions) -> Self {
        let (tx, rx) = sync_channel(opts.queue_capacity.max(1));
        let batch_size = opts.batch_size.max(1);
        let interval = opts.flush_interval;
        // If the thread cannot start the receiver is dropped and every send reports Closed.
        let handle = thread::Builder::new()
            .name("cite-store-writer".into())
            .spawn(move || run(&inner, &rx, batch_size, interval))
            .ok();
        Self { tx, handle }
    }
}

impl Drop for WriterCore {
    fn drop(&mut self) {
        let _ = self.tx.send(Msg::Stop);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Dropping the last clone commits everything still queued before returning.
#[derive(Clone)]
pub struct Writer {
    core: Arc<WriterCore>,
}

impl Writer {
    pub(crate) fn from_core(core: Arc<WriterCore>) -> Self {
        Self { core }
    }

    /// Queues one event, blocking while the queue is full; fails only if the writer thread is gone.
    pub fn send(&self, event: LogEvent) -> Result<()> {
        self.core
            .tx
            .send(Msg::Event(Box::new(event)))
            .map_err(|_| Error::Closed)
    }

    pub fn flush(&self) -> Result<()> {
        let (ack, done) = sync_channel(1);
        self.core
            .tx
            .send(Msg::Flush(ack))
            .map_err(|_| Error::Closed)?;
        done.recv().map_err(|_| Error::Closed)?
    }

    pub fn close(self) -> Result<()> {
        self.flush()
    }
}

// Commits the pending batch; on failure the events stay queued for the next attempt.
fn commit(inner: &Inner, batch: &mut Vec<LogEvent>, oldest: &mut Option<Instant>) -> Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    match inner.insert(batch) {
        Ok(_) => {
            batch.clear();
            *oldest = None;
            Ok(())
        }
        Err(e) => {
            *oldest = Some(Instant::now());
            Err(e)
        }
    }
}

fn settle(
    inner: &Inner,
    batch: &mut Vec<LogEvent>,
    oldest: &mut Option<Instant>,
    interval: Duration,
    batch_size: usize,
) {
    while commit(inner, batch, oldest).is_err()
        && batch.len() >= batch_size.saturating_mul(BACKLOG_BATCHES)
    {
        thread::sleep(interval);
    }
}

fn run(inner: &Inner, rx: &Receiver<Msg>, batch_size: usize, interval: Duration) {
    let mut batch: Vec<LogEvent> = Vec::with_capacity(batch_size);
    let mut oldest: Option<Instant> = None;
    loop {
        let received = match oldest {
            None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
            Some(t) => rx.recv_timeout(interval.saturating_sub(t.elapsed())),
        };
        match received {
            Ok(Msg::Event(ev)) => {
                oldest.get_or_insert_with(Instant::now);
                batch.push(*ev);
                if batch.len() >= batch_size {
                    settle(inner, &mut batch, &mut oldest, interval, batch_size);
                }
            }
            Ok(Msg::Flush(ack)) => {
                let _ = ack.send(commit(inner, &mut batch, &mut oldest));
            }
            Err(RecvTimeoutError::Timeout) => {
                let _ = commit(inner, &mut batch, &mut oldest);
            }
            Ok(Msg::Stop) | Err(RecvTimeoutError::Disconnected) => {
                drain(inner, &mut batch, &mut oldest, interval);
                return;
            }
        }
    }
}

fn drain(
    inner: &Inner,
    batch: &mut Vec<LogEvent>,
    oldest: &mut Option<Instant>,
    interval: Duration,
) {
    let mut last = None;
    for attempt in 0..SHUTDOWN_ATTEMPTS {
        if attempt > 0 {
            thread::sleep(interval);
        }
        match commit(inner, batch, oldest) {
            Ok(()) => return,
            Err(e) => last = Some(e),
        }
    }
    if let Some(e) = last {
        tracing::error!(
            events = batch.len(),
            error = %e,
            "analytics writer is stopping with events it could not commit; they are lost"
        );
    }
}
