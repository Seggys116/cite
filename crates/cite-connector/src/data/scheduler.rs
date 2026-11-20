//! Scheduled backups, rotation upkeep and the daily prune.
//!
//! The catalog is the schedule's state: a database is due when its newest scheduled record is older than the latest
//! slot, so a connector that was down at the slot runs one catch-up backup when it starts, never more.

use std::sync::Arc;
use std::time::Duration;

use cite_edge::datamodel::BackupSchedule;
use cite_edge::datawire::{BackupRecord, BackupTrigger};
use cite_edge::model::Site;
use time::{Date, OffsetDateTime, Time};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use super::service::{DataService, lk, parse_time};

const TICK: Duration = Duration::from_secs(60);
/// Backups the scheduler runs at once, on top of the node-wide job permits.
const CONCURRENCY: usize = 2;
const MAX_JITTER_SECS: u64 = 300;
/// The daily prune runs at the first tick after this time (UTC).
const PRUNE_HOUR: u8 = 3;
const PRUNE_MINUTE: u8 = 17;

/// The latest UTC time `t <= now` with `t.hour % every_hours == 0` and `t.minute == minute`.
pub fn due_slot(now: OffsetDateTime, every_hours: u8, minute: u8) -> OffsetDateTime {
    let every = every_hours.max(1);
    let now = now.to_offset(time::UtcOffset::UTC);
    let mut date: Date = now.date();
    let mut hour = (now.hour() / every) * every;
    loop {
        let t = date
            .with_time(Time::from_hms(hour, minute.min(59), 0).unwrap_or(Time::MIDNIGHT))
            .assume_utc();
        if t <= now {
            return t;
        }
        if hour >= every {
            hour -= every;
        } else {
            date = date.previous_day().unwrap_or(date);
            hour = (23 / every) * every;
        }
    }
}

/// True when no scheduled backup was started since `slot`; failed attempts count, so a failing database waits for the
/// next slot instead of retrying every minute.
pub fn needs_backup(records: &[BackupRecord], slot: OffsetDateTime) -> bool {
    !records.iter().any(|r| {
        r.trigger == BackupTrigger::Scheduled
            && parse_time(&r.created_at).is_some_and(|t| t >= slot)
    })
}

/// Random delay before a scheduled backup: up to `min(300, every_hours * 360)` seconds.
pub fn jitter_secs(every_hours: u8) -> u64 {
    let span = (u64::from(every_hours) * 360).min(MAX_JITTER_SECS);
    let mut raw = [0u8; 8];
    if span == 0 || getrandom::fill(&mut raw).is_err() {
        return 0;
    }
    u64::from_le_bytes(raw) % (span + 1)
}

/// `(site, database key)` pairs due now, given each database's records.
pub fn due_databases(
    sites: &[Site],
    now: OffsetDateTime,
    records: impl Fn(&str, &str) -> Vec<BackupRecord>,
) -> Vec<(String, String, BackupSchedule)> {
    let mut out = Vec::new();
    for site in sites {
        let Some(pg) = site.data.postgres.as_ref() else {
            continue;
        };
        let Some(schedule) = pg.backup.schedule.as_ref() else {
            continue;
        };
        let slot = due_slot(now, schedule.every_hours, schedule.minute);
        for db in &pg.databases {
            let key = format!("pg:{}", db.name);
            if needs_backup(&records(&site.id, &key), slot) {
                out.push((site.id.clone(), key, schedule.clone()));
            }
        }
    }
    out
}

fn prune_due(now: OffsetDateTime, last: Option<Date>) -> bool {
    let at = Time::from_hms(PRUNE_HOUR, PRUNE_MINUTE, 0).unwrap_or(Time::MIDNIGHT);
    now.time() >= at && last != Some(now.date())
}

impl DataService {
    fn claim(&self, site: &str, key: &str) -> bool {
        lk(&self.inflight).insert(format!("{site}/{key}"))
    }

    fn release(&self, site: &str, key: &str) {
        lk(&self.inflight).remove(&format!("{site}/{key}"));
    }

    /// One scheduler pass: start due backups, finish rotations, prune once a day.
    pub(crate) async fn tick(
        self: &Arc<Self>,
        sem: &Arc<Semaphore>,
        last_prune: &mut Option<Date>,
    ) {
        let now = OffsetDateTime::now_utc();
        let sites = self.deployer.sites();
        let mut catalogs = std::collections::HashMap::new();
        for s in sites.iter().filter(|s| s.data.postgres.is_some()) {
            if let Ok(cat) = self.read_catalog(&s.id).await {
                catalogs.insert(s.id.clone(), cat);
            }
        }
        let due = due_databases(&sites, now, |site, key| {
            catalogs
                .get(site)
                .and_then(|c| c.get(key))
                .map(|d| d.backups.clone())
                .unwrap_or_default()
        });
        for (site, key, schedule) in due {
            if !self.claim(&site, &key) {
                continue;
            }
            let (svc, sem) = (Arc::clone(self), Arc::clone(sem));
            let delay = Duration::from_secs(jitter_secs(schedule.every_hours));
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                if let Ok(_permit) = sem.acquire_owned().await
                    && let Err(e) = svc.run_scheduled_backup(&site, &key).await
                {
                    tracing::warn!(%site, database = %key, error = %e, "scheduled backup failed");
                }
                svc.release(&site, &key);
            });
        }
        let retired = self.retire_due(now).await;
        if retired > 0 {
            tracing::info!(retired, "retired rotated database logins");
        }
        if prune_due(now, *last_prune) {
            *last_prune = Some(now.date());
            for id in self.dirs.sites() {
                if let Err(e) = self.prune_site(&id).await {
                    tracing::warn!(site = %id, error = %e, "daily prune failed");
                }
            }
        }
    }

    pub fn spawn_scheduler(self: &Arc<Self>) -> JoinHandle<()> {
        let svc = Arc::clone(self);
        tokio::spawn(async move {
            let sem = Arc::new(Semaphore::new(CONCURRENCY));
            let mut last_prune = None;
            let mut tick = tokio::time::interval(TICK);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let changed = crate::orchestrator::data::networks_changed();
            loop {
                tokio::select! {
                    _ = tick.tick() => svc.tick(&sem, &mut last_prune).await,
                    () = changed.notified() => svc.reconcile().await,
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::format_description::well_known::Rfc3339;

    fn at(s: &str) -> OffsetDateTime {
        OffsetDateTime::parse(s, &Rfc3339).unwrap()
    }

    fn scheduled(created: &str) -> BackupRecord {
        serde_json::from_value(serde_json::json!({
            "id": "i", "database": "pg:app", "version": 1, "created_at": created,
            "trigger": "scheduled", "status": "ok"
        }))
        .unwrap()
    }

    #[test]
    fn the_slot_is_the_latest_matching_time_not_after_now() {
        assert_eq!(
            due_slot(at("2026-11-20T10:30:00Z"), 6, 15),
            at("2026-11-20T06:15:00Z")
        );
        assert_eq!(
            due_slot(at("2026-11-20T06:15:00Z"), 6, 15),
            at("2026-11-20T06:15:00Z")
        );
        assert_eq!(
            due_slot(at("2026-11-20T06:14:59Z"), 6, 15),
            at("2026-11-20T00:15:00Z")
        );
        assert_eq!(
            due_slot(at("2026-11-20T00:10:00Z"), 6, 15),
            at("2026-11-19T18:15:00Z")
        );
        assert_eq!(
            due_slot(at("2026-11-20T09:00:00Z"), 24, 0),
            at("2026-11-20T00:00:00Z")
        );
        assert_eq!(
            due_slot(at("2026-11-20T09:05:00Z"), 1, 10),
            at("2026-11-20T08:10:00Z")
        );
        assert_eq!(
            due_slot(at("2026-03-01T00:05:00Z"), 8, 30),
            at("2026-02-28T16:30:00Z")
        );
        assert_eq!(
            due_slot(at("2024-03-01T00:05:00Z"), 8, 30),
            at("2024-02-29T16:30:00Z")
        );
    }

    #[test]
    fn a_database_is_due_until_a_scheduled_backup_starts_after_the_slot() {
        let slot = at("2026-11-20T06:15:00Z");
        assert!(needs_backup(&[], slot));
        assert!(needs_backup(&[scheduled("2026-11-20T00:16:00Z")], slot));
        assert!(!needs_backup(&[scheduled("2026-11-20T06:16:00Z")], slot));
        assert!(
            !needs_backup(&[scheduled("2026-11-20T06:15:00Z")], slot),
            "starting exactly at the slot counts"
        );
        let mut manual = scheduled("2026-11-20T07:00:00Z");
        manual.trigger = BackupTrigger::Manual;
        assert!(
            needs_backup(&[manual], slot),
            "manual backups do not satisfy the schedule"
        );
        let mut failed = scheduled("2026-11-20T06:20:00Z");
        failed.status = cite_edge::datawire::BackupStatus::Failed;
        assert!(
            !needs_backup(&[failed], slot),
            "a failed attempt waits for the next slot"
        );
    }

    #[test]
    fn a_restart_after_missed_slots_catches_up_once() {
        let slot = due_slot(at("2026-11-20T23:00:00Z"), 6, 15);
        let old = scheduled("2026-11-18T06:20:00Z");
        assert!(needs_backup(std::slice::from_ref(&old), slot));
        let caught_up = scheduled("2026-11-20T23:00:30Z");
        assert!(!needs_backup(&[old, caught_up], slot));
    }

    #[test]
    fn jitter_stays_inside_its_bounds() {
        for every in [1u8, 2, 6, 24] {
            let cap = (u64::from(every) * 360).min(300);
            for _ in 0..50 {
                assert!(jitter_secs(every) <= cap);
            }
        }
        assert_eq!(jitter_secs(0), 0);
    }

    #[test]
    fn the_daily_prune_runs_once_after_its_time() {
        let day = at("2026-11-20T03:16:00Z");
        assert!(!prune_due(day, None));
        let later = at("2026-11-20T03:17:00Z");
        assert!(prune_due(later, None));
        assert!(!prune_due(later, Some(later.date())));
        assert!(prune_due(at("2026-11-21T04:00:00Z"), Some(later.date())));
    }
}
