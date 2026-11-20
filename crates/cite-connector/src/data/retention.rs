//! Grandfather-father-son retention of backup versions. Pure: the same records, policy and clock always
//! give the same plan, all in UTC.

use std::collections::BTreeMap;

use cite_edge::datamodel::BackupRetention;
use cite_edge::datawire::{
    BackupRecord, BackupStatus, BackupTrigger, PruneKeep, PrunePlanView, PruneTier,
};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

/// Failed records stay this long in the catalog.
pub const FAILED_RECORD_DAYS: i64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Local,
    S3,
}

impl From<Tier> for PruneTier {
    fn from(t: Tier) -> Self {
        match t {
            Tier::Local => PruneTier::Local,
            Tier::S3 => PruneTier::S3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepReason {
    Pinned,
    Newest,
    /// The record has no usable timestamp, so it is never deleted.
    Undated,
    Recent,
    PreRestore,
    Daily,
    Weekly,
    Monthly,
}

impl KeepReason {
    pub fn as_str(self) -> &'static str {
        match self {
            KeepReason::Pinned => "pinned",
            KeepReason::Newest => "newest",
            KeepReason::Undated => "undated",
            KeepReason::Recent => "recent",
            KeepReason::PreRestore => "pre_restore",
            KeepReason::Daily => "daily",
            KeepReason::Weekly => "weekly",
            KeepReason::Monthly => "monthly",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrunePlan {
    pub keep: Vec<(String, KeepReason)>,
    pub delete: Vec<String>,
}

impl PrunePlan {
    /// The wire shape the prune preview route returns.
    pub fn to_view(&self) -> PrunePlanView {
        PrunePlanView {
            keep: self
                .keep
                .iter()
                .map(|(id, reason)| PruneKeep {
                    id: id.clone(),
                    reason: reason.as_str().to_string(),
                })
                .collect(),
            delete: self.delete.clone(),
        }
    }
}

fn parse_time(text: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(text, &Rfc3339).ok()
}

fn has_copy(r: &BackupRecord, tier: Tier) -> bool {
    match tier {
        Tier::Local => r.local.is_some(),
        Tier::S3 => r.s3.is_some(),
    }
}

/// Julian day of the UTC calendar day.
fn day_key(t: OffsetDateTime) -> i64 {
    i64::from(t.to_offset(time::UtcOffset::UTC).date().to_julian_day())
}

/// Julian day of the Monday that starts the UTC week.
fn week_key(t: OffsetDateTime) -> i64 {
    let d = t.to_offset(time::UtcOffset::UTC).date();
    i64::from(d.to_julian_day()) - i64::from(d.weekday().number_days_from_monday())
}

fn month_key(t: OffsetDateTime) -> i64 {
    let d = t.to_offset(time::UtcOffset::UTC).date();
    i64::from(d.year()) * 12 + i64::from(u8::from(d.month())) - 1
}

/// Which records of one database a tier keeps, and which it may drop.
///
/// Only records with status ok and a copy in the tier take part. A record is kept when the first of these
/// holds: pinned; the newest of its database; younger than `keep_all_hours`; a pre_restore younger than
/// `pre_restore_days`; the newest member of one of the last `daily_days` UTC days, `weekly_weeks` ISO weeks
/// (Monday start) or `monthly_months` calendar months.
pub fn plan_prune(
    records: &[BackupRecord],
    tier: Tier,
    policy: &BackupRetention,
    now: OffsetDateTime,
) -> PrunePlan {
    struct Entry<'a> {
        rec: &'a BackupRecord,
        at: Option<OffsetDateTime>,
    }
    let entries: Vec<Entry<'_>> = records
        .iter()
        .filter(|r| r.status == BackupStatus::Ok && has_copy(r, tier))
        .map(|rec| Entry {
            rec,
            at: parse_time(&rec.created_at),
        })
        .collect();

    let newer = |a: &Entry<'_>, b: &Entry<'_>| (a.at, a.rec.version) > (b.at, b.rec.version);
    let newest_idx = (0..entries.len())
        .filter(|i| entries[*i].at.is_some())
        .fold(None::<usize>, |best, i| match best {
            Some(b) if !newer(&entries[i], &entries[b]) => Some(b),
            _ => Some(i),
        });

    let now_day = day_key(now);
    let now_week = week_key(now);
    let now_month = month_key(now);
    let mut best_day: BTreeMap<i64, usize> = BTreeMap::new();
    let mut best_week: BTreeMap<i64, usize> = BTreeMap::new();
    let mut best_month: BTreeMap<i64, usize> = BTreeMap::new();
    let note = |map: &mut BTreeMap<i64, usize>, key: i64, i: usize| {
        let slot = map.entry(key).or_insert(i);
        if newer(&entries[i], &entries[*slot]) {
            *slot = i;
        }
    };
    for (i, e) in entries.iter().enumerate() {
        let Some(at) = e.at else { continue };
        let d = day_key(at);
        if d <= now_day && now_day - d < i64::from(policy.daily_days) {
            note(&mut best_day, d, i);
        }
        let w = week_key(at);
        if w <= now_week && (now_week - w) / 7 < i64::from(policy.weekly_weeks) {
            note(&mut best_week, w, i);
        }
        let m = month_key(at);
        if m <= now_month && now_month - m < i64::from(policy.monthly_months) {
            note(&mut best_month, m, i);
        }
    }

    let mut plan = PrunePlan::default();
    for (i, e) in entries.iter().enumerate() {
        let id = e.rec.id.clone();
        let reason = if e.rec.pinned {
            Some(KeepReason::Pinned)
        } else if e.at.is_none() {
            Some(KeepReason::Undated)
        } else if newest_idx == Some(i) {
            Some(KeepReason::Newest)
        } else {
            let at = e.at.unwrap_or(now);
            let age = (now - at).max(Duration::ZERO);
            if age < Duration::hours(i64::from(policy.keep_all_hours)) {
                Some(KeepReason::Recent)
            } else if e.rec.trigger == BackupTrigger::PreRestore
                && age < Duration::days(i64::from(policy.pre_restore_days))
            {
                Some(KeepReason::PreRestore)
            } else if best_day.get(&day_key(at)) == Some(&i) {
                Some(KeepReason::Daily)
            } else if best_week.get(&week_key(at)) == Some(&i) {
                Some(KeepReason::Weekly)
            } else if best_month.get(&month_key(at)) == Some(&i) {
                Some(KeepReason::Monthly)
            } else {
                None
            }
        };
        match reason {
            Some(r) => plan.keep.push((id, r)),
            None => plan.delete.push(id),
        }
    }
    plan
}

/// Ids of failed records older than 30 days; the catalog drops them. Records without a usable timestamp stay.
pub fn expired_failed(records: &[BackupRecord], now: OffsetDateTime) -> Vec<String> {
    records
        .iter()
        .filter(|r| r.status == BackupStatus::Failed)
        .filter(|r| {
            parse_time(&r.created_at).is_some_and(|t| now - t >= Duration::days(FAILED_RECORD_DAYS))
        })
        .map(|r| r.id.clone())
        .collect()
}

/// Ids of finished records that have no copy left in any tier; the catalog drops them (its version counter keeps counting).
pub fn without_copies(records: &[BackupRecord]) -> Vec<String> {
    records
        .iter()
        .filter(|r| r.status == BackupStatus::Ok && r.local.is_none() && r.s3.is_none())
        .map(|r| r.id.clone())
        .collect()
}

#[cfg(test)]
pub(crate) mod testutil {
    use cite_edge::datawire::{BackupRecord, BackupStatus, BackupTrigger, LocalCopy, S3CopyInfo};

    /// A finished local backup; tests adjust the fields they care about.
    pub fn record(id: &str, version: u32, created_at: &str) -> BackupRecord {
        BackupRecord {
            id: id.into(),
            database: "pg:app".into(),
            version,
            created_at: created_at.into(),
            completed_at: Some(created_at.into()),
            trigger: BackupTrigger::Manual,
            label: None,
            pinned: false,
            size_bytes: 10,
            sha256: "00".into(),
            server_version: "18.1".into(),
            format: "pg_dump-custom".into(),
            encryption: None,
            local: Some(LocalCopy {
                file: format!("{id}.cbk"),
                stored_bytes: 20,
            }),
            s3: None,
            status: BackupStatus::Ok,
            error: None,
            actor: "admin".into(),
            source: None,
        }
    }

    pub fn s3_copy(id: &str) -> S3CopyInfo {
        S3CopyInfo {
            target: "t1".into(),
            key: format!("cite/node/shop/pg-app/{id}.cbk"),
            etag: None,
            version_id: None,
            uploaded_at: "2026-01-01T00:00:00Z".into(),
            delete_error: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::{record, s3_copy};
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    fn t(text: &str) -> OffsetDateTime {
        OffsetDateTime::parse(text, &Rfc3339).unwrap()
    }

    fn policy(
        keep_all_hours: u32,
        daily: u32,
        weekly: u32,
        monthly: u32,
        pre_restore: u32,
    ) -> BackupRetention {
        BackupRetention {
            keep_all_hours,
            daily_days: daily,
            weekly_weeks: weekly,
            monthly_months: monthly,
            pre_restore_days: pre_restore,
        }
    }

    fn ids(v: &[(String, KeepReason)]) -> Vec<&str> {
        v.iter().map(|(i, _)| i.as_str()).collect()
    }

    fn reason(plan: &PrunePlan, id: &str) -> Option<KeepReason> {
        plan.keep.iter().find(|(i, _)| i == id).map(|(_, r)| *r)
    }

    #[test]
    fn daily_buckets_split_at_utc_midnight_and_keep_the_newest_member() {
        let now = t("2026-03-10T12:00:00Z");
        let recs = [
            record("v1", 1, "2026-03-10T01:00:00Z"),
            record("v2", 2, "2026-03-10T11:00:00Z"),
            record("v3", 3, "2026-03-09T23:59:59Z"),
            record("v4", 4, "2026-03-09T00:00:00Z"),
            record("v5", 5, "2026-03-08T23:59:59Z"),
        ];
        let plan = plan_prune(&recs, Tier::Local, &policy(0, 2, 0, 0, 0), now);
        assert_eq!(ids(&plan.keep), ["v2", "v3"]);
        assert_eq!(reason(&plan, "v2"), Some(KeepReason::Newest));
        assert_eq!(reason(&plan, "v3"), Some(KeepReason::Daily));
        assert_eq!(plan.delete, ["v1", "v4", "v5"]);
    }

    #[test]
    fn weekly_buckets_start_on_monday_midnight() {
        // 2026-03-09 is a Monday.
        let now = t("2026-03-11T12:00:00Z");
        let recs = [
            record("a", 1, "2026-03-09T00:00:00Z"),
            record("b", 2, "2026-03-10T05:00:00Z"),
            record("c", 3, "2026-03-08T23:59:59Z"),
            record("d", 4, "2026-03-02T00:00:00Z"),
            record("e", 5, "2026-03-11T08:00:00Z"),
            record("f", 6, "2026-03-01T10:00:00Z"),
        ];
        let plan = plan_prune(&recs, Tier::Local, &policy(0, 0, 2, 0, 0), now);
        assert_eq!(ids(&plan.keep), ["c", "e"]);
        assert_eq!(reason(&plan, "c"), Some(KeepReason::Weekly));
        assert_eq!(plan.delete, ["a", "b", "d", "f"]);
    }

    #[test]
    fn monthly_buckets_include_the_leap_day() {
        let now = t("2024-03-15T00:00:00Z");
        let recs = [
            record("m1", 1, "2024-03-01T00:00:00Z"),
            record("m2", 2, "2024-02-29T23:59:59Z"),
            record("m3", 3, "2024-02-29T00:00:00Z"),
            record("m4", 4, "2024-02-01T00:00:00Z"),
            record("m5", 5, "2024-01-31T23:59:59Z"),
            record("m6", 6, "2024-03-14T00:00:00Z"),
        ];
        let plan = plan_prune(&recs, Tier::Local, &policy(0, 0, 0, 2, 0), now);
        assert_eq!(ids(&plan.keep), ["m2", "m6"]);
        assert_eq!(reason(&plan, "m2"), Some(KeepReason::Monthly));
        assert_eq!(plan.delete, ["m1", "m3", "m4", "m5"]);
    }

    #[test]
    fn daily_window_crosses_a_leap_day() {
        let now = t("2024-03-01T10:00:00Z");
        let recs = [
            record("x", 1, "2024-02-28T23:00:00Z"),
            record("y", 2, "2024-02-29T23:00:00Z"),
            record("z", 3, "2024-03-01T09:00:00Z"),
        ];
        let plan = plan_prune(&recs, Tier::Local, &policy(0, 2, 0, 0, 0), now);
        assert_eq!(ids(&plan.keep), ["y", "z"]);
        assert_eq!(plan.delete, ["x"]);
    }

    #[test]
    fn year_boundary_week_and_month() {
        // 2025-12-29 is a Monday; its week holds Jan 1 2026.
        let now = t("2026-01-02T00:00:00Z");
        let recs = [
            record("dec", 1, "2025-12-31T23:00:00Z"),
            record("jan", 2, "2026-01-01T01:00:00Z"),
            record("old", 3, "2025-12-28T23:00:00Z"),
            record("new", 4, "2026-01-01T23:00:00Z"),
        ];
        let weekly = plan_prune(&recs, Tier::Local, &policy(0, 0, 1, 0, 0), now);
        assert_eq!(ids(&weekly.keep), ["new"]);
        let monthly = plan_prune(&recs, Tier::Local, &policy(0, 0, 0, 2, 0), now);
        assert_eq!(ids(&monthly.keep), ["dec", "new"]);
    }

    #[test]
    fn recent_window_is_strictly_younger_than_the_limit_and_future_counts_as_age_zero() {
        let now = t("2026-03-10T12:00:00Z");
        let recs = [
            record("newest", 9, "2026-03-10T11:00:00Z"),
            record("inside", 1, "2026-03-09T12:00:01Z"),
            record("edge", 2, "2026-03-09T12:00:00Z"),
            record("future", 3, "2026-03-12T00:00:00Z"),
        ];
        let plan = plan_prune(&recs, Tier::Local, &policy(24, 0, 0, 0, 0), now);
        assert_eq!(reason(&plan, "inside"), Some(KeepReason::Recent));
        assert_eq!(reason(&plan, "future"), Some(KeepReason::Newest));
        assert_eq!(plan.delete, ["edge"]);
        let hidden_future = [
            record("a", 1, "2026-03-12T00:00:00Z"),
            record("b", 2, "2026-03-13T00:00:00Z"),
        ];
        let p = plan_prune(&hidden_future, Tier::Local, &policy(1, 0, 0, 0, 0), now);
        assert_eq!(reason(&p, "a"), Some(KeepReason::Recent));
    }

    #[test]
    fn pre_restore_backups_live_for_their_own_window() {
        let now = t("2026-03-10T12:00:00Z");
        let mut young = record("pre1", 1, "2026-03-05T00:00:00Z");
        young.trigger = BackupTrigger::PreRestore;
        let mut old = record("pre2", 2, "2026-03-02T00:00:00Z");
        old.trigger = BackupTrigger::PreRestore;
        let newest = record("n", 3, "2026-03-10T11:00:00Z");
        let plan = plan_prune(
            &[young, old, newest],
            Tier::Local,
            &policy(0, 0, 0, 0, 7),
            now,
        );
        assert_eq!(reason(&plan, "pre1"), Some(KeepReason::PreRestore));
        assert_eq!(plan.delete, ["pre2"]);
    }

    #[test]
    fn pinned_and_newest_are_never_deleted_even_with_an_empty_policy() {
        let now = t("2026-03-10T12:00:00Z");
        let mut pinned = record("pin", 1, "2020-01-01T00:00:00Z");
        pinned.pinned = true;
        let recs = [
            pinned,
            record("mid", 2, "2021-01-01T00:00:00Z"),
            record("last", 3, "2022-01-01T00:00:00Z"),
        ];
        let plan = plan_prune(&recs, Tier::Local, &policy(0, 0, 0, 0, 0), now);
        assert_eq!(reason(&plan, "pin"), Some(KeepReason::Pinned));
        assert_eq!(reason(&plan, "last"), Some(KeepReason::Newest));
        assert_eq!(plan.delete, ["mid"]);
    }

    #[test]
    fn newest_breaks_timestamp_ties_by_version() {
        let now = t("2026-03-10T12:00:00Z");
        let recs = [
            record("lo", 1, "2026-03-10T10:00:00Z"),
            record("hi", 2, "2026-03-10T10:00:00Z"),
        ];
        let plan = plan_prune(&recs, Tier::Local, &policy(0, 0, 0, 0, 0), now);
        assert_eq!(reason(&plan, "hi"), Some(KeepReason::Newest));
        assert_eq!(plan.delete, ["lo"]);
    }

    #[test]
    fn tiers_only_see_their_own_copies_and_finished_records() {
        let now = t("2026-03-10T12:00:00Z");
        let local_only = record("l", 1, "2026-03-01T00:00:00Z");
        let mut both = record("b", 2, "2026-03-02T00:00:00Z");
        both.s3 = Some(s3_copy("b"));
        let mut s3_only = record("s", 3, "2026-03-03T00:00:00Z");
        s3_only.local = None;
        s3_only.s3 = Some(s3_copy("s"));
        let mut failed = record("f", 4, "2026-03-04T00:00:00Z");
        failed.status = BackupStatus::Failed;
        let mut running = record("r", 5, "2026-03-05T00:00:00Z");
        running.status = BackupStatus::Running;
        let recs = [local_only, both, s3_only, failed, running];
        let local = plan_prune(&recs, Tier::Local, &policy(0, 0, 0, 0, 0), now);
        assert_eq!(ids(&local.keep), ["b"]);
        assert_eq!(local.delete, ["l"]);
        let s3 = plan_prune(&recs, Tier::S3, &policy(0, 0, 0, 0, 0), now);
        assert_eq!(ids(&s3.keep), ["s"]);
        assert_eq!(s3.delete, ["b"]);
    }

    #[test]
    fn records_with_unreadable_timestamps_are_kept() {
        let now = t("2026-03-10T12:00:00Z");
        let recs = [
            record("bad", 1, "yesterday"),
            record("ok", 2, "2026-03-09T00:00:00Z"),
        ];
        let plan = plan_prune(&recs, Tier::Local, &policy(0, 0, 0, 0, 0), now);
        assert_eq!(reason(&plan, "bad"), Some(KeepReason::Undated));
        assert_eq!(reason(&plan, "ok"), Some(KeepReason::Newest));
        assert!(plan.delete.is_empty());
    }

    #[test]
    fn offsets_are_normalised_to_utc() {
        let now = t("2026-03-10T12:00:00Z");
        // 2026-03-09T23:30:00-02:00 is 2026-03-10T01:30:00Z, so it shares the newest day with `b`.
        let recs = [
            record("a", 1, "2026-03-09T23:30:00-02:00"),
            record("b", 2, "2026-03-10T11:00:00Z"),
        ];
        let plan = plan_prune(&recs, Tier::Local, &policy(0, 1, 0, 0, 0), now);
        assert_eq!(plan.delete, ["a"]);
    }

    #[test]
    fn the_view_names_each_reason() {
        let now = t("2026-03-10T12:00:00Z");
        let recs = [
            record("a", 1, "2026-03-01T00:00:00Z"),
            record("b", 2, "2026-03-10T00:00:00Z"),
        ];
        let view = plan_prune(&recs, Tier::Local, &policy(0, 0, 0, 0, 0), now).to_view();
        assert_eq!(view.keep.len(), 1);
        assert_eq!(view.keep[0].reason, "newest");
        assert_eq!(view.delete, ["a"]);
    }

    #[test]
    fn failed_records_expire_after_thirty_days_and_copyless_ones_are_listed() {
        let now = t("2026-03-31T00:00:00Z");
        let mut old = record("old", 1, "2026-03-01T00:00:00Z");
        old.status = BackupStatus::Failed;
        let mut fresh = record("fresh", 2, "2026-03-02T00:00:00Z");
        fresh.status = BackupStatus::Failed;
        let mut undated = record("undated", 3, "nope");
        undated.status = BackupStatus::Failed;
        let mut running = record("run", 4, "2025-01-01T00:00:00Z");
        running.status = BackupStatus::Running;
        assert_eq!(
            expired_failed(&[old, fresh, undated, running], now),
            ["old"]
        );

        let mut gone = record("gone", 5, "2026-03-01T00:00:00Z");
        gone.local = None;
        let kept = record("kept", 6, "2026-03-01T00:00:00Z");
        let mut running = record("run", 7, "2026-03-01T00:00:00Z");
        running.local = None;
        running.status = BackupStatus::Running;
        assert_eq!(without_copies(&[gone, kept, running]), ["gone"]);
    }

    fn arb_records() -> impl Strategy<Value = Vec<BackupRecord>> {
        proptest::collection::vec(
            (
                -48i64..(24 * 900),
                0u8..3,
                any::<bool>(),
                any::<bool>(),
                any::<bool>(),
                0u8..8,
            ),
            0..40,
        )
        .prop_map(|rows| {
            let base = t("2026-06-15T12:00:00Z");
            rows.into_iter()
                .enumerate()
                .map(|(i, (hours_ago, trig, pinned, local, s3, status))| {
                    let at = base - Duration::hours(hours_ago) - Duration::seconds(i as i64);
                    let mut r = record(
                        &format!("r{i}"),
                        i as u32 + 1,
                        &at.format(&Rfc3339).unwrap(),
                    );
                    r.trigger = match trig {
                        0 => BackupTrigger::Manual,
                        1 => BackupTrigger::Scheduled,
                        _ => BackupTrigger::PreRestore,
                    };
                    r.pinned = pinned;
                    r.local = local.then(|| r.local.clone().unwrap());
                    r.s3 = s3.then(|| s3_copy(&r.id));
                    r.status = match status {
                        0 => BackupStatus::Failed,
                        1 => BackupStatus::Running,
                        _ => BackupStatus::Ok,
                    };
                    r
                })
                .collect()
        })
    }

    fn arb_policy() -> impl Strategy<Value = BackupRetention> {
        (0u32..100, 0u32..40, 0u32..20, 0u32..24, 0u32..30)
            .prop_map(|(a, b, c, d, e)| policy(a, b, c, d, e))
    }

    fn eligible(recs: &[BackupRecord], tier: Tier) -> Vec<&BackupRecord> {
        recs.iter()
            .filter(|r| r.status == BackupStatus::Ok && has_copy(r, tier))
            .collect()
    }

    proptest! {
        #[test]
        fn plans_partition_the_eligible_records_and_protect_pinned_and_newest(
            recs in arb_records(), pol in arb_policy(), s3 in any::<bool>()
        ) {
            let tier = if s3 { Tier::S3 } else { Tier::Local };
            let now = t("2026-06-15T12:00:00Z");
            let plan = plan_prune(&recs, tier, &pol, now);
            let elig = eligible(&recs, tier);
            let mut seen: BTreeSet<&str> = BTreeSet::new();
            for id in plan.keep.iter().map(|(i, _)| i.as_str()).chain(plan.delete.iter().map(String::as_str)) {
                prop_assert!(seen.insert(id), "{id} listed twice");
            }
            let want: BTreeSet<&str> = elig.iter().map(|r| r.id.as_str()).collect();
            prop_assert_eq!(seen, want);
            for r in &elig {
                if r.pinned {
                    prop_assert!(!plan.delete.contains(&r.id));
                }
            }
            if let Some(newest) = elig.iter().max_by_key(|r| (parse_time(&r.created_at), r.version)) {
                prop_assert!(!plan.delete.contains(&newest.id));
            }
        }

        #[test]
        fn applying_a_plan_is_idempotent(recs in arb_records(), pol in arb_policy()) {
            let now = t("2026-06-15T12:00:00Z");
            let plan = plan_prune(&recs, Tier::Local, &pol, now);
            let remaining: Vec<BackupRecord> = recs
                .iter()
                .filter(|r| !plan.delete.contains(&r.id))
                .cloned()
                .collect();
            let again = plan_prune(&remaining, Tier::Local, &pol, now);
            prop_assert!(again.delete.is_empty(), "second pass deleted {:?}", again.delete);
            prop_assert_eq!(again.keep.len(), plan.keep.len());
        }

        #[test]
        fn adding_an_older_record_keeps_everything_that_was_kept(
            recs in arb_records(), pol in arb_policy(), extra_hours in 0i64..2000
        ) {
            let now = t("2026-06-15T12:00:00Z");
            let before = plan_prune(&recs, Tier::Local, &pol, now);
            let oldest = recs
                .iter()
                .filter_map(|r| parse_time(&r.created_at))
                .min()
                .unwrap_or(now);
            let at = oldest - Duration::hours(extra_hours + 1);
            let mut older = record("older", 0, &at.format(&Rfc3339).unwrap());
            older.version = 0;
            let mut grown = recs.clone();
            grown.push(older);
            let after = plan_prune(&grown, Tier::Local, &pol, now);
            let kept_after: BTreeSet<&str> = after.keep.iter().map(|(i, _)| i.as_str()).collect();
            for (id, _) in &before.keep {
                prop_assert!(kept_after.contains(id.as_str()), "{id} lost its keep");
            }
        }
    }
}
