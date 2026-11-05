use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use cite_edge::analytics::RequestFilter;
use cite_edge::model::LogEvent;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use crate::{ArchiveItem, Error, Store, StoreOptions};

const DAY: i64 = 86_400_000;
// 12:00 UTC on a day, so the start of that day is NOW - DAY / 2.
const NOW: i64 = 1_730_721_600_000;
const DAY0: i64 = NOW - DAY / 2;

fn open_archived() -> (TempDir, Store, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let archive = dir.path().join("archive");
    let store = Store::open(
        &dir.path().join("events.db"),
        StoreOptions {
            archive_dir: Some(archive.clone()),
            ..StoreOptions::default()
        },
    )
    .expect("open");
    (dir, store, archive)
}

fn rich(ts: i64, i: usize) -> LogEvent {
    LogEvent {
        ts_ms: ts,
        client_ip: format!("203.0.113.{}", i % 7),
        host: format!("h{}.test", i % 3),
        method: "GET".into(),
        path: format!("/p/{i}"),
        query_len: u32::try_from(i).expect("small"),
        status: [200, 404, 500][i % 3],
        bytes_in: 100 + i as u64,
        bytes_out: 1000 + 10 * i as u64,
        total_ms: 5 + i as u32,
        user_agent: format!("ua-{}", i % 4),
        referer: if i.is_multiple_of(2) {
            "https://r.test/".into()
        } else {
            String::new()
        },
        content_type: "text/html".into(),
        backend: "be_s_blue".into(),
        server: "app1".into(),
        site: if i.is_multiple_of(2) {
            "shop".into()
        } else {
            String::new()
        },
        blocked: (i.is_multiple_of(5)).then(|| "rate-limit".to_string()),
        http_version: "HTTP/2.0".into(),
        accept_language: "en-GB".into(),
        tls_version: "TLSv1.3".into(),
        resp_ms: 3 + i as u32,
        bot_score: u8::try_from(i % 100).expect("score"),
        bot_class: if i.is_multiple_of(3) {
            "crawler".into()
        } else {
            "human".into()
        },
        bot_signals: if i.is_multiple_of(3) {
            "no_referer,headless".into()
        } else {
            String::new()
        },
        ..LogEvent::default()
    }
}

fn day_events(day_start: i64, count: usize) -> Vec<LogEvent> {
    (0..count)
        .map(|i| rich(day_start + 1000 * (i as i64 + 1), i))
        .collect()
}

fn rows(s: &Store) -> u64 {
    s.stats().expect("stats").rows
}

fn all(s: &Store) -> Vec<LogEvent> {
    s.requests(&RequestFilter::default(), 100_000)
        .expect("requests")
}

fn archive_name(from: i64) -> String {
    format!("requests-{:013}-{:013}.ndjson.gz", from, from + DAY)
}

fn files_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .map(|it| {
            it.map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

fn expiring(s: &Store) {
    s.set_retention_days(1);
}

#[test]
fn the_default_is_unlimited_retention_and_never_deletes() {
    let opts = StoreOptions::default();
    assert_eq!(opts.retention_days, 0);
    assert!(opts.archive_before_delete);
    let dir = tempfile::tempdir().expect("tempdir");
    let s = Store::open(&dir.path().join("events.db"), opts).expect("open");
    s.insert(&[rich(NOW - 400 * DAY, 1), rich(NOW - 5 * DAY, 2)])
        .expect("insert");
    let report = s.prune(NOW).expect("prune");
    assert_eq!(report.cutoff_ms, None);
    assert!(report.is_empty());
    assert_eq!(rows(&s), 2);
}

#[test]
fn pruning_archives_complete_days_and_keeps_the_rest() {
    let (_d, s, archive) = open_archived();
    expiring(&s);
    let mut events = day_events(DAY0 - 5 * DAY, 3);
    events.extend(day_events(DAY0 - 3 * DAY, 2));
    events.push(rich(DAY0 - DAY + 5000, 9));
    events.extend((0..4).map(|i| rich(NOW - 1000 - i, i as usize)));
    s.insert(&events).expect("insert");

    let report = s.prune(NOW).expect("prune");
    assert_eq!(report.archive_error, None);
    assert_eq!(report.expired_rows, 5);
    assert_eq!(report.archived_rows, 5);
    assert_eq!(rows(&s), 5);

    let list = s.list_archives().expect("list");
    assert_eq!(list.items.len(), 2);
    let names: Vec<&str> = list.items.iter().map(|i| i.name.as_str()).collect();
    assert!(names.contains(&archive_name(DAY0 - 5 * DAY).as_str()));
    assert!(names.contains(&archive_name(DAY0 - 3 * DAY).as_str()));
    assert_eq!(list.items.iter().map(|i| i.rows).sum::<u64>(), 5);
    for item in &list.items {
        assert_eq!(item.kind, "archive");
        assert_eq!(item.sha256.len(), 64);
        assert_eq!(
            item.bytes,
            fs::metadata(archive.join(&item.name)).expect("file").len()
        );
        assert!(item.from_ms.is_some() && item.to_ms >= item.from_ms);
    }
    assert!(list.dir_bytes >= list.items.iter().map(|i| i.bytes).sum::<u64>());
    assert!(s.prune(NOW).expect("again").is_empty());
}

#[test]
fn archiving_then_restoring_returns_the_original_rows() {
    let (_d, s, _a) = open_archived();
    let mut events = day_events(DAY0 - 4 * DAY, 25);
    events.extend(day_events(DAY0 - 2 * DAY, 10));
    s.insert(&events).expect("insert");
    let before = all(&s);
    assert_eq!(before.len(), 35);

    let cut = s.cut_before(NOW, true, false).expect("cut");
    assert_eq!((cut.rows, cut.archived_rows), (35, 35));
    assert_eq!(cut.files.len(), 2);
    assert_eq!(rows(&s), 0);

    let mut restored = 0;
    for name in &cut.files {
        restored += s.restore_archive(name).expect("restore");
    }
    assert_eq!(restored, 35);
    assert_eq!(all(&s), before);
    let summary = s.summary(30 * 86_400, None, NOW).expect("summary");
    assert_eq!(summary.requests, 35);
}

#[test]
fn a_manual_cut_inside_a_day_archives_only_the_older_part() {
    let (_d, s, _a) = open_archived();
    let day = DAY0 - DAY;
    s.insert(&[
        rich(day + 1000, 1),
        rich(day + 2000, 2),
        rich(day + 7_200_000, 3),
    ])
    .expect("insert");
    let cut = s.cut_before(day + 3_600_000, true, false).expect("cut");
    assert_eq!((cut.rows, cut.archived_rows), (2, 2));
    assert_eq!(cut.oldest_ms, Some(day + 1000));
    assert_eq!(rows(&s), 1);
    assert_eq!(s.restore_archive(&cut.files[0]).expect("restore"), 2);
    assert_eq!(rows(&s), 3);
}

#[test]
fn a_dry_run_counts_and_deletes_nothing() {
    let (_d, s, archive) = open_archived();
    s.insert(&day_events(DAY0 - 3 * DAY, 6)).expect("insert");
    let report = s.cut_before(NOW, true, true).expect("dry run");
    assert!(report.dry_run && report.archive);
    assert_eq!((report.rows, report.archived_rows), (6, 0));
    assert_eq!(report.oldest_ms, Some(DAY0 - 3 * DAY + 1000));
    assert!(report.files.is_empty());
    assert_eq!(rows(&s), 6);
    assert!(files_in(&archive).is_empty());
    let plain = s.cut_before(NOW, false, true).expect("plain dry run");
    assert_eq!(plain.rows, 6);
    assert_eq!(rows(&s), 6);
}

#[test]
fn a_cut_without_archiving_deletes_and_writes_no_files() {
    let (_d, s, archive) = open_archived();
    s.insert(&day_events(DAY0 - 3 * DAY, 4)).expect("insert");
    s.insert(&[rich(NOW - 1000, 1)]).expect("recent");
    let report = s.cut_before(DAY0, false, false).expect("cut");
    assert!(!report.archive);
    assert_eq!((report.rows, report.archived_rows), (4, 0));
    assert_eq!(rows(&s), 1);
    assert!(files_in(&archive).is_empty());
}

#[test]
fn a_cut_that_archives_needs_an_archive_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let s = Store::open(&dir.path().join("events.db"), StoreOptions::default()).expect("open");
    s.insert(&day_events(DAY0 - 3 * DAY, 2)).expect("insert");
    for dry_run in [true, false] {
        assert!(matches!(
            s.cut_before(NOW, true, dry_run),
            Err(Error::Rejected(_))
        ));
    }
    assert!(matches!(s.backup(), Err(Error::Rejected(_))));
    assert!(matches!(s.list_archives(), Err(Error::Rejected(_))));
    assert_eq!(rows(&s), 2);
}

#[test]
fn a_failed_verification_deletes_nothing_and_the_next_pass_retries() {
    let (_d, s, archive) = open_archived();
    expiring(&s);
    s.insert(&day_events(DAY0 - 5 * DAY, 8)).expect("insert");
    s.inner.archive_fault.store(true, Ordering::Relaxed);

    let report = s.prune(NOW).expect("prune");
    assert!(
        report
            .archive_error
            .as_deref()
            .is_some_and(|e| e.contains("verification"))
    );
    assert_eq!((report.expired_rows, report.archived_rows), (0, 0));
    assert_eq!(rows(&s), 8);
    assert!(files_in(&archive).is_empty(), "{:?}", files_in(&archive));
    assert!(matches!(
        s.cut_before(NOW, true, false),
        Err(Error::Archive(_))
    ));
    assert_eq!(rows(&s), 8);

    s.inner.archive_fault.store(false, Ordering::Relaxed);
    let retry = s.prune(NOW).expect("retry");
    assert_eq!(retry.archive_error, None);
    assert_eq!((retry.expired_rows, retry.archived_rows), (8, 8));
    assert_eq!(rows(&s), 0);
}

#[test]
fn an_unwritable_archive_directory_deletes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let blocker = dir.path().join("file");
    fs::write(&blocker, b"x").expect("blocker");
    let s = Store::open(
        &dir.path().join("events.db"),
        StoreOptions {
            archive_dir: Some(blocker.join("archive")),
            retention_days: 1,
            ..StoreOptions::default()
        },
    )
    .expect("open");
    s.insert(&day_events(DAY0 - 5 * DAY, 3)).expect("insert");
    let report = s.prune(NOW).expect("prune");
    assert!(report.archive_error.is_some());
    assert_eq!(report.expired_rows, 0);
    assert!(s.cut_before(NOW, true, false).is_err());
    assert_eq!(rows(&s), 3);
}

#[test]
fn age_deletion_waits_when_archiving_is_on_but_no_directory_exists() {
    let dir = tempfile::tempdir().expect("tempdir");
    let s = Store::open(
        &dir.path().join("events.db"),
        StoreOptions {
            retention_days: 1,
            ..StoreOptions::default()
        },
    )
    .expect("open");
    s.insert(&day_events(DAY0 - 5 * DAY, 3)).expect("insert");
    let report = s.prune(NOW).expect("prune");
    assert!(report.archive_error.is_some());
    assert_eq!(rows(&s), 3);
    s.set_archive_before_delete(false);
    let report = s.prune(NOW).expect("prune without archiving");
    assert_eq!(report.expired_rows, 3);
}

#[test]
fn rows_arriving_after_a_day_was_archived_get_their_own_file() {
    let (_d, s, _a) = open_archived();
    let day = DAY0 - 3 * DAY;
    s.insert(&[rich(day + 1000, 1)]).expect("first");
    let first = s.cut_before(NOW, true, false).expect("first cut");
    s.insert(&[rich(day + 2000, 2)]).expect("late");
    let second = s.cut_before(NOW, true, false).expect("second cut");
    assert_eq!(first.files.len(), 1);
    assert_eq!(second.files.len(), 1);
    assert_ne!(first.files[0], second.files[0]);
    let list = s.list_archives().expect("list");
    assert_eq!(list.items.iter().map(|i| i.rows).sum::<u64>(), 2);
}

#[test]
fn bad_names_never_reach_the_filesystem() {
    let (_d, s, archive) = open_archived();
    s.insert(&day_events(DAY0 - 3 * DAY, 2)).expect("insert");
    s.cut_before(NOW, true, false).expect("cut");
    let outside = archive.parent().expect("parent").join("events.db");
    assert!(outside.exists());
    let valid = archive_name(DAY0 - 3 * DAY);
    let manifest = format!("{valid}.manifest.json");
    let leftover = format!("{valid}.tmp");
    let bad = [
        "",
        "..",
        "../events.db",
        "../backup-1.db",
        "/etc/passwd",
        "requests-1.ndjson.gz/../../events.db",
        "sub/requests-1.ndjson.gz",
        "sub\\requests-1.ndjson.gz",
        "requests-..ndjson.gz",
        ".requests-1.ndjson.gz",
        "requests-1.ndjson.gz\0",
        "requests-1.ndjson.gz ",
        "events.db",
        "notes.txt",
        manifest.as_str(),
        leftover.as_str(),
    ];
    for name in bad {
        assert!(
            matches!(s.restore_archive(name), Err(Error::Rejected(_))),
            "restore {name:?}"
        );
        assert!(
            matches!(s.delete_archive(name), Err(Error::Rejected(_))),
            "delete {name:?}"
        );
        assert!(
            matches!(s.open_archive(name), Err(Error::Rejected(_))),
            "open {name:?}"
        );
    }
    let long = format!("requests-{}.ndjson.gz", "1".repeat(200));
    assert!(matches!(s.open_archive(&long), Err(Error::Rejected(_))));
    assert!(outside.exists());
    assert_eq!(s.list_archives().expect("list").items.len(), 1);
}

#[test]
fn a_well_formed_name_that_does_not_exist_is_not_found() {
    let (_d, s, _a) = open_archived();
    let name = archive_name(DAY0);
    assert!(matches!(s.restore_archive(&name), Err(Error::NotFound(_))));
    assert!(matches!(s.delete_archive(&name), Err(Error::NotFound(_))));
    assert!(matches!(s.open_archive(&name), Err(Error::NotFound(_))));
}

#[cfg(unix)]
#[test]
fn a_symlink_in_the_archive_directory_is_not_followed() {
    let (dir, s, archive) = open_archived();
    fs::create_dir_all(&archive).expect("dir");
    let name = archive_name(DAY0);
    std::os::unix::fs::symlink(dir.path().join("events.db"), archive.join(&name)).expect("link");
    assert!(matches!(s.open_archive(&name), Err(Error::Rejected(_))));
    assert!(matches!(s.delete_archive(&name), Err(Error::Rejected(_))));
    assert!(dir.path().join("events.db").exists());
}

#[test]
fn a_damaged_archive_is_refused_before_anything_is_imported() {
    let (_d, s, archive) = open_archived();
    s.insert(&day_events(DAY0 - 3 * DAY, 12)).expect("insert");
    let cut = s.cut_before(NOW, true, false).expect("cut");
    let path = archive.join(&cut.files[0]);
    let mut bytes = fs::read(&path).expect("read");
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xff;
    fs::write(&path, bytes).expect("damage");
    assert!(matches!(
        s.restore_archive(&cut.files[0]),
        Err(Error::Archive(_))
    ));
    assert_eq!(rows(&s), 0);
}

#[test]
fn an_archive_without_a_manifest_is_neither_listed_nor_restorable() {
    let (_d, s, archive) = open_archived();
    s.insert(&day_events(DAY0 - 3 * DAY, 3)).expect("insert");
    let cut = s.cut_before(NOW, true, false).expect("cut");
    fs::remove_file(archive.join(format!("{}.manifest.json", cut.files[0]))).expect("remove");
    assert!(s.list_archives().expect("list").items.is_empty());
    assert!(matches!(
        s.restore_archive(&cut.files[0]),
        Err(Error::Archive(_))
    ));
}

#[test]
fn a_backup_is_a_checksummed_consistent_copy() {
    let (_d, s, archive) = open_archived();
    s.insert(&day_events(DAY0 - 2 * DAY, 30)).expect("insert");
    let item: ArchiveItem = s.backup().expect("backup");
    assert_eq!(item.kind, "backup");
    assert!(item.name.starts_with("backup-") && item.name.ends_with(".db"));
    assert_eq!(item.rows, 30);
    assert_eq!(item.from_ms, Some(DAY0 - 2 * DAY + 1000));
    assert_eq!(item.to_ms, Some(DAY0 - 2 * DAY + 30_000));

    let path = archive.join(&item.name);
    let bytes = fs::read(&path).expect("read");
    assert_eq!(item.bytes, bytes.len() as u64);
    let digest: String = Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(item.sha256, digest);
    let copy = rusqlite::Connection::open(&path).expect("open copy");
    let n: i64 = copy
        .query_row("SELECT count(*) FROM requests", [], |r| r.get(0))
        .expect("count");
    assert_eq!(n, 30);
    drop(copy);
    assert!(!archive.join(format!("{}-wal", item.name)).exists());

    let list = s.list_archives().expect("list");
    assert_eq!(list.items, vec![item.clone()]);
    assert!(matches!(
        s.restore_archive(&item.name),
        Err(Error::Rejected(_))
    ));
    assert_eq!(rows(&s), 30);
}

#[test]
fn deleting_an_archive_removes_the_file_and_its_manifest() {
    let (_d, s, archive) = open_archived();
    s.insert(&day_events(DAY0 - 3 * DAY, 3)).expect("insert");
    let cut = s.cut_before(NOW, true, false).expect("cut");
    assert_eq!(files_in(&archive).len(), 2);
    s.delete_archive(&cut.files[0]).expect("delete");
    assert!(files_in(&archive).is_empty());
    assert!(s.list_archives().expect("list").items.is_empty());
    assert!(matches!(
        s.delete_archive(&cut.files[0]),
        Err(Error::NotFound(_))
    ));
}

#[cfg(unix)]
#[test]
fn the_archive_directory_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let (_d, s, archive) = open_archived();
    s.insert(&day_events(DAY0 - 3 * DAY, 3)).expect("insert");
    let cut = s.cut_before(NOW, true, false).expect("cut");
    let mode = |p: &Path| fs::metadata(p).expect("meta").permissions().mode() & 0o777;
    assert_eq!(mode(&archive), 0o700);
    assert_eq!(mode(&archive.join(&cut.files[0])), 0o600);
}

fn archive_text(path: &Path) -> String {
    use std::io::Read;
    let mut text = String::new();
    flate2::read::GzDecoder::new(fs::File::open(path).expect("open"))
        .read_to_string(&mut text)
        .expect("gunzip");
    text
}

fn sha_of(path: &Path) -> String {
    Sha256::digest(fs::read(path).expect("read"))
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn a_second_restore_is_refused_unless_asked_for() {
    let (_d, s, _a) = open_archived();
    s.insert(&day_events(DAY0 - 3 * DAY, 6)).expect("insert");
    let cut = s.cut_before(NOW, true, false).expect("cut");
    let name = &cut.files[0];
    assert_eq!(s.restore_archive(name).expect("restore"), 6);
    assert!(matches!(s.restore_archive(name), Err(Error::Conflict(_))));
    assert_eq!(rows(&s), 6);
    assert_eq!(s.restore_archive_again(name).expect("again"), 6);
    assert_eq!(rows(&s), 12);
}

#[test]
fn concurrent_restores_import_the_archive_once() {
    let (_d, s, _a) = open_archived();
    s.insert(&day_events(DAY0 - 3 * DAY, 20)).expect("insert");
    let cut = s.cut_before(NOW, true, false).expect("cut");
    let name = &cut.files[0];
    let results: Vec<_> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|_| scope.spawn(|| s.restore_archive(name)))
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("join"))
            .collect()
    });
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert!(
        results
            .iter()
            .filter(|r| r.is_err())
            .all(|r| matches!(r, Err(Error::Conflict(_))))
    );
    assert_eq!(rows(&s), 20);
}

#[test]
fn a_failed_restore_leaves_no_marker_and_can_be_retried() {
    let (_d, s, archive) = open_archived();
    s.insert(&day_events(DAY0 - 3 * DAY, 12)).expect("insert");
    let cut = s.cut_before(NOW, true, false).expect("cut");
    let path = archive.join(&cut.files[0]);
    let good = fs::read(&path).expect("read");
    let mut bad = good.clone();
    let mid = bad.len() / 2;
    bad[mid] ^= 0xff;
    fs::write(&path, bad).expect("damage");
    assert!(s.restore_archive(&cut.files[0]).is_err());
    assert!(
        !files_in(&archive)
            .iter()
            .any(|n| n.ends_with(".restored.json"))
    );
    fs::write(&path, good).expect("repair");
    assert_eq!(s.restore_archive(&cut.files[0]).expect("retry"), 12);
}

#[test]
fn deleting_an_archive_also_removes_its_restore_marker() {
    let (_d, s, archive) = open_archived();
    s.insert(&day_events(DAY0 - 3 * DAY, 3)).expect("insert");
    let cut = s.cut_before(NOW, true, false).expect("cut");
    s.restore_archive(&cut.files[0]).expect("restore");
    assert!(
        files_in(&archive)
            .iter()
            .any(|n| n.ends_with(".restored.json"))
    );
    s.delete_archive(&cut.files[0]).expect("delete");
    assert!(files_in(&archive).is_empty());
}

#[test]
fn a_cut_inside_an_hour_rounds_down_so_a_restore_does_not_double_count() {
    let (_d, s, _a) = open_archived();
    let day = DAY0 - 2 * DAY;
    let hour = 3_600_000;
    let mut events = day_events(day, 5);
    events.push(rich(day + 3 * hour + 10_000, 1));
    events.push(rich(day + 3 * hour + 2_000_000, 2));
    events.push(rich(day + 3 * hour + 3_000_000, 3));
    s.insert(&events).expect("insert");
    let window = 30 * 86_400;
    let before = s.summary(window, None, NOW).expect("summary");

    let cut = s
        .cut_before(day + 3 * hour + 1_800_000, true, false)
        .expect("cut");
    assert_eq!(cut.cutoff_ms, day + 3 * hour);
    assert_eq!(cut.archived_rows, 5);
    let during = s.summary(window, None, NOW).expect("summary");
    assert_eq!(during.requests, 3);

    s.restore_archive(&cut.files[0]).expect("restore");
    let after = s.summary(window, None, NOW).expect("summary");
    assert_eq!(after.requests, before.requests);
    assert_eq!(rows(&s), 8);
}

#[test]
fn two_backups_at_once_both_succeed_under_different_names() {
    let (_d, s, archive) = open_archived();
    s.insert(&day_events(DAY0 - 2 * DAY, 10)).expect("insert");
    let items: Vec<_> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4).map(|_| scope.spawn(|| s.backup())).collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("join"))
            .collect()
    });
    let mut names: Vec<String> = items.into_iter().map(|r| r.expect("backup").name).collect();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), 4);
    assert!(!files_in(&archive).iter().any(|n| n.ends_with(".tmp")));
}

#[test]
fn oversized_lines_and_oversized_archives_are_refused_while_reading() {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;
    let gz = |bytes: &[u8]| {
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(bytes).expect("write");
        enc.finish().expect("finish")
    };
    let line = serde_json::to_string(&rich(NOW, 1)).expect("json");
    let ok = gz(format!("{line}\n{line}\n").as_bytes());
    let n = crate::archive::read_events_capped(ok.as_slice(), 4096, 1 << 20, |_| Ok(()));
    assert_eq!(n.expect("read"), 2);

    let long = gz(&vec![b'x'; 5000]);
    let err = crate::archive::read_events_capped(long.as_slice(), 4096, 1 << 20, |_| Ok(()));
    assert!(matches!(err, Err(Error::Archive(_))));

    let total = line.len() as u64 + 1;
    let err = crate::archive::read_events_capped(ok.as_slice(), 4096, total, |_| Ok(()));
    assert!(matches!(err, Err(Error::Archive(_))));
}

#[test]
fn scrubbing_blanks_archives_and_backups_and_keeps_them_valid() {
    let (_d, s, archive) = open_archived();
    s.insert(&day_events(DAY0 - 3 * DAY, 8)).expect("insert");
    let cut = s.cut_before(NOW, true, false).expect("cut");
    s.insert(&day_events(DAY0 - DAY / 2, 4)).expect("live");
    let backup = s.backup().expect("backup");
    s.restore_archive(&cut.files[0]).expect("restore");

    let path = archive.join(&cut.files[0]);
    assert!(archive_text(&path).contains("203.0.113."));
    let report = s.scrub_archived_fields(true, false).expect("scrub");
    assert_eq!((report.archives, report.backups, report.rows), (1, 1, 8));
    assert!(report.failed.is_empty());

    let text = archive_text(&path);
    assert!(!text.contains("203.0.113."));
    assert!(text.contains("ua-1"));
    let list = s.list_archives().expect("list");
    for item in &list.items {
        assert_eq!(item.sha256, sha_of(&archive.join(&item.name)));
    }
    let item = list
        .items
        .iter()
        .find(|i| i.name == cut.files[0])
        .expect("archive");
    assert_eq!(item.rows, 8);
    assert!(matches!(
        s.restore_archive(&cut.files[0]),
        Err(Error::Conflict(_))
    ));

    let copy = rusqlite::Connection::open(archive.join(&backup.name)).expect("open");
    let ips: i64 = copy
        .query_row(
            "SELECT (SELECT count(*) FROM requests WHERE client_ip_id IS NOT NULL) + (SELECT count(*) FROM dict WHERE kind = ?1)",
            [crate::schema::kind::CLIENT_IP],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(ips, 0);
    let uas: i64 = copy
        .query_row(
            "SELECT count(*) FROM requests WHERE ua_id IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .expect("count");
    assert!(uas > 0);
    drop(copy);
    let raw = fs::read(archive.join(&backup.name)).expect("read");
    assert!(!raw.windows(10).any(|w| w == b"203.0.113."));

    let again = s.scrub_archived_fields(true, true).expect("scrub both");
    assert_eq!((again.archives, again.backups), (1, 1));
    assert!(!archive_text(&path).contains("ua-1"));
    let none = s.scrub_archived_fields(true, true).expect("scrub clean");
    assert_eq!((none.archives, none.backups, none.rows), (0, 0, 0));
}

#[test]
fn a_scrub_waits_for_the_maintenance_lock_and_precedes_an_archive_pass() {
    let (_d, s, archive) = open_archived();
    s.insert(&day_events(DAY0 - 3 * DAY, 6)).expect("insert");
    let turn = s
        .inner
        .maintenance
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    std::thread::scope(|scope| {
        let scrub = scope.spawn(|| s.scrub_fields(true, false));
        std::thread::sleep(std::time::Duration::from_millis(300));
        let held = s
            .requests(&RequestFilter::default(), 100)
            .expect("requests");
        assert!(held.iter().all(|e| !e.client_ip.is_empty()));
        drop(turn);
        assert_eq!(scrub.join().expect("join").expect("scrub"), 6);
    });
    let cut = s.cut_before(NOW, true, false).expect("cut");
    assert!(!archive_text(&archive.join(&cut.files[0])).contains("203.0.113."));
}
