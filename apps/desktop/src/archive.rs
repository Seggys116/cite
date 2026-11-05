#[cfg(test)]
use cite_client::ARCHIVE_EXTENSIONS;
use cite_client::{ArchiveKind, CutRequest, archive_download_name};

use crate::bots::{fmt_stamp, parse_datetime};
use crate::demo::iso;
use crate::model::{fmt_bytes, fmt_int};

pub const MAX_KEEP_DAYS: u32 = 3650;
pub const DAY_MS: i64 = 86_400_000;
pub const ARCHIVE_MAX_BYTES: u64 = 16 * 1024 * 1024 * 1024;

pub fn kind_label(kind: ArchiveKind) -> &'static str {
    match kind {
        ArchiveKind::Archive => "Archive",
        ArchiveKind::Backup => "Backup",
        ArchiveKind::Unknown => "Other",
    }
}

// The client builds the local name: the stem is sanitised and the extension comes from a fixed list by kind.
pub fn download_name(kind: ArchiveKind, name: &str) -> String {
    archive_download_name(name, kind)
}

pub fn short_sha(sha: &str) -> String {
    let short: String = sha
        .chars()
        .take_while(char::is_ascii_hexdigit)
        .take(12)
        .collect();
    if short.is_empty() {
        "-".to_string()
    } else {
        short.to_ascii_lowercase()
    }
}

pub fn fmt_rows(rows: Option<u64>) -> String {
    rows.map_or_else(|| "-".to_string(), fmt_int)
}

pub fn fmt_day(ms: i64) -> String {
    iso(ms)[..10].to_string()
}

pub fn fmt_range(from: Option<i64>, to: Option<i64>) -> Option<String> {
    match (from, to) {
        (Some(a), Some(b)) => Some(format!("{} to {}", fmt_day(a), fmt_day(b))),
        _ => None,
    }
}

pub fn fmt_dir(items: usize, dir_bytes: u64) -> String {
    let noun = if items == 1 { "item" } else { "items" };
    format!("{items} {noun}, {} on disk", fmt_bytes(dir_bytes))
}

pub fn parse_keep_days(text: &str) -> Result<u32, String> {
    let t = text.trim();
    let range = format!("Enter a whole number of days from 1 to {MAX_KEEP_DAYS}.");
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        return Err(range);
    }
    match t.parse::<u32>() {
        Ok(n) if (1..=MAX_KEEP_DAYS).contains(&n) => Ok(n),
        _ => Err(range),
    }
}

// Deleting history without keeping a copy is the one combination worth warning about.
pub fn retention_warning(forever: bool, archive: bool, days: &str) -> Option<String> {
    if forever || archive {
        return None;
    }
    let span = match days.trim().parse::<u32>() {
        Ok(n) if n > 0 => format!("older than {n} days"),
        _ => "past the limit".to_string(),
    };
    Some(format!(
        "Data {span} will be deleted permanently and cannot be recovered. Turn on archiving to keep a copy first."
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CutBasis {
    Days,
    Date,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CutForm {
    pub basis: CutBasis,
    pub days: String,
    pub date: String,
    pub archive: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cutoff {
    Days(u32),
    At(i64),
}

// What a preview and the cut that follows must agree on: the cutoff and whether a copy is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CutSpec {
    pub cutoff: Cutoff,
    pub archive: bool,
}

impl CutForm {
    pub fn new() -> Self {
        Self {
            basis: CutBasis::Days,
            days: String::new(),
            date: String::new(),
            archive: true,
        }
    }

    pub fn spec(&self, now_ms: i64) -> Result<CutSpec, String> {
        let cutoff = match self.basis {
            CutBasis::Days => Cutoff::Days(parse_keep_days(&self.days)?),
            CutBasis::Date => {
                let Some(ms) = parse_datetime(&self.date) else {
                    return Err(
                        "Enter the cut date in UTC, for example 2026-01-31 or 2026-01-31 12:00."
                            .into(),
                    );
                };
                if ms <= 0 || ms >= now_ms {
                    return Err("The cut date must be in the past.".into());
                }
                Cutoff::At(ms)
            }
        };
        Ok(CutSpec {
            cutoff,
            archive: self.archive,
        })
    }
}

impl Default for CutForm {
    fn default() -> Self {
        Self::new()
    }
}

impl CutSpec {
    pub fn cutoff_ms(&self, now_ms: i64) -> i64 {
        match self.cutoff {
            Cutoff::Days(d) => now_ms - i64::from(d) * DAY_MS,
            Cutoff::At(ms) => ms,
        }
    }

    pub fn request(&self, dry_run: bool) -> Result<CutRequest, String> {
        let base = match self.cutoff {
            Cutoff::Days(d) => CutRequest::before_days(d),
            Cutoff::At(ms) => CutRequest::before_ms(ms),
        };
        let req = base.archive(self.archive).dry_run(dry_run);
        req.validate().map_err(|e| e.to_string())?;
        Ok(req)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preview {
    pub spec: CutSpec,
    pub rows: u64,
    pub oldest_ms: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Block {
    NeedsPreview,
    Stale,
    NothingToCut,
    NeedsAcknowledge,
}

impl Block {
    pub fn hint(self) -> &'static str {
        match self {
            Block::NeedsPreview => "Preview the cut first.",
            Block::Stale => "The cut changed since the preview. Preview it again.",
            Block::NothingToCut => "Nothing is older than that, so there is nothing to cut.",
            Block::NeedsAcknowledge => "Tick the box to confirm that the data is deleted for good.",
        }
    }
}

// A cut runs only for the exact settings that were previewed, and only once the user has accepted any data loss.
#[derive(Clone, Debug, Default)]
pub struct CutGate {
    preview: Option<Preview>,
}

impl CutGate {
    pub fn record(&mut self, preview: Preview) {
        self.preview = Some(preview);
    }

    pub fn clear(&mut self) {
        self.preview = None;
    }

    pub fn preview(&self) -> Option<&Preview> {
        self.preview.as_ref()
    }

    pub fn check(&self, spec: &CutSpec, understood: bool) -> Result<(), Block> {
        let Some(p) = &self.preview else {
            return Err(Block::NeedsPreview);
        };
        if p.spec != *spec {
            return Err(Block::Stale);
        }
        if p.rows == 0 {
            return Err(Block::NothingToCut);
        }
        if !spec.archive && !understood {
            return Err(Block::NeedsAcknowledge);
        }
        Ok(())
    }
}

// Without a kept copy the cut is irreversible, so the dialog stands between the click and the node.
pub fn needs_confirm(spec: &CutSpec) -> bool {
    !spec.archive
}

pub fn preview_text(rows: u64, oldest_ms: Option<i64>, cutoff_ms: i64, archive: bool) -> String {
    if rows == 0 {
        return format!("Nothing is older than {}.", fmt_stamp(cutoff_ms));
    }
    let oldest = oldest_ms.map_or(String::new(), |ms| {
        format!(", the oldest from {}", fmt_stamp(ms))
    });
    let tail = if archive {
        "A copy is archived first."
    } else {
        "No copy is kept."
    };
    format!(
        "{} rows are older than {}{oldest}. {tail}",
        fmt_int(rows),
        fmt_stamp(cutoff_ms)
    )
}

pub fn cut_done_text(rows: u64, archived_rows: u64, files: &[String], archive: bool) -> String {
    if !archive {
        return format!("Deleted {} rows.", fmt_int(rows));
    }
    let n = files.len();
    let noun = if n == 1 { "file" } else { "files" };
    format!(
        "Archived {} rows into {n} {noun} and deleted {} rows.",
        fmt_int(archived_rows),
        fmt_int(rows)
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Busy {
    Idle,
    Backup,
    Preview,
    Cut,
    Restore(String),
    Delete(String),
    Download(String),
}

impl Busy {
    pub fn is_idle(&self) -> bool {
        *self == Busy::Idle
    }

    pub fn label(&self) -> Option<String> {
        match self {
            Busy::Idle => None,
            Busy::Backup => Some("Backing up the database...".into()),
            Busy::Preview => Some("Counting the rows to cut...".into()),
            Busy::Cut => Some("Cutting old data...".into()),
            Busy::Restore(n) => Some(format!("Restoring {n}...")),
            Busy::Delete(n) => Some(format!("Deleting {n}...")),
            Busy::Download(n) => Some(format!("Downloading {n}...")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000_000;

    fn form(basis: CutBasis, days: &str, date: &str, archive: bool) -> CutForm {
        CutForm {
            basis,
            days: days.into(),
            date: date.into(),
            archive,
        }
    }

    fn preview(spec: CutSpec, rows: u64) -> Preview {
        Preview {
            spec,
            rows,
            oldest_ms: Some(NOW - 40 * DAY_MS),
        }
    }

    #[test]
    fn kinds_have_labels() {
        assert_eq!(kind_label(ArchiveKind::Archive), "Archive");
        assert_eq!(kind_label(ArchiveKind::Backup), "Backup");
        assert_eq!(kind_label(ArchiveKind::Unknown), "Other");
    }

    #[test]
    fn download_names_use_the_allowlist_only() {
        assert_eq!(
            download_name(ArchiveKind::Backup, "cite-backup-20261105.db"),
            "cite-backup-20261105.db"
        );
        assert_eq!(download_name(ArchiveKind::Backup, "x.exe"), "x_exe.db");
        assert_eq!(
            download_name(ArchiveKind::Archive, "march.csv.gz"),
            "march.csv.gz"
        );
        assert_eq!(
            download_name(ArchiveKind::Archive, "march"),
            "march.ndjson.gz"
        );
        for kind in [
            ArchiveKind::Archive,
            ArchiveKind::Backup,
            ArchiveKind::Unknown,
        ] {
            let name = download_name(kind, "q.zip");
            assert!(ARCHIVE_EXTENSIONS.iter().any(|e| name.ends_with(e)));
        }
    }

    #[test]
    fn entries_format_for_the_table() {
        assert_eq!(short_sha("ABCDEF0123456789abcdef"), "abcdef012345");
        assert_eq!(short_sha("abc"), "abc");
        assert_eq!(short_sha(""), "-");
        assert_eq!(short_sha("zzzz"), "-");
        assert_eq!(fmt_rows(Some(1_234_567)), "1,234,567");
        assert_eq!(fmt_rows(None), "-");
        assert_eq!(fmt_day(1_700_000_123_000), "2023-11-14");
        assert_eq!(
            fmt_range(Some(1_700_000_123_000), Some(1_700_000_123_000 + DAY_MS)),
            Some("2023-11-14 to 2023-11-15".into())
        );
        assert_eq!(fmt_range(Some(1), None), None);
        assert_eq!(fmt_dir(1, 1536), "1 item, 1.5 KB on disk");
        assert_eq!(fmt_dir(0, 0), "0 items, 0 B on disk");
    }

    #[test]
    fn keep_days_accept_one_to_the_maximum() {
        assert_eq!(parse_keep_days("1"), Ok(1));
        assert_eq!(parse_keep_days(" 365 "), Ok(365));
        assert_eq!(parse_keep_days("3650"), Ok(3650));
        for bad in ["", "0", "3651", "-5", "9.5", "abc", "99999999999999"] {
            assert!(parse_keep_days(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn only_a_limit_without_archiving_warns() {
        assert!(retention_warning(true, false, "").is_none());
        assert!(retention_warning(false, true, "30").is_none());
        let w = retention_warning(false, false, "30").expect("warning");
        assert!(w.contains("30 days") && w.contains("permanently"));
        assert!(
            retention_warning(false, false, "")
                .expect("warning")
                .contains("past the limit")
        );
    }

    #[test]
    fn day_forms_build_a_spec_and_a_cutoff() {
        let spec = form(CutBasis::Days, "30", "", true)
            .spec(NOW)
            .expect("spec");
        assert_eq!(spec.cutoff, Cutoff::Days(30));
        assert!(spec.archive);
        assert_eq!(spec.cutoff_ms(NOW), NOW - 30 * DAY_MS);
        assert!(form(CutBasis::Days, "0", "", true).spec(NOW).is_err());
        assert!(form(CutBasis::Days, "", "", true).spec(NOW).is_err());
    }

    #[test]
    fn date_forms_must_be_a_past_utc_date() {
        let spec = form(CutBasis::Date, "", "2023-01-01", false)
            .spec(NOW)
            .expect("spec");
        let ms = parse_datetime("2023-01-01").expect("ms");
        assert_eq!(spec.cutoff, Cutoff::At(ms));
        assert_eq!(spec.cutoff_ms(NOW), ms);
        assert!(!spec.archive);
        assert!(
            form(CutBasis::Date, "", "2030-01-01", true)
                .spec(NOW)
                .unwrap_err()
                .contains("past")
        );
        assert!(
            form(CutBasis::Date, "", "soon", true)
                .spec(NOW)
                .unwrap_err()
                .contains("UTC")
        );
        assert!(form(CutBasis::Date, "", "", true).spec(NOW).is_err());
    }

    #[test]
    fn specs_turn_into_valid_requests() {
        let days = CutSpec {
            cutoff: Cutoff::Days(90),
            archive: true,
        };
        assert!(days.request(true).is_ok());
        assert!(days.request(false).is_ok());
        let at = CutSpec {
            cutoff: Cutoff::At(NOW - DAY_MS),
            archive: false,
        };
        assert!(at.request(true).is_ok());
    }

    #[test]
    fn the_gate_blocks_until_a_matching_preview_exists() {
        let spec = form(CutBasis::Days, "30", "", true)
            .spec(NOW)
            .expect("spec");
        let mut gate = CutGate::default();
        assert_eq!(gate.check(&spec, false), Err(Block::NeedsPreview));
        gate.record(preview(spec, 10));
        assert_eq!(gate.check(&spec, false), Ok(()));
        let other = form(CutBasis::Days, "60", "", true)
            .spec(NOW)
            .expect("spec");
        assert_eq!(gate.check(&other, false), Err(Block::Stale));
        let toggled = CutSpec {
            archive: false,
            ..spec
        };
        assert_eq!(gate.check(&toggled, true), Err(Block::Stale));
        gate.clear();
        assert!(gate.preview().is_none());
        assert_eq!(gate.check(&spec, true), Err(Block::NeedsPreview));
    }

    #[test]
    fn an_empty_preview_cannot_be_cut() {
        let spec = form(CutBasis::Days, "30", "", true)
            .spec(NOW)
            .expect("spec");
        let mut gate = CutGate::default();
        gate.record(preview(spec, 0));
        assert_eq!(gate.check(&spec, true), Err(Block::NothingToCut));
    }

    #[test]
    fn deleting_without_a_copy_needs_the_acknowledgement_and_a_dialog() {
        let spec = form(CutBasis::Days, "30", "", false)
            .spec(NOW)
            .expect("spec");
        let mut gate = CutGate::default();
        gate.record(preview(spec, 5));
        assert_eq!(gate.check(&spec, false), Err(Block::NeedsAcknowledge));
        assert_eq!(gate.check(&spec, true), Ok(()));
        assert!(needs_confirm(&spec));
        let kept = CutSpec {
            archive: true,
            ..spec
        };
        assert!(!needs_confirm(&kept));
        assert!(!Block::NeedsAcknowledge.hint().is_empty());
    }

    #[test]
    fn texts_describe_previews_and_results() {
        let cutoff = 1_700_000_123_000;
        assert_eq!(
            preview_text(0, None, cutoff, true),
            "Nothing is older than 2023-11-14 22:15 UTC."
        );
        let t = preview_text(1200, Some(cutoff - DAY_MS), cutoff, true);
        assert!(t.starts_with("1,200 rows are older than 2023-11-14 22:15 UTC"));
        assert!(t.contains("oldest from 2023-11-13 22:15 UTC"));
        assert!(t.ends_with("A copy is archived first."));
        assert!(preview_text(3, None, cutoff, false).ends_with("No copy is kept."));
        assert_eq!(cut_done_text(7, 0, &[], false), "Deleted 7 rows.");
        assert_eq!(
            cut_done_text(2000, 2000, &["a.ndjson.gz".into()], true),
            "Archived 2,000 rows into 1 file and deleted 2,000 rows."
        );
    }

    #[test]
    fn busy_states_label_themselves() {
        assert!(Busy::Idle.is_idle());
        assert_eq!(Busy::Idle.label(), None);
        assert!(!Busy::Cut.is_idle());
        assert!(
            Busy::Restore("a.db".into())
                .label()
                .expect("label")
                .contains("a.db")
        );
        assert!(Busy::Backup.label().is_some());
    }
}
