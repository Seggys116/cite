use serde::{Deserialize, Serialize};

use crate::error::ClientError;

type Res<T> = std::result::Result<T, ClientError>;

pub const MAX_ARCHIVE_NAME_CHARS: usize = 128;
pub const MAX_CUT_DAYS: u32 = 3650;
// The only extensions a suggested download name may carry, never one the node supplied.
pub const ARCHIVE_EXTENSIONS: [&str; 3] = [".ndjson.gz", ".db", ".csv.gz"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArchiveKind {
    Archive,
    Backup,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveEntry {
    pub name: String,
    pub kind: ArchiveKind,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub created_ms: i64,
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub rows: Option<u64>,
    #[serde(default)]
    pub from_ms: Option<i64>,
    #[serde(default)]
    pub to_ms: Option<i64>,
}

impl ArchiveEntry {
    pub fn download_name(&self) -> String {
        archive_download_name(&self.name, self.kind)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveList {
    #[serde(default)]
    pub items: Vec<ArchiveEntry>,
    #[serde(default)]
    pub dir_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CutRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    before_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    before_days: Option<u32>,
    archive: bool,
    dry_run: bool,
}

impl CutRequest {
    /// Cuts data older than this many days; archiving is on and the cut is real unless changed.
    pub fn before_days(days: u32) -> Self {
        Self {
            before_ms: None,
            before_days: Some(days),
            archive: true,
            dry_run: false,
        }
    }

    pub fn before_ms(ts: i64) -> Self {
        Self {
            before_ms: Some(ts),
            before_days: None,
            archive: true,
            dry_run: false,
        }
    }

    pub fn archive(mut self, archive: bool) -> Self {
        self.archive = archive;
        self
    }

    pub fn dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    pub fn validate(&self) -> Res<()> {
        match (self.before_ms, self.before_days) {
            (Some(_), Some(_)) => Err(invalid("set either before_ms or before_days, not both")),
            (None, None) => Err(invalid("a cut needs before_ms or before_days")),
            (Some(ts), None) if ts < 0 => Err(invalid("before_ms must not be negative")),
            (None, Some(days)) if !(1..=MAX_CUT_DAYS).contains(&days) => Err(invalid(format!(
                "before_days must be between 1 and {MAX_CUT_DAYS}"
            ))),
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CutReport {
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub cutoff_ms: i64,
    #[serde(default)]
    pub rows: u64,
    #[serde(default)]
    pub oldest_ms: Option<i64>,
    #[serde(default)]
    pub archived_rows: u64,
    #[serde(default)]
    pub files: Vec<String>,
    #[serde(default)]
    pub archive: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreReport {
    #[serde(default)]
    pub rows: u64,
}

fn invalid(message: impl Into<String>) -> ClientError {
    ClientError::Config(message.into())
}

/// Only [A-Za-z0-9._-], no leading dot, at most 128 characters, so a name can never be a path.
pub fn validate_archive_name(name: &str) -> Res<&str> {
    if name.is_empty() {
        return Err(invalid("archive name must not be empty"));
    }
    if name.len() > MAX_ARCHIVE_NAME_CHARS {
        return Err(invalid("archive name is too long"));
    }
    if name.starts_with('.') {
        return Err(invalid("archive name must not start with a dot"));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(invalid("archive name has unsupported characters"));
    }
    Ok(name)
}

/// Stem from the stored name, extension from the fixed allowlist by kind.
pub fn archive_download_name(name: &str, kind: ArchiveKind) -> String {
    let ext = match kind {
        ArchiveKind::Backup => ".db",
        _ if name.ends_with(".csv.gz") => ".csv.gz",
        _ => ".ndjson.gz",
    };
    let base = ARCHIVE_EXTENSIONS
        .iter()
        .find_map(|e| name.strip_suffix(e))
        .unwrap_or(name);
    let stem: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .take(MAX_ARCHIVE_NAME_CHARS)
        .collect();
    let stem = stem.trim_matches('_');
    let stem = if stem.is_empty() {
        match kind {
            ArchiveKind::Backup => "cite-backup",
            _ => "cite-archive",
        }
    } else {
        stem
    };
    format!("{stem}{ext}")
}

/// A backup is a database copy; every other stored name is treated as an archive.
pub fn archive_kind_from_name(name: &str) -> ArchiveKind {
    if name.ends_with(".db") {
        ArchiveKind::Backup
    } else {
        ArchiveKind::Archive
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_plain_file_names() {
        for ok in [
            "requests-2026-11-05.ndjson.gz",
            "analytics-20261105-101500.db",
            "a_b-c.1",
        ] {
            assert_eq!(validate_archive_name(ok).expect("valid"), ok);
        }
        let long = "a".repeat(129);
        let bad_names = [
            "",
            ".hidden",
            "..",
            "a/b",
            "a\\b",
            "a b",
            "a%2e",
            "a\n",
            "é.gz",
            long.as_str(),
        ];
        for bad in bad_names {
            assert!(
                matches!(validate_archive_name(bad), Err(ClientError::Config(_))),
                "{bad:?}"
            );
        }
        assert!(validate_archive_name(&"a".repeat(128)).is_ok());
    }

    #[test]
    fn cut_requests_validate_and_serialise_one_cutoff() {
        let by_days = CutRequest::before_days(30).dry_run(true);
        by_days.validate().expect("valid");
        assert_eq!(
            serde_json::to_value(&by_days).expect("json"),
            serde_json::json!({ "before_days": 30, "archive": true, "dry_run": true })
        );
        let by_ms = CutRequest::before_ms(1_700_000_000_000).archive(false);
        by_ms.validate().expect("valid");
        assert_eq!(
            serde_json::to_value(&by_ms).expect("json"),
            serde_json::json!({ "before_ms": 1_700_000_000_000_i64, "archive": false, "dry_run": false })
        );
        for bad in [
            CutRequest::before_days(0),
            CutRequest::before_days(MAX_CUT_DAYS + 1),
            CutRequest::before_ms(-1),
        ] {
            let result = bad.validate();
            assert!(matches!(result, Err(ClientError::Config(_))), "{bad:?}");
        }
        CutRequest::before_days(MAX_CUT_DAYS)
            .validate()
            .expect("max");
    }

    #[test]
    fn download_names_use_the_allowlisted_extension_for_the_kind() {
        let name = |n: &str, k| archive_download_name(n, k);
        assert_eq!(
            name("requests-2026-11-05.ndjson.gz", ArchiveKind::Archive),
            "requests-2026-11-05.ndjson.gz"
        );
        assert_eq!(
            name("analytics-20261105-101500.db", ArchiveKind::Backup),
            "analytics-20261105-101500.db"
        );
        assert_eq!(
            name("hourly-2026.csv.gz", ArchiveKind::Archive),
            "hourly-2026.csv.gz"
        );
        assert_eq!(name("evil.exe", ArchiveKind::Archive), "evil_exe.ndjson.gz");
        assert_eq!(name("evil.ndjson.gz", ArchiveKind::Backup), "evil.db");
        assert_eq!(name("....", ArchiveKind::Backup), "cite-backup.db");
        assert_eq!(
            name(".ndjson.gz", ArchiveKind::Unknown),
            "cite-archive.ndjson.gz"
        );
        assert_eq!(archive_kind_from_name("x.db"), ArchiveKind::Backup);
        assert_eq!(archive_kind_from_name("x.ndjson.gz"), ArchiveKind::Archive);
    }

    #[test]
    fn entries_decode_with_optional_fields_and_unknown_kinds() {
        let list: ArchiveList = serde_json::from_str(
            r#"{"items":[
                {"name":"requests-2026-11-05.ndjson.gz","kind":"archive","bytes":10,"created_ms":5,"sha256":"ab","rows":3,"from_ms":1,"to_ms":2},
                {"name":"analytics-1.db","kind":"backup","bytes":20,"created_ms":6,"sha256":"cd","rows":null,"from_ms":null,"to_ms":null},
                {"name":"x","kind":"future","bytes":1,"created_ms":1,"sha256":""}
            ],"dir_bytes":31}"#,
        )
        .expect("list");
        assert_eq!(list.dir_bytes, 31);
        assert_eq!(list.items[0].rows, Some(3));
        assert_eq!(list.items[1].kind, ArchiveKind::Backup);
        assert_eq!(list.items[1].rows, None);
        assert_eq!(list.items[2].kind, ArchiveKind::Unknown);
        assert_eq!(list.items[1].download_name(), "analytics-1.db");
    }
}
