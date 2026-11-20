//! Backup catalog storage on the `cite-backups` volume.
//!
//! ```text
//! <root>/staging/<site>/            the only directory a site job sees
//! <root>/staging/_shared/           instance jobs ("_" never occurs in a site id)
//! <root>/sites/<site>/catalog.json
//! <root>/sites/<site>/<backup>.cbk
//! <root>/sites/<site>/sessions/    imports/
//! <root>/shared/catalog.json
//! ```
//!
//! Functions here are blocking and do no locking: the data service calls them from blocking tasks under its
//! per-site mutex, so every read-modify-write is serialised there.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use cite_core::atomic::{ensure_dir, read_limited, write_atomic};
use cite_edge::datawire::{BackupRecord, BackupStatus};
use serde::{Deserialize, Serialize};

pub const CATALOG_VERSION: u32 = 1;
/// Largest catalog file read or written.
pub const MAX_CATALOG_BYTES: u64 = 8 * 1024 * 1024;
/// Records kept per database.
pub const MAX_RECORDS: usize = 2000;
pub const SHARED_STAGING: &str = "_shared";
pub const INTERRUPTED: &str = "interrupted by a connector restart";
const CATALOG_FILE: &str = "catalog.json";

#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    #[error("catalog i/o: {0}")]
    Io(String),
    #[error("the catalog is larger than {max} bytes", max = MAX_CATALOG_BYTES)]
    TooLarge,
    #[error("the catalog version {0} is not supported")]
    Version(u32),
    #[error("the catalog is not valid: {0}")]
    Parse(String),
    #[error("{0} already has {max} backups and none can be dropped; delete some first", max = MAX_RECORDS)]
    Full(String),
    #[error("backup {0} already exists in the catalog")]
    Duplicate(String),
    #[error("{0:?} is not a valid site or backup id")]
    BadId(String),
}

/// `pg:<db>` for a managed database.
pub fn pg_key(db: &str) -> String {
    format!("pg:{db}")
}

/// `ext:<name>` for an external database.
pub fn ext_key(name: &str) -> String {
    format!("ext:{name}")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DbCatalog {
    pub next_version: u32,
    #[serde(default)]
    pub backups: Vec<BackupRecord>,
}

impl Default for DbCatalog {
    fn default() -> Self {
        DbCatalog {
            next_version: 1,
            backups: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub version: u32,
    #[serde(default)]
    pub databases: BTreeMap<String, DbCatalog>,
}

impl Default for Catalog {
    fn default() -> Self {
        Catalog {
            version: CATALOG_VERSION,
            databases: BTreeMap::new(),
        }
    }
}

impl Catalog {
    pub fn get(&self, key: &str) -> Option<&DbCatalog> {
        self.databases.get(key)
    }

    pub fn entry(&mut self, key: &str) -> &mut DbCatalog {
        self.databases.entry(key.to_string()).or_default()
    }

    /// The next version of a database; versions are never reused, even after records are deleted.
    pub fn allocate_version(&mut self, key: &str) -> Result<u32, CatalogError> {
        let db = self.entry(key);
        let v = db.next_version;
        db.next_version = v
            .checked_add(1)
            .ok_or_else(|| CatalogError::Parse("version counter overflow".into()))?;
        Ok(v)
    }

    /// Adds a record. At the record limit the oldest failed record is dropped first; with none to drop the add is refused.
    pub fn insert(&mut self, key: &str, record: BackupRecord) -> Result<(), CatalogError> {
        let db = self.entry(key);
        if db.backups.iter().any(|r| r.id == record.id) {
            return Err(CatalogError::Duplicate(record.id));
        }
        if db.backups.len() >= MAX_RECORDS {
            let victim = db
                .backups
                .iter()
                .position(|r| r.status == BackupStatus::Failed)
                .ok_or_else(|| CatalogError::Full(key.to_string()))?;
            db.backups.remove(victim);
        }
        if db.next_version <= record.version {
            db.next_version = record.version.saturating_add(1);
        }
        db.backups.push(record);
        Ok(())
    }

    pub fn find(&self, key: &str, id: &str) -> Option<&BackupRecord> {
        self.databases.get(key)?.backups.iter().find(|r| r.id == id)
    }

    pub fn find_mut(&mut self, key: &str, id: &str) -> Option<&mut BackupRecord> {
        self.databases
            .get_mut(key)?
            .backups
            .iter_mut()
            .find(|r| r.id == id)
    }

    pub fn remove(&mut self, key: &str, id: &str) -> Option<BackupRecord> {
        let db = self.databases.get_mut(key)?;
        let at = db.backups.iter().position(|r| r.id == id)?;
        Some(db.backups.remove(at))
    }

    /// Marks every running record failed; a connector restart killed whatever was producing it.
    pub fn recover_interrupted(&mut self, now_rfc3339: &str) -> usize {
        let mut changed = 0;
        for db in self.databases.values_mut() {
            for r in db
                .backups
                .iter_mut()
                .filter(|r| r.status == BackupStatus::Running)
            {
                r.status = BackupStatus::Failed;
                r.error = Some(INTERRUPTED.to_string());
                r.completed_at = Some(now_rfc3339.to_string());
                changed += 1;
            }
        }
        changed
    }

    fn validate(&self) -> Result<(), CatalogError> {
        if self.version != CATALOG_VERSION {
            return Err(CatalogError::Version(self.version));
        }
        for (key, db) in &self.databases {
            if db.backups.len() > MAX_RECORDS {
                return Err(CatalogError::Full(key.clone()));
            }
        }
        Ok(())
    }
}

fn io_err(e: impl std::fmt::Display) -> CatalogError {
    CatalogError::Io(e.to_string())
}

/// A missing file is an empty catalog; anything unreadable, oversized or of another version is an error and is never overwritten.
pub fn load(path: &Path) -> Result<Catalog, CatalogError> {
    if !path.try_exists().map_err(io_err)? {
        return Ok(Catalog::default());
    }
    let bytes = read_limited(path, MAX_CATALOG_BYTES + 1).map_err(io_err)?;
    if bytes.len() as u64 > MAX_CATALOG_BYTES {
        return Err(CatalogError::TooLarge);
    }
    let catalog: Catalog =
        serde_json::from_slice(&bytes).map_err(|e| CatalogError::Parse(e.to_string()))?;
    catalog.validate()?;
    Ok(catalog)
}

/// Atomic write, mode 0600. The parent directory must exist.
pub fn store(path: &Path, catalog: &Catalog) -> Result<(), CatalogError> {
    catalog.validate()?;
    let bytes = serde_json::to_vec_pretty(catalog).map_err(io_err)?;
    if bytes.len() as u64 > MAX_CATALOG_BYTES {
        return Err(CatalogError::TooLarge);
    }
    write_atomic(path, &bytes, 0o600).map_err(io_err)
}

/// A single path component: letters, digits, `_`, `.`, `-`; no leading dot, no `..`.
fn component(id: &str) -> Result<&str, CatalogError> {
    let ok = !id.is_empty()
        && id.len() <= 128
        && !id.starts_with('.')
        && !id.contains("..")
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
    if ok {
        Ok(id)
    } else {
        Err(CatalogError::BadId(id.to_string()))
    }
}

/// Paths of the backup volume as the connector sees it.
#[derive(Debug, Clone)]
pub struct BackupDirs {
    root: PathBuf,
}

/// What `BackupDirs::recover` did at start.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoverReport {
    pub interrupted: usize,
    pub staging_entries: usize,
    pub partials: usize,
    /// Catalogs that could not be read or written; they are left untouched.
    pub failures: Vec<String>,
}

impl BackupDirs {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        BackupDirs { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn lock_path(&self) -> PathBuf {
        self.root.join(".lock")
    }

    pub fn staging_root(&self) -> PathBuf {
        self.root.join("staging")
    }

    pub fn staging_dir(&self, site: &str) -> Result<PathBuf, CatalogError> {
        Ok(self.staging_root().join(component(site)?))
    }

    pub fn shared_staging_dir(&self) -> PathBuf {
        self.staging_root().join(SHARED_STAGING)
    }

    fn sites_root(&self) -> PathBuf {
        self.root.join("sites")
    }

    pub fn site_dir(&self, site: &str) -> Result<PathBuf, CatalogError> {
        Ok(self.sites_root().join(component(site)?))
    }

    pub fn catalog_path(&self, site: &str) -> Result<PathBuf, CatalogError> {
        Ok(self.site_dir(site)?.join(CATALOG_FILE))
    }

    /// `<site dir>/<backup id>.cbk`
    pub fn backup_file(&self, site: &str, backup_id: &str) -> Result<PathBuf, CatalogError> {
        Ok(self
            .site_dir(site)?
            .join(format!("{}.cbk", component(backup_id)?)))
    }

    /// The file a backup is written to before it is renamed into place.
    pub fn partial_file(&self, site: &str, backup_id: &str) -> Result<PathBuf, CatalogError> {
        Ok(self
            .site_dir(site)?
            .join(format!("{}.cbk.partial", component(backup_id)?)))
    }

    pub fn sessions_dir(&self, site: &str) -> Result<PathBuf, CatalogError> {
        Ok(self.site_dir(site)?.join("sessions"))
    }

    pub fn imports_dir(&self, site: &str) -> Result<PathBuf, CatalogError> {
        Ok(self.site_dir(site)?.join("imports"))
    }

    pub fn shared_dir(&self) -> PathBuf {
        self.root.join("shared")
    }

    pub fn shared_catalog_path(&self) -> PathBuf {
        self.shared_dir().join(CATALOG_FILE)
    }

    /// `<root>/shared/<backup id>/<part>.cbk`
    pub fn shared_part_file(&self, backup_id: &str, part: &str) -> Result<PathBuf, CatalogError> {
        Ok(self
            .shared_dir()
            .join(component(backup_id)?)
            .join(format!("{}.cbk", component(part)?)))
    }

    /// Creates the top-level directories, all 0700.
    pub fn ensure_layout(&self) -> Result<(), CatalogError> {
        for dir in [
            self.root.clone(),
            self.staging_root(),
            self.shared_staging_dir(),
            self.sites_root(),
            self.shared_dir(),
        ] {
            ensure_dir(&dir, 0o700).map_err(io_err)?;
        }
        Ok(())
    }

    /// Creates a site's directories (backups, sessions, imports and its staging directory), all 0700.
    pub fn ensure_site(&self, site: &str) -> Result<(), CatalogError> {
        for dir in [
            self.site_dir(site)?,
            self.sessions_dir(site)?,
            self.imports_dir(site)?,
            self.staging_dir(site)?,
        ] {
            ensure_dir(&dir, 0o700).map_err(io_err)?;
        }
        Ok(())
    }

    /// Sites that have a directory on the volume.
    pub fn sites(&self) -> Vec<String> {
        let Ok(rd) = fs::read_dir(self.sites_root()) else {
            return Vec::new();
        };
        let mut out: Vec<String> = rd
            .flatten()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        out.sort();
        out
    }

    /// Empties every staging directory but keeps the directories themselves. Symlinks are removed, never followed.
    pub fn clear_staging(&self) -> std::io::Result<usize> {
        let mut removed = 0;
        let rd = match fs::read_dir(self.staging_root()) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e),
        };
        for entry in rd.flatten() {
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                for inner in fs::read_dir(&path)?.flatten() {
                    remove_entry(&inner.path(), inner.file_type()?.is_dir())?;
                    removed += 1;
                }
            } else {
                fs::remove_file(&path)?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Deletes `*.cbk.partial` files directly inside site directories; a partial is never resumed.
    /// Import partials in `imports/` belong to resumable sessions and stay.
    pub fn remove_orphan_partials(&self) -> std::io::Result<usize> {
        let mut removed = 0;
        for site in self.sites() {
            let Ok(dir) = self.site_dir(&site) else {
                continue;
            };
            for entry in fs::read_dir(&dir)?.flatten() {
                let name = entry.file_name();
                if name.to_string_lossy().ends_with(".cbk.partial") && !entry.file_type()?.is_dir()
                {
                    fs::remove_file(entry.path())?;
                    removed += 1;
                }
            }
        }
        Ok(removed)
    }

    /// Start-up recovery: running records become failed, staging is emptied, orphan partials are deleted.
    /// A catalog that cannot be read is reported and left as it is.
    pub fn recover(&self, now_rfc3339: &str) -> RecoverReport {
        let mut report = RecoverReport::default();
        let mut paths: Vec<(String, PathBuf)> = self
            .sites()
            .into_iter()
            .filter_map(|s| self.catalog_path(&s).ok().map(|p| (format!("site {s}"), p)))
            .collect();
        paths.push(("shared instance".to_string(), self.shared_catalog_path()));
        for (label, path) in paths {
            match load(&path) {
                Ok(mut catalog) => {
                    let n = catalog.recover_interrupted(now_rfc3339);
                    if n > 0 {
                        match store(&path, &catalog) {
                            Ok(()) => report.interrupted += n,
                            Err(e) => report.failures.push(format!("{label}: {e}")),
                        }
                    }
                }
                Err(e) => report.failures.push(format!("{label}: {e}")),
            }
        }
        match self.clear_staging() {
            Ok(n) => report.staging_entries = n,
            Err(e) => report.failures.push(format!("staging: {e}")),
        }
        match self.remove_orphan_partials() {
            Ok(n) => report.partials = n,
            Err(e) => report.failures.push(format!("partial files: {e}")),
        }
        report
    }
}

fn remove_entry(path: &Path, is_dir: bool) -> std::io::Result<()> {
    if is_dir {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::retention::testutil::record;
    use std::os::unix::fs::PermissionsExt;

    fn dirs() -> (tempfile::TempDir, BackupDirs) {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = BackupDirs::new(tmp.path());
        dirs.ensure_layout().unwrap();
        (tmp, dirs)
    }

    #[test]
    fn missing_catalog_is_empty_and_round_trips_with_mode_0600() {
        let (_tmp, dirs) = dirs();
        dirs.ensure_site("shop").unwrap();
        let path = dirs.catalog_path("shop").unwrap();
        assert_eq!(load(&path).unwrap(), Catalog::default());
        let mut c = Catalog::default();
        let v = c.allocate_version("pg:app").unwrap();
        c.insert("pg:app", record("b1", v, "2026-03-01T00:00:00Z"))
            .unwrap();
        store(&path, &c).unwrap();
        assert_eq!(load(&path).unwrap(), c);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"version\": 1") && text.contains("\"next_version\": 2"));
    }

    #[test]
    fn versions_are_monotonic_and_never_reused_after_a_delete() {
        let mut c = Catalog::default();
        let v1 = c.allocate_version("pg:app").unwrap();
        let v2 = c.allocate_version("pg:app").unwrap();
        assert_eq!((v1, v2), (1, 2));
        c.insert("pg:app", record("b2", v2, "2026-03-01T00:00:00Z"))
            .unwrap();
        assert!(c.remove("pg:app", "b2").is_some());
        assert_eq!(c.allocate_version("pg:app").unwrap(), 3);
        assert_eq!(c.allocate_version("ext:billing").unwrap(), 1);
        assert_eq!(c.get("pg:app").unwrap().next_version, 4);
    }

    #[test]
    fn insert_keeps_the_counter_ahead_of_imported_versions_and_refuses_duplicates() {
        let mut c = Catalog::default();
        c.insert("pg:app", record("b", 9, "2026-03-01T00:00:00Z"))
            .unwrap();
        assert_eq!(c.get("pg:app").unwrap().next_version, 10);
        assert!(matches!(
            c.insert("pg:app", record("b", 10, "2026-03-02T00:00:00Z")),
            Err(CatalogError::Duplicate(_))
        ));
    }

    #[test]
    fn at_the_record_limit_the_oldest_failed_record_makes_room() {
        let mut c = Catalog::default();
        for i in 0..MAX_RECORDS {
            let mut r = record(&format!("r{i}"), i as u32 + 1, "2026-03-01T00:00:00Z");
            if i == 5 || i == 6 {
                r.status = BackupStatus::Failed;
            }
            c.insert("pg:app", r).unwrap();
        }
        c.insert("pg:app", record("extra", 5000, "2026-03-02T00:00:00Z"))
            .unwrap();
        let db = c.get("pg:app").unwrap();
        assert_eq!(db.backups.len(), MAX_RECORDS);
        assert!(c.find("pg:app", "r5").is_none() && c.find("pg:app", "r6").is_some());
        // r6 is the last failed one; after it goes, nothing can make room.
        c.insert("pg:app", record("extra2", 5001, "2026-03-02T00:00:00Z"))
            .unwrap();
        assert!(matches!(
            c.insert("pg:app", record("extra3", 5002, "2026-03-02T00:00:00Z")),
            Err(CatalogError::Full(_))
        ));
        assert_eq!(c.get("pg:app").unwrap().backups.len(), MAX_RECORDS);
    }

    #[test]
    fn find_edit_and_remove() {
        let mut c = Catalog::default();
        c.insert("pg:app", record("b1", 1, "2026-03-01T00:00:00Z"))
            .unwrap();
        c.find_mut("pg:app", "b1").unwrap().pinned = true;
        assert!(c.find("pg:app", "b1").unwrap().pinned);
        assert!(c.find("pg:other", "b1").is_none());
        assert_eq!(c.remove("pg:app", "b1").unwrap().id, "b1");
        assert!(c.remove("pg:app", "b1").is_none());
    }

    #[test]
    fn running_records_become_failed_on_recovery() {
        let mut c = Catalog::default();
        let mut run = record("run", 1, "2026-03-01T00:00:00Z");
        run.status = BackupStatus::Running;
        run.completed_at = None;
        c.insert("pg:app", run).unwrap();
        c.insert("pg:app", record("ok", 2, "2026-03-01T00:00:00Z"))
            .unwrap();
        assert_eq!(c.recover_interrupted("2026-03-02T00:00:00Z"), 1);
        let r = c.find("pg:app", "run").unwrap();
        assert_eq!(r.status, BackupStatus::Failed);
        assert_eq!(r.error.as_deref(), Some(INTERRUPTED));
        assert_eq!(r.completed_at.as_deref(), Some("2026-03-02T00:00:00Z"));
        assert_eq!(c.find("pg:app", "ok").unwrap().status, BackupStatus::Ok);
        assert_eq!(c.recover_interrupted("2026-03-02T00:00:00Z"), 0);
    }

    #[test]
    fn unreadable_catalogs_are_errors_and_never_replaced() {
        let (_tmp, dirs) = dirs();
        dirs.ensure_site("shop").unwrap();
        let path = dirs.catalog_path("shop").unwrap();
        fs::write(&path, b"{ not json").unwrap();
        assert!(matches!(load(&path), Err(CatalogError::Parse(_))));
        fs::write(&path, br#"{"version":2,"databases":{}}"#).unwrap();
        assert!(matches!(load(&path), Err(CatalogError::Version(2))));
        fs::write(&path, br#"{"version":1,"databases":{},"extra":1}"#).unwrap();
        assert!(matches!(load(&path), Err(CatalogError::Parse(_))));
        let big = vec![b' '; (MAX_CATALOG_BYTES + 10) as usize];
        fs::write(&path, big).unwrap();
        assert!(load(&path).is_err());

        let report = dirs.recover("2026-03-02T00:00:00Z");
        assert_eq!(report.failures.len(), 1, "{:?}", report.failures);
        assert!(report.failures[0].contains("site shop"));
        assert_eq!(fs::metadata(&path).unwrap().len(), MAX_CATALOG_BYTES + 10);
    }

    #[test]
    fn a_failed_store_leaves_the_old_catalog_intact() {
        let (_tmp, dirs) = dirs();
        dirs.ensure_site("shop").unwrap();
        let path = dirs.catalog_path("shop").unwrap();
        let mut c = Catalog::default();
        c.insert("pg:app", record("b1", 1, "2026-03-01T00:00:00Z"))
            .unwrap();
        store(&path, &c).unwrap();
        c.version = 7;
        assert!(matches!(store(&path, &c), Err(CatalogError::Version(7))));
        assert_eq!(
            load(&path).unwrap().find("pg:app", "b1").unwrap().version,
            1
        );
        let leftovers: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn paths_refuse_anything_that_could_leave_the_volume() {
        let (_tmp, dirs) = dirs();
        let long = "x".repeat(129);
        for bad in [
            "",
            "..",
            "../etc",
            "a/b",
            ".hidden",
            "a..b",
            "a b",
            "a\0b",
            long.as_str(),
        ] {
            assert!(dirs.site_dir(bad).is_err(), "{bad:?}");
            assert!(dirs.staging_dir(bad).is_err(), "{bad:?}");
            assert!(dirs.backup_file("shop", bad).is_err(), "{bad:?}");
            assert!(dirs.partial_file("shop", bad).is_err(), "{bad:?}");
        }
        let f = dirs
            .backup_file("shop", "01J0000000000000000000000A")
            .unwrap();
        assert!(f.ends_with("sites/shop/01J0000000000000000000000A.cbk"));
        let p = dirs.partial_file("shop", "abc").unwrap();
        assert!(p.ends_with("sites/shop/abc.cbk.partial"));
        assert!(
            dirs.shared_part_file("b", "globals")
                .unwrap()
                .ends_with("shared/b/globals.cbk")
        );
        assert!(dirs.shared_part_file("b", "../x").is_err());
        assert!(dirs.staging_dir("shop").unwrap().ends_with("staging/shop"));
        assert!(dirs.shared_staging_dir().ends_with("staging/_shared"));
    }

    #[test]
    fn layout_directories_are_private() {
        let (_tmp, dirs) = dirs();
        dirs.ensure_site("shop").unwrap();
        for d in [
            dirs.root().to_path_buf(),
            dirs.staging_root(),
            dirs.shared_staging_dir(),
            dirs.site_dir("shop").unwrap(),
            dirs.sessions_dir("shop").unwrap(),
            dirs.imports_dir("shop").unwrap(),
            dirs.staging_dir("shop").unwrap(),
            dirs.shared_dir(),
        ] {
            assert_eq!(
                fs::metadata(&d).unwrap().permissions().mode() & 0o777,
                0o700,
                "{d:?}"
            );
        }
        assert_eq!(dirs.sites(), ["shop"]);
    }

    #[test]
    fn recovery_fails_running_records_empties_staging_and_drops_partials() {
        let (_tmp, dirs) = dirs();
        dirs.ensure_site("shop").unwrap();
        dirs.ensure_site("blog").unwrap();
        let mut c = Catalog::default();
        let mut run = record("run", 1, "2026-03-01T00:00:00Z");
        run.status = BackupStatus::Running;
        c.insert("pg:app", run).unwrap();
        store(&dirs.catalog_path("shop").unwrap(), &c).unwrap();

        fs::write(dirs.staging_dir("shop").unwrap().join("job.dump"), b"plain").unwrap();
        let nested = dirs.staging_dir("blog").unwrap().join("sub");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("x"), b"x").unwrap();
        fs::write(dirs.shared_staging_dir().join("job.sizes"), b"x").unwrap();
        fs::write(dirs.root().join("staging").join("stray"), b"x").unwrap();
        let partial = dirs.partial_file("shop", "gone").unwrap();
        fs::write(&partial, b"half").unwrap();
        let keep = dirs.backup_file("shop", "kept").unwrap();
        fs::write(&keep, b"data").unwrap();
        let import = dirs.imports_dir("shop").unwrap().join("i1.cbk.partial");
        fs::write(&import, b"resumable").unwrap();

        let report = dirs.recover("2026-03-02T00:00:00Z");
        assert!(report.failures.is_empty(), "{:?}", report.failures);
        assert_eq!(report.interrupted, 1);
        assert_eq!(report.staging_entries, 4);
        assert_eq!(report.partials, 1);
        assert!(!partial.exists() && keep.exists() && import.exists());
        assert!(dirs.staging_dir("shop").unwrap().is_dir());
        assert_eq!(
            fs::read_dir(dirs.staging_dir("shop").unwrap())
                .unwrap()
                .count(),
            0
        );
        assert!(!dirs.root().join("staging").join("stray").exists());
        let after = load(&dirs.catalog_path("shop").unwrap()).unwrap();
        assert_eq!(
            after.find("pg:app", "run").unwrap().status,
            BackupStatus::Failed
        );
        // a second run finds nothing left to do
        assert_eq!(
            dirs.recover("2026-03-03T00:00:00Z"),
            RecoverReport::default()
        );
    }

    #[test]
    fn staging_cleanup_does_not_follow_symlinks() {
        let (tmp, dirs) = dirs();
        dirs.ensure_site("shop").unwrap();
        let outside = tmp.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("precious"), b"keep").unwrap();
        std::os::unix::fs::symlink(&outside, dirs.staging_dir("shop").unwrap().join("link"))
            .unwrap();
        dirs.clear_staging().unwrap();
        assert!(outside.join("precious").exists());
        assert!(!dirs.staging_dir("shop").unwrap().join("link").exists());
    }
}
