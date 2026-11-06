use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use cite_core::atomic::write_atomic_in;
use cite_core::confined::{FileName, TrustedDir};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::store::now_rfc3339;
use crate::{ConnectorError, Result};

const FILE: &str = "zone-secrets.json";
const MAX_FILE_BYTES: u64 = 1024 * 1024;
const SECRET_BYTES: usize = 32;
const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn internal(what: &str, err: impl fmt::Display) -> ConnectorError {
    ConnectorError::Internal(format!("{what}: {err}"))
}

// Unpadded base64url, which is what keeps the secret inside the header-safe alphabet the firewall accepts.
fn b64url(bytes: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity((bytes.len() * 4).div_ceil(3)));
    for chunk in bytes.chunks(3) {
        let get = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
        let value = (get(0) << 16) | (get(1) << 8) | get(2);
        for i in 0..=chunk.len() {
            out.push(char::from(B64URL[((value >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
}

fn generate() -> Result<Zeroizing<String>> {
    let mut raw = Zeroizing::new([0u8; SECRET_BYTES]);
    getrandom::fill(&mut raw[..]).map_err(|e| internal("random source", e))?;
    Ok(b64url(&raw[..]))
}

pub fn fingerprint(secret: &str) -> String {
    Sha256::digest(secret.as_bytes())
        .iter()
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[derive(Clone)]
pub struct Entry {
    secret: Zeroizing<String>,
    pub created_at: String,
}

impl Entry {
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.secret)
    }
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("secret", &"<redacted>")
            .field("created_at", &self.created_at)
            .finish()
    }
}

#[derive(Serialize)]
struct RecordOut<'a> {
    secret: &'a str,
    created_at: &'a str,
}

#[derive(Deserialize)]
struct RecordIn {
    secret: String,
    created_at: String,
}

// The secrets one apply renders with; nothing in it is stored until `ZoneStore::commit`.
pub struct Plan {
    target: BTreeMap<String, Entry>,
    generated: BTreeSet<String>,
    pruned: bool,
}

impl Plan {
    pub fn secret_for(&self, site: &str) -> Option<String> {
        self.target.get(site).map(|e| e.secret.to_string())
    }

    pub fn secrets(&self) -> Vec<String> {
        self.target.values().map(|e| e.secret.to_string()).collect()
    }
}

impl fmt::Debug for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Plan")
            .field("sites", &self.target.keys().collect::<Vec<_>>())
            .field("secrets", &"<redacted>")
            .finish()
    }
}

pub struct Meta {
    pub created_at: String,
    pub fingerprint: String,
}

pub struct Rotated {
    pub secret: Zeroizing<String>,
    pub meta: Meta,
    pub previous: Option<Entry>,
}

impl fmt::Debug for Rotated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rotated")
            .field("secret", &"<redacted>")
            .field("fingerprint", &self.meta.fingerprint)
            .finish()
    }
}

// Per-site secrets for Cloudflare zone locks; they are injected into the rendered config only and never enter edge.json.
pub struct ZoneStore {
    dir: PathBuf,
    // Set when the file existed but could not be read: nothing is generated or written over it, and renders fail closed.
    broken: bool,
    secrets: Mutex<BTreeMap<String, Entry>>,
    // Test hook: -1 is off; otherwise that many writes succeed and the one after fails.
    #[cfg(test)]
    fail_in: std::sync::atomic::AtomicI64,
}

impl fmt::Debug for ZoneStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZoneStore")
            .field("sites", &self.lock().keys().collect::<Vec<_>>())
            .finish()
    }
}

impl ZoneStore {
    pub fn open(dir: PathBuf) -> Result<Self> {
        let secrets = match TrustedDir::open(&dir) {
            Ok(root) => read_file(&root)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(internal("cannot open the data directory", e)),
        };
        Ok(Self {
            dir,
            broken: false,
            secrets: Mutex::new(secrets),
            #[cfg(test)]
            fail_in: std::sync::atomic::AtomicI64::new(-1),
        })
    }

    pub fn unreadable(dir: PathBuf) -> Self {
        Self {
            dir,
            broken: true,
            secrets: Mutex::new(BTreeMap::new()),
            #[cfg(test)]
            fail_in: std::sync::atomic::AtomicI64::new(-1),
        }
    }

    #[cfg(test)]
    pub(crate) fn fail_write_after(&self, successes: i64) {
        self.fail_in
            .store(successes, std::sync::atomic::Ordering::SeqCst);
    }

    // True when the secrets file could not be read at start, so "no secret" may only mean "unknown".
    pub fn is_broken(&self) -> bool {
        self.broken
    }

    fn lock(&self) -> MutexGuard<'_, BTreeMap<String, Entry>> {
        self.secrets.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn secret_for(&self, site: &str) -> Option<String> {
        self.lock().get(site).map(|e| e.secret.to_string())
    }

    pub fn meta(&self, site: &str) -> Option<Meta> {
        self.lock().get(site).map(|e| Meta {
            created_at: e.created_at.clone(),
            fingerprint: e.fingerprint(),
        })
    }

    pub fn all_secrets(&self) -> Vec<String> {
        self.lock().values().map(|e| e.secret.to_string()).collect()
    }

    pub fn has_any(&self) -> bool {
        !self.lock().is_empty()
    }

    fn persist(&self, map: &BTreeMap<String, Entry>) -> Result<()> {
        #[cfg(test)]
        {
            use std::sync::atomic::Ordering;
            let left = self.fail_in.load(Ordering::SeqCst);
            if left == 0 {
                self.fail_in.store(-1, Ordering::SeqCst);
                return Err(internal(
                    "cannot write the zone secrets",
                    "injected failure",
                ));
            }
            if left > 0 {
                self.fail_in.store(left - 1, Ordering::SeqCst);
            }
        }
        if self.broken {
            return Err(ConnectorError::Internal(
                "zone-secrets.json could not be read at start; fix or remove it".into(),
            ));
        }
        let records: BTreeMap<&str, RecordOut<'_>> = map
            .iter()
            .map(|(site, e)| {
                (
                    site.as_str(),
                    RecordOut {
                        secret: &e.secret,
                        created_at: &e.created_at,
                    },
                )
            })
            .collect();
        let bytes = Zeroizing::new(serde_json::to_vec(&records)?);
        let root = TrustedDir::open(&self.dir)
            .map_err(|e| internal("cannot open the data directory", e))?;
        let name = FileName::new(FILE).map_err(|e| internal("zone secret file name", e))?;
        write_atomic_in(&root, &name, &bytes, 0o600)
            .map_err(|e| internal("cannot write the zone secrets", e))
    }

    // What the secrets should look like for these locked sites, without touching the store: stored secrets are reused and only a site that has none gets a new one.
    pub fn plan(&self, locked: &[String]) -> Result<Plan> {
        let map = self.lock();
        let mut target = BTreeMap::new();
        let mut generated = BTreeSet::new();
        for site in locked {
            if let Some(entry) = map.get(site) {
                target.insert(site.clone(), entry.clone());
            } else if !self.broken {
                // an unreadable file must not be overwritten; the render fails closed instead
                target.insert(
                    site.clone(),
                    Entry {
                        secret: generate()?,
                        created_at: now_rfc3339(),
                    },
                );
                generated.insert(site.clone());
            }
        }
        let pruned = map.keys().any(|site| !locked.contains(site));
        Ok(Plan {
            target,
            generated,
            pruned,
        })
    }

    // Called only after the planned config has been validated and loaded: new secrets are stored and those of sites no longer locked are dropped.
    pub fn commit(&self, plan: Plan) -> Result<()> {
        if self.broken || (plan.generated.is_empty() && !plan.pruned) {
            return Ok(());
        }
        let mut map = self.lock();
        let before = map.clone();
        map.retain(|site, _| plan.target.contains_key(site));
        for site in &plan.generated {
            if let Some(entry) = plan.target.get(site) {
                map.entry(site.clone()).or_insert_with(|| entry.clone());
            }
        }
        if let Err(e) = self.persist(&map) {
            *map = before;
            return Err(e);
        }
        Ok(())
    }

    // Replaces or creates the secret; `previous` lets the caller undo the rotation if HAProxy refuses the new config.
    pub fn rotate(&self, site: &str) -> Result<Rotated> {
        let mut map = self.lock();
        let fresh = Entry {
            secret: generate()?,
            created_at: now_rfc3339(),
        };
        let previous = map.insert(site.to_string(), fresh.clone());
        if let Err(e) = self.persist(&map) {
            match previous {
                Some(old) => map.insert(site.to_string(), old),
                None => map.remove(site),
            };
            return Err(e);
        }
        Ok(Rotated {
            secret: fresh.secret.clone(),
            meta: Meta {
                created_at: fresh.created_at.clone(),
                fingerprint: fresh.fingerprint(),
            },
            previous,
        })
    }

    pub fn restore(&self, site: &str, previous: Option<Entry>) -> Result<()> {
        let mut map = self.lock();
        let before = map.clone();
        match previous {
            Some(old) => map.insert(site.to_string(), old),
            None => map.remove(site),
        };
        if let Err(e) = self.persist(&map) {
            // memory keeps matching the file, so a failed undo never leaves the two disagreeing
            *map = before;
            return Err(e);
        }
        Ok(())
    }
}

fn read_file(root: &TrustedDir) -> Result<BTreeMap<String, Entry>> {
    let name = FileName::new(FILE).map_err(|e| internal("zone secret file name", e))?;
    let bytes = match root.read_limited(&name, MAX_FILE_BYTES) {
        Ok(b) => Zeroizing::new(b),
        Err(cite_core::Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(BTreeMap::new());
        }
        Err(e) => return Err(internal("cannot read zone-secrets.json", e)),
    };
    // serde errors can quote input, so the text of this one is not passed on
    let records: BTreeMap<String, RecordIn> = serde_json::from_slice(&bytes)
        .map_err(|_| ConnectorError::Internal("zone-secrets.json is not valid".into()))?;
    Ok(records
        .into_iter()
        .map(|(site, r)| {
            (
                site,
                Entry {
                    secret: Zeroizing::new(r.secret),
                    created_at: r.created_at,
                },
            )
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn ids(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    // Compares a secret without handing it to a macro that would print it when the check fails.
    fn holds(actual: Option<String>, expected: &str) -> bool {
        actual.as_deref() == Some(expected)
    }

    #[test]
    fn base64url_matches_known_vectors_without_padding() {
        assert_eq!(b64url(b"foobar").as_str(), "Zm9vYmFy");
        assert_eq!(b64url(b"fo").as_str(), "Zm8");
        assert_eq!(b64url(b"f").as_str(), "Zg");
        assert_eq!(b64url(&[0xfb, 0xff]).as_str(), "-_8");
    }

    #[test]
    fn generated_secrets_fit_the_firewall_rule() {
        let a = generate().unwrap();
        let b = generate().unwrap();
        assert_eq!(a.len(), 43);
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        );
        assert!(*a != *b, "two generated secrets must differ");
    }

    fn sync(store: &ZoneStore, sites: &[&str]) {
        let plan = store.plan(&ids(sites)).unwrap();
        store.commit(plan).unwrap();
    }

    #[test]
    fn planning_changes_nothing_until_it_is_committed() {
        let dir = tempfile::tempdir().unwrap();
        let store = ZoneStore::open(dir.path().to_path_buf()).unwrap();
        let first = store.rotate("a").unwrap();
        let plan = store.plan(&ids(&["b"])).unwrap();
        assert!(plan.secret_for("b").is_some());
        assert!(plan.secret_for("a").is_none());
        assert!(
            holds(store.secret_for("a"), first.secret.as_str()),
            "the stored secret changed"
        );
        assert!(store.secret_for("b").is_none());
        let reopened = ZoneStore::open(dir.path().to_path_buf()).unwrap();
        assert!(reopened.secret_for("a").is_some() && reopened.secret_for("b").is_none());
        let again = store.plan(&ids(&["a", "b"])).unwrap();
        assert!(
            holds(again.secret_for("a"), first.secret.as_str()),
            "the planned secret changed"
        );
        assert!(!format!("{again:?}").contains(first.secret.as_str()));
    }

    #[test]
    fn a_dropped_secret_is_planned_again_as_the_same_value_until_commit() {
        let dir = tempfile::tempdir().unwrap();
        let store = ZoneStore::open(dir.path().to_path_buf()).unwrap();
        let kept = store.rotate("a").unwrap();
        for _ in 0..2 {
            let _unlocked = store.plan(&[]).unwrap();
            let relocked = store.plan(&ids(&["a"])).unwrap();
            assert!(
                holds(relocked.secret_for("a"), kept.secret.as_str()),
                "the planned secret changed"
            );
        }
    }

    #[test]
    fn sync_generates_persists_and_prunes() {
        let dir = tempfile::tempdir().unwrap();
        let store = ZoneStore::open(dir.path().to_path_buf()).unwrap();
        assert!(!store.has_any());
        sync(&store, &["a", "b"]);
        let a = store.secret_for("a").unwrap();
        assert_eq!(a.len(), 43);
        let file = dir.path().join(FILE);
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        sync(&store, &["a"]);
        assert!(
            holds(store.secret_for("a"), a.as_str()),
            "the kept secret changed"
        );
        assert!(store.secret_for("b").is_none());

        let reopened = ZoneStore::open(dir.path().to_path_buf()).unwrap();
        assert!(
            holds(reopened.secret_for("a"), a.as_str()),
            "the file lost the secret"
        );
        assert!(
            reopened
                .meta("a")
                .is_some_and(|m| m.fingerprint == fingerprint(&a))
        );

        sync(&store, &[]);
        assert!(!store.has_any());
        assert!(!ZoneStore::open(dir.path().to_path_buf()).unwrap().has_any());
    }

    #[test]
    fn rotation_replaces_and_can_be_undone() {
        let dir = tempfile::tempdir().unwrap();
        let store = ZoneStore::open(dir.path().to_path_buf()).unwrap();
        let first = store.rotate("a").unwrap();
        assert!(first.previous.is_none());
        let second = store.rotate("a").unwrap();
        assert!(
            *first.secret != *second.secret,
            "a rotation must change the secret"
        );
        assert!(
            first.meta.fingerprint != second.meta.fingerprint,
            "a rotation must change the fingerprint"
        );
        assert!(
            holds(store.secret_for("a"), second.secret.as_str()),
            "the rotated secret is not the stored one"
        );
        store.restore("a", second.previous).unwrap();
        assert!(
            holds(store.secret_for("a"), first.secret.as_str()),
            "the restore did not bring the first secret back"
        );
        store.restore("a", None).unwrap();
        assert!(store.secret_for("a").is_none());
    }

    #[test]
    fn a_failed_restore_leaves_memory_matching_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = ZoneStore::open(dir.path().to_path_buf()).unwrap();
        let first = store.rotate("a").unwrap();
        let second = store.rotate("a").unwrap();
        store.fail_write_after(0);
        assert!(store.restore("a", second.previous).is_err());
        assert!(
            holds(store.secret_for("a"), second.secret.as_str()),
            "memory no longer matches the file"
        );
        let reopened = ZoneStore::open(dir.path().to_path_buf()).unwrap();
        assert!(
            holds(reopened.secret_for("a"), second.secret.as_str()),
            "the file no longer matches memory"
        );
        assert!(*first.secret != *second.secret, "the secrets must differ");
    }

    #[test]
    fn debug_output_hides_the_secret() {
        let dir = tempfile::tempdir().unwrap();
        let store = ZoneStore::open(dir.path().to_path_buf()).unwrap();
        let rotated = store.rotate("a").unwrap();
        let entry = store.lock().get("a").cloned().unwrap();
        for text in [
            format!("{rotated:?}"),
            format!("{entry:?}"),
            format!("{store:?}"),
        ] {
            assert!(!text.contains(rotated.secret.as_str()), "{text}");
        }
    }

    #[test]
    fn an_unreadable_file_is_never_overwritten_and_nothing_is_generated() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILE), "not json").unwrap();
        assert!(ZoneStore::open(dir.path().to_path_buf()).is_err());
        let store = ZoneStore::unreadable(dir.path().to_path_buf());
        let plan = store.plan(&ids(&["a"])).unwrap();
        assert!(plan.secret_for("a").is_none());
        store.commit(plan).unwrap();
        assert!(store.secret_for("a").is_none());
        assert!(store.rotate("a").is_err());
        assert_eq!(
            std::fs::read_to_string(dir.path().join(FILE)).unwrap(),
            "not json"
        );
    }
}
