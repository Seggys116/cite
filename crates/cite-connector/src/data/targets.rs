//! Node-level S3 backup destinations. They are separate from a site's own S3 attachments, so credentials an
//! application holds can never delete backups. Keys live in the sealed secret store; the list of targets in
//! `<data dir>/data/targets.json` holds no secret.

use cite_edge::datawire::{TargetReq, TargetTestResult, TargetView};
use cite_edge::validate::parse_s3_endpoint;
use serde::{Deserialize, Serialize};
use ulid::Ulid;
use zeroize::Zeroizing;

use super::s3::{S3Client, S3Error, S3Keys, S3Location};
use super::service::{DataService, S3Secret};
use crate::{ConnectorError, Result};

const FILE: &str = "targets.json";
const MAX_FILE: u64 = 1 << 20;
pub const MAX_TARGETS: usize = 16;
const DEFAULT_PREFIX: &str = "cite";

pub fn target_secret_name(id: &str) -> String {
    format!("node.data.target.{id}")
}

/// Validates a target's endpoint. Without `allow_private` the endpoint must be https and name a public
/// address. With it, plain http and the private ranges RFC 1918, ULA and CGNAT are allowed, but only to an
/// IP literal in those ranges for http; loopback, link-local (including the metadata address),
/// unspecified, multicast and other reserved literals stay refused. A host name is checked when it is
/// resolved at connect time.
fn check_endpoint(req: &TargetReq, allow_private: bool) -> Result<()> {
    if !allow_private {
        if !req.endpoint.starts_with("https://") {
            return Err(ConnectorError::BadRequest(
                "the endpoint must use https (CITE_DATA_S3_ALLOW_PRIVATE=true allows http to RFC 1918, ULA and CGNAT addresses)".into(),
            ));
        }
        parse_s3_endpoint(&req.endpoint)
            .map_err(|e| ConnectorError::BadRequest(format!("endpoint: {e}")))?;
    }
    S3Location::parse(&req.endpoint, &req.bucket, &req.region, req.path_style)
        .and_then(|loc| loc.check_literal(allow_private))
        .map_err(|e| ConnectorError::BadRequest(e.to_string()))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3Target {
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    #[serde(default)]
    pub path_style: bool,
    pub prefix: String,
    pub encrypt: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct TargetsFile {
    version: u32,
    #[serde(default)]
    targets: Vec<S3Target>,
}

impl S3Target {
    pub fn view(&self) -> TargetView {
        TargetView {
            id: self.id.clone(),
            name: self.name.clone(),
            endpoint: self.endpoint.clone(),
            bucket: self.bucket.clone(),
            region: self.region.clone(),
            path_style: self.path_style,
            prefix: self.prefix.clone(),
            encrypt: self.encrypt,
        }
    }
}

fn valid_prefix(p: &str) -> bool {
    let t = p.trim_matches('/');
    !t.is_empty()
        && t.len() <= 100
        && !t.contains("//")
        && t.split('/').all(|s| s != "." && s != "..")
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
}

impl DataService {
    fn targets_path(&self) -> std::path::PathBuf {
        self.cfg.data_dir.join("data").join(FILE)
    }

    fn read_targets(&self) -> Result<Vec<S3Target>> {
        let path = self.targets_path();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let bytes = cite_core::atomic::read_limited(&path, MAX_FILE).map_err(|e| {
            ConnectorError::Internal(format!("cannot read the backup targets: {e}"))
        })?;
        let file: TargetsFile = serde_json::from_slice(&bytes)
            .map_err(|_| ConnectorError::Internal("the backup targets file is damaged".into()))?;
        if file.version != 1 {
            return Err(ConnectorError::Internal(
                "the backup targets file has an unknown version".into(),
            ));
        }
        Ok(file.targets)
    }

    fn write_targets(&self, targets: Vec<S3Target>) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(&TargetsFile {
            version: 1,
            targets,
        })?;
        cite_core::atomic::write_atomic(&self.targets_path(), &bytes, 0o600)
            .map_err(|e| ConnectorError::Internal(format!("cannot write the backup targets: {e}")))
    }

    pub(crate) async fn list_targets(&self) -> Result<Vec<S3Target>> {
        let _g = self.targets_lock.lock().await;
        self.read_targets()
    }

    pub(crate) async fn target(&self, id: &str) -> Result<Option<S3Target>> {
        Ok(self.list_targets().await?.into_iter().find(|t| t.id == id))
    }

    fn check_target_fields(&self, name: &str, req: &TargetReq) -> Result<(String, bool)> {
        if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
            return Err(ConnectorError::BadRequest(
                "a target name has 1 to 64 characters and no control characters".into(),
            ));
        }
        check_endpoint(req, self.cfg.s3_allow_private)?;
        let prefix = req
            .prefix
            .clone()
            .unwrap_or_else(|| DEFAULT_PREFIX.to_string());
        if !valid_prefix(&prefix) {
            return Err(ConnectorError::BadRequest(
                "the prefix has 1 to 100 of letters, digits, '.', '_', '-' and '/'".into(),
            ));
        }
        if req.encrypt == Some(false) {
            return Err(ConnectorError::BadRequest(
                "backups are always encrypted before they leave the node; encrypt cannot be false"
                    .into(),
            ));
        }
        Ok((prefix.trim_matches('/').to_string(), true))
    }

    fn check_keys(keys: &S3Secret) -> Result<()> {
        let ok = |s: &str, max: usize| {
            !s.is_empty() && s.len() <= max && s.bytes().all(|b| b.is_ascii_graphic())
        };
        if !ok(&keys.access_key_id, 256) || !ok(&keys.secret_access_key, 512) {
            return Err(ConnectorError::BadRequest(
                "the S3 keys must be printable text without spaces".into(),
            ));
        }
        Ok(())
    }

    pub(crate) async fn create_target(&self, req: TargetReq) -> Result<TargetView> {
        let _g = self.targets_lock.lock().await;
        let mut all = self.read_targets()?;
        if all.len() >= MAX_TARGETS {
            return Err(ConnectorError::BadRequest(format!(
                "at most {MAX_TARGETS} backup targets"
            )));
        }
        let (prefix, encrypt) = self.check_target_fields(&req.name, &req)?;
        if all.iter().any(|t| t.name == req.name) {
            return Err(ConnectorError::Conflict(format!(
                "a target named {} exists",
                req.name
            )));
        }
        let (Some(id), Some(secret)) = (req.access_key_id.clone(), req.secret_access_key.clone())
        else {
            return Err(ConnectorError::BadRequest(
                "access_key_id and secret_access_key are required".into(),
            ));
        };
        let keys = S3Secret {
            access_key_id: id,
            secret_access_key: secret,
        };
        Self::check_keys(&keys)?;
        let target = S3Target {
            id: Ulid::generate().to_string().to_ascii_lowercase(),
            name: req.name.clone(),
            endpoint: req.endpoint.clone(),
            bucket: req.bucket.clone(),
            region: req.region.clone(),
            path_style: req.path_style,
            prefix,
            encrypt,
        };
        self.secret_put(None, &target_secret_name(&target.id), &keys)
            .await?;
        all.push(target.clone());
        if let Err(e) = self.write_targets(all) {
            self.secret_del(None, &target_secret_name(&target.id)).await;
            return Err(e);
        }
        Ok(target.view())
    }

    pub(crate) async fn update_target(&self, id: &str, req: TargetReq) -> Result<TargetView> {
        let _g = self.targets_lock.lock().await;
        let mut all = self.read_targets()?;
        let at = all
            .iter()
            .position(|t| t.id == id)
            .ok_or_else(|| ConnectorError::NotFound(format!("backup target {id} not found")))?;
        let (prefix, encrypt) = self.check_target_fields(&req.name, &req)?;
        if all.iter().any(|t| t.name == req.name && t.id != id) {
            return Err(ConnectorError::Conflict(format!(
                "a target named {} exists",
                req.name
            )));
        }
        let name = target_secret_name(id);
        let old: S3Secret = self
            .secret_get(&name)
            .await?
            .ok_or_else(|| ConnectorError::Unavailable("the target's keys are missing".into()))?;
        let keys = S3Secret {
            access_key_id: req
                .access_key_id
                .clone()
                .unwrap_or_else(|| old.access_key_id.clone()),
            secret_access_key: req
                .secret_access_key
                .clone()
                .unwrap_or_else(|| old.secret_access_key.clone()),
        };
        Self::check_keys(&keys)?;
        all[at] = S3Target {
            id: id.to_string(),
            name: req.name.clone(),
            endpoint: req.endpoint.clone(),
            bucket: req.bucket.clone(),
            region: req.region.clone(),
            path_style: req.path_style,
            prefix,
            encrypt,
        };
        let view = all[at].view();
        self.secret_put(None, &name, &keys).await?;
        if let Err(e) = self.write_targets(all) {
            let _ = self.secret_put(None, &name, &old).await;
            return Err(e);
        }
        Ok(view)
    }

    pub(crate) async fn delete_target(&self, id: &str) -> Result<()> {
        let _g = self.targets_lock.lock().await;
        let mut all = self.read_targets()?;
        if !all.iter().any(|t| t.id == id) {
            return Err(ConnectorError::NotFound(format!(
                "backup target {id} not found"
            )));
        }
        let users: Vec<String> = self
            .deployer
            .sites()
            .into_iter()
            .filter(|s| {
                s.data
                    .postgres
                    .as_ref()
                    .and_then(|p| p.backup.s3.as_ref())
                    .is_some_and(|c| c.target == id)
            })
            .map(|s| s.id)
            .collect();
        if !users.is_empty() {
            return Err(ConnectorError::Conflict(format!(
                "the backup target is used by the policy of {}",
                users.join(", ")
            )));
        }
        all.retain(|t| t.id != id);
        self.write_targets(all)?;
        self.secret_del(None, &target_secret_name(id)).await;
        Ok(())
    }

    pub(crate) async fn s3_for_target(&self, id: &str) -> Result<(S3Client, S3Target)> {
        let (client, target) = self.target_client(id).await?;
        let client = client.map_err(|e| ConnectorError::BadRequest(e.to_string()))?;
        Ok((client, target))
    }

    /// The target and its client; a client the transport rules refuse comes back as the `S3Error`.
    async fn target_client(
        &self,
        id: &str,
    ) -> Result<(std::result::Result<S3Client, S3Error>, S3Target)> {
        let target = self
            .target(id)
            .await?
            .ok_or_else(|| ConnectorError::NotFound(format!("backup target {id} not found")))?;
        let keys: S3Secret = self
            .secret_get(&target_secret_name(id))
            .await?
            .ok_or_else(|| ConnectorError::Unavailable("the target's keys are missing".into()))?;
        let loc = S3Location::parse(
            &target.endpoint,
            &target.bucket,
            &target.region,
            target.path_style,
        )
        .map_err(|e| ConnectorError::BadRequest(e.to_string()))?;
        let client = S3Client::new(
            loc,
            S3Keys {
                access_key_id: keys.access_key_id,
                secret_access_key: Zeroizing::new(keys.secret_access_key),
            },
            self.cfg.s3_allow_private,
        );
        Ok((client, target))
    }

    /// Puts and deletes a one-byte object to prove the keys can write and delete. The result carries a
    /// fixed classification (see `S3Error::outcome`), never text from the server; that text is only logged
    /// at debug level.
    pub(crate) async fn test_target(&self, id: &str) -> Result<TargetTestResult> {
        let (client, target) = self.target_client(id).await?;
        let client = match client {
            Ok(client) => client,
            Err(e) => {
                tracing::debug!(target_id = %id, error = %e, "backup target test refused");
                return Ok(TargetTestResult {
                    ok: false,
                    error: Some(e.outcome()),
                });
            }
        };
        let probe = format!(
            "{}/{}/.cite-probe-{}",
            target.prefix,
            self.cfg.node_name,
            Ulid::generate().to_string().to_ascii_lowercase()
        );
        Ok(match client.check(&probe).await {
            Ok(()) => TargetTestResult {
                ok: true,
                error: None,
            },
            Err(e) => {
                tracing::debug!(target_id = %id, error = %e, "backup target test failed");
                TargetTestResult {
                    ok: false,
                    error: Some(e.outcome()),
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_are_plain_paths() {
        assert!(valid_prefix("cite"));
        assert!(valid_prefix("/backups/cite/"));
        for bad in ["", "/", "a//b", "../x", "a/../b", "has space", "x?y"] {
            assert!(!valid_prefix(bad), "{bad}");
        }
        assert!(!valid_prefix(&"a".repeat(101)));
    }

    fn req(endpoint: &str) -> TargetReq {
        TargetReq {
            name: "t".into(),
            endpoint: endpoint.into(),
            bucket: "my-backups".into(),
            region: "eu-west-1".into(),
            path_style: false,
            prefix: None,
            encrypt: None,
            access_key_id: None,
            secret_access_key: None,
        }
    }

    const BLOCKED: [&str; 12] = [
        "169.254.169.254",
        "127.0.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "255.255.255.255",
        "192.0.2.1",
        "[::1]",
        "[::ffff:127.0.0.1]",
        "[::ffff:169.254.169.254]",
        "[fe80::1]",
        "[::]",
        "[ff02::1]",
    ];

    #[test]
    fn blocked_endpoints_are_refused_with_the_flag_on_and_off() {
        for host in BLOCKED {
            for scheme in ["https", "http"] {
                for allow in [false, true] {
                    let r = req(&format!("{scheme}://{host}:9000"));
                    assert!(
                        matches!(
                            check_endpoint(&r, allow),
                            Err(ConnectorError::BadRequest(_))
                        ),
                        "{scheme}://{host} allow_private={allow}"
                    );
                }
            }
        }
    }

    #[test]
    fn only_rfc1918_ula_and_cgnat_open_with_the_flag() {
        for host in [
            "10.0.0.5",
            "172.16.0.1",
            "192.168.1.10",
            "100.64.0.1",
            "[fd00::1]",
            "[fc00::1]",
            "[::ffff:10.0.0.5]",
        ] {
            for scheme in ["https", "http"] {
                let r = req(&format!("{scheme}://{host}:9000"));
                assert!(check_endpoint(&r, true).is_ok(), "{scheme}://{host}");
                assert!(check_endpoint(&r, false).is_err(), "{scheme}://{host} off");
            }
        }
    }

    #[test]
    fn plain_http_needs_the_flag_and_a_private_literal() {
        assert!(check_endpoint(&req("http://s3.example.com"), false).is_err());
        assert!(check_endpoint(&req("https://s3.example.com"), false).is_ok());
        assert!(check_endpoint(&req("https://s3.example.com"), true).is_ok());
        assert!(check_endpoint(&req("http://8.8.8.8"), true).is_err());
        assert!(check_endpoint(&req("https://8.8.8.8"), true).is_ok());
    }

    #[test]
    fn test_results_use_fixed_classifications() {
        let leak = "AccessDenied</Code><Message>db.internal says no";
        for e in [
            S3Error::Denied(format!("HTTP 403 AccessDenied: {leak}")),
            S3Error::Permanent(format!("HTTP 400 Odd: {leak}")),
            S3Error::Transient(format!("HTTP 503 SlowDown: {leak}")),
            S3Error::Transient("could not connect to db.internal".into()),
            S3Error::Permanent(leak.into()),
        ] {
            let o = e.outcome();
            assert!(!o.contains("internal") && !o.contains("says"), "{o}");
            assert!(
                o.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{o}"
            );
        }
    }

    #[test]
    fn target_secrets_have_a_node_scoped_name() {
        assert_eq!(target_secret_name("abc"), "node.data.target.abc");
    }
}
