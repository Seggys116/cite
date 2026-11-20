//! Site data services: managed and external Postgres, S3 attachments, generated secrets and the env links that deliver them.
//!
//! Only names, limits and non-secret settings live here. Passwords, URLs with credentials and S3 keys are connector-only secrets.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const DEFAULT_PG_MAJOR: u8 = 18;
pub const DEFAULT_PG_MEMORY_MB: u32 = 512;
pub const DEFAULT_PG_MAX_CONNECTIONS: u32 = 100;
pub const DEFAULT_CONN_LIMIT: u32 = 20;
pub const DEFAULT_SECRET_BYTES: u16 = 32;

pub(crate) fn default_pg_memory_mb() -> u32 {
    DEFAULT_PG_MEMORY_MB
}
pub(crate) fn default_pg_max_connections() -> u32 {
    DEFAULT_PG_MAX_CONNECTIONS
}
pub(crate) fn default_conn_limit() -> u32 {
    DEFAULT_CONN_LIMIT
}
pub(crate) fn default_secret_bytes() -> u16 {
    DEFAULT_SECRET_BYTES
}

/// Databases, object storage, generated secrets and env links; only the data routes change it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteData {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postgres: Option<ManagedPostgres>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub external_postgres: Vec<ExternalPostgres>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub s3: Vec<S3Attachment>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<GeneratedSecret>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<EnvLink>,
}

impl SiteData {
    pub fn is_empty(&self) -> bool {
        *self == SiteData::default()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PgMode {
    #[default]
    Dedicated,
    Shared,
}

impl PgMode {
    pub fn as_str(self) -> &'static str {
        match self {
            PgMode::Dedicated => "dedicated",
            PgMode::Shared => "shared",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedPostgres {
    pub mode: PgMode,
    /// 17 or 18; a shared tenant mirrors the instance.
    pub major: u8,
    #[serde(default = "default_pg_memory_mb")]
    pub memory_mb: u32,
    #[serde(default = "default_pg_max_connections")]
    pub max_connections: u32,
    pub databases: Vec<PgDatabase>,
    #[serde(default)]
    pub backup: BackupPolicy,
    /// Reserved for in-node TLS; must be false in this release.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tls: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired: Option<RetiredPostgres>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PgDatabase {
    pub name: String,
    pub users: Vec<PgUser>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PgLevel {
    Owner,
    Readwrite,
    Readonly,
}

impl PgLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            PgLevel::Owner => "owner",
            PgLevel::Readwrite => "readwrite",
            PgLevel::Readonly => "readonly",
        }
    }

    /// Statement timeout a user of this level gets when none is set: 30 s for DML levels, none for the owner.
    pub fn default_statement_timeout_ms(self) -> u32 {
        match self {
            PgLevel::Owner => 0,
            PgLevel::Readwrite | PgLevel::Readonly => 30_000,
        }
    }
}

pub const DEFAULT_IDLE_IN_TRANSACTION_MS: u32 = 60_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PgUser {
    pub name: String,
    pub level: PgLevel,
    #[serde(default = "default_conn_limit")]
    pub connection_limit: u32,
    /// Milliseconds; 0 means none. When unset: 30_000 for readwrite and readonly, 0 for owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement_timeout_ms: Option<u32>,
    /// Milliseconds, 1_000..=3_600_000. When unset: 60_000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_in_transaction_timeout_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
}

impl PgUser {
    pub fn effective_statement_timeout_ms(&self) -> u32 {
        self.statement_timeout_ms
            .unwrap_or_else(|| self.level.default_statement_timeout_ms())
    }

    pub fn effective_idle_in_transaction_ms(&self) -> u32 {
        self.idle_in_transaction_timeout_ms
            .unwrap_or(DEFAULT_IDLE_IN_TRANSACTION_MS)
    }
}

/// The database a site had before a local conversion; it stays frozen until deleted explicitly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetiredPostgres {
    pub mode: PgMode,
    pub major: u8,
    pub since: String,
}

/// An attached Postgres outside the node. The URL (credentials included) is a connector-only secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalPostgres {
    pub name: String,
    pub host: String,
    pub port: u16,
    /// Parsed from the URL, display only.
    pub database: String,
    /// Parsed from the URL, display only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sslmode: Option<String>,
}

/// An attached S3-compatible bucket. The keys are connector-only secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3Attachment {
    pub name: String,
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    #[serde(default)]
    pub path_style: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretEncoding {
    #[default]
    Base64url,
    Hex,
}

impl SecretEncoding {
    pub fn as_str(self) -> &'static str {
        match self {
            SecretEncoding::Base64url => "base64url",
            SecretEncoding::Hex => "hex",
        }
    }
}

/// A random value the connector generates and holds; the value is never returned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedSecret {
    pub name: String,
    #[serde(default = "default_secret_bytes")]
    pub bytes: u16,
    #[serde(default)]
    pub encoding: SecretEncoding,
    /// RFC3339, set by the connector.
    #[serde(default)]
    pub rotated_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkTarget {
    Runtime,
    Build,
}

impl LinkTarget {
    pub fn as_str(self) -> &'static str {
        match self {
            LinkTarget::Runtime => "runtime",
            LinkTarget::Build => "build",
        }
    }
}

/// One env var a data resource produces, for one target. The pair `(var, target)` is unique within a site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvLink {
    pub var: String,
    pub target: LinkTarget,
    pub source: LinkSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LinkSource {
    Postgres {
        database: String,
        user: String,
        field: PgField,
    },
    /// `PgField::User` is the URL's user; `TlsServername` is allowed here only.
    External {
        name: String,
        field: PgField,
    },
    S3 {
        name: String,
        field: S3Field,
    },
    Secret {
        name: String,
    },
    /// `https://<first host of the site>`.
    SiteUrl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PgField {
    Url,
    Host,
    Port,
    Database,
    User,
    Password,
    Sslmode,
    TlsServername,
}

impl PgField {
    pub fn as_str(self) -> &'static str {
        match self {
            PgField::Url => "url",
            PgField::Host => "host",
            PgField::Port => "port",
            PgField::Database => "database",
            PgField::User => "user",
            PgField::Password => "password",
            PgField::Sslmode => "sslmode",
            PgField::TlsServername => "tls_servername",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum S3Field {
    Endpoint,
    Bucket,
    Region,
    AccessKeyId,
    SecretAccessKey,
    PathStyle,
}

impl S3Field {
    pub fn as_str(self) -> &'static str {
        match self {
            S3Field::Endpoint => "endpoint",
            S3Field::Bucket => "bucket",
            S3Field::Region => "region",
            S3Field::AccessKeyId => "access_key_id",
            S3Field::SecretAccessKey => "secret_access_key",
            S3Field::PathStyle => "path_style",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<BackupSchedule>,
    #[serde(default)]
    pub local: BackupRetention,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub s3: Option<S3Copy>,
}

/// Runs at the latest UTC time with `hour % every_hours == 0` and the given minute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSchedule {
    /// One of `BACKUP_EVERY_HOURS`.
    pub every_hours: u8,
    /// 0..=59.
    pub minute: u8,
}

pub const BACKUP_EVERY_HOURS: [u8; 8] = [1, 2, 3, 4, 6, 8, 12, 24];

/// Grandfather-father-son retention of one backup tier. Named `BackupRetention` because `model::Retention` is the analytics window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BackupRetention {
    /// 0..=720
    pub keep_all_hours: u32,
    /// 0..=366
    pub daily_days: u32,
    /// 0..=260
    pub weekly_weeks: u32,
    /// 0..=120
    pub monthly_months: u32,
    /// 0..=366
    pub pre_restore_days: u32,
}

impl Default for BackupRetention {
    fn default() -> Self {
        BackupRetention {
            keep_all_hours: 24,
            daily_days: 7,
            weekly_weeks: 4,
            monthly_months: 6,
            pre_restore_days: 7,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3Copy {
    /// Id of a node-level backup target.
    pub target: String,
    #[serde(default)]
    pub retention: BackupRetention,
}

// ---- name rules ----

/// `^[a-z][a-z0-9]{0,15}$`: database and user names, which end up inside Postgres role names.
pub fn is_pg_ident(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=16).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

/// `^[a-z][a-z0-9-]{0,30}$`: external Postgres, S3 attachment and generated secret names.
pub fn is_resource_name(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=31).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// Database names Postgres owns.
pub const RESERVED_PG_DATABASES: [&str; 3] = ["postgres", "template0", "template1"];

// ---- Postgres name derivation, shared by the connector and the Docker proxy tests ----

/// 10 lowercase hex chars of sha256("cite-pg-v1:" + site_id).
pub fn pg_site_tag(site_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"cite-pg-v1:");
    hasher.update(site_id.as_bytes());
    let digest = hasher.finalize();
    digest.iter().take(5).map(|b| format!("{b:02x}")).collect()
}

/// Dedicated: the logical name. Shared: `t<tag>_<db>`.
pub fn pg_db_name(mode: PgMode, site_id: &str, db: &str) -> String {
    match mode {
        PgMode::Dedicated => db.to_string(),
        PgMode::Shared => format!("t{}_{db}", pg_site_tag(site_id)),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PgGroup {
    Owner,
    Rw,
    Ro,
    Login,
}

impl PgGroup {
    pub fn suffix(self) -> &'static str {
        match self {
            PgGroup::Owner => "owner",
            PgGroup::Rw => "rw",
            PgGroup::Ro => "ro",
            PgGroup::Login => "login",
        }
    }
}

/// The two login roles of a user that alternate on rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Alt {
    A,
    B,
}

impl Alt {
    pub fn other(self) -> Alt {
        match self {
            Alt::A => Alt::B,
            Alt::B => Alt::A,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Alt::A => "a",
            Alt::B => "b",
        }
    }
}

/// `t<tag>_<db>_owner|_rw|_ro|_login` (at most 34 bytes). Identical in both modes.
pub fn pg_group(site_id: &str, db: &str, group: PgGroup) -> String {
    format!("t{}_{db}_{}", pg_site_tag(site_id), group.suffix())
}

/// `t<tag>_<db>_<user>_a|_b` (at most 47 bytes). Identical in both modes.
pub fn pg_login(site_id: &str, db: &str, user: &str, alt: Alt) -> String {
    format!("t{}_{db}_{user}_{}", pg_site_tag(site_id), alt.as_str())
}

/// `t<tag>_<db>`: the prefix the provision jobs and pg_hba entries use, in both modes.
pub fn pg_role_tag(site_id: &str, db: &str) -> String {
    format!("t{}_{db}", pg_site_tag(site_id))
}

/// Secret store name of a managed user's credentials.
pub fn pg_user_secret_name(site_id: &str, db: &str, user: &str) -> String {
    format!("site-{site_id}.data.pg.{db}.{user}")
}

/// Secret store name of a retired database's user credentials.
pub fn pg_retired_secret_name(site_id: &str, db: &str, user: &str) -> String {
    format!("site-{site_id}.data.pg-retired.{db}.{user}")
}

/// Secret store name of a dedicated instance's superuser password.
pub fn pg_superuser_secret_name(site_id: &str) -> String {
    format!("site-{site_id}.data.pg-su")
}

/// Secret store name of an external Postgres URL.
pub fn external_secret_name(site_id: &str, name: &str) -> String {
    format!("site-{site_id}.data.ext.{name}")
}

/// Secret store name of an S3 attachment's keys.
pub fn s3_secret_name(site_id: &str, name: &str) -> String {
    format!("site-{site_id}.data.s3.{name}")
}

/// Secret store name of a generated secret's value.
pub fn generated_secret_name(site_id: &str, name: &str) -> String {
    format!("site-{site_id}.data.gen.{name}")
}

/// Fixed container, volume and network names of the shared instance (A2, A3).
pub const SHARED_DB: &str = "cite-pg-shared";
pub const SHARED_DATA: &str = "cite-pg-shared-data";
pub const SHARED_CONF: &str = "cite-pg-shared-conf";
pub const SHARED_ADMIN: &str = "cite-pg-shared-admin";
pub const SHARED_JOB: &str = "cite-pg-shared-job";

/// `cite-<id>-db`
pub fn db_container_name(site_id: &str) -> String {
    format!("cite-{site_id}-db")
}

/// `cite-<id>-db-data`
pub fn db_volume_name(site_id: &str) -> String {
    format!("cite-{site_id}-db-data")
}

/// `cite-<id>-dbnet`
pub fn dbnet_name(site_id: &str) -> String {
    format!("cite-{site_id}-dbnet")
}

/// `cite-<id>-dbjob`
pub fn dbjob_name(site_id: &str) -> String {
    format!("cite-{site_id}-dbjob")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const LONGEST_ID: &str = "a123456789-123456789-123456789-123456789";

    #[test]
    fn site_tag_is_ten_lowercase_hex_chars_and_stable() {
        for id in ["shop", "a", LONGEST_ID, "my-site-1"] {
            let tag = pg_site_tag(id);
            assert_eq!(tag.len(), 10, "{id}");
            assert!(
                tag.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "{tag}"
            );
            assert_eq!(tag, pg_site_tag(id));
        }
        assert_ne!(pg_site_tag("shop"), pg_site_tag("shop2"));
        assert_ne!(pg_site_tag("shop"), pg_site_tag("Shop"));
    }

    #[test]
    fn site_tag_is_the_prefix_of_the_sha256_of_the_versioned_input() {
        let digest = Sha256::digest(b"cite-pg-v1:shop");
        let expected: String = digest[..5].iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(pg_site_tag("shop"), expected);
        // The unversioned input must hash differently, so a change of the version string is detected.
        let unversioned = Sha256::digest(b"shop");
        let other: String = unversioned[..5]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_ne!(pg_site_tag("shop"), other);
    }

    #[test]
    fn derived_names_follow_the_documented_shapes() {
        let tag = pg_site_tag("shop");
        assert_eq!(pg_db_name(PgMode::Dedicated, "shop", "app"), "app");
        assert_eq!(
            pg_db_name(PgMode::Shared, "shop", "app"),
            format!("t{tag}_app")
        );
        assert_eq!(
            pg_group("shop", "app", PgGroup::Owner),
            format!("t{tag}_app_owner")
        );
        assert_eq!(
            pg_group("shop", "app", PgGroup::Rw),
            format!("t{tag}_app_rw")
        );
        assert_eq!(
            pg_group("shop", "app", PgGroup::Ro),
            format!("t{tag}_app_ro")
        );
        assert_eq!(
            pg_group("shop", "app", PgGroup::Login),
            format!("t{tag}_app_login")
        );
        assert_eq!(
            pg_login("shop", "app", "migrate", Alt::A),
            format!("t{tag}_app_migrate_a")
        );
        assert_eq!(
            pg_login("shop", "app", "migrate", Alt::B),
            format!("t{tag}_app_migrate_b")
        );
        assert_eq!(pg_role_tag("shop", "app"), format!("t{tag}_app"));
    }

    #[test]
    fn derived_names_fit_their_documented_lengths() {
        let db = "d".repeat(16);
        let user = "u".repeat(16);
        for id in ["a", LONGEST_ID] {
            assert_eq!(pg_login(id, &db, &user, Alt::A).len(), 47);
            assert!(pg_group(id, &db, PgGroup::Login).len() <= 34);
            assert!(pg_group(id, &db, PgGroup::Owner).len() <= 34);
            assert!(pg_db_name(PgMode::Shared, id, &db).len() <= 63);
            assert!(pg_login(id, &db, &user, Alt::B).len() <= 63);
            assert!(pg_role_tag(id, &db).len() <= 28);
        }
    }

    #[test]
    fn roles_are_identical_across_modes_and_differ_across_sites() {
        // Role names take no mode argument, so a conversion or transfer keeps them.
        assert_ne!(
            pg_login("shop", "app", "app", Alt::A),
            pg_login("blog", "app", "app", Alt::A)
        );
        assert_ne!(
            pg_login("shop", "app", "app", Alt::A),
            pg_login("shop", "app", "app", Alt::B)
        );
        assert_eq!(Alt::A.other(), Alt::B);
        assert_eq!(Alt::B.other(), Alt::A);
    }

    #[test]
    fn container_volume_and_network_names() {
        assert_eq!(db_container_name("shop"), "cite-shop-db");
        assert_eq!(db_volume_name("shop"), "cite-shop-db-data");
        assert_eq!(dbnet_name("shop"), "cite-shop-dbnet");
        assert_eq!(dbjob_name("shop"), "cite-shop-dbjob");
        assert_eq!(SHARED_DB, "cite-pg-shared");
        assert_eq!(SHARED_DATA, "cite-pg-shared-data");
        assert_eq!(SHARED_CONF, "cite-pg-shared-conf");
        assert_eq!(SHARED_ADMIN, "cite-pg-shared-admin");
        assert_eq!(SHARED_JOB, "cite-pg-shared-job");
    }

    #[test]
    fn secret_names_fit_the_store_limit() {
        assert_eq!(pg_superuser_secret_name("shop"), "site-shop.data.pg-su");
        assert_eq!(
            pg_user_secret_name("shop", "app", "migrate"),
            "site-shop.data.pg.app.migrate"
        );
        assert_eq!(
            pg_retired_secret_name("shop", "app", "migrate"),
            "site-shop.data.pg-retired.app.migrate"
        );
        assert_eq!(
            external_secret_name("shop", "billing"),
            "site-shop.data.ext.billing"
        );
        assert_eq!(s3_secret_name("shop", "media"), "site-shop.data.s3.media");
        assert_eq!(
            generated_secret_name("shop", "auth-secret"),
            "site-shop.data.gen.auth-secret"
        );
        let long = "x".repeat(31);
        for name in [
            pg_retired_secret_name(LONGEST_ID, &"d".repeat(16), &"u".repeat(16)),
            external_secret_name(LONGEST_ID, &long),
            s3_secret_name(LONGEST_ID, &long),
            generated_secret_name(LONGEST_ID, &long),
        ] {
            assert!(name.len() <= 128, "{name}");
        }
    }

    #[test]
    fn name_rules() {
        for ok in ["a", "app", "a0", &"a".repeat(16)] {
            assert!(is_pg_ident(ok), "{ok}");
        }
        for bad in [
            "",
            "0a",
            "A",
            "a_b",
            "a-b",
            "a.b",
            &"a".repeat(17),
            "app ",
            "é",
        ] {
            assert!(!is_pg_ident(bad), "{bad:?}");
        }
        for ok in ["a", "auth-secret", "a-b-c", &"a".repeat(31)] {
            assert!(is_resource_name(ok), "{ok}");
        }
        for bad in ["", "-a", "0a", "A", "a_b", "a.b", &"a".repeat(32), "a b"] {
            assert!(!is_resource_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn minimal_documents_get_the_documented_defaults() {
        let pg: ManagedPostgres = serde_json::from_value(json!({
            "mode": "dedicated",
            "major": 18,
            "databases": [{"name": "app", "users": [{"name": "app", "level": "readwrite"}]}]
        }))
        .unwrap();
        assert_eq!(pg.memory_mb, 512);
        assert_eq!(pg.max_connections, 100);
        assert_eq!(pg.backup, BackupPolicy::default());
        assert!(!pg.tls && pg.retired.is_none());
        let user = &pg.databases[0].users[0];
        assert_eq!(user.connection_limit, 20);
        assert_eq!(user.effective_statement_timeout_ms(), 30_000);
        assert_eq!(user.effective_idle_in_transaction_ms(), 60_000);
        assert!(!user.disabled);
        let owner: PgUser =
            serde_json::from_value(json!({"name": "migrate", "level": "owner"})).unwrap();
        assert_eq!(owner.effective_statement_timeout_ms(), 0);
        let r = BackupRetention::default();
        assert_eq!(
            (
                r.keep_all_hours,
                r.daily_days,
                r.weekly_weeks,
                r.monthly_months,
                r.pre_restore_days
            ),
            (24, 7, 4, 6, 7)
        );
        let partial: BackupRetention = serde_json::from_value(json!({"daily_days": 30})).unwrap();
        assert_eq!(partial.daily_days, 30);
        assert_eq!(partial.weekly_weeks, 4);
        let g: GeneratedSecret = serde_json::from_value(json!({"name": "auth-secret"})).unwrap();
        assert_eq!((g.bytes, g.encoding), (32, SecretEncoding::Base64url));
    }

    #[test]
    fn explicit_defaults_are_not_written_back() {
        let user = PgUser {
            name: "app".into(),
            level: PgLevel::Readwrite,
            connection_limit: 20,
            statement_timeout_ms: None,
            idle_in_transaction_timeout_ms: None,
            disabled: false,
        };
        assert_eq!(
            serde_json::to_value(&user).unwrap(),
            json!({"name": "app", "level": "readwrite", "connection_limit": 20})
        );
    }

    #[test]
    fn every_data_type_refuses_unknown_fields() {
        assert!(serde_json::from_value::<SiteData>(json!({"nope": 1})).is_err());
        assert!(
            serde_json::from_value::<PgUser>(json!({"name": "a", "level": "owner", "x": 1}))
                .is_err()
        );
        assert!(
            serde_json::from_value::<PgDatabase>(json!({"name": "a", "users": [], "x": 1}))
                .is_err()
        );
        assert!(
            serde_json::from_value::<ExternalPostgres>(
                json!({"name": "a", "host": "h", "port": 1, "database": "d", "x": 1})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<S3Attachment>(
                json!({"name": "a", "endpoint": "e", "bucket": "b", "region": "r", "x": 1})
            )
            .is_err()
        );
        assert!(serde_json::from_value::<GeneratedSecret>(json!({"name": "a", "x": 1})).is_err());
        assert!(
            serde_json::from_value::<EnvLink>(
                json!({"var": "A", "target": "runtime", "source": {"kind": "site_url"}, "x": 1})
            )
            .is_err()
        );
        assert!(serde_json::from_value::<BackupPolicy>(json!({"x": 1})).is_err());
        assert!(
            serde_json::from_value::<BackupSchedule>(
                json!({"every_hours": 6, "minute": 1, "x": 1})
            )
            .is_err()
        );
        assert!(serde_json::from_value::<BackupRetention>(json!({"x": 1})).is_err());
        assert!(serde_json::from_value::<S3Copy>(json!({"target": "t", "x": 1})).is_err());
        assert!(
            serde_json::from_value::<RetiredPostgres>(
                json!({"mode": "shared", "major": 18, "since": "t", "x": 1})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<ManagedPostgres>(
                json!({"mode": "dedicated", "major": 18, "databases": [], "x": 1})
            )
            .is_err()
        );
    }

    #[test]
    fn site_data_round_trips_in_full() {
        let data = SiteData {
            postgres: Some(ManagedPostgres {
                mode: PgMode::Shared,
                major: 17,
                memory_mb: 1024,
                max_connections: 50,
                databases: vec![PgDatabase {
                    name: "app".into(),
                    users: vec![PgUser {
                        name: "migrate".into(),
                        level: PgLevel::Owner,
                        connection_limit: 5,
                        statement_timeout_ms: Some(0),
                        idle_in_transaction_timeout_ms: Some(2_000),
                        disabled: true,
                    }],
                }],
                backup: BackupPolicy {
                    schedule: Some(BackupSchedule {
                        every_hours: 6,
                        minute: 17,
                    }),
                    local: BackupRetention::default(),
                    s3: Some(S3Copy {
                        target: "tgt-1".into(),
                        retention: BackupRetention::default(),
                    }),
                },
                tls: false,
                retired: Some(RetiredPostgres {
                    mode: PgMode::Dedicated,
                    major: 18,
                    since: "2026-11-20T00:00:00Z".into(),
                }),
            }),
            external_postgres: vec![ExternalPostgres {
                name: "billing".into(),
                host: "db.example.com".into(),
                port: 5432,
                database: "bill".into(),
                sslmode: Some("require".into()),
            }],
            s3: vec![S3Attachment {
                name: "media".into(),
                endpoint: "https://s3.example.com".into(),
                bucket: "media-bucket".into(),
                region: "eu-west-1".into(),
                path_style: true,
            }],
            secrets: vec![GeneratedSecret {
                name: "auth-secret".into(),
                bytes: 64,
                encoding: SecretEncoding::Hex,
                rotated_at: "2026-11-20T00:00:00Z".into(),
            }],
            links: vec![EnvLink {
                var: "DATABASE_URL".into(),
                target: LinkTarget::Runtime,
                source: LinkSource::Postgres {
                    database: "app".into(),
                    user: "app".into(),
                    field: PgField::Url,
                },
            }],
        };
        assert!(!data.is_empty());
        let text = serde_json::to_string(&data).unwrap();
        let back: SiteData = serde_json::from_str(&text).unwrap();
        assert_eq!(back, data);
        assert!(SiteData::default().is_empty());
        assert_eq!(serde_json::to_string(&SiteData::default()).unwrap(), "{}");
    }
}
