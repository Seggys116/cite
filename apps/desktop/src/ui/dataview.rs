// Pure rules for the site Data tab and the node Databases page: wording, validation, request bodies, link and preset
// planning, retention text and job tracking. No gpui here, so every rule can be tested without a window. The wording
// and the rules mirror the dashboard's datalib.js so both clients say the same thing.

use cite_client::{
    ClientError, CountDiff, TransferPhase, TransferPlan, TransferState, compare_counts,
};
use cite_edge::datamodel::RetiredPostgres;
use cite_edge::datamodel::{
    BACKUP_EVERY_HOURS, BackupPolicy, BackupRetention, BackupSchedule, LinkSource, LinkTarget,
    PgField, PgLevel, PgMode, RESERVED_PG_DATABASES, S3Copy, S3Field, SecretEncoding, is_pg_ident,
    is_resource_name,
};
use cite_edge::datawire::{
    BackupRecord, BackupStatus, BackupTrigger, ConflictSetBy, EnvLinkReq, ExternalPutReq, JobState,
    JobView, LinkConflict, LinkTargetSel, LinkView, LinksReq, OrphanView, PgEnableReq, PgUserView,
    Preset, PresetRequest, PrunePreview, S3PutReq, SecretCreateReq, SecretView, SharedReq,
    SharedView, SiteDataView, TargetReq, TargetTestResult, UserCreateReq, UserPatchReq,
    is_valid_backup_label,
};
use cite_edge::datawire::{Freeze, Session, SessionState, TableCount};
use cite_edge::validate::{
    MAX_PG_DATABASES, MAX_PG_USERS_PER_DATABASE, PG_MAJORS, validate_backup_policy,
};

use crate::siteops::has_cap;
use crate::theme::Tone;

pub const CAP_DATA_POSTGRES: &str = "data-postgres";
pub const CAP_DATA_SHARED: &str = "data-shared";
pub const CAP_DATA_EXTERNAL: &str = "data-external";
pub const CAP_DATA_S3: &str = "data-s3";
pub const CAP_DATA_BACKUPS: &str = "data-backups";
pub const CAP_DATA_LINKS: &str = "data-links";
pub const CAP_DATA_TRANSFER: &str = "data-transfer";

pub const DEFAULT_MAJOR: u8 = 18;
pub const MIN_PG_MEMORY_MB: u32 = 256;
pub const MAX_PG_MEMORY_MB: u32 = 65_536;
pub const MIN_SECRET_BYTES: u32 = 32;
pub const MAX_SECRET_BYTES: u32 = 128;

pub const WRITE_ONLY_PASSWORDS: &str = "Passwords are never shown. Linked env vars deliver them where they are used, and Rotate password issues a new one.";
pub const WRITE_ONLY_CREDENTIALS: &str =
    "Write-only: the node stores it and never sends it back. Saving again replaces it.";
pub const EXTERNAL_EGRESS_NOTE: &str = "External databases are reached through the node egress forward: the site runs on a filtered network and its connection goes through a TCP forward that still refuses private and internal addresses. With sslmode verify-full the host name check fails through the forward, so link the TLS server name where your driver accepts one.";
pub const EXTERNAL_BACKUP_NOTE: &str = "External databases can be backed up by hand only. A version can be restored into a managed database, never back into the external one.";
pub const KEY_BACKUP_NOTE: &str = "Backups are encrypted with the node key. A copy in S3 cannot be restored without it: export the key and keep it somewhere else.";
pub const ROTATE_TEXT: &str = "A new password is issued on the spare login while the current one keeps working, so running connections are not cut. Linked runtime env vars pick it up on the next deploy, and the old login is retired once nothing uses it.";
pub const AUTH_ROTATE_WARNING: &str = "Rotating an auth secret signs every user out, because sessions signed with the old value stop validating.";
pub const BUCKET_EXPLANATION: &str = "Days, weeks and months are calendar buckets in UTC: each bucket keeps its newest version, and anything no rule keeps is deleted. Weeks start on Monday.";
pub const SHARED_UPDATE_TEXT: &str =
    "Changing the limits recreates the container. Every tenant is disconnected for a moment.";

// ---- capabilities ----

// The Data tab needs the node to offer at least one data service.
pub fn data_tab_offered(caps: &[String]) -> bool {
    has_cap(caps, CAP_DATA_POSTGRES)
        || has_cap(caps, CAP_DATA_EXTERNAL)
        || has_cap(caps, CAP_DATA_S3)
}

pub fn databases_page_offered(caps: &[String]) -> bool {
    has_cap(caps, CAP_DATA_SHARED) || has_cap(caps, CAP_DATA_POSTGRES)
}

// ---- Postgres mode and the trade-off table ----

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PgChoice {
    Off,
    Dedicated,
    Shared,
    External,
}

impl PgChoice {
    // What a site without a database can pick.
    pub const ENABLE: [PgChoice; 3] = [PgChoice::Dedicated, PgChoice::Shared, PgChoice::External];

    pub fn label(self) -> &'static str {
        match self {
            PgChoice::Off => "Off",
            PgChoice::Dedicated => "Dedicated database",
            PgChoice::Shared => "Shared node database",
            PgChoice::External => "External database",
        }
    }

    pub fn summary(self) -> &'static str {
        match self {
            PgChoice::Off => "The site has no database.",
            PgChoice::Dedicated => "Its own Postgres container, volume and network for this site.",
            PgChoice::Shared => "A database and roles on the one Postgres instance of the node.",
            PgChoice::External => {
                "A Postgres you run elsewhere; the node keeps the URL and links it into the site."
            }
        }
    }

    pub fn mode(self) -> Option<PgMode> {
        match self {
            PgChoice::Dedicated => Some(PgMode::Dedicated),
            PgChoice::Shared => Some(PgMode::Shared),
            PgChoice::Off | PgChoice::External => None,
        }
    }
}

// Managed Postgres wins, then an attached external one, else the site has no database.
pub fn current_choice(view: &SiteDataView) -> PgChoice {
    match &view.postgres {
        Some(pg) => match pg.mode {
            PgMode::Dedicated => PgChoice::Dedicated,
            PgMode::Shared => PgChoice::Shared,
        },
        None if !view.external.is_empty() => PgChoice::External,
        None => PgChoice::Off,
    }
}

// Aspect, dedicated, shared.
pub const TRADEOFFS: [(&str, &str, &str); 7] = [
    (
        "Isolation",
        "Own process, own volume, own network.",
        "Separate database and roles, but the same process, volume and network rules per site.",
    ),
    (
        "Noisy neighbour",
        "None.",
        "CPU, memory, I/O and connection slots are shared with every tenant.",
    ),
    (
        "Postgres major",
        "Chosen per site.",
        "One for all tenants; upgrading means moving every tenant.",
    ),
    (
        "Blast radius",
        "This site only.",
        "An instance crash or a full disk affects every tenant.",
    ),
    (
        "Resources",
        "About 30 to 60 MiB of idle memory per site plus its own shared buffers.",
        "One process, much cheaper with many small sites.",
    ),
    (
        "Restart",
        "Per site.",
        "An instance restart interrupts every tenant.",
    ),
    (
        "Backups",
        "Per database.",
        "Per database, plus an optional whole-instance backup.",
    ),
];

// ---- names and numbers ----

fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

// A whole number inside [min, max]; blank is allowed only when `optional`.
pub fn optional_number(text: &str, min: u32, max: u32, what: &str) -> Result<Option<u32>, String> {
    let v = text.trim();
    if v.is_empty() {
        return Ok(None);
    }
    if !v.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("{} must be a whole number.", capitalize(what)));
    }
    let out_of_range = || format!("{} must be between {min} and {max}.", capitalize(what));
    let n: u32 = v.parse().map_err(|_| out_of_range())?;
    if n < min || n > max {
        return Err(out_of_range());
    }
    Ok(Some(n))
}

pub fn required_number(text: &str, min: u32, max: u32, what: &str) -> Result<u32, String> {
    optional_number(text, min, max, what)?.ok_or_else(|| format!("Enter {what}."))
}

pub fn pg_name_problem(name: &str, what: &str) -> Option<String> {
    if !is_pg_ident(name) {
        return Some(format!(
            "A {what} is 1 to 16 characters: lowercase letters and digits, starting with a letter."
        ));
    }
    if what == "database" && RESERVED_PG_DATABASES.contains(&name) {
        return Some(format!("{name} is reserved by Postgres."));
    }
    None
}

pub fn resource_name_problem(name: &str, what: &str) -> Option<String> {
    if is_resource_name(name) {
        None
    } else {
        Some(format!(
            "A {what} is 1 to 31 characters: lowercase letters, digits and dashes, starting with a letter."
        ))
    }
}

pub fn label_problem(label: &str) -> Option<String> {
    if is_valid_backup_label(label) {
        None
    } else {
        Some("A label is at most 100 characters without control characters.".into())
    }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

// ---- Postgres enable and databases ----

// Dedicated limits are checked as the node checks them; blank keeps the node's default.
// Enabling creates the default database, users and links in the same step (the generic preset).
pub fn pg_enable_req(
    mode: PgMode,
    major: u8,
    memory: &str,
    connections: &str,
) -> Result<PgEnableReq, String> {
    if mode == PgMode::Shared {
        return Ok(PgEnableReq {
            mode,
            major: None,
            memory_mb: None,
            max_connections: None,
            preset: Some("generic".into()),
        });
    }
    if !PG_MAJORS.contains(&major) {
        return Err(format!(
            "Pick Postgres {} or {}.",
            PG_MAJORS[1], PG_MAJORS[0]
        ));
    }
    Ok(PgEnableReq {
        mode,
        major: Some(major),
        memory_mb: optional_number(
            memory,
            MIN_PG_MEMORY_MB,
            MAX_PG_MEMORY_MB,
            "the memory in MiB",
        )?,
        max_connections: optional_number(connections, 10, 1000, "the connection limit")?,
        preset: Some("generic".into()),
    })
}

pub fn level_label(level: PgLevel) -> &'static str {
    match level {
        PgLevel::Owner => "Owner",
        PgLevel::Readwrite => "Read and write",
        PgLevel::Readonly => "Read only",
    }
}

pub fn level_text(level: PgLevel) -> &'static str {
    match level {
        PgLevel::Owner => {
            "Owns every object and can change the schema. Use it for migrations, not for the running app."
        }
        PgLevel::Readwrite => {
            "Reads and changes data, cannot change the schema. The right level for the running app."
        }
        PgLevel::Readonly => "Reads data only. For reports and analytics.",
    }
}

pub const LEVELS: [PgLevel; 3] = [PgLevel::Owner, PgLevel::Readwrite, PgLevel::Readonly];

pub fn database_create_problem(name: &str, existing: &[String]) -> Option<String> {
    let name = name.trim();
    if let Some(p) = pg_name_problem(name, "database") {
        return Some(p);
    }
    if existing.iter().any(|e| e == name) {
        return Some(format!("{name} already exists."));
    }
    if existing.len() >= MAX_PG_DATABASES {
        return Some(format!(
            "A site can have at most {MAX_PG_DATABASES} databases."
        ));
    }
    None
}

pub fn user_create_req(
    name: &str,
    level: PgLevel,
    limit: &str,
    existing: &[String],
) -> Result<UserCreateReq, String> {
    let name = name.trim();
    if let Some(p) = pg_name_problem(name, "user name") {
        return Err(p);
    }
    if existing.iter().any(|e| e == name) {
        return Err(format!("{name} already exists in this database."));
    }
    if existing.len() >= MAX_PG_USERS_PER_DATABASE {
        return Err(format!(
            "A database can have at most {MAX_PG_USERS_PER_DATABASE} users."
        ));
    }
    Ok(UserCreateReq {
        name: name.to_string(),
        level,
        connection_limit: optional_number(limit, 1, 500, "the connection limit")?,
        statement_timeout_ms: None,
        idle_in_transaction_timeout_ms: None,
    })
}

// Only a changed limit is sent.
pub fn limit_patch(limit: &str, current: u32) -> Result<UserPatchReq, String> {
    let n = required_number(limit, 1, 500, "the connection limit")?;
    if n == current {
        return Err("The connection limit is unchanged.".into());
    }
    Ok(UserPatchReq {
        connection_limit: Some(n),
        ..UserPatchReq::default()
    })
}

pub fn disable_patch(disabled: bool) -> UserPatchReq {
    UserPatchReq {
        disabled: Some(disabled),
        ..UserPatchReq::default()
    }
}

pub fn user_state(user: &PgUserView) -> (&'static str, Tone) {
    if user.disabled {
        ("Disabled", Tone::Warn)
    } else if user.retiring.is_some() {
        ("Rotating", Tone::Info)
    } else {
        ("Active", Tone::Ok)
    }
}

// Why a resource cannot be deleted yet, naming what still uses it.
pub fn delete_blocked_reason(linked_by: &[String]) -> Option<String> {
    (!linked_by.is_empty()).then(|| {
        format!(
            "Linked by {}. Remove those links first.",
            linked_by.join(", ")
        )
    })
}

// ---- generated secrets ----

pub fn is_auth_secret(name: &str) -> bool {
    name.to_ascii_lowercase().contains("auth")
}

pub fn rotate_secret_text(name: &str) -> String {
    let base = format!(
        "Replace the value of {name}. The previous value stops working once a deploy picks the new one up."
    );
    if is_auth_secret(name) {
        format!("{base} {AUTH_ROTATE_WARNING}")
    } else {
        base
    }
}

pub fn secret_create_req(
    name: &str,
    bytes: &str,
    encoding: SecretEncoding,
    existing: &[SecretView],
) -> Result<SecretCreateReq, String> {
    let name = name.trim();
    if let Some(p) = resource_name_problem(name, "secret name") {
        return Err(p);
    }
    if existing.iter().any(|s| s.name == name) {
        return Err(format!("{name} already exists."));
    }
    let bytes = optional_number(
        bytes,
        MIN_SECRET_BYTES,
        MAX_SECRET_BYTES,
        "the size in bytes",
    )?;
    Ok(SecretCreateReq {
        name: name.to_string(),
        bytes: bytes.map(|b| b as u16),
        encoding: Some(encoding),
    })
}

// ---- external Postgres and S3 attachments ----

// The same shape the node accepts: one host, a user, a database, at most 2048 characters.
pub fn external_url_problem(text: &str) -> Option<String> {
    let v = text.trim();
    if v.is_empty() {
        return Some("Enter the connection URL.".into());
    }
    if v.len() > 2048 {
        return Some("The URL is longer than 2048 characters.".into());
    }
    if v.chars().any(char::is_whitespace) {
        return Some("The URL has a space in it.".into());
    }
    let lower = v.to_ascii_lowercase();
    let rest = ["postgresql://", "postgres://"]
        .iter()
        .find(|p| lower.starts_with(**p))
        .and_then(|p| v.get(p.len()..));
    let Some(rest) = rest else {
        return Some("The URL must start with postgres:// or postgresql://.".into());
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, ""),
    };
    if authority.contains(',') {
        return Some("Give exactly one host.".into());
    }
    let (user_info, host) = match authority.rfind('@') {
        Some(i) => (&authority[..i], &authority[i + 1..]),
        None => ("", authority),
    };
    if host.is_empty() || host.starts_with(':') {
        return Some("Give exactly one host.".into());
    }
    if user_info.is_empty() || user_info.starts_with(':') {
        return Some(
            "Include the user name in the URL, as postgres://user:password@host/database.".into(),
        );
    }
    let database = path.split(['?', '#']).next().unwrap_or("");
    if database.is_empty() {
        return Some("Include the database name at the end of the URL.".into());
    }
    None
}

pub fn external_put_req(url: &str) -> ExternalPutReq {
    ExternalPutReq {
        url: url.trim().to_string(),
    }
}

// The fields of an S3 attachment or backup target as typed.
#[derive(Clone, Debug, Default)]
pub struct S3Form {
    pub name: String,
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub prefix: String,
    pub path_style: bool,
    pub encrypt: bool,
    pub access_key_id: String,
    pub secret_access_key: String,
}

impl S3Form {
    // Overwrites the typed keys before the form is dropped.
    pub fn wipe(&mut self) {
        crate::certs::wipe(&mut self.access_key_id);
        crate::certs::wipe(&mut self.secret_access_key);
    }
}

fn endpoint_problem(endpoint: &str, https_only: bool) -> Option<String> {
    let v = endpoint.trim();
    let scheme = v
        .split_once("://")
        .map(|(s, rest)| (s.to_ascii_lowercase(), rest));
    match scheme {
        Some((s, rest)) if (s == "https" || (s == "http" && !https_only)) && !rest.is_empty() => {
            None
        }
        _ if https_only => Some(
            "Backup targets must use https. Enter the endpoint as a full URL, for example https://s3.eu-west-1.amazonaws.com."
                .into(),
        ),
        _ => Some(
            "Enter the endpoint as a full http or https URL, for example https://s3.eu-west-1.amazonaws.com."
                .into(),
        ),
    }
}

fn keys_problem(f: &S3Form, has_keys: bool) -> Option<String> {
    let has_id = !f.access_key_id.trim().is_empty();
    let has_secret = !f.secret_access_key.is_empty();
    if !has_keys && !(has_id && has_secret) {
        return Some("Enter both the access key id and the secret access key.".into());
    }
    if has_keys && has_id != has_secret {
        return Some("Enter both keys, or neither to keep the stored ones.".into());
    }
    None
}

// `has_keys` is true when the attachment already holds keys, so they may be left blank to keep them.
pub fn s3_problem(f: &S3Form, has_keys: bool) -> Option<String> {
    resource_name_problem(f.name.trim(), "attachment name")
        .or_else(|| endpoint_problem(&f.endpoint, false))
        .or_else(|| {
            f.bucket
                .trim()
                .is_empty()
                .then(|| "Enter the bucket.".to_string())
        })
        .or_else(|| {
            f.region
                .trim()
                .is_empty()
                .then(|| "Enter the region.".to_string())
        })
        .or_else(|| keys_problem(f, has_keys))
}

pub fn s3_put_req(f: &S3Form) -> S3PutReq {
    S3PutReq {
        endpoint: f.endpoint.trim().to_string(),
        bucket: f.bucket.trim().to_string(),
        region: f.region.trim().to_string(),
        path_style: f.path_style,
        access_key_id: Some(f.access_key_id.trim().to_string()).filter(|k| !k.is_empty()),
        secret_access_key: Some(f.secret_access_key.clone()).filter(|k| !k.is_empty()),
    }
}

pub fn target_problem(f: &S3Form, has_keys: bool) -> Option<String> {
    let name = f.name.trim();
    if name.is_empty() {
        return Some("Enter a name.".into());
    }
    if name.chars().count() > 64 {
        return Some("The name is at most 64 characters.".into());
    }
    endpoint_problem(&f.endpoint, true)
        .or_else(|| {
            f.bucket
                .trim()
                .is_empty()
                .then(|| "Enter the bucket.".to_string())
        })
        .or_else(|| {
            f.region
                .trim()
                .is_empty()
                .then(|| "Enter the region.".to_string())
        })
        .or_else(|| keys_problem(f, has_keys))
}

pub fn target_req(f: &S3Form) -> TargetReq {
    TargetReq {
        name: f.name.trim().to_string(),
        endpoint: f.endpoint.trim().to_string(),
        bucket: f.bucket.trim().to_string(),
        region: f.region.trim().to_string(),
        path_style: f.path_style,
        prefix: Some(f.prefix.trim().to_string()),
        encrypt: Some(f.encrypt),
        access_key_id: Some(f.access_key_id.trim().to_string()).filter(|k| !k.is_empty()),
        secret_access_key: Some(f.secret_access_key.clone()).filter(|k| !k.is_empty()),
    }
}

pub fn target_test_text(result: &TargetTestResult) -> String {
    if result.ok {
        "The node reached the bucket and could write and read a test object.".into()
    } else {
        format!(
            "Test failed: {}",
            result
                .error
                .as_deref()
                .unwrap_or("the node did not say why")
        )
    }
}

// ---- env links ----

pub fn source_label(source: &LinkSource) -> String {
    match source {
        LinkSource::Postgres {
            database,
            user,
            field,
        } => format!("postgres {database}/{user} {}", field.as_str()),
        LinkSource::External { name, field } => format!("external {name} {}", field.as_str()),
        LinkSource::S3 { name, field } => format!("s3 {name} {}", field.as_str()),
        LinkSource::Secret { name } => format!("secret {name}"),
        LinkSource::SiteUrl => "site url".into(),
    }
}

// The node supplies the label; the text built here is only the fallback for an answer without one.
pub fn link_label(link: &LinkView) -> String {
    if link.label.is_empty() {
        source_label(&link.source)
    } else {
        link.label.clone()
    }
}

pub fn target_label(target: LinkTarget) -> &'static str {
    match target {
        LinkTarget::Runtime => "Runtime",
        LinkTarget::Build => "Build",
    }
}

// One row per var and target, in a stable order.
pub fn link_rows(links: &[LinkView]) -> Vec<LinkView> {
    let mut rows = links.to_vec();
    rows.sort_by(|a, b| (&a.var, a.target).cmp(&(&b.var, b.target)));
    rows
}

// A variable the Environment tab shows read-only because a data resource produces it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkedRow {
    pub var: String,
    pub text: String,
    pub shadows_doppler: bool,
}

pub fn linked_rows(links: &[LinkView], target: LinkTarget) -> Vec<LinkedRow> {
    link_rows(links)
        .into_iter()
        .filter(|l| l.target == target)
        .map(|l| LinkedRow {
            text: format!("linked from {}", link_label(&l)),
            shadows_doppler: l.shadows_doppler,
            var: l.var,
        })
        .collect()
}

pub fn conflict_lines(conflicts: &[LinkConflict]) -> Vec<String> {
    conflicts
        .iter()
        .map(|c| {
            format!(
                "{} ({}) is set {}",
                c.var,
                c.target.as_str(),
                match c.set_by {
                    ConflictSetBy::Link => "by another link",
                    ConflictSetBy::Manual => "by hand",
                }
            )
        })
        .collect()
}

pub fn conflict_summary(conflicts: &[LinkConflict]) -> String {
    let named = |by: ConflictSetBy| -> Vec<String> {
        conflicts
            .iter()
            .filter(|c| c.set_by == by)
            .map(|c| format!("{} ({})", c.var, c.target.as_str()))
            .collect()
    };
    let manual = named(ConflictSetBy::Manual);
    let linked = named(ConflictSetBy::Link);
    let mut parts = Vec::new();
    if !manual.is_empty() {
        parts.push(format!(
            "Override deletes the manual value of {}.",
            manual.join(", ")
        ));
    }
    if !linked.is_empty() {
        parts.push(format!(
            "{} already linked elsewhere; remove that link first, override does not replace links.",
            linked.join(", ")
        ));
    }
    parts.join(" ")
}

// ---- presets ----

pub const PRESETS: [(Preset, &str, &str); 5] = [
    (
        Preset::Generic,
        "Generic",
        "DATABASE_URL and the PG* variables at runtime, MIGRATION_DATABASE_URL for the build.",
    ),
    (
        Preset::Prisma,
        "Prisma",
        "DATABASE_URL at runtime, DATABASE_URL and DIRECT_URL for the build.",
    ),
    (
        Preset::Drizzle,
        "Drizzle",
        "DATABASE_URL at runtime and for the build.",
    ),
    (
        Preset::Authjs,
        "Auth.js",
        "AUTH_SECRET, plus a separate auth database with its own runtime and migration URLs.",
    ),
    (
        Preset::BetterAuth,
        "Better Auth",
        "BETTER_AUTH_SECRET, BETTER_AUTH_URL and DATABASE_URL.",
    ),
];

pub fn preset_label(preset: Preset) -> &'static str {
    PRESETS
        .iter()
        .find(|(p, _, _)| *p == preset)
        .map_or("Preset", |(_, label, _)| label)
}

pub fn preset_summary(preset: Preset) -> &'static str {
    PRESETS
        .iter()
        .find(|(p, _, _)| *p == preset)
        .map_or("", |(_, _, summary)| summary)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresetOpts {
    pub database: String,
    pub runtime_user: String,
    pub migrate_user: String,
    pub auth_database: String,
}

impl Default for PresetOpts {
    fn default() -> Self {
        Self {
            database: "app".into(),
            runtime_user: "app".into(),
            migrate_user: "migrate".into(),
            auth_database: "auth".into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpecLink {
    pub var: &'static str,
    pub target: LinkTarget,
    pub source: LinkSource,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresetSpec {
    // (database, user, level) the preset needs.
    pub users: Vec<(String, String, PgLevel)>,
    pub secrets: Vec<&'static str>,
    pub links: Vec<SpecLink>,
}

fn pg_source(database: &str, user: &str, field: PgField) -> LinkSource {
    LinkSource::Postgres {
        database: database.into(),
        user: user.into(),
        field,
    }
}

// Mirrors the node's preset table: what each preset needs and links.
pub fn preset_spec(preset: Preset, o: &PresetOpts) -> PresetSpec {
    let runtime = |var, source| SpecLink {
        var,
        target: LinkTarget::Runtime,
        source,
    };
    let build = |var, source| SpecLink {
        var,
        target: LinkTarget::Build,
        source,
    };
    let main_users = vec![
        (
            o.database.clone(),
            o.runtime_user.clone(),
            PgLevel::Readwrite,
        ),
        (o.database.clone(), o.migrate_user.clone(), PgLevel::Owner),
    ];
    let rw_url = || pg_source(&o.database, &o.runtime_user, PgField::Url);
    let owner_url = || pg_source(&o.database, &o.migrate_user, PgField::Url);
    match preset {
        Preset::Generic => {
            let mut links: Vec<SpecLink> = [
                ("DATABASE_URL", PgField::Url),
                ("PGHOST", PgField::Host),
                ("PGPORT", PgField::Port),
                ("PGDATABASE", PgField::Database),
                ("PGUSER", PgField::User),
                ("PGPASSWORD", PgField::Password),
                ("PGSSLMODE", PgField::Sslmode),
            ]
            .into_iter()
            .map(|(var, field)| runtime(var, pg_source(&o.database, &o.runtime_user, field)))
            .collect();
            links.push(build("MIGRATION_DATABASE_URL", owner_url()));
            PresetSpec {
                users: main_users,
                secrets: Vec::new(),
                links,
            }
        }
        Preset::Prisma => PresetSpec {
            users: main_users,
            secrets: Vec::new(),
            links: vec![
                runtime("DATABASE_URL", rw_url()),
                build("DATABASE_URL", owner_url()),
                build("DIRECT_URL", owner_url()),
            ],
        },
        Preset::Drizzle => PresetSpec {
            users: main_users,
            secrets: Vec::new(),
            links: vec![
                runtime("DATABASE_URL", rw_url()),
                build("DATABASE_URL", owner_url()),
            ],
        },
        Preset::Authjs => PresetSpec {
            users: vec![
                (
                    o.auth_database.clone(),
                    o.runtime_user.clone(),
                    PgLevel::Readwrite,
                ),
                (
                    o.auth_database.clone(),
                    o.migrate_user.clone(),
                    PgLevel::Owner,
                ),
            ],
            secrets: vec!["auth-secret"],
            links: vec![
                runtime(
                    "AUTH_SECRET",
                    LinkSource::Secret {
                        name: "auth-secret".into(),
                    },
                ),
                runtime(
                    "AUTH_DATABASE_URL",
                    pg_source(&o.auth_database, &o.runtime_user, PgField::Url),
                ),
                build(
                    "AUTH_MIGRATION_DATABASE_URL",
                    pg_source(&o.auth_database, &o.migrate_user, PgField::Url),
                ),
            ],
        },
        Preset::BetterAuth => PresetSpec {
            users: main_users,
            secrets: vec!["better-auth-secret"],
            links: vec![
                runtime(
                    "BETTER_AUTH_SECRET",
                    LinkSource::Secret {
                        name: "better-auth-secret".into(),
                    },
                ),
                runtime("BETTER_AUTH_URL", LinkSource::SiteUrl),
                runtime("DATABASE_URL", rw_url()),
                build("DATABASE_URL", owner_url()),
            ],
        },
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkState {
    New,
    Exists,
    // Another link already owns the variable; the preset cannot take it.
    Blocked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewUser {
    pub database: String,
    pub user: String,
    pub level: PgLevel,
}

// What applying a preset would do to the site as it is now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresetPreview {
    pub links: Vec<(SpecLink, LinkState)>,
    pub users: Vec<NewUser>,
    pub databases: Vec<String>,
    pub secrets: Vec<String>,
    // Manual variables the new links would shadow; applying needs an explicit override.
    pub conflicts: Vec<LinkConflict>,
    pub problem: Option<String>,
}

impl PresetPreview {
    pub fn needs_override(&self) -> bool {
        !self.conflicts.is_empty()
    }

    // True when applying would change nothing.
    pub fn is_noop(&self) -> bool {
        self.links.iter().all(|(_, s)| *s == LinkState::Exists)
            && self.users.is_empty()
            && self.databases.is_empty()
            && self.secrets.is_empty()
    }
}

pub fn preset_options_problem(o: &PresetOpts, preset: Preset) -> Option<String> {
    pg_name_problem(&o.database, "database")
        .or_else(|| pg_name_problem(&o.runtime_user, "user name"))
        .or_else(|| pg_name_problem(&o.migrate_user, "user name"))
        .or_else(|| {
            (preset == Preset::Authjs)
                .then(|| pg_name_problem(&o.auth_database, "database"))
                .flatten()
        })
        .or_else(|| {
            (o.runtime_user == o.migrate_user)
                .then(|| "The runtime user and the migrate user must differ.".to_string())
        })
}

// `manual_runtime` and `manual_build` are the variable names set by hand on the site.
pub fn preset_preview(
    preset: Preset,
    opts: &PresetOpts,
    view: &SiteDataView,
    manual_runtime: &[String],
    manual_build: &[String],
) -> PresetPreview {
    let spec = preset_spec(preset, opts);
    let mut out = PresetPreview {
        links: Vec::new(),
        users: Vec::new(),
        databases: Vec::new(),
        secrets: Vec::new(),
        conflicts: Vec::new(),
        problem: preset_options_problem(opts, preset),
    };
    let Some(pg) = &view.postgres else {
        out.problem
            .get_or_insert_with(|| "Enable Postgres before applying a preset.".to_string());
        return out;
    };
    let mut problems: Vec<String> = Vec::new();
    for (database, user, level) in &spec.users {
        let db = pg.databases.iter().find(|d| d.name == *database);
        if db.is_none() && !out.databases.contains(database) {
            out.databases.push(database.clone());
        }
        let existing = db.and_then(|d| d.users.iter().find(|u| u.name == *user));
        match existing {
            Some(u) if u.level == Some(*level) => {}
            Some(u) => problems.push(format!(
                "User {database}/{user} is {} but this preset needs {}.",
                u.level.map_or("unknown", level_label).to_lowercase(),
                level_label(*level).to_lowercase()
            )),
            None => out.users.push(NewUser {
                database: database.clone(),
                user: user.clone(),
                level: *level,
            }),
        }
    }
    if pg.databases.len() + out.databases.len() > MAX_PG_DATABASES {
        problems.push(format!(
            "A site can have at most {MAX_PG_DATABASES} databases."
        ));
    }
    out.secrets = spec
        .secrets
        .iter()
        .filter(|n| !view.secrets.iter().any(|s| s.name == **n))
        .map(|n| n.to_string())
        .collect();
    for link in spec.links {
        let same = view
            .links
            .iter()
            .find(|e| e.var == link.var && e.target == link.target);
        let state = match same {
            Some(e) if e.source == link.source => LinkState::Exists,
            Some(e) => {
                problems.push(format!(
                    "{} ({}) is already linked from {}. Remove that link first.",
                    link.var,
                    link.target.as_str(),
                    link_label(e)
                ));
                LinkState::Blocked
            }
            None => {
                let manual = match link.target {
                    LinkTarget::Runtime => manual_runtime,
                    LinkTarget::Build => manual_build,
                };
                if manual.iter().any(|m| m == link.var) {
                    out.conflicts.push(LinkConflict {
                        var: link.var.to_string(),
                        target: link.target,
                        set_by: ConflictSetBy::Manual,
                    });
                }
                LinkState::New
            }
        };
        out.links.push((link, state));
    }
    if out.problem.is_none() {
        out.problem = problems.into_iter().next();
    }
    out
}

pub fn preset_request(preset: Preset, o: &PresetOpts, override_manual: bool) -> PresetRequest {
    PresetRequest {
        preset,
        database: o.database.clone(),
        runtime_user: o.runtime_user.clone(),
        migrate_user: o.migrate_user.clone(),
        auth_database: (preset == Preset::Authjs).then(|| o.auth_database.clone()),
        override_manual,
    }
}

// One line per planned link: "DATABASE_URL (runtime) from postgres app/app url".
pub fn spec_link_text(link: &SpecLink) -> String {
    format!(
        "{} ({}) from {}",
        link.var,
        link.target.as_str(),
        source_label(&link.source)
    )
}

pub fn link_state_text(state: LinkState) -> (&'static str, Tone) {
    match state {
        LinkState::New => ("new", Tone::Ok),
        LinkState::Exists => ("already linked", Tone::Muted),
        LinkState::Blocked => ("blocked", Tone::Bad),
    }
}

// ---- custom links ----

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkKind {
    Postgres,
    External,
    S3,
    Secret,
    SiteUrl,
}

impl LinkKind {
    pub fn label(self) -> &'static str {
        match self {
            LinkKind::Postgres => "Managed database",
            LinkKind::External => "External database",
            LinkKind::S3 => "S3 attachment",
            LinkKind::Secret => "Generated secret",
            LinkKind::SiteUrl => "Site URL",
        }
    }
}

const PG_FIELDS: [PgField; 7] = [
    PgField::Url,
    PgField::Host,
    PgField::Port,
    PgField::Database,
    PgField::User,
    PgField::Password,
    PgField::Sslmode,
];
const EXTERNAL_FIELDS: [PgField; 8] = [
    PgField::Url,
    PgField::Host,
    PgField::Port,
    PgField::Database,
    PgField::User,
    PgField::Password,
    PgField::Sslmode,
    PgField::TlsServername,
];
const S3_FIELDS: [S3Field; 6] = [
    S3Field::Endpoint,
    S3Field::Bucket,
    S3Field::Region,
    S3Field::AccessKeyId,
    S3Field::SecretAccessKey,
    S3Field::PathStyle,
];

// The fields a resource of this kind can deliver, by wire name.
pub fn fields_for(kind: LinkKind) -> Vec<&'static str> {
    match kind {
        LinkKind::Postgres => PG_FIELDS.iter().map(|f| f.as_str()).collect(),
        LinkKind::External => EXTERNAL_FIELDS.iter().map(|f| f.as_str()).collect(),
        LinkKind::S3 => S3_FIELDS.iter().map(|f| f.as_str()).collect(),
        LinkKind::Secret | LinkKind::SiteUrl => Vec::new(),
    }
}

pub fn target_sel_label(sel: LinkTargetSel) -> &'static str {
    match sel {
        LinkTargetSel::Runtime => "Runtime",
        LinkTargetSel::Build => "Build",
        LinkTargetSel::Both => "Runtime and build",
    }
}

// The add-link form as chosen: what to link, and to which variable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkDraft {
    pub kind: LinkKind,
    pub database: String,
    pub user: String,
    pub name: String,
    pub field: String,
    pub var: String,
    pub target: LinkTargetSel,
}

pub fn source_from_draft(d: &LinkDraft) -> Result<LinkSource, String> {
    let pg_field = |list: &[PgField]| {
        list.iter()
            .copied()
            .find(|f| f.as_str() == d.field)
            .ok_or_else(|| "Pick a field.".to_string())
    };
    Ok(match d.kind {
        LinkKind::Postgres => {
            if d.database.is_empty() {
                return Err("Pick a database.".into());
            }
            if d.user.is_empty() {
                return Err("Pick a user.".into());
            }
            LinkSource::Postgres {
                database: d.database.clone(),
                user: d.user.clone(),
                field: pg_field(&PG_FIELDS)?,
            }
        }
        LinkKind::External => {
            if d.name.is_empty() {
                return Err("Pick an external database.".into());
            }
            LinkSource::External {
                name: d.name.clone(),
                field: pg_field(&EXTERNAL_FIELDS)?,
            }
        }
        LinkKind::S3 => {
            if d.name.is_empty() {
                return Err("Pick an S3 attachment.".into());
            }
            LinkSource::S3 {
                name: d.name.clone(),
                field: S3_FIELDS
                    .iter()
                    .copied()
                    .find(|f| f.as_str() == d.field)
                    .ok_or_else(|| "Pick a field.".to_string())?,
            }
        }
        LinkKind::Secret => {
            if d.name.is_empty() {
                return Err("Pick a generated secret.".into());
            }
            LinkSource::Secret {
                name: d.name.clone(),
            }
        }
        LinkKind::SiteUrl => LinkSource::SiteUrl,
    })
}

// A name for the variable that matches common conventions.
pub fn suggested_var(source: &LinkSource) -> String {
    let upper = |s: &str| s.to_ascii_uppercase().replace('-', "_");
    match source {
        LinkSource::Secret { name } => upper(name),
        LinkSource::SiteUrl => "SITE_URL".into(),
        LinkSource::S3 { field, .. } => format!("S3_{}", upper(field.as_str())),
        LinkSource::External {
            name,
            field: PgField::Url,
        } => format!("{}_URL", upper(name)),
        LinkSource::Postgres {
            field: PgField::Url,
            ..
        } => "DATABASE_URL".into(),
        LinkSource::Postgres { field, .. } | LinkSource::External { field, .. } => {
            format!("PG{}", upper(field.as_str()))
        }
    }
}

fn is_env_var_name(name: &str) -> bool {
    let b = name.as_bytes();
    (1..=64).contains(&b.len())
        && (b[0].is_ascii_uppercase() || b[0] == b'_')
        && b.iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
}

// Checks the draft and, like the node, refuses a variable another link already owns with a different source.
pub fn link_draft_problem(d: &LinkDraft, links: &[LinkView]) -> Option<String> {
    if !is_env_var_name(&d.var) {
        return Some(
            "Use capital letters, digits and underscores for the variable name, up to 64 characters."
                .into(),
        );
    }
    let source = match source_from_draft(d) {
        Ok(s) => s,
        Err(e) => return Some(e),
    };
    d.target.targets().iter().find_map(|t| {
        links
            .iter()
            .find(|l| l.var == d.var && l.target == *t && l.source != source)
            .map(|l| {
                format!(
                    "{} ({}) is already linked from {}. Remove that link first.",
                    d.var,
                    t.as_str(),
                    link_label(l)
                )
            })
    })
}

pub fn link_request(d: &LinkDraft, source: LinkSource, override_manual: bool) -> LinksReq {
    LinksReq {
        links: vec![EnvLinkReq {
            var: d.var.clone(),
            target: d.target,
            source,
        }],
        override_manual,
    }
}

// The manual variables the new link would shadow.
pub fn manual_link_conflicts(
    d: &LinkDraft,
    links: &[LinkView],
    manual_runtime: &[String],
    manual_build: &[String],
) -> Vec<LinkConflict> {
    d.target
        .targets()
        .iter()
        .filter(|t| !links.iter().any(|l| l.var == d.var && l.target == **t))
        .filter(|t| {
            let names = match t {
                LinkTarget::Runtime => manual_runtime,
                LinkTarget::Build => manual_build,
            };
            names.contains(&d.var)
        })
        .map(|t| LinkConflict {
            var: d.var.clone(),
            target: *t,
            set_by: ConflictSetBy::Manual,
        })
        .collect()
}

// Override only replaces manual variables, never another link.
pub fn can_override(conflicts: &[LinkConflict]) -> bool {
    !conflicts.is_empty() && conflicts.iter().all(|c| c.set_by == ConflictSetBy::Manual)
}

// ---- backups ----

pub fn trigger_label(trigger: BackupTrigger) -> &'static str {
    match trigger {
        BackupTrigger::Manual => "Manual",
        BackupTrigger::Scheduled => "Scheduled",
        BackupTrigger::PreRestore => "Before restore",
        BackupTrigger::Transfer => "Transfer",
        BackupTrigger::Import => "Import",
    }
}

pub fn status_tone(status: BackupStatus) -> Tone {
    match status {
        BackupStatus::Ok => Tone::Ok,
        BackupStatus::Failed => Tone::Bad,
        BackupStatus::Running => Tone::Info,
    }
}

pub fn status_text(status: BackupStatus) -> &'static str {
    match status {
        BackupStatus::Ok => "Complete",
        BackupStatus::Failed => "Failed",
        BackupStatus::Running => "Running",
    }
}

pub fn short_sha(sha: &str) -> String {
    if sha.is_empty() {
        "-".into()
    } else {
        sha.chars().take(8).collect()
    }
}

pub fn database_key(name: &str) -> String {
    format!("pg:{name}")
}

pub fn database_name(key: &str) -> &str {
    key.strip_prefix("pg:")
        .or_else(|| key.strip_prefix("ext:"))
        .unwrap_or(key)
}

pub fn is_external_key(key: &str) -> bool {
    key.starts_with("ext:")
}

// Every database a backup can be taken of, managed first.
pub fn backup_databases(view: &SiteDataView) -> Vec<String> {
    let mut keys: Vec<String> = view
        .postgres
        .iter()
        .flat_map(|pg| pg.databases.iter().map(|d| database_key(&d.name)))
        .collect();
    keys.extend(view.external.iter().map(|e| format!("ext:{}", e.name)));
    keys
}

// Where a version's bytes are held.
pub fn locations(rec: &BackupRecord) -> Vec<&'static str> {
    let mut out = Vec::new();
    if rec.local.is_some() {
        out.push("node");
    }
    if rec.s3.is_some() {
        out.push("s3");
    }
    out
}

// Newest first; `key` (pg:<db> or ext:<name>) narrows the list.
pub fn backup_rows(records: &[BackupRecord], key: Option<&str>) -> Vec<BackupRecord> {
    let mut rows: Vec<BackupRecord> = records
        .iter()
        .filter(|r| key.is_none_or(|k| r.database == k))
        .cloned()
        .collect();
    rows.sort_by(|a, b| (&b.created_at, b.version).cmp(&(&a.created_at, a.version)));
    rows
}

pub fn can_download(rec: &BackupRecord) -> bool {
    rec.status == BackupStatus::Ok && !locations(rec).is_empty()
}

// A version of an external database can be restored into a managed one elsewhere, never back into the external one.
pub fn can_restore(rec: &BackupRecord) -> bool {
    can_download(rec) && !is_external_key(&rec.database)
}

pub fn can_push(rec: &BackupRecord, has_target: bool) -> bool {
    rec.status == BackupStatus::Ok && rec.local.is_some() && rec.s3.is_none() && has_target
}

// Pinned versions are refused by the node; the button says why before a request is made.
pub fn delete_backup_block(rec: &BackupRecord) -> Option<&'static str> {
    if rec.pinned {
        Some("Pinned versions cannot be deleted. Unpin it first.")
    } else if rec.status == BackupStatus::Running {
        Some("This backup is still running.")
    } else {
        None
    }
}

pub fn restore_text(rec: &BackupRecord, site: &str) -> String {
    format!(
        "Restore version {} of {} into {site}. A backup of the current data is taken first, as a Before restore version, then connections drop while the restore runs and the app sees errors until it finishes. A failed restore is rolled back.",
        rec.version,
        database_name(&rec.database)
    )
}

pub fn delete_backup_text(rec: &BackupRecord) -> String {
    let loc = locations(rec);
    let where_ = match loc.as_slice() {
        [_, _] => "the node and S3",
        ["s3"] => "S3",
        _ => "the node",
    };
    format!(
        "Delete version {} from {where_}. This cannot be undone.",
        rec.version
    )
}

// ---- retention and policy ----

pub struct RetentionField {
    pub label: &'static str,
    pub min: u32,
    pub max: u32,
}

// The order of `retention_texts`.
pub const RETENTION_FIELDS: [RetentionField; 5] = [
    RetentionField {
        label: "Keep every backup for (hours)",
        min: 0,
        max: 720,
    },
    RetentionField {
        label: "Keep one a day for (days)",
        min: 0,
        max: 366,
    },
    RetentionField {
        label: "Keep one a week for (weeks)",
        min: 0,
        max: 260,
    },
    RetentionField {
        label: "Keep one a month for (months)",
        min: 0,
        max: 120,
    },
    RetentionField {
        label: "Keep Before restore versions for (days)",
        min: 0,
        max: 366,
    },
];

pub fn retention_texts(r: &BackupRetention) -> [String; 5] {
    [
        r.keep_all_hours.to_string(),
        r.daily_days.to_string(),
        r.weekly_weeks.to_string(),
        r.monthly_months.to_string(),
        r.pre_restore_days.to_string(),
    ]
}

pub fn retention_from_texts(texts: &[String; 5]) -> Result<BackupRetention, String> {
    let mut values = [0u32; 5];
    for (i, field) in RETENTION_FIELDS.iter().enumerate() {
        let label = field.label;
        values[i] = optional_number(&texts[i], field.min, field.max, "the value")
            .map_err(|e| format!("{label}: {e}"))?
            .ok_or_else(|| format!("{label}: enter a number."))?;
    }
    Ok(BackupRetention {
        keep_all_hours: values[0],
        daily_days: values[1],
        weekly_weeks: values[2],
        monthly_months: values[3],
        pre_restore_days: values[4],
    })
}

pub fn retention_text(r: &BackupRetention) -> String {
    let mut parts = Vec::new();
    if r.keep_all_hours > 0 {
        parts.push(format!(
            "every backup from the last {}",
            plural(r.keep_all_hours as usize, "hour", "hours")
        ));
    }
    if r.daily_days > 0 {
        parts.push(format!(
            "the newest of each day for {}",
            plural(r.daily_days as usize, "day", "days")
        ));
    }
    if r.weekly_weeks > 0 {
        parts.push(format!(
            "the newest of each week for {}",
            plural(r.weekly_weeks as usize, "week", "weeks")
        ));
    }
    if r.monthly_months > 0 {
        parts.push(format!(
            "the newest of each month for {}",
            plural(r.monthly_months as usize, "month", "months")
        ));
    }
    let base = if parts.is_empty() {
        "Keeps only the newest version.".to_string()
    } else {
        format!("Keeps {}.", parts.join(", "))
    };
    format!("{base} Pinned versions and the newest complete version are always kept.")
}

pub fn schedule_text(schedule: Option<&BackupSchedule>) -> String {
    let Some(s) = schedule else {
        return "No scheduled backups.".into();
    };
    if s.every_hours == 24 {
        return format!("Every day at 00:{:02} UTC.", s.minute);
    }
    let every = if s.every_hours == 1 {
        "hour".to_string()
    } else {
        format!("{} hours", s.every_hours)
    };
    format!(
        "Every {every} at minute {:02}, on the hours that divide evenly (UTC).",
        s.minute
    )
}

// The backup policy as the editor holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyDraft {
    pub scheduled: bool,
    pub every_hours: u8,
    pub minute: String,
    pub local: [String; 5],
    pub s3_target: Option<String>,
    pub s3: [String; 5],
}

impl PolicyDraft {
    pub fn from_policy(policy: &BackupPolicy) -> Self {
        Self {
            scheduled: policy.schedule.is_some(),
            every_hours: policy.schedule.as_ref().map_or(24, |s| s.every_hours),
            minute: policy
                .schedule
                .as_ref()
                .map_or(17, |s| s.minute)
                .to_string(),
            local: retention_texts(&policy.local),
            s3_target: policy.s3.as_ref().map(|c| c.target.clone()),
            s3: retention_texts(
                &policy
                    .s3
                    .as_ref()
                    .map_or_else(BackupRetention::default, |c| c.retention.clone()),
            ),
        }
    }

    pub fn to_policy(&self) -> Result<BackupPolicy, String> {
        let schedule = if self.scheduled {
            if !BACKUP_EVERY_HOURS.contains(&self.every_hours) {
                return Err(format!(
                    "Pick one of {} hours.",
                    BACKUP_EVERY_HOURS
                        .iter()
                        .map(u8::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            let minute = required_number(&self.minute, 0, 59, "the minute")?;
            Some(BackupSchedule {
                every_hours: self.every_hours,
                minute: minute as u8,
            })
        } else {
            None
        };
        let local = retention_from_texts(&self.local).map_err(|e| format!("Node copies: {e}"))?;
        let s3 = match &self.s3_target {
            Some(target) => Some(S3Copy {
                target: target.clone(),
                retention: retention_from_texts(&self.s3).map_err(|e| format!("S3 copies: {e}"))?,
            }),
            None => None,
        };
        let policy = BackupPolicy {
            schedule,
            local,
            s3,
        };
        validate_backup_policy("backup policy", &policy).map_err(|e| e.to_string())?;
        Ok(policy)
    }
}

pub fn keep_reason_text(reason: &str) -> String {
    match reason {
        "pinned" => "pinned",
        "newest" => "newest complete version",
        "recent" => "inside the keep-everything window",
        "pre_restore" => "taken before a restore",
        "daily" => "newest of its day",
        "weekly" => "newest of its week",
        "monthly" => "newest of its month",
        other => other,
    }
    .to_string()
}

pub fn prune_total(previews: &[PrunePreview], s3: bool) -> usize {
    previews
        .iter()
        .map(|p| if s3 { &p.s3 } else { &p.local }.delete.len())
        .sum()
}

pub fn prune_summary(previews: &[PrunePreview]) -> String {
    let local = prune_total(previews, false);
    let s3 = prune_total(previews, true);
    if local == 0 && s3 == 0 {
        return "Nothing would be deleted.".into();
    }
    let mut parts = Vec::new();
    if local > 0 {
        parts.push(format!("{} on the node", plural(local, "copy", "copies")));
    }
    if s3 > 0 {
        parts.push(format!("{} in S3", plural(s3, "copy", "copies")));
    }
    format!("Would delete {}.", parts.join(" and "))
}

// One line per database and tier: what is kept and why, and what goes.
pub fn prune_lines(preview: &PrunePreview, records: &[BackupRecord]) -> Vec<String> {
    let name = |id: &str| {
        records
            .iter()
            .find(|r| r.id == id)
            .map_or_else(|| id.to_string(), |r| format!("v{}", r.version))
    };
    let mut lines = Vec::new();
    for (tier, plan) in [("node", &preview.local), ("S3", &preview.s3)] {
        if plan.keep.is_empty() && plan.delete.is_empty() {
            continue;
        }
        let keep: Vec<String> = plan
            .keep
            .iter()
            .map(|k| format!("{} ({})", name(&k.id), keep_reason_text(&k.reason)))
            .collect();
        let delete: Vec<String> = plan.delete.iter().map(|id| name(id)).collect();
        lines.push(format!(
            "{} on {tier}: keeps {}; deletes {}",
            database_name(&preview.database),
            if keep.is_empty() {
                "nothing".into()
            } else {
                keep.join(", ")
            },
            if delete.is_empty() {
                "nothing".into()
            } else {
                delete.join(", ")
            },
        ));
    }
    lines
}

// ---- jobs ----

// The tick is half a second, so a job is read about once a second.
pub const JOB_POLL_TICKS: u64 = 2;
// 30 minutes of ticks.
pub const JOB_MAX_TICKS: u64 = 3600;
pub const JOB_MAX_FAILED_READS: u8 = 5;

// A connector job the page is following.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobTrack {
    pub id: String,
    pub node: String,
    pub site: Option<String>,
    pub what: String,
    pub step: Option<String>,
    pub in_flight: bool,
    pub started_tick: u64,
    pub failed_reads: u8,
}

impl JobTrack {
    pub fn new(id: &str, node: &str, site: Option<&str>, what: &str, tick: u64) -> Self {
        Self {
            id: id.to_string(),
            node: node.to_string(),
            site: site.map(str::to_string),
            what: what.to_string(),
            step: None,
            in_flight: false,
            started_tick: tick,
            failed_reads: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobUpdate {
    Running,
    Finished,
    Failed(String),
}

// Folds one read of the job into the track. Five reads in a row that fail, a job the node no longer knows, and a job that runs
// for 30 minutes all end the tracking with a message; the job itself keeps going on the node.
pub fn apply_job_read(
    track: &mut JobTrack,
    read: Result<JobView, (Option<u16>, String)>,
    tick: u64,
) -> JobUpdate {
    track.in_flight = false;
    match read {
        Ok(job) => {
            track.failed_reads = 0;
            track.step = job.step.clone();
            match job.state {
                JobState::Ok => JobUpdate::Finished,
                JobState::Failed => JobUpdate::Failed(
                    job.error
                        .filter(|e| !e.is_empty())
                        .unwrap_or_else(|| "The job failed without a message.".into()),
                ),
                JobState::Running if tick.saturating_sub(track.started_tick) > JOB_MAX_TICKS => {
                    JobUpdate::Failed(
                        "The job is still running after 30 minutes. It keeps going on the node; reload later to check."
                            .into(),
                    )
                }
                JobState::Running => JobUpdate::Running,
            }
        }
        Err((Some(404), _)) => JobUpdate::Failed(
            "The node no longer knows this job. It may have restarted; reload to see where things stand."
                .into(),
        ),
        Err((_, message)) => {
            track.failed_reads += 1;
            if track.failed_reads >= JOB_MAX_FAILED_READS {
                JobUpdate::Failed(message)
            } else {
                JobUpdate::Running
            }
        }
    }
}

pub fn read_error(e: &ClientError) -> (Option<u16>, String) {
    (e.status_code(), e.to_string())
}

// Indexes of the tracks to read on this tick.
pub fn jobs_due(tracks: &[JobTrack], tick: u64) -> Vec<usize> {
    if !tick.is_multiple_of(JOB_POLL_TICKS) {
        return Vec::new();
    }
    tracks
        .iter()
        .enumerate()
        .filter(|(_, t)| !t.in_flight)
        .map(|(i, _)| i)
        .collect()
}

pub fn job_step_text(track: &JobTrack) -> String {
    let step = track
        .step
        .as_deref()
        .map(|s| s.replace(['_', '-'], " "))
        .filter(|s| !s.is_empty());
    match step {
        Some(step) => format!("{}: {step}", track.what),
        None => format!("{}: running", track.what),
    }
}

// ---- shared instance ----

pub fn health_tone(text: &str) -> Tone {
    let v = text.to_ascii_lowercase();
    if v.is_empty() {
        Tone::Muted
    } else if ["unhealthy", "missing", "exited", "dead", "stopped"]
        .iter()
        .any(|w| v.contains(w))
    {
        Tone::Bad
    } else if ["starting", "restarting", "paused"]
        .iter()
        .any(|w| v.contains(w))
    {
        Tone::Warn
    } else if v.contains("healthy") || v.contains("running") {
        Tone::Ok
    } else {
        Tone::Muted
    }
}

pub fn cpus_of(nano_cpus: i64) -> f64 {
    if nano_cpus <= 0 {
        0.0
    } else {
        (nano_cpus as f64 / 1e9 * 100.0).round() / 100.0
    }
}

pub fn cpus_text(nano_cpus: i64) -> String {
    let cpus = cpus_of(nano_cpus);
    if cpus == 0.0 {
        "unlimited".into()
    } else {
        format!("{cpus}")
    }
}

// `major` is chosen only when the instance is created; later updates omit it.
pub fn shared_req(
    major: Option<u8>,
    memory: &str,
    cpus: &str,
    connections: &str,
) -> Result<SharedReq, String> {
    if let Some(m) = major
        && !PG_MAJORS.contains(&m)
    {
        return Err(format!(
            "Pick Postgres {} or {}.",
            PG_MAJORS[1], PG_MAJORS[0]
        ));
    }
    let memory_mb = required_number(
        memory,
        MIN_PG_MEMORY_MB,
        MAX_PG_MEMORY_MB,
        "the memory limit in MiB",
    )?;
    let cpus_value: f64 = cpus
        .trim()
        .parse()
        .ok()
        .filter(|c: &f64| c.is_finite() && (0.25..=64.0).contains(c))
        .ok_or_else(|| "CPUs must be a number from 0.25 to 64.".to_string())?;
    let max_connections = required_number(connections, 10, 1000, "the connection limit")?;
    Ok(SharedReq {
        major,
        memory_mb,
        cpus: cpus_value,
        max_connections,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantRow {
    pub site: String,
    pub databases: Vec<(String, u64)>,
    pub size_bytes: u64,
}

pub fn tenant_rows(shared: &SharedView) -> Vec<TenantRow> {
    let mut rows: Vec<TenantRow> = shared
        .tenants
        .iter()
        .map(|t| TenantRow {
            site: t.site.clone(),
            databases: t
                .databases
                .iter()
                .map(|d| (d.name.clone(), d.size_bytes))
                .collect(),
            size_bytes: t.databases.iter().map(|d| d.size_bytes).sum(),
        })
        .collect();
    rows.sort_by(|a, b| a.site.cmp(&b.site));
    rows
}

// The node refuses to delete the instance while sites still have databases on it; the button says so before asking.
pub fn shared_delete_block(shared: &SharedView) -> Option<String> {
    let tenants = shared.tenants.len();
    (tenants > 0).then(|| {
        format!(
            "{} still use this instance. Move or remove their databases first.",
            plural(tenants, "site", "sites")
        )
    })
}

pub fn shared_delete_text() -> &'static str {
    "Removes the shared Postgres container and its network. The data volumes are kept."
}

pub fn orphan_text(o: &OrphanView) -> String {
    let mut parts = Vec::new();
    if o.dedicated_volume.is_some() {
        parts.push("a dedicated database volume".to_string());
    }
    if !o.shared_databases.is_empty() {
        parts.push(plural(
            o.shared_databases.len(),
            "shared database",
            "shared databases",
        ));
    }
    if o.backups > 0 {
        parts.push(plural(o.backups as usize, "backup", "backups"));
    }
    if o.secrets > 0 {
        parts.push(plural(
            o.secrets as usize,
            "stored secret",
            "stored secrets",
        ));
    }
    if parts.is_empty() {
        "nothing left".into()
    } else {
        parts.join(", ")
    }
}

// ---- transfer between nodes ----

pub const SOURCE_KEPT_NOTE: &str = "The transfer never deletes the source database. It stays on the source node, frozen, until you delete it yourself.";
pub const CONVERT_NOTE: &str = "Converting copies the database to the other placement and then switches the site to it. The old database is kept, frozen, until you delete it.";

// The two freezes this release offers; moving without any freeze would lose writes made during the copy.
pub const FREEZES: [Freeze; 2] = [Freeze::Maintenance, Freeze::ReadOnly];

pub fn freeze_label(freeze: Freeze) -> &'static str {
    match freeze {
        Freeze::Maintenance => "Maintenance page",
        Freeze::ReadOnly => "Read-only",
        Freeze::None => "No freeze",
    }
}

pub fn freeze_text(freeze: Freeze) -> &'static str {
    match freeze {
        Freeze::Maintenance => {
            "The site serves the maintenance page during the final copy, so nothing changes in the database while it is copied."
        }
        Freeze::ReadOnly => {
            "The site stays up but refuses writes during the final copy: visitors can read, and anything that writes to the database fails until the move finishes."
        }
        Freeze::None => {
            "The site is not frozen, so writes made during the copy are not carried over."
        }
    }
}

pub fn phase_label(phase: TransferPhase) -> &'static str {
    match phase {
        TransferPhase::Pending => "Waiting",
        TransferPhase::Freezing => "Freezing the source",
        TransferPhase::Dumping => "Dumping",
        TransferPhase::Streaming => "Copying",
        TransferPhase::Restoring => "Restoring on the target",
        TransferPhase::Verifying => "Verifying",
        TransferPhase::Cutover => "Cutting over",
        TransferPhase::Done => "Done",
        TransferPhase::Failed => "Failed",
        TransferPhase::RolledBack => "Rolled back",
    }
}

pub fn phase_tone(phase: TransferPhase) -> Tone {
    match phase {
        TransferPhase::Done => Tone::Ok,
        TransferPhase::Failed => Tone::Bad,
        TransferPhase::RolledBack => Tone::Muted,
        _ => Tone::Info,
    }
}

pub fn progress_fraction(done: u64, total: u64) -> f32 {
    if total == 0 {
        0.0
    } else {
        (done as f64 / total as f64).clamp(0.0, 1.0) as f32
    }
}

pub fn progress_text(done: u64, total: u64) -> String {
    if total == 0 {
        return "Size not known yet".into();
    }
    format!(
        "{} of {} ({}%)",
        crate::model::fmt_bytes(done.min(total)),
        crate::model::fmt_bytes(total),
        (progress_fraction(done, total) * 100.0).round() as u32
    )
}

pub fn transfer_title(t: &TransferState) -> String {
    format!(
        "{} of {}: {} to {}",
        t.plan.database, t.plan.site, t.plan.source_node, t.plan.target_node
    )
}

pub fn mismatch_text(d: &CountDiff) -> String {
    let name = format!("{}.{}", d.schema, d.table);
    match (d.source, d.target) {
        (Some(s), Some(t)) => format!("{name}: {s} rows on the source, {t} on the target"),
        (Some(s), None) => format!("{name}: {s} rows on the source, missing on the target"),
        (None, Some(t)) => format!("{name}: not on the source, {t} rows on the target"),
        (None, None) => name,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XferAction {
    Cancel,
    Resume,
    Cutover,
    Rollback,
    Forget,
}

// What the operator can do with a transfer, given whether this app is driving it right now.
pub fn xfer_actions(state: &TransferState, running: bool) -> Vec<XferAction> {
    if running {
        return vec![XferAction::Cancel];
    }
    if state.phase.is_finished() {
        return vec![XferAction::Forget];
    }
    if state.awaiting_operator() {
        return vec![XferAction::Cutover, XferAction::Rollback];
    }
    match state.phase {
        // A cutover that stopped halfway can only be finished, not undone.
        TransferPhase::Cutover => vec![XferAction::Resume],
        _ => vec![XferAction::Resume, XferAction::Rollback],
    }
}

// The node refuses a cutover whose counts differ; the button says why before a request is made.
pub fn cutover_block(state: &TransferState) -> Option<&'static str> {
    (state.counts_match != Some(true)).then_some(
        "The row counts of the two databases differ. Roll back, or fix the difference and run the transfer again.",
    )
}

// Online nodes other than the one the site is on.
pub fn target_candidates(nodes: &[crate::targets::NodeInfo], current: &str) -> Vec<String> {
    nodes
        .iter()
        .filter(|n| n.online && n.name != current)
        .map(|n| n.name.clone())
        .collect()
}

pub fn transfer_plan(
    source: &str,
    target: &str,
    site: &str,
    database: &str,
    freeze: Freeze,
    replace: bool,
    override_manual: bool,
    auto_cutover: bool,
) -> Result<TransferPlan, String> {
    TransferPlan {
        source_node: source.into(),
        target_node: target.into(),
        site: site.into(),
        database: database.into(),
        freeze,
        override_manual,
        replace,
        auto_cutover,
    }
    .validated()
    .map_err(|e| e.to_string())
}

const DEMO_TRANSFER_BYTES: u64 = 48 * 1024 * 1024;

// The simulated driver of demo mode: one call is one step. Returns whether it should be called again.
// A transfer of the auth database ends with a row count that differs, so the mismatch table can be seen.
pub fn demo_step(state: &mut TransferState) -> bool {
    match state.phase {
        TransferPhase::Pending => state.phase = TransferPhase::Freezing,
        TransferPhase::Freezing => state.phase = TransferPhase::Dumping,
        TransferPhase::Dumping => {
            state.bytes_total = DEMO_TRANSFER_BYTES;
            state.phase = TransferPhase::Streaming;
        }
        TransferPhase::Streaming => {
            state.bytes_done = (state.bytes_done + state.bytes_total / 4).min(state.bytes_total);
            if state.bytes_done >= state.bytes_total {
                state.phase = TransferPhase::Restoring;
            }
        }
        TransferPhase::Restoring => {
            state.mismatches = if state.plan.database.ends_with("auth") {
                vec![CountDiff {
                    schema: "public".into(),
                    table: "sessions".into(),
                    source: Some(120),
                    target: Some(118),
                }]
            } else {
                Vec::new()
            };
            state.counts_match = Some(state.mismatches.is_empty());
            state.phase = TransferPhase::Verifying;
        }
        _ => {}
    }
    !(state.phase.is_finished()
        || state.phase == TransferPhase::Failed
        || state.awaiting_operator())
}

// Demo cutover and rollback follow the driver's rules: a cutover needs equal counts, a finished transfer stays as it is.
pub fn demo_cutover(state: &mut TransferState) -> Result<(), String> {
    if state.phase.is_finished() {
        return Ok(());
    }
    if let Some(reason) = cutover_block(state) {
        return Err(reason.to_string());
    }
    state.phase = TransferPhase::Done;
    state.error = None;
    Ok(())
}

pub fn demo_rollback(state: &mut TransferState) {
    if !state.phase.is_finished() {
        state.phase = TransferPhase::RolledBack;
        state.error = None;
    }
}

pub fn convert_to_label(to: PgMode) -> &'static str {
    match to {
        PgMode::Dedicated => "Convert to a dedicated database",
        PgMode::Shared => "Convert to the shared instance",
    }
}

pub fn other_mode(mode: PgMode) -> PgMode {
    match mode {
        PgMode::Dedicated => PgMode::Shared,
        PgMode::Shared => PgMode::Dedicated,
    }
}

pub fn session_state_label(state: SessionState) -> &'static str {
    match state {
        SessionState::Pending => "Waiting",
        SessionState::Freezing => "Freezing the site",
        SessionState::Dumping => "Dumping",
        SessionState::Ready => "Ready",
        SessionState::Receiving => "Receiving",
        SessionState::Restoring => "Restoring",
        SessionState::Verifying => "Verifying",
        SessionState::AwaitingCutover => "Waiting for you to cut over",
        SessionState::Cutover => "Cutting over",
        SessionState::Done => "Done",
        SessionState::Failed => "Failed",
        SessionState::RolledBack => "Aborted",
    }
}

pub fn session_tone(state: SessionState) -> Tone {
    match state {
        SessionState::Done => Tone::Ok,
        SessionState::Failed => Tone::Bad,
        SessionState::RolledBack => Tone::Muted,
        SessionState::AwaitingCutover => Tone::Warn,
        _ => Tone::Info,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConvertAction {
    Cutover,
    Abort,
}

pub fn convert_actions(session: &Session) -> Vec<ConvertAction> {
    match session.state {
        SessionState::AwaitingCutover => vec![ConvertAction::Cutover, ConvertAction::Abort],
        SessionState::Failed => vec![ConvertAction::Abort],
        _ => Vec::new(),
    }
}

// A conversion is read again while it works; it waits for the operator at AwaitingCutover and is over at a terminal state.
pub fn session_working(session: &Session) -> bool {
    !session.state.is_terminal() && session.state != SessionState::AwaitingCutover
}

pub fn convert_mismatches(session: &Session) -> Vec<CountDiff> {
    match (&session.counts, &session.peer_counts) {
        (Some(a), Some(b)) => compare_counts(a, b),
        _ => Vec::new(),
    }
}

pub fn count_rows(counts: &[TableCount]) -> u64 {
    counts.iter().map(|c| c.rows).sum()
}

pub fn retired_text(r: &RetiredPostgres) -> String {
    format!(
        "The previous {} database (Postgres {}) from {} is kept, frozen, until you delete it.",
        match r.mode {
            PgMode::Dedicated => "dedicated",
            PgMode::Shared => "shared",
        },
        r.major,
        r.since
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cite_edge::datawire::{
        LocalCopy, PgDatabaseView, PgView, PruneKeep, PrunePlanView, S3CopyInfo,
        TenantDatabaseView, TenantView,
    };

    fn plan(db: &str) -> TransferPlan {
        transfer_plan(
            "edge-fra",
            "edge-iad",
            "docs",
            db,
            Freeze::Maintenance,
            false,
            false,
            false,
        )
        .expect("plan")
    }

    fn state_at(db: &str, phase: TransferPhase) -> TransferState {
        let mut s = TransferState::new(plan(db)).expect("state");
        s.phase = phase;
        s
    }

    #[test]
    fn a_plan_is_checked_and_names_the_database_as_pg() {
        assert_eq!(plan("app").database, "pg:app");
        assert!(
            transfer_plan(
                "a",
                "a",
                "docs",
                "app",
                Freeze::Maintenance,
                false,
                false,
                false
            )
            .unwrap_err()
            .contains("different nodes")
        );
        assert!(
            transfer_plan(
                "a",
                "",
                "docs",
                "app",
                Freeze::Maintenance,
                false,
                false,
                false
            )
            .is_err()
        );
        assert!(
            transfer_plan(
                "a",
                "b",
                "docs",
                "App",
                Freeze::Maintenance,
                false,
                false,
                false
            )
            .is_err()
        );
        let nodes = vec![
            crate::targets::NodeInfo {
                name: "edge-fra".into(),
                online: true,
            },
            crate::targets::NodeInfo {
                name: "edge-iad".into(),
                online: true,
            },
            crate::targets::NodeInfo {
                name: "edge-ams".into(),
                online: false,
            },
        ];
        assert_eq!(target_candidates(&nodes, "edge-fra"), ["edge-iad"]);
    }

    #[test]
    fn the_freeze_choices_say_what_happens_to_the_site() {
        assert_eq!(FREEZES, [Freeze::Maintenance, Freeze::ReadOnly]);
        assert!(freeze_text(Freeze::Maintenance).contains("maintenance page"));
        let read_only = freeze_text(Freeze::ReadOnly);
        assert!(read_only.contains("stays up") && read_only.contains("refuses writes"));
        assert_eq!(freeze_label(Freeze::ReadOnly), "Read-only");
        assert!(SOURCE_KEPT_NOTE.contains("never deletes the source"));
    }

    #[test]
    fn progress_reads_as_bytes_and_a_percentage() {
        assert_eq!(progress_text(0, 0), "Size not known yet");
        assert_eq!(
            progress_text(12 * 1024 * 1024, 48 * 1024 * 1024),
            "12.0 MB of 48.0 MB (25%)"
        );
        assert_eq!(progress_fraction(5, 0), 0.0);
        assert_eq!(progress_fraction(9, 3), 1.0);
        assert_eq!(phase_label(TransferPhase::Streaming), "Copying");
        assert_eq!(phase_tone(TransferPhase::Failed), Tone::Bad);
        assert_eq!(phase_tone(TransferPhase::Done), Tone::Ok);
        assert!(
            transfer_title(&state_at("app", TransferPhase::Pending))
                .contains("pg:app of docs: edge-fra to edge-iad")
        );
    }

    #[test]
    fn a_count_difference_reads_per_table() {
        let d = |s, t| CountDiff {
            schema: "public".into(),
            table: "orders".into(),
            source: s,
            target: t,
        };
        assert_eq!(
            mismatch_text(&d(Some(5), Some(4))),
            "public.orders: 5 rows on the source, 4 on the target"
        );
        assert!(mismatch_text(&d(Some(5), None)).contains("missing on the target"));
        assert!(mismatch_text(&d(None, Some(2))).contains("not on the source"));
    }

    #[test]
    fn the_operator_is_offered_what_the_phase_allows() {
        let running = state_at("app", TransferPhase::Streaming);
        assert_eq!(xfer_actions(&running, true), [XferAction::Cancel]);
        assert_eq!(
            xfer_actions(&running, false),
            [XferAction::Resume, XferAction::Rollback]
        );
        assert_eq!(
            xfer_actions(&state_at("app", TransferPhase::Failed), false),
            [XferAction::Resume, XferAction::Rollback]
        );
        assert_eq!(
            xfer_actions(&state_at("app", TransferPhase::Done), false),
            [XferAction::Forget]
        );
        assert_eq!(
            xfer_actions(&state_at("app", TransferPhase::RolledBack), false),
            [XferAction::Forget]
        );
        assert_eq!(
            xfer_actions(&state_at("app", TransferPhase::Cutover), false),
            [XferAction::Resume]
        );
        let mut waiting = state_at("app", TransferPhase::Verifying);
        assert_eq!(
            xfer_actions(&waiting, false),
            [XferAction::Resume, XferAction::Rollback]
        );
        waiting.counts_match = Some(true);
        assert_eq!(
            xfer_actions(&waiting, false),
            [XferAction::Cutover, XferAction::Rollback]
        );
        assert_eq!(cutover_block(&waiting), None);
        waiting.counts_match = Some(false);
        assert!(cutover_block(&waiting).unwrap().contains("differ"));
    }

    #[test]
    fn the_demo_driver_walks_the_phases_and_stops_for_the_operator() {
        let mut s = state_at("app", TransferPhase::Pending);
        let mut seen = vec![s.phase];
        let mut steps = 0;
        while demo_step(&mut s) {
            if seen.last() != Some(&s.phase) {
                seen.push(s.phase);
            }
            steps += 1;
            assert!(steps < 30, "never settles");
        }
        seen.push(s.phase);
        assert!(seen.contains(&TransferPhase::Dumping) && seen.contains(&TransferPhase::Streaming));
        assert_eq!(s.phase, TransferPhase::Verifying);
        assert!(
            s.awaiting_operator() && s.counts_match == Some(true) && s.bytes_done == s.bytes_total
        );
        demo_cutover(&mut s).expect("cutover");
        assert_eq!(s.phase, TransferPhase::Done);
        assert!(!demo_step(&mut s));
    }

    #[test]
    fn the_demo_auth_transfer_ends_with_a_difference_that_blocks_the_cutover() {
        let mut s = state_at("auth", TransferPhase::Pending);
        while demo_step(&mut s) {}
        assert_eq!(s.counts_match, Some(false));
        assert_eq!(s.mismatches.len(), 1);
        assert!(demo_cutover(&mut s).unwrap_err().contains("differ"));
        assert_eq!(s.phase, TransferPhase::Verifying);
        demo_rollback(&mut s);
        assert_eq!(s.phase, TransferPhase::RolledBack);
        demo_rollback(&mut s);
        assert_eq!(s.phase, TransferPhase::RolledBack);
    }

    fn session(state: SessionState) -> Session {
        serde_json::from_value(serde_json::json!({
            "id": "s1", "kind": "convert", "site": "docs", "database": "pg:app",
            "state": state, "created_at": "2026-11-01T00:00:00Z", "updated_at": "2026-11-01T00:00:00Z"
        }))
        .expect("session")
    }

    #[test]
    fn a_conversion_waits_for_the_operator_and_compares_row_counts() {
        assert!(session_working(&session(SessionState::Dumping)));
        assert!(!session_working(&session(SessionState::AwaitingCutover)));
        assert!(!session_working(&session(SessionState::Done)));
        assert!(!session_working(&session(SessionState::Failed)));
        assert_eq!(
            convert_actions(&session(SessionState::AwaitingCutover)),
            [ConvertAction::Cutover, ConvertAction::Abort]
        );
        assert_eq!(
            convert_actions(&session(SessionState::Failed)),
            [ConvertAction::Abort]
        );
        assert!(convert_actions(&session(SessionState::Done)).is_empty());
        let mut s = session(SessionState::AwaitingCutover);
        assert!(convert_mismatches(&s).is_empty());
        let count = |rows| TableCount {
            schema: "public".into(),
            table: "t".into(),
            rows,
        };
        s.counts = Some(vec![count(3)]);
        s.peer_counts = Some(vec![count(2)]);
        assert_eq!(convert_mismatches(&s).len(), 1);
        assert_eq!(count_rows(&[count(3), count(4)]), 7);
        assert_eq!(other_mode(PgMode::Dedicated), PgMode::Shared);
        assert!(convert_to_label(PgMode::Shared).contains("shared"));
        assert_eq!(session_tone(SessionState::AwaitingCutover), Tone::Warn);
        assert_eq!(session_state_label(SessionState::RolledBack), "Aborted");
        let retired = RetiredPostgres {
            mode: PgMode::Dedicated,
            major: 17,
            since: "2026-11-01T00:00:00Z".into(),
        };
        assert!(retired_text(&retired).contains("dedicated database (Postgres 17)"));
    }

    fn caps(list: &[&str]) -> Vec<String> {
        list.iter().map(|c| c.to_string()).collect()
    }

    fn user(name: &str, level: PgLevel) -> PgUserView {
        PgUserView {
            name: name.into(),
            level: Some(level),
            connection_limit: 20,
            ..PgUserView::default()
        }
    }

    fn view_with(databases: Vec<PgDatabaseView>) -> SiteDataView {
        SiteDataView {
            postgres: Some(PgView {
                mode: PgMode::Dedicated,
                major: 18,
                databases,
                ..PgView::default()
            }),
            ..SiteDataView::default()
        }
    }

    fn app_db() -> PgDatabaseView {
        PgDatabaseView {
            name: "app".into(),
            users: vec![
                user("app", PgLevel::Readwrite),
                user("migrate", PgLevel::Owner),
            ],
            size_bytes: Some(1024),
        }
    }

    fn rec(version: u32, db: &str, status: BackupStatus) -> BackupRecord {
        BackupRecord {
            id: format!("ID{version}"),
            database: db.into(),
            version,
            created_at: format!("2026-11-{:02}T10:00:00Z", version),
            completed_at: None,
            trigger: BackupTrigger::Manual,
            label: None,
            pinned: false,
            size_bytes: 10,
            sha256: "0123456789abcdef".into(),
            server_version: "18.1".into(),
            format: "pg_dump-custom".into(),
            encryption: None,
            local: Some(LocalCopy {
                file: "x.cbk".into(),
                stored_bytes: 5,
            }),
            s3: None,
            status,
            error: None,
            actor: String::new(),
            source: None,
        }
    }

    #[test]
    fn the_data_tab_needs_a_data_capability() {
        assert!(!data_tab_offered(&caps(&["volumes", "site-logs"])));
        assert!(!data_tab_offered(&[]));
        assert!(data_tab_offered(&caps(&["data-postgres"])));
        assert!(data_tab_offered(&caps(&["data-external"])));
        assert!(data_tab_offered(&caps(&["data-s3"])));
        assert!(!data_tab_offered(&caps(&["data-backups", "data-links"])));
        assert!(databases_page_offered(&caps(&["data-shared"])));
        assert!(databases_page_offered(&caps(&["data-postgres"])));
        assert!(!databases_page_offered(&caps(&["data-s3"])));
    }

    #[test]
    fn the_mode_follows_what_the_site_has() {
        assert_eq!(current_choice(&SiteDataView::default()), PgChoice::Off);
        assert_eq!(current_choice(&view_with(vec![])), PgChoice::Dedicated);
        let mut shared = view_with(vec![]);
        shared.postgres.as_mut().unwrap().mode = PgMode::Shared;
        assert_eq!(current_choice(&shared), PgChoice::Shared);
        let mut external = SiteDataView::default();
        external.external.push(Default::default());
        assert_eq!(current_choice(&external), PgChoice::External);
        assert_eq!(PgChoice::Shared.mode(), Some(PgMode::Shared));
        assert_eq!(PgChoice::External.mode(), None);
        assert_eq!(TRADEOFFS.len(), 7);
    }

    #[test]
    fn numbers_are_whole_and_in_range() {
        assert_eq!(optional_number("", 1, 5, "x"), Ok(None));
        assert_eq!(optional_number(" 3 ", 1, 5, "x"), Ok(Some(3)));
        assert!(
            optional_number("0", 1, 5, "the limit")
                .unwrap_err()
                .contains("between 1 and 5")
        );
        assert!(
            optional_number("six", 1, 5, "the limit")
                .unwrap_err()
                .contains("whole number")
        );
        assert!(optional_number("-1", 1, 5, "the limit").is_err());
        assert!(optional_number("99999999999999", 1, 5, "the limit").is_err());
        assert!(
            required_number("", 1, 5, "the limit")
                .unwrap_err()
                .contains("Enter the limit")
        );
    }

    #[test]
    fn names_follow_the_nodes_rules() {
        assert_eq!(pg_name_problem("app", "database"), None);
        assert!(pg_name_problem("App", "database").is_some());
        assert!(pg_name_problem("a-b", "user name").is_some());
        assert!(
            pg_name_problem("postgres", "database")
                .unwrap()
                .contains("reserved")
        );
        assert_eq!(pg_name_problem("postgres", "user name"), None);
        assert_eq!(resource_name_problem("auth-secret", "name"), None);
        assert!(resource_name_problem("Auth", "name").is_some());
        assert_eq!(label_problem("before the migration"), None);
        assert!(label_problem(&"x".repeat(101)).is_some());
        assert!(label_problem("a\nb").is_some());
    }

    #[test]
    fn enabling_sends_the_generic_preset_and_the_chosen_major() {
        let req = pg_enable_req(PgMode::Dedicated, 17, "", "").unwrap();
        assert_eq!(req.major, Some(17));
        assert_eq!(req.preset.as_deref(), Some("generic"));
        assert_eq!(req.memory_mb, None);
        let sized = pg_enable_req(PgMode::Dedicated, DEFAULT_MAJOR, "512", "100").unwrap();
        assert_eq!(
            (sized.memory_mb, sized.max_connections),
            (Some(512), Some(100))
        );
        assert!(pg_enable_req(PgMode::Dedicated, 16, "", "").is_err());
        assert!(pg_enable_req(PgMode::Dedicated, 18, "100", "").is_err());
        assert!(pg_enable_req(PgMode::Dedicated, 18, "", "5").is_err());
        let shared = pg_enable_req(PgMode::Shared, 17, "9999999", "x").unwrap();
        assert_eq!(
            (shared.major, shared.memory_mb, shared.max_connections),
            (None, None, None)
        );
    }

    #[test]
    fn users_are_checked_before_they_are_sent() {
        let taken = vec!["app".to_string()];
        let req = user_create_req(" reports ", PgLevel::Readonly, "5", &taken).unwrap();
        assert_eq!(
            (req.name.as_str(), req.connection_limit),
            ("reports", Some(5))
        );
        assert!(
            user_create_req("app", PgLevel::Readwrite, "", &taken)
                .unwrap_err()
                .contains("already exists")
        );
        assert!(user_create_req("Bad", PgLevel::Readwrite, "", &taken).is_err());
        assert!(user_create_req("x", PgLevel::Readwrite, "501", &taken).is_err());
        let full: Vec<String> = (0..MAX_PG_USERS_PER_DATABASE)
            .map(|i| format!("u{i}"))
            .collect();
        assert!(
            user_create_req("more", PgLevel::Readonly, "", &full)
                .unwrap_err()
                .contains("at most")
        );
        assert_eq!(limit_patch("30", 20).unwrap().connection_limit, Some(30));
        assert!(limit_patch("20", 20).unwrap_err().contains("unchanged"));
        assert!(limit_patch("", 20).is_err());
        assert_eq!(disable_patch(true).disabled, Some(true));
        assert!(!disable_patch(false).is_empty());
        let mut retiring = user("a", PgLevel::Owner);
        assert_eq!(user_state(&retiring), ("Active", Tone::Ok));
        retiring.retiring = Some("a".into());
        assert_eq!(user_state(&retiring).0, "Rotating");
        retiring.disabled = true;
        assert_eq!(user_state(&retiring).0, "Disabled");
        assert!(delete_blocked_reason(&[]).is_none());
        assert!(
            delete_blocked_reason(&["DATABASE_URL".to_string()])
                .unwrap()
                .contains("DATABASE_URL")
        );
        assert!(database_create_problem("auth", &["app".to_string()]).is_none());
        assert!(database_create_problem("app", &["app".to_string()]).is_some());
        let four: Vec<String> = (0..MAX_PG_DATABASES).map(|i| format!("d{i}")).collect();
        assert!(
            database_create_problem("fifth", &four)
                .unwrap()
                .contains("at most")
        );
    }

    #[test]
    fn rotating_an_auth_secret_warns_about_sessions() {
        assert!(is_auth_secret("better-auth-secret"));
        assert!(!is_auth_secret("webhook-key"));
        assert!(rotate_secret_text("auth-secret").contains("signs every user out"));
        assert!(!rotate_secret_text("webhook-key").contains("signs every user out"));
        let existing = vec![SecretView {
            name: "taken".into(),
            ..SecretView::default()
        }];
        let ok = secret_create_req("hook", "48", SecretEncoding::Hex, &existing).unwrap();
        assert_eq!(
            (ok.bytes, ok.encoding),
            (Some(48), Some(SecretEncoding::Hex))
        );
        assert!(secret_create_req("taken", "", SecretEncoding::Hex, &existing).is_err());
        assert!(secret_create_req("hook", "8", SecretEncoding::Hex, &existing).is_err());
        assert_eq!(
            secret_create_req("hook", "", SecretEncoding::Hex, &existing)
                .unwrap()
                .bytes,
            None
        );
    }

    #[test]
    fn external_urls_need_one_host_a_user_and_a_database() {
        for ok in [
            "postgres://u:p@db.example.com/app",
            "postgresql://u:p@db.example.com:5433/app?sslmode=require",
            "POSTGRES://u@h/d",
        ] {
            assert_eq!(external_url_problem(ok), None, "{ok}");
        }
        for (bad, word) in [
            ("", "Enter"),
            ("mysql://u:p@h/d", "must start"),
            ("postgres://h/d", "user name"),
            ("postgres://:p@h/d", "user name"),
            ("postgres://u:p@h1,h2/d", "one host"),
            ("postgres://u:p@/d", "one host"),
            ("postgres://u:p@h", "database name"),
            ("postgres://u:p@h/?sslmode=require", "database name"),
            ("postgres://u:p@h/d x", "space"),
        ] {
            let got = external_url_problem(bad).unwrap_or_else(|| panic!("{bad} passed"));
            assert!(got.contains(word), "{bad}: {got}");
        }
        assert!(external_url_problem(&format!("postgres://u:p@h/{}", "d".repeat(2048))).is_some());
        assert_eq!(
            external_put_req(" postgres://u:p@h/d ").url,
            "postgres://u:p@h/d"
        );
    }

    #[test]
    fn s3_attachments_and_targets_keep_their_keys_write_only() {
        let mut f = S3Form {
            name: "assets".into(),
            endpoint: "http://minio.local:9000".into(),
            bucket: "b".into(),
            region: "us-east-1".into(),
            access_key_id: "id".into(),
            secret_access_key: "secret".into(),
            ..S3Form::default()
        };
        assert_eq!(s3_problem(&f, false), None);
        // A target must be https; an attachment may be http.
        assert!(target_problem(&f, false).unwrap().contains("https"));
        f.endpoint = "https://s3.example.com".into();
        assert_eq!(target_problem(&f, false), None);
        f.secret_access_key.clear();
        assert!(s3_problem(&f, false).unwrap().contains("both"));
        // With stored keys, one key alone is refused and none keeps them.
        assert!(s3_problem(&f, true).unwrap().contains("both keys"));
        f.access_key_id.clear();
        assert_eq!(s3_problem(&f, true), None);
        let req = s3_put_req(&f);
        assert!(req.access_key_id.is_none() && req.secret_access_key.is_none());
        f.name = "Bad".into();
        assert!(s3_problem(&f, true).is_some());
        f.secret_access_key = "s".into();
        f.access_key_id = "i".into();
        f.wipe();
        assert!(f.access_key_id.is_empty() && f.secret_access_key.is_empty());
        let t = S3Form {
            name: "offsite".into(),
            endpoint: "https://s3.example.com".into(),
            bucket: "b".into(),
            region: "r".into(),
            prefix: " cite ".into(),
            encrypt: true,
            ..S3Form::default()
        };
        let req = target_req(&t);
        assert_eq!(
            (req.prefix.as_deref(), req.encrypt),
            (Some("cite"), Some(true))
        );
        assert!(
            target_problem(&S3Form::default(), false)
                .unwrap()
                .contains("name")
        );
        assert!(
            target_test_text(&TargetTestResult {
                ok: true,
                error: None
            })
            .contains("reached")
        );
        assert!(
            target_test_text(&TargetTestResult {
                ok: false,
                error: Some("denied".into())
            })
            .contains("denied")
        );
        assert!(target_test_text(&TargetTestResult::default()).contains("did not say why"));
    }

    #[test]
    fn links_read_as_linked_from_with_a_fallback_label() {
        let link = |var: &str, target, label: &str| LinkView {
            var: var.into(),
            target,
            source: pg_source("app", "app", PgField::Url),
            label: label.into(),
            shadows_doppler: false,
        };
        let links = vec![
            link("DATABASE_URL", LinkTarget::Runtime, "postgres app/app url"),
            link("MIGRATION_DATABASE_URL", LinkTarget::Build, ""),
            link(
                "DATABASE_URL",
                LinkTarget::Build,
                "postgres app/migrate url",
            ),
        ];
        let runtime = linked_rows(&links, LinkTarget::Runtime);
        assert_eq!(runtime.len(), 1);
        assert_eq!(runtime[0].text, "linked from postgres app/app url");
        let build = linked_rows(&links, LinkTarget::Build);
        assert_eq!(
            build.iter().map(|r| r.var.as_str()).collect::<Vec<_>>(),
            ["DATABASE_URL", "MIGRATION_DATABASE_URL"]
        );
        assert_eq!(build[1].text, "linked from postgres app/app url");
        assert_eq!(link_rows(&links)[0].var, "DATABASE_URL");
        assert_eq!(source_label(&LinkSource::SiteUrl), "site url");
        assert_eq!(
            source_label(&LinkSource::Secret { name: "k".into() }),
            "secret k"
        );
        assert_eq!(target_label(LinkTarget::Build), "Build");
    }

    #[test]
    fn conflicts_are_explained_and_override_names_what_it_deletes() {
        let manual = LinkConflict {
            var: "DATABASE_URL".into(),
            target: LinkTarget::Runtime,
            set_by: ConflictSetBy::Manual,
        };
        let linked = LinkConflict {
            var: "DIRECT_URL".into(),
            target: LinkTarget::Build,
            set_by: ConflictSetBy::Link,
        };
        let lines = conflict_lines(&[manual.clone(), linked.clone()]);
        assert_eq!(lines[0], "DATABASE_URL (runtime) is set by hand");
        assert_eq!(lines[1], "DIRECT_URL (build) is set by another link");
        let text = conflict_summary(&[manual, linked]);
        assert!(text.contains("deletes the manual value of DATABASE_URL (runtime)"));
        assert!(text.contains("DIRECT_URL (build) already linked elsewhere"));
        assert_eq!(conflict_summary(&[]), "");
    }

    #[test]
    fn each_preset_creates_the_links_of_the_node_table() {
        let o = PresetOpts::default();
        let vars = |p: Preset, t: LinkTarget| -> Vec<&'static str> {
            preset_spec(p, &o)
                .links
                .iter()
                .filter(|l| l.target == t)
                .map(|l| l.var)
                .collect()
        };
        assert_eq!(vars(Preset::Generic, LinkTarget::Runtime).len(), 7);
        assert_eq!(
            vars(Preset::Generic, LinkTarget::Build),
            ["MIGRATION_DATABASE_URL"]
        );
        assert_eq!(vars(Preset::Prisma, LinkTarget::Runtime), ["DATABASE_URL"]);
        assert_eq!(
            vars(Preset::Prisma, LinkTarget::Build),
            ["DATABASE_URL", "DIRECT_URL"]
        );
        assert_eq!(vars(Preset::Drizzle, LinkTarget::Build), ["DATABASE_URL"]);
        assert_eq!(
            vars(Preset::Authjs, LinkTarget::Runtime),
            ["AUTH_SECRET", "AUTH_DATABASE_URL"]
        );
        assert_eq!(
            vars(Preset::Authjs, LinkTarget::Build),
            ["AUTH_MIGRATION_DATABASE_URL"]
        );
        assert_eq!(
            vars(Preset::BetterAuth, LinkTarget::Runtime),
            ["BETTER_AUTH_SECRET", "BETTER_AUTH_URL", "DATABASE_URL"]
        );
        let auth = preset_spec(Preset::Authjs, &o);
        assert!(auth.users.iter().all(|(db, _, _)| db == "auth"));
        assert_eq!(auth.secrets, ["auth-secret"]);
        // Runtime gets the readwrite user and the build gets the owner.
        let prisma = preset_spec(Preset::Prisma, &o);
        assert_eq!(
            prisma.links[0].source,
            pg_source("app", "app", PgField::Url)
        );
        assert_eq!(
            prisma.links[1].source,
            pg_source("app", "migrate", PgField::Url)
        );
        assert_eq!(PRESETS.len(), Preset::ALL.len());
        assert_eq!(preset_label(Preset::BetterAuth), "Better Auth");
        assert!(preset_summary(Preset::Generic).contains("PG*"));
    }

    #[test]
    fn a_preview_lists_what_is_new_and_what_would_be_shadowed() {
        let o = PresetOpts::default();
        let none: Vec<String> = Vec::new();
        // No Postgres: nothing to apply to.
        let off = preset_preview(Preset::Prisma, &o, &SiteDataView::default(), &none, &none);
        assert!(off.problem.unwrap().contains("Enable Postgres"));
        // An empty instance: the database and both users are created.
        let empty = view_with(vec![]);
        let p = preset_preview(Preset::Prisma, &o, &empty, &none, &none);
        assert_eq!(p.problem, None);
        assert_eq!(p.databases, ["app"]);
        assert_eq!(p.users.len(), 2);
        assert!(p.links.iter().all(|(_, s)| *s == LinkState::New));
        // The default users already exist: nothing is created, links are new.
        let with_users = view_with(vec![app_db()]);
        let p = preset_preview(Preset::Prisma, &o, &with_users, &none, &none);
        assert!(p.databases.is_empty() && p.users.is_empty());
        // A manual DATABASE_URL at runtime must be overridden, and the build one is not in the way.
        let manual = vec!["DATABASE_URL".to_string()];
        let p = preset_preview(Preset::Prisma, &o, &with_users, &manual, &none);
        assert!(p.needs_override());
        assert_eq!(p.conflicts.len(), 1);
        assert_eq!(p.conflicts[0].target, LinkTarget::Runtime);
        assert_eq!(p.conflicts[0].set_by, ConflictSetBy::Manual);
        assert!(
            !preset_preview(Preset::Prisma, &o, &with_users, &none, &manual)
                .conflicts
                .is_empty()
        );
        // Secrets already present are not created again.
        let mut with_secret = with_users.clone();
        with_secret.secrets.push(SecretView {
            name: "better-auth-secret".into(),
            ..SecretView::default()
        });
        let p = preset_preview(Preset::BetterAuth, &o, &with_secret, &none, &none);
        assert!(p.secrets.is_empty());
        let p = preset_preview(Preset::BetterAuth, &o, &with_users, &none, &none);
        assert_eq!(p.secrets, ["better-auth-secret"]);
    }

    #[test]
    fn a_preview_blocks_on_foreign_links_users_of_another_level_and_the_database_limit() {
        let o = PresetOpts::default();
        let none: Vec<String> = Vec::new();
        let mut view = view_with(vec![app_db()]);
        view.links.push(LinkView {
            var: "DATABASE_URL".into(),
            target: LinkTarget::Runtime,
            source: pg_source("app", "migrate", PgField::Url),
            label: "postgres app/migrate url".into(),
            shadows_doppler: false,
        });
        let p = preset_preview(Preset::Prisma, &o, &view, &none, &none);
        assert!(
            p.problem
                .unwrap()
                .contains("already linked from postgres app/migrate url")
        );
        assert_eq!(p.links[0].1, LinkState::Blocked);
        // The same link again is a no-op for that link.
        view.links[0].source = pg_source("app", "app", PgField::Url);
        view.links[0].label.clear();
        let p = preset_preview(Preset::Prisma, &o, &view, &none, &none);
        assert_eq!(p.links[0].1, LinkState::Exists);
        assert!(!p.is_noop());
        // A user of the wrong level cannot be reused.
        let mut wrong = app_db();
        wrong.users[0].level = Some(PgLevel::Readonly);
        let p = preset_preview(Preset::Drizzle, &o, &view_with(vec![wrong]), &none, &none);
        assert!(
            p.problem
                .unwrap()
                .contains("read only but this preset needs read and write")
        );
        // The fifth database is refused.
        let dbs: Vec<PgDatabaseView> = (0..MAX_PG_DATABASES)
            .map(|i| PgDatabaseView {
                name: format!("d{i}"),
                ..PgDatabaseView::default()
            })
            .collect();
        let p = preset_preview(Preset::Prisma, &o, &view_with(dbs), &none, &none);
        assert!(p.problem.unwrap().contains("at most"));
        // Options that break the name rules are refused first.
        let bad = PresetOpts {
            runtime_user: "migrate".into(),
            ..PresetOpts::default()
        };
        assert!(
            preset_options_problem(&bad, Preset::Prisma)
                .unwrap()
                .contains("must differ")
        );
        let bad_auth = PresetOpts {
            auth_database: "Auth".into(),
            ..PresetOpts::default()
        };
        assert!(preset_options_problem(&bad_auth, Preset::Authjs).is_some());
        assert!(preset_options_problem(&bad_auth, Preset::Prisma).is_none());
    }

    #[test]
    fn a_preset_request_carries_the_auth_database_only_for_authjs() {
        let o = PresetOpts::default();
        let req = preset_request(Preset::Authjs, &o, true);
        assert_eq!(req.auth_database.as_deref(), Some("auth"));
        assert!(req.override_manual);
        let req = preset_request(Preset::Prisma, &o, false);
        assert_eq!(req.auth_database, None);
        assert_eq!(
            (
                req.database.as_str(),
                req.runtime_user.as_str(),
                req.migrate_user.as_str()
            ),
            ("app", "app", "migrate")
        );
        let text = spec_link_text(&preset_spec(Preset::Prisma, &o).links[0]);
        assert_eq!(text, "DATABASE_URL (runtime) from postgres app/app url");
        assert_eq!(link_state_text(LinkState::New).0, "new");
    }

    fn draft(kind: LinkKind, var: &str) -> LinkDraft {
        LinkDraft {
            kind,
            database: "app".into(),
            user: "app".into(),
            name: "assets".into(),
            field: "url".into(),
            var: var.into(),
            target: LinkTargetSel::Runtime,
        }
    }

    #[test]
    fn a_custom_link_names_its_source_field_and_variable() {
        let pg = source_from_draft(&draft(LinkKind::Postgres, "DATABASE_URL")).unwrap();
        assert_eq!(pg, pg_source("app", "app", PgField::Url));
        assert_eq!(suggested_var(&pg), "DATABASE_URL");
        let mut d = draft(LinkKind::Postgres, "X");
        d.field = "password".into();
        assert_eq!(suggested_var(&source_from_draft(&d).unwrap()), "PGPASSWORD");
        d.field = "bogus".into();
        assert!(source_from_draft(&d).is_err());
        d.field = "url".into();
        d.user.clear();
        assert!(source_from_draft(&d).unwrap_err().contains("user"));
        // The TLS server name is offered for an external database only.
        assert!(fields_for(LinkKind::External).contains(&"tls_servername"));
        assert!(!fields_for(LinkKind::Postgres).contains(&"tls_servername"));
        assert_eq!(fields_for(LinkKind::S3).len(), 6);
        assert!(fields_for(LinkKind::Secret).is_empty());
        let mut ext = draft(LinkKind::External, "X");
        ext.name = "billing-db".into();
        assert_eq!(
            suggested_var(&source_from_draft(&ext).unwrap()),
            "BILLING_DB_URL"
        );
        let mut s3 = draft(LinkKind::S3, "X");
        s3.field = "bucket".into();
        assert_eq!(suggested_var(&source_from_draft(&s3).unwrap()), "S3_BUCKET");
        let mut secret = draft(LinkKind::Secret, "X");
        secret.name = "auth-secret".into();
        assert_eq!(
            suggested_var(&source_from_draft(&secret).unwrap()),
            "AUTH_SECRET"
        );
        assert_eq!(
            source_from_draft(&draft(LinkKind::SiteUrl, "X")).unwrap(),
            LinkSource::SiteUrl
        );
        assert_eq!(target_sel_label(LinkTargetSel::Both), "Runtime and build");
    }

    #[test]
    fn a_custom_link_is_refused_for_a_bad_name_or_a_variable_another_link_owns() {
        let existing = vec![LinkView {
            var: "DATABASE_URL".into(),
            target: LinkTarget::Runtime,
            source: pg_source("app", "migrate", PgField::Url),
            label: "postgres app/migrate url".into(),
            shadows_doppler: false,
        }];
        assert_eq!(
            link_draft_problem(&draft(LinkKind::Postgres, "APP_URL"), &existing),
            None
        );
        assert!(
            link_draft_problem(&draft(LinkKind::Postgres, "app_url"), &existing)
                .unwrap()
                .contains("capital letters")
        );
        assert!(link_draft_problem(&draft(LinkKind::Postgres, ""), &existing).is_some());
        let clash =
            link_draft_problem(&draft(LinkKind::Postgres, "DATABASE_URL"), &existing).unwrap();
        assert!(clash.contains("already linked from postgres app/migrate url"));
        // The same source again is not a clash, and another target is free.
        let mut same = draft(LinkKind::Postgres, "DATABASE_URL");
        same.user = "migrate".into();
        assert_eq!(link_draft_problem(&same, &existing), None);
        let mut build = draft(LinkKind::Postgres, "DATABASE_URL");
        build.target = LinkTargetSel::Build;
        assert_eq!(link_draft_problem(&build, &existing), None);
        build.target = LinkTargetSel::Both;
        assert!(link_draft_problem(&build, &existing).is_some());
    }

    #[test]
    fn manual_variables_in_the_way_need_an_explicit_override() {
        let d = draft(LinkKind::Postgres, "DATABASE_URL");
        let manual = vec!["DATABASE_URL".to_string()];
        let none: Vec<String> = Vec::new();
        let found = manual_link_conflicts(&d, &[], &manual, &none);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].set_by, ConflictSetBy::Manual);
        assert!(can_override(&found));
        assert!(manual_link_conflicts(&d, &[], &none, &manual).is_empty());
        let mut both = d.clone();
        both.target = LinkTargetSel::Both;
        assert_eq!(manual_link_conflicts(&both, &[], &manual, &manual).len(), 2);
        // A link that already owns the variable is not a manual conflict.
        let owned = vec![LinkView {
            var: "DATABASE_URL".into(),
            target: LinkTarget::Runtime,
            source: pg_source("app", "app", PgField::Url),
            label: String::new(),
            shadows_doppler: false,
        }];
        assert!(manual_link_conflicts(&d, &owned, &manual, &none).is_empty());
        // Override never replaces another link.
        let by_link = vec![LinkConflict {
            var: "X".into(),
            target: LinkTarget::Build,
            set_by: ConflictSetBy::Link,
        }];
        assert!(!can_override(&by_link) && !can_override(&[]));
        let req = link_request(&d, pg_source("app", "app", PgField::Url), true);
        assert!(req.override_manual);
        assert_eq!(req.links[0].var, "DATABASE_URL");
        assert_eq!(req.links[0].target, LinkTargetSel::Runtime);
    }

    #[test]
    fn backup_rows_are_newest_first_and_per_database() {
        let records = vec![
            rec(1, "pg:app", BackupStatus::Ok),
            rec(3, "pg:app", BackupStatus::Ok),
            rec(2, "pg:auth", BackupStatus::Ok),
        ];
        let app = backup_rows(&records, Some("pg:app"));
        assert_eq!(app.iter().map(|r| r.version).collect::<Vec<_>>(), [3, 1]);
        assert_eq!(backup_rows(&records, None).len(), 3);
        assert_eq!(backup_rows(&records, Some("ext:x")).len(), 0);
        let mut view = view_with(vec![app_db()]);
        view.external.push(cite_edge::datawire::ExternalView {
            name: "billing".into(),
            ..Default::default()
        });
        assert_eq!(backup_databases(&view), ["pg:app", "ext:billing"]);
        assert_eq!(database_name("pg:app"), "app");
        assert_eq!(database_name("ext:billing"), "billing");
        assert_eq!(database_key("app"), "pg:app");
    }

    #[test]
    fn backup_actions_follow_status_location_and_pinning() {
        let ok = rec(1, "pg:app", BackupStatus::Ok);
        assert!(can_download(&ok) && can_restore(&ok));
        assert!(!can_restore(&rec(1, "ext:billing", BackupStatus::Ok)));
        assert!(can_download(&rec(1, "ext:billing", BackupStatus::Ok)));
        assert!(!can_download(&rec(1, "pg:app", BackupStatus::Failed)));
        assert!(!can_download(&rec(1, "pg:app", BackupStatus::Running)));
        let mut gone = ok.clone();
        gone.local = None;
        assert!(!can_download(&gone));
        assert!(can_push(&ok, true) && !can_push(&ok, false));
        let mut on_s3 = ok.clone();
        on_s3.s3 = Some(S3CopyInfo {
            target: "t".into(),
            key: "k".into(),
            etag: None,
            version_id: None,
            uploaded_at: String::new(),
            delete_error: None,
        });
        assert!(!can_push(&on_s3, true));
        assert_eq!(locations(&on_s3), ["node", "s3"]);
        assert!(delete_backup_text(&on_s3).contains("the node and S3"));
        assert!(delete_backup_text(&ok).contains("from the node"));
        assert_eq!(delete_backup_block(&ok), None);
        let mut pinned = ok.clone();
        pinned.pinned = true;
        assert!(delete_backup_block(&pinned).unwrap().contains("Pinned"));
        assert!(delete_backup_block(&rec(1, "pg:app", BackupStatus::Running)).is_some());
    }

    #[test]
    fn a_restore_says_a_backup_is_taken_first() {
        let text = restore_text(&rec(4, "pg:app", BackupStatus::Ok), "shop");
        assert!(text.contains("version 4 of app into shop"));
        assert!(text.contains("A backup of the current data is taken first"));
        assert!(text.contains("connections drop"));
        assert_eq!(trigger_label(BackupTrigger::PreRestore), "Before restore");
        assert_eq!(status_text(BackupStatus::Ok), "Complete");
        assert_eq!(status_tone(BackupStatus::Failed), Tone::Bad);
        assert_eq!(short_sha("0123456789abcdef"), "01234567");
        assert_eq!(short_sha(""), "-");
    }

    #[test]
    fn retention_reads_as_a_sentence_and_round_trips_through_text() {
        let r = BackupRetention::default();
        let text = retention_text(&r);
        assert!(text.starts_with(
            "Keeps every backup from the last 24 hours, the newest of each day for 7 days"
        ));
        assert!(text.ends_with("Pinned versions and the newest complete version are always kept."));
        let none = BackupRetention {
            keep_all_hours: 0,
            daily_days: 0,
            weekly_weeks: 0,
            monthly_months: 0,
            pre_restore_days: 0,
        };
        assert!(retention_text(&none).starts_with("Keeps only the newest version."));
        let one_hour = BackupRetention {
            keep_all_hours: 1,
            ..none.clone()
        };
        assert!(retention_text(&one_hour).starts_with("Keeps every backup from the last 1 hour."));
        assert_eq!(retention_from_texts(&retention_texts(&r)).unwrap(), r);
        let mut texts = retention_texts(&r);
        texts[2] = "261".into();
        assert!(
            retention_from_texts(&texts)
                .unwrap_err()
                .contains("Keep one a week for")
        );
        texts[2] = "".into();
        assert!(retention_from_texts(&texts).is_err());
    }

    #[test]
    fn schedules_read_in_utc() {
        assert_eq!(schedule_text(None), "No scheduled backups.");
        assert_eq!(
            schedule_text(Some(&BackupSchedule {
                every_hours: 24,
                minute: 17
            })),
            "Every day at 00:17 UTC."
        );
        assert!(
            schedule_text(Some(&BackupSchedule {
                every_hours: 6,
                minute: 5
            }))
            .starts_with("Every 6 hours at minute 05")
        );
        assert!(
            schedule_text(Some(&BackupSchedule {
                every_hours: 1,
                minute: 0
            }))
            .starts_with("Every hour at minute 00")
        );
    }

    #[test]
    fn a_policy_draft_round_trips_and_is_validated() {
        let policy = BackupPolicy {
            schedule: Some(BackupSchedule {
                every_hours: 6,
                minute: 30,
            }),
            local: BackupRetention::default(),
            s3: Some(S3Copy {
                target: "offsite".into(),
                retention: BackupRetention {
                    monthly_months: 12,
                    ..BackupRetention::default()
                },
            }),
        };
        let draft = PolicyDraft::from_policy(&policy);
        assert_eq!(draft.to_policy().unwrap(), policy);
        let off = PolicyDraft::from_policy(&BackupPolicy::default());
        assert!(!off.scheduled && off.s3_target.is_none());
        assert_eq!(off.to_policy().unwrap(), BackupPolicy::default());
        let mut bad = draft.clone();
        bad.every_hours = 5;
        assert!(bad.to_policy().unwrap_err().contains("Pick one of"));
        let mut bad = draft.clone();
        bad.minute = "60".into();
        assert!(bad.to_policy().is_err());
        let mut bad = draft.clone();
        bad.local[0] = "9999".into();
        assert!(bad.to_policy().unwrap_err().starts_with("Node copies:"));
        let mut bad = draft;
        bad.s3[1] = "x".into();
        assert!(bad.to_policy().unwrap_err().starts_with("S3 copies:"));
    }

    #[test]
    fn a_prune_preview_counts_and_explains() {
        let records = vec![
            rec(1, "pg:app", BackupStatus::Ok),
            rec(2, "pg:app", BackupStatus::Ok),
        ];
        let preview = PrunePreview {
            database: "pg:app".into(),
            local: PrunePlanView {
                keep: vec![PruneKeep {
                    id: "ID2".into(),
                    reason: "newest".into(),
                }],
                delete: vec!["ID1".into()],
            },
            s3: PrunePlanView::default(),
        };
        assert_eq!(prune_total(std::slice::from_ref(&preview), false), 1);
        assert_eq!(prune_total(std::slice::from_ref(&preview), true), 0);
        assert_eq!(
            prune_summary(std::slice::from_ref(&preview)),
            "Would delete 1 copy on the node."
        );
        assert_eq!(prune_summary(&[]), "Nothing would be deleted.");
        let lines = prune_lines(&preview, &records);
        assert_eq!(
            lines,
            ["app on node: keeps v2 (newest complete version); deletes v1"]
        );
        assert_eq!(keep_reason_text("daily"), "newest of its day");
        assert_eq!(keep_reason_text("odd"), "odd");
    }

    fn view(state: JobState, step: Option<&str>, error: Option<&str>) -> JobView {
        JobView {
            id: "j".into(),
            kind: "backup".into(),
            state,
            step: step.map(str::to_string),
            error: error.map(str::to_string),
            ..JobView::default()
        }
    }

    #[test]
    fn a_job_is_followed_until_it_finishes_or_fails() {
        let mut t = JobTrack::new("j1", "edge-fra", Some("shop"), "Backup", 10);
        assert_eq!(
            apply_job_read(
                &mut t,
                Ok(view(JobState::Running, Some("dumping"), None)),
                12
            ),
            JobUpdate::Running
        );
        assert_eq!(job_step_text(&t), "Backup: dumping");
        assert_eq!(
            apply_job_read(&mut t, Ok(view(JobState::Ok, None, None)), 14),
            JobUpdate::Finished
        );
        assert_eq!(
            apply_job_read(
                &mut t,
                Ok(view(JobState::Failed, None, Some("disk full"))),
                16
            ),
            JobUpdate::Failed("disk full".into())
        );
        assert!(
            matches!(apply_job_read(&mut t, Ok(view(JobState::Failed, None, None)), 16), JobUpdate::Failed(m) if m.contains("without a message"))
        );
        let fresh = JobTrack::new("j2", "n", None, "Restart", 0);
        assert_eq!(job_step_text(&fresh), "Restart: running");
    }

    #[test]
    fn a_job_that_cannot_be_read_ends_the_tracking_after_five_failures() {
        let mut t = JobTrack::new("j1", "n", None, "x", 0);
        for _ in 0..JOB_MAX_FAILED_READS - 1 {
            assert_eq!(
                apply_job_read(&mut t, Err((Some(502), "bad gateway".into())), 2),
                JobUpdate::Running
            );
        }
        // A good read resets the count.
        assert_eq!(
            apply_job_read(&mut t, Ok(view(JobState::Running, None, None)), 4),
            JobUpdate::Running
        );
        assert_eq!(t.failed_reads, 0);
        for _ in 0..JOB_MAX_FAILED_READS - 1 {
            apply_job_read(&mut t, Err((None, "timeout".into())), 6);
        }
        assert_eq!(
            apply_job_read(&mut t, Err((None, "timeout".into())), 6),
            JobUpdate::Failed("timeout".into())
        );
        // A job the node forgot ends at once; a job that runs too long is given up on.
        let mut gone = JobTrack::new("j1", "n", None, "x", 0);
        assert!(
            matches!(apply_job_read(&mut gone, Err((Some(404), "not found".into())), 2), JobUpdate::Failed(m) if m.contains("no longer knows"))
        );
        let mut slow = JobTrack::new("j1", "n", None, "x", 0);
        assert_eq!(
            apply_job_read(
                &mut slow,
                Ok(view(JobState::Running, None, None)),
                JOB_MAX_TICKS
            ),
            JobUpdate::Running
        );
        assert!(
            matches!(apply_job_read(&mut slow, Ok(view(JobState::Running, None, None)), JOB_MAX_TICKS + 1), JobUpdate::Failed(m) if m.contains("30 minutes"))
        );
    }

    #[test]
    fn jobs_are_read_about_once_a_second_and_never_twice_at_once() {
        let mut tracks = vec![
            JobTrack::new("a", "n", None, "x", 0),
            JobTrack::new("b", "n", None, "x", 0),
        ];
        assert_eq!(jobs_due(&tracks, 1), Vec::<usize>::new());
        assert_eq!(jobs_due(&tracks, 2), vec![0, 1]);
        tracks[0].in_flight = true;
        assert_eq!(jobs_due(&tracks, 4), vec![1]);
        assert!(jobs_due(&[], 2).is_empty());
    }

    #[test]
    fn health_text_maps_to_a_tone() {
        assert_eq!(health_tone("healthy"), Tone::Ok);
        assert_eq!(health_tone("running"), Tone::Ok);
        assert_eq!(health_tone("unhealthy"), Tone::Bad);
        assert_eq!(health_tone("starting"), Tone::Warn);
        assert_eq!(health_tone(""), Tone::Muted);
        assert_eq!(health_tone("something"), Tone::Muted);
    }

    #[test]
    fn the_shared_instance_limits_are_validated() {
        let req = shared_req(Some(18), "1024", "1.5", "200").unwrap();
        assert_eq!(
            (req.major, req.memory_mb, req.max_connections),
            (Some(18), 1024, 200)
        );
        assert!((req.cpus - 1.5).abs() < f64::EPSILON);
        assert!(
            shared_req(None, "1024", "1", "200")
                .unwrap()
                .major
                .is_none()
        );
        assert!(shared_req(Some(16), "1024", "1", "200").is_err());
        assert!(shared_req(None, "100", "1", "200").is_err());
        assert!(
            shared_req(None, "1024", "0.1", "200")
                .unwrap_err()
                .contains("CPUs")
        );
        assert!(shared_req(None, "1024", "abc", "200").is_err());
        assert!(shared_req(None, "1024", "65", "200").is_err());
        assert!(shared_req(None, "1024", "1", "5").is_err());
        assert_eq!(cpus_of(1_500_000_000), 1.5);
        assert_eq!(cpus_text(0), "unlimited");
        assert_eq!(cpus_text(2_000_000_000), "2");
        assert!(SHARED_UPDATE_TEXT.contains("tenant"));
    }

    #[test]
    fn deleting_the_shared_instance_is_refused_while_tenants_exist() {
        let mut shared = SharedView::default();
        assert_eq!(shared_delete_block(&shared), None);
        shared.tenants = vec![
            TenantView {
                site: "shop".into(),
                databases: vec![
                    TenantDatabaseView {
                        name: "app".into(),
                        size_bytes: 100,
                    },
                    TenantDatabaseView {
                        name: "auth".into(),
                        size_bytes: 20,
                    },
                ],
            },
            TenantView {
                site: "api".into(),
                databases: vec![],
            },
        ];
        assert!(
            shared_delete_block(&shared)
                .unwrap()
                .starts_with("2 sites still use")
        );
        let rows = tenant_rows(&shared);
        assert_eq!(rows[0].site, "api");
        assert_eq!(rows[1].size_bytes, 120);
        shared.tenants.truncate(1);
        assert!(
            shared_delete_block(&shared)
                .unwrap()
                .starts_with("1 site still use")
        );
    }

    #[test]
    fn orphans_list_what_a_deleted_site_left_behind() {
        let o = OrphanView {
            site: "old".into(),
            dedicated_volume: Some("cite-old-db-data".into()),
            shared_databases: vec!["a".into(), "b".into()],
            backups: 1,
            secrets: 3,
        };
        assert_eq!(
            orphan_text(&o),
            "a dedicated database volume, 2 shared databases, 1 backup, 3 stored secrets"
        );
        assert_eq!(orphan_text(&OrphanView::default()), "nothing left");
    }
}
