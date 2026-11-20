//! Env links: turns a site's stored credentials into the env vars its links name, rewrites external
//! database URLs onto egress forwards, builds the presets and generates random secrets.
//!
//! Everything here is pure. No secret appears in a `Debug` output or in an error string.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, Ipv6Addr};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cite_edge::datamodel::{
    DEFAULT_CONN_LIMIT, EnvLink, GeneratedSecret, LinkSource, LinkTarget, ManagedPostgres, PgField,
    PgLevel, PgUser, RESERVED_PG_DATABASES, S3Attachment, S3Field, SecretEncoding, SiteData,
    is_pg_ident,
};
use cite_edge::datawire::{Preset, PresetRequest};
use cite_edge::validate::{
    MAX_ENV_LINKS, MAX_GENERATED_SECRETS, MAX_PG_DATABASES, MAX_PG_USERS_PER_DATABASE,
};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

use crate::egress::Forward;

/// First listen port of the egress proxy's TCP forwards; see `cite-egress/src/forward.rs:FORWARD_PORTS`.
pub const FORWARD_PORT_BASE: u16 = 15432;
/// Number of forward ports the egress proxy offers.
pub const FORWARD_PORT_COUNT: usize = 8;
/// Longest postgres URL accepted.
pub const MAX_URL_BYTES: usize = 2048;
/// Generated database passwords are 32 random bytes, base64url without padding.
pub const PASSWORD_BYTES: usize = 32;

// ---- percent encoding ----

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// Encodes everything except RFC 3986 unreserved characters; safe for userinfo, path segments and query parts.
pub(crate) fn percent_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input {
        if is_unreserved(b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// None for a malformed escape.
pub(crate) fn percent_decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hi = (*bytes.get(i + 1)? as char).to_digit(16)?;
            let lo = (*bytes.get(i + 2)? as char).to_digit(16)?;
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Some(out)
}

fn decode_text(input: &str, what: &str) -> Result<String, String> {
    let bytes = percent_decode(input)
        .ok_or_else(|| format!("the {what} has a malformed percent escape"))?;
    let text = String::from_utf8(bytes).map_err(|_| format!("the {what} is not valid UTF-8"))?;
    if text.chars().any(char::is_control) {
        return Err(format!("the {what} contains a control character"));
    }
    Ok(text)
}

fn host_for_url(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

// ---- credentials the service hands in ----

/// The active login of one managed user, with its password.
#[derive(Clone)]
pub struct PgCreds {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub user: String,
    pub password: Zeroizing<String>,
    pub sslmode: &'static str,
}

impl fmt::Debug for PgCreds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PgCreds")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("database", &self.database)
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .finish()
    }
}

#[derive(Clone)]
pub struct ExtCreds {
    pub name: String,
    pub url: Zeroizing<String>,
    pub forward_port: u16,
}

impl fmt::Debug for ExtCreds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtCreds")
            .field("name", &self.name)
            .field("url", &"<redacted>")
            .field("forward_port", &self.forward_port)
            .finish()
    }
}

#[derive(Clone)]
pub struct S3Creds {
    pub att: S3Attachment,
    pub access_key_id: String,
    pub secret_access_key: Zeroizing<String>,
}

impl fmt::Debug for S3Creds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3Creds")
            .field("att", &self.att)
            .field("access_key_id", &"<redacted>")
            .field("secret_access_key", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Default)]
pub struct DataBindings {
    pub links: Vec<EnvLink>,
    /// `(database, user)` to the active login and its password.
    pub pg: BTreeMap<(String, String), PgCreds>,
    pub ext: BTreeMap<String, ExtCreds>,
    pub s3: BTreeMap<String, S3Creds>,
    pub secrets: BTreeMap<String, Zeroizing<String>>,
    pub site_url: String,
    pub build_needs_dbnet: bool,
}

impl fmt::Debug for DataBindings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let vars: Vec<String> = self
            .links
            .iter()
            .map(|l| format!("{}:{}", l.target.as_str(), l.var))
            .collect();
        f.debug_struct("DataBindings")
            .field("links", &vars)
            .field("pg", &self.pg.keys().collect::<Vec<_>>())
            .field("ext", &self.ext.keys().collect::<Vec<_>>())
            .field("s3", &self.s3.keys().collect::<Vec<_>>())
            .field("secrets", &self.secrets.keys().collect::<Vec<_>>())
            .field("build_needs_dbnet", &self.build_needs_dbnet)
            .finish()
    }
}

/// Where a target reaches an external database from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbRoute {
    /// The URL as stored.
    Direct,
    /// Through the TCP forward of the site's egress proxy.
    ViaEgressProxy { proxy_host: String },
}

// ---- postgres URLs ----

/// Query keys a connection URL must not carry: they would move the connection somewhere the egress rewrite
/// and the forward cannot see, or read local files.
const REFUSED_QUERY_KEYS: [&str; 15] = [
    "host",
    "hostaddr",
    "port",
    "user",
    "password",
    "dbname",
    "service",
    "passfile",
    "sslpassword",
    "sslcert",
    "sslkey",
    "sslrootcert",
    "sslcrl",
    "sslcrldir",
    "gsslib",
];

#[derive(Clone, PartialEq, Eq)]
pub struct PgUrl {
    /// `postgres` or `postgresql`
    pub scheme: String,
    pub user: String,
    pub password: Zeroizing<String>,
    /// Lowercase; an IPv6 literal without brackets.
    pub host: String,
    pub port: u16,
    pub database: String,
    /// The raw query string as given, kept verbatim on rewrite.
    pub query: Option<String>,
    pub sslmode: Option<String>,
}

impl fmt::Debug for PgUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PgUrl")
            .field("scheme", &self.scheme)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("database", &self.database)
            .field("credentials", &"<redacted>")
            .finish()
    }
}

/// Accepts `postgres://` and `postgresql://` URLs with one host, userinfo and a database.
pub fn parse_postgres_url(url: &str) -> Result<PgUrl, String> {
    if url.len() > MAX_URL_BYTES {
        return Err(format!("the URL is longer than {MAX_URL_BYTES} bytes"));
    }
    if !url.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("the URL must be printable ASCII; percent-encode other characters".into());
    }
    let (scheme, rest) = if let Some(r) = strip_scheme(url, "postgresql://") {
        ("postgresql", r)
    } else if let Some(r) = strip_scheme(url, "postgres://") {
        ("postgres", r)
    } else {
        return Err("the URL must start with postgres:// or postgresql://".into());
    };
    if rest.contains('#') {
        return Err("the URL must not have a fragment".into());
    }
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    let (userinfo, hostport) = authority
        .rsplit_once('@')
        .ok_or("the URL needs credentials: postgres://user:password@host/database")?;
    if hostport.contains(',') {
        return Err("only one host is supported".into());
    }
    let (user_raw, password_raw) = match userinfo.split_once(':') {
        Some((u, p)) => (u, p),
        None => (userinfo, ""),
    };
    let user = decode_text(user_raw, "user name")?;
    if user.is_empty() {
        return Err("the URL needs a user name".into());
    }
    let password = Zeroizing::new(decode_text(password_raw, "password")?);

    let (host_text, port_text) = if let Some(inner) = hostport.strip_prefix('[') {
        let (host, after) = inner.split_once(']').ok_or("the host is malformed")?;
        match after {
            "" => (host, None),
            _ => (
                host,
                Some(after.strip_prefix(':').ok_or("the host is malformed")?),
            ),
        }
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (hostport, None),
        }
    };
    if host_text.is_empty() {
        return Err("the URL needs a host".into());
    }
    if host_text.contains('%') {
        return Err("socket paths and percent-encoded hosts are not supported".into());
    }
    let host = host_text.to_ascii_lowercase();
    if hostport.starts_with('[') {
        host.parse::<Ipv6Addr>()
            .map_err(|_| "the host is not a valid IPv6 address")?;
    } else if host.parse::<IpAddr>().is_err() {
        cite_edge::alerts::check_host(&host)?;
    }
    let port = match port_text {
        None => 5432,
        Some(p) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => p
            .parse::<u16>()
            .ok()
            .filter(|p| *p != 0)
            .ok_or("the port must be 1..=65535")?,
        Some(_) => return Err("the port must be 1..=65535".into()),
    };

    let (path, query) = match tail.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (tail, None),
    };
    let db_raw = path.strip_prefix('/').unwrap_or("");
    if db_raw.is_empty() {
        return Err("the URL needs a database name".into());
    }
    if db_raw.contains('/') {
        return Err("the database name must not contain '/'".into());
    }
    let database = decode_text(db_raw, "database name")?;
    if database.is_empty() || database.len() > 63 {
        return Err("the database name must be 1 to 63 bytes".into());
    }

    let mut sslmode = None;
    let mut kept_query = None;
    if let Some(q) = query.filter(|q| !q.is_empty()) {
        for pair in q.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let key = decode_text(k, "query key")?.to_ascii_lowercase();
            if REFUSED_QUERY_KEYS.contains(&key.as_str()) {
                return Err(format!("the query parameter {key} is not allowed"));
            }
            if key == "sslmode" {
                sslmode = Some(decode_text(v, "sslmode")?);
            }
        }
        kept_query = Some(q.to_string());
    }

    Ok(PgUrl {
        scheme: scheme.to_string(),
        user,
        password,
        host,
        port,
        database,
        query: kept_query,
        sslmode,
    })
}

fn strip_scheme<'a>(url: &'a str, scheme: &str) -> Option<&'a str> {
    let head = url.get(..scheme.len())?;
    head.eq_ignore_ascii_case(scheme)
        .then(|| &url[scheme.len()..])
}

/// The same URL with another host and port; credentials are re-encoded, the query is kept as given.
pub fn rewrite_postgres_url(url: &PgUrl, host: &str, port: u16) -> String {
    let mut out = format!("{}://{}", url.scheme, percent_encode(url.user.as_bytes()));
    if !url.password.is_empty() {
        out.push(':');
        out.push_str(&percent_encode(url.password.as_bytes()));
    }
    out.push('@');
    out.push_str(&host_for_url(host));
    out.push(':');
    out.push_str(&port.to_string());
    out.push('/');
    out.push_str(&percent_encode(url.database.as_bytes()));
    if let Some(q) = &url.query {
        out.push('?');
        out.push_str(q);
    }
    out
}

fn managed_url(c: &PgCreds) -> String {
    format!(
        "postgres://{}:{}@{}:{}/{}?sslmode={}",
        percent_encode(c.user.as_bytes()),
        percent_encode(c.password.as_bytes()),
        host_for_url(&c.host),
        c.port,
        percent_encode(c.database.as_bytes()),
        c.sslmode
    )
}

// ---- rendering ----

fn pg_value(c: &PgCreds, field: PgField) -> Result<String, String> {
    Ok(match field {
        PgField::Url => managed_url(c),
        PgField::Host => c.host.clone(),
        PgField::Port => c.port.to_string(),
        PgField::Database => c.database.clone(),
        PgField::User => c.user.clone(),
        PgField::Password => c.password.to_string(),
        PgField::Sslmode => c.sslmode.to_string(),
        PgField::TlsServername => {
            return Err("tls_servername only applies to external databases".into());
        }
    })
}

fn external_value(c: &ExtCreds, field: PgField, route: &DbRoute) -> Result<String, String> {
    let parsed = parse_postgres_url(&c.url).map_err(|e| {
        format!(
            "the stored URL of external database {} is unusable: {e}",
            c.name
        )
    })?;
    let (host, port) = match route {
        DbRoute::Direct => (parsed.host.clone(), parsed.port),
        DbRoute::ViaEgressProxy { proxy_host } => (proxy_host.clone(), c.forward_port),
    };
    Ok(match field {
        PgField::Url => match route {
            DbRoute::Direct => c.url.to_string(),
            DbRoute::ViaEgressProxy { .. } => rewrite_postgres_url(&parsed, &host, port),
        },
        PgField::Host => host,
        PgField::Port => port.to_string(),
        PgField::Database => parsed.database.clone(),
        PgField::User => parsed.user.clone(),
        PgField::Password => parsed.password.to_string(),
        PgField::Sslmode => parsed
            .sslmode
            .clone()
            .unwrap_or_else(|| "prefer".to_string()),
        PgField::TlsServername => parsed.host.clone(),
    })
}

fn s3_value(c: &S3Creds, field: S3Field) -> String {
    match field {
        S3Field::Endpoint => c.att.endpoint.clone(),
        S3Field::Bucket => c.att.bucket.clone(),
        S3Field::Region => c.att.region.clone(),
        S3Field::AccessKeyId => c.access_key_id.clone(),
        S3Field::SecretAccessKey => c.secret_access_key.to_string(),
        S3Field::PathStyle => c.att.path_style.to_string(),
    }
}

fn link_value(b: &DataBindings, source: &LinkSource, route: &DbRoute) -> Result<String, String> {
    match source {
        LinkSource::Postgres {
            database,
            user,
            field,
        } => {
            let creds =
                b.pg.get(&(database.clone(), user.clone()))
                    .ok_or_else(|| format!("no credentials for postgres user {database}/{user}"))?;
            pg_value(creds, *field)
        }
        LinkSource::External { name, field } => {
            let creds = b
                .ext
                .get(name)
                .ok_or_else(|| format!("no credentials for external database {name}"))?;
            external_value(creds, *field, route)
        }
        LinkSource::S3 { name, field } => {
            let creds =
                b.s3.get(name)
                    .ok_or_else(|| format!("no credentials for s3 attachment {name}"))?;
            Ok(s3_value(creds, *field))
        }
        LinkSource::Secret { name } => b
            .secrets
            .get(name)
            .map(|v| v.to_string())
            .ok_or_else(|| format!("no value for generated secret {name}")),
        LinkSource::SiteUrl => {
            if b.site_url.is_empty() {
                Err("the site has no host to build its URL from".into())
            } else {
                Ok(b.site_url.clone())
            }
        }
    }
}

/// The env vars the links of one target produce.
pub fn render(
    b: &DataBindings,
    target: LinkTarget,
    route: &DbRoute,
) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    for link in b.links.iter().filter(|l| l.target == target) {
        let value = link_value(b, &link.source, route)
            .map_err(|e| format!("{} ({}): {e}", link.var, target.as_str()))?;
        if out.insert(link.var.clone(), value).is_some() {
            return Err(format!(
                "{} is linked twice for {}",
                link.var,
                target.as_str()
            ));
        }
    }
    Ok(out)
}

/// Sorted names of the vars the links of a target own; manual edits of these are refused.
pub fn linked_vars(data: &SiteData, target: LinkTarget) -> Vec<String> {
    let set: BTreeSet<&str> = data
        .links
        .iter()
        .filter(|l| l.target == target)
        .map(|l| l.var.as_str())
        .collect();
    set.into_iter().map(str::to_string).collect()
}

/// True when a build-target link reads from managed Postgres, so the manager must join the site's `dbnet`.
pub fn build_needs_dbnet(data: &SiteData) -> bool {
    data.links
        .iter()
        .any(|l| l.target == LinkTarget::Build && matches!(l.source, LinkSource::Postgres { .. }))
}

fn sorted_externals(data: &SiteData) -> Vec<&cite_edge::datamodel::ExternalPostgres> {
    let mut all: Vec<_> = data.external_postgres.iter().collect();
    all.sort_by(|a, b| a.name.cmp(&b.name));
    all
}

/// Forward port of an external attachment: the base port plus its index by sorted name.
pub fn forward_port(data: &SiteData, name: &str) -> Option<u16> {
    sorted_externals(data)
        .iter()
        .take(FORWARD_PORT_COUNT)
        .position(|e| e.name == name)
        .map(|i| FORWARD_PORT_BASE + i as u16)
}

/// One forward per external database, by sorted name.
pub fn egress_forwards(data: &SiteData) -> Vec<Forward> {
    sorted_externals(data)
        .into_iter()
        .take(FORWARD_PORT_COUNT)
        .enumerate()
        .map(|(i, e)| Forward {
            listen: FORWARD_PORT_BASE + i as u16,
            host: e
                .host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string(),
            port: e.port,
        })
        .collect()
}

fn is_ip_text(host: &str) -> bool {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .is_ok()
}

/// Host names of external databases and S3 endpoints; IP literals are not names and are left out.
pub fn auto_allow_hosts(data: &SiteData) -> Vec<String> {
    let mut hosts = BTreeSet::new();
    for e in &data.external_postgres {
        if !is_ip_text(&e.host) {
            hosts.insert(e.host.to_ascii_lowercase());
        }
    }
    for s in &data.s3 {
        if let Ok(ep) = cite_edge::validate::parse_s3_endpoint(&s.endpoint)
            && !is_ip_text(&ep.host)
        {
            hosts.insert(ep.host);
        }
    }
    hosts.into_iter().collect()
}

// ---- random values ----

fn random_bytes(n: usize) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut buf = Zeroizing::new(vec![0u8; n]);
    SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| "the system random source failed".to_string())?;
    Ok(buf)
}

/// 32 bytes from the OS CSPRNG as 43 URL-safe characters.
pub fn generate_password() -> Result<Zeroizing<String>, String> {
    generate_secret(PASSWORD_BYTES as u16, SecretEncoding::Base64url)
}

/// `bytes` random bytes in the given encoding.
pub fn generate_secret(bytes: u16, encoding: SecretEncoding) -> Result<Zeroizing<String>, String> {
    let raw = random_bytes(usize::from(bytes))?;
    let mut out = Zeroizing::new(String::new());
    match encoding {
        SecretEncoding::Base64url => URL_SAFE_NO_PAD.encode_string(&*raw, &mut out),
        SecretEncoding::Hex => {
            out.reserve(raw.len() * 2);
            for b in raw.iter() {
                out.push_str(&format!("{b:02x}"));
            }
        }
    }
    Ok(out)
}

// ---- presets ----

/// What applying a preset adds. Nothing is changed until the service saves it in one update.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PresetPlan {
    pub databases: Vec<String>,
    /// `(database, user)` pairs to create.
    pub users: Vec<(String, PgUser)>,
    pub secrets: Vec<GeneratedSecret>,
    pub links: Vec<EnvLink>,
}

struct Planner<'a> {
    pg: &'a ManagedPostgres,
    plan: PresetPlan,
}

impl Planner<'_> {
    fn ensure_user(&mut self, database: &str, user: &str, level: PgLevel) -> Result<(), String> {
        let existing_db = self.pg.databases.iter().find(|d| d.name == database);
        if existing_db.is_none() && !self.plan.databases.iter().any(|d| d == database) {
            self.plan.databases.push(database.to_string());
        }
        let existing = existing_db.and_then(|d| d.users.iter().find(|u| u.name == user));
        if let Some(u) = existing {
            return if u.level == level {
                Ok(())
            } else {
                Err(format!(
                    "user {database}/{user} is {} but this preset needs {}",
                    u.level.as_str(),
                    level.as_str()
                ))
            };
        }
        if let Some((_, u)) = self
            .plan
            .users
            .iter()
            .find(|(d, u)| d == database && u.name == user)
        {
            return if u.level == level {
                Ok(())
            } else {
                Err(format!(
                    "user {database}/{user} would need two different levels"
                ))
            };
        }
        self.plan.users.push((
            database.to_string(),
            PgUser {
                name: user.to_string(),
                level,
                connection_limit: DEFAULT_CONN_LIMIT,
                statement_timeout_ms: None,
                idle_in_transaction_timeout_ms: None,
                disabled: false,
            },
        ));
        Ok(())
    }

    fn ensure_secret(&mut self, data: &SiteData, name: &str) {
        if !data.secrets.iter().any(|s| s.name == name)
            && !self.plan.secrets.iter().any(|s| s.name == name)
        {
            self.plan.secrets.push(GeneratedSecret {
                name: name.to_string(),
                bytes: cite_edge::datamodel::DEFAULT_SECRET_BYTES,
                encoding: SecretEncoding::Base64url,
                rotated_at: String::new(),
            });
        }
    }

    fn link(
        &mut self,
        data: &SiteData,
        var: &str,
        target: LinkTarget,
        source: LinkSource,
    ) -> Result<(), String> {
        if let Some(existing) = data
            .links
            .iter()
            .find(|l| l.var == var && l.target == target)
        {
            return if existing.source == source {
                Ok(())
            } else {
                Err(format!(
                    "{var} ({}) is already linked to another source; remove that link first",
                    target.as_str()
                ))
            };
        }
        self.plan.links.push(EnvLink {
            var: var.to_string(),
            target,
            source,
        });
        Ok(())
    }
}

fn pg_source(database: &str, user: &str, field: PgField) -> LinkSource {
    LinkSource::Postgres {
        database: database.to_string(),
        user: user.to_string(),
        field,
    }
}

fn or_default<'a>(value: &'a str, default: &'a str) -> &'a str {
    if value.is_empty() { default } else { value }
}

fn check_name(what: &str, name: &str) -> Result<(), String> {
    if !is_pg_ident(name) {
        return Err(format!(
            "{what} {name:?} must be 1 to 16 characters of a-z and 0-9, starting with a letter"
        ));
    }
    Ok(())
}

/// Computes the users, secrets and links a preset needs on top of the site's current data.
pub fn apply_preset(data: &SiteData, req: &PresetRequest) -> Result<PresetPlan, String> {
    let pg = data
        .postgres
        .as_ref()
        .ok_or("managed Postgres is not enabled for this site")?;
    let runtime_user = or_default(&req.runtime_user, "app");
    let migrate_user = or_default(&req.migrate_user, "migrate");
    let main_db = or_default(&req.database, "app");
    check_name("runtime user", runtime_user)?;
    check_name("migrate user", migrate_user)?;
    check_name("database", main_db)?;
    if runtime_user == migrate_user {
        return Err("the runtime user and the migrate user must differ".into());
    }
    let mut p = Planner {
        pg,
        plan: PresetPlan::default(),
    };
    let rt = LinkTarget::Runtime;
    let bd = LinkTarget::Build;

    match req.preset {
        Preset::Generic => {
            p.ensure_user(main_db, runtime_user, PgLevel::Readwrite)?;
            p.ensure_user(main_db, migrate_user, PgLevel::Owner)?;
            for (var, field) in [
                ("DATABASE_URL", PgField::Url),
                ("PGHOST", PgField::Host),
                ("PGPORT", PgField::Port),
                ("PGDATABASE", PgField::Database),
                ("PGUSER", PgField::User),
                ("PGPASSWORD", PgField::Password),
                ("PGSSLMODE", PgField::Sslmode),
            ] {
                p.link(data, var, rt, pg_source(main_db, runtime_user, field))?;
            }
            p.link(
                data,
                "MIGRATION_DATABASE_URL",
                bd,
                pg_source(main_db, migrate_user, PgField::Url),
            )?;
        }
        Preset::Prisma => {
            p.ensure_user(main_db, runtime_user, PgLevel::Readwrite)?;
            p.ensure_user(main_db, migrate_user, PgLevel::Owner)?;
            p.link(
                data,
                "DATABASE_URL",
                rt,
                pg_source(main_db, runtime_user, PgField::Url),
            )?;
            p.link(
                data,
                "DATABASE_URL",
                bd,
                pg_source(main_db, migrate_user, PgField::Url),
            )?;
            p.link(
                data,
                "DIRECT_URL",
                bd,
                pg_source(main_db, migrate_user, PgField::Url),
            )?;
        }
        Preset::Drizzle => {
            p.ensure_user(main_db, runtime_user, PgLevel::Readwrite)?;
            p.ensure_user(main_db, migrate_user, PgLevel::Owner)?;
            p.link(
                data,
                "DATABASE_URL",
                rt,
                pg_source(main_db, runtime_user, PgField::Url),
            )?;
            p.link(
                data,
                "DATABASE_URL",
                bd,
                pg_source(main_db, migrate_user, PgField::Url),
            )?;
        }
        Preset::Authjs => {
            let auth_db = or_default(req.auth_database.as_deref().unwrap_or(""), "auth");
            check_name("auth database", auth_db)?;
            p.ensure_user(auth_db, runtime_user, PgLevel::Readwrite)?;
            p.ensure_user(auth_db, migrate_user, PgLevel::Owner)?;
            p.ensure_secret(data, "auth-secret");
            p.link(
                data,
                "AUTH_SECRET",
                rt,
                LinkSource::Secret {
                    name: "auth-secret".into(),
                },
            )?;
            p.link(
                data,
                "AUTH_DATABASE_URL",
                rt,
                pg_source(auth_db, runtime_user, PgField::Url),
            )?;
            p.link(
                data,
                "AUTH_MIGRATION_DATABASE_URL",
                bd,
                pg_source(auth_db, migrate_user, PgField::Url),
            )?;
        }
        Preset::BetterAuth => {
            p.ensure_user(main_db, runtime_user, PgLevel::Readwrite)?;
            p.ensure_user(main_db, migrate_user, PgLevel::Owner)?;
            p.ensure_secret(data, "better-auth-secret");
            p.link(
                data,
                "BETTER_AUTH_SECRET",
                rt,
                LinkSource::Secret {
                    name: "better-auth-secret".into(),
                },
            )?;
            p.link(data, "BETTER_AUTH_URL", rt, LinkSource::SiteUrl)?;
            p.link(
                data,
                "DATABASE_URL",
                rt,
                pg_source(main_db, runtime_user, PgField::Url),
            )?;
            p.link(
                data,
                "DATABASE_URL",
                bd,
                pg_source(main_db, migrate_user, PgField::Url),
            )?;
        }
    }

    let plan = p.plan;
    for db in &plan.databases {
        if RESERVED_PG_DATABASES.contains(&db.as_str()) {
            return Err(format!("{db} is a reserved database name"));
        }
    }
    if pg.databases.len() + plan.databases.len() > MAX_PG_DATABASES {
        return Err(format!(
            "a site can have at most {MAX_PG_DATABASES} databases"
        ));
    }
    let mut counts: BTreeMap<&str, usize> = pg
        .databases
        .iter()
        .map(|d| (d.name.as_str(), d.users.len()))
        .collect();
    for (db, _) in &plan.users {
        *counts.entry(db.as_str()).or_default() += 1;
    }
    if counts.values().any(|n| *n > MAX_PG_USERS_PER_DATABASE) {
        return Err(format!(
            "a database can have at most {MAX_PG_USERS_PER_DATABASE} users"
        ));
    }
    if data.secrets.len() + plan.secrets.len() > MAX_GENERATED_SECRETS {
        return Err(format!(
            "a site can have at most {MAX_GENERATED_SECRETS} generated secrets"
        ));
    }
    if data.links.len() + plan.links.len() > MAX_ENV_LINKS {
        return Err(format!("a site can have at most {MAX_ENV_LINKS} env links"));
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cite_edge::datamodel::{BackupPolicy, ExternalPostgres, PgDatabase, PgMode};

    fn creds(user: &str, pw: &str) -> PgCreds {
        PgCreds {
            host: "cite-shop-db".into(),
            port: 5432,
            database: "app".into(),
            user: user.into(),
            password: Zeroizing::new(pw.into()),
            sslmode: "disable",
        }
    }

    fn link(var: &str, target: LinkTarget, source: LinkSource) -> EnvLink {
        EnvLink {
            var: var.into(),
            target,
            source,
        }
    }

    fn pgl(field: PgField) -> LinkSource {
        LinkSource::Postgres {
            database: "app".into(),
            user: "app".into(),
            field,
        }
    }

    fn user(name: &str, level: PgLevel) -> PgUser {
        PgUser {
            name: name.into(),
            level,
            connection_limit: 20,
            statement_timeout_ms: None,
            idle_in_transaction_timeout_ms: None,
            disabled: false,
        }
    }

    fn data_with_pg() -> SiteData {
        SiteData {
            postgres: Some(ManagedPostgres {
                mode: PgMode::Dedicated,
                major: 18,
                memory_mb: 512,
                max_connections: 100,
                databases: vec![PgDatabase {
                    name: "app".into(),
                    users: vec![
                        user("app", PgLevel::Readwrite),
                        user("migrate", PgLevel::Owner),
                    ],
                }],
                backup: BackupPolicy::default(),
                tls: false,
                retired: None,
            }),
            ..SiteData::default()
        }
    }

    fn bindings(links: Vec<EnvLink>) -> DataBindings {
        let mut b = DataBindings {
            links,
            site_url: "https://shop.example.com".into(),
            ..DataBindings::default()
        };
        b.pg.insert(
            ("app".into(), "app".into()),
            creds("t0123456789_app_app_a", "pw/with:odd@chars"),
        );
        b.ext.insert(
            "billing".into(),
            ExtCreds {
                name: "billing".into(),
                url: Zeroizing::new(
                    "postgres://bob:p%40ss@Db.Example.com:6543/shop?sslmode=require".into(),
                ),
                forward_port: 15432,
            },
        );
        b.s3.insert(
            "media".into(),
            S3Creds {
                att: S3Attachment {
                    name: "media".into(),
                    endpoint: "https://s3.example.com".into(),
                    bucket: "media-bucket".into(),
                    region: "eu-west-1".into(),
                    path_style: true,
                },
                access_key_id: "AKIDEXAMPLE".into(),
                secret_access_key: Zeroizing::new("s3secret".into()),
            },
        );
        b.secrets
            .insert("auth-secret".into(), Zeroizing::new("abc123".into()));
        b
    }

    #[test]
    fn managed_fields_render_for_every_field() {
        let fields = [
            (PgField::Host, "cite-shop-db"),
            (PgField::Port, "5432"),
            (PgField::Database, "app"),
            (PgField::User, "t0123456789_app_app_a"),
            (PgField::Password, "pw/with:odd@chars"),
            (PgField::Sslmode, "disable"),
        ];
        let links: Vec<EnvLink> = fields
            .iter()
            .map(|(f, _)| link(&format!("V_{}", f.as_str()), LinkTarget::Runtime, pgl(*f)))
            .collect();
        let out = render(&bindings(links), LinkTarget::Runtime, &DbRoute::Direct).unwrap();
        for (f, want) in fields {
            assert_eq!(out[&format!("V_{}", f.as_str())], want);
        }
    }

    #[test]
    fn managed_url_percent_encodes_the_password() {
        let b = bindings(vec![link(
            "DATABASE_URL",
            LinkTarget::Runtime,
            pgl(PgField::Url),
        )]);
        let out = render(&b, LinkTarget::Runtime, &DbRoute::Direct).unwrap();
        assert_eq!(
            out["DATABASE_URL"],
            "postgres://t0123456789_app_app_a:pw%2Fwith%3Aodd%40chars@cite-shop-db:5432/app?sslmode=disable"
        );
        let parsed = parse_postgres_url(&out["DATABASE_URL"]).unwrap();
        assert_eq!(parsed.password.as_str(), "pw/with:odd@chars");
    }

    #[test]
    fn managed_tls_servername_is_refused() {
        let b = bindings(vec![link(
            "X",
            LinkTarget::Runtime,
            pgl(PgField::TlsServername),
        )]);
        let err = render(&b, LinkTarget::Runtime, &DbRoute::Direct).unwrap_err();
        assert!(err.contains("X (runtime)"), "{err}");
    }

    #[test]
    fn render_only_returns_links_of_the_requested_target() {
        let b = bindings(vec![
            link("DATABASE_URL", LinkTarget::Runtime, pgl(PgField::Url)),
            link(
                "MIGRATION_DATABASE_URL",
                LinkTarget::Build,
                pgl(PgField::Url),
            ),
        ]);
        let rt = render(&b, LinkTarget::Runtime, &DbRoute::Direct).unwrap();
        let bd = render(&b, LinkTarget::Build, &DbRoute::Direct).unwrap();
        assert_eq!(rt.keys().collect::<Vec<_>>(), ["DATABASE_URL"]);
        assert_eq!(bd.keys().collect::<Vec<_>>(), ["MIGRATION_DATABASE_URL"]);
    }

    #[test]
    fn external_fields_follow_the_route() {
        let ext = |f| LinkSource::External {
            name: "billing".into(),
            field: f,
        };
        let fields = [
            PgField::Url,
            PgField::Host,
            PgField::Port,
            PgField::Database,
            PgField::User,
            PgField::Password,
            PgField::Sslmode,
            PgField::TlsServername,
        ];
        let links: Vec<EnvLink> = fields
            .iter()
            .map(|f| link(&format!("E_{}", f.as_str()), LinkTarget::Runtime, ext(*f)))
            .collect();
        let b = bindings(links);
        let direct = render(&b, LinkTarget::Runtime, &DbRoute::Direct).unwrap();
        assert_eq!(
            direct["E_url"],
            "postgres://bob:p%40ss@Db.Example.com:6543/shop?sslmode=require"
        );
        assert_eq!(direct["E_host"], "db.example.com");
        assert_eq!(direct["E_port"], "6543");
        assert_eq!(direct["E_database"], "shop");
        assert_eq!(direct["E_user"], "bob");
        assert_eq!(direct["E_password"], "p@ss");
        assert_eq!(direct["E_sslmode"], "require");
        assert_eq!(direct["E_tls_servername"], "db.example.com");

        let route = DbRoute::ViaEgressProxy {
            proxy_host: "cite-shop-blue-egress-proxy".into(),
        };
        let via = render(&b, LinkTarget::Runtime, &route).unwrap();
        assert_eq!(
            via["E_url"],
            "postgres://bob:p%40ss@cite-shop-blue-egress-proxy:15432/shop?sslmode=require"
        );
        assert_eq!(via["E_host"], "cite-shop-blue-egress-proxy");
        assert_eq!(via["E_port"], "15432");
        assert_eq!(via["E_tls_servername"], "db.example.com");
        assert_eq!(via["E_password"], "p@ss");
    }

    #[test]
    fn external_without_sslmode_renders_the_libpq_default() {
        let mut b = bindings(vec![link(
            "S",
            LinkTarget::Build,
            LinkSource::External {
                name: "billing".into(),
                field: PgField::Sslmode,
            },
        )]);
        b.ext.get_mut("billing").unwrap().url =
            Zeroizing::new("postgres://u:p@db.example.com/shop".into());
        assert_eq!(
            render(&b, LinkTarget::Build, &DbRoute::Direct).unwrap()["S"],
            "prefer"
        );
    }

    #[test]
    fn s3_secret_and_site_url_fields_render() {
        let s3 = |f| LinkSource::S3 {
            name: "media".into(),
            field: f,
        };
        let b = bindings(vec![
            link("S3_ENDPOINT", LinkTarget::Runtime, s3(S3Field::Endpoint)),
            link("S3_BUCKET", LinkTarget::Runtime, s3(S3Field::Bucket)),
            link("S3_REGION", LinkTarget::Runtime, s3(S3Field::Region)),
            link("S3_KEY", LinkTarget::Runtime, s3(S3Field::AccessKeyId)),
            link(
                "S3_SECRET",
                LinkTarget::Runtime,
                s3(S3Field::SecretAccessKey),
            ),
            link("S3_PATH", LinkTarget::Runtime, s3(S3Field::PathStyle)),
            link(
                "AUTH_SECRET",
                LinkTarget::Runtime,
                LinkSource::Secret {
                    name: "auth-secret".into(),
                },
            ),
            link("SITE", LinkTarget::Runtime, LinkSource::SiteUrl),
        ]);
        let out = render(&b, LinkTarget::Runtime, &DbRoute::Direct).unwrap();
        assert_eq!(out["S3_ENDPOINT"], "https://s3.example.com");
        assert_eq!(out["S3_BUCKET"], "media-bucket");
        assert_eq!(out["S3_REGION"], "eu-west-1");
        assert_eq!(out["S3_KEY"], "AKIDEXAMPLE");
        assert_eq!(out["S3_SECRET"], "s3secret");
        assert_eq!(out["S3_PATH"], "true");
        assert_eq!(out["AUTH_SECRET"], "abc123");
        assert_eq!(out["SITE"], "https://shop.example.com");
    }

    #[test]
    fn missing_bindings_and_duplicates_are_errors_without_values() {
        let b = DataBindings {
            links: vec![link("A", LinkTarget::Runtime, pgl(PgField::Url))],
            ..DataBindings::default()
        };
        assert!(
            render(&b, LinkTarget::Runtime, &DbRoute::Direct)
                .unwrap_err()
                .contains("A (runtime)")
        );
        let b = bindings(vec![
            link("A", LinkTarget::Runtime, pgl(PgField::Host)),
            link("A", LinkTarget::Runtime, pgl(PgField::Port)),
        ]);
        assert!(
            render(&b, LinkTarget::Runtime, &DbRoute::Direct)
                .unwrap_err()
                .contains("twice")
        );
        let b = DataBindings {
            links: vec![link("U", LinkTarget::Runtime, LinkSource::SiteUrl)],
            ..DataBindings::default()
        };
        assert!(render(&b, LinkTarget::Runtime, &DbRoute::Direct).is_err());
    }

    #[test]
    fn debug_output_never_shows_secrets() {
        let b = bindings(vec![link(
            "DATABASE_URL",
            LinkTarget::Runtime,
            pgl(PgField::Url),
        )]);
        let shown = format!("{b:?}");
        for secret in [
            "pw/with:odd@chars",
            "p%40ss",
            "p@ss",
            "s3secret",
            "abc123",
            "AKIDEXAMPLE",
        ] {
            assert!(!shown.contains(secret), "{secret} leaked: {shown}");
        }
        assert!(shown.contains("DATABASE_URL"));
        let parsed = parse_postgres_url("postgres://bob:hunter2@db.example.com/shop").unwrap();
        assert!(!format!("{parsed:?}").contains("hunter2"));
    }

    #[test]
    fn url_parse_table() {
        let ok = parse_postgres_url("postgresql://u:p@db.example.com/d").unwrap();
        assert_eq!(
            (ok.scheme.as_str(), ok.host.as_str(), ok.port),
            ("postgresql", "db.example.com", 5432)
        );
        assert_eq!(ok.sslmode, None);

        let v6 = parse_postgres_url("postgres://u:p@[2001:db8::1]:6000/d").unwrap();
        assert_eq!((v6.host.as_str(), v6.port), ("2001:db8::1", 6000));
        assert!(rewrite_postgres_url(&v6, "2001:db8::1", 6000).contains("@[2001:db8::1]:6000/"));

        let v4 = parse_postgres_url("postgres://u:p@203.0.113.5/d").unwrap();
        assert_eq!(v4.host, "203.0.113.5");

        let enc = parse_postgres_url("postgres://us%3Aer:p%2F%40%25w@h.example.com/my%2Ddb?sslmode=verify-full&application_name=x").unwrap();
        assert_eq!(enc.user, "us:er");
        assert_eq!(enc.password.as_str(), "p/@%w");
        assert_eq!(enc.database, "my-db");
        assert_eq!(enc.sslmode.as_deref(), Some("verify-full"));

        let no_pw = parse_postgres_url("postgres://u@h.example.com/d").unwrap();
        assert_eq!(
            rewrite_postgres_url(&no_pw, "p", 15432),
            "postgres://u@p:15432/d"
        );
    }

    #[test]
    fn url_parse_refusals() {
        let long = format!("postgres://u:p@h.example.com/{}", "d".repeat(2048));
        let cases: [(&str, &str); 17] = [
            ("mysql://u:p@h.example.com/d", "start with"),
            ("http://u:p@h.example.com/d", "start with"),
            ("postgres://h.example.com/d", "credentials"),
            ("postgres://:p@h.example.com/d", "user name"),
            ("postgres://u:p@h1.example.com,h2.example.com/d", "one host"),
            ("postgres://u:p@%2Fvar%2Frun%2Fpostgresql/d", "socket"),
            ("postgres://u:p@h.example.com/", "database"),
            ("postgres://u:p@h.example.com", "database"),
            ("postgres://u:p@h.example.com/a/b", "'/'"),
            ("postgres://u:p@h.example.com:0/d", "port"),
            ("postgres://u:p@h.example.com:99999/d", "port"),
            (
                "postgres://u:p@h.example.com/d?host=evil.example.com",
                "host",
            ),
            (
                "postgres://u:p@h.example.com/d?HostAddr=10.0.0.1",
                "hostaddr",
            ),
            (
                "postgres://u:p@h.example.com/d?sslkey=/etc/passwd",
                "sslkey",
            ),
            ("postgres://u:p@h.example.com/d#frag", "fragment"),
            ("postgres://u:p@localhost/d", "loopback"),
            (long.as_str(), "longer"),
        ];
        for (url, why) in cases {
            let err = parse_postgres_url(url).unwrap_err();
            assert!(err.contains(why), "{url}: {err}");
            assert!(!err.contains(":p@"), "error leaked credentials: {err}");
        }
        assert!(parse_postgres_url("postgres://u:p@h.example.com/d é").is_err());
        assert!(parse_postgres_url("postgres://u:%zz@h.example.com/d").is_err());
        assert!(parse_postgres_url("postgres://u:p@[::1/d").is_err());
        assert!(parse_postgres_url("postgres://u:p@2130706433.example.5/d").is_err());
    }

    #[test]
    fn rewrite_round_trips_credentials_and_keeps_the_query() {
        let url = "postgres://us%40er:p%3Aw%2Fd@Db.Example.com:6543/shop?sslmode=require&connect_timeout=5";
        let parsed = parse_postgres_url(url).unwrap();
        let rewritten = rewrite_postgres_url(&parsed, "proxy-host", 15433);
        assert_eq!(
            rewritten,
            "postgres://us%40er:p%3Aw%2Fd@proxy-host:15433/shop?sslmode=require&connect_timeout=5"
        );
        let again = parse_postgres_url(&rewritten).unwrap();
        assert_eq!(again.user, "us@er");
        assert_eq!(again.password.as_str(), "p:w/d");
        assert_eq!(again.database, "shop");
    }

    #[test]
    fn percent_helpers_round_trip_all_bytes() {
        let all: Vec<u8> = (0..=255).collect();
        let enc = percent_encode(&all);
        assert!(
            enc.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~%".contains(&b))
        );
        assert_eq!(percent_decode(&enc).unwrap(), all);
        assert_eq!(percent_decode("%4"), None);
        assert_eq!(percent_decode("%zz"), None);
        assert_eq!(percent_encode(b"a b/c"), "a%20b%2Fc");
    }

    fn ext(name: &str, host: &str, port: u16) -> ExternalPostgres {
        ExternalPostgres {
            name: name.into(),
            host: host.into(),
            port,
            database: "d".into(),
            sslmode: None,
        }
    }

    #[test]
    fn forwards_are_sorted_by_name_from_the_base_port() {
        let data = SiteData {
            external_postgres: vec![
                ext("zeta", "z.example.com", 5432),
                ext("alpha", "a.example.com", 6543),
                ext("mid", "2001:db8::5", 5432),
            ],
            ..SiteData::default()
        };
        let f = egress_forwards(&data);
        assert_eq!(
            f,
            vec![
                Forward {
                    listen: 15432,
                    host: "a.example.com".into(),
                    port: 6543
                },
                Forward {
                    listen: 15433,
                    host: "2001:db8::5".into(),
                    port: 5432
                },
                Forward {
                    listen: 15434,
                    host: "z.example.com".into(),
                    port: 5432
                },
            ]
        );
        assert_eq!(forward_port(&data, "alpha"), Some(15432));
        assert_eq!(forward_port(&data, "zeta"), Some(15434));
        assert_eq!(forward_port(&data, "nope"), None);
        assert!(egress_forwards(&SiteData::default()).is_empty());
    }

    #[test]
    fn auto_allow_lists_names_only() {
        let data = SiteData {
            external_postgres: vec![
                ext("a", "DB.example.com", 5432),
                ext("b", "203.0.113.9", 5432),
                ext("c", "2001:db8::5", 5432),
            ],
            s3: vec![
                S3Attachment {
                    name: "m".into(),
                    endpoint: "https://s3.example.com".into(),
                    bucket: "bucket".into(),
                    region: "eu".into(),
                    path_style: false,
                },
                S3Attachment {
                    name: "n".into(),
                    endpoint: "https://203.0.113.20:9000".into(),
                    bucket: "bucket".into(),
                    region: "eu".into(),
                    path_style: true,
                },
            ],
            ..SiteData::default()
        };
        assert_eq!(
            auto_allow_hosts(&data),
            vec!["db.example.com", "s3.example.com"]
        );
    }

    #[test]
    fn linked_vars_are_per_target_sorted_and_unique() {
        let data = SiteData {
            links: vec![
                link("B", LinkTarget::Runtime, LinkSource::SiteUrl),
                link("A", LinkTarget::Runtime, LinkSource::SiteUrl),
                link("A", LinkTarget::Build, LinkSource::SiteUrl),
            ],
            ..SiteData::default()
        };
        assert_eq!(linked_vars(&data, LinkTarget::Runtime), vec!["A", "B"]);
        assert_eq!(linked_vars(&data, LinkTarget::Build), vec!["A"]);
        assert!(!build_needs_dbnet(&data));
        let with_pg = SiteData {
            links: vec![link("M", LinkTarget::Build, pgl(PgField::Url))],
            ..SiteData::default()
        };
        assert!(build_needs_dbnet(&with_pg));
        let runtime_only = SiteData {
            links: vec![link("M", LinkTarget::Runtime, pgl(PgField::Url))],
            ..SiteData::default()
        };
        assert!(!build_needs_dbnet(&runtime_only));
    }

    #[test]
    fn generated_passwords_are_43_url_safe_characters_and_distinct() {
        let a = generate_password().unwrap();
        let b = generate_password().unwrap();
        assert_eq!(a.len(), 43);
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        );
        assert_ne!(a.as_str(), b.as_str());
    }

    #[test]
    fn generated_secrets_follow_bytes_and_encoding() {
        let hex = generate_secret(48, SecretEncoding::Hex).unwrap();
        assert_eq!(hex.len(), 96);
        assert!(
            hex.bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        let b64 = generate_secret(128, SecretEncoding::Base64url).unwrap();
        assert_eq!(b64.len(), 171);
        assert!(!b64.contains('='));
        let decoded = URL_SAFE_NO_PAD.decode(b64.as_bytes()).unwrap();
        assert_eq!(decoded.len(), 128);
    }

    fn req(preset: Preset) -> PresetRequest {
        PresetRequest {
            preset,
            database: "app".into(),
            runtime_user: "app".into(),
            migrate_user: "migrate".into(),
            auth_database: None,
            override_manual: false,
        }
    }

    fn vars(plan: &PresetPlan, target: LinkTarget) -> Vec<String> {
        let mut v: Vec<String> = plan
            .links
            .iter()
            .filter(|l| l.target == target)
            .map(|l| l.var.clone())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn generic_preset_matches_the_documented_links() {
        let mut data = data_with_pg();
        data.postgres.as_mut().unwrap().databases.clear();
        let plan = apply_preset(&data, &req(Preset::Generic)).unwrap();
        assert_eq!(plan.databases, vec!["app"]);
        assert_eq!(plan.users.len(), 2);
        assert_eq!(
            vars(&plan, LinkTarget::Runtime),
            [
                "DATABASE_URL",
                "PGDATABASE",
                "PGHOST",
                "PGPASSWORD",
                "PGPORT",
                "PGSSLMODE",
                "PGUSER"
            ]
        );
        assert_eq!(vars(&plan, LinkTarget::Build), ["MIGRATION_DATABASE_URL"]);
        let build = plan
            .links
            .iter()
            .find(|l| l.target == LinkTarget::Build)
            .unwrap();
        assert_eq!(build.source, pg_source("app", "migrate", PgField::Url));
    }

    #[test]
    fn prisma_and_drizzle_use_the_rw_user_at_runtime_and_the_owner_at_build() {
        let data = data_with_pg();
        let prisma = apply_preset(&data, &req(Preset::Prisma)).unwrap();
        assert!(prisma.users.is_empty() && prisma.databases.is_empty());
        assert_eq!(vars(&prisma, LinkTarget::Runtime), ["DATABASE_URL"]);
        assert_eq!(
            vars(&prisma, LinkTarget::Build),
            ["DATABASE_URL", "DIRECT_URL"]
        );
        let rt = prisma
            .links
            .iter()
            .find(|l| l.target == LinkTarget::Runtime)
            .unwrap();
        assert_eq!(rt.source, pg_source("app", "app", PgField::Url));
        for l in prisma
            .links
            .iter()
            .filter(|l| l.target == LinkTarget::Build)
        {
            assert_eq!(l.source, pg_source("app", "migrate", PgField::Url));
        }
        let drizzle = apply_preset(&data, &req(Preset::Drizzle)).unwrap();
        assert_eq!(vars(&drizzle, LinkTarget::Build), ["DATABASE_URL"]);
        assert_eq!(vars(&drizzle, LinkTarget::Runtime), ["DATABASE_URL"]);
    }

    #[test]
    fn authjs_uses_a_separate_auth_database_and_a_generated_secret() {
        let data = data_with_pg();
        let plan = apply_preset(&data, &req(Preset::Authjs)).unwrap();
        assert_eq!(plan.databases, vec!["auth"]);
        assert_eq!(plan.users.len(), 2);
        assert!(plan.users.iter().all(|(d, _)| d == "auth"));
        assert_eq!(plan.secrets.len(), 1);
        assert_eq!(plan.secrets[0].name, "auth-secret");
        assert_eq!(plan.secrets[0].bytes, 32);
        assert_eq!(plan.secrets[0].encoding, SecretEncoding::Base64url);
        assert_eq!(
            vars(&plan, LinkTarget::Runtime),
            ["AUTH_DATABASE_URL", "AUTH_SECRET"]
        );
        assert_eq!(
            vars(&plan, LinkTarget::Build),
            ["AUTH_MIGRATION_DATABASE_URL"]
        );
        let mut custom = req(Preset::Authjs);
        custom.auth_database = Some("identity".into());
        assert_eq!(
            apply_preset(&data, &custom).unwrap().databases,
            vec!["identity"]
        );
    }

    #[test]
    fn better_auth_links_the_secret_site_url_and_database() {
        let plan = apply_preset(&data_with_pg(), &req(Preset::BetterAuth)).unwrap();
        assert_eq!(
            vars(&plan, LinkTarget::Runtime),
            ["BETTER_AUTH_SECRET", "BETTER_AUTH_URL", "DATABASE_URL"]
        );
        assert_eq!(vars(&plan, LinkTarget::Build), ["DATABASE_URL"]);
        assert_eq!(plan.secrets[0].name, "better-auth-secret");
        assert!(plan.links.iter().any(|l| l.source == LinkSource::SiteUrl));
    }

    #[test]
    fn presets_reuse_existing_links_and_secrets_and_refuse_conflicts() {
        let mut data = data_with_pg();
        let first = apply_preset(&data, &req(Preset::BetterAuth)).unwrap();
        data.links.extend(first.links.clone());
        data.secrets.extend(first.secrets.clone());
        let second = apply_preset(&data, &req(Preset::BetterAuth)).unwrap();
        assert!(second.links.is_empty() && second.secrets.is_empty());

        let mut clash = data_with_pg();
        clash.links.push(link(
            "DATABASE_URL",
            LinkTarget::Runtime,
            pg_source("app", "migrate", PgField::Url),
        ));
        let err = apply_preset(&clash, &req(Preset::Prisma)).unwrap_err();
        assert!(
            err.contains("DATABASE_URL") && err.contains("runtime"),
            "{err}"
        );
    }

    #[test]
    fn preset_refusals() {
        assert!(
            apply_preset(&SiteData::default(), &req(Preset::Generic))
                .unwrap_err()
                .contains("not enabled")
        );
        let data = data_with_pg();
        let mut same = req(Preset::Generic);
        same.migrate_user = "app".into();
        assert!(apply_preset(&data, &same).is_err());
        let mut bad = req(Preset::Generic);
        bad.runtime_user = "Bad-Name".into();
        assert!(apply_preset(&data, &bad).is_err());
        let mut reserved = req(Preset::Generic);
        reserved.database = "postgres".into();
        assert!(
            apply_preset(&data, &reserved)
                .unwrap_err()
                .contains("reserved")
        );
        let mut wrong_level = req(Preset::Generic);
        wrong_level.runtime_user = "migrate".into();
        wrong_level.migrate_user = "other".into();
        assert!(
            apply_preset(&data, &wrong_level)
                .unwrap_err()
                .contains("needs readwrite")
        );
    }

    #[test]
    fn preset_limits_are_enforced() {
        let mut full = data_with_pg();
        for i in 0..3 {
            full.postgres.as_mut().unwrap().databases.push(PgDatabase {
                name: format!("d{i}"),
                users: vec![user("app", PgLevel::Readwrite)],
            });
        }
        let err = apply_preset(&full, &req(Preset::Authjs)).unwrap_err();
        assert!(err.contains("at most 4 databases"), "{err}");

        let mut many_links = data_with_pg();
        for i in 0..MAX_ENV_LINKS {
            many_links.links.push(link(
                &format!("V{i}"),
                LinkTarget::Runtime,
                LinkSource::SiteUrl,
            ));
        }
        assert!(
            apply_preset(&many_links, &req(Preset::Prisma))
                .unwrap_err()
                .contains("env links")
        );
    }
}
