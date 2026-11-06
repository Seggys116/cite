use std::fmt;
use std::io::Read;
use std::net::IpAddr;

use cite_edge::model::{BotPolicy, SiteAccess, TlsMode};

use crate::archive::fmt_day;
use crate::model::parse_rfc3339_ms;
use crate::theme::Tone;

pub const MAX_PEM_BYTES: u64 = 100 * 1024;
pub const SOON_DAYS: i64 = 30;
pub const URGENT_DAYS: i64 = 7;
const MAX_NAME_CHARS: usize = 64;
const COVERS_SHOWN: usize = 3;
const CERT_LABEL: &str = "CERTIFICATE";

pub const FULL_HELP: &str = "Full: Cloudflare and visitors reach this node over HTTPS, so a certificate that covers the host is needed.";
pub const FLEXIBLE_HELP: &str = "Flexible: Cloudflare terminates HTTPS and talks plain HTTP to this node. No certificate is needed here. Use it together with Cloudflare only.";

// The desktop's own view of the node's certificate data, so only api.rs knows the client types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertItem {
    pub id: String,
    pub name: String,
    pub subject: String,
    pub sans: Vec<String>,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub days_left: i64,
    pub fingerprint: String,
    pub key_type: String,
    pub created_at: String,
    pub covers: Vec<String>,
    pub source: String,
    pub warning: Option<String>,
}

pub const MANUAL_NOTE: &str = "Placed by hand on the node: read-only";

// Certificates dropped into the node's directory by hand are listed but the node refuses to change them through the API.
pub fn is_read_only(source: &str, id: &str) -> bool {
    source == "manual" || id.starts_with("file:")
}

impl CertItem {
    pub fn read_only(&self) -> bool {
        is_read_only(&self.source, &self.id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertListing {
    pub items: Vec<CertItem>,
    pub https_port: Option<u16>,
    pub dir_ready: bool,
    pub uncovered_hosts: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangesListing {
    pub source: String,
    pub updated: String,
    pub ranges: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadOutcome {
    pub cert: CertItem,
    pub warning: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expiry {
    Fine,
    Soon,
    Urgent,
    Expired,
}

pub fn classify_expiry(days_left: i64) -> Expiry {
    match days_left {
        d if d < 0 => Expiry::Expired,
        d if d < URGENT_DAYS => Expiry::Urgent,
        d if d < SOON_DAYS => Expiry::Soon,
        _ => Expiry::Fine,
    }
}

impl Expiry {
    pub fn tone(self) -> Tone {
        match self {
            Expiry::Fine => Tone::Muted,
            Expiry::Soon => Tone::Warn,
            Expiry::Urgent | Expiry::Expired => Tone::Bad,
        }
    }
}

fn plural(n: i64, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

pub fn days_text(days_left: i64) -> String {
    match days_left {
        d if d < 0 => format!("expired {} ago", plural(-d, "day", "days")),
        0 => "expires today".to_string(),
        d => format!("{} left", plural(d, "day", "days")),
    }
}

// The node sends RFC 3339 stamps; anything else is shown as received so nothing is hidden.
pub fn date_text(stamp: &str) -> String {
    let stamp = stamp.trim();
    match parse_rfc3339_ms(stamp) {
        Some(ms) => fmt_day(ms),
        None if stamp.is_empty() => "-".to_string(),
        None => stamp.to_string(),
    }
}

pub fn validity_text(not_before: &str, not_after: &str) -> String {
    format!("{} to {}", date_text(not_before), date_text(not_after))
}

pub fn sans_text(sans: &[String]) -> String {
    match sans.len() {
        0 => "no names".to_string(),
        1 => "1 name".to_string(),
        n => format!("{n} names"),
    }
}

pub fn short_fingerprint(fingerprint: &str) -> String {
    let short: String = fingerprint
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(12)
        .collect();
    if short.is_empty() {
        "-".to_string()
    } else {
        short.to_ascii_lowercase()
    }
}

pub fn coverage_text(covers: &[String]) -> String {
    if covers.is_empty() {
        return "covers no site host".to_string();
    }
    let shown = covers
        .iter()
        .take(COVERS_SHOWN)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    match covers.len() - covers.len().min(COVERS_SHOWN) {
        0 => format!("covers {shown}"),
        more => format!("covers {shown} and {more} more"),
    }
}

pub fn uncovered_note(hosts: &[String]) -> Option<String> {
    if hosts.is_empty() {
        return None;
    }
    let noun = if hosts.len() == 1 {
        "host has"
    } else {
        "hosts have"
    };
    Some(format!(
        "{} site {noun} no certificate: {}. Visitors get a certificate warning on HTTPS until one is uploaded.",
        hosts.len(),
        hosts.join(", ")
    ))
}

// A wildcard name matches exactly one label, as in the certificate rules browsers apply.
pub fn host_covered(host: &str, sans: &[String]) -> bool {
    let host = host.trim().to_ascii_lowercase();
    sans.iter().any(|san| {
        let san = san.trim().to_ascii_lowercase();
        match san.strip_prefix("*.") {
            Some(base) => host
                .split_once('.')
                .is_some_and(|(label, rest)| !label.is_empty() && rest == base),
            None => san == host,
        }
    })
}

pub fn covered_hosts(hosts: &[String], sans: &[String]) -> Vec<String> {
    hosts
        .iter()
        .filter(|h| host_covered(h, sans))
        .cloned()
        .collect()
}

fn pem_labels(pem: &str) -> Vec<&str> {
    pem.lines()
        .filter_map(|l| {
            l.trim()
                .strip_prefix("-----BEGIN ")
                .and_then(|r| r.strip_suffix("-----"))
        })
        .collect()
}

fn has_end(pem: &str, label: &str) -> bool {
    let end = format!("-----END {label}-----");
    pem.lines().any(|l| l.trim() == end)
}

fn check_size(pem: &str, what: &str) -> Result<(), String> {
    if pem.len() as u64 > MAX_PEM_BYTES {
        return Err(format!("The {what} is larger than 100 KiB."));
    }
    Ok(())
}

// The client caps the certificate and the key together, so a pair of large fields can fail while each alone passes.
pub fn check_combined_size(certificate: &str, private_key: &str) -> Result<(), String> {
    if (certificate.len() + private_key.len()) as u64 > MAX_PEM_BYTES {
        return Err("The certificate and the private key together are larger than 100 KiB.".into());
    }
    Ok(())
}

// Certificate ids from the node are 26 characters of 0-9 and A-Z (ULIDs).
pub fn valid_cert_id(id: &str) -> bool {
    id.len() == 26
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
}

// Line endings are unified and the text ends with one newline, which is what PEM readers expect.
// Leading whitespace is skipped and trailing whitespace cut in one buffer, so no intermediate copy is left to wipe and the spare capacity holds only whitespace.
pub fn normalize_pem(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 1);
    let mut keep = 0;
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        let ch = if ch == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            '\n'
        } else {
            ch
        };
        if out.is_empty() && ch.is_whitespace() {
            continue;
        }
        out.push(ch);
        if !ch.is_whitespace() {
            keep = out.len();
        }
    }
    out.truncate(keep);
    if !out.is_empty() {
        out.push('\n');
    }
    out
}

fn wipe_bytes(bytes: &mut Vec<u8>) {
    bytes.fill(0);
    std::hint::black_box(&*bytes);
}

pub fn check_certificate_pem(pem: &str) -> Result<(), String> {
    check_size(pem, "certificate")?;
    let labels = pem_labels(pem);
    if labels.is_empty() {
        return Err("The certificate is not PEM text: it has no BEGIN CERTIFICATE line.".into());
    }
    for label in &labels {
        if label.ends_with("PRIVATE KEY") {
            return Err(
                "That is a private key. Put the certificate chain in the certificate field.".into(),
            );
        }
        if *label != CERT_LABEL {
            return Err(format!(
                "The certificate holds an unexpected {label} block. Include only CERTIFICATE blocks."
            ));
        }
        if !has_end(pem, label) {
            return Err("The certificate is cut off: it has no END CERTIFICATE line.".into());
        }
    }
    Ok(())
}

pub fn check_key_pem(pem: &str) -> Result<(), String> {
    check_size(pem, "private key")?;
    if pem.contains("Proc-Type: 4,ENCRYPTED") {
        return Err("The private key is encrypted. Remove the passphrase before uploading.".into());
    }
    let labels = pem_labels(pem);
    let Some(label) = labels.iter().find(|l| l.ends_with("PRIVATE KEY")) else {
        return Err(if labels.contains(&CERT_LABEL) {
            "That is a certificate. Put the private key in the key field.".into()
        } else {
            "The private key is not PEM text: it has no BEGIN PRIVATE KEY line.".into()
        });
    };
    if label.starts_with("ENCRYPTED") {
        return Err("The private key is encrypted. Remove the passphrase before uploading.".into());
    }
    if labels.len() != 1 {
        return Err("Provide exactly one private key and nothing else in the key field.".into());
    }
    if !has_end(pem, label) {
        return Err("The private key is cut off: it has no END PRIVATE KEY line.".into());
    }
    Ok(())
}

// Only regular files are read, and never more than the cap, so a device or a huge file cannot stall the app.
pub fn read_pem_file(path: &str, what: &str) -> Result<String, String> {
    let path = path.trim();
    if path.is_empty() {
        return Err(format!("Enter the path of the {what} file."));
    }
    let meta =
        std::fs::metadata(path).map_err(|e| format!("Cannot read the {what} file {path}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{path} is not a regular file."));
    }
    let too_big = || format!("The {what} file {path} is larger than 100 KiB.");
    if meta.len() > MAX_PEM_BYTES {
        return Err(too_big());
    }
    let file = std::fs::File::open(path)
        .map_err(|e| format!("Cannot read the {what} file {path}: {e}"))?;
    let mut bytes = Vec::new();
    if let Err(e) = file.take(MAX_PEM_BYTES + 1).read_to_end(&mut bytes) {
        wipe_bytes(&mut bytes);
        return Err(format!("Cannot read the {what} file {path}: {e}"));
    }
    if bytes.len() as u64 > MAX_PEM_BYTES {
        wipe_bytes(&mut bytes);
        return Err(too_big());
    }
    String::from_utf8(bytes).map_err(|e| {
        wipe_bytes(&mut e.into_bytes());
        format!("The {what} file {path} is not text.")
    })
}

pub fn validate_cert_name(name: &str) -> Result<String, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("Give the certificate a name.".into());
    }
    if name.chars().count() > MAX_NAME_CHARS {
        return Err(format!(
            "The name is longer than {MAX_NAME_CHARS} characters."
        ));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b' ' | b'.' | b'_' | b'-'))
    {
        return Err(
            "Use letters, digits, spaces, dots, dashes and underscores in the name.".into(),
        );
    }
    if !name.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return Err("The name must start with a letter or a digit.".into());
    }
    if name.contains("-----") {
        return Err("The name cannot contain five dashes in a row.".into());
    }
    Ok(name.to_string())
}

// Holds the key text while the user edits, so Debug never prints it.
#[derive(Clone, Default)]
pub struct UploadForm {
    pub name: String,
    pub files: bool,
    pub cert_text: String,
    pub key_text: String,
    pub cert_path: String,
    pub key_path: String,
}

impl fmt::Debug for UploadForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UploadForm")
            .field("name", &self.name)
            .field("files", &self.files)
            .field("cert_text", &format_args!("{} bytes", self.cert_text.len()))
            .field("key_text", &"[redacted]")
            .field("cert_path", &self.cert_path)
            .field("key_path", &self.key_path)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum Material {
    Text(String),
    Path(String),
}

impl fmt::Debug for Material {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Material::Text(t) => write!(f, "Text([redacted {} bytes])", t.len()),
            Material::Path(p) => write!(f, "Path({p:?})"),
        }
    }
}

// Where the PEM text comes from; files are only read when the plan is loaded on the background task.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadPlan {
    pub name: String,
    pub certificate: Material,
    pub key: Material,
}

#[derive(Clone, PartialEq, Eq)]
pub struct UploadRequest {
    pub name: String,
    pub certificate: String,
    pub private_key: String,
}

impl fmt::Debug for UploadRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UploadRequest")
            .field("name", &self.name)
            .field(
                "certificate",
                &format_args!("{} bytes", self.certificate.len()),
            )
            .field("private_key", &"[redacted]")
            .finish()
    }
}

impl UploadForm {
    pub fn plan(&self) -> Result<UploadPlan, String> {
        let name = validate_cert_name(&self.name)?;
        let (certificate, key) = if self.files {
            (
                Material::Path(self.cert_path.clone()),
                Material::Path(self.key_path.clone()),
            )
        } else {
            if self.cert_text.trim().is_empty() {
                return Err("Paste the certificate chain.".into());
            }
            if self.key_text.trim().is_empty() {
                return Err("Paste the private key.".into());
            }
            (
                Material::Text(self.cert_text.clone()),
                Material::Text(self.key_text.clone()),
            )
        };
        Ok(UploadPlan {
            name,
            certificate,
            key,
        })
    }
}

// Overwrites a string's bytes before it is freed; best effort, since copies the allocator or the OS made are out of reach.
pub fn wipe(text: &mut String) {
    let mut bytes = std::mem::take(text).into_bytes();
    wipe_bytes(&mut bytes);
}

impl Drop for UploadForm {
    fn drop(&mut self) {
        wipe(&mut self.key_text);
    }
}

impl Drop for Material {
    fn drop(&mut self) {
        if let Material::Text(t) = self {
            wipe(t);
        }
    }
}

impl Drop for UploadRequest {
    fn drop(&mut self) {
        wipe(&mut self.private_key);
    }
}

fn resolve(mut material: Material, what: &str) -> Result<String, String> {
    let mut text = match &mut material {
        Material::Text(t) => std::mem::take(t),
        Material::Path(p) => read_pem_file(p, what)?,
    };
    let normalized = normalize_pem(&text);
    wipe(&mut text);
    Ok(normalized)
}

impl UploadPlan {
    pub fn load(self) -> Result<UploadRequest, String> {
        let certificate = resolve(self.certificate, "certificate")?;
        check_certificate_pem(&certificate)?;
        let mut private_key = resolve(self.key, "private key")?;
        let checked = check_key_pem(&private_key)
            .and_then(|()| check_combined_size(&certificate, &private_key));
        if let Err(e) = checked {
            wipe(&mut private_key);
            return Err(e);
        }
        Ok(UploadRequest {
            name: self.name,
            certificate,
            private_key,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClearOn {
    Submit,
    Success,
    Cancel,
    ToFiles,
    ToPaste,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Clears {
    pub name: bool,
    pub cert_text: bool,
    pub key_text: bool,
    pub cert_path: bool,
    pub key_path: bool,
}

// Key material leaves the inputs as soon as it is sent, and whenever the panel closes or changes mode.
pub fn clears_for(on: ClearOn) -> Clears {
    let keys = Clears {
        key_text: true,
        key_path: true,
        ..Clears::default()
    };
    match on {
        ClearOn::Submit => keys,
        ClearOn::Success | ClearOn::Cancel => Clears {
            name: true,
            cert_text: true,
            cert_path: true,
            ..keys
        },
        ClearOn::ToFiles => Clears {
            key_text: true,
            ..Clears::default()
        },
        ClearOn::ToPaste => Clears {
            key_path: true,
            ..Clears::default()
        },
    }
}

// A panel or dialog opened for one node must never act on another, even if a switch slipped past the cleanup.
pub fn ensure_same_node(opened_for: &str, active: Option<&str>) -> Result<(), String> {
    match active {
        Some(node) if node == opened_for => Ok(()),
        _ => Err(
            "The selected node changed since this was opened, so nothing was sent. Open it again for the node you want.".into(),
        ),
    }
}

pub fn delete_message(name: &str, covers: &[String]) -> String {
    let effect = if covers.is_empty() {
        String::new()
    } else {
        format!(
            " Visitors to {} get a certificate warning on HTTPS until another certificate covers them.",
            covers.join(", ")
        )
    };
    format!(
        "Delete {name} from the node?{effect} The stored files are removed and cannot be recovered."
    )
}

pub fn uploaded_text(name: &str, replaced: bool) -> String {
    let verb = if replaced { "replaced" } else { "uploaded" };
    format!("Certificate {name} {verb}.")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CertBusy {
    Idle,
    Upload,
    Replace(String),
    Delete(String),
    Port,
    Ranges,
}

impl CertBusy {
    pub fn is_idle(&self) -> bool {
        *self == CertBusy::Idle
    }

    // What a toast calls the operation when its result arrives after the user has moved elsewhere.
    pub fn noun(&self) -> String {
        match self {
            CertBusy::Idle => "Operation".to_string(),
            CertBusy::Upload => "Certificate upload".to_string(),
            CertBusy::Replace(n) => format!("Certificate {n} replacement"),
            CertBusy::Delete(n) => format!("Certificate {n} deletion"),
            CertBusy::Port => "HTTPS port change".to_string(),
            CertBusy::Ranges => "Cloudflare ranges change".to_string(),
        }
    }

    pub fn label(&self) -> Option<String> {
        match self {
            CertBusy::Idle => None,
            CertBusy::Upload => Some("Uploading the certificate...".into()),
            CertBusy::Replace(n) => Some(format!("Replacing {n}...")),
            CertBusy::Delete(n) => Some(format!("Deleting {n}...")),
            CertBusy::Port => Some("Saving the HTTPS port...".into()),
            CertBusy::Ranges => Some("Saving the Cloudflare ranges...".into()),
        }
    }
}

pub fn parse_port(text: &str) -> Result<u16, String> {
    let t = text.trim();
    let range = "Enter a port number from 1 to 65535.".to_string();
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        return Err(range);
    }
    match t.parse::<u16>() {
        Ok(p) if p > 0 => Ok(p),
        _ => Err(range),
    }
}

fn valid_range(token: &str) -> Result<String, String> {
    let bad = || format!("{token:?} is not a CIDR range such as 203.0.113.0/24 or 2001:db8::/32.");
    let (addr, prefix) = match token.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (token, None),
    };
    let ip: IpAddr = addr.parse().map_err(|_| bad())?;
    let Some(prefix) = prefix else {
        return Ok(ip.to_string());
    };
    if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    let bits: u8 = prefix.parse().map_err(|_| bad())?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    if bits > max {
        return Err(format!("{token:?} has a prefix longer than {max} bits."));
    }
    if bits == 0 {
        return Err(format!(
            "{token:?} matches every address and would switch the Cloudflare restriction off."
        ));
    }
    Ok(format!("{ip}/{bits}"))
}

// One range per line, with commas, blanks and # comments tolerated; repeats are dropped.
pub fn parse_range_list(text: &str) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        let code = line.split('#').next().unwrap_or_default();
        for token in code
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|t| !t.is_empty())
        {
            let range = valid_range(token)?;
            if !out.contains(&range) {
                out.push(range);
            }
        }
    }
    if out.is_empty() {
        return Err("Enter at least one range, or use the built-in list.".into());
    }
    Ok(out)
}

pub fn ranges_text(ranges: &[String]) -> String {
    ranges.join("\n")
}

pub fn source_label(source: &str) -> String {
    match source {
        "builtin" | "built-in" | "default" => "Built-in list".to_string(),
        "custom" => "Custom list".to_string(),
        other => other.to_string(),
    }
}

pub fn is_custom_source(source: &str) -> bool {
    source == "custom"
}

pub fn ranges_summary(listing: &RangesListing) -> String {
    let n = listing.ranges.len() as i64;
    format!(
        "{}, updated {}, {}",
        source_label(&listing.source),
        date_text(&listing.updated),
        plural(n, "range", "ranges")
    )
}

// What the Access card edits; zone_lock only means anything while cloudflare_only is on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AccessDraft {
    pub cloudflare_only: bool,
    pub flexible: bool,
    pub bots: BotPolicy,
    pub zone_lock: bool,
}

impl AccessDraft {
    pub fn from_access(access: &SiteAccess) -> Self {
        Self {
            cloudflare_only: access.cloudflare_only,
            flexible: access.tls == TlsMode::Flexible,
            bots: access.bots,
            zone_lock: access.zone_lock,
        }
    }

    // Turning Cloudflare only off also turns the zone lock off, because the node refuses the pair.
    pub fn set_cloudflare_only(&mut self, on: bool) {
        self.cloudflare_only = on;
        if !on {
            self.zone_lock = false;
        }
    }

    pub fn set_zone_lock(&mut self, on: bool) {
        self.zone_lock = on && self.cloudflare_only;
    }

    pub fn to_access(self) -> SiteAccess {
        SiteAccess {
            cloudflare_only: self.cloudflare_only,
            tls: if self.flexible {
                TlsMode::Flexible
            } else {
                TlsMode::Full
            },
            bots: self.bots,
            zone_lock: self.zone_lock && self.cloudflare_only,
        }
    }
}

// A new secret is only shown when the lock goes from off to on or is rotated by hand.
pub fn zone_newly_enabled(before: &SiteAccess, after: &SiteAccess) -> bool {
    after.zone_lock && !before.zone_lock
}

pub fn bots_label(policy: BotPolicy) -> &'static str {
    match policy {
        BotPolicy::Allow => "Allow all",
        BotPolicy::BlockBad => "Block scrapers and tools",
        BotPolicy::BlockAll => "Block all bots",
    }
}

pub fn bots_help(policy: BotPolicy) -> &'static str {
    match policy {
        BotPolicy::Allow => "Every visitor is served, whatever its user agent says.",
        BotPolicy::BlockBad => {
            "Refuses scrapers, scanners and command-line tools by user agent. Search engines stay allowed."
        }
        BotPolicy::BlockAll => {
            "Refuses every request whose user agent names a bot, including search engines."
        }
    }
}

pub fn bots_warning(policy: BotPolicy) -> Option<&'static str> {
    (policy == BotPolicy::BlockAll).then_some(
        "Blocking all bots also blocks Googlebot and Bingbot, so the site drops out of search results (SEO).",
    )
}

pub const BOTS_NOTE: &str = "Bots are recognised by their User-Agent header, which a scraper can fake, so this is not a security boundary. Blocked requests still appear in analytics.";

pub fn zone_lock_help(cloudflare_only: bool) -> &'static str {
    if cloudflare_only {
        "Refuses requests that lack a secret header set by a Transform Rule in your own Cloudflare zone, so other Cloudflare customers cannot reach this site."
    } else {
        "Needs Only accept traffic from Cloudflare to be on."
    }
}

// Flexible without the Cloudflare restriction leaves plain HTTP reachable by anyone who finds the node.
pub fn flexible_warning(cloudflare_only: bool, flexible: bool) -> Option<&'static str> {
    (flexible && !cloudflare_only).then_some(
        "Flexible without Cloudflare only sends plain HTTP that anyone can reach directly, bypassing Cloudflare. Turn on Only accept traffic from Cloudflare.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{begin_line, cert, key, key_of, key_with_body, pem};

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("cite-desktop-certs-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn form(files: bool) -> UploadForm {
        UploadForm {
            name: " shop ".into(),
            files,
            cert_text: cert(),
            key_text: key(),
            cert_path: String::new(),
            key_path: String::new(),
        }
    }

    #[test]
    fn expiry_levels_follow_thirty_and_seven_days() {
        assert_eq!(classify_expiry(90), Expiry::Fine);
        assert_eq!(classify_expiry(30), Expiry::Fine);
        assert_eq!(classify_expiry(29), Expiry::Soon);
        assert_eq!(classify_expiry(7), Expiry::Soon);
        assert_eq!(classify_expiry(6), Expiry::Urgent);
        assert_eq!(classify_expiry(0), Expiry::Urgent);
        assert_eq!(classify_expiry(-1), Expiry::Expired);
        assert_eq!(Expiry::Fine.tone(), Tone::Muted);
        assert_eq!(Expiry::Soon.tone(), Tone::Warn);
        assert_eq!(Expiry::Urgent.tone(), Tone::Bad);
        assert_eq!(Expiry::Expired.tone(), Tone::Bad);
    }

    #[test]
    fn expiry_text_handles_plurals_and_the_past() {
        assert_eq!(days_text(66), "66 days left");
        assert_eq!(days_text(1), "1 day left");
        assert_eq!(days_text(0), "expires today");
        assert_eq!(days_text(-1), "expired 1 day ago");
        assert_eq!(days_text(-12), "expired 12 days ago");
    }

    #[test]
    fn dates_are_shown_as_days_or_as_received() {
        assert_eq!(date_text("2026-11-05T12:30:00Z"), "2026-11-05");
        assert_eq!(date_text("soon"), "soon");
        assert_eq!(date_text("  "), "-");
    }

    #[test]
    fn validity_spans_two_dates() {
        assert_eq!(
            validity_text("2026-08-01T00:00:00Z", "2027-01-12T00:00:00Z"),
            "2026-08-01 to 2027-01-12"
        );
    }

    #[test]
    fn names_and_fingerprints_are_short() {
        assert_eq!(sans_text(&[]), "no names");
        assert_eq!(sans_text(&["a".into()]), "1 name");
        assert_eq!(sans_text(&["a".into(), "b".into()]), "2 names");
        assert_eq!(
            short_fingerprint("AB:CD:EF:01:23:45:67:89:ab:cd:ef"),
            "abcdef012345"
        );
        assert_eq!(short_fingerprint("zz"), "-");
        assert_eq!(short_fingerprint(""), "-");
    }

    #[test]
    fn coverage_text_lists_a_few_hosts() {
        assert_eq!(coverage_text(&[]), "covers no site host");
        let one = vec!["a.example.com".to_string()];
        assert_eq!(coverage_text(&one), "covers a.example.com");
        let many: Vec<String> = ["a", "b", "c", "d", "e"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(coverage_text(&many), "covers a, b, c and 2 more");
    }

    #[test]
    fn uncovered_hosts_get_a_note() {
        assert_eq!(uncovered_note(&[]), None);
        let one = uncovered_note(&["docs.example.com".into()]).expect("note");
        assert!(one.starts_with("1 site host has no certificate: docs.example.com."));
        let two = uncovered_note(&["a".into(), "b".into()]).expect("note");
        assert!(two.starts_with("2 site hosts have no certificate: a, b."));
    }

    #[test]
    fn wildcards_cover_exactly_one_label() {
        let sans = vec![
            "*.example.com".to_string(),
            "Static.Example.org".to_string(),
        ];
        assert!(host_covered("shop.example.com", &sans));
        assert!(host_covered("SHOP.example.com", &sans));
        assert!(!host_covered("example.com", &sans));
        assert!(!host_covered("a.b.example.com", &sans));
        assert!(host_covered("static.example.org", &sans));
        assert!(!host_covered("other.example.org", &sans));
        let hosts = vec!["shop.example.com".to_string(), "x.test".to_string()];
        assert_eq!(covered_hosts(&hosts, &sans), vec!["shop.example.com"]);
    }

    #[test]
    fn certificate_pem_needs_certificate_blocks_only() {
        assert!(check_certificate_pem(&cert()).is_ok());
        let chain = format!("{0}{0}", cert());
        assert!(check_certificate_pem(&chain).is_ok());
        assert!(
            check_certificate_pem("hello")
                .unwrap_err()
                .contains("not PEM")
        );
        assert!(
            check_certificate_pem(&key())
                .unwrap_err()
                .contains("private key")
        );
        assert!(
            check_certificate_pem(&format!("{}MIIB\n", begin_line("CERTIFICATE")))
                .unwrap_err()
                .contains("cut off")
        );
        assert!(
            check_certificate_pem(&pem("X509 CRL", ""))
                .unwrap_err()
                .contains("unexpected")
        );
    }

    #[test]
    fn key_pem_needs_one_unencrypted_key() {
        assert!(check_key_pem(&key()).is_ok());
        assert!(check_key_pem(&key_of("RSA")).is_ok());
        assert!(check_key_pem(&key_of("EC")).is_ok());
        assert!(check_key_pem(&cert()).unwrap_err().contains("certificate"));
        assert!(check_key_pem("nope").unwrap_err().contains("not PEM"));
        assert!(
            check_key_pem(&key_of("ENCRYPTED"))
                .unwrap_err()
                .contains("encrypted")
        );
        let legacy = key_with_body("Proc-Type: 4,ENCRYPTED\nMIIE");
        assert!(check_key_pem(&legacy).unwrap_err().contains("encrypted"));
        assert!(
            check_key_pem(&format!(
                "{}MIIE\n",
                begin_line(&crate::testkit::key_label(""))
            ))
            .unwrap_err()
            .contains("cut off")
        );
        assert!(
            check_key_pem(&format!("{0}{0}", key()))
                .unwrap_err()
                .contains("exactly one")
        );
    }

    #[test]
    fn pem_text_is_normalized_and_capped() {
        assert_eq!(normalize_pem("  a\r\nb\r\n\r\n"), "a\nb\n");
        assert_eq!(normalize_pem("   "), "");
        assert_eq!(normalize_pem(""), "");
        assert_eq!(normalize_pem("\n\n  a\rb\r\n"), "a\nb\n");
        assert_eq!(normalize_pem("a  b \t\n"), "a  b\n");
        assert_eq!(normalize_pem("\u{e9}\r\n\r\n"), "\u{e9}\n");
        assert_eq!(normalize_pem("one\r\r\ntwo"), "one\n\ntwo\n");
        let big = format!("{}{}", cert(), "A".repeat(MAX_PEM_BYTES as usize));
        assert!(check_certificate_pem(&big).unwrap_err().contains("100 KiB"));
        assert!(
            check_key_pem(&"A".repeat(MAX_PEM_BYTES as usize + 1))
                .unwrap_err()
                .contains("100 KiB")
        );
    }

    #[test]
    fn the_certificate_and_key_are_capped_together() {
        let half = MAX_PEM_BYTES as usize / 2;
        assert!(check_combined_size(&"a".repeat(half), &"b".repeat(half)).is_ok());
        let err = check_combined_size(&"a".repeat(half), &"b".repeat(half + 1)).unwrap_err();
        assert!(err.contains("together") && err.contains("100 KiB"));
        let plan = UploadPlan {
            name: "pair".into(),
            certificate: Material::Text(format!("{}{}\n", cert(), "A".repeat(half))),
            key: Material::Text(format!("{}{}\n", key(), "B".repeat(half))),
        };
        assert!(plan.load().unwrap_err().contains("together"));
    }

    #[test]
    fn certificate_ids_are_26_upper_case_alphanumerics() {
        assert!(valid_cert_id("01JC9ZQ7M3X8V4N2B6T5R0WHYA"));
        for bad in [
            "",
            "c-1",
            "01JC9ZQ7M3X8V4N2B6T5R0WHY",
            "01JC9ZQ7M3X8V4N2B6T5R0WHYAA",
            "01jc9zq7m3x8v4n2b6t5r0whya",
            "0123456789abcdef",
            "../JC9ZQ7M3X8V4N2B6T5R0WH",
        ] {
            assert!(!valid_cert_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn files_are_read_only_when_regular_and_small() {
        let dir = scratch("files");
        let good = dir.join("cert.pem");
        std::fs::write(&good, cert()).expect("write");
        let path = good.to_str().expect("utf8");
        assert_eq!(read_pem_file(path, "certificate").expect("read"), cert());
        assert_eq!(
            read_pem_file(&format!("  {path}  "), "certificate").expect("trim"),
            cert()
        );

        let err = read_pem_file(dir.to_str().expect("utf8"), "certificate").unwrap_err();
        assert!(err.contains("not a regular file"));
        let missing = dir.join("missing.pem");
        assert!(
            read_pem_file(missing.to_str().expect("utf8"), "certificate")
                .unwrap_err()
                .contains("Cannot read")
        );
        assert!(
            read_pem_file("  ", "certificate")
                .unwrap_err()
                .contains("Enter the path")
        );

        let big = dir.join("big.pem");
        std::fs::write(&big, vec![b'a'; MAX_PEM_BYTES as usize + 1]).expect("write");
        assert!(
            read_pem_file(big.to_str().expect("utf8"), "private key")
                .unwrap_err()
                .contains("100 KiB")
        );
        let exact = dir.join("exact.pem");
        std::fs::write(&exact, vec![b'a'; MAX_PEM_BYTES as usize]).expect("write");
        assert!(read_pem_file(exact.to_str().expect("utf8"), "certificate").is_ok());

        let binary = dir.join("binary.pem");
        std::fs::write(&binary, [0xff, 0xfe, 0x00]).expect("write");
        assert!(
            read_pem_file(binary.to_str().expect("utf8"), "certificate")
                .unwrap_err()
                .contains("not text")
        );
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn a_read_error_never_quotes_the_file_content() {
        let dir = scratch("secret");
        let key = dir.join("key.pem");
        std::fs::write(&key, vec![b'k'; MAX_PEM_BYTES as usize + 1]).expect("write");
        let err = read_pem_file(key.to_str().expect("utf8"), "private key").unwrap_err();
        assert!(!err.contains("kkkk"));
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn names_are_trimmed_and_bounded() {
        assert_eq!(validate_cert_name("  shop  "), Ok("shop".to_string()));
        assert!(validate_cert_name("  ").is_err());
        assert!(validate_cert_name(&"x".repeat(65)).is_err());
        assert!(validate_cert_name("a\nb").is_err());
        assert!(validate_cert_name("a/b").is_err());
        assert!(validate_cert_name("My cert_2026-11.x").is_ok());
        assert!(validate_cert_name("é").is_err());
        for bad in [
            "-leading",
            ".dot",
            "_under",
            "-----BEGIN CERTIFICATE-----",
            "ok-----bad",
        ] {
            assert!(validate_cert_name(bad).is_err(), "{bad:?}");
        }
        assert!(validate_cert_name("a----b").is_ok());
        assert!(validate_cert_name(&"x".repeat(64)).is_ok());
    }

    #[test]
    fn a_pasted_form_becomes_a_request() {
        let plan = form(false).plan().expect("plan");
        assert_eq!(plan.name, "shop");
        assert!(matches!(plan.certificate, Material::Text(_)));
        let req = plan.load().expect("load");
        assert_eq!(req.name, "shop");
        assert_eq!(req.certificate, cert());
        assert!(req.private_key == key(), "values differ");
    }

    #[test]
    fn a_file_form_reads_both_files_when_loaded() {
        let dir = scratch("form");
        std::fs::write(dir.join("c.pem"), cert().replace('\n', "\r\n")).expect("write");
        std::fs::write(dir.join("k.pem"), key()).expect("write");
        let mut f = form(true);
        f.cert_path = dir.join("c.pem").to_str().expect("utf8").into();
        f.key_path = dir.join("k.pem").to_str().expect("utf8").into();
        f.cert_text.clear();
        f.key_text.clear();
        let plan = f.plan().expect("plan");
        assert!(matches!(plan.key, Material::Path(_)));
        let req = plan.load().expect("load");
        assert_eq!(req.certificate, cert());
        assert!(req.private_key == key(), "values differ");
        f.key_path = dir.join("nope.pem").to_str().expect("utf8").into();
        assert!(f.plan().expect("plan").load().is_err());
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn incomplete_forms_are_refused_before_any_request() {
        let mut f = form(false);
        f.name = " ".into();
        assert!(f.plan().is_err());
        let mut f = form(false);
        f.cert_text = "  ".into();
        assert!(f.plan().unwrap_err().contains("certificate"));
        let mut f = form(false);
        f.key_text.clear();
        assert!(f.plan().unwrap_err().contains("private key"));
        let mut f = form(false);
        f.key_text = cert();
        assert!(
            f.plan()
                .expect("plan")
                .load()
                .unwrap_err()
                .contains("certificate")
        );
        let mut f = form(false);
        f.cert_text = key();
        assert!(
            f.plan()
                .expect("plan")
                .load()
                .unwrap_err()
                .contains("private key")
        );
    }

    #[test]
    fn debug_output_never_shows_key_material() {
        let secret = crate::testkit::joined(&["KEY", "BODY", "MARKER", "0123"]);
        let mut f = form(false);
        f.key_text = key_with_body(&secret);
        let plan = f.plan().expect("plan");
        let req = plan.clone().load().expect("load");
        for shown in [format!("{f:?}"), format!("{plan:?}"), format!("{req:?}")] {
            assert!(!shown.contains(secret.as_str()), "{shown}");
            assert!(shown.contains("shop"));
        }
        assert!(format!("{req:?}").contains("[redacted]"));
    }

    #[test]
    fn busy_states_label_themselves() {
        assert!(CertBusy::Idle.is_idle());
        assert_eq!(CertBusy::Idle.label(), None);
        assert!(!CertBusy::Upload.is_idle());
        assert!(
            CertBusy::Replace("shop".into())
                .label()
                .expect("label")
                .contains("shop")
        );
        assert!(
            CertBusy::Delete("api".into())
                .label()
                .expect("label")
                .contains("api")
        );
        assert!(CertBusy::Port.label().is_some() && CertBusy::Ranges.label().is_some());
        assert_eq!(CertBusy::Upload.noun(), "Certificate upload");
        assert!(CertBusy::Delete("api".into()).noun().contains("api"));
        assert!(!CertBusy::Idle.noun().is_empty());
        assert_eq!(uploaded_text("shop", false), "Certificate shop uploaded.");
        assert_eq!(uploaded_text("shop", true), "Certificate shop replaced.");
    }

    #[test]
    fn key_inputs_are_cleared_when_sent_closed_or_switched() {
        for on in [ClearOn::Submit, ClearOn::Success, ClearOn::Cancel] {
            let c = clears_for(on);
            assert!(c.key_text && c.key_path, "{on:?}");
        }
        let done = clears_for(ClearOn::Success);
        assert!(done.name && done.cert_text && done.cert_path);
        assert_eq!(clears_for(ClearOn::Success), clears_for(ClearOn::Cancel));
        let sent = clears_for(ClearOn::Submit);
        assert!(!sent.name && !sent.cert_text && !sent.cert_path);
        let files = clears_for(ClearOn::ToFiles);
        assert!(files.key_text && !files.key_path);
        let paste = clears_for(ClearOn::ToPaste);
        assert!(paste.key_path && !paste.key_text);
        assert!(!files.cert_text && !paste.cert_path);
    }

    #[test]
    fn hand_placed_certificates_are_read_only() {
        assert!(is_read_only("manual", "file:legacy.pem"));
        assert!(is_read_only("manual", "anything"));
        assert!(is_read_only("api", "file:odd"));
        assert!(!is_read_only("api", "01JC9ZQ7M3X8V4N2B6T5R0WHYA"));
        assert!(!is_read_only("", "01JC9ZQ7M3X8V4N2B6T5R0WHYA"));
        let item = CertItem {
            id: "file:legacy.pem".into(),
            name: "legacy".into(),
            subject: String::new(),
            sans: Vec::new(),
            issuer: String::new(),
            not_before: String::new(),
            not_after: String::new(),
            days_left: 5,
            fingerprint: String::new(),
            key_type: String::new(),
            created_at: String::new(),
            covers: Vec::new(),
            source: "manual".into(),
            warning: Some("no key file".into()),
        };
        assert!(item.read_only());
        let managed = CertItem {
            id: "01JC9ZQ7M3X8V4N2B6T5R0WHYA".into(),
            source: "api".into(),
            ..item
        };
        assert!(!managed.read_only());
        assert!(MANUAL_NOTE.contains("read-only"));
    }

    #[test]
    fn wiping_leaves_an_empty_string() {
        let mut s = key();
        wipe(&mut s);
        assert!(s.is_empty());
        let mut none = String::new();
        wipe(&mut none);
        assert!(none.is_empty());
    }

    #[test]
    fn work_for_one_node_is_refused_on_another() {
        assert!(ensure_same_node("edge-fra", Some("edge-fra")).is_ok());
        let other = ensure_same_node("edge-fra", Some("edge-iad")).unwrap_err();
        assert!(other.contains("nothing was sent"));
        assert!(ensure_same_node("edge-fra", None).is_err());
        assert!(ensure_same_node("", Some("edge-fra")).is_err());
    }

    #[test]
    fn delete_messages_name_the_hosts_that_lose_coverage() {
        let plain = delete_message("old", &[]);
        assert!(plain.starts_with("Delete old from the node?"));
        assert!(!plain.contains("warning"));
        let covered = delete_message("shop", &["a.example.com".into(), "b.example.com".into()]);
        assert!(covered.contains("a.example.com, b.example.com"));
        assert!(covered.contains("cannot be recovered"));
    }

    #[test]
    fn ports_are_one_to_65535() {
        assert_eq!(parse_port("443"), Ok(443));
        assert_eq!(parse_port(" 8443 "), Ok(8443));
        assert_eq!(parse_port("65535"), Ok(65535));
        for bad in ["", "0", "65536", "-1", "44.3", "https", "99999999999"] {
            assert!(parse_port(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn ranges_parse_one_per_line_and_validate() {
        let list = parse_range_list("173.245.48.0/20\n103.21.244.0/22, 2400:CB00::/32 # v6\n# note\n\n173.245.48.0/20\n198.51.100.7")
            .expect("parse");
        assert_eq!(
            list,
            vec![
                "173.245.48.0/20",
                "103.21.244.0/22",
                "2400:cb00::/32",
                "198.51.100.7"
            ]
        );
        for bad in [
            "10.0.0.0/33",
            "2001:db8::/129",
            "nope",
            "10.0.0.0/",
            "10.0.0.0/x",
            "10.0.0.0/-1",
            "300.1.1.1/8",
        ] {
            assert!(parse_range_list(bad).is_err(), "{bad}");
        }
        assert!(parse_range_list("").is_err());
        assert!(parse_range_list("# only a comment").is_err());
    }

    #[test]
    fn a_range_that_matches_everything_is_refused() {
        assert!(
            parse_range_list("0.0.0.0/0")
                .unwrap_err()
                .contains("every address")
        );
        assert!(
            parse_range_list("::/0")
                .unwrap_err()
                .contains("every address")
        );
        assert!(parse_range_list("10.0.0.0/8, 0.0.0.0/0").is_err());
    }

    #[test]
    fn range_texts_describe_the_source() {
        let listing = RangesListing {
            source: "builtin".into(),
            updated: "2026-10-01T00:00:00Z".into(),
            ranges: vec!["10.0.0.0/8".into()],
        };
        assert_eq!(
            ranges_summary(&listing),
            "Built-in list, updated 2026-10-01, 1 range"
        );
        assert!(!is_custom_source(&listing.source));
        assert_eq!(source_label("custom"), "Custom list");
        assert_eq!(source_label("fetched"), "fetched");
        assert!(is_custom_source("custom"));
        assert_eq!(ranges_text(&["a".into(), "b".into()]), "a\nb");
    }

    #[test]
    fn access_drafts_round_trip_through_the_model() {
        for cf in [false, true] {
            for flexible in [false, true] {
                for bots in [BotPolicy::Allow, BotPolicy::BlockBad, BotPolicy::BlockAll] {
                    for zone_lock in [false, true] {
                        let draft = AccessDraft {
                            cloudflare_only: cf,
                            flexible,
                            bots,
                            zone_lock: zone_lock && cf,
                        };
                        assert_eq!(AccessDraft::from_access(&draft.to_access()), draft);
                    }
                }
            }
        }
        assert_eq!(AccessDraft::default().to_access(), SiteAccess::default());
        let flexible = AccessDraft {
            flexible: true,
            ..AccessDraft::default()
        };
        assert_eq!(flexible.to_access().tls, TlsMode::Flexible);
    }

    #[test]
    fn the_zone_lock_follows_cloudflare_only() {
        let mut d = AccessDraft::default();
        d.set_zone_lock(true);
        assert!(!d.zone_lock, "refused while Cloudflare only is off");
        d.set_cloudflare_only(true);
        d.set_zone_lock(true);
        assert!(d.zone_lock && d.to_access().zone_lock);
        d.set_cloudflare_only(false);
        assert!(!d.zone_lock && !d.to_access().zone_lock);
        let forced = AccessDraft {
            zone_lock: true,
            ..AccessDraft::default()
        };
        assert!(!forced.to_access().zone_lock);
    }

    #[test]
    fn a_secret_is_shown_only_when_the_lock_is_newly_enabled() {
        let off = SiteAccess::default();
        let on = SiteAccess {
            cloudflare_only: true,
            zone_lock: true,
            ..SiteAccess::default()
        };
        assert!(zone_newly_enabled(&off, &on));
        assert!(!zone_newly_enabled(&on, &on));
        assert!(!zone_newly_enabled(&on, &off));
        assert!(!zone_newly_enabled(&off, &off));
    }

    #[test]
    fn bot_policies_have_labels_and_an_seo_warning_for_block_all() {
        assert_eq!(bots_label(BotPolicy::Allow), "Allow all");
        assert_eq!(bots_label(BotPolicy::BlockBad), "Block scrapers and tools");
        assert_eq!(bots_label(BotPolicy::BlockAll), "Block all bots");
        for p in [BotPolicy::Allow, BotPolicy::BlockBad, BotPolicy::BlockAll] {
            assert!(!bots_help(p).is_empty());
        }
        assert!(
            bots_warning(BotPolicy::BlockAll)
                .expect("warn")
                .contains("SEO")
        );
        assert!(bots_warning(BotPolicy::BlockBad).is_none());
        assert!(bots_warning(BotPolicy::Allow).is_none());
        assert!(BOTS_NOTE.contains("fake") && BOTS_NOTE.contains("analytics"));
        assert!(zone_lock_help(false).contains("Needs"));
        assert!(zone_lock_help(true).contains("Transform Rule"));
    }

    #[test]
    fn flexible_without_cloudflare_only_warns() {
        assert!(flexible_warning(false, true).is_some());
        assert!(flexible_warning(true, true).is_none());
        assert!(flexible_warning(false, false).is_none());
        assert!(flexible_warning(true, false).is_none());
        assert!(FLEXIBLE_HELP.contains("plain HTTP"));
    }
}
