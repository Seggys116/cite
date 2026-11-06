use std::fmt;
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

use crate::alertcfg::check_email;
use crate::certs::wipe;
use crate::theme::Tone;

pub const POLL_EVERY: Duration = Duration::from_secs(3);
// Ten minutes of polling at three seconds each.
pub const MAX_POLLS: u32 = 200;
pub const MAX_POLL_ERRORS: u32 = 5;
pub const MAX_HOSTS: usize = 50;
pub const MAX_NAME_CHARS: usize = cite_client::MAX_CERT_NAME_CHARS;
pub const DEFAULT_DAYS: u32 = 365;
pub const MAX_DAYS: u32 = 3650;
pub const ORIGIN_VALIDITY_DAYS: [u32; 7] = [7, 30, 90, 365, 730, 1095, 5475];
pub const DEFAULT_ORIGIN_DAYS: u32 = 365;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Generate,
    OriginCa,
    Acme,
}

impl Mode {
    pub const ALL: [Mode; 3] = [Mode::Generate, Mode::OriginCa, Mode::Acme];

    pub fn title(self) -> &'static str {
        match self {
            Mode::Generate => "Create a certificate for me",
            Mode::OriginCa => "Cloudflare Origin CA",
            Mode::Acme => "Let's Encrypt",
        }
    }

    pub fn blurb(self) -> &'static str {
        match self {
            Mode::Generate => {
                "The node makes a self-signed certificate. It is instant and free, but browsers warn about it unless Cloudflare is in front with HTTPS set to Full."
            }
            Mode::OriginCa => {
                "Cloudflare signs a certificate for the link between Cloudflare and your node. Visitors never see it, so use it only for sites behind the Cloudflare proxy. Needs a Cloudflare API token."
            }
            Mode::Acme => {
                "A free certificate every browser trusts, renewed automatically. A Cloudflare API token lets the node prove you own the domain."
            }
        }
    }

    pub fn noun(self) -> &'static str {
        match self {
            Mode::Generate => "Certificate creation",
            Mode::OriginCa => "Origin CA certificate request",
            Mode::Acme => "Let's Encrypt request",
        }
    }

    pub fn busy_label(self) -> &'static str {
        match self {
            Mode::Generate => "Creating the certificate...",
            Mode::OriginCa => "Asking Cloudflare for a certificate...",
            Mode::Acme => "Sending the request to the node...",
        }
    }

    pub fn needs_token(self) -> bool {
        self != Mode::Generate
    }

    pub fn submit_label(self) -> &'static str {
        match self {
            Mode::Generate => "Create certificate",
            Mode::OriginCa => "Request certificate",
            Mode::Acme => "Start issuing",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Hosts,
    Details,
}

impl Stage {
    pub fn label(self) -> &'static str {
        match self {
            Stage::Hosts => "Step 1 of 2: choose the hosts",
            Stage::Details => "Step 2 of 2: details",
        }
    }
}

fn shown(raw: &str) -> String {
    let t = raw.trim();
    if t.chars().count() > 60 {
        let cut: String = t.chars().take(60).collect();
        format!("{cut}...")
    } else {
        t.to_string()
    }
}

pub fn normalize_host(raw: &str) -> Result<String, String> {
    let host = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Err("Enter a host name.".into());
    }
    let name = shown(raw);
    if host.contains("://") || host.contains('/') {
        return Err(format!(
            "{name}: enter just the host name, without http:// or a path."
        ));
    }
    if host.contains(':') {
        return Err(format!("{name}: enter the host name without a port."));
    }
    if host.len() > 253 {
        return Err(format!("{name}: that host name is too long."));
    }
    let body = host.strip_prefix("*.").unwrap_or(&host);
    if body.contains('*') {
        return Err(format!(
            "{name}: a wildcard is only allowed as the first label, like *.example.com."
        ));
    }
    let labels: Vec<&str> = body.split('.').collect();
    if labels.len() < 2 && body != "localhost" {
        return Err(format!(
            "{name}: a host name needs a dot, like shop.example.com."
        ));
    }
    for label in &labels {
        let ok = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if !ok {
            return Err(format!("{name}: that is not a valid host name."));
        }
    }
    if labels.len() > 1
        && labels
            .last()
            .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(format!("{name}: enter a host name, not an IP address."));
    }
    Ok(host)
}

fn too_many_hosts() -> String {
    format!("A certificate can cover at most {MAX_HOSTS} hosts.")
}

pub fn parse_hosts(text: &str) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    let parts = text
        .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .filter(|p| !p.is_empty());
    for part in parts {
        let host = normalize_host(part)?;
        if !out.contains(&host) {
            out.push(host);
        }
    }
    if out.len() > MAX_HOSTS {
        return Err(too_many_hosts());
    }
    Ok(out)
}

// Adds every host in the text, or none of them when any is invalid or the list would grow too long.
pub fn add_hosts(list: &mut Vec<String>, raw: &str) -> Result<usize, String> {
    let parsed = parse_hosts(raw)?;
    if parsed.is_empty() {
        return Err("Enter a host name.".into());
    }
    let fresh: Vec<String> = parsed.into_iter().filter(|h| !list.contains(h)).collect();
    if list.len() + fresh.len() > MAX_HOSTS {
        return Err(too_many_hosts());
    }
    let added = fresh.len();
    list.extend(fresh);
    Ok(added)
}

// Returns whether the host is selected afterwards.
pub fn toggle_host(list: &mut Vec<String>, host: &str) -> bool {
    if let Some(at) = list.iter().position(|h| h == host) {
        list.remove(at);
        false
    } else {
        list.push(host.to_string());
        true
    }
}

// Hosts that still lack a certificate come first, then the node's other site hosts, then anything typed by hand.
pub fn candidates(uncovered: &[String], site_hosts: &[String], selected: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for host in uncovered.iter().chain(site_hosts).chain(selected) {
        let host = host.trim().to_ascii_lowercase();
        if !host.is_empty() && !out.contains(&host) {
            out.push(host);
        }
    }
    out
}

pub fn check_hosts(hosts: &[String]) -> Result<(), String> {
    if hosts.is_empty() {
        return Err("Choose at least one host.".into());
    }
    if hosts.len() > MAX_HOSTS {
        return Err(too_many_hosts());
    }
    for host in hosts {
        normalize_host(host)?;
    }
    Ok(())
}

pub fn check_cloudflare_token(token: &str) -> Result<(), String> {
    let t = token.trim();
    if t.is_empty() {
        return Err("Paste a Cloudflare API token.".into());
    }
    if t.to_ascii_lowercase().starts_with("bearer ") {
        return Err("Remove the word Bearer and paste only the token.".into());
    }
    if t.chars().any(char::is_whitespace) {
        return Err("The token has spaces or line breaks in it. Paste only the token.".into());
    }
    if t.len() < 20 {
        return Err("That is too short to be a Cloudflare API token.".into());
    }
    if t.len() > 256 {
        return Err("That is too long to be a Cloudflare API token.".into());
    }
    if !t
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err("That has characters a Cloudflare API token never contains.".into());
    }
    Ok(())
}

pub fn check_name(name: &str) -> Result<Option<String>, String> {
    let t = name.trim();
    if t.is_empty() {
        return Ok(None);
    }
    if t.chars().count() > MAX_NAME_CHARS {
        return Err(format!(
            "The name can be at most {MAX_NAME_CHARS} characters."
        ));
    }
    if t.chars().any(char::is_control) {
        return Err("The name cannot contain control characters.".into());
    }
    Ok(Some(t.to_string()))
}

pub fn parse_days(text: &str) -> Result<u32, String> {
    let t = text.trim();
    if t.is_empty() {
        return Ok(DEFAULT_DAYS);
    }
    let range = format!("Enter a number of days from 1 to {MAX_DAYS}.");
    if !t.bytes().all(|b| b.is_ascii_digit()) {
        return Err(range);
    }
    match t.parse::<u32>() {
        Ok(d) if (1..=MAX_DAYS).contains(&d) => Ok(d),
        _ => Err(range),
    }
}

pub fn origin_days_label(days: u32) -> String {
    match days {
        7 => "7 days".into(),
        30 => "30 days".into(),
        365 => "1 year".into(),
        730 => "2 years".into(),
        1095 => "3 years".into(),
        5475 => "15 years".into(),
        d => format!("{d} days"),
    }
}

pub struct IssueForm {
    pub mode: Mode,
    pub hosts: Vec<String>,
    pub name: String,
    pub days: String,
    pub email: String,
    pub token: String,
    pub origin_days: u32,
    pub remember_token: bool,
    pub agree_tos: bool,
    pub staging: bool,
}

impl fmt::Debug for IssueForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssueForm")
            .field("mode", &self.mode)
            .field("hosts", &self.hosts)
            .field("name", &self.name)
            .field("email", &self.email)
            .field("token", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl Drop for IssueForm {
    fn drop(&mut self) {
        wipe(&mut self.token);
    }
}

#[derive(Serialize)]
struct GenerateBody<'a> {
    hosts: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    days: u32,
}

#[derive(Serialize)]
struct OriginBody<'a> {
    hosts: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    validity_days: u32,
    remember_token: bool,
}

#[derive(Serialize)]
struct AcmeBody<'a> {
    hosts: &'a [String],
    email: &'a str,
    agree_tos: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    staging: bool,
}

// The body never holds the token; the client adds it at the last moment and the copy kept here is wiped on drop.
pub struct IssueRequest {
    pub mode: Mode,
    body: Value,
    token: String,
}

impl IssueRequest {
    pub fn take_parts(&mut self) -> (Value, String) {
        (self.body.take(), std::mem::take(&mut self.token))
    }
}

impl fmt::Debug for IssueRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IssueRequest({:?}, {}, token redacted)",
            self.mode, self.body
        )
    }
}

impl Drop for IssueRequest {
    fn drop(&mut self) {
        wipe(&mut self.token);
    }
}

impl IssueForm {
    pub fn check_hosts(&self) -> Result<(), String> {
        check_hosts(&self.hosts)
    }

    pub fn request(&self) -> Result<IssueRequest, String> {
        self.check_hosts()?;
        let name = check_name(&self.name)?;
        let name = name.as_deref();
        let hosts = self.hosts.as_slice();
        let body = match self.mode {
            Mode::Generate => {
                let days = parse_days(&self.days)?;
                serde_json::to_value(GenerateBody { hosts, name, days })
            }
            Mode::OriginCa => {
                check_cloudflare_token(&self.token)?;
                if !ORIGIN_VALIDITY_DAYS.contains(&self.origin_days) {
                    return Err("Choose how long the certificate should last.".into());
                }
                serde_json::to_value(OriginBody {
                    hosts,
                    name,
                    validity_days: self.origin_days,
                    remember_token: self.remember_token,
                })
            }
            Mode::Acme => {
                let email = check_email(&self.email)?;
                check_cloudflare_token(&self.token)?;
                if !self.agree_tos {
                    return Err(
                        "Agree to the Let's Encrypt Subscriber Agreement to continue.".into(),
                    );
                }
                serde_json::to_value(AcmeBody {
                    hosts,
                    email: &email,
                    agree_tos: true,
                    name,
                    staging: self.staging,
                })
            }
        }
        .map_err(|_| "Could not prepare the request.".to_string())?;
        let token = if self.mode.needs_token() {
            self.token.trim().to_string()
        } else {
            String::new()
        };
        Ok(IssueRequest {
            mode: self.mode,
            body,
            token,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssueOutcome {
    pub name: String,
    pub warning: Option<String>,
}

pub fn json_text(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

pub fn json_opt_text(v: &Value, key: &str) -> Option<String> {
    let t = json_text(v, key);
    let t = t.trim();
    (!t.is_empty()).then(|| t.to_string())
}

pub fn json_list<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    v.get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

pub fn json_strings(v: &Value, key: &str) -> Vec<String> {
    json_list(v, key)
        .iter()
        .filter_map(|x| x.as_str().map(str::to_string))
        .collect()
}

pub fn parse_issue_outcome(v: &Value) -> IssueOutcome {
    let name = v
        .get("cert")
        .map(|c| json_text(c, "name"))
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| json_text(v, "name"));
    IssueOutcome {
        name,
        warning: json_opt_text(v, "warning"),
    }
}

pub fn issued_text(mode: Mode, outcome: &IssueOutcome) -> String {
    let what = match mode {
        Mode::Generate => "Created a self-signed certificate",
        _ => "Issued the certificate",
    };
    if outcome.name.is_empty() {
        format!("{what}.")
    } else {
        format!("{what} {}.", outcome.name)
    }
}

pub fn parse_job_id(v: &Value) -> Result<String, String> {
    let id = json_text(v, "job_id");
    let ok = !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'));
    if ok {
        Ok(id)
    } else {
        Err("The node accepted the request but did not return a usable job id.".into())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobStatus {
    Pending,
    Issued,
    Failed,
}

impl JobStatus {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "pending" => Some(Self::Pending),
            "issued" => Some(Self::Issued),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Pending => "in progress",
            Self::Issued => "issued",
            Self::Failed => "failed",
        }
    }

    pub fn tone(self) -> Tone {
        match self {
            Self::Pending => Tone::Info,
            Self::Issued => Tone::Ok,
            Self::Failed => Tone::Bad,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcmeJob {
    pub job_id: String,
    pub hosts: Vec<String>,
    pub status: JobStatus,
    pub error: Option<String>,
    pub started_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedCert {
    pub id: String,
    pub hosts: Vec<String>,
    pub status: String,
    pub not_after: String,
    pub renew_at: String,
    pub staging: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AcmeListing {
    pub jobs: Vec<AcmeJob>,
    pub managed: Vec<ManagedCert>,
}

impl AcmeListing {
    pub fn pending(&self) -> Option<&AcmeJob> {
        self.jobs.iter().find(|j| j.status == JobStatus::Pending)
    }
}

pub fn parse_acme_listing(v: &Value) -> Result<AcmeListing, String> {
    if !v.is_object() {
        return Err("The node sent an unexpected certificate job list.".into());
    }
    let mut out = AcmeListing::default();
    for j in json_list(v, "jobs") {
        let raw = json_text(j, "status");
        let status = JobStatus::parse(&raw)
            .ok_or_else(|| format!("The node reported an unknown job status ({}).", shown(&raw)))?;
        out.jobs.push(AcmeJob {
            job_id: json_text(j, "job_id"),
            hosts: json_strings(j, "hosts"),
            status,
            error: json_opt_text(j, "error"),
            started_at: json_text(j, "started_at"),
        });
    }
    for m in json_list(v, "managed") {
        out.managed.push(ManagedCert {
            id: json_text(m, "id"),
            hosts: json_strings(m, "hosts"),
            status: json_text(m, "status"),
            not_after: json_text(m, "not_after"),
            renew_at: json_text(m, "renew_at"),
            staging: m.get("staging").and_then(Value::as_bool).unwrap_or(false),
            error: json_opt_text(m, "error"),
        });
    }
    Ok(out)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PollStep {
    Wait,
    Issued,
    Failed(String),
    Lost,
    TimedOut,
}

pub fn failure_reason(error: Option<&str>) -> String {
    match error.map(str::trim).filter(|e| !e.is_empty()) {
        Some(e) => e.to_string(),
        None => "The node did not say why.".into(),
    }
}

// polls counts the answers already seen, so the limit is reached after MAX_POLLS of them.
pub fn poll_step(job_id: &str, listing: &AcmeListing, polls: u32) -> PollStep {
    match listing.jobs.iter().find(|j| j.job_id == job_id) {
        None => PollStep::Lost,
        Some(job) => match job.status {
            JobStatus::Issued => PollStep::Issued,
            JobStatus::Failed => PollStep::Failed(failure_reason(job.error.as_deref())),
            JobStatus::Pending if polls >= MAX_POLLS => PollStep::TimedOut,
            JobStatus::Pending => PollStep::Wait,
        },
    }
}

pub fn gives_up_after_errors(consecutive: u32) -> bool {
    consecutive >= MAX_POLL_ERRORS
}

pub fn step_note(step: &PollStep, hosts: &[String]) -> Option<(String, Tone)> {
    let list = hosts.join(", ");
    match step {
        PollStep::Wait => None,
        PollStep::Issued => Some((
            format!("Let's Encrypt issued the certificate for {list}. The node renews it automatically."),
            Tone::Ok,
        )),
        PollStep::Failed(reason) => Some((
            format!("Let's Encrypt could not issue the certificate for {list}: {reason}"),
            Tone::Bad,
        )),
        PollStep::Lost => Some((
            "The node no longer lists this request. It may have restarted; check the managed certificates below."
                .into(),
            Tone::Warn,
        )),
        PollStep::TimedOut => Some((
            "Still waiting after ten minutes. The node keeps working on it; check back later."
                .into(),
            Tone::Warn,
        )),
    }
}

pub fn managed_text(m: &ManagedCert) -> String {
    let kind = if m.staging { "test certificate, " } else { "" };
    let until = if m.not_after.is_empty() {
        String::new()
    } else {
        format!(", valid until {}", date_part(&m.not_after))
    };
    let renew = if m.renew_at.is_empty() {
        String::new()
    } else {
        format!(", renews {}", date_part(&m.renew_at))
    };
    format!("{kind}{}{until}{renew}", m.status)
}

fn date_part(stamp: &str) -> &str {
    stamp.split('T').next().unwrap_or(stamp)
}

pub(crate) fn demo_issue_outcome(mode: Mode, hosts: &[String], name: &str) -> IssueOutcome {
    let label = if name.trim().is_empty() {
        hosts.first().cloned().unwrap_or_default()
    } else {
        name.trim().to_string()
    };
    let warning = (mode == Mode::Generate)
        .then(|| "Self-signed: browsers warn unless Cloudflare is in front.".to_string());
    IssueOutcome {
        name: label,
        warning,
    }
}

pub(crate) fn demo_acme_job_id(now_secs: u64) -> String {
    format!("demo-{now_secs}")
}

// A demo job finishes six seconds after it starts.
pub(crate) fn demo_acme_listing(job_id: Option<&str>, now_secs: u64) -> AcmeListing {
    let mut jobs = Vec::new();
    if let Some(id) = job_id {
        let started = id
            .strip_prefix("demo-")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let status = if now_secs.saturating_sub(started) < 6 {
            JobStatus::Pending
        } else {
            JobStatus::Issued
        };
        jobs.push(AcmeJob {
            job_id: id.to_string(),
            hosts: vec!["demo.example.com".into()],
            status,
            error: None,
            started_at: "2026-11-06T09:00:00Z".into(),
        });
    }
    AcmeListing {
        jobs,
        managed: vec![ManagedCert {
            id: "acme-shop".into(),
            hosts: vec!["shop.example.com".into()],
            status: "issued".into(),
            not_after: "2027-02-01T00:00:00Z".into(),
            renew_at: "2027-01-02T00:00:00Z".into(),
            staging: false,
            error: None,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn form(mode: Mode) -> IssueForm {
        IssueForm {
            mode,
            hosts: vec!["shop.example.com".into()],
            name: String::new(),
            days: String::new(),
            email: "ops@example.com".into(),
            token: "abcdefghijklmnopqrstuvwxyz0123456789ABCD".into(),
            origin_days: DEFAULT_ORIGIN_DAYS,
            remember_token: false,
            agree_tos: true,
            staging: false,
        }
    }

    fn body(mut req: IssueRequest) -> Value {
        req.take_parts().0
    }

    #[test]
    fn hosts_are_lowercased_and_trailing_dots_dropped() {
        assert_eq!(
            normalize_host(" Shop.Example.COM. ").unwrap(),
            "shop.example.com"
        );
        assert_eq!(normalize_host("*.example.com").unwrap(), "*.example.com");
        assert_eq!(normalize_host("localhost").unwrap(), "localhost");
    }

    #[test]
    fn bad_hosts_are_refused_with_a_reason() {
        for bad in [
            "",
            "   ",
            "https://example.com",
            "example.com/path",
            "example.com:443",
            "nodot",
            "-a.example.com",
            "a-.example.com",
            "a..example.com",
            "ex ample.com",
            "a.*.example.com",
            "under_score.example.com",
            "10.0.0.1",
        ] {
            assert!(normalize_host(bad).is_err(), "{bad:?} must be refused");
        }
        assert!(normalize_host(&format!("{}.com", "a".repeat(64))).is_err());
        assert!(normalize_host(&format!("{}.com", "a.".repeat(130))).is_err());
    }

    #[test]
    fn host_lists_split_on_commas_and_whitespace_and_dedupe() {
        let got = parse_hosts("a.example.com, B.example.com\nA.example.com;c.example.com").unwrap();
        assert_eq!(got, ["a.example.com", "b.example.com", "c.example.com"]);
        assert!(parse_hosts("").unwrap().is_empty());
        assert!(parse_hosts("a.example.com bad_host").is_err());
    }

    #[test]
    fn adding_hosts_is_all_or_nothing_and_capped() {
        let mut list = vec!["a.example.com".to_string()];
        assert_eq!(
            add_hosts(&mut list, "a.example.com b.example.com").unwrap(),
            1
        );
        assert_eq!(list, ["a.example.com", "b.example.com"]);
        assert!(add_hosts(&mut list, "c.example.com nope").is_err());
        assert_eq!(list.len(), 2);
        assert!(add_hosts(&mut list, "  ").is_err());
        let many: Vec<String> = (0..MAX_HOSTS)
            .map(|i| format!("h{i}.example.com"))
            .collect();
        let mut full = many.clone();
        assert!(add_hosts(&mut full, "extra.example.com").is_err());
        assert_eq!(full, many);
        assert!(parse_hosts(&many.join(" ")).is_ok());
        assert!(parse_hosts(&format!("{} extra.example.com", many.join(" "))).is_err());
    }

    #[test]
    fn toggling_a_host_adds_then_removes_it() {
        let mut list = Vec::new();
        assert!(toggle_host(&mut list, "a.example.com"));
        assert!(!toggle_host(&mut list, "a.example.com"));
        assert!(list.is_empty());
    }

    #[test]
    fn candidates_put_uncovered_hosts_first_without_duplicates() {
        let got = candidates(
            &["b.example.com".into()],
            &["a.example.com".into(), "B.example.com".into()],
            &["c.example.com".into(), "a.example.com".into()],
        );
        assert_eq!(got, ["b.example.com", "a.example.com", "c.example.com"]);
    }

    #[test]
    fn token_shape_is_checked_without_echoing_it() {
        assert!(check_cloudflare_token("abcdefghijklmnopqrstuvwxyz0123456789ABCD").is_ok());
        assert!(check_cloudflare_token("v1.0-abcdef0123456789abcdef-0123456789").is_ok());
        for bad in [
            "",
            "  ",
            "short",
            "Bearer abcdefghijklmnopqrstuvwxyz0123",
            "abcdefghijklmnop qrstuvwxyz0123",
            "abcdefghijklmnopqrstuvwxyz0123456789$$",
        ] {
            let err = check_cloudflare_token(bad).unwrap_err();
            if bad.trim().len() > 8 {
                assert!(!err.contains(bad.trim()), "{err}");
            }
        }
        assert!(check_cloudflare_token(&"a".repeat(257)).is_err());
    }

    #[test]
    fn days_default_when_blank_and_stay_in_range() {
        assert_eq!(parse_days("").unwrap(), DEFAULT_DAYS);
        assert_eq!(parse_days(" 90 ").unwrap(), 90);
        for bad in ["0", "-1", "abc", "3651", "1.5", "99999999999"] {
            assert!(parse_days(bad).is_err(), "{bad:?}");
        }
        assert_eq!(parse_days("3650").unwrap(), 3650);
    }

    #[test]
    fn names_are_optional_and_bounded() {
        assert_eq!(check_name("  ").unwrap(), None);
        assert_eq!(check_name(" shop ").unwrap().as_deref(), Some("shop"));
        assert!(check_name(&"n".repeat(MAX_NAME_CHARS + 1)).is_err());
        assert!(check_name("bad\nname").is_err());
    }

    #[test]
    fn generate_request_has_hosts_name_and_days_only() {
        let mut f = form(Mode::Generate);
        f.name = "shop".into();
        f.days = "30".into();
        let v = body(f.request().unwrap());
        assert_eq!(
            v,
            json!({"hosts": ["shop.example.com"], "name": "shop", "days": 30})
        );
        let v = body(form(Mode::Generate).request().unwrap());
        assert_eq!(v, json!({"hosts": ["shop.example.com"], "days": 365}));
    }

    #[test]
    fn origin_request_keeps_the_token_out_of_the_body() {
        let mut f = form(Mode::OriginCa);
        f.remember_token = true;
        f.origin_days = 730;
        f.token = format!("  {}  ", f.token);
        let (v, token) = f.request().unwrap().take_parts();
        assert_eq!(v["validity_days"], 730);
        assert_eq!(v["remember_token"], true);
        assert!(!v.to_string().contains(&token));
        assert_eq!(token, f.token.trim());
        f.origin_days = 100;
        assert!(f.request().is_err());
    }

    #[test]
    fn a_generated_certificate_request_carries_no_token() {
        let (v, token) = form(Mode::Generate).request().unwrap().take_parts();
        assert!(token.is_empty() && v.get("cloudflare_token").is_none());
    }

    #[test]
    fn acme_request_needs_the_terms_an_email_and_a_token() {
        let mut f = form(Mode::Acme);
        f.staging = true;
        let v = body(f.request().unwrap());
        assert_eq!(v["agree_tos"], true);
        assert_eq!(v["staging"], true);
        assert_eq!(v["email"], "ops@example.com");
        assert!(v.get("name").is_none());
        f.agree_tos = false;
        assert!(f.request().unwrap_err().contains("Agreement"));
        f.agree_tos = true;
        f.email = "not-an-email".into();
        assert!(f.request().is_err());
        f.email = "ops@example.com".into();
        f.token = "short".into();
        assert!(f.request().is_err());
    }

    #[test]
    fn a_request_without_hosts_is_refused() {
        let mut f = form(Mode::Generate);
        f.hosts.clear();
        assert_eq!(f.request().unwrap_err(), "Choose at least one host.");
    }

    #[test]
    fn debug_output_never_shows_the_token() {
        let f = form(Mode::Acme);
        let shown = format!("{f:?}");
        assert!(!shown.contains(&f.token));
        let req = f.request().unwrap();
        assert!(!format!("{req:?}").contains(&f.token));
    }

    #[test]
    fn taking_the_parts_leaves_nothing_behind() {
        let mut req = form(Mode::Acme).request().unwrap();
        let (body, token) = req.take_parts();
        assert!(!body.is_null() && !token.is_empty());
        let (body, token) = req.take_parts();
        assert!(body.is_null() && token.is_empty());
    }

    #[test]
    fn outcomes_read_the_nested_or_flat_name_and_warning() {
        let nested = parse_issue_outcome(&json!({"cert": {"name": "shop"}, "warning": "slow"}));
        assert_eq!(nested.name, "shop");
        assert_eq!(nested.warning.as_deref(), Some("slow"));
        let flat = parse_issue_outcome(&json!({"name": "api"}));
        assert_eq!(
            flat,
            IssueOutcome {
                name: "api".into(),
                warning: None
            }
        );
        assert_eq!(
            issued_text(Mode::Generate, &flat),
            "Created a self-signed certificate api."
        );
        assert_eq!(
            issued_text(
                Mode::OriginCa,
                &IssueOutcome {
                    name: String::new(),
                    warning: None
                }
            ),
            "Issued the certificate."
        );
    }

    #[test]
    fn job_ids_must_be_plain_tokens() {
        assert_eq!(
            parse_job_id(&json!({"job_id": "job-1_a:b.c"})).unwrap(),
            "job-1_a:b.c"
        );
        for bad in [
            json!({}),
            json!({"job_id": ""}),
            json!({"job_id": "a b"}),
            json!({"job_id": 5}),
        ] {
            assert!(parse_job_id(&bad).is_err());
        }
        assert!(parse_job_id(&json!({"job_id": "x".repeat(129)})).is_err());
    }

    fn listing(status: &str, error: Option<&str>) -> AcmeListing {
        parse_acme_listing(&json!({
            "jobs": [{"job_id": "j1", "hosts": ["a.example.com"], "status": status, "error": error, "started_at": "t"}],
            "managed": [{"id": "m1", "hosts": ["a.example.com"], "status": "issued", "not_after": "2027-02-01T00:00:00Z", "renew_at": "2027-01-02T00:00:00Z", "staging": true}]
        }))
        .unwrap()
    }

    #[test]
    fn the_listing_parses_jobs_and_managed_certificates() {
        let l = listing("pending", None);
        assert_eq!(l.jobs.len(), 1);
        assert_eq!(l.pending().unwrap().job_id, "j1");
        assert_eq!(l.managed[0].id, "m1");
        assert!(l.managed[0].staging);
        assert_eq!(
            managed_text(&l.managed[0]),
            "test certificate, issued, valid until 2027-02-01, renews 2027-01-02"
        );
        assert!(
            parse_acme_listing(&json!({"jobs": [{"job_id": "x", "status": "weird"}]})).is_err()
        );
        assert!(parse_acme_listing(&json!([])).is_err());
        assert_eq!(
            parse_acme_listing(&json!({})).unwrap(),
            AcmeListing::default()
        );
    }

    #[test]
    fn polling_waits_while_pending_and_stops_on_a_result() {
        assert_eq!(
            poll_step("j1", &listing("pending", None), 0),
            PollStep::Wait
        );
        assert_eq!(
            poll_step("j1", &listing("pending", None), MAX_POLLS - 1),
            PollStep::Wait
        );
        assert_eq!(
            poll_step("j1", &listing("pending", None), MAX_POLLS),
            PollStep::TimedOut
        );
        assert_eq!(
            poll_step("j1", &listing("issued", None), 1),
            PollStep::Issued
        );
        assert_eq!(
            poll_step("j1", &listing("failed", Some("dns timeout")), 1),
            PollStep::Failed("dns timeout".into())
        );
        assert_eq!(
            poll_step("j1", &listing("failed", None), 1),
            PollStep::Failed("The node did not say why.".into())
        );
        assert_eq!(
            poll_step("other", &listing("pending", None), 1),
            PollStep::Lost
        );
    }

    #[test]
    fn a_failure_banner_names_the_reason_and_the_hosts() {
        let hosts = vec!["a.example.com".to_string(), "b.example.com".to_string()];
        let (text, tone) = step_note(&PollStep::Failed("rate limited".into()), &hosts).unwrap();
        assert_eq!(tone, Tone::Bad);
        assert!(text.contains("rate limited") && text.contains("a.example.com, b.example.com"));
        assert!(step_note(&PollStep::Wait, &hosts).is_none());
        assert_eq!(step_note(&PollStep::Issued, &hosts).unwrap().1, Tone::Ok);
        assert_eq!(step_note(&PollStep::Lost, &hosts).unwrap().1, Tone::Warn);
        assert_eq!(
            step_note(&PollStep::TimedOut, &hosts).unwrap().1,
            Tone::Warn
        );
    }

    #[test]
    fn polling_gives_up_after_repeated_errors() {
        assert!(!gives_up_after_errors(MAX_POLL_ERRORS - 1));
        assert!(gives_up_after_errors(MAX_POLL_ERRORS));
    }

    #[test]
    fn the_demo_job_finishes_after_six_seconds() {
        let id = demo_acme_job_id(100);
        assert_eq!(
            demo_acme_listing(Some(&id), 105).jobs[0].status,
            JobStatus::Pending
        );
        assert_eq!(
            demo_acme_listing(Some(&id), 106).jobs[0].status,
            JobStatus::Issued
        );
        assert!(demo_acme_listing(None, 0).jobs.is_empty());
        assert_eq!(demo_acme_listing(None, 0).managed.len(), 1);
    }

    #[test]
    fn the_demo_outcome_warns_only_for_self_signed() {
        let hosts = vec!["a.example.com".to_string()];
        assert!(
            demo_issue_outcome(Mode::Generate, &hosts, "")
                .warning
                .is_some()
        );
        let o = demo_issue_outcome(Mode::OriginCa, &hosts, " shop ");
        assert_eq!((o.name.as_str(), o.warning), ("shop", None));
        assert_eq!(
            demo_issue_outcome(Mode::OriginCa, &hosts, "").name,
            "a.example.com"
        );
    }

    #[test]
    fn every_mode_has_distinct_copy() {
        let titles: Vec<_> = Mode::ALL.iter().map(|m| m.title()).collect();
        assert_eq!(
            titles,
            [
                "Create a certificate for me",
                "Cloudflare Origin CA",
                "Let's Encrypt"
            ]
        );
        assert!(
            Mode::ALL
                .iter()
                .all(|m| !m.blurb().is_empty() && !m.submit_label().is_empty())
        );
        assert!(
            !Mode::Generate.needs_token()
                && Mode::OriginCa.needs_token()
                && Mode::Acme.needs_token()
        );
        assert_eq!(Stage::Hosts.label(), "Step 1 of 2: choose the hosts");
    }
}
