use std::fmt;

use cite_edge::model::{
    Cors, FirewallAction, FirewallRule, HeaderMatch, HeaderOp, HeaderOpKind, HeaderTarget,
    Matchers, Redirect,
};
use cite_edge::validate::validate_rule;

use crate::model::{matcher_problem, slugify};
use crate::theme::Tone;

pub const REDIRECT_STATUSES: [u16; 4] = [301, 302, 307, 308];
pub const MAX_HEADER_OPS: usize = 16;
pub const MAX_CORS_ENTRIES: usize = 32;
pub const MAX_CORS_MAX_AGE: u32 = 86_400;
pub const REDIRECT_PLACEHOLDERS: &str = "{scheme} {host} {www_host} {apex_host} {path} {query}";
pub const REDIRECT_EXAMPLES: [&str; 3] = [
    "{scheme}://{www_host}{path}{query}",
    "https://{host}{path}{query}",
    "/new-home",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleKind {
    Block,
    Redirect,
    Effects,
}

impl RuleKind {
    pub fn label(self) -> &'static str {
        match self {
            RuleKind::Block => "Block",
            RuleKind::Redirect => "Redirect",
            RuleKind::Effects => "Headers and CORS",
        }
    }

    pub fn help(self) -> &'static str {
        match self {
            RuleKind::Block => "Stop matching requests before they reach the site.",
            RuleKind::Redirect => {
                "Answer matching requests with a redirect to another address. Add a matcher so it cannot loop."
            }
            RuleKind::Effects => {
                "Let matching requests through, changing request or response headers and answering CORS."
            }
        }
    }
}

pub fn target_label(t: HeaderTarget) -> &'static str {
    match t {
        HeaderTarget::Request => "Request",
        HeaderTarget::Response => "Response",
    }
}

pub fn op_label(op: HeaderOpKind) -> &'static str {
    match op {
        HeaderOpKind::Set => "Set",
        HeaderOpKind::Add => "Add",
        HeaderOpKind::Remove => "Remove",
    }
}

pub fn action_tone(a: FirewallAction) -> Tone {
    match a {
        FirewallAction::Deny => Tone::Bad,
        FirewallAction::Drop => Tone::Warn,
        FirewallAction::Tarpit => Tone::Info,
    }
}

// The kinds of condition a row can express; rows of one kind are OR'd, different kinds are AND'd.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CondKind {
    PathPrefix,
    PathRegex,
    UserAgent,
    Referer,
    Method,
    Host,
    Cidr,
    Scheme,
    Header,
}

// The extra settings of a Header row; its value lives in the row's value field.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HeaderCond {
    pub name: String,
    pub regex: bool,
    pub negate: bool,
    pub secret: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct CondRow {
    pub kind: CondKind,
    pub value: String,
    pub header: HeaderCond,
}

impl CondRow {
    pub fn value(kind: CondKind, value: &str) -> Self {
        Self {
            kind,
            value: value.to_string(),
            header: HeaderCond::default(),
        }
    }

    pub fn header(name: &str, value: &str, regex: bool, negate: bool, secret: bool) -> Self {
        Self {
            kind: CondKind::Header,
            value: value.to_string(),
            header: HeaderCond {
                name: name.to_string(),
                regex,
                negate,
                secret,
            },
        }
    }

    fn is_blank(&self) -> bool {
        if self.kind == CondKind::Header {
            self.header.name.trim().is_empty() && self.value.trim().is_empty()
        } else {
            self.value.trim().is_empty()
        }
    }

    fn normalised(&self) -> String {
        let v = self.value.trim();
        if self.kind == CondKind::Method {
            v.to_uppercase()
        } else {
            v.to_string()
        }
    }
}

// A secret matcher value never reaches Debug output, so a logged row cannot leak it.
impl fmt::Debug for CondRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = if self.kind == CondKind::Header && self.header.secret {
            "[redacted]"
        } else {
            self.value.as_str()
        };
        f.debug_struct("CondRow")
            .field("kind", &self.kind)
            .field("value", &value)
            .field("header", &self.header.name)
            .finish_non_exhaustive()
    }
}

// One row per value; regexes split on spaces only, because a comma is valid inside one such as a{1,3}.
pub fn rows_from_list(kind: CondKind, text: &str) -> Vec<CondRow> {
    let values: Vec<String> = match kind {
        CondKind::PathRegex | CondKind::UserAgent | CondKind::Referer => {
            text.split_whitespace().map(str::to_string).collect()
        }
        _ => parse_list(text),
    };
    values.iter().map(|v| CondRow::value(kind, v)).collect()
}

fn distinct(values: impl Iterator<Item = String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for v in values {
        if !out.contains(&v) {
            out.push(v);
        }
    }
    out
}

// Blank rows are ignored and repeated values collapse, so only distinct lists reach the node.
pub fn rows_to_matchers(rows: &[CondRow]) -> Matchers {
    let of = |kind: CondKind| -> Vec<String> {
        distinct(
            rows.iter()
                .filter(|r| r.kind == kind && !r.is_blank())
                .map(CondRow::normalised),
        )
    };
    Matchers {
        path_prefixes: of(CondKind::PathPrefix),
        path_regexes: of(CondKind::PathRegex),
        user_agent_regexes: of(CondKind::UserAgent),
        referer_regexes: of(CondKind::Referer),
        methods: of(CondKind::Method),
        hosts: of(CondKind::Host),
        cidrs: of(CondKind::Cidr),
        scheme: of(CondKind::Scheme).into_iter().next(),
        headers: rows
            .iter()
            .filter(|r| r.kind == CondKind::Header && !r.is_blank())
            .map(header_match)
            .collect(),
    }
}

fn header_match(row: &CondRow) -> HeaderMatch {
    let value = row.value.trim().to_string();
    HeaderMatch {
        name: row.header.name.trim().to_string(),
        regex: row.header.regex.then(|| value.clone()),
        equals: (!row.header.regex).then_some(value),
        negate: row.header.negate,
        secret: row.header.secret,
    }
}

// The first problem in the list, or None; two different schemes can never both hold.
pub fn conditions_problem(rows: &[CondRow]) -> Option<String> {
    for (i, row) in rows.iter().enumerate().filter(|(_, r)| !r.is_blank()) {
        let single = rows_to_matchers(std::slice::from_ref(row));
        if let Some(bad) = matcher_problem(single) {
            return Some(format!("Condition {}: {bad}", i + 1));
        }
    }
    let schemes = distinct(
        rows.iter()
            .filter(|r| r.kind == CondKind::Scheme && !r.is_blank())
            .map(CondRow::normalised),
    );
    if schemes.len() > 1 {
        return Some(
            "A request is either http or https, so only one scheme condition can be used.".into(),
        );
    }
    if rows.iter().all(CondRow::is_blank) {
        return None;
    }
    matcher_problem(rows_to_matchers(rows))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderOpDraft {
    pub target: HeaderTarget,
    pub op: HeaderOpKind,
    pub name: String,
    pub value: String,
}

impl HeaderOpDraft {
    pub fn new() -> Self {
        Self {
            target: HeaderTarget::Response,
            op: HeaderOpKind::Set,
            name: String::new(),
            value: String::new(),
        }
    }
}

impl Default for HeaderOpDraft {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CorsDraft {
    pub origins: String,
    pub methods: String,
    pub allow_headers: String,
    pub expose_headers: String,
    pub credentials: bool,
    pub max_age: String,
}

#[derive(Clone, Debug)]
pub struct RuleDraft {
    pub name: String,
    pub label: String,
    pub site: String,
    pub kind: RuleKind,
    pub action: FirewallAction,
    pub conditions: Vec<CondRow>,
    pub redirect_to: String,
    pub redirect_status: u16,
    pub header_ops: Vec<HeaderOpDraft>,
    pub cors_on: bool,
    pub cors: CorsDraft,
}

impl Default for RuleDraft {
    fn default() -> Self {
        Self {
            name: String::new(),
            label: String::new(),
            site: String::new(),
            kind: RuleKind::Block,
            action: FirewallAction::Deny,
            conditions: Vec::new(),
            redirect_to: String::new(),
            redirect_status: 301,
            header_ops: Vec::new(),
            cors_on: false,
            cors: CorsDraft::default(),
        }
    }
}

fn some_trimmed(text: &str) -> Option<String> {
    Some(text.trim().to_string()).filter(|t| !t.is_empty())
}

pub fn parse_list(text: &str) -> Vec<String> {
    text.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn upper_list(text: &str) -> Vec<String> {
    parse_list(text)
        .into_iter()
        .map(|m| m.to_uppercase())
        .collect()
}

// Rows left completely blank are ignored, so an unused row never blocks the save.
pub fn build_header_ops(rows: &[HeaderOpDraft]) -> Result<Vec<HeaderOp>, String> {
    let mut out = Vec::new();
    for row in rows {
        let (name, value) = (row.name.trim(), row.value.trim());
        if name.is_empty() && value.is_empty() {
            continue;
        }
        if name.is_empty() {
            return Err("Every header change needs a header name.".into());
        }
        let value = match row.op {
            HeaderOpKind::Remove => None,
            _ if value.is_empty() => {
                return Err(format!(
                    "Header {name}: {} needs a value.",
                    op_label(row.op).to_lowercase()
                ));
            }
            _ => Some(value.to_string()),
        };
        out.push(HeaderOp {
            target: row.target,
            op: row.op,
            name: name.to_string(),
            value,
        });
    }
    if out.len() > MAX_HEADER_OPS {
        return Err(format!("Use at most {MAX_HEADER_OPS} header changes."));
    }
    Ok(out)
}

fn check_origin_shape(origin: &str) -> Result<(), String> {
    let rest = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"));
    match rest {
        Some(r) if !r.is_empty() && !r.contains(['/', '?', '#']) => Ok(()),
        _ => Err(format!(
            "Origin {origin} must look like https://app.example.com with no path."
        )),
    }
}

pub fn build_cors(c: &CorsDraft) -> Result<Cors, String> {
    let origins = parse_list(&c.origins);
    if origins.is_empty() {
        return Err("List at least one allowed origin, or * for any origin.".into());
    }
    if origins.len() > MAX_CORS_ENTRIES {
        return Err(format!("Use at most {MAX_CORS_ENTRIES} origins."));
    }
    let wildcard = origins.iter().any(|o| o == "*");
    if wildcard && origins.len() != 1 {
        return Err("The origin * must be the only origin.".into());
    }
    if wildcard && c.credentials {
        return Err(
            "Credentials cannot be combined with the origin *. List the exact origins instead."
                .into(),
        );
    }
    for origin in origins.iter().filter(|o| *o != "*") {
        check_origin_shape(origin)?;
    }
    let methods = upper_list(&c.methods);
    let allow_headers = parse_list(&c.allow_headers);
    let expose_headers = parse_list(&c.expose_headers);
    for (label, list) in [
        ("methods", &methods),
        ("allowed headers", &allow_headers),
        ("exposed headers", &expose_headers),
    ] {
        if list.len() > MAX_CORS_ENTRIES {
            return Err(format!("Use at most {MAX_CORS_ENTRIES} {label}."));
        }
    }
    let age = c.max_age.trim();
    let max_age_secs = if age.is_empty() {
        0
    } else {
        age.parse::<u32>()
            .ok()
            .filter(|n| *n <= MAX_CORS_MAX_AGE && age.bytes().all(|b| b.is_ascii_digit()))
            .ok_or_else(|| {
                format!("Max age must be a whole number of seconds up to {MAX_CORS_MAX_AGE}.")
            })?
    };
    Ok(Cors {
        origins,
        methods,
        allow_headers,
        expose_headers,
        credentials: c.credentials,
        max_age_secs,
    })
}

pub fn build_redirect(to: &str, status: u16) -> Result<Redirect, String> {
    let to = to.trim();
    if to.is_empty() {
        return Err("Enter where the redirect should send visitors.".into());
    }
    let shaped = to.starts_with('/')
        || to.starts_with("http://")
        || to.starts_with("https://")
        || to.starts_with("{scheme}://");
    if !shaped {
        return Err(
            "The target must be an absolute http or https URL or a path starting with /.".into(),
        );
    }
    if !REDIRECT_STATUSES.contains(&status) {
        return Err("The redirect status must be 301, 302, 307 or 308.".into());
    }
    Ok(Redirect {
        to: to.to_string(),
        status,
    })
}

// The connector's own validation has the last word, so the form can never accept what the node would refuse.
pub fn build_rule(d: &RuleDraft, suffix: &str) -> Result<FirewallRule, String> {
    let name = d.name.trim();
    if name.is_empty() {
        return Err("Give the rule a name.".into());
    }
    if let Some(problem) = conditions_problem(&d.conditions) {
        return Err(problem);
    }
    let mut rule = FirewallRule {
        id: format!("{}-{}", slugify(name), suffix.to_lowercase()),
        name: name.to_string(),
        enabled: true,
        matchers: rows_to_matchers(&d.conditions),
        site: some_trimmed(&d.site),
        label: some_trimmed(&d.label),
        ..FirewallRule::default()
    };
    match d.kind {
        RuleKind::Block => rule.action = Some(d.action),
        RuleKind::Redirect => {
            rule.redirect = Some(build_redirect(&d.redirect_to, d.redirect_status)?)
        }
        RuleKind::Effects => {
            rule.headers = build_header_ops(&d.header_ops)?;
            rule.cors = if d.cors_on {
                Some(build_cors(&d.cors)?)
            } else {
                None
            };
            if rule.headers.is_empty() && rule.cors.is_none() {
                return Err("Add a header change or turn on CORS.".into());
            }
        }
    }
    validate_rule(&rule).map_err(|e| e.to_string())?;
    Ok(rule)
}

pub fn rule_kind(rule: &FirewallRule) -> RuleKind {
    if rule.action.is_some() {
        RuleKind::Block
    } else if rule.redirect.is_some() {
        RuleKind::Redirect
    } else {
        RuleKind::Effects
    }
}

// The pill text and colour for the Action column of the rule list.
pub fn effect_pill(rule: &FirewallRule) -> (String, Tone) {
    match (rule_kind(rule), rule.action, &rule.redirect) {
        (RuleKind::Block, Some(a), _) => {
            (crate::model::action_label(a).to_string(), action_tone(a))
        }
        (RuleKind::Redirect, _, Some(r)) => (format!("Redirect {}", r.status), Tone::Info),
        _ => {
            let text = match (rule.headers.is_empty(), rule.cors.is_some()) {
                (false, true) => "Headers + CORS",
                (false, false) => "Headers",
                (true, true) => "CORS",
                (true, false) => "No effect",
            };
            (text.to_string(), Tone::Blue)
        }
    }
}

// A second line for the list: where a redirect goes or what the header and CORS parts do.
pub fn effect_detail(rule: &FirewallRule) -> Option<String> {
    if let Some(r) = &rule.redirect {
        return Some(format!("to {}", r.to));
    }
    let mut parts = Vec::new();
    for op in &rule.headers {
        parts.push(format!(
            "{} {} ({})",
            op_label(op.op).to_lowercase(),
            op.name,
            target_label(op.target).to_lowercase()
        ));
    }
    if let Some(c) = &rule.cors {
        let origins = if c.origins.len() > 2 {
            format!("{} origins", c.origins.len())
        } else {
            c.origins.join(", ")
        };
        parts.push(format!("cors for {origins}"));
    }
    (!parts.is_empty()).then(|| parts.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(kind: CondKind, value: &str) -> CondRow {
        CondRow::value(kind, value)
    }

    fn block() -> RuleDraft {
        RuleDraft {
            name: "Block WP".into(),
            conditions: vec![row(CondKind::PathRegex, "^/wp-")],
            ..RuleDraft::default()
        }
    }

    fn redirect() -> RuleDraft {
        RuleDraft {
            name: "To www".into(),
            kind: RuleKind::Redirect,
            redirect_to: "{scheme}://{www_host}{path}{query}".into(),
            ..RuleDraft::default()
        }
    }

    fn cors(origins: &str) -> RuleDraft {
        RuleDraft {
            name: "Api cors".into(),
            kind: RuleKind::Effects,
            cors_on: true,
            cors: CorsDraft {
                origins: origins.into(),
                ..CorsDraft::default()
            },
            ..RuleDraft::default()
        }
    }

    fn op(target: HeaderTarget, kind: HeaderOpKind, name: &str, value: &str) -> HeaderOpDraft {
        HeaderOpDraft {
            target,
            op: kind,
            name: name.into(),
            value: value.into(),
        }
    }

    #[test]
    fn same_kind_rows_are_listed_together_and_blanks_are_ignored() {
        let rows = vec![
            row(CondKind::PathPrefix, "/old"),
            row(CondKind::PathPrefix, " /older "),
            row(CondKind::PathPrefix, "/old"),
            row(CondKind::PathPrefix, "  "),
            row(CondKind::Method, "get"),
            row(CondKind::Method, "Post"),
            row(CondKind::Scheme, "https"),
            CondRow::header("", "", false, false, false),
        ];
        let m = rows_to_matchers(&rows);
        assert_eq!(m.path_prefixes, vec!["/old", "/older"]);
        assert_eq!(m.methods, vec!["GET", "POST"]);
        assert_eq!(m.scheme.as_deref(), Some("https"));
        assert!(m.headers.is_empty() && m.hosts.is_empty() && m.cidrs.is_empty());
        assert_eq!(rows_to_matchers(&[]), Matchers::default());
    }

    #[test]
    fn a_list_in_one_input_becomes_one_row_per_value() {
        let rows = rows_from_list(CondKind::PathRegex, "^/a ^/b\t ^/c");
        assert_eq!(rows.len(), 3);
        assert_eq!(rows_from_list(CondKind::PathRegex, "^/a{1,3}").len(), 1);
        assert_eq!(
            rows_from_list(CondKind::Cidr, "10.0.0.0/8, 192.168.0.0/16").len(),
            2
        );
        let d = RuleDraft {
            conditions: rows,
            ..block()
        };
        let rule = build_rule(&d, "x").expect("valid");
        assert_eq!(rule.matchers.path_regexes, vec!["^/a", "^/b", "^/c"]);
        assert!(rows_from_list(CondKind::Host, " , ").is_empty());
    }

    #[test]
    fn rows_are_checked_with_the_nodes_own_rules() {
        let problem = |r: CondRow| conditions_problem(&[r]);
        assert!(problem(row(CondKind::PathPrefix, "")).is_none());
        assert!(problem(row(CondKind::PathPrefix, "/ok")).is_none());
        assert!(problem(row(CondKind::PathPrefix, "nope")).is_some());
        assert!(problem(row(CondKind::PathRegex, "(")).is_some());
        assert!(problem(row(CondKind::Method, "G E T")).is_some());
        assert!(problem(row(CondKind::Host, "*.example.com")).is_none());
        assert!(problem(row(CondKind::Host, "not a host")).is_some());
        assert!(problem(row(CondKind::Cidr, "203.0.113.0/24")).is_none());
        assert!(problem(row(CondKind::Cidr, "203.0.113.0/99")).is_some());
        assert!(problem(row(CondKind::Scheme, "ftp")).is_some());
        assert!(problem(CondRow::header("X-A", "v", false, false, false)).is_none());
        assert!(problem(CondRow::header("X-A", "", false, false, false)).is_some());
        assert!(problem(CondRow::header("1bad", "v", false, false, false)).is_some());
        assert!(problem(CondRow::header("X-A", "^a", true, false, true)).is_some());
    }

    #[test]
    fn the_list_checks_name_the_row_and_apply_the_node_limits() {
        let rows = vec![
            row(CondKind::PathPrefix, "/ok"),
            row(CondKind::Host, "bad host"),
        ];
        assert!(
            conditions_problem(&rows)
                .unwrap()
                .starts_with("Condition 2:")
        );
        let two = vec![
            row(CondKind::Scheme, "http"),
            row(CondKind::Scheme, "https"),
        ];
        assert!(
            conditions_problem(&two)
                .unwrap()
                .contains("only one scheme")
        );
        let many: Vec<CondRow> = (0..40)
            .map(|i| row(CondKind::PathPrefix, &format!("/p{i}")))
            .collect();
        assert!(conditions_problem(&many).unwrap().contains("at most"));
        assert!(conditions_problem(&[]).is_none());
    }

    #[test]
    fn block_rules_keep_their_action_and_matchers() {
        let d = RuleDraft {
            action: FirewallAction::Drop,
            conditions: vec![
                row(CondKind::PathRegex, "^/wp-"),
                row(CondKind::Method, "get"),
                row(CondKind::Method, "post"),
            ],
            ..block()
        };
        let rule = build_rule(&d, "AB12").expect("valid");
        assert_eq!(rule.id, "block-wp-ab12");
        assert_eq!(rule.action, Some(FirewallAction::Drop));
        assert_eq!(rule.matchers.methods, vec!["GET", "POST"]);
        assert!(rule.redirect.is_none() && rule.headers.is_empty() && rule.cors.is_none());
        assert_eq!(rule_kind(&rule), RuleKind::Block);
        assert!(build_rule(&RuleDraft::default(), "x").is_err());
        let empty = RuleDraft {
            name: "Nothing".into(),
            ..RuleDraft::default()
        };
        assert!(build_rule(&empty, "x").unwrap_err().contains("matcher"));
    }

    #[test]
    fn redirect_rules_carry_a_template_and_a_status() {
        let rule = build_rule(&redirect(), "r1").expect("valid");
        assert_eq!(rule.action, None);
        let r = rule.redirect.clone().expect("redirect");
        assert_eq!(
            (r.to.as_str(), r.status),
            ("{scheme}://{www_host}{path}{query}", 301)
        );
        assert_eq!(rule_kind(&rule), RuleKind::Redirect);
        let temp = RuleDraft {
            redirect_status: 307,
            ..redirect()
        };
        assert_eq!(
            build_rule(&temp, "r1")
                .expect("valid")
                .redirect
                .expect("r")
                .status,
            307
        );
        let bad_status = RuleDraft {
            redirect_status: 303,
            ..redirect()
        };
        assert!(build_rule(&bad_status, "r").unwrap_err().contains("301"));
    }

    #[test]
    fn redirect_targets_are_checked_here_and_by_the_connector() {
        let blank = RuleDraft {
            redirect_to: "  ".into(),
            ..redirect()
        };
        assert!(build_rule(&blank, "r").unwrap_err().contains("Enter where"));
        let shapeless = RuleDraft {
            redirect_to: "relative/path".into(),
            ..redirect()
        };
        assert!(
            build_rule(&shapeless, "r")
                .unwrap_err()
                .contains("absolute")
        );
        let unknown = RuleDraft {
            redirect_to: "https://example.com/{nope}".into(),
            conditions: vec![row(CondKind::PathPrefix, "/old")],
            ..redirect()
        };
        assert!(build_rule(&unknown, "r").unwrap_err().contains("{nope}"));
        let loops = RuleDraft {
            redirect_to: "/new".into(),
            ..redirect()
        };
        assert!(build_rule(&loops, "r").unwrap_err().contains("loop"));
        let fine = RuleDraft {
            redirect_to: "/new".into(),
            conditions: vec![row(CondKind::PathPrefix, "/old")],
            ..redirect()
        };
        assert!(build_rule(&fine, "r").is_ok());
        let upgrade = RuleDraft {
            redirect_to: "https://{host}{path}{query}".into(),
            conditions: vec![row(CondKind::Scheme, "http")],
            ..redirect()
        };
        assert!(build_rule(&upgrade, "r").is_ok());
        let no_scheme = RuleDraft {
            conditions: Vec::new(),
            ..upgrade
        };
        assert!(build_rule(&no_scheme, "r").unwrap_err().contains("scheme"));
    }

    #[test]
    fn header_rules_need_at_least_one_change() {
        let none = RuleDraft {
            name: "Headers".into(),
            kind: RuleKind::Effects,
            header_ops: vec![HeaderOpDraft::new()],
            ..RuleDraft::default()
        };
        assert!(
            build_rule(&none, "h")
                .unwrap_err()
                .contains("Add a header change")
        );
        let ok = RuleDraft {
            header_ops: vec![
                op(
                    HeaderTarget::Response,
                    HeaderOpKind::Set,
                    "X-Frame-Options",
                    "DENY",
                ),
                op(
                    HeaderTarget::Request,
                    HeaderOpKind::Remove,
                    "Cookie",
                    "ignored",
                ),
                HeaderOpDraft::new(),
            ],
            ..none
        };
        let rule = build_rule(&ok, "h").expect("valid");
        assert_eq!(rule.headers.len(), 2);
        assert_eq!(rule.headers[1].value, None);
        assert_eq!(rule_kind(&rule), RuleKind::Effects);
    }

    #[test]
    fn header_changes_are_checked_for_names_values_and_caps() {
        let rows = |r: Vec<HeaderOpDraft>| build_header_ops(&r);
        assert!(rows(vec![op(HeaderTarget::Response, HeaderOpKind::Set, "", "x")]).is_err());
        let missing = rows(vec![op(
            HeaderTarget::Response,
            HeaderOpKind::Add,
            "X-A",
            " ",
        )]);
        assert!(missing.unwrap_err().contains("needs a value"));
        let many: Vec<_> = (0..=MAX_HEADER_OPS)
            .map(|i| {
                op(
                    HeaderTarget::Response,
                    HeaderOpKind::Set,
                    &format!("X-H{i}"),
                    "v",
                )
            })
            .collect();
        assert!(rows(many).unwrap_err().contains("at most 16"));
        let reserved = RuleDraft {
            name: "Bad".into(),
            kind: RuleKind::Effects,
            header_ops: vec![op(HeaderTarget::Response, HeaderOpKind::Set, "Host", "x")],
            ..RuleDraft::default()
        };
        assert!(build_rule(&reserved, "h").is_err());
    }

    #[test]
    fn cors_refuses_a_wildcard_with_credentials() {
        let d = RuleDraft {
            cors: CorsDraft {
                origins: "*".into(),
                credentials: true,
                ..CorsDraft::default()
            },
            ..cors("*")
        };
        assert!(build_rule(&d, "c").unwrap_err().contains("Credentials"));
        let listed = RuleDraft {
            cors: CorsDraft {
                origins: "https://app.example.com".into(),
                credentials: true,
                ..CorsDraft::default()
            },
            ..cors("")
        };
        assert!(build_rule(&listed, "c").is_ok());
        assert!(build_rule(&cors("*"), "c").is_ok());
    }

    #[test]
    fn cors_origins_must_be_exact_and_bounded() {
        assert!(
            build_cors(&CorsDraft::default())
                .unwrap_err()
                .contains("at least one")
        );
        let e = |o: &str| {
            build_cors(&CorsDraft {
                origins: o.into(),
                ..CorsDraft::default()
            })
        };
        assert!(
            e("* https://a.example.com")
                .unwrap_err()
                .contains("only origin")
        );
        for bad in [
            "app.example.com",
            "https://a.example.com/x",
            "ftp://a.example.com",
            "https://",
        ] {
            assert!(e(bad).is_err(), "{bad}");
        }
        let many = (0..=MAX_CORS_ENTRIES)
            .map(|i| format!("https://a{i}.example.com"))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(e(&many).unwrap_err().contains("at most 32"));
        let ok = e("https://a.example.com http://b.example.com:8080").expect("ok");
        assert_eq!(ok.origins.len(), 2);
    }

    #[test]
    fn cors_lists_and_max_age_are_parsed_and_capped() {
        let c = build_cors(&CorsDraft {
            origins: "https://a.example.com".into(),
            methods: "get, post".into(),
            allow_headers: "Authorization, X-Trace".into(),
            expose_headers: "X-Total".into(),
            credentials: true,
            max_age: " 600 ".into(),
        })
        .expect("cors");
        assert_eq!(c.methods, vec!["GET", "POST"]);
        assert_eq!(c.allow_headers, vec!["Authorization", "X-Trace"]);
        assert_eq!(c.max_age_secs, 600);
        assert!(c.credentials);
        let age = |a: &str| {
            build_cors(&CorsDraft {
                origins: "*".into(),
                max_age: a.into(),
                ..CorsDraft::default()
            })
        };
        assert_eq!(age("").expect("empty").max_age_secs, 0);
        assert_eq!(age("86400").expect("cap").max_age_secs, 86_400);
        for bad in ["86401", "-1", "1.5", "soon"] {
            assert!(age(bad).is_err(), "{bad}");
        }
        let long = CorsDraft {
            origins: "*".into(),
            methods: (0..=MAX_CORS_ENTRIES)
                .map(|_| "GET")
                .collect::<Vec<_>>()
                .join(" "),
            ..CorsDraft::default()
        };
        assert!(
            build_cors(&long)
                .unwrap_err()
                .contains("at most 32 methods")
        );
    }

    #[test]
    fn header_conditions_compare_equality_or_a_regex() {
        let value = crate::testkit::joined(&["gate", "-value-", "123"]);
        let eq = RuleDraft {
            conditions: vec![CondRow::header("X-Beta", &value, false, true, true)],
            ..block()
        };
        let rule = build_rule(&eq, "m").expect("valid");
        let h = &rule.matchers.headers[0];
        assert!(h.equals.as_deref() == Some(value.as_str()), "values differ");
        assert!(h.regex.is_none() && h.negate && h.secret);
        let re = RuleDraft {
            conditions: vec![CondRow::header("X-Beta", "^beta", true, false, false)],
            ..block()
        };
        let rule = build_rule(&re, "m").expect("valid");
        let h = &rule.matchers.headers[0];
        assert_eq!(h.regex.as_deref(), Some("^beta"));
        assert!(h.equals.is_none() && !h.secret);
    }

    #[test]
    fn a_rejected_secret_value_is_never_echoed() {
        let d = RuleDraft {
            conditions: vec![CondRow::header(
                "X-Beta",
                "bad value with spaces",
                false,
                false,
                true,
            )],
            ..block()
        };
        let err = build_rule(&d, "m").unwrap_err();
        assert!(!err.contains("bad value"), "{err}");
    }

    #[test]
    fn rows_never_debug_print_a_secret_value() {
        let value = crate::testkit::joined(&["hidden", "-matcher", "-value"]);
        let secret = CondRow::header("X-Beta", &value, false, false, true);
        assert!(!format!("{secret:?}").contains(value.as_str()));
        let open = CondRow::header("X-Beta", &value, false, false, false);
        assert!(format!("{open:?}").contains(value.as_str()));
        let d = RuleDraft {
            conditions: vec![secret],
            ..block()
        };
        assert!(!format!("{d:?}").contains(value.as_str()));
    }

    #[test]
    fn rules_are_scoped_and_labelled_when_asked() {
        let d = RuleDraft {
            site: " shop ".into(),
            label: "wp-probe".into(),
            ..block()
        };
        let rule = build_rule(&d, "x").expect("valid");
        assert_eq!(rule.site.as_deref(), Some("shop"));
        assert_eq!(rule.label.as_deref(), Some("wp-probe"));
        let bad_site = RuleDraft {
            site: "Not A Site".into(),
            ..block()
        };
        assert!(build_rule(&bad_site, "x").is_err());
    }

    #[test]
    fn the_list_shows_the_effect_of_each_rule_kind() {
        let blocked = build_rule(&block(), "a").expect("valid");
        assert_eq!(effect_pill(&blocked), ("Deny".to_string(), Tone::Bad));
        assert_eq!(effect_detail(&blocked), None);

        let moved = build_rule(&redirect(), "b").expect("valid");
        assert_eq!(
            effect_pill(&moved),
            ("Redirect 301".to_string(), Tone::Info)
        );
        assert!(
            effect_detail(&moved)
                .expect("detail")
                .starts_with("to {scheme}://")
        );

        let both = RuleDraft {
            header_ops: vec![op(
                HeaderTarget::Response,
                HeaderOpKind::Set,
                "X-Frame-Options",
                "DENY",
            )],
            ..cors("https://a.example.com")
        };
        let rule = build_rule(&both, "c").expect("valid");
        assert_eq!(effect_pill(&rule).0, "Headers + CORS");
        let detail = effect_detail(&rule).expect("detail");
        assert!(
            detail.contains("set X-Frame-Options (response)")
                && detail.contains("cors for https://a.example.com")
        );

        let only_cors = build_rule(&cors("*"), "d").expect("valid");
        assert_eq!(effect_pill(&only_cors), ("CORS".to_string(), Tone::Blue));
        let many = RuleDraft {
            cors: CorsDraft {
                origins: "https://a.example.com https://b.example.com https://c.example.com".into(),
                ..CorsDraft::default()
            },
            ..cors("")
        };
        let rule = build_rule(&many, "e").expect("valid");
        assert!(effect_detail(&rule).expect("detail").contains("3 origins"));
    }

    #[test]
    fn kinds_and_choices_have_labels() {
        for kind in [RuleKind::Block, RuleKind::Redirect, RuleKind::Effects] {
            assert!(!kind.label().is_empty() && !kind.help().is_empty());
        }
        assert_eq!(op_label(HeaderOpKind::Remove), "Remove");
        assert_eq!(target_label(HeaderTarget::Request), "Request");
        assert!(REDIRECT_PLACEHOLDERS.contains("{www_host}"));
        assert!(REDIRECT_EXAMPLES.iter().all(|e| !e.is_empty()));
        assert_eq!(action_tone(FirewallAction::Tarpit), Tone::Info);
    }
}
