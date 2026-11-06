use std::fmt;

use cite_edge::model::{
    Cors, FirewallAction, FirewallRule, HeaderMatch, HeaderOp, HeaderOpKind, HeaderTarget,
    Matchers, Redirect,
};
use cite_edge::validate::validate_rule;

use crate::model::slugify;
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

#[derive(Clone)]
pub struct RuleDraft {
    pub name: String,
    pub label: String,
    pub site: String,
    pub kind: RuleKind,
    pub action: FirewallAction,
    pub path_regex: String,
    pub path_prefix: String,
    pub methods: String,
    pub user_agent_regex: String,
    pub cidrs: String,
    pub host: String,
    pub header_name: String,
    pub header_value: String,
    pub header_regex: bool,
    pub header_negate: bool,
    pub header_secret: bool,
    pub scheme: Option<String>,
    pub referer_regex: String,
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
            path_regex: String::new(),
            path_prefix: String::new(),
            methods: String::new(),
            user_agent_regex: String::new(),
            cidrs: String::new(),
            host: String::new(),
            header_name: String::new(),
            header_value: String::new(),
            header_regex: false,
            header_negate: false,
            header_secret: false,
            scheme: None,
            referer_regex: String::new(),
            redirect_to: String::new(),
            redirect_status: 301,
            header_ops: Vec::new(),
            cors_on: false,
            cors: CorsDraft::default(),
        }
    }
}

// A secret matcher value never reaches Debug output, so a logged draft cannot leak it.
impl fmt::Debug for RuleDraft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = if self.header_secret {
            "[redacted]"
        } else {
            self.header_value.as_str()
        };
        f.debug_struct("RuleDraft")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("header_name", &self.header_name)
            .field("header_value", &value)
            .field("header_secret", &self.header_secret)
            .finish_non_exhaustive()
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

pub fn build_header_match(d: &RuleDraft) -> Result<Option<HeaderMatch>, String> {
    let name = d.header_name.trim();
    let value = d.header_value.trim();
    if name.is_empty() {
        if value.is_empty() {
            return Ok(None);
        }
        return Err("Enter the header name to compare the value with.".into());
    }
    if value.is_empty() {
        return Err("Enter the header value to compare.".into());
    }
    if d.header_secret && d.header_regex {
        return Err(
            "A secret header value can only be compared for equality, not as a regex.".into(),
        );
    }
    Ok(Some(HeaderMatch {
        name: name.to_string(),
        regex: d.header_regex.then(|| value.to_string()),
        equals: (!d.header_regex).then(|| value.to_string()),
        negate: d.header_negate,
        secret: d.header_secret,
    }))
}

pub fn build_matchers(d: &RuleDraft) -> Result<Matchers, String> {
    Ok(Matchers {
        path_regex: some_trimmed(&d.path_regex),
        path_prefix: some_trimmed(&d.path_prefix),
        methods: upper_list(&d.methods),
        user_agent_regex: some_trimmed(&d.user_agent_regex),
        cidrs: parse_list(&d.cidrs),
        host: some_trimmed(&d.host),
        header: build_header_match(d)?,
        scheme: d.scheme.clone(),
        referer_regex: some_trimmed(&d.referer_regex),
    })
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
    let mut rule = FirewallRule {
        id: format!("{}-{}", slugify(name), suffix.to_lowercase()),
        name: name.to_string(),
        enabled: true,
        matchers: build_matchers(d)?,
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

    fn block() -> RuleDraft {
        RuleDraft {
            name: "Block WP".into(),
            path_regex: "^/wp-".into(),
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
    fn block_rules_keep_their_action_and_matchers() {
        let d = RuleDraft {
            action: FirewallAction::Drop,
            methods: "get, post".into(),
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
            path_prefix: "/old".into(),
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
            path_prefix: "/old".into(),
            ..redirect()
        };
        assert!(build_rule(&fine, "r").is_ok());
        let upgrade = RuleDraft {
            redirect_to: "https://{host}{path}{query}".into(),
            scheme: Some("http".into()),
            ..redirect()
        };
        assert!(build_rule(&upgrade, "r").is_ok());
        let no_scheme = RuleDraft {
            scheme: None,
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
    fn header_matchers_compare_equality_or_a_regex() {
        let eq = RuleDraft {
            header_name: "X-Beta".into(),
            header_value: crate::testkit::joined(&["gate", "-value-", "123"]),
            header_negate: true,
            header_secret: true,
            ..block()
        };
        let rule = build_rule(&eq, "m").expect("valid");
        let h = rule.matchers.header.expect("header");
        assert!(
            h.equals.as_deref() == Some(eq.header_value.as_str()),
            "values differ"
        );
        assert!(h.regex.is_none() && h.negate && h.secret);
        let re = RuleDraft {
            header_name: "X-Beta".into(),
            header_value: "^beta".into(),
            header_regex: true,
            ..block()
        };
        let h = build_rule(&re, "m")
            .expect("valid")
            .matchers
            .header
            .expect("h");
        assert_eq!(h.regex.as_deref(), Some("^beta"));
        assert!(h.equals.is_none() && !h.secret);
    }

    #[test]
    fn header_matcher_mistakes_are_explained() {
        let secret_regex = RuleDraft {
            header_name: "X-A".into(),
            header_value: "^a".into(),
            header_regex: true,
            header_secret: true,
            ..block()
        };
        assert!(
            build_rule(&secret_regex, "m")
                .unwrap_err()
                .contains("equality")
        );
        let no_value = RuleDraft {
            header_name: "X-A".into(),
            ..block()
        };
        assert!(
            build_rule(&no_value, "m")
                .unwrap_err()
                .contains("header value")
        );
        let no_name = RuleDraft {
            header_value: "v".into(),
            ..block()
        };
        assert!(
            build_rule(&no_name, "m")
                .unwrap_err()
                .contains("header name")
        );
        let bad_name = RuleDraft {
            header_name: "1bad name".into(),
            header_value: "v".into(),
            ..block()
        };
        assert!(build_rule(&bad_name, "m").is_err());
    }

    #[test]
    fn a_rejected_secret_value_is_never_echoed() {
        let d = RuleDraft {
            header_name: "X-Beta".into(),
            header_value: "bad value with spaces".into(),
            header_secret: true,
            ..block()
        };
        let err = build_rule(&d, "m").unwrap_err();
        assert!(!err.contains("bad value"), "{err}");
    }

    #[test]
    fn scheme_and_referer_matchers_are_carried() {
        let d = RuleDraft {
            scheme: Some("https".into()),
            referer_regex: "spam\\.example".into(),
            path_regex: String::new(),
            ..block()
        };
        let m = build_rule(&d, "s").expect("valid").matchers;
        assert_eq!(m.scheme.as_deref(), Some("https"));
        assert_eq!(m.referer_regex.as_deref(), Some("spam\\.example"));
    }

    #[test]
    fn drafts_never_debug_print_a_secret_value() {
        let d = RuleDraft {
            header_name: "X-Beta".into(),
            header_value: crate::testkit::joined(&["hidden", "-matcher", "-value"]),
            header_secret: true,
            ..block()
        };
        let value = d.header_value.clone();
        assert!(!format!("{d:?}").contains(value.as_str()));
        let open = RuleDraft {
            header_secret: false,
            ..d
        };
        assert!(format!("{open:?}").contains(value.as_str()));
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
        for example in REDIRECT_EXAMPLES {
            assert!(!example.is_empty());
        }
        assert_eq!(action_tone(FirewallAction::Tarpit), Tone::Info);
    }
}
