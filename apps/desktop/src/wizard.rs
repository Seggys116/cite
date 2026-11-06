use crate::certs::{AccessDraft, bots_label};
use crate::model::{
    SiteDraft, SourceKind, branch_problem, clean_list, github_problem, health_problem,
    normalize_repo, parse_hosts, parse_targets, paths_problem, poll_problem, repo_problem,
};

// The create-site wizard shows one decision per step and nothing from the branch not taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Source,
    Setup,
    Domains,
    Protection,
    Where,
}

pub const STEPS: [Step; 5] = [
    Step::Source,
    Step::Setup,
    Step::Domains,
    Step::Protection,
    Step::Where,
];

impl Step {
    pub fn index(self) -> usize {
        STEPS.iter().position(|s| *s == self).unwrap_or(0)
    }

    pub fn next(self) -> Step {
        STEPS[(self.index() + 1).min(STEPS.len() - 1)]
    }

    pub fn prev(self) -> Step {
        STEPS[self.index().saturating_sub(1)]
    }

    pub fn is_last(self) -> bool {
        self == Step::Where
    }

    pub fn title(self, source: SourceKind) -> &'static str {
        match (self, source) {
            (Step::Source, _) => "Source",
            (Step::Setup, SourceKind::Github) => "Repository",
            (Step::Setup, SourceKind::Servers) => "Servers",
            (Step::Domains, _) => "Domains",
            (Step::Protection, _) => "Protection",
            (Step::Where, _) => "Place and review",
        }
    }

    pub fn heading(self, source: SourceKind) -> &'static str {
        match (self, source) {
            (Step::Source, _) => "Where does the site come from?",
            (Step::Setup, SourceKind::Github) => "Which repository should the node build?",
            (Step::Setup, SourceKind::Servers) => "Which servers should receive the traffic?",
            (Step::Domains, _) => "Which domains reach this site?",
            (Step::Protection, _) => "How should visitors be allowed in?",
            (Step::Where, _) => "Which nodes get the site?",
        }
    }
}

pub const TOKEN_HELP_NODE: &str =
    "This node already has a GitHub token (CITE_GITHUB_TOKEN). Leave this empty to use it.";
pub const TOKEN_HELP_NONE: &str = "Fine-grained token with Contents: read for this repository. Better: set CITE_GITHUB_TOKEN on the node once. Stored only on the node.";
pub const TOKEN_HELP_MIXED: &str = "Some of the chosen nodes have no GitHub token of their own, so this token is stored on every chosen node. Better: set CITE_GITHUB_TOKEN on each node once.";
pub const TOKEN_TOGGLE: &str = "Use a different token for this site";

// What the GitHub token control shows for the chosen nodes; true means that node has its own token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenView {
    pub offer_toggle: bool,
    pub show_field: bool,
    pub required: bool,
    pub help: &'static str,
}

pub fn token_view(configured: &[bool], use_own: bool, typed: &str) -> TokenView {
    let all_have = !configured.is_empty() && configured.iter().all(|c| *c);
    if all_have {
        return TokenView {
            offer_toggle: true,
            show_field: use_own,
            required: use_own && typed.trim().is_empty(),
            help: TOKEN_HELP_NODE,
        };
    }
    let mixed = configured.iter().any(|c| *c);
    TokenView {
        offer_toggle: false,
        show_field: true,
        required: typed.trim().is_empty(),
        help: if mixed {
            TOKEN_HELP_MIXED
        } else {
            TOKEN_HELP_NONE
        },
    }
}

// A hidden field never contributes a token, even if something was typed before it was hidden.
pub fn effective_token(view: &TokenView, typed: &str) -> String {
    if view.show_field {
        typed.trim().to_string()
    } else {
        String::new()
    }
}

fn id_problem(id: &str) -> Option<String> {
    let ok = !id.is_empty()
        && id.len() <= 40
        && !id.starts_with('-')
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    (!ok).then(|| "The site id must be lowercase letters, digits and dashes.".to_string())
}

fn host_problem(host: &str) -> Option<String> {
    let name = host.strip_prefix("*.").unwrap_or(host);
    let ok = !name.is_empty()
        && !name.starts_with(['.', '-'])
        && !name.ends_with(['.', '-'])
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    (!ok).then(|| format!("\"{host}\" is not a valid host name."))
}

// Next stays disabled until this returns None for the visible step.
pub fn step_problem(step: Step, d: &SiteDraft, picked: usize, token: &TokenView) -> Option<String> {
    match step {
        Step::Source | Step::Protection => None,
        Step::Setup => match d.source {
            SourceKind::Github => github_problem(d),
            SourceKind::Servers => servers_problem(d),
        },
        Step::Domains => {
            if d.name.trim().is_empty() {
                return Some("Give the site a name.".into());
            }
            if let Some(p) = id_problem(d.id.trim()) {
                return Some(p);
            }
            let hosts = parse_hosts(&d.hosts);
            if hosts.is_empty() {
                return Some("Add at least one host name.".into());
            }
            if let Some(p) = hosts.iter().find_map(|h| host_problem(h)) {
                return Some(p);
            }
            paths_problem(
                &clean_list(d.path_prefixes.iter().cloned()),
                &clean_list(d.path_regexes.iter().cloned()),
            )
            .map(|p| format!("The routing paths are not valid: {p}"))
        }
        Step::Where => {
            if picked == 0 {
                return Some("Pick at least one node.".into());
            }
            (d.source == SourceKind::Github && token.required).then(|| {
                "A chosen node has no GitHub token. Go back to Repository and enter one.".into()
            })
        }
    }
}

fn servers_problem(d: &SiteDraft) -> Option<String> {
    match parse_targets(&d.blue) {
        Err(e) => return Some(e),
        Ok(t) if t.is_empty() => return Some("Add at least one blue target.".into()),
        Ok(_) => {}
    }
    if let Err(e) = parse_targets(&d.green) {
        return Some(e);
    }
    health_problem(d)
}

// Problems per field, so both the wizard and the edit form can show them next to the field they belong to.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct FieldProblems {
    pub name: Option<String>,
    pub id: Option<String>,
    pub hosts: Option<String>,
    pub paths: Option<String>,
    pub repo: Option<String>,
    pub branch: Option<String>,
    pub poll: Option<String>,
    pub health: Option<String>,
}

impl FieldProblems {
    pub fn first(&self) -> Option<&String> {
        [
            &self.name,
            &self.id,
            &self.hosts,
            &self.paths,
            &self.repo,
            &self.branch,
            &self.poll,
            &self.health,
        ]
        .into_iter()
        .find_map(Option::as_ref)
    }
}

// The source fields are only checked for sites built from GitHub; the id only when it can still be chosen.
pub fn field_problems(d: &SiteDraft, check_id: bool) -> FieldProblems {
    let github = d.source == SourceKind::Github;
    let hosts = parse_hosts(&d.hosts);
    let prefixes = clean_list(d.path_prefixes.iter().cloned());
    let regexes = clean_list(d.path_regexes.iter().cloned());
    FieldProblems {
        name: d
            .name
            .trim()
            .is_empty()
            .then(|| "Give the site a name.".into()),
        id: if check_id {
            id_problem(d.id.trim())
        } else {
            None
        },
        hosts: if hosts.is_empty() {
            Some("Add at least one host name.".into())
        } else {
            hosts.iter().find_map(|h| host_problem(h))
        },
        paths: paths_problem(&prefixes, &regexes)
            .map(|p| format!("The routing paths are not valid: {p}")),
        repo: if github { repo_problem(&d.repo) } else { None },
        branch: if github {
            branch_problem(&d.branch)
        } else {
            None
        },
        poll: if github {
            poll_problem(&d.poll_interval)
        } else {
            None
        },
        health: health_problem(d),
    }
}

// The first step from the start that is not valid, used to stop a jump to the end with a bad earlier answer.
pub fn first_blocked(d: &SiteDraft, picked: usize, token: &TokenView) -> Option<(Step, String)> {
    STEPS
        .iter()
        .find_map(|s| step_problem(*s, d, picked, token).map(|p| (*s, p)))
}

pub fn protection_summary(a: &AccessDraft) -> String {
    let mut parts = Vec::new();
    parts.push(if a.cloudflare_only {
        "Only through the Cloudflare proxy"
    } else {
        "Open to any visitor"
    });
    if a.cloudflare_only && a.flexible {
        parts.push("Cloudflare handles HTTPS");
    } else {
        parts.push("Node serves HTTPS");
    }
    if a.cloudflare_only && a.zone_lock {
        parts.push("Only my Cloudflare account");
    }
    let bots = bots_label(a.bots);
    let mut text = parts.join(", ");
    text.push_str(". Bots: ");
    text.push_str(&bots.to_lowercase());
    text.push('.');
    text
}

// Plain words for the optional routing paths; either kind alone or both match a request.
pub fn paths_summary(prefixes: &[String], regexes: &[String]) -> String {
    let prefixes = clean_list(prefixes.iter().cloned());
    let regexes = clean_list(regexes.iter().cloned());
    let mut parts = Vec::new();
    if !prefixes.is_empty() {
        parts.push(format!("starts with {}", prefixes.join(" or ")));
    }
    if !regexes.is_empty() {
        parts.push(format!("matches {}", regexes.join(" or ")));
    }
    if parts.is_empty() {
        "Every path".to_string()
    } else {
        format!("Paths whose path {}", parts.join(", or "))
    }
}

// The label and value rows of the review on the last step.
pub fn review_rows(d: &SiteDraft, nodes: &[String]) -> Vec<(&'static str, String)> {
    let mut rows = vec![("Name", format!("{} ({})", d.name.trim(), d.id.trim()))];
    match d.source {
        SourceKind::Github => {
            let runtime = d.runtime.trim();
            let version = if runtime == "rust" {
                String::new()
            } else {
                format!(" {}", d.node_major)
            };
            rows.push((
                "Source",
                format!(
                    "GitHub {} on {}, {runtime}{version}, checked every {}",
                    normalize_repo(&d.repo),
                    d.branch.trim(),
                    d.poll_interval.trim()
                ),
            ));
        }
        SourceKind::Servers => rows.push(("Servers", d.blue.trim().to_string())),
    }
    rows.push(("Domains", parse_hosts(&d.hosts).join(", ")));
    rows.push(("Paths", paths_summary(&d.path_prefixes, &d.path_regexes)));
    rows.push(("Protection", protection_summary(&d.access)));
    rows.push(("Nodes", nodes.join(", ")));
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    fn github() -> SiteDraft {
        SiteDraft {
            source: SourceKind::Github,
            name: "Shop".into(),
            id: "shop".into(),
            hosts: "shop.example.com".into(),
            repo: "acme/shop".into(),
            branch: "main".into(),
            runtime: "node".into(),
            node_major: 22,
            poll_interval: "5m".into(),
            health_path: "/".into(),
            ..SiteDraft::default()
        }
    }

    fn servers() -> SiteDraft {
        SiteDraft {
            source: SourceKind::Servers,
            blue: "10.0.0.1:8080".into(),
            ..github()
        }
    }

    fn quiet() -> TokenView {
        token_view(&[true], false, "")
    }

    #[test]
    fn steps_walk_forward_and_back_within_bounds() {
        assert_eq!(Step::Source.prev(), Step::Source);
        assert_eq!(Step::Source.next(), Step::Setup);
        assert_eq!(Step::Where.next(), Step::Where);
        assert!(Step::Where.is_last() && !Step::Domains.is_last());
        for (i, s) in STEPS.iter().enumerate() {
            assert_eq!(s.index(), i);
        }
    }

    #[test]
    fn setup_step_names_follow_the_chosen_source() {
        assert_eq!(Step::Setup.title(SourceKind::Github), "Repository");
        assert_eq!(Step::Setup.title(SourceKind::Servers), "Servers");
        assert!(!Step::Setup.heading(SourceKind::Github).contains("server"));
        assert!(
            !Step::Setup
                .heading(SourceKind::Servers)
                .contains("repository")
        );
    }

    #[test]
    fn github_setup_ignores_upstreams_and_servers_ignore_github() {
        let mut g = github();
        g.blue.clear();
        assert!(step_problem(Step::Setup, &g, 1, &quiet()).is_none());
        g.repo = "nope".into();
        assert!(step_problem(Step::Setup, &g, 1, &quiet()).is_some());
        let mut s = servers();
        s.repo.clear();
        assert!(step_problem(Step::Setup, &s, 1, &quiet()).is_none());
        s.blue.clear();
        assert!(
            step_problem(Step::Setup, &s, 1, &quiet())
                .unwrap()
                .contains("blue")
        );
        s.blue = "10.0.0.1".into();
        assert!(step_problem(Step::Setup, &s, 1, &quiet()).is_some());
        s.blue = "10.0.0.1:80".into();
        s.health_path = "health".into();
        assert!(
            step_problem(Step::Setup, &s, 1, &quiet())
                .unwrap()
                .contains("health")
        );
    }

    #[test]
    fn domains_step_checks_name_id_hosts_and_path() {
        let mut d = github();
        assert!(step_problem(Step::Domains, &d, 1, &quiet()).is_none());
        d.name = " ".into();
        assert!(
            step_problem(Step::Domains, &d, 1, &quiet())
                .unwrap()
                .contains("name")
        );
        d = github();
        d.id = "Bad Id".into();
        assert!(
            step_problem(Step::Domains, &d, 1, &quiet())
                .unwrap()
                .contains("id")
        );
        d = github();
        d.hosts = "".into();
        assert!(
            step_problem(Step::Domains, &d, 1, &quiet())
                .unwrap()
                .contains("host")
        );
        d.hosts = "bad_host!".into();
        assert!(
            step_problem(Step::Domains, &d, 1, &quiet())
                .unwrap()
                .contains("bad_host!")
        );
        d.hosts = "*.example.com".into();
        assert!(step_problem(Step::Domains, &d, 1, &quiet()).is_none());
        d.path_regexes = vec!["(".into()];
        assert!(
            step_problem(Step::Domains, &d, 1, &quiet())
                .unwrap()
                .contains("routing paths")
        );
        d.path_regexes = vec!["^/api/".into(), "^/v[0-9]+/".into()];
        d.path_prefixes = vec!["/static".into(), "/assets".into(), "".into()];
        assert!(step_problem(Step::Domains, &d, 1, &quiet()).is_none());
        d.path_prefixes = vec!["static".into()];
        assert!(step_problem(Step::Domains, &d, 1, &quiet()).is_some());
    }

    #[test]
    fn paths_are_described_in_plain_words() {
        assert_eq!(paths_summary(&[], &[]), "Every path");
        let both = paths_summary(&["/a".into(), "/b".into()], &["^/c".into()]);
        assert_eq!(
            both,
            "Paths whose path starts with /a or /b, or matches ^/c"
        );
        assert!(paths_summary(&[" ".into()], &[]).contains("Every"));
    }

    #[test]
    fn the_last_step_needs_a_node_and_a_token_where_one_is_missing() {
        let d = github();
        assert!(step_problem(Step::Where, &d, 0, &quiet()).is_some());
        assert!(step_problem(Step::Where, &d, 1, &quiet()).is_none());
        let none = token_view(&[false], false, "");
        assert!(
            step_problem(Step::Where, &d, 1, &none)
                .unwrap()
                .contains("token")
        );
        let filled = token_view(&[false], false, "typed");
        assert!(step_problem(Step::Where, &d, 1, &filled).is_none());
        assert!(step_problem(Step::Where, &servers(), 1, &none).is_none());
    }

    #[test]
    fn token_control_follows_the_chosen_nodes() {
        let has = token_view(&[true], false, "");
        assert!(has.offer_toggle && !has.show_field && !has.required);
        assert_eq!(has.help, TOKEN_HELP_NODE);
        let own = token_view(&[true, true], true, "");
        assert!(own.show_field && own.required);
        assert!(!token_view(&[true], true, "typed").required);
        let none = token_view(&[false], false, "");
        assert!(!none.offer_toggle && none.show_field && none.required);
        assert_eq!(none.help, TOKEN_HELP_NONE);
        let mixed = token_view(&[true, false], false, "");
        assert!(mixed.show_field && mixed.required);
        assert_eq!(mixed.help, TOKEN_HELP_MIXED);
        let unknown = token_view(&[], false, "");
        assert!(unknown.show_field && unknown.required);
    }

    #[test]
    fn a_hidden_token_field_sends_nothing() {
        let hidden = token_view(&[true], false, "left over");
        assert_eq!(effective_token(&hidden, "left over"), "");
        let shown = token_view(&[false], false, " typed ");
        assert_eq!(effective_token(&shown, " typed "), "typed");
    }

    #[test]
    fn first_blocked_names_the_earliest_bad_step() {
        let mut d = github();
        d.repo = "bad".into();
        d.hosts.clear();
        let (step, _) = first_blocked(&d, 1, &quiet()).expect("blocked");
        assert_eq!(step, Step::Setup);
        assert!(first_blocked(&github(), 1, &quiet()).is_none());
    }

    #[test]
    fn field_problems_sit_next_to_their_fields() {
        let none = field_problems(&github(), true);
        assert_eq!(none, FieldProblems::default());
        assert!(none.first().is_none());
        let mut d = github();
        d.name.clear();
        d.id = "Bad".into();
        d.hosts = "bad host!".into();
        d.repo = "nope".into();
        d.branch = "-x".into();
        d.poll_interval = "5s".into();
        d.path_prefixes = vec!["nope".into()];
        let p = field_problems(&d, true);
        assert!(p.name.is_some() && p.id.is_some() && p.hosts.is_some());
        assert!(p.repo.is_some() && p.branch.is_some() && p.poll.is_some() && p.paths.is_some());
        assert_eq!(p.first(), p.name.as_ref());
        assert!(field_problems(&d, false).id.is_none());
        let mut s = servers();
        s.repo = "nope".into();
        s.poll_interval = "5s".into();
        let p = field_problems(&s, true);
        assert!(p.repo.is_none() && p.poll.is_none() && p.branch.is_none());
        s.health_interval = "10".into();
        assert!(
            field_problems(&s, true)
                .health
                .unwrap()
                .contains("interval")
        );
        let mut long = github();
        long.id = "a".repeat(41);
        assert!(field_problems(&long, true).id.is_some());
        long.id = "a".repeat(40);
        assert!(field_problems(&long, true).id.is_none());
    }

    #[test]
    fn protection_summary_describes_the_choices_in_plain_words() {
        let open = protection_summary(&AccessDraft::default());
        assert!(open.contains("Open to any visitor") && open.contains("Node serves HTTPS"));
        let mut a = AccessDraft::default();
        a.set_cloudflare_only(true);
        a.flexible = true;
        a.set_zone_lock(true);
        let text = protection_summary(&a);
        assert!(text.contains("Cloudflare proxy") && text.contains("Cloudflare handles HTTPS"));
        assert!(text.contains("my Cloudflare account"));
        let lower = protection_summary(&AccessDraft::default()).to_lowercase();
        assert!(!lower.contains("transform") && !lower.contains("secret"));
    }

    #[test]
    fn review_lists_only_the_chosen_branch() {
        let rows = review_rows(&github(), &["edge-1".into()]);
        let labels: Vec<&str> = rows.iter().map(|r| r.0).collect();
        assert!(labels.contains(&"Source") && !labels.contains(&"Servers"));
        assert!(rows.iter().any(|r| r.1.contains("acme/shop")));
        let rows = review_rows(&servers(), &["edge-1".into(), "edge-2".into()]);
        let labels: Vec<&str> = rows.iter().map(|r| r.0).collect();
        assert!(labels.contains(&"Servers") && !labels.contains(&"Source"));
        assert!(
            rows.iter()
                .any(|r| r.0 == "Nodes" && r.1 == "edge-1, edge-2")
        );
    }
}
