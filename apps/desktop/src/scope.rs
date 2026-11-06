use std::collections::BTreeMap;
use std::mem::Discriminant;

use crate::app::View;

// Loaders tag their request with the scope they were issued in, and the scope moves on whenever the node or view changes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Scope(u64);

impl Scope {
    pub fn advance(&mut self) {
        self.0 = self.0.wrapping_add(1);
    }

    pub fn accepts(self, issued: Scope) -> bool {
        self == issued
    }
}

// Runs apply only for a result that still belongs to the current scope; returns whether it ran.
pub fn apply_if_current<T>(current: Scope, issued: Scope, value: T, apply: impl FnOnce(T)) -> bool {
    if current.accepts(issued) {
        apply(value);
        true
    } else {
        false
    }
}

// Where the user was when an action was issued: the node, the site on a site page, and the kind of view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    pub node: String,
    pub site: Option<String>,
    view: Discriminant<View>,
}

impl Origin {
    pub fn new(node: &str, site: Option<&str>, view: &View) -> Self {
        Self {
            node: node.to_string(),
            site: site.map(str::to_string),
            view: std::mem::discriminant(view),
        }
    }

    // "shop (edge-fra)" on a site page, the node name elsewhere.
    pub fn place(&self) -> String {
        match &self.site {
            Some(site) => format!("{site} ({})", self.node),
            None => self.node.clone(),
        }
    }
}

// The toast text for an outcome that arrives after the user has moved on; it names where it happened.
pub fn foreign_notice(action: &str, origin: &Origin, message: &str) -> String {
    if message.is_empty() {
        format!("{action} on {}", origin.place())
    } else {
        format!("{action} on {}: {message}", origin.place())
    }
}

// New API tokens are shown once, so each is kept under the node it belongs to until it is dismissed.
#[derive(Default)]
pub struct TokenShelf(BTreeMap<String, String>);

impl TokenShelf {
    pub fn put(&mut self, node: &str, token: String) {
        if let Some(mut old) = self.0.insert(node.to_string(), token) {
            crate::certs::wipe(&mut old);
        }
    }

    pub fn for_node(&self, node: &str) -> Option<&str> {
        self.0.get(node).map(String::as_str)
    }

    pub fn dismiss(&mut self, node: &str) {
        if let Some(mut token) = self.0.remove(node) {
            crate::certs::wipe(&mut token);
        }
    }
}

impl std::fmt::Debug for TokenShelf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TokenShelf({} tokens, redacted)", self.0.len())
    }
}

// A site page keeps its error through the reload that follows an action on the same site and node, and drops it for any other.
pub fn error_survives(prev_node: &str, prev_site: &str, next_node: &str, next_site: &str) -> bool {
    !prev_site.is_empty() && prev_node == next_node && prev_site == next_site
}

// Which list response may be applied: only one that is not older than the newest request already applied.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sequence {
    issued: u64,
    applied: u64,
}

impl Sequence {
    pub fn issue(&mut self) -> u64 {
        self.issued += 1;
        self.issued
    }

    // Returns true when the response numbered seq is newer than everything applied so far.
    pub fn accept(&mut self, seq: u64) -> bool {
        if seq > self.applied {
            self.applied = seq;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detail(node: &str, site: &str) -> View {
        View::SiteDetail {
            node: node.into(),
            id: site.into(),
        }
    }

    #[test]
    fn an_origin_matches_only_the_same_node_site_and_view_kind() {
        let here = Origin::new("edge-fra", Some("shop"), &detail("edge-fra", "shop"));
        assert!(here == Origin::new("edge-fra", Some("shop"), &detail("edge-fra", "shop")));
        assert!(here != Origin::new("edge-iad", Some("shop"), &detail("edge-iad", "shop")));
        assert!(here != Origin::new("edge-fra", Some("api"), &detail("edge-fra", "api")));
        assert!(here != Origin::new("edge-fra", None, &detail("edge-fra", "shop")));
        assert!(here != Origin::new("edge-fra", Some("shop"), &View::Settings));
        let settings = Origin::new("edge-fra", None, &View::Settings);
        assert!(settings == Origin::new("edge-fra", None, &View::Settings));
        assert!(settings != Origin::new("edge-fra", None, &View::Firewall));
        assert!(settings != Origin::new("edge-iad", None, &View::Settings));
    }

    #[test]
    fn outcomes_that_arrive_elsewhere_name_the_place() {
        let site = Origin::new("edge-fra", Some("shop"), &detail("edge-fra", "shop"));
        assert_eq!(site.place(), "shop (edge-fra)");
        assert_eq!(
            foreign_notice("Deploy", &site, "Deployed."),
            "Deploy on shop (edge-fra): Deployed."
        );
        let node = Origin::new("edge-iad", None, &View::Settings);
        assert_eq!(node.place(), "edge-iad");
        assert_eq!(
            foreign_notice("Rule added", &node, ""),
            "Rule added on edge-iad"
        );
    }

    #[test]
    fn tokens_are_kept_per_node_until_dismissed() {
        let mut shelf = TokenShelf::default();
        shelf.put("edge-fra", "one".to_string());
        shelf.put("edge-iad", "two".to_string());
        assert!(shelf.for_node("edge-fra") == Some("one"), "values differ");
        assert!(shelf.for_node("edge-iad") == Some("two"), "values differ");
        assert!(shelf.for_node("edge-sin").is_none());
        shelf.dismiss("edge-fra");
        assert!(shelf.for_node("edge-fra").is_none());
        assert!(shelf.for_node("edge-iad").is_some());
        shelf.put("edge-iad", "three".to_string());
        assert!(shelf.for_node("edge-iad") == Some("three"), "values differ");
        shelf.dismiss("edge-sin");
        assert!(!format!("{shelf:?}").contains("three"));
    }

    #[test]
    fn an_error_survives_a_reload_of_the_same_site_only() {
        assert!(error_survives("edge-fra", "shop", "edge-fra", "shop"));
        assert!(!error_survives("edge-fra", "shop", "edge-fra", "api"));
        assert!(!error_survives("edge-fra", "shop", "edge-iad", "shop"));
        assert!(!error_survives("", "", "edge-fra", "shop"));
        assert!(!error_survives("edge-fra", "", "edge-fra", ""));
    }

    #[test]
    fn an_older_list_response_never_replaces_a_newer_one() {
        let mut seq = Sequence::default();
        let first = seq.issue();
        let second = seq.issue();
        assert!(seq.accept(second));
        assert!(!seq.accept(first), "the stale list must be dropped");
        assert!(!seq.accept(second), "a repeat is not newer");
        let third = seq.issue();
        assert!(seq.accept(third));
    }

    #[test]
    fn responses_arriving_in_order_are_all_applied() {
        let mut seq = Sequence::default();
        let (a, b) = (seq.issue(), seq.issue());
        assert!(seq.accept(a) && seq.accept(b));
    }

    #[test]
    fn a_result_from_the_current_scope_is_applied() {
        let now = Scope::default();
        let mut seen = None;
        assert!(apply_if_current(now, now, 7, |v| seen = Some(v)));
        assert_eq!(seen, Some(7));
    }

    #[test]
    fn a_result_issued_before_a_node_switch_is_ignored() {
        let mut current = Scope::default();
        let issued_for_a = current;
        current.advance();
        let mut applied = false;
        assert!(!apply_if_current(
            current,
            issued_for_a,
            "settings of node a",
            |_| {
                applied = true;
            }
        ));
        assert!(!applied);
        let issued_for_b = current;
        assert!(apply_if_current(
            current,
            issued_for_b,
            "settings of node b",
            |_| {
                applied = true;
            }
        ));
        assert!(applied);
    }

    #[test]
    fn every_advance_invalidates_all_earlier_requests() {
        let mut current = Scope::default();
        let first = current;
        current.advance();
        let second = current;
        current.advance();
        assert!(!current.accepts(first) && !current.accepts(second));
        assert!(current.accepts(current));
        assert!(first != second);
    }
}
