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
