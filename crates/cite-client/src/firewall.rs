use std::collections::HashSet;

use cite_edge::model::FirewallRule;
use serde::{Deserialize, Serialize};

use crate::error::ClientError;

type Res<T> = std::result::Result<T, ClientError>;

pub const MAX_BULK_ENTRIES: usize = 200;
const MAX_RULE_ID_CHARS: usize = 40;

/// Many rule changes applied by the node as one configuration change: one validation and one reload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FirewallBulk {
    pub replace: Vec<FirewallRule>,
    pub delete: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BulkResult {
    #[serde(default)]
    pub created: u32,
    #[serde(default)]
    pub replaced: u32,
    #[serde(default)]
    pub deleted: u32,
}

fn invalid(message: impl Into<String>) -> ClientError {
    ClientError::Config(message.into())
}

/// Rule ids share the node's id shape, so an id can never be a path.
pub fn validate_rule_id(id: &str) -> Res<&str> {
    let mut bytes = id.bytes();
    let first_ok = bytes
        .next()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    let rest_ok = bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if first_ok && rest_ok && id.len() <= MAX_RULE_ID_CHARS {
        Ok(id)
    } else {
        Err(invalid(
            "rule id must be lowercase letters, digits and dashes, up to 40 characters",
        ))
    }
}

impl FirewallBulk {
    pub fn new(replace: Vec<FirewallRule>, delete: Vec<String>) -> Self {
        Self { replace, delete }
    }

    /// Checks ids, counts and overlaps before anything is sent; the node validates the rules themselves.
    pub fn validate(&self) -> Res<()> {
        if self.replace.is_empty() && self.delete.is_empty() {
            return Err(invalid(
                "a bulk change needs at least one rule to replace or delete",
            ));
        }
        if self.replace.len() > MAX_BULK_ENTRIES || self.delete.len() > MAX_BULK_ENTRIES {
            return Err(invalid(format!(
                "a bulk change holds at most {MAX_BULK_ENTRIES} rules to replace and {MAX_BULK_ENTRIES} to delete"
            )));
        }
        let mut seen = HashSet::new();
        for rule in &self.replace {
            validate_rule_id(&rule.id)?;
            if !seen.insert(rule.id.as_str()) {
                return Err(invalid(format!(
                    "rule {} appears twice in replace",
                    rule.id
                )));
            }
        }
        for id in &self.delete {
            validate_rule_id(id)?;
            if seen.contains(id.as_str()) {
                return Err(invalid(format!("rule {id} is both replaced and deleted")));
            }
        }
        let unique: HashSet<&str> = self.delete.iter().map(String::as_str).collect();
        if unique.len() != self.delete.len() {
            return Err(invalid("a rule id appears twice in delete"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cite_edge::model::FirewallAction;

    fn rule(id: &str) -> FirewallRule {
        FirewallRule {
            id: id.to_string(),
            name: "n".to_string(),
            enabled: true,
            action: Some(FirewallAction::Deny),
            ..FirewallRule::default()
        }
    }

    #[test]
    fn rule_ids_match_the_node_shape() {
        for ok in ["redirect-1", "a", "0x", "preset-cms-probes-1"] {
            assert_eq!(validate_rule_id(ok).expect("valid"), ok);
        }
        let long = "a".repeat(41);
        for bad in ["", "-a", "A", "a_b", "a/b", "..", "a b", long.as_str()] {
            assert!(
                matches!(validate_rule_id(bad), Err(ClientError::Config(_))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn bulk_changes_are_checked_before_sending() {
        FirewallBulk::new(vec![rule("a"), rule("b")], vec!["c".into()])
            .validate()
            .expect("valid");
        FirewallBulk::new(vec![], vec!["c".into()])
            .validate()
            .expect("delete only");
        let bad = [
            FirewallBulk::default(),
            FirewallBulk::new(vec![rule("a"), rule("a")], vec![]),
            FirewallBulk::new(vec![rule("a")], vec!["a".into()]),
            FirewallBulk::new(vec![], vec!["c".into(), "c".into()]),
            FirewallBulk::new(vec![rule("Bad Id")], vec![]),
            FirewallBulk::new(vec![], vec!["../x".into()]),
            FirewallBulk::new(
                (0..=MAX_BULK_ENTRIES)
                    .map(|i| rule(&format!("r{i}")))
                    .collect(),
                vec![],
            ),
        ];
        for bulk in &bad {
            assert!(
                matches!(bulk.validate(), Err(ClientError::Config(_))),
                "{bulk:?}"
            );
        }
    }

    #[test]
    fn bulk_serialises_to_the_documented_body_and_results_decode() {
        let bulk = FirewallBulk::new(vec![rule("a")], vec!["b".into()]);
        let json = serde_json::to_value(&bulk).expect("json");
        assert_eq!(json["delete"], serde_json::json!(["b"]));
        assert_eq!(json["replace"][0]["id"], "a");
        let done: BulkResult =
            serde_json::from_str(r#"{"created":2,"replaced":1,"deleted":3}"#).expect("result");
        assert_eq!((done.created, done.replaced, done.deleted), (2, 1, 3));
        assert_eq!(
            serde_json::from_str::<BulkResult>("{}").expect("empty"),
            BulkResult::default()
        );
    }
}
