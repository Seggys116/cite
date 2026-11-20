#![allow(dead_code)] // The views use these helpers.
//! Which nodes a write lands on. A write is never sent to a node the person did not pick:
//! "All nodes" selects nothing by itself. Port of the dashboard's `targetlib.js`.

use std::collections::HashSet;

const ALL: &str = "all";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeInfo {
    pub name: String,
    pub online: bool,
}

/// The outcome of a write on one node of a fan-out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeResult {
    pub node: String,
    pub outcome: Result<(), String>,
}

pub fn is_all_scope(scope: Option<&str>) -> bool {
    matches!(scope, None | Some("") | Some(ALL))
}

fn names(nodes: &[NodeInfo]) -> impl Iterator<Item = &str> {
    nodes.iter().map(|n| n.name.as_str())
}

/// The nodes ticked when a picker first opens. A single selected node is the target;
/// "All nodes" starts with nothing ticked.
pub fn initial_targets(scope: Option<&str>, nodes: &[NodeInfo]) -> Vec<String> {
    if is_all_scope(scope) {
        return Vec::new();
    }
    match scope {
        Some(s) if names(nodes).any(|n| n == s) => vec![s.to_string()],
        _ => Vec::new(),
    }
}

pub fn toggle_target(selected: &[String], name: &str) -> Vec<String> {
    if selected.iter().any(|n| n == name) {
        selected
            .iter()
            .filter(|n| n.as_str() != name)
            .cloned()
            .collect()
    } else {
        let mut next = selected.to_vec();
        next.push(name.to_string());
        next
    }
}

/// Keeps node order and drops names that are not configured, so a stale selection cannot
/// name a node that was removed.
pub fn normalize_targets(selected: &[String], nodes: &[NodeInfo]) -> Vec<String> {
    let wanted: HashSet<&str> = selected.iter().map(String::as_str).collect();
    names(nodes)
        .filter(|n| wanted.contains(n))
        .map(str::to_string)
        .collect()
}

pub fn can_confirm(selected: &[String], nodes: &[NodeInfo]) -> bool {
    !normalize_targets(selected, nodes).is_empty()
}

pub fn offline_targets(selected: &[String], nodes: &[NodeInfo]) -> Vec<String> {
    let picked: HashSet<&str> = selected.iter().map(String::as_str).collect();
    nodes
        .iter()
        .filter(|n| picked.contains(n.name.as_str()) && !n.online)
        .map(|n| n.name.clone())
        .collect()
}

pub fn not_targeted(selected: &[String], nodes: &[NodeInfo]) -> Vec<String> {
    let picked: HashSet<&str> = selected.iter().map(String::as_str).collect();
    names(nodes)
        .filter(|n| !picked.contains(n))
        .map(str::to_string)
        .collect()
}

/// "edge-nyc", "2 nodes: edge-fra, edge-nyc" or "No node selected"
pub fn target_summary(selected: &[String], nodes: &[NodeInfo]) -> String {
    let list = normalize_targets(selected, nodes);
    match list.len() {
        0 => "No node selected".to_string(),
        1 => list[0].clone(),
        n => format!("{n} nodes: {}", list.join(", ")),
    }
}

/// The confirm button names where the change lands: "Turn on for edge-nyc", "Turn on for 2 nodes"
pub fn confirm_label(verb: &str, selected: &[String], nodes: &[NodeInfo]) -> String {
    let list = normalize_targets(selected, nodes);
    match list.len() {
        0 => verb.to_string(),
        1 => format!("{verb} for {}", list[0]),
        n => format!("{verb} for {n} nodes"),
    }
}

/// A toast line for a fan-out: "Added on edge-nyc" or
/// "Added on edge-fra. Failed on edge-nyc: <reason>"
pub fn result_message(done: &str, results: &[NodeResult]) -> String {
    let ok: Vec<&str> = results
        .iter()
        .filter(|r| r.outcome.is_ok())
        .map(|r| r.node.as_str())
        .collect();
    let mut parts: Vec<String> = Vec::new();
    if !ok.is_empty() {
        parts.push(format!("{done} on {}", ok.join(", ")));
    }
    for r in results {
        if let Err(reason) = &r.outcome {
            parts.push(format!("Failed on {}: {reason}", r.node));
        }
    }
    parts.join(". ")
}

/// Toast kinds the console styles are success, info and error; any failure is shown as an
/// error so it is not missed.
pub fn result_kind(results: &[NodeResult]) -> &'static str {
    if results.iter().all(|r| r.outcome.is_ok()) {
        "success"
    } else {
        "error"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nodes() -> Vec<NodeInfo> {
        [("edge-fra", true), ("edge-nyc", true), ("edge-ams", false)]
            .iter()
            .map(|(name, online)| NodeInfo {
                name: name.to_string(),
                online: *online,
            })
            .collect()
    }

    fn sel(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn all_nodes_selects_nothing_one_node_selects_itself() {
        let nodes = nodes();
        assert_eq!(initial_targets(Some("all"), &nodes), Vec::<String>::new());
        assert_eq!(initial_targets(None, &nodes), Vec::<String>::new());
        assert_eq!(initial_targets(Some(""), &nodes), Vec::<String>::new());
        assert_eq!(
            initial_targets(Some("edge-nyc"), &nodes),
            sel(&["edge-nyc"])
        );
        assert_eq!(initial_targets(Some("gone"), &nodes), Vec::<String>::new());
    }

    #[test]
    fn toggle_adds_and_removes_a_node() {
        assert_eq!(toggle_target(&[], "edge-fra"), sel(&["edge-fra"]));
        assert_eq!(
            toggle_target(&sel(&["edge-fra", "edge-nyc"]), "edge-fra"),
            sel(&["edge-nyc"])
        );
    }

    #[test]
    fn a_selection_keeps_node_order_and_drops_removed_nodes() {
        assert_eq!(
            normalize_targets(&sel(&["edge-nyc", "ghost", "edge-fra"]), &nodes()),
            sel(&["edge-fra", "edge-nyc"])
        );
    }

    #[test]
    fn confirm_needs_at_least_one_known_node() {
        let nodes = nodes();
        assert!(!can_confirm(&[], &nodes));
        assert!(!can_confirm(&sel(&["ghost"]), &nodes));
        assert!(can_confirm(&sel(&["edge-fra"]), &nodes));
    }

    #[test]
    fn offline_and_untargeted_nodes_are_listed() {
        let nodes = nodes();
        assert_eq!(
            offline_targets(&sel(&["edge-fra", "edge-ams"]), &nodes),
            sel(&["edge-ams"])
        );
        assert_eq!(
            not_targeted(&sel(&["edge-nyc"]), &nodes),
            sel(&["edge-fra", "edge-ams"])
        );
    }

    #[test]
    fn the_summary_and_the_confirm_label_name_the_nodes() {
        let nodes = nodes();
        assert_eq!(target_summary(&[], &nodes), "No node selected");
        assert_eq!(target_summary(&sel(&["edge-nyc"]), &nodes), "edge-nyc");
        assert_eq!(
            target_summary(&sel(&["edge-nyc", "edge-fra"]), &nodes),
            "2 nodes: edge-fra, edge-nyc"
        );
        assert_eq!(
            confirm_label("Turn on", &sel(&["edge-nyc"]), &nodes),
            "Turn on for edge-nyc"
        );
        assert_eq!(
            confirm_label("Turn on", &sel(&["edge-nyc", "edge-fra"]), &nodes),
            "Turn on for 2 nodes"
        );
        assert_eq!(confirm_label("Turn on", &[], &nodes), "Turn on");
    }

    #[test]
    fn a_fan_out_reports_each_node() {
        let results = vec![
            NodeResult {
                node: "edge-fra".to_string(),
                outcome: Ok(()),
            },
            NodeResult {
                node: "edge-nyc".to_string(),
                outcome: Err("refused".to_string()),
            },
        ];
        assert_eq!(
            result_message("Added", &results),
            "Added on edge-fra. Failed on edge-nyc: refused"
        );
        assert_eq!(result_kind(&results), "error");
        assert_eq!(result_kind(&results[..1]), "success");
    }

    #[test]
    fn result_message_lists_several_successes_and_only_failures() {
        let ok = |n: &str| NodeResult {
            node: n.to_string(),
            outcome: Ok(()),
        };
        assert_eq!(
            result_message("Added", &[ok("edge-fra"), ok("edge-nyc")]),
            "Added on edge-fra, edge-nyc"
        );
        let bad = NodeResult {
            node: "edge-ams".to_string(),
            outcome: Err("down".to_string()),
        };
        assert_eq!(result_message("Added", &[bad]), "Failed on edge-ams: down");
        assert_eq!(result_message("Added", &[]), "");
        assert_eq!(result_kind(&[]), "success");
    }

    #[test]
    fn normalize_targets_is_idempotent() {
        let nodes = nodes();
        let inputs: Vec<Vec<String>> = vec![
            vec![],
            sel(&["ghost"]),
            sel(&["edge-nyc", "ghost", "edge-fra"]),
            sel(&["edge-ams", "edge-ams", "edge-fra"]),
            sel(&["edge-fra", "edge-nyc", "edge-ams"]),
        ];
        for input in inputs {
            let once = normalize_targets(&input, &nodes);
            let twice = normalize_targets(&once, &nodes);
            assert_eq!(once, twice, "input {input:?}");
        }
    }
}
