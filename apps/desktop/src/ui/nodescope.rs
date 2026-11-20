// nodescope: the explicit node chooser shared by the single-node screens.
//
// "All nodes" in the switcher names no node, so a screen that writes to one node needs its own
// visible choice. Each such screen keeps a NodeScope in its state, draws scope_bar, and sends every
// write to the node that resolve picked, looked up by name.

use std::future::Future;

use cite_client::ClientError;
use gpui::{AnyElement, Context, Div, div, prelude::*, px};

use crate::api::NodeHandle;
use crate::app::Console;
use crate::targets::{NodeInfo, is_all_scope};
use crate::theme::{Tone, font, space};
use crate::ui::widgets::{id, notice, seg_item, seg_item_off, seg_row, text_dim, tip};

// One screen's own node choice; it never touches the global switcher.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeScope {
    pub chosen: Option<String>,
    // The switcher selection the choice was made under: moving the switcher drops the choice.
    under: Option<String>,
}

impl NodeScope {
    pub fn choose(&mut self, name: &str, selected: Option<&str>) {
        self.chosen = Some(name.to_string());
        self.under = selected.map(str::to_string);
    }

    // The chosen node, unless the switcher moved since it was chosen.
    pub fn current(&self, selected: Option<&str>) -> Option<&str> {
        let chosen = self.chosen.as_deref()?;
        (self.under.as_deref() == selected).then_some(chosen)
    }
}

// The node a single-node screen acts on: the chosen node if it is still configured, else the one
// node picked in the switcher. Under "All nodes" nothing is chosen for the person, so the result is
// None until they pick on the screen's own bar. The one exception is a console with a single node,
// where there is nothing to choose between (the bar is not drawn then).
pub fn resolve(selected: Option<&str>, chosen: Option<&str>, nodes: &[NodeInfo]) -> Option<String> {
    if let [only] = nodes {
        return Some(only.name.clone());
    }
    let known = |name: &str| nodes.iter().any(|n| n.name == name);
    chosen
        .filter(|name| known(name))
        .or_else(|| selected.filter(|name| !is_all_scope(Some(*name)) && known(name)))
        .map(str::to_string)
}

pub const CHOOSE_NODE: &str = "Choose a node to continue";

// What a single-node screen shows, under its header and bar, until a node is chosen.
pub fn choose_node_notice() -> Div {
    notice(CHOOSE_NODE, Tone::Info)
}

// Why a write cannot go anywhere: no node chosen yet, or the chosen one is not connected.
pub fn unresolved_text(node: Option<&str>) -> String {
    match node {
        Some(name) => no_node_text(Some(name)),
        None => CHOOSE_NODE.to_string(),
    }
}

// "edge-fra", or "edge-fra (offline)" for a node that cannot be reached.
pub fn entry_label(node: &NodeInfo) -> String {
    if node.online {
        node.name.clone()
    } else {
        format!("{} (offline)", node.name)
    }
}

// "Settings saved" becomes "Settings saved on edge-fra"; a closing full stop stays at the end.
pub fn on_node(text: &str, node: &str) -> String {
    match text.strip_suffix('.') {
        Some(body) => format!("{body} on {node}."),
        None => format!("{text} on {node}"),
    }
}

pub fn failed_on(what: &str, node: &str, reason: &str) -> String {
    format!("{what} failed on {node}: {reason}")
}

pub fn no_node_text(node: Option<&str>) -> String {
    match node {
        Some(name) => format!("{name} is not connected."),
        None => "No node is online.".to_string(),
    }
}

pub fn no_node_notice(node: Option<&str>) -> Div {
    notice(&no_node_text(node), Tone::Warn)
}

// One entry per node, so the target of every write on the page is a visible choice. Offline nodes
// cannot be picked. `choose` receives the node name and does the screen's own reset and reload.
pub fn scope_bar(
    key: &'static str,
    nodes: &[NodeInfo],
    current: Option<&str>,
    choose: fn(&mut Console, String, &mut Context<Console>),
    cx: &mut Context<Console>,
) -> Div {
    let mut items = Vec::with_capacity(nodes.len());
    for node in nodes {
        let active = current == Some(node.name.as_str());
        if node.online {
            let item = seg_item(id(key, &node.name), &entry_label(node), active);
            let name = node.name.clone();
            items.push(
                item.on_click(cx.listener(move |this, _, _, cx| {
                    choose(this, name.clone(), cx);
                    cx.notify();
                }))
                .into_any_element(),
            );
        } else {
            items.push(
                tip(
                    seg_item_off(id(key, &node.name), &entry_label(node), active),
                    id(key, format!("{}-offline", node.name)),
                    format!("{} is offline", node.name),
                )
                .into_any_element(),
            );
        }
    }
    div()
        .flex()
        .flex_wrap()
        .items_center()
        .gap(px(space::SM))
        .child(text_dim("Node").text_size(px(font::SM)))
        .child(seg_row(items))
}

impl Console {
    // The node the screen holding `scope` acts on right now.
    pub fn scoped_node(&self, scope: &NodeScope) -> Option<String> {
        let selected = self.selected.as_deref();
        resolve(selected, scope.current(selected), &self.node_infos())
    }

    // Its connection; None when the node is offline or unknown.
    pub fn scoped_handle(&self, scope: &NodeScope) -> Option<NodeHandle> {
        self.scoped_node(scope)
            .and_then(|name| self.handle_named(&name))
    }

    // The bar for a page header, only when there is more than one node to choose from.
    pub fn scope_bar_for(
        &self,
        key: &'static str,
        scope: &NodeScope,
        choose: fn(&mut Console, String, &mut Context<Console>),
        cx: &mut Context<Console>,
    ) -> Option<AnyElement> {
        let nodes = self.node_infos();
        if nodes.len() < 2 {
            return None;
        }
        let selected = self.selected.as_deref();
        let current = resolve(selected, scope.current(selected), &nodes);
        Some(scope_bar(key, &nodes, current.as_deref(), choose, cx).into_any_element())
    }

    // Runs a write on one named node. `current` says which node the screen shows now, so the
    // completion knows whether the user is still looking at the node the write went to.
    pub fn fetch_on<T, F>(
        &mut self,
        cx: &mut Context<Self>,
        node: &str,
        current: fn(&Console) -> Option<String>,
        fut: F,
        apply: impl FnOnce(&mut Self, Result<T, ClientError>, bool, &mut Context<Self>) + 'static,
    ) where
        T: Send + 'static,
        F: Future<Output = Result<T, ClientError>> + Send + 'static,
    {
        let (node, view) = (node.to_string(), self.view.clone());
        self.toasts.retain(|t| t.tone != Tone::Bad);
        self.fetch(cx, fut, move |this, res, cx| {
            let here = this.view == view && current(this).as_deref() == Some(node.as_str());
            apply(this, res, here, cx);
        });
    }

    // Like mutate, but the toast names the node and the reload happens only if the user is still on it.
    pub fn mutate_on<T, F>(
        &mut self,
        cx: &mut Context<Self>,
        node: &str,
        current: fn(&Console) -> Option<String>,
        fut: F,
        done: &str,
        what: &str,
    ) where
        T: Send + 'static,
        F: Future<Output = Result<T, ClientError>> + Send + 'static,
    {
        let (done, what, name) = (on_node(done, node), what.to_string(), node.to_string());
        self.fetch_on(cx, node, current, fut, move |this, res, here, cx| {
            match res {
                Ok(_) => this.say(done, Tone::Ok),
                Err(e) => this.say(failed_on(&what, &name, &e.to_string()), Tone::Bad),
            }
            if here {
                this.load_current(cx);
            }
            cx.notify();
        });
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

    #[test]
    fn a_chosen_node_wins_over_the_switcher() {
        let nodes = nodes();
        assert_eq!(
            resolve(Some("edge-fra"), Some("edge-nyc"), &nodes).as_deref(),
            Some("edge-nyc")
        );
        assert_eq!(
            resolve(None, Some("edge-nyc"), &nodes).as_deref(),
            Some("edge-nyc")
        );
    }

    #[test]
    fn a_chosen_node_that_is_gone_falls_back_to_the_switcher() {
        let nodes = nodes();
        assert_eq!(
            resolve(Some("edge-nyc"), Some("ghost"), &nodes).as_deref(),
            Some("edge-nyc")
        );
    }

    #[test]
    fn all_nodes_chooses_nothing_for_the_person() {
        let nodes = nodes();
        assert_eq!(resolve(None, None, &nodes), None);
        assert_eq!(resolve(Some("all"), None, &nodes), None);
        assert_eq!(resolve(Some(""), None, &nodes), None);
        assert_eq!(resolve(Some("ghost"), Some("ghost"), &nodes), None);
        let mut offline_first = nodes;
        offline_first.swap(0, 2);
        assert_eq!(resolve(None, None, &offline_first), None);
    }

    #[test]
    fn a_console_with_one_node_has_nothing_to_choose() {
        let one = vec![NodeInfo {
            name: "edge-fra".into(),
            online: true,
        }];
        assert_eq!(resolve(None, None, &one).as_deref(), Some("edge-fra"));
    }

    #[test]
    fn a_choice_is_dropped_when_the_switcher_moves() {
        let nodes = nodes();
        let mut scope = NodeScope::default();
        scope.choose("edge-nyc", None);
        let under_all = scope.current(None);
        assert_eq!(
            resolve(None, under_all, &nodes).as_deref(),
            Some("edge-nyc")
        );
        // The switcher now names edge-fra: the screen follows it, not the old choice.
        let moved = scope.current(Some("edge-fra"));
        assert_eq!(
            resolve(Some("edge-fra"), moved, &nodes).as_deref(),
            Some("edge-fra")
        );
        // Back on All nodes with a stale choice from another switcher state: nothing resolves.
        let mut stale = NodeScope::default();
        stale.choose("edge-nyc", Some("edge-fra"));
        assert_eq!(resolve(None, stale.current(None), &nodes), None);
    }

    #[test]
    fn a_single_selected_node_is_used_even_when_it_is_offline() {
        assert_eq!(
            resolve(Some("edge-ams"), None, &nodes()).as_deref(),
            Some("edge-ams")
        );
    }

    #[test]
    fn nothing_resolves_without_an_online_node() {
        assert_eq!(resolve(None, None, &[]), None);
        let mut down = nodes();
        for n in &mut down {
            n.online = false;
        }
        assert_eq!(resolve(None, None, &down), None);
        assert_eq!(resolve(Some("ghost"), None, &down), None);
    }

    #[test]
    fn an_unresolved_screen_says_what_to_do() {
        assert_eq!(unresolved_text(None), "Choose a node to continue");
        assert_eq!(
            unresolved_text(Some("edge-fra")),
            "edge-fra is not connected."
        );
    }

    #[test]
    fn a_choice_lasts_only_while_the_switcher_stays_put() {
        let mut scope = NodeScope::default();
        assert_eq!(scope.current(None), None);
        scope.choose("edge-nyc", None);
        assert_eq!(scope.current(None), Some("edge-nyc"));
        assert_eq!(scope.current(Some("edge-fra")), None);
        scope.choose("edge-nyc", Some("edge-fra"));
        assert_eq!(scope.current(Some("edge-fra")), Some("edge-nyc"));
        assert_eq!(scope.current(None), None);
    }

    #[test]
    fn offline_nodes_carry_a_marker() {
        let list = nodes();
        assert_eq!(entry_label(&list[0]), "edge-fra");
        assert_eq!(entry_label(&list[2]), "edge-ams (offline)");
    }

    #[test]
    fn messages_name_the_node() {
        assert_eq!(
            on_node("Settings saved", "edge-fra"),
            "Settings saved on edge-fra"
        );
        assert_eq!(
            on_node("Deleted 12 rows.", "edge-fra"),
            "Deleted 12 rows on edge-fra."
        );
        assert_eq!(
            failed_on("Saving settings", "edge-fra", "refused"),
            "Saving settings failed on edge-fra: refused"
        );
        assert_eq!(no_node_text(Some("edge-fra")), "edge-fra is not connected.");
        assert_eq!(no_node_text(None), "No node is online.");
    }
}
