use std::future::Future;

use cite_client::{ClientError, PresetInfo};
use cite_edge::analytics::TopItem;
use cite_edge::model::{FirewallAction, FirewallRule, HeaderOpKind, HeaderTarget, Site};
use gpui::{AnyElement, Context, Div, Entity, div, prelude::*, px};

use crate::api::{NodeHandle, join_all};
use crate::app::{Console, Load, TargetPicker, new_input};
use crate::model::{action_label, fmt_int, matcher_summary};
use crate::rules::{
    CondKind, CondRow, CorsDraft, HeaderOpDraft, MAX_HEADER_OPS, REDIRECT_EXAMPLES,
    REDIRECT_PLACEHOLDERS, REDIRECT_STATUSES, RuleDraft, RuleKind, build_rule, effect_detail,
    effect_pill, op_label, rows_from_list, rule_kind, target_label,
};
use crate::targets::{NodeInfo, NodeResult, result_kind, result_message};
use crate::theme::{
    CHIP_RADIUS, DIM, FAINT, MONO, PILL_RADIUS, TEXT, Tone, c, chip_fill, chip_stroke, font,
};
use crate::ui::chart::{clip_tip, wide};
use crate::ui::input::TextInput;
use crate::ui::widgets::{
    BtnKind, ClipText, Col, btn, card, checkbox, empty_state, field, id, mono, notice, page_header,
    pill, seg_item, seg_row, skeleton, strong, table, text_dim, tip, tip_mono, tip_rows, toggle,
};

// One node's copy of a rule. Whether the rule is on is a per-node state, so it lives in the copy.
#[derive(Clone, Debug, PartialEq)]
pub struct Holder {
    pub node: String,
    pub rule: FirewallRule,
}

// One row of the rules table: a rule id whose content is the same on every node that holds it.
// The same id with different content on two nodes gives two rows, both flagged `differs`.
#[derive(Clone, Debug, PartialEq)]
pub struct RuleRow {
    pub key: String,
    pub rule: FirewallRule,
    pub holders: Vec<Holder>,
    pub differs: bool,
}

pub struct Data {
    pub rows: Vec<RuleRow>,
    pub presets: Vec<PresetInfo>,
    // Site id and name, one entry per id across the nodes read.
    pub sites: Vec<(String, String)>,
    pub sites_by_node: Vec<(String, Vec<String>)>,
    // The blocked-by-rule counts of the last 24 hours, per node.
    pub blocked: Vec<(String, Vec<TopItem>)>,
    // Nodes that did not answer; they are named in a notice and left out.
    pub down: Vec<String>,
}

// The rule being edited and the nodes that hold it, each with its own on or off state.
#[derive(Clone)]
pub struct Editing {
    pub id: String,
    pub holders: Vec<(String, bool)>,
}

// One header change in the editor; its text lives in inputs so typing needs no state round trip.
pub struct OpRow {
    pub target: HeaderTarget,
    pub op: HeaderOpKind,
    pub name: Entity<TextInput>,
    pub value: Entity<TextInput>,
}

pub struct State {
    pub data: Load<Data>,
    pub adding: bool,
    pub editing: Option<Editing>,
    pub saving: bool,
    pub kind: RuleKind,
    pub action: FirewallAction,
    pub error: Option<String>,
    pub scheme: Option<&'static str>,
    pub header_regex: bool,
    pub header_negate: bool,
    pub header_secret: bool,
    pub redirect_status: u16,
    pub cors_on: bool,
    pub cors_credentials: bool,
    pub ops: Vec<OpRow>,
    pub name: Entity<TextInput>,
    pub label: Entity<TextInput>,
    pub site: Entity<TextInput>,
    pub path_regex: Entity<TextInput>,
    pub path_prefix: Entity<TextInput>,
    pub methods: Entity<TextInput>,
    pub ua: Entity<TextInput>,
    pub cidrs: Entity<TextInput>,
    pub host: Entity<TextInput>,
    pub header_name: Entity<TextInput>,
    pub header_value: Entity<TextInput>,
    pub header_secret_value: Entity<TextInput>,
    pub referer: Entity<TextInput>,
    pub redirect_to: Entity<TextInput>,
    pub cors_origins: Entity<TextInput>,
    pub cors_methods: Entity<TextInput>,
    pub cors_allow: Entity<TextInput>,
    pub cors_expose: Entity<TextInput>,
    pub cors_max_age: Entity<TextInput>,
}

impl State {
    pub fn new(cx: &mut Context<Console>) -> Self {
        Self {
            data: Load::Idle,
            adding: false,
            editing: None,
            saving: false,
            kind: RuleKind::Block,
            action: FirewallAction::Deny,
            error: None,
            scheme: None,
            header_regex: false,
            header_negate: false,
            header_secret: false,
            redirect_status: 301,
            cors_on: false,
            cors_credentials: false,
            ops: Vec::new(),
            name: new_input(cx, "Block WordPress probes", |i| i),
            label: new_input(cx, "wp-probe (optional)", |i| i.mono()),
            site: new_input(cx, "shop (optional, empty means every site)", |i| i.mono()),
            path_regex: new_input(cx, "^/wp-(login|admin)", |i| i.mono()),
            path_prefix: new_input(cx, "/phpmyadmin", |i| i.mono()),
            methods: new_input(cx, "TRACE, CONNECT", |i| i.mono()),
            ua: new_input(cx, "(sqlmap|nikto)", |i| i.mono()),
            cidrs: new_input(cx, "203.0.113.0/24", |i| i.mono()),
            host: new_input(cx, "shop.example.com", |i| i.mono()),
            header_name: new_input(cx, "X-Beta-Key", |i| i.mono()),
            header_value: new_input(cx, "value to compare", |i| i.mono()),
            header_secret_value: new_input(cx, "secret value (hidden)", |i| i.masked().mono()),
            referer: new_input(cx, "spam\\.example", |i| i.mono()),
            redirect_to: new_input(cx, "{scheme}://{www_host}{path}{query}", |i| i.mono()),
            cors_origins: new_input(cx, "https://app.example.com, or *", |i| i.mono()),
            cors_methods: new_input(cx, "GET, POST", |i| i.mono()),
            cors_allow: new_input(cx, "Authorization, Content-Type", |i| i.mono()),
            cors_expose: new_input(cx, "X-Total-Count", |i| i.mono()),
            cors_max_age: new_input(cx, "600 (seconds, up to 86400)", |i| i.mono()),
        }
    }

    fn text_inputs(&self) -> Vec<&Entity<TextInput>> {
        vec![
            &self.name,
            &self.label,
            &self.site,
            &self.path_regex,
            &self.path_prefix,
            &self.methods,
            &self.ua,
            &self.cidrs,
            &self.host,
            &self.header_name,
            &self.header_value,
            &self.header_secret_value,
            &self.referer,
            &self.redirect_to,
            &self.cors_origins,
            &self.cors_methods,
            &self.cors_allow,
            &self.cors_expose,
            &self.cors_max_age,
        ]
    }
}

// Wording matches the web dashboard so both clients describe actions identically.
fn action_help(a: FirewallAction) -> &'static str {
    match a {
        FirewallAction::Deny => {
            "Answer with 403 Forbidden. Clear to the client and cheap for the edge."
        }
        FirewallAction::Drop => {
            "Close the connection with no reply at all, so scanners learn nothing."
        }
        FirewallAction::Tarpit => {
            "Hold the connection open and answer slowly to waste the scanner's time."
        }
    }
}

// ---- Pure helpers: merging what several nodes report, and describing it.

// Whether two copies do the same thing; on or off is a per-node state and does not count.
fn same_content(a: &FirewallRule, b: &FirewallRule) -> bool {
    let mut other = b.clone();
    other.enabled = a.enabled;
    *a == other
}

// One row per rule id when every holder has identical content. When the same id has different
// content on two nodes, each variant gets its own row and is never merged.
pub fn merge_rules(per_node: &[(String, Vec<FirewallRule>)]) -> Vec<RuleRow> {
    let mut by_id: Vec<(String, Vec<Vec<Holder>>)> = Vec::new();
    for (node, rules) in per_node {
        for rule in rules {
            let slot = match by_id.iter().position(|(id, _)| *id == rule.id) {
                Some(i) => i,
                None => {
                    by_id.push((rule.id.clone(), Vec::new()));
                    by_id.len() - 1
                }
            };
            let holder = Holder {
                node: node.clone(),
                rule: rule.clone(),
            };
            let variants = &mut by_id[slot].1;
            match variants.iter_mut().find(|v| same_content(&v[0].rule, rule)) {
                Some(variant) => variant.push(holder),
                None => variants.push(vec![holder]),
            }
        }
    }
    let mut rows = Vec::new();
    for (id, variants) in by_id {
        let differs = variants.len() > 1;
        for (n, holders) in variants.into_iter().enumerate() {
            rows.push(RuleRow {
                key: if differs {
                    format!("{id}#{n}")
                } else {
                    id.clone()
                },
                rule: holders[0].rule.clone(),
                holders,
                differs,
            });
        }
    }
    rows
}

// The switch reads on only when every node holding the rule has it on.
pub fn enabled_everywhere(row: &RuleRow) -> bool {
    !row.holders.is_empty() && row.holders.iter().all(|h| h.rule.enabled)
}

// The blocked-by-rule table names a rule by its id, label or name, whichever fired.
pub fn rule_hits(rule: &FirewallRule, top: &[TopItem]) -> u64 {
    [
        Some(rule.id.as_str()),
        rule.label.as_deref(),
        Some(rule.name.as_str()),
    ]
    .into_iter()
    .flatten()
    .find_map(|key| {
        top.iter()
            .find(|t| t.key == key)
            .map(|t| t.count)
            .filter(|n| *n > 0)
    })
    .unwrap_or(0)
}

// Hits are summed over the nodes that hold the row.
pub fn row_hits(row: &RuleRow, blocked: &[(String, Vec<TopItem>)]) -> u64 {
    row.holders
        .iter()
        .map(|h| {
            blocked
                .iter()
                .find(|(node, _)| *node == h.node)
                .map_or(0, |(_, top)| rule_hits(&h.rule, top))
        })
        .sum()
}

// The first item per key wins, so a list read from several nodes shows each entry once.
pub fn first_per_key<T>(items: impl IntoIterator<Item = T>, key: impl Fn(&T) -> String) -> Vec<T> {
    let mut seen: Vec<String> = Vec::new();
    let mut out = Vec::new();
    for item in items {
        let k = key(&item);
        if !seen.contains(&k) {
            seen.push(k);
            out.push(item);
        }
    }
    out
}

// Online nodes that can take a rule: a rule scoped to a site only goes to nodes that hold the site.
pub fn writable_nodes(
    nodes: &[NodeInfo],
    sites_by_node: &[(String, Vec<String>)],
    site: Option<&str>,
) -> Vec<String> {
    nodes
        .iter()
        .filter(|n| n.online)
        .filter(|n| match site {
            None => true,
            Some(wanted) => sites_by_node
                .iter()
                .any(|(node, ids)| *node == n.name && ids.iter().any(|i| i == wanted)),
        })
        .map(|n| n.name.clone())
        .collect()
}

pub fn unreachable_note(names: &[String]) -> Option<String> {
    match names {
        [] => None,
        [one] => Some(format!("{one} is unreachable and is left out.")),
        many => Some(format!(
            "{} are unreachable and are left out.",
            many.join(", ")
        )),
    }
}

// The first sentence of a preset description; the rules listed beside it carry the detail.
pub fn preset_blurb(description: &str) -> String {
    let text = description.trim();
    let mut chars = text.char_indices().peekable();
    while let Some((i, ch)) = chars.next() {
        let ends = matches!(ch, '.' | '!' | '?');
        if ends && chars.peek().is_none_or(|(_, next)| next.is_whitespace()) {
            return text[..i + ch.len_utf8()].to_string();
        }
    }
    text.to_string()
}

// Redirect presets carry no site, so applying one acts on every site on the node.
pub fn preset_needs_scope_warning(preset: &PresetInfo) -> bool {
    preset
        .rules
        .iter()
        .any(|r| r.redirect.is_some() && r.site.is_none())
}

fn rule_badge(rule: &FirewallRule) -> String {
    match (rule.action, rule.redirect.is_some()) {
        (Some(FirewallAction::Deny), _) => "Deny".to_string(),
        (Some(FirewallAction::Drop), _) => "Drop".to_string(),
        (Some(FirewallAction::Tarpit), _) => "Tarpit".to_string(),
        (None, true) => "Redirect".to_string(),
        (None, false) => effect_pill(rule).0,
    }
}

// What a preset would add, one entry per rule: its name, what it does and the patterns it matches.
pub fn preset_rows(preset: &PresetInfo) -> Vec<(String, Option<String>, String)> {
    preset
        .rules
        .iter()
        .map(|rule| {
            let mut lines = matcher_summary(&rule.matchers);
            if let Some(redirect) = &rule.redirect {
                lines.push(format!("to {}", redirect.to));
            }
            let detail = if lines.is_empty() {
                "Every request".to_string()
            } else {
                lines.join("\n")
            };
            (rule.name.clone(), Some(rule_badge(rule)), detail)
        })
        .collect()
}

// The editor holds one header matcher and splits lists on spaces, so a rule that does not fit
// cannot be loaded into it without changing what it does.
fn edit_problem(rule: &FirewallRule) -> Option<&'static str> {
    let m = &rule.matchers;
    if m.headers.len() > 1 {
        return Some("has several header matchers");
    }
    if m.headers.iter().any(|h| h.secret) {
        return Some("has a secret header value, which cannot be read back");
    }
    let lists = [
        &m.path_regexes,
        &m.path_prefixes,
        &m.user_agent_regexes,
        &m.referer_regexes,
        &m.methods,
        &m.hosts,
        &m.cidrs,
    ];
    if lists
        .iter()
        .any(|l| l.iter().any(|v| v.contains(char::is_whitespace)))
    {
        return Some("has a pattern with spaces");
    }
    match m.scheme.as_deref() {
        None | Some("http") | Some("https") => None,
        Some(_) => Some("has an unusual scheme matcher"),
    }
}

// ---- Shared write plumbing. Firewall and maintenance both fan a write out to several nodes,
// report it in one toast and reload.

// Runs one job per key at once on the network runtime. A job that fails, or whose task dies, is
// reported for its key; nothing here can stop the others.
pub(crate) async fn run_each<F, Fut>(keys: Vec<String>, job: F) -> Vec<NodeResult>
where
    F: Fn(String) -> Fut + Send + 'static,
    Fut: Future<Output = Result<(), String>> + Send + 'static,
{
    let jobs: Vec<_> = keys
        .iter()
        .map(|key| {
            let node = key.clone();
            let work = job(key.clone());
            async move {
                NodeResult {
                    node,
                    outcome: work.await,
                }
            }
        })
        .collect();
    let done = join_all(jobs).await;
    keys.into_iter()
        .zip(done)
        .map(|(node, result)| {
            result.unwrap_or(NodeResult {
                node,
                outcome: Err("the background task failed".to_string()),
            })
        })
        .collect()
}

// The text of a failed call, with its value dropped: the fan-out only needs to know it worked.
pub(crate) fn settled<T>(res: Result<T, ClientError>) -> Result<(), String> {
    res.map(|_| ()).map_err(|e| e.to_string())
}

pub(crate) fn write_tone(results: &[NodeResult]) -> Tone {
    if result_kind(results) == "success" {
        Tone::Ok
    } else {
        Tone::Bad
    }
}

// The usual end of a fan-out: one toast that names every node, then a reload.
pub(crate) fn reporter(
    done: String,
) -> impl FnOnce(&mut Console, &mut Context<Console>, Vec<NodeResult>) + 'static {
    move |this: &mut Console, cx: &mut Context<Console>, results: Vec<NodeResult>| {
        let message = result_message(&done, &results);
        this.report_writes(cx, message, write_tone(&results));
    }
}

impl Console {
    // The configured nodes that are among `names`, with whether each is online.
    pub(crate) fn infos_of(&self, names: &[String]) -> Vec<NodeInfo> {
        self.node_infos()
            .into_iter()
            .filter(|n| names.contains(&n.name))
            .collect()
    }

    // Asks which of `only` a change lands on. Under All nodes nothing is ticked, so a write never
    // reaches a node the person did not pick; with one node selected that node is ticked.
    pub(crate) fn pick_nodes(
        &mut self,
        title: String,
        message: String,
        verb: &str,
        only: &[String],
        danger: bool,
        action: impl FnOnce(&mut Console, &mut Context<Console>, Vec<String>) + 'static,
    ) {
        let nodes = self.infos_of(only);
        let selected = self.initial_targets();
        self.ask_targets(TargetPicker {
            title,
            message,
            verb: verb.to_string(),
            nodes,
            selected,
            danger,
            action: Box::new(action),
        });
    }

    // Hands the work to the network runtime and calls `then` with one result per key.
    pub(crate) fn settle<Fut>(
        &mut self,
        cx: &mut Context<Self>,
        work: Fut,
        then: impl FnOnce(&mut Self, &mut Context<Self>, Vec<NodeResult>) + 'static,
    ) where
        Fut: Future<Output = Vec<NodeResult>> + Send + 'static,
    {
        self.toasts.retain(|t| t.tone != Tone::Bad);
        let fut = async move { Ok::<_, ClientError>(work.await) };
        self.fetch(cx, fut, move |this, res, cx| {
            match res {
                Ok(results) => then(this, cx, results),
                Err(e) => {
                    this.say(e.to_string(), Tone::Bad);
                    then(this, cx, Vec::new());
                }
            }
            cx.notify();
        });
    }

    // Runs `job` on each named node at once. A node with no live connection is reported as such.
    pub(crate) fn fan_out<F, Fut>(
        &mut self,
        cx: &mut Context<Self>,
        nodes: Vec<String>,
        job: F,
        then: impl FnOnce(&mut Self, &mut Context<Self>, Vec<NodeResult>) + 'static,
    ) where
        F: Fn(NodeHandle) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        let handles = self.handles.clone();
        let work = run_each(nodes, move |name: String| {
            let pending = handles.iter().find(|h| h.name() == name).cloned().map(&job);
            async move {
                match pending {
                    Some(run) => run.await,
                    None => Err(format!("{name} is not connected")),
                }
            }
        });
        self.settle(cx, work, then);
    }

    // Says how a write went and reloads, so what is shown is what the nodes now hold.
    pub(crate) fn report_writes(&mut self, cx: &mut Context<Self>, message: String, tone: Tone) {
        if !message.is_empty() {
            self.say(message, tone);
        }
        self.load_current(cx);
    }
}

// Narrowest the two flex columns of the rules table get; below that the table scrolls sideways.
pub(crate) const RULE_MIN: f32 = 180.;
pub(crate) const MATCHES_MIN: f32 = 200.;

// A table row action: the pill button at row height, so two fit beside each other in a cell.
fn compact(b: gpui::Stateful<Div>) -> gpui::Stateful<Div> {
    b.h(px(26.)).px(px(10.))
}

// A small rounded label: a node name or a status. `color` is the text colour.
pub(crate) fn chip(text: &str, color: u32) -> Div {
    div()
        .flex()
        .items_center()
        .flex_none()
        .px(px(8.))
        .py(px(1.))
        .rounded(px(PILL_RADIUS))
        .border_1()
        .border_color(chip_stroke())
        .bg(chip_fill())
        .text_color(c(color))
        .text_size(px(font::XS))
        .whitespace_nowrap()
        .child(text.to_string())
}

// The matchers of a rule as chips that wrap onto as many lines as they need. A chip moves to the
// next line whole; one wider than the column ellipsizes and shows the full matcher on hover.
fn match_chips(key: &str, items: &[String]) -> Div {
    let mut row = div()
        .flex()
        .flex_wrap()
        .flex_1()
        .min_w_0()
        .gap(px(4.))
        .debug_selector(|| format!("fw-matches-{key}"));
    for (i, item) in items.iter().enumerate() {
        row = row.child(
            tip_mono(
                div()
                    .flex()
                    .flex_col()
                    .min_w_0()
                    .overflow_hidden()
                    .px(px(8.))
                    .py(px(2.))
                    .rounded(px(CHIP_RADIUS))
                    .border_1()
                    .border_color(chip_stroke())
                    .bg(chip_fill())
                    .font_family(MONO)
                    .text_size(px(font::XS))
                    .debug_selector(|| format!("fw-match-{key}-{i}"))
                    .child(ClipText::new(item.clone())),
                id("fw-match", format!("{key}-{i}")),
                item.clone(),
            )
            .flex()
            .min_w_0()
            .max_w_full(),
        );
    }
    row
}

// What one node answered while the page loaded.
struct NodeRead {
    node: String,
    rules: Result<Vec<FirewallRule>, ClientError>,
    presets: Vec<PresetInfo>,
    sites: Option<Vec<Site>>,
    blocked: Vec<TopItem>,
}

// A node whose rules cannot be read is down; the other calls are only extras, so they never fail the node.
async fn read_node(h: NodeHandle) -> NodeRead {
    let node = h.name().to_string();
    let rules = h.list_rules().await;
    if rules.is_err() {
        return NodeRead {
            node,
            rules,
            presets: Vec::new(),
            sites: None,
            blocked: Vec::new(),
        };
    }
    let presets = h.list_presets().await.unwrap_or_default();
    let sites = h.list_sites().await.ok();
    let blocked = h
        .summary("24h")
        .await
        .map(|s| s.top_blocked)
        .unwrap_or_default();
    NodeRead {
        node,
        rules,
        presets,
        sites,
        blocked,
    }
}

// Fails only when no node answered; otherwise the nodes that did are shown and the rest are named.
fn collect(reads: Vec<NodeRead>) -> Result<Data, ClientError> {
    let mut per_node = Vec::new();
    let mut presets = Vec::new();
    let mut sites = Vec::new();
    let mut sites_by_node = Vec::new();
    let mut blocked = Vec::new();
    let mut down = Vec::new();
    let mut first_err = None;
    for read in reads {
        match read.rules {
            Ok(rules) => {
                presets.extend(read.presets);
                if let Some(list) = read.sites {
                    sites_by_node.push((
                        read.node.clone(),
                        list.iter().map(|s| s.id.clone()).collect(),
                    ));
                    sites.extend(list.into_iter().map(|s| (s.id, s.name)));
                }
                blocked.push((read.node.clone(), read.blocked));
                per_node.push((read.node, rules));
            }
            Err(e) => {
                down.push(read.node);
                first_err.get_or_insert(e);
            }
        }
    }
    if per_node.is_empty() {
        return Err(
            first_err.unwrap_or_else(|| ClientError::Config("no node answered".to_string()))
        );
    }
    Ok(Data {
        rows: merge_rules(&per_node),
        presets: first_per_key(presets, |p| p.name.clone()),
        sites: first_per_key(sites, |s| s.0.clone()),
        sites_by_node,
        blocked,
        down,
    })
}

// A write to one node of a rule's own copy; the copy is chosen by the node's name.
async fn put_rule(h: NodeHandle, rule: Option<FirewallRule>) -> Result<(), String> {
    let Some(rule) = rule else {
        return Err("holds no copy of this rule".to_string());
    };
    settled(h.update_rule(&rule.id, &rule).await)
}

impl Console {
    pub fn load_firewall(&mut self, cx: &mut Context<Self>) {
        self.firewall.data = Load::Loading;
        let handles = self.selected_handles();
        if handles.is_empty() {
            self.firewall.data = Load::Idle;
            return;
        }
        let fut = async move {
            let reads = join_all(handles.into_iter().map(read_node).collect()).await;
            collect(reads.into_iter().flatten().collect())
        };
        self.fetch_scoped(cx, fut, |this, res, cx| {
            this.firewall.data = Load::from_result(res);
            cx.notify();
        });
    }

    // A short random tail keeps generated rule ids unique per node.
    fn rule_suffix() -> String {
        cite_client::fsio::new_id().chars().rev().take(6).collect()
    }

    fn rule_draft(&self, cx: &Context<Self>) -> RuleDraft {
        let t = |e: &Entity<TextInput>| e.read(cx).text().to_string();
        let f = &self.firewall;
        let header_value = if f.header_secret {
            t(&f.header_secret_value)
        } else {
            t(&f.header_value)
        };
        let mut conditions = Vec::new();
        for (kind, text) in [
            (CondKind::PathPrefix, t(&f.path_prefix)),
            (CondKind::PathRegex, t(&f.path_regex)),
            (CondKind::UserAgent, t(&f.ua)),
            (CondKind::Referer, t(&f.referer)),
            (CondKind::Method, t(&f.methods)),
            (CondKind::Host, t(&f.host)),
            (CondKind::Cidr, t(&f.cidrs)),
        ] {
            conditions.extend(rows_from_list(kind, &text));
        }
        conditions.extend(f.scheme.map(|s| CondRow::value(CondKind::Scheme, s)));
        conditions.push(CondRow::header(
            &t(&f.header_name),
            &header_value,
            f.header_regex,
            f.header_negate,
            f.header_secret,
        ));
        RuleDraft {
            name: t(&f.name),
            label: t(&f.label),
            site: t(&f.site),
            kind: f.kind,
            action: f.action,
            conditions,
            redirect_to: t(&f.redirect_to),
            redirect_status: f.redirect_status,
            header_ops: f
                .ops
                .iter()
                .map(|r| HeaderOpDraft {
                    target: r.target,
                    op: r.op,
                    name: t(&r.name),
                    value: t(&r.value),
                })
                .collect(),
            cors_on: f.cors_on,
            cors: CorsDraft {
                origins: t(&f.cors_origins),
                methods: t(&f.cors_methods),
                allow_headers: t(&f.cors_allow),
                expose_headers: t(&f.cors_expose),
                credentials: f.cors_credentials,
                max_age: t(&f.cors_max_age),
            },
        }
    }

    // A saved or closed form keeps nothing, least of all a secret header value.
    fn reset_rule_form(&mut self, cx: &mut Context<Self>) {
        let inputs: Vec<Entity<TextInput>> =
            self.firewall.text_inputs().into_iter().cloned().collect();
        for input in inputs {
            input.update(cx, |i, cx| i.set_text("", cx));
        }
        let f = &mut self.firewall;
        for row in f.ops.drain(..) {
            for input in [row.name, row.value] {
                input.update(cx, |i, cx| i.set_text("", cx));
            }
        }
        f.editing = None;
        f.kind = RuleKind::Block;
        f.action = FirewallAction::Deny;
        f.scheme = None;
        f.header_regex = false;
        f.header_negate = false;
        f.header_secret = false;
        f.redirect_status = 301;
        f.cors_on = false;
        f.cors_credentials = false;
        f.error = None;
    }

    // Puts an existing rule into the form. Callers have already checked `edit_problem`.
    fn fill_rule_form(&mut self, rule: &FirewallRule, cx: &mut Context<Self>) {
        fn put(input: &Entity<TextInput>, text: &str, cx: &mut Context<Console>) {
            input.update(cx, |i, cx| i.set_text(text, cx));
        }
        self.reset_rule_form(cx);
        let m = &rule.matchers;
        let header = m.headers.first();
        let f = &self.firewall;
        put(&f.name, &rule.name, cx);
        put(&f.label, rule.label.as_deref().unwrap_or(""), cx);
        put(&f.site, rule.site.as_deref().unwrap_or(""), cx);
        put(&f.path_regex, &m.path_regexes.join(" "), cx);
        put(&f.path_prefix, &m.path_prefixes.join(", "), cx);
        put(&f.methods, &m.methods.join(", "), cx);
        put(&f.ua, &m.user_agent_regexes.join(" "), cx);
        put(&f.cidrs, &m.cidrs.join(", "), cx);
        put(&f.host, &m.hosts.join(", "), cx);
        put(&f.referer, &m.referer_regexes.join(" "), cx);
        if let Some(h) = header {
            let value = h.regex.as_deref().or(h.equals.as_deref()).unwrap_or("");
            put(&f.header_name, &h.name, cx);
            put(&f.header_value, value, cx);
        }
        if let Some(r) = &rule.redirect {
            put(&f.redirect_to, &r.to, cx);
        }
        if let Some(cors) = &rule.cors {
            put(&f.cors_origins, &cors.origins.join(", "), cx);
            put(&f.cors_methods, &cors.methods.join(", "), cx);
            put(&f.cors_allow, &cors.allow_headers.join(", "), cx);
            put(&f.cors_expose, &cors.expose_headers.join(", "), cx);
            let age = if cors.max_age_secs == 0 {
                String::new()
            } else {
                cors.max_age_secs.to_string()
            };
            put(&f.cors_max_age, &age, cx);
        }
        let mut ops = Vec::new();
        for op in &rule.headers {
            let row = OpRow {
                target: op.target,
                op: op.op,
                name: new_input(cx, "X-Frame-Options", |i| i.mono()),
                value: new_input(cx, "DENY", |i| i.mono()),
            };
            put(&row.name, &op.name, cx);
            put(&row.value, op.value.as_deref().unwrap_or(""), cx);
            ops.push(row);
        }
        let f = &mut self.firewall;
        f.ops = ops;
        f.kind = rule_kind(rule);
        f.action = rule.action.unwrap_or(FirewallAction::Deny);
        f.scheme = match m.scheme.as_deref() {
            Some("http") => Some("http"),
            Some("https") => Some("https"),
            _ => None,
        };
        f.header_regex = header.is_some_and(|h| h.regex.is_some());
        f.header_negate = header.is_some_and(|h| h.negate);
        f.redirect_status = rule.redirect.as_ref().map_or(301, |r| r.status);
        f.cors_on = rule.cors.is_some();
        f.cors_credentials = rule.cors.as_ref().is_some_and(|c| c.credentials);
    }

    // The secret flag decides which input holds the value, and the text moves with it.
    fn set_header_secret(&mut self, on: bool, cx: &mut Context<Self>) {
        if self.firewall.header_secret == on {
            return;
        }
        let (plain, hidden) = (
            self.firewall.header_value.clone(),
            self.firewall.header_secret_value.clone(),
        );
        let (from, to) = if on { (plain, hidden) } else { (hidden, plain) };
        let text = from.read(cx).text().to_string();
        to.update(cx, |i, cx| i.set_text(&text, cx));
        from.update(cx, |i, cx| i.set_text("", cx));
        self.firewall.header_secret = on;
    }

    // Builds the rule, then asks which nodes get it. Nothing is written before that answer.
    fn submit_rule(&mut self, cx: &mut Context<Self>) {
        let mut rule = match build_rule(&self.rule_draft(cx), &Self::rule_suffix()) {
            Ok(rule) => rule,
            Err(e) => {
                self.firewall.error = Some(e);
                return;
            }
        };
        let editing = self.firewall.editing.clone();
        if let Some(e) = &editing {
            rule.id = e.id.clone();
        }
        let Load::Ready(data) = &self.firewall.data else {
            self.firewall.error =
                Some("The nodes are still loading. Try again in a moment.".into());
            return;
        };
        let mut only = writable_nodes(
            &self.node_infos(),
            &data.sites_by_node,
            rule.site.as_deref(),
        );
        if let Some(e) = &editing {
            only.retain(|n| e.holders.iter().any(|(held, _)| held == n));
        }
        if only.is_empty() {
            self.firewall.error = Some(
                match (&editing, &rule.site) {
                    (Some(_), _) => {
                        "No online node holds this rule and its site, so it cannot be saved."
                    }
                    (None, Some(_)) => "No online node has that site, so the rule cannot be saved.",
                    (None, None) => "No node is online to take the rule.",
                }
                .to_string(),
            );
            return;
        }
        self.firewall.error = None;
        let verb = if editing.is_some() {
            "Save rule"
        } else {
            "Add rule"
        };
        let done = format!(
            "{} {}",
            if editing.is_some() { "Saved" } else { "Added" },
            rule.name
        );
        let holders = editing.map(|e| e.holders);
        let message = rule.name.clone();
        self.pick_nodes(
            verb.to_string(),
            message,
            verb,
            &only,
            false,
            move |this, cx, nodes| {
                this.firewall.saving = true;
                let then = move |this: &mut Console,
                                 cx: &mut Context<Console>,
                                 results: Vec<NodeResult>| {
                    this.firewall.saving = false;
                    let message = result_message(&done, &results);
                    if results.iter().any(|r| r.outcome.is_ok()) {
                        this.reset_rule_form(cx);
                        this.firewall.adding = false;
                        this.report_writes(cx, message, write_tone(&results));
                    } else if message.is_empty() {
                        this.firewall.error = Some("Nothing was saved.".to_string());
                    } else {
                        this.firewall.error = Some(message);
                    }
                };
                match holders {
                    // An edit keeps each node's own on or off state.
                    Some(holders) => {
                        let rules = holders
                            .into_iter()
                            .map(|(node, enabled)| {
                                (
                                    node,
                                    FirewallRule {
                                        enabled,
                                        ..rule.clone()
                                    },
                                )
                            })
                            .collect();
                        this.put_rules(cx, nodes, rules, then);
                    }
                    None => this.fan_out(
                        cx,
                        nodes,
                        move |h| {
                            let rule = rule.clone();
                            async move { settled(h.create_rule(&rule).await) }
                        },
                        then,
                    ),
                }
            },
        );
    }

    // Saves each node's own copy of a rule, picked by the node's name.
    fn put_rules(
        &mut self,
        cx: &mut Context<Self>,
        nodes: Vec<String>,
        rules: Vec<(String, FirewallRule)>,
        then: impl FnOnce(&mut Self, &mut Context<Self>, Vec<NodeResult>) + 'static,
    ) {
        self.fan_out(
            cx,
            nodes,
            move |h: NodeHandle| {
                let rule = rules
                    .iter()
                    .find(|(node, _)| node == h.name())
                    .map(|(_, r)| r.clone());
                put_rule(h, rule)
            },
            then,
        );
    }

    // Flips the enabled flag on the nodes that hold the rule. One holder is applied to directly and
    // named in the toast; several holders ask which ones.
    fn toggle_rule(&mut self, row: &RuleRow, cx: &mut Context<Self>) {
        let on = !enabled_everywhere(row);
        let verb = if on { "Turn on" } else { "Turn off" };
        let name = row.rule.name.clone();
        let done = format!("Turned {} {name}", if on { "on" } else { "off" });
        let nodes: Vec<String> = row.holders.iter().map(|h| h.node.clone()).collect();
        let rules: Vec<(String, FirewallRule)> = row
            .holders
            .iter()
            .map(|h| {
                (
                    h.node.clone(),
                    FirewallRule {
                        enabled: on,
                        ..h.rule.clone()
                    },
                )
            })
            .collect();
        if nodes.len() == 1 {
            self.put_rules(cx, nodes, rules, reporter(done));
            return;
        }
        self.pick_nodes(
            format!("{verb} {name}"),
            format!("{verb} {name} on the nodes you pick."),
            verb,
            &nodes,
            false,
            move |this, cx, picked| this.put_rules(cx, picked, rules, reporter(done)),
        );
    }

    fn delete_rule(&mut self, row: &RuleRow) {
        let (rule_id, name) = (row.rule.id.clone(), row.rule.name.clone());
        let only: Vec<String> = row.holders.iter().map(|h| h.node.clone()).collect();
        let done = format!("Deleted {name}");
        self.pick_nodes(
            "Delete rule".to_string(),
            format!("Delete {name}? Matching traffic will pass through again."),
            "Delete rule",
            &only,
            true,
            move |this, cx, nodes| {
                this.fan_out(
                    cx,
                    nodes,
                    move |h| {
                        let rule_id = rule_id.clone();
                        async move { settled(h.delete_rule(&rule_id).await) }
                    },
                    reporter(done),
                );
            },
        );
    }

    fn edit_rule(&mut self, row: &RuleRow, cx: &mut Context<Self>) {
        if let Some(problem) = edit_problem(&row.rule) {
            self.say(
                format!("{} {problem}, so it cannot be edited here.", row.rule.name),
                Tone::Warn,
            );
            return;
        }
        self.fill_rule_form(&row.rule, cx);
        self.firewall.editing = Some(Editing {
            id: row.rule.id.clone(),
            holders: row
                .holders
                .iter()
                .map(|h| (h.node.clone(), h.rule.enabled))
                .collect(),
        });
        self.firewall.adding = true;
    }

    // A preset only adds the rules a node does not already have, on the nodes the person picks.
    fn apply_preset(&mut self, preset: &PresetInfo) {
        let online: Vec<String> = self
            .node_infos()
            .into_iter()
            .filter(|n| n.online)
            .map(|n| n.name)
            .collect();
        if online.is_empty() {
            self.say("No node is online to apply it to", Tone::Bad);
            return;
        }
        let message = if preset_needs_scope_warning(preset) {
            "No site is set, so it acts on every site on the node."
        } else {
            "Adds the rules each node does not have yet."
        };
        let (name, title) = (preset.name.clone(), preset.title.clone());
        let done = format!("Applied {title}");
        self.pick_nodes(
            format!("Apply {title}"),
            message.to_string(),
            "Apply",
            &online,
            false,
            move |this, cx, nodes| {
                this.fan_out(
                    cx,
                    nodes,
                    move |h| {
                        let name = name.clone();
                        async move { settled(h.apply_preset(&name).await) }
                    },
                    reporter(done),
                );
            },
        );
    }

    // Names the nodes the page covers: every configured node, with a muted chip for one that is offline.
    fn scope_chips(&self) -> AnyElement {
        let mut row = div().flex().flex_wrap().items_center().gap(px(6.));
        for node in self.node_infos() {
            row = row.child(chip(&node.name, if node.online { TEXT } else { FAINT }));
        }
        row.into_any_element()
    }

    pub fn render_firewall(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let add = btn(
            id("fw", "add"),
            if self.firewall.adding {
                "Cancel"
            } else {
                "Add rule"
            },
            BtnKind::Primary,
        )
        .on_click(cx.listener(|this, _, _, cx| {
            if this.firewall.adding {
                this.reset_rule_form(cx);
            }
            this.firewall.adding = !this.firewall.adding;
            this.firewall.error = None;
            cx.notify();
        }));
        let subtitle = match &self.selected {
            Some(node) => node.clone(),
            None => "All nodes".to_string(),
        };
        let header = page_header("Firewall", &subtitle, vec![add.into_any_element()]);
        let mut col = div().flex().flex_col().gap(px(16.)).child(header);
        if self.handles.is_empty() {
            return col.child(self.no_nodes_block(cx)).into_any_element();
        }
        if self.selected.is_none() {
            col = col.child(self.scope_chips());
        }
        if self.firewall.adding {
            col = col.child(self.rule_form(cx));
        }
        match &self.firewall.data {
            Load::Idle | Load::Loading => col = col.child(skeleton(200.)),
            Load::Failed(msg) => {
                let msg = msg.clone();
                col = col.child(self.error_block(cx, &msg));
            }
            Load::Ready(data) => {
                if let Some(note) = unreachable_note(&data.down) {
                    col = col.child(notice(&note, Tone::Warn));
                }
                col = col
                    .child(self.rules_card(data, cx))
                    .child(self.presets_card(data, cx));
            }
        }
        col.into_any_element()
    }

    fn rules_card(&self, data: &Data, cx: &mut Context<Self>) -> AnyElement {
        let show_nodes = self.selected.is_none();
        let rows: Vec<Vec<AnyElement>> = data
            .rows
            .iter()
            .map(|row| self.rule_cells(row, data, show_nodes, cx))
            .collect();
        // The node chips sit under the rule name, so the two flex columns keep the spare width.
        let cols = [
            Col::fixed("On", 52.),
            Col::flex("Rule").min(RULE_MIN),
            Col::fixed("Effect", 124.),
            Col::flex("Matches").min(MATCHES_MIN),
            Col::fixed("Scope", 112.),
            Col::fixed("Hits (24h)", 76.).right(),
            Col::fixed("", 116.),
        ];
        let fixed: f32 = cols.iter().filter_map(|col| col.width).sum();
        let body = wide(
            id("fw", "rules"),
            fixed + RULE_MIN + MATCHES_MIN + 20.,
            table(
                &cols,
                rows,
                Some(empty_state(
                    "No firewall rules",
                    "Add a rule or apply a preset below.",
                )),
            ),
        );
        card(
            Some("Rules"),
            Some("First match wins. Redirects and headers apply after blocks."),
            body,
        )
        .into_any_element()
    }

    // The cells of one table row. The switch, Edit and Delete act on the nodes that hold the row.
    fn rule_cells(
        &self,
        row: &RuleRow,
        data: &Data,
        show_nodes: bool,
        cx: &mut Context<Self>,
    ) -> Vec<AnyElement> {
        let r = &row.rule;
        let (flip, edit_row, del_row) = (row.clone(), row.clone(), row.clone());
        let sw = toggle(id("rule-on", &row.key), enabled_everywhere(row)).on_click(cx.listener(
            move |this, _, _, cx| {
                this.toggle_rule(&flip, cx);
                cx.notify();
            },
        ));
        let edit = compact(btn(id("rule-edit", &row.key), "Edit", BtnKind::Plain)).on_click(
            cx.listener(move |this, _, _, cx| {
                this.edit_rule(&edit_row, cx);
                cx.notify();
            }),
        );
        let del = compact(btn(id("rule-del", &row.key), "Delete", BtnKind::Danger)).on_click(
            cx.listener(move |this, _, _, cx| {
                this.delete_rule(&del_row);
                cx.notify();
            }),
        );

        let mut title = div().flex().flex_wrap().items_center().gap(px(6.)).child(
            // Shrinks with the column so a long name wraps instead of running under the next cell.
            strong(r.name.clone())
                .min_w_0()
                .debug_selector(|| format!("fw-title-{}", row.key)),
        );
        if row.differs {
            title = title.child(tip(
                pill("differs", Tone::Warn),
                id("fw-differs", &row.key),
                "Another node holds a different version of this rule",
            ));
        }
        let mut name_cell = div()
            .flex()
            .flex_col()
            .flex_1()
            .min_w_0()
            .debug_selector(|| format!("fw-name-{}", row.key))
            .child(title)
            .child(mono(r.id.clone()).text_color(c(DIM)));
        if let Some(label) = &r.label {
            name_cell = name_cell.child(text_dim(format!("label {label}")).text_size(px(11.)));
        }
        if show_nodes {
            let mut chips = div().flex().flex_wrap().min_w_0().gap(px(4.)).pt(px(4.));
            for holder in &row.holders {
                let on = holder.rule.enabled;
                chips = chips.child(tip(
                    chip(&holder.node, if on { TEXT } else { FAINT }),
                    id("fw-node", format!("{}-{}", row.key, holder.node)),
                    format!("{}: {}", holder.node, if on { "on" } else { "off" }),
                ));
            }
            name_cell = name_cell.child(chips);
        }

        let (effect, tone) = effect_pill(r);
        let mut effect_cell = div()
            .flex()
            .flex_col()
            .flex_1()
            .min_w_0()
            .gap(px(2.))
            .child(div().flex().child(pill(&effect, tone)));
        if let Some(detail) = effect_detail(r) {
            effect_cell = effect_cell.child(
                div()
                    .flex()
                    .flex_col()
                    .min_w_0()
                    .font_family(MONO)
                    .text_size(px(11.))
                    .text_color(c(DIM))
                    .child(detail),
            );
        }

        let patterns = matcher_summary(&r.matchers);
        let matches = if patterns.is_empty() {
            text_dim("Any request").into_any_element()
        } else {
            match_chips(&row.key, &patterns).into_any_element()
        };

        let scope = match &r.site {
            Some(site) => {
                let name = data
                    .sites
                    .iter()
                    .find(|(sid, _)| sid == site)
                    .map_or_else(|| site.clone(), |(_, name)| name.clone());
                clip_tip(id("fw-scope", &row.key), name).into_any_element()
            }
            None => text_dim("All sites").into_any_element(),
        };

        let mut cells = vec![sw.into_any_element(), name_cell.into_any_element()];
        cells.extend([
            effect_cell.into_any_element(),
            matches,
            scope,
            mono(fmt_int(row_hits(row, &data.blocked))).into_any_element(),
            div()
                .flex()
                .gap(px(4.))
                .child(edit)
                .child(del)
                .into_any_element(),
        ]);
        cells
    }

    fn presets_card(&self, data: &Data, cx: &mut Context<Self>) -> AnyElement {
        let mut list = div().flex().flex_wrap().gap(px(12.));
        for p in &data.presets {
            let preset = p.clone();
            let apply = btn(id("preset", &p.name), "Apply", BtnKind::Plain).on_click(cx.listener(
                move |this, _, _, cx| {
                    this.apply_preset(&preset);
                    cx.notify();
                },
            ));
            let count = p.rules.len();
            let count_text = format!("{count} rule{}", if count == 1 { "" } else { "s" });
            let count_pill = if count == 0 {
                pill(&count_text, Tone::Muted).into_any_element()
            } else {
                tip_rows(
                    pill(&count_text, Tone::Muted),
                    id("fw-preset-rules", &p.name),
                    preset_rows(p),
                )
                .into_any_element()
            };
            list = list.child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(8.))
                    .flex_1()
                    .min_w(px(260.))
                    .max_w(px(420.))
                    .p(px(12.))
                    .rounded(px(crate::theme::CARD_RADIUS))
                    .border_1()
                    .border_color(c(crate::theme::BORDER))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .gap(px(8.))
                            .child(strong(p.title.clone()))
                            .child(count_pill),
                    )
                    .child(text_dim(preset_blurb(&p.description)).text_size(px(12.)))
                    .child(div().flex().child(apply)),
            );
        }
        if data.presets.is_empty() {
            list = list.child(text_dim("No presets available."));
        }
        card(Some("Presets"), None, list).into_any_element()
    }

    fn rule_form(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let f = &self.firewall;
        let editing = f.editing.is_some();
        let half = |label: &str, hint: Option<&str>, e: &Entity<TextInput>| {
            div()
                .flex()
                .flex_col()
                .flex_1()
                .child(field(label, hint, e.clone()))
        };
        let mut kinds = Vec::new();
        for kind in [RuleKind::Block, RuleKind::Redirect, RuleKind::Effects] {
            kinds.push(
                seg_item(id("fw-kind", kind.label()), kind.label(), f.kind == kind)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.firewall.kind = kind;
                        cx.notify();
                    }))
                    .into_any_element(),
            );
        }
        let mut form = div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(half("Name", None, &f.name))
                    .child(half(
                        "Label",
                        Some("Shown in logs and the blocked-by-rule table"),
                        &f.label,
                    )),
            )
            .child(field(
                "Site",
                Some("A site id. Empty means every site."),
                f.site.clone(),
            ))
            .child(field(
                "Rule type",
                Some(f.kind.help()),
                div().flex().child(seg_row(kinds)),
            ));
        form = match f.kind {
            RuleKind::Block => form.child(self.block_section(cx)),
            RuleKind::Redirect => form.child(self.redirect_section(cx)),
            RuleKind::Effects => form.child(self.effects_section(cx)),
        };
        form = form
            .child(strong("Matchers").text_size(px(13.)))
            .child(
                text_dim(
                    "Values of one matcher are alternatives. Every filled matcher must match.",
                )
                .text_size(px(12.)),
            )
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(half(
                        "Path regex",
                        Some("Separate several with spaces; any one may match"),
                        &f.path_regex,
                    ))
                    .child(half(
                        "Path prefix",
                        Some("Separate several with commas; any one may match"),
                        &f.path_prefix,
                    )),
            )
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(half("Methods", Some("Comma separated"), &f.methods))
                    .child(half("User agent regex", None, &f.ua)),
            )
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(half(
                        "Client CIDR ranges",
                        Some("Comma separated"),
                        &f.cidrs,
                    ))
                    .child(half("Host", None, &f.host)),
            )
            .child(self.header_matcher_section(cx))
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .flex_1()
                            .child(self.scheme_field(cx)),
                    )
                    .child(half("Referer regex", None, &self.firewall.referer)),
            );
        if let Some(err) = &self.firewall.error {
            form = form.child(notice(err, Tone::Bad));
        }
        form = form.child(
            div().flex().child(
                btn(
                    id("fw", "save"),
                    if editing { "Save rule" } else { "Add rule" },
                    BtnKind::Primary,
                )
                .on_click(cx.listener(|this, _, _, cx| {
                    if !this.firewall.saving {
                        this.submit_rule(cx);
                    }
                    cx.notify();
                })),
            ),
        );
        card(
            Some(if editing {
                "Edit firewall rule"
            } else {
                "Add firewall rule"
            }),
            Some("You pick the nodes when you save."),
            form,
        )
        .into_any_element()
    }

    fn block_section(&self, cx: &mut Context<Self>) -> AnyElement {
        let mut actions = Vec::new();
        for a in [
            FirewallAction::Deny,
            FirewallAction::Drop,
            FirewallAction::Tarpit,
        ] {
            actions.push(
                seg_item(
                    id("fw-action", action_label(a)),
                    action_label(a),
                    self.firewall.action == a,
                )
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.firewall.action = a;
                    cx.notify();
                }))
                .into_any_element(),
            );
        }
        field(
            "Action",
            Some(action_help(self.firewall.action)),
            div().flex().child(seg_row(actions)),
        )
        .into_any_element()
    }

    fn redirect_section(&self, cx: &mut Context<Self>) -> AnyElement {
        let mut statuses = Vec::new();
        for status in REDIRECT_STATUSES {
            statuses.push(
                seg_item(
                    id("fw-status", status),
                    &status.to_string(),
                    self.firewall.redirect_status == status,
                )
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.firewall.redirect_status = status;
                    cx.notify();
                }))
                .into_any_element(),
            );
        }
        let mut examples = div().flex().flex_wrap().items_center().gap(px(6.));
        examples = examples.child(text_dim("Examples").text_size(px(11.)));
        for (i, example) in REDIRECT_EXAMPLES.iter().enumerate() {
            let text = (*example).to_string();
            examples = examples.child(btn(id("fw-example", i), example, BtnKind::Plain).on_click(
                cx.listener(move |this, _, _, cx| {
                    let value = text.clone();
                    this.firewall
                        .redirect_to
                        .update(cx, |input, cx| input.set_text(&value, cx));
                    cx.notify();
                }),
            ));
        }
        div()
            .flex()
            .flex_col()
            .gap(px(10.))
            .child(field(
                "Redirect to",
                Some(&format!(
                    "An absolute http(s) URL or a path starting with /. Placeholders: {REDIRECT_PLACEHOLDERS}"
                )),
                self.firewall.redirect_to.clone(),
            ))
            .child(examples)
            .child(field(
                "Status",
                Some("301 and 308 are permanent; 302 and 307 are temporary."),
                div().flex().child(seg_row(statuses)),
            ))
            .into_any_element()
    }

    fn effects_section(&self, cx: &mut Context<Self>) -> AnyElement {
        let f = &self.firewall;
        let mut ops = div().flex().flex_col().gap(px(8.));
        for (i, row) in f.ops.iter().enumerate() {
            ops = ops.child(self.op_row(i, row, cx));
        }
        if f.ops.is_empty() {
            ops = ops.child(text_dim("No header changes yet.").text_size(px(12.)));
        }
        let can_add = f.ops.len() < MAX_HEADER_OPS;
        let add = if can_add {
            btn(id("fw-op", "add"), "Add header change", BtnKind::Plain)
                .on_click(cx.listener(|this, _, _, cx| {
                    let row = OpRow {
                        target: HeaderTarget::Response,
                        op: HeaderOpKind::Set,
                        name: new_input(cx, "X-Frame-Options", |i| i.mono()),
                        value: new_input(cx, "DENY", |i| i.mono()),
                    };
                    this.firewall.ops.push(row);
                    cx.notify();
                }))
                .into_any_element()
        } else {
            text_dim(format!("At most {MAX_HEADER_OPS} header changes."))
                .text_size(px(12.))
                .into_any_element()
        };
        let cors_box =
            checkbox(id("fw-cors", "on"), f.cors_on).on_click(cx.listener(|this, _, _, cx| {
                this.firewall.cors_on = !this.firewall.cors_on;
                cx.notify();
            }));
        let mut cors = div().flex().flex_col().gap(px(10.)).child(
            div()
                .flex()
                .items_center()
                .gap(px(10.))
                .child(cors_box)
                .child(div().flex().flex_col().child("Answer CORS requests")),
        );
        if f.cors_on {
            cors = cors.child(self.cors_fields(cx));
        }
        div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(field(
                "Header changes",
                Some("Set, add or remove request or response headers."),
                ops,
            ))
            .child(div().flex().child(add))
            .child(cors)
            .into_any_element()
    }

    fn op_row(&self, i: usize, row: &OpRow, cx: &mut Context<Self>) -> AnyElement {
        let mut targets = Vec::new();
        for t in [HeaderTarget::Request, HeaderTarget::Response] {
            targets.push(
                seg_item(
                    id("fw-op-target", format!("{i}-{}", target_label(t))),
                    target_label(t),
                    row.target == t,
                )
                .on_click(cx.listener(move |this, _, _, cx| {
                    if let Some(r) = this.firewall.ops.get_mut(i) {
                        r.target = t;
                    }
                    cx.notify();
                }))
                .into_any_element(),
            );
        }
        let mut kinds = Vec::new();
        for op in [HeaderOpKind::Set, HeaderOpKind::Add, HeaderOpKind::Remove] {
            kinds.push(
                seg_item(
                    id("fw-op-kind", format!("{i}-{}", op_label(op))),
                    op_label(op),
                    row.op == op,
                )
                .on_click(cx.listener(move |this, _, _, cx| {
                    if let Some(r) = this.firewall.ops.get_mut(i) {
                        r.op = op;
                    }
                    cx.notify();
                }))
                .into_any_element(),
            );
        }
        let value: AnyElement = if row.op == HeaderOpKind::Remove {
            text_dim("No value needed")
                .text_size(px(12.))
                .into_any_element()
        } else {
            row.value.clone().into_any_element()
        };
        div()
            .flex()
            .flex_wrap()
            .items_center()
            .gap(px(8.))
            .child(seg_row(targets))
            .child(seg_row(kinds))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_w(px(140.))
                    .max_w(px(220.))
                    .child(row.name.clone()),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_w(px(160.))
                    .child(value),
            )
            .child(
                btn(id("fw-op-del", i), "Remove", BtnKind::Danger).on_click(cx.listener(
                    move |this, _, _, cx| {
                        if i < this.firewall.ops.len() {
                            let gone = this.firewall.ops.remove(i);
                            for input in [gone.name, gone.value] {
                                input.update(cx, |t, cx| t.set_text("", cx));
                            }
                        }
                        cx.notify();
                    },
                )),
            )
            .into_any_element()
    }

    fn cors_fields(&self, cx: &mut Context<Self>) -> AnyElement {
        let f = &self.firewall;
        let half = |label: &str, hint: Option<&str>, e: &Entity<TextInput>| {
            div()
                .flex()
                .flex_col()
                .flex_1()
                .child(field(label, hint, e.clone()))
        };
        let creds = checkbox(id("fw-cors", "creds"), f.cors_credentials).on_click(cx.listener(
            |this, _, _, cx| {
                this.firewall.cors_credentials = !this.firewall.cors_credentials;
                cx.notify();
            },
        ));
        let mut col = div()
            .flex()
            .flex_col()
            .gap(px(10.))
            .child(field(
                "Allowed origins",
                Some("Exact origins such as https://app.example.com, separated by spaces or commas, or a single *. At most 32."),
                f.cors_origins.clone(),
            ))
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(half("Methods", Some("Comma separated"), &f.cors_methods))
                    .child(half("Allowed headers", Some("Comma separated"), &f.cors_allow)),
            )
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(half("Exposed headers", Some("Comma separated"), &f.cors_expose))
                    .child(half("Max age (seconds)", Some("0 to 86400"), &f.cors_max_age)),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .child(creds)
                    .child(div().flex().flex_col().child("Allow credentials")),
            );
        if f.cors_credentials {
            col = col.child(
                text_dim("Credentials need exact origins; * is refused with them.")
                    .text_size(px(12.)),
            );
        }
        col.into_any_element()
    }

    fn header_matcher_section(&self, cx: &mut Context<Self>) -> AnyElement {
        let f = &self.firewall;
        let mut modes = Vec::new();
        for (regex, label) in [(false, "Equals"), (true, "Regex")] {
            modes.push(
                seg_item(id("fw-hmode", label), label, f.header_regex == regex)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.firewall.header_regex = regex;
                        if regex {
                            this.set_header_secret(false, cx);
                        }
                        cx.notify();
                    }))
                    .into_any_element(),
            );
        }
        let value = if f.header_secret {
            f.header_secret_value.clone()
        } else {
            f.header_value.clone()
        };
        let negate = checkbox(id("fw-header", "negate"), f.header_negate).on_click(cx.listener(
            |this, _, _, cx| {
                this.firewall.header_negate = !this.firewall.header_negate;
                cx.notify();
            },
        ));
        let secret = checkbox(id("fw-header", "secret"), f.header_secret).on_click(cx.listener(
            |this, _, _, cx| {
                let on = !this.firewall.header_secret;
                if on && this.firewall.header_regex {
                    this.firewall.error =
                        Some("A secret header value can only be compared for equality.".into());
                } else {
                    this.set_header_secret(on, cx);
                }
                cx.notify();
            },
        ));
        let toggles = div()
            .flex()
            .flex_col()
            .gap(px(6.))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .child(negate)
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .child("Match when the header is not this value"),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .child(secret)
                    .child(div().flex().flex_col().child("Secret value")),
            )
            .child(
                text_dim("A secret value is hidden, never listed and cannot be read back.")
                    .text_size(px(11.)),
            );
        div()
            .flex()
            .flex_col()
            .gap(px(10.))
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(div().flex().flex_col().flex_1().child(field(
                        "Header name",
                        Some("Optional. Letters, digits, - and _."),
                        f.header_name.clone(),
                    )))
                    .child(div().flex().flex_col().flex_1().child(field(
                        "Header value",
                        None,
                        value,
                    )))
                    .child(div().flex().flex_col().child(field(
                        "Compare as",
                        None,
                        div().flex().child(seg_row(modes)),
                    ))),
            )
            .child(toggles)
            .into_any_element()
    }

    fn scheme_field(&self, cx: &mut Context<Self>) -> AnyElement {
        let mut items = Vec::new();
        for (value, label) in [
            (None, "Any"),
            (Some("http"), "HTTP"),
            (Some("https"), "HTTPS"),
        ] {
            items.push(
                seg_item(id("fw-scheme", label), label, self.firewall.scheme == value)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.firewall.scheme = value;
                        cx.notify();
                    }))
                    .into_any_element(),
            );
        }
        field(
            "Scheme",
            Some("How the visitor connected"),
            div().flex().child(seg_row(items)),
        )
        .into_any_element()
    }
}

#[cfg(test)]
mod tests {
    use cite_edge::model::{Matchers, Redirect};

    use super::*;

    fn rule(id: &str, name: &str, enabled: bool) -> FirewallRule {
        FirewallRule {
            id: id.to_string(),
            name: name.to_string(),
            enabled,
            action: Some(FirewallAction::Deny),
            ..FirewallRule::default()
        }
    }

    fn with_path(mut r: FirewallRule, regex: &str) -> FirewallRule {
        r.matchers.path_regexes = vec![regex.to_string()];
        r
    }

    fn per_node(entries: Vec<(&str, Vec<FirewallRule>)>) -> Vec<(String, Vec<FirewallRule>)> {
        entries
            .into_iter()
            .map(|(n, r)| (n.to_string(), r))
            .collect()
    }

    fn top(key: &str, count: u64) -> TopItem {
        TopItem {
            key: key.to_string(),
            count,
            bytes: 0,
        }
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn identical_rules_merge_into_one_row_and_ignore_the_enabled_flag() {
        let rows = merge_rules(&per_node(vec![
            ("a", vec![rule("wp", "WordPress", true)]),
            ("b", vec![rule("wp", "WordPress", false)]),
        ]));
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].differs);
        assert_eq!(rows[0].key, "wp");
        let nodes: Vec<&str> = rows[0].holders.iter().map(|h| h.node.as_str()).collect();
        assert_eq!(nodes, ["a", "b"]);
        assert!(rows[0].holders[0].rule.enabled);
        assert!(!rows[0].holders[1].rule.enabled);
    }

    #[test]
    fn a_same_id_rule_with_different_content_is_never_merged() {
        let rows = merge_rules(&per_node(vec![
            ("a", vec![with_path(rule("wp", "WordPress", true), "^/wp-")]),
            (
                "b",
                vec![with_path(rule("wp", "WordPress", true), "^/admin")],
            ),
            (
                "c",
                vec![with_path(rule("wp", "WordPress", false), "^/wp-")],
            ),
        ]));
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.differs));
        assert_eq!(rows[0].key, "wp#0");
        assert_eq!(rows[1].key, "wp#1");
        let first: Vec<&str> = rows[0].holders.iter().map(|h| h.node.as_str()).collect();
        let second: Vec<&str> = rows[1].holders.iter().map(|h| h.node.as_str()).collect();
        assert_eq!(first, ["a", "c"]);
        assert_eq!(second, ["b"]);
    }

    #[test]
    fn rules_held_by_only_one_node_keep_their_order_and_holder() {
        let rows = merge_rules(&per_node(vec![
            (
                "a",
                vec![rule("one", "One", true), rule("two", "Two", true)],
            ),
            ("b", vec![rule("three", "Three", true)]),
        ]));
        let keys: Vec<&str> = rows.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(keys, ["one", "two", "three"]);
        assert_eq!(rows[2].holders.len(), 1);
        assert_eq!(rows[2].holders[0].node, "b");
    }

    #[test]
    fn the_switch_reads_on_only_when_every_holder_has_the_rule_on() {
        let rows = merge_rules(&per_node(vec![
            ("a", vec![rule("wp", "WordPress", true)]),
            ("b", vec![rule("wp", "WordPress", false)]),
        ]));
        assert!(!enabled_everywhere(&rows[0]));
        let both = merge_rules(&per_node(vec![
            ("a", vec![rule("wp", "WordPress", true)]),
            ("b", vec![rule("wp", "WordPress", true)]),
        ]));
        assert!(enabled_everywhere(&both[0]));
    }

    #[test]
    fn hits_match_by_id_then_label_then_name() {
        let mut r = rule("wp-1", "WordPress", true);
        assert_eq!(rule_hits(&r, &[top("wp-1", 7), top("WordPress", 99)]), 7);
        assert_eq!(rule_hits(&r, &[top("WordPress", 4)]), 4);
        r.label = Some("wp-probe".to_string());
        assert_eq!(rule_hits(&r, &[top("wp-probe", 5), top("WordPress", 4)]), 5);
        assert_eq!(rule_hits(&r, &[top("other", 3)]), 0);
        assert_eq!(rule_hits(&r, &[]), 0);
    }

    #[test]
    fn hits_are_summed_over_the_nodes_that_hold_the_row() {
        let rows = merge_rules(&per_node(vec![
            ("a", vec![rule("wp", "WordPress", true)]),
            ("b", vec![rule("wp", "WordPress", true)]),
            ("c", vec![]),
        ]));
        let blocked = vec![
            ("a".to_string(), vec![top("wp", 10)]),
            ("b".to_string(), vec![top("wp", 5)]),
            ("c".to_string(), vec![top("wp", 1000)]),
        ];
        assert_eq!(row_hits(&rows[0], &blocked), 15);
        assert_eq!(row_hits(&rows[0], &[]), 0);
    }

    #[test]
    fn first_per_key_keeps_the_first_copy_in_order() {
        let merged = first_per_key(["b:1", "a:2", "b:3"], |s| s[..1].to_string());
        assert_eq!(merged, ["b:1", "a:2"]);
    }

    fn info(name: &str, online: bool) -> NodeInfo {
        NodeInfo {
            name: name.to_string(),
            online,
        }
    }

    #[test]
    fn a_rule_only_goes_to_online_nodes_that_hold_its_site() {
        let nodes = [info("a", true), info("b", true), info("c", false)];
        let sites = vec![
            ("a".to_string(), strs(&["shop", "blog"])),
            ("b".to_string(), strs(&["blog"])),
            ("c".to_string(), strs(&["shop"])),
        ];
        assert_eq!(writable_nodes(&nodes, &sites, None), strs(&["a", "b"]));
        assert_eq!(writable_nodes(&nodes, &sites, Some("shop")), strs(&["a"]));
        assert_eq!(
            writable_nodes(&nodes, &sites, Some("blog")),
            strs(&["a", "b"])
        );
        assert!(writable_nodes(&nodes, &sites, Some("none")).is_empty());
        assert!(writable_nodes(&nodes, &[], Some("shop")).is_empty());
    }

    #[test]
    fn unreachable_nodes_are_named_in_one_line() {
        assert_eq!(unreachable_note(&[]), None);
        assert_eq!(
            unreachable_note(&strs(&["edge-nyc"])).as_deref(),
            Some("edge-nyc is unreachable and is left out.")
        );
        assert_eq!(
            unreachable_note(&strs(&["edge-nyc", "edge-fra"])).as_deref(),
            Some("edge-nyc, edge-fra are unreachable and are left out.")
        );
    }

    #[test]
    fn a_preset_description_is_cut_to_its_first_sentence() {
        assert_eq!(
            preset_blurb("Blocks probes. Also logs them for review."),
            "Blocks probes."
        );
        assert_eq!(preset_blurb("  Blocks probes  "), "Blocks probes");
        assert_eq!(
            preset_blurb("Is this v1.2 safe? Yes."),
            "Is this v1.2 safe?"
        );
        assert_eq!(preset_blurb(""), "");
    }

    fn preset(rules: Vec<FirewallRule>) -> PresetInfo {
        PresetInfo {
            name: "p".to_string(),
            title: "P".to_string(),
            description: String::new(),
            rules,
        }
    }

    fn redirect_rule(site: Option<&str>) -> FirewallRule {
        FirewallRule {
            id: "r".to_string(),
            name: "Move".to_string(),
            enabled: true,
            redirect: Some(Redirect {
                to: "/new".to_string(),
                status: 301,
            }),
            site: site.map(str::to_string),
            ..FirewallRule::default()
        }
    }

    #[test]
    fn only_a_preset_with_a_siteless_redirect_needs_the_scope_warning() {
        assert!(preset_needs_scope_warning(&preset(vec![redirect_rule(
            None
        )])));
        assert!(!preset_needs_scope_warning(&preset(vec![redirect_rule(
            Some("shop")
        )])));
        assert!(!preset_needs_scope_warning(&preset(vec![rule(
            "a", "A", true
        )])));
    }

    #[test]
    fn preset_rows_list_every_rule_with_its_action_and_patterns() {
        let drop = FirewallRule {
            action: Some(FirewallAction::Drop),
            matchers: Matchers {
                path_regexes: vec!["^/wp-".to_string()],
                methods: vec!["TRACE".to_string()],
                ..Matchers::default()
            },
            ..rule("d", "Probes", true)
        };
        let rows = preset_rows(&preset(vec![
            drop,
            redirect_rule(None),
            rule("any", "Everything", true),
        ]));
        assert_eq!(
            rows,
            vec![
                (
                    "Probes".to_string(),
                    Some("Drop".to_string()),
                    "path ~ ^/wp-\nTRACE".to_string()
                ),
                (
                    "Move".to_string(),
                    Some("Redirect".to_string()),
                    "to /new".to_string()
                ),
                (
                    "Everything".to_string(),
                    Some("Deny".to_string()),
                    "Every request".to_string()
                ),
            ]
        );
    }

    #[test]
    fn rules_the_form_cannot_hold_are_not_editable() {
        use cite_edge::model::HeaderMatch;
        let header = |secret: bool| HeaderMatch {
            name: "X-Key".to_string(),
            equals: Some("v".to_string()),
            secret,
            ..HeaderMatch::default()
        };
        let mut r = rule("a", "A", true);
        assert_eq!(edit_problem(&r), None);
        r.matchers.headers = vec![header(false)];
        assert_eq!(edit_problem(&r), None);
        r.matchers.headers = vec![header(true)];
        assert!(edit_problem(&r).is_some());
        r.matchers.headers = vec![header(false), header(false)];
        assert!(edit_problem(&r).is_some());
        let spaced = with_path(rule("b", "B", true), "a b");
        assert!(edit_problem(&spaced).is_some());
    }
}
