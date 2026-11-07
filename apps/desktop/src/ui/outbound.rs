use std::net::IpAddr;

use cite_client::{OutboundMode, OutboundRules};
use cite_edge::model::Site;
use gpui::{AnyElement, Context, Entity, div, prelude::*, px};

use crate::app::{Console, new_input};
use crate::siteops::{CAP_OUTBOUND, has_cap};
use crate::theme::{DIVIDER, Tone, c};
use crate::ui::detail::Data;
use crate::ui::detail::volumes::volumes_apply;
use crate::ui::input::TextInput;
use crate::ui::widgets::{
    BtnKind, btn, card, id, mono, notice, seg_item, seg_row, strong, text_dim, toggle,
};

pub const MAX_ENTRIES: usize = 64;
const MAX_HOST: usize = 253;
const SWITCH_HELP: &str = "Lets this site's server code make requests to the public internet. Private, internal and Docker addresses are blocked unless you allow them below. Applies on the next deploy.";

fn is_allowlist(r: &OutboundRules) -> bool {
    r.mode == OutboundMode::Allowlist
}

fn ip_problem(text: &str) -> String {
    format!("{text} is not a valid IP address.")
}

fn cidr(text: &str) -> Result<String, String> {
    let Some((addr, bits)) = text.split_once('/') else {
        return Err(ip_problem(text));
    };
    let ip: IpAddr = addr.parse().map_err(|_| ip_problem(addr))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    match bits.parse::<u8>() {
        Ok(n) if n <= max => Ok(format!("{ip}/{n}")),
        _ => Err(format!("The prefix length of {addr} is 0 to {max}.")),
    }
}

// A leading *. means the same as a leading dot: the name and everything under it.
fn host(text: &str) -> Result<String, String> {
    let name = match text.strip_prefix("*.") {
        Some(rest) => format!(".{rest}"),
        None => text.to_string(),
    };
    let body = name.strip_prefix('.').unwrap_or(&name);
    if body.is_empty() || name.len() > MAX_HOST {
        return Err("A host name is 1 to 253 characters.".into());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
    {
        return Err("Host names use letters, digits, . and - only.".into());
    }
    if body
        .split('.')
        .any(|l| l.is_empty() || l.starts_with('-') || l.ends_with('-'))
    {
        return Err(format!("{name} is not a valid host name."));
    }
    Ok(name)
}

// An IP, a CIDR range or a host name or suffix, normalised to lower case with a leading dot for suffixes.
pub fn normalize_entry(text: &str) -> Result<String, String> {
    let t = text.trim().to_ascii_lowercase();
    if t.is_empty() {
        return Err("Type an address, a CIDR range or a host name.".into());
    }
    if t.contains('/') {
        return cidr(&t);
    }
    if t.contains(':') || t.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return t
            .parse::<IpAddr>()
            .map(|ip| ip.to_string())
            .map_err(|_| ip_problem(&t));
    }
    host(&t)
}

pub fn add_entry(text: &str, list: &[String]) -> Result<String, String> {
    let entry = normalize_entry(text)?;
    if list.contains(&entry) {
        return Err(format!("{entry} is already listed."));
    }
    if list.len() >= MAX_ENTRIES {
        return Err("A list holds at most 64 entries.".into());
    }
    Ok(entry)
}

// Why the rules cannot be saved, or None when they can.
pub fn rules_problem(r: &OutboundRules) -> Option<String> {
    if is_allowlist(r) && r.allow.is_empty() {
        return Some(
            "The allow list needs at least one entry, or switch to Public internet only.".into(),
        );
    }
    None
}

// The effective policy in plain words.
pub fn summary(on: bool, r: &OutboundRules) -> String {
    if !on {
        return "Outbound requests are blocked.".into();
    }
    let mut text = if is_allowlist(r) {
        if r.allow.is_empty() {
            "Only allow-listed destinations are reachable, and none is listed yet.".to_string()
        } else {
            format!("Only these destinations are reachable: {}.", r.allow.join(", "))
        }
    } else {
        let mut t = "Public internet allowed. Blocked: private networks, Docker, this host, cloud metadata."
            .to_string();
        if !r.allow.is_empty() {
            t.push_str(&format!(" Also allowed: {}.", r.allow.join(", ")));
        }
        t
    };
    if !r.deny.is_empty() {
        let lead = if is_allowlist(r) { "Always blocked" } else { "Also blocked" };
        text.push_str(&format!(" {lead}: {}.", r.deny.join(", ")));
    }
    if r.block_mail {
        text.push_str(" Mail ports 25, 465 and 587 are blocked.");
    }
    text
}

// The switch shows the edit while there is one, otherwise what the node has saved.
pub fn outbound_shown(saved: bool, staged: Option<bool>) -> bool {
    staged.unwrap_or(saved)
}

// The node says its executors have no route out, so nothing on the card can have an effect.
pub fn egress_blocked(egress: Option<bool>, mode: Option<&str>) -> bool {
    egress == Some(false) || mode == Some("off")
}

// The node does not filter, so the rules are stored but not enforced.
pub fn egress_unfiltered(mode: Option<&str>) -> bool {
    mode == Some("open")
}

pub struct OutboundState {
    pub on: Option<bool>,
    pub rules: Option<OutboundRules>,
    pub error: Option<String>,
    pub allow_in: Entity<TextInput>,
    pub deny_in: Entity<TextInput>,
}

impl OutboundState {
    pub fn new(cx: &mut Context<Console>) -> Self {
        Self {
            on: None,
            rules: None,
            error: None,
            allow_in: new_input(cx, "192.168.1.20/32 or api.github.com", |i| i.mono()),
            deny_in: new_input(cx, "10.0.0.0/8 or ads.example.com", |i| i.mono()),
        }
    }

    pub fn clear(&mut self) {
        self.on = None;
        self.rules = None;
        self.error = None;
    }

    pub fn reset(&mut self, cx: &mut Context<Console>) {
        self.clear();
        for input in [self.allow_in.clone(), self.deny_in.clone()] {
            input.update(cx, |i, cx| i.set_text("", cx));
        }
    }

    pub fn apply_to(&self, site: &mut Site) {
        if let Some(on) = self.on {
            site.outbound = on;
        }
        if let Some(r) = &self.rules {
            site.outbound_rules = r.clone();
        }
    }
}

impl Console {
    fn current_rules(&self) -> Option<OutboundRules> {
        let saved = self.detail.data.ready()?.site.outbound_rules.clone();
        Some(self.ops.volumes.outbound.rules.clone().unwrap_or(saved))
    }

    fn outbound_edit(&mut self, change: impl FnOnce(&mut OutboundRules)) {
        let Some(mut rules) = self.current_rules() else {
            return;
        };
        change(&mut rules);
        self.ops.volumes.outbound.rules = Some(rules);
        self.ops.volumes.outbound.error = None;
    }

    fn outbound_add(&mut self, deny: bool, cx: &mut Context<Self>) {
        let Some(mut rules) = self.current_rules() else {
            return;
        };
        let state = &self.ops.volumes.outbound;
        let input = if deny { state.deny_in.clone() } else { state.allow_in.clone() };
        let text = input.read(cx).text().to_string();
        let list = if deny { &mut rules.deny } else { &mut rules.allow };
        match add_entry(&text, list.as_slice()) {
            Ok(entry) => {
                list.push(entry);
                self.ops.volumes.outbound.rules = Some(rules);
                self.ops.volumes.outbound.error = None;
                input.update(cx, |i, cx| i.set_text("", cx));
            }
            Err(e) => self.ops.volumes.outbound.error = Some(e),
        }
    }

    fn outbound_remove(&mut self, deny: bool, entry: &str) {
        self.outbound_edit(|r| {
            let list = if deny { &mut r.deny } else { &mut r.allow };
            list.retain(|e| e != entry);
        });
    }

    fn outbound_list(
        &self,
        deny: bool,
        entries: &[String],
        allowlist: bool,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let (title, hint) = match (deny, allowlist) {
            (false, false) => (
                "Always allow",
                "Reachable even when the address is private, such as a database on your network.",
            ),
            (false, true) => ("Allowed destinations", "The only addresses and hosts this site can reach."),
            (true, _) => ("Always block", "Refused even when allowed above."),
        };
        let prefix = if deny { "ob-deny-rm" } else { "ob-allow-rm" };
        let mut col = div()
            .flex()
            .flex_col()
            .gap(px(6.))
            .child(strong(title).text_size(px(13.)))
            .child(text_dim(hint).text_size(px(11.)));
        if entries.is_empty() {
            col = col.child(text_dim("No entries.").text_size(px(12.)));
        }
        for entry in entries {
            let victim = entry.clone();
            col = col.child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .py(px(4.))
                    .border_b_1()
                    .border_color(c(DIVIDER))
                    .child(div().flex_1().min_w_0().child(mono(entry.clone())))
                    .child(btn(id(prefix, entry), "Remove", BtnKind::Plain).on_click(
                        cx.listener(move |this, _, _, cx| {
                            this.outbound_remove(deny, &victim);
                            cx.notify();
                        }),
                    )),
            );
        }
        let state = &self.ops.volumes.outbound;
        let input = if deny { state.deny_in.clone() } else { state.allow_in.clone() };
        col = col.child(
            div()
                .flex()
                .items_center()
                .gap(px(8.))
                .child(div().flex_1().min_w_0().child(input))
                .child(
                    btn(id(prefix, "add"), "Add", BtnKind::Primary).on_click(cx.listener(
                        move |this, _, _, cx| {
                            this.outbound_add(deny, cx);
                            cx.notify();
                        },
                    )),
                ),
        );
        col.into_any_element()
    }

    pub(crate) fn outbound_card(&self, data: &Data, cx: &mut Context<Self>) -> Option<AnyElement> {
        let ex = &self.ops.extras;
        if !self.ops.loaded || !has_cap(&ex.caps, CAP_OUTBOUND) || !volumes_apply(&data.site) {
            return None;
        }
        let mode = ex.egress_mode.as_deref();
        let blocked = egress_blocked(ex.executor_egress, mode);
        let state = &self.ops.volumes.outbound;
        let on = outbound_shown(data.site.outbound, state.on);
        let rules = state
            .rules
            .clone()
            .unwrap_or_else(|| data.site.outbound_rules.clone());
        let mut switch = toggle(id("outbound", "switch"), on);
        if !blocked {
            switch = switch.on_click(cx.listener(|this, _, _, cx| {
                let saved = this.detail.data.ready().is_some_and(|d| d.site.outbound);
                let now = outbound_shown(saved, this.ops.volumes.outbound.on);
                this.ops.volumes.outbound.on = Some(!now);
                cx.notify();
            }));
        }
        let mut body = div()
            .flex()
            .flex_col()
            .gap(px(14.))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(12.))
                    .child(switch)
                    .child(strong(if on { "Allowed" } else { "Blocked" })),
            )
            .child(text_dim(SWITCH_HELP).text_size(px(12.)));
        if blocked {
            body = body.child(notice(
                "This node blocks all outbound requests from sites, so this switch and the rules below have no effect until the node allows them.",
                Tone::Warn,
            ));
        } else if egress_unfiltered(mode) {
            body = body.child(notice(
                "This node does not filter outbound traffic: the rules below are saved but not enforced.",
                Tone::Warn,
            ));
        }
        if on && !blocked {
            let allowlist = is_allowlist(&rules);
            let modes = seg_row(vec![
                seg_item(id("ob-mode", "public"), "Public internet only", !allowlist)
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.outbound_edit(|r| r.mode = OutboundMode::Public);
                        cx.notify();
                    }))
                    .into_any_element(),
                seg_item(id("ob-mode", "allowlist"), "Only my allow list", allowlist)
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.outbound_edit(|r| r.mode = OutboundMode::Allowlist);
                        cx.notify();
                    }))
                    .into_any_element(),
            ]);
            body = body
                .child(div().flex().child(modes))
                .child(self.outbound_list(false, &rules.allow, allowlist, cx))
                .child(self.outbound_list(true, &rules.deny, allowlist, cx))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(10.))
                        .child(toggle(id("ob", "mail"), rules.block_mail).on_click(cx.listener(
                            |this, _, _, cx| {
                                this.outbound_edit(|r| r.block_mail = !r.block_mail);
                                cx.notify();
                            },
                        )))
                        .child(div().text_size(px(12.)).child("Block mail ports (25, 465, 587)")),
                );
            if let Some(e) = &state.error {
                body = body.child(
                    text_dim(e.clone())
                        .text_size(px(12.))
                        .text_color(c(Tone::Bad.color())),
                );
            }
            if let Some(p) = rules_problem(&rules) {
                body = body.child(
                    text_dim(p)
                        .text_size(px(12.))
                        .text_color(c(Tone::Bad.color())),
                );
            }
        }
        body = body.child(strong(summary(on, &rules)).text_size(px(12.)));
        Some(card(Some("Outbound network access"), None, body).into_any_element())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(mode: &str, allow: &[&str], deny: &[&str], mail: bool) -> OutboundRules {
        OutboundRules {
            mode: if mode == "allowlist" { OutboundMode::Allowlist } else { OutboundMode::Public },
            allow: allow.iter().map(|s| s.to_string()).collect(),
            deny: deny.iter().map(|s| s.to_string()).collect(),
            block_mail: mail,
        }
    }

    #[test]
    fn entries_are_validated_and_normalised() {
        let ok = [
            ("192.168.1.20/32", "192.168.1.20/32"),
            ("10.0.0.0/8", "10.0.0.0/8"),
            (" 192.168.1.20 ", "192.168.1.20"),
            ("fd00::/8", "fd00::/8"),
            ("::1", "::1"),
            ("API.GitHub.com", "api.github.com"),
            (".apple.com", ".apple.com"),
            ("*.apple.com", ".apple.com"),
            ("my-host", "my-host"),
        ];
        for (typed, want) in ok {
            assert_eq!(normalize_entry(typed).as_deref(), Ok(want), "{typed}");
        }
        for bad in [
            "", "  ", "10.0.0.0/33", "10.0.0.0/x", "300.1.1.1", "1.2.3", "fd00::/129", "a b.com",
            "under_score.com", "*", "*.", ".", "a..b.com", "-bad.com", "bad-.com", "http://x.com",
            "ex*ample.com",
        ] {
            assert!(normalize_entry(bad).is_err(), "{bad:?}");
        }
        assert!(normalize_entry(&"a".repeat(254)).is_err());
        assert!(normalize_entry(&format!("{}.com", "a".repeat(60))).is_ok());
    }

    #[test]
    fn lists_refuse_duplicates_and_stay_within_64() {
        let list = vec!["api.github.com".to_string()];
        assert!(add_entry("API.github.com", &list).unwrap_err().contains("already listed"));
        assert_eq!(add_entry("*.apple.com", &list).as_deref(), Ok(".apple.com"));
        let full: Vec<String> = (0..MAX_ENTRIES).map(|i| format!("h{i}.example.com")).collect();
        assert!(add_entry("extra.example.com", &full).unwrap_err().contains("64"));
        assert!(add_entry("extra.example.com", &full[..MAX_ENTRIES - 1]).is_ok());
    }

    #[test]
    fn the_mode_decides_what_must_be_listed() {
        assert_eq!(rules_problem(&OutboundRules::default()), None);
        assert!(rules_problem(&rules("allowlist", &[], &[], true)).unwrap().contains("at least one"));
        assert!(rules_problem(&rules("allowlist", &[], &["x.com"], true)).is_some());
        assert_eq!(rules_problem(&rules("allowlist", &["api.github.com"], &[], true)), None);
        assert_eq!(rules_problem(&rules("public", &[], &[], false)), None);
    }

    #[test]
    fn the_summary_states_the_effective_policy() {
        let public = rules("public", &["192.168.1.20/32"], &["ads.example.com"], false);
        assert_eq!(
            summary(true, &public),
            "Public internet allowed. Blocked: private networks, Docker, this host, cloud metadata. Also allowed: 192.168.1.20/32. Also blocked: ads.example.com."
        );
        assert!(summary(true, &rules("public", &[], &[], true)).ends_with("Mail ports 25, 465 and 587 are blocked."));
        assert_eq!(summary(false, &public), "Outbound requests are blocked.");
        let only = rules("allowlist", &["api.github.com", ".apple.com"], &["bad.apple.com"], false);
        assert_eq!(
            summary(true, &only),
            "Only these destinations are reachable: api.github.com, .apple.com. Always blocked: bad.apple.com."
        );
        assert!(summary(true, &rules("allowlist", &[], &[], false)).contains("none is listed"));
    }

    #[test]
    fn the_nodes_egress_decides_what_applies() {
        assert!(outbound_shown(true, None) && !outbound_shown(true, Some(false)));
        assert!(egress_blocked(Some(false), None));
        assert!(egress_blocked(None, Some("off")));
        assert!(!egress_blocked(Some(true), Some("filtered")) && !egress_blocked(None, None));
        assert!(egress_unfiltered(Some("open")));
        assert!(!egress_unfiltered(Some("filtered")) && !egress_unfiltered(None));
    }
}
