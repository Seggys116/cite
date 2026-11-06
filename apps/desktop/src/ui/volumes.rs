use cite_client::VolumeInfo;
use cite_edge::model::{RenderMode, Site, Source, Volume};
use gpui::{AnyElement, Context, Entity, div, prelude::*, px};

use crate::api::{NodeHandle, Res};
use crate::app::{Confirm, Console, new_input};
use crate::demo::now_ms;
use crate::model::{fmt_bytes, parse_rfc3339_ms, rel_time};
use crate::theme::Tone;
use crate::ui::detail::Data;
use crate::ui::input::TextInput;
use crate::ui::widgets::{
    BtnKind, Col, btn, btn_off, card, empty_state, field, id, mono, notice, pill, strong, table,
    text_dim, toggle,
};
use crate::siteops::{CAP_OUTBOUND, has_cap};

const MAX_NAME: usize = 31;
const MIN_PATH: usize = 2;
const MAX_PATH: usize = 255;
const RESERVED: [&str; 12] = [
    "/proc", "/sys", "/dev", "/etc", "/run", "/usr", "/bin", "/sbin", "/lib", "/root", "/app",
    "/tmp",
];

// The node wrappers live here because the volume routes are used by this tab only.
impl NodeHandle {
    pub(crate) async fn vol_list(&self, site: &str) -> Res<Vec<VolumeInfo>> {
        match self {
            Self::Live(c) => c.site_volumes(site).await,
            Self::Demo(_, d) => d.volumes(site),
        }
    }

    pub(crate) async fn vol_delete(&self, site: &str, name: &str) -> Res<()> {
        match self {
            Self::Live(c) => c.site_volume_delete(site, name).await,
            Self::Demo(_, d) => d.volume_delete(site, name),
        }
    }
}

// Only a site the node runs as a server has a container to mount into; a static build is served from files.
pub fn source_serves(source: Option<&Source>) -> bool {
    source.is_some_and(|s| {
        s.rendering != Some(RenderMode::Static) && s.runtime.as_deref() != Some("static")
    })
}

pub fn volumes_apply(site: &Site) -> bool {
    source_serves(site.source.as_ref())
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'
}

// The node's own rule: [a-z0-9][a-z0-9-]{0,30}, and unique within the site.
pub fn name_problem(name: &str, taken: &[String]) -> Option<String> {
    if name.is_empty() {
        return Some("Type a volume name.".into());
    }
    let starts_ok = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    if name.chars().count() > MAX_NAME || !starts_ok || !name.chars().all(is_name_char) {
        return Some(
            "A volume name is 1 to 31 characters: lower case letters, digits and -, starting with a letter or digit."
                .into(),
        );
    }
    if taken.iter().any(|t| t == name) {
        return Some(format!("A volume named {name} already exists."));
    }
    None
}

fn under(path: &str, root: &str) -> bool {
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('/'))
}

// Two mounts overlap when they are the same folder or one sits inside the other.
pub fn overlaps(a: &str, b: &str) -> bool {
    under(a, b) || under(b, a)
}

// The node's own rule for a mount path, plus a check against the paths already used.
pub fn path_problem(path: &str, others: &[String]) -> Option<String> {
    if !path.starts_with('/') {
        return Some("The mount path must be absolute and start with /.".into());
    }
    let len = path.chars().count();
    if !(MIN_PATH..=MAX_PATH).contains(&len) {
        return Some("The mount path is 2 to 255 characters.".into());
    }
    if !path
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'))
    {
        return Some("The mount path may use letters, digits and . _ / - only.".into());
    }
    if path.contains("..") {
        return Some("The mount path cannot contain ..".into());
    }
    if path.ends_with('/') {
        return Some("The mount path cannot end with /.".into());
    }
    if let Some(root) = RESERVED.iter().find(|r| under(path, r)) {
        return Some(format!("{root} is reserved: choose another folder."));
    }
    others
        .iter()
        .find(|o| overlaps(path, o))
        .map(|o| format!("{path} overlaps the volume mounted at {o}."))
}

pub fn add_problem(name: &str, path: &str, declared: &[Volume]) -> Option<String> {
    let names: Vec<String> = declared.iter().map(|v| v.name.clone()).collect();
    let paths: Vec<String> = declared.iter().map(|v| v.mount_path.clone()).collect();
    name_problem(name, &names).or_else(|| path_problem(path, &paths))
}

// Volumes that exist on the node but are not in the declared list: their data is kept until deleted.
pub fn undeclared<'a>(existing: &'a [VolumeInfo], declared: &[Volume]) -> Vec<&'a VolumeInfo> {
    existing
        .iter()
        .filter(|e| !declared.iter().any(|d| d.name == e.name))
        .collect()
}

// The edited list while there is one, otherwise what the node has saved.
pub fn staged_or(staged: &Option<Vec<Volume>>, saved: &[Volume]) -> Vec<Volume> {
    staged.clone().unwrap_or_else(|| saved.to_vec())
}

pub fn size_text(bytes: Option<u64>) -> String {
    bytes.map_or_else(|| "-".to_string(), fmt_bytes)
}

fn created_text(at: Option<&str>, now: i64) -> String {
    at.and_then(parse_rfc3339_ms)
        .map_or_else(|| "-".to_string(), |t| rel_time(now, t))
}

pub struct VolumeState {
    // The declared list being edited, or None while the page shows what the node has.
    pub staged: Option<Vec<Volume>>,
    pub existing: Option<Result<Vec<VolumeInfo>, String>>,
    pub error: Option<String>,
    // The outbound switch as edited; saved together with the volumes through the Save bar.
    pub outbound: Option<bool>,
    pub name_in: Entity<TextInput>,
    pub path_in: Entity<TextInput>,
}

impl VolumeState {
    pub fn new(cx: &mut Context<Console>) -> Self {
        Self {
            staged: None,
            existing: None,
            error: None,
            outbound: None,
            name_in: new_input(cx, "uploads", |i| i.mono()),
            path_in: new_input(cx, "/data", |i| i.mono()),
        }
    }

    pub fn reset(&mut self, cx: &mut Context<Console>) {
        self.staged = None;
        self.existing = None;
        self.error = None;
        self.outbound = None;
        for input in [self.name_in.clone(), self.path_in.clone()] {
            input.update(cx, |i, cx| i.set_text("", cx));
        }
    }

    // The site as the save would send it: the edited volume list replaces the stored one.
    pub fn apply_to(&self, mut site: Site) -> Site {
        if let Some(list) = &self.staged {
            site.volumes = list.clone();
        }
        if let Some(on) = self.outbound {
            site.outbound = on;
        }
        site
    }

    // Both edits are dropped together once saved or discarded.
    pub fn clear_edits(&mut self) {
        self.staged = None;
        self.outbound = None;
        self.error = None;
    }
}

// The switch shows the edit while there is one, otherwise what the node has saved.
pub fn outbound_shown(saved: bool, staged: Option<bool>) -> bool {
    staged.unwrap_or(saved)
}

// The node says its executors have no route out, so the switch cannot have an effect.
pub fn egress_blocked(egress: Option<bool>) -> bool {
    egress == Some(false)
}

impl Console {
    fn vol_handle(&self) -> Option<(NodeHandle, String)> {
        let site = self.detail.data.ready()?.site.id.clone();
        Some((self.handle_named(&self.detail.node)?, site))
    }

    fn volume_add(&mut self, cx: &mut Context<Self>) {
        let Some(saved) = self.detail.data.ready().map(|d| d.site.volumes.clone()) else {
            return;
        };
        let name = self.ops.volumes.name_in.read(cx).text().trim().to_string();
        let path = self.ops.volumes.path_in.read(cx).text().trim().to_string();
        let mut list = staged_or(&self.ops.volumes.staged, &saved);
        if let Some(p) = add_problem(&name, &path, &list) {
            self.ops.volumes.error = Some(p);
            return;
        }
        list.push(Volume {
            name,
            mount_path: path,
        });
        self.ops.volumes.staged = Some(list);
        self.ops.volumes.error = None;
        for input in [
            self.ops.volumes.name_in.clone(),
            self.ops.volumes.path_in.clone(),
        ] {
            input.update(cx, |i, cx| i.set_text("", cx));
        }
    }

    fn volume_remove(&mut self, name: &str, cx: &mut Context<Self>) {
        let Some(saved) = self.detail.data.ready().map(|d| d.site.volumes.clone()) else {
            return;
        };
        let mut list = staged_or(&self.ops.volumes.staged, &saved);
        list.retain(|v| v.name != name);
        self.ops.volumes.staged = Some(list);
        self.ops.volumes.error = None;
        cx.notify();
    }

    fn volume_delete(&mut self, name: String, cx: &mut Context<Self>) {
        let Some((h, site)) = self.vol_handle() else {
            return;
        };
        let shown = name.clone();
        let fut = async move { h.vol_delete(&site, &name).await };
        self.ops_action(cx, "Volume data", fut, move |_| {
            format!("The data of volume {shown} was deleted")
        });
    }

    pub(crate) fn outbound_card(&self, data: &Data, cx: &mut Context<Self>) -> Option<AnyElement> {
        let ex = &self.ops.extras;
        if !self.ops.loaded || !has_cap(&ex.caps, CAP_OUTBOUND) || !volumes_apply(&data.site) {
            return None;
        }
        let blocked = egress_blocked(ex.executor_egress);
        let on = outbound_shown(data.site.outbound, self.ops.volumes.outbound);
        let mut switch = toggle(id("outbound", "switch"), on);
        if !blocked {
            switch = switch.on_click(cx.listener(|this, _, _, cx| {
                let saved = this.detail.data.ready().is_some_and(|d| d.site.outbound);
                let now = outbound_shown(saved, this.ops.volumes.outbound);
                this.ops.volumes.outbound = Some(!now);
                cx.notify();
            }));
        }
        let mut body = div().flex().flex_col().gap(px(10.)).child(
            div()
                .flex()
                .items_center()
                .gap(px(12.))
                .child(switch)
                .child(strong(if on { "Allowed" } else { "Blocked" })),
        );
        body = body.child(
            text_dim("Lets this site's server code make requests to the internet, for example to GitHub or the App Store. Applies on the next deploy.")
                .text_size(px(12.)),
        );
        if blocked {
            body = body.child(notice(
                "This node does not let site containers reach the internet, so this switch has no effect until the node allows it.",
                Tone::Warn,
            ));
        }
        Some(card(Some("Outbound network access"), None, body).into_any_element())
    }

    // The declared volumes with their live state, the add row, and the data kept for volumes no longer declared.
    pub(crate) fn volumes_tab(
        &self,
        data: &Data,
        bar: AnyElement,
        cx: &mut Context<Self>,
    ) -> Vec<AnyElement> {
        let v = &self.ops.volumes;
        let declared = staged_or(&v.staged, &data.site.volumes);
        let existing: &[VolumeInfo] = match &v.existing {
            Some(Ok(list)) => list.as_slice(),
            _ => &[],
        };
        let busy = self.detail.busy || self.ops.busy;
        let now = now_ms();
        let mut rows: Vec<Vec<AnyElement>> = Vec::new();
        for vol in &declared {
            let info = existing.iter().find(|i| i.name == vol.name);
            let saved = data
                .site
                .volumes
                .iter()
                .any(|s| s.name == vol.name && s.mount_path == vol.mount_path);
            let state = match (saved, info) {
                (false, _) => pill("unsaved", Tone::Warn),
                (true, Some(i)) if i.mounted => pill("mounted", Tone::Ok),
                (true, Some(_)) => pill("not mounted", Tone::Muted),
                (true, None) => pill("new", Tone::Info),
            };
            let name = vol.name.clone();
            let remove = if busy {
                btn_off("Remove").into_any_element()
            } else {
                btn(id("vol-remove", &vol.name), "Remove", BtnKind::Plain)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.volume_remove(&name, cx);
                        cx.notify();
                    }))
                    .into_any_element()
            };
            rows.push(vec![
                mono(vol.name.clone()).into_any_element(),
                mono(vol.mount_path.clone()).into_any_element(),
                text_dim(size_text(info.and_then(|i| i.size_bytes))).into_any_element(),
                state.into_any_element(),
                text_dim(created_text(info.and_then(|i| i.created_at.as_deref()), now))
                    .into_any_element(),
                remove,
            ]);
        }
        let cols = [
            Col::fixed("Name", 150.),
            Col::flex("Mount path"),
            Col::fixed("Size", 90.),
            Col::fixed("State", 110.),
            Col::fixed("Created", 110.),
            Col::fixed("", 90.),
        ];
        let mut list = div().flex().flex_col().gap(px(14.));
        if let Some(Err(e)) = &v.existing {
            list = list.child(notice(
                &format!("Volumes could not be read from the node: {e}"),
                Tone::Warn,
            ));
        }
        list = list.child(table(
            &cols,
            rows,
            Some(empty_state(
                "No volumes",
                "Add a folder below to keep its data between deploys.",
            )),
        ));
        let add = if busy {
            btn_off("Add").into_any_element()
        } else {
            btn(id("vol", "add"), "Add", BtnKind::Primary)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.volume_add(cx);
                    cx.notify();
                }))
                .into_any_element()
        };
        list = list.child(
            div()
                .flex()
                .items_end()
                .gap(px(12.))
                .child(div().flex_1().min_w_0().child(field(
                    "Name",
                    Some("Lower case letters, digits and -."),
                    v.name_in.clone(),
                )))
                .child(div().flex_1().min_w_0().child(field(
                    "Mount path",
                    Some("Absolute folder inside the container."),
                    v.path_in.clone(),
                )))
                .child(div().pb(px(18.)).child(add)),
        );
        if let Some(e) = &v.error {
            list = list.child(text_dim(e.clone()).text_size(px(12.)).text_color(
                crate::theme::c(Tone::Bad.color()),
            ));
        }
        list = list.child(
            text_dim("Data in a volume survives redeploys and rollbacks. Both slots mount the same volumes, so the idle slot sees what the live one wrote. Changes apply on the next deploy.")
                .text_size(px(11.)),
        );
        let mut out = vec![
            card(
                Some("Persistent volumes"),
                Some("Folders whose files are kept outside the build"),
                list,
            )
            .into_any_element(),
        ];
        let kept = undeclared(existing, &declared);
        if !kept.is_empty() {
            let mut kept_rows: Vec<Vec<AnyElement>> = Vec::new();
            for info in kept {
                let pending = data.site.volumes.iter().any(|s| s.name == info.name);
                let name = info.name.clone();
                let action = if pending {
                    text_dim("Kept after you save").text_size(px(11.)).into_any_element()
                } else if busy {
                    btn_off("Delete data").into_any_element()
                } else {
                    btn(id("vol-delete", &info.name), "Delete data", BtnKind::Danger)
                        .on_click(cx.listener(move |this, _, _, cx| {
                            let victim = name.clone();
                            this.ask(Confirm {
                                title: "Delete volume data".into(),
                                message: format!(
                                    "Permanently delete everything stored in {victim}? This cannot be undone."
                                ),
                                label: "Delete data".into(),
                                danger: true,
                                action: Box::new(move |this, cx| this.volume_delete(victim, cx)),
                            });
                            cx.notify();
                        }))
                        .into_any_element()
                };
                kept_rows.push(vec![
                    mono(info.name.clone()).into_any_element(),
                    text_dim(size_text(info.size_bytes)).into_any_element(),
                    text_dim(created_text(info.created_at.as_deref(), now)).into_any_element(),
                    action,
                ]);
            }
            let kept_cols = [
                Col::flex("Name"),
                Col::fixed("Size", 90.),
                Col::fixed("Created", 110.),
                Col::fixed("", 140.),
            ];
            out.push(
                card(
                    Some("Data kept without a volume"),
                    Some("Removing a volume from the list keeps its data on the node until you delete it here."),
                    table(&kept_cols, kept_rows, None),
                )
                .into_any_element(),
            );
        }
        out.push(bar);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vol(name: &str, path: &str) -> Volume {
        Volume {
            name: name.into(),
            mount_path: path.into(),
        }
    }

    fn info(name: &str) -> VolumeInfo {
        VolumeInfo {
            name: name.into(),
            mount_path: String::new(),
            size_bytes: None,
            mounted: false,
            created_at: None,
            declared: false,
        }
    }

    #[test]
    fn names_follow_the_nodes_rule() {
        let taken = vec!["data".to_string()];
        let long = "a".repeat(32);
        for ok in ["uploads", "a", "9lives", "my-vol-2", &"a".repeat(31)] {
            assert_eq!(name_problem(ok, &taken), None, "{ok}");
        }
        for bad in ["", "-x", "Upper", "has_underscore", "sp ace", "dot.name", &long] {
            assert!(name_problem(bad, &taken).is_some(), "{bad}");
        }
        assert!(name_problem("data", &taken).unwrap().contains("already exists"));
    }

    #[test]
    fn mount_paths_follow_the_nodes_rule() {
        let none: Vec<String> = Vec::new();
        for ok in ["/data", "/srv/uploads", "/var/lib/app.db", "/a_b-c.d", "/ab"] {
            assert_eq!(path_problem(ok, &none), None, "{ok}");
        }
        let long = format!("/{}", "a".repeat(255));
        let table = [
            ("data", "absolute"),
            ("", "absolute"),
            ("/", "2 to 255"),
            (long.as_str(), "2 to 255"),
            ("/da ta", "letters"),
            ("/data*", "letters"),
            ("/a/../b", ".."),
            ("/data/", "end with /"),
            ("/proc", "reserved"),
            ("/etc/conf", "reserved"),
            ("/tmp/x/y", "reserved"),
            ("/app", "reserved"),
            ("/lib", "reserved"),
        ];
        for (path, word) in table {
            let problem = path_problem(path, &none).unwrap_or_else(|| panic!("{path} passed"));
            assert!(problem.contains(word), "{path}: {problem}");
        }
        assert_eq!(path_problem("/library", &none), None);
        assert_eq!(path_problem("/application", &none), None);
        assert_eq!(path_problem("/tmpfiles", &none), None);
    }

    #[test]
    fn overlapping_mounts_are_found_on_folder_boundaries() {
        assert!(overlaps("/data", "/data"));
        assert!(overlaps("/data", "/data/uploads"));
        assert!(overlaps("/data/uploads", "/data"));
        assert!(!overlaps("/data", "/data2"));
        assert!(!overlaps("/data/a", "/data/b"));
        let used = vec!["/data".to_string(), "/srv/cache".to_string()];
        assert!(path_problem("/data/more", &used).unwrap().contains("overlaps"));
        assert!(path_problem("/srv", &used).unwrap().contains("/srv/cache"));
        assert_eq!(path_problem("/database", &used), None);
    }

    #[test]
    fn adding_checks_the_name_before_the_path() {
        let declared = vec![vol("data", "/data")];
        assert!(add_problem("data", "/other", &declared).unwrap().contains("already exists"));
        assert!(add_problem("cache", "/data/c", &declared).unwrap().contains("overlaps"));
        assert!(add_problem("Bad", "/data/c", &declared).unwrap().contains("volume name"));
        assert_eq!(add_problem("cache", "/cache", &declared), None);
        assert_eq!(add_problem("first", "/first", &[]), None);
    }

    #[test]
    fn undeclared_volumes_are_those_the_node_has_beyond_the_list() {
        let existing = vec![info("data"), info("old-cache"), info("logs")];
        let declared = vec![vol("data", "/data")];
        let kept: Vec<&str> = undeclared(&existing, &declared)
            .iter()
            .map(|v| v.name.as_str())
            .collect();
        assert_eq!(kept, vec!["old-cache", "logs"]);
        assert!(undeclared(&existing, &[vol("data", "/d"), vol("old-cache", "/o"), vol("logs", "/l")]).is_empty());
        assert_eq!(undeclared(&existing, &[]).len(), 3);
        assert!(undeclared(&[], &declared).is_empty());
    }

    #[test]
    fn the_edited_list_replaces_the_saved_one_only_while_it_exists() {
        let saved = vec![vol("data", "/data")];
        assert_eq!(staged_or(&None, &saved).len(), 1);
        assert!(staged_or(&Some(Vec::new()), &saved).is_empty());
        let edited = staged_or(&Some(vec![vol("a", "/a"), vol("b", "/b")]), &saved);
        assert_eq!(edited.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(), vec!["a", "b"]);
    }

    #[test]
    fn only_server_rendered_sources_get_volumes() {
        let source = |rendering, runtime: Option<&str>| Source {
            repo: "acme/x".into(),
            rendering,
            runtime: runtime.map(str::to_string),
            ..Default::default()
        };
        assert!(source_serves(Some(&source(Some(RenderMode::Ssr), Some("node")))));
        assert!(source_serves(Some(&source(None, Some("node")))));
        assert!(!source_serves(Some(&source(Some(RenderMode::Static), Some("node")))));
        assert!(!source_serves(Some(&source(None, Some("static")))));
        assert!(!source_serves(None));
    }

    #[test]
    fn the_outbound_switch_follows_the_edit_and_the_nodes_egress() {
        assert!(outbound_shown(true, None));
        assert!(!outbound_shown(true, Some(false)));
        assert!(outbound_shown(false, Some(true)));
        assert!(egress_blocked(Some(false)));
        assert!(!egress_blocked(Some(true)) && !egress_blocked(None));
    }

    #[test]
    fn sizes_and_ages_have_a_fallback() {
        assert_eq!(size_text(None), "-");
        assert_eq!(size_text(Some(2048)), "2.0 KB");
        assert_eq!(created_text(None, 0), "-");
        assert_eq!(created_text(Some("not a date"), 0), "-");
        assert_eq!(created_text(Some("2026-01-02T03:04:05Z"), 0), "just now");
    }
}
