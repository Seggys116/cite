use cite_client::VolumeInfo;
use cite_edge::model::{RenderMode, Site, Source, Volume};
use cite_edge::validate::{MAX_VOLUMES, is_valid_volume_name, mount_path_problem};
use gpui::{AnyElement, Context, Entity, div, prelude::*, px};

use crate::api::{NodeHandle, Res};
use crate::app::{Confirm, Console, new_input};
use crate::demo::now_ms;
use crate::model::{fmt_bytes, parse_rfc3339_ms, rel_time};
use crate::theme::Tone;
use crate::ui::detail::Data;
use crate::ui::detail::outbound::OutboundState;
use crate::ui::input::TextInput;
use crate::ui::widgets::{
    BtnKind, Col, btn, btn_off, card, empty_state, field, id, mono, notice, pill, table, text_dim,
    tip,
};

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

// The node's own rule: [a-z0-9][a-z0-9-]{0,30}, and unique within the site.
pub fn name_problem(name: &str, taken: &[String]) -> Option<String> {
    if name.is_empty() {
        return Some("Type a volume name.".into());
    }
    if !is_valid_volume_name(name) {
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
    if let Some(why) = mount_path_problem(path) {
        return Some(format!("The mount path {why}."));
    }
    others
        .iter()
        .find(|o| overlaps(path, o))
        .map(|o| format!("{path} overlaps the volume mounted at {o}."))
}

pub fn add_problem(name: &str, path: &str, declared: &[Volume]) -> Option<String> {
    if declared.len() >= MAX_VOLUMES {
        return Some(format!("A site can have at most {MAX_VOLUMES} volumes."));
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeKind {
    // In the list the page edits; `saved` is false until the node has the entry.
    Declared { saved: bool },
    // The node keeps data for it but the list does not name it; `removal_pending` while the saved list still does.
    Kept { removal_pending: bool },
}

// One line of the volume list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeRow {
    pub name: String,
    pub mount_path: String,
    pub size_bytes: Option<u64>,
    pub created_at: Option<String>,
    pub kind: VolumeKind,
    // None while the node has no data for it yet.
    pub mounted: Option<bool>,
}

// Declared volumes in the order of the list, then the data the node keeps for volumes the list no longer names.
pub fn volume_rows(
    declared: &[Volume],
    saved: &[Volume],
    existing: &[VolumeInfo],
) -> Vec<VolumeRow> {
    let mut rows: Vec<VolumeRow> = declared
        .iter()
        .map(|v| {
            let info = existing.iter().find(|i| i.name == v.name);
            VolumeRow {
                name: v.name.clone(),
                mount_path: v.mount_path.clone(),
                size_bytes: info.and_then(|i| i.size_bytes),
                created_at: info.and_then(|i| i.created_at.clone()),
                kind: VolumeKind::Declared {
                    saved: saved.contains(v),
                },
                mounted: info.map(|i| i.mounted),
            }
        })
        .collect();
    rows.extend(
        undeclared(existing, declared)
            .into_iter()
            .map(|i| VolumeRow {
                name: i.name.clone(),
                mount_path: i.mount_path.clone(),
                size_bytes: i.size_bytes,
                created_at: i.created_at.clone(),
                kind: VolumeKind::Kept {
                    removal_pending: saved.iter().any(|s| s.name == i.name),
                },
                mounted: Some(i.mounted),
            }),
    );
    rows
}

// The pills of a row: whether the site lists the volume, and whether a container has it mounted.
pub fn volume_pills(row: &VolumeRow) -> Vec<(&'static str, Tone)> {
    let mount = match row.mounted {
        Some(true) => ("mounted", Tone::Ok),
        Some(false) => ("not mounted", Tone::Muted),
        None => ("no data yet", Tone::Muted),
    };
    match row.kind {
        VolumeKind::Declared { saved: false } => vec![("unsaved", Tone::Warn)],
        VolumeKind::Declared { saved: true } => vec![("declared", Tone::Info), mount],
        VolumeKind::Kept { .. } => vec![("not declared", Tone::Warn), mount],
    }
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
    // The outbound policy as edited; saved together with the volumes through the Save bar.
    pub outbound: OutboundState,
    pub name_in: Entity<TextInput>,
    pub path_in: Entity<TextInput>,
}

impl VolumeState {
    pub fn new(cx: &mut Context<Console>) -> Self {
        Self {
            staged: None,
            existing: None,
            error: None,
            outbound: OutboundState::new(cx),
            name_in: new_input(cx, "uploads", |i| i.mono()),
            path_in: new_input(cx, "/data", |i| i.mono()),
        }
    }

    pub fn reset(&mut self, cx: &mut Context<Console>) {
        self.staged = None;
        self.existing = None;
        self.error = None;
        self.outbound.reset(cx);
        for input in [self.name_in.clone(), self.path_in.clone()] {
            input.update(cx, |i, cx| i.set_text("", cx));
        }
    }

    // The site as the save would send it: the edited volume list replaces the stored one.
    pub fn apply_to(&self, mut site: Site) -> Site {
        if let Some(list) = &self.staged {
            site.volumes = list.clone();
        }
        self.outbound.apply_to(&mut site);
        site
    }

    // The volume and outbound edits are dropped together once saved or discarded.
    pub fn clear_edits(&mut self) {
        self.staged = None;
        self.outbound.clear();
        self.error = None;
    }
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
        let node = self.detail.node.clone();
        let fut = async move { h.vol_delete(&site, &name).await };
        self.ops_action(cx, "Volume data", fut, move |_| {
            format!("The data of volume {shown} was deleted on {node}")
        });
    }

    // One list of every volume: the declared ones with their live state, then the data kept for volumes no longer declared, and the add row.
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
        let node = self.detail.node.clone();
        let mut rows: Vec<Vec<AnyElement>> = Vec::new();
        for row in volume_rows(&declared, &data.site.volumes, existing) {
            let kept = matches!(row.kind, VolumeKind::Kept { .. });
            let mut pills = div().flex().flex_wrap().gap(px(4.));
            for (i, (text, tone)) in volume_pills(&row).into_iter().enumerate() {
                let badge = pill(text, tone);
                pills = pills.child(if kept && i == 0 {
                    tip(
                        badge,
                        id("vol-kept-tip", &row.name),
                        "The site no longer lists it. Its data stays on the node until you delete it.",
                    )
                    .into_any_element()
                } else {
                    badge.into_any_element()
                });
            }
            let name = row.name.clone();
            let action = match row.kind {
                _ if busy => btn_off(if kept { "Delete" } else { "Remove" }).into_any_element(),
                VolumeKind::Declared { .. } => {
                    btn(id("vol-remove", &row.name), "Remove", BtnKind::Plain)
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.volume_remove(&name, cx);
                            cx.notify();
                        }))
                        .into_any_element()
                }
                VolumeKind::Kept {
                    removal_pending: true,
                } => text_dim("Kept after you save")
                    .text_size(px(11.))
                    .into_any_element(),
                VolumeKind::Kept {
                    removal_pending: false,
                } => {
                    let node = node.clone();
                    btn(id("vol-delete", &row.name), "Delete", BtnKind::Danger)
                        .on_click(cx.listener(move |this, _, _, cx| {
                            let victim = name.clone();
                            this.ask(Confirm {
                                title: format!("Delete volume data on {node}"),
                                message: format!(
                                    "Permanently delete everything stored in {victim} on {node}? This cannot be undone."
                                ),
                                label: "Delete data".into(),
                                danger: true,
                                action: Box::new(move |this, cx| this.volume_delete(victim, cx)),
                            });
                            cx.notify();
                        }))
                        .into_any_element()
                }
            };
            let path = if row.mount_path.is_empty() {
                "-".to_string()
            } else {
                row.mount_path.clone()
            };
            rows.push(vec![
                mono(row.name.clone()).into_any_element(),
                mono(path).into_any_element(),
                text_dim(size_text(row.size_bytes)).into_any_element(),
                pills.into_any_element(),
                text_dim(created_text(row.created_at.as_deref(), now)).into_any_element(),
                action,
            ]);
        }
        let cols = [
            Col::fixed("Name", 140.),
            Col::flex("Mount path"),
            Col::fixed("Size", 80.),
            Col::fixed("State", 190.),
            Col::fixed("Created", 100.),
            Col::fixed("", 110.),
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
                .child(div().flex().flex_col().flex_1().min_w_0().child(field(
                    "Name",
                    Some("Lower case letters, digits and -."),
                    v.name_in.clone(),
                )))
                .child(div().flex().flex_col().flex_1().min_w_0().child(field(
                    "Mount path",
                    Some("Absolute folder inside the container."),
                    v.path_in.clone(),
                )))
                .child(div().flex().flex_col().pb(px(18.)).child(add)),
        );
        if let Some(e) = &v.error {
            list = list.child(
                text_dim(e.clone())
                    .text_size(px(12.))
                    .text_color(crate::theme::c(Tone::Bad.color())),
            );
        }
        vec![
            card(
                Some("Persistent volumes"),
                Some("Data in a volume survives redeploys and rollbacks."),
                list,
            )
            .into_any_element(),
            bar,
        ]
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
        for bad in [
            "",
            "-x",
            "Upper",
            "has_underscore",
            "sp ace",
            "dot.name",
            &long,
        ] {
            assert!(name_problem(bad, &taken).is_some(), "{bad}");
        }
        assert!(
            name_problem("data", &taken)
                .unwrap()
                .contains("already exists")
        );
    }

    #[test]
    fn mount_paths_follow_the_nodes_rule() {
        let none: Vec<String> = Vec::new();
        let oks = [
            "/data",
            "/srv/uploads",
            "/var/lib/app.db",
            "/a_b-c.d",
            "/ab",
            "/app",
            "/app/uploads",
            "/a..b",
            "/data/..x",
        ];
        for ok in oks {
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
            ("/a/../b", "'..'"),
            ("/a/..", "'..'"),
            ("/a//b", "empty"),
            ("/a/./b", "'.'"),
            ("/data/", "trailing slash"),
            ("/proc", "system uses"),
            ("/etc/conf", "system uses"),
            ("/tmp/x/y", "system uses"),
            ("/lib", "system uses"),
            ("/lib64", "system uses"),
            ("/libx32/x", "system uses"),
            ("/boot", "system uses"),
            ("/nodejs/bin", "system uses"),
            ("/cite-executor", "system uses"),
            ("/var/lib/cite/x", "system uses"),
            ("/var/run/app", "system uses"),
            ("/var", "system uses"),
            ("/var/lib", "system uses"),
        ];
        for (path, word) in table {
            let problem = path_problem(path, &none).unwrap_or_else(|| panic!("{path} passed"));
            assert!(problem.contains(word), "{path}: {problem}");
        }
        assert_eq!(path_problem("/library", &none), None);
        assert_eq!(path_problem("/application", &none), None);
        assert_eq!(path_problem("/tmpfiles", &none), None);
        assert_eq!(path_problem("/variable", &none), None);
    }

    #[test]
    fn the_desktop_and_the_node_agree_on_mount_paths() {
        let none: Vec<String> = Vec::new();
        let paths = [
            "/data", "/app", "/a..b", "/var", "/a//b", "/x/./y", "/x/../y", "/",
        ];
        for path in paths {
            assert_eq!(
                path_problem(path, &none).is_none(),
                mount_path_problem(path).is_none(),
                "{path}"
            );
        }
    }

    #[test]
    fn a_site_takes_at_most_the_nodes_volume_count() {
        let full: Vec<Volume> = (0..MAX_VOLUMES)
            .map(|i| vol(&format!("v{i}"), &format!("/v{i}")))
            .collect();
        assert!(
            add_problem("more", "/more", &full)
                .unwrap()
                .contains("at most")
        );
        assert_eq!(add_problem("more", "/more", &full[..MAX_VOLUMES - 1]), None);
    }

    #[test]
    fn overlapping_mounts_are_found_on_folder_boundaries() {
        assert!(overlaps("/data", "/data"));
        assert!(overlaps("/data", "/data/uploads"));
        assert!(overlaps("/data/uploads", "/data"));
        assert!(!overlaps("/data", "/data2"));
        assert!(!overlaps("/data/a", "/data/b"));
        let used = vec!["/data".to_string(), "/srv/cache".to_string()];
        assert!(
            path_problem("/data/more", &used)
                .unwrap()
                .contains("overlaps")
        );
        assert!(path_problem("/srv", &used).unwrap().contains("/srv/cache"));
        assert_eq!(path_problem("/database", &used), None);
    }

    #[test]
    fn adding_checks_the_name_before_the_path() {
        let declared = vec![vol("data", "/data")];
        assert!(
            add_problem("data", "/other", &declared)
                .unwrap()
                .contains("already exists")
        );
        assert!(
            add_problem("cache", "/data/c", &declared)
                .unwrap()
                .contains("overlaps")
        );
        assert!(
            add_problem("Bad", "/data/c", &declared)
                .unwrap()
                .contains("volume name")
        );
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
        assert!(
            undeclared(
                &existing,
                &[vol("data", "/d"), vol("old-cache", "/o"), vol("logs", "/l")]
            )
            .is_empty()
        );
        assert_eq!(undeclared(&existing, &[]).len(), 3);
        assert!(undeclared(&[], &declared).is_empty());
    }

    #[test]
    fn the_edited_list_replaces_the_saved_one_only_while_it_exists() {
        let saved = vec![vol("data", "/data")];
        assert_eq!(staged_or(&None, &saved).len(), 1);
        assert!(staged_or(&Some(Vec::new()), &saved).is_empty());
        let edited = staged_or(&Some(vec![vol("a", "/a"), vol("b", "/b")]), &saved);
        assert_eq!(
            edited.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(),
            vec!["a", "b"]
        );
    }

    #[test]
    fn only_server_rendered_sources_get_volumes() {
        let source = |rendering, runtime: Option<&str>| Source {
            repo: "acme/x".into(),
            rendering,
            runtime: runtime.map(str::to_string),
            ..Default::default()
        };
        assert!(source_serves(Some(&source(
            Some(RenderMode::Ssr),
            Some("node")
        ))));
        assert!(source_serves(Some(&source(None, Some("node")))));
        assert!(!source_serves(Some(&source(
            Some(RenderMode::Static),
            Some("node")
        ))));
        assert!(!source_serves(Some(&source(None, Some("static")))));
        assert!(!source_serves(None));
    }

    fn stored(name: &str, path: &str, size: Option<u64>, mounted: bool) -> VolumeInfo {
        VolumeInfo {
            name: name.into(),
            mount_path: path.into(),
            size_bytes: size,
            mounted,
            created_at: None,
            declared: true,
        }
    }

    #[test]
    fn the_list_has_one_row_per_volume_declared_ones_first() {
        let saved = vec![vol("data", "/data"), vol("cache", "/cache")];
        // "cache" was dropped from the edited list; "old" is data the node keeps from an earlier list.
        let declared = vec![vol("data", "/data"), vol("uploads", "/uploads")];
        let existing = vec![
            stored("old", "", Some(10), false),
            stored("data", "/data", Some(2048), true),
            stored("cache", "/cache", Some(5), true),
        ];
        let rows = volume_rows(&declared, &saved, &existing);
        let names: Vec<&str> = rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["data", "uploads", "old", "cache"]);
        assert_eq!(rows[0].kind, VolumeKind::Declared { saved: true });
        assert_eq!(rows[0].size_bytes, Some(2048));
        assert_eq!(rows[0].mounted, Some(true));
        // Not saved yet, so the node knows nothing about it.
        assert_eq!(rows[1].kind, VolumeKind::Declared { saved: false });
        assert_eq!(rows[1].mounted, None);
        assert_eq!(
            rows[2].kind,
            VolumeKind::Kept {
                removal_pending: false
            }
        );
        // Dropped from the edited list but still in the saved one: the data is kept after the save.
        assert_eq!(
            rows[3].kind,
            VolumeKind::Kept {
                removal_pending: true
            }
        );
        assert_eq!(rows[3].mount_path, "/cache");
    }

    #[test]
    fn a_changed_mount_path_counts_as_unsaved() {
        let saved = vec![vol("data", "/data")];
        let rows = volume_rows(&[vol("data", "/srv/data")], &saved, &[]);
        assert_eq!(rows[0].kind, VolumeKind::Declared { saved: false });
    }

    #[test]
    fn pills_say_whether_the_site_lists_the_volume_and_whether_it_is_mounted() {
        let row = |kind, mounted| VolumeRow {
            name: "data".into(),
            mount_path: "/data".into(),
            size_bytes: None,
            created_at: None,
            kind,
            mounted,
        };
        let declared = VolumeKind::Declared { saved: true };
        assert_eq!(
            volume_pills(&row(declared, Some(true))),
            vec![("declared", Tone::Info), ("mounted", Tone::Ok)]
        );
        assert_eq!(
            volume_pills(&row(declared, Some(false))),
            vec![("declared", Tone::Info), ("not mounted", Tone::Muted)]
        );
        assert_eq!(
            volume_pills(&row(declared, None)),
            vec![("declared", Tone::Info), ("no data yet", Tone::Muted)]
        );
        assert_eq!(
            volume_pills(&row(VolumeKind::Declared { saved: false }, None)),
            vec![("unsaved", Tone::Warn)]
        );
        assert_eq!(
            volume_pills(&row(
                VolumeKind::Kept {
                    removal_pending: false
                },
                Some(false)
            )),
            vec![("not declared", Tone::Warn), ("not mounted", Tone::Muted)]
        );
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
