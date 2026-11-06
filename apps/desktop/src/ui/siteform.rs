use gpui::{AnyElement, Context, Div, Entity, div, prelude::*, px};

use crate::app::{Console, new_input};
use crate::certs::AccessDraft;
use crate::model::{
    BUILD_DETECTION_NOTE, BuildDraft, DEFAULT_BRANCH, DEFAULT_POLL, DEFAULT_RUNTIME, NODE_HELP,
    NODE_MAJORS, POLL_HELP, RUNTIMES, SiteDraft, SourceKind, runtime_help, takes_node_major,
};
use crate::repo::parse_repo;
use crate::siteops::{auto_placeholder, detected_value};
use crate::theme::{Tone, c};
use crate::ui::input::TextInput;
use crate::ui::paths::{PathRow, clear_rows, path_editor, read_paths, rows_from};
use crate::ui::widgets::{BtnKind, btn, field, id, mono, notice, seg_item, seg_row, text_dim};
use crate::wizard::FieldProblems;
use cite_edge::status::SiteStatus;

// Every input of the site form. The create wizard and the site page each own one and render the same sections from it, so the two cannot drift.
pub struct SiteFields {
    pub api: bool,
    pub source: SourceKind,
    pub runtime: String,
    pub node_major: u8,
    pub access: AccessDraft,
    pub paths: Vec<PathRow>,
    pub name: Entity<TextInput>,
    pub id: Entity<TextInput>,
    pub hosts: Entity<TextInput>,
    pub sample: Entity<TextInput>,
    pub blue: Entity<TextInput>,
    pub green: Entity<TextInput>,
    pub health: Entity<TextInput>,
    pub health_interval: Entity<TextInput>,
    pub health_timeout: Entity<TextInput>,
    pub health_rise: Entity<TextInput>,
    pub health_fall: Entity<TextInput>,
    pub repo: Entity<TextInput>,
    pub branch: Entity<TextInput>,
    pub poll: Entity<TextInput>,
    pub gh_token: Entity<TextInput>,
    pub build: BuildInputs,
}

// The build and resource settings of a source-built site: three choices and eleven text fields, all blank for "let the node decide".
pub struct BuildInputs {
    pub package_manager: String,
    pub rendering: String,
    pub prune: String,
    pub root_dir: Entity<TextInput>,
    pub install_command: Entity<TextInput>,
    pub build_command: Entity<TextInput>,
    pub output_dir: Entity<TextInput>,
    pub framework: Entity<TextInput>,
    pub start_command: Entity<TextInput>,
    pub spa_fallback: Entity<TextInput>,
    pub memory_mb: Entity<TextInput>,
    pub cpus: Entity<TextInput>,
    pub build_memory_mb: Entity<TextInput>,
    pub build_cpus: Entity<TextInput>,
}

impl BuildInputs {
    pub fn new(cx: &mut Context<Console>) -> Self {
        let auto = |cx: &mut Context<Console>| new_input(cx, "Auto", |i| i.mono());
        Self {
            package_manager: String::new(),
            rendering: String::new(),
            prune: String::new(),
            root_dir: auto(cx),
            install_command: auto(cx),
            build_command: auto(cx),
            output_dir: auto(cx),
            framework: auto(cx),
            start_command: auto(cx),
            spa_fallback: auto(cx),
            memory_mb: new_input(cx, "Node default", |i| i.mono()),
            cpus: new_input(cx, "Node default", |i| i.mono()),
            build_memory_mb: new_input(cx, "Node default", |i| i.mono()),
            build_cpus: new_input(cx, "Node default", |i| i.mono()),
        }
    }

    fn texts(&self) -> [&Entity<TextInput>; 11] {
        [
            &self.root_dir,
            &self.install_command,
            &self.build_command,
            &self.output_dir,
            &self.framework,
            &self.start_command,
            &self.spa_fallback,
            &self.memory_mb,
            &self.cpus,
            &self.build_memory_mb,
            &self.build_cpus,
        ]
    }

    pub fn draft(&self, cx: &Context<Console>) -> BuildDraft {
        let t = |e: &Entity<TextInput>| e.read(cx).text().to_string();
        BuildDraft {
            root_dir: t(&self.root_dir),
            install_command: t(&self.install_command),
            build_command: t(&self.build_command),
            output_dir: t(&self.output_dir),
            framework: t(&self.framework),
            start_command: t(&self.start_command),
            spa_fallback: t(&self.spa_fallback),
            package_manager: self.package_manager.clone(),
            rendering: self.rendering.clone(),
            prune: self.prune.clone(),
            memory_mb: t(&self.memory_mb),
            cpus: t(&self.cpus),
            build_memory_mb: t(&self.build_memory_mb),
            build_cpus: t(&self.build_cpus),
        }
    }

    pub fn load(&mut self, d: &BuildDraft, cx: &mut Context<Console>) {
        let values = [
            &d.root_dir,
            &d.install_command,
            &d.build_command,
            &d.output_dir,
            &d.framework,
            &d.start_command,
            &d.spa_fallback,
            &d.memory_mb,
            &d.cpus,
            &d.build_memory_mb,
            &d.build_cpus,
        ];
        for (input, text) in self.texts().into_iter().zip(values) {
            input.update(cx, |i, cx| i.set_text(text, cx));
        }
        self.package_manager = d.package_manager.clone();
        self.rendering = d.rendering.clone();
        self.prune = d.prune.clone();
    }

    // The hints of the text fields that have a detected value: "Auto (detected: X)" instead of plain "Auto".
    pub fn show_detected(&self, status: Option<&SiteStatus>, cx: &mut Context<Console>) {
        let keyed = [
            (&self.root_dir, "root_dir"),
            (&self.install_command, "install_command"),
            (&self.build_command, "build_command"),
            (&self.output_dir, "output_dir"),
            (&self.framework, "framework"),
            (&self.start_command, "start_command"),
            (&self.spa_fallback, "spa_fallback"),
        ];
        for (input, key) in keyed {
            let hint = auto_placeholder(status.and_then(|s| detected_value(s, key)).as_deref());
            input.update(cx, |i, cx| i.set_placeholder(&hint, cx));
        }
    }
}

// How a page reaches its own form; the key keeps element ids of the two pages apart.
#[derive(Clone, Copy)]
pub struct Home {
    pub key: &'static str,
    pub fields: fn(&mut Console) -> &mut SiteFields,
    pub paths: fn(&mut Console) -> &mut Vec<PathRow>,
}

// What a brand-new site starts from: built from GitHub on Node, with the node's defaults.
pub fn blank_draft() -> SiteDraft {
    SiteDraft {
        source: SourceKind::Github,
        health_path: "/".into(),
        branch: DEFAULT_BRANCH.into(),
        runtime: DEFAULT_RUNTIME.into(),
        node_major: NODE_MAJORS[0],
        poll_interval: DEFAULT_POLL.into(),
        ..SiteDraft::default()
    }
}

impl SiteFields {
    pub fn new(cx: &mut Context<Console>) -> Self {
        Self {
            api: false,
            source: SourceKind::Github,
            runtime: DEFAULT_RUNTIME.into(),
            node_major: NODE_MAJORS[0],
            access: AccessDraft::default(),
            paths: Vec::new(),
            name: new_input(cx, "Storefront", |i| i),
            id: new_input(cx, "storefront", |i| i.mono()),
            hosts: new_input(cx, "shop.example.com, www.example.com", |i| i.mono()),
            sample: new_input(cx, "/api/v1/users", |i| i.mono()),
            blue: new_input(cx, "10.0.0.11:8080, 10.0.0.12:8080", |i| i.mono()),
            green: new_input(cx, "10.0.0.21:8080 (optional)", |i| i.mono()),
            health: new_input(cx, "/", |i| i.mono()),
            health_interval: new_input(cx, "2000", |i| i.mono()),
            health_timeout: new_input(cx, "1500", |i| i.mono()),
            health_rise: new_input(cx, "2", |i| i.mono()),
            health_fall: new_input(cx, "3", |i| i.mono()),
            repo: new_input(cx, "acme/shop or https://github.com/acme/shop", |i| {
                i.mono()
            }),
            branch: new_input(cx, DEFAULT_BRANCH, |i| i.mono()),
            poll: new_input(cx, DEFAULT_POLL, |i| i.mono()),
            gh_token: new_input(cx, "GitHub token for this site", |i| i.masked().mono()),
            build: BuildInputs::new(cx),
        }
    }

    fn texts(&self) -> [&Entity<TextInput>; 14] {
        [
            &self.name,
            &self.id,
            &self.hosts,
            &self.sample,
            &self.blue,
            &self.green,
            &self.health,
            &self.health_interval,
            &self.health_timeout,
            &self.health_rise,
            &self.health_fall,
            &self.repo,
            &self.branch,
            &self.poll,
        ]
    }

    // Reads the form as a draft. The GitHub token is never part of it: only the create page has one, and it adds it itself.
    pub fn draft(&self, cx: &Context<Console>) -> SiteDraft {
        let t = |e: &Entity<TextInput>| e.read(cx).text().to_string();
        let (prefixes, regexes) = read_paths(&self.paths, cx);
        SiteDraft {
            api: self.api,
            source: self.source,
            name: t(&self.name),
            id: t(&self.id),
            hosts: t(&self.hosts),
            path_prefixes: prefixes,
            path_regexes: regexes,
            blue: t(&self.blue),
            green: t(&self.green),
            health_path: t(&self.health),
            health_interval: t(&self.health_interval),
            health_timeout: t(&self.health_timeout),
            health_rise: t(&self.health_rise),
            health_fall: t(&self.health_fall),
            repo: t(&self.repo),
            branch: t(&self.branch),
            runtime: self.runtime.clone(),
            node_major: self.node_major,
            poll_interval: t(&self.poll),
            build: self.build.draft(cx),
            github_token: String::new(),
            access: self.access,
        }
    }

    // Fills every input from a draft; the token input and the path tester always start empty.
    pub fn load(&mut self, d: &SiteDraft, cx: &mut Context<Console>) {
        let empty = String::new();
        let values = [
            &d.name,
            &d.id,
            &d.hosts,
            &empty,
            &d.blue,
            &d.green,
            &d.health_path,
            &d.health_interval,
            &d.health_timeout,
            &d.health_rise,
            &d.health_fall,
            &d.repo,
            &d.branch,
            &d.poll_interval,
        ];
        for (input, text) in self.texts().into_iter().zip(values) {
            input.update(cx, |i, cx| i.set_text(text, cx));
        }
        self.gh_token.update(cx, |i, cx| i.set_text("", cx));
        self.build.load(&d.build, cx);
        self.api = d.api;
        self.source = d.source;
        self.runtime = d.runtime.clone();
        self.node_major = d.node_major;
        self.access = d.access;
        clear_rows(&mut self.paths, cx);
        self.paths = rows_from(cx, &d.path_prefixes, &d.path_regexes);
    }
}

fn problem_text(message: &str) -> Div {
    text_dim(message.to_string())
        .text_size(px(12.))
        .text_color(c(Tone::Bad.color()))
}

// A field with its problem under it; an untouched empty field stays quiet unless the page asks for everything.
fn with_problem(
    label: &str,
    hint: Option<&str>,
    input: &Entity<TextInput>,
    problem: Option<&String>,
    loud: bool,
    cx: &Context<Console>,
) -> Div {
    let shown = problem.filter(|_| loud || !input.read(cx).text().trim().is_empty());
    div()
        .flex()
        .flex_col()
        .gap(px(4.))
        .child(field(label, hint, input.clone()))
        .children(shown.map(|p| problem_text(p)))
}

// Kind, name and id. The id is fixed once the site exists.
pub fn basics(
    f: &SiteFields,
    home: Home,
    problems: &FieldProblems,
    editing: bool,
    cx: &mut Context<Console>,
) -> Div {
    let get = home.fields;
    let kind = seg_row(vec![
        seg_item(id(home.key, "kind-site"), "Site", !f.api)
            .on_click(cx.listener(move |this, _, _, cx| {
                get(this).api = false;
                cx.notify();
            }))
            .into_any_element(),
        seg_item(id(home.key, "kind-api"), "API", f.api)
            .on_click(cx.listener(move |this, _, _, cx| {
                get(this).api = true;
                cx.notify();
            }))
            .into_any_element(),
    ]);
    let id_field: AnyElement = if editing {
        field(
            "Id",
            Some("The id is used in URLs and cannot change."),
            mono(f.id.read(cx).text().to_string()),
        )
        .into_any_element()
    } else {
        with_problem(
            "Id",
            Some("Lowercase letters, digits and dashes, up to 40. Cannot change later."),
            &f.id,
            problems.id.as_ref(),
            false,
            cx,
        )
        .into_any_element()
    };
    div()
        .flex()
        .flex_col()
        .gap(px(12.))
        .child(field(
            "Kind",
            Some("APIs usually route by path prefix; sites by host name."),
            div().flex().child(kind),
        ))
        .child(
            div()
                .flex()
                .gap(px(12.))
                .child(div().flex_1().child(with_problem(
                    "Name",
                    None,
                    &f.name,
                    problems.name.as_ref(),
                    editing,
                    cx,
                )))
                .child(div().flex_1().child(id_field)),
        )
}

// Hosts and the optional routing paths.
pub fn domains(
    f: &SiteFields,
    home: Home,
    problems: &FieldProblems,
    editing: bool,
    cx: &mut Context<Console>,
) -> Div {
    let paths = path_editor(&f.paths, home.key, Some(&f.sample), home.paths, cx);
    div()
        .flex()
        .flex_col()
        .gap(px(12.))
        .child(with_problem(
            "Hosts",
            Some("Requests with these Host headers go to this site. Separate with commas."),
            &f.hosts,
            problems.hosts.as_ref(),
            editing,
            cx,
        ))
        .child(field("Routing paths", None, paths))
}

// Repository, branch, runtime, Node version and poll interval: everything the node's source accepts.
pub fn source_fields(
    f: &SiteFields,
    home: Home,
    problems: &FieldProblems,
    cx: &mut Context<Console>,
) -> Div {
    let get = home.fields;
    let repo_text = f.repo.read(cx).text().to_string();
    let mut repo = div().flex().flex_col().gap(px(6.)).child(field(
        "Repository",
        Some("owner/name, or paste the repository's address (https, ssh, with or without .git)."),
        f.repo.clone(),
    ));
    if !repo_text.trim().is_empty() {
        match parse_repo(&repo_text) {
            Err(e) => repo = repo.child(problem_text(&e)),
            Ok(found) => {
                repo =
                    repo.child(text_dim(format!("Repository: {}", found.name)).text_size(px(12.)));
                if let Some(hint) = found.host_hint() {
                    repo = repo.child(notice(hint, Tone::Warn));
                }
                let current = f.branch.read(cx).text().trim().to_string();
                if let Some(branch) = found.branch.filter(|b| *b != current) {
                    let label = format!("Use branch {branch}");
                    repo = repo.child(div().flex().child(
                        btn(id(home.key, "use-branch"), &label, BtnKind::Plain).on_click(
                            cx.listener(move |this, _, _, cx| {
                                get(this).branch.update(cx, |i, cx| i.set_text(&branch, cx));
                                cx.notify();
                            }),
                        ),
                    ));
                }
            }
        }
    }
    let rkey = format!("{}-runtime", home.key);
    let mut runtimes = div().flex().flex_col().gap(px(6.));
    for r in RUNTIMES {
        let name = r.to_string();
        runtimes = runtimes.child(
            div()
                .flex()
                .items_center()
                .gap(px(10.))
                .child(
                    seg_item(id(&rkey, r), r, f.runtime == r).on_click(cx.listener(
                        move |this, _, _, cx| {
                            get(this).runtime = name.clone();
                            cx.notify();
                        },
                    )),
                )
                .child(text_dim(runtime_help(r)).text_size(px(12.))),
        );
    }
    let mut body = div()
        .flex()
        .flex_col()
        .gap(px(12.))
        .child(repo)
        .child(with_problem(
            "Branch",
            Some("The branch the node builds and watches."),
            &f.branch,
            problems.branch.as_ref(),
            false,
            cx,
        ))
        .child(field("Runtime", None, runtimes));
    if takes_node_major(&f.runtime) {
        let mkey = format!("{}-major", home.key);
        let majors = seg_row(
            NODE_MAJORS
                .iter()
                .map(|m| {
                    let major = *m;
                    seg_item(id(&mkey, m), &format!("Node {m}"), f.node_major == major)
                        .on_click(cx.listener(move |this, _, _, cx| {
                            get(this).node_major = major;
                            cx.notify();
                        }))
                        .into_any_element()
                })
                .collect(),
        );
        body = body.child(field(
            "Node version",
            Some(NODE_HELP),
            div().flex().child(majors),
        ));
    }
    body.child(with_problem(
        "Poll interval",
        Some(POLL_HELP),
        &f.poll,
        problems.poll.as_ref(),
        false,
        cx,
    ))
    .child(text_dim(BUILD_DETECTION_NOTE).text_size(px(12.)))
}

// Targets for a site that serves servers the owner already runs; only the create page shows these.
pub fn servers_fields(f: &SiteFields) -> Div {
    div()
        .flex()
        .gap(px(12.))
        .child(div().flex_1().child(field(
            "Blue targets",
            Some("host:port with an optional weight, separated by commas."),
            f.blue.clone(),
        )))
        .child(div().flex_1().child(field(
            "Green targets",
            Some("Green is where the first deploy lands."),
            f.green.clone(),
        )))
}

// The health check: path and the timing the node accepts.
pub fn health_fields(f: &SiteFields, problems: &FieldProblems) -> Div {
    let small = |label: &str, hint: &str, input: &Entity<TextInput>| {
        div()
            .flex_1()
            .child(field(label, Some(hint), input.clone()))
    };
    let mut col = div().flex().flex_col().gap(px(12.)).child(field(
        "Health check path",
        Some("Probed on every target to decide readiness. Must start with /."),
        f.health.clone(),
    ));
    col = col.child(
        div()
            .flex()
            .gap(px(12.))
            .child(small("Interval (ms)", "100 to 60000", &f.health_interval))
            .child(small(
                "Timeout (ms)",
                "100 to 10000, not above the interval",
                &f.health_timeout,
            ))
            .child(small(
                "Rise",
                "Passing probes to count as up, 1 to 10",
                &f.health_rise,
            ))
            .child(small(
                "Fall",
                "Failing probes to count as down, 1 to 10",
                &f.health_fall,
            )),
    );
    if let Some(p) = &problems.health {
        col = col.child(problem_text(p));
    }
    col
}
