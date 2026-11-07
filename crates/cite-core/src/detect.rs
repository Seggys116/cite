use std::collections::VecDeque;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::LazyLock;

use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions, OpenOptionsExt};

use regex::Regex;
use serde::Deserialize;
use serde_json::Value;

use crate::argv::{split_command, validate_start_argv};
use crate::error::{Error, Result};
use crate::schema::Rendering;

/// A package whose declared `bin` the start command runs through `node`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartBin {
    pub package: String,
    pub bin: String,
}

/// What the manager inferred from a checkout. Operator config overrides any field.
#[derive(Debug, Clone, PartialEq)]
pub struct Detection {
    pub framework: String,
    pub rendering: Rendering,
    pub package_manager: String,
    pub node_major: Option<String>,
    /// The major came from `.nvmrc` / `.node-version`, so it is a requirement rather than a range.
    pub node_exact: bool,
    pub node_engines: Option<String>,
    pub output_dir: String,
    /// Tried after `output_dir` when the build left no index.html there.
    pub alt_output_dirs: Vec<String>,
    pub install_command: String,
    pub build_command: String,
    pub start_argv: Vec<String>,
    /// SSR releases pack only this directory and start from it; `None` packs the site root.
    pub ssr_root: Option<String>,
    /// Once dependencies are installed, this package's declared bin replaces `start_argv[1]`.
    pub start_bin: Option<StartBin>,
    /// Next.js distDir; a standalone server found under it after the build is staged and preferred.
    pub next_dist_dir: Option<String>,
    pub spa_fallback: Option<String>,
    pub confidence: f32,
    /// Non-fatal findings such as conflicting lockfiles; the manager logs them.
    pub warnings: Vec<String>,
    /// What detection assumed or could not confirm, shown to the owner with the detection.
    pub notes: Vec<String>,
    /// Static sites pack only `output_dir`. SSR sites pack the app root.
    pub pack_output_only: bool,
}

impl Detection {
    fn blank(framework: &str, rendering: Rendering, confidence: f32) -> Self {
        Self {
            framework: framework.into(),
            rendering,
            package_manager: "npm".into(),
            node_major: None,
            node_exact: false,
            node_engines: None,
            output_dir: ".".into(),
            alt_output_dirs: Vec::new(),
            install_command: String::new(),
            build_command: String::new(),
            start_argv: Vec::new(),
            ssr_root: None,
            start_bin: None,
            next_dist_dir: None,
            spa_fallback: None,
            confidence,
            warnings: Vec::new(),
            notes: Vec::new(),
            pack_output_only: rendering == Rendering::Static,
        }
    }

    fn note(&mut self, text: impl Into<String>, confidence: f32) {
        self.notes.push(text.into());
        self.confidence = self.confidence.min(confidence);
    }
}

#[derive(Debug, Default, Deserialize)]
struct PackageJson {
    #[serde(default)]
    dependencies: Value,
    #[serde(default, rename = "devDependencies")]
    dev_dependencies: Value,
    #[serde(default)]
    scripts: Value,
    #[serde(default)]
    main: Value,
    #[serde(default, rename = "packageManager")]
    package_manager: Value,
    #[serde(default)]
    engines: Value,
}

pub fn detect_site(repo_dir: &Path) -> Result<Detection> {
    detect_site_with(repo_dir, None)
}

/// `package_manager` is the operator's explicit choice; `None` or `auto` detects it.
pub fn detect_site_with(repo_dir: &Path, package_manager: Option<&str>) -> Result<Detection> {
    detect_site_configured(repo_dir, package_manager, None)
}

/// `rendering` is the operator's explicit choice; when no framework is recognised it yields a generic detection instead of an error.
pub fn detect_site_configured(
    repo_dir: &Path,
    package_manager: Option<&str>,
    rendering: Option<Rendering>,
) -> Result<Detection> {
    detect_site_in(repo_dir, ".", package_manager, rendering)
}

/// Detects the site at `root_dir` inside the checkout; lockfiles, `packageManager` and Node version files are also looked up in the workspace directories above it.
pub fn detect_site_in(
    repo_root: &Path,
    root_dir: &str,
    package_manager: Option<&str>,
    rendering: Option<Rendering>,
) -> Result<Detection> {
    let top = Dir::open_ambient_dir(repo_root, ambient_authority())?;
    let rel = root_dir.trim_matches('/');
    if rel.is_empty() || rel == "." {
        return detect_dir(top, Vec::new(), package_manager, rendering);
    }
    if !workspace_member_ok(rel) {
        return Err(Error::Config(format!(
            "root_dir `{root_dir}` is absolute or contains `..`"
        )));
    }
    let site = top
        .open_dir(rel)
        .map_err(|err| Error::Config(format!("root_dir `{root_dir}`: {err}")))?;
    let mut parents = Vec::new();
    let mut prefix = Path::new(rel).parent();
    while let Some(dir) = prefix.filter(|p| !p.as_os_str().is_empty() && *p != Path::new(".")) {
        if let Ok(opened) = top.open_dir(dir) {
            parents.push(opened);
        }
        prefix = dir.parent();
    }
    parents.push(top);
    detect_dir(site, parents, package_manager, rendering)
}

/// Directories a plain static site is commonly served from, in preference order.
const STATIC_DIRS: [&str; 9] = [
    ".", "public", "dist", "build", "site", "www", "docs", "_site", "out",
];

fn detect_dir(
    dir: Dir,
    parents: Vec<Dir>,
    package_manager: Option<&str>,
    rendering: Option<Rendering>,
) -> Result<Detection> {
    if !dir.is_file("package.json") {
        if dir.is_file("Cargo.toml") {
            return detect_rust(&dir);
        }
        if let Some(found) = STATIC_DIRS
            .iter()
            .find(|sub| dir.is_file(Path::new(sub).join("index.html")))
        {
            let mut det = Detection::blank("generic-static", Rendering::Static, 0.6);
            det.output_dir = (*found).into();
            det.install_command = "true".into();
            det.build_command = "true".into();
            det.notes.push(format!(
                "no package.json; serving {found} as plain static files"
            ));
            return Ok(det);
        }
        return Err(Error::Config(
            "no package.json or index.html; set CITE_RENDERING and CITE_OUTPUT_DIR".into(),
        ));
    }
    let text = read_capped(&dir, "package.json", 1_048_576)?;
    let pkg: PackageJson =
        serde_json::from_str(&text).map_err(|err| Error::Config(format!("package.json: {err}")))?;
    let mut warnings = Vec::new();
    let pm = resolve_pm(&dir, &parents, &pkg, package_manager, &mut warnings);
    let (node_major, node_exact) = node_major(&dir, &parents, &pkg, &mut warnings);
    let node_engines = pkg
        .engines
        .get("node")
        .and_then(Value::as_str)
        .map(str::to_string);
    let site = Site {
        deps: dep_names(&pkg, true),
        prod_deps: dep_names(&pkg, false),
        dir,
        parents,
        pkg,
        pm,
    };
    let mut det = detect_framework(&site, rendering)?;
    det.package_manager = site.pm.name.clone();
    det.node_major = node_major;
    det.node_exact = node_exact;
    det.node_engines = node_engines;
    if det.install_command.is_empty() {
        det.install_command = install_command(&site, det.rendering);
    }
    if site.pm.pnp && det.rendering == Rendering::Ssr {
        det.notes.push(
            "Yarn Plug'n'Play has no node_modules for the server, so the install uses YARN_NODE_LINKER=node-modules"
                .into(),
        );
    }
    let mut notes = site.pm.notes.clone();
    notes.append(&mut det.notes);
    det.notes = notes;
    det.warnings = warnings;
    Ok(det)
}

/// The checkout as detection sees it.
struct Site {
    dir: Dir,
    /// Workspace directories above the site, nearest first; empty when the site is the checkout root.
    parents: Vec<Dir>,
    pkg: PackageJson,
    deps: Vec<String>,
    prod_deps: Vec<String>,
    pm: Pm,
}

impl Site {
    fn has(&self, name: &str) -> bool {
        self.deps.iter().any(|dep| dep == name)
    }

    fn has_prod(&self, name: &str) -> bool {
        self.prod_deps.iter().any(|dep| dep == name)
    }

    fn script(&self, name: &str) -> Option<&str> {
        self.pkg.scripts.get(name).and_then(Value::as_str)
    }

    fn monorepo(&self) -> bool {
        !self.parents.is_empty()
    }

    /// The first config file that exists, with comments removed.
    fn config(&self, names: &[&str]) -> Option<String> {
        names
            .iter()
            .find_map(|name| read_optional(&self.dir, name))
            .map(|text| strip_js_comments(&text))
    }

    fn has_config(&self, names: &[&str]) -> bool {
        names.iter().any(|name| self.dir.is_file(name))
    }

    /// The `build` script when the site has one, otherwise the framework CLI through the package manager.
    fn build(&self, cli: &str) -> String {
        if self.script("build").is_some() {
            format!("{} run build", self.pm.name)
        } else if cli.is_empty() {
            "true".into()
        } else {
            self.exec(cli)
        }
    }

    fn exec(&self, cli: &str) -> String {
        match self.pm.name.as_str() {
            "pnpm" => format!("pnpm exec {cli}"),
            "yarn" => format!("yarn {cli}"),
            "bun" => format!("bun x {cli}"),
            _ => format!("npm exec -- {cli}"),
        }
    }

    fn dep_major(&self, name: &str) -> Option<u32> {
        [&self.pkg.dependencies, &self.pkg.dev_dependencies]
            .iter()
            .find_map(|deps| deps.get(name)?.as_str())
            .and_then(leading_major)
            .and_then(|major| major.parse().ok())
    }
}

fn static_of(
    site: &Site,
    framework: &str,
    output: &str,
    alts: &[&str],
    spa: Option<&str>,
    confidence: f32,
    cli: &str,
) -> Detection {
    let mut det = Detection::blank(framework, Rendering::Static, confidence);
    det.output_dir = output.into();
    det.alt_output_dirs = alts
        .iter()
        .filter(|alt| **alt != output)
        .map(|alt| alt.to_string())
        .collect();
    det.spa_fallback = spa.map(str::to_string);
    det.build_command = site.build(cli);
    det
}

fn ssr_of(
    site: &Site,
    framework: &str,
    argv: Vec<String>,
    confidence: f32,
    cli: &str,
) -> Detection {
    let mut det = Detection::blank(framework, Rendering::Ssr, confidence);
    det.start_bin = start_bin_for(&argv);
    det.start_argv = argv;
    det.build_command = site.build(cli);
    det
}

fn strings(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| part.to_string()).collect()
}

const NEXT_CONFIGS: [&str; 5] = [
    "next.config.js",
    "next.config.mjs",
    "next.config.ts",
    "next.config.cjs",
    "next.config.mts",
];
const NUXT_CONFIGS: [&str; 4] = [
    "nuxt.config.ts",
    "nuxt.config.js",
    "nuxt.config.mjs",
    "nuxt.config.mts",
];
const SVELTE_CONFIGS: [&str; 3] = ["svelte.config.js", "svelte.config.mjs", "svelte.config.ts"];
const ASTRO_CONFIGS: [&str; 5] = [
    "astro.config.mjs",
    "astro.config.ts",
    "astro.config.js",
    "astro.config.mts",
    "astro.config.cjs",
];
const VITE_CONFIGS: [&str; 6] = [
    "vite.config.ts",
    "vite.config.js",
    "vite.config.mjs",
    "vite.config.mts",
    "vite.config.cjs",
    "vite.config.cts",
];
const REMIX_CONFIGS: [&str; 4] = [
    "remix.config.js",
    "remix.config.mjs",
    "remix.config.cjs",
    "remix.config.ts",
];
const REACT_ROUTER_CONFIGS: [&str; 3] = [
    "react-router.config.ts",
    "react-router.config.js",
    "react-router.config.mjs",
];

/// Dependencies that mark a plain Node HTTP server, with the framework name reported for each.
const SERVER_DEPS: [(&str, &str); 14] = [
    ("@nestjs/core", "nest"),
    ("express", "express"),
    ("fastify", "fastify"),
    ("koa", "koa"),
    ("@hono/node-server", "hono"),
    ("hono", "hono"),
    ("h3", "h3"),
    ("polka", "polka"),
    ("restify", "restify"),
    ("@hapi/hapi", "hapi"),
    ("@adonisjs/core", "adonis"),
    ("@feathersjs/feathers", "feathers"),
    ("elysia", "elysia"),
    ("socket.io", "socket.io"),
];

fn detect_framework(site: &Site, rendering: Option<Rendering>) -> Result<Detection> {
    if site.has("next") {
        return Ok(detect_next(site));
    }
    if site.has("nuxt") || site.has("nuxt3") || site.has("nuxt-edge") {
        return Ok(detect_nuxt(site));
    }
    if site.has("@sveltejs/kit") {
        return Ok(detect_sveltekit(site));
    }
    if site.has("astro") {
        return Ok(detect_astro(site));
    }
    if site.has("@react-router/dev")
        || site.has("@react-router/serve")
        || site.has("@react-router/node")
        || site.has_config(&REACT_ROUTER_CONFIGS)
    {
        return Ok(detect_react_router(site));
    }
    if site.has("@remix-run/dev") || site.has("@remix-run/serve") || site.has("@remix-run/node") {
        return Ok(detect_remix(site));
    }
    if site.has("@angular/core") {
        return Ok(detect_angular(site));
    }
    if site.has("@docusaurus/core") {
        return Ok(static_of(
            site,
            "docusaurus",
            "build",
            &[],
            None,
            0.9,
            "docusaurus build",
        ));
    }
    if site.has("vitepress") {
        return Ok(detect_vitepress(site));
    }
    if site.has("@11ty/eleventy") {
        return Ok(static_of(
            site,
            "eleventy",
            "_site",
            &["dist", "public", "build"],
            None,
            0.85,
            "eleventy",
        ));
    }
    if site.has("gatsby") {
        return Ok(static_of(
            site,
            "gatsby",
            "public",
            &[],
            None,
            0.9,
            "gatsby build",
        ));
    }
    if site.has("react-scripts") {
        return Ok(static_of(
            site,
            "create-react-app",
            "build",
            &[],
            Some("index.html"),
            0.9,
            "react-scripts build",
        ));
    }
    if site.has("@vue/cli-service") {
        return Ok(static_of(
            site,
            "vue-cli",
            "dist",
            &[],
            Some("index.html"),
            0.85,
            "vue-cli-service build",
        ));
    }
    if site.has("vite") {
        return Ok(detect_vite(site));
    }
    match rendering {
        Some(Rendering::Static) => return Ok(generic_static(site)),
        Some(Rendering::Ssr) => {
            return Ok(match detect_node_server(site) {
                Ok(Some(det)) => det,
                Ok(None) => ssr_of(site, "generic-node", Vec::new(), 0.4, ""),
                Err(err) => {
                    let mut det = ssr_of(site, "generic-node", Vec::new(), 0.4, "");
                    det.notes.push(err.to_string());
                    det
                }
            });
        }
        None => {}
    }
    if site.has("parcel") {
        return Ok(static_of(
            site,
            "parcel",
            "dist",
            &[],
            None,
            0.6,
            "parcel build",
        ));
    }
    if let Some(det) = detect_node_server(site)? {
        return Ok(det);
    }
    detect_plain(site)
}

fn detect_next(site: &Site) -> Detection {
    let text = site.config(&NEXT_CONFIGS).unwrap_or_default();
    let output = js_string(&text, "output");
    let dist = js_string(&text, "distDir")
        .and_then(|dir| clean_rel(&dir))
        .unwrap_or_else(|| ".next".into());
    let base_path = js_string(&text, "basePath").filter(|path| !path.is_empty());
    let exports = output.as_deref() == Some("export")
        || site
            .script("build")
            .is_some_and(|s| s.contains("next export"));
    if exports {
        let alts: Vec<&str> = if dist == ".next" {
            Vec::new()
        } else {
            vec![dist.as_str()]
        };
        let mut det = static_of(site, "next", "out", &alts, None, 0.9, "next build");
        if let Some(base) = base_path {
            det.note(
                format!("basePath {base}: the export is served from the site root, so links under {base} need a matching route"),
                0.7,
            );
        }
        return det;
    }
    let mut det = if output.as_deref() == Some("standalone") {
        let mut det = ssr_of(
            site,
            "next",
            strings(&["node", "server.js"]),
            0.9,
            "next build",
        );
        det.ssr_root = Some(format!("{dist}/standalone"));
        det
    } else {
        let mut notes = Vec::new();
        let argv = match site
            .script("start")
            .map(|_| script_argv(site, "start", &mut notes))
        {
            Some(Ok(argv)) if argv.first().is_some_and(|a| a == "node") => argv,
            _ => {
                notes.clear();
                next_start_argv(&[])
            }
        };
        let mut det = ssr_of(site, "next", argv, 0.85, "next build");
        for note in notes {
            det.note(note, 0.7);
        }
        if site.monorepo() {
            det.note(
                monorepo_note("set output: 'standalone' in next.config"),
                0.5,
            );
        }
        det
    };
    if output.is_none() && js_key_is_expression(&text, "output") {
        det.note(
            "next.config sets output from an expression; Cite runs the standalone server if the build writes one, otherwise next start",
            0.7,
        );
    }
    det.next_dist_dir = Some(dist);
    det
}

/// `next start` through node; a port or host in the script is dropped because the executor sets PORT.
fn next_start_argv(extra: &[String]) -> Vec<String> {
    let mut argv = strings(&["node", "node_modules/next/dist/bin/next", "start"]);
    let mut args = extra.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-p" | "--port" | "-H" | "--hostname" => {
                args.next();
            }
            other
                if other.starts_with("--port=")
                    || other.starts_with("--hostname=")
                    || other.starts_with("-p=")
                    || other.starts_with("-H=") => {}
            "start" => {}
            other => argv.push(other.to_string()),
        }
    }
    argv.extend(strings(&["-H", "127.0.0.1"]));
    argv
}

fn monorepo_note(fix: &str) -> String {
    format!(
        "monorepo: only the site directory is packed, so dependencies hoisted to the workspace root are missing at runtime; {fix} or set CITE_START_COMMAND to a bundled server"
    )
}

fn detect_nuxt(site: &Site) -> Detection {
    let text = site.config(&NUXT_CONFIGS).unwrap_or_default();
    if site.dep_major("nuxt").is_some_and(|major| major < 3) {
        let mut det = ssr_of(
            site,
            "nuxt",
            strings(&["node", "node_modules/nuxt/bin/nuxt.js", "start"]),
            0.5,
            "nuxt build",
        );
        det.note(
            "Nuxt 2 detected; Cite runs `nuxt start` and expects .nuxt and nuxt.config in the release",
            0.5,
        );
        return det;
    }
    let ssr_off = SSR_FALSE.is_match(&text);
    let preset = js_string(&text, "preset");
    let generates = site
        .script("build")
        .is_some_and(|script| script.contains("generate"));
    let static_preset = preset
        .as_deref()
        .is_some_and(|p| matches!(p, "static" | "github-pages" | "github_pages"));
    if ssr_off || generates || static_preset {
        let spa = ssr_off.then_some("index.html");
        let mut det = static_of(site, "nuxt", ".output/public", &["dist"], spa, 0.85, "");
        det.build_command = if generates {
            format!("{} run build", site.pm.name)
        } else if site.script("generate").is_some() {
            format!("{} run generate", site.pm.name)
        } else {
            site.exec("nuxt generate")
        };
        return det;
    }
    let mut det = ssr_of(
        site,
        "nuxt",
        strings(&["node", "server/index.mjs"]),
        0.9,
        "nuxt build",
    );
    det.ssr_root = Some(".output".into());
    if let Some(preset) =
        preset.filter(|p| !matches!(p.as_str(), "node-server" | "node" | "node_server"))
    {
        det.note(
            format!("nitro preset `{preset}` may not build a Node server; Cite expects .output/server/index.mjs from the node-server preset"),
            0.5,
        );
    }
    det
}

fn detect_sveltekit(site: &Site) -> Detection {
    let text = site.config(&SVELTE_CONFIGS).unwrap_or_default();
    let names_static = text.contains("adapter-static");
    let names_node = text.contains("adapter-node");
    let (use_static, use_node) = if names_static != names_node {
        (names_static, names_node)
    } else {
        let node = site.has("@sveltejs/adapter-node");
        (site.has("@sveltejs/adapter-static") && !node, node)
    };
    if use_static {
        let pages = js_string(&text, "pages")
            .and_then(|dir| clean_rel(&dir))
            .unwrap_or_else(|| "build".into());
        let fallback = js_string(&text, "fallback").and_then(|f| clean_rel(&f));
        return static_of(
            site,
            "sveltekit",
            &pages,
            &[],
            fallback.as_deref(),
            0.85,
            "vite build",
        );
    }
    let out = use_node
        .then(|| js_string(&text, "out").and_then(|dir| clean_rel(&dir)))
        .flatten()
        .unwrap_or_else(|| "build".into());
    let mut det = ssr_of(
        site,
        "sveltekit",
        vec!["node".into(), format!("{out}/index.js")],
        0.9,
        "vite build",
    );
    if !use_node {
        det.note(
            "SvelteKit has no adapter-node or adapter-static; adapter-auto writes no runnable server here. Install @sveltejs/adapter-node for SSR or @sveltejs/adapter-static for a static site",
            0.4,
        );
    }
    if site.monorepo() {
        det.note(monorepo_note("bundle dependencies into the build"), 0.6);
    }
    det
}

fn detect_astro(site: &Site) -> Detection {
    let text = site.config(&ASTRO_CONFIGS).unwrap_or_default();
    let out = js_string(&text, "outDir")
        .and_then(|dir| clean_rel(&dir))
        .unwrap_or_else(|| "dist".into());
    let node = site.has("@astrojs/node") && (text.is_empty() || text.contains("@astrojs/node"));
    if node {
        let mut det = ssr_of(
            site,
            "astro",
            vec!["node".into(), format!("{out}/server/entry.mjs")],
            0.85,
            "astro build",
        );
        if js_string(&text, "mode").as_deref() == Some("middleware") {
            det.note(
                "the Astro node adapter is in middleware mode, which exports a handler and does not listen; set mode: 'standalone'",
                0.4,
            );
        }
        if site.monorepo() {
            det.note(monorepo_note("bundle dependencies into the build"), 0.6);
        }
        return det;
    }
    let mut det = static_of(site, "astro", &out, &[], None, 0.9, "astro build");
    if js_string(&text, "output").as_deref() == Some("server") {
        det.note(
            "astro.config sets output: 'server' without @astrojs/node; Cite serves the static files only. Add @astrojs/node with mode: 'standalone' for SSR",
            0.4,
        );
        det.alt_output_dirs.push(format!("{out}/client"));
    }
    det
}

fn detect_react_router(site: &Site) -> Detection {
    let text = site.config(&REACT_ROUTER_CONFIGS).unwrap_or_default();
    if SSR_FALSE.is_match(&text) {
        return static_of(
            site,
            "react-router",
            "build/client",
            &[],
            Some("index.html"),
            0.85,
            "react-router build",
        );
    }
    let default = strings(&[
        "node",
        "node_modules/@react-router/serve/dist/cli.js",
        "./build/server/index.js",
    ]);
    let mut det = framework_server(site, "react-router", default, "react-router build");
    if det
        .start_bin
        .as_ref()
        .is_some_and(|bin| bin.package == "@react-router/serve")
        && !site.has_prod("@react-router/serve")
    {
        det.note(
            "@react-router/serve must be in dependencies (not devDependencies) to start the server",
            0.5,
        );
    }
    det
}

fn detect_remix(site: &Site) -> Detection {
    let vite = site
        .config(&VITE_CONFIGS)
        .is_some_and(|text| text.contains("remix"));
    let classic = !vite && site.has_config(&REMIX_CONFIGS);
    let server = if classic {
        site.config(&REMIX_CONFIGS)
            .and_then(|text| js_string(&text, "serverBuildPath"))
            .and_then(|path| clean_rel(&path))
            .map(|path| format!("./{path}"))
            .unwrap_or_else(|| "./build/index.js".into())
    } else {
        "./build/server/index.js".into()
    };
    let default = vec![
        "node".into(),
        "node_modules/@remix-run/serve/dist/cli.js".into(),
        server,
    ];
    let cli = if classic {
        "remix build"
    } else {
        "remix vite:build"
    };
    let mut det = framework_server(site, "remix", default, cli);
    if det
        .start_bin
        .as_ref()
        .is_some_and(|bin| bin.package == "@remix-run/serve")
        && !site.has_prod("@remix-run/serve")
    {
        det.note(
            "@remix-run/serve must be in dependencies (not devDependencies) to start the server",
            0.5,
        );
    }
    det
}

/// Uses the site's own start script when it parses to an argv, otherwise the framework's default server.
fn framework_server(site: &Site, framework: &str, default: Vec<String>, cli: &str) -> Detection {
    let mut notes = Vec::new();
    let argv = match site.script("start") {
        Some(_) => match script_argv(site, "start", &mut notes) {
            Ok(argv) => argv,
            Err(err) => {
                notes.push(format!(
                    "{err}; using `{}`",
                    crate::argv::render_argv(&default)
                ));
                default
            }
        },
        None => default,
    };
    let mut det = ssr_of(site, framework, argv, 0.85, cli);
    for note in notes {
        det.note(note, 0.7);
    }
    if site.monorepo() {
        det.note(monorepo_note("bundle dependencies into the build"), 0.6);
    }
    det
}

fn detect_angular(site: &Site) -> Detection {
    let project = angular_project(&site.dir);
    let name = project
        .as_ref()
        .map(|p| p.name.clone())
        .unwrap_or_else(|| "app".into());
    let base = project
        .as_ref()
        .and_then(|p| p.output_base.clone())
        .unwrap_or_else(|| format!("dist/{name}"));
    let browser = project
        .as_ref()
        .and_then(|p| p.browser.clone())
        .unwrap_or_else(|| "browser".into());
    if site.has("@angular/ssr") || site.has("@nguniversal/express-engine") {
        let script = site.pkg.scripts.as_object().and_then(|scripts| {
            scripts
                .keys()
                .find(|key| key.starts_with("serve:ssr"))
                .cloned()
        });
        let mut notes = Vec::new();
        let argv = script
            .and_then(|key| script_argv(site, &key, &mut notes).ok())
            .unwrap_or_else(|| {
                let entry = if site.has("@angular/ssr") {
                    "server/server.mjs"
                } else {
                    "server/main.js"
                };
                vec!["node".into(), format!("{base}/{entry}")]
            });
        let mut det = ssr_of(site, "angular", argv, 0.8, "ng build");
        for note in notes {
            det.note(note, 0.7);
        }
        return det;
    }
    let primary = if browser.is_empty() {
        base.clone()
    } else {
        format!("{base}/{browser}")
    };
    static_of(
        site,
        "angular",
        &primary,
        &[base.as_str()],
        Some("index.html"),
        0.8,
        "ng build",
    )
}

fn detect_vitepress(site: &Site) -> Detection {
    let src = site
        .script("build")
        .and_then(|script| VITEPRESS_BUILD.captures(script))
        .and_then(|caps| clean_rel(caps.get(1)?.as_str()));
    let output = match &src {
        Some(dir) => format!("{dir}/.vitepress/dist"),
        None => ".vitepress/dist".into(),
    };
    static_of(
        site,
        "vitepress",
        &output,
        &["docs/.vitepress/dist", ".vitepress/dist"],
        None,
        0.9,
        "vitepress build",
    )
}

fn detect_vite(site: &Site) -> Detection {
    let text = site.config(&VITE_CONFIGS).unwrap_or_default();
    let out = js_string(&text, "outDir")
        .and_then(|dir| clean_rel(&dir))
        .unwrap_or_else(|| "dist".into());
    let root = js_string(&text, "root").and_then(|dir| clean_rel(&dir));
    let primary = match &root {
        Some(root) => format!("{root}/{out}"),
        None => out.clone(),
    };
    let mut det = static_of(
        site,
        "vite",
        &primary,
        &[out.as_str()],
        Some("index.html"),
        0.8,
        "vite build",
    );
    if site.has("vike") || site.has("vite-plugin-ssr") {
        det.note(
            "vike/vite-plugin-ssr can render on a server; Cite serves the prerendered files. Set CITE_RENDERING=ssr and CITE_START_COMMAND for a server",
            0.5,
        );
    }
    det
}

fn generic_static(site: &Site) -> Detection {
    if site.script("build").is_none() {
        let found = STATIC_DIRS
            .iter()
            .find(|sub| site.dir.is_file(Path::new(sub).join("index.html")))
            .copied()
            .unwrap_or(".");
        return static_of(site, "generic-static", found, &[], None, 0.5, "");
    }
    let mut det = static_of(
        site,
        "generic-static",
        "dist",
        &["build", "out", "public", "_site", "."],
        None,
        0.4,
        "",
    );
    det.notes.push(
        "no framework recognised; Cite serves the first of dist, build, out, public, _site or the site root that holds index.html after the build"
            .into(),
    );
    det
}

fn detect_node_server(site: &Site) -> Result<Option<Detection>> {
    let framework = SERVER_DEPS
        .iter()
        .find(|(dep, _)| site.has(dep))
        .map(|(_, name)| *name);
    let nest = site.has("@nestjs/core");
    let script = if nest && site.script("start:prod").is_some() {
        "start:prod"
    } else {
        "start"
    };
    let has_start = site.script(script).is_some();
    if !has_start && framework.is_none() {
        return Ok(None);
    }
    let name = framework.unwrap_or("node");
    let main = site
        .pkg
        .main
        .as_str()
        .and_then(clean_rel)
        .filter(|main| main != ".");
    let mut notes = Vec::new();
    let argv = if has_start {
        script_argv(site, script, &mut notes).map_err(Error::Config)?
    } else if let Some(main) = main {
        vec!["node".into(), main]
    } else if nest {
        notes.push("no start:prod script; assuming the Nest build writes dist/main.js".into());
        strings(&["node", "dist/main.js"])
    } else {
        return Err(Error::Config(format!(
            "found {name} but no start script or main field; set CITE_START_COMMAND (for example `node server.js`)"
        )));
    };
    let confidence = if framework.is_some() { 0.8 } else { 0.7 };
    let mut det = ssr_of(site, name, argv, confidence, "");
    for note in notes {
        det.note(note, 0.7);
    }
    if det.start_argv.first().is_some_and(|argv0| argv0 == "bun") {
        det.note(
            "this start command runs with Bun, so the site needs CITE_RUNTIME=bun",
            0.7,
        );
    }
    if site.monorepo() {
        det.note(monorepo_note("bundle dependencies into the build"), 0.6);
    }
    Ok(Some(det))
}

fn detect_plain(site: &Site) -> Result<Detection> {
    if site.script("build").is_none() {
        if let Some(found) = STATIC_DIRS
            .iter()
            .find(|sub| site.dir.is_file(Path::new(sub).join("index.html")))
        {
            let mut det = static_of(site, "generic-static", found, &[], None, 0.6, "");
            det.notes.push(format!(
                "no framework, build script or start script; serving {found} as plain static files"
            ));
            return Ok(det);
        }
        return Err(Error::Config(
            "ambiguous site: package.json names no known framework, start script or index.html; set CITE_RENDERING (static or ssr)"
                .into(),
        ));
    }
    Err(Error::Config(
        "ambiguous site: package.json has a build script but no start script or known framework, so Cite cannot tell whether it builds a static site or a server; set CITE_RENDERING=static (with CITE_OUTPUT_DIR if the build does not write dist) or CITE_RENDERING=ssr with CITE_START_COMMAND"
            .into(),
    ))
}

/// Parses a package.json script into a shell-free argv, following `npm run <script>` style indirection.
fn script_argv(
    site: &Site,
    name: &str,
    notes: &mut Vec<String>,
) -> std::result::Result<Vec<String>, String> {
    let mut name = name.to_string();
    for _ in 0..4 {
        let script = site
            .script(&name)
            .ok_or_else(|| format!("scripts.{name} is missing"))?;
        let argv = start_script_argv(script).map_err(|_| {
            format!(
                "scripts.{name} `{}` needs a shell (&&, |, ;, $ or redirects) but Cite starts the site without one; set CITE_START_COMMAND to a plain argv such as `node server.js`",
                clip(script, 120)
            )
        })?;
        let argv = strip_env_prefix(argv, &name, notes);
        if let Some(next) = run_target(&argv).filter(|next| site.script(next).is_some()) {
            name = next.to_string();
            continue;
        }
        let argv = normalize_launcher(site, argv, &name, notes);
        validate_start_argv(&argv).map_err(|err| format!("scripts.{name}: {err}"))?;
        return Ok(argv);
    }
    Err(format!(
        "scripts.{name} refers to other scripts too deeply; set CITE_START_COMMAND"
    ))
}

fn start_script_argv(script: &str) -> Result<Vec<String>> {
    split_command(script)
}

fn strip_env_prefix(argv: Vec<String>, name: &str, notes: &mut Vec<String>) -> Vec<String> {
    let mut rest = argv.as_slice();
    let mut dropped = Vec::new();
    loop {
        match rest.first().map(String::as_str) {
            Some("cross-env") => rest = &rest[1..],
            Some(arg) if ENV_ASSIGN.is_match(arg) => {
                let key = arg.split('=').next().unwrap_or(arg);
                if key != "NODE_ENV" {
                    dropped.push(key.to_string());
                }
                rest = &rest[1..];
            }
            _ => break,
        }
    }
    if !dropped.is_empty() {
        notes.push(format!(
            "scripts.{name} sets {}; Cite ignores it, set it in the site's runtime environment",
            dropped.join(", ")
        ));
    }
    rest.to_vec()
}

/// The script an `npm run x` / `pnpm x` / `yarn x` / `bun run x` argv points at.
fn run_target(argv: &[String]) -> Option<&str> {
    let arg = |i: usize| argv.get(i).map(String::as_str);
    match (arg(0)?, arg(1)) {
        ("npm", Some("run" | "run-script")) => arg(2),
        ("npm", Some("start")) => Some("start"),
        ("pnpm" | "yarn", Some("run")) => arg(2),
        ("pnpm" | "yarn", Some(other)) => Some(other),
        ("bun", Some("run")) => arg(2).filter(|target| !target.contains(['/', '.'])),
        _ => None,
    }
}

/// Known CLI bins that `node` can run directly once their package is installed.
const NODE_BINS: [(&str, &str, &str); 3] = [
    ("next", "next", "node_modules/next/dist/bin/next"),
    (
        "remix-serve",
        "@remix-run/serve",
        "node_modules/@remix-run/serve/dist/cli.js",
    ),
    (
        "react-router-serve",
        "@react-router/serve",
        "node_modules/@react-router/serve/dist/cli.js",
    ),
];

fn start_bin_for(argv: &[String]) -> Option<StartBin> {
    if argv.first().map(String::as_str) != Some("node") {
        return None;
    }
    let script = argv.get(1)?;
    NODE_BINS
        .iter()
        .find(|(_, _, path)| script == path)
        .map(|(bin, package, _)| StartBin {
            package: package.to_string(),
            bin: bin.to_string(),
        })
}

const WATCHER_VALUE_FLAGS: [&str; 12] = [
    "-w", "--watch", "-e", "--ext", "-i", "--ignore", "-x", "--exec", "-d", "--delay", "--signal",
    "--config",
];

fn normalize_launcher(
    site: &Site,
    argv: Vec<String>,
    name: &str,
    notes: &mut Vec<String>,
) -> Vec<String> {
    let Some(argv0) = argv.first().cloned() else {
        return argv;
    };
    if argv0 == "next" {
        return next_start_argv(&argv[1..]);
    }
    if let Some((_, _, path)) = NODE_BINS.iter().find(|(bin, _, _)| *bin == argv0) {
        let mut out = vec!["node".to_string(), path.to_string()];
        out.extend(argv[1..].iter().cloned());
        return out;
    }
    if argv0 == "bun" && argv.get(1).map(String::as_str) == Some("run") {
        let mut out = vec![argv0];
        out.extend(argv[2..].iter().cloned());
        return out;
    }
    if matches!(argv0.as_str(), "nodemon" | "node-dev" | "supervisor") {
        notes.push(format!(
            "scripts.{name} uses {argv0}, a development watcher; Cite runs the same file with node"
        ));
        let mut out = vec!["node".to_string()];
        let mut args = argv[1..].iter();
        while let Some(arg) = args.next() {
            if WATCHER_VALUE_FLAGS.contains(&arg.as_str()) {
                args.next();
            } else if !arg.starts_with('-') {
                out.push(arg.clone());
            }
        }
        return out;
    }
    if !matches!(argv0.as_str(), "node" | "bun") && !argv0.contains('/') && !site.has_prod(&argv0) {
        notes.push(format!(
            "scripts.{name} runs `{argv0}`, which must come from a package in dependencies; the production prune removes devDependencies"
        ));
    }
    argv
}

/// The resolved package manager; `berry` only matters for yarn 2 and newer.
#[derive(Debug, Clone, PartialEq)]
struct Pm {
    name: String,
    berry: bool,
    /// Yarn 2+ without a node_modules linker.
    pnp: bool,
    /// Lockfiles in the nearest directory (site, then workspace parents) that has any.
    locks: Vec<&'static str>,
    notes: Vec<String>,
}

fn install_command(site: &Site, rendering: Rendering) -> String {
    let pm = &site.pm;
    if site.deps.is_empty() && pm.locks.is_empty() {
        return "true".into();
    }
    let locked = |names: &[&str]| pm.locks.iter().any(|lock| names.contains(lock));
    let command = match pm.name.as_str() {
        "pnpm" if locked(&["pnpm-lock.yaml"]) => "pnpm install --frozen-lockfile",
        "pnpm" => "pnpm install",
        "yarn" if !locked(&["yarn.lock"]) => "yarn install",
        "yarn" if pm.berry => "yarn install --immutable",
        "yarn" => "yarn install --frozen-lockfile",
        "bun" if locked(&["bun.lock", "bun.lockb"]) => "bun install --frozen-lockfile",
        "bun" => "bun install",
        _ if locked(&["package-lock.json", "npm-shrinkwrap.json"]) => "npm ci",
        _ => "npm install",
    };
    if pm.pnp && rendering == Rendering::Ssr {
        return format!("YARN_NODE_LINKER=node-modules {command}");
    }
    command.into()
}

const LOCKFILES: [&str; 6] = [
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
    "package-lock.json",
    "npm-shrinkwrap.json",
];

/// Precedence: explicit operator choice, then the `packageManager` field, then lockfiles (pnpm, yarn, bun, npm).
fn resolve_pm(
    dir: &Dir,
    parents: &[Dir],
    pkg: &PackageJson,
    explicit: Option<&str>,
    warnings: &mut Vec<String>,
) -> Pm {
    let dirs = || std::iter::once(dir).chain(parents.iter());
    let field_text = pkg
        .package_manager
        .as_str()
        .map(str::to_string)
        .or_else(|| {
            parents.iter().find_map(|parent| {
                let text = read_optional(parent, "package.json")?;
                let value: Value = serde_json::from_str(&text).ok()?;
                value.get("packageManager")?.as_str().map(str::to_string)
            })
        });
    let field = field_text.as_deref().and_then(|field| {
        let (name, version) = field.split_once('@').unwrap_or((field, ""));
        matches!(name, "pnpm" | "bun" | "npm" | "yarn")
            .then(|| (name.to_string(), version.to_string()))
    });
    let lock_dir = dirs().find(|d| LOCKFILES.iter().any(|name| d.exists(name)));
    let locks: Vec<&'static str> = lock_dir
        .map(|d| {
            LOCKFILES
                .iter()
                .copied()
                .filter(|name| d.exists(name))
                .collect()
        })
        .unwrap_or_default();
    let (name, reason) = if let Some(name) = explicit.filter(|name| *name != "auto") {
        (name.to_string(), "CITE_PACKAGE_MANAGER")
    } else if let Some((name, _)) = &field {
        (name.clone(), "the packageManager field in package.json")
    } else if let Some(name) = lockfile_manager(&locks) {
        (name.to_string(), "lockfile precedence pnpm, yarn, bun, npm")
    } else {
        ("npm".to_string(), "no lockfile found")
    };
    if locks.len() > 1 {
        warnings.push(format!(
            "multiple lockfiles found ({}); using {name} because of {reason}",
            locks.join(", ")
        ));
    }
    let yarnrc = dirs().find_map(|d| read_optional(d, ".yarnrc.yml"));
    let berry_lock = lock_dir
        .and_then(|d| read_head(d, "yarn.lock", 4096))
        .is_some_and(|head| head.contains("__metadata:"));
    let field_major = field
        .as_ref()
        .and_then(|(_, version)| leading_major(version));
    let field_berry = field
        .as_ref()
        .is_some_and(|(field_name, _)| field_name == "yarn")
        && field_major
            .as_deref()
            .is_some_and(|major| major != "1" && major != "0");
    let berry = yarnrc.is_some() || field_berry || berry_lock;
    let linker = yarnrc
        .as_deref()
        .and_then(|text| yaml_value(text, "nodeLinker"));
    let pnp =
        name == "yarn" && berry && !matches!(linker.as_deref(), Some("node-modules" | "pnpm"));
    let mut notes = Vec::new();
    let pinned = field
        .as_ref()
        .is_some_and(|(field_name, _)| *field_name == name);
    if name == "yarn"
        && berry
        && !pinned
        && !yarnrc.as_deref().is_some_and(|t| t.contains("yarnPath"))
    {
        notes.push(
            "the Yarn 2+ lockfile has no packageManager field to pin Yarn; add \"packageManager\": \"yarn@<version>\" so Corepack runs the right Yarn"
                .into(),
        );
    }
    if name == "pnpm" && !pinned && locks.contains(&"pnpm-lock.yaml") {
        let version = lock_dir
            .and_then(|d| read_head(d, "pnpm-lock.yaml", 512))
            .and_then(|head| yaml_value(&head, "lockfileVersion"))
            .and_then(|v| leading_major(&v));
        if let Some(version) = version.filter(|v| v.parse::<u32>().is_ok_and(|n| n < 9)) {
            notes.push(format!(
                "pnpm-lock.yaml is lockfile v{version} from an older pnpm and package.json has no packageManager field; add \"packageManager\": \"pnpm@<version>\" if the frozen install refuses it"
            ));
        }
    }
    Pm {
        name,
        berry,
        pnp,
        locks,
        notes,
    }
}

fn lockfile_manager(locks: &[&str]) -> Option<&'static str> {
    let has = |name: &str| locks.contains(&name);
    if has("pnpm-lock.yaml") {
        Some("pnpm")
    } else if has("yarn.lock") {
        Some("yarn")
    } else if has("bun.lock") || has("bun.lockb") {
        Some("bun")
    } else if has("package-lock.json") || has("npm-shrinkwrap.json") {
        Some("npm")
    } else {
        None
    }
}

/// The value of a top-level `key: value` line in a small YAML file.
fn yaml_value(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let rest = line.strip_prefix(key)?.trim_start().strip_prefix(':')?;
        let value = rest.trim().trim_matches(['"', '\'']);
        (!value.is_empty()).then(|| value.to_string())
    })
}

fn node_major(
    dir: &Dir,
    parents: &[Dir],
    pkg: &PackageJson,
    warnings: &mut Vec<String>,
) -> (Option<String>, bool) {
    for d in std::iter::once(dir).chain(parents.iter()) {
        for name in [".nvmrc", ".node-version"] {
            let Some(text) = read_optional(d, name) else {
                continue;
            };
            let Some(value) = text
                .lines()
                .map(str::trim)
                .find(|line| !line.is_empty() && !line.starts_with('#'))
            else {
                continue;
            };
            if let Some(major) = version_major(value) {
                return (Some(major), true);
            }
            warnings.push(format!(
                "{name} is not a numeric version (version aliases are unsupported); ignoring it"
            ));
        }
    }
    let engines = pkg.engines.get("node").and_then(Value::as_str);
    (engines.and_then(leading_major), false)
}

/// Whether a semver range such as `>=18`, `^20 || ^22` or `18.x` admits Node `major`; `None` when the range is not understood.
pub fn node_range_allows(range: &str, major: u32) -> Option<bool> {
    let range = range.trim();
    if range.is_empty() || range == "*" || range == "x" {
        return Some(true);
    }
    let mut any = false;
    for alternative in range.split("||") {
        let alternative = alternative.trim();
        if let Some((low, high)) = alternative.split_once(" - ") {
            let low = range_major(low)?;
            let high = range_major(high)?;
            any |= low <= major && major <= high;
            continue;
        }
        let mut tokens = Vec::new();
        let mut pending = String::new();
        for word in alternative.split_whitespace() {
            if matches!(word, ">=" | "<=" | ">" | "<" | "=" | "^" | "~") {
                pending = word.to_string();
            } else {
                tokens.push(format!("{pending}{word}"));
                pending.clear();
            }
        }
        let mut all = true;
        for token in &tokens {
            all &= comparator_allows(token, major)?;
        }
        any |= all && !tokens.is_empty();
    }
    Some(any)
}

fn comparator_allows(token: &str, major: u32) -> Option<bool> {
    let (op, version) = [">=", "<=", ">", "<", "=", "^", "~", "v"]
        .iter()
        .find_map(|op| token.strip_prefix(op).map(|rest| (*op, rest)))
        .unwrap_or(("", token));
    if matches!(version, "*" | "x" | "X") {
        return Some(true);
    }
    let wanted = range_major(version)?;
    let exact_minor = version
        .split('.')
        .nth(1)
        .is_some_and(|minor| minor.chars().all(|c| c.is_ascii_digit()) && minor != "0");
    Some(match op {
        ">=" => major >= wanted,
        ">" if exact_minor => major >= wanted,
        ">" => major > wanted || (major == wanted && version.contains('.')),
        "<=" => major <= wanted,
        "<" => major < wanted || (major == wanted && exact_minor),
        _ => major == wanted,
    })
}

fn range_major(version: &str) -> Option<u32> {
    let version = version.trim().trim_start_matches(['v', 'V', '=']);
    let digits: String = version.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// Accepts `22`, `v22.1.0` and `22.x`; aliases such as `lts/*` or `node` yield `None`.
fn version_major(value: &str) -> Option<String> {
    let rest = value.strip_prefix(['v', 'V']).unwrap_or(value);
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    let after = &rest[digits.len()..];
    (!digits.is_empty() && (after.is_empty() || after.starts_with(['.', ' ', '-', 'x'])))
        .then_some(digits)
}

fn leading_major(text: &str) -> Option<String> {
    let digits: String = text
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        None
    } else {
        Some(digits)
    }
}

fn dep_names(pkg: &PackageJson, include_dev: bool) -> Vec<String> {
    let mut names = Vec::new();
    let sources: &[&Value] = if include_dev {
        &[&pkg.dependencies, &pkg.dev_dependencies]
    } else {
        &[&pkg.dependencies]
    };
    for value in sources {
        if let Some(map) = value.as_object() {
            names.extend(map.keys().cloned());
        }
    }
    names
}

static BLOCK_COMMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)/\*.*?\*/").expect("block comment regex"));
static LINE_COMMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)(^|[\s;,{(])//.*$").expect("line comment regex"));
static SSR_FALSE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\bssr["']?\s*:\s*false\b"#).expect("ssr regex"));
static ENV_ASSIGN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*=").expect("env regex"));
static VITEPRESS_BUILD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"vitepress\s+build\s+([^\s-][^\s]*)").expect("vitepress regex"));

/// Drops `/* */` and `//` comments so a commented-out option is not read; `//` inside a URL is kept.
fn strip_js_comments(text: &str) -> String {
    let without_blocks = BLOCK_COMMENT.replace_all(text, " ");
    LINE_COMMENT.replace_all(&without_blocks, "$1").into_owned()
}

/// The literal string value of `key` in a JS or JSON config, if it is written as one.
fn js_string(text: &str, key: &str) -> Option<String> {
    let pattern = format!(
        r#"(?:^|[^\w$.])["']?{}["']?\s*:\s*["'`]([^"'`\n]*)["'`]"#,
        regex::escape(key)
    );
    let re = Regex::new(&pattern).ok()?;
    re.captures(text)?.get(1).map(|m| m.as_str().to_string())
}

/// True when `key` is assigned something other than a string literal, such as an env lookup.
fn js_key_is_expression(text: &str, key: &str) -> bool {
    let pattern = format!(
        r#"(?:^|[^\w$.])["']?{}["']?\s*:\s*[^"'`\s,}}]"#,
        regex::escape(key)
    );
    Regex::new(&pattern).is_ok_and(|re| re.is_match(text))
}

/// A relative path that stays inside the site, without a leading `./` or trailing `/`.
fn clean_rel(path: &str) -> Option<String> {
    let trimmed = path.trim().trim_end_matches('/');
    let trimmed = trimmed.strip_prefix("./").unwrap_or(trimmed);
    if trimmed.is_empty() || trimmed == "." {
        return Some(".".into());
    }
    workspace_member_ok(trimmed).then(|| trimmed.to_string())
}

fn clip(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max_chars.saturating_sub(3)).collect();
    out.push_str("...");
    out
}

struct AngularProject {
    name: String,
    output_base: Option<String>,
    browser: Option<String>,
}

fn angular_project(dir: &Dir) -> Option<AngularProject> {
    let text = read_optional(dir, "angular.json")?;
    let value: Value = serde_json::from_str(&text).ok()?;
    let projects = value.get("projects")?.as_object()?;
    let name = value
        .get("defaultProject")
        .and_then(Value::as_str)
        .filter(|name| projects.contains_key(*name))
        .map(str::to_string)
        .or_else(|| {
            projects
                .iter()
                .find(|(_, p)| p.get("projectType").and_then(Value::as_str) == Some("application"))
                .map(|(name, _)| name.clone())
        })
        .or_else(|| projects.keys().next().cloned())?;
    let output = projects
        .get(&name)
        .and_then(|p| p.pointer("/architect/build/options/outputPath"));
    let (output_base, browser) = match output {
        Some(Value::String(path)) => (clean_rel(path), None),
        Some(Value::Object(map)) => (
            map.get("base").and_then(Value::as_str).and_then(clean_rel),
            map.get("browser")
                .and_then(Value::as_str)
                .map(|b| clean_rel(b).filter(|b| b != ".").unwrap_or_default()),
        ),
        _ => (None, None),
    };
    Some(AngularProject {
        name,
        output_base,
        browser,
    })
}

/// Finds the directory holding Next's standalone `server.js` with its distDir beside it, relative to `standalone`; monorepos nest it under the workspace path.
pub fn next_standalone_server_dir(standalone: &Path, dist_dir: &str) -> Option<PathBuf> {
    let mut queue = VecDeque::from([(PathBuf::new(), 0usize)]);
    while let Some((rel, depth)) = queue.pop_front() {
        let dir = standalone.join(&rel);
        if dir.join("server.js").is_file() && dir.join(dist_dir).is_dir() {
            return Some(rel);
        }
        if depth >= 6 {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut names: Vec<_> = entries
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().is_ok_and(|t| t.is_dir()))
            .map(|entry| entry.file_name())
            .filter(|name| name != "node_modules" && !name.to_string_lossy().starts_with('.'))
            .collect();
        names.sort();
        for name in names {
            queue.push_back((rel.join(name), depth + 1));
        }
    }
    None
}

/// The path, relative to `site`, of the script `bin` names in the installed package's package.json.
pub fn package_bin_path(site: &Path, start_bin: &StartBin) -> Option<String> {
    if !workspace_member_ok(&start_bin.package) {
        return None;
    }
    let root = Dir::open_ambient_dir(site, ambient_authority()).ok()?;
    let package_dir = format!("node_modules/{}", start_bin.package);
    let text = read_capped(&root, &format!("{package_dir}/package.json"), 1_048_576).ok()?;
    let value: Value = serde_json::from_str(&text).ok()?;
    let rel = match value.get("bin")? {
        Value::String(path) => path.clone(),
        Value::Object(map) => map.get(&start_bin.bin)?.as_str()?.to_string(),
        _ => return None,
    };
    let rel = clean_rel(&rel).filter(|rel| rel != ".")?;
    Some(format!("{package_dir}/{rel}"))
}

/// Reads through the repo-rooted handle so a symlink in the checkout cannot point outside it.
fn read_capped(dir: &Dir, name: &str, max: u64) -> Result<String> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32);
    let file = dir.open_with(name, &options)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(Error::msg(format!("{name} is not a regular file")));
    }
    if meta.len() > max {
        return Err(Error::TooLarge {
            len: meta.len(),
            max,
        });
    }
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(Error::TooLarge {
            len: bytes.len() as u64,
            max,
        });
    }
    String::from_utf8(bytes).map_err(|err| Error::msg(err.to_string()))
}

fn read_optional(dir: &Dir, name: &str) -> Option<String> {
    read_capped(dir, name, 262_144).ok()
}

/// The first `max` bytes of a file of any size, decoded lossily.
fn read_head(dir: &Dir, name: &str, max: u64) -> Option<String> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32);
    let file = dir.open_with(name, &options).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(max).read_to_end(&mut bytes).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

#[derive(Debug, Deserialize)]
struct CargoToml {
    #[serde(default)]
    package: Option<CargoPackage>,
    #[serde(default)]
    bin: Option<Vec<CargoBin>>,
    #[serde(default)]
    workspace: Option<CargoWorkspace>,
}

#[derive(Debug, Deserialize)]
struct CargoPackage {
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CargoBin {
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CargoWorkspace {
    #[serde(default)]
    members: Option<Vec<String>>,
    #[serde(default, rename = "default-members")]
    default_members: Option<Vec<String>>,
}

pub fn detect_rust_site(repo_dir: &Path) -> Result<Detection> {
    let root = Dir::open_ambient_dir(repo_dir, ambient_authority())?;
    if !root.is_file("Cargo.toml") {
        return Err(Error::Config(
            "no Cargo.toml; this checkout is not a Rust crate".into(),
        ));
    }
    detect_rust(&root)
}

fn detect_rust(root: &Dir) -> Result<Detection> {
    let name = cargo_bin_name(root)?;
    let locked = root.is_file("Cargo.lock");
    let mut warnings = Vec::new();
    if !locked {
        warnings.push("no Cargo.lock; cargo fetch and cargo build omit --locked".into());
    }
    let (install_command, build_command) = if locked {
        (
            "cargo fetch --locked".to_string(),
            "cargo build --release --locked".to_string(),
        )
    } else {
        (
            "cargo fetch".to_string(),
            "cargo build --release".to_string(),
        )
    };
    let mut det = Detection::blank("rust", Rendering::Ssr, 0.9);
    det.package_manager = "cargo".into();
    det.install_command = install_command;
    det.build_command = build_command;
    det.start_argv = vec![format!("bin/{name}")];
    det.warnings = warnings;
    Ok(det)
}

fn cargo_bin_name(root: &Dir) -> Result<String> {
    let text = read_capped(root, "Cargo.toml", 1_048_576)?;
    bin_name_from_manifest(&text, Some(root))
}

fn bin_name_from_manifest(text: &str, root: Option<&Dir>) -> Result<String> {
    let manifest: CargoToml =
        toml::from_str(text).map_err(|err| Error::Config(format!("Cargo.toml: {err}")))?;
    if let Some(name) = manifest
        .bin
        .as_ref()
        .and_then(|bins| bins.first())
        .and_then(|bin| bin.name.as_deref())
    {
        return checked_bin_name(name);
    }
    if let Some(name) = manifest
        .package
        .as_ref()
        .and_then(|package| package.name.as_deref())
    {
        return checked_bin_name(name);
    }
    if let Some(root) = root
        && let Some(member) = manifest.workspace.as_ref().and_then(workspace_member)
    {
        return member_bin_name(root, member);
    }
    Err(Error::Config(
        "could not name a cargo binary; set CITE_START_COMMAND".into(),
    ))
}

fn member_bin_name(root: &Dir, member: &str) -> Result<String> {
    if !workspace_member_ok(member) {
        return Err(Error::Config(format!(
            "cargo workspace member `{member}` is absolute or contains `..`"
        )));
    }
    let rel = Path::new(member).join("Cargo.toml");
    let rel = rel
        .to_str()
        .ok_or_else(|| Error::Config(format!("cargo workspace member `{member}` is not utf-8")))?;
    let text = read_capped(root, rel, 1_048_576)
        .map_err(|err| Error::Config(format!("cargo workspace member `{member}`: {err}")))?;
    bin_name_from_manifest(&text, None)
}

fn workspace_member(ws: &CargoWorkspace) -> Option<&str> {
    let defaults = ws
        .default_members
        .as_deref()
        .filter(|members| !members.is_empty());
    let members = defaults.or(ws.members.as_deref())?;
    members
        .iter()
        .find(|member| !member.is_empty())
        .map(String::as_str)
}

fn workspace_member_ok(member: &str) -> bool {
    if member.is_empty() || member.contains(['\0', '\\']) {
        return false;
    }
    let path = Path::new(member);
    if path.is_absolute() {
        return false;
    }
    let mut saw_normal = false;
    for component in path.components() {
        match component {
            Component::Normal(_) => saw_normal = true,
            Component::CurDir => {}
            _ => return false,
        }
    }
    saw_normal
}

fn checked_bin_name(name: &str) -> Result<String> {
    if bin_name_ok(name) {
        Ok(name.to_string())
    } else {
        Err(Error::Config(format!(
            "cargo binary name `{name}` is not a single path component; set CITE_START_COMMAND"
        )))
    }
}

fn bin_name_ok(name: &str) -> bool {
    !name.is_empty() && !name.contains(['/', '\\', '\0']) && name != "." && name != ".."
}

#[cfg(test)]
mod tests;
