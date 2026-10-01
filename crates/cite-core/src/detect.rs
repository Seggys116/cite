use std::io::Read;
use std::path::{Component, Path};

use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions, OpenOptionsExt};

use serde::Deserialize;
use serde_json::Value;

use crate::error::{Error, Result};
use crate::schema::Rendering;

/// What the manager inferred from a checkout. Operator config overrides any field.
#[derive(Debug, Clone, PartialEq)]
pub struct Detection {
    pub framework: String,
    pub rendering: Rendering,
    pub package_manager: String,
    pub node_major: Option<String>,
    pub output_dir: String,
    pub install_command: String,
    pub build_command: String,
    pub start_argv: Vec<String>,
    pub spa_fallback: Option<String>,
    pub confidence: f32,
    /// Non-fatal findings such as conflicting lockfiles; the manager logs them.
    pub warnings: Vec<String>,
    /// Static sites pack only `output_dir`. SSR sites pack the app root.
    pub pack_output_only: bool,
}

#[derive(Debug, Deserialize)]
struct PackageJson {
    #[serde(default)]
    dependencies: Value,
    #[serde(default, rename = "devDependencies")]
    dev_dependencies: Value,
    #[serde(default)]
    scripts: Value,
    #[serde(rename = "packageManager")]
    package_manager: Option<String>,
    #[serde(default)]
    engines: Option<Engines>,
}

#[derive(Debug, Deserialize)]
struct Engines {
    node: Option<String>,
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
    let root = Dir::open_ambient_dir(repo_dir, ambient_authority())?;
    if !root.is_file("package.json") {
        if root.is_file("Cargo.toml") {
            return detect_rust(&root);
        }
        if root.is_file("index.html") {
            return Ok(static_detection("generic-static", ".", None, 0.4));
        }
        return Err(Error::Config(
            "no package.json or index.html; set CITE_RENDERING and CITE_OUTPUT_DIR".into(),
        ));
    }
    let text = read_capped(&root, "package.json", 1_048_576)?;
    let pkg: PackageJson =
        serde_json::from_str(&text).map_err(|err| Error::Config(format!("package.json: {err}")))?;
    let mut warnings = Vec::new();
    let pm = resolve_pm(&root, &pkg, package_manager, &mut warnings);
    let node_major = node_major(&root, &pkg, &mut warnings);
    let mut det = detect_framework(&root, &pkg, &pm, node_major, rendering)?;
    det.warnings = warnings;
    Ok(det)
}

fn detect_framework(
    repo_dir: &Dir,
    pkg: &PackageJson,
    pm: &Pm,
    node_major: Option<String>,
    rendering: Option<Rendering>,
) -> Result<Detection> {
    let deps = dep_names(pkg);
    let has = |name: &str| deps.iter().any(|dep| dep == name);

    if has("next") {
        let configs = [
            "next.config.js",
            "next.config.mjs",
            "next.config.ts",
            "next.config.cjs",
        ];
        let export = config_contains(
            repo_dir,
            &configs,
            &["output: 'export'", "output: \"export\""],
        );
        if export {
            return Ok(static_detection("next", "out", None, 0.9).with_pm(repo_dir, pm, node_major));
        }
        let standalone = config_contains(
            repo_dir,
            &configs,
            &["output: 'standalone'", "output: \"standalone\""],
        );
        let mut det = if standalone {
            ssr(
                "next",
                "npm run build && mkdir -p .next/standalone/.next && cp -R .next/static .next/standalone/.next/static && (cp -R public .next/standalone/public || true)",
                vec!["node".into(), ".next/standalone/server.js".into()],
            )
        } else {
            ssr(
                "next",
                "",
                vec![
                    "next".into(),
                    "start".into(),
                    "-H".into(),
                    "127.0.0.1".into(),
                ],
            )
        };
        det.install_command = install_command(pm, repo_dir);
        det.build_command = build_with_pm(&pm.name, &det.build_command);
        det.package_manager = pm.name.clone();
        det.node_major = node_major;
        return Ok(det);
    }
    if has("nuxt") || has("nuxt3") {
        let static_site = config_contains(
            repo_dir,
            &["nuxt.config.ts", "nuxt.config.js", "nuxt.config.mjs"],
            &["ssr: false", "ssr:false"],
        );
        if static_site {
            return Ok(static_detection("nuxt", ".output/public", None, 0.85)
                .with_pm(repo_dir, pm, node_major));
        }
        return Ok(ssr(
            "nuxt",
            "",
            vec!["node".into(), ".output/server/index.mjs".into()],
        )
        .with_pm(repo_dir, pm, node_major));
    }
    if has("@sveltejs/kit") {
        if has("@sveltejs/adapter-static") {
            return Ok(static_detection("sveltekit", "build", None, 0.85)
                .with_pm(repo_dir, pm, node_major));
        }
        return Ok(ssr(
            "sveltekit",
            "",
            vec!["node".into(), "build/index.js".into()],
        )
        .with_pm(repo_dir, pm, node_major));
    }
    if has("astro") {
        if has("@astrojs/node") {
            return Ok(ssr(
                "astro",
                "",
                vec!["node".into(), "dist/server/entry.mjs".into()],
            )
            .with_pm(repo_dir, pm, node_major));
        }
        return Ok(static_detection("astro", "dist", None, 0.9).with_pm(repo_dir, pm, node_major));
    }
    if has("@angular/core") {
        let project = angular_project(repo_dir).unwrap_or_else(|| "app".into());
        if has("@angular/ssr") || has("@angular/platform-server") {
            return Ok(ssr(
                "angular",
                "",
                vec!["node".into(), format!("dist/{project}/server/server.mjs")],
            )
            .with_pm(repo_dir, pm, node_major));
        }
        return Ok(static_detection(
            "angular",
            &format!("dist/{project}/browser"),
            Some("index.html"),
            0.8,
        )
        .with_pm(repo_dir, pm, node_major));
    }
    if has("react-router") || has("@react-router/node") || has("@react-router/serve") {
        return Ok(ssr(
            "remix",
            "",
            vec!["react-router-serve".into(), "build/server/index.js".into()],
        )
        .with_pm(repo_dir, pm, node_major));
    }
    if has("@remix-run/node") || has("@remix-run/serve") {
        return Ok(ssr(
            "remix",
            "",
            vec!["remix-serve".into(), "build/index.js".into()],
        )
        .with_pm(repo_dir, pm, node_major));
    }
    if has("@docusaurus/core") {
        return Ok(
            static_detection("docusaurus", "build", None, 0.9).with_pm(repo_dir, pm, node_major)
        );
    }
    if has("vitepress") {
        return Ok(static_detection("vitepress", ".vitepress/dist", None, 0.9)
            .with_pm(repo_dir, pm, node_major));
    }
    if has("@11ty/eleventy") {
        return Ok(
            static_detection("eleventy", "_site", None, 0.9).with_pm(repo_dir, pm, node_major)
        );
    }
    if has("gatsby") {
        return Ok(
            static_detection("gatsby", "public", None, 0.85).with_pm(repo_dir, pm, node_major)
        );
    }
    if has("vite") {
        return Ok(static_detection("vite", "dist", Some("index.html"), 0.8)
            .with_pm(repo_dir, pm, node_major));
    }
    match rendering {
        Some(Rendering::Static) => {
            let mut det = static_detection("generic-static", ".", None, 0.4)
                .with_pm(repo_dir, pm, node_major);
            if script(pkg, "build").is_none() {
                det.build_command = "true".into();
            }
            return Ok(det);
        }
        Some(Rendering::Ssr) => {
            let mut det = ssr("generic-node", "", Vec::new());
            det.start_argv = start_script_argv(pkg).unwrap_or_default();
            return Ok(det.with_pm(repo_dir, pm, node_major));
        }
        None => {}
    }
    if script(pkg, "start").is_some() {
        let mut det = ssr("generic-node", "", Vec::new());
        det.start_argv = start_script_argv(pkg).unwrap_or_default();
        if det.start_argv.is_empty() {
            return Err(Error::Config(
                "could not derive an argv-only start command; set CITE_START_COMMAND".into(),
            ));
        }
        return Ok(det.with_pm(repo_dir, pm, node_major));
    }
    Err(Error::Config(
        "ambiguous site; set CITE_RENDERING (static or ssr)".into(),
    ))
}

fn start_script_argv(pkg: &PackageJson) -> Option<Vec<String>> {
    let argv = crate::argv::split_command(script(pkg, "start")?).ok()?;
    crate::argv::validate_start_argv(&argv).ok()?;
    Some(argv)
}

fn static_detection(
    framework: &str,
    output: &str,
    spa: Option<&str>,
    confidence: f32,
) -> Detection {
    Detection {
        framework: framework.into(),
        rendering: Rendering::Static,
        package_manager: "npm".into(),
        node_major: None,
        output_dir: output.into(),
        install_command: "npm ci".into(),
        build_command: "npm run build".into(),
        start_argv: Vec::new(),
        spa_fallback: spa.map(str::to_string),
        confidence,
        warnings: Vec::new(),
        pack_output_only: true,
    }
}

fn ssr(framework: &str, build_suffix: &str, start_argv: Vec<String>) -> Detection {
    let build_command = if build_suffix.is_empty() {
        "npm run build".into()
    } else if framework == "next" {
        build_suffix.into()
    } else {
        format!("npm run build && {build_suffix}")
    };
    Detection {
        framework: framework.into(),
        rendering: Rendering::Ssr,
        package_manager: "npm".into(),
        node_major: None,
        output_dir: ".".into(),
        install_command: "npm ci".into(),
        build_command,
        start_argv,
        spa_fallback: None,
        confidence: 0.85,
        warnings: Vec::new(),
        pack_output_only: false,
    }
}

impl Detection {
    fn with_pm(mut self, dir: &Dir, pm: &Pm, node_major: Option<String>) -> Self {
        self.package_manager = pm.name.clone();
        self.node_major = node_major;
        if self.framework == "next" {
            self.build_command = build_with_pm(&pm.name, &self.build_command);
        } else {
            self.build_command = format!("{} run build", pm.name);
        }
        self.install_command = install_command(pm, dir);
        self
    }
}

/// The resolved package manager; `berry` only matters for yarn 2 and newer.
#[derive(Debug, Clone, PartialEq)]
struct Pm {
    name: String,
    berry: bool,
}

fn build_with_pm(pm: &str, npm_command: &str) -> String {
    npm_command.replace("npm run build", &format!("{pm} run build"))
}

fn install_command(pm: &Pm, dir: &Dir) -> String {
    match pm.name.as_str() {
        "pnpm" if dir.is_file("pnpm-lock.yaml") => "pnpm install --frozen-lockfile".into(),
        "pnpm" => "pnpm install".into(),
        "yarn" if !dir.is_file("yarn.lock") => "yarn install".into(),
        "yarn" if pm.berry => "yarn install --immutable".into(),
        "yarn" => "yarn install --frozen-lockfile".into(),
        "bun" if dir.is_file("bun.lock") || dir.is_file("bun.lockb") => {
            "bun install --frozen-lockfile".into()
        }
        "bun" => "bun install".into(),
        _ if dir.is_file("package-lock.json") || dir.is_file("npm-shrinkwrap.json") => {
            "npm ci".into()
        }
        _ => "npm install".into(),
    }
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
    pkg: &PackageJson,
    explicit: Option<&str>,
    warnings: &mut Vec<String>,
) -> Pm {
    let field = pkg.package_manager.as_deref().and_then(|field| {
        let (name, version) = field.split_once('@').unwrap_or((field, ""));
        matches!(name, "pnpm" | "bun" | "npm" | "yarn").then(|| (name.to_string(), version))
    });
    let (name, reason) = if let Some(name) = explicit.filter(|name| *name != "auto") {
        (name.to_string(), "CITE_PACKAGE_MANAGER")
    } else if let Some((name, _)) = &field {
        (name.clone(), "the packageManager field in package.json")
    } else if let Some(name) = lockfile_manager(dir) {
        (name.to_string(), "lockfile precedence pnpm, yarn, bun, npm")
    } else {
        ("npm".to_string(), "no lockfile found")
    };
    let found: Vec<&str> = LOCKFILES
        .iter()
        .copied()
        .filter(|name| dir.exists(name))
        .collect();
    if found.len() > 1 {
        warnings.push(format!(
            "multiple lockfiles found ({}); using {name} because of {reason}",
            found.join(", ")
        ));
    }
    let berry = dir.is_file(".yarnrc.yml")
        || field.as_ref().is_some_and(|(field_name, version)| {
            field_name == "yarn"
                && leading_major(version).is_some_and(|major| major != "1" && major != "0")
        });
    Pm { name, berry }
}

fn lockfile_manager(dir: &Dir) -> Option<&'static str> {
    if dir.exists("pnpm-lock.yaml") {
        Some("pnpm")
    } else if dir.exists("yarn.lock") {
        Some("yarn")
    } else if dir.exists("bun.lock") || dir.exists("bun.lockb") {
        Some("bun")
    } else if dir.exists("package-lock.json") || dir.exists("npm-shrinkwrap.json") {
        Some("npm")
    } else {
        None
    }
}

fn node_major(dir: &Dir, pkg: &PackageJson, warnings: &mut Vec<String>) -> Option<String> {
    for name in [".nvmrc", ".node-version"] {
        let Some(text) = read_optional(dir, name) else {
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
            return Some(major);
        }
        warnings.push(format!(
            "{name} is not a numeric version (version aliases are unsupported); ignoring it"
        ));
    }
    pkg.engines
        .as_ref()
        .and_then(|engines| engines.node.as_deref())
        .and_then(leading_major)
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

fn dep_names(pkg: &PackageJson) -> Vec<String> {
    let mut names = Vec::new();
    for value in [&pkg.dependencies, &pkg.dev_dependencies] {
        if let Some(map) = value.as_object() {
            names.extend(map.keys().cloned());
        }
    }
    names
}

fn script<'a>(pkg: &'a PackageJson, name: &str) -> Option<&'a str> {
    pkg.scripts.get(name).and_then(Value::as_str)
}

fn config_contains(dir: &Dir, files: &[&str], needles: &[&str]) -> bool {
    files.iter().any(|name| {
        read_optional(dir, name)
            .is_some_and(|text| needles.iter().any(|needle| text.contains(needle)))
    })
}

fn angular_project(dir: &Dir) -> Option<String> {
    let text = read_optional(dir, "angular.json")?;
    let value: Value = serde_json::from_str(&text).ok()?;
    value.get("projects")?.as_object()?.keys().next().cloned()
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
    Ok(Detection {
        framework: "rust".into(),
        rendering: Rendering::Ssr,
        package_manager: "cargo".into(),
        node_major: None,
        output_dir: ".".into(),
        install_command,
        build_command,
        start_argv: vec![format!("bin/{name}")],
        spa_fallback: None,
        confidence: 0.9,
        warnings,
        pack_output_only: false,
    })
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
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn site(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempdir().unwrap();
        for (name, body) in files {
            let path = dir.path().join(name);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, body).unwrap();
        }
        dir
    }

    #[test]
    fn detects_vite_pnpm_and_node() {
        let dir = site(&[
            (
                "package.json",
                r#"{"dependencies":{"vite":"^6","react":"^19"},"scripts":{"build":"vite build"}}"#,
            ),
            ("pnpm-lock.yaml", "lockfileVersion: 9\n"),
            (".nvmrc", "22\n"),
        ]);
        let det = detect_site(dir.path()).unwrap();
        assert_eq!(det.framework, "vite");
        assert_eq!(det.rendering, Rendering::Static);
        assert_eq!(det.output_dir, "dist");
        assert_eq!(det.spa_fallback.as_deref(), Some("index.html"));
        assert_eq!(det.package_manager, "pnpm");
        assert_eq!(det.node_major.as_deref(), Some("22"));
        assert_eq!(det.install_command, "pnpm install --frozen-lockfile");
    }

    #[test]
    fn detects_next_astro_nuxt() {
        let next = site(&[(
            "package.json",
            r#"{"dependencies":{"next":"15.0.0"},"scripts":{"build":"next build"}}"#,
        )]);
        let det = detect_site(next.path()).unwrap();
        assert_eq!(det.framework, "next");
        assert_eq!(det.rendering, Rendering::Ssr);
        assert_eq!(det.start_argv, vec!["next", "start", "-H", "127.0.0.1"]);
        assert_eq!(det.build_command, "npm run build");

        let standalone = site(&[
            (
                "package.json",
                r#"{"dependencies":{"next":"15.0.0"},"scripts":{"build":"next build"}}"#,
            ),
            (
                "next.config.ts",
                "const nextConfig = { output: 'standalone' };\nexport default nextConfig;\n",
            ),
        ]);
        let det = detect_site(standalone.path()).unwrap();
        assert_eq!(det.start_argv, vec!["node", ".next/standalone/server.js"]);
        assert!(det.build_command.contains(".next/standalone"));

        let astro = site(&[(
            "package.json",
            r#"{"dependencies":{"astro":"5.0.0","@astrojs/node":"9.0.0"}}"#,
        )]);
        let det = detect_site(astro.path()).unwrap();
        assert_eq!(det.rendering, Rendering::Ssr);
        assert_eq!(det.start_argv[1], "dist/server/entry.mjs");

        let nuxt = site(&[("package.json", r#"{"dependencies":{"nuxt":"3.0.0"}}"#)]);
        assert_eq!(
            detect_site(nuxt.path()).unwrap().start_argv[1],
            ".output/server/index.mjs"
        );
    }

    const NEXT_STANDALONE: [(&str, &str); 2] = [
        (
            "package.json",
            r#"{"dependencies":{"next":"15.0.0"},"scripts":{"build":"next build"}}"#,
        ),
        (
            "next.config.ts",
            "export default { output: 'standalone' };\n",
        ),
    ];

    fn next_with(extra: &[(&str, &str)]) -> tempfile::TempDir {
        let mut files = NEXT_STANDALONE.to_vec();
        files.extend_from_slice(extra);
        site(&files)
    }

    #[test]
    fn explicit_package_manager_drives_install_and_build() {
        let dir = next_with(&[("pnpm-lock.yaml", "lockfileVersion: 9\n")]);
        let auto = detect_site(dir.path()).unwrap();
        assert!(auto.build_command.starts_with("pnpm run build && "));
        for choice in [None, Some("auto")] {
            let det = detect_site_with(dir.path(), choice).unwrap();
            assert_eq!(det.package_manager, "pnpm");
        }
        let det = detect_site_with(dir.path(), Some("npm")).unwrap();
        assert_eq!(det.package_manager, "npm");
        assert!(det.build_command.starts_with("npm run build && "));
        assert!(!det.build_command.contains("pnpm"));
        assert_eq!(det.install_command, "npm install");
        assert!(det.warnings.is_empty());

        let det = detect_site_with(dir.path(), Some("yarn")).unwrap();
        assert!(det.build_command.starts_with("yarn run build && "));
        assert_eq!(det.install_command, "yarn install");
    }

    #[test]
    fn explicit_package_manager_drives_non_next_presets() {
        let dir = site(&[
            ("package.json", r#"{"dependencies":{"vite":"^6"}}"#),
            ("package-lock.json", "{}"),
        ]);
        let det = detect_site_with(dir.path(), Some("bun")).unwrap();
        assert_eq!(det.build_command, "bun run build");
        assert_eq!(det.install_command, "bun install");
    }

    #[test]
    fn multiple_lockfiles_warn_with_the_winner_and_reason() {
        let dir = next_with(&[
            ("pnpm-lock.yaml", "x"),
            ("package-lock.json", "{}"),
            ("yarn.lock", "x"),
        ]);
        let det = detect_site(dir.path()).unwrap();
        assert_eq!(det.warnings.len(), 1);
        let warning = &det.warnings[0];
        for needle in [
            "pnpm-lock.yaml",
            "package-lock.json",
            "yarn.lock",
            "using pnpm",
            "lockfile precedence",
        ] {
            assert!(warning.contains(needle), "{warning}");
        }
        let det = detect_site_with(dir.path(), Some("npm")).unwrap();
        assert!(det.warnings[0].contains("using npm because of CITE_PACKAGE_MANAGER"));

        let single = next_with(&[("yarn.lock", "x")]);
        assert!(detect_site(single.path()).unwrap().warnings.is_empty());
    }

    #[test]
    fn package_manager_field_outranks_lockfiles() {
        let dir = site(&[
            (
                "package.json",
                r#"{"packageManager":"npm@10.0.0","dependencies":{"vite":"^6"}}"#,
            ),
            ("pnpm-lock.yaml", "x"),
            ("bun.lockb", "x"),
        ]);
        let det = detect_site(dir.path()).unwrap();
        assert_eq!(det.package_manager, "npm");
        assert!(det.warnings[0].contains("packageManager field"));
    }

    #[test]
    fn lockfile_precedence_is_pnpm_yarn_bun_npm() {
        let pm = |files: &[(&str, &str)]| {
            let mut all = vec![("package.json", r#"{"dependencies":{"vite":"^6"}}"#)];
            all.extend_from_slice(files);
            detect_site(site(&all).path()).unwrap().package_manager
        };
        assert_eq!(
            pm(&[("pnpm-lock.yaml", ""), ("yarn.lock", ""), ("bun.lock", "")]),
            "pnpm"
        );
        assert_eq!(
            pm(&[
                ("yarn.lock", ""),
                ("bun.lock", ""),
                ("package-lock.json", "")
            ]),
            "yarn"
        );
        assert_eq!(pm(&[("bun.lock", ""), ("package-lock.json", "")]), "bun");
        assert_eq!(pm(&[("npm-shrinkwrap.json", "")]), "npm");
        assert_eq!(pm(&[]), "npm");
    }

    #[test]
    fn shrinkwrap_is_npm_ci() {
        let dir = site(&[
            ("package.json", r#"{"dependencies":{"vite":"^6"}}"#),
            ("npm-shrinkwrap.json", "{}"),
        ]);
        let det = detect_site(dir.path()).unwrap();
        assert_eq!(det.package_manager, "npm");
        assert_eq!(det.install_command, "npm ci");
    }

    #[test]
    fn yarn_classic_and_berry() {
        let classic = next_with(&[("yarn.lock", "# yarn lockfile v1\n")]);
        let det = detect_site(classic.path()).unwrap();
        assert_eq!(det.package_manager, "yarn");
        assert_eq!(det.install_command, "yarn install --frozen-lockfile");
        assert!(det.build_command.starts_with("yarn run build && "));

        let rc = next_with(&[
            ("yarn.lock", "x"),
            (".yarnrc.yml", "nodeLinker: node-modules\n"),
        ]);
        assert_eq!(
            detect_site(rc.path()).unwrap().install_command,
            "yarn install --immutable"
        );

        let field = |version: &str| {
            let json =
                format!(r#"{{"packageManager":"yarn@{version}","dependencies":{{"vite":"^6"}}}}"#);
            let dir = site(&[("package.json", json.as_str()), ("yarn.lock", "x")]);
            detect_site(dir.path()).unwrap().install_command
        };
        assert_eq!(field("4.1.0+sha256.abc"), "yarn install --immutable");
        assert_eq!(field("2.4.3"), "yarn install --immutable");
        assert_eq!(field("1.22.22"), "yarn install --frozen-lockfile");

        let det = detect_site_with(classic.path(), Some("yarn")).unwrap();
        assert_eq!(det.package_manager, "yarn");
    }

    #[test]
    fn node_version_files_accept_v_prefix_and_ignore_aliases() {
        let major = |name: &str, body: &str| {
            let dir = site(&[
                (
                    "package.json",
                    r#"{"dependencies":{"vite":"^6"},"engines":{"node":">=18"}}"#,
                ),
                (name, body),
            ]);
            detect_site(dir.path()).unwrap()
        };
        assert_eq!(
            major(".nvmrc", "v20.11.1\n").node_major.as_deref(),
            Some("20")
        );
        assert_eq!(
            major(".node-version", "v22\n").node_major.as_deref(),
            Some("22")
        );
        assert_eq!(
            major(".nvmrc", "# pinned\n21.x\n").node_major.as_deref(),
            Some("21")
        );
        for alias in ["lts/*", "lts/iron", "lts/-1", "node", "latest"] {
            let det = major(".nvmrc", alias);
            assert_eq!(det.node_major.as_deref(), Some("18"), "{alias}");
            assert!(det.warnings.iter().any(|w| w.contains(".nvmrc")), "{alias}");
            assert!(det.warnings.iter().all(|w| !w.contains(alias)), "{alias}");
        }
        assert_eq!(major(".nvmrc", "").node_major.as_deref(), Some("18"));
    }

    #[test]
    fn ssr_presets_start_entries() {
        let entry = |deps: &str| {
            let json = format!(r#"{{"dependencies":{deps}}}"#);
            detect_site(site(&[("package.json", json.as_str())]).path())
                .unwrap()
                .start_argv
        };
        assert_eq!(
            entry(r#"{"@sveltejs/kit":"2"}"#),
            ["node", "build/index.js"]
        );
        assert_eq!(
            entry(r#"{"nuxt":"3"}"#),
            ["node", ".output/server/index.mjs"]
        );
        assert_eq!(
            entry(r#"{"astro":"5","@astrojs/node":"9"}"#),
            ["node", "dist/server/entry.mjs"]
        );
    }

    #[test]
    fn explicit_rendering_rescues_frameworkless_sites() {
        let dir = site(&[
            ("package.json", r#"{"scripts":{"build":"node build.js"}}"#),
            ("pnpm-lock.yaml", "x"),
        ]);
        assert!(detect_site(dir.path()).is_err());
        let det = detect_site_configured(dir.path(), None, Some(Rendering::Static)).unwrap();
        assert_eq!(det.framework, "generic-static");
        assert_eq!(det.rendering, Rendering::Static);
        assert_eq!(det.build_command, "pnpm run build");
        assert_eq!(det.install_command, "pnpm install --frozen-lockfile");
        let det = detect_site_configured(dir.path(), Some("npm"), Some(Rendering::Static)).unwrap();
        assert_eq!(det.build_command, "npm run build");

        let nobuild = site(&[("package.json", r#"{"name":"x"}"#)]);
        let det = detect_site_configured(nobuild.path(), None, Some(Rendering::Static)).unwrap();
        assert_eq!(det.build_command, "true");

        let det = detect_site_configured(dir.path(), None, Some(Rendering::Ssr)).unwrap();
        assert_eq!(det.framework, "generic-node");
        assert_eq!(det.rendering, Rendering::Ssr);
        assert!(det.start_argv.is_empty());

        let started = site(&[("package.json", r#"{"scripts":{"start":"node server.js"}}"#)]);
        let det = detect_site_configured(started.path(), None, Some(Rendering::Ssr)).unwrap();
        assert_eq!(det.start_argv, ["node", "server.js"]);
        let shell = site(&[("package.json", r#"{"scripts":{"start":"a && b"}}"#)]);
        assert!(detect_site(shell.path()).is_err());
        let det = detect_site_configured(shell.path(), None, Some(Rendering::Ssr)).unwrap();
        assert!(det.start_argv.is_empty());
    }

    #[test]
    fn explicit_rendering_does_not_change_recognised_frameworks() {
        let dir = site(&[("package.json", r#"{"dependencies":{"vite":"^6"}}"#)]);
        let det = detect_site_configured(dir.path(), None, Some(Rendering::Ssr)).unwrap();
        assert_eq!(det.framework, "vite");
    }

    #[test]
    fn detection_reads_do_not_follow_symlinks_out_of_the_repo() {
        let outside = site(&[
            ("secret.json", r#"{"dependencies":{"vite":"^6"}}"#),
            ("version", "99\n"),
        ]);
        let repo = site(&[("package.json", r#"{"dependencies":{"vite":"^6"}}"#)]);
        std::os::unix::fs::symlink(outside.path().join("version"), repo.path().join(".nvmrc"))
            .unwrap();
        let det = detect_site(repo.path()).unwrap();
        assert_eq!(det.node_major, None);

        let linked = site(&[]);
        std::os::unix::fs::symlink(
            outside.path().join("secret.json"),
            linked.path().join("package.json"),
        )
        .unwrap();
        assert!(detect_site(linked.path()).is_err());
    }

    #[test]
    fn ambiguous_without_framework() {
        let dir = site(&[("package.json", r#"{"name":"x"}"#)]);
        let err = detect_site(dir.path()).unwrap_err();
        assert!(err.to_string().contains("CITE_RENDERING"));
    }

    #[test]
    fn detects_a_cargo_package_and_keeps_hyphens() {
        let locked = site(&[
            (
                "Cargo.toml",
                "[package]\nname = \"my-app\"\nversion = \"0.1.0\"\n",
            ),
            ("Cargo.lock", ""),
        ]);
        let det = detect_site(locked.path()).unwrap();
        assert_eq!(det.framework, "rust");
        assert_eq!(det.rendering, Rendering::Ssr);
        assert_eq!(det.package_manager, "cargo");
        assert_eq!(det.node_major, None);
        assert_eq!(det.output_dir, ".");
        assert!(!det.pack_output_only);
        assert_eq!(det.install_command, "cargo fetch --locked");
        assert!(
            det.build_command.contains("--release"),
            "{}",
            det.build_command
        );
        assert!(
            det.build_command.contains("--locked"),
            "{}",
            det.build_command
        );
        assert_eq!(det.start_argv, ["bin/my-app"]);
        assert!((det.confidence - 0.9).abs() < f32::EPSILON);
        assert!(det.warnings.is_empty());

        let unlocked = site(&[("Cargo.toml", "[package]\nname = \"my-app\"\n")]);
        let det = detect_site(unlocked.path()).unwrap();
        assert_eq!(det.build_command, "cargo build --release");
        assert_eq!(det.install_command, "cargo fetch");
        assert!(det.warnings.iter().any(|w| w.contains("Cargo.lock")));

        let html = site(&[("index.html", "<html></html>\n")]);
        assert_eq!(
            detect_site(html.path()).unwrap().rendering,
            Rendering::Static
        );

        let both = site(&[
            ("package.json", r#"{"dependencies":{"vite":"^6"}}"#),
            ("Cargo.toml", "[package]\nname = \"my-app\"\n"),
        ]);
        let det = detect_site(both.path()).unwrap();
        assert_eq!(det.framework, "vite");
        assert_ne!(det.package_manager, "cargo");
        assert_eq!(detect_rust_site(both.path()).unwrap().framework, "rust");
        assert_eq!(
            detect_rust_site(both.path()).unwrap().start_argv,
            ["bin/my-app"]
        );
    }

    #[test]
    fn rust_bin_name_prefers_bin_table_then_workspace_member() {
        let named = site(&[(
            "Cargo.toml",
            "[package]\nname = \"my-app\"\n\n[[bin]]\nname = \"serve\"\n",
        )]);
        assert_eq!(detect_site(named.path()).unwrap().start_argv, ["bin/serve"]);

        let workspace = site(&[
            ("Cargo.toml", "[workspace]\nmembers = [\"server\"]\n"),
            ("server/Cargo.toml", "[package]\nname = \"api\"\n"),
        ]);
        assert_eq!(
            detect_site(workspace.path()).unwrap().start_argv,
            ["bin/api"]
        );

        let preferred = site(&[
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"other\", \"server\"]\ndefault-members = [\"server\"]\n",
            ),
            ("other/Cargo.toml", "[package]\nname = \"other\"\n"),
            ("server/Cargo.toml", "[package]\nname = \"api\"\n"),
        ]);
        assert_eq!(
            detect_rust_site(preferred.path()).unwrap().start_argv,
            ["bin/api"]
        );

        let escaped = site(&[("Cargo.toml", "[workspace]\nmembers = [\"../x\"]\n")]);
        let err = detect_site(escaped.path()).unwrap_err();
        assert!(err.to_string().contains(".."), "{err}");

        let unnamed = site(&[("Cargo.toml", "[workspace]\nmembers = []\n")]);
        let err = detect_site(unnamed.path()).unwrap_err();
        assert!(err.to_string().contains("CITE_START_COMMAND"), "{err}");
    }
}
