use std::fs;
use std::path::Path;

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
    let manifest = repo_dir.join("package.json");
    if !manifest.is_file() {
        if repo_dir.join("index.html").is_file() {
            return Ok(static_detection("generic-static", ".", None, 0.4));
        }
        return Err(Error::Config(
            "no package.json or index.html; set CITE_RENDERING and CITE_OUTPUT_DIR".into(),
        ));
    }
    let text = read_capped(&manifest, 1_048_576)?;
    let pkg: PackageJson =
        serde_json::from_str(&text).map_err(|err| Error::Config(format!("package.json: {err}")))?;
    let pm = package_manager(repo_dir, &pkg);
    let node_major = node_major(repo_dir, &pkg);
    let deps = dep_names(&pkg);
    let has = |name: &str| deps.iter().any(|dep| dep == name);

    if has("next") {
        let export = config_contains(
            repo_dir,
            &["next.config.js", "next.config.mjs", "next.config.ts"],
            &["output: 'export'", "output: \"export\""],
        );
        if export {
            return Ok(
                static_detection("next", "out", None, 0.9).with_pm(repo_dir, &pm, node_major)
            );
        }
        let mut det = ssr(
            "next",
            "npm run build && mkdir -p .next/standalone/.next && cp -R .next/static .next/standalone/.next/static && (cp -R public .next/standalone/public || true)",
            vec!["node".into(), ".next/standalone/server.js".into()],
        );
        det.install_command = install_command(&pm, repo_dir);
        det.build_command = build_with_pm(&pm, &det.build_command);
        det.package_manager = pm;
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
                .with_pm(repo_dir, &pm, node_major));
        }
        return Ok(ssr(
            "nuxt",
            "",
            vec!["node".into(), ".output/server/index.mjs".into()],
        )
        .with_pm(repo_dir, &pm, node_major));
    }
    if has("@sveltejs/kit") {
        if has("@sveltejs/adapter-static") {
            return Ok(static_detection("sveltekit", "build", None, 0.85)
                .with_pm(repo_dir, &pm, node_major));
        }
        return Ok(ssr(
            "sveltekit",
            "",
            vec!["node".into(), "build/index.js".into()],
        )
        .with_pm(repo_dir, &pm, node_major));
    }
    if has("astro") {
        if has("@astrojs/node") {
            return Ok(ssr(
                "astro",
                "",
                vec!["node".into(), "dist/server/entry.mjs".into()],
            )
            .with_pm(repo_dir, &pm, node_major));
        }
        return Ok(static_detection("astro", "dist", None, 0.9).with_pm(repo_dir, &pm, node_major));
    }
    if has("@angular/core") {
        let project = angular_project(repo_dir).unwrap_or_else(|| "app".into());
        if has("@angular/ssr") || has("@angular/platform-server") {
            return Ok(ssr(
                "angular",
                "",
                vec!["node".into(), format!("dist/{project}/server/server.mjs")],
            )
            .with_pm(repo_dir, &pm, node_major));
        }
        return Ok(static_detection(
            "angular",
            &format!("dist/{project}/browser"),
            Some("index.html"),
            0.8,
        )
        .with_pm(repo_dir, &pm, node_major));
    }
    if has("react-router") || has("@react-router/node") || has("@react-router/serve") {
        return Ok(ssr(
            "remix",
            "",
            vec!["react-router-serve".into(), "build/server/index.js".into()],
        )
        .with_pm(repo_dir, &pm, node_major));
    }
    if has("@remix-run/node") || has("@remix-run/serve") {
        return Ok(ssr(
            "remix",
            "",
            vec!["remix-serve".into(), "build/index.js".into()],
        )
        .with_pm(repo_dir, &pm, node_major));
    }
    if has("@docusaurus/core") {
        return Ok(
            static_detection("docusaurus", "build", None, 0.9).with_pm(repo_dir, &pm, node_major)
        );
    }
    if has("vitepress") {
        return Ok(static_detection("vitepress", ".vitepress/dist", None, 0.9)
            .with_pm(repo_dir, &pm, node_major));
    }
    if has("@11ty/eleventy") {
        return Ok(
            static_detection("eleventy", "_site", None, 0.9).with_pm(repo_dir, &pm, node_major)
        );
    }
    if has("gatsby") {
        return Ok(
            static_detection("gatsby", "public", None, 0.85).with_pm(repo_dir, &pm, node_major)
        );
    }
    if has("vite") {
        return Ok(static_detection("vite", "dist", Some("index.html"), 0.8)
            .with_pm(repo_dir, &pm, node_major));
    }
    if script(&pkg, "start").is_some() {
        let mut det = ssr("generic-node", "", Vec::new());
        if let Some(start) = script(&pkg, "start")
            && let Ok(argv) = crate::argv::split_command(start)
            && crate::argv::validate_start_argv(&argv).is_ok()
        {
            det.start_argv = argv;
        }
        if det.start_argv.is_empty() {
            return Err(Error::Config(
                "could not derive an argv-only start command; set CITE_START_COMMAND".into(),
            ));
        }
        return Ok(det.with_pm(repo_dir, &pm, node_major));
    }
    Err(Error::Config(
        "ambiguous site; set CITE_RENDERING (static or ssr)".into(),
    ))
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
        pack_output_only: false,
    }
}

impl Detection {
    fn with_pm(mut self, dir: &Path, pm: &str, node_major: Option<String>) -> Self {
        self.package_manager = pm.into();
        self.node_major = node_major;
        if self.framework == "next" {
            self.build_command = build_with_pm(pm, &self.build_command);
        } else {
            self.build_command = format!("{pm} run build");
        }
        self.install_command = install_command(pm, dir);
        self
    }
}

fn build_with_pm(pm: &str, npm_command: &str) -> String {
    npm_command.replace("npm run build", &format!("{pm} run build"))
}

fn install_command(pm: &str, dir: &Path) -> String {
    match pm {
        "pnpm" if dir.join("pnpm-lock.yaml").is_file() => "pnpm install --frozen-lockfile".into(),
        "pnpm" => "pnpm install".into(),
        "bun" if dir.join("bun.lock").is_file() || dir.join("bun.lockb").is_file() => {
            "bun install --frozen-lockfile".into()
        }
        "bun" => "bun install".into(),
        _ if dir.join("package-lock.json").is_file()
            || dir.join("npm-shrinkwrap.json").is_file() =>
        {
            "npm ci".into()
        }
        _ => "npm install".into(),
    }
}

fn package_manager(dir: &Path, pkg: &PackageJson) -> String {
    if let Some(field) = &pkg.package_manager
        && let Some(name) = field.split('@').next()
        && matches!(name, "pnpm" | "bun" | "npm")
    {
        return name.to_string();
    }
    if dir.join("pnpm-lock.yaml").exists() {
        return "pnpm".into();
    }
    if dir.join("bun.lock").exists() || dir.join("bun.lockb").exists() {
        return "bun".into();
    }
    "npm".into()
}

fn node_major(dir: &Path, pkg: &PackageJson) -> Option<String> {
    for name in [".nvmrc", ".node-version"] {
        if let Ok(text) = fs::read_to_string(dir.join(name))
            && let Some(major) = leading_major(text.trim().trim_start_matches('v'))
        {
            return Some(major);
        }
    }
    pkg.engines
        .as_ref()
        .and_then(|engines| engines.node.as_deref())
        .and_then(leading_major)
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

fn config_contains(dir: &Path, files: &[&str], needles: &[&str]) -> bool {
    files.iter().any(|name| {
        fs::read_to_string(dir.join(name))
            .ok()
            .is_some_and(|text| needles.iter().any(|needle| text.contains(needle)))
    })
}

fn angular_project(dir: &Path) -> Option<String> {
    let text = fs::read_to_string(dir.join("angular.json")).ok()?;
    let value: Value = serde_json::from_str(&text).ok()?;
    value.get("projects")?.as_object()?.keys().next().cloned()
}

fn read_capped(path: &Path, max: u64) -> Result<String> {
    let meta = fs::metadata(path)?;
    if meta.len() > max {
        return Err(Error::TooLarge {
            len: meta.len(),
            max,
        });
    }
    let bytes = fs::read(path)?;
    String::from_utf8(bytes).map_err(|err| Error::msg(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert_eq!(det.start_argv, vec!["node", ".next/standalone/server.js"]);

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

    #[test]
    fn ambiguous_without_framework() {
        let dir = site(&[("package.json", r#"{"name":"x"}"#)]);
        let err = detect_site(dir.path()).unwrap_err();
        assert!(err.to_string().contains("CITE_RENDERING"));
    }
}
