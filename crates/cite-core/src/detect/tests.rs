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

fn detect(files: &[(&str, &str)]) -> Detection {
    detect_site(site(files).path()).unwrap()
}

#[test]
fn detects_vite_pnpm_and_node() {
    let dir = site(&[
        (
            "package.json",
            r#"{"dependencies":{"vite":"^6","react":"^19"},"scripts":{"build":"vite build"}}"#,
        ),
        ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n"),
        (".nvmrc", "22\n"),
    ]);
    let det = detect_site(dir.path()).unwrap();
    assert_eq!(det.framework, "vite");
    assert_eq!(det.rendering, Rendering::Static);
    assert_eq!(det.output_dir, "dist");
    assert_eq!(det.spa_fallback.as_deref(), Some("index.html"));
    assert_eq!(det.package_manager, "pnpm");
    assert_eq!(det.node_major.as_deref(), Some("22"));
    assert!(det.node_exact);
    assert_eq!(det.install_command, "pnpm install --frozen-lockfile");
    assert_eq!(det.build_command, "pnpm run build");
    assert!(det.notes.is_empty(), "{:?}", det.notes);
}

#[test]
fn next_default_server_runs_next_start_through_node() {
    let det = detect(&[
        (
            "package.json",
            r#"{"dependencies":{"next":"15.0.0","react":"19"},"scripts":{"build":"next build","start":"next start -p 3000"}}"#,
        ),
        ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n"),
    ]);
    assert_eq!(det.framework, "next");
    assert_eq!(det.rendering, Rendering::Ssr);
    assert_eq!(det.package_manager, "pnpm");
    assert_eq!(det.install_command, "pnpm install --frozen-lockfile");
    assert_eq!(det.build_command, "pnpm run build");
    assert_eq!(
        det.start_argv,
        [
            "node",
            "node_modules/next/dist/bin/next",
            "start",
            "-H",
            "127.0.0.1"
        ]
    );
    assert_eq!(
        det.start_bin,
        Some(StartBin {
            package: "next".into(),
            bin: "next".into()
        })
    );
    assert_eq!(det.next_dist_dir.as_deref(), Some(".next"));
    assert_eq!(det.ssr_root, None);
    assert!(!det.pack_output_only);
    assert!(validate_start_argv(&det.start_argv).is_ok());
}

#[test]
fn next_standalone_export_dist_dir_and_comments() {
    let standalone = detect(&[
        (
            "package.json",
            r#"{"dependencies":{"next":"15.0.0"},"scripts":{"build":"next build"}}"#,
        ),
        (
            "next.config.ts",
            "const nextConfig = {\n  // output: 'export',\n  output: 'standalone',\n  distDir: 'build',\n};\nexport default nextConfig;\n",
        ),
    ]);
    assert_eq!(standalone.rendering, Rendering::Ssr);
    assert_eq!(standalone.start_argv, ["node", "server.js"]);
    assert_eq!(standalone.ssr_root.as_deref(), Some("build/standalone"));
    assert_eq!(standalone.next_dist_dir.as_deref(), Some("build"));
    assert_eq!(standalone.build_command, "npm run build");
    assert_eq!(standalone.start_bin, None);

    let export = detect(&[
        (
            "package.json",
            r#"{"dependencies":{"next":"14"},"scripts":{"build":"next build"}}"#,
        ),
        (
            "next.config.mjs",
            "export default { output: \"export\", basePath: '/docs' };\n",
        ),
    ]);
    assert_eq!(export.rendering, Rendering::Static);
    assert_eq!(export.output_dir, "out");
    assert!(export.pack_output_only);
    assert!(export.notes.iter().any(|n| n.contains("basePath /docs")));

    let legacy = detect(&[(
        "package.json",
        r#"{"dependencies":{"next":"13"},"scripts":{"build":"next build && next export"}}"#,
    )]);
    assert_eq!(legacy.rendering, Rendering::Static);
    assert_eq!(legacy.output_dir, "out");

    let expression = detect(&[
        ("package.json", r#"{"dependencies":{"next":"15"}}"#),
        (
            "next.config.js",
            "module.exports = { output: process.env.NEXT_OUTPUT };\n",
        ),
    ]);
    assert_eq!(expression.rendering, Rendering::Ssr);
    assert_eq!(expression.build_command, "npm exec -- next build");
    assert!(expression.confidence <= 0.7);
    assert!(expression.notes.iter().any(|n| n.contains("expression")));
}

#[test]
fn next_custom_node_server_is_kept() {
    let det = detect(&[(
        "package.json",
        r#"{"dependencies":{"next":"15","express":"4"},"scripts":{"build":"next build","start":"NODE_ENV=production node server.js"}}"#,
    )]);
    assert_eq!(det.start_argv, ["node", "server.js"]);
    assert_eq!(det.start_bin, None);
    assert!(det.notes.is_empty(), "{:?}", det.notes);
}

#[test]
fn nuxt_server_and_static_generation() {
    let server = detect(&[(
        "package.json",
        r#"{"dependencies":{"nuxt":"^3.12.0"},"scripts":{"build":"nuxt build"}}"#,
    )]);
    assert_eq!(server.framework, "nuxt");
    assert_eq!(server.rendering, Rendering::Ssr);
    assert_eq!(server.ssr_root.as_deref(), Some(".output"));
    assert_eq!(server.start_argv, ["node", "server/index.mjs"]);
    assert_eq!(server.build_command, "npm run build");

    let generated = detect(&[(
        "package.json",
        r#"{"dependencies":{"nuxt":"3"},"scripts":{"build":"nuxt build","generate":"nuxt generate"}}"#,
    ), ("nuxt.config.ts", "export default defineNuxtConfig({ ssr: false })\n")]);
    assert_eq!(generated.rendering, Rendering::Static);
    assert_eq!(generated.output_dir, ".output/public");
    assert_eq!(generated.build_command, "npm run generate");
    assert_eq!(generated.spa_fallback.as_deref(), Some("index.html"));

    let generate_build = detect(&[(
        "package.json",
        r#"{"devDependencies":{"nuxt":"3"},"scripts":{"build":"nuxt generate"}}"#,
    )]);
    assert_eq!(generate_build.rendering, Rendering::Static);
    assert_eq!(generate_build.build_command, "npm run build");
    assert_eq!(generate_build.spa_fallback, None);
}

#[test]
fn sveltekit_adapters() {
    let node = detect(&[
        (
            "package.json",
            r#"{"devDependencies":{"@sveltejs/kit":"2","@sveltejs/adapter-node":"5"},"scripts":{"build":"vite build"}}"#,
        ),
        (
            "svelte.config.js",
            "import adapter from '@sveltejs/adapter-node';\nexport default { kit: { adapter: adapter({ out: 'server-build' }) } };\n",
        ),
    ]);
    assert_eq!(node.rendering, Rendering::Ssr);
    assert_eq!(node.start_argv, ["node", "server-build/index.js"]);
    assert!(node.notes.is_empty(), "{:?}", node.notes);

    let static_site = detect(&[
        (
            "package.json",
            r#"{"devDependencies":{"@sveltejs/kit":"2","@sveltejs/adapter-static":"3"}}"#,
        ),
        (
            "svelte.config.js",
            "import adapter from '@sveltejs/adapter-static';\nexport default { kit: { adapter: adapter({ fallback: '200.html' }) } };\n",
        ),
    ]);
    assert_eq!(static_site.rendering, Rendering::Static);
    assert_eq!(static_site.output_dir, "build");
    assert_eq!(static_site.spa_fallback.as_deref(), Some("200.html"));
    assert_eq!(static_site.build_command, "npm exec -- vite build");

    let auto = detect(&[(
        "package.json",
        r#"{"devDependencies":{"@sveltejs/kit":"2","@sveltejs/adapter-auto":"3"}}"#,
    )]);
    assert_eq!(auto.start_argv, ["node", "build/index.js"]);
    assert!(auto.confidence < 0.5);
    assert!(auto.notes.iter().any(|n| n.contains("adapter-node")));
}

#[test]
fn astro_static_and_node_standalone() {
    let static_site = detect(&[
        ("package.json", r#"{"dependencies":{"astro":"5"}}"#),
        ("astro.config.mjs", "export default defineConfig({ outDir: './public-out' });\n"),
    ]);
    assert_eq!(static_site.rendering, Rendering::Static);
    assert_eq!(static_site.output_dir, "public-out");
    assert_eq!(static_site.build_command, "npm exec -- astro build");

    let node = detect(&[
        (
            "package.json",
            r#"{"dependencies":{"astro":"5","@astrojs/node":"9"},"scripts":{"build":"astro build"}}"#,
        ),
        (
            "astro.config.mjs",
            "import node from '@astrojs/node';\nexport default defineConfig({ output: 'server', adapter: node({ mode: 'standalone' }) });\n",
        ),
    ]);
    assert_eq!(node.rendering, Rendering::Ssr);
    assert_eq!(node.start_argv, ["node", "dist/server/entry.mjs"]);
    assert!(node.notes.is_empty(), "{:?}", node.notes);

    let middleware = detect(&[
        ("package.json", r#"{"dependencies":{"astro":"5","@astrojs/node":"9"}}"#),
        (
            "astro.config.mjs",
            "import node from '@astrojs/node';\nexport default { adapter: node({ mode: 'middleware' }) };\n",
        ),
    ]);
    assert!(middleware.notes.iter().any(|n| n.contains("middleware")));
}

#[test]
fn remix_and_react_router_servers() {
    let remix = detect(&[
        (
            "package.json",
            r#"{"dependencies":{"@remix-run/node":"2","@remix-run/serve":"2"},"devDependencies":{"@remix-run/dev":"2","vite":"5"},"scripts":{"build":"remix vite:build","start":"remix-serve ./build/server/index.js"}}"#,
        ),
        ("vite.config.ts", "import { vitePlugin as remix } from '@remix-run/dev';\n"),
    ]);
    assert_eq!(remix.framework, "remix");
    assert_eq!(
        remix.start_argv,
        [
            "node",
            "node_modules/@remix-run/serve/dist/cli.js",
            "./build/server/index.js"
        ]
    );
    assert_eq!(remix.start_bin.unwrap().package, "@remix-run/serve");

    let classic = detect(&[
        (
            "package.json",
            r#"{"dependencies":{"@remix-run/node":"1","@remix-run/serve":"1"},"devDependencies":{"@remix-run/dev":"1"}}"#,
        ),
        ("remix.config.js", "module.exports = {};\n"),
    ]);
    assert_eq!(classic.start_argv[2], "./build/index.js");
    assert_eq!(classic.build_command, "npm exec -- remix build");

    let router = detect(&[(
        "package.json",
        r#"{"dependencies":{"react-router":"7","@react-router/node":"7","@react-router/serve":"7"},"devDependencies":{"@react-router/dev":"7"},"scripts":{"build":"react-router build","start":"react-router-serve ./build/server/index.js"}}"#,
    )]);
    assert_eq!(router.framework, "react-router");
    assert_eq!(router.start_argv[0], "node");
    assert_eq!(router.start_argv[2], "./build/server/index.js");
    assert_eq!(router.start_bin.unwrap().bin, "react-router-serve");

    let spa = detect(&[
        (
            "package.json",
            r#"{"devDependencies":{"@react-router/dev":"7"},"dependencies":{"react-router":"7"}}"#,
        ),
        ("react-router.config.ts", "export default { ssr: false };\n"),
    ]);
    assert_eq!(spa.rendering, Rendering::Static);
    assert_eq!(spa.output_dir, "build/client");
    assert_eq!(spa.spa_fallback.as_deref(), Some("index.html"));
}

#[test]
fn react_router_library_in_a_vite_spa_is_not_a_server() {
    let det = detect(&[(
        "package.json",
        r#"{"dependencies":{"react":"19","react-router":"7","react-router-dom":"7"},"devDependencies":{"vite":"6"},"scripts":{"build":"vite build"}}"#,
    )]);
    assert_eq!(det.framework, "vite");
    assert_eq!(det.rendering, Rendering::Static);
}

#[test]
fn static_frameworks_have_their_output_dirs() {
    let cases: [(&str, &str, &str, Option<&str>); 6] = [
        (r#"{"dependencies":{"react-scripts":"5"}}"#, "create-react-app", "build", Some("index.html")),
        (r#"{"dependencies":{"@docusaurus/core":"3"}}"#, "docusaurus", "build", None),
        (r#"{"dependencies":{"gatsby":"5"}}"#, "gatsby", "public", None),
        (r#"{"devDependencies":{"@11ty/eleventy":"3"}}"#, "eleventy", "_site", None),
        (r#"{"devDependencies":{"@vue/cli-service":"5"}}"#, "vue-cli", "dist", Some("index.html")),
        (
            r#"{"devDependencies":{"vitepress":"1"},"scripts":{"build":"vitepress build docs"}}"#,
            "vitepress",
            "docs/.vitepress/dist",
            None,
        ),
    ];
    for (json, framework, output, spa) in cases {
        let det = detect(&[("package.json", json)]);
        assert_eq!(det.framework, framework, "{json}");
        assert_eq!(det.rendering, Rendering::Static, "{json}");
        assert_eq!(det.output_dir, output, "{json}");
        assert_eq!(det.spa_fallback.as_deref(), spa, "{json}");
        assert!(det.start_argv.is_empty());
    }
}

#[test]
fn angular_static_and_ssr_follow_angular_json() {
    let angular_json = r#"{"projects":{"shop":{"projectType":"application","architect":{"build":{"options":{"outputPath":"dist/shop-web"}}}}}}"#;
    let spa = detect(&[
        ("package.json", r#"{"dependencies":{"@angular/core":"18"},"scripts":{"build":"ng build"}}"#),
        ("angular.json", angular_json),
    ]);
    assert_eq!(spa.rendering, Rendering::Static);
    assert_eq!(spa.output_dir, "dist/shop-web/browser");
    assert_eq!(spa.alt_output_dirs, ["dist/shop-web"]);
    assert_eq!(spa.spa_fallback.as_deref(), Some("index.html"));

    let ssr = detect(&[
        (
            "package.json",
            r#"{"dependencies":{"@angular/core":"18","@angular/ssr":"18"},"scripts":{"build":"ng build","serve:ssr:shop":"node dist/shop/server/server.mjs"}}"#,
        ),
        ("angular.json", angular_json),
    ]);
    assert_eq!(ssr.rendering, Rendering::Ssr);
    assert_eq!(ssr.start_argv, ["node", "dist/shop/server/server.mjs"]);
}

#[test]
fn vite_out_dir_and_root_are_read_from_the_config() {
    let det = detect(&[
        ("package.json", r#"{"devDependencies":{"vite":"6"},"scripts":{"build":"vite build"}}"#),
        ("vite.config.ts", "export default { root: 'web', build: { outDir: 'public-build' } };\n"),
    ]);
    assert_eq!(det.output_dir, "web/public-build");
    assert_eq!(det.alt_output_dirs, ["public-build"]);
}

#[test]
fn plain_node_servers_parse_their_start_scripts() {
    let express = detect(&[
        (
            "package.json",
            r#"{"dependencies":{"express":"4"},"scripts":{"start":"cross-env NODE_ENV=production SECRET_MODE=1 node --enable-source-maps server.js"}}"#,
        ),
        ("package-lock.json", "{}"),
    ]);
    assert_eq!(express.framework, "express");
    assert_eq!(express.rendering, Rendering::Ssr);
    assert_eq!(express.start_argv, ["node", "--enable-source-maps", "server.js"]);
    assert_eq!(express.install_command, "npm ci");
    assert_eq!(express.build_command, "true");
    assert!(express.notes.iter().any(|n| n.contains("SECRET_MODE")));
    assert!(express.notes.iter().all(|n| !n.contains("NODE_ENV")));

    let nest = detect(&[(
        "package.json",
        r#"{"dependencies":{"@nestjs/core":"10"},"devDependencies":{"@nestjs/cli":"10"},"scripts":{"build":"nest build","start":"nest start","start:prod":"node dist/main"}}"#,
    )]);
    assert_eq!(nest.framework, "nest");
    assert_eq!(nest.start_argv, ["node", "dist/main"]);
    assert_eq!(nest.build_command, "npm run build");

    let indirect = detect(&[(
        "package.json",
        r#"{"dependencies":{"fastify":"5"},"scripts":{"start":"npm run serve","serve":"node dist/index.js"}}"#,
    )]);
    assert_eq!(indirect.start_argv, ["node", "dist/index.js"]);

    let main_only = detect(&[(
        "package.json",
        r#"{"main":"./app.js","dependencies":{"koa":"2"}}"#,
    )]);
    assert_eq!(main_only.start_argv, ["node", "app.js"]);

    let watcher = detect(&[(
        "package.json",
        r#"{"dependencies":{"express":"4"},"scripts":{"start":"nodemon --watch src server.js"}}"#,
    )]);
    assert_eq!(watcher.start_argv, ["node", "server.js"]);
    assert!(watcher.notes.iter().any(|n| n.contains("nodemon")));
}

#[test]
fn shell_start_scripts_are_refused_with_a_clear_message() {
    let dir = site(&[(
        "package.json",
        r#"{"dependencies":{"express":"4"},"scripts":{"start":"node migrate.js && node server.js"}}"#,
    )]);
    let err = detect_site(dir.path()).unwrap_err().to_string();
    assert!(err.contains("needs a shell"), "{err}");
    assert!(err.contains("CITE_START_COMMAND"), "{err}");
    assert!(err.contains("scripts.start"), "{err}");
}

#[test]
fn bun_servers_start_the_file_directly_and_note_the_runtime() {
    let det = detect(&[
        (
            "package.json",
            r#"{"dependencies":{"hono":"4"},"scripts":{"start":"bun run src/index.ts"}}"#,
        ),
        ("bun.lock", "{}"),
    ]);
    assert_eq!(det.framework, "hono");
    assert_eq!(det.package_manager, "bun");
    assert_eq!(det.install_command, "bun install --frozen-lockfile");
    assert_eq!(det.start_argv, ["bun", "src/index.ts"]);
    assert!(det.notes.iter().any(|n| n.contains("CITE_RUNTIME=bun")));
}

#[test]
fn static_sites_without_a_build_are_served_from_their_html_dir() {
    let root = detect(&[("package.json", r#"{"name":"x"}"#), ("index.html", "<html>")]);
    assert_eq!(root.rendering, Rendering::Static);
    assert_eq!(root.output_dir, ".");
    assert_eq!(root.install_command, "true");
    assert_eq!(root.build_command, "true");

    let public = detect(&[("package.json", r#"{"name":"x"}"#), ("public/index.html", "<html>")]);
    assert_eq!(public.output_dir, "public");

    let bare = detect(&[("dist/index.html", "<html>")]);
    assert_eq!(bare.output_dir, "dist");
    assert_eq!(bare.install_command, "true");
    assert_eq!(bare.build_command, "true");
}

#[test]
fn package_managers_choose_their_install_commands() {
    let install = |files: &[(&str, &str)]| detect(files).install_command;
    let pkg = ("package.json", r#"{"dependencies":{"vite":"6"}}"#);
    assert_eq!(install(&[pkg, ("package-lock.json", "{}")]), "npm ci");
    assert_eq!(install(&[pkg]), "npm install");
    assert_eq!(
        install(&[pkg, ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n")]),
        "pnpm install --frozen-lockfile"
    );
    assert_eq!(
        install(&[pkg, ("yarn.lock", "# yarn lockfile v1\n")]),
        "yarn install --frozen-lockfile"
    );
    assert_eq!(
        install(&[pkg, ("yarn.lock", "__metadata:\n  version: 8\n")]),
        "yarn install --immutable"
    );
    assert_eq!(install(&[pkg, ("bun.lockb", "x")]), "bun install --frozen-lockfile");
    assert_eq!(install(&[pkg, ("bun.lock", "{}")]), "bun install --frozen-lockfile");
}

#[test]
fn yarn_pnp_ssr_installs_with_a_node_modules_linker() {
    let det = detect(&[
        (
            "package.json",
            r#"{"packageManager":"yarn@4.5.0","dependencies":{"next":"15"},"scripts":{"build":"next build"}}"#,
        ),
        ("yarn.lock", "__metadata:\n"),
        (".yarnrc.yml", "enableTelemetry: false\n"),
    ]);
    assert_eq!(
        det.install_command,
        "YARN_NODE_LINKER=node-modules yarn install --immutable"
    );
    assert!(det.notes.iter().any(|n| n.contains("Plug'n'Play")));

    let linked = detect(&[
        (
            "package.json",
            r#"{"packageManager":"yarn@4.5.0","dependencies":{"next":"15"}}"#,
        ),
        ("yarn.lock", "__metadata:\n"),
        (".yarnrc.yml", "nodeLinker: \"node-modules\"\n"),
    ]);
    assert_eq!(linked.install_command, "yarn install --immutable");
}

#[test]
fn old_pnpm_lockfiles_and_unpinned_berry_are_noted() {
    let det = detect(&[
        ("package.json", r#"{"dependencies":{"vite":"5"}}"#),
        ("pnpm-lock.yaml", "lockfileVersion: '6.0'\n"),
    ]);
    assert!(det.notes.iter().any(|n| n.contains("lockfile v6")), "{:?}", det.notes);

    let pinned = detect(&[
        ("package.json", r#"{"packageManager":"pnpm@8.15.0","dependencies":{"vite":"5"}}"#),
        ("pnpm-lock.yaml", "lockfileVersion: '6.0'\n"),
    ]);
    assert!(pinned.notes.is_empty(), "{:?}", pinned.notes);
}

#[test]
fn monorepo_root_dir_reads_workspace_lockfiles_and_version_files() {
    let repo = site(&[
        (
            "package.json",
            r#"{"private":true,"packageManager":"pnpm@9.12.0"}"#,
        ),
        ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n"),
        ("pnpm-workspace.yaml", "packages:\n  - apps/*\n"),
        (".nvmrc", "22\n"),
        (
            "apps/web/package.json",
            r#"{"dependencies":{"next":"15"},"scripts":{"build":"next build"}}"#,
        ),
        ("apps/web/next.config.js", "module.exports = { output: 'standalone' };\n"),
    ]);
    let det = detect_site_in(repo.path(), "apps/web", None, None).unwrap();
    assert_eq!(det.package_manager, "pnpm");
    assert_eq!(det.install_command, "pnpm install --frozen-lockfile");
    assert_eq!(det.node_major.as_deref(), Some("22"));
    assert_eq!(det.ssr_root.as_deref(), Some(".next/standalone"));

    let plain = site(&[
        ("package-lock.json", "{}"),
        (
            "apps/web/package.json",
            r#"{"dependencies":{"next":"15"},"scripts":{"build":"next build"}}"#,
        ),
    ]);
    let det = detect_site_in(plain.path(), "./apps/web/", None, None).unwrap();
    assert_eq!(det.install_command, "npm ci");
    assert!(det.notes.iter().any(|n| n.contains("monorepo")));
    assert!(det.confidence <= 0.5);

    assert!(detect_site_in(plain.path(), "../x", None, None).is_err());
}

#[test]
fn node_ranges_are_compared_by_major() {
    for (range, major, allowed) in [
        (">=18", 22, Some(true)),
        (">= 18.17.0", 22, Some(true)),
        ("^20 || ^22", 22, Some(true)),
        ("^20 || ^22", 21, Some(false)),
        ("18.x", 22, Some(false)),
        ("22", 22, Some(true)),
        (">=18 <21", 22, Some(false)),
        ("18 - 22", 20, Some(true)),
        ("*", 22, Some(true)),
        ("lts", 22, None),
    ] {
        assert_eq!(node_range_allows(range, major), allowed, "{range}");
    }
}

#[test]
fn standalone_server_dir_is_found_at_the_root_or_nested_for_monorepos() {
    let flat = site(&[("server.js", ""), (".next/BUILD_ID", "x")]);
    assert_eq!(
        next_standalone_server_dir(flat.path(), ".next"),
        Some(PathBuf::new())
    );
    let nested = site(&[
        ("node_modules/x/server.js", ""),
        ("apps/web/server.js", ""),
        ("apps/web/.next/BUILD_ID", "x"),
    ]);
    assert_eq!(
        next_standalone_server_dir(nested.path(), ".next"),
        Some(PathBuf::from("apps/web"))
    );
    let missing = site(&[("server.js", "")]);
    assert_eq!(next_standalone_server_dir(missing.path(), ".next"), None);
}

#[test]
fn package_bins_resolve_from_the_installed_package_json() {
    let dir = site(&[(
        "node_modules/@react-router/serve/package.json",
        r#"{"bin":{"react-router-serve":"./bin.js"}}"#,
    ), ("node_modules/next/package.json", r#"{"bin":{"next":"./dist/bin/next"}}"#)]);
    let rr = StartBin {
        package: "@react-router/serve".into(),
        bin: "react-router-serve".into(),
    };
    assert_eq!(
        package_bin_path(dir.path(), &rr).as_deref(),
        Some("node_modules/@react-router/serve/bin.js")
    );
    let next = StartBin {
        package: "next".into(),
        bin: "next".into(),
    };
    assert_eq!(
        package_bin_path(dir.path(), &next).as_deref(),
        Some("node_modules/next/dist/bin/next")
    );
    let escape = StartBin {
        package: "../x".into(),
        bin: "x".into(),
    };
    assert_eq!(package_bin_path(dir.path(), &escape), None);
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
    let dir = next_with(&[("pnpm-lock.yaml", "lockfileVersion: '9.0'\n")]);
    let auto = detect_site(dir.path()).unwrap();
    assert_eq!(auto.build_command, "pnpm run build");
    for choice in [None, Some("auto")] {
        let det = detect_site_with(dir.path(), choice).unwrap();
        assert_eq!(det.package_manager, "pnpm");
    }
    let det = detect_site_with(dir.path(), Some("npm")).unwrap();
    assert_eq!(det.package_manager, "npm");
    assert_eq!(det.build_command, "npm run build");
    assert_eq!(det.install_command, "npm install");
    assert!(det.warnings.is_empty());

    let det = detect_site_with(dir.path(), Some("yarn")).unwrap();
    assert_eq!(det.build_command, "yarn run build");
    assert_eq!(det.install_command, "yarn install");
}

#[test]
fn explicit_package_manager_drives_non_next_presets() {
    let dir = site(&[
        ("package.json", r#"{"dependencies":{"vite":"^6"}}"#),
        ("package-lock.json", "{}"),
    ]);
    let det = detect_site_with(dir.path(), Some("bun")).unwrap();
    assert_eq!(det.build_command, "bun x vite build");
    assert_eq!(det.install_command, "bun install");
    for (pm, build) in [
        ("pnpm", "pnpm exec vite build"),
        ("yarn", "yarn vite build"),
        ("npm", "npm exec -- vite build"),
    ] {
        assert_eq!(
            detect_site_with(dir.path(), Some(pm)).unwrap().build_command,
            build
        );
    }
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
    assert_eq!(det.build_command, "yarn run build");

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
        assert!(!det.node_exact, "{alias}");
        assert_eq!(det.node_engines.as_deref(), Some(">=18"), "{alias}");
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
    assert_eq!(entry(r#"{"nuxt":"3"}"#), ["node", "server/index.mjs"]);
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
    let err = detect_site(dir.path()).unwrap_err().to_string();
    assert!(err.contains("CITE_RENDERING"), "{err}");
    let det = detect_site_configured(dir.path(), None, Some(Rendering::Static)).unwrap();
    assert_eq!(det.framework, "generic-static");
    assert_eq!(det.rendering, Rendering::Static);
    assert_eq!(det.build_command, "pnpm run build");
    assert_eq!(det.install_command, "pnpm install --frozen-lockfile");
    assert_eq!(det.output_dir, "dist");
    assert!(det.alt_output_dirs.contains(&"build".to_string()));
    assert!(!det.notes.is_empty());
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
    assert!(det.notes.iter().any(|n| n.contains("needs a shell")));
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
