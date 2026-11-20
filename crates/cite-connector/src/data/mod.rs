//! Site data services: managed and external Postgres, S3, generated secrets and the env links that deliver them.
//!
//! The pure building blocks (env links, S3, catalog, retention, streams) sit next to the service that drives them:
//! `service` (state and flows), `jobs` (database jobs, backups, restore), `users`, `scheduler`, `shared` and `targets`.

pub mod catalog;
pub mod env;
pub mod jobs;
pub mod retention;
pub mod s3;
pub mod scheduler;
pub mod service;
pub mod shared;
pub mod stream;
pub mod targets;
pub mod transfer;
pub mod users;

pub use service::DataService;

#[cfg(test)]
mod image_tests {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    fn root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn read(rel: &str) -> String {
        std::fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
    }

    fn script_path() -> PathBuf {
        root().join("images/postgres/cite-pg-job")
    }

    #[test]
    fn the_job_script_parses_as_posix_sh() {
        let out = Command::new("sh")
            .arg("-n")
            .arg(script_path())
            .output()
            .expect("sh is available");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn the_job_script_is_strict_and_never_splices_values_into_sql() {
        let text = read("images/postgres/cite-pg-job");
        assert!(text.starts_with("#!/bin/sh\n"));
        assert!(text.lines().any(|l| l == "set -eu"));
        assert!(text.lines().any(|l| l == "umask 077"));
        for banned in ["eval ", "bash", "source ", "$(("] {
            assert!(!text.contains(banned), "the script must not use {banned:?}");
        }
        assert!(
            !text.contains("<<SQL") && !text.contains("<<\"SQL\""),
            "heredocs must be quoted"
        );
        // Inside every SQL heredoc the shell expands nothing, so no `$` may appear except in dollar quoting-free SQL.
        let mut rest = text.as_str();
        let mut blocks = 0;
        while let Some(start) = rest.find("<<'SQL'") {
            let after = &rest[start..];
            let body_start = after.find('\n').expect("heredoc body") + 1;
            let body = &after[body_start..];
            let end = body.find("\nSQL\n").expect("heredoc end");
            assert!(
                !body[..end].contains('$'),
                "shell variable inside SQL: {}",
                &body[..end]
            );
            blocks += 1;
            rest = &body[end..];
        }
        assert!(blocks >= 14, "found {blocks} SQL heredocs");
        // Passwords reach psql through the environment, never an argument.
        assert!(text.contains("\\getenv pw CITE_USER_PASSWORD"));
        assert!(text.contains("\\getenv pw CITE_JOB_PASSWORD"));
        assert!(!text.contains("-v pw="));
        assert!(!text.contains("PASSWORD=\"$"));
        assert!(text.contains("log_min_error_statement = panic"));
    }

    #[test]
    fn the_job_script_implements_every_op() {
        let text = read("images/postgres/cite-pg-job");
        for op in [
            "backup",
            "restore",
            "counts",
            "joblogin",
            "freeze",
            "unfreeze",
            "provision",
            "deprovision",
            "regrant",
            "user",
            "hba",
            "sizes",
            "globals",
        ] {
            assert!(text.contains(&format!("op_{op}()")), "missing op_{op}");
            assert!(
                text.contains(&format!("  {op}) op_{op} ;;")),
                "op {op} is not dispatched"
            );
        }
        assert!(text.contains("*) die \"unknown operation\" ;;"));
        for needle in [
            "pg_dump -Fc -Z 6",
            "--clean --if-exists --exit-on-error --single-transaction --no-owner --no-acl",
            "--role=\"$owner_role\"",
            "DROP DATABASE IF EXISTS :\"db\" WITH (FORCE)",
            "pg_dumpall --globals-only --no-role-passwords -l postgres",
            "host all all 0.0.0.0/0 reject",
            "host all all ::/0 reject",
            "host postgres postgres %s scram-sha-256",
            "host %s %s_job %s scram-sha-256",
            "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS",
            "NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS INHERIT",
            "ALTER ROLE :\"job\" LOGIN PASSWORD :'pw';",
            "NOLOGIN PASSWORD NULL",
            "COMMENT ON ROLE :\"login\" IS 'cite:frozen';",
            "'cite:locked'",
            "permission denied to create extension",
        ] {
            assert!(text.contains(needle), "missing {needle:?}");
        }
    }

    /// The text of the shell function `name`, from its header to the closing brace at the start of a line.
    fn function_body<'a>(text: &'a str, name: &str) -> &'a str {
        let header = format!("\n{name}() {{\n");
        let start = text
            .find(&header)
            .unwrap_or_else(|| panic!("no function {name}"))
            + 1;
        let end = text[start..].find("\n}\n").expect("function end") + start;
        &text[start..end]
    }

    /// The function a line belongs to, found from the nearest `name() {` header above it.
    fn enclosing_function(lines: &[&str], at: usize) -> String {
        lines[..at]
            .iter()
            .rev()
            .find_map(|l| l.strip_suffix("() {"))
            .unwrap_or("<top level>")
            .to_string()
    }

    // Lines that run a tool as a command (not as text inside SQL or a message).
    fn command_lines(text: &str, tool: &str) -> Vec<usize> {
        text.lines()
            .enumerate()
            .filter(|(_, l)| l.trim_start().starts_with(&format!("{tool} ")))
            .map(|(i, _)| i)
            .collect()
    }

    #[test]
    fn every_psql_session_runs_with_the_pinned_search_path() {
        let text = read("images/postgres/cite-pg-job");
        let lines: Vec<&str> = text.lines().collect();
        // Exported once, at the top, before any helper or operation; never changed or removed after.
        let set_at = lines
            .iter()
            .position(|l| *l == "PGOPTIONS='-c search_path=pg_catalog,pg_temp'")
            .expect("PGOPTIONS is pinned");
        let export_at = lines
            .iter()
            .position(|l| l.starts_with("export ") && l.contains(" PGOPTIONS"))
            .expect("PGOPTIONS is exported");
        let first_function = lines.iter().position(|l| l.ends_with("() {")).unwrap();
        assert!(set_at < first_function && export_at < first_function);
        assert_eq!(text.matches("PGOPTIONS=").count(), 1);
        for banned in ["unset PGOPTIONS", "env -u", "env -i", "PGOPTIONS+="] {
            assert!(!text.contains(banned), "{banned:?}");
        }
        // psql starts only inside the four session helpers.
        let psql = command_lines(&text, "psql");
        assert_eq!(psql.len(), 4, "psql runs outside the session helpers");
        let mut helpers: Vec<String> = psql
            .iter()
            .map(|&i| enclosing_function(&lines, i))
            .collect();
        helpers.sort();
        assert_eq!(helpers, ["db_psql", "db_query", "su_psql", "su_query"]);
        for pipe in ["| psql", "$(psql", "&& psql", "; psql", "exec psql"] {
            assert!(!text.contains(pipe), "{pipe:?}");
        }
    }

    #[test]
    fn the_superuser_opens_only_the_maintenance_database() {
        let text = read("images/postgres/cite-pg-job");
        for helper in ["su_psql", "su_query"] {
            let body = function_body(&text, helper);
            assert!(body.contains("need_superuser"), "{helper}");
            assert!(body.contains(" -d postgres "), "{helper}: {body}");
            assert!(!body.contains("PGDATABASE"), "{helper}");
        }
        for helper in ["db_psql", "db_query"] {
            let body = function_body(&text, helper);
            assert!(body.contains("-d \"$PGDATABASE\""), "{helper}");
            assert!(body.contains("db_login_checked"), "{helper}");
        }
        // Only need_job_login and need_external_login mark a database login as checked; the job login check refuses
        // the superuser by name, and the external one refuses the node's own servers.
        assert_eq!(text.matches("db_login_checked=1").count(), 2);
        let job = function_body(&text, "need_job_login");
        assert!(job.contains("[ \"$PGUSER\" != postgres ]"));
        assert!(job.contains("db_login_checked=1"));
        let ext = function_body(&text, "need_external_login");
        assert!(ext.contains("cite-pg-shared | cite-*-db"));
        assert!(text.contains("[ \"$PGUSER\" = postgres ] || die"));
        // No SQL switches databases.
        for banned in ["\\connect", "\\c ", "\\c\n", "dbname="] {
            assert!(!text.contains(banned), "{banned:?}");
        }
        // Superuser SQL names catalog objects with their schema.
        for unqualified in [
            "FROM pg_roles",
            "FROM pg_stat_activity",
            "FROM pg_database",
            "JOIN pg_roles",
            "SELECT format(",
            "(format(",
            " left(",
            "SELECT pg_terminate_backend",
            " !~ ",
            "query_to_xml(format",
        ] {
            assert!(!text.contains(unqualified), "unqualified: {unqualified:?}");
        }
    }

    #[test]
    fn dumps_and_restores_never_run_as_the_superuser() {
        let text = read("images/postgres/cite-pg-job");
        let lines: Vec<&str> = text.lines().collect();
        let checked_before = |at: usize, function: &str, check: &str| {
            let start = lines
                .iter()
                .position(|l| *l == format!("{function}() {{"))
                .unwrap();
            assert!(
                lines[start..at].iter().any(|l| l.contains(check)),
                "{function} runs line {} before {check}",
                at + 1
            );
        };
        let restore = command_lines(&text, "pg_restore");
        assert_eq!(restore.len(), 1);
        assert_eq!(enclosing_function(&lines, restore[0]), "op_restore");
        checked_before(restore[0], "op_restore", "need_job_login");
        let dump = command_lines(&text, "pg_dump");
        assert_eq!(dump.len(), 1);
        assert_eq!(enclosing_function(&lines, dump[0]), "op_backup");
        checked_before(dump[0], "op_backup", "need_job_login");
        checked_before(dump[0], "op_backup", "need_external_login");
        let dumpall = command_lines(&text, "pg_dumpall");
        assert_eq!(dumpall.len(), 1);
        assert_eq!(enclosing_function(&lines, dumpall[0]), "op_globals");
        checked_before(dumpall[0], "op_globals", "need_superuser");
        // Every operation inside a tenant database checks the job login first.
        for op in ["op_counts", "op_regrant", "op_restore"] {
            assert!(function_body(&text, op).contains("need_job_login"), "{op}");
        }
    }

    fn job(args: &[&str], env: &[(&str, &str)]) -> (Option<i32>, String) {
        let job_id = "0".repeat(26);
        let mut cmd = Command::new("sh");
        cmd.arg(script_path())
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin");
        let mut vars: Vec<(&str, &str)> = vec![
            ("CITE_JOB_ID", job_id.as_str()),
            ("PGHOST", "cite-shop-db"),
            ("PGPORT", "5432"),
            ("PGUSER", "postgres"),
            ("PGPASSWORD", "pw"),
        ];
        for (k, v) in env {
            vars.retain(|(name, _)| name != k);
            vars.push((k, v));
        }
        for (k, v) in vars {
            cmd.env(k, v);
        }
        let out = cmd.output().expect("sh is available");
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn refused(args: &[&str], env: &[(&str, &str)], why: &str) {
        let (code, err) = job(args, env);
        assert_eq!(code, Some(2), "{args:?} {env:?}: {err}");
        assert!(
            err.contains("cite-pg-job:") && err.contains(why),
            "{args:?} {env:?}: {err}"
        );
    }

    #[test]
    fn the_job_script_refuses_bad_common_input() {
        refused(&[], &[], "usage");
        refused(&["a", "b"], &[], "usage");
        refused(&["bogus"], &[], "unknown operation");
        refused(&["backup"], &[("CITE_JOB_ID", "")], "CITE_JOB_ID");
        refused(&["backup"], &[("CITE_JOB_ID", "short")], "CITE_JOB_ID");
        let long = "0".repeat(27);
        refused(
            &["backup"],
            &[("CITE_JOB_ID", long.as_str())],
            "CITE_JOB_ID",
        );
        refused(
            &["backup"],
            &[("CITE_JOB_ID", "../../etc/passwd000000000000")],
            "CITE_JOB_ID",
        );
        for host in [
            "",
            "/var/run/postgresql",
            "a,b",
            "-h",
            "host name",
            "h;x",
            "$(id)",
        ] {
            refused(&["backup"], &[("PGHOST", host)], "PGHOST");
        }
        for port in ["", "abc", "54 32", "-1", "5432;"] {
            refused(&["backup"], &[("PGPORT", port)], "PGPORT");
        }
        refused(&["backup"], &[("PGPASSWORD", "")], "PGPASSWORD");
        refused(&["backup"], &[("PGSSLMODE", "bogus")], "PGSSLMODE");
    }

    #[test]
    fn the_job_script_refuses_database_names_that_could_be_connection_strings_or_sql() {
        for db in [
            "",
            "a b",
            "a;b",
            "x=y",
            "postgres://u@h/d",
            "-x",
            "a'b",
            "a\"b",
            "a/b",
            "$(id)",
            "`id`",
        ] {
            refused(&["backup"], &[("PGDATABASE", db)], "PGDATABASE");
            refused(&["counts"], &[("PGDATABASE", db)], "PGDATABASE");
        }
        let long = "d".repeat(64);
        refused(&["backup"], &[("PGDATABASE", long.as_str())], "PGDATABASE");
    }

    #[test]
    fn the_job_script_refuses_malformed_role_names_and_settings() {
        let db = ("PGDATABASE", "app");
        for tag in [
            "",
            "bad",
            "t0123456789_APP",
            "t012345678_app",
            "t0123456789",
            "t0123456789_app; drop",
            "t012345678g_app",
            "t0123456789_1app",
            "t0123456789_abcdefghijklmnopq",
        ] {
            refused(
                &["provision"],
                &[db, ("CITE_ROLE_TAG", tag)],
                "CITE_ROLE_TAG",
            );
            refused(
                &["deprovision"],
                &[db, ("CITE_ROLE_TAG", tag)],
                "CITE_ROLE_TAG",
            );
            refused(&["regrant"], &[db, ("CITE_ROLE_TAG", tag)], "CITE_ROLE_TAG");
        }
        let tag = ("CITE_ROLE_TAG", "t0123456789_app");
        let base = [db, tag];
        let user = |extra: &[(&'static str, &'static str)]| {
            let mut v: Vec<(&str, &str)> = base.to_vec();
            v.push(("CITE_USER_ROLE", "t0123456789_app_app_a"));
            v.push(("CITE_USER_ACTION", "create"));
            v.push(("CITE_USER_PASSWORD", "pw"));
            for (k, val) in extra {
                v.retain(|(n, _)| n != k);
                v.push((k, val));
            }
            v
        };
        refused(
            &["user"],
            &user(&[("CITE_USER_ROLE", "other_a")]),
            "CITE_USER_ROLE",
        );
        refused(
            &["user"],
            &user(&[("CITE_USER_ROLE", "t0123456789_app_app_c")]),
            "CITE_USER_ROLE",
        );
        refused(
            &["user"],
            &user(&[("CITE_USER_ROLE", "t0123456789_app_App_a")]),
            "CITE_USER_ROLE",
        );
        refused(
            &["user"],
            &user(&[("CITE_USER_ROLE", "t0123456789_app_a;drop_a")]),
            "CITE_USER_ROLE",
        );
        refused(
            &["user"],
            &user(&[("CITE_USER_ROLE", "t0123456789_other_app_a")]),
            "CITE_USER_ROLE",
        );
        refused(
            &["user"],
            &user(&[("CITE_USER_ACTION", "evil")]),
            "CITE_USER_ACTION",
        );
        refused(
            &["user"],
            &user(&[("CITE_USER_ACTION", "")]),
            "CITE_USER_ACTION",
        );
        refused(
            &["user"],
            &user(&[("CITE_USER_LEVEL", "root")]),
            "CITE_USER_LEVEL",
        );
        refused(
            &["user"],
            &user(&[("CITE_USER_CONN_LIMIT", "1;2")]),
            "CITE_USER_CONN_LIMIT",
        );
        refused(
            &["user"],
            &user(&[("CITE_USER_STMT_MS", "-5")]),
            "CITE_USER_STMT_MS",
        );
        refused(
            &["user"],
            &user(&[("CITE_USER_IDLE_MS", "x")]),
            "CITE_USER_IDLE_MS",
        );
        refused(
            &["user"],
            &user(&[("CITE_USER_PASSWORD", "")]),
            "CITE_USER_PASSWORD",
        );
        refused(
            &["user"],
            &user(&[("CITE_USER_ACTION", "password"), ("CITE_USER_PASSWORD", "")]),
            "CITE_USER_PASSWORD",
        );

        refused(
            &["restore"],
            &[
                db,
                ("CITE_OWNER_ROLE", "t0123456789_app_rw"),
                ("CITE_LOGIN_ROLE", "t0123456789_app_login"),
            ],
            "CITE_OWNER_ROLE",
        );
        refused(
            &["restore"],
            &[
                db,
                ("CITE_OWNER_ROLE", "t0123456789_app_owner"),
                ("CITE_LOGIN_ROLE", "t0123456789_other_login"),
            ],
            "CITE_LOGIN_ROLE",
        );
        refused(
            &["restore"],
            &[
                db,
                ("CITE_OWNER_ROLE", "t0123456789_app_owner"),
                ("CITE_LOGIN_ROLE", "t0123456789_app_login"),
                ("PGUSER", "t0123456789_app_job"),
            ],
            "no dump",
        );
        refused(
            &["freeze"],
            &[db, ("CITE_LOGIN_ROLE", "t0123456789_app_owner")],
            "CITE_LOGIN_ROLE",
        );
        refused(&["unfreeze"], &[db], "CITE_LOGIN_ROLE");
    }

    #[test]
    fn the_job_script_refuses_the_superuser_inside_a_tenant_database_and_anyone_else_outside() {
        let db = ("PGDATABASE", "app");
        let tag = ("CITE_ROLE_TAG", "t0123456789_app");
        let restore = [
            db,
            ("CITE_OWNER_ROLE", "t0123456789_app_owner"),
            ("CITE_LOGIN_ROLE", "t0123456789_app_login"),
        ];
        // The default PGUSER of `job` is postgres.
        refused(&["restore"], &restore, "job login");
        refused(&["counts"], &[db, tag], "job login");
        refused(&["regrant"], &[db, tag], "job login");
        refused(&["backup"], &[db, tag], "job login");
        // Another database's job login is no better.
        let other = ("PGUSER", "t0123456789_other_job");
        let mut with_other = restore.to_vec();
        with_other.push(other);
        refused(&["restore"], &with_other, "job login");
        refused(&["counts"], &[db, tag, other], "job login");
        // A backup without a tag is an external one and may not reach the node's servers.
        refused(&["backup"], &[db], "managed database");
        refused(
            &["backup"],
            &[db, ("PGHOST", "cite-pg-shared")],
            "managed database",
        );
        // A tenant-database job may only drop the privileges of its own database's logins.
        refused(
            &["regrant"],
            &[
                db,
                tag,
                ("PGUSER", "t0123456789_app_job"),
                ("CITE_USER_ROLE", "t0123456789_other_app_a"),
            ],
            "CITE_USER_ROLE",
        );
        // The job login itself is opened and closed by the superuser only, with a password only to open.
        let job = ("PGUSER", "t0123456789_app_job");
        refused(
            &["joblogin"],
            &[db, tag, job, ("CITE_JOB_ACTION", "close")],
            "superuser",
        );
        refused(
            &["joblogin"],
            &[db, tag, ("CITE_JOB_ACTION", "open")],
            "CITE_JOB_PASSWORD",
        );
        refused(
            &["joblogin"],
            &[
                db,
                tag,
                ("CITE_JOB_ACTION", "close"),
                ("CITE_JOB_PASSWORD", "pw"),
            ],
            "CITE_JOB_PASSWORD",
        );
        refused(
            &["joblogin"],
            &[db, tag, ("CITE_JOB_ACTION", "grant")],
            "CITE_JOB_ACTION",
        );
        refused(
            &["joblogin"],
            &[db, ("CITE_JOB_ACTION", "close")],
            "CITE_ROLE_TAG",
        );
        refused(&["globals"], &[job], "superuser");
    }

    #[test]
    fn the_dockerfile_pins_the_base_runs_as_postgres_and_bakes_in_the_script() {
        let text = read("images/postgres/Dockerfile");
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines.contains(&"ARG PG_IMAGE"));
        assert!(lines.contains(&"FROM ${PG_IMAGE}"));
        assert!(lines.contains(&"ENV PGDATA=/var/lib/postgresql/data/pgdata"));
        assert!(lines.contains(&"USER 70:70"));
        assert!(
            lines.contains(
                &"COPY --chmod=0755 images/postgres/cite-pg-job /usr/local/bin/cite-pg-job"
            )
        );
        assert!(text.contains("chown 70:70 /var/lib/postgresql/data"));
        assert!(text.contains("chmod 0700 /var/lib/postgresql/data"));
        assert!(text.contains("chown 10001:10001 /conf /etc/cite-pg"));
        assert!(
            !text.contains("HEALTHCHECK"),
            "the proxy-validated create body carries the health check"
        );
        assert!(!text.contains(":latest"));
        let last_user = lines.iter().rev().find(|l| l.starts_with("USER ")).unwrap();
        assert_ne!(*last_user, "USER root");
    }

    #[derive(Default, Debug)]
    struct PgEntry {
        major: Option<u8>,
        default: bool,
        image: String,
        digest: String,
    }

    fn postgres_entries() -> Vec<PgEntry> {
        let text = read("images/images.toml");
        let mut out: Vec<PgEntry> = Vec::new();
        let mut inside = false;
        for line in text.lines().map(str::trim) {
            if line.starts_with('[') {
                inside = line == "[[postgres]]";
                if inside {
                    out.push(PgEntry::default());
                }
                continue;
            }
            let Some(entry) = out.last_mut().filter(|_| inside) else {
                continue;
            };
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = value.trim().trim_matches('"');
            match key.trim() {
                "major" => entry.major = value.parse().ok(),
                "default" => entry.default = value == "true",
                "image" => entry.image = value.to_string(),
                "digest" => entry.digest = value.to_string(),
                _ => {}
            }
        }
        out
    }

    #[test]
    fn images_toml_pins_one_alpine_image_per_supported_major() {
        let entries = postgres_entries();
        let majors: BTreeSet<u8> = entries.iter().filter_map(|e| e.major).collect();
        let supported: BTreeSet<u8> = cite_edge::validate::PG_MAJORS.into_iter().collect();
        assert_eq!(
            majors, supported,
            "images.toml and cite_edge::validate::PG_MAJORS must list the same majors"
        );
        assert_eq!(entries.len(), supported.len());
        let defaults: Vec<u8> = entries
            .iter()
            .filter(|e| e.default)
            .filter_map(|e| e.major)
            .collect();
        assert_eq!(defaults, [cite_edge::datamodel::DEFAULT_PG_MAJOR]);
        for e in &entries {
            let major = e.major.unwrap();
            assert_eq!(
                e.image,
                format!("docker.io/library/postgres:{major}-alpine")
            );
            let hex = e.digest.strip_prefix("sha256:").unwrap_or("");
            assert!(
                hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
                "postgres {major} has no pinned digest in images/images.toml (resolve it with `docker buildx imagetools inspect {}`)",
                e.image
            );
        }
        assert!(read("images/images.toml").contains("postgres = \"cite-postgres\""));
    }

    #[test]
    fn workflows_build_and_publish_both_majors() {
        let release = read(".github/workflows/release.yml");
        for major in ["17", "18"] {
            assert!(release.contains(&format!(
                "{{ key: postgres-pg{major}, name: cite-postgres, dockerfile: images/postgres/Dockerfile, pg: \"{major}\", args: \"\" }}"
            )));
            assert!(release.contains(&format!(
                "{{ key: postgres-pg{major}, name: cite-postgres, suffix: \"-pg{major}\" }}"
            )));
        }
        assert!(release.contains("PG_IMAGE={0}"));
        let node = read(".github/workflows/node.yml");
        assert!(node.contains("images/postgres/Dockerfile"));
        assert!(node.contains("major: [\"17\", \"18\"]"));
        assert!(node.contains("shellcheck --shell=sh images/postgres/cite-pg-job"));
    }
}
