// The connector builds the data bodies and the filtering Docker proxy rebuilds and compares them. The two sides
// were written against one contract, so these tests feed the connector's real bodies into the proxy's validators
// and then change each one by a single forbidden thing.
//
// Expected job environments are written out by hand from the contract (design section C5), not taken from the
// connector, so a drift on either side fails here.

mod common;

use cite_connector::data::shared::SharedSettings;
use cite_connector::egress::{Egress, EgressMode};
use cite_connector::orchestrator::data::{
    DataSpecSet, JobNet, JobOp, JobScope, JobSpec, data_specs, postgres_image,
};
use cite_connector::orchestrator::{SpecSet, StackEnv, stack_specs};
use cite_dockerproxy::policy::{DataNetwork, DataRole, DataVolume, Policy, Route};
use cite_dockerproxy::spec_data::{PG_MAJORS as PROXY_PG_MAJORS, pg_site_tag as proxy_site_tag};
use cite_dockerproxy::target::normalise;
use cite_edge::datamodel::{
    EnvLink, ExternalPostgres, LinkSource, LinkTarget, ManagedPostgres, PgField, S3Attachment,
    SHARED_ADMIN, SHARED_CONF, SHARED_DATA, SHARED_DB, SHARED_JOB, db_container_name,
    db_volume_name, dbjob_name, dbnet_name, pg_site_tag,
};
use cite_edge::model::{
    HealthCheck, Maintenance, OutboundMode, OutboundRules, Site, SiteKind, Slot, Source, Upstream,
};
use cite_edge::validate::PG_MAJORS;
use serde_json::{Value, json};

const VERSION: &str = "0.5.0";
const BACKUPS: &str = "cite-backups";
// 43 characters from [A-Za-z0-9_-], the shape of a generated password.
const SU: &str = "Zx9_-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ab";
const USER_PW: &str = "Qq7-_ZyXwVuTsRqPoNmLkJiHgFeDcBa9876543210zz";
// The password a job login gets for one job; same shape.
const JOB_PW: &str = "Jj4_-QwErTyUiOpAsDfGhJkLzXcVbNm1029384756qz";
// A 26 character uppercase ULID.
const JOB: &str = "01HZX3K9M2N4P5Q6R7S8T9V0WX";
const TOKEN: &str = "ghp_secrettoken123";

// ---------------------------------------------------------------------------------------------------------------
// Builders

fn base_site(id: &str, runtime: &str) -> Site {
    Site {
        id: id.to_string(),
        name: id.to_string(),
        hosts: vec![format!("{id}.example.com")],
        path_regexes: Vec::new(),
        path_prefixes: Vec::new(),
        kind: SiteKind::Site,
        blue: Upstream::default(),
        green: Upstream::default(),
        active: Slot::Blue,
        maintenance: Maintenance::default(),
        health: HealthCheck::default(),
        source: Some(Source {
            repo: "acme/shop".to_string(),
            branch: None,
            runtime: Some(runtime.to_string()),
            node_major: None,
            poll_interval: Some("10m".to_string()),
            secret: None,
            ..Default::default()
        }),
        history: Vec::new(),
        access: Default::default(),
        volumes: Vec::new(),
        outbound: true,
        outbound_rules: Default::default(),
        data: Default::default(),
    }
}

fn pg_config(mode: &str, major: u8, memory_mb: u32, max_connections: u32) -> ManagedPostgres {
    serde_json::from_value(json!({
        "mode": mode,
        "major": major,
        "memory_mb": memory_mb,
        "max_connections": max_connections,
        "databases": [{ "name": "app", "users": [{ "name": "app", "level": "readwrite" }] }],
    }))
    .unwrap()
}

fn data_site(id: &str, mode: &str, major: u8) -> Site {
    let mut site = base_site(id, "node");
    site.data.postgres = Some(pg_config(mode, major, 512, 100));
    site
}

fn shared_settings(major: u8) -> SharedSettings {
    serde_json::from_value(json!({
        "version": 1,
        "enabled": true,
        "major": major,
        "memory_mb": 1024,
        "nano_cpus": 2_000_000_000i64,
        "max_connections": 200,
    }))
    .unwrap()
}

fn stack_env(egress: &Egress, isolate: bool) -> StackEnv<'_> {
    StackEnv {
        registry: common::REGISTRY,
        version: VERSION,
        edge_network: "cite_edge",
        isolate,
        github_api_url: None,
        egress,
    }
}

fn data_set(site: &Site, shared_major: u8, jobs: &[JobSpec]) -> DataSpecSet {
    let egress = Egress::default();
    data_specs(
        site,
        &stack_env(&egress, true),
        BACKUPS,
        SU,
        &shared_settings(shared_major),
        jobs,
    )
    .unwrap()
}

fn stack(site: &Site, slot: Slot, isolate: bool, mode: EgressMode) -> SpecSet {
    let egress = Egress::with_mode(mode);
    stack_specs(site, slot, None, TOKEN, &stack_env(&egress, isolate)).unwrap()
}

fn policy_for(mode: EgressMode) -> Policy {
    match mode {
        EgressMode::Filtered => common::policy(),
        EgressMode::Open => common::policy_with(&[("CITE_STACK_EGRESS_MODE", "open")]),
        EgressMode::Off => common::policy_with(&[("CITE_STACK_EGRESS_MODE", "off")]),
    }
}

fn data_off() -> Policy {
    common::policy_with(&[("CITE_PROXY_DATA", "false")])
}

// Runs a body through the same classify and validate steps the HTTP layer uses.
fn create(policy: &Policy, name: &str, body: &Value) -> Result<(), String> {
    let target = normalise(&format!("/v1.45/containers/create?name={name}"))?;
    let route = policy.classify("POST", &target)?;
    policy.validate_body(&route, body)
}

fn accepted(result: Result<(), String>, what: &str) {
    if let Err(e) = result {
        panic!("{what} was refused: {e}");
    }
}

fn refused(result: Result<(), String>, what: &str) {
    assert!(result.is_err(), "{what} was accepted");
}

fn edited(body: &Value, edit: impl FnOnce(&mut Value)) -> Value {
    let mut copy = body.clone();
    edit(&mut copy);
    copy
}

fn endpoints(body: &Value) -> Vec<String> {
    let mut names: Vec<String> = body["NetworkingConfig"]["EndpointsConfig"]
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    names.sort();
    names
}

fn put_env(body: &mut Value, key: &str, value: &str) {
    let env = body["Env"].as_array_mut().unwrap();
    let entry = json!(format!("{key}={value}"));
    let at = env
        .iter()
        .position(|e| e.as_str().is_some_and(|t| t.split('=').next() == Some(key)));
    match at {
        Some(i) => env[i] = entry,
        None => env.push(entry),
    }
}

fn drop_env(body: &mut Value, key: &str) {
    body["Env"]
        .as_array_mut()
        .unwrap()
        .retain(|e| e.as_str().is_none_or(|t| t.split('=').next() != Some(key)));
}

fn env_entries(body: &Value) -> Vec<String> {
    body["Env"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e.as_str().unwrap().to_string())
        .collect()
}

// `t<10 hex>_<db>` from the shared tag function; the proxy's own copy is compared in the constants test.
fn role(id: &str, db: &str) -> String {
    format!("t{}_{db}", pg_site_tag(id))
}

// ---------------------------------------------------------------------------------------------------------------
// Job cases written from the contract table

fn job(scope: JobScope, op: JobOp, net: JobNet, major: u8, env: Vec<(String, String)>) -> JobSpec {
    JobSpec {
        scope,
        op,
        net,
        major,
        env: env.into_iter().map(|(k, v)| (k, v.into())).collect(),
        read_only: op == JobOp::Restore,
    }
}

fn internal_env(host: &str, extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut env = vec![
        ("CITE_JOB_ID", JOB),
        ("PGHOST", host),
        ("PGPORT", "5432"),
        ("PGUSER", "postgres"),
        ("PGPASSWORD", SU),
    ];
    env.extend_from_slice(extra);
    env.into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

// The contract: backup, restore, counts and regrant work inside the tenant database and connect as its job login
// `<tag>_job` with a password generated for the job; every other operation is the superuser's.
fn env_for(op: JobOp, host: &str, extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut env = internal_env(host, extra);
    let inside = matches!(
        op,
        JobOp::Backup | JobOp::Restore | JobOp::Counts | JobOp::Regrant
    );
    let tag = extra.iter().find_map(|(k, v)| match *k {
        "CITE_ROLE_TAG" => Some(v.to_string()),
        "CITE_OWNER_ROLE" => v.strip_suffix("_owner").map(str::to_string),
        _ => None,
    });
    if inside && let Some(tag) = tag {
        for (k, v) in env.iter_mut() {
            match k.as_str() {
                "PGUSER" => *v = format!("{tag}_job"),
                "PGPASSWORD" => *v = JOB_PW.to_string(),
                _ => {}
            }
        }
    }
    env
}

// One site and the way its jobs reach the database: its own dbnet (dedicated) or the admin network (shared).
struct Tenant {
    id: String,
    shared: bool,
    major: u8,
}

impl Tenant {
    fn new(id: &str, shared: bool, major: u8) -> Tenant {
        Tenant {
            id: id.to_string(),
            shared,
            major,
        }
    }

    fn net(&self) -> JobNet {
        if self.shared {
            JobNet::SharedAdmin
        } else {
            JobNet::Dbnet
        }
    }

    fn host(&self) -> String {
        if self.shared {
            "cite-pg-shared".to_string()
        } else {
            format!("cite-{}-db", self.id)
        }
    }

    // Dedicated servers use the logical name; the shared instance names a tenant database like its role tag.
    fn db(&self) -> String {
        if self.shared {
            role(&self.id, "app")
        } else {
            "app".to_string()
        }
    }

    fn job(&self, op: JobOp, extra: &[(&str, &str)]) -> JobSpec {
        job(
            JobScope::Site(self.id.clone()),
            op,
            self.net(),
            self.major,
            env_for(op, &self.host(), extra),
        )
    }
}

fn user_job(t: &Tenant, action: &str) -> JobSpec {
    let tag = role(&t.id, "app");
    let login = format!("{tag}_app_a");
    let db = t.db();
    let mut extra = vec![
        ("PGDATABASE", db.as_str()),
        ("CITE_ROLE_TAG", tag.as_str()),
        ("CITE_USER_ACTION", action),
        ("CITE_USER_ROLE", login.as_str()),
        ("CITE_USER_LEVEL", "readwrite"),
        ("CITE_USER_CONN_LIMIT", "20"),
        ("CITE_USER_STMT_MS", "30000"),
        ("CITE_USER_IDLE_MS", "60000"),
    ];
    if matches!(action, "create" | "password") {
        extra.push(("CITE_USER_PASSWORD", USER_PW));
    }
    t.job(JobOp::User, &extra)
}

// Every operation a site job container may run, each labelled with the literal `Cmd` the contract names.
fn site_cases(t: &Tenant) -> Vec<(&'static str, JobSpec)> {
    let tag_text = role(&t.id, "app");
    let owner_text = format!("{tag_text}_owner");
    let login_text = format!("{tag_text}_login");
    let db_text = t.db();
    let (tag, owner, login, db) = (
        tag_text.as_str(),
        owner_text.as_str(),
        login_text.as_str(),
        db_text.as_str(),
    );
    let user_login = format!("{tag}_app_a");
    let mut cases = vec![
        (
            "backup",
            t.job(JobOp::Backup, &[("PGDATABASE", db), ("CITE_ROLE_TAG", tag)]),
        ),
        (
            "counts",
            t.job(JobOp::Counts, &[("PGDATABASE", db), ("CITE_ROLE_TAG", tag)]),
        ),
        (
            "joblogin",
            t.job(
                JobOp::JobLogin,
                &[
                    ("PGDATABASE", db),
                    ("CITE_ROLE_TAG", tag),
                    ("CITE_JOB_ACTION", "open"),
                    ("CITE_JOB_PASSWORD", JOB_PW),
                ],
            ),
        ),
        (
            "joblogin",
            t.job(
                JobOp::JobLogin,
                &[
                    ("PGDATABASE", db),
                    ("CITE_ROLE_TAG", tag),
                    ("CITE_JOB_ACTION", "lock"),
                    ("CITE_JOB_PASSWORD", JOB_PW),
                ],
            ),
        ),
        (
            "joblogin",
            t.job(
                JobOp::JobLogin,
                &[
                    ("PGDATABASE", db),
                    ("CITE_ROLE_TAG", tag),
                    ("CITE_JOB_ACTION", "close"),
                ],
            ),
        ),
        (
            "regrant",
            t.job(
                JobOp::Regrant,
                &[
                    ("PGDATABASE", db),
                    ("CITE_ROLE_TAG", tag),
                    ("CITE_USER_ROLE", user_login.as_str()),
                ],
            ),
        ),
        (
            "restore",
            t.job(
                JobOp::Restore,
                &[
                    ("PGDATABASE", db),
                    ("CITE_OWNER_ROLE", owner),
                    ("CITE_LOGIN_ROLE", login),
                ],
            ),
        ),
        (
            "freeze",
            t.job(
                JobOp::Freeze,
                &[("PGDATABASE", db), ("CITE_LOGIN_ROLE", login)],
            ),
        ),
        (
            "unfreeze",
            t.job(
                JobOp::Unfreeze,
                &[("PGDATABASE", db), ("CITE_LOGIN_ROLE", login)],
            ),
        ),
        (
            "provision",
            t.job(
                JobOp::Provision,
                &[("PGDATABASE", db), ("CITE_ROLE_TAG", tag)],
            ),
        ),
        (
            "provision",
            t.job(
                JobOp::Provision,
                &[("PGDATABASE", "postgres"), ("CITE_ROLE_TAG", tag)],
            ),
        ),
        (
            "deprovision",
            t.job(
                JobOp::Deprovision,
                &[("PGDATABASE", db), ("CITE_ROLE_TAG", tag)],
            ),
        ),
        (
            "deprovision",
            t.job(
                JobOp::Deprovision,
                &[("PGDATABASE", "postgres"), ("CITE_ROLE_TAG", tag)],
            ),
        ),
        (
            "regrant",
            t.job(
                JobOp::Regrant,
                &[("PGDATABASE", db), ("CITE_ROLE_TAG", tag)],
            ),
        ),
    ];
    for action in [
        "create", "password", "settings", "disable", "enable", "retire", "drop",
    ] {
        cases.push(("user", user_job(t, action)));
    }
    cases
}

fn shared_job(major: u8, op: JobOp, extra: &[(&str, &str)]) -> JobSpec {
    job(
        JobScope::Shared,
        op,
        JobNet::SharedAdmin,
        major,
        env_for(op, "cite-pg-shared", extra),
    )
}

// The instance-wide jobs: provisioning and users for any tenant, the hba file, sizes and global objects.
fn shared_cases(major: u8, tenants: &[&str]) -> Vec<(&'static str, JobSpec)> {
    let mut cases = Vec::new();
    for id in tenants {
        let tag_text = role(id, "app");
        let login_text = format!("{tag_text}_app_b");
        let (tag, login) = (tag_text.as_str(), login_text.as_str());
        cases.push((
            "provision",
            shared_job(
                major,
                JobOp::Provision,
                &[("PGDATABASE", tag), ("CITE_ROLE_TAG", tag)],
            ),
        ));
        cases.push((
            "provision",
            shared_job(
                major,
                JobOp::Provision,
                &[("PGDATABASE", "postgres"), ("CITE_ROLE_TAG", tag)],
            ),
        ));
        cases.push((
            "deprovision",
            shared_job(
                major,
                JobOp::Deprovision,
                &[("PGDATABASE", tag), ("CITE_ROLE_TAG", tag)],
            ),
        ));
        // The instance backup: the tenant's job login is opened, dumps its database and is closed.
        cases.push((
            "joblogin",
            shared_job(
                major,
                JobOp::JobLogin,
                &[
                    ("PGDATABASE", tag),
                    ("CITE_ROLE_TAG", tag),
                    ("CITE_JOB_ACTION", "open"),
                    ("CITE_JOB_PASSWORD", JOB_PW),
                ],
            ),
        ));
        cases.push((
            "backup",
            shared_job(
                major,
                JobOp::Backup,
                &[("PGDATABASE", tag), ("CITE_ROLE_TAG", tag)],
            ),
        ));
        cases.push((
            "joblogin",
            shared_job(
                major,
                JobOp::JobLogin,
                &[
                    ("PGDATABASE", tag),
                    ("CITE_ROLE_TAG", tag),
                    ("CITE_JOB_ACTION", "close"),
                ],
            ),
        ));
        cases.push((
            "user",
            shared_job(
                major,
                JobOp::User,
                &[
                    ("PGDATABASE", tag),
                    ("CITE_ROLE_TAG", tag),
                    ("CITE_USER_ACTION", "create"),
                    ("CITE_USER_ROLE", login),
                    ("CITE_USER_LEVEL", "readonly"),
                    ("CITE_USER_CONN_LIMIT", "5"),
                    ("CITE_USER_STMT_MS", "0"),
                    ("CITE_USER_IDLE_MS", "1000"),
                    ("CITE_USER_PASSWORD", USER_PW),
                ],
            ),
        ));
    }
    let hba = format!(
        "_admin|172.30.0.0/16;{}|172.31.0.0/16;{}|172.32.0.0/16",
        role("shop", "app"),
        role("other", "app")
    );
    cases.push((
        "hba",
        shared_job(
            major,
            JobOp::Hba,
            &[("CITE_PG_HBA", hba.as_str()), ("CITE_PG_RELOAD", "1")],
        ),
    ));
    cases.push(("sizes", shared_job(major, JobOp::Sizes, &[])));
    cases.push(("globals", shared_job(major, JobOp::Globals, &[])));
    cases
}

fn external_job(
    net: JobNet,
    host: &str,
    port: &str,
    user: &str,
    db: &str,
    ssl: Option<&str>,
) -> JobSpec {
    let mut env = vec![
        ("CITE_JOB_ID", JOB),
        ("PGHOST", host),
        ("PGPORT", port),
        ("PGUSER", user),
        ("PGPASSWORD", SU),
        ("PGDATABASE", db),
    ];
    if let Some(mode) = ssl {
        env.push(("PGSSLMODE", mode));
    }
    job(
        JobScope::Site("shop".to_string()),
        JobOp::Backup,
        net,
        18,
        env.into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    )
}

// External database backups: on the filtered outbound network through the egress proxy's forward, and on the
// open egress bridge directly. The flag is true for the open egress mode.
fn external_cases() -> Vec<(&'static str, JobSpec, bool)> {
    vec![
        (
            "xnet blue",
            external_job(
                JobNet::Xnet(Slot::Blue),
                "cite-shop-blue-egress-proxy",
                "15432",
                "app_user",
                "appdb",
                Some("require"),
            ),
            false,
        ),
        (
            "xnet green",
            external_job(
                JobNet::Xnet(Slot::Green),
                "cite-shop-green-egress-proxy",
                "15439",
                "svc.user",
                "appdb",
                None,
            ),
            false,
        ),
        (
            "egress blue by name",
            external_job(
                JobNet::Egress(Slot::Blue),
                "db.example.com",
                "5432",
                "reader",
                "appdb",
                Some("verify-full"),
            ),
            true,
        ),
        (
            "egress green by address",
            external_job(
                JobNet::Egress(Slot::Green),
                "203.0.113.9",
                "5432",
                "reader",
                "appdb",
                None,
            ),
            true,
        ),
    ]
}

fn open_policy() -> Policy {
    policy_for(EgressMode::Open)
}

fn job_body(spec: JobSpec) -> (String, Value) {
    let set = data_set(&data_site("shop", "dedicated", 18), 18, &[spec]);
    set.jobs.into_iter().next().unwrap()
}

// ---------------------------------------------------------------------------------------------------------------
// Constants that both sides carry

fn images_toml_postgres_majors() -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../images/images.toml");
    let text = std::fs::read_to_string(&path).expect("images/images.toml");
    let mut majors = Vec::new();
    let mut in_postgres = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_postgres = line == "[[postgres]]";
            continue;
        }
        if in_postgres
            && let Some(rest) = line.strip_prefix("major")
            && let Some(value) = rest.trim_start().strip_prefix('=')
        {
            majors.push(value.trim().parse::<u8>().expect("a major number"));
        }
    }
    majors
}

#[test]
fn the_postgres_majors_agree_across_the_proxy_the_model_and_the_images() {
    assert_eq!(PROXY_PG_MAJORS, PG_MAJORS);
    assert_eq!(PG_MAJORS, [17, 18]);
    let mut toml = images_toml_postgres_majors();
    toml.sort_unstable();
    assert_eq!(
        toml,
        PG_MAJORS.to_vec(),
        "images.toml needs one [[postgres]] per major"
    );
}

#[test]
fn the_site_tag_is_the_same_function_on_both_sides() {
    let mut ids: Vec<String> = (0..100).map(|i| format!("site-{i}")).collect();
    ids.extend(["shop", "a", "x-1", "0", "shop-2"].map(str::to_string));
    for id in &ids {
        let tag = pg_site_tag(id);
        assert_eq!(tag, proxy_site_tag(id), "{id}");
        assert_eq!(tag.len(), 10, "{id}");
        assert!(
            tag.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "{id}"
        );
    }
    let mut tags: Vec<String> = ids.iter().map(|id| pg_site_tag(id)).collect();
    tags.sort();
    tags.dedup();
    assert_eq!(tags.len(), ids.len(), "two ids share a tag");
}

#[test]
fn the_fixed_data_names_are_classified_by_the_proxy_as_the_connector_names_them() {
    assert_eq!(SHARED_DB, "cite-pg-shared");
    assert_eq!(SHARED_DATA, "cite-pg-shared-data");
    assert_eq!(SHARED_CONF, "cite-pg-shared-conf");
    assert_eq!(SHARED_ADMIN, "cite-pg-shared-admin");
    assert_eq!(SHARED_JOB, "cite-pg-shared-job");
    assert_eq!(cite_dockerproxy::spec_data::SHARED_DB, SHARED_DB);
    assert_eq!(cite_dockerproxy::spec_data::SHARED_DATA, SHARED_DATA);
    assert_eq!(cite_dockerproxy::spec_data::SHARED_CONF, SHARED_CONF);
    assert_eq!(cite_dockerproxy::spec_data::SHARED_ADMIN, SHARED_ADMIN);

    let policy = common::policy();
    for id in ["shop", "a", "shop-2", "a1-b2-c3"] {
        let db = policy.data_container(&db_container_name(id)).unwrap();
        assert!(
            matches!(db.role, DataRole::Db) && db.id.as_deref() == Some(id),
            "{id}"
        );
        let job = policy.data_container(&dbjob_name(id)).unwrap();
        assert!(
            matches!(job.role, DataRole::DbJob) && job.id.as_deref() == Some(id),
            "{id}"
        );
        assert!(matches!(
            policy.data_volume(&db_volume_name(id)),
            Some(DataVolume::Site(ref got)) if got == id
        ));
        assert!(matches!(
            policy.data_network(&dbnet_name(id)),
            Some(DataNetwork::Site(ref got)) if got == id
        ));
    }
    assert!(matches!(
        policy.data_container(SHARED_DB).unwrap().role,
        DataRole::SharedDb
    ));
    assert!(matches!(
        policy.data_container(SHARED_JOB).unwrap().role,
        DataRole::SharedJob
    ));
    assert!(matches!(
        policy.data_volume(SHARED_DATA),
        Some(DataVolume::SharedData)
    ));
    assert!(matches!(
        policy.data_volume(SHARED_CONF),
        Some(DataVolume::SharedConf)
    ));
    assert!(matches!(
        policy.data_network(SHARED_ADMIN),
        Some(DataNetwork::SharedAdmin)
    ));
}

#[test]
fn the_connector_names_the_images_the_proxy_pulls_and_nothing_else() {
    let policy = common::policy();
    for major in PG_MAJORS {
        let image = postgres_image(common::REGISTRY, VERSION, major).unwrap();
        assert_eq!(
            image,
            format!("ghcr.io/seggys116/cite-postgres:{VERSION}-pg{major}")
        );
        assert!(policy.is_postgres_image(&image), "{image}");
        let (repo, tag) = image.rsplit_once(':').unwrap();
        let target =
            normalise(&format!("/v1.45/images/create?fromImage={repo}&tag={tag}")).unwrap();
        assert_eq!(
            policy.classify("POST", &target),
            Ok(Route::ImagePull),
            "{image}"
        );
    }
    for major in [16u8, 19, 0] {
        assert!(
            postgres_image(common::REGISTRY, VERSION, major).is_err(),
            "{major}"
        );
        let image = format!("ghcr.io/seggys116/cite-postgres:{VERSION}-pg{major}");
        assert!(!policy.is_postgres_image(&image), "{image}");
        let target = normalise(&format!(
            "/v1.45/images/create?fromImage=ghcr.io/seggys116/cite-postgres&tag={VERSION}-pg{major}"
        ))
        .unwrap();
        assert!(policy.classify("POST", &target).is_err(), "{image}");
    }
}

#[test]
fn the_test_passwords_have_the_generated_shape() {
    for pw in [SU, USER_PW, JOB_PW] {
        assert_eq!(pw.len(), 43);
        assert!(
            pw.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        );
    }
    assert_eq!(JOB.len(), 26);
}

// ---------------------------------------------------------------------------------------------------------------
// Servers, volumes and networks

#[test]
fn dedicated_and_shared_servers_with_their_volumes_and_networks_are_accepted_for_both_majors() {
    let policy = common::policy();
    for major in PG_MAJORS {
        for id in ["shop", "shop-2", "a"] {
            let set = data_set(&data_site(id, "dedicated", major), major, &[]);
            let tag = format!("cite-postgres:{VERSION}-pg{major}");
            assert!(set.image.ends_with(&tag), "{}", set.image);
            assert!(set.shared_image.ends_with(&tag), "{}", set.shared_image);
            assert_eq!(set.names.db, format!("cite-{id}-db"));
            assert_eq!(set.names.db_volume, format!("cite-{id}-db-data"));
            assert_eq!(set.names.dbnet, format!("cite-{id}-dbnet"));
            assert_eq!(set.names.job, format!("cite-{id}-dbjob"));

            accepted(
                create(&policy, &set.names.db, &set.db),
                &format!("{id} db pg{major}"),
            );
            accepted(
                create(&policy, SHARED_DB, &set.shared_db),
                &format!("shared db pg{major}"),
            );
            for (what, body) in [
                ("db volume", &set.db_volume),
                ("shared data volume", &set.shared_data_volume),
                ("shared conf volume", &set.shared_conf_volume),
            ] {
                accepted(policy.validate_body(&Route::VolumeCreate, body), what);
            }
            for (what, body) in [("dbnet", &set.dbnet), ("admin network", &set.shared_admin)] {
                accepted(policy.validate_body(&Route::NetworkCreate, body), what);
            }
        }
    }
}

#[test]
fn the_volume_and_network_bodies_have_the_contract_shape() {
    let set = data_set(&data_site("shop", "dedicated", 18), 18, &[]);
    assert_eq!(
        set.db_volume,
        json!({ "Name": "cite-shop-db-data", "Labels": { "cite.managed": "true", "cite.site": "shop", "cite.volume": "db-data" } })
    );
    assert_eq!(
        set.shared_data_volume,
        json!({ "Name": "cite-pg-shared-data", "Labels": { "cite.managed": "true", "cite.volume": "pg-shared-data" } })
    );
    assert_eq!(
        set.shared_conf_volume,
        json!({ "Name": "cite-pg-shared-conf", "Labels": { "cite.managed": "true", "cite.volume": "pg-shared-conf" } })
    );
    assert_eq!(
        set.dbnet,
        json!({ "Name": "cite-shop-dbnet", "Driver": "bridge", "Internal": true, "Labels": { "cite.managed": "true", "cite.site": "shop", "cite.role": "dbnet" } })
    );
    assert_eq!(
        set.shared_admin,
        json!({ "Name": "cite-pg-shared-admin", "Driver": "bridge", "Internal": true, "Labels": { "cite.managed": "true", "cite.role": "pg-shared-admin" } })
    );
}

#[test]
fn volume_and_network_near_misses_are_refused() {
    let policy = common::policy();
    let set = data_set(&data_site("shop", "dedicated", 18), 18, &[]);
    let volume = |body: &Value| policy.validate_body(&Route::VolumeCreate, body);
    let network = |body: &Value| policy.validate_body(&Route::NetworkCreate, body);

    let v = &set.db_volume;
    refused(
        volume(&edited(v, |b| b["Name"] = json!("cite-other-db-data"))),
        "another site's volume name",
    );
    refused(
        volume(&edited(v, |b| b["Labels"]["cite.site"] = json!("other"))),
        "another site's label",
    );
    refused(
        volume(&edited(v, |b| b["Labels"]["cite.slot"] = json!("blue"))),
        "a slot label",
    );
    refused(
        volume(&edited(v, |b| b["Labels"]["cite.volume"] = json!("data"))),
        "a wrong volume label",
    );
    refused(
        volume(&edited(v, |b| b["Labels"]["cite.extra"] = json!("1"))),
        "an extra label",
    );
    refused(
        volume(&edited(v, |b| {
            b["Labels"].as_object_mut().unwrap().remove("cite.managed");
        })),
        "a missing managed label",
    );
    refused(
        volume(&edited(v, |b| b["Driver"] = json!("local"))),
        "a driver",
    );
    refused(
        volume(&edited(v, |b| {
            b["DriverOpts"] = json!({ "type": "none", "o": "bind", "device": "/" })
        })),
        "bind driver options",
    );
    refused(
        volume(&edited(v, |b| b["Name"] = json!("cite-shop-db-data-2"))),
        "a name outside the scheme",
    );
    refused(
        volume(&edited(v, |b| b["Name"] = json!("cite-shop-blue-data"))),
        "a stack volume name with data labels",
    );

    let data = &set.shared_data_volume;
    let conf = &set.shared_conf_volume;
    refused(
        volume(&edited(data, |b| b["Labels"] = conf["Labels"].clone())),
        "conf labels on the data volume",
    );
    refused(
        volume(&edited(conf, |b| b["Labels"] = data["Labels"].clone())),
        "data labels on the conf volume",
    );
    refused(
        volume(&edited(data, |b| b["Labels"]["cite.site"] = json!("shop"))),
        "a site label on a shared volume",
    );
    refused(
        volume(&edited(data, |b| b["Name"] = json!("cite-pg-shared-other"))),
        "an unknown shared volume",
    );

    let n = &set.dbnet;
    refused(
        network(&edited(n, |b| b["Name"] = json!("cite-other-dbnet"))),
        "another site's network name",
    );
    refused(
        network(&edited(n, |b| b["Internal"] = json!(false))),
        "an external dbnet",
    );
    refused(
        network(&edited(n, |b| b["Driver"] = json!("macvlan"))),
        "a macvlan driver",
    );
    refused(
        network(&edited(n, |b| b["Driver"] = json!("host"))),
        "the host driver",
    );
    refused(
        network(&edited(n, |b| b["Options"] = json!({ "parent": "eth0" }))),
        "driver options",
    );
    refused(
        network(&edited(n, |b| {
            b["IPAM"] = json!({ "Config": [{ "Subnet": "10.0.0.0/8" }] })
        })),
        "an IPAM block",
    );
    refused(
        network(&edited(n, |b| b["Attachable"] = json!(true))),
        "an attachable network",
    );
    refused(
        network(&edited(n, |b| b["EnableIPv6"] = json!(true))),
        "IPv6",
    );
    refused(
        network(&edited(n, |b| b["Labels"]["cite.site"] = json!("other"))),
        "another site's label",
    );
    refused(
        network(&edited(n, |b| b["Labels"]["cite.slot"] = json!("blue"))),
        "a slot label",
    );
    refused(
        network(&edited(n, |b| b["Labels"]["cite.role"] = json!("network"))),
        "the stack network role",
    );
    refused(
        network(&edited(n, |b| b["Name"] = json!("cite-shop-dbnet-2"))),
        "a name outside the scheme",
    );

    let admin = &set.shared_admin;
    refused(
        network(&edited(admin, |b| b["Internal"] = json!(false))),
        "an external admin network",
    );
    refused(
        network(&edited(admin, |b| b["Labels"]["cite.site"] = json!("shop"))),
        "a site label on the admin network",
    );
    refused(
        network(&edited(admin, |b| b["Labels"] = n["Labels"].clone())),
        "dbnet labels on the admin network",
    );
    refused(
        network(&edited(n, |b| b["Name"] = json!("cite-pg-shared-admin"))),
        "admin name with dbnet labels",
    );
}

#[test]
fn server_memory_cpu_and_connection_bounds_follow_the_proxys_limits() {
    let build = |memory_mb: u32, conns: u32| {
        let mut site = base_site("shop", "node");
        site.data.postgres = Some(pg_config("dedicated", 18, memory_mb, conns));
        let set = data_set(&site, 18, &[]);
        (set.names.db.clone(), set.db)
    };
    let default = common::policy();
    let tuned = common::policy_with_limits("32g", "8");
    for (mem, conns) in [(256, 10), (512, 100), (16_384, 1000)] {
        let (name, body) = build(mem, conns);
        accepted(
            create(&default, &name, &body),
            &format!("{mem} MiB {conns} connections"),
        );
    }
    let (name, body) = build(255, 100);
    refused(create(&default, &name, &body), "255 MiB");
    let (name, body) = build(16_385, 100);
    refused(
        create(&default, &name, &body),
        "16385 MiB under the default cap",
    );
    accepted(create(&tuned, &name, &body), "16385 MiB under a 32g cap");
    let (name, body) = build(32_769, 100);
    refused(create(&tuned, &name, &body), "32769 MiB under a 32g cap");
    let (name, body) = build(512, 9);
    refused(create(&default, &name, &body), "9 connections");
    let (name, body) = build(512, 1001);
    refused(create(&default, &name, &body), "1001 connections");
}

#[test]
fn the_server_bodies_cannot_be_changed_by_one_forbidden_thing() {
    let policy = common::policy();
    let set = data_set(&data_site("shop", "dedicated", 18), 18, &[]);
    let db = |edit: &dyn Fn(&mut Value)| create(&policy, "cite-shop-db", &edited(&set.db, edit));
    let shared =
        |edit: &dyn Fn(&mut Value)| create(&policy, SHARED_DB, &edited(&set.shared_db, edit));

    refused(
        db(&|b| put_env(b, "POSTGRES_PASSWORD", "short")),
        "a short password",
    );
    refused(
        db(&|b| put_env(b, "POSTGRES_PASSWORD", &format!("{SU}x"))),
        "a 44 character password",
    );
    refused(
        db(&|b| put_env(b, "POSTGRES_USER", "root")),
        "another superuser",
    );
    refused(
        db(&|b| put_env(b, "POSTGRES_DB", "app")),
        "another initial database",
    );
    refused(
        db(&|b| put_env(b, "POSTGRES_HOST_AUTH_METHOD", "trust")),
        "trust authentication",
    );
    refused(
        db(&|b| put_env(b, "PGDATA", "/var/lib/postgresql/data")),
        "another data directory",
    );
    refused(db(&|b| put_env(b, "LD_PRELOAD", "/tmp/x.so")), "LD_PRELOAD");
    refused(db(&|b| drop_env(b, "PGDATA")), "a missing key");
    refused(db(&|b| b["User"] = json!("0:0")), "root");
    refused(db(&|b| b["User"] = json!("70:0")), "group zero");
    refused(
        db(&|b| {
            b["Cmd"]
                .as_array_mut()
                .unwrap()
                .extend([json!("-c"), json!("fsync=off")])
        }),
        "an extra server setting",
    );
    refused(
        db(&|b| b["Cmd"][2] = json!("listen_addresses=localhost")),
        "another listen address",
    );
    refused(
        db(&|b| b["Cmd"][4] = json!("max_connections=007")),
        "a leading zero",
    );
    refused(
        db(&|b| {
            b["Cmd"]
                .as_array_mut()
                .unwrap()
                .extend([json!("-c"), json!("hba_file=/etc/cite-pg/pg_hba.conf")])
        }),
        "a dedicated server reading the shared hba file",
    );
    refused(
        db(&|b| b["Labels"]["cite.site"] = json!("other")),
        "another site's label",
    );
    refused(
        db(&|b| b["Labels"]["cite.role"] = json!("dbjob")),
        "the job role label",
    );
    refused(
        db(&|b| b["Entrypoint"] = json!(["/bin/sh"])),
        "an entrypoint",
    );
    refused(
        db(&|b| b["HostConfig"]["Mounts"][0]["Source"] = json!("cite-other-db-data")),
        "another site's volume",
    );
    refused(
        db(&|b| b["HostConfig"]["Mounts"][0]["Source"] = json!(SHARED_DATA)),
        "the shared data volume",
    );
    refused(
        db(&|b| b["HostConfig"]["Mounts"][0]["ReadOnly"] = json!(true)),
        "a read-only data directory",
    );
    refused(
        db(&|b| b["HostConfig"]["Mounts"][0]["Target"] = json!("/")),
        "another mount target",
    );
    refused(
        db(&|b| b["HostConfig"]["Mounts"][0]["VolumeOptions"] = json!({ "Subpath": "x" })),
        "a subpath on the data volume",
    );
    refused(
        db(&|b| b["HostConfig"]["NetworkMode"] = json!("cite-other-dbnet")),
        "another site's network mode",
    );
    refused(
        db(&|b| b["HostConfig"]["NetworkMode"] = json!(SHARED_ADMIN)),
        "the admin network for a dedicated server",
    );
    refused(
        db(&|b| b["HostConfig"]["NetworkMode"] = json!("cite_edge")),
        "the edge network",
    );
    refused(
        db(&|b| b["NetworkingConfig"]["EndpointsConfig"] = json!({ "cite-other-dbnet": {} })),
        "another site's endpoint",
    );
    refused(
        db(&|b| b["NetworkingConfig"]["EndpointsConfig"]["cite_edge"] = json!({})),
        "an extra edge endpoint",
    );
    refused(
        db(&|b| b["HostConfig"]["CapDrop"] = json!([])),
        "no dropped capabilities",
    );
    refused(
        db(&|b| b["HostConfig"]["ReadonlyRootfs"] = json!(false)),
        "a writable root",
    );
    refused(
        db(&|b| b["HostConfig"]["SecurityOpt"] = json!(["seccomp=unconfined"])),
        "seccomp off",
    );
    refused(
        db(&|b| b["HostConfig"]["MemorySwap"] = json!(-1)),
        "unlimited swap",
    );
    refused(
        db(&|b| b["HostConfig"]["PidsLimit"] = json!(-1)),
        "unlimited processes",
    );
    refused(
        db(&|b| b["HostConfig"]["ShmSize"] = json!(1i64 << 40)),
        "a huge shared memory",
    );
    refused(
        db(&|b| b["HostConfig"]["RestartPolicy"] = json!({ "Name": "always" })),
        "another restart policy",
    );
    refused(
        db(&|b| b["Healthcheck"]["Test"] = json!(["CMD-SHELL", "id"])),
        "another health check",
    );
    refused(
        create(&policy, "cite-other-db", &set.db),
        "the body of one site under another site's name",
    );
    refused(
        create(&policy, SHARED_DB, &set.db),
        "a dedicated body under the shared name",
    );
    refused(
        create(&policy, "cite-shop-db", &set.shared_db),
        "the shared body under a site name",
    );
    refused(
        create(&policy, SHARED_JOB, &set.shared_db),
        "the shared body under the job name",
    );

    refused(
        shared(&|b| b["HostConfig"]["Mounts"][1]["ReadOnly"] = json!(false)),
        "a writable hba volume",
    );
    refused(
        shared(&|b| b["HostConfig"]["Mounts"][1]["Source"] = json!(SHARED_DATA)),
        "another volume as the hba volume",
    );
    refused(
        shared(&|b| {
            b["HostConfig"]["Mounts"].as_array_mut().unwrap().pop();
        }),
        "no hba volume",
    );
    refused(
        shared(&|b| {
            b["Cmd"].as_array_mut().unwrap().truncate(13);
        }),
        "no hba file setting",
    );
    refused(
        shared(&|b| b["HostConfig"]["NetworkMode"] = json!("cite-shop-dbnet")),
        "a site's network for the shared server",
    );
    refused(
        shared(&|b| b["NetworkingConfig"]["EndpointsConfig"]["cite-shop-dbnet"] = json!({})),
        "a tenant endpoint at creation",
    );
    refused(
        shared(&|b| b["Labels"]["cite.site"] = json!("shop")),
        "a site label on the shared server",
    );
    refused(
        shared(&|b| b["Labels"]["cite.role"] = json!("db")),
        "the site role on the shared server",
    );
}

// ---------------------------------------------------------------------------------------------------------------
// Jobs

const OPS: [&str; 13] = [
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
];

// Exhaustive on purpose: a new operation fails to compile here until the cases above learn about it.
fn literal(op: JobOp) -> &'static str {
    match op {
        JobOp::Backup => "backup",
        JobOp::Restore => "restore",
        JobOp::Counts => "counts",
        JobOp::JobLogin => "joblogin",
        JobOp::Freeze => "freeze",
        JobOp::Unfreeze => "unfreeze",
        JobOp::Provision => "provision",
        JobOp::Deprovision => "deprovision",
        JobOp::Regrant => "regrant",
        JobOp::User => "user",
        JobOp::Hba => "hba",
        JobOp::Sizes => "sizes",
        JobOp::Globals => "globals",
    }
}

#[test]
fn every_job_operation_has_the_command_the_contract_names_and_a_case() {
    for op in [
        JobOp::Backup,
        JobOp::Restore,
        JobOp::Counts,
        JobOp::JobLogin,
        JobOp::Freeze,
        JobOp::Unfreeze,
        JobOp::Provision,
        JobOp::Deprovision,
        JobOp::Regrant,
        JobOp::User,
        JobOp::Hba,
        JobOp::Sizes,
        JobOp::Globals,
    ] {
        assert_eq!(op.arg(), literal(op));
        assert!(OPS.contains(&op.arg()));
    }
    let mut seen: Vec<&str> = Vec::new();
    for shared in [false, true] {
        seen.extend(
            site_cases(&Tenant::new("shop", shared, 18))
                .iter()
                .map(|(l, _)| *l),
        );
    }
    seen.extend(shared_cases(18, &["shop"]).iter().map(|(l, _)| *l));
    for op in OPS {
        assert!(seen.contains(&op), "no accepted case for {op}");
    }
}

#[test]
fn every_job_of_a_dedicated_and_a_shared_site_is_accepted_for_both_majors() {
    let policy = common::policy();
    let mut checked = 0;
    for major in PG_MAJORS {
        for id in ["shop", "shop-2"] {
            for shared in [false, true] {
                let cases = site_cases(&Tenant::new(id, shared, major));
                let specs: Vec<JobSpec> = cases.iter().map(|(_, s)| s.clone()).collect();
                let set = data_set(
                    &data_site(id, if shared { "shared" } else { "dedicated" }, major),
                    major,
                    &specs,
                );
                assert_eq!(set.jobs.len(), cases.len());
                for ((op, _), (name, body)) in cases.iter().zip(&set.jobs) {
                    let what = format!("{id} shared={shared} pg{major} {op}");
                    assert_eq!(name, &format!("cite-{id}-dbjob"), "{what}");
                    assert_eq!(body["Cmd"], json!([op]), "{what}");
                    assert_eq!(body["Entrypoint"], json!(["cite-pg-job"]), "{what}");
                    assert!(
                        body["Image"]
                            .as_str()
                            .unwrap()
                            .ends_with(&format!("-pg{major}")),
                        "{what}"
                    );
                    let ro = *op == "restore";
                    assert_eq!(
                        body["HostConfig"]["Mounts"][0]["ReadOnly"],
                        json!(ro),
                        "{what}"
                    );
                    assert_eq!(
                        body["HostConfig"]["Mounts"][0]["VolumeOptions"]["Subpath"],
                        json!(format!("staging/{id}")),
                        "{what}"
                    );
                    assert_eq!(
                        body["HostConfig"]["Mounts"].as_array().unwrap().len(),
                        1,
                        "{what}"
                    );
                    let net = if shared {
                        SHARED_ADMIN.to_string()
                    } else {
                        format!("cite-{id}-dbnet")
                    };
                    assert_eq!(body["HostConfig"]["NetworkMode"], json!(net), "{what}");
                    accepted(create(&policy, name, body), &what);
                    checked += 1;
                }
            }
        }
        let cases = shared_cases(major, &["shop", "other"]);
        let specs: Vec<JobSpec> = cases.iter().map(|(_, s)| s.clone()).collect();
        let set = data_set(&data_site("shop", "shared", major), major, &specs);
        for ((op, _), (name, body)) in cases.iter().zip(&set.jobs) {
            let what = format!("shared job pg{major} {op}");
            assert_eq!(name, SHARED_JOB, "{what}");
            assert_eq!(body["Cmd"], json!([op]), "{what}");
            assert_eq!(
                body["HostConfig"]["Mounts"][0]["VolumeOptions"]["Subpath"],
                json!("staging/_shared"),
                "{what}"
            );
            assert_eq!(
                body["Labels"],
                json!({ "cite.managed": "true", "cite.role": "pg-shared-job" }),
                "{what}"
            );
            let mounts = body["HostConfig"]["Mounts"].as_array().unwrap();
            assert_eq!(mounts.len(), if *op == "hba" { 2 } else { 1 }, "{what}");
            if *op == "hba" {
                assert_eq!(
                    mounts[1],
                    json!({ "Type": "volume", "Source": SHARED_CONF, "Target": "/conf", "ReadOnly": false }),
                );
            }
            accepted(create(&policy, name, body), &what);
            checked += 1;
        }
    }
    assert!(checked > 100, "{checked} bodies");
}

#[test]
fn external_database_backups_are_accepted_on_the_outbound_network_of_the_nodes_egress_mode() {
    for (what, spec, open) in external_cases() {
        let (name, body) = job_body(spec);
        assert_eq!(name, "cite-shop-dbjob");
        let (right, wrong) = if open {
            (open_policy(), common::policy())
        } else {
            (common::policy(), open_policy())
        };
        accepted(create(&right, &name, &body), what);
        refused(
            create(&wrong, &name, &body),
            &format!("{what} in the other egress mode"),
        );
        refused(
            create(&policy_for(EgressMode::Off), &name, &body),
            &format!("{what} with outbound access off"),
        );
        assert_eq!(body["Cmd"], json!(["backup"]));
        assert_eq!(body["HostConfig"]["Mounts"][0]["ReadOnly"], json!(false));
    }
}

#[test]
// An attached external database keeps its own port (`ExternalPostgres.port` is any u16, and the filtered mode
// forwards it). In open mode the connector puts that port into PGPORT of the backup job on the egress bridge, so
// a database on 6432 or 25060 must be backed up like one on 5432. The contract text (C5 value rules) says PGPORT
// is 5432 except on xnet, so this is expected to fail until the two sides agree.
fn an_external_backup_on_the_open_egress_bridge_may_use_the_databases_own_port() {
    let open = open_policy();
    for port in ["5432", "6432", "25060"] {
        let (name, body) = job_body(external_job(
            JobNet::Egress(Slot::Blue),
            "db.example.com",
            port,
            "reader",
            "appdb",
            None,
        ));
        accepted(
            create(&open, &name, &body),
            &format!("an external backup on port {port}"),
        );
    }
}

#[test]
fn external_backups_cannot_reach_anything_but_the_own_forward_or_a_plain_host() {
    let filtered = common::policy();
    let open = open_policy();
    let xnet = |host: &str, port: &str| {
        job_body(external_job(
            JobNet::Xnet(Slot::Blue),
            host,
            port,
            "app_user",
            "appdb",
            None,
        ))
    };
    let (name, ok) = xnet("cite-shop-blue-egress-proxy", "15432");
    accepted(create(&filtered, &name, &ok), "the baseline");
    for (host, port, what) in [
        (
            "db.example.com",
            "15432",
            "a direct host on the filtered network",
        ),
        (
            "cite-shop-green-egress-proxy",
            "15432",
            "the other slot's proxy",
        ),
        (
            "cite-other-blue-egress-proxy",
            "15432",
            "another site's proxy",
        ),
        (
            "cite-shop-blue-egress-proxy",
            "5432",
            "the plain port on the forward network",
        ),
        (
            "cite-shop-blue-egress-proxy",
            "15431",
            "a port below the forwards",
        ),
        (
            "cite-shop-blue-egress-proxy",
            "15440",
            "a port above the forwards",
        ),
        ("cite-shop-blue-egress-proxy", "015432", "a padded port"),
    ] {
        let (name, body) = xnet(host, port);
        refused(create(&filtered, &name, &body), what);
    }
    let direct = |host: &str, port: &str| {
        job_body(external_job(
            JobNet::Egress(Slot::Blue),
            host,
            port,
            "reader",
            "appdb",
            None,
        ))
    };
    let (name, body) = direct("db.example.com", "5432");
    accepted(create(&open, &name, &body), "the open baseline");
    for (host, port, what) in [
        ("Db.Example.com", "5432", "an uppercase host"),
        ("db.example.com\n", "5432", "a host with a line break"),
        ("db example", "5432", "a host with a space"),
        ("", "5432", "an empty host"),
        ("db.example.com", "5432 ", "a port with a space"),
        ("db.example.com", "0", "port zero"),
        ("db.example.com", "65536", "a port above 65535"),
    ] {
        let (name, body) = direct(host, port);
        refused(create(&open, &name, &body), what);
    }
    for (net, what) in [
        (JobNet::Xnet(Slot::Blue), "a different net"),
        (JobNet::Egress(Slot::Blue), "a different net"),
    ] {
        let (name, mut body) = xnet("cite-shop-blue-egress-proxy", "15432");
        let other = match net {
            JobNet::Xnet(_) => "cite-other-blue-xnet",
            _ => "cite-other-blue-egress",
        };
        body["HostConfig"]["NetworkMode"] = json!(other);
        body["NetworkingConfig"]["EndpointsConfig"] = json!({ other: {} });
        refused(
            create(&filtered, &name, &body),
            &format!("another site's outbound network ({what})"),
        );
        refused(
            create(&open, &name, &body),
            &format!("another site's outbound network ({what}), open"),
        );
    }
}

#[test]
fn operations_outside_their_scope_or_network_are_refused_with_the_reason() {
    let policy = common::policy();
    let tenant = Tenant::new("shop", false, 18);
    let tag = role("shop", "app");
    // Instance-wide operations never run in a site job.
    for (op, extra) in [
        (
            JobOp::Hba,
            vec![
                ("CITE_PG_HBA", "_admin|172.30.0.0/16"),
                ("CITE_PG_RELOAD", "0"),
            ],
        ),
        (JobOp::Sizes, vec![]),
        (JobOp::Globals, vec![]),
    ] {
        let (name, body) = job_body(tenant.job(op, &extra));
        let reason = create(&policy, &name, &body).unwrap_err();
        assert!(
            reason.contains("does not run in this container"),
            "{op:?}: {reason}"
        );
    }
    // Per-site operations never run in the shared job (backup is pinned separately by the instance backup test).
    let db = tag.clone();
    let login = format!("{tag}_login");
    let owner = format!("{tag}_owner");
    for (op, extra) in [
        (JobOp::Counts, vec![("PGDATABASE", db.as_str())]),
        (
            JobOp::Restore,
            vec![
                ("PGDATABASE", db.as_str()),
                ("CITE_OWNER_ROLE", owner.as_str()),
                ("CITE_LOGIN_ROLE", login.as_str()),
            ],
        ),
        (
            JobOp::Freeze,
            vec![
                ("PGDATABASE", db.as_str()),
                ("CITE_LOGIN_ROLE", login.as_str()),
            ],
        ),
        (
            JobOp::Unfreeze,
            vec![
                ("PGDATABASE", db.as_str()),
                ("CITE_LOGIN_ROLE", login.as_str()),
            ],
        ),
        (
            JobOp::Regrant,
            vec![("PGDATABASE", db.as_str()), ("CITE_ROLE_TAG", tag.as_str())],
        ),
    ] {
        let (name, body) = job_body(shared_job(18, op, &extra));
        let reason = create(&policy, &name, &body).unwrap_err();
        assert!(
            reason.contains("does not run in this container"),
            "{op:?}: {reason}"
        );
    }
    // Only a backup may leave the node's internal networks.
    let open = open_policy();
    for op in [JobOp::Counts, JobOp::Provision, JobOp::Restore, JobOp::User] {
        for (net, host, port, p) in [
            (
                JobNet::Xnet(Slot::Blue),
                "cite-shop-blue-egress-proxy",
                "15432",
                &policy,
            ),
            (JobNet::Egress(Slot::Blue), "db.example.com", "5432", &open),
        ] {
            let env = vec![
                ("CITE_JOB_ID", JOB),
                ("PGHOST", host),
                ("PGPORT", port),
                ("PGUSER", "reader"),
                ("PGPASSWORD", SU),
                ("PGDATABASE", "app"),
            ];
            let spec = job(
                JobScope::Site("shop".to_string()),
                op,
                net,
                18,
                env.into_iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            );
            let (name, body) = job_body(spec);
            let reason = create(p, &name, &body).unwrap_err();
            assert!(
                reason.contains("not allowed for this job operation"),
                "{op:?} {net:?}: {reason}"
            );
        }
    }
}

#[test]
// The whole-instance backup (design M6, `shared.rs:instance_parts`) runs `globals` and then one `backup` per
// tenant database, all in the shared job container, each as that database's job login.
fn the_instance_backup_dumps_each_tenant_database_through_the_shared_job() {
    let policy = common::policy();
    let tag = role("shop", "app");
    let spec = shared_job(
        18,
        JobOp::Backup,
        &[
            ("PGDATABASE", tag.as_str()),
            ("CITE_ROLE_TAG", tag.as_str()),
        ],
    );
    let (name, body) = job_body(spec);
    assert_eq!(name, SHARED_JOB);
    accepted(
        create(&policy, &name, &body),
        "a tenant database dump in the shared job",
    );
    // Never as the superuser, never as another tenant's job login, and never without the tag.
    let (_, su) = job_body(job(
        JobScope::Shared,
        JobOp::Backup,
        JobNet::SharedAdmin,
        18,
        internal_env(
            "cite-pg-shared",
            &[
                ("PGDATABASE", tag.as_str()),
                ("CITE_ROLE_TAG", tag.as_str()),
            ],
        ),
    ));
    refused(
        create(&policy, &name, &su),
        "an instance backup as the superuser",
    );
    let mut other = body.clone();
    put_env(
        &mut other,
        "PGUSER",
        &format!("{}_job", role("other", "app")),
    );
    refused(create(&policy, &name, &other), "another tenant's job login");
    let mut untagged = body.clone();
    drop_env(&mut untagged, "CITE_ROLE_TAG");
    refused(
        create(&policy, &name, &untagged),
        "an untagged instance backup",
    );
}

#[test]
fn a_shared_job_stays_on_the_admin_network_and_never_on_a_site_network() {
    let policy = common::policy();
    let (name, body) = job_body(shared_job(18, JobOp::Sizes, &[]));
    accepted(create(&policy, &name, &body), "the baseline");
    for net in [
        "cite-shop-dbnet",
        "cite-shop-blue-xnet",
        "cite-shop-blue-egress",
        "cite_edge",
        "bridge",
    ] {
        let bad = edited(&body, |b| {
            b["HostConfig"]["NetworkMode"] = json!(net);
            b["NetworkingConfig"]["EndpointsConfig"] = json!({ net: {} });
        });
        refused(
            create(&policy, &name, &bad),
            &format!("the shared job on {net}"),
        );
    }
    refused(
        create(
            &policy,
            &name,
            &edited(&body, |b| {
                b["HostConfig"]["Mounts"][0]["VolumeOptions"]["Subpath"] = json!("staging/shop")
            }),
        ),
        "the shared job on a site's staging directory",
    );
    refused(
        create(&policy, "cite-shop-dbjob", &body),
        "the shared body under a site job name",
    );
}

#[test]
fn a_job_body_cannot_be_changed_by_one_forbidden_thing() {
    let policy = common::policy();
    let t = Tenant::new("shop", false, 18);
    let db = t.db();
    let own_tag = role("shop", "app");
    let (name, backup) = job_body(t.job(
        JobOp::Backup,
        &[
            ("PGDATABASE", db.as_str()),
            ("CITE_ROLE_TAG", own_tag.as_str()),
        ],
    ));
    accepted(create(&policy, &name, &backup), "the backup baseline");
    let run = |edit: &dyn Fn(&mut Value)| create(&policy, &name, &edited(&backup, edit));

    refused(run(&|b| put_env(b, "CITE_EXTRA", "1")), "an extra env key");
    refused(
        run(&|b| {
            put_env(
                b,
                "CITE_USER_ROLE",
                &format!("{}_app_a", role("shop", "app")),
            )
        }),
        "another operation's env key",
    );
    refused(
        run(&|b| put_env(b, "PGUSER", "postgres")),
        "the superuser inside a tenant database",
    );
    refused(
        run(&|b| put_env(b, "PGUSER", &format!("{}_owner", role("shop", "app")))),
        "the owner group instead of the job login",
    );
    refused(
        run(&|b| put_env(b, "PGPASSWORD", "not a generated password")),
        "a job login password of another shape",
    );
    refused(
        run(&|b| drop_env(b, "CITE_ROLE_TAG")),
        "a managed backup without its tag",
    );
    refused(
        run(&|b| put_env(b, "CITE_ROLE_TAG", &role("shop", "auth"))),
        "a tag of another database than the job login's",
    );
    refused(
        run(&|b| put_env(b, "CITE_JOB_PASSWORD", JOB_PW)),
        "a job login password on a backup",
    );
    refused(
        run(&|b| put_env(b, "CITE_USER_PASSWORD", USER_PW)),
        "a password on a backup",
    );
    refused(
        run(&|b| put_env(b, "PGSERVICEFILE", "/etc/passwd")),
        "a libpq file variable",
    );
    refused(
        run(&|b| put_env(b, "LD_PRELOAD", "/tmp/x.so")),
        "LD_PRELOAD",
    );
    refused(
        run(&|b| put_env(b, "PGPASSWORD", "line\nbreak")),
        "a control character",
    );
    refused(run(&|b| put_env(b, "PGPASSWORD", "")), "an empty password");
    refused(
        run(&|b| put_env(b, "PGUSER", "root")),
        "another database user",
    );
    refused(run(&|b| put_env(b, "PGPORT", "5433")), "another port");
    refused(
        run(&|b| put_env(b, "PGHOST", "cite-shop-db.evil")),
        "another host",
    );
    refused(
        run(&|b| put_env(b, "PGHOST", SHARED_DB)),
        "the shared host on a dedicated network",
    );
    refused(
        run(&|b| put_env(b, "CITE_JOB_ID", "01hzx3k9m2n4p5q6r7s8t9v0wx")),
        "a lowercase job id",
    );
    refused(
        run(&|b| put_env(b, "CITE_JOB_ID", "short")),
        "a short job id",
    );
    refused(
        run(&|b| put_env(b, "PGDATABASE", "postgres")),
        "the maintenance database for a backup",
    );
    refused(run(&|b| put_env(b, "PGDATABASE", "template0")), "template0");
    refused(
        run(&|b| put_env(b, "PGDATABASE", &role("shop", "app"))),
        "a shared-style name on a dedicated server",
    );
    refused(run(&|b| drop_env(b, "PGPASSWORD")), "a missing password");
    refused(run(&|b| drop_env(b, "PGDATABASE")), "a missing database");
    refused(
        run(&|b| {
            b["Env"]
                .as_array_mut()
                .unwrap()
                .push(json!("PGDATABASE=app"))
        }),
        "a repeated key",
    );
    refused(
        run(&|b| b["Cmd"] = json!(["backup", "--all"])),
        "an extra argument",
    );
    refused(run(&|b| b["Cmd"] = json!(["sh"])), "an unknown command");
    refused(run(&|b| b["Cmd"] = json!([])), "no command");
    refused(
        run(&|b| b["Entrypoint"] = json!(["/bin/sh", "-c"])),
        "another entrypoint",
    );
    refused(run(&|b| b["User"] = json!("0:0")), "root");
    refused(run(&|b| b["User"] = json!("70:70")), "the server user");
    refused(
        run(&|b| b["Image"] = json!("ghcr.io/seggys116/cite-postgres:0.5.0-pg16")),
        "an unsupported major",
    );
    refused(
        run(&|b| b["Image"] = json!("ghcr.io/seggys116/cite-postgres:latest")),
        "a floating tag",
    );
    refused(
        run(&|b| b["Image"] = json!("ghcr.io/seggys116/cite-manager:0.5.0-node22")),
        "another cite image",
    );
    refused(run(&|b| b["Image"] = json!("alpine")), "a foreign image");
    refused(
        run(&|b| b["HostConfig"]["Mounts"][0]["ReadOnly"] = json!(true)),
        "a read-only staging directory for a backup",
    );
    refused(
        run(&|b| b["HostConfig"]["Mounts"][0]["Source"] = json!("cite-other-backups")),
        "another volume as the backup volume",
    );
    refused(
        run(&|b| b["HostConfig"]["Mounts"][0]["Target"] = json!("/")),
        "another mount target",
    );
    refused(
        run(&|b| b["HostConfig"]["Mounts"][0]["Type"] = json!("bind")),
        "a bind mount",
    );
    refused(
        run(&|b| {
            b["HostConfig"]["Mounts"][0]["VolumeOptions"]
                .as_object_mut()
                .unwrap()
                .remove("Subpath");
        }),
        "the whole backup volume",
    );
    refused(
        run(&|b| {
            b["HostConfig"]["Mounts"].as_array_mut().unwrap().push(json!({ "Type": "volume", "Source": SHARED_CONF, "Target": "/conf", "ReadOnly": false }))
        }),
        "the hba volume on a backup",
    );
    refused(
        run(&|b| {
            b["HostConfig"]["Mounts"].as_array_mut().unwrap().push(json!({ "Type": "volume", "Source": "cite-shop-db-data", "Target": "/data", "ReadOnly": false }))
        }),
        "the data volume in a job",
    );
    refused(
        run(&|b| b["HostConfig"]["Memory"] = json!(1i64 << 33)),
        "more memory",
    );
    refused(
        run(&|b| b["HostConfig"]["PidsLimit"] = json!(4096)),
        "more processes",
    );
    refused(
        run(&|b| b["HostConfig"]["NanoCpus"] = json!(8_000_000_000i64)),
        "more CPUs",
    );
    refused(
        run(&|b| b["HostConfig"]["RestartPolicy"] = json!({ "Name": "always" })),
        "a restart policy",
    );
    refused(
        run(&|b| b["HostConfig"]["ReadonlyRootfs"] = json!(false)),
        "a writable root",
    );
    refused(
        run(&|b| b["HostConfig"]["CapDrop"] = json!([])),
        "no dropped capabilities",
    );
    refused(
        run(&|b| b["HostConfig"]["Tmpfs"]["/tmp"] = json!("size=64g")),
        "a large tmpfs",
    );
    refused(
        run(&|b| b["Healthcheck"] = json!({ "Test": ["CMD", "id"] })),
        "a health check",
    );
    refused(
        run(&|b| b["Labels"]["cite.role"] = json!("db")),
        "the server role label",
    );
    refused(
        run(&|b| b["Labels"]["cite.site"] = json!("other")),
        "another site's label",
    );
    refused(
        run(&|b| b["Labels"]["cite.slot"] = json!("blue")),
        "a slot label",
    );

    let restore_t = Tenant::new("shop", false, 18);
    let tag = role("shop", "app");
    let (owner, login) = (format!("{tag}_owner"), format!("{tag}_login"));
    let (rname, restore) = job_body(restore_t.job(
        JobOp::Restore,
        &[
            ("PGDATABASE", db.as_str()),
            ("CITE_OWNER_ROLE", owner.as_str()),
            ("CITE_LOGIN_ROLE", login.as_str()),
        ],
    ));
    accepted(create(&policy, &rname, &restore), "the restore baseline");
    refused(
        create(
            &policy,
            &rname,
            &edited(&restore, |b| {
                b["HostConfig"]["Mounts"][0]["ReadOnly"] = json!(false)
            }),
        ),
        "a writable staging directory for a restore",
    );
    refused(
        create(
            &policy,
            &rname,
            &edited(&restore, |b| put_env(b, "PGSSLMODE", "disable")),
        ),
        "an ssl mode on a restore",
    );
    refused(
        create(
            &policy,
            &rname,
            &edited(&restore, |b| {
                put_env(
                    b,
                    "CITE_LOGIN_ROLE",
                    &format!("{}_login", role("shop", "other")),
                )
            }),
        ),
        "an owner and a login of different databases",
    );
}

#[test]
fn one_sites_job_cannot_use_another_sites_network_staging_directory_roles_or_databases() {
    let policy = common::policy();
    for shared in [false, true] {
        let shop = Tenant::new("shop", shared, 18);
        let other = Tenant::new("other", shared, 18);
        let shop_cases = site_cases(&shop);
        let other_cases = site_cases(&other);
        let shop_set = data_set(
            &data_site("shop", if shared { "shared" } else { "dedicated" }, 18),
            18,
            &shop_cases
                .iter()
                .map(|(_, s)| s.clone())
                .collect::<Vec<_>>(),
        );
        for ((op, _), (name, body)) in shop_cases.iter().zip(&shop_set.jobs) {
            let what = format!("shared={shared} {op}");
            accepted(create(&policy, name, body), &what);
            // The same body under another site's job name.
            refused(
                create(&policy, "cite-other-dbjob", body),
                &format!("{what} under another site's name"),
            );
            refused(
                create(&policy, SHARED_JOB, body),
                &format!("{what} under the shared job name"),
            );
            // The staging subpath of another site, of the shared job, of the whole volume.
            for sub in [
                "staging/other",
                "staging/_shared",
                "staging",
                "staging/shop/..",
                "staging/shop/x",
                "other",
            ] {
                let bad = edited(body, |b| {
                    b["HostConfig"]["Mounts"][0]["VolumeOptions"]["Subpath"] = json!(sub)
                });
                refused(
                    create(&policy, name, &bad),
                    &format!("{what} with subpath {sub}"),
                );
            }
            // The network of another site, both as the mode and as the endpoint.
            let net = if shared {
                SHARED_ADMIN
            } else {
                "cite-shop-dbnet"
            };
            for foreign in [
                "cite-other-dbnet",
                "cite-other-blue-xnet",
                "cite-other-blue-egress",
            ] {
                let bad = edited(body, |b| {
                    b["HostConfig"]["NetworkMode"] = json!(foreign);
                    b["NetworkingConfig"]["EndpointsConfig"] = json!({ foreign: {} });
                });
                refused(create(&policy, name, &bad), &format!("{what} on {foreign}"));
            }
            let both = edited(body, |b| {
                b["NetworkingConfig"]["EndpointsConfig"]["cite-other-dbnet"] = json!({})
            });
            refused(
                create(&policy, name, &both),
                &format!("{what} on {net} and another site's dbnet"),
            );
            // The labels of another site.
            let bad = edited(body, |b| b["Labels"]["cite.site"] = json!("other"));
            refused(
                create(&policy, name, &bad),
                &format!("{what} with another site's label"),
            );
        }
        // The other site's own jobs are accepted under its own name only.
        let other_set = data_set(
            &data_site("other", if shared { "shared" } else { "dedicated" }, 18),
            18,
            &other_cases
                .iter()
                .map(|(_, s)| s.clone())
                .collect::<Vec<_>>(),
        );
        for ((op, _), (name, body)) in other_cases.iter().zip(&other_set.jobs) {
            accepted(
                create(&policy, name, body),
                &format!("other shared={shared} {op}"),
            );
            refused(
                create(&policy, "cite-shop-dbjob", body),
                &format!("other {op} under shop's name"),
            );
        }
    }
}

#[test]
fn roles_and_databases_of_another_site_are_refused_in_a_site_job() {
    let policy = common::policy();
    let other_tag = role("other", "app");
    let own_tag = role("shop", "app");
    for shared in [false, true] {
        let shop = Tenant::new("shop", shared, 18);
        let cases = site_cases(&shop);
        let set = data_set(
            &data_site("shop", if shared { "shared" } else { "dedicated" }, 18),
            18,
            &cases.iter().map(|(_, s)| s.clone()).collect::<Vec<_>>(),
        );
        for ((op, _), (name, body)) in cases.iter().zip(&set.jobs) {
            let what = format!("shared={shared} {op}");
            let has = |key: &str| {
                env_entries(body)
                    .iter()
                    .any(|e| e.starts_with(&format!("{key}=")))
            };
            if has("CITE_ROLE_TAG") {
                refused(
                    create(
                        &policy,
                        name,
                        &edited(body, |b| put_env(b, "CITE_ROLE_TAG", &other_tag)),
                    ),
                    &format!("{what} naming another site's tag"),
                );
            }
            if has("CITE_OWNER_ROLE") {
                refused(
                    create(
                        &policy,
                        name,
                        &edited(body, |b| {
                            put_env(b, "CITE_OWNER_ROLE", &format!("{other_tag}_owner"))
                        }),
                    ),
                    &format!("{what} naming another site's owner"),
                );
            }
            if has("CITE_LOGIN_ROLE") {
                refused(
                    create(
                        &policy,
                        name,
                        &edited(body, |b| {
                            put_env(b, "CITE_LOGIN_ROLE", &format!("{other_tag}_login"))
                        }),
                    ),
                    &format!("{what} naming another site's login"),
                );
            }
            if has("CITE_USER_ROLE") {
                refused(
                    create(
                        &policy,
                        name,
                        &edited(body, |b| {
                            put_env(b, "CITE_USER_ROLE", &format!("{other_tag}_app_a"))
                        }),
                    ),
                    &format!("{what} naming another site's user"),
                );
            }
            if shared && has("PGDATABASE") {
                let current = env_entries(body)
                    .into_iter()
                    .find(|e| e.starts_with("PGDATABASE="))
                    .unwrap();
                if current != "PGDATABASE=postgres" {
                    refused(
                        create(
                            &policy,
                            name,
                            &edited(body, |b| put_env(b, "PGDATABASE", &other_tag)),
                        ),
                        &format!("{what} on another tenant's database"),
                    );
                }
            }
            put_env_check_own(&policy, name, body, &own_tag, &what);
        }
    }
}

// Writing the site's own tag back must leave an already valid body valid, so the checks above fail only because
// of the other site's name.
fn put_env_check_own(policy: &Policy, name: &str, body: &Value, own_tag: &str, what: &str) {
    if env_entries(body)
        .iter()
        .any(|e| e.starts_with("CITE_ROLE_TAG="))
    {
        accepted(
            create(
                policy,
                name,
                &edited(body, |b| put_env(b, "CITE_ROLE_TAG", own_tag)),
            ),
            what,
        );
    }
}

#[test]
fn user_password_and_hba_values_follow_the_contract_grammar() {
    let policy = common::policy();
    let t = Tenant::new("shop", false, 18);
    let check = |spec: JobSpec| {
        let (name, body) = job_body(spec);
        create(&policy, &name, &body)
    };
    accepted(check(user_job(&t, "create")), "create with a password");
    accepted(check(user_job(&t, "retire")), "retire without a password");
    // A password travels with create and password only.
    let tag = role("shop", "app");
    let login = format!("{tag}_app_a");
    let db = t.db();
    let base = |action: &'static str| {
        vec![
            ("PGDATABASE", db.as_str()),
            ("CITE_ROLE_TAG", tag.as_str()),
            ("CITE_USER_ACTION", action),
            ("CITE_USER_ROLE", login.as_str()),
            ("CITE_USER_LEVEL", "readwrite"),
            ("CITE_USER_CONN_LIMIT", "20"),
            ("CITE_USER_STMT_MS", "30000"),
            ("CITE_USER_IDLE_MS", "60000"),
        ]
    };
    refused(
        check(t.job(JobOp::User, &base("create"))),
        "create without a password",
    );
    let mut with_pw = base("drop");
    with_pw.push(("CITE_USER_PASSWORD", USER_PW));
    refused(check(t.job(JobOp::User, &with_pw)), "drop with a password");
    let mut short = base("password");
    short.push(("CITE_USER_PASSWORD", "short"));
    refused(check(t.job(JobOp::User, &short)), "a short password");
    for (key, value, what) in [
        ("CITE_USER_ACTION", "grant", "an unknown action"),
        ("CITE_USER_LEVEL", "superuser", "an unknown level"),
        ("CITE_USER_CONN_LIMIT", "0", "no connections"),
        ("CITE_USER_CONN_LIMIT", "501", "too many connections"),
        ("CITE_USER_STMT_MS", "3600001", "a long statement timeout"),
        ("CITE_USER_IDLE_MS", "999", "a short idle timeout"),
        (
            "CITE_USER_ROLE",
            "postgres",
            "the superuser as the user role",
        ),
        (
            "CITE_USER_ROLE",
            "tdeadbeef00_app_app_a",
            "a role of an unknown tag",
        ),
    ] {
        let mut env = base("settings");
        env.retain(|(k, _)| *k != key);
        env.push((key, value));
        refused(check(t.job(JobOp::User, &env)), what);
    }

    let shared = |hba: &str, reload: &str| {
        let (name, body) = job_body(shared_job(
            18,
            JobOp::Hba,
            &[("CITE_PG_HBA", hba), ("CITE_PG_RELOAD", reload)],
        ));
        create(&policy, &name, &body)
    };
    let own = role("shop", "app");
    accepted(
        shared(&format!("_admin|172.30.0.0/16;{own}|172.31.0.0/16"), "0"),
        "an hba list",
    );
    let bad: Vec<(String, &str, &str)> = vec![
        (String::new(), "0", "an empty list"),
        (
            format!("{own}|172.31.0.0/16;_admin|172.30.0.0/16"),
            "0",
            "the admin entry not first",
        ),
        (
            format!("_admin|172.30.0.0/16;{own}|172.31.0.0/16;{own}|172.31.0.0/16"),
            "0",
            "a duplicate entry",
        ),
        (
            "_admin|10.0.0.0/7".to_string(),
            "0",
            "a prefix below the floor",
        ),
        (
            "_admin|172.30.0.0/16;postgres|172.31.0.0/16".to_string(),
            "0",
            "a non-tenant database",
        ),
        (
            format!("_admin|172.30.0.0/16;{own}|0.0.0.0/0"),
            "0",
            "every address",
        ),
        (
            "_admin|172.30.0.0/16".to_string(),
            "2",
            "another reload value",
        ),
        (
            format!("_admin|172.30.0.0/16\n{own}|172.31.0.0/16"),
            "0",
            "a line break",
        ),
    ];
    for (hba, reload, what) in &bad {
        refused(shared(hba, reload), what);
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Executor, manager and egress proxy

#[test]
fn executor_and_manager_join_the_dbnet_only_as_the_contract_says_and_the_proxy_accepts_them() {
    let mut checked = 0;
    for runtime in ["node", "bun", "static", "rust"] {
        for variant in ['A', 'B', 'C', 'D'] {
            for mode in [EgressMode::Filtered, EgressMode::Open, EgressMode::Off] {
                let policy = policy_for(mode);
                for slot in [Slot::Blue, Slot::Green] {
                    for isolate in [true, false] {
                        let mut site = base_site("shop", runtime);
                        if variant == 'A' || variant == 'B' {
                            site.data.postgres = Some(pg_config("dedicated", 18, 512, 100));
                        }
                        if variant == 'B' {
                            site.data.links.push(EnvLink {
                                var: "DATABASE_URL".to_string(),
                                target: LinkTarget::Build,
                                source: LinkSource::Postgres {
                                    database: "app".to_string(),
                                    user: "app".to_string(),
                                    field: PgField::Url,
                                },
                            });
                        }
                        if variant == 'C' {
                            site.data.external_postgres.push(ExternalPostgres {
                                name: "warehouse".to_string(),
                                host: "db.example.com".to_string(),
                                port: 5432,
                                database: "wh".to_string(),
                                sslmode: None,
                            });
                        }
                        let s = stack(&site, slot, isolate, mode);
                        let what =
                            format!("{runtime} {variant} {mode:?} {slot:?} isolate={isolate}");
                        let dbnet = "cite-shop-dbnet".to_string();
                        assert_eq!(
                            endpoints(&s.executor).contains(&dbnet),
                            variant == 'A' || variant == 'B',
                            "executor {what}"
                        );
                        assert_eq!(
                            endpoints(&s.manager).contains(&dbnet),
                            variant == 'B',
                            "manager {what}"
                        );
                        // The manager keeps its egress network as the network mode and the dbnet is only an endpoint.
                        assert_eq!(
                            s.manager["HostConfig"]["NetworkMode"],
                            json!(format!("cite-shop-{}-egress", slot.as_str())),
                            "manager {what}"
                        );
                        accepted(
                            create(&policy, &s.executor_name, &s.executor),
                            &format!("executor {what}"),
                        );
                        accepted(
                            create(&policy, &s.manager_name, &s.manager),
                            &format!("manager {what}"),
                        );
                        accepted(
                            create(&policy, &s.init_name, &s.init),
                            &format!("init {what}"),
                        );
                        if let Some(proxy) = &s.egress_proxy {
                            accepted(
                                create(&policy, &s.egress_proxy_name, proxy),
                                &format!("egress proxy {what}"),
                            );
                        }
                        checked += 1;
                    }
                }
            }
        }
    }
    assert_eq!(checked, 4 * 4 * 3 * 2 * 2);
}

#[test]
fn the_dbnet_endpoint_of_a_stack_cannot_be_redirected() {
    let mut site = data_site("shop", "dedicated", 18);
    site.data.links.push(EnvLink {
        var: "DATABASE_URL".to_string(),
        target: LinkTarget::Build,
        source: LinkSource::Postgres {
            database: "app".to_string(),
            user: "app".to_string(),
            field: PgField::Url,
        },
    });
    let policy = common::policy();
    let s = stack(&site, Slot::Blue, true, EgressMode::Filtered);
    assert!(endpoints(&s.executor).contains(&"cite-shop-dbnet".to_string()));
    assert!(endpoints(&s.manager).contains(&"cite-shop-dbnet".to_string()));
    for (what, name, body) in [
        ("executor", &s.executor_name, &s.executor),
        ("manager", &s.manager_name, &s.manager),
    ] {
        let run = |edit: &dyn Fn(&mut Value)| create(&policy, name, &edited(body, edit));
        refused(
            run(&|b| {
                let eps = b["NetworkingConfig"]["EndpointsConfig"]
                    .as_object_mut()
                    .unwrap();
                eps.remove("cite-shop-dbnet");
                eps.insert("cite-other-dbnet".to_string(), json!({}));
            }),
            &format!("{what} on another site's dbnet"),
        );
        refused(
            run(&|b| b["NetworkingConfig"]["EndpointsConfig"]["cite-other-dbnet"] = json!({})),
            &format!("{what} on its own and another site's dbnet"),
        );
        refused(
            run(&|b| b["NetworkingConfig"]["EndpointsConfig"][SHARED_ADMIN] = json!({})),
            &format!("{what} on the admin network"),
        );
        refused(
            run(&|b| b["NetworkingConfig"]["EndpointsConfig"]["cite-shop-green-net"] = json!({})),
            &format!("{what} on the other slot's network"),
        );
        refused(
            run(&|b| b["HostConfig"]["NetworkMode"] = json!("cite-shop-dbnet")),
            &format!("{what} with the dbnet as its network mode"),
        );
        refused(
            run(&|b| {
                b["NetworkingConfig"]["EndpointsConfig"]["cite-shop-dbnet"] =
                    json!({ "Aliases": ["cite-shop-db"] })
            }),
            &format!("{what} with an alias on the dbnet"),
        );
        refused(
            run(&|b| {
                b["NetworkingConfig"]["EndpointsConfig"]["cite-shop-dbnet"] =
                    json!({ "IPAMConfig": { "IPv4Address": "172.30.0.2" } })
            }),
            &format!("{what} with a fixed address on the dbnet"),
        );
    }
    refused(
        create(&policy, "cite-other-blue-executor", &s.executor),
        "the executor under another site's name",
    );
    // A site without managed Postgres cannot attach a dbnet either way round.
    let plain = stack(
        &base_site("shop", "node"),
        Slot::Blue,
        true,
        EgressMode::Filtered,
    );
    accepted(
        create(&policy, &plain.executor_name, &plain.executor),
        "a plain executor",
    );
    accepted(
        create(&policy, &plain.manager_name, &plain.manager),
        "a plain manager",
    );
}

fn external_site() -> Site {
    let mut site = base_site("shop", "node");
    site.data.postgres = Some(pg_config("dedicated", 18, 512, 100));
    for (name, host, port) in [
        ("alpha", "db.example.com", 5432),
        ("bravo", "203.0.113.9", 5433),
        ("charlie", "2001:db8::1", 5432),
        ("delta", "reports.example.org", 6432),
    ] {
        site.data.external_postgres.push(ExternalPostgres {
            name: name.to_string(),
            host: host.to_string(),
            port,
            database: "wh".to_string(),
            sslmode: None,
        });
    }
    for (name, endpoint) in [
        ("files", "https://s3.eu.example.com"),
        ("media", "https://objects.example.org"),
    ] {
        site.data.s3.push(S3Attachment {
            name: name.to_string(),
            endpoint: endpoint.to_string(),
            bucket: "bucket".to_string(),
            region: "eu-west-1".to_string(),
            path_style: false,
        });
    }
    site
}

#[test]
fn the_egress_proxy_env_with_forwards_and_auto_allow_is_what_the_contract_writes_and_is_accepted() {
    let policy = common::policy();
    let s = stack(&external_site(), Slot::Blue, true, EgressMode::Filtered);
    let proxy = s
        .egress_proxy
        .as_ref()
        .expect("a filtered node has an egress proxy");
    let env = env_entries(proxy);
    // Appended last, in this order, each only when non-empty; forwards by sorted name, IPv6 bracketed, IP hosts
    // never auto-allowed.
    let n = env.len();
    assert_eq!(
        env[n - 2],
        "CITE_EGRESS_FORWARDS=15432=db.example.com:5432,15433=203.0.113.9:5433,15434=[2001:db8::1]:5432,15435=reports.example.org:6432"
    );
    assert_eq!(
        env[n - 1],
        "CITE_EGRESS_AUTO_ALLOW=db.example.com,objects.example.org,reports.example.org,s3.eu.example.com"
    );
    accepted(
        create(&policy, &s.egress_proxy_name, proxy),
        "forwards and auto-allow",
    );

    // Without data attachments neither key is written.
    let plain = stack(
        &base_site("shop", "node"),
        Slot::Blue,
        true,
        EgressMode::Filtered,
    );
    let plain_env = env_entries(plain.egress_proxy.as_ref().unwrap());
    assert!(!plain_env.iter().any(
        |e| e.starts_with("CITE_EGRESS_FORWARDS=") || e.starts_with("CITE_EGRESS_AUTO_ALLOW=")
    ));
    accepted(
        create(
            &policy,
            &plain.egress_proxy_name,
            plain.egress_proxy.as_ref().unwrap(),
        ),
        "a plain proxy",
    );
}

#[test]
fn the_egress_proxy_env_is_accepted_with_site_rules_and_node_settings() {
    let mut site = external_site();
    site.outbound_rules = OutboundRules {
        mode: OutboundMode::Allowlist,
        allow: vec![
            "api.example.com".to_string(),
            ".cdn.example.com".to_string(),
        ],
        deny: vec!["bad.example.com".to_string()],
        block_mail: true,
    };
    let pairs = [
        ("CITE_STACK_EGRESS_ALLOW_PORTS", "443,5432,6432"),
        ("CITE_STACK_EGRESS_DENY_HOSTS", "evil.example"),
    ];
    let egress = Egress::from_lookup(|k| {
        pairs
            .iter()
            .find(|(key, _)| *key == k)
            .map(|(_, v)| v.to_string())
    })
    .unwrap();
    let s = stack_specs(&site, Slot::Green, None, TOKEN, &stack_env(&egress, true)).unwrap();
    let proxy = s.egress_proxy.as_ref().unwrap();
    let policy = common::policy_with(&pairs);
    accepted(
        create(&policy, &s.egress_proxy_name, proxy),
        "rules, node settings, forwards and auto-allow",
    );
    // The proxy must know the node's own entries, so a policy without them refuses the body.
    refused(
        create(&common::policy(), &s.egress_proxy_name, proxy),
        "node entries the proxy does not know",
    );

    // An allowlist needs a site allow entry or an attachment host.
    let only_auto = edited(proxy, |b| {
        put_env(b, "CITE_EGRESS_MODE", "allowlist");
        drop_env(b, "CITE_EGRESS_ALLOW");
    });
    accepted(
        create(&policy, &s.egress_proxy_name, &only_auto),
        "an allowlist satisfied by auto-allow",
    );
    let neither = edited(&only_auto, |b| drop_env(b, "CITE_EGRESS_AUTO_ALLOW"));
    refused(
        create(&policy, &s.egress_proxy_name, &neither),
        "an allowlist with nothing to allow",
    );
}

#[test]
fn the_egress_proxy_env_cannot_carry_malformed_forwards_or_auto_allow_entries() {
    let policy = common::policy();
    let s = stack(&external_site(), Slot::Blue, true, EgressMode::Filtered);
    let name = &s.egress_proxy_name;
    let base = s.egress_proxy.clone().unwrap();
    let with =
        |key: &str, value: &str| create(&policy, name, &edited(&base, |b| put_env(b, key, value)));

    let eight: Vec<String> = (0..8)
        .map(|i| format!("{}=h{i}.example.com:5432", 15432 + i))
        .collect();
    accepted(
        with("CITE_EGRESS_FORWARDS", &eight.join(",")),
        "eight forwards",
    );
    let sixteen: Vec<String> = (0..16).map(|i| format!("h{i}.example.com")).collect();
    accepted(
        with("CITE_EGRESS_AUTO_ALLOW", &sixteen.join(",")),
        "sixteen hosts",
    );

    let nine: Vec<String> = (0..9)
        .map(|i| format!("{}=h{i}.example.com:5432", 15432 + i))
        .collect();
    let seventeen: Vec<String> = (0..17).map(|i| format!("h{i}.example.com")).collect();
    for (key, value, what) in [
        ("CITE_EGRESS_FORWARDS", nine.join(","), "nine forwards"),
        (
            "CITE_EGRESS_FORWARDS",
            String::new(),
            "an empty forward list",
        ),
        (
            "CITE_EGRESS_FORWARDS",
            "15431=db.example.com:5432".to_string(),
            "a listen port below the range",
        ),
        (
            "CITE_EGRESS_FORWARDS",
            "15440=db.example.com:5432".to_string(),
            "a listen port above the range",
        ),
        (
            "CITE_EGRESS_FORWARDS",
            "15432=db.example.com:5432,15432=other.example.com:5432".to_string(),
            "a repeated listen port",
        ),
        (
            "CITE_EGRESS_FORWARDS",
            "15432=db.example.com:5432,15433=db.example.com:5432".to_string(),
            "a repeated target",
        ),
        (
            "CITE_EGRESS_FORWARDS",
            "15432=DB.example.com:5432".to_string(),
            "an uppercase host",
        ),
        (
            "CITE_EGRESS_FORWARDS",
            "15432=db.example.com:0".to_string(),
            "port zero",
        ),
        (
            "CITE_EGRESS_FORWARDS",
            "15432=db.example.com:70000".to_string(),
            "a port above 65535",
        ),
        (
            "CITE_EGRESS_FORWARDS",
            "15432=db.example.com".to_string(),
            "no target port",
        ),
        (
            "CITE_EGRESS_FORWARDS",
            "15432=db.example.com:5432 ".to_string(),
            "trailing space",
        ),
        (
            "CITE_EGRESS_FORWARDS",
            "15432=2001:db8::1:5432".to_string(),
            "an unbracketed IPv6 address",
        ),
        (
            "CITE_EGRESS_FORWARDS",
            "15432=999.1.1.1:5432".to_string(),
            "a malformed address",
        ),
        (
            "CITE_EGRESS_FORWARDS",
            ".example.com".to_string(),
            "a bare host",
        ),
        (
            "CITE_EGRESS_AUTO_ALLOW",
            seventeen.join(","),
            "seventeen hosts",
        ),
        (
            "CITE_EGRESS_AUTO_ALLOW",
            String::new(),
            "an empty host list",
        ),
        (
            "CITE_EGRESS_AUTO_ALLOW",
            "*.example.com".to_string(),
            "a wildcard",
        ),
        (
            "CITE_EGRESS_AUTO_ALLOW",
            ".example.com".to_string(),
            "a leading dot",
        ),
        (
            "CITE_EGRESS_AUTO_ALLOW",
            "DB.example.com".to_string(),
            "an uppercase host",
        ),
        (
            "CITE_EGRESS_AUTO_ALLOW",
            "203.0.113.9".to_string(),
            "an IP literal",
        ),
        (
            "CITE_EGRESS_AUTO_ALLOW",
            "db.example.com,db.example.com".to_string(),
            "a repeated host",
        ),
        ("CITE_EGRESS_EXTRA", "1".to_string(), "an unknown key"),
    ] {
        refused(with(key, &value), what);
    }
    refused(
        create(
            &policy,
            name,
            &edited(&base, |b| {
                b["Env"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!("CITE_EGRESS_FORWARDS=15432=a.example.com:1"))
            }),
        ),
        "a repeated forwards key",
    );
}

// ---------------------------------------------------------------------------------------------------------------
// Whole-set mutations and the data switch

// Applies the `which`th forbidden change to a create body and says what it was. Every change is refused
// regardless of the role, so the same list runs over servers, jobs, executors, managers and egress proxies.
const GENERIC_EDITS: usize = 10;

fn generic_edit(which: usize, b: &mut Value) -> &'static str {
    match which {
        0 => {
            b["Env"].as_array_mut().unwrap().push(json!("CITE_EXTRA=1"));
            "an extra env key"
        }
        1 => {
            b["HostConfig"]["Privileged"] = json!(true);
            "privileged"
        }
        2 => {
            b["HostConfig"]["Binds"] = json!(["/:/host"]);
            "a host bind"
        }
        3 => {
            let bind =
                json!({ "Type": "bind", "Source": "/", "Target": "/host", "ReadOnly": false });
            if b["HostConfig"]["Mounts"].is_array() {
                b["HostConfig"]["Mounts"].as_array_mut().unwrap().push(bind);
            } else {
                b["HostConfig"]["Mounts"] = json!([bind]);
            }
            "a host mount"
        }
        4 => {
            b["HostConfig"]["CapAdd"] = json!(["SYS_ADMIN"]);
            "an added capability"
        }
        5 => {
            b["HostConfig"]["PortBindings"] = json!({ "5432/tcp": [{ "HostPort": "5432" }] });
            "a published port"
        }
        6 => {
            b["Image"] = json!("ghcr.io/seggys116/cite-postgres:latest");
            "a wrong image tag"
        }
        7 => {
            b["HostConfig"]["NetworkMode"] = json!("bridge");
            b["NetworkingConfig"] = json!({ "EndpointsConfig": { "bridge": {} } });
            "a wrong network"
        }
        8 => {
            b["NetworkingConfig"]["EndpointsConfig"]["bridge"] = json!({});
            "an extra endpoint"
        }
        _ => {
            b["HostConfig"]["PidMode"] = json!("host");
            "the host pid namespace"
        }
    }
}

// Every body the connector builds for a filtered node, with the name it is created under.
fn all_filtered_bodies() -> Vec<(String, String, Value)> {
    let mut out: Vec<(String, String, Value)> = Vec::new();
    for major in PG_MAJORS {
        let mut jobs: Vec<(&'static str, JobSpec)> = Vec::new();
        for shared in [false, true] {
            jobs.extend(site_cases(&Tenant::new("shop", shared, major)));
        }
        jobs.extend(shared_cases(major, &["shop", "other"]));
        jobs.extend(
            external_cases()
                .into_iter()
                .filter(|(_, _, open)| !open)
                .map(|(what, spec, _)| (what, spec)),
        );
        let specs: Vec<JobSpec> = jobs.iter().map(|(_, s)| s.clone()).collect();
        let set = data_set(&data_site("shop", "dedicated", major), major, &specs);
        out.push((
            format!("db pg{major}"),
            set.names.db.clone(),
            set.db.clone(),
        ));
        out.push((
            format!("shared db pg{major}"),
            SHARED_DB.to_string(),
            set.shared_db.clone(),
        ));
        for ((op, _), (name, body)) in jobs.iter().zip(&set.jobs) {
            out.push((format!("job {op} pg{major}"), name.clone(), body.clone()));
        }
    }
    let mut site = external_site();
    site.data.links.push(EnvLink {
        var: "DATABASE_URL".to_string(),
        target: LinkTarget::Build,
        source: LinkSource::Postgres {
            database: "app".to_string(),
            user: "app".to_string(),
            field: PgField::Url,
        },
    });
    for isolate in [true, false] {
        let s = stack(&site, Slot::Blue, isolate, EgressMode::Filtered);
        out.push((
            format!("manager isolate={isolate}"),
            s.manager_name.clone(),
            s.manager.clone(),
        ));
        out.push((
            format!("executor isolate={isolate}"),
            s.executor_name.clone(),
            s.executor.clone(),
        ));
        out.push((
            format!("egress proxy isolate={isolate}"),
            s.egress_proxy_name.clone(),
            s.egress_proxy.clone().unwrap(),
        ));
    }
    out
}

#[test]
fn every_accepted_body_is_refused_after_each_single_forbidden_change() {
    let policy = common::policy();
    let bodies = all_filtered_bodies();
    assert!(bodies.len() > 100, "{} bodies", bodies.len());
    for (what, name, body) in &bodies {
        accepted(create(&policy, name, body), what);
        for which in 0..GENERIC_EDITS {
            let mut bad = body.clone();
            let change = generic_edit(which, &mut bad);
            refused(
                create(&policy, name, &bad),
                &format!("{what} with {change}"),
            );
        }
        if name.contains("-shop-") {
            let other = name.replace("-shop-", "-other-");
            refused(
                create(&policy, &other, body),
                &format!("{what} under {other}"),
            );
        }
    }
}

#[test]
fn every_data_body_is_refused_while_data_services_are_off_and_stacks_without_data_still_work() {
    let off = data_off();
    for (what, name, body) in all_filtered_bodies() {
        let data_name =
            name.ends_with("-db") || name.ends_with("-dbjob") || name.starts_with("cite-pg-shared");
        let dbnet = endpoints(&body).iter().any(|e| e.ends_with("-dbnet"));
        let forwards = env_entries(&body).iter().any(|e| {
            e.starts_with("CITE_EGRESS_FORWARDS=") || e.starts_with("CITE_EGRESS_AUTO_ALLOW=")
        });
        if data_name || dbnet || forwards {
            refused(
                create(&off, &name, &body),
                &format!("{what} while data services are off"),
            );
        } else {
            accepted(
                create(&off, &name, &body),
                &format!("{what} while data services are off"),
            );
        }
    }
    let set = data_set(&data_site("shop", "dedicated", 18), 18, &[]);
    for (what, body) in [
        ("db volume", &set.db_volume),
        ("shared data volume", &set.shared_data_volume),
        ("shared conf volume", &set.shared_conf_volume),
    ] {
        refused(off.validate_body(&Route::VolumeCreate, body), what);
    }
    for (what, body) in [("dbnet", &set.dbnet), ("admin network", &set.shared_admin)] {
        refused(off.validate_body(&Route::NetworkCreate, body), what);
    }
    let plain = stack(
        &base_site("shop", "node"),
        Slot::Blue,
        true,
        EgressMode::Filtered,
    );
    accepted(
        create(&off, &plain.executor_name, &plain.executor),
        "a plain executor",
    );
    accepted(
        create(&off, &plain.manager_name, &plain.manager),
        "a plain manager",
    );
    accepted(
        create(
            &off,
            &plain.egress_proxy_name,
            plain.egress_proxy.as_ref().unwrap(),
        ),
        "a plain egress proxy",
    );
}

#[test]
fn only_the_shared_instance_may_be_attached_to_a_dbnet() {
    let policy = common::policy();
    let target = |net: &str| normalise(&format!("/v1.45/networks/{net}/connect")).unwrap();
    let route = policy.classify("POST", &target("cite-shop-dbnet")).unwrap();
    assert_eq!(route, Route::NetworkConnect("cite-shop-dbnet".to_string()));
    accepted(
        policy.validate_body(&route, &json!({ "Container": SHARED_DB })),
        "the shared instance on a dbnet",
    );
    for bad in [
        json!({ "Container": "cite-shop-db" }),
        json!({ "Container": "cite-other-db" }),
        json!({ "Container": "cite-shop-dbjob" }),
        json!({ "Container": SHARED_JOB }),
        json!({ "Container": common::HAPROXY }),
        json!({ "Container": SHARED_DB, "Force": true }),
        json!({ "Container": SHARED_DB, "EndpointConfig": { "Aliases": ["cite-shop-db"] } }),
        json!({ "Container": SHARED_DB, "EndpointConfig": { "IPAMConfig": { "IPv4Address": "172.30.0.9" } } }),
        json!({}),
        json!({ "Container": 1 }),
    ] {
        refused(policy.validate_body(&route, &bad), &format!("{bad}"));
    }
    // Nothing is attached to the admin network by name, and the shared instance is not a stack network member.
    assert!(policy.classify("POST", &target(SHARED_ADMIN)).is_err());
    let stack_net = policy
        .classify("POST", &target("cite-shop-blue-net"))
        .unwrap();
    accepted(
        policy.validate_body(&stack_net, &json!({ "Container": common::HAPROXY })),
        "haproxy on a stack network",
    );
    refused(
        policy.validate_body(&stack_net, &json!({ "Container": SHARED_DB })),
        "the shared instance on a stack network",
    );
    refused(
        data_off()
            .classify("POST", &target("cite-shop-dbnet"))
            .and_then(|r| data_off().validate_body(&r, &json!({ "Container": SHARED_DB }))),
        "the shared instance on a dbnet while data services are off",
    );
}

#[test]
fn the_connector_refuses_what_the_proxy_would_refuse_before_building_a_body() {
    let egress = Egress::default();
    let env = stack_env(&egress, true);
    let site = data_site("shop", "dedicated", 18);
    let build = |jobs: &[JobSpec], shared_major: u8| {
        data_specs(
            &site,
            &env,
            BACKUPS,
            SU,
            &shared_settings(shared_major),
            jobs,
        )
    };
    let t = Tenant::new("shop", false, 18);
    let db = t.db();
    let tag = role("shop", "app");
    let good = t.job(
        JobOp::Backup,
        &[("PGDATABASE", db.as_str()), ("CITE_ROLE_TAG", tag.as_str())],
    );
    assert!(build(std::slice::from_ref(&good), 18).is_ok());
    let mut major16 = good.clone();
    major16.major = 16;
    assert!(
        build(&[major16], 18).is_err(),
        "a job image of an unsupported major"
    );
    assert!(
        build(&[good], 16).is_err(),
        "a shared instance of an unsupported major"
    );
    let mut old = base_site("shop", "node");
    old.data.postgres = Some(pg_config("dedicated", 16, 512, 100));
    assert!(data_specs(&old, &env, BACKUPS, SU, &shared_settings(18), &[]).is_err());
    assert!(
        data_specs(
            &base_site("shop", "node"),
            &env,
            BACKUPS,
            SU,
            &shared_settings(18),
            &[]
        )
        .is_err()
    );
}
