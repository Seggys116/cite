//! Managed database users: credential state, the two-login rotation, and database add/remove.
//!
//! Every user is two login roles (`_a`, `_b`) that alternate on rotation. A rotation sets a new password on the
//! inactive alternate, switches the stored `active` marker, and keeps the old alternate logging in until the next
//! deploy has replaced the running containers (or 7 days passed); only then is it retired.

use std::fmt;

use cite_edge::datamodel::{
    Alt, DEFAULT_CONN_LIMIT, LinkSource, PgDatabase, PgLevel, PgMode, PgUser, pg_user_secret_name,
};
use cite_edge::datawire::{UserCreateReq, UserPatchReq};
use cite_edge::model::Site;
use cite_edge::validate::{MAX_PG_USERS_PER_DATABASE, validate_site_data};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};

use super::service::{
    DataService, JobCtx, MAX_DATABASES, links_to, new_user, parse_time, valid_database_name,
};
use crate::store::now_rfc3339;
use crate::{ConnectorError, Result};

/// An alternate is retired after this long even when no deploy replaced the containers.
pub const RETIRE_AFTER: Duration = Duration::days(7);
/// A user only builds use (no runtime link) can drop the old login once builds that started before are over.
pub const BUILD_ONLY_GRACE: Duration = Duration::hours(2);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Retiring {
    pub alt: String,
    pub since: String,
}

/// `site-<id>.data.pg.<db>.<user>`
#[derive(Clone, Serialize, Deserialize)]
pub struct UserSecret {
    pub active: String,
    #[serde(default)]
    pub a: Option<String>,
    #[serde(default)]
    pub b: Option<String>,
    #[serde(default)]
    pub retiring: Option<Retiring>,
    #[serde(default)]
    pub rotated_at: Option<String>,
    /// Alternates whose login role exists in the database.
    #[serde(default)]
    pub created: Vec<String>,
}

impl fmt::Debug for UserSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserSecret")
            .field("active", &self.active)
            .field("retiring", &self.retiring)
            .field("passwords", &"<redacted>")
            .finish()
    }
}

fn parse_alt(text: &str) -> Result<Alt> {
    match text {
        "a" => Ok(Alt::A),
        "b" => Ok(Alt::B),
        _ => Err(ConnectorError::Internal(
            "a stored credential names an unknown login".into(),
        )),
    }
}

impl UserSecret {
    pub fn fresh(password: String, now: &str) -> Self {
        UserSecret {
            active: "a".into(),
            a: Some(password),
            b: None,
            retiring: None,
            rotated_at: Some(now.to_string()),
            created: Vec::new(),
        }
    }

    pub fn active_alt(&self) -> Result<Alt> {
        parse_alt(&self.active)
    }

    pub fn password(&self, alt: Alt) -> Option<&str> {
        match alt {
            Alt::A => self.a.as_deref(),
            Alt::B => self.b.as_deref(),
        }
    }

    pub fn exists(&self, alt: Alt) -> bool {
        self.created.iter().any(|c| c == alt.as_str())
    }

    pub fn mark_created(&mut self, alt: Alt) {
        if !self.exists(alt) {
            self.created.push(alt.as_str().to_string());
        }
    }

    /// Alternates whose login role exists.
    pub fn existing(&self) -> Vec<Alt> {
        [Alt::A, Alt::B]
            .into_iter()
            .filter(|a| self.exists(*a))
            .collect()
    }

    /// Switches to the inactive alternate with a new password; the old one is retiring.
    pub fn rotate_to(&mut self, new_password: String, now: &str) -> Result<Alt> {
        if self.retiring.is_some() {
            return Err(ConnectorError::Conflict(
                "the previous rotation is still in progress".into(),
            ));
        }
        let old = self.active_alt()?;
        let next = old.other();
        match next {
            Alt::A => self.a = Some(new_password),
            Alt::B => self.b = Some(new_password),
        }
        self.mark_created(next);
        self.active = next.as_str().to_string();
        self.retiring = Some(Retiring {
            alt: old.as_str().to_string(),
            since: now.to_string(),
        });
        self.rotated_at = Some(now.to_string());
        Ok(next)
    }

    /// Ends a rotation: forgets the retired alternate's password. Returns the alternate.
    pub fn retire(&mut self) -> Option<Alt> {
        let r = self.retiring.take()?;
        let alt = parse_alt(&r.alt).ok()?;
        match alt {
            Alt::A => self.a = None,
            Alt::B => self.b = None,
        }
        Some(alt)
    }

    pub fn passwords(&self) -> Vec<&str> {
        [self.a.as_deref(), self.b.as_deref()]
            .into_iter()
            .flatten()
            .collect()
    }
}

/// True when the retiring login may be switched off: 7 days passed, or no running manager or executor still carries
/// it in its env. A user with only build links also waits `BUILD_ONLY_GRACE`, so a build that started before the
/// rotation has finished.
pub fn retire_ready(
    since: &str,
    now: OffsetDateTime,
    has_runtime_link: bool,
    still_referenced: bool,
) -> bool {
    let Some(since) = parse_time(since) else {
        return true;
    };
    if now - since >= RETIRE_AFTER {
        return true;
    }
    if still_referenced {
        return false;
    }
    has_runtime_link || now - since >= BUILD_ONLY_GRACE
}

fn has_runtime_link(site: &Site, db: &str, user: &str) -> bool {
    site.data.links.iter().any(|l| {
        l.target == cite_edge::datamodel::LinkTarget::Runtime
            && matches!(&l.source, LinkSource::Postgres { database, user: u, .. } if database == db && u == user)
    })
}

pub(crate) fn check_create_user(site: &Site, db: &str, req: &UserCreateReq) -> Result<PgUser> {
    let pg = site.data.postgres.as_ref().ok_or_else(|| {
        ConnectorError::BadRequest("managed Postgres is not enabled for this site".into())
    })?;
    let d = pg
        .databases
        .iter()
        .find(|d| d.name == db)
        .ok_or_else(|| ConnectorError::NotFound(format!("database {db} not found")))?;
    if d.users.iter().any(|u| u.name == req.name) {
        return Err(ConnectorError::Conflict(format!(
            "user {db}/{} already exists",
            req.name
        )));
    }
    if d.users.len() >= MAX_PG_USERS_PER_DATABASE {
        return Err(ConnectorError::BadRequest(format!(
            "a database has at most {MAX_PG_USERS_PER_DATABASE} users"
        )));
    }
    let user = PgUser {
        name: req.name.clone(),
        level: req.level,
        connection_limit: req.connection_limit.unwrap_or(DEFAULT_CONN_LIMIT),
        statement_timeout_ms: req.statement_timeout_ms,
        idle_in_transaction_timeout_ms: req.idle_in_transaction_timeout_ms,
        disabled: false,
    };
    let mut next = site.clone();
    if let Some(p) = next.data.postgres.as_mut()
        && let Some(d) = p.databases.iter_mut().find(|d| d.name == db)
    {
        d.users.push(user.clone());
    }
    validate_site_data(&next)?;
    Ok(user)
}

/// Applies a patch to a copy of the user and validates the site; returns the new user.
pub(crate) fn check_patch_user(
    site: &Site,
    db: &str,
    name: &str,
    patch: &UserPatchReq,
) -> Result<PgUser> {
    if patch.is_empty() {
        return Err(ConnectorError::BadRequest(
            "the patch changes nothing".into(),
        ));
    }
    let pg = site.data.postgres.as_ref().ok_or_else(|| {
        ConnectorError::BadRequest("managed Postgres is not enabled for this site".into())
    })?;
    let user = pg
        .databases
        .iter()
        .find(|d| d.name == db)
        .and_then(|d| d.users.iter().find(|u| u.name == name))
        .ok_or_else(|| ConnectorError::NotFound(format!("user {db}/{name} not found")))?;
    let mut next = user.clone();
    if let Some(l) = patch.level {
        next.level = l;
    }
    if let Some(c) = patch.connection_limit {
        next.connection_limit = c;
    }
    if let Some(s) = patch.statement_timeout_ms {
        next.statement_timeout_ms = Some(s);
    }
    if let Some(i) = patch.idle_in_transaction_timeout_ms {
        next.idle_in_transaction_timeout_ms = Some(i);
    }
    if let Some(d) = patch.disabled {
        next.disabled = d;
    }
    let mut candidate = site.clone();
    if let Some(p) = candidate.data.postgres.as_mut()
        && let Some(u) = p
            .databases
            .iter_mut()
            .find(|d| d.name == db)
            .and_then(|d| d.users.iter_mut().find(|u| u.name == name))
    {
        *u = next.clone();
    }
    validate_site_data(&candidate)?;
    if user.level == PgLevel::Owner
        && next.level != PgLevel::Owner
        && pg
            .databases
            .iter()
            .find(|d| d.name == db)
            .is_some_and(|d| d.users.iter().filter(|u| u.level == PgLevel::Owner).count() == 1)
    {
        return Err(ConnectorError::Conflict(
            "the last owner-level user of a database cannot be demoted".into(),
        ));
    }
    Ok(next)
}

pub(crate) fn check_delete_user(site: &Site, db: &str, name: &str) -> Result<()> {
    let pg = site.data.postgres.as_ref().ok_or_else(|| {
        ConnectorError::BadRequest("managed Postgres is not enabled for this site".into())
    })?;
    let d = pg
        .databases
        .iter()
        .find(|d| d.name == db)
        .ok_or_else(|| ConnectorError::NotFound(format!("database {db} not found")))?;
    let u = d
        .users
        .iter()
        .find(|u| u.name == name)
        .ok_or_else(|| ConnectorError::NotFound(format!("user {db}/{name} not found")))?;
    let linked = links_to(
        &site.data,
        |s| matches!(s, LinkSource::Postgres { database, user, .. } if database == db && user == name),
    );
    if !linked.is_empty() {
        return Err(ConnectorError::Conflict(format!(
            "user {db}/{name} is linked by {}; remove the links first",
            linked.join(", ")
        )));
    }
    if u.level == PgLevel::Owner
        && d.users.iter().filter(|x| x.level == PgLevel::Owner).count() == 1
    {
        return Err(ConnectorError::Conflict(
            "the last owner-level user of a database cannot be deleted".into(),
        ));
    }
    Ok(())
}

impl DataService {
    // ---- create ----

    pub(crate) async fn do_create_user(
        &self,
        ctx: &JobCtx,
        actor: &str,
        site_id: &str,
        db: &str,
        req: UserCreateReq,
    ) -> Result<Value> {
        let lock = self.site_lock(site_id);
        let _g = lock.lock().await;
        let site = self.site(site_id)?;
        let user = check_create_user(&site, db, &req)?;
        ctx.step("creating the login");
        self.add_user_locked_with(actor, site_id, db, user, &site)
            .await?;
        Ok(Value::Null)
    }

    /// Creates a user (credentials, login role, config entry); the site lock is held by the caller.
    pub(crate) async fn add_user_locked(
        &self,
        actor: &str,
        site_id: &str,
        db: &str,
        user: PgUser,
    ) -> Result<()> {
        let site = self.site(site_id)?;
        self.add_user_locked_with(actor, site_id, db, user, &site)
            .await
    }

    async fn add_user_locked_with(
        &self,
        actor: &str,
        site_id: &str,
        db: &str,
        user: PgUser,
        site: &Site,
    ) -> Result<()> {
        let secret_name = pg_user_secret_name(site_id, db, &user.name);
        let pw = crate::data::env::generate_password().map_err(ConnectorError::Internal)?;
        let mut secret = UserSecret::fresh(pw.to_string(), &now_rfc3339());
        self.secret_put(Some(site_id), &secret_name, &secret)
            .await?;
        let mut candidate = site.clone();
        if let Some(p) = candidate.data.postgres.as_mut()
            && let Some(d) = p.databases.iter_mut().find(|d| d.name == db)
        {
            d.users.push(user.clone());
        }
        if let Err(e) = self.ensure_login(&candidate, db, &user, Alt::A).await {
            self.secret_del(Some(site_id), &secret_name).await;
            return Err(e);
        }
        secret.mark_created(Alt::A);
        self.secret_put(Some(site_id), &secret_name, &secret)
            .await?;
        let (d, u) = (db.to_string(), user.clone());
        let detail = format!("site={site_id} db={db} user={}", user.name);
        self.update_site(actor, "data.user.create", &detail, site_id, move |s| {
            if let Some(p) = s.data.postgres.as_mut()
                && let Some(dbx) = p.databases.iter_mut().find(|x| x.name == d)
            {
                dbx.users.push(u);
            }
            Ok(())
        })
        .await
    }

    // ---- patch ----

    pub(crate) async fn do_patch_user(
        &self,
        ctx: &JobCtx,
        actor: &str,
        site_id: &str,
        db: &str,
        name: &str,
        patch: UserPatchReq,
    ) -> Result<Value> {
        let lock = self.site_lock(site_id);
        let _g = lock.lock().await;
        let site = self.site(site_id)?;
        let next = check_patch_user(&site, db, name, &patch)?;
        let old = site
            .data
            .postgres
            .as_ref()
            .and_then(|p| p.databases.iter().find(|d| d.name == db))
            .and_then(|d| d.users.iter().find(|u| u.name == name))
            .cloned()
            .ok_or_else(|| ConnectorError::NotFound(format!("user {db}/{name} not found")))?;
        let secret_name = pg_user_secret_name(site_id, db, name);
        let secret: UserSecret = self.secret_get(&secret_name).await?.ok_or_else(|| {
            ConnectorError::Unavailable(format!("the credentials of {db}/{name} are missing"))
        })?;
        let settings_changed = next.level != old.level
            || next.connection_limit != old.connection_limit
            || next.effective_statement_timeout_ms() != old.effective_statement_timeout_ms()
            || next.effective_idle_in_transaction_ms() != old.effective_idle_in_transaction_ms();
        if settings_changed {
            ctx.step("applying settings");
            for alt in secret.existing() {
                self.login_action(&site, db, &next, alt, "settings", None)
                    .await?;
            }
        }
        if next.disabled != old.disabled {
            if next.disabled {
                ctx.step("disabling the login");
                for alt in secret.existing() {
                    self.login_action(&site, db, &next, alt, "disable", None)
                        .await?;
                }
            } else {
                ctx.step("enabling the login");
                let active = secret.active_alt()?;
                self.login_action(&site, db, &next, active, "enable", None)
                    .await?;
            }
        }
        let (d, n, saved) = (db.to_string(), name.to_string(), next.clone());
        let action = match patch.disabled {
            Some(true) if !settings_changed => "data.user.disable",
            Some(false) if !settings_changed => "data.user.enable",
            _ => "data.user.update",
        };
        let detail = format!("site={site_id} db={db} user={name}");
        self.update_site(actor, action, &detail, site_id, move |s| {
            if let Some(u) = s
                .data
                .postgres
                .as_mut()
                .and_then(|p| p.databases.iter_mut().find(|x| x.name == d))
                .and_then(|x| x.users.iter_mut().find(|u| u.name == n))
            {
                *u = saved;
            }
            Ok(())
        })
        .await?;
        Ok(Value::Null)
    }

    // ---- rotate ----

    /// True when a rotation of this user needs a deploy before running containers use the new login.
    pub(crate) fn rotation_needs_deploy(&self, site: &Site, db: &str, user: &str) -> bool {
        has_runtime_link(site, db, user)
    }

    pub(crate) fn check_rotate(&self, site: &Site, db: &str, name: &str) -> Result<()> {
        let user = site
            .data
            .postgres
            .as_ref()
            .and_then(|p| p.databases.iter().find(|d| d.name == db))
            .and_then(|d| d.users.iter().find(|u| u.name == name))
            .ok_or_else(|| ConnectorError::NotFound(format!("user {db}/{name} not found")))?;
        if user.disabled {
            return Err(ConnectorError::Conflict(
                "enable the user before rotating its password".into(),
            ));
        }
        Ok(())
    }

    /// 409 while the previous rotation of this user has not been retired yet.
    pub(crate) async fn ensure_not_rotating(
        &self,
        site_id: &str,
        db: &str,
        name: &str,
    ) -> Result<()> {
        let secret: Option<UserSecret> = self
            .secret_get(&pg_user_secret_name(site_id, db, name))
            .await?;
        if secret.is_some_and(|s| s.retiring.is_some()) {
            return Err(ConnectorError::Conflict(
                "the previous rotation is still in progress".into(),
            ));
        }
        Ok(())
    }

    pub(crate) async fn do_rotate_user(
        &self,
        ctx: &JobCtx,
        actor: &str,
        site_id: &str,
        db: &str,
        name: &str,
    ) -> Result<Value> {
        let lock = self.site_lock(site_id);
        let _g = lock.lock().await;
        let site = self.site(site_id)?;
        self.check_rotate(&site, db, name)?;
        let user = site
            .data
            .postgres
            .as_ref()
            .and_then(|p| p.databases.iter().find(|d| d.name == db))
            .and_then(|d| d.users.iter().find(|u| u.name == name))
            .cloned()
            .ok_or_else(|| ConnectorError::NotFound(format!("user {db}/{name} not found")))?;
        let secret_name = pg_user_secret_name(site_id, db, name);
        let mut secret: UserSecret = self.secret_get(&secret_name).await?.ok_or_else(|| {
            ConnectorError::Unavailable(format!("the credentials of {db}/{name} are missing"))
        })?;
        if secret.retiring.is_some() {
            return Err(ConnectorError::Conflict(
                "the previous rotation is still in progress".into(),
            ));
        }
        let pw = crate::data::env::generate_password().map_err(ConnectorError::Internal)?;
        let target = secret.active_alt()?.other();
        ctx.step("setting the new password on the idle login");
        self.upsert_login(&site, db, &user, target, &pw).await?;
        secret.rotate_to(pw.to_string(), &now_rfc3339())?;
        self.secret_put(Some(site_id), &secret_name, &secret)
            .await?;
        self.store
            .audit(
                actor,
                "data.user.rotated",
                &format!("site={site_id} db={db} user={name}"),
            )
            .await;
        Ok(json!({ "redeploy_needed": self.rotation_needs_deploy(&site, db, name) }))
    }

    /// Ends every rotation that is ready; returns how many logins were retired.
    pub(crate) async fn retire_due(&self, now: OffsetDateTime) -> u32 {
        let mut retired = 0;
        for site in self.sites_with_data() {
            let Some(pg) = site.data.postgres.clone() else {
                continue;
            };
            for db in &pg.databases {
                for user in &db.users {
                    match self.retire_one(&site.id, &db.name, &user.name, now).await {
                        Ok(true) => retired += 1,
                        Ok(false) => {}
                        Err(e) => {
                            tracing::warn!(site = %site.id, error = %e, "retiring a rotated login failed")
                        }
                    }
                }
            }
        }
        retired
    }

    async fn retire_one(
        &self,
        site_id: &str,
        db: &str,
        name: &str,
        now: OffsetDateTime,
    ) -> Result<bool> {
        let secret_name = pg_user_secret_name(site_id, db, name);
        let Some(secret) = self.secret_get::<UserSecret>(&secret_name).await? else {
            return Ok(false);
        };
        let Some(r) = &secret.retiring else {
            return Ok(false);
        };
        let site = self.site(site_id)?;
        let alt = parse_alt(&r.alt)?;
        let login = cite_edge::datamodel::pg_login(site_id, db, name, alt);
        let referenced = self
            .engine
            .env_mentions(site_id, &[login])
            .await
            .unwrap_or(true);
        if !retire_ready(&r.since, now, has_runtime_link(&site, db, name), referenced) {
            return Ok(false);
        }
        let lock = self.site_lock(site_id);
        let _g = lock.lock().await;
        let site = self.site(site_id)?;
        let Some(mut secret) = self.secret_get::<UserSecret>(&secret_name).await? else {
            return Ok(false);
        };
        let Some(alt) = secret
            .retiring
            .as_ref()
            .and_then(|r| parse_alt(&r.alt).ok())
        else {
            return Ok(false);
        };
        let user = site
            .data
            .postgres
            .as_ref()
            .and_then(|p| p.databases.iter().find(|d| d.name == db))
            .and_then(|d| d.users.iter().find(|u| u.name == name))
            .cloned();
        if let Some(user) = user {
            self.login_action(&site, db, &user, alt, "retire", None)
                .await?;
        }
        secret.retire();
        self.secret_put(Some(site_id), &secret_name, &secret)
            .await?;
        self.store
            .audit(
                "scheduler",
                "data.user.retired",
                &format!("site={site_id} db={db} user={name}"),
            )
            .await;
        Ok(true)
    }

    // ---- delete ----

    pub(crate) async fn do_delete_user(
        &self,
        ctx: &JobCtx,
        actor: &str,
        site_id: &str,
        db: &str,
        name: &str,
    ) -> Result<Value> {
        let lock = self.site_lock(site_id);
        let _g = lock.lock().await;
        let site = self.site(site_id)?;
        check_delete_user(&site, db, name)?;
        let user = site
            .data
            .postgres
            .as_ref()
            .and_then(|p| p.databases.iter().find(|d| d.name == db))
            .and_then(|d| d.users.iter().find(|u| u.name == name))
            .cloned()
            .ok_or_else(|| ConnectorError::NotFound(format!("user {db}/{name} not found")))?;
        let secret_name = pg_user_secret_name(site_id, db, name);
        if let Some(secret) = self.secret_get::<UserSecret>(&secret_name).await? {
            ctx.step("dropping the logins");
            for alt in secret.existing() {
                self.drop_login(&site, db, &user, alt).await?;
            }
        }
        let (d, n) = (db.to_string(), name.to_string());
        let detail = format!("site={site_id} db={db} user={name}");
        self.update_site(actor, "data.user.delete", &detail, site_id, move |s| {
            if let Some(dbx) = s
                .data
                .postgres
                .as_mut()
                .and_then(|p| p.databases.iter_mut().find(|x| x.name == d))
            {
                dbx.users.retain(|u| u.name != n);
            }
            Ok(())
        })
        .await?;
        self.secret_del(Some(site_id), &secret_name).await;
        Ok(Value::Null)
    }

    // ---- databases ----

    pub(crate) fn check_create_database(&self, site: &Site, name: &str) -> Result<()> {
        let pg = site.data.postgres.as_ref().ok_or_else(|| {
            ConnectorError::BadRequest("managed Postgres is not enabled for this site".into())
        })?;
        if !valid_database_name(name) {
            return Err(ConnectorError::BadRequest(
                "a database name must match ^[a-z][a-z0-9]{0,15}$ and not be postgres, template0 or template1".into(),
            ));
        }
        if pg.databases.iter().any(|d| d.name == name) {
            return Err(ConnectorError::Conflict(format!(
                "database {name} already exists"
            )));
        }
        if pg.databases.len() >= MAX_DATABASES {
            return Err(ConnectorError::BadRequest(format!(
                "a site has at most {MAX_DATABASES} databases"
            )));
        }
        Ok(())
    }

    pub(crate) async fn do_create_database(
        &self,
        ctx: &JobCtx,
        actor: &str,
        site_id: &str,
        name: &str,
    ) -> Result<Value> {
        let lock = self.site_lock(site_id);
        let _g = lock.lock().await;
        let site = self.site(site_id)?;
        self.check_create_database(&site, name)?;
        ctx.step("creating the database");
        let defaults = vec![
            new_user("app", PgLevel::Readwrite),
            new_user("migrate", PgLevel::Owner),
        ];
        self.provision_database(actor, site_id, name, &defaults)
            .await?;
        Ok(Value::Null)
    }

    /// Creates a database and the given users; with no users the database exists in config with none yet, to be
    /// filled by the caller (a preset adds its own). The site lock is held by the caller.
    pub(crate) async fn provision_database(
        &self,
        actor: &str,
        site_id: &str,
        name: &str,
        users: &[PgUser],
    ) -> Result<()> {
        let site = self.site(site_id)?;
        self.check_create_database(&site, name)?;
        if users.is_empty() {
            return Err(ConnectorError::BadRequest(
                "a database needs at least one user".into(),
            ));
        }
        for u in users {
            self.ensure_user_secret(site_id, name, &u.name).await?;
        }
        let mut candidate = site.clone();
        if let Some(p) = candidate.data.postgres.as_mut() {
            p.databases.push(PgDatabase {
                name: name.to_string(),
                users: users.to_vec(),
            });
        }
        validate_site_data(&candidate)?;
        // On the shared instance the new database's logins and its job login need their pg_hba.conf entries
        // before anything connects to it (the provisioning itself ends with a job inside the database).
        if candidate
            .data
            .postgres
            .as_ref()
            .is_some_and(|p| p.mode == cite_edge::datamodel::PgMode::Shared)
        {
            let _sg = self.shared_lock.lock().await;
            self.write_hba(Some(&candidate), true).await?;
        }
        self.provision_db_job(&candidate, name).await?;
        for u in users {
            self.ensure_login(&candidate, name, u, Alt::A).await?;
            let sn = pg_user_secret_name(site_id, name, &u.name);
            if let Some(mut s) = self.secret_get::<UserSecret>(&sn).await? {
                s.mark_created(Alt::A);
                self.secret_put(Some(site_id), &sn, &s).await?;
            }
        }
        let (n, us) = (name.to_string(), users.to_vec());
        let detail = format!("site={site_id} db={name}");
        self.update_site(actor, "data.database.create", &detail, site_id, move |s| {
            if let Some(p) = s.data.postgres.as_mut() {
                p.databases.push(PgDatabase { name: n, users: us });
            }
            Ok(())
        })
        .await?;
        let n = name.to_string();
        self.index_edit(site_id, move |i| {
            i.databases.insert(n);
        })
        .await
    }

    pub(crate) fn check_delete_database(&self, site: &Site, db: &str, purge: bool) -> Result<()> {
        let pg = site.data.postgres.as_ref().ok_or_else(|| {
            ConnectorError::BadRequest("managed Postgres is not enabled for this site".into())
        })?;
        if !pg.databases.iter().any(|d| d.name == db) {
            return Err(ConnectorError::NotFound(format!("database {db} not found")));
        }
        if pg.databases.len() == 1 {
            return Err(ConnectorError::Conflict(
                "a site with managed Postgres needs at least one database; disable Postgres instead".into(),
            ));
        }
        if !purge {
            let linked = links_to(
                &site.data,
                |s| matches!(s, LinkSource::Postgres { database, .. } if database == db),
            );
            if !linked.is_empty() {
                return Err(ConnectorError::Conflict(format!(
                    "database {db} is linked by {}; remove the links first or purge",
                    linked.join(", ")
                )));
            }
        }
        Ok(())
    }

    pub(crate) async fn do_delete_database(
        &self,
        ctx: &JobCtx,
        actor: &str,
        site_id: &str,
        db: &str,
        purge: bool,
    ) -> Result<Value> {
        let lock = self.site_lock(site_id);
        let _g = lock.lock().await;
        let site = self.site(site_id)?;
        self.check_delete_database(&site, db, purge)?;
        if !purge && self.has_pinned_backup(site_id, db).await? {
            return Err(ConnectorError::Conflict(format!(
                "database {db} has pinned backups; unpin them or purge"
            )));
        }
        ctx.step("dropping the database");
        self.deprovision_db_job(&site, db).await?;
        let users: Vec<String> = site
            .data
            .postgres
            .as_ref()
            .and_then(|p| p.databases.iter().find(|d| d.name == db))
            .map(|d| d.users.iter().map(|u| u.name.clone()).collect())
            .unwrap_or_default();
        let (d, mode) = (db.to_string(), site.data.postgres.as_ref().map(|p| p.mode));
        let detail = format!("site={site_id} db={db}");
        let removed = self
            .update_site(actor, "data.database.delete", &detail, site_id, move |s| {
                if let Some(p) = s.data.postgres.as_mut() {
                    p.databases.retain(|x| x.name != d);
                }
                let before = s.data.links.len();
                s.data
                    .links
                    .retain(|l| !matches!(&l.source, LinkSource::Postgres { database, .. } if *database == d));
                Ok(before - s.data.links.len())
            })
            .await?;
        for u in &users {
            self.secret_del(Some(site_id), &pg_user_secret_name(site_id, db, u))
                .await;
        }
        let n = db.to_string();
        self.index_edit(site_id, move |i| {
            i.databases.remove(&n);
        })
        .await?;
        if mode == Some(PgMode::Shared) {
            let fresh = self.site(site_id)?;
            let _sg = self.shared_lock.lock().await;
            self.write_hba(Some(&fresh), true).await?;
        }
        Ok(json!({ "redeploy_needed": removed > 0, "links_removed": removed }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::format_description::well_known::Rfc3339;

    fn at(s: &str) -> OffsetDateTime {
        OffsetDateTime::parse(s, &Rfc3339).unwrap()
    }

    #[test]
    fn rotation_switches_the_active_alternate_and_keeps_the_old_one_retiring() {
        let mut s = UserSecret::fresh("pw-a".into(), "2026-11-01T00:00:00Z");
        s.mark_created(Alt::A);
        let next = s.rotate_to("pw-b".into(), "2026-11-02T00:00:00Z").unwrap();
        assert_eq!(next, Alt::B);
        assert_eq!(s.active_alt().unwrap(), Alt::B);
        assert_eq!(s.password(Alt::A), Some("pw-a"));
        assert_eq!(s.password(Alt::B), Some("pw-b"));
        assert_eq!(s.retiring.as_ref().unwrap().alt, "a");
        assert!(s.exists(Alt::B));
        let err = s
            .rotate_to("pw-c".into(), "2026-11-02T01:00:00Z")
            .unwrap_err();
        assert!(matches!(err, ConnectorError::Conflict(m) if m.contains("still in progress")));
        assert_eq!(s.retire(), Some(Alt::A));
        assert_eq!(s.password(Alt::A), None);
        assert!(s.retiring.is_none());
        assert!(s.exists(Alt::A), "the role still exists, NOLOGIN");
        s.rotate_to("pw-d".into(), "2026-11-03T00:00:00Z").unwrap();
        assert_eq!(s.active_alt().unwrap(), Alt::A);
    }

    #[test]
    fn debug_output_never_shows_passwords() {
        let s = UserSecret::fresh("hunter2hunter2".into(), "2026-11-01T00:00:00Z");
        assert!(!format!("{s:?}").contains("hunter2"));
    }

    #[test]
    fn a_runtime_login_is_retired_once_no_running_container_carries_it() {
        let since = "2026-11-02T00:00:00Z";
        let now = at("2026-11-02T12:00:00Z");
        assert!(
            !retire_ready(since, now, true, true),
            "an old slot still runs with it"
        );
        assert!(retire_ready(since, now, true, false));
    }

    #[test]
    fn a_build_only_login_waits_for_builds_and_every_login_expires_after_a_week() {
        let since = "2026-11-02T00:00:00Z";
        assert!(!retire_ready(
            since,
            at("2026-11-02T01:00:00Z"),
            false,
            false
        ));
        assert!(retire_ready(
            since,
            at("2026-11-02T02:00:00Z"),
            false,
            false
        ));
        assert!(retire_ready(since, at("2026-11-09T00:00:00Z"), true, true));
        assert!(!retire_ready(since, at("2026-11-08T23:59:00Z"), true, true));
        assert!(retire_ready(
            "garbage",
            at("2026-11-02T00:00:00Z"),
            true,
            true
        ));
    }
}
