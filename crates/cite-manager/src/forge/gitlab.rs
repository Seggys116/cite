//! GitLab REST API v4 adapter.

use std::time::Duration;

use reqwest::StatusCode;
use serde::Deserialize;

use super::transport::{AuthScheme, Transport};
use super::{
    BranchHead, ForgeKind, RepoTarget, check_repo_and_branch, compare_json, encode_segment,
    ensure_sha_ref, normalize_expiry, path_matches, poll_branch, warn_if_token_expiring,
};
use crate::Result;
use crate::github::{PollResult, RateHints, ValidateOk};

#[derive(Debug, Clone)]
pub struct GitlabClient {
    http: Transport,
    project: String,
    owner: String,
    name: String,
    branch: String,
}

#[derive(Debug, Deserialize)]
struct BranchJson {
    commit: CommitJson,
}

#[derive(Debug, Deserialize)]
struct CommitJson {
    id: String,
    title: Option<String>,
    message: Option<String>,
    author_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CompareJson {
    diffs: Option<Vec<DiffJson>>,
}

#[derive(Debug, Deserialize)]
struct DiffJson {
    old_path: Option<String>,
    new_path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenJson {
    expires_at: Option<String>,
}

impl GitlabClient {
    /// The project is addressed by its url-encoded `owner/name` path, so nested groups work too.
    pub fn new(
        api_url: &str,
        owner: &str,
        name: &str,
        branch: &str,
        token: &cite_core::GithubToken,
    ) -> Result<Self> {
        Ok(Self {
            http: Transport::new(api_url, token, AuthScheme::Bearer)?,
            project: encode_segment(&format!("{owner}/{name}")),
            owner: owner.to_string(),
            name: name.to_string(),
            branch: branch.to_string(),
        })
    }

    #[must_use]
    pub fn with_max_tarball_bytes(mut self, max: u64) -> Self {
        self.http.max_archive_bytes = max;
        self
    }

    #[must_use]
    pub fn with_tarball_timeout(mut self, timeout: Duration) -> Self {
        self.http.archive_timeout = timeout;
        self
    }

    pub fn read_token(&self) -> Result<String> {
        self.http.read_token()
    }

    fn project_url(&self, suffix: &str) -> String {
        self.http
            .endpoint(&format!("/projects/{}{suffix}", self.project))
    }

    fn branch_url(&self) -> String {
        self.project_url(&format!(
            "/repository/branches/{}",
            encode_segment(&self.branch)
        ))
    }

    fn target(&self) -> RepoTarget<'_> {
        RepoTarget {
            kind: ForgeKind::Gitlab,
            owner: &self.owner,
            name: &self.name,
            branch: &self.branch,
            scope: "read_api",
        }
    }

    pub async fn validate_access(&self) -> Result<ValidateOk> {
        check_repo_and_branch(
            &self.http,
            &self.target(),
            &self.project_url(""),
            &self.branch_url(),
        )
        .await?;
        let expires = self.token_expiry().await;
        if let Some(ref exp) = expires {
            warn_if_token_expiring(ForgeKind::Gitlab, exp);
        }
        Ok(ValidateOk {
            token_expires_at: expires,
        })
    }

    // OAuth and some deploy tokens cannot read this endpoint, so any failure just means unknown.
    async fn token_expiry(&self) -> Option<String> {
        let url = self.http.endpoint("/personal_access_tokens/self");
        let resp = self.http.get_json(&url, None).await.ok()?;
        if resp.status() != StatusCode::OK {
            return None;
        }
        let body: TokenJson = Transport::json(resp).await.ok()?;
        normalize_expiry(&body.expires_at?)
    }

    pub async fn poll_head(&self, etag: Option<&str>) -> Result<(PollResult, RateHints)> {
        poll_branch(&self.http, &self.branch_url(), etag, |b: BranchJson| {
            BranchHead {
                sha: b.commit.id,
                message: b.commit.title.or(b.commit.message).unwrap_or_default(),
                author: b.commit.author_name,
            }
        })
        .await
    }

    pub async fn paths_changed(
        &self,
        base_sha: &str,
        head_sha: &str,
        paths: &[String],
    ) -> Result<bool> {
        if paths.is_empty() {
            return Ok(true);
        }
        ensure_sha_ref(base_sha)?;
        ensure_sha_ref(head_sha)?;
        let url = self.project_url(&format!(
            "/repository/compare?from={base_sha}&to={head_sha}"
        ));
        let Some(CompareJson { diffs: Some(diffs) }) =
            compare_json::<CompareJson>(&self.http, &url).await?
        else {
            return Ok(true);
        };
        Ok(diffs.iter().any(|diff| {
            [&diff.old_path, &diff.new_path]
                .into_iter()
                .flatten()
                .any(|file| path_matches(paths, file))
        }))
    }

    pub async fn fetch_tarball(&self, sha: &str) -> Result<Vec<u8>> {
        ensure_sha_ref(sha)?;
        let url = self.project_url(&format!("/repository/archive.tar.gz?sha={sha}"));
        self.http.fetch_archive(&url).await
    }
}
