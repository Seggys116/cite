//! Gitea and Forgejo REST API v1 adapter.

use std::time::Duration;

use serde::Deserialize;

use super::transport::{AuthScheme, Transport};
use super::{
    BranchHead, ForgeKind, RepoTarget, check_repo_and_branch, compare_json, encode_segment,
    ensure_sha_ref, path_matches, poll_branch,
};
use crate::Result;
use crate::github::{PollResult, RateHints, ValidateOk};

#[derive(Debug, Clone)]
pub struct GiteaClient {
    http: Transport,
    repo_path: String,
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
    message: Option<String>,
    author: Option<AuthorJson>,
}

#[derive(Debug, Deserialize)]
struct AuthorJson {
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CompareJson {
    commits: Option<Vec<CompareCommit>>,
}

#[derive(Debug, Deserialize)]
struct CompareCommit {
    files: Option<Vec<CompareFile>>,
}

#[derive(Debug, Deserialize)]
struct CompareFile {
    filename: String,
}

impl GiteaClient {
    pub fn new(
        api_url: &str,
        owner: &str,
        name: &str,
        branch: &str,
        token: &cite_core::GithubToken,
    ) -> Result<Self> {
        Ok(Self {
            http: Transport::new(api_url, token, AuthScheme::Token)?,
            repo_path: format!("/repos/{}/{}", encode_segment(owner), encode_segment(name)),
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

    fn repo_url(&self, suffix: &str) -> String {
        self.http.endpoint(&format!("{}{suffix}", self.repo_path))
    }

    fn branch_url(&self) -> String {
        self.repo_url(&format!("/branches/{}", encode_segment(&self.branch)))
    }

    fn target(&self) -> RepoTarget<'_> {
        RepoTarget {
            kind: ForgeKind::Gitea,
            owner: &self.owner,
            name: &self.name,
            branch: &self.branch,
            scope: "read:repository",
        }
    }

    /// Gitea and Forgejo access tokens carry no expiry, so none is reported.
    pub async fn validate_access(&self) -> Result<ValidateOk> {
        check_repo_and_branch(
            &self.http,
            &self.target(),
            &self.repo_url(""),
            &self.branch_url(),
        )
        .await?;
        Ok(ValidateOk {
            token_expires_at: None,
        })
    }

    pub async fn poll_head(&self, etag: Option<&str>) -> Result<(PollResult, RateHints)> {
        poll_branch(&self.http, &self.branch_url(), etag, |b: BranchJson| {
            BranchHead {
                sha: b.commit.id,
                message: b.commit.message.unwrap_or_default(),
                author: b.commit.author.and_then(|a| a.name),
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
        let url = self.repo_url(&format!("/compare/{base_sha}...{head_sha}"));
        let Some(CompareJson {
            commits: Some(commits),
        }) = compare_json::<CompareJson>(&self.http, &url).await?
        else {
            return Ok(true);
        };
        // Older servers omit per-commit files; without them the change set is unknown.
        if commits.is_empty() || commits.iter().any(|c| c.files.is_none()) {
            return Ok(true);
        }
        Ok(commits
            .iter()
            .flat_map(|c| c.files.iter().flatten())
            .any(|file| path_matches(paths, &file.filename)))
    }

    pub async fn fetch_tarball(&self, sha: &str) -> Result<Vec<u8>> {
        ensure_sha_ref(sha)?;
        self.http
            .fetch_archive(&self.repo_url(&format!("/archive/{sha}.tar.gz")))
            .await
    }
}
