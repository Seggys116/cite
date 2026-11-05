use std::collections::BTreeMap;
use std::future::Future;
use std::time::Duration;

use cite_edge::model::{Site, Target};
use futures_util::StreamExt;
use futures_util::stream;
use serde::{Deserialize, Serialize};

use crate::client::NodeClient;
use crate::error::ClientError;

pub const DEFAULT_FAN_OUT_LIMIT: usize = 8;

pub async fn fan_out<T, F, Fut>(
    clients: &[NodeClient],
    limit: usize,
    timeout: Option<Duration>,
    op: F,
) -> Vec<(String, Result<T, ClientError>)>
where
    F: Fn(NodeClient) -> Fut,
    Fut: Future<Output = Result<T, ClientError>>,
{
    // `buffered` keeps at most `limit` operations in flight and yields results in input order.
    stream::iter(clients.iter().cloned())
        .map(|client| {
            let name = client.name().to_string();
            let fut = op(client);
            async move {
                let result = match timeout {
                    Some(budget) => tokio::time::timeout(budget, fut)
                        .await
                        .unwrap_or_else(|_| Err(ClientError::timeout())),
                    None => fut.await,
                };
                (name, result)
            }
        })
        .buffered(limit.max(1))
        .collect::<Vec<_>>()
        .await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReplicationMode {
    Each,
    Replicate,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeTargets {
    #[serde(default)]
    pub blue: Option<Vec<Target>>,
    #[serde(default)]
    pub green: Option<Vec<Target>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicationPlan {
    pub site: Site,
    pub mode: ReplicationMode,
    pub per_node: BTreeMap<String, NodeTargets>,
}

impl ReplicationPlan {
    pub fn new(site: Site, mode: ReplicationMode) -> Self {
        Self {
            site,
            mode,
            per_node: BTreeMap::new(),
        }
    }

    pub fn with_node_targets(mut self, node: impl Into<String>, targets: NodeTargets) -> Self {
        self.per_node.insert(node.into(), targets);
        self
    }

    // Replicate mode ignores per-node overrides: its contract is an identical Site everywhere.
    pub fn site_for(&self, node: &str) -> Site {
        let mut site = self.site.clone();
        site.history.clear();
        if self.mode == ReplicationMode::Each
            && let Some(targets) = self.per_node.get(node)
        {
            if let Some(blue) = &targets.blue {
                site.blue.targets = blue.clone();
            }
            if let Some(green) = &targets.green {
                site.green.targets = green.clone();
            }
        }
        site
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeOutcome {
    pub node: String,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl NodeOutcome {
    pub fn failed(node: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            node: node.into(),
            ok: false,
            action: None,
            error: Some(error.into()),
        }
    }
}

async fn apply_one(
    client: NodeClient,
    mut site: Site,
    mode: ReplicationMode,
) -> Result<&'static str, ClientError> {
    match mode {
        ReplicationMode::Each => {
            client.create_site(&site).await?;
            Ok("created")
        }
        ReplicationMode::Replicate => match client.get_site(&site.id).await {
            Ok(existing) => {
                site.history = existing.site.history;
                client.update_site(&site.id, &site).await?;
                Ok("updated")
            }
            Err(err) if err.status_code() == Some(404) => {
                client.create_site(&site).await?;
                Ok("created")
            }
            Err(err) => Err(err),
        },
    }
}

pub async fn apply_plan(clients: &[NodeClient], plan: &ReplicationPlan) -> Vec<NodeOutcome> {
    let results = fan_out(clients, DEFAULT_FAN_OUT_LIMIT, None, |client| {
        let site = plan.site_for(client.name());
        apply_one(client, site, plan.mode)
    })
    .await;
    results
        .into_iter()
        .map(|(node, result)| match result {
            Ok(action) => NodeOutcome {
                node,
                ok: true,
                action: Some(action.to_string()),
                error: None,
            },
            Err(err) => NodeOutcome::failed(node, err.to_string()),
        })
        .collect()
}

pub async fn apply_site_to_nodes(
    clients: &[NodeClient],
    site: &Site,
    mode: ReplicationMode,
) -> Vec<NodeOutcome> {
    apply_plan(clients, &ReplicationPlan::new(site.clone(), mode)).await
}
