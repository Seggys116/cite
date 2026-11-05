#![forbid(unsafe_code)]

pub mod client;
pub mod config;
pub mod error;
pub mod fleet;
pub mod tokens;

pub use client::{
    AuditEntry, CreatedToken, DeployRequest, Forwarded, LoginResponse, NodeClient, NodeInfo,
    PresetInfo, ReloadResult, RequestQuery, SiteDetail, TokenMeta,
};
pub use config::{
    CONFIG_VERSION, ConfigFile, DEFAULT_LISTEN, DashboardConfig, MAX_NODES, NodeConfig,
    is_loopback_host, parse_node_url,
};
pub use error::{ClientError, ConfigError};
pub use fleet::{
    DEFAULT_FAN_OUT_LIMIT, NodeOutcome, NodeTargets, ReplicationMode, ReplicationPlan, apply_plan,
    apply_site_to_nodes, fan_out,
};
pub use tokens::{JsonTokenStore, MemoryTokenStore, TokenStore};
