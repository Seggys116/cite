#![forbid(unsafe_code)]

pub mod archive;
pub mod certificate;
pub mod client;
pub mod config;
pub mod error;
pub mod export;
pub mod fleet;
pub mod fsio;
pub mod tokens;
pub mod zone;

pub use archive::{
    ARCHIVE_EXTENSIONS, ArchiveEntry, ArchiveKind, ArchiveList, CutReport, CutRequest,
    MAX_ARCHIVE_NAME_CHARS, MAX_CUT_DAYS, RestoreReport, archive_download_name,
    archive_kind_from_name, validate_archive_name,
};
pub use certificate::{
    CertificateInfo, CertificateList, CertificateSaved, CertificateUpload, CloudflareRanges,
    MAX_CERT_NAME_CHARS, MAX_PEM_BYTES, validate_certificate_id, validate_certificate_name,
};
pub use client::{
    AuditEntry, CreatedToken, DeployRequest, Forwarded, LoginResponse, NodeClient, NodeInfo,
    PresetInfo, ReloadResult, RequestQuery, SiteDetail, TokenMeta,
};
pub use config::{
    CONFIG_VERSION, ConfigFile, DEFAULT_LISTEN, DashboardConfig, MAX_NODES, NodeConfig,
    is_loopback_host, parse_node_url,
};
pub use error::{ClientError, ConfigError};
pub use export::{
    AnalyticsStats, BOT_CLASSES, DEFAULT_EXPORT_MAX_BYTES, EXPORT_TIMEOUT, ExportFormat,
    ExportKind, ExportQuery, ExportReport, ExportStream, TOP_KINDS, export_file_name,
    filename_from_disposition,
};
pub use fleet::{
    DEFAULT_FAN_OUT_LIMIT, NodeOutcome, NodeTargets, ReplicationMode, ReplicationPlan, apply_plan,
    apply_site_to_nodes, fan_out,
};
pub use tokens::{JsonTokenStore, MemoryTokenStore, TokenStore};
pub use zone::{ZoneSecret, ZoneSecretStatus, validate_site_id};
