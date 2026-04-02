//! Layered configuration via `figment` (TOML file → env vars → CLI overrides).
//!
//! Precedence (highest wins): CLI flags > `MUSPELL_*` env vars > config file
//! > built-in defaults.

use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use url::Url;

use crate::error::{MuspellError, Result};

// ── KNS subsection ────────────────────────────────────────────────────────────

/// Configuration for the Kaspa Name Service RPC client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnsConfig {
    /// Primary KNS RPC endpoint.
    pub rpc_url: Url,

    /// Optional failover RPC endpoints tried in order.
    #[serde(default)]
    pub fallback_urls: Vec<Url>,

    /// Per-request timeout in milliseconds.
    #[serde(default = "default_kns_timeout_ms")]
    pub timeout_ms: u64,

    /// Maximum number of retry attempts before surfacing an error.
    #[serde(default = "default_kns_max_retries")]
    pub max_retries: u32,

    /// Initial backoff delay in milliseconds (doubles on each attempt).
    #[serde(default = "default_kns_backoff_ms")]
    pub initial_backoff_ms: u64,

    /// Hard cap on backoff delay in milliseconds.
    #[serde(default = "default_kns_max_backoff_ms")]
    pub max_backoff_ms: u64,

    /// Cache TTL for successfully resolved records (seconds).
    #[serde(default = "default_kns_cache_ttl_s")]
    pub cache_ttl_s: u64,
}

impl Default for KnsConfig {
    fn default() -> Self {
        Self {
            rpc_url: "https://api.kasplex.org/v1/kns"
                .parse()
                .expect("hardcoded URL is valid"),
            fallback_urls: vec![],
            timeout_ms: default_kns_timeout_ms(),
            max_retries: default_kns_max_retries(),
            initial_backoff_ms: default_kns_backoff_ms(),
            max_backoff_ms: default_kns_max_backoff_ms(),
            cache_ttl_s: default_kns_cache_ttl_s(),
        }
    }
}

fn default_kns_timeout_ms() -> u64 { 5_000 }
fn default_kns_max_retries() -> u32 { 5 }
fn default_kns_backoff_ms() -> u64 { 200 }
fn default_kns_max_backoff_ms() -> u64 { 30_000 }
fn default_kns_cache_ttl_s() -> u64 { 300 }

// ── Mirror subsection ─────────────────────────────────────────────────────────

/// Configuration for the EigenMead data-mirroring engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorConfig {
    /// Minimum number of live peers required before a blob is considered
    /// durably mirrored (quorum).
    #[serde(default = "default_quorum")]
    pub quorum: usize,

    /// How often (seconds) the mirror engine re-verifies peer health and
    /// triggers re-sync for any missing blobs.
    #[serde(default = "default_sync_interval_s")]
    pub sync_interval_s: u64,

    /// Maximum number of concurrent blob-push operations.
    #[serde(default = "default_max_concurrent_syncs")]
    pub max_concurrent_syncs: usize,

    /// Maximum blob size (bytes) the engine will mirror automatically.
    /// Larger blobs require explicit opt-in via the CLI.
    #[serde(default = "default_max_blob_bytes")]
    pub max_blob_bytes: u64,

    /// Local storage path for mirrored blobs.
    #[serde(default = "default_blob_store_path")]
    pub blob_store_path: PathBuf,
}

impl Default for MirrorConfig {
    fn default() -> Self {
        Self {
            quorum: default_quorum(),
            sync_interval_s: default_sync_interval_s(),
            max_concurrent_syncs: default_max_concurrent_syncs(),
            max_blob_bytes: default_max_blob_bytes(),
            blob_store_path: default_blob_store_path(),
        }
    }
}

fn default_quorum() -> usize { 3 }
fn default_sync_interval_s() -> u64 { 60 }
fn default_max_concurrent_syncs() -> usize { 8 }
fn default_max_blob_bytes() -> u64 { 512 * 1024 * 1024 } // 512 MiB
fn default_blob_store_path() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("muspell")
        .join("blobs")
}

// ── Node subsection ───────────────────────────────────────────────────────────

/// Configuration for the local Iroh node identity and networking.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// Path to the persistent node secret key file.
    #[serde(default = "default_key_path")]
    pub key_path: PathBuf,

    /// KNS names this node claims to own (validated on startup).
    #[serde(default)]
    pub owned_names: Vec<String>,

    /// Relay server URLs for NAT traversal.
    #[serde(default)]
    pub relay_urls: Vec<Url>,

    /// Bind address for the Iroh node's QUIC listener.
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            key_path: default_key_path(),
            owned_names: vec![],
            relay_urls: vec![],
            bind_addr: default_bind_addr(),
        }
    }
}

fn default_key_path() -> PathBuf {
    dirs::config_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("muspell")
        .join("node.key")
}
fn default_bind_addr() -> String { "0.0.0.0:11204".to_string() }

// ── Observability subsection ──────────────────────────────────────────────────

/// Tracing and health endpoint configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservabilityConfig {
    /// Log level filter (e.g. "info", "muspell=debug,warn").
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Output format: "pretty" | "json" | "compact".
    #[serde(default = "default_log_format")]
    pub log_format: String,

    /// Bind address for the HTTP health/metrics endpoint.
    #[serde(default = "default_health_addr")]
    pub health_addr: String,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
            log_format: default_log_format(),
            health_addr: default_health_addr(),
        }
    }
}

fn default_log_level() -> String { "info".to_string() }
fn default_log_format() -> String { "pretty".to_string() }
fn default_health_addr() -> String { "127.0.0.1:9090".to_string() }

// ── Root config ───────────────────────────────────────────────────────────────

/// Root configuration object, composed from all subsections.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct MuspellConfig {
    #[serde(default)]
    pub node: NodeConfig,

    #[serde(default)]
    pub kns: KnsConfig,

    #[serde(default)]
    pub mirror: MirrorConfig,

    #[serde(default)]
    pub observability: ObservabilityConfig,
}

impl MuspellConfig {
    /// Load configuration from `path` (TOML), then overlay `MUSPELL_*` env vars.
    ///
    /// # Errors
    ///
    /// Returns [`MuspellError::Config`] if the TOML is malformed or a required
    /// field is absent after all layers have been applied.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        Figment::from(Serialized::defaults(MuspellConfig::default()))
            .merge(Toml::file(path.as_ref()))
            .merge(Env::prefixed("MUSPELL_").split("__"))
            .extract()
            .map_err(|e| MuspellError::Config(e.to_string()))
    }

    /// Load from a specific path, falling back to XDG default location.
    pub fn load_or_default(path: Option<impl AsRef<Path>>) -> Result<Self> {
        let default_path = dirs::config_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("muspell")
            .join("config.toml");

        let p = path
            .as_ref()
            .map(|p| p.as_ref().to_path_buf())
            .unwrap_or(default_path);

        Self::load(&p)
    }
}
