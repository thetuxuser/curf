/// curf configuration types and loader.
///
/// curf is configured with a single YAML file (default: curf.yml).
/// Run `curf --config /path/to/curf.yml` to specify a different path.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

// ─── Top-level config ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    /// Global server settings
    #[serde(default)]
    pub server: ServerConfig,

    /// Per-domain configurations  (domain name → config)
    pub domains: HashMap<String, DomainConfig>,
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("Cannot read config file '{}'", path))?;
        let config: Config = serde_yaml::from_str(&raw)
            .with_context(|| format!("Failed to parse YAML in '{}'", path))?;
        Ok(config)
    }
}

// ─── Server-level settings ────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    /// HTTP port (default: 80)
    #[serde(default = "default_http_port")]
    pub http_port: u16,

    /// HTTPS/TLS port (default: 443)
    #[serde(default = "default_https_port")]
    pub https_port: u16,

    /// Per-request timeout in seconds (default: 30)
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,

    /// Maximum simultaneous connections across all clients (default: 10_000)
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    /// Maximum simultaneous connections from a single IP (default: 100)
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: usize,

    /// Max requests per second per IP — 0 disables rate limiting (default: 100)
    #[serde(default = "default_rps")]
    pub rate_limit_rps: u32,

    /// Burst allowance on top of rate_limit_rps (default: 200)
    #[serde(default = "default_burst")]
    pub rate_limit_burst: u32,

    /// Security feature flags
    #[serde(default)]
    pub security: SecurityFlags,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            http_port: default_http_port(),
            https_port: default_https_port(),
            timeout_secs: default_timeout(),
            max_connections: default_max_connections(),
            max_connections_per_ip: default_max_connections_per_ip(),
            rate_limit_rps: default_rps(),
            rate_limit_burst: default_burst(),
            security: SecurityFlags::default(),
        }
    }
}

// ─── Security flags ───────────────────────────────────────────────────────────

/// Fine-grained on/off switches for security features.
/// All default to `true`. Set any to `false` to disable.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityFlags {
    /// Detect and block obvious SQL injection patterns in URLs/query strings
    #[serde(default = "default_true")]
    pub waf_sqli: bool,

    /// Detect and block obvious XSS patterns
    #[serde(default = "default_true")]
    pub waf_xss: bool,

    /// Detect and block directory traversal attempts (../)
    #[serde(default = "default_true")]
    pub waf_path_traversal: bool,

    /// Block IPs after too many failed TLS handshakes
    #[serde(default = "default_true")]
    pub block_tls_abusers: bool,

    /// Max TLS failures before an IP is blocked (default: 10)
    #[serde(default = "default_tls_failures")]
    pub max_tls_failures: u32,

    /// Block requests with no User-Agent header
    #[serde(default = "default_false")]
    pub block_empty_user_agent: bool,
}

impl Default for SecurityFlags {
    fn default() -> Self {
        Self {
            waf_sqli: true,
            waf_xss: true,
            waf_path_traversal: true,
            block_tls_abusers: true,
            max_tls_failures: default_tls_failures(),
            block_empty_user_agent: false,
        }
    }
}

// ─── Domain config ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DomainConfig {
    /// Upstream backends to proxy to.
    /// Leave empty if you are only serving static files.
    /// e.g.  ["http://127.0.0.1:3000", "http://127.0.0.1:3001"]
    #[serde(default)]
    pub backends: Vec<String>,

    /// Load-balancing strategy when multiple backends are listed (default: round_robin)
    #[serde(default)]
    pub load_balance: LoadBalance,

    /// TLS certificate files for this domain.
    /// Required if you want HTTPS for this domain.
    #[serde(default)]
    pub tls: Option<TlsConfig>,

    /// Serve static files from a local directory
    #[serde(default)]
    pub static_files: Option<StaticFilesConfig>,

    /// Redirect all HTTP requests for this domain to HTTPS
    #[serde(default)]
    pub redirect_to_https: bool,

    /// Health-check configuration for backends
    #[serde(default)]
    pub health_check: HealthCheckConfig,

    /// Extra response headers to inject (e.g. CORS, HSTS, caching)
    #[serde(default)]
    pub headers: Vec<ExtraHeader>,
}

// ─── Load balancing ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalance {
    /// Distribute requests evenly across backends in order (default)
    #[default]
    RoundRobin,
    /// Always pick the backend with the fewest active connections
    LeastConnections,
    /// Hash the client IP to always send the same IP to the same backend
    IpHash,
}

// ─── TLS config ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsConfig {
    /// Path to the PEM certificate chain file
    pub cert: String,
    /// Path to the PEM private key file
    pub key: String,
}

// ─── Static files config ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StaticFilesConfig {
    /// Root directory to serve files from.
    /// IMPORTANT: This must be an absolute path.
    pub root: String,

    /// List of filenames to look for when a directory is requested.
    /// Default: ["index.html"]
    #[serde(default = "default_index_files")]
    pub index: Vec<String>,

    /// Show a directory listing when no index file exists (default: false)
    #[serde(default)]
    pub autoindex: bool,
}

// ─── Health check config ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HealthCheckConfig {
    /// Enable periodic health checks (default: true)
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// How often to check, in seconds (default: 15)
    #[serde(default = "default_hc_interval")]
    pub interval_secs: u64,

    /// How long to wait for a response, in seconds (default: 5)
    #[serde(default = "default_hc_timeout")]
    pub timeout_secs: u64,

    /// Path to request (default: "/")
    #[serde(default = "default_hc_path")]
    pub path: String,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: default_hc_interval(),
            timeout_secs: default_hc_timeout(),
            path: default_hc_path(),
        }
    }
}

// ─── Extra header ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExtraHeader {
    pub name: String,
    pub value: String,
}

// ─── Default value helpers ────────────────────────────────────────────────────

fn default_http_port() -> u16 { 80 }
fn default_https_port() -> u16 { 443 }
fn default_timeout() -> u64 { 30 }
fn default_max_connections() -> usize { 10_000 }
fn default_max_connections_per_ip() -> usize { 100 }
fn default_rps() -> u32 { 100 }
fn default_burst() -> u32 { 200 }
fn default_true() -> bool { true }
fn default_false() -> bool { false }
fn default_tls_failures() -> u32 { 10 }
fn default_hc_interval() -> u64 { 15 }
fn default_hc_timeout() -> u64 { 5 }
fn default_hc_path() -> String { "/".to_string() }
fn default_index_files() -> Vec<String> {
    vec!["index.html".to_string()]
}
