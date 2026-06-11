//! curf — a simple, fast reverse proxy and web server
//! https://github.com/thetuxuser/curf

mod config;
mod error;
mod health_check;
mod load_balancer;
mod proxy;
mod rate_limit;
mod security;
mod ssl;
mod static_files;

use crate::config::Config;
use crate::health_check::start_health_checks;
use crate::load_balancer::{LoadBalancer, LoadBalancerManager};
use crate::proxy::ProxyHandler;
use crate::rate_limit::RateLimiter;
use crate::security::SecurityChecker;
use crate::ssl::SslManager;

use anyhow::{Context, Result};
use clap::Parser;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{error, info, warn};

// ─── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "curf",
    about = "A simple, fast reverse proxy and web server",
    long_about = None
)]
struct Args {
    /// Path to your curf.yml config file
    #[arg(short, long, default_value = "curf.yml")]
    config: String,

    /// Override the HTTP port from config
    #[arg(long)]
    http_port: Option<u16>,

    /// Override the HTTPS port from config
    #[arg(long)]
    https_port: Option<u16>,
}

// ─── Per-IP connection guard (auto-decrements on drop) ───────────────────────

struct IpConnectionGuard {
    security: Arc<SecurityChecker>,
    ip: IpAddr,
}

impl Drop for IpConnectionGuard {
    fn drop(&mut self) {
        self.security.release_connection(self.ip);
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    // Set up logging — use RUST_LOG env var to control verbosity
    // e.g. RUST_LOG=debug curf  or  RUST_LOG=warn curf
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "curf=info".into()),
        )
        .init();

    let args = Args::parse();

    // ── Load config ─────────────────────────────────────────────────────────
    info!("Loading config from: {}", args.config);
    let mut config = Config::load(&args.config)
        .with_context(|| format!("Failed to load config file '{}'", args.config))?;

    // CLI port overrides
    if let Some(p) = args.http_port {
        config.server.http_port = p;
    }
    if let Some(p) = args.https_port {
        config.server.https_port = p;
    }

    info!(
        "Starting curf  |  HTTP :{} HTTPS :{}  |  {} domain(s)",
        config.server.http_port,
        config.server.https_port,
        config.domains.len()
    );

    // ── Build shared components ──────────────────────────────────────────────
    let lb_manager = Arc::new(LoadBalancerManager::new());
    let mut ssl_manager = SslManager::new();
    let mut tls_domains: Vec<String> = Vec::new();

    for (domain, domain_cfg) in &config.domains {
        info!("  domain: {}  backends: {:?}", domain, domain_cfg.backends);

        // Set up load balancer
        let lb = Arc::new(LoadBalancer::new(domain_cfg));
        lb_manager.add_domain(domain.clone(), lb);

        // Set up TLS if configured
        if let Some(tls) = &domain_cfg.tls {
            ssl_manager
                .add_domain(domain.clone(), &tls.cert, &tls.key)
                .with_context(|| format!("Failed to load TLS certs for '{}'", domain))?;
            tls_domains.push(domain.clone());
            info!("  TLS enabled for {}", domain);
        }
    }

    // Build the shared security/rate-limit state
    let rate_limiter = Arc::new(RateLimiter::new(
        config.server.rate_limit_rps,
        config.server.rate_limit_burst,
    ));
    let security = Arc::new(SecurityChecker::new(
        config.server.max_connections_per_ip,
        config.server.security.clone(),
    ));

    // ── Build proxy handler ──────────────────────────────────────────────────
    let proxy = Arc::new(ProxyHandler::new(
        lb_manager.clone(),
        rate_limiter,
        security.clone(),
        config.server.timeout_secs,
        Arc::new(config.domains.clone()),
    ));

    // ── Start background health checks ───────────────────────────────────────
    start_health_checks(Arc::new(config.domains.clone()), lb_manager.clone());

    // ── Spawn HTTP listener ──────────────────────────────────────────────────
    let http_port = config.server.http_port;
    let http_proxy = proxy.clone();
    let http_security = security.clone();
    let max_conns = config.server.max_connections;
    tokio::spawn(async move {
        if let Err(e) = serve_http(http_port, http_proxy, http_security, max_conns).await {
            error!("HTTP listener error: {}", e);
        }
    });

    // ── Start HTTPS listener (or just wait for Ctrl-C) ───────────────────────
    if ssl_manager.has_domains() {
        ssl_manager
            .build()
            .context("Failed to build TLS acceptor")?;
        let ssl_manager = Arc::new(ssl_manager);
        info!("TLS configured for: {:?}", tls_domains);
        serve_https(
            config.server.https_port,
            proxy,
            ssl_manager,
            security,
            max_conns,
        )
        .await?;
    } else {
        info!("No TLS domains configured — HTTPS listener not started.");
        tokio::signal::ctrl_c()
            .await
            .context("Failed to listen for Ctrl-C")?;
        info!("Shutdown signal received.");
    }

    Ok(())
}

// ─── HTTP listener ────────────────────────────────────────────────────────────

async fn serve_http(
    port: u16,
    proxy: Arc<ProxyHandler>,
    security: Arc<SecurityChecker>,
    max_conns: usize,
) -> Result<()> {
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("Cannot bind HTTP listener to {}", addr))?;
    info!("HTTP listening on {}", addr);

    let semaphore = Arc::new(Semaphore::new(max_conns));

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("Accept error: {}", e);
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };

        // Global connection cap
        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!("Global connection limit reached — dropping {}", peer);
                continue;
            }
        };

        // Per-IP connection cap
        if security.check_and_acquire_connection(peer.ip()).is_err() {
            warn!(
                "Per-IP connection limit reached for {} — dropping",
                peer.ip()
            );
            continue;
        }

        let _ = stream.set_nodelay(true);
        let io = TokioIo::new(stream);
        let proxy = proxy.clone();
        let security = security.clone();
        let ip = peer.ip();

        tokio::spawn(async move {
            let _permit = permit;
            let _guard = IpConnectionGuard {
                security: security.clone(),
                ip,
            };

            let svc = service_fn(move |req| {
                let proxy = proxy.clone();
                async move { proxy.handle(peer, req, false).await }
            });

            let builder = auto::Builder::new(TokioExecutor::new());
            let conn = builder.serve_connection(io, svc);
            if let Err(e) = timeout(Duration::from_secs(60), conn).await {
                warn!("HTTP connection timeout from {}: {:?}", peer, e);
            }
        });
    }
}

// ─── HTTPS listener ───────────────────────────────────────────────────────────

async fn serve_https(
    port: u16,
    proxy: Arc<ProxyHandler>,
    ssl: Arc<SslManager>,
    security: Arc<SecurityChecker>,
    max_conns: usize,
) -> Result<()> {
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("Cannot bind HTTPS listener to {}", addr))?;
    info!("HTTPS listening on {}", addr);

    let semaphore = Arc::new(Semaphore::new(max_conns));

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("HTTPS accept error: {}", e);
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };

        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!("Global HTTPS connection limit reached — dropping {}", peer);
                continue;
            }
        };

        if security.check_and_acquire_connection(peer.ip()).is_err() {
            warn!("Per-IP HTTPS connection limit reached for {}", peer.ip());
            continue;
        }

        let _ = stream.set_nodelay(true);
        let proxy = proxy.clone();
        let ssl = ssl.clone();
        let security = security.clone();
        let ip = peer.ip();

        tokio::spawn(async move {
            let _permit = permit;
            let _guard = IpConnectionGuard {
                security: security.clone(),
                ip,
            };

            let acceptor = ssl.acceptor();

            // TLS handshake (10s timeout)
            let tls_stream = match timeout(Duration::from_secs(10), acceptor.accept(stream)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    warn!("TLS handshake failed from {}: {}", peer, e);
                    security.record_tls_failure(peer.ip());
                    return;
                }
                Err(_) => {
                    warn!("TLS handshake timeout from {}", peer);
                    security.record_tls_failure(peer.ip());
                    return;
                }
            };

            let io = TokioIo::new(tls_stream);
            let svc = service_fn(move |req| {
                let proxy = proxy.clone();
                async move { proxy.handle(peer, req, true).await }
            });

            let builder = auto::Builder::new(TokioExecutor::new());
            let conn = builder.serve_connection(io, svc);
            if let Err(e) = timeout(Duration::from_secs(60), conn).await {
                warn!("HTTPS connection timeout from {}: {:?}", peer, e);
            }
        });
    }
}
