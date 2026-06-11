//! Core request handler for curf.
//!
//! For each incoming request it:
//!   1. Runs security checks (WAF, rate limit, blocked IPs)
//!   2. Checks if the domain should redirect HTTP → HTTPS
//!   3. Tries to serve from static files (if configured)
//!   4. Forwards to a backend via the load balancer
//!   5. Handles WebSocket upgrades transparently
//!   6. Injects any configured extra response headers

use crate::config::DomainConfig;
use crate::error::{error_response, html_error};
use crate::load_balancer::LoadBalancerManager;
use crate::rate_limit::RateLimiter;
use crate::security::SecurityChecker;
use crate::static_files::StaticFileServer;

use anyhow::Result;
use http_body_util::{combinators::BoxBody, BodyExt, Empty};
use hyper::body::{Bytes, Incoming};
use hyper::client::conn::http1;
use hyper::header::{self, HeaderValue};
use hyper::upgrade;
use hyper::{Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::copy;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, error, warn};

type BoxResponse = Response<BoxBody<Bytes, hyper::Error>>;

// ─── ProxyHandler ─────────────────────────────────────────────────────────────

pub struct ProxyHandler {
    lb_manager: Arc<LoadBalancerManager>,
    rate_limiter: Arc<RateLimiter>,
    security: Arc<SecurityChecker>,
    timeout: Duration,
    domain_configs: Arc<HashMap<String, DomainConfig>>,
    static_servers: HashMap<String, StaticFileServer>,
}

impl ProxyHandler {
    pub fn new(
        lb_manager: Arc<LoadBalancerManager>,
        rate_limiter: Arc<RateLimiter>,
        security: Arc<SecurityChecker>,
        timeout_secs: u64,
        domain_configs: Arc<HashMap<String, DomainConfig>>,
    ) -> Self {
        // Pre-build static file servers for domains that have them
        let mut static_servers = HashMap::new();
        for (domain, cfg) in domain_configs.as_ref() {
            if let Some(sf) = &cfg.static_files {
                static_servers.insert(
                    domain.clone(),
                    StaticFileServer::new(&sf.root, sf.index.clone(), sf.autoindex),
                );
            }
        }

        Self {
            lb_manager,
            rate_limiter,
            security,
            timeout: Duration::from_secs(timeout_secs),
            domain_configs,
            static_servers,
        }
    }

    /// Main entry point — called for every HTTP/HTTPS request.
    pub async fn handle(
        &self,
        peer: SocketAddr,
        req: Request<Incoming>,
        is_tls: bool,
    ) -> Result<BoxResponse, hyper::Error> {
        let client_ip = peer.ip();
        let method = req.method().clone();
        let uri = req.uri().clone();
        let path = uri.path().to_string();
        let query = uri.query().map(|s| s.to_string());

        // Resolve the Host header to pick the right domain config
        let host = req
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(|h| h.split(':').next().unwrap_or(h).to_lowercase())
            .unwrap_or_default();

        debug!("{} {} {} (from {})", method, host, path, client_ip);

        // ── 1. Rate limiting ─────────────────────────────────────────────────
        if !self.rate_limiter.is_allowed(client_ip) {
            warn!("Rate limit exceeded for {}", client_ip);
            return Ok(error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "Too Many Requests",
            ));
        }

        // ── 2. WAF / security checks ─────────────────────────────────────────
        let ua = req
            .headers()
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok());
        if let Err(reason) = self.security.check_request(&path, query.as_deref(), ua) {
            warn!(
                "Security block for {} on {}{}: {}",
                client_ip, host, path, reason
            );
            return Ok(html_error(StatusCode::FORBIDDEN, "Forbidden", reason));
        }

        // ── 3. HTTP → HTTPS redirect ─────────────────────────────────────────
        if !is_tls {
            if let Some(cfg) = self.domain_configs.get(&host) {
                if cfg.redirect_to_https {
                    let location = format!(
                        "https://{}{}",
                        host,
                        uri.path_and_query().map(|p| p.as_str()).unwrap_or("/")
                    );
                    return Ok(Response::builder()
                        .status(StatusCode::MOVED_PERMANENTLY)
                        .header(header::LOCATION, &location)
                        .body(empty_body())
                        .unwrap());
                }
            }
        }

        // ── 4. WebSocket upgrade ─────────────────────────────────────────────
        if is_websocket_upgrade(&req) {
            return match self.proxy_websocket(req, &host, peer).await {
                Ok(r) => Ok(r),
                Err(e) => {
                    error!("WebSocket proxy error: {}", e);
                    Ok(error_response(
                        StatusCode::BAD_GATEWAY,
                        "WebSocket proxy error",
                    ))
                }
            };
        }

        // ── 5. Static files ──────────────────────────────────────────────────
        if let Some(sf) = self.static_servers.get(&host) {
            if let Some(mut resp) = sf.serve(&path, &method, req.headers()).await {
                inject_extra_headers(&mut resp, &host, &self.domain_configs);
                return Ok(resp);
            }
        }

        // ── 6. Proxy to backend ──────────────────────────────────────────────
        match self.proxy_http(req, &host, peer).await {
            Ok(mut resp) => {
                inject_extra_headers(&mut resp, &host, &self.domain_configs);
                Ok(resp)
            }
            Err(e) => {
                error!("Proxy error for {} {}: {}", host, path, e);
                Ok(html_error(
                    StatusCode::BAD_GATEWAY,
                    "Bad Gateway",
                    "The upstream server is unreachable.",
                ))
            }
        }
    }

    // ─── HTTP proxy ──────────────────────────────────────────────────────────

    async fn proxy_http(
        &self,
        mut req: Request<Incoming>,
        host: &str,
        peer: SocketAddr,
    ) -> Result<BoxResponse, anyhow::Error> {
        // Pick a backend
        let lb = self
            .lb_manager
            .get(host)
            .ok_or_else(|| anyhow::anyhow!("No backend for '{}'", host))?;

        let (backend_url, _guard) = lb
            .select(Some(peer.ip()))
            .ok_or_else(|| anyhow::anyhow!("All backends for '{}' are down", host))?;

        debug!("Proxying to backend: {}", backend_url);

        // Parse backend address
        let backend_uri: Uri = backend_url.parse()?;
        let backend_host = backend_uri.host().unwrap_or("localhost");
        let backend_port = backend_uri.port_u16().unwrap_or(80);
        let backend_addr = format!("{}:{}", backend_host, backend_port);

        // Rewrite request URI to origin-form (path + query only)
        let path_and_query = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());

        *req.uri_mut() = path_and_query.parse()?;

        // Set forwarding headers
        add_forwarding_headers(&mut req, peer, host);

        // Connect to backend
        let stream = timeout(self.timeout, TcpStream::connect(&backend_addr))
            .await
            .map_err(|_| anyhow::anyhow!("Connection timeout to {}", backend_addr))?
            .map_err(|e| anyhow::anyhow!("Cannot connect to {}: {}", backend_addr, e))?;

        let io = TokioIo::new(stream);
        let (mut sender, conn) = http1::handshake(io).await?;

        // Drive the connection in background
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!("Backend connection closed: {}", e);
            }
        });

        // Send the request
        let resp = timeout(self.timeout, sender.send_request(req))
            .await
            .map_err(|_| anyhow::anyhow!("Request timeout to {}", backend_addr))?
            .map_err(|e| anyhow::anyhow!("Request failed to {}: {}", backend_addr, e))?;

        lb.success(&backend_url);

        // Convert body type
        Ok(resp.map(|b| b.map_err(|e| e).boxed()))
    }

    // ─── WebSocket tunnel ────────────────────────────────────────────────────

    async fn proxy_websocket(
        &self,
        mut req: Request<Incoming>,
        host: &str,
        peer: SocketAddr,
    ) -> Result<BoxResponse, anyhow::Error> {
        let lb = self
            .lb_manager
            .get(host)
            .ok_or_else(|| anyhow::anyhow!("No backend for '{}'", host))?;

        let (backend_url, _guard) = lb
            .select(Some(peer.ip()))
            .ok_or_else(|| anyhow::anyhow!("All backends for '{}' are down", host))?;

        let backend_uri: Uri = backend_url.parse()?;
        let backend_host = backend_uri.host().unwrap_or("localhost");
        let backend_port = backend_uri.port_u16().unwrap_or(80);
        let backend_addr = format!("{}:{}", backend_host, backend_port);

        // Capture the client upgrade future BEFORE forwarding the request
        let client_upgrade = upgrade::on(&mut req);

        // Rewrite URI
        let path_and_query = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        *req.uri_mut() = path_and_query.parse()?;
        add_forwarding_headers(&mut req, peer, host);

        // Connect to backend
        let stream = timeout(self.timeout, TcpStream::connect(&backend_addr))
            .await
            .map_err(|_| anyhow::anyhow!("WS connection timeout to {}", backend_addr))?
            .map_err(|e| anyhow::anyhow!("WS cannot connect to {}: {}", backend_addr, e))?;

        let io = TokioIo::new(stream);
        let (mut sender, conn) = http1::handshake(io).await?;

        tokio::spawn(async move {
            if let Err(e) = conn.with_upgrades().await {
                debug!("WS backend connection closed: {}", e);
            }
        });

        // Send upgrade request to backend
        let backend_resp = timeout(self.timeout, sender.send_request(req))
            .await
            .map_err(|_| anyhow::anyhow!("WS handshake timeout to {}", backend_addr))?
            .map_err(|e| anyhow::anyhow!("WS handshake failed to {}: {}", backend_addr, e))?;

        if backend_resp.status() != StatusCode::SWITCHING_PROTOCOLS {
            anyhow::bail!(
                "Backend rejected WebSocket upgrade: {}",
                backend_resp.status()
            );
        }

        // Capture backend upgrade future
        let backend_upgrade = upgrade::on(backend_resp);

        // Spawn bidirectional tunnel
        tokio::spawn(async move {
            let client_io = match client_upgrade.await {
                Ok(u) => TokioIo::new(u),
                Err(e) => {
                    error!("Client WebSocket upgrade failed: {}", e);
                    return;
                }
            };
            let backend_io = match backend_upgrade.await {
                Ok(u) => TokioIo::new(u),
                Err(e) => {
                    error!("Backend WebSocket upgrade failed: {}", e);
                    return;
                }
            };
            let (mut cr, mut cw) = tokio::io::split(client_io);
            let (mut br, mut bw) = tokio::io::split(backend_io);
            tokio::select! {
                _ = copy(&mut cr, &mut bw) => {}
                _ = copy(&mut br, &mut cw) => {}
            }
        });

        // Return the 101 Switching Protocols to the client
        Ok(Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .body(empty_body())
            .unwrap())
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// True if the request is a WebSocket upgrade handshake.
fn is_websocket_upgrade(req: &Request<Incoming>) -> bool {
    let upgrade = req
        .headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    upgrade.eq_ignore_ascii_case("websocket")
}

/// Append standard forwarding headers to an outbound proxy request.
fn add_forwarding_headers(req: &mut Request<Incoming>, peer: SocketAddr, host: &str) {
    let headers = req.headers_mut();

    // X-Forwarded-For — append this hop's IP
    let xff = if let Some(existing) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        format!("{}, {}", existing, peer.ip())
    } else {
        peer.ip().to_string()
    };
    headers.insert(
        "x-forwarded-for",
        HeaderValue::from_str(&xff).unwrap_or(HeaderValue::from_static("")),
    );

    // X-Real-IP — always the direct connecting client IP
    headers.insert(
        "x-real-ip",
        HeaderValue::from_str(&peer.ip().to_string()).unwrap_or(HeaderValue::from_static("")),
    );

    // X-Forwarded-Host — original Host header
    if !host.is_empty() {
        if let Ok(v) = HeaderValue::from_str(host) {
            headers.insert("x-forwarded-host", v);
        }
    }
}

/// Inject domain-level extra response headers.
fn inject_extra_headers(
    resp: &mut BoxResponse,
    host: &str,
    domain_configs: &HashMap<String, DomainConfig>,
) {
    if let Some(cfg) = domain_configs.get(host) {
        for h in &cfg.headers {
            if let (Ok(name), Ok(value)) = (
                h.name.parse::<hyper::header::HeaderName>(),
                HeaderValue::from_str(&h.value),
            ) {
                resp.headers_mut().insert(name, value);
            }
        }
    }
}

fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new().map_err(|e| match e {}).boxed()
}
