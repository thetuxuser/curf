/// Background health checker for curf.
///
/// For each domain that has health checks enabled, this spawns a task that
/// periodically sends an HTTP GET to the configured `path` on every backend.
/// Backends that fail to respond with a 2xx are marked as failed in the
/// circuit-breaker, causing the load balancer to skip them.

use crate::config::DomainConfig;
use crate::load_balancer::LoadBalancerManager;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{interval, timeout};
use tracing::{debug, info, warn};

/// Spawn one health-check background task per domain that has checking enabled.
pub fn start_health_checks(
    domain_configs: Arc<HashMap<String, DomainConfig>>,
    lb_manager: Arc<LoadBalancerManager>,
) {
    for (domain, cfg) in domain_configs.as_ref() {
        if !cfg.health_check.enabled || cfg.backends.is_empty() {
            continue;
        }

        let domain = domain.clone();
        let backends = cfg.backends.clone();
        let hc = cfg.health_check.clone();
        let lb_manager = lb_manager.clone();

        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(hc.interval_secs));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            info!(
                "Health checker started for '{}' — checking {} backend(s) every {}s",
                domain,
                backends.len(),
                hc.interval_secs,
            );

            loop {
                ticker.tick().await;

                let lb = match lb_manager.get(&domain) {
                    Some(lb) => lb,
                    None => break, // domain removed
                };

                for backend_url in &backends {
                    let check_url = format!(
                        "{}{}",
                        backend_url.trim_end_matches('/'),
                        if hc.path.starts_with('/') { hc.path.clone() } else { format!("/{}", hc.path) }
                    );

                    let ok = check_backend(&check_url, hc.timeout_secs).await;

                    if ok {
                        debug!("Health OK: {} ({})", backend_url, domain);
                        lb.success(backend_url);
                    } else {
                        warn!("Health FAIL: {} ({}) — marking as failed", backend_url, domain);
                        lb.failure(backend_url);
                    }
                }
            }
        });
    }
}

/// Send a GET request and return true if the response is 2xx.
async fn check_backend(url: &str, timeout_secs: u64) -> bool {
    let result = timeout(
        Duration::from_secs(timeout_secs),
        do_get(url),
    )
    .await;

    match result {
        Ok(Ok(status)) => status >= 200 && status < 300,
        Ok(Err(e)) => {
            debug!("Health check error for {}: {}", url, e);
            false
        }
        Err(_) => {
            debug!("Health check timeout for {}", url);
            false
        }
    }
}

/// Minimal HTTP GET using only std + tokio (no heavy HTTP client dependency).
async fn do_get(url: &str) -> Result<u16, Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    // Parse the URL manually (we only need host, port, path)
    let without_scheme = url
        .strip_prefix("http://")
        .ok_or("only http:// backends supported for health checks")?;

    let (host_port, path) = if let Some(idx) = without_scheme.find('/') {
        (&without_scheme[..idx], &without_scheme[idx..])
    } else {
        (without_scheme, "/")
    };

    let (host, port) = if let Some(idx) = host_port.rfind(':') {
        (&host_port[..idx], host_port[idx + 1..].parse::<u16>().unwrap_or(80))
    } else {
        (host_port, 80u16)
    };

    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect(&addr).await?;

    // Write a minimal HTTP/1.0 request (no keep-alive, no fuss)
    let request = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nUser-Agent: curf-healthcheck/0.1\r\nConnection: close\r\n\r\n",
        path, host
    );
    stream.write_all(request.as_bytes()).await?;

    // Read just enough to get the status line
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).await?;
    let response = std::str::from_utf8(&buf[..n]).unwrap_or("");

    // Parse "HTTP/1.x NNN ..."
    let status: u16 = response
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    Ok(status)
}
