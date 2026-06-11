//! Security module for curf.
//!
//! Provides:
//!   - Per-IP connection tracking (prevents connection exhaustion from one IP)
//!   - Basic WAF: blocks SQLi, XSS and path-traversal patterns in URLs
//!   - TLS abuse detection: blocks IPs with too many failed handshakes
//!   - Optional: block requests with no User-Agent

use crate::config::SecurityFlags;
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use tracing::warn;

// ─── SecurityChecker ─────────────────────────────────────────────────────────

pub struct SecurityChecker {
    max_connections_per_ip: usize,
    connections: DashMap<IpAddr, usize>,
    tls_failures: DashMap<IpAddr, AtomicU32>,
    blocked_ips: DashMap<IpAddr, ()>,
    flags: SecurityFlags,
}

impl SecurityChecker {
    pub fn new(max_connections_per_ip: usize, flags: SecurityFlags) -> Self {
        Self {
            max_connections_per_ip,
            connections: DashMap::new(),
            tls_failures: DashMap::new(),
            blocked_ips: DashMap::new(),
            flags,
        }
    }

    // ── Connection tracking ──────────────────────────────────────────────────

    /// Returns Ok(()) and increments connection count.
    /// Returns Err(()) when the IP has hit the limit.
    pub fn check_and_acquire_connection(&self, ip: IpAddr) -> Result<(), ()> {
        if self.blocked_ips.contains_key(&ip) {
            return Err(());
        }
        let mut count = self.connections.entry(ip).or_insert(0);
        if *count >= self.max_connections_per_ip {
            return Err(());
        }
        *count += 1;
        Ok(())
    }

    /// Must be called when a connection for this IP ends.
    pub fn release_connection(&self, ip: IpAddr) {
        if let Some(mut count) = self.connections.get_mut(&ip) {
            if *count > 0 {
                *count -= 1;
            }
        }
    }

    // ── TLS abuse detection ──────────────────────────────────────────────────

    pub fn record_tls_failure(&self, ip: IpAddr) {
        if !self.flags.block_tls_abusers {
            return;
        }
        let entry = self
            .tls_failures
            .entry(ip)
            .or_insert_with(|| AtomicU32::new(0));
        let count = entry.fetch_add(1, Ordering::Relaxed) + 1;
        if count >= self.flags.max_tls_failures {
            warn!("Blocking {} after {} TLS failures", ip, count);
            self.blocked_ips.insert(ip, ());
        }
    }

    // ── WAF ──────────────────────────────────────────────────────────────────

    /// Check a request URL path + query for basic attack patterns.
    /// Returns an error message string if the request should be blocked.
    pub fn check_request(
        &self,
        path: &str,
        query: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<(), &'static str> {
        let _ip_blocked_sentinel = "blocked";

        // Block empty User-Agent if the flag is on
        if self.flags.block_empty_user_agent {
            let ua = user_agent.unwrap_or("").trim();
            if ua.is_empty() {
                return Err("No User-Agent");
            }
        }

        // Combine path and query for pattern matching
        let target = if let Some(q) = query {
            format!("{}?{}", path, q)
        } else {
            path.to_string()
        };
        let lower = target.to_lowercase();

        // Path traversal
        if self.flags.waf_path_traversal && (lower.contains("../") || lower.contains("..\\")) {
            return Err("Path traversal attempt");
        }

        // SQL injection — very common patterns
        if self.flags.waf_sqli {
            let sqli_patterns = [
                " or 1=1",
                "' or '",
                "' or 1",
                "union select",
                "union all select",
                "select * from",
                "drop table",
                "insert into",
                "delete from",
                "--",
                "xp_cmdshell",
                "exec(",
            ];
            for pat in sqli_patterns {
                if lower.contains(pat) {
                    return Err("SQL injection pattern detected");
                }
            }
        }

        // XSS — common patterns
        if self.flags.waf_xss {
            let xss_patterns = [
                "<script",
                "javascript:",
                "onerror=",
                "onload=",
                "onclick=",
                "alert(",
                "document.cookie",
                "eval(",
                "<iframe",
                "vbscript:",
            ];
            for pat in xss_patterns {
                if lower.contains(pat) {
                    return Err("XSS pattern detected");
                }
            }
        }

        Ok(())
    }
}
