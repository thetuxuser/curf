//! Load balancer for curf.
//!
//! Supports three strategies:
//!   round_robin      — cycle through backends evenly (default)
//!   least_connections — pick the backend with fewest active requests
//!   ip_hash           — always send the same client IP to the same backend
//!
//! A simple circuit-breaker per backend opens after 5 consecutive failures
//! and resets after 30 seconds, allowing the backend a chance to recover.

use crate::config::{DomainConfig, LoadBalance};
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};

const CB_THRESHOLD: usize = 5; // failures before circuit opens
const CB_RESET_SECS: u64 = 30; // seconds before circuit half-opens

// ─── Backend ──────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct Backend {
    /// Full URL, e.g. "http://127.0.0.1:3000"
    pub url: String,

    /// Number of requests currently being served
    active: Arc<AtomicUsize>,

    /// Consecutive failure count (resets on success)
    failures: Arc<AtomicUsize>,

    /// Unix timestamp of the last failure
    last_failure: Arc<AtomicU64>,

    /// True when the circuit is open (backend is considered down)
    circuit_open: Arc<AtomicBool>,
}

impl Backend {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            active: Arc::new(AtomicUsize::new(0)),
            failures: Arc::new(AtomicUsize::new(0)),
            last_failure: Arc::new(AtomicU64::new(0)),
            circuit_open: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn acquire(&self) {
        self.active.fetch_add(1, Ordering::Relaxed);
    }

    pub fn release(&self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn active_count(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    pub fn record_success(&self) {
        self.failures.store(0, Ordering::Relaxed);
        self.circuit_open.store(false, Ordering::Relaxed);
    }

    pub fn record_failure(&self) {
        let f = self.failures.fetch_add(1, Ordering::Relaxed) + 1;
        self.last_failure.store(unix_now(), Ordering::Relaxed);
        if f >= CB_THRESHOLD {
            self.circuit_open.store(true, Ordering::Relaxed);
        }
    }

    /// Returns true if the backend should receive traffic.
    /// An open circuit resets to closed after CB_RESET_SECS to allow recovery.
    pub fn is_healthy(&self) -> bool {
        if !self.circuit_open.load(Ordering::Relaxed) {
            return true;
        }
        let elapsed = unix_now() - self.last_failure.load(Ordering::Relaxed);
        if elapsed >= CB_RESET_SECS {
            // Half-open: allow one probe
            self.circuit_open.store(false, Ordering::Relaxed);
            self.failures.store(0, Ordering::Relaxed);
            true
        } else {
            false
        }
    }
}

// ─── ConnectionGuard — auto-releases when dropped ────────────────────────────

pub struct ConnectionGuard(Arc<Backend>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.release();
    }
}

// ─── LoadBalancer ─────────────────────────────────────────────────────────────

pub struct LoadBalancer {
    backends: Vec<Arc<Backend>>,
    strategy: LoadBalance,
    /// Round-robin cursor
    cursor: AtomicUsize,
}

impl LoadBalancer {
    pub fn new(cfg: &DomainConfig) -> Self {
        let backends = cfg
            .backends
            .iter()
            .map(|u| Arc::new(Backend::new(u)))
            .collect();
        Self {
            backends,
            strategy: cfg.load_balance.clone(),
            cursor: AtomicUsize::new(0),
        }
    }

    /// Pick an available backend and return (url, guard).
    /// Returns None when all backends have open circuits.
    pub fn select(&self, client_ip: Option<IpAddr>) -> Option<(String, ConnectionGuard)> {
        if self.backends.is_empty() {
            return None;
        }

        let b = match self.strategy {
            LoadBalance::RoundRobin => self.round_robin(),
            LoadBalance::LeastConnections => self.least_connections(),
            LoadBalance::IpHash => self.ip_hash(client_ip),
        }?;

        b.acquire();
        let url = b.url.clone();
        Some((url, ConnectionGuard(b)))
    }

    fn round_robin(&self) -> Option<Arc<Backend>> {
        let n = self.backends.len();
        for _ in 0..n {
            let idx = self.cursor.fetch_add(1, Ordering::Relaxed) % n;
            let b = &self.backends[idx];
            if b.is_healthy() {
                return Some(b.clone());
            }
        }
        None
    }

    fn least_connections(&self) -> Option<Arc<Backend>> {
        self.backends
            .iter()
            .filter(|b| b.is_healthy())
            .min_by_key(|b| b.active_count())
            .cloned()
    }

    fn ip_hash(&self, ip: Option<IpAddr>) -> Option<Arc<Backend>> {
        let hash = match ip {
            Some(IpAddr::V4(v4)) => u32::from(v4) as usize,
            Some(IpAddr::V6(v6)) => {
                let bytes = v6.octets();
                u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize
            }
            None => 0,
        };
        let n = self.backends.len();
        // Walk from the hash slot until we find a healthy backend
        for i in 0..n {
            let b = &self.backends[(hash + i) % n];
            if b.is_healthy() {
                return Some(b.clone());
            }
        }
        None
    }

    /// Record success for a backend URL (for circuit-breaker feedback)
    pub fn success(&self, url: &str) {
        if let Some(b) = self.backends.iter().find(|b| b.url == url) {
            b.record_success();
        }
    }

    /// Record failure for a backend URL
    pub fn failure(&self, url: &str) {
        if let Some(b) = self.backends.iter().find(|b| b.url == url) {
            b.record_failure();
        }
    }
}

// ─── LoadBalancerManager — one LB per domain ─────────────────────────────────

pub struct LoadBalancerManager {
    map: DashMap<String, Arc<LoadBalancer>>,
    // For domains without backends (static-only), we store None
}

impl LoadBalancerManager {
    pub fn new() -> Self {
        Self {
            map: DashMap::new(),
        }
    }

    pub fn add_domain(&self, domain: String, lb: Arc<LoadBalancer>) {
        self.map.insert(domain, lb);
    }

    pub fn get(&self, domain: &str) -> Option<Arc<LoadBalancer>> {
        self.map.get(domain).map(|r| r.clone())
    }
}

// ─── helpers ─────────────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
