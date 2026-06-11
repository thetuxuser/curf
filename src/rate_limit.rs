/// Token-bucket rate limiter for curf.
///
/// Each IP gets a separate bucket. Tokens refill at `rps` tokens/second.
/// The bucket can hold up to `burst` tokens, allowing short bursts.
///
/// A value of 0 for `rps` disables rate limiting entirely.

use dashmap::DashMap;
use std::net::IpAddr;
use std::time::Instant;

/// Per-IP token bucket
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

pub struct RateLimiter {
    rps: f64,
    burst: f64,
    buckets: DashMap<IpAddr, Bucket>,
}

impl RateLimiter {
    /// `rps`   — maximum sustained requests per second (0 = unlimited)
    /// `burst` — maximum burst size
    pub fn new(rps: u32, burst: u32) -> Self {
        Self {
            rps: rps as f64,
            burst: burst as f64,
            buckets: DashMap::new(),
        }
    }

    /// Returns true if the request is allowed, false if it exceeds the limit.
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        // Rate limiting is disabled when rps == 0
        if self.rps == 0.0 {
            return true;
        }

        let now = Instant::now();

        let mut bucket = self.buckets.entry(ip).or_insert_with(|| Bucket {
            tokens: self.burst,
            last_refill: now,
        });

        // Refill based on elapsed time
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rps).min(self.burst);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}
