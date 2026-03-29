use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

pub struct RateLimiter {
    max_requests: u32,
    window_secs: u64,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

struct Bucket {
    tokens: u32,
    last_refill: Instant,
}

impl RateLimiter {
    pub fn new(max_requests_per_minute: u32) -> Self {
        Self {
            max_requests: max_requests_per_minute,
            window_secs: crate::constants::RATE_LIMIT_WINDOW_SECS,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    pub fn check(&self, ip: IpAddr) -> bool {
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();

        let bucket = buckets.entry(ip).or_insert_with(|| Bucket {
            tokens: self.max_requests,
            last_refill: now,
        });

        let elapsed = now.duration_since(bucket.last_refill).as_secs();
        if elapsed >= self.window_secs {
            bucket.tokens = self.max_requests;
            bucket.last_refill = now;
        } else {
            let refill =
                ((elapsed as f64 / self.window_secs as f64) * self.max_requests as f64) as u32;
            bucket.tokens = (bucket.tokens + refill).min(self.max_requests);
            if refill > 0 {
                bucket.last_refill = now;
            }
        }

        if bucket.tokens > 0 {
            bucket.tokens -= 1;
            true
        } else {
            false
        }
    }

    pub fn cleanup_stale(&self) {
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        buckets.retain(|_, b| {
            now.duration_since(b.last_refill).as_secs()
                < crate::constants::RATE_LIMIT_BUCKET_RETENTION_SECS
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    #[test]
    fn allows_up_to_limit() {
        let limiter = RateLimiter::new(5);
        let addr = ip(1);
        for _ in 0..5 {
            assert!(limiter.check(addr));
        }
    }

    #[test]
    fn blocks_over_limit() {
        let limiter = RateLimiter::new(3);
        let addr = ip(2);
        assert!(limiter.check(addr));
        assert!(limiter.check(addr));
        assert!(limiter.check(addr));
        assert!(!limiter.check(addr));
    }

    #[test]
    fn independent_per_ip() {
        let limiter = RateLimiter::new(2);
        let a = ip(3);
        let b = ip(4);
        assert!(limiter.check(a));
        assert!(limiter.check(a));
        assert!(!limiter.check(a));
        assert!(limiter.check(b));
        assert!(limiter.check(b));
        assert!(!limiter.check(b));
    }

    #[test]
    fn refills_after_window() {
        let limiter = RateLimiter::new(1);
        let addr = ip(5);
        assert!(limiter.check(addr));
        assert!(!limiter.check(addr));

        {
            let mut buckets = limiter.buckets.lock().unwrap();
            let bucket = buckets.get_mut(&addr).unwrap();
            bucket.last_refill = Instant::now()
                - std::time::Duration::from_secs(crate::constants::RATE_LIMIT_WINDOW_SECS + 1);
        }

        assert!(limiter.check(addr));
    }

    #[test]
    fn cleanup_removes_stale() {
        let limiter = RateLimiter::new(10);
        let a = ip(6);
        let b = ip(7);
        limiter.check(a);
        limiter.check(b);

        {
            let mut buckets = limiter.buckets.lock().unwrap();
            let bucket = buckets.get_mut(&a).unwrap();
            bucket.last_refill = Instant::now()
                - std::time::Duration::from_secs(
                    crate::constants::RATE_LIMIT_BUCKET_RETENTION_SECS + 1,
                );
        }

        limiter.cleanup_stale();

        let buckets = limiter.buckets.lock().unwrap();
        assert!(!buckets.contains_key(&a));
        assert!(buckets.contains_key(&b));
    }
}
