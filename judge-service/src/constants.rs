use std::time::Duration;

pub use rustbox::config::constants::{KB, MB};

pub const DEFAULT_PORT: u16 = 4096;
pub const DEFAULT_WORKERS: usize = 2;
pub const DEFAULT_QUEUE_SIZE: usize = 100;
pub const DEFAULT_REAPER_INTERVAL_SECS: u64 = 60;
pub const DEFAULT_STALE_TIMEOUT_SECS: u64 = 300;
pub const DEFAULT_MAX_CODE_BYTES: usize = 64 * KB as usize;
pub const DEFAULT_MAX_STDIN_BYTES: usize = 256 * KB as usize;
pub const DEFAULT_SYNC_WAIT_TIMEOUT_SECS: u64 = 30;
pub const DEFAULT_WEBHOOK_TIMEOUT_SECS: u64 = 10;
pub const DEFAULT_DRAIN_TIMEOUT_SECS: u64 = 35;

pub const MAX_API_SECRET_LENGTH: usize = 256;
pub const MAX_LOG_CODE_LENGTH: usize = 512;
pub const HTTP_BODY_LIMIT: usize = MB as usize;
pub const DB_BUSY_TIMEOUT: Duration = Duration::from_millis(5000);

pub const RATE_LIMIT_WINDOW_SECS: u64 = 60;
pub const RATE_LIMIT_BUCKET_RETENTION_SECS: u64 = 300;

pub const WORKER_RETRY_DELAY: Duration = Duration::from_secs(1);
pub const WEBHOOK_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub const TEST_DEADLINE_SECS: u64 = 15;
pub const TEST_POLL_INTERVAL: Duration = Duration::from_millis(250);
pub const E2E_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
pub const E2E_HEALTH_TIMEOUT: Duration = Duration::from_secs(10);
pub const E2E_POLL_INTERVAL: Duration = Duration::from_millis(100);
