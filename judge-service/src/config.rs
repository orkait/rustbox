use crate::constants;

#[derive(Debug, Clone)]
pub struct ServiceConfig {
    pub port: u16,
    pub workers: usize,
    pub queue_size: usize,
    pub database_url: String,
    pub api_key: Option<String>,
    pub node_id: String,
    pub reaper_interval_secs: u64,
    pub stale_timeout_secs: u64,
    pub allow_localhost_webhooks: bool,
    pub max_code_bytes: usize,
    pub max_stdin_bytes: usize,
    pub sync_wait_timeout_secs: u64,
    pub webhook_timeout_secs: u64,
    pub drain_timeout_secs: u64,
    pub rate_limit_per_minute: u32,
    pub trust_proxy_headers: bool,
}

impl ServiceConfig {
    pub fn from_env() -> Self {
        Self {
            port: env_or("RUSTBOX_PORT", constants::DEFAULT_PORT),
            workers: env_or("RUSTBOX_WORKERS", constants::DEFAULT_WORKERS),
            queue_size: env_or("RUSTBOX_QUEUE_SIZE", constants::DEFAULT_QUEUE_SIZE),
            database_url: std::env::var("RUSTBOX_DATABASE_URL")
                .unwrap_or_else(|_| "sqlite:rustbox.db".to_string()),
            api_key: std::env::var("RUSTBOX_API_KEY")
                .ok()
                .filter(|k| !k.is_empty()),
            node_id: std::env::var("RUSTBOX_NODE_ID")
                .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string()),
            reaper_interval_secs: env_or(
                "RUSTBOX_REAPER_INTERVAL_SECS",
                constants::DEFAULT_REAPER_INTERVAL_SECS,
            ),
            stale_timeout_secs: env_or(
                "RUSTBOX_STALE_TIMEOUT_SECS",
                constants::DEFAULT_STALE_TIMEOUT_SECS,
            ),
            allow_localhost_webhooks: env_or("RUSTBOX_ALLOW_LOCALHOST_WEBHOOKS", false),
            max_code_bytes: env_or("RUSTBOX_MAX_CODE_BYTES", constants::DEFAULT_MAX_CODE_BYTES),
            max_stdin_bytes: env_or(
                "RUSTBOX_MAX_STDIN_BYTES",
                constants::DEFAULT_MAX_STDIN_BYTES,
            ),
            sync_wait_timeout_secs: env_or(
                "RUSTBOX_SYNC_WAIT_TIMEOUT_SECS",
                constants::DEFAULT_SYNC_WAIT_TIMEOUT_SECS,
            ),
            webhook_timeout_secs: env_or(
                "RUSTBOX_WEBHOOK_TIMEOUT_SECS",
                constants::DEFAULT_WEBHOOK_TIMEOUT_SECS,
            ),
            drain_timeout_secs: env_or(
                "RUSTBOX_DRAIN_TIMEOUT_SECS",
                constants::DEFAULT_DRAIN_TIMEOUT_SECS,
            ),
            rate_limit_per_minute: env_or("RUSTBOX_RATE_LIMIT", 0),
            trust_proxy_headers: env_or("RUSTBOX_TRUST_PROXY_HEADERS", false),
        }
    }
}

fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
