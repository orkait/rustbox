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
            port: env_or("RUSTBOX_PORT", 4096),
            workers: env_or("RUSTBOX_WORKERS", 2),
            queue_size: env_or("RUSTBOX_QUEUE_SIZE", 100),
            database_url: std::env::var("RUSTBOX_DATABASE_URL")
                .unwrap_or_else(|_| "sqlite:rustbox.db".to_string()),
            api_key: std::env::var("RUSTBOX_API_KEY")
                .ok()
                .filter(|k| !k.is_empty()),
            node_id: std::env::var("RUSTBOX_NODE_ID")
                .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string()),
            reaper_interval_secs: env_or("RUSTBOX_REAPER_INTERVAL_SECS", 60),
            stale_timeout_secs: env_or("RUSTBOX_STALE_TIMEOUT_SECS", 300),
            allow_localhost_webhooks: env_or("RUSTBOX_ALLOW_LOCALHOST_WEBHOOKS", false),
            max_code_bytes: env_or("RUSTBOX_MAX_CODE_BYTES", 64 * 1024),
            max_stdin_bytes: env_or("RUSTBOX_MAX_STDIN_BYTES", 256 * 1024),
            sync_wait_timeout_secs: env_or("RUSTBOX_SYNC_WAIT_TIMEOUT_SECS", 30),
            webhook_timeout_secs: env_or("RUSTBOX_WEBHOOK_TIMEOUT_SECS", 10),
            drain_timeout_secs: env_or("RUSTBOX_DRAIN_TIMEOUT_SECS", 35),
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
