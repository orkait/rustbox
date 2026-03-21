/// Service configuration loaded from environment variables.
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
}

impl ServiceConfig {
    pub fn from_env() -> Self {
        Self {
            port: env_or("RUSTBOX_PORT", 8080),
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
        }
    }
}

fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
