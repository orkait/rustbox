/// Service configuration loaded from environment variables.
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    pub port: u16,
    pub workers: usize,
    pub queue_size: usize,
    pub database_url: String,
    pub redis_url: String,
    /// Store full execution metadata (JudgeResultV1 JSON, compressed) in DB.
    /// Opt-in via RUSTBOX_STORE_META=true.
    pub store_meta: bool,
}

impl ServiceConfig {
    pub fn from_env() -> Self {
        Self {
            port: env_or("RUSTBOX_PORT", 8080),
            workers: env_or("RUSTBOX_WORKERS", 2),
            queue_size: env_or("RUSTBOX_QUEUE_SIZE", 100),
            database_url: std::env::var("RUSTBOX_DATABASE_URL")
                .expect("RUSTBOX_DATABASE_URL must be set"),
            redis_url: std::env::var("RUSTBOX_REDIS_URL")
                .expect("RUSTBOX_REDIS_URL must be set"),
            store_meta: env_or("RUSTBOX_STORE_META", false),
        }
    }
}

fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
