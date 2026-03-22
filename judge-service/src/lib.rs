pub mod api;
pub mod config;
pub mod database;
pub mod job_queue;
pub mod types;
pub mod worker;

use std::sync::Arc;

use crate::database::Database;
use crate::job_queue::JobQueue;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<dyn Database>,
    pub queue: Arc<JobQueue>,
    pub worker_count: usize,
    pub api_key: Option<String>,
    pub node_id: String,
    pub allow_localhost_webhooks: bool,
    pub max_code_bytes: usize,
    pub max_stdin_bytes: usize,
    pub sync_wait_timeout_secs: u64,
    pub sync_poll_interval_ms: u64,
    pub webhook_timeout_secs: u64,
}
