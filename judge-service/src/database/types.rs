use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const STATUS_PENDING: &str = "pending";
pub const STATUS_RUNNING: &str = "running";
pub const STATUS_COMPLETED: &str = "completed";
pub const STATUS_ERROR: &str = "error";

pub const VERDICT_ACCEPTED: &str = "AC";
pub const VERDICT_RUNTIME_ERROR: &str = "RE";
pub const VERDICT_TIME_LIMIT: &str = "TLE";
pub const VERDICT_MEMORY_LIMIT: &str = "MLE";
pub const VERDICT_SIGNALED: &str = "SIG";
pub const VERDICT_INTERNAL_ERROR: &str = "IE";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Submission {
    pub id: Uuid,
    pub user_id: Option<String>,
    pub ip_address: Option<String>,
    pub language: String,
    pub code: String,
    pub stdin: String,
    pub webhook_url: Option<String>,
    pub webhook_secret: Option<String>,
    pub status: String,
    pub node_id: Option<String>,
    pub sandbox_id: Option<String>,
    pub verdict: Option<String>,
    pub exit_code: Option<i32>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub signal: Option<i32>,
    pub error_message: Option<String>,
    pub cpu_time: Option<f64>,
    pub wall_time: Option<f64>,
    pub memory_peak: Option<i64>,
    pub wall_time_limit_secs: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

pub struct ExecutionOutput {
    pub verdict: String,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub signal: Option<i32>,
    pub error_message: Option<String>,
    pub cpu_time: f64,
    pub wall_time: f64,
    pub memory_peak: i64,
}
