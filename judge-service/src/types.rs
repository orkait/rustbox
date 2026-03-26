use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::database::types::Submission;

#[derive(Debug, Deserialize)]
pub struct SubmitRequest {
    pub language: String,
    pub code: String,
    #[serde(default)]
    pub stdin: String,
    #[serde(default)]
    pub webhook_url: Option<String>,
    #[serde(default)]
    pub webhook_secret: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SubmitResponse {
    pub id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct ResultResponse {
    pub id: Uuid,
    pub status: String,
    pub language: String,
    pub verdict: Option<String>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub error_message: Option<String>,
    pub cpu_time: Option<f64>,
    pub wall_time: Option<f64>,
    pub memory_peak: Option<i64>,
    pub created_at: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
}

impl From<Submission> for ResultResponse {
    fn from(sub: Submission) -> Self {
        Self {
            id: sub.id,
            status: sub.status,
            language: sub.language,
            verdict: sub.verdict,
            stdout: sub.stdout,
            stderr: sub.stderr,
            exit_code: sub.exit_code,
            signal: sub.signal,
            error_message: sub.error_message,
            cpu_time: sub.cpu_time,
            wall_time: sub.wall_time,
            memory_peak: sub.memory_peak,
            created_at: sub.created_at.to_rfc3339(),
            started_at: sub.started_at.map(|t| t.to_rfc3339()),
            completed_at: sub.completed_at.map(|t| t.to_rfc3339()),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub enforcement_mode: String,
    pub cgroup_backend: Option<String>,
    pub namespace_support: bool,
    pub workers: usize,
    pub queue_depth: usize,
    pub node_id: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}
