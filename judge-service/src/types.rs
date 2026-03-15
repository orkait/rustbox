use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct SubmitRequest {
    pub language: String,
    pub code: String,
    #[serde(default)]
    pub stdin: String,
}

#[derive(Debug, Serialize)]
pub struct SubmitResponse {
    pub id: Uuid,
}

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct SubmissionRow {
    pub id: Uuid,
    pub language: String,
    pub code: String,
    pub stdin: String,
    pub status: String,
    pub verdict: Option<String>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub exit_code: Option<i32>,
    pub time_ms: Option<f64>,
    pub memory_kb: Option<i64>,
    pub cpu_time_ms: Option<f64>,
    pub wall_time_ms: Option<f64>,
    pub signal: Option<i32>,
    pub error_message: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize)]
pub struct ResultResponse {
    pub id: Uuid,
    pub status: String,
    pub verdict: Option<String>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub exit_code: Option<i32>,
    pub time_ms: Option<f64>,
    pub memory_kb: Option<i64>,
    pub cpu_time_ms: Option<f64>,
    pub wall_time_ms: Option<f64>,
    pub signal: Option<i32>,
    pub error_message: Option<String>,
    pub language: String,
    pub created_at: String,
    pub completed_at: Option<String>,
}

impl From<SubmissionRow> for ResultResponse {
    fn from(row: SubmissionRow) -> Self {
        Self {
            id: row.id,
            status: row.status,
            verdict: row.verdict,
            stdout: row.stdout,
            stderr: row.stderr,
            exit_code: row.exit_code,
            time_ms: row.time_ms,
            memory_kb: row.memory_kb,
            cpu_time_ms: row.cpu_time_ms,
            wall_time_ms: row.wall_time_ms,
            signal: row.signal,
            error_message: row.error_message,
            language: row.language,
            created_at: row.created_at.to_rfc3339(),
            completed_at: row.completed_at.map(|t| t.to_rfc3339()),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub workers: usize,
    pub queue_depth: usize,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}
