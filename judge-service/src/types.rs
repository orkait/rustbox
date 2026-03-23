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

#[allow(dead_code)]
pub fn compress_meta(json: &str) -> String {
    use base64::Engine;
    use flate2::write::DeflateEncoder;
    use flate2::Compression;
    use std::io::Write;

    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(json.as_bytes()).unwrap();
    let compressed = encoder.finish().unwrap();
    base64::engine::general_purpose::STANDARD.encode(&compressed)
}

#[allow(dead_code)]
pub fn decompress_meta(compressed: &str) -> Option<serde_json::Value> {
    use base64::Engine;
    use flate2::read::DeflateDecoder;
    use std::io::Read;

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(compressed)
        .ok()?;
    let mut decoder = DeflateDecoder::new(&bytes[..]);
    let mut json_str = String::new();
    decoder.read_to_string(&mut json_str).ok()?;
    serde_json::from_str(&json_str).ok()
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
