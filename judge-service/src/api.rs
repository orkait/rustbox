use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use uuid::Uuid;

use crate::database::types::Submission;
use crate::types::{ErrorResponse, HealthResponse, ResultResponse, SubmitRequest, SubmitResponse};
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/submit", post(submit))
        .route("/api/result/{id}", get(result))
        .route("/api/languages", get(languages))
        .route("/api/health", get(health))
}

async fn submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SubmitRequest>,
) -> impl IntoResponse {
    // Check API key if configured
    if let Some(ref key) = state.api_key {
        let provided = headers.get("x-api-key").and_then(|v| v.to_str().ok());
        if provided != Some(key.as_str()) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!(ErrorResponse {
                    error: "invalid or missing API key".to_string(),
                })),
            )
                .into_response();
        }
    }

    // Validate code size
    const MAX_CODE_SIZE: usize = 64 * 1024; // 64KB
    if req.code.len() > MAX_CODE_SIZE {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "code exceeds maximum size of 64KB"})),
        )
            .into_response();
    }

    // Validate language
    let lang = req.language.to_lowercase();
    if !matches!(lang.as_str(), "python" | "py" | "cpp" | "c++" | "cxx" | "java") {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!(ErrorResponse {
                error: format!("unsupported language: {}", req.language),
            })),
        )
            .into_response();
    }

    // Parse optional Idempotency-Key header; generate UUID if absent
    let id = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_else(Uuid::new_v4);

    // Idempotency check: if this ID already exists, return current state
    match state.db.get_submission(id).await {
        Ok(Some(existing)) => {
            tracing::info!(%id, "idempotent hit - submission already exists");
            return (
                StatusCode::ACCEPTED,
                Json(serde_json::json!({
                    "id": existing.id,
                    "status": existing.status,
                })),
            )
                .into_response();
        }
        Ok(None) => { /* new submission, proceed */ }
        Err(e) => {
            tracing::error!(error = %e, "failed to check idempotency");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!(ErrorResponse {
                    error: "database error".to_string(),
                })),
            )
                .into_response();
        }
    }

    // Check queue backpressure before inserting
    if state.queue.is_full() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!(ErrorResponse {
                error: "queue full, try again later".to_string(),
            })),
        )
            .into_response();
    }

    // Build new submission
    let submission = Submission {
        id,
        user_id: None,
        ip_address: None,
        language: lang.clone(),
        code: req.code,
        stdin: req.stdin,
        status: "pending".to_string(),
        node_id: None,
        sandbox_id: None,
        verdict: None,
        exit_code: None,
        stdout: None,
        stderr: None,
        signal: None,
        error_message: None,
        cpu_time: None,
        wall_time: None,
        memory_peak: None,
        created_at: Utc::now(),
        started_at: None,
        completed_at: None,
    };

    // Insert into database
    if let Err(e) = state.db.insert_submission(&submission).await {
        tracing::error!(error = %e, "failed to create submission");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!(ErrorResponse {
                error: "database error".to_string(),
            })),
        )
            .into_response();
    }

    // Enqueue to job queue (no-op in Postgres mode; trigger fires NOTIFY)
    if let Err(e) = state.queue.enqueue(id).await {
        tracing::error!(error = %e, "failed to enqueue job");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!(ErrorResponse {
                error: "queue full, try again later".to_string(),
            })),
        )
            .into_response();
    }

    tracing::info!(%id, language = %lang, "submission queued");
    (StatusCode::ACCEPTED, Json(serde_json::json!(SubmitResponse { id }))).into_response()
}

async fn result(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    // Check API key if configured
    if let Some(ref key) = state.api_key {
        let provided = headers.get("x-api-key").and_then(|v| v.to_str().ok());
        if provided != Some(key.as_str()) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!(ErrorResponse {
                    error: "invalid or missing API key".to_string(),
                })),
            )
                .into_response();
        }
    }

    match state.db.get_submission(id).await {
        Ok(Some(sub)) => {
            let resp: ResultResponse = sub.into();
            (StatusCode::OK, Json(serde_json::json!(resp))).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!(ErrorResponse {
                error: "submission not found".to_string(),
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "database error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!(ErrorResponse {
                    error: "database error".to_string(),
                })),
            )
                .into_response()
        }
    }
}

async fn languages() -> Json<Vec<&'static str>> {
    Json(vec!["python", "cpp", "java"])
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".to_string(),
        workers: state.worker_count,
        queue_depth: state.queue.depth(),
        node_id: state.node_id.clone(),
    })
}
