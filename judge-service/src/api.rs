use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use uuid::Uuid;

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

    let id = Uuid::new_v4();

    // Insert into Postgres
    if let Err(e) = crate::db::create_submission(&state.db, id, &lang, &req.code, &req.stdin).await
    {
        tracing::error!(error = %e, "failed to create submission");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!(ErrorResponse {
                error: "database error".to_string(),
            })),
        )
            .into_response();
    }

    // Push to Redis queue (MultiplexedConnection is cheaply cloneable)
    let mut con = state.redis.clone();

    // Enforce queue size limit to prevent unbounded accumulation
    let queue_depth = crate::queue::queue_depth(&mut con).await.unwrap_or(0);
    if queue_depth >= state.max_queue_size {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!(ErrorResponse {
                error: "queue full, try again later".to_string(),
            })),
        )
            .into_response();
    }

    if let Err(e) = crate::queue::enqueue(&mut con, id).await {
        tracing::error!(error = %e, "failed to enqueue job");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!(ErrorResponse {
                error: "queue error".to_string(),
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

    match crate::db::get_submission(&state.db, id).await {
        Ok(Some(row)) => {
            let resp: ResultResponse = row.into();
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
    let mut con = state.redis.clone();
    let queue_depth = crate::queue::queue_depth(&mut con).await.unwrap_or(0);

    Json(HealthResponse {
        status: "ok".to_string(),
        workers: state.worker_count,
        queue_depth,
    })
}
