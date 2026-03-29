use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;

use crate::database::types::{Submission, STATUS_COMPLETED, STATUS_ERROR, STATUS_PENDING};
use crate::types::{ErrorResponse, HealthResponse, ResultResponse, SubmitRequest, SubmitResponse};
use crate::AppState;

fn is_blocked_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64)  // CGN 100.64/10
                || (v4.octets()[0] == 198 && (v4.octets()[1] & 0xFE) == 18) // benchmark 198.18/15
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || {
                let seg = v6.segments();
                // fc00::/7 (unique local)
                (seg[0] & 0xFE00) == 0xFC00
                    // fe80::/10 (link-local)
                    || (seg[0] & 0xFFC0) == 0xFE80
                    // ::ffff:0:0/96 (IPv4-mapped) - check the mapped IPv4
                    || (seg[0..5] == [0, 0, 0, 0, 0] && seg[5] == 0xFFFF && {
                        let v4 = std::net::Ipv4Addr::new(
                            (seg[6] >> 8) as u8, seg[6] as u8,
                            (seg[7] >> 8) as u8, seg[7] as u8,
                        );
                        is_blocked_ip(std::net::IpAddr::V4(v4))
                    })
                    // ::ffff:0:0:0/96 (IPv4-translated)
                    || (seg[0..4] == [0, 0, 0, 0] && seg[4] == 0xFFFF && seg[5] == 0 && {
                        let v4 = std::net::Ipv4Addr::new(
                            (seg[6] >> 8) as u8, seg[6] as u8,
                            (seg[7] >> 8) as u8, seg[7] as u8,
                        );
                        is_blocked_ip(std::net::IpAddr::V4(v4))
                    })
            }
        }
    }
}

async fn validate_webhook_url(url: &str, allow_localhost: bool) -> Result<(), String> {
    let parsed: url::Url = url.parse().map_err(|_| "invalid webhook URL".to_string())?;

    if !allow_localhost && parsed.scheme() != "https" {
        return Err(
            "webhook_url must use HTTPS (set RUSTBOX_ALLOW_LOCALHOST_WEBHOOKS=true for dev mode)"
                .to_string(),
        );
    }
    if allow_localhost && !matches!(parsed.scheme(), "https" | "http") {
        return Err("webhook_url must use HTTP or HTTPS".to_string());
    }

    let host = parsed.host_str().ok_or("webhook_url missing host")?;

    if !allow_localhost {
        if host == "localhost" || host == "[::1]" {
            return Err("webhook_url cannot target localhost".to_string());
        }

        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            if is_blocked_ip(ip) {
                return Err("webhook_url cannot target private/loopback IPs".to_string());
            }
        } else {
            let lookup = format!("{}:{}", host, parsed.port().unwrap_or(443));
            let resolved: Vec<std::net::SocketAddr> = match tokio::net::lookup_host(&lookup).await {
                Ok(addrs) => addrs.collect(),
                Err(_) => {
                    return Err(format!("webhook_url host '{}' could not be resolved", host));
                }
            };
            for addr in &resolved {
                if is_blocked_ip(addr.ip()) {
                    return Err(format!(
                        "webhook_url host '{}' resolves to blocked IP {}",
                        host,
                        addr.ip()
                    ));
                }
            }
        }
    }

    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    // HMAC-based comparison: constant-time regardless of input length.
    // Both sides are MACed with a fixed key so timing reveals nothing.
    let fixed_key = b"rustbox-api-key-comparison";
    let mut mac_a = Hmac::<Sha256>::new_from_slice(fixed_key).unwrap();
    mac_a.update(a);
    let tag_a = mac_a.finalize().into_bytes();

    let mut mac_b = Hmac::<Sha256>::new_from_slice(fixed_key).unwrap();
    mac_b.update(b);
    let tag_b = mac_b.finalize().into_bytes();

    let mut diff = 0u8;
    for (x, y) in tag_a.iter().zip(tag_b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/submit", post(submit))
        .route("/api/result/{id}", get(result))
        .route("/api/languages", get(languages))
        .route("/api/health", get(health))
        .route("/api/health/ready", get(readiness))
}

#[derive(Debug, Deserialize, Default)]
struct SubmitQuery {
    #[serde(default)]
    wait: bool,
}

async fn submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SubmitQuery>,
    Json(req): Json<SubmitRequest>,
) -> impl IntoResponse {
    if let Some(ref limiter) = state.rate_limiter {
        let ip = if state.trust_proxy_headers {
            headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(',').next())
                .and_then(|s| s.trim().parse::<std::net::IpAddr>().ok())
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
        } else {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.trim().parse::<std::net::IpAddr>().ok())
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
        };
        if !limiter.check(ip) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!(ErrorResponse {
                    error: "rate limit exceeded, try again later".to_string(),
                })),
            )
                .into_response();
        }
    }

    if let Some(ref key) = state.api_key {
        let provided = headers
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !constant_time_eq(provided.as_bytes(), key.as_bytes()) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!(ErrorResponse {
                    error: "invalid or missing API key".to_string(),
                })),
            )
                .into_response();
        }
    }

    if req.code.len() > state.max_code_bytes {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("code exceeds maximum size of {}KB", state.max_code_bytes / crate::constants::KB as usize)})),
        )
            .into_response();
    }
    if req.stdin.len() > state.max_stdin_bytes {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("stdin exceeds maximum size of {}KB", state.max_stdin_bytes / crate::constants::KB as usize)})),
        )
            .into_response();
    }

    if let Some(ref url) = req.webhook_url {
        if let Err(msg) = validate_webhook_url(url, state.allow_localhost_webhooks).await {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!(ErrorResponse { error: msg })),
            )
                .into_response();
        }
        let secret = req.webhook_secret.as_deref().unwrap_or("");
        if secret.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!(ErrorResponse {
                    error: "webhook_secret is required when webhook_url is provided".to_string(),
                })),
            )
                .into_response();
        }
        if secret.len() > crate::constants::MAX_API_SECRET_LENGTH {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!(ErrorResponse {
                    error: "webhook_secret must be 256 bytes or less".to_string(),
                })),
            )
                .into_response();
        }
    }

    let lang = req.language.to_lowercase();
    if !state.available_languages.iter().any(|l| l == &lang) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!(ErrorResponse {
                error: format!(
                    "unsupported language: {}. available: {}",
                    req.language,
                    state.available_languages.join(", ")
                ),
            })),
        )
            .into_response();
    }

    let id = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_else(Uuid::new_v4);

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
        Ok(None) => {}
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

    if state.queue.is_full() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!(ErrorResponse {
                error: "queue full, try again later".to_string(),
            })),
        )
            .into_response();
    }

    let submission = Submission {
        id,
        user_id: None,
        ip_address: None,
        language: lang.clone(),
        code: req.code,
        stdin: req.stdin,
        webhook_url: req.webhook_url,
        webhook_secret: req.webhook_secret,
        status: STATUS_PENDING.to_string(),
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

    if !query.wait {
        return (
            StatusCode::ACCEPTED,
            Json(serde_json::json!(SubmitResponse { id })),
        )
            .into_response();
    }

    const SYNC_POLL_INTERVAL_MS: u64 = 10;
    let poll_interval = std::time::Duration::from_millis(SYNC_POLL_INTERVAL_MS);
    let max_wait = std::time::Duration::from_secs(state.sync_wait_timeout_secs);
    let deadline = tokio::time::Instant::now() + max_wait;

    loop {
        tokio::time::sleep(poll_interval).await;
        match state.db.get_submission(id).await {
            Ok(Some(sub)) if sub.status == STATUS_COMPLETED || sub.status == STATUS_ERROR => {
                let resp: ResultResponse = sub.into();
                return (StatusCode::OK, Json(serde_json::json!(resp))).into_response();
            }
            _ => {}
        }
        if tokio::time::Instant::now() >= deadline {
            return (
                StatusCode::REQUEST_TIMEOUT,
                Json(serde_json::json!({
                    "id": id,
                    "error": "execution did not complete within 30s, poll GET /api/result/{id}"
                })),
            )
                .into_response();
        }
    }
}

async fn result(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    if let Some(ref key) = state.api_key {
        let provided = headers
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !constant_time_eq(provided.as_bytes(), key.as_bytes()) {
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

async fn languages(State(state): State<AppState>) -> Json<Vec<String>> {
    Json(state.available_languages.clone())
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let mut resp = Json(serde_json::json!(HealthResponse {
        status: "ok".to_string(),
        enforcement_mode: state.enforcement_mode.clone(),
        cgroup_backend: state.cgroup_backend.clone(),
        namespace_support: state.namespace_support,
        workers: state.worker_count,
        queue_depth: state.queue.depth(),
        node_id: state.node_id.clone(),
    }))
    .into_response();
    if state.api_key.is_none() {
        resp.headers_mut().insert(
            "X-Rustbox-Warning",
            "No API key configured. Set RUSTBOX_API_KEY for production."
                .parse()
                .unwrap(),
        );
    }
    resp
}

async fn readiness(State(state): State<AppState>) -> impl IntoResponse {
    if state.enforcement_mode == "none" {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "not_ready",
                "enforcement_mode": state.enforcement_mode,
                "error": "no cgroup or namespace support available"
            })),
        )
            .into_response();
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ready",
            "enforcement_mode": state.enforcement_mode,
            "cgroup_backend": state.cgroup_backend,
            "namespace_support": state.namespace_support,
        })),
    )
        .into_response()
}
