//! Single-node integration tests for judge-service (SQLite mode).
//!
//! Each test spins up an Axum server on a random port backed by a temporary
//! SQLite database, then exercises the API over HTTP with reqwest.
//!
//! These tests verify the API contract and request flow. Actual sandbox
//! execution requires root and cgroup setup, so verdicts may be "IE" or "RE"
//! in unprivileged CI environments - the tests assert that the submission
//! progressed past "pending" (i.e., the worker attempted execution).

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use uuid::Uuid;

/// Spin up a judge-service HTTP server on a random port with a fresh SQLite DB.
/// Returns the base URL (e.g. "http://127.0.0.1:12345") and the DB handle.
async fn start_server() -> (String, Arc<dyn judge_service::database::Database>) {
    let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
    let db_url = format!("sqlite:{}", tmp.path().display());

    let db: Arc<dyn judge_service::database::Database> = Arc::from(
        judge_service::database::connect(&db_url)
            .await
            .expect("failed to connect to temp SQLite"),
    );

    let queue = Arc::new(judge_service::job_queue::JobQueue::channel(100));

    // Spawn channel workers (they will attempt sandbox execution)
    let _handles = judge_service::worker::spawn_channel_workers(
        2,
        db.clone(),
        queue.clone(),
        "test-node".to_string(),
        10,
    );

    let state = judge_service::AppState {
        db: db.clone(),
        queue,
        worker_count: 2,
        api_key: None,
        node_id: "test-node".to_string(),
        allow_localhost_webhooks: true,
        max_code_bytes: 64 * 1024,
        max_stdin_bytes: 256 * 1024,
        sync_wait_timeout_secs: 30,
        sync_poll_interval_ms: 200,
        webhook_timeout_secs: 10,
        cgroup_backend: None,
        namespace_support: false,
        enforcement_mode: "none".to_string(),
        available_languages: vec![
            "python".to_string(),
            "c".to_string(),
            "cpp".to_string(),
            "java".to_string(),
            "javascript".to_string(),
            "typescript".to_string(),
        ],
        rate_limiter: None,
    };

    let app = judge_service::api::router().with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind to random port");
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Keep the temp file alive by leaking it - it will be cleaned up when the
    // process exits. This prevents the file from being deleted while the DB
    // connection is still open.
    std::mem::forget(tmp);

    (format!("http://127.0.0.1:{port}"), db)
}

/// Poll GET /api/result/{id} until the submission leaves "pending"/"running",
/// or until the timeout expires. Returns the final JSON response body.
async fn poll_until_done(client: &reqwest::Client, base_url: &str, id: &str) -> Value {
    let url = format!("{base_url}/api/result/{id}");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);

    loop {
        let resp = client.get(&url).send().await.expect("poll request failed");
        assert_eq!(resp.status(), 200, "expected 200 from result endpoint");

        let body: Value = resp.json().await.expect("failed to parse result JSON");
        let status = body["status"].as_str().unwrap_or("");

        if status != "pending" && status != "running" {
            return body;
        }

        if tokio::time::Instant::now() >= deadline {
            panic!(
                "submission {id} still in status \"{status}\" after 15s timeout. Last body: {body}"
            );
        }

        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_submit_and_poll_python() {
    let (base_url, _db) = start_server().await;
    let client = reqwest::Client::new();

    // POST /api/submit
    let resp = client
        .post(format!("{base_url}/api/submit"))
        .json(&serde_json::json!({
            "language": "python",
            "code": "print(42)"
        }))
        .send()
        .await
        .expect("submit request failed");

    assert_eq!(resp.status(), 202, "expected 202 Accepted");

    let body: Value = resp.json().await.expect("failed to parse submit JSON");
    let id = body["id"].as_str().expect("response missing 'id' field");

    // The id should be a valid UUID
    Uuid::parse_str(id).expect("id is not a valid UUID");

    // Poll until done
    let result = poll_until_done(&client, &base_url, id).await;
    let status = result["status"].as_str().unwrap();

    // The submission must have been attempted (not still pending)
    assert!(
        status == "completed" || status == "error",
        "expected status 'completed' or 'error', got '{status}'"
    );

    // If the worker managed to run the sandbox, we get a verdict.
    // If python3 is available and we're running as root, verdict should be AC
    // with stdout containing "42". Otherwise it may be RE/IE - that's acceptable.
    if let Some(verdict) = result["verdict"].as_str() {
        if verdict == "AC" {
            let stdout = result["stdout"].as_str().unwrap_or("");
            assert!(
                stdout.contains("42"),
                "AC verdict but stdout does not contain '42': {stdout}"
            );
        } else {
            // RE, IE, SIG are all acceptable in unprivileged environments
            assert!(
                ["RE", "IE", "SIG", "TLE", "MLE"].contains(&verdict),
                "unexpected verdict: {verdict}"
            );
        }
    }
}

#[tokio::test]
async fn test_idempotency_returns_cached() {
    let (base_url, _db) = start_server().await;
    let client = reqwest::Client::new();

    let idempotency_key = Uuid::new_v4().to_string();

    // First submission with Idempotency-Key
    let resp1 = client
        .post(format!("{base_url}/api/submit"))
        .header("idempotency-key", &idempotency_key)
        .json(&serde_json::json!({
            "language": "python",
            "code": "print('hello')"
        }))
        .send()
        .await
        .expect("first submit failed");

    assert_eq!(resp1.status(), 202);
    let body1: Value = resp1.json().await.unwrap();
    let id1 = body1["id"].as_str().expect("missing id in first response");

    // The returned ID should match the idempotency key (the API uses it as the UUID)
    assert_eq!(
        id1, idempotency_key,
        "first submission ID should equal the idempotency key"
    );

    // Second submission with the same Idempotency-Key
    let resp2 = client
        .post(format!("{base_url}/api/submit"))
        .header("idempotency-key", &idempotency_key)
        .json(&serde_json::json!({
            "language": "python",
            "code": "print('hello')"
        }))
        .send()
        .await
        .expect("second submit failed");

    assert_eq!(resp2.status(), 202);
    let body2: Value = resp2.json().await.unwrap();
    let id2 = body2["id"].as_str().expect("missing id in second response");

    // Same ID both times - the second call hit the idempotency check
    assert_eq!(id1, id2, "idempotent resubmit should return the same ID");

    // Verify via the result endpoint that both point to the same submission
    let result1 = client
        .get(format!("{base_url}/api/result/{id1}"))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let result2 = client
        .get(format!("{base_url}/api/result/{id2}"))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();

    assert_eq!(
        result1["created_at"], result2["created_at"],
        "idempotent submissions should share the same created_at"
    );
}

#[tokio::test]
async fn test_health_endpoint() {
    let (base_url, _db) = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{base_url}/api/health"))
        .send()
        .await
        .expect("health request failed");

    assert_eq!(resp.status(), 200);

    let body: Value = resp.json().await.expect("failed to parse health JSON");

    assert_eq!(body["status"].as_str(), Some("ok"));
    assert_eq!(body["workers"].as_u64(), Some(2));
    assert_eq!(body["node_id"].as_str(), Some("test-node"));
    assert!(
        body["queue_depth"].is_number(),
        "queue_depth should be a number"
    );
}

#[tokio::test]
async fn test_languages_endpoint() {
    let (base_url, _db) = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{base_url}/api/languages"))
        .send()
        .await
        .expect("languages request failed");

    assert_eq!(resp.status(), 200);

    let body: Value = resp.json().await.expect("failed to parse languages JSON");
    let languages: Vec<&str> = body
        .as_array()
        .expect("expected JSON array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();

    assert!(
        languages.contains(&"python"),
        "languages should contain 'python'"
    );
    assert!(languages.contains(&"cpp"), "languages should contain 'cpp'");
    assert!(
        languages.contains(&"java"),
        "languages should contain 'java'"
    );
}

#[tokio::test]
async fn test_invalid_language_rejected() {
    let (base_url, _db) = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base_url}/api/submit"))
        .json(&serde_json::json!({
            "language": "brainfuck",
            "code": "+++"
        }))
        .send()
        .await
        .expect("submit request failed");

    assert_eq!(
        resp.status(),
        400,
        "unsupported language should return 400 Bad Request"
    );

    let body: Value = resp.json().await.expect("failed to parse error JSON");
    let error_msg = body["error"].as_str().unwrap_or("");
    assert!(
        error_msg.contains("unsupported language"),
        "error should mention unsupported language, got: {error_msg}"
    );
}

#[tokio::test]
async fn test_result_not_found() {
    let (base_url, _db) = start_server().await;
    let client = reqwest::Client::new();

    let random_id = Uuid::new_v4();

    let resp = client
        .get(format!("{base_url}/api/result/{random_id}"))
        .send()
        .await
        .expect("result request failed");

    assert_eq!(
        resp.status(),
        404,
        "non-existent submission should return 404"
    );

    let body: Value = resp.json().await.expect("failed to parse error JSON");
    let error_msg = body["error"].as_str().unwrap_or("");
    assert!(
        error_msg.contains("not found"),
        "error should mention not found, got: {error_msg}"
    );
}
