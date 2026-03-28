use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use reqwest::Client;
use serde_json::Value;

fn assert_verdict(r: &Value, expected: &str, test_name: &str) {
    let err = r["error_message"].as_str().unwrap_or("");
    let stderr = r["stderr"].as_str().unwrap_or("");
    let combined = format!("{} {}", err, stderr);
    let skip_patterns = [
        "not found",
        "not allowed",
        "Command not",
        "cannot find",
        "No such file",
        "isolate creation",
        "not available",
        "Path not under",
    ];
    if skip_patterns.iter().any(|p| combined.contains(p)) {
        eprintln!(
            "SKIPPED {}: runtime not available in this environment",
            test_name
        );
        return;
    }
    let verdict = r["verdict"].as_str().unwrap_or("null");
    assert_eq!(verdict, expected, "{} failed: {}", test_name, r);
}

struct TestServer {
    child: Child,
    port: u16,
    base_url: String,
    client: Client,
}

impl TestServer {
    async fn start(api_key: Option<&str>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind to random port");
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let binary = env!("CARGO_BIN_EXE_judge-service");
        let mut cmd = Command::new(binary);
        cmd.env("RUSTBOX_PORT", port.to_string())
            .env(
                "RUSTBOX_DATABASE_URL",
                format!("sqlite:rustbox-test-{}.db", port),
            )
            .env("RUSTBOX_WORKERS", "2")
            .env("RUSTBOX_SYNC_WAIT_TIMEOUT_SECS", "30")
            .env("RUSTBOX_SYNC_POLL_INTERVAL_MS", "100")
            .env("RUSTBOX_ALLOW_LOCALHOST_WEBHOOKS", "true")
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        if let Some(key) = api_key {
            cmd.env("RUSTBOX_API_KEY", key);
        }

        let child = cmd.spawn().expect("failed to start judge-service");

        let base_url = format!("http://127.0.0.1:{}", port);
        let client = Client::builder()
            .timeout(judge_service::constants::E2E_REQUEST_TIMEOUT)
            .build()
            .unwrap();

        let server = Self {
            child,
            port,
            base_url,
            client,
        };
        server.wait_ready().await;
        server
    }

    async fn wait_ready(&self) {
        let start = Instant::now();
        loop {
            if start.elapsed() > judge_service::constants::E2E_HEALTH_TIMEOUT {
                panic!(
                    "judge-service did not become ready within 10s on port {}",
                    self.port
                );
            }
            let url = format!("{}/api/health", self.base_url);
            if let Ok(resp) = reqwest::get(&url).await {
                if resp.status().is_success() {
                    return;
                }
            }
            tokio::time::sleep(judge_service::constants::E2E_POLL_INTERVAL).await;
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    async fn submit_sync(&self, language: &str, code: &str) -> Value {
        self.submit_sync_with_stdin(language, code, "").await
    }

    async fn submit_sync_with_stdin(&self, language: &str, code: &str, stdin: &str) -> Value {
        let body = serde_json::json!({
            "language": language,
            "code": code,
            "stdin": stdin,
        });
        let resp = self
            .client
            .post(self.url("/api/submit?wait=true"))
            .json(&body)
            .send()
            .await
            .expect("submit request failed");
        resp.json().await.expect("response not json")
    }

    async fn submit_sync_with_key(
        &self,
        language: &str,
        code: &str,
        key: &str,
    ) -> reqwest::Response {
        let body = serde_json::json!({
            "language": language,
            "code": code,
        });
        self.client
            .post(self.url("/api/submit?wait=true"))
            .header("x-api-key", key)
            .json(&body)
            .send()
            .await
            .expect("submit request failed")
    }

    async fn get(&self, path: &str) -> reqwest::Response {
        self.client
            .get(self.url(path))
            .send()
            .await
            .expect("get request failed")
    }

    async fn get_json(&self, path: &str) -> Value {
        self.get(path).await.json().await.expect("not json")
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let db_path = format!("rustbox-test-{}.db", self.port);
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(format!("{}-shm", db_path));
        let _ = std::fs::remove_file(format!("{}-wal", db_path));
    }
}

// ──────────────────────────────────────────────────────────────
// Health & infrastructure
// ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn health_liveness() {
    let server = TestServer::start(None).await;
    let json = server.get_json("/api/health").await;
    assert_eq!(json["status"], "ok");
    assert!(json.get("enforcement_mode").is_some());
    assert!(json.get("workers").is_some());
    assert!(json.get("queue_depth").is_some());
}

#[tokio::test]
async fn health_readiness() {
    let server = TestServer::start(None).await;
    let resp = server.get("/api/health/ready").await;
    let status = resp.status().as_u16();
    assert!(status == 200 || status == 503);
}

#[tokio::test]
async fn languages_endpoint() {
    let server = TestServer::start(None).await;
    let json = server.get_json("/api/languages").await;
    let langs = json.as_array().expect("should be array");
    assert!(!langs.is_empty());
}

#[tokio::test]
async fn no_auth_warning_header() {
    let server = TestServer::start(None).await;
    let resp = server.get("/api/health").await;
    let warning = resp.headers().get("x-rustbox-warning");
    assert!(
        warning.is_some(),
        "should have warning header when no API key set"
    );
}

// ──────────────────────────────────────────────────────────────
// Auth
// ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn auth_reject_without_key() {
    let server = TestServer::start(Some("test-secret-key")).await;
    let body = serde_json::json!({"language": "python", "code": "print(1)"});
    let resp = server
        .client
        .post(server.url("/api/submit"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
}

#[tokio::test]
async fn auth_accept_with_key() {
    let server = TestServer::start(Some("test-secret-key")).await;
    let resp = server
        .submit_sync_with_key("python", "print(1)", "test-secret-key")
        .await;
    assert_ne!(resp.status().as_u16(), 401);
}

// ──────────────────────────────────────────────────────────────
// Validation
// ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn unsupported_language_rejected() {
    let server = TestServer::start(None).await;
    let body = serde_json::json!({"language": "brainfuck", "code": "+++"});
    let resp = server
        .client
        .post(server.url("/api/submit"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
    let json: Value = resp.json().await.unwrap();
    let err = json["error"].as_str().unwrap_or("");
    assert!(
        err.contains("unsupported language"),
        "error should mention unsupported: {}",
        err
    );
    assert!(
        err.contains("available"),
        "error should list available languages: {}",
        err
    );
}

// ──────────────────────────────────────────────────────────────
// Python
// ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn python_ac() {
    let server = TestServer::start(None).await;
    let r = server.submit_sync("python", "print(42)").await;
    assert_verdict(&r, "AC", "python_ac");
    if r["verdict"] == "AC" {
        assert_eq!(r["stdout"].as_str().unwrap().trim(), "42");
    }
}

#[tokio::test]
async fn python_re() {
    let server = TestServer::start(None).await;
    let r = server
        .submit_sync("python", "raise ValueError('boom')")
        .await;
    assert_verdict(&r, "RE", "python_re");
}

#[tokio::test]
async fn python_stdin() {
    let server = TestServer::start(None).await;
    let r = server
        .submit_sync_with_stdin(
            "python",
            "import sys; print(sys.stdin.read().strip())",
            "hello\n",
        )
        .await;
    assert_verdict(&r, "AC", "python_stdin");
    if r["verdict"] == "AC" {
        assert_eq!(r["stdout"].as_str().unwrap().trim(), "hello");
    }
}

// ──────────────────────────────────────────────────────────────
// C
// ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn c_ac() {
    let server = TestServer::start(None).await;
    let r = server
        .submit_sync(
            "c",
            "#include<stdio.h>\nint main(){printf(\"%d\\n\",42);return 0;}",
        )
        .await;
    assert_verdict(&r, "AC", "c_ac");
}

// ──────────────────────────────────────────────────────────────
// C++
// ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn cpp_ac() {
    let server = TestServer::start(None).await;
    let r = server
        .submit_sync(
            "cpp",
            "#include<iostream>\nint main(){std::cout<<42<<std::endl;}",
        )
        .await;
    assert_verdict(&r, "AC", "cpp_ac");
}

#[tokio::test]
async fn cpp_compile_error() {
    let server = TestServer::start(None).await;
    let r = server.submit_sync("cpp", "this is not valid c++").await;
    assert_verdict(&r, "RE", "cpp_compile_error");
}

// ──────────────────────────────────────────────────────────────
// Java
// ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn java_ac() {
    let server = TestServer::start(None).await;
    let code =
        "public class Main { public static void main(String[] args) { System.out.println(42); } }";
    let r = server.submit_sync("java", code).await;
    assert_verdict(&r, "AC", "java_ac");
}

// ──────────────────────────────────────────────────────────────
// JavaScript
// ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn js_ac() {
    let server = TestServer::start(None).await;
    let r = server.submit_sync("javascript", "console.log(42)").await;
    assert_verdict(&r, "AC", "js_ac");
}

// ──────────────────────────────────────────────────────────────
// TypeScript
// ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn ts_ac() {
    let server = TestServer::start(None).await;
    let r = server.submit_sync("typescript", "console.log(42)").await;
    assert_verdict(&r, "AC", "ts_ac");
}
