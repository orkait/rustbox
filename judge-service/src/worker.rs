use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::database::types::{
    ExecutionOutput, VERDICT_ACCEPTED, VERDICT_INTERNAL_ERROR, VERDICT_MEMORY_LIMIT,
    VERDICT_RUNTIME_ERROR, VERDICT_SIGNALED, VERDICT_TIME_LIMIT,
};
use crate::database::Database;
use crate::job_queue::JobQueue;

pub fn spawn_channel_workers(
    count: usize,
    db: Arc<dyn Database>,
    queue: Arc<JobQueue>,
    node_id: String,
    webhook_timeout_secs: u64,
) -> Vec<tokio::task::JoinHandle<()>> {
    (0..count)
        .map(|idx| {
            let db = db.clone();
            let queue = queue.clone();
            let node_id = node_id.clone();
            tokio::spawn(async move {
                info!(worker = idx, "channel worker started");
                loop {
                    let job_id = match queue.dequeue().await {
                        Some(id) => id,
                        None => {
                            info!(worker = idx, "channel closed, worker exiting");
                            return;
                        }
                    };
                    info!(worker = idx, %job_id, "processing submission");
                    process_job(db.as_ref(), job_id, &node_id, webhook_timeout_secs).await;
                }
            })
        })
        .collect()
}

pub fn spawn_pg_workers(
    count: usize,
    db: Arc<dyn Database>,
    pg_db: Arc<crate::database::postgres::PgDatabase>,
    node_id: String,
    webhook_timeout_secs: u64,
) -> Vec<tokio::task::JoinHandle<()>> {
    let semaphore = Arc::new(Semaphore::new(count));

    let drain_handle = {
        let db = db.clone();
        let node_id = node_id.clone();
        let sem = semaphore.clone();
        tokio::spawn(async move {
            drain_pending(db, sem, node_id, webhook_timeout_secs).await;
        })
    };

    let listener_handle = {
        let db = db.clone();
        let node_id = node_id.clone();
        let sem = semaphore.clone();
        tokio::spawn(async move {
            let _ = drain_handle.await;

            let mut listener = match pg_db.listener().await {
                Ok(l) => l,
                Err(e) => {
                    error!(error = %e, "failed to create PG listener");
                    return;
                }
            };

            info!(concurrency = count, "pg listener started");

            loop {
                match listener.recv().await {
                    Ok(_notification) => {
                        let permit = sem.clone().acquire_owned().await;
                        match permit {
                            Ok(permit) => {
                                let db = db.clone();
                                let node_id = node_id.clone();
                                tokio::spawn(async move {
                                    if let Ok(Some(sub)) = db.claim_pending(&node_id).await {
                                        process_job(
                                            db.as_ref(),
                                            sub.id,
                                            &node_id,
                                            webhook_timeout_secs,
                                        )
                                        .await;
                                    }
                                    drop(permit);
                                });
                            }
                            Err(_) => {
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "pg listener error, reconnecting in 1s");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        })
    };

    vec![listener_handle]
}

async fn drain_pending(
    db: Arc<dyn Database>,
    sem: Arc<Semaphore>,
    node_id: String,
    webhook_timeout_secs: u64,
) {
    loop {
        let permit = match sem.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => return,
        };

        match db.claim_pending(&node_id).await {
            Ok(Some(sub)) => {
                let db = db.clone();
                let node_id = node_id.clone();
                tokio::spawn(async move {
                    process_job(db.as_ref(), sub.id, &node_id, webhook_timeout_secs).await;
                    drop(permit);
                });
            }
            Ok(None) => {
                drop(permit);
                return;
            }
            Err(e) => {
                warn!(error = %e, "drain_pending error");
                drop(permit);
                return;
            }
        }
    }
}

async fn process_job(db: &dyn Database, job_id: Uuid, node_id: &str, webhook_timeout_secs: u64) {
    if let Err(e) = db.mark_running(job_id, node_id, "allocating").await {
        error!(%job_id, error = %e, "failed to mark running, aborting");
        return;
    }

    let submission = match db.get_submission(job_id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            warn!(%job_id, "submission not found in database");
            let _ = db
                .mark_error(job_id, "submission vanished from database")
                .await;
            return;
        }
        Err(e) => {
            error!(%job_id, error = %e, "database read error");
            let _ = db
                .mark_error(job_id, &format!("database read error: {e}"))
                .await;
            return;
        }
    };

    let language = submission.language.clone();
    let code = submission.code.clone();
    let stdin = submission.stdin.clone();
    let webhook_url = submission.webhook_url.clone();
    let webhook_secret = submission.webhook_secret.clone();

    let code_hash = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(code.as_bytes());
        format!("{:x}", h.finalize())[..16].to_string()
    };
    info!(%job_id, %language, code_hash, code_bytes = code.len(), "executing submission");

    let result =
        tokio::task::spawn_blocking(move || execute_in_sandbox(&language, &code, &stdin)).await;

    match result {
        Ok(Ok(output)) => {
            if let Err(e) = db.mark_completed(job_id, &output).await {
                error!(%job_id, error = %e, "failed to store result, marking error");
                let _ = db
                    .mark_error(job_id, "execution succeeded but result storage failed")
                    .await;
            } else {
                info!(%job_id, verdict = output.verdict, "submission completed");
            }
        }
        Ok(Err(e)) => {
            error!(%job_id, error = %e, "execution failed");
            let _ = db.mark_error(job_id, &sanitize_error(&e)).await;
        }
        Err(e) => {
            error!(%job_id, error = %e, "worker task panicked");
            let _ = db.mark_error(job_id, "internal execution error").await;
        }
    }

    if let Some(url) = webhook_url {
        let secret = webhook_secret.unwrap_or_default();
        let payload = match db.get_submission(job_id).await {
            Ok(Some(s)) => Some(crate::types::ResultResponse::from(s)),
            _ => {
                warn!(%job_id, "webhook: could not fetch result for delivery");
                None
            }
        };
        if let Some(payload) = payload {
            tokio::spawn(deliver_webhook(
                job_id,
                url,
                secret,
                payload,
                webhook_timeout_secs,
            ));
        }
    }
}

async fn deliver_webhook(
    job_id: Uuid,
    url: String,
    secret: String,
    payload: crate::types::ResultResponse,
    timeout_secs: u64,
) {
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let body = match serde_json::to_string(&payload) {
        Ok(b) => b,
        Err(e) => {
            warn!(%job_id, error = %e, "webhook: failed to serialize payload");
            return;
        }
    };

    let timestamp = chrono::Utc::now().timestamp();
    let msg_id = job_id.to_string();

    // Standard Webhooks: sign "{msg_id}.{timestamp}.{body}"
    let signed_content = format!("{}.{}.{}", msg_id, timestamp, body);
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(signed_content.as_bytes());
    let signature = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .connect_timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_default();

    let delays = [0, 1, 5];
    for (attempt, delay_secs) in delays.iter().enumerate() {
        if *delay_secs > 0 {
            tokio::time::sleep(Duration::from_secs(*delay_secs)).await;
        }

        let result = client
            .post(&url)
            .header("webhook-id", &msg_id)
            .header("webhook-timestamp", timestamp.to_string())
            .header("webhook-signature", format!("v1,{}", signature))
            .header("content-type", "application/json")
            .body(body.clone())
            .send()
            .await;

        match result {
            Ok(resp) if resp.status().is_success() || resp.status().is_redirection() => {
                info!(%job_id, status = %resp.status(), attempt, "webhook delivered");
                return;
            }
            Ok(resp) => {
                warn!(%job_id, status = %resp.status(), attempt, "webhook rejected by server");
                if resp.status().as_u16() < 500 {
                    return;
                }
            }
            Err(e) => {
                warn!(%job_id, attempt, error = %e, "webhook delivery failed");
            }
        }
    }
    error!(%job_id, url, "webhook delivery failed after 3 attempts");
}

fn sanitize_error(raw: &str) -> String {
    let sanitized = raw
        .replace("/home/", "/.../<redacted>/")
        .replace("/tmp/rustbox/", "/sandbox/")
        .replace("/tmp/rustbox-uid-", "/sandbox-uid-")
        .replace("/tmp/rustbox-strict-root-", "/sandbox-root-")
        .replace("/sys/fs/cgroup/", "/cgroup/")
        .replace("/proc/self/", "/proc/.../<redacted>/")
        .replace("/etc/rustbox/", "/config/");
    if sanitized.len() > 512 {
        let end = sanitized
            .char_indices()
            .map(|(i, _)| i)
            .take_while(|&i| i <= 512)
            .last()
            .unwrap_or(0);
        format!("{}... (truncated)", &sanitized[..end])
    } else {
        sanitized
    }
}

fn execute_in_sandbox(language: &str, code: &str, stdin: &str) -> Result<ExecutionOutput, String> {
    use rustbox::config::types::IsolateConfig;
    use rustbox::runtime::isolate::{ExecutionOverrides, Isolate};

    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = rustbox::observability::audit::init_security_logger(None);
    });

    let mut config = IsolateConfig::with_language_defaults(language, "rustbox/0".to_string())
        .map_err(|e| format!("config error: {e}"))?;
    let is_root = unsafe { libc::geteuid() } == 0;
    if !is_root {
        config.strict_mode = false;
        config.allow_degraded = true;
    }

    let mut isolate = Isolate::new(config).map_err(|e| format!("isolate creation error: {e}"))?;

    let overrides = ExecutionOverrides {
        stdin_data: if stdin.is_empty() {
            None
        } else {
            Some(stdin.to_string())
        },
        ..ExecutionOverrides::default()
    };

    let result = isolate
        .execute_code_string(language, code, &overrides)
        .map_err(|e| format!("execution error: {e}"))?;

    let verdict = match result.status {
        rustbox::config::types::ExecutionStatus::Ok => VERDICT_ACCEPTED,
        rustbox::config::types::ExecutionStatus::RuntimeError => VERDICT_RUNTIME_ERROR,
        rustbox::config::types::ExecutionStatus::TimeLimit => VERDICT_TIME_LIMIT,
        rustbox::config::types::ExecutionStatus::MemoryLimit => VERDICT_MEMORY_LIMIT,
        rustbox::config::types::ExecutionStatus::Signaled => VERDICT_SIGNALED,
        rustbox::config::types::ExecutionStatus::InternalError => VERDICT_INTERNAL_ERROR,
        _ => VERDICT_RUNTIME_ERROR,
    }
    .to_string();

    let output = ExecutionOutput {
        verdict,
        exit_code: result.exit_code,
        stdout: result.stdout,
        stderr: result.stderr,
        signal: result.signal,
        error_message: result.error_message,
        cpu_time: result.cpu_time,
        wall_time: result.wall_time,
        memory_peak: (result.memory_peak / 1024) as i64,
    };

    let _ = isolate.cleanup();

    Ok(output)
}

pub fn spawn_reaper(
    db: Arc<dyn Database>,
    interval: Duration,
    timeout: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        info!(
            interval_secs = interval.as_secs(),
            timeout_secs = timeout.as_secs(),
            "reaper started"
        );
        loop {
            tokio::time::sleep(interval).await;
            match db.reap_stale(timeout).await {
                Ok(0) => {}
                Ok(n) => info!(count = n, "reaped stale submissions"),
                Err(e) => warn!(error = %e, "reaper error"),
            }
        }
    })
}
