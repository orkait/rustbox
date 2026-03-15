use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{db, queue};

/// Spawn N worker tasks that dequeue jobs from Redis and execute via rustbox.
pub fn spawn_workers(
    count: usize,
    pool: PgPool,
    redis_client: redis::Client,
) -> Vec<tokio::task::JoinHandle<()>> {
    (0..count)
        .map(|worker_id| {
            let pool = pool.clone();
            let client = redis_client.clone();
            tokio::spawn(async move {
                worker_loop(worker_id, pool, client).await;
            })
        })
        .collect()
}

async fn worker_loop(worker_id: usize, pool: PgPool, redis_client: redis::Client) {
    info!(worker_id, "worker started");

    let mut con = match redis_client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(e) => {
            error!(worker_id, error = %e, "worker failed to connect to redis");
            return;
        }
    };

    loop {
        // Block-pop from Redis queue (5 second timeout, then retry)
        let job_id = match queue::dequeue(&mut con, 5.0).await {
            Ok(Some(id)) => id,
            Ok(None) => continue, // timeout, retry
            Err(e) => {
                warn!(worker_id, error = %e, "redis dequeue error, retrying in 1s");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };

        info!(worker_id, %job_id, "processing submission");
        process_job(worker_id, &pool, job_id).await;
    }
}

async fn process_job(worker_id: usize, pool: &PgPool, job_id: Uuid) {
    // Fetch submission from Postgres
    let submission = match db::get_submission(pool, job_id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            warn!(worker_id, %job_id, "submission not found in database");
            return;
        }
        Err(e) => {
            error!(worker_id, %job_id, error = %e, "database read error");
            return;
        }
    };

    // Mark as running
    if let Err(e) = db::mark_running(pool, job_id).await {
        error!(worker_id, %job_id, error = %e, "failed to mark running");
    }

    // Execute via rustbox (blocking — run on a dedicated thread)
    let language = submission.language.clone();
    let code = submission.code.clone();
    let stdin = submission.stdin.clone();
    let box_id = worker_id as u32;

    let result = tokio::task::spawn_blocking(move || execute_submission(&language, &code, &stdin, box_id))
        .await;

    match result {
        Ok(Ok((verdict, stdout, stderr, exit_code, time_ms, memory_kb))) => {
            if let Err(e) = db::update_result(
                pool, job_id, &verdict, &stdout, &stderr, exit_code, time_ms, memory_kb,
            )
            .await
            {
                error!(worker_id, %job_id, error = %e, "failed to update result");
            } else {
                info!(worker_id, %job_id, verdict, "submission completed");
            }
        }
        Ok(Err(e)) => {
            error!(worker_id, %job_id, error = %e, "execution failed");
            let _ = db::mark_error(pool, job_id, &e).await;
        }
        Err(e) => {
            error!(worker_id, %job_id, error = %e, "worker task panicked");
            let _ = db::mark_error(pool, job_id, &format!("internal error: {e}")).await;
        }
    }
}

/// Run a submission through rustbox. Returns (verdict, stdout, stderr, exit_code, time_ms, memory_kb).
fn execute_submission(
    language: &str,
    code: &str,
    stdin: &str,
    box_id: u32,
) -> Result<(String, String, String, Option<i32>, f64, i64), String> {
    use rustbox::config::types::IsolateConfig;
    use rustbox::runtime::isolate::{ExecutionOverrides, Isolate};

    // Initialize subsystems (lock manager, security logger) — idempotent
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = rustbox::observability::audit::init_security_logger(None);
        if let Err(e) = rustbox::safety::lock_manager::init_lock_manager() {
            eprintln!("lock manager init failed: {e}");
        }
    });

    let config = IsolateConfig::with_language_defaults(language, format!("rustbox/{box_id}"))
        .map_err(|e| format!("config error: {e}"))?;

    let mut isolate =
        Isolate::new(config).map_err(|e| format!("isolate creation error: {e}"))?;

    let overrides = ExecutionOverrides {
        stdin_data: if stdin.is_empty() { None } else { Some(stdin.to_string()) },
        ..ExecutionOverrides::default()
    };
    let result = isolate
        .execute_code_string(language, code, &overrides)
        .map_err(|e| format!("execution error: {e}"))?;

    let verdict = match result.status {
        rustbox::config::types::ExecutionStatus::Ok => "AC",
        rustbox::config::types::ExecutionStatus::RuntimeError => "RE",
        rustbox::config::types::ExecutionStatus::TimeLimit => "TLE",
        rustbox::config::types::ExecutionStatus::MemoryLimit => "MLE",
        rustbox::config::types::ExecutionStatus::Signaled => "SIG",
        rustbox::config::types::ExecutionStatus::InternalError => "IE",
        _ => "RE",
    }
    .to_string();
    let time_ms = result.wall_time * 1000.0;
    let memory_kb = (result.memory_peak / 1024) as i64;

    // Extract result data before cleanup consumes the isolate
    let output = (
        verdict,
        result.stdout,
        result.stderr,
        result.exit_code,
        time_ms,
        memory_kb,
    );

    // Explicit cleanup to avoid cgroup/dir accumulation
    let _ = isolate.cleanup();

    Ok(output)
}
