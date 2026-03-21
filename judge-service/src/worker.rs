use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::database::types::ExecutionOutput;
use crate::database::Database;
use crate::job_queue::JobQueue;

// ---------------------------------------------------------------------------
// Channel workers (single-node / SQLite mode)
// ---------------------------------------------------------------------------

/// Spawn `count` workers that dequeue from the async-channel and process jobs.
pub fn spawn_channel_workers(
    count: usize,
    db: Arc<dyn Database>,
    queue: Arc<JobQueue>,
    node_id: String,
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
                            // Channel closed - shut down gracefully
                            info!(worker = idx, "channel closed, worker exiting");
                            return;
                        }
                    };
                    info!(worker = idx, %job_id, "processing submission");
                    process_job(db.as_ref(), job_id, &node_id).await;
                }
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Postgres workers (cluster mode via LISTEN/NOTIFY)
// ---------------------------------------------------------------------------

/// Spawn a single listener task that wakes on NOTIFY and fans out to a
/// semaphore-bounded pool of `count` concurrent executors.
pub fn spawn_pg_workers(
    count: usize,
    db: Arc<dyn Database>,
    pg_db: Arc<crate::database::postgres::PgDatabase>,
    node_id: String,
) -> Vec<tokio::task::JoinHandle<()>> {
    let semaphore = Arc::new(Semaphore::new(count));

    // Drain any pending rows that accumulated before we started listening
    let drain_handle = {
        let db = db.clone();
        let node_id = node_id.clone();
        let sem = semaphore.clone();
        tokio::spawn(async move {
            drain_pending(db, sem, node_id).await;
        })
    };

    // Main listener loop
    let listener_handle = {
        let db = db.clone();
        let node_id = node_id.clone();
        let sem = semaphore.clone();
        tokio::spawn(async move {
            // Wait for drain to finish before starting the listener so we
            // do not double-process rows.
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
                        // A new submission was inserted. Try to claim it.
                        let permit = sem.clone().acquire_owned().await;
                        match permit {
                            Ok(permit) => {
                                let db = db.clone();
                                let node_id = node_id.clone();
                                tokio::spawn(async move {
                                    if let Ok(Some(sub)) = db.claim_pending(&node_id).await {
                                        process_job(db.as_ref(), sub.id, &node_id).await;
                                    }
                                    drop(permit);
                                });
                            }
                            Err(_) => {
                                // Semaphore closed, exit
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

/// Drain all pending submissions that were inserted before the listener started.
async fn drain_pending(db: Arc<dyn Database>, sem: Arc<Semaphore>, node_id: String) {
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
                    process_job(db.as_ref(), sub.id, &node_id).await;
                    drop(permit);
                });
            }
            Ok(None) => {
                // No more pending rows
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

// ---------------------------------------------------------------------------
// Shared job processor
// ---------------------------------------------------------------------------

async fn process_job(db: &dyn Database, job_id: Uuid, node_id: &str) {
    // Core sandbox expects numeric box_id (for UID derivation: 60000 + box_id).
    // Random u32 avoids collision across nodes without changing the core.
    let sandbox_id = fastrand::u32(10000..u32::MAX).to_string();

    // Mark running with our sandbox_id
    if let Err(e) = db.mark_running(job_id, node_id, &sandbox_id).await {
        error!(%job_id, error = %e, "failed to mark running");
    }

    // Fetch submission to get language/code/stdin
    let submission = match db.get_submission(job_id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            warn!(%job_id, "submission not found in database");
            return;
        }
        Err(e) => {
            error!(%job_id, error = %e, "database read error");
            return;
        }
    };

    let language = submission.language.clone();
    let code = submission.code.clone();
    let stdin = submission.stdin.clone();
    let sb_id = sandbox_id.clone();

    let result =
        tokio::task::spawn_blocking(move || execute_in_sandbox(&language, &code, &stdin, &sb_id))
            .await;

    match result {
        Ok(Ok(output)) => {
            if let Err(e) = db.mark_completed(job_id, &output).await {
                error!(%job_id, error = %e, "failed to mark completed");
            } else {
                info!(%job_id, verdict = output.verdict, "submission completed");
            }
        }
        Ok(Err(e)) => {
            error!(%job_id, error = %e, "execution failed");
            let _ = db.mark_error(job_id, &e).await;
        }
        Err(e) => {
            error!(%job_id, error = %e, "worker task panicked");
            let _ = db.mark_error(job_id, &format!("internal error: {e}")).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Sandbox execution
// ---------------------------------------------------------------------------

fn execute_in_sandbox(
    language: &str,
    code: &str,
    stdin: &str,
    sandbox_id: &str,
) -> Result<ExecutionOutput, String> {
    use rustbox::config::types::IsolateConfig;
    use rustbox::runtime::isolate::{ExecutionOverrides, Isolate};

    // One-time subsystem init (idempotent)
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = rustbox::observability::audit::init_security_logger(None);
        if let Err(e) = rustbox::safety::lock_manager::init_lock_manager() {
            eprintln!("lock manager init failed: {e}");
        }
    });

    let instance_id = format!("rustbox/{sandbox_id}");
    let config = IsolateConfig::with_language_defaults(language, instance_id)
        .map_err(|e| format!("config error: {e}"))?;

    let mut isolate =
        Isolate::new(config).map_err(|e| format!("isolate creation error: {e}"))?;

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
        rustbox::config::types::ExecutionStatus::Ok => "AC",
        rustbox::config::types::ExecutionStatus::RuntimeError => "RE",
        rustbox::config::types::ExecutionStatus::TimeLimit => "TLE",
        rustbox::config::types::ExecutionStatus::MemoryLimit => "MLE",
        rustbox::config::types::ExecutionStatus::Signaled => "SIG",
        rustbox::config::types::ExecutionStatus::InternalError => "IE",
        _ => "RE",
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

    // Explicit cleanup to avoid cgroup/dir accumulation
    let _ = isolate.cleanup();

    Ok(output)
}

// ---------------------------------------------------------------------------
// Stale submission reaper
// ---------------------------------------------------------------------------

/// Background loop that periodically reaps stale running submissions.
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
