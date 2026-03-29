use std::sync::Arc;
use std::time::Duration;

#[allow(unused_imports)]
use tracing::warn;

use axum::extract::DefaultBodyLimit;
use axum::http::{header, HeaderValue, Method};
use tower_http::cors::CorsLayer;
use tracing::info;

use judge_service::database::Database;
use judge_service::job_queue::JobQueue;
use judge_service::AppState;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if let Some(role_arg) = args.iter().find(|a| a.starts_with("--internal-role=")) {
        let role = role_arg.split('=').nth(1).unwrap_or("");
        if role == "proxy" {
            let _ = rustbox::observability::audit::init_security_logger(None);
            return rustbox::sandbox::proxy::run_proxy_role()
                .map_err(|e| anyhow::anyhow!("proxy role failed: {e}"));
        }
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async_main())
}

async fn async_main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cfg = judge_service::config::ServiceConfig::from_env();
    info!(
        port = cfg.port,
        workers = cfg.workers,
        node_id = %cfg.node_id,
        database_url = %cfg.database_url,
        "starting judge-service"
    );

    let db: Arc<dyn Database> =
        Arc::from(judge_service::database::connect(&cfg.database_url).await?);
    info!("database ready");

    let is_postgres = cfg.database_url.starts_with("postgres://")
        || cfg.database_url.starts_with("postgresql://");

    let (queue, _worker_handles) = if is_postgres {
        let pg_db = Arc::new(
            judge_service::database::postgres::PgDatabase::connect(&cfg.database_url).await?,
        );
        let queue = Arc::new(JobQueue::postgres());
        let handles = judge_service::worker::spawn_pg_workers(
            cfg.workers,
            db.clone(),
            pg_db,
            cfg.node_id.clone(),
            cfg.webhook_timeout_secs,
        );
        info!(
            count = cfg.workers,
            mode = "postgres",
            "worker pool started"
        );
        (queue, handles)
    } else {
        let queue = Arc::new(JobQueue::channel(cfg.queue_size));
        let handles = judge_service::worker::spawn_channel_workers(
            cfg.workers,
            db.clone(),
            queue.clone(),
            cfg.node_id.clone(),
            cfg.webhook_timeout_secs,
        );
        info!(count = cfg.workers, mode = "channel", "worker pool started");
        (queue, handles)
    };

    let _reaper = judge_service::worker::spawn_reaper(
        db.clone(),
        Duration::from_secs(cfg.reaper_interval_secs),
        Duration::from_secs(cfg.stale_timeout_secs),
    );

    let db_for_shutdown = db.clone();

    let available_languages = detect_installed_languages();
    info!(languages = ?available_languages, "detected language runtimes");

    let cgroup_backend = if rustbox::kernel::cgroup::is_cgroup_v2_available() {
        Some("cgroup_v2".to_string())
    } else {
        None
    };
    let namespace_support = rustbox::kernel::namespace::NamespaceIsolation::is_supported();
    let is_root = unsafe { libc::geteuid() } == 0;
    let enforcement_mode = match (&cgroup_backend, namespace_support, is_root) {
        (Some(_), true, true) => "strict",
        (Some(_), _, _) | (_, true, _) => "degraded",
        _ => "none",
    }
    .to_string();
    info!(
        enforcement = %enforcement_mode,
        cgroup = ?cgroup_backend,
        namespaces = namespace_support,
        "enforcement probed"
    );

    let state = AppState {
        db,
        queue,
        worker_count: cfg.workers,
        api_key: cfg.api_key,
        node_id: cfg.node_id,
        allow_localhost_webhooks: cfg.allow_localhost_webhooks,
        max_code_bytes: cfg.max_code_bytes,
        max_stdin_bytes: cfg.max_stdin_bytes,
        sync_wait_timeout_secs: cfg.sync_wait_timeout_secs,
        webhook_timeout_secs: cfg.webhook_timeout_secs,
        cgroup_backend,
        namespace_support,
        enforcement_mode,
        available_languages,
        trust_proxy_headers: cfg.trust_proxy_headers,
        rate_limiter: if cfg.rate_limit_per_minute > 0 {
            info!(rpm = cfg.rate_limit_per_minute, "rate limiting enabled");
            Some(std::sync::Arc::new(
                judge_service::rate_limit::RateLimiter::new(cfg.rate_limit_per_minute),
            ))
        } else {
            None
        },
    };

    if let Some(ref limiter) = state.rate_limiter {
        let limiter = limiter.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(
                    judge_service::constants::RATE_LIMIT_BUCKET_RETENTION_SECS,
                ))
                .await;
                limiter.cleanup_stale();
            }
        });
    }

    if state.api_key.is_some() {
        info!("API key authentication enabled");
    } else {
        warn!("WARNING: No API key set. API is open to anyone who can reach this port.");
        warn!("Set RUSTBOX_API_KEY for production deployments.");
    }

    let cors_origin = std::env::var("RUSTBOX_CORS_ORIGIN")
        .unwrap_or_else(|_| "http://localhost:3000".to_string());

    let cors = CorsLayer::new()
        .allow_origin(
            cors_origin
                .parse::<HeaderValue>()
                .expect("invalid CORS origin"),
        )
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::CONTENT_TYPE]);

    let app = judge_service::api::router()
        .layer(cors)
        .layer(DefaultBodyLimit::max(
            judge_service::constants::HTTP_BODY_LIMIT,
        ))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", cfg.port);
    info!(%addr, "listening");

    let listener = tokio::net::TcpListener::bind(&addr).await?;

    let shutdown_signal = async {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .expect("failed to install SIGINT handler");
        tokio::select! {
            _ = sigterm.recv() => info!("SIGTERM received, shutting down..."),
            _ = sigint.recv() => info!("SIGINT received, shutting down..."),
        }
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await?;

    info!("server stopped, draining in-flight workers...");

    let drain_timeout = Duration::from_secs(cfg.drain_timeout_secs);
    match tokio::time::timeout(drain_timeout, async {
        for handle in _worker_handles {
            let _ = handle.await;
        }
    })
    .await
    {
        Ok(()) => info!("all workers drained cleanly"),
        Err(_) => {
            tracing::warn!(
                "worker drain timed out after {}s, marking stale submissions",
                drain_timeout.as_secs()
            );
            if let Err(e) = db_for_shutdown.reap_stale(Duration::ZERO).await {
                tracing::error!(error = %e, "failed to reap stale submissions on shutdown");
            }
        }
    }

    info!("shutdown complete");
    Ok(())
}

fn detect_installed_languages() -> Vec<String> {
    let checks: &[(&str, &[&str])] = &[
        ("python", &["/usr/bin/python3"]),
        ("c", &["/usr/bin/gcc"]),
        ("cpp", &["/usr/bin/g++"]),
        ("java", &["/usr/bin/java", "/usr/bin/javac"]),
        ("javascript", &["/usr/local/bin/bun"]),
        ("typescript", &["/usr/local/bin/bun"]),
        ("go", &["/usr/local/go/bin/go"]),
        ("rust", &["/usr/local/bin/rustc"]),
    ];
    checks
        .iter()
        .filter(|(_, binaries)| binaries.iter().all(|b| std::path::Path::new(b).exists()))
        .map(|(lang, _)| lang.to_string())
        .collect()
}
