use std::sync::Arc;
use std::time::Duration;

use axum::extract::DefaultBodyLimit;
use axum::http::{header, HeaderValue, Method};
use tower_http::cors::CorsLayer;
use tracing::info;

use judge_service::database::Database;
use judge_service::job_queue::JobQueue;
use judge_service::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cfg = judge_service::config::ServiceConfig::from_env();
    info!(
        port = cfg.port,
        workers = cfg.workers,
        node_id = %cfg.node_id,
        database_url = %cfg.database_url,
        "starting judge-service"
    );

    let db: Arc<dyn Database> = Arc::from(judge_service::database::connect(&cfg.database_url).await?);
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
        info!(count = cfg.workers, mode = "postgres", "worker pool started");
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
        sync_poll_interval_ms: cfg.sync_poll_interval_ms,
        webhook_timeout_secs: cfg.webhook_timeout_secs,
    };

    if state.api_key.is_some() {
        info!("API key authentication enabled");
    }

    let cors_origin = std::env::var("RUSTBOX_CORS_ORIGIN")
        .unwrap_or_else(|_| "http://localhost:3000".to_string());

    let cors = CorsLayer::new()
        .allow_origin(cors_origin.parse::<HeaderValue>().expect("invalid CORS origin"))
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::CONTENT_TYPE]);

    let app = judge_service::api::router()
        .layer(cors)
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", cfg.port);
    info!(%addr, "listening");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
