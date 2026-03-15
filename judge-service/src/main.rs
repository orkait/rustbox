mod api;
mod config;
mod db;
mod queue;
mod types;
mod worker;

use axum::extract::DefaultBodyLimit;
use axum::http::{header, HeaderValue, Method};
use sqlx::postgres::PgPoolOptions;
use tower_http::cors::CorsLayer;
use tracing::info;

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub redis: redis::Client,
    pub worker_count: usize,
    pub max_queue_size: usize,
    pub api_key: Option<String>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let cfg = config::ServiceConfig::from_env();
    info!(
        port = cfg.port,
        workers = cfg.workers,
        "starting judge-service"
    );

    // Connect to Postgres
    let pool = PgPoolOptions::new()
        .max_connections(cfg.workers as u32 + 5)
        .connect(&cfg.database_url)
        .await
        .expect("failed to connect to postgres");

    // Run migrations
    db::run_migrations(&pool)
        .await
        .expect("failed to run migrations");
    info!("database ready");

    // Connect to Redis
    let redis_client =
        redis::Client::open(cfg.redis_url.as_str()).expect("failed to create redis client");

    // Verify Redis connection
    let _con = redis_client
        .get_multiplexed_async_connection()
        .await
        .expect("failed to connect to redis");
    info!("redis ready");

    // Spawn worker pool
    let _workers = worker::spawn_workers(cfg.workers, pool.clone(), redis_client.clone());
    info!(count = cfg.workers, "worker pool started");

    // Build HTTP server
    let api_key = std::env::var("RUSTBOX_API_KEY").ok();
    if api_key.is_some() {
        info!("API key authentication enabled");
    }

    let state = AppState {
        db: pool,
        redis: redis_client,
        worker_count: cfg.workers,
        max_queue_size: cfg.queue_size,
        api_key,
    };

    let cors_origin = std::env::var("RUSTBOX_CORS_ORIGIN")
        .unwrap_or_else(|_| "http://localhost:3000".to_string());

    let cors = CorsLayer::new()
        .allow_origin(cors_origin.parse::<HeaderValue>().expect("invalid CORS origin"))
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::CONTENT_TYPE]);

    let app = api::router()
        .layer(cors)
        .layer(DefaultBodyLimit::max(1024 * 1024)) // 1 MB max request body
        .with_state(state);

    let addr = format!("0.0.0.0:{}", cfg.port);
    info!(%addr, "listening");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind");

    axum::serve(listener, app).await.expect("server error");
}
