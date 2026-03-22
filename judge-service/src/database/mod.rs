pub mod types;
pub mod sqlite;
pub mod postgres;

use async_trait::async_trait;
use std::time::Duration;
use uuid::Uuid;
use types::{ExecutionOutput, Submission};

#[async_trait]
pub trait Database: Send + Sync {
    async fn insert_submission(&self, sub: &Submission) -> anyhow::Result<()>;
    async fn claim_pending(&self, node_id: &str) -> anyhow::Result<Option<Submission>>;
    async fn mark_running(&self, id: Uuid, node_id: &str, sandbox_id: &str) -> anyhow::Result<()>;
    async fn mark_completed(&self, id: Uuid, result: &ExecutionOutput) -> anyhow::Result<()>;
    async fn mark_error(&self, id: Uuid, error: &str) -> anyhow::Result<()>;
    async fn get_submission(&self, id: Uuid) -> anyhow::Result<Option<Submission>>;
    async fn reap_stale(&self, timeout: Duration) -> anyhow::Result<u64>;
}

pub async fn connect(database_url: &str) -> anyhow::Result<Box<dyn Database>> {
    if database_url.starts_with("sqlite:") {
        let path = database_url.strip_prefix("sqlite:").unwrap();
        let db = sqlite::SqliteDatabase::open(path)?;
        db.run_migrations()?;
        Ok(Box::new(db))
    } else if database_url.starts_with("postgres://") || database_url.starts_with("postgresql://") {
        let db = postgres::PgDatabase::connect(database_url).await?;
        db.run_migrations().await?;
        Ok(Box::new(db))
    } else {
        anyhow::bail!("Unsupported DATABASE_URL scheme. Use sqlite: or postgres://")
    }
}
