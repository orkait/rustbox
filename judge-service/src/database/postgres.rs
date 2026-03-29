use async_trait::async_trait;
use chrono::Utc;
use sqlx::postgres::PgPoolOptions;
use std::time::Duration;
use uuid::Uuid;

use super::types::{ExecutionOutput, Submission};
use super::Database;

pub struct PgDatabase {
    pool: sqlx::PgPool,
}

#[derive(sqlx::FromRow)]
struct PgSubmissionRow {
    id: Uuid,
    user_id: Option<String>,
    ip_address: Option<String>,
    language: String,
    code: String,
    stdin: String,
    webhook_url: Option<String>,
    webhook_secret: Option<String>,
    status: String,
    node_id: Option<String>,
    sandbox_id: Option<String>,
    verdict: Option<String>,
    exit_code: Option<i32>,
    stdout: Option<String>,
    stderr: Option<String>,
    signal: Option<i32>,
    error_message: Option<String>,
    cpu_time: Option<f64>,
    wall_time: Option<f64>,
    memory_peak: Option<i64>,
    wall_time_limit_secs: Option<i64>,
    created_at: chrono::DateTime<Utc>,
    started_at: Option<chrono::DateTime<Utc>>,
    completed_at: Option<chrono::DateTime<Utc>>,
}

impl From<PgSubmissionRow> for Submission {
    fn from(r: PgSubmissionRow) -> Self {
        Submission {
            id: r.id,
            user_id: r.user_id,
            ip_address: r.ip_address,
            language: r.language,
            code: r.code,
            stdin: r.stdin,
            webhook_url: r.webhook_url,
            webhook_secret: r.webhook_secret,
            status: r.status,
            node_id: r.node_id,
            sandbox_id: r.sandbox_id,
            verdict: r.verdict,
            exit_code: r.exit_code,
            stdout: r.stdout,
            stderr: r.stderr,
            signal: r.signal,
            error_message: r.error_message,
            cpu_time: r.cpu_time,
            wall_time: r.wall_time,
            memory_peak: r.memory_peak,
            wall_time_limit_secs: r.wall_time_limit_secs,
            created_at: r.created_at,
            started_at: r.started_at,
            completed_at: r.completed_at,
        }
    }
}

impl PgDatabase {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(20)
            .connect(database_url)
            .await?;
        Ok(Self { pool })
    }

    pub async fn run_migrations(&self) -> anyhow::Result<()> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query("SELECT pg_advisory_lock(42)")
            .execute(&mut *conn)
            .await?;

        let result = self.run_migrations_inner(&mut conn).await;

        let _ = sqlx::query("SELECT pg_advisory_unlock(42)")
            .execute(&mut *conn)
            .await;

        result
    }

    async fn run_migrations_inner(&self, conn: &mut sqlx::PgConnection) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS submissions (
                id            UUID          PRIMARY KEY,
                user_id       TEXT,
                ip_address    TEXT,
                language      TEXT          NOT NULL,
                code          TEXT          NOT NULL,
                stdin         TEXT          NOT NULL DEFAULT '',
                webhook_url   TEXT,
                webhook_secret TEXT,
                status        TEXT          NOT NULL DEFAULT 'pending',
                node_id       TEXT,
                sandbox_id    TEXT,
                verdict       TEXT,
                exit_code     INTEGER,
                stdout        TEXT,
                stderr        TEXT,
                signal        INTEGER,
                error_message TEXT,
                cpu_time      DOUBLE PRECISION,
                wall_time     DOUBLE PRECISION,
                memory_peak   BIGINT,
                wall_time_limit_secs BIGINT,
                created_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
                started_at    TIMESTAMPTZ,
                completed_at  TIMESTAMPTZ
            )
            "#,
        )
        .execute(&mut *conn)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_submissions_status_created \
             ON submissions (status, created_at)",
        )
        .execute(&mut *conn)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_submissions_node_id \
             ON submissions (node_id) WHERE node_id IS NOT NULL",
        )
        .execute(&mut *conn)
        .await?;

        sqlx::query(
            r#"
            CREATE OR REPLACE FUNCTION notify_new_submission() RETURNS TRIGGER AS $$
            BEGIN
                PERFORM pg_notify('new_submission', NEW.id::text);
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
            "#,
        )
        .execute(&mut *conn)
        .await?;

        sqlx::query(
            r#"
            DO $$ BEGIN
                CREATE TRIGGER submission_inserted
                    AFTER INSERT ON submissions
                    FOR EACH ROW EXECUTE FUNCTION notify_new_submission();
            EXCEPTION WHEN duplicate_object THEN NULL;
            END $$
            "#,
        )
        .execute(&mut *conn)
        .await?;

        Ok(())
    }

    pub async fn listener(&self) -> anyhow::Result<sqlx::postgres::PgListener> {
        let mut listener = sqlx::postgres::PgListener::connect_with(&self.pool).await?;
        listener.listen("new_submission").await?;
        Ok(listener)
    }
}

#[async_trait]
impl Database for PgDatabase {
    async fn insert_submission(&self, sub: &Submission) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            INSERT INTO submissions
                (id, user_id, ip_address, language, code, stdin, webhook_url, webhook_secret,
                 status, node_id, sandbox_id, verdict, exit_code, stdout, stderr, signal,
                 error_message, cpu_time, wall_time, memory_peak,
                 wall_time_limit_secs, created_at, started_at, completed_at)
            VALUES
                ($1, $2, $3, $4, $5, $6, $7, $8,
                 $9, $10, $11, $12, $13, $14, $15, $16,
                 $17, $18, $19, $20,
                 $21, $22, $23, $24)
            ON CONFLICT (id) DO NOTHING
            "#,
        )
        .bind(sub.id)
        .bind(&sub.user_id)
        .bind(&sub.ip_address)
        .bind(&sub.language)
        .bind(&sub.code)
        .bind(&sub.stdin)
        .bind(&sub.webhook_url)
        .bind(&sub.webhook_secret)
        .bind(&sub.status)
        .bind(&sub.node_id)
        .bind(&sub.sandbox_id)
        .bind(&sub.verdict)
        .bind(sub.exit_code)
        .bind(&sub.stdout)
        .bind(&sub.stderr)
        .bind(sub.signal)
        .bind(&sub.error_message)
        .bind(sub.cpu_time)
        .bind(sub.wall_time)
        .bind(sub.memory_peak)
        .bind(sub.wall_time_limit_secs)
        .bind(sub.created_at)
        .bind(sub.started_at)
        .bind(sub.completed_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn claim_pending(&self, node_id: &str) -> anyhow::Result<Option<Submission>> {
        let row: Option<PgSubmissionRow> = sqlx::query_as(
            r#"
            UPDATE submissions
               SET status     = 'running',
                   node_id    = $1,
                   started_at = NOW()
             WHERE id = (
                     SELECT id
                       FROM submissions
                      WHERE status = 'pending'
                      ORDER BY created_at
                      LIMIT 1
                      FOR UPDATE SKIP LOCKED
                   )
            RETURNING *
            "#,
        )
        .bind(node_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(Submission::from))
    }

    async fn mark_running(&self, id: Uuid, node_id: &str, sandbox_id: &str) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            UPDATE submissions
               SET status     = 'running',
                   node_id    = $2,
                   sandbox_id = $3,
                   started_at = COALESCE(started_at, NOW())
             WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(node_id)
        .bind(sandbox_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn mark_completed(&self, id: Uuid, result: &ExecutionOutput) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            UPDATE submissions
               SET status       = 'completed',
                   verdict      = $2,
                   exit_code    = $3,
                   stdout       = $4,
                   stderr       = $5,
                   signal       = $6,
                   error_message = $7,
                   cpu_time     = $8,
                   wall_time    = $9,
                   memory_peak  = $10,
                   completed_at = NOW()
             WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(&result.verdict)
        .bind(result.exit_code)
        .bind(&result.stdout)
        .bind(&result.stderr)
        .bind(result.signal)
        .bind(&result.error_message)
        .bind(result.cpu_time)
        .bind(result.wall_time)
        .bind(result.memory_peak)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn mark_error(&self, id: Uuid, error: &str) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            UPDATE submissions
               SET status        = 'error',
                   error_message = $2,
                   completed_at  = NOW()
             WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(error)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_submission(&self, id: Uuid) -> anyhow::Result<Option<Submission>> {
        let row: Option<PgSubmissionRow> =
            sqlx::query_as("SELECT * FROM submissions WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;

        Ok(row.map(Submission::from))
    }

    async fn reap_stale(&self, _timeout: Duration) -> anyhow::Result<u64> {
        let fallback = crate::constants::DEFAULT_REAPER_FALLBACK_SECS as f64;
        let result = sqlx::query(
            r#"
            UPDATE submissions
               SET status        = 'error',
                   verdict       = 'IE',
                   error_message = 'reaped: execution timed out',
                   completed_at  = NOW()
             WHERE status = 'running'
               AND started_at IS NOT NULL
               AND (
                   (wall_time_limit_secs IS NOT NULL
                    AND started_at < NOW() - ((wall_time_limit_secs + 10) || ' seconds')::INTERVAL)
                   OR
                   (wall_time_limit_secs IS NULL
                    AND started_at < NOW() - ($1 || ' seconds')::INTERVAL)
               )
            "#,
        )
        .bind(fallback)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }
}
