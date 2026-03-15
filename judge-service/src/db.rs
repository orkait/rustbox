use sqlx::PgPool;
use uuid::Uuid;

use crate::types::SubmissionRow;

/// Run migrations (create table if not exists).
pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS submissions (
            id            UUID PRIMARY KEY,
            language      VARCHAR(10) NOT NULL,
            code          TEXT NOT NULL,
            stdin         TEXT NOT NULL DEFAULT '',
            status        VARCHAR(20) NOT NULL DEFAULT 'pending',
            verdict       VARCHAR(20),
            stdout        TEXT,
            stderr        TEXT,
            exit_code     INTEGER,
            time_ms       DOUBLE PRECISION,
            memory_kb     BIGINT,
            created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            completed_at  TIMESTAMPTZ
        )
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Insert a new submission with status=pending.
pub async fn create_submission(
    pool: &PgPool,
    id: Uuid,
    language: &str,
    code: &str,
    stdin: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO submissions (id, language, code, stdin, status) VALUES ($1, $2, $3, $4, 'pending')",
    )
    .bind(id)
    .bind(language)
    .bind(code)
    .bind(stdin)
    .execute(pool)
    .await?;
    Ok(())
}

/// Get a submission by ID.
pub async fn get_submission(pool: &PgPool, id: Uuid) -> Result<Option<SubmissionRow>, sqlx::Error> {
    sqlx::query_as::<_, SubmissionRow>("SELECT * FROM submissions WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

/// Mark submission as running.
pub async fn mark_running(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE submissions SET status = 'running' WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Update submission with execution result.
pub async fn update_result(
    pool: &PgPool,
    id: Uuid,
    verdict: &str,
    stdout: &str,
    stderr: &str,
    exit_code: Option<i32>,
    time_ms: f64,
    memory_kb: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE submissions
        SET status = 'completed',
            verdict = $2,
            stdout = $3,
            stderr = $4,
            exit_code = $5,
            time_ms = $6,
            memory_kb = $7,
            completed_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(verdict)
    .bind(stdout)
    .bind(stderr)
    .bind(exit_code)
    .bind(time_ms)
    .bind(memory_kb)
    .execute(pool)
    .await?;
    Ok(())
}

/// Mark submission as errored.
pub async fn mark_error(pool: &PgPool, id: Uuid, error_msg: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE submissions
        SET status = 'error',
            stderr = $2,
            completed_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(error_msg)
    .execute(pool)
    .await?;
    Ok(())
}
