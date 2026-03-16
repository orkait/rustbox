use sqlx::PgPool;
use uuid::Uuid;

use crate::types::SubmissionRow;

/// Run migrations (create table if not exists).
pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::Error> {
    // V1: base table
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

    // V2: detailed execution info
    for col in &[
        ("cpu_time_ms", "DOUBLE PRECISION"),
        ("wall_time_ms", "DOUBLE PRECISION"),
        ("signal", "INTEGER"),
        ("error_message", "TEXT"),
        ("meta", "TEXT"),
    ] {
        sqlx::query(&format!(
            "ALTER TABLE submissions ADD COLUMN IF NOT EXISTS {} {}",
            col.0, col.1
        ))
        .execute(pool)
        .await?;
    }
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
    cpu_time_ms: f64,
    wall_time_ms: f64,
    signal: Option<i32>,
    error_message: Option<&str>,
    meta: Option<&str>,
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
            cpu_time_ms = $8,
            wall_time_ms = $9,
            signal = $10,
            error_message = $11,
            meta = $12,
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
    .bind(cpu_time_ms)
    .bind(wall_time_ms)
    .bind(signal)
    .bind(error_message)
    .bind(meta)
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
