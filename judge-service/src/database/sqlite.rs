use std::sync::Mutex;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, Row};
use uuid::Uuid;

use super::types::{ExecutionOutput, Submission};
use super::Database;

pub struct SqliteDatabase {
    conn: Mutex<Connection>,
}

impl SqliteDatabase {
    pub fn open(path: &str) -> anyhow::Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("Failed to open SQLite database at {}", path))?;

        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        conn.busy_timeout(crate::constants::DB_BUSY_TIMEOUT)?;
        conn.execute_batch("PRAGMA synchronous=NORMAL;")?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn run_migrations(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());

        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS submissions (
                id              TEXT PRIMARY KEY,
                user_id         TEXT,
                ip_address      TEXT,
                language        TEXT NOT NULL,
                code            TEXT NOT NULL,
                stdin           TEXT NOT NULL DEFAULT '',
                webhook_url     TEXT,
                webhook_secret  TEXT,
                status          TEXT NOT NULL DEFAULT 'pending',
                node_id         TEXT,
                sandbox_id      TEXT,
                verdict         TEXT,
                exit_code       INTEGER,
                stdout          TEXT,
                stderr          TEXT,
                signal          INTEGER,
                error_message   TEXT,
                cpu_time        REAL,
                wall_time       REAL,
                memory_peak     INTEGER,
                created_at      TEXT NOT NULL,
                started_at      TEXT,
                completed_at    TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_submissions_status_created
                ON submissions (status, created_at);
            "#,
        )?;

        Ok(())
    }
}

fn row_to_submission(row: &Row) -> rusqlite::Result<Submission> {
    let id_str: String = row.get(0)?;
    let id = Uuid::parse_str(&id_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;

    let created_at_str: String = row.get(20)?;
    let created_at = DateTime::parse_from_rfc3339(&created_at_str)
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(20, rusqlite::types::Type::Text, Box::new(e))
        })?
        .with_timezone(&Utc);

    let started_at = parse_optional_datetime(row, 21)?;
    let completed_at = parse_optional_datetime(row, 22)?;

    Ok(Submission {
        id,
        user_id: row.get(1)?,
        ip_address: row.get(2)?,
        language: row.get(3)?,
        code: row.get(4)?,
        stdin: row.get(5)?,
        webhook_url: row.get(6)?,
        webhook_secret: row.get(7)?,
        status: row.get(8)?,
        node_id: row.get(9)?,
        sandbox_id: row.get(10)?,
        verdict: row.get(11)?,
        exit_code: row.get(12)?,
        stdout: row.get(13)?,
        stderr: row.get(14)?,
        signal: row.get(15)?,
        error_message: row.get(16)?,
        cpu_time: row.get(17)?,
        wall_time: row.get(18)?,
        memory_peak: row.get(19)?,
        created_at,
        started_at,
        completed_at,
    })
}

fn parse_optional_datetime(row: &Row, idx: usize) -> rusqlite::Result<Option<DateTime<Utc>>> {
    let s: Option<String> = row.get(idx)?;
    match s {
        None => Ok(None),
        Some(s) => {
            let dt = DateTime::parse_from_rfc3339(&s)
                .map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        idx,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?
                .with_timezone(&Utc);
            Ok(Some(dt))
        }
    }
}

#[async_trait]
impl Database for SqliteDatabase {
    async fn insert_submission(&self, sub: &Submission) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            r#"
            INSERT OR IGNORE INTO submissions (
                id, user_id, ip_address, language, code, stdin, webhook_url, webhook_secret,
                status, node_id, sandbox_id, verdict, exit_code, stdout, stderr,
                signal, error_message, cpu_time, wall_time, memory_peak,
                created_at, started_at, completed_at
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8,
                ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                ?16, ?17, ?18, ?19, ?20,
                ?21, ?22, ?23
            )
            "#,
            params![
                sub.id.to_string(),
                sub.user_id,
                sub.ip_address,
                sub.language,
                sub.code,
                sub.stdin,
                sub.webhook_url,
                sub.webhook_secret,
                sub.status,
                sub.node_id,
                sub.sandbox_id,
                sub.verdict,
                sub.exit_code,
                sub.stdout,
                sub.stderr,
                sub.signal,
                sub.error_message,
                sub.cpu_time,
                sub.wall_time,
                sub.memory_peak,
                sub.created_at.to_rfc3339(),
                sub.started_at.map(|t| t.to_rfc3339()),
                sub.completed_at.map(|t| t.to_rfc3339()),
            ],
        )?;
        Ok(())
    }

    async fn claim_pending(&self, node_id: &str) -> anyhow::Result<Option<Submission>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());

        let result = conn.query_row(
            r#"
            UPDATE submissions
            SET status = 'running',
                node_id = ?1,
                started_at = ?2
            WHERE id = (
                SELECT id FROM submissions
                WHERE status = 'pending'
                ORDER BY created_at ASC
                LIMIT 1
            )
            RETURNING
                id, user_id, ip_address, language, code, stdin, webhook_url, webhook_secret,
                status, node_id, sandbox_id, verdict, exit_code, stdout, stderr,
                signal, error_message, cpu_time, wall_time, memory_peak,
                created_at, started_at, completed_at
            "#,
            params![node_id, Utc::now().to_rfc3339()],
            row_to_submission,
        );

        match result {
            Ok(sub) => Ok(Some(sub)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e).context("claim_pending query failed"),
        }
    }

    async fn mark_running(&self, id: Uuid, node_id: &str, sandbox_id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            r#"
            UPDATE submissions
            SET status = 'running',
                node_id = ?2,
                sandbox_id = ?3,
                started_at = ?4
            WHERE id = ?1
            "#,
            params![id.to_string(), node_id, sandbox_id, Utc::now().to_rfc3339(),],
        )?;
        Ok(())
    }

    async fn mark_completed(&self, id: Uuid, result: &ExecutionOutput) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            r#"
            UPDATE submissions
            SET status = 'completed',
                verdict = ?2,
                exit_code = ?3,
                stdout = ?4,
                stderr = ?5,
                signal = ?6,
                error_message = ?7,
                cpu_time = ?8,
                wall_time = ?9,
                memory_peak = ?10,
                completed_at = ?11
            WHERE id = ?1
            "#,
            params![
                id.to_string(),
                result.verdict,
                result.exit_code,
                result.stdout,
                result.stderr,
                result.signal,
                result.error_message,
                result.cpu_time,
                result.wall_time,
                result.memory_peak,
                Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    async fn mark_error(&self, id: Uuid, error: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            r#"
            UPDATE submissions
            SET status = 'error',
                error_message = ?2,
                completed_at = ?3
            WHERE id = ?1
            "#,
            params![id.to_string(), error, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    async fn get_submission(&self, id: Uuid) -> anyhow::Result<Option<Submission>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let result = conn.query_row(
            r#"
            SELECT
                id, user_id, ip_address, language, code, stdin, webhook_url, webhook_secret,
                status, node_id, sandbox_id, verdict, exit_code, stdout, stderr,
                signal, error_message, cpu_time, wall_time, memory_peak,
                created_at, started_at, completed_at
            FROM submissions
            WHERE id = ?1
            "#,
            params![id.to_string()],
            row_to_submission,
        );

        match result {
            Ok(sub) => Ok(Some(sub)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e).context("get_submission query failed"),
        }
    }

    async fn reap_stale(&self, timeout: Duration) -> anyhow::Result<u64> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let cutoff = Utc::now() - chrono::Duration::from_std(timeout)?;
        let rows_updated = conn.execute(
            r#"
            UPDATE submissions
            SET status = 'error',
                error_message = 'reaped: execution timed out',
                completed_at = ?1
            WHERE status = 'running'
              AND started_at < ?2
            "#,
            params![Utc::now().to_rfc3339(), cutoff.to_rfc3339()],
        )?;
        Ok(rows_updated as u64)
    }
}
