use redis::AsyncCommands;
use uuid::Uuid;

const QUEUE_KEY: &str = "rustbox:jobs";

/// Push a job ID onto the Redis queue.
pub async fn enqueue(con: &mut redis::aio::MultiplexedConnection, id: Uuid) -> redis::RedisResult<()> {
    con.rpush(QUEUE_KEY, id.to_string()).await
}

/// Pop a job ID from the Redis queue (blocking, timeout in seconds).
pub async fn dequeue(con: &mut redis::aio::MultiplexedConnection, timeout_secs: f64) -> redis::RedisResult<Option<Uuid>> {
    let result: Option<(String, String)> = redis::cmd("BLPOP")
        .arg(QUEUE_KEY)
        .arg(timeout_secs)
        .query_async(con)
        .await?;

    match result {
        Some((_key, id_str)) => {
            let id = Uuid::parse_str(&id_str)
                .map_err(|e| redis::RedisError::from((redis::ErrorKind::TypeError, "invalid uuid", e.to_string())))?;
            Ok(Some(id))
        }
        None => Ok(None),
    }
}

/// Get the current queue depth.
pub async fn queue_depth(con: &mut redis::aio::MultiplexedConnection) -> redis::RedisResult<usize> {
    con.llen(QUEUE_KEY).await
}
