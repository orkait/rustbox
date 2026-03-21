use uuid::Uuid;

/// Dual-mode job queue.
/// - Channel mode (single-node): async-channel bounded queue with backpressure
/// - Postgres mode (cluster): no-op queue, workers poll DB via LISTEN/NOTIFY
pub enum JobQueue {
    Channel {
        sender: async_channel::Sender<Uuid>,
        receiver: async_channel::Receiver<Uuid>,
    },
    Postgres,
}

impl JobQueue {
    pub fn channel(capacity: usize) -> Self {
        let (sender, receiver) = async_channel::bounded(capacity);
        JobQueue::Channel { sender, receiver }
    }

    pub fn postgres() -> Self {
        JobQueue::Postgres
    }

    /// Enqueue a job ID. In Postgres mode this is a no-op
    /// (the DB INSERT trigger fires NOTIFY automatically).
    pub async fn enqueue(&self, id: Uuid) -> anyhow::Result<()> {
        match self {
            JobQueue::Channel { sender, .. } => {
                sender.try_send(id).map_err(|_| anyhow::anyhow!("queue full"))?;
                Ok(())
            }
            JobQueue::Postgres => Ok(()),
        }
    }

    /// Dequeue a job ID. In Postgres mode returns None
    /// (workers use Database::claim_pending instead).
    pub async fn dequeue(&self) -> Option<Uuid> {
        match self {
            JobQueue::Channel { receiver, .. } => receiver.recv().await.ok(),
            JobQueue::Postgres => None,
        }
    }

    /// Approximate queue depth.
    pub fn depth(&self) -> usize {
        match self {
            JobQueue::Channel { sender, .. } => sender.len(),
            JobQueue::Postgres => 0,
        }
    }

    /// Check if queue is full (for 503 backpressure response).
    pub fn is_full(&self) -> bool {
        match self {
            JobQueue::Channel { sender, .. } => sender.is_full(),
            JobQueue::Postgres => false, // Postgres mode relies on DB, not queue depth
        }
    }
}
