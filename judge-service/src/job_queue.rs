use uuid::Uuid;

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

    pub async fn enqueue(&self, id: Uuid) -> anyhow::Result<()> {
        match self {
            JobQueue::Channel { sender, .. } => {
                sender
                    .try_send(id)
                    .map_err(|_| anyhow::anyhow!("queue full"))?;
                Ok(())
            }
            JobQueue::Postgres => Ok(()),
        }
    }

    pub async fn dequeue(&self) -> Option<Uuid> {
        match self {
            JobQueue::Channel { receiver, .. } => receiver.recv().await.ok(),
            JobQueue::Postgres => None,
        }
    }

    pub fn depth(&self) -> usize {
        match self {
            JobQueue::Channel { sender, .. } => sender.len(),
            JobQueue::Postgres => 0,
        }
    }

    pub fn is_full(&self) -> bool {
        match self {
            JobQueue::Channel { sender, .. } => sender.is_full(),
            JobQueue::Postgres => false,
        }
    }
}
