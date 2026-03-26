use thiserror::Error;

#[derive(Error, Debug)]
pub enum IsolateError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Cgroup error: {0}")]
    Cgroup(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Process error: {0}")]
    Process(String),

    #[error("Lock error: {0}")]
    Lock(String),

    #[error("Namespace isolation error: {0}")]
    Namespace(String),

    #[error("Resource limit error: {0}")]
    ResourceLimit(String),

    #[error("Filesystem error: {0}")]
    Filesystem(String),

    #[error("Privilege error: {0}")]
    Privilege(String),
}

impl IsolateError {
    pub fn process(prefix: &str, err: impl std::fmt::Display) -> Self {
        Self::Process(format!("{prefix}: {err}"))
    }
}

pub type Result<T> = std::result::Result<T, IsolateError>;

impl From<nix::errno::Errno> for IsolateError {
    fn from(err: nix::errno::Errno) -> Self {
        IsolateError::Process(err.to_string())
    }
}
