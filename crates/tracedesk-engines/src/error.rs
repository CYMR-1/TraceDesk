use std::io;
use thiserror::Error;

/// Unified error type for `tracedesk-engines`.
#[derive(Debug, Error)]
pub enum EngineError {
    #[error("I/O 错误：{0}")]
    Io(#[from] io::Error),

    #[error("{0}")]
    Cancelled(String),

    #[error("{0}")]
    Timeout(String),

    #[error("{0}")]
    InvalidArgument(String),

    #[error("{0}")]
    TskNotFound(String),

    #[error("{0}")]
    TskCommandDenied(String),

    #[error("TSK 命令 {command} 执行失败：{message}")]
    TskFailed { command: String, message: String },

    #[error("{0}")]
    Encoding(String),

    #[error("{0}")]
    Locked(String),

    #[error("{0}")]
    SourceGuard(String),

    #[error("{0}")]
    SourceChanged(String),

    #[error("{0}")]
    Ewf(String),

    #[error("{0}")]
    Fat(String),

    #[error("{0}")]
    Ntfs(String),

    #[error("{0}")]
    RandomRead(String),
}

impl EngineError {
    /// Returns `true` when this error represents cooperative cancellation.
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled(_))
    }
}

pub type EngineResult<T> = Result<T, EngineError>;
