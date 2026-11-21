use std::io;
use thiserror::Error;

/// `tracedesk-engines` 的统一错误类型。
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
    /// 当此错误表示协作式取消时返回 `true`。
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled(_))
    }
}

pub type EngineResult<T> = Result<T, EngineError>;
