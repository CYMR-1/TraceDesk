use std::io;
use thiserror::Error;
use tracedesk_engines::EngineError;

/// Unified error type for `tracedesk-core`.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("I/O 错误：{0}")]
    Io(#[from] io::Error),

    #[error("{0}")]
    Engine(#[from] EngineError),

    #[error("JSON 解析或序列化失败：{0}")]
    Json(#[from] serde_json::Error),

    #[error("ZIP 归档处理失败：{0}")]
    Zip(#[from] zip::result::ZipError),

    #[error("{0}")]
    InvalidInput(String),

    #[error("{0}")]
    NotFound(String),

    #[error("{0}")]
    Locked(String),

    #[error("案件已关闭")]
    CaseClosed,

    #[error("案件数据损坏：{0}")]
    CorruptCase(String),

    #[error("{0}")]
    AuditTampered(String),

    #[error("{0}")]
    IntegrityFailed(String),

    #[error("{0}")]
    Cancelled(String),

    #[error("{0}")]
    MissingMaterials(String),

    #[error("{0}")]
    Preview(String),

    #[error("{0}")]
    Other(String),
}

impl CoreError {
    /// Returns `true` when this error represents cooperative cancellation.
    pub fn is_cancelled(&self) -> bool {
        match self {
            Self::Cancelled(_) => true,
            Self::Engine(e) => e.is_cancelled(),
            _ => false,
        }
    }

    /// Returns `true` when this error indicates `case.lock` contention.
    pub fn is_locked(&self) -> bool {
        matches!(self, Self::Locked(_) | Self::Engine(EngineError::Locked(_)))
    }

    /// Short error category name suitable for structured logs and MCP error text.
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::Io(_) => "IOError",
            Self::Engine(_) => "EngineError",
            Self::Json(_) => "JsonError",
            Self::Zip(_) => "ZipError",
            Self::InvalidInput(_) => "ValueError",
            Self::NotFound(_) => "FileNotFoundError",
            Self::Locked(_) => "LockError",
            Self::CaseClosed => "RuntimeError",
            Self::CorruptCase(_) => "ValueError",
            Self::AuditTampered(_) => "AuditError",
            Self::IntegrityFailed(_) => "IntegrityError",
            Self::Cancelled(_) => "Cancelled",
            Self::MissingMaterials(_) => "FileNotFoundError",
            Self::Preview(_) => "PreviewError",
            Self::Other(_) => "RuntimeError",
        }
    }
}

pub type CoreResult<T> = Result<T, CoreError>;
