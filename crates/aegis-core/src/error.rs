//! One error type for everything that crosses a boundary (Tauri `invoke`, MCP,
//! the approval portal). It carries a stable machine-readable code plus a
//! human message, and never any secret.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    InvalidArguments,
    UnknownTool,
    PluginDisabled,
    ComponentDisabled,
    RequiresAdmin,
    AccessDenied,
    ExecutionFailed,
    OffLanTrustRequired,
    LlmNotConfigured,
    LlmFailed,
    VaultMissing,
    VaultExists,
    VaultLocked,
    PinRequired,
    PinInvalid,
    PinLockedOut,
    PinTooWeak,
    NotFound,
    Conflict,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, thiserror::Error)]
#[error("{message}")]
pub struct AegisError {
    pub code: ErrorCode,
    pub message: String,
}

impl AegisError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidArguments, message)
    }
    pub fn failed(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::ExecutionFailed, message)
    }
    pub fn requires_admin(what: &str) -> Self {
        Self::new(
            ErrorCode::RequiresAdmin,
            format!("{what} needs administrator rights. Use \"Restart as administrator\" in AegisWin, then try again."),
        )
    }
}

pub type AegisResult<T> = Result<T, AegisError>;
