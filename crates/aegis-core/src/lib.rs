//! AegisWin core. Everything security-relevant lives here so it can be tested
//! without a window; `src-tauri` is a thin command layer on top.

pub mod error;
pub mod os;
pub mod registry;
pub mod schema;
pub mod vault;

pub use error::{AegisError, AegisResult, ErrorCode};
