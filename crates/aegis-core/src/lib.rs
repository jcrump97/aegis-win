//! AegisWin core. Everything security-relevant lives here so it can be tested
//! without a window; `src-tauri` is a thin command layer on top.

pub mod engine;
pub mod error;
pub mod llm;
pub mod mcp;
pub mod os;
pub mod registry;
pub mod schema;
pub mod secret;
pub mod state;
#[cfg(any(test, feature = "test-util"))]
pub mod testing;
pub mod tickets;
pub mod vault;

pub use error::{AegisError, AegisResult, ErrorCode};
