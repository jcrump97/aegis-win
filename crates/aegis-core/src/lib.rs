//! AegisWin core. Everything security-relevant lives here so it can be tested
//! without a window; `src-tauri` is a thin command layer on top.

pub mod autostart;
pub mod chain;
pub mod engine;
pub mod error;
pub mod executor;
pub mod history;
pub mod history_service;
pub mod llm;
pub mod notify;
pub mod mcp;
pub mod os;
pub mod passphrase;
pub mod plan;
pub mod plugin_data;
pub mod qr;
pub mod registry;
pub mod schema;
pub mod secret;
pub mod state;
pub mod sync;
#[cfg(any(test, feature = "test-util"))]
pub mod testing;
pub mod tickets;
pub mod tls;
pub mod vault;

pub use error::{AegisError, AegisResult, ErrorCode};
