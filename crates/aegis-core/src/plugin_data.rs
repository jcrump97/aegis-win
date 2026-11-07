//! Small per-plugin records kept inside the encrypted vault (ADR 0002 §1:
//! monitor rules). A plugin reaches only its own records, through a
//! [`PluginStore`] the engine binds to its id, and only while the vault is
//! unlocked and the plugin is installed.
//!
//! Every write re-encrypts and saves the whole vault, so this is for
//! configuration that changes when the owner acts, never for telemetry.

use std::sync::Weak;

use serde_json::Value;

use crate::engine::Engine;
use crate::error::{AegisError, AegisResult, ErrorCode};

/// Total serialized size of one plugin's records.
pub const MAX_PLUGIN_DATA_BYTES: usize = 256 * 1024;
pub const MAX_KEY_CHARS: usize = 64;

/// Keys are short identifiers so they can never be confused with data.
pub fn check_key(key: &str) -> AegisResult<()> {
    let ok = !key.is_empty()
        && key.len() <= MAX_KEY_CHARS
        && key.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    if ok {
        Ok(())
    } else {
        Err(AegisError::invalid(format!("plugin data keys must be 1-{MAX_KEY_CHARS} lowercase letters, digits, '_' or '-'")))
    }
}

/// A plugin's handle to its own records. Holds no secret and no data: every
/// call goes back to the engine, which checks the vault is unlocked and the
/// plugin is still installed.
#[derive(Clone)]
pub struct PluginStore {
    engine: Weak<Engine>,
    plugin_id: String,
}

impl std::fmt::Debug for PluginStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginStore").field("plugin_id", &self.plugin_id).finish()
    }
}

impl PluginStore {
    pub(crate) fn new(engine: Weak<Engine>, plugin_id: &str) -> Self {
        Self { engine, plugin_id: plugin_id.to_owned() }
    }

    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    fn engine(&self) -> AegisResult<std::sync::Arc<Engine>> {
        self.engine.upgrade().ok_or_else(|| AegisError::new(ErrorCode::Internal, "engine is shutting down"))
    }

    pub fn get(&self, key: &str) -> AegisResult<Option<Value>> {
        check_key(key)?;
        self.engine()?.plugin_data_get(&self.plugin_id, key)
    }

    /// Stores `value` under `key`, replacing any previous value, and saves the vault.
    pub fn set(&self, key: &str, value: Value) -> AegisResult<()> {
        check_key(key)?;
        self.engine()?.plugin_data_set(&self.plugin_id, key, Some(value))
    }

    /// Removes `key` (no error if it was not there) and saves the vault.
    pub fn remove(&self, key: &str) -> AegisResult<()> {
        check_key(key)?;
        self.engine()?.plugin_data_set(&self.plugin_id, key, None)
    }

    /// Removes every record of this plugin and saves the vault.
    pub fn clear(&self) -> AegisResult<()> {
        self.engine()?.plugin_data_clear(&self.plugin_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_identifiers() {
        for good in ["monitors", "rule-1", "a_b", "x"] {
            assert!(check_key(good).is_ok(), "{good}");
        }
        for bad in ["", "Monitors", "a/b", "a.b", "a b", "../x", &"x".repeat(65)] {
            assert!(check_key(bad).is_err(), "{bad}");
        }
    }
}
