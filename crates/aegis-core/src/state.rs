//! What lives inside the encrypted vault, and the secret-free views of it
//! that are sent to the webview.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::history::{Retention, StreamKey};
use crate::llm::LlmConfig;
use crate::registry::GatePolicy;
use crate::secret::Secret;

pub const DEFAULT_MCP_PORT: u16 = 47821;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpConfig {
    /// Start the MCP server automatically after unlocking.
    pub enabled: bool,
    /// `127.0.0.1`, or one of this PC's private LAN IPv4 addresses.
    pub host: String,
    pub port: u16,
    pub auth_token: Secret,
    /// Add a Windows Firewall rule for LAN binds (only possible when elevated).
    pub open_firewall: bool,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self { enabled: false, host: "127.0.0.1".into(), port: DEFAULT_MCP_PORT, auth_token: Secret::random_token(), open_firewall: true }
    }
}

/// The idle auto-lock choices. There is no "off".
pub const AUTO_LOCK_CHOICES: [u32; 4] = [5, 15, 30, 60];
pub const DEFAULT_AUTO_LOCK_MINUTES: u32 = 15;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VaultState {
    pub first_run_completed: bool,
    pub installed_plugins: Vec<String>,
    /// Plugin id → enabled sub-component ids.
    pub installed_components: BTreeMap<String, Vec<String>>,
    pub trusted_external_llm_plugins: Vec<String>,
    /// `plugin:tool` → policy, overriding the manifest default.
    pub tool_gate_overrides: BTreeMap<String, GatePolicy>,
    /// UI zoom in percent (80-150).
    pub ui_scale: u32,
    /// Minutes without owner activity before the vault locks itself (ADR 0002 §4).
    pub auto_lock_minutes: u32,
    pub llm: LlmConfig,
    pub mcp: McpConfig,
    /// Plugin id → key → record (`plugin_data::PluginStore`). Kept when a
    /// plugin is uninstalled, but unreachable until it is installed again.
    pub plugin_data: BTreeMap<String, BTreeMap<String, Value>>,
    /// History stream → its keypair (ADR 0002 §5). The private half never
    /// leaves the vault; the public half is cached for writing while locked.
    pub history_keys: BTreeMap<String, StreamKey>,
    /// History stream → retention, when the owner changed the default.
    pub history_retention: BTreeMap<String, Retention>,
    /// Plugin id → what it runs while locked: the copy each runtime file is
    /// checked against on unlock (`history_service::RuntimeFile::plugin`).
    pub runtime: BTreeMap<String, Value>,
}

impl Default for VaultState {
    fn default() -> Self {
        Self {
            first_run_completed: false,
            installed_plugins: vec![],
            installed_components: BTreeMap::new(),
            trusted_external_llm_plugins: vec![],
            tool_gate_overrides: BTreeMap::new(),
            ui_scale: 100,
            auto_lock_minutes: DEFAULT_AUTO_LOCK_MINUTES,
            llm: LlmConfig::default(),
            mcp: McpConfig::default(),
            plugin_data: BTreeMap::new(),
            history_keys: BTreeMap::new(),
            history_retention: BTreeMap::new(),
            runtime: BTreeMap::new(),
        }
    }
}

impl VaultState {
    pub fn components_for(&self, plugin_id: &str) -> Vec<String> {
        self.installed_components.get(plugin_id).cloned().unwrap_or_default()
    }

    pub fn is_installed(&self, plugin_id: &str) -> bool {
        self.installed_plugins.iter().any(|p| p == plugin_id)
    }

    pub fn is_trusted(&self, plugin_id: &str) -> bool {
        self.trusted_external_llm_plugins.iter().any(|p| p == plugin_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn older_vaults_without_new_fields_still_load() {
        let state: VaultState = serde_json::from_str(r#"{ "firstRunCompleted": true, "installedPlugins": ["event-logs"] }"#).unwrap();
        assert!(state.first_run_completed);
        assert_eq!(state.ui_scale, 100);
        assert_eq!(state.auto_lock_minutes, 15);
        assert_eq!(state.mcp.port, DEFAULT_MCP_PORT);
        assert_eq!(state.mcp.auth_token.expose().len(), 48);
        assert!(state.plugin_data.is_empty());
        assert!(state.history_keys.is_empty() && state.runtime.is_empty());
    }
}
