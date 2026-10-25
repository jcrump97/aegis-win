//! What lives inside the encrypted vault, and the secret-free views of it
//! that are sent to the webview.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

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
    pub llm: LlmConfig,
    pub mcp: McpConfig,
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
            llm: LlmConfig::default(),
            mcp: McpConfig::default(),
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
        assert_eq!(state.mcp.port, DEFAULT_MCP_PORT);
        assert_eq!(state.mcp.auth_token.expose().len(), 48);
    }
}
