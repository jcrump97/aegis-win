//! Plugin contract, manifest validation, and the per-tool gate decision.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::AegisResult;
use crate::schema;

/// MCP clients (including Claude) reject tool names outside
/// `^[a-zA-Z0-9_-]{1,64}$`, so the MCP name is `<plugin>__<tool>`.
pub const MCP_SEPARATOR: &str = "__";
const MAX_MCP_NAME: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatePolicy {
    Auto,
    PinRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubComponent {
    pub id: String,
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolManifest {
    pub id: String,
    pub name: String,
    pub description: String,
    pub requires_admin: bool,
    pub default_gate_policy: GatePolicy,
    /// True when the tool never changes system or app state (MCP `readOnlyHint`).
    pub read_only: bool,
    /// Component that must be enabled for this tool to run, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component: Option<String>,
    pub input_schema: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub optional_install_default: bool,
    pub uses_llm: bool,
    #[serde(default)]
    pub sub_components: Vec<SubComponent>,
    pub tools: Vec<ToolManifest>,
}

impl PluginManifest {
    /// Parses and validates a manifest (plugins embed theirs with `include_str!`).
    pub fn from_json(json: &str) -> Result<Self, String> {
        let manifest: Self = serde_json::from_str(json).map_err(|e| format!("manifest.json: {e}"))?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), String> {
        let id_ok = |s: &str, extra: char| {
            !s.is_empty()
                && s.starts_with(|c: char| c.is_ascii_lowercase())
                && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == extra)
                && !s.contains(MCP_SEPARATOR)
        };
        if !id_ok(&self.id, '-') {
            return Err(format!("plugin id '{}' must be lowercase letters, digits and '-'", self.id));
        }
        if self.tools.is_empty() {
            return Err(format!("{}: a plugin must declare at least one tool", self.id));
        }
        let mut seen = std::collections::HashSet::new();
        for tool in &self.tools {
            let at = format!("{}:{}", self.id, tool.id);
            if !id_ok(&tool.id, '_') {
                return Err(format!("{at}: tool id must be lowercase letters, digits and single '_'"));
            }
            if mcp_tool_name(&self.id, &tool.id).len() > MAX_MCP_NAME {
                return Err(format!("{at}: MCP tool name would exceed {MAX_MCP_NAME} characters"));
            }
            if !seen.insert(tool.id.as_str()) {
                return Err(format!("{at}: duplicate tool id"));
            }
            if tool.input_schema.get("type").and_then(Value::as_str) != Some("object") {
                return Err(format!("{at}: inputSchema must be an object schema"));
            }
            schema::check_schema(&tool.input_schema, &at)?;
            if let Some(dry) = tool.input_schema.pointer("/properties/dryRun") {
                if dry.get("type").and_then(Value::as_str) != Some("boolean") {
                    return Err(format!("{at}: dryRun must be a boolean"));
                }
            }
            if let Some(component) = &tool.component {
                if !self.sub_components.iter().any(|c| &c.id == component) {
                    return Err(format!("{at}: unknown component '{component}'"));
                }
            }
        }
        Ok(())
    }

    pub fn tool(&self, id: &str) -> Option<&ToolManifest> {
        self.tools.iter().find(|t| t.id == id)
    }
}

/// Per-call context handed to plugins. Built fresh for every call from the
/// unlocked vault state, so a plugin never holds secrets between calls.
#[derive(Clone, Default)]
pub struct ToolContext {
    pub elevated: bool,
    pub enabled_components: Vec<String>,
}

impl ToolContext {
    pub fn component_enabled(&self, id: &str) -> bool {
        self.enabled_components.iter().any(|c| c == id)
    }
}

#[async_trait]
pub trait Plugin: Send + Sync {
    fn manifest(&self) -> &PluginManifest;

    /// Runs one tool. Arguments are already validated against the tool's
    /// `inputSchema` with defaults applied, and the gate has already passed.
    async fn call(&self, tool: &str, args: Value, ctx: ToolContext) -> AegisResult<Value>;

    /// Called when the vault unlocks with this plugin installed (start background work here).
    fn on_unlock(&self, _enabled_components: &[String]) {}

    /// Called when the vault locks or the plugin is uninstalled.
    fn on_lock(&self) {}
}

pub struct Registry {
    plugins: Vec<Arc<dyn Plugin>>,
}

impl Registry {
    pub fn new(plugins: Vec<Arc<dyn Plugin>>) -> Result<Self, String> {
        let mut ids = std::collections::HashSet::new();
        for p in &plugins {
            p.manifest().validate()?;
            if !ids.insert(p.manifest().id.clone()) {
                return Err(format!("duplicate plugin id '{}'", p.manifest().id));
            }
        }
        Ok(Self { plugins })
    }

    pub fn plugins(&self) -> &[Arc<dyn Plugin>] {
        &self.plugins
    }

    pub fn plugin(&self, id: &str) -> Option<&Arc<dyn Plugin>> {
        self.plugins.iter().find(|p| p.manifest().id == id)
    }

    pub fn tool(&self, plugin_id: &str, tool_id: &str) -> Option<(&Arc<dyn Plugin>, &ToolManifest)> {
        let plugin = self.plugin(plugin_id)?;
        let tool = plugin.manifest().tool(tool_id)?;
        Some((plugin, tool))
    }
}

pub fn mcp_tool_name(plugin_id: &str, tool_id: &str) -> String {
    format!("{plugin_id}{MCP_SEPARATOR}{tool_id}")
}

pub fn parse_mcp_tool_name(name: &str) -> Option<(&str, &str)> {
    name.split_once(MCP_SEPARATOR)
}

/// Key used for gate overrides in the vault (`plugin:tool`).
pub fn policy_key(plugin_id: &str, tool_id: &str) -> String {
    format!("{plugin_id}:{tool_id}")
}

pub fn effective_policy(plugin_id: &str, tool: &ToolManifest, overrides: &BTreeMap<String, GatePolicy>) -> GatePolicy {
    overrides.get(&policy_key(plugin_id, &tool.id)).copied().unwrap_or(tool.default_gate_policy)
}

/// A dry run only describes what would happen, so it skips the PIN and admin gates.
pub fn is_dry_run(tool: &ToolManifest, args: &Value) -> bool {
    tool.input_schema.pointer("/properties/dryRun").is_some() && args.get("dryRun") == Some(&Value::Bool(true))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    Run,
    NeedsPin,
    NeedsAdmin,
}

/// Admin is checked before the PIN: approving something that cannot run would waste the approval.
pub fn gate(tool: &ToolManifest, policy: GatePolicy, args: &Value, elevated: bool) -> Gate {
    if is_dry_run(tool, args) {
        Gate::Run
    } else if tool.requires_admin && !elevated {
        Gate::NeedsAdmin
    } else if policy == GatePolicy::PinRequired {
        Gate::NeedsPin
    } else {
        Gate::Run
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn manifest() -> PluginManifest {
        PluginManifest::from_json(
            &json!({
                "id": "demo-plugin",
                "name": "Demo",
                "version": "1.0.0",
                "description": "d",
                "optionalInstallDefault": true,
                "usesLlm": false,
                "subComponents": [{ "id": "demo-plugin:extra", "name": "Extra", "description": "e" }],
                "tools": [
                    { "id": "read_it", "name": "Read", "description": "r", "requiresAdmin": false,
                      "defaultGatePolicy": "auto", "readOnly": true, "inputSchema": { "type": "object", "properties": {} } },
                    { "id": "fix_it", "name": "Fix", "description": "f", "requiresAdmin": true,
                      "defaultGatePolicy": "pin_required", "readOnly": false, "component": "demo-plugin:extra",
                      "inputSchema": { "type": "object", "properties": { "dryRun": { "type": "boolean", "default": false } } } }
                ]
            })
            .to_string(),
        )
        .unwrap()
    }

    #[test]
    fn mcp_names_are_client_safe_and_round_trip() {
        let name = mcp_tool_name("event-logs", "query_logs");
        assert_eq!(name, "event-logs__query_logs");
        assert!(name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'));
        assert_eq!(parse_mcp_tool_name(&name), Some(("event-logs", "query_logs")));
    }

    #[test]
    fn rejects_bad_manifests() {
        let mut m = manifest();
        m.id = "Bad:Id".into();
        assert!(m.validate().is_err());

        let mut m = manifest();
        m.tools[0].id = "has__double".into();
        assert!(m.validate().is_err());

        let mut m = manifest();
        m.tools[1].component = Some("demo-plugin:missing".into());
        assert!(m.validate().is_err());

        let mut m = manifest();
        m.tools[0].input_schema = json!({ "type": "object", "properties": { "q": { "type": "string", "format": "x" } } });
        assert!(m.validate().is_err());

        assert!(PluginManifest::from_json(r#"{"id":"x"}"#).is_err(), "requiresAdmin/defaultGatePolicy must be declared");
    }

    #[test]
    fn gate_order_dry_run_then_admin_then_pin() {
        let m = manifest();
        let fix = m.tool("fix_it").unwrap();
        let read = m.tool("read_it").unwrap();
        assert_eq!(gate(fix, GatePolicy::PinRequired, &json!({ "dryRun": true }), false), Gate::Run);
        assert_eq!(gate(fix, GatePolicy::PinRequired, &json!({}), false), Gate::NeedsAdmin);
        assert_eq!(gate(fix, GatePolicy::PinRequired, &json!({}), true), Gate::NeedsPin);
        assert_eq!(gate(read, GatePolicy::Auto, &json!({}), false), Gate::Run);
        // dryRun only counts for tools that declare it.
        assert_eq!(gate(read, GatePolicy::PinRequired, &json!({ "dryRun": true }), false), Gate::NeedsPin);
    }

    #[test]
    fn overrides_replace_the_default_policy() {
        let m = manifest();
        let read = m.tool("read_it").unwrap();
        let mut overrides = BTreeMap::new();
        assert_eq!(effective_policy("demo-plugin", read, &overrides), GatePolicy::Auto);
        overrides.insert(policy_key("demo-plugin", "read_it"), GatePolicy::PinRequired);
        assert_eq!(effective_policy("demo-plugin", read, &overrides), GatePolicy::PinRequired);
    }
}
