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
    /// Only the AegisWin app may call this tool. It is left out of MCP
    /// `tools/list`, and an MCP call gets the same error as an unknown tool.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub app_only: bool,
    /// May be a step of an action plan (ADR 0003 §4). Only pin-gated,
    /// state-changing tools with a boolean `dryRun` qualify.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub plan_eligible: bool,
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
            if tool.plan_eligible
                && (tool.default_gate_policy != GatePolicy::PinRequired
                    || tool.read_only
                    || tool.app_only
                    || tool.input_schema.pointer("/properties/dryRun").is_none())
            {
                return Err(format!("{at}: planEligible needs defaultGatePolicy pin_required, readOnly false, a boolean dryRun, and no appOnly"));
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
    /// Present for plugins with `usesLlm: true`; already bound to this plugin's id and trust grant.
    pub llm: Option<crate::llm::LlmHandle>,
    /// This plugin's own records in the vault. Always set by the engine.
    pub store: Option<crate::plugin_data::PluginStore>,
    /// This plugin's own encrypted history stream. Always set by the engine.
    pub history: Option<crate::history_service::HistoryHandle>,
}

impl ToolContext {
    pub fn component_enabled(&self, id: &str) -> bool {
        self.enabled_components.iter().any(|c| c == id)
    }

    pub fn llm(&self) -> AegisResult<&crate::llm::LlmHandle> {
        self.llm.as_ref().ok_or_else(|| crate::AegisError::new(crate::ErrorCode::LlmNotConfigured, "this plugin is not allowed to use the LLM service"))
    }

    pub fn store(&self) -> AegisResult<&crate::plugin_data::PluginStore> {
        self.store.as_ref().ok_or_else(|| crate::AegisError::new(crate::ErrorCode::Internal, "no plugin data store in this context"))
    }
    pub fn history(&self) -> AegisResult<&crate::history_service::HistoryHandle> {
        self.history.as_ref().ok_or_else(|| crate::AegisError::new(crate::ErrorCode::Internal, "no history stream in this context"))
    }
}

/// What a call would do, written by the plugin's own code from the arguments
/// (never from AI- or agent-supplied text). Shown with an approval request,
/// next to the raw arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallReview {
    /// Plain sentences describing exactly what will happen.
    pub lines: Vec<String>,
    /// Things the owner should notice before approving.
    pub warnings: Vec<String>,
}

/// Handed to [`Plugin::on_unlock`]. The store stays usable from background
/// threads, but only while the vault is unlocked and the plugin installed.
#[derive(Clone, Default)]
pub struct UnlockContext {
    pub enabled_components: Vec<String>,
    /// This plugin's own records in the vault. Always set by the engine.
    pub store: Option<crate::plugin_data::PluginStore>,
    /// This plugin's own encrypted history stream. Always set by the engine.
    /// Appending keeps working after lock; reading does not.
    pub history: Option<crate::history_service::HistoryHandle>,
    /// Monitoring is paused from the tray (also from a pause kept in the
    /// runtime file across a restart).
    pub paused: bool,
}

/// Handed to [`Plugin::run_locked`]. On a lock everything in it comes from
/// the vault (what the plugin declared with `HistoryHandle::set_runtime`).
/// At launch (`launch` is set) it comes from the runtime file on disk,
/// which is checked against the vault only at the next unlock (ADR 0002 §6).
#[derive(Clone)]
pub struct LockedContext {
    /// The plugin's own runtime section, as it last declared it.
    pub runtime: Value,
    /// This plugin's history stream: appending works, reading does not.
    pub history: crate::history_service::HistoryHandle,
    /// Monitoring is paused from the tray.
    pub paused: bool,
    /// Set when AegisWin resumes this work at launch, not at a lock.
    pub launch: Option<Launch>,
}

/// How AegisWin was started, for a plugin's session record.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Launch {
    /// The owner started it.
    #[default]
    Manual,
    /// The Startup shortcut started it at sign-in (`--background`).
    Autostart,
}

impl Launch {
    pub fn as_str(self) -> &'static str {
        match self {
            Launch::Manual => "manual",
            Launch::Autostart => "autostart",
        }
    }
}

/// Shown once after the first unlock that follows a resume at launch: when
/// monitoring was not running before this launch (ADR 0002 §6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResumeNotice {
    /// When monitoring stopped (RFC 3339), if the history still has it.
    pub from: Option<String>,
    /// When this launch started monitoring again (RFC 3339).
    pub to: String,
    /// Why it was not running, in a plain sentence.
    pub label: String,
}

/// Why AegisWin is exiting, for a plugin's clean-stop record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    /// Quit from the tray or by closing the window.
    Quit,
    /// Windows is shutting down or signing out (the event loop ended on its own).
    Shutdown,
}

#[async_trait]
pub trait Plugin: Send + Sync {
    fn manifest(&self) -> &PluginManifest;

    /// Runs one tool. Arguments are already validated against the tool's
    /// `inputSchema` with defaults applied, and the gate has already passed.
    async fn call(&self, tool: &str, args: Value, ctx: ToolContext) -> AegisResult<Value>;

    /// Called when the vault unlocks with this plugin installed, and again
    /// when its components change (start background work here).
    fn on_unlock(&self, _ctx: &UnlockContext) {}

    /// Called when the vault locks or the plugin is uninstalled.
    fn on_lock(&self) {}

    /// Describes a gated call for its approval request. Arguments are already
    /// validated. `None` (the default) shows the tool description and the
    /// arguments only.
    fn review_call(&self, _tool: &str, _args: &Value, _enabled_components: &[String]) -> Option<CallReview> {
        None
    }

    /// True while the plugin is doing work the owner asked to keep running
    /// in the background (for example an active monitor). Closing the window
    /// then hides AegisWin to the tray instead of quitting.
    fn background_active(&self) -> bool {
        false
    }

    /// Called **instead of** `on_lock` when the vault locks while this plugin
    /// has declared locked work (ADR 0002 §4) and its runtime file is not
    /// waiting for review. It must drop everything `on_lock` drops, then may
    /// keep running only what `ctx.runtime` describes, writing only to
    /// `ctx.history`. Returns true if it keeps running. The default stops
    /// everything, like `on_lock`.
    fn run_locked(&self, _ctx: &LockedContext) -> bool {
        self.on_lock();
        false
    }

    /// Pause or resume background work from the tray (no PIN: agents cannot
    /// reach the tray). The plugin records the pause in its history.
    fn set_paused(&self, _paused: bool) {}

    /// AegisWin is exiting: write a clean-stop record. Called before the
    /// final `on_lock`, whether the vault is locked or not.
    fn on_exit(&self, _reason: ExitReason) {}

    /// Called once after `on_unlock` at each unlock. A plugin that resumed at
    /// launch says when it was not running before; the engine shows it in
    /// the app until dismissed. Never sent over MCP.
    fn resume_notice(&self) -> Option<ResumeNotice> {
        None
    }
}

pub struct Registry {
    plugins: Vec<Arc<dyn Plugin>>,
}

impl Registry {
    pub fn new(plugins: Vec<Arc<dyn Plugin>>) -> Result<Self, String> {
        let mut ids = std::collections::HashSet::new();
        for p in &plugins {
            p.manifest().validate()?;
            if p.manifest().id == crate::history_service::APPROVALS_STREAM {
                return Err(format!("plugin id '{}' is reserved for the approvals history", p.manifest().id));
            }
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
    fn only_pin_gated_changes_with_a_dry_run_can_be_plan_steps() {
        let mut m = manifest();
        m.tools[1].plan_eligible = true;
        m.validate().unwrap();
        let broken: [fn(&mut ToolManifest); 4] = [
            |t| t.default_gate_policy = GatePolicy::Auto,
            |t| t.read_only = true,
            |t| t.app_only = true,
            |t| t.input_schema = json!({ "type": "object", "properties": {} }),
        ];
        for (i, breaks) in broken.iter().enumerate() {
            let mut m = manifest();
            m.tools[1].plan_eligible = true;
            breaks(&mut m.tools[1]);
            assert!(m.validate().unwrap_err().contains("planEligible"), "case {i}");
        }
        // A read-only tool can never be a step.
        let mut m = manifest();
        m.tools[0].plan_eligible = true;
        assert!(m.validate().is_err());
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
