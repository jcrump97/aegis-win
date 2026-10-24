//! The engine owns the vault, the plugin registry, the PIN guard, approval
//! tickets and the MCP server. Tauri commands and the MCP server both call
//! into it, so every gate is enforced in exactly one place.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{AegisError, AegisResult, ErrorCode};
use crate::llm::{classify_endpoint, Endpoint, LlmHandle};
use crate::mcp::{self, McpHandle, McpStatus};
use crate::registry::{self, Gate, GatePolicy, Plugin, Registry, ToolContext, ToolManifest};
use crate::schema;
use crate::secret::Secret;
use crate::state::VaultState;
use crate::tickets::{NewTicket, TicketStatus, TicketStore, TicketView, STRIKES_PER_TICKET};
use crate::vault::{self, KdfParams, NewKey, PinGuard, UnlockedVault, VaultError};

pub const VAULT_FILE: &str = "vault.enc.json";
const MAX_COMMENT_CHARS: usize = 500;

pub struct EngineOptions {
    pub kdf: KdfParams,
    pub elevated: bool,
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self { kdf: KdfParams::DEFAULT, elevated: crate::os::is_elevated() }
    }
}

pub struct Engine {
    /// Lets `&self` methods hand an owning reference to background tasks.
    me: std::sync::Weak<Engine>,
    data_dir: PathBuf,
    registry: Registry,
    vault: Mutex<Option<UnlockedVault<VaultState>>>,
    guard: Mutex<PinGuard>,
    /// Serializes PIN checks so parallel guesses cannot all slip past the guard.
    pin_check: tokio::sync::Mutex<()>,
    tickets: Mutex<TicketStore>,
    http: reqwest::Client,
    elevated: bool,
    kdf: KdfParams,
    mcp: tokio::sync::Mutex<Option<McpHandle>>,
}

/// Where a tool call came from. Only the desktop UI can pass a PIN inline;
/// MCP callers get an approval ticket instead.
pub enum Origin {
    Ui { pin: Option<String> },
    Mcp,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RunOutcome {
    Completed { result: Value },
    PendingApproval { ticket: Box<TicketView> },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub vault_exists: bool,
    pub unlocked: bool,
    pub first_run_completed: bool,
    pub elevated: bool,
    pub version: &'static str,
    pub data_dir: String,
    pub pin_lockout_seconds: u64,
    pub ui_scale: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LlmSettingsView {
    pub base_url: String,
    pub model: String,
    pub has_api_key: bool,
    pub endpoint: Option<Endpoint>,
    pub endpoint_error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpSettingsView {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub open_firewall: bool,
    pub status: McpStatus,
    /// This PC's private LAN address, offered as the alternative to loopback.
    pub suggested_lan_host: Option<String>,
}

/// Everything the Settings screens need, without any secret.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsView {
    pub ui_scale: u32,
    pub llm: LlmSettingsView,
    pub mcp: McpSettingsView,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettingsUpdate {
    pub ui_scale: Option<u32>,
    pub llm_base_url: Option<String>,
    pub llm_model: Option<String>,
    pub mcp_enabled: Option<bool>,
    pub mcp_host: Option<String>,
    pub mcp_port: Option<u16>,
    pub mcp_open_firewall: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComponentView {
    pub id: String,
    pub name: String,
    pub description: String,
    pub enabled: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolView {
    pub id: String,
    pub name: String,
    pub description: String,
    pub requires_admin: bool,
    pub read_only: bool,
    pub component: Option<String>,
    /// False when the tool's component is turned off.
    pub available: bool,
    pub default_gate_policy: GatePolicy,
    pub effective_policy: GatePolicy,
    pub mcp_name: String,
    pub input_schema: Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginView {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub installed: bool,
    pub optional_install_default: bool,
    pub uses_llm: bool,
    pub trusted_off_lan: bool,
    pub sub_components: Vec<ComponentView>,
    pub tools: Vec<ToolView>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LlmTest {
    pub endpoint: Endpoint,
    pub models: Vec<String>,
}

/// A tool an MCP client may see (installed plugin, component enabled).
pub struct ExposedTool {
    pub plugin_id: String,
    pub tool: ToolManifest,
    pub policy: GatePolicy,
}

/// A call that passed every check except the gate.
struct Prepared {
    plugin: Arc<dyn Plugin>,
    tool: ToolManifest,
    args: Value,
    gate: Gate,
    ctx: ToolContext,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn vault_err(e: VaultError) -> AegisError {
    match e {
        VaultError::AlreadyExists => AegisError::new(ErrorCode::VaultExists, "AegisWin is already set up in this folder."),
        VaultError::NotFound => AegisError::new(ErrorCode::VaultMissing, "AegisWin has not been set up yet."),
        VaultError::WrongPin => AegisError::new(ErrorCode::PinInvalid, "Incorrect PIN."),
        VaultError::PinTooShort | VaultError::PinTooLong => AegisError::new(ErrorCode::PinTooWeak, e.to_string()),
        VaultError::Corrupt(_) | VaultError::Io(_) => AegisError::new(ErrorCode::Internal, e.to_string()),
    }
}

fn locked() -> AegisError {
    AegisError::new(ErrorCode::VaultLocked, "Unlock AegisWin first.")
}

fn lockout(remaining: Duration) -> AegisError {
    AegisError::new(ErrorCode::PinLockedOut, format!("Too many wrong PINs. Try again in {} seconds.", remaining.as_secs().max(1)))
}

fn internal(e: impl std::fmt::Display) -> AegisError {
    AegisError::new(ErrorCode::Internal, e.to_string())
}

/// `127.0.0.1`, or a private IPv4 (10/8, 172.16/12, 192.168/16). Never `0.0.0.0`.
pub fn validate_mcp_host(host: &str) -> AegisResult<Ipv4Addr> {
    let ip: Ipv4Addr = host.trim().parse().map_err(|_| AegisError::invalid("MCP host must be an IPv4 address such as 127.0.0.1."))?;
    if ip == Ipv4Addr::LOCALHOST || ip.is_private() {
        Ok(ip)
    } else {
        Err(AegisError::invalid("MCP host must be 127.0.0.1 or a private LAN address of this PC (10.x, 172.16-31.x or 192.168.x)."))
    }
}

fn plugin_component_ids(plugin: &dyn Plugin) -> Vec<String> {
    plugin.manifest().sub_components.iter().map(|c| c.id.clone()).collect()
}

impl Engine {
    pub fn new(data_dir: impl Into<PathBuf>, registry: Registry, options: EngineOptions) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            me: me.clone(),
            data_dir: data_dir.into(),
            registry,
            vault: Mutex::new(None),
            guard: Mutex::new(PinGuard::default()),
            pin_check: tokio::sync::Mutex::new(()),
            tickets: Mutex::new(TicketStore::default()),
            http: crate::llm::http_client(),
            elevated: options.elevated,
            kdf: options.kdf,
            mcp: tokio::sync::Mutex::new(None),
        })
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    pub fn elevated(&self) -> bool {
        self.elevated
    }

    fn vault_path(&self) -> PathBuf {
        self.data_dir.join(VAULT_FILE)
    }

    fn with_state<R>(&self, f: impl FnOnce(&VaultState) -> R) -> AegisResult<R> {
        let guard = lock(&self.vault);
        guard.as_ref().map(|v| f(&v.state)).ok_or_else(locked)
    }

    /// Applies a change to the vault state and saves it; on a failed save the
    /// in-memory state is rolled back.
    fn mutate<R>(&self, f: impl FnOnce(&mut VaultState) -> AegisResult<R>) -> AegisResult<R> {
        let mut guard = lock(&self.vault);
        let vault = guard.as_mut().ok_or_else(locked)?;
        let before = vault.state.clone();
        let out = f(&mut vault.state)?;
        if let Err(e) = vault.save() {
            vault.state = before;
            return Err(vault_err(e));
        }
        Ok(out)
    }

    fn guard_check(&self) -> AegisResult<()> {
        lock(&self.guard).check(Instant::now()).map_err(lockout)
    }

    // ---- lifecycle -------------------------------------------------------

    pub fn status(&self) -> Status {
        let guard = lock(&self.vault);
        let state = guard.as_ref().map(|v| &v.state);
        Status {
            vault_exists: vault::vault_exists(&self.vault_path()),
            unlocked: state.is_some(),
            first_run_completed: state.is_some_and(|s| s.first_run_completed),
            elevated: self.elevated,
            version: env!("CARGO_PKG_VERSION"),
            data_dir: self.data_dir.display().to_string(),
            pin_lockout_seconds: lock(&self.guard).check(Instant::now()).err().map_or(0, |d| d.as_secs().max(1)),
            ui_scale: state.map_or(100, |s| s.ui_scale),
        }
    }

    /// Creates the vault. Plugins marked `optionalInstallDefault` start
    /// installed with every component on; the wizard can change that.
    pub async fn setup(&self, pin: String) -> AegisResult<Status> {
        let pin = Zeroizing::new(pin);
        vault::validate_new_pin(&pin).map_err(vault_err)?;
        let mut state = VaultState::default();
        for plugin in self.registry.plugins() {
            let m = plugin.manifest();
            if m.optional_install_default {
                state.installed_plugins.push(m.id.clone());
                state.installed_components.insert(m.id.clone(), plugin_component_ids(plugin.as_ref()));
            }
        }
        let (path, kdf) = (self.vault_path(), self.kdf);
        let vault = tokio::task::spawn_blocking(move || UnlockedVault::create_with_params(&path, &pin, state, kdf))
            .await
            .map_err(internal)?
            .map_err(vault_err)?;
        self.finish_unlock(vault).await;
        Ok(self.status())
    }

    pub async fn unlock(&self, pin: String) -> AegisResult<Status> {
        let pin = Zeroizing::new(pin);
        if lock(&self.vault).is_some() {
            return Ok(self.status());
        }
        let _serial = self.pin_check.lock().await;
        self.guard_check()?;
        let path = self.vault_path();
        let result = tokio::task::spawn_blocking(move || UnlockedVault::<VaultState>::unlock(&path, &pin)).await.map_err(internal)?;
        match result {
            Ok(vault) => {
                lock(&self.guard).record(true, Instant::now());
                self.finish_unlock(vault).await;
                Ok(self.status())
            }
            Err(VaultError::WrongPin) => {
                lock(&self.guard).record(false, Instant::now());
                Err(vault_err(VaultError::WrongPin))
            }
            Err(e) => Err(vault_err(e)),
        }
    }

    async fn finish_unlock(&self, vault: UnlockedVault<VaultState>) {
        let mcp_enabled = vault.state.mcp.enabled;
        let installed: Vec<(String, Vec<String>)> =
            vault.state.installed_plugins.iter().map(|id| (id.clone(), vault.state.components_for(id))).collect();
        *lock(&self.vault) = Some(vault);
        for (id, components) in installed {
            if let Some(plugin) = self.registry.plugin(&id) {
                plugin.on_unlock(&components);
            }
        }
        if mcp_enabled {
            // A failure (port in use) is shown on the MCP tab; unlocking still succeeds.
            let _ = self.start_mcp_inner().await;
        }
    }

    /// Stops the MCP server and background work, drops the key, and forgets tickets.
    pub async fn lock(&self) -> Status {
        self.stop_mcp().await;
        let installed = lock(&self.vault).take().map(|v| v.state.installed_plugins.clone()).unwrap_or_default();
        for id in installed {
            if let Some(plugin) = self.registry.plugin(&id) {
                plugin.on_lock();
            }
        }
        lock(&self.tickets).clear();
        self.status()
    }

    /// Checks a PIN against the open vault, with the global rate limit.
    pub async fn check_pin(&self, pin: &str) -> AegisResult<()> {
        let _serial = self.pin_check.lock().await;
        self.verify_pin_serialized(pin).await
    }

    /// Caller must hold `pin_check`.
    async fn verify_pin_serialized(&self, pin: &str) -> AegisResult<()> {
        self.guard_check()?;
        let verifier = {
            let guard = lock(&self.vault);
            guard.as_ref().ok_or_else(locked)?.verifier()
        };
        let pin = Zeroizing::new(pin.to_owned());
        let ok = tokio::task::spawn_blocking(move || verifier.verify(&pin)).await.map_err(internal)?;
        lock(&self.guard).record(ok, Instant::now());
        if ok {
            Ok(())
        } else {
            Err(vault_err(VaultError::WrongPin))
        }
    }

    pub async fn change_pin(&self, current: String, new_pin: String) -> AegisResult<()> {
        let new_pin = Zeroizing::new(new_pin);
        vault::validate_new_pin(&new_pin).map_err(vault_err)?;
        self.check_pin(&current).await?;
        let params = {
            let guard = lock(&self.vault);
            guard.as_ref().ok_or_else(locked)?.params()
        };
        let key = tokio::task::spawn_blocking(move || NewKey::derive(&new_pin, params)).await.map_err(internal)?.map_err(vault_err)?;
        let mut guard = lock(&self.vault);
        guard.as_mut().ok_or_else(locked)?.install_key(key).map_err(vault_err)
    }

    // ---- settings --------------------------------------------------------

    pub async fn settings(&self) -> AegisResult<SettingsView> {
        let status = self.mcp_status().await;
        self.with_state(|s| {
            let (endpoint, endpoint_error) = match classify_endpoint(&s.llm.base_url) {
                Ok(e) => (Some(e), None),
                Err(e) => (None, Some(e.message)),
            };
            SettingsView {
                ui_scale: s.ui_scale,
                llm: LlmSettingsView {
                    base_url: s.llm.base_url.clone(),
                    model: s.llm.model.clone(),
                    has_api_key: s.llm.api_key.as_ref().is_some_and(|k| !k.is_empty()),
                    endpoint,
                    endpoint_error,
                },
                mcp: McpSettingsView {
                    enabled: s.mcp.enabled,
                    host: s.mcp.host.clone(),
                    port: s.mcp.port,
                    open_firewall: s.mcp.open_firewall,
                    status,
                    suggested_lan_host: crate::os::primary_lan_ipv4().map(|ip| ip.to_string()),
                },
            }
        })
    }

    pub async fn update_settings(&self, update: SettingsUpdate) -> AegisResult<SettingsView> {
        let (mcp_changed, enabled) = self.mutate(|s| {
            if let Some(scale) = update.ui_scale {
                if !(80..=150).contains(&scale) {
                    return Err(AegisError::invalid("UI scale must be between 80 and 150 percent."));
                }
                s.ui_scale = scale;
            }
            if let Some(url) = &update.llm_base_url {
                let url = url.trim();
                let new = classify_endpoint(url)?;
                if !new.is_lan && !new.https {
                    return Err(AegisError::invalid("Off-LAN LLM endpoints must use https://."));
                }
                // Trust is granted for a destination; a different host needs a new grant.
                let old_host = classify_endpoint(&s.llm.base_url).ok().map(|e| e.host);
                if old_host.as_deref() != Some(new.host.as_str()) {
                    s.trusted_external_llm_plugins.clear();
                }
                s.llm.base_url = url.to_owned();
            }
            if let Some(model) = &update.llm_model {
                let model = model.trim();
                if model.is_empty() || model.len() > 200 {
                    return Err(AegisError::invalid("Model name must be 1-200 characters."));
                }
                s.llm.model = model.to_owned();
            }
            let before = (s.mcp.host.clone(), s.mcp.port, s.mcp.open_firewall);
            if let Some(host) = &update.mcp_host {
                s.mcp.host = validate_mcp_host(host)?.to_string();
            }
            if let Some(port) = update.mcp_port {
                if port < 1024 {
                    return Err(AegisError::invalid("MCP port must be between 1024 and 65535."));
                }
                s.mcp.port = port;
            }
            if let Some(open) = update.mcp_open_firewall {
                s.mcp.open_firewall = open;
            }
            if let Some(enabled) = update.mcp_enabled {
                s.mcp.enabled = enabled;
            }
            Ok((before != (s.mcp.host.clone(), s.mcp.port, s.mcp.open_firewall), update.mcp_enabled))
        })?;
        let running = self.mcp_status().await.running;
        match enabled {
            Some(true) if !running || mcp_changed => {
                self.start_mcp_inner().await?;
            }
            Some(false) => {
                self.stop_mcp().await;
            }
            _ if running && mcp_changed => {
                self.start_mcp_inner().await?;
            }
            _ => {}
        }
        self.settings().await
    }

    /// Stores (or with an empty string, clears) the LLM API key.
    pub fn set_llm_api_key(&self, key: String) -> AegisResult<()> {
        let key = Secret::new(key.trim());
        self.mutate(|s| {
            s.llm.api_key = (!key.is_empty()).then_some(key);
            Ok(())
        })
    }

    pub async fn test_llm(&self) -> AegisResult<LlmTest> {
        let config = self.with_state(|s| s.llm.clone())?;
        let endpoint = classify_endpoint(&config.base_url)?;
        let models = crate::llm::list_models(&self.http, &config).await?;
        Ok(LlmTest { endpoint, models })
    }

    // ---- plugins ---------------------------------------------------------

    pub fn plugins(&self) -> AegisResult<Vec<PluginView>> {
        self.with_state(|s| {
            self.registry
                .plugins()
                .iter()
                .map(|plugin| {
                    let m = plugin.manifest();
                    let components = s.components_for(&m.id);
                    PluginView {
                        id: m.id.clone(),
                        name: m.name.clone(),
                        version: m.version.clone(),
                        description: m.description.clone(),
                        installed: s.is_installed(&m.id),
                        optional_install_default: m.optional_install_default,
                        uses_llm: m.uses_llm,
                        trusted_off_lan: s.is_trusted(&m.id),
                        sub_components: m
                            .sub_components
                            .iter()
                            .map(|c| ComponentView {
                                id: c.id.clone(),
                                name: c.name.clone(),
                                description: c.description.clone(),
                                enabled: components.contains(&c.id),
                            })
                            .collect(),
                        tools: m
                            .tools
                            .iter()
                            .map(|t| ToolView {
                                id: t.id.clone(),
                                name: t.name.clone(),
                                description: t.description.clone(),
                                requires_admin: t.requires_admin,
                                read_only: t.read_only,
                                component: t.component.clone(),
                                available: t.component.as_ref().is_none_or(|c| components.contains(c)),
                                default_gate_policy: t.default_gate_policy,
                                effective_policy: registry::effective_policy(&m.id, t, &s.tool_gate_overrides),
                                mcp_name: registry::mcp_tool_name(&m.id, &t.id),
                                input_schema: t.input_schema.clone(),
                            })
                            .collect(),
                    }
                })
                .collect()
        })
    }

    /// Sets which plugins are installed and which of their components are on
    /// (plugin id → component ids), and marks the first-run wizard done.
    pub fn set_installed(&self, selection: BTreeMap<String, Vec<String>>) -> AegisResult<Vec<PluginView>> {
        for (plugin_id, components) in &selection {
            let plugin = self.registry.plugin(plugin_id).ok_or_else(|| AegisError::invalid(format!("unknown plugin '{plugin_id}'")))?;
            let known = plugin_component_ids(plugin.as_ref());
            if let Some(bad) = components.iter().find(|c| !known.contains(c)) {
                return Err(AegisError::invalid(format!("unknown component '{bad}' for plugin '{plugin_id}'")));
            }
        }
        let (old, new) = self.mutate(|s| {
            let old: BTreeMap<String, Vec<String>> = s.installed_plugins.iter().map(|id| (id.clone(), s.components_for(id))).collect();
            // Keep registry order so the UI and MCP list stay stable.
            s.installed_plugins =
                self.registry.plugins().iter().map(|p| p.manifest().id.clone()).filter(|id| selection.contains_key(id)).collect();
            s.installed_components = selection.clone();
            s.trusted_external_llm_plugins.retain(|id| selection.contains_key(id));
            s.first_run_completed = true;
            Ok((old, selection.clone()))
        })?;
        for plugin in self.registry.plugins() {
            let id = &plugin.manifest().id;
            let (before, after) = (old.get(id), new.get(id));
            if before == after {
                continue;
            }
            if before.is_some() {
                plugin.on_lock();
            }
            if let Some(components) = after {
                plugin.on_unlock(components);
            }
        }
        self.plugins()
    }

    /// Changes a tool's gate. Loosening a gate to `auto` needs the PIN.
    pub async fn set_gate_policy(&self, plugin_id: &str, tool_id: &str, policy: GatePolicy, pin: Option<String>) -> AegisResult<GatePolicy> {
        let (_, tool) = self.registry.tool(plugin_id, tool_id).ok_or_else(|| AegisError::new(ErrorCode::UnknownTool, format!("unknown tool {plugin_id}:{tool_id}")))?;
        let current = self.with_state(|s| registry::effective_policy(plugin_id, tool, &s.tool_gate_overrides))?;
        if current == GatePolicy::PinRequired && policy == GatePolicy::Auto {
            let pin = pin.ok_or_else(|| AegisError::new(ErrorCode::PinRequired, "Enter your PIN to let this tool run without approval."))?;
            self.check_pin(&pin).await?;
        }
        let key = registry::policy_key(plugin_id, tool_id);
        let default = tool.default_gate_policy;
        self.mutate(|s| {
            if policy == default {
                s.tool_gate_overrides.remove(&key);
            } else {
                s.tool_gate_overrides.insert(key, policy);
            }
            Ok(policy)
        })
    }

    /// Lets a plugin send (scrubbed) diagnostics to an off-LAN LLM. Needs the PIN.
    pub async fn grant_llm_trust(&self, plugin_id: &str, pin: String) -> AegisResult<()> {
        let plugin = self.registry.plugin(plugin_id).ok_or_else(|| AegisError::invalid(format!("unknown plugin '{plugin_id}'")))?;
        if !plugin.manifest().uses_llm {
            return Err(AegisError::invalid(format!("plugin '{plugin_id}' does not use the LLM service")));
        }
        self.check_pin(&pin).await?;
        self.mutate(|s| {
            if !s.is_trusted(plugin_id) {
                s.trusted_external_llm_plugins.push(plugin_id.to_owned());
            }
            Ok(())
        })
    }

    pub fn revoke_llm_trust(&self, plugin_id: &str) -> AegisResult<()> {
        self.mutate(|s| {
            s.trusted_external_llm_plugins.retain(|p| p != plugin_id);
            Ok(())
        })
    }

    // ---- tools -----------------------------------------------------------

    /// Tools an MCP client may call: installed plugins, enabled components.
    pub fn exposed_tools(&self) -> AegisResult<Vec<ExposedTool>> {
        self.with_state(|s| {
            let mut out = Vec::new();
            for plugin in self.registry.plugins() {
                let m = plugin.manifest();
                if !s.is_installed(&m.id) {
                    continue;
                }
                let components = s.components_for(&m.id);
                for tool in &m.tools {
                    if tool.component.as_ref().is_none_or(|c| components.contains(c)) {
                        out.push(ExposedTool {
                            plugin_id: m.id.clone(),
                            tool: tool.clone(),
                            policy: registry::effective_policy(&m.id, tool, &s.tool_gate_overrides),
                        });
                    }
                }
            }
            out
        })
    }

    fn prepare(&self, plugin_id: &str, tool_id: &str, args: Value) -> AegisResult<Prepared> {
        let (plugin, tool) = self
            .registry
            .tool(plugin_id, tool_id)
            .ok_or_else(|| AegisError::new(ErrorCode::UnknownTool, format!("unknown tool {plugin_id}:{tool_id}")))?;
        let guard = lock(&self.vault);
        let state = &guard.as_ref().ok_or_else(locked)?.state;
        if !state.is_installed(plugin_id) {
            return Err(AegisError::new(ErrorCode::PluginDisabled, format!("{} is not installed. Turn it on in Settings.", plugin.manifest().name)));
        }
        let components = state.components_for(plugin_id);
        if let Some(component) = &tool.component {
            if !components.contains(component) {
                return Err(AegisError::new(ErrorCode::ComponentDisabled, format!("{} needs the '{component}' component, which is turned off.", tool.name)));
            }
        }
        let args = schema::validate(&tool.input_schema, args).map_err(AegisError::invalid)?;
        let policy = registry::effective_policy(plugin_id, tool, &state.tool_gate_overrides);
        let gate = registry::gate(tool, policy, &args, self.elevated);
        let llm = plugin
            .manifest()
            .uses_llm
            .then(|| LlmHandle::new(self.http.clone(), state.llm.clone(), plugin_id, state.is_trusted(plugin_id)));
        Ok(Prepared {
            plugin: plugin.clone(),
            tool: tool.clone(),
            args,
            gate,
            ctx: ToolContext { elevated: self.elevated, enabled_components: components, llm },
        })
    }

    pub async fn run_tool(&self, origin: Origin, plugin_id: &str, tool_id: &str, args: Value) -> AegisResult<RunOutcome> {
        let prepared = self.prepare(plugin_id, tool_id, args)?;
        match prepared.gate {
            Gate::NeedsAdmin => Err(AegisError::requires_admin(&prepared.tool.name)),
            Gate::Run => execute(prepared).await,
            Gate::NeedsPin => match origin {
                Origin::Ui { pin: None } => {
                    Err(AegisError::new(ErrorCode::PinRequired, format!("Enter your PIN to run {}.", prepared.tool.name)))
                }
                Origin::Ui { pin: Some(pin) } => {
                    let pin = Zeroizing::new(pin);
                    self.check_pin(&pin).await?;
                    execute(prepared).await
                }
                Origin::Mcp => {
                    let ticket = lock(&self.tickets).create(
                        NewTicket {
                            plugin_id: plugin_id.to_owned(),
                            tool_id: prepared.tool.id.clone(),
                            tool_name: prepared.tool.name.clone(),
                            tool_description: prepared.tool.description.clone(),
                            requires_admin: prepared.tool.requires_admin,
                            args: prepared.args,
                        },
                        Instant::now(),
                    );
                    Ok(RunOutcome::PendingApproval { ticket: Box::new(ticket) })
                }
            },
        }
    }

    // ---- approval tickets ------------------------------------------------

    pub fn list_tickets(&self) -> Vec<TicketView> {
        lock(&self.tickets).list(Instant::now())
    }

    pub fn ticket(&self, id: &str) -> Option<TicketView> {
        lock(&self.tickets).get(id, Instant::now()).map(|t| t.view())
    }

    /// Constant-time check of a ticket's CSRF token (browser approval portal).
    pub fn ticket_csrf_matches(&self, id: &str, candidate: &str) -> bool {
        lock(&self.tickets).get(id, Instant::now()).is_some_and(|t| bool::from(t.csrf.as_bytes().ct_eq(candidate.as_bytes())))
    }

    /// The CSRF token for the portal form. Never sent to agents.
    pub fn ticket_csrf(&self, id: &str) -> Option<String> {
        lock(&self.tickets).get(id, Instant::now()).map(|t| t.csrf.clone())
    }

    /// Approves or declines a pending ticket. Both need the PIN, so an agent
    /// cannot decline-spam or probe PINs. Three wrong PINs lock the ticket;
    /// every wrong PIN also counts toward the global guard.
    pub async fn decide_ticket(
        &self,
        id: &str,
        approve: bool,
        pin: String,
        comment: Option<String>,
        via: &'static str,
    ) -> AegisResult<TicketView> {
        let pin = Zeroizing::new(pin);
        self.pending_ticket(id)?;
        let verified = {
            let _serial = self.pin_check.lock().await;
            self.pending_ticket(id)?;
            self.verify_pin_serialized(&pin).await
        };
        let mut store = lock(&self.tickets);
        let ticket = store.get_mut(id, Instant::now()).ok_or_else(ticket_not_found)?;
        if ticket.status != TicketStatus::PendingApproval {
            return Err(ticket_conflict(ticket.status));
        }
        match verified {
            Ok(()) => {}
            Err(e) if e.code == ErrorCode::PinInvalid => {
                ticket.strikes += 1;
                let left = STRIKES_PER_TICKET.saturating_sub(ticket.strikes);
                if left == 0 {
                    ticket.status = TicketStatus::LockedOut;
                    ticket.decided_via = Some(via);
                    return Err(AegisError::new(ErrorCode::PinLockedOut, "Too many wrong PINs for this request, so it was locked. The agent has to ask again."));
                }
                return Err(AegisError::new(ErrorCode::PinInvalid, format!("Incorrect PIN. {left} attempt(s) left for this request.")));
            }
            Err(e) => return Err(e),
        }
        ticket.comment = comment.map(|c| c.trim().chars().take(MAX_COMMENT_CHARS).collect::<String>()).filter(|c| !c.is_empty());
        ticket.decided_via = Some(via);
        if !approve {
            ticket.status = TicketStatus::Declined;
            return Ok(ticket.view());
        }
        let (plugin_id, tool_id, args) = (ticket.plugin_id.clone(), ticket.tool_id.clone(), ticket.args.clone());
        drop(store);
        let engine = self.self_arc()?;

        // Re-check everything: the plugin may have been turned off since the ticket was opened.
        let prepared = self.prepare(&plugin_id, &tool_id, args).and_then(|p| match p.gate {
            Gate::NeedsAdmin => Err(AegisError::requires_admin(&p.tool.name)),
            _ => Ok(p),
        });
        let mut store = lock(&self.tickets);
        let ticket = store.get_mut(id, Instant::now()).ok_or_else(ticket_not_found)?;
        match prepared {
            Err(e) => {
                ticket.status = TicketStatus::ExecutionFailed;
                ticket.error = Some(e);
                Ok(ticket.view())
            }
            Ok(prepared) => {
                ticket.status = TicketStatus::Running;
                let view = ticket.view();
                drop(store);
                let id = id.to_owned();
                tokio::spawn(async move {
                    let result = prepared.plugin.call(&prepared.tool.id, prepared.args, prepared.ctx).await;
                    let mut store = lock(&engine.tickets);
                    if let Some(ticket) = store.get_mut(&id, Instant::now()) {
                        match result {
                            Ok(value) => {
                                ticket.status = TicketStatus::Approved;
                                ticket.result = Some(value);
                            }
                            Err(e) => {
                                ticket.status = TicketStatus::ExecutionFailed;
                                ticket.error = Some(e);
                            }
                        }
                    }
                });
                Ok(view)
            }
        }
    }

    fn pending_ticket(&self, id: &str) -> AegisResult<()> {
        let mut store = lock(&self.tickets);
        let ticket = store.get(id, Instant::now()).ok_or_else(ticket_not_found)?;
        if ticket.status != TicketStatus::PendingApproval {
            return Err(ticket_conflict(ticket.status));
        }
        Ok(())
    }

    // ---- MCP server ------------------------------------------------------

    /// Constant-time check of the MCP bearer token against the vault.
    pub fn mcp_token_matches(&self, candidate: &str) -> bool {
        self.with_state(|s| bool::from(s.mcp.auth_token.expose().as_bytes().ct_eq(candidate.as_bytes()))).unwrap_or(false)
    }

    pub async fn start_mcp(&self) -> AegisResult<McpStatus> {
        self.mutate(|s| {
            s.mcp.enabled = true;
            Ok(())
        })?;
        self.start_mcp_inner().await
    }

    async fn start_mcp_inner(&self) -> AegisResult<McpStatus> {
        let config = self.with_state(|s| s.mcp.clone())?;
        let host = validate_mcp_host(&config.host)?;
        let mut slot = self.mcp.lock().await;
        if let Some(old) = slot.take() {
            old.stop().await;
        }
        let engine = self.self_arc()?;
        let handle = mcp::start(engine, host, config.port, config.open_firewall, self.elevated).await?;
        let status = handle.status();
        *slot = Some(handle);
        Ok(status)
    }

    pub async fn stop_mcp(&self) -> McpStatus {
        if let Some(handle) = self.mcp.lock().await.take() {
            handle.stop().await;
        }
        McpStatus::stopped()
    }

    /// Stops the server and turns off auto-start.
    pub async fn disable_mcp(&self) -> AegisResult<McpStatus> {
        self.mutate(|s| {
            s.mcp.enabled = false;
            Ok(())
        })?;
        Ok(self.stop_mcp().await)
    }

    pub async fn mcp_status(&self) -> McpStatus {
        self.mcp.lock().await.as_ref().map_or_else(McpStatus::stopped, McpHandle::status)
    }

    /// Shows the bearer token in the UI so it can be pasted into an MCP client.
    /// The only secret that ever reaches the webview, and only after the PIN.
    pub async fn reveal_mcp_token(&self, pin: String) -> AegisResult<String> {
        let pin = Zeroizing::new(pin);
        self.check_pin(&pin).await?;
        self.with_state(|s| s.mcp.auth_token.expose().to_owned())
    }

    /// Issues a new bearer token; existing MCP clients stop working at once.
    pub fn rotate_mcp_token(&self) -> AegisResult<()> {
        self.mutate(|s| {
            s.mcp.auth_token = Secret::random_token();
            Ok(())
        })
    }

    fn self_arc(&self) -> AegisResult<Arc<Self>> {
        self.me.upgrade().ok_or_else(|| internal("engine is shutting down"))
    }
}

fn ticket_not_found() -> AegisError {
    AegisError::new(ErrorCode::NotFound, "No such approval request.")
}

fn ticket_conflict(status: TicketStatus) -> AegisError {
    let label = serde_json::to_value(status).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default();
    AegisError::new(ErrorCode::Conflict, format!("This request is no longer pending ({}).", label.replace('_', " ")))
}

async fn execute(prepared: Prepared) -> AegisResult<RunOutcome> {
    prepared.plugin.call(&prepared.tool.id, prepared.args, prepared.ctx).await.map(|result| RunOutcome::Completed { result })
}
