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
use crate::executor::{self, ChangeView, Executor, Place, Stop, QUEUE_TIMEOUT};
use crate::llm::{classify, classify_endpoint, Endpoint, LlmHandle};
use crate::mcp::{self, McpHandle, McpStatus};
use crate::plan::{self, PlanOrigin, PlanRequest, MAX_PENDING_PLANS};
use crate::plugin_data::{PluginStore, MAX_PLUGIN_DATA_BYTES};
use crate::registry::{self, Gate, GatePolicy, Plugin, Registry, ToolContext, ToolManifest, UnlockContext};
use crate::schema;
use crate::secret::Secret;
use crate::state::{VaultState, AUTO_LOCK_CHOICES, DEFAULT_AUTO_LOCK_MINUTES};
use crate::tickets::{NewTicket, PlanMeta, PlanStep, StepStatus, TicketStatus, TicketStore, TicketView, STRIKES_PER_TICKET};
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
    /// Last owner activity, for idle auto-lock.
    activity: Mutex<Instant>,
    /// One state-changing run at a time.
    executor: Executor,
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
    /// The change running now and how many wait (for the app's top bar).
    pub change: ChangeView,
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
    pub auto_lock_minutes: u32,
    pub llm: LlmSettingsView,
    pub mcp: McpSettingsView,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettingsUpdate {
    pub ui_scale: Option<u32>,
    pub auto_lock_minutes: Option<u32>,
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
    /// Reached only from the app; agents never see it (PLUGIN_SPEC §2).
    pub app_only: bool,
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
            activity: Mutex::new(Instant::now()),
            executor: Executor::default(),
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

    /// Applies a change to the vault state and saves it. If the change is
    /// rejected part-way or the save fails, the in-memory state is rolled
    /// back, so a rejected change never reaches disk with a later save.
    fn mutate<R>(&self, f: impl FnOnce(&mut VaultState) -> AegisResult<R>) -> AegisResult<R> {
        let mut guard = lock(&self.vault);
        let vault = guard.as_mut().ok_or_else(locked)?;
        let before = vault.state.clone();
        let out = match f(&mut vault.state) {
            Ok(out) => out,
            Err(e) => {
                vault.state = before;
                return Err(e);
            }
        };
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
            change: self.executor.view(),
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
        self.note_activity();
        let mcp_enabled = vault.state.mcp.enabled;
        let installed: Vec<(String, Vec<String>)> =
            vault.state.installed_plugins.iter().map(|id| (id.clone(), vault.state.components_for(id))).collect();
        *lock(&self.vault) = Some(vault);
        for (id, components) in installed {
            if let Some(plugin) = self.registry.plugin(&id) {
                plugin.on_unlock(&self.unlock_context(&id, components));
            }
        }
        if mcp_enabled {
            // A failure (port in use) is shown on the MCP tab; unlocking still succeeds.
            let _ = self.start_mcp_inner().await;
        }
    }

    /// Records that the owner is using AegisWin: input in the app window, or
    /// a correct PIN anywhere. Agent requests never count, and neither does
    /// loading the approval page, which an agent can do too.
    pub fn note_activity(&self) {
        *lock(&self.activity) = Instant::now();
    }

    pub fn last_activity(&self) -> Instant {
        *lock(&self.activity)
    }

    /// True while a change is running or waiting, or an installed plugin has
    /// background work (only while unlocked: locking stops it). Closing the
    /// window then hides to the tray, so a repair is not cut off.
    pub fn background_active(&self) -> bool {
        if self.executor.view() != ChangeView::default() {
            return true;
        }
        let installed = lock(&self.vault).as_ref().map(|v| v.state.installed_plugins.clone()).unwrap_or_default();
        installed.iter().filter_map(|id| self.registry.plugin(id)).any(|p| p.background_active())
    }

    /// Locks the vault when the owner has been away for the auto-lock
    /// timeout. Returns true when it locked. A change that is running then
    /// finishes first, and nothing new starts meanwhile, so a long queue cannot
    /// hold the vault open.
    pub async fn lock_if_idle(&self, now: Instant) -> bool {
        let Some(minutes) = lock(&self.vault).as_ref().map(|v| v.state.auto_lock_minutes) else {
            return false;
        };
        let minutes = if AUTO_LOCK_CHOICES.contains(&minutes) { minutes } else { DEFAULT_AUTO_LOCK_MINUTES };
        let due = now.saturating_duration_since(self.last_activity()) >= Duration::from_secs(u64::from(minutes) * 60);
        self.executor.hold(due);
        if !due || self.executor.running().is_some() {
            return false;
        }
        self.lock().await;
        true
    }

    /// The tool whose change is running now, if any.
    pub fn change_running(&self) -> Option<String> {
        self.executor.running()
    }

    /// Stops the MCP server and background work, drops the key, and forgets tickets.
    pub async fn lock(&self) -> Status {
        self.stop_mcp().await;
        let installed = lock(&self.vault).take().map(|v| v.state.installed_plugins.clone()).unwrap_or_default();
        // Waiting changes never resume after unlock; a running one finishes.
        self.executor.cancel_all();
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
            // A correct PIN, in the app or on the approval page, is the owner.
            self.note_activity();
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
            let (endpoint, endpoint_error) = match classify(&s.llm.base_url, &s.llm.model) {
                Ok(e) => (Some(e), None),
                Err(e) => (None, Some(e.message)),
            };
            SettingsView {
                ui_scale: s.ui_scale,
                auto_lock_minutes: s.auto_lock_minutes,
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
            if let Some(minutes) = update.auto_lock_minutes {
                if !AUTO_LOCK_CHOICES.contains(&minutes) {
                    return Err(AegisError::invalid("Auto-lock must be 5, 15, 30, or 60 minutes."));
                }
                s.auto_lock_minutes = minutes;
            }
            let destination = |llm: &crate::llm::LlmConfig| classify(&llm.base_url, &llm.model).ok().map(|e| (e.host, e.relayed));
            let before_destination = destination(&s.llm);
            if let Some(url) = &update.llm_base_url {
                let url = url.trim();
                let new = classify_endpoint(url)?;
                if !new.is_lan && !new.https {
                    return Err(AegisError::invalid("Off-LAN LLM endpoints must use https://."));
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
            // Trust is granted for a destination: a different host, or moving
            // between a local and an Ollama cloud model, needs a new grant.
            if destination(&s.llm) != before_destination {
                s.trusted_external_llm_plugins.clear();
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
        let endpoint = classify(&config.base_url, &config.model)?;
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
                                app_only: t.app_only,
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
                plugin.on_unlock(&self.unlock_context(id, components.clone()));
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

    // ---- plugin data -----------------------------------------------------

    fn store_for(&self, plugin_id: &str) -> PluginStore {
        PluginStore::new(self.me.clone(), plugin_id)
    }

    fn unlock_context(&self, plugin_id: &str, enabled_components: Vec<String>) -> UnlockContext {
        UnlockContext { enabled_components, store: Some(self.store_for(plugin_id)) }
    }

    fn require_installed(&self, s: &VaultState, plugin_id: &str) -> AegisResult<()> {
        if s.is_installed(plugin_id) && self.registry.plugin(plugin_id).is_some() {
            Ok(())
        } else {
            Err(AegisError::new(ErrorCode::PluginDisabled, format!("plugin '{plugin_id}' is not installed")))
        }
    }

    pub(crate) fn plugin_data_get(&self, plugin_id: &str, key: &str) -> AegisResult<Option<Value>> {
        self.with_state(|s| {
            self.require_installed(s, plugin_id)?;
            Ok(s.plugin_data.get(plugin_id).and_then(|records| records.get(key)).cloned())
        })?
    }

    /// `None` removes the key. A write that would take the plugin over its
    /// size limit is refused and nothing changes.
    pub(crate) fn plugin_data_set(&self, plugin_id: &str, key: &str, value: Option<Value>) -> AegisResult<()> {
        self.mutate(|s| {
            self.require_installed(s, plugin_id)?;
            let records = s.plugin_data.entry(plugin_id.to_owned()).or_default();
            match value {
                Some(v) => {
                    records.insert(key.to_owned(), v);
                }
                None => {
                    records.remove(key);
                }
            }
            let size = serde_json::to_vec(&*records).map_err(internal)?.len();
            if records.is_empty() {
                s.plugin_data.remove(plugin_id);
            }
            if size > MAX_PLUGIN_DATA_BYTES {
                return Err(AegisError::invalid(format!("plugin data for '{plugin_id}' would exceed {} KiB", MAX_PLUGIN_DATA_BYTES / 1024)));
            }
            Ok(())
        })
    }

    pub(crate) fn plugin_data_clear(&self, plugin_id: &str) -> AegisResult<()> {
        self.mutate(|s| {
            self.require_installed(s, plugin_id)?;
            s.plugin_data.remove(plugin_id);
            Ok(())
        })
    }

    // ---- tools -----------------------------------------------------------

    /// Tools an MCP client may call: installed plugins, enabled components,
    /// never `appOnly` tools.
    pub fn exposed_tools(&self) -> AegisResult<Vec<ExposedTool>> {
        self.with_state(|s| {
            let mut out = Vec::new();
            for plugin in self.registry.plugins() {
                let m = plugin.manifest();
                if !s.is_installed(&m.id) {
                    continue;
                }
                let components = s.components_for(&m.id);
                for tool in m.tools.iter().filter(|t| !t.app_only) {
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
            ctx: ToolContext { elevated: self.elevated, enabled_components: components, llm, store: Some(self.store_for(plugin_id)) },
        })
    }

    pub async fn run_tool(&self, origin: Origin, plugin_id: &str, tool_id: &str, args: Value) -> AegisResult<RunOutcome> {
        // Read before the vault is checked, so a change cannot slip into the queue across a lock.
        let epoch = self.executor.epoch();
        // Checked before anything else, so an agent learns nothing about an app-only tool.
        if matches!(origin, Origin::Mcp) && self.registry.tool(plugin_id, tool_id).is_some_and(|(_, t)| t.app_only) {
            return Err(AegisError::new(ErrorCode::UnknownTool, format!("unknown tool {plugin_id}:{tool_id}")));
        }
        let prepared = self.prepare(plugin_id, tool_id, args)?;
        match prepared.gate {
            Gate::NeedsAdmin => Err(AegisError::requires_admin(&prepared.tool.name)),
            Gate::Run => self.run_in_turn(epoch, prepared).await,
            Gate::NeedsPin => match origin {
                Origin::Ui { pin: None } => {
                    Err(AegisError::new(ErrorCode::PinRequired, format!("Enter your PIN to run {}.", prepared.tool.name)))
                }
                Origin::Ui { pin: Some(pin) } => {
                    let pin = Zeroizing::new(pin);
                    self.check_pin(&pin).await?;
                    self.run_in_turn(epoch, prepared).await
                }
                Origin::Mcp => {
                    let review = prepared.plugin.review_call(&prepared.tool.id, &prepared.args, &prepared.ctx.enabled_components);
                    let ticket = lock(&self.tickets).create(
                        NewTicket {
                            plugin_id: plugin_id.to_owned(),
                            tool_id: prepared.tool.id.clone(),
                            tool_name: prepared.tool.name.clone(),
                            tool_description: prepared.tool.description.clone(),
                            requires_admin: prepared.tool.requires_admin,
                            args: prepared.args,
                            review,
                            plan: None,
                            steps: Vec::new(),
                        },
                        Instant::now(),
                    );
                    Ok(RunOutcome::PendingApproval { ticket: Box::new(ticket) })
                }
            },
        }
    }

    /// Runs a call now if it cannot change the system, otherwise in its turn.
    async fn run_in_turn(&self, epoch: u64, prepared: Prepared) -> AegisResult<RunOutcome> {
        if !changes_system(&prepared.tool, &prepared.args) {
            return execute(prepared).await;
        }
        let engine = self.self_arc()?;
        let place = self.executor.enqueue(epoch, &prepared.tool.name, None).map_err(queue_error)?;
        // On its own task, so a caller that goes away cannot cut a change off halfway.
        tokio::spawn(async move {
            let _turn = engine.executor.turn(place, Instant::now() + QUEUE_TIMEOUT).await.map_err(stop_error)?;
            execute(engine.recheck(&prepared)?).await
        })
        .await
        .map_err(internal)?
    }

    /// Checked again when an item leaves the queue: the plugin may have been
    /// turned off, or the vault locked, while it waited.
    fn recheck(&self, prepared: &Prepared) -> AegisResult<Prepared> {
        let fresh = self.prepare(&prepared.plugin.manifest().id, &prepared.tool.id, prepared.args.clone())?;
        if fresh.gate == Gate::NeedsAdmin {
            return Err(AegisError::requires_admin(&fresh.tool.name));
        }
        Ok(fresh)
    }

    // ---- approval tickets ------------------------------------------------

    fn with_position(&self, mut view: TicketView) -> TicketView {
        if view.status == TicketStatus::Queued {
            view.queue_position = self.executor.position(&view.ticket_id);
        }
        view
    }

    pub fn list_tickets(&self) -> Vec<TicketView> {
        let views = lock(&self.tickets).list(Instant::now());
        views.into_iter().map(|v| self.with_position(v)).collect()
    }

    pub fn ticket(&self, id: &str) -> Option<TicketView> {
        let view = lock(&self.tickets).get(id, Instant::now()).map(|t| t.view());
        view.map(|v| self.with_position(v))
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
        self.decide(id, approve, pin, comment, via, None).await
    }

    /// Like [`Self::decide_ticket`]; approving a plan must also name its hash,
    /// so the decision is bound to the plan that was shown.
    pub async fn decide(
        &self,
        id: &str,
        approve: bool,
        pin: String,
        comment: Option<String>,
        via: &'static str,
        plan_hash: Option<&str>,
    ) -> AegisResult<TicketView> {
        let pin = Zeroizing::new(pin);
        let epoch = self.executor.epoch();
        self.pending_ticket(id)?;
        // Checked before the PIN, so a stale page does not cost an attempt.
        if approve {
            let expected = lock(&self.tickets).get(id, Instant::now()).and_then(|t| t.plan.as_ref().map(|p| p.hash.clone()));
            if let Some(expected) = expected {
                let matches = plan_hash.is_some_and(|h| bool::from(h.as_bytes().ct_eq(expected.as_bytes())));
                if !matches {
                    return Err(AegisError::new(ErrorCode::Conflict, "This approval does not match the plan's fingerprint. Reload the request and check its steps again."));
                }
            }
        }
        // A full queue is refused before the PIN is checked; the request stays pending.
        if approve && self.ticket_changes_system(id) && !self.executor.has_room() {
            return Err(queue_error(executor::Full::Full));
        }
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
        let comment = comment.map(|c| c.trim().chars().take(MAX_COMMENT_CHARS).collect::<String>()).filter(|c| !c.is_empty());
        if !approve {
            ticket.comment = comment;
            ticket.decided_via = Some(via);
            ticket.status = TicketStatus::Declined;
            return Ok(ticket.view());
        }
        let calls: Vec<(String, String, Value)> = if ticket.plan.is_some() {
            ticket.steps.iter().map(|s| (s.plugin_id.clone(), s.tool_id.clone(), s.args.clone())).collect()
        } else {
            vec![(ticket.plugin_id.clone(), ticket.tool_id.clone(), ticket.args.clone())]
        };
        let is_plan = ticket.plan.is_some();
        let label = ticket.tool_name.clone();
        drop(store);
        let engine = self.self_arc()?;

        // Re-check everything: the plugin may have been turned off since the ticket was opened.
        let prepared: AegisResult<Vec<Prepared>> = calls
            .into_iter()
            .map(|(plugin_id, tool_id, args)| {
                self.prepare(&plugin_id, &tool_id, args).and_then(|p| match p.gate {
                    Gate::NeedsAdmin => Err(AegisError::requires_admin(&p.tool.name)),
                    _ => Ok(p),
                })
            })
            .collect();
        // Taken before the ticket changes, so a full queue leaves it pending.
        let place = match &prepared {
            Ok(p) if is_plan || changes_system(&p[0].tool, &p[0].args) => Some(self.executor.enqueue(epoch, &label, Some(id)).map_err(queue_error)?),
            _ => None,
        };
        let mut store = lock(&self.tickets);
        let Some(ticket) = store.get_mut(id, Instant::now()) else {
            drop(store);
            if let Some(place) = place {
                // Gone meanwhile (locked): give the place back.
                self.executor.withdraw(place);
            }
            return Err(ticket_not_found());
        };
        // Decided or cancelled meanwhile by another call: only one decision counts.
        if ticket.status != TicketStatus::PendingApproval {
            let status = ticket.status;
            drop(store);
            if let Some(place) = place {
                self.executor.withdraw(place);
            }
            return Err(ticket_conflict(status));
        }
        ticket.comment = comment;
        ticket.decided_via = Some(via);
        match prepared {
            Err(e) => {
                if let Some(plan) = &mut ticket.plan {
                    plan.stop_reason = Some(format!("Nothing ran: {}", e.message));
                    for step in &mut ticket.steps {
                        step.status = StepStatus::Cancelled;
                    }
                }
                ticket.status = TicketStatus::ExecutionFailed;
                ticket.error = Some(e);
                Ok(ticket.view())
            }
            Ok(prepared) => {
                // Shown as queued only when something is ahead of it.
                let waits = place.is_some_and(|p| !self.executor.is_next(p));
                ticket.status = if waits { TicketStatus::Queued } else { TicketStatus::Running };
                let view = ticket.view();
                drop(store);
                let id = id.to_owned();
                tokio::spawn(async move { engine.run_ticket(&id, place, prepared).await });
                Ok(self.with_position(view))
            }
        }
    }

    /// Runs an approved ticket, in its turn when it changes the system.
    async fn run_ticket(&self, id: &str, place: Option<Place>, mut steps: Vec<Prepared>) {
        let finish = |result: AegisResult<Value>, failed: TicketStatus| {
            if let Some(ticket) = lock(&self.tickets).get_mut(id, Instant::now()) {
                // Cancelled while it waited: leave it so.
                if ticket.status.is_final() {
                    return;
                }
                if let (Some(plan), Err(e)) = (&mut ticket.plan, &result) {
                    plan.stop_reason = Some(e.message.clone());
                    for step in &mut ticket.steps {
                        step.status = StepStatus::Cancelled;
                    }
                }
                match result {
                    Ok(value) => {
                        ticket.status = TicketStatus::Approved;
                        ticket.result = Some(value);
                    }
                    Err(e) => {
                        ticket.status = failed;
                        ticket.error = Some(e);
                    }
                }
            }
        };
        let failed = TicketStatus::ExecutionFailed;
        let _turn = match place {
            None => None,
            Some(place) => match self.executor.turn(place, Instant::now() + QUEUE_TIMEOUT).await {
                Ok(turn) => Some(turn),
                Err(stop) => {
                    let status = if stop == Stop::Expired { TicketStatus::Expired } else { failed };
                    return finish(Err(stop_error(stop)), status);
                }
            },
        };
        let is_plan = match lock(&self.tickets).get_mut(id, Instant::now()) {
            // Locked, or cancelled just as its turn came.
            None => return,
            Some(ticket) if ticket.status.is_final() => return,
            Some(ticket) => ticket.plan.is_some(),
        };
        if is_plan {
            return self.run_plan(id, steps).await;
        }
        let Some(prepared) = steps.pop() else { return };
        let prepared = if place.is_some() {
            match self.recheck(&prepared) {
                Ok(p) => p,
                Err(e) => return finish(Err(e), failed),
            }
        } else {
            prepared
        };
        if let Some(ticket) = lock(&self.tickets).get_mut(id, Instant::now()) {
            ticket.status = TicketStatus::Running;
        }
        finish(prepared.plugin.call(&prepared.tool.id, prepared.args, prepared.ctx).await, failed);
    }

    /// Runs a plan's steps in order while holding the one slot. Before each
    /// step it stops if the plan was cancelled, AegisWin locked, or idle
    /// auto-lock is waiting, and it checks the step again. The first failure
    /// ends the plan; later steps are skipped and earlier changes stay.
    async fn run_plan(&self, id: &str, steps: Vec<Prepared>) {
        // Applies `f` to the ticket; false when it is gone (AegisWin locked).
        let update = |f: &mut dyn FnMut(&mut crate::tickets::Ticket)| -> bool {
            match lock(&self.tickets).get_mut(id, Instant::now()) {
                Some(ticket) => {
                    f(ticket);
                    true
                }
                None => false,
            }
        };
        let end = |status: TicketStatus, reason: String, from: usize, rest: StepStatus| {
            update(&mut |t| {
                t.status = status;
                for step in t.steps.iter_mut().skip(from) {
                    step.status = rest;
                }
                if let Some(plan) = &mut t.plan {
                    plan.stop_reason = Some(reason.clone());
                }
            });
        };
        for (i, step) in steps.iter().enumerate() {
            let n = i + 1;
            let mut cancelled = false;
            if !update(&mut |t| cancelled = t.cancel_requested || t.status.is_final()) {
                return;
            }
            if cancelled {
                return end(TicketStatus::Cancelled, format!("Cancelled before step {n}."), i, StepStatus::Cancelled);
            }
            if self.executor.held() {
                return end(TicketStatus::Cancelled, format!("AegisWin is locking after inactivity, so step {n} did not start."), i, StepStatus::Cancelled);
            }
            let fresh = match self.recheck(step) {
                Ok(p) => p,
                Err(e) => {
                    let reason = format!("Step {n} could not start: {}", e.message);
                    update(&mut |t| {
                        t.steps[i].status = StepStatus::Failed;
                        t.steps[i].error = Some(e.clone());
                        t.error = Some(AegisError { message: reason.clone(), ..e.clone() });
                    });
                    return end(TicketStatus::ExecutionFailed, reason, n, StepStatus::Skipped);
                }
            };
            update(&mut |t| {
                t.status = TicketStatus::Running;
                t.steps[i].status = StepStatus::Running;
            });
            let (output, outcome) = match fresh.plugin.call(&fresh.tool.id, fresh.args, fresh.ctx).await {
                // A tool that ran but reports `"success": false` failed too; its output is kept.
                Ok(value) if value.get("success") == Some(&Value::Bool(false)) => {
                    (Some(value), Err(AegisError::new(ErrorCode::ExecutionFailed, format!("{} reported that it did not succeed.", fresh.tool.name))))
                }
                Ok(value) => (Some(value), Ok(())),
                Err(e) => (None, Err(e)),
            };
            let failed = outcome.as_ref().err().cloned();
            update(&mut |t| {
                t.steps[i].result = output.clone();
                t.steps[i].status = if failed.is_some() { StepStatus::Failed } else { StepStatus::Succeeded };
                if let Some(e) = &failed {
                    t.steps[i].error = Some(e.clone());
                    t.error = Some(AegisError { message: format!("Step {n} failed: {}", e.message), ..e.clone() });
                }
            });
            if let Some(e) = failed {
                return end(TicketStatus::ExecutionFailed, format!("Step {n} failed: {}", e.message), n, StepStatus::Skipped);
            }
        }
        update(&mut |t| t.status = TicketStatus::Approved);
    }

    /// Withdraws a pending or waiting request, or stops a running plan before
    /// its next step. Needs no PIN: it can only make less happen. A running
    /// single action is not stopped, since killing a repair mid-run is unsafe.
    pub fn cancel_ticket(&self, id: &str) -> AegisResult<TicketView> {
        let mut store = lock(&self.tickets);
        let ticket = store.get_mut(id, Instant::now()).ok_or_else(ticket_not_found)?;
        match ticket.status {
            TicketStatus::PendingApproval | TicketStatus::Queued => {
                let queued = ticket.status == TicketStatus::Queued;
                ticket.status = TicketStatus::Cancelled;
                for step in &mut ticket.steps {
                    step.status = StepStatus::Cancelled;
                }
                if let Some(plan) = &mut ticket.plan {
                    plan.stop_reason = Some(if queued { "Cancelled while it waited its turn." } else { "Withdrawn before a decision." }.into());
                }
                let view = ticket.view();
                drop(store);
                if queued {
                    self.executor.withdraw_ticket(id);
                }
                Ok(view)
            }
            TicketStatus::Running if ticket.plan.is_some() => {
                ticket.cancel_requested = true;
                Ok(ticket.view())
            }
            TicketStatus::Running => Err(AegisError::new(ErrorCode::Conflict, "This action is already running, and stopping a repair halfway is unsafe. It will finish on its own.")),
            status => Err(ticket_conflict(status)),
        }
    }

    // ---- action plans ----------------------------------------------------

    /// Opens a plan ticket: every step is an opted-in tool, checked, filled
    /// in, and dry-run now, so the review shows the exact commands. Nothing
    /// runs until the owner approves with the PIN.
    pub async fn propose_plan(&self, origin: PlanOrigin, request: Value) -> AegisResult<TicketView> {
        let request = PlanRequest::parse(request).map_err(AegisError::invalid)?;
        let at = |n: usize, e: AegisError| AegisError { message: format!("Step {n}: {}", e.message), ..e };
        let unknown = |n: usize, name: &str| AegisError::new(ErrorCode::UnknownTool, format!("Step {n}: unknown tool {name}"));
        let mut steps = Vec::with_capacity(request.steps.len());
        for (i, step) in request.steps.iter().enumerate() {
            let n = i + 1;
            let (plugin_id, tool_id) = registry::parse_mcp_tool_name(&step.tool).ok_or_else(|| unknown(n, &step.tool))?;
            let (_, tool) = self.registry.tool(plugin_id, tool_id).ok_or_else(|| unknown(n, &step.tool))?;
            if tool.app_only && origin == PlanOrigin::Agent {
                return Err(unknown(n, &step.tool));
            }
            if !tool.plan_eligible {
                return Err(AegisError::invalid(format!("Step {n}: {} cannot be a plan step. Plans can only use repairs that allow it.", tool.name)));
            }
            let prepared = self.prepare(plugin_id, tool_id, step.args.clone()).map_err(|e| at(n, e))?;
            if prepared.gate == Gate::NeedsAdmin {
                return Err(AegisError::new(
                    ErrorCode::RequiresAdmin,
                    format!("Step {n}: {} needs administrator rights. Restart AegisWin as administrator first: restarting later locks AegisWin and would throw the plan away.", tool.name),
                ));
            }
            steps.push((step, prepared));
        }
        for (i, (_, a)) in steps.iter().enumerate() {
            for (j, (_, b)) in steps.iter().enumerate().skip(i + 1) {
                if a.tool.id == b.tool.id && a.plugin.manifest().id == b.plugin.manifest().id && a.args == b.args {
                    return Err(AegisError::invalid(format!("Steps {} and {} are the same; a plan runs each change once.", i + 1, j + 1)));
                }
            }
        }
        if lock(&self.tickets).pending_plans(Instant::now()) >= MAX_PENDING_PLANS {
            return Err(too_many_plans());
        }

        // Dry runs: the exact commands each step would run. One that fails rejects the plan.
        let mut shown = Vec::with_capacity(steps.len());
        for (i, (step, p)) in steps.iter().enumerate() {
            let mut args = p.args.clone();
            args["dryRun"] = Value::Bool(true);
            let preview = p.plugin.call(&p.tool.id, args, p.ctx.clone()).await.map_err(|e| at(i + 1, AegisError { message: format!("its dry run failed: {}", e.message), ..e }))?;
            let commands: Vec<String> = preview.get("commands").and_then(Value::as_array).map(|c| c.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect()).unwrap_or_default();
            shown.push(PlanStep {
                index: i + 1,
                tool: step.tool.clone(),
                plugin_id: p.plugin.manifest().id.clone(),
                tool_id: p.tool.id.clone(),
                tool_name: p.tool.name.clone(),
                tool_description: p.tool.description.clone(),
                requires_admin: p.tool.requires_admin,
                args: p.args.clone(),
                reasoning: step.reasoning.clone(),
                commands,
                status: StepStatus::Pending,
                result: None,
                error: None,
            });
        }

        let hashed: Vec<(String, Value, Option<String>)> = shown.iter().map(|s| (s.tool.clone(), s.args.clone(), s.reasoning.clone())).collect();
        let hash = plan::plan_hash(request.title.as_deref(), request.reasoning.as_deref(), &hashed);
        let known: Vec<(String, String, String)> = self
            .registry
            .plugins()
            .iter()
            .flat_map(|p| p.manifest().tools.iter().map(|t| (registry::mcp_tool_name(&p.manifest().id, &t.id), t.id.clone(), t.name.clone())).collect::<Vec<_>>())
            .collect();
        let in_plan: Vec<String> = shown.iter().map(|s| s.tool.clone()).collect();
        let texts: Vec<&str> = request.reasoning.iter().chain(request.title.iter()).chain(shown.iter().filter_map(|s| s.reasoning.as_ref())).map(String::as_str).collect();
        let admin_steps = shown.iter().filter(|s| s.requires_admin).count();
        let summary = plan::summary(shown.len(), admin_steps);
        let meta = PlanMeta {
            title: request.title.clone(),
            reasoning: request.reasoning.clone(),
            origin,
            supplied_label: origin.label(),
            short_hash: plan::short_hash(&hash).to_owned(),
            hash,
            summary: summary.clone(),
            flags: plan::consistency_flags(&texts, &known, &in_plan),
            expires_at: String::new(),
            stop_reason: None,
        };
        let mut store = lock(&self.tickets);
        if store.pending_plans(Instant::now()) >= MAX_PENDING_PLANS {
            return Err(too_many_plans());
        }
        Ok(store.create(
            NewTicket {
                plugin_id: "aegis".into(),
                tool_id: "plan".into(),
                tool_name: request.title.unwrap_or_else(|| "Action plan".into()),
                tool_description: summary,
                requires_admin: admin_steps > 0,
                args: Value::Null,
                review: None,
                plan: Some(meta),
                steps: shown,
            },
            Instant::now(),
        ))
    }

    fn ticket_changes_system(&self, id: &str) -> bool {
        let Some((plugin_id, tool_id, args, is_plan)) =
            lock(&self.tickets).get(id, Instant::now()).map(|t| (t.plugin_id.clone(), t.tool_id.clone(), t.args.clone(), t.plan.is_some()))
        else {
            return false;
        };
        if is_plan {
            return true;
        }
        self.registry.tool(&plugin_id, &tool_id).is_some_and(|(_, tool)| changes_system(tool, &args))
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

/// Every run that can change Windows or AegisWin goes through the executor.
/// Read-only tools and dry runs never wait.
fn changes_system(tool: &ToolManifest, args: &Value) -> bool {
    !tool.read_only && args.get("dryRun") != Some(&Value::Bool(true))
}

fn queue_error(e: executor::Full) -> AegisError {
    match e {
        executor::Full::Full => AegisError::new(
            ErrorCode::Conflict,
            format!("{} changes are already waiting to run. Try again when one has finished.", executor::MAX_QUEUED),
        ),
        executor::Full::Locked => locked(),
    }
}

fn stop_error(stop: Stop) -> AegisError {
    match stop {
        Stop::Locked => AegisError::new(ErrorCode::VaultLocked, "AegisWin locked before this change could start, so it was cancelled."),
        Stop::Expired => AegisError::new(ErrorCode::ExecutionFailed, "This change waited more than 30 minutes behind others, so it was cancelled. Ask again if it is still needed."),
    }
}

fn too_many_plans() -> AegisError {
    AegisError::new(ErrorCode::Conflict, format!("{MAX_PENDING_PLANS} plans are already waiting for a decision. Wait for those to be decided or to expire."))
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
