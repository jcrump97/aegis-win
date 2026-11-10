//! The engine owns the vault, the plugin registry, the PIN guard, approval
//! tickets and the MCP server. Tauri commands and the MCP server both call
//! into it, so every gate is enforced in exactly one place.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::chain::{self, Head, MacCheck, Session};
use crate::error::{AegisError, AegisResult, ErrorCode};
use crate::executor::{self, ChangeView, Executor, Place, Stop, QUEUE_TIMEOUT};
use crate::history::{self, Retention, StreamKey, StreamRead};
use crate::history_service::{self, Append, AppendError, ChangeWindow, HistoryHandle, HistoryService, RuntimeFile, RuntimeReview, APPROVALS_STREAM, MAX_RUNTIME_BYTES, RUNTIME_VERSION};
use crate::llm::{classify, classify_endpoint, Endpoint, LlmHandle};
use crate::mcp::{self, McpHandle, McpStatus};
use crate::plan::{self, PlanOrigin, PlanRequest, MAX_PENDING_PLANS};
use crate::plugin_data::{PluginStore, MAX_PLUGIN_DATA_BYTES};
use crate::registry::{self, ExitReason, Gate, GatePolicy, Launch, LockedContext, Plugin, Registry, ResumeNotice, ToolContext, ToolManifest, UnlockContext};
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
    /// Encrypted history streams (public keys and open files only).
    history: HistoryService,
    /// Runtime files that did not match the vault, until the owner rewrites them.
    runtime_reviews: Mutex<BTreeMap<String, RuntimeReview>>,
    /// Plugins that kept running when the vault locked (*locked, monitoring*).
    locked_work: Mutex<BTreeSet<String>>,
    /// Shown after unlock until dismissed: monitoring was not running before
    /// this launch. App only.
    resume_notices: Mutex<BTreeMap<String, ResumeNotice>>,
    /// Monitoring paused from the tray (no PIN).
    paused: AtomicBool,
    /// "Approve from another device" (ADR 0004 §1.2). Memory only: off at
    /// every start and every lock, so it never turns on by itself.
    device_approval: AtomicBool,
    /// Wrong device codes in the last hour, across all tickets.
    device_misses: Mutex<VecDeque<Instant>>,
    /// Device approval was turned off by too many wrong codes.
    device_tripped: AtomicBool,
    /// When agents last asked for approval, newest last (ADR 0004 §1.3).
    agent_requests: Mutex<VecDeque<Instant>>,
    /// Approval record events that could not be written yet, oldest first.
    /// Written before the next record (ADR 0004 §4.6).
    unwritten: Mutex<Vec<Value>>,
    /// Size at which the approval record refuses new agent requests (§4.5).
    record_full_bytes: AtomicU64,
    /// Size past which no approval record event is written.
    record_hard_bytes: AtomicU64,
    /// Held events dropped because too many were waiting; noted in the record once it can be written.
    unwritten_lost: AtomicU64,
}

/// The approval record refuses new agent requests at this size (ADR 0004 §4.5).
pub const APPROVAL_RECORD_FULL_BYTES: u64 = 256 * 1024 * 1024;
/// Past this, no approval record event is written at all, so a flood can
/// never fill the disk; what fails then follows ADR 0004 §4.6.
const APPROVAL_RECORD_HEADROOM: u64 = 16 * 1024 * 1024;
/// Unwritten events held in memory at most; the oldest go first.
const MAX_UNWRITTEN: usize = 1000;
/// What an agent sees when the approval record is full.
pub const RECORD_FULL: &str = "The approval record is full. Open AegisWin.";

/// Agent requests that may wait for the owner at once (plans included).
pub const MAX_AGENT_PENDING: usize = 10;
/// Agent requests for approval allowed per hour, refused ones included.
pub const AGENT_REQUESTS_PER_HOUR: usize = 30;

/// Wrong device codes allowed in an hour before device approval turns off.
pub const DEVICE_MISSES_PER_HOUR: usize = 10;

/// A device code as the app shows it, once.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceCodeView {
    /// `K7QM-4XRT`.
    pub code: String,
    pub expires_at: String,
    /// The device page; also drawn as `qr`.
    pub url: String,
    pub qr: crate::qr::QrView,
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
    /// Runtime files set aside at unlock, waiting for the owner (empty while locked).
    pub runtime_reviews: Vec<RuntimeReview>,
    /// Gaps before a resume at launch, by plugin. Empty while locked.
    pub resume_notices: Vec<ResumeNoticeView>,
    /// The vault key is a short PIN from before passphrases (ADR 0004 §3.2):
    /// the app asks the owner to choose (decision D2). False while locked.
    pub needs_passphrase: bool,
    /// A short PIN on this PC can unlock (ADR 0004 §3.3). Known while locked.
    pub this_pc_pin: bool,
    /// The approval record reached its size limit, so agent requests are
    /// refused (ADR 0004 §4.5). False while locked.
    pub approval_record_full: bool,
    /// Approval record events that could not be written yet (§4.6). They
    /// are written before the next event.
    pub unwritten_records: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResumeNoticeView {
    pub plugin_id: String,
    #[serde(flatten)]
    pub notice: ResumeNotice,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LlmSettingsView {
    pub base_url: String,
    pub model: String,
    pub has_api_key: bool,
    pub context_tokens: u32,
    pub first_token_secs: u32,
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
    /// Approve from another device, with a one-time code (memory only).
    pub device_approval: bool,
    /// Why device approval was turned off, when too many wrong codes did it.
    pub device_approval_notice: Option<String>,
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
    pub llm_context_tokens: Option<u32>,
    pub llm_first_token_secs: Option<u32>,
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
    /// Can be a step of an action plan (ADR 0003 §4).
    pub plan_eligible: bool,
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
    #[serde(flatten)]
    pub server: crate::llm::ServerInfo,
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
        VaultError::WrongPin => AegisError::new(ErrorCode::PinInvalid, "Incorrect passphrase or PIN."),
        VaultError::PinTooShort => AegisError::new(ErrorCode::PinTooWeak, "The PIN for this PC must be at least 6 characters."),
        VaultError::PassphraseTooShort => AegisError::new(ErrorCode::PinTooWeak, "The passphrase must be at least 14 characters."),
        VaultError::PinTooLong => AegisError::new(ErrorCode::PinTooWeak, "That is too long: at most 128 characters."),
        VaultError::ThisPc | VaultError::Corrupt(_) | VaultError::Io(_) => AegisError::new(ErrorCode::Internal, e.to_string()),
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
        let data_dir: PathBuf = data_dir.into();
        Arc::new_cyclic(|me| Self {
            me: me.clone(),
            history: HistoryService::new(&data_dir),
            runtime_reviews: Mutex::new(BTreeMap::new()),
            locked_work: Mutex::new(BTreeSet::new()),
            resume_notices: Mutex::new(BTreeMap::new()),
            paused: AtomicBool::new(false),
            device_approval: AtomicBool::new(false),
            device_misses: Mutex::new(VecDeque::new()),
            device_tripped: AtomicBool::new(false),
            agent_requests: Mutex::new(VecDeque::new()),
            unwritten: Mutex::new(Vec::new()),
            record_full_bytes: AtomicU64::new(APPROVAL_RECORD_FULL_BYTES),
            record_hard_bytes: AtomicU64::new(APPROVAL_RECORD_FULL_BYTES + APPROVAL_RECORD_HEADROOM),
            unwritten_lost: AtomicU64::new(0),
            data_dir,
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
        let full = self.approval_record_full();
        let unwritten = lock(&self.unwritten).len();
        let reviews = self.runtime_reviews();
        let notices: Vec<ResumeNoticeView> =
            lock(&self.resume_notices).iter().map(|(id, n)| ResumeNoticeView { plugin_id: id.clone(), notice: n.clone() }).collect();
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
            runtime_reviews: if state.is_some() { reviews } else { Vec::new() },
            resume_notices: if state.is_some() { notices } else { Vec::new() },
            needs_passphrase: guard.as_ref().is_some_and(|v| !v.meets_passphrase_rule()),
            this_pc_pin: guard.as_ref().map_or_else(|| vault::this_pc_exists(&self.vault_path()), |v| v.has_this_pc()),
            approval_record_full: state.is_some() && full,
            unwritten_records: unwritten,
        }
    }

    /// Creates the vault, keyed by a passphrase (ADR 0004 §3.2). Plugins
    /// marked `optionalInstallDefault` start installed with every component
    /// on; the wizard can change that.
    pub async fn setup(&self, pin: String) -> AegisResult<Status> {
        let pin = Zeroizing::new(pin);
        vault::validate_new_passphrase(&pin).map_err(vault_err)?;
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
        // Plugins running locked carry on under `on_unlock`. One resumed at
        // launch from a file whose plugin is not installed stops here.
        let was_running = std::mem::take(&mut *lock(&self.locked_work));
        for id in was_running.iter().filter(|id| !installed.iter().any(|(i, _)| i == *id)) {
            if let Some(plugin) = self.registry.plugin(id) {
                plugin.on_lock();
            }
        }
        self.load_history_keys();
        // If this fails the record is not chained, and agent requests and
        // approvals are refused until it works (ADR 0004 §4.6).
        let _ = self.turn_approval_session(true);
        self.check_runtime_files();
        for (id, components) in installed {
            if let Some(plugin) = self.registry.plugin(&id) {
                plugin.on_unlock(&self.unlock_context(&id, components));
                if let Some(notice) = plugin.resume_notice() {
                    lock(&self.resume_notices).insert(id, notice);
                }
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

    /// True while a change is running or waiting, an installed plugin has
    /// background work, or a plugin kept running when the vault locked.
    /// Closing the window then hides to the tray, so a repair or a monitor
    /// is not cut off.
    pub fn background_active(&self) -> bool {
        if self.executor.view() != ChangeView::default() {
            return true;
        }
        self.background_plugins().iter().filter_map(|id| self.registry.plugin(id)).any(|p| p.background_active())
    }

    /// Plugins that may have background work: the installed ones while
    /// unlocked, the ones running locked otherwise.
    fn background_plugins(&self) -> Vec<String> {
        let installed = lock(&self.vault).as_ref().map(|v| v.state.installed_plugins.clone());
        installed.unwrap_or_else(|| lock(&self.locked_work).iter().cloned().collect())
    }

    /// True while locked with a plugin still running (*locked, monitoring*).
    pub fn locked_monitoring(&self) -> bool {
        lock(&self.vault).is_none() && !lock(&self.locked_work).is_empty()
    }

    pub fn monitoring_paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    /// Pauses or resumes background monitoring from the tray. Needs no PIN:
    /// the tray is not reachable by agents (ADR 0002 §4). Flips `paused` in
    /// each runtime file (not part of the tamper check) and tells the plugins,
    /// which record the pause in their history.
    pub fn set_monitoring_paused(&self, paused: bool) {
        if self.paused.swap(paused, Ordering::SeqCst) == paused {
            return;
        }
        for id in self.history.runtime_files() {
            if let Some(Ok(file)) = self.history.read_runtime(&id) {
                let _ = self.history.write_runtime(&id, Some(&RuntimeFile { paused, ..file }));
            }
        }
        for id in self.background_plugins() {
            if let Some(plugin) = self.registry.plugin(&id) {
                plugin.set_paused(paused);
            }
        }
    }

    /// At launch, before any unlock: resumes the work each runtime file
    /// declares, in *locked, monitoring* (ADR 0002 §6). The file is not
    /// checked against the vault until the next unlock, which stops work
    /// from a file that differs. A file set aside for review is never
    /// resumed from, and neither is one with an invalid key or retention.
    /// Also restores a tray pause kept in the files. Returns true if
    /// anything runs.
    pub fn resume_at_launch(&self, launch: Launch) -> bool {
        if lock(&self.vault).is_some() || !lock(&self.locked_work).is_empty() || !vault::vault_exists(&self.vault_path()) {
            return false;
        }
        let mut files = Vec::new();
        for id in self.history.runtime_files() {
            if self.history.rejected_path(&id).exists() || self.registry.plugin(&id).is_none() {
                continue;
            }
            if let Some(Ok(file)) = self.history.read_runtime(&id) {
                if file.version == RUNTIME_VERSION && file.stream == id && file.public_key().is_valid() && file.retention.is_valid() {
                    files.push((id, file));
                }
            }
        }
        let paused = files.iter().any(|(_, f)| f.paused);
        self.paused.store(paused, Ordering::SeqCst);
        let mut running = BTreeSet::new();
        for (id, file) in files {
            let Some(plugin) = self.registry.plugin(&id) else { continue };
            self.history.set_key(&id, file.public_key(), file.retention);
            let ctx = LockedContext { runtime: file.plugin, history: self.history_for(&id), paused, launch: Some(launch) };
            if plugin.run_locked(&ctx) {
                running.insert(id);
            }
        }
        self.history.enforce_retention(chrono::Utc::now());
        let any = !running.is_empty();
        *lock(&self.locked_work) = running;
        any
    }

    /// Whether the Startup shortcut has anything to start: some installed
    /// plugin has saved background work. `None` while locked or while a
    /// plugin does not know yet; the shortcut is only removed on `Some(false)`.
    pub fn autostart_wanted(&self) -> Option<bool> {
        let installed = lock(&self.vault).as_ref().map(|v| v.state.installed_plugins.clone())?;
        let mut wanted = false;
        for plugin in installed.iter().filter_map(|id| self.registry.plugin(id)) {
            wanted |= plugin.saved_background_work()?;
        }
        Some(wanted)
    }

    /// The owner closed the banner about the gap before a resume.
    pub fn dismiss_resume_notice(&self, plugin_id: &str) {
        lock(&self.resume_notices).remove(plugin_id);
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
    /// Locks the vault. A plugin that declared locked work keeps running it
    /// (*locked, monitoring*, ADR 0002 §4) unless its runtime file waits for
    /// the owner's review; everything else stops.
    pub async fn lock(&self) -> Status {
        self.lock_inner(true).await
    }

    /// AegisWin is exiting: plugins write their clean-stop record, then
    /// everything stops, including locked work.
    pub async fn exit(&self, reason: ExitReason) {
        for id in self.background_plugins() {
            if let Some(plugin) = self.registry.plugin(&id) {
                plugin.on_exit(reason);
            }
        }
        self.lock_inner(false).await;
    }

    async fn lock_inner(&self, keep_locked_work: bool) -> Status {
        self.stop_mcp().await;
        // Recorded while the vault is still open; the requests are forgotten below.
        let open: Vec<String> = lock(&self.tickets).list(Instant::now()).into_iter().filter(|v| !v.status.is_final()).map(|v| v.ticket_id).collect();
        for id in open {
            self.record_approval(json!({
                "event": "cancelled",
                "ticketId": id,
                "from": "lock",
                "reason": "AegisWin locked. A change already running finishes; its outcome is recorded.",
            }));
        }
        // While the vault key is still here: close the file, checkpoint, and
        // store the key of the session that covers the locked period (ADR 0004 §4.2).
        let _ = self.turn_approval_session(false);
        let reviews: BTreeSet<String> = lock(&self.runtime_reviews).keys().cloned().collect();
        let taken = lock(&self.vault).take().map(|v| (v.state.installed_plugins.clone(), v.state.runtime.clone()));
        // Waiting changes never resume after unlock; a running one finishes.
        self.executor.cancel_all();
        match taken {
            Some((installed, runtime)) => {
                let paused = self.monitoring_paused();
                let mut running = BTreeSet::new();
                for id in installed {
                    let Some(plugin) = self.registry.plugin(&id) else { continue };
                    match runtime.get(&id).filter(|_| keep_locked_work && !reviews.contains(&id)) {
                        Some(section) => {
                            if plugin.run_locked(&LockedContext { runtime: section.clone(), history: self.history_for(&id), paused, launch: None }) {
                                running.insert(id);
                            }
                        }
                        None => plugin.on_lock(),
                    }
                }
                *lock(&self.locked_work) = running;
            }
            // Already locked: only an exit stops what runs locked.
            None if !keep_locked_work => {
                let running = std::mem::take(&mut *lock(&self.locked_work));
                for id in running {
                    if let Some(plugin) = self.registry.plugin(&id) {
                        plugin.on_lock();
                    }
                }
            }
            None => {}
        }
        // A fresh file (and HPKE context) for anything written while locked.
        self.history.close_all();
        lock(&self.tickets).clear();
        lock(&self.resume_notices).clear();
        self.device_approval.store(false, Ordering::SeqCst);
        lock(&self.device_misses).clear();
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
        let verifier = self.verifier()?;
        let pin = Zeroizing::new(pin.to_owned());
        let ok = tokio::task::spawn_blocking(move || verifier.verify(&pin)).await.map_err(internal)?;
        lock(&self.guard).record(ok, Instant::now());
        if ok {
            // A correct PIN is the owner: only the app asks for it.
            self.note_activity();
            Ok(())
        } else {
            Err(vault_err(VaultError::WrongPin))
        }
    }

    /// Sets a new passphrase under a new data key (ADR 0004 §3.2). The short
    /// PIN for this PC is set to `pc_pin` if given; otherwise it is removed,
    /// because it opened the old data key.
    pub async fn change_passphrase(&self, current: String, passphrase: String, pc_pin: Option<String>) -> AegisResult<Status> {
        let (current, passphrase, pc_pin) = (Zeroizing::new(current), Zeroizing::new(passphrase), pc_pin.map(Zeroizing::new));
        vault::validate_new_passphrase(&passphrase).map_err(vault_err)?;
        if let Some(pin) = &pc_pin {
            vault::validate_new_pin(pin).map_err(vault_err)?;
            if pin.as_str() == passphrase.as_str() {
                return Err(AegisError::new(ErrorCode::PinTooWeak, "Use a different PIN for this PC than the passphrase."));
            }
        }
        self.check_pin(&current).await?;
        let kdf = self.kdf;
        let (pass_key, pc_key) = tokio::task::spawn_blocking(move || -> Result<_, VaultError> {
            Ok((NewKey::derive(&passphrase, kdf)?, pc_pin.map(|p| NewKey::derive(&p, kdf)).transpose()?))
        })
        .await
        .map_err(internal)?
        .map_err(vault_err)?;
        {
            let mut guard = lock(&self.vault);
            guard.as_mut().ok_or_else(locked)?.install_passphrase(pass_key, pc_key).map_err(vault_err)?;
        }
        Ok(self.status())
    }

    /// Sets or replaces the short PIN for this PC (ADR 0004 §3.3). Needs the
    /// passphrase or the current PIN.
    pub async fn set_this_pc_pin(&self, current: String, pin: String) -> AegisResult<Status> {
        let (current, pin) = (Zeroizing::new(current), Zeroizing::new(pin));
        vault::validate_new_pin(&pin).map_err(vault_err)?;
        if vault::meets_passphrase_rule(&current) && pin.as_str() == current.as_str() {
            return Err(AegisError::new(ErrorCode::PinTooWeak, "Use a different PIN for this PC than the passphrase."));
        }
        self.check_pin(&current).await?;
        let kdf = self.kdf;
        let key = tokio::task::spawn_blocking(move || NewKey::derive(&pin, kdf)).await.map_err(internal)?.map_err(vault_err)?;
        {
            let mut guard = lock(&self.vault);
            guard.as_mut().ok_or_else(locked)?.set_this_pc(key).map_err(vault_err)?;
        }
        Ok(self.status())
    }

    /// Deletes the short PIN for this PC. Needs no PIN, works while locked:
    /// it only removes a way in (ADR 0004 §3.3).
    pub fn forget_this_pc(&self) -> AegisResult<Status> {
        {
            let mut guard = lock(&self.vault);
            match guard.as_mut() {
                Some(v) => v.forget_this_pc(),
                None => vault::forget_this_pc(&self.vault_path()),
            }
            .map_err(vault_err)?;
        }
        Ok(self.status())
    }

    fn verifier(&self) -> AegisResult<vault::PinVerifier> {
        let guard = lock(&self.vault);
        Ok(guard.as_ref().ok_or_else(locked)?.verifier())
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
                    context_tokens: s.llm.context_tokens,
                    first_token_secs: s.llm.first_token_secs,
                    endpoint,
                    endpoint_error,
                },
                mcp: McpSettingsView {
                    enabled: s.mcp.enabled,
                    host: s.mcp.host.clone(),
                    port: s.mcp.port,
                    open_firewall: s.mcp.open_firewall,
                    device_approval: self.device_approval.load(Ordering::SeqCst),
                    device_approval_notice: self.device_tripped.load(Ordering::SeqCst).then(|| {
                        format!("{DEVICE_MISSES_PER_HOUR} wrong codes were typed on the device page within an hour, so Approve from another device was turned off. Turn it on again only if you typed them.")
                    }),
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
            if let Some(tokens) = update.llm_context_tokens {
                if !(crate::llm::MIN_CONTEXT_TOKENS..=crate::llm::MAX_CONTEXT_TOKENS).contains(&tokens) {
                    return Err(AegisError::invalid(format!(
                        "Context window must be between {} and {} tokens.",
                        crate::llm::MIN_CONTEXT_TOKENS,
                        crate::llm::MAX_CONTEXT_TOKENS
                    )));
                }
                s.llm.context_tokens = tokens;
            }
            if let Some(secs) = update.llm_first_token_secs {
                if !(crate::llm::MIN_FIRST_TOKEN_SECS..=crate::llm::MAX_FIRST_TOKEN_SECS).contains(&secs) {
                    return Err(AegisError::invalid(format!(
                        "First answer wait must be between {} and {} seconds.",
                        crate::llm::MIN_FIRST_TOKEN_SECS,
                        crate::llm::MAX_FIRST_TOKEN_SECS
                    )));
                }
                s.llm.first_token_secs = secs;
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
        let server = crate::llm::server_info(&self.http, &config).await;
        Ok(LlmTest { endpoint, models, server })
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
                                plan_eligible: t.plan_eligible,
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
            // An uninstalled plugin runs nothing while locked.
            s.runtime.retain(|id, _| selection.contains_key(id));
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
                if after.is_none() {
                    let _ = self.history.write_runtime(id, None);
                }
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
        UnlockContext {
            enabled_components,
            store: Some(self.store_for(plugin_id)),
            history: Some(self.history_for(plugin_id)),
            paused: self.monitoring_paused(),
        }
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

    // ---- history (ADR 0002 §5) --------------------------------------------

    fn history_for(&self, plugin_id: &str) -> HistoryHandle {
        HistoryHandle::new(self.me.clone(), plugin_id)
    }

    /// Forces pending history frames to disk every 30 seconds. Called from
    /// the app's 5-second idle check, so a quiet stream is not left unsynced.
    pub fn history_tick(&self) {
        self.history.sync_due();
    }

    fn retention_of(s: &VaultState, stream: &str) -> Retention {
        s.history_retention.get(stream).copied().unwrap_or_else(|| history_service::default_retention(stream))
    }

    /// Caches every stream's public key (and retention) from the vault,
    /// replacing any key read from a runtime file, and applies retention.
    fn load_history_keys(&self) {
        let keys = self
            .with_state(|s| s.history_keys.iter().map(|(stream, k)| (stream.clone(), k.public(), Self::retention_of(s, stream))).collect::<Vec<_>>())
            .unwrap_or_default();
        for (stream, key, retention) in keys {
            self.history.set_key(&stream, key, retention);
        }
        self.history.enforce_retention(chrono::Utc::now());
    }

    /// Creates the stream's keypair in the vault the first time it is used.
    fn ensure_history_key(&self, stream: &str) -> AegisResult<()> {
        let (key, retention) = self.mutate(|s| {
            let key = s.history_keys.entry(stream.to_owned()).or_insert_with(StreamKey::generate).public();
            Ok((key, Self::retention_of(s, stream)))
        })?;
        self.history.set_key(stream, key, retention);
        Ok(())
    }

    pub(crate) fn history_append(&self, stream: &str, mut record: Value) -> AegisResult<()> {
        let Value::Object(fields) = &mut record else {
            return Err(AegisError::invalid("a history record is a JSON object"));
        };
        let now = chrono::Utc::now();
        fields.insert("at".into(), Value::String(now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)));
        if !self.history.knows(stream) {
            self.ensure_history_key(stream)?;
        }
        self.history.append(stream, &record, now)
    }

    pub(crate) fn history_read(&self, stream: &str, since: Option<chrono::NaiveDate>) -> AegisResult<StreamRead> {
        let key = self.with_state(|s| self.require_installed(s, stream).map(|()| s.history_keys.get(stream).cloned()))??;
        match key {
            Some(key) => self.history.read(stream, &key, since),
            None => Ok(StreamRead::default()),
        }
    }

    /// Deletes the stream's files and replaces its keypair, so a deleted
    /// file recovered from the disk cannot be read with the vault later.
    pub(crate) fn history_purge(&self, stream: &str) -> AegisResult<usize> {
        self.purge_stream(stream, true)
    }

    fn purge_stream(&self, stream: &str, plugin: bool) -> AegisResult<usize> {
        let (key, retention) = self.mutate(|s| {
            if plugin {
                self.require_installed(s, stream)?;
            }
            let key = StreamKey::generate();
            let public = key.public();
            s.history_keys.insert(stream.to_owned(), key);
            Ok((public, Self::retention_of(s, stream)))
        })?;
        let removed = self.history.purge(stream, key, retention)?;
        if plugin {
            self.rewrite_runtime(stream)?;
        }
        Ok(removed)
    }

    // ---- approval record (ADR 0003 §7, ADR 0004 §4) -----------------------

    /// Starts a new MAC session for the approval record, with its key in the
    /// vault before any record uses it, then checkpoints (ADR 0004 §4.2,
    /// §4.3). Runs at unlock (`prune`: retention too) and just before lock,
    /// while the vault key is in memory. The first time in a run, the chain
    /// carries on from the files or the checkpoint, whichever is further on:
    /// a checkpoint ahead of the files means records were removed, and
    /// carrying on from it keeps that gap visible.
    fn turn_approval_session(&self, prune: bool) -> AegisResult<()> {
        if !self.history.knows(APPROVALS_STREAM) {
            self.ensure_history_key(APPROVALS_STREAM)?;
        }
        let today = chrono::Utc::now().date_naive().to_string();
        let (session, id, stored) = Session::start(&today);
        let (key, chain) = self.mutate(|s| {
            let chain = s.history_chains.entry(APPROVALS_STREAM.to_owned()).or_default();
            chain.add_session(id, stored, &today);
            let chain = chain.clone();
            Ok((s.history_keys.get(APPROVALS_STREAM).cloned(), chain))
        })?;
        let dir = self.history.dir(APPROVALS_STREAM);
        self.history.turn_session(APPROVALS_STREAM, session, || {
            let mut macs = MacCheck::new(Some(&chain));
            let disk = match &key {
                Some(key) => history::chain_tail(&dir, APPROVALS_STREAM, key, &mut macs).map_err(|e| AegisError::new(ErrorCode::Internal, format!("history: {e}")))?,
                None => None,
            };
            let saved = chain.checkpoint.as_ref().map(Head::from);
            Ok(match (disk, saved) {
                (Some(disk), Some(saved)) if saved.seq > disk.seq => saved,
                (disk, saved) => disk.or(saved).unwrap_or_else(Head::genesis),
            })
        })?;
        self.checkpoint_approvals(prune)
    }

    /// Applies retention to the approval record when `prune` (each removed
    /// file leaves a `pruned` record), then stores the chain's head in the
    /// vault and forgets session keys whose records have all aged out.
    fn checkpoint_approvals(&self, prune: bool) -> AegisResult<()> {
        let now = chrono::Utc::now();
        let (key, retention) = self.with_state(|s| (s.history_keys.get(APPROVALS_STREAM).cloned(), Self::retention_of(s, APPROVALS_STREAM)))?;
        let oldest = now.date_naive() - chrono::Days::new(u64::from(retention.max_days.saturating_sub(1)));
        if let Some(key) = key.filter(|_| prune) {
            self.history.prune_chained(APPROVALS_STREAM, &key, oldest, now)?;
        }
        let head = self.history.chain_head(APPROVALS_STREAM);
        let oldest = oldest.to_string();
        self.mutate(|s| {
            let chain = s.history_chains.entry(APPROVALS_STREAM.to_owned()).or_default();
            if let Some(head) = &head {
                chain.checkpoint = Some(head.checkpoint());
            }
            chain.forget_sessions_before(&oldest);
            Ok(())
        })
    }

    fn approval_record_full(&self) -> bool {
        self.history.bytes(APPROVALS_STREAM).is_some_and(|b| b >= self.record_full_bytes.load(Ordering::SeqCst))
    }

    /// Sets the approval record's size limits: full for new requests, and
    /// for every event. Tests only.
    #[doc(hidden)]
    pub fn set_approval_record_limits(&self, full: u64, hard: u64) {
        self.record_full_bytes.store(full, Ordering::SeqCst);
        self.record_hard_bytes.store(hard, Ordering::SeqCst);
    }

    fn append_approval(&self, record: &Value, new_request: bool, sync: bool) -> Result<(), AppendError> {
        let limit = if new_request { &self.record_full_bytes } else { &self.record_hard_bytes }.load(Ordering::SeqCst);
        self.history.append_with(APPROVALS_STREAM, record, chrono::Utc::now(), Append { limit: Some(limit), sync, chained: true })
    }

    /// Writes the held events first, oldest first, so the record keeps its order.
    fn write_held(&self, held: &mut Vec<Value>) -> Result<(), AppendError> {
        let lost = self.unwritten_lost.load(Ordering::SeqCst);
        if lost > 0 {
            let note = Self::stamped(json!({ "event": "integrity", "problem": format!("{} events could not be written in time and were lost.", chain::thousands(lost)) }));
            self.append_approval(&note, false, false)?;
            self.unwritten_lost.fetch_sub(lost, Ordering::SeqCst);
        }
        while let Some(record) = held.first() {
            self.append_approval(record, false, false)?;
            held.remove(0);
        }
        Ok(())
    }

    fn stamped(mut record: Value) -> Value {
        if let Value::Object(fields) = &mut record {
            fields.entry("at").or_insert_with(|| Value::String(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)));
        }
        record
    }

    /// An event whose loss must not block anything: one that cannot be
    /// written is held in memory and written before the next, and the app
    /// shows a banner meanwhile (ADR 0004 §4.6). The PIN is never part of a record.
    fn record_approval(&self, record: Value) {
        let record = Self::stamped(record);
        let mut held = lock(&self.unwritten);
        if self.write_held(&mut held).is_ok() && self.append_approval(&record, false, false).is_ok() {
            return;
        }
        if held.len() >= MAX_UNWRITTEN {
            held.remove(0);
            self.unwritten_lost.fetch_add(1, Ordering::SeqCst);
        }
        held.push(record);
    }

    /// An event that must be on disk before AegisWin acts on it (§4.6).
    fn record_required(&self, record: Value, new_request: bool, sync: bool, refused: &str) -> AegisResult<()> {
        let record = Self::stamped(record);
        let mut held = lock(&self.unwritten);
        self.write_held(&mut held).and_then(|()| self.append_approval(&record, new_request, sync)).map_err(|e| match e {
            AppendError::Full if new_request => AegisError::new(ErrorCode::Conflict, RECORD_FULL),
            _ => AegisError::new(ErrorCode::Internal, format!("AegisWin couldn't write its approval record, so {refused}.")),
        })
    }

    /// Records a new request; if that fails the request is refused (§4.6).
    fn record_created(&self, view: &TicketView, origin: &str) -> AegisResult<()> {
        let mut record = json!({
            "event": "created",
            "ticketId": view.ticket_id,
            "origin": origin,
            "toolName": view.tool_name,
            "requiresAdmin": view.requires_admin,
        });
        match &view.plan {
            Some(plan) => {
                record["plan"] = json!({
                    "hash": plan.hash,
                    "title": plan.title.as_deref().map(cut_text),
                    "titleLabel": plan.supplied_label,
                    "steps": view.steps.iter().map(|s| json!({ "tool": s.tool, "args": capped_args(&s.args) })).collect::<Vec<_>>(),
                });
            }
            None => {
                record["tool"] = json!(registry::mcp_tool_name(&view.plugin_id, &view.tool_id));
                record["args"] = capped_args(&view.args);
            }
        }
        let refused = self.record_required(record, origin.starts_with("mcp"), false, "the request was refused");
        if refused.is_err() {
            lock(&self.tickets).remove(&view.ticket_id);
        }
        refused
    }

    fn decided(id: &str, approved: bool, via: &str, comment: Option<&str>, locked_out: bool) -> Value {
        json!({ "event": "decided", "ticketId": id, "approved": approved, "via": via, "comment": comment, "lockedOut": locked_out })
    }

    /// A decline or a lockout: it happens even if it cannot be recorded (§4.6).
    fn record_declined(&self, id: &str, via: &str, comment: Option<&str>, locked_out: bool) {
        self.record_approval(Self::decided(id, false, via, comment, locked_out));
    }

    /// `finished` for a request the store no longer holds: AegisWin locked
    /// while it ran, so the task records from what it knows (ADR 0004 §4.7).
    fn record_finished_as(&self, id: &str, status: TicketStatus, reason: Option<&str>) {
        self.record_approval(json!({ "event": "finished", "ticketId": id, "status": status, "reason": reason.map(cut_text), "afterLock": true }));
    }

    /// Records how a request ended, once it has. Call with the ticket store unlocked.
    fn record_finished(&self, id: &str) {
        let Some(view) = lock(&self.tickets).get(id, Instant::now()).map(|t| t.view()) else { return };
        if !view.status.is_final() {
            return;
        }
        let reason = view.plan.as_ref().and_then(|p| p.stop_reason.clone()).or_else(|| view.error.as_ref().map(|e| e.message.clone()));
        self.record_approval(json!({ "event": "finished", "ticketId": id, "status": view.status, "reason": reason.as_deref().map(cut_text) }));
    }

    /// Runs a call. One that changes the system is bracketed by
    /// `change_started` and `change_finished` records, so the record shows
    /// every change AegisWin made and monitor events can be labelled as
    /// happening during a repair (ADR 0003 §5, §7).
    async fn call_recorded(&self, prepared: Prepared, by: Value) -> AegisResult<Value> {
        if !changes_system(&prepared.tool, &prepared.args) {
            return prepared.plugin.call(&prepared.tool.id, prepared.args, prepared.ctx).await;
        }
        let tool = registry::mcp_tool_name(&prepared.plugin.manifest().id, &prepared.tool.id);
        let mut started = json!({ "event": "change_started", "tool": tool, "toolName": prepared.tool.name, "args": capped_args(&prepared.args) });
        merge(&mut started, &by);
        // On disk before the change runs; if it cannot be, the change does not run (§4.6).
        self.record_required(started, false, true, &format!("{} did not run", prepared.tool.name))?;
        let result = prepared.plugin.call(&prepared.tool.id, prepared.args, prepared.ctx).await;
        let outcome = match &result {
            Ok(v) if v.get("success") == Some(&Value::Bool(false)) => "reported_failure",
            Ok(_) => "succeeded",
            Err(_) => "failed",
        };
        let mut finished = json!({ "event": "change_finished", "tool": tool, "outcome": outcome, "error": result.as_ref().err().map(|e| cut_text(&e.message)) });
        merge(&mut finished, &by);
        self.record_approval(finished);
        result
    }

    /// The approval record, oldest first. App only, after the PIN; never MCP.
    pub fn read_approvals(&self, since: Option<chrono::NaiveDate>) -> AegisResult<StreamRead> {
        match self.with_state(|s| s.history_keys.get(APPROVALS_STREAM).cloned())? {
            Some(key) => self.history.read(APPROVALS_STREAM, &key, since),
            None => Ok(StreamRead::default()),
        }
    }

    /// Deletes the approval record and replaces its key. A new chain starts,
    /// whose first event after its `open` frame is `purged` (ADR 0004 §4.3).
    /// App only, after the PIN.
    pub fn purge_approvals(&self) -> AegisResult<usize> {
        let removed = self.purge_stream(APPROVALS_STREAM, false)?;
        let today = chrono::Utc::now().date_naive().to_string();
        let (session, id, stored) = Session::start(&today);
        self.mutate(|s| {
            let mut chain = chain::ChainVault::default();
            chain.add_session(id, stored, &today);
            s.history_chains.insert(APPROVALS_STREAM.to_owned(), chain);
            Ok(())
        })?;
        self.history.restart_chain(APPROVALS_STREAM, session)?;
        // Events waiting to be written belonged to the deleted record.
        lock(&self.unwritten).clear();
        self.unwritten_lost.store(0, Ordering::SeqCst);
        self.record_required(json!({ "event": "purged", "files": removed }), false, true, "the deletion was not recorded")?;
        self.checkpoint_approvals(false)?;
        Ok(removed)
    }

    /// The owner's view of the approval record: the last `days` days (1-90),
    /// newest first, with an integrity line for the whole record (ADR 0004
    /// §4.4). Problems found are also written into the record, once each.
    /// Needs the PIN. App only, never MCP.
    pub async fn approval_record(&self, pin: &str, days: u32) -> AegisResult<Value> {
        self.check_pin(pin).await?;
        let days = days.clamp(1, APPROVAL_RECORD_MAX_DAYS);
        let since = (chrono::Utc::now().date_naive() - chrono::Days::new(u64::from(days - 1))).to_string();
        let (key, chain, retention) = self.with_state(|s| {
            (s.history_keys.get(APPROVALS_STREAM).cloned(), s.history_chains.get(APPROVALS_STREAM).cloned(), Self::retention_of(s, APPROVALS_STREAM))
        })?;
        let mut macs = MacCheck::new(chain.as_ref());
        let (files, current) = match &key {
            Some(key) => self.history.read_files(APPROVALS_STREAM, key, None, &mut macs)?,
            None => (Vec::new(), None),
        };
        let integrity = chain::verify(&files, chain.as_ref().and_then(|c| c.checkpoint.as_ref()), current.as_deref());
        let noted: BTreeSet<&str> = files
            .iter()
            .flat_map(|f| &f.frames)
            .filter(|f| f.record.get("event").and_then(Value::as_str) == Some("integrity"))
            .filter_map(|f| f.record.get("problem").and_then(Value::as_str))
            .collect();
        let problems: Vec<String> = integrity.problems.iter().map(chain::Problem::text).collect();
        for problem in problems.iter().filter(|p| !noted.contains(p.as_str())) {
            self.record_approval(json!({ "event": "integrity", "problem": problem }));
        }
        let mut events: Vec<Value> = files
            .iter()
            .flat_map(|f| {
                let failed = f.chained || integrity.failed_files.contains(&f.name);
                f.frames.iter().map(move |frame| (failed, frame))
            })
            .filter(|(_, f)| !matches!(f.record.get("event").and_then(Value::as_str), Some("open" | "close")))
            .filter(|(_, f)| f.record.get("at").and_then(Value::as_str).is_some_and(|at| at >= since.as_str()))
            .map(|(checked, f)| {
                let mut record = f.record.clone();
                if let Value::Object(fields) = &mut record {
                    for chain_field in ["prev", "sess", "mi"] {
                        fields.remove(chain_field);
                    }
                    if checked && f.mac_ok != Some(true) {
                        fields.insert("unverified".into(), Value::Bool(true));
                    }
                }
                record
            })
            .collect();
        events.reverse();
        let omitted = events.len().saturating_sub(APPROVAL_RECORD_LIMIT);
        events.truncate(APPROVAL_RECORD_LIMIT);
        let reports: Vec<history::FileReport> = files.iter().map(history::FileRead::report).collect();
        Ok(json!({
            "days": days,
            "retention": retention,
            "events": events,
            "omitted": omitted,
            "files": reports,
            "integrity": { "ok": integrity.ok(), "line": integrity.line(), "problems": problems, "verified": integrity.verified, "legacy": integrity.legacy },
        }))
    }

    /// Keeps the approval record for `days` (1-90) and applies it now,
    /// recording what it removes. Needs the PIN. App only, never MCP.
    pub async fn set_approval_retention(&self, pin: &str, days: u32) -> AegisResult<Retention> {
        self.check_pin(pin).await?;
        if !Retention::DAYS.contains(&days) {
            return Err(AegisError::invalid(format!("Keep the approval record for {} to {} days.", Retention::DAYS.start(), Retention::DAYS.end())));
        }
        let (retention, key) = self.mutate(|s| {
            let mut r = Self::retention_of(s, APPROVALS_STREAM);
            r.max_days = days;
            s.history_retention.insert(APPROVALS_STREAM.to_owned(), r);
            Ok((r, s.history_keys.get(APPROVALS_STREAM).map(StreamKey::public)))
        })?;
        if let Some(key) = key {
            self.history.set_key(APPROVALS_STREAM, key, retention);
        }
        self.checkpoint_approvals(true)?;
        Ok(retention)
    }

    /// Deletes the whole approval record. Needs the PIN. App only, never MCP.
    pub async fn delete_approval_record(&self, pin: &str) -> AegisResult<usize> {
        self.check_pin(pin).await?;
        self.purge_approvals()
    }

    /// When AegisWin itself was changing the system, from the approval record.
    pub(crate) fn change_windows(&self, since: chrono::NaiveDate) -> AegisResult<Vec<ChangeWindow>> {
        Ok(history_service::change_windows(&self.read_approvals(Some(since))?.records))
    }

    pub(crate) fn history_retention(&self, stream: &str) -> AegisResult<Retention> {
        self.with_state(|s| self.require_installed(s, stream).map(|()| Self::retention_of(s, stream)))?
    }

    pub(crate) fn set_history_retention(&self, stream: &str, retention: Retention) -> AegisResult<()> {
        if !retention.is_valid() {
            return Err(AegisError::invalid(format!(
                "history is kept for {}-{} days and {}-{} MB",
                Retention::DAYS.start(),
                Retention::DAYS.end(),
                Retention::MB.start(),
                Retention::MB.end()
            )));
        }
        self.mutate(|s| {
            self.require_installed(s, stream)?;
            s.history_retention.insert(stream.to_owned(), retention);
            s.history_keys.entry(stream.to_owned()).or_insert_with(StreamKey::generate);
            Ok(())
        })?;
        self.load_history_keys();
        self.rewrite_runtime(stream)
    }

    /// What the runtime file of `plugin_id` should say, from the vault.
    fn expected_runtime(s: &VaultState, plugin_id: &str) -> Option<RuntimeFile> {
        let plugin = s.runtime.get(plugin_id)?;
        let key = s.history_keys.get(plugin_id)?.public();
        Some(RuntimeFile {
            version: RUNTIME_VERSION,
            stream: plugin_id.to_owned(),
            key_id: key.key_id,
            public_key: key.public_key,
            retention: Self::retention_of(s, plugin_id),
            paused: false,
            plugin: plugin.clone(),
        })
    }

    /// Saves what a plugin runs while locked (`None`: nothing) in the vault,
    /// then writes its runtime file, unless that file waits for the owner's
    /// review.
    pub(crate) fn set_runtime(&self, plugin_id: &str, plugin: Option<Value>) -> AegisResult<()> {
        if let Some(v) = &plugin {
            if serde_json::to_vec(v).map_err(internal)?.len() > MAX_RUNTIME_BYTES {
                return Err(AegisError::invalid(format!("the runtime settings would exceed {} KiB", MAX_RUNTIME_BYTES / 1024)));
            }
        }
        self.mutate(|s| {
            self.require_installed(s, plugin_id)?;
            match plugin {
                Some(v) => {
                    s.history_keys.entry(plugin_id.to_owned()).or_insert_with(StreamKey::generate);
                    s.runtime.insert(plugin_id.to_owned(), v);
                }
                None => {
                    s.runtime.remove(plugin_id);
                }
            }
            Ok(())
        })?;
        self.load_history_keys();
        self.rewrite_runtime(plugin_id)
    }

    /// Writes the runtime file from the vault, keeping a tray pause. Does
    /// nothing while the file waits for the owner's review.
    fn rewrite_runtime(&self, plugin_id: &str) -> AegisResult<()> {
        if lock(&self.runtime_reviews).contains_key(plugin_id) {
            return Ok(());
        }
        let expected = self.with_state(|s| Self::expected_runtime(s, plugin_id))?;
        let paused = self.monitoring_paused() || matches!(self.history.read_runtime(plugin_id), Some(Ok(f)) if f.paused);
        self.history.write_runtime(plugin_id, expected.map(|f| RuntimeFile { paused, ..f }).as_ref())
    }

    /// The tamper check (ADR 0002 §5), run before any plugin starts. A
    /// runtime file that differs from the vault, cannot be read, or that
    /// AegisWin never wrote is moved aside and waits for the owner, also
    /// across restarts. A missing file is written again from the vault.
    fn check_runtime_files(&self) {
        let Ok(expected) = self.with_state(|s| {
            let mut ids: Vec<String> = s.runtime.keys().cloned().collect();
            ids.extend(self.history.runtime_files());
            ids.sort();
            ids.dedup();
            ids.into_iter().map(|id| (Self::expected_runtime(s, &id), id)).collect::<Vec<_>>()
        }) else {
            return;
        };
        let mut reviews = BTreeMap::new();
        for (want, id) in expected {
            let found = self.history.read_runtime(&id);
            let differences: Vec<String> = match (&found, &want) {
                (None, _) => Vec::new(),
                (Some(Ok(file)), Some(want)) => file.differences(want).into_iter().map(str::to_owned).collect(),
                (Some(Ok(_)), None) => vec!["AegisWin did not write this file".into()],
                (Some(Err(_)), _) => vec!["the file could not be read".into()],
            };
            if !differences.is_empty() {
                self.history.reject_runtime(&id);
                reviews.insert(id.clone(), RuntimeReview { plugin_id: id, differences });
            } else if let Some(review) = lock(&self.runtime_reviews).get(&id).cloned() {
                reviews.insert(id, review);
            } else if self.history.rejected_path(&id).exists() {
                reviews.insert(id.clone(), RuntimeReview { plugin_id: id, differences: vec!["it was set aside at an earlier unlock".into()] });
            } else if found.is_none() && want.is_some() {
                let paused = self.monitoring_paused();
                let _ = self.history.write_runtime(&id, want.map(|f| RuntimeFile { paused, ..f }).as_ref());
            }
        }
        *lock(&self.runtime_reviews) = reviews;
    }

    /// Runtime files set aside at unlock, for the owner to review.
    pub fn runtime_reviews(&self) -> Vec<RuntimeReview> {
        lock(&self.runtime_reviews).values().cloned().collect()
    }

    /// The owner reviewed a set-aside runtime file: write it again from the
    /// vault (the owner's own saved settings) and delete the rejected copy.
    /// App only: never reachable over MCP.
    pub fn rewrite_runtime_from_vault(&self, plugin_id: &str) -> AegisResult<()> {
        self.with_state(|_| ())?;
        if lock(&self.runtime_reviews).remove(plugin_id).is_none() {
            return Err(AegisError::invalid(format!("no runtime file of '{plugin_id}' is waiting for review")));
        }
        let _ = std::fs::remove_file(self.history.rejected_path(plugin_id));
        self.rewrite_runtime(plugin_id)
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
            ctx: ToolContext {
                elevated: self.elevated,
                enabled_components: components,
                llm,
                store: Some(self.store_for(plugin_id)),
                history: Some(self.history_for(plugin_id)),
            },
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
        let source = if matches!(origin, Origin::Mcp) { "mcp" } else { "app" };
        match prepared.gate {
            Gate::NeedsAdmin => Err(AegisError::requires_admin(&prepared.tool.name)),
            Gate::Run => self.run_in_turn(epoch, prepared, source).await,
            Gate::NeedsPin => match origin {
                Origin::Ui { pin: None } => {
                    Err(AegisError::new(ErrorCode::PinRequired, format!("Enter your PIN to run {}.", prepared.tool.name)))
                }
                Origin::Ui { pin: Some(pin) } => {
                    let pin = Zeroizing::new(pin);
                    self.check_pin(&pin).await?;
                    self.run_in_turn(epoch, prepared, "app (PIN)").await
                }
                Origin::Mcp => {
                    self.count_agent_request()?;
                    let review = prepared.plugin.review_call(&prepared.tool.id, &prepared.args, &prepared.ctx.enabled_components);
                    let mut store = lock(&self.tickets);
                    if store.pending_from_agents(Instant::now()) >= MAX_AGENT_PENDING {
                        return Err(too_many_pending());
                    }
                    let ticket = store.create(
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
                    drop(store);
                    self.record_created(&ticket, "mcp")?;
                    Ok(RunOutcome::PendingApproval { ticket: Box::new(ticket) })
                }
            },
        }
    }

    /// Runs a call now if it cannot change the system, otherwise in its turn.
    async fn run_in_turn(&self, epoch: u64, prepared: Prepared, source: &'static str) -> AegisResult<RunOutcome> {
        if !changes_system(&prepared.tool, &prepared.args) {
            return execute(prepared).await;
        }
        let engine = self.self_arc()?;
        let place = self.executor.enqueue(epoch, &prepared.tool.name, None).map_err(queue_error)?;
        // On its own task, so a caller that goes away cannot cut a change off halfway.
        tokio::spawn(async move {
            let _turn = engine.executor.turn(place, Instant::now() + QUEUE_TIMEOUT).await.map_err(stop_error)?;
            let result = engine.call_recorded(engine.recheck(&prepared)?, json!({ "ticketId": null, "origin": source })).await?;
            Ok(RunOutcome::Completed { result })
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

    /// Approves or declines a pending ticket in the app. Both need the PIN.
    /// Three wrong PINs lock the ticket; every wrong PIN also counts toward
    /// the global guard. Agents never reach this: the PIN is only typed in
    /// the app (ADR 0004 §1.1).
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
        self.before_decision(id, approve, plan_hash)?;
        let verified = {
            let _serial = self.pin_check.lock().await;
            self.pending_ticket(id)?;
            self.verify_pin_serialized(&pin).await
        };
        match verified {
            Ok(()) => {}
            Err(e) if e.code == ErrorCode::PinInvalid => {
                return Err(self.strike(id, via, |left| match left {
                    0 => AegisError::new(ErrorCode::PinLockedOut, "Too many wrong PINs for this request, so it was locked. The agent has to ask again."),
                    left => AegisError::new(ErrorCode::PinInvalid, format!("Incorrect PIN. {left} attempt(s) left for this request.")),
                }));
            }
            Err(e) => return Err(e),
        }
        self.apply_decision(epoch, id, approve, comment, via)
    }

    /// Approves or declines from the device page (ADR 0004 §1.2). Approving
    /// needs the one-time code the app showed for this ticket; declining needs
    /// nothing. Wrong codes count per ticket and toward an hourly limit that
    /// turns the feature off, never toward the vault PIN guard.
    pub fn decide_on_device(&self, id: &str, approve: bool, code: &str, comment: Option<String>, plan_hash: Option<&str>) -> AegisResult<TicketView> {
        const VIA: &str = "device code";
        if !self.device_approval_on() {
            return Err(ticket_not_found());
        }
        let epoch = self.executor.epoch();
        self.before_decision(id, approve, plan_hash)?;
        if approve && crate::tickets::normalize_code(code).is_none() {
            // Not a code at all (empty or mistyped length): costs no attempt.
            return Err(AegisError::new(ErrorCode::CodeInvalid, "Type the 8-character code shown in the AegisWin app, like K7QM-4XRT."));
        }
        if approve {
            let now = Instant::now();
            let mut store = lock(&self.tickets);
            let ticket = store.get_mut(id, now).ok_or_else(ticket_not_found)?;
            if ticket.status != TicketStatus::PendingApproval {
                return Err(ticket_conflict(ticket.status));
            }
            if ticket.device_code.as_ref().is_some_and(|c| c.matches(code, now)) {
                // Single use.
                ticket.device_code = None;
            } else {
                drop(store);
                self.device_miss(now);
                return Err(self.strike(id, VIA, |left| match left {
                    0 => AegisError::new(ErrorCode::CodeInvalid, "Too many wrong codes for this request, so it was locked. The agent has to ask again."),
                    left => AegisError::new(
                        ErrorCode::CodeInvalid,
                        format!("Wrong or expired code. {left} attempt(s) left for this request. In the AegisWin app, click Approve on another device on this request for a new code."),
                    ),
                }));
            }
        }
        self.apply_decision(epoch, id, approve, comment, VIA)
    }

    /// Checked before any PIN or code, so a stale page costs no attempt.
    fn before_decision(&self, id: &str, approve: bool, plan_hash: Option<&str>) -> AegisResult<()> {
        self.pending_ticket(id)?;
        if !approve {
            return Ok(());
        }
        let expected = lock(&self.tickets).get(id, Instant::now()).and_then(|t| t.plan.as_ref().map(|p| p.hash.clone()));
        if let Some(expected) = expected {
            let matches = plan_hash.is_some_and(|h| bool::from(h.as_bytes().ct_eq(expected.as_bytes())));
            if !matches {
                return Err(AegisError::new(ErrorCode::Conflict, "This approval does not match the plan's fingerprint. Reload the request and check its steps again."));
            }
        }
        // A full queue is refused first; the request stays pending.
        if self.ticket_changes_system(id) && !self.executor.has_room() {
            return Err(queue_error(executor::Full::Full));
        }
        Ok(())
    }

    /// Counts a wrong PIN or code against a ticket; the third locks it.
    /// `error` gets the attempts left.
    fn strike(&self, id: &str, via: &'static str, error: impl Fn(u8) -> AegisError) -> AegisError {
        let mut store = lock(&self.tickets);
        let Some(ticket) = store.get_mut(id, Instant::now()) else { return ticket_not_found() };
        if ticket.status != TicketStatus::PendingApproval {
            return ticket_conflict(ticket.status);
        }
        ticket.strikes += 1;
        let left = STRIKES_PER_TICKET.saturating_sub(ticket.strikes);
        if left == 0 {
            ticket.status = TicketStatus::LockedOut;
            ticket.decided_via = Some(via);
            drop(store);
            self.record_declined(id, via, None, true);
        }
        error(left)
    }

    /// The decision itself, once the PIN or code checked out.
    fn apply_decision(&self, epoch: u64, id: &str, approve: bool, comment: Option<String>, via: &'static str) -> AegisResult<TicketView> {
        let comment = comment.map(|c| c.trim().chars().take(MAX_COMMENT_CHARS).collect::<String>()).filter(|c| !c.is_empty());
        let mut store = lock(&self.tickets);
        let ticket = store.get_mut(id, Instant::now()).ok_or_else(ticket_not_found)?;
        if ticket.status != TicketStatus::PendingApproval {
            return Err(ticket_conflict(ticket.status));
        }
        if !approve {
            ticket.comment = comment.clone();
            ticket.decided_via = Some(via);
            ticket.status = TicketStatus::Declined;
            let view = ticket.view();
            drop(store);
            self.record_declined(id, via, comment.as_deref(), false);
            return Ok(view);
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
        // On disk before the ticket changes: an approval that is not
        // recorded is not applied, and the ticket stays pending (ADR 0004 §4.6).
        if let Err(e) = self.record_required(Self::decided(id, true, via, comment.as_deref(), false), false, false, "the approval was not applied") {
            drop(store);
            if let Some(place) = place {
                self.executor.withdraw(place);
            }
            return Err(e);
        }
        ticket.comment = comment.clone();
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
                let view = ticket.view();
                drop(store);
                self.record_finished(id);
                Ok(view)
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
            let mut store = lock(&self.tickets);
            if let Some(ticket) = store.get_mut(id, Instant::now()) {
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
            } else {
                drop(store);
                // Locked meanwhile, which cleared the store (ADR 0004 §4.7).
                let status = if result.is_ok() { TicketStatus::Approved } else { failed };
                return self.record_finished_as(id, status, result.as_ref().err().map(|e| e.message.as_str()));
            }
            drop(store);
            self.record_finished(id);
        };
        let failed = TicketStatus::ExecutionFailed;
        let _turn = match place {
            None => None,
            Some(place) => match self.executor.turn(place, Instant::now() + QUEUE_TIMEOUT).await {
                Ok(turn) => Some(turn),
                Err(stop) => {
                    let status = match stop {
                        Stop::Expired => TicketStatus::Expired,
                        Stop::Cancelled => TicketStatus::Cancelled,
                        Stop::Locked => failed,
                    };
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
        finish(self.call_recorded(prepared, json!({ "ticketId": id })).await, failed);
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
            let kept = update(&mut |t| {
                t.status = status;
                for step in t.steps.iter_mut().skip(from) {
                    step.status = rest;
                }
                if let Some(plan) = &mut t.plan {
                    plan.stop_reason = Some(reason.clone());
                }
            });
            if kept {
                self.record_finished(id);
            } else {
                self.record_finished_as(id, status, Some(&reason));
            }
        };
        for (i, step) in steps.iter().enumerate() {
            let n = i + 1;
            let mut cancelled = false;
            if !update(&mut |t| cancelled = t.cancel_requested || t.status.is_final()) {
                return self.record_finished_as(id, TicketStatus::Cancelled, Some(&format!("AegisWin locked, so step {n} did not start.")));
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
            let tool_name = fresh.tool.name.clone();
            let (output, outcome) = match self.call_recorded(fresh, json!({ "ticketId": id, "step": n })).await {
                // A tool that ran but reports `"success": false` failed too; its output is kept.
                Ok(value) if value.get("success") == Some(&Value::Bool(false)) => {
                    (Some(value), Err(AegisError::new(ErrorCode::ExecutionFailed, format!("{tool_name} reported that it did not succeed."))))
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
        if update(&mut |t| t.status = TicketStatus::Approved) {
            self.record_finished(id);
        } else {
            self.record_finished_as(id, TicketStatus::Approved, None);
        }
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
                self.record_approval(json!({ "event": "cancelled", "ticketId": id, "from": if queued { "queued" } else { "pending" } }));
                Ok(view)
            }
            TicketStatus::Running if ticket.plan.is_some() => {
                ticket.cancel_requested = true;
                let view = ticket.view();
                drop(store);
                self.record_approval(json!({ "event": "cancel_requested", "ticketId": id }));
                Ok(view)
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
        if origin == PlanOrigin::Agent {
            self.count_agent_request()?;
        }
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
        if origin == PlanOrigin::Agent && store.pending_from_agents(Instant::now()) >= MAX_AGENT_PENDING {
            return Err(too_many_pending());
        }
        let view = store.create(
            NewTicket {
                plugin_id: "aegis".into(),
                tool_id: "plan".into(),
                // Written by code: the name also shows in the top bar, the tray, and
                // notifications, where the supplied title would appear without its label.
                tool_name: format!("Action plan ({} step{})", shown.len(), if shown.len() == 1 { "" } else { "s" }),
                tool_description: summary,
                requires_admin: admin_steps > 0,
                args: Value::Null,
                review: None,
                plan: Some(meta),
                steps: shown,
            },
            Instant::now(),
        );
        drop(store);
        self.record_created(&view, if origin == PlanOrigin::Agent { "mcp plan" } else { "app plan" })?;
        Ok(view)
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

    // ---- approve from another device (ADR 0004 §1.2) ---------------------

    pub fn device_approval_on(&self) -> bool {
        self.device_approval.load(Ordering::SeqCst)
    }

    /// Turning device approval on needs the PIN, in the app; turning it off
    /// does not, and forgets every code.
    pub async fn set_device_approval(&self, on: bool, pin: Option<String>) -> AegisResult<()> {
        if on {
            let pin = Zeroizing::new(pin.unwrap_or_default());
            self.check_pin(&pin).await?;
            lock(&self.device_misses).clear();
            self.device_tripped.store(false, Ordering::SeqCst);
            self.device_approval.store(true, Ordering::SeqCst);
        } else {
            self.device_approval.store(false, Ordering::SeqCst);
            lock(&self.tickets).clear_device_codes();
        }
        Ok(())
    }

    /// Makes a new one-time code for a pending ticket, replacing any earlier
    /// one. App only: the code is shown once and only its hash is kept.
    pub async fn device_code(&self, id: &str) -> AegisResult<DeviceCodeView> {
        if !self.device_approval_on() {
            return Err(AegisError::invalid("Turn on Approve from another device in the MCP server tab first."));
        }
        let url = self
            .mcp_status()
            .await
            .url
            .and_then(|u| u.strip_suffix("/mcp").map(|base| format!("{base}/approve/{id}")))
            .ok_or_else(|| AegisError::invalid("The MCP server is not running, so there is no device page."))?;
        let now = Instant::now();
        let mut store = lock(&self.tickets);
        let ticket = store.get_mut(id, now).ok_or_else(ticket_not_found)?;
        if ticket.status != TicketStatus::PendingApproval {
            return Err(ticket_conflict(ticket.status));
        }
        let expires = (now + crate::tickets::DEVICE_CODE_TTL).min(ticket.created + ticket.ttl);
        let (code, device_code) = crate::tickets::DeviceCode::generate(expires);
        ticket.device_code = Some(device_code);
        drop(store);
        let expires_at = chrono::Utc::now() + chrono::Duration::from_std(expires.saturating_duration_since(now)).unwrap_or_default();
        let qr = crate::qr::encode(&url).ok_or_else(|| AegisError::failed("The QR code could not be drawn."))?;
        Ok(DeviceCodeView { code, expires_at: expires_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true), url, qr })
    }

    /// Counts an agent's request for approval, refusing it past the hourly
    /// limit. Refused requests count too, so a flood stays refused.
    fn count_agent_request(&self) -> AegisResult<()> {
        let now = Instant::now();
        let mut log = lock(&self.agent_requests);
        while log.front().is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(3600)) {
            log.pop_front();
        }
        log.push_back(now);
        // Only whether the limit is passed matters, so the newest few are enough.
        while log.len() > AGENT_REQUESTS_PER_HOUR + 1 {
            log.pop_front();
        }
        if log.len() > AGENT_REQUESTS_PER_HOUR {
            return Err(AegisError::new(
                ErrorCode::Conflict,
                format!("More than {AGENT_REQUESTS_PER_HOUR} approval requests in the last hour, so this one was refused. Wait, and ask only for what the owner needs."),
            ));
        }
        Ok(())
    }

    /// Notes a wrong device code. Too many in an hour turn the feature off.
    fn device_miss(&self, now: Instant) {
        let mut misses = lock(&self.device_misses);
        while misses.front().is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(3600)) {
            misses.pop_front();
        }
        misses.push_back(now);
        if misses.len() >= DEVICE_MISSES_PER_HOUR {
            misses.clear();
            drop(misses);
            self.device_approval.store(false, Ordering::SeqCst);
            self.device_tripped.store(true, Ordering::SeqCst);
            lock(&self.tickets).clear_device_codes();
        }
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
        Stop::Cancelled => AegisError::new(ErrorCode::Conflict, "This change was cancelled before it started."),
    }
}

fn too_many_pending() -> AegisError {
    AegisError::new(ErrorCode::Conflict, format!("{MAX_AGENT_PENDING} requests are already waiting for the owner. Wait for those to be decided or to expire."))
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

/// The approval record view covers at most this many days (its default retention).
pub const APPROVAL_RECORD_MAX_DAYS: u32 = 90;
/// Newest events shown at once.
const APPROVAL_RECORD_LIMIT: usize = 1000;

/// Longest text (titles, errors) kept in an approval record.
const RECORD_TEXT_CHARS: usize = 300;
/// Arguments larger than this are recorded by size only.
const RECORD_ARGS_BYTES: usize = 4096;

fn cut_text(text: &str) -> String {
    text.chars().take(RECORD_TEXT_CHARS).collect()
}

fn capped_args(args: &Value) -> Value {
    let size = serde_json::to_vec(args).map(|v| v.len()).unwrap_or(0);
    if size > RECORD_ARGS_BYTES {
        json!({ "omitted": format!("{size} bytes of arguments") })
    } else {
        args.clone()
    }
}

fn merge(into: &mut Value, from: &Value) {
    if let (Value::Object(into), Value::Object(from)) = (into, from) {
        for (k, v) in from {
            into.insert(k.clone(), v.clone());
        }
    }
}

async fn execute(prepared: Prepared) -> AegisResult<RunOutcome> {
    prepared.plugin.call(&prepared.tool.id, prepared.args, prepared.ctx).await.map(|result| RunOutcome::Completed { result })
}
