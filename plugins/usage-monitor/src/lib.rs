//! `usage-monitor`: resource spikes, crash correlation, and foreground-app
//! tracking during a user-defined daily watch window, plus owner-approved
//! monitors (ADR 0002).
//!
//! Recent telemetry, including monitor hits, is kept in memory (bounded
//! ring buffers) and cleared when the vault locks. The same events, plus a
//! heartbeat each minute and session start and stop, are written to the
//! plugin's encrypted, write-only history stream (ADR 0002 §5), readable
//! only with the PIN. Saved monitors live in the encrypted vault. Only
//! process names are recorded, never window titles.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use aegis_core::history::Retention;
use aegis_core::history_service::HistoryHandle;
use aegis_core::llm::LlmHandle;
use aegis_core::os::{self, eventlog};
use aegis_core::plugin_data::PluginStore;
use aegis_core::registry::{CallReview, ExitReason, Launch, LockedContext, Plugin, PluginManifest, ResumeNotice, ToolContext, UnlockContext};
use aegis_core::{AegisError, AegisResult, ErrorCode};
use async_trait::async_trait;
use chrono::{DateTime, Datelike, Local, NaiveTime, Utc};
use serde::{Deserialize, Serialize};
use monitors::{MonitorBook, MonitorHit, MonitorRuntime};
use replay::RecordedTick;
use serde_json::{json, Value};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

pub mod chat;
pub mod creator;
pub mod monitors;
pub mod replay;
pub mod rules;
pub mod timeline;

pub const COMPONENT_SPIKES: &str = "usage-monitor:resource-spikes";
pub const COMPONENT_CRASHES: &str = "usage-monitor:crash-correlator";
pub const COMPONENT_FOREGROUND: &str = "usage-monitor:active-window";
const SAMPLE_EVERY: Duration = Duration::from_secs(5);
const SPIKE_COOLDOWN: Duration = Duration::from_secs(60);
const MAX_ENTRIES: usize = 500;
const CORRELATION_WINDOW_MINUTES: i64 = 10;
/// How often the sampler re-reads the event logs that active monitors use.
const EVENT_POLL_EVERY: Duration = Duration::from_secs(15);
const EVENT_POLL_LIMIT: usize = 200;
const HEARTBEAT_EVERY: Duration = Duration::from_secs(timeline::HEARTBEAT_SECONDS);

const SYSTEM_PROMPT: &str = "You are a Windows performance and stability assistant. The user message is a JSON \
diagnostic snapshot: top processes by CPU and memory, recorded resource spikes, application crash or hang events, \
and foreground application changes, all from the same time window. Find the most likely culprit, explain the \
evidence that links the clues, and suggest safe next steps. Say when the evidence is weak. Never ask for passwords or PINs.";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WatchConfig {
    pub start_time: String,
    pub end_time: String,
    pub cpu_threshold_percent: f64,
    pub ram_threshold_mb: u64,
    pub target_processes: Vec<String>,
}

impl Default for WatchConfig {
    fn default() -> Self {
        // Equal start and end means "all day".
        Self { start_time: "00:00".into(), end_time: "00:00".into(), cpu_threshold_percent: 85.0, ram_threshold_mb: 2048, target_processes: vec![] }
    }
}

pub fn parse_hhmm(s: &str) -> Option<NaiveTime> {
    NaiveTime::parse_from_str(s.trim(), "%H:%M").ok()
}

/// Daily window; wraps past midnight when `end < start`; `start == end` is all day.
pub fn in_window(now: NaiveTime, start: NaiveTime, end: NaiveTime) -> bool {
    if start == end {
        true
    } else if start < end {
        now >= start && now < end
    } else {
        now >= start || now < end
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcSample {
    pub pid: u32,
    pub name: String,
    /// Share of total CPU capacity (0-100), not of one core.
    pub cpu_percent: f64,
    pub ram_mb: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Spike {
    pub time: String,
    pub process: String,
    pub pid: u32,
    pub kind: &'static str,
    pub cpu_percent: f64,
    pub ram_mb: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ForegroundChange {
    pub time: String,
    pub process: String,
}

/// Processes over a threshold, restricted to `target_processes` when set.
pub fn detect_spikes<'a>(samples: &'a [ProcSample], watch: &WatchConfig) -> Vec<(&'a ProcSample, &'static str)> {
    let targeted = |name: &str| {
        watch.target_processes.is_empty() || watch.target_processes.iter().any(|t| t.trim().eq_ignore_ascii_case(name))
    };
    let mut out = Vec::new();
    for s in samples.iter().filter(|s| targeted(&s.name)) {
        if s.cpu_percent >= watch.cpu_threshold_percent {
            out.push((s, "cpu"));
        }
        if s.ram_mb >= watch.ram_threshold_mb {
            out.push((s, "ram"));
        }
    }
    out
}

#[derive(Default)]
struct Telemetry {
    watch: WatchConfig,
    components: Vec<String>,
    spikes: VecDeque<Spike>,
    foreground: VecDeque<ForegroundChange>,
    last_spike: HashMap<(String, &'static str), Instant>,
    last_foreground: Option<String>,
    sampling_since: Option<String>,
    monitors: MonitorRuntime,
    hits: VecDeque<MonitorHit>,
    /// The last 30 minutes of samples, for replaying a proposed rule.
    recent: VecDeque<RecordedTick>,
    /// This plugin's history stream, once the engine handed it over.
    history: Option<HistoryHandle>,
    /// Records for the history stream, written by the sampler outside the lock.
    outbox: Vec<Value>,
    /// Running while the vault is locked: monitors only, history only.
    locked: bool,
    /// Paused from the tray: the sampler stays off until resumed.
    paused: bool,
    /// A `session_start` was written and its `session_stop` not yet.
    session_open: bool,
    /// How AegisWin was started, for the next `session_start`.
    launch: Launch,
    /// Resumed at launch: the first unlock reports the gap before it.
    resumed_at_launch: bool,
}

impl Telemetry {
    fn enabled(&self, component: &str) -> bool {
        self.components.iter().any(|c| c == component)
    }

    fn in_watch_window(&self, now_local: NaiveTime) -> bool {
        let (Some(start), Some(end)) = (parse_hhmm(&self.watch.start_time), parse_hhmm(&self.watch.end_time)) else { return false };
        in_window(now_local, start, end)
    }

    /// Runs every saved monitor against this tick and records their hits.
    /// Inside the watch window, like all other telemetry, it also keeps what
    /// the enabled components allow for replay.
    fn evaluate_monitors(&mut self, tick: &rules::Tick) {
        if !self.locked && self.in_watch_window(tick.local_time) {
            replay::remember(&mut self.recent, RecordedTick::keep(tick, &self.components));
        }
        let locked = self.locked;
        let Self { monitors, hits, outbox, history, .. } = self;
        for m in &mut monitors.active {
            if let Some(hit) = m.evaluator.tick(tick) {
                let hit = MonitorHit::new(&m.id, &m.evaluator.rule().name, hit);
                if history.is_some() {
                    outbox.push(json!({ "kind": "monitor_hit", "monitorId": hit.monitor_id, "name": hit.name, "matched": hit.matched }));
                }
                // While locked nothing is kept in memory, only in the history.
                if !locked {
                    push_capped(hits, hit);
                }
            }
        }
    }

    /// Channels and event ids the running monitors need, de-duplicated.
    fn event_needs(&self) -> Vec<(rules::Channel, Vec<u32>)> {
        group_needs(self.monitors.active.iter().flat_map(|m| rules::event_needs(m.evaluator.rule())))
    }

    /// Spikes and foreground changes, inside the watch window, while
    /// unlocked only: locked work is limited to the running monitors.
    fn record(&mut self, samples: &[ProcSample], foreground: Option<String>, now_local: NaiveTime, now: Instant) {
        if self.locked || !self.in_watch_window(now_local) {
            return;
        }
        let stamp = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        if self.enabled(COMPONENT_SPIKES) {
            let found: Vec<Spike> = detect_spikes(samples, &self.watch)
                .into_iter()
                .filter(|(s, kind)| {
                    let key = (s.name.to_ascii_lowercase(), *kind);
                    let fresh = self.last_spike.get(&key).is_none_or(|t| now.duration_since(*t) >= SPIKE_COOLDOWN);
                    if fresh {
                        self.last_spike.insert(key, now);
                    }
                    fresh
                })
                .map(|(s, kind)| Spike { time: stamp.clone(), process: s.name.clone(), pid: s.pid, kind, cpu_percent: round1(s.cpu_percent), ram_mb: s.ram_mb })
                .collect();
            for spike in found {
                if self.history.is_some() {
                    self.outbox.push(json!({ "kind": "spike", "process": spike.process, "pid": spike.pid, "type": spike.kind, "cpuPercent": spike.cpu_percent, "ramMb": spike.ram_mb }));
                }
                push_capped(&mut self.spikes, spike);
            }
        }
        if self.enabled(COMPONENT_FOREGROUND) {
            if let Some(name) = foreground {
                if self.last_foreground.as_deref() != Some(name.as_str()) {
                    self.last_foreground = Some(name.clone());
                    if self.history.is_some() {
                        self.outbox.push(json!({ "kind": "foreground", "process": name }));
                    }
                    push_capped(&mut self.foreground, ForegroundChange { time: stamp, process: name });
                }
            }
        }
    }

    fn clear(&mut self) {
        self.outbox.clear();
        self.hits.clear();
        self.recent.clear();
        self.spikes.clear();
        self.foreground.clear();
        self.last_spike.clear();
        self.last_foreground = None;
    }
}

/// Takes what the last tick queued for the history stream.
fn take_outbox(t: &mut Telemetry) -> Option<(HistoryHandle, Vec<Value>)> {
    if t.outbox.is_empty() {
        return None;
    }
    Some((t.history.clone()?, std::mem::take(&mut t.outbox)))
}

/// Writes records to the history stream. A failed write (disk full, no key
/// yet) loses those records only; the in-memory telemetry is unaffected.
fn write_history(history: &HistoryHandle, records: Vec<Value>) {
    for record in records {
        let _ = history.append(record);
    }
}

/// How far back the gap before a resume is looked for.
const RESUME_NOTICE_DAYS: i64 = 14;

fn session_start(launch: Launch) -> Value {
    let boot = DateTime::<Utc>::from_timestamp(i64::try_from(System::boot_time()).unwrap_or(0), 0)
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    json!({ "kind": "session_start", "launch": launch.as_str(), "bootTime": boot, "version": env!("CARGO_PKG_VERSION") })
}

fn push_capped<T>(buf: &mut VecDeque<T>, item: T) {
    if buf.len() >= MAX_ENTRIES {
        buf.pop_front();
    }
    buf.push_back(item);
}

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

fn refresh(sys: &mut System) {
    sys.refresh_cpu_usage();
    sys.refresh_memory();
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing().with_cpu().with_memory());
}

fn samples(sys: &System) -> Vec<ProcSample> {
    let cores = sys.cpus().len().max(1) as f64;
    sys.processes()
        .values()
        .filter(|p| p.pid().as_u32() != 0)
        .map(|p| ProcSample {
            pid: p.pid().as_u32(),
            name: p.name().to_string_lossy().into_owned(),
            cpu_percent: f64::from(p.cpu_usage()) / cores,
            ram_mb: p.memory() / (1024 * 1024),
        })
        .collect()
}

fn group_needs(needs: impl IntoIterator<Item = (rules::Channel, u32)>) -> Vec<(rules::Channel, Vec<u32>)> {
    let mut out: Vec<(rules::Channel, Vec<u32>)> = Vec::new();
    for (channel, id) in needs {
        match out.iter_mut().find(|(c, _)| *c == channel) {
            Some((_, ids)) if !ids.contains(&id) => ids.push(id),
            Some(_) => {}
            None => out.push((channel, vec![id])),
        }
    }
    out
}

fn system_memory_percent(sys: &System) -> f64 {
    let total = sys.total_memory();
    if total == 0 {
        0.0
    } else {
        sys.used_memory() as f64 * 100.0 / total as f64
    }
}

/// Reads recent entries of the event ids active monitors use. A channel that
/// cannot be read is skipped; monitors on it simply do not fire.
fn poll_events(needs: &[(rules::Channel, Vec<u32>)]) -> Vec<rules::ObservedEvent> {
    let mut out = Vec::new();
    for (channel, ids) in needs {
        let query = eventlog::EventQuery { channel: channel.as_str().into(), event_ids: ids.clone(), lookback_hours: Some(1), limit: EVENT_POLL_LIMIT, ..Default::default() };
        let Ok(records) = eventlog::query(&query) else { continue };
        out.extend(records.into_iter().filter_map(|r| {
            Some(rules::ObservedEvent {
                channel: *channel,
                time: DateTime::parse_from_rfc3339(&r.time_created).ok()?.with_timezone(&Utc),
                provider: r.provider,
                event_id: r.event_id,
                message: r.message.unwrap_or_default(),
            })
        }));
    }
    out
}

/// Running process names, for the one lookup the owner agrees to in the chat.
fn running_app_names() -> Vec<String> {
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing());
    chat::clean_app_names(sys.processes().values().map(|p| p.name().to_string_lossy().into_owned()))
}

/// Where the next LLM request would go, without sending anything.
fn destination(llm: &LlmHandle) -> Value {
    match llm.preflight() {
        Ok(e) => json!({ "offLan": !e.stays_on_lan(), "host": e.host }),
        Err(e) => json!({ "problem": e.message }),
    }
}

/// A chat reply that passed every check.
enum Checked {
    Proposal(rules::Rule, Vec<String>),
    Other(creator::Reply),
}

const MCP_REASONING_LABEL: &str = "Supplied by the requesting agent (AI-generated, may be wrong). AegisWin did not check it; the description is what the monitor does.";

fn chat_ended() -> AegisError {
    AegisError::invalid("This conversation ended (AegisWin locked, or a new one started). Start a new one.")
}

fn foreground_name(sys: &System) -> Option<String> {
    let pid = os::foreground_process_id()?;
    sys.process(Pid::from_u32(pid)).map(|p| p.name().to_string_lossy().into_owned())
}

struct Sampler {
    stop: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}

pub struct UsageMonitorPlugin {
    manifest: PluginManifest,
    telemetry: Arc<Mutex<Telemetry>>,
    sampler: Mutex<Option<Sampler>>,
    /// Serializes read-modify-write of the saved monitors.
    book: Mutex<()>,
    /// The in-app monitor chat (memory only, cleared on lock).
    chat: Mutex<Option<chat::Session>>,
    chat_generation: AtomicU64,
}

impl Default for UsageMonitorPlugin {
    fn default() -> Self {
        Self {
            manifest: PluginManifest::from_json(include_str!("../manifest.json")).expect("usage-monitor manifest.json is valid"),
            telemetry: Arc::default(),
            sampler: Mutex::new(None),
            book: Mutex::new(()),
            chat: Mutex::new(None),
            chat_generation: AtomicU64::new(0),
        }
    }
}

impl UsageMonitorPlugin {
    pub fn is_sampling(&self) -> bool {
        self.sampler.lock().unwrap().is_some()
    }

    fn start_sampler(&self) {
        let mut slot = self.sampler.lock().unwrap();
        if slot.is_some() {
            return;
        }
        let stop = Arc::new(AtomicBool::new(false));
        let telemetry = Arc::clone(&self.telemetry);
        let flag = Arc::clone(&stop);
        let opened = {
            let mut t = self.telemetry.lock().unwrap();
            match t.history.clone() {
                Some(history) if !t.session_open => {
                    t.session_open = true;
                    Some((history, t.launch))
                }
                _ => None,
            }
        };
        if let Some((history, launch)) = opened {
            write_history(&history, vec![session_start(launch)]);
        }
        let thread = std::thread::Builder::new()
            .name("usage-monitor-sampler".into())
            .spawn(move || {
                let mut sys = System::new();
                refresh(&mut sys);
                let mut events: Vec<rules::ObservedEvent> = Vec::new();
                let mut last_poll: Option<Instant> = None;
                let mut last_heartbeat = Instant::now();
                while !flag.load(Ordering::Relaxed) {
                    let mut waited = Duration::ZERO;
                    while waited < SAMPLE_EVERY && !flag.load(Ordering::Relaxed) {
                        std::thread::sleep(Duration::from_millis(250));
                        waited += Duration::from_millis(250);
                    }
                    if flag.load(Ordering::Relaxed) {
                        break;
                    }
                    refresh(&mut sys);
                    let current = samples(&sys);
                    let fg = foreground_name(&sys);
                    if last_poll.is_none_or(|t| t.elapsed() >= EVENT_POLL_EVERY) {
                        last_poll = Some(Instant::now());
                        let needs = telemetry.lock().unwrap().event_needs();
                        events = if needs.is_empty() { Vec::new() } else { poll_events(&needs) };
                    }
                    let local = Local::now();
                    let mut t = telemetry.lock().unwrap();
                    if last_heartbeat.elapsed() >= HEARTBEAT_EVERY {
                        last_heartbeat = Instant::now();
                        if t.history.is_some() {
                            t.outbox.push(json!({ "kind": "heartbeat" }));
                        }
                    }
                    t.record(&current, fg.clone(), local.time(), Instant::now());
                    t.evaluate_monitors(&rules::Tick {
                        now: Utc::now(),
                        local_time: local.time(),
                        local_weekday: local.weekday(),
                        processes: &current,
                        system_cpu_percent: f64::from(sys.global_cpu_usage()),
                        system_memory_percent: system_memory_percent(&sys),
                        foreground: fg.as_deref(),
                        events: &events,
                    });
                    let out = take_outbox(&mut t);
                    drop(t);
                    if let Some((history, records)) = out {
                        write_history(&history, records);
                    }
                }
            })
            .expect("can spawn the sampler thread");
        self.telemetry.lock().unwrap().sampling_since = Some(Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
        *slot = Some(Sampler { stop, thread });
    }

    /// Stops the sampler thread, if it runs.
    fn join_sampler(&self) {
        if let Some(sampler) = self.sampler.lock().unwrap().take() {
            sampler.stop.store(true, Ordering::Relaxed);
            let _ = sampler.thread.join();
        }
    }

    /// Stops the sampler and writes what it queued, then `marker` if a
    /// session is open: `session_stop` ends the session, `paused` keeps it.
    fn halt(&self, marker: Value) {
        self.join_sampler();
        let ends = marker["kind"] == "session_stop";
        let (history, records) = {
            let mut t = self.telemetry.lock().unwrap();
            let mut records = std::mem::take(&mut t.outbox);
            if t.session_open {
                t.session_open = !ends;
                records.push(marker);
            }
            (t.history.clone(), records)
        };
        if let Some(history) = history {
            write_history(&history, records);
        }
    }

    /// Stops the sampler and ends the session with `reason`.
    fn stop_sampler(&self, reason: &str) {
        self.halt(json!({ "kind": "session_stop", "reason": reason }));
    }

    /// What `on_lock` does, for callers that already hold `book`.
    fn stop_everything(&self) {
        self.chat_generation.fetch_add(1, Ordering::SeqCst);
        *self.chat.lock().unwrap() = None;
        self.stop_sampler(timeline::STOP_LOCKED);
        let mut t = self.telemetry.lock().unwrap();
        t.clear();
        t.sampling_since = None;
        t.monitors = MonitorRuntime::default();
        t.locked = false;
    }

    /// Tells the engine what runs while locked: the running monitors and
    /// the components they need. Nothing running, nothing declared.
    fn sync_runtime(&self) {
        let (history, section) = {
            let t = self.telemetry.lock().unwrap();
            let monitors: Vec<Value> = t.monitors.active.iter().map(|m| json!({ "id": m.id, "rule": m.evaluator.rule() })).collect();
            let section = (!monitors.is_empty()).then(|| json!({ "monitors": monitors, "components": t.components }));
            (t.history.clone(), section)
        };
        if let Some(history) = history {
            let _ = history.set_runtime(section);
        }
    }

    fn configure(&self, args: &Value) -> AegisResult<Value> {
        let mut t = self.telemetry.lock().unwrap();
        let mut watch = t.watch.clone();
        if let Some(s) = args.get("startTime").and_then(Value::as_str) {
            watch.start_time = s.trim().to_owned();
        }
        if let Some(s) = args.get("endTime").and_then(Value::as_str) {
            watch.end_time = s.trim().to_owned();
        }
        if parse_hhmm(&watch.start_time).is_none() || parse_hhmm(&watch.end_time).is_none() {
            return Err(AegisError::invalid("startTime and endTime must be 24-hour HH:MM, e.g. 21:00"));
        }
        if let Some(n) = args.get("cpuThresholdPercent").and_then(Value::as_f64) {
            watch.cpu_threshold_percent = n;
        }
        if let Some(n) = args.get("ramThresholdMb").and_then(Value::as_u64) {
            watch.ram_threshold_mb = n;
        }
        if let Some(list) = args.get("targetProcesses").and_then(Value::as_array) {
            watch.target_processes = list.iter().filter_map(Value::as_str).map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()).collect();
        }
        t.watch = watch.clone();
        Ok(json!({ "watch": watch, "note": "The watch window applies while AegisWin is running and unlocked." }))
    }

    /// Loads the saved monitors and (re)builds what runs.
    fn load_monitors(&self, store: Option<&PluginStore>, components: &[String]) {
        let _serial = self.book.lock().unwrap_or_else(|e| e.into_inner());
        let runtime = match store.map(|s| s.get(monitors::STORE_KEY)) {
            None => MonitorRuntime::failed("no plugin data store".into()),
            // Locked again before this ran: start nothing.
            Some(Err(e)) if e.code == ErrorCode::VaultLocked => return,
            Some(Err(e)) => MonitorRuntime::failed(e.message),
            Some(Ok(value)) => match MonitorBook::from_store(value) {
                Ok(book) => MonitorRuntime::build(&book, components),
                Err(e) => MonitorRuntime::failed(e),
            },
        };
        self.telemetry.lock().unwrap().monitors = runtime;
        self.sync_runtime();
        self.refresh_sampler();
    }

    /// The sampler is wanted while a monitor runs or, unlocked, a sampling
    /// component is on.
    fn sampler_wanted(t: &Telemetry) -> bool {
        !t.monitors.active.is_empty() || (!t.locked && [COMPONENT_SPIKES, COMPONENT_FOREGROUND].iter().any(|c| t.enabled(c)))
    }

    /// Starts the sampler when it is wanted and not paused from the tray.
    fn start_sampler_if_needed(&self) {
        let needed = {
            let t = self.telemetry.lock().unwrap();
            !t.paused && Self::sampler_wanted(&t)
        };
        if needed {
            self.start_sampler();
        }
    }

    /// After the monitors changed: starts the sampler when needed, or ends
    /// the session when nothing needs it any more (the last monitor was
    /// paused or deleted with no sampling component on).
    fn refresh_sampler(&self) {
        let unwanted = {
            let t = self.telemetry.lock().unwrap();
            !t.paused && !Self::sampler_wanted(&t)
        };
        if unwanted {
            self.stop_sampler(timeline::STOP_LOCKED);
        } else {
            self.start_sampler_if_needed();
        }
    }

    /// Applies `change` to the saved monitors, saves them, and restarts the
    /// runtime from what was saved. Nothing changes if any step fails.
    fn change_monitors<R>(&self, ctx: &ToolContext, change: impl FnOnce(&mut MonitorBook) -> Result<R, String>) -> AegisResult<R> {
        let store = ctx.store()?;
        let _serial = self.book.lock().unwrap_or_else(|e| e.into_inner());
        let mut book = MonitorBook::from_store(store.get(monitors::STORE_KEY)?).map_err(AegisError::failed)?;
        let out = change(&mut book).map_err(AegisError::invalid)?;
        store.set(monitors::STORE_KEY, book.to_value())?;
        self.telemetry.lock().unwrap().monitors = MonitorRuntime::build(&book, &ctx.enabled_components);
        self.sync_runtime();
        self.refresh_sampler();
        Ok(out)
    }

    fn validated(args: &Value, ctx: &ToolContext) -> Result<rules::Rule, Vec<String>> {
        rules::validate(args.get("rule").unwrap_or(&Value::Null), &ctx.enabled_components)
    }

    async fn propose(&self, args: &Value, ctx: &ToolContext) -> AegisResult<Value> {
        let rule = match Self::validated(args, ctx) {
            Ok(rule) => rule,
            Err(problems) => return Ok(json!({ "valid": false, "problems": problems, "activated": false })),
        };
        let reasoning = args.get("reasoning").and_then(Value::as_str).map(rules::clean_text).filter(|r| !r.is_empty());
        Ok(self.review_proposal(&rule, reasoning.map(|t| (t, MCP_REASONING_LABEL))).await)
    }

    /// How a rule that nothing has started is shown: the generated
    /// description and privacy flags, the replay, and the labelled reasoning.
    async fn review_proposal(&self, rule: &rules::Rule, reasoning: Option<(String, &'static str)>) -> Value {
        let recent: Vec<RecordedTick> = self.telemetry.lock().unwrap().recent.iter().cloned().collect();
        let needs = group_needs(rules::event_needs(rule));
        let events = if recent.is_empty() || needs.is_empty() {
            Vec::new()
        } else {
            tokio::task::spawn_blocking(move || poll_events(&needs)).await.unwrap_or_default()
        };
        json!({
            "valid": true,
            "activated": false,
            "rule": rule,
            "review": monitors::review(rule),
            "replay": replay::replay(rule, &recent, &events),
            "reasoning": reasoning.map(|(text, label)| json!({
                "warning": creator::mentions_unwatched(&text, rule).then_some(creator::INCONSISTENT),
                "text": text,
                "label": label,
            })),
            "next": "Nothing runs yet. To start it, call activate_monitor with this exact rule. That needs the owner's PIN.",
        })
    }

    // ---- in-app monitor chat (ADR 0002 §3) --------------------------------

    fn chat_start(&self, args: &Value) -> AegisResult<()> {
        let generation = self.chat_generation.fetch_add(1, Ordering::SeqCst) + 1;
        let session = chat::Session::new(generation, args["request"].as_str().unwrap_or_default()).map_err(AegisError::invalid)?;
        *self.chat.lock().unwrap() = Some(session);
        Ok(())
    }

    /// Takes the owner's answers or consent, then runs the AI's turn.
    async fn chat_reply(&self, args: &Value) -> AegisResult<bool> {
        let propose_now = args["proposeNow"].as_bool().unwrap_or(false);
        let share = args.get("shareRunningApps").and_then(Value::as_bool);
        let (generation, awaiting) = {
            let guard = self.chat.lock().unwrap();
            let s = guard.as_ref().ok_or_else(|| AegisError::invalid("There is no monitor conversation. Start one first."))?;
            (s.generation, s.awaiting)
        };
        let apps = match awaiting {
            chat::Awaiting::Done => return Err(AegisError::invalid("This conversation is finished. Start a new one.")),
            chat::Awaiting::AppsConsent => match share.or(propose_now.then_some(false)) {
                Some(true) => Some(tokio::task::spawn_blocking(running_app_names).await.unwrap_or_default()),
                Some(false) => None,
                None => return Err(AegisError::invalid("Say whether the AI may see running app names (shareRunningApps).")),
            },
            chat::Awaiting::Answers | chat::Awaiting::Turn => None,
        };
        let mut guard = self.chat.lock().unwrap();
        let s = guard.as_mut().filter(|s| s.generation == generation).ok_or_else(chat_ended)?;
        match awaiting {
            chat::Awaiting::AppsConsent => s.running_apps = apps,
            chat::Awaiting::Answers => {
                let answers: Vec<String> = args["answers"].as_array().into_iter().flatten().map(|a| a.as_str().unwrap_or_default().to_owned()).collect();
                s.record_answers(&answers).map_err(AegisError::invalid)?;
            }
            chat::Awaiting::Turn | chat::Awaiting::Done => {}
        }
        s.awaiting = chat::Awaiting::Turn;
        Ok(propose_now)
    }

    /// One AI turn: at most two LLM requests (one retry), each checked
    /// against the reply format, the conversation, and the rule language.
    async fn chat_turn(&self, ctx: &ToolContext, propose_now: bool) -> AegisResult<Value> {
        let llm = ctx.llm()?;
        let session = self.chat.lock().unwrap().clone().ok_or_else(chat_ended)?;
        let must = session.must_conclude(propose_now);
        let mut problem: Option<String> = None;
        let mut sent = Value::Null;
        for _ in 0..2 {
            let answer = llm.complete(chat::SYSTEM_PROMPT, session.payload(&ctx.enabled_components, must, problem.as_deref())).await?;
            sent = json!({ "offLan": answer.off_lan, "host": answer.endpoint_host, "model": answer.model, "scrubbed": answer.scrubbed });
            let checked = creator::parse_reply(&answer.text).and_then(|reply| session.accept(&reply, must).map(|()| reply)).and_then(|reply| match reply {
                creator::Reply::Proposal { rule, reasoning } => rules::validate(&rule, &ctx.enabled_components)
                    .map(|rule| Checked::Proposal(rule, reasoning))
                    .map_err(|p| format!("the rule is not valid: {}", p.join("; "))),
                other => Ok(Checked::Other(other)),
            });
            match checked {
                Ok(checked) => {
                    let mut view = self.chat_apply(session.generation, checked).await?;
                    view["sentTo"] = sent;
                    view["nextSendGoesTo"] = destination(llm);
                    return Ok(view);
                }
                Err(p) => problem = Some(p),
            }
        }
        // The owner can reply again (or press "Propose now") to retry.
        Ok(json!({ "status": "failed", "message": chat::UNUSABLE, "problem": problem, "sentTo": sent, "nextSendGoesTo": destination(llm) }))
    }

    async fn chat_apply(&self, generation: u64, checked: Checked) -> AegisResult<Value> {
        let proposal = match &checked {
            Checked::Proposal(rule, bullets) => Some(self.review_proposal(rule, Some((bullets.join("\n"), chat::REASONING_LABEL))).await),
            Checked::Other(_) => None,
        };
        let mut guard = self.chat.lock().unwrap();
        let s = guard.as_mut().filter(|s| s.generation == generation).ok_or_else(chat_ended)?;
        // Two replies sent at once both run a turn; only the first result counts.
        if s.awaiting != chat::Awaiting::Turn {
            return Err(AegisError::invalid("The conversation already moved on. Show its latest step."));
        }
        Ok(match checked {
            Checked::Proposal(..) => {
                s.awaiting = chat::Awaiting::Done;
                json!({ "status": "proposal", "proposal": proposal })
            }
            Checked::Other(creator::Reply::Questions(questions)) => {
                let (kept, dropped) = creator::filter_questions(questions);
                s.rounds.push(chat::Round { questions: kept.clone(), answers: Vec::new() });
                s.awaiting = chat::Awaiting::Answers;
                json!({
                    "status": "questions",
                    "questions": kept.iter().map(|q| json!({ "text": q.text, "choices": q.choices })).collect::<Vec<_>>(),
                    "dropped": dropped.iter().map(|d| format!("A question from the AI was not shown because {}.", d.reason)).collect::<Vec<_>>(),
                    "round": s.rounds.len(),
                    "maxRounds": creator::MAX_ROUNDS,
                    "note": "You can skip any question, or ask for a proposal now.",
                })
            }
            Checked::Other(creator::Reply::RequestRunningApps { reason }) => {
                s.apps_requested = true;
                s.awaiting = chat::Awaiting::AppsConsent;
                json!({ "status": "requestRunningApps", "consent": "Let the AI see running app names?", "reason": reason, "note": "Only process names are sent, once. Nothing is sent unless you agree." })
            }
            Checked::Other(creator::Reply::Unsupported { reason }) => {
                s.awaiting = chat::Awaiting::Done;
                json!({ "status": "unsupported", "reason": reason })
            }
            Checked::Other(creator::Reply::Proposal { .. }) => unreachable!("proposals are checked into Checked::Proposal"),
        })
    }

    fn activate(&self, args: &Value, ctx: &ToolContext) -> AegisResult<Value> {
        let rule = Self::validated(args, ctx).map_err(|p| AegisError::invalid(p.join("; ")))?;
        let replace = args.get("replaceId").and_then(Value::as_str);
        let id = self.change_monitors(ctx, |book| book.activate(&rule, replace))?;
        Ok(json!({ "id": id, "replaced": replace.is_some(), "running": true, "review": monitors::review(&rule) }))
    }

    fn list(&self, ctx: &ToolContext) -> AegisResult<Value> {
        let book = MonitorBook::from_store(ctx.store()?.get(monitors::STORE_KEY)?).map_err(AegisError::failed)?;
        let t = self.telemetry.lock().unwrap();
        let hits: Vec<MonitorHit> = t.hits.iter().cloned().collect();
        Ok(json!({
            "monitors": book.monitors.iter().map(|m| monitors::view(m, &t.monitors, &hits)).collect::<Vec<_>>(),
            "maxMonitors": rules::MAX_MONITORS,
            "loadError": t.monitors.load_error,
            "historyRetention": ctx.history.as_ref().and_then(|h| h.retention().ok()),
            "note": "Monitors watch and record while AegisWin is running, also while it is locked (then to the encrypted history only). They never run anything or change Windows.",
        }))
    }

    async fn snapshot(&self, label: String) -> AegisResult<Value> {
        let (watch, components, spikes, foreground, since, hits) = {
            let t = self.telemetry.lock().unwrap();
            (
                t.watch.clone(),
                t.components.clone(),
                t.spikes.iter().cloned().collect::<Vec<_>>(),
                t.foreground.iter().cloned().collect::<Vec<_>>(),
                t.sampling_since.clone(),
                t.hits.iter().cloned().collect::<Vec<_>>(),
            )
        };
        let enabled = |c: &str| components.iter().any(|x| x == c);

        let (system, mut current) = tokio::task::spawn_blocking(|| {
            let mut sys = System::new();
            refresh(&mut sys);
            std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL.max(Duration::from_millis(500)));
            refresh(&mut sys);
            let system = json!({
                "cpuPercent": round1(f64::from(sys.global_cpu_usage())),
                "logicalCpus": sys.cpus().len(),
                "memoryUsedMb": sys.used_memory() / (1024 * 1024),
                "memoryTotalMb": sys.total_memory() / (1024 * 1024),
                "uptimeHours": round1(System::uptime() as f64 / 3600.0),
            });
            (system, samples(&sys))
        })
        .await
        .map_err(|e| AegisError::failed(e.to_string()))?;

        current.sort_by(|a, b| b.cpu_percent.total_cmp(&a.cpu_percent));
        let top_cpu: Vec<Value> = current.iter().take(10).map(|s| json!({ "process": s.name, "pid": s.pid, "cpuPercent": round1(s.cpu_percent), "ramMb": s.ram_mb })).collect();
        current.sort_by(|a, b| b.ram_mb.cmp(&a.ram_mb));
        let top_ram: Vec<Value> = current.iter().take(10).map(|s| json!({ "process": s.name, "pid": s.pid, "cpuPercent": round1(s.cpu_percent), "ramMb": s.ram_mb })).collect();

        let crashes = if enabled(COMPONENT_CRASHES) {
            let query = eventlog::EventQuery { channel: "Application".into(), event_ids: vec![1000, 1002], lookback_hours: Some(24), limit: 50, ..Default::default() };
            match tokio::task::spawn_blocking(move || eventlog::query(&query)).await {
                Ok(Ok(events)) => json!(correlate(&events, &spikes)),
                Ok(Err(e)) => json!({ "error": e.to_string() }),
                Err(e) => json!({ "error": e.to_string() }),
            }
        } else {
            json!("component disabled")
        };

        let now = Local::now().time();
        let inside = matches!((parse_hhmm(&watch.start_time), parse_hhmm(&watch.end_time)), (Some(s), Some(e)) if in_window(now, s, e));
        Ok(json!({
            "label": label,
            "capturedAt": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "watch": watch,
            "insideWatchWindow": inside,
            "samplingSince": since,
            "system": system,
            "topByCpu": top_cpu,
            "topByMemory": top_ram,
            "spikes": if enabled(COMPONENT_SPIKES) { json!(spikes) } else { json!("component disabled") },
            "crashes": crashes,
            "foregroundChanges": if enabled(COMPONENT_FOREGROUND) { json!(foreground) } else { json!("component disabled") },
            "monitorHits": hits,
        }))
    }
}

impl UsageMonitorPlugin {
    /// Decrypts the last `days` days and builds the timeline with gaps. The
    /// System log is read for gap evidence only.
    async fn read_history(&self, args: &Value, ctx: &ToolContext) -> AegisResult<Value> {
        let days = args["days"].as_u64().and_then(|n| u32::try_from(n).ok()).unwrap_or(1).clamp(1, timeline::MAX_DAYS);
        let limit = args["limit"].as_u64().and_then(|n| usize::try_from(n).ok()).unwrap_or(timeline::DEFAULT_LIMIT).clamp(1, timeline::MAX_LIMIT);
        let history = ctx.history()?.clone();
        let now = Utc::now();
        let since = (now.date_naive() - chrono::Days::new(u64::from(days - 1))).and_hms_opt(0, 0, 0).expect("midnight exists").and_utc();
        let retention = history.retention()?;
        let (read, events) = tokio::task::spawn_blocking(move || {
            let read = history.read(Some(since.date_naive()));
            let events = eventlog::query(&timeline::evidence_query(days)).unwrap_or_default();
            (read, events)
        })
        .await
        .map_err(|e| AegisError::failed(e.to_string()))?;
        let mut view = timeline::view(&read?, &events, since, now, limit);
        view["days"] = json!(days);
        view["retention"] = json!(retention);
        view["note"] = json!("Gaps are worked out from the records; System log events are shown as evidence when they fall inside a gap. Values are never filled in across a gap.");
        Ok(view)
    }
}

/// Attaches to each crash/hang event the spikes of the same process recorded
/// in the preceding ten minutes.
pub fn correlate(events: &[eventlog::EventRecord], spikes: &[Spike]) -> Vec<Value> {
    events
        .iter()
        .map(|e| {
            let message = e.message.clone().unwrap_or_default();
            let lower = message.to_ascii_lowercase();
            let crash_time = DateTime::parse_from_rfc3339(&e.time_created).ok();
            let related: Vec<&Spike> = spikes
                .iter()
                .filter(|s| lower.contains(&s.process.to_ascii_lowercase()))
                .filter(|s| match (crash_time, DateTime::parse_from_rfc3339(&s.time).ok()) {
                    (Some(c), Some(t)) => t <= c && (c - t).num_minutes() <= CORRELATION_WINDOW_MINUTES,
                    _ => false,
                })
                .collect();
            json!({
                "timeCreated": e.time_created,
                "eventId": e.event_id,
                "provider": e.provider,
                "kind": if e.event_id == 1002 { "hang" } else { "crash" },
                "message": message.chars().take(600).collect::<String>(),
                "relatedSpikes": related,
            })
        })
        .collect()
}

#[async_trait]
impl Plugin for UsageMonitorPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn call(&self, tool: &str, args: Value, ctx: ToolContext) -> AegisResult<Value> {
        self.telemetry.lock().unwrap().components = ctx.enabled_components.clone();
        match tool {
            "configure_watch_window" => self.configure(&args),
            "propose_monitor" => self.propose(&args, &ctx).await,
            "monitor_chat_start" => {
                ctx.llm()?;
                self.chat_start(&args)?;
                self.chat_turn(&ctx, false).await
            }
            "monitor_chat_reply" => {
                ctx.llm()?;
                let propose_now = self.chat_reply(&args).await?;
                self.chat_turn(&ctx, propose_now).await
            }
            "monitor_chat_cancel" => {
                self.chat_generation.fetch_add(1, Ordering::SeqCst);
                let had = self.chat.lock().unwrap().take().is_some();
                Ok(json!({ "cancelled": had }))
            }
            "activate_monitor" => self.activate(&args, &ctx),
            "list_monitors" => self.list(&ctx),
            "pause_monitor" => {
                let (id, paused) = (args["id"].as_str().unwrap_or_default().to_owned(), args["paused"].as_bool().unwrap_or(true));
                self.change_monitors(&ctx, |book| book.set_paused(&id, paused))?;
                Ok(json!({ "id": id, "paused": paused }))
            }
            "delete_monitor" => {
                let id = args["id"].as_str().unwrap_or_default().to_owned();
                let removed = self.change_monitors(&ctx, |book| book.delete(&id))?;
                Ok(json!({ "id": removed.id, "deleted": true }))
            }
            "capture_diagnostic_snapshot" => {
                let label = args.get("windowLabel").and_then(Value::as_str).unwrap_or("Current diagnostic window").to_owned();
                self.snapshot(label).await
            }
            "analyze_clues_with_llm" => {
                let snapshot = args.get("snapshot").cloned().unwrap_or(Value::Null);
                let answer = ctx.llm()?.complete(SYSTEM_PROMPT, snapshot).await?;
                Ok(json!({ "analysis": answer }))
            }
            "purge_telemetry_history" => {
                let removed = {
                    let mut t = self.telemetry.lock().unwrap();
                    let removed = t.spikes.len() + t.foreground.len() + t.hits.len() + t.recent.len();
                    t.clear();
                    removed
                };
                let files = ctx.history()?.purge()?;
                Ok(json!({ "purged": true, "entriesRemoved": removed, "historyFilesRemoved": files, "newKey": true }))
            }
            "read_monitor_history" => self.read_history(&args, &ctx).await,
            "configure_history_retention" => {
                let retention = Retention {
                    max_days: args["maxDays"].as_u64().and_then(|n| u32::try_from(n).ok()).unwrap_or(0),
                    max_mb: args["maxMb"].as_u64().and_then(|n| u32::try_from(n).ok()).unwrap_or(0),
                };
                ctx.history()?.set_retention(retention)?;
                Ok(json!({ "retention": retention, "note": "Older history beyond these limits is deleted, oldest files first." }))
            }
            other => Err(AegisError::new(ErrorCode::UnknownTool, format!("usage-monitor has no tool '{other}'"))),
        }
    }

    fn on_unlock(&self, ctx: &UnlockContext) {
        let enabled_components = &ctx.enabled_components;
        {
            let mut t = self.telemetry.lock().unwrap();
            t.components = enabled_components.clone();
            t.history = ctx.history.clone();
            // A sampler still running from the locked state carries on, now unlocked.
            t.locked = false;
            t.paused = ctx.paused;
        }
        self.load_monitors(ctx.store.as_ref(), enabled_components);
    }

    /// After a resume at launch, the first unlock reports when monitoring
    /// was not running before it, read from the last two weeks of history
    /// (ADR 0002 §6), so a large history does not hold up the unlock.
    fn resume_notice(&self) -> Option<ResumeNotice> {
        let history = {
            let mut t = self.telemetry.lock().unwrap();
            if !std::mem::take(&mut t.resumed_at_launch) {
                return None;
            }
            t.history.clone()?
        };
        let since = (Utc::now() - chrono::Duration::days(RESUME_NOTICE_DAYS)).date_naive();
        let read = history.read(Some(since)).ok()?;
        let gap = timeline::gap_before_last_start(&timeline::ordered(&read.records))?;
        Some(ResumeNotice { from: Some(gap.from), to: gap.to?, label: gap.label })
    }

    fn background_active(&self) -> bool {
        !self.telemetry.lock().unwrap().monitors.active.is_empty()
    }

    fn on_lock(&self) {
        // Waits for a monitor change in progress, so it cannot restart the
        // sampler after this. Later changes fail: the vault is already locked.
        let _serial = self.book.lock().unwrap_or_else(|e| e.into_inner());
        self.stop_everything();
    }

    /// *Locked, monitoring* (ADR 0002 §4): drops what `on_lock` drops (chat,
    /// in-memory telemetry, the watch window's data) and keeps only the
    /// monitors the vault's runtime section lists, writing their hits and a
    /// heartbeat to the encrypted history.
    fn run_locked(&self, ctx: &LockedContext) -> bool {
        let _serial = self.book.lock().unwrap_or_else(|e| e.into_inner());
        let (declared, components) = MonitorRuntime::from_runtime(&ctx.runtime);
        if declared.active.is_empty() {
            self.stop_everything();
            return false;
        }
        self.chat_generation.fetch_add(1, Ordering::SeqCst);
        *self.chat.lock().unwrap() = None;
        {
            let mut t = self.telemetry.lock().unwrap();
            t.clear();
            t.history = Some(ctx.history.clone());
            t.locked = true;
            t.paused = ctx.paused;
            if let Some(launch) = ctx.launch {
                t.launch = launch;
                t.resumed_at_launch = true;
            }
            // Keep the running evaluators (and their cooldowns) when they are the declared ones.
            let ids = |rt: &MonitorRuntime| rt.active.iter().map(|m| m.id.clone()).collect::<Vec<_>>();
            if ids(&t.monitors) != ids(&declared) {
                t.monitors = declared;
            }
            t.components = components;
        }
        if ctx.paused {
            self.join_sampler();
        } else {
            self.start_sampler_if_needed();
        }
        true
    }

    /// Tray pause: the sampler stops and `paused` is recorded; resuming
    /// records `resumed` and starts it again. The session stays open.
    fn set_paused(&self, paused: bool) {
        let _serial = self.book.lock().unwrap_or_else(|e| e.into_inner());
        {
            let mut t = self.telemetry.lock().unwrap();
            if t.paused == paused {
                return;
            }
            t.paused = paused;
        }
        if paused {
            self.halt(json!({ "kind": "paused" }));
            return;
        }
        let history = {
            let t = self.telemetry.lock().unwrap();
            t.session_open.then(|| t.history.clone()).flatten()
        };
        if let Some(history) = history {
            write_history(&history, vec![json!({ "kind": "resumed" })]);
        }
        self.start_sampler_if_needed();
    }

    /// Ends the session with why AegisWin is exiting.
    fn on_exit(&self, reason: ExitReason) {
        let _serial = self.book.lock().unwrap_or_else(|e| e.into_inner());
        self.stop_sampler(match reason {
            ExitReason::Quit => timeline::STOP_QUIT,
            ExitReason::Shutdown => timeline::STOP_SHUTDOWN,
        });
    }

    /// The approval request for `activate_monitor` shows the description
    /// AegisWin writes from the rule, not only the raw JSON (ADR 0002 §1).
    fn review_call(&self, tool: &str, args: &Value, enabled_components: &[String]) -> Option<CallReview> {
        if tool != "activate_monitor" {
            return None;
        }
        Some(match rules::validate(&args["rule"], enabled_components) {
            Ok(rule) => {
                let mut lines = rules::describe(&rule);
                if let Some(id) = args.get("replaceId").and_then(Value::as_str) {
                    lines.insert(0, format!("Replaces the rule of monitor {}.", rules::echo(id, 20)));
                }
                let warnings = rules::privacy_flags(&rule).into_iter().map(|f| f.explain().to_owned()).collect();
                CallReview { lines, warnings }
            }
            Err(problems) => CallReview { lines: Vec::new(), warnings: vec![format!("This rule is not valid, so approving it will fail: {}", problems.join("; "))] },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn monitor_runtime(trigger: Value) -> MonitorRuntime {
        let rule = json!({
            "version": 1, "name": "Busy", "schedule": { "startTime": "00:00", "endTime": "00:00" },
            "trigger": trigger, "cooldownSeconds": 60, "notify": "none"
        });
        let components = vec![COMPONENT_SPIKES.to_owned(), COMPONENT_CRASHES.to_owned()];
        let mut book = MonitorBook::default();
        book.activate(&rules::validate(&rule, &components).unwrap(), None).unwrap();
        MonitorRuntime::build(&book, &components)
    }

    #[test]
    fn the_sampler_tick_records_monitor_hits() {
        let mut t = Telemetry { monitors: monitor_runtime(json!({ "any": [{ "type": "system_cpu", "atLeastPercent": 50, "forSeconds": 5 }] })), ..Default::default() };
        let now = Utc.with_ymd_and_hms(2026, 11, 7, 12, 0, 0).unwrap();
        let tick = |cpu: f64| rules::Tick {
            now,
            local_time: now.time(),
            local_weekday: now.weekday(),
            processes: &[],
            system_cpu_percent: cpu,
            system_memory_percent: 10.0,
            foreground: None,
            events: &[],
        };
        t.evaluate_monitors(&tick(20.0));
        assert!(t.hits.is_empty());
        t.evaluate_monitors(&tick(80.0));
        assert_eq!(t.hits.len(), 1);
        assert_eq!((t.hits[0].monitor_id.as_str(), t.hits[0].name.as_str()), ("m1", "Busy"));
        assert_eq!(t.recent.len(), 2, "each tick is kept for replay");
        t.clear();
        assert!(t.hits.is_empty() && t.recent.is_empty(), "purge and lock clear hits and the replay history");

        // Outside the watch window monitors still run, but nothing is kept for replay.
        t.watch.start_time = "08:00".into();
        t.watch.end_time = "09:00".into();
        t.evaluate_monitors(&tick(20.0));
        assert!(t.recent.is_empty());
    }

    #[test]
    fn while_locked_nothing_is_kept_in_memory() {
        let mut t = Telemetry { monitors: monitor_runtime(json!({ "any": [{ "type": "system_cpu", "atLeastPercent": 50, "forSeconds": 5 }] })), locked: true, ..Default::default() };
        t.components = vec![COMPONENT_SPIKES.into(), COMPONENT_FOREGROUND.into()];
        let now = Utc.with_ymd_and_hms(2026, 11, 7, 12, 0, 0).unwrap();
        let busy = [ProcSample { pid: 7, name: "game.exe".into(), cpu_percent: 99.0, ram_mb: 9000 }];
        let tick = rules::Tick {
            now,
            local_time: now.time(),
            local_weekday: now.weekday(),
            processes: &busy,
            system_cpu_percent: 90.0,
            system_memory_percent: 10.0,
            foreground: Some("game.exe"),
            events: &[],
        };
        t.record(&busy, Some("game.exe".into()), now.time(), Instant::now());
        t.evaluate_monitors(&tick);
        t.evaluate_monitors(&tick);
        assert!(t.spikes.is_empty() && t.foreground.is_empty(), "no spikes or foreground apps while locked");
        assert!(t.hits.is_empty() && t.recent.is_empty(), "hits go to the history only, nothing is kept for replay");
        assert!(t.outbox.is_empty(), "without a history stream nothing is queued");
    }

    #[test]
    fn only_the_event_ids_monitors_use_are_polled() {
        let t = Telemetry {
            monitors: monitor_runtime(json!({ "any": [
                { "type": "crash", "process": "game.exe" },
                { "type": "event", "channel": "Application", "eventId": 1000 },
                { "type": "event", "channel": "System", "eventId": 41 }
            ] })),
            ..Default::default()
        };
        assert_eq!(t.event_needs(), vec![(rules::Channel::Application, vec![1000, 1002]), (rules::Channel::System, vec![41])]);
        assert!(Telemetry::default().event_needs().is_empty(), "no monitors, no event polling");
    }

    fn t(s: &str) -> NaiveTime {
        parse_hhmm(s).unwrap()
    }

    #[test]
    fn watch_windows_wrap_midnight() {
        assert!(in_window(t("22:00"), t("21:00"), t("23:00")));
        assert!(!in_window(t("23:00"), t("21:00"), t("23:00")));
        assert!(in_window(t("01:00"), t("22:00"), t("02:00")));
        assert!(!in_window(t("12:00"), t("22:00"), t("02:00")));
        assert!(in_window(t("12:00"), t("00:00"), t("00:00")));
        assert!(parse_hhmm("25:00").is_none() && parse_hhmm("9pm").is_none());
    }

    fn sample(name: &str, cpu: f64, ram: u64) -> ProcSample {
        ProcSample { pid: 1, name: name.into(), cpu_percent: cpu, ram_mb: ram }
    }

    #[test]
    fn records_spikes_once_per_cooldown_and_only_for_targets() {
        let mut tel = Telemetry { components: vec![COMPONENT_SPIKES.into(), COMPONENT_FOREGROUND.into()], ..Default::default() };
        tel.watch.target_processes = vec!["Game.exe".into()];
        let procs = [sample("game.exe", 95.0, 4096), sample("other.exe", 99.0, 9000)];
        let now = Instant::now();
        tel.record(&procs, Some("game.exe".into()), t("12:00"), now);
        tel.record(&procs, Some("game.exe".into()), t("12:00"), now + Duration::from_secs(5));
        assert_eq!(tel.spikes.len(), 2, "cpu + ram for game.exe only, once");
        assert!(tel.spikes.iter().all(|s| s.process == "game.exe"));
        assert_eq!(tel.foreground.len(), 1, "foreground is recorded on change only");
        tel.record(&procs, Some("explorer.exe".into()), t("12:00"), now + SPIKE_COOLDOWN);
        assert_eq!(tel.spikes.len(), 4);
        assert_eq!(tel.foreground.len(), 2);
    }

    #[test]
    fn nothing_is_recorded_outside_the_window_or_with_components_off() {
        let mut tel = Telemetry { components: vec![COMPONENT_SPIKES.into()], ..Default::default() };
        tel.watch.start_time = "21:00".into();
        tel.watch.end_time = "23:00".into();
        tel.record(&[sample("a.exe", 99.0, 1)], Some("a.exe".into()), t("12:00"), Instant::now());
        assert!(tel.spikes.is_empty());
        tel.record(&[sample("a.exe", 99.0, 1)], Some("a.exe".into()), t("22:00"), Instant::now());
        assert_eq!(tel.spikes.len(), 1);
        assert!(tel.foreground.is_empty(), "active-window component is off");
    }

    #[test]
    fn correlates_crashes_with_recent_spikes_of_the_same_process() {
        let crash = eventlog::EventRecord {
            record_id: 1,
            time_created: "2026-01-01T12:10:00Z".into(),
            provider: "Application Error".into(),
            event_id: 1000,
            level: 2,
            level_name: "Error",
            message: Some("Faulting application name: Game.exe, version: 1.0".into()),
        };
        let spike = |time: &str, process: &str| Spike { time: time.into(), process: process.into(), pid: 1, kind: "ram", cpu_percent: 0.0, ram_mb: 9000 };
        let spikes = [spike("2026-01-01T12:05:00Z", "game.exe"), spike("2026-01-01T11:00:00Z", "game.exe"), spike("2026-01-01T12:06:00Z", "other.exe")];
        let out = correlate(&[crash], &spikes);
        assert_eq!(out[0]["kind"], "crash");
        assert_eq!(out[0]["relatedSpikes"].as_array().unwrap().len(), 1);
        assert_eq!(out[0]["relatedSpikes"][0]["time"], "2026-01-01T12:05:00Z");
    }
}
