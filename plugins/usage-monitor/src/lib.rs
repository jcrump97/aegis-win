//! `usage-monitor`: resource spikes, crash correlation, and foreground-app
//! tracking during a user-defined daily watch window.
//!
//! Telemetry lives in memory only (bounded ring buffers) and is cleared when
//! the vault locks. Only process names are recorded, never window titles.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use aegis_core::os::{self, eventlog};
use aegis_core::registry::{Plugin, PluginManifest, ToolContext};
use aegis_core::{AegisError, AegisResult, ErrorCode};
use async_trait::async_trait;
use chrono::{DateTime, Local, NaiveTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

pub const COMPONENT_SPIKES: &str = "usage-monitor:resource-spikes";
pub const COMPONENT_CRASHES: &str = "usage-monitor:crash-correlator";
pub const COMPONENT_FOREGROUND: &str = "usage-monitor:active-window";
const SAMPLE_EVERY: Duration = Duration::from_secs(5);
const SPIKE_COOLDOWN: Duration = Duration::from_secs(60);
const MAX_ENTRIES: usize = 500;
const CORRELATION_WINDOW_MINUTES: i64 = 10;

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
}

impl Telemetry {
    fn enabled(&self, component: &str) -> bool {
        self.components.iter().any(|c| c == component)
    }

    fn record(&mut self, samples: &[ProcSample], foreground: Option<String>, now_local: NaiveTime, now: Instant) {
        let (Some(start), Some(end)) = (parse_hhmm(&self.watch.start_time), parse_hhmm(&self.watch.end_time)) else { return };
        if !in_window(now_local, start, end) {
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
                push_capped(&mut self.spikes, spike);
            }
        }
        if self.enabled(COMPONENT_FOREGROUND) {
            if let Some(name) = foreground {
                if self.last_foreground.as_deref() != Some(name.as_str()) {
                    self.last_foreground = Some(name.clone());
                    push_capped(&mut self.foreground, ForegroundChange { time: stamp, process: name });
                }
            }
        }
    }

    fn clear(&mut self) {
        self.spikes.clear();
        self.foreground.clear();
        self.last_spike.clear();
        self.last_foreground = None;
    }
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
}

impl Default for UsageMonitorPlugin {
    fn default() -> Self {
        Self {
            manifest: PluginManifest::from_json(include_str!("../manifest.json")).expect("usage-monitor manifest.json is valid"),
            telemetry: Arc::default(),
            sampler: Mutex::new(None),
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
        let thread = std::thread::Builder::new()
            .name("usage-monitor-sampler".into())
            .spawn(move || {
                let mut sys = System::new();
                refresh(&mut sys);
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
                    telemetry.lock().unwrap().record(&current, fg, Local::now().time(), Instant::now());
                }
            })
            .expect("can spawn the sampler thread");
        self.telemetry.lock().unwrap().sampling_since = Some(Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
        *slot = Some(Sampler { stop, thread });
    }

    fn stop_sampler(&self) {
        if let Some(sampler) = self.sampler.lock().unwrap().take() {
            sampler.stop.store(true, Ordering::Relaxed);
            let _ = sampler.thread.join();
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

    async fn snapshot(&self, label: String) -> AegisResult<Value> {
        let (watch, components, spikes, foreground, since) = {
            let t = self.telemetry.lock().unwrap();
            (t.watch.clone(), t.components.clone(), t.spikes.iter().cloned().collect::<Vec<_>>(), t.foreground.iter().cloned().collect::<Vec<_>>(), t.sampling_since.clone())
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
        }))
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
                let mut t = self.telemetry.lock().unwrap();
                let removed = t.spikes.len() + t.foreground.len();
                t.clear();
                Ok(json!({ "purged": true, "entriesRemoved": removed }))
            }
            other => Err(AegisError::new(ErrorCode::UnknownTool, format!("usage-monitor has no tool '{other}'"))),
        }
    }

    fn on_unlock(&self, enabled_components: &[String]) {
        self.telemetry.lock().unwrap().components = enabled_components.to_vec();
        let wants_sampling = [COMPONENT_SPIKES, COMPONENT_FOREGROUND].iter().any(|c| enabled_components.iter().any(|e| e == c));
        if wants_sampling {
            self.start_sampler();
        }
    }

    fn on_lock(&self) {
        self.stop_sampler();
        let mut t = self.telemetry.lock().unwrap();
        t.clear();
        t.sampling_since = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
