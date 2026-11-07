//! Monitor rule language, version 1 (ADR 0002 §1).
//!
//! A rule is untrusted input: it may come from an AI. [`validate`] is the only
//! way to get a [`Rule`] the evaluator accepts, [`describe`] writes the
//! plain-language description from the rule itself (never from AI text), and
//! [`Evaluator`] decides when a rule fires. Rules only observe and record.

use std::collections::HashSet;

use chrono::{DateTime, NaiveTime, Utc, Weekday};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{in_window, parse_hhmm, ProcSample, COMPONENT_CRASHES, COMPONENT_FOREGROUND, COMPONENT_SPIKES};

pub const RULE_VERSION: u32 = 1;
pub const MAX_MONITORS: usize = 20;
pub const MAX_CONDITIONS: usize = 8;
/// The lowest thresholds a rule may use. Replay relies on these.
pub const MIN_CPU_PERCENT: f64 = 1.0;
pub const MIN_MEMORY_MB: u64 = 64;
/// Every monitor is evaluated on the shared 5-second sampler tick.
pub const SAMPLE_SECONDS: u32 = 5;
/// An event or crash counts as true for this long after it is logged.
pub const EVENT_HOLD_MINUTES: i64 = 10;
const MAX_NAME_CHARS: usize = 60;
const MAX_PROCESS_CHARS: usize = 260;
const MAX_PROVIDER_CHARS: usize = 128;
const MAX_REASONING_CHARS: usize = 600;
/// A gap this long between ticks (sleep, a stalled sampler) resets "for N seconds" counters.
const MAX_TICK_GAP_SECONDS: i64 = 15;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Rule {
    pub version: u32,
    pub name: String,
    pub schedule: Schedule,
    pub trigger: Trigger,
    pub cooldown_seconds: u32,
    pub notify: Notify,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Schedule {
    pub start_time: String,
    pub end_time: String,
    /// Empty means every day.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub days: Vec<Day>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Day {
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
    Sun,
}

impl Day {
    const ALL: [Day; 7] = [Day::Mon, Day::Tue, Day::Wed, Day::Thu, Day::Fri, Day::Sat, Day::Sun];

    fn weekday(self) -> Weekday {
        match self {
            Day::Mon => Weekday::Mon,
            Day::Tue => Weekday::Tue,
            Day::Wed => Weekday::Wed,
            Day::Thu => Weekday::Thu,
            Day::Fri => Weekday::Fri,
            Day::Sat => Weekday::Sat,
            Day::Sun => Weekday::Sun,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Day::Mon => "Mon",
            Day::Tue => "Tue",
            Day::Wed => "Wed",
            Day::Thu => "Thu",
            Day::Fri => "Fri",
            Day::Sat => "Sat",
            Day::Sun => "Sun",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum Trigger {
    All(Vec<Condition>),
    Any(Vec<Condition>),
}

impl Trigger {
    pub fn conditions(&self) -> &[Condition] {
        match self {
            Trigger::All(c) | Trigger::Any(c) => c,
        }
    }

    fn conditions_mut(&mut self) -> &mut Vec<Condition> {
        match self {
            Trigger::All(c) | Trigger::Any(c) => c,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Notify {
    Tray,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Channel {
    Application,
    System,
    Setup,
}

impl Channel {
    pub fn as_str(self) -> &'static str {
        match self {
            Channel::Application => "Application",
            Channel::System => "System",
            Channel::Setup => "Setup",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Condition {
    #[serde(rename_all = "camelCase")]
    ProcessCpu { process: String, at_least_percent: f64, for_seconds: u32 },
    #[serde(rename_all = "camelCase")]
    ProcessMemory { process: String, at_least_mb: u64, for_seconds: u32 },
    #[serde(rename_all = "camelCase")]
    SystemCpu { at_least_percent: f64, for_seconds: u32 },
    #[serde(rename_all = "camelCase")]
    SystemMemory { at_least_percent: f64, for_seconds: u32 },
    #[serde(rename_all = "camelCase")]
    Event {
        channel: Channel,
        event_id: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    Crash { process: String },
    #[serde(rename_all = "camelCase")]
    Foreground { process: String },
}

/// Control characters, and invisible format characters (bidi overrides,
/// zero-width marks) that could make the review text read differently from
/// what the rule does.
fn is_hidden(c: char) -> bool {
    c.is_control() || matches!(c, '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{206F}' | '\u{FEFF}')
}

/// Free text such as an AI's reasoning, cleaned for display: hidden
/// characters removed, trimmed, and capped.
pub fn clean_text(s: &str) -> String {
    echo(s.trim(), MAX_REASONING_CHARS).trim().to_owned()
}

/// Input echoed back in an error message: bounded and with hidden characters removed.
fn echo(s: &str, max: usize) -> String {
    s.chars().filter(|c| !is_hidden(*c)).take(max).collect()
}

/// Allowed fields per condition type. Serde's internally tagged enums do not
/// support `deny_unknown_fields`, so unknown fields are rejected here instead.
fn allowed_fields(kind: &str) -> Option<&'static [&'static str]> {
    Some(match kind {
        "process_cpu" => &["type", "process", "atLeastPercent", "forSeconds"],
        "process_memory" => &["type", "process", "atLeastMb", "forSeconds"],
        "system_cpu" | "system_memory" => &["type", "atLeastPercent", "forSeconds"],
        "event" => &["type", "channel", "eventId", "provider"],
        "crash" | "foreground" => &["type", "process"],
        _ => return None,
    })
}

impl Condition {
    /// The component a condition needs. Monitors never turn components on.
    pub fn component(&self) -> &'static str {
        match self {
            Condition::ProcessCpu { .. } | Condition::ProcessMemory { .. } | Condition::SystemCpu { .. } | Condition::SystemMemory { .. } => COMPONENT_SPIKES,
            Condition::Event { .. } | Condition::Crash { .. } => COMPONENT_CRASHES,
            Condition::Foreground { .. } => COMPONENT_FOREGROUND,
        }
    }

    fn for_seconds(&self) -> Option<u32> {
        match self {
            Condition::ProcessCpu { for_seconds, .. }
            | Condition::ProcessMemory { for_seconds, .. }
            | Condition::SystemCpu { for_seconds, .. }
            | Condition::SystemMemory { for_seconds, .. } => Some(*for_seconds),
            _ => None,
        }
    }

    fn for_seconds_mut(&mut self) -> Option<&mut u32> {
        match self {
            Condition::ProcessCpu { for_seconds, .. }
            | Condition::ProcessMemory { for_seconds, .. }
            | Condition::SystemCpu { for_seconds, .. }
            | Condition::SystemMemory { for_seconds, .. } => Some(for_seconds),
            _ => None,
        }
    }

    fn process(&self) -> Option<&str> {
        match self {
            Condition::ProcessCpu { process, .. }
            | Condition::ProcessMemory { process, .. }
            | Condition::Crash { process }
            | Condition::Foreground { process } => Some(process),
            _ => None,
        }
    }
}

/// Things the review screen must point out before the owner approves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PrivacyFlag {
    /// Records which app is in the foreground.
    TracksForegroundApp,
    /// Watches every process, not named ones.
    AnyProcess,
    /// Active all day, every day.
    AlwaysOn,
}

impl PrivacyFlag {
    pub fn explain(self) -> &'static str {
        match self {
            PrivacyFlag::TracksForegroundApp => "Records which app you are using (process names only, never window titles).",
            PrivacyFlag::AnyProcess => "Watches every process on this PC, not only named ones.",
            PrivacyFlag::AlwaysOn => "Runs all day, every day.",
        }
    }
}

/// Parses and validates untrusted rule JSON, and normalizes it: names and
/// process names are trimmed, `forSeconds` rounds up to the sample period,
/// and days are sorted and de-duplicated. Returns every problem found.
pub fn validate(value: &Value, enabled_components: &[String]) -> Result<Rule, Vec<String>> {
    let mut errors = Vec::new();
    if let Some(trigger) = value.get("trigger").and_then(Value::as_object) {
        for list in trigger.values().filter_map(Value::as_array) {
            for (i, cond) in list.iter().enumerate() {
                let Some(obj) = cond.as_object() else { continue };
                let kind = obj.get("type").and_then(Value::as_str).unwrap_or_default();
                match allowed_fields(kind) {
                    None => errors.push(format!("condition {}: unknown type '{}'", i + 1, echo(kind, 40))),
                    Some(allowed) => {
                        for key in obj.keys().filter(|k| !allowed.contains(&k.as_str())) {
                            errors.push(format!("condition {}: unknown field '{}' for type {kind}", i + 1, echo(key, 40)));
                        }
                    }
                }
            }
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    let mut rule: Rule = match serde_json::from_value(value.clone()) {
        Ok(r) => r,
        Err(e) => return Err(vec![format!("not a valid rule: {}", echo(&e.to_string(), 200))]),
    };

    if rule.version != RULE_VERSION {
        errors.push(format!("version must be {RULE_VERSION}"));
    }
    rule.name = rule.name.trim().to_owned();
    if rule.name.is_empty() || rule.name.chars().count() > MAX_NAME_CHARS || rule.name.chars().any(is_hidden) {
        errors.push(format!("name must be 1-{MAX_NAME_CHARS} characters with no control or invisible characters"));
    }
    for (label, time) in [("startTime", &rule.schedule.start_time), ("endTime", &rule.schedule.end_time)] {
        if parse_hhmm(time).is_none() || time.trim().len() != 5 {
            errors.push(format!("schedule.{label} must be 24-hour HH:MM, e.g. 21:00"));
        }
    }
    rule.schedule.start_time = rule.schedule.start_time.trim().to_owned();
    rule.schedule.end_time = rule.schedule.end_time.trim().to_owned();
    let unique: HashSet<Day> = rule.schedule.days.iter().copied().collect();
    rule.schedule.days = Day::ALL.into_iter().filter(|d| unique.contains(d)).collect();
    if !(60..=86_400).contains(&rule.cooldown_seconds) {
        errors.push("cooldownSeconds must be 60-86400".into());
    }

    let count = rule.trigger.conditions().len();
    if count == 0 || count > MAX_CONDITIONS {
        errors.push(format!("a trigger needs 1-{MAX_CONDITIONS} conditions"));
    }
    for (i, cond) in rule.trigger.conditions_mut().iter_mut().enumerate() {
        let n = i + 1;
        match cond {
            Condition::ProcessCpu { process, .. } | Condition::ProcessMemory { process, .. } | Condition::Crash { process } => {
                *process = process.trim().to_owned();
                if let Err(e) = check_process(process, true) {
                    errors.push(format!("condition {n}: {e}"));
                }
            }
            Condition::Foreground { process } => {
                *process = process.trim().to_owned();
                if let Err(e) = check_process(process, false) {
                    errors.push(format!("condition {n}: {e}"));
                }
            }
            Condition::Event { provider: Some(p), .. } => {
                *p = p.trim().to_owned();
                // The same characters the event log query accepts.
                if p.is_empty() || p.len() > MAX_PROVIDER_CHARS || !p.chars().all(|c| c.is_ascii_alphanumeric() || " ._-()/".contains(c)) {
                    errors.push(format!("condition {n}: provider must be 1-{MAX_PROVIDER_CHARS} letters, digits, spaces or . _ - ( ) /"));
                }
            }
            _ => {}
        }
        match cond {
            Condition::ProcessCpu { at_least_percent, .. } | Condition::SystemCpu { at_least_percent, .. } | Condition::SystemMemory { at_least_percent, .. } => {
                if !(MIN_CPU_PERCENT..=100.0).contains(at_least_percent) {
                    errors.push(format!("condition {n}: atLeastPercent must be {MIN_CPU_PERCENT}-100"));
                }
            }
            Condition::ProcessMemory { at_least_mb, .. } => {
                if !(MIN_MEMORY_MB..=1_048_576).contains(at_least_mb) {
                    errors.push(format!("condition {n}: atLeastMb must be {MIN_MEMORY_MB}-1048576"));
                }
            }
            Condition::Event { event_id, .. } if *event_id > 65_535 => {
                errors.push(format!("condition {n}: eventId must be 0-65535"));
            }
            _ => {}
        }
        if let Some(secs) = cond.for_seconds_mut() {
            if !(SAMPLE_SECONDS..=3600).contains(secs) {
                errors.push(format!("condition {n}: forSeconds must be {SAMPLE_SECONDS}-3600"));
            }
            *secs = secs.div_ceil(SAMPLE_SECONDS) * SAMPLE_SECONDS;
        }
        if !enabled_components.iter().any(|c| c == cond.component()) {
            errors.push(format!("condition {n}: needs the '{}' component, which is turned off (a monitor never turns it on)", cond.component()));
        }
    }
    let conds = rule.trigger.conditions();
    for (i, a) in conds.iter().enumerate() {
        if conds[..i].contains(a) {
            errors.push(format!("condition {} repeats an earlier condition", i + 1));
        }
    }
    if errors.is_empty() {
        Ok(rule)
    } else {
        Err(errors)
    }
}

/// An executable name like `game.exe`, or `"*"` for any process when allowed.
fn check_process(name: &str, allow_any: bool) -> Result<(), String> {
    if name == "*" {
        return if allow_any { Ok(()) } else { Err("this condition needs a named process, not \"*\"".into()) };
    }
    if name.is_empty() || name.chars().count() > MAX_PROCESS_CHARS {
        return Err(format!("process must be 1-{MAX_PROCESS_CHARS} characters"));
    }
    if name.chars().any(|c| is_hidden(c) || matches!(c, '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|')) {
        return Err("process must be an executable name such as game.exe, not a path or pattern".into());
    }
    Ok(())
}

/// The event-log entries a rule needs the sampler to poll for.
pub fn event_needs(rule: &Rule) -> Vec<(Channel, u32)> {
    let mut out = Vec::new();
    for c in rule.trigger.conditions() {
        match c {
            Condition::Event { channel, event_id, .. } => out.push((*channel, *event_id)),
            Condition::Crash { .. } => out.extend([(Channel::Application, 1000), (Channel::Application, 1002)]),
            _ => {}
        }
    }
    out
}

pub fn privacy_flags(rule: &Rule) -> Vec<PrivacyFlag> {
    let mut flags = Vec::new();
    if rule.trigger.conditions().iter().any(|c| matches!(c, Condition::Foreground { .. })) {
        flags.push(PrivacyFlag::TracksForegroundApp);
    }
    if rule.trigger.conditions().iter().any(|c| c.process() == Some("*")) {
        flags.push(PrivacyFlag::AnyProcess);
    }
    let all_days = rule.schedule.days.is_empty() || rule.schedule.days.len() == 7;
    if all_days && rule.schedule.start_time == rule.schedule.end_time {
        flags.push(PrivacyFlag::AlwaysOn);
    }
    flags
}

fn who(process: &str) -> String {
    if process == "*" {
        "Any process".into()
    } else {
        process.to_owned()
    }
}

fn for_text(seconds: u32) -> String {
    if seconds <= SAMPLE_SECONDS {
        "in a single 5-second sample".into()
    } else if seconds.is_multiple_of(60) {
        format!("for {} minute(s) or more", seconds / 60)
    } else {
        format!("for {seconds} seconds or more")
    }
}

fn duration_text(seconds: u32) -> String {
    if seconds.is_multiple_of(3600) {
        format!("{} hour(s)", seconds / 3600)
    } else if seconds.is_multiple_of(60) {
        format!("{} minute(s)", seconds / 60)
    } else {
        format!("{seconds} seconds")
    }
}

pub fn describe_condition(c: &Condition) -> String {
    match c {
        Condition::ProcessCpu { process, at_least_percent, for_seconds } => {
            format!("{} uses at least {at_least_percent}% of total CPU {}", who(process), for_text(*for_seconds))
        }
        Condition::ProcessMemory { process, at_least_mb, for_seconds } => {
            format!("{} uses at least {at_least_mb} MB of memory {}", who(process), for_text(*for_seconds))
        }
        Condition::SystemCpu { at_least_percent, for_seconds } => format!("Total CPU use is at least {at_least_percent}% {}", for_text(*for_seconds)),
        Condition::SystemMemory { at_least_percent, for_seconds } => {
            format!("Memory in use is at least {at_least_percent}% of installed memory {}", for_text(*for_seconds))
        }
        Condition::Event { channel, event_id, provider } => {
            let source = provider.as_deref().map(|p| format!(" from source \"{p}\"")).unwrap_or_else(|| " from any source".into());
            format!("Event {event_id} is logged in the {} log{source} (counts for {EVENT_HOLD_MINUTES} minutes after it is logged)", channel.as_str())
        }
        Condition::Crash { process } => format!(
            "{} crashes or hangs (Application Error 1000 or Application Hang 1002; counts for {EVENT_HOLD_MINUTES} minutes)",
            if process == "*" { "Any app".to_owned() } else { process.clone() }
        ),
        Condition::Foreground { process } => format!("{process} is the app in the foreground"),
    }
}

/// The code-generated description shown on review. It is written from the
/// rule alone; the name is quoted because it may be AI-supplied text.
pub fn describe(rule: &Rule) -> Vec<String> {
    let mut lines = vec![format!("Monitor \"{}\"", rule.name)];
    let days = if rule.schedule.days.is_empty() || rule.schedule.days.len() == 7 {
        "every day".to_owned()
    } else {
        rule.schedule.days.iter().map(|d| d.label()).collect::<Vec<_>>().join(", ")
    };
    let hours = if rule.schedule.start_time == rule.schedule.end_time {
        "all day".to_owned()
    } else {
        format!("{}-{} local time", rule.schedule.start_time, rule.schedule.end_time)
    };
    lines.push(format!("Active {days}, {hours}."));
    let conds = rule.trigger.conditions();
    if conds.len() == 1 {
        lines.push("Fires when:".into());
    } else {
        lines.push(match rule.trigger {
            Trigger::All(_) => "Fires when all of these are true at the same time:".into(),
            Trigger::Any(_) => "Fires when any of these is true:".into(),
        });
    }
    lines.extend(conds.iter().map(|c| format!("- {}", describe_condition(c))));
    lines.push(format!("After firing, it waits {} before it can fire again.", duration_text(rule.cooldown_seconds)));
    lines.push(match rule.notify {
        Notify::Tray => "When it fires, it records a hit and changes the tray icon.".into(),
        Notify::None => "When it fires, it records a hit.".into(),
    });
    lines.push("It only watches. It never runs anything or changes Windows.".into());
    lines
}

/// One event-log entry as the evaluator sees it.
#[derive(Debug, Clone)]
pub struct ObservedEvent {
    pub channel: Channel,
    pub provider: String,
    pub event_id: u32,
    pub time: DateTime<Utc>,
    pub message: String,
}

/// Everything one sampler tick knows.
pub struct Tick<'a> {
    pub now: DateTime<Utc>,
    pub local_time: NaiveTime,
    pub local_weekday: Weekday,
    pub processes: &'a [ProcSample],
    pub system_cpu_percent: f64,
    pub system_memory_percent: f64,
    pub foreground: Option<&'a str>,
    /// Recent events from the channels the active rules use.
    pub events: &'a [ObservedEvent],
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Hit {
    pub time: String,
    /// The conditions that were true, as code-generated text.
    pub matched: Vec<String>,
}

/// True when the event text names `process` as a whole word. Windows writes
/// e.g. "Faulting application name: game.exe, version: ..." (1000) and
/// "The program game.exe version ... stopped interacting" (1002).
fn names_process(message: &str, process: &str) -> bool {
    message.split(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | '(' | ')' | '"' | '\\' | '/')).any(|w| w.eq_ignore_ascii_case(process))
}

/// Runtime state for one rule: consecutive-sample counters and cooldown.
pub struct Evaluator {
    rule: Rule,
    streaks: Vec<u32>,
    last_tick: Option<DateTime<Utc>>,
    last_fired: Option<DateTime<Utc>>,
}

impl Evaluator {
    /// Takes a rule that has passed [`validate`].
    pub fn new(rule: Rule) -> Self {
        let n = rule.trigger.conditions().len();
        Self { rule, streaks: vec![0; n], last_tick: None, last_fired: None }
    }

    pub fn rule(&self) -> &Rule {
        &self.rule
    }

    fn scheduled(&self, tick: &Tick) -> bool {
        let s = &self.rule.schedule;
        let (Some(start), Some(end)) = (parse_hhmm(&s.start_time), parse_hhmm(&s.end_time)) else { return false };
        if !in_window(tick.local_time, start, end) {
            return false;
        }
        if s.days.is_empty() {
            return true;
        }
        // An overnight window belongs to the day it started on.
        let day = if start > end && tick.local_time < end { tick.local_weekday.pred() } else { tick.local_weekday };
        s.days.iter().any(|d| d.weekday() == day)
    }

    fn holds_now(c: &Condition, tick: &Tick) -> bool {
        let named = |process: &str, name: &str| process == "*" || process.eq_ignore_ascii_case(name);
        let recent = |e: &ObservedEvent| e.time <= tick.now && (tick.now - e.time).num_minutes() < EVENT_HOLD_MINUTES;
        match c {
            Condition::ProcessCpu { process, at_least_percent, .. } => {
                tick.processes.iter().any(|p| named(process, &p.name) && p.cpu_percent >= *at_least_percent)
            }
            Condition::ProcessMemory { process, at_least_mb, .. } => tick.processes.iter().any(|p| named(process, &p.name) && p.ram_mb >= *at_least_mb),
            Condition::SystemCpu { at_least_percent, .. } => tick.system_cpu_percent >= *at_least_percent,
            Condition::SystemMemory { at_least_percent, .. } => tick.system_memory_percent >= *at_least_percent,
            Condition::Event { channel, event_id, provider } => tick.events.iter().any(|e| {
                e.channel == *channel && e.event_id == *event_id && provider.as_ref().is_none_or(|p| p.eq_ignore_ascii_case(&e.provider)) && recent(e)
            }),
            Condition::Crash { process } => tick.events.iter().any(|e| {
                e.channel == Channel::Application
                    && matches!((e.event_id, e.provider.as_str()), (1000, "Application Error") | (1002, "Application Hang"))
                    && (process == "*" || names_process(&e.message, process))
                    && recent(e)
            }),
            Condition::Foreground { process } => tick.foreground.is_some_and(|f| f.eq_ignore_ascii_case(process)),
        }
    }

    /// Advances one sampler tick and returns a hit when the rule fires.
    pub fn tick(&mut self, tick: &Tick) -> Option<Hit> {
        // A gap breaks every streak; the current sample still counts as the first of a new one.
        // The clock moving backwards counts as a gap too.
        let gap = self.last_tick.is_some_and(|t| !(0..=MAX_TICK_GAP_SECONDS).contains(&(tick.now - t).num_seconds()));
        self.last_tick = Some(tick.now);
        let scheduled = self.scheduled(tick);
        if gap || !scheduled {
            self.streaks.iter_mut().for_each(|s| *s = 0);
        }
        if !scheduled {
            return None;
        }
        let mut met = Vec::new();
        for (i, c) in self.rule.trigger.conditions().iter().enumerate() {
            self.streaks[i] = if Self::holds_now(c, tick) { self.streaks[i].saturating_add(1) } else { 0 };
            let needed = c.for_seconds().map_or(1, |s| s / SAMPLE_SECONDS).max(1);
            met.push(self.streaks[i] >= needed);
        }
        let fires = match self.rule.trigger {
            Trigger::All(_) => met.iter().all(|m| *m),
            Trigger::Any(_) => met.iter().any(|m| *m),
        };
        // A backwards clock jump ends the cooldown instead of stretching it.
        let cooling = self.last_fired.is_some_and(|t| (0..i64::from(self.rule.cooldown_seconds)).contains(&(tick.now - t).num_seconds()));
        if !fires || cooling {
            return None;
        }
        self.last_fired = Some(tick.now);
        let matched = self.rule.trigger.conditions().iter().zip(&met).filter(|(_, m)| **m).map(|(c, _)| describe_condition(c)).collect();
        Some(Hit { time: tick.now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true), matched })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Datelike, TimeZone};
    use serde_json::json;

    fn all() -> Vec<String> {
        vec![COMPONENT_SPIKES.into(), COMPONENT_CRASHES.into(), COMPONENT_FOREGROUND.into()]
    }

    fn example() -> Value {
        json!({
            "version": 1,
            "name": "  Game stutter in the evening ",
            "schedule": { "startTime": "20:30", "endTime": "23:30", "days": ["sat", "fri", "fri"] },
            "trigger": { "all": [
                { "type": "process_cpu", "process": " game.exe ", "atLeastPercent": 80, "forSeconds": 12 },
                { "type": "event", "channel": "Application", "eventId": 1002 }
            ] },
            "cooldownSeconds": 300,
            "notify": "tray"
        })
    }

    fn with(mut v: Value, f: impl FnOnce(&mut Value)) -> Value {
        f(&mut v);
        v
    }

    fn errors(v: Value) -> String {
        validate(&v, &all()).unwrap_err().join(" | ")
    }

    #[test]
    fn valid_rules_are_normalized() {
        let rule = validate(&example(), &all()).unwrap();
        assert_eq!(rule.name, "Game stutter in the evening");
        assert_eq!(rule.schedule.days, vec![Day::Fri, Day::Sat]);
        assert_eq!(rule.trigger.conditions()[0], Condition::ProcessCpu { process: "game.exe".into(), at_least_percent: 80.0, for_seconds: 15 });
        // Round-trips through its own serialization.
        assert_eq!(validate(&serde_json::to_value(&rule).unwrap(), &all()).unwrap(), rule);
    }

    #[test]
    fn unknown_fields_and_types_are_rejected() {
        assert!(errors(with(example(), |v| v["run"] = json!("cmd.exe"))).contains("not a valid rule"));
        assert!(errors(with(example(), |v| v["trigger"]["all"][0]["command"] = json!("x"))).contains("unknown field 'command'"));
        assert!(errors(with(example(), |v| v["trigger"]["all"][0]["type"] = json!("run_script"))).contains("unknown type 'run_script'"));
        assert!(errors(with(example(), |v| v["trigger"] = json!({ "all": [], "any": [] }))).contains("not a valid rule"));
        assert!(errors(with(example(), |v| v["schedule"]["timezone"] = json!("UTC"))).contains("not a valid rule"));
        assert!(errors(with(example(), |v| v["notify"] = json!("email"))).contains("not a valid rule"));
    }

    #[test]
    fn ranges_names_and_caps_are_enforced() {
        assert!(errors(with(example(), |v| v["version"] = json!(2))).contains("version must be 1"));
        assert!(errors(with(example(), |v| v["name"] = json!("   "))).contains("name must be"));
        assert!(errors(with(example(), |v| v["name"] = json!("a\u{7}b"))).contains("name must be"));
        assert!(errors(with(example(), |v| v["name"] = json!("x".repeat(61)))).contains("name must be"));
        // Bidi overrides and zero-width characters could disguise the review text.
        assert!(errors(with(example(), |v| v["name"] = json!("Safe \u{202E}exe.dmc"))).contains("invisible"));
        let hidden = with(example(), |v| v["trigger"]["all"][0]["process"] = json!("game\u{200B}.exe"));
        assert!(errors(hidden).contains("process must"));
        let echoed = errors(with(example(), |v| v["trigger"]["all"][0]["type"] = json!(format!("x\u{202E}{}", "y".repeat(100)))));
        assert!(!echoed.contains('\u{202E}') && echoed.len() < 120, "{echoed}");
        assert!(errors(with(example(), |v| v["schedule"]["startTime"] = json!("9pm"))).contains("startTime"));
        assert!(errors(with(example(), |v| v["schedule"]["endTime"] = json!("7:00"))).contains("endTime"));
        assert!(errors(with(example(), |v| v["cooldownSeconds"] = json!(59))).contains("cooldownSeconds"));
        assert!(errors(with(example(), |v| v["trigger"]["all"][0]["atLeastPercent"] = json!(101))).contains("atLeastPercent"));
        assert!(errors(with(example(), |v| v["trigger"]["all"][0]["forSeconds"] = json!(4))).contains("forSeconds"));
        assert!(errors(with(example(), |v| v["trigger"]["all"][0]["forSeconds"] = json!(3601))).contains("forSeconds"));
        assert!(errors(with(example(), |v| v["trigger"]["all"][1]["eventId"] = json!(70000))).contains("eventId"));
        let mem = json!({ "type": "process_memory", "process": "a.exe", "atLeastMb": 63, "forSeconds": 5 });
        assert!(errors(with(example(), |v| v["trigger"]["all"][0] = mem)).contains("atLeastMb"));
        assert!(errors(with(example(), |v| v["trigger"]["all"] = json!([]))).contains("1-8 conditions"));
        let many: Vec<Value> = (0..9).map(|i| json!({ "type": "event", "channel": "System", "eventId": i })).collect();
        assert!(errors(with(example(), |v| v["trigger"]["all"] = json!(many))).contains("1-8 conditions"));
        let dup = json!({ "type": "event", "channel": "Application", "eventId": 1002 });
        assert!(errors(with(example(), |v| v["trigger"]["all"][0] = dup)).contains("repeats"));
        // Security is not an allowed channel in v1.
        assert!(errors(with(example(), |v| v["trigger"]["all"][1]["channel"] = json!("Security"))).contains("not a valid rule"));
    }

    #[test]
    fn process_names_are_names_not_paths_or_patterns() {
        for bad in ["C:\\Games\\game.exe", "../game.exe", "game*.exe", "a|b", "", "x".repeat(261).as_str()] {
            let v = with(example(), |v| v["trigger"]["all"][0]["process"] = json!(bad));
            assert!(errors(v).contains("process must"), "{bad}");
        }
        let any = with(example(), |v| v["trigger"]["all"][0]["process"] = json!("*"));
        assert!(validate(&any, &all()).is_ok());
        let fg = with(example(), |v| v["trigger"]["all"][0] = json!({ "type": "foreground", "process": "*" }));
        assert!(errors(fg).contains("named process"));
    }

    #[test]
    fn rules_cannot_use_disabled_components() {
        let err = validate(&example(), &[COMPONENT_SPIKES.to_owned()]).unwrap_err().join(" | ");
        assert!(err.contains("usage-monitor:crash-correlator"), "{err}");
        assert!(!err.contains("resource-spikes"));
    }

    #[test]
    fn privacy_flags_point_out_wide_monitors() {
        let rule = validate(&example(), &all()).unwrap();
        assert!(privacy_flags(&rule).is_empty());
        let wide = with(example(), |v| {
            v["schedule"] = json!({ "startTime": "00:00", "endTime": "00:00" });
            v["trigger"]["all"][0]["process"] = json!("*");
            v["trigger"]["all"][1] = json!({ "type": "foreground", "process": "game.exe" });
        });
        let flags = privacy_flags(&validate(&wide, &all()).unwrap());
        assert_eq!(flags, vec![PrivacyFlag::TracksForegroundApp, PrivacyFlag::AnyProcess, PrivacyFlag::AlwaysOn]);
    }

    #[test]
    fn descriptions_come_from_the_rule() {
        let text = describe(&validate(&example(), &all()).unwrap()).join("\n");
        assert!(text.contains("Monitor \"Game stutter in the evening\""));
        assert!(text.contains("Active Fri, Sat, 20:30-23:30 local time."));
        assert!(text.contains("all of these are true at the same time"));
        assert!(text.contains("- game.exe uses at least 80% of total CPU for 15 seconds or more"));
        assert!(text.contains("- Event 1002 is logged in the Application log from any source"));
        assert!(text.contains("waits 5 minute(s)"));
        assert!(text.contains("changes the tray icon"));
        assert!(text.ends_with("It never runs anything or changes Windows."));
    }

    fn proc(name: &str, cpu: f64, ram: u64) -> ProcSample {
        ProcSample { pid: 1, name: name.into(), cpu_percent: cpu, ram_mb: ram }
    }

    fn at(h: u32, m: u32, s: u32) -> DateTime<Utc> {
        // Friday 2026-11-06.
        Utc.with_ymd_and_hms(2026, 11, 6, h, m, s).unwrap()
    }

    fn tick<'a>(now: DateTime<Utc>, procs: &'a [ProcSample], events: &'a [ObservedEvent]) -> Tick<'a> {
        Tick {
            now,
            local_time: now.time(),
            local_weekday: now.weekday(),
            processes: procs,
            system_cpu_percent: 10.0,
            system_memory_percent: 40.0,
            foreground: None,
            events,
        }
    }

    fn hang(time: DateTime<Utc>) -> ObservedEvent {
        ObservedEvent { channel: Channel::Application, provider: "Application Hang".into(), event_id: 1002, time, message: "The program Game.exe stopped".into() }
    }

    #[test]
    fn fires_only_after_the_full_duration_and_respects_cooldown() {
        let mut ev = Evaluator::new(validate(&example(), &all()).unwrap());
        let hot = [proc("Game.exe", 90.0, 100)];
        let events = [hang(at(21, 0, 0))];
        // forSeconds 15 = three consecutive 5-second samples.
        assert!(ev.tick(&tick(at(21, 0, 0), &hot, &events)).is_none());
        assert!(ev.tick(&tick(at(21, 0, 5), &hot, &events)).is_none());
        let hit = ev.tick(&tick(at(21, 0, 10), &hot, &events)).expect("fires on the third sample");
        assert_eq!(hit.matched.len(), 2);
        assert_eq!(hit.time, "2026-11-06T21:00:10Z");
        // Cooldown of 300 s.
        assert!(ev.tick(&tick(at(21, 0, 15), &hot, &events)).is_none());
        // Ticks stop (sleep) and resume after the cooldown: a new streak must build up again.
        let later = [hang(at(21, 5, 0))];
        assert!(ev.tick(&tick(at(21, 5, 10), &hot, &later)).is_none(), "first sample after a gap");
        assert!(ev.tick(&tick(at(21, 5, 15), &hot, &later)).is_none());
        assert!(ev.tick(&tick(at(21, 5, 20), &hot, &later)).is_some());
    }

    #[test]
    fn a_cool_sample_or_a_gap_resets_the_streak() {
        let mut ev = Evaluator::new(validate(&example(), &all()).unwrap());
        let (hot, cool) = ([proc("game.exe", 90.0, 1)], [proc("game.exe", 5.0, 1)]);
        let events = [hang(at(21, 0, 0))];
        ev.tick(&tick(at(21, 0, 0), &hot, &events));
        ev.tick(&tick(at(21, 0, 5), &hot, &events));
        assert!(ev.tick(&tick(at(21, 0, 10), &cool, &events)).is_none());
        ev.tick(&tick(at(21, 0, 15), &hot, &events));
        ev.tick(&tick(at(21, 0, 20), &hot, &events));
        // A 30-second gap (sleep) resets the counter instead of bridging it.
        assert!(ev.tick(&tick(at(21, 0, 50), &hot, &events)).is_none());
        assert!(ev.tick(&tick(at(21, 0, 55), &hot, &events)).is_none());
        assert!(ev.tick(&tick(at(21, 1, 0), &hot, &events)).is_some(), "third sample of the new streak");
    }

    #[test]
    fn a_backwards_clock_breaks_the_streak_and_ends_the_cooldown() {
        let mut ev = Evaluator::new(validate(&example(), &all()).unwrap());
        let hot = [proc("game.exe", 90.0, 1)];
        let events = [hang(at(20, 59, 0))];
        ev.tick(&tick(at(21, 0, 0), &hot, &events));
        ev.tick(&tick(at(21, 0, 5), &hot, &events));
        assert!(ev.tick(&tick(at(21, 0, 3), &hot, &events)).is_none(), "backwards step resets the streak");
        ev.tick(&tick(at(21, 0, 8), &hot, &events));
        assert!(ev.tick(&tick(at(21, 0, 13), &hot, &events)).is_some());
        // Clock set back 5 minutes (still in the 20:30 window): the cooldown does not stretch.
        let back = [hang(at(20, 55, 0))];
        ev.tick(&tick(at(20, 56, 0), &hot, &back));
        ev.tick(&tick(at(20, 56, 5), &hot, &back));
        assert!(ev.tick(&tick(at(20, 56, 10), &hot, &back)).is_some());
    }

    #[test]
    fn events_count_for_ten_minutes_and_must_match() {
        let any = with(example(), |v| v["trigger"] = json!({ "any": [{ "type": "crash", "process": "game.exe" }] }));
        let mut ev = Evaluator::new(validate(&any, &all()).unwrap());
        let other = [ObservedEvent { message: "The program mygame.exe version 1.0 stopped".into(), ..hang(at(21, 0, 0)) }];
        assert!(ev.tick(&tick(at(21, 0, 5), &[], &other)).is_none());
        let old = [hang(at(20, 45, 0))];
        assert!(ev.tick(&tick(at(21, 0, 10), &[], &old)).is_none(), "older than 10 minutes");
        let fresh = [hang(at(20, 55, 0))];
        assert!(ev.tick(&tick(at(21, 0, 15), &[], &fresh)).is_some());
        let crash = ObservedEvent { provider: "Application Error".into(), event_id: 1000, message: "Faulting application name: GAME.EXE, version: 1.0".into(), ..hang(at(21, 6, 0)) };
        assert!(ev.tick(&tick(at(21, 6, 15), &[], std::slice::from_ref(&crash))).is_some(), "1000 crash, after the 300 s cooldown");
        // Only the two crash/hang events count; other Application events do not.
        let mut ev2 = Evaluator::new(validate(&any, &all()).unwrap());
        let other_id = ObservedEvent { event_id: 1001, ..crash };
        assert!(ev2.tick(&tick(at(21, 6, 20), &[], &[other_id])).is_none());
    }

    #[test]
    fn schedule_days_and_overnight_windows() {
        let night = with(example(), |v| {
            v["schedule"] = json!({ "startTime": "22:00", "endTime": "02:00", "days": ["fri"] });
            v["trigger"] = json!({ "any": [{ "type": "system_cpu", "atLeastPercent": 5, "forSeconds": 5 }] });
            v["cooldownSeconds"] = json!(60);
        });
        let rule = validate(&night, &all()).unwrap();
        // 01:00 on Saturday belongs to Friday night.
        let sat_1am = Utc.with_ymd_and_hms(2026, 11, 7, 1, 0, 0).unwrap();
        assert!(Evaluator::new(rule.clone()).tick(&tick(sat_1am, &[], &[])).is_some());
        // 23:00 on Saturday is a Saturday night: not scheduled.
        let sat_11pm = Utc.with_ymd_and_hms(2026, 11, 7, 23, 0, 0).unwrap();
        assert!(Evaluator::new(rule.clone()).tick(&tick(sat_11pm, &[], &[])).is_none());
        // Outside the hours.
        assert!(Evaluator::new(rule).tick(&tick(at(12, 0, 0), &[], &[])).is_none());
    }

    #[test]
    fn any_triggers_and_foreground() {
        let any = with(example(), |v| {
            v["trigger"] = json!({ "any": [
                { "type": "foreground", "process": "Game.exe" },
                { "type": "system_memory", "atLeastPercent": 95, "forSeconds": 5 }
            ] });
        });
        let mut ev = Evaluator::new(validate(&any, &all()).unwrap());
        let mut t = tick(at(21, 0, 0), &[], &[]);
        assert!(ev.tick(&t).is_none());
        t.now = at(21, 0, 5);
        t.foreground = Some("game.exe");
        let hit = ev.tick(&t).unwrap();
        assert_eq!(hit.matched, vec!["Game.exe is the app in the foreground".to_owned()]);
    }
}
