//! Replay (ADR 0002 §2): runs a proposed rule over the samples kept in memory
//! for the last 30 minutes, so the owner sees how often it would have fired
//! before approving it.
//!
//! Samples are kept only inside the watch window, like all other telemetry,
//! because `propose_monitor` is open to agents without the PIN: replay must not
//! reveal more than the snapshot already can.
//! What is kept follows the enabled components: process and system load only
//! while `resource-spikes` is on, the foreground app only while
//! `active-window` is on. Processes below the lowest threshold a rule may use
//! are dropped, so replay loses nothing a rule could match. Memory only,
//! cleared on lock and by purge, and never sent to the LLM.

use std::collections::VecDeque;

use chrono::{DateTime, NaiveTime, SecondsFormat, Utc, Weekday};
use serde_json::{json, Value};

use crate::rules::{Evaluator, Hit, ObservedEvent, Rule, Tick, MIN_CPU_PERCENT, MIN_MEMORY_MB, SAMPLE_SECONDS};
use crate::{ProcSample, COMPONENT_FOREGROUND, COMPONENT_SPIKES};

pub const REPLAY_MINUTES: u32 = 30;
pub const MAX_RECORDED: usize = (REPLAY_MINUTES * 60 / SAMPLE_SECONDS) as usize;
const MAX_SHOWN_HITS: usize = 5;

/// One sampler tick, kept only as far as the enabled components allow.
#[derive(Debug, Clone)]
pub struct RecordedTick {
    pub now: DateTime<Utc>,
    pub local_time: NaiveTime,
    pub local_weekday: Weekday,
    /// Empty while `resource-spikes` is off.
    pub processes: Vec<ProcSample>,
    pub system_cpu_percent: f64,
    pub system_memory_percent: f64,
    /// `None` while `active-window` is off.
    pub foreground: Option<String>,
}

impl RecordedTick {
    pub fn keep(tick: &Tick, enabled_components: &[String]) -> Self {
        let on = |c: &str| enabled_components.iter().any(|e| e == c);
        let load = on(COMPONENT_SPIKES);
        Self {
            now: tick.now,
            local_time: tick.local_time,
            local_weekday: tick.local_weekday,
            processes: if load {
                tick.processes.iter().filter(|p| p.cpu_percent >= MIN_CPU_PERCENT || p.ram_mb >= MIN_MEMORY_MB).cloned().collect()
            } else {
                Vec::new()
            },
            system_cpu_percent: if load { tick.system_cpu_percent } else { 0.0 },
            system_memory_percent: if load { tick.system_memory_percent } else { 0.0 },
            foreground: if on(COMPONENT_FOREGROUND) { tick.foreground.map(str::to_owned) } else { None },
        }
    }

    pub fn as_tick<'a>(&'a self, events: &'a [ObservedEvent]) -> Tick<'a> {
        Tick {
            now: self.now,
            local_time: self.local_time,
            local_weekday: self.local_weekday,
            processes: &self.processes,
            system_cpu_percent: self.system_cpu_percent,
            system_memory_percent: self.system_memory_percent,
            foreground: self.foreground.as_deref(),
            events,
        }
    }
}

/// Keeps the newest [`MAX_RECORDED`] ticks.
pub fn remember(buf: &mut VecDeque<RecordedTick>, tick: RecordedTick) {
    if buf.len() >= MAX_RECORDED {
        buf.pop_front();
    }
    buf.push_back(tick);
}

/// Runs `rule` over `ticks` with a fresh evaluator. `events` are the log
/// entries read now; each tick only sees the ones logged before it.
pub fn replay(rule: &Rule, ticks: &[RecordedTick], events: &[ObservedEvent]) -> Value {
    let mut evaluator = Evaluator::new(rule.clone());
    let hits: Vec<Hit> = ticks.iter().filter_map(|t| evaluator.tick(&t.as_tick(events))).collect();
    let time = |t: Option<&RecordedTick>| t.map(|t| t.now.to_rfc3339_opts(SecondsFormat::Secs, true));
    json!({
        "samples": ticks.len(),
        "from": time(ticks.first()),
        "to": time(ticks.last()),
        "wouldHaveFired": hits.len(),
        "firstHits": hits.into_iter().take(MAX_SHOWN_HITS).collect::<Vec<_>>(),
        "note": format!(
            "How often this rule would have fired on the samples AegisWin kept in memory (up to the last {REPLAY_MINUTES} minutes, inside the watch window, while unlocked). \
             It is not a prediction: few or no samples means little was checked."
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::validate;
    use crate::COMPONENT_CRASHES;
    use chrono::{Datelike, Duration, TimeZone};

    fn components() -> Vec<String> {
        vec![COMPONENT_SPIKES.into(), COMPONENT_CRASHES.into(), COMPONENT_FOREGROUND.into()]
    }

    fn rule(trigger: Value) -> Rule {
        let v = json!({
            "version": 1, "name": "Replay", "schedule": { "startTime": "00:00", "endTime": "00:00" },
            "trigger": trigger, "cooldownSeconds": 60, "notify": "none"
        });
        validate(&v, &components()).unwrap()
    }

    fn proc(name: &str, cpu: f64, ram: u64) -> ProcSample {
        ProcSample { pid: 1, name: name.into(), cpu_percent: cpu, ram_mb: ram }
    }

    fn start() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 7, 12, 0, 0).unwrap()
    }

    /// `cpus[i]` is game.exe's CPU at the i-th 5-second sample.
    fn ticks(cpus: &[f64]) -> Vec<RecordedTick> {
        cpus.iter()
            .enumerate()
            .map(|(i, cpu)| {
                let now = start() + Duration::seconds(5 * i as i64);
                let processes = [proc("game.exe", *cpu, 900)];
                let tick = Tick { now, local_time: now.time(), local_weekday: now.weekday(), processes: &processes, system_cpu_percent: *cpu, system_memory_percent: 40.0, foreground: Some("game.exe"), events: &[] };
                RecordedTick::keep(&tick, &components())
            })
            .collect()
    }

    #[test]
    fn replay_counts_what_would_have_fired_and_respects_the_cooldown() {
        let r = rule(json!({ "any": [{ "type": "process_cpu", "process": "game.exe", "atLeastPercent": 50, "forSeconds": 10 }] }));
        // Busy for 3 samples, quiet, then busy again 15 s later: inside the 60 s cooldown.
        let mut cpus = vec![90.0, 90.0, 90.0, 5.0, 90.0, 90.0];
        let out = replay(&r, &ticks(&cpus), &[]);
        assert_eq!((out["samples"].as_u64(), out["wouldHaveFired"].as_u64()), (Some(6), Some(1)), "{out}");
        assert_eq!(out["firstHits"][0]["time"], "2026-11-07T12:00:05Z");

        // Past the cooldown it fires again.
        cpus.extend([5.0; 12]);
        cpus.extend([90.0, 90.0]);
        assert_eq!(replay(&r, &ticks(&cpus), &[])["wouldHaveFired"], 2);
        assert_eq!(replay(&r, &[], &[])["wouldHaveFired"], 0, "no history, nothing fires");
    }

    #[test]
    fn events_only_count_from_the_tick_they_were_logged() {
        let r = rule(json!({ "any": [{ "type": "crash", "process": "game.exe" }] }));
        let crash = ObservedEvent {
            channel: crate::rules::Channel::Application,
            provider: "Application Hang".into(),
            event_id: 1002,
            time: start() + Duration::seconds(12),
            message: "The program game.exe version 1.0 stopped interacting with Windows.".into(),
        };
        let out = replay(&r, &ticks(&[1.0; 6]), std::slice::from_ref(&crash));
        assert_eq!(out["wouldHaveFired"], 1);
        assert_eq!(out["firstHits"][0]["time"], "2026-11-07T12:00:15Z", "the first tick after the event");
    }

    #[test]
    fn only_what_enabled_components_allow_is_kept() {
        let now = start();
        let processes = [proc("game.exe", 30.0, 900), proc("idle.exe", 0.5, 10), proc("big.exe", 0.0, 64)];
        let tick = Tick { now, local_time: now.time(), local_weekday: now.weekday(), processes: &processes, system_cpu_percent: 30.0, system_memory_percent: 50.0, foreground: Some("game.exe"), events: &[] };

        let all = RecordedTick::keep(&tick, &components());
        let kept: Vec<&str> = all.processes.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(kept, ["game.exe", "big.exe"], "below every rule's lowest threshold is dropped");
        assert_eq!(all.foreground.as_deref(), Some("game.exe"));

        let none = RecordedTick::keep(&tick, &[COMPONENT_CRASHES.into()]);
        assert!(none.processes.is_empty() && none.foreground.is_none());
        assert_eq!((none.system_cpu_percent, none.system_memory_percent), (0.0, 0.0));
    }

    #[test]
    fn the_history_is_capped_at_thirty_minutes() {
        let mut buf = VecDeque::new();
        for t in ticks(&vec![1.0; MAX_RECORDED + 10]) {
            remember(&mut buf, t);
        }
        assert_eq!(buf.len(), 360);
        assert_eq!(buf.front().unwrap().now, start() + Duration::seconds(50));
    }
}
