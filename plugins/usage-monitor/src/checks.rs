//! Diagnose checks (ADR 0005 §4): memory pressure now and in the sampler's
//! recent ticks, and one process holding the CPU. Pure functions over what
//! was read and the time, so the tests feed them recorded ticks.

use std::collections::BTreeMap;

use aegis_core::diagnose::{CheckResult, Evidence, Finding, Next, Severity};
use chrono::{DateTime, Utc};

use crate::replay::RecordedTick;
use crate::ProcSample;

pub const MEMORY_PRESSURE_PERCENT: f64 = 90.0;
pub const CPU_HOG_PERCENT: f64 = 80.0;
/// Recent ticks needed to judge "most of the time" (one minute at 5 s).
pub const MIN_TICKS: usize = 12;

/// Memory as read now.
#[derive(Debug, Clone)]
pub struct MemoryNow {
    pub used_mb: u64,
    pub total_mb: u64,
    /// The processes using the most memory, largest first.
    pub top: Vec<ProcSample>,
}

impl MemoryNow {
    pub fn percent(&self) -> f64 {
        if self.total_mb == 0 {
            0.0
        } else {
            self.used_mb as f64 * 100.0 / self.total_mb as f64
        }
    }
}

fn gb(mb: u64) -> String {
    format!("{:.1} GB", mb as f64 / 1024.0)
}

fn minutes(ticks: &[&RecordedTick]) -> i64 {
    match (ticks.first(), ticks.last()) {
        (Some(a), Some(b)) => ((b.now - a.now).num_seconds() as f64 / 60.0).round().max(1.0) as i64,
        _ => 0,
    }
}

/// "the last minute", "the last 5 minutes".
fn the_last(ticks: &[&RecordedTick]) -> String {
    match minutes(ticks) {
        1 => "the last minute".into(),
        n => format!("the last {n} minutes"),
    }
}

fn more_than_half(n: usize, of: usize) -> bool {
    of > 0 && n * 2 > of
}

pub fn memory_pressure(now: &MemoryNow, recent: &[RecordedTick], at: DateTime<Utc>) -> CheckResult {
    let id = "memory_pressure";
    if now.total_mb == 0 {
        return CheckResult::failed(id, "Could not read how much memory this PC has.");
    }
    // A tick records memory only while Resource spikes is on; 0 means not recorded.
    let measured: Vec<&RecordedTick> = recent.iter().filter(|t| t.system_memory_percent > 0.0).collect();
    let high = measured.iter().filter(|t| t.system_memory_percent >= MEMORY_PRESSURE_PERCENT).count();
    let percent = now.percent();
    let high_now = percent >= MEMORY_PRESSURE_PERCENT;
    let high_lately = measured.len() >= MIN_TICKS && more_than_half(high, measured.len());
    if !high_now && !high_lately {
        return CheckResult::ran(id, vec![]);
    }
    let title = if high_now {
        format!("Memory is nearly full: {percent:.0}% in use")
    } else {
        format!("Memory was {MEMORY_PRESSURE_PERCENT:.0}% or more in use for most of {}", the_last(&measured))
    };
    let top: Vec<String> = now.top.iter().take(3).map(|p| format!("{} {}", p.name, gb(p.ram_mb))).collect();
    let mut message = format!("In use now: {percent:.0}% ({} of {}).", gb(now.used_mb), gb(now.total_mb));
    if !top.is_empty() {
        message.push_str(&format!(" Using the most: {}.", top.join(", ")));
    }
    if !measured.is_empty() {
        message.push_str(&format!(" {high} of the last {} samples were at {MEMORY_PRESSURE_PERCENT:.0}% or more.", measured.len()));
    }
    let mut next = vec![Next::Manual { text: "Close programs and browser tabs you are not using.".into() }];
    if let Some(p) = now.top.first() {
        next.push(Next::Manual { text: format!("{} is using the most memory; restart it if it keeps growing.", p.name) });
    }
    next.push(Next::Manual { text: "If this happens often, the PC may need more memory.".into() });
    let first = if high_lately { measured.iter().find(|t| t.system_memory_percent >= MEMORY_PRESSURE_PERCENT).map(|t| t.now) } else { Some(at) };
    CheckResult::ran(
        id,
        vec![Finding {
            key: None,
            severity: Severity::Warning,
            title,
            detail: "When memory runs out, Windows moves data to the disk, and everything slows down.".into(),
            count: 1,
            count_is_minimum: false,
            first_seen: first,
            last_seen: Some(at),
            evidence: vec![Evidence { source: "Memory".into(), provider: None, event_id: None, record_id: None, time: Some(at), message }],
            next,
        }],
    )
}

/// `recording`: the sampler is running with Resource spikes on, the only
/// time ticks hold which processes are busy.
pub fn sustained_cpu(recent: &[RecordedTick], recording: bool) -> CheckResult {
    let id = "sustained_cpu";
    if !recording {
        return CheckResult::skipped(id, "Needs Resource spikes turned on in the usage monitor, so it records which processes are busy.");
    }
    // Every tick records the busy processes while Resource spikes is on; an idle PC may record none.
    let ticks: Vec<&RecordedTick> = recent.iter().filter(|t| t.system_cpu_percent > 0.0).collect();
    if ticks.len() < MIN_TICKS {
        return CheckResult::skipped(id, "Not enough recent samples yet. Try again in a minute.");
    }
    let mut busy: BTreeMap<String, (String, Vec<f64>)> = BTreeMap::new();
    for t in &ticks {
        // One process at a time: the busiest process of each name in this tick.
        let mut top: BTreeMap<String, &ProcSample> = BTreeMap::new();
        for p in &t.processes {
            let entry = top.entry(p.name.to_ascii_lowercase()).or_insert(p);
            if p.cpu_percent > entry.cpu_percent {
                *entry = p;
            }
        }
        for (key, p) in top {
            if p.cpu_percent >= CPU_HOG_PERCENT {
                busy.entry(key).or_insert_with(|| (p.name.clone(), Vec::new())).1.push(p.cpu_percent);
            }
        }
    }
    let span = the_last(&ticks);
    let findings = busy
        .into_iter()
        .filter(|(_, (_, hits))| more_than_half(hits.len(), ticks.len()))
        .map(|(key, (name, hits))| {
            let average = hits.iter().sum::<f64>() / hits.len() as f64;
            Finding {
                key: Some(key),
                severity: Severity::Warning,
                title: format!("{name} used over {CPU_HOG_PERCENT:.0}% of the CPU for most of {span}"),
                detail: "One process using almost all of the processor makes everything else slow, and drains the battery on a laptop.".into(),
                count: hits.len() as u64,
                count_is_minimum: false,
                first_seen: ticks.first().map(|t| t.now),
                last_seen: ticks.last().map(|t| t.now),
                evidence: vec![Evidence {
                    source: "Usage sampler".into(),
                    provider: None,
                    event_id: None,
                    record_id: None,
                    time: ticks.last().map(|t| t.now),
                    message: format!("{name} was at {CPU_HOG_PERCENT:.0}% or more in {} of {} samples, {average:.0}% on average.", hits.len(), ticks.len()),
                }],
                next: vec![
                    Next::Manual { text: format!("If you are not using {name} right now, close it or restart it.") },
                    Next::Manual { text: "If you do not recognise it, check it with your antivirus.".into() },
                ],
            }
        })
        .collect();
    CheckResult::ran(id, findings)
}
