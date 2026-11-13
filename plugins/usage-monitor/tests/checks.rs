//! Diagnose checks on recorded ticks (ADR 0005 §4).

use aegis_core::diagnose::{CheckContext, CheckOutcome, CheckResult, Finding, Severity};
use aegis_core::registry::Plugin;
use aegis_plugin_usage_monitor::checks::{self, MemoryNow, MIN_TICKS};
use aegis_plugin_usage_monitor::replay::RecordedTick;
use aegis_plugin_usage_monitor::{ProcSample, UsageMonitorPlugin};
use chrono::{DateTime, Duration, NaiveTime, Utc, Weekday};

fn now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-11-10T12:00:00Z").unwrap().with_timezone(&Utc)
}

fn proc(name: &str, cpu: f64, ram_mb: u64) -> ProcSample {
    ProcSample { pid: 1, name: name.into(), cpu_percent: cpu, ram_mb }
}

/// `n` ticks five seconds apart, ending now.
fn ticks(n: usize, memory: f64, processes: impl Fn(usize) -> Vec<ProcSample>) -> Vec<RecordedTick> {
    (0..n)
        .map(|i| RecordedTick {
            now: now() - Duration::seconds(5 * (n - 1 - i) as i64),
            local_time: NaiveTime::from_hms_opt(12, 0, 0).unwrap(),
            local_weekday: Weekday::Tue,
            processes: processes(i),
            system_cpu_percent: 20.0,
            system_memory_percent: memory,
            foreground: None,
        })
        .collect()
}

fn ran(r: CheckResult) -> Vec<Finding> {
    match r.outcome {
        CheckOutcome::Ran(f) => f,
        other => panic!("{other:?}"),
    }
}

fn memory(used_mb: u64) -> MemoryNow {
    MemoryNow { used_mb, total_mb: 16384, top: vec![proc("chrome.exe", 0.0, 4096), proc("game.exe", 0.0, 2048)] }
}

#[test]
fn the_manifest_declares_exactly_the_checks_the_code_runs() {
    let plugin = UsageMonitorPlugin::default();
    let ids: Vec<&str> = plugin.manifest().checks.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids, ["memory_pressure", "sustained_cpu"]);
}

#[test]
fn memory_nearly_full_now_is_a_finding() {
    let f = ran(checks::memory_pressure(&memory(15_000), &[], now()));
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].severity, Severity::Warning);
    assert_eq!(f[0].title, "Memory is nearly full: 92% in use");
    assert!(f[0].evidence[0].message.contains("chrome.exe 4.0 GB"), "{}", f[0].evidence[0].message);
    assert!(ran(checks::memory_pressure(&memory(8_000), &[], now())).is_empty());
}

#[test]
fn memory_high_in_most_recent_samples_is_a_finding_even_if_fine_now() {
    let busy = ticks(MIN_TICKS, 95.0, |_| vec![]);
    let f = ran(checks::memory_pressure(&memory(8_000), &busy, now()));
    assert_eq!(f[0].title, "Memory was 90% or more in use for most of the last minute");
    // Too few samples to judge, or only half of them high: nothing.
    assert!(ran(checks::memory_pressure(&memory(8_000), &busy[..MIN_TICKS - 1], now())).is_empty());
    let half: Vec<_> = ticks(MIN_TICKS, 95.0, |_| vec![]).into_iter().enumerate().map(|(i, mut t)| {
        if i % 2 == 0 {
            t.system_memory_percent = 50.0;
        }
        t
    }).collect();
    assert!(ran(checks::memory_pressure(&memory(8_000), &half, now())).is_empty());
    // Ticks without Resource spikes record no memory (0) and are not counted.
    assert!(ran(checks::memory_pressure(&memory(8_000), &ticks(MIN_TICKS, 0.0, |_| vec![]), now())).is_empty());
}

#[test]
fn memory_that_cannot_be_read_fails_the_check() {
    let r = checks::memory_pressure(&MemoryNow { used_mb: 0, total_mb: 0, top: vec![] }, &[], now());
    assert!(matches!(r.outcome, CheckOutcome::Failed(_)));
}

#[test]
fn sustained_cpu_needs_the_sampler_and_enough_samples() {
    assert!(matches!(checks::sustained_cpu(&[], false).outcome, CheckOutcome::Skipped(_)));
    let few = ticks(MIN_TICKS - 1, 50.0, |_| vec![proc("miner.exe", 95.0, 100)]);
    assert!(matches!(checks::sustained_cpu(&few, true).outcome, CheckOutcome::Skipped(_)));
}

#[test]
fn one_process_over_the_limit_in_most_samples_is_a_finding() {
    let recent = ticks(20, 50.0, |i| {
        let mut p = vec![proc("Miner.exe", if i < 15 { 92.0 } else { 10.0 }, 100), proc("browser.exe", if i < 8 { 85.0 } else { 5.0 }, 100)];
        // Two processes of one name: the busiest counts, they are not added up.
        p.push(proc("svc.exe", 45.0, 10));
        p.push(proc("svc.exe", 45.0, 10));
        p
    });
    let f = ran(checks::sustained_cpu(&recent, true));
    assert_eq!(f.len(), 1, "browser.exe was busy in 8 of 20 samples, svc.exe never over 80 alone");
    assert_eq!(f[0].key.as_deref(), Some("miner.exe"));
    assert_eq!(f[0].count, 15);
    assert_eq!(f[0].title, "Miner.exe used over 80% of the CPU for most of the last 2 minutes");
    assert!(f[0].evidence[0].message.contains("15 of 20 samples, 92% on average"));
}

#[tokio::test]
async fn the_plugin_reports_both_checks_here() {
    let ctx = CheckContext { lookback_days: 7, enabled_components: vec![], elevated: false, now: Utc::now() };
    let results = UsageMonitorPlugin::default().run_checks(&ctx).await;
    let ids: Vec<&str> = results.iter().map(|r| r.check.as_str()).collect();
    assert_eq!(ids, ["memory_pressure", "sustained_cpu"]);
    assert!(matches!(results[0].outcome, CheckOutcome::Ran(_)));
    // Not sampling in a fresh plugin.
    assert!(matches!(results[1].outcome, CheckOutcome::Skipped(_)));
}
