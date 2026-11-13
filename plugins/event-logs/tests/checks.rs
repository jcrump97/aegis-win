//! Diagnose checks on recorded events (ADR 0005 §4): never this PC's logs,
//! except the last test, which only checks that the real reads work.

use std::sync::Arc;

use aegis_core::diagnose::{CheckContext, CheckOutcome, CheckResult, Finding, Severity, MAX_EVENTS_PER_QUERY};
use aegis_core::os::eventlog::EventRecord;
use aegis_core::registry::{Plugin, Registry};
use aegis_plugin_event_logs::checks::{self, ReadFailure, Reads, Window, CHECKS, READS};
use aegis_plugin_event_logs::EventLogsPlugin;
use chrono::{DateTime, Duration, Utc};

fn now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-11-10T12:00:00Z").unwrap().with_timezone(&Utc)
}

fn window(days: u32) -> Window {
    Window { since: now() - Duration::days(i64::from(days)), now: now(), days }
}

/// An event `minutes` before now.
fn ev(provider: &str, event_id: u32, minutes: i64, message: &str) -> EventRecord {
    EventRecord {
        record_id: (minutes as u64) * 10 + u64::from(event_id),
        time_created: (now() - Duration::minutes(minutes)).to_rfc3339(),
        provider: provider.into(),
        event_id,
        level: 2,
        level_name: "Error",
        message: Some(message.into()),
    }
}

const DAY: i64 = 24 * 60;

fn run(reads: &Reads, days: u32) -> Vec<CheckResult> {
    checks::evaluate_all(reads, &window(days))
}

fn findings<'a>(results: &'a [CheckResult], id: &str) -> &'a [Finding] {
    match &results.iter().find(|r| r.check == id).unwrap().outcome {
        CheckOutcome::Ran(f) => f,
        other => panic!("{id}: {other:?}"),
    }
}

fn first(reads: &Reads, days: u32, id: &str) -> Finding {
    findings(&run(reads, days), id).first().cloned().unwrap_or_else(|| panic!("{id}: no finding"))
}

fn kp41(minutes: i64) -> EventRecord {
    ev("Microsoft-Windows-Kernel-Power", 41, minutes, "The system has rebooted without cleanly shutting down first.")
}

fn bugcheck(minutes: i64, code: &str) -> EventRecord {
    ev("Microsoft-Windows-WER-SystemErrorReporting", 1001, minutes, &format!("The computer has rebooted from a bugcheck.  The bugcheck was: {code} (0x1, 0x2). A dump was saved in: C:\\WINDOWS\\MEMORY.DMP."))
}

#[test]
fn the_manifest_declares_exactly_the_checks_the_code_runs() {
    let plugin = EventLogsPlugin::default();
    let declared: Vec<&str> = plugin.manifest().checks.iter().map(|c| c.id.as_str()).collect();
    let coded: Vec<&str> = CHECKS.iter().map(|(id, _)| *id).collect();
    assert_eq!(declared, coded);
    for (id, keys) in CHECKS {
        for key in *keys {
            assert!(READS.iter().any(|r| r.key == *key), "{id} needs a read for {key}");
        }
    }
    // The suggested tools belong to windows-health: valid only with both plugins compiled in.
    Registry::new(vec![Arc::new(EventLogsPlugin::default()) as Arc<dyn Plugin>, Arc::new(aegis_plugin_windows_health::WindowsHealthPlugin::default())]).unwrap();
    assert!(Registry::new(vec![Arc::new(EventLogsPlugin::default()) as Arc<dyn Plugin>]).is_err());
}

#[test]
fn a_quiet_log_finds_nothing() {
    let results = run(&Reads::default(), 7);
    assert_eq!(results.len(), CHECKS.len());
    assert!(results.iter().all(|r| r.outcome == CheckOutcome::Ran(vec![])));
}

#[test]
fn unexpected_shutdowns_count_incidents_and_leave_blue_screens_out() {
    let reads = Reads::default()
        // One restart: 41 and 6008 logged together count once.
        .with("kernel_power", vec![kp41(60), kp41(3 * DAY)])
        .with("unexpected", vec![ev("EventLog", 6008, 61, "The previous system shutdown at 10:58 was unexpected.")])
        // This 41 belongs to a blue screen.
        .with("bugcheck", vec![bugcheck(2 * DAY + 1, "0x0000009f")])
        .with("kernel_power", vec![kp41(2 * DAY)]);
    let results = run(&reads, 7);
    let shutdowns = findings(&results, "unexpected_shutdown");
    assert_eq!(shutdowns.len(), 1);
    let f = &shutdowns[0];
    assert_eq!((f.count, f.severity), (2, Severity::Warning));
    assert_eq!(f.title, "Windows shut down unexpectedly 2 times in the last 7 days");
    assert_eq!(f.last_seen, Some(now() - Duration::minutes(60)));
    assert_eq!(f.first_seen, Some(now() - Duration::minutes(3 * DAY)));
    assert_eq!(f.evidence.len(), 3);
    assert_eq!(findings(&results, "blue_screen")[0].count, 1);

    let three = Reads::default().with("kernel_power", vec![kp41(60), kp41(DAY), kp41(2 * DAY)]);
    assert_eq!(findings(&run(&three, 7), "unexpected_shutdown")[0].severity, Severity::Critical);
}

#[test]
fn blue_screens_name_their_stop_codes() {
    assert_eq!(checks::stop_code("... The bugcheck was: 0x0000009f (0x3, ...)").as_deref(), Some("0x9F"));
    assert_eq!(checks::stop_code("no code here"), None);
    let one = Reads::default().with("bugcheck", vec![bugcheck(30, "0x00000133")]);
    let f = first(&one, 7, "blue_screen");
    assert_eq!(f.severity, Severity::Warning, "a single blue screen is already a warning");
    assert_eq!(f.title, "Windows stopped with a blue screen once in the last 7 days (stop code 0x133)");
    assert_eq!(f.next.len(), 3);
    let two = Reads::default().with("bugcheck", vec![bugcheck(30, "0x133"), bugcheck(DAY, "0x9f")]);
    let f = first(&two, 7, "blue_screen");
    assert_eq!(f.severity, Severity::Critical);
    assert!(f.title.ends_with("(stop code 0x133, 0x9F)"), "{}", f.title);
}

fn crash(program: &str, minutes: i64) -> EventRecord {
    ev("Application Error", 1000, minutes, &format!("Faulting application name: {program}, version: 1.0.0.0, time stamp: 0x0"))
}

#[test]
fn app_crashes_are_grouped_by_program_from_three() {
    let hang = ev("Application Hang", 1002, 3 * 60 + 2, "The program Game.exe version 1.0 stopped interacting with Windows and was closed.");
    let reads = Reads::default().with(
        "app_crash",
        vec![crash("Game.exe", 60), crash("Game.exe", 2 * 60), crash("Game.exe", 3 * 60), hang, crash("notes.exe", 10), crash("notes.exe", DAY)],
    );
    let found = findings(&run(&reads, 7), "app_crashes").to_vec();
    assert_eq!(found.len(), 1, "notes.exe crashed only twice");
    assert_eq!(found[0].key.as_deref(), Some("game.exe"));
    // The hang and the crash two minutes apart are one incident.
    assert_eq!((found[0].count, found[0].severity), (3, Severity::Info));
    let many = Reads::default().with("app_crash", (0..10).map(|i| crash("game.exe", i * 60)).collect());
    assert_eq!(findings(&run(&many, 7), "app_crashes")[0].severity, Severity::Warning);
    // Messages AegisWin cannot read are grouped, not dropped.
    let unnamed = Reads::default().with("app_crash", (0..3).map(|i| ev("Application Error", 1000, i * 60, "Nom de l'application défaillante")).collect());
    let f = first(&unnamed, 7, "app_crashes");
    assert_eq!(f.key.as_deref(), Some("unknown"));
    assert!(f.title.starts_with("A program AegisWin could not name"));
}

fn scm(id: u32, service: &str, minutes: i64) -> EventRecord {
    let msg = match id {
        7031 | 7034 => format!("The {service} service terminated unexpectedly.  It has done this 1 time(s)."),
        7000 => format!("The {service} service failed to start due to the following error: ..."),
        _ => format!("A timeout was reached (30000 milliseconds) while waiting for the {service} service to connect."),
    };
    ev("Service Control Manager", id, minutes, &msg)
}

#[test]
fn service_failures_by_service_without_one_off_boot_timing() {
    let boot = |m| ev("EventLog", 6005, m, "The Event log service was started.");
    let reads = Reads::default()
        .with("boot", vec![boot(DAY), boot(2 * DAY)])
        // Failed to start once, a minute after one boot: left out.
        .with("scm", vec![scm(7000, "Slow Starter", DAY - 1)])
        // At two boots: kept.
        .with("scm", vec![scm(7009, "Flaky Agent", DAY - 1), scm(7009, "Flaky Agent", 2 * DAY - 1)])
        // Crashed: kept, whenever it happened.
        .with("scm", vec![scm(7031, "Print Spooler", 30), scm(7034, "Print Spooler", 3 * 60), scm(7031, "Print Spooler", 6 * 60)]);
    let found = findings(&run(&reads, 7), "service_failures").to_vec();
    let keys: Vec<_> = found.iter().map(|f| f.key.as_deref().unwrap()).collect();
    assert_eq!(keys, ["Flaky Agent", "Print Spooler"]);
    assert_eq!(found[0].title, "The Flaky Agent service failed to start 2 times in the last 7 days");
    assert_eq!(found[0].severity, Severity::Info);
    assert_eq!(found[1].title, "The Print Spooler service stopped unexpectedly 3 times in the last 7 days");
    assert_eq!(found[1].severity, Severity::Warning);
}

#[test]
fn disk_and_hardware_errors_are_warnings_from_one_and_serious_ones_critical() {
    let reset = Reads::default().with("disk", vec![ev("stornvme", 129, 60, "Reset to device, \\Device\\RaidPort0, was issued.")]);
    let f = first(&reset, 7, "disk_errors");
    assert_eq!((f.count, f.severity), (1, Severity::Warning));
    let bad_block = Reads::default().with("disk", vec![ev("disk", 7, 60, "The device, \\Device\\Harddisk0\\DR0, has a bad block.")]);
    assert_eq!(findings(&run(&bad_block, 7), "disk_errors")[0].severity, Severity::Critical);

    let corrected = Reads::default().with("whea", vec![ev("Microsoft-Windows-WHEA-Logger", 17, 60, "A corrected hardware error has occurred.")]);
    assert_eq!(findings(&run(&corrected, 7), "hardware_errors")[0].severity, Severity::Warning);
    let fatal = Reads::default().with("whea", vec![ev("Microsoft-Windows-WHEA-Logger", 18, 60, "A fatal hardware error has occurred.")]);
    assert_eq!(findings(&run(&fatal, 7), "hardware_errors")[0].severity, Severity::Critical);
}

#[test]
fn display_resets_and_update_failures_grow_from_info_to_warning() {
    let resets = |n: i64| Reads::default().with("display", (0..n).map(|i| ev("Display", 4101, i * 60, "Display driver nvlddmkm stopped responding and has successfully recovered.")).collect());
    assert_eq!(findings(&run(&resets(1), 7), "display_driver_resets")[0].severity, Severity::Info);
    assert_eq!(findings(&run(&resets(3), 7), "display_driver_resets")[0].severity, Severity::Warning);
    let updates = Reads::default().with("update", vec![ev("Microsoft-Windows-WindowsUpdateClient", 20, 60, "Installation Failure: Windows failed to install the following update with error 0x80070002: KB5000001.")]);
    let f = first(&updates, 7, "update_failures");
    assert_eq!(f.severity, Severity::Info);
    assert!(matches!(&f.next[0], aegis_core::diagnose::Next::Tool { tool, .. } if tool == "windows-health:sfc_scan"));
}

#[test]
fn dns_timeouts_need_ten_and_count_each_one() {
    let timeouts = |n: i64| Reads::default().with("dns", (0..n).map(|i| ev("Microsoft-Windows-DNS-Client", 1014, i, "Name resolution for the name example.com timed out.")).collect());
    assert!(findings(&run(&timeouts(9), 7), "dns_timeouts").is_empty());
    let f = first(&timeouts(10), 7, "dns_timeouts");
    assert_eq!((f.count, f.severity), (10, Severity::Info));
    assert!(matches!(&f.next[0], aegis_core::diagnose::Next::Tool { tool, .. } if tool == "windows-health:flush_dns"));
    assert_eq!(findings(&run(&timeouts(50), 7), "dns_timeouts")[0].severity, Severity::Warning);
}

#[test]
fn only_the_lookback_window_counts_and_a_full_read_is_at_least() {
    let old = Reads::default().with("bugcheck", vec![bugcheck(2 * DAY, "0x9f")]);
    assert!(findings(&run(&old, 1), "blue_screen").is_empty());
    assert_eq!(findings(&run(&old, 7), "blue_screen").len(), 1);

    let full = Reads::default().with("dns", (0..MAX_EVENTS_PER_QUERY as i64).map(|i| ev("Microsoft-Windows-DNS-Client", 1014, i, "timed out")).collect());
    let f = first(&full, 7, "dns_timeouts");
    assert!(f.count_is_minimum);
    assert_eq!(f.evidence.len(), aegis_core::diagnose::MAX_EVIDENCE);
}

#[test]
fn a_read_that_fails_affects_only_the_checks_that_need_it() {
    let mut reads = Reads::default();
    reads.fail("bugcheck", ReadFailure::NeedsAdmin("Reading the System log needs administrator rights.".into()));
    reads.fail("dns", ReadFailure::Failed("Could not read the System log: broken".into()));
    let results = run(&reads, 7);
    let outcome = |id: &str| results.iter().find(|r| r.check == id).unwrap().outcome.clone();
    assert!(matches!(outcome("blue_screen"), CheckOutcome::Skipped(_)));
    assert!(matches!(outcome("unexpected_shutdown"), CheckOutcome::Skipped(_)));
    assert!(matches!(outcome("dns_timeouts"), CheckOutcome::Failed(_)));
    assert_eq!(outcome("disk_errors"), CheckOutcome::Ran(vec![]));
}

#[tokio::test]
async fn the_real_logs_can_be_read_by_every_check() {
    let ctx = CheckContext { lookback_days: 1, enabled_components: vec![], elevated: false, now: Utc::now() };
    let results = EventLogsPlugin::default().run_checks(&ctx).await;
    assert_eq!(results.len(), CHECKS.len());
    for r in &results {
        assert!(matches!(r.outcome, CheckOutcome::Ran(_)), "{}: {:?}", r.check, r.outcome);
    }
}

#[tokio::test]
async fn the_engine_runs_these_checks_and_keeps_their_steps_to_next_tools() {
    use aegis_core::diagnose::{CheckStatus, NextStep};
    use aegis_core::engine::{Engine, EngineOptions};
    let dir = tempfile::tempdir().unwrap();
    let registry = Registry::new(vec![Arc::new(EventLogsPlugin::default()) as Arc<dyn Plugin>, Arc::new(aegis_plugin_windows_health::WindowsHealthPlugin::default())]).unwrap();
    let engine = Engine::new(dir.path().join("data"), registry, EngineOptions { kdf: aegis_core::vault::KdfParams::INSECURE_TEST, elevated: false });
    engine.setup("two-four-six-eight".into()).await.unwrap();
    let selection = [("event-logs".to_owned(), vec![]), ("windows-health".to_owned(), vec![])].into_iter().collect();
    engine.set_installed(selection).unwrap();
    let report = engine.diagnose(30).await.unwrap();
    let ids: Vec<String> = report.checks.iter().map(|c| c.id.trim_start_matches("event-logs.").to_owned()).collect();
    assert_eq!(ids, CHECKS.iter().map(|(id, _)| id.to_string()).collect::<Vec<_>>());
    assert!(report.checks.iter().all(|c| c.status != CheckStatus::Failed), "{:?}", report.checks);
    for f in &report.findings {
        for step in &f.next {
            if let NextStep::Tool { tool, .. } = step {
                assert!(["windows-health:sfc_scan", "windows-health:flush_dns"].contains(&tool.as_str()), "{tool}");
            }
        }
    }
}
