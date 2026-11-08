//! The monitor's encrypted history, *locked, monitoring*, and resume at
//! launch through the real engine (ADR 0002 §4-§6).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use aegis_core::engine::{Engine, EngineOptions, Origin, RunOutcome};
use aegis_core::registry::{ExitReason, Launch, Plugin, Registry};
use aegis_core::vault::KdfParams;
use aegis_core::ErrorCode;
use aegis_plugin_usage_monitor::{UsageMonitorPlugin, COMPONENT_CRASHES};
use serde_json::{json, Value};

const PIN: &str = "246810";
const UM: &str = "usage-monitor";

async fn engine() -> (Arc<Engine>, tempfile::TempDir) {
    let (engine, _plugin, dir) = engine_with_plugin().await;
    (engine, dir)
}

async fn engine_with_plugin() -> (Arc<Engine>, Arc<UsageMonitorPlugin>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let plugin = Arc::new(UsageMonitorPlugin::default());
    let registry = Registry::new(vec![Arc::clone(&plugin) as Arc<dyn Plugin>]).unwrap();
    let engine = Engine::new(dir.path().join("data"), registry, EngineOptions { kdf: KdfParams::INSECURE_TEST, elevated: false });
    engine.setup(PIN.into()).await.unwrap();
    engine.set_installed(BTreeMap::from([(UM.to_owned(), vec![COMPONENT_CRASHES.to_owned()])])).unwrap();
    (engine, plugin, dir)
}

fn reasons(view: &Value) -> Vec<String> {
    view["events"].as_array().unwrap().iter().filter(|e| e["kind"] == "session_stop").map(|e| e["reason"].as_str().unwrap().to_owned()).collect()
}

fn crash_rule() -> Value {
    json!({
        "version": 1, "name": "Game crashes",
        "schedule": { "startTime": "00:00", "endTime": "00:00" },
        "trigger": { "any": [{ "type": "crash", "process": "game.exe" }] },
        "cooldownSeconds": 600, "notify": "tray"
    })
}

fn ui(pin: Option<&str>) -> Origin {
    Origin::Ui { pin: pin.map(str::to_owned) }
}

async fn run(engine: &Engine, tool: &str, args: Value) -> aegis_core::AegisResult<Value> {
    match engine.run_tool(ui(Some(PIN)), UM, tool, args).await? {
        RunOutcome::Completed { result } => Ok(result),
        RunOutcome::PendingApproval { .. } => panic!("{tool} unexpectedly waited for approval"),
    }
}

fn kinds(view: &Value) -> Vec<String> {
    view["events"].as_array().unwrap().iter().map(|e| e["kind"].as_str().unwrap().to_owned()).collect()
}

fn segment_files(engine: &Engine) -> Vec<PathBuf> {
    std::fs::read_dir(engine.data_dir().join("history").join(UM)).map(|d| d.map(|e| e.unwrap().path()).collect()).unwrap_or_default()
}

fn runtime_file(engine: &Engine) -> PathBuf {
    engine.data_dir().join("runtime").join(format!("{UM}.json"))
}

#[tokio::test]
async fn reading_and_changing_history_needs_the_pin() {
    let (engine, _dir) = engine().await;
    for (tool, args) in [("read_monitor_history", json!({})), ("configure_history_retention", json!({ "maxDays": 3, "maxMb": 8 }))] {
        assert_eq!(engine.run_tool(ui(None), UM, tool, args.clone()).await.unwrap_err().code, ErrorCode::PinRequired, "{tool}");
        let outcome = engine.run_tool(Origin::Mcp, UM, tool, args).await.unwrap();
        assert!(matches!(outcome, RunOutcome::PendingApproval { .. }), "an agent waits for approval to {tool}");
    }
}

#[tokio::test]
async fn sessions_are_recorded_encrypted_and_a_running_monitor_keeps_going_while_locked() {
    let (engine, plugin, _dir) = engine_with_plugin().await;
    run(&engine, "activate_monitor", json!({ "rule": crash_rule() })).await.unwrap();
    engine.lock().await;
    assert!(plugin.is_sampling(), "locked, monitoring: the monitor keeps running");
    assert!(engine.locked_monitoring() && engine.background_active(), "the tray and close-to-tray see the locked work");
    engine.unlock(PIN.into()).await.unwrap();
    assert!(!engine.locked_monitoring());

    let files = segment_files(&engine);
    assert!(!files.is_empty());
    for file in &files {
        let raw = String::from_utf8_lossy(&std::fs::read(file).unwrap()).into_owned();
        assert!(!raw.contains("session_start") && !raw.contains("Game crashes"), "nothing readable on disk");
    }

    // Setup starts the sampler with every component on; choosing only the
    // crash component stops it; the monitor starts it again and it runs on
    // through the lock and the unlock, in one session.
    let view = run(&engine, "read_monitor_history", json!({ "days": 1 })).await.unwrap();
    assert_eq!(kinds(&view), ["session_start", "session_stop", "session_start"]);
    assert_eq!(reasons(&view), ["monitoring stopped"]);
    assert_eq!(view["events"][0]["launch"], "manual");
    let gaps = view["gaps"].as_array().unwrap();
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0]["kind"], "stopped");
    assert!(gaps[0]["label"].as_str().unwrap().contains("settings changed"));
    assert!(view["problems"].as_array().unwrap().is_empty());
    assert_eq!(view["retention"], json!({ "maxDays": 14, "maxMb": 64 }));
}

#[tokio::test]
async fn the_runtime_file_lists_the_running_monitors_only() {
    let (engine, _dir) = engine().await;
    assert!(!runtime_file(&engine).exists(), "nothing runs yet");
    run(&engine, "activate_monitor", json!({ "rule": crash_rule() })).await.unwrap();
    let file: Value = serde_json::from_slice(&std::fs::read(runtime_file(&engine)).unwrap()).unwrap();
    assert_eq!(file["stream"], UM);
    assert_eq!(file["plugin"]["monitors"][0]["id"], "m1");
    assert_eq!(file["plugin"]["monitors"][0]["rule"]["name"], "Game crashes");
    assert_eq!(file["plugin"]["components"], json!([COMPONENT_CRASHES]));
    let text = std::fs::read_to_string(runtime_file(&engine)).unwrap();
    assert!(!text.to_ascii_lowercase().contains("privatekey") && !text.contains(PIN));

    engine.lock().await;
    engine.unlock(PIN.into()).await.unwrap();
    assert!(engine.runtime_reviews().is_empty(), "an untouched file passes the check");

    run(&engine, "pause_monitor", json!({ "id": "m1" })).await.unwrap();
    assert!(!runtime_file(&engine).exists(), "a paused monitor does not run while locked");
}

#[tokio::test]
async fn purge_deletes_files_and_replaces_the_key() {
    let (engine, _dir) = engine().await;
    run(&engine, "activate_monitor", json!({ "rule": crash_rule() })).await.unwrap();
    let key_before: Value = serde_json::from_slice(&std::fs::read(runtime_file(&engine)).unwrap()).unwrap();
    let out = run(&engine, "purge_telemetry_history", json!({})).await.unwrap();
    assert_eq!(out["historyFilesRemoved"], 1);
    assert!(segment_files(&engine).is_empty());
    let key_after: Value = serde_json::from_slice(&std::fs::read(runtime_file(&engine)).unwrap()).unwrap();
    assert_ne!(key_before["keyId"], key_after["keyId"]);
    assert!(kinds(&run(&engine, "read_monitor_history", json!({})).await.unwrap()).is_empty());
}

#[tokio::test]
async fn retention_is_validated_and_shown_in_the_list() {
    let (engine, _dir) = engine().await;
    let err = engine.run_tool(ui(Some(PIN)), UM, "configure_history_retention", json!({ "maxDays": 0, "maxMb": 8 })).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArguments);
    run(&engine, "configure_history_retention", json!({ "maxDays": 3, "maxMb": 16 })).await.unwrap();
    let listed = engine.run_tool(ui(None), UM, "list_monitors", json!({})).await.unwrap();
    let RunOutcome::Completed { result } = listed else { panic!() };
    assert_eq!(result["historyRetention"], json!({ "maxDays": 3, "maxMb": 16 }));
}

#[tokio::test]
async fn a_lock_with_no_monitor_running_ends_the_session() {
    let (engine, plugin, _dir) = engine_with_plugin().await;
    run(&engine, "activate_monitor", json!({ "rule": crash_rule() })).await.unwrap();
    run(&engine, "pause_monitor", json!({ "id": "m1" })).await.unwrap();
    assert!(!plugin.is_sampling(), "the last monitor paused, nothing needs the sampler");
    run(&engine, "pause_monitor", json!({ "id": "m1", "paused": false })).await.unwrap();
    run(&engine, "delete_monitor", json!({ "id": "m1" })).await.unwrap();
    engine.lock().await;
    assert!(!plugin.is_sampling() && !engine.locked_monitoring() && !engine.background_active());
    engine.unlock(PIN.into()).await.unwrap();
    let view = run(&engine, "read_monitor_history", json!({})).await.unwrap();
    assert_eq!(kinds(&view), ["session_start", "session_stop", "session_start", "session_stop", "session_start", "session_stop"]);
}

#[tokio::test]
async fn the_tray_pause_is_recorded_and_quit_and_shutdown_say_why() {
    let (engine, plugin, _dir) = engine_with_plugin().await;
    run(&engine, "activate_monitor", json!({ "rule": crash_rule() })).await.unwrap();
    engine.lock().await;

    // Pausing needs no PIN and works while locked.
    engine.set_monitoring_paused(true);
    assert!(engine.monitoring_paused() && !plugin.is_sampling());
    let file: Value = serde_json::from_slice(&std::fs::read(runtime_file(&engine)).unwrap()).unwrap();
    assert_eq!(file["paused"], true);
    engine.set_monitoring_paused(false);
    assert!(plugin.is_sampling());

    engine.exit(ExitReason::Quit).await;
    assert!(!plugin.is_sampling() && !engine.locked_monitoring(), "exiting stops the locked work too");

    // A later launch (the same engine here) starts a new session; Windows ending it is a shutdown.
    engine.unlock(PIN.into()).await.unwrap();
    engine.exit(ExitReason::Shutdown).await;
    engine.unlock(PIN.into()).await.unwrap();

    let view = run(&engine, "read_monitor_history", json!({})).await.unwrap();
    assert_eq!(kinds(&view)[2..], ["session_start", "paused", "resumed", "session_stop", "session_start", "session_stop", "session_start"]);
    assert_eq!(reasons(&view)[1..], ["quit", "shutdown"]);
    let gaps: Vec<&str> = view["gaps"].as_array().unwrap().iter().map(|g| g["kind"].as_str().unwrap()).collect();
    assert_eq!(gaps, ["stopped", "paused", "stopped", "stopped"]);
}

#[tokio::test]
async fn a_pause_carries_over_a_lock_and_an_unlock() {
    let (engine, plugin, _dir) = engine_with_plugin().await;
    run(&engine, "activate_monitor", json!({ "rule": crash_rule() })).await.unwrap();
    engine.set_monitoring_paused(true);
    assert!(!plugin.is_sampling());
    engine.lock().await;
    assert!(!plugin.is_sampling() && engine.locked_monitoring(), "paused, but still the locked state with a monitor");
    engine.unlock(PIN.into()).await.unwrap();
    assert!(!plugin.is_sampling(), "still paused after unlock");
    let file: Value = serde_json::from_slice(&std::fs::read(runtime_file(&engine)).unwrap()).unwrap();
    assert_eq!(file["paused"], true);
    assert!(engine.runtime_reviews().is_empty(), "a tray pause is not tampering");
    engine.set_monitoring_paused(false);
    assert!(plugin.is_sampling());
}

#[tokio::test]
async fn a_runtime_file_waiting_for_review_does_not_run_while_locked() {
    let (engine, plugin, _dir) = engine_with_plugin().await;
    run(&engine, "activate_monitor", json!({ "rule": crash_rule() })).await.unwrap();
    let mut file: Value = serde_json::from_slice(&std::fs::read(runtime_file(&engine)).unwrap()).unwrap();
    file["plugin"]["components"] = json!(["usage-monitor:active-window"]);
    std::fs::write(runtime_file(&engine), serde_json::to_vec(&file).unwrap()).unwrap();

    engine.lock().await;
    engine.unlock(PIN.into()).await.unwrap();
    assert_eq!(engine.runtime_reviews().len(), 1, "the changed file was set aside");
    assert!(plugin.is_sampling(), "unlocked, the monitor runs from the vault");
    engine.lock().await;
    assert!(!plugin.is_sampling() && !engine.locked_monitoring(), "nothing runs locked until the owner reviews it");

    engine.unlock(PIN.into()).await.unwrap();
    engine.rewrite_runtime_from_vault(UM).unwrap();
    engine.lock().await;
    assert!(plugin.is_sampling(), "after the rewrite, locking keeps the monitor running");
}

/// A new launch of AegisWin on the same data folder: a fresh engine and plugin.
fn relaunch(dir: &tempfile::TempDir) -> (Arc<Engine>, Arc<UsageMonitorPlugin>) {
    let plugin = Arc::new(UsageMonitorPlugin::default());
    let registry = Registry::new(vec![Arc::clone(&plugin) as Arc<dyn Plugin>]).unwrap();
    (Engine::new(dir.path().join("data"), registry, EngineOptions { kdf: KdfParams::INSECURE_TEST, elevated: false }), plugin)
}

#[tokio::test]
async fn a_launch_resumes_running_monitors_locked_and_reports_the_gap_after_unlock() {
    let (engine, _plugin, dir) = engine_with_plugin().await;
    run(&engine, "activate_monitor", json!({ "rule": crash_rule() })).await.unwrap();
    engine.exit(ExitReason::Quit).await;
    drop(engine);

    let (engine, plugin) = relaunch(&dir);
    assert!(engine.resume_at_launch(Launch::Autostart), "the runtime file lists a running monitor");
    assert!(plugin.is_sampling() && engine.locked_monitoring() && !engine.status().unlocked);
    assert!(!engine.resume_at_launch(Launch::Manual), "only once per launch");

    engine.unlock(PIN.into()).await.unwrap();
    assert!(plugin.is_sampling(), "still running after unlock");
    let status = engine.status();
    assert!(status.runtime_reviews.is_empty(), "the file matched the vault");
    assert_eq!(status.resume_notices.len(), 1);
    let notice = &status.resume_notices[0];
    assert_eq!(notice.plugin_id, UM);
    assert!(notice.notice.from.is_some());
    assert!(notice.notice.label.contains("closed"), "{}", notice.notice.label);

    let view = run(&engine, "read_monitor_history", json!({})).await.unwrap();
    let starts: Vec<&Value> = view["events"].as_array().unwrap().iter().filter(|e| e["kind"] == "session_start").collect();
    assert_eq!(starts.last().unwrap()["launch"], "autostart", "this launch came from the Startup shortcut");
    assert_eq!(starts[0]["launch"], "manual");
    assert_eq!(reasons(&view).last().unwrap(), "quit");

    engine.dismiss_resume_notice(UM);
    assert!(engine.status().resume_notices.is_empty());
    engine.lock().await;
    engine.unlock(PIN.into()).await.unwrap();
    assert!(engine.status().resume_notices.is_empty(), "shown once per launch");
}

#[tokio::test]
async fn a_launch_keeps_the_tray_pause_and_resumes_nothing_from_a_set_aside_file() {
    let (engine, _plugin, dir) = engine_with_plugin().await;
    run(&engine, "activate_monitor", json!({ "rule": crash_rule() })).await.unwrap();
    engine.set_monitoring_paused(true);
    engine.exit(ExitReason::Quit).await;
    drop(engine);

    let (engine, plugin) = relaunch(&dir);
    assert!(engine.resume_at_launch(Launch::Manual));
    assert!(engine.monitoring_paused() && !plugin.is_sampling() && engine.locked_monitoring(), "paused, but the monitor is declared");
    engine.unlock(PIN.into()).await.unwrap();
    assert!(!plugin.is_sampling(), "still paused after unlock");
    engine.exit(ExitReason::Quit).await;
    drop(engine);

    // A set-aside copy waits for the owner, also across restarts.
    std::fs::copy(runtime_file_in(&dir), runtime_file_in(&dir).with_file_name(format!("{UM}.rejected.json"))).unwrap();
    let (engine, plugin) = relaunch(&dir);
    assert!(!engine.resume_at_launch(Launch::Autostart), "nothing resumes while a file waits for review");
    assert!(!plugin.is_sampling() && !engine.locked_monitoring());
}

#[tokio::test]
async fn a_changed_runtime_file_runs_until_the_next_unlock_then_the_vault_wins() {
    let (engine, _plugin, dir) = engine_with_plugin().await;
    run(&engine, "activate_monitor", json!({ "rule": crash_rule() })).await.unwrap();
    engine.exit(ExitReason::Quit).await;
    drop(engine);

    // Something edits the file while AegisWin is not running.
    let path = runtime_file_in(&dir);
    let mut file: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    file["plugin"]["components"] = json!([COMPONENT_CRASHES, "usage-monitor:active-window"]);
    // A file with a broken key is never resumed from.
    let mut broken = file.clone();
    broken["publicKey"] = json!("not a key");
    std::fs::write(&path, serde_json::to_vec(&broken).unwrap()).unwrap();
    let (engine, _plugin) = relaunch(&dir);
    assert!(!engine.resume_at_launch(Launch::Manual), "an invalid key is never used");
    drop(engine);

    std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
    let (engine, plugin) = relaunch(&dir);
    assert!(engine.resume_at_launch(Launch::Manual), "locked, the file cannot be checked (detected, not prevented)");
    engine.unlock(PIN.into()).await.unwrap();
    let status = engine.status();
    assert_eq!(status.runtime_reviews.len(), 1, "the unlock sets the changed file aside");
    assert!(plugin.is_sampling(), "the monitor now runs from the vault");
    let view = run(&engine, "list_monitors", json!({})).await.unwrap();
    assert_eq!(view["monitors"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn a_planted_file_for_an_uninstalled_plugin_stops_at_unlock() {
    let (engine, _plugin, dir) = engine_with_plugin().await;
    run(&engine, "activate_monitor", json!({ "rule": crash_rule() })).await.unwrap();
    let saved = std::fs::read(runtime_file_in(&dir)).unwrap();
    engine.set_installed(BTreeMap::new()).unwrap();
    engine.exit(ExitReason::Quit).await;
    drop(engine);
    std::fs::write(runtime_file_in(&dir), saved).unwrap();

    let (engine, plugin) = relaunch(&dir);
    assert!(engine.resume_at_launch(Launch::Manual), "locked, AegisWin cannot tell the plugin is not installed");
    engine.unlock(PIN.into()).await.unwrap();
    assert!(!plugin.is_sampling() && !engine.background_active(), "the unlock stops it");
    assert_eq!(engine.status().runtime_reviews.len(), 1, "and sets the file aside");
}

fn runtime_file_in(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("data").join("runtime").join(format!("{UM}.json"))
}
