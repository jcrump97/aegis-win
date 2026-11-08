//! The monitor's encrypted history through the real engine (ADR 0002 §5).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use aegis_core::engine::{Engine, EngineOptions, Origin, RunOutcome};
use aegis_core::registry::{Plugin, Registry};
use aegis_core::vault::KdfParams;
use aegis_core::ErrorCode;
use aegis_plugin_usage_monitor::{UsageMonitorPlugin, COMPONENT_CRASHES};
use serde_json::{json, Value};

const PIN: &str = "246810";
const UM: &str = "usage-monitor";

async fn engine() -> (Arc<Engine>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let registry = Registry::new(vec![Arc::new(UsageMonitorPlugin::default()) as Arc<dyn Plugin>]).unwrap();
    let engine = Engine::new(dir.path().join("data"), registry, EngineOptions { kdf: KdfParams::INSECURE_TEST, elevated: false });
    engine.setup(PIN.into()).await.unwrap();
    engine.set_installed(BTreeMap::from([(UM.to_owned(), vec![COMPONENT_CRASHES.to_owned()])])).unwrap();
    (engine, dir)
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
async fn sessions_are_recorded_encrypted_and_a_lock_shows_as_a_stop() {
    let (engine, _dir) = engine().await;
    run(&engine, "activate_monitor", json!({ "rule": crash_rule() })).await.unwrap();
    engine.lock().await;
    engine.unlock(PIN.into()).await.unwrap();

    let files = segment_files(&engine);
    assert!(!files.is_empty());
    for file in &files {
        let raw = String::from_utf8_lossy(&std::fs::read(file).unwrap()).into_owned();
        assert!(!raw.contains("session_start") && !raw.contains("Game crashes"), "nothing readable on disk");
    }

    // Setup starts the sampler with every component on; choosing components
    // restarts it; the monitor starts it again; lock stops it; unlock restarts.
    let view = run(&engine, "read_monitor_history", json!({ "days": 1 })).await.unwrap();
    assert_eq!(kinds(&view), ["session_start", "session_stop", "session_start", "session_stop", "session_start"]);
    assert_eq!(view["events"][3]["reason"], "monitoring stopped");
    assert_eq!(view["events"][0]["launch"], "manual");
    let gaps = view["gaps"].as_array().unwrap();
    assert_eq!(gaps.len(), 2);
    assert!(gaps.iter().all(|g| g["kind"] == "stopped"));
    assert!(gaps[1]["label"].as_str().unwrap().contains("locked"));
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
