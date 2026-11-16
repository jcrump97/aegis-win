//! Restart as administrator through the real engine and monitor (SECURITY_MODEL §5).
//! The launch is a closure, so no UAC prompt is involved.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;

use aegis_core::engine::{Engine, EngineOptions, Origin, RunOutcome};
use aegis_core::registry::{ExitReason, Launch, Plugin, Registry};
use aegis_core::restart::restart_elevated;
use aegis_core::vault::KdfParams;
use aegis_core::ErrorCode;
use aegis_plugin_usage_monitor::{UsageMonitorPlugin, COMPONENT_CRASHES};
use serde_json::{json, Value};

const PIN: &str = "two-four-six-eight";
const UM: &str = "usage-monitor";

fn engine_in(dir: &tempfile::TempDir) -> (Arc<Engine>, Arc<UsageMonitorPlugin>) {
    let plugin = Arc::new(UsageMonitorPlugin::default());
    let registry = Registry::new(vec![Arc::clone(&plugin) as Arc<dyn Plugin>]).unwrap();
    (Engine::new(dir.path().join("data"), registry, EngineOptions { kdf: KdfParams::INSECURE_TEST, elevated: false }), plugin)
}

/// A set-up engine with one running monitor, locked (*locked, monitoring*).
async fn locked_monitoring() -> (Arc<Engine>, Arc<UsageMonitorPlugin>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let (engine, plugin) = engine_in(&dir);
    engine.setup(PIN.into()).await.unwrap();
    engine.set_installed(BTreeMap::from([(UM.to_owned(), vec![COMPONENT_CRASHES.to_owned()])])).unwrap();
    let rule = json!({
        "version": 1, "name": "Game crashes", "schedule": { "startTime": "00:00", "endTime": "00:00" },
        "trigger": { "any": [{ "type": "crash", "process": "game.exe" }] }, "cooldownSeconds": 600, "notify": "tray"
    });
    run(&engine, "activate_monitor", json!({ "rule": rule })).await.unwrap();
    engine.lock().await;
    assert!(plugin.is_sampling() && engine.locked_monitoring());
    (engine, plugin, dir)
}

async fn run(engine: &Engine, tool: &str, args: Value) -> aegis_core::AegisResult<Value> {
    match engine.run_tool(Origin::Ui { pin: Some(PIN.into()) }, UM, tool, args).await? {
        RunOutcome::Completed { result } => Ok(result),
        RunOutcome::PendingApproval { .. } => panic!("{tool} unexpectedly waited for approval"),
    }
}

fn kinds(view: &Value) -> Vec<String> {
    view["events"].as_array().unwrap().iter().map(|e| e["kind"].as_str().unwrap().to_owned()).collect()
}

fn quits(view: &Value) -> usize {
    view["events"].as_array().unwrap().iter().filter(|e| e["kind"] == "session_stop" && e["reason"] == "quit").count()
}

#[tokio::test]
async fn a_cancelled_or_failed_launch_leaves_monitoring_running_and_records_no_quit() {
    for (error, code) in [(io::ErrorKind::Interrupted, ErrorCode::AccessDenied), (io::ErrorKind::NotFound, ErrorCode::ExecutionFailed)] {
        let (engine, plugin, _dir) = locked_monitoring().await;
        let (released, quit) = (Cell::new(false), Cell::new(false));
        let out = restart_elevated(&engine, || Err(io::Error::from(error)), || released.set(true), || quit.set(true)).await;
        assert_eq!(out.unwrap_err().code, code);
        assert!(!released.get() && !quit.get(), "the claim is kept and the app does not quit");
        assert!(plugin.is_sampling() && engine.locked_monitoring(), "monitoring keeps running, locked");

        engine.unlock(PIN.into()).await.unwrap();
        let view = run(&engine, "read_monitor_history", json!({})).await.unwrap();
        assert_eq!(quits(&view), 0, "no quit record: {view}");
    }
}

#[tokio::test]
async fn an_accepted_launch_records_the_quit_once_and_the_new_copy_starts_only_after_it() {
    let (engine, plugin, dir) = locked_monitoring().await;
    let steps = RefCell::new(Vec::new());
    let launch = || {
        assert!(plugin.is_sampling(), "nothing is stopped before the launch is accepted");
        steps.borrow_mut().push("launch");
        Ok(())
    };
    // The install claim is let go only after monitoring stopped and the quit record is written;
    // the elevated copy waits for the claim before it resumes anything.
    let release = || {
        assert!(!plugin.is_sampling() && !engine.locked_monitoring(), "the old copy stopped before the elevated copy can claim the install");
        steps.borrow_mut().push("release");
    };
    restart_elevated(&engine, launch, release, || steps.borrow_mut().push("quit")).await.unwrap();
    assert_eq!(*steps.borrow(), ["launch", "release", "quit"]);
    // The app's exit handler runs the exit again: it adds no second record.
    engine.exit(ExitReason::Quit).await;
    drop(engine);

    let (elevated, new_plugin) = engine_in(&dir);
    assert!(elevated.resume_at_launch(Launch::Manual) && new_plugin.is_sampling());
    elevated.unlock(PIN.into()).await.unwrap();
    let view = run(&elevated, "read_monitor_history", json!({})).await.unwrap();
    assert_eq!(quits(&view), 1, "{view}");
    let events = view["events"].as_array().unwrap();
    let quit_at = events.iter().position(|e| e["kind"] == "session_stop" && e["reason"] == "quit").unwrap();
    let starts_after: Vec<&Value> = events[quit_at..].iter().filter(|e| e["kind"] == "session_start").collect();
    assert_eq!((starts_after.len(), events.last().unwrap()["kind"].as_str()), (1, Some("session_start")), "the new session starts after the quit: {:?}", kinds(&view));
}

#[tokio::test]
async fn already_elevated_or_busy_refuses_before_launching() {
    let dir = tempfile::tempdir().unwrap();
    let plugin = Arc::new(UsageMonitorPlugin::default());
    let registry = Registry::new(vec![plugin as Arc<dyn Plugin>]).unwrap();
    let engine = Engine::new(dir.path().join("data"), registry, EngineOptions { kdf: KdfParams::INSECURE_TEST, elevated: true });
    let launched = Cell::new(false);
    let out = restart_elevated(&engine, || { launched.set(true); Ok(()) }, || {}, || {}).await;
    assert_eq!(out.unwrap_err().code, ErrorCode::Conflict);
    assert!(!launched.get());
}
