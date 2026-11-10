use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use aegis_core::engine::{Engine, EngineOptions, Origin, RunOutcome};
use aegis_core::registry::{GatePolicy, Plugin, Registry, ToolContext, UnlockContext};
use aegis_core::tickets::TicketStatus;
use aegis_core::vault::KdfParams;
use aegis_core::{schema, ErrorCode};
use aegis_plugin_usage_monitor::{UsageMonitorPlugin, COMPONENT_CRASHES, COMPONENT_FOREGROUND, COMPONENT_SPIKES};
use serde_json::{json, Value};

const PIN: &str = "two-four-six-eight";

fn all_components() -> Vec<String> {
    vec![COMPONENT_SPIKES.into(), COMPONENT_CRASHES.into(), COMPONENT_FOREGROUND.into()]
}

async fn call(plugin: &UsageMonitorPlugin, tool: &str, args: Value, ctx: ToolContext) -> aegis_core::AegisResult<Value> {
    let schema = &plugin.manifest().tool(tool).unwrap().input_schema;
    let args = schema::validate(schema, args).map_err(aegis_core::AegisError::invalid)?;
    plugin.call(tool, args, ctx).await
}

#[tokio::test]
async fn snapshot_reports_real_processes_and_crash_events() {
    let plugin = UsageMonitorPlugin::default();
    let ctx = ToolContext { enabled_components: all_components(), ..Default::default() };
    let snap = call(&plugin, "capture_diagnostic_snapshot", json!({}), ctx).await.unwrap();
    assert!(snap["system"]["memoryTotalMb"].as_u64().unwrap() > 0);
    assert!(snap["system"]["logicalCpus"].as_u64().unwrap() > 0);
    assert!(!snap["topByMemory"].as_array().unwrap().is_empty());
    assert!(snap["crashes"].is_array(), "{}", snap["crashes"]);
    assert_eq!(snap["label"], "Current diagnostic window");
}

#[tokio::test]
async fn disabled_components_are_left_out() {
    let plugin = UsageMonitorPlugin::default();
    let snap = call(&plugin, "capture_diagnostic_snapshot", json!({}), ToolContext::default()).await.unwrap();
    assert_eq!(snap["crashes"], "component disabled");
    assert_eq!(snap["spikes"], "component disabled");
    assert_eq!(snap["foregroundChanges"], "component disabled");
}

#[tokio::test]
async fn configures_and_validates_the_watch_window() {
    let plugin = UsageMonitorPlugin::default();
    let out = call(&plugin, "configure_watch_window", json!({ "startTime": "21:00", "endTime": "23:30", "targetProcesses": [" game.exe "] }), ToolContext::default())
        .await
        .unwrap();
    assert_eq!(out["watch"]["startTime"], "21:00");
    assert_eq!(out["watch"]["targetProcesses"], json!(["game.exe"]));
    let err = call(&plugin, "configure_watch_window", json!({ "startTime": "9pm" }), ToolContext::default()).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArguments);
    let err = call(&plugin, "configure_watch_window", json!({ "cpuThresholdPercent": 0 }), ToolContext::default()).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArguments);
}

/// An unlocked engine with only usage-monitor installed (no components, so no sampler).
async fn engine() -> (Arc<Engine>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let registry = Registry::new(vec![Arc::new(UsageMonitorPlugin::default()) as Arc<dyn Plugin>]).unwrap();
    let engine = Engine::new(dir.path().join("data"), registry, EngineOptions { kdf: KdfParams::INSECURE_TEST, elevated: false });
    engine.setup(PIN.into()).await.unwrap();
    engine.set_installed(BTreeMap::from([("usage-monitor".to_owned(), vec![])])).unwrap();
    (engine, dir)
}

async fn watch_start(engine: &Engine) -> Value {
    let RunOutcome::Completed { result } =
        engine.run_tool(Origin::Ui { pin: None }, "usage-monitor", "capture_diagnostic_snapshot", json!({})).await.unwrap()
    else {
        panic!("snapshot is auto and read-only");
    };
    result["watch"]["startTime"].clone()
}

#[test]
fn changing_the_watch_window_is_pin_gated_by_default() {
    let plugin = UsageMonitorPlugin::default();
    let tool = plugin.manifest().tool("configure_watch_window").unwrap();
    assert_eq!(tool.default_gate_policy, GatePolicy::PinRequired);
    assert!(!tool.read_only);
}

#[tokio::test]
async fn in_app_watch_window_changes_need_the_right_pin() {
    let (engine, _dir) = engine().await;
    let args = json!({ "startTime": "21:00", "endTime": "23:00" });
    let ui = |pin: Option<&str>| Origin::Ui { pin: pin.map(str::to_owned) };

    let err = engine.run_tool(ui(None), "usage-monitor", "configure_watch_window", args.clone()).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::PinRequired);
    let err = engine.run_tool(ui(Some("000000")), "usage-monitor", "configure_watch_window", args.clone()).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::PinInvalid);
    assert_eq!(watch_start(&engine).await, "00:00", "rejected calls change nothing");

    let out = engine.run_tool(ui(Some(PIN)), "usage-monitor", "configure_watch_window", args).await.unwrap();
    let RunOutcome::Completed { result } = out else { panic!("expected the change to run") };
    assert_eq!(result["watch"]["startTime"], "21:00");
    assert_eq!(watch_start(&engine).await, "21:00");
}

#[tokio::test]
async fn mcp_watch_window_changes_wait_for_pin_approval() {
    let (engine, _dir) = engine().await;
    let outcome = engine
        .run_tool(Origin::Mcp, "usage-monitor", "configure_watch_window", json!({ "startTime": "21:00", "endTime": "23:00" }))
        .await
        .unwrap();
    assert_eq!(serde_json::to_value(&outcome).unwrap()["status"], "pending_approval");
    let RunOutcome::PendingApproval { ticket } = outcome else { panic!("expected a ticket") };
    assert_eq!(ticket.status, TicketStatus::PendingApproval);
    assert_eq!(watch_start(&engine).await, "00:00", "nothing changes before approval");

    let err = engine.decide_ticket(&ticket.ticket_id, true, "000000".into(), None, "app").await.unwrap_err();
    assert_eq!(err.code, ErrorCode::PinInvalid);
    assert_eq!(engine.ticket(&ticket.ticket_id).unwrap().status, TicketStatus::PendingApproval);
    assert_eq!(watch_start(&engine).await, "00:00", "a wrong PIN changes nothing");

    engine.decide_ticket(&ticket.ticket_id, true, PIN.into(), None, "app").await.unwrap();
    let mut status = TicketStatus::Running;
    for _ in 0..200 {
        status = engine.ticket(&ticket.ticket_id).unwrap().status;
        if status.is_final() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(status, TicketStatus::Approved);
    assert_eq!(watch_start(&engine).await, "21:00");
}

#[tokio::test]
async fn sampler_runs_only_while_unlocked_and_purge_is_pin_gated() {
    let plugin = UsageMonitorPlugin::default();
    plugin.on_unlock(&UnlockContext { enabled_components: all_components(), ..Default::default() });
    assert!(plugin.is_sampling());
    let snap = call(&plugin, "capture_diagnostic_snapshot", json!({}), ToolContext { enabled_components: all_components(), ..Default::default() })
        .await
        .unwrap();
    assert!(snap["samplingSince"].is_string());
    plugin.on_lock();
    assert!(!plugin.is_sampling());

    let purge = plugin.manifest().tool("purge_telemetry_history").unwrap();
    assert_eq!(purge.default_gate_policy, aegis_core::registry::GatePolicy::PinRequired);
    // Purge also deletes the history files, so it fails without a history
    // stream rather than report a purge it did not do (tests/history.rs).
    let err = call(&plugin, "purge_telemetry_history", json!({}), ToolContext::default()).await.unwrap_err();
    assert_eq!(err.code, aegis_core::ErrorCode::Internal);
}

#[tokio::test]
async fn analysis_goes_through_the_llm_handle() {
    let plugin = UsageMonitorPlugin::default();
    let (base, server) = aegis_core::testing::mock_llm("game.exe leaks memory.").await;
    let ctx = ToolContext { llm: Some(aegis_core::testing::llm_handle(&base, "usage-monitor")), ..Default::default() };
    let out = call(&plugin, "analyze_clues_with_llm", json!({ "snapshot": { "spikes": [{ "process": "game.exe" }] } }), ctx).await.unwrap();
    assert_eq!(out["analysis"]["text"], "game.exe leaks memory.");
    assert!(server.await.unwrap().contains("game.exe"));
}
