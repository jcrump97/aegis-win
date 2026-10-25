use aegis_core::registry::{Plugin, ToolContext};
use aegis_core::{schema, ErrorCode};
use aegis_plugin_usage_monitor::{UsageMonitorPlugin, COMPONENT_CRASHES, COMPONENT_FOREGROUND, COMPONENT_SPIKES};
use serde_json::{json, Value};

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

#[tokio::test]
async fn sampler_runs_only_while_unlocked_and_purge_is_pin_gated() {
    let plugin = UsageMonitorPlugin::default();
    plugin.on_unlock(&all_components());
    assert!(plugin.is_sampling());
    let snap = call(&plugin, "capture_diagnostic_snapshot", json!({}), ToolContext { enabled_components: all_components(), ..Default::default() })
        .await
        .unwrap();
    assert!(snap["samplingSince"].is_string());
    plugin.on_lock();
    assert!(!plugin.is_sampling());

    let purge = plugin.manifest().tool("purge_telemetry_history").unwrap();
    assert_eq!(purge.default_gate_policy, aegis_core::registry::GatePolicy::PinRequired);
    let out = call(&plugin, "purge_telemetry_history", json!({}), ToolContext::default()).await.unwrap();
    assert_eq!(out["purged"], true);
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
