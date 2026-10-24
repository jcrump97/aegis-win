//! These tests never run a real repair: CI runners are administrators, so a
//! mistake here would reset a machine's network stack. Execution of System32
//! binaries is covered in aegis-core with harmless commands.

use aegis_core::registry::{self, Gate, GatePolicy, Plugin, ToolContext};
use aegis_core::{schema, ErrorCode};
use aegis_plugin_windows_health::{plan, summarize_sfc, valid_adapter_filter, WindowsHealthPlugin};
use serde_json::{json, Value};

async fn call(tool: &str, args: Value) -> aegis_core::AegisResult<Value> {
    let plugin = WindowsHealthPlugin::default();
    let schema = &plugin.manifest().tool(tool).unwrap().input_schema;
    let args = schema::validate(schema, args).map_err(aegis_core::AegisError::invalid)?;
    plugin.call(tool, args, ToolContext::default()).await
}

#[test]
fn every_repair_is_pin_gated_and_supports_dry_run() {
    let plugin = WindowsHealthPlugin::default();
    for tool in plugin.manifest().tools.iter().filter(|t| !t.read_only) {
        assert_eq!(tool.default_gate_policy, GatePolicy::PinRequired, "{}", tool.id);
        assert!(tool.input_schema.pointer("/properties/dryRun").is_some(), "{}", tool.id);
        let policy = tool.default_gate_policy;
        assert_ne!(registry::gate(tool, policy, &json!({ "dryRun": false }), true), Gate::Run, "{}", tool.id);
        assert_eq!(registry::gate(tool, policy, &json!({ "dryRun": true }), false), Gate::Run, "{}", tool.id);
    }
}

#[tokio::test]
async fn dry_runs_describe_commands_without_running_them() {
    for (tool, expected) in [
        ("sfc_scan", vec!["sfc.exe /scannow"]),
        ("flush_dns", vec!["ipconfig.exe /flushdns"]),
        ("winsock_reset", vec!["netsh.exe winsock reset"]),
        ("ip_release_renew", vec!["ipconfig.exe /release", "ipconfig.exe /renew"]),
    ] {
        let out = call(tool, json!({ "dryRun": true })).await.unwrap();
        assert_eq!(out["executed"], false, "{tool}");
        assert_eq!(out["commands"], json!(expected), "{tool}");
        assert!(out["impact"].as_str().unwrap().len() > 20);
    }
}

#[test]
fn adapter_filter_becomes_one_argument() {
    let p = plan("ip_release_renew", &json!({ "adapterFilter": "*Wi-Fi*" })).unwrap();
    assert_eq!(p.steps[0].args, vec!["/release", "*Wi-Fi*"]);
    assert_eq!(p.steps[1].args, vec!["/renew", "*Wi-Fi*"]);
    assert!(valid_adapter_filter("Ethernet 2"));
    assert!(valid_adapter_filter("Wi-Fi (Intel)"));
    for bad in ["x\" & del", "a|b", "%PATH%", "a;b"] {
        assert!(!valid_adapter_filter(bad), "{bad}");
        assert!(plan("ip_release_renew", &json!({ "adapterFilter": bad })).is_err());
    }
}

#[test]
fn classifies_sfc_results() {
    assert_eq!(summarize_sfc("Windows Resource Protection did not find any integrity violations."), "no_violations");
    assert_eq!(summarize_sfc("Windows Resource Protection found corrupt files and successfully repaired them."), "repaired");
    assert_eq!(summarize_sfc("Windows Resource Protection found corrupt files but was unable to fix some of them."), "unrepaired");
    assert_eq!(summarize_sfc("Windows Resource Protection could not perform the requested operation."), "could_not_run");
    assert_eq!(summarize_sfc("something else"), "unknown");
}

#[tokio::test]
async fn interprets_output_through_the_llm_handle() {
    let err = call("interpret_health_output", json!({ "commandOutput": "x" })).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::LlmNotConfigured);

    let (base, server) = aegis_core::testing::mock_llm("Run DISM next.").await;
    let plugin = WindowsHealthPlugin::default();
    let ctx = ToolContext { llm: Some(aegis_core::testing::llm_handle(&base, "windows-health")), ..Default::default() };
    let out = plugin
        .call("interpret_health_output", json!({ "commandOutput": "found corrupt files but was unable to fix" }), ctx)
        .await
        .unwrap();
    assert_eq!(out["analysis"]["text"], "Run DISM next.");
    assert!(server.await.unwrap().contains("unable to fix"));
}
