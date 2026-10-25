use aegis_core::registry::{Plugin, ToolContext};
use aegis_core::{os, schema, ErrorCode};
use aegis_plugin_event_logs::{levels_for, EventLogsPlugin};
use serde_json::{json, Value};

async fn call(tool: &str, args: Value, ctx: ToolContext) -> aegis_core::AegisResult<Value> {
    let plugin = EventLogsPlugin::default();
    let schema = &plugin.manifest().tool(tool).unwrap().input_schema;
    let args = schema::validate(schema, args).map_err(aegis_core::AegisError::invalid)?;
    plugin.call(tool, args, ctx).await
}

#[test]
fn manifest_is_valid_and_every_tool_is_read_only() {
    let plugin = EventLogsPlugin::default();
    for tool in &plugin.manifest().tools {
        assert!(tool.read_only && !tool.requires_admin, "{}", tool.id);
    }
}

#[test]
fn severity_is_a_minimum() {
    assert_eq!(levels_for("Critical"), vec![1]);
    assert_eq!(levels_for("Warning"), vec![1, 2, 3]);
    assert!(levels_for("All").is_empty());
}

#[tokio::test]
async fn queries_the_real_application_log() {
    let out = call("query_logs", json!({ "severity": "All", "limit": 3 }), ToolContext::default()).await.unwrap();
    assert_eq!(out["channel"], "Application");
    let events = out["events"].as_array().unwrap();
    assert!(!events.is_empty() && events.len() <= 3);
    assert!(events[0]["eventId"].is_u64() && events[0]["timeCreated"].is_string());
}

#[tokio::test]
async fn filters_by_the_id_of_a_real_event() {
    let newest = call("query_logs", json!({ "severity": "All", "limit": 1 }), ToolContext::default()).await.unwrap();
    let id = newest["events"][0]["eventId"].as_u64().unwrap();
    let source = newest["events"][0]["provider"].as_str().unwrap().to_owned();
    let out = call("filter_by_event_id", json!({ "eventId": id, "source": source, "limit": 5 }), ToolContext::default()).await.unwrap();
    let events = out["events"].as_array().unwrap();
    assert!(!events.is_empty());
    assert!(events.iter().all(|e| e["eventId"] == id && e["provider"] == source.as_str()));
}

#[tokio::test]
async fn rejects_unknown_channels_and_injection() {
    let err = call("query_logs", json!({ "channel": "Microsoft-Windows-Sysmon/Operational" }), ToolContext::default()).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArguments);
    let err = call("filter_by_event_id", json!({ "eventId": 1, "source": "x'] or [1=1" }), ToolContext::default()).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArguments);
}

#[tokio::test]
async fn security_log_needs_admin_when_not_elevated() {
    let elevated = os::is_elevated();
    let ctx = ToolContext { elevated, ..Default::default() };
    let result = call("query_logs", json!({ "channel": "Security", "limit": 1 }), ctx).await;
    if elevated {
        assert!(result.is_ok(), "{result:?}");
    } else {
        assert_eq!(result.unwrap_err().code, ErrorCode::RequiresAdmin);
    }
}

#[tokio::test]
async fn analysis_goes_through_the_bound_llm_handle() {
    let err = call("analyze_logs_with_llm", json!({ "events": [{ "eventId": 1000 }] }), ToolContext::default()).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::LlmNotConfigured);

    let (base, server) = aegis_core::testing::mock_llm("The indexer crashed.").await;
    let ctx = ToolContext { llm: Some(aegis_core::testing::llm_handle(&base, "event-logs")), ..Default::default() };
    let out = call("analyze_logs_with_llm", json!({ "events": [{ "eventId": 1000, "provider": "Application Error" }] }), ctx)
        .await
        .unwrap();
    assert_eq!(out["analysis"]["text"], "The indexer crashed.");
    assert!(server.await.unwrap().contains("Application Error"));
}
