//! `appOnly` tools: callable from the app, invisible and unreachable over MCP.

use std::collections::BTreeMap;
use std::sync::Arc;

use aegis_core::engine::{Engine, EngineOptions, Origin, RunOutcome};
use aegis_core::registry::{Plugin, PluginManifest, Registry, ToolContext};
use aegis_core::vault::KdfParams;
use aegis_core::{AegisResult, ErrorCode};
use async_trait::async_trait;
use serde_json::{json, Value};

const PIN: &str = "135790";

struct Chatty(PluginManifest);

#[async_trait]
impl Plugin for Chatty {
    fn manifest(&self) -> &PluginManifest {
        &self.0
    }

    async fn call(&self, tool: &str, _args: Value, _ctx: ToolContext) -> AegisResult<Value> {
        Ok(json!({ "ran": tool }))
    }
}

fn tool(id: &str, app_only: bool, policy: &str) -> Value {
    json!({
        "id": id, "name": id, "description": "test", "requiresAdmin": false,
        "defaultGatePolicy": policy, "readOnly": true, "appOnly": app_only,
        "inputSchema": { "type": "object", "properties": {} }
    })
}

async fn engine() -> (Arc<Engine>, tempfile::TempDir) {
    let manifest = json!({
        "id": "chatty", "name": "Chatty", "version": "1.0.0", "description": "test",
        "optionalInstallDefault": true, "usesLlm": false,
        "tools": [tool("public", false, "auto"), tool("chat", true, "auto"), tool("secret_change", true, "pin_required")]
    });
    let plugin = Chatty(PluginManifest::from_json(&manifest.to_string()).unwrap());
    let dir = tempfile::tempdir().unwrap();
    let registry = Registry::new(vec![Arc::new(plugin) as Arc<dyn Plugin>]).unwrap();
    let engine = Engine::new(dir.path().join("data"), registry, EngineOptions { kdf: KdfParams::INSECURE_TEST, elevated: false });
    engine.setup(PIN.into()).await.unwrap();
    engine.set_installed(BTreeMap::from([("chatty".to_owned(), vec![])])).unwrap();
    (engine, dir)
}

#[tokio::test]
async fn app_only_tools_are_not_listed_for_agents() {
    let (engine, _dir) = engine().await;
    let listed: Vec<String> = engine.exposed_tools().unwrap().into_iter().map(|t| t.tool.id).collect();
    assert_eq!(listed, ["public"]);
}

#[tokio::test]
async fn an_agent_call_looks_like_an_unknown_tool_and_never_opens_a_ticket() {
    let (engine, _dir) = engine().await;
    for id in ["chat", "secret_change", "does_not_exist"] {
        let err = engine.run_tool(Origin::Mcp, "chatty", id, json!({})).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::UnknownTool, "{id}");
        assert_eq!(err.message, format!("unknown tool chatty:{id}"), "the same message whether or not it exists");
    }
    assert!(engine.list_tickets().is_empty(), "no approval request for an app-only tool");
}

#[tokio::test]
async fn the_app_can_call_them_and_their_gate_still_applies() {
    let (engine, _dir) = engine().await;
    let ui = |pin: Option<&str>| Origin::Ui { pin: pin.map(str::to_owned) };
    let out = engine.run_tool(ui(None), "chatty", "chat", json!({})).await.unwrap();
    assert!(matches!(out, RunOutcome::Completed { result } if result["ran"] == "chat"));
    assert_eq!(engine.run_tool(ui(None), "chatty", "secret_change", json!({})).await.unwrap_err().code, ErrorCode::PinRequired);
    assert!(matches!(engine.run_tool(ui(Some(PIN)), "chatty", "secret_change", json!({})).await.unwrap(), RunOutcome::Completed { .. }));
}

#[test]
fn the_flag_defaults_to_off_and_is_only_serialized_when_set() {
    let mut plain = tool("x", false, "auto");
    plain.as_object_mut().unwrap().remove("appOnly");
    let m: aegis_core::registry::ToolManifest = serde_json::from_value(plain).unwrap();
    assert!(!m.app_only);
    assert!(serde_json::to_value(&m).unwrap().get("appOnly").is_none());
}
