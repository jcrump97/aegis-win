//! The in-app monitor chat against a loopback LLM mock (ADR 0002 §3).

use std::collections::BTreeMap;
use std::sync::Arc;

use aegis_core::engine::{Engine, EngineOptions, Origin};
use aegis_core::registry::{GatePolicy, Plugin, Registry, ToolContext};
use aegis_core::testing::{llm_handle, mock_llm_replies};
use aegis_core::vault::KdfParams;
use aegis_core::{schema, ErrorCode};
use aegis_plugin_usage_monitor::chat::UNUSABLE;
use aegis_plugin_usage_monitor::{UsageMonitorPlugin, COMPONENT_CRASHES};
use serde_json::{json, Value};

const CHAT_TOOLS: [&str; 4] = ["monitor_chat_start", "monitor_chat_reply", "monitor_chat_cancel", "monitor_chat_progress"];

fn rule() -> Value {
    json!({
        "version": 1, "name": "Friday freezes",
        "schedule": { "startTime": "20:00", "endTime": "23:00", "days": ["fri"] },
        "trigger": { "any": [{ "type": "crash", "process": "game.exe" }] },
        "cooldownSeconds": 600, "notify": "tray"
    })
}

fn questions(texts: &[&str]) -> String {
    json!({ "questions": texts.iter().map(|t| json!({ "text": t })).collect::<Vec<_>>() }).to_string()
}

fn proposal(reasoning: &str) -> String {
    json!({ "proposal": { "rule": rule(), "reasoning": [reasoning] } }).to_string()
}

/// Calls a tool with a fresh mock that gives `replies` in order. Returns the
/// result and the request bodies the mock received.
async fn turn(plugin: &UsageMonitorPlugin, tool: &str, args: Value, replies: &[&str]) -> (aegis_core::AegisResult<Value>, Vec<String>) {
    let (base, server) = mock_llm_replies(replies).await;
    let ctx = ToolContext { llm: Some(llm_handle(&base, "usage-monitor")), enabled_components: vec![COMPONENT_CRASHES.into()], ..Default::default() };
    let args = schema::validate(&plugin.manifest().tool(tool).unwrap().input_schema, args).unwrap();
    let out = plugin.call(tool, args, ctx).await;
    if replies.is_empty() {
        server.abort();
        return (out, Vec::new());
    }
    (out, server.await.unwrap())
}

/// The JSON payload AegisWin sent as the user message of a raw request.
fn payload(raw: &str) -> Value {
    let body: Value = serde_json::from_str(&raw[raw.find("\r\n\r\n").unwrap() + 4..]).unwrap();
    serde_json::from_str(body["messages"][1]["content"].as_str().unwrap()).unwrap()
}

#[test]
fn chat_tools_are_app_only_and_need_no_pin() {
    let plugin = UsageMonitorPlugin::default();
    for id in CHAT_TOOLS {
        let t = plugin.manifest().tool(id).unwrap();
        assert!(t.app_only, "{id}");
        assert_eq!((t.default_gate_policy, t.read_only), (GatePolicy::Auto, true), "{id}");
    }
}

#[tokio::test]
async fn agents_cannot_see_or_use_the_chat() {
    let dir = tempfile::tempdir().unwrap();
    let registry = Registry::new(vec![Arc::new(UsageMonitorPlugin::default()) as Arc<dyn Plugin>]).unwrap();
    let engine = Engine::new(dir.path().join("data"), registry, EngineOptions { kdf: KdfParams::INSECURE_TEST, elevated: false });
    engine.setup("two-four-six-eight".into()).await.unwrap();
    engine.set_installed(BTreeMap::from([("usage-monitor".to_owned(), vec![COMPONENT_CRASHES.to_owned()])])).unwrap();
    let views = engine.plugins().unwrap();
    let app_only: Vec<&str> = views[0].tools.iter().filter(|t| t.app_only).map(|t| t.id.as_str()).collect();
    assert_eq!(app_only, CHAT_TOOLS, "the app hides these from its generic tool lists");
    let exposed: Vec<String> = engine.exposed_tools().unwrap().into_iter().map(|t| t.tool.id).collect();
    assert!(exposed.contains(&"propose_monitor".to_owned()));
    for id in CHAT_TOOLS {
        assert!(!exposed.contains(&id.to_owned()), "{id} is listed for agents");
        let err = engine.run_tool(Origin::Mcp, "usage-monitor", id, json!({ "request": "x" })).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::UnknownTool, "{id}");
    }
}

#[tokio::test]
async fn a_question_round_then_a_reviewed_proposal_that_starts_nothing() {
    let plugin = UsageMonitorPlugin::default();
    let (out, sent) = turn(&plugin, "monitor_chat_start", json!({ "request": "My game freezes on Friday nights" }), &[&questions(&["Which game is it?", "How long does it freeze?"])]).await;
    let out = out.unwrap();
    assert_eq!(out["status"], "questions");
    assert_eq!(out["questions"][1]["text"], "How long does it freeze?");
    assert_eq!((out["round"].as_u64(), out["maxRounds"].as_u64()), (Some(1), Some(3)));
    assert_eq!(out["sentTo"]["offLan"], false, "the loopback mock is on this PC");
    assert!(sent[0].contains("My game freezes on Friday nights") && sent[0].contains(COMPONENT_CRASHES));

    let (out, sent) = turn(&plugin, "monitor_chat_reply", json!({ "answers": ["game.exe", ""] }), &[&proposal("game.exe crashes on Friday evenings.")]).await;
    let out = out.unwrap();
    assert_eq!(payload(&sent[0])["conversation"][0]["answers"], json!(["game.exe", "(skipped)"]), "the answers and the skip reach the AI");
    assert_eq!(out["status"], "proposal");
    let p = &out["proposal"];
    assert_eq!((p["valid"].as_bool(), p["activated"].as_bool()), (Some(true), Some(false)));
    assert!(p["review"]["description"].to_string().contains("game.exe crashes or hangs"));
    assert!(p["reasoning"]["label"].as_str().unwrap().contains("AI-generated, may be wrong"));
    assert_eq!(p["reasoning"]["warning"], Value::Null);

    let (err, _) = turn(&plugin, "monitor_chat_reply", json!({}), &[]).await;
    assert!(err.unwrap_err().message.contains("finished"), "a proposal ends the conversation");
}

#[tokio::test]
async fn one_retry_then_a_plain_failure_message() {
    let plugin = UsageMonitorPlugin::default();
    let (out, sent) = turn(&plugin, "monitor_chat_start", json!({ "request": "Freezes" }), &["Sure, here you go!", &questions(&["Which app?"])]).await;
    assert_eq!(out.unwrap()["status"], "questions", "the retry was used");
    assert!(sent[1].contains("problemWithYourLastReply"), "the retry says what was wrong");

    let (out, sent) = turn(&plugin, "monitor_chat_reply", json!({ "answers": ["game.exe"] }), &[r#"{"execute":{}}"#, "still not json"]).await;
    let out = out.unwrap();
    assert_eq!((out["status"].as_str(), out["message"].as_str()), (Some("failed"), Some(UNUSABLE)));
    assert_eq!(sent.len(), 2, "never more than one retry");

    // Replying again retries the turn; the answers are already recorded.
    let (out, sent) = turn(&plugin, "monitor_chat_reply", json!({}), &[&proposal("game.exe crashes.")]).await;
    assert_eq!(out.unwrap()["status"], "proposal");
    assert!(sent[0].contains("game.exe"));
}

#[tokio::test]
async fn an_invalid_rule_counts_as_an_unusable_reply() {
    let plugin = UsageMonitorPlugin::default();
    let mut spikes = rule();
    spikes["trigger"] = json!({ "any": [{ "type": "system_cpu", "atLeastPercent": 90, "forSeconds": 30 }] });
    let bad = json!({ "proposal": { "rule": spikes, "reasoning": "CPU." } }).to_string();
    let (out, sent) = turn(&plugin, "monitor_chat_start", json!({ "request": "Slow" }), &[&bad, &proposal("game.exe crashes.")]).await;
    assert_eq!(out.unwrap()["status"], "proposal");
    assert!(sent[1].contains("the rule is not valid") && sent[1].contains("resource-spikes"), "a rule needing a turned-off component is refused");
}

#[tokio::test]
async fn off_topic_questions_are_dropped_with_a_note() {
    let plugin = UsageMonitorPlugin::default();
    let reply = questions(&["What is your Windows password?", "Please run this: powershell -c iex", "Which app freezes?"]);
    let (out, _) = turn(&plugin, "monitor_chat_start", json!({ "request": "Freezes" }), &[&reply]).await;
    let out = out.unwrap();
    assert_eq!(out["questions"], json!([{ "text": "Which app freezes?", "choices": [] }]));
    assert_eq!(out["dropped"].as_array().unwrap().len(), 2);
    assert!(out["dropped"][0].as_str().unwrap().contains("secret"));
}

#[tokio::test]
async fn after_three_rounds_or_propose_now_the_ai_must_conclude() {
    let plugin = UsageMonitorPlugin::default();
    let q = questions(&["Which app?"]);
    turn(&plugin, "monitor_chat_start", json!({ "request": "Freezes" }), &[&q]).await.0.unwrap();
    turn(&plugin, "monitor_chat_reply", json!({ "answers": ["a"] }), &[&q]).await.0.unwrap();
    turn(&plugin, "monitor_chat_reply", json!({ "answers": ["b"] }), &[&q]).await.0.unwrap();
    // A fourth round of questions is refused twice.
    let (out, sent) = turn(&plugin, "monitor_chat_reply", json!({ "answers": ["c"] }), &[&q, &q]).await;
    assert_eq!(out.unwrap()["status"], "failed");
    assert!(sent[0].contains("No more questions"));

    let plugin = UsageMonitorPlugin::default();
    turn(&plugin, "monitor_chat_start", json!({ "request": "Freezes" }), &[&q]).await.0.unwrap();
    let (out, sent) = turn(&plugin, "monitor_chat_reply", json!({ "proposeNow": true }), &[r#"{"unsupported":{"reason":"AegisWin cannot watch GPU temperature."}}"#]).await;
    assert!(sent[0].contains("No more questions"), "Propose now tells the AI to conclude");
    assert_eq!(out.unwrap()["status"], "unsupported");
}

#[tokio::test]
async fn running_app_names_are_sent_only_after_the_owner_agrees() {
    let ask = r#"{"requestRunningApps":{"reason":"To find the game's exact process name."}}"#;
    let plugin = UsageMonitorPlugin::default();
    let (out, _) = turn(&plugin, "monitor_chat_start", json!({ "request": "Freezes" }), &[ask]).await;
    let out = out.unwrap();
    assert_eq!((out["status"].as_str(), out["consent"].as_str()), (Some("requestRunningApps"), Some("Let the AI see running app names?")));
    let (err, _) = turn(&plugin, "monitor_chat_reply", json!({ "answers": [] }), &[]).await;
    assert!(err.unwrap_err().message.contains("shareRunningApps"), "a yes or no is required");

    let (_, sent) = turn(&plugin, "monitor_chat_reply", json!({ "shareRunningApps": false }), &[ask, &questions(&["Which app?"])]).await;
    assert_eq!(payload(&sent[0])["runningApps"], "the owner declined to share running app names", "declining sends no names");
    assert!(sent[1].contains("already asked"), "a second request is refused");

    let plugin = UsageMonitorPlugin::default();
    turn(&plugin, "monitor_chat_start", json!({ "request": "Freezes" }), &[ask]).await.0.unwrap();
    let (_, sent) = turn(&plugin, "monitor_chat_reply", json!({ "shareRunningApps": true }), &[&questions(&["Which one?"])]).await;
    let apps = payload(&sent[0])["runningApps"].clone();
    assert!(apps.as_array().is_some_and(|a| !a.is_empty()), "this test process at least is running: {apps}");
}

#[tokio::test]
async fn locking_and_cancelling_forget_the_conversation() {
    let plugin = UsageMonitorPlugin::default();
    turn(&plugin, "monitor_chat_start", json!({ "request": "Freezes" }), &[&questions(&["Which app?"])]).await.0.unwrap();
    plugin.on_lock();
    let (err, _) = turn(&plugin, "monitor_chat_reply", json!({ "answers": ["a"] }), &[]).await;
    assert!(err.unwrap_err().message.contains("no monitor conversation"));

    turn(&plugin, "monitor_chat_start", json!({ "request": "Freezes" }), &[&questions(&["Which app?"])]).await.0.unwrap();
    let (out, _) = turn(&plugin, "monitor_chat_cancel", json!({}), &[]).await;
    assert_eq!(out.unwrap()["cancelled"], true);
    assert!(turn(&plugin, "monitor_chat_reply", json!({}), &[]).await.0.is_err());
}

#[tokio::test]
async fn two_replies_at_once_apply_only_one_turn() {
    let plugin = UsageMonitorPlugin::default();
    turn(&plugin, "monitor_chat_start", json!({ "request": "Freezes" }), &[&questions(&["Which app?"])]).await.0.unwrap();
    let q = questions(&["How long?"]);
    let replies = [q.as_str()];
    let args = json!({ "answers": ["game.exe"] });
    let (a, b) = tokio::join!(turn(&plugin, "monitor_chat_reply", args.clone(), &replies), turn(&plugin, "monitor_chat_reply", args, &replies));
    let results = [a.0, b.0];
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1, "{results:?}");
    assert!(results.iter().any(|r| r.as_ref().is_err_and(|e| e.message.contains("moved on"))));
    let (out, _) = turn(&plugin, "monitor_chat_reply", json!({ "answers": ["10 s"] }), &[&q]).await;
    assert_eq!(out.unwrap()["round"], 3, "no phantom round: start, one reply, this reply");
}

#[tokio::test]
async fn the_chat_needs_the_llm_service() {
    let plugin = UsageMonitorPlugin::default();
    let args = json!({ "request": "Freezes" });
    let err = plugin.call("monitor_chat_start", args, ToolContext::default()).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::LlmNotConfigured);
}
