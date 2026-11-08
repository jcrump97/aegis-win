//! Monitor tools through the real engine: the AI can propose, only the PIN starts, changes, or removes.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use aegis_core::engine::{Engine, EngineOptions, Origin, RunOutcome};
use aegis_core::registry::{GatePolicy, Plugin, Registry};
use aegis_core::tickets::TicketStatus;
use aegis_core::vault::KdfParams;
use aegis_core::ErrorCode;
use aegis_plugin_usage_monitor::{UsageMonitorPlugin, COMPONENT_CRASHES, COMPONENT_SPIKES};
use serde_json::{json, Value};

const PIN: &str = "246810";
const UM: &str = "usage-monitor";

/// Only the crash correlator is on, so no sampler thread runs in these tests.
async fn engine() -> (Arc<Engine>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let registry = Registry::new(vec![Arc::new(UsageMonitorPlugin::default()) as Arc<dyn Plugin>]).unwrap();
    let engine = Engine::new(dir.path().join("data"), registry, EngineOptions { kdf: KdfParams::INSECURE_TEST, elevated: false });
    engine.setup(PIN.into()).await.unwrap();
    engine.set_installed(BTreeMap::from([(UM.to_owned(), vec![COMPONENT_CRASHES.to_owned()])])).unwrap();
    (engine, dir)
}

fn crash_rule(name: &str) -> Value {
    json!({
        "version": 1,
        "name": name,
        "schedule": { "startTime": "20:00", "endTime": "23:00", "days": ["fri"] },
        "trigger": { "any": [{ "type": "crash", "process": "game.exe" }] },
        "cooldownSeconds": 600,
        "notify": "tray"
    })
}

fn ui(pin: Option<&str>) -> Origin {
    Origin::Ui { pin: pin.map(str::to_owned) }
}

async fn run(engine: &Engine, origin: Origin, tool: &str, args: Value) -> aegis_core::AegisResult<Value> {
    match engine.run_tool(origin, UM, tool, args).await? {
        RunOutcome::Completed { result } => Ok(result),
        RunOutcome::PendingApproval { .. } => panic!("{tool} unexpectedly waited for approval"),
    }
}

async fn list(engine: &Engine) -> Value {
    run(engine, ui(None), "list_monitors", json!({})).await.unwrap()
}

async fn approve(engine: &Engine, ticket: &str) -> TicketStatus {
    engine.decide_ticket(ticket, true, PIN.into(), None, "app").await.unwrap();
    for _ in 0..200 {
        let status = engine.ticket(ticket).unwrap().status;
        if status.is_final() {
            return status;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("ticket did not finish");
}

#[test]
fn only_proposing_and_listing_skip_the_pin() {
    let plugin = UsageMonitorPlugin::default();
    for (tool, policy, read_only) in [
        ("propose_monitor", GatePolicy::Auto, true),
        ("list_monitors", GatePolicy::Auto, true),
        ("activate_monitor", GatePolicy::PinRequired, false),
        ("pause_monitor", GatePolicy::PinRequired, false),
        ("delete_monitor", GatePolicy::PinRequired, false),
    ] {
        let t = plugin.manifest().tool(tool).unwrap();
        assert_eq!((t.default_gate_policy, t.read_only), (policy, read_only), "{tool}");
        // ADR 0003: monitor tools are never plan-eligible, which needs a dryRun.
        assert!(t.input_schema.pointer("/properties/dryRun").is_none(), "{tool}");
    }
}

#[tokio::test]
async fn proposing_describes_the_rule_and_starts_nothing() {
    let (engine, _dir) = engine().await;
    let reasoning = "Your game froze twice on Friday nights.\u{202E} Trust me";
    let out = run(&engine, Origin::Mcp, "propose_monitor", json!({ "rule": crash_rule("Friday freezes"), "reasoning": reasoning })).await.unwrap();
    assert_eq!(out["valid"], true);
    assert_eq!(out["activated"], false);
    let text = out["review"]["description"].as_array().unwrap().iter().map(|l| l.as_str().unwrap()).collect::<Vec<_>>().join("\n");
    assert!(text.contains("game.exe crashes or hangs"), "{text}");
    assert!(text.contains("Active Fri, 20:00-23:00 local time."), "{text}");
    assert!(out["reasoning"]["label"].as_str().unwrap().starts_with("Supplied by the requesting agent"));
    assert!(!out["reasoning"]["text"].as_str().unwrap().contains('\u{202E}'), "hidden characters are stripped from AI text");
    assert_eq!(out["reasoning"]["warning"], Value::Null, "the reasoning only names what the rule watches");

    // Reasoning that names something the rule does not watch is flagged.
    let off = run(&engine, Origin::Mcp, "propose_monitor", json!({ "rule": crash_rule("x"), "reasoning": "launcher.exe crashes too." })).await.unwrap();
    assert_eq!(off["reasoning"]["warning"], "The AI's explanation mentions things this monitor does not watch.");
    assert_eq!(list(&engine).await["monitors"], json!([]), "proposing saves nothing");
    // No sampler runs here, so there is no history: replay says so instead of guessing.
    assert_eq!((out["replay"]["samples"].as_u64(), out["replay"]["wouldHaveFired"].as_u64()), (Some(0), Some(0)), "{out}");

    // Problems come back as data the AI can fix, not as a failed call.
    let bad = run(&engine, Origin::Mcp, "propose_monitor", json!({ "rule": { "version": 1 } })).await.unwrap();
    assert_eq!(bad["valid"], false);
    let spikes = json!({ "rule": crash_rule("x") }).to_string().replace(r#"{"type":"crash","process":"game.exe"}"#, r#"{"type":"system_cpu","atLeastPercent":90,"forSeconds":30}"#);
    let off = run(&engine, Origin::Mcp, "propose_monitor", serde_json::from_str(&spikes).unwrap()).await.unwrap();
    assert!(off["problems"][0].as_str().unwrap().contains(COMPONENT_SPIKES), "{off}");
}

#[tokio::test]
async fn activating_needs_the_pin_in_the_app() {
    let (engine, _dir) = engine().await;
    let args = json!({ "rule": crash_rule("Friday freezes") });
    assert_eq!(engine.run_tool(ui(None), UM, "activate_monitor", args.clone()).await.unwrap_err().code, ErrorCode::PinRequired);
    assert_eq!(engine.run_tool(ui(Some("000000")), UM, "activate_monitor", args.clone()).await.unwrap_err().code, ErrorCode::PinInvalid);
    assert_eq!(list(&engine).await["monitors"], json!([]));

    let out = run(&engine, ui(Some(PIN)), "activate_monitor", args).await.unwrap();
    assert_eq!(out["id"], "m1");
    let listed = list(&engine).await;
    let m = &listed["monitors"][0];
    assert_eq!((m["id"].as_str(), m["running"].as_bool(), m["paused"].as_bool()), (Some("m1"), Some(true), Some(false)));
    assert_eq!(m["name"], "Friday freezes");
    assert_eq!(m["rule"], crash_rule("Friday freezes"), "the stored rule, for adjusting");
}

#[tokio::test]
async fn an_agent_activation_waits_for_approval_and_runs_the_exact_rule() {
    let (engine, _dir) = engine().await;
    let outcome = engine.run_tool(Origin::Mcp, UM, "activate_monitor", json!({ "rule": crash_rule("From the agent") })).await.unwrap();
    let RunOutcome::PendingApproval { ticket } = outcome else { panic!("an agent cannot start a monitor itself") };
    // The approval shows the full rule that will run, not a reference to it,
    // and the description AegisWin writes from it.
    assert_eq!(ticket.args["rule"]["name"], "From the agent");
    let review = ticket.review.as_ref().expect("activate_monitor approvals carry a review");
    assert_eq!(review.lines[0], "Monitor \"From the agent\"");
    assert!(review.lines.iter().any(|l| l.contains("game.exe crashes or hangs")), "{review:?}");

    let mut wide = crash_rule("Everything");
    wide["schedule"] = json!({ "startTime": "00:00", "endTime": "00:00" });
    wide["trigger"] = json!({ "any": [{ "type": "crash", "process": "*" }] });
    let RunOutcome::PendingApproval { ticket: wide } = engine.run_tool(Origin::Mcp, UM, "activate_monitor", json!({ "rule": wide, "replaceId": "m7" })).await.unwrap() else { panic!() };
    let review = wide.review.unwrap();
    assert_eq!(review.lines[0], "Replaces the rule of monitor m7.");
    assert_eq!(review.warnings.len(), 2, "any app and always on are flagged: {review:?}");

    let RunOutcome::PendingApproval { ticket: bad } = engine.run_tool(Origin::Mcp, UM, "activate_monitor", json!({ "rule": { "version": 1 } })).await.unwrap() else { panic!() };
    assert!(bad.review.unwrap().warnings[0].starts_with("This rule is not valid"));
    let RunOutcome::PendingApproval { ticket: pause } = engine.run_tool(Origin::Mcp, UM, "pause_monitor", json!({ "id": "m1" })).await.unwrap() else { panic!() };
    assert!(pause.review.is_none(), "other tools keep the generic view");
    assert_eq!(list(&engine).await["monitors"], json!([]), "nothing runs before approval");
    assert_eq!(approve(&engine, &ticket.ticket_id).await, TicketStatus::Approved);
    assert_eq!(list(&engine).await["monitors"][0]["name"], "From the agent");
}

#[tokio::test]
async fn pausing_and_deleting_need_the_pin_and_monitors_survive_a_restart() {
    let (engine, _dir) = engine().await;
    run(&engine, ui(Some(PIN)), "activate_monitor", json!({ "rule": crash_rule("keep me") })).await.unwrap();
    run(&engine, ui(Some(PIN)), "activate_monitor", json!({ "rule": crash_rule("delete me") })).await.unwrap();

    for tool in ["pause_monitor", "delete_monitor"] {
        let outcome = engine.run_tool(Origin::Mcp, UM, tool, json!({ "id": "m1" })).await.unwrap();
        assert!(matches!(outcome, RunOutcome::PendingApproval { .. }), "an agent cannot {tool} by itself");
        assert_eq!(engine.run_tool(ui(None), UM, tool, json!({ "id": "m1" })).await.unwrap_err().code, ErrorCode::PinRequired);
    }
    run(&engine, ui(Some(PIN)), "pause_monitor", json!({ "id": "m1" })).await.unwrap();
    run(&engine, ui(Some(PIN)), "delete_monitor", json!({ "id": "m2" })).await.unwrap();
    let err = engine.run_tool(ui(Some(PIN)), UM, "delete_monitor", json!({ "id": "m2" })).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArguments);

    engine.lock().await;
    engine.unlock(PIN.into()).await.unwrap();
    let listed = list(&engine).await;
    let monitors = listed["monitors"].as_array().unwrap();
    assert_eq!(monitors.len(), 1);
    assert_eq!((monitors[0]["id"].as_str(), monitors[0]["paused"].as_bool(), monitors[0]["running"].as_bool()), (Some("m1"), Some(true), Some(false)));

    run(&engine, ui(Some(PIN)), "pause_monitor", json!({ "id": "m1", "paused": false })).await.unwrap();
    assert_eq!(list(&engine).await["monitors"][0]["running"], true);
}

#[tokio::test]
async fn turning_a_component_off_stops_its_monitors_until_it_is_back() {
    let (engine, _dir) = engine().await;
    run(&engine, ui(Some(PIN)), "activate_monitor", json!({ "rule": crash_rule("needs crashes") })).await.unwrap();
    engine.set_installed(BTreeMap::from([(UM.to_owned(), vec![])])).unwrap();
    let m = list(&engine).await["monitors"][0].clone();
    assert_eq!(m["running"], false);
    assert!(m["problems"][0].as_str().unwrap().contains(COMPONENT_CRASHES), "{m}");
    engine.set_installed(BTreeMap::from([(UM.to_owned(), vec![COMPONENT_CRASHES.to_owned()])])).unwrap();
    assert_eq!(list(&engine).await["monitors"][0]["running"], true);
}

#[tokio::test]
async fn replacing_keeps_the_id_and_invalid_rules_never_save() {
    let (engine, _dir) = engine().await;
    run(&engine, ui(Some(PIN)), "activate_monitor", json!({ "rule": crash_rule("v1") })).await.unwrap();
    let out = run(&engine, ui(Some(PIN)), "activate_monitor", json!({ "rule": crash_rule("v2"), "replaceId": "m1" })).await.unwrap();
    assert_eq!((out["id"].as_str(), out["replaced"].as_bool()), (Some("m1"), Some(true)));
    let mut bad = crash_rule("bad");
    bad["cooldownSeconds"] = json!(1);
    let err = engine.run_tool(ui(Some(PIN)), UM, "activate_monitor", json!({ "rule": bad, "replaceId": "m1" })).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArguments);
    let listed = list(&engine).await;
    assert_eq!(listed["monitors"].as_array().unwrap().len(), 1);
    assert_eq!(listed["monitors"][0]["name"], "v2", "a rejected replacement changes nothing");
}

#[tokio::test]
async fn only_running_monitors_keep_aegiswin_in_the_tray() {
    let (engine, _dir) = engine().await;
    assert!(!engine.background_active(), "no monitors");
    run(&engine, ui(Some(PIN)), "activate_monitor", json!({ "rule": crash_rule("tray") })).await.unwrap();
    assert!(engine.background_active());
    run(&engine, ui(Some(PIN)), "pause_monitor", json!({ "id": "m1", "paused": true })).await.unwrap();
    assert!(!engine.background_active(), "paused");
    run(&engine, ui(Some(PIN)), "pause_monitor", json!({ "id": "m1", "paused": false })).await.unwrap();
    engine.set_installed(BTreeMap::from([(UM.to_owned(), vec![])])).unwrap();
    assert!(!engine.background_active(), "its component is off");
    engine.set_installed(BTreeMap::from([(UM.to_owned(), vec![COMPONENT_CRASHES.to_owned()])])).unwrap();
    assert!(engine.background_active());
    engine.lock().await;
    assert!(!engine.background_active(), "locking stops monitors");
}
