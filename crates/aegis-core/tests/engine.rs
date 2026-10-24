mod common;

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::time::Duration;

use aegis_core::engine::{Origin, RunOutcome, SettingsUpdate};
use aegis_core::registry::GatePolicy;
use aegis_core::tickets::TicketStatus;
use aegis_core::ErrorCode;
use common::{fixture, ready, PIN};
use serde_json::json;

fn ui(pin: Option<&str>) -> Origin {
    Origin::Ui { pin: pin.map(str::to_owned) }
}

#[tokio::test]
async fn setup_lock_and_unlock() {
    let f = fixture();
    let status = f.engine.status();
    assert!(!status.vault_exists && !status.unlocked);
    assert_eq!(f.engine.setup("123".into()).await.unwrap_err().code, ErrorCode::PinTooWeak);

    let status = f.engine.setup(PIN.into()).await.unwrap();
    assert!(status.vault_exists && status.unlocked && !status.first_run_completed);
    assert!(f.engine.data_dir().join("vault.enc.json").is_file());
    assert_eq!(f.engine.setup(PIN.into()).await.unwrap_err().code, ErrorCode::VaultExists);
    // optionalInstallDefault plugins start installed and get on_unlock.
    assert_eq!(f.plugin.unlocks.load(Ordering::SeqCst), 1);

    f.engine.set_installed(BTreeMap::from([("demo".to_owned(), vec![])])).unwrap();
    assert!(f.engine.status().first_run_completed);

    let status = f.engine.lock().await;
    assert!(!status.unlocked);
    assert!(f.plugin.locks.load(Ordering::SeqCst) >= 1);
    let err = f.engine.run_tool(ui(None), "demo", "echo", json!({})).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::VaultLocked);

    assert_eq!(f.engine.unlock("999999".into()).await.unwrap_err().code, ErrorCode::PinInvalid);
    let status = f.engine.unlock(PIN.into()).await.unwrap();
    assert!(status.unlocked && status.first_run_completed);
}

#[tokio::test]
async fn auto_tools_run_and_arguments_are_validated() {
    let f = ready().await;
    let out = f.engine.run_tool(ui(None), "demo", "echo", json!({ "text": "hi" })).await.unwrap();
    match out {
        RunOutcome::Completed { result } => assert_eq!(result["echo"]["text"], "hi"),
        other => panic!("{other:?}"),
    }
    let err = f.engine.run_tool(ui(None), "demo", "echo", json!({ "nope": 1 })).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArguments);
    let err = f.engine.run_tool(ui(None), "demo", "missing", json!({})).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::UnknownTool);
}

#[tokio::test]
async fn pin_required_tools_need_the_pin_in_the_ui() {
    let f = ready().await;
    let err = f.engine.run_tool(ui(None), "demo", "fix", json!({})).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::PinRequired);
    let err = f.engine.run_tool(ui(Some("000000")), "demo", "fix", json!({})).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::PinInvalid);
    let out = f.engine.run_tool(ui(Some(PIN)), "demo", "fix", json!({})).await.unwrap();
    assert!(matches!(out, RunOutcome::Completed { .. }));
    // Dry runs skip the gate.
    let out = f.engine.run_tool(ui(None), "demo", "fix", json!({ "dryRun": true })).await.unwrap();
    assert!(matches!(out, RunOutcome::Completed { result } if result["dryRun"] == true));
}

#[tokio::test]
async fn admin_tools_fail_fast_when_not_elevated() {
    let f = ready().await;
    let err = f.engine.run_tool(ui(Some(PIN)), "demo", "admin_fix", json!({})).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::RequiresAdmin);
    let err = f.engine.run_tool(Origin::Mcp, "demo", "admin_fix", json!({})).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::RequiresAdmin, "no ticket for something that cannot run");
    assert!(f.engine.list_tickets().is_empty());
}

#[tokio::test]
async fn disabled_plugins_and_components_are_refused() {
    let f = ready().await;
    f.engine.set_installed(BTreeMap::from([("demo".to_owned(), vec![])])).unwrap();
    let err = f.engine.run_tool(ui(None), "demo", "extra_tool", json!({})).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::ComponentDisabled);
    assert!(f.engine.exposed_tools().unwrap().iter().all(|t| t.tool.id != "extra_tool"));

    f.engine.set_installed(BTreeMap::new()).unwrap();
    let err = f.engine.run_tool(ui(None), "demo", "echo", json!({})).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::PluginDisabled);
    assert!(f.engine.exposed_tools().unwrap().is_empty());

    let err = f.engine.set_installed(BTreeMap::from([("demo".to_owned(), vec!["demo:nope".to_owned()])])).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArguments);
}

#[tokio::test]
async fn the_global_guard_locks_out_after_repeated_wrong_pins() {
    let f = ready().await;
    for _ in 0..5 {
        let err = f.engine.check_pin("000000").await.unwrap_err();
        assert_eq!(err.code, ErrorCode::PinInvalid);
    }
    let err = f.engine.check_pin(PIN).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::PinLockedOut, "even the right PIN waits out the cooldown");
    assert!(f.engine.status().pin_lockout_seconds > 0);
}

async fn wait_final(f: &common::Fixture, id: &str) -> aegis_core::tickets::TicketView {
    for _ in 0..100 {
        let t = f.engine.ticket(id).unwrap();
        if t.status != TicketStatus::Running {
            return t;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("ticket never finished");
}

#[tokio::test]
async fn mcp_calls_open_tickets_that_need_the_pin() {
    let f = ready().await;
    let RunOutcome::PendingApproval { ticket } = f.engine.run_tool(Origin::Mcp, "demo", "fix", json!({ "note": "x" })).await.unwrap() else {
        panic!("expected a ticket");
    };
    assert_eq!(ticket.status, TicketStatus::PendingApproval);
    assert_eq!(ticket.args["dryRun"], false, "stored args have defaults applied");

    let err = f.engine.decide_ticket(&ticket.ticket_id, true, "000000".into(), None, "app").await.unwrap_err();
    assert_eq!(err.code, ErrorCode::PinInvalid);
    let view = f.engine.decide_ticket(&ticket.ticket_id, true, PIN.into(), Some("  go ahead ".into()), "app").await.unwrap();
    assert_eq!(view.status, TicketStatus::Running);
    let done = wait_final(&f, &ticket.ticket_id).await;
    assert_eq!(done.status, TicketStatus::Approved);
    assert_eq!(done.result.unwrap()["done"], "fix");
    assert_eq!(done.comment.as_deref(), Some("go ahead"));
    assert_eq!(done.decided_via, Some("app"));

    let err = f.engine.decide_ticket(&ticket.ticket_id, false, PIN.into(), None, "app").await.unwrap_err();
    assert_eq!(err.code, ErrorCode::Conflict, "a decided ticket stays decided");
}

#[tokio::test]
async fn three_wrong_pins_lock_a_ticket_and_declines_need_the_pin() {
    let f = ready().await;
    let RunOutcome::PendingApproval { ticket } = f.engine.run_tool(Origin::Mcp, "demo", "fix", json!({})).await.unwrap() else { panic!() };
    for expected in [ErrorCode::PinInvalid, ErrorCode::PinInvalid, ErrorCode::PinLockedOut] {
        let err = f.engine.decide_ticket(&ticket.ticket_id, false, "000000".into(), None, "browser").await.unwrap_err();
        assert_eq!(err.code, expected);
    }
    assert_eq!(f.engine.ticket(&ticket.ticket_id).unwrap().status, TicketStatus::LockedOut);

    // A correct PIN resets the global guard; then a decline works.
    f.engine.check_pin(PIN).await.unwrap();
    let RunOutcome::PendingApproval { ticket } = f.engine.run_tool(Origin::Mcp, "demo", "fix", json!({})).await.unwrap() else { panic!() };
    let view = f.engine.decide_ticket(&ticket.ticket_id, false, PIN.into(), None, "app").await.unwrap();
    assert_eq!(view.status, TicketStatus::Declined);
}

#[tokio::test]
async fn approval_rechecks_that_the_plugin_is_still_installed() {
    let f = ready().await;
    let RunOutcome::PendingApproval { ticket } = f.engine.run_tool(Origin::Mcp, "demo", "fix", json!({})).await.unwrap() else { panic!() };
    f.engine.set_installed(BTreeMap::new()).unwrap();
    let view = f.engine.decide_ticket(&ticket.ticket_id, true, PIN.into(), None, "app").await.unwrap();
    assert_eq!(view.status, TicketStatus::ExecutionFailed);
    assert_eq!(view.error.unwrap().code, ErrorCode::PluginDisabled);
}

#[tokio::test]
async fn locking_forgets_tickets() {
    let f = ready().await;
    f.engine.run_tool(Origin::Mcp, "demo", "fix", json!({})).await.unwrap();
    assert_eq!(f.engine.list_tickets().len(), 1);
    f.engine.lock().await;
    assert!(f.engine.list_tickets().is_empty());
}

#[tokio::test]
async fn loosening_a_gate_needs_the_pin() {
    let f = ready().await;
    let err = f.engine.set_gate_policy("demo", "fix", GatePolicy::Auto, None).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::PinRequired);
    let err = f.engine.set_gate_policy("demo", "fix", GatePolicy::Auto, Some("000000".into())).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::PinInvalid);
    f.engine.set_gate_policy("demo", "fix", GatePolicy::Auto, Some(PIN.into())).await.unwrap();
    assert!(matches!(f.engine.run_tool(Origin::Mcp, "demo", "fix", json!({})).await.unwrap(), RunOutcome::Completed { .. }));

    // Tightening never needs the PIN.
    f.engine.set_gate_policy("demo", "echo", GatePolicy::PinRequired, None).await.unwrap();
    let plugins = f.engine.plugins().unwrap();
    let echo = plugins[0].tools.iter().find(|t| t.id == "echo").unwrap();
    assert_eq!(echo.effective_policy, GatePolicy::PinRequired);
    assert_eq!(echo.mcp_name, "demo__echo");
}

#[tokio::test]
async fn settings_are_validated_and_hold_no_secrets() {
    let f = ready().await;
    for host in ["0.0.0.0", "8.8.8.8", "localhost", "::1"] {
        let err = f.engine.update_settings(SettingsUpdate { mcp_host: Some(host.into()), ..Default::default() }).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArguments, "{host}");
    }
    let err = f.engine.update_settings(SettingsUpdate { mcp_port: Some(80), ..Default::default() }).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArguments);
    let err = f.engine.update_settings(SettingsUpdate { llm_base_url: Some("http://api.example.com/v1".into()), ..Default::default() }).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArguments, "off-LAN must be https");
    let err = f.engine.update_settings(SettingsUpdate { ui_scale: Some(300), ..Default::default() }).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArguments);

    f.engine.set_llm_api_key("sk-secret-value".into()).unwrap();
    let view = f.engine.update_settings(SettingsUpdate { ui_scale: Some(125), mcp_host: Some("192.168.1.20".into()), ..Default::default() }).await.unwrap();
    assert_eq!(view.ui_scale, 125);
    assert_eq!(view.mcp.host, "192.168.1.20");
    assert!(view.llm.has_api_key);
    assert!(view.llm.endpoint.as_ref().unwrap().is_lan);
    let json = serde_json::to_string(&view).unwrap();
    assert!(!json.contains("sk-secret-value"));
    let token = f.engine.reveal_mcp_token(PIN.into()).await.unwrap();
    assert!(!json.contains(&token));
    assert_eq!(f.engine.reveal_mcp_token("000000".into()).await.unwrap_err().code, ErrorCode::PinInvalid);
}

#[tokio::test]
async fn changing_the_pin_re_keys_the_vault() {
    let f = ready().await;
    assert_eq!(f.engine.change_pin("000000".into(), "135791".into()).await.unwrap_err().code, ErrorCode::PinInvalid);
    assert_eq!(f.engine.change_pin(PIN.into(), "1".into()).await.unwrap_err().code, ErrorCode::PinTooWeak);
    f.engine.change_pin(PIN.into(), "135791".into()).await.unwrap();
    f.engine.lock().await;
    assert_eq!(f.engine.unlock(PIN.into()).await.unwrap_err().code, ErrorCode::PinInvalid);
    f.engine.unlock("135791".into()).await.unwrap();
}

#[tokio::test]
async fn rotating_the_token_invalidates_the_old_one() {
    let f = ready().await;
    let old = f.engine.reveal_mcp_token(PIN.into()).await.unwrap();
    assert!(f.engine.mcp_token_matches(&old));
    f.engine.rotate_mcp_token().unwrap();
    assert!(!f.engine.mcp_token_matches(&old));
    assert!(!f.engine.mcp_token_matches(""));
}
