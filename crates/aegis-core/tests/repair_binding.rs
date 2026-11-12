//! ADR 0004 §5: what runs is bound to what was shown. A plugin describes its
//! commands from the arguments; AegisWin answers dry runs from that without
//! calling the plugin, shows and records the commands, covers them with a
//! plan's hash, and refuses a call whose commands changed after approval.

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use aegis_core::engine::{Origin, RunOutcome};
use aegis_core::plan::PlanOrigin;
use aegis_core::tickets::{StepStatus, TicketStatus, TicketView};
use aegis_core::ErrorCode;
use common::{ready, Fixture, PIN};
use serde_json::{json, Value};

async fn wait_final(f: &Fixture, id: &str) -> TicketView {
    for _ in 0..250 {
        let t = f.engine.ticket(id).unwrap();
        if !matches!(t.status, TicketStatus::Running | TicketStatus::Queued) {
            return t;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("ticket never finished");
}

async fn ticket(f: &Fixture, tool: &str, args: Value) -> TicketView {
    match f.engine.run_tool(Origin::Mcp, "demo", tool, args).await.unwrap() {
        RunOutcome::PendingApproval { ticket } => *ticket,
        other => panic!("expected a ticket, got {other:?}"),
    }
}

#[tokio::test]
async fn aegiswin_answers_dry_runs_itself_and_never_calls_the_plugin() {
    let f = ready().await;
    for origin in [Origin::Mcp, Origin::Ui { pin: None }] {
        let out = f.engine.run_tool(origin, "demo", "fix", json!({ "note": "a b", "dryRun": true })).await.unwrap();
        let RunOutcome::Completed { result } = out else { panic!("a dry run needs no approval: {out:?}") };
        assert_eq!(result["executed"], false);
        assert_eq!(result["commands"], json!([r#"C:\demo\fix.exe "a b""#]));
        assert_eq!(result["commandLines"], json!([{ "exe": r"C:\demo\fix.exe", "args": ["a b"] }]));
        assert_eq!(result["review"]["lines"], json!(["Fixes a b."]), "the plugin's own review comes with it");
    }
    assert_eq!(f.plugin.dry_calls.load(Ordering::SeqCst), 0, "Plugin::call never saw a dry run");
    assert!(f.engine.list_tickets().is_empty());
    // A description that fails refuses the call, dry or not.
    let err = f.engine.run_tool(Origin::Mcp, "demo", "fix", json!({ "note": "nodry", "dryRun": true })).await.unwrap_err();
    assert!(err.message.contains("cannot describe"), "{err:?}");
    let err = f.engine.run_tool(Origin::Mcp, "demo", "fix", json!({ "note": "nodry" })).await.unwrap_err();
    assert!(err.message.contains("cannot describe"), "{err:?}");
    assert!(f.engine.list_tickets().is_empty());
}

#[tokio::test]
async fn a_dry_run_of_a_tool_that_cannot_list_its_commands_needs_approval() {
    let f = ready().await;
    let t = ticket(&f, "old_fix", json!({ "dryRun": true })).await;
    assert_eq!(t.status, TicketStatus::PendingApproval, "no free dry run without describe");
    assert!(t.commands.is_empty());
    let err = f.engine.run_tool(Origin::Ui { pin: None }, "demo", "old_fix", json!({ "dryRun": true })).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::PinRequired);
    assert_eq!(f.plugin.dry_calls.load(Ordering::SeqCst), 0);
    // Approved, it runs like any change.
    f.engine.decide_ticket(&t.ticket_id, true, PIN.into(), None, "app").await.unwrap();
    assert_eq!(wait_final(&f, &t.ticket_id).await.status, TicketStatus::Approved);
    assert_eq!(f.plugin.dry_calls.load(Ordering::SeqCst), 1);
    // And it cannot be a plan step.
    let err = f.engine.propose_plan(PlanOrigin::Owner, json!({ "steps": [{ "tool": "demo__old_fix" }] })).await.unwrap_err();
    assert!(err.message.contains("cannot be a plan step"), "{err:?}");
}

#[tokio::test]
async fn a_request_shows_and_records_its_commands_and_runs_only_those() {
    let f = ready().await;
    let t = ticket(&f, "fix", json!({ "note": "one" })).await;
    assert_eq!(t.commands, [r"C:\demo\fix.exe one"]);
    f.engine.decide_ticket(&t.ticket_id, true, PIN.into(), None, "app").await.unwrap();
    assert_eq!(wait_final(&f, &t.ticket_id).await.status, TicketStatus::Approved);
    let record = f.engine.approval_record(PIN, 1).await.unwrap();
    let created = record["events"].as_array().unwrap().iter().find(|e| e["event"] == "created" && e["ticketId"] == t.ticket_id.as_str()).unwrap().clone();
    assert_eq!(created["commands"], json!([r"C:\demo\fix.exe one"]), "the record keeps what was shown");

    // The plugin now describes something else: the approval does not cover it.
    let t = ticket(&f, "fix", json!({ "note": "two" })).await;
    *f.plugin.describe_extra.lock().unwrap() = Some("/also-this".into());
    f.engine.decide_ticket(&t.ticket_id, true, PIN.into(), None, "app").await.unwrap();
    let done = wait_final(&f, &t.ticket_id).await;
    assert_eq!(done.status, TicketStatus::ExecutionFailed);
    assert!(done.error.unwrap().message.starts_with("The commands changed since you approved them"));
    assert_eq!(*f.plugin.fixed.lock().unwrap(), ["one"], "only the first change ran");
}

#[tokio::test]
async fn a_plan_hashes_its_commands_and_stops_at_a_step_whose_commands_changed() {
    let f = ready().await;
    let steps = json!({ "steps": [{ "tool": "demo__fix", "args": { "note": "a" } }, { "tool": "demo__fix", "args": { "note": "b" } }] });
    let first = f.engine.propose_plan(PlanOrigin::Owner, steps.clone()).await.unwrap();
    assert_eq!(first.steps[1].commands, [r"C:\demo\fix.exe b"]);
    // The same request with other commands is a different plan.
    *f.plugin.describe_extra.lock().unwrap() = Some("/x".into());
    let other = f.engine.propose_plan(PlanOrigin::Owner, steps).await.unwrap();
    assert_ne!(first.plan.as_ref().unwrap().hash, other.plan.as_ref().unwrap().hash, "the hash covers the commands");
    f.engine.cancel_ticket(&other.ticket_id).unwrap();

    // Approved as shown, then the commands change before it runs.
    let hash = first.plan.as_ref().unwrap().hash.clone();
    f.engine.decide(&first.ticket_id, true, PIN.into(), None, "app", Some(&hash)).await.unwrap();
    let done = wait_final(&f, &first.ticket_id).await;
    assert_eq!(done.status, TicketStatus::ExecutionFailed);
    assert_eq!(done.steps[0].status, StepStatus::Failed);
    assert_eq!(done.steps[1].status, StepStatus::Skipped);
    let reason = done.plan.unwrap().stop_reason.unwrap();
    assert!(reason.starts_with("Step 1 could not start: The commands changed"), "{reason}");
    assert!(f.plugin.fixed.lock().unwrap().is_empty(), "nothing ran");
}
