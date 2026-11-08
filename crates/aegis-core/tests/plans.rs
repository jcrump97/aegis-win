//! Action plans through the engine (ADR 0003 §3–§5): a plan is checked and
//! dry-run when proposed, approved once with the PIN and its fingerprint, run
//! step by step in one turn, and stops at the first failure.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aegis_core::engine::{Origin, RunOutcome};
use aegis_core::plan::{PlanOrigin, MAX_PENDING_PLANS};
use aegis_core::tickets::{StepStatus, TicketStatus, TicketView, STRIKES_PER_TICKET};
use aegis_core::ErrorCode;
use common::{ready, Fixture, PIN};
use serde_json::{json, Value};

async fn until(what: &str, mut cond: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(5);
    while !cond() {
        assert!(Instant::now() < end, "timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn fix(note: &str) -> Value {
    json!({ "tool": "demo__fix", "args": { "note": note } })
}

async fn propose(f: &Fixture, steps: Vec<Value>) -> TicketView {
    f.engine.propose_plan(PlanOrigin::Agent, json!({ "title": "Repair", "reasoning": "Because.", "steps": steps })).await.unwrap()
}

async fn approve(f: &Fixture, t: &TicketView) -> TicketView {
    let hash = t.plan.as_ref().unwrap().hash.clone();
    f.engine.decide(&t.ticket_id, true, PIN.into(), None, "app", Some(&hash)).await.unwrap()
}

fn view(f: &Fixture, id: &str) -> TicketView {
    f.engine.ticket(id).unwrap()
}

fn steps(t: &TicketView) -> Vec<StepStatus> {
    t.steps.iter().map(|s| s.status).collect()
}

fn fixed(f: &Fixture) -> Vec<String> {
    f.plugin.fixed.lock().unwrap().clone()
}

async fn done(f: &Fixture, id: &str) -> TicketView {
    until("the plan finishes", || view(f, id).status.is_final()).await;
    view(f, id)
}

#[tokio::test]
async fn a_proposed_plan_is_dry_run_and_runs_nothing_until_approved() {
    let f = ready().await;
    let t = propose(&f, vec![fix("one"), fix("two")]).await;
    assert_eq!(t.status, TicketStatus::PendingApproval);
    assert_eq!((t.plugin_id.as_str(), t.tool_name.as_str()), ("aegis", "Action plan (2 steps)"), "the supplied title never names the ticket");
    assert_eq!(t.plan.as_ref().unwrap().title.as_deref(), Some("Repair"));
    let plan = t.plan.as_ref().unwrap();
    assert_eq!(plan.hash.len(), 64);
    assert_eq!(plan.supplied_label, "Supplied by the requesting agent");
    assert!(plan.summary.starts_with("2 steps"), "{}", plan.summary);
    assert_eq!(t.steps[0].commands, ["fix.exe one"]);
    assert_eq!(t.steps[1].args, json!({ "note": "two", "dryRun": false }), "defaults are filled in and shown");
    assert_eq!(steps(&t), [StepStatus::Pending, StepStatus::Pending]);
    assert!(fixed(&f).is_empty(), "only dry runs so far");

    let t = approve(&f, &t).await;
    let t = done(&f, &t.ticket_id).await;
    assert_eq!(t.status, TicketStatus::Approved);
    assert_eq!(steps(&t), [StepStatus::Succeeded, StepStatus::Succeeded]);
    assert_eq!(fixed(&f), ["one", "two"]);
}

#[tokio::test]
async fn only_opted_in_tools_can_be_steps() {
    let f = ready().await;
    let refuse = |steps: Vec<Value>| f.engine.propose_plan(PlanOrigin::Agent, json!({ "steps": steps }));
    let e = refuse(vec![json!({ "tool": "demo__echo" })]).await.unwrap_err();
    assert!(e.message.contains("cannot be a plan step"), "{e:?}");
    let e = refuse(vec![json!({ "tool": "demo__nope" })]).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::UnknownTool);
    let e = refuse(vec![fix("a"), json!({ "tool": "demo__fix", "args": { "note": 5 } })]).await.unwrap_err();
    assert!(e.message.starts_with("Step 2:"), "{e:?}");
    let e = refuse(vec![fix("a"), fix("a")]).await.unwrap_err();
    assert!(e.message.contains("the same"), "{e:?}");
    let e = refuse(vec![fix("nodry")]).await.unwrap_err();
    assert!(e.message.contains("dry run failed"), "{e:?}");
    // Turned-off plugins are refused like any call.
    f.engine.set_installed(BTreeMap::new()).unwrap();
    assert_eq!(refuse(vec![fix("a")]).await.unwrap_err().code, ErrorCode::PluginDisabled);
    assert!(fixed(&f).is_empty());
}

#[tokio::test]
async fn approval_must_name_the_plan_shown_and_a_mismatch_costs_no_attempt() {
    let f = ready().await;
    let t = propose(&f, vec![fix("one")]).await;
    let id = t.ticket_id.clone();
    for hash in [None, Some("0".repeat(64))] {
        let e = f.engine.decide(&id, true, "wrong".into(), None, "app", hash.as_deref()).await.unwrap_err();
        assert_eq!(e.code, ErrorCode::Conflict, "checked before the PIN");
    }
    assert_eq!(view(&f, &id).status, TicketStatus::PendingApproval);
    let hash = t.plan.as_ref().unwrap().hash.clone();
    let e = f.engine.decide(&id, true, "wrong".into(), None, "app", Some(&hash)).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::PinInvalid);
    assert!(e.message.contains(&format!("{} attempt(s) left", STRIKES_PER_TICKET - 1)), "the mismatches cost nothing: {e:?}");
    // The plain single-ticket path cannot approve a plan.
    assert_eq!(f.engine.decide_ticket(&id, true, PIN.into(), None, "app").await.unwrap_err().code, ErrorCode::Conflict);
    // Declining needs no fingerprint.
    let t = f.engine.decide(&id, false, PIN.into(), None, "app", None).await.unwrap();
    assert_eq!(t.status, TicketStatus::Declined);
    assert!(fixed(&f).is_empty());
}

#[tokio::test]
async fn the_first_failure_stops_the_plan_and_earlier_changes_stay() {
    let f = ready().await;
    for bad in ["fail", "unwell"] {
        let t = propose(&f, vec![fix(&format!("{bad}-first")), fix(&format!("{bad}-x")), fix(&format!("{bad}-y"))]).await;
        // The failing step is first here, so nothing after it runs.
        let t = done(&f, &approve(&f, &t).await.ticket_id).await;
        assert_eq!(t.status, TicketStatus::ExecutionFailed);
        assert_eq!(steps(&t), [StepStatus::Failed, StepStatus::Skipped, StepStatus::Skipped], "{bad}");
        assert!(t.plan.unwrap().stop_reason.unwrap().starts_with("Step 1 failed"));
    }
    let t = propose(&f, vec![fix("ok"), fix("fail-2"), fix("never")]).await;
    let t = done(&f, &approve(&f, &t).await.ticket_id).await;
    assert_eq!(steps(&t), [StepStatus::Succeeded, StepStatus::Failed, StepStatus::Skipped]);
    assert_eq!(t.steps[1].error.as_ref().unwrap().message, "fix broke");
    assert_eq!(t.error.unwrap().message, "Step 2 failed: fix broke", "the plan's error names the step");
    assert!(!fixed(&f).contains(&"never".to_owned()));
    assert!(fixed(&f).contains(&"ok".to_owned()), "the first change stays");
}

#[tokio::test]
async fn each_step_is_checked_again_before_it_runs() {
    let f = ready().await;
    let t = propose(&f, vec![fix("wait-1"), fix("two")]).await;
    let id = approve(&f, &t).await.ticket_id;
    until("step 1 runs", || f.plugin.started.lock().unwrap().len() == 1).await;
    f.engine.set_installed(BTreeMap::new()).unwrap();
    f.plugin.release.add_permits(1);
    let t = done(&f, &id).await;
    assert_eq!(steps(&t), [StepStatus::Succeeded, StepStatus::Failed]);
    assert_eq!(t.steps[1].error.as_ref().unwrap().code, ErrorCode::PluginDisabled);
    assert_eq!(fixed(&f), ["wait-1"]);
}

#[tokio::test]
async fn cancel_withdraws_a_request_or_stops_a_plan_before_its_next_step() {
    let f = ready().await;
    // Pending: withdrawn, nothing runs.
    let t = propose(&f, vec![fix("p")]).await;
    assert_eq!(f.engine.cancel_ticket(&t.ticket_id).unwrap().status, TicketStatus::Cancelled);
    assert_eq!(f.engine.cancel_ticket(&t.ticket_id).unwrap_err().code, ErrorCode::Conflict, "final");
    let e = f.engine.decide(&t.ticket_id, true, PIN.into(), None, "app", Some(&t.plan.unwrap().hash)).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Conflict);

    // Running: the current step finishes, the rest are cancelled.
    let t = propose(&f, vec![fix("wait-a"), fix("b"), fix("c")]).await;
    let running = approve(&f, &t).await.ticket_id;
    until("step 1 runs", || f.plugin.started.lock().unwrap().len() == 1).await;
    f.engine.cancel_ticket(&running).unwrap();

    // Queued behind it: withdrawn from the queue.
    let q = f.engine.run_tool(Origin::Mcp, "demo", "fix", json!({ "note": "queued" })).await.unwrap();
    let RunOutcome::PendingApproval { ticket } = q else { panic!() };
    let q = f.engine.decide_ticket(&ticket.ticket_id, true, PIN.into(), None, "app").await.unwrap();
    assert_eq!(q.status, TicketStatus::Queued);
    assert_eq!(f.engine.cancel_ticket(&q.ticket_id).unwrap().status, TicketStatus::Cancelled);
    assert_eq!(f.engine.status().change.queued, 0);

    f.plugin.release.add_permits(1);
    let t = done(&f, &running).await;
    assert_eq!(t.status, TicketStatus::Cancelled);
    assert_eq!(steps(&t), [StepStatus::Succeeded, StepStatus::Cancelled, StepStatus::Cancelled]);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(fixed(&f), ["wait-a"], "neither later steps nor the withdrawn request ran");
    assert_eq!(view(&f, &q.ticket_id).status, TicketStatus::Cancelled);
}

#[tokio::test]
async fn a_running_single_action_cannot_be_cancelled() {
    let f = ready().await;
    let RunOutcome::PendingApproval { ticket } = f.engine.run_tool(Origin::Mcp, "demo", "fix", json!({ "note": "wait" })).await.unwrap() else { panic!() };
    f.engine.decide_ticket(&ticket.ticket_id, true, PIN.into(), None, "app").await.unwrap();
    until("it runs", || f.plugin.started.lock().unwrap().len() == 1).await;
    assert_eq!(f.engine.cancel_ticket(&ticket.ticket_id).unwrap_err().code, ErrorCode::Conflict);
    f.plugin.release.add_permits(1);
    assert_eq!(done(&f, &ticket.ticket_id).await.status, TicketStatus::Approved);
}

#[tokio::test]
async fn idle_auto_lock_stops_a_plan_between_steps() {
    let f = ready().await;
    let t = propose(&f, vec![fix("wait-1"), fix("two")]).await;
    let id = approve(&f, &t).await.ticket_id;
    until("step 1 runs", || f.plugin.started.lock().unwrap().len() == 1).await;
    let away = f.engine.last_activity() + Duration::from_secs(61 * 60);
    assert!(!f.engine.lock_if_idle(away).await, "the running step finishes first");
    f.plugin.release.add_permits(1);
    let t = done(&f, &id).await;
    assert_eq!(t.status, TicketStatus::Cancelled);
    assert_eq!(steps(&t), [StepStatus::Succeeded, StepStatus::Cancelled]);
    assert!(t.plan.unwrap().stop_reason.unwrap().contains("inactivity"));
    assert!(f.engine.lock_if_idle(away).await);
    assert_eq!(fixed(&f), ["wait-1"]);
}

#[tokio::test]
async fn locking_ends_a_plan_after_its_running_step() {
    let f = ready().await;
    let t = propose(&f, vec![fix("wait-1"), fix("two")]).await;
    approve(&f, &t).await;
    until("step 1 runs", || f.plugin.started.lock().unwrap().len() == 1).await;
    f.engine.lock().await;
    f.plugin.release.add_permits(1);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(fixed(&f), ["wait-1"], "nothing runs after the lock");
}

#[tokio::test]
async fn pending_plans_are_limited() {
    let f = ready().await;
    for i in 0..MAX_PENDING_PLANS {
        propose(&f, vec![fix(&format!("n{i}"))]).await;
    }
    let e = f.engine.propose_plan(PlanOrigin::Agent, json!({ "steps": [fix("more")] })).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Conflict);
    assert!(e.message.contains("already waiting"));
}

#[tokio::test]
async fn reasoning_that_names_another_tool_is_flagged() {
    let f = ready().await;
    let t = f.engine.propose_plan(PlanOrigin::Agent, json!({ "reasoning": "Run admin_fix afterwards.", "steps": [fix("a")] })).await.unwrap();
    let flags = &t.plan.unwrap().flags;
    assert_eq!(flags.len(), 1);
    assert!(flags[0].contains("Admin fix"), "{flags:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_approvals_run_a_request_once() {
    let f = ready().await;
    for round in 0..20 {
        let RunOutcome::PendingApproval { ticket } = f.engine.run_tool(Origin::Mcp, "demo", "fix", json!({ "note": format!("r{round}") })).await.unwrap() else { panic!() };
        let tasks: Vec<_> = (0..3)
            .map(|_| {
                let (engine, id) = (Arc::clone(&f.engine), ticket.ticket_id.clone());
                tokio::spawn(async move { engine.decide_ticket(&id, true, PIN.into(), None, "app").await })
            })
            .collect();
        let mut ok = 0;
        for t in tasks {
            if t.await.unwrap().is_ok() {
                ok += 1;
            }
        }
        assert_eq!(ok, 1, "round {round}");
        done(&f, &ticket.ticket_id).await;
    }
    let mut runs = fixed(&f);
    runs.dedup();
    assert_eq!(runs.len(), 20, "each request ran exactly once");
    assert_eq!(fixed(&f).len(), 20);
}

#[tokio::test]
async fn the_owner_builds_plans_through_the_same_checks() {
    let f = ready().await;
    let plugins = f.engine.plugins().unwrap();
    let tools = &plugins[0].tools;
    let eligible: Vec<(&str, bool)> = tools.iter().map(|t| (t.id.as_str(), t.plan_eligible)).collect();
    assert!(eligible.contains(&("fix", true)) && eligible.contains(&("echo", false)), "the app knows which tools can be steps");

    let t = f.engine.propose_plan(PlanOrigin::Owner, json!({ "title": "Mine", "steps": [fix("own")] })).await.unwrap();
    let plan = t.plan.as_ref().unwrap();
    assert_eq!((plan.origin, plan.supplied_label), (PlanOrigin::Owner, "Written by you"));
    assert!(fixed(&f).is_empty(), "creating it runs nothing");
    let e = f.engine.propose_plan(PlanOrigin::Owner, json!({ "steps": [{ "tool": "demo__echo" }] })).await.unwrap_err();
    assert!(e.message.contains("cannot be a plan step"));
    // It still needs the PIN and its hash.
    assert_eq!(f.engine.decide(&t.ticket_id, true, PIN.into(), None, "app", None).await.unwrap_err().code, ErrorCode::Conflict);
    let t = done(&f, &approve(&f, &t).await.ticket_id).await;
    assert_eq!(t.status, TicketStatus::Approved);
    assert_eq!(fixed(&f), ["own"]);
}
