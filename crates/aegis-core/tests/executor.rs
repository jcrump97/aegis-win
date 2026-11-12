//! The serial executor seen through the engine (ADR 0003 §5.1): one
//! state-changing run at a time, in approval order, for every origin.

mod common;

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aegis_core::engine::{Engine, Origin, RunOutcome};
use aegis_core::executor::{ChangeView, MAX_QUEUED};
use aegis_core::tickets::TicketStatus;
use aegis_core::{AegisResult, ErrorCode};
use common::{ready, Fixture, PIN};
use serde_json::json;
use tokio::task::JoinHandle;

fn ui() -> Origin {
    Origin::Ui { pin: Some(PIN.to_owned()) }
}

async fn until(what: &str, mut cond: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(5);
    while !cond() {
        assert!(Instant::now() < end, "timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn started(f: &Fixture) -> Vec<String> {
    f.plugin.started.lock().unwrap().clone()
}

/// An agent asks for `fix` with this note; returns the ticket id.
async fn ask(f: &Fixture, note: &str) -> String {
    match f.engine.run_tool(Origin::Mcp, "demo", "fix", json!({ "note": note })).await.unwrap() {
        RunOutcome::PendingApproval { ticket } => ticket.ticket_id,
        other => panic!("{other:?}"),
    }
}

async fn approve(f: &Fixture, id: &str) -> TicketStatus {
    f.engine.decide_ticket(id, true, PIN.into(), None, "app").await.unwrap().status
}

fn status(f: &Fixture, id: &str) -> TicketStatus {
    f.engine.ticket(id).unwrap().status
}

/// The owner clicks Run in the app; the call waits for its turn.
fn run_in_app(engine: &Arc<Engine>, note: &str) -> JoinHandle<AegisResult<RunOutcome>> {
    let (engine, note) = (engine.clone(), note.to_owned());
    tokio::spawn(async move { engine.run_tool(ui(), "demo", "fix", json!({ "note": note })).await })
}

async fn finished<T>(task: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), task).await.expect("should finish")
}

#[tokio::test]
async fn changes_never_overlap_and_run_in_approval_order_from_every_origin() {
    let f = ready().await;
    let (t1, t2) = (ask(&f, "wait-1").await, ask(&f, "wait-2").await);
    // Approval order, not creation order: t2 is approved first.
    assert_eq!(approve(&f, &t2).await, TicketStatus::Running, "nothing ahead of it");
    until("t2 starts", || started(&f) == ["wait-2"]).await;
    assert_eq!(status(&f, &t2), TicketStatus::Running);
    assert_eq!(approve(&f, &t1).await, TicketStatus::Queued);
    let app = run_in_app(&f.engine, "wait-3");
    until("the app run queues", || f.engine.status().change.queued == 2).await;
    let view = f.engine.ticket(&t1).unwrap();
    assert_eq!((view.status, view.queue_position), (TicketStatus::Queued, Some(1)));
    assert_eq!(f.engine.status().change, ChangeView { running: Some("Fix <it>".into()), queued: 2 });
    assert!(f.engine.background_active(), "closing the window must not cut a change off");

    // Read-only tools and dry runs do not wait.
    finished(f.engine.run_tool(ui(), "demo", "echo", json!({ "text": "hi" }))).await.unwrap();
    finished(f.engine.run_tool(ui(), "demo", "fix", json!({ "dryRun": true }))).await.unwrap();

    for (released, expect) in [(1, vec!["wait-2", "wait-1"]), (2, vec!["wait-2", "wait-1", "wait-3"])] {
        f.plugin.release.add_permits(1);
        until("the next change starts", || started(&f).len() == released + 1).await;
        assert_eq!(started(&f), expect);
    }
    f.plugin.release.add_permits(1);
    assert!(matches!(finished(app).await.unwrap().unwrap(), RunOutcome::Completed { .. }));
    until("all done", || status(&f, &t1) == TicketStatus::Approved).await;
    assert_eq!(status(&f, &t2), TicketStatus::Approved);
    assert_eq!(f.plugin.max_running.load(Ordering::SeqCst), 1, "never two changes at once");
    assert_eq!(f.engine.status().change, ChangeView::default());
    assert!(!f.engine.background_active());
}

#[tokio::test]
async fn lock_cancels_waiting_changes_and_they_never_resume() {
    let f = ready().await;
    let t1 = ask(&f, "wait-1").await;
    approve(&f, &t1).await;
    until("t1 runs", || started(&f) == ["wait-1"]).await;
    let t2 = ask(&f, "wait-2").await;
    approve(&f, &t2).await;
    let app = run_in_app(&f.engine, "wait-3");
    until("both wait", || f.engine.status().change.queued == 2).await;

    f.engine.lock().await;
    assert_eq!(finished(app).await.unwrap().unwrap_err().code, ErrorCode::VaultLocked);
    // The running change is not killed.
    assert_eq!(f.engine.status().change, ChangeView { running: Some("Fix <it>".into()), queued: 0 });

    // After unlock, a new change still waits for the one that was running.
    f.engine.unlock(PIN.into()).await.unwrap();
    let after = run_in_app(&f.engine, "wait-4");
    until("the new run queues", || f.engine.status().change.queued == 1).await;
    f.plugin.release.add_permits(2);
    finished(after).await.unwrap().unwrap();
    assert_eq!(started(&f), ["wait-1", "wait-4"], "wait-2 and wait-3 never ran");
    assert_eq!(f.plugin.max_running.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_full_queue_refuses_approval_before_the_pin_is_checked() {
    let f = ready().await;
    let first = run_in_app(&f.engine, "wait-0");
    until("one runs", || started(&f).len() == 1).await;
    let waiting: Vec<_> = (1..=MAX_QUEUED).map(|i| run_in_app(&f.engine, &format!("wait-{i}"))).collect();
    until("the queue fills", || f.engine.status().change.queued == MAX_QUEUED).await;

    let t = ask(&f, "wait-late").await;
    // A wrong PIN is not even looked at, so the request keeps all its attempts.
    let err = f.engine.decide_ticket(&t, true, "000000".into(), None, "browser").await.unwrap_err();
    assert_eq!(err.code, ErrorCode::Conflict);
    let view = f.engine.ticket(&t).unwrap();
    assert_eq!((view.status, view.attempts_remaining), (TicketStatus::PendingApproval, 3));
    // Declining still works.
    assert_eq!(f.engine.decide_ticket(&t, false, PIN.into(), None, "app").await.unwrap().status, TicketStatus::Declined);
    let err = finished(f.engine.run_tool(ui(), "demo", "fix", json!({ "note": "wait-x" }))).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::Conflict);

    f.plugin.release.add_permits(MAX_QUEUED + 1);
    finished(first).await.unwrap().unwrap();
    for w in waiting {
        finished(w).await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn idle_auto_lock_waits_for_the_running_change_and_starts_nothing_new() {
    let f = ready().await;
    let first = run_in_app(&f.engine, "wait-1");
    until("it runs", || started(&f).len() == 1).await;
    let second = run_in_app(&f.engine, "wait-2");
    until("the second waits", || f.engine.status().change.queued == 1).await;

    let away = f.engine.last_activity() + Duration::from_secs(61 * 60);
    assert!(!f.engine.lock_if_idle(away).await, "the running change finishes first");
    assert!(f.engine.status().unlocked);
    f.plugin.release.add_permits(1);
    finished(first).await.unwrap().unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(started(&f), ["wait-1"], "nothing new starts while the lock is due");
    assert!(f.engine.lock_if_idle(away).await);
    assert_eq!(finished(second).await.unwrap().unwrap_err().code, ErrorCode::VaultLocked);
    assert_eq!(f.engine.status().change, ChangeView::default());
}

#[tokio::test]
async fn the_owner_coming_back_releases_the_hold() {
    let f = ready().await;
    let first = run_in_app(&f.engine, "wait-1");
    until("it runs", || started(&f).len() == 1).await;
    let second = run_in_app(&f.engine, "wait-2");
    until("the second waits", || f.engine.status().change.queued == 1).await;
    assert!(!f.engine.lock_if_idle(f.engine.last_activity() + Duration::from_secs(61 * 60)).await);
    f.engine.note_activity();
    assert!(!f.engine.lock_if_idle(Instant::now()).await);
    f.plugin.release.add_permits(2);
    finished(first).await.unwrap().unwrap();
    finished(second).await.unwrap().unwrap();
    assert_eq!(started(&f), ["wait-1", "wait-2"]);
}

#[tokio::test]
async fn a_waiting_change_is_checked_again_when_its_turn_comes() {
    let f = ready().await;
    let first = run_in_app(&f.engine, "wait-1");
    until("it runs", || started(&f).len() == 1).await;
    let t = ask(&f, "wait-2").await;
    assert_eq!(approve(&f, &t).await, TicketStatus::Queued);
    let app = run_in_app(&f.engine, "wait-3");
    until("both wait", || f.engine.status().change.queued == 2).await;

    // The owner turns the plugin off while they wait.
    f.engine.set_installed(BTreeMap::new()).unwrap();
    f.plugin.release.add_permits(1);
    finished(first).await.unwrap().unwrap();
    assert_eq!(finished(app).await.unwrap().unwrap_err().code, ErrorCode::PluginDisabled);
    until("the ticket fails", || status(&f, &t) == TicketStatus::ExecutionFailed).await;
    assert_eq!(f.engine.ticket(&t).unwrap().error.unwrap().code, ErrorCode::PluginDisabled);
    assert_eq!(started(&f), ["wait-1"]);
}
