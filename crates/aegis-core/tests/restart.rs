//! Restart as administrator and the serial executor (SECURITY_MODEL §5, issue #87):
//! while the UAC prompt is open no change starts, so the exit that follows an
//! accepted launch cannot cut one off. The launch is a closure; no prompt is shown.

mod common;

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aegis_core::engine::{Engine, Origin, RunOutcome};
use aegis_core::restart::restart_elevated;
use aegis_core::{AegisResult, ErrorCode};
use common::{ready, Fixture, PIN};
use serde_json::json;
use tokio::task::JoinHandle;

/// The owner clicks Run in the app while the prompt is open.
fn run_in_app(engine: &Arc<Engine>, note: &str) -> JoinHandle<AegisResult<RunOutcome>> {
    let (engine, note) = (engine.clone(), note.to_owned());
    tokio::spawn(async move { engine.run_tool(Origin::Ui { pin: Some(PIN.to_owned()) }, "demo", "fix", json!({ "note": note })).await })
}

fn started(f: &Fixture) -> Vec<String> {
    f.plugin.started.lock().unwrap().clone()
}

/// The prompt is open for a moment: the change asked for meanwhile is queued, not started.
fn prompt_open_while(f: &Fixture, handle: &tokio::runtime::Handle, note: &str) -> JoinHandle<AegisResult<RunOutcome>> {
    let _enter = handle.enter();
    let task = run_in_app(&f.engine, note);
    let end = Instant::now() + Duration::from_secs(5);
    while f.engine.status().change.queued == 0 {
        assert!(Instant::now() < end, "the change should queue");
        std::thread::sleep(Duration::from_millis(5));
    }
    std::thread::sleep(Duration::from_millis(100));
    assert!(started(f).is_empty(), "no change starts while the prompt is open");
    assert_eq!(f.engine.change_running(), None);
    task
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_change_asked_for_during_an_accepted_prompt_never_starts() {
    let f = ready().await;
    let handle = tokio::runtime::Handle::current();
    let mut task = None;
    restart_elevated(&f.engine, || {
        task = Some(prompt_open_while(&f, &handle, "wait-during"));
        Ok(())
    }, || {}, || {})
    .await
    .unwrap();
    // The exit cancels what waited, so nothing was cut off and nothing runs in the old copy.
    let out = tokio::time::timeout(Duration::from_secs(5), task.unwrap()).await.expect("the waiting run ends").unwrap();
    assert!(out.is_err(), "{out:?}");
    assert!(started(&f).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_change_asked_for_during_a_cancelled_prompt_starts_once_it_is_answered() {
    let f = ready().await;
    let handle = tokio::runtime::Handle::current();
    let mut task = None;
    let out = restart_elevated(&f.engine, || {
        task = Some(prompt_open_while(&f, &handle, "wait-after"));
        Err(io::Error::from(io::ErrorKind::Interrupted))
    }, || panic!("the claim is kept"), || panic!("the app keeps running"))
    .await;
    assert_eq!(out.unwrap_err().code, ErrorCode::AccessDenied);
    let end = Instant::now() + Duration::from_secs(5);
    while started(&f).is_empty() {
        assert!(Instant::now() < end, "the change starts once the prompt is gone");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(started(&f), ["wait-after"]);
    f.plugin.release.add_permits(1);
    let done = tokio::time::timeout(Duration::from_secs(5), task.unwrap()).await.unwrap().unwrap().unwrap();
    assert!(matches!(done, RunOutcome::Completed { .. }), "{done:?}");
}

#[tokio::test]
async fn a_running_change_refuses_the_restart_before_any_prompt() {
    let f = ready().await;
    let run = run_in_app(&f.engine, "wait-busy");
    let end = Instant::now() + Duration::from_secs(5);
    while started(&f).is_empty() {
        assert!(Instant::now() < end);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let out = restart_elevated(&f.engine, || panic!("no prompt while a change runs"), || {}, || {}).await;
    assert_eq!(out.unwrap_err().code, ErrorCode::Conflict);
    f.plugin.release.add_permits(1);
    run.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_prompt_is_refused_while_the_first_is_open() {
    use aegis_core::executor::RestartRefused;
    // The app has two Restart buttons: the answer to one prompt must not end the other's hold.
    let f = ready().await;
    let out = restart_elevated(&f.engine, || {
        assert_eq!(f.engine.hold_changes_for_restart().err(), Some(RestartRefused::AlreadyAsking));
        Err(io::Error::from(io::ErrorKind::Interrupted))
    }, || {}, || {})
    .await;
    assert_eq!(out.unwrap_err().code, ErrorCode::AccessDenied);
    assert!(f.engine.hold_changes_for_restart().is_ok(), "the hold ends with the prompt");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn after_an_accepted_restart_the_app_s_exit_handler_stops_nothing_more() {
    // Issue #91: the claim may already be the elevated copy's, so the app's own exit,
    // which runs after `quit`, must not stop or write anything a second time.
    let f = ready().await;
    let (released, quit) = (std::cell::Cell::new(false), std::cell::Cell::new(false));
    restart_elevated(&f.engine, || Ok(()), || released.set(true), || quit.set(true)).await.unwrap();
    assert!(released.get() && quit.get());
    assert!(!f.engine.status().unlocked, "the restart's exit ran and locked the vault");
    f.engine.unlock(PIN.into()).await.unwrap();
    f.engine.exit(aegis_core::registry::ExitReason::Quit).await;
    assert!(f.engine.status().unlocked, "a later exit does nothing");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_exit_cut_at_its_budget_runs_no_stop_step_after_the_claim_is_let_go() {
    // Issue #91: a stop step that blocks its thread (usage-monitor joins its sampler)
    // outlives the budget. Once the claim is let go the elevated copy may own the
    // files, so when the step returns, the exit starts nothing more: here the vault
    // stays open, where the rest of the exit would have locked it.
    let f = ready().await;
    f.engine.set_exit_hook(Some(Arc::new(|| std::thread::sleep(Duration::from_millis(800)))));
    let started = Instant::now();
    aegis_core::restart::restart_elevated_within(&f.engine, Duration::from_millis(100), || Ok(()), || {}, || {}).await.unwrap();
    assert!(started.elapsed() < Duration::from_millis(600), "the restart is cut at its budget");
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(f.engine.status().unlocked, "nothing after the blocked step ran");
    f.engine.set_exit_hook(None);

    // A later Restart click while this copy is ending is refused, not prompted.
    let out = restart_elevated(&f.engine, || panic!("no second prompt"), || {}, || {}).await;
    assert_eq!(out.unwrap_err().message, "AegisWin is already restarting as administrator.");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lock_while_a_restart_ends_this_copy_starts_nothing() {
    // The tray's Lock or idle auto-lock during the restart's exit would start locked
    // monitoring in this copy; it does nothing instead (the exit locks).
    let f = ready().await;
    restart_elevated(&f.engine, || Ok(()), || {}, || {}).await.unwrap();
    f.engine.unlock(PIN.into()).await.unwrap();
    assert!(f.engine.lock().await.unlocked, "a lock after the restart began its exit does nothing");
}
