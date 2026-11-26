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
