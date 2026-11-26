//! Restart as administrator and the serial executor (SECURITY_MODEL §5, issue #87):
//! while the UAC prompt is open no change starts, so the exit that follows an
//! accepted launch cannot cut one off. The launch is a closure; no prompt is shown.

mod common;

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
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
    // which runs after `quit`, must not stop or write anything a second time, and this
    // copy cannot be unlocked again.
    let f = ready().await;
    let exits = Arc::new(AtomicUsize::new(0));
    let counted = exits.clone();
    f.engine.set_exit_hook(Some(Arc::new(move || {
        counted.fetch_add(1, Ordering::SeqCst);
    })));
    let (released, quit) = (std::cell::Cell::new(false), std::cell::Cell::new(false));
    restart_elevated(&f.engine, || Ok(()), || released.set(true), || quit.set(true)).await.unwrap();
    assert!(released.get() && quit.get());
    assert!(!f.engine.status().unlocked, "the restart's exit ran and locked the vault");
    assert_eq!(exits.load(Ordering::SeqCst), 1);
    f.engine.exit(aegis_core::registry::ExitReason::Quit).await;
    assert_eq!(exits.load(Ordering::SeqCst), 1, "a later exit does nothing");
    assert_eq!(f.engine.unlock(PIN.into()).await.unwrap_err().code, ErrorCode::Conflict, "this copy is ending; the new one is unlocked instead");
    f.engine.set_exit_hook(None);
}

fn stream_bytes(f: &Fixture) -> u64 {
    let dir = f.engine.data_dir().join("history").join("demo");
    std::fs::read_dir(dir).map(|d| d.map(|e| e.unwrap().metadata().unwrap().len()).sum()).unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_exit_cut_at_its_budget_writes_nothing_after_the_claim_is_let_go() {
    // Issue #91: a stop step that blocks its thread (usage-monitor joins its sampler,
    // then writes its stop record) outlives the budget. Once the claim is let go the
    // elevated copy may own the files, so when the step returns, its write is refused
    // and nothing in ./data changes.
    let f = ready().await;
    let history = f.plugin.unlock_history.lock().unwrap().clone().expect("on_unlock gets a history handle");
    history.append(json!({ "kind": "before" })).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let tx = std::sync::Mutex::new(tx);
    f.engine.set_exit_hook(Some(Arc::new(move || {
        std::thread::sleep(Duration::from_millis(800));
        let _ = tx.lock().unwrap().send(history.append(json!({ "kind": "after the claim" })));
    })));
    let released = std::sync::Mutex::new(None);
    let started = Instant::now();
    aegis_core::restart::restart_elevated_within(&f.engine, Duration::from_millis(100), || Ok(()), || *released.lock().unwrap() = Some(stream_bytes(&f)), || {}).await.unwrap();
    assert!(started.elapsed() < Duration::from_millis(600), "the restart is cut at its budget");
    let at_release = released.lock().unwrap().expect("the claim was let go");
    let late = tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(30))).await.unwrap().expect("the blocked step returns");
    assert_eq!(late.unwrap_err().code, ErrorCode::Conflict, "its write is refused");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(stream_bytes(&f), at_release, "nothing was written after the claim was let go");
    f.engine.history_tick();
    assert_eq!(stream_bytes(&f), at_release, "the app's history tick writes nothing either");
    f.engine.set_exit_hook(None);

    // A later Restart click while this copy is ending is refused with its own message.
    let out = restart_elevated(&f.engine, || panic!("no second prompt"), || {}, || {}).await;
    assert_eq!(out.unwrap_err().message, "AegisWin is already restarting as administrator.");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lock_while_a_restart_ends_this_copy_leaves_the_stopping_to_the_exit() {
    // The tray's Lock or idle auto-lock while the restart's exit runs must not start
    // locked work in this copy, nor take the vault before the exit has stopped the
    // plugins (then they would get neither their exit nor their lock). It does
    // nothing; the exit locks, once. An unlock meanwhile is refused.
    let f = ready().await;
    let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let (entered_tx, go_rx) = (std::sync::Mutex::new(entered_tx), std::sync::Mutex::new(go_rx));
    f.engine.set_exit_hook(Some(Arc::new(move || {
        let _ = entered_tx.lock().unwrap().send(());
        let _ = go_rx.lock().unwrap().recv_timeout(Duration::from_secs(30));
    })));
    let engine = f.engine.clone();
    let restart = tokio::spawn(async move { restart_elevated(&engine, || Ok(()), || {}, || {}).await });
    tokio::task::spawn_blocking(move || entered_rx.recv_timeout(Duration::from_secs(30))).await.unwrap().expect("the exit begins");
    let locks_before = f.plugin.locks.load(Ordering::SeqCst);
    assert!(f.engine.lock().await.unlocked, "the lock leaves the vault to the exit");
    assert_eq!(f.plugin.locks.load(Ordering::SeqCst), locks_before, "and stops nothing itself");
    assert_eq!(f.engine.unlock(PIN.into()).await.unwrap_err().code, ErrorCode::Conflict, "this copy cannot be unlocked again");
    assert_eq!(f.engine.start_mcp().await.unwrap_err().code, ErrorCode::Conflict, "nor serve agents again");
    assert!(!f.engine.mcp_status().await.running);
    go_tx.send(()).unwrap();
    restart.await.unwrap().unwrap();
    assert_eq!(f.plugin.locks.load(Ordering::SeqCst), locks_before + 1, "the exit stopped the plugin, once");
    assert!(!f.engine.status().unlocked && !f.engine.locked_monitoring(), "no locked work runs in the ending copy");
    assert_eq!(f.engine.forget_this_pc().unwrap_err().code, ErrorCode::Conflict, "nothing in ./data changes after the claim is let go");
    f.engine.set_exit_hook(None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unlocks_under_way_when_a_restart_begins_keep_nothing() {
    // The owner unlocks, and while the key is being derived a second unlock
    // waits its turn and the restart is accepted. The first keeps no vault
    // and tells no plugin it unlocked; the second is refused once its turn
    // comes and derives no key at all.
    let f = ready().await;
    f.engine.lock().await;
    assert!(!f.engine.status().unlocked);
    let unlocks_before = f.plugin.unlocks.load(Ordering::SeqCst);
    let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let (entered_tx, go_rx) = (std::sync::Mutex::new(entered_tx), std::sync::Mutex::new(go_rx));
    let derived = Arc::new(AtomicUsize::new(0));
    let counted = derived.clone();
    f.engine.set_unlock_hook(Some(Arc::new(move || {
        if counted.fetch_add(1, Ordering::SeqCst) == 0 {
            let _ = entered_tx.lock().unwrap().send(());
            let _ = go_rx.lock().unwrap().recv_timeout(Duration::from_secs(30));
        }
    })));
    let engine = f.engine.clone();
    let first = tokio::spawn(async move { engine.unlock(PIN.into()).await });
    tokio::task::spawn_blocking(move || entered_rx.recv_timeout(Duration::from_secs(30))).await.unwrap().expect("the unlock derives its key");
    let engine = f.engine.clone();
    let second = tokio::spawn(async move { engine.unlock(PIN.into()).await });
    tokio::time::sleep(Duration::from_millis(100)).await; // the second now waits its turn
    let engine = f.engine.clone();
    let restart = tokio::spawn(async move { restart_elevated(&engine, || Ok(()), || {}, || {}).await });
    let started = Instant::now();
    while !f.engine.exiting_for_restart() {
        assert!(started.elapsed() < Duration::from_secs(30), "the restart was accepted");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    go_tx.send(()).unwrap();
    assert_eq!(first.await.unwrap().unwrap_err().code, ErrorCode::Conflict, "the first unlock is refused");
    assert_eq!(second.await.unwrap().unwrap_err().code, ErrorCode::Conflict, "the second unlock is refused");
    restart.await.unwrap().unwrap();
    assert_eq!(derived.load(Ordering::SeqCst), 1, "the waiting unlock derived no key");
    assert_eq!(f.plugin.unlocks.load(Ordering::SeqCst), unlocks_before, "no plugin was told this copy unlocked");
    assert!(!f.engine.status().unlocked && !f.engine.locked_monitoring(), "the ending copy holds no vault and runs nothing");
    f.engine.set_unlock_hook(None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unlock_that_kept_the_vault_just_before_a_restart_finishes_before_the_exit_stops_anything() {
    // The vault is kept, then the restart is accepted before the plugins are
    // told. The exit waits for that unlock, so no plugin hears of the unlock
    // after its stop, and the exit's lock is the last word.
    let f = ready().await;
    f.engine.lock().await;
    let unlocks_before = f.plugin.unlocks.load(Ordering::SeqCst);
    let locks_before = f.plugin.locks.load(Ordering::SeqCst);
    let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let (entered_tx, go_rx) = (std::sync::Mutex::new(entered_tx), std::sync::Mutex::new(go_rx));
    f.engine.set_unlock_kept_hook(Some(Arc::new(move || {
        let _ = entered_tx.lock().unwrap().send(());
        let _ = go_rx.lock().unwrap().recv_timeout(Duration::from_secs(30));
    })));
    // What the plugin had heard when the exit's stop steps began.
    let heard = Arc::new(AtomicUsize::new(usize::MAX));
    let (heard_at_exit, plugin) = (heard.clone(), f.plugin.clone());
    f.engine.set_exit_hook(Some(Arc::new(move || heard_at_exit.store(plugin.unlocks.load(Ordering::SeqCst), Ordering::SeqCst))));
    let engine = f.engine.clone();
    let unlock = tokio::spawn(async move { engine.unlock(PIN.into()).await });
    tokio::task::spawn_blocking(move || entered_rx.recv_timeout(Duration::from_secs(30))).await.unwrap().expect("the unlock keeps the vault");
    let engine = f.engine.clone();
    let restart = tokio::spawn(async move { restart_elevated(&engine, || Ok(()), || {}, || {}).await });
    let started = Instant::now();
    while !f.engine.exiting_for_restart() {
        assert!(started.elapsed() < Duration::from_secs(30), "the restart was accepted");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // Give an exit that does not wait the time to reach its stop steps.
    let waited = Instant::now();
    while heard.load(Ordering::SeqCst) == usize::MAX && waited.elapsed() < Duration::from_millis(500) {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(heard.load(Ordering::SeqCst), usize::MAX, "no stop step starts while the unlock is under way");
    go_tx.send(()).unwrap();
    assert_eq!(unlock.await.unwrap().unwrap_err().code, ErrorCode::Conflict, "the unlock reports the restart");
    restart.await.unwrap().unwrap();
    assert_eq!(heard.load(Ordering::SeqCst), unlocks_before + 1, "the plugin heard of the unlock before the exit stopped it");
    assert_eq!(f.plugin.locks.load(Ordering::SeqCst), locks_before + 1, "the exit stopped the plugin, once");
    assert!(!f.engine.status().unlocked && !f.engine.mcp_status().await.running, "the ending copy holds no vault and serves nothing");
    f.engine.set_unlock_kept_hook(None);
    f.engine.set_exit_hook(None);
}
