//! The durable approval record (ADR 0003 §7): the engine's encrypted
//! `approvals` stream keeps every request, decision, change and outcome
//! after the request itself is forgotten. Reading and deleting it need the
//! PIN; the PIN is never in it.

mod common;

use std::time::{Duration, Instant};

use aegis_core::engine::{Origin, RunOutcome};
use aegis_core::history_service::{change_windows, ChangeWindow, OPEN_CHANGE_LIMIT};
use aegis_core::plan::PlanOrigin;
use aegis_core::tickets::{TicketStatus, TicketView, STRIKES_PER_TICKET};
use aegis_core::ErrorCode;
use chrono::{DateTime, TimeZone, Utc};
use common::{ready, Fixture, PIN};
use serde_json::{json, Value};

async fn until(what: &str, mut cond: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(5);
    while !cond() {
        assert!(Instant::now() < end, "timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn done(f: &Fixture, id: &str) -> TicketView {
    until("the request finishes", || f.engine.ticket(id).unwrap().status.is_final()).await;
    f.engine.ticket(id).unwrap()
}

async fn mcp_fix(f: &Fixture, note: &str) -> TicketView {
    let RunOutcome::PendingApproval { ticket } = f.engine.run_tool(Origin::Mcp, "demo", "fix", json!({ "note": note })).await.unwrap() else { panic!("a fix waits for approval") };
    *ticket
}

/// The record, oldest first.
async fn record(f: &Fixture) -> Vec<Value> {
    let v = f.engine.approval_record(PIN, 1).await.unwrap();
    let mut events = v["events"].as_array().unwrap().clone();
    events.reverse();
    events
}

/// `event` names of one request, in order.
fn of(events: &[Value], id: &str) -> Vec<String> {
    events.iter().filter(|e| e["ticketId"] == id).map(|e| e["event"].as_str().unwrap().to_owned()).collect()
}

fn find<'a>(events: &'a [Value], id: &str, event: &str) -> &'a Value {
    events.iter().find(|e| e["ticketId"] == id && e["event"] == event).unwrap_or_else(|| panic!("no {event} for {id}"))
}

#[tokio::test]
async fn every_request_decision_and_change_is_recorded_without_the_pin() {
    let f = ready().await;

    // An agent's single request, approved with a note.
    let one = mcp_fix(&f, "one").await;
    f.engine.decide_ticket(&one.ticket_id, true, PIN.into(), Some("  go ahead  ".into()), "browser").await.unwrap();
    assert_eq!(done(&f, &one.ticket_id).await.status, TicketStatus::Approved);

    // A plan whose second step fails.
    let plan = f.engine.propose_plan(PlanOrigin::Agent, json!({ "title": "Repair", "steps": [
        { "tool": "demo__fix", "args": { "note": "a" } },
        { "tool": "demo__fix", "args": { "note": "fail-b" } },
    ] })).await.unwrap();
    let hash = plan.plan.as_ref().unwrap().hash.clone();
    f.engine.decide(&plan.ticket_id, true, PIN.into(), None, "app", Some(&hash)).await.unwrap();
    assert_eq!(done(&f, &plan.ticket_id).await.status, TicketStatus::ExecutionFailed);

    // Declined, withdrawn, and locked out after wrong PINs.
    let declined = mcp_fix(&f, "no").await;
    f.engine.decide_ticket(&declined.ticket_id, false, PIN.into(), Some("not now".into()), "app").await.unwrap();
    let withdrawn = mcp_fix(&f, "later").await;
    f.engine.cancel_ticket(&withdrawn.ticket_id).unwrap();
    let guessed = mcp_fix(&f, "guess").await;
    for _ in 0..STRIKES_PER_TICKET {
        let _ = f.engine.decide_ticket(&guessed.ticket_id, true, "999999".into(), None, "browser").await;
    }
    assert_eq!(f.engine.ticket(&guessed.ticket_id).unwrap().status, TicketStatus::LockedOut);

    // The owner runs a change from the app with the PIN: no request, still recorded.
    f.engine.run_tool(Origin::Ui { pin: Some(PIN.into()) }, "demo", "fix", json!({ "note": "direct" })).await.unwrap();
    // A read-only call changes nothing and is not recorded.
    f.engine.run_tool(Origin::Mcp, "demo", "echo", json!({ "text": "hi" })).await.unwrap();

    let events = record(&f).await;
    assert_eq!(of(&events, &one.ticket_id), ["created", "decided", "change_started", "change_finished", "finished"]);
    let created = find(&events, &one.ticket_id, "created");
    assert_eq!((created["origin"].as_str(), created["tool"].as_str()), (Some("mcp"), Some("demo__fix")));
    assert_eq!(created["args"], json!({ "note": "one", "dryRun": false }));
    let decided = find(&events, &one.ticket_id, "decided");
    assert_eq!((decided["approved"].as_bool(), decided["via"].as_str(), decided["comment"].as_str()), (Some(true), Some("browser"), Some("go ahead")));
    assert_eq!(find(&events, &one.ticket_id, "change_finished")["outcome"], "succeeded");
    assert_eq!(find(&events, &one.ticket_id, "finished")["status"], "approved");

    assert_eq!(of(&events, &plan.ticket_id), ["created", "decided", "change_started", "change_finished", "change_started", "change_finished", "finished"]);
    let created = find(&events, &plan.ticket_id, "created");
    assert_eq!(created["origin"], "mcp plan");
    assert_eq!((created["plan"]["hash"].as_str(), created["plan"]["title"].as_str()), (Some(hash.as_str()), Some("Repair")));
    assert_eq!(created["plan"]["titleLabel"], "Supplied by the requesting agent", "the supplied title keeps its label");
    let steps: Vec<(u64, &str)> = events.iter().filter(|e| e["ticketId"] == plan.ticket_id.as_str() && e["event"] == "change_finished").map(|e| (e["step"].as_u64().unwrap(), e["outcome"].as_str().unwrap())).collect();
    assert_eq!(steps, [(1, "succeeded"), (2, "failed")]);
    let finished = find(&events, &plan.ticket_id, "finished");
    assert_eq!(finished["status"], "execution_failed");
    assert!(finished["reason"].as_str().unwrap().starts_with("Step 2 failed"), "{finished}");

    assert_eq!(of(&events, &declined.ticket_id), ["created", "decided"]);
    assert_eq!(find(&events, &declined.ticket_id, "decided")["approved"], false);
    assert_eq!(of(&events, &withdrawn.ticket_id), ["created", "cancelled"]);
    assert_eq!(find(&events, &withdrawn.ticket_id, "cancelled")["from"], "pending");
    assert_eq!(of(&events, &guessed.ticket_id), ["created", "decided"]);
    assert_eq!(find(&events, &guessed.ticket_id, "decided")["lockedOut"], true);

    let direct: Vec<&Value> = events.iter().filter(|e| e["ticketId"].is_null()).collect();
    assert_eq!(direct.len(), 2, "started and finished: {direct:?}");
    assert_eq!((direct[0]["event"].as_str(), direct[0]["origin"].as_str()), (Some("change_started"), Some("app (PIN)")));
    assert!(events.iter().all(|e| e["tool"] != "demo__echo"), "read-only calls are not changes");
    assert!(events.iter().all(|e| e["at"].is_string()), "the engine stamps every record");

    let text = serde_json::to_string(&events).unwrap();
    assert!(!text.contains(PIN) && !text.contains("999999"), "no PIN, right or wrong, is ever recorded");
    assert!(!text.to_lowercase().contains("csrf"));
}

#[tokio::test]
async fn reading_and_deleting_the_record_need_the_pin() {
    let f = ready().await;
    assert_eq!(f.engine.approval_record(PIN, 1).await.unwrap()["events"], json!([]), "empty before anything happened");
    let t = mcp_fix(&f, "x").await;
    f.engine.cancel_ticket(&t.ticket_id).unwrap();

    assert_eq!(f.engine.approval_record("000000", 1).await.unwrap_err().code, ErrorCode::PinInvalid);
    assert_eq!(f.engine.delete_approval_record("000000").await.unwrap_err().code, ErrorCode::PinInvalid);
    assert_eq!(record(&f).await.len(), 2);

    assert!(f.engine.delete_approval_record(PIN).await.unwrap() >= 1);
    let events = record(&f).await;
    assert_eq!(events.len(), 1, "deleted, leaving only the note that it was: {events:?}");
    assert_eq!(events[0]["event"], "purged");
    assert!(integrity(&f).await["ok"].as_bool().unwrap(), "a purge is an authorised gap");
    // Recording goes on, under the new key.
    let t = mcp_fix(&f, "y").await;
    assert_eq!(of(&record(&f).await, &t.ticket_id), ["created"]);

    f.engine.lock().await;
    assert_eq!(f.engine.approval_record(PIN, 1).await.unwrap_err().code, ErrorCode::VaultLocked);
}

#[tokio::test]
async fn locking_records_the_requests_it_forgets() {
    let f = ready().await;
    let pending = mcp_fix(&f, "pending").await;
    let running = mcp_fix(&f, "wait-running").await;
    f.engine.decide_ticket(&running.ticket_id, true, PIN.into(), None, "app").await.unwrap();
    until("it runs", || f.plugin.started.lock().unwrap().len() == 1).await;

    f.engine.lock().await;
    // The running change finishes while locked; its outcome is still written.
    f.plugin.release.add_permits(1);
    tokio::time::sleep(Duration::from_millis(100)).await;
    f.engine.unlock(PIN.into()).await.unwrap();

    let events = record(&f).await;
    assert_eq!(of(&events, &pending.ticket_id), ["created", "cancelled"]);
    assert_eq!(find(&events, &pending.ticket_id, "cancelled")["from"], "lock");
    assert_eq!(of(&events, &running.ticket_id), ["created", "decided", "change_started", "cancelled", "change_finished", "finished"]);
    assert_eq!(find(&events, &running.ticket_id, "change_finished")["outcome"], "succeeded");
    // Written by the run task from its own copy, after lock cleared the store (ADR 0004 §4.7).
    let finished = find(&events, &running.ticket_id, "finished");
    assert_eq!((finished["status"].as_str(), finished["afterLock"].as_bool()), (Some("approved"), Some(true)));
    assert!(integrity(&f).await["ok"].as_bool().unwrap(), "records written while locked carry valid MACs");
}

#[tokio::test]
async fn a_large_argument_is_recorded_by_size() {
    let f = ready().await;
    let t = mcp_fix(&f, &"n".repeat(5000)).await;
    let events = record(&f).await;
    let args = &find(&events, &t.ticket_id, "created")["args"];
    assert!(args["omitted"].as_str().unwrap().ends_with("bytes of arguments"), "{args}");
}

/// The integrity part of the record's view.
async fn integrity(f: &Fixture) -> Value {
    f.engine.approval_record(PIN, 90).await.unwrap()["integrity"].clone()
}

fn approvals_dir(f: &Fixture) -> std::path::PathBuf {
    f.engine.data_dir().join("history").join("approvals")
}

fn segment_files(f: &Fixture) -> Vec<std::path::PathBuf> {
    let mut files: Vec<_> = std::fs::read_dir(approvals_dir(f)).unwrap().map(|e| e.unwrap().path()).collect();
    files.sort();
    files
}

/// Locks and unlocks, which closes the record's file and checkpoints it.
async fn relock(f: &Fixture) {
    f.engine.lock().await;
    f.engine.unlock(PIN.into()).await.unwrap();
}

#[tokio::test]
async fn the_record_verifies_and_says_when_a_file_was_deleted() {
    let f = ready().await;
    for note in ["a", "b", "c"] {
        let t = mcp_fix(&f, note).await;
        f.engine.cancel_ticket(&t.ticket_id).unwrap();
        relock(&f).await;
    }
    let v = integrity(&f).await;
    assert_eq!(v["ok"], true, "{v}");
    assert!(v["line"].as_str().unwrap().starts_with("Verified: "), "{v}");
    let view = f.engine.approval_record(PIN, 1).await.unwrap();
    let events = view["events"].as_array().unwrap();
    assert!(events.iter().all(|e| e["seq"].is_u64() && e.get("prev").is_none() && e.get("mi").is_none()), "seq is shown, the chain's other fields are not");
    assert!(events.iter().all(|e| e["event"] != "open" && e["event"] != "close"), "file frames are not events");

    // A whole closed file deleted outside AegisWin: a gap in the middle.
    let files = segment_files(&f);
    assert_eq!(files.len(), 3, "{files:?}");
    std::fs::remove_file(&files[1]).unwrap();
    let v = integrity(&f).await;
    assert_eq!(v["ok"], false);
    let line = v["line"].as_str().unwrap();
    assert!(line.starts_with("Events ") && line.ends_with(" are missing (removed outside AegisWin)."), "{line}");

    // The finding is written into the record once, for later readers.
    let noted = |events: &[Value]| events.iter().filter(|e| e["event"] == "integrity").count();
    assert_eq!(noted(&record(&f).await), 1);
    assert_eq!(noted(&record(&f).await), 1, "not again on the next read");
}

#[tokio::test]
async fn cutting_the_record_short_after_the_last_checkpoint_shows() {
    let f = ready().await;
    let t = mcp_fix(&f, "a").await;
    f.engine.cancel_ticket(&t.ticket_id).unwrap();
    f.engine.lock().await;
    // While locked, the newest file goes: the vault's checkpoint still knows its last event.
    let files = segment_files(&f);
    std::fs::remove_file(files.last().unwrap()).unwrap();
    f.engine.unlock(PIN.into()).await.unwrap();
    let v = integrity(&f).await;
    let line = v["line"].as_str().unwrap();
    assert!(line.contains("missing") || line.contains("cut short"), "{line}");
    assert_eq!(v["ok"], false);
}

#[tokio::test]
async fn retention_records_what_it_removes() {
    let f = ready().await;
    let t = mcp_fix(&f, "old").await;
    f.engine.cancel_ticket(&t.ticket_id).unwrap();
    relock(&f).await;
    let t = mcp_fix(&f, "new").await;
    f.engine.cancel_ticket(&t.ticket_id).unwrap();
    // Make the first file 100 days old: its name carries its day.
    let first = segment_files(&f)[0].clone();
    let old_day = (Utc::now().date_naive() - chrono::Days::new(100)).format("%Y%m%d");
    std::fs::rename(&first, approvals_dir(&f).join(format!("seg-{old_day}-001.bin"))).unwrap();

    let kept = f.engine.set_approval_retention(PIN, 30).await.unwrap();
    assert_eq!(kept.max_days, 30);
    assert_eq!(f.engine.set_approval_retention("000000", 30).await.unwrap_err().code, ErrorCode::PinInvalid);
    assert_eq!(f.engine.set_approval_retention(PIN, 0).await.unwrap_err().code, ErrorCode::InvalidArguments);
    assert!(!segment_files(&f).iter().any(|p| p.to_string_lossy().contains(&old_day.to_string())), "the old file is gone");
    let events = record(&f).await;
    let pruned = events.iter().find(|e| e["event"] == "pruned").expect("a pruned record");
    assert!(pruned["to"].as_u64().unwrap() >= 2 && pruned["lastHash"].is_string(), "{pruned}");
    let v = integrity(&f).await;
    assert_eq!(v["ok"], true, "a gap retention recorded is not tampering: {v}");
    assert_eq!(f.engine.approval_record(PIN, 1).await.unwrap()["retention"]["maxDays"], 30);
}

#[tokio::test]
async fn a_record_that_cannot_be_written_fails_closed_for_changes() {
    let f = ready().await;
    let waiting = mcp_fix(&f, "held").await;
    let other = mcp_fix(&f, "other").await;

    // Full for new requests: agents are refused, and the app says why.
    f.engine.set_approval_record_limits(0, u64::MAX);
    let err = f.engine.run_tool(Origin::Mcp, "demo", "fix", json!({ "note": "x" })).await.unwrap_err();
    assert_eq!(err.message, "The approval record is full. Open AegisWin.");
    assert!(f.engine.status().approval_record_full);
    assert_eq!(f.engine.list_tickets().len(), 2, "the refused request is not kept");

    // Nothing can be written now.
    f.engine.set_approval_record_limits(0, 0);
    let err = f.engine.decide_ticket(&waiting.ticket_id, true, PIN.into(), None, "app").await.unwrap_err();
    assert!(err.message.contains("approval record"), "{err:?}");
    assert_eq!(f.engine.ticket(&waiting.ticket_id).unwrap().status, TicketStatus::PendingApproval, "an approval not recorded is not applied");
    let err = f.engine.run_tool(Origin::Ui { pin: Some(PIN.into()) }, "demo", "fix", json!({ "note": "direct" })).await.unwrap_err();
    assert!(err.message.contains("did not run"), "{err:?}");
    assert!(f.plugin.started.lock().unwrap().is_empty(), "the change did not run");
    // A decline still happens, and waits in memory to be written.
    f.engine.decide_ticket(&other.ticket_id, false, PIN.into(), None, "app").await.unwrap();
    assert_eq!(f.engine.ticket(&other.ticket_id).unwrap().status, TicketStatus::Declined);
    assert_eq!(f.engine.status().unwritten_records, 1);

    // Writable again: the held event goes in first.
    f.engine.set_approval_record_limits(u64::MAX, u64::MAX);
    f.engine.cancel_ticket(&waiting.ticket_id).unwrap();
    assert_eq!(f.engine.status().unwritten_records, 0);
    let events = record(&f).await;
    assert_eq!(of(&events, &other.ticket_id), ["created", "decided"]);
    assert_eq!(of(&events, &waiting.ticket_id), ["created", "cancelled"]);
    assert!(integrity(&f).await["ok"].as_bool().unwrap());
}

fn t(h: u32, m: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 8, h, m, 0).unwrap()
}

fn rec(h: u32, m: u32, event: &str, tool: &str) -> Value {
    json!({ "at": t(h, m).to_rfc3339(), "event": event, "tool": "demo__fix", "toolName": tool })
}

#[test]
fn changes_become_windows_and_an_unfinished_one_is_bounded() {
    let records = [
        rec(9, 0, "created", "x"),
        rec(9, 1, "change_started", "Fix A"),
        rec(9, 3, "change_finished", "Fix A"),
        // AegisWin quit mid-change: it lasts until the next start.
        rec(10, 0, "change_started", "Fix B"),
        rec(10, 30, "change_started", "Fix C"),
        rec(10, 31, "change_finished", "Fix C"),
        // Never finished: at most two hours.
        rec(11, 0, "change_started", "Fix D"),
        // A finish without a start is ignored.
        rec(9, 0, "change_finished", "stray"),
    ];
    let w = |from: DateTime<Utc>, to: DateTime<Utc>, tool: &str| ChangeWindow { from, to, tool: tool.into() };
    // The stray finish sorts before anything started, so it closes nothing.
    assert_eq!(
        change_windows(&records),
        [w(t(9, 1), t(9, 3), "Fix A"), w(t(10, 0), t(10, 30), "Fix B"), w(t(10, 30), t(10, 31), "Fix C"), w(t(11, 0), t(11, 0) + OPEN_CHANGE_LIMIT, "Fix D")]
    );
}
