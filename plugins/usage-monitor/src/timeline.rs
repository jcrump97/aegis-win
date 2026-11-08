//! The monitor history view (ADR 0002 §5, §7): turns the decrypted records
//! into a timeline and works out where monitoring stopped and why.
//!
//! Gaps are computed when history is read, from the records alone; the
//! System event log then adds evidence (sleep, a requested shutdown, an
//! unexpected one). Values are never filled in across a gap.

use aegis_core::history::{FileStatus, StreamRead};
use aegis_core::history_service::ChangeWindow;
use aegis_core::os::eventlog::{EventQuery, EventRecord};
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use serde_json::{json, Value};

/// One heartbeat a minute; a longer silence inside a session is a gap.
pub const HEARTBEAT_SECONDS: u64 = 60;
const SLEEP_GAP: Duration = Duration::minutes(2);
/// How far around a gap a System event still counts as its evidence.
const EVIDENCE_SLACK: Duration = Duration::minutes(2);
pub const MAX_DAYS: u32 = 90;
pub const DEFAULT_LIMIT: usize = 500;
/// Most events one read returns (the manifest's `limit` maximum).
pub const MAX_LIMIT: usize = 2000;
const MESSAGE_CHARS: usize = 300;

/// Why monitoring stopped, as written in `session_stop` records.
pub const STOP_LOCKED: &str = "monitoring stopped";
pub const STOP_QUIT: &str = "quit";
pub const STOP_SHUTDOWN: &str = "shutdown";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GapKind {
    /// Silence inside a session: sleep or hibernate, or a frozen PC.
    Sleep,
    /// A `session_stop`, then a new `session_start`.
    Stopped,
    /// A new `session_start` with no `session_stop` before it.
    Unexpected,
    /// `paused` until `resumed` (or until now).
    Paused,
}

impl GapKind {
    /// System log events that explain this kind of gap: (provider, event id).
    fn evidence_ids(self) -> &'static [(&'static str, u32)] {
        match self {
            Self::Sleep => &[("Kernel-Power", 42), ("Kernel-Power", 107)],
            Self::Stopped => &[("User32", 1074)],
            Self::Unexpected => &[("Kernel-Power", 41), ("EventLog", 6008)],
            Self::Paused => &[],
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub time: String,
    pub event_id: u32,
    pub provider: String,
    pub meaning: &'static str,
    /// The event's own text, shortened. Only kept for 1074 (who asked for the shutdown).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Gap {
    pub kind: GapKind,
    pub from: String,
    /// `None` while still paused.
    pub to: Option<String>,
    /// Plain sentence for the owner.
    pub label: String,
    pub evidence: Vec<Evidence>,
}

fn at(record: &Value) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(record.get("at")?.as_str()?).ok().map(|t| t.with_timezone(&Utc))
}

fn kind(record: &Value) -> &str {
    record.get("kind").and_then(Value::as_str).unwrap_or("")
}

fn stamp(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn stop_label(reason: &str) -> String {
    match reason {
        STOP_QUIT => "Not monitoring: AegisWin was closed.".into(),
        STOP_SHUTDOWN => "Not monitoring: Windows shut down, restarted, or signed out.".into(),
        STOP_LOCKED => "Not monitoring: monitoring was stopped (AegisWin locked, or its monitoring settings changed).".into(),
        _ => "Not monitoring: monitoring was stopped.".into(),
    }
}

/// Records in time order, each with its parsed time. Records without a
/// readable time are left out (they cannot be placed on a timeline).
pub fn ordered(records: &[Value]) -> Vec<(DateTime<Utc>, &Value)> {
    let mut out: Vec<(DateTime<Utc>, &Value)> = records.iter().filter_map(|r| Some((at(r)?, r))).collect();
    out.sort_by_key(|(t, _)| *t);
    out
}

/// Where monitoring was not running (ADR 0002 §7).
pub fn gaps(records: &[(DateTime<Utc>, &Value)]) -> Vec<Gap> {
    let mut out = Vec::new();
    let mut last: Option<DateTime<Utc>> = None;
    let mut stopped: Option<(DateTime<Utc>, String)> = None;
    let mut paused: Option<DateTime<Utc>> = None;
    let gap = |kind, from, to: Option<DateTime<Utc>>, label: String| Gap { kind, from: stamp(from), to: to.map(stamp), label, evidence: Vec::new() };
    for &(t, record) in records {
        match kind(record) {
            "session_start" => {
                if let Some(p) = paused.take() {
                    out.push(gap(GapKind::Paused, p, Some(stopped.as_ref().map_or(t, |(s, _)| *s)), "Paused by you.".into()));
                }
                match stopped.take() {
                    Some((from, reason)) => out.push(gap(GapKind::Stopped, from, Some(t), stop_label(&reason))),
                    None => {
                        if let Some(from) = last {
                            out.push(gap(GapKind::Unexpected, from, Some(t), "Not monitoring: AegisWin stopped without closing (a crash, power loss, or forced shutdown).".into()));
                        }
                    }
                }
            }
            other => {
                if let (Some(from), None, None) = (last, &stopped, paused) {
                    if t - from > SLEEP_GAP {
                        out.push(gap(GapKind::Sleep, from, Some(t), "Not monitoring: the PC was asleep, hibernating, or not responding.".into()));
                    }
                }
                match other {
                    "session_stop" => {
                        let reason = record.get("reason").and_then(Value::as_str).unwrap_or_default().to_owned();
                        stopped = Some((t, reason));
                    }
                    "paused" if paused.is_none() => paused = Some(t),
                    "resumed" => {
                        if let Some(p) = paused.take() {
                            out.push(gap(GapKind::Paused, p, Some(t), "Paused by you.".into()));
                        }
                    }
                    _ => {}
                }
            }
        }
        last = Some(t);
    }
    if let Some(p) = paused {
        let to = stopped.map(|(s, _)| s);
        out.push(gap(GapKind::Paused, p, to, "Paused by you.".into()));
    }
    out
}

/// The stop (or unexpected end) just before the latest `session_start`:
/// what a resume at launch reports after unlock. `None` for the first
/// session in the history.
pub fn gap_before_last_start(records: &[(DateTime<Utc>, &Value)]) -> Option<Gap> {
    let (start, _) = records.iter().rev().find(|(_, r)| kind(r) == "session_start")?;
    let to = stamp(*start);
    gaps(records).into_iter().rev().find(|g| matches!(g.kind, GapKind::Stopped | GapKind::Unexpected) && g.to.as_deref() == Some(to.as_str()))
}

/// The System log query that finds evidence for gaps over `days` days.
pub fn evidence_query(days: u32) -> EventQuery {
    EventQuery {
        channel: "System".into(),
        event_ids: vec![41, 42, 107, 1074, 6008],
        lookback_hours: Some(days.saturating_add(1).saturating_mul(24)),
        limit: 500,
        ..Default::default()
    }
}

fn meaning(event_id: u32) -> &'static str {
    match event_id {
        41 => "Windows restarted without shutting down cleanly (Kernel-Power 41).",
        42 => "Windows went to sleep (Kernel-Power 42).",
        107 => "Windows woke from sleep (Kernel-Power 107).",
        1074 => "A shutdown or restart was requested (User32 1074).",
        6008 => "The previous shutdown was unexpected (EventLog 6008).",
        _ => "",
    }
}

/// Attaches the System events that fall inside each gap (with a little slack).
pub fn attach_evidence(gaps: &mut [Gap], events: &[EventRecord], now: DateTime<Utc>) {
    let parsed: Vec<(DateTime<Utc>, &EventRecord)> =
        events.iter().filter_map(|e| Some((DateTime::parse_from_rfc3339(&e.time_created).ok()?.with_timezone(&Utc), e))).collect();
    for gap in gaps {
        let (Some(from), to) = (DateTime::parse_from_rfc3339(&gap.from).ok(), gap.to.as_deref().and_then(|t| DateTime::parse_from_rfc3339(t).ok())) else {
            continue;
        };
        let (from, to) = (from.with_timezone(&Utc) - EVIDENCE_SLACK, to.map_or(now, |t| t.with_timezone(&Utc)) + EVIDENCE_SLACK);
        let wanted = gap.kind.evidence_ids();
        let mut found: Vec<&(DateTime<Utc>, &EventRecord)> = parsed
            .iter()
            .filter(|(t, e)| *t >= from && *t <= to && wanted.iter().any(|(p, id)| *id == e.event_id && e.provider.contains(p)))
            .collect();
        found.sort_by_key(|(t, _)| *t);
        gap.evidence = found
            .into_iter()
            .map(|(t, e)| Evidence {
                time: stamp(*t),
                event_id: e.event_id,
                provider: e.provider.clone(),
                meaning: meaning(e.event_id),
                message: (e.event_id == 1074).then(|| e.message.as_deref().unwrap_or_default().chars().take(MESSAGE_CHARS).collect()),
            })
            .collect();
    }
}

fn file_problem(name: &str, status: FileStatus) -> Option<String> {
    Some(match status {
        FileStatus::Ok => return None,
        FileStatus::Truncated => format!("{name}: the last record was cut off (power loss or a crash while writing); everything before it was read."),
        FileStatus::Corrupt => format!("{name}: damaged in the middle; records after the damage could not be read."),
        FileStatus::OtherKey => format!("{name}: written with a different key (from before a purge, or not by this AegisWin); it cannot be read."),
        FileStatus::Unreadable => format!("{name}: not a readable history file."),
    })
}

/// The history view: events (heartbeats left out), gaps with evidence,
/// and any file problems. Keeps the newest `limit` events.
/// `repairs`: when AegisWin itself was changing the system (from the
/// engine's approval record); events inside one are labelled `duringRepair`.
pub fn view(read: &StreamRead, events: &[EventRecord], repairs: &[ChangeWindow], since: DateTime<Utc>, now: DateTime<Utc>, limit: usize) -> Value {
    let ordered: Vec<(DateTime<Utc>, &Value)> = ordered(&read.records).into_iter().filter(|(t, _)| *t >= since).collect();
    let mut gaps = gaps(&ordered);
    attach_evidence(&mut gaps, events, now);
    let shown: Vec<Value> = ordered
        .iter()
        .filter(|(_, r)| kind(r) != "heartbeat")
        .map(|(t, r)| {
            let mut r = (*r).clone();
            if let Some(w) = repairs.iter().find(|w| w.from <= *t && *t <= w.to) {
                r["duringRepair"] = json!(w.tool);
            }
            r
        })
        .collect();
    let omitted = shown.len().saturating_sub(limit);
    json!({
        "from": stamp(since),
        "to": stamp(now),
        "events": &shown[omitted..],
        "omitted": omitted,
        "gaps": gaps,
        "files": read.files,
        "problems": read.files.iter().filter_map(|f| file_problem(&f.name, f.status)).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn t(h: u32, m: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 8, h, m, 0).unwrap()
    }

    fn rec(h: u32, m: u32, kind: &str) -> Value {
        json!({ "at": t(h, m).to_rfc3339(), "kind": kind })
    }

    fn stop(h: u32, m: u32, reason: &str) -> Value {
        json!({ "at": t(h, m).to_rfc3339(), "kind": "session_stop", "reason": reason })
    }

    fn found(records: &[Value]) -> Vec<(GapKind, String, Option<String>)> {
        gaps(&ordered(records)).into_iter().map(|g| (g.kind, g.from, g.to)).collect()
    }

    fn s(h: u32, m: u32) -> String {
        stamp(t(h, m))
    }

    #[test]
    fn the_gap_before_a_resume_is_the_one_ending_at_the_latest_start() {
        let first = [rec(8, 0, "session_start"), rec(8, 1, "heartbeat")];
        assert!(gap_before_last_start(&ordered(&first)).is_none(), "the first session has nothing before it");

        let quit = [rec(8, 0, "session_start"), stop(9, 0, STOP_QUIT), rec(10, 0, "session_start"), stop(11, 0, STOP_SHUTDOWN), rec(12, 0, "session_start"), rec(12, 1, "heartbeat")];
        let gap = gap_before_last_start(&ordered(&quit)).unwrap();
        assert_eq!((gap.kind, gap.from, gap.to), (GapKind::Stopped, s(11, 0), Some(s(12, 0))));

        let crashed = [rec(8, 0, "session_start"), rec(8, 1, "heartbeat"), rec(9, 0, "session_start")];
        assert_eq!(gap_before_last_start(&ordered(&crashed)).unwrap().kind, GapKind::Unexpected);
    }

    #[test]
    fn steady_heartbeats_have_no_gap() {
        let records = [rec(10, 0, "session_start"), rec(10, 1, "heartbeat"), rec(10, 2, "heartbeat"), rec(10, 3, "spike")];
        assert!(found(&records).is_empty());
    }

    #[test]
    fn silence_inside_a_session_is_sleep() {
        let records = [rec(10, 0, "session_start"), rec(10, 1, "heartbeat"), rec(11, 30, "heartbeat")];
        assert_eq!(found(&records), [(GapKind::Sleep, s(10, 1), Some(s(11, 30)))]);
    }

    #[test]
    fn a_clean_stop_and_a_crash_are_told_apart() {
        let records = [
            rec(9, 0, "session_start"),
            stop(9, 1, STOP_QUIT),
            rec(9, 40, "session_start"),
            rec(9, 41, "heartbeat"),
            rec(10, 20, "session_start"),
        ];
        let gaps = gaps(&ordered(&records));
        assert_eq!(gaps.iter().map(|g| (g.kind, g.from.clone(), g.to.clone())).collect::<Vec<_>>(), [
            (GapKind::Stopped, s(9, 1), Some(s(9, 40))),
            (GapKind::Unexpected, s(9, 41), Some(s(10, 20))),
        ]);
        assert!(gaps[0].label.contains("closed"));
        assert!(gaps[1].label.contains("crash"));
    }

    #[test]
    fn a_pause_is_its_own_gap_and_hides_the_silence_inside_it() {
        let records = [rec(10, 0, "session_start"), rec(10, 1, "paused"), rec(12, 0, "resumed"), rec(12, 1, "heartbeat")];
        assert_eq!(found(&records), [(GapKind::Paused, s(10, 1), Some(s(12, 0)))]);
        let still = [rec(10, 0, "session_start"), rec(10, 1, "paused")];
        assert_eq!(found(&still), [(GapKind::Paused, s(10, 1), None)], "a pause still running is open-ended");
    }

    #[test]
    fn records_out_of_order_or_without_a_time_are_handled() {
        let records = [rec(10, 1, "heartbeat"), json!({ "kind": "heartbeat" }), rec(10, 0, "session_start"), rec(10, 2, "heartbeat")];
        assert!(found(&records).is_empty());
    }

    fn event(time: DateTime<Utc>, provider: &str, id: u32, message: &str) -> EventRecord {
        EventRecord {
            record_id: 1,
            time_created: time.to_rfc3339(),
            provider: provider.into(),
            event_id: id,
            level: 4,
            level_name: "Information",
            message: Some(message.into()),
        }
    }

    #[test]
    fn system_events_are_attached_to_the_gap_they_explain() {
        let records = [rec(9, 0, "session_start"), rec(9, 1, "heartbeat"), rec(10, 0, "heartbeat"), stop(10, 1, STOP_SHUTDOWN), rec(11, 0, "session_start")];
        let mut g = gaps(&ordered(&records));
        let events = [
            event(t(9, 2), "Microsoft-Windows-Kernel-Power", 42, "sleep"),
            event(t(9, 59), "Microsoft-Windows-Kernel-Power", 107, "wake"),
            event(t(10, 4), "User32", 1074, "The process C:\\Windows\\System32\\shutdown.exe has initiated the restart"),
            event(t(10, 30), "Microsoft-Windows-Kernel-Power", 41, "not in a crash gap"),
            event(t(9, 30), "Some-Other-Provider", 42, "wrong provider"),
        ];
        attach_evidence(&mut g, &events, t(12, 0));
        assert_eq!(g.len(), 2);
        assert_eq!(g[0].evidence.iter().map(|e| e.event_id).collect::<Vec<_>>(), [42, 107]);
        assert!(g[0].evidence.iter().all(|e| e.message.is_none()), "only 1074 keeps its text");
        assert_eq!(g[1].kind, GapKind::Stopped);
        assert_eq!(g[1].evidence.iter().map(|e| e.event_id).collect::<Vec<_>>(), [1074]);
        assert!(g[1].evidence[0].message.as_deref().unwrap().contains("shutdown.exe"));
    }

    #[test]
    fn the_view_drops_heartbeats_keeps_the_newest_and_explains_bad_files() {
        let mut records = vec![rec(10, 0, "session_start")];
        records.extend((1..=5).map(|m| rec(10, m, "heartbeat")));
        records.extend((6..=9).map(|m| rec(10, m, "spike")));
        let read = StreamRead {
            records,
            files: vec![aegis_core::history::FileReport { name: "seg-20261108-001.bin".into(), status: FileStatus::Truncated, records: 10, bytes: 1 }],
        };
        let v = view(&read, &[], &[], t(0, 0), t(12, 0), 3);
        assert_eq!(v["events"].as_array().unwrap().iter().map(|e| e["at"].as_str().unwrap().to_owned()).collect::<Vec<_>>(), [
            t(10, 7).to_rfc3339(),
            t(10, 8).to_rfc3339(),
            t(10, 9).to_rfc3339()
        ]);
        assert_eq!(v["omitted"], 2);
        assert!(v["problems"][0].as_str().unwrap().contains("cut off"));
        let later = view(&read, &[], &[], t(10, 8), t(12, 0), 10);
        assert_eq!(later["events"].as_array().unwrap().len(), 2, "records before `since` are left out");
    }

    #[test]
    fn events_during_an_aegiswin_repair_are_labelled() {
        let read = StreamRead { records: vec![rec(10, 0, "spike"), rec(10, 5, "spike"), rec(10, 10, "monitor_hit")], files: vec![] };
        let repairs = [ChangeWindow { from: t(10, 4), to: t(10, 10), tool: "Reset network".into() }];
        let v = view(&read, &[], &repairs, t(0, 0), t(12, 0), 10);
        let labels: Vec<Option<&str>> = v["events"].as_array().unwrap().iter().map(|e| e["duringRepair"].as_str()).collect();
        assert_eq!(labels, [None, Some("Reset network"), Some("Reset network")], "inclusive at both ends");
    }
}
