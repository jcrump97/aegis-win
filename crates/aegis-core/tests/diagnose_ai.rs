//! The AI summary and suggested plan (ADR 0005 §5): what is sent, and what
//! code keeps of the reply. The AI may only pick fixes code linked to the
//! same finding.

use aegis_core::diagnose::ai::{self, NONE_MATCHED};
use aegis_core::diagnose::{Evidence, NextStep, Report, ReportFinding, Severity};
use serde_json::{json, Value};

fn tool(tool: &str, args: Value, available: bool) -> NextStep {
    NextStep::Tool {
        tool: tool.into(),
        mcp_name: tool.replace(':', "__"),
        name: format!("Run {tool}"),
        args,
        why: "Because.".into(),
        available,
        reason: None,
    }
}

fn finding(id: &str, severity: Severity, next: Vec<NextStep>) -> ReportFinding {
    ReportFinding {
        id: id.into(),
        check: "p.c".into(),
        severity,
        title: format!("{id} happened"),
        detail: "It stopped.".into(),
        count: 2,
        count_is_minimum: false,
        first_seen: None,
        last_seen: None,
        evidence: (0..3)
            .map(|i| Evidence { source: "System".into(), provider: None, event_id: Some(41), record_id: None, time: None, message: format!("{i}{}", "m".repeat(200)) })
            .collect(),
        next,
    }
}

fn report() -> Report {
    Report {
        ran_at: chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
        lookback_days: 7,
        elevated: false,
        checks: vec![],
        findings: vec![
            finding(
                "p.c:disk",
                Severity::Critical,
                vec![
                    tool("p:repair", json!({ "drive": "C", "dryRun": false }), true),
                    tool("p:admin_fix", json!({}), false),
                    NextStep::Manual { text: "Back up your files.".into() },
                ],
            ),
            finding("p.c:dns", Severity::Warning, vec![tool("p:flush", json!({ "dryRun": false }), true)]),
            finding("p.c:app", Severity::Info, vec![]),
        ],
    }
}

fn schema_of(id: &str) -> Option<Value> {
    let dry = json!({ "type": "boolean", "default": false });
    match id {
        "p:repair" => Some(json!({ "type": "object", "additionalProperties": false, "properties": { "dryRun": dry, "drive": { "type": "string", "enum": ["C", "D"] } } })),
        "p:flush" | "p:admin_fix" => Some(json!({ "type": "object", "properties": { "dryRun": dry } })),
        _ => None,
    }
}

fn check(reply: Value) -> Result<ai::Checked, String> {
    ai::check(&reply.to_string(), &report(), &schema_of)
}

#[test]
fn the_payload_has_the_findings_and_only_the_fixes_that_can_run() {
    let v = ai::payload(&report(), 100_000).unwrap();
    let disk = &v["findings"][0];
    assert_eq!(disk["id"], "p.c:disk");
    assert_eq!(disk["evidence"].as_array().unwrap().len(), 3);
    assert_eq!(disk["fixes"], json!([{ "tool": "p__repair", "name": "Run p:repair", "args": { "drive": "C", "dryRun": false }, "why": "Because." }]), "not the unavailable one");
    assert_eq!(disk["manualSteps"], json!(["Back up your files."]));
    assert!(v.get("omitted").is_none());
}

#[test]
fn the_payload_cuts_evidence_first_then_the_least_serious_findings() {
    let size = |v: &Value| v.to_string().chars().count();
    let full = ai::payload(&report(), 100_000).unwrap();
    let one = ai::payload(&report(), size(&full) - 1).unwrap();
    assert!(one["findings"].as_array().unwrap().iter().all(|f| f["evidence"].as_array().unwrap().len() == 1));
    assert_eq!(one["findings"].as_array().unwrap().len(), 3);
    let none = ai::payload(&report(), size(&one) - 1).unwrap();
    assert!(none["findings"].as_array().unwrap().iter().all(|f| f.get("evidence").is_none()));
    let fewer = ai::payload(&report(), size(&none) - 1).unwrap();
    assert_eq!(fewer["findings"].as_array().unwrap().len(), 2);
    assert_eq!(fewer["omitted"], 1);
    assert_eq!(fewer["findings"][1]["id"], "p.c:dns", "the least serious goes first");
    assert!(ai::payload(&report(), 50).is_none());
}

#[test]
fn a_matching_reply_is_kept_in_the_ais_order() {
    let c = check(json!({
        "summary": "The disk\u{202E} is failing.",
        "order": ["p.c:dns", "p.c:disk"],
        "steps": [
            { "findingId": "p.c:disk", "tool": "p__repair", "args": { "drive": "D" }, "reasoning": "Repair the  disk." },
            { "findingId": "p.c:dns", "tool": "p:flush" }
        ]
    }))
    .unwrap();
    assert_eq!(c.summary.as_deref(), Some("The disk is failing."), "hidden characters removed");
    assert_eq!(c.order, ["p.c:dns", "p.c:disk", "p.c:app"], "the rest follow in code's order");
    assert_eq!(c.steps.len(), 2);
    assert_eq!((c.steps[0].tool.as_str(), c.steps[0].mcp_name.as_str()), ("p:repair", "p__repair"));
    assert_eq!(c.steps[0].args, json!({ "drive": "D", "dryRun": false }), "checked against the schema, defaults filled in");
    assert_eq!(c.steps[0].reasoning.as_deref(), Some("Repair the disk."));
    assert_eq!(c.steps[1].args, json!({ "dryRun": false }), "no args: the ones code chose");
    assert_eq!((c.dropped, c.notice), (0, None));
}

#[test]
fn steps_code_did_not_link_to_that_finding_are_dropped() {
    let c = check(json!({
        "summary": "s",
        "steps": [
            { "findingId": "p.c:dns", "tool": "p__flush" },
            // The same step twice is kept once, and not counted as dropped.
            { "findingId": "p.c:dns", "tool": "p__flush", "args": {} },
            // Another finding's fix.
            { "findingId": "p.c:dns", "tool": "p__repair" },
            // A fix that cannot run now.
            { "findingId": "p.c:disk", "tool": "p__admin_fix" },
            // Invented.
            { "findingId": "p.c:disk", "tool": "windows-health__winsock_reset" }
        ]
    }))
    .unwrap();
    assert_eq!(c.steps.iter().map(|s| s.tool.as_str()).collect::<Vec<_>>(), ["p:flush"]);
    assert_eq!(c.dropped, 3);
    assert!(c.notice.unwrap().starts_with("3 of the AI's suggestions"));
    assert_eq!(c.summary.as_deref(), Some("s"));

    let c = check(json!({
        "summary": "s",
        "steps": [
            { "findingId": "nope", "tool": "p__flush" },
            // Arguments the schema refuses.
            { "findingId": "p.c:disk", "tool": "p__repair", "args": { "drive": "Z" } },
            { "findingId": "p.c:disk", "tool": "p__repair", "args": "C" },
            // A dry run cannot be a plan step.
            { "findingId": "p.c:dns", "tool": "p__flush", "args": { "dryRun": true } }
        ]
    }))
    .unwrap();
    assert!(c.steps.is_empty());
    assert_eq!((c.summary, c.notice.as_deref()), (None, Some(NONE_MATCHED)));
}

#[test]
fn when_nothing_matches_the_summary_is_not_shown_either() {
    let c = check(json!({ "summary": "Run winsock reset.", "order": ["x"], "steps": [{ "findingId": "x", "tool": "y" }] })).unwrap();
    assert_eq!(c.summary, None);
    assert_eq!(c.notice.as_deref(), Some(NONE_MATCHED));
    assert!(c.steps.is_empty());
    assert_eq!(c.order, ["p.c:disk", "p.c:dns", "p.c:app"]);
    // A summary with no suggestions at all is fine.
    let c = check(json!({ "summary": "Nothing urgent." })).unwrap();
    assert_eq!((c.summary.as_deref(), c.notice), (Some("Nothing urgent."), None));
}

#[test]
fn at_most_five_steps_and_limited_text() {
    let steps: Vec<Value> = (0..7).map(|i| json!({ "findingId": "p.c:disk", "tool": "p__repair", "args": { "drive": if i % 2 == 0 { "C" } else { "D" } } })).collect();
    let c = check(json!({ "summary": "x".repeat(900), "steps": steps })).unwrap();
    assert_eq!(c.dropped, 2, "steps six and seven");
    assert_eq!(c.steps.len(), 2, "the rest repeat the first two");
    assert_eq!(c.summary.unwrap().chars().count(), ai::MAX_SUMMARY_CHARS);
    let long = check(json!({ "summary": "s", "steps": [{ "findingId": "p.c:dns", "tool": "p__flush", "reasoning": "r".repeat(500) }] })).unwrap();
    assert_eq!(long.steps[0].reasoning.as_ref().unwrap().chars().count(), ai::MAX_STEP_REASONING_CHARS);
}

#[test]
fn replies_in_the_wrong_format_are_refused() {
    for (reply, why) in [
        ("I think the disk is failing.", "not a JSON object"),
        ("{\"summary\": \"s\", \"plan\": []}", "unknown field 'plan'"),
        ("{\"order\": []}", "needs a 'summary'"),
        ("{\"summary\": \"  \"}", "empty"),
        ("{\"summary\": \"s\", \"steps\": {}}", "must be a list"),
        ("{\"summary\": \"s\", \"steps\": [{\"findingId\": \"p.c:dns\", \"tool\": \"p__flush\", \"run\": true}]}", "step 1 has an unknown field 'run'"),
    ] {
        let err = ai::check(reply, &report(), &schema_of).unwrap_err();
        assert!(err.contains(why), "{reply}: {err}");
    }
    // A fenced block is fine.
    assert!(ai::check("```json\n{\"summary\": \"s\"}\n```", &report(), &schema_of).is_ok());
}
