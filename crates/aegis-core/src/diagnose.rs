//! Diagnose this PC ([ADR 0005](../../../documentation/adr/0005-diagnose-this-pc.md)):
//! the finding model plugins return from [`Plugin::run_checks`](crate::registry::Plugin::run_checks),
//! and the checks the engine applies before anyone sees a finding.
//!
//! The rule: code finds, code describes, the AI ranks and explains, the
//! owner approves with the PIN. Plugin code writes every field of a finding
//! except evidence messages, which come from Windows and are untrusted text.
//! Next steps are limited here, by the engine, to the tools a check declares
//! in its manifest (`nextTools`), whatever the check's code returns.

pub mod ai;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::registry::{mcp_tool_name, PluginManifest, Registry};
use crate::schema::{self, is_hidden_char};

/// Lookback choices the app offers; anything else is refused.
pub const LOOKBACK_DAYS: [u32; 3] = [1, 7, 30];
pub const DEFAULT_LOOKBACK_DAYS: u32 = 7;
/// One plugin's checks may take this long before they are reported as failed.
pub const PLUGIN_TIME_LIMIT: std::time::Duration = std::time::Duration::from_secs(20);
/// A check reads at most this many events per query (ADR 0005 §1).
pub const MAX_EVENTS_PER_QUERY: usize = 500;
pub const MAX_EVIDENCE: usize = 5;
pub const MAX_EVIDENCE_MESSAGE_CHARS: usize = 300;
pub const MAX_TITLE_CHARS: usize = 160;
pub const MAX_DETAIL_CHARS: usize = 600;
pub const MAX_WHY_CHARS: usize = 300;
pub const MAX_FINDINGS_PER_CHECK: usize = 20;
pub const MAX_NEXT_STEPS: usize = 4;
pub const MAX_KEY_CHARS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

/// What a plugin's check reads, given by the engine. It has no store,
/// history, or LLM handle on purpose: checks cannot write, record, or call
/// an LLM (ADR 0005 §2).
#[derive(Debug, Clone)]
pub struct CheckContext {
    pub lookback_days: u32,
    pub enabled_components: Vec<String>,
    pub elevated: bool,
    /// The time the run started, so every check measures from the same moment.
    pub now: DateTime<Utc>,
}

impl CheckContext {
    pub fn component_enabled(&self, id: &str) -> bool {
        self.enabled_components.iter().any(|c| c == id)
    }

    pub fn since(&self) -> DateTime<Utc> {
        self.now - chrono::Duration::days(i64::from(self.lookback_days))
    }
}

/// One record behind a finding. `message` is Windows text: untrusted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time: Option<DateTime<Utc>>,
    pub message: String,
}

/// A next step as a check writes it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Next {
    /// A tool, as `plugin:tool`, with the arguments to run it with.
    Tool { tool: String, args: Value, why: String },
    /// Something the owner can check or do themselves.
    Manual { text: String },
}

/// A finding as a check writes it. The engine adds the id and checks the rest.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    /// Tells findings of one check apart (a program, a service). `None` for
    /// a check that reports at most one finding.
    pub key: Option<String>,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub count: u64,
    /// The read hit [`MAX_EVENTS_PER_QUERY`]: `count` is "at least".
    pub count_is_minimum: bool,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub evidence: Vec<Evidence>,
    pub next: Vec<Next>,
}

/// How one check went, as a plugin reports it.
#[derive(Debug, Clone, PartialEq)]
pub enum CheckOutcome {
    /// It ran. No findings means it found nothing wrong.
    Ran(Vec<Finding>),
    /// It could not run here, for a reason the owner can act on (needs
    /// administrator rights, a component is off).
    Skipped(String),
    /// It tried and failed.
    Failed(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct CheckResult {
    /// The check's id in the plugin's manifest (`checks[].id`).
    pub check: String,
    pub outcome: CheckOutcome,
}

impl CheckResult {
    pub fn ran(check: &str, findings: Vec<Finding>) -> Self {
        Self { check: check.to_owned(), outcome: CheckOutcome::Ran(findings) }
    }
    pub fn skipped(check: &str, reason: impl Into<String>) -> Self {
        Self { check: check.to_owned(), outcome: CheckOutcome::Skipped(reason.into()) }
    }
    pub fn failed(check: &str, reason: impl Into<String>) -> Self {
        Self { check: check.to_owned(), outcome: CheckOutcome::Failed(reason.into()) }
    }
}

// ---- the report -----------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Ok,
    Finding,
    Skipped,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckEntry {
    /// `<plugin>.<check>`.
    pub id: String,
    pub plugin_id: String,
    pub name: String,
    pub description: String,
    pub status: CheckStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A next step after the engine checked it.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NextStep {
    #[serde(rename_all = "camelCase")]
    Tool {
        /// `plugin:tool`.
        tool: String,
        mcp_name: String,
        name: String,
        /// Validated against the tool's schema, defaults filled in.
        args: Value,
        why: String,
        /// False when the tool's component is off or it needs administrator rights.
        available: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    Manual { text: String },
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportFinding {
    /// Unique in a run: `<plugin>.<check>` or `<plugin>.<check>:<key>`.
    pub id: String,
    pub check: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub count: u64,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub count_is_minimum: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<DateTime<Utc>>,
    pub evidence: Vec<Evidence>,
    pub next: Vec<NextStep>,
}

/// The last report and what the AI made of it, kept for the app until the
/// next run or the next lock (ADR 0005 D4).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Diagnosis {
    pub report: Report,
    pub advice: Option<ai::Advice>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub ran_at: DateTime<Utc>,
    pub lookback_days: u32,
    pub elevated: bool,
    pub checks: Vec<CheckEntry>,
    pub findings: Vec<ReportFinding>,
}

impl Report {
    /// The report an agent gets: the findings of `withheld` plugins are left
    /// out, and their checks listed as skipped, so Diagnose cannot be used to
    /// get around a read tool the owner set to need the PIN (ADR 0005 §3).
    pub fn for_agent(&self, withheld: &[String]) -> Report {
        let mut out = self.clone();
        for entry in out.checks.iter_mut().filter(|c| withheld.contains(&c.plugin_id)) {
            entry.status = CheckStatus::Skipped;
            entry.reason = Some(WITHHELD.to_owned());
        }
        let checks: Vec<&str> = out.checks.iter().filter(|c| withheld.contains(&c.plugin_id)).map(|c| c.id.as_str()).collect();
        let kept: Vec<ReportFinding> = out.findings.iter().filter(|f| !checks.contains(&f.check.as_str())).cloned().collect();
        out.findings = kept;
        out
    }
}

pub const WITHHELD: &str = "Needs approval for this plugin's tools.";

/// Where the tools a check may suggest stand at the time of a run.
pub struct ToolAvailability<'a> {
    pub registry: &'a Registry,
    pub installed: &'a dyn Fn(&str) -> bool,
    pub components: &'a dyn Fn(&str) -> Vec<String>,
    pub elevated: bool,
}

/// Turns one plugin's results into report entries and findings. Checks the
/// plugin did not declare are ignored; declared checks it did not report
/// are listed as failed. Next steps outside a check's `nextTools`, with
/// arguments its schema refuses, or for a plugin that is not installed, are
/// dropped (ADR 0005 §2).
pub fn collect(manifest: &PluginManifest, results: Vec<CheckResult>, tools: &ToolAvailability) -> (Vec<CheckEntry>, Vec<ReportFinding>) {
    let mut entries = Vec::new();
    let mut findings = Vec::new();
    let mut results: Vec<Option<CheckResult>> = results.into_iter().map(Some).collect();
    for declared in &manifest.checks {
        let id = format!("{}.{}", manifest.id, declared.id);
        let result = results.iter_mut().find(|r| r.as_ref().is_some_and(|r| r.check == declared.id)).and_then(Option::take);
        let (status, reason) = match result.map(|r| r.outcome) {
            None => (CheckStatus::Failed, Some("The check did not report.".to_owned())),
            Some(CheckOutcome::Skipped(reason)) => (CheckStatus::Skipped, Some(clean(&reason, MAX_DETAIL_CHARS))),
            Some(CheckOutcome::Failed(reason)) => (CheckStatus::Failed, Some(clean(&reason, MAX_DETAIL_CHARS))),
            Some(CheckOutcome::Ran(found)) => {
                let before = findings.len();
                let mut keys = std::collections::HashSet::new();
                for f in found.into_iter().take(MAX_FINDINGS_PER_CHECK) {
                    let finding_id = match &f.key {
                        Some(key) => format!("{id}:{}", clean_key(key)),
                        None => id.clone(),
                    };
                    // Two findings with one id would let the AI's references be ambiguous.
                    if !keys.insert(finding_id.clone()) {
                        continue;
                    }
                    findings.push(ReportFinding {
                        id: finding_id,
                        check: id.clone(),
                        severity: f.severity,
                        title: clean(&f.title, MAX_TITLE_CHARS),
                        detail: clean(&f.detail, MAX_DETAIL_CHARS),
                        count: f.count,
                        count_is_minimum: f.count_is_minimum,
                        first_seen: f.first_seen,
                        last_seen: f.last_seen,
                        evidence: newest_first(f.evidence).into_iter().take(MAX_EVIDENCE).map(clean_evidence).collect(),
                        next: f.next.into_iter().filter_map(|n| check_next(n, &declared.next_tools, tools)).take(MAX_NEXT_STEPS).collect(),
                    });
                }
                let status = if findings.len() > before { CheckStatus::Finding } else { CheckStatus::Ok };
                (status, None)
            }
        };
        entries.push(CheckEntry {
            id,
            plugin_id: manifest.id.clone(),
            name: declared.name.clone(),
            description: declared.description.clone(),
            status,
            reason,
        });
    }
    (entries, findings)
}

fn check_next(next: Next, allowed: &[String], tools: &ToolAvailability) -> Option<NextStep> {
    match next {
        Next::Manual { text } => Some(NextStep::Manual { text: clean(&text, MAX_WHY_CHARS) }),
        Next::Tool { tool, args, why } => {
            if !allowed.contains(&tool) {
                return None;
            }
            let (plugin_id, tool_id) = tool.split_once(':')?;
            let (_, manifest) = tools.registry.tool(plugin_id, tool_id)?;
            if !(tools.installed)(plugin_id) {
                return None;
            }
            let args = schema::validate(&manifest.input_schema, args).ok()?;
            let reason = if manifest.component.as_ref().is_some_and(|c| !(tools.components)(plugin_id).contains(c)) {
                Some(format!("{} needs a component that is turned off.", manifest.name))
            } else if manifest.requires_admin && !tools.elevated {
                Some("Needs administrator rights.".to_owned())
            } else {
                None
            };
            Some(NextStep::Tool {
                mcp_name: mcp_tool_name(plugin_id, tool_id),
                name: manifest.name.clone(),
                tool,
                args,
                why: clean(&why, MAX_WHY_CHARS),
                available: reason.is_none(),
                reason,
            })
        }
    }
}

/// Most serious first, then the most recent, then the most frequent.
pub fn sort(findings: &mut [ReportFinding]) {
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(b.last_seen.cmp(&a.last_seen)).then(b.count.cmp(&a.count)).then(a.id.cmp(&b.id)));
}

fn newest_first(mut evidence: Vec<Evidence>) -> Vec<Evidence> {
    evidence.sort_by(|a, b| b.time.cmp(&a.time));
    evidence
}

fn clean_evidence(mut e: Evidence) -> Evidence {
    e.source = clean(&e.source, 64);
    e.provider = e.provider.map(|p| clean(&p, 128));
    e.message = clean(&e.message, MAX_EVIDENCE_MESSAGE_CHARS);
    e
}

/// Without hidden or control characters (newlines kept as spaces), cut to `max` characters.
pub(crate) fn clean(text: &str, max: usize) -> String {
    let flat: String = text.chars().map(|c| if c.is_whitespace() { ' ' } else { c }).filter(|c| !is_hidden_char(*c)).collect();
    let flat = flat.split(' ').filter(|w| !w.is_empty()).collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max {
        return flat;
    }
    let mut cut: String = flat.chars().take(max.saturating_sub(1)).collect();
    cut.push('…');
    cut
}

/// Keys go into ids the AI refers to: kept to a plain, short form.
fn clean_key(key: &str) -> String {
    let k: String = key
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '_' })
        .take(MAX_KEY_CHARS)
        .collect();
    if k.is_empty() {
        "_".to_owned()
    } else {
        k
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn finding(key: Option<&str>, severity: Severity, last: i64) -> Finding {
        Finding {
            key: key.map(str::to_owned),
            severity,
            title: "t".into(),
            detail: "d".into(),
            count: 1,
            count_is_minimum: false,
            first_seen: None,
            last_seen: DateTime::from_timestamp(last, 0),
            evidence: vec![],
            next: vec![],
        }
    }

    #[test]
    fn text_is_flattened_cleaned_and_cut() {
        assert_eq!(clean("a\r\n  b\u{200B}c\u{7}", 100), "a bc");
        assert_eq!(clean("abcdef", 4), "abc…");
        assert_eq!(clean_key("Game Launcher.EXE"), "game_launcher.exe");
        assert_eq!(clean_key("::"), "__");
        assert_eq!(clean_key(""), "_");
    }

    #[test]
    fn findings_sort_by_severity_then_recency_then_count() {
        let rf = |id: &str, s, last, count| ReportFinding {
            id: id.into(),
            check: "p.c".into(),
            severity: s,
            title: String::new(),
            detail: String::new(),
            count,
            count_is_minimum: false,
            first_seen: None,
            last_seen: DateTime::from_timestamp(last, 0),
            evidence: vec![],
            next: vec![],
        };
        let mut v = vec![
            rf("old-warning", Severity::Warning, 10, 9),
            rf("info", Severity::Info, 99, 99),
            rf("new-warning", Severity::Warning, 20, 1),
            rf("critical", Severity::Critical, 1, 1),
            rf("new-warning-more", Severity::Warning, 20, 5),
        ];
        sort(&mut v);
        let ids: Vec<_> = v.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, ["critical", "new-warning-more", "new-warning", "old-warning", "info"]);
    }

    #[test]
    fn evidence_is_kept_newest_first() {
        let e = |t: i64| Evidence { source: "s".into(), provider: None, event_id: None, record_id: None, time: DateTime::from_timestamp(t, 0), message: String::new() };
        let times: Vec<_> = newest_first(vec![e(1), e(3), e(2)]).iter().map(|e| e.time.unwrap().timestamp()).collect();
        assert_eq!(times, [3, 2, 1]);
    }

    #[test]
    fn severity_orders_info_below_warning_below_critical() {
        assert!(Severity::Info < Severity::Warning && Severity::Warning < Severity::Critical);
        assert_eq!(serde_json::to_value(Severity::Critical).unwrap(), json!("critical"));
        let _ = finding(None, Severity::Info, 0);
    }
}
