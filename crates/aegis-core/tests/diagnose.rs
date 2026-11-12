//! Diagnose this PC (ADR 0005 Phase 1a): the engine runs installed plugins'
//! checks, enforces each check's `nextTools`, and runs one diagnosis at a time.

mod common;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use aegis_core::diagnose::{CheckContext, CheckResult, CheckStatus, Evidence, Finding, Next, NextStep, Severity};
use aegis_core::engine::{Engine, EngineOptions};
use aegis_core::registry::{Plugin, PluginManifest, Registry, ToolContext};
use aegis_core::vault::KdfParams;
use aegis_core::{AegisResult, ErrorCode};
use async_trait::async_trait;
use common::{DemoPlugin, PIN};
use serde_json::{json, Value};

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Normal,
    /// Waits for a permit in `release`.
    Block,
    /// Never finishes.
    Hang,
    Panic,
}

struct Checker {
    manifest: PluginManifest,
    mode: Mutex<Mode>,
    runs: AtomicUsize,
    release: tokio::sync::Semaphore,
    last_ctx: Mutex<Option<CheckContext>>,
}

impl Checker {
    fn new() -> Self {
        let dry = json!({ "dryRun": { "type": "boolean", "default": false } });
        let manifest = PluginManifest::from_json(
            &json!({
                "id": "checker", "name": "Checker", "version": "1.0.0", "description": "Has checks.",
                "optionalInstallDefault": true, "usesLlm": false,
                "subComponents": [{ "id": "checker:extra", "name": "Extra", "description": "e" }],
                "tools": [
                    { "id": "repair", "name": "Repair", "description": "r", "requiresAdmin": true, "defaultGatePolicy": "pin_required",
                      "readOnly": false, "planEligible": true,
                      "inputSchema": { "type": "object", "additionalProperties": false,
                        "properties": { "dryRun": dry["dryRun"], "target": { "type": "string", "enum": ["a", "b"] } } } },
                    { "id": "tune", "name": "Tune", "description": "t", "requiresAdmin": false, "defaultGatePolicy": "pin_required",
                      "readOnly": false, "planEligible": true, "component": "checker:extra",
                      "inputSchema": { "type": "object", "properties": dry } },
                    { "id": "look", "name": "Look", "description": "l", "requiresAdmin": false, "defaultGatePolicy": "auto",
                      "readOnly": true, "inputSchema": { "type": "object", "properties": {} } }
                ],
                "checks": [
                    { "id": "crash", "name": "Crashes", "description": "c", "nextTools": ["checker:repair", "checker:tune", "demo:fix"] },
                    { "id": "quiet", "name": "Quiet", "description": "q" },
                    { "id": "silent", "name": "Silent", "description": "never reports" }
                ]
            })
            .to_string(),
        )
        .unwrap();
        Self { manifest, mode: Mutex::new(Mode::Normal), runs: AtomicUsize::new(0), release: tokio::sync::Semaphore::new(0), last_ctx: Mutex::new(None) }
    }
}

fn at(secs: i64) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::from_timestamp(1_800_000_000 + secs, 0)
}

fn finding(key: &str, severity: Severity, last: i64, next: Vec<Next>) -> Finding {
    Finding {
        key: Some(key.into()),
        severity,
        title: format!("{key} crashed"),
        detail: "It stopped.".into(),
        count: 3,
        count_is_minimum: false,
        first_seen: at(0),
        last_seen: at(last),
        evidence: vec![Evidence {
            source: "Application".into(),
            provider: Some("Application Error".into()),
            event_id: Some(1000),
            record_id: Some(7),
            time: at(last),
            message: format!("{}\u{202E}hidden", "x".repeat(400)),
        }],
        next,
    }
}

fn tool(tool: &str, args: Value) -> Next {
    Next::Tool { tool: tool.into(), args, why: "Because.".into() }
}

#[async_trait]
impl Plugin for Checker {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn call(&self, tool: &str, _args: Value, _ctx: ToolContext) -> AegisResult<Value> {
        Ok(json!({ "done": tool }))
    }

    async fn run_checks(&self, ctx: &CheckContext) -> Vec<CheckResult> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        *self.last_ctx.lock().unwrap() = Some(ctx.clone());
        let mode = *self.mode.lock().unwrap();
        match mode {
            Mode::Block => self.release.acquire().await.unwrap().forget(),
            Mode::Hang => std::future::pending::<()>().await,
            Mode::Panic => panic!("a check broke"),
            Mode::Normal => {}
        }
        vec![
            CheckResult::ran(
                "crash",
                vec![
                    finding("older.exe", Severity::Warning, 10, vec![]),
                    finding(
                        "Game.EXE",
                        Severity::Critical,
                        5,
                        vec![
                            tool("checker:repair", json!({ "target": "a" })),
                            // Not in the check's nextTools.
                            tool("checker:look", json!({})),
                            // Arguments the schema refuses.
                            tool("checker:repair", json!({ "target": "z" })),
                            // Its component is off; still listed, as unavailable.
                            tool("checker:tune", json!({})),
                            // Another plugin's tool, declared in nextTools.
                            tool("demo:fix", json!({ "note": "n" })),
                            Next::Manual { text: "Reinstall\nthe game.".into() },
                        ],
                    ),
                    // Same id as above after cleaning: dropped.
                    finding("game.exe", Severity::Info, 1, vec![]),
                ],
            ),
            CheckResult::ran("quiet", vec![]),
            CheckResult::ran("undeclared", vec![finding("x", Severity::Critical, 99, vec![])]),
        ]
    }
}

struct Setup {
    engine: Arc<Engine>,
    checker: Arc<Checker>,
    _dir: tempfile::TempDir,
}

async fn setup(installed: &[(&str, &[&str])]) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let checker = Arc::new(Checker::new());
    let registry = Registry::new(vec![checker.clone() as Arc<dyn Plugin>, Arc::new(DemoPlugin::default())]).unwrap();
    let engine = Engine::new(dir.path().join("data"), registry, EngineOptions { kdf: KdfParams::INSECURE_TEST, elevated: false });
    engine.setup(PIN.into()).await.unwrap();
    let selection: BTreeMap<String, Vec<String>> = installed.iter().map(|(id, c)| (id.to_string(), c.iter().map(|s| s.to_string()).collect())).collect();
    engine.set_installed(selection).unwrap();
    Setup { engine, checker, _dir: dir }
}

#[tokio::test]
async fn refuses_while_locked_and_odd_lookbacks() {
    let s = setup(&[("checker", &[])]).await;
    assert_eq!(s.engine.diagnose(3).await.unwrap_err().code, ErrorCode::InvalidArguments);
    s.engine.lock().await;
    assert_eq!(s.engine.diagnose(7).await.unwrap_err().code, ErrorCode::VaultLocked);
    assert_eq!(s.checker.runs.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn reports_declared_checks_and_sorted_cleaned_findings() {
    let s = setup(&[("checker", &[]), ("demo", &[])]).await;
    let report = s.engine.diagnose(7).await.unwrap();
    assert_eq!(report.lookback_days, 7);
    assert!(!report.elevated);
    let ctx = s.checker.last_ctx.lock().unwrap().clone().unwrap();
    assert_eq!((ctx.lookback_days, ctx.now), (7, report.ran_at));

    let status: Vec<_> = report.checks.iter().map(|c| (c.id.as_str(), c.status)).collect();
    assert_eq!(status, [("checker.crash", CheckStatus::Finding), ("checker.quiet", CheckStatus::Ok), ("checker.silent", CheckStatus::Failed)]);
    assert_eq!(report.checks[2].reason.as_deref(), Some("The check did not report."));

    // The undeclared check is ignored and the duplicate id dropped; critical first.
    let ids: Vec<_> = report.findings.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(ids, ["checker.crash:game.exe", "checker.crash:older.exe"]);
    let top = &report.findings[0];
    assert_eq!(top.check, "checker.crash");
    let message = &top.evidence[0].message;
    assert_eq!(message.chars().count(), 300);
    assert!(!message.contains('\u{202E}'));
}

#[tokio::test]
async fn the_engine_enforces_next_tools_whatever_the_check_returns() {
    let s = setup(&[("checker", &[]), ("demo", &[])]).await;
    let report = s.engine.diagnose(7).await.unwrap();
    let next = &report.findings[0].next;
    let summary: Vec<(String, bool)> = next
        .iter()
        .map(|n| match n {
            NextStep::Tool { tool, available, .. } => (tool.clone(), *available),
            NextStep::Manual { text } => (text.clone(), true),
        })
        .collect();
    // Four steps at most: look (undeclared) and repair with a bad target are gone.
    assert_eq!(summary, [("checker:repair".into(), false), ("checker:tune".into(), false), ("demo:fix".into(), true), ("Reinstall the game.".into(), true)]);
    let NextStep::Tool { mcp_name, args, reason, .. } = &next[0] else { panic!() };
    assert_eq!(mcp_name, "checker__repair");
    assert_eq!(args, &json!({ "target": "a", "dryRun": false }), "validated, defaults filled in");
    assert_eq!(reason.as_deref(), Some("Needs administrator rights."));
    let NextStep::Tool { reason, .. } = &next[1] else { panic!() };
    assert!(reason.as_deref().unwrap().contains("component"));
}

#[tokio::test]
async fn steps_for_a_plugin_that_is_not_installed_are_dropped() {
    let s = setup(&[("checker", &["checker:extra"])]).await;
    let report = s.engine.diagnose(1).await.unwrap();
    let tools: Vec<_> = report.findings[0]
        .next
        .iter()
        .filter_map(|n| match n {
            NextStep::Tool { tool, available, .. } => Some((tool.as_str(), *available)),
            NextStep::Manual { .. } => None,
        })
        .collect();
    assert_eq!(tools, [("checker:repair", false), ("checker:tune", true)]);
}

#[tokio::test]
async fn plugins_that_are_not_installed_are_not_run() {
    let s = setup(&[("demo", &[])]).await;
    let report = s.engine.diagnose(7).await.unwrap();
    assert!(report.checks.is_empty() && report.findings.is_empty());
    assert_eq!(s.checker.runs.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn one_diagnosis_at_a_time_and_waiters_share_its_report() {
    let s = setup(&[("checker", &[])]).await;
    *s.checker.mode.lock().unwrap() = Mode::Block;
    let (a, b) = (s.engine.clone(), s.engine.clone());
    let first = tokio::spawn(async move { a.diagnose(7).await });
    while s.checker.runs.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    let second = tokio::spawn(async move { b.diagnose(30).await });
    tokio::task::yield_now().await;
    s.checker.release.add_permits(1);
    let (first, second) = (first.await.unwrap().unwrap(), second.await.unwrap().unwrap());
    assert_eq!(s.checker.runs.load(Ordering::SeqCst), 1);
    assert_eq!(first, second);
    // Once it finished, the next request runs again.
    *s.checker.mode.lock().unwrap() = Mode::Normal;
    s.engine.diagnose(7).await.unwrap();
    assert_eq!(s.checker.runs.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_lock_during_the_run_withholds_the_report() {
    let s = setup(&[("checker", &[])]).await;
    *s.checker.mode.lock().unwrap() = Mode::Block;
    let e = s.engine.clone();
    let run = tokio::spawn(async move { e.diagnose(7).await });
    while s.checker.runs.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    s.engine.lock().await;
    s.checker.release.add_permits(1);
    assert_eq!(run.await.unwrap().unwrap_err().code, ErrorCode::VaultLocked);
}

#[tokio::test(start_paused = true)]
async fn checks_that_take_too_long_are_reported_as_failed() {
    let s = setup(&[("checker", &[])]).await;
    *s.checker.mode.lock().unwrap() = Mode::Hang;
    let report = s.engine.diagnose(7).await.unwrap();
    assert!(report.checks.iter().all(|c| c.status == CheckStatus::Failed && c.reason.as_deref() == Some("Timed out.")));
    assert!(report.findings.is_empty());
}

#[tokio::test]
async fn a_panicking_check_fails_its_plugin_only_and_the_next_run_works() {
    let s = setup(&[("checker", &[])]).await;
    *s.checker.mode.lock().unwrap() = Mode::Panic;
    let report = s.engine.diagnose(7).await.unwrap();
    assert!(report.checks.iter().all(|c| c.status == CheckStatus::Failed));
    *s.checker.mode.lock().unwrap() = Mode::Normal;
    assert_eq!(s.engine.diagnose(7).await.unwrap().findings.len(), 2);
}

#[test]
fn next_tools_must_name_plan_eligible_tools_of_compiled_plugins() {
    let with_next = |next: &str| {
        let mut c = Checker::new();
        c.manifest.checks[0].next_tools = vec![next.to_owned()];
        Registry::new(vec![Arc::new(c) as Arc<dyn Plugin>, Arc::new(DemoPlugin::default())]).map(|_| ())
    };
    with_next("demo:fix").unwrap();
    for bad in ["demo:echo", "demo:missing", "nobody:fix", "checker:look"] {
        assert!(with_next(bad).unwrap_err().contains("nextTools"), "{bad}");
    }
}
