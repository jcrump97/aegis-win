#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use aegis_core::engine::{Engine, EngineOptions};
use aegis_core::history_service::HistoryHandle;
use aegis_core::plugin_data::PluginStore;
use aegis_core::registry::{CallReview, CommandLine, Plugin, PluginManifest, Registry, ToolContext, UnlockContext};
use aegis_core::vault::KdfParams;
use aegis_core::AegisResult;
use async_trait::async_trait;
use serde_json::{json, Value};

pub const PIN: &str = "two-four-six-eight";

pub struct DemoPlugin {
    manifest: PluginManifest,
    pub unlocks: AtomicUsize,
    pub locks: AtomicUsize,
    /// The store handed to the last `on_unlock` and the last tool call.
    pub unlock_store: Mutex<Option<PluginStore>>,
    pub call_store: Mutex<Option<PluginStore>>,
    /// The history handle handed to the last `on_unlock`.
    pub unlock_history: Mutex<Option<HistoryHandle>>,
    /// `fix` with a note starting "wait" records the note, then blocks until
    /// a permit is added to `release`. A note starting "fail" makes `fix`
    /// fail, "unwell" makes it report `"success": false`, and "nodry" makes
    /// `describe` fail. Every `fix` run is recorded in `fixed`, and every
    /// dry run that reached `call` in `dry_calls`.
    pub started: Mutex<Vec<String>>,
    pub release: tokio::sync::Semaphore,
    pub running: AtomicUsize,
    pub max_running: AtomicUsize,
    pub fixed: Mutex<Vec<String>>,
    pub dry_calls: AtomicUsize,
    /// Added to `fix`'s described arguments, to change its commands after approval.
    pub describe_extra: Mutex<Option<String>>,
}

impl Default for DemoPlugin {
    fn default() -> Self {
        Self::with_id("demo")
    }
}

impl DemoPlugin {
    /// The same plugin under another id (for isolation tests).
    pub fn with_id(id: &str) -> Self {
        let manifest = PluginManifest::from_json(
            &json!({
                "id": "demo",
                "name": "Demo",
                "version": "1.0.0",
                "description": "Test plugin",
                "optionalInstallDefault": true,
                "usesLlm": true,
                "subComponents": [{ "id": "demo:extra", "name": "Extra", "description": "e" }],
                "tools": [
                    { "id": "echo", "name": "Echo", "description": "Returns its input.", "requiresAdmin": false,
                      "defaultGatePolicy": "auto", "readOnly": true,
                      "inputSchema": { "type": "object", "properties": { "text": { "type": "string", "maxLength": 200 } }, "additionalProperties": false } },
                    { "id": "fix", "name": "Fix <it>", "description": "Changes something.", "requiresAdmin": false,
                      "defaultGatePolicy": "pin_required", "readOnly": false, "planEligible": true,
                      "inputSchema": { "type": "object", "properties": { "dryRun": { "type": "boolean", "default": false }, "note": { "type": "string" } } } },
                    { "id": "old_fix", "name": "Old fix", "description": "Changes something, and does not describe its commands.", "requiresAdmin": false,
                      "defaultGatePolicy": "pin_required", "readOnly": false,
                      "inputSchema": { "type": "object", "properties": { "dryRun": { "type": "boolean", "default": false } } } },
                    { "id": "admin_fix", "name": "Admin fix", "description": "Needs admin.", "requiresAdmin": true,
                      "defaultGatePolicy": "pin_required", "readOnly": false, "inputSchema": { "type": "object", "properties": {} } },
                    { "id": "extra_tool", "name": "Extra", "description": "Component tool.", "requiresAdmin": false,
                      "defaultGatePolicy": "auto", "readOnly": true, "component": "demo:extra", "inputSchema": { "type": "object", "properties": {} } }
                ]
            })
            .to_string()
            .replace("\"demo", &format!("\"{id}")),
        )
        .unwrap();
        Self {
            manifest,
            unlocks: AtomicUsize::new(0),
            locks: AtomicUsize::new(0),
            unlock_store: Mutex::new(None),
            call_store: Mutex::new(None),
            unlock_history: Mutex::new(None),
            started: Mutex::new(Vec::new()),
            release: tokio::sync::Semaphore::new(0),
            running: AtomicUsize::new(0),
            max_running: AtomicUsize::new(0),
            fixed: Mutex::new(Vec::new()),
            dry_calls: AtomicUsize::new(0),
            describe_extra: Mutex::new(None),
        }
    }
}

#[async_trait]
impl Plugin for DemoPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn call(&self, tool: &str, args: Value, ctx: ToolContext) -> AegisResult<Value> {
        *self.call_store.lock().unwrap() = ctx.store;
        let note = args["note"].as_str().unwrap_or_default().to_owned();
        if tool == "fix" && args["dryRun"] != true && note.starts_with("wait") {
            self.started.lock().unwrap().push(note.clone());
            let now = self.running.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_running.fetch_max(now, Ordering::SeqCst);
            self.release.acquire().await.unwrap().forget();
            self.running.fetch_sub(1, Ordering::SeqCst);
        }
        if args["dryRun"] == true {
            self.dry_calls.fetch_add(1, Ordering::SeqCst);
        }
        if tool == "fix" {
            let dry = args["dryRun"] == true;
            if !dry {
                self.fixed.lock().unwrap().push(note.clone());
                if note.starts_with("fail") {
                    return Err(aegis_core::AegisError::new(aegis_core::ErrorCode::ExecutionFailed, "fix broke"));
                }
                if note.starts_with("unwell") {
                    return Ok(json!({ "executed": true, "success": false }));
                }
            }
        }
        Ok(match tool {
            "echo" => json!({ "echo": args }),
            _ => json!({ "done": tool }),
        })
    }

    fn on_unlock(&self, ctx: &UnlockContext) {
        *self.unlock_store.lock().unwrap() = ctx.store.clone();
        *self.unlock_history.lock().unwrap() = ctx.history.clone();
        self.unlocks.fetch_add(1, Ordering::SeqCst);
    }

    fn on_lock(&self) {
        self.locks.fetch_add(1, Ordering::SeqCst);
    }

    fn describe(&self, tool: &str, args: &Value) -> Option<AegisResult<Vec<CommandLine>>> {
        (tool == "fix").then(|| {
            let note = args["note"].as_str().unwrap_or_default();
            if note.starts_with("nodry") {
                return Err(aegis_core::AegisError::invalid("cannot describe that note"));
            }
            let mut argv = vec![note];
            let extra = self.describe_extra.lock().unwrap().clone();
            argv.extend(extra.as_deref());
            Ok(vec![CommandLine::new(r"C:\demo\fix.exe", &argv)])
        })
    }

    fn review_call(&self, tool: &str, args: &Value, _enabled_components: &[String]) -> Option<CallReview> {
        (tool == "fix").then(|| CallReview {
            lines: vec![format!("Fixes {}.", args["note"].as_str().unwrap_or("nothing"))],
            warnings: vec!["Fixing <b>cannot</b> be undone.".into()],
        })
    }
}

pub struct Fixture {
    pub engine: Arc<Engine>,
    pub plugin: Arc<DemoPlugin>,
    _dir: tempfile::TempDir,
}

pub fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let plugin = Arc::new(DemoPlugin::default());
    let registry = Registry::new(vec![plugin.clone() as Arc<dyn Plugin>]).unwrap();
    let engine = Engine::new(dir.path().join("data"), registry, EngineOptions { kdf: KdfParams::INSECURE_TEST, elevated: false });
    Fixture { engine, plugin, _dir: dir }
}

/// Set up, unlocked, with the demo plugin and its component installed.
pub async fn ready() -> Fixture {
    let f = fixture();
    f.engine.setup(PIN.into()).await.unwrap();
    f.engine.set_installed(BTreeMap::from([("demo".to_owned(), vec!["demo:extra".to_owned()])])).unwrap();
    f
}
