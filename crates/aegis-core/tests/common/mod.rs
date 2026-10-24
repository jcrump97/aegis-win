#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use aegis_core::engine::{Engine, EngineOptions};
use aegis_core::registry::{Plugin, PluginManifest, Registry, ToolContext};
use aegis_core::vault::KdfParams;
use aegis_core::AegisResult;
use async_trait::async_trait;
use serde_json::{json, Value};

pub const PIN: &str = "246810";

pub struct DemoPlugin {
    manifest: PluginManifest,
    pub unlocks: AtomicUsize,
    pub locks: AtomicUsize,
}

impl Default for DemoPlugin {
    fn default() -> Self {
        let manifest = PluginManifest::from_json(
            &json!({
                "id": "demo",
                "name": "Demo",
                "version": "1.0.0",
                "description": "Test plugin",
                "optionalInstallDefault": true,
                "usesLlm": false,
                "subComponents": [{ "id": "demo:extra", "name": "Extra", "description": "e" }],
                "tools": [
                    { "id": "echo", "name": "Echo", "description": "Returns its input.", "requiresAdmin": false,
                      "defaultGatePolicy": "auto", "readOnly": true,
                      "inputSchema": { "type": "object", "properties": { "text": { "type": "string", "maxLength": 200 } }, "additionalProperties": false } },
                    { "id": "fix", "name": "Fix <it>", "description": "Changes something.", "requiresAdmin": false,
                      "defaultGatePolicy": "pin_required", "readOnly": false,
                      "inputSchema": { "type": "object", "properties": { "dryRun": { "type": "boolean", "default": false }, "note": { "type": "string" } } } },
                    { "id": "admin_fix", "name": "Admin fix", "description": "Needs admin.", "requiresAdmin": true,
                      "defaultGatePolicy": "pin_required", "readOnly": false, "inputSchema": { "type": "object", "properties": {} } },
                    { "id": "extra_tool", "name": "Extra", "description": "Component tool.", "requiresAdmin": false,
                      "defaultGatePolicy": "auto", "readOnly": true, "component": "demo:extra", "inputSchema": { "type": "object", "properties": {} } }
                ]
            })
            .to_string(),
        )
        .unwrap();
        Self { manifest, unlocks: AtomicUsize::new(0), locks: AtomicUsize::new(0) }
    }
}

#[async_trait]
impl Plugin for DemoPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn call(&self, tool: &str, args: Value, _ctx: ToolContext) -> AegisResult<Value> {
        Ok(match tool {
            "echo" => json!({ "echo": args }),
            "fix" if args["dryRun"] == true => json!({ "dryRun": true, "wouldRun": ["fix.exe"] }),
            _ => json!({ "done": tool }),
        })
    }

    fn on_unlock(&self, _components: &[String]) {
        self.unlocks.fetch_add(1, Ordering::SeqCst);
    }

    fn on_lock(&self) {
        self.locks.fetch_add(1, Ordering::SeqCst);
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
