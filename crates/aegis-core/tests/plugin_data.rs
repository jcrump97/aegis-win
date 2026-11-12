mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use aegis_core::engine::{Engine, EngineOptions, Origin, VAULT_FILE};
use aegis_core::plugin_data::{PluginStore, MAX_PLUGIN_DATA_BYTES};
use aegis_core::registry::{Plugin, Registry};
use aegis_core::vault::KdfParams;
use aegis_core::ErrorCode;
use common::{ready, DemoPlugin, PIN};
use serde_json::json;

fn unlock_store(plugin: &DemoPlugin) -> PluginStore {
    plugin.unlock_store.lock().unwrap().clone().expect("on_unlock gets a store")
}

#[tokio::test]
async fn records_survive_lock_and_unlock_and_are_encrypted_on_disk() {
    let f = ready().await;
    let store = unlock_store(&f.plugin);
    assert_eq!(store.plugin_id(), "demo");
    assert_eq!(store.get("monitors").unwrap(), None);
    store.set("monitors", json!([{ "name": "plain-text-marker-7731" }])).unwrap();

    let raw = std::fs::read_to_string(f.engine.data_dir().join(VAULT_FILE)).unwrap();
    assert!(!raw.contains("plain-text-marker-7731"), "records are inside the encrypted vault");

    f.engine.lock().await;
    assert_eq!(store.get("monitors").unwrap_err().code, ErrorCode::VaultLocked, "an old handle cannot read while locked");
    assert_eq!(store.set("monitors", json!(1)).unwrap_err().code, ErrorCode::VaultLocked);
    f.engine.unlock(PIN.into()).await.unwrap();
    let fresh = unlock_store(&f.plugin);
    assert_eq!(fresh.get("monitors").unwrap(), Some(json!([{ "name": "plain-text-marker-7731" }])));

    fresh.remove("monitors").unwrap();
    assert_eq!(fresh.get("monitors").unwrap(), None);
    fresh.remove("monitors").unwrap();
}

#[tokio::test]
async fn tool_calls_get_the_same_store() {
    let f = ready().await;
    unlock_store(&f.plugin).set("k", json!("v")).unwrap();
    f.engine.run_tool(Origin::Ui { pin: None }, "demo", "echo", json!({})).await.unwrap();
    let store = f.plugin.call_store.lock().unwrap().clone().expect("tool calls get a store");
    assert_eq!(store.get("k").unwrap(), Some(json!("v")));
}

#[tokio::test]
async fn plugins_only_reach_their_own_records() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (Arc::new(DemoPlugin::with_id("demo")), Arc::new(DemoPlugin::with_id("other")));
    let registry = Registry::new(vec![a.clone() as Arc<dyn Plugin>, b.clone() as Arc<dyn Plugin>]).unwrap();
    let engine = Engine::new(dir.path(), registry, EngineOptions { kdf: KdfParams::INSECURE_TEST, elevated: false });
    engine.setup(PIN.into()).await.unwrap();
    engine.set_installed(BTreeMap::from([("demo".to_owned(), vec![]), ("other".to_owned(), vec![])])).unwrap();
    let (sa, sb) = (unlock_store(&a), unlock_store(&b));
    sa.set("shared-name", json!("from demo")).unwrap();
    assert_eq!(sb.get("shared-name").unwrap(), None);
    sb.set("shared-name", json!("from other")).unwrap();
    assert_eq!(sa.get("shared-name").unwrap(), Some(json!("from demo")));
    sb.clear().unwrap();
    assert_eq!(sa.get("shared-name").unwrap(), Some(json!("from demo")), "clear only touches the caller's records");
}

#[tokio::test]
async fn uninstalled_plugins_cannot_reach_their_records_until_reinstalled() {
    let f = ready().await;
    let store = unlock_store(&f.plugin);
    store.set("monitors", json!(["kept"])).unwrap();
    f.engine.set_installed(BTreeMap::new()).unwrap();
    assert_eq!(store.get("monitors").unwrap_err().code, ErrorCode::PluginDisabled);
    assert_eq!(store.set("monitors", json!([])).unwrap_err().code, ErrorCode::PluginDisabled);
    assert_eq!(store.clear().unwrap_err().code, ErrorCode::PluginDisabled);
    f.engine.set_installed(BTreeMap::from([("demo".to_owned(), vec![])])).unwrap();
    assert_eq!(store.get("monitors").unwrap(), Some(json!(["kept"])));
}

#[tokio::test]
async fn keys_and_size_are_limited_and_a_refused_write_changes_nothing() {
    let f = ready().await;
    let store = unlock_store(&f.plugin);
    for bad in ["", "Upper", "../vault", "a.b"] {
        assert_eq!(store.set(bad, json!(1)).unwrap_err().code, ErrorCode::InvalidArguments, "{bad}");
    }
    store.set("big", json!("x".repeat(MAX_PLUGIN_DATA_BYTES / 2))).unwrap();
    let err = store.set("bigger", json!("y".repeat(MAX_PLUGIN_DATA_BYTES / 2))).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArguments);
    assert_eq!(store.get("bigger").unwrap(), None, "the refused write was rolled back");
    // Replacing a record counts its new size, not old + new.
    store.set("big", json!("z".repeat(MAX_PLUGIN_DATA_BYTES / 2))).unwrap();
    f.engine.lock().await;
    f.engine.unlock(PIN.into()).await.unwrap();
    let store = unlock_store(&f.plugin);
    assert_eq!(store.get("bigger").unwrap(), None);
    assert!(store.get("big").unwrap().unwrap().as_str().unwrap().starts_with('z'));
}
