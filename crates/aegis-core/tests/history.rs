//! The engine's history service: per-plugin streams, writing after lock,
//! purge with a new key, and the runtime file's tamper check (ADR 0002 §5).

mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use aegis_core::engine::{Engine, EngineOptions};
use aegis_core::history::{FileStatus, Retention};
use aegis_core::history_service::{HistoryHandle, RuntimeFile};
use aegis_core::registry::{Plugin, Registry};
use aegis_core::vault::KdfParams;
use aegis_core::ErrorCode;
use common::{ready, DemoPlugin, PIN};
use serde_json::{json, Value};

fn history(plugin: &DemoPlugin) -> HistoryHandle {
    plugin.unlock_history.lock().unwrap().clone().expect("on_unlock gets a history handle")
}

fn stream_dir(engine: &Engine, stream: &str) -> PathBuf {
    engine.data_dir().join("history").join(stream)
}

fn files(engine: &Engine, stream: &str) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(stream_dir(engine, stream)).map(|d| d.map(|e| e.unwrap().path()).collect()).unwrap_or_default();
    out.sort();
    out
}

fn runtime_path(engine: &Engine, id: &str) -> PathBuf {
    engine.data_dir().join("runtime").join(format!("{id}.json"))
}

fn runtime(engine: &Engine, id: &str) -> RuntimeFile {
    serde_json::from_slice(&std::fs::read(runtime_path(engine, id)).unwrap()).unwrap()
}

fn kinds(records: &[Value]) -> Vec<&str> {
    records.iter().map(|r| r["kind"].as_str().unwrap()).collect()
}

#[tokio::test]
async fn records_are_sealed_kept_writing_after_lock_and_read_only_when_unlocked() {
    let f = ready().await;
    let h = history(&f.plugin);
    assert_eq!(h.stream(), "demo");
    h.append(json!({ "kind": "start", "secret": "plain-text-marker-5521", "at": "forged" })).unwrap();
    assert_eq!(files(&f.engine, "demo").len(), 1);
    let raw = std::fs::read(&files(&f.engine, "demo")[0]).unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("plain-text-marker-5521"), "records are encrypted on disk");

    f.engine.lock().await;
    h.append(json!({ "kind": "while-locked" })).unwrap();
    assert_eq!(files(&f.engine, "demo").len(), 2, "lock closes the file; locked writing starts a new one");
    assert_eq!(h.read(None).unwrap_err().code, ErrorCode::VaultLocked, "nothing is readable while locked");
    assert_eq!(h.purge().unwrap_err().code, ErrorCode::VaultLocked);

    f.engine.unlock(PIN.into()).await.unwrap();
    let read = history(&f.plugin).read(None).unwrap();
    assert_eq!(kinds(&read.records), ["start", "while-locked"]);
    assert_ne!(read.records[0]["at"], "forged", "the engine stamps each record");
    assert!(read.records[0]["at"].as_str().unwrap().ends_with('Z'));
    assert!(read.files.iter().all(|file| file.status == FileStatus::Ok));

    assert_eq!(h.append(json!(["not", "an", "object"])).unwrap_err().code, ErrorCode::InvalidArguments);
}

#[tokio::test]
async fn a_stream_cannot_be_written_while_locked_before_it_has_a_key() {
    let f = ready().await;
    let h = history(&f.plugin);
    f.engine.lock().await;
    assert_eq!(h.append(json!({ "kind": "x" })).unwrap_err().code, ErrorCode::VaultLocked);
    assert!(files(&f.engine, "demo").is_empty());
}

#[tokio::test]
async fn plugins_only_reach_their_own_stream() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (Arc::new(DemoPlugin::with_id("demo")), Arc::new(DemoPlugin::with_id("other")));
    let registry = Registry::new(vec![a.clone() as Arc<dyn Plugin>, b.clone() as Arc<dyn Plugin>]).unwrap();
    let engine = Engine::new(dir.path(), registry, EngineOptions { kdf: KdfParams::INSECURE_TEST, elevated: false });
    engine.setup(PIN.into()).await.unwrap();
    engine.set_installed(BTreeMap::from([("demo".to_owned(), vec![]), ("other".to_owned(), vec![])])).unwrap();
    history(&a).append(json!({ "kind": "from-demo" })).unwrap();
    history(&b).append(json!({ "kind": "from-other" })).unwrap();
    assert_eq!(kinds(&history(&a).read(None).unwrap().records), ["from-demo"]);
    assert_eq!(kinds(&history(&b).read(None).unwrap().records), ["from-other"]);
    history(&b).purge().unwrap();
    assert_eq!(kinds(&history(&a).read(None).unwrap().records), ["from-demo"], "purging one stream leaves the other");
}

#[test]
fn no_plugin_may_take_the_approvals_stream() {
    let err = Registry::new(vec![Arc::new(DemoPlugin::with_id("approvals")) as Arc<dyn Plugin>]).err().unwrap();
    assert!(err.contains("reserved"), "{err}");
}

#[tokio::test]
async fn purge_deletes_the_files_and_replaces_the_key() {
    let f = ready().await;
    let h = history(&f.plugin);
    h.set_runtime(Some(json!({ "watch": 1 }))).unwrap();
    let old_key = runtime(&f.engine, "demo").key_id;
    h.append(json!({ "kind": "before" })).unwrap();
    let old_file = files(&f.engine, "demo")[0].clone();
    let copy = std::fs::read(&old_file).unwrap();

    assert_eq!(h.purge().unwrap(), 1);
    assert!(files(&f.engine, "demo").is_empty());
    let new_key = runtime(&f.engine, "demo").key_id;
    assert_ne!(old_key, new_key, "the runtime file carries the new key");

    // A deleted file recovered from the disk is useless with the new key.
    std::fs::write(&old_file, copy).unwrap();
    h.append(json!({ "kind": "after" })).unwrap();
    let read = h.read(None).unwrap();
    assert_eq!(kinds(&read.records), ["after"]);
    assert_eq!(read.files.iter().map(|file| file.status).collect::<Vec<_>>(), [FileStatus::OtherKey, FileStatus::Ok]);
}

#[tokio::test]
async fn retention_is_bounded_and_saved() {
    let f = ready().await;
    let h = history(&f.plugin);
    assert_eq!(h.retention().unwrap(), Retention::MONITOR_DEFAULT);
    for bad in [Retention { max_days: 0, max_mb: 64 }, Retention { max_days: 91, max_mb: 64 }, Retention { max_days: 14, max_mb: 4 }] {
        assert_eq!(h.set_retention(bad).unwrap_err().code, ErrorCode::InvalidArguments);
    }
    let r = Retention { max_days: 3, max_mb: 8 };
    h.set_retention(r).unwrap();
    f.engine.lock().await;
    f.engine.unlock(PIN.into()).await.unwrap();
    assert_eq!(history(&f.plugin).retention().unwrap(), r);
}

#[tokio::test]
async fn the_runtime_file_mirrors_the_vault_and_a_tray_pause_is_not_tampering() {
    let f = ready().await;
    let h = history(&f.plugin);
    h.set_runtime(Some(json!({ "rules": ["busy"] }))).unwrap();
    let file = runtime(&f.engine, "demo");
    assert_eq!((file.stream.as_str(), file.plugin.clone(), file.paused), ("demo", json!({ "rules": ["busy"] }), false));
    assert_eq!(file.retention, Retention::MONITOR_DEFAULT);

    // Pausing from the tray needs no PIN, so it only flips `paused` on disk.
    let paused = RuntimeFile { paused: true, ..file.clone() };
    std::fs::write(runtime_path(&f.engine, "demo"), serde_json::to_vec(&paused).unwrap()).unwrap();
    let locks = f.plugin.locks.load(std::sync::atomic::Ordering::SeqCst);
    f.engine.lock().await;
    // A plugin without `run_locked` stops on lock as before, declared work or not.
    assert_eq!(f.plugin.locks.load(std::sync::atomic::Ordering::SeqCst), locks + 1);
    assert!(!f.engine.locked_monitoring() && !f.engine.background_active());
    f.engine.unlock(PIN.into()).await.unwrap();
    assert!(f.engine.runtime_reviews().is_empty());
    history(&f.plugin).set_runtime(Some(json!({ "rules": ["busy", "hot"] }))).unwrap();
    assert!(runtime(&f.engine, "demo").paused, "rewriting keeps the tray pause");

    // A deleted file is written again from the vault.
    std::fs::remove_file(runtime_path(&f.engine, "demo")).unwrap();
    f.engine.lock().await;
    f.engine.unlock(PIN.into()).await.unwrap();
    assert_eq!(runtime(&f.engine, "demo").plugin, json!({ "rules": ["busy", "hot"] }));

    history(&f.plugin).set_runtime(None).unwrap();
    assert!(!runtime_path(&f.engine, "demo").exists());
}

#[tokio::test]
async fn a_changed_runtime_file_is_set_aside_until_the_owner_rewrites_it() {
    let f = ready().await;
    history(&f.plugin).set_runtime(Some(json!({ "rules": ["busy"] }))).unwrap();
    let mut file = runtime(&f.engine, "demo");
    file.plugin = json!({ "rules": ["busy", "planted"] });
    file.key_id = "0000000000000000".into();
    std::fs::write(runtime_path(&f.engine, "demo"), serde_json::to_vec(&file).unwrap()).unwrap();

    f.engine.lock().await;
    f.engine.unlock(PIN.into()).await.unwrap();
    let reviews = f.engine.runtime_reviews();
    assert_eq!(reviews.len(), 1);
    assert_eq!(reviews[0].plugin_id, "demo");
    assert_eq!(reviews[0].differences, ["history key", "monitoring settings"]);
    assert!(!runtime_path(&f.engine, "demo").exists(), "the changed file is never resumed from");
    assert!(f.engine.data_dir().join("runtime").join("demo.rejected.json").exists());

    // Plugin updates while the review waits go to the vault only.
    history(&f.plugin).set_runtime(Some(json!({ "rules": ["busy", "hot"] }))).unwrap();
    assert!(!runtime_path(&f.engine, "demo").exists());

    // The app sees the review in its status, only while unlocked.
    assert_eq!(f.engine.status().runtime_reviews.len(), 1);

    // Still waiting after another lock and unlock.
    f.engine.lock().await;
    assert!(f.engine.status().runtime_reviews.is_empty(), "nothing is shown while locked");
    assert_eq!(f.engine.rewrite_runtime_from_vault("demo").unwrap_err().code, ErrorCode::VaultLocked);
    f.engine.unlock(PIN.into()).await.unwrap();
    assert_eq!(f.engine.runtime_reviews().len(), 1);
    assert!(!runtime_path(&f.engine, "demo").exists());

    f.engine.rewrite_runtime_from_vault("demo").unwrap();
    assert!(f.engine.runtime_reviews().is_empty());
    assert_eq!(runtime(&f.engine, "demo").plugin, json!({ "rules": ["busy", "hot"] }));
    assert!(!f.engine.data_dir().join("runtime").join("demo.rejected.json").exists());
    assert_eq!(f.engine.rewrite_runtime_from_vault("demo").unwrap_err().code, ErrorCode::InvalidArguments);
}

#[tokio::test]
async fn a_planted_or_broken_runtime_file_is_set_aside() {
    let f = ready().await;
    let dir = f.engine.data_dir().join("runtime");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("demo.json"), b"{ not json").unwrap();
    std::fs::write(dir.join("ghost.json"), br#"{"version":1,"stream":"ghost","keyId":"00","publicKey":"00","retention":{"maxDays":1,"maxMb":8},"plugin":{}}"#).unwrap();
    f.engine.lock().await;
    f.engine.unlock(PIN.into()).await.unwrap();
    let reviews = f.engine.runtime_reviews();
    let found: Vec<(&str, &str)> = reviews.iter().map(|r| (r.plugin_id.as_str(), r.differences[0].as_str())).collect();
    assert_eq!(found, [("demo", "the file could not be read"), ("ghost", "AegisWin did not write this file")]);
    assert!(!dir.join("demo.json").exists() && !dir.join("ghost.json").exists());
}

#[tokio::test]
async fn uninstalling_a_plugin_removes_its_runtime_file() {
    let f = ready().await;
    history(&f.plugin).set_runtime(Some(json!({ "rules": [] }))).unwrap();
    assert!(runtime_path(&f.engine, "demo").exists());
    f.engine.set_installed(BTreeMap::new()).unwrap();
    assert!(!runtime_path(&f.engine, "demo").exists());
    assert_eq!(history(&f.plugin).read(None).unwrap_err().code, ErrorCode::PluginDisabled);
    f.engine.set_installed(BTreeMap::from([("demo".to_owned(), vec![])])).unwrap();
    assert!(!runtime_path(&f.engine, "demo").exists(), "reinstalling does not bring back what it ran");
    f.engine.lock().await;
    f.engine.unlock(PIN.into()).await.unwrap();
    assert!(f.engine.runtime_reviews().is_empty());
}
