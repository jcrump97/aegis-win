//! The engine's history service (ADR 0002 §5): one encrypted, write-only
//! stream per plugin (named after the plugin id) plus the engine's own
//! `approvals` stream, and the plaintext `runtime` file that lets a stream
//! keep recording while the vault is locked.
//!
//! Only public keys are held here. They are cached in memory when the vault
//! unlocks and kept after it locks, so locked writing works; private keys
//! stay in the vault. A plugin reaches only its own stream, through a
//! [`HistoryHandle`] the engine binds to its id.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, Weak};

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::engine::Engine;
use crate::error::{AegisError, AegisResult, ErrorCode};
use crate::chain::{ChainWriter, Head, MacCheck, Session};
use crate::history::{self, FileRead, PublicStreamKey, Retention, SegmentWriter, StreamKey, StreamRead};

/// `./data/history/<stream>/` holds a stream's segment files.
pub const HISTORY_DIR: &str = "history";
/// `./data/runtime/<plugin>.json`: what a plugin runs while locked.
pub const RUNTIME_DIR: &str = "runtime";
/// The engine's own stream for approval outcomes (ADR 0003 §7). No plugin may use this id.
pub const APPROVALS_STREAM: &str = "approvals";
pub const RUNTIME_VERSION: u32 = 1;
/// Largest plugin section of a runtime file.
pub const MAX_RUNTIME_BYTES: usize = 64 * 1024;

pub fn default_retention(stream: &str) -> Retention {
    if stream == APPROVALS_STREAM {
        Retention::APPROVALS_DEFAULT
    } else {
        Retention::MONITOR_DEFAULT
    }
}

/// Longest a change counts as running when its `change_finished` record is
/// missing (AegisWin quit or crashed mid-change).
pub const OPEN_CHANGE_LIMIT: chrono::Duration = chrono::Duration::hours(2);

/// A stretch of time in which AegisWin was changing the system.
#[derive(Debug, Clone, PartialEq)]
pub struct ChangeWindow {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    /// The tool's display name.
    pub tool: String,
}

/// Pairs `change_started` with the next `change_finished`. Changes run one
/// at a time, so a start without a finish lasts until the next start, at
/// most [`OPEN_CHANGE_LIMIT`].
pub fn change_windows(records: &[Value]) -> Vec<ChangeWindow> {
    let at = |r: &Value| r.get("at").and_then(Value::as_str).and_then(|s| DateTime::parse_from_rfc3339(s).ok()).map(|t| t.with_timezone(&Utc));
    let mut events: Vec<(DateTime<Utc>, &Value)> = records.iter().filter_map(|r| Some((at(r)?, r))).collect();
    events.sort_by_key(|(t, _)| *t);
    let mut out = Vec::new();
    let mut open: Option<(DateTime<Utc>, String)> = None;
    for (t, r) in events {
        match r.get("event").and_then(Value::as_str) {
            Some("change_started") => {
                if let Some((from, tool)) = open.take() {
                    out.push(ChangeWindow { from, to: t.min(from + OPEN_CHANGE_LIMIT), tool });
                }
                let tool = r.get("toolName").or_else(|| r.get("tool")).and_then(Value::as_str).unwrap_or("a repair").to_owned();
                open = Some((t, tool));
            }
            Some("change_finished") => {
                if let Some((from, tool)) = open.take() {
                    out.push(ChangeWindow { from, to: t, tool });
                }
            }
            _ => {}
        }
    }
    if let Some((from, tool)) = open {
        out.push(ChangeWindow { from, to: from + OPEN_CHANGE_LIMIT, tool });
    }
    out
}

/// The plaintext runtime file. It reveals what is monitored, never what was
/// recorded. Compared with the vault's copy on every unlock.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeFile {
    pub version: u32,
    pub stream: String,
    pub key_id: String,
    pub public_key: String,
    pub retention: Retention,
    /// Set from the tray without the PIN, so it is not part of the tamper check.
    #[serde(default)]
    pub paused: bool,
    /// The plugin's own description of its locked work.
    pub plugin: Value,
}

impl RuntimeFile {
    pub fn public_key(&self) -> PublicStreamKey {
        PublicStreamKey { key_id: self.key_id.clone(), public_key: self.public_key.clone() }
    }

    /// Field names that differ from `expected`, ignoring `paused`.
    pub fn differences(&self, expected: &RuntimeFile) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.version != expected.version {
            out.push("version");
        }
        if self.stream != expected.stream {
            out.push("stream");
        }
        if self.key_id != expected.key_id || self.public_key != expected.public_key {
            out.push("history key");
        }
        if self.retention != expected.retention {
            out.push("retention");
        }
        if self.plugin != expected.plugin {
            out.push("monitoring settings");
        }
        out
    }
}

/// A runtime file that did not match the vault at unlock. It was moved
/// aside (`<plugin>.rejected.json`) so it is never resumed from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeReview {
    pub plugin_id: String,
    /// What differed, in words ("history key", "monitoring settings", ...).
    pub differences: Vec<String>,
}

struct Slot {
    key: PublicStreamKey,
    retention: Retention,
    writer: Option<SegmentWriter>,
}

impl Slot {
    fn writer(&mut self, dir: PathBuf, stream: &str) -> &mut SegmentWriter {
        self.writer.get_or_insert_with(|| SegmentWriter::new(dir, stream, self.key.clone(), self.retention))
    }
}

/// How one record is written.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Append {
    /// Refuse the record once the stream holds this many bytes.
    pub limit: Option<u64>,
    /// Force it to disk before returning.
    pub sync: bool,
    /// Refuse it unless the stream is chained (its MAC session is set).
    pub chained: bool,
}

/// Why a record was not written.
#[derive(Debug)]
pub(crate) enum AppendError {
    /// The stream reached [`Append::limit`].
    Full,
    Failed(AegisError),
}

impl From<AegisError> for AppendError {
    fn from(e: AegisError) -> Self {
        Self::Failed(e)
    }
}

/// Segment writers and cached public keys, by stream.
pub(crate) struct HistoryService {
    data_dir: PathBuf,
    streams: Mutex<BTreeMap<String, Slot>>,
}

fn io_err(e: io::Error) -> AegisError {
    AegisError::new(ErrorCode::Internal, format!("history: {e}"))
}

impl HistoryService {
    pub(crate) fn new(data_dir: &Path) -> Self {
        Self { data_dir: data_dir.to_owned(), streams: Mutex::new(BTreeMap::new()) }
    }

    fn streams(&self) -> MutexGuard<'_, BTreeMap<String, Slot>> {
        self.streams.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn dir(&self, stream: &str) -> PathBuf {
        self.data_dir.join(HISTORY_DIR).join(stream)
    }

    pub(crate) fn runtime_path(&self, plugin_id: &str) -> PathBuf {
        self.data_dir.join(RUNTIME_DIR).join(format!("{plugin_id}.json"))
    }

    pub(crate) fn rejected_path(&self, plugin_id: &str) -> PathBuf {
        self.data_dir.join(RUNTIME_DIR).join(format!("{plugin_id}.rejected.json"))
    }

    pub(crate) fn knows(&self, stream: &str) -> bool {
        self.streams().contains_key(stream)
    }

    /// Sets the key and retention new records use. A different key closes
    /// the open file, so no file mixes two keys.
    pub(crate) fn set_key(&self, stream: &str, key: PublicStreamKey, retention: Retention) {
        let mut streams = self.streams();
        match streams.get_mut(stream) {
            Some(slot) if slot.key == key => {
                slot.retention = retention;
                if let Some(w) = slot.writer.as_mut() {
                    w.set_retention(retention);
                }
            }
            _ => {
                streams.insert(stream.to_owned(), Slot { key, retention, writer: None });
            }
        }
    }

    /// Seals one record. Fails if the stream has no key yet.
    pub(crate) fn append(&self, stream: &str, record: &Value, now: DateTime<Utc>) -> AegisResult<()> {
        self.append_with(stream, record, now, Append::default()).map_err(|e| match e {
            AppendError::Full => AegisError::new(ErrorCode::Conflict, "this history stream is full"),
            AppendError::Failed(e) => e,
        })
    }

    /// Seals one record as `how` says.
    pub(crate) fn append_with(&self, stream: &str, record: &Value, now: DateTime<Utc>, how: Append) -> Result<(), AppendError> {
        let mut streams = self.streams();
        let slot = streams.get_mut(stream).ok_or_else(|| AegisError::new(ErrorCode::VaultLocked, "this history stream has no key yet; unlock AegisWin once"))?;
        let writer = slot.writer(self.dir(stream), stream);
        if how.chained && !writer.is_chained() {
            return Err(AppendError::Failed(AegisError::new(ErrorCode::VaultLocked, "the approval record is not ready; unlock AegisWin once")));
        }
        if let Some(limit) = how.limit {
            if writer.stream_bytes().map_err(io_err)? >= limit {
                return Err(AppendError::Full);
            }
        }
        writer.append(record, now).map_err(io_err)?;
        if how.sync {
            writer.sync().map_err(io_err)?;
        }
        Ok(())
    }

    /// Bytes in a stream's files, when it has a writer.
    pub(crate) fn bytes(&self, stream: &str) -> Option<u64> {
        self.streams().get_mut(stream)?.writer.as_mut()?.stream_bytes().ok()
    }

    /// The chain's last record, when the stream is chained in this run.
    pub(crate) fn chain_head(&self, stream: &str) -> Option<Head> {
        let mut streams = self.streams();
        Some(streams.get_mut(stream)?.writer.as_mut()?.chain_mut()?.head().clone())
    }

    /// Closes the stream's file and moves to a new MAC session. A stream
    /// not yet chained in this run starts from `head`, worked out under the
    /// same lock so no record lands in between. Returns the chain's head.
    pub(crate) fn turn_session(&self, stream: &str, session: Session, head: impl FnOnce() -> AegisResult<Head>) -> AegisResult<Head> {
        let mut streams = self.streams();
        let slot = streams.get_mut(stream).ok_or_else(|| AegisError::new(ErrorCode::VaultLocked, "this history stream has no key yet"))?;
        let writer = slot.writer(self.dir(stream), stream);
        writer.close().map_err(io_err)?;
        match writer.chain_mut() {
            Some(chain) => {
                chain.set_session(session);
                Ok(chain.head().clone())
            }
            None => {
                let head = head()?;
                writer.set_chain(ChainWriter::new(head.clone(), session));
                Ok(head)
            }
        }
    }

    /// Starts the stream's chain again from nothing (after a purge).
    pub(crate) fn restart_chain(&self, stream: &str, session: Session) -> AegisResult<()> {
        let mut streams = self.streams();
        let slot = streams.get_mut(stream).ok_or_else(|| AegisError::new(ErrorCode::VaultLocked, "this history stream has no key yet"))?;
        slot.writer(self.dir(stream), stream).set_chain(ChainWriter::new(Head::genesis(), session));
        Ok(())
    }

    /// Forces every stream's pending frames to disk once 30 seconds have passed.
    pub(crate) fn sync_due(&self) {
        for slot in self.streams().values_mut() {
            if let Some(w) = slot.writer.as_mut() {
                let _ = w.sync_if_due();
            }
        }
    }

    /// Syncs and closes every open file. Called on lock, so the HPKE
    /// context in memory while locked never covers frames written before.
    /// The writers stay, so a chained stream carries on from where it was.
    pub(crate) fn close_all(&self) {
        for slot in self.streams().values_mut() {
            if let Some(w) = slot.writer.as_mut() {
                let _ = w.close();
            }
        }
    }

    /// Reads a stream with its private key. The writer is held still meanwhile.
    pub(crate) fn read(&self, stream: &str, key: &StreamKey, since: Option<NaiveDate>) -> AegisResult<StreamRead> {
        let mut streams = self.streams();
        if let Some(w) = streams.get_mut(stream).and_then(|s| s.writer.as_mut()) {
            w.sync().map_err(io_err)?;
        }
        history::read_stream_since(&self.dir(stream), stream, key, since).map_err(io_err)
    }

    /// Reads a stream file by file, checking MACs with `macs`. Also names
    /// the file still open, which has no `close` frame yet.
    pub(crate) fn read_files(&self, stream: &str, key: &StreamKey, since: Option<NaiveDate>, macs: &mut MacCheck) -> AegisResult<(Vec<FileRead>, Option<String>)> {
        let mut streams = self.streams();
        let writer = streams.get_mut(stream).and_then(|s| s.writer.as_mut());
        let current = match writer {
            Some(w) => {
                w.sync().map_err(io_err)?;
                w.current_name().map(str::to_owned)
            }
            None => None,
        };
        Ok((history::read_files(&self.dir(stream), stream, key, since, Some(macs)).map_err(io_err)?, current))
    }

    /// Retention for a chained stream (ADR 0004 §4.3): each file started
    /// before `oldest` is read, a `pruned` record naming its range and last
    /// hash is written and synced, and only then is the file deleted.
    pub(crate) fn prune_chained(&self, stream: &str, key: &StreamKey, oldest: NaiveDate, now: DateTime<Utc>) -> AegisResult<usize> {
        let mut streams = self.streams();
        let dir = self.dir(stream);
        let slot = streams.get_mut(stream).ok_or_else(|| AegisError::new(ErrorCode::VaultLocked, "this history stream has no key yet"))?;
        let writer = slot.writer(dir.clone(), stream);
        if !writer.is_chained() {
            return Ok(0);
        }
        let keep = writer.current_name().map(str::to_owned);
        let mut removed = 0;
        for name in history::files_before(&dir, oldest, keep.as_deref()).map_err(io_err)? {
            let file = history::read_named(&dir, &name, stream, key, None).map_err(io_err)?;
            let last = file.frames.iter().filter_map(|f| Some((f.record.get("seq")?.as_u64()?, f))).max_by_key(|(seq, _)| *seq);
            let first = file.frames.iter().filter_map(|f| f.record.get("seq")?.as_u64()).min();
            let mut record = serde_json::json!({ "event": "pruned", "segment": name, "records": file.frames.len(), "at": now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true) });
            if let (Some(from), Some((to, frame))) = (first, last) {
                record["from"] = from.into();
                record["to"] = to.into();
                record["lastHash"] = hex::encode(frame.hash).into();
            }
            writer.append(&record, now).map_err(io_err)?;
            writer.sync().map_err(io_err)?;
            std::fs::remove_file(dir.join(&name)).map_err(io_err)?;
            writer.forget_size();
            removed += 1;
        }
        Ok(removed)
    }

    /// Switches the stream to `key` and deletes every file, in one step, so
    /// no record lands in between under the old key.
    pub(crate) fn purge(&self, stream: &str, key: PublicStreamKey, retention: Retention) -> AegisResult<usize> {
        let mut streams = self.streams();
        // Replacing the slot drops the old writer, which closes its file.
        streams.insert(stream.to_owned(), Slot { key, retention, writer: None });
        history::purge(&self.dir(stream)).map_err(io_err)
    }

    /// Applies retention to every stream with a known key (at startup and unlock).
    pub(crate) fn enforce_retention(&self, now: DateTime<Utc>) {
        for (stream, slot) in self.streams().iter() {
            // A chained stream is pruned by the engine, which records what it removes.
            if stream == APPROVALS_STREAM || slot.writer.as_ref().is_some_and(SegmentWriter::is_chained) {
                continue;
            }
            let keep = slot.writer.as_ref().and_then(|w| w.current_file()).map(Path::to_path_buf);
            let _ = history::enforce_retention(&self.dir(stream), slot.retention, now, keep.as_deref());
        }
    }

    pub(crate) fn read_runtime(&self, plugin_id: &str) -> Option<Result<RuntimeFile, String>> {
        let raw = match std::fs::read(self.runtime_path(plugin_id)) {
            Ok(raw) => raw,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
            Err(e) => return Some(Err(e.to_string())),
        };
        Some(serde_json::from_slice(&raw).map_err(|e| e.to_string()))
    }

    pub(crate) fn write_runtime(&self, plugin_id: &str, file: Option<&RuntimeFile>) -> AegisResult<()> {
        let path = self.runtime_path(plugin_id);
        match file {
            Some(file) => {
                let bytes = serde_json::to_vec_pretty(file).map_err(|e| AegisError::new(ErrorCode::Internal, e.to_string()))?;
                crate::vault::write_atomic(&path, &bytes).map_err(io_err)
            }
            None => match std::fs::remove_file(&path) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => Err(io_err(e)),
                _ => Ok(()),
            },
        }
    }

    /// Moves a runtime file aside so it is never resumed from.
    pub(crate) fn reject_runtime(&self, plugin_id: &str) {
        let _ = std::fs::rename(self.runtime_path(plugin_id), self.rejected_path(plugin_id));
    }

    /// Plugin ids with a runtime file on disk (including unexpected ones).
    pub(crate) fn runtime_files(&self) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(self.data_dir.join(RUNTIME_DIR)) else { return Vec::new() };
        entries
            .filter_map(|e| e.ok()?.file_name().to_str()?.strip_suffix(".json").map(str::to_owned))
            .filter(|id| !id.ends_with(".rejected"))
            .collect()
    }
}

/// A plugin's handle to its own history stream. Holds no key: every call
/// goes back to the engine. Writing works while locked once the stream has a
/// key; reading, purging and settings need the vault unlocked.
#[derive(Clone)]
pub struct HistoryHandle {
    engine: Weak<Engine>,
    stream: String,
}

impl std::fmt::Debug for HistoryHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoryHandle").field("stream", &self.stream).finish()
    }
}

impl HistoryHandle {
    pub(crate) fn new(engine: Weak<Engine>, stream: &str) -> Self {
        Self { engine, stream: stream.to_owned() }
    }

    pub fn stream(&self) -> &str {
        &self.stream
    }

    fn engine(&self) -> AegisResult<std::sync::Arc<Engine>> {
        self.engine.upgrade().ok_or_else(|| AegisError::new(ErrorCode::Internal, "engine is shutting down"))
    }

    /// Seals one record (a JSON object). The engine adds `at`, the time it
    /// was written, replacing any `at` the plugin set.
    pub fn append(&self, record: Value) -> AegisResult<()> {
        self.engine()?.history_append(&self.stream, record)
    }

    /// Decrypts the stream, oldest first, skipping files from before `since`.
    pub fn read(&self, since: Option<NaiveDate>) -> AegisResult<StreamRead> {
        self.engine()?.history_read(&self.stream, since)
    }

    /// Deletes every file of the stream and replaces its keypair.
    pub fn purge(&self) -> AegisResult<usize> {
        self.engine()?.history_purge(&self.stream)
    }

    pub fn retention(&self) -> AegisResult<Retention> {
        self.engine()?.history_retention(&self.stream)
    }

    pub fn set_retention(&self, retention: Retention) -> AegisResult<()> {
        self.engine()?.set_history_retention(&self.stream, retention)
    }

    /// Records what this plugin runs while locked (`None`: nothing). Saved in
    /// the vault and written to the runtime file.
    pub fn set_runtime(&self, plugin: Option<Value>) -> AegisResult<()> {
        self.engine()?.set_runtime(&self.stream, plugin)
    }

    /// When AegisWin itself was changing the system since `since`, from the
    /// engine's approval record, so events can be labelled "during AegisWin
    /// repair". Gives times and tool names only. Needs the vault unlocked.
    pub fn change_windows(&self, since: NaiveDate) -> AegisResult<Vec<ChangeWindow>> {
        self.engine()?.change_windows(since)
    }

}
