//! Encrypted, append-only history files (ADR 0002 §5).
//!
//! Each stream (`usage-monitor`, `approvals`) has its own X25519 keypair.
//! Writing needs only the public key, so AegisWin can record while locked
//! but can never read back what it wrote: the private key lives only in the
//! vault. Files use HPKE (RFC 9180) base mode with DHKEM(X25519,
//! HKDF-SHA256), HKDF-SHA256 and AES-256-GCM, through the `hpke` crate.
//!
//! A segment file is a header (magic, version, key id, the HPKE encapsulated
//! key) followed by frames: a 4-byte little-endian length, then one sealed
//! JSON record. Each frame's additional data is the SHA-256 of the header
//! plus the frame's index, so frames cannot be moved between files or
//! reordered. One HPKE context covers one file and is dropped when the file
//! closes; the writer closes the file on lock, so the context held while
//! locked never covers frames written before.
//!
//! A chained stream (the `approvals` record, ADR 0004 §4) writes format 2
//! files: each frame's plaintext is the record's JSON with its chain fields,
//! followed by a 32-byte MAC ([`crate::chain`]). Such a file starts with an
//! `open` frame and, when closed cleanly, ends with a `close` frame. Format 1
//! files (plain JSON frames) are still read, as records from before the
//! integrity checks.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chrono::{DateTime, NaiveDate, Utc};
use hpke::aead::{AeadCtxS, AesGcm256};
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::chain::{self, ChainWriter, Head, MacCheck};
use crate::secret::Secret;

type Kem = X25519HkdfSha256;
type Aead = AesGcm256;
type Kdf = HkdfSha256;
type PublicKey = <Kem as hpke::Kem>::PublicKey;
type PrivateKey = <Kem as hpke::Kem>::PrivateKey;
type EncappedKey = <Kem as hpke::Kem>::EncappedKey;

const MAGIC: &[u8; 4] = b"AGHS";
/// Plain JSON frames.
const FORMAT_PLAIN: u8 = 1;
/// Chained frames: JSON with `seq`, `prev`, `sess` and `mi`, then a MAC.
const FORMAT_CHAINED: u8 = 2;
const KEY_ID_LEN: usize = 8;
const ENC_LEN: usize = 32;
const HEADER_LEN: usize = MAGIC.len() + 1 + KEY_ID_LEN + ENC_LEN;
/// Batches are forced to disk at least this often, and on close.
pub const SYNC_EVERY: Duration = Duration::from_secs(30);
/// A new file starts each UTC day, or when the current one reaches this size.
pub const MAX_SEGMENT_BYTES: u64 = 4 * 1024 * 1024;
/// A record larger than this is refused rather than written.
pub const MAX_RECORD_BYTES: usize = 64 * 1024;

/// A stream's keypair, kept only inside the vault.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamKey {
    pub key_id: String,
    pub public_key: String,
    private_key: Secret,
}

impl std::fmt::Debug for StreamKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamKey").field("key_id", &self.key_id).finish_non_exhaustive()
    }
}

/// The half of a stream key that may sit outside the vault (`runtime.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicStreamKey {
    pub key_id: String,
    pub public_key: String,
}

impl StreamKey {
    pub fn generate() -> Self {
        let (sk, pk) = Kem::gen_keypair(&mut OsRng);
        let public = pk.to_bytes();
        let private = Zeroizing::new(sk.to_bytes().to_vec());
        Self { key_id: key_id(&public), public_key: hex::encode(public), private_key: Secret::new(hex::encode(private.as_slice())) }
    }

    pub fn public(&self) -> PublicStreamKey {
        PublicStreamKey { key_id: self.key_id.clone(), public_key: self.public_key.clone() }
    }

    fn private(&self) -> io::Result<PrivateKey> {
        let bytes = Zeroizing::new(hex::decode(self.private_key.expose()).map_err(|_| invalid("history private key is not hex"))?);
        PrivateKey::from_bytes(&bytes).map_err(|_| invalid("history private key is damaged"))
    }
}

impl PublicStreamKey {
    fn key(&self) -> io::Result<PublicKey> {
        let bytes = hex::decode(&self.public_key).map_err(|_| invalid("history public key is not hex"))?;
        if key_id(&bytes) != self.key_id {
            return Err(invalid("history public key does not match its key id"));
        }
        PublicKey::from_bytes(&bytes).map_err(|_| invalid("history public key is damaged"))
    }

    /// True when the key decodes and matches its id.
    pub fn is_valid(&self) -> bool {
        self.key().is_ok()
    }
}

/// First 8 bytes of SHA-256 of the public key, as hex.
fn key_id(public: &[u8]) -> String {
    hex::encode(&Sha256::digest(public)[..KEY_ID_LEN])
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_owned())
}

/// HPKE `info`: binds a file's context to its stream and key.
fn info(stream: &str, key_id: &str) -> Vec<u8> {
    // Both formats share this label; the header, which holds the version,
    // is bound into every frame's additional data.
    format!("aegis-win history v1|{stream}|{key_id}").into_bytes()
}

fn frame_aad(header_hash: &[u8; 32], index: u64) -> [u8; 40] {
    let mut aad = [0u8; 40];
    aad[..32].copy_from_slice(header_hash);
    aad[32..].copy_from_slice(&index.to_le_bytes());
    aad
}

/// `rand_core` 0.6 interface over the OS generator (`getrandom`).
struct OsRng;

impl rand_core::RngCore for OsRng {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }
    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::fill(dest).expect("the OS random number generator is unavailable");
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for OsRng {}

/// How long a stream keeps its files. Oldest files go first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Retention {
    pub max_days: u32,
    pub max_mb: u32,
}

impl Retention {
    pub const MONITOR_DEFAULT: Self = Self { max_days: 14, max_mb: 64 };
    pub const APPROVALS_DEFAULT: Self = Self { max_days: 90, max_mb: 64 };
    pub const DAYS: std::ops::RangeInclusive<u32> = 1..=90;
    pub const MB: std::ops::RangeInclusive<u32> = 8..=512;

    pub fn is_valid(&self) -> bool {
        Self::DAYS.contains(&self.max_days) && Self::MB.contains(&self.max_mb)
    }
}

/// A segment file's name: `seg-YYYYMMDD-NNN.bin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SegmentName {
    day: NaiveDate,
    n: u32,
}

impl SegmentName {
    fn parse(name: &str) -> Option<Self> {
        let rest = name.strip_prefix("seg-")?.strip_suffix(".bin")?;
        let (day, n) = rest.split_once('-')?;
        if day.len() != 8 || n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Some(Self { day: NaiveDate::parse_from_str(day, "%Y%m%d").ok()?, n: n.parse().ok()? })
    }

    fn file_name(&self) -> String {
        format!("seg-{}-{:03}.bin", self.day.format("%Y%m%d"), self.n)
    }
}

/// The segment files in `dir`, oldest first, with their sizes.
fn segments(dir: &Path) -> io::Result<Vec<(SegmentName, PathBuf, u64)>> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry?;
        if let Some(name) = entry.file_name().to_str().and_then(SegmentName::parse) {
            let meta = entry.metadata()?;
            if meta.is_file() {
                out.push((name, entry.path(), meta.len()));
            }
        }
    }
    out.sort_by_key(|(name, ..)| *name);
    Ok(out)
}

struct OpenSegment {
    file: File,
    path: PathBuf,
    name: String,
    day: NaiveDate,
    ctx: AeadCtxS<Aead, Kdf, Kem>,
    header_hash: [u8; 32],
    index: u64,
    bytes: u64,
    dirty: bool,
}

/// Appends sealed records to one stream's directory. Holds only the public key.
pub struct SegmentWriter {
    dir: PathBuf,
    stream: String,
    key: PublicStreamKey,
    retention: Retention,
    open: Option<OpenSegment>,
    last_sync: Instant,
    /// Set for a chained stream, which also skips retention here: the
    /// engine prunes it while unlocked, recording what it removed.
    chain: Option<ChainWriter>,
    /// Bytes in the stream's files, counted once and then kept up to date.
    total: Option<u64>,
}

fn stamp(now: DateTime<Utc>) -> String {
    now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

impl SegmentWriter {
    pub fn new(dir: impl Into<PathBuf>, stream: &str, key: PublicStreamKey, retention: Retention) -> Self {
        Self { dir: dir.into(), stream: stream.to_owned(), key, retention, open: None, last_sync: Instant::now(), chain: None, total: None }
    }

    /// Makes this a chained stream, continuing from `chain`'s head.
    pub fn set_chain(&mut self, chain: ChainWriter) {
        self.chain = Some(chain);
    }

    pub fn chain_mut(&mut self) -> Option<&mut ChainWriter> {
        self.chain.as_mut()
    }

    pub fn is_chained(&self) -> bool {
        self.chain.is_some()
    }

    /// Bytes in the stream's files, including frames not yet synced.
    pub fn stream_bytes(&mut self) -> io::Result<u64> {
        if let Some(total) = self.total {
            return Ok(total);
        }
        let total = segments(&self.dir)?.iter().map(|(.., b)| b).sum();
        self.total = Some(total);
        Ok(total)
    }

    /// Counts the files again next time (after files were deleted).
    pub fn forget_size(&mut self) {
        self.total = None;
    }

    pub fn key(&self) -> &PublicStreamKey {
        &self.key
    }

    pub fn set_retention(&mut self, retention: Retention) {
        self.retention = retention;
    }

    /// Seals one record. Starts a new file on a new UTC day, when the file is
    /// full, or after [`Self::close`]; retention runs whenever a file starts.
    pub fn append(&mut self, record: &Value, now: DateTime<Utc>) -> io::Result<()> {
        if serde_json::to_vec(record).map_err(|e| invalid(&e.to_string()))?.len() > MAX_RECORD_BYTES {
            return Err(invalid("history record is too large"));
        }
        let day = now.date_naive();
        let rotate = self.open.as_ref().is_none_or(|o| o.day != day || o.bytes >= MAX_SEGMENT_BYTES);
        if rotate {
            self.close()?;
            self.start(day, now)?;
        }
        self.write(record)?;
        if self.last_sync.elapsed() >= SYNC_EVERY {
            self.sync()?;
        }
        Ok(())
    }

    /// Seals one frame into the open file. A chained stream's state moves on
    /// only once the frame is written, so a failed write leaves no gap.
    fn write(&mut self, record: &Value) -> io::Result<()> {
        let seg = self.open.as_mut().ok_or_else(|| invalid("no history file is open"))?;
        let sealed = self.chain.as_ref().map(|c| c.seal(record)).transpose()?;
        let plaintext = match &sealed {
            Some(s) => s.plaintext.clone(),
            None => Zeroizing::new(serde_json::to_vec(record).map_err(|e| invalid(&e.to_string()))?),
        };
        let aad = frame_aad(&seg.header_hash, seg.index);
        let ciphertext = seg.ctx.seal(&plaintext, &aad).map_err(|e| invalid(&format!("sealing failed: {e}")))?;
        let len = u32::try_from(ciphertext.len()).map_err(|_| invalid("frame too large"))?;
        let mut frame = Vec::with_capacity(4 + ciphertext.len());
        frame.extend_from_slice(&len.to_le_bytes());
        frame.extend_from_slice(&ciphertext);
        if let Err(e) = seg.file.write_all(&frame) {
            // A partly written frame would misalign every later one: drop
            // this file (its tail reads as torn) and start a new one next time.
            self.open = None;
            return Err(e);
        }
        seg.index += 1;
        seg.bytes += frame.len() as u64;
        seg.dirty = true;
        if let Some(total) = self.total.as_mut() {
            *total += frame.len() as u64;
        }
        if let (Some(chain), Some(sealed)) = (self.chain.as_mut(), sealed) {
            chain.commit(sealed);
        }
        Ok(())
    }

    fn start(&mut self, day: NaiveDate, now: DateTime<Utc>) -> io::Result<()> {
        fs::create_dir_all(&self.dir)?;
        let next = segments(&self.dir)?.iter().filter(|(n, ..)| n.day == day).map(|(n, ..)| n.n + 1).max().unwrap_or(1);
        let name = SegmentName { day, n: next };
        let path = self.dir.join(name.file_name());
        let pk = self.key.key()?;
        let (enc, ctx) = hpke::setup_sender::<Aead, Kdf, Kem, _>(&OpModeS::Base, &pk, &info(&self.stream, &self.key.key_id), &mut OsRng)
            .map_err(|e| invalid(&format!("HPKE setup failed: {e}")))?;
        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(MAGIC);
        header.push(if self.chain.is_some() { FORMAT_CHAINED } else { FORMAT_PLAIN });
        header.extend_from_slice(&hex::decode(&self.key.key_id).map_err(|_| invalid("key id is not hex"))?);
        header.extend_from_slice(&enc.to_bytes());
        debug_assert_eq!(header.len(), HEADER_LEN);
        let mut file = OpenOptions::new().create_new(true).append(true).open(&path)?;
        file.write_all(&header)?;
        file.sync_data()?;
        let header_hash: [u8; 32] = Sha256::digest(&header).into();
        if let Some(total) = self.total.as_mut() {
            *total += HEADER_LEN as u64;
        }
        if self.chain.is_none() {
            // Retention never removes the file just started.
            let _ = enforce_retention(&self.dir, self.retention, now, Some(&path));
            self.forget_size();
        }
        let name = name.file_name();
        self.open = Some(OpenSegment { file, path, name: name.clone(), day, ctx, header_hash, index: 0, bytes: HEADER_LEN as u64, dirty: false });
        if self.chain.is_some() {
            self.write(&serde_json::json!({ "event": "open", "segment": name, "at": stamp(now) }))?;
        }
        Ok(())
    }

    /// Syncs when [`SYNC_EVERY`] has passed since the last sync, so frames
    /// reach the disk on time even when no further record arrives.
    pub fn sync_if_due(&mut self) -> io::Result<()> {
        if self.last_sync.elapsed() >= SYNC_EVERY {
            self.sync()?;
        }
        Ok(())
    }

    /// Forces written frames to disk.
    pub fn sync(&mut self) -> io::Result<()> {
        self.last_sync = Instant::now();
        if let Some(seg) = self.open.as_mut().filter(|s| s.dirty) {
            seg.file.sync_data()?;
            seg.dirty = false;
        }
        Ok(())
    }

    /// Syncs and closes the current file, dropping its HPKE context. The
    /// next record starts a new file. A chained file gets its `close` frame
    /// first; if that cannot be written, the file reads as not closed.
    pub fn close(&mut self) -> io::Result<()> {
        if let Some(seg) = self.open.as_ref().filter(|_| self.chain.is_some()) {
            let close = serde_json::json!({ "event": "close", "segment": seg.name, "records": seg.index, "at": stamp(Utc::now()) });
            let _ = self.write(&close);
        }
        let result = self.sync();
        self.open = None;
        result
    }

    /// The file being written, if any.
    pub fn current_file(&self) -> Option<&Path> {
        self.open.as_ref().map(|s| s.path.as_path())
    }

    /// The name of the file being written, if any.
    pub fn current_name(&self) -> Option<&str> {
        self.open.as_ref().map(|s| s.name.as_str())
    }
}

impl Drop for SegmentWriter {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// What reading one file found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileStatus {
    /// Every frame authenticated.
    Ok,
    /// The last frame was incomplete or did not authenticate (a power cut
    /// mid-write); it was dropped.
    Truncated,
    /// A frame that is not the last did not authenticate; reading stopped there.
    Corrupt,
    /// Written under a different key (replaced by a purge, or not this vault's).
    OtherKey,
    /// Not a history file, or its header is damaged.
    Unreadable,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileReport {
    pub name: String,
    pub status: FileStatus,
    pub records: usize,
    pub bytes: u64,
}

/// One record as read, with what the integrity check needs.
#[derive(Debug, Clone)]
pub struct Frame {
    pub record: Value,
    /// SHA-256 of the frame's whole plaintext (the next record's `prev`).
    pub hash: [u8; 32],
    /// Whether a chained frame's MAC checked out; `None` for format 1, or
    /// when read without the session keys.
    pub mac_ok: Option<bool>,
}

/// One file as read.
#[derive(Debug, Clone)]
pub struct FileRead {
    pub name: String,
    pub status: FileStatus,
    /// A format 2 (chained) file.
    pub chained: bool,
    pub bytes: u64,
    pub frames: Vec<Frame>,
}

impl FileRead {
    pub fn report(&self) -> FileReport {
        FileReport { name: self.name.clone(), status: self.status, records: self.frames.len(), bytes: self.bytes }
    }
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamRead {
    /// Every readable record, oldest file first, in write order.
    pub records: Vec<Value>,
    pub files: Vec<FileReport>,
}

/// Decrypts every file of a stream. Needs the private key (unlocked only).
pub fn read_stream(dir: &Path, stream: &str, key: &StreamKey) -> io::Result<StreamRead> {
    read_stream_since(dir, stream, key, None)
}

/// Like [`read_stream`], but skips files started before `since` (UTC day).
/// A file holds records from its own day only, so nothing later is missed.
pub fn read_stream_since(dir: &Path, stream: &str, key: &StreamKey, since: Option<NaiveDate>) -> io::Result<StreamRead> {
    let mut out = StreamRead::default();
    for file in read_files(dir, stream, key, since, None)? {
        out.files.push(file.report());
        out.records.extend(file.frames.into_iter().map(|f| f.record));
    }
    Ok(out)
}

/// Reads every file of a stream (from `since`), file by file, checking
/// chained frames' MACs when `macs` is given.
pub fn read_files(dir: &Path, stream: &str, key: &StreamKey, since: Option<NaiveDate>, mut macs: Option<&mut MacCheck>) -> io::Result<Vec<FileRead>> {
    let sk = key.private()?;
    let mut out = Vec::new();
    for (name, path, bytes) in segments(dir)? {
        if since.is_some_and(|day| name.day < day) {
            continue;
        }
        out.push(read_file(&path, name.file_name(), bytes, stream, key, &sk, macs.as_deref_mut()));
    }
    Ok(out)
}

fn read_file(path: &Path, name: String, bytes: u64, stream: &str, key: &StreamKey, sk: &PrivateKey, macs: Option<&mut MacCheck>) -> FileRead {
    let (status, chained, frames) = match fs::read(path) {
        Ok(raw) => read_segment(&raw, stream, key, sk, macs),
        Err(_) => (FileStatus::Unreadable, false, Vec::new()),
    };
    FileRead { name, status, chained, bytes, frames }
}

/// The last record of a chained stream whose MAC checks out, newest file
/// first, so the writer can carry on from it after a restart.
pub fn chain_tail(dir: &Path, stream: &str, key: &StreamKey, macs: &mut MacCheck) -> io::Result<Option<Head>> {
    let sk = key.private()?;
    for (name, path, bytes) in segments(dir)?.into_iter().rev() {
        let file = read_file(&path, name.file_name(), bytes, stream, key, &sk, Some(macs));
        if !file.chained {
            continue;
        }
        let tail = file.frames.iter().rev().filter(|f| f.mac_ok == Some(true)).find_map(|f| Some(Head { seq: f.record.get("seq")?.as_u64()?, hash: hex::encode(f.hash) }));
        if tail.is_some() {
            return Ok(tail);
        }
    }
    Ok(None)
}

/// Segment files of a stream started before `oldest` (UTC day), oldest
/// first, except `keep`.
pub fn files_before(dir: &Path, oldest: NaiveDate, keep: Option<&str>) -> io::Result<Vec<String>> {
    Ok(segments(dir)?.into_iter().filter(|(n, ..)| n.day < oldest).map(|(n, ..)| n.file_name()).filter(|n| Some(n.as_str()) != keep).collect())
}

/// Reads one named file of a stream.
pub fn read_named(dir: &Path, name: &str, stream: &str, key: &StreamKey, macs: Option<&mut MacCheck>) -> io::Result<FileRead> {
    let sk = key.private()?;
    let path = dir.join(name);
    let bytes = fs::metadata(&path)?.len();
    Ok(read_file(&path, name.to_owned(), bytes, stream, key, &sk, macs))
}

fn read_segment(raw: &[u8], stream: &str, key: &StreamKey, sk: &PrivateKey, mut macs: Option<&mut MacCheck>) -> (FileStatus, bool, Vec<Frame>) {
    if raw.len() < HEADER_LEN || &raw[..4] != MAGIC || !matches!(raw[4], FORMAT_PLAIN | FORMAT_CHAINED) {
        return (FileStatus::Unreadable, false, Vec::new());
    }
    let chained = raw[4] == FORMAT_CHAINED;
    if hex::encode(&raw[5..5 + KEY_ID_LEN]) != key.key_id {
        return (FileStatus::OtherKey, chained, Vec::new());
    }
    let header = &raw[..HEADER_LEN];
    let Ok(enc) = EncappedKey::from_bytes(&header[5 + KEY_ID_LEN..]) else {
        return (FileStatus::Unreadable, chained, Vec::new());
    };
    let Ok(mut ctx) = hpke::setup_receiver::<Aead, Kdf, Kem>(&OpModeR::Base, sk, &enc, &info(stream, &key.key_id)) else {
        return (FileStatus::Unreadable, chained, Vec::new());
    };
    let header_hash: [u8; 32] = Sha256::digest(header).into();
    let mut records: Vec<Frame> = Vec::new();
    let mut at = HEADER_LEN;
    let mut index = 0u64;
    while at < raw.len() {
        let rest = &raw[at..];
        if rest.len() < 4 {
            return (FileStatus::Truncated, chained, records);
        }
        let len = u32::from_le_bytes(rest[..4].try_into().expect("4 bytes")) as usize;
        if rest.len() - 4 < len {
            return (FileStatus::Truncated, chained, records);
        }
        let last = rest.len() - 4 == len;
        let opened = ctx.open(&rest[4..4 + len], &frame_aad(&header_hash, index)).ok().map(Zeroizing::new);
        let frame = opened.and_then(|plain| {
            let hash: [u8; 32] = Sha256::digest(plain.as_slice()).into();
            if chained {
                let (body, tag) = chain::split_frame(&plain)?;
                let record = serde_json::from_slice::<Value>(body).ok()?;
                let mac_ok = macs.as_deref_mut().map(|m| m.check(&record, body, tag));
                Some(Frame { record, hash, mac_ok })
            } else {
                Some(Frame { record: serde_json::from_slice::<Value>(&plain).ok()?, hash, mac_ok: None })
            }
        });
        match frame {
            Some(frame) => records.push(frame),
            None if last => return (FileStatus::Truncated, chained, records),
            None => return (FileStatus::Corrupt, chained, records),
        }
        at += 4 + len;
        index += 1;
    }
    (FileStatus::Ok, chained, records)
}

/// Deletes the oldest files until the stream is within its limits. Needs no
/// key, so it also runs while locked. `keep` is never deleted.
pub fn enforce_retention(dir: &Path, retention: Retention, now: DateTime<Utc>, keep: Option<&Path>) -> io::Result<usize> {
    let files = segments(dir)?;
    let oldest_day = now.date_naive() - chrono::Days::new(u64::from(retention.max_days.saturating_sub(1)));
    let max_bytes = u64::from(retention.max_mb) * 1024 * 1024;
    let mut total: u64 = files.iter().map(|(.., b)| b).sum();
    let mut removed = 0;
    for (name, path, bytes) in files {
        if keep == Some(path.as_path()) {
            continue;
        }
        if name.day >= oldest_day && total <= max_bytes {
            break;
        }
        fs::remove_file(&path)?;
        total -= bytes;
        removed += 1;
    }
    Ok(removed)
}

/// Deletes every file of a stream. The caller replaces the stream's key.
pub fn purge(dir: &Path) -> io::Result<usize> {
    let files = segments(dir)?;
    for (_, path, _) in &files {
        fs::remove_file(path)?;
    }
    Ok(files.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    fn at(day: u32, hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, day, hour, 0, 0).unwrap()
    }

    fn writer(dir: &Path, key: &StreamKey) -> SegmentWriter {
        SegmentWriter::new(dir, "usage-monitor", key.public(), Retention::MONITOR_DEFAULT)
    }

    #[test]
    fn records_round_trip_and_nothing_is_readable_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let key = StreamKey::generate();
        let mut w = writer(dir.path(), &key);
        for i in 0..3 {
            w.append(&json!({ "kind": "heartbeat", "secretish": "game.exe", "n": i }), at(8, 10)).unwrap();
        }
        w.close().unwrap();
        let files = segments(dir.path()).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].0.file_name(), "seg-20261108-001.bin");
        let raw = fs::read(&files[0].1).unwrap();
        assert!(!raw.windows(8).any(|w| w == b"game.exe"), "plaintext must not reach the disk");
        assert!(!raw.windows(9).any(|w| w == b"heartbeat"));

        let read = read_stream(dir.path(), "usage-monitor", &key).unwrap();
        assert_eq!(read.records.iter().map(|r| r["n"].as_i64().unwrap()).collect::<Vec<_>>(), vec![0, 1, 2]);
        assert_eq!(read.files[0].status, FileStatus::Ok);
        assert_eq!(read.files[0].records, 3);
    }

    #[test]
    fn the_writer_cannot_read_and_other_keys_or_streams_cannot_open_it() {
        let dir = tempfile::tempdir().unwrap();
        let key = StreamKey::generate();
        let mut w = writer(dir.path(), &key);
        w.append(&json!({ "n": 1 }), at(8, 10)).unwrap();
        w.close().unwrap();
        // A different keypair: the file names another key.
        let other = StreamKey::generate();
        assert_eq!(read_stream(dir.path(), "usage-monitor", &other).unwrap().files[0].status, FileStatus::OtherKey);
        // The same key under another stream's name: the context does not match.
        let read = read_stream(dir.path(), "approvals", &key).unwrap();
        assert!(read.records.is_empty());
        assert_eq!(read.files[0].status, FileStatus::Truncated, "the only frame fails to authenticate");
    }

    #[test]
    fn a_torn_last_frame_is_dropped_and_a_bad_middle_frame_marks_the_file_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let key = StreamKey::generate();
        let mut w = writer(dir.path(), &key);
        for i in 0..3 {
            w.append(&json!({ "n": i }), at(8, 10)).unwrap();
        }
        w.close().unwrap();
        let path = segments(dir.path()).unwrap()[0].1.clone();
        let good = fs::read(&path).unwrap();

        // Power cut mid-write: the last frame is cut short.
        fs::write(&path, &good[..good.len() - 5]).unwrap();
        let read = read_stream(dir.path(), "usage-monitor", &key).unwrap();
        assert_eq!((read.files[0].status, read.records.len()), (FileStatus::Truncated, 2));

        // A flipped byte in the first frame: corrupt, reading stops there.
        let mut bad = good.clone();
        bad[HEADER_LEN + 10] ^= 1;
        fs::write(&path, &bad).unwrap();
        let read = read_stream(dir.path(), "usage-monitor", &key).unwrap();
        assert_eq!((read.files[0].status, read.records.len()), (FileStatus::Corrupt, 0));

        // Swapping two frames breaks their binding to the frame index.
        let frame_len = 4 + u32::from_le_bytes(good[HEADER_LEN..HEADER_LEN + 4].try_into().unwrap()) as usize;
        let mut swapped = good[..HEADER_LEN].to_vec();
        swapped.extend_from_slice(&good[HEADER_LEN + frame_len..HEADER_LEN + 2 * frame_len]);
        swapped.extend_from_slice(&good[HEADER_LEN..HEADER_LEN + frame_len]);
        swapped.extend_from_slice(&good[HEADER_LEN + 2 * frame_len..]);
        fs::write(&path, &swapped).unwrap();
        assert_eq!(read_stream(dir.path(), "usage-monitor", &key).unwrap().files[0].status, FileStatus::Corrupt);

        // A damaged header.
        fs::write(&path, b"not a history file").unwrap();
        assert_eq!(read_stream(dir.path(), "usage-monitor", &key).unwrap().files[0].status, FileStatus::Unreadable);
    }

    #[test]
    fn a_file_moved_into_another_slot_does_not_authenticate() {
        let dir = tempfile::tempdir().unwrap();
        let key = StreamKey::generate();
        let mut w = writer(dir.path(), &key);
        w.append(&json!({ "n": 1 }), at(8, 10)).unwrap();
        w.close().unwrap();
        w.append(&json!({ "n": 2 }), at(8, 11)).unwrap();
        w.close().unwrap();
        let files = segments(dir.path()).unwrap();
        let (a, b) = (fs::read(&files[0].1).unwrap(), fs::read(&files[1].1).unwrap());
        // File B's frame after file A's header: a different HPKE context.
        let mut spliced = a[..HEADER_LEN].to_vec();
        spliced.extend_from_slice(&b[HEADER_LEN..]);
        fs::write(&files[0].1, &spliced).unwrap();
        let read = read_stream(dir.path(), "usage-monitor", &key).unwrap();
        assert_eq!(read.files[0].status, FileStatus::Truncated);
        assert_eq!(read.records, vec![json!({ "n": 2 })]);
    }

    #[test]
    fn files_rotate_on_close_new_day_and_size() {
        let dir = tempfile::tempdir().unwrap();
        let key = StreamKey::generate();
        let mut w = writer(dir.path(), &key);
        w.append(&json!({ "n": 1 }), at(8, 10)).unwrap();
        w.append(&json!({ "n": 2 }), at(8, 11)).unwrap();
        w.close().unwrap();
        assert!(w.current_file().is_none());
        w.append(&json!({ "n": 3 }), at(8, 12)).unwrap();
        w.append(&json!({ "n": 4 }), at(9, 0)).unwrap();
        let big = json!({ "pad": "x".repeat(60 * 1024) });
        for _ in 0..140 {
            w.append(&big, at(9, 1)).unwrap();
        }
        w.close().unwrap();
        let names: Vec<String> = segments(dir.path()).unwrap().iter().map(|(n, ..)| n.file_name()).collect();
        assert_eq!(&names[..3], ["seg-20261108-001.bin", "seg-20261108-002.bin", "seg-20261109-001.bin"]);
        assert_eq!(names.len(), 5, "the 4 MB limit started two more files on day 9: {names:?}");
        let read = read_stream(dir.path(), "usage-monitor", &key).unwrap();
        assert_eq!(read.records.len(), 144);
        assert!(read.files.iter().all(|f| f.status == FileStatus::Ok));
        assert!(w.append(&json!({ "pad": "x".repeat(MAX_RECORD_BYTES) }), at(9, 2)).is_err(), "oversized records are refused");
    }

    #[test]
    fn retention_removes_the_oldest_files_by_age_and_size_but_never_the_current_one() {
        let dir = tempfile::tempdir().unwrap();
        let key = StreamKey::generate();
        let mut w = SegmentWriter::new(dir.path(), "usage-monitor", key.public(), Retention { max_days: 3, max_mb: 8 });
        for day in 1..=5 {
            w.append(&json!({ "day": day }), at(day, 10)).unwrap();
        }
        w.close().unwrap();
        // Starting the day-5 file removed days 1 and 2 (the window is days 3-5).
        let days: Vec<u32> = segments(dir.path()).unwrap().iter().map(|(n, ..)| chrono::Datelike::day(&n.day)).collect();
        assert_eq!(days, vec![3, 4, 5]);

        // Size: 8 MB cap with three ~3.9 MB files keeps the newest two.
        let dir = tempfile::tempdir().unwrap();
        for n in 1..=3 {
            fs::write(dir.path().join(SegmentName { day: at(8, 0).date_naive(), n }.file_name()), vec![0u8; 3_900_000]).unwrap();
        }
        let keep = dir.path().join("seg-20261108-001.bin");
        let removed = enforce_retention(dir.path(), Retention { max_days: 14, max_mb: 8 }, at(8, 12), Some(&keep)).unwrap();
        assert_eq!(removed, 1);
        let left: Vec<String> = segments(dir.path()).unwrap().iter().map(|(n, ..)| n.file_name()).collect();
        assert_eq!(left, vec!["seg-20261108-001.bin", "seg-20261108-003.bin"], "the kept file survives; the next oldest goes");
        // Other files in the folder are never touched.
        fs::write(dir.path().join("notes.txt"), b"x").unwrap();
        assert_eq!(purge(dir.path()).unwrap(), 2);
        assert!(dir.path().join("notes.txt").exists());
        assert!(Retention::MONITOR_DEFAULT.is_valid() && Retention::APPROVALS_DEFAULT.is_valid());
        assert!(!Retention { max_days: 0, max_mb: 64 }.is_valid() && !Retention { max_days: 14, max_mb: 4 }.is_valid());
    }

    #[test]
    fn keys_are_checked_and_never_printed() {
        let key = StreamKey::generate();
        assert!(key.public().is_valid());
        assert_eq!(key.key_id.len(), 16);
        let mut forged = key.public();
        forged.public_key = StreamKey::generate().public_key;
        assert!(!forged.is_valid(), "a public key must match its id");
        let printed = format!("{key:?}");
        assert!(!printed.contains(key.private_key.expose()) && printed.contains(&key.key_id));
        let names = ["seg-20261108-001.bin", "seg-20261108-1000.bin"];
        assert!(names.iter().all(|n| SegmentName::parse(n).is_some()));
        assert!(SegmentName::parse("seg-20261108-001.bin").unwrap() < SegmentName::parse("seg-20261108-1000.bin").unwrap());
        for bad in ["seg-2026110-001.bin", "seg-20261108-.bin", "seg-20261108-0a1.bin", "x.bin", "seg-20261340-001.bin"] {
            assert!(SegmentName::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn a_chained_stream_writes_open_and_close_frames_and_macs_check_against_the_vault() {
        use crate::chain::{ChainVault, Session};
        let dir = tempfile::tempdir().unwrap();
        let key = StreamKey::generate();
        let (session, id, stored) = Session::start("2026-11-08");
        let mut vault = ChainVault::default();
        vault.add_session(id, stored, "2026-11-08");
        let mut w = SegmentWriter::new(dir.path(), "approvals", key.public(), Retention::APPROVALS_DEFAULT);
        w.set_chain(ChainWriter::new(Head::genesis(), session));
        w.append(&json!({ "event": "created" }), at(8, 10)).unwrap();
        w.close().unwrap();
        w.append(&json!({ "event": "decided" }), at(8, 11)).unwrap();
        assert_eq!(w.current_name(), Some("seg-20261108-002.bin"));

        let files = read_files(dir.path(), "approvals", &key, None, Some(&mut MacCheck::new(Some(&vault)))).unwrap();
        let events: Vec<Vec<&str>> = files.iter().map(|f| f.frames.iter().map(|fr| fr.record["event"].as_str().unwrap()).collect()).collect();
        assert_eq!(events, [vec!["open", "created", "close"], vec!["open", "decided"]]);
        assert!(files.iter().all(|f| f.chained && f.frames.iter().all(|fr| fr.mac_ok == Some(true))));
        assert_eq!(files[0].frames[2].record["records"], 2, "close counts the frames before it");
        let integrity = crate::chain::verify(&files, Some(&w.chain_mut().unwrap().head().checkpoint()), w.current_name());
        assert!(integrity.ok(), "{integrity:?}");
        assert_eq!(chain_tail(dir.path(), "approvals", &key, &mut MacCheck::new(Some(&vault))).unwrap().map(|h| h.seq), Some(5));

        // Someone with only the public key seals a file: it does not check out.
        let (forger, ..) = Session::start("2026-11-08");
        let mut f = SegmentWriter::new(dir.path(), "approvals", key.public(), Retention::APPROVALS_DEFAULT);
        f.set_chain(ChainWriter::new(Head { seq: 5, hash: crate::chain::GENESIS_HASH.into() }, forger));
        f.append(&json!({ "event": "created" }), at(8, 12)).unwrap();
        f.close().unwrap();
        let files = read_files(dir.path(), "approvals", &key, None, Some(&mut MacCheck::new(Some(&vault)))).unwrap();
        assert!(files[2].frames.iter().all(|fr| fr.mac_ok == Some(false)));
        assert!(matches!(crate::chain::verify(&files, None, None).problems.as_slice(), [crate::chain::Problem::Unclosed { .. }, crate::chain::Problem::Forged { events: 3, .. }]));
        // The tail ignores forged frames.
        assert_eq!(chain_tail(dir.path(), "approvals", &key, &mut MacCheck::new(Some(&vault))).unwrap().map(|h| h.seq), Some(5));
        // Format 1 files still read, as before.
        assert_eq!(read_stream(dir.path(), "approvals", &key).unwrap().records.len(), 8);
    }

    /// Known-answer test for exactly our suite: the CFRG HPKE test vector for
    /// base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM
    /// (`test-vectors-5f503c5.json` shipped with `hpke` 0.12.0; RFC 9180's
    /// Appendix A has no vector for this combination). It pins the pinned
    /// crate's key derivation and the first two sealed messages.
    #[test]
    fn the_suite_matches_the_cfrg_known_answer_vector() {
        let h = |s: &str| hex::decode(s).unwrap();
        let (sk, pk) = Kem::derive_keypair(&h("dac33b0e9db1b59dbbea58d59a14e7b5896e9bdf98fad6891e99d1686492b9ee"));
        assert_eq!(sk.to_bytes().to_vec(), h("497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d"));
        assert_eq!(pk.to_bytes().to_vec(), h("430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c"));
        let enc = EncappedKey::from_bytes(&h("6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256")).unwrap();
        let mut ctx = hpke::setup_receiver::<Aead, Kdf, Kem>(&OpModeR::Base, &sk, &enc, &h("4f6465206f6e2061204772656369616e2055726e")).unwrap();
        let pt = h("4265617574792069732074727574682c20747275746820626561757479");
        let ct0 = h("e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be9931980a41de125a925cdad859d5b7a");
        let ct1 = h("2c43aff25343fdbff864506f0818b9d87df84ea01b1a2144d23b4d40c26bf655fdf197fe40297a8aebeed5cc2d");
        assert_eq!(ctx.open(&ct0, &h("436f756e742d30")).unwrap(), pt);
        assert_eq!(ctx.open(&ct1, &h("436f756e742d31")).unwrap(), pt);
    }

    /// Checks this module drives the crate correctly: a frame on disk opens
    /// with the crate's single-shot API given the header's key and binding.
    #[test]
    fn segment_frames_match_the_crates_own_single_shot_open() {
        let dir = tempfile::tempdir().unwrap();
        let key = StreamKey::generate();
        let mut w = writer(dir.path(), &key);
        w.append(&json!({ "n": 7 }), at(8, 10)).unwrap();
        w.close().unwrap();
        let raw = fs::read(&segments(dir.path()).unwrap()[0].1).unwrap();
        let enc = EncappedKey::from_bytes(&raw[5 + KEY_ID_LEN..HEADER_LEN]).unwrap();
        let header_hash: [u8; 32] = Sha256::digest(&raw[..HEADER_LEN]).into();
        let len = u32::from_le_bytes(raw[HEADER_LEN..HEADER_LEN + 4].try_into().unwrap()) as usize;
        let plain = hpke::single_shot_open::<Aead, Kdf, Kem>(
            &OpModeR::Base,
            &key.private().unwrap(),
            &enc,
            &info("usage-monitor", &key.key_id),
            &raw[HEADER_LEN + 4..HEADER_LEN + 4 + len],
            &frame_aad(&header_hash, 0),
        )
        .unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&plain).unwrap(), json!({ "n": 7 }));
    }
}
