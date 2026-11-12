//! Integrity for the approval record (ADR 0004 §4).
//!
//! Every record of a chained stream carries `seq` (rising by one, across
//! files), `prev` (the SHA-256 of the previous record's sealed plaintext),
//! `sess` and `mi` (the MAC session and step). The plaintext of a frame is
//! the record's JSON followed by a 32-byte `HMAC-SHA256(Mi, json)`.
//!
//! `Mi` comes from a ratchet: each session starts with a random `M0` kept in
//! the vault, and after every frame the writer replaces its key with
//! `SHA-256("aegis-ratchet" || Mi)` and wipes the old one. Someone with the
//! stream's public key (which sits outside the vault) can seal frames, but
//! cannot produce a valid MAC; someone who reads process memory later gets
//! only the current key, so frames written before stay unforgeable.
//!
//! The vault also keeps a checkpoint, the last `seq` and hash AegisWin saw,
//! taken at unlock and lock (which Quit goes through). Reading compares the
//! files with it, so deleting a file or cutting the record short shows.

use std::collections::BTreeMap;
use std::io;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::history::FileRead;
use crate::secret::Secret;

type HmacSha256 = Hmac<Sha256>;

/// `prev` of the first record of a chain.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// Bytes of the MAC after a chained frame's JSON.
pub const MAC_LEN: usize = 32;
/// The furthest a reader ratchets for one frame. A larger step is a forgery
/// (anyone with the public key can seal a frame) and is refused, not computed.
const MAX_RATCHET: u64 = 1_000_000;
/// Fields the writer owns; a caller's values for them are replaced.
const CHAIN_FIELDS: [&str; 4] = ["seq", "prev", "sess", "mi"];

/// A session's starting key, as kept in the vault.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionKey {
    m0: Secret,
    /// UTC day the session started (`YYYY-MM-DD`).
    pub started: String,
    /// UTC day the next session replaced it. Kept until its records age out.
    #[serde(default)]
    pub ended: Option<String>,
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKey").field("started", &self.started).field("ended", &self.ended).finish_non_exhaustive()
    }
}

/// The last record AegisWin saw, stored in the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Checkpoint {
    pub seq: u64,
    pub hash: String,
}

/// A chained stream's secrets in the vault.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ChainVault {
    /// Session id → starting key.
    pub sessions: BTreeMap<String, SessionKey>,
    pub checkpoint: Option<Checkpoint>,
}

impl ChainVault {
    /// Adds a new session and marks the ones before it ended `today`.
    pub fn add_session(&mut self, id: String, key: SessionKey, today: &str) {
        for s in self.sessions.values_mut().filter(|s| s.ended.is_none()) {
            s.ended = Some(today.to_owned());
        }
        self.sessions.insert(id, key);
    }

    /// Forgets sessions that ended before `oldest` (a `YYYY-MM-DD` day):
    /// retention has removed every record they could have written.
    pub fn forget_sessions_before(&mut self, oldest: &str) {
        self.sessions.retain(|_, s| s.ended.as_deref().is_none_or(|end| end >= oldest));
    }
}

/// The last record of a chain: its `seq` and the hash of its plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub seq: u64,
    pub hash: String,
}

impl Head {
    pub fn genesis() -> Self {
        Self { seq: 0, hash: GENESIS_HASH.to_owned() }
    }

    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint { seq: self.seq, hash: self.hash.clone() }
    }
}

impl From<&Checkpoint> for Head {
    fn from(c: &Checkpoint) -> Self {
        Self { seq: c.seq, hash: c.hash.clone() }
    }
}

/// The writer's MAC key: only the current step is ever in memory.
pub struct Session {
    id: String,
    step: u64,
    key: Zeroizing<[u8; 32]>,
}

impl Session {
    /// A new session, and the starting key to store in the vault before it is used.
    pub fn start(today: &str) -> (Self, String, SessionKey) {
        let mut m0 = Zeroizing::new([0u8; 32]);
        getrandom::fill(m0.as_mut()).expect("the OS random number generator is unavailable");
        let mut id = [0u8; 8];
        getrandom::fill(&mut id).expect("the OS random number generator is unavailable");
        let id = hex::encode(id);
        let stored = SessionKey { m0: Secret::new(hex::encode(m0.as_ref())), started: today.to_owned(), ended: None };
        (Self { id: id.clone(), step: 0, key: m0 }, id, stored)
    }
}

fn ratchet(key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut h = Sha256::new();
    h.update(b"aegis-ratchet");
    h.update(key);
    Zeroizing::new(h.finalize().into())
}

fn mac(key: &[u8; 32], body: &[u8]) -> [u8; 32] {
    let mut m = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    m.update(body);
    m.finalize().into_bytes().into()
}

/// The chain state of a stream's writer.
pub struct ChainWriter {
    head: Head,
    session: Session,
}

/// A sealed record, waiting to be committed once its frame is on disk.
pub struct Sealed {
    /// The record's JSON followed by its MAC.
    pub plaintext: Zeroizing<Vec<u8>>,
    head: Head,
    key: Zeroizing<[u8; 32]>,
}

impl ChainWriter {
    pub fn new(head: Head, session: Session) -> Self {
        Self { head, session }
    }

    pub fn head(&self) -> &Head {
        &self.head
    }

    /// Switches to a new MAC session; the chain carries on.
    pub fn set_session(&mut self, session: Session) {
        self.session = session;
    }

    /// Adds the chain fields to `record` and MACs it. Nothing changes until
    /// [`Self::commit`], so a frame that fails to write leaves no gap.
    pub fn seal(&self, record: &Value) -> io::Result<Sealed> {
        let Value::Object(fields) = record else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "a chained record is a JSON object"));
        };
        let mut out = Map::with_capacity(fields.len() + CHAIN_FIELDS.len());
        for (k, v) in fields.iter().filter(|(k, _)| !CHAIN_FIELDS.contains(&k.as_str())) {
            out.insert(k.clone(), v.clone());
        }
        let seq = self.head.seq + 1;
        out.insert("seq".into(), seq.into());
        out.insert("prev".into(), self.head.hash.clone().into());
        out.insert("sess".into(), self.session.id.clone().into());
        out.insert("mi".into(), self.session.step.into());
        let mut plaintext = Zeroizing::new(serde_json::to_vec(&Value::Object(out)).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?);
        let tag = mac(&self.session.key, &plaintext);
        plaintext.extend_from_slice(&tag);
        let hash = hex::encode(Sha256::digest(plaintext.as_slice()));
        Ok(Sealed { plaintext, head: Head { seq, hash }, key: ratchet(&self.session.key) })
    }

    /// Advances the chain and the ratchet after the frame was written; the
    /// old key is wiped as it drops.
    pub fn commit(&mut self, sealed: Sealed) {
        self.head = sealed.head;
        self.session.key = sealed.key;
        self.session.step += 1;
    }
}

/// Splits a chained frame's plaintext into its JSON and MAC.
pub fn split_frame(plaintext: &[u8]) -> Option<(&[u8], &[u8; MAC_LEN])> {
    let at = plaintext.len().checked_sub(MAC_LEN)?;
    let (body, tag) = plaintext.split_at(at);
    Some((body, tag.try_into().ok()?))
}

/// Checks frames' MACs with the session keys from the vault.
pub struct MacCheck {
    starts: BTreeMap<String, Zeroizing<[u8; 32]>>,
    /// Session id → the last step reached and its key.
    at: BTreeMap<String, (u64, Zeroizing<[u8; 32]>)>,
}

impl MacCheck {
    pub fn new(vault: Option<&ChainVault>) -> Self {
        let mut starts = BTreeMap::new();
        for (id, s) in vault.map(|v| &v.sessions).into_iter().flatten() {
            let mut key = Zeroizing::new([0u8; 32]);
            if hex::decode_to_slice(s.m0.expose(), key.as_mut()).is_ok() {
                starts.insert(id.clone(), key);
            }
        }
        Self { starts, at: BTreeMap::new() }
    }

    /// True when `tag` is the MAC of `body` for the session and step the record names.
    pub fn check(&mut self, record: &Value, body: &[u8], tag: &[u8; MAC_LEN]) -> bool {
        let (Some(id), Some(step)) = (record.get("sess").and_then(Value::as_str), record.get("mi").and_then(Value::as_u64)) else {
            return false;
        };
        let Some(start) = self.starts.get(id) else { return false };
        let (mut n, mut key) = match self.at.remove(id) {
            Some((n, key)) if n <= step => (n, key),
            _ => (0, start.clone()),
        };
        if step - n > MAX_RATCHET {
            return false;
        }
        while n < step {
            key = ratchet(&key);
            n += 1;
        }
        let mut m = <HmacSha256 as Mac>::new_from_slice(key.as_ref()).expect("HMAC takes any key length");
        m.update(body);
        let ok = m.verify_slice(tag).is_ok();
        self.at.insert(id.to_owned(), (n, key));
        ok
    }
}

/// One thing reading the record found wrong.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum Problem {
    /// Records `from` to `to` are not on disk and nothing AegisWin wrote explains it.
    Missing { from: u64, to: u64 },
    /// The files end before the last record AegisWin saw.
    CutShort { last: u64, saw: u64 },
    /// A file whose frames do not carry valid MACs.
    Forged { file: String, events: usize },
    /// A record that does not link to the one before it.
    Broken { seq: u64, after: u64 },
    /// A file without its `close` frame.
    Unclosed { file: String },
    /// A file that stops being readable part way.
    Damaged { file: String, after: usize },
}

/// `1284` as `1,284`.
pub fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

impl Problem {
    /// The sentence the approval record card shows, and the `integrity` event keeps.
    pub fn text(&self) -> String {
        match self {
            Self::Missing { from, to } if from == to => format!("Event {} is missing (removed outside AegisWin).", thousands(*from)),
            Self::Missing { from, to } => format!("Events {} to {} are missing (removed outside AegisWin).", thousands(*from), thousands(*to)),
            Self::CutShort { last, saw } => format!("The record ends at event {}, but AegisWin last saw {} (it was cut short).", thousands(*last), thousands(*saw)),
            Self::Forged { file, events: 1 } => format!("File {file} failed its check (changed or forged); its 1 event is shown in red."),
            Self::Forged { file, events } => format!("File {file} failed its check (changed or forged); its {} events are shown in red.", thousands(*events as u64)),
            Self::Broken { seq, after } => format!("Event {} does not follow event {} (the record was changed).", thousands(*seq), thousands(*after)),
            Self::Unclosed { file } => format!("{file} ended without closing (AegisWin stopped unexpectedly, or the file was cut short)."),
            Self::Damaged { file, after } => format!("File {file} is damaged after its first {} frames; the rest could not be read.", thousands(*after as u64)),
        }
    }
}

/// What checking the whole record found.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Integrity {
    /// Records whose MAC and links checked out.
    pub verified: u64,
    /// Records from before integrity checks (format 1 files).
    pub legacy: u64,
    pub problems: Vec<Problem>,
    /// Files that failed their check; their unverified frames are shown in red.
    #[serde(skip)]
    pub failed_files: Vec<String>,
}

impl Integrity {
    pub fn ok(&self) -> bool {
        self.problems.is_empty()
    }

    /// The one line above the table.
    pub fn line(&self) -> String {
        let mut line = if self.ok() {
            format!("Verified: {} events, no gaps.", thousands(self.verified))
        } else if self.problems.len() == 1 {
            self.problems[0].text()
        } else {
            format!("{} problems found in the record.", self.problems.len())
        };
        if self.legacy > 0 {
            let (n, verb) = if self.legacy == 1 { ("event", "was") } else { ("events", "were") };
            line.push_str(&format!(" {} earlier {n} {verb} recorded before integrity checks.", thousands(self.legacy)));
        }
        line
    }
}

fn seq_of(r: &Value) -> Option<u64> {
    r.get("seq").and_then(Value::as_u64)
}

fn text_of<'a>(r: &'a Value, field: &str) -> Option<&'a str> {
    r.get(field).and_then(Value::as_str)
}

/// Checks a whole stream, oldest file first. `current` is the file the
/// writer still has open, which has no `close` frame yet. Frames with a bad
/// MAC are flagged in place (`mac_ok == Some(false)`) for the caller to show.
pub fn verify(files: &[FileRead], checkpoint: Option<&Checkpoint>, current: Option<&str>) -> Integrity {
    let mut out = Integrity::default();
    // Retention removes the oldest files and says so first, in a `pruned`
    // record that only a MAC-holder could write: (last seq removed, its hash).
    let pruned: Vec<(u64, &str)> = files
        .iter()
        .flat_map(|f| &f.frames)
        .filter(|fr| fr.mac_ok == Some(true) && text_of(&fr.record, "event") == Some("pruned"))
        .filter_map(|fr| Some((fr.record.get("to").and_then(Value::as_u64)?, text_of(&fr.record, "lastHash")?)))
        .collect();
    let mut last: Option<(u64, String)> = None;
    // After a file that failed its check, the next good record starts afresh.
    let mut resync = false;
    let mut highest = 0;
    let mut seen_chained = false;
    for f in files {
        if !f.chained {
            let readable = !matches!(f.status, crate::history::FileStatus::Unreadable | crate::history::FileStatus::OtherKey);
            if seen_chained && readable {
                // Format 1 files all predate the first chained one; a later
                // one was sealed with the public key, outside AegisWin.
                out.problems.push(Problem::Forged { file: f.name.clone(), events: f.frames.len() });
                out.failed_files.push(f.name.clone());
                resync = true;
                last = None;
            } else {
                out.legacy += f.frames.len() as u64;
            }
            continue;
        }
        seen_chained = true;
        if f.status == crate::history::FileStatus::Corrupt {
            out.problems.push(Problem::Damaged { file: f.name.clone(), after: f.frames.len() });
        }
        let bad = f.frames.iter().filter(|fr| fr.mac_ok != Some(true)).count();
        if bad > 0 {
            out.problems.push(Problem::Forged { file: f.name.clone(), events: bad });
            out.failed_files.push(f.name.clone());
            resync = true;
            last = None;
            continue;
        }
        for fr in &f.frames {
            let Some(seq) = seq_of(&fr.record) else { continue };
            let prev = text_of(&fr.record, "prev").unwrap_or_default();
            let restart = seq == 1 && prev == GENESIS_HASH;
            match &last {
                // A purge starts a new chain; so does the very first record.
                _ if restart && (last.is_none() || text_of(&fr.record, "event") == Some("purged")) => {}
                None if resync => {}
                None => {
                    let covered = pruned.iter().any(|(to, hash)| *to + 1 == seq && *hash == prev);
                    if !covered {
                        out.problems.push(Problem::Missing { from: 1, to: seq - 1 });
                    }
                }
                Some((ls, lh)) if seq == ls + 1 => {
                    if prev != lh {
                        out.problems.push(Problem::Broken { seq, after: *ls });
                    }
                }
                Some((ls, _)) if seq > ls + 1 => out.problems.push(Problem::Missing { from: ls + 1, to: seq - 1 }),
                Some((ls, _)) => out.problems.push(Problem::Broken { seq, after: *ls }),
            }
            resync = false;
            last = Some((seq, hex::encode(fr.hash)));
            highest = highest.max(seq);
            out.verified += 1;
        }
        let closed = f.frames.last().is_some_and(|fr| text_of(&fr.record, "event") == Some("close"));
        if !closed && current != Some(f.name.as_str()) {
            out.problems.push(Problem::Unclosed { file: f.name.clone() });
        }
    }
    if let Some(cp) = checkpoint {
        if highest < cp.seq {
            out.problems.push(Problem::CutShort { last: highest, saw: cp.seq });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::{FileStatus, Frame};
    use serde_json::json;

    fn writer() -> (ChainWriter, ChainVault) {
        let (session, id, key) = Session::start("2026-11-10");
        let mut vault = ChainVault::default();
        vault.add_session(id, key, "2026-11-10");
        (ChainWriter::new(Head::genesis(), session), vault)
    }

    /// Seals `records` and reads them back the way the history reader does.
    fn frames(w: &mut ChainWriter, check: &mut MacCheck, records: &[Value]) -> Vec<Frame> {
        records
            .iter()
            .map(|r| {
                let sealed = w.seal(r).unwrap();
                let (body, tag) = split_frame(&sealed.plaintext).unwrap();
                let record: Value = serde_json::from_slice(body).unwrap();
                let mac_ok = Some(check.check(&record, body, tag));
                let hash: [u8; 32] = Sha256::digest(sealed.plaintext.as_slice()).into();
                w.commit(sealed);
                Frame { record, hash, mac_ok }
            })
            .collect()
    }

    fn file(name: &str, frames: Vec<Frame>) -> FileRead {
        FileRead { name: name.into(), status: FileStatus::Ok, chained: true, bytes: 0, frames }
    }

    fn ev(event: &str) -> Value {
        json!({ "event": event })
    }

    #[test]
    fn records_link_and_verify_and_the_ratchet_moves_on() {
        let (mut w, vault) = writer();
        let mut check = MacCheck::new(Some(&vault));
        let a = frames(&mut w, &mut check, &[ev("open"), json!({ "event": "created", "seq": 99, "mi": 7 }), ev("close")]);
        assert!(a.iter().all(|f| f.mac_ok == Some(true)));
        assert_eq!(a.iter().map(|f| seq_of(&f.record).unwrap()).collect::<Vec<_>>(), [1, 2, 3], "the writer owns seq");
        assert_eq!(a[1].record["mi"], 1);
        assert_eq!(a[1].record["prev"], hex::encode(a[0].hash));
        let integrity = verify(&[file("seg-20261110-001.bin", a)], Some(&w.head().checkpoint()), None);
        assert!(integrity.ok(), "{integrity:?}");
        assert_eq!(integrity.line(), "Verified: 3 events, no gaps.");

        // A frame sealed with the step-0 key does not pass as step 1.
        let (session, id, key) = Session::start("2026-11-10");
        let mut vault2 = ChainVault::default();
        vault2.add_session(id, key, "2026-11-10");
        let w2 = ChainWriter::new(Head::genesis(), session);
        let sealed = w2.seal(&ev("x")).unwrap();
        let (body, tag) = split_frame(&sealed.plaintext).unwrap();
        let mut record: Value = serde_json::from_slice(body).unwrap();
        assert!(MacCheck::new(Some(&vault2)).check(&record, body, tag));
        record["mi"] = json!(1);
        assert!(!MacCheck::new(Some(&vault2)).check(&record, body, tag));
        // Another vault's sessions, or a huge step, fail without work.
        assert!(!MacCheck::new(Some(&vault)).check(&serde_json::from_slice(body).unwrap(), body, tag));
        record["mi"] = json!(u64::MAX);
        assert!(!MacCheck::new(Some(&vault2)).check(&record, body, tag));
    }

    #[test]
    fn gaps_breaks_forgeries_and_cut_ends_are_named() {
        let (mut w, vault) = writer();
        let mut check = MacCheck::new(Some(&vault));
        let a = frames(&mut w, &mut check, &[ev("open"), ev("created"), ev("close")]);
        let b = frames(&mut w, &mut check, &[ev("open"), ev("created"), ev("close")]);
        let c = frames(&mut w, &mut check, &[ev("open"), ev("decided")]);
        let cp = w.head().checkpoint();
        let all = || vec![file("a", a.clone()), file("b", b.clone()), file("c", c.clone())];

        // b deleted: events 4 to 6 are missing.
        let files = vec![file("a", a.clone()), file("c", c.clone())];
        let i = verify(&files, Some(&cp), Some("c"));
        assert_eq!(i.problems, [Problem::Missing { from: 4, to: 6 }]);
        assert_eq!(i.line(), "Events 4 to 6 are missing (removed outside AegisWin).");

        // c cut after its first frame, and not the open file: cut short and unclosed.
        let mut files = all();
        files[2].frames.truncate(1);
        let i = verify(&files, Some(&cp), None);
        assert_eq!(i.problems, [Problem::Unclosed { file: "c".into() }, Problem::CutShort { last: 7, saw: 8 }]);
        assert_eq!(i.problems[1].text(), "The record ends at event 7, but AegisWin last saw 8 (it was cut short).");

        // A frame with a bad MAC fails its whole file.
        let mut files = all();
        files[1].frames[1].mac_ok = Some(false);
        let i = verify(&files, Some(&cp), Some("c"));
        assert_eq!(i.problems, [Problem::Forged { file: "b".into(), events: 1 }]);

        // Two files swapped: links break.
        let files = vec![file("b", b.clone()), file("a", a.clone()), file("c", c.clone())];
        assert!(!verify(&files, Some(&cp), Some("c")).ok());

        // A changed prev link.
        let mut files = all();
        files[1].frames[0].record["prev"] = json!(GENESIS_HASH);
        assert_eq!(verify(&files, Some(&cp), Some("c")).problems, [Problem::Broken { seq: 4, after: 3 }]);
        assert_eq!(thousands(1_234_567), "1,234,567");
    }

    #[test]
    fn retention_and_purges_are_authorised_gaps_and_old_files_count_as_legacy() {
        let (mut w, vault) = writer();
        let mut check = MacCheck::new(Some(&vault));
        let a = frames(&mut w, &mut check, &[ev("open"), ev("created"), ev("close")]);
        let last = hex::encode(a[2].hash);
        let b = frames(&mut w, &mut check, &[ev("open"), json!({ "event": "pruned", "from": 1, "to": 3, "lastHash": last })]);
        let legacy = FileRead { name: "old".into(), status: FileStatus::Ok, chained: false, bytes: 0, frames: vec![Frame { record: ev("created"), hash: [0; 32], mac_ok: None }] };
        let i = verify(&[legacy.clone(), file("b", b.clone())], Some(&w.head().checkpoint()), Some("b"));
        assert!(i.ok(), "{i:?}");
        assert_eq!(i.legacy, 1);
        assert!(i.line().ends_with("1 earlier event was recorded before integrity checks."), "{}", i.line());
        // A format 1 file after a chained one was made outside AegisWin.
        let late = FileRead { name: "late".into(), ..legacy };
        let i = verify(&[file("b", b.clone()), late], None, Some("b"));
        assert_eq!((i.problems.as_slice(), i.failed_files.as_slice()), ([Problem::Forged { file: "late".into(), events: 1 }].as_slice(), ["late".to_owned()].as_slice()));
        assert_eq!(i.line(), "File late failed its check (changed or forged); its 1 event is shown in red.");

        // A pruned record that names another hash does not cover the gap.
        let mut forged = b.clone();
        forged[1].record["lastHash"] = json!(GENESIS_HASH);
        assert_eq!(verify(&[file("b", forged)], None, Some("b")).problems, [Problem::Missing { from: 1, to: 3 }]);

        // A purge restarts the chain at 1.
        let (session, id, key) = Session::start("2026-11-10");
        let mut vault2 = ChainVault::default();
        vault2.add_session(id, key, "2026-11-10");
        let mut w2 = ChainWriter::new(Head::genesis(), session);
        let p = frames(&mut w2, &mut MacCheck::new(Some(&vault2)), &[ev("open"), json!({ "event": "purged" })]);
        assert!(verify(&[file("p", p)], Some(&w2.head().checkpoint()), Some("p")).ok());
    }

    #[test]
    fn sessions_end_and_are_forgotten_once_aged_out() {
        let mut v = ChainVault::default();
        let (_, a, ka) = Session::start("2026-08-01");
        v.add_session(a.clone(), ka, "2026-08-01");
        let (_, b, kb) = Session::start("2026-11-09");
        v.add_session(b.clone(), kb, "2026-11-09");
        assert_eq!(v.sessions[&a].ended.as_deref(), Some("2026-11-09"));
        v.forget_sessions_before("2026-08-12");
        assert_eq!(v.sessions.len(), 2, "a ended inside the window");
        let (_, c, kc) = Session::start("2026-11-10");
        v.add_session(c, kc, "2026-11-10");
        v.forget_sessions_before("2026-11-10");
        assert!(!v.sessions.contains_key(&a) && v.sessions.contains_key(&b), "b ended today, so stays");
        assert!(!format!("{v:?}").contains("m0"), "keys are never printed");
    }
}
