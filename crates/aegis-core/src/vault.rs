//! Portable encrypted vault (`./data/vault.enc.json`) and the global PIN guard.
//!
//! Format 2 (ADR 0004 §3): the state is encrypted with AES-256-GCM under a
//! random 256-bit **data key**. The data key is stored wrapped:
//! - always, under Argon2id(passphrase), in the vault header (`wrap`): the
//!   portable path that works on any PC;
//! - optionally, under Argon2id(short PIN) and then DPAPI for this Windows
//!   account, in `vault.thispc.bin` next to the vault.
//!
//! Nothing secret is stored in clear: no passphrase, no PIN, no hash of them.
//! A wrong one simply fails GCM authentication. The KDF parameters, salt and
//! whether the key meets the passphrase rule are bound into each wrap as
//! associated data, so tampering with the header fails too.
//!
//! Format 1 vaults (the PIN key encrypted the state directly) still open; the
//! first unlock rewrites them as format 2, keeping the same secret.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Shortest short PIN for this PC (§3.3).
pub const MIN_PIN_LEN: usize = 6;
/// Shortest passphrase for the portable vault key (§3.2).
pub const MIN_PASSPHRASE_LEN: usize = 14;
pub const MAX_PIN_LEN: usize = 128;
/// The file next to the vault that holds the DPAPI-wrapped key for this PC.
pub const THIS_PC_FILE: &str = "vault.thispc.bin";
const FORMAT_V1: u32 = 1;
const FORMAT_VERSION: u32 = 2;
const THIS_PC_VERSION: u32 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("a vault already exists at this location")]
    AlreadyExists,
    #[error("no vault exists yet")]
    NotFound,
    #[error("incorrect passphrase or PIN")]
    WrongPin,
    #[error("the PIN must be at least {MIN_PIN_LEN} characters")]
    PinTooShort,
    #[error("the passphrase must be at least {MIN_PASSPHRASE_LEN} characters")]
    PassphraseTooShort,
    #[error("must be at most {MAX_PIN_LEN} characters")]
    PinTooLong,
    #[error("Windows could not protect the key for this PC")]
    ThisPc,
    #[error("vault file is damaged or not an AegisWin vault: {0}")]
    Corrupt(String),
    #[error("vault I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Argon2id cost parameters, stored in the vault header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    /// 256 MiB, 3 passes: about 1 s on a current desktop CPU (§3.2).
    pub const DEFAULT: Self = Self { m_kib: 256 * 1024, t: 3, p: 1 };
    /// What [`Self::tuned`] falls back to on a slow PC.
    pub const FLOOR: Self = Self { m_kib: 128 * 1024, t: 3, p: 1 };
    /// Cheap parameters so unit tests stay fast. Never used for real vaults.
    pub const INSECURE_TEST: Self = Self { m_kib: 64, t: 1, p: 1 };

    /// The parameters for a new key. [`Self::DEFAULT`] drops to [`Self::FLOOR`]
    /// when one derivation takes over 1.5 s here; measured once per run.
    /// Other parameters (tests) are used as given.
    pub fn tuned(self) -> Self {
        if self != Self::DEFAULT {
            return self;
        }
        static TUNED: OnceLock<KdfParams> = OnceLock::new();
        *TUNED.get_or_init(|| {
            let start = Instant::now();
            let slow = derive_key("aegis-win-tuning", &[0u8; SALT_LEN], &Self::DEFAULT).is_err() || start.elapsed() > Duration::from_millis(1500);
            if slow { Self::FLOOR } else { Self::DEFAULT }
        })
    }
}

#[derive(Serialize, Deserialize)]
struct VaultFile {
    version: u32,
    kdf: String,
    params: KdfParams,
    salt: String,
    /// Format 2: the data key wrapped under the passphrase key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wrap: Option<WrapFile>,
    /// Format 2: whether the passphrase met the rule when it was set.
    #[serde(default)]
    passphrase: bool,
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
struct WrapFile {
    nonce: String,
    ciphertext: String,
}

/// Contents of `vault.thispc.bin` before DPAPI.
#[derive(Serialize, Deserialize)]
struct ThisPcFile {
    version: u32,
    params: KdfParams,
    salt: String,
    nonce: String,
    ciphertext: String,
}

fn aad_v1(params: &KdfParams, salt: &[u8]) -> Vec<u8> {
    format!("aegis-win-vault|v{FORMAT_V1}|argon2id|{}|{}|{}|{}", params.m_kib, params.t, params.p, hex::encode(salt)).into_bytes()
}

const STATE_AAD: &[u8] = b"aegis-win-vault|v2|state";

/// Which secret a wrap is for; part of its associated data.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Passphrase { meets_rule: bool },
    ThisPc,
}

impl Kind {
    fn aad(self, params: &KdfParams, salt: &[u8]) -> Vec<u8> {
        let what = match self {
            Kind::Passphrase { meets_rule } => format!("aegis-win-vault|v{FORMAT_VERSION}|wrap-pass|rule={meets_rule}"),
            Kind::ThisPc => format!("aegis-win-thispc|v{THIS_PC_VERSION}|wrap-pin"),
        };
        format!("{what}|argon2id|{}|{}|{}|{}", params.m_kib, params.t, params.p, hex::encode(salt)).into_bytes()
    }
}

/// True when `secret` is long enough to be the portable vault key.
pub fn meets_passphrase_rule(secret: &str) -> bool {
    secret.chars().count() >= MIN_PASSPHRASE_LEN
}

pub fn validate_new_passphrase(passphrase: &str) -> Result<(), VaultError> {
    if !meets_passphrase_rule(passphrase) {
        return Err(VaultError::PassphraseTooShort);
    }
    if passphrase.chars().count() > MAX_PIN_LEN {
        return Err(VaultError::PinTooLong);
    }
    Ok(())
}

pub fn validate_new_pin(pin: &str) -> Result<(), VaultError> {
    let len = pin.chars().count();
    if len < MIN_PIN_LEN {
        return Err(VaultError::PinTooShort);
    }
    if len > MAX_PIN_LEN {
        return Err(VaultError::PinTooLong);
    }
    Ok(())
}

fn derive_key(secret: &str, salt: &[u8], params: &KdfParams) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let argon_params = Params::new(params.m_kib, params.t, params.p, Some(32))
        .map_err(|e| VaultError::Corrupt(format!("invalid KDF parameters: {e}")))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params)
        .hash_password_into(secret.as_bytes(), salt, key.as_mut())
        .map_err(|e| VaultError::Corrupt(format!("key derivation failed: {e}")))?;
    Ok(key)
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("the OS random number generator is unavailable");
    buf
}

fn cipher(key: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
}

pub fn vault_exists(path: &Path) -> bool {
    path.is_file()
}

/// Where the DPAPI-wrapped key for this PC lives, next to the vault.
pub fn this_pc_path(vault: &Path) -> PathBuf {
    vault.with_file_name(THIS_PC_FILE)
}

/// Whether a short PIN is set up on this PC for the vault at `vault`.
pub fn this_pc_exists(vault: &Path) -> bool {
    this_pc_path(vault).is_file()
}

/// Deletes the short PIN for this PC. Needs no PIN (§3.3): it only removes
/// a way in. Missing is fine.
pub fn forget_this_pc(vault: &Path) -> Result<(), VaultError> {
    match fs::remove_file(this_pc_path(vault)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// The data key wrapped under a key derived from one secret.
#[derive(Clone)]
struct Wrapped {
    kind: Kind,
    params: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

impl Wrapped {
    fn seal(kek: &[u8; 32], data_key: &[u8; 32], kind: Kind, params: KdfParams, salt: [u8; SALT_LEN]) -> Result<Self, VaultError> {
        let nonce = random_bytes::<NONCE_LEN>();
        let ciphertext = cipher(kek)
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: data_key, aad: &kind.aad(&params, &salt) })
            .map_err(|_| VaultError::Corrupt("encryption failed".into()))?;
        Ok(Self { kind, params, salt, nonce, ciphertext })
    }

    /// The data key, if `secret` is the one this wrap was made with.
    fn open(&self, secret: &str) -> Option<Zeroizing<[u8; 32]>> {
        let kek = derive_key(secret, &self.salt, &self.params).ok()?;
        let plain = Zeroizing::new(
            cipher(&kek).decrypt(Nonce::from_slice(&self.nonce), Payload { msg: &self.ciphertext, aad: &self.kind.aad(&self.params, &self.salt) }).ok()?,
        );
        let key: [u8; 32] = plain.as_slice().try_into().ok()?;
        Some(Zeroizing::new(key))
    }
}

/// Tries the passphrase and the PIN for this PC, likelier first: input too
/// short to be a passphrase is tried as the PIN first.
fn open_any(pass: &Wrapped, pc: Option<&Wrapped>, secret: &str) -> Option<Zeroizing<[u8; 32]>> {
    let mut order = [Some(pass), pc];
    if !meets_passphrase_rule(secret) {
        order.reverse();
    }
    order.into_iter().flatten().find_map(|w| w.open(secret))
}

/// Reads `vault.thispc.bin`, if present and readable as this Windows user.
/// A file from another PC or account is ignored, as if absent.
fn read_this_pc(vault: &Path) -> Option<Wrapped> {
    let blob = fs::read(this_pc_path(vault)).ok()?;
    let plain = crate::os::dpapi_unprotect(&blob)?;
    let file: ThisPcFile = serde_json::from_slice(&plain).ok()?;
    if file.version != THIS_PC_VERSION {
        return None;
    }
    Some(Wrapped {
        kind: Kind::ThisPc,
        params: file.params,
        salt: decode_fixed(&file.salt, "salt").ok()?,
        nonce: decode_fixed(&file.nonce, "nonce").ok()?,
        ciphertext: hex::decode(&file.ciphertext).ok()?,
    })
}

fn write_this_pc(vault: &Path, w: &Wrapped) -> Result<(), VaultError> {
    let file = ThisPcFile {
        version: THIS_PC_VERSION,
        params: w.params,
        salt: hex::encode(w.salt),
        nonce: hex::encode(w.nonce),
        ciphertext: hex::encode(&w.ciphertext),
    };
    let json = serde_json::to_vec(&file).map_err(|e| VaultError::Corrupt(e.to_string()))?;
    let blob = crate::os::dpapi_protect(&json).ok_or(VaultError::ThisPc)?;
    write_atomic(&this_pc_path(vault), &blob)?;
    Ok(())
}

/// An open vault: the data key plus the decrypted state.
///
/// Deliberately not `Debug` or `Serialize`, so the key and state cannot end up
/// in a log line or an IPC response by accident.
pub struct UnlockedVault<T> {
    path: PathBuf,
    pass: Wrapped,
    this_pc: Option<Wrapped>,
    key: Zeroizing<[u8; 32]>,
    pub state: T,
}

impl<T: Serialize + DeserializeOwned> UnlockedVault<T> {
    pub fn create(path: &Path, passphrase: &str, state: T) -> Result<Self, VaultError> {
        Self::create_with_params(path, passphrase, state, KdfParams::DEFAULT)
    }

    pub fn create_with_params(path: &Path, passphrase: &str, state: T, params: KdfParams) -> Result<Self, VaultError> {
        validate_new_passphrase(passphrase)?;
        if vault_exists(path) {
            return Err(VaultError::AlreadyExists);
        }
        let new = NewKey::derive(passphrase, params)?;
        let key = Zeroizing::new(random_bytes::<32>());
        let pass = new.wrap(&key, true)?;
        // A short PIN left over from a vault that was deleted cannot open this one.
        forget_this_pc(path)?;
        let vault = Self { path: path.to_path_buf(), pass, this_pc: None, key, state };
        vault.save()?;
        Ok(vault)
    }

    /// Opens the vault with its passphrase, or with the short PIN on this PC.
    pub fn unlock(path: &Path, secret: &str) -> Result<Self, VaultError> {
        let raw = match fs::read(path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(VaultError::NotFound),
            Err(e) => return Err(e.into()),
        };
        let file: VaultFile = serde_json::from_slice(&raw).map_err(|e| VaultError::Corrupt(e.to_string()))?;
        if file.kdf != "argon2id" {
            return Err(VaultError::Corrupt(format!("unsupported key derivation {}", file.kdf)));
        }
        let salt: [u8; SALT_LEN] = decode_fixed(&file.salt, "salt")?;
        let nonce: [u8; NONCE_LEN] = decode_fixed(&file.nonce, "nonce")?;
        let ciphertext = hex::decode(&file.ciphertext).map_err(|_| VaultError::Corrupt("ciphertext is not hex".into()))?;
        match (file.version, file.wrap) {
            (FORMAT_V1, None) => Self::unlock_v1(path, secret, file.params, salt, &nonce, &ciphertext),
            (FORMAT_VERSION, Some(wrap)) => {
                let pass = Wrapped {
                    kind: Kind::Passphrase { meets_rule: file.passphrase },
                    params: file.params,
                    salt,
                    nonce: decode_fixed(&wrap.nonce, "wrap nonce")?,
                    ciphertext: hex::decode(&wrap.ciphertext).map_err(|_| VaultError::Corrupt("wrap is not hex".into()))?,
                };
                let this_pc = read_this_pc(path);
                let key = open_any(&pass, this_pc.as_ref(), secret).ok_or(VaultError::WrongPin)?;
                // A short PIN made for an older copy of the vault opens a stale key.
                let plain = Zeroizing::new(
                    cipher(&key).decrypt(Nonce::from_slice(&nonce), Payload { msg: &ciphertext, aad: STATE_AAD }).map_err(|_| VaultError::WrongPin)?,
                );
                let state = serde_json::from_slice(&plain).map_err(|e| VaultError::Corrupt(e.to_string()))?;
                Ok(Self { path: path.to_path_buf(), pass, this_pc, key, state })
            }
            (v, _) => Err(VaultError::Corrupt(format!("unsupported format {v}"))),
        }
    }

    /// Format 1: the PIN key encrypted the state. Rewrites the file as format
    /// 2 with a new data key wrapped under the same PIN key, so the same
    /// secret keeps working until the owner sets a passphrase (decision D2).
    fn unlock_v1(path: &Path, secret: &str, params: KdfParams, salt: [u8; SALT_LEN], nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Result<Self, VaultError> {
        let kek = derive_key(secret, &salt, &params)?;
        let plain = Zeroizing::new(
            cipher(&kek)
                .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad: &aad_v1(&params, &salt) })
                .map_err(|_| VaultError::WrongPin)?,
        );
        let state = serde_json::from_slice(&plain).map_err(|e| VaultError::Corrupt(e.to_string()))?;
        let key = Zeroizing::new(random_bytes::<32>());
        // Old parameters were cheaper, so only a long secret counts as meeting the rule.
        let meets_rule = meets_passphrase_rule(secret) && params.m_kib >= KdfParams::FLOOR.m_kib;
        let pass = Wrapped::seal(&kek, &key, Kind::Passphrase { meets_rule }, params, salt)?;
        let vault = Self { path: path.to_path_buf(), pass, this_pc: None, key, state };
        vault.save()?;
        Ok(vault)
    }

    /// Re-encrypts the state with a fresh nonce and replaces the file atomically.
    pub fn save(&self) -> Result<(), VaultError> {
        let plaintext = Zeroizing::new(serde_json::to_vec(&self.state).map_err(|e| VaultError::Corrupt(e.to_string()))?);
        let nonce = random_bytes::<NONCE_LEN>();
        let ciphertext = cipher(&self.key)
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: &plaintext, aad: STATE_AAD })
            .map_err(|_| VaultError::Corrupt("encryption failed".into()))?;
        let Kind::Passphrase { meets_rule } = self.pass.kind else { unreachable!("the header wrap is the passphrase wrap") };
        let file = VaultFile {
            version: FORMAT_VERSION,
            kdf: "argon2id".into(),
            params: self.pass.params,
            salt: hex::encode(self.pass.salt),
            wrap: Some(WrapFile { nonce: hex::encode(self.pass.nonce), ciphertext: hex::encode(&self.pass.ciphertext) }),
            passphrase: meets_rule,
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ciphertext),
        };
        let json = serde_json::to_vec_pretty(&file).map_err(|e| VaultError::Corrupt(e.to_string()))?;
        write_atomic(&self.path, &json)?;
        Ok(())
    }

    /// Checks the passphrase or this PC's PIN (used for approvals).
    pub fn verify_pin(&self, secret: &str) -> bool {
        self.verifier().verify(secret)
    }

    /// A detached copy of what is needed to check a secret, so the slow
    /// Argon2 derivation can run without holding the lock on the vault.
    pub fn verifier(&self) -> PinVerifier {
        PinVerifier { pass: self.pass.clone(), this_pc: self.this_pc.clone(), key: self.key.clone() }
    }

    /// Whether the portable key meets the passphrase rule (§3.2). False for a
    /// vault still keyed by a short PIN from before format 2.
    pub fn meets_passphrase_rule(&self) -> bool {
        matches!(self.pass.kind, Kind::Passphrase { meets_rule: true })
    }

    /// Whether a short PIN on this PC can open the vault.
    pub fn has_this_pc(&self) -> bool {
        self.this_pc.is_some()
    }

    /// Sets a new passphrase under a **new data key**, so copies of the folder
    /// taken before (perhaps with a weak key) cannot open later saves. The
    /// short PIN for this PC is set to `this_pc` if given, or removed: the
    /// old one wraps the old data key.
    pub fn install_passphrase(&mut self, passphrase: NewKey, this_pc: Option<NewKey>) -> Result<(), VaultError> {
        let key = Zeroizing::new(random_bytes::<32>());
        let pass = passphrase.wrap(&key, true)?;
        let pc = this_pc.map(|n| n.wrap(&key, false)).transpose()?;
        let old = (std::mem::replace(&mut self.pass, pass), std::mem::replace(&mut self.key, key));
        if let Err(e) = self.save() {
            (self.pass, self.key) = old;
            return Err(e);
        }
        // The vault now needs the new key; a failure below only loses the PC PIN.
        self.this_pc = None;
        match pc {
            Some(w) => {
                if let Err(e) = write_this_pc(&self.path, &w) {
                    let _ = forget_this_pc(&self.path);
                    return Err(e);
                }
                self.this_pc = Some(w);
                Ok(())
            }
            None => forget_this_pc(&self.path),
        }
    }

    /// Sets (or replaces) the short PIN for this PC.
    pub fn set_this_pc(&mut self, pin: NewKey) -> Result<(), VaultError> {
        let w = pin.wrap(&self.key, false)?;
        write_this_pc(&self.path, &w)?;
        self.this_pc = Some(w);
        Ok(())
    }

    /// Removes the short PIN for this PC.
    pub fn forget_this_pc(&mut self) -> Result<(), VaultError> {
        forget_this_pc(&self.path)?;
        self.this_pc = None;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// A key derived from a new passphrase or PIN, away from the vault lock
/// (Argon2 is slow). Validate the secret before deriving.
pub struct NewKey {
    params: KdfParams,
    salt: [u8; SALT_LEN],
    kek: Zeroizing<[u8; 32]>,
}

impl NewKey {
    /// Derives with `params` (pass [`KdfParams::DEFAULT`]; see [`KdfParams::tuned`]).
    pub fn derive(secret: &str, params: KdfParams) -> Result<Self, VaultError> {
        let params = params.tuned();
        let salt = random_bytes::<SALT_LEN>();
        let kek = derive_key(secret, &salt, &params)?;
        Ok(Self { params, salt, kek })
    }

    fn wrap(&self, data_key: &[u8; 32], passphrase: bool) -> Result<Wrapped, VaultError> {
        let kind = if passphrase { Kind::Passphrase { meets_rule: true } } else { Kind::ThisPc };
        Wrapped::seal(&self.kek, data_key, kind, self.params, self.salt)
    }
}

pub struct PinVerifier {
    pass: Wrapped,
    this_pc: Option<Wrapped>,
    key: Zeroizing<[u8; 32]>,
}

impl PinVerifier {
    pub fn verify(&self, secret: &str) -> bool {
        open_any(&self.pass, self.this_pc.as_ref(), secret).is_some_and(|k| bool::from(k.as_ref().ct_eq(self.key.as_ref())))
    }
}

fn decode_fixed<const N: usize>(value: &str, what: &str) -> Result<[u8; N], VaultError> {
    hex::decode(value)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| VaultError::Corrupt(format!("{what} has the wrong length")))
}

/// Writes to a sibling temp file, flushes it to disk, then renames over the
/// target, so a crash mid-save never leaves a half-written vault.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

/// Rate limit shared by every place a PIN is checked: unlock, in-app
/// approvals, gate changes and the rest. Per-ticket lockout alone is not
/// enough, because an agent can open unlimited tickets.
#[derive(Debug, Default)]
pub struct PinGuard {
    consecutive_failures: u32,
    locked_until: Option<Instant>,
}

impl PinGuard {
    pub const FREE_ATTEMPTS: u32 = 5;
    const BASE_COOLDOWN: Duration = Duration::from_secs(30);
    const MAX_COOLDOWN: Duration = Duration::from_secs(3600);

    /// `Err(remaining)` while a cooldown is active.
    pub fn check(&self, now: Instant) -> Result<(), Duration> {
        match self.locked_until {
            Some(until) if until > now => Err(until - now),
            _ => Ok(()),
        }
    }

    pub fn record(&mut self, success: bool, now: Instant) {
        if success {
            *self = Self::default();
            return;
        }
        self.consecutive_failures += 1;
        if self.consecutive_failures >= Self::FREE_ATTEMPTS {
            let doublings = (self.consecutive_failures - Self::FREE_ATTEMPTS).min(16);
            let cooldown = Self::BASE_COOLDOWN.saturating_mul(1 << doublings).min(Self::MAX_COOLDOWN);
            self.locked_until = Some(now + cooldown);
        }
    }

    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Demo {
        api_key: String,
        n: u32,
    }

    fn demo() -> Demo {
        Demo { api_key: "sk-test-123".into(), n: 7 }
    }

    const PASS: &str = "correct-horse-battery";

    fn new_vault(dir: &tempfile::TempDir) -> (PathBuf, UnlockedVault<Demo>) {
        let path = dir.path().join("vault.enc");
        let v = UnlockedVault::create_with_params(&path, PASS, demo(), KdfParams::INSECURE_TEST).unwrap();
        (path, v)
    }

    fn test_key(secret: &str) -> NewKey {
        NewKey::derive(secret, KdfParams::INSECURE_TEST).unwrap()
    }

    /// Writes a format 1 vault the way older versions did.
    fn write_v1(path: &Path, pin: &str, state: &Demo) {
        let params = KdfParams::INSECURE_TEST;
        let salt = random_bytes::<SALT_LEN>();
        let nonce = random_bytes::<NONCE_LEN>();
        let key = derive_key(pin, &salt, &params).unwrap();
        let plain = serde_json::to_vec(state).unwrap();
        let ct = cipher(&key).encrypt(Nonce::from_slice(&nonce), Payload { msg: &plain, aad: &aad_v1(&params, &salt) }).unwrap();
        let file = serde_json::json!({"version": 1, "kdf": "argon2id", "params": params, "salt": hex::encode(salt), "nonce": hex::encode(nonce), "ciphertext": hex::encode(ct)});
        fs::write(path, serde_json::to_vec(&file).unwrap()).unwrap();
    }

    #[test]
    fn round_trips_state_and_keeps_secrets_out_of_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let (path, v) = new_vault(&dir);
        assert!(v.meets_passphrase_rule());
        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("sk-test-123"));
        assert!(!raw.contains(PASS));
        let file: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(file["version"], 2);
        assert_eq!(file["passphrase"], true);
        let reopened = UnlockedVault::<Demo>::unlock(&path, PASS).unwrap();
        assert_eq!(reopened.state, demo());
    }

    #[test]
    fn wrong_secret_fails_and_missing_vault_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = new_vault(&dir);
        assert!(matches!(UnlockedVault::<Demo>::unlock(&path, "wrong-passphrase-here"), Err(VaultError::WrongPin)));
        assert!(matches!(UnlockedVault::<Demo>::unlock(&path, "123456"), Err(VaultError::WrongPin)));
        assert!(matches!(UnlockedVault::<Demo>::unlock(&dir.path().join("nope.enc"), PASS), Err(VaultError::NotFound)));
    }

    #[test]
    fn refuses_short_passphrases_and_overwriting_an_existing_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.enc");
        assert!(matches!(
            UnlockedVault::create_with_params(&path, "only-13-chars", demo(), KdfParams::INSECURE_TEST),
            Err(VaultError::PassphraseTooShort)
        ));
        let (path, _) = new_vault(&dir);
        assert!(matches!(
            UnlockedVault::create_with_params(&path, "another-passphrase", demo(), KdfParams::INSECURE_TEST),
            Err(VaultError::AlreadyExists)
        ));
    }

    #[test]
    fn header_tampering_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = new_vault(&dir);
        let original = fs::read(&path).unwrap();
        for (field, value) in [("params", serde_json::json!({"m_kib": 64, "t": 2, "p": 1})), ("passphrase", serde_json::json!(false))] {
            let mut file: serde_json::Value = serde_json::from_slice(&original).unwrap();
            file[field] = value;
            fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
            assert!(matches!(UnlockedVault::<Demo>::unlock(&path, PASS), Err(VaultError::WrongPin)), "{field}");
        }
    }

    #[test]
    fn save_uses_a_fresh_nonce_and_persists_changes() {
        let dir = tempfile::tempdir().unwrap();
        let (path, mut v) = new_vault(&dir);
        let first = fs::read_to_string(&path).unwrap();
        v.state.n = 8;
        v.save().unwrap();
        let second = fs::read_to_string(&path).unwrap();
        assert_ne!(first, second);
        assert!(!path.with_extension("tmp").exists());
        assert_eq!(UnlockedVault::<Demo>::unlock(&path, PASS).unwrap().state.n, 8);
    }

    #[test]
    fn a_format_1_vault_opens_with_its_pin_and_is_rewritten_as_format_2() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.enc");
        write_v1(&path, "135790", &demo());
        assert!(matches!(UnlockedVault::<Demo>::unlock(&path, "135791"), Err(VaultError::WrongPin)));
        let v = UnlockedVault::<Demo>::unlock(&path, "135790").unwrap();
        assert_eq!(v.state, demo());
        assert!(!v.meets_passphrase_rule(), "a short PIN must be replaced");
        let file: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(file["version"], 2);
        assert_eq!(file["passphrase"], false);
        // The same PIN still opens it until the owner chooses (D2).
        assert!(!UnlockedVault::<Demo>::unlock(&path, "135790").unwrap().meets_passphrase_rule());
    }

    #[test]
    fn a_new_passphrase_uses_a_new_data_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.enc");
        write_v1(&path, "135790", &demo());
        let mut v = UnlockedVault::<Demo>::unlock(&path, "135790").unwrap();
        let weak_copy = fs::read(&path).unwrap();
        assert!(v.verify_pin("135790"));
        v.install_passphrase(test_key("new-passphrase-456"), None).unwrap();
        assert!(v.meets_passphrase_rule());
        assert!(!v.verify_pin("135790"));
        assert!(v.verify_pin("new-passphrase-456"));
        assert!(matches!(UnlockedVault::<Demo>::unlock(&path, "135790"), Err(VaultError::WrongPin)));
        assert_eq!(UnlockedVault::<Demo>::unlock(&path, "new-passphrase-456").unwrap().state, demo());
        // The data key from the weak copy does not decrypt the new file.
        let old: serde_json::Value = serde_json::from_slice(&weak_copy).unwrap();
        let new: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let mut spliced = new.clone();
        spliced["wrap"] = old["wrap"].clone();
        spliced["salt"] = old["salt"].clone();
        spliced["params"] = old["params"].clone();
        spliced["passphrase"] = old["passphrase"].clone();
        fs::write(&path, serde_json::to_vec(&spliced).unwrap()).unwrap();
        assert!(matches!(UnlockedVault::<Demo>::unlock(&path, "135790"), Err(VaultError::WrongPin)));
    }

    #[test]
    fn a_short_pin_on_this_pc_opens_the_vault_until_forgotten() {
        let dir = tempfile::tempdir().unwrap();
        let (path, mut v) = new_vault(&dir);
        assert!(!this_pc_exists(&path));
        v.set_this_pc(test_key("246810")).unwrap();
        assert!(v.has_this_pc() && this_pc_exists(&path));
        let blob = fs::read(this_pc_path(&path)).unwrap();
        assert!(!String::from_utf8_lossy(&blob).contains("argon2") && !String::from_utf8_lossy(&blob).contains("m_kib"), "DPAPI-wrapped");
        assert!(v.verify_pin("246810") && v.verify_pin(PASS) && !v.verify_pin("246811"));
        let reopened = UnlockedVault::<Demo>::unlock(&path, "246810").unwrap();
        assert!(reopened.has_this_pc());
        assert_eq!(UnlockedVault::<Demo>::unlock(&path, PASS).unwrap().state, demo());
        // Forgetting needs no PIN and leaves the passphrase working.
        forget_this_pc(&path).unwrap();
        assert!(matches!(UnlockedVault::<Demo>::unlock(&path, "246810"), Err(VaultError::WrongPin)));
        assert!(!UnlockedVault::<Demo>::unlock(&path, PASS).unwrap().has_this_pc());
    }

    #[test]
    fn a_new_passphrase_replaces_or_drops_the_pc_pin() {
        let dir = tempfile::tempdir().unwrap();
        let (path, mut v) = new_vault(&dir);
        v.set_this_pc(test_key("246810")).unwrap();
        let stale = fs::read(this_pc_path(&path)).unwrap();
        v.install_passphrase(test_key("second-passphrase"), Some(test_key("975310"))).unwrap();
        assert!(UnlockedVault::<Demo>::unlock(&path, "975310").is_ok());
        assert!(matches!(UnlockedVault::<Demo>::unlock(&path, "246810"), Err(VaultError::WrongPin)));
        // A PIN file for the old data key cannot open the new vault.
        fs::write(this_pc_path(&path), &stale).unwrap();
        assert!(matches!(UnlockedVault::<Demo>::unlock(&path, "246810"), Err(VaultError::WrongPin)));
        let mut v = UnlockedVault::<Demo>::unlock(&path, "second-passphrase").unwrap();
        v.install_passphrase(test_key("third-passphrase!"), None).unwrap();
        assert!(!v.has_this_pc() && !this_pc_exists(&path));
    }

    #[test]
    fn a_pc_pin_file_from_another_account_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = new_vault(&dir);
        fs::write(this_pc_path(&path), b"not a DPAPI blob").unwrap();
        assert!(!UnlockedVault::<Demo>::unlock(&path, PASS).unwrap().has_this_pc());
        assert!(matches!(UnlockedVault::<Demo>::unlock(&path, "246810"), Err(VaultError::WrongPin)));
    }

    #[test]
    fn creating_a_vault_drops_a_leftover_pc_pin() {
        let dir = tempfile::tempdir().unwrap();
        let (path, mut v) = new_vault(&dir);
        v.set_this_pc(test_key("246810")).unwrap();
        fs::remove_file(&path).unwrap();
        let v = UnlockedVault::create_with_params(&path, "fresh-passphrase", demo(), KdfParams::INSECURE_TEST).unwrap();
        assert!(!v.has_this_pc() && !this_pc_exists(&path));
    }

    #[test]
    fn real_parameters_are_tuned_to_the_floor_or_above() {
        assert_eq!(KdfParams::INSECURE_TEST.tuned(), KdfParams::INSECURE_TEST);
        assert!(KdfParams::FLOOR.m_kib >= 128 * 1024 && KdfParams::DEFAULT.m_kib == 256 * 1024);
    }

    #[test]
    fn pin_guard_allows_free_attempts_then_backs_off_exponentially() {
        let mut g = PinGuard::default();
        let t0 = Instant::now();
        for _ in 0..PinGuard::FREE_ATTEMPTS - 1 {
            g.record(false, t0);
            assert!(g.check(t0).is_ok());
        }
        g.record(false, t0);
        assert_eq!(g.check(t0), Err(Duration::from_secs(30)));
        assert!(g.check(t0 + Duration::from_secs(31)).is_ok());
        g.record(false, t0);
        assert_eq!(g.check(t0), Err(Duration::from_secs(60)));
        for _ in 0..20 {
            g.record(false, t0);
        }
        assert_eq!(g.check(t0), Err(Duration::from_secs(3600)));
        g.record(true, t0);
        assert!(g.check(t0).is_ok());
        assert_eq!(g.consecutive_failures(), 0);
    }
}
