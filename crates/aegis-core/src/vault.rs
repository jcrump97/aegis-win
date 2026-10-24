//! Portable encrypted vault (`./data/vault.enc`) and the global PIN guard.
//!
//! The PIN is stretched with Argon2id into a 256-bit key that encrypts the whole
//! state with AES-256-GCM. Nothing secret is stored in clear: no PIN, no PIN
//! hash, no verifier. A wrong PIN simply fails GCM authentication. The KDF
//! parameters and salt are bound into the ciphertext as associated data, so
//! tampering with the header fails decryption too.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const MIN_PIN_LEN: usize = 6;
pub const MAX_PIN_LEN: usize = 128;
const FORMAT_VERSION: u32 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("a vault already exists at this location")]
    AlreadyExists,
    #[error("no vault exists yet")]
    NotFound,
    #[error("incorrect PIN")]
    WrongPin,
    #[error("PIN must be at least {MIN_PIN_LEN} characters")]
    PinTooShort,
    #[error("PIN must be at most {MAX_PIN_LEN} characters")]
    PinTooLong,
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
    /// 64 MiB, 3 passes: roughly 0.2-0.5 s on a current desktop CPU.
    pub const DEFAULT: Self = Self { m_kib: 64 * 1024, t: 3, p: 1 };
    /// Cheap parameters so unit tests stay fast. Never used for real vaults.
    pub const INSECURE_TEST: Self = Self { m_kib: 64, t: 1, p: 1 };
}

#[derive(Serialize, Deserialize)]
struct VaultFile {
    version: u32,
    kdf: String,
    params: KdfParams,
    salt: String,
    nonce: String,
    ciphertext: String,
}

fn aad(params: &KdfParams, salt: &[u8]) -> Vec<u8> {
    format!("aegis-win-vault|v{FORMAT_VERSION}|argon2id|{}|{}|{}|{}", params.m_kib, params.t, params.p, hex::encode(salt))
        .into_bytes()
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

fn derive_key(pin: &str, salt: &[u8], params: &KdfParams) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let argon_params = Params::new(params.m_kib, params.t, params.p, Some(32))
        .map_err(|e| VaultError::Corrupt(format!("invalid KDF parameters: {e}")))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params)
        .hash_password_into(pin.as_bytes(), salt, key.as_mut())
        .map_err(|e| VaultError::Corrupt(format!("key derivation failed: {e}")))?;
    Ok(key)
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("the OS random number generator is unavailable");
    buf
}

pub fn vault_exists(path: &Path) -> bool {
    path.is_file()
}

/// An open vault: the derived key plus the decrypted state.
///
/// Deliberately not `Debug` or `Serialize`, so the key and state cannot end up
/// in a log line or an IPC response by accident.
pub struct UnlockedVault<T> {
    path: PathBuf,
    params: KdfParams,
    salt: [u8; SALT_LEN],
    key: Zeroizing<[u8; 32]>,
    pub state: T,
}

impl<T: Serialize + DeserializeOwned> UnlockedVault<T> {
    pub fn create(path: &Path, pin: &str, state: T) -> Result<Self, VaultError> {
        Self::create_with_params(path, pin, state, KdfParams::DEFAULT)
    }

    pub fn create_with_params(path: &Path, pin: &str, state: T, params: KdfParams) -> Result<Self, VaultError> {
        validate_new_pin(pin)?;
        if vault_exists(path) {
            return Err(VaultError::AlreadyExists);
        }
        let salt = random_bytes::<SALT_LEN>();
        let key = derive_key(pin, &salt, &params)?;
        let vault = Self { path: path.to_path_buf(), params, salt, key, state };
        vault.save()?;
        Ok(vault)
    }

    pub fn unlock(path: &Path, pin: &str) -> Result<Self, VaultError> {
        let raw = match fs::read(path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(VaultError::NotFound),
            Err(e) => return Err(e.into()),
        };
        let file: VaultFile = serde_json::from_slice(&raw).map_err(|e| VaultError::Corrupt(e.to_string()))?;
        if file.version != FORMAT_VERSION || file.kdf != "argon2id" {
            return Err(VaultError::Corrupt(format!("unsupported format {} / {}", file.version, file.kdf)));
        }
        let salt: [u8; SALT_LEN] = decode_fixed(&file.salt, "salt")?;
        let nonce: [u8; NONCE_LEN] = decode_fixed(&file.nonce, "nonce")?;
        let ciphertext = hex::decode(&file.ciphertext).map_err(|_| VaultError::Corrupt("ciphertext is not hex".into()))?;

        let key = derive_key(pin, &salt, &file.params)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_ref()));
        let aad = aad(&file.params, &salt);
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(Nonce::from_slice(&nonce), Payload { msg: &ciphertext, aad: &aad })
                .map_err(|_| VaultError::WrongPin)?,
        );
        let state = serde_json::from_slice(&plaintext).map_err(|e| VaultError::Corrupt(e.to_string()))?;
        Ok(Self { path: path.to_path_buf(), params: file.params, salt, key, state })
    }

    /// Re-encrypts the state with a fresh nonce and replaces the file atomically.
    pub fn save(&self) -> Result<(), VaultError> {
        let plaintext = Zeroizing::new(serde_json::to_vec(&self.state).map_err(|e| VaultError::Corrupt(e.to_string()))?);
        let nonce = random_bytes::<NONCE_LEN>();
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(self.key.as_ref()));
        let aad = aad(&self.params, &self.salt);
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: &plaintext, aad: &aad })
            .map_err(|_| VaultError::Corrupt("encryption failed".into()))?;
        let file = VaultFile {
            version: FORMAT_VERSION,
            kdf: "argon2id".into(),
            params: self.params,
            salt: hex::encode(self.salt),
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ciphertext),
        };
        let json = serde_json::to_vec_pretty(&file).map_err(|e| VaultError::Corrupt(e.to_string()))?;
        write_atomic(&self.path, &json)?;
        Ok(())
    }

    /// Checks a PIN against the open vault in constant time (used for approvals).
    pub fn verify_pin(&self, pin: &str) -> bool {
        self.verifier().verify(pin)
    }

    /// A detached copy of what is needed to check a PIN, so the slow Argon2
    /// derivation can run without holding the lock on the vault.
    pub fn verifier(&self) -> PinVerifier {
        PinVerifier { params: self.params, salt: self.salt, key: self.key.clone() }
    }

    pub fn change_pin(&mut self, current: &str, new_pin: &str) -> Result<(), VaultError> {
        if !self.verify_pin(current) {
            return Err(VaultError::WrongPin);
        }
        let key = NewKey::derive(new_pin, self.params)?;
        self.install_key(key)
    }

    pub fn params(&self) -> KdfParams {
        self.params
    }

    /// Switches to a key derived with [`NewKey::derive`] and re-encrypts.
    pub fn install_key(&mut self, new: NewKey) -> Result<(), VaultError> {
        let (old_salt, old_key) = (self.salt, self.key.clone());
        self.salt = new.salt;
        self.key = new.key;
        self.save().inspect_err(|_| {
            self.salt = old_salt;
            self.key = old_key;
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// A key for a new PIN, derived away from the vault lock (Argon2 is slow).
pub struct NewKey {
    salt: [u8; SALT_LEN],
    key: Zeroizing<[u8; 32]>,
}

impl NewKey {
    pub fn derive(new_pin: &str, params: KdfParams) -> Result<Self, VaultError> {
        validate_new_pin(new_pin)?;
        let salt = random_bytes::<SALT_LEN>();
        let key = derive_key(new_pin, &salt, &params)?;
        Ok(Self { salt, key })
    }
}

pub struct PinVerifier {
    params: KdfParams,
    salt: [u8; SALT_LEN],
    key: Zeroizing<[u8; 32]>,
}

impl PinVerifier {
    pub fn verify(&self, pin: &str) -> bool {
        match derive_key(pin, &self.salt, &self.params) {
            Ok(candidate) => bool::from(candidate.as_ref().ct_eq(self.key.as_ref())),
            Err(_) => false,
        }
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
/// approvals, and the browser approval portal. Per-ticket lockout alone is not
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

    fn new_vault(dir: &tempfile::TempDir) -> (PathBuf, UnlockedVault<Demo>) {
        let path = dir.path().join("vault.enc");
        let v = UnlockedVault::create_with_params(&path, "correct-pin", demo(), KdfParams::INSECURE_TEST).unwrap();
        (path, v)
    }

    #[test]
    fn round_trips_state_and_keeps_secrets_out_of_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = new_vault(&dir);
        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("sk-test-123"));
        assert!(!raw.contains("correct-pin"));
        let reopened = UnlockedVault::<Demo>::unlock(&path, "correct-pin").unwrap();
        assert_eq!(reopened.state, demo());
    }

    #[test]
    fn wrong_pin_fails_and_missing_vault_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = new_vault(&dir);
        assert!(matches!(UnlockedVault::<Demo>::unlock(&path, "wrong-pin"), Err(VaultError::WrongPin)));
        assert!(matches!(
            UnlockedVault::<Demo>::unlock(&dir.path().join("nope.enc"), "correct-pin"),
            Err(VaultError::NotFound)
        ));
    }

    #[test]
    fn refuses_short_pins_and_overwriting_an_existing_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.enc");
        assert!(matches!(
            UnlockedVault::create_with_params(&path, "12345", demo(), KdfParams::INSECURE_TEST),
            Err(VaultError::PinTooShort)
        ));
        let (path, _) = new_vault(&dir);
        assert!(matches!(
            UnlockedVault::create_with_params(&path, "another-pin", demo(), KdfParams::INSECURE_TEST),
            Err(VaultError::AlreadyExists)
        ));
    }

    #[test]
    fn header_tampering_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = new_vault(&dir);
        let mut file: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        file["params"]["t"] = serde_json::json!(2);
        fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        assert!(matches!(UnlockedVault::<Demo>::unlock(&path, "correct-pin"), Err(VaultError::WrongPin)));
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
        assert_eq!(UnlockedVault::<Demo>::unlock(&path, "correct-pin").unwrap().state.n, 8);
    }

    #[test]
    fn verify_and_change_pin() {
        let dir = tempfile::tempdir().unwrap();
        let (path, mut v) = new_vault(&dir);
        assert!(v.verify_pin("correct-pin"));
        assert!(!v.verify_pin("correct-pim"));
        assert!(matches!(v.change_pin("bad", "new-pin-456"), Err(VaultError::WrongPin)));
        v.change_pin("correct-pin", "new-pin-456").unwrap();
        assert!(matches!(UnlockedVault::<Demo>::unlock(&path, "correct-pin"), Err(VaultError::WrongPin)));
        assert_eq!(UnlockedVault::<Demo>::unlock(&path, "new-pin-456").unwrap().state, demo());
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
