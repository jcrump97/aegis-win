//! HTTPS for a LAN bind of the MCP server ([ADR 0004 §2](../../../documentation/adr/0004-approval-channel-and-key-hardening.md)).
//!
//! - **Generated (Option A):** an ECDSA P-256 certificate for the bound
//!   address and `localhost`, `CA:FALSE`, extended key usage `serverAuth`,
//!   valid for 397 days. It is replaced 30 days before it expires and when the
//!   bound address changes. Its private key lives only in the vault.
//! - **The owner's own (Option D):** `mcp-cert.pem` and `mcp-key.pem` in the
//!   data folder are read once, at the next start: the key moves into the
//!   vault and its file is removed.
//!
//! Only the public certificate is written to disk (`mcp-cert.pem`), for agent
//! clients to trust. Loopback stays plain HTTP.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use chrono::{Datelike, NaiveDate};
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, Semaphore};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

use crate::secret::Secret;

/// The public certificate, next to the vault, for agent clients to trust.
pub const CERT_FILE: &str = "mcp-cert.pem";
/// The owner's own key, read once and moved into the vault.
pub const KEY_FILE: &str = "mcp-key.pem";
/// iOS refuses server certificates valid for more than 825 days; 397 stays inside every limit.
pub const VALID_DAYS: u64 = 397;
/// A generated certificate is replaced this long before it expires.
pub const RENEW_DAYS: u64 = 30;
/// Shown whenever a generated certificate is replaced.
pub const CHANGED: &str = "Your AegisWin certificate changed. Phones will warn once more, and agents need the new certificate file.";

/// The LAN certificate and its key, as kept in the vault.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsMaterial {
    /// The certificate chain, PEM, leaf first.
    pub cert_pem: String,
    /// PKCS#8, SEC1 or PKCS#1 PEM. Never written to disk.
    pub key_pem: Secret,
    /// Set when AegisWin made it; `None` for the owner's own certificate.
    pub generated: Option<Generated>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Generated {
    /// The address it was made for.
    pub host: String,
    /// When it expires (00:00 UTC that day).
    pub not_after: NaiveDate,
}

/// What the app shows about the certificate in use. No key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsInfo {
    /// SHA-256 of the leaf certificate, upper-case hex in groups of 4.
    pub fingerprint: String,
    /// When a generated certificate expires (00:00 UTC that day).
    pub not_after: Option<NaiveDate>,
    /// The owner brought it (Option D).
    pub own: bool,
    /// Where its public certificate is, for agents.
    pub cert_path: String,
    /// The public certificate, PEM, for **Copy certificate**.
    pub cert_pem: String,
}

impl TlsMaterial {
    /// Makes a certificate for `host` (and `localhost`), valid from yesterday
    /// (for clock skew) across 397 calendar days.
    pub fn generate(host: Ipv4Addr, today: NaiveDate) -> Result<Self, String> {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
        let mut params = rcgen::CertificateParams::new(vec![host.to_string(), "localhost".to_owned()]).map_err(|e| e.to_string())?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, format!("AegisWin {host}"));
        params.is_ca = rcgen::IsCa::ExplicitNoCa;
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let from = today.pred_opt().ok_or("bad date")?;
        let until = from.checked_add_days(chrono::Days::new(VALID_DAYS - 1)).ok_or("bad date")?;
        // rcgen's date type, without naming the `time` crate here.
        let ymd = |d: NaiveDate| rcgen::date_time_ymd(d.year(), d.month() as u8, d.day() as u8);
        params.not_before = ymd(from);
        params.not_after = ymd(until);
        let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
        Ok(Self {
            cert_pem: cert.pem(),
            key_pem: Secret::new(key.serialize_pem()),
            generated: Some(Generated { host: host.to_string(), not_after: until }),
        })
    }

    /// Why a generated certificate must be replaced before serving `host`, if it must.
    /// The owner's own certificate is never replaced.
    pub fn replace_reason(&self, host: Ipv4Addr, today: NaiveDate) -> Option<&'static str> {
        let g = self.generated.as_ref()?;
        if g.host != host.to_string() {
            Some("the LAN address changed")
        } else if today.checked_add_days(chrono::Days::new(RENEW_DAYS)).is_none_or(|d| d > g.not_after) {
            Some("it expires within 30 days")
        } else {
            None
        }
    }

    /// The `rustls` configuration. Fails if the key does not match the certificate.
    pub fn server_config(&self) -> Result<Arc<ServerConfig>, String> {
        let (chain, key) = parse(self.cert_pem.as_bytes(), self.key_pem.expose().as_bytes())?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .map_err(|e| format!("the key does not fit the certificate ({e})"))?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }

    pub fn info(&self, cert_path: &Path) -> TlsInfo {
        TlsInfo {
            fingerprint: fingerprint(self.cert_pem.as_bytes()).unwrap_or_default(),
            not_after: self.generated.as_ref().map(|g| g.not_after),
            own: self.generated.is_none(),
            cert_path: cert_path.display().to_string(),
            cert_pem: self.cert_pem.clone(),
        }
    }

    /// The certificate to serve `host` with, from the data folder `dir` and
    /// the vault's `current`: the owner's own when `mcp-key.pem` is there,
    /// else `current` unless it must be replaced, else a new one.
    pub fn choose(dir: &Path, current: Option<Self>, host: Ipv4Addr, today: NaiveDate) -> Result<(Self, Choice), String> {
        if let Some(own) = Self::import(dir)? {
            return Ok((own, Choice::Imported));
        }
        match current {
            Some(kept) if kept.replace_reason(host, today).is_none() => Ok((kept, Choice::Kept)),
            replaced => Ok((Self::generate(host, today)?, Choice::New { replaced: replaced.is_some() })),
        }
    }

    /// Reads the owner's `mcp-cert.pem` and `mcp-key.pem` when the key file
    /// exists (Option D). `Ok(None)` when there is none. The caller removes
    /// the key file once the result is in the vault.
    pub fn import(dir: &Path) -> Result<Option<Self>, String> {
        let key_path = dir.join(KEY_FILE);
        if !key_path.exists() {
            return Ok(None);
        }
        let key = std::fs::read_to_string(&key_path).map_err(|e| format!("{KEY_FILE} could not be read: {e}"))?;
        let cert = std::fs::read_to_string(dir.join(CERT_FILE)).map_err(|e| format!("{KEY_FILE} is there but {CERT_FILE} could not be read: {e}"))?;
        let material = Self { cert_pem: cert, key_pem: Secret::new(key), generated: None };
        material.server_config()?;
        Ok(Some(material))
    }
}

/// What `TlsMaterial::choose` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    /// The vault's certificate, unchanged.
    Kept,
    /// The owner's own, read from the data folder; store it and remove the key file.
    Imported,
    /// Generated; `replaced` when there was one before.
    New { replaced: bool },
}

fn parse(cert: &[u8], key: &[u8]) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(cert).collect::<Result<_, _>>().map_err(|e| format!("{CERT_FILE} is not a PEM certificate ({e})"))?;
    if chain.is_empty() {
        return Err(format!("{CERT_FILE} holds no certificate"));
    }
    let key = PrivateKeyDer::from_pem_slice(key).map_err(|e| format!("{KEY_FILE} is not a PEM private key ({e})"))?;
    Ok((chain, key))
}

/// SHA-256 of the first certificate in `pem`, as `AB12 CD34 …`.
pub fn fingerprint(pem: &[u8]) -> Option<String> {
    let leaf = CertificateDer::pem_slice_iter(pem).next()?.ok()?;
    let hex = hex::encode_upper(Sha256::digest(leaf.as_ref()));
    Some(hex.as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join(" "))
}

/// At most this many handshakes run at once; more connections wait.
const MAX_HANDSHAKES: usize = 32;
/// A client that has not finished its handshake by then is dropped.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// A TLS listener for `axum::serve`. Handshakes run on their own tasks, so a
/// slow or silent client cannot hold up the others.
pub struct TlsListener {
    ready: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local: SocketAddr,
}

impl TlsListener {
    /// Accepts on `listener` until `stopped` turns true.
    pub fn new(listener: TcpListener, config: Arc<ServerConfig>, mut stopped: watch::Receiver<bool>) -> io::Result<Self> {
        let local = listener.local_addr()?;
        let (tx, ready) = mpsc::channel(MAX_HANDSHAKES);
        let acceptor = TlsAcceptor::from(config);
        let slots = Arc::new(Semaphore::new(MAX_HANDSHAKES));
        tokio::spawn(async move {
            loop {
                let Ok(permit) = slots.clone().acquire_owned().await else { return };
                let (tcp, peer) = tokio::select! {
                    _ = async { let _ = stopped.wait_for(|s| *s).await; } => return,
                    accepted = listener.accept() => match accepted {
                        Ok(a) => a,
                        // Out of sockets or similar: try again shortly.
                        Err(_) => {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            continue;
                        }
                    },
                };
                let (acceptor, tx) = (acceptor.clone(), tx.clone());
                tokio::spawn(async move {
                    if let Ok(Ok(tls)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                        let _ = tx.send((tls, peer)).await;
                    }
                    drop(permit);
                });
            }
        });
        Ok(Self { ready, local })
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.ready.recv().await {
            Some(conn) => conn,
            // Stopped: graceful shutdown ends the server.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.local)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn day(s: &str) -> NaiveDate {
        s.parse().unwrap()
    }

    #[test]
    fn a_generated_certificate_is_for_its_address_and_is_replaced_in_time() {
        let host = Ipv4Addr::new(192, 168, 1, 20);
        let m = TlsMaterial::generate(host, day("2026-11-10")).unwrap();
        let g = m.generated.clone().unwrap();
        assert_eq!(g.not_after, day("2027-12-10"), "396 days after yesterday, under the 398-day browser limit");
        assert!(m.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(m.key_pem.expose().contains("PRIVATE KEY"));
        m.server_config().unwrap();
        assert_eq!(m.replace_reason(host, day("2026-11-10")), None);
        assert_eq!(m.replace_reason(Ipv4Addr::new(192, 168, 1, 21), day("2026-11-10")), Some("the LAN address changed"));
        assert_eq!(m.replace_reason(host, day("2027-11-10")), None);
        assert_eq!(m.replace_reason(host, day("2027-11-11")), Some("it expires within 30 days"));
        let info = m.info(Path::new(r"C:\x\mcp-cert.pem"));
        assert_eq!(info.fingerprint.len(), 64 + 15, "{}", info.fingerprint);
        assert!(!info.own && info.cert_pem == m.cert_pem);
        // Two certificates never share a key.
        let other = TlsMaterial::generate(host, day("2026-11-10")).unwrap();
        assert_ne!(other.key_pem.expose(), m.key_pem.expose());
        assert_ne!(other.info(Path::new("x")).fingerprint, info.fingerprint);
    }

    #[test]
    fn the_owners_certificate_is_imported_only_with_a_matching_key() {
        let dir = tempfile::tempdir().unwrap();
        assert!(TlsMaterial::import(dir.path()).unwrap().is_none(), "no key file, nothing to import");
        let a = TlsMaterial::generate(Ipv4Addr::new(10, 0, 0, 2), day("2026-11-10")).unwrap();
        let b = TlsMaterial::generate(Ipv4Addr::new(10, 0, 0, 2), day("2026-11-10")).unwrap();
        std::fs::write(dir.path().join(CERT_FILE), &a.cert_pem).unwrap();
        std::fs::write(dir.path().join(KEY_FILE), b.key_pem.expose()).unwrap();
        assert!(TlsMaterial::import(dir.path()).err().unwrap().contains("does not fit"));
        std::fs::write(dir.path().join(KEY_FILE), "not a key").unwrap();
        assert!(TlsMaterial::import(dir.path()).err().unwrap().contains("not a PEM private key"));
        std::fs::write(dir.path().join(KEY_FILE), a.key_pem.expose()).unwrap();
        let own = TlsMaterial::import(dir.path()).unwrap().unwrap();
        assert!(own.generated.is_none());
        assert_eq!(own.replace_reason(Ipv4Addr::new(10, 0, 0, 3), day("2030-01-01")), None, "the owner's certificate is never replaced");
        assert!(own.info(Path::new("x")).own);
    }

    #[test]
    fn the_certificate_is_kept_until_the_owner_brings_one_or_it_must_be_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let host = Ipv4Addr::new(192, 168, 1, 20);
        let today = day("2026-11-10");
        let (first, how) = TlsMaterial::choose(dir.path(), None, host, today).unwrap();
        assert_eq!(how, Choice::New { replaced: false });
        let (kept, how) = TlsMaterial::choose(dir.path(), Some(first.clone()), host, today).unwrap();
        assert_eq!((how, kept.cert_pem.as_str()), (Choice::Kept, first.cert_pem.as_str()));
        let (moved, how) = TlsMaterial::choose(dir.path(), Some(first.clone()), Ipv4Addr::new(192, 168, 1, 21), today).unwrap();
        assert_eq!(how, Choice::New { replaced: true });
        assert_eq!(moved.generated.unwrap().host, "192.168.1.21");
        let (_, how) = TlsMaterial::choose(dir.path(), Some(first.clone()), host, day("2027-11-11")).unwrap();
        assert_eq!(how, Choice::New { replaced: true }, "renewed 30 days before it expires");

        let own = TlsMaterial::generate(Ipv4Addr::new(10, 0, 0, 9), today).unwrap();
        std::fs::write(dir.path().join(CERT_FILE), &own.cert_pem).unwrap();
        std::fs::write(dir.path().join(KEY_FILE), own.key_pem.expose()).unwrap();
        let (imported, how) = TlsMaterial::choose(dir.path(), Some(first), host, today).unwrap();
        assert_eq!((how, imported.cert_pem.as_str()), (Choice::Imported, own.cert_pem.as_str()));
        std::fs::write(dir.path().join(KEY_FILE), "broken").unwrap();
        assert!(TlsMaterial::choose(dir.path(), None, host, today).is_err(), "a broken key file is reported, not skipped");
    }

    /// A real handshake through `TlsListener`, checked by Windows' own TLS
    /// (reqwest uses Schannel here) trusting only the generated certificate.
    #[tokio::test]
    async fn an_agent_trusting_the_certificate_file_connects_and_others_are_refused() {
        let today = chrono::Utc::now().date_naive();
        let m = TlsMaterial::generate(Ipv4Addr::LOCALHOST, today).unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = tcp.local_addr().unwrap().port();
        let (stop, rx) = watch::channel(false);
        let listener = TlsListener::new(tcp, m.server_config().unwrap(), rx).unwrap();
        let app = axum::Router::new().route("/mcp", axum::routing::get(|| async { "hello" }));
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        let url = format!("https://127.0.0.1:{port}/mcp");

        let cert = reqwest::Certificate::from_pem(m.cert_pem.as_bytes()).unwrap();
        let trusting = reqwest::Client::builder().add_root_certificate(cert).build().unwrap();
        let body = trusting.get(&url).send().await.unwrap().text().await.unwrap();
        assert_eq!(body, "hello");

        let other = reqwest::Client::builder().build().unwrap();
        assert!(other.get(&url).send().await.is_err(), "a client without the certificate is refused");

        // A silent client does not hold up the others.
        let _idle = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        assert_eq!(trusting.get(&url).send().await.unwrap().text().await.unwrap(), "hello");
        stop.send(true).unwrap();
        server.abort();
    }
}
