//! Local certificate authority used to mint per-host certificates for TLS interception.

use std::collections::HashMap;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context as _, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use time::{Duration, OffsetDateTime};

const CA_CERT_FILE: &str = "ca.pem";
const CA_KEY_FILE: &str = "ca-key.pem";

/// The per-user directory that holds the CA (`<OS data dir>/roxy`).
///
/// # Errors
/// Fails when the OS does not report a data directory.
pub fn default_dir() -> Result<PathBuf> {
    // Not the cache dir: an OS cache purge would silently break every client's trust.
    dirs::data_dir()
        .map(|d| d.join("roxy"))
        .context("could not determine the per-user data directory")
}

/// Path of the CA certificate PEM inside `dir`.
#[must_use]
pub fn cert_path(dir: &Path) -> PathBuf {
    dir.join(CA_CERT_FILE)
}

pub struct CertificateAuthority {
    issuer: Issuer<'static, KeyPair>,
    ca_der: CertificateDer<'static>,
    ca_pem: String,
    leaf_key: KeyPair,
    signing_key: Arc<dyn rustls::sign::SigningKey>,
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl std::fmt::Debug for CertificateAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateAuthority")
            .finish_non_exhaustive()
    }
}

impl CertificateAuthority {
    /// Loads the CA from `dir`, generating and saving a new one on first run.
    ///
    /// # Errors
    /// Fails on I/O errors or when the stored CA cannot be parsed.
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        let cert_file = dir.join(CA_CERT_FILE);
        let key_file = dir.join(CA_KEY_FILE);
        let (cert_pem, key_pem) = if cert_file.exists() && key_file.exists() {
            (
                fs::read_to_string(&cert_file)
                    .with_context(|| format!("reading {}", cert_file.display()))?,
                fs::read_to_string(&key_file)
                    .with_context(|| format!("reading {}", key_file.display()))?,
            )
        } else {
            let (cert_pem, key_pem) = generate_ca()?;
            fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
            write_private(&key_file, &key_pem)?;
            fs::write(&cert_file, &cert_pem)
                .with_context(|| format!("writing {}", cert_file.display()))?;
            tracing::info!(path = %cert_file.display(), "generated new CA certificate");
            (cert_pem, key_pem)
        };
        Self::from_pem(&cert_pem, &key_pem)
    }

    /// Builds a CA from PEM-encoded certificate and private key.
    ///
    /// # Errors
    /// Fails when either PEM cannot be parsed.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self> {
        let key = KeyPair::from_pem(key_pem).context("parsing CA private key")?;
        let issuer = Issuer::from_ca_cert_pem(cert_pem, key).context("parsing CA certificate")?;
        let ca_der = rustls_pemfile_cert(cert_pem)?;
        let leaf_key = KeyPair::generate().context("generating leaf key")?;
        let provider = CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
        let signing_key = provider
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                leaf_key.serialize_der(),
            )))
            .context("loading leaf key")?;
        Ok(Self {
            issuer,
            ca_der,
            ca_pem: cert_pem.to_owned(),
            leaf_key,
            signing_key,
            cache: Mutex::new(HashMap::new()),
        })
    }

    #[must_use]
    pub fn cert_pem(&self) -> &str {
        &self.ca_pem
    }

    #[must_use]
    pub const fn cert_der(&self) -> &CertificateDer<'static> {
        &self.ca_der
    }

    /// Returns a certificate for `host` signed by this CA, minting it on first use.
    ///
    /// # Errors
    /// Fails when `host` is not a valid DNS name or IP address.
    pub fn leaf_for(&self, host: &str) -> Result<Arc<CertifiedKey>> {
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase();
        if let Some(found) = self.cache.lock().ok().and_then(|c| c.get(&host).cloned()) {
            return Ok(found);
        }
        let mut params = CertificateParams::new(vec![host.clone()])
            .with_context(|| format!("invalid host name {host:?}"))?;
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, host.clone());
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::days(1);
        // Apple rejects leaf certificates valid for more than 398 days.
        params.not_after = now + Duration::days(365);
        let cert = params
            .signed_by(&self.leaf_key, &self.issuer)
            .context("signing leaf certificate")?;
        let certified = Arc::new(CertifiedKey::new(
            vec![cert.der().clone(), self.ca_der.clone()],
            Arc::clone(&self.signing_key),
        ));
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(host, Arc::clone(&certified));
        }
        Ok(certified)
    }
}

fn generate_ca() -> Result<(String, String)> {
    let key = KeyPair::generate().context("generating CA key")?;
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "roxy local CA");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "roxy");
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(3650);
    let cert = params.self_signed(&key).context("self-signing CA")?;
    Ok((cert.pem(), key.serialize_pem()))
}

fn write_private(path: &Path, contents: &str) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("writing {}", path.display()))
}

fn rustls_pemfile_cert(pem: &str) -> Result<CertificateDer<'static>> {
    use rustls::pki_types::pem::PemObject as _;
    CertificateDer::from_pem_slice(pem.as_bytes()).context("decoding CA certificate PEM")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_then_reloads_same_ca() {
        let dir = tempfile::tempdir().unwrap();
        let first = CertificateAuthority::load_or_create(dir.path()).unwrap();
        let second = CertificateAuthority::load_or_create(dir.path()).unwrap();
        assert_eq!(first.cert_pem(), second.cert_pem());
        assert!(cert_path(dir.path()).exists());
    }

    #[cfg(unix)]
    #[test]
    fn key_file_is_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        CertificateAuthority::load_or_create(dir.path()).unwrap();
        let mode = fs::metadata(dir.path().join(CA_KEY_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn mints_and_caches_leaf_certs() {
        let dir = tempfile::tempdir().unwrap();
        let ca = CertificateAuthority::load_or_create(dir.path()).unwrap();
        let a = ca.leaf_for("example.com").unwrap();
        let b = ca.leaf_for("EXAMPLE.com").unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(a.cert.len(), 2);
        ca.leaf_for("127.0.0.1").unwrap();
        ca.leaf_for("[::1]").unwrap();
    }
}
