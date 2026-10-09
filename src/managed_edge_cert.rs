//! TLS policy and edge client certificate for managed RDS connections.
//!
//! Only public (Mozilla / webpki) roots are trusted for RDS calls, so a locally installed root -
//! AdGuard, antivirus web shields, corporate TLS inspection - cannot read or alter RDC's RDS
//! traffic. The device's Cloudflare client certificate is presented when the edge asks for one;
//! its private key is generated here and never leaves this machine.

use hbb_common::{anyhow::anyhow, log, ResultType};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use serde_derive::{Deserialize, Serialize};
use std::path::PathBuf;

const KEY_FILE: &str = "edge_client_key.pem";
const CERT_FILE: &str = "edge_client_cert.json";
const RENEW_BEFORE_SECS: i64 = 30 * 24 * 3600;

#[derive(Serialize, Deserialize)]
pub struct StoredEdgeCert {
    pub certificate: String,
    pub expires_at: i64,
}

fn store_dir() -> ResultType<PathBuf> {
    Ok(crate::platform::get_program_data_dir()?.join("RustDeskManaged"))
}

// On Android the key file is also Keystore-wrapped, like the app's other secrets (see
// platform::protect_machine_scope); on Windows the machine-secret ACL protects it.
#[cfg(target_os = "android")]
fn seal_key(key_pem: &str) -> ResultType<Vec<u8>> {
    crate::platform::protect_machine_scope(key_pem.as_bytes())
}

#[cfg(not(target_os = "android"))]
fn seal_key(key_pem: &str) -> ResultType<Vec<u8>> {
    Ok(key_pem.as_bytes().to_vec())
}

#[cfg(target_os = "android")]
fn open_key(bytes: &[u8]) -> Option<String> {
    String::from_utf8(crate::platform::unprotect_machine_scope(bytes).ok()?).ok()
}

#[cfg(not(target_os = "android"))]
fn open_key(bytes: &[u8]) -> Option<String> {
    String::from_utf8(bytes.to_vec()).ok()
}

fn load() -> Option<(String, StoredEdgeCert)> {
    let dir = store_dir().ok()?;
    let key = open_key(&std::fs::read(dir.join(KEY_FILE)).ok()?)?;
    let cert = serde_json::from_slice(&std::fs::read(dir.join(CERT_FILE)).ok()?).ok()?;
    Some((key, cert))
}

/// Changes whenever a new certificate is stored, so a cached TLS client knows to rebuild. The file
/// time is read rather than an in-process counter: the service stores the certificate, while the
/// session's --server process uses it too.
pub fn identity_stamp() -> Option<std::time::SystemTime> {
    std::fs::metadata(store_dir().ok()?.join(CERT_FILE)).ok()?.modified().ok()
}

/// No certificate yet, or within 30 days of expiry.
pub fn needs_renewal() -> bool {
    load().map_or(true, |(_, cert)| {
        cert.expires_at - hbb_common::get_time() / 1000 < RENEW_BEFORE_SECS
    })
}

/// A fresh P-256 key and a CSR for `rdc-device:<rustdesk id>` (the name RDS requires).
pub fn new_key_and_csr(rustdesk_id: &str) -> ResultType<(String, String)> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, format!("rdc-device:{rustdesk_id}"));
    let csr = params.serialize_request(&key)?;
    Ok((key.serialize_pem(), csr.pem()?))
}

/// Key and certificate are replaced together; the key file keeps the machine-secret ACL.
pub fn store(key_pem: &str, cert: &StoredEdgeCert) -> ResultType<()> {
    identity(key_pem, &cert.certificate)?;
    let dir = store_dir()?;
    for (name, bytes) in [
        (KEY_FILE, seal_key(key_pem)?),
        (CERT_FILE, serde_json::to_vec(cert)?),
    ] {
        let path = dir.join(name);
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, &path)?;
        crate::platform::set_path_permission_for_machine_secret(&path, false)?;
    }
    Ok(())
}

fn identity(
    key_pem: &str,
    cert_pem: &str,
) -> ResultType<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let chain = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("edge certificate: {e}"))?;
    if chain.is_empty() {
        return Err(anyhow!("edge certificate: no certificate in PEM"));
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .map_err(|e| anyhow!("edge certificate key: {e}"))?;
    Ok((chain, key))
}

/// Client TLS config for every managed RDS request: public roots only, plus the device's edge
/// client certificate when one is stored and usable.
pub fn rustls_config() -> ResultType<rustls::ClientConfig> {
    let roots = || {
        let mut store = rustls::RootCertStore::empty();
        store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        store
    };
    if let Some((key_pem, cert)) = load() {
        match identity(&key_pem, &cert.certificate).and_then(|(chain, key)| {
            Ok(rustls::ClientConfig::builder()
                .with_root_certificates(roots())
                .with_client_auth_cert(chain, key)?)
        }) {
            Ok(config) => return Ok(config),
            Err(e) => log::warn!("managed edge certificate unusable, connecting without it: {e}"),
        }
    }
    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(roots())
        .with_no_client_auth())
}
