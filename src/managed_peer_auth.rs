//! Managed peer authentication: only RDS-approved devices may connect to each other, on any
//! route. RDS signs a short-lived certificate binding each approved device's RustDesk id to its
//! identity key (`Config::get_key_pair()`); the controlling device proves it on every login by
//! signing the receiving device's login challenge, and the receiving device verifies that before
//! the password step, applying the mode RDS hands out with the directory (off | log | enforce).
//!
//! Certificate: `b64url(payload_json).b64url(ed25519 signature by the RDS peer CA)`.
//! Proof: `u16 LE cert length | cert | 64-byte ed25519 signature of proof_message()`.
use hbb_common::{
    base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _},
    config::Config,
    log,
    sodiumoxide::crypto::sign,
    ResultType,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant},
};

const CERT_FILE: &str = "peer_cert.json";
const PROOF_DOMAIN: &[u8] = b"rdc-peer-proof-v1\0";
const CLOCK_SKEW_SECS: i64 = 300;
// The directory refreshes about every minute; older than this and the receiving side stops
// treating "not in the directory" as "not approved" and relies on the certificate alone.
const DIRECTORY_FRESH_FOR: Duration = Duration::from_secs(600);

pub const MODE_OFF: &str = "off";
pub const MODE_LOG: &str = "log";
pub const MODE_ENFORCE: &str = "enforce";

/// The certificate the service keeps for this device, as fetched from RDS.
#[derive(Serialize, Deserialize, Clone)]
pub struct StoredCert {
    pub cert: String,
    /// Local unix seconds when it was fetched; renewal is due `renew_after_seconds` later.
    pub fetched_at: i64,
    pub renew_after_seconds: i64,
}

#[derive(Deserialize, Clone, Debug)]
pub struct CertPayload {
    pub v: u32,
    pub rid: String,
    pub pk: String,
    pub nbf: i64,
    pub exp: i64,
    pub sn: String,
}

/// What the service knows from the last directory download, for one controller id.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct PeerAuthInfo {
    pub mode: String,
    /// The controller's identity key as listed by RDS, when it is an approved device.
    pub peer_key: Option<String>,
    /// Whether the directory is recent enough to treat "not listed" as "not approved".
    pub directory_fresh: bool,
    pub relay_fallback_delay_ms: u64,
    /// Whether RDS has WebRTC on for this device ("on", or "test" with this device listed).
    #[serde(default)]
    pub webrtc: bool,
}

struct DirectoryAuth {
    mode: String,
    relay_fallback_delay_ms: u64,
    webrtc: bool,
    keys: HashMap<String, String>,
    updated: Instant,
}

static DIRECTORY: Mutex<Option<DirectoryAuth>> = Mutex::new(None);

fn now_secs() -> i64 {
    hbb_common::get_time() / 1000
}

fn ca_public_key() -> Option<sign::PublicKey> {
    let encoded = option_env!("RUSTDESK_MANAGED_PEER_CA_PUBKEY")?.trim();
    sign::PublicKey::from_slice(&crate::decode64(encoded).ok()?)
}

fn cert_path() -> ResultType<PathBuf> {
    Ok(crate::platform::get_program_data_dir()?
        .join("RustDeskManaged")
        .join(CERT_FILE))
}

pub fn load_cert() -> Option<StoredCert> {
    serde_json::from_slice(&std::fs::read(cert_path().ok()?).ok()?).ok()
}

/// Atomic replace; the certificate is not secret (useless without the device key).
pub fn store_cert(cert: &StoredCert) -> ResultType<()> {
    let path = cert_path()?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(cert)?)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Whether the service should fetch a fresh certificate: none yet, due for renewal, or within an
/// hour of expiry (e.g. after the device was off for days).
pub fn cert_needs_renewal() -> bool {
    let Some(stored) = load_cert() else {
        return true;
    };
    let now = now_secs();
    if now - stored.fetched_at >= stored.renew_after_seconds.max(60) || now < stored.fetched_at {
        return true;
    }
    parse_payload(&stored.cert).map_or(true, |p| now >= p.exp - 3600)
}

fn b64url(s: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| "certificate is not valid base64url".to_owned())
}

fn parse_payload(cert: &str) -> Result<CertPayload, String> {
    let (payload, _) = cert.split_once('.').ok_or("malformed certificate")?;
    serde_json::from_slice(&b64url(payload)?).map_err(|_| "malformed certificate payload".to_owned())
}

fn signature(bytes: &[u8]) -> Result<sign::Signature, String> {
    sign::Signature::from_bytes(bytes).map_err(|_| "malformed signature".to_owned())
}

/// Checks a certificate against the RDS peer CA key built into this client.
pub fn verify_cert(cert: &str, now: i64) -> Result<CertPayload, String> {
    let ca = ca_public_key().ok_or("RDS peer CA key is not built into this client")?;
    let (payload_b64, sig_b64) = cert.split_once('.').ok_or("malformed certificate")?;
    let payload = b64url(payload_b64)?;
    if !sign::verify_detached(&signature(&b64url(sig_b64)?)?, &payload, &ca) {
        return Err("certificate is not signed by RDS".to_owned());
    }
    let payload: CertPayload =
        serde_json::from_slice(&payload).map_err(|_| "malformed certificate payload".to_owned())?;
    if payload.v != 1 {
        return Err(format!("unsupported certificate version {}", payload.v));
    }
    if now + CLOCK_SKEW_SECS < payload.nbf {
        return Err("certificate is not valid yet".to_owned());
    }
    if now - CLOCK_SKEW_SECS > payload.exp {
        return Err("certificate has expired".to_owned());
    }
    Ok(payload)
}

fn proof_message(challenge: &str, controlled_id: &str, controller_id: &str, session_id: u64) -> Vec<u8> {
    let mut msg = PROOF_DOMAIN.to_vec();
    for part in [challenge, controlled_id, controller_id] {
        msg.extend_from_slice(part.as_bytes());
        msg.push(0);
    }
    msg.extend_from_slice(&session_id.to_le_bytes());
    msg
}

/// Runs in the `--server` process, which holds the device key: the proof this device attaches to
/// a login on `controlled_id`. None without a certificate or key.
pub fn build_proof(
    challenge: &str,
    controlled_id: &str,
    controller_id: &str,
    session_id: u64,
) -> Option<Vec<u8>> {
    if controller_id != Config::get_id() {
        log::warn!("managed peer auth: refusing to sign a proof for another id");
        return None;
    }
    let cert = load_cert()?.cert;
    let sk = sign::SecretKey::from_slice(&Config::get_key_pair().0)?;
    let sig = sign::sign_detached(
        &proof_message(challenge, controlled_id, controller_id, session_id),
        &sk,
    );
    let len = u16::try_from(cert.len()).ok()?;
    let mut proof = Vec::with_capacity(2 + cert.len() + 64);
    proof.extend_from_slice(&len.to_le_bytes());
    proof.extend_from_slice(cert.as_bytes());
    proof.extend_from_slice(&sig.to_bytes());
    Some(proof)
}

/// Runs in the receiving `--server`: checks a controller's proof for this login.
pub fn verify_proof(
    proof: &[u8],
    challenge: &str,
    controlled_id: &str,
    controller_id: &str,
    session_id: u64,
    info: &PeerAuthInfo,
) -> Result<CertPayload, String> {
    if proof.is_empty() {
        return Err("no device certificate presented (older or unmanaged client)".to_owned());
    }
    if proof.len() < 2 {
        return Err("malformed proof".to_owned());
    }
    let cert_len = u16::from_le_bytes([proof[0], proof[1]]) as usize;
    if proof.len() != 2 + cert_len + 64 {
        return Err("malformed proof".to_owned());
    }
    let cert = std::str::from_utf8(&proof[2..2 + cert_len]).map_err(|_| "malformed proof".to_owned())?;
    let payload = verify_cert(cert, now_secs())?;
    if payload.rid != controller_id {
        return Err(format!("certificate belongs to {}, not {}", payload.rid, controller_id));
    }
    let pk = crate::decode64(&payload.pk)
        .ok()
        .and_then(|raw| sign::PublicKey::from_slice(&raw))
        .ok_or("malformed certificate key")?;
    if !sign::verify_detached(
        &signature(&proof[2 + cert_len..])?,
        &proof_message(challenge, controlled_id, controller_id, session_id),
        &pk,
    ) {
        return Err("proof signature does not match the certificate".to_owned());
    }
    match &info.peer_key {
        Some(listed) if listed.trim() != payload.pk => {
            Err("certificate key differs from the key RDS lists for this device".to_owned())
        }
        None if info.directory_fresh => Err("not an approved device in RDS".to_owned()),
        _ => Ok(payload),
    }
}

/// Service side: remember the auth-relevant parts of the latest directory download.
pub fn update_directory(
    mode: &str,
    relay_fallback_delay_ms: u64,
    webrtc: bool,
    keys: HashMap<String, String>,
) {
    let mode = match mode {
        MODE_OFF | MODE_LOG | MODE_ENFORCE => mode.to_owned(),
        _ => MODE_LOG.to_owned(),
    };
    if let Ok(mut current) = DIRECTORY.lock() {
        *current = Some(DirectoryAuth {
            mode,
            relay_fallback_delay_ms,
            webrtc,
            keys,
            updated: Instant::now(),
        });
    }
}

/// Service side: answer a `--server` (or GUI) query about one controller id.
pub fn directory_info(controller_id: &str) -> PeerAuthInfo {
    let Ok(current) = DIRECTORY.lock() else {
        return PeerAuthInfo::default();
    };
    match current.as_ref() {
        Some(d) => PeerAuthInfo {
            mode: d.mode.clone(),
            peer_key: d.keys.get(controller_id).cloned(),
            directory_fresh: d.updated.elapsed() < DIRECTORY_FRESH_FOR,
            relay_fallback_delay_ms: d.relay_fallback_delay_ms,
            webrtc: d.webrtc,
        },
        None => PeerAuthInfo::default(),
    }
}
