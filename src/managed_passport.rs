//! sec8 device passports: this device's own identity key, moving the CA VM from the RustDesk key to it,
//! and keeping a short-lived passport from the CA fresh. Whether hbbs requires it is RDS's passport check.
//!
//! Formats match the CA's `rdc-passport` crate: Ed25519 over a domain prefix plus the exact JSON body.
//! Passport `rdcp1.<ikc body>.<ikc sig>.<body>.<sig>` (the issuing-key certificate is signed by a CA root
//! built into this client), renewal `<body>.<sig>`, key update `<body>.<sig by old key>.<sig by new key>`.
use hbb_common::{
    anyhow::anyhow,
    base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _},
    config::Config,
    log,
    sodiumoxide::{crypto::sign, randombytes::randombytes},
    ResultType,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicU32, Ordering},
        Mutex,
    },
    time::{Duration, Instant, SystemTime},
};

const KEY_FILE: &str = "identity_key.dpapi";
const PASSPORT_FILE: &str = "passport.json";
const IKC_DOMAIN: &[u8] = b"rdcp1-ikc\0";
const PASSPORT_DOMAIN: &[u8] = b"rdcp1-passport\0";
const RENEW_DOMAIN: &[u8] = b"rdcp1-renew\0";
const KEYUPDATE_DOMAIN: &[u8] = b"rdcp1-keyupdate\0";
const DEVAUTH_DOMAIN: &[u8] = b"rdcp1-devauth\0";
/// hbbs's public key + both ephemeral keys of the key exchange + the picked version (u32 LE).
pub const DEVICE_AUTH_BINDING_LEN: usize = 32 + 32 + 32 + 4;
/// KxParams.managed_capabilities bit: hbbs takes a DeviceAuth on this connection.
pub const KX_CAP_DEVICE_AUTH: u32 = 1;
/// How the identity key is held, as reported to the CA.
#[cfg(windows)]
pub const PROTECTION: &str = "dpapi";
#[cfg(target_os = "android")]
pub const PROTECTION: &str = "keystore";

static NEXT_CHECK: Mutex<Option<Instant>> = Mutex::new(None);
static UNANSWERED: AtomicU32 = AtomicU32::new(0);
static IDENTITY: Mutex<Option<(SystemTime, sign::SecretKey)>> = Mutex::new(None);

#[derive(Deserialize)]
struct IkcBody {
    typ: String,
    kid: String,
    key: String,
}

#[derive(Deserialize, Clone, Debug)]
pub struct PassportBody {
    pub typ: String,
    pub serial: String,
    pub rid: String,
    pub did: String,
    pub idk: String,
    pub prot: String,
    pub iat: i64,
    pub exp: i64,
    pub ikid: String,
}

/// The passport the service keeps for this device (not secret: useless without the identity key).
#[derive(Serialize, Deserialize, Clone)]
pub struct StoredPassport {
    pub passport: String,
    pub serial: String,
    pub iat: i64,
    pub exp: i64,
    pub prot: String,
}

fn now_secs() -> i64 {
    hbb_common::get_time() / 1000
}

fn store_dir() -> ResultType<PathBuf> {
    let dir = crate::platform::get_program_data_dir()?.join("RustDeskManaged");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn signed(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut message = domain.to_vec();
    message.extend_from_slice(body);
    message
}

pub fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

/// SHA-256 of the raw public key, first 16 bytes, hex - the fingerprint the CA mails and RDS shows.
pub fn fingerprint(raw_public_key: &[u8]) -> String {
    Sha256::digest(raw_public_key)[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn nonce() -> String {
    randombytes(16).iter().map(|b| format!("{b:02x}")).collect()
}

/// CA root public keys built into this client (base64url, comma-separated).
fn roots() -> Vec<sign::PublicKey> {
    option_env!("RUSTDESK_MANAGED_PASSPORT_ROOTS")
        .unwrap_or_default()
        .split(',')
        .filter_map(|key| sign::PublicKey::from_slice(&B64.decode(key.trim()).ok()?))
        .collect()
}

/// This device's identity key: created on first use, kept DPAPI-protected (machine scope) in a file with
/// the machine-secret ACL, like the edge certificate key.
pub fn identity_key() -> ResultType<(sign::PublicKey, sign::SecretKey)> {
    let path = store_dir()?.join(KEY_FILE);
    if let Ok(protected) = std::fs::read(&path) {
        let mut raw = crate::platform::unprotect_machine_scope(&protected)?;
        let secret = sign::SecretKey::from_slice(&raw);
        raw.fill(0);
        let secret = secret.ok_or_else(|| anyhow!("stored identity key is malformed"))?;
        let public = sign::PublicKey::from_slice(&secret.0[32..])
            .ok_or_else(|| anyhow!("stored identity key is malformed"))?;
        return Ok((public, secret));
    }
    let (public, secret) = sign::gen_keypair();
    let protected = crate::platform::protect_machine_scope(&secret.0)?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, protected)?;
    crate::platform::set_path_permission_for_machine_secret(&tmp, false)?;
    std::fs::rename(&tmp, &path)?;
    log::info!("sec8: created this device's identity key {}", fingerprint(&public.0));
    Ok((public, secret))
}

/// Whether this device already has its identity key (without creating one).
pub fn has_identity_key() -> bool {
    store_dir().map_or(false, |dir| dir.join(KEY_FILE).exists())
}

/// A renewal request signed with the identity key.
pub fn renew_request(rid: &str, did: &str, public: &sign::PublicKey, secret: &sign::SecretKey) -> ResultType<String> {
    let body = serde_json::to_vec(&serde_json::json!({
        "typ": "rdc-renew", "v": 1, "rid": rid, "did": did,
        "idk": b64(&public.0), "ts": now_secs(), "nonce": nonce(),
    }))?;
    let sig = sign::sign_detached(&signed(RENEW_DOMAIN, &body), secret);
    Ok(format!("{}.{}", b64(&body), b64(&sig.to_bytes())))
}

/// Moves the CA to `new` (this device's identity key), signed by the key the CA has on file (`old`,
/// the RustDesk key for devices enrolled before build 33) and by the new key.
pub fn key_update_request(
    rid: &str,
    did: &str,
    old: (&[u8], &sign::SecretKey),
    new: (&sign::PublicKey, &sign::SecretKey),
) -> ResultType<String> {
    let body = serde_json::to_vec(&serde_json::json!({
        "typ": "rdc-keyupdate", "v": 1, "rid": rid, "did": did,
        "old_key": b64(old.0), "new_key": b64(&new.0 .0), "new_alg": "ed25519",
        "prot": PROTECTION, "ts": now_secs(), "nonce": nonce(),
    }))?;
    let message = signed(KEYUPDATE_DOMAIN, &body);
    let old_sig = sign::sign_detached(&message, old.1);
    let new_sig = sign::sign_detached(&message, new.1);
    Ok(format!("{}.{}.{}", b64(&body), b64(&old_sig.to_bytes()), b64(&new_sig.to_bytes())))
}

/// The RustDesk key pair, which is the identity on file at the CA until the first key update.
pub fn rustdesk_key() -> Option<(Vec<u8>, sign::SecretKey)> {
    let (secret, public) = Config::get_key_pair();
    Some((public, sign::SecretKey::from_slice(&secret)?))
}

fn part(text: &str) -> ResultType<Vec<u8>> {
    B64.decode(text).map_err(|_| anyhow!("passport is not valid base64url"))
}

fn signature(bytes: &[u8]) -> ResultType<sign::Signature> {
    sign::Signature::from_bytes(bytes).map_err(|_| anyhow!("malformed passport signature"))
}

/// Checks a passport against the CA roots built into this client. Expiry is left to the caller.
pub fn verify(token: &str) -> ResultType<PassportBody> {
    let roots = roots();
    if roots.is_empty() {
        return Err(anyhow!("no CA root is built into this client"));
    }
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 5 || parts[0] != "rdcp1" {
        return Err(anyhow!("malformed passport"));
    }
    let ikc_bytes = part(parts[1])?;
    let ikc_sig = signature(&part(parts[2])?)?;
    let ikc_message = signed(IKC_DOMAIN, &ikc_bytes);
    if !roots.iter().any(|root| sign::verify_detached(&ikc_sig, &ikc_message, root)) {
        return Err(anyhow!("passport's issuing key is not certified by a trusted CA root"));
    }
    let ikc: IkcBody = serde_json::from_slice(&ikc_bytes).map_err(|_| anyhow!("malformed issuing-key certificate"))?;
    let issuing = sign::PublicKey::from_slice(&part(&ikc.key)?).ok_or_else(|| anyhow!("malformed issuing key"))?;
    let body_bytes = part(parts[3])?;
    if ikc.typ != "rdc-ikc"
        || !sign::verify_detached(&signature(&part(parts[4])?)?, &signed(PASSPORT_DOMAIN, &body_bytes), &issuing)
    {
        return Err(anyhow!("passport signature does not verify"));
    }
    let body: PassportBody = serde_json::from_slice(&body_bytes).map_err(|_| anyhow!("malformed passport"))?;
    if body.typ != "rdc-passport" || body.ikid != ikc.kid {
        return Err(anyhow!("passport does not match its issuing key"));
    }
    Ok(body)
}

pub fn load() -> Option<StoredPassport> {
    serde_json::from_slice(&std::fs::read(store_dir().ok()?.join(PASSPORT_FILE)).ok()?).ok()
}

pub fn store(token: &str, body: &PassportBody) -> ResultType<()> {
    let path = store_dir()?.join(PASSPORT_FILE);
    let tmp = path.with_extension("json.tmp");
    let stored = StoredPassport {
        passport: token.to_owned(),
        serial: body.serial.clone(),
        iat: body.iat,
        exp: body.exp,
        prot: body.prot.clone(),
    };
    std::fs::write(&tmp, serde_json::to_vec(&stored)?)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Past half its life (renewal due).
pub fn renewal_due(body: &PassportBody) -> bool {
    now_secs() >= body.iat + (body.exp - body.iat) / 2
}

/// Whether the service should talk to RDS about the passport now.
pub fn due() -> bool {
    NEXT_CHECK
        .lock()
        .ok()
        .and_then(|next| *next)
        .map_or(true, |next| Instant::now() >= next)
}

/// The identity key if it already exists (never creates one: that is the service's job), kept in
/// memory while the file is unchanged, since every hbbs connection signs with it.
fn existing_identity_secret() -> Option<sign::SecretKey> {
    let path = store_dir().ok()?.join(KEY_FILE);
    let modified = std::fs::metadata(&path).and_then(|m| m.modified()).ok()?;
    let mut cache = IDENTITY.lock().ok()?;
    if let Some((at, secret)) = cache.as_ref() {
        if *at == modified {
            return Some(secret.clone());
        }
    }
    let mut raw = crate::platform::unprotect_machine_scope(&std::fs::read(&path).ok()?).ok()?;
    let secret = sign::SecretKey::from_slice(&raw);
    raw.fill(0);
    let secret = secret?;
    *cache = Some((modified, secret.clone()));
    Some(secret)
}

/// For `--server` (it can read the identity key): the stored passport and the identity key's
/// signature over one key-exchanged hbbs connection. Only exactly-sized bindings are signed, always
/// behind the device-auth domain, so nothing else can be signed this way. None until a passport is
/// stored.
pub fn sign_device_auth(binding: &[u8]) -> Option<(String, Vec<u8>)> {
    if binding.len() != DEVICE_AUTH_BINDING_LEN {
        return None;
    }
    let stored = load()?;
    let secret = existing_identity_secret()?;
    let sig = sign::sign_detached(&signed(DEVAUTH_DOMAIN, binding), &secret);
    Some((stored.passport, sig.to_bytes().to_vec()))
}

/// Proves this device on a freshly key-exchanged hbbs connection that asked for it (DeviceAuth).
/// Best effort: without a passport nothing is sent, and hbbs's mode decides what an unproven
/// connection may still do. GUI processes get the signature from `--server` over IPC.
pub async fn send_device_auth(
    conn: &mut hbb_common::Stream,
    server_pk: &[u8],
    initiator_pk: &[u8],
    responder_pk: &[u8],
    version: u32,
) {
    use hbb_common::rendezvous_proto::{DeviceAuth, RendezvousMessage};
    let mut binding = Vec::with_capacity(DEVICE_AUTH_BINDING_LEN);
    binding.extend_from_slice(server_pk);
    binding.extend_from_slice(initiator_pk);
    binding.extend_from_slice(responder_pk);
    binding.extend_from_slice(&version.to_le_bytes());
    // Android has only the app process, which holds the identity key itself.
    #[cfg(target_os = "android")]
    let signed = sign_device_auth(&binding);
    #[cfg(windows)]
    let signed = if crate::is_server() {
        sign_device_auth(&binding)
    } else {
        crate::ipc::request_device_auth(binding).await.unwrap_or_else(|err| {
            log::debug!("sec8: no DeviceAuth from --server: {}", err);
            None
        })
    };
    let Some((passport, signature)) = signed else {
        log::debug!("sec8: no passport to show hbbs yet");
        return;
    };
    let mut msg = RendezvousMessage::new();
    msg.set_device_auth(DeviceAuth {
        passport,
        signature: signature.into(),
        ..Default::default()
    });
    if let Err(err) = conn.send(&msg).await {
        log::warn!("sec8: DeviceAuth not sent: {}", err);
    }
}

/// Seconds to give the CA after sending a request: 90, doubling while requests go unanswered (a rejected
/// request closes without a new passport), up to an hour.
pub fn request_sent() -> u64 {
    (90u64 << UNANSWERED.fetch_add(1, Ordering::Relaxed).min(6)).min(3600)
}

pub fn request_answered() {
    UNANSWERED.store(0, Ordering::Relaxed);
}

pub fn check_again_in(seconds: u64) {
    if let Ok(mut next) = NEXT_CHECK.lock() {
        *next = Some(Instant::now() + Duration::from_secs(seconds));
    }
}
