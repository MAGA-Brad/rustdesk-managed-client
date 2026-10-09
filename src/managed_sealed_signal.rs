//! Managed builds (sec5 C6): WebRTC signaling sealed end to end between the two devices. hbbs
//! routes the offer, the answer and every ICE candidate, but sees only its routing fields.
//!
//! - The controller makes a fresh 32-byte key K per attempt and seals it to the target's device
//!   key (its RDS-listed Ed25519 key, converted to X25519), so only the target can read it.
//! - The controller's device key signs the offer, and the target checks that signature against
//!   its own RDS directory copy, so a compromised hbbs can neither read nor inject offers.
//! - K encrypts the offer, the answer and every candidate, with a direction byte inside so a
//!   captured candidate can't be reflected back to its sender.
//!
//! Offer: `sealed1:` b64url(sealedbox(K)) `.` controller id `.` b64url(nonce | secretbox_K(dir | offer)) `.` b64url(sig)
//! Answer and candidates: `sealed1:` b64url(nonce | secretbox_K(dir | payload))
use hbb_common::{
    anyhow::anyhow,
    base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _},
    bail, log,
    sodiumoxide::crypto::secretbox,
    ResultType,
};
#[cfg(any(windows, target_os = "android"))]
use hbb_common::{
    config::Config,
    sodiumoxide::crypto::{sealedbox, sign},
};

const PREFIX: &str = "sealed1:";
#[cfg(any(windows, target_os = "android"))]
const SIGN_DOMAIN: &[u8] = b"rdc-sealed-signal-v1\0";
pub const TO_TARGET: u8 = 1;
pub const TO_CONTROLLER: u8 = 2;

/// The per-attempt signaling key K.
#[derive(Clone)]
pub struct SignalKey(secretbox::Key);

fn enabled() -> bool {
    (cfg!(windows) || cfg!(target_os = "android"))
        && option_env!("RUSTDESK_MANAGED_DIRECTORY_BASE").is_some()
}

fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode(s: &str) -> ResultType<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| anyhow!("sealed signal is not valid base64url"))
}

fn seal_body(key: &secretbox::Key, dir: u8, payload: &str) -> Vec<u8> {
    let nonce = secretbox::gen_nonce();
    let mut plain = Vec::with_capacity(1 + payload.len());
    plain.push(dir);
    plain.extend_from_slice(payload.as_bytes());
    let mut body = nonce.0.to_vec();
    body.extend(secretbox::seal(&plain, &nonce, key));
    body
}

fn open_body(key: &secretbox::Key, dir: u8, body: &[u8]) -> ResultType<String> {
    if body.len() < secretbox::NONCEBYTES {
        bail!("sealed signal is too short");
    }
    let (nonce, ciphertext) = body.split_at(secretbox::NONCEBYTES);
    let nonce = secretbox::Nonce::from_slice(nonce).ok_or_else(|| anyhow!("bad nonce"))?;
    let plain = secretbox::open(ciphertext, &nonce, key)
        .map_err(|_| anyhow!("sealed signal does not open with this session's key"))?;
    match plain.split_first() {
        Some((d, payload)) if *d == dir => Ok(String::from_utf8(payload.to_vec())?),
        _ => bail!("sealed signal is addressed the other way"),
    }
}

impl SignalKey {
    fn seal(&self, dir: u8, payload: &str) -> String {
        format!("{PREFIX}{}", encode(&seal_body(&self.0, dir, payload)))
    }

    fn open(&self, dir: u8, sealed: &str) -> ResultType<String> {
        let body = sealed
            .strip_prefix(PREFIX)
            .ok_or_else(|| anyhow!("unsealed signal on a sealed session"))?;
        open_body(&self.0, dir, &decode(body)?)
    }
}

/// An outgoing answer or candidate: sealed when this session has a key, unchanged otherwise.
pub fn seal_outgoing(key: &Option<SignalKey>, dir: u8, payload: String) -> String {
    match key {
        Some(key) if !payload.is_empty() => key.seal(dir, &payload),
        _ => payload,
    }
}

/// An incoming answer or candidate: opened when this session has a key, unchanged otherwise.
/// Anything that doesn't open becomes empty, which every caller already treats as "none".
pub fn open_incoming(key: &Option<SignalKey>, dir: u8, sealed: String) -> String {
    match key {
        Some(key) if !sealed.is_empty() => key.open(dir, &sealed).unwrap_or_else(|err| {
            log::warn!("dropped a WebRTC signal: {}", err);
            String::new()
        }),
        _ => sealed,
    }
}

#[cfg(any(windows, target_os = "android"))]
fn signed_message(target_id: &str, controller_id: &str, sealed_key: &[u8], body: &[u8]) -> Vec<u8> {
    let mut msg = SIGN_DOMAIN.to_vec();
    for part in [target_id, controller_id] {
        msg.extend_from_slice(part.as_bytes());
        msg.push(0);
    }
    msg.extend_from_slice(&(sealed_key.len() as u32).to_le_bytes());
    msg.extend_from_slice(sealed_key);
    msg.extend_from_slice(body);
    msg
}

#[cfg(any(windows, target_os = "android"))]
fn listed_key(listed: &str) -> ResultType<sign::PublicKey> {
    crate::decode64(listed.trim())
        .ok()
        .and_then(|raw| sign::PublicKey::from_slice(&raw))
        .ok_or_else(|| anyhow!("malformed device key in the RDS directory"))
}

/// Controller (GUI process): the offer as it goes out, plus the key for the rest of the session.
/// Managed builds never send an offer in the clear: if it can't be sealed it isn't sent, and the
/// connection proceeds without WebRTC.
pub async fn seal_outgoing_offer(target_id: &str, offer: String) -> (String, Option<SignalKey>) {
    if !enabled() || offer.is_empty() {
        return (offer, None);
    }
    #[cfg(any(windows, target_os = "android"))]
    match seal_offer(target_id, &offer).await {
        Ok((sealed, key)) => return (sealed, Some(key)),
        Err(err) => log::warn!("WebRTC offer to {} not sent, it cannot be sealed: {}", target_id, err),
    }
    let _ = target_id;
    (String::new(), None)
}

#[cfg(any(windows, target_os = "android"))]
async fn seal_offer(target_id: &str, offer: &str) -> ResultType<(String, SignalKey)> {
    // Android (controller only) runs the directory worker and holds the device key in this process.
    #[cfg(windows)]
    let peer_key = crate::ipc::query_managed_peer_auth(target_id.to_owned()).await?.peer_key;
    #[cfg(target_os = "android")]
    let peer_key = crate::managed_peer_auth::directory_info(target_id).peer_key;
    let Some(listed) = peer_key else {
        bail!("{} is not an approved device in RDS", target_id);
    };
    let target_pk = sign::to_curve25519_pk(&listed_key(&listed)?)
        .map_err(|_| anyhow!("the target's device key can't take a sealed key"))?;
    let key = secretbox::gen_key();
    let sealed_key = sealedbox::seal(&key.0, &target_pk);
    let body = seal_body(&key, TO_TARGET, offer);
    #[cfg(windows)]
    let signed = crate::ipc::request_managed_signal_signature(
        target_id.to_owned(),
        sealed_key.clone(),
        body.clone(),
    )
    .await?;
    #[cfg(target_os = "android")]
    let signed = sign_offer(target_id, &sealed_key, &body);
    let Some((controller_id, sig)) = signed else {
        bail!("this device could not sign the offer");
    };
    if controller_id.is_empty() || controller_id.contains('.') {
        bail!("unusable device id for a sealed offer");
    }
    Ok((
        format!(
            "{PREFIX}{}.{}.{}.{}",
            encode(&sealed_key),
            controller_id,
            encode(&body),
            encode(&sig)
        ),
        SignalKey(key),
    ))
}

/// `--server` (holds the device key): signs a sealed offer as this device. Domain-separated, and
/// the signer is always this device's own id, so it can't stand in for any other signature.
#[cfg(any(windows, target_os = "android"))]
pub fn sign_offer(target_id: &str, sealed_key: &[u8], body: &[u8]) -> Option<(String, Vec<u8>)> {
    let controller_id = Config::get_id();
    let sk = sign::SecretKey::from_slice(&Config::get_key_pair().0)?;
    let sig = sign::sign_detached(
        &signed_message(target_id, &controller_id, sealed_key, body),
        &sk,
    );
    Some((controller_id, sig.to_bytes().to_vec()))
}

/// Target (`--server`): replaces a sealed offer with the offer itself and returns the session's
/// key. Managed builds answer only sealed offers from RDS-approved devices; any other offer is
/// dropped (emptied), which makes this an ordinary punch without WebRTC.
pub async fn open_incoming_offer(offer: &mut String) -> Option<SignalKey> {
    if !enabled() || offer.is_empty() {
        return None;
    }
    #[cfg(windows)]
    match open_offer(offer).await {
        Ok((plain, key)) => {
            *offer = plain;
            return Some(key);
        }
        Err(err) => log::warn!("declined a WebRTC offer: {}", err),
    }
    offer.clear();
    None
}

#[cfg(windows)]
async fn open_offer(envelope: &str) -> ResultType<(String, SignalKey)> {
    let rest = envelope
        .strip_prefix(PREFIX)
        .ok_or_else(|| anyhow!("unsealed offer"))?;
    let parts: Vec<&str> = rest.split('.').collect();
    let [sealed_key, controller_id, body, sig] = parts[..] else {
        bail!("malformed sealed offer");
    };
    let (sealed_key, body) = (decode(sealed_key)?, decode(body)?);
    let sig = sign::Signature::from_bytes(&decode(sig)?)
        .map_err(|_| anyhow!("malformed sealed offer signature"))?;
    let info = crate::ipc::query_managed_peer_auth(controller_id.to_owned()).await?;
    let Some(listed) = info.peer_key else {
        bail!("offer from {}, which is not an approved device in RDS", controller_id);
    };
    let my_id = Config::get_id();
    if !sign::verify_detached(
        &sig,
        &signed_message(&my_id, controller_id, &sealed_key, &body),
        &listed_key(&listed)?,
    ) {
        bail!("offer signature does not match the key RDS lists for {}", controller_id);
    }
    let (sk, pk) = Config::get_key_pair();
    let my_sk = sign::SecretKey::from_slice(&sk)
        .and_then(|sk| sign::to_curve25519_sk(&sk).ok())
        .ok_or_else(|| anyhow!("this device's key can't open a sealed key"))?;
    let my_pk = sign::PublicKey::from_slice(&pk)
        .and_then(|pk| sign::to_curve25519_pk(&pk).ok())
        .ok_or_else(|| anyhow!("this device's key can't open a sealed key"))?;
    let raw = sealedbox::open(&sealed_key, &my_pk, &my_sk)
        .map_err(|_| anyhow!("offer is sealed to another device"))?;
    let key = secretbox::Key::from_slice(&raw).ok_or_else(|| anyhow!("malformed sealed key"))?;
    let offer = open_body(&key, TO_TARGET, &body)?;
    Ok((offer, SignalKey(key)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads_open_only_with_the_key_and_direction_they_were_sealed_for() {
        let key = Some(SignalKey(secretbox::gen_key()));
        let other = Some(SignalKey(secretbox::gen_key()));
        let sealed = seal_outgoing(&key, TO_CONTROLLER, "candidate:1 1 udp".to_owned());
        assert!(sealed.starts_with(PREFIX));
        assert_eq!(open_incoming(&key, TO_CONTROLLER, sealed.clone()), "candidate:1 1 udp");
        assert_eq!(open_incoming(&key, TO_TARGET, sealed.clone()), "");
        assert_eq!(open_incoming(&other, TO_CONTROLLER, sealed), "");
        assert_eq!(open_incoming(&key, TO_CONTROLLER, "plain".to_owned()), "");
        assert_eq!(seal_outgoing(&key, TO_TARGET, String::new()), "");
        assert_eq!(seal_outgoing(&None, TO_TARGET, "plain".to_owned()), "plain");
    }

    #[cfg(windows)]
    #[test]
    fn offer_round_trip_with_device_keys() {
        let (target_pk, target_sk) = sign::gen_keypair();
        let (controller_pk, controller_sk) = sign::gen_keypair();
        let key = secretbox::gen_key();
        let sealed_key = sealedbox::seal(&key.0, &sign::to_curve25519_pk(&target_pk).unwrap());
        let body = seal_body(&key, TO_TARGET, "offer");
        let msg = signed_message("target", "controller", &sealed_key, &body);
        let sig = sign::sign_detached(&msg, &controller_sk);
        assert!(sign::verify_detached(&sig, &msg, &controller_pk));
        assert!(!sign::verify_detached(
            &sig,
            &signed_message("someone-else", "controller", &sealed_key, &body),
            &controller_pk
        ));
        let raw = sealedbox::open(
            &sealed_key,
            &sign::to_curve25519_pk(&target_pk).unwrap(),
            &sign::to_curve25519_sk(&target_sk).unwrap(),
        )
        .unwrap();
        let opened = secretbox::Key::from_slice(&raw).unwrap();
        assert_eq!(open_body(&opened, TO_TARGET, &body).unwrap(), "offer");
    }
}
