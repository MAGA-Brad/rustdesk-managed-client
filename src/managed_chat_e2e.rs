//! Managed builds (sec8 Phase E): chat messages sealed end to end between the two devices, so RDS
//! stores and forwards only ciphertext. Same keys and construction as sealed WebRTC signaling
//! (managed_sealed_signal.rs):
//!
//! - The sender makes a fresh 32-byte key K per message and seals it to the recipient's RDS-listed
//!   device key (Ed25519, converted to X25519), so only the recipient can read it.
//! - The sender's device key signs the message, bound to the conversation and both ids; the
//!   recipient checks that signature against its own RDS directory copy and only accepts the
//!   conversation's other device as the signer.
//!
//! `rdce1:` b64url(sealedbox(K)) `.` sender id `.` b64url(nonce | secretbox_K(payload)) `.` b64url(sig)
//!
//! Every message is sealed; one RDS doesn't list the recipient's key for is not sent, and a
//! received body that isn't sealed is refused. The sealed payload carries a random id and the time
//! it was sealed (build 43+), so a message replayed under a new RDS id is refused too. Runs in
//! `--server`, which holds the key.
use crate::hbbs_http::{
    directory_enrollment::current_device_id,
    managed_chat::{list_conversations, ChatMessage},
};
use hbb_common::{
    anyhow::{anyhow, Error},
    base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _},
    bail,
    config::Config,
    log,
    sodiumoxide::{
        crypto::{sealedbox, secretbox, sign},
        randombytes::randombytes,
    },
    ResultType,
};
use serde::{Deserialize, Serialize};

const PREFIX: &str = "rdce1:";
const SIGN_DOMAIN: &[u8] = b"rdc-chat-e2e-v1\0";
const UNREADABLE: &str = "[This message could not be decrypted]";
/// How long after a message was sent a signer or key RDS doesn't list may still be the directory
/// lagging behind the sender (newly approved or re-keyed): managed_peer_auth's 10-minute freshness
/// window plus clock skew.
const IDENTITY_GRACE_SECS: i64 = 15 * 60;
/// How far the time a message was sealed may be from when RDS says it received it: the sender's
/// and RDS's clocks, plus the send itself.
const SEALED_AT_SKEW_SECS: i64 = 60 * 60;
/// RDS deletes an undelivered message after 30 days, so an older seal can only be a replay. The
/// store remembers sealed ids a day longer than this (managed_chat_store::note_sealed_id).
const SEALED_MAX_AGE_SECS: i64 = 40 * 24 * 3600;

#[derive(Serialize, Deserialize)]
struct Payload {
    t: String,
    /// A random id per message and the Unix time it was sealed at (build 43+), against replays.
    /// Messages from earlier builds have neither and are deduplicated by RDS message id only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    i: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    s: Option<i64>,
}

/// Why a sealed message did not open.
enum OpenFailure {
    /// Malformed, or not sealed for this device: it never opens.
    Broken(Error),
    /// Doesn't match what RDS lists (the conversation's other device, its key). Final only against
    /// a fresh directory that postdates the message.
    Identity { fresh: bool, error: Error },
    /// A lookup failed (the service has no directory yet or doesn't answer, the network, the
    /// store): try again later.
    Unavailable(Error),
}

impl std::fmt::Display for OpenFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenFailure::Broken(error)
            | OpenFailure::Identity { error, .. }
            | OpenFailure::Unavailable(error) => write!(f, "{}", error),
        }
    }
}

fn age_secs(sent_at: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(sent_at)
        .ok()
        .map(|sent| chrono::Utc::now().signed_duration_since(sent).num_seconds())
}

fn failed_state(failure: &OpenFailure, sent_at: &str) -> i64 {
    use crate::managed_chat_store::{OPEN_STATE_PENDING, OPEN_STATE_UNREADABLE};
    let permanent = match failure {
        OpenFailure::Broken(_) => true,
        OpenFailure::Identity { fresh, .. } => {
            *fresh && age_secs(sent_at).map_or(true, |age| age > IDENTITY_GRACE_SECS)
        }
        OpenFailure::Unavailable(_) => false,
    };
    if permanent {
        OPEN_STATE_UNREADABLE
    } else {
        OPEN_STATE_PENDING
    }
}

fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode(s: &str) -> ResultType<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| anyhow!("sealed chat message is not valid base64url"))
}

fn signed_message(
    conversation_id: &str,
    recipient_id: &str,
    sender_id: &str,
    sealed_key: &[u8],
    body: &[u8],
) -> Vec<u8> {
    let mut msg = SIGN_DOMAIN.to_vec();
    for part in [conversation_id, recipient_id, sender_id] {
        msg.extend_from_slice(part.as_bytes());
        msg.push(0);
    }
    msg.extend_from_slice(&(sealed_key.len() as u32).to_le_bytes());
    msg.extend_from_slice(sealed_key);
    msg.extend_from_slice(body);
    msg
}

fn listed_key(listed: &str) -> ResultType<sign::PublicKey> {
    crate::decode64(listed.trim())
        .ok()
        .and_then(|raw| sign::PublicKey::from_slice(&raw))
        .ok_or_else(|| anyhow!("malformed device key in the RDS directory"))
}

/// The RustDesk id of the conversation's other device: from the local store, else from RDS.
async fn other_device(conversation_id: &str) -> ResultType<String> {
    let self_device = current_device_id()?;
    let pick = |participants: Vec<crate::hbbs_http::managed_chat::ChatParticipant>| {
        participants
            .into_iter()
            .find(|p| p.device_id != self_device && !p.rustdesk_id.is_empty())
            .map(|p| p.rustdesk_id)
    };
    if let Some(id) = crate::managed_chat_store::conversation_participants(conversation_id)?
        .and_then(|participants| pick(participants))
    {
        return Ok(id);
    }
    let conversation = list_conversations()
        .await?
        .into_iter()
        .find(|c| c.id == conversation_id)
        .ok_or_else(|| anyhow!("conversation {} not found in RDS", conversation_id))?;
    crate::managed_chat_store::upsert_conversation(&conversation).ok();
    pick(conversation.participants)
        .ok_or_else(|| anyhow!("conversation {} has no other device", conversation_id))
}

/// The body as it goes to RDS, always sealed: a recipient RDS doesn't list a key for yet gets
/// nothing rather than the plain text.
pub async fn seal_outgoing(conversation_id: &str, text: &str) -> ResultType<String> {
    let recipient = other_device(conversation_id).await?;
    let info = crate::ipc::query_managed_peer_auth(recipient.clone()).await?;
    let Some(listed) = info.peer_key else {
        bail!("The directory doesn't list the recipient yet - try again in a moment");
    };
    let recipient_pk = sign::to_curve25519_pk(&listed_key(&listed)?)
        .map_err(|_| anyhow!("the recipient's device key can't take a sealed key"))?;
    let sender = Config::get_id();
    if sender.is_empty() || sender.contains('.') {
        bail!("unusable device id for a sealed chat message");
    }
    let sk = sign::SecretKey::from_slice(&Config::get_key_pair().0)
        .ok_or_else(|| anyhow!("this device's key can't sign"))?;
    let key = secretbox::gen_key();
    let sealed_key = sealedbox::seal(&key.0, &recipient_pk);
    let nonce = secretbox::gen_nonce();
    let mut body = nonce.0.to_vec();
    let payload = Payload {
        t: text.to_owned(),
        i: Some(encode(&randombytes(16))),
        s: Some(chrono::Utc::now().timestamp()),
    };
    body.extend(secretbox::seal(&serde_json::to_vec(&payload)?, &nonce, &key));
    let sig = sign::sign_detached(
        &signed_message(conversation_id, &recipient, &sender, &sealed_key, &body),
        &sk,
    );
    Ok(format!(
        "{PREFIX}{}.{}.{}.{}",
        encode(&sealed_key),
        sender,
        encode(&body),
        encode(&sig.to_bytes())
    ))
}

/// Replaces a sealed message's body with its text. One that can't be opened, or isn't sealed (every
/// sender seals, so only a tampered RDS database holds one), is shown as unreadable, never as its
/// ciphertext or as unverified text.
pub async fn open_incoming(conversation_id: &str, message: &mut ChatMessage) {
    if !message.body.starts_with(PREFIX) {
        log::warn!("managed chat: message {} is not sealed; refused", message.id);
        message.body = UNREADABLE.to_owned();
        return;
    }
    match open(conversation_id, &message.id, &message.sent_at, &message.body, false).await {
        Ok(text) => message.body = text,
        Err(err) => {
            log::warn!("managed chat: message {} could not be decrypted: {}", message.id, err);
            message.body = UNREADABLE.to_owned();
        }
    }
}

/// open_incoming for a pushed message that is about to be stored: one that can't be opened yet
/// keeps its envelope (returned, with an empty body) instead of becoming a placeholder, since many
/// failures pass - no directory in the service yet after a restart, a sender approved or re-keyed
/// since the last download, the service or network not answering - and RDS no longer has a copy.
/// Returns the store's open state and the envelope to keep. A body that isn't sealed is stored
/// empty and unreadable.
pub async fn open_for_store(conversation_id: &str, message: &mut ChatMessage) -> (i64, Option<String>) {
    if !message.body.starts_with(PREFIX) {
        log::warn!("managed chat: message {} is not sealed; refused", message.id);
        message.body.clear();
        return (crate::managed_chat_store::OPEN_STATE_UNREADABLE, None);
    }
    match open(conversation_id, &message.id, &message.sent_at, &message.body, false).await {
        Ok(text) => {
            message.body = text;
            (crate::managed_chat_store::OPEN_STATE_OPENED, None)
        }
        Err(err) => {
            let state = failed_state(&err, &message.sent_at);
            log::warn!(
                "managed chat: message {} could not be decrypted (state {}): {}",
                message.id,
                state,
                err
            );
            (state, Some(std::mem::take(&mut message.body)))
        }
    }
}

/// Tries every stored message open_for_store kept sealed again. Returns the conversations whose
/// messages changed. Never calls RDS: the service's directory and the stored participants only.
pub async fn retry_pending() -> Vec<String> {
    let pending = match crate::managed_chat_store::pending_opens() {
        Ok(pending) => pending,
        Err(err) => {
            log::warn!("managed chat: could not list messages waiting to be decrypted: {}", err);
            return Vec::new();
        }
    };
    let mut changed: Vec<String> = Vec::new();
    for message in pending {
        let stored = match open(
            &message.conversation_id,
            &message.id,
            &message.sent_at,
            &message.raw_body,
            true,
        )
        .await
        {
            Ok(text) => crate::managed_chat_store::mark_opened(&message.id, &text),
            Err(err)
                if failed_state(&err, &message.sent_at)
                    == crate::managed_chat_store::OPEN_STATE_UNREADABLE =>
            {
                log::warn!("managed chat: message {} can't be decrypted: {}", message.id, err);
                crate::managed_chat_store::mark_unreadable(&message.id)
            }
            Err(err) => {
                log::debug!("managed chat: message {} still can't be decrypted: {}", message.id, err);
                continue;
            }
        };
        match stored {
            Ok(()) => {
                if !changed.contains(&message.conversation_id) {
                    changed.push(message.conversation_id);
                }
            }
            Err(err) => log::error!("managed chat: could not update message {}: {}", message.id, err),
        }
    }
    changed
}

/// other_device from the local store only.
fn stored_other_device(conversation_id: &str) -> ResultType<String> {
    let self_device = current_device_id()?;
    crate::managed_chat_store::conversation_participants(conversation_id)?
        .and_then(|participants| {
            participants
                .into_iter()
                .find(|p| p.device_id != self_device && !p.rustdesk_id.is_empty())
                .map(|p| p.rustdesk_id)
        })
        .ok_or_else(|| anyhow!("conversation {} is not stored with its other device", conversation_id))
}

/// Refuses a sealed time that makes the message a replay: far from when RDS received it, or older
/// than anything RDS still delivers.
fn check_sealed_at(sealed_at: i64, sent_at: &str, now: i64) -> ResultType<()> {
    let received = chrono::DateTime::parse_from_rfc3339(sent_at)
        .map_err(|_| anyhow!("unreadable receive time {:?}", sent_at))?
        .timestamp();
    if (received - sealed_at).abs() > SEALED_AT_SKEW_SECS {
        bail!("sealed {} s away from when RDS received it", received - sealed_at);
    }
    if now - sealed_at > SEALED_MAX_AGE_SECS {
        bail!("sealed too long ago to be anything but a replay");
    }
    Ok(())
}

async fn open(
    conversation_id: &str,
    message_id: &str,
    sent_at: &str,
    envelope: &str,
    stored_only: bool,
) -> Result<String, OpenFailure> {
    use OpenFailure::{Broken, Identity, Unavailable};
    let rest = envelope
        .strip_prefix(PREFIX)
        .ok_or_else(|| Broken(anyhow!("unsealed message")))?;
    let parts: Vec<&str> = rest.split('.').collect();
    let [sealed_key, sender, body, sig] = parts[..] else {
        return Err(Broken(anyhow!("malformed sealed chat message")));
    };
    let expected = if stored_only {
        stored_other_device(conversation_id)
    } else {
        other_device(conversation_id).await
    }
    .map_err(Unavailable)?;
    if sender != expected {
        return Err(Identity {
            fresh: true,
            error: anyhow!("signed by {}, not this conversation's other device", sender),
        });
    }
    let (sealed_key, body) = (decode(sealed_key).map_err(Broken)?, decode(body).map_err(Broken)?);
    let sig = sign::Signature::from_bytes(&decode(sig).map_err(Broken)?)
        .map_err(|_| Broken(anyhow!("malformed sealed chat signature")))?;
    let info = crate::ipc::query_managed_peer_auth(sender.to_owned())
        .await
        .map_err(Unavailable)?;
    let fresh = info.directory_fresh;
    let Some(listed) = info.peer_key else {
        return Err(Identity {
            fresh,
            error: anyhow!("{} is not an approved device in RDS", sender),
        });
    };
    let listed = listed_key(&listed).map_err(|error| Identity { fresh, error })?;
    let my_id = Config::get_id();
    if !sign::verify_detached(
        &sig,
        &signed_message(conversation_id, &my_id, sender, &sealed_key, &body),
        &listed,
    ) {
        return Err(Identity {
            fresh,
            error: anyhow!("signature does not match the key RDS lists for {}", sender),
        });
    }
    let (sk, pk) = Config::get_key_pair();
    let my_sk = sign::SecretKey::from_slice(&sk)
        .and_then(|sk| sign::to_curve25519_sk(&sk).ok())
        .ok_or_else(|| Unavailable(anyhow!("this device's key can't open a sealed key")))?;
    let my_pk = sign::PublicKey::from_slice(&pk)
        .and_then(|pk| sign::to_curve25519_pk(&pk).ok())
        .ok_or_else(|| Unavailable(anyhow!("this device's key can't open a sealed key")))?;
    let raw = sealedbox::open(&sealed_key, &my_pk, &my_sk)
        .map_err(|_| Broken(anyhow!("sealed to another device")))?;
    let key = secretbox::Key::from_slice(&raw).ok_or_else(|| Broken(anyhow!("malformed sealed key")))?;
    if body.len() < secretbox::NONCEBYTES {
        return Err(Broken(anyhow!("sealed chat message is too short")));
    }
    let (nonce, ciphertext) = body.split_at(secretbox::NONCEBYTES);
    let nonce = secretbox::Nonce::from_slice(nonce).ok_or_else(|| Broken(anyhow!("bad nonce")))?;
    let plain = secretbox::open(ciphertext, &nonce, &key)
        .map_err(|_| Broken(anyhow!("does not open with its sealed key")))?;
    let payload = serde_json::from_slice::<Payload>(&plain).map_err(|err| Broken(err.into()))?;
    let now = chrono::Utc::now().timestamp();
    if let Some(sealed_at) = payload.s {
        check_sealed_at(sealed_at, sent_at, now).map_err(Broken)?;
    }
    if let Some(sealed_id) = &payload.i {
        let first = crate::managed_chat_store::note_sealed_id(
            conversation_id,
            sealed_id,
            message_id,
            now - SEALED_MAX_AGE_SECS - 24 * 3600,
        )
        .map_err(Unavailable)?;
        if !first {
            return Err(Broken(anyhow!("replays an earlier message of this conversation")));
        }
    }
    Ok(payload.t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_binds_conversation_and_both_ids() {
        let a = signed_message("c1", "r", "s", b"k", b"b");
        assert_ne!(a, signed_message("c2", "r", "s", b"k", b"b"));
        assert_ne!(a, signed_message("c1", "s", "r", b"k", b"b"));
        assert!(a.starts_with(SIGN_DOMAIN));
    }

    #[derive(Serialize, Deserialize)]
    struct Build42Payload {
        t: String,
    }

    #[test]
    fn payload_stays_compatible_with_build_42() {
        let old: Payload = serde_json::from_slice(br#"{"t":"hi"}"#).unwrap();
        assert_eq!((old.t.as_str(), old.i, old.s), ("hi", None, None));
        let new = serde_json::to_vec(&Payload {
            t: "hi".to_owned(),
            i: Some("abc".to_owned()),
            s: Some(1),
        })
        .unwrap();
        assert_eq!(serde_json::from_slice::<Build42Payload>(&new).unwrap().t, "hi");
    }

    #[test]
    fn sealed_time_must_match_receipt_and_be_recent() {
        let sent_at = "2026-10-18T12:00:00.123456+00:00";
        let received = chrono::DateTime::parse_from_rfc3339(sent_at).unwrap().timestamp();
        assert!(check_sealed_at(received - 5, sent_at, received + 60).is_ok());
        assert!(check_sealed_at(received - SEALED_AT_SKEW_SECS - 1, sent_at, received).is_err());
        assert!(check_sealed_at(received + SEALED_AT_SKEW_SECS + 1, sent_at, received).is_err());
        assert!(check_sealed_at(received, sent_at, received + SEALED_MAX_AGE_SECS + 1).is_err());
        assert!(check_sealed_at(received, "not a time", received).is_err());
    }
}
