//! Managed builds (sec8 Phase E): every call to RDS carries a one-time proof, signed with this
//! device's identity key, that this device made this call (`X-RDC-Proof`). RDS checks it against
//! the identity key it has on file; its Config page decides whether a call without one is still
//! served. Format and the RDS check: RDS `app/main.py` (`check_device_proof`).
//!
//! `X-RDC-Proof: v1.<unix seconds>.<b64url nonce>.<b64url signature>` over
//! `rdc-proof-v1\0 | METHOD \0 | path[?query] \0 | seconds \0 | nonce`
//!
//! The body is not signed: the proof is single-use and only ever travels inside TLS or the sealed
//! envelope, which already protect the body, and a large upload is never buffered to hash it.
use hbb_common::{
    base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _},
    sodiumoxide::randombytes,
};

pub const HEADER: &str = "x-rdc-proof";
pub const DOMAIN: &[u8] = b"rdc-proof-v1\0";
const NONCE_LEN: usize = 16;

pub fn signed_message(method: &str, target: &str, seconds: i64, nonce: &[u8]) -> Vec<u8> {
    let mut msg = DOMAIN.to_vec();
    msg.extend_from_slice(method.to_ascii_uppercase().as_bytes());
    msg.push(0);
    msg.extend_from_slice(target.as_bytes());
    msg.push(0);
    msg.extend_from_slice(seconds.to_string().as_bytes());
    msg.push(0);
    msg.extend_from_slice(nonce);
    msg
}

/// The path and query exactly as they go on the wire (both already percent-encoded by `Url`).
fn target_of(url: &reqwest::Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{}", url.path(), query),
        None => url.path().to_owned(),
    }
}

/// Adds the proof to a request bound for RDS. Best effort: without an identity key (or with
/// `--server` unreachable) the call goes without one and RDS's mode decides.
pub async fn sign_request(request: &mut reqwest::Request) {
    if option_env!("RUSTDESK_MANAGED_DIRECTORY_BASE").is_none() {
        return;
    }
    let Some(value) = header_value(request.method().as_str(), &target_of(request.url())).await else {
        return;
    };
    if let Ok(value) = reqwest::header::HeaderValue::from_str(&value) {
        request.headers_mut().insert(HEADER, value);
    }
}

/// The header value for one call, e.g. the chat WebSocket's upgrade request.
pub async fn header_value(method: &str, target: &str) -> Option<String> {
    let seconds = hbb_common::get_time() / 1000;
    let nonce = randombytes::randombytes(NONCE_LEN);
    let signature = sign(method, target, seconds, &nonce).await?;
    Some(format!(
        "v1.{seconds}.{}.{}",
        URL_SAFE_NO_PAD.encode(&nonce),
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

async fn sign(method: &str, target: &str, seconds: i64, nonce: &[u8]) -> Option<Vec<u8>> {
    if let Some(signature) =
        crate::managed_passport::sign_request_proof(&signed_message(method, target, seconds, nonce))
    {
        return Some(signature);
    }
    // Only SYSTEM processes can read the identity key; the GUI and RustDrop ask `--server`.
    #[cfg(windows)]
    if !crate::platform::is_root() {
        return crate::ipc::request_managed_proof(
            method.to_owned(),
            target.to_owned(),
            seconds,
            nonce.to_vec(),
        )
        .await
        .unwrap_or_else(|err| {
            hbb_common::log::debug!("sec8: no RDS call proof from --server: {}", err);
            None
        });
    }
    None
}

/// `--server`: signs a proof for a process that can't read the identity key. The message is built
/// here, behind the proof domain, so nothing else can be signed this way.
#[cfg(windows)]
pub fn sign_for_ipc(method: &str, target: &str, seconds: i64, nonce: &[u8]) -> Option<Vec<u8>> {
    if nonce.len() != NONCE_LEN || target.contains('\0') || method.contains('\0') {
        return None;
    }
    crate::managed_passport::sign_request_proof(&signed_message(method, target, seconds, nonce))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_layout_matches_the_rds_check() {
        let msg = signed_message("get", "/v1/device/me?x=1", 1700000000, &[7u8; NONCE_LEN]);
        let mut expected = b"rdc-proof-v1\0GET\0/v1/device/me?x=1\01700000000\0".to_vec();
        expected.extend_from_slice(&[7u8; NONCE_LEN]);
        assert_eq!(msg, expected);
    }
}
