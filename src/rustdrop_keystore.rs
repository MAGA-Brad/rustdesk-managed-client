// RustDrop's X25519 keypair custody. Now owned by RDC's own service process
// (this file runs in the same binary, whichever mode it's launched as) -
// no separate Electron userData directory, no IPC hand-off. Both the
// `--service` instance (background register/poll/notify) and a
// `--rustdrop` UI instance reach the exact same file via `Config::path`,
// the same mechanism that already makes this device's enrollment
// credential shared between them.

use crate::rustdrop_crypto::{generate_keypair, PRIVATE_KEY_BYTES, PUBLIC_KEY_BYTES};
use hbb_common::config::Config;
use std::sync::OnceLock;

const KEYPAIR_FILENAME: &str = "rustdrop_keypair.json";

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredKeypair {
    public_key: String,
    private_key: String,
}

pub struct Keypair {
    pub public_key: [u8; PUBLIC_KEY_BYTES],
    pub private_key: [u8; PRIVATE_KEY_BYTES],
    pub public_key_base64: String,
}

static KEYPAIR: OnceLock<Keypair> = OnceLock::new();

fn keypair_path() -> std::path::PathBuf {
    Config::path(KEYPAIR_FILENAME)
}

fn to_keypair(public_key: [u8; PUBLIC_KEY_BYTES], private_key: [u8; PRIVATE_KEY_BYTES]) -> Keypair {
    let public_key_base64 = base64_encode(&public_key);
    Keypair {
        public_key,
        private_key,
        public_key_base64,
    }
}

fn base64_encode(bytes: &[u8]) -> String {
    use hbb_common::base64::Engine;
    hbb_common::base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use hbb_common::base64::Engine;
    hbb_common::base64::engine::general_purpose::STANDARD
        .decode(s)
        .ok()
}

fn try_load() -> Option<Keypair> {
    let contents = std::fs::read_to_string(keypair_path()).ok()?;
    let stored: StoredKeypair = serde_json::from_str(&contents).ok()?;
    let pk = base64_decode(&stored.public_key)?;
    let sk = base64_decode(&stored.private_key)?;
    if pk.len() != PUBLIC_KEY_BYTES || sk.len() != PRIVATE_KEY_BYTES {
        return None;
    }
    let mut public_key = [0u8; PUBLIC_KEY_BYTES];
    let mut private_key = [0u8; PRIVATE_KEY_BYTES];
    public_key.copy_from_slice(&pk);
    private_key.copy_from_slice(&sk);
    Some(Keypair {
        public_key,
        private_key,
        public_key_base64: stored.public_key,
    })
}

/// Generates a fresh keypair and tries to persist it. A disk-write failure
/// is logged but not fatal - callers still get a valid, usable keypair for
/// this process's lifetime, they just won't survive a restart (this is the
/// same "best-effort, not a crash" posture the retired Electron client's
/// own registration heartbeat already had for its own failure modes).
fn generate_and_try_save() -> Keypair {
    let (public_key, private_key) = generate_keypair();
    let record = StoredKeypair {
        public_key: base64_encode(&public_key),
        private_key: base64_encode(&private_key),
    };
    let path = keypair_path();
    let save_result: std::io::Result<()> = (|| {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string(&record)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(&path, json)
    })();
    match save_result {
        Ok(()) => {
            #[cfg(windows)]
            if let Err(e) = crate::platform::set_path_permission_for_machine_secret(&path, false)
            {
                hbb_common::log::error!(
                    "rustdrop keystore: failed to harden ACL on {}: {}",
                    path.display(),
                    e
                );
            }
        }
        Err(e) => {
            hbb_common::log::error!(
                "rustdrop keystore: failed to persist keypair to {}: {} - using an in-memory-only keypair for this run",
                path.display(),
                e
            );
        }
    }
    to_keypair(public_key, private_key)
}

/// Loads the persisted keypair, or generates and persists a new one on
/// first use. Generated once per process lifetime and cached - a
/// deliberate reset is a manual file delete, not a feature, matching the
/// retired Electron client's own design.
pub fn load_or_create() -> &'static Keypair {
    KEYPAIR.get_or_init(|| try_load().unwrap_or_else(generate_and_try_save))
}

/// JSON view of this device's RustDrop keypair, for `--server` to hand to
/// the `--rustdrop` UI process over IPC (ipc::Data::RustDropKeypairRequest) -
/// same ACL wall and shape convention as directory_enrollment's
/// device_credential_ipc_json.
#[cfg(windows)]
pub(crate) fn keypair_ipc_json() -> String {
    let keypair = load_or_create();
    serde_json::json!({
        "public_key": keypair.public_key_base64,
        "private_key": base64_encode(&keypair.private_key),
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_keypair_round_trips_through_json() {
        let (public_key, private_key) = generate_keypair();
        let record = StoredKeypair {
            public_key: base64_encode(&public_key),
            private_key: base64_encode(&private_key),
        };
        let json = serde_json::to_string(&record).unwrap();
        let parsed: StoredKeypair = serde_json::from_str(&json).unwrap();
        assert_eq!(
            base64_decode(&parsed.public_key).unwrap(),
            public_key.to_vec()
        );
        assert_eq!(
            base64_decode(&parsed.private_key).unwrap(),
            private_key.to_vec()
        );
    }

    #[test]
    fn base64_round_trip() {
        let (public_key, _) = generate_keypair();
        let encoded = base64_encode(&public_key);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, public_key.to_vec());
    }
}
