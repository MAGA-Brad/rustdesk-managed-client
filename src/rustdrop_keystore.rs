// RustDrop's X25519 keypair custody. The file is at `Config::path` - for `--server`, which runs as
// LocalSystem, that is the LocalService profile's RustDesk config folder - and `--server` hands the
// keypair to the `--rustdrop` UI process over IPC (ipc::Data::RustDropKeypairRequest). On Windows
// the private key is DPAPI-protected (machine scope) and the file carries the machine-secret ACL,
// like the device's other secrets (audit RDC-IPC-PLATFORM#2).
//
// A new keypair is made only when the file is missing or isn't a keypair at all. One that exists
// but can't be read or unprotected right now is left alone, and this run neither registers nor
// hands out a key, so a passing failure never changes the device's RustDrop key (audit
// RDC-RUSTDROP#7): RDS refuses drops sent under any key but the registered one.

use crate::rustdrop_crypto::{generate_keypair, PRIVATE_KEY_BYTES, PUBLIC_KEY_BYTES};
use hbb_common::config::Config;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const KEYPAIR_FILENAME: &str = "rustdrop_keypair.json";
const READ_ATTEMPTS: u32 = 4;
const READ_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(300);

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredKeypair {
    public_key: String,
    /// Plaintext: how every build before 43 wrote it, and how platforms without machine-scope
    /// protection still do.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    private_key: Option<String>,
    /// base64 of platform::protect_machine_scope(private key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    private_key_protected: Option<String>,
}

pub struct Keypair {
    pub public_key: [u8; PUBLIC_KEY_BYTES],
    pub private_key: [u8; PRIVATE_KEY_BYTES],
    pub public_key_base64: String,
    /// Made up for this run because the stored keypair couldn't be read: never registered and never
    /// handed out, so the next start loads the real one.
    pub ephemeral: bool,
}

enum LoadError {
    /// Reading failed (a sharing violation, I/O): retried, never a reason to make a new key.
    Io(std::io::Error),
    /// Not a keypair file: moved aside, then a new keypair is made.
    Corrupt(String),
    /// The protected private key can't be opened here: the file is kept as it is.
    Unprotect(String),
}

static KEYPAIR: OnceLock<Keypair> = OnceLock::new();

fn keypair_path() -> PathBuf {
    Config::path(KEYPAIR_FILENAME)
}

fn to_keypair(public_key: [u8; PUBLIC_KEY_BYTES], private_key: [u8; PRIVATE_KEY_BYTES]) -> Keypair {
    let public_key_base64 = base64_encode(&public_key);
    Keypair {
        public_key,
        private_key,
        public_key_base64,
        ephemeral: false,
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

fn decode_key<const N: usize>(b64: &str, what: &str) -> Result<[u8; N], LoadError> {
    let bytes =
        base64_decode(b64).ok_or_else(|| LoadError::Corrupt(format!("{what} is not base64")))?;
    bytes
        .try_into()
        .map_err(|_| LoadError::Corrupt(format!("{what} has the wrong length")))
}

#[cfg(windows)]
fn unprotect_private_key(protected_b64: &str) -> Result<[u8; PRIVATE_KEY_BYTES], LoadError> {
    let protected = base64_decode(protected_b64)
        .ok_or_else(|| LoadError::Corrupt("protected private key is not base64".into()))?;
    let mut raw = crate::platform::unprotect_machine_scope(&protected)
        .map_err(|e| LoadError::Unprotect(e.to_string()))?;
    let key = <[u8; PRIVATE_KEY_BYTES]>::try_from(raw.as_slice())
        .map_err(|_| LoadError::Corrupt("protected private key has the wrong length".into()));
    raw.fill(0);
    key
}

#[cfg(not(windows))]
fn unprotect_private_key(_protected_b64: &str) -> Result<[u8; PRIVATE_KEY_BYTES], LoadError> {
    Err(LoadError::Unprotect(
        "this platform has no machine-scope protection".into(),
    ))
}

/// What the file holds for `keypair`: the private key protected on Windows (the only platform
/// RustDrop's service runs on), in plaintext elsewhere as before.
#[cfg(windows)]
fn stored_record(keypair: &Keypair) -> std::io::Result<StoredKeypair> {
    let protected = crate::platform::protect_machine_scope(&keypair.private_key)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(StoredKeypair {
        public_key: keypair.public_key_base64.clone(),
        private_key: None,
        private_key_protected: Some(base64_encode(&protected)),
    })
}

#[cfg(not(windows))]
fn stored_record(keypair: &Keypair) -> std::io::Result<StoredKeypair> {
    Ok(StoredKeypair {
        public_key: keypair.public_key_base64.clone(),
        private_key: Some(base64_encode(&keypair.private_key)),
        private_key_protected: None,
    })
}

/// Ok(None): no keypair file. The bool: the private key is stored in plaintext on a platform that
/// can protect it, so the file should be rewritten.
fn try_load(path: &Path) -> Result<Option<(Keypair, bool)>, LoadError> {
    let contents = match std::fs::read(path) {
        Ok(contents) => contents,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(LoadError::Io(e)),
    };
    let stored: StoredKeypair = serde_json::from_slice(&contents)
        .map_err(|e| LoadError::Corrupt(format!("not a keypair file: {e}")))?;
    let public_key = decode_key::<PUBLIC_KEY_BYTES>(&stored.public_key, "public key")?;
    let (private_key, plaintext) = match (&stored.private_key_protected, &stored.private_key) {
        (Some(protected), _) => (unprotect_private_key(protected)?, false),
        (None, Some(plain)) => (
            decode_key::<PRIVATE_KEY_BYTES>(plain, "private key")?,
            cfg!(windows),
        ),
        (None, None) => return Err(LoadError::Corrupt("no private key".into())),
    };
    Ok(Some((
        Keypair {
            public_key,
            private_key,
            public_key_base64: stored.public_key,
            ephemeral: false,
        },
        plaintext,
    )))
}

/// Written beside `path`, hardened, then moved into place. `replace` false: a brand-new keypair,
/// which must not overwrite a file another process created meanwhile (AlreadyExists then).
fn save(path: &Path, record: &StoredKeypair, replace: bool) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension("json.tmp");
    let json = serde_json::to_vec(record).map_err(std::io::Error::other)?;
    std::fs::write(&temp, json)?;
    #[cfg(windows)]
    if let Err(e) = crate::platform::set_path_permission_for_machine_secret(&temp, false) {
        hbb_common::log::error!(
            "rustdrop keystore: failed to harden ACL on {}: {}",
            temp.display(),
            e
        );
    }
    let placed = if replace {
        std::fs::rename(&temp, path)
    } else {
        match std::fs::hard_link(&temp, path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(e),
            Err(_) if !path.exists() => std::fs::rename(&temp, path),
            Err(e) => Err(e),
        }
    };
    let _ = std::fs::remove_file(&temp);
    placed
}

fn ephemeral() -> Keypair {
    let (public_key, private_key) = generate_keypair();
    Keypair {
        ephemeral: true,
        ..to_keypair(public_key, private_key)
    }
}

/// A new keypair for a device that has none. A disk-write failure is logged but not fatal: the
/// keypair still works for this process's lifetime, it just won't survive a restart.
fn create(path: &Path) -> Keypair {
    let (public_key, private_key) = generate_keypair();
    let keypair = to_keypair(public_key, private_key);
    match stored_record(&keypair).and_then(|record| save(path, &record, false)) {
        Ok(()) => {
            hbb_common::log::info!("rustdrop keystore: created this device's keypair");
            keypair
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => match try_load(path) {
            Ok(Some((existing, _))) => existing,
            _ => {
                hbb_common::log::error!(
                    "rustdrop keystore: {} appeared meanwhile and can't be read - RustDrop is off for this run",
                    path.display()
                );
                Keypair {
                    ephemeral: true,
                    ..keypair
                }
            }
        },
        Err(e) => {
            hbb_common::log::error!(
                "rustdrop keystore: failed to persist keypair to {}: {} - using an in-memory-only keypair for this run",
                path.display(),
                e
            );
            keypair
        }
    }
}

fn set_aside(path: &Path, why: &str) {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut aside = path.as_os_str().to_os_string();
    aside.push(format!(".corrupt-{stamp}"));
    match std::fs::rename(path, &aside) {
        Ok(()) => hbb_common::log::error!(
            "rustdrop keystore: {} was not a usable keypair ({why}); moved to {} - this device gets a new RustDrop key",
            path.display(),
            PathBuf::from(&aside).display()
        ),
        Err(e) => hbb_common::log::error!(
            "rustdrop keystore: {} is not a usable keypair ({why}) and could not be moved aside: {e}",
            path.display()
        ),
    }
}

/// One-time migration of a keypair written before build 43: the same keys, the private key now
/// protected. On failure the file stays as it was and the keys are used as they are.
#[cfg(windows)]
fn protect_existing(path: &Path, keypair: &Keypair) {
    match stored_record(keypair).and_then(|record| save(path, &record, true)) {
        Ok(()) => {
            hbb_common::log::info!("rustdrop keystore: private key is now stored DPAPI-protected")
        }
        Err(e) => hbb_common::log::error!(
            "rustdrop keystore: could not rewrite {} with the private key protected: {}",
            path.display(),
            e
        ),
    }
}

#[cfg(not(windows))]
fn protect_existing(_path: &Path, _keypair: &Keypair) {}

fn load_or_create_at(path: &Path) -> Keypair {
    let mut attempt = 1;
    loop {
        match try_load(path) {
            Ok(Some((keypair, plaintext))) => {
                if plaintext {
                    protect_existing(path, &keypair);
                }
                return keypair;
            }
            Ok(None) => return create(path),
            Err(LoadError::Corrupt(why)) => {
                set_aside(path, &why);
                return create(path);
            }
            Err(LoadError::Unprotect(why)) => {
                hbb_common::log::error!(
                    "rustdrop keystore: the private key in {} can't be opened ({why}) - RustDrop is off for this run; the file is kept",
                    path.display()
                );
                return ephemeral();
            }
            Err(LoadError::Io(_)) if attempt < READ_ATTEMPTS => {
                attempt += 1;
                std::thread::sleep(READ_RETRY_DELAY);
            }
            Err(LoadError::Io(e)) => {
                hbb_common::log::error!(
                    "rustdrop keystore: could not read {} ({e}) - RustDrop is off for this run; the file is kept",
                    path.display()
                );
                return ephemeral();
            }
        }
    }
}

/// Loads the persisted keypair, or generates and persists a new one on first use. Loaded once per
/// process lifetime and cached; the first load may wait about a second retrying a failed read, so
/// async callers run it on a blocking thread.
pub fn load_or_create() -> &'static Keypair {
    KEYPAIR.get_or_init(|| load_or_create_at(&keypair_path()))
}

/// JSON view of this device's RustDrop keypair, for `--server` to hand to
/// the `--rustdrop` UI process over IPC (ipc::Data::RustDropKeypairRequest) -
/// same ACL wall and shape convention as directory_enrollment's
/// device_credential_ipc_json.
#[cfg(windows)]
pub(crate) fn keypair_ipc_json() -> String {
    let keypair = load_or_create();
    if keypair.ephemeral {
        return serde_json::json!({
            "error": "this device's RustDrop key could not be read - restart RDC, and see its log if this persists",
        })
        .to_string();
    }
    serde_json::json!({
        "public_key": keypair.public_key_base64,
        "private_key": base64_encode(&keypair.private_key),
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_keypair_path() -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("rustdrop_keystore_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(KEYPAIR_FILENAME)
    }

    fn cleanup(path: &Path) {
        if let Some(dir) = path.parent() {
            std::fs::remove_dir_all(dir).ok();
        }
    }

    /// The keystore hardens its file to SYSTEM + Administrators (it runs in `--server`), so on
    /// Windows only an elevated test run can read the file back.
    fn can_read_hardened_files() -> bool {
        #[cfg(windows)]
        if !crate::platform::is_elevated(None).unwrap_or(false) {
            eprintln!("skipped: reading back the machine-secret ACL needs an elevated test run");
            return false;
        }
        true
    }

    #[test]
    fn stored_keypair_round_trips_through_json() {
        let (public_key, private_key) = generate_keypair();
        let record = StoredKeypair {
            public_key: base64_encode(&public_key),
            private_key: Some(base64_encode(&private_key)),
            private_key_protected: None,
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(!json.contains("private_key_protected"));
        let parsed: StoredKeypair = serde_json::from_str(&json).unwrap();
        assert_eq!(
            base64_decode(&parsed.public_key).unwrap(),
            public_key.to_vec()
        );
        assert_eq!(
            base64_decode(parsed.private_key.as_deref().unwrap()).unwrap(),
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

    #[test]
    fn a_new_keypair_is_persisted_and_loaded_back() {
        if !can_read_hardened_files() {
            return;
        }
        let path = temp_keypair_path();
        let created = load_or_create_at(&path);
        assert!(!created.ephemeral);
        let loaded = load_or_create_at(&path);
        assert_eq!(loaded.public_key, created.public_key);
        assert_eq!(loaded.private_key, created.private_key);
        let stored: StoredKeypair = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(stored.private_key_protected.is_some(), cfg!(windows));
        assert_eq!(stored.private_key.is_some(), !cfg!(windows));
        assert!(!path.with_extension("json.tmp").exists());
        cleanup(&path);
    }

    #[test]
    fn a_plaintext_keypair_keeps_its_keys() {
        if !can_read_hardened_files() {
            return;
        }
        let path = temp_keypair_path();
        let (public_key, private_key) = generate_keypair();
        let legacy = format!(
            r#"{{"public_key":"{}","private_key":"{}"}}"#,
            base64_encode(&public_key),
            base64_encode(&private_key)
        );
        std::fs::write(&path, &legacy).unwrap();
        let loaded = load_or_create_at(&path);
        assert!(!loaded.ephemeral);
        assert_eq!(loaded.public_key, public_key);
        assert_eq!(loaded.private_key, private_key);
        let rewritten = std::fs::read_to_string(&path).unwrap();
        // Windows migrates it to the protected form once; elsewhere it stays as written.
        assert_eq!(
            rewritten.contains(&base64_encode(&private_key)),
            !cfg!(windows)
        );
        let again = load_or_create_at(&path);
        assert_eq!(again.private_key, private_key);
        cleanup(&path);
    }

    #[test]
    fn a_corrupt_file_is_set_aside_before_a_new_key_is_made() {
        if !can_read_hardened_files() {
            return;
        }
        let path = temp_keypair_path();
        std::fs::write(&path, b"{ truncated").unwrap();
        let created = load_or_create_at(&path);
        assert!(!created.ephemeral);
        let dir = path.parent().unwrap();
        let aside: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".corrupt-"))
            .collect();
        assert_eq!(aside.len(), 1);
        assert_eq!(std::fs::read(aside[0].path()).unwrap(), b"{ truncated");
        assert_eq!(load_or_create_at(&path).public_key, created.public_key);
        cleanup(&path);
    }

    #[test]
    fn an_unreadable_file_is_never_replaced() {
        // A directory where the file should be: every read fails, as with a locked file.
        let path = temp_keypair_path();
        std::fs::create_dir_all(&path).unwrap();
        let keypair = load_or_create_at(&path);
        assert!(keypair.ephemeral);
        assert!(path.is_dir(), "left exactly as it was");
        cleanup(&path);
    }

    #[test]
    fn a_protected_key_that_cannot_be_opened_is_kept() {
        let path = temp_keypair_path();
        let (public_key, _) = generate_keypair();
        let contents = format!(
            r#"{{"public_key":"{}","private_key_protected":"{}"}}"#,
            base64_encode(&public_key),
            base64_encode(b"not a DPAPI blob")
        );
        std::fs::write(&path, &contents).unwrap();
        let keypair = load_or_create_at(&path);
        assert!(keypair.ephemeral);
        assert_ne!(keypair.public_key, public_key);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), contents);
        cleanup(&path);
    }

    #[test]
    fn a_new_keypair_never_overwrites_an_existing_file() {
        if !can_read_hardened_files() {
            return;
        }
        let path = temp_keypair_path();
        std::fs::write(&path, b"someone else's").unwrap();
        let record = stored_record(&ephemeral()).unwrap();
        let err = save(&path, &record, false).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), b"someone else's");
        assert!(!path.with_extension("json.tmp").exists());
        cleanup(&path);
    }
}
