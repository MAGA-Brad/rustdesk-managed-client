//! Managed builds: a controller that has logged in with the password and TOTP twice may ask this
//! PC to trust it, and then skips the TOTP prompt for 90 days. Brad 2026-10-15: "complete 2
//! successful pass + Totp before granting that allowance to save"; "Trust for 90 days is ok too".
//!
//! Upstream's trusted devices are keyed on the hwid, id, name and platform the controller reports
//! about itself, so managed builds keep them off (connection.rs `enable_trusted_devices`). Here the
//! key is the controller's id plus the identity key its RDS certificate proved on this login
//! (managed_peer_auth.rs): the trust can't be claimed from another computer, and it stops working
//! with that certificate once RDS revokes the device. Changing this PC's TOTP secret or permanent
//! password voids every count and trust. The password is still checked on every login.
//!
//! Stored in ProgramData (SYSTEM/Administrators only) next to the reconnect passes; ids, keys and
//! the secret only as hashes.
use hbb_common::{config::Config, log, ResultType};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, path::PathBuf, sync::Mutex};

const FILE: &str = "trusted_controllers.json";
const LOGINS_BEFORE_TRUST: u32 = 2;
const TRUST_SECS: i64 = 90 * 24 * 60 * 60;

#[derive(Serialize, Deserialize, Default)]
struct Store {
    /// hashed (controller id, certificate key) -> record
    controllers: HashMap<String, Record>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct Record {
    /// This PC's TOTP secret and permanent password the record was made under (hashed).
    secret: String,
    /// Password + TOTP logins under that secret.
    logins: u32,
    /// When the controller was trusted (unix seconds); 0 until then.
    trusted_at: i64,
    last_login_at: i64,
}

impl Record {
    fn trusted(&self, now: i64) -> bool {
        self.trusted_at > 0 && now - self.trusted_at < TRUST_SECS
    }
}

static LOCK: Mutex<()> = Mutex::new(());

fn hash(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update([0u8]);
    }
    hasher.finalize()[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn key(peer_id: &str, peer_key: &str) -> String {
    hash(&["rdc-2fa-trust", peer_id, peer_key])
}

fn current_secret() -> String {
    let (password, salt) = Config::get_local_permanent_password_storage_and_salt();
    hash(&["rdc-2fa-secret", &Config::get_option("2fa"), &password, &salt])
}

fn now() -> i64 {
    hbb_common::get_time() / 1000
}

fn path() -> ResultType<PathBuf> {
    Ok(crate::platform::get_program_data_dir()?
        .join("RustDeskManaged")
        .join(FILE))
}

fn load(path: &PathBuf) -> Store {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn save(path: &PathBuf, store: &Store) -> ResultType<()> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(store)?)?;
    crate::platform::set_path_permission_for_machine_secret(&tmp, false)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn record(peer_id: &str, peer_key: &str) -> Option<Record> {
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let record = load(&path().ok()?)
        .controllers
        .get(&key(peer_id, peer_key))
        .cloned()?;
    (record.secret == current_secret()).then_some(record)
}

/// Whether this verified controller skips the TOTP prompt.
pub fn trusted(peer_id: &str, peer_key: &str) -> bool {
    record(peer_id, peer_key).map_or(false, |r| r.trusted(now()))
}

/// Whether the TOTP prompt may offer "Trust this device": two password + TOTP logins are done.
pub fn may_offer(peer_id: &str, peer_key: &str) -> bool {
    record(peer_id, peer_key).map_or(false, |r| r.logins >= LOGINS_BEFORE_TRUST)
}

/// Counts a password + TOTP login, and trusts the controller if it asked on a prompt that
/// offered it. Returns whether the controller is trusted now.
pub fn note_login(peer_id: &str, peer_key: &str, trust_requested: bool) -> bool {
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Ok(path) = path() else {
        return false;
    };
    let mut store = load(&path);
    let trusted = note(
        &mut store,
        key(peer_id, peer_key),
        current_secret(),
        now(),
        trust_requested,
    );
    if let Err(err) = save(&path, &store) {
        log::warn!("2FA trust not saved: {}", err);
    }
    trusted
}

fn note(store: &mut Store, key: String, secret: String, now: i64, trust_requested: bool) -> bool {
    store.controllers.retain(|_, r| {
        r.secret == secret && (r.trusted(now) || now - r.last_login_at < TRUST_SECS)
    });
    let record = store.controllers.entry(key).or_insert_with(|| Record {
        secret,
        ..Default::default()
    });
    let offered = record.logins >= LOGINS_BEFORE_TRUST;
    record.logins = record.logins.saturating_add(1);
    record.last_login_at = now;
    if trust_requested && offered {
        record.trusted_at = now;
    }
    record.trusted(now)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 24 * 60 * 60;

    fn offered(store: &Store, key: &str) -> bool {
        store.controllers.get(key).map_or(false, |r| r.logins >= LOGINS_BEFORE_TRUST)
    }

    #[test]
    fn trust_is_offered_only_after_two_logins() {
        let mut store = Store::default();
        let k = || "controller".to_owned();
        assert!(!note(&mut store, k(), "s".into(), 1_000, true), "first login can't trust");
        assert!(!offered(&store, "controller"));
        assert!(!note(&mut store, k(), "s".into(), 2_000, true), "second login can't trust");
        assert!(offered(&store, "controller"), "the third prompt offers it");
        assert!(!note(&mut store, k(), "s".into(), 3_000, false), "not asked, not trusted");
        assert!(note(&mut store, k(), "s".into(), 4_000, true));
        assert!(store.controllers["controller"].trusted(4_000 + 89 * DAY));
        assert!(!store.controllers["controller"].trusted(4_000 + 90 * DAY), "90 days at most");
    }

    #[test]
    fn a_new_secret_voids_counts_and_trust() {
        let mut store = Store::default();
        for at in 1..=3 {
            note(&mut store, "controller".into(), "old".into(), at, true);
        }
        assert!(store.controllers["controller"].trusted(10));
        assert!(!note(&mut store, "controller".into(), "new".into(), 20, true));
        assert_eq!(store.controllers["controller"].logins, 1);
        assert!(!offered(&store, "controller"));
    }

    #[test]
    fn controllers_are_counted_separately_and_idle_ones_expire() {
        let mut store = Store::default();
        note(&mut store, "a".into(), "s".into(), 0, false);
        note(&mut store, "a".into(), "s".into(), 1, false);
        note(&mut store, "b".into(), "s".into(), 2, false);
        assert!(offered(&store, "a"));
        assert!(!offered(&store, "b"));
        note(&mut store, "b".into(), "s".into(), 91 * DAY, false);
        assert!(!store.controllers.contains_key("a"), "untrusted and idle for 90 days");
    }
}
