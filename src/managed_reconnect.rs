//! Managed builds: a quick reconnect of an authenticated session doesn't ask again.
//!
//! Every authorized connection keeps a reconnect pass for its controller session (controller id
//! + that window's session id), valid until PASS_TTL_SECS after the connection was last seen
//! alive (renewed every 30 s while it runs). A new login with the same id and session id, from a
//! controller that verified its RDS device certificate on this login, is let in on the pass: no
//! password, TOTP or click again after a network blip, a stalled stream, or this service
//! restarting for an install or update. A new window has a new session id, and a session ended on
//! purpose (by the local user, policy or the controller) revokes its pass, so neither gets in.
//!
//! The passes live in ProgramData (SYSTEM/Administrators only) to survive the service
//! restarting; ids are stored only as a hash.
use hbb_common::{log, ResultType};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, path::PathBuf, sync::Mutex};

const FILE: &str = "reconnect_passes.json";
pub const PASS_TTL_SECS: i64 = 120;
pub const RENEW_EVERY_SECS: u64 = 30;

#[derive(Serialize, Deserialize, Default)]
struct Passes {
    /// hashed controller session -> valid until (unix seconds)
    passes: HashMap<String, i64>,
}

static LOCK: Mutex<()> = Mutex::new(());

fn key(peer_id: &str, session_id: u64) -> String {
    Sha256::digest(format!("rdc-reconnect\0{peer_id}\0{session_id}").as_bytes())[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn now() -> i64 {
    hbb_common::get_time() / 1000
}

fn path() -> ResultType<PathBuf> {
    Ok(crate::platform::get_program_data_dir()?
        .join("RustDeskManaged")
        .join(FILE))
}

fn load(path: &PathBuf) -> Passes {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn save(path: &PathBuf, passes: &Passes) -> ResultType<()> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(passes)?)?;
    crate::platform::set_path_permission_for_machine_secret(&tmp, false)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn update(peer_id: &str, session_id: u64, until: Option<i64>) {
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Ok(path) = path() else {
        return;
    };
    let mut passes = load(&path);
    let now = now();
    passes.passes.retain(|_, valid_until| *valid_until > now);
    match until {
        Some(until) => passes.passes.insert(key(peer_id, session_id), until),
        None => passes.passes.remove(&key(peer_id, session_id)),
    };
    if let Err(err) = save(&path, &passes) {
        log::warn!("reconnect pass not saved: {}", err);
    }
}

/// Keeps (or starts) the pass for this controller session, valid PASS_TTL_SECS from now.
pub fn keep(peer_id: &str, session_id: u64) {
    if session_id != 0 {
        update(peer_id, session_id, Some(now() + PASS_TTL_SECS));
    }
}

/// Ends the pass: the session was ended on purpose, so the controller has to log in again.
pub fn revoke(peer_id: &str, session_id: u64) {
    update(peer_id, session_id, None);
}

/// Whether this controller session holds a live pass.
pub fn valid(peer_id: &str, session_id: u64) -> bool {
    if session_id == 0 {
        return false;
    }
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Ok(path) = path() else {
        return false;
    };
    load(&path)
        .passes
        .get(&key(peer_id, session_id))
        .map_or(false, |until| *until > now())
}
