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
//! A pass is bound to the kind of session it was issued for (connection.rs
//! `reconnect_pass_scope`) and carries what that session had been granted: a reconnect comes back
//! as the same kind of session, under the same login, with no permission the session no longer
//! had. A click-approved (view-only) session stays view-only, and a file transfer can't come back
//! as remote control.
//!
//! The passes live in ProgramData (SYSTEM/Administrators only) to survive the service
//! restarting; ids are stored only as a hash.
//!
//! After a network drop the connection left behind runs on until its own timeout, beside the
//! reconnect that took its session over. A pass belongs to the connection that started keeping it
//! last: older ones can neither write nor revoke it, and once it is revoked none that kept it
//! before can write it back. Each is told so, and stops keeping it for good.
use hbb_common::{log, ResultType};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{mpsc, Mutex},
    time::{Duration, Instant},
};

const FILE: &str = "reconnect_passes.json";
pub const PASS_TTL_SECS: i64 = 120;
pub const RENEW_EVERY_SECS: u64 = 30;
// Forgetting who holds a pass nobody has touched for this long is safe: a connection that lost it
// learns so at its next renewal, RENEW_EVERY_SECS on, and stops keeping it for good.
const HOLDER_KEEP: Duration = Duration::from_secs(600);

#[derive(Serialize, Deserialize, Default)]
struct Passes {
    /// hashed controller session and scope -> pass. Passes from before the scope binding don't
    /// parse, so the whole file reads as empty and none of them is honoured.
    passes: HashMap<String, Pass>,
}

#[derive(Serialize, Deserialize, Clone, Copy)]
struct Pass {
    /// valid until (unix seconds)
    until: i64,
    grant: Grant,
}

/// What a session had been granted, as its connection holds it.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Grant {
    /// The audit codes of the login the session came in on (primary auth and second factor).
    pub primary_auth: i64,
    pub two_factor: i64,
    pub keyboard: bool,
    pub clipboard: bool,
    pub audio: bool,
    pub file: bool,
    pub restart: bool,
    pub recording: bool,
    pub block_input: bool,
    pub privacy_mode: bool,
}

static LOCK: Mutex<()> = Mutex::new(());
/// Who holds each pass. In memory only: every connection that could write one is in this process.
static HOLDERS: Mutex<Vec<(String, Holder)>> = Mutex::new(Vec::new());
/// Kept passes reach the file in the order they were kept, off the connections' async loops.
static WRITER: Mutex<Option<mpsc::Sender<Kept>>> = Mutex::new(None);

/// The connection holding a pass, known by when it started keeping it (`since` in `keep`).
struct Holder {
    since: Instant,
    /// Revoked at `since`: only a connection that starts keeping it later may.
    revoked: bool,
    touched: Instant,
}

struct Kept {
    key: String,
    pass: Pass,
    since: Instant,
}

fn key(peer_id: &str, session_id: u64, scope: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("rdc-reconnect\0{peer_id}\0{session_id}\0").as_bytes());
    hasher.update(scope);
    hasher.finalize()[..16]
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

/// The caller holds LOCK.
fn update(key: String, pass: Option<Pass>) {
    let Ok(path) = path() else {
        return;
    };
    let mut passes = load(&path);
    apply(&mut passes, key, pass, now());
    if let Err(err) = save(&path, &passes) {
        log::warn!("reconnect pass not saved: {}", err);
    }
}

fn lock_holders() -> std::sync::MutexGuard<'static, Vec<(String, Holder)>> {
    HOLDERS.lock().unwrap_or_else(|e| e.into_inner())
}

/// Whether the connection that started keeping the pass at `since` still holds it.
fn may_write(holders: &[(String, Holder)], key: &str, since: Instant) -> bool {
    holders
        .iter()
        .find(|(k, _)| k == key)
        .map_or(true, |(_, holder)| {
            if holder.revoked {
                since > holder.since
            } else {
                since >= holder.since
            }
        })
}

/// The connection that started keeping the pass at `since` keeps it from now on, or revokes it;
/// false (and nothing recorded) when it had already lost it.
fn claim(
    holders: &mut Vec<(String, Holder)>,
    key: &str,
    since: Instant,
    revoke: bool,
    now: Instant,
) -> bool {
    holders.retain(|(_, holder)| now.duration_since(holder.touched) < HOLDER_KEEP);
    if !may_write(holders, key, since) {
        return false;
    }
    let holder = Holder {
        since: if revoke { now } else { since },
        revoked: revoke,
        touched: now,
    };
    match holders.iter_mut().find(|(k, _)| k == key) {
        Some((_, held)) => *held = holder,
        None => holders.push((key.to_owned(), holder)),
    }
    true
}

fn store(kept: Kept) {
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Checked again here: the pass may have moved on, or been revoked, while this write waited.
    let held = may_write(&lock_holders(), &kept.key, kept.since);
    if held {
        update(kept.key, Some(kept.pass));
    }
}

fn write_in_order(kept: Kept) {
    let mut writer = WRITER.lock().unwrap_or_else(|e| e.into_inner());
    let kept = match writer.as_ref() {
        Some(tx) => match tx.send(kept) {
            Ok(()) => return,
            Err(mpsc::SendError(kept)) => kept,
        },
        None => kept,
    };
    let (tx, rx) = mpsc::channel::<Kept>();
    let started = std::thread::Builder::new()
        .name("reconnect-pass".to_owned())
        .spawn(move || rx.into_iter().for_each(store));
    match started {
        Ok(_) => {
            if tx.send(kept).is_err() {
                log::warn!("reconnect pass not saved: its writer stopped");
            }
            *writer = Some(tx);
        }
        Err(err) => log::warn!("reconnect pass not saved: no writer: {}", err),
    }
}

fn apply(passes: &mut Passes, key: String, pass: Option<Pass>, now: i64) {
    passes.passes.retain(|_, kept| kept.until > now);
    match pass {
        Some(pass) => passes.passes.insert(key, pass),
        None => passes.passes.remove(&key),
    };
}

fn lookup(passes: &Passes, key: &str, now: i64) -> Option<Grant> {
    passes
        .passes
        .get(key)
        .filter(|pass| pass.until > now)
        .map(|pass| pass.grant)
}

/// Keeps (or starts) the pass for this controller session and scope, valid PASS_TTL_SECS from
/// now, carrying what the session holds now. `since` is when the keeping connection first kept
/// it. False when a newer connection has kept the pass since, or it was revoked: that connection
/// must stop keeping it. The write itself happens on the pass writer thread.
pub fn keep(
    peer_id: &str,
    session_id: u64,
    scope: &[u8; 32],
    grant: Grant,
    since: Instant,
) -> bool {
    if session_id == 0 {
        return true;
    }
    let key = key(peer_id, session_id, scope);
    if !claim(&mut lock_holders(), &key, since, false, Instant::now()) {
        return false;
    }
    let until = now() + PASS_TTL_SECS;
    write_in_order(Kept {
        key,
        pass: Pass { until, grant },
        since,
    });
    true
}

/// Ends the pass: the session was ended on purpose, so the controller has to log in again. A
/// connection a newer one had taken the pass from (`since` as in `keep`) leaves it alone.
pub fn revoke(peer_id: &str, session_id: u64, scope: &[u8; 32], since: Instant) {
    let key = key(peer_id, session_id, scope);
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let held = claim(&mut lock_holders(), &key, since, true, Instant::now());
    if held {
        update(key, None);
    }
}

/// What this controller session had been granted, if it holds a live pass for this scope.
pub fn grant(peer_id: &str, session_id: u64, scope: &[u8; 32]) -> Option<Grant> {
    if session_id == 0 {
        return None;
    }
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Ok(path) = path() else {
        return None;
    };
    lookup(&load(&path), &key(peer_id, session_id, scope), now())
}

#[cfg(test)]
mod tests {
    use super::*;

    const REMOTE: [u8; 32] = [1; 32];
    const FILE_TRANSFER: [u8; 32] = [2; 32];

    fn view_only() -> Grant {
        Grant {
            primary_auth: 1,
            clipboard: true,
            file: true,
            ..Default::default()
        }
    }

    fn pass(until: i64, grant: Grant) -> Option<Pass> {
        Some(Pass { until, grant })
    }

    #[test]
    fn a_pass_lets_in_only_the_scope_it_was_kept_for() {
        let mut passes = Passes::default();
        apply(&mut passes, key("c", 7, &FILE_TRANSFER), pass(200, view_only()), 100);
        assert_eq!(lookup(&passes, &key("c", 7, &FILE_TRANSFER), 150), Some(view_only()));
        assert_eq!(lookup(&passes, &key("c", 7, &REMOTE), 150), None, "other scope");
        assert_eq!(lookup(&passes, &key("c", 8, &FILE_TRANSFER), 150), None, "other window");
        assert_eq!(lookup(&passes, &key("d", 7, &FILE_TRANSFER), 150), None, "other controller");
    }

    #[test]
    fn a_kept_pass_carries_the_latest_grant_until_it_expires() {
        let mut passes = Passes::default();
        let k = || key("c", 7, &REMOTE);
        apply(&mut passes, k(), pass(200, view_only()), 100);
        let granted = Grant {
            keyboard: true,
            ..view_only()
        };
        apply(&mut passes, k(), pass(230, granted), 110);
        assert_eq!(lookup(&passes, &k(), 229), Some(granted));
        assert_eq!(lookup(&passes, &k(), 230), None, "expired");
        apply(&mut passes, key("other", 1, &REMOTE), pass(400, view_only()), 300);
        assert!(!passes.passes.contains_key(&k()), "expired passes are dropped");
    }

    #[test]
    fn revoking_removes_only_that_pass() {
        let mut passes = Passes::default();
        apply(&mut passes, key("c", 7, &REMOTE), pass(200, view_only()), 100);
        apply(&mut passes, key("c", 9, &REMOTE), pass(200, view_only()), 100);
        apply(&mut passes, key("c", 7, &REMOTE), None, 110);
        assert_eq!(lookup(&passes, &key("c", 7, &REMOTE), 120), None);
        assert_eq!(lookup(&passes, &key("c", 9, &REMOTE), 120), Some(view_only()));
    }

    #[test]
    fn passes_saved_before_the_scope_binding_are_not_honoured() {
        assert!(serde_json::from_slice::<Passes>(br#"{"passes":{"00ff":4102444800}}"#).is_err());
        let mut passes = Passes::default();
        apply(&mut passes, key("c", 7, &REMOTE), pass(200, view_only()), 100);
        let saved = serde_json::to_vec(&passes).unwrap();
        let loaded: Passes = serde_json::from_slice(&saved).unwrap();
        assert_eq!(lookup(&loaded, &key("c", 7, &REMOTE), 150), Some(view_only()));
    }

    fn at(start: Instant, secs: u64) -> Instant {
        start + Duration::from_secs(secs)
    }

    #[test]
    fn a_reconnect_takes_the_pass_from_the_connection_it_replaced() {
        let t = Instant::now();
        let (left_behind, reconnect) = (at(t, 0), at(t, 5));
        let k = key("c", 7, &REMOTE);
        let mut holders = Vec::new();
        assert!(claim(&mut holders, &k, left_behind, false, at(t, 1)));
        assert!(claim(&mut holders, &k, reconnect, false, at(t, 6)));
        assert!(
            claim(&mut holders, &k, reconnect, false, at(t, 7)),
            "the reconnect renews"
        );
        assert!(
            !claim(&mut holders, &k, left_behind, false, at(t, 30)),
            "its older permissions don't overwrite the reconnect's"
        );
        assert!(
            !may_write(&holders, &k, left_behind),
            "nor does a write already queued"
        );
        assert!(
            !claim(&mut holders, &k, left_behind, true, at(t, 31)),
            "nor can it revoke the reconnect's pass"
        );
        assert!(may_write(&holders, &k, reconnect));
        let other_scope = key("c", 7, &FILE_TRANSFER);
        assert!(
            may_write(&holders, &other_scope, left_behind),
            "other scope"
        );
    }

    #[test]
    fn a_revoked_pass_is_not_written_back_by_a_connection_from_before_the_revoke() {
        let t = Instant::now();
        let (left_behind, reconnect) = (at(t, 0), at(t, 5));
        let k = key("c", 7, &REMOTE);
        let mut holders = Vec::new();
        assert!(claim(&mut holders, &k, left_behind, false, at(t, 1)));
        assert!(claim(&mut holders, &k, reconnect, false, at(t, 6)));
        assert!(
            claim(&mut holders, &k, reconnect, true, at(t, 10)),
            "disconnected on purpose"
        );
        assert!(!may_write(&holders, &k, reconnect), "its own queued write");
        assert!(!claim(&mut holders, &k, reconnect, false, at(t, 11)));
        assert!(!claim(&mut holders, &k, left_behind, false, at(t, 12)));
        assert!(
            !claim(&mut holders, &k, at(t, 10), false, at(t, 13)),
            "a tie is refused"
        );
        assert!(
            claim(&mut holders, &k, at(t, 14), false, at(t, 14)),
            "a login after the revoke keeps its own pass"
        );
    }

    #[test]
    fn holders_nobody_touched_for_a_while_are_forgotten() {
        let t = Instant::now();
        let (k7, k8, k9) = (
            key("c", 7, &REMOTE),
            key("c", 8, &REMOTE),
            key("c", 9, &REMOTE),
        );
        let mut holders = Vec::new();
        assert!(claim(&mut holders, &k7, t, true, t));
        assert!(claim(&mut holders, &k8, t, false, t + HOLDER_KEEP / 2));
        assert_eq!(holders.len(), 2);
        assert!(claim(&mut holders, &k9, t, false, t + HOLDER_KEEP));
        assert_eq!(holders.len(), 2);
        assert!(may_write(&holders, &k7, t));
    }
}
