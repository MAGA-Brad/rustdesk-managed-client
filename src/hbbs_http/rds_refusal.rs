//! Managed builds: back off once RDS refuses this device's credential, so a deleted, revoked or
//! blocked device stops hammering RDS (one deleted device sent thousands of refused requests within
//! hours). Per process: each one backs off its own callers after its own refusals. Credential
//! recovery in the directory worker runs first and is never gated here.
use hbb_common::{bail, ResultType};
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    sync::Mutex,
    time::{Duration, Instant},
};

const FIRST_DELAY: Duration = Duration::from_secs(5);
const MAX_DELAY: Duration = Duration::from_secs(30 * 60);
/// RDS said the device is gone or no longer approved: check back hourly in case it is restored.
const REMOVED_DELAY: Duration = Duration::from_secs(60 * 60);

#[derive(Default)]
struct State {
    refusals: u32,
    retry_at: Option<Instant>,
    refused_credential: u64,
    /// The X-RDC-Device-Status RDS sent with its last refusal (RDS from 2026-10-14).
    device_status: Option<String>,
}

static STATE: Mutex<State> = Mutex::new(State {
    refusals: 0,
    retry_at: None,
    refused_credential: 0,
    device_status: None,
});

fn managed() -> bool {
    option_env!("RUSTDESK_MANAGED_DIRECTORY_BASE").is_some()
}

fn tag(credential: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    credential.hash(&mut hasher);
    hasher.finish()
}

/// Err (no network call) while this process is backing off from a refusal of this credential.
/// A different credential (recovery issued a new one) starts clean.
pub fn check(credential: &str) -> ResultType<()> {
    if !managed() {
        return Ok(());
    }
    let mut state = STATE.lock().unwrap();
    let Some(retry_at) = state.retry_at else {
        return Ok(());
    };
    if state.refused_credential != tag(credential) {
        *state = State::default();
        return Ok(());
    }
    let now = Instant::now();
    if now >= retry_at {
        return Ok(());
    }
    if removed_status(&state) {
        bail!("{}", REMOVED_TEXT);
    }
    bail!(
        "RDS refused this device's credential; next try in {} s",
        (retry_at - now).as_secs()
    )
}

/// A 401/403 for this credential. Loops that fail together inside one wait count once.
pub fn note_refused(status: u16, credential: &str) {
    if !managed() || !(status == 401 || status == 403) {
        return;
    }
    let mut state = STATE.lock().unwrap();
    let now = Instant::now();
    let credential = tag(credential);
    if state.refused_credential == credential && state.retry_at.map_or(false, |at| now < at) {
        return;
    }
    state.refused_credential = credential;
    state.refusals = state.refusals.saturating_add(1);
    let delay = if removed_status(&state) {
        REMOVED_DELAY
    } else {
        FIRST_DELAY
            .saturating_mul(1u32 << (state.refusals - 1).min(10))
            .min(MAX_DELAY)
    };
    state.retry_at = Some(now + delay);
    hbb_common::log::warn!(
        "RDS refused this device ({status}, refusal {}); backing off {} s",
        state.refusals,
        delay.as_secs()
    );
}

pub fn note_success() {
    if !managed() {
        return;
    }
    let mut state = STATE.lock().unwrap();
    if state.retry_at.is_some() || state.device_status.is_some() {
        *state = State::default();
    }
}

/// From any RDS response: the device status RDS reports alongside a refusal.
pub fn note_device_status(headers: &reqwest::header::HeaderMap) {
    if !managed() {
        return;
    }
    if let Some(value) = headers
        .get("x-rdc-device-status")
        .and_then(|value| value.to_str().ok())
    {
        STATE.lock().unwrap().device_status = Some(value.trim().to_owned());
    }
}

fn removed_status(state: &State) -> bool {
    matches!(state.device_status.as_deref(), Some(status) if status != "approved")
}

/// RDS no longer knows this device or it is no longer approved.
pub fn removed() -> bool {
    managed() && removed_status(&STATE.lock().unwrap())
}

pub fn removed_delay() -> Duration {
    REMOVED_DELAY
}

pub const REMOVED_TEXT: &str = "No longer enrolled \u{2014} ask the owner to enroll it again";
