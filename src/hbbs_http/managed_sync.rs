//! Change-driven sync with RDS (RDS app/device_sync.py): a held-open "wait for change" call wakes
//! this process the moment something it handles changes, instead of polling on timers. Every
//! heartbeat reply carries the same versions, so a failed or blocked wait costs at most one
//! heartbeat interval, and the old timers stay as slow backstops.

use super::directory_enrollment::{
    current_directory_credential, managed_build_number, managed_update_channel,
};
use crate::managed_sealed::SendSealed;
use hbb_common::{bail, log, tokio, ResultType};
use serde_derive::{Deserialize, Serialize};
use std::{
    sync::atomic::{AtomicBool, AtomicI64, Ordering},
    time::Duration,
};

const WAIT_SECONDS: u64 = 50;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(WAIT_SECONDS + 20);
const RETRY_MIN_SECONDS: u64 = 5;
const RETRY_MAX_SECONDS: u64 = 120;
/// RDS without the wait endpoint: the heartbeat-and-timer path covers everything, so ask rarely.
const UNSUPPORTED_RETRY_SECONDS: u64 = 600;
const HEALTHY_WITHIN_MS: i64 = 3 * 60 * 1000;
/// RDS holds a wait until something changes, so answers normally arrive seconds to a minute
/// apart. More than this many in a row arriving within QUICK_ANSWER means it is not holding them
/// (a server fault), and the loop slows down rather than hammering it.
const QUICK_ANSWER: Duration = Duration::from_secs(5);
const QUICK_ANSWERS_ALLOWED: u32 = 3;

#[derive(Clone, Default, Deserialize, Serialize, PartialEq, Debug)]
pub struct Versions {
    #[serde(default)]
    pub directory: String,
    #[serde(default)]
    pub build: u64,
    #[serde(default)]
    pub drops: u64,
    #[serde(default)]
    pub log: bool,
    #[serde(default)]
    pub status: String,
}

/// For the heartbeat reply: versions it cannot read count as absent, so they can never fail the
/// heartbeat itself (the wait loop and the timers still cover what they would have triggered).
pub fn lenient_versions<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<Versions>, D::Error> {
    let value = <serde_json::Value as serde::Deserialize>::deserialize(deserializer)?;
    Ok(serde_json::from_value(value).ok())
}

/// Which process this is: each waits only for what it handles.
#[derive(Clone, Copy)]
pub enum Role {
    /// The Windows service: managed-directory worker.
    Service,
    /// The session's --server process: RustDrop poller and updater.
    Session,
    /// The RustDrop window, while open: its device and drop lists.
    Window,
}

impl Role {
    fn keys(self) -> &'static [&'static str] {
        match self {
            // Android is one process: its worker also handles its own updates.
            #[cfg(target_os = "android")]
            Role::Service => &["directory", "log", "status", "build"],
            #[cfg(not(target_os = "android"))]
            Role::Service => &["directory", "log", "status"],
            Role::Session => &["drops", "build"],
            Role::Window => &["drops", "directory"],
        }
    }
}

static DROPS_CHANGES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static DIRECTORY_CHANGES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Bumped each time RDS reports a change, so the RustDrop window refetches a list only when the
/// count moved since it last did.
pub fn drops_changes() -> u64 {
    DROPS_CHANGES.load(Ordering::Relaxed)
}

pub fn directory_changes() -> u64 {
    DIRECTORY_CHANGES.load(Ordering::Relaxed)
}

/// The RustDrop window starts its own loop on first use; a process only ever needs one.
pub fn spawn_window_once() {
    static STARTED: std::sync::Once = std::sync::Once::new();
    STARTED.call_once(|| spawn_with(Role::Window, CredentialSource::ServerIpc));
}

#[derive(Clone, Copy)]
enum CredentialSource {
    /// Read directly, as the service and --server can.
    DirectoryFile,
    /// Asked from --server over local IPC: the RustDrop window runs as the signed-in user, who
    /// cannot read the device credential file (the same route its own RustDrop calls take).
    ServerIpc,
}

/// (directory base URL, device credential)
async fn fetch_credential(source: CredentialSource) -> ResultType<(String, String)> {
    match source {
        CredentialSource::DirectoryFile => current_directory_credential("managed sync"),
        #[cfg(target_os = "android")]
        CredentialSource::ServerIpc => bail!("no server process on Android"),
        #[cfg(not(target_os = "android"))]
        CredentialSource::ServerIpc => {
            #[derive(Deserialize)]
            struct Identity {
                directory_base_url: String,
                directory_credential: String,
            }
            let json = crate::ipc::rustdrop_identity_ipc_call().await;
            match serde_json::from_str::<Identity>(&json) {
                Ok(identity) => Ok((identity.directory_base_url, identity.directory_credential)),
                Err(_) => bail!("no identity from the server process: {}", json),
            }
        }
    }
}

static WAKE: std::sync::LazyLock<tokio::sync::Notify> = std::sync::LazyLock::new(tokio::sync::Notify::new);
static DIRECTORY_CHANGED: AtomicBool = AtomicBool::new(false);
static LOG_REQUESTED: AtomicBool = AtomicBool::new(false);
static STATUS_CHANGED: AtomicBool = AtomicBool::new(false);
static LAST_WAIT_OK_MS: AtomicI64 = AtomicI64::new(0);
static LATEST_DIRECTORY_VERSION: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// The directory version this loop last saw, so a fetch it triggered is recorded against the new
/// version rather than the one in the previous heartbeat (which would look like another change).
pub fn latest_directory_version() -> Option<String> {
    LATEST_DIRECTORY_VERSION.lock().unwrap().clone()
}

pub fn spawn(role: Role) {
    spawn_with(role, CredentialSource::DirectoryFile);
}

fn spawn_with(role: Role, credential: CredentialSource) {
    if option_env!("RUSTDESK_MANAGED_DIRECTORY_BASE").is_none() {
        return;
    }
    std::thread::spawn(move || run(role, credential));
}

/// The wait loop answered recently, so changes arrive within seconds and timers can slow down.
pub fn healthy() -> bool {
    hbb_common::get_time() - LAST_WAIT_OK_MS.load(Ordering::Relaxed) < HEALTHY_WITHIN_MS
}

pub fn take_directory_changed() -> bool {
    DIRECTORY_CHANGED.swap(false, Ordering::Relaxed)
}

pub fn take_log_requested() -> bool {
    LOG_REQUESTED.swap(false, Ordering::Relaxed)
}

pub fn take_status_changed() -> bool {
    STATUS_CHANGED.swap(false, Ordering::Relaxed)
}

/// The directory worker's idle wait, cut short when the wait loop reports a change.
pub async fn sleep_or_wake(delay: Duration) {
    tokio::select! {
        _ = tokio::time::sleep(delay) => {}
        _ = WAKE.notified() => {}
    }
}

#[tokio::main(flavor = "current_thread")]
async fn run(role: Role, credential: CredentialSource) {
    let mut known: Option<Versions> = None;
    let mut failures = 0u32;
    let mut quick_answers = 0u32;
    loop {
        let started = std::time::Instant::now();
        match wait_once(role, credential, known.as_ref()).await {
            Ok(Some((changed, versions))) => {
                failures = 0;
                LAST_WAIT_OK_MS.store(hbb_common::get_time(), Ordering::Relaxed);
                handle(role, known.is_none(), &changed, &versions);
                known = Some(versions);
                quick_answers = if started.elapsed() < QUICK_ANSWER { quick_answers + 1 } else { 0 };
                if quick_answers > QUICK_ANSWERS_ALLOWED {
                    let delay = RETRY_MIN_SECONDS
                        .saturating_mul(1u64 << (quick_answers - QUICK_ANSWERS_ALLOWED).min(5))
                        .min(RETRY_MAX_SECONDS);
                    log::debug!("managed sync: {quick_answers} immediate answers in a row, pausing {delay}s");
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                }
            }
            Ok(None) => {
                tokio::time::sleep(Duration::from_secs(UNSUPPORTED_RETRY_SECONDS)).await;
            }
            Err(error) => {
                failures = failures.saturating_add(1);
                log::debug!("managed sync: wait failed: {}", error);
                let delay = RETRY_MIN_SECONDS
                    .saturating_mul(1u64 << failures.min(5))
                    .min(RETRY_MAX_SECONDS);
                tokio::time::sleep(Duration::from_secs(delay)).await;
            }
        }
    }
}

/// Ok(None): this RDS has no wait endpoint.
async fn wait_once(
    role: Role,
    credential: CredentialSource,
    known: Option<&Versions>,
) -> ResultType<Option<(Vec<String>, Versions)>> {
    #[derive(Deserialize)]
    struct WaitResponse {
        #[serde(default)]
        changed: Vec<String>,
        versions: Versions,
    }

    let (base_url, credential) = fetch_credential(credential).await?;
    let url = format!("{}/v1/device/wait", base_url.trim_end_matches('/'));
    let known = match known {
        Some(known) => {
            let all = serde_json::to_value(known)?;
            role.keys()
                .iter()
                .filter_map(|key| Some((key.to_string(), all.get(*key)?.clone())))
                .collect::<serde_json::Map<_, _>>()
        }
        None => serde_json::Map::new(),
    };
    let client = super::http_client::create_http_client_async_with_url_strict(&url).await?;
    let response = client
        .post(&url)
        .bearer_auth(credential)
        .json(&serde_json::json!({
            "known": known,
            "arch": super::directory_enrollment::managed_update_arch(),
            "channel": managed_update_channel(),
            "wait_seconds": WAIT_SECONDS,
        }))
        .timeout(REQUEST_TIMEOUT)
        .send_sealed()
        .await?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !response.status().is_success() {
        bail!("HTTP {}", response.status());
    }
    let response = response.json::<WaitResponse>().await?;
    Ok(Some((response.changed, response.versions)))
}

fn handle(role: Role, first: bool, changed: &[String], versions: &Versions) {
    match role {
        Role::Service => {
            *LATEST_DIRECTORY_VERSION.lock().unwrap() = Some(versions.directory.clone());
            #[cfg(target_os = "android")]
            if versions.build > crate::managed_android::installed_release()
                && (first || changed.iter().any(|key| key == "build"))
            {
                crate::managed_android::on_update_pushed();
            }
            // The first answer only establishes what is current: the worker fetches on start anyway.
            if first {
                return;
            }
            for key in changed {
                match key.as_str() {
                    "directory" => DIRECTORY_CHANGED.store(true, Ordering::Relaxed),
                    "log" if versions.log => LOG_REQUESTED.store(true, Ordering::Relaxed),
                    "status" => STATUS_CHANGED.store(true, Ordering::Relaxed),
                    _ => {}
                }
            }
            WAKE.notify_one();
        }
        #[cfg(target_os = "android")]
        Role::Session => {}
        #[cfg(not(target_os = "android"))]
        Role::Session => {
            if !first && changed.iter().any(|key| key == "drops") {
                crate::rustdrop_service::poke();
            }
            // Checked on the first answer too: a device that was asleep or offline when a build
            // was published learns about it as soon as it is back.
            if versions.build > managed_build_number() && (first || changed.iter().any(|key| key == "build")) {
                crate::updater::on_update_pushed();
            }
        }
        Role::Window => {
            for key in changed {
                match key.as_str() {
                    "drops" => DROPS_CHANGES.fetch_add(1, Ordering::Relaxed),
                    "directory" => DIRECTORY_CHANGES.fetch_add(1, Ordering::Relaxed),
                    _ => 0,
                };
            }
        }
    }
}
