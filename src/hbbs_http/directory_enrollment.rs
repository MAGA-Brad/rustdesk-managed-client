use hbb_common::{
    anyhow::anyhow,
    config::{keys, Config},
    log, tokio, ResultType,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::windows::ffi::OsStrExt,
    path::PathBuf,
    sync::Once,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use winapi::um::winbase::{
    MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
};

static START_DIRECTORY_WORKER: Once = Once::new();
static DIRECTORY_SNAPSHOT_JSON: std::sync::Mutex<String> =
    std::sync::Mutex::new(String::new());
const DIRECTORY_STATE_SCHEMA_VERSION: u32 = 1;
const DIRECTORY_STATE_FILE: &str = "directory_state.dpapi";

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PersistedEnrollmentStatus {
    NotEnrolled,
    Pending,
    Approved,
    Denied,
    Blocked,
    Revoked,
}

#[derive(Clone, Serialize, Deserialize)]
struct PersistedDirectoryAuth {
    version: u32,
    rustdesk_id: String,
    device_public_key: String,
    status: PersistedEnrollmentStatus,

    // Durable enrollment continuity identity. Once first enrollment succeeds,
    // these remain stored across Pending, Approved, Blocked, and Revoked.
    device_id: Option<String>,
    enrollment_poll_token: Option<String>,

    // Server-directed polling metadata. These may change over the device
    // lifetime without changing the continuity identity above.
    poll_expires_at: Option<String>,
    poll_after_seconds: Option<u64>,

    // Approved-device authorization. This may be removed or invalidated
    // without erasing device_id or enrollment_poll_token.
    device_credential: Option<String>,
    credential_serial: Option<String>,
}

fn protect_persisted_auth(
    state: &PersistedDirectoryAuth,
) -> ResultType<Vec<u8>> {
    let mut plaintext = serde_json::to_vec(state)
        .map_err(|error| anyhow!("Failed to serialize directory state: {}", error))?;

    let result = crate::platform::protect_machine_scope(&plaintext);

    // Do not leave the serialized poll token or credential in this
    // temporary plaintext buffer longer than necessary.
    plaintext.fill(0);

    result
}

fn unprotect_persisted_auth(
    protected: &[u8],
) -> ResultType<PersistedDirectoryAuth> {
    let mut plaintext = crate::platform::unprotect_machine_scope(protected)?;

    let result = serde_json::from_slice::<PersistedDirectoryAuth>(&plaintext)
        .map_err(|error| anyhow!("Failed to decode protected directory state: {}", error));

    plaintext.fill(0);

    let state = result?;

    if state.version != DIRECTORY_STATE_SCHEMA_VERSION {
        return Err(anyhow!(
            "Unsupported directory state schema version: {}",
            state.version
        ));
    }

    Ok(state)
}
fn validate_persisted_auth_identity(
    state: &PersistedDirectoryAuth,
    identity: &DirectoryIdentity,
) -> ResultType<()> {
    if state.rustdesk_id != identity.rustdesk_id {
        return Err(anyhow!(
            "Protected directory state belongs to a different RustDesk ID"
        ));
    }

    if state.device_public_key != identity.device_public_key {
        return Err(anyhow!(
            "Protected directory state belongs to a different device key"
        ));
    }

    match state.status {
        PersistedEnrollmentStatus::NotEnrolled => {}
        PersistedEnrollmentStatus::Pending
        | PersistedEnrollmentStatus::Approved
        | PersistedEnrollmentStatus::Denied
        | PersistedEnrollmentStatus::Blocked
        | PersistedEnrollmentStatus::Revoked => {
            if state
                .device_id
                .as_deref()
                .unwrap_or_default()
                .trim()
                .is_empty()
            {
                return Err(anyhow!(
                    "Protected directory state is missing device continuity ID"
                ));
            }

            if state
                .enrollment_poll_token
                .as_deref()
                .unwrap_or_default()
                .is_empty()
            {
                return Err(anyhow!(
                    "Protected directory state is missing enrollment continuity token"
                ));
            }
        }
    }

    if matches!(state.status, PersistedEnrollmentStatus::Approved) {
        if state
            .device_credential
            .as_deref()
            .unwrap_or_default()
            .is_empty()
        {
            return Err(anyhow!(
                "Approved directory state is missing device credential"
            ));
        }

        if state
            .credential_serial
            .as_deref()
            .unwrap_or_default()
            .trim()
            .is_empty()
        {
            return Err(anyhow!(
                "Approved directory state is missing credential serial"
            ));
        }
    }

    Ok(())
}
fn read_persisted_auth() -> ResultType<Option<PersistedDirectoryAuth>> {
    let path = directory_state_path()?;

    if !path.exists() {
        return Ok(None);
    }

    // Reject reparse points and restore/verify the exact machine-secret ACL
    // before reading any persisted authentication material.
    crate::platform::set_path_permission_for_machine_secret(
        &path,
        false,
    )?;

    let protected = fs::read(&path).map_err(|error| {
        anyhow!(
            "Failed to read protected directory state '{}': {}",
            path.display(),
            error
        )
    })?;

    if protected.is_empty() {
        return Err(anyhow!(
            "Protected directory state file is empty: '{}'",
            path.display()
        ));
    }

    let state = unprotect_persisted_auth(&protected)?;
    let identity = current_identity()?;

    validate_persisted_auth_identity(&state, &identity)?;

    Ok(Some(state))
}
fn write_persisted_auth(state: &PersistedDirectoryAuth) -> ResultType<()> {
    let dir = ensure_directory_store_dir()?;
    let state_path = directory_state_path()?;

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| anyhow!("System clock is before Unix epoch: {}", error))?
        .as_nanos();

    let temp_path = dir.join(format!(
        "{}.{}.{}.tmp",
        DIRECTORY_STATE_FILE,
        std::process::id(),
        nonce
    ));

    let protected = protect_persisted_auth(state)?;

    let result = (|| -> ResultType<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(|error| {
                anyhow!(
                    "Failed to create protected directory state temporary file '{}': {}",
                    temp_path.display(),
                    error
                )
            })?;

        // Apply the exact machine-secret ACL before any ciphertext is written.
        crate::platform::set_path_permission_for_machine_secret(
            &temp_path,
            false,
        )?;

        file.write_all(&protected).map_err(|error| {
            anyhow!(
                "Failed to write protected directory state temporary file '{}': {}",
                temp_path.display(),
                error
            )
        })?;

        file.sync_all().map_err(|error| {
            anyhow!(
                "Failed to flush protected directory state temporary file '{}': {}",
                temp_path.display(),
                error
            )
        })?;

        drop(file);

        let temp_wide: Vec<u16> = temp_path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let state_wide: Vec<u16> = state_path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let moved = unsafe {
            MoveFileExW(
                temp_wide.as_ptr(),
                state_wide.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };

        if moved == 0 {
            return Err(anyhow!(
                "Failed to atomically replace protected directory state '{}': {}",
                state_path.display(),
                std::io::Error::last_os_error()
            ));
        }

        // The replacement retains the temporary file's restrictive ACL.
        // Reapply/verify our exact desired ACL before returning success.
        crate::platform::set_path_permission_for_machine_secret(
            &state_path,
            false,
        )?;

        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }

    result
}
fn directory_store_dir() -> ResultType<PathBuf> {
    Ok(crate::platform::get_program_data_dir()?
        .join("RustDeskManaged"))
}

fn directory_state_path() -> ResultType<PathBuf> {
    Ok(directory_store_dir()?.join(DIRECTORY_STATE_FILE))
}

fn ensure_directory_store_dir() -> ResultType<PathBuf> {
    let dir = directory_store_dir()?;

    crate::platform::create_machine_secret_directory(&dir)?;

    Ok(dir)
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryState {
    NotEnrolled,
    Enrolling,
    Pending,
    Ready,
    Unavailable,
    Denied,
    Blocked,
    Revoked,
}

static DIRECTORY_STATE: std::sync::Mutex<DirectoryState> =
    std::sync::Mutex::new(DirectoryState::NotEnrolled);

pub fn set_state(state: DirectoryState) {
    if let Ok(mut current) = DIRECTORY_STATE.lock() {
        *current = state;
    }
}

pub fn snapshot_json() -> String {
    DIRECTORY_SNAPSHOT_JSON
        .lock()
        .map(|snapshot| snapshot.clone())
        .unwrap_or_default()
}

fn store_directory_snapshot(response: &DirectoryResponse) {
    if let Ok(snapshot) = serde_json::to_string(response) {
        if let Ok(mut current) = DIRECTORY_SNAPSHOT_JSON.lock() {
            *current = snapshot;
        }
    }
}

fn store_management_snapshot(value: serde_json::Value) {
    if let Ok(snapshot) = serde_json::to_string(&value) {
        if let Ok(mut current) = DIRECTORY_SNAPSHOT_JSON.lock() {
            *current = snapshot;
        }
    }
}

fn clear_directory_snapshot() {
    if let Ok(mut current) = DIRECTORY_SNAPSHOT_JSON.lock() {
        current.clear();
    }
}

fn reenrollment_snapshot_flags() -> (bool, bool) {
    let snapshot = snapshot_json();
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&snapshot) else {
        return (false, false);
    };
    (
        value
            .get("reenrollment_requested")
            .and_then(|value| value.as_bool())
            .unwrap_or(false),
        value
            .get("reenrollment_authorized")
            .and_then(|value| value.as_bool())
            .unwrap_or(false),
    )
}

pub fn get_state() -> DirectoryState {
    DIRECTORY_STATE
        .lock()
        .map(|state| *state)
        .unwrap_or(DirectoryState::Unavailable)
}

pub fn state_key() -> &'static str {
    match get_state() {
        DirectoryState::NotEnrolled => "not_enrolled",
        DirectoryState::Enrolling => "enrolling",
        DirectoryState::Pending => "pending",
        DirectoryState::Ready => "ready",
        DirectoryState::Unavailable => "unavailable",
        DirectoryState::Denied => "denied",
        DirectoryState::Blocked => "blocked",
        DirectoryState::Revoked => "revoked",
    }
}

pub fn status_text() -> String {
    let friendly_name = Config::get_option(keys::OPTION_PRESET_DEVICE_NAME)
        .trim()
        .to_owned();
    let (reenrollment_requested, reenrollment_authorized) =
        reenrollment_snapshot_flags();

    match get_state() {
        DirectoryState::NotEnrolled => {
            format!("Not enrolled \u{2014} {friendly_name}")
        }
        DirectoryState::Enrolling => {
            format!("Enrolling \u{2014} {friendly_name}")
        }
        DirectoryState::Pending => {
            format!("Pending approval \u{2014} {friendly_name}")
        }
        DirectoryState::Ready => {
            format!("Ready \u{2014} {friendly_name}")
        }
        DirectoryState::Unavailable => {
            format!("Directory unavailable \u{2014} {friendly_name}")
        }
        DirectoryState::Denied => {
            if reenrollment_authorized {
                "Re-enrollment authorized \u{2014} Recovering managed enrollment".to_owned()
            } else if reenrollment_requested {
                "Re-enrollment requested \u{2014} Waiting for approval".to_owned()
            } else {
                "Enrollment denied \u{2014} Re-enrollment required".to_owned()
            }
        }
        DirectoryState::Blocked => {
            if reenrollment_authorized {
                "Re-enrollment authorized \u{2014} Recovering managed enrollment".to_owned()
            } else if reenrollment_requested {
                "Re-enrollment requested \u{2014} Waiting for approval".to_owned()
            } else {
                "Device blocked \u{2014} Re-enrollment required".to_owned()
            }
        }
        DirectoryState::Revoked => {
            if reenrollment_authorized {
                "Re-enrollment authorized \u{2014} Recovering managed enrollment".to_owned()
            } else if reenrollment_requested {
                "Re-enrollment requested \u{2014} Waiting for approval".to_owned()
            } else {
                "Access revoked \u{2014} Re-enrollment required".to_owned()
            }
        }
    }
}
#[derive(Serialize)]
struct EnrollmentRequest<'a> {
    enrollment_password: &'a str,
    rustdesk_id: &'a str,
    hostname: &'a str,
    friendly_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    contact_email: Option<&'a str>,
    device_public_key: &'a str,
    client_version: Option<&'a str>,

    #[serde(skip_serializing_if = "Option::is_none")]
    reenrollment_poll_token: Option<&'a str>,
}

#[derive(Deserialize)]
struct EnrollmentDevice {
    id: String,
    rustdesk_id: String,
    hostname: String,
    friendly_name: Option<String>,
    status: String,
    created_at: String,
}

#[derive(Deserialize)]
struct EnrollmentResponse {
    result: String,
    device: EnrollmentDevice,
    poll_token: String,
    poll_expires_at: String,
    poll_after_seconds: u64,
}
#[derive(Serialize)]
struct EnrollmentStatusRequest<'a> {
    device_id: &'a str,
    poll_token: &'a str,
}

#[derive(Deserialize)]
struct EnrollmentStatusResponse {
    device_id: String,
    rustdesk_id: String,
    hostname: String,
    friendly_name: Option<String>,
    status: String,
    status_reason: Option<String>,
    status_changed_at: Option<String>,
    poll_expires_at: Option<String>,
    poll_after_seconds: u64,

    credential: Option<String>,
    credential_serial: Option<String>,
    client_settings: Option<serde_json::Value>,

    #[serde(default)]
    reenrollment_requested: bool,
    #[serde(default)]
    reenrollment_request_id: Option<String>,
    #[serde(default)]
    reenrollment_request_expires_at: Option<String>,
    #[serde(default)]
    reenrollment_authorized: bool,
    #[serde(default)]
    reenrollment_authorization_expires_at: Option<String>,
}

#[derive(Serialize)]
struct ReenrollmentControlRequest<'a> {
    device_id: &'a str,
    poll_token: &'a str,
}

#[derive(Deserialize)]
struct ReenrollmentRequestResponse {
    status: String,
    device_id: String,
    device_status: String,
    poll_expires_at: String,
    reenrollment_requested: bool,
    reenrollment_request_id: Option<String>,
    reenrollment_request_expires_at: Option<String>,
    reenrollment_authorized: bool,
    reenrollment_authorization_expires_at: Option<String>,
}

#[derive(Serialize)]
struct ReenrollmentCompleteRequest<'a> {
    device_id: &'a str,
    poll_token: &'a str,
    rustdesk_id: &'a str,
    hostname: &'a str,
    friendly_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    contact_email: Option<&'a str>,
    device_public_key: &'a str,
    client_version: Option<&'a str>,
}
#[derive(Deserialize)]
struct DeviceMeResponse {
    id: String,
    rustdesk_id: String,
    hostname: String,
    friendly_name: Option<String>,
    status: String,
    credential_serial: String,
    credential_issued_at: String,
    credential_expires_at: Option<String>,
    instance_id: String,
}
#[derive(Serialize)]
struct HeartbeatRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<&'a str>,

    #[serde(skip_serializing_if = "Option::is_none")]
    friendly_name: Option<&'a str>,

    #[serde(skip_serializing_if = "Option::is_none")]
    client_version: Option<&'a str>,
}

#[derive(Deserialize)]
struct HeartbeatResponse {
    status: String,
    server_time: String,
    device_status: String,
    client_version: Option<String>,
    client_settings: Option<serde_json::Value>,
}
#[derive(Deserialize, Serialize)]
struct DirectoryDevice {
    id: String,
    rustdesk_id: String,
    display_name: String,
    hostname: String,
    last_ip: Option<String>,
    last_seen_at: Option<String>,
    #[serde(default)]
    online: bool,
}

#[derive(Deserialize, Serialize)]
struct DirectoryResponse {
    instance_id: String,
    generated_at: String,
    refresh_seconds: u64,
    devices: Vec<DirectoryDevice>,
    client_settings: Option<serde_json::Value>,
    #[serde(default)]
    server_stats: Option<DirectoryServerStats>,
}

// Optional and defaulted: an older or temporarily degraded server may omit
// this field entirely, and the Directory response must still parse.
#[derive(Clone, Deserialize, Serialize)]
struct DirectoryServerStats {
    online_clients: u64,
    active_sessions: u64,
    #[serde(default)]
    online_window_seconds: u64,
    #[serde(default)]
    active_session_timeout_seconds: u64,
}

fn remove_current_device_from_directory(
    response: &mut DirectoryResponse,
    current_device_id: Option<&str>,
) {
    let Some(current_device_id) = current_device_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return;
    };

    response
        .devices
        .retain(|device| device.id.trim() != current_device_id);
}
#[derive(Deserialize)]
struct RelayLeaseResponse {
    status: String,
    lease_id: String,
    device_id: String,
    credential_serial: String,
    source_ip: String,
    issued_at: String,
    expires_at: String,
    renew_after_seconds: u64,
    firewall_sync_after_seconds: u64,
    guard_mode: String,
    rustdesk_server: String,
    guarded_tcp_ports: Vec<u16>,
    guarded_udp_ports: Vec<u16>,
}

#[derive(Serialize)]
struct ManagedSessionHeartbeatRequest<'a> {
    session_id: &'a str,
    session_type: &'a str,
    state: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_rustdesk_id: Option<&'a str>,
}

pub struct ManagedSessionTelemetry {
    stop_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for ManagedSessionTelemetry {
    fn drop(&mut self) {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
    }
}

async fn post_managed_session_heartbeat(
    base_url: &str,
    credential: &str,
    session_id: &str,
    session_type: &str,
    state: &str,
    peer_rustdesk_id: Option<&str>,
) -> ResultType<()> {
    const OPERATION: &str = "managed session heartbeat";

    let url = directory_api_url(
        base_url,
        "/v1/device/session-heartbeat",
        OPERATION,
    )
    .map_err(|error| anyhow!("{}", error))?;

    let client = super::http_client::create_http_client_async_with_url_strict(
        &url,
    )
    .await
    .map_err(|_| anyhow!("Managed session heartbeat HTTPS client is unavailable"))?;

    let response = client
        .post(&url)
        .bearer_auth(credential)
        .json(&ManagedSessionHeartbeatRequest {
            session_id,
            session_type,
            state,
            peer_rustdesk_id,
        })
        .send()
        .await
        .map_err(|error| anyhow!("Managed session heartbeat failed: {}", error))?;

    if response.status() != reqwest::StatusCode::OK {
        return Err(anyhow!(
            "Managed session heartbeat returned HTTP {}",
            response.status()
        ));
    }

    Ok(())
}

pub fn start_managed_session_telemetry(
    session_id: String,
    session_type: &'static str,
    peer_rustdesk_id: Option<String>,
) -> Option<ManagedSessionTelemetry> {
    if session_type != "remote_desktop" && session_type != "file_transfer" {
        return None;
    }

    let base_url = managed_directory_base_url()?.to_owned();
    let state = read_persisted_auth().ok().flatten()?;
    if !matches!(state.status, PersistedEnrollmentStatus::Approved) {
        return None;
    }
    let credential = state
        .device_credential
        .as_deref()
        .filter(|value| !value.is_empty())?
        .to_owned();

    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(error) = post_managed_session_heartbeat(
                        &base_url,
                        &credential,
                        &session_id,
                        session_type,
                        "active",
                        peer_rustdesk_id.as_deref(),
                    ).await {
                        log::warn!("Managed session telemetry heartbeat failed: {}", error);
                    }
                }
                _ = &mut stop_rx => {
                    if let Err(error) = post_managed_session_heartbeat(
                        &base_url,
                        &credential,
                        &session_id,
                        session_type,
                        "ended",
                        peer_rustdesk_id.as_deref(),
                    ).await {
                        log::warn!("Managed session telemetry end failed: {}", error);
                    }
                    break;
                }
            }
        }
    });

    Some(ManagedSessionTelemetry {
        stop_tx: Some(stop_tx),
    })
}
fn runtime_state_from_persisted_status(
    status: &PersistedEnrollmentStatus,
) -> DirectoryState {
    match status {
        PersistedEnrollmentStatus::NotEnrolled => {
            DirectoryState::NotEnrolled
        }
        PersistedEnrollmentStatus::Pending => DirectoryState::Pending,

        // An approved credential is not Ready until /v1/device/me
        // validates it for this exact device and credential serial.
        PersistedEnrollmentStatus::Approved => {
            DirectoryState::Unavailable
        }

        PersistedEnrollmentStatus::Denied => DirectoryState::Denied,
        PersistedEnrollmentStatus::Blocked => DirectoryState::Blocked,
        PersistedEnrollmentStatus::Revoked => DirectoryState::Revoked,
    }
}

fn persist_pending_enrollment(
    identity: &DirectoryIdentity,
    response: EnrollmentResponse,
) -> ResultType<PersistedDirectoryAuth> {
    let state = pending_state_from_enrollment(identity, response)?;

    write_persisted_auth(&state)?;
    clear_directory_snapshot();
    set_state(DirectoryState::Pending);

    Ok(state)
}

fn persist_enrollment_status(
    state: PersistedDirectoryAuth,
    response: EnrollmentStatusResponse,
) -> ResultType<PersistedDirectoryAuth> {
    let updated = state_from_enrollment_status(state, response)?;

    write_persisted_auth(&updated)?;

    let runtime_state =
        runtime_state_from_persisted_status(&updated.status);
    set_state(runtime_state);

    Ok(updated)
}
fn validate_device_me_response(
    state: &PersistedDirectoryAuth,
    response: &DeviceMeResponse,
) -> ResultType<()> {
    let expected_device_id = state
        .device_id
        .as_deref()
        .unwrap_or_default();

    let expected_serial = state
        .credential_serial
        .as_deref()
        .unwrap_or_default();

    if expected_device_id.is_empty() {
        return Err(anyhow!(
            "Protected directory state is missing device continuity ID"
        ));
    }

    if expected_serial.is_empty() {
        return Err(anyhow!(
            "Protected directory state is missing credential serial"
        ));
    }

    if response.id != expected_device_id {
        return Err(anyhow!(
            "Device identity response belongs to a different device"
        ));
    }

    if response.rustdesk_id != state.rustdesk_id {
        return Err(anyhow!(
            "Device identity response RustDesk ID does not match this device"
        ));
    }

    if response.status != "approved" {
        return Err(anyhow!(
            "Device identity response is not approved"
        ));
    }

    if response.credential_serial != expected_serial {
        return Err(anyhow!(
            "Device identity response credential serial does not match"
        ));
    }

    Ok(())
}
fn state_from_enrollment_status(
    mut state: PersistedDirectoryAuth,
    response: EnrollmentStatusResponse,
) -> ResultType<PersistedDirectoryAuth> {
    validate_enrollment_status_response(&state, &response)?;

    state.poll_expires_at =
        response.poll_expires_at.or(state.poll_expires_at);
    state.poll_after_seconds = Some(response.poll_after_seconds);

    match response.status.as_str() {
        "pending" => {
            state.status = PersistedEnrollmentStatus::Pending;
            state.device_credential = None;
            state.credential_serial = None;
        }

        "approved" => {
            state.status = PersistedEnrollmentStatus::Approved;
            state.device_credential = response.credential;
            state.credential_serial = response.credential_serial;
        }

        "denied" => {
            state.status = PersistedEnrollmentStatus::Denied;
            state.device_credential = None;
            state.credential_serial = None;
        }

        "blocked" => {
            state.status = PersistedEnrollmentStatus::Blocked;
            state.device_credential = None;
            state.credential_serial = None;
        }

        "revoked" => {
            state.status = PersistedEnrollmentStatus::Revoked;
            state.device_credential = None;
            state.credential_serial = None;
        }

        _ => unreachable!(
            "status was validated before persisted-state transition"
        ),
    }

    Ok(state)
}
fn validate_enrollment_status_response(
    state: &PersistedDirectoryAuth,
    response: &EnrollmentStatusResponse,
) -> ResultType<()> {
    let expected_device_id = state
        .device_id
        .as_deref()
        .unwrap_or_default();

    if expected_device_id.is_empty() {
        return Err(anyhow!(
            "Protected directory state is missing device continuity ID"
        ));
    }

    if response.device_id != expected_device_id {
        return Err(anyhow!(
            "Enrollment status response belongs to a different device"
        ));
    }

    if response.rustdesk_id != state.rustdesk_id {
        return Err(anyhow!(
            "Enrollment status response RustDesk ID does not match this device"
        ));
    }

    match response.status.as_str() {
        "pending" | "denied" | "blocked" | "revoked" => {}

        "approved" => {
            if response
                .credential
                .as_deref()
                .unwrap_or_default()
                .is_empty()
            {
                return Err(anyhow!(
                    "Approved enrollment status is missing device credential"
                ));
            }

            if response
                .credential_serial
                .as_deref()
                .unwrap_or_default()
                .trim()
                .is_empty()
            {
                return Err(anyhow!(
                    "Approved enrollment status is missing credential serial"
                ));
            }
        }

        _ => {
            return Err(anyhow!(
                "Enrollment status response returned an unknown device status"
            ));
        }
    }

    Ok(())
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectoryApiErrorKind {
    Configuration,
    Timeout,
    Connection,
    Transport,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Unprocessable,
    RateLimited,
    Server,
    UnexpectedStatus,
    InvalidResponse,
}

#[derive(Debug)]
struct DirectoryApiError {
    operation: &'static str,
    kind: DirectoryApiErrorKind,
    status: Option<u16>,
    retry_after_seconds: Option<u64>,
}

impl std::fmt::Display for DirectoryApiError {
    fn fmt(
        &self,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        if let Some(status) = self.status {
            if let Some(retry_after) = self.retry_after_seconds {
                return write!(
                    formatter,
                    "{} failed with HTTP {} (retry after {} seconds)",
                    self.operation,
                    status,
                    retry_after
                );
            }

            return write!(
                formatter,
                "{} failed with HTTP {}",
                self.operation,
                status
            );
        }

        let reason = match self.kind {
            DirectoryApiErrorKind::Configuration => "configuration",
            DirectoryApiErrorKind::Timeout => "timeout",
            DirectoryApiErrorKind::Connection => "connection",
            DirectoryApiErrorKind::Transport => "transport",
            DirectoryApiErrorKind::InvalidResponse => "invalid response",
            DirectoryApiErrorKind::Unauthorized => "unauthorized",
            DirectoryApiErrorKind::Forbidden => "forbidden",
            DirectoryApiErrorKind::NotFound => "not found",
            DirectoryApiErrorKind::Conflict => "conflict",
            DirectoryApiErrorKind::Unprocessable => "unprocessable",
            DirectoryApiErrorKind::RateLimited => "rate limited",
            DirectoryApiErrorKind::Server => "server",
            DirectoryApiErrorKind::UnexpectedStatus => {
                "unexpected status"
            }
        };

        write!(formatter, "{} failed ({})", self.operation, reason)
    }
}

impl std::error::Error for DirectoryApiError {}

type DirectoryApiResult<T> =
    std::result::Result<T, DirectoryApiError>;

impl DirectoryApiError {
    fn configuration(operation: &'static str) -> Self {
        Self {
            operation,
            kind: DirectoryApiErrorKind::Configuration,
            status: None,
            retry_after_seconds: None,
        }
    }

    fn invalid_response(operation: &'static str) -> Self {
        Self {
            operation,
            kind: DirectoryApiErrorKind::InvalidResponse,
            status: None,
            retry_after_seconds: None,
        }
    }

    fn transport(
        operation: &'static str,
        error: &reqwest::Error,
    ) -> Self {
        let kind = if error.is_timeout() {
            DirectoryApiErrorKind::Timeout
        } else if error.is_connect() {
            DirectoryApiErrorKind::Connection
        } else {
            DirectoryApiErrorKind::Transport
        };

        Self {
            operation,
            kind,
            status: None,
            retry_after_seconds: None,
        }
    }

    fn from_http_response(
        operation: &'static str,
        response: &reqwest::Response,
    ) -> Self {
        let status = response.status();

        let retry_after_seconds = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok());

        let kind = match status {
            reqwest::StatusCode::UNAUTHORIZED => {
                DirectoryApiErrorKind::Unauthorized
            }
            reqwest::StatusCode::FORBIDDEN => {
                DirectoryApiErrorKind::Forbidden
            }
            reqwest::StatusCode::NOT_FOUND => {
                DirectoryApiErrorKind::NotFound
            }
            reqwest::StatusCode::CONFLICT => {
                DirectoryApiErrorKind::Conflict
            }
            reqwest::StatusCode::UNPROCESSABLE_ENTITY => {
                DirectoryApiErrorKind::Unprocessable
            }
            reqwest::StatusCode::TOO_MANY_REQUESTS => {
                DirectoryApiErrorKind::RateLimited
            }
            status if status.is_server_error() => {
                DirectoryApiErrorKind::Server
            }
            _ => DirectoryApiErrorKind::UnexpectedStatus,
        };

        Self {
            operation,
            kind,
            status: Some(status.as_u16()),
            retry_after_seconds,
        }
    }
}

fn directory_api_url(
    base_url: &str,
    path: &str,
    operation: &'static str,
) -> DirectoryApiResult<String> {
    let mut url = url::Url::parse(base_url)
        .map_err(|_| DirectoryApiError::configuration(operation))?;

    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(DirectoryApiError::configuration(operation));
    }

    url.set_query(None);
    url.set_fragment(None);
    url.set_path(path);

    Ok(url.to_string())
}

async fn post_enrollment_request(
    base_url: &str,
    identity: &DirectoryIdentity,
    enrollment_password: &str,
    reenrollment_poll_token: Option<&str>,
) -> DirectoryApiResult<EnrollmentResponse> {
    const OPERATION: &str = "directory enrollment";

    let url = directory_api_url(
        base_url,
        "/v1/enrollment/devices",
        OPERATION,
    )?;

    let client =
        super::http_client::create_http_client_async_with_url_strict(
            &url,
        )
        .await
        .map_err(|_| DirectoryApiError::configuration(OPERATION))?;

    let request = EnrollmentRequest {
        enrollment_password,
        rustdesk_id: identity.rustdesk_id.as_str(),
        hostname: identity.hostname.as_str(),
        friendly_name: Some(identity.friendly_name.as_str()),
        contact_email: Some(identity.contact_email.as_str())
            .filter(|value| !value.is_empty()),
        device_public_key: identity.device_public_key.as_str(),
        client_version: Some(identity.client_version.as_str()),
        reenrollment_poll_token,
    };

    let response = client
        .post(&url)
        .json(&request)
        .send()
        .await
        .map_err(|error| {
            DirectoryApiError::transport(OPERATION, &error)
        })?;

    if response.status() != reqwest::StatusCode::OK {
        return Err(DirectoryApiError::from_http_response(
            OPERATION,
            &response,
        ));
    }

    response
        .json::<EnrollmentResponse>()
        .await
        .map_err(|_| DirectoryApiError::invalid_response(OPERATION))
}

async fn post_enrollment_status_request(
    base_url: &str,
    state: &PersistedDirectoryAuth,
) -> DirectoryApiResult<EnrollmentStatusResponse> {
    const OPERATION: &str = "directory enrollment status";

    let device_id = state
        .device_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| DirectoryApiError::configuration(OPERATION))?;

    let poll_token = state
        .enrollment_poll_token
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| DirectoryApiError::configuration(OPERATION))?;

    let url = directory_api_url(
        base_url,
        "/v1/enrollment/status",
        OPERATION,
    )?;

    let client =
        super::http_client::create_http_client_async_with_url_strict(
            &url,
        )
        .await
        .map_err(|_| DirectoryApiError::configuration(OPERATION))?;

    let request = EnrollmentStatusRequest {
        device_id,
        poll_token,
    };

    let response = client
        .post(&url)
        .json(&request)
        .send()
        .await
        .map_err(|error| {
            DirectoryApiError::transport(OPERATION, &error)
        })?;

    if response.status() != reqwest::StatusCode::OK {
        return Err(DirectoryApiError::from_http_response(
            OPERATION,
            &response,
        ));
    }

    response
        .json::<EnrollmentStatusResponse>()
        .await
        .map_err(|_| DirectoryApiError::invalid_response(OPERATION))
}
fn management_snapshot_from_status(response: &EnrollmentStatusResponse) {
    store_management_snapshot(serde_json::json!({
        "reenrollment_requested": response.reenrollment_requested,
        "reenrollment_request_id": response.reenrollment_request_id.as_deref(),
        "reenrollment_request_expires_at": response.reenrollment_request_expires_at.as_deref(),
        "reenrollment_authorized": response.reenrollment_authorized,
        "reenrollment_authorization_expires_at": response.reenrollment_authorization_expires_at.as_deref(),
        "status_reason": response.status_reason.as_deref(),
        "status_changed_at": response.status_changed_at.as_deref(),
    }));
}

fn management_snapshot_from_request(response: &ReenrollmentRequestResponse) {
    log::debug!(
        "Managed re-enrollment request ok: device_status={} poll_expires_at={}",
        response.device_status,
        response.poll_expires_at,
    );
    store_management_snapshot(serde_json::json!({
        "reenrollment_requested": response.reenrollment_requested,
        "reenrollment_request_id": response.reenrollment_request_id.as_deref(),
        "reenrollment_request_expires_at": response.reenrollment_request_expires_at.as_deref(),
        "reenrollment_authorized": response.reenrollment_authorized,
        "reenrollment_authorization_expires_at": response.reenrollment_authorization_expires_at.as_deref(),
    }));
}

async fn post_reenrollment_request(
    base_url: &str,
    state: &PersistedDirectoryAuth,
) -> DirectoryApiResult<ReenrollmentRequestResponse> {
    const OPERATION: &str = "directory re-enrollment request";
    let device_id = state
        .device_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| DirectoryApiError::configuration(OPERATION))?;
    let poll_token = state
        .enrollment_poll_token
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| DirectoryApiError::configuration(OPERATION))?;
    let url = directory_api_url(
        base_url,
        "/v1/enrollment/reenrollment-request",
        OPERATION,
    )?;
    let client =
        super::http_client::create_http_client_async_with_url_strict(&url)
            .await
            .map_err(|_| DirectoryApiError::configuration(OPERATION))?;
    let response = client
        .post(&url)
        .json(&ReenrollmentControlRequest {
            device_id,
            poll_token,
        })
        .send()
        .await
        .map_err(|error| DirectoryApiError::transport(OPERATION, &error))?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(DirectoryApiError::from_http_response(
            OPERATION,
            &response,
        ));
    }
    response
        .json::<ReenrollmentRequestResponse>()
        .await
        .map_err(|_| DirectoryApiError::invalid_response(OPERATION))
}

async fn post_reenrollment_complete(
    base_url: &str,
    state: &PersistedDirectoryAuth,
    identity: &DirectoryIdentity,
) -> DirectoryApiResult<EnrollmentResponse> {
    const OPERATION: &str = "directory re-enrollment recovery";
    let device_id = state
        .device_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| DirectoryApiError::configuration(OPERATION))?;
    let poll_token = state
        .enrollment_poll_token
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| DirectoryApiError::configuration(OPERATION))?;
    let url = directory_api_url(
        base_url,
        "/v1/enrollment/reenroll",
        OPERATION,
    )?;
    let client =
        super::http_client::create_http_client_async_with_url_strict(&url)
            .await
            .map_err(|_| DirectoryApiError::configuration(OPERATION))?;
    let response = client
        .post(&url)
        .json(&ReenrollmentCompleteRequest {
            device_id,
            poll_token,
            rustdesk_id: identity.rustdesk_id.as_str(),
            hostname: identity.hostname.as_str(),
            friendly_name: Some(identity.friendly_name.as_str()),
            contact_email: Some(identity.contact_email.as_str())
                .filter(|value| !value.is_empty()),
            device_public_key: identity.device_public_key.as_str(),
            client_version: Some(identity.client_version.as_str()),
        })
        .send()
        .await
        .map_err(|error| DirectoryApiError::transport(OPERATION, &error))?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(DirectoryApiError::from_http_response(
            OPERATION,
            &response,
        ));
    }
    response
        .json::<EnrollmentResponse>()
        .await
        .map_err(|_| DirectoryApiError::invalid_response(OPERATION))
}

pub async fn request_reenrollment_once() -> ResultType<()> {
    let base_url = managed_directory_base_url().ok_or_else(|| {
        anyhow!("Managed directory endpoint is not configured")
    })?;
    let state = read_persisted_auth()?
        .ok_or_else(|| anyhow!("Managed device continuity state is unavailable"))?;
    if !matches!(
        state.status,
        PersistedEnrollmentStatus::Denied
            | PersistedEnrollmentStatus::Blocked
            | PersistedEnrollmentStatus::Revoked
    ) {
        return Err(anyhow!(
            "Re-enrollment may only be requested for denied, blocked, or revoked devices"
        ));
    }
    let response = post_reenrollment_request(base_url, &state)
        .await
        .map_err(|error| anyhow!("{}", error))?;
    if response.status != "requested" {
        return Err(anyhow!("Directory returned an invalid re-enrollment request state"));
    }
    if response.device_id != state.device_id.as_deref().unwrap_or_default() {
        return Err(anyhow!("Re-enrollment response belongs to a different device"));
    }
    management_snapshot_from_request(&response);
    Ok(())
}

fn approved_credential<'a>(
    state: &'a PersistedDirectoryAuth,
    operation: &'static str,
) -> DirectoryApiResult<&'a str> {
    if !matches!(
        state.status,
        PersistedEnrollmentStatus::Approved
    ) {
        return Err(DirectoryApiError::configuration(operation));
    }

    state
        .device_credential
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| DirectoryApiError::configuration(operation))
}

async fn get_device_me_request(
    base_url: &str,
    state: &PersistedDirectoryAuth,
) -> DirectoryApiResult<DeviceMeResponse> {
    const OPERATION: &str = "directory device identity";

    let credential = approved_credential(state, OPERATION)?;

    let url = directory_api_url(
        base_url,
        "/v1/device/me",
        OPERATION,
    )?;

    let client =
        super::http_client::create_http_client_async_with_url_strict(
            &url,
        )
        .await
        .map_err(|_| DirectoryApiError::configuration(OPERATION))?;

    let response = client
        .get(&url)
        .bearer_auth(credential)
        .send()
        .await
        .map_err(|error| {
            DirectoryApiError::transport(OPERATION, &error)
        })?;

    if response.status() != reqwest::StatusCode::OK {
        return Err(DirectoryApiError::from_http_response(
            OPERATION,
            &response,
        ));
    }

    let response = response
        .json::<DeviceMeResponse>()
        .await
        .map_err(|_| DirectoryApiError::invalid_response(OPERATION))?;

    validate_device_me_response(state, &response)
        .map_err(|_| DirectoryApiError::invalid_response(OPERATION))?;

    log::debug!(
        "Managed device identity ok: hostname={} friendly_name={:?} instance_id={} credential_issued_at={} credential_expires_at={:?}",
        response.hostname,
        response.friendly_name,
        response.instance_id,
        response.credential_issued_at,
        response.credential_expires_at,
    );

    Ok(response)
}

fn validate_heartbeat_response(
    response: &HeartbeatResponse,
) -> DirectoryApiResult<()> {
    const OPERATION: &str = "directory heartbeat";

    if response.status != "ok"
        || response.device_status != "approved"
    {
        return Err(DirectoryApiError::invalid_response(OPERATION));
    }

    Ok(())
}

async fn post_heartbeat_request(
    base_url: &str,
    state: &PersistedDirectoryAuth,
    identity: &DirectoryIdentity,
) -> DirectoryApiResult<HeartbeatResponse> {
    const OPERATION: &str = "directory heartbeat";

    let credential = approved_credential(state, OPERATION)?;

    let url = directory_api_url(
        base_url,
        "/v1/device/heartbeat",
        OPERATION,
    )?;

    let client =
        super::http_client::create_http_client_async_with_url_strict(
            &url,
        )
        .await
        .map_err(|_| DirectoryApiError::configuration(OPERATION))?;

    let request = HeartbeatRequest {
        hostname: Some(identity.hostname.as_str()),
        friendly_name: Some(identity.friendly_name.as_str()),
        client_version: Some(identity.client_version.as_str()),
    };

    let response = client
        .post(&url)
        .bearer_auth(credential)
        .json(&request)
        .send()
        .await
        .map_err(|error| {
            DirectoryApiError::transport(OPERATION, &error)
        })?;

    if response.status() != reqwest::StatusCode::OK {
        return Err(DirectoryApiError::from_http_response(
            OPERATION,
            &response,
        ));
    }

    let response = response
        .json::<HeartbeatResponse>()
        .await
        .map_err(|_| DirectoryApiError::invalid_response(OPERATION))?;

    validate_heartbeat_response(&response)?;

    log::debug!(
        "Managed heartbeat ok: server_time={} client_version={:?} client_settings_present={}",
        response.server_time,
        response.client_version,
        response.client_settings.is_some(),
    );

    Ok(response)
}

async fn get_directory_request(
    base_url: &str,
    state: &PersistedDirectoryAuth,
) -> DirectoryApiResult<DirectoryResponse> {
    const OPERATION: &str = "directory download";

    let credential = approved_credential(state, OPERATION)?;

    let url = directory_api_url(
        base_url,
        "/v1/directory",
        OPERATION,
    )?;

    let client =
        super::http_client::create_http_client_async_with_url_strict(
            &url,
        )
        .await
        .map_err(|_| DirectoryApiError::configuration(OPERATION))?;

    let response = client
        .get(&url)
        .bearer_auth(credential)
        .send()
        .await
        .map_err(|error| {
            DirectoryApiError::transport(OPERATION, &error)
        })?;

    if response.status() != reqwest::StatusCode::OK {
        return Err(DirectoryApiError::from_http_response(
            OPERATION,
            &response,
        ));
    }

    let mut response = response
        .json::<DirectoryResponse>()
        .await
        .map_err(|_| DirectoryApiError::invalid_response(OPERATION))?;

    response.refresh_seconds =
        normalize_directory_refresh_seconds(response.refresh_seconds);
    remove_current_device_from_directory(
        &mut response,
        state.device_id.as_deref(),
    );

    Ok(response)
}

#[derive(Serialize)]
struct ContactEmailUpdateRequest<'a> {
    contact_email: &'a str,
}

async fn put_contact_email_request(
    base_url: &str,
    state: &PersistedDirectoryAuth,
    contact_email: &str,
) -> DirectoryApiResult<()> {
    const OPERATION: &str = "directory contact email update";

    let credential = approved_credential(state, OPERATION)?;

    // Device-scoped endpoint: the device_id comes from the bearer
    // credential's own verified claims server-side, not a URL parameter -
    // a device can only ever update its own email this way.
    let url = directory_api_url(
        base_url,
        "/v1/device/contact-email",
        OPERATION,
    )?;

    let client =
        super::http_client::create_http_client_async_with_url_strict(
            &url,
        )
        .await
        .map_err(|_| DirectoryApiError::configuration(OPERATION))?;

    let request = ContactEmailUpdateRequest { contact_email };

    let response = client
        .put(&url)
        .bearer_auth(credential)
        .json(&request)
        .send()
        .await
        .map_err(|error| {
            DirectoryApiError::transport(OPERATION, &error)
        })?;

    if response.status() != reqwest::StatusCode::OK {
        return Err(DirectoryApiError::from_http_response(
            OPERATION,
            &response,
        ));
    }

    Ok(())
}

// Unlike friendly_name (which self-syncs on every heartbeat), the server's
// contact-email endpoint is a dedicated, audited PUT - it isn't part of the
// heartbeat payload, so a settings-page change needs to call it directly
// rather than just writing local config and waiting for the next heartbeat.
pub async fn update_contact_email_once(
    contact_email: &str,
) -> ResultType<()> {
    let base_url = managed_directory_base_url().ok_or_else(|| {
        anyhow!("Managed directory endpoint is not configured")
    })?;

    let state = read_persisted_auth()?.ok_or_else(|| {
        anyhow!("Device is not enrolled")
    })?;

    put_contact_email_request(base_url, &state, contact_email)
        .await
        .map_err(|error| anyhow!("{}", error))
}


#[derive(Deserialize)]
struct ManagedUpdateManifest {
    channel: String,
    build_number: u64,
    version: String,
    file_name: String,
    size: u64,
    sha256: String,
    signature: String,
    published_at: String,
    download_path: String,
}

pub struct ManagedUpdateCandidate {
    pub build_number: u64,
    pub version: String,
    pub file_path: PathBuf,
}

pub fn managed_build_number() -> u64 {
    option_env!("RUSTDESK_MANAGED_BUILD_NUMBER")
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

fn managed_update_channel() -> &'static str {
    option_env!("RUSTDESK_MANAGED_UPDATE_CHANNEL")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("stable")
}

fn managed_update_signing_public_key(
) -> ResultType<hbb_common::sodiumoxide::crypto::sign::PublicKey> {
    use hbb_common::sodiumoxide::crypto::sign;

    let encoded = option_env!("RUSTDESK_UPDATE_SIGNING_PUBLIC_KEY")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("Managed update signing key is not compiled in"))?;

    let raw = crate::decode64(encoded)
        .map_err(|_| anyhow!("Managed update signing key is invalid base64"))?;

    sign::PublicKey::from_slice(&raw)
        .ok_or_else(|| anyhow!("Managed update signing key has invalid length"))
}

fn managed_update_signed_payload(manifest: &ManagedUpdateManifest) -> String {
    format!(
        concat!(
            "rustdesk-managed-update-v1\n",
            "channel={}\n",
            "build_number={}\n",
            "version={}\n",
            "file_name={}\n",
            "size={}\n",
            "sha256={}\n",
            "published_at={}\n"
        ),
        manifest.channel,
        manifest.build_number,
        manifest.version,
        manifest.file_name,
        manifest.size,
        manifest.sha256,
        manifest.published_at,
    )
}

fn verify_managed_update_manifest(manifest: &ManagedUpdateManifest) -> ResultType<()> {
    use hbb_common::sodiumoxide::crypto::sign;

    if manifest.channel != managed_update_channel() {
        return Err(anyhow!("Managed update channel mismatch"));
    }
    if manifest.file_name.is_empty()
        || manifest.file_name.contains('/')
        || manifest.file_name.contains('\\')
        || !manifest.file_name.to_ascii_lowercase().ends_with(".exe")
    {
        return Err(anyhow!("Managed update file name is invalid"));
    }
    if manifest.download_path
        != format!("/v1/updates/releases/{}", manifest.file_name)
    {
        return Err(anyhow!("Managed update download path is invalid"));
    }
    if manifest.sha256.len() != 64
        || !manifest.sha256.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(anyhow!("Managed update SHA256 is invalid"));
    }

    let signature = crate::decode64(&manifest.signature)
        .map_err(|_| anyhow!("Managed update signature is invalid base64"))?;
    if signature.len() != 64 {
        return Err(anyhow!("Managed update signature has invalid length"));
    }

    let payload = managed_update_signed_payload(manifest).into_bytes();
    let mut signed = signature;
    signed.extend_from_slice(&payload);
    let public_key = managed_update_signing_public_key()?;
    let verified = sign::verify(&signed, &public_key)
        .map_err(|_| anyhow!("Managed update signature verification failed"))?;
    if verified != payload {
        return Err(anyhow!("Managed update signed payload mismatch"));
    }
    Ok(())
}

fn managed_update_temp_path(manifest: &ManagedUpdateManifest) -> PathBuf {
    std::env::temp_dir().join(format!(
        "rustdesk-managed-update-{}-{}",
        manifest.build_number, manifest.file_name
    ))
}

fn verify_managed_update_file(path: &PathBuf, manifest: &ManagedUpdateManifest) -> ResultType<()> {
    use sha2::{Digest, Sha256};

    let data = std::fs::read(path)?;
    if data.len() as u64 != manifest.size {
        return Err(anyhow!("Managed update file size mismatch"));
    }
    let digest = Sha256::digest(&data);
    if hex::encode(digest) != manifest.sha256.to_ascii_lowercase() {
        return Err(anyhow!("Managed update SHA256 verification failed"));
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
pub async fn managed_update_check_and_download(
) -> ResultType<Option<ManagedUpdateCandidate>> {
    let base_url = option_env!("RUSTDESK_MANAGED_DIRECTORY_BASE")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("Managed directory URL is not compiled in"))?;

    let state = read_persisted_auth()?
        .ok_or_else(|| anyhow!("Managed device is not enrolled"))?;
    if !matches!(state.status, PersistedEnrollmentStatus::Approved) {
        return Ok(None);
    }
    let credential = approved_credential(&state, "managed update")?;
    let channel = managed_update_channel();
    let latest_base = directory_api_url(base_url, "/v1/updates/latest", "managed update")?;
    let mut latest_url_parsed = url::Url::parse(&latest_base)
        .map_err(|_| anyhow!("Managed update URL is invalid"))?;
    latest_url_parsed
        .query_pairs_mut()
        .append_pair("channel", channel);
    let latest_url = latest_url_parsed.to_string();
    let client = super::http_client::create_http_client_async_with_url_strict(&latest_url)
        .await
        .map_err(|_| DirectoryApiError::configuration("managed update"))?;

    let response = client
        .get(&latest_url)
        .bearer_auth(credential)
        .send()
        .await
        .map_err(|error| DirectoryApiError::transport("managed update", &error))?;

    if response.status() == reqwest::StatusCode::NO_CONTENT {
        return Ok(None);
    }
    if response.status() != reqwest::StatusCode::OK {
        return Err(DirectoryApiError::from_http_response(
            "managed update",
            &response,
        )
        .into());
    }

    let manifest = response
        .json::<ManagedUpdateManifest>()
        .await
        .map_err(|_| DirectoryApiError::invalid_response("managed update"))?;
    verify_managed_update_manifest(&manifest)?;

    if manifest.build_number <= managed_build_number() {
        return Ok(None);
    }

    let file_path = managed_update_temp_path(&manifest);
    if file_path.exists() && verify_managed_update_file(&file_path, &manifest).is_ok() {
        return Ok(Some(ManagedUpdateCandidate {
            build_number: manifest.build_number,
            version: manifest.version,
            file_path,
        }));
    }
    if file_path.exists() {
        std::fs::remove_file(&file_path).ok();
    }

    let download_url = directory_api_url(
        base_url,
        &manifest.download_path,
        "managed update download",
    )?;
    let download_client =
        super::http_client::create_http_client_async_with_url_strict(&download_url)
            .await
            .map_err(|_| DirectoryApiError::configuration("managed update download"))?;
    let response = download_client
        .get(&download_url)
        .bearer_auth(credential)
        .send()
        .await
        .map_err(|error| DirectoryApiError::transport("managed update download", &error))?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(DirectoryApiError::from_http_response(
            "managed update download",
            &response,
        )
        .into());
    }
    let data = response
        .bytes()
        .await
        .map_err(|_| DirectoryApiError::invalid_response("managed update download"))?;
    if data.len() as u64 != manifest.size {
        return Err(anyhow!("Managed update download size mismatch"));
    }

    let tmp = file_path.with_extension("part");
    {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)?;
        file.write_all(&data)?;
        file.sync_all()?;
    }
    verify_managed_update_file(&tmp, &manifest)?;
    std::fs::rename(&tmp, &file_path)?;

    Ok(Some(ManagedUpdateCandidate {
        build_number: manifest.build_number,
        version: manifest.version,
        file_path,
    }))
}

fn normalize_directory_refresh_seconds(refresh_seconds: u64) -> u64 {
    if refresh_seconds == 0
        || refresh_seconds > DIRECTORY_REFRESH_MAX_SECONDS
    {
        DIRECTORY_REFRESH_MAX_SECONDS
    } else {
        refresh_seconds
    }
}

fn validate_relay_lease_response(
    state: &PersistedDirectoryAuth,
    response: &RelayLeaseResponse,
) -> DirectoryApiResult<()> {
    const OPERATION: &str = "directory relay lease";

    let expected_device_id = state
        .device_id
        .as_deref()
        .unwrap_or_default();

    let expected_serial = state
        .credential_serial
        .as_deref()
        .unwrap_or_default();

    if response.status != "authorized"
        || response.lease_id.trim().is_empty()
        || response.device_id != expected_device_id
        || response.credential_serial != expected_serial
        || response.renew_after_seconds == 0
        || response.expires_at.trim().is_empty()
        || !matches!(
            response.guard_mode.as_str(),
            "staged" | "enforced"
        )
    {
        return Err(
            DirectoryApiError::invalid_response(OPERATION)
        );
    }

    Ok(())
}

async fn post_relay_lease_request(
    base_url: &str,
    state: &PersistedDirectoryAuth,
) -> DirectoryApiResult<RelayLeaseResponse> {
    const OPERATION: &str = "directory relay lease";

    let credential = approved_credential(state, OPERATION)?;

    let relay_lease_base_url =
        managed_relay_lease_base_url(base_url);

    let url = directory_api_url(
        relay_lease_base_url,
        "/v1/device/relay-lease",
        OPERATION,
    )?;

    let client =
        super::http_client::create_http_client_async_with_url_strict(
            &url,
        )
        .await
        .map_err(|_| DirectoryApiError::configuration(OPERATION))?;

    let response = client
        .post(&url)
        .bearer_auth(credential)
        .send()
        .await
        .map_err(|error| {
            DirectoryApiError::transport(OPERATION, &error)
        })?;

    if response.status() != reqwest::StatusCode::OK {
        return Err(DirectoryApiError::from_http_response(
            OPERATION,
            &response,
        ));
    }

    let response = response
        .json::<RelayLeaseResponse>()
        .await
        .map_err(|_| DirectoryApiError::invalid_response(OPERATION))?;

    validate_relay_lease_response(state, &response)?;

    log::debug!(
        "Managed relay lease ok: rustdesk_server={} source_ip={} issued_at={} guard_mode={} firewall_sync_after_seconds={} guarded_tcp_ports={:?} guarded_udp_ports={:?}",
        response.rustdesk_server,
        response.source_ip,
        response.issued_at,
        response.guard_mode,
        response.firewall_sync_after_seconds,
        response.guarded_tcp_ports,
        response.guarded_udp_ports,
    );

    Ok(response)
}
const DIRECTORY_RETRY_BASE_SECONDS: u64 = 5;
const DIRECTORY_RETRY_MAX_SECONDS: u64 = 30;

fn directory_api_error_is_transient(
    error: &DirectoryApiError,
) -> bool {
    matches!(
        error.kind,
        DirectoryApiErrorKind::Timeout
            | DirectoryApiErrorKind::Connection
            | DirectoryApiErrorKind::Transport
            | DirectoryApiErrorKind::RateLimited
            | DirectoryApiErrorKind::Server
    )
}

fn directory_retry_delay_seconds(
    error: &DirectoryApiError,
    consecutive_failures: u32,
) -> Option<u64> {
    if !directory_api_error_is_transient(error) {
        return None;
    }

    // HTTP 429 must honor the server's Retry-After value.
    if error.kind == DirectoryApiErrorKind::RateLimited {
        if let Some(retry_after) = error.retry_after_seconds {
            return Some(retry_after.max(1));
        }
    }

    let multiplier =
        1u64 << consecutive_failures.min(6);

    Some(
        DIRECTORY_RETRY_BASE_SECONDS
            .saturating_mul(multiplier)
            .min(DIRECTORY_RETRY_MAX_SECONDS),
    )
}
fn pending_state_from_enrollment(
    identity: &DirectoryIdentity,
    response: EnrollmentResponse,
) -> ResultType<PersistedDirectoryAuth> {
    if response.result != "accepted_pending" {
        return Err(anyhow!(
            "Enrollment response returned unexpected result"
        ));
    }

    if response.device.status != "pending" {
        return Err(anyhow!(
            "Enrollment response returned unexpected device status"
        ));
    }

    if response.device.rustdesk_id != identity.rustdesk_id {
        return Err(anyhow!(
            "Enrollment response RustDesk ID does not match this device"
        ));
    }

    if response.device.hostname != identity.hostname {
        return Err(anyhow!(
            "Enrollment response hostname does not match this device"
        ));
    }

    if response.device.friendly_name.as_deref()
        != Some(identity.friendly_name.as_str())
    {
        return Err(anyhow!(
            "Enrollment response friendly name does not match this device"
        ));
    }

    if response.device.id.trim().is_empty() {
        return Err(anyhow!(
            "Enrollment response is missing device continuity ID"
        ));
    }

    if response.poll_token.is_empty() {
        return Err(anyhow!(
            "Enrollment response is missing continuity poll token"
        ));
    }

    Ok(PersistedDirectoryAuth {
        version: DIRECTORY_STATE_SCHEMA_VERSION,
        rustdesk_id: identity.rustdesk_id.clone(),
        device_public_key: identity.device_public_key.clone(),
        status: PersistedEnrollmentStatus::Pending,
        device_id: Some(response.device.id),
        enrollment_poll_token: Some(response.poll_token),
        poll_expires_at: Some(response.poll_expires_at),
        poll_after_seconds: Some(response.poll_after_seconds),
        device_credential: None,
        credential_serial: None,
    })
}
#[derive(Clone, Serialize)]
struct DirectoryIdentity {
    rustdesk_id: String,
    hostname: String,
    friendly_name: String,
    contact_email: String,
    device_public_key: String,
    client_version: String,
}

fn current_identity() -> ResultType<DirectoryIdentity> {
    let rustdesk_id = Config::get_id().trim().to_owned();
    if rustdesk_id.is_empty() {
        return Err(anyhow!("RustDesk ID is unavailable"));
    }

    let sysinfo = crate::get_sysinfo();
    let hostname = sysinfo["hostname"]
        .as_str()
        .unwrap_or_default()
        .trim()
        .to_owned();

    if hostname.is_empty() {
        return Err(anyhow!("Windows hostname is unavailable"));
    }

    let friendly_name = Config::get_option(keys::OPTION_PRESET_DEVICE_NAME)
        .trim()
        .to_owned();

    if friendly_name.is_empty() {
        return Err(anyhow!("Managed friendly name is not configured"));
    }

    // Not enforced as mandatory here: this identity is also resolved on every
    // heartbeat/status cycle for devices that enrolled before this option
    // existed, and a missing email must not break their ongoing presence.
    // Mandatory-at-collection is enforced instead at the installer's own
    // validation gate (install_install_me in flutter_ffi.rs).
    let contact_email = Config::get_option(keys::OPTION_PRESET_DEVICE_EMAIL)
        .trim()
        .to_owned();

    let public_key = Config::get_key_pair().1;
    if public_key.is_empty() {
        return Err(anyhow!("RustDesk device public key is unavailable"));
    }

    Ok(DirectoryIdentity {
        rustdesk_id,
        hostname,
        friendly_name,
        contact_email,
        device_public_key: crate::encode64(public_key),
        client_version: env!("CARGO_PKG_VERSION").to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_enrollment_omits_reenrollment_poll_token() {
        let request = EnrollmentRequest {
            enrollment_password: "test-password",
            rustdesk_id: "123456789",
            hostname: "test-host",
            friendly_name: Some("test-friendly"),
            contact_email: Some("test@example.com"),
            device_public_key: "test-public-key",
            client_version: Some("1.0.0"),
            reenrollment_poll_token: None,
        };

        let value = serde_json::to_value(&request).unwrap();

        assert!(
            value.get("reenrollment_poll_token").is_none()
        );
    }

    #[test]
    fn transient_errors_use_bounded_exponential_backoff() {
        let error = DirectoryApiError {
            operation: "test operation",
            kind: DirectoryApiErrorKind::Server,
            status: Some(503),
            retry_after_seconds: None,
        };

        assert_eq!(
            directory_retry_delay_seconds(&error, 0),
            Some(5)
        );
        assert_eq!(
            directory_retry_delay_seconds(&error, 1),
            Some(10)
        );
        assert_eq!(
            directory_retry_delay_seconds(&error, 6),
            Some(30)
        );

        let rate_limited = DirectoryApiError {
            operation: "test operation",
            kind: DirectoryApiErrorKind::RateLimited,
            status: Some(429),
            retry_after_seconds: Some(60),
        };

        assert_eq!(
            directory_retry_delay_seconds(&rate_limited, 0),
            Some(60)
        );

        let unauthorized = DirectoryApiError {
            operation: "test operation",
            kind: DirectoryApiErrorKind::Unauthorized,
            status: Some(401),
            retry_after_seconds: None,
        };

        assert_eq!(
            directory_retry_delay_seconds(&unauthorized, 0),
            None
        );
    }
    #[test]
    fn relay_lease_must_match_device_and_credential() {
        let state = PersistedDirectoryAuth {
            version: DIRECTORY_STATE_SCHEMA_VERSION,
            rustdesk_id: "123456789".to_owned(),
            device_public_key: "test-public-key".to_owned(),
            status: PersistedEnrollmentStatus::Approved,
            device_id: Some("test-device-id".to_owned()),
            enrollment_poll_token: Some("test-poll-token".to_owned()),
            poll_expires_at: None,
            poll_after_seconds: Some(10),
            device_credential: Some("test-credential".to_owned()),
            credential_serial: Some("test-serial".to_owned()),
        };

        let good = RelayLeaseResponse {
            status: "authorized".to_owned(),
            lease_id: "test-lease".to_owned(),
            device_id: "test-device-id".to_owned(),
            credential_serial: "test-serial".to_owned(),
            source_ip: "192.0.2.1".to_owned(),
            issued_at: "test-issued".to_owned(),
            expires_at: "test-expires".to_owned(),
            renew_after_seconds: 240,
            firewall_sync_after_seconds: 3,
            guard_mode: "staged".to_owned(),
            rustdesk_server: "example.invalid".to_owned(),
            guarded_tcp_ports: vec![21115, 21116, 21117],
            guarded_udp_ports: vec![21116],
        };

        assert!(
            validate_relay_lease_response(&state, &good).is_ok()
        );

        let mut bad = good;
        bad.credential_serial = "wrong-serial".to_owned();

        assert!(
            validate_relay_lease_response(&state, &bad).is_err()
        );
    }
    #[test]
    fn protected_routes_require_approved_credential() {
        let pending = PersistedDirectoryAuth {
            version: DIRECTORY_STATE_SCHEMA_VERSION,
            rustdesk_id: "123456789".to_owned(),
            device_public_key: "test-public-key".to_owned(),
            status: PersistedEnrollmentStatus::Pending,
            device_id: Some("test-device-id".to_owned()),
            enrollment_poll_token: Some("test-poll-token".to_owned()),
            poll_expires_at: None,
            poll_after_seconds: Some(10),
            device_credential: None,
            credential_serial: None,
        };

        assert!(
            approved_credential(&pending, "test operation").is_err()
        );

        let mut approved = pending;
        approved.status = PersistedEnrollmentStatus::Approved;
        approved.device_credential =
            Some("test-credential".to_owned());
        approved.credential_serial =
            Some("test-serial".to_owned());

        assert_eq!(
            approved_credential(
                &approved,
                "test operation"
            )
            .unwrap(),
            "test-credential"
        );
    }

    #[test]
    fn heartbeat_requires_approved_response() {
        let good = HeartbeatResponse {
            status: "ok".to_owned(),
            server_time: "test-time".to_owned(),
            device_status: "approved".to_owned(),
            client_version: Some("1.0.0".to_owned()),
            client_settings: None,
        };

        assert!(validate_heartbeat_response(&good).is_ok());

        let bad = HeartbeatResponse {
            status: "ok".to_owned(),
            server_time: "test-time".to_owned(),
            device_status: "blocked".to_owned(),
            client_version: Some("1.0.0".to_owned()),
            client_settings: None,
        };

        assert!(validate_heartbeat_response(&bad).is_err());
    }
    #[test]
    fn directory_api_requires_https() {
        assert!(
            directory_api_url(
                "http://example.invalid",
                "/v1/enrollment/devices",
                "test operation",
            )
            .is_err()
        );

        assert!(
            directory_api_url(
                "https://example.invalid",
                "/v1/enrollment/devices",
                "test operation",
            )
            .is_ok()
        );
    }
    #[test]
    fn restored_approved_state_requires_validation_before_ready() {
        assert_eq!(
            runtime_state_from_persisted_status(
                &PersistedEnrollmentStatus::Approved
            ),
            DirectoryState::Unavailable
        );

        assert_eq!(
            runtime_state_from_persisted_status(
                &PersistedEnrollmentStatus::Pending
            ),
            DirectoryState::Pending
        );

        assert_eq!(
            runtime_state_from_persisted_status(
                &PersistedEnrollmentStatus::Blocked
            ),
            DirectoryState::Blocked
        );
    }
    #[test]
    fn blocked_status_removes_credential_but_preserves_continuity() {
        let state = PersistedDirectoryAuth {
            version: DIRECTORY_STATE_SCHEMA_VERSION,
            rustdesk_id: "123456789".to_owned(),
            device_public_key: "test-device-public-key".to_owned(),
            status: PersistedEnrollmentStatus::Approved,
            device_id: Some("test-device-id".to_owned()),
            enrollment_poll_token: Some("test-poll-token".to_owned()),
            poll_expires_at: Some("test-expiry".to_owned()),
            poll_after_seconds: Some(10),
            device_credential: Some("test-credential".to_owned()),
            credential_serial: Some("test-serial".to_owned()),
        };

        let response = EnrollmentStatusResponse {
            device_id: "test-device-id".to_owned(),
            rustdesk_id: "123456789".to_owned(),
            hostname: "test-host".to_owned(),
            friendly_name: Some("test-friendly".to_owned()),
            status: "blocked".to_owned(),
            status_reason: Some("test-reason".to_owned()),
            status_changed_at: Some("test-time".to_owned()),
            poll_expires_at: Some("new-expiry".to_owned()),
            poll_after_seconds: 10,
            credential: None,
            credential_serial: None,
            client_settings: None,
            reenrollment_requested: false,
            reenrollment_request_id: None,
            reenrollment_request_expires_at: None,
            reenrollment_authorized: false,
            reenrollment_authorization_expires_at: None,
        };

        let updated =
            state_from_enrollment_status(state, response).unwrap();

        assert!(matches!(
            updated.status,
            PersistedEnrollmentStatus::Blocked
        ));
        assert_eq!(
            updated.enrollment_poll_token.as_deref(),
            Some("test-poll-token")
        );
        assert!(updated.device_credential.is_none());
        assert!(updated.credential_serial.is_none());
    }
    #[test]
    fn approved_status_preserves_continuity() {
        let state = PersistedDirectoryAuth {
            version: DIRECTORY_STATE_SCHEMA_VERSION,
            rustdesk_id: "123456789".to_owned(),
            device_public_key: "test-device-public-key".to_owned(),
            status: PersistedEnrollmentStatus::Pending,
            device_id: Some("test-device-id".to_owned()),
            enrollment_poll_token: Some("test-poll-token".to_owned()),
            poll_expires_at: Some("test-expiry".to_owned()),
            poll_after_seconds: Some(10),
            device_credential: None,
            credential_serial: None,
        };

        let response = EnrollmentStatusResponse {
            device_id: "test-device-id".to_owned(),
            rustdesk_id: "123456789".to_owned(),
            hostname: "test-host".to_owned(),
            friendly_name: Some("test-friendly".to_owned()),
            status: "approved".to_owned(),
            status_reason: None,
            status_changed_at: Some("test-time".to_owned()),
            poll_expires_at: Some("new-expiry".to_owned()),
            poll_after_seconds: 10,
            credential: Some("test-credential".to_owned()),
            credential_serial: Some("test-serial".to_owned()),
            client_settings: None,
            reenrollment_requested: false,
            reenrollment_request_id: None,
            reenrollment_request_expires_at: None,
            reenrollment_authorized: false,
            reenrollment_authorization_expires_at: None,
        };

        let updated =
            state_from_enrollment_status(state, response).unwrap();

        assert!(matches!(
            updated.status,
            PersistedEnrollmentStatus::Approved
        ));
        assert_eq!(
            updated.enrollment_poll_token.as_deref(),
            Some("test-poll-token")
        );
        assert_eq!(
            updated.device_credential.as_deref(),
            Some("test-credential")
        );
        assert_eq!(
            updated.credential_serial.as_deref(),
            Some("test-serial")
        );
    }
    #[test]
    fn directory_snapshot_excludes_current_device_uuid() {
        let mut response = DirectoryResponse {
            instance_id: "instance".to_owned(),
            generated_at: "2026-08-08T00:00:00Z".to_owned(),
            refresh_seconds: 15,
            devices: vec![
                DirectoryDevice {
                    id: "device-self".to_owned(),
                    rustdesk_id: "111111111".to_owned(),
                    display_name: "Self".to_owned(),
                    hostname: "self-host".to_owned(),
                    last_ip: None,
                    last_seen_at: None,
                    online: true,
                },
                DirectoryDevice {
                    id: "device-peer".to_owned(),
                    rustdesk_id: "222222222".to_owned(),
                    display_name: "Peer".to_owned(),
                    hostname: "peer-host".to_owned(),
                    last_ip: None,
                    last_seen_at: None,
                    online: true,
                },
            ],
            client_settings: None,
            server_stats: None,
        };

        remove_current_device_from_directory(&mut response, Some("device-self"));

        assert_eq!(response.devices.len(), 1);
        assert_eq!(response.devices[0].id, "device-peer");
    }

    #[test]
    fn managed_poll_intervals_are_capped_at_fifteen_seconds() {
        assert_eq!(DIRECTORY_HEARTBEAT_SECONDS, 15);
        assert_eq!(DIRECTORY_REFRESH_MAX_SECONDS, 15);

        assert_eq!(normalize_directory_refresh_seconds(0), 15);
        assert_eq!(normalize_directory_refresh_seconds(1), 1);
        assert_eq!(normalize_directory_refresh_seconds(10), 10);
        assert_eq!(normalize_directory_refresh_seconds(15), 15);
        assert_eq!(normalize_directory_refresh_seconds(16), 15);
        assert_eq!(normalize_directory_refresh_seconds(300), 15);
    }

    #[test]
    fn pending_auth_dpapi_round_trip() {
        let state = PersistedDirectoryAuth {
            version: DIRECTORY_STATE_SCHEMA_VERSION,
            rustdesk_id: "123456789".to_owned(),
            device_public_key: "test-device-public-key".to_owned(),
            status: PersistedEnrollmentStatus::Pending,
            device_id: Some("test-device-id".to_owned()),
            enrollment_poll_token: Some("test-poll-token".to_owned()),
            poll_expires_at: Some("2026-08-07T18:00:00Z".to_owned()),
            poll_after_seconds: Some(10),
            device_credential: None,
            credential_serial: None,
        };

        let plaintext = serde_json::to_vec(&state).unwrap();
        let protected = protect_persisted_auth(&state).unwrap();

        assert_ne!(protected, plaintext);

        let restored = unprotect_persisted_auth(&protected).unwrap();

        assert_eq!(restored.version, DIRECTORY_STATE_SCHEMA_VERSION);
        assert_eq!(restored.rustdesk_id, "123456789");
        assert_eq!(
            restored.device_public_key,
            "test-device-public-key"
        );
        assert!(matches!(
            restored.status,
            PersistedEnrollmentStatus::Pending
        ));
                assert!(restored.device_credential.is_none());
        assert!(restored.credential_serial.is_none());

        assert_eq!(restored.device_id.as_deref(), Some("test-device-id"));
        assert_eq!(
            restored.enrollment_poll_token.as_deref(),
            Some("test-poll-token")
        );
        assert_eq!(
            restored.poll_expires_at.as_deref(),
            Some("2026-08-07T18:00:00Z")
        );
        assert_eq!(restored.poll_after_seconds, Some(10));
    }
}
const DIRECTORY_HEARTBEAT_SECONDS: u64 = 15;
const DIRECTORY_REFRESH_MAX_SECONDS: u64 = 15;
const DIRECTORY_IDLE_SECONDS: u64 = 300;

fn managed_directory_base_url() -> Option<&'static str> {
    option_env!("RUSTDESK_MANAGED_DIRECTORY_BASE")
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn managed_relay_lease_base_url(fallback: &str) -> &str {
    match option_env!("RUSTDESK_MANAGED_RELAY_LEASE_BASE")
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(value) => value,
        None => fallback,
    }
}

struct ApprovedSchedule {
    next_heartbeat: Instant,
    next_directory: Instant,
    next_relay_lease: Instant,
}

impl ApprovedSchedule {
    fn due_now() -> Self {
        let now = Instant::now();

        Self {
            next_heartbeat: now,
            next_directory: now,
            next_relay_lease: now,
        }
    }

    fn next_delay(&self) -> Duration {
        let now = Instant::now();

        let next = [
            self.next_heartbeat,
            self.next_directory,
            self.next_relay_lease,
        ]
        .into_iter()
        .min()
        .unwrap_or(now);

        next.saturating_duration_since(now)
            .max(Duration::from_secs(1))
    }
}

fn worker_error_delay(
    error: &DirectoryApiError,
    consecutive_failures: &mut u32,
) -> Duration {
    let delay = directory_retry_delay_seconds(
        error,
        *consecutive_failures,
    );

    if let Some(seconds) = delay {
        *consecutive_failures =
            consecutive_failures.saturating_add(1);

        Duration::from_secs(seconds.max(1))
    } else {
        Duration::from_secs(DIRECTORY_IDLE_SECONDS)
    }
}

async fn run_pending_cycle(
    base_url: &str,
    state: PersistedDirectoryAuth,
    consecutive_failures: &mut u32,
) -> Duration {
    match post_enrollment_status_request(base_url, &state).await {
        Ok(response) => {
            management_snapshot_from_status(&response);
            match persist_enrollment_status(state, response) {
                Ok(updated) => {
                    *consecutive_failures = 0;

                    match updated.status {
                        PersistedEnrollmentStatus::Pending => {
                            Duration::from_secs(
                                updated
                                    .poll_after_seconds
                                    .unwrap_or(10)
                                    .max(1),
                            )
                        }

                        PersistedEnrollmentStatus::Approved => {
                            Duration::from_secs(1)
                        }

                        PersistedEnrollmentStatus::Denied
                        | PersistedEnrollmentStatus::Blocked
                        | PersistedEnrollmentStatus::Revoked => {
                            Duration::from_secs(
                                DIRECTORY_IDLE_SECONDS,
                            )
                        }

                        PersistedEnrollmentStatus::NotEnrolled => {
                            Duration::from_secs(
                                DIRECTORY_IDLE_SECONDS,
                            )
                        }
                    }
                }

                Err(_) => {
                    set_state(DirectoryState::Unavailable);

                    Duration::from_secs(
                        DIRECTORY_IDLE_SECONDS,
                    )
                }
            }
        }

        Err(error) => {
            log::warn!("{}", error);

            set_state(DirectoryState::Unavailable);

            worker_error_delay(
                &error,
                consecutive_failures,
            )
        }
    }
}

async fn run_terminal_cycle(
    base_url: &str,
    state: PersistedDirectoryAuth,
    consecutive_failures: &mut u32,
) -> Duration {
    match post_enrollment_status_request(base_url, &state).await {
        Ok(response) => {
            let authorized = response.reenrollment_authorized;
            management_snapshot_from_status(&response);

            let updated = match persist_enrollment_status(state, response) {
                Ok(updated) => updated,
                Err(error) => {
                    log::warn!("Failed to persist terminal directory status: {}", error);
                    set_state(DirectoryState::Unavailable);
                    return Duration::from_secs(DIRECTORY_RETRY_BASE_SECONDS);
                }
            };
            *consecutive_failures = 0;

            if authorized
                && matches!(
                    updated.status,
                    PersistedEnrollmentStatus::Denied
                        | PersistedEnrollmentStatus::Blocked
                        | PersistedEnrollmentStatus::Revoked
                )
            {
                let identity = match current_identity() {
                    Ok(identity) => identity,
                    Err(error) => {
                        log::warn!("Managed re-enrollment identity is unavailable: {}", error);
                        return Duration::from_secs(15);
                    }
                };

                match post_reenrollment_complete(base_url, &updated, &identity).await {
                    Ok(response) => {
                        if let Err(error) = persist_pending_enrollment(&identity, response) {
                            log::warn!("Failed to persist managed re-enrollment: {}", error);
                            return Duration::from_secs(15);
                        }
                        log::info!("Managed re-enrollment returned device to Pending approval");
                        return Duration::from_secs(1);
                    }
                    Err(error) => {
                        log::warn!("Managed re-enrollment recovery is not ready: {}", error);
                        return worker_error_delay(&error, consecutive_failures)
                            .min(Duration::from_secs(30));
                    }
                }
            }

            Duration::from_secs(
                updated.poll_after_seconds.unwrap_or(15).max(5).min(30),
            )
        }
        Err(error) => {
            log::warn!("{}", error);
            set_state(runtime_state_from_persisted_status(&state.status));
            worker_error_delay(&error, consecutive_failures)
                .min(Duration::from_secs(30))
        }
    }
}

async fn resolve_approved_unauthorized(
    base_url: &str,
    consecutive_failures: &mut u32,
) -> Duration {
    let current = match read_persisted_auth() {
        Ok(Some(state)) => state,

        _ => {
            set_state(DirectoryState::Unavailable);

            return Duration::from_secs(
                DIRECTORY_IDLE_SECONDS,
            );
        }
    };

    let response =
        match post_enrollment_status_request(
            base_url,
            &current,
        )
        .await
        {
            Ok(response) => response,

            Err(error) => {
                log::warn!("{}", error);
                set_state(DirectoryState::Unavailable);

                return worker_error_delay(
                    &error,
                    consecutive_failures,
                );
            }
        };

    let rejected_credential = current.device_credential.clone();

    let updated =
        match state_from_enrollment_status(
            current,
            response,
        ) {
            Ok(updated) => updated,

            Err(_) => {
                set_state(DirectoryState::Unavailable);

                return Duration::from_secs(
                    DIRECTORY_IDLE_SECONDS,
                );
            }
        };

    match &updated.status {
        PersistedEnrollmentStatus::Denied
        | PersistedEnrollmentStatus::Blocked
        | PersistedEnrollmentStatus::Revoked => {
            if write_persisted_auth(&updated).is_err() {
                set_state(DirectoryState::Unavailable);

                return Duration::from_secs(
                    DIRECTORY_IDLE_SECONDS,
                );
            }

            set_state(
                runtime_state_from_persisted_status(
                    &updated.status,
                ),
            );

            *consecutive_failures = 0;

            Duration::from_secs(
                DIRECTORY_IDLE_SECONDS,
            )
        }

        PersistedEnrollmentStatus::Approved => {
            let replacement_credential =
                updated.device_credential.as_deref().unwrap_or_default();

            let credential_changed =
                !replacement_credential.is_empty()
                    && Some(replacement_credential)
                        != rejected_credential.as_deref();

            if credential_changed {
                match write_persisted_auth(&updated) {
                    Ok(()) => {
                        // Keep runtime state Unavailable until the
                        // replacement Bearer passes /v1/device/me.
                        set_state(DirectoryState::Unavailable);
                        *consecutive_failures = 0;

                        return Duration::from_secs(1);
                    }

                    Err(error) => {
                        log::warn!(
                            "Failed to persist recovered directory credential: {}",
                            error
                        );
                    }
                }
            }

            // Continuity still says Approved, but it returned the same
            // Bearer that was just rejected. Do not resurrect it or
            // create a tight authentication retry loop.
            set_state(DirectoryState::Unavailable);
            *consecutive_failures = 0;

            Duration::from_secs(
                DIRECTORY_RETRY_MAX_SECONDS,
            )
        }

        PersistedEnrollmentStatus::Pending
        | PersistedEnrollmentStatus::NotEnrolled => {
            set_state(DirectoryState::Unavailable);
            *consecutive_failures = 0;

            Duration::from_secs(
                DIRECTORY_IDLE_SECONDS,
            )
        }
    }
}

async fn approved_request_error_delay(
    base_url: &str,
    error: &DirectoryApiError,
    consecutive_failures: &mut u32,
) -> Duration {
    log::warn!("{}", error);
    set_state(DirectoryState::Unavailable);

    if matches!(
        error.kind,
        DirectoryApiErrorKind::Unauthorized
            | DirectoryApiErrorKind::Forbidden
    ) {
        return resolve_approved_unauthorized(
            base_url,
            consecutive_failures,
        )
        .await;
    }

    worker_error_delay(
        error,
        consecutive_failures,
    )
}

async fn run_approved_cycle(
    base_url: &str,
    state: &PersistedDirectoryAuth,
    identity: &DirectoryIdentity,
    schedule: &mut ApprovedSchedule,
    consecutive_failures: &mut u32,
) -> Duration {
    // A restored Approved credential starts as Unavailable.
    // It may become Ready only after /v1/device/me confirms it.
    if get_state() != DirectoryState::Ready {
        match get_device_me_request(base_url, state).await {
            Ok(_) => {
                *consecutive_failures = 0;
                set_state(DirectoryState::Ready);
            }

            Err(error) => {
                return approved_request_error_delay(
                    base_url,
                    &error,
                    consecutive_failures,
                )
                .await;
            }
        }
    }

    let now = Instant::now();

    if now >= schedule.next_heartbeat {
        match post_heartbeat_request(
            base_url,
            state,
            identity,
        )
        .await
        {
            Ok(_) => {
                *consecutive_failures = 0;

                schedule.next_heartbeat =
                    Instant::now()
                        + Duration::from_secs(
                            DIRECTORY_HEARTBEAT_SECONDS,
                        );
            }

            Err(error) => {
                return approved_request_error_delay(
                    base_url,
                    &error,
                    consecutive_failures,
                )
                .await;
            }
        }
    }

    let now = Instant::now();

    if now >= schedule.next_directory {
        match get_directory_request(base_url, state).await {
            Ok(response) => {
                *consecutive_failures = 0;
                store_directory_snapshot(&response);

                schedule.next_directory =
                    Instant::now()
                        + Duration::from_secs(
                            response.refresh_seconds.max(1),
                        );
            }

            Err(error) => {
                return approved_request_error_delay(
                    base_url,
                    &error,
                    consecutive_failures,
                )
                .await;
            }
        }
    }

    let now = Instant::now();

    if now >= schedule.next_relay_lease {
        match post_relay_lease_request(base_url, state).await {
            Ok(response) => {
                *consecutive_failures = 0;

                schedule.next_relay_lease =
                    Instant::now()
                        + Duration::from_secs(
                            response
                                .renew_after_seconds
                                .max(1),
                        );
            }

            Err(error) => {
                return approved_request_error_delay(
                    base_url,
                    &error,
                    consecutive_failures,
                )
                .await;
            }
        }
    }

    set_state(DirectoryState::Ready);
    schedule.next_delay()
}
pub async fn enroll_once(
    enrollment_password: &str,
) -> ResultType<()> {
    if enrollment_password.is_empty() {
        return Err(anyhow!(
            "Directory enrollment password is required"
        ));
    }

    let base_url = managed_directory_base_url().ok_or_else(|| {
        anyhow!("Managed directory endpoint is not configured")
    })?;

    let identity = current_identity()?;
    let existing = read_persisted_auth()?;

    let previous_runtime_state = existing
        .as_ref()
        .map(|state| runtime_state_from_persisted_status(&state.status))
        .unwrap_or(DirectoryState::NotEnrolled);

    let reenrollment_poll_token = match existing.as_ref() {
        None => None,

        Some(state) => match state.status {
            PersistedEnrollmentStatus::NotEnrolled => None,

            PersistedEnrollmentStatus::Pending => {
                return Err(anyhow!(
                    "Directory enrollment is already pending"
                ));
            }

            PersistedEnrollmentStatus::Approved => {
                return Err(anyhow!(
                    "Device is already enrolled"
                ));
            }

            PersistedEnrollmentStatus::Denied
            | PersistedEnrollmentStatus::Blocked
            | PersistedEnrollmentStatus::Revoked => state
                .enrollment_poll_token
                .as_deref(),
        },
    };

    set_state(DirectoryState::Enrolling);

    let response = match post_enrollment_request(
        base_url,
        &identity,
        enrollment_password,
        reenrollment_poll_token,
    )
    .await
    {
        Ok(response) => response,

        Err(error) => {
            let failure_state =
                if directory_api_error_is_transient(&error) {
                    DirectoryState::Unavailable
                } else {
                    previous_runtime_state
                };

            set_state(failure_state);

            return Err(anyhow!("{}", error));
        }
    };

    persist_pending_enrollment(
        &identity,
        response,
    )?;

    Ok(())
}
fn restore_local_directory_state() -> ResultType<()> {
    let state = match read_persisted_auth()? {
        Some(state) => state,
        None => {
            set_state(DirectoryState::NotEnrolled);
            return Ok(());
        }
    };

    let runtime_state =
        runtime_state_from_persisted_status(&state.status);

    set_state(runtime_state);
    Ok(())
}
pub fn start() {
    START_DIRECTORY_WORKER.call_once(|| {
        match std::thread::Builder::new()
            .name("rustdesk-directory".to_owned())
            .spawn(|| {
                if let Err(error) = run() {
                    log::error!("Directory worker stopped: {error:?}");
                }
            })
        {
            Ok(_) => {}
            Err(error) => {
                log::error!("Failed to start directory worker: {error}");
            }
        }
    });
}

#[tokio::main(flavor = "current_thread")]
async fn run() -> ResultType<()> {
    log::info!("Directory worker started");

    restore_local_directory_state()?;

    let base_url = match managed_directory_base_url() {
        Some(value) => value,
        None => {
            log::info!(
                "Managed directory endpoint is not configured"
            );

            loop {
                tokio::time::sleep(
                    Duration::from_secs(
                        DIRECTORY_IDLE_SECONDS,
                    ),
                )
                .await;
            }
        }
    };

    let mut consecutive_failures = 0u32;
    let mut approved_schedule =
        ApprovedSchedule::due_now();

    loop {
        let state = match read_persisted_auth() {
            Ok(Some(state)) => state,

            Ok(None) => {
                set_state(DirectoryState::NotEnrolled);

                tokio::time::sleep(
                    Duration::from_secs(5),
                )
                .await;

                continue;
            }

            Err(_) => {
                set_state(DirectoryState::Unavailable);

                tokio::time::sleep(
                    Duration::from_secs(
                        DIRECTORY_IDLE_SECONDS,
                    ),
                )
                .await;

                continue;
            }
        };

        let delay = match state.status {
            PersistedEnrollmentStatus::Pending => {
                approved_schedule =
                    ApprovedSchedule::due_now();

                run_pending_cycle(
                    base_url,
                    state,
                    &mut consecutive_failures,
                )
                .await
            }

            PersistedEnrollmentStatus::Approved => {
                let identity = match current_identity() {
                    Ok(identity) => identity,

                    Err(_) => {
                        set_state(
                            DirectoryState::Unavailable,
                        );

                        tokio::time::sleep(
                            Duration::from_secs(
                                DIRECTORY_IDLE_SECONDS,
                            ),
                        )
                        .await;

                        continue;
                    }
                };

                run_approved_cycle(
                    base_url,
                    &state,
                    &identity,
                    &mut approved_schedule,
                    &mut consecutive_failures,
                )
                .await
            }

            PersistedEnrollmentStatus::Denied
            | PersistedEnrollmentStatus::Blocked
            | PersistedEnrollmentStatus::Revoked => {
                approved_schedule = ApprovedSchedule::due_now();
                run_terminal_cycle(
                    base_url,
                    state,
                    &mut consecutive_failures,
                )
                .await
            }

            PersistedEnrollmentStatus::NotEnrolled => {
                consecutive_failures = 0;
                set_state(DirectoryState::NotEnrolled);

                Duration::from_secs(5)
            }
        };

        tokio::time::sleep(delay).await;
    }
}
