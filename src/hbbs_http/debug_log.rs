// Daily diagnostic log upload to RDS - see the RDS-side counterpart at
// device_logs.py (POST /v1/device/log-upload). Deliberately self-contained:
// takes plain primitives (base_url/credential/client_version) rather than
// reaching into directory_enrollment.rs's private auth-state types, so this
// module has no coupling to that file's enrollment state machine beyond the
// one-line hook that calls it.
use hbb_common::{log, ResultType};
use serde::Serialize;
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

const LOG_UPLOAD_PATH: &str = "/v1/device/log-upload";
// Once a day is the baseline cadence; a heartbeat-carried request (see
// device_heartbeat's debug_log_requested flag) bypasses this via `force`.
const MIN_UPLOAD_INTERVAL: Duration = Duration::from_secs(24 * 3600);
// Matches the server's own 5_000_000-byte cap (device_logs.py's
// LogUploadRequest) with room to spare for the JSON envelope around it.
const MAX_LOG_BYTES: u64 = 2 * 1024 * 1024;
const MARKER_FILE: &str = "debug_log_last_upload.marker";

#[derive(Serialize)]
struct LogUploadRequest {
    log_content: String,
    client_version: String,
    hardware_info: serde_json::Value,
}

fn marker_path() -> ResultType<PathBuf> {
    Ok(crate::platform::get_program_data_dir()?
        .join("RustDeskManaged")
        .join(MARKER_FILE))
}

// Missing/unreadable marker (including "never uploaded yet") means due now.
fn should_upload(force: bool) -> bool {
    if force {
        return true;
    }
    let Ok(path) = marker_path() else {
        return true;
    };
    let Ok(modified) = fs::metadata(&path).and_then(|meta| meta.modified()) else {
        return true;
    };
    SystemTime::now()
        .duration_since(modified)
        .map(|elapsed| elapsed >= MIN_UPLOAD_INTERVAL)
        .unwrap_or(true)
}

fn mark_uploaded() {
    let Ok(path) = marker_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(&path, b"");
}

// This runs inside the SYSTEM-context managed-directory worker (see
// directory_enrollment.rs's "Machine-scoped managed-directory state belongs
// to the Windows service" comment), so Config::log_path() would resolve to
// SYSTEM's own profile rather than any real user's. The log worth
// uploading is whichever interactive session actually saw activity - found
// by scanning real user profiles directly (the same class of workaround
// already used elsewhere in this codebase for SYSTEM-vs-user profile
// resolution) and picking the most recently written one.
#[cfg(windows)]
fn find_active_log_file() -> Option<PathBuf> {
    let app_name = crate::get_app_name();
    let users_dir = Path::new(r"C:\Users");

    fs::read_dir(users_dir)
        .ok()?
        .flatten()
        .filter_map(|entry| {
            let log_path = entry
                .path()
                .join("AppData")
                .join("Roaming")
                .join(&app_name)
                .join("log")
                .join("rustdesk_rCURRENT.log");
            let modified = fs::metadata(&log_path).ok()?.modified().ok()?;
            Some((modified, log_path))
        })
        .max_by_key(|(modified, _)| *modified)
        .map(|(_, path)| path)
}

// Tail rather than truncate-from-start: the most recent activity is what a
// support conversation actually needs, and this also bounds a pathological
// case where a session ran for a very long time between uploads.
fn read_log_tail(path: &Path, max_bytes: u64) -> ResultType<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = fs::File::open(path)?;
    let len = file.metadata()?.len();
    if len > max_bytes {
        file.seek(SeekFrom::Start(len - max_bytes))?;
    }
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(windows)]
fn registry_bios_string(value_name: &str) -> Option<String> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    let key = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(r"HARDWARE\DESCRIPTION\System\BIOS")
        .ok()?;
    key.get_value::<String, _>(value_name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn system_drive_space() -> Option<(u64, u64)> {
    use hbb_common::sysinfo::Disks;
    let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_owned());
    let mount_point = format!("{}\\", system_drive);
    let disks = Disks::new_with_refreshed_list();
    disks
        .list()
        .iter()
        .find(|disk| disk.mount_point().to_string_lossy().eq_ignore_ascii_case(&mount_point))
        .map(|disk| (disk.total_space(), disk.available_space()))
}

// Builds on common::get_sysinfo() (cpu/memory/os/hostname, already used
// elsewhere for the stock RustDesk sysinfo report) rather than duplicating
// it, adding only what that function doesn't cover and what's cheaply
// available without a new dependency (registry via the already-present
// `winreg` crate, disk/uptime via the already-present `sysinfo` crate).
// GPU model is deliberately not included yet - the registry path for a
// friendly adapter name needs a DEVICEMAP indirection this pass didn't
// take on; worth adding later given this fork's hwcodec/vram build.
fn gather_hardware_info() -> serde_json::Value {
    let mut info = crate::get_sysinfo();

    info["architecture"] = json!(std::env::consts::ARCH);
    info["client_reported_time"] = json!(chrono::Utc::now().to_rfc3339());

    // Which managed build this device is actually running, plus whether its
    // own background update-checker has already noticed something newer -
    // both already tracked for the "Update Available" UI (see
    // managed_build_number/pending_managed_update in directory_enrollment.rs),
    // just not previously surfaced anywhere Brad/Claude could see per-device.
    // A device sitting on an old build while pending_managed_update is empty
    // means it hasn't even checked yet (or the check itself is failing) -
    // different from one that's seen and is stuck applying it.
    info["managed_build_number"] = json!(super::directory_enrollment::managed_build_number());
    info["pending_managed_update"] = match super::directory_enrollment::pending_managed_update() {
        Some((build_number, version)) => json!({ "build_number": build_number, "version": version }),
        None => serde_json::Value::Null,
    };

    #[cfg(windows)]
    {
        if let Some(manufacturer) = registry_bios_string("SystemManufacturer") {
            info["manufacturer"] = json!(manufacturer);
        }
        if let Some(model) = registry_bios_string("SystemProductName") {
            info["model"] = json!(model);
        }
        info["uptime_seconds"] = json!(hbb_common::sysinfo::System::new().uptime());
    }

    if let Some((total, available)) = system_drive_space() {
        info["system_drive_total_bytes"] = json!(total);
        info["system_drive_available_bytes"] = json!(available);
    }

    info
}

// diag_write() (server/input_service.rs) traces SAS/Ctrl+Alt+Del handling,
// the silent-upgrade path, and the service watchdog into a separate plain
// file - kept as its own thing rather than folded into log::* because
// several of its call sites (the early --service-watchdog CLI dispatch,
// core_main.rs's silent-upgrade path) run before this build's own logger is
// reliably initialized, the same reason this module's own --upload-debug-log
// test path needed plain eprintln! rather than log:: to see anything.
// Nobody was actually collecting this file though, so fold it into the
// upload instead of leaving it as a separate manual-check artifact.
#[cfg(windows)]
const DIAG_FILE_PATH: &str = r"C:\ProgramData\rustdesk-ctrlaltdel-diag.txt";

#[cfg(windows)]
fn read_diag_file_tail() -> Option<String> {
    let path = Path::new(DIAG_FILE_PATH);
    if !path.exists() {
        return None;
    }
    read_log_tail(path, MAX_LOG_BYTES).ok().filter(|s| !s.trim().is_empty())
}

async fn upload(base_url: &str, credential: &str, client_version: &str) -> ResultType<()> {
    #[cfg(windows)]
    let log_path = find_active_log_file();
    #[cfg(not(windows))]
    let log_path: Option<PathBuf> = None;

    let Some(log_path) = log_path else {
        log::debug!("debug log upload: no active user log file found, skipping");
        return Ok(());
    };

    let mut log_content = read_log_tail(&log_path, MAX_LOG_BYTES)?;
    if log_content.trim().is_empty() {
        return Ok(());
    }

    #[cfg(windows)]
    if let Some(diag) = read_diag_file_tail() {
        log_content.push_str("\n\n=== Ctrl+Alt+Del / SAS / watchdog diagnostic trace (");
        log_content.push_str(DIAG_FILE_PATH);
        log_content.push_str(") ===\n");
        log_content.push_str(&diag);
    }

    let url = format!("{}{}", base_url.trim_end_matches('/'), LOG_UPLOAD_PATH);
    let client = super::create_http_client_async_with_url_strict(&url).await?;

    let request = LogUploadRequest {
        log_content,
        client_version: client_version.to_owned(),
        hardware_info: gather_hardware_info(),
    };

    let response = client
        .post(&url)
        .bearer_auth(credential)
        .json(&request)
        .send()
        .await?;

    if response.status() != reqwest::StatusCode::OK {
        return Err(hbb_common::anyhow::anyhow!(
            "debug log upload failed: HTTP {}",
            response.status()
        ));
    }

    log::info!("debug log uploaded ({} bytes)", request.log_content.len());
    Ok(())
}

/// Called once per managed-directory worker cycle (see run_approved_cycle
/// in directory_enrollment.rs). Cheap to call every cycle - the marker-file
/// mtime check below is the only work done when nothing is actually due.
/// `force` is true when the last heartbeat's response asked for a fresh
/// log (Brad/Claude requesting one on-demand rather than waiting for the
/// daily cadence) - a missed/failed attempt here just tries again next
/// cycle, same as the daily case, so a dropped request isn't lost.
pub async fn maybe_upload(base_url: &str, credential: &str, client_version: &str, force: bool) {
    if !should_upload(force) {
        return;
    }

    match upload(base_url, credential, client_version).await {
        Ok(()) => mark_uploaded(),
        Err(error) => log::warn!("debug log upload failed: {}", error),
    }
}
