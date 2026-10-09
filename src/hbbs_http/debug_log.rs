// Periodic diagnostic log upload to RDS - see the RDS-side counterpart at
// device_logs.py (POST /v1/device/log-upload). Deliberately self-contained:
// takes plain primitives (base_url/credential/client_version) rather than
// reaching into directory_enrollment.rs's private auth-state types, so this
// module has no coupling to that file's enrollment state machine beyond the
// one-line hook that calls it.
use crate::managed_sealed::SendSealed;
use hbb_common::{log, ResultType};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::HashMap,
    fs,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant, SystemTime},
};

const LOG_UPLOAD_PATH: &str = "/v1/device/log-upload";
// Hourly. Each upload carries only what was logged since the last one (see
// UPLOAD_STATE_FILE), so this is a small delta, not a repeated tail. A device
// that was offline is simply overdue and uploads on its first worker cycle
// after reconnecting; a heartbeat-carried request (device_heartbeat's
// debug_log_requested flag) bypasses this via `force` for an immediate one.
const MIN_UPLOAD_INTERVAL: Duration = Duration::from_secs(60 * 60);
// Per source. All four sources (GUI, RustDrop, --server, diag trace) together
// must stay under the server's 5_000_000-character log_content cap
// (device_logs.py's LogUploadRequest): an oversized upload is rejected every
// time and, since offsets only advance on success, would never recover.
const MAX_LOG_BYTES: u64 = 1024 * 1024;
const MARKER_FILE: &str = "debug_log_last_upload.marker";
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(120);
// How far into each live log file has already been uploaded. The log files
// are never deleted: the GUI/RustDrop/--server processes hold them open for
// days, and deleting one only unlinks it - the process keeps writing into
// the nameless file until it restarts or the log rotates at midnight, so
// everything logged in between was lost (machines asleep at midnight stopped
// uploading entirely).
const UPLOAD_STATE_FILE: &str = "debug_log_upload_state.json";
// The first bytes of a file identify it across uploads; a rotated log starts
// with different content even if Windows hands back the same name and
// creation time.
const HEAD_FINGERPRINT_BYTES: u64 = 512;
// The GUI/RustDrop sources are keyed per path (see collect_source), so the
// saved state gains an entry for every Windows user whose log was ever the
// newest one.
const MAX_TRACKED_SOURCES: usize = 16;
// See try_lock_upload. Never deleted: a holder may have it open.
const UPLOAD_LOCK_FILE: &str = "debug_log_upload.lock";
// How long --upload-debug-log waits on an upload already in flight before
// reporting it; the worker never waits.
const MANUAL_LOCK_WAIT: Duration = Duration::from_secs(15);

// In-process backstop, independent of the marker file below. Build 18
// shipped with a real incident: mark_uploaded()'s write silently failed
// (swallowed by `let _ =`) on affected machines, so should_upload()'s
// "unreadable marker means due now" fallback kept firing on every single
// worker-cycle tick for days - one device alone uploaded ~40GB before this
// was caught. This in-memory gate can't be defeated by any filesystem
// issue: even if mark_uploaded() fails every time, a single process can
// never attempt more than one real upload per MIN_UPLOAD_INTERVAL. The
// marker file is kept too, since it's still needed for the cross-restart
// case the in-memory gate can't cover.
static LAST_UPLOAD_ATTEMPT: Mutex<Option<Instant>> = Mutex::new(None);

// A heartbeat keeps re-requesting a log until one lands, so a forced upload
// that keeps failing would otherwise be retried on every worker cycle.
const FORCED_MIN_INTERVAL: Duration = Duration::from_secs(60);

fn in_memory_gate_allows(force: bool) -> bool {
    let mut guard = LAST_UPLOAD_ATTEMPT.lock().unwrap();
    let now = Instant::now();
    let min_interval = if force {
        FORCED_MIN_INTERVAL
    } else {
        MIN_UPLOAD_INTERVAL
    };
    let allowed = guard
        .map(|last| now.duration_since(last) >= min_interval)
        .unwrap_or(true);
    if allowed {
        *guard = Some(now);
    }
    allowed
}

// Only for an attempt that never reached RDS (connection refused / DNS /
// unreachable): nothing was sent, so the next worker cycle may retry instead
// of waiting out MIN_UPLOAD_INTERVAL. Never used once a request got a
// response, so a server-side failure can't turn into a resend loop.
fn release_in_memory_gate() {
    *LAST_UPLOAD_ATTEMPT.lock().unwrap() = None;
}

fn is_connect_error(error: &hbb_common::anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<reqwest::Error>()
            .map(|e| e.is_connect())
            .unwrap_or(false)
    })
}

#[derive(Serialize, Deserialize, Clone, Default)]
struct SourceProgress {
    path: String,
    offset: u64,
    head_len: u64,
    head: String,
}

fn upload_state_path() -> ResultType<PathBuf> {
    Ok(crate::platform::get_program_data_dir()?
        .join("RustDeskManaged")
        .join(UPLOAD_STATE_FILE))
}

fn load_upload_state() -> HashMap<String, SourceProgress> {
    upload_state_path()
        .ok()
        .and_then(|path| fs::read_to_string(path).ok())
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

fn save_upload_state(state: &HashMap<String, SourceProgress>) {
    let result = upload_state_path().and_then(|path| {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, serde_json::to_vec(state)?)?;
        Ok(())
    });
    if let Err(error) = result {
        // Next upload just resends from the previous offsets - duplicated
        // content, bounded by MAX_LOG_BYTES, never lost content.
        log::warn!("debug log upload: failed to save upload state: {}", error);
    }
}

fn source_key(kind: &str, path: &str) -> String {
    format!("{}:{}", kind, path)
}

// Build 26 saved one entry per kind ("gui"); move each to its path's key so
// the first upload after updating doesn't resend what it already covered.
fn rekey_legacy_entries(state: HashMap<String, SourceProgress>) -> HashMap<String, SourceProgress> {
    state
        .into_iter()
        .map(|(key, progress)| {
            if key.contains(':') {
                (key, progress)
            } else {
                (source_key(&key, &progress.path), progress)
            }
        })
        .collect()
}

// Drops entries whose log is gone (profile deleted) and, past
// MAX_TRACKED_SOURCES, the least recently written. The sources just read are
// the newest of their kind, so they are not the ones dropped.
fn prune_upload_state(state: &mut HashMap<String, SourceProgress>) {
    let mut by_age = Vec::new();
    state.retain(|key, progress| {
        match fs::metadata(&progress.path).and_then(|meta| meta.modified()) {
            Ok(modified) => {
                by_age.push((modified, key.clone()));
                true
            }
            Err(_) => false,
        }
    });
    if by_age.len() > MAX_TRACKED_SOURCES {
        by_age.sort_by(|a, b| b.0.cmp(&a.0));
        for (_, key) in &by_age[MAX_TRACKED_SOURCES..] {
            state.remove(key);
        }
    }
}

fn read_head(file: &mut fs::File, len: u64) -> ResultType<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut buf = Vec::new();
    file.by_ref().take(len).read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

// Reads `file` from `start` to `len`, keeping only the newest `cap` bytes and
// ending at the last complete line so a line being written right now is sent
// whole next time. Returns the bytes and the offset they end at.
fn read_complete_lines(file: &mut fs::File, start: u64, len: u64, cap: u64) -> ResultType<(Vec<u8>, u64)> {
    let start = start.max(len.saturating_sub(cap));
    file.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::new();
    file.by_ref().take(len - start).read_to_end(&mut buf)?;
    buf.truncate(buf.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1));
    let end = start + buf.len() as u64;
    Ok((buf, end))
}

// flexi_logger renames rustdesk_rCURRENT.log on every process start as well as
// at midnight/16 MiB, so the lines written between the last upload and a
// restart (often the ones leading up to a crash) are in a rotated sibling
// file. Finds it by its head fingerprint and returns what was never sent.
fn read_rotated_remainder(prev: &SourceProgress) -> Option<String> {
    let dir = Path::new(&prev.path).parent()?;
    let mut candidates: Vec<(SystemTime, PathBuf)> = fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().map_or(false, |ext| ext == "log"))
        .filter_map(|path| Some((fs::metadata(&path).ok()?.modified().ok()?, path)))
        .collect();
    candidates.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, path) in candidates.into_iter().take(10) {
        let Ok(mut file) = fs::File::open(&path) else {
            continue;
        };
        let Ok(len) = file.metadata().map(|meta| meta.len()) else {
            continue;
        };
        if len < prev.offset
            || read_head(&mut file, prev.head_len).ok().as_deref() != Some(prev.head.as_str())
        {
            continue;
        }
        let (buf, _) = read_complete_lines(&mut file, prev.offset, len, MAX_LOG_BYTES / 2).ok()?;
        if buf.is_empty() {
            return None;
        }
        return Some(format!(
            "=== unsent remainder of {} ===\n{}=== current log file ===\n",
            path.display(),
            String::from_utf8_lossy(&buf)
        ));
    }
    None
}

// Reads what was appended to `path` since `prev`. A different file than last
// time (rotation, restart) starts from its beginning, after whatever the
// previous file still had unsent.
fn read_new_content(path: &Path, prev: Option<&SourceProgress>) -> ResultType<(String, SourceProgress)> {
    let mut file = fs::File::open(path)?;
    let len = file.metadata()?.len();
    let path_text = path.display().to_string();
    let mut start = 0;
    let mut text = String::new();
    if let Some(prev) = prev {
        if prev.path == path_text
            && prev.offset <= len
            && read_head(&mut file, prev.head_len)? == prev.head
        {
            start = prev.offset;
        } else if let Some(earlier) = read_rotated_remainder(prev) {
            text = earlier;
        }
    }
    let cap = MAX_LOG_BYTES.saturating_sub(text.len() as u64);
    let (buf, end) = read_complete_lines(&mut file, start, len, cap)?;
    text.push_str(&String::from_utf8_lossy(&buf));
    let head_len = HEAD_FINGERPRINT_BYTES.min(len);
    let head = read_head(&mut file, head_len)?;
    Ok((
        text,
        SourceProgress {
            path: path_text,
            offset: end,
            head_len,
            head,
        },
    ))
}

// One upload source: reads its new content, leaving `state` untouched if
// the file is missing or unreadable this cycle. Keyed by path, not just
// `kind`: the GUI and RustDrop logs are per Windows user, and one entry per
// kind made every switch of active user resend up to MAX_LOG_BYTES of that
// user's already-uploaded log.
fn collect_source(
    kind: &str,
    path: Option<PathBuf>,
    state: &HashMap<String, SourceProgress>,
    next_state: &mut HashMap<String, SourceProgress>,
) -> Option<(PathBuf, String)> {
    let path = path?;
    let key = source_key(kind, &path.display().to_string());
    match read_new_content(&path, state.get(&key)) {
        Ok((content, progress)) => {
            next_state.insert(key, progress);
            Some((path, content))
        }
        Err(error) => {
            log::debug!("debug log upload: could not read {}: {}", path.display(), error);
            None
        }
    }
}

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
    let path = match marker_path() {
        Ok(path) => path,
        Err(error) => {
            log::warn!("debug log upload: could not resolve marker path: {}", error);
            return;
        }
    };
    if let Some(parent) = path.parent() {
        if let Err(error) = fs::create_dir_all(parent) {
            log::warn!(
                "debug log upload: could not create marker directory {}: {}",
                parent.display(),
                error
            );
        }
    }
    // Real content (not an empty file) so should_upload()'s mtime check has
    // something to point to if this ever needs inspecting by hand again.
    let stamp = chrono::Utc::now().to_rfc3339();
    if let Err(error) = fs::write(&path, stamp.as_bytes()) {
        // Loud on failure: a silently-lost write here previously meant
        // should_upload()'s "unreadable marker" fallback kept saying "due
        // now" forever, since fs::write's error was discarded with no
        // trace of it anywhere. The in-memory gate in maybe_upload() below
        // is what actually bounds the damage if this keeps failing; this
        // log line is what lets it get diagnosed and fixed for real.
        log::warn!(
            "debug log upload: failed to write marker file {}: {} - hourly throttle may not persist across restarts until this is fixed",
            path.display(),
            error
        );
        return;
    }
    // Confirms the write actually landed rather than being silently
    // swallowed by something outside this process (AV/EDR folder
    // protection has been observed to report success while discarding the
    // write) - build 25's marker sat stale for three weeks through
    // multiple successful uploads with no error ever logged, which is only
    // possible if fs::write's own Ok(()) can't be trusted on its own here.
    match fs::metadata(&path).and_then(|meta| meta.modified()) {
        Ok(modified) if SystemTime::now().duration_since(modified).unwrap_or_default() < Duration::from_secs(60) => {
            log::debug!("debug log upload: marker updated ({})", stamp);
        }
        Ok(modified) => {
            log::warn!(
                "debug log upload: marker write returned Ok but mtime is stale ({:?} old) - something outside this process is discarding the write to {}",
                SystemTime::now().duration_since(modified).unwrap_or_default(),
                path.display()
            );
        }
        Err(error) => {
            log::warn!(
                "debug log upload: marker write returned Ok but re-reading it failed: {}",
                error
            );
        }
    }
}

// This runs inside the SYSTEM-context managed-directory worker (see
// directory_enrollment.rs's "Machine-scoped managed-directory state belongs
// to the Windows service" comment), so Config::log_path() would resolve to
// SYSTEM's own profile rather than any real user's. The log worth
// uploading is whichever interactive session actually saw activity - found
// by scanning real user profiles directly (the same class of workaround
// already used elsewhere in this codebase for SYSTEM-vs-user profile
// resolution) and picking the most recently written one.
// `subdir` matches hbb_common::init_log()'s own behavior: a process launched
// with a `--something` argument (core_main.rs derives this from args[0])
// gets its own `log/something/` subdirectory rather than sharing the plain
// `log/rustdesk_rCURRENT.log` file - confirmed on disk (log/cm/, log/tray/,
// log/whiteboard/, log/rustdrop/ all exist as real, separate subdirectories
// on this machine). None finds the plain top-level file; Some(name) finds
// that specific mode's own log.
#[cfg(windows)]
fn find_log_file(subdir: Option<&str>) -> Option<PathBuf> {
    let app_name = crate::get_app_name();
    let users_dir = Path::new(r"C:\Users");

    fs::read_dir(users_dir)
        .ok()?
        .flatten()
        .filter_map(|entry| {
            let mut log_dir = entry
                .path()
                .join("AppData")
                .join("Roaming")
                .join(&app_name)
                .join("log");
            if let Some(subdir) = subdir {
                log_dir = log_dir.join(subdir);
            }
            let log_path = log_dir.join("rustdesk_rCURRENT.log");
            let modified = fs::metadata(&log_path).ok()?.modified().ok()?;
            Some((modified, log_path))
        })
        .max_by_key(|(modified, _)| *modified)
        .map(|(_, path)| path)
}

#[cfg(windows)]
fn find_active_log_file() -> Option<PathBuf> {
    find_log_file(None)
}

// RustDrop's own UI process (--rustdrop, a separate top-level app from
// --server - see rustdrop_service.rs's doc comment on why) logs to its own
// subdirectory like every other named launch mode, so it needs its own scan
// here or its Send/Accept diagnostics would never make it into an upload at
// all despite riding the exact same log::* macros as everything else.
#[cfg(windows)]
fn find_rustdrop_log_file() -> Option<PathBuf> {
    find_log_file(Some("rustdrop"))
}

// --server (remote sessions, managed chat, whiteboard) runs as SYSTEM like
// this worker, so its log lives under this process's own log_path() (the
// LocalService profile), in the `server` subdirectory init_log() gives it.
#[cfg(windows)]
fn find_server_log_file() -> Option<PathBuf> {
    let path = hbb_common::config::Config::log_path()
        .join("server")
        .join("rustdesk_rCURRENT.log");
    path.exists().then_some(path)
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

// Display adapters Windows reports as present, each tagged dedicated /
// integrated for the Client Management details popup. SetupAPI + the
// adapter's driver key rather than DXGI, because this runs in the SYSTEM
// service (session 0). Microsoft-provided adapters (Basic Display, Remote
// Display, Hyper-V video) are skipped - they are not real GPUs.
#[cfg(windows)]
fn gather_gpus() -> Vec<serde_json::Value> {
    use std::ptr::null_mut;
    use winapi::{
        shared::{devguid::GUID_DEVCLASS_DISPLAY, minwindef::DWORD},
        um::{
            setupapi::{
                SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo, SetupDiGetClassDevsW,
                SetupDiGetDeviceRegistryPropertyW, HDEVINFO, SP_DEVINFO_DATA,
            },
            winnt::HANDLE,
        },
    };
    use winreg::{enums::HKEY_LOCAL_MACHINE, RegKey};

    const DIGCF_PRESENT: DWORD = 0x00000002;
    const SPDRP_DEVICEDESC: DWORD = 0x00000000;
    const SPDRP_HARDWAREID: DWORD = 0x00000001;
    const SPDRP_DRIVER: DWORD = 0x00000009;
    const SPDRP_BUSNUMBER: DWORD = 0x00000015;
    const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;

    // First string of a REG_SZ / REG_MULTI_SZ device property.
    fn property(set: HDEVINFO, data: &mut SP_DEVINFO_DATA, prop: DWORD) -> Option<String> {
        let mut buf = [0u16; 512];
        let ok = unsafe {
            SetupDiGetDeviceRegistryPropertyW(
                set,
                data,
                prop,
                null_mut(),
                buf.as_mut_ptr() as *mut u8,
                (buf.len() * 2) as DWORD,
                null_mut(),
            )
        };
        if ok == 0 {
            return None;
        }
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        let value = String::from_utf16_lossy(&buf[..end]).trim().to_owned();
        (!value.is_empty()).then_some(value)
    }

    let set = unsafe {
        SetupDiGetClassDevsW(&GUID_DEVCLASS_DISPLAY, null_mut(), null_mut(), DIGCF_PRESENT)
    };
    if set == INVALID_HANDLE_VALUE || set.is_null() {
        return Vec::new();
    }
    let class_root = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(r"SYSTEM\CurrentControlSet\Control\Class")
        .ok();
    let mut gpus = Vec::new();
    let mut index = 0;
    loop {
        let mut data: SP_DEVINFO_DATA = unsafe { std::mem::zeroed() };
        data.cbSize = std::mem::size_of::<SP_DEVINFO_DATA>() as DWORD;
        if unsafe { SetupDiEnumDeviceInfo(set, index, &mut data) } == 0 {
            break;
        }
        index += 1;
        let Some(name) = property(set, &mut data, SPDRP_DEVICEDESC) else {
            continue;
        };
        let driver_key = property(set, &mut data, SPDRP_DRIVER)
            .and_then(|path| class_root.as_ref()?.open_subkey(path).ok());
        let driver_value = |value_name: &str| -> Option<String> {
            driver_key
                .as_ref()?
                .get_value::<String, _>(value_name)
                .ok()
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        };
        if driver_value("ProviderName").as_deref() == Some("Microsoft") {
            continue;
        }
        // Bytes of dedicated video memory; the qw value is the accurate one
        // above 4 GB, the older DWORD/binary value is the fallback.
        let memory_bytes = driver_key.as_ref().and_then(|key| {
            ["HardwareInformation.qwMemorySize", "HardwareInformation.MemorySize"]
                .iter()
                .find_map(|value_name| {
                    let raw = key.get_raw_value(value_name).ok()?;
                    match raw.bytes.len() {
                        8 => Some(u64::from_le_bytes(raw.bytes[..8].try_into().ok()?)),
                        4 => Some(u32::from_le_bytes(raw.bytes[..4].try_into().ok()?) as u64),
                        _ => None,
                    }
                })
                .filter(|bytes| *bytes > 0)
        });
        let hardware_id = property(set, &mut data, SPDRP_HARDWAREID)
            .unwrap_or_default()
            .to_ascii_uppercase();
        // Software-enumerated display drivers (ROOT\..., e.g. a projector's
        // indirect-display driver) are not GPUs either.
        if hardware_id.starts_with("ROOT\\") {
            continue;
        }
        let vendor_id = hardware_id
            .find("VEN_")
            .map(|start| {
                hardware_id[start + 4..]
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric())
                    .collect::<String>()
            })
            .unwrap_or_default();
        let mut bus: DWORD = 0;
        let bus_number = (unsafe {
            SetupDiGetDeviceRegistryPropertyW(
                set,
                &mut data,
                SPDRP_BUSNUMBER,
                null_mut(),
                &mut bus as *mut DWORD as *mut u8,
                std::mem::size_of::<DWORD>() as DWORD,
                null_mut(),
            )
        } != 0)
            .then_some(bus);
        gpus.push(json!({
            "name": name,
            "vendor": gpu_vendor_name(&vendor_id),
            "kind": gpu_kind(&vendor_id, &name, bus_number, memory_bytes),
            "memory_bytes": memory_bytes,
            "driver_version": driver_value("DriverVersion"),
        }));
    }
    unsafe { SetupDiDestroyDeviceInfoList(set) };
    gpus
}

#[cfg(windows)]
fn gpu_vendor_name(vendor_id: &str) -> String {
    match vendor_id {
        "10DE" => "NVIDIA",
        "8086" => "Intel",
        "1002" | "1022" => "AMD",
        "5143" | "QCOM" => "Qualcomm",
        "1AF4" | "1B36" => "Red Hat (virtual)",
        "15AD" => "VMware (virtual)",
        "1234" => "QEMU (virtual)",
        other => return other.to_owned(),
    }
    .to_owned()
}

// No Windows API marks a GPU integrated vs dedicated directly. NVIDIA is
// always discrete and Qualcomm always integrated. Intel's integrated GPU is
// always on PCI bus 0 while its discrete Arc cards sit behind a PCIe bridge -
// names can't tell them apart (the Panther Lake iGPU is "Arc B390", the
// discrete card "Arc B580"). AMD discrete cards are RX / Pro / FirePro; its
// APUs are "Radeon(TM) Graphics" / "Radeon 780M Graphics".
#[cfg(windows)]
fn gpu_kind(
    vendor_id: &str,
    name: &str,
    bus_number: Option<u32>,
    memory_bytes: Option<u64>,
) -> &'static str {
    let upper = name.to_ascii_uppercase();
    match vendor_id {
        "10DE" => "dedicated",
        "5143" | "QCOM" => "integrated",
        "1AF4" | "1B36" | "15AD" | "1234" => "virtual",
        "8086" => match bus_number {
            Some(bus) if bus > 0 => "dedicated",
            _ => "integrated",
        },
        "1002" | "1022" => {
            if upper.contains(" RX ")
                || upper.contains("RADEON PRO")
                || upper.contains("FIREPRO")
                || upper.contains("RADEON VII")
            {
                "dedicated"
            } else {
                "integrated"
            }
        }
        _ => match memory_bytes {
            Some(bytes) if bytes >= 2 * 1024 * 1024 * 1024 => "dedicated",
            _ => "unknown",
        },
    }
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
// GPUs come from SetupAPI's display device class (see gather_gpus()).
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
        info["gpus"] = json!(gather_gpus());
    }
    // Android releases are numbered apart from the managed build (see installed_release).
    #[cfg(target_os = "android")]
    {
        info["android_release"] = json!(crate::managed_android::installed_release());
    }

    if let Some((total, available)) = system_drive_space() {
        info["system_drive_total_bytes"] = json!(total);
        info["system_drive_available_bytes"] = json!(available);
    }

    info
}

// diag_write() (server/input_service.rs, managed builds only) traces the
// service watchdog's repairs and the managed silent-upgrade path into a
// separate plain file, and the AIO launcher (libs/portable) appends its own
// steps to the same file - kept as its own thing rather than folded into
// log::* because those call sites (the early --service-watchdog CLI dispatch,
// core_main.rs's silent-upgrade path, the launcher) run before this build's
// own logger is reliably initialized or have none, the same reason this
// module's own --upload-debug-log test path needed plain eprintln! rather
// than log:: to see anything.
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

async fn upload(
    base_url: &str,
    credential: &str,
    client_version: &str,
    force: bool,
) -> ResultType<()> {
    #[cfg(windows)]
    let (log_path, rustdrop_log_path, server_log_path) = (
        find_active_log_file(),
        find_rustdrop_log_file(),
        find_server_log_file(),
    );
    #[cfg(target_os = "android")]
    let (log_path, rustdrop_log_path, server_log_path): (
        Option<PathBuf>,
        Option<PathBuf>,
        Option<PathBuf>,
    ) = (crate::managed_android::active_log_file(), None, None);
    #[cfg(not(any(windows, target_os = "android")))]
    let (log_path, rustdrop_log_path, server_log_path): (
        Option<PathBuf>,
        Option<PathBuf>,
        Option<PathBuf>,
    ) = (None, None, None);

    // Each source is tracked independently: RustDrop and --server are their
    // own processes on their own schedules, so any one of them can have new
    // content while the others are quiet.
    let state = rekey_legacy_entries(load_upload_state());
    let mut next_state = state.clone();
    let main = collect_source("gui", log_path, &state, &mut next_state);
    let rustdrop = collect_source("rustdrop", rustdrop_log_path, &state, &mut next_state);
    let server = collect_source("server", server_log_path, &state, &mut next_state);

    let has_new = |source: &Option<(PathBuf, String)>| {
        source
            .as_ref()
            .map(|(_, content)| !content.trim().is_empty())
            .unwrap_or(false)
    };
    let nothing_new = !has_new(&main) && !has_new(&rustdrop) && !has_new(&server);
    if nothing_new && !force {
        log::debug!("debug log upload: no new log content from any source, skipping");
        return Ok(());
    }

    let mut log_content = main.map(|(_, content)| content).unwrap_or_default();
    // RDS only clears an on-demand request when a log arrives, and rejects an
    // empty one, so a forced upload always sends something.
    if nothing_new {
        log_content.push_str("(no new log lines since the previous upload)\n");
    }

    // Unlike the log files above, this file is never rotated by
    // the app itself (diag_write() only ever appends) - without deleting it
    // here on a successful upload, every future upload re-sends the same
    // growing history forever, crowding out whatever's actually new. Same
    // tail-not-truncate-from-start tradeoff as the other two sources: a
    // file that grew past MAX_LOG_BYTES between uploads loses its untailed
    // older portion, which was already true for main_log_content/
    // rustdrop_log_content and is accepted there for the same reason.
    #[cfg(windows)]
    let had_diag_content = if let Some(diag) = read_diag_file_tail() {
        log_content.push_str("\n\n=== Watchdog / silent-upgrade / launcher diagnostic trace (");
        log_content.push_str(DIAG_FILE_PATH);
        log_content.push_str(") ===\n");
        log_content.push_str(&diag);
        true
    } else {
        false
    };
    #[cfg(not(windows))]
    #[allow(unused_variables)]
    let had_diag_content = false;

    for (label, source) in [("RustDrop log", &rustdrop), ("--server log", &server)] {
        if let Some((path, content)) = source {
            if !content.trim().is_empty() {
                log_content.push_str(&format!("\n\n=== {} ({}) ===\n", label, path.display()));
                log_content.push_str(content);
            }
        }
    }

    // Postgres text can't hold NUL; one stray byte would fail every upload
    // until it scrolled out of the window.
    log_content.retain(|c| c != '\0');

    let url = format!("{}{}", base_url.trim_end_matches('/'), LOG_UPLOAD_PATH);
    let client = super::create_http_client_async_with_url_strict(&url).await?;

    let request = LogUploadRequest {
        log_content,
        client_version: client_version.to_owned(),
        hardware_info: {
            #[allow(unused_mut)]
            let mut info = gather_hardware_info();
            #[cfg(windows)]
            if let Ok(security) =
                hbb_common::tokio::task::spawn_blocking(crate::platform::windows::security_info).await
            {
                info["security"] = security;
            }
            #[cfg(target_os = "android")]
            if let Ok(security) =
                hbb_common::tokio::task::spawn_blocking(crate::managed_android::security_info).await
            {
                info["security"] = security;
            }
            info
        },
    };

    let response = client
        .post(&url)
        .bearer_auth(credential)
        .json(&request)
        // The client default (20s, sized for small API calls) would time out
        // a few-MB upload on a slow uplink every hour, forever.
        .timeout(UPLOAD_TIMEOUT)
        .send_sealed()
        .await?;

    if response.status() != reqwest::StatusCode::OK {
        return Err(hbb_common::anyhow::anyhow!(
            "debug log upload failed: HTTP {}",
            response.status()
        ));
    }

    log::info!("debug log uploaded ({} bytes)", request.log_content.len());

    // Best-effort only: a failed attempt here just means this content is
    // included again next cycle, never lost.
    #[cfg(windows)]
    if had_diag_content {
        let _ = fs::remove_file(DIAG_FILE_PATH);
    }
    // The live log files are never deleted: their writers hold them open, so
    // deleting one only unlinks it while the logger keeps writing into the
    // nameless file until restart/rotation, and that output is lost. The
    // saved offsets stop the same lines being sent twice instead.
    prune_upload_state(&mut next_state);
    save_upload_state(&next_state);

    Ok(())
}

// Held across collect -> upload -> save-state. --upload-debug-log runs in its
// own process alongside the service's worker; unserialized, both read the
// same saved offsets, send the same lines, and whichever saves last can move
// an offset backwards. An exclusively-opened handle rather than a file that
// merely exists, so Windows releases it when the holder exits or crashes and
// a dead holder can't wedge uploads. Ok(None) means another process holds it.
fn try_lock_upload() -> ResultType<Option<fs::File>> {
    let path = crate::platform::get_program_data_dir()?
        .join("RustDeskManaged")
        .join(UPLOAD_LOCK_FILE);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true);
    // Only Windows ships; elsewhere the open always succeeds and nothing is
    // serialized.
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0);
    }
    match options.open(&path) {
        Ok(file) => Ok(Some(file)),
        #[cfg(windows)]
        Err(error)
            if error.raw_os_error()
                == Some(winapi::shared::winerror::ERROR_SHARING_VIOLATION as i32) =>
        {
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}

// The process core_main.rs starts for --upload-debug-log never runs the
// worker, so this tells its call apart from a heartbeat-forced worker cycle
// (both pass `force`) without changing maybe_upload's signature.
fn is_manual_upload_process() -> bool {
    std::env::args_os().skip(1).any(|arg| arg == "--upload-debug-log")
}

// None: another process is mid-upload. Some(None): the lock couldn't be
// opened at all (permissions, AV) - carry on unserialized, as before the lock
// existed, rather than stopping this machine's uploads for good.
async fn lock_upload(wait: bool) -> Option<Option<fs::File>> {
    let deadline = Instant::now() + MANUAL_LOCK_WAIT;
    loop {
        match try_lock_upload() {
            Ok(Some(lock)) => return Some(Some(lock)),
            Ok(None) if wait && Instant::now() < deadline => {
                hbb_common::tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Ok(None) => return None,
            Err(error) => {
                log::warn!(
                    "debug log upload: could not open upload lock, continuing without it: {}",
                    error
                );
                return Some(None);
            }
        }
    }
}

/// Called once per managed-directory worker cycle (see run_approved_cycle
/// in directory_enrollment.rs). Cheap to call every cycle - the marker-file
/// mtime check below is the only work done when nothing is actually due.
/// `force` is true when the last heartbeat's response asked for a fresh
/// log (Brad/Claude requesting one on-demand rather than waiting for the
/// hourly cadence) - a missed/failed attempt here just tries again next
/// cycle, same as the hourly case, so a dropped request isn't lost.
pub async fn maybe_upload(base_url: &str, credential: &str, client_version: &str, force: bool) {
    if !should_upload(force) {
        return;
    }
    // Taken before the in-memory gate so a skipped cycle doesn't also cost
    // this process its next hour, and held until return, through
    // mark_uploaded(). A busy worker just skips: the other process's upload
    // carries the same log, and a heartbeat request is re-sent until one lands.
    let manual = is_manual_upload_process();
    let Some(_lock) = lock_upload(manual).await else {
        if manual {
            eprintln!("Another debug log upload is already in progress and will carry the current log - not uploading again.");
        } else {
            log::info!("debug log upload: another process is uploading, skipping this cycle");
        }
        return;
    };
    // Second, independent gate - see LAST_UPLOAD_ATTEMPT's own comment for
    // why this exists alongside (not instead of) the marker-file check
    // above. Order matters: only consumes the in-memory gate once the
    // marker file has already said an upload is actually due, so a normal
    // hourly upload still only advances this once an hour too.
    if !in_memory_gate_allows(force) {
        return;
    }

    match upload(base_url, credential, client_version, force).await {
        Ok(()) => mark_uploaded(),
        Err(error) => {
            log::warn!("debug log upload failed: {}", error);
            // RDS unreachable (device offline/asleep): retry on the next
            // worker cycle instead of waiting out the in-memory gate.
            if is_connect_error(&error) {
                release_in_memory_gate();
            }
        }
    }
}
