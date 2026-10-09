//! Managed RDC on Android. The app is one process with no service, so what the Windows service
//! and --server do runs here: a log file (uploaded with debug logs, mirrored to logcat), the
//! device report sent with it, and signed self-updates from the RDS update channel.

use hbb_common::{config::Config, flexi_logger, log};
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    sync::{Condvar, Mutex},
    time::Duration,
};

const LOG_BASENAME: &str = "rdc";
const LOG_SPEC: &str = "info,reqwest=warn,hyper_util=warn,rustls=warn,webrtc_sctp=error,webrtc=warn,\
webrtc::mux=error,webrtc::data_channel=error,webrtc_ice::agent::agent_internal=error,\
webrtc_ice::agent::agent_selector=error,webrtc_ice::agent::agent_gather=error,\
webrtc::peer_connection=error,librustdesk::managed_passport=debug,librustdesk::managed_peer_auth=debug";

struct Logcat(android_logger::AndroidLogger);

impl flexi_logger::writers::LogWriter for Logcat {
    fn write(&self, _now: &mut flexi_logger::DeferredNow, record: &log::Record) -> std::io::Result<()> {
        log::Log::log(&self.0, record);
        Ok(())
    }

    fn flush(&self) -> std::io::Result<()> {
        Ok(())
    }
}

static LOGGER: Mutex<Option<flexi_logger::LoggerHandle>> = Mutex::new(None);

/// File log in the app's storage (what a debug-log upload sends), every line also to logcat
/// (tag "rdc", readable over adb).
pub fn init_log() {
    use flexi_logger::{Age, Cleanup, Criterion, FileSpec, Logger, Naming};
    let logcat = Logcat(android_logger::AndroidLogger::new(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Debug)
            .with_tag("rdc"),
    ));
    let started = Logger::try_with_str(LOG_SPEC).and_then(|logger| {
        logger
            .log_to_file_and_writer(
                FileSpec::default()
                    .directory(Config::log_path())
                    .basename(LOG_BASENAME),
                Box::new(logcat),
            )
            .format(flexi_logger::opt_format)
            .rotate(
                Criterion::AgeOrSize(Age::Day, 8 * 1024 * 1024),
                Naming::Timestamps,
                Cleanup::KeepLogFiles(14),
            )
            .start()
    });
    match started {
        Ok(handle) => *LOGGER.lock().unwrap() = Some(handle),
        Err(error) => {
            android_logger::init_once(
                android_logger::Config::default()
                    .with_max_level(log::LevelFilter::Info)
                    .with_tag("rdc"),
            );
            log::warn!("file log unavailable, logging to logcat only: {}", error);
        }
    }
}

pub fn active_log_file() -> Option<PathBuf> {
    let path = Config::log_path().join(format!("{LOG_BASENAME}_rCURRENT.log"));
    path.exists().then_some(path)
}

/// The Android counterpart of the Windows security inventory (platform::windows::security_info),
/// for hardware_info.security. Blocking (reads a few system properties): call through spawn_blocking.
pub fn security_info() -> Value {
    let mut info = match scrap::android::ffi::call_rdc_platform("device_report", "") {
        Ok(report) => match serde_json::from_str::<Value>(&report) {
            Ok(android) => json!({ "android": android }),
            Err(_) => json!({ "error": report.chars().take(80).collect::<String>() }),
        },
        Err(error) => json!({ "error": format!("device report: {error}") }),
    };
    info["identity_key_protection"] = json!(if crate::managed_passport::has_identity_key() {
        crate::managed_passport::PROTECTION
    } else {
        "none"
    });
    info["passport"] = crate::managed_passport::load()
        .map_or(Value::Null, |p| json!({ "serial": p.serial, "exp": p.exp, "prot": p.prot }));
    info["peer_cert_expires"] = crate::managed_peer_auth::load_cert()
        .and_then(|stored| {
            crate::managed_peer_auth::verify_cert(&stored.cert, hbb_common::get_time() / 1000).ok()
        })
        .map_or(Value::Null, |payload| json!(payload.exp));
    let (path, since) = crate::managed_ws_fallback::current_path();
    info["connection_path"] = json!({ "path": path, "tcp_lost_seconds_ago": since });
    info
}

/// This APK's versionCode: what an Android update manifest's build_number is compared against.
/// Android releases are numbered managed build * 100 + revision, so the app can be re-released
/// within one managed build.
pub fn installed_release() -> u64 {
    option_env!("RDC_ANDROID_VERSION_CODE")
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or_else(|| crate::hbbs_http::directory_enrollment::managed_build_number() * 100)
}

pub fn update_dir() -> PathBuf {
    let dir = crate::platform::get_program_data_dir()
        .unwrap_or_else(|_| Config::path(""))
        .join("updates");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

const UPDATE_FIRST_CHECK: Duration = Duration::from_secs(60);
const UPDATE_CHECK_INTERVAL: Duration = Duration::from_secs(6 * 3600);
/// While an update waits: how quickly a newly opened remote session holds it (RdcPlatform commits a
/// staged update as soon as the app leaves the screen).
const UPDATE_STAGE_REFRESH: Duration = Duration::from_secs(5);
const UPDATE_CONFIRM_RETRY: Duration = Duration::from_secs(1800);

static UPDATE_WAKE: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());

/// A newer Android release was published (managed_sync's "build" version moved).
pub fn on_update_pushed() {
    let (pushed, wake) = &UPDATE_WAKE;
    *pushed.lock().unwrap() = true;
    wake.notify_one();
}

fn wait_for_update_wake(timeout: Duration) -> bool {
    let (pushed, wake) = &UPDATE_WAKE;
    let guard = pushed.lock().unwrap();
    let (mut guard, _) = wake
        .wait_timeout_while(guard, timeout, |pushed| !*pushed)
        .unwrap();
    std::mem::replace(&mut *guard, false)
}

pub fn start_updater() {
    if option_env!("RDC_ANDROID_VERSION_CODE").is_none() {
        return;
    }
    static STARTED: std::sync::Once = std::sync::Once::new();
    STARTED.call_once(|| {
        if let Err(error) = std::thread::Builder::new()
            .name("rdc-updater".to_owned())
            .spawn(run_updater)
        {
            log::error!("managed update: could not start: {}", error);
        }
    });
}

// Same signed manifest, size and SHA-256 checks as Windows (managed_update_check_and_download);
// never installs while a remote session is open.
fn run_updater() {
    let _ = std::fs::remove_dir_all(update_dir());
    let mut delay = UPDATE_FIRST_CHECK;
    let mut candidate: Option<crate::hbbs_http::directory_enrollment::ManagedUpdateCandidate> = None;
    let mut next_confirm = std::time::Instant::now();
    loop {
        let pushed = wait_for_update_wake(delay);
        delay = UPDATE_CHECK_INTERVAL;
        if pushed || candidate.is_none() {
            candidate = match crate::hbbs_http::directory_enrollment::managed_update_check_and_download() {
                Ok(found) => found,
                Err(error) => {
                    log::warn!("managed update check failed: {}", error);
                    continue;
                }
            };
        }
        let Some(update) = candidate.as_ref() else {
            crate::hbbs_http::directory_enrollment::clear_pending_managed_update();
            continue;
        };
        crate::hbbs_http::directory_enrollment::note_pending_managed_update(
            update.build_number,
            &update.version,
        );
        delay = UPDATE_STAGE_REFRESH;
        let path = if crate::flutter::sessions::get_sessions().is_empty() {
            update.file_path.to_string_lossy().into_owned()
        } else {
            String::new()
        };
        let mode = match scrap::android::ffi::call_rdc_platform("stage_update", &path) {
            Ok(mode) => mode,
            Err(error) => {
                log::warn!("managed update: staging failed: {}", error);
                delay = UPDATE_CONFIRM_RETRY;
                continue;
            }
        };
        if mode != "confirm" || path.is_empty() || std::time::Instant::now() < next_confirm {
            continue;
        }
        match scrap::android::ffi::call_rdc_platform("install_update", &path) {
            Ok(result) if result == "started" => {
                log::info!(
                    "managed update: asking to install release {} ({})",
                    update.build_number,
                    update.version
                );
                next_confirm = std::time::Instant::now() + UPDATE_CONFIRM_RETRY;
            }
            Ok(result) if result.starts_with("deferred:") => {}
            Ok(result) => {
                log::warn!("managed update: install failed: {}", result);
                next_confirm = std::time::Instant::now() + UPDATE_CONFIRM_RETRY;
            }
            Err(error) => {
                log::warn!("managed update: install call failed: {}", error);
                next_confirm = std::time::Instant::now() + UPDATE_CONFIRM_RETRY;
            }
        }
    }
}
