//! Managed installer (install_page.dart): an install that stopped the installed instance
//! (`stop_running_instance_before_install`) and then does not go ahead puts it back, so the device
//! doesn't drop out of the fleet until someone reboots it.
//!
//! The install-time 2FA secret is saved through a main IPC listener of this process that lives
//! only for that save. A service started while this installer held the channel (a restore, or the
//! install itself) could not bind it, and its `--server` would then send Close down the channel
//! and kill whatever holds it: this installer.
use super::{
    get_install_info, is_self_service_running, run_cmds, watchdog_logon_task_name,
    watchdog_task_name, ResultType,
};
use hbb_common::{anyhow, bail, config::Config, log, tokio};
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

/// Told to the user when the installed instance could not be started again.
pub(crate) const NOT_RESTORED: &str = "The installed copy could not be restarted, so this device stays offline until it is rebooted or the installer is run again.";

/// Set while save_install_2fa's listener may hold the main IPC channel.
static SAVING_2FA: AtomicBool = AtomicBool::new(false);

/// Enables the SYSTEM watchdog tasks again, starts the service if it is stopped, and starts this
/// session's tray. With nothing installed yet (a first install) nothing is touched, so there is no
/// UAC prompt either. An error means the installed service is not running.
pub(crate) fn restore_instance_after_abandoned_install() -> ResultType<()> {
    if SAVING_2FA.load(Ordering::SeqCst) {
        bail!("the install-time 2FA save still holds the main IPC channel");
    }
    let (_, _, _, exe) = get_install_info();
    if std::fs::metadata(&exe).is_err() {
        return Ok(());
    }
    let app_name = crate::get_app_name();
    let was_running = is_self_service_running();
    let start_service = if was_running {
        String::new()
    } else {
        format!("sc start {app_name}")
    };
    let restored = run_cmds(
        format!(
            "chcp 65001\nschtasks /Change /TN \"{}\" /Enable\nschtasks /Change /TN \"{}\" /Enable\n{start_service}\n",
            watchdog_task_name(),
            watchdog_logon_task_name(),
        ),
        false,
        "restore_instance",
    );
    if was_running {
        // The stop was declined, so the watchdog tasks were never disabled either.
        if let Err(err) = restored {
            log::warn!(
                "Watchdog tasks not re-enabled after an abandoned install: {}",
                err
            );
        }
    } else {
        restored?;
        if !service_started() {
            bail!("the {app_name} service did not start");
        }
    }
    if Config::get_option("stop-service") != "Y" {
        if let Err(err) = std::process::Command::new(&exe).arg("--tray").spawn() {
            log::warn!("Tray not started after an abandoned install: {}", err);
        }
    }
    log::info!("Installed instance restored after an abandoned install");
    Ok(())
}

fn service_started() -> bool {
    for _ in 0..20 {
        if is_self_service_running() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    false
}

/// install_me failed (ui_interface.rs `install_me_managed`): puts the installed instance back if
/// the install never got to it. Returns what to add to the error shown, or "".
pub(crate) fn restore_after_failed_install(error: &anyhow::Error) -> String {
    if !failed_before_changes(&error.to_string()) {
        log::warn!("Installed instance not restored: the install had already started replacing it");
        return String::new();
    }
    match restore_instance_after_abandoned_install() {
        Ok(()) => String::new(),
        Err(err) => {
            log::warn!("Installed instance not restored: {}", err);
            format!("\n\n{NOT_RESTORED}")
        }
    }
}

/// Whether install_me stopped before its elevated script ran. The script starts by uninstalling
/// the installed copy, so once it has run the install is missing or mixed, and must not be started
/// again. run_cmds (installer_handoff.rs) reports the script's exit code; 0x5253_0001..=0x5253_0007
/// are its handoff and preamble checks, which exit before the first command. An elevated process
/// it lost track of ("... elevated process ...") may have run. Anything else failed before the
/// launch (a declined UAC prompt included) and changed nothing.
fn failed_before_changes(message: &str) -> bool {
    const BEFORE_FIRST_COMMAND: std::ops::RangeInclusive<u32> = 0x5253_0001..=0x5253_0007;
    if let Some((_, rest)) = message.split_once("failed with elevated exit code ") {
        let code = rest
            .split(|c: char| !c.is_ascii_digit())
            .next()
            .unwrap_or_default();
        return code
            .parse::<u32>()
            .map_or(false, |code| BEFORE_FIRST_COMMAND.contains(&code));
    }
    !message.contains("elevated process")
}

/// Saves the install-time 2FA secret (auth_2fa::save_install2fa, which goes over the main IPC
/// channel) through a listener of this process that answers only this process, and only until
/// the save is done.
pub(crate) fn save_install_2fa() -> bool {
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    SAVING_2FA.store(true, Ordering::SeqCst);
    let listener = std::thread::Builder::new()
        .name("install-2fa-ipc".to_owned())
        .spawn(move || serve_install_2fa(ready_tx, stop_rx));
    let saved = match listener {
        Ok(listener) => {
            let saved = ready_rx.recv().unwrap_or(false) && save_with_retries();
            stop_tx.send(()).ok();
            if listener.join().is_err() {
                log::warn!("Install-time 2FA listener panicked");
            }
            saved
        }
        Err(err) => {
            log::warn!("Install-time 2FA listener not started: {}", err);
            false
        }
    };
    SAVING_2FA.store(false, Ordering::SeqCst);
    saved
}

fn save_with_retries() -> bool {
    for _ in 0..4 {
        if crate::auth_2fa::save_install2fa() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    false
}

fn serve_install_2fa(
    ready: std::sync::mpsc::Sender<bool>,
    stop: tokio::sync::oneshot::Receiver<()>,
) {
    match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime.block_on(listen_for_install_2fa(ready, stop)),
        Err(err) => {
            log::warn!("Install-time 2FA listener has no runtime: {}", err);
            ready.send(false).ok();
        }
    }
}

async fn listen_for_install_2fa(
    ready: std::sync::mpsc::Sender<bool>,
    mut stop: tokio::sync::oneshot::Receiver<()>,
) {
    // The stopped instance can take a moment to free the channel.
    let mut incoming = None;
    for _ in 0..20 {
        match crate::ipc::new_listener("").await {
            Ok(listener) => {
                incoming = Some(listener);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(250)).await,
        }
    }
    let Some(mut incoming) = incoming else {
        log::warn!("Install-time 2FA not saved: another process holds the main IPC channel");
        ready.send(false).ok();
        return;
    };
    ready.send(true).ok();
    loop {
        tokio::select! {
            _ = &mut stop => break,
            accepted = incoming.next() => match accepted {
                Some(Ok(stream)) if is_this_process(&stream) => {
                    tokio::spawn(answer_install_2fa(crate::ipc::Connection::new(stream)));
                }
                Some(Ok(_)) => log::warn!("Install-time 2FA listener refused another process"),
                Some(Err(err)) => {
                    log::warn!("Install-time 2FA listener stopped: {}", err);
                    break;
                }
                None => break,
            },
        }
    }
}

fn is_this_process(stream: &parity_tokio_ipc::Connection) -> bool {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::{Foundation::HANDLE, System::Pipes::GetNamedPipeClientProcessId};
    let mut pid = 0u32;
    let known = unsafe {
        GetNamedPipeClientProcessId(HANDLE(stream.as_raw_handle()), &mut pid as *mut u32)
    }
    .is_ok();
    known && pid == std::process::id()
}

/// The two requests ipc::set_2fa_with_ack makes, answered as the main IPC handler does.
async fn answer_install_2fa(mut stream: crate::ipc::Connection) {
    while let Ok(data) = stream.next().await {
        let Some(crate::ipc::Data::Config((name, value))) = data else {
            continue;
        };
        if name != "2fa" {
            continue;
        }
        let reply = match value {
            None => Config::get_option("2fa"),
            Some(value) => {
                Config::set_option("2fa".to_owned(), value.clone());
                let ack = if Config::get_option("2fa") == value {
                    "Y"
                } else {
                    "N"
                };
                ack.to_owned()
            }
        };
        if stream
            .send(&crate::ipc::Data::Config((name, Some(reply))))
            .await
            .is_err()
        {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exit_code(code: u32) -> String {
        format!("install failed with elevated exit code {code}: installer command failed")
    }

    #[test]
    fn only_an_install_that_never_ran_its_script_is_restored() {
        // UAC declined, and refusals before the launch.
        assert!(failed_before_changes(
            "The operation was canceled by the user. (0x800704C7)"
        ));
        assert!(failed_before_changes(
            "Cannot install the EXE package over an existing MSI installation"
        ));
        // Handoff and preamble checks, before the script's first command.
        assert!(failed_before_changes(&exit_code(0x5253_0001)));
        assert!(failed_before_changes(&exit_code(0x5253_0007)));
        // The script ran: a shortcut it could not decode, files it could not replace, anything.
        assert!(!failed_before_changes(&exit_code(0x5253_0008)));
        assert!(!failed_before_changes(&exit_code(0x5253_0009)));
        assert!(!failed_before_changes(&exit_code(1)));
        // Launched, then lost track of.
        assert!(!failed_before_changes(
            "Unexpected elevated process wait result: 258"
        ));
        assert!(!failed_before_changes(
            "Windows did not return an elevated process handle"
        ));
    }
}
