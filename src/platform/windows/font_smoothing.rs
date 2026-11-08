//! Managed builds swap ClearType for grayscale text smoothing while a controller views this
//! desktop. ClearType tints glyph edges, and 4:2:0 video smears those tints off the letters
//! (seen from a tablet controller over H.265). The switch must be persisted: Explorer kept
//! ClearType after an in-memory-only change. A marker file records that RDC made the switch,
//! so ClearType comes back after the last session, or at the next tray start if the
//! connection manager died in between.

use hbb_common::{config::Config, log};
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Mutex,
    },
    time::Duration,
};
use winapi::{
    shared::minwindef::{BOOL, FALSE, UINT},
    um::winuser::{
        SystemParametersInfoW, FE_FONTSMOOTHINGCLEARTYPE, FE_FONTSMOOTHINGSTANDARD,
        SPIF_SENDCHANGE, SPIF_UPDATEINIFILE, SPI_GETFONTSMOOTHING, SPI_GETFONTSMOOTHINGTYPE,
        SPI_SETFONTSMOOTHINGTYPE,
    },
};

const MARKER: &str = "rdc_font_smoothing_switched";
// The change is broadcast to every top-level window, so it runs on its own thread. Only the
// restore is waited for (bounded): the connection manager may exit right after its last session.
const RESTORE_WAIT: Duration = Duration::from_secs(3);

static WANTED: AtomicBool = AtomicBool::new(false);
static APPLY: Mutex<()> = Mutex::new(());

#[derive(Debug, PartialEq)]
enum Step {
    Switch,
    Restore,
    Keep,
}

/// Connection manager hook: `active` is whether any authorized desktop session is open.
pub fn on_desktop_sessions_changed(active: bool) {
    if option_env!("RUSTDESK_MANAGED_DIRECTORY_BASE").is_none() {
        return;
    }
    // Workers read the latest wish under the lock, so the last call wins whatever order they run in.
    WANTED.store(active, Ordering::SeqCst);
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _guard = APPLY.lock().unwrap_or_else(|e| e.into_inner());
        reconcile(WANTED.load(Ordering::SeqCst));
        let _ = tx.send(());
    });
    if !active && rx.recv_timeout(RESTORE_WAIT).is_err() {
        log::warn!("text smoothing: restore still pending after {:?}", RESTORE_WAIT);
    }
}

/// Tray start: put ClearType back if an earlier process switched it and no session holds it.
pub fn restore_if_left_switched() {
    if option_env!("RUSTDESK_MANAGED_DIRECTORY_BASE").is_none()
        || !Config::path(MARKER).exists()
        || crate::check_process("--cm", true)
    {
        return;
    }
    on_desktop_sessions_changed(false);
}

fn reconcile(want_grayscale: bool) {
    let marker = Config::path(MARKER);
    match next_step(
        want_grayscale,
        marker.exists(),
        smoothing_enabled(),
        smoothing_type(),
    ) {
        Step::Switch => switch_to_grayscale(&marker),
        Step::Restore => restore_cleartype(&marker),
        Step::Keep => {}
    }
}

fn next_step(
    want_grayscale: bool,
    switched_by_us: bool,
    enabled: Option<bool>,
    kind: Option<UINT>,
) -> Step {
    match (want_grayscale, switched_by_us) {
        (true, false) if enabled == Some(true) && kind == Some(FE_FONTSMOOTHINGCLEARTYPE) => {
            Step::Switch
        }
        (false, true) => Step::Restore,
        _ => Step::Keep,
    }
}

fn switch_to_grayscale(marker: &Path) {
    // Marker first: a crash right after the switch must still lead to a restore.
    if let Err(err) = std::fs::write(marker, b"cleartype") {
        log::warn!("text smoothing: marker not written, keeping ClearType: {}", err);
        return;
    }
    if set_smoothing_type(FE_FONTSMOOTHINGSTANDARD) {
        log::info!("text smoothing: ClearType -> grayscale while a remote session is open");
    } else {
        log::warn!(
            "text smoothing: switch to grayscale failed: {}",
            std::io::Error::last_os_error()
        );
        let _ = std::fs::remove_file(marker);
    }
}

fn restore_cleartype(marker: &Path) {
    if set_smoothing_type(FE_FONTSMOOTHINGCLEARTYPE) {
        log::info!("text smoothing: back to ClearType");
        if let Err(err) = std::fs::remove_file(marker) {
            log::warn!("text smoothing: marker not removed: {}", err);
        }
    } else {
        // The marker stays, so the next session end or tray start retries.
        log::warn!(
            "text smoothing: restore to ClearType failed: {}",
            std::io::Error::last_os_error()
        );
    }
}

fn smoothing_enabled() -> Option<bool> {
    let mut on: BOOL = FALSE;
    let ok = unsafe { SystemParametersInfoW(SPI_GETFONTSMOOTHING, 0, &mut on as *mut BOOL as _, 0) };
    (ok != 0).then_some(on != FALSE)
}

fn smoothing_type() -> Option<UINT> {
    let mut kind: UINT = 0;
    let ok =
        unsafe { SystemParametersInfoW(SPI_GETFONTSMOOTHINGTYPE, 0, &mut kind as *mut UINT as _, 0) };
    (ok != 0).then_some(kind)
}

fn set_smoothing_type(kind: UINT) -> bool {
    unsafe {
        SystemParametersInfoW(
            SPI_SETFONTSMOOTHINGTYPE,
            0,
            kind as usize as _,
            SPIF_UPDATEINIFILE | SPIF_SENDCHANGE,
        ) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ON: Option<bool> = Some(true);
    const CLEARTYPE: Option<UINT> = Some(FE_FONTSMOOTHINGCLEARTYPE);
    const GRAYSCALE: Option<UINT> = Some(FE_FONTSMOOTHINGSTANDARD);

    #[test]
    fn switches_only_a_cleartype_desktop_it_has_not_switched_yet() {
        assert_eq!(next_step(true, false, ON, CLEARTYPE), Step::Switch);
        assert_eq!(next_step(true, false, ON, GRAYSCALE), Step::Keep);
        assert_eq!(next_step(true, false, Some(false), CLEARTYPE), Step::Keep);
        assert_eq!(next_step(true, false, None, None), Step::Keep);
        assert_eq!(next_step(true, true, ON, GRAYSCALE), Step::Keep);
    }

    #[test]
    fn restores_only_what_it_switched() {
        assert_eq!(next_step(false, true, ON, GRAYSCALE), Step::Restore);
        assert_eq!(next_step(false, true, None, None), Step::Restore);
        assert_eq!(next_step(false, false, ON, GRAYSCALE), Step::Keep);
        assert_eq!(next_step(false, false, ON, CLEARTYPE), Step::Keep);
    }
}
