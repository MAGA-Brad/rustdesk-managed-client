// RustDrop's background register/poll/notify loop. Ports the retired
// Electron client's registerLoop()/pollIncomingLoop() one-to-one
// (rustdrop/main.js) - same intervals, same "notify on complete or
// uploading" status filter.
//
// On Windows this is spawned from inside `--server`, not the raw SYSTEM
// service, for the exact same reason managed_chat's websocket task lives
// there (see ipc::Data::ManagedChatIpcRequest's doc comment):
// current_identity() reads the enrollment credential, which is ACL'd to
// LocalSystem + Administrators only (rustdrop_keystore's keypair file gets
// the identical treatment), and `--server` is the only session-side
// process whose token satisfies that ACL. The plain GUI window has no such
// access and isn't where this belongs anyway - `--server` is already the
// one long-lived per-session process, alive independent of whether any
// RustDrop window is currently open.
//
// This loop never touches the private key - registration only ever sends
// the public key, and polling only reads drop status/metadata. Accept always
// requires the user to click, so the actual download+decrypt path (which
// does need the private key) is separate and not part of this module.

use crate::rustdrop_keystore::load_or_create;
use crate::rustdrop_rds_client::{self, current_identity};
use hbb_common::tokio;
use std::collections::HashSet;
use std::time::{Duration, Instant};

const REGISTER_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
const POLL_INTERVAL: Duration = Duration::from_secs(20);

/// Spawns the loop on a dedicated OS thread with its own runtime - same
/// pattern as managed_chat::spawn_chat_websocket_task, for the same reason
/// (no ambient tokio runtime can be assumed at the call site).
pub fn spawn_task() {
    std::thread::spawn(run_loop);
}

#[tokio::main(flavor = "current_thread")]
async fn run_loop() {
    let mut notified_drop_ids: HashSet<String> = HashSet::new();
    // Register immediately on startup, then every REGISTER_INTERVAL.
    let mut next_register_at = Instant::now();
    loop {
        if Instant::now() >= next_register_at {
            register_once().await;
            next_register_at = Instant::now() + REGISTER_INTERVAL;
        }
        poll_once(&mut notified_drop_ids).await;
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

async fn register_once() {
    let identity = match current_identity() {
        Ok(identity) => identity,
        Err(e) => {
            hbb_common::log::debug!("rustdrop: registration skipped, not enrolled yet: {e}");
            return;
        }
    };
    let keypair = load_or_create();
    match rustdrop_rds_client::register_device(&identity, &keypair.public_key_base64).await {
        Ok(()) => hbb_common::log::info!("rustdrop: registration heartbeat sent"),
        Err(e) => {
            // Best-effort: a missed heartbeat just means this device drops
            // out of other devices' send-to pickers until the next one
            // lands, not a fatal error for the process.
            hbb_common::log::error!("rustdrop: registration heartbeat failed: {e}");
        }
    }
}

async fn poll_once(notified_drop_ids: &mut HashSet<String>) {
    let identity = match current_identity() {
        Ok(identity) => identity,
        Err(_) => return,
    };
    let drops = match rustdrop_rds_client::list_drops(&identity).await {
        Ok(drops) => drops,
        Err(e) => {
            hbb_common::log::error!("rustdrop: polling incoming drops failed: {e}");
            return;
        }
    };
    for drop in &drops.incoming {
        if drop.status != "complete" && drop.status != "uploading" {
            continue;
        }
        if !notified_drop_ids.insert(drop.id.clone()) {
            continue;
        }
        hbb_common::log::info!("rustdrop: incoming file: {}", drop.filename);
        open_rustdrop_window();
    }
}

// The RustDrop window itself is the notification (no toast: Windows refuses
// toasts from this LocalSystem process). main_launch_rustdrop() opens it in
// the user's session, or finds the one already open; then it is raised to
// the front once visible - a fresh launch takes a moment to show its window,
// and this process isn't in the foreground, so only raise_window() can
// bring it on top.
#[cfg(windows)]
fn open_rustdrop_window() {
    if !crate::flutter_ffi::main_launch_rustdrop() {
        return;
    }
    std::thread::spawn(|| {
        for _ in 0..60 {
            if crate::platform::windows::raise_window(
                &crate::platform::FLUTTER_RUNNER_WIN32_WINDOW_CLASS,
                "RustDrop",
            ) {
                hbb_common::log::info!("rustdrop: window raised for incoming file");
                return;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        hbb_common::log::warn!("rustdrop: window did not appear within 15s to be raised");
    });
}

#[cfg(not(windows))]
fn open_rustdrop_window() {}
