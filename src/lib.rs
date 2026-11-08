mod frb_generated; /* AUTO INJECTED BY flutter_rust_bridge. This line may not be accurate, and you can change it according to your needs. */
#[cfg(any(test, not(target_os = "linux")))]
mod audio_resampler;
mod keyboard;
/// cbindgen:ignore
pub mod platform;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub use platform::{
    clip_cursor, get_cursor, get_cursor_data, get_cursor_pos, get_focused_display,
    set_cursor_pos, start_os_service,
};
#[cfg(not(any(target_os = "ios")))]
/// cbindgen:ignore
mod server;
#[cfg(not(any(target_os = "ios")))]
pub use self::server::*;
mod client;
mod lan;
#[cfg(not(any(target_os = "ios")))]
mod rendezvous_mediator;
#[cfg(not(any(target_os = "ios")))]
pub use self::rendezvous_mediator::*;
/// cbindgen:ignore
pub mod common;
#[cfg(not(any(target_os = "ios")))]
pub mod ipc;
#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter"
)))]
pub mod ui;
pub(crate) mod update_metadata;
pub(crate) mod update_hash;
#[cfg(target_os = "macos")]
mod manual_update;
mod version;
pub use version::*;
#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
pub mod flutter;
#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
pub mod flutter_ffi;
use common::*;
mod auth_2fa;
mod trusted_devices;
#[cfg(not(target_os = "ios"))]
mod clipboard;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub mod core_main;
mod custom_server;
mod lang;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod port_forward;
mod port_forward_mux;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod tray;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod whiteboard;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod updater;

mod ui_cm_interface;
mod ui_interface;
mod ui_session_interface;

mod hbbs_http;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod managed_chat_store;

#[cfg(any(windows, target_os = "android", feature = "rdc_gateway"))]
mod managed_peer_auth;

#[cfg(any(windows, target_os = "android", feature = "rdc_gateway"))]
mod managed_edge_cert;

#[cfg(any(windows, target_os = "android", feature = "rdc_gateway"))]
mod managed_ech;

#[cfg(any(windows, target_os = "android", feature = "rdc_gateway"))]
mod managed_passport;

#[cfg(any(windows, target_os = "android", feature = "rdc_gateway"))]
mod managed_proof;

#[cfg(windows)]
mod managed_chat_e2e;

#[cfg(windows)]
mod managed_reconnect;

#[cfg(windows)]
mod managed_2fa_trust;

mod managed_sealed;

mod managed_sealed_signal;

mod managed_ws_fallback;

#[cfg(any(windows, target_os = "android", feature = "rdc_gateway"))]
mod managed_connection_report;
#[cfg(target_os = "android")]
mod managed_android;
#[cfg(feature = "rdc_gateway")]
pub mod managed_gateway;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod rustdrop_crypto;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod rustdrop_rds_client;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod rustdrop_keystore;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod rustdrop_save_path;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod rustdrop_service;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod rustdrop_transfer;

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
pub mod clipboard_file;

pub mod privacy_mode;

#[cfg(windows)]
pub mod virtual_display_manager;

mod kcp_stream;
