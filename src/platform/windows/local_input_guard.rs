use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc::{sync_channel, SyncSender},
    Once, OnceLock,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use winapi::{
    shared::{minwindef::{LPARAM, LRESULT, WPARAM}, ntdef::NULL},
    um::winuser::{
        CallNextHookEx, DispatchMessageW, GetMessageW, SetWindowsHookExW,
        TranslateMessage, UnhookWindowsHookEx, HC_ACTION, KBDLLHOOKSTRUCT, LLKHF_ALTDOWN,
        LLKHF_INJECTED, MSG, MSLLHOOKSTRUCT, WH_KEYBOARD_LL, WH_MOUSE_LL, WM_KEYDOWN,
        WM_SYSKEYDOWN,
    },
};

static START_MONITOR: Once = Once::new();
static MONITOR_STARTED: AtomicBool = AtomicBool::new(false);
static LAST_LOCAL_MOUSE_MS: AtomicU64 = AtomicU64::new(0);
static PRIORITY_WINDOW_MS: AtomicU64 = AtomicU64::new(250);
static PRIORITY_TX: OnceLock<SyncSender<()>> = OnceLock::new();

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

unsafe extern "system" fn mouse_hook(code: i32, w_param: WPARAM, l_param: LPARAM) -> LRESULT {
    if code == HC_ACTION {
        let mouse = &*(l_param as *const MSLLHOOKSTRUCT);
        if mouse.dwExtraInfo != enigo::ENIGO_INPUT_EXTRA_VALUE {
            LAST_LOCAL_MOUSE_MS.store(now_ms(), Ordering::SeqCst);
            if let Some(tx) = PRIORITY_TX.get() {
                let _ = tx.try_send(());
            }
        }
    }
    CallNextHookEx(NULL as _, code, w_param, l_param)
}

// Unlike the mouse hook, injected keys never count: RustDesk's own key injection is not
// reliably tagged, because rdev only uses ENIGO_INPUT_EXTRA_VALUE after the server's input
// thread sets it and never in the portable service process. Every RustDesk mouse event
// goes through enigo, so the mouse hook can still count other software's injected input.
// Key-ups and Alt-less WM_SYSKEYDOWN (F10) don't count: privacy mode's keyboard hook usually
// runs ahead of this one and passes them through while swallowing the local user's other keys.
unsafe extern "system" fn keyboard_hook(code: i32, w_param: WPARAM, l_param: LPARAM) -> LRESULT {
    if code == HC_ACTION {
        let key = &*(l_param as *const KBDLLHOOKSTRUCT);
        let key_down = match w_param as u32 {
            WM_KEYDOWN => true,
            WM_SYSKEYDOWN => key.flags & LLKHF_ALTDOWN != 0,
            _ => false,
        };
        if key_down && key.flags & LLKHF_INJECTED == 0 {
            LAST_LOCAL_MOUSE_MS.store(now_ms(), Ordering::SeqCst);
            if let Some(tx) = PRIORITY_TX.get() {
                let _ = tx.try_send(());
            }
        }
    }
    CallNextHookEx(NULL as _, code, w_param, l_param)
}

fn local_mouse_has_priority_now(window_ms: u64) -> bool {
    let last = LAST_LOCAL_MOUSE_MS.load(Ordering::SeqCst);
    last != 0 && now_ms().saturating_sub(last) < window_ms
}

fn local_mouse_priority_until_ms(window_ms: u64) -> u64 {
    LAST_LOCAL_MOUSE_MS
        .load(Ordering::SeqCst)
        .saturating_add(window_ms)
}

pub fn ensure_local_mouse_monitor() {
    START_MONITOR.call_once(|| {
        let (priority_tx, priority_rx) = sync_channel::<()>(1);
        if PRIORITY_TX.set(priority_tx).is_err() {
            hbb_common::log::error!("Failed to initialize local input priority channel");
            return;
        }

        if let Err(e) = std::thread::Builder::new()
            .name("rustdesk-local-input-priority".to_owned())
            .spawn(move || {
                while priority_rx.recv().is_ok() {
                    loop {
                        let window_ms = PRIORITY_WINDOW_MS.load(Ordering::SeqCst).max(1);
                        let until_ms = local_mouse_priority_until_ms(window_ms);
                        if now_ms() < until_ms {
                            crate::portable_service::client::apply_local_input_priority_until(
                                until_ms,
                            );
                        }

                        std::thread::sleep(Duration::from_millis(10));
                        let mut more_activity = false;
                        while priority_rx.try_recv().is_ok() {
                            more_activity = true;
                        }
                        if !more_activity {
                            break;
                        }
                    }
                }
            })
        {
            hbb_common::log::error!("Failed to start local input priority worker: {}", e);
            return;
        }
        std::thread::Builder::new()
            .name("rustdesk-local-mouse-guard".to_owned())
            .spawn(|| unsafe {
                let hook = SetWindowsHookExW(WH_MOUSE_LL, Some(mouse_hook), NULL as _, 0);
                if hook.is_null() {
                    hbb_common::log::error!("Failed to install local mouse priority hook");
                    return;
                }
                let kb_hook = SetWindowsHookExW(WH_KEYBOARD_LL, Some(keyboard_hook), NULL as _, 0);
                if kb_hook.is_null() {
                    hbb_common::log::error!("Failed to install local keyboard priority hook");
                }
                MONITOR_STARTED.store(true, Ordering::SeqCst);
                let mut msg: MSG = std::mem::zeroed();
                while GetMessageW(&mut msg, NULL as _, 0, 0) > 0 {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
                if !kb_hook.is_null() {
                    UnhookWindowsHookEx(kb_hook);
                }
                UnhookWindowsHookEx(hook);
                MONITOR_STARTED.store(false, Ordering::SeqCst);
            })
            .map_err(|e| {
                hbb_common::log::error!("Failed to start local mouse priority monitor: {}", e)
            })
            .ok();
    });
}

pub fn local_mouse_has_priority(window_ms: u64) -> bool {
    PRIORITY_WINDOW_MS.store(window_ms.max(1), Ordering::SeqCst);
    ensure_local_mouse_monitor();
    if !MONITOR_STARTED.load(Ordering::SeqCst) {
        return false;
    }
    local_mouse_has_priority_now(window_ms)
}
