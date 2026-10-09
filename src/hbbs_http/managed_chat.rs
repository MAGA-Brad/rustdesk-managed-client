// Out-of-session chat between managed devices. Talks to RDS's own
// /v1/messaging/* REST endpoints and its /v1/messaging/ws websocket -
// entirely separate from the RustDesk protocol's own in-session chat
// channel, and from hbbs/hbbr, which this feature never touches.

use crate::hbbs_http::directory_enrollment::{current_device_id, current_directory_credential};
use crate::managed_sealed::SendSealed;
use hbb_common::{
    anyhow::{anyhow, bail},
    futures::StreamExt,
    log, tokio, ResultType,
};
use serde::{Deserialize, Serialize};
use tokio_tungstenite::tungstenite::{
    client::IntoClientRequest, http::HeaderValue, Message as WsMessage,
};

const OPERATION_START_CONVERSATION: &str = "chat start conversation";
const OPERATION_SEND_MESSAGE: &str = "chat send message";
const OPERATION_LIST_CONVERSATIONS: &str = "chat list conversations";
const OPERATION_GET_MESSAGES: &str = "chat get messages";
const OPERATION_WEBSOCKET: &str = "chat websocket";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub id: String,
    pub sender_device_id: String,
    pub body: String,
    pub sent_at: String,
    // Only ever populated on the immediate response to sending a message -
    // absent (defaults empty) on every other shape this struct is parsed
    // from (an incoming push, a get_messages drain). Empty means the
    // recipient wasn't connected to receive it live at that moment; the
    // message is still safely queued server-side either way. See
    // managed_chat_store::insert_message's `delivered` column.
    #[serde(default)]
    pub delivered_to: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatParticipant {
    pub device_id: String,
    pub friendly_name: Option<String>,
    // #[serde(default)]: tolerates talking to an RDS that hasn't picked up
    // this field yet (managed_chat.py's _conversation_summary) - falls back
    // to empty rather than failing to parse the whole conversation.
    #[serde(default)]
    pub rustdesk_id: String,
}

// No last_message/unread_count here - the server is a delivery mailbox,
// not a history archive, so it doesn't reliably have either once a
// message is purged on delivery. Both are purely local concepts now,
// computed from managed_chat_store's own copy after a message lands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatConversation {
    pub id: String,
    pub conversation_type: String,
    pub name: Option<String>,
    pub created_at: String,
    pub participants: Vec<ChatParticipant>,
}

#[derive(Serialize)]
struct StartConversationBody<'a> {
    // The RustDesk numeric id (Peer.id in the Directory tab), not RDS's
    // internal device UUID - the client never needs to know the UUID at
    // all, the server resolves it from this.
    peer_rustdesk_id: &'a str,
}

#[derive(Serialize)]
struct SendMessageBody<'a> {
    body: &'a str,
}

/// This device's own RDS device UUID - needed client-side purely to tell
/// which conversation participant is "me" (e.g. to name a 1:1 dialog after
/// the *other* party). No network call.
pub fn self_device_id() -> ResultType<String> {
    current_device_id()
}

fn join_url(base_url: &str, path: &str) -> String {
    format!("{}{}", base_url.trim_end_matches('/'), path)
}

pub async fn start_conversation(peer_rustdesk_id: &str) -> ResultType<ChatConversation> {
    let (base_url, credential) = current_directory_credential(OPERATION_START_CONVERSATION)?;
    let client = super::http_client::create_http_client_async_with_url_strict(&base_url).await?;
    let response = client
        .post(join_url(&base_url, "/v1/messaging/conversations"))
        .bearer_auth(credential)
        .json(&StartConversationBody { peer_rustdesk_id })
        .send_sealed()
        .await?;
    if response.status() != reqwest::StatusCode::OK {
        bail!(
            "start_conversation failed: {} {}",
            response.status(),
            response.text().await.unwrap_or_default()
        );
    }
    Ok(response.json().await?)
}

pub async fn send_message(conversation_id: &str, body: &str) -> ResultType<ChatMessage> {
    let (base_url, credential) = current_directory_credential(OPERATION_SEND_MESSAGE)?;
    let client = super::http_client::create_http_client_async_with_url_strict(&base_url).await?;
    let response = client
        .post(join_url(
            &base_url,
            &format!("/v1/messaging/conversations/{}/messages", conversation_id),
        ))
        .bearer_auth(credential)
        .json(&SendMessageBody { body })
        .send_sealed()
        .await?;
    if response.status() != reqwest::StatusCode::OK {
        bail!(
            "send_message failed: {} {}",
            response.status(),
            response.text().await.unwrap_or_default()
        );
    }
    Ok(response.json().await?)
}

#[derive(Deserialize)]
struct ConversationsResponse {
    conversations: Vec<ChatConversation>,
}

pub async fn list_conversations() -> ResultType<Vec<ChatConversation>> {
    let (base_url, credential) = current_directory_credential(OPERATION_LIST_CONVERSATIONS)?;
    let client = super::http_client::create_http_client_async_with_url_strict(&base_url).await?;
    let response = client
        .get(join_url(&base_url, "/v1/messaging/conversations"))
        .bearer_auth(credential)
        .send_sealed()
        .await?;
    if response.status() != reqwest::StatusCode::OK {
        bail!(
            "list_conversations failed: {} {}",
            response.status(),
            response.text().await.unwrap_or_default()
        );
    }
    Ok(response.json::<ConversationsResponse>().await?.conversations)
}

#[derive(Deserialize)]
struct MessagesResponse {
    messages: Vec<ChatMessage>,
}

pub async fn get_messages(conversation_id: &str) -> ResultType<Vec<ChatMessage>> {
    let (base_url, credential) = current_directory_credential(OPERATION_GET_MESSAGES)?;
    let client = super::http_client::create_http_client_async_with_url_strict(&base_url).await?;
    let response = client
        .get(join_url(
            &base_url,
            &format!("/v1/messaging/conversations/{}/messages", conversation_id),
        ))
        .bearer_auth(credential)
        .send_sealed()
        .await?;
    if response.status() != reqwest::StatusCode::OK {
        bail!(
            "get_messages failed: {} {}",
            response.status(),
            response.text().await.unwrap_or_default()
        );
    }
    Ok(response.json::<MessagesResponse>().await?.messages)
}

#[derive(Deserialize)]
struct IncomingPush {
    #[serde(rename = "type")]
    kind: String,
    conversation_id: String,
    // Present for kind == "message"; absent (and irrelevant) for
    // kind == "delivered".
    #[serde(default)]
    message: Option<ChatMessage>,
    // Present for kind == "delivered"; absent for kind == "message".
    #[serde(default)]
    message_id: Option<String>,
}

fn ws_url_for(base_url: &str) -> ResultType<String> {
    if let Some(rest) = base_url.strip_prefix("https://") {
        Ok(format!("wss://{}/v1/messaging/ws", rest.trim_end_matches('/')))
    } else if let Some(rest) = base_url.strip_prefix("http://") {
        Ok(format!("ws://{}/v1/messaging/ws", rest.trim_end_matches('/')))
    } else {
        Err(anyhow!("Unrecognized managed directory base URL scheme"))
    }
}

/// No app window is listening for chat pushes: start the app as the signed-in user in this
/// --server process's own session (the launcher RustDrop uses for incoming files), so its push
/// handler opens the conversation. Fails, and returns false, when nobody is signed in to the
/// session.
#[cfg(windows)]
fn launch_gui_for_chat() -> bool {
    let Ok(current_exe) = std::env::current_exe() else {
        return false;
    };
    let Some(exe) = current_exe.to_str() else {
        return false;
    };
    if !crate::platform::is_root() {
        return std::process::Command::new(exe).spawn().is_ok();
    }
    let session_id = crate::platform::windows::get_current_process_session_id()
        .unwrap_or_else(|| crate::platform::windows::get_current_session_id(false));
    match crate::platform::windows::run_exe_in_session(exe, vec![], session_id, true) {
        Ok(_) => {
            log::info!("managed chat: started the app in session {} to show a new message", session_id);
            true
        }
        Err(error) => {
            log::warn!("managed chat: could not start the app in session {}: {}", session_id, error);
            false
        }
    }
}

/// Started without arguments, the app shows its main window. A chat window it creates while the
/// main one is still starting can leave the main window never shown, so an app this service
/// started gets nothing until then; its chat windows then also open in front of it.
#[cfg(windows)]
async fn wait_for_main_window() {
    let app_name = crate::get_app_name();
    for _ in 0..40 {
        if crate::platform::windows::is_window_visible(
            crate::platform::FLUTTER_RUNNER_WIN32_WINDOW_CLASS,
            &app_name,
        ) {
            // Shown, then focused.
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            return;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
    }
    log::warn!("managed chat: the app's main window did not appear within 10s");
}

/// A window opened by an app this service just started does not take the foreground by itself.
#[cfg(windows)]
fn raise_chat_window() {
    // desktop_multi_window's class for every window except the main one.
    const SUB_WINDOW_CLASS: &str = "RustdeskMultiWindow";
    let title = format!("Chat - {}", crate::get_app_name());
    std::thread::spawn(move || {
        for _ in 0..60 {
            if crate::platform::windows::raise_visible_window(SUB_WINDOW_CLASS, &title) {
                log::info!("managed chat: chat window raised");
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        log::warn!("managed chat: chat window did not appear within 15s to be raised");
    });
}

/// Events for the app, delivered in order by one task so waiting for the app never stalls the
/// websocket: the server drops a connection that stops reading.
#[cfg(windows)]
static GUI_EVENTS: std::sync::OnceLock<tokio::sync::mpsc::UnboundedSender<(String, bool)>> =
    std::sync::OnceLock::new();

/// `show`: a new message, which starts the app if it is closed. Anything else only updates an
/// app that is already open; the store has it for when the app opens.
#[cfg(windows)]
fn relay_event_to_gui(payload: String, show: bool) {
    match GUI_EVENTS.get() {
        Some(events) => {
            if events.send((payload, show)).is_err() {
                log::warn!("managed chat: event relay to the app has stopped");
            }
        }
        None => log::warn!("managed chat: event relay to the app is not running"),
    }
}

#[cfg(windows)]
async fn run_gui_relay(mut events: tokio::sync::mpsc::UnboundedReceiver<(String, bool)>) {
    // When this task last started the app, until the app answers.
    let mut launched_at = None;
    while let Some((payload, show)) = events.recv().await {
        deliver_event_to_gui(payload, show, &mut launched_at).await;
    }
}

// On a fresh "restart the app and service" (the common case right after
// installing an update, or after being offline), --server's websocket
// connects and gets its catch-up burst of pending messages almost
// immediately - often before the GUI process has finished starting up
// and bound its own "_managed_chat_push" listener. A single connect
// attempt would silently miss that window and the user would never
// see the message (though it's already safely stored locally by the
// time this is called - see the insert_message call in run_websocket_once). Retry for
// a few seconds to cover normal GUI startup time.
#[cfg(windows)]
async fn deliver_event_to_gui(
    payload: String,
    show: bool,
    launched_at: &mut Option<std::time::Instant>,
) {
    use std::time::{Duration, Instant};
    log::info!("managed chat: relaying event to GUI process via IPC");
    const MAX_ATTEMPTS: u32 = 10;
    // An app this task starts itself needs longer to come up and bind its listener.
    const LAUNCH_WAIT: Duration = Duration::from_secs(45);
    // An app started this recently that never answered is not started again for every message.
    const RELAUNCH_AFTER: Duration = Duration::from_secs(120);
    let mut app_starting = false;
    let mut main_window_waited = false;
    let mut attempt = 0;
    loop {
        attempt += 1;
        match crate::ipc::connect(1_000, "_managed_chat_push").await {
            Ok(mut ipc_stream) => {
                if launched_at.is_some() && !main_window_waited {
                    // The app's listener drops a connection that sends nothing for a second, so
                    // connect again once its main window is up.
                    drop(ipc_stream);
                    wait_for_main_window().await;
                    main_window_waited = true;
                    continue;
                }
                if let Err(error) = ipc_stream
                    .send(&crate::ipc::Data::ManagedChatIncomingMessage(payload))
                    .await
                {
                    log::info!("managed chat: failed to relay event to GUI process: {}", error);
                } else {
                    log::info!("managed chat: relay to GUI process sent");
                    if launched_at.take().is_some() {
                        raise_chat_window();
                    }
                }
                return;
            }
            Err(error) => {
                if attempt == 1 {
                    // The main window exists before the app binds its listener, and a second
                    // copy started then would not see it.
                    app_starting = crate::platform::windows::window_exists(
                        crate::platform::FLUTTER_RUNNER_WIN32_WINDOW_CLASS,
                        &crate::get_app_name(),
                    );
                    if show
                        && !app_starting
                        && launched_at.map_or(true, |at| at.elapsed() >= RELAUNCH_AFTER)
                        && launch_gui_for_chat()
                    {
                        *launched_at = Some(Instant::now());
                    }
                }
                log::info!(
                    "managed chat: no GUI process listening for event relay (attempt {}): {}",
                    attempt,
                    error
                );
                let waiting_for_launch = launched_at.is_some_and(|at| at.elapsed() < LAUNCH_WAIT);
                if !waiting_for_launch && !(app_starting && attempt < MAX_ATTEMPTS) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1_000)).await;
            }
        }
    }
    log::info!("managed chat: giving up relaying event to GUI process - it will still show up next time the conversation is opened or synced");
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn run_websocket_once() -> ResultType<()> {
    let (base_url, credential) = current_directory_credential(OPERATION_WEBSOCKET)?;
    let ws_url = ws_url_for(&base_url)?;

    let mut request = ws_url.into_client_request()?;
    request.headers_mut().insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {}", credential))?,
    );

    // Public certificate authorities only, plus the edge client certificate - not the Windows store,
    // which a network's inspecting CA can be added to, letting it read the credential above.
    #[cfg(windows)]
    let (mut stream, _response) = tokio_tungstenite::connect_async_tls_with_config(
        request,
        None,
        false,
        Some(tokio_tungstenite::Connector::Rustls(std::sync::Arc::new(
            crate::managed_edge_cert::rustls_config()?,
        ))),
    )
    .await?;
    #[cfg(not(windows))]
    let (mut stream, _response) = tokio_tungstenite::connect_async(request).await?;
    log::info!("managed chat websocket connected");

    // Messages that arrived while nobody could see them (signed out, or the app closed) are
    // already stored. Once per --server start - e.g. at sign-in - pop the conversations that
    // still have unread messages, the same way a live message is shown.
    #[cfg(windows)]
    {
        static UNREAD_SHOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if !UNREAD_SHOWN.swap(true, std::sync::atomic::Ordering::Relaxed) {
            match crate::managed_chat_store::list_conversations() {
                Ok(conversations) => {
                    let unread: Vec<String> = conversations
                        .into_iter()
                        .filter(|conversation| conversation.unread_count > 0)
                        .map(|conversation| conversation.id)
                        .collect();
                    if !unread.is_empty() {
                        log::info!("managed chat: {} conversation(s) with unread messages; showing them", unread.len());
                        for conversation_id in unread {
                            let payload = serde_json::json!({
                                "name": "managed_chat_message",
                                "conversation_id": conversation_id,
                            });
                            relay_event_to_gui(payload.to_string(), true);
                        }
                    }
                }
                Err(error) => log::error!("managed chat: could not check for unread messages: {}", error),
            }
        }
    }

    // Windows-only: this task runs in --server there (see this module's
    // spawn_chat_websocket_task doc comment for the ACL reason), so
    // push_global_event has to be relayed over IPC to reach the GUI
    // process's Flutter engine instead of being called directly. On
    // other platforms the file permission model doesn't have this
    // GUI-vs-privileged-process split - GUI and --server run as the
    // same Unix user with the same file access - so this task still
    // runs directly in the GUI process there and can call
    // push_global_event in-process, same as it always did.

    // RDS pings every 20 s, so a silent minute means the connection died under us (a network
    // change, say) without a close ever arriving. Reconnect; RDS resends what was missed.
    while let Some(frame) = tokio::time::timeout(tokio::time::Duration::from_secs(60), stream.next())
        .await
        .map_err(|_| anyhow!("managed chat websocket silent for 60 s; reconnecting"))?
    {
        match frame {
            Ok(WsMessage::Text(text)) => {
                if let Ok(push) = serde_json::from_str::<IncomingPush>(&text) {
                    if push.kind == "message" {
                        if let Some(message) = &push.message {
                            // Store first: the server has already (or will
                            // soon have) purged its own copy once this
                            // delivery is acked, so this is the only durable
                            // record left. Not from self - a push is always
                            // someone else's message.
                            if let Err(error) = crate::managed_chat_store::insert_message(
                                &push.conversation_id,
                                message,
                                false,
                                true,
                            ) {
                                log::error!(
                                    "managed chat: failed to store incoming message: {}",
                                    error
                                );
                            }
                            let payload = serde_json::json!({
                                "name": "managed_chat_message",
                                "conversation_id": push.conversation_id,
                                "message": message,
                            });
                            #[cfg(windows)]
                            relay_event_to_gui(payload.to_string(), true);
                            #[cfg(not(windows))]
                            crate::flutter::push_global_event(
                                crate::flutter::APP_TYPE_MAIN,
                                payload.to_string(),
                            );
                        }
                    } else if push.kind == "delivered" {
                        if let Some(message_id) = &push.message_id {
                            // A message this device sent earlier has now
                            // been received by the recipient - update our
                            // local copy so the "pending delivery" marker
                            // clears next time it's rendered, and tell the
                            // GUI so an already-open chat window for this
                            // conversation refreshes right away instead of
                            // only on next open.
                            if let Err(error) =
                                crate::managed_chat_store::mark_delivered(message_id)
                            {
                                log::error!(
                                    "managed chat: failed to mark message delivered: {}",
                                    error
                                );
                            }
                            let payload = serde_json::json!({
                                "name": "managed_chat_delivered",
                                "conversation_id": push.conversation_id,
                                "message_id": message_id,
                            });
                            #[cfg(windows)]
                            relay_event_to_gui(payload.to_string(), false);
                            #[cfg(not(windows))]
                            crate::flutter::push_global_event(
                                crate::flutter::APP_TYPE_MAIN,
                                payload.to_string(),
                            );
                        }
                    }
                }
            }
            Ok(WsMessage::Close(_)) => bail!("managed chat websocket closed by server"),
            Ok(_) => {}
            Err(error) => bail!("managed chat websocket error: {}", error),
        }
    }
    bail!("managed chat websocket stream ended")
}

/// Runs forever in the background: connects, serves pushes, reconnects
/// with a short backoff on any disconnect (server restart, network blip,
/// laptop sleep/wake). Called once from initialize(); a device that never
/// enrolls just keeps failing current_directory_credential() harmlessly
/// in a slow loop until it does.
///
/// initialize() is a plain sync fn called directly across the Dart/Rust
/// FFI boundary - there's no ambient tokio runtime on that thread, so the
/// bare tokio::spawn() free function used here previously would panic
/// immediately ("must be called from the context of a Tokio 1.x
/// runtime"), and a panic unwinding across an extern FFI boundary aborts
/// the whole process. Spawning a dedicated OS thread with its own runtime
/// - the same pattern flutter.rs's start_flutter_async_runner() already
/// uses for the identical problem - avoids depending on any caller
/// context at all.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn spawn_chat_websocket_task() {
    std::thread::spawn(run_websocket_loop);
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[tokio::main(flavor = "current_thread")]
async fn run_websocket_loop() {
    #[cfg(windows)]
    {
        let (events, receiver) = tokio::sync::mpsc::unbounded_channel();
        if GUI_EVENTS.set(events).is_ok() {
            tokio::spawn(run_gui_relay(receiver));
        }
    }
    loop {
        if let Err(error) = run_websocket_once().await {
            log::debug!("managed chat websocket ended: {}", error);
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    }
}

#[derive(Deserialize)]
struct StartConversationArgs {
    peer_rustdesk_id: String,
}

#[derive(Deserialize)]
struct SendMessageArgs {
    conversation_id: String,
    body: String,
}

#[derive(Deserialize)]
struct ConversationIdArgs {
    conversation_id: String,
}

/// Runs one managed-chat operation and returns its JSON result (or a JSON
/// `{"error": "..."}` object on failure) as a plain String, uniformly for
/// both call paths that reach here:
///  - directly, in-process, on platforms without the Windows ACL problem
///    documented on `ipc::Data::ManagedChatIpcRequest`
///  - relayed over IPC from the GUI process to `--server` on Windows,
///    which actually has permission to read the enrollment credential
///
/// `flutter_ffi.rs`'s wrappers own everything after this returns
/// (deserializing into a typed struct and updating the local store) -
/// this function's only job is running the one named operation.
pub async fn handle_ipc_request(operation: &str, args_json: &str) -> String {
    let outcome: ResultType<String> = async {
        match operation {
            "start_conversation" => {
                let args: StartConversationArgs = serde_json::from_str(args_json)?;
                let conversation = start_conversation(&args.peer_rustdesk_id).await?;
                Ok(serde_json::to_string(&conversation)?)
            }
            "send_message" => {
                let args: SendMessageArgs = serde_json::from_str(args_json)?;
                let message = send_message(&args.conversation_id, &args.body).await?;
                Ok(serde_json::to_string(&message)?)
            }
            "list_conversations" => {
                let conversations = list_conversations().await?;
                Ok(serde_json::to_string(&conversations)?)
            }
            "get_messages" => {
                let args: ConversationIdArgs = serde_json::from_str(args_json)?;
                let messages = get_messages(&args.conversation_id).await?;
                Ok(serde_json::to_string(&messages)?)
            }
            "self_device_id" => {
                Ok(serde_json::json!({ "device_id": self_device_id()? }).to_string())
            }
            _ => bail!("unknown managed chat IPC operation: {}", operation),
        }
    }
    .await;

    match outcome {
        Ok(json) => json,
        Err(error) => serde_json::json!({ "error": error.to_string() }).to_string(),
    }
}
