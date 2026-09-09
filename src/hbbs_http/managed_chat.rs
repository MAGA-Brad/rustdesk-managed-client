// Out-of-session chat between managed devices. Talks to RDS's own
// /v1/messaging/* REST endpoints and its /v1/messaging/ws websocket -
// entirely separate from the RustDesk protocol's own in-session chat
// channel, and from hbbs/hbbr, which this feature never touches.

use crate::hbbs_http::directory_enrollment::{current_device_id, current_directory_credential};
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
    pub hostname: String,
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
        .send()
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
        .send()
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
        .send()
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
        .send()
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

async fn run_websocket_once() -> ResultType<()> {
    let (base_url, credential) = current_directory_credential(OPERATION_WEBSOCKET)?;
    let ws_url = ws_url_for(&base_url)?;

    let mut request = ws_url.into_client_request()?;
    request.headers_mut().insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {}", credential))?,
    );

    let (mut stream, _response) = tokio_tungstenite::connect_async(request).await?;
    log::info!("managed chat websocket connected");

    // Windows-only: this task runs in --server there (see this module's
    // spawn_chat_websocket_task doc comment for the ACL reason), so
    // push_global_event has to be relayed over IPC to reach the GUI
    // process's Flutter engine instead of being called directly. On
    // other platforms the file permission model doesn't have this
    // GUI-vs-privileged-process split - GUI and --server run as the
    // same Unix user with the same file access - so this task still
    // runs directly in the GUI process there and can call
    // push_global_event in-process, same as it always did.
    // On a fresh "restart the app and service" (the common case right after
    // installing an update, or after being offline), --server's websocket
    // connects and gets its catch-up burst of pending messages almost
    // immediately - often before the GUI process has finished starting up
    // and bound its own "_managed_chat_push" listener. A single connect
    // attempt would silently miss that window and the user would never
    // see the message (though it's already safely stored locally by the
    // time this is called - see the insert_message call above). Retry for
    // a few seconds to cover normal GUI startup time.
    #[cfg(windows)]
    async fn relay_event_to_gui(payload: String) {
        log::info!("managed chat: relaying event to GUI process via IPC");
        const MAX_ATTEMPTS: u32 = 10;
        for attempt in 1..=MAX_ATTEMPTS {
            match crate::ipc::connect(1_000, "_managed_chat_push").await {
                Ok(mut ipc_stream) => {
                    if let Err(error) = ipc_stream
                        .send(&crate::ipc::Data::ManagedChatIncomingMessage(payload))
                        .await
                    {
                        log::info!(
                            "managed chat: failed to relay event to GUI process: {}",
                            error
                        );
                    } else {
                        log::info!("managed chat: relay to GUI process sent");
                    }
                    return;
                }
                Err(error) => {
                    log::info!(
                        "managed chat: no GUI process listening for event relay (attempt {}/{}): {}",
                        attempt,
                        MAX_ATTEMPTS,
                        error
                    );
                    if attempt < MAX_ATTEMPTS {
                        tokio::time::sleep(tokio::time::Duration::from_millis(1_000)).await;
                    }
                }
            }
        }
        log::info!("managed chat: giving up relaying event to GUI process - it will still show up next time the conversation is opened or synced");
    }

    while let Some(frame) = stream.next().await {
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
                            relay_event_to_gui(payload.to_string()).await;
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
                            relay_event_to_gui(payload.to_string()).await;
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
pub fn spawn_chat_websocket_task() {
    std::thread::spawn(run_websocket_loop);
}

#[tokio::main(flavor = "current_thread")]
async fn run_websocket_loop() {
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
