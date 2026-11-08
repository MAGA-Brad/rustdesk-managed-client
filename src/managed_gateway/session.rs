//! One viewer's remote session: the browser's WebSocket on one side, an RDC Client on the other,
//! reached as this gateway device (its RDS certificate and passport), exactly as Windows RDC would.
//!
//! The gateway never decodes video: the Client's encoded frames go to the browser as they are and
//! the browser decodes them (WebCodecs). Keys arrive as browser key codes and leave as the Client's
//! own scan codes (map mode). No audio, clipboard or files are relayed.

use super::{
    rds,
    web::{self, CheckFailure, Viewer},
    GatewaySession,
};
use crate::client::{Client, Data, Interface, REQUIRE_2FA, LOGIN_MSG_2FA_WRONG, LOGIN_MSG_PASSWORD_WRONG};
use base::message_proto::*;
use hbb_common::{
    config::{LocalConfig, READ_TIMEOUT},
    futures::{SinkExt, StreamExt},
    log,
    protobuf::Message as _,
    rendezvous_proto::ConnType,
    timeout,
    tokio::{
        self,
        net::TcpStream,
        sync::mpsc,
        time::{interval, Duration, Instant},
    },
    Stream,
};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, LazyLock, Mutex,
    },
};
use tokio_tungstenite::{tungstenite::Message as WsMessage, WebSocketStream};

/// Messages queued for a browser before video drops to the next key frame (a slow viewer must not
/// stall the session or grow the gateway's memory).
const OUT_QUEUE: usize = 48;
const MAX_INPUT: usize = 16 * 1024;
const START_WAIT: Duration = Duration::from_secs(30);
/// How long to wait for a password, a code, or the person at the PC to accept.
const LOGIN_WAIT: Duration = Duration::from_secs(180);
const SESSION_CHECK: Duration = Duration::from_secs(60);
/// A live session ends when RDS has been out of reach this long since it last confirmed the
/// sign-in (fail closed).
const CHECK_GRACE: Duration = Duration::from_secs(5 * 60);
const REFRESH_SPACING: Duration = Duration::from_secs(2);
/// Wrong passwords, or wrong codes, one session may get before it ends.
const SESSION_WRONG: u32 = 3;
/// Wrong answers one account may get from one PC before ACCOUNT_LOCKOUT (or until it signs in).
/// The PC counts failures by address, so every viewer shares the gateway's: past 30 it locks the
/// gateway out for all of them, and no one account may spend that.
const ACCOUNT_WRONG: u32 = 10;
/// The same as RustDWeb's own sign-in lockout.
const ACCOUNT_LOCKOUT: Duration = Duration::from_secs(30 * 60);
const TOO_MANY_WRONG: &str = "Too many wrong attempts for this computer";

static WRONG_ANSWERS: LazyLock<Mutex<WrongAnswers>> = LazyLock::new(Default::default);

/// Wrong passwords and codes per (account id, PC id) since that account last signed in to that PC,
/// with when the count reached ACCOUNT_WRONG.
#[derive(Default)]
struct WrongAnswers(HashMap<(String, String), (u32, Option<Instant>)>);

impl WrongAnswers {
    /// How much longer the account is locked out of that PC; None when it isn't.
    fn locked_for(&mut self, key: &(String, String), now: Instant) -> Option<Duration> {
        let locked_at = self.0.get(key)?.1?;
        let left = ACCOUNT_LOCKOUT.saturating_sub(now.saturating_duration_since(locked_at));
        if left.is_zero() {
            self.0.remove(key);
            return None;
        }
        Some(left)
    }

    /// Returns the account's count for that PC, this one included.
    fn record(&mut self, key: (String, String), now: Instant) -> u32 {
        let (count, locked_at) = self.0.entry(key).or_default();
        if locked_at.map_or(false, |at| now.saturating_duration_since(at) >= ACCOUNT_LOCKOUT) {
            (*count, *locked_at) = (0, None);
        }
        *count = count.saturating_add(1);
        if *count >= ACCOUNT_WRONG && locked_at.is_none() {
            *locked_at = Some(now);
        }
        *count
    }

    fn clear(&mut self, key: &(String, String)) {
        self.0.remove(key);
    }
}

fn locked_out(left: Duration) -> String {
    let minutes = left.as_secs().div_ceil(60).max(1);
    let unit = if minutes == 1 { "minute" } else { "minutes" };
    format!("Locked for about {minutes} more {unit}: too many wrong attempts for this computer")
}

/// The Client sends its delay test about every second, before and after login, so silence this
/// long means it is gone.
fn peer_silent(last_peer: Instant, now: Instant) -> bool {
    now.saturating_duration_since(last_peer) > Duration::from_millis(READ_TIMEOUT)
}

const CODEC_VP9: u8 = 1;
const CODEC_AV1: u8 = 2;
const CODEC_H264: u8 = 3;
const CODEC_VP8: u8 = 4;
const CODEC_H265: u8 = 5;

fn text(value: Value) -> WsMessage {
    WsMessage::text(value.to_string())
}

pub async fn run(ws: WebSocketStream<TcpStream>, viewer: Viewer, peer_id: String, client_ip: String) {
    let (mut ws_tx, mut ws_rx) = ws.split();
    let (out, mut out_rx) = mpsc::channel::<WsMessage>(OUT_QUEUE);
    let writer = tokio::spawn(async move {
        while let Some(message) = out_rx.recv().await {
            if ws_tx.send(message).await.is_err() {
                break;
            }
        }
        let _ = ws_tx.close().await;
    });
    let connection_id = uuid::Uuid::new_v4().to_string();
    let mut relay = Relay::new(viewer, peer_id, client_ip, connection_id, out.clone());
    let reason = relay.serve(&mut ws_rx).await;
    log::info!(
        "RustDWeb session {} -> {} ended: {}",
        relay.viewer.display_name(),
        relay.peer_id,
        reason
    );
    let _ = out.send(text(json!({ "t": "closed", "reason": reason }))).await;
    relay.event("ended", json!({ "end_reason": end_code(&reason) })).await;
    drop(relay);
    drop(out);
    let _ = writer.await;
}

fn end_code(reason: &str) -> String {
    reason
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == ' ')
        .take(60)
        .collect::<String>()
        .trim()
        .replace(' ', "_")
        .to_lowercase()
}

/// RDS's periodic word on the sign-in, in its own task so a slow or unreachable RDS never holds
/// up video or input. Sends why the session must end; stops when dropped.
struct SignInWatch(tokio::task::JoinHandle<()>);

impl SignInWatch {
    fn start(token: String, activity: Arc<AtomicBool>, end: mpsc::Sender<String>) -> Self {
        Self(tokio::spawn(async move {
            let mut unconfirmed = Unconfirmed::new(Instant::now());
            loop {
                tokio::time::sleep(SESSION_CHECK).await;
                let active = activity.swap(false, Ordering::Relaxed);
                let result = web::check_session(&token, active).await.map(|_| ());
                if result.is_err() && active {
                    // RDS didn't hear about it: tell it next time.
                    activity.store(true, Ordering::Relaxed);
                }
                if let Some(reason) = unconfirmed.record(result, Instant::now()) {
                    let _ = end.send(reason).await;
                    return;
                }
            }
        }))
    }
}

impl Drop for SignInWatch {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// How long RDS has been out of reach since it last confirmed the sign-in. Only a check that got
/// no answer at all counts: a 429 or 5xx is how RDS's per-address limit on the gateway arrives.
/// The web front's call limits never apply to these checks, so they are never skipped.
struct Unconfirmed {
    last_check: Instant,
    unreachable: Duration,
}

impl Unconfirmed {
    fn new(now: Instant) -> Self {
        Self { last_check: now, unreachable: Duration::ZERO }
    }

    /// Returns why the session must end, if it must.
    fn record(&mut self, result: Result<(), CheckFailure>, now: Instant) -> Option<String> {
        let since = now.saturating_duration_since(self.last_check);
        self.last_check = now;
        match result {
            Ok(()) => self.unreachable = Duration::ZERO,
            Err(CheckFailure::Ended) => return Some("Your RustDWeb sign-in has ended".to_owned()),
            Err(CheckFailure::Unreachable) => {
                self.unreachable += since;
                if self.unreachable > CHECK_GRACE {
                    return Some(format!("RustDWeb could not confirm your sign-in for {} minutes", CHECK_GRACE.as_secs() / 60));
                }
            }
            Err(CheckFailure::Busy) => {}
        }
        None
    }
}

struct Relay {
    viewer: Viewer,
    peer_id: String,
    client_ip: String,
    connection_id: String,
    out: mpsc::Sender<WsMessage>,
    password_used: bool,
    totp: String,
    totp_sent: bool,
    logged_in: bool,
    peer_platform: String,
    displays: Vec<DisplayInfo>,
    current_display: i32,
    need_key: bool,
    last_refresh: Option<Instant>,
    last_input: Instant,
    started: Instant,
    wrong_passwords: u32,
    wrong_codes: u32,
}

impl Relay {
    fn new(viewer: Viewer, peer_id: String, client_ip: String, connection_id: String, out: mpsc::Sender<WsMessage>) -> Self {
        Self {
            viewer,
            peer_id,
            client_ip,
            connection_id,
            out,
            password_used: false,
            totp: String::new(),
            totp_sent: false,
            logged_in: false,
            peer_platform: String::new(),
            displays: Vec::new(),
            current_display: 0,
            need_key: true,
            last_refresh: None,
            last_input: Instant::now(),
            started: Instant::now(),
            wrong_passwords: 0,
            wrong_codes: 0,
        }
    }

    fn wrong_key(&self) -> (String, String) {
        (self.viewer.account_id(), self.peer_id.clone())
    }

    /// Counts a wrong password or code from the PC; returns why the session must end, if it must.
    fn wrong_answer(&mut self, error: &str) -> Option<String> {
        let tries = if error == LOGIN_MSG_PASSWORD_WRONG {
            &mut self.wrong_passwords
        } else if error == LOGIN_MSG_2FA_WRONG {
            &mut self.wrong_codes
        } else {
            return None;
        };
        *tries += 1;
        let session_tries = *tries;
        let account_tries = WRONG_ANSWERS.lock().unwrap().record(self.wrong_key(), Instant::now());
        (session_tries >= SESSION_WRONG || account_tries >= ACCOUNT_WRONG).then(|| TOO_MANY_WRONG.to_owned())
    }

    async fn event(&self, event: &str, extra: Value) -> Option<rds::Answer> {
        let mut body = json!({
            "session_token": self.viewer.token,
            "connection_id": self.connection_id,
            "event": event,
            "target_rustdesk_id": self.peer_id,
            "client_ip": self.client_ip,
        });
        if let (Value::Object(body), Value::Object(extra)) = (&mut body, extra) {
            body.extend(extra);
        }
        match rds::post("/v1/device/rustdweb/connection-event", &body).await {
            Ok(answer) => Some(answer),
            Err(error) => {
                log::warn!("RustDWeb connection event {event} not sent: {error}");
                None
            }
        }
    }

    async fn say(&self, value: Value) {
        let _ = self.out.send(text(value)).await;
    }

    /// The whole session; returns why it ended, in words for the viewer.
    async fn serve(&mut self, ws_rx: &mut (impl StreamExt<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>> + Unpin)) -> String {
        // 1. The page says what it can decode and, optionally, the PC's password and code.
        let start = match timeout(START_WAIT.as_millis() as u64, ws_rx.next()).await {
            Ok(Some(Ok(WsMessage::Text(t)))) if t.len() <= MAX_INPUT => serde_json::from_str::<Value>(&t).unwrap_or(Value::Null),
            _ => return "The page did not start the session".to_owned(),
        };
        if start["t"] != "start" {
            return "The page did not start the session".to_owned();
        }
        let decoding = supported_decoding(&start["codecs"]);
        if decoding.ability_vp9 == 0 && decoding.ability_av1 == 0 && decoding.ability_h264 == 0 && decoding.ability_vp8 == 0 {
            return "This browser can't decode any of the video formats RDC uses".to_owned();
        }
        let password = start["password"].as_str().unwrap_or_default().to_owned();
        self.totp = start["totp"].as_str().unwrap_or_default().trim().to_owned();

        // 2. RDS records the attempt and enforces the per-viewer session limit.
        match self.event("started", json!({ "method": "pending" })).await {
            Some(answer) if answer.ok() => {}
            Some(answer) => return answer.detail(),
            None => return "RustDWeb is not available right now".to_owned(),
        }
        // After "started", so the "ended" event records the refusal in RDS.
        let locked = WRONG_ANSWERS.lock().unwrap().locked_for(&self.wrong_key(), Instant::now());
        if let Some(left) = locked {
            return locked_out(left);
        }
        let max_session = Duration::from_secs(self.viewer.limit("max_session_minutes", 480) * 60);
        let idle_limit = Duration::from_secs(self.viewer.limit("idle_disconnect_minutes", 30) * 60);

        // 3. Reach the Client as this device.
        let (session, mut data_rx) = GatewaySession::new(&self.peer_id, format!("{} (RDC Web)", self.viewer.display_name()));
        session.get_lch().write().unwrap().gateway_supported_decoding = Some(decoding);
        self.say(json!({ "t": "state", "state": "connecting" })).await;
        let key = crate::common::get_key(true).await;
        let token = LocalConfig::get_option("access_token");
        let mut stream = match Client::start(&self.peer_id, &key, &token, ConnType::DEFAULT_CONN, session.clone()).await {
            Ok(((stream, _direct, _pk, _kcp, _transport), _)) => stream,
            Err(error) => return format!("Could not reach the Client: {error}"),
        };

        let mut tick = interval(Duration::from_secs(1));
        let mut last_peer = Instant::now();
        let activity = Arc::new(AtomicBool::new(false));
        let (end_tx, mut end_rx) = mpsc::channel::<String>(1);
        let _watch = SignInWatch::start(self.viewer.token.clone(), activity.clone(), end_tx);
        loop {
            tokio::select! {
                read = stream.next() => {
                    let bytes = match read {
                        Some(Ok(bytes)) => bytes,
                        Some(Err(error)) => return format!("Connection lost: {error}"),
                        None => return "The Client closed the connection".to_owned(),
                    };
                    last_peer = Instant::now();
                    let Ok(message) = Message::parse_from_bytes(&bytes) else { continue };
                    if let Some(reason) = self.from_peer(message, &session, &password, &mut stream).await {
                        return reason;
                    }
                }
                incoming = ws_rx.next() => {
                    let value = match incoming {
                        Some(Ok(WsMessage::Text(t))) if t.len() <= MAX_INPUT => serde_json::from_str::<Value>(&t).unwrap_or(Value::Null),
                        Some(Ok(WsMessage::Ping(_))) | Some(Ok(WsMessage::Pong(_))) => continue,
                        Some(Ok(WsMessage::Close(_))) | None | Some(Err(_)) => return "Closed by the viewer".to_owned(),
                        _ => continue,
                    };
                    if value["t"] == "close" {
                        return "Closed by the viewer".to_owned();
                    }
                    if self.from_viewer(&value, &session, &mut stream).await {
                        activity.store(true, Ordering::Relaxed);
                        self.last_input = Instant::now();
                    }
                }
                ended = end_rx.recv() => {
                    return ended.unwrap_or_else(|| "RustDWeb could not confirm your sign-in".to_owned());
                }
                data = data_rx.recv() => match data {
                    Some(Data::Message(message)) => {
                        if stream.send(&message).await.is_err() {
                            return "Connection lost".to_owned();
                        }
                    }
                    Some(Data::Close) | None => return "Session closed".to_owned(),
                    _ => {}
                },
                _ = tick.tick() => {
                    if peer_silent(last_peer, Instant::now()) {
                        return "The Client stopped answering".to_owned();
                    }
                    if !self.logged_in && self.started.elapsed() > LOGIN_WAIT {
                        return "No answer from the Client's password, code, or the person at the PC".to_owned();
                    }
                    if self.started.elapsed() > max_session {
                        return format!("Session time limit reached ({} minutes)", max_session.as_secs() / 60);
                    }
                    if self.logged_in && self.last_input.elapsed() > idle_limit {
                        return format!("Disconnected after {} minutes without input", idle_limit.as_secs() / 60);
                    }
                }
            }
        }
    }

    /// Returns Some(reason) when the session must end.
    async fn from_peer(&mut self, message: Message, session: &GatewaySession, password: &str, stream: &mut Stream) -> Option<String> {
        match message.union {
            Some(message::Union::Hash(hash)) => {
                // An empty password asks the person at the PC to accept (where the PC allows that).
                self.password_used = !password.is_empty();
                session.handle_hash(password, hash, &mut Default::default(), stream).await;
                if password.is_empty() {
                    self.say(json!({ "t": "need", "what": "password_or_accept" })).await;
                }
            }
            Some(message::Union::LoginResponse(response)) => match response.union {
                Some(login_response::Union::Error(error)) => return self.login_error(error, stream).await,
                Some(login_response::Union::PeerInfo(info)) => self.connected(info, session).await,
                _ => {}
            },
            Some(message::Union::VideoFrame(frame)) => self.video(frame, stream).await,
            Some(message::Union::CursorData(cursor)) => {
                if let Some(value) = cursor_json(cursor) {
                    let _ = self.out.try_send(text(value));
                }
            }
            Some(message::Union::CursorId(id)) => {
                let _ = self.out.try_send(text(json!({ "t": "cursorId", "id": id.to_string() })));
            }
            Some(message::Union::CursorPosition(pos)) => {
                let _ = self.out.try_send(text(json!({ "t": "cursorPos", "x": pos.x, "y": pos.y })));
            }
            Some(message::Union::TestDelay(delay)) => session.handle_test_delay(delay, stream).await,
            Some(message::Union::Misc(misc)) => match misc.union {
                Some(misc::Union::SwitchDisplay(display)) => {
                    self.current_display = display.display;
                    self.need_key = true;
                    self.say(json!({
                        "t": "display", "display": display.display,
                        "x": display.x, "y": display.y, "width": display.width, "height": display.height,
                    }))
                    .await;
                }
                Some(misc::Union::CloseReason(reason)) if !reason.is_empty() => return Some(reason),
                Some(misc::Union::PermissionInfo(permission)) => {
                    self.say(json!({
                        "t": "permission",
                        "name": format!("{:?}", permission.permission.enum_value_or_default()),
                        "enabled": permission.enabled,
                    }))
                    .await;
                }
                _ => {}
            },
            _ => {}
        }
        None
    }

    async fn login_error(&mut self, error: String, stream: &mut Stream) -> Option<String> {
        if let Some(reason) = self.wrong_answer(&error) {
            return Some(reason);
        }
        if error == REQUIRE_2FA || error == LOGIN_MSG_2FA_WRONG {
            if error == REQUIRE_2FA && !self.totp_sent && self.totp.len() == 6 {
                self.totp_sent = true;
                send_2fa(stream, &self.totp).await;
            } else {
                self.say(json!({ "t": "need", "what": "2fa", "error": error })).await;
            }
            return None;
        }
        if error.contains("Password") || error.contains("password") {
            self.say(json!({ "t": "need", "what": "password", "error": error })).await;
            return None;
        }
        Some(error)
    }

    async fn connected(&mut self, info: PeerInfo, session: &GatewaySession) {
        session.handle_peer_info(info.clone());
        WRONG_ANSWERS.lock().unwrap().clear(&self.wrong_key());
        self.logged_in = true;
        self.last_input = Instant::now();
        self.peer_platform = info.platform.clone();
        self.displays = info.displays.clone();
        self.current_display = info.current_display;
        let method = if self.password_used { "password_totp" } else { "accepted" };
        self.event("authorized", json!({ "method": method })).await;
        let displays: Vec<Value> = info
            .displays
            .iter()
            .map(|d| json!({ "x": d.x, "y": d.y, "width": d.width, "height": d.height, "name": d.name, "online": d.online }))
            .collect();
        self.say(json!({
            "t": "connected",
            "platform": info.platform,
            "hostname": info.hostname,
            "displays": displays,
            "current": info.current_display,
            "sas": info.sas_enabled,
        }))
        .await;
    }

    async fn video(&mut self, frame: VideoFrame, stream: &mut Stream) {
        let (codec, frames) = match frame.union {
            Some(video_frame::Union::Vp9s(f)) => (CODEC_VP9, f.frames),
            Some(video_frame::Union::Av1s(f)) => (CODEC_AV1, f.frames),
            Some(video_frame::Union::H264s(f)) => (CODEC_H264, f.frames),
            Some(video_frame::Union::Vp8s(f)) => (CODEC_VP8, f.frames),
            Some(video_frame::Union::H265s(f)) => (CODEC_H265, f.frames),
            _ => return,
        };
        for encoded in frames {
            if self.need_key && !encoded.key {
                continue;
            }
            let mut packet = Vec::with_capacity(12 + encoded.data.len());
            packet.extend_from_slice(&[1, codec, encoded.key as u8, frame.display.clamp(0, 255) as u8]);
            packet.extend_from_slice(&encoded.pts.to_le_bytes());
            packet.extend_from_slice(&encoded.data);
            match self.out.try_send(WsMessage::binary(packet)) {
                Ok(()) => self.need_key = false,
                Err(_) => {
                    // The browser is behind: skip to the next key frame, and ask for one.
                    self.need_key = true;
                    if self.last_refresh.map_or(true, |at| at.elapsed() > REFRESH_SPACING) {
                        self.last_refresh = Some(Instant::now());
                        let mut misc = Misc::new();
                        misc.set_refresh_video(true);
                        let mut message = Message::new();
                        message.set_misc(misc);
                        let _ = stream.send(&message).await;
                    }
                }
            }
        }
    }

    /// Returns whether this was viewer input (which keeps the session from idling out).
    async fn from_viewer(&mut self, value: &Value, session: &GatewaySession, stream: &mut Stream) -> bool {
        let kind = value["t"].as_str().unwrap_or_default();
        match kind {
            "password" => {
                let password = value["password"].as_str().unwrap_or_default().to_owned();
                if let Some(totp) = value["totp"].as_str() {
                    self.totp = totp.trim().to_owned();
                    self.totp_sent = false;
                }
                if !password.is_empty() && !self.logged_in {
                    self.password_used = true;
                    session.handle_login_from_ui(String::new(), String::new(), password, false, &mut Default::default(), stream).await;
                }
                return false;
            }
            "2fa" => {
                let code = value["code"].as_str().unwrap_or_default().trim().to_owned();
                if code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()) && !self.logged_in {
                    self.totp_sent = true;
                    send_2fa(stream, &code).await;
                }
                return false;
            }
            _ => {}
        }
        if !self.logged_in {
            return false;
        }
        let message = match kind {
            "mouse" => mouse_message(value),
            "key" => key_message(value, &self.peer_platform),
            "text" => text_message(value),
            "cad" => Some(ctrl_alt_del(&self.peer_platform)),
            "display" => {
                let index = value["index"].as_i64().unwrap_or(-1);
                if index < 0 || index as usize >= self.displays.len() {
                    return false;
                }
                let mut switch = Misc::new();
                switch.set_switch_display(SwitchDisplay { display: index as i32, ..Default::default() });
                let mut message = Message::new();
                message.set_misc(switch);
                let _ = stream.send(&message).await;
                let mut capture = Misc::new();
                capture.set_capture_displays(CaptureDisplays { set: vec![index as i32], ..Default::default() });
                let mut message = Message::new();
                message.set_misc(capture);
                Some(message)
            }
            "refresh" => {
                self.need_key = true;
                let mut misc = Misc::new();
                misc.set_refresh_video(true);
                let mut message = Message::new();
                message.set_misc(misc);
                Some(message)
            }
            _ => None,
        };
        match message {
            Some(message) => stream.send(&message).await.is_ok() && kind != "refresh" && kind != "display",
            None => false,
        }
    }
}

async fn send_2fa(stream: &mut Stream, code: &str) {
    let mut message = Message::new();
    message.set_auth_2fa(Auth2FA { code: code.to_owned(), ..Default::default() });
    let _ = stream.send(&message).await;
}

fn supported_decoding(codecs: &Value) -> SupportedDecoding {
    let has = |name: &str| codecs[name].as_bool().unwrap_or(false) as i32;
    SupportedDecoding {
        ability_vp9: has("vp9"),
        ability_av1: has("av1"),
        ability_h264: has("h264"),
        ability_vp8: has("vp8"),
        ability_h265: 0,
        prefer: supported_decoding::PreferCodec::Auto.into(),
        ..Default::default()
    }
}

const MOUSE_TYPES: i32 = 4;
const MOUSE_BUTTONS: i32 = 0x1f;

fn modifiers(value: &Value) -> Vec<hbb_common::protobuf::EnumOrUnknown<ControlKey>> {
    let Some(list) = value["mods"].as_array() else { return vec![] };
    list.iter()
        .filter_map(|m| match m.as_str()? {
            "ctrl" => Some(ControlKey::Control),
            "shift" => Some(ControlKey::Shift),
            "alt" => Some(ControlKey::Alt),
            "meta" => Some(ControlKey::Meta),
            _ => None,
        })
        .map(Into::into)
        .collect()
}

fn mouse_message(value: &Value) -> Option<Message> {
    let mask = value["mask"].as_i64()? as i32;
    let (kind, buttons) = (mask & 0x7, mask >> 3);
    if kind > MOUSE_TYPES || buttons & !MOUSE_BUTTONS != 0 {
        return None;
    }
    let clamp = |v: &Value| v.as_i64().map(|v| v.clamp(-1_000_000, 1_000_000) as i32);
    let mut message = Message::new();
    message.set_mouse_event(MouseEvent {
        mask,
        x: clamp(&value["x"])?,
        y: clamp(&value["y"])?,
        modifiers: modifiers(value),
        ..Default::default()
    });
    Some(message)
}

/// A browser key code (KeyboardEvent.code) as the Client's own key code, in map mode: what the
/// key is on the keyboard, whatever the layout.
fn key_message(value: &Value, peer_platform: &str) -> Option<Message> {
    let key = rdev::chrome_key_from_code(value["code"].as_str()?);
    if matches!(key, rdev::Key::Unknown(_)) {
        return None;
    }
    let down = value["down"].as_bool()?;
    let mut event = KeyEvent::new();
    event.down = down;
    if peer_platform == "Windows" && key == rdev::Key::Pause {
        // No usable scan code for Pause on Windows: send it as a control key, as RDC does.
        event.set_control_key(ControlKey::Pause);
        event.mode = KeyboardMode::Legacy.into();
    } else {
        let code = match peer_platform {
            "Windows" => rdev::win_scancode_from_key(key)?,
            "Mac OS" => rdev::macos_keycode_from_key(key)?,
            _ => rdev::linux_keycode_from_key(key)?,
        };
        event.set_chr(code);
        event.mode = KeyboardMode::Map.into();
    }
    let mut message = Message::new();
    message.set_key_event(event);
    Some(message)
}

/// Text from a phone or tablet keyboard, which doesn't report physical keys: the Client types it
/// as text (the same as RDC's legacy text input), so letters with accents and other scripts work.
fn text_message(value: &Value) -> Option<Message> {
    let text: String = value["s"]
        .as_str()?
        .chars()
        .filter(|c| !c.is_control() || *c == '\t')
        .take(512)
        .collect();
    if text.is_empty() {
        return None;
    }
    let mut event = KeyEvent::new();
    event.press = true;
    event.set_seq(text);
    event.mode = KeyboardMode::Legacy.into();
    let mut message = Message::new();
    message.set_key_event(event);
    Some(message)
}

fn ctrl_alt_del(peer_platform: &str) -> Message {
    let mut event = KeyEvent::new();
    if peer_platform == "Windows" {
        event.set_control_key(ControlKey::CtrlAltDel);
        event.down = true;
    } else {
        event.set_control_key(ControlKey::Delete);
        event.modifiers = vec![ControlKey::Control.into(), ControlKey::Alt.into()];
        event.press = true;
    }
    event.mode = KeyboardMode::Legacy.into();
    let mut message = Message::new();
    message.set_key_event(event);
    message
}

/// The Client's cursor image for the page (RGBA, zstd-compressed on the wire).
fn cursor_json(cursor: CursorData) -> Option<Value> {
    const MAX_SIZE: i32 = 256;
    if !(1..=MAX_SIZE).contains(&cursor.width) || !(1..=MAX_SIZE).contains(&cursor.height) {
        return None;
    }
    if !(0..cursor.width).contains(&cursor.hotx) || !(0..cursor.height).contains(&cursor.hoty) {
        return None;
    }
    let expected = (cursor.width * cursor.height * 4) as usize;
    let rgba = zstd::bulk::decompress(&cursor.colors, expected).ok()?;
    if rgba.len() != expected {
        return None;
    }
    use hbb_common::sodiumoxide::base64;
    Some(json!({
        "t": "cursor",
        "id": cursor.id.to_string(),
        "hotx": cursor.hotx,
        "hoty": cursor.hoty,
        "width": cursor.width,
        "height": cursor.height,
        "rgba": base64::encode(&rgba, base64::Variant::Original),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: Duration = Duration::from_secs(60);

    #[test]
    fn unreachable_rds_ends_the_session_after_the_grace() {
        let start = Instant::now();
        let mut unconfirmed = Unconfirmed::new(start);
        for minute in 1..=5 {
            assert_eq!(unconfirmed.record(Err(CheckFailure::Unreachable), start + MINUTE * minute), None);
        }
        let reason = unconfirmed.record(Err(CheckFailure::Unreachable), start + MINUTE * 5 + Duration::from_secs(1));
        assert!(reason.is_some_and(|r| r.contains("could not confirm")));
    }

    #[test]
    fn a_confirmation_restarts_the_grace() {
        let start = Instant::now();
        let mut unconfirmed = Unconfirmed::new(start);
        for minute in 1..=4 {
            assert_eq!(unconfirmed.record(Err(CheckFailure::Unreachable), start + MINUTE * minute), None);
        }
        assert_eq!(unconfirmed.record(Ok(()), start + MINUTE * 5), None);
        for minute in 6..=10 {
            assert_eq!(unconfirmed.record(Err(CheckFailure::Unreachable), start + MINUTE * minute), None);
        }
        assert!(unconfirmed.record(Err(CheckFailure::Unreachable), start + MINUTE * 11).is_some());
    }

    #[test]
    fn rate_limited_checks_never_end_the_session() {
        let start = Instant::now();
        let mut unconfirmed = Unconfirmed::new(start);
        for minute in 1..=600 {
            assert_eq!(unconfirmed.record(Err(CheckFailure::Busy), start + MINUTE * minute), None);
        }
    }

    #[test]
    fn busy_checks_neither_count_nor_reset_unreachable_time() {
        let start = Instant::now();
        let mut unconfirmed = Unconfirmed::new(start);
        let mut at = start;
        // Three unreachable minutes, an hour of 502s, then two more unreachable minutes and a bit.
        for _ in 0..3 {
            at += MINUTE;
            assert_eq!(unconfirmed.record(Err(CheckFailure::Unreachable), at), None);
        }
        for _ in 0..60 {
            at += MINUTE;
            assert_eq!(unconfirmed.record(Err(CheckFailure::Busy), at), None);
        }
        at += MINUTE;
        assert_eq!(unconfirmed.record(Err(CheckFailure::Unreachable), at), None);
        at += MINUTE + Duration::from_secs(1);
        assert!(unconfirmed.record(Err(CheckFailure::Unreachable), at).is_some());
    }

    #[test]
    fn an_ended_sign_in_ends_the_session_at_once() {
        let start = Instant::now();
        let mut unconfirmed = Unconfirmed::new(start);
        let reason = unconfirmed.record(Err(CheckFailure::Ended), start + MINUTE);
        assert_eq!(reason.as_deref(), Some("Your RustDWeb sign-in has ended"));
    }

    #[test]
    fn a_quiet_client_is_noticed_whatever_else_happens() {
        let last_peer = Instant::now();
        assert!(!peer_silent(last_peer, last_peer));
        assert!(!peer_silent(last_peer, last_peer + Duration::from_millis(READ_TIMEOUT)));
        assert!(peer_silent(last_peer, last_peer + Duration::from_millis(READ_TIMEOUT + 1)));
        // A clock reading from before the last message never counts as silence.
        assert!(!peer_silent(last_peer + MINUTE, last_peer));
    }

    fn test_relay(account_id: &str, peer_id: &str) -> Relay {
        let viewer = Viewer {
            token: "rdw_test".to_owned(),
            account: json!({ "id": account_id, "username": "test", "role": "viewer" }),
            limits: Value::Null,
        };
        let (out, _) = mpsc::channel(1);
        Relay::new(viewer, peer_id.to_owned(), String::new(), String::new(), out)
    }

    #[test]
    fn three_wrong_passwords_end_the_session() {
        let mut relay = test_relay("acct-pw", "peer-pw");
        assert_eq!(relay.wrong_answer(LOGIN_MSG_PASSWORD_WRONG), None);
        assert_eq!(relay.wrong_answer(LOGIN_MSG_PASSWORD_WRONG), None);
        assert_eq!(relay.wrong_answer(LOGIN_MSG_PASSWORD_WRONG).as_deref(), Some(TOO_MANY_WRONG));
    }

    #[test]
    fn three_wrong_codes_end_the_session() {
        let mut relay = test_relay("acct-2fa", "peer-2fa");
        assert_eq!(relay.wrong_answer(LOGIN_MSG_PASSWORD_WRONG), None);
        assert_eq!(relay.wrong_answer(LOGIN_MSG_2FA_WRONG), None);
        assert_eq!(relay.wrong_answer(LOGIN_MSG_2FA_WRONG), None);
        assert_eq!(relay.wrong_answer(LOGIN_MSG_2FA_WRONG).as_deref(), Some(TOO_MANY_WRONG));
    }

    #[test]
    fn other_login_errors_are_not_wrong_answers() {
        let mut relay = test_relay("acct-other", "peer-other");
        for error in [REQUIRE_2FA, "Empty Password", "No Password Access", "Too many wrong attempts"] {
            for _ in 0..5 {
                assert_eq!(relay.wrong_answer(error), None);
            }
        }
        assert!(!WRONG_ANSWERS.lock().unwrap().0.contains_key(&relay.wrong_key()));
    }

    #[test]
    fn an_account_is_locked_out_of_a_pc_after_ten_wrong_answers() {
        let key = |peer: &str| ("acct-lock".to_owned(), peer.to_owned());
        // Four sessions of two wrong passwords each, then a fifth that reaches ten.
        for _ in 0..4 {
            let mut relay = test_relay("acct-lock", "peer-lock");
            assert_eq!(relay.wrong_answer(LOGIN_MSG_PASSWORD_WRONG), None);
            assert_eq!(relay.wrong_answer(LOGIN_MSG_PASSWORD_WRONG), None);
        }
        assert_eq!(WRONG_ANSWERS.lock().unwrap().locked_for(&key("peer-lock"), Instant::now()), None);
        let mut relay = test_relay("acct-lock", "peer-lock");
        assert_eq!(relay.wrong_answer(LOGIN_MSG_2FA_WRONG), None);
        assert_eq!(relay.wrong_answer(LOGIN_MSG_2FA_WRONG).as_deref(), Some(TOO_MANY_WRONG));
        let mut wrong = WRONG_ANSWERS.lock().unwrap();
        let now = Instant::now();
        assert!(wrong.locked_for(&key("peer-lock"), now).is_some());
        // Another PC, and another account on the same PC, are untouched.
        assert_eq!(wrong.locked_for(&key("peer-lock-other"), now), None);
        assert_eq!(wrong.locked_for(&("acct-lock-other".to_owned(), "peer-lock".to_owned()), now), None);
    }

    #[test]
    fn a_sign_in_clears_the_count() {
        let mut wrong = WrongAnswers::default();
        let key = ("acct".to_owned(), "peer".to_owned());
        let now = Instant::now();
        for count in 1..ACCOUNT_WRONG {
            assert_eq!(wrong.record(key.clone(), now), count);
            assert_eq!(wrong.locked_for(&key, now), None);
        }
        assert_eq!(wrong.record(key.clone(), now), ACCOUNT_WRONG);
        assert_eq!(wrong.locked_for(&key, now), Some(ACCOUNT_LOCKOUT));
        wrong.clear(&key);
        assert_eq!(wrong.locked_for(&key, now), None);
        assert_eq!(wrong.record(key, now), 1);
    }

    #[test]
    fn the_lockout_lifts_thirty_minutes_after_the_tenth_failure() {
        let mut wrong = WrongAnswers::default();
        let key = ("acct".to_owned(), "peer".to_owned());
        let start = Instant::now();
        // Nine failures well before the tenth: the lockout counts from the tenth.
        for _ in 1..ACCOUNT_WRONG {
            wrong.record(key.clone(), start);
        }
        let tenth = start + MINUTE * 20;
        assert_eq!(wrong.record(key.clone(), tenth), ACCOUNT_WRONG);
        assert_eq!(wrong.locked_for(&key, tenth + MINUTE * 5), Some(MINUTE * 25));
        let last_second = tenth + ACCOUNT_LOCKOUT - Duration::from_secs(1);
        assert_eq!(wrong.locked_for(&key, last_second), Some(Duration::from_secs(1)));
        assert_eq!(wrong.locked_for(&key, tenth + ACCOUNT_LOCKOUT), None);
        // Once lifted, the count starts again.
        assert_eq!(wrong.record(key.clone(), tenth + ACCOUNT_LOCKOUT), 1);
        assert_eq!(wrong.locked_for(&key, tenth + ACCOUNT_LOCKOUT), None);
    }

    #[test]
    fn a_failure_after_an_unchecked_lockout_lifted_starts_a_new_count() {
        let mut wrong = WrongAnswers::default();
        let key = ("acct".to_owned(), "peer".to_owned());
        let start = Instant::now();
        for _ in 0..ACCOUNT_WRONG {
            wrong.record(key.clone(), start);
        }
        assert_eq!(wrong.record(key.clone(), start + ACCOUNT_LOCKOUT), 1);
        assert_eq!(wrong.locked_for(&key, start + ACCOUNT_LOCKOUT), None);
    }

    #[test]
    fn the_lockout_message_says_when_it_lifts() {
        let reason = ": too many wrong attempts for this computer";
        assert_eq!(locked_out(MINUTE * 25), format!("Locked for about 25 more minutes{reason}"));
        assert_eq!(locked_out(MINUTE * 24 + Duration::from_secs(1)), locked_out(MINUTE * 25));
        assert_eq!(locked_out(Duration::from_secs(1)), format!("Locked for about 1 more minute{reason}"));
        assert_eq!(locked_out(ACCOUNT_LOCKOUT), format!("Locked for about 30 more minutes{reason}"));
    }

    #[test]
    fn end_codes_for_wrong_attempts_fit_rds() {
        assert_eq!(end_code(TOO_MANY_WRONG), "too_many_wrong_attempts_for_this_computer");
        // RDS keeps 64 characters of an end reason.
        assert_eq!(end_code(&locked_out(MINUTE * 25)), "locked_for_about_25_more_minutes_too_many_wrong_attempts_for");
        assert!(end_code(&locked_out(ACCOUNT_LOCKOUT)).len() <= 64);
    }
}
