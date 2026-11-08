//! RustDWeb's web front. The reverse proxy on this machine is the only client: it terminates TLS
//! for rustdweb.<domain> and forwards plain HTTP/1.1 to 127.0.0.1, one request per connection, with
//! the viewer's real address in X-RDW-Client-IP (set by the proxy, overwriting anything the browser
//! sent).
//!
//! Sign-in, sign-out and session checks go to RDS, which owns the accounts; the gateway keeps only
//! the opaque session token, in a host-only cookie the page's script can't read.

use super::{rds, session};
use hbb_common::{
    anyhow::anyhow,
    bail, log,
    sha2::{Digest, Sha256},
    tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::{OwnedSemaphorePermit, Semaphore},
    },
    ResultType,
};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, LazyLock, Mutex},
    time::{Duration, Instant},
};

const LISTEN: &str = "127.0.0.1:8480";
const COOKIE: &str = "__Host-rdw";
const MAX_HEAD: usize = 16 * 1024;
const MAX_BODY: usize = 16 * 1024;
const SESSION_CACHE: Duration = Duration::from_secs(30);
/// Requests being handled at once; a session WebSocket counts here only until its handshake.
const MAX_REQUESTS: usize = 256;
/// Session WebSockets open at once, across all sign-ins. They last up to hours, so they have their
/// own pool: a full one never keeps sign-in, sign-out or the page from loading.
const MAX_SESSIONS: usize = 128;
/// Connections being told "busy" at once; past this a connection with no slot is closed unanswered.
const MAX_REFUSALS: usize = 64;
const REFUSE_WAIT: Duration = Duration::from_secs(2);
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
/// A request that hasn't fully arrived by then gives its connection slot back.
const REQUEST_WAIT: Duration = Duration::from_secs(15);
/// RDS mints `rdw_` + secrets.token_urlsafe(32), 43 URL-safe base64 characters (RDS
/// app/rustdweb.py); the range leaves room for a longer token later.
const TOKEN_PREFIX: &str = "rdw_";
const TOKEN_BODY: std::ops::RangeInclusive<usize> = 43..=128;
/// A token RDS refused is refused here for this long without asking RDS again.
const REJECTED_FOR: Duration = Duration::from_secs(10 * 60);
const MAX_REJECTED: usize = 4096;
/// RDS calls one client address may cause per window: session checks the gateway can't answer
/// itself, sign-ins and sign-outs. RDS allows the gateway's address 1200 sealed calls a minute in
/// all, live sessions' checks included, so no one visitor may spend them.
const ADDRESS_CALLS: u32 = 30;
const ADDRESS_WINDOW: Duration = Duration::from_secs(60);
const MAX_ADDRESSES: usize = 4096;
/// The same calls from all addresses together, per ADDRESS_WINDOW: half of RDS's 1200, so a flood
/// from many addresses still leaves room for live sessions' checks (SignInWatch, which no web
/// limit applies to) and the directory worker.
const GATEWAY_CALLS: u32 = 600;
/// The page's largest message (a text chunk or the start message) is a few KiB; session.rs reads
/// at most 16 KiB of it.
const MAX_WS_MESSAGE: usize = 64 * 1024;

const INDEX_HTML: &str = include_str!("assets/index.html");
const APP_JS: &str = include_str!("assets/app.js");
const APP_CSS: &str = include_str!("assets/app.css");

pub async fn serve() -> ResultType<()> {
    let listener = TcpListener::bind(LISTEN).await?;
    log::info!("RustDWeb web front listening on {LISTEN}");
    let requests = Arc::new(Semaphore::new(MAX_REQUESTS));
    let refusals = Arc::new(Semaphore::new(MAX_REFUSALS));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                // Returning would end the whole gateway (every viewer's session) over e.g. EMFILE.
                log::warn!("RustDWeb web front: accept failed: {error}");
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            }
        };
        if !peer.ip().is_loopback() {
            continue;
        }
        // Never wait for a slot before accepting: a full gateway answers at once rather than
        // leaving connections in the backlog.
        let Ok(slot) = requests.clone().try_acquire_owned() else {
            refuse_busy(stream, &refusals);
            continue;
        };
        tokio::spawn(async move {
            if let Err(error) = handle(stream, slot).await {
                log::debug!("web request ended: {error}");
            }
        });
    }
}

fn refuse_busy(mut stream: TcpStream, refusals: &Arc<Semaphore>) {
    let Ok(permit) = refusals.clone().try_acquire_owned() else {
        log::debug!("RustDWeb web front: full, connection closed unanswered");
        return;
    };
    tokio::spawn(async move {
        let _permit = permit;
        match tokio::time::timeout(REFUSE_WAIT, answer_busy(&mut stream)).await {
            Ok(Ok(())) => log::debug!("RustDWeb web front: full, answered 503"),
            Ok(Err(error)) => log::debug!("RustDWeb web front: busy answer failed: {error}"),
            Err(_) => log::debug!("RustDWeb web front: busy answer timed out"),
        }
    });
}

async fn answer_busy(stream: &mut TcpStream) -> ResultType<()> {
    write_response(stream, Response::error(503, "RustDWeb is busy. Try again shortly.")).await?;
    stream.shutdown().await?;
    // Closing with the request still unread would reset the connection, which can lose the answer.
    let mut sink = [0u8; 2048];
    while stream.read(&mut sink).await? > 0 {}
    Ok(())
}

pub struct Request {
    pub method: String,
    pub path: String,
    /// Raw (still percent-encoded); parsed only by the route that reads it.
    pub query: String,
    headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn cookie(&self, name: &str) -> Option<String> {
        self.header("cookie")?.split(';').find_map(|part| {
            let (k, v) = part.trim().split_once('=')?;
            (k == name && !v.is_empty()).then(|| v.to_owned())
        })
    }

    pub fn client_ip(&self) -> String {
        self.header("x-rdw-client-ip").unwrap_or_default().trim().to_owned()
    }

    pub fn user_agent(&self) -> String {
        self.header("user-agent").unwrap_or_default().chars().take(400).collect()
    }

    /// The page's own origin: what a same-site request carries in Origin.
    fn same_origin(&self) -> bool {
        match (self.header("origin"), self.header("host")) {
            (Some(origin), Some(host)) => origin == format!("https://{host}"),
            _ => false,
        }
    }
}

async fn read_request(stream: &mut TcpStream) -> ResultType<Request> {
    let mut buf = Vec::with_capacity(2048);
    let head_end = loop {
        let mut chunk = [0u8; 2048];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            bail!("connection closed before the request head");
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > MAX_HEAD {
            bail!("request head too large");
        }
    };
    let head = std::str::from_utf8(&buf[..head_end])?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split(' ');
    let method = first.next().unwrap_or_default().to_owned();
    let target = first.next().unwrap_or_default().to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':').map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned())))
        .collect();
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path.to_owned(), query.to_owned()),
        None => (target, String::new()),
    };
    let mut request = Request { method, path, query, headers, body: buf[head_end + 4..].to_vec() };
    let length: usize = request.header("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    if length > MAX_BODY {
        bail!("request body too large");
    }
    while request.body.len() < length {
        let mut chunk = vec![0u8; length - request.body.len()];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            bail!("connection closed inside the request body");
        }
        request.body.extend_from_slice(&chunk[..n]);
    }
    request.body.truncate(length);
    Ok(request)
}

fn parse_query(query: &str) -> HashMap<String, String> {
    query
        .split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            Some((k.to_owned(), percent_decode(v)))
        })
        .collect()
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            // Bytes only: slicing the &str here panics when a multi-byte character follows '%'.
            b'%' if i + 2 < bytes.len() && bytes[i + 1].is_ascii_hexdigit() && bytes[i + 2].is_ascii_hexdigit() => {
                out.push((hex_value(bytes[i + 1]) << 4) | hex_value(bytes[i + 2]));
                i += 3;
                continue;
            }
            b'+' => out.push(b' '),
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'a'..=b'f' => digit - b'a' + 10,
        b'A'..=b'F' => digit - b'A' + 10,
        _ => 0,
    }
}

struct Response {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
    headers: Vec<String>,
}

impl Response {
    fn json(status: u16, value: Value) -> Self {
        Self { status, content_type: "application/json", body: value.to_string().into_bytes(), headers: vec![] }
    }

    fn error(status: u16, message: &str) -> Self {
        Self::json(status, json!({ "error": message }))
    }

    fn asset(content_type: &'static str, body: &'static str) -> Self {
        Self { status: 200, content_type, body: body.as_bytes().to_vec(), headers: vec![] }
    }

    fn with_header(mut self, header: String) -> Self {
        self.headers.push(header);
        self
    }
}

async fn write_response(stream: &mut TcpStream, response: Response) -> ResultType<()> {
    let reason = match response.status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n",
        response.status,
        reason,
        response.content_type,
        response.body.len()
    );
    for header in &response.headers {
        head.push_str(header);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&response.body).await?;
    stream.flush().await?;
    Ok(())
}

async fn handle(mut stream: TcpStream, slot: OwnedSemaphorePermit) -> ResultType<()> {
    let request = tokio::time::timeout(REQUEST_WAIT, read_request(&mut stream)).await??;
    if !request.path.is_ascii() || !request.query.is_ascii() {
        return write_response(&mut stream, Response::error(400, "Bad request")).await;
    }
    if request.path == "/api/session" && request.header("upgrade").map_or(false, |v| v.eq_ignore_ascii_case("websocket")) {
        return upgrade(stream, request, slot).await;
    }
    let response = route(&request).await;
    write_response(&mut stream, response).await
}

async fn route(request: &Request) -> Response {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") | ("GET", "/index.html") => Response::asset("text/html", INDEX_HTML),
        ("GET", "/app.js") => Response::asset("text/javascript", APP_JS),
        ("GET", "/app.css") => Response::asset("text/css", APP_CSS),
        ("POST", path) if path.starts_with("/api/") && !(request.same_origin() && request.header("x-rdw") == Some("1")) => {
            Response::error(403, "Request refused")
        }
        ("POST", "/api/login") => login(request).await,
        ("POST", "/api/logout") => logout(request).await,
        ("GET", "/api/me") => match signed_in(request, false).await {
            Ok(viewer) => Response::json(200, json!({ "account": viewer.account, "limits": viewer.limits })),
            Err(response) => response,
        },
        ("GET", "/api/devices") => match signed_in(request, false).await {
            Ok(viewer) => Response::json(200, json!({ "devices": devices_for(&viewer) })),
            Err(response) => response,
        },
        ("GET", "/api/session/ready") => session_ready(request).await,
        (_, path) if path.starts_with("/api/") => Response::error(405, "Not available"),
        _ => Response::error(404, "Not found"),
    }
}

fn session_cookie(token: &str, max_age: i64) -> String {
    format!("Set-Cookie: {COOKIE}={token}; Path=/; Max-Age={max_age}; HttpOnly; Secure; SameSite=Strict")
}

async fn login(request: &Request) -> Response {
    let Ok(input) = serde_json::from_slice::<Value>(&request.body) else {
        return Response::error(400, "Bad request");
    };
    let text = |key: &str| input.get(key).and_then(Value::as_str).unwrap_or_default().to_owned();
    let (username, password, totp) = (text("username"), text("password"), text("totp_code"));
    if username.trim().is_empty() || password.is_empty() || totp.len() != 6 || !totp.bytes().all(|b| b.is_ascii_digit()) {
        return Response::error(400, "Enter your username, password and the 6-digit code from your authenticator app");
    }
    if let Err(refusal) = rds_call_allowed(request) {
        return refusal.response();
    }
    let body = json!({
        "username": username.trim(),
        "password": password,
        "totp_code": totp,
        "client_ip": request.client_ip(),
        "user_agent": request.user_agent(),
    });
    match rds::post("/v1/device/rustdweb/login", &body).await {
        Ok(answer) if answer.ok() => {
            let token = answer.body.get("session_token").and_then(Value::as_str).unwrap_or_default();
            if !token_well_formed(token) {
                if !token.is_empty() {
                    log::error!("RustDWeb sign-in: RDS issued a session token this gateway would refuse (see TOKEN_PREFIX)");
                }
                return Response::error(503, "RDS did not start a session");
            }
            let max_age = answer
                .body
                .get("expires_at")
                .and_then(Value::as_str)
                .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                .map(|t| (t.timestamp() - chrono::Utc::now().timestamp()).max(60))
                .unwrap_or(12 * 3600);
            Response::json(200, json!({ "account": answer.body["account"], "limits": answer.body["limits"] }))
                .with_header(session_cookie(token, max_age))
        }
        Ok(answer) if answer.status == 429 => Response::error(429, &answer.detail()),
        Ok(answer) if answer.status == 503 || answer.status == 403 => {
            log::warn!("RustDWeb sign-in refused by RDS for the gateway: {}", answer.detail());
            Response::error(503, "RustDWeb is not available right now")
        }
        // Includes the sealed layer's 502, which is also how RDS's per-address limit arrives.
        Ok(answer) if answer.status >= 500 => {
            log::warn!("RustDWeb sign-in: RDS answered {}: {}", answer.status, answer.detail());
            Response::error(503, "RustDWeb could not reach the server, try again shortly")
        }
        Ok(answer) if login_refused_the_gateway(&answer) => {
            log::error!("RustDWeb: RDS refused the gateway's own credential: {} {}", answer.status, answer.detail());
            Response::error(503, "RustDWeb is not available right now")
        }
        Ok(_) => Response::error(401, "Invalid username, password, or authenticator code"),
        Err(error) => {
            log::warn!("RustDWeb sign-in: RDS unreachable: {error}");
            Response::error(503, "RustDWeb is not available right now")
        }
    }
}

async fn logout(request: &Request) -> Response {
    if let Some(token) = request.cookie(COOKIE) {
        forget(&token);
        // A token RDS could not have issued has nothing to end there.
        if token_well_formed(&token) {
            match rds_call_allowed(request) {
                Ok(()) => {
                    let _ = rds::post("/v1/device/rustdweb/logout", &json!({ "session_token": token })).await;
                }
                Err(refusal) => log::warn!(
                    "RustDWeb sign-out: RDS not told ({refusal:?} call limit reached); the sign-in ends there when it idles out"
                ),
            }
        }
    }
    Response::json(200, json!({ "status": "signed_out" })).with_header(session_cookie("", 0))
}

#[derive(Clone)]
pub struct Viewer {
    pub token: String,
    pub account: Value,
    pub limits: Value,
}

impl Viewer {
    pub fn display_name(&self) -> String {
        let name = self.account.get("display_name").and_then(Value::as_str).unwrap_or_default();
        if name.trim().is_empty() {
            self.account.get("username").and_then(Value::as_str).unwrap_or("Viewer").to_owned()
        } else {
            name.to_owned()
        }
    }

    pub fn limit(&self, key: &str, default: u64) -> u64 {
        self.limits.get(key).and_then(Value::as_u64).filter(|v| *v > 0).unwrap_or(default)
    }

    /// RDS's id for the account (its username if an answer ever lacks one).
    pub fn account_id(&self) -> String {
        ["id", "username"]
            .iter()
            .find_map(|key| self.account.get(*key).and_then(Value::as_str).filter(|v| !v.is_empty()))
            .unwrap_or_default()
            .to_owned()
    }

    /// Who each PC is in session with is for accounts above Viewer (none sign in to RustDWeb today).
    fn sees_session_peers(&self) -> bool {
        self.account.get("role").and_then(Value::as_str).map_or(false, |role| role != "viewer")
    }
}

static CHECKED: Mutex<Vec<([u8; 32], Instant, Viewer)>> = Mutex::new(Vec::new());

fn token_key(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn forget(token: &str) {
    let key = token_key(token);
    CHECKED.lock().unwrap().retain(|(k, _, _)| *k != key);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckFailure {
    /// RDS refused the sign-in, or the cookie can't be one: it has ended.
    Ended,
    /// No answer from RDS at all, or RDS refused the gateway's own device credential.
    Unreachable,
    /// RDS answered 429 or 5xx. The sealed layer turns every refusal of the sealed call into a 502,
    /// so this is also how RDS's per-address limit on the gateway arrives: it says nothing about
    /// the sign-in.
    Busy,
}

static REJECTED: LazyLock<Mutex<Rejected>> = LazyLock::new(Default::default);
static ADDRESS_LIMIT: LazyLock<Mutex<AddressLimit>> = LazyLock::new(Default::default);
static GATEWAY_LIMIT: Mutex<Option<(Instant, u32)>> = Mutex::new(None);

fn token_well_formed(token: &str) -> bool {
    token.strip_prefix(TOKEN_PREFIX).map_or(false, |body| {
        TOKEN_BODY.contains(&body.len()) && body.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

/// Tokens RDS refused (by token hash), so a cookie that keeps coming back costs one RDS call.
#[derive(Default)]
struct Rejected(HashMap<[u8; 32], Instant>);

impl Rejected {
    fn contains(&self, key: &[u8; 32], now: Instant) -> bool {
        self.0.get(key).map_or(false, |at| now.duration_since(*at) < REJECTED_FOR)
    }

    fn insert(&mut self, key: [u8; 32], now: Instant) {
        if self.0.len() >= MAX_REJECTED {
            self.0.retain(|_, at| now.duration_since(*at) < REJECTED_FOR);
        }
        if self.0.len() >= MAX_REJECTED {
            if let Some(oldest) = self.0.iter().min_by_key(|(_, at)| **at).map(|(k, _)| *k) {
                self.0.remove(&oldest);
            }
        }
        self.0.insert(key, now);
    }
}

/// RDS calls per client address, counted in fixed windows.
#[derive(Default)]
struct AddressLimit(HashMap<String, (Instant, u32)>);

impl AddressLimit {
    fn allow(&mut self, address: &str, now: Instant) -> bool {
        if !self.0.contains_key(address) && self.0.len() >= MAX_ADDRESSES {
            self.0.retain(|_, (start, _)| now.duration_since(*start) < ADDRESS_WINDOW);
            if self.0.len() >= MAX_ADDRESSES {
                return false;
            }
        }
        let (start, calls) = self.0.entry(address.to_owned()).or_insert((now, 0));
        if now.duration_since(*start) >= ADDRESS_WINDOW {
            *start = now;
            *calls = 0;
        }
        if *calls >= ADDRESS_CALLS {
            return false;
        }
        *calls += 1;
        true
    }
}

/// What the limit counts by. X-RDW-Client-IP is the proxy's (see the module docs); an IPv6 address
/// counts by its /64, which one subscriber usually holds whole.
fn address_key(client_ip: &str) -> String {
    let ip = client_ip.parse::<IpAddr>().or_else(|_| client_ip.parse::<SocketAddr>().map(|a| a.ip()));
    match ip {
        Ok(IpAddr::V4(v4)) => v4.to_string(),
        Ok(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
        Err(_) => client_ip.chars().take(64).collect(),
    }
}

/// A fixed-window counter: the gateway-wide share of RDS calls.
fn window_allows(window: &mut Option<(Instant, u32)>, limit: u32, now: Instant) -> bool {
    let (start, calls) = window.get_or_insert((now, 0));
    if now.duration_since(*start) >= ADDRESS_WINDOW {
        *start = now;
        *calls = 0;
    }
    if *calls >= limit {
        return false;
    }
    *calls += 1;
    true
}

#[derive(Debug, PartialEq, Eq)]
enum CallRefusal {
    Address,
    Gateway,
}

impl CallRefusal {
    fn response(&self) -> Response {
        match self {
            Self::Address => Response::error(429, "Too many requests. Try again in a minute."),
            Self::Gateway => Response::error(503, "RustDWeb is busy. Try again shortly."),
        }
    }
}

/// The address's own share first, so calls it is refused never use up the gateway-wide share.
fn call_allowed(
    addresses: &mut AddressLimit,
    gateway: &mut Option<(Instant, u32)>,
    address: &str,
    now: Instant,
) -> Result<(), CallRefusal> {
    if !addresses.allow(address, now) {
        return Err(CallRefusal::Address);
    }
    if !window_allows(gateway, GATEWAY_CALLS, now) {
        return Err(CallRefusal::Gateway);
    }
    Ok(())
}

/// For RDS calls web traffic causes: session checks the gateway can't answer itself (pages, the
/// session pre-check and handshake), sign-ins and sign-outs. Never for SignInWatch.
fn rds_call_allowed(request: &Request) -> Result<(), CallRefusal> {
    let address = address_key(&request.client_ip());
    let result = call_allowed(&mut ADDRESS_LIMIT.lock().unwrap(), &mut GATEWAY_LIMIT.lock().unwrap(), &address, Instant::now());
    if let Err(refusal) = &result {
        log::debug!("RustDWeb: RDS call for {address} refused ({refusal:?} limit)");
    }
    result
}

/// RDS's word on the session behind the cookie (cached briefly); `activity` tells RDS the viewer
/// is doing something, which keeps the page-idle timer from ending the sign-in.
pub async fn check_session(token: &str, activity: bool) -> Result<Viewer, CheckFailure> {
    match known_session(token, activity) {
        Some(known) => known,
        None => ask_session(token, activity).await,
    }
}

/// The answer when the gateway has it without asking RDS.
fn known_session(token: &str, activity: bool) -> Option<Result<Viewer, CheckFailure>> {
    if !token_well_formed(token) {
        return Some(Err(CheckFailure::Ended));
    }
    let key = token_key(token);
    if REJECTED.lock().unwrap().contains(&key, Instant::now()) {
        return Some(Err(CheckFailure::Ended));
    }
    if !activity {
        if let Some((_, at, viewer)) = CHECKED.lock().unwrap().iter().find(|(k, _, _)| *k == key) {
            if at.elapsed() < SESSION_CACHE {
                return Some(Ok(viewer.clone()));
            }
        }
    }
    None
}

async fn ask_session(token: &str, activity: bool) -> Result<Viewer, CheckFailure> {
    let key = token_key(token);
    let answer = rds::post("/v1/device/rustdweb/session", &json!({ "session_token": token, "activity": activity }))
        .await
        .map_err(|error| {
            log::warn!("RustDWeb session check: RDS unreachable: {error}");
            CheckFailure::Unreachable
        })?;
    if !answer.ok() {
        // RDS being overloaded or failing (429, 5xx), or refusing the gateway's own credential,
        // leaves the sign-in standing; only RDS refusing the sign-in itself ends it.
        if answer.status == 429 || answer.status >= 500 {
            return Err(CheckFailure::Busy);
        }
        if !sign_in_refused(&answer) {
            log::error!("RustDWeb: RDS refused the gateway's own credential: {} {}", answer.status, answer.detail());
            return Err(CheckFailure::Unreachable);
        }
        forget(token);
        REJECTED.lock().unwrap().insert(key, Instant::now());
        return Err(CheckFailure::Ended);
    }
    let viewer = Viewer { token: token.to_owned(), account: answer.body["account"].clone(), limits: answer.body["limits"].clone() };
    let mut checked = CHECKED.lock().unwrap();
    checked.retain(|(k, at, _)| *k != key && at.elapsed() < SESSION_CACHE);
    checked.push((key, Instant::now(), viewer.clone()));
    Ok(viewer)
}

/// RDS's refusals of a viewer's sign-in all start with "RustDWeb" (app/rustdweb.py: "... session is
/// not valid", "... session ended after inactivity", "... is turned off"), and the 403 for a gateway
/// RDS no longer names ends every sign-in too. Any other refusal, such as require_device's 401
/// "Invalid or expired authentication" or a 428 key-proof demand, is about the gateway's own device
/// credential and says nothing about the sign-in.
fn sign_in_refused(answer: &rds::Answer) -> bool {
    match answer.status {
        401 | 410 => answer.detail().starts_with("RustDWeb"),
        403 => answer.detail().contains("not the RustDWeb gateway"),
        _ => false,
    }
}

/// RDS's answer to a wrong username, password or code (GENERIC_FAILURE in app/rustdweb.py).
const LOGIN_REFUSED: &str = "Invalid username, password, or authenticator code";

/// A sign-in refused over the gateway's own device credential, not the viewer's.
fn login_refused_the_gateway(answer: &rds::Answer) -> bool {
    (answer.status == 401 && answer.detail() != LOGIN_REFUSED) || answer.status == 428
}

async fn signed_in(request: &Request, activity: bool) -> Result<Viewer, Response> {
    let Some(token) = request.cookie(COOKIE) else {
        return Err(Response::error(401, "Sign in to continue"));
    };
    let checked = match known_session(&token, activity) {
        Some(known) => known,
        None => match rds_call_allowed(request) {
            Ok(()) => ask_session(&token, activity).await,
            Err(refusal) => return Err(refusal.response()),
        },
    };
    checked.map_err(|failure| match failure {
        CheckFailure::Ended => Response::error(401, "Your sign-in has ended. Sign in again.").with_header(session_cookie("", 0)),
        CheckFailure::Unreachable | CheckFailure::Busy => Response::error(503, "RustDWeb is not available right now"),
    })
}

/// Approved RDC Clients a viewer can connect to: the gateway's own directory, without itself and
/// without devices that only connect out (RDC for Android, the gateway).
fn devices() -> Vec<Value> {
    let snapshot: Value = serde_json::from_str(&crate::hbbs_http::directory_enrollment::snapshot_json()).unwrap_or(Value::Null);
    let me = hbb_common::config::Config::get_id();
    let mut list: Vec<Value> = snapshot
        .get("devices")
        .and_then(Value::as_array)
        .map(|devices| {
            devices
                .iter()
                .filter(|d| {
                    let platform = d.get("platform").and_then(Value::as_str).unwrap_or("windows");
                    platform == "windows" && d.get("rustdesk_id").and_then(Value::as_str) != Some(me.as_str())
                })
                .map(|d| {
                    json!({
                        "id": d["rustdesk_id"],
                        "name": d["display_name"],
                        "hostname": d["hostname"],
                        "online": d.get("online").and_then(Value::as_bool).unwrap_or(false),
                        "in_session_with": d["active_session_peer"],
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    list.sort_by_key(|d| d["name"].as_str().unwrap_or_default().to_lowercase());
    list
}

fn devices_for(viewer: &Viewer) -> Vec<Value> {
    let mut list = devices();
    if !viewer.sees_session_peers() {
        hide_session_peers(&mut list);
    }
    list
}

fn hide_session_peers(list: &mut [Value]) {
    for device in list.iter_mut().filter_map(Value::as_object_mut) {
        device.remove("in_session_with");
    }
}

pub fn is_listed_device(id: &str) -> bool {
    devices().iter().any(|d| d["id"].as_str() == Some(id))
}

fn session_target(peer_id: &str) -> bool {
    !peer_id.is_empty() && peer_id.bytes().all(|b| b.is_ascii_alphanumeric()) && is_listed_device(peer_id)
}

/// Session starts one account may make to one PC per START_WINDOW: each can put an accept prompt
/// on that PC's screen.
const MAX_STARTS: usize = 6;
const START_WINDOW: Duration = Duration::from_secs(10 * 60);
const MAX_START_KEYS: usize = 4096;

static STARTS: LazyLock<Mutex<StartLimit>> = LazyLock::new(Default::default);

/// Recent session starts per (account id, PC id), in a sliding window.
#[derive(Default)]
struct StartLimit(HashMap<(String, String), Vec<Instant>>);

impl StartLimit {
    /// How long until the pair may start another session; None when it may now.
    fn wait(&mut self, key: &(String, String), now: Instant) -> Option<Duration> {
        let starts = self.0.get_mut(key)?;
        starts.retain(|at| now.saturating_duration_since(*at) < START_WINDOW);
        if starts.len() < MAX_STARTS {
            return None;
        }
        let oldest = starts.iter().min()?;
        Some(START_WINDOW.saturating_sub(now.saturating_duration_since(*oldest)))
    }

    fn take(&mut self, key: (String, String), now: Instant) -> Result<(), Duration> {
        if let Some(wait) = self.wait(&key, now) {
            return Err(wait);
        }
        if !self.0.contains_key(&key) && self.0.len() >= MAX_START_KEYS {
            self.0.retain(|_, starts| starts.iter().any(|at| now.saturating_duration_since(*at) < START_WINDOW));
            if self.0.len() >= MAX_START_KEYS {
                return Err(START_WINDOW);
            }
        }
        self.0.entry(key).or_default().push(now);
        Ok(())
    }
}

fn start_refusal(wait: Duration) -> Response {
    let minutes = wait.as_secs().div_ceil(60).max(1);
    let unit = if minutes == 1 { "minute" } else { "minutes" };
    Response::error(
        429,
        &format!("Too many sessions were started to this computer from your account. Try again in {minutes} {unit}."),
    )
}

/// RDS counts a viewer's sessions only once each has started; the extra one covers a reconnect
/// that opens before the old socket has closed.
fn session_cap(viewer: &Viewer) -> usize {
    (viewer.limit("max_sessions_per_user", 2) as usize).saturating_add(1)
}

/// The page asks here before opening a session: a browser can't read the answer to a refused
/// WebSocket handshake, so it would only see a lost connection.
async fn session_ready(request: &Request) -> Response {
    let viewer = match signed_in(request, false).await {
        Ok(viewer) => viewer,
        Err(response) => return response,
    };
    let peer_id = parse_query(&request.query).remove("id").unwrap_or_default();
    if !session_target(&peer_id) {
        return Response::error(404, "That Client is not in the directory");
    }
    let wait = STARTS.lock().unwrap().wait(&(viewer.account_id(), peer_id), Instant::now());
    if let Some(wait) = wait {
        return start_refusal(wait);
    }
    match SocketSlot::refusal(&viewer.token, session_cap(&viewer)) {
        Some(refusal) => refusal.response(),
        None => Response::json(200, json!({ "ready": true })),
    }
}

async fn upgrade(mut stream: TcpStream, request: Request, request_slot: OwnedSemaphorePermit) -> ResultType<()> {
    if !request.same_origin() {
        return write_response(&mut stream, Response::error(403, "Request refused")).await;
    }
    let viewer = match signed_in(&request, true).await {
        Ok(viewer) => viewer,
        Err(response) => return write_response(&mut stream, response).await,
    };
    let peer_id = parse_query(&request.query).remove("id").unwrap_or_default();
    if !session_target(&peer_id) {
        return write_response(&mut stream, Response::error(404, "That Client is not in the directory")).await;
    }
    let _slot = match SocketSlot::take(&viewer.token, session_cap(&viewer)) {
        Ok(slot) => slot,
        Err(refusal) => return write_response(&mut stream, refusal.response()).await,
    };
    let started = STARTS.lock().unwrap().take((viewer.account_id(), peer_id.clone()), Instant::now());
    if let Err(wait) = started {
        return write_response(&mut stream, start_refusal(wait)).await;
    }
    drop(request_slot);
    let key = request.header("sec-websocket-key").ok_or_else(|| anyhow!("no Sec-WebSocket-Key"))?;
    let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
    let head = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).await?;
    let config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
        .max_message_size(Some(MAX_WS_MESSAGE))
        .max_frame_size(Some(MAX_WS_MESSAGE));
    let ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
        stream,
        tokio_tungstenite::tungstenite::protocol::Role::Server,
        Some(config),
    )
    .await;
    session::run(ws, viewer, peer_id, request.client_ip()).await;
    Ok(())
}

static OPEN_SOCKETS: Mutex<Vec<[u8; 32]>> = Mutex::new(Vec::new());

/// One open session WebSocket, counted against its sign-in (by token hash) and the gateway's
/// MAX_SESSIONS until dropped.
struct SocketSlot([u8; 32]);

#[derive(Debug, PartialEq, Eq)]
enum SlotRefusal {
    SignIn,
    Gateway,
}

impl SlotRefusal {
    fn response(&self) -> Response {
        match self {
            Self::SignIn => Response::error(429, "Too many RustDWeb sessions are open for this sign-in"),
            Self::Gateway => Response::error(503, "RustDWeb has no free session slots right now. Try again later."),
        }
    }
}

fn slot_refusal(open: &[[u8; 32]], key: &[u8; 32], cap: usize) -> Option<SlotRefusal> {
    if open.iter().filter(|k| *k == key).count() >= cap {
        Some(SlotRefusal::SignIn)
    } else if open.len() >= MAX_SESSIONS {
        Some(SlotRefusal::Gateway)
    } else {
        None
    }
}

impl SocketSlot {
    fn take(token: &str, cap: usize) -> Result<Self, SlotRefusal> {
        let key = token_key(token);
        let mut open = OPEN_SOCKETS.lock().unwrap();
        if let Some(refusal) = slot_refusal(&open, &key, cap) {
            return Err(refusal);
        }
        open.push(key);
        Ok(Self(key))
    }

    fn refusal(token: &str, cap: usize) -> Option<SlotRefusal> {
        slot_refusal(&OPEN_SOCKETS.lock().unwrap(), &token_key(token), cap)
    }
}

impl Drop for SocketSlot {
    fn drop(&mut self) {
        let mut open = OPEN_SOCKETS.lock().unwrap();
        if let Some(pos) = open.iter().position(|k| *k == self.0) {
            open.swap_remove(pos);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_decodes_escapes_and_plus() {
        assert_eq!(percent_decode("a+b%20c%41"), "a b cA");
        assert_eq!(percent_decode("%e2%82%AC"), "\u{20ac}");
    }

    #[test]
    fn percent_decode_keeps_invalid_escapes() {
        assert_eq!(percent_decode("%"), "%");
        assert_eq!(percent_decode("%4"), "%4");
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(percent_decode("%0g"), "%0g");
        // from_str_radix would have read "+1" as 0x01.
        assert_eq!(percent_decode("%+1"), "% 1");
        assert_eq!(percent_decode("%ff"), "\u{fffd}");
    }

    #[test]
    fn percent_decode_multibyte_after_percent_does_not_panic() {
        assert_eq!(percent_decode("%a\u{e9}"), "%a\u{e9}");
        assert_eq!(percent_decode("%\u{e9}"), "%\u{e9}");
        assert_eq!(percent_decode("%\u{20ac}"), "%\u{20ac}");
        assert_eq!(percent_decode("x%\u{1f600}y"), "x%\u{1f600}y");
    }

    #[test]
    fn parse_query_reads_id_beside_bad_escapes() {
        let mut query = parse_query("id=123456789&x=%a\u{e9}");
        assert_eq!(query.remove("x").as_deref(), Some("%a\u{e9}"));
        assert_eq!(query.remove("id").as_deref(), Some("123456789"));
    }

    #[test]
    fn socket_slots_cap_per_sign_in_and_free_on_drop() {
        let first = SocketSlot::take("test-token-slots", 2);
        let second = SocketSlot::take("test-token-slots", 2);
        assert!(first.is_ok() && second.is_ok());
        assert_eq!(SocketSlot::take("test-token-slots", 2).err(), Some(SlotRefusal::SignIn));
        assert_eq!(SocketSlot::refusal("test-token-slots", 2), Some(SlotRefusal::SignIn));
        assert!(SocketSlot::take("test-token-other", 2).is_ok());
        drop(first);
        assert_eq!(SocketSlot::refusal("test-token-slots", 2), None);
        assert!(SocketSlot::take("test-token-slots", 2).is_ok());
    }

    #[test]
    fn slot_refusal_caps_the_gateway_separately_from_a_sign_in() {
        let mine = token_key("test-token-mine");
        let mut open: Vec<[u8; 32]> = (0..MAX_SESSIONS - 1).map(|i| token_key(&format!("test-token-{i}"))).collect();
        assert_eq!(slot_refusal(&open, &mine, 3), None);
        open.push(token_key("test-token-last"));
        assert_eq!(slot_refusal(&open, &mine, 3), Some(SlotRefusal::Gateway));
        assert_eq!(slot_refusal(&[mine, mine, mine], &mine, 3), Some(SlotRefusal::SignIn));
        assert_eq!(SlotRefusal::SignIn.response().status, 429);
        assert_eq!(SlotRefusal::Gateway.response().status, 503);
    }

    fn real_shaped_token(fill: char) -> String {
        format!("rdw_{}", fill.to_string().repeat(43))
    }

    #[test]
    fn token_shape_matches_what_rds_mints() {
        assert!(token_well_formed("rdw_AbC-_0123456789abcdefghijklmnopqrstuvwxyzAB"));
        assert!(token_well_formed(&real_shaped_token('x')));
        assert!(token_well_formed(&format!("rdw_{}", "a".repeat(128))));
        assert!(!token_well_formed(""));
        assert!(!token_well_formed("bogus"));
        assert!(!token_well_formed(&format!("rdx_{}", "a".repeat(43))));
        assert!(!token_well_formed(&format!("rdw_{}", "a".repeat(42))));
        assert!(!token_well_formed(&format!("rdw_{}", "a".repeat(129))));
        assert!(!token_well_formed(&format!("rdw_{}=", "a".repeat(43))));
        assert!(!token_well_formed(&format!("rdw_{}.x", "a".repeat(43))));
        assert!(!token_well_formed(&format!("rdw_{}\u{e9}", "a".repeat(43))));
    }

    #[test]
    fn known_session_refuses_without_rds() {
        assert!(matches!(known_session("bogus-cookie-value", false), Some(Err(CheckFailure::Ended))));
        assert!(matches!(known_session("bogus-cookie-value", true), Some(Err(CheckFailure::Ended))));
        // A well-formed token the gateway knows nothing about has to go to RDS.
        let fresh = real_shaped_token('f');
        assert!(known_session(&fresh, false).is_none());
        let refused = real_shaped_token('r');
        REJECTED.lock().unwrap().insert(token_key(&refused), Instant::now());
        assert!(matches!(known_session(&refused, false), Some(Err(CheckFailure::Ended))));
        assert!(matches!(known_session(&refused, true), Some(Err(CheckFailure::Ended))));
    }

    #[test]
    fn rejected_tokens_expire_and_stay_bounded() {
        let now = Instant::now();
        let mut rejected = Rejected::default();
        let key = token_key("test-rejected");
        rejected.insert(key, now);
        assert!(rejected.contains(&key, now + Duration::from_secs(60)));
        assert!(!rejected.contains(&key, now + REJECTED_FOR));
        assert!(!rejected.contains(&token_key("test-other"), now));
        for i in 0..MAX_REJECTED + 10 {
            rejected.insert(token_key(&format!("test-rejected-{i}")), now + Duration::from_millis(i as u64));
        }
        assert!(rejected.0.len() <= MAX_REJECTED);
        let newest = token_key(&format!("test-rejected-{}", MAX_REJECTED + 9));
        assert!(rejected.contains(&newest, now + Duration::from_secs(10)));
    }

    #[test]
    fn address_limit_counts_per_address_and_window() {
        let now = Instant::now();
        let mut limit = AddressLimit::default();
        for _ in 0..ADDRESS_CALLS {
            assert!(limit.allow("203.0.113.7", now));
        }
        assert!(!limit.allow("203.0.113.7", now + Duration::from_secs(1)));
        assert!(limit.allow("203.0.113.8", now + Duration::from_secs(1)));
        assert!(limit.allow("203.0.113.7", now + ADDRESS_WINDOW));
    }

    #[test]
    fn address_limit_table_stays_bounded() {
        let now = Instant::now();
        let mut limit = AddressLimit::default();
        for i in 0..MAX_ADDRESSES {
            assert!(limit.allow(&format!("addr-{i}"), now));
        }
        assert!(!limit.allow("addr-new", now + Duration::from_secs(1)));
        assert!(limit.allow("addr-0", now + Duration::from_secs(1)));
        // Once the old windows have passed, their entries make room.
        assert!(limit.allow("addr-new", now + ADDRESS_WINDOW));
        assert!(limit.0.len() <= MAX_ADDRESSES);
    }

    #[test]
    fn gateway_window_caps_and_resets() {
        let now = Instant::now();
        let mut window = None;
        for _ in 0..GATEWAY_CALLS {
            assert!(window_allows(&mut window, GATEWAY_CALLS, now));
        }
        assert!(!window_allows(&mut window, GATEWAY_CALLS, now + Duration::from_secs(59)));
        assert!(window_allows(&mut window, GATEWAY_CALLS, now + ADDRESS_WINDOW));
    }

    #[test]
    fn many_addresses_together_stop_at_the_gateway_cap() {
        // Enough addresses, each within its own share, to spend all of RDS's 1200 a minute.
        let now = Instant::now();
        let mut addresses = AddressLimit::default();
        let mut gateway = None;
        let (mut allowed, mut gateway_refused) = (0u32, 0u32);
        for i in 0..1200 / ADDRESS_CALLS {
            for _ in 0..ADDRESS_CALLS {
                match call_allowed(&mut addresses, &mut gateway, &format!("198.51.100.{i}"), now) {
                    Ok(()) => allowed += 1,
                    Err(CallRefusal::Gateway) => gateway_refused += 1,
                    Err(CallRefusal::Address) => panic!("no address went over its own share"),
                }
            }
        }
        assert_eq!(allowed, GATEWAY_CALLS);
        assert_eq!(gateway_refused, 1200 - GATEWAY_CALLS);
        assert_eq!(call_allowed(&mut addresses, &mut gateway, "203.0.113.1", now), Err(CallRefusal::Gateway));
        // An address over its own share is refused before it can spend the gateway's.
        let mut fresh = None;
        let mut one = AddressLimit::default();
        for _ in 0..ADDRESS_CALLS {
            assert_eq!(call_allowed(&mut one, &mut fresh, "203.0.113.2", now), Ok(()));
        }
        assert_eq!(call_allowed(&mut one, &mut fresh, "203.0.113.2", now), Err(CallRefusal::Address));
        assert_eq!(fresh.map(|(_, calls)| calls), Some(ADDRESS_CALLS));
        assert_eq!(CallRefusal::Address.response().status, 429);
        assert_eq!(CallRefusal::Gateway.response().status, 503);
        assert_eq!(call_allowed(&mut addresses, &mut gateway, "203.0.113.1", now + ADDRESS_WINDOW), Ok(()));
    }

    #[test]
    fn address_key_groups_ipv6_by_prefix() {
        assert_eq!(address_key("203.0.113.7"), "203.0.113.7");
        assert_eq!(address_key("203.0.113.7:51000"), "203.0.113.7");
        assert_eq!(address_key("::ffff:203.0.113.7"), "203.0.113.7");
        assert_eq!(address_key("2001:db8:1:2:aaaa::1"), "2001:db8:1:2::/64");
        assert_eq!(address_key("2001:db8:1:2:bbbb::9"), "2001:db8:1:2::/64");
        assert_eq!(address_key("[2001:db8:1:3::1]:443"), "2001:db8:1:3::/64");
        assert_eq!(address_key(""), "");
        assert_eq!(address_key(&"x".repeat(100)).len(), 64);
    }

    fn answer(status: u16, detail: &str) -> rds::Answer {
        rds::Answer { status, body: json!({ "detail": detail }) }
    }

    #[test]
    fn only_refusals_of_the_sign_in_end_it() {
        assert!(sign_in_refused(&answer(401, "RustDWeb session is not valid")));
        assert!(sign_in_refused(&answer(401, "RustDWeb session ended after inactivity")));
        assert!(sign_in_refused(&answer(401, "RustDWeb is turned off")));
        assert!(sign_in_refused(&answer(410, "RustDWeb session is not valid")));
        assert!(sign_in_refused(&answer(403, "This device is not the RustDWeb gateway")));
        // The gateway's own credential, or anything else RDS might say.
        assert!(!sign_in_refused(&answer(401, "Invalid or expired authentication")));
        assert!(!sign_in_refused(&answer(403, "Device is not approved")));
        assert!(!sign_in_refused(&answer(428, "Device key proof required")));
        assert!(!sign_in_refused(&answer(410, "Gone")));
        assert!(!sign_in_refused(&answer(404, "Not Found")));
        assert!(!sign_in_refused(&rds::Answer { status: 401, body: Value::Null }));
    }

    #[test]
    fn a_refused_gateway_credential_is_not_a_wrong_password() {
        assert!(!login_refused_the_gateway(&answer(401, LOGIN_REFUSED)));
        assert!(!login_refused_the_gateway(&answer(422, "String should have at most 64 characters")));
        assert!(login_refused_the_gateway(&answer(401, "Invalid or expired authentication")));
        assert!(login_refused_the_gateway(&rds::Answer { status: 401, body: Value::Null }));
        assert!(login_refused_the_gateway(&answer(428, "Device key proof required")));
    }

    fn pair(account: &str, peer: &str) -> (String, String) {
        (account.to_owned(), peer.to_owned())
    }

    #[test]
    fn session_starts_are_limited_per_account_and_pc() {
        let now = Instant::now();
        let mut limit = StartLimit::default();
        let minute = Duration::from_secs(60);
        for i in 0..MAX_STARTS as u32 {
            assert_eq!(limit.wait(&pair("a", "pc1"), now + minute * i), None);
            assert_eq!(limit.take(pair("a", "pc1"), now + minute * i), Ok(()));
        }
        let at = now + minute * 6;
        // The first start leaves the window four minutes from now.
        assert_eq!(limit.wait(&pair("a", "pc1"), at), Some(minute * 4));
        assert_eq!(limit.take(pair("a", "pc1"), at), Err(minute * 4));
        assert_eq!(limit.take(pair("a", "pc2"), at), Ok(()));
        assert_eq!(limit.take(pair("b", "pc1"), at), Ok(()));
        // A refused start is not counted: one more is allowed once the first has aged out.
        assert_eq!(limit.take(pair("a", "pc1"), now + START_WINDOW), Ok(()));
        assert!(limit.take(pair("a", "pc1"), now + START_WINDOW).is_err());
    }

    #[test]
    fn start_limit_table_stays_bounded() {
        let now = Instant::now();
        let mut limit = StartLimit::default();
        for i in 0..MAX_START_KEYS {
            assert_eq!(limit.take(pair("a", &format!("pc{i}")), now), Ok(()));
        }
        assert_eq!(limit.take(pair("a", "pc-new"), now), Err(START_WINDOW));
        assert_eq!(limit.take(pair("a", "pc0"), now), Ok(()));
        assert_eq!(limit.take(pair("a", "pc-new"), now + START_WINDOW), Ok(()));
        assert!(limit.0.len() <= MAX_START_KEYS);
    }

    #[test]
    fn start_refusal_is_a_429_with_the_wait() {
        let body = |response: Response| serde_json::from_slice::<Value>(&response.body).unwrap()["error"].clone();
        assert_eq!(start_refusal(Duration::from_secs(1)).status, 429);
        assert!(body(start_refusal(Duration::from_secs(1))).as_str().unwrap().ends_with("in 1 minute."));
        assert!(body(start_refusal(Duration::from_secs(61))).as_str().unwrap().ends_with("in 2 minutes."));
        assert!(body(start_refusal(START_WINDOW)).as_str().unwrap().ends_with("in 10 minutes."));
    }

    fn viewer(account: Value) -> Viewer {
        Viewer { token: String::new(), account, limits: Value::Null }
    }

    #[test]
    fn viewer_accounts_are_not_told_who_a_pc_is_in_session_with() {
        assert!(!viewer(json!({ "id": "x", "role": "viewer" })).sees_session_peers());
        assert!(!viewer(json!({ "id": "x" })).sees_session_peers());
        assert!(viewer(json!({ "id": "x", "role": "manager" })).sees_session_peers());
        let mut list = vec![
            json!({ "id": "1", "name": "PC", "online": true, "in_session_with": "Someone" }),
            json!({ "id": "2", "name": "PC 2", "online": false, "in_session_with": null }),
        ];
        hide_session_peers(&mut list);
        assert!(list.iter().all(|d| d.get("in_session_with").is_none()));
        assert_eq!(list[0]["name"], "PC");
        assert_eq!(list[1]["online"], false);
    }

    #[test]
    fn account_id_prefers_rds_id() {
        assert_eq!(viewer(json!({ "id": "1f0c", "username": "viewer1" })).account_id(), "1f0c");
        assert_eq!(viewer(json!({ "id": "", "username": "viewer1" })).account_id(), "viewer1");
        assert_eq!(viewer(json!({ "username": "viewer1" })).account_id(), "viewer1");
        assert_eq!(viewer(Value::Null).account_id(), "");
    }
}
