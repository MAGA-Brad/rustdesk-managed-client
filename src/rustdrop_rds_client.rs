// RustDrop's RDS API client. Ports the retired Electron client's
// rds-client.js one-to-one (same endpoints, same request/response shapes -
// the RDS backend itself needed zero changes for this rewrite). Identity
// is no longer fetched over IPC at all: this code runs in the same process
// as the rest of RDC's `--service`, so it calls directory_enrollment's own
// `pub(crate)` helpers directly - the exact functions that used to answer
// RustDrop's `GetDeviceCredentialRequest` IPC message.

use crate::hbbs_http::directory_enrollment::{current_device_id, current_directory_credential};
use crate::hbbs_http::create_http_client_async_with_url_strict;
use crate::managed_sealed::SendSealed;
use bytes::Bytes;
use futures::{Stream, StreamExt};
use serde::{Deserialize, Serialize};

const FILEDROP_PATH: &str = "/v1/filedrop";
// Small JSON calls (register/list/create/decline/complete) get a bounded
// timeout; upload/download bodies can be up to the 10 GiB drop cap and are
// given no timeout at all (per-request override below), matching the
// retired client's own REQUEST_TIMEOUT_MS/TRANSFER_TIMEOUT_MS split.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

#[derive(Debug)]
pub struct RdsError(pub String);

impl std::fmt::Display for RdsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rustdrop RDS client error: {}", self.0)
    }
}
impl std::error::Error for RdsError {}

pub type Result<T> = std::result::Result<T, RdsError>;

/// Starts the error of a 429. RDS limits each RustDrop route per address per minute
/// (security_extension.py), which a batch of many small files can reach.
pub const RATE_LIMITED: &str = "RDS rate limit reached";
const RATE_LIMIT_WAIT: std::time::Duration = std::time::Duration::from_secs(60);
const RATE_LIMIT_TRIES: u32 = 10;

/// `call` again after RDS's one-minute window while it answers 429, for up to ten minutes.
pub async fn retry_rate_limited<T, F, Fut>(what: &str, mut call: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let mut tries = 1;
    loop {
        match call().await {
            Err(e) if e.0.starts_with(RATE_LIMITED) && tries < RATE_LIMIT_TRIES => {
                hbb_common::log::info!(
                    "rustdrop: {what}: {}, trying again in {} s",
                    e.0,
                    RATE_LIMIT_WAIT.as_secs()
                );
                hbb_common::tokio::time::sleep(RATE_LIMIT_WAIT).await;
                tries += 1;
            }
            result => return result,
        }
    }
}

/// `reqwest::Error`'s own `Display` only ever prints its "kind" plus the
/// URL (e.g. "error sending request for url (...)") - the actual cause
/// (timeout, connection reset, TLS failure, DNS failure) lives in the
/// `source()` chain and is otherwise silently dropped from every log line
/// that formats the error with `{e}`. Walk the chain so failures are
/// actually diagnosable.
fn describe_reqwest_error(e: &reqwest::Error) -> String {
    let mut msg = e.to_string();
    let mut source = std::error::Error::source(e);
    while let Some(s) = source {
        msg.push_str(": ");
        msg.push_str(&s.to_string());
        source = s.source();
    }
    msg
}

#[derive(Debug, Clone)]
pub struct Identity {
    pub device_id: String,
    pub directory_base_url: String,
    pub directory_credential: String,
}

/// This device's own identity, read straight from local persisted
/// enrollment state - no network call, and no IPC round-trip either now
/// that this runs inside the same process as the rest of `--service`.
pub fn current_identity() -> Result<Identity> {
    let device_id = current_device_id().map_err(|e| RdsError(e.to_string()))?;
    let (directory_base_url, directory_credential) =
        current_directory_credential("rustdrop").map_err(|e| RdsError(e.to_string()))?;
    Ok(Identity {
        device_id,
        directory_base_url,
        directory_credential,
    })
}

/// While set, transfers go through the directory host because the transfer host was unreachable
/// from this network. Each request is one bounded part (at most MAX_PART_SIZE_BYTES).
static VIA_DIRECTORY_UNTIL_MS: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
const VIA_DIRECTORY_RECHECK_MS: i64 = 30 * 60 * 1000;

/// Called on a failed transfer request: a connection that never got going (refused, reset during
/// the TLS handshake) is a route problem, so the caller's retry goes the other way. A part that
/// merely timed out on a slow but working link is not.
fn note_transfer_failure(error: &reqwest::Error) {
    if !error.is_connect() {
        return;
    }
    let now = hbb_common::get_time();
    let previous = VIA_DIRECTORY_UNTIL_MS.swap(now + VIA_DIRECTORY_RECHECK_MS, std::sync::atomic::Ordering::Relaxed);
    if previous <= now {
        hbb_common::log::warn!(
            "rustdrop: transfer host unreachable ({}), sending transfers through the directory host for 30 minutes",
            describe_reqwest_error(error)
        );
    }
}

/// Upload/download bodies go via a separate transfer hostname
/// (filedrop.<domain>). Small JSON calls stay on `directory_base_url` as normal.
fn transfer_base_url(identity: &Identity) -> Result<String> {
    if hbb_common::get_time() < VIA_DIRECTORY_UNTIL_MS.load(std::sync::atomic::Ordering::Relaxed) {
        let url = url::Url::parse(&identity.directory_base_url)
            .map_err(|e| RdsError(format!("bad directory_base_url: {e}")))?;
        return Ok(url.origin().unicode_serialization());
    }
    let mut url = url::Url::parse(&identity.directory_base_url)
        .map_err(|e| RdsError(format!("bad directory_base_url: {e}")))?;
    let host = url
        .host_str()
        .ok_or_else(|| RdsError("directory_base_url has no host".into()))?;
    let new_host = match host.split_once('.') {
        Some((_, rest)) => format!("filedrop.{rest}"),
        None => format!("filedrop.{host}"),
    };
    url.set_host(Some(&new_host))
        .map_err(|e| RdsError(format!("failed to rewrite host: {e}")))?;
    Ok(url.origin().unicode_serialization())
}

/// The client for one transfer request to `base`. The transfer's own client was built for the
/// filedrop host and can't serve the directory-host fallback, which needs the directory host's own
/// client (ECH included).
async fn transfer_client_for(client: &reqwest::Client, base: &str, identity: &Identity) -> Result<reqwest::Client> {
    let directory = url::Url::parse(&identity.directory_base_url)
        .map_err(|e| RdsError(format!("bad directory_base_url: {e}")))?
        .origin()
        .unicode_serialization();
    if base != directory {
        return Ok(client.clone());
    }
    create_http_client_async_with_url_strict(base)
        .await
        .map_err(|e| RdsError(format!("failed to build HTTP client: {e}")))
}

async fn response_error_detail(response: reqwest::Response) -> String {
    let status = response.status();
    match response.json::<serde_json::Value>().await {
        Ok(body) => match body.get("detail") {
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
            None => format!("HTTP {status}"),
        },
        Err(_) => format!("HTTP {status}"),
    }
}

async fn request_json<T: serde::de::DeserializeOwned>(
    identity: &Identity,
    method: reqwest::Method,
    path: &str,
    body: Option<&impl Serialize>,
) -> Result<T> {
    crate::hbbs_http::rds_refusal::check(&identity.directory_credential)
        .map_err(|e| RdsError(e.to_string()))?;
    let url = format!("{}{}", identity.directory_base_url, path);

    // Once a host's TLS-capability probe is cached (see hbb_common::tls),
    // every later call takes a fast path that skips the probe entirely and
    // trusts the cached decision with zero validation - nothing normally
    // invalidates it on an actual request failure. A single transient
    // hiccup that makes rustls choke on a response from a given host used
    // to leave every retry forever reusing that same bad cached decision,
    // consistent for as long as the process stayed up (this is what
    // produced a 30+ minute outage previously - only a full process
    // restart, which wipes the in-memory table, cleared it). `is_connect()`
    // covers the actual failure category here (never got a real HTTP
    // response back at all - includes the TLS handshake itself), not a
    // successful connection that just returned a 4xx/5xx, which retrying
    // wouldn't fix and shouldn't mask.
    let mut attempt = 0;
    let response = loop {
        attempt += 1;
        hbb_common::log::debug!("diag: request_json: building client for {method} {url}");
        let client = create_http_client_async_with_url_strict(&url)
            .await
            .map_err(|e| RdsError(format!("failed to build HTTP client: {e}")))?;
        let mut builder = client
            .request(method.clone(), &url)
            .bearer_auth(&identity.directory_credential)
            .timeout(REQUEST_TIMEOUT);
        if let Some(b) = body {
            builder = builder.json(b);
        }
        hbb_common::log::debug!("diag: request_json: sending {method} {url}");
        match builder.send_sealed().await {
            Ok(response) => break response,
            Err(e) if attempt == 1 && e.is_connect() => {
                hbb_common::log::warn!(
                    "request_json: connect/TLS error on {method} {url}, resetting TLS cache and retrying once: {}",
                    describe_reqwest_error(&e)
                );
                hbb_common::tls::reset_tls_cache();
                continue;
            }
            Err(e) => {
                return Err(RdsError(format!(
                    "request failed: {}",
                    describe_reqwest_error(&e)
                )))
            }
        }
    };
    hbb_common::log::debug!(
        "diag: request_json: got response for {method} {url}, status={}",
        response.status()
    );
    if !response.status().is_success() {
        crate::hbbs_http::rds_refusal::note_refused(
            response.status().as_u16(),
            &identity.directory_credential,
        );
        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(RdsError(format!("{RATE_LIMITED}: {}", response_error_detail(response).await)));
        }
        return Err(RdsError(response_error_detail(response).await));
    }
    crate::hbbs_http::rds_refusal::note_success();
    let parsed = response
        .json::<T>()
        .await
        .map_err(|e| RdsError(format!("bad response JSON: {e}")));
    hbb_common::log::debug!(
        "diag: request_json: parsed body for {method} {url}, ok={}",
        parsed.is_ok()
    );
    parsed
}

#[derive(Debug, Serialize)]
struct RegisterDeviceRequest<'a> {
    public_key: &'a str,
    capabilities: &'a [&'a str],
}

/// Called on startup and periodically after - this is what makes a device
/// appear in *other* devices' send-to pickers. Carries this device's
/// current X25519 public key on every call (cheap, idempotent) rather than
/// a separate one-time registration.
pub async fn register_device(identity: &Identity, public_key_b64: &str) -> Result<()> {
    let _: serde_json::Value = request_json(
        identity,
        reqwest::Method::POST,
        &format!("{FILEDROP_PATH}/register"),
        Some(&RegisterDeviceRequest {
            public_key: public_key_b64,
            capabilities: &[
                crate::rustdrop_transfer::ZSTD_CHUNKS,
                crate::rustdrop_transfer::DROP_FORMAT_2,
            ],
        }),
    )
    .await?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: String,
    pub rustdesk_id: String,
    pub friendly_name: Option<String>,
    pub hostname: Option<String>,
    pub public_key: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct DevicesListResponse {
    devices: Vec<DeviceInfo>,
}

pub async fn list_devices(identity: &Identity) -> Result<Vec<DeviceInfo>> {
    let resp: DevicesListResponse = request_json::<DevicesListResponse>(
        identity,
        reqwest::Method::GET,
        &format!("{FILEDROP_PATH}/devices"),
        None::<&()>,
    )
    .await?;
    remember_capabilities(&resp.devices);
    Ok(resp.devices)
}

/// What each device advertised in its registration, as of this process's last list_devices. A send
/// lists the devices right before it starts, so send_file reads the recipient's formats from here.
static DEVICE_CAPABILITIES: std::sync::Mutex<
    Option<std::collections::HashMap<String, Vec<String>>>,
> = std::sync::Mutex::new(None);

fn remember_capabilities(devices: &[DeviceInfo]) {
    *DEVICE_CAPABILITIES.lock().unwrap() = Some(
        devices
            .iter()
            .map(|d| (d.device_id.clone(), d.capabilities.clone()))
            .collect(),
    );
}

fn remembered_capability(device_id: &str, capability: &str) -> Option<bool> {
    DEVICE_CAPABILITIES
        .lock()
        .unwrap()
        .as_ref()?
        .get(device_id)
        .map(|capabilities| capabilities.iter().any(|c| c == capability))
}

/// Whether `device_id` advertised `capability`; lists the devices once if it isn't known yet.
/// Anything unknown counts as not advertised, so a sender falls back to the older format.
pub async fn device_has_capability(identity: &Identity, device_id: &str, capability: &str) -> bool {
    if let Some(found) = remembered_capability(device_id, capability) {
        return found;
    }
    if let Err(e) = list_devices(identity).await {
        hbb_common::log::warn!("rustdrop: could not read device {device_id}'s formats: {e}");
    }
    remembered_capability(device_id, capability).unwrap_or(false)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DropInfo {
    pub id: String,
    pub sender_device_id: String,
    pub recipient_device_id: String,
    pub filename: String,
    pub declared_size: u64,
    pub status: String,
    pub content_sha256: Option<String>,
    pub sender_public_key: Option<String>,
    pub peer_friendly_name: Option<String>,
    pub peer_hostname: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
    #[serde(default)]
    pub downloading: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DropsList {
    pub incoming: Vec<DropInfo>,
    pub outgoing: Vec<DropInfo>,
}

pub async fn list_drops(identity: &Identity) -> Result<DropsList> {
    request_json(
        identity,
        reqwest::Method::GET,
        &format!("{FILEDROP_PATH}/drops"),
        None::<&()>,
    )
    .await
}

#[derive(Debug, Serialize)]
struct CreateDropRequest<'a> {
    recipient_device_id: &'a str,
    filename: &'a str,
    declared_size: u64,
    sender_public_key: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    drop_id: Option<&'a str>,
}

/// `drop_id`: chosen by a format-2 send (its key covers the id); None lets RDS choose.
pub async fn create_drop(
    identity: &Identity,
    recipient_device_id: &str,
    filename: &str,
    declared_size: u64,
    sender_public_key_b64: &str,
    drop_id: Option<&str>,
) -> Result<DropInfo> {
    request_json(
        identity,
        reqwest::Method::POST,
        &format!("{FILEDROP_PATH}/drops"),
        Some(&CreateDropRequest {
            recipient_device_id,
            filename,
            declared_size,
            sender_public_key: sender_public_key_b64,
            drop_id,
        }),
    )
    .await
}

pub async fn decline_drop(identity: &Identity, drop_id: &str) -> Result<()> {
    let _: serde_json::Value = request_json(
        identity,
        reqwest::Method::POST,
        &format!("{FILEDROP_PATH}/drops/{drop_id}/decline"),
        None::<&()>,
    )
    .await?;
    Ok(())
}

/// The sender takes back a drop it is uploading or has uploaded. RDS refuses (409) once the
/// recipient is downloading it.
pub async fn cancel_drop(identity: &Identity, drop_id: &str) -> Result<()> {
    let _: serde_json::Value = request_json(
        identity,
        reqwest::Method::POST,
        &format!("{FILEDROP_PATH}/drops/{drop_id}/cancel"),
        None::<&()>,
    )
    .await?;
    Ok(())
}

/// Called only after a full download + hash verification has succeeded -
/// marks the drop 'delivered' server-side so it stops reappearing as a
/// pending Incoming offer and drops off the sender's Sent list too.
pub async fn complete_drop(identity: &Identity, drop_id: &str) -> Result<()> {
    let _: serde_json::Value = request_json(
        identity,
        reqwest::Method::POST,
        &format!("{FILEDROP_PATH}/drops/{drop_id}/complete"),
        None::<&()>,
    )
    .await?;
    Ok(())
}

/// Client-facing resumable-transfer tuning, live-editable server-side (see
/// the RDS Config page) - fetched fresh per send/accept call rather than
/// cached across the process lifetime, so a Config-page edit takes effect
/// on the next transfer without a client restart. On a fetch failure
/// (network hiccup reaching RDS itself), falls back to fixed defaults
/// rather than blocking the transfer on a config call that isn't the
/// actual thing being transferred.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct TransferConfig {
    pub part_size_bytes: u64,
    pub min_throughput_bps: u64,
    pub stall_giveup_minutes: u64,
}

const FALLBACK_PART_SIZE_BYTES: u64 = 8 * 1024 * 1024;
const FALLBACK_MIN_THROUGHPUT_BPS: u64 = 100_000;
const FALLBACK_STALL_GIVEUP_MINUTES: u64 = 30;

impl TransferConfig {
    fn fallback() -> Self {
        TransferConfig {
            part_size_bytes: FALLBACK_PART_SIZE_BYTES,
            min_throughput_bps: FALLBACK_MIN_THROUGHPUT_BPS,
            stall_giveup_minutes: FALLBACK_STALL_GIVEUP_MINUTES,
        }
    }

    /// The per-part-request timeout this config implies: how long a part
    /// of `part_size_bytes` may take to move at the configured minimum
    /// acceptable throughput before it's considered stalled rather than
    /// just slow. This - not a flat constant - is the actual fix for the
    /// 20s client-level default silently capping what used to be a whole-
    /// file single request (see http_client.rs's configure_http_client!).
    pub fn part_timeout(&self) -> std::time::Duration {
        let bits = self.part_size_bytes.saturating_mul(8);
        let seconds = (bits / self.min_throughput_bps.max(1)).max(1);
        std::time::Duration::from_secs(seconds)
    }
}

/// Upper bound on one part. Parts are sized up front and may later go through the directory host
/// instead (see VIA_DIRECTORY_UNTIL_MS), so every route must accept a part this large.
const MAX_PART_SIZE_BYTES: u64 = 90 * 1024 * 1024;

pub async fn get_transfer_config(identity: &Identity) -> TransferConfig {
    let mut config = request_json::<TransferConfig>(
        identity,
        reqwest::Method::GET,
        &format!("{FILEDROP_PATH}/config"),
        None::<&()>,
    )
    .await
    .unwrap_or_else(|_| TransferConfig::fallback());
    config.part_size_bytes = config.part_size_bytes.min(MAX_PART_SIZE_BYTES);
    config
}

#[derive(Debug, Clone)]
pub struct PartAck {
    pub upload_offset: u64,
    pub complete: bool,
    pub content_sha256: Option<String>,
}

#[derive(Debug)]
pub enum PartUploadError {
    /// Connection reset, timeout, DNS hiccup - retry this same part.
    Transport(String),
    /// Server reports a different offset than assumed - resync via
    /// query_upload_offset() and continue from there, not a blind retry.
    OffsetMismatch { server_offset: u64 },
    /// Unrecoverable locally - wrong device, drop no longer accepting an
    /// upload, or the upload session is gone server-side (410).
    Fatal(String),
}

impl PartUploadError {
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            PartUploadError::Transport(_) | PartUploadError::OffsetMismatch { .. }
        )
    }
}

impl std::fmt::Display for PartUploadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PartUploadError::Transport(msg) => write!(f, "transport error: {msg}"),
            PartUploadError::OffsetMismatch { server_offset } => {
                write!(f, "offset mismatch, server has {server_offset} bytes")
            }
            PartUploadError::Fatal(msg) => write!(f, "{msg}"),
        }
    }
}
impl std::error::Error for PartUploadError {}

/// Built exactly once per logical transfer (send_file/accept_drop) and
/// reused for every part - `create_http_client_async_with_url_strict`
/// builds a fresh reqwest::Client (fresh connection pool, no warm
/// connections) on every call, so calling it per-part meant a brand new
/// TCP+TLS handshake for every single 8MiB part. Harmless-but-slow while
/// storage latency dominated; with fast storage, the per-part handshake
/// overhead became the actual bottleneck - seen on a multi-GB transfer
/// that stayed slow despite fast storage. One client, kept alive for the
/// whole transfer, lets reqwest's own connection pool actually do its job.
pub async fn build_transfer_client(identity: &Identity) -> Result<reqwest::Client> {
    let base = transfer_base_url(identity)?;
    create_http_client_async_with_url_strict(&base)
        .await
        .map_err(|e| RdsError(format!("failed to build HTTP client: {e}")))
}

/// One resumable-upload part PUT. `offset`/`declared_size` become the
/// Upload-Offset/Upload-Length headers (Upload-Length only sent at offset
/// 0, matching RDS's contract - it's meaningless on any later part).
/// `part` is a plain sized slice (not a wrapped stream) - reqwest sets
/// Content-Length automatically, and the caller already bounds it to one
/// TransferConfig::part_size_bytes-sized piece, so nothing here needs to
/// stream. `timeout` is TransferConfig::part_timeout() - an explicit
/// override that actually takes effect, unlike the old upload_drop's
/// belief that the shared client had no default (it does: 20s, see
/// http_client.rs). `client` is built once per transfer by
/// build_transfer_client and reused across every part - see its own doc
/// comment for why that matters.
pub async fn upload_drop_part(
    client: &reqwest::Client,
    identity: &Identity,
    drop_id: &str,
    offset: u64,
    part: &[u8],
    declared_size: u64,
    timeout: std::time::Duration,
) -> std::result::Result<PartAck, PartUploadError> {
    let base = transfer_base_url(identity).map_err(|e| PartUploadError::Fatal(e.0))?;
    let client = &transfer_client_for(client, &base, identity)
        .await
        .map_err(|e| PartUploadError::Transport(e.0))?;
    let url = format!("{base}{FILEDROP_PATH}/drops/{drop_id}/upload");

    let sent = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut builder = client
        .put(&url)
        .bearer_auth(&identity.directory_credential)
        .timeout(timeout)
        .header("Upload-Offset", offset.to_string())
        .header(reqwest::header::CONTENT_LENGTH, part.len())
        .body(watched_part_body(part, sent.clone()));
    if offset == 0 {
        builder = builder.header("Upload-Length", declared_size.to_string());
    }

    let response = hbb_common::tokio::select! {
        response = crate::managed_sealed::send_with_proof(builder) => response.map_err(|e| {
            note_transfer_failure(&e);
            PartUploadError::Transport(e.to_string())
        })?,
        idle = upload_stalled(&sent, part.len() as u64, UPLOAD_STALL_TIMEOUT, UPLOAD_RESPONSE_WAIT) => {
            return Err(PartUploadError::Transport(format!(
                "no upload progress for {} s",
                idle.as_secs()
            )));
        }
    };

    if response.status().as_u16() == 409 {
        let server_offset = response
            .headers()
            .get("upload-offset")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(offset);
        return Err(PartUploadError::OffsetMismatch { server_offset });
    }
    if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return Err(PartUploadError::Transport(response_error_detail(response).await));
    }
    if response.status().is_server_error() {
        // RDS's own relay code deliberately never fails the whole drop for
        // a transient hiccup relaying to the storage backend - its comments say plainly
        // "the client retries the same part on its own backoff instead."
        // Bucketing a 5xx into Fatal here silently defeated that design:
        // any transient server-side error (a storage-backend blip, a momentarily
        // broken storage-client connection) killed the transfer outright
        // instead of being retried the way the server-side design assumes.
        return Err(PartUploadError::Transport(response_error_detail(response).await));
    }
    if !response.status().is_success() {
        return Err(PartUploadError::Fatal(response_error_detail(response).await));
    }

    let headers = response.headers().clone();
    let upload_offset = headers
        .get("upload-offset")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(offset + part.len() as u64);
    let complete =
        headers.get("x-upload-complete").and_then(|v| v.to_str().ok()) == Some("true");
    let content_sha256 = headers
        .get("x-content-sha256")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    Ok(PartAck { upload_offset, complete, content_sha256 })
}

/// A part's body is handed to the connection one piece at a time, and the next piece is taken as
/// soon as the last one drains - seconds apart even at the throughput floor. None taken for this
/// long means the connection is dead; without this it held the part for the whole part_timeout
/// (about 3 h for 64 MiB at 50 kbit/s).
const UPLOAD_STALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
/// After the last piece, what the connection still buffers (up to about a MiB) must drain at the
/// link's speed before RDS can answer.
const UPLOAD_RESPONSE_WAIT: std::time::Duration = std::time::Duration::from_secs(300);
const UPLOAD_BODY_PIECE: usize = 64 * 1024;
const UPLOAD_STALL_CHECK: std::time::Duration = std::time::Duration::from_secs(5);

fn watched_part_body(part: &[u8], sent: std::sync::Arc<std::sync::atomic::AtomicU64>) -> reqwest::Body {
    reqwest::Body::wrap_stream(watched_part_pieces(part, sent))
}

fn watched_part_pieces(
    part: &[u8],
    sent: std::sync::Arc<std::sync::atomic::AtomicU64>,
) -> impl Stream<Item = std::result::Result<Bytes, std::convert::Infallible>> + Send + 'static {
    let part = Bytes::copy_from_slice(part);
    let len = part.len();
    let pieces = (0..len)
        .step_by(UPLOAD_BODY_PIECE)
        .map(move |start| part.slice(start..(start + UPLOAD_BODY_PIECE).min(len)));
    futures::stream::iter(pieces).map(move |piece| {
        sent.fetch_add(piece.len() as u64, std::sync::atomic::Ordering::Relaxed);
        Ok(piece)
    })
}

/// Resolves, with how long nothing moved, once no piece of a `len`-byte body has been taken for
/// `stall`, or the whole body went out and `response_wait` passed without an answer.
async fn upload_stalled(
    sent: &std::sync::atomic::AtomicU64,
    len: u64,
    stall: std::time::Duration,
    response_wait: std::time::Duration,
) -> std::time::Duration {
    let check = UPLOAD_STALL_CHECK.min(stall / 4);
    let mut last = sent.load(std::sync::atomic::Ordering::Relaxed);
    let mut since = std::time::Instant::now();
    loop {
        hbb_common::tokio::time::sleep(check).await;
        let now = sent.load(std::sync::atomic::Ordering::Relaxed);
        if now != last {
            last = now;
            since = std::time::Instant::now();
            continue;
        }
        let limit = if now >= len { response_wait } else { stall };
        if since.elapsed() >= limit {
            return since.elapsed();
        }
    }
}

/// "How many bytes does the server actually have for this drop" - called
/// at the start of any resume rather than trusting possibly-stale local
/// bookkeeping (an ack can be lost even though the server got the bytes).
/// RDS always answers with a real offset (0 if nothing's been uploaded
/// yet) rather than a 404 for an otherwise-valid drop, so this only
/// errors for a genuine auth/not-found/network failure.
pub async fn query_upload_offset(
    client: &reqwest::Client,
    identity: &Identity,
    drop_id: &str,
) -> Result<u64> {
    let base = transfer_base_url(identity)?;
    let client = &transfer_client_for(client, &base, identity).await?;
    let url = format!("{base}{FILEDROP_PATH}/drops/{drop_id}/upload");
    let response = crate::managed_sealed::send_with_proof(
        client
            .head(&url)
            .bearer_auth(&identity.directory_credential)
            .timeout(REQUEST_TIMEOUT),
    )
    .await
        .map_err(|e| {
            note_transfer_failure(&e);
            RdsError(format!("HEAD request failed: {}", describe_reqwest_error(&e)))
        })?;
    if !response.status().is_success() {
        return Err(RdsError(response_error_detail(response).await));
    }
    Ok(response
        .headers()
        .get("upload-offset")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0))
}

pub const SENDER_NOT_STARTED: &str = "the sender has not started uploading yet";
/// Starts the error of a download request that got no answer at all (the network, not RDS).
pub const DOWNLOAD_REQUEST_FAILED: &str = "download request failed";
/// Not DOWNLOAD_REQUEST_FAILED: asking again at the same offset gets the same answer, so the
/// receiver starts the drop over from byte 0 instead.
pub const DOWNLOAD_RESUME_MISALIGNED: &str = "download resumed at the wrong offset";

/// Whether a ranged download's bytes start where it asked. A 200 is the whole body from byte 0 (a
/// proxy that ignored Range); appended after the bytes already held, it would misalign every frame.
fn download_resumes_at(status: u16, content_range: Option<&str>, range_start: u64) -> bool {
    match status {
        200 => range_start == 0,
        206 => {
            content_range
                .and_then(|value| value.trim().strip_prefix("bytes "))
                .and_then(|value| value.split_once('-'))
                .and_then(|(start, _)| start.trim().parse::<u64>().ok())
                == Some(range_start)
        }
        _ => false,
    }
}

pub struct DownloadResponse {
    pub status: u16,
    pub content_sha256: Option<String>,
    pub byte_stream: std::pin::Pin<
        Box<dyn Stream<Item = std::result::Result<Bytes, reqwest::Error>> + Send>,
    >,
}

/// Exactly one HTTP request per call - retry-on-drop is the caller's job.
/// `range_start` (bytes already received in a prior interrupted attempt)
/// becomes a `Range: bytes=<n>-` header; `range_end`, when given, bounds it
/// to a closed `bytes=<n>-<m>` range - this is what makes `timeout` an
/// actually-correct fixed value instead of a guess (an open-ended range on
/// a multi-GB remaining download has no correct flat timeout).
pub async fn download_drop_chunks(
    client: &reqwest::Client,
    identity: &Identity,
    drop_id: &str,
    range_start: Option<u64>,
    range_end: Option<u64>,
    timeout: std::time::Duration,
) -> Result<DownloadResponse> {
    let base = transfer_base_url(identity)?;
    let client = &transfer_client_for(client, &base, identity).await?;
    let url = format!("{base}{FILEDROP_PATH}/drops/{drop_id}/download");
    let mut builder = client
        .get(&url)
        .bearer_auth(&identity.directory_credential)
        .timeout(timeout);
    if let Some(n) = range_start {
        let range_value = match range_end {
            Some(m) => format!("bytes={n}-{m}"),
            None => format!("bytes={n}-"),
        };
        builder = builder.header(reqwest::header::RANGE, range_value);
    }
    let response = crate::managed_sealed::send_with_proof(builder)
        .await
        .map_err(|e| {
            note_transfer_failure(&e);
            RdsError(format!("{DOWNLOAD_REQUEST_FAILED}: {}", describe_reqwest_error(&e)))
        })?;
    let status = response.status();
    // RDS waited for the sender's first bytes and none arrived; the window waits and retries. Any
    // other 409 (the drop failed) is final, or the window retried it forever (audit RDC-RUSTDROP#5).
    if status.as_u16() == 409 {
        let detail = response_error_detail(response).await;
        if detail.contains("still uploading") {
            return Err(RdsError(SENDER_NOT_STARTED.into()));
        }
        return Err(RdsError(detail));
    }
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return Err(RdsError(format!("{RATE_LIMITED}: {}", response_error_detail(response).await)));
    }
    if !status.is_success() && status.as_u16() != 206 {
        return Err(RdsError(response_error_detail(response).await));
    }
    if let Some(n) = range_start {
        let content_range = response
            .headers()
            .get(reqwest::header::CONTENT_RANGE)
            .and_then(|v| v.to_str().ok());
        if !download_resumes_at(status.as_u16(), content_range, n) {
            return Err(RdsError(format!(
                "{DOWNLOAD_RESUME_MISALIGNED}: asked for bytes from {n}, got HTTP {} with Content-Range {content_range:?}",
                status.as_u16()
            )));
        }
    }
    let content_sha256 = response
        .headers()
        .get("x-content-sha256")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    Ok(DownloadResponse {
        status: status.as_u16(),
        content_sha256,
        byte_stream: Box::pin(response.bytes_stream()),
    })
}

#[derive(Debug, Deserialize)]
pub struct SelfInfo {
    pub friendly_name: Option<String>,
    pub hostname: Option<String>,
}

pub async fn get_self(identity: &Identity) -> Result<SelfInfo> {
    request_json(
        identity,
        reqwest::Method::GET,
        "/v1/device/me",
        None::<&()>,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity(base_url: &str) -> Identity {
        Identity {
            device_id: "test-device".into(),
            directory_base_url: base_url.into(),
            directory_credential: "test-credential".into(),
        }
    }

    #[test]
    fn transfer_base_url_swaps_first_label() {
        let id = test_identity("https://client.example.com");
        assert_eq!(
            transfer_base_url(&id).unwrap(),
            "https://filedrop.example.com"
        );
    }

    #[test]
    fn transfer_base_url_preserves_port() {
        let id = test_identity("https://client.example.com:8443");
        let result = transfer_base_url(&id).unwrap();
        assert_eq!(result, "https://filedrop.example.com:8443");
    }

    #[test]
    fn transfer_base_url_rejects_garbage() {
        let id = test_identity("not a url");
        assert!(transfer_base_url(&id).is_err());
    }

    #[test]
    fn capabilities_come_from_the_last_device_list() {
        let device = |device_id: &str, capabilities: &[&str]| DeviceInfo {
            device_id: device_id.into(),
            rustdesk_id: "1".into(),
            friendly_name: None,
            hostname: None,
            public_key: None,
            capabilities: capabilities.iter().map(|c| c.to_string()).collect(),
        };
        remember_capabilities(&[
            device("new", &["zstd-chunks", "drop-format-2"]),
            device("old", &["zstd-chunks"]),
        ]);
        assert_eq!(remembered_capability("new", "drop-format-2"), Some(true));
        assert_eq!(remembered_capability("old", "drop-format-2"), Some(false));
        assert_eq!(remembered_capability("gone", "drop-format-2"), None);
        remember_capabilities(&[device("old", &["zstd-chunks", "drop-format-2"])]);
        assert_eq!(
            remembered_capability("old", "drop-format-2"),
            Some(true),
            "a newer list wins"
        );
        assert_eq!(remembered_capability("new", "drop-format-2"), None);
    }

    #[test]
    fn ranged_download_must_start_at_the_requested_byte() {
        assert!(download_resumes_at(200, None, 0));
        assert!(download_resumes_at(206, Some("bytes 0-99/100"), 0));
        assert!(download_resumes_at(206, Some("bytes 4096-8191/*"), 4096));

        // A proxy answering a resume with the whole body.
        assert!(!download_resumes_at(200, None, 4096));
        assert!(!download_resumes_at(200, Some("bytes 4096-8191/9000"), 4096));
        assert!(!download_resumes_at(206, Some("bytes 0-8191/9000"), 4096));
        assert!(!download_resumes_at(206, None, 4096));
        assert!(!download_resumes_at(206, Some("bytes */9000"), 4096));
        assert!(!download_resumes_at(204, None, 0));
    }

    use hbb_common::tokio;
    use std::sync::{atomic::{AtomicU64, Ordering}, Arc};
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn watched_part_pieces_carry_the_whole_part_and_count_it() {
        let part: Vec<u8> = (0..UPLOAD_BODY_PIECE * 2 + 7).map(|i| i as u8).collect();
        let sent = Arc::new(AtomicU64::new(0));
        let pieces: Vec<Bytes> = watched_part_pieces(&part, sent.clone())
            .map(|piece| piece.unwrap())
            .collect()
            .await;
        assert_eq!(pieces.len(), 3);
        assert_eq!(pieces.concat(), part);
        assert_eq!(sent.load(Ordering::Relaxed), part.len() as u64);

        let empty: Vec<_> = watched_part_pieces(&[], sent.clone()).collect().await;
        assert!(empty.is_empty());
    }

    #[tokio::test]
    async fn upload_stall_fires_when_no_piece_is_taken() {
        let sent = AtomicU64::new(3);
        let started = Instant::now();
        upload_stalled(&sent, 10, Duration::from_millis(200), Duration::from_secs(5)).await;
        let took = started.elapsed();
        assert!(took >= Duration::from_millis(200) && took < Duration::from_secs(2), "{took:?}");
    }

    #[tokio::test]
    async fn upload_stall_waits_longer_for_the_answer_once_the_body_is_out() {
        let sent = AtomicU64::new(10);
        let started = Instant::now();
        upload_stalled(&sent, 10, Duration::from_millis(200), Duration::from_millis(800)).await;
        assert!(started.elapsed() >= Duration::from_millis(800));
    }

    #[tokio::test]
    async fn upload_stall_keeps_waiting_while_pieces_move() {
        let sent = Arc::new(AtomicU64::new(0));
        let feeder = sent.clone();
        tokio::spawn(async move {
            for _ in 0..12 {
                tokio::time::sleep(Duration::from_millis(50)).await;
                feeder.fetch_add(1, Ordering::Relaxed);
            }
        });
        let started = Instant::now();
        upload_stalled(&sent, 100, Duration::from_millis(200), Duration::from_secs(5)).await;
        assert!(started.elapsed() >= Duration::from_millis(800), "{:?}", started.elapsed());
    }
}
