// RustDrop's Send/Accept orchestration. Ports the retired Electron client's
// rustdrop:send-file / rustdrop:accept-drop IPC handlers (main.js) one-to-
// one at the orchestration level - the crypto internals underneath already
// changed to a streaming AEAD, see rustdrop_crypto.rs's own doc comment.
//
// Deliberately does not touch rustdrop_keystore or the raw private key:
// both entry points take an already-derived symmetric `key` instead. Who's
// allowed to read the private key and call derive_key() is a privilege
// question for whatever process embeds this module (see rustdrop_service.rs's
// doc comment on the same ACL boundary managed_chat already solved) - this
// module only needs to be correct about the wire format and the filesystem,
// not about who's allowed to hold key material.

use crate::rustdrop_crypto::{
    ciphertext_size, Decryptor, Encryptor, FileMetadata, Tag, CHUNK_SIZE, STREAM_HEADER_BYTES,
};
use crate::rustdrop_rds_client::{self, DropInfo, Identity, TransferConfig};
use crate::rustdrop_save_path::AtomicFileWriter;
use bytes::{Bytes, BytesMut};
use futures::{Stream, StreamExt};
use hbb_common::tokio;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::{Duration, Instant};
use tokio::sync::watch;

#[derive(Debug)]
pub struct TransferError(pub String);

impl std::fmt::Display for TransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rustdrop transfer error: {}", self.0)
    }
}
impl std::error::Error for TransferError {}

pub type Result<T> = std::result::Result<T, TransferError>;

/// Active: making progress normally. Retrying: a part failed and is
/// backing off before trying again (automatic, no user action needed).
/// Paused: the user hit Pause - Resume is the only way out. Stalled: the
/// same gate as Paused, but set automatically after `stall_giveup_minutes`
/// of zero confirmed-offset progress despite what still looks like a
/// retryable failure - answers "does too-slow drop the transfer" (no; it
/// stops cleanly and visibly instead of retrying forever with no signal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferState {
    Active,
    Retrying,
    Paused,
    Stalled,
}

impl TransferState {
    fn as_str(self) -> &'static str {
        match self {
            TransferState::Active => "active",
            TransferState::Retrying => "retrying",
            TransferState::Paused => "paused",
            TransferState::Stalled => "stalled",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ProgressEntry {
    bytes_done: u64,
    total_bytes: u64,
    state: TransferState,
}

// In-memory upload/download progress + pause control, keyed by drop id, for
// the UI to poll/drive. Not persisted - a transfer in progress when the app
// closes just loses its progress display along with the transfer itself
// (matches the session-only nature of a send/accept in general, and the
// explicitly in-session-only scope of resumability here - surviving a full
// app restart would need the crypto stream's state persisted to disk,
// which this does not attempt). Entries are removed on completion (success
// or failure) so this can't grow unbounded over a long-lived process.
lazy_static::lazy_static! {
    static ref TRANSFER_PROGRESS: std::sync::RwLock<std::collections::HashMap<String, ProgressEntry>> =
        Default::default();
    static ref TRANSFER_CONTROL: std::sync::RwLock<std::collections::HashMap<String, watch::Sender<bool>>> =
        Default::default();
}

fn set_transfer_progress(drop_id: &str, bytes_done: u64, total_bytes: u64, state: TransferState) {
    TRANSFER_PROGRESS
        .write()
        .unwrap()
        .insert(drop_id.to_string(), ProgressEntry { bytes_done, total_bytes, state });
}

fn clear_transfer_progress(drop_id: &str) {
    TRANSFER_PROGRESS.write().unwrap().remove(drop_id);
    TRANSFER_CONTROL.write().unwrap().remove(drop_id);
}

/// `None` means "no active transfer for this drop" (not started yet,
/// already finished, or never tracked) - the UI treats that as "nothing to
/// show a progress bar for" rather than an error.
pub fn get_transfer_progress(drop_id: &str) -> Option<(u64, u64, &'static str)> {
    TRANSFER_PROGRESS
        .read()
        .unwrap()
        .get(drop_id)
        .map(|e| (e.bytes_done, e.total_bytes, e.state.as_str()))
}

fn register_transfer_control(drop_id: &str) -> watch::Receiver<bool> {
    let (tx, rx) = watch::channel(false);
    TRANSFER_CONTROL.write().unwrap().insert(drop_id.to_string(), tx);
    rx
}

/// Reused by both the explicit Pause button (FFI-driven) and the automatic
/// stall-giveup timer inside send_part_with_resync - same gate either way,
/// see TransferState's doc comment. Returns false when there's nothing to
/// pause (already finished, or never started).
pub fn pause_transfer(drop_id: &str) -> bool {
    match TRANSFER_CONTROL.read().unwrap().get(drop_id) {
        // send() only fails if the receiver (the transfer's own loop) has
        // already been dropped - i.e. the transfer is already finishing/
        // finished. Propagating that instead of always returning true means
        // the UI is told the truth about whether this pause actually did
        // anything, rather than reporting success for a no-op.
        Some(tx) => tx.send(true).is_ok(),
        None => false,
    }
}

pub fn resume_transfer(drop_id: &str) -> bool {
    match TRANSFER_CONTROL.read().unwrap().get(drop_id) {
        Some(tx) => tx.send(false).is_ok(),
        None => false,
    }
}

/// Blocks while the shared pause gate is set. Reflects Paused in the
/// progress entry while waiting, unless it's already showing the more
/// specific Stalled reason (the stall-detection call site sets that state
/// itself immediately before pausing) - and restores Active once the gate
/// lifts, so callers don't need their own "what state now" bookkeeping
/// around a pause.
async fn wait_while_paused(
    control_rx: &mut watch::Receiver<bool>,
    drop_id: &str,
    bytes_done: u64,
    total_bytes: u64,
) {
    if !*control_rx.borrow() {
        return;
    }
    let already_stalled = TRANSFER_PROGRESS
        .read()
        .unwrap()
        .get(drop_id)
        .map(|e| e.state == TransferState::Stalled)
        .unwrap_or(false);
    if !already_stalled {
        set_transfer_progress(drop_id, bytes_done, total_bytes, TransferState::Paused);
    }
    while *control_rx.borrow() {
        if control_rx.changed().await.is_err() {
            return;
        }
    }
    set_transfer_progress(drop_id, bytes_done, total_bytes, TransferState::Active);
}

impl TransferError {
    fn from_crypto(e: crate::rustdrop_crypto::CryptoError) -> Self {
        TransferError(e.to_string())
    }
    fn from_rds(e: crate::rustdrop_rds_client::RdsError) -> Self {
        TransferError(e.to_string())
    }
}

/// Reads exactly `chunk_size` bytes (looping over short reads), or fewer at
/// true EOF - the empty-Vec case is the only way callers can tell "no more
/// data", since a real file's last read can legitimately return between 1
/// and chunk_size-1 bytes without being EOF yet.
fn read_full_chunk(file: &mut std::fs::File, chunk_size: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; chunk_size];
    let mut filled = 0;
    while filled < chunk_size {
        let n = file.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    buf.truncate(filled);
    Ok(buf)
}

fn hash_and_size(path: &Path) -> std::io::Result<(String, u64)> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hex::encode(hasher.finalize()), total))
}

/// Runs on a blocking thread, pushing framed ciphertext into `tx` as it
/// goes - never buffers the whole (possibly 10 GiB) file or its ciphertext
/// in memory. Needs one-chunk lookahead to know which chunk is last (the
/// only one `Encryptor::finish` gets, since it consumes the encryptor) -
/// a plain "read until 0 bytes" loop can't tell a full CHUNK_SIZE read
/// apart from "coincidentally ended exactly on a boundary" without peeking
/// one read ahead.
/// Runs exactly once per `send_file` call, spawned before any transport
/// work starts and never respawned on retry or pause - the encryption
/// stream (libsodium secretstream) generates a fresh random header per
/// `Encryptor::new()` call, so recreating it mid-transfer would produce
/// ciphertext incompatible with anything already sent. Progress reporting
/// lives with the transport loop instead (confirmed server offset, not
/// bytes produced here) - what's produced-but-not-yet-delivered can sit
/// behind an arbitrarily long pause, so a producer-driven bar would look
/// done while nothing has actually left a paused connection.
fn encrypt_file_to_channel(
    path: &Path,
    key: [u8; 32],
    metadata: FileMetadata,
    tx: tokio::sync::mpsc::Sender<std::io::Result<Bytes>>,
) {
    let result: Result<()> = (|| {
        let (mut encryptor, header) = Encryptor::new(&key).map_err(TransferError::from_crypto)?;
        send_framed(&tx, header)?;
        let meta_framed = encryptor
            .push_metadata(&metadata)
            .map_err(TransferError::from_crypto)?;
        send_framed(&tx, meta_framed)?;

        let mut file = std::fs::File::open(path)
            .map_err(|e| TransferError(format!("failed to open {}: {e}", path.display())))?;
        let mut current = read_full_chunk(&mut file, CHUNK_SIZE)
            .map_err(|e| TransferError(format!("failed to read {}: {e}", path.display())))?;
        loop {
            let next = read_full_chunk(&mut file, CHUNK_SIZE)
                .map_err(|e| TransferError(format!("failed to read {}: {e}", path.display())))?;
            if next.is_empty() {
                let framed = encryptor
                    .finish(&current)
                    .map_err(TransferError::from_crypto)?;
                send_framed(&tx, framed)?;
                break;
            }
            let framed = encryptor
                .push_chunk(&current)
                .map_err(TransferError::from_crypto)?;
            send_framed(&tx, framed)?;
            current = next;
        }
        Ok(())
    })();
    if let Err(e) = result {
        let _ = tx.blocking_send(Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())));
    }
}

fn send_framed(tx: &tokio::sync::mpsc::Sender<std::io::Result<Bytes>>, framed: Vec<u8>) -> Result<()> {
    tx.blocking_send(Ok(Bytes::from(framed)))
        .map_err(|_| TransferError("upload was cancelled".into()))
}

/// Chunk encoding a recipient advertises in its RustDrop registration once it can decode it. Each
/// data chunk's plaintext is a flag byte followed by the chunk raw or zstd-compressed, whichever
/// is smaller, so the already-compressed parts of a file cost one byte per chunk.
pub const ZSTD_CHUNKS: &str = "zstd-chunks";
const CHUNK_RAW: u8 = 0;
const CHUNK_ZSTD: u8 = 1;
const ZSTD_LEVEL: i32 = 3;
/// Below this, compression saves too little to be worth another pass over the file.
const COMPRESS_MIN_FILE_BYTES: u64 = 1024 * 1024;
/// Media and archives are already compressed: the start of the file decides whether the rest is
/// worth compressing.
const COMPRESS_SAMPLE_BYTES: u64 = 4 * 1024 * 1024;
const COMPRESS_WORTHWHILE_RATIO: f64 = 0.9;
const COMPRESSED_PIECE_BYTES: usize = 256 * 1024;
const COMPRESSED_TEMP_PREFIX: &str = "rustdrop-send-";
const COMPRESSED_TEMP_STALE_AFTER: Duration = Duration::from_secs(24 * 60 * 60);
/// The compressed copy can approach the file's own size, so compression needs room for all of it
/// and still leaves this much free on the temp drive.
const COMPRESS_FREE_SPACE_MARGIN: u64 = 1024 * 1024 * 1024;
/// A file can start compressible and continue as already-compressed data (disk images, archives
/// with a text header); the running ratio is rechecked this often and the copy abandoned if it no
/// longer pays.
const COMPRESS_RECHECK_BYTES: u64 = 256 * 1024 * 1024;
const COMPRESS_KEEP_GOING_RATIO: f64 = 0.95;

/// A compressed drop's finished ciphertext. It is written before the upload because a drop
/// declares its exact size when it is created, and compressed sizes are only known afterwards.
/// Deleted when dropped, which is once its reader has handed every byte to the uploader.
struct CompressedCiphertext {
    path: PathBuf,
    len: u64,
}

impl Drop for CompressedCiphertext {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn encode_chunk(compressor: &mut zstd::bulk::Compressor<'_>, raw: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(raw.len() + 1);
    match compressor.compress(raw) {
        Ok(packed) if packed.len() < raw.len() => {
            encoded.push(CHUNK_ZSTD);
            encoded.extend_from_slice(&packed);
        }
        _ => {
            encoded.push(CHUNK_RAW);
            encoded.extend_from_slice(raw);
        }
    }
    encoded
}

fn decode_chunk(decompressor: &mut zstd::bulk::Decompressor<'_>, encoded: Vec<u8>) -> Result<Vec<u8>> {
    match encoded.split_first() {
        None => Ok(encoded),
        Some((&CHUNK_RAW, raw)) => Ok(raw.to_vec()),
        // Bounded to one chunk, so a malicious sender cannot make the recipient inflate a bomb.
        Some((&CHUNK_ZSTD, packed)) => decompressor
            .decompress(packed, CHUNK_SIZE)
            .map_err(|e| TransferError(format!("failed to decompress a chunk: {e}"))),
        Some((flag, _)) => Err(TransferError(format!("unknown chunk encoding flag {flag}"))),
    }
}

fn worth_compressing(path: &Path, compressor: &mut zstd::bulk::Compressor<'_>) -> std::io::Result<bool> {
    let mut file = std::fs::File::open(path)?;
    let (mut raw, mut encoded) = (0u64, 0u64);
    while raw < COMPRESS_SAMPLE_BYTES {
        let chunk = read_full_chunk(&mut file, CHUNK_SIZE)?;
        if chunk.is_empty() {
            break;
        }
        raw += chunk.len() as u64;
        encoded += encode_chunk(compressor, &chunk).len() as u64;
    }
    Ok(raw > 0 && (encoded as f64) < raw as f64 * COMPRESS_WORTHWHILE_RATIO)
}

/// A send cut short by a crash or power loss leaves its ciphertext behind.
fn remove_stale_compressed_temps() {
    let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    for entry in entries.flatten() {
        let ours = entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(COMPRESSED_TEMP_PREFIX));
        let stale = ours
            && entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|modified| modified.elapsed().ok())
                .is_some_and(|age| age > COMPRESSED_TEMP_STALE_AFTER);
        if stale {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

fn free_space_for(path: &Path) -> Option<u64> {
    use hbb_common::sysinfo::Disks;
    let path = path.to_string_lossy().to_lowercase();
    Disks::new_with_refreshed_list()
        .list()
        .iter()
        .filter(|disk| path.starts_with(&disk.mount_point().to_string_lossy().to_lowercase()))
        .max_by_key(|disk| disk.mount_point().as_os_str().len())
        .map(|disk| disk.available_space())
}

/// Ok(None): the file does not compress well enough, or the temp drive lacks room for the
/// compressed copy, so it goes raw exactly as before.
fn compress_and_encrypt_to_temp(
    path: &Path,
    key: &[u8; 32],
    metadata: &FileMetadata,
) -> std::io::Result<Option<CompressedCiphertext>> {
    let crypto_error = |e: crate::rustdrop_crypto::CryptoError| std::io::Error::other(e.to_string());
    let mut compressor = zstd::bulk::Compressor::new(ZSTD_LEVEL)?;
    if !worth_compressing(path, &mut compressor)? {
        return Ok(None);
    }
    remove_stale_compressed_temps();
    let needed = metadata.plaintext_size.saturating_add(COMPRESS_FREE_SPACE_MARGIN);
    let free = free_space_for(&std::env::temp_dir());
    if !free.is_some_and(|free| free >= needed) {
        hbb_common::log::info!(
            "rustdrop: not compressing, the temp drive has {free:?} bytes free and {needed} are needed"
        );
        return Ok(None);
    }
    let mut ciphertext = CompressedCiphertext {
        path: std::env::temp_dir().join(format!("{COMPRESSED_TEMP_PREFIX}{}.tmp", uuid::Uuid::new_v4())),
        len: 0,
    };
    let mut out = std::io::BufWriter::with_capacity(1024 * 1024, std::fs::File::create(&ciphertext.path)?);
    let (mut encryptor, header) = Encryptor::new(key).map_err(crypto_error)?;
    out.write_all(&header)?;
    out.write_all(&encryptor.push_metadata(metadata).map_err(crypto_error)?)?;

    let mut file = std::fs::File::open(path)?;
    let mut current = read_full_chunk(&mut file, CHUNK_SIZE)?;
    let (mut raw_done, mut encoded_done) = (0u64, 0u64);
    loop {
        let next = read_full_chunk(&mut file, CHUNK_SIZE)?;
        let encoded = encode_chunk(&mut compressor, &current);
        raw_done += current.len() as u64;
        encoded_done += encoded.len() as u64;
        if raw_done % COMPRESS_RECHECK_BYTES == 0
            && (encoded_done as f64) > raw_done as f64 * COMPRESS_KEEP_GOING_RATIO
        {
            hbb_common::log::info!(
                "rustdrop: stopped compressing at {raw_done} bytes ({encoded_done} encoded), sending raw"
            );
            return Ok(None);
        }
        if next.is_empty() {
            out.write_all(&encryptor.finish(&encoded).map_err(crypto_error)?)?;
            break;
        }
        out.write_all(&encryptor.push_chunk(&encoded).map_err(crypto_error)?)?;
        current = next;
    }
    ciphertext.len = out.into_inner().map_err(|e| e.into_error())?.metadata()?.len();
    Ok(Some(ciphertext))
}

async fn compress_for_upload(path: &Path, key: &[u8; 32], metadata: &FileMetadata) -> Option<CompressedCiphertext> {
    let (path, key) = (path.to_path_buf(), *key);
    let metadata = FileMetadata {
        encoding: Some(ZSTD_CHUNKS.to_string()),
        ..metadata.clone()
    };
    let plaintext_size = metadata.plaintext_size;
    match tokio::task::spawn_blocking(move || compress_and_encrypt_to_temp(&path, &key, &metadata)).await {
        Ok(Ok(Some(ciphertext))) => {
            hbb_common::log::info!(
                "rustdrop: compressed {plaintext_size} bytes to {} for sending",
                ciphertext.len
            );
            Some(ciphertext)
        }
        Ok(Ok(None)) => None,
        Ok(Err(e)) => {
            hbb_common::log::warn!("rustdrop: sending uncompressed, compression failed: {e}");
            None
        }
        Err(e) => {
            hbb_common::log::warn!("rustdrop: sending uncompressed, compression task failed: {e}");
            None
        }
    }
}

/// The compressed path's producer: the ciphertext already exists, so this only reads it out.
fn stream_ciphertext_to_channel(
    ciphertext: CompressedCiphertext,
    tx: tokio::sync::mpsc::Sender<std::io::Result<Bytes>>,
) {
    let result: Result<()> = (|| {
        let mut file = std::fs::File::open(&ciphertext.path)
            .map_err(|e| TransferError(format!("failed to open the compressed copy: {e}")))?;
        loop {
            let piece = read_full_chunk(&mut file, COMPRESSED_PIECE_BYTES)
                .map_err(|e| TransferError(format!("failed to read the compressed copy: {e}")))?;
            if piece.is_empty() {
                return Ok(());
            }
            send_framed(&tx, piece)?;
        }
    })();
    if let Err(e) = result {
        let _ = tx.blocking_send(Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())));
    }
}

const RETRY_DELAY_MIN: Duration = Duration::from_secs(10);
const RETRY_DELAY_MAX: Duration = Duration::from_secs(120);

/// One resumable-upload part, retried indefinitely (capped exponential
/// backoff) on any retryable failure - "any transport-level failure should
/// reconnect and continue" is the explicit scope here, so there's no hard
/// attempt cap the way the old whole-file retry loop had. Re-syncs via
/// query_upload_offset() after every failure rather than blindly resending,
/// so a lost ack in either direction still converges correctly. Gives up
/// (transitions to Stalled, same gate as manual Pause) only after
/// `stall_giveup` of continuous failure with zero forward progress -
/// answers "does a too-slow link just drop the transfer": no, it stops
/// cleanly and visibly instead of retrying forever unseen.
async fn send_part_with_resync(
    client: &reqwest::Client,
    identity: &Identity,
    drop_id: &str,
    offset: u64,
    part: &[u8],
    declared_size: u64,
    part_timeout: Duration,
    stall_giveup: Duration,
    control_rx: &mut watch::Receiver<bool>,
) -> Result<u64> {
    let mut current = offset;
    let mut backoff = RETRY_DELAY_MIN;
    let mut attempt_started_at = Instant::now();

    loop {
        wait_while_paused(control_rx, drop_id, current, declared_size).await;
        let slice = &part[(current - offset) as usize..];
        match rustdrop_rds_client::upload_drop_part(
            client, identity, drop_id, current, slice, declared_size, part_timeout,
        )
        .await
        {
            Ok(ack) => return Ok(ack.upload_offset),
            Err(e) if !e.is_retryable() => {
                return Err(TransferError(format!("upload failed: {e}")));
            }
            Err(e) => {
                if attempt_started_at.elapsed() > stall_giveup {
                    set_transfer_progress(drop_id, current, declared_size, TransferState::Stalled);
                    pause_transfer(drop_id);
                    wait_while_paused(control_rx, drop_id, current, declared_size).await;
                    attempt_started_at = Instant::now();
                    continue;
                }
                set_transfer_progress(drop_id, current, declared_size, TransferState::Retrying);
                hbb_common::log::warn!(
                    "rustdrop: part upload at offset {current} for drop {drop_id} failed, retrying: {e}"
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(RETRY_DELAY_MAX);
                if let Ok(server_offset) = rustdrop_rds_client::query_upload_offset(client, identity, drop_id).await {
                    if (offset..=offset + part.len() as u64).contains(&server_offset) {
                        current = server_offset;
                    }
                    // else: outside the expected window for this part -
                    // keep retrying at `current`, the next ack will resync.
                }
                // A failed query just means retry at `current` again -
                // the stall-giveup timer above is what bounds this, not
                // this specific query's own success/failure.
            }
        }
    }
}

/// Splits the live ciphertext byte stream (from the channel the producer
/// task is feeding) into TransferConfig::part_size_bytes-sized pieces and
/// sends each with send_part_with_resync. Sequential fill -> send -> wait-
/// for-ack, deliberately not pipelined: pipelining would only overlap the
/// producer's CPU-bound encryption latency (small) against network time
/// (the actual bottleneck on a slow link), and would double the bound on
/// how much unconfirmed data one failure can throw away. Bounds that
/// unconfirmed-and-not-yet-discardable buffer to about one part's worth
/// (~part_size_bytes plus whatever's already in the channel), never the
/// whole file - no on-disk spill buffer needed at this part size.
async fn upload_with_resume(
    client: &reqwest::Client,
    identity: &Identity,
    drop_id: &str,
    declared_size: u64,
    config: TransferConfig,
    mut rx: tokio::sync::mpsc::Receiver<std::io::Result<Bytes>>,
    mut control_rx: watch::Receiver<bool>,
) -> Result<()> {
    let part_size = config.part_size_bytes as usize;
    let part_timeout = config.part_timeout();
    let stall_giveup = Duration::from_secs(config.stall_giveup_minutes * 60);

    let mut confirmed_offset = rustdrop_rds_client::query_upload_offset(client, identity, drop_id)
        .await
        .unwrap_or(0);
    let mut pending = BytesMut::new();
    let mut producer_done = false;

    loop {
        wait_while_paused(&mut control_rx, drop_id, confirmed_offset, declared_size).await;

        while pending.len() < part_size && !producer_done {
            match rx.recv().await {
                Some(Ok(bytes)) => pending.extend_from_slice(&bytes),
                Some(Err(e)) => return Err(TransferError(format!("encryption failed: {e}"))),
                None => producer_done = true,
            }
        }
        if pending.is_empty() && producer_done {
            break;
        }

        let take = pending.len().min(part_size);
        let new_offset = send_part_with_resync(
            client,
            identity,
            drop_id,
            confirmed_offset,
            &pending[..take],
            declared_size,
            part_timeout,
            stall_giveup,
            &mut control_rx,
        )
        .await?;
        let advanced = (new_offset - confirmed_offset) as usize;
        let _ = pending.split_to(advanced);
        confirmed_offset = new_offset;
        set_transfer_progress(drop_id, confirmed_offset, declared_size, TransferState::Active);
    }
    Ok(())
}

/// Sender side. `key` must already be `derive_key(my_private_key,
/// recipient_public_key)` - see this module's doc comment for why the key
/// itself, not the private key, is this function's boundary.
pub async fn send_file(
    identity: &Identity,
    key: &[u8; 32],
    my_public_key_b64: &str,
    recipient_device_id: &str,
    local_path: &Path,
    recipient_decodes_zstd: bool,
) -> Result<DropInfo> {
    let filename = local_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| TransferError(format!("not a valid filename: {}", local_path.display())))?
        .to_string();

    let path_for_hash = local_path.to_path_buf();
    let (plaintext_sha256, plaintext_size) =
        tokio::task::spawn_blocking(move || hash_and_size(&path_for_hash))
            .await
            .map_err(|e| TransferError(format!("hashing task panicked: {e}")))?
            .map_err(|e| TransferError(format!("failed to hash {}: {e}", local_path.display())))?;

    let metadata = FileMetadata {
        plaintext_sha256,
        plaintext_size,
        encoding: None,
    };
    let compressed = if recipient_decodes_zstd && plaintext_size >= COMPRESS_MIN_FILE_BYTES {
        compress_for_upload(local_path, key, &metadata).await
    } else {
        None
    };
    let declared_size = match &compressed {
        Some(ciphertext) => ciphertext.len,
        None => ciphertext_size(&metadata, plaintext_size),
    };

    let drop = rustdrop_rds_client::create_drop(
        identity,
        recipient_device_id,
        &filename,
        declared_size,
        my_public_key_b64,
    )
    .await
    .map_err(TransferError::from_rds)?;

    let config = rustdrop_rds_client::get_transfer_config(identity).await;
    let client = rustdrop_rds_client::build_transfer_client(identity)
        .await
        .map_err(TransferError::from_rds)?;

    let (tx, rx) = tokio::sync::mpsc::channel::<std::io::Result<Bytes>>(4);
    let control_rx = register_transfer_control(&drop.id);
    set_transfer_progress(&drop.id, 0, declared_size, TransferState::Active);

    // Spawned exactly once, before any transport work starts, and never
    // respawned on retry or pause - see encrypt_file_to_channel's own doc
    // comment for why recreating this mid-transfer would corrupt the
    // stream.
    let path_for_encrypt = local_path.to_path_buf();
    let key_for_encrypt = *key;
    let metadata_for_encrypt = metadata.clone();
    tokio::task::spawn_blocking(move || match compressed {
        Some(ciphertext) => stream_ciphertext_to_channel(ciphertext, tx),
        None => encrypt_file_to_channel(&path_for_encrypt, key_for_encrypt, metadata_for_encrypt, tx),
    });

    let upload_result =
        upload_with_resume(&client, identity, &drop.id, declared_size, config, rx, control_rx)
            .await;
    clear_transfer_progress(&drop.id);
    upload_result.map(|()| drop)
}

/// Incrementally extracts fixed-size or length-prefixed pieces from an
/// arbitrarily-chunked byte stream - HTTP delivers bytes in whatever sizes
/// the network happens to give it, never aligned to our own framing.
/// `try_take_*` return `Ok(None)` (not an error) when more bytes are simply
/// needed - a partial frame mid-stream is the normal case, not a fault.
#[derive(Default)]
struct FrameReader {
    buf: Vec<u8>,
}

impl FrameReader {
    fn feed(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    fn try_take_exact(&mut self, n: usize) -> Option<Vec<u8>> {
        if self.buf.len() < n {
            return None;
        }
        let out = self.buf[..n].to_vec();
        self.buf.drain(..n);
        Some(out)
    }

    fn try_take_frame(&mut self) -> Result<Option<Vec<u8>>> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let len = Decryptor::read_chunk_len(&self.buf).map_err(TransferError::from_crypto)?;
        let total = 4 + len;
        if self.buf.len() < total {
            return Ok(None);
        }
        let frame = self.buf[4..total].to_vec();
        self.buf.drain(..total);
        Ok(Some(frame))
    }
}

type DownloadByteStream =
    Pin<Box<dyn Stream<Item = std::result::Result<Bytes, reqwest::Error>> + Send>>;

async fn open_download_stream(
    client: &reqwest::Client,
    identity: &Identity,
    drop_id: &str,
    from_offset: u64,
    part_size: u64,
    timeout: Duration,
) -> Result<DownloadByteStream> {
    let range_end = from_offset + part_size - 1;
    let response = rustdrop_rds_client::download_drop_chunks(
        client,
        identity,
        drop_id,
        Some(from_offset),
        Some(range_end),
        timeout,
    )
    .await
    .map_err(TransferError::from_rds)?;
    Ok(response.byte_stream)
}

/// Pulls frames out of a bounded-range byte stream, transparently opening
/// the next bounded range (same pattern as the upload side's per-part
/// retry) whenever the current one ends - whether that's a normal chunk
/// boundary (more data waiting) or a transport error. `ciphertext_offset`
/// is raw transport bytes fed into `reader` so far, not plaintext bytes -
/// Range operates below the crypto framing, so this is the number that has
/// to become the next request's start. The file-drop server's own tail-follow already
/// waits (up to its own idle timeout) for a still-uploading sender to
/// produce more bytes before ending a request, so a healthy resume always
/// makes forward progress on each re-open; three consecutive re-opens at
/// the *same* offset with nothing new is treated as a genuinely ended (or
/// truncated) stream rather than looped on forever.
async fn fill_until<T>(
    client: &reqwest::Client,
    identity: &Identity,
    drop_id: &str,
    ciphertext_offset: &mut u64,
    byte_stream: &mut DownloadByteStream,
    part_size: u64,
    timeout: Duration,
    reader: &mut FrameReader,
    mut try_take: impl FnMut(&mut FrameReader) -> Result<Option<T>>,
) -> Result<T> {
    let mut backoff = RETRY_DELAY_MIN;
    let mut stalls_at_same_offset = 0u32;
    let mut last_offset_seen = *ciphertext_offset;
    loop {
        if let Some(value) = try_take(reader)? {
            return Ok(value);
        }
        match byte_stream.next().await {
            Some(Ok(bytes)) => {
                *ciphertext_offset += bytes.len() as u64;
                reader.feed(&bytes);
            }
            Some(Err(e)) => {
                hbb_common::log::warn!(
                    "rustdrop: download stream error for drop {drop_id} at offset {ciphertext_offset}, retrying: {e}"
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(RETRY_DELAY_MAX);
                *byte_stream = open_download_stream(
                    client, identity, drop_id, *ciphertext_offset, part_size, timeout,
                )
                .await?;
            }
            None => {
                if *ciphertext_offset == last_offset_seen {
                    stalls_at_same_offset += 1;
                    if stalls_at_same_offset >= 3 {
                        return Err(TransferError("download stream ended unexpectedly".into()));
                    }
                } else {
                    stalls_at_same_offset = 0;
                    last_offset_seen = *ciphertext_offset;
                }
                *byte_stream = open_download_stream(
                    client, identity, drop_id, *ciphertext_offset, part_size, timeout,
                )
                .await?;
            }
        }
    }
}

async fn download_and_decrypt(
    client: &reqwest::Client,
    identity: &Identity,
    drop: &DropInfo,
    key: &[u8; 32],
    dest_dir: &Path,
    config: TransferConfig,
) -> Result<PathBuf> {
    let part_size = config.part_size_bytes;
    let timeout = config.part_timeout();
    let mut ciphertext_offset: u64 = 0;
    let mut byte_stream =
        open_download_stream(client, identity, &drop.id, ciphertext_offset, part_size, timeout)
            .await?;
    let mut reader = FrameReader::default();

    let header = fill_until(
        client, identity, &drop.id, &mut ciphertext_offset, &mut byte_stream, part_size, timeout,
        &mut reader, |r| Ok(r.try_take_exact(STREAM_HEADER_BYTES)),
    )
    .await?;
    let mut dec = Decryptor::new(&header, key).map_err(TransferError::from_crypto)?;

    let meta_frame = fill_until(
        client, identity, &drop.id, &mut ciphertext_offset, &mut byte_stream, part_size, timeout,
        &mut reader, FrameReader::try_take_frame,
    )
    .await?;
    let (meta_plain, tag) = dec.pull_chunk(&meta_frame).map_err(TransferError::from_crypto)?;
    if tag != Tag::Message {
        return Err(TransferError(
            "malformed drop: metadata chunk was marked Final".into(),
        ));
    }
    let metadata = Decryptor::parse_metadata(&meta_plain).map_err(TransferError::from_crypto)?;
    let mut decompressor = match metadata.encoding.as_deref() {
        None => None,
        Some(ZSTD_CHUNKS) => Some(
            zstd::bulk::Decompressor::new()
                .map_err(|e| TransferError(format!("failed to start decompression: {e}")))?,
        ),
        Some(other) => {
            return Err(TransferError(format!(
                "this drop was sent in a newer format ({other}); update RDC to receive it"
            )))
        }
    };

    let mut writer = AtomicFileWriter::create(dest_dir, &drop.filename)
        .map_err(|e| TransferError(format!("failed to create destination file: {e}")))?;
    let mut hasher = Sha256::new();
    let mut bytes_done: u64 = 0;
    loop {
        let frame = match fill_until(
            client, identity, &drop.id, &mut ciphertext_offset, &mut byte_stream, part_size, timeout,
            &mut reader, FrameReader::try_take_frame,
        )
        .await
        {
            Ok(frame) => frame,
            Err(e) => {
                // A repeatedly-stalled stream (fill_until gives up after 3
                // consecutive zero-progress reconnects) used to leave this
                // partial file behind forever - AtomicFileWriter's own doc
                // comment is explicit that dropping it is not a cleanup
                // hook, callers on an error path must call abort()
                // themselves.
                writer.abort();
                return Err(e);
            }
        };
        let (plain, tag) = match dec.pull_chunk(&frame) {
            Ok(result) => result,
            Err(e) => {
                // Same reasoning as above, for a corrupted/undecryptable
                // chunk mid-transfer.
                writer.abort();
                return Err(TransferError::from_crypto(e));
            }
        };
        let plain = match decompressor.as_mut() {
            Some(decompressor) => match decode_chunk(decompressor, plain) {
                Ok(plain) => plain,
                Err(e) => {
                    writer.abort();
                    return Err(e);
                }
            },
            None => plain,
        };
        hasher.update(&plain);
        bytes_done += plain.len() as u64;
        set_transfer_progress(&drop.id, bytes_done, metadata.plaintext_size, TransferState::Active);
        if let Err(e) = writer.file_mut().write_all(&plain) {
            writer.abort();
            return Err(TransferError(format!("failed to write downloaded data: {e}")));
        }
        if tag == Tag::Final {
            break;
        }
    }
    if !dec.is_finalized() {
        writer.abort();
        return Err(TransferError(
            "download ended without a valid Final chunk - truncated or tampered".into(),
        ));
    }

    let computed_hash = hex::encode(hasher.finalize());
    if computed_hash != metadata.plaintext_sha256 {
        writer.abort();
        return Err(TransferError(
            "downloaded file failed integrity verification - deleted, not saved".into(),
        ));
    }
    writer
        .finish()
        .map_err(|e| TransferError(format!("failed to finalize downloaded file: {e}")))
}

/// Recipient side. `key` must already be `derive_key(my_private_key,
/// drop.sender_public_key)`. Automatic resume lives inside
/// download_and_decrypt/fill_until now (network blips reconnect and
/// continue from the last received byte, same "any transport-level
/// failure should reconnect and continue" scope as the upload side) - this
/// outer retry is only for a failure category that resuming can't help
/// with at all (e.g. a real auth failure, or integrity verification
/// failing after a fully-received file). No manual Pause/Resume UI for
/// incoming drops in this pass - deliberately deferred, see the plan's
/// reasoning; the receiver's own partially-written file is already its own
/// source of truth for what it has, so this needed no resync mechanism
/// the way upload's query_upload_offset does.
pub async fn accept_drop(
    identity: &Identity,
    key: &[u8; 32],
    drop: &DropInfo,
    dest_dir: &Path,
) -> Result<PathBuf> {
    let config = rustdrop_rds_client::get_transfer_config(identity).await;
    let client = rustdrop_rds_client::build_transfer_client(identity)
        .await
        .map_err(TransferError::from_rds)?;
    let mut last_error = None;
    for _ in 0..2 {
        match download_and_decrypt(&client, identity, drop, key, dest_dir, config).await {
            Ok(path) => {
                clear_transfer_progress(&drop.id);
                if let Err(e) = rustdrop_rds_client::complete_drop(identity, &drop.id).await {
                    // Best-effort: the file is already safely saved, which is
                    // what matters to the user. A failed completion signal
                    // just means this drop may reappear once more next poll.
                    hbb_common::log::error!("rustdrop: failed to mark drop complete: {e}");
                }
                return Ok(path);
            }
            Err(e) => last_error = Some(e),
        }
    }
    clear_transfer_progress(&drop.id);
    Err(last_error.unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rustdrop_crypto::{derive_key, generate_keypair};
    use std::path::PathBuf;

    fn temp_file(contents: &[u8]) -> PathBuf {
        let path = std::env::temp_dir().join(format!("rustdrop_transfer_test_{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn read_full_chunk_splits_across_boundaries() {
        let path = temp_file(b"abcdefghij");
        let mut file = std::fs::File::open(&path).unwrap();
        assert_eq!(read_full_chunk(&mut file, 4).unwrap(), b"abcd");
        assert_eq!(read_full_chunk(&mut file, 4).unwrap(), b"efgh");
        assert_eq!(read_full_chunk(&mut file, 4).unwrap(), b"ij");
        assert_eq!(read_full_chunk(&mut file, 4).unwrap(), b"");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn read_full_chunk_on_empty_file_is_empty_then_stays_empty() {
        let path = temp_file(b"");
        let mut file = std::fs::File::open(&path).unwrap();
        assert_eq!(read_full_chunk(&mut file, 4).unwrap(), b"");
        assert_eq!(read_full_chunk(&mut file, 4).unwrap(), b"");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn hash_and_size_matches_known_vector() {
        // NIST test vector: sha256("abc").
        let path = temp_file(b"abc");
        let (hash, size) = hash_and_size(&path).unwrap();
        assert_eq!(
            hash,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(size, 3);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn hash_and_size_of_empty_file() {
        let path = temp_file(b"");
        let (hash, size) = hash_and_size(&path).unwrap();
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(size, 0);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn frame_reader_reassembles_frame_fed_in_arbitrary_pieces() {
        let mut reader = FrameReader::default();
        // A 3-byte "ciphertext" frame: 4-byte BE length prefix + payload,
        // fed in deliberately awkward byte-at-a-time and mid-frame pieces.
        let frame = [0u8, 0, 0, 3, b'x', b'y', b'z'];
        for byte in frame {
            assert!(reader.try_take_frame().unwrap().is_none());
            reader.feed(&[byte]);
        }
        assert_eq!(reader.try_take_frame().unwrap(), Some(vec![b'x', b'y', b'z']));
        assert_eq!(reader.try_take_frame().unwrap(), None);
    }

    #[test]
    fn chunk_encoding_roundtrips_and_picks_the_smaller_form() {
        let mut compressor = zstd::bulk::Compressor::new(ZSTD_LEVEL).unwrap();
        let mut decompressor = zstd::bulk::Decompressor::new().unwrap();
        let text = b"rustdrop ".repeat(CHUNK_SIZE / 9);
        let encoded = encode_chunk(&mut compressor, &text);
        assert_eq!(encoded[0], CHUNK_ZSTD);
        assert!(encoded.len() < text.len() / 10);
        assert_eq!(decode_chunk(&mut decompressor, encoded).unwrap(), text);

        let mut noise = vec![0u8; CHUNK_SIZE];
        sodiumoxide::randombytes::randombytes_into(&mut noise);
        let encoded = encode_chunk(&mut compressor, &noise);
        assert_eq!(encoded[0], CHUNK_RAW);
        assert_eq!(encoded.len(), CHUNK_SIZE + 1);
        assert_eq!(decode_chunk(&mut decompressor, encoded).unwrap(), noise);
    }

    #[test]
    fn chunk_decoding_refuses_more_than_one_chunk() {
        let mut decompressor = zstd::bulk::Decompressor::new().unwrap();
        let mut bomb = vec![CHUNK_ZSTD];
        bomb.extend_from_slice(&zstd::bulk::compress(&vec![0u8; CHUNK_SIZE + 1], ZSTD_LEVEL).unwrap());
        assert!(decode_chunk(&mut decompressor, bomb).is_err());
        assert!(decode_chunk(&mut decompressor, vec![7, 1, 2]).is_err());
    }

    #[test]
    fn compressed_ciphertext_decrypts_to_the_original() {
        let (pub_a, priv_a) = generate_keypair();
        let (pub_b, priv_b) = generate_keypair();
        let key_a = derive_key(&priv_a, &pub_b).unwrap();
        let key_b = derive_key(&priv_b, &pub_a).unwrap();
        let plaintext = b"0123456789 compressible line\n".repeat(150_000);
        let path = temp_file(&plaintext);
        let (plaintext_sha256, plaintext_size) = hash_and_size(&path).unwrap();
        let metadata = FileMetadata {
            plaintext_sha256,
            plaintext_size,
            encoding: Some(ZSTD_CHUNKS.to_string()),
        };

        let ciphertext = compress_and_encrypt_to_temp(&path, &key_a, &metadata).unwrap().unwrap();
        let wire = std::fs::read(&ciphertext.path).unwrap();
        assert_eq!(wire.len() as u64, ciphertext.len);
        assert!(ciphertext.len < plaintext_size / 10);
        let temp_path = ciphertext.path.clone();
        drop(ciphertext);
        assert!(!temp_path.exists());

        let mut reader = FrameReader::default();
        reader.feed(&wire);
        let mut dec = Decryptor::new(&reader.try_take_exact(STREAM_HEADER_BYTES).unwrap(), &key_b).unwrap();
        let (meta_plain, _) = dec.pull_chunk(&reader.try_take_frame().unwrap().unwrap()).unwrap();
        let parsed = Decryptor::parse_metadata(&meta_plain).unwrap();
        assert_eq!(parsed.encoding.as_deref(), Some(ZSTD_CHUNKS));
        let mut decompressor = zstd::bulk::Decompressor::new().unwrap();
        let mut decoded = Vec::new();
        loop {
            let (plain, tag) = dec.pull_chunk(&reader.try_take_frame().unwrap().unwrap()).unwrap();
            decoded.extend_from_slice(&decode_chunk(&mut decompressor, plain).unwrap());
            if tag == Tag::Final {
                break;
            }
        }
        assert_eq!(decoded, plaintext);
        assert_eq!(hex::encode(Sha256::digest(&decoded)), parsed.plaintext_sha256);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn incompressible_files_are_left_raw() {
        let mut noise = vec![0u8; 2 * 1024 * 1024];
        sodiumoxide::randombytes::randombytes_into(&mut noise);
        let path = temp_file(&noise);
        let metadata = FileMetadata {
            plaintext_sha256: String::new(),
            plaintext_size: noise.len() as u64,
            encoding: Some(ZSTD_CHUNKS.to_string()),
        };
        assert!(compress_and_encrypt_to_temp(&path, &[7u8; 32], &metadata).unwrap().is_none());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn frame_reader_take_exact() {
        let mut reader = FrameReader::default();
        reader.feed(&[1, 2]);
        assert_eq!(reader.try_take_exact(3), None);
        reader.feed(&[3, 4]);
        assert_eq!(reader.try_take_exact(3), Some(vec![1, 2, 3]));
        // Leftover byte stays buffered for the next take.
        assert_eq!(reader.try_take_exact(1), Some(vec![4]));
    }

    #[test]
    fn frame_reader_handles_multiple_frames_fed_at_once() {
        let mut reader = FrameReader::default();
        let mut wire = Vec::new();
        wire.extend_from_slice(&[0, 0, 0, 1, b'a']);
        wire.extend_from_slice(&[0, 0, 0, 2, b'b', b'c']);
        reader.feed(&wire);
        assert_eq!(reader.try_take_frame().unwrap(), Some(vec![b'a']));
        assert_eq!(reader.try_take_frame().unwrap(), Some(vec![b'b', b'c']));
        assert_eq!(reader.try_take_frame().unwrap(), None);
    }

    /// Encrypts a small in-memory file with rustdrop_crypto directly (same
    /// wire format download_and_decrypt consumes), then drives it through
    /// FrameReader exactly as the real download loop would - but fed in
    /// deliberately tiny, misaligned pieces to prove the framing survives
    /// arbitrary network chunking. No network or async runtime involved.
    #[test]
    fn frame_reader_plus_decryptor_roundtrips_a_full_wire_buffer() {
        let (pub_a, priv_a) = generate_keypair();
        let (pub_b, priv_b) = generate_keypair();
        let key_a = derive_key(&priv_a, &pub_b).unwrap();
        let key_b = derive_key(&priv_b, &pub_a).unwrap();

        let plaintext = b"the quick brown fox jumps over the lazy dog".to_vec();
        let metadata = FileMetadata {
            plaintext_sha256: hex::encode(Sha256::digest(&plaintext)),
            plaintext_size: plaintext.len() as u64,
            encoding: None,
        };

        let (mut enc, header) = Encryptor::new(&key_a).unwrap();
        let mut wire = header;
        wire.extend_from_slice(&enc.push_metadata(&metadata).unwrap());
        wire.extend_from_slice(&enc.finish(&plaintext).unwrap());

        let mut reader = FrameReader::default();
        // Feed 3 bytes at a time - guaranteed to split length prefixes and
        // ciphertext payloads across arbitrary boundaries.
        let mut fed = 0;
        let take = |r: &mut FrameReader, n: usize| loop {
            if let Some(v) = r.try_take_exact(n) {
                break v;
            }
        };
        let header_bytes = {
            while fed < STREAM_HEADER_BYTES {
                let end = (fed + 3).min(wire.len());
                reader.feed(&wire[fed..end]);
                fed = end;
            }
            take(&mut reader, STREAM_HEADER_BYTES)
        };
        let mut dec = Decryptor::new(&header_bytes, &key_b).unwrap();

        let take_frame = |r: &mut FrameReader, wire: &[u8], fed: &mut usize| loop {
            if let Some(v) = r.try_take_frame().unwrap() {
                break v;
            }
            let end = (*fed + 3).min(wire.len());
            r.feed(&wire[*fed..end]);
            *fed = end;
        };

        let meta_frame = take_frame(&mut reader, &wire, &mut fed);
        let (meta_plain, tag) = dec.pull_chunk(&meta_frame).unwrap();
        assert_eq!(tag, Tag::Message);
        let parsed_metadata = Decryptor::parse_metadata(&meta_plain).unwrap();

        let data_frame = take_frame(&mut reader, &wire, &mut fed);
        let (data_plain, tag) = dec.pull_chunk(&data_frame).unwrap();
        assert_eq!(tag, Tag::Final);
        assert!(dec.is_finalized());

        assert_eq!(data_plain, plaintext);
        assert_eq!(hex::encode(Sha256::digest(&data_plain)), parsed_metadata.plaintext_sha256);
    }
}
