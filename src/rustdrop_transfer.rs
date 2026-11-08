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
    ciphertext_size, derive_drop_key, Decryptor, Encryptor, FileMetadata, Tag, CHUNK_SIZE,
    STREAM_HEADER_BYTES,
};
use crate::rustdrop_rds_client::{self, DropInfo, Identity, TransferConfig};
use crate::rustdrop_save_path::{mark_from_internet, AtomicFileWriter};
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
    static ref TRANSFER_CANCEL: std::sync::RwLock<std::collections::HashMap<String, watch::Sender<bool>>> =
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
    TRANSFER_CANCEL.write().unwrap().remove(drop_id);
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

/// Ends with send_file's error, so the sender's window can tell a cancel from a failure.
pub const SEND_CANCELLED: &str = "sending was cancelled";

/// Stops this process's upload of a drop the sender cancelled. Call only after RDS accepted the
/// cancel: RDS refuses it while the recipient is downloading, and the upload must go on then.
pub fn cancel_transfer(drop_id: &str) -> bool {
    match TRANSFER_CANCEL.read().unwrap().get(drop_id) {
        Some(tx) => tx.send(true).is_ok(),
        None => false,
    }
}

async fn wait_cancelled(mut cancel_rx: watch::Receiver<bool>) {
    while !*cancel_rx.borrow() {
        if cancel_rx.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
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

/// In the error for a file that differs from what was hashed when the send started.
const FILE_CHANGED: &str = "the file changed while it was being sent";

/// Reads the file being sent as it was when hash_and_size measured it: never past that size, and
/// `verify` refuses it if it shrank, grew or changed since (audit RDC-RUSTDROP#6). Without this a
/// shrunk file left a short upload that the sender reported as sent.
struct PlaintextReader {
    file: std::fs::File,
    remaining: u64,
    hasher: Sha256,
}

impl PlaintextReader {
    fn open(path: &Path, size: u64) -> std::io::Result<Self> {
        Ok(PlaintextReader {
            file: std::fs::File::open(path)?,
            remaining: size,
            hasher: Sha256::new(),
        })
    }

    /// Like read_full_chunk with CHUNK_SIZE, ending where the hashed size ends.
    fn next_chunk(&mut self) -> std::io::Result<Vec<u8>> {
        let chunk = read_full_chunk(
            &mut self.file,
            self.remaining.min(CHUNK_SIZE as u64) as usize,
        )?;
        self.remaining -= chunk.len() as u64;
        self.hasher.update(&chunk);
        Ok(chunk)
    }

    /// Called before the final chunk is encrypted, so a changed file never yields a finished stream.
    fn verify(&mut self, metadata: &FileMetadata) -> std::io::Result<()> {
        let mut extra = [0u8; 1];
        let unchanged = self.remaining == 0
            && self.file.read(&mut extra)? == 0
            && hex::encode(self.hasher.finalize_reset()) == metadata.plaintext_sha256;
        if unchanged {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                FILE_CHANGED,
            ))
        }
    }
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

        let mut file = PlaintextReader::open(path, metadata.plaintext_size)
            .map_err(|e| TransferError(format!("failed to open {}: {e}", path.display())))?;
        let mut current = file
            .next_chunk()
            .map_err(|e| TransferError(format!("failed to read {}: {e}", path.display())))?;
        loop {
            let next = file
                .next_chunk()
                .map_err(|e| TransferError(format!("failed to read {}: {e}", path.display())))?;
            if next.is_empty() {
                file.verify(&metadata)
                    .map_err(|e| TransferError(format!("{}: {e}", path.display())))?;
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
/// Format a recipient advertises once it reads it: each drop encrypted under its own key
/// (rustdrop_crypto::derive_drop_key) with the file name inside the encrypted metadata. A sender
/// uses it only for recipients that advertise it, and every receiver still reads format 1.
pub const DROP_FORMAT_2: &str = "drop-format-2";
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

const FOLDER_ZIP_PREFIX: &str = "rustdrop-folder-";

/// A folder being sent: one stored zip of it, in a temp directory of its own so the file can carry
/// the folder's name ("Photos" goes as "Photos.zip"). Removed when the send ends.
struct FolderZip {
    dir: PathBuf,
    path: PathBuf,
}

impl Drop for FolderZip {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// What a crash or power loss left of a folder send.
fn remove_stale_folder_zips() {
    let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    for entry in entries.flatten() {
        let ours = entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(FOLDER_ZIP_PREFIX));
        let stale = ours
            && entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|modified| modified.elapsed().ok())
                .is_some_and(|age| age > COMPRESSED_TEMP_STALE_AFTER);
        if stale {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

struct FolderEntry {
    path: PathBuf,
    name: String,
    is_dir: bool,
}

/// Links and junctions are left out: following one could pull in files from outside the folder, or
/// loop forever.
fn list_folder(dir: &Path, prefix: &str, out: &mut Vec<FolderEntry>, total: &mut u64) -> std::io::Result<()> {
    let mut children = std::fs::read_dir(dir)?.collect::<std::io::Result<Vec<_>>>()?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        let file_type = child.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        let Some(name) = child.file_name().to_str().map(|name| format!("{prefix}/{name}")) else {
            hbb_common::log::warn!("rustdrop: leaving {} out of the zip, its name is not valid Unicode", child.path().display());
            continue;
        };
        let is_dir = file_type.is_dir();
        out.push(FolderEntry {
            path: child.path(),
            name: name.clone(),
            is_dir,
        });
        if is_dir {
            list_folder(&child.path(), &name, out, total)?;
        } else {
            *total = total.saturating_add(child.metadata()?.len());
        }
    }
    Ok(())
}

fn zip_entry_time(path: &Path) -> zip::DateTime {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|modified| {
            zip::DateTime::try_from(chrono::DateTime::<chrono::Local>::from(modified).naive_local()).ok()
        })
        .unwrap_or_default()
}

/// Stored, not deflated: a recipient that reads zstd chunks gets the zip compressed anyway, and an
/// already-compressed folder (photos, video) would only cost time.
fn zip_folder(folder: &Path) -> std::io::Result<FolderZip> {
    let name = folder
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| std::io::Error::other(format!("not a valid folder name: {}", folder.display())))?
        .to_string();
    let mut entries = Vec::new();
    let mut total = 0u64;
    list_folder(folder, &name, &mut entries, &mut total)?;
    remove_stale_folder_zips();
    let needed = total.saturating_add(COMPRESS_FREE_SPACE_MARGIN);
    let free = free_space_for(&std::env::temp_dir());
    if !free.is_some_and(|free| free >= needed) {
        return Err(std::io::Error::other(format!(
            "{NOT_ENOUGH_SPACE} to zip {name}: it needs {needed} bytes on the temp drive, {} are free",
            free.unwrap_or(0)
        )));
    }

    let dir = std::env::temp_dir().join(format!("{FOLDER_ZIP_PREFIX}{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir)?;
    let zipped = FolderZip {
        path: dir.join(format!("{name}.zip")),
        dir,
    };
    let file = std::fs::File::create(&zipped.path)?;
    let mut zip = zip::ZipWriter::new(std::io::BufWriter::with_capacity(1024 * 1024, file));
    let stored = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.add_directory(format!("{name}/"), stored.last_modified_time(zip_entry_time(folder)))
        .map_err(std::io::Error::other)?;
    for entry in &entries {
        let options = stored.last_modified_time(zip_entry_time(&entry.path));
        if entry.is_dir {
            zip.add_directory(format!("{}/", entry.name), options)
                .map_err(std::io::Error::other)?;
            continue;
        }
        let mut source = std::fs::File::open(&entry.path)?;
        let large = source.metadata()?.len() >= u32::MAX as u64;
        zip.start_file(entry.name.as_str(), options.large_file(large))
            .map_err(std::io::Error::other)?;
        std::io::copy(&mut source, &mut zip)?;
    }
    zip.finish().map_err(std::io::Error::other)?.flush()?;
    hbb_common::log::info!(
        "rustdrop: zipped {} entries ({total} bytes) of {name} for sending",
        entries.len()
    );
    Ok(zipped)
}

/// In every error a drop's own content causes (rustdrop_crypto's frame length check uses it too):
/// another attempt at the same drop fails the same way, so it is not retried.
const MALFORMED_DROP: &str = "malformed drop";
const NOT_ENOUGH_SPACE: &str = "not enough free space";
/// AEAD already rules out damage in transit, so downloading the drop again can't help.
const INTEGRITY_FAILED: &str = "downloaded file failed integrity verification";
const DOWNLOAD_STALLED: &str = "download made no progress";

/// Failures another download of the same drop would only repeat.
fn not_worth_retrying(e: &TransferError) -> bool {
    [
        MALFORMED_DROP,
        NOT_ENOUGH_SPACE,
        INTEGRITY_FAILED,
        DOWNLOAD_STALLED,
    ]
    .iter()
    .any(|reason| e.0.contains(reason))
}

/// Gives up a download nothing has arrived for in `stall_giveup` (the transfer config's
/// stall_giveup_minutes, as uploads use): each reconnect otherwise retried forever, e.g. on an
/// abandoned upload whose part timeout is shorter than storage's tail wait (audit RDC-RUSTDROP#11).
fn check_download_progress(last_progress_at: Instant, stall_giveup: Duration) -> Result<()> {
    if last_progress_at.elapsed() >= stall_giveup {
        return Err(TransferError(format!(
            "{DOWNLOAD_STALLED} for {} minutes",
            stall_giveup.as_secs() / 60
        )));
    }
    Ok(())
}

/// Opens the metadata chunk with format 2's drop key, else format 1's file key: a sender uses
/// format 2 only for recipients that advertise it, so either can arrive. The chunk is authenticated,
/// so only the key it was sealed with opens it.
fn open_metadata(
    header: &[u8],
    meta_frame: &[u8],
    drop_key: &[u8; 32],
    file_key: &[u8; 32],
) -> Result<(Decryptor, Vec<u8>, Tag)> {
    let mut dec = Decryptor::new(header, drop_key).map_err(TransferError::from_crypto)?;
    if let Ok((plain, tag)) = dec.pull_chunk(meta_frame) {
        return Ok((dec, plain, tag));
    }
    let mut dec = Decryptor::new(header, file_key).map_err(TransferError::from_crypto)?;
    let (plain, tag) = dec
        .pull_chunk(meta_frame)
        .map_err(TransferError::from_crypto)?;
    Ok((dec, plain, tag))
}

/// An oversized frame length can be ciphertext read at the wrong offset after a resume, so the
/// first time it is retried from byte 0; only a fresh download that hits it again is malformed.
fn misframed_on_first_attempt(e: &TransferError, attempt: u32) -> bool {
    attempt == 0 && e.0.contains(crate::rustdrop_crypto::OVERSIZED_CHUNK)
}
/// Room a received file must leave free on its volume.
const RECEIVE_FREE_SPACE_RESERVE: u64 = 512 * 1024 * 1024;

/// Checked against the authenticated metadata before anything is written. A raw drop's plaintext
/// is smaller than its ciphertext; a compressed one can be far larger, so the destination volume
/// must have room for all of it. download_and_decrypt then never writes more than it declares.
fn check_receive_size(
    metadata: &FileMetadata,
    declared_size: u64,
    free_space: Option<u64>,
) -> Result<()> {
    if metadata.encoding.is_none() && metadata.plaintext_size > declared_size {
        return Err(TransferError(format!(
            "{MALFORMED_DROP}: its metadata declares more data than it holds"
        )));
    }
    if let Some(free_space) = free_space {
        if metadata.plaintext_size.saturating_add(RECEIVE_FREE_SPACE_RESERVE) > free_space {
            return Err(TransferError(format!(
                "{NOT_ENOUGH_SPACE} to receive this file ({} MB, {} MB free)",
                metadata.plaintext_size >> 20,
                free_space >> 20
            )));
        }
    }
    Ok(())
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

    let mut file = PlaintextReader::open(path, metadata.plaintext_size)?;
    let mut current = file.next_chunk()?;
    let (mut raw_done, mut encoded_done) = (0u64, 0u64);
    loop {
        let next = file.next_chunk()?;
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
            file.verify(metadata)?;
            out.write_all(&encryptor.finish(&encoded).map_err(crypto_error)?)?;
            break;
        }
        out.write_all(&encryptor.push_chunk(&encoded).map_err(crypto_error)?)?;
        current = next;
    }
    ciphertext.len = out.into_inner().map_err(|e| e.into_error())?.metadata()?.len();
    Ok(Some(ciphertext))
}

/// Err only when the file changed while it was being compressed: sending it raw would fail the same way.
async fn compress_for_upload(
    path: &Path,
    key: &[u8; 32],
    metadata: &FileMetadata,
) -> Result<Option<CompressedCiphertext>> {
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
            Ok(Some(ciphertext))
        }
        Ok(Ok(None)) => Ok(None),
        Ok(Err(e))
            if e.kind() == std::io::ErrorKind::InvalidData && e.to_string() == FILE_CHANGED =>
        {
            Err(TransferError(FILE_CHANGED.into()))
        }
        Ok(Err(e)) => {
            hbb_common::log::warn!("rustdrop: sending uncompressed, compression failed: {e}");
            Ok(None)
        }
        Err(e) => {
            hbb_common::log::warn!("rustdrop: sending uncompressed, compression task failed: {e}");
            Ok(None)
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
                set_transfer_progress(drop_id, current, declared_size, TransferState::Retrying);
                hbb_common::log::warn!(
                    "rustdrop: part upload at offset {current} for drop {drop_id} failed, retrying: {e}"
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(RETRY_DELAY_MAX);
                if let Ok(server_offset) = rustdrop_rds_client::query_upload_offset(client, identity, drop_id).await {
                    if (offset..=offset + part.len() as u64).contains(&server_offset) {
                        // Storage keeps what a failed attempt delivered, so a slow part that fails
                        // late still made progress; the give-up timer counts from that.
                        if server_offset > current {
                            attempt_started_at = Instant::now();
                        }
                        current = server_offset;
                    }
                    // else: outside the expected window for this part -
                    // keep retrying at `current`, the next ack will resync.
                }
                // A failed query just means retry at `current` again -
                // the stall-giveup timer below is what bounds this, not
                // this specific query's own success/failure.
                if attempt_started_at.elapsed() > stall_giveup {
                    set_transfer_progress(drop_id, current, declared_size, TransferState::Stalled);
                    pause_transfer(drop_id);
                    wait_while_paused(control_rx, drop_id, current, declared_size).await;
                    attempt_started_at = Instant::now();
                }
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
    if confirmed_offset != declared_size {
        return Err(TransferError(format!(
            "the upload ended at byte {confirmed_offset} of {declared_size}"
        )));
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
    // Zipped when its turn comes, so a queue of folders holds one temp copy at a time.
    let folder_zip = if local_path.is_dir() {
        let folder = local_path.to_path_buf();
        Some(
            tokio::task::spawn_blocking(move || zip_folder(&folder))
                .await
                .map_err(|e| TransferError(format!("zipping task panicked: {e}")))?
                .map_err(|e| TransferError(format!("failed to zip {}: {e}", local_path.display())))?,
        )
    } else {
        None
    };
    let local_path = folder_zip.as_ref().map_or(local_path, |zipped| zipped.path.as_path());
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

    // Format 2 only for a recipient that reads it. Its key needs the drop id, and a compressed drop
    // is encrypted before it exists, so this end picks the id and RDS records it.
    let drop_id =
        rustdrop_rds_client::device_has_capability(identity, recipient_device_id, DROP_FORMAT_2)
            .await
            .then(|| uuid::Uuid::new_v4().to_string());
    let drop_key = match &drop_id {
        Some(drop_id) => derive_drop_key(key, &identity.device_id, recipient_device_id, drop_id)
            .map_err(TransferError::from_crypto)?,
        None => *key,
    };
    let key = &drop_key;
    let metadata = FileMetadata {
        plaintext_sha256,
        plaintext_size,
        encoding: None,
        filename: drop_id.as_ref().map(|_| filename.clone()),
    };
    let compressed = if recipient_decodes_zstd && plaintext_size >= COMPRESS_MIN_FILE_BYTES {
        compress_for_upload(local_path, key, &metadata).await?
    } else {
        None
    };
    let declared_size = match &compressed {
        Some(ciphertext) => ciphertext.len,
        None => ciphertext_size(&metadata, plaintext_size),
    };

    let drop = rustdrop_rds_client::retry_rate_limited("creating the drop", || {
        rustdrop_rds_client::create_drop(
            identity,
            recipient_device_id,
            &filename,
            declared_size,
            my_public_key_b64,
            drop_id.as_deref(),
        )
    })
    .await
    .map_err(TransferError::from_rds)?;
    // The new drop shows in this window's Sent list (with its progress) right away.
    #[cfg(windows)]
    crate::hbbs_http::managed_sync::note_local_drops_change();
    if drop_id.as_deref().is_some_and(|wanted| wanted != drop.id) {
        cancel_failed_send(identity, &drop.id).await;
        return Err(TransferError(
            "the server did not keep the drop id this file was encrypted for - update RDS".into(),
        ));
    }

    let config = rustdrop_rds_client::get_transfer_config(identity).await;
    let client = match rustdrop_rds_client::build_transfer_client(identity).await {
        Ok(client) => client,
        Err(e) => {
            cancel_failed_send(identity, &drop.id).await;
            return Err(TransferError::from_rds(e));
        }
    };

    let (tx, rx) = tokio::sync::mpsc::channel::<std::io::Result<Bytes>>(4);
    let control_rx = register_transfer_control(&drop.id);
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let cancelled = cancel_rx.clone();
    TRANSFER_CANCEL.write().unwrap().insert(drop.id.clone(), cancel_tx);
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

    let upload_result = {
        let upload =
            upload_with_resume(&client, identity, &drop.id, declared_size, config, rx, control_rx);
        tokio::pin!(upload);
        tokio::select! {
            biased;
            r = &mut upload => r,
            _ = wait_cancelled(cancel_rx) => Err(TransferError(format!("{filename}: {SEND_CANCELLED}"))),
            _ = wait_until_drop_gone(identity, &drop.id) => {
                // A delivered drop leaves the list too, so let a finishing upload answer first.
                match tokio::time::timeout(Duration::from_secs(5), &mut upload).await {
                    Ok(r) => r,
                    Err(_) => Err(TransferError(format!(
                        "{filename} was declined, so the upload stopped"
                    ))),
                }
            }
        }
    };
    // RDS deleted the drop before the signal arrived, so the upload may have ended on its own.
    let upload_result = if *cancelled.borrow() {
        Err(TransferError(format!("{filename}: {SEND_CANCELLED}")))
    } else {
        upload_result
    };
    clear_transfer_progress(&drop.id);
    // Storage and RDS answer a deleted drop's next part with these; say what happened instead.
    let upload_result = upload_result.map_err(|e| {
        if e.0.contains("no longer exists") || e.0.contains("Drop not found") {
            TransferError(format!(
                "{filename} was declined or removed from the server, so the upload stopped"
            ))
        } else {
            e
        }
    });
    if let Err(e) = &upload_result {
        if !e.0.contains(SEND_CANCELLED) && !e.0.contains(" was declined") {
            cancel_failed_send(identity, &drop.id).await;
        }
    }
    upload_result.map(|()| drop)
}

/// A send that failed after its drop was created takes the drop back, so the recipient isn't left
/// with an offer that can never finish (audit RDC-RUSTDROP#5). RDS refuses while the recipient is
/// downloading it, which is only logged.
async fn cancel_failed_send(identity: &Identity, drop_id: &str) {
    match rustdrop_rds_client::cancel_drop(identity, drop_id).await {
        Ok(()) => {
            hbb_common::log::info!("rustdrop: took back drop {drop_id} after its send failed")
        }
        Err(e) => {
            hbb_common::log::warn!(
                "rustdrop: could not take back drop {drop_id} after its send failed: {e}"
            )
        }
    }
    #[cfg(windows)]
    crate::hbbs_http::managed_sync::note_local_drops_change();
}

/// How often a running send checks that its drop still exists. A part in flight only hears of a
/// decline once its whole body is sent, which can take many minutes on a slow uplink.
const DROP_GONE_CHECK: Duration = Duration::from_secs(20);

async fn wait_until_drop_gone(identity: &Identity, drop_id: &str) {
    loop {
        tokio::time::sleep(DROP_GONE_CHECK).await;
        match rustdrop_rds_client::list_drops(identity).await {
            Ok(list) if !list.outgoing.iter().any(|d| d.id == drop_id) => return,
            Ok(_) => {}
            Err(e) => hbb_common::log::debug!("rustdrop: checking drop {drop_id} failed: {e}"),
        }
    }
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

/// No bytes for this long means the download connection is dead, unless storage is still waiting
/// on the sender. Without it a dead connection held the download for the whole part_timeout.
const DOWNLOAD_STALL_TIMEOUT: Duration = Duration::from_secs(120);
/// Storage holds a download of a drop still being uploaded open up to 10 minutes for the sender's
/// next bytes, then ends it; a response silent for longer than this is dead either way.
const DOWNLOAD_TAIL_WAIT_MAX: Duration = Duration::from_secs(12 * 60);
/// How long a dead download keeps trying to reconnect while the network is down.
const DOWNLOAD_RECONNECT_GIVEUP: Duration = Duration::from_secs(30 * 60);

async fn next_download_piece(
    identity: &Identity,
    drop_id: &str,
    byte_stream: &mut DownloadByteStream,
) -> Option<std::result::Result<Bytes, String>> {
    let waiting_since = Instant::now();
    loop {
        if let Ok(item) = tokio::time::timeout(DOWNLOAD_STALL_TIMEOUT, byte_stream.next()).await {
            return item.map(|r| r.map_err(|e| e.to_string()));
        }
        let waited = waiting_since.elapsed();
        if waited >= DOWNLOAD_TAIL_WAIT_MAX || !sender_still_uploading(identity, drop_id).await {
            return Some(Err(format!("no data for {} s", waited.as_secs())));
        }
    }
}

async fn sender_still_uploading(identity: &Identity, drop_id: &str) -> bool {
    match rustdrop_rds_client::list_drops(identity).await {
        Ok(list) => list.incoming.iter().any(|d| d.id == drop_id && d.status == "uploading"),
        Err(_) => false,
    }
}

/// open_download_stream for a stream that died or ended. Keeps retrying while the request gets no
/// answer at all, so an outage longer than the stall timeout doesn't fail the download; anything
/// RDS answers stays final.
async fn reopen_download_stream(
    client: &reqwest::Client,
    identity: &Identity,
    drop_id: &str,
    from_offset: u64,
    part_size: u64,
    timeout: Duration,
) -> Result<DownloadByteStream> {
    let started = Instant::now();
    let mut backoff = RETRY_DELAY_MIN;
    loop {
        match open_download_stream(client, identity, drop_id, from_offset, part_size, timeout).await {
            Err(e)
                if e.0.contains(rustdrop_rds_client::DOWNLOAD_REQUEST_FAILED)
                    && started.elapsed() < DOWNLOAD_RECONNECT_GIVEUP =>
            {
                hbb_common::log::warn!(
                    "rustdrop: reconnecting the download of drop {drop_id} failed, retrying: {e}"
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(RETRY_DELAY_MAX);
            }
            result => return result,
        }
    }
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
    stall_giveup: Duration,
    reader: &mut FrameReader,
    mut try_take: impl FnMut(&mut FrameReader) -> Result<Option<T>>,
) -> Result<T> {
    let mut backoff = RETRY_DELAY_MIN;
    let mut stalls_at_same_offset = 0u32;
    let mut last_offset_seen = *ciphertext_offset;
    let mut last_progress_at = Instant::now();
    loop {
        if let Some(value) = try_take(reader)? {
            return Ok(value);
        }
        match next_download_piece(identity, drop_id, byte_stream).await {
            Some(Ok(bytes)) => {
                if !bytes.is_empty() {
                    last_progress_at = Instant::now();
                }
                *ciphertext_offset += bytes.len() as u64;
                reader.feed(&bytes);
            }
            Some(Err(e)) => {
                check_download_progress(last_progress_at, stall_giveup)?;
                hbb_common::log::warn!(
                    "rustdrop: download stream error for drop {drop_id} at offset {ciphertext_offset}, retrying: {e}"
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(RETRY_DELAY_MAX);
                *byte_stream = reopen_download_stream(
                    client, identity, drop_id, *ciphertext_offset, part_size, timeout,
                )
                .await?;
            }
            None => {
                check_download_progress(last_progress_at, stall_giveup)?;
                if *ciphertext_offset == last_offset_seen {
                    stalls_at_same_offset += 1;
                    if stalls_at_same_offset >= 3 {
                        return Err(TransferError("download stream ended unexpectedly".into()));
                    }
                } else {
                    stalls_at_same_offset = 0;
                    last_offset_seen = *ciphertext_offset;
                }
                *byte_stream = reopen_download_stream(
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
    let stall_giveup = Duration::from_secs(config.stall_giveup_minutes * 60);
    let mut ciphertext_offset: u64 = 0;
    let mut byte_stream =
        open_download_stream(client, identity, &drop.id, ciphertext_offset, part_size, timeout)
            .await?;
    let mut reader = FrameReader::default();

    let header = fill_until(
        client, identity, &drop.id, &mut ciphertext_offset, &mut byte_stream, part_size, timeout,
        stall_giveup, &mut reader, |r| Ok(r.try_take_exact(STREAM_HEADER_BYTES)),
    )
    .await?;

    let meta_frame = fill_until(
        client, identity, &drop.id, &mut ciphertext_offset, &mut byte_stream, part_size, timeout,
        stall_giveup, &mut reader, FrameReader::try_take_frame,
    )
    .await?;
    let drop_key = derive_drop_key(
        key,
        &drop.sender_device_id,
        &drop.recipient_device_id,
        &drop.id,
    )
    .map_err(TransferError::from_crypto)?;
    let (mut dec, meta_plain, tag) = open_metadata(&header, &meta_frame, &drop_key, key)?;
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
    check_receive_size(&metadata, drop.declared_size, free_space_for(dest_dir))?;

    // Format 2 names the file inside the encryption; RDS's copy of the name is only for the list.
    let filename = metadata.filename.as_deref().unwrap_or(&drop.filename);
    if filename != drop.filename {
        hbb_common::log::info!(
            "rustdrop: saving drop {} under its sender's name {filename:?} (listed as {:?})",
            drop.id,
            drop.filename
        );
    }
    let mut writer = AtomicFileWriter::create(dest_dir, filename)
        .map_err(|e| TransferError(format!("failed to create destination file: {e}")))?;
    let mut hasher = Sha256::new();
    let mut bytes_done: u64 = 0;
    loop {
        let frame = match fill_until(
            client, identity, &drop.id, &mut ciphertext_offset, &mut byte_stream, part_size, timeout,
            stall_giveup, &mut reader, FrameReader::try_take_frame,
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
        if bytes_done.saturating_add(plain.len() as u64) > metadata.plaintext_size {
            writer.abort();
            return Err(TransferError(format!(
                "{MALFORMED_DROP}: more data than its metadata declares"
            )));
        }
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
    if bytes_done != metadata.plaintext_size {
        writer.abort();
        return Err(TransferError(format!(
            "{MALFORMED_DROP}: less data than its metadata declares"
        )));
    }

    let computed_hash = hex::encode(hasher.finalize());
    if computed_hash != metadata.plaintext_sha256 {
        writer.abort();
        return Err(TransferError(format!(
            "{INTEGRITY_FAILED} - deleted, not saved"
        )));
    }
    let saved = writer
        .finish()
        .map_err(|e| TransferError(format!("failed to finalize downloaded file: {e}")))?;
    let sender = drop
        .peer_friendly_name
        .as_deref()
        .or(drop.peer_hostname.as_deref())
        .unwrap_or(&drop.sender_device_id);
    mark_from_internet(&saved, sender);
    Ok(saved)
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
    for attempt in 0..2 {
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
            // RDS already held this attempt 40 s for the sender; the window retries later.
            Err(e) if e.0.contains(rustdrop_rds_client::SENDER_NOT_STARTED) => {
                last_error = Some(e);
                break;
            }
            Err(e) if misframed_on_first_attempt(&e, attempt) => {
                hbb_common::log::warn!(
                    "rustdrop: {e} for drop {}; downloading it again from the start",
                    drop.id
                );
                last_error = Some(e);
            }
            Err(e) if not_worth_retrying(&e) => {
                last_error = Some(e);
                break;
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
    fn receive_size_is_checked_against_the_authenticated_metadata() {
        let metadata = |plaintext_size, encoding: Option<&str>| FileMetadata {
            plaintext_sha256: String::new(),
            plaintext_size,
            encoding: encoding.map(str::to_owned),
            filename: None,
        };
        let gib = 1024 * 1024 * 1024u64;

        assert!(check_receive_size(&metadata(1000, None), 2000, None).is_ok());
        let err = check_receive_size(&metadata(3000, None), 2000, None).unwrap_err();
        assert!(err.0.contains(MALFORMED_DROP));

        // A compressed drop can legitimately decode to far more than its ciphertext,
        // as long as the destination has room for it.
        let zstd = metadata(100 * gib, Some(ZSTD_CHUNKS));
        assert!(check_receive_size(&zstd, 50 * 1024 * 1024, None).is_ok());
        assert!(check_receive_size(&zstd, 50 * 1024 * 1024, Some(200 * gib)).is_ok());
        let err = check_receive_size(&zstd, 50 * 1024 * 1024, Some(100 * gib)).unwrap_err();
        assert!(err.0.contains(NOT_ENOUGH_SPACE));
    }

    #[test]
    fn oversized_frame_length_is_refused_before_it_is_buffered() {
        let mut reader = FrameReader::default();
        reader.feed(&u32::MAX.to_be_bytes());
        let err = reader.try_take_frame().unwrap_err();
        assert!(err.0.contains(MALFORMED_DROP));
        assert!(err.0.contains(crate::rustdrop_crypto::OVERSIZED_CHUNK));
    }

    #[test]
    fn oversized_frame_is_retried_from_the_start_once() {
        let mut reader = FrameReader::default();
        reader.feed(&u32::MAX.to_be_bytes());
        let misframed = reader.try_take_frame().unwrap_err();
        assert!(misframed_on_first_attempt(&misframed, 0));
        assert!(!misframed_on_first_attempt(&misframed, 1));

        let other = TransferError(format!("{MALFORMED_DROP}: more data than its metadata declares"));
        assert!(!misframed_on_first_attempt(&other, 0));
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
            filename: None,
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
            filename: None,
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
            filename: None,
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

    fn metadata_for(contents: &[u8]) -> FileMetadata {
        FileMetadata {
            plaintext_sha256: hex::encode(Sha256::digest(contents)),
            plaintext_size: contents.len() as u64,
            encoding: None,
            filename: None,
        }
    }

    fn read_all(reader: &mut PlaintextReader) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let chunk = reader.next_chunk().unwrap();
            if chunk.is_empty() {
                break out;
            }
            out.extend_from_slice(&chunk);
        }
    }

    #[test]
    fn plaintext_reader_refuses_a_file_that_changed_after_hashing() {
        let path = temp_file(b"abcdef");
        let mut same = PlaintextReader::open(&path, 6).unwrap();
        assert_eq!(read_all(&mut same), b"abcdef");
        assert!(same.verify(&metadata_for(b"abcdef")).is_ok());

        let mut grew = PlaintextReader::open(&path, 3).unwrap();
        assert_eq!(
            read_all(&mut grew),
            b"abc",
            "never reads past the hashed size"
        );
        assert!(grew.verify(&metadata_for(b"abc")).is_err());

        let mut shrank = PlaintextReader::open(&path, 10).unwrap();
        assert_eq!(read_all(&mut shrank), b"abcdef");
        assert!(shrank.verify(&metadata_for(b"abcdefghij")).is_err());

        let mut edited = PlaintextReader::open(&path, 6).unwrap();
        read_all(&mut edited);
        assert_eq!(
            edited
                .verify(&metadata_for(b"abcdeX"))
                .unwrap_err()
                .to_string(),
            FILE_CHANGED
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_changed_file_never_gets_a_final_chunk() {
        let path = temp_file(b"current contents");
        let metadata = metadata_for(b"what was hashed!");
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let producer = {
            let path = path.clone();
            std::thread::spawn(move || encrypt_file_to_channel(&path, [9u8; 32], metadata, tx))
        };
        let mut items = Vec::new();
        while let Some(item) = rx.blocking_recv() {
            items.push(item);
        }
        producer.join().unwrap();
        let last = items.pop().unwrap();
        assert!(last.unwrap_err().to_string().contains(FILE_CHANGED));
        assert_eq!(items.len(), 2, "only the header and metadata went out");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn compression_stops_for_a_file_that_changed() {
        let plaintext = b"0123456789 compressible line\n".repeat(150_000);
        let path = temp_file(&plaintext);
        let metadata = FileMetadata {
            plaintext_sha256: hex::encode(Sha256::digest(b"something else")),
            encoding: Some(ZSTD_CHUNKS.to_string()),
            ..metadata_for(&plaintext)
        };
        match compress_and_encrypt_to_temp(&path, &[7u8; 32], &metadata) {
            Err(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
                assert_eq!(e.to_string(), FILE_CHANGED);
            }
            Ok(_) => panic!("a changed file must not produce a compressed copy"),
        }
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn format_2_and_format_1_drops_both_open() {
        let (pub_a, priv_a) = generate_keypair();
        let (pub_b, priv_b) = generate_keypair();
        let sender_file_key = derive_key(&priv_a, &pub_b).unwrap();
        let recipient_file_key = derive_key(&priv_b, &pub_a).unwrap();
        let drop_id = uuid::Uuid::new_v4().to_string();
        let sender_drop_key =
            derive_drop_key(&sender_file_key, "dev-a", "dev-b", &drop_id).unwrap();
        let recipient_drop_key =
            derive_drop_key(&recipient_file_key, "dev-a", "dev-b", &drop_id).unwrap();
        let seal = |key: &[u8; 32], filename: Option<&str>| {
            let metadata = FileMetadata {
                filename: filename.map(str::to_owned),
                ..metadata_for(b"hi")
            };
            let (mut enc, header) = Encryptor::new(key).unwrap();
            (header, enc.push_metadata(&metadata).unwrap()[4..].to_vec())
        };

        let (header, frame) = seal(&sender_drop_key, Some("report.pdf"));
        let (_dec, plain, tag) =
            open_metadata(&header, &frame, &recipient_drop_key, &recipient_file_key).unwrap();
        assert_eq!(tag, Tag::Message);
        assert_eq!(
            Decryptor::parse_metadata(&plain)
                .unwrap()
                .filename
                .as_deref(),
            Some("report.pdf")
        );

        let (header, frame) = seal(&sender_file_key, None);
        let (_dec, plain, _) =
            open_metadata(&header, &frame, &recipient_drop_key, &recipient_file_key).unwrap();
        assert!(
            Decryptor::parse_metadata(&plain)
                .unwrap()
                .filename
                .is_none(),
            "format 1 still opens"
        );

        // The recipient's own format-2 drop to the sender, offered back to it.
        let reflected = derive_drop_key(&recipient_file_key, "dev-b", "dev-a", &drop_id).unwrap();
        let (header, frame) = seal(&reflected, Some("x"));
        assert!(open_metadata(&header, &frame, &recipient_drop_key, &recipient_file_key).is_err());
    }

    #[test]
    fn a_download_gives_up_once_nothing_arrives_for_the_stall_limit() {
        let limit = Duration::from_secs(30 * 60);
        assert!(check_download_progress(Instant::now(), limit).is_ok());
        if let Some(long_ago) = Instant::now().checked_sub(limit + Duration::from_secs(1)) {
            let err = check_download_progress(long_ago, limit).unwrap_err();
            assert!(
                err.0.contains(DOWNLOAD_STALLED) && err.0.contains("30 minutes"),
                "{}",
                err.0
            );
            assert!(not_worth_retrying(&err));
        }
    }

    #[test]
    fn failures_a_second_download_would_repeat_are_not_retried() {
        assert!(not_worth_retrying(&TransferError(format!("{INTEGRITY_FAILED} - deleted, not saved"))));
        assert!(not_worth_retrying(&TransferError(format!("{MALFORMED_DROP}: x"))));
        assert!(not_worth_retrying(&TransferError(format!("{NOT_ENOUGH_SPACE} to receive this file"))));
        assert!(!not_worth_retrying(&TransferError("download stream ended unexpectedly".into())));
    }
}
