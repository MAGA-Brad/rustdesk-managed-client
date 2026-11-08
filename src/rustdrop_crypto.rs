// RustDrop's file-transfer encryption. Sender-side only - RDS and the
// storage backend never see plaintext, only ever handle this module's
// ciphertext as an opaque blob.
//
// This is a clean break from the retired Electron client's wire format
// (single AES-256-GCM operation over the whole file, one tag at the very
// end) - confirmed safe to change since every deployed client was being
// rewritten together, so no other client exists to stay
// compatible with. The new format uses libsodium's
// crypto_secretstream_xchacha20poly1305 (via the already-vetted `sodiumoxide`
// crate, already a dependency of this project) instead: each chunk is
// individually authenticated and the last chunk is cryptographically
// marked Final, so truncation or tampering is caught as soon as the bad
// chunk arrives rather than only after the entire (up to 10 GiB) file has
// downloaded.
//
// Key agreement is unchanged in spirit from the retired client: X25519 ECDH
// (via sodiumoxide's `scalarmult`) then HKDF-SHA256 (via the `hkdf`/`sha2`
// crates, both already transitive dependencies promoted to direct ones -
// no new crates added for this module) to turn the shared secret into the
// stream's symmetric key. The HKDF `info` string is versioned
// ("rustdrop-v1-file-key") per HKDF best practice, so a future protocol
// change can't accidentally derive the same key under different framing.

use hkdf::Hkdf;
use sha2::Sha256;
use sodiumoxide::crypto::scalarmult::curve25519::{
    scalarmult, scalarmult_base, GroupElement, Scalar,
};
use sodiumoxide::crypto::secretstream::xchacha20poly1305 as stream;
pub use sodiumoxide::crypto::secretstream::Tag;

pub const PUBLIC_KEY_BYTES: usize = 32;
pub const PRIVATE_KEY_BYTES: usize = 32;

// A chunk boundary, not a security parameter - 64 KiB balances per-chunk
// tag overhead (17 bytes/chunk, ~0.026% at this size) against how much
// plaintext a single tamper/truncation event can hide before the next
// chunk's tag catches it.
pub const CHUNK_SIZE: usize = 64 * 1024;

/// The longest framed chunk an honest sender writes: CHUNK_SIZE of data plus the one-byte chunk
/// encoding flag a compressed drop adds (rustdrop_transfer.rs), plus the tag. The metadata chunk
/// is far smaller. The length prefix is read before anything is authenticated, so a longer one is
/// refused before its bytes are buffered.
pub const MAX_FRAMED_CHUNK_LEN: usize = CHUNK_SIZE + 1 + stream::ABYTES;
/// In the error for a longer length prefix. Ciphertext read at the wrong offset after a resume
/// looks the same, so the receiver tells the two apart by downloading again from the start.
pub const OVERSIZED_CHUNK: &str = "a chunk claims more bytes than any sender writes";

/// Exposed so callers driving the wire format from outside this module
/// (reading the header off a download stream before any Decryptor exists
/// yet) don't need their own direct sodiumoxide dependency just for this
/// one constant.
pub const STREAM_HEADER_BYTES: usize = stream::HEADERBYTES;

const HKDF_INFO: &[u8] = b"rustdrop-v1-file-key";
const DROP_KEY_INFO: &[u8] = b"rustdrop-v2-drop-key";

#[derive(Debug)]
pub struct CryptoError(pub String);

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rustdrop crypto error: {}", self.0)
    }
}
impl std::error::Error for CryptoError {}

type Result<T> = std::result::Result<T, CryptoError>;

/// Fresh X25519 keypair for this device's RustDrop identity. Matches the
/// retired client's own design decision to use a dedicated keypair rather
/// than reusing RDC's own Ed25519 signing key - wrong curve/purpose for ECDH.
pub fn generate_keypair() -> ([u8; PUBLIC_KEY_BYTES], [u8; PRIVATE_KEY_BYTES]) {
    let mut seed = [0u8; 32];
    sodiumoxide::randombytes::randombytes_into(&mut seed);
    let private = Scalar(seed);
    let public = scalarmult_base(&private);
    (public.0, private.0)
}

/// ECDH (X25519) + HKDF-SHA256. Same shared key results regardless of which
/// side calls it, as long as one side's public key and the other's private
/// key are paired correctly - standard ECDH symmetry.
pub fn derive_key(
    my_private_key: &[u8; PRIVATE_KEY_BYTES],
    peer_public_key: &[u8; PUBLIC_KEY_BYTES],
) -> Result<[u8; 32]> {
    let scalar = Scalar(*my_private_key);
    let point = GroupElement(*peer_public_key);
    let shared = scalarmult(&scalar, &point)
        .map_err(|_| CryptoError("ECDH scalarmult failed (peer key on small subgroup?)".into()))?;

    let hk = Hkdf::<Sha256>::new(None, &shared.0);
    let mut key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut key)
        .map_err(|_| CryptoError("HKDF expand failed".into()))?;
    Ok(key)
}

/// Format 2's key for one drop: `file_key` (derive_key's result for the pair) expanded with the
/// sender, the recipient and the drop id, each length-prefixed. A drop's ciphertext then opens only
/// as that drop, sent in that direction - not reflected back to its sender, and not under another
/// drop's id (audit RDC-RUSTDROP#3). Ids are compared in RDS's form: a UUID lowercase and
/// hyphenated, anything else lowercase.
pub fn derive_drop_key(
    file_key: &[u8; 32],
    sender_device_id: &str,
    recipient_device_id: &str,
    drop_id: &str,
) -> Result<[u8; 32]> {
    let mut info = DROP_KEY_INFO.to_vec();
    for part in [sender_device_id, recipient_device_id, drop_id] {
        let part = uuid::Uuid::parse_str(part.trim())
            .map(|id| id.to_string())
            .unwrap_or_else(|_| part.trim().to_ascii_lowercase());
        info.extend_from_slice(&(part.len() as u32).to_be_bytes());
        info.extend_from_slice(part.as_bytes());
    }
    let hk = Hkdf::<Sha256>::new(None, file_key);
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key)
        .map_err(|_| CryptoError("HKDF expand failed".into()))?;
    Ok(key)
}

/// Everything the recipient needs to verify the file after decrypting it,
/// carried as the stream's first (encrypted) chunk rather than a plaintext
/// DB column - RDS never sees it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileMetadata {
    pub plaintext_sha256: String,
    pub plaintext_size: u64,
    /// How each data chunk is encoded before encryption; absent means raw. Left out of the JSON
    /// when absent, so a raw drop's metadata (and declared size) is byte-identical to before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
    /// Format 2: the sender's own file name, so the saved name doesn't come from RDS. Left out of
    /// the JSON in format 1, like `encoding`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
}

/// Total on-the-wire byte count for a given plaintext size, so the sender
/// can declare an exact Content-Length upfront (RDS/storage enforce this as
/// a live cap against actual bytes streamed, not just a claimed value).
pub fn ciphertext_size(metadata: &FileMetadata, plaintext_size: u64) -> u64 {
    let metadata_json_len = serde_json::to_vec(metadata)
        .map(|v| v.len())
        .unwrap_or(0) as u64;
    let mut total = stream::HEADERBYTES as u64;
    total += framed_chunk_len(metadata_json_len);

    let full_chunks = plaintext_size / CHUNK_SIZE as u64;
    let remainder = plaintext_size % CHUNK_SIZE as u64;
    total += full_chunks * framed_chunk_len(CHUNK_SIZE as u64);
    // Always at least one data chunk (tagged Final) even for a 0-byte file,
    // and a non-empty remainder after the full chunks otherwise.
    if remainder > 0 || full_chunks == 0 {
        total += framed_chunk_len(remainder);
    }
    total
}

fn framed_chunk_len(plaintext_len: u64) -> u64 {
    4 /* u32 BE length prefix */ + plaintext_len + stream::ABYTES as u64
}

/// Sender side. `new()` returns the stream plus the header bytes, which
/// must be sent first (unencrypted - it's an init vector, not a secret).
/// Every subsequent `push_*` call returns one length-prefixed framed
/// chunk, ready to concatenate directly onto the outgoing byte stream.
pub struct Encryptor {
    stream: stream::Stream<stream::Push>,
    finished: bool,
}

impl Encryptor {
    pub fn new(key: &[u8; 32]) -> Result<(Self, Vec<u8>)> {
        let stream_key = stream::Key(*key);
        let (encoder, header) = stream::Stream::init_push(&stream_key)
            .map_err(|_| CryptoError("secretstream init_push failed".into()))?;
        Ok((
            Encryptor {
                stream: encoder,
                finished: false,
            },
            header.0.to_vec(),
        ))
    }

    /// Must be the first chunk pushed, before any file-data chunks.
    pub fn push_metadata(&mut self, metadata: &FileMetadata) -> Result<Vec<u8>> {
        let json = serde_json::to_vec(metadata)
            .map_err(|e| CryptoError(format!("metadata serialize failed: {e}")))?;
        self.push_framed(&json, Tag::Message)
    }

    /// One file-data chunk. Caller is responsible for chunking the
    /// plaintext (CHUNK_SIZE is a guideline, not enforced here) and for
    /// calling `finish()` exactly once after the last chunk.
    pub fn push_chunk(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.push_framed(plaintext, Tag::Message)
    }

    /// Closes the stream with a Final-tagged chunk (possibly empty, for a
    /// zero-byte file) so the recipient can detect truncation - a stream
    /// that ends without ever pulling a Final chunk is provably incomplete.
    pub fn finish(mut self, last_plaintext: &[u8]) -> Result<Vec<u8>> {
        let framed = self.push_framed(last_plaintext, Tag::Final)?;
        self.finished = true;
        Ok(framed)
    }

    fn push_framed(&mut self, plaintext: &[u8], tag: Tag) -> Result<Vec<u8>> {
        if self.finished {
            return Err(CryptoError("push after finish".into()));
        }
        let ciphertext = self
            .stream
            .push(plaintext, None, tag)
            .map_err(|_| CryptoError("secretstream push failed".into()))?;
        let mut framed = Vec::with_capacity(4 + ciphertext.len());
        framed.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
        framed.extend_from_slice(&ciphertext);
        Ok(framed)
    }
}

/// Recipient side. Feed it the header first (from the start of the
/// downloaded stream), then repeatedly call `pull_chunk` with each framed
/// chunk read off the wire (`read_chunk_len` tells the caller how many
/// ciphertext bytes to read next). `is_finalized()` is the truncation
/// check: a download that ends before a Final-tagged chunk was pulled was
/// cut short, tampered with, or both - reject it either way.
pub struct Decryptor {
    stream: stream::Stream<stream::Pull>,
}

impl Decryptor {
    pub fn new(header: &[u8], key: &[u8; 32]) -> Result<Self> {
        let stream_key = stream::Key(*key);
        let stream_header = stream::Header::from_slice(header)
            .ok_or_else(|| CryptoError("bad secretstream header length".into()))?;
        let decoder = stream::Stream::init_pull(&stream_header, &stream_key)
            .map_err(|_| CryptoError("secretstream init_pull failed (wrong key?)".into()))?;
        Ok(Decryptor { stream: decoder })
    }

    /// Reads a big-endian u32 chunk length from the start of `framed`,
    /// matching what `Encryptor::push_framed` wrote. Returns the length
    /// and the number of header bytes consumed (always 4).
    pub fn read_chunk_len(framed: &[u8]) -> Result<usize> {
        if framed.len() < 4 {
            return Err(CryptoError("truncated chunk length prefix".into()));
        }
        let len = u32::from_be_bytes([framed[0], framed[1], framed[2], framed[3]]);
        if len as usize > MAX_FRAMED_CHUNK_LEN {
            return Err(CryptoError(format!(
                "malformed drop: {OVERSIZED_CHUNK} ({len} bytes, at most {MAX_FRAMED_CHUNK_LEN})"
            )));
        }
        Ok(len as usize)
    }

    pub fn pull_chunk(&mut self, ciphertext: &[u8]) -> Result<(Vec<u8>, Tag)> {
        self.stream
            .pull(ciphertext, None)
            .map_err(|_| CryptoError("decrypt/auth failed - tampered or corrupted chunk".into()))
    }

    pub fn is_finalized(&self) -> bool {
        self.stream.is_finalized()
    }

    pub fn parse_metadata(json: &[u8]) -> Result<FileMetadata> {
        serde_json::from_slice(json).map_err(|e| CryptoError(format!("bad metadata JSON: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(chunks: &[&[u8]]) -> Vec<u8> {
        let (pub_a, priv_a) = generate_keypair();
        let (pub_b, priv_b) = generate_keypair();
        let key_a = derive_key(&priv_a, &pub_b).unwrap();
        let key_b = derive_key(&priv_b, &pub_a).unwrap();
        assert_eq!(key_a, key_b, "ECDH must be symmetric");

        let metadata = FileMetadata {
            plaintext_sha256: "deadbeef".into(),
            plaintext_size: chunks.iter().map(|c| c.len() as u64).sum(),
            encoding: None,
            filename: None,
        };

        let (mut enc, header) = Encryptor::new(&key_a).unwrap();
        let mut wire = header.clone();
        wire.extend_from_slice(&enc.push_metadata(&metadata).unwrap());
        if let Some((last, rest)) = chunks.split_last() {
            for chunk in rest {
                wire.extend_from_slice(&enc.push_chunk(chunk).unwrap());
            }
            wire.extend_from_slice(&enc.finish(last).unwrap());
        } else {
            wire.extend_from_slice(&enc.finish(&[]).unwrap());
        }

        // Decrypt and verify round-trip content before returning the wire
        // bytes, so every call site gets both checks for free.
        let mut pos = stream::HEADERBYTES;
        let mut dec = Decryptor::new(&wire[..pos], &key_b).unwrap();

        let (meta_len, meta_bytes_start) = (
            Decryptor::read_chunk_len(&wire[pos..]).unwrap(),
            pos + 4,
        );
        let (plain_meta, tag) = dec
            .pull_chunk(&wire[meta_bytes_start..meta_bytes_start + meta_len])
            .unwrap();
        assert_eq!(tag, Tag::Message);
        let parsed_meta = Decryptor::parse_metadata(&plain_meta).unwrap();
        assert_eq!(parsed_meta.plaintext_size, metadata.plaintext_size);
        pos = meta_bytes_start + meta_len;

        let mut decrypted = Vec::new();
        loop {
            let len = Decryptor::read_chunk_len(&wire[pos..]).unwrap();
            let start = pos + 4;
            let (plain, tag) = dec.pull_chunk(&wire[start..start + len]).unwrap();
            decrypted.extend_from_slice(&plain);
            pos = start + len;
            if tag == Tag::Final {
                break;
            }
        }
        assert!(dec.is_finalized());
        assert_eq!(decrypted, chunks.concat());
        assert_eq!(pos, wire.len(), "no trailing bytes after Final chunk");
        wire
    }

    #[test]
    fn empty_file() {
        roundtrip(&[]);
    }

    #[test]
    fn single_byte() {
        roundtrip(&[&[0x42]]);
    }

    #[test]
    fn exact_chunk_multiple() {
        let chunk = vec![0xABu8; CHUNK_SIZE];
        roundtrip(&[&chunk, &chunk]);
    }

    #[test]
    fn one_byte_over_chunk_boundary() {
        let full = vec![0xCDu8; CHUNK_SIZE];
        roundtrip(&[&full, &[0x01]]);
    }

    #[test]
    fn many_small_chunks() {
        let data: Vec<u8> = (0u8..=255).collect();
        let chunks: Vec<&[u8]> = data.chunks(1).collect();
        roundtrip(&chunks);
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let (pub_a, priv_a) = generate_keypair();
        let (_pub_b, priv_b) = generate_keypair();
        let (pub_wrong, _priv_wrong) = generate_keypair();

        let key_a = derive_key(&priv_a, &pub_wrong).unwrap();
        let (mut enc, header) = Encryptor::new(&key_a).unwrap();
        let metadata = FileMetadata {
            plaintext_sha256: "x".into(),
            plaintext_size: 3,
            encoding: None,
            filename: None,
        };
        let mut wire = header;
        wire.extend_from_slice(&enc.push_metadata(&metadata).unwrap());
        wire.extend_from_slice(&enc.finish(b"abc").unwrap());

        // Derive with the WRONG peer key on the receiving side.
        let wrong_recipient_key = derive_key(&priv_b, &pub_a).unwrap();
        let mut dec = Decryptor::new(&wire[..stream::HEADERBYTES], &wrong_recipient_key).unwrap();
        let len = Decryptor::read_chunk_len(&wire[stream::HEADERBYTES..]).unwrap();
        let start = stream::HEADERBYTES + 4;
        assert!(
            dec.pull_chunk(&wire[start..start + len]).is_err(),
            "decrypting with an unrelated recipient's key must fail"
        );
    }

    #[test]
    fn tampered_chunk_fails_auth() {
        let (pub_a, priv_a) = generate_keypair();
        let (pub_b, priv_b) = generate_keypair();
        let key_a = derive_key(&priv_a, &pub_b).unwrap();
        let key_b = derive_key(&priv_b, &pub_a).unwrap();

        let (mut enc, header) = Encryptor::new(&key_a).unwrap();
        let metadata = FileMetadata {
            plaintext_sha256: "x".into(),
            plaintext_size: 5,
            encoding: None,
            filename: None,
        };
        let mut wire = header;
        wire.extend_from_slice(&enc.push_metadata(&metadata).unwrap());
        wire.extend_from_slice(&enc.finish(b"hello").unwrap());

        // Flip one bit deep in the final (only) data chunk's ciphertext.
        let flip_at = wire.len() - 3;
        wire[flip_at] ^= 0x01;

        let mut dec = Decryptor::new(&wire[..stream::HEADERBYTES], &key_b).unwrap();
        let mut pos = stream::HEADERBYTES;
        let meta_len = Decryptor::read_chunk_len(&wire[pos..]).unwrap();
        let meta_start = pos + 4;
        dec.pull_chunk(&wire[meta_start..meta_start + meta_len])
            .unwrap();
        pos = meta_start + meta_len;

        let data_len = Decryptor::read_chunk_len(&wire[pos..]).unwrap();
        let data_start = pos + 4;
        assert!(
            dec.pull_chunk(&wire[data_start..data_start + data_len])
                .is_err(),
            "a single flipped bit must fail authentication"
        );
    }

    #[test]
    fn truncated_stream_never_finalizes() {
        let (pub_a, priv_a) = generate_keypair();
        let (pub_b, priv_b) = generate_keypair();
        let key_a = derive_key(&priv_a, &pub_b).unwrap();
        let key_b = derive_key(&priv_b, &pub_a).unwrap();

        let (mut enc, header) = Encryptor::new(&key_a).unwrap();
        let metadata = FileMetadata {
            plaintext_sha256: "x".into(),
            plaintext_size: 10,
            encoding: None,
            filename: None,
        };
        let mut wire = header;
        wire.extend_from_slice(&enc.push_metadata(&metadata).unwrap());
        let chunk1 = enc.push_chunk(b"hello").unwrap();
        wire.extend_from_slice(&chunk1);
        let _final_chunk = enc.finish(b"world").unwrap();
        // Deliberately drop the Final chunk - simulates a connection that
        // died mid-transfer.

        let mut dec = Decryptor::new(&wire[..stream::HEADERBYTES], &key_b).unwrap();
        let mut pos = stream::HEADERBYTES;
        let meta_len = Decryptor::read_chunk_len(&wire[pos..]).unwrap();
        let meta_start = pos + 4;
        dec.pull_chunk(&wire[meta_start..meta_start + meta_len])
            .unwrap();
        pos = meta_start + meta_len;
        let data_len = Decryptor::read_chunk_len(&wire[pos..]).unwrap();
        let data_start = pos + 4;
        dec.pull_chunk(&wire[data_start..data_start + data_len])
            .unwrap();

        assert!(
            !dec.is_finalized(),
            "must not report finalized without ever seeing a Final-tagged chunk"
        );
    }

    #[test]
    fn chunk_length_prefix_is_bounded() {
        let (pub_a, priv_a) = generate_keypair();
        let (pub_b, _priv_b) = generate_keypair();
        let key_a = derive_key(&priv_a, &pub_b).unwrap();
        let (mut enc, _header) = Encryptor::new(&key_a).unwrap();
        // The largest chunk a compressed drop writes: a raw-flagged full chunk.
        let largest = enc.push_chunk(&vec![0u8; CHUNK_SIZE + 1]).unwrap();
        assert_eq!(Decryptor::read_chunk_len(&largest).unwrap(), MAX_FRAMED_CHUNK_LEN);

        let over = ((MAX_FRAMED_CHUNK_LEN + 1) as u32).to_be_bytes();
        assert!(Decryptor::read_chunk_len(&over).is_err_and(|e| e.0.contains(OVERSIZED_CHUNK)));
        assert!(Decryptor::read_chunk_len(&u32::MAX.to_be_bytes()).is_err());
    }

    #[test]
    fn ciphertext_size_matches_actual_wire_length() {
        let data = vec![0x11u8; CHUNK_SIZE * 2 + 37];
        let (pub_a, priv_a) = generate_keypair();
        let (pub_b, _priv_b) = generate_keypair();
        let key_a = derive_key(&priv_a, &pub_b).unwrap();

        let metadata = FileMetadata {
            plaintext_sha256: "x".into(),
            plaintext_size: data.len() as u64,
            encoding: None,
            filename: None,
        };
        let predicted = ciphertext_size(&metadata, data.len() as u64);

        let (mut enc, header) = Encryptor::new(&key_a).unwrap();
        let mut wire = header;
        wire.extend_from_slice(&enc.push_metadata(&metadata).unwrap());
        let chunks: Vec<&[u8]> = data.chunks(CHUNK_SIZE).collect();
        let (last, rest) = chunks.split_last().unwrap();
        for c in rest {
            wire.extend_from_slice(&enc.push_chunk(c).unwrap());
        }
        wire.extend_from_slice(&enc.finish(last).unwrap());

        assert_eq!(wire.len() as u64, predicted);
    }

    #[test]
    fn drop_key_is_shared_and_bound_to_direction_and_drop() {
        let (pub_a, priv_a) = generate_keypair();
        let (pub_b, priv_b) = generate_keypair();
        let file_key_a = derive_key(&priv_a, &pub_b).unwrap();
        let file_key_b = derive_key(&priv_b, &pub_a).unwrap();
        let (a, b, drop) = ("dev-a", "dev-b", "5f0c3a52-1111-4222-8333-944455556666");

        let sender = derive_drop_key(&file_key_a, a, b, drop).unwrap();
        let recipient = derive_drop_key(&file_key_b, a, b, drop).unwrap();
        assert_eq!(sender, recipient, "both ends derive the same drop key");
        assert_ne!(
            sender, file_key_a,
            "format 2 never encrypts under the pair's file key"
        );
        assert_ne!(
            sender,
            derive_drop_key(&file_key_a, b, a, drop).unwrap(),
            "reflected direction differs"
        );
        assert_ne!(
            sender,
            derive_drop_key(&file_key_a, a, b, "5f0c3a52-1111-4222-8333-944455556667").unwrap(),
            "another drop id differs"
        );
        assert_eq!(
            sender,
            derive_drop_key(&file_key_a, "DEV-A ", b, &drop.to_uppercase()).unwrap()
        );
        for spelling in [format!("{{{drop}}}"), drop.replace('-', "")] {
            assert_eq!(
                sender,
                derive_drop_key(&file_key_a, a, b, &spelling).unwrap(),
                "any UUID spelling: {spelling}"
            );
        }
        // Length prefixes: moving a character between fields changes the key.
        assert_ne!(
            derive_drop_key(&file_key_a, "ab", "c", drop).unwrap(),
            derive_drop_key(&file_key_a, "a", "bc", drop).unwrap()
        );
    }

    #[test]
    fn format_1_metadata_is_unchanged_and_format_2_carries_the_name() {
        let format_1 = FileMetadata {
            plaintext_sha256: "x".into(),
            plaintext_size: 3,
            encoding: None,
            filename: None,
        };
        assert_eq!(
            serde_json::to_string(&format_1).unwrap(),
            r#"{"plaintext_sha256":"x","plaintext_size":3}"#
        );
        let format_2 = FileMetadata {
            filename: Some("report \"Q3\".pdf".into()),
            ..format_1.clone()
        };
        let parsed = Decryptor::parse_metadata(&serde_json::to_vec(&format_2).unwrap()).unwrap();
        assert_eq!(parsed.filename.as_deref(), Some("report \"Q3\".pdf"));
        assert!(
            Decryptor::parse_metadata(br#"{"plaintext_sha256":"x","plaintext_size":3}"#)
                .unwrap()
                .filename
                .is_none()
        );
        assert!(ciphertext_size(&format_2, 3) > ciphertext_size(&format_1, 3));
    }
}
