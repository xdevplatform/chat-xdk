//! Message and media encryption.
//!
//! Provides symmetric encryption for chat payloads using:
//! - XSalsa20-Poly1305 (SecretBox) for single messages
//! - XChaCha20-Poly1305 secretstream for media / large files
//!
//! The streaming format uses `crypto_secretstream_xchacha20poly1305`
//! (libsodium secretstream), ensuring cross-platform wire-format
//! compatibility.
//!
//! Uses pure-Rust implementations that are WASM-compatible.
//!

use crate::crypto::keys::XChatConversationKey;
use crate::error::CryptoError;

use rand::rngs::OsRng;
use rand::RngCore;
use std::io::{Read, Write};
use xsalsa20poly1305::{
    aead::{AeadInPlace, KeyInit},
    Tag, XSalsa20Poly1305,
};

/// Nonce size for XSalsa20-Poly1305: 24 bytes
pub const NONCE_SIZE: usize = 24;

/// Tag size for Poly1305: 16 bytes
pub const TAG_SIZE: usize = 16;

/// Chunk size for streaming encryption (plaintext): 1024 bytes.
pub const DECRYPTED_CHUNK_SIZE: usize = 1024;

/// Overhead per chunk added by `crypto_secretstream_xchacha20poly1305`.
///
/// 1 byte tag + 16 bytes Poly1305 MAC = 17 bytes.
pub const SECRETSTREAM_ABYTES: usize = 17;

/// Chunk size for streaming encryption (ciphertext).
///
/// `DECRYPTED_CHUNK_SIZE + SECRETSTREAM_ABYTES` (1024 + 17 = 1041).
pub const ENCRYPTED_CHUNK_SIZE: usize = DECRYPTED_CHUNK_SIZE + SECRETSTREAM_ABYTES;

/// Encrypt a message using XSalsa20-Poly1305.
///
/// # Wire Format
/// Output: nonce (24 bytes) || tag (16 bytes) || ciphertext
///
pub fn encrypt_message(
    key: &XChatConversationKey,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XSalsa20Poly1305::new_from_slice(key.encoded())
        .map_err(|_| CryptoError::InvalidKey("Invalid conversation key".into()))?;

    // Generate random nonce
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);

    // Detached format: tag || ciphertext. Empty AAD is passed: message
    // context is authenticated by the event signature, not by the AEAD.
    let mut buffer = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(nonce.as_ref().into(), b"", &mut buffer)
        .map_err(|_| CryptoError::EncryptionFailed("XSalsa20-Poly1305 encryption failed".into()))?;

    // Output: nonce || tag || ciphertext
    let mut output = Vec::with_capacity(NONCE_SIZE + TAG_SIZE + buffer.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&tag);
    output.extend_from_slice(&buffer);

    Ok(output)
}

/// Decrypt a message using XSalsa20-Poly1305.
///
/// # Wire Format
/// Input: nonce (24 bytes) || tag (16 bytes) || ciphertext
///
pub fn decrypt_message(
    key: &XChatConversationKey,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // Minimum size: nonce (24) + tag (16) = 40 bytes
    if ciphertext.len() < NONCE_SIZE + TAG_SIZE {
        return Err(CryptoError::DecryptionFailed("Ciphertext too short".into()));
    }

    let cipher = XSalsa20Poly1305::new_from_slice(key.encoded())
        .map_err(|_| CryptoError::InvalidKey("Invalid conversation key".into()))?;

    // Extract nonce
    let nonce = &ciphertext[..NONCE_SIZE];

    // Extract tag and ciphertext (detached format)
    let tag_bytes = &ciphertext[NONCE_SIZE..NONCE_SIZE + TAG_SIZE];
    let mut buffer = ciphertext[NONCE_SIZE + TAG_SIZE..].to_vec();
    let tag = Tag::from_slice(tag_bytes);

    // Decrypt
    cipher
        .decrypt_in_place_detached(nonce.into(), b"", &mut buffer, tag)
        .map_err(|_| {
            CryptoError::DecryptionFailed(
                "Decryption failed - invalid key or corrupted data".into(),
            )
        })?;
    Ok(buffer)
}

// Streaming encryption — crypto_secretstream_xchacha20poly1305
//
// Wire format:
//   header (24 bytes) || chunk_0 || chunk_1 || … || chunk_n
//
// Each chunk is (plaintext_len + ABYTES) bytes.  Intermediate chunks carry
// TAG_MESSAGE; the final chunk carries TAG_FINAL.

/// Read from `reader` until `buf` is full or EOF is reached.
///
/// Unlike a single `Read::read` call, this tolerates short reads (e.g.
/// network streams), which is required for correct chunk framing.
/// Returns the number of bytes read (0 only at EOF).
fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = reader.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

/// Incremental streaming encryptor.
///
/// Feed plaintext with [`push`](Self::push) and call [`finish`](Self::finish)
/// once to emit the terminating frame. The concatenated output is the same
/// wire format as [`encrypt_stream`]:
///
/// ```text
/// header (24B) || chunk_0 || chunk_1 || … || chunk_n
/// ```
///
/// Plaintext is framed into 1024-byte chunks; intermediate chunks carry the
/// message tag and the last chunk carries the final tag. Framing is identical
/// regardless of how the input is split across `push` calls. Empty input (no
/// non-empty `push`) produces only the 24-byte header.
pub struct StreamEncryptor {
    /// Underlying secretstream pusher.
    push: crypto_secretstream::PushStream,
    /// Header bytes, emitted ahead of the first frame.
    prefix: Vec<u8>,
    /// Plaintext held until a full chunk is available; at most one chunk.
    buf: Vec<u8>,
    /// Whether any non-empty plaintext has been pushed.
    started: bool,
}

// `buf` holds up to one chunk of caller plaintext; wipe it when the
// encryptor is dropped (including after `finish`, which empties it first).
impl Drop for StreamEncryptor {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.buf.zeroize();
    }
}

impl StreamEncryptor {
    /// Create an encryptor for one stream.
    pub fn new(key: &XChatConversationKey) -> Result<Self, CryptoError> {
        let cs_key = crypto_secretstream::Key::from(*secretstream_key_bytes(key)?);
        let (header, push) = crypto_secretstream::PushStream::init(OsRng, &cs_key);
        Ok(Self {
            push,
            prefix: header.as_ref().to_vec(),
            buf: Vec::new(),
            started: false,
        })
    }

    /// Encrypt a plaintext chunk, returning the ciphertext available so far.
    ///
    /// The last full chunk is held back so [`finish`](Self::finish) can tag the
    /// final frame, so the returned bytes may be empty for small inputs.
    pub fn push(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut out = std::mem::take(&mut self.prefix);
        if !plaintext.is_empty() {
            self.started = true;
            self.buf.extend_from_slice(plaintext);
        }
        while self.buf.len() > DECRYPTED_CHUNK_SIZE {
            let mut frame: Vec<u8> = self.buf.drain(..DECRYPTED_CHUNK_SIZE).collect();
            self.push
                .push(&mut frame, &[], crypto_secretstream::Tag::Message)
                .map_err(|_| CryptoError::EncryptionFailed("secretstream push failed".into()))?;
            out.extend_from_slice(&frame);
        }
        Ok(out)
    }

    /// Emit the final frame and consume the encryptor.
    pub fn finish(mut self) -> Result<Vec<u8>, CryptoError> {
        let mut out = std::mem::take(&mut self.prefix);
        if self.started {
            let mut frame = std::mem::take(&mut self.buf);
            self.push
                .push(&mut frame, &[], crypto_secretstream::Tag::Final)
                .map_err(|_| CryptoError::EncryptionFailed("secretstream push failed".into()))?;
            out.extend_from_slice(&frame);
        }
        Ok(out)
    }
}

/// Encrypt all of `reader` into `writer` using the secretstream wire format.
///
/// Reads one chunk at a time, so memory use is constant regardless of payload
/// size. Empty input produces only the 24-byte header.
pub fn encrypt_stream<R: Read, W: Write>(
    key: &XChatConversationKey,
    mut reader: R,
    mut writer: W,
) -> Result<(), CryptoError> {
    let mut enc = StreamEncryptor::new(key)?;
    let mut chunk = vec![0u8; DECRYPTED_CHUNK_SIZE];
    loop {
        let n = read_full(&mut reader, &mut chunk)
            .map_err(|e| CryptoError::EncryptionFailed(format!("Read failed: {}", e)))?;
        if n == 0 {
            break;
        }
        let out = enc.push(&chunk[..n])?;
        writer.write_all(&out).map_err(write_err)?;
    }
    let out = enc.finish()?;
    writer.write_all(&out).map_err(write_err)?;
    writer.flush().map_err(write_err)?;
    Ok(())
}

/// Incremental streaming decryptor.
///
/// Feed ciphertext with [`push`](Self::push) and call [`finish`](Self::finish)
/// once at end of input. Each chunk fed to `push` is authenticated as it is
/// decrypted, but the stream is only proven complete when `finish` returns
/// `Ok`: a stream that ends before its final frame is rejected as truncated.
/// Callers must therefore not treat plaintext from `push` as complete until
/// `finish` succeeds.
///
/// Input may be split across `push` calls at any byte boundary; frames are
/// reassembled internally.
pub struct StreamDecryptor {
    /// Stream key bytes, used to initialize `pull` once the header is
    /// complete. Held as a wiped-on-drop array because
    /// `crypto_secretstream::Key` does not zeroize itself.
    key: zeroize::Zeroizing<[u8; 32]>,
    /// Underlying secretstream puller; `None` until the header is consumed.
    pull: Option<crypto_secretstream::PullStream>,
    /// Header bytes accumulated until the 24-byte header is complete.
    header: Vec<u8>,
    /// Ciphertext held until a full frame is available; at most one frame.
    buf: Vec<u8>,
    /// Whether any frame has been decrypted.
    saw_chunk: bool,
    /// Whether the final frame has been decrypted.
    saw_final: bool,
}

impl StreamDecryptor {
    /// Create a decryptor for one stream.
    pub fn new(key: &XChatConversationKey) -> Result<Self, CryptoError> {
        Ok(Self {
            key: secretstream_key_bytes(key)?,
            pull: None,
            header: Vec::new(),
            buf: Vec::new(),
            saw_chunk: false,
            saw_final: false,
        })
    }

    /// Decrypt a ciphertext chunk, returning the plaintext recoverable so far.
    ///
    /// The final frame is held back for [`finish`](Self::finish), so the
    /// returned bytes may be empty until enough input has arrived.
    pub fn push(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.saw_final {
            return Err(CryptoError::DecryptionFailed(
                "data after final stream frame".into(),
            ));
        }
        let mut input = ciphertext;

        // Consume the header before any frame can be pulled.
        if self.pull.is_none() {
            let need = SECRETSTREAM_HEADER_SIZE - self.header.len();
            let take = need.min(input.len());
            self.header.extend_from_slice(&input[..take]);
            input = &input[take..];
            if self.header.len() < SECRETSTREAM_HEADER_SIZE {
                return Ok(Vec::new());
            }
            let mut hdr = [0u8; SECRETSTREAM_HEADER_SIZE];
            hdr.copy_from_slice(&self.header);
            self.pull = Some(crypto_secretstream::PullStream::init(
                crypto_secretstream::Header::from(hdr),
                &crypto_secretstream::Key::from(*self.key),
            ));
        }

        self.buf.extend_from_slice(input);
        let pull = self.pull.as_mut().expect("pull initialized above");

        // While more than one full frame is buffered, the leading frame has
        // data after it and so must be a non-final message frame.
        let mut out = Vec::new();
        while self.buf.len() > ENCRYPTED_CHUNK_SIZE {
            let mut frame: Vec<u8> = self.buf.drain(..ENCRYPTED_CHUNK_SIZE).collect();
            let tag = pull
                .pull(&mut frame, &[])
                .map_err(|_| CryptoError::DecryptionFailed("secretstream pull failed".into()))?;
            self.saw_chunk = true;
            out.extend_from_slice(&frame);
            if tag == crypto_secretstream::Tag::Final {
                return Err(CryptoError::DecryptionFailed(
                    "data after final stream frame".into(),
                ));
            }
        }
        Ok(out)
    }

    /// Decrypt the final frame and consume the decryptor.
    ///
    /// Returns an error if the stream ended before its final frame, which
    /// detects truncation. A stream of only the 24-byte header decrypts to
    /// empty output.
    pub fn finish(mut self) -> Result<Vec<u8>, CryptoError> {
        let pull = self.pull.as_mut().ok_or_else(|| {
            CryptoError::DecryptionFailed("stream ended before header was complete".into())
        })?;

        let mut out = Vec::new();
        if !self.buf.is_empty() {
            let mut frame = std::mem::take(&mut self.buf);
            let tag = pull
                .pull(&mut frame, &[])
                .map_err(|_| CryptoError::DecryptionFailed("secretstream pull failed".into()))?;
            self.saw_chunk = true;
            out.extend_from_slice(&frame);
            if tag == crypto_secretstream::Tag::Final {
                self.saw_final = true;
            }
        }

        if self.saw_chunk && !self.saw_final {
            return Err(CryptoError::DecryptionFailed(
                "stream truncated: ended before final frame".into(),
            ));
        }
        Ok(out)
    }
}

/// Decrypt all of `reader` into `writer`, rejecting truncated streams.
///
/// Reads one frame at a time, so memory use is constant regardless of payload
/// size. A non-empty stream that ends before its final frame is rejected.
pub fn decrypt_stream<R: Read, W: Write>(
    key: &XChatConversationKey,
    mut reader: R,
    mut writer: W,
) -> Result<(), CryptoError> {
    let mut dec = StreamDecryptor::new(key)?;
    let mut chunk = vec![0u8; ENCRYPTED_CHUNK_SIZE];
    loop {
        let n = read_full(&mut reader, &mut chunk).map_err(read_err)?;
        if n == 0 {
            break;
        }
        let out = dec.push(&chunk[..n])?;
        writer.write_all(&out).map_err(write_err)?;
    }
    let out = dec.finish()?;
    writer.write_all(&out).map_err(write_err)?;
    writer.flush().map_err(write_err)?;
    Ok(())
}

/// Size of the `crypto_secretstream_xchacha20poly1305` header.
const SECRETSTREAM_HEADER_SIZE: usize = 24;

/// Copy an [`XChatConversationKey`] into a wiped-on-drop 32-byte array for
/// `crypto_secretstream` use (the `Key` type itself does not zeroize, so it
/// is constructed only transiently at stream init).
///
/// The wipe is partial: the transient `crypto_secretstream::Key` built from
/// this array at stream init and the derived state held inside
/// `PushStream`/`PullStream` for the stream's lifetime are *not* zeroized —
/// the upstream types do not implement `Zeroize`. This array being wiped
/// does not remove those residual copies of the key material.
///
/// The raw conversation key is used directly both here (XChaCha20-Poly1305
/// secretstream for media) and as the XSalsa20-Poly1305 message key. The two
/// uses employ different nonce spaces (random 24-byte nonce vs. secretstream
/// header+counter), so keystream reuse does not occur.
fn secretstream_key_bytes(
    key: &XChatConversationKey,
) -> Result<zeroize::Zeroizing<[u8; 32]>, CryptoError> {
    let bytes: [u8; 32] = key
        .encoded()
        .try_into()
        .map_err(|_| CryptoError::InvalidKey("Conversation key must be 32 bytes".into()))?;
    Ok(zeroize::Zeroizing::new(bytes))
}

// Error helpers

fn write_err(e: std::io::Error) -> CryptoError {
    CryptoError::EncryptionFailed(format!("Write failed: {}", e))
}

fn read_err(e: std::io::Error) -> CryptoError {
    CryptoError::DecryptionFailed(format!("Read failed: {}", e))
}

/// Generate cryptographically secure random bytes.
pub fn random_bytes(length: usize) -> Result<Vec<u8>, CryptoError> {
    let mut bytes = vec![0u8; length];
    OsRng.fill_bytes(&mut bytes);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_encrypt_decrypt_message() {
        let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let plaintext = b"Hello, World!";

        let ciphertext = encrypt_message(&key, plaintext).unwrap();

        // Should be: nonce (24) + plaintext (13) + tag (16) = 53
        assert_eq!(ciphertext.len(), NONCE_SIZE + plaintext.len() + TAG_SIZE);

        let decrypted = decrypt_message(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty_message() {
        let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let plaintext = b"";

        let ciphertext = encrypt_message(&key, plaintext).unwrap();
        let decrypted = decrypt_message(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_large_message() {
        let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let plaintext = vec![0xABu8; 10000];

        let ciphertext = encrypt_message(&key, &plaintext).unwrap();
        let decrypted = decrypt_message(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key1 = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let key2 = XChatConversationKey::from_bytes(vec![0x43u8; 32]).unwrap();
        let plaintext = b"Secret message";

        let ciphertext = encrypt_message(&key1, plaintext).unwrap();
        let result = decrypt_message(&key2, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_corrupted_data_fails() {
        let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let plaintext = b"Hello";

        let mut ciphertext = encrypt_message(&key, plaintext).unwrap();
        // Corrupt a byte in the ciphertext
        ciphertext[30] ^= 0xFF;

        let result = decrypt_message(&key, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_stream() {
        let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let plaintext = b"Hello, streaming world! This is a test message.";

        let mut encrypted = Vec::new();
        encrypt_stream(&key, Cursor::new(plaintext.to_vec()), &mut encrypted).unwrap();

        // Should be: header (24) + one chunk (plaintext_len + ABYTES)
        assert_eq!(
            encrypted.len(),
            SECRETSTREAM_HEADER_SIZE + plaintext.len() + SECRETSTREAM_ABYTES
        );

        let mut decrypted = Vec::new();
        decrypt_stream(&key, Cursor::new(encrypted), &mut decrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_stream_large() {
        let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let plaintext = vec![0xABu8; 5000]; // Multiple chunks (5 chunks: 4×1024 + 904)

        let mut encrypted = Vec::new();
        encrypt_stream(&key, Cursor::new(plaintext.clone()), &mut encrypted).unwrap();

        // 5 chunks: 4 full (1024+17 each) + 1 partial (904+17)
        let expected = SECRETSTREAM_HEADER_SIZE
            + 4 * (DECRYPTED_CHUNK_SIZE + SECRETSTREAM_ABYTES)
            + (904 + SECRETSTREAM_ABYTES);
        assert_eq!(encrypted.len(), expected);

        let mut decrypted = Vec::new();
        decrypt_stream(&key, Cursor::new(encrypted), &mut decrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_stream_empty() {
        let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();

        let mut encrypted = Vec::new();
        encrypt_stream(&key, Cursor::new(vec![]), &mut encrypted).unwrap();

        // Empty input → just the 24-byte header, no chunks.
        assert_eq!(encrypted.len(), SECRETSTREAM_HEADER_SIZE);

        let mut decrypted = Vec::new();
        decrypt_stream(&key, Cursor::new(encrypted), &mut decrypted).unwrap();
        assert_eq!(decrypted, Vec::<u8>::new());
    }

    #[test]
    fn test_encrypt_decrypt_stream_exact_chunk() {
        // Exactly one chunk (1024 bytes) — boundary case
        let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let plaintext = vec![0xCDu8; DECRYPTED_CHUNK_SIZE];

        let mut encrypted = Vec::new();
        encrypt_stream(&key, Cursor::new(plaintext.clone()), &mut encrypted).unwrap();

        assert_eq!(
            encrypted.len(),
            SECRETSTREAM_HEADER_SIZE + DECRYPTED_CHUNK_SIZE + SECRETSTREAM_ABYTES
        );

        let mut decrypted = Vec::new();
        decrypt_stream(&key, Cursor::new(encrypted), &mut decrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_stream_tampered_chunk_fails() {
        let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let plaintext = vec![0xABu8; 3000]; // 3 chunks

        let mut encrypted = Vec::new();
        encrypt_stream(&key, Cursor::new(plaintext), &mut encrypted).unwrap();

        // Tamper with a byte in the first chunk (right after the header)
        let tamper_offset = SECRETSTREAM_HEADER_SIZE + 5;
        encrypted[tamper_offset] ^= 0xFF;

        let mut decrypted = Vec::new();
        let result = decrypt_stream(&key, Cursor::new(encrypted), &mut decrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_stream_tampered_header_fails() {
        let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let plaintext = b"test data";

        let mut encrypted = Vec::new();
        encrypt_stream(&key, Cursor::new(plaintext.to_vec()), &mut encrypted).unwrap();

        // Tamper with a byte in the 24-byte header
        encrypted[10] ^= 0x01;

        let mut decrypted = Vec::new();
        let result = decrypt_stream(&key, Cursor::new(encrypted), &mut decrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_stream_wrong_key_fails() {
        let key1 = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let key2 = XChatConversationKey::from_bytes(vec![0x43u8; 32]).unwrap();
        let plaintext = b"secret media payload";

        let mut encrypted = Vec::new();
        encrypt_stream(&key1, Cursor::new(plaintext.to_vec()), &mut encrypted).unwrap();

        let mut decrypted = Vec::new();
        let result = decrypt_stream(&key2, Cursor::new(encrypted), &mut decrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_random_bytes() {
        let bytes1 = random_bytes(32).unwrap();
        let bytes2 = random_bytes(32).unwrap();

        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2); // Should be different (with overwhelming probability)
    }

    #[test]
    fn test_random_bytes_various_sizes() {
        for size in [0, 1, 16, 32, 64, 1024] {
            let bytes = random_bytes(size).unwrap();
            assert_eq!(bytes.len(), size);
        }
    }

    // Additional decrypt_message error-path tests

    #[test]
    fn test_decrypt_message_too_short() {
        let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        // 39 bytes is less than NONCE_SIZE (24) + TAG_SIZE (16) = 40
        let result = decrypt_message(&key, &[0u8; 39]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_message_empty_ciphertext() {
        let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let result = decrypt_message(&key, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_message_exactly_nonce_plus_tag_garbage() {
        // Exactly 40 bytes (nonce + tag, zero-length ciphertext body) but all garbage
        let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let result = decrypt_message(&key, &[0xAA; NONCE_SIZE + TAG_SIZE]);
        // Passes the length check but authentication will fail
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_message_corrupted_nonce() {
        let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let plaintext = b"Hello";
        let mut ciphertext = encrypt_message(&key, plaintext).unwrap();
        // Corrupt byte 0 (inside the nonce region)
        ciphertext[0] ^= 0xFF;
        let result = decrypt_message(&key, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_message_corrupted_tag() {
        let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let plaintext = b"Hello";
        let mut ciphertext = encrypt_message(&key, plaintext).unwrap();
        // Corrupt byte inside the tag region (bytes NONCE_SIZE .. NONCE_SIZE+TAG_SIZE)
        ciphertext[NONCE_SIZE] ^= 0xFF;
        let result = decrypt_message(&key, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_message_single_byte() {
        let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let plaintext = &[0xFF];
        let ciphertext = encrypt_message(&key, plaintext).unwrap();
        assert_eq!(ciphertext.len(), NONCE_SIZE + TAG_SIZE + 1);
        let decrypted = decrypt_message(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    // Additional streaming encryption edge-case tests

    #[test]
    fn test_encrypt_decrypt_stream_two_exact_chunks() {
        let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let plaintext = vec![0xABu8; DECRYPTED_CHUNK_SIZE * 2]; // Exactly 2048 bytes

        let mut encrypted = Vec::new();
        encrypt_stream(&key, Cursor::new(plaintext.clone()), &mut encrypted).unwrap();

        let expected = SECRETSTREAM_HEADER_SIZE + 2 * (DECRYPTED_CHUNK_SIZE + SECRETSTREAM_ABYTES);
        assert_eq!(encrypted.len(), expected);

        let mut decrypted = Vec::new();
        decrypt_stream(&key, Cursor::new(encrypted), &mut decrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_stream_just_over_one_chunk() {
        let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let plaintext = vec![0xABu8; DECRYPTED_CHUNK_SIZE + 1]; // 1025 bytes → 2 chunks

        let mut encrypted = Vec::new();
        encrypt_stream(&key, Cursor::new(plaintext.clone()), &mut encrypted).unwrap();

        // 2 chunks: full (1024+17) + partial (1+17) + header (24)
        let expected = SECRETSTREAM_HEADER_SIZE
            + (DECRYPTED_CHUNK_SIZE + SECRETSTREAM_ABYTES)
            + (1 + SECRETSTREAM_ABYTES);
        assert_eq!(encrypted.len(), expected);

        let mut decrypted = Vec::new();
        decrypt_stream(&key, Cursor::new(encrypted), &mut decrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_stream_three_exact_chunks() {
        let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let plaintext = vec![0xCDu8; DECRYPTED_CHUNK_SIZE * 3]; // 3072 bytes

        let mut encrypted = Vec::new();
        encrypt_stream(&key, Cursor::new(plaintext.clone()), &mut encrypted).unwrap();

        let expected = SECRETSTREAM_HEADER_SIZE + 3 * (DECRYPTED_CHUNK_SIZE + SECRETSTREAM_ABYTES);
        assert_eq!(encrypted.len(), expected);

        let mut decrypted = Vec::new();
        decrypt_stream(&key, Cursor::new(encrypted), &mut decrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_stream_truncated_header() {
        let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        // Stream input shorter than the 24-byte header → read_exact fails
        let mut decrypted = Vec::new();
        let result = decrypt_stream(&key, Cursor::new(vec![0u8; 10]), &mut decrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_stream_truncated_chunk() {
        let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let plaintext = b"Hello, streaming world!";

        let mut encrypted = Vec::new();
        encrypt_stream(&key, Cursor::new(plaintext.to_vec()), &mut encrypted).unwrap();

        // Truncate to just header + 5 bytes (incomplete chunk) → pull fails
        encrypted.truncate(SECRETSTREAM_HEADER_SIZE + 5);

        let mut decrypted = Vec::new();
        let result = decrypt_stream(&key, Cursor::new(encrypted), &mut decrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_stream_empty_header_only() {
        let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        // 24 bytes = valid header but no chunks → should succeed with empty output
        // (same as encrypt_stream with empty input)
        let mut encrypted = Vec::new();
        encrypt_stream(&key, Cursor::new(vec![]), &mut encrypted).unwrap();
        assert_eq!(encrypted.len(), SECRETSTREAM_HEADER_SIZE);

        let mut decrypted = Vec::new();
        decrypt_stream(&key, Cursor::new(encrypted), &mut decrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_decrypt_stream_truncated_at_chunk_boundary_fails() {
        // Dropping trailing *whole* chunks must be detected. Mid-chunk
        // truncation is caught by the Poly1305 tag; boundary truncation
        // is only caught by the TAG_FINAL check.
        let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let plaintext = vec![0xABu8; DECRYPTED_CHUNK_SIZE * 3]; // 3 full chunks

        let mut encrypted = Vec::new();
        encrypt_stream(&key, Cursor::new(plaintext), &mut encrypted).unwrap();

        // Keep header + exactly one intact chunk, drop the rest.
        encrypted.truncate(SECRETSTREAM_HEADER_SIZE + ENCRYPTED_CHUNK_SIZE);

        let mut decrypted = Vec::new();
        let result = decrypt_stream(&key, Cursor::new(encrypted), &mut decrypted);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("truncated"));
    }

    #[test]
    fn test_decrypt_stream_truncated_two_of_three_chunks_fails() {
        // Same as above but keeping two intact chunks of three.
        let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let plaintext = vec![0xCDu8; DECRYPTED_CHUNK_SIZE * 2 + 500]; // 3 chunks

        let mut encrypted = Vec::new();
        encrypt_stream(&key, Cursor::new(plaintext), &mut encrypted).unwrap();

        encrypted.truncate(SECRETSTREAM_HEADER_SIZE + 2 * ENCRYPTED_CHUNK_SIZE);

        let mut decrypted = Vec::new();
        let result = decrypt_stream(&key, Cursor::new(encrypted), &mut decrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_stream_tampered_last_chunk() {
        let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let plaintext = vec![0xABu8; DECRYPTED_CHUNK_SIZE + 500]; // 2 chunks

        let mut encrypted = Vec::new();
        encrypt_stream(&key, Cursor::new(plaintext), &mut encrypted).unwrap();

        // Tamper with the last byte of the ciphertext (inside the final chunk)
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;

        let mut decrypted = Vec::new();
        let result = decrypt_stream(&key, Cursor::new(encrypted), &mut decrypted);
        assert!(result.is_err());
    }

    /// Encrypt `plaintext` through `StreamEncryptor`, feeding it in `step`-byte
    /// pushes.
    fn incremental_encrypt(key: &XChatConversationKey, plaintext: &[u8], step: usize) -> Vec<u8> {
        let mut enc = StreamEncryptor::new(key).unwrap();
        let mut out = Vec::new();
        for chunk in plaintext.chunks(step.max(1)) {
            out.extend_from_slice(&enc.push(chunk).unwrap());
        }
        out.extend_from_slice(&enc.finish().unwrap());
        out
    }

    /// Decrypt `ciphertext` through `StreamDecryptor`, feeding it in `step`-byte
    /// pushes.
    fn incremental_decrypt(
        key: &XChatConversationKey,
        ciphertext: &[u8],
        step: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        let mut dec = StreamDecryptor::new(key)?;
        let mut out = Vec::new();
        for chunk in ciphertext.chunks(step.max(1)) {
            out.extend_from_slice(&dec.push(chunk)?);
        }
        out.extend_from_slice(&dec.finish()?);
        Ok(out)
    }

    #[test]
    fn test_incremental_roundtrip_various_splits() {
        let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        for len in [0usize, 1, 100, 1024, 1025, 2048, 5000, 9000] {
            let plaintext = vec![0xABu8; len];
            for enc_step in [1usize, 7, 1024, 1041, 4096] {
                let ciphertext = incremental_encrypt(&key, &plaintext, enc_step);
                for dec_step in [1usize, 13, 1024, 1041, 4096] {
                    let decrypted = incremental_decrypt(&key, &ciphertext, dec_step).unwrap();
                    assert_eq!(
                        decrypted, plaintext,
                        "len={len} enc={enc_step} dec={dec_step}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_incremental_encrypt_matches_whole_buffer() {
        // Framing must be identical to encrypt_stream regardless of push sizes,
        // so a stream encrypted incrementally decrypts byte-for-byte the same.
        let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        for len in [0usize, 1, 1024, 3000] {
            let plaintext = vec![0x5Au8; len];

            let mut whole = Vec::new();
            encrypt_stream(&key, Cursor::new(plaintext.clone()), &mut whole).unwrap();

            for step in [1usize, 100, 1024, 4096] {
                let incremental = incremental_encrypt(&key, &plaintext, step);
                // Headers differ (random per stream), so compare frame lengths
                // and that both decrypt back to the same plaintext.
                assert_eq!(incremental.len(), whole.len(), "len={len} step={step}");
                let back = incremental_decrypt(&key, &incremental, 1024).unwrap();
                assert_eq!(back, plaintext);
            }
        }
    }

    #[test]
    fn test_incremental_decrypt_truncation_detected() {
        let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let plaintext = vec![0xABu8; DECRYPTED_CHUNK_SIZE * 3];
        let mut encrypted = Vec::new();
        encrypt_stream(&key, Cursor::new(plaintext), &mut encrypted).unwrap();

        // Drop the final whole frame.
        encrypted.truncate(SECRETSTREAM_HEADER_SIZE + 2 * ENCRYPTED_CHUNK_SIZE);
        let err = incremental_decrypt(&key, &encrypted, 1041).unwrap_err();
        assert!(err.to_string().contains("truncated"), "{err}");
    }

    #[test]
    fn test_incremental_decrypt_rejects_data_after_final() {
        let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        // Exactly one chunk → the final frame is a full ENCRYPTED_CHUNK_SIZE
        // frame, so appended bytes land cleanly after it and the guard fires.
        let plaintext = vec![0x11u8; DECRYPTED_CHUNK_SIZE];
        let mut encrypted = Vec::new();
        encrypt_stream(&key, Cursor::new(plaintext), &mut encrypted).unwrap();
        encrypted.extend_from_slice(&[0u8; 100]); // junk after the final frame

        let err = incremental_decrypt(&key, &encrypted, 4096).unwrap_err();
        assert!(err.to_string().contains("final"), "{err}");
    }

    #[test]
    fn test_incremental_empty_stream() {
        let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let enc = StreamEncryptor::new(&key).unwrap();
        let header_only = enc.finish().unwrap();
        assert_eq!(header_only.len(), SECRETSTREAM_HEADER_SIZE);

        let decrypted = incremental_decrypt(&key, &header_only, 8).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_incremental_decrypt_finish_without_header_errors() {
        let key = XChatConversationKey::from_bytes(vec![0x42u8; 32]).unwrap();
        let dec = StreamDecryptor::new(&key).unwrap();
        assert!(dec.finish().is_err());
    }
}
