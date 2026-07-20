# X Chat SDK — Cryptography Reference

This document describes the cryptographic operations, key lifecycle, wire formats, and dependencies used by the X Chat SDK.

## Table of Contents

1. [Dependencies](#1-dependencies)
2. [Key Types](#2-key-types)
3. [Key Lifecycle](#3-key-lifecycle)
4. [ECIES — Asymmetric Encryption](#4-ecies--asymmetric-encryption)
5. [Message Encryption — XSalsa20-Poly1305](#5-message-encryption--xsalsa20-poly1305)
6. [Streaming Encryption](#6-streaming-encryption)
7. [Digital Signatures — ECDSA P-256](#7-digital-signatures--ecdsa-p-256)
8. [Key Derivation Functions](#8-key-derivation-functions)
9. [Encryption Flow](#9-encryption-flow)
10. [Decryption Flow](#10-decryption-flow)
11. [Security Properties](#11-security-properties)

---

## 1. Dependencies

All crypto dependencies are **pure Rust** and **WASM-compatible** (no C bindings, no system libsodium).

| Crate | Version | Purpose |
|-------|---------|---------|
| `p256` | 0.13 | EC P-256 key generation, ECDH key agreement |
| `ecdsa` | 0.16 | ECDSA signing and verification (P-256) |
| `elliptic-curve` | 0.13 | SEC1 point encoding/decoding |
| `aes-gcm` | 0.10 | AES-128-GCM for ECIES payload encryption |
| `xsalsa20poly1305` | 0.9 | XSalsa20-Poly1305 for message encryption (secretbox construction) |
| `crypto_secretstream` | 0.2 | `crypto_secretstream_xchacha20poly1305` for streaming media encryption (libsodium-compatible) |
| `sha2` | 0.10 | SHA-256 hashing |
| `hmac` | 0.12 | HMAC-SHA256; also the building block for the SDK's HKDF-SHA256 expand step (`crypto/hash.rs`) |
| `zeroize` | 1.7 | Secure memory zeroing on drop for all secret key types |
| `rand` | 0.8 | Cryptographically secure random number generation (`OsRng`) |
| `getrandom` | 0.2 | Platform entropy source (backing `OsRng`) |
| `base64` | 0.22 | Base64 encoding for wire transport |

> **Note**: The SDK uses the `xsalsa20poly1305` crate (pure Rust). The wire format is compatible with the secretbox construction used by other X Chat clients.

---

## 2. Key Types

### Identity Keypair (P-256)

- **Purpose**: ECDH key agreement — used to encrypt/decrypt conversation keys
- **Private key**: 32-byte P-256 scalar (`XChatPrivateKey`, purpose `Identity`)
- **Public key**: 65-byte uncompressed SEC1 point `0x04 || x || y` (`XChatPublicKey`, purpose `Identity`)
- **Stored in**: Juicebox (PIN-protected) as the first 32 bytes

### Signing Keypair (P-256)

- **Purpose**: ECDSA signatures — used to sign outgoing messages and verify incoming messages
- **Private key**: 32-byte P-256 scalar (`XChatPrivateKey`, purpose `Signing`)
- **Public key**: 65-byte uncompressed SEC1 point (`XChatPublicKey`, purpose `Signing`)
- **Stored in**: Juicebox (PIN-protected) as bytes 32–63
- **Registered as**: SPKI/DER-encoded public key (91 bytes) in the X API

### Conversation Key (symmetric)

- **Purpose**: Encrypt/decrypt message payloads within a conversation
- **Format**: 32-byte random key (`XChatConversationKey`)
- **Algorithm**: Used with XSalsa20-Poly1305
- **Distribution**: Encrypted per-participant using ECIES with each user's identity public key

### Private Key Storage Format

Private keys are stored as a concatenated blob for Juicebox:

```
┌──────────────────────────┬──────────────────────────┐
│  Identity private key    │  Signing private key     │
│  (32 bytes)              │  (32 bytes, optional)    │
└──────────────────────────┴──────────────────────────┘
```

Total: 32 bytes (identity only) or 64 bytes (identity + signing).

### Memory Safety

All secret key types implement `Zeroize` and `ZeroizeOnDrop` (via the `zeroize` crate) to securely clear key material from memory when keys go out of scope. `Debug` output is redacted for all secret types.

---

## 3. Key Lifecycle

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         KEY LIFECYCLE                                        │
│                                                                             │
│   ┌──────────────┐                                                          │
│   │  generate_   │   Generates P-256 identity + signing keypairs            │
│   │  keypairs()  │   Stores in KeypairManager (in-memory)                   │
│   └──────┬───────┘   Returns PublicKeyRegistrationPayload                   │
│          │                                                                   │
│          ▼                                                                   │
│   ┌──────────────┐                                                          │
│   │   setup()    │   Serializes private keys → 64-byte blob                 │
│   │              │   Registers with Juicebox (PIN-protected)                │
│   └──────┬───────┘   Returns PublicKeys                                     │
│          │                                                                   │
│          ▼                                                                   │
│   ┌──────────────┐                                                          │
│   │  unlock()    │   Recovers 64-byte blob from Juicebox (PIN)              │
│   │              │   Reconstructs keypairs → loads into KeypairManager       │
│   └──────┬───────┘   Keys now available for encrypt/decrypt/sign            │
│          │                                                                   │
│          ▼                                                                   │
│   ┌──────────────┐                                                          │
│   │   (use)      │   decrypt_event(), encrypt_message(), sign(), etc.       │
│   └──────┬───────┘                                                          │
│          │                                                                   │
│          ▼                                                                   │
│   ┌──────────────┐                                                          │
│   │   lock()     │   Zeroizes all keys from memory                          │
│   └──────────────┘                                                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. ECIES — Asymmetric Encryption

ECIES (Elliptic Curve Integrated Encryption Scheme) is used to encrypt conversation keys for distribution to participants. Each participant's copy of the conversation key is encrypted with their identity public key.

### Algorithm

```
Encrypt(recipient_public_key, plaintext):
  1. ephemeral_keypair ← P-256.generate()
  2. shared_secret     ← ECDH(ephemeral_keypair.private, recipient_public_key)
  3. kdf_output (32B)  ← X9.63_KDF(shared_secret, ephemeral_keypair.public)
  4. aes_key (16B)     ← kdf_output[0..16]
  5. iv (16B)          ← kdf_output[16..32]
  6. ciphertext + tag  ← AES-128-GCM(aes_key, iv, plaintext)
  7. output            ← ephemeral_public (65B) || ciphertext || tag (16B)

Decrypt(private_key, data):
  1. ephemeral_public  ← data[0..65]
  2. ciphertext_tag    ← data[65..]
  3. shared_secret     ← ECDH(private_key, ephemeral_public)
  4. kdf_output (32B)  ← X9.63_KDF(shared_secret, ephemeral_public)
  5. aes_key (16B)     ← kdf_output[0..16]
  6. iv (16B)          ← kdf_output[16..32]
  7. plaintext         ← AES-128-GCM.decrypt(aes_key, iv, ciphertext_tag)
```

### Wire Format

```
┌────────────────────────┬────────────────────────┬──────────┐
│  Ephemeral public key  │  Ciphertext            │  Tag     │
│  (65 bytes, SEC1)      │  (variable)            │  (16B)   │
└────────────────────────┴────────────────────────┴──────────┘
```

Minimum output size: 65 + 0 + 16 = **81 bytes** (encrypting empty input).

### Key Derivation (X9.63 KDF / KDF2)

The shared secret from ECDH is not used directly as a key. Instead, it's expanded using X9.63 KDF (ANSI X9.63 / IEEE P1363a / ISO 18033-2):

```
for counter = 1 to ceil(key_length / 32):
    K_i = SHA-256(shared_secret || counter_be32 || shared_info)
output = K_1 || K_2 || ... truncated to key_length
```

- `shared_info` = the ephemeral public key bytes (65 bytes)
- `key_length` = 32 bytes (16 for AES key + 16 for IV)

### AES-GCM Configuration

| Parameter | Value |
|-----------|-------|
| Algorithm | AES-128-GCM |
| Key size | 16 bytes (128 bits) |
| Nonce/IV size | **16 bytes** (non-standard) |
| Tag size | 16 bytes (128 bits) |
| AAD | None (empty) |

> **Important**: This uses a **16-byte nonce** for AES-GCM, not the NIST-recommended 12-byte nonce (SP 800-38D). This is a cross-platform protocol compatibility requirement. Non-96-bit nonces are processed through GHASH to derive J0. This is safe because every nonce is derived from a fresh ephemeral ECDH shared secret and is never reused. The `aes-gcm` crate supports this via `AesGcm<Aes128, U16>`.

---

## 5. Message Encryption — XSalsa20-Poly1305

Message payloads (the decrypted Thrift `MessageEntryHolder`) are encrypted using XSalsa20-Poly1305 (the secretbox construction).

### Algorithm

```
Encrypt(conversation_key, plaintext):
  1. nonce (24B) ← random()
  2. (ciphertext, tag) ← XSalsa20-Poly1305.encrypt(conversation_key, nonce, plaintext)
  3. output ← nonce || tag || ciphertext

Decrypt(conversation_key, data):
  1. nonce      ← data[0..24]
  2. tag        ← data[24..40]
  3. ciphertext ← data[40..]
  4. plaintext  ← XSalsa20-Poly1305.decrypt(conversation_key, nonce, tag, ciphertext)
```

### Wire Format

```
┌──────────┬──────────┬────────────────────────┐
│  Nonce   │  Tag     │  Ciphertext            │
│  (24B)   │  (16B)   │  (same length as PT)   │
└──────────┴──────────┴────────────────────────┘
```

Total size = plaintext length + **40 bytes** overhead (24 nonce + 16 tag).

### Parameters

| Parameter | Value |
|-----------|-------|
| Algorithm | XSalsa20-Poly1305 |
| Key size | 32 bytes (256 bits) |
| Nonce size | 24 bytes (192 bits) |
| Tag size | 16 bytes (128 bits) |
| AAD | None (empty) |

> The 24-byte nonce is large enough to be generated randomly without realistic collision risk (~2^96 messages before birthday bound).

---

## 6. Streaming Encryption

Large payloads (e.g., media attachments) use `crypto_secretstream_xchacha20poly1305` — the libsodium secretstream AEAD construct. This is a pure-Rust implementation (via the `crypto_secretstream` crate) that produces wire-format-compatible output with libsodium.

### Algorithm

```
Encrypt(conversation_key, plaintext_stream):
  1. (header, state) ← secretstream_init_push(conversation_key)
  2. Write: header (24B)
  3. chunks ← split plaintext into 1024-byte blocks
  4. For each chunk (except last):
       encrypted_chunk ← secretstream_push(state, chunk, TAG_MESSAGE)
       Write: encrypted_chunk
  5. For last chunk:
       encrypted_chunk ← secretstream_push(state, chunk, TAG_FINAL)
       Write: encrypted_chunk

Decrypt(conversation_key, encrypted_stream):
  1. Read: header (24B)
  2. state ← secretstream_init_pull(conversation_key, header)
  3. Loop:
       encrypted_chunk ← Read(≤1041 bytes)
       (plaintext_chunk, tag) ← secretstream_pull(state, encrypted_chunk)
       Write: plaintext_chunk
       if tag == TAG_FINAL: break
  4. If the input ended without a TAG_FINAL chunk, reject as truncated.
```

### Wire Format

```
┌──────────┬──────────┬──────────┬─────┐
│  Header  │ Chunk 0  │ Chunk 1  │ ... │
│  (24B)   │ (≤1041B) │ (≤1041B) │     │
└──────────┴──────────┴──────────┴─────┘
```

### Parameters

| Parameter | Value |
|-----------|-------|
| Algorithm | `crypto_secretstream_xchacha20poly1305` |
| Plaintext chunk size | 1024 bytes |
| Overhead per chunk (ABYTES) | 17 bytes (1 tag byte + 16 MAC bytes) |
| Encrypted chunk size | 1041 bytes (1024 + 17) |
| Header size | 24 bytes |
| Tags | `TAG_MESSAGE` (intermediate), `TAG_FINAL` (last chunk) |
| Empty input | Header only (24 bytes), no chunks |

### Truncation detection

Every non-empty stream ends with a `TAG_FINAL` chunk. Decryption rejects a
non-empty stream that ends before its `TAG_FINAL` chunk, so dropping trailing
whole chunks (which the per-chunk MAC alone cannot catch) is detected. The only
stream that legitimately has no `TAG_FINAL` is the empty stream (bare 24-byte
header).

### Incremental API

For large payloads, the whole-buffer `encrypt_stream` / `decrypt_stream` have
incremental counterparts so callers can process one chunk at a time without
holding the entire payload in memory: a stream encryptor and decryptor that
accept chunks via `push` and emit the final frame via `finish`. Output bytes
are byte-for-byte identical to the whole-buffer functions regardless of how the
input is split. Because truncation is only proven absent once `finish`
succeeds, plaintext returned by `push` must not be treated as complete until
`finish` returns successfully.

---

## 7. Digital Signatures — ECDSA P-256

All outgoing messages are signed with the user's signing key. Incoming messages have their signatures verified before being trusted.

### Signing

```
Sign(signing_private_key, payload):
  1. signature (64B) ← ECDSA-P256-SHA256.sign(signing_private_key, payload)
  2. Return signature as raw r || s (32 + 32 bytes)
```

### Verification

```
Verify(signing_public_key, signature, payload):
  1. Parse r || s from signature (64 bytes)
  2. result ← ECDSA-P256-SHA256.verify(signing_public_key, signature, payload)
  3. Return true/false
```

### Signature Format

All ECDSA signatures are raw `r || s` (64 bytes):

| Context | Format | Length | Used By |
|---------|--------|--------|---------|
| Message signing (`KeyFactory::sign`) | Raw `r \|\| s` | 64 bytes | `encrypt_message`, `encrypt_reply`, `encrypt_add_reaction`, `encrypt_remove_reaction` |
| Action signing | Raw `r \|\| s` | 64 bytes | `prepare_conversation_key_change`, `prepare_group_create`, `prepare_group_members_change` |
| Key registration (`generate_keypairs`) | Raw `r \|\| s` | 64 bytes | `identity_public_key_signature` in registration payload |

### Signature Versions

The signature protocol is versioned, and the version travels with each signature
(`MessageEventSignature.signature_version` / `ActionSignature.signature_version`).

| Constant | Value | Meaning |
|----------|-------|---------|
| `SIGNATURE_VERSION` (current) | `"7"` | Stamped on every signature the SDK produces |
| `MIN_SIGNATURE_VERSION` | `2` | Oldest version accepted on verification; older payloads omit the event-type discriminant and conversation-key version, so they are rejected to prevent downgrade |
| `CKEY_PLAINTEXT_SIGNATURE_VERSION` | `6` | First version whose conversation-key-change payload signs the plaintext conversation key (so a recipient can reproduce and verify it) |

### What Gets Signed

All message-creation methods (`encrypt_message`, `encrypt_reply`,
`encrypt_add_reaction`, `encrypt_remove_reaction`) share one signing path
(`encrypt_and_sign`). The signature is computed over a **comma-separated
component payload**, not over the raw ciphertext:

```
"MessageCreateEvent,{message_id},{sender_id},{conversation_id},{conversation_key_version},{contents_b64_no_pad}"
```

`contents_b64_no_pad` is the Base64-without-padding (`STANDARD_NO_PAD`) encoding
of the XSalsa20-Poly1305 ciphertext. Signing the surrounding metadata (sender,
conversation, key version) binds the signature to its context and prevents a
signature from being replayed onto a different message or conversation.

`message_id` is generated by the SDK (a random UUID) in the encrypt entry
points, so it is bound into the signature the same way, and returned to the
caller in the `SendPayload`. Callers do not supply it: reuse the returned
payload on retries so the id is never minted twice for one logical message.

#### Action signatures

Group operations are signed the same way, over their own comma-separated
payloads (`signatures.rs`):

- **GroupCreate** (from `prepare_group_create`, v4+):
  ```
  "GroupChangeEvent.GroupCreate,{message_id},{sender_id},{conversation_key_version},{member_ids...},{is_legacy_group_upgrade},{title},{avatar_url}"
  ```
  The conversation id, admin ids, and TTL are carried in the event detail but
  are **not** part of the signed payload; absent `is_legacy_group_upgrade`,
  `title`, and `avatar_url` render as the literal `null`.
- **GroupMemberAdd** (from `prepare_group_members_change`, v7 field layout):
  ```
  "GroupChangeEvent.GroupMemberAddChange,{message_id},{sender_id},{conversation_id},{new_member_ids...},{current_member_ids...},{current_admin_ids...},{title},{avatar_url},{ttl_msec},{conversation_key_version},{screen_capture_blocking}"
  ```
  Pending member ids are not signed at v7; absent `title`/`avatar_url`/`ttl_msec`
  render as the literal `null`. The trailing screen-capture slot is the
  caller-supplied `current_screen_capture_blocking_enabled` flag — the group's
  current screen-capture-blocking state — and renders as `null` when unset.
- **ConversationKeyChange** (from `prepare_conversation_key_change`, v6+):
  ```
  "ConversationKeyChangeEvent,{message_id},{sender_id},{conversation_id},{conversation_key_version},{conversation_key_b64_no_pad}"
  ```
  where `conversation_key_b64_no_pad` is the Base64-without-padding encoding of
  the plaintext 32-byte conversation key.

Both `prepare_group_create` and `prepare_group_members_change` emit **two**
action signatures — a `ConversationKeyChangeEvent` plus the group change — since
the backend validates the pair together.

These payloads are comma-joined with no escaping, and the verifier rejects any
component containing a comma. String fields signed inline — group `title` and
`avatar_url` for GroupCreate/GroupMemberAdd — must therefore not contain a `,`,
or the resulting signature is unverifiable.

### Base64 Conventions

Two base64 flavors appear on the wire, and both are frozen for interop with
other X Chat clients. ECDSA signature values (`MessageEventSignature.signature`,
`ActionSignature.signature`) and byte values embedded inside signed payloads
(the ciphertext and plaintext conversation key components above) use standard
base64 **without** padding (`STANDARD_NO_PAD`). Encoded Thrift blobs —
`encrypted_content`, `encoded_event_signature`, and
`ActionSignature.encoded_message_event_detail` — use standard base64 **with**
padding (`base64_encode` in `protocol/serialization.rs`); decoding accepts
either form (`DecodePaddingMode::Indifferent`), but producers must not swap
conventions.

### Public Key Encoding

When registering keys or embedding in signatures:

| Format | Size | Where Used |
|--------|------|------------|
| SEC1 uncompressed (`0x04 \|\| x \|\| y`) | 65 bytes | Internal key storage, ECDH |
| SPKI/DER | 91 bytes | X API registration, `MessageEventSignature.signing_public_key` |

The `Chat::verify()` method automatically handles both 91-byte SPKI and 65-byte raw keys by stripping the 26-byte SPKI header when present.

---

## 8. Key Derivation Functions

### HKDF-SHA256

Used for deriving conversation keys from tree secrets and general key derivation.

```
HKDF-Extract (RFC 5869 §2.2):
  PRK = HMAC-SHA256(key=salt, msg=IKM)

HKDF-Expand:
  T(0) = empty
  T(i) = HMAC-SHA256(T(i-1) || counter_byte, PRK)
  Output = T(1) || T(2) || ... truncated to desired length
```

The extract step follows standard HKDF (RFC 5869).  The `hmac_sha256(message, key)` helper uses `(message, key)` argument order — so `hmac_sha256(secret, salt)` is `HMAC(key=salt, msg=IKM)`, which is the standard order.

**Notes**:
- Expand step does not use an `info` parameter — just `T(i-1) || counter`
- Empty salt string is treated as 32 zero bytes

### X9.63 KDF (KDF2)

Used by ECIES for deriving AES key + IV from the ECDH shared secret.

```
for counter = 1, 2, ...:
    K_i = SHA-256(shared_secret || counter_be32 || shared_info)
output = K_1 || K_2 || ... truncated to key_length
```

- `shared_info` = ephemeral public key bytes (65 bytes)

---

## 9. Encryption Flow

Complete flow for encrypting a message via `encrypt_message()` (the `encrypt_reply` / `encrypt_add_reaction` / `encrypt_remove_reaction` methods share the same pipeline):

```
                  Text: "Hello!"  +  optional entities
                              │
                              ▼
            ┌─────────────────────────────────┐
            │  1. Build rich-text entities    │
            │     (if provided: url, mention, │
            │      hashtag descriptors →      │
            │      Thrift RichTextEntity)     │
            │  2. Serialize text + entities   │
            │     as Thrift MessageEntryHolder│
            │     (TBinaryProtocol)           │
            └────────────────┬────────────────┘
                             │ content_bytes
                             ▼
            ┌─────────────────────────────────┐
            │  3. Wrap the caller-supplied    │
            │     raw 32-byte conversation    │
            │     key (already ECIES-decrypted│
            │     by decrypt_conversation_key │
            │     or extract_conversation_    │
            │     keys) → XChatConversationKey│
            └────────────────┬────────────────┘
                             │ conversation_key
                             ▼
            ┌─────────────────────────────────┐
            │  4. Encrypt content             │
            │     XSalsa20-Poly1305(          │
            │       conversation_key,         │
            │       content_bytes             │
            │     ) → encrypted_bytes         │
            └────────────────┬────────────────┘
                             │ encrypted_bytes
                             ▼
            ┌─────────────────────────────────┐
            │  5. Wrap in MessageCreateEvent  │
            │     (Thrift struct with         │
            │      conv_key_version,          │
            │      should_notify, etc.)       │
            │     Serialize → event_bytes     │
            └────────────────┬────────────────┘
                             │ event_bytes
                             ▼
            ┌─────────────────────────────────┐
            │  6. Sign the component payload  │
            │     ECDSA-P256(                 │
            │       signing_private_key,      │
            │       "MessageCreateEvent,…,    │
            │        contents_b64_no_pad"     │
            │     ) → signature               │
            └────────────────┬────────────────┘
                             │
                             ▼
            ┌─────────────────────────────────┐
            │  7. Build MessageEventSignature │
            │     (Thrift struct with         │
            │      signature_b64,             │
            │      signing_key_version,       │
            │      version = "7")             │
            └────────────────┬────────────────┘
                             │
                             ▼
                        SendPayload {
                          encrypted_content: base64(event_bytes),
                          signature: base64(signature),
                          encoded_event_signature: base64(sig_thrift),
                          ...
                        }
```

---

## 10. Decryption Flow

Complete flow for decrypting a webhook event via `decrypt_event()`:

```
            event_b64, conversation_keys (version → key), signing_keys
                              │
                              ▼
            ┌─────────────────────────────────┐
            │  1. Base64-decode event         │
            └────────────────┬────────────────┘
                             │ event_bytes
                             ▼
            ┌─────────────────────────────────┐
            │  2. Parse Thrift MessageEvent   │
            │     (TBinaryProtocol)           │
            └────────────────┬────────────────┘
                             │ MessageEvent (detail, signature, meta)
                             ▼
            ┌─────────────────────────────────┐
            │  3. Route on MessageEventDetail │
            │     union variant               │
            │     (MessageCreateEvent,        │
            │      KeyChange, Typing, etc.)   │
            └────────────────┬────────────────┘
                             │ If MessageCreateEvent:
                             ▼
            ┌─────────────────────────────────┐
            │  4. Look up conversation key    │
            │     by mce.conversation_key_    │
            │     version in the pre-extracted│
            │     map (ECIES already done in  │
            │     extract_conversation_keys)  │
            └────────────────┬────────────────┘
                             │
                             ▼
            ┌─────────────────────────────────┐
            │  5. Decrypt content             │
            │     XSalsa20-Poly1305.decrypt(  │
            │       conversation_key,         │
            │       mce.contents              │
            │     ) → plaintext_bytes         │
            └────────────────┬────────────────┘
                             │
                             ▼
            ┌─────────────────────────────────┐
            │  6. Verify signature            │
            │     Pick signing key whose      │
            │     version matches the sig;    │
            │     rebuild the comma-separated  │
            │     component payload and        │
            │     ECDSA-P256.verify(...) → bool│
            │     Under reject_unverified,     │
            │     both invalid and "no key"    │
            │     (Ok(false)) → return Err     │
            └────────────────┬────────────────┘
                             │
                             ▼
            ┌─────────────────────────────────┐
            │  7. Parse content               │
            │     Thrift MessageEntryHolder    │
            │     (TBinaryProtocol)           │
            └────────────────┬────────────────┘
                             │
                             ▼
            ┌─────────────────────────────────┐
            │  8. Map to Event enum           │
            │     MessageEntryContents →      │
            │     MessageContent::Text,       │
            │     Reaction, Edit, etc.        │
            └────────────────┬────────────────┘
                             │
                             ▼
                      Event::Message(Message {
                        content: MessageContent::Text { text, ... },
                        verified: true/false,
                        attachments: [...],
                        ...
                      })
```

### Reply preview validation

A reply's preview (the quoted sender, text, entities, and attachments of the
message being replied to) travels **inside the encrypted envelope**, so the
backend cannot check it — only the recipient can. Without validation, any
conversation participant could attribute fabricated words to another
participant.

The SDK closes this on both sides:

- **Send** (`encrypt_reply` with a raw event): the preview fields are derived
  from the decrypted original, and the original's **raw signed event** is
  embedded in the preview (`raw_event_message_create`), together with any
  key-change events needed to decrypt it (`raw_event_ckces`) when the original
  was encrypted under a different conversation-key version than the reply.
  When the original was **edited**, pass the raw edit event
  (`reply_to_edit_event`): it is embedded as `raw_event_edit_message` and the
  preview's text and entities derive from the edit's contents — the preview
  quotes what the message says now. Attachments always derive from the
  original (edits do not carry them).
- **Receive** (`decrypt_event` / `decrypt_events`): when a decrypted message
  carries a preview with an embedded raw event, the SDK always validates it:
  1. The raw event must belong to the **same conversation** as the reply.
  2. Its **signature is verified** against the caller-supplied signing keys —
     the same per-sender filtering and version selection as top-level events;
     a key carried inside the event is never used.
  3. Its contents are **decrypted** (using the supplied conversation keys, the
     embedded key-change events, or the opt-in key cache) and every claim the
     preview makes is compared against the decrypted contents: sender id,
     sequence id, message id, text (truncation-tolerant — the claimed text
     must match the quoted contents up to the preview's own length on a
     character boundary), entities, and attachments.
  4. When an **edit event is embedded**, it must verify the same way and come
     from the original's author, and the text and entity claims are checked
     against the edit's updated contents instead of the original's; the
     attachment claims still check against the original.

A `Valid` outcome authenticates the quoted **content and authorship** — the
signature covers the original's message id, sender, conversation, key version,
and ciphertext. It does **not** authenticate the sequence-id anchor: sequence
ids are unsigned backend metadata, so the sequence-id claim is only checked
for consistency with the embedded event's own (rewritable) envelope. Anchor
reply navigation on the signed `replying_to_message_id`, not the sequence id.

The outcome is surfaced on the decrypted message as
`reply_preview_validation` (`Valid` / `Invalid`); the batch path never throws
for an invalid preview — the message itself is authentic, only the quoted
material inside it is untrusted. A preview without an embedded raw event
passes through with no validation outcome, so histories written before raw
events were embedded remain readable.

---

## 11. Security Properties

### Confidentiality

| Layer | Protection |
|-------|-----------|
| Conversation keys | ECIES (ECDH P-256 + AES-128-GCM) — only the intended recipient can decrypt |
| Message payloads | XSalsa20-Poly1305 — 256-bit key, 192-bit nonce (random) |
| Keys at rest | Juicebox distributed PIN-protected storage |

### Integrity & Authentication

| Layer | Protection |
|-------|-----------|
| Message payloads | Poly1305 MAC (embedded in XSalsa20-Poly1305) |
| Conversation keys | GCM tag (embedded in ECIES AES-128-GCM) |
| Message authorship | ECDSA P-256 signature over encrypted content |

### Memory Safety

| Property | Mechanism |
|----------|-----------|
| Key zeroization | `zeroize` crate — all `XChatPrivateKey`, `XChatConversationKey`, and `XChatPrivateKeys` types implement `ZeroizeOnDrop` |
| Debug redaction | `Debug` impl outputs `[REDACTED]` for all secret types |
| No key logging | Private key bytes are never written to logs or error messages |

### Conversation-Key Cache (opt-in)

`set_cache_keys(true)` enables a per-conversation cache that lets the encrypt
methods resolve an omitted `conversation_key`/`conversation_key_version` pair
and the decrypt methods fall back when no key map is passed. Its guardrails:

- A key enters the cache **only** when its key-change event carries a valid
  signature — a merely adopted (unverified) key change can decrypt history but
  never becomes an encryption key.
- The cached version follows the per-conversation monotonic high-water mark:
  a replayed older key change, even validly signed, never displaces a newer
  cached key, so encryption cannot be downgraded to a stale key.
- Cached keys are held in zeroize-on-drop containers, redacted from `Debug`
  output, and cleared when the cache is disabled.
- The signing-key store (`set_signing_keys`) is populated only by that
  explicit call — verification never trusts a key carried inside an event —
  and the per-sender filtering plus identity-binding checks run against the
  stored entries exactly as they do for caller-passed keys.

### Known Limitations

#### No Forward Secrecy

The protocol uses long-lived symmetric conversation keys encrypted under long-term identity public keys. There is no key ratcheting, ephemeral key exchange, or session-level key derivation. Compromise of an identity private key exposes all conversation keys ever encrypted to that public key, and therefore all past and future messages in those conversations.

This differs from protocols like Signal's Double Ratchet, where each message derives keys from ephemeral material that is deleted after use.

#### No Post-Compromise Security

If an identity key is compromised and later rotated, messages encrypted under the old key remain decryptable by the attacker. There is no mechanism by which a key rotation retroactively protects prior messages.

#### Conversation Key Reuse

A single conversation key is generated per conversation (or per key rotation event) and reused for every message until the next rotation. All messages under the same conversation key share the same symmetric secret.

#### Implications

Integrators should understand that:
- Extracting conversation keys from a device exposes the **full message history** of that conversation.
- A passive attacker with access to the identity private key can eavesdrop on all future messages **undetectably**.
- Key rotation (`KeyChangeEvent`) creates a new conversation key but does **not** retroactively protect messages encrypted under the previous key.

### Random Number Generation

All randomness (key generation, nonces, IVs) uses `OsRng` via the `rand` crate, which sources entropy from the operating system:

| Platform | Source |
|----------|--------|
| Linux/macOS | `getrandom(2)` / `/dev/urandom` |
| Windows | `BCryptGenRandom` |
| WASM (browser) | `crypto.getRandomValues()` |
| WASM (Node.js) | `crypto.randomFillSync()` |