# X Chat SDK — Cryptography Reference

This document describes the cryptographic operations, key lifecycle, wire formats, and dependencies used by the X Chat SDK.

## Table of Contents

1. [Dependencies](#1-dependencies)
2. [Key Types](#2-key-types)
3. [Key Lifecycle](#3-key-lifecycle)
4. [ECIES — Asymmetric Encryption](#4-ecies--asymmetric-encryption)
5. [Message Encryption — XSalsa20-Poly1305](#5-message-encryption--xsalsa20-poly1305)
6. [File Encryption](#6-file-encryption)
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
| `crypto_secretstream` | 0.2 | `crypto_secretstream_xchacha20poly1305` for media file encryption (libsodium-compatible) |
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

Message payloads (the decrypted Thrift `MessageEntryHolder`) are encrypted using XSalsa20-Poly1305 (the secretbox construction). A group's title and description are encrypted the same way under the conversation key: `prepare_group_create` (under the key it seeds), `prepare_group_members_change` and `prepare_group_members_remove` (under the key they rotate to), `prepare_group_title_change` and `prepare_group_description_change` encrypt the plaintext the caller passes, `decrypt_event` decrypts a received create or change, and `decrypt` opens the values the X API returns with a conversation. A received value that names no key version is plaintext, and one that does not decrypt comes back unavailable, with the value as carried, rather than failing the event. A group's avatar URL is not encrypted: the app encrypts the image under the conversation key with `encrypt_file_with_key` (see [Files under a key](#files-under-a-key)) and uploads it, and the avatar change signs the media URL with the version of the key the image is encrypted under.

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

### Message Keys

A message whose `MessageCreateEvent.contents_encryption_version` is 1 or more
is encrypted under its own **message key** instead of the conversation key,
with the same algorithm and wire format:

```
message_key = HKDF-SHA256(ikm  = conversation_key,
                          salt = "xchat-message-key",
                          info = "{sender_id}:{message_id}",
                          length = 32)
```

`sender_id` is the event's sender in canonical decimal and `message_id` is the
event's own message id, so every event that carries message contents (texts,
edits, reactions, …) has its own key. An unset, zero, or negative
`contents_encryption_version` means the conversation key.

The SDK decrypts both forms, and sends each message, reply, reaction, and edit
in one of two formats:

- **v1** encrypts the contents under the message key, carries
  `contents_encryption_version` 1, and is signed at signature version 10,
  whose payload covers that field.
- **v0** encrypts the contents under the conversation key, leaves
  `contents_encryption_version` unset, and is signed at signature version 7,
  as 0.5.x sends.

A chat sends v1 while the X API's `v1_send` feature switch is on for it, and
v0 otherwise: the language bindings read the switch themselves, and a Rust
app or a direct C ABI caller hands a chat the answer with
`set_feature_switches` (`chat_xdk_set_feature_switches`). The sender id must be
the sender's numeric user id, the form the key derivation and recipients use.
The SDK generates the message id and returns it in the `SendPayload`: one
derived from its files for a v1 message with files (see
[Media Keys](#media-keys)), and a random one otherwise.

Readers that predate message keys cannot open v1 messages: they decrypt the
contents with the conversation key, and readers that do not know signature
version 10 reject the signature.

---

## 6. File Encryption

Files (e.g., media attachments) use `crypto_secretstream_xchacha20poly1305` — the libsodium secretstream AEAD construct. This is a pure-Rust implementation (via the `crypto_secretstream` crate) that produces wire-format-compatible output with libsodium.

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

Every non-empty encrypted file ends with a `TAG_FINAL` chunk. Decryption
rejects a non-empty file that ends before its `TAG_FINAL` chunk, so dropping
trailing whole chunks (which the per-chunk MAC alone cannot catch) is detected.
The only file that legitimately has no `TAG_FINAL` is the empty file (bare
24-byte header). Nothing in a bare header is authenticated, so any 24 bytes
decrypt to an empty file under any key, and a file cut to its header can't
be told from an empty one: a caller whose files are never empty, such as a
message's media or a group's avatar image, treats an empty result as a
failure.

### Incremental API

For large files, the whole-file `encrypt_file` / `decrypt_file` have
incremental counterparts, `file_encryptor` / `file_decryptor`, so callers can
process one chunk at a time without holding the entire file in memory: they
accept chunks via `push` and emit the final frame via `finish`. Output bytes
are byte-for-byte identical to the whole-file functions regardless of how the
input is split. Because truncation is only proven absent once `finish`
succeeds, plaintext returned by `push` must not be treated as complete until
`finish` returns successfully.

### Files under a key

`encrypt_file_with_key` and `decrypt_file_with_key` run the algorithm above
under a raw 32-byte key the caller passes, with nothing derived from a
message: for a file no message carries, such as a group's avatar image, which
X clients encrypt under the conversation key whose version the avatar change
signs, or an app's own files at rest. A key that is not 32 bytes is rejected.
These are the files 0.5.x `encrypt_stream` and `decrypt_stream` wrote and
read: each release opens the other's.

### Media Keys

Each media file is encrypted under one key, set by the message that carries
it. A message without a [message key](#message-keys) encrypts its media
under the conversation key. A message with one encrypts each attachment under
its own key:

```
attachment_key = HKDF-SHA256(ikm  = message_key,
                             salt = "xchat-attachment-key",
                             info = attachment_id (UTF-8),
                             length = 32)
```

`attachment_id` is the attachment's `attachment_id` when set (an empty string
counts as set); otherwise it is the message id for the first attachment and
`{message_id}#{index}` for later ones, by position in the message's attachment
list, counting every attachment, including kinds the SDK does not surface. A
URL card's banner and favicon images share the card's key.

On send, the message is built before its files are encrypted. Each file of
the message names the media hash key its upload started with. `encrypt_file`
and `file_encryptor` take the message's `event_b64` (returned in the
`SendPayload`), the conversation key the message was encrypted under (passed
with its version, or resolved from the key cache), and the file's media hash
key: they find the attachment in the message, derive the message key and that
attachment's key, and encrypt the file under it, so a file's key always
matches the message that carries it. They need no session identity: the
sender, message id and key version come from the event. The SDK writes each
attachment's id into the message explicitly — the message id for the first
and `{message_id}#{index}` for later ones — so recipients derive the same keys
whatever their fallback.

A v1 message with files takes its id from them:

```
info       = len(conversation_key_version) ‖ conversation_key_version
           ‖ len(sender_id)                ‖ sender_id
           ‖ len(conversation_id)          ‖ conversation_id
           ‖ len(media_hash_key_1)         ‖ media_hash_key_1 ‖ …
bytes      = HKDF-SHA256(ikm  = conversation_key,
                         salt = "chat-xdk-media-message-id",
                         info = info,
                         length = 16)
message_id = bytes as a version-4 UUID (version and variant bits set),
             lowercase and hyphenated
```

Each `len` is the field's byte length as a big-endian u64, so no two inputs
share an encoding. `sender_id` is the numeric sender, `conversation_id` the
canonical form that is signed, and the media hash keys are the message's
files in attachment order (a URL card contributes its banner, then its
favicon). Every upload has its own media hash key, so the id is unique to
the message, and building the same message again (same files, sender,
conversation and key) gives the same id, which keeps the files already
encrypted for it valid. The text does not affect the id. A message without
files, and every v0 message, takes a random version-4 UUID: v0 files use the
conversation key, so their keys don't depend on the id. A message that lists an empty media hash
key, or lists one in more than one attachment, is rejected: each file is
uploaded once and encrypted under the key of the one attachment that names it
(a URL card's banner and favicon share the card's key, so they may share an
upload).

`decrypt_file` and `file_decryptor` take the event of the message that carries
the media, the conversation key map, and the media hash key, and derive the
key from those alone:

1. Parse the event. It must be a `MessageCreateEvent` with a conversation key
   version; one without is unencrypted, and so is its media.
2. Take the key for that version from the map, derive the message key when the
   message uses one, and decrypt the contents.
3. Find the attachment whose media hash key matches: a media attachment, or a
   URL card whose banner or favicon carries it. Its key follows from step 2 as
   described above.
4. Otherwise, when the message is a reply whose preview embeds the quoted
   message from the same conversation, open the quoted message with the key for
   its own version from the map — or, when the map lacks that version and the
   quoted message uses a message key, with the key the reply carries for it —
   and find the attachment there.
5. Decrypt the bytes with that key alone.

Nothing is kept between calls, so the result does not depend on what the
instance decrypted before. Signatures are not checked here; the `verified` flag
from `decrypt_event` covers the message.

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
(`MessageEventSignature.signature_version`, which an `ActionSignature` nests
as `message_event_signature.signature_version`).

| Constant | Value | Meaning |
|----------|-------|---------|
| `MESSAGE_SIGNATURE_VERSION` | `10` | Stamped on every v1 message the SDK sends: the first version that signs `contents_encryption_version` |
| `SIGNATURE_VERSION` | `"7"` | Stamped on v0 messages and on the action signatures the SDK produces (conversation-key changes, group changes, deletes, read receipts) |
| `MIN_SIGNATURE_VERSION` | `2` | Oldest version accepted on verification; older payloads omit the event-type discriminant and conversation-key version, so they are rejected to prevent downgrade |
| `MAX_SIGNATURE_VERSION` (internal) | `11` | Newest version accepted on verification; a signature labeled with a newer version is rejected, since its payload layout is unknown |
| `CKEY_PLAINTEXT_SIGNATURE_VERSION` | `6` | First version whose conversation-key-change payload signs the plaintext conversation key (so a recipient can reproduce and verify it) |

### What Gets Signed

All message-creation methods (`encrypt_message`, `encrypt_reply`,
`encrypt_add_reaction`, `encrypt_remove_reaction`, `encrypt_edit`) share one
signing path (`encrypt_and_sign`), which signs with the payload builder
verification uses: at version 10 for a v1 send, at version 7 for a v0 send.
The signature is computed over a **comma-separated component payload**, not
over the raw ciphertext. A v1 send signs:

```
"MessageCreateEvent,{message_id},{sender_id},{conversation_id},{conversation_key_version},{contents_b64_no_pad},1,signature_version=10"
```

`conversation_key_version` is signed as an integer, and `1` is the
`contents_encryption_version`, so the choice of key for the contents is
covered by the signature. A v0 send signs the version 7 layout, which signs
the key version as carried and has neither trailing component:

```
"MessageCreateEvent,{message_id},{sender_id},{conversation_id},{conversation_key_version},{contents_b64_no_pad}"
```

`contents_b64_no_pad` is the Base64-without-padding (`STANDARD_NO_PAD`) encoding
of the XSalsa20-Poly1305 ciphertext. Signing the surrounding metadata (sender,
conversation, key version) binds the signature to its context and prevents a
signature from being replayed onto a different message or conversation.

`message_id` is a version-4 UUID the encrypt entry point generates — derived
from its files for a v1 message with files (see [Media Keys](#media-keys)),
random otherwise — bound into the signature the same way and
returned in the `SendPayload`. Reuse the returned payload on retries so one
logical message is never sent under two ids. The derivation leaves the text
out, so two v1 messages from one sender in one conversation and key version
that carry the same uploads share an id; each upload belongs to one message.

#### Action signatures

Group operations and read receipts are signed the same way, over their own
comma-separated payloads (`signatures.rs`):

- **GroupCreate** (from `prepare_group_create`, v4+):
  ```
  "GroupChangeEvent.GroupCreate,{message_id},{sender_id},{conversation_key_version},{member_ids...},{is_legacy_group_upgrade},{title},{avatar_url}"
  ```
  `title` is the group's title encrypted under the conversation key the
  create seeds, as the event detail carries it; the SDK's creates set no
  avatar, so `avatar_url` is `null`. The conversation id, admin ids, and TTL
  are carried in the event detail but are **not** part of the signed
  payload; absent `is_legacy_group_upgrade` and `title` render as the
  literal `null`.
- **GroupMemberAdd** (from `prepare_group_members_change`, v7 field layout,
  v8 with a description):
  ```
  "GroupChangeEvent.GroupMemberAddChange,{message_id},{sender_id},{conversation_id},{new_member_ids...},{current_member_ids...},{current_admin_ids...},{title},{avatar_url},{ttl_msec},{conversation_key_version},{screen_capture_blocking}[,{description}]"
  ```
  `title` and `description` are the group's title and description encrypted
  under the key the add rotates to, and `conversation_key_version` is that
  key's version; `avatar_url` is the avatar's media URL as passed. Pending
  member ids are not signed at v7; absent `title`/`avatar_url`/`ttl_msec`
  render as the literal `null`. The screen-capture slot is the
  caller-supplied `current_screen_capture_blocking_enabled` flag — the group's
  current screen-capture-blocking state — and renders as `null` when unset.
  An add that carries a description appends it and signs at v8, the first
  version that covers it; any other add signs at v7.
- **ConversationKeyChange** (from `prepare_conversation_key_change`, v6+):
  ```
  "ConversationKeyChangeEvent,{message_id},{sender_id},{conversation_id},{conversation_key_version},{conversation_key_b64_no_pad}"
  ```
  where `conversation_key_b64_no_pad` is the Base64-without-padding encoding of
  the plaintext 32-byte conversation key.
- **MarkConversationRead** (from `prepare_mark_conversation_read`):
  ```
  "MarkConversationReadEvent,{message_id},{sender_id},{conversation_id},{seen_until_sequence_id},{seen_at_msec}"
  ```
  `seen_at_msec` is the read time in milliseconds since the Unix epoch, the
  same value the event detail carries as `seen_at_millis`.

Both `prepare_group_create` and `prepare_group_members_change` emit **two**
action signatures — a `ConversationKeyChangeEvent` plus the group change —
since the backend validates the pair together.
`prepare_group_members_remove` always rotates the conversation key for the
remaining members: it emits the removal at signature version 11, bound to
the new key version; a title and a description change for each one the
caller passes, encrypted under the new key, with `for_key_rotation` set on
the event so X clients don't show the re-encryption as a change; then the
`ConversationKeyChangeEvent`:

```
"GroupChangeEvent.GroupMemberRemoveChange,{message_id},{sender_id},{conversation_id},{user_ids...},{conversation_key_version},signature_version=11"
```

`prepare_group_leave` signs that same removal of the sender, without
rotating the key, so its key version is the one the caller passes or `null`;
then a `GroupAdminAddChange` when a member is promoted, then
`ConversationDeleteEvent,{message_id},{sender_id},{conversation_id}`. The
other group and metadata prepares sign one version-7 payload: title
(`GroupTitleChange`, key version then the encrypted title), avatar
(`GroupAvatarUrlChange`, the version of the key the image is encrypted under
then the media URL), description (`GroupDescriptionChange`, key version then
the encrypted description), admin add and remove, invite enable (`url`,
expiry or `null`, affiliate or `null`), invite disable, join request, join
reject, message TTL (`MessageDurationChange` with the millisecond count, or
`MessageDurationRemove` with no further fields), and one screen-capture
event (`EnableScreenCaptureBlocking`, `DisableScreenCaptureBlocking`,
`EnableScreenCaptureDetection`, or `DisableScreenCaptureDetection`) with no
further fields.

#### Verifying newer versions

The action layouts above are the ones the SDK signs, at v7 (v8 for a member
add with a description, v11 for a removal); messages are signed at v10 (v1
sends) or v7 (v0 sends). Verification rebuilds each payload in the layout of
the version its signature carries, 2 through 11:

- **v8**: the message payload's conversation-key-version component is the
  version parsed as an integer, `null` when missing or not an integer (v7 and
  below sign the carried string, empty when missing). GroupMemberAdd appends
  `current_description`.
- **v9**: every payload — messages, conversation-key changes, and group
  actions — ends with `,signature_version={n}`. GroupCreate appends the number
  of its `group_type`.
- **v10**: the message payload appends `contents_encryption_version` before
  that suffix, so a message's key choice cannot be changed or stripped without
  breaking its signature. GroupCreate appends `ttl_msec`.
- **v11**: GroupMemberRemove appends `conversation_key_version` after the
  member ids.

Unset optional components render as `null`, so a v10 message without a
message key signs `null` where the SDK's messages sign `1`.

These payloads are comma-joined with no escaping, and the verifier rejects
any component containing a comma. String fields signed inline — an avatar
URL, in a GroupMemberAdd or a GroupAvatarUrlChange — must therefore not
contain a `,`, or the resulting signature is unverifiable. Encrypted values
are base64, which has no comma, so any plaintext title or description can be
encrypted and signed.

### Base64 Conventions

Two base64 flavors appear on the wire, and both are frozen for interop with
other X Chat clients. ECDSA signature values
(`MessageEventSignature.signature`, also nested in each `ActionSignature`)
and byte values embedded inside signed payloads (the ciphertext and
plaintext conversation key components above) use standard base64 **without**
padding (`STANDARD_NO_PAD`). Encoded Thrift blobs —
`encoded_message_create_event`, `encoded_message_event_signature`, and
`ActionSignature.encoded_message_event_detail` — use standard base64
**with** padding (`base64_encode` in `protocol/serialization.rs`), and so
does an encrypted group title or description, which its create or change
event carries and its signature covers as the same string; decoding accepts
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

Used for deriving conversation keys from tree secrets, for
[message keys](#message-keys) and [attachment keys](#media-keys), and for
general key derivation.

```
HKDF-Extract (RFC 5869 §2.2):
  PRK = HMAC-SHA256(key=salt, msg=IKM)

HKDF-Expand:
  T(0) = empty
  T(i) = HMAC-SHA256(T(i-1) || info || counter_byte, PRK)
  Output = T(1) || T(2) || ... truncated to desired length
```

The extract step follows standard HKDF (RFC 5869).  The `hmac_sha256(message, key)` helper uses `(message, key)` argument order — so `hmac_sha256(secret, salt)` is `HMAC(key=salt, msg=IKM)`, which is the standard order.

**Notes**:
- Message keys, attachment keys and the id of a message with files pass an
  `info` string; every other derivation uses an empty `info`, so its expand
  step is just `T(i-1) || counter`
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

Complete flow for encrypting a message via `encrypt_message()` (the `encrypt_reply` / `encrypt_add_reaction` / `encrypt_remove_reaction` / `encrypt_edit` methods share the same pipeline). The diagram shows a v1 send; a v0 send encrypts under the conversation key in step 4, leaves `contents_encryption_version` unset in step 5, and signs the version 7 payload in steps 6 and 7 (see [What Gets Signed](#what-gets-signed)):

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
            │  4. Derive the message key and  │
            │     encrypt content             │
            │     HKDF(conversation_key,      │
            │       "{sender_id}:{msg_id}")   │
            │       → message_key             │
            │     XSalsa20-Poly1305(          │
            │       message_key,              │
            │       content_bytes             │
            │     ) → encrypted_bytes         │
            └────────────────┬────────────────┘
                             │ encrypted_bytes
                             ▼
            ┌─────────────────────────────────┐
            │  5. Wrap in MessageCreateEvent  │
            │     (Thrift struct with         │
            │      conv_key_version,          │
            │      contents_encryption_       │
            │      version = 1,               │
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
            │        contents_b64_no_pad,1,   │
            │        signature_version=10"    │
            │     ) → signature               │
            └────────────────┬────────────────┘
                             │
                             ▼
            ┌─────────────────────────────────┐
            │  7. Build MessageEventSignature │
            │     (Thrift struct with         │
            │      signature_b64,             │
            │      signing_key_version,       │
            │      version = "10")            │
            └────────────────┬────────────────┘
                             │
                             ▼
                        SendPayload {
                          message_id,
                          event_b64: base64(MessageEvent { message_id,
                                     sender_id, conversation_id,
                                     detail, signature }),
                          encoded_message_create_event: base64(event_bytes),
                          signature: base64(signature),
                          encoded_message_event_signature: base64(sig_thrift),
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

When `contents_encryption_version` is 1 or more, step 5 decrypts with the
[message key](#message-keys) derived from the step-4 conversation key.

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
  original (edits do not carry them). When the original or its edit uses a
  [message key](#message-keys), that key travels with it
  (`raw_event_message_key` / `raw_event_edit_message_key`), so recipients can
  open it without its conversation key; a conversation key is never carried.
- **Receive** (`decrypt_event` / `decrypt_events`): when a decrypted message
  carries a preview with an embedded raw event, the SDK always validates it:
  1. The raw event must belong to the **same conversation** as the reply.
  2. Its **signature is verified** against the caller-supplied signing keys —
     the same per-sender filtering and version selection as top-level events;
     a key carried inside the event is never used.
  3. Its contents are **decrypted** (a message-key event with the 32-byte key
     carried for it, otherwise with the supplied conversation keys, the
     embedded key-change events, or the opt-in key cache) and every claim the
     preview makes is compared against the decrypted contents: sender id,
     sequence id, message id, text (truncation-tolerant — the claimed text
     must match the quoted contents up to the preview's own length on a
     character boundary), entities, and attachments.
  4. When an **edit event is embedded**, it must verify the same way and come
     from the original's author, and the text and entity claims are checked
     against the edit's updated contents instead of the original's; the
     attachment claims still check against the original. When the original
     uses a message key, the edit must also name it by its signed message id
     (`MessageEdit.message_id`); an edit without one cannot be tied to it.

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
and `decrypt_event` fall back when its key map is empty. Its guardrails:

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