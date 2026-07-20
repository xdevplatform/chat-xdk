# X Chat SDK — Architecture

## Table of Contents

1. [Overview](#1-overview)
2. [System Context](#2-system-context)
3. [Module Architecture](#3-module-architecture)
4. [Component Deep Dive](#4-component-deep-dive)
   - [4.1 Crypto Module](#41-crypto-module)
   - [4.2 Keys Module](#42-keys-module)
   - [4.3 Protocol Module](#43-protocol-module)
   - [4.4 Public API](#44-public-api)
5. [Data Flow](#5-data-flow)

---

## 1. Overview

The X Chat Rust SDK is a **cryptographic library** for encrypted direct messaging. It handles all encryption, decryption, signing, and key management operations.

### What the SDK Does

| Responsibility | Description |
|---------------|-------------|
| **Key Generation** | Generate EC P-256 identity and signing keypairs |
| **Key Storage** | Store/retrieve keys via Juicebox SDK (PIN-protected) |
| **Encryption** | Encrypt message payloads with conversation keys |
| **Decryption** | Decrypt incoming event payloads |
| **Signing** | Sign outgoing messages with signing key |
| **Verification** | Verify signatures on incoming messages |
| **Conversation Key Management** | Generate, encrypt, and distribute conversation keys |

### What the SDK Does NOT Do

| Not Responsible For | Who Handles It |
|--------------------|----------------|
| **HTTP Communication** | Developer's application code |
| **REST API Calls** | Developer calls `/2/chat/*` endpoints directly |
| **Webhook Server** | Developer hosts their own webhook endpoint |
| **Message Persistence** | Developer's database/storage |
| **OAuth Token Management** | Developer's auth infrastructure |

### Core Guarantee

```
┌─────────────────────────────────────────────────────────────────┐
│  Developer gives SDK: plaintext + keys                          │
│  SDK returns: encrypted blob + signature                        │
│                                                                 │
│  Developer gives SDK: encrypted blob + keys                     │
│  SDK returns: plaintext (after verification)                    │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. System Context

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Developer's Environment                           │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                     Developer's Application                          │   │
│  │                                                                      │   │
│  │   ┌─────────────┐      ┌─────────────┐      ┌─────────────────────┐  │   │
│  │   │  HTTP       │      │  Webhook    │      │  Business Logic     │  │   │
│  │   │  Client     │      │  Handler    │      │  & Storage          │  │   │
│  │   └──────┬──────┘      └──────┬──────┘      └──────────┬──────────┘  │   │
│  │          │                    │                        │             │   │
│  │          │     ┌──────────────┴────────────────────────┘             │   │
│  │          │     │                                                     │   │
│  │          │     ▼                                                     │   │
│  │   ┌──────┴─────────────────────────────────────────────────────────┐ │   │
│  │   │                    Rust Chat SDK (this library)                │ │   │
│  │   │  ┌─────────┐  ┌─────────┐  ┌──────────┐  ┌───────────────────┐ │ │   │
│  │   │  │ Crypto  │  │  Keys   │  │ Protocol │  │   Chat            │ │ │   │
│  │   │  │ Module  │──│ Module  │──│  Module  │──│   (Public API)    │ │ │   │
│  │   │  └─────────┘  └────┬────┘  └──────────┘  └───────────────────┘ │ │   │
│  │   └────────────────────┼───────────────────────────────────────────┘ │   │
│  │                        │                                             │   │
│  └────────────────────────┼─────────────────────────────────────────────┘   │
│                           │                                                 │
│                           ▼                                                 │
│                  ┌─────────────────┐                                        │
│                  │  Juicebox SDK   │  (External dependency)                 │
│                  │  (Key Storage)  │                                        │
│                  └─────────────────┘                                        │
└─────────────────────────────────────────────────────────────────────────────┘
                           │
          Developer's HTTP │ (SDK not involved)
                           ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              X Infrastructure                               │
│  ┌────────────────┐    ┌────────────────┐    ┌────────────────────────┐    │
│  │  /2/chat/ API  │    │  UET/CT Store  │    │   Webhook Delivery     │    │
│  │   (REST)       │    │  (Encrypted)   │    │   (Push to Developer)  │    │
│  └────────────────┘    └────────────────┘    └────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
```

### SDK Boundary

The SDK is a **pure function library**. It transforms data but does not perform I/O (except Juicebox communication):

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              SDK Boundary                                   │
│                                                                             │
│  INPUTS (from developer):              OUTPUTS (to developer):              │
│  ─────────────────────────             ────────────────────────             │
│  • Plaintext messages                  • Encrypted payloads                 │
│  • Encrypted payloads                  • Decrypted plaintext                │
│  • Public keys (from API)              • Encrypted conversation keys        │
│  • Encrypted conv keys                 • Public keys (for API upload)       │
│  • PIN (for Juicebox)                  • Signatures                         │
│                                        • Verification results               │
│                                                                             │
│  EXTERNAL I/O (SDK handles):                                                │
│  ────────────────────────────                                               │
│  • Juicebox SDK communication (key storage/retrieval)                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Module Architecture

```
crates/core/src/
├── lib.rs                        # Public API exports & prelude
├── core.rs                       # ChatCore — platform-agnostic encryption engine
├── chat.rs                       # Chat — Juicebox wrapper over ChatCore
├── pipeline.rs                   # Stateless encrypt-sign pipeline (internal)
├── signatures.rs                 # Group operation action signatures
├── types.rs                      # Public types (Event, SendPayload, etc.)
├── error.rs                      # Error type hierarchy
├── utils.rs                      # base64/hex, MIME sniffing, image dimensions
│
├── crypto/                       # Layer 1: Cryptographic Primitives
│   ├── mod.rs
│   ├── keys.rs                   # Key type definitions (XChatKeyPair, etc.)
│   ├── key_factory.rs            # Key generation, ECDH, signing, verification
│   ├── hash.rs                   # SHA-256, HKDF-SHA256, HMAC-SHA256
│   └── encryption.rs             # XSalsa20-Poly1305 message & streaming encryption
│
├── keys/                         # Layer 2: Key Lifecycle Management
│   ├── mod.rs
│   ├── juicebox.rs               # Juicebox SDK integration (PIN-protected storage)
│   ├── keypair_manager.rs        # In-memory key state
│   └── conversation_keys.rs      # Conversation key encrypt/decrypt
│
├── protocol/                     # Layer 3: Serialization Helpers
│   ├── mod.rs
│   ├── serialization.rs          # Base64 and JSON helpers
│   └── safe_reader.rs            # BoundedProtocol — caps Thrift collection sizes
│
└── thrift/                       # Layer 4: Generated Wire Types
    ├── mod.rs
    ├── event.rs                   # Generated from event.thrift
    ├── product.rs                 # Generated from product.thrift
    └── trees.rs                   # Generated from trees.thrift
```

### Platform Bindings

```
crates/
├── macros/                       # JsCamelCase derive — generates camelCase JS types
│
├── pyo3/                         # Python bindings via PyO3
│   └── src/lib.rs                # Thin wrapper: delegates to core Chat
│
├── go/                           # Go bindings (cgo + staticlib; see go/chatxdk/)
│   ├── src/lib.rs                # C ABI (`chat_xdk.h`)
│   └── go/chatxdk/               # Go package
│
├── wasm/                         # JavaScript/WASM bindings via wasm-bindgen
│   ├── src/lib.rs                # Thin wrapper: delegates to ChatCore
│   └── js/                       # JS wrapper, TypeScript types, tests
│
├── dotnet/                       # .NET bindings (P/Invoke over a Rust cdylib)
│   ├── src/lib.rs                # C ABI (csbindgen-generated NativeMethods)
│   └── dotnet/ChatXdk/           # C# package
│
└── jvm/                          # JVM bindings (JNA over the dotnet cdylib)
    └── java/chatxdk/             # Java package
```

### Layer Dependencies

```
┌─────────────────────────────────────────────────────────┐
│  core.rs / chat.rs      Public API (ChatCore + Chat)    │
├─────────────────────────────────────────────────────────┤
│  pipeline.rs            Encrypt-sign pipeline           │
├─────────────────────────────────────────────────────────┤
│  thrift/                Generated wire types            │
├─────────────────────────────────────────────────────────┤
│  keys/                  Key lifecycle & Juicebox        │
├─────────────────────────────────────────────────────────┤
│  crypto/                Cryptographic primitives        │
└─────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│  External: Juicebox Rust SDK                            │
└─────────────────────────────────────────────────────────┘
```

---

## 4. Component Deep Dive

### 4.1 Crypto Module

**Purpose**: Provides low-level cryptographic primitives that all other modules depend on. This is the foundation of the SDK's security guarantees. **No network I/O** — pure cryptographic transformations.

#### `crypto/keys.rs` — Key Type Definitions

Defines the core key types used throughout the SDK.

| Type | Description |
|------|-------------|
| `XChatKeyPair` | Container for a public/private key pair |
| `XChatPublicKey` | EC P-256 public key (65 bytes uncompressed, 33 bytes compressed) |
| `XChatPrivateKey` | EC P-256 private key (32-byte scalar), zeroized on drop |
| `XChatConversationKey` | 32-byte (256-bit) symmetric key for message encryption (XSalsa20-Poly1305 / secretstream) |
| `XChatPrivateKeys` | Container for identity + optional signing private keys |
| `KeypairPurpose` | Enum: `Identity` (ECDH) or `Signing` (ECDSA) |

All secret key types implement `Zeroize` and `ZeroizeOnDrop` to securely clear memory. `Debug` output is redacted for secrets.

#### `crypto/key_factory.rs` — Key Operations

Stateless utility struct (`KeyFactory`) providing all cryptographic key operations.

| Function | Description |
|----------|-------------|
| `generate_keypair(purpose)` | Generate EC P-256 keypair |
| `generate_conversation_key()` | Generate random 32-byte conversation key |
| `encrypt_with_public_key(pk, data)` | ECIES: ephemeral ECDH + X9.63 KDF + AES-128-GCM |
| `decrypt_with_private_key(sk, data)` | ECIES decryption |
| `sign(sk, payload)` | ECDSA P-256 signature |
| `verify(pk, sig, payload)` | ECDSA verification |
| `reconstruct_public_key(bytes, purpose)` | Deserialize public key from SEC1 bytes |
| `get_keypair_from_private_key_bytes(bytes, purpose)` | Derive full keypair from private key bytes |

**ECIES wire format**: `ephemeral_public_key (65 bytes) || ciphertext || tag (16 bytes)`

Uses `p256` and `aes-gcm` crates from RustCrypto. All functions are pure — no I/O.

#### `crypto/hash.rs` — Hash Utilities

| Function | Description |
|----------|-------------|
| `sha256(data)` | SHA-256 hash |
| `hmac_sha256(message, key)` | HMAC-SHA256 |
| `hkdf(secret, salt, len)` | HKDF-SHA256 key derivation |
| `kdf2_sha256(shared_secret, shared_info, len)` | X9.63 KDF (used in ECIES) |

Uses `sha2` and `hmac` crates.

#### `crypto/encryption.rs` — Message Encryption

Provides symmetric encryption for message payloads. Uses pure-Rust implementations that are WASM-compatible.

| Function | Description |
|----------|-------------|
| `encrypt_message(key, plaintext)` | XSalsa20-Poly1305 single-shot encryption |
| `decrypt_message(key, ciphertext)` | XSalsa20-Poly1305 decryption |
| `encrypt_stream(key, reader, writer)` | `crypto_secretstream_xchacha20poly1305` streaming encryption |
| `decrypt_stream(key, reader, writer)` | Streaming decryption |
| `stream_encryptor(key)` → `StreamEncryptor` | Incremental encryption (`push`/`finish`) for chunk-at-a-time processing |
| `stream_decryptor(key)` → `StreamDecryptor` | Incremental decryption (`push`/`finish`); `finish` rejects truncated streams |

**Wire formats**:
- **Message**: `nonce (24 bytes) || tag (16 bytes) || ciphertext`
- **Stream**: `header (24B) || chunk_0 || chunk_1 || ...` (1024-byte plaintext chunks, 17-byte overhead per chunk)

The incremental `StreamEncryptor` / `StreamDecryptor` produce and consume this same wire format; output is identical regardless of how input is split across `push` calls.

Uses `xsalsa20poly1305` (messages) and `crypto_secretstream` (streams) crates.

---

### 4.2 Keys Module

**Purpose**: Manages the lifecycle of cryptographic keys, including secure storage via Juicebox. This module **does** perform I/O to communicate with Juicebox.

#### `keys/juicebox.rs` — Secure Key Storage

Integrates with the Juicebox Rust SDK for PIN-protected key storage. This is the **only external I/O** the SDK performs.

| Type / Function | Description |
|-----------------|-------------|
| `JuiceboxApi` trait | Abstraction over Juicebox SDK |
| `JuiceboxClient` | Production implementation using `juicebox_sdk` |
| `JuiceboxConfig` | Configuration with SDK config JSON, auth tokens, max guesses |
| `JuiceboxConfig::from_x_api_json` | Parses the X API Juicebox config JSON into `JuiceboxConfig`. Lives in core so every binding delegates to it (not duplicated per binding). |
| `register_private_key(pin, config, secret)` | Store keys with PIN |
| `recover_private_key(pin, config)` | Retrieve keys with PIN |
| `RecoverResult` | Enum: `Success(bytes)`, `Failure`, `KeyReconstructionFailed`, `NoTokens` |
| `RegisterResult` | Enum: `Success`, `Failure(reason)` |

Keys are stored as concatenated bytes: `identity_private (32 bytes) || signing_private (32 bytes)`.

#### `keys/keypair_manager.rs` — In-Memory Key State

Manages unlocked keys in memory. Uses `RwLock` for thread-safe interior mutability.

| Function | Description |
|----------|-------------|
| `new()` | Create manager (no keys loaded) |
| `has_keypair()` | Check if keys are in memory |
| `get_identity_keypair()` | Get identity keypair (returns `KeyError::NotUnlocked` if locked) |
| `get_signing_keypair()` | Get signing keypair |
| `set_keypairs(identity, signing)` | Load keypairs into memory |
| `load_from_private_keys(private_keys)` | Reconstruct full keypairs from private key bytes |
| `get_private_keys()` | Export private keys for backup/storage |
| `clear()` | Zeroize and remove keys from memory |

```
┌─────────────┐     set_keypairs()     ┌─────────────┐
│   Locked    │────────────────────────▶│  Unlocked   │
│ (no keys)   │                         │ (keys in    │
└─────────────┘                         │  memory)    │
       ▲                                └─────────────┘
       │              clear()                  │
       └───────────────────────────────────────┘
```

#### `keys/conversation_keys.rs` — Conversation Key Operations

| Function | Description |
|----------|-------------|
| `encrypt_conversation_key(ckey, recipient_pk)` | Encrypt a conversation key for one recipient using ECIES |
| `encrypt_conversation_key_for_recipients(ckey, recipients)` | Encrypt for list of `(user_id, public_key, version)` |
| `decrypt_conversation_key(encrypted, private_key)` | Decrypt a received conversation key |

---

### 4.3 Protocol Module

**Purpose**: Defines the wire format for messages and events, matching the Thrift definitions used by the X Chat API.

#### `thrift/event.rs` — Event Wire Types (generated)

Auto-generated from `event.thrift`. Key types:

| Type | Description |
|------|-------------|
| `MessageEvent` | Top-level event container with metadata and detail union |
| `MessageEventDetail` | Union: `MessageCreateEvent`, `ConversationKeyChangeEvent`, `GroupChangeEvent`, `MessageFailureEvent`, `MessageTypingEvent`, `MessageDeleteEvent`, `ConversationDeleteEvent`, `ConversationMetadataChangeEvent`, `MemberAccountDeleteEvent`, etc. |
| `MessageCreateEvent` | Encrypted message content with key version, notification, TTL |
| `MessageEventSignature` | Signature, public key version, signing public key |

#### `thrift/product.rs` — Content Wire Types (generated)

Auto-generated from `product.thrift`. Key types:

| Type | Description |
|------|-------------|
| `MessageEntryHolder` | Wrapper for `MessageEntryContents` union |
| `MessageEntryContents` | Union: `Message`, `ReactionAdd`, `ReactionRemove`, `MessageEdit`, `MarkConversationRead`, `MarkConversationUnread`, etc. |
| `MessageContents` | Text, entities, attachments, reply preview, forwarded message, quick reply, CTAs |
| `MediaAttachment` | Media with hash key, dimensions, type, duration, filesize |

#### `thrift/trees.rs` — Tree Wire Types (generated)

Auto-generated from `trees.thrift`. Contains ratchet tree structures for group key management.

#### `protocol/serialization.rs` — Helpers

| Function | Description |
|----------|-------------|
| `base64_encode(bytes)` | Standard base64 encoding |
| `base64_decode(str)` | Standard base64 decoding (accepts padded and unpadded input) |
| `to_json` / `from_json` | JSON (de)serialization helpers |

Thrift binary serialization (`serialize_thrift(value)`, for any
`TSerializable`) lives in `pipeline.rs`, next to the encrypt-sign pipeline
that uses it.

---

### 4.4 Public API

The public API lives in `core.rs`, `chat.rs`, `types.rs`, and `error.rs`.

#### `core.rs` — `ChatCore`

The platform-agnostic encryption engine. All crypto operations live here.
Both `Chat` (Juicebox) and WASM `Chat` delegate to `ChatCore`.

Holds:
- `keypair_manager: KeypairManager` — in-memory key state
- `reject_unverified: bool` — signature verification policy (defaults to `true`)
- `conversation_key_high_water: RwLock<HashMap<String, u64>>` — per-conversation monotonic high-water mark of verified key versions, backing the anti-downgrade guarantee on `latest_version`

#### `chat.rs` — `Chat` (Juicebox wrapper)

Thin wrapper over `ChatCore` that adds PIN-protected key storage via Juicebox.
Requires the `juicebox` feature flag.

Holds:
- `inner: ChatCore` — the encryption engine
- `config: JuiceboxConfig` — current Juicebox auth configuration
- `juicebox: Arc<dyn JuiceboxApi>` — Juicebox client for key storage

See [API.md](API.md) for the complete method reference.

#### `types.rs` — Developer-Facing Types

| Type | Description |
|------|-------------|
| `Event` | Enum with 12 variants: `Message`, `KeyChange`, `GroupChange`, `MessageDeleted`, `ConversationDeleted`, `Typing`, `ReadReceipt`, `MarkedUnread`, `Failure`, `SettingsChange`, `MemberDeleted`, `Unknown` |
| `Message` | Decrypted message with content, metadata, attachments, verification status |
| `MessageContent` | Enum: `Text`, `Reaction`, `ReactionRemoved`, `Edit`, `MarkRead`, `MarkUnread`, `Unknown` |
| `SendPayload` | Encrypted content + signature + metadata ready for the X API |
| `PublicKeys` | Identity + signing public keys (base64) |
| `PublicKeyRegistrationPayload` | Registration payload for the X API |
| `EntityDescriptor` | Rich-text entity descriptor (URL, mention, hashtag) with byte offsets; used by `EncryptMessageParams` and `EncryptReplyParams` |

#### `error.rs` — Error Hierarchy

| Type | Description |
|------|-------------|
| `SdkError` | Top-level: `Crypto`, `Key`, `Juicebox`, `Serialization`, `Parse` |
| `CryptoError` | Key generation, encryption, decryption, signing, verification failures |
| `KeyError` | `NotUnlocked`, `NotFound`, `WeakPin`, `ReconstructionFailed` |
| `JuiceboxError` | `InvalidPin`, `NotRegistered`, `InvalidAuth`, `UpgradeRequired`, `Transient`, `RateLimitExceeded`, etc. |
| `SerializationError` | JSON, Base64, Thrift, format errors |

---

## 5. Data Flow

### 5.1 Registration Flow (One-Time)

```
Developer                          SDK                           Juicebox
    │                               │                               │
    │  chat.generate_keypairs()     │                               │
    │──────────────────────────────▶│                               │
    │                               │  KeyFactory::generate_keypair │
    │                               │  (identity + signing)         │
    │  payload                      │                               │
    │◀──────────────────────────────│                               │
    │                               │                               │
    │  POST /2/chat/keys            │                               │
    │  (developer calls X API)      │                               │
    │                               │                               │
    │  chat.update_config(config)   │                               │
    │  chat.setup(pin)              │                               │
    │──────────────────────────────▶│                               │
    │                               │  JuiceboxApi::register(...)   │
    │                               │──────────────────────────────▶│
    │                               │              Ok               │
    │                               │◀──────────────────────────────│
    │       PublicKeys              │                               │
    │◀──────────────────────────────│                               │
    ▼                               ▼                               ▼
```

### 5.2 Unlock Flow (On Startup)

```
Developer                          SDK                           Juicebox
    │                               │                               │
    │  chat.unlock(pin)             │                               │
    │──────────────────────────────▶│                               │
    │                               │  JuiceboxApi::recover(...)    │
    │                               │──────────────────────────────▶│
    │                               │    private_key_bytes          │
    │                               │◀──────────────────────────────│
    │                               │                               │
    │                               │  Reconstruct keypairs         │
    │                               │  Load into KeypairManager     │
    │              Ok               │                               │
    │◀──────────────────────────────│                               │
    ▼                               ▼                               ▼
```

### 5.3 Sending a Message

```
Developer                          SDK
    │                               │
    │  chat.encrypt_message(params)  (supports entities, attachments)
    │──────────────────────────────▶│
    │                               │  1. Resolve inputs: sender_id / signing_key_version
    │                               │     from params or the session identity (set_identity);
    │                               │     the raw conversation key + version from params or
    │                               │     the opt-in key cache (ECIES decryption happened
    │                               │     earlier, in decrypt_conversation_key /
    │                               │     extract_conversation_keys / decrypt_events)
    │                               │  2. Build rich-text entities (if provided)
    │                               │  3. Serialize text + entities as Thrift MessageEntryHolder
    │                               │  4. Encrypt with XSalsa20-Poly1305
    │                               │  5. Wrap in MessageCreateEvent
    │                               │  6. Sign the comma-separated component payload
    │                               │     (MessageCreateEvent,ids…,contents_b64), version "7"
    │                               │  7. Build MessageEventSignature
    │  SendPayload                  │
    │◀──────────────────────────────│
    │                               │
    │  POST /2/chat/conversations/{id}/messages
    │  (developer calls X API with SendPayload fields)
    ▼                               ▼
```

### 5.4 Receiving a Message

```
Developer                          SDK
    │                               │
    │  (receive from webhook or polling)
    │  encrypted_event from X API   │
    │                               │
    │  Step 1: Extract conversation keys ONCE (expensive ECIES per KeyChange)
    │  keys = chat.extract_conversation_keys(events)   // version → key map
    │──────────────────────────────▶│  ECIES P-256 decrypt of KeyChange events
    │  ConversationKeyResult        │
    │◀──────────────────────────────│
    │                               │
    │  Step 2: Decrypt each event (fast symmetric, repeat per message)
    │  chat.decrypt_event(event_b64, &keys, &signing_keys)
    │──────────────────────────────▶│
    │                               │  1. Base64-decode event
    │                               │  2. Parse Thrift MessageEvent (TBinaryProtocol)
    │                               │  3. Route on event type
    │                               │  4. (MessageCreateEvent only) XSalsa20-Poly1305 decrypt
    │                               │  5. Parse Thrift MessageEntryHolder
    │                               │  6. Verify signature (reject_unverified by default)
    │                               │  7. Validate any reply preview that embeds its raw
    │  Event                        │     source event, then map to the typed Event enum
    │◀──────────────────────────────│
    │                               │
    │  Step 3: Key change events (key map may be empty)
    │  chat.decrypt_event(key_change_b64, &keys, &signing_keys)
    │──────────────────────────────▶│  Parse Thrift; verify the signature by
    │  Event::KeyChange             │  self-decrypting the conversation key
    │◀──────────────────────────────│
    │                               │
    │  Step 4: Unencrypted messages (conversation_key_version is None)
    │  chat.decrypt_event(event_b64, &keys, &signing_keys)
    │──────────────────────────────▶│  1. Detect: conversation_key_version is None
    │                               │  2. No signature → rejected under reject_unverified
    │  Event::Message               │     (default); returned verified=false only when
    │  (verified=false)             │     reject_unverified is disabled
    │◀──────────────────────────────│
    ▼                               ▼
```

> In practice prefer the batch `decrypt_events(events, signing_keys)`, which
> performs Step 1 internally and verifies each event's signing-key binding.

---

## Appendix A: Crypto Algorithm Summary

| Operation | Algorithm | Rust Crate |
|-----------|-----------|------------|
| Identity/Signing Keys | EC P-256 | `p256` |
| Key Agreement | ECDH P-256 | `p256` |
| Digital Signatures | ECDSA P-256 | `p256`, `ecdsa` |
| Conversation Key | 32 random bytes (used with XSalsa20-Poly1305 / secretstream) | `rand` |
| Public Key Encryption | ECIES (ECDH + X9.63 KDF + AES-128-GCM) | `p256`, `aes-gcm` |
| Message Encryption | XSalsa20-Poly1305 | `xsalsa20poly1305` |
| Stream Encryption | `crypto_secretstream_xchacha20poly1305` | `crypto_secretstream` |
| Key Derivation | HKDF-SHA256 | `hmac`, `sha2` |
| Hashing | SHA-256 | `sha2` |
| HMAC | HMAC-SHA256 | `hmac` |
| Secure Memory | Zeroize on drop | `zeroize` |

---

## Appendix B: Wire Format Details

### Message Encryption (XSalsa20-Poly1305)
```
Input:  plaintext bytes
Output: nonce (24 bytes) || tag (16 bytes) || ciphertext
```

### Stream Encryption (crypto_secretstream_xchacha20poly1305)
```
Output: header (24B) || chunk_0 || chunk_1 || ...
Each chunk: ≤1041B (1024B plaintext + 17B ABYTES)
Tags: TAG_MESSAGE (intermediate), TAG_FINAL (last)
```

### ECIES (encrypt_with_public_key)
```
1. Generate ephemeral P-256 keypair
2. ECDH(ephemeral_private, recipient_public) → shared_secret
3. X9.63_KDF(shared_secret) → aes_key (16 bytes)
4. AES-128-GCM(aes_key, plaintext) → ciphertext + tag
5. Output: ephemeral_public (65 bytes) || ciphertext || tag (16 bytes)
```
