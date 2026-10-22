# X Chat SDK API Reference

This document covers the full API across Rust, Python, JavaScript/WASM, Go (`github.com/xdevplatform/chat-xdk/go/chatxdk`), .NET (`ChatXdk` — [`crates/dotnet/README.md`](../crates/dotnet/README.md)), and JVM (`com.x.chatxdk` — [`crates/jvm/README.md`](../crates/jvm/README.md); JNA to the same native library as .NET).

The JVM binding mirrors the .NET surface (JSON across the native boundary, same method names in `camelCase`). Tables below list Rust, JS, Python, Go, JVM, and .NET. Go consumers: `crates/go/README.md`.

**Key design principle**: Base64 is only at the edges (data from/to the X API). Between SDK methods, everything is raw bytes.

**FFI note (Go / .NET / JVM)**: these bindings marshal arguments to the native library as a JSON params document, so the raw conversation key transits the FFI boundary base64-encoded inside an immutable string. Those intermediate string copies live in the host runtime (Go string / .NET `string` / Java `String`) and cannot be zeroized by the caller. The decoded key copy on the Rust side is zeroized on drop.

---

## Unified API Reference

### Constructor & Config

| # | Method | Rust | JS | Python | Go | JVM | .NET |
|---|--------|------|-----|--------|-----|------|------|
| 1 | **new** | `Chat::new(config: JuiceboxConfig)` | `new Chat()` (config via `createChat(opts)`; `juiceboxConfig` optional; free with `free()`) | `Chat(config_json?: str)` (stop its background work with `close()`) | `New() *Chat` (free with `Close()`) | `new Chat()` (free with `close()` / `try-with-resources`) | `new Chat()` then `UpdateConfig(string)` (free with `Dispose()` / `using`) |
| 2 | **update_config** | `update_config(&mut self, config)` | `updateConfig(config: string)` | `update_config(config_json: str)` | `UpdateConfig(configJSON string) error` | `updateConfig(String)` | `UpdateConfig(string)` |
| 3 | **set_reject_unverified** | `set_reject_unverified(&mut self, reject: bool)` | `setRejectUnverified(reject: boolean)` | `set_reject_unverified(reject: bool)` | `SetRejectUnverified(reject bool)` | `setRejectUnverified(boolean)` | `SetRejectUnverified(bool)` |

The config JSON accepted by the constructor, `update_config`, `setup`, and
`unlock` supports three shapes, checked in this order:

1. **Direct SDK config** — `{"sdk_config": "<json string>", "tokens": {realm_id: token}, "max_guess_count": N}`;
   `sdk_config` goes straight to the Juicebox SDK. Default guesses: 20.
2. **X API `juicebox_config` object** — the `juicebox_config` field from
   `GET /2/users/{id}/public_keys` (your own user), passed through as-is:
   `{"key_store_token_map_json": "...", "max_guess_count": N, "token_map": [...]}`.
   The `key_store_token_map_json` string is used **verbatim** as the SDK
   config — it carries each realm's `public_key` and the server's
   register/recover thresholds, which the realms require — and auth tokens
   come from `token_map`. A malformed embedded config is an error. Default
   guesses: 20. **This is the shape to use with the X API.**
3. **Bare `token_map` array** — `{"token_map": [{key, value: {address, token}}, ...]}`
   with no `key_store_token_map_json`; the realm list and majority
   thresholds are derived. This derivation cannot recover realm public
   keys, so it only works against realms that don't require them. Default
   guesses: 5.

In JS, realm auth tokens always come from the `getAuthToken` callback
instead of the config, so the `tokens`/`token_map` token fields are not
validated there (and a raw realms config is accepted as a fourth shape);
a config accepted by JS may still be rejected by the native bindings.

`createChat`'s `juiceboxConfig` is optional to support **JS first boot**: the
account's `juicebox_config` is created by `POST /2/users/{id}/public_keys`, so
a brand-new user has none yet. Created without a config, the instance runs
every crypto method (including `generateKeypairs`) but builds no Juicebox
client; `setup`/`unlock`/`changePin`/`delete` throw a clear error until
`updateConfig` supplies a real config. The first-boot flow is:
`createChat({ getAuthToken })` → `generateKeypairs()` → caller POSTs the
payload → `updateConfig(configFromGet)` → `setup(pin)`. Already-provisioned
accounts keep passing `juiceboxConfig` at creation, unchanged.

### Juicebox Key Storage

| # | Method | Rust | JS | Python | Go | JVM | .NET |
|---|--------|------|-----|--------|-----|------|------|
| 4 | **setup** | `async setup(pin: &[u8]) → PublicKeys` | `setup(pin: string \| Uint8Array) → Promise<PublicKeys>` | `setup(pin: str) → PublicKeys` | `Setup(pin []byte, configJSON string) (*PublicKeys, error)` | `setup(String pin, String configJson)` | `Setup(string pin, string configJson)` |
| 5 | **unlock** | `async unlock(pin: &[u8])` | `unlock(pin: string \| Uint8Array) → Promise<void>` | `unlock(pin: str)` | `Unlock(pin []byte, configJSON string) error` | `unlock(String pin, String configJson)` | `Unlock(string pin, string configJson)` |
| 6 | **change_pin** | `async change_pin(old: &[u8], new: &[u8])` | `changePin(old: string \| Uint8Array, new: string \| Uint8Array) → Promise<void>` | `change_pin(old_pin: str, new_pin: str)` | `ChangePin(oldPin, newPin []byte) error` | `changePin(String oldPin, String newPin)` | `ChangePin(string oldPin, string newPin)` |
| 7 | **delete** | `async delete()` | `delete() → Promise<void>` | `delete()` | `Delete() error` | `delete()` | `Delete()` |
| 8 | **lock** | `lock()` | `lock()` | `lock()` | `Lock()` | `lock()` | `Lock()` |
| 9 | **is_unlocked** | `is_unlocked() → bool` | `isUnlocked() → boolean` | `is_unlocked() → bool` | `IsUnlocked() bool` | `isUnlocked()` | `IsUnlocked { get; }` |
| 10 | **has_identity_key** | `has_identity_key() → bool` | `hasIdentityKey() → boolean` | `has_identity_key() → bool` | `HasIdentityKey() bool` | `hasIdentityKey()` | `HasIdentityKey { get; }` |

### Key Management

| # | Method | Rust | JS | Python | Go | JVM | .NET |
|---|--------|------|-----|--------|-----|------|------|
| 11 | **generate_keypairs** | `→ PublicKeyRegistrationPayload` | `generateKeypairs() → object` | `generate_keypairs() → PublicKeyRegistrationPayload` | `GenerateKeypairs() (*PublicKeyRegistrationPayload, error)` | `generateKeypairs()` | `GenerateKeypairs()` |
| 12 | **get_public_keys** | `→ PublicKeys` | `getPublicKeys() → object` | `get_public_keys() → PublicKeys` | `GetPublicKeys() (*PublicKeys, error)` | `getPublicKeys()` | `GetPublicKeys()` |
| 13 | **get_public_key_fingerprint** | `→ String` | `getPublicKeyFingerprint() → string` | `get_public_key_fingerprint() → str` | `GetPublicKeyFingerprint() (string, error)` | `getPublicKeyFingerprint()` | `GetPublicKeyFingerprint()` |
| 14 | **export_keys** | `→ Vec<u8>` | not exposed¹ | `export_keys() → Optional[bytearray]` | `ExportKeys() ([]byte, error)` | `exportKeys()` → `byte[]` | `ExportKeys()` → `byte[]?` |
| 15 | **import_keys** | `import_keys(&ImportKeysParams)` | not exposed¹ | `import_keys(ImportKeysParams)` | `ImportKeys(ImportKeysParams) error` | `importKeys(ImportKeysParams)` | `ImportKeys(ImportKeysParams)` |
| 16 | **set_identity** | `set_identity(&SetIdentityParams) → Result<()>` | `setIdentity(params: SetIdentityParams)` | `set_identity(SetIdentityParams)` | `SetIdentity(SetIdentityParams) error` | `setIdentity(SetIdentityParams)` | `SetIdentity(SetIdentityParams)` |

¹ By design: the public JS surface (`createChat()`/`ChatWithJuicebox`) does
not expose raw key export/import, so raw private key material stays inside
the wasm boundary; keys are managed through `setup`/`unlock` instead.

`export_keys` returns **unencrypted** private key material — handle with
care (Python returns a mutable `bytearray` so callers can zero it after
use). It requires a loaded identity key (the signing key is optional,
giving a 32-byte export); Python/Go/.NET/JVM return `None`/`nil`/`null`
when no identity key is loaded, while Rust errors.

Both calls take a params object, as every call with more than one input
does. `ImportKeysParams` holds the key blob (`keys`) and an optional
`signing_key_version`; `SetIdentityParams` holds `user_id` and
`signing_key_version`.

The SDK needs to know the version the X API reports for your registered
public key, so KeyChange participant entries targeting other key versions are
skipped. Set it in either of two equivalent ways: pass `signing_key_version`
in `ImportKeysParams`, or call `set_identity`, which sets it together with the
user id. After registering the keys from `generate_keypairs`, call
`set_identity` with the `public_key_version` the registration returns.

`set_identity` stores the **session identity**.
Every method with optional `sender_id` / `signing_key_version` fields — the
`encrypt_*` family and the three `prepare_*` methods — resolves omitted values
from it. An explicit per-call value always overrides, and an omitted value and
its explicit equivalent produce byte-identical signed output for the same
logical inputs. Calling a signing method with neither a per-call value nor a
session identity is an error.

`decrypt_events`
reports `latest_version` (the version to encrypt with) as the newest key
change with a valid signature and holds it monotonic for the lifetime of the
instance, so a replayed older key cannot downgrade what you encrypt with.
This applies to key changes with signature version ≥ 6 (whose signed payload
embeds the plaintext key); for a conversation seen only through older key
changes, `latest_version` falls back to the batch's highest version.

PINs passed to `setup`/`change_pin` must be at least 4 characters and must
not be a single repeated character or a sequential digit run; `unlock`
performs no validation so existing registrations stay recoverable. The
Rust core takes PINs as `&[u8]` and Go takes `[]byte` so callers can
zeroize their buffers; the JS wrapper additionally accepts `Uint8Array`
PINs for the same reason.

A wrong PIN fails `unlock` (and `change_pin`, which unlocks with the old PIN
first) with an invalid-PIN error whose message carries the stable token
`guesses_remaining=N` — the attempt budget Juicebox reports after the failure.
`0` means the budget is exhausted and the stored keys are locked; the token is
absent when no count is available. Read it structurally instead of parsing the
message: Rust `JuiceboxError::InvalidPin { guesses_remaining: Option<u16> }`,
JVM `ChatXdkException.getGuessesRemaining()` (`Integer`, `null` when absent),
.NET `ChatXdkException.GuessesRemaining` (`int?`), Go
`GuessesRemaining(err) (int, bool)`, Python `chat_xdk.guesses_remaining(exc)`
(`int | None`), JS `guessesRemaining(err)` (`number | null`, reading the
wrapper's `reason=InvalidPin guesses_remaining=N` error form).

### Conversation Keys

| # | Method | Rust | JS | Python | Go | JVM | .NET |
|---|--------|------|-----|--------|-----|------|------|
| 17 | **decrypt_conversation_key** | `(encrypted_b64: &str) → XChatConversationKey` | `decryptConversationKey(b64: string) → Uint8Array` | `decrypt_conversation_key(b64: str) → bytes` | `DecryptConversationKey(encryptedKeyB64 string) ([]byte, error)` | `decryptConversationKey(String)` → `byte[]` | `DecryptConversationKey(string)` → `byte[]` |
| 18 | **prepare_conversation_key_change** | `prepare_conversation_key_change(&ConversationKeyChangeParams) → PreparedConversationChange` | `prepareConversationKeyChange(params: ConversationKeyChangeParams) → PreparedConversationChange` | `prepare_conversation_key_change(ConversationKeyChangeParams) → dict` | `PrepareConversationKeyChange(ConversationKeyChangeParams) (*PreparedConversationChange, error)` | `prepareConversationKeyChange(ConversationKeyChangeParams)` | `PrepareConversationKeyChange(ConversationKeyChangeParams)` |
| 19 | **prepare_group_members_change** | `prepare_group_members_change(&GroupMembersChangeParams) → PreparedConversationChange` | `prepareGroupMembersChange(params: GroupMembersChangeParams) → PreparedConversationChange` | `prepare_group_members_change(GroupMembersChangeParams) → dict` | `PrepareGroupMembersChange(GroupMembersChangeParams) (*PreparedConversationChange, error)` | `prepareGroupMembersChange(GroupMembersChangeParams)` | `PrepareGroupMembersChange(GroupMembersChangeParams)` |
| 20 | **prepare_group_create** | `prepare_group_create(&GroupCreateParams) → PreparedConversationChange` | `prepareGroupCreate(params: GroupCreateParams) → PreparedConversationChange` | `prepare_group_create(GroupCreateParams) → dict` | `PrepareGroupCreate(GroupCreateParams) (*PreparedConversationChange, error)` | `prepareGroupCreate(GroupCreateParams)` | `PrepareGroupCreate(GroupCreateParams)` |

Each `prepare_*`, `encrypt_*`, `decrypt_event(s)` and file method takes a
single params value, named the same in every language: Rust
`chat_xdk_core::*Params`, JS plain objects matching the exported interfaces,
and the `*Params` classes/structs in Python, Go, JVM and .NET. The Python classes take the required fields positionally and
the optional ones as keywords, and expose every field as a read/write
attribute. Field names follow each language's idiom: `snake_case` in
Rust/Python (`sender_id`), `camelCase` in JS/JVM (`senderId`), `PascalCase` in
Go/.NET (`SenderID` / `SenderId`).

On all three prepare methods, `sender_id` / `signing_key_version` are optional
overrides: omitted values (unset / `None` / `null` / empty string) resolve
from the session identity set via `set_identity`.

### Events

| # | Method | Rust | JS | Python | Go | JVM | .NET |
|---|--------|------|-----|--------|-----|------|------|
| 21 | **extract_conversation_keys** | `(events: &[&str]) → ConversationKeyResult` | `extractConversationKeys(string[]) → ConversationKeyResult` | `extract_conversation_keys(list[str]) → dict` | `ExtractConversationKeys(events []string) (*ConversationKeyBundle, error)` | `extractConversationKeys(List<String>)` | `ExtractConversationKeys(IEnumerable<string>)` |
| 22 | **set_cache_keys** | `set_cache_keys(enabled: bool)` | `setCacheKeys(enabled: boolean)` | `set_cache_keys(enabled: bool)` | `SetCacheKeys(enabled bool)` | `setCacheKeys(boolean)` | `SetCacheKeys(bool)` |
| 23 | **set_signing_keys** | `set_signing_keys(Vec<SigningKeyEntry>)` | `setSigningKeys(signingKeys: SigningKeyEntry[])` | `set_signing_keys(list[dict])` | `SetSigningKeys(keys []SigningKeyEntry) error` | `setSigningKeys(List<SigningKeyEntry>)` | `SetSigningKeys(IReadOnlyList<SigningKeyEntry>)` |
| 24 | **decrypt_events** | `decrypt_events(DecryptEventsParams) → DecryptEventsResult` | `decryptEvents(params: DecryptEventsParams) → DecryptEventsResult` | `decrypt_events(DecryptEventsParams) → dict` | `DecryptEvents(DecryptEventsParams) (*DecryptEventsResult, error)` | `decryptEvents(DecryptEventsParams)` → `DecryptEventsResult` | `DecryptEvents(DecryptEventsParams)` → `DecryptEventsResult` |
| 25 | **decrypt_event** | `decrypt_event(DecryptEventParams) → Event` | `decryptEvent(params: DecryptEventParams) → Event` | `decrypt_event(DecryptEventParams) → dict` | `DecryptEvent(DecryptEventParams) (*Event, error)` | `decryptEvent(DecryptEventParams)` → `JsonNode` | `DecryptEvent(DecryptEventParams)` → `JsonElement` |

**Session stores for the decrypt/encrypt paths.** Both decrypt methods accept
unset or empty key fields and fall back to two opt-in session stores:

- `set_signing_keys(entries)` stores signing keys that `decrypt_events` and
  `decrypt_event` use when their params' `signing_keys` is unset or empty.
  Each call replaces the previous set. Only this explicit call populates the
  store — a key carried inside an event is never trusted for verification.
- `set_cache_keys(enabled)` enables the conversation-key cache (**off by
  default**). While enabled, `decrypt_events` caches, per conversation, the
  key whose key change carried a valid signature at the highest version seen;
  `decrypt_event` falls back to it when its params' `conversation_keys` map is
  omitted or empty; and the `encrypt_*` methods resolve an omitted
  `conversation_key` / `conversation_key_version` pair from it. Disabling
  clears the cache; the cached keys zeroize on drop.

  Only `decrypt_events` populates the cache, and only from KeyChange events
  in its own batch whose signature verified. `extract_conversation_keys`
  never feeds it: that method adopts every decryptable key without signature
  checks, and the cache holds verified keys only. To use its result, pass
  the returned key map to `decrypt_event` explicitly.

An explicit non-empty value always wins over the stores. The stores do not
change the two decrypt contracts: `decrypt_events` never throws (per-event
errors are collected in the result) and `decrypt_event` throws on failure.

---

#### When to use which

| Scenario | Use |
|---|---|
| Initial load — fetching all events for a conversation | `decryptEvents` |
| Polling / paginating through conversation history | `decryptEvents` |
| Single webhook event arrives and you already have conversation keys cached | `decryptEvent` |
| Real-time stream where events arrive one at a time | `decryptEvent` with cached keys |

**Typical flow:**
1. Once per instance: `setSigningKeys(allParticipantKeys)` and `setCacheKeys(true)`
2. Use `decryptEvents({ events })` on first load — it extracts conversation keys and returns them (and, with caching on, retains each conversation's latest verified key)
3. When new events arrive individually (webhooks, polling), use `decryptEvent({ eventB64 })` — the omitted key map and signing keys resolve from the session stores. Alternatively, cache `result.conversationKeys.keys` client-side and pass it as `conversationKeys`.

---

#### Conversation lifecycle — when to use which prepare method

All three `prepare*` methods return the same `PreparedConversationChange` shape
(fresh conversation key + encrypted participant keys + action signatures,
POST-ready). They differ in which lifecycle action they sign:

| Scenario | Use | Then POST to |
|---|---|---|
| Start a one-to-one (first contact) | `prepareConversationKeyChange` — omit `conversationId` | `/2/chat/conversations/{recipientId}/keys` |
| Rotate an existing conversation's key (one-to-one or group) | `prepareConversationKeyChange` — pass the conversation id | `/2/chat/conversations/{id}/keys` |
| Create a group | `prepareGroupCreate` | `/2/chat/conversations/group/initialize` (mints the `g…` id), then `/2/chat/conversations/group` |
| Add members to a group | `prepareGroupMembersChange` | `/2/chat/conversations/{id}/members` |

The group methods are separate because they sign different events: a group
create must carry a `GroupChangeEvent.GroupCreate` signature and a member add a
`GroupChangeEvent.GroupMemberAddChange` signature — each **in addition to** the
conversation-key change signature, so both return two `actionSignatures`.
A key rotation signs only the key change, so `prepareConversationKeyChange`
returns one.

After any of the three, store the returned `conversationKey` locally and use it
with `encryptMessage` until the next key change.

Two hygiene notes:

- **Verify recipient keys before wrapping.** The prepare methods encrypt the
  fresh conversation key to whatever public keys you pass; run
  `verifyKeyBinding` on fetched keys first, so a substituted identity key
  can't receive the conversation key. For stronger assurance, each party can
  call `getPublicKeyFingerprint()` on their own device and compare the values
  out-of-band.
- **Key-change signatures carry no `signaturePayload`.** The signed payload of
  a conversation-key change embeds the plaintext conversation key, so the SDK
  withholds it — the field is empty/omitted on that signature and must never be
  reconstructed and sent. Group-action signatures keep their payload (it
  contains only public fields).
- **Optional group fields normalize in core.** An empty-string `title` or
  `avatarUrl` and a negative `ttlMsec` are treated as "not set", so every
  binding signs identical bytes whether it can express an absent value or
  only the FFI encodings of one. A `title` or `avatarUrl` containing a comma
  is rejected at signing time (the signed payload is comma-joined with no
  escaping, so it could never verify).

---

#### prepare_conversation_key_change

**Recommended** — Generate, encrypt, and sign a conversation-key change in one call.

Use this to create a one-to-one conversation or rotate a conversation's key. The SDK:
1. Groups public keys by userId and picks the latest version per user
2. Generates a fresh conversation key (random 32 bytes) and a `conversationKeyVersion` (millisecond timestamp)
3. Encrypts the key for each participant (ECIES)
4. Signs the change so recipients can verify it came from the sender
5. Derives the conversation id for a one-to-one, or uses the id you pass for a group

Omit `conversationId` for a one-to-one and the SDK derives the canonical
`min:max` id from the two participants; pass the existing id for a group rotation.

**Conversation-id input forms.** Everywhere a one-to-one conversation id is
accepted for signing (`encryptMessage`, `encryptReply`, reactions,
`prepareConversationKeyChange`), the SDK canonicalizes whatever form you hold:
the colon form (`A:B`), the hyphen form from listings and URL paths (`A-B`, in
either order), or just the other participant's bare user id (paired with the
sender, exactly as the backend derives it from the request path). All forms
sign identical bytes — the numeric-sorted `min:max` colon form carried in
events. Group ids (`g…`) and non-numeric ids pass through unchanged.

**Returns: `PreparedConversationChange`**

```typescript
// JS
interface PreparedConversationChange {
  conversationId: string;           // derived (one-to-one) or the id you passed
  conversationKey: Uint8Array;      // raw 32-byte key — store locally
  conversationKeyVersion: string;   // timestamp-based version
  conversationParticipantKeys: EncryptedKeyForRecipient[];  // ready to POST
  actionSignatures: ActionSignature[];                      // ready to POST
}
```

```python
# Python
{
    "conversation_id": "17380288:1491585161162473473",
    "conversation_key": b"...",              # raw 32 bytes
    "conversation_key_version": "171000...", # timestamp string
    "conversation_participant_keys": [ {"user_id": "111", "encrypted_conversation_key": "...", "public_key_version": "1"} ],
    "action_signatures": [ {"message_id": "...", "message_event_signature": {"signature": "...", ...}, ...} ],
}
```

**Example — one-to-one creation / key rotation:**

```typescript
// 1. App fetches public keys (self + recipient) from X API
const publicKeys = await api.getPublicKeys([myId, recipientId]);

// 2. SDK generates, encrypts, and signs the change (id derived for a 1:1;
//    the sender identity resolves from setIdentity — set senderId /
//    signingKeyVersion on the params to override)
const result = chat.prepareConversationKeyChange({ publicKeys });

// 3. App POSTs to X API
await fetch(`/api/conversations/${result.conversationId}/keys`, {
  body: JSON.stringify({
    conversationKeyVersion: result.conversationKeyVersion,
    conversationParticipantKeys: result.conversationParticipantKeys,
    actionSignatures: result.actionSignatures,
  })
});

// 4. App stores the conversation key locally
cache.set(result.conversationId, result.conversationKey, result.conversationKeyVersion);
```

For a group key rotation, set `conversationId` to the existing group's id.

---

#### prepare_group_create

Generate, encrypt, and sign a group **create**. Same return shape as
`prepare_conversation_key_change`; additionally takes the initial `member_ids`
and `admin_ids` lists and optional title, avatar, and TTL.

The backend validates a group create as a pair of signed actions, so the
returned `actionSignatures` array carries **two** entries: a conversation-key
change (`ConversationKeyChangeEvent`) and the group create
(`GroupChangeEvent.GroupCreate`). Each signature's `encodedMessageEventDetail`
carries the corresponding event, ready to POST.

The signed payload is comma-joined without escaping, so `title` and `avatar_url`
must not contain a comma — such a signature cannot be verified.

---

#### prepare_group_members_change

Generate, encrypt, and sign a group **member-add** change for the updated roster.
Same return shape as `prepare_conversation_key_change`; additionally takes the
new/current/admin/pending member id lists and optional title, avatar, TTL, and
screen-capture-blocking state.

**Optional group-state fields (per binding):**

| Field | Rust | JS | Python | Go | JVM | .NET |
|---|---|---|---|---|---|---|
| current_title | `Option<String>` | `currentTitle?: string \| null` | `current_title=None` | `CurrentTitle string` (empty = unset) | `String currentTitle` (null = unset) | `string? CurrentTitle` |
| current_avatar_url | `Option<String>` | `currentAvatarUrl?: string \| null` | `current_avatar_url=None` | `CurrentAvatarURL string` (empty = unset) | `String currentAvatarUrl` (null = unset) | `string? CurrentAvatarUrl` |
| current_ttl_msec | `Option<i64>` | `currentTtlMsec?: number \| null` | `current_ttl_msec=None` | `CurrentTTLMsec *int64` (nil = unset) | `Long currentTtlMsec` (null = unset) | `long? CurrentTtlMsec` |
| current_screen_capture_blocking_enabled | `Option<bool>` | `currentScreenCaptureBlockingEnabled?: boolean \| null` | `current_screen_capture_blocking_enabled=None` | `CurrentScreenCaptureBlockingEnabled *bool` (nil = unset) | `Boolean currentScreenCaptureBlockingEnabled` (null = unset) | `bool? CurrentScreenCaptureBlockingEnabled` |

Pass the group's current `screenCaptureBlockingEnabled` state when the group
has it set: the backend compares it against the signed value, so a member add
on a screen-capture-blocking group only validates when the flag is supplied.
Leave it absent/null when the group never enabled it — absent signs the `null`
sentinel, not `false`.

Like `prepare_group_create`, this returns **two** `actionSignatures`: a
conversation-key change (`ConversationKeyChangeEvent`) and the member add
(`GroupChangeEvent.GroupMemberAddChange`), each with its
`encodedMessageEventDetail` populated. As with group create, the `title` and
`avatar_url` fields must not contain a comma.

---

#### extract_conversation_keys

Scans an array of raw events for KeyChange events and decrypts the conversation keys from them.

**Params:**

| Param | JS | Python | Rust | Go | JVM | .NET |
|---|---|---|---|---|---|---|
| events | `string[]` | `list[str]` | `&[&str]` | `[]string` | `List<String>` | `IEnumerable<string>` |

**Returns: `ConversationKeyResult`**

```typescript
// JS
interface ConversationKeyResult {
  keys: { [version: string]: Uint8Array };  // version → raw conversation key
  latestVersion: string | null;             // highest version (for encrypting)
}
```

```python
# Python
{
    "keys": { "1": b"...", "2": b"..." },   # version → raw bytes
    "latest_version": "2"                    # or None
}
```

---

#### decrypt_events — batch, self-contained

Decrypts multiple events in one call. Handles everything internally:
1. First pass: extracts conversation keys from any KeyChange events in the array
2. Second pass: for each event, extracts the sender ID, filters signing keys by `userId`, and decrypts

**Params: `DecryptEventsParams`**

| Field | JS | Python | Rust | Go | JVM | .NET | Description |
|---|---|---|---|---|---|---|---|
| events | `events: string[]` | `events: list[str]` | `events: Vec<String>` | `Events []string` | `List<String> events` | `IReadOnlyList<string> Events` | All base64-encoded raw events. **Must include KeyChange events** — without them, messages depending on those keys will land in `errors`. The events endpoint returns KeyChange events in **`meta.conversation_key_events`**, separate from the `data` array; concatenate both into this field. |
| signing_keys | `signingKeys?: SigningKeyEntry[] \| null` | `signing_keys: list[dict] \| None` (keyword) | `signing_keys: Option<Vec<SigningKeyEntry>>` | `SigningKeys []SigningKeyEntry` (nil = unset) | `List<SigningKeyEntry> signingKeys` (null = unset) | `IReadOnlyList<SigningKeyEntry>? SigningKeys` | Signing keys for **all participants**. The SDK extracts each event's `senderId` internally and filters to the matching keys. Leaving it unset (or empty) falls back to the keys stored via `setSigningKeys`; if none are stored either, under the default reject-unverified policy every **signed** event fails decryption and lands in `errors`. Only after `setRejectUnverified(false)` are such events returned with `verified: false`. |

**Returns: `DecryptEventsResult`** — never throws/raises. Errors are collected.

```typescript
// JS
interface DecryptEventsResult {
  messages: DecryptedMessage[];             // successfully decrypted events
  conversationKeys: ConversationKeyResult;  // extracted keys (cache these)
  errors: { [index: string]: string };      // event index (string key) → error message
}

interface DecryptedMessage {
  event: Event;           // the decrypted event (same type as decryptEvent returns)
  originalB64?: string;   // the raw input string, for reference
}
```

```python
# Python
{
    "messages": [
        { "event": { "type": "Message", ... }, "original_b64": "SGVsbG8..." },
        ...
    ],
    "conversation_keys": { "keys": { ... }, "latest_version": "3" },
    "errors": { "2": "Missing conversation key for version 4" }
}
```

**Rule out a missing-key-events batch first.** The most common cause of
`Message encrypted with key version '…' but no matching key found` is caller
input: the KeyChange events were left out of the batch (they arrive in
`meta.conversation_key_events`, not `data` — see the events argument above).
That case is fixed by re-batching with the key events included.

**The remaining per-event errors are permanent.** Signatures are immutable and
verified by rebuilding the signed payload from the event, so an event whose
signature was produced from the wrong input (or never signed at all) fails
verification on every future load — it cannot be healed by retrying,
refreshing keys, or any API call. Treat these as tombstones, not transient
failures:

| Error | Meaning |
|---|---|
| `…signature missing or no matching signing key` on a KeyChange | The key change was never signed (or signed with an unpublished key). Its conversation key is never extracted. |
| `ECDSA mismatch: key_version=…` | The signer fed different bytes into the signature than the event carries (e.g. a non-canonical conversation id). |
| `Message encrypted with key version '…' but no matching key found` (key events included in the batch) | The message's key came from an unverifiable KeyChange above — collateral of the first row. |

New messages are unaffected: rotating the key starts a clean, verifiable
history from that point forward. (Verifiability only — rotation does not
retroactively protect earlier messages if a key was compromised; see the
forward-secrecy note in [CRYPTO.md](CRYPTO.md#known-limitations).)

**JS example:**
```typescript
// Fetch all events from the API
const rawEvents: string[] = await fetchConversationEvents(conversationId);

// Fetch signing keys for all participants (pass the X API response through directly)
const signingKeys: SigningKeyEntry[] = [
  { userId: "111", publicKeyVersion: "1", publicKey: "BASE64...", identityPublicKey: "BASE64...", identityPublicKeySignature: "BASE64..." },
  { userId: "111", publicKeyVersion: "2", publicKey: "BASE64...", identityPublicKey: "BASE64...", identityPublicKeySignature: "BASE64..." },
  { userId: "222", publicKeyVersion: "1", publicKey: "BASE64...", identityPublicKey: "BASE64...", identityPublicKeySignature: "BASE64..." },
];

const result = chat.decryptEvents({ events: rawEvents, signingKeys });

// Iterate decrypted messages
for (const dm of result.messages) {
  if (dm.event.type === "message") {
    console.log(dm.event.senderId, dm.event.content.text);
  }
}

// Cache conversation keys for later decryptEvent calls
const cachedKeys = result.conversationKeys;
console.log(cachedKeys.latestVersion); // "3" — use for encrypting replies
```

**Python example:**
```python
from chat_xdk import DecryptEventsParams

result = chat.decrypt_events(DecryptEventsParams(raw_events, signing_keys=signing_keys))

for dm in result["messages"]:
    evt = dm["event"]
    if evt["type"] == "Message":
        print(evt["sender_id"], evt["content"]["text"])

# Cache for later
cached_keys = result["conversation_keys"]
```

**Go example:**
```go
result, err := chat.DecryptEvents(chatxdk.DecryptEventsParams{
    Events:      rawEvents,
    SigningKeys: signingKeys,
})
if err != nil {
    panic(err)
}

for _, dm := range result.Messages {
    if dm.Event.Type == "Message" {
        fmt.Println(dm.Event.AsMessage().Text())
    }
}

// Cache for later
cachedKeys := result.ConversationKeys.Keys
```

**JVM example:**
```java
DecryptEventsParams params = new DecryptEventsParams(rawEvents);
params.signingKeys = signingKeys;
DecryptEventsResult result = chat.decryptEvents(params);

for (DecryptedMessage dm : result.messages) {
    JsonNode event = dm.event;
    if ("Message".equals(event.path("type").asText())) {
        System.out.println(event.path("content").path("text").asText());
    }
}

// Cache for later
Map<String, byte[]> cachedKeys = result.conversationKeys.keys;
```

**.NET example:**
```csharp
var result = chat.DecryptEvents(new DecryptEventsParams(rawEvents) { SigningKeys = signingKeys });

foreach (var dm in result.Messages)
{
    if (dm.Event.GetProperty("type").GetString() == "Message")
        Console.WriteLine(dm.Event.GetProperty("content").GetProperty("text").GetString());
}

// Cache for later
var cachedKeys = result.ConversationKeys.Keys;
```

In Python, `result["errors"]` maps **string** indices (e.g. `"2"`) to error messages — JSON object keys, consistent with other bindings.

---

#### decrypt_event — single event, with pre-cached keys

Decrypts a single event using conversation keys you already have — cached from a prior `decryptEvents` or `extractConversationKeys` call, or resolved from the opt-in key cache (`setCacheKeys`) when the key map is empty.

**Params: `DecryptEventParams`**

| Field | JS | Python | Rust | Go | JVM | .NET | Description |
|---|---|---|---|---|---|---|---|
| event_b64 | `eventB64: string` | `event_b64: str` | `event_b64: String` | `EventB64 string` | `String eventB64` | `string EventB64` | One base64-encoded raw event. |
| conversation_keys | `conversationKeys?: ConversationKeyMap \| null` | `conversation_keys: dict[str, bytes] \| None = None` | `conversation_keys: HashMap<String, XChatConversationKey>` | `ConversationKeys map[string][]byte` | `Map<String, byte[]> conversationKeys` (or the one-argument constructor) | `IReadOnlyDictionary<string, byte[]>? ConversationKeys` (optional constructor argument) | Pre-extracted keys: **version → raw 32-byte key**. Every binding passes raw key bytes. Optional everywhere but Rust, where the map may be empty: omitted or empty, the keys come from the opt-in key cache (`setCacheKeys`), and non-message events (typing, read receipts) need no keys at all. |
| signing_keys | `signingKeys?: SigningKeyEntry[] \| null` | `signing_keys: list[dict] \| None` (keyword) | `signing_keys: Option<Vec<SigningKeyEntry>>` | `SigningKeys []SigningKeyEntry` (nil = unset) | `List<SigningKeyEntry> signingKeys` (null = unset) | `IReadOnlyList<SigningKeyEntry>? SigningKeys` | Signing keys for **the event's sender**. The SDK matches by `publicKeyVersion` against the version in the event's signature. Leaving it unset (or empty) falls back to the keys stored via `setSigningKeys`; if none are stored either, under the default reject-unverified policy every **signed** event fails with an error. Only after `setRejectUnverified(false)` are such events returned with `verified: false`. |

**Returns: `Event`** directly — or **throws/raises** on failure (unlike `decryptEvents` which collects errors).

```typescript
// JS — returns Event, throws on error
interface DecryptEventParams {
  eventB64: string;
  conversationKeys?: ConversationKeyMap | null;  // omitted ⇒ opt-in key cache (setCacheKeys)
  signingKeys?: SigningKeyEntry[] | null;  // unset ⇒ keys from setSigningKeys; if
                                           // none stored, signed events throw,
                                           // unless setRejectUnverified(false)
}
decryptEvent(params: DecryptEventParams): Event
```

```python
# Python — returns dict, raises on error
DecryptEventParams(
    event_b64: str,
    conversation_keys: dict[str, bytes] | None = None,  # { version: bytes };
                                          # None ⇒ opt-in key cache (set_cache_keys)
    *,
    signing_keys: list[dict] | None = None,  # None ⇒ keys from set_signing_keys;
                                             # if none stored, signed events raise,
                                             # unless set_reject_unverified(False)
)
decrypt_event(params: DecryptEventParams) -> dict
```

**JS example:**
```typescript
// You cached keys from a previous decryptEvents call
const cachedKeys = previousResult.conversationKeys.keys;

// A new event arrives via webhook
const event = chat.decryptEvent({
  eventB64: webhookEventB64,
  conversationKeys: cachedKeys,
  signingKeys: [
    { userId: "111", publicKeyVersion: "2", publicKey: "BASE64...", identityPublicKey: "BASE64...", identityPublicKeySignature: "BASE64..." },
  ],
});

console.log(event.type);             // "message"
console.log(event.senderId);         // "111"
console.log(event.content.text);     // "hello"
console.log(event.verified);         // true
```

**Python example:**
```python
from chat_xdk import DecryptEventParams

event = chat.decrypt_event(
    DecryptEventParams(event_b64, cached_keys, signing_keys=sender_signing_keys)
)
if event["type"] == "Message":
    print(event["content"]["text"])
```

**Go example:**
```go
event, err := chat.DecryptEvent(chatxdk.DecryptEventParams{
    EventB64:         eventB64,
    ConversationKeys: cachedKeys,
    SigningKeys:      senderSigningKeys,
})
if err != nil {
    panic(err)
}
fmt.Println(event.Type)
```

**JVM example:**
```java
DecryptEventParams params = new DecryptEventParams(eventB64, cachedKeys);
params.signingKeys = senderSigningKeys;
JsonNode event = chat.decryptEvent(params);
if ("Message".equals(event.path("type").asText())) {
    System.out.println(event.path("content").path("text").asText());
}
```

**.NET example:**
```csharp
var eventJson = chat.DecryptEvent(
    new DecryptEventParams(eventB64, cachedKeys) { SigningKeys = senderSigningKeys });
if (eventJson.GetProperty("type").GetString() == "Message")
    Console.WriteLine(eventJson.GetProperty("content").GetProperty("text").GetString());
```

---

#### Side-by-side comparison

| | `decryptEvent` | `decryptEvents` |
|---|---|---|
| **Input** | 1 event (`string`) | N events (`string[]`) |
| **Conversation keys** | Caller provides (`ConversationKeyMap`); empty ⇒ opt-in key cache (`setCacheKeys`) | SDK extracts from KeyChange events internally |
| **Signing keys** | For the **sender only**, matched by `publicKeyVersion`; unset ⇒ `setSigningKeys` store | For **all participants**, SDK filters by `userId` per event; unset ⇒ `setSigningKeys` store |
| **Error handling** | **Throws** on failure | **Never throws** — errors collected in `result.errors` |
| **Return type** | `Event` (flat) | `DecryptEventsResult` wrapping `DecryptedMessage[]` |
| **Returns original b64** | No | Yes (`originalB64` on each message) |
| **Returns conv keys** | No | Yes (`conversationKeys` with `latestVersion`) |
| **Parses each event** | 1× | multiple passes (key extraction → key-change signature enforcement → freshness pinning → senderId extraction → decrypt) |
| **Requires KeyChange in input** | No — you bring your own keys | Yes — or keyless messages end up in `errors` |

---

#### Shared types

**SigningKeyEntry** — used by both methods. Every field maps directly to one
entry of the X API public keys response, so you can pass the API data through
unchanged:
```typescript
// JS
interface SigningKeyEntry {
  userId: string;                     // user ID that owns this key
  publicKeyVersion: string;           // key version from the X API ("public_key_version")
  publicKey: string;                  // base64 signing public key ("signing_public_key")
  identityPublicKey: string;          // base64 identity public key ("public_key")
  identityPublicKeySignature: string; // base64 raw r||s binding signature ("identity_public_key_signature")
}
```
```python
# Python
{
  "user_id": "123",
  "public_key_version": "1",
  "public_key": "BASE64...",                    # signing public key
  "identity_public_key": "BASE64...",
  "identity_public_key_signature": "BASE64...",
}
```

The SDK verifies each entry's identity binding (`identityPublicKeySignature`)
before trusting it for signature verification, so all fields are required.

**ConversationKeyMap** — the `conversationKeys` field of `DecryptEventParams` and of the file decrypt params, and the `keys` field of `ConversationKeyResult`:
```typescript
// JS
type ConversationKeyMap = { [version: string]: Uint8Array };
```
```python
# Python
{ "1": b"\x01\x02...", "2": b"\x03\x04..." }
```

**Unencrypted events**: Events without a `conversationKeyVersion` carry no verifiable signature, so under the default reject-unverified policy they are **rejected** (`decryptEvent` throws; `decryptEvents` records them in `errors`). After `setRejectUnverified(false)` they are returned with `keyVersion: null` and `verified: false`.

### Message Encryption

| # | Method | Rust | JS | Python | Go | JVM | .NET |
|---|--------|------|-----|--------|-----|------|------|
| 26 | **encrypt_message** | `encrypt_message(&EncryptMessageParams) → SendPayload` | `encryptMessage(params: EncryptMessageParams) → SendPayload` | `encrypt_message(EncryptMessageParams) → SendPayload` | `EncryptMessage(params EncryptMessageParams) (*SendPayload, error)` | `encryptMessage(EncryptMessageParams)` | `EncryptMessage(EncryptMessageParams)` |
| 27 | **encrypt_reply** | `encrypt_reply(&EncryptReplyParams) → SendPayload` | `encryptReply(params: EncryptReplyParams) → SendPayload` | `encrypt_reply(EncryptReplyParams) → SendPayload` | `EncryptReply(params EncryptReplyParams) (*SendPayload, error)` | `encryptReply(EncryptReplyParams)` | `EncryptReply(EncryptReplyParams)` |
| 28 | **encrypt_add_reaction** | `encrypt_add_reaction(&EncryptReactionParams) → SendPayload` | `encryptAddReaction(params: EncryptReactionParams) → SendPayload` | `encrypt_add_reaction(EncryptReactionParams) → SendPayload` | `EncryptAddReaction(params EncryptReactionParams) (*SendPayload, error)` | `encryptAddReaction(EncryptReactionParams)` | `EncryptAddReaction(EncryptReactionParams)` |
| 29 | **encrypt_remove_reaction** | `encrypt_remove_reaction(&EncryptReactionParams) → SendPayload` | `encryptRemoveReaction(params: EncryptReactionParams) → SendPayload` | `encrypt_remove_reaction(EncryptReactionParams) → SendPayload` | `EncryptRemoveReaction(params EncryptReactionParams) (*SendPayload, error)` | `encryptRemoveReaction(EncryptReactionParams)` | `EncryptRemoveReaction(EncryptReactionParams)` |
| 30 | **encrypt_edit** | `encrypt_edit(&EncryptEditParams) → SendPayload` | `encryptEdit(params: EncryptEditParams) → SendPayload` | `encrypt_edit(EncryptEditParams) → SendPayload` | `EncryptEdit(params EncryptEditParams) (*SendPayload, error)` | `encryptEdit(EncryptEditParams)` | `EncryptEdit(EncryptEditParams)` |
| 31 | **prepare_message_delete** | `prepare_message_delete(&MessageDeleteParams) → PreparedAction` | `prepareMessageDelete(params: MessageDeleteParams) → PreparedAction` | `prepare_message_delete(MessageDeleteParams) → dict` | `PrepareMessageDelete(params MessageDeleteParams) (*PreparedAction, error)` | `prepareMessageDelete(MessageDeleteParams)` → `PreparedAction` | `PrepareMessageDelete(MessageDeleteParams)` → `PreparedAction` |
| 32 | **prepare_mark_conversation_read** | `prepare_mark_conversation_read(&MarkConversationReadParams) → PreparedAction` | `prepareMarkConversationRead(params: MarkConversationReadParams) → PreparedAction` | `prepare_mark_conversation_read(MarkConversationReadParams) → dict` | `PrepareMarkConversationRead(params MarkConversationReadParams) (*PreparedAction, error)` | `prepareMarkConversationRead(MarkConversationReadParams)` → `PreparedAction` | `PrepareMarkConversationRead(MarkConversationReadParams)` → `PreparedAction` |

Required fields of `EncryptMessageParams` (all bindings, names per language
idiom): `conversation_id` and `text`. Everything else is an optional override:

- `sender_id` / `signing_key_version` — resolve from the session identity
  (`set_identity`) when omitted.
- `conversation_key` / `conversation_key_version` — resolve from the opt-in
  key cache (`set_cache_keys`) when omitted. The pair travels together: set
  both or neither. When set, `conversation_key` is the **raw 32-byte key**
  (`Uint8Array` in JS, `bytes` in Python, `[]byte` in Go, `byte[]` in
  JVM/.NET) from `prepare_conversation_key_change()` /
  `decrypt_conversation_key()`.
- `entities`, `attachments`, `quick_reply`, `should_notify` (defaults to true), `ttl_msec`.

An omitted value and its explicit equivalent produce byte-identical signed
output for the same logical inputs (Rust: `params.with_identity(…)` /
`params.with_conversation_key(…)`).
The SDK generates the message id and returns it on the `SendPayload` (see
below), together with `event_b64`: the message as recipients receive it.

**A message with files is built before its files are encrypted.** Each file —
a media attachment, or a link card's banner or favicon image — names the
`media_hash_key` its upload started with. Encrypt the message first, then
encrypt each file from the payload's `event_b64` and its `media_hash_key`
(see [Files (Media)](#files-media)). In v1 (see below) the SDK derives the id
of a message with files from the conversation key and its version, the
sender, the conversation, and the files' media hash keys in order, so
building the same message again (same files, sender, conversation and key)
gives the same id, and the files encrypted for it stay valid. The text does
not affect the id. v0 messages, and messages without files, take a random
id, as in 0.5.x. Each file needs its own media hash key: an empty one, or one
listed in more than one attachment, is rejected.

**Upload each file for one message only.** Because the text does not affect
a v1 message's id, a second message in the same conversation, from the same
sender under the same key version, that reuses the first one's uploads gets
the first one's id, and recipients, who deduplicate on the message id, drop
it as a repeat. To send the same file again, upload it again: the new upload
gets its own media hash key.

**The SDK picks each send's format.** An encrypted send (message, reply,
reaction, edit) is either v0, the 0.5.x format, with contents under the
conversation key, no `contents_encryption_version`, and signature version 7,
or v1, with contents encrypted under a key derived from the conversation key,
the sender id, and the message id, the `MessageCreateEvent` marked with
`contents_encryption_version` 1, and signature version 10, which covers that
field (see [CRYPTO.md — Message Keys](CRYPTO.md#message-keys)). Files follow
their message's format. The sender id must be the sender's numeric user id
and the conversation key version an integer, as the key-change event carries
it; anything else is rejected, since v1 recipients derive the key from the
numeric id and look the key up by the version.

**Every user id is a string of digits** in every binding: the `set_identity`
user id, `sender_id`, `reply_to_sender_id`, the `user_id` of each public key,
and group member, admin and pending-member ids. Each must be a positive
integer written without a sign or leading zeros, and anything else fails
with an error naming the field (`Invalid reply_to_sender_id '…'`). JS takes
no numbers for them: ids pass 2^53, where JS numbers stop being exact.

**Every key version is a string of digits**, as the X API returns it: the
signing-key version (`signing_key_version` in `set_identity`,
`import_keys` and per call, and each public key's `key_version`) and the
`conversation_key_version`. Both kinds take the same check, a non-negative
integer written without a sign or leading zeros, and anything else fails
with an error naming the field.

The format follows the X API's `v1_send` feature switch, which the JS,
Python, Go, .NET and JVM bindings fetch in the background (see
[ARCHITECTURE.md — Feature Switches](ARCHITECTURE.md#feature-switches)).
**The Rust crate never fetches it, so `ChatCore` and `Chat` always send
v0.** They read v1 sends like every binding. The fetch logs nothing; to see
which format a send used, read the payload's
`signature_info.signature_version`: `"7"` for v0, `"10"` for v1. A 0.5.x
reader rejects a v1 send as a signature verification failure, so in its logs
v1 sends look like forged messages.

The `entities` parameter shape is split by binding: **Rust, .NET, and JVM**
take structured `EntityDescriptor` objects (`{ start, end, entity_type }`),
while **JS, Python, and Go** take positional `[start, end, type]` tuples
(`EntityTuple` in JS/Go, plain tuples in Python). Same wire format underneath
— see the [EntityDescriptor / EntityTuple](#entitydescriptor-rust-net-jvm--entitytuple-go-js--tuple-python)
type section.
The `attachments` parameter takes media, URL-card (optionally with encrypted
banner/favicon preview images), and post descriptors — see
[AttachmentDescriptor (send side)](#attachmentdescriptor-send-side).
The `quick_reply` parameter attaches a quick-reply request (selectable
options) or response (the selected option) — see
[QuickReply](#quickreply).
**Temporary restriction:** `encrypt_message` and `encrypt_reply` reject
attachment lists that current first-party clients cannot render — multiple
attachments are allowed only when every one is image/gif/video media
(`media_type` 1/2/3, or omitted, which defaults to image), up to 10 per
message; everything else — audio, file, svg, or unrecognized media types, URL
cards, and posts — must be the sole attachment. Disallowed combinations fail
with a "disallowed attachment combination…" (or "too many attachments…")
error in every binding rather than producing a message that
breaks receivers. This mirrors the first-party encrypted-send rules and will
be relaxed when clients support heterogeneous attachment lists; the wire
format already carries them.

**Replies are event-based.** The preferred form of `EncryptReplyParams` adds
`reply_to_event` — the base64 raw signed event being replied to. The SDK
derives the reply preview (sequence id, sender, text, entities, attachments)
from it and embeds the raw event in the outgoing message so recipients can
validate the preview (see
[CRYPTO.md — Reply preview validation](CRYPTO.md#reply-preview-validation)).
Two companions cover the edge cases: `reply_to_edit_event` carries the raw
edit event when the original was edited, and `reply_to_ckces` carries the raw
key-change events needed to decrypt an original that was encrypted under a
different key version than this reply. When the original or its edit is
encrypted under a per-message key, the reply also carries that key so
recipients can open it. The explicit preview fields —
`reply_to_sequence_id`, `reply_to_sender_id`, `reply_to_text`,
`reply_to_entities`, `reply_to_attachments` — remain as overrides for callers
that no longer hold the raw event.

**Reactions are event-based too.** `EncryptReactionParams` (shared by add and
remove — the same params value can add and later remove the same reaction)
requires `emoji` plus a target: pass `target_event`, the base64 raw event
being reacted to, and the SDK derives `conversation_id` and
`target_message_sequence_id` from it; or set those two fields explicitly
instead.

**Edits target an event the same way.** `EncryptEditParams` requires
`updated_text` — the replacement message text — plus the same target choice
as a reaction: `target_event` (the base64 raw event of the message being
edited) or the explicit `conversation_id` / `target_message_sequence_id`
pair. Optional `entities` describe rich text in the replacement text;
omitting them clears any entities the original carried. With
`target_event`, the edit also names the original's signed message id, which
receivers need to tie an edit to a message encrypted under a per-message key.
The edit is encrypted and signed like a regular message (the identity/key
overrides above apply) and returns a `SendPayload` with its own fresh
`message_id`.

> **Delivery-race warning.** Receiving clients apply an edit to their stored
> copy of the original and park it when the original has not arrived yet;
> the backend stops serving a superseded original, so an edit that reaches a
> client before the original leaves the message permanently invisible on
> that client. Give a freshly sent message a few seconds to be delivered
> before sending its first edit.

**Message deletes are signed, not encrypted.** `MessageDeleteParams`
requires `conversation_id`, the `sequence_ids` of the messages to delete,
and `delete_for_all` — `true` deletes for every participant (own messages
only), `false` only from the caller's view. No conversation key is involved:
`prepare_message_delete` returns a `PreparedAction`, the request's
`action_signatures` with one entry. The entry is an `ActionSignature`, the
same shape as the conversation-change `actionSignatures` entries (see
**Action signatures** below), with its `signature_payload` populated; its
`encodedMessageEventDetail` carries the `MessageDeleteEvent`. The optional
`sender_id` / `signing_key_version` overrides resolve from the session
identity, and a one-to-one id is signed in its canonical colon form, as
everywhere.

**Read receipts are signed, not encrypted.** `MarkConversationReadParams`
requires `conversation_id` and `seen_until_sequence_id` — the `sequence_id`
of the newest event read. The optional `seen_at_msec` (milliseconds since the
Unix epoch) records when it was read and defaults to the current time; the JS
binding reads the JavaScript clock. `prepare_mark_conversation_read` returns a
`PreparedAction` shaped as for deletes, whose entry's
`encodedMessageEventDetail` carries the `MarkConversationReadEvent`. The
signature covers the read point and its time, so a recipient's
`decrypt_event` returns the receipt as a `ReadReceipt` event with `verified`
set, `seen_until_id`, and `seen_at_msec`. The identity overrides and the
canonical one-to-one id work as for deletes.

Send the receipt in the mark-read request,
`POST /2/chat/conversations/{id}/read`: its `action_signatures` take the
`PreparedAction`'s entries as they are.

**Action signatures.** Every prepare method returns its signed actions in
the shape a request's `action_signatures` carries them, so they serialize
into the request body as they are (snake_case shown; JS returns camelCase):

```json
{
  "action_signatures": [
    {
      "message_id": "<the action's message id, generated by the SDK>",
      "encoded_message_event_detail": "<base64 MessageEventDetail>",
      "message_event_signature": {
        "signature": "<base64 ECDSA signature>",
        "signature_version": "7",
        "public_key_version": "<your signing key version>",
        "signing_public_key": "<your signing public key, as get_public_keys returns it>"
      },
      "signature_payload": "<the signed payload; omitted for conversation-key changes>"
    }
  ]
}
```

The Rust structs pair a `new(…required…)` constructor with public optional
fields:

```rust
// Rust — session identity + key cache resolve the omitted fields
chat.set_identity(&SetIdentityParams::new(my_user_id, signing_key_version))?;
chat.set_cache_keys(true); // filled by decrypt_events

let mut params = EncryptMessageParams::new(conversation_id, "Hello");
params.ttl_msec = Some(86_400_000);
let payload = chat.encrypt_message(&params)?;
let message_id = payload.message_id; // generated by the SDK

// Reply / react by handing back the raw event being answered
let reply = chat.encrypt_reply(&EncryptReplyParams::new(
    conversation_id, "pong", original_event_b64,
))?;
let reaction =
    chat.encrypt_add_reaction(&EncryptReactionParams::new(original_event_b64, "👍"))?;
```

```typescript
// JS
chat.setIdentity({ userId: myUserId, signingKeyVersion });
chat.setCacheKeys(true);

const payload = chat.encryptMessage({
  conversationId,
  text: "Hello",
  ttlMsec: 86_400_000,
});
const messageId = payload.messageId; // generated by the SDK

const reply = chat.encryptReply({
  conversationId,
  text: "pong",
  replyToEvent: originalEventB64,
});
const reaction = chat.encryptAddReaction({ emoji: "👍", targetEvent: originalEventB64 });
```

```python
# Python — params classes: required fields positional, optionals as keywords
from chat_xdk import (
    EncryptMessageParams,
    EncryptReactionParams,
    EncryptReplyParams,
    SetIdentityParams,
)

chat.set_identity(SetIdentityParams(my_user_id, signing_key_version))
chat.set_cache_keys(True)

payload = chat.encrypt_message(
    EncryptMessageParams(conversation_id, "Hello", ttl_msec=86_400_000)
)
message_id = payload.message_id  # generated by the SDK

reply = chat.encrypt_reply(EncryptReplyParams(conversation_id, "pong", original_event_b64))
reaction = chat.encrypt_add_reaction(EncryptReactionParams(original_event_b64, "👍"))
```

### Files (Media)

| # | Method | Rust | JS | Python | Go | JVM | .NET |
|---|--------|------|-----|--------|-----|------|------|
| 33 | **encrypt_file** | `encrypt_file(&EncryptFileParams) → Vec<u8>` | `encryptFile(params: EncryptFileParams) → Uint8Array` | `encrypt_file(EncryptFileParams) → bytes` | `EncryptFile(EncryptFileParams) ([]byte, error)` | `encryptFile(EncryptFileParams)` → `byte[]` | `EncryptFile(EncryptFileParams)` → `byte[]` |
| 34 | **file_encryptor** | `file_encryptor(&FileEncryptorParams) → FileEncryptor` | `fileEncryptor(params: FileEncryptorParams) → FileEncryptor` | `file_encryptor(FileEncryptorParams) → FileEncryptor` | `FileEncryptor(FileEncryptorParams) (*FileEncryptor, error)` | `fileEncryptor(FileEncryptorParams)` → `FileEncryptor` | `FileEncryptor(FileEncryptorParams)` → `FileEncryptor` |
| 35 | **decrypt_file** | `decrypt_file(DecryptFileParams) → Vec<u8>` | `decryptFile(params: DecryptFileParams) → Uint8Array` | `decrypt_file(DecryptFileParams) → bytes` | `DecryptFile(DecryptFileParams) ([]byte, error)` | `decryptFile(DecryptFileParams)` → `byte[]` | `DecryptFile(DecryptFileParams)` → `byte[]` |
| 36 | **file_decryptor** | `file_decryptor(FileDecryptorParams) → FileDecryptor` | `fileDecryptor(params: FileDecryptorParams) → FileDecryptor` | `file_decryptor(FileDecryptorParams) → FileDecryptor` | `FileDecryptor(FileDecryptorParams) (*FileDecryptor, error)` | `fileDecryptor(FileDecryptorParams)` → `FileDecryptor` | `FileDecryptor(FileDecryptorParams)` → `FileDecryptor` |

The file calls take the key the way the message calls do: a send takes the
one key its message was encrypted under, and a receive takes the
conversation's key map, as `decrypt_event` does (names per language idiom):

| Params | Fields |
|---|---|
| `EncryptFileParams` | `file`, `event_b64`, `media_hash_key`; optional `conversation_key` + `conversation_key_version` |
| `FileEncryptorParams` | `event_b64`, `media_hash_key`; optional `conversation_key` + `conversation_key_version` |
| `DecryptFileParams` | `encrypted`, `event_b64`, `conversation_keys`, `media_hash_key` |
| `FileDecryptorParams` | `event_b64`, `conversation_keys`, `media_hash_key` |

`event_b64` is the base64 event of the message that carries the file and
`media_hash_key` the file's media hash key. On a send, `conversation_key` and
`conversation_key_version` are the raw 32-byte key the message was encrypted
under and its version, set together as on `EncryptMessageParams`; with both
unset they resolve from the key cache. On a receive, `conversation_keys` is
the conversation's key map (version → raw 32-byte key). Each file of a
message is encrypted under its own key, derived from the message's key and
the file's attachment (see [CRYPTO.md — Media Keys](CRYPTO.md#media-keys)),
so a file encrypted for another message or attachment does not decrypt.

**Sending files.** A message with files is built before its files are
encrypted:

1. Start each file's upload to the conversation's media store
   (`POST /2/chat/media/upload/initialize`, with `total_bytes` set to
   `encrypted_file_size` of the file's size) and keep the returned
   `media_hash_key`. A media hash key names one file of one message: start a
   new upload for each file of each message.
2. Encrypt the message with `encrypt_message` or `encrypt_reply`, its
   attachments naming those media hash keys.
3. Encrypt each file with `encrypt_file` or `file_encryptor`: pass the
   payload's `event_b64`, the file's `media_hash_key`, and the conversation
   key and version the message was encrypted under (or neither, to resolve
   them from the key cache). The SDK finds the file in the message and
   encrypts it under that attachment's key.
4. Upload each encrypted file and finish its upload (`append` → `finalize`),
   then send the message.

The order of the uploads does not matter, and the file calls need no session
identity: the sender, message id and key version come from `event_b64`. If
you build the message again (for example after a restart), the same files,
sender, conversation and key give the same message id, so files already
encrypted for it stay valid.

```js
const totalBytes = encryptedFileSize(photo.length);
const { sessionId, mediaHashKey } = await startMediaUpload(conversationId, totalBytes);
const payload = chat.encryptMessage({
  conversationId,
  text: "a photo",
  attachments: [{ attachment_type: "media", media_hash_key: mediaHashKey, width, height, filesize_bytes: totalBytes, filename: "photo.jpg", media_type: 1 }],
});
const encrypted = chat.encryptFile({
  file: photo,
  eventB64: payload.eventB64,
  conversationKey,
  conversationKeyVersion,
  mediaHashKey,
});
await finishMediaUpload(conversationId, { sessionId, mediaHashKey }, encrypted);
await sendMessage(conversationId, payload);
```

**Receiving files.** Pass the base64 event of the message that carries the
file and the conversation's key map — the same two values `decrypt_event`
takes — plus the file's `media_hash_key` from the decrypted message: one of
its media attachments, a link card's banner or favicon (both listed in
`media_hashes`), or media quoted in its reply preview. The SDK finds that
attachment in the event, picks the key for the message's version from the
map, and derives the file's key: newer clients encrypt each attachment under
its own key derived from the message, and older messages encrypt media under
the conversation key. Everything comes from these values, so any instance can
decrypt any file at any time, before or after the message itself. Signatures
are not checked here; use the `verified` flag from `decrypt_event`.

```js
const keys = result.conversationKeys.keys;
const message = chat.decryptEvent({ eventB64, conversationKeys: keys });
for (const { mediaHashKey } of message.mediaHashes ?? []) {
  const encrypted = await downloadMedia(mediaHashKey);
  const plaintext = chat.decryptFile({ encrypted, eventB64, conversationKeys: keys, mediaHashKey });
}
```

**Whole file or incremental.** `encrypt_file` and `decrypt_file` process the
whole file in memory. `file_encryptor` and `file_decryptor` return an
incremental object for large files, so memory stays bounded by the chunk
size: feed chunks with `push`, then call `finish` once. The encryptor's
`finish` emits the final frame, without which the file does not decrypt. The
decryptor's `finish` errors if the file ended before its final frame
(truncation detection), so output from `push` must not be treated as complete
until `finish` succeeds. The native bindings (Go, JVM, .NET) free the object
via `Close`/`close`/`Dispose`. In JS/WASM, `finish()` consumes and frees the
object; call `free()` only when abandoning a file without finishing it
(calling it after `finish()` throws).

The file calls raise an error that says what to pass instead when:

- (encrypting) `conversation_key_version` is not the message's key version, `conversation_key` is not 32 bytes, or only one of the two is set;
- (decrypting) the key map has no key for the message's version (the error names the version), or an entry is not a 32-byte key;
- `media_hash_key` is empty, or is not one of the message's files (the error lists the media hash keys that are);
- the event is not a message, is an edit, reaction or other entry without files, or is a message with no files;
- (encrypting) `media_hash_key` names media the reply quotes: that file belongs to the quoted message, so there is nothing to encrypt;
- (decrypting) the bytes are not the file's complete encrypted form: another file, corrupted, or truncated;
- (decrypting) the message is not encrypted, so neither is its media: use the downloaded bytes as they are;
- (decrypting) a reply shows quoted media but does not embed the quoted message: pass the quoted message's own event.

### Generic Encrypt / Decrypt

| # | Method | Rust | JS | Python | Go | JVM | .NET |
|---|--------|------|-----|--------|-----|------|------|
| 37 | **encrypt** | `(&str, &Key) → String` | `(string, Uint8Array) → string` | `(str, bytes) → str` | `Encrypt(plaintext string, conversationKey []byte) (string, error)` — returns base64 ciphertext | `encrypt(String, byte[])` → `String` | `Encrypt(string, byte[])` → `string` |
| 38 | **decrypt** | `(&str, &Key) → String` | `(string, Uint8Array) → string` | `(str, bytes) → str` | `Decrypt(ciphertextB64 string, conversationKey []byte) (string, error)` — UTF-8 plaintext | `decrypt(String, byte[])` → `String` | `Decrypt(string, byte[])` → `string` |

Encrypt/decrypt arbitrary UTF-8 strings using XSalsa20-Poly1305 with a conversation key. Use for encrypted metadata fields like `group_name`, `group_avatar_url`, and `group_description` returned by the XChat API.

- `encrypt(plaintext, key)` returns base64-encoded ciphertext
- `decrypt(ciphertext_b64, key)` returns the UTF-8 plaintext

Wire format: `base64(nonce[24B] || poly1305_tag[16B] || ciphertext)` — same as message content encryption.

```typescript
// JS — decrypt group name from API response
const groupName = chat.decrypt(conversation.groupName, conversationKey);
```

```python
# Python
group_name = chat.decrypt(conversation["group_name"], conv_key)
```

### Signing

| # | Method | Rust | JS | Python | Go | JVM | .NET |
|---|--------|------|-----|--------|-----|------|------|
| 39 | **sign** | `(&[u8]) → Vec<u8>` | `(Uint8Array) → Uint8Array` | `(bytes) → bytes` | `Sign(data []byte) ([]byte, error)` | `sign(byte[])` → `byte[]` | `Sign(byte[])` → `byte[]` |
| 40 | **verify** | `(pk_b64, &[u8] sig, &[u8] data) → bool` | `(pk_b64, Uint8Array sig, Uint8Array data) → boolean` | `(pk_b64, bytes sig, bytes data) → bool` | `Verify(publicKeyB64 string, signature, data []byte) (bool, error)` | `verify(String publicKeyB64, byte[] signature, byte[] data)` | `Verify(string publicKeyB64, byte[] signature, byte[] data)` |
| 41 | **verify_key_binding** | `(identity_b64, signing_b64, sig_b64) → bool` | `verifyKeyBinding(identityB64, signingB64, sigB64) → boolean` | `verify_key_binding(identity_b64, signing_b64, sig_b64) → bool` | `VerifyKeyBinding(identityB64, signingB64, sigB64 string) (bool, error)` | `verifyKeyBinding(String, String, String)` | `VerifyKeyBinding(string, string, string)` |
| 42 | **matches_registered_key** | `(public_key_b64) → bool` | `matchesRegisteredKey(publicKeyB64) → boolean` | `matches_registered_key(public_key_b64) → bool` | `MatchesRegisteredKey(publicKeyB64 string) (bool, error)` | `matchesRegisteredKey(String)` | `MatchesRegisteredKey(string)` |

Conversation-key changes, group creates, and group member-adds are signed by the
one-call prepare methods (`prepare_conversation_key_change`,
`prepare_group_create`, `prepare_group_members_change`), which return the
`actionSignatures` ready to POST. Group create and member-add each return two
signatures (a conversation-key change plus the group change). Message deletes
and read receipts are signed by `prepare_message_delete` and
`prepare_mark_conversation_read`, which each return a `PreparedAction` with
one entry in its `actionSignatures`.

### Utilities

Common helpers exported as module-level functions (Rust crate root / JS module / Python module / **Go `chatxdk` package** / **JVM and .NET `ChatXdkUtilities` classes**):

| # | Function | Rust | JS | Python | Go | JVM | .NET |
|---|----------|------|-----|--------|-----|------|------|
| 43 | **bytes_to_base64** | `(&[u8]) → String` | `bytesToBase64(Uint8Array) → string` | `bytes_to_base64(bytes) → str` | `BytesToBase64(data []byte) (string, error)` | `ChatXdkUtilities.bytesToBase64(byte[])` | `ChatXdkUtilities.BytesToBase64(ReadOnlySpan<byte>)` |
| 44 | **base64_to_bytes** | `(&str) → Option<Vec<u8>>` | `base64ToBytes(string) → Uint8Array?` | `base64_to_bytes(str) → bytes?` | `Base64ToBytes(b64 string) ([]byte, error)` | `ChatXdkUtilities.base64ToBytes(String)` | `ChatXdkUtilities.Base64ToBytes(string)` |
| 45 | **bytes_to_hex** | `(&[u8]) → String` | `bytesToHex(Uint8Array) → string` | `bytes_to_hex(bytes) → str` | `BytesToHex(data []byte) (string, error)` | `ChatXdkUtilities.bytesToHex(byte[])` | `ChatXdkUtilities.BytesToHex(ReadOnlySpan<byte>)` |
| 46 | **hex_to_bytes** | `(&str) → Option<Vec<u8>>` | `hexToBytes(string) → Uint8Array?` | `hex_to_bytes(str) → bytes?` | `HexToBytes(hex string) ([]byte, error)` | `ChatXdkUtilities.hexToBytes(String)` | `ChatXdkUtilities.HexToBytes(string)` |
| 47 | **detect_mime_type** | `(&[u8]) → Option<&str>` | `detectMimeType(Uint8Array) → string?` | `detect_mime_type(bytes) → str?` | `DetectMimeType(data []byte) (mime string, err error)` — empty string if unknown | `ChatXdkUtilities.detectMimeType(byte[])` → `String` or `null` | `ChatXdkUtilities.DetectMimeType(ReadOnlySpan<byte>)` → `string?` |
| 48 | **detect_image_dimensions** | `(&[u8]) → Option<ImageDimensions>` | `detectImageDimensions(Uint8Array) → {width, height}?` | `detect_image_dimensions(bytes) → (w, h)?` | `DetectImageDimensions(data []byte) (*ImageDimensions, error)` — nil if unknown | `ChatXdkUtilities.detectImageDimensions(byte[])` → `ImageDimensions` or `null` | `ChatXdkUtilities.DetectImageDimensions(ReadOnlySpan<byte>)` → `ImageDimensions?` |
| 49 | **encrypted_file_size** | `(plaintext_size: u64) → Option<u64>` | `encryptedFileSize(plaintextSize: number) → number` | `encrypted_file_size(plaintext_size: int) → int` | `EncryptedFileSize(plaintextSize uint64) (uint64, error)` | `ChatXdkUtilities.encryptedFileSize(long)` → `long` | `ChatXdkUtilities.EncryptedFileSize(ulong)` → `ulong` |

`encrypted_file_size` returns the exact byte length that `encrypt_file` or
`file_encryptor` will produce, without encrypting or requiring a key:
`24 + plaintext_size + 17 × ceil(plaintext_size / 1024)` for non-empty input,
and `24` for empty input. Use it for the upload's `total_bytes`, which the
upload needs before the file is encrypted.

**Failure modes differ by binding.** On undecodable input,
`base64_to_bytes` / `hex_to_bytes` return `None` (Rust `Option`), `undefined`
(JS), and `None` (Python), while Go returns a non-nil `error` and .NET/JVM
throw `ChatXdkException` (`"Invalid base64"` / `"Invalid hex"`). For an
unrecognized file type, `detect_mime_type` returns `None`/`undefined`/`null`
in Rust/JS/Python/.NET/JVM, but Go returns `("", nil)` — an empty string with
no error. Match on the failure convention of the binding you are using when
porting code.

```typescript
// JS/TS example
import { bytesToBase64, detectMimeType, detectImageDimensions } from '@xdevplatform/chat-xdk';

const b64 = bytesToBase64(new Uint8Array([1, 2, 3]));  // "AQID"
const mime = detectMimeType(imageBytes);               // "image/png"
const dims = detectImageDimensions(imageBytes);        // { width: 1024, height: 768 }
```

```python
# Python example
from chat_xdk import bytes_to_base64, detect_mime_type, detect_image_dimensions

b64 = bytes_to_base64(b"\x01\x02\x03")  # "AQID"
mime = detect_mime_type(image_bytes)     # "image/png"
dims = detect_image_dimensions(image_bytes)  # (1024, 768)
```

```go
// Go example (package chatxdk)
import "github.com/xdevplatform/chat-xdk/go/chatxdk"

b64, _ := chatxdk.BytesToBase64([]byte{1, 2, 3}) // "AQID"
mime, _ := chatxdk.DetectMimeType(imageBytes)   // "image/png" or "" if unknown
dims, _ := chatxdk.DetectImageDimensions(imageBytes) // non-nil *ImageDimensions or nil
```

```java
// JVM — static helpers on ChatXdkUtilities
import com.x.chatxdk.ChatXdkUtilities;
import com.x.chatxdk.Types.ImageDimensions;

String b64 = ChatXdkUtilities.bytesToBase64(new byte[] { 1, 2, 3 }); // "AQID"
String mime = ChatXdkUtilities.detectMimeType(imageBytes);           // "image/png" or null
ImageDimensions dims = ChatXdkUtilities.detectImageDimensions(imageBytes);
```

```csharp
// .NET — static helpers on ChatXdkUtilities
using ChatXdk;

string b64 = ChatXdkUtilities.BytesToBase64(new byte[] { 1, 2, 3 }); // "AQID"
string? mime = ChatXdkUtilities.DetectMimeType(imageBytes);          // "image/png" or null
ImageDimensions? dims = ChatXdkUtilities.DetectImageDimensions(imageBytes);
```

**Supported MIME types**: PNG, JPEG, GIF, WebP, BMP, TIFF, ICO, HEIC, AVIF, MP4, WebM, AVI, MOV, PDF, ZIP, MP3, WAV, OGG, FLAC.

**Supported image dimensions**: PNG, JPEG, GIF, WebP, BMP.

---

## Quick Start

### JavaScript/WASM

First boot — `juicebox_config` is created by `POST /2/users/{id}/public_keys`,
so a brand-new user creates the chat without one:

```typescript
import { createChat } from '@xdevplatform/chat-xdk';

const chat = await createChat({
  getAuthToken: async (realmId) => await backend.getToken(realmId),
});
const payload = chat.generateKeypairs();
// … POST payload to /2/users/{id}/public_keys, GET juicebox_config back …
chat.updateConfig(configJson);
await chat.setup("2580");
```

Later sessions — the account is provisioned:

```typescript
import { createChat } from '@xdevplatform/chat-xdk';

const chat = await createChat({
  juiceboxConfig: configJson,
  getAuthToken: async (realmId) => await backend.getToken(realmId),
});
await chat.unlock("2580");

// ── Set the session once ──
// Identity (sender + signing-key version), signing keys for all
// participants, and the opt-in conversation-key cache.
chat.setIdentity({ userId: myUserId, signingKeyVersion: mySigningKeyVersion });
chat.setCacheKeys(true);
chat.setSigningKeys([
  { userId: "111", publicKeyVersion: "1", publicKey: "BASE64...", identityPublicKey: "BASE64...", identityPublicKeySignature: "BASE64..." },
  { userId: "222", publicKeyVersion: "1", publicKey: "BASE64...", identityPublicKey: "BASE64...", identityPublicKeySignature: "BASE64..." },
]);

// ── Initial load: use decryptEvents ──
// The SDK extracts conversation keys, matches signing keys automatically,
// and (with the cache on) retains each conversation's latest verified key.
const result = chat.decryptEvents({ events: rawEvents });

for (const dm of result.messages) {
  if (dm.event.type === "message") {
    console.log(dm.event.senderId, dm.event.content.text);
  }
}

// ── New event arrives (webhook / poll): use decryptEvent ──
// The empty key map and unset signing keys resolve from the key cache and
// the signing-key store.
const event = chat.decryptEvent({ eventB64: webhookEventB64 });
if (event.type === "message") {
  console.log(event.content.text);
}

// ── Send: identity and conversation key resolve from the session ──
const payload = chat.encryptMessage({ conversationId: event.conversationId, text: "hi!" });
const reply = chat.encryptReply({
  conversationId: event.conversationId,
  text: "pong",
  replyToEvent: webhookEventB64, // preview derived + embedded for validation
});
const reaction = chat.encryptAddReaction({ emoji: "👍", targetEvent: webhookEventB64 });

// ── Metadata (group name, avatar, description) ──
const groupName = chat.decrypt(conversation.groupName, convKey);

// ── Files (whole file): the message's event, its key map, the media hash key ──
const keys = result.conversationKeys.keys;
const mediaHashKey = event.mediaHashes[0].mediaHashKey;
const decrypted: Uint8Array = chat.decryptFile({
  encrypted: encryptedBytes,
  eventB64: webhookEventB64,
  conversationKeys: keys,
  mediaHashKey,
});

// ── Files (incremental, for large files) ──
// Decrypt chunk-by-chunk as bytes arrive, e.g. from a fetch() body stream,
// without holding the whole file in memory.
const dec = chat.fileDecryptor({ eventB64: webhookEventB64, conversationKeys: keys, mediaHashKey });
const reader = response.body.getReader();
const parts: Uint8Array[] = [];
for (;;) {
  const { done, value } = await reader.read();
  if (done) break;
  parts.push(dec.push(value));
}
// finish() consumes and frees the decryptor (do not call free() after it);
// it throws if the file was truncated.
parts.push(dec.finish());

// ── Send a file: build the message first, then encrypt the file from it ──
// newMediaHashKey comes from starting the upload with encryptedFileSize(photo.length).
const photoMessage = chat.encryptMessage({
  conversationId: event.conversationId,
  text: "a photo",
  attachments: [{ attachment_type: "media", media_hash_key: newMediaHashKey, width, height, filesize_bytes: encryptedFileSize(photo.length), filename: "photo.jpg", media_type: 1 }],
});
const encryptedPhoto = chat.encryptFile({
  file: photo,
  eventB64: photoMessage.eventB64,
  mediaHashKey: newMediaHashKey,
});
// … finish the upload with encryptedPhoto, then send photoMessage …
```

### Python

```python
from chat_xdk import (
    Chat,
    DecryptEventParams,
    DecryptEventsParams,
    DecryptFileParams,
    EncryptFileParams,
    EncryptMessageParams,
    EncryptReactionParams,
    EncryptReplyParams,
    SetIdentityParams,
    encrypted_file_size,
)

chat = Chat(config_json)
chat.unlock("2580")

# ── Set the session once ──
chat.set_identity(SetIdentityParams(my_user_id, my_signing_key_version))
chat.set_cache_keys(True)
chat.set_signing_keys(signing_keys)  # all participants

# ── Initial load: use decrypt_events ──
result = chat.decrypt_events(DecryptEventsParams(raw_events))
for dm in result["messages"]:
    if dm["event"]["type"] == "Message":
        print(dm["event"]["sender_id"], dm["event"]["content"]["text"])

# ── New event arrives: use decrypt_event ──
# The empty key map and unset signing keys resolve from the key cache and
# the signing-key store.
event = chat.decrypt_event(DecryptEventParams(event_b64))
if event["type"] == "Message":
    print(event["content"]["text"])

# ── Send: identity and conversation key resolve from the session ──
payload = chat.encrypt_message(EncryptMessageParams(event["conversation_id"], "hi!"))
reply = chat.encrypt_reply(EncryptReplyParams(event["conversation_id"], "pong", event_b64))
reaction = chat.encrypt_add_reaction(EncryptReactionParams(event_b64, "👍"))

# ── Metadata (group name, avatar, description) ──
group_name = chat.decrypt(conversation["group_name"], conv_key)

# ── Files: the message's event, its key map, the media hash key ──
keys = result["conversation_keys"]["keys"]
media_hash_key = event["media_hashes"][0]["media_hash_key"]
decrypted = chat.decrypt_file(DecryptFileParams(encrypted_bytes, event_b64, keys, media_hash_key))

# ── Send a file: build the message first, then encrypt the file from it ──
# new_media_hash_key comes from starting the upload with encrypted_file_size(len(photo)).
photo_message = chat.encrypt_message(
    EncryptMessageParams(
        event["conversation_id"],
        "a photo",
        attachments=[{
            "attachment_type": "media",
            "media_hash_key": new_media_hash_key,
            "width": width,
            "height": height,
            "filesize_bytes": encrypted_file_size(len(photo)),
            "filename": "photo.jpg",
            "media_type": 1,
        }],
    )
)
encrypted_photo = chat.encrypt_file(
    EncryptFileParams(photo, photo_message.event_b64, new_media_hash_key)
)
# … finish the upload with encrypted_photo, then send photo_message …
```

### Go

```go
import (
    "fmt"

    "github.com/xdevplatform/chat-xdk/go/chatxdk"
)

func main() {
    chat := chatxdk.New()
    defer chat.Close()

    _ = chat.Unlock([]byte("2580"), juiceboxConfigJSON)

    // ── Set the session once ──
    chat.SetIdentity(chatxdk.SetIdentityParams{UserID: myUserID, SigningKeyVersion: mySigningKeyVersion})
    chat.SetCacheKeys(true)
    _ = chat.SetSigningKeys(signingKeys) // all participants

    // ── Initial load: use DecryptEvents (unset SigningKeys = stored signing keys) ──
    result, err := chat.DecryptEvents(chatxdk.DecryptEventsParams{Events: rawEvents})
    if err != nil {
        panic(err)
    }
    for _, dm := range result.Messages {
        if dm.Event.Type == "Message" {
            fmt.Println(dm.Event.AsMessage().Text())
        }
    }

    // ── New event arrives: use DecryptEvent ──
    // The empty key map and unset signing keys resolve from the key cache
    // and the signing-key store.
    event, err := chat.DecryptEvent(chatxdk.DecryptEventParams{EventB64: eventB64})
    if err != nil {
        panic(err)
    }
    msg := event.AsMessage() // nil unless event.Type == "Message"
    if msg != nil {
        fmt.Println(msg.Text())
    }

    // ── Send: identity and conversation key resolve from the session ──
    payload, err := chat.EncryptMessage(chatxdk.EncryptMessageParams{
        ConversationID: *msg.ConversationID,
        Text:           "hi!",
    })
    if err != nil {
        panic(err)
    }
    _ = payload
    reply, _ := chat.EncryptReply(chatxdk.EncryptReplyParams{
        ConversationID: *msg.ConversationID,
        Text:           "pong",
        ReplyToEvent:   eventB64, // preview derived + embedded for validation
    })
    _ = reply
    reaction, _ := chat.EncryptAddReaction(chatxdk.EncryptReactionParams{
        Emoji:       "👍",
        TargetEvent: eventB64,
    })
    _ = reaction

    // Raw 32-byte conversation key for the metadata call below,
    // e.g. from DecryptConversationKey or result.ConversationKeys.Keys.
    convKey := result.ConversationKeys.Keys[keyVersion]

    // ── Metadata (group name, avatar, description) ──
    groupName, err := chat.Decrypt(conversationGroupNameB64, convKey)
    _ = groupName

    // ── Files: the message's event, its key map, the media hash key ──
    // Raw bytes in, raw bytes out.
    decrypted, err := chat.DecryptFile(chatxdk.DecryptFileParams{
        Encrypted:        encryptedMedia,
        EventB64:         eventB64,
        ConversationKeys: result.ConversationKeys.Keys,
        MediaHashKey:     msg.MediaHashes[0].MediaHashKey,
    })
    _ = decrypted

    // ── Send a file: build the message first, then encrypt the file from it ──
    // newMediaHashKey comes from starting the upload with EncryptedFileSize.
    size, _ := chatxdk.EncryptedFileSize(uint64(len(photo)))
    mediaType := int32(1)
    photoMessage, err := chat.EncryptMessage(chatxdk.EncryptMessageParams{
        ConversationID: *msg.ConversationID,
        Text:           "a photo",
        Attachments: []chatxdk.AttachmentDescriptor{{
            AttachmentType: "media",
            MediaHashKey:   newMediaHashKey,
            Width:          width,
            Height:         height,
            FilesizeBytes:  int64(size),
            Filename:       "photo.jpg",
            MediaType:      &mediaType,
        }},
    })
    if err != nil {
        panic(err)
    }
    encryptedPhoto, err := chat.EncryptFile(chatxdk.EncryptFileParams{
        File:         photo,
        EventB64:     photoMessage.EventB64,
        MediaHashKey: newMediaHashKey,
    })
    _ = encryptedPhoto // … finish the upload with it, then send photoMessage …
}
```

### Rust

```rust
use std::collections::HashMap;

use chat_xdk_core::keys::juicebox::JuiceboxConfig;
use chat_xdk_core::{
    AttachmentDescriptor, Chat, DecryptEventParams, DecryptEventsParams, DecryptFileParams,
    EncryptFileParams, EncryptMessageParams, EncryptReactionParams, EncryptReplyParams, Event,
};

let config = JuiceboxConfig::from_json(config_json);
let chat = Chat::new(config);
chat.unlock(b"2580").await?;

// ── Set the session once ──
chat.set_identity(&SetIdentityParams::new(my_user_id, my_signing_key_version))?;
chat.set_cache_keys(true);
chat.set_signing_keys(signing_keys); // all participants

// ── Initial load: use decrypt_events (unset signing keys = stored signing keys) ──
let result = chat.decrypt_events(DecryptEventsParams::new(raw_events));
for dm in &result.messages {
    if let Event::Message(msg) = &dm.event {
        println!("{}: {}", msg.meta.sender_id.as_deref().unwrap_or("?"), msg.text().unwrap_or(""));
    }
}

// ── New event arrives: use decrypt_event ──
// The empty key map and unset signing keys resolve from the key cache and
// the signing-key store.
let event = chat.decrypt_event(DecryptEventParams::new(event_b64, HashMap::new()))?;

// ── Send: identity and conversation key resolve from the session ──
let payload = chat.encrypt_message(&EncryptMessageParams::new(conversation_id, "hi!"))?;
let reply = chat.encrypt_reply(&EncryptReplyParams::new(conversation_id, "pong", event_b64))?;
let reaction = chat.encrypt_add_reaction(&EncryptReactionParams::new(event_b64, "👍"))?;

// ── Metadata (group name, avatar, description) ──
let group_name = chat.decrypt(&conversation.group_name, &conv_key)?;

// ── Files: the message's event, its key map, the media hash key ──
// (`media_hash_key` from the decrypted message's `media_hashes`)
let keys = result.conversation_keys.keys.clone();
let decrypted = chat.decrypt_file(DecryptFileParams::new(
    encrypted_bytes,
    event_b64,
    keys.clone(),
    media_hash_key,
))?;

// ── Send a file: build the message first, then encrypt the file from it ──
// `new_media_hash_key` comes from starting the upload with
// `utils::encrypted_file_size(photo.len() as u64)`.
let size = chat_xdk_core::utils::encrypted_file_size(photo.len() as u64).unwrap();
let mut params = EncryptMessageParams::new(conversation_id, "a photo");
params.attachments = Some(vec![AttachmentDescriptor::Media {
    media_hash_key: new_media_hash_key.clone(),
    width,
    height,
    filesize_bytes: size as i64,
    filename: "photo.jpg".to_string(),
    media_type: Some(1),
    duration_millis: None,
}]);
let photo_message = chat.encrypt_message(&params)?;
let encrypted_photo = chat.encrypt_file(&EncryptFileParams::new(
    photo,
    &photo_message.event_b64,
    new_media_hash_key,
))?;
// … finish the upload with encrypted_photo, then send photo_message …
```

### .NET (C#)

Decrypted events are returned as `System.Text.Json.JsonElement` (snake_case property names in the JSON). Use `GetProperty` / `GetString` as in the examples below, or deserialize into your own models.

```csharp
using ChatXdk;

using var chat = new Chat();
chat.UpdateConfig(juiceboxConfigJson);
chat.Unlock(pin, juiceboxConfigJson);

// Set the session once: identity, opt-in key cache, signing-key store.
chat.SetIdentity(new SetIdentityParams(myUserId, mySigningKeyVersion));
chat.SetCacheKeys(true);
chat.SetSigningKeys(signingKeys); // all participants

// Initial load — unset signing keys come from the store.
var result = chat.DecryptEvents(new DecryptEventsParams(rawEvents));
foreach (var dm in result.Messages)
{
    if (dm.Event.GetProperty("type").GetString() == "Message")
        Console.WriteLine(dm.Event.GetProperty("content").GetProperty("text").GetString());
}

// Single event — the empty key map and unset signing keys resolve from the session stores.
var evt = chat.DecryptEvent(new DecryptEventParams(webhookB64, new Dictionary<string, byte[]>()));
var conversationId = evt.GetProperty("conversation_id").GetString()!;

// Send: identity and conversation key resolve from the session.
var payload = chat.EncryptMessage(new EncryptMessageParams(conversationId, "hi!"));
// Preview derived from + embedded raw event for validation.
var reply = chat.EncryptReply(new EncryptReplyParams(conversationId, "pong", webhookB64));
var reaction = chat.EncryptAddReaction(new EncryptReactionParams(webhookB64, "👍"));

var groupName = chat.Decrypt(conversationGroupNameB64, convKeyBytes);

// Files: the message's event, its key map, the media hash key.
var keys = result.ConversationKeys.Keys;
var mediaHashKey = evt.GetProperty("media_hashes")[0].GetProperty("media_hash_key").GetString()!;
var mediaPlain = chat.DecryptFile(
    new DecryptFileParams(encryptedMediaBytes, webhookB64, keys, mediaHashKey));

// Send a file: build the message first, then encrypt the file from it.
// newMediaHashKey comes from starting the upload with EncryptedFileSize.
var size = ChatXdkUtilities.EncryptedFileSize((ulong)photo.Length);
var photoMessage = chat.EncryptMessage(new EncryptMessageParams(conversationId, "a photo")
{
    Attachments = new[]
    {
        AttachmentDescriptor.Media(newMediaHashKey, width, height, (long)size, "photo.jpg", 1),
    },
});
var encryptedPhoto = chat.EncryptFile(
    new EncryptFileParams(photo, photoMessage.EventB64, newMediaHashKey));
// … finish the upload with encryptedPhoto, then send photoMessage …
```

```bash
make dotnet-build
make dotnet-test
```

Stateless helpers: `ChatXdkUtilities.BytesToBase64`, `DetectMimeType`, etc. (`crates/dotnet/README.md`).

### JVM

`com.x.chatxdk` — same native `chat_xdk_dotnet` cdylib as .NET, via JNA. Use **`try-with-resources`** on `Chat` (implements `AutoCloseable`). Stateless helpers live on **`ChatXdkUtilities`**.

```java
import com.fasterxml.jackson.databind.JsonNode;
import com.x.chatxdk.*;
import com.x.chatxdk.Types.*;

import java.util.List;
import java.util.Map;

try (Chat chat = new Chat()) {
    chat.unlock("2580", juiceboxConfigJson);

    // Set the session once: identity, opt-in key cache, signing-key store.
    chat.setIdentity(new SetIdentityParams(myUserId, mySigningKeyVersion));
    chat.setCacheKeys(true);
    chat.setSigningKeys(signingKeys); // all participants

    // Initial load — unset (null) signing keys fall back to the store
    DecryptEventsResult batch = chat.decryptEvents(new DecryptEventsParams(rawEvents));
    for (DecryptedMessage dm : batch.messages) {
        JsonNode evt = dm.event;
        if (evt != null && "Message".equals(evt.path("type").asText())) {
            String text = evt.path("content").path("text").asText();
            // …
        }
    }

    // Single event — the empty key map and unset signing keys resolve from the session stores
    JsonNode event = chat.decryptEvent(new DecryptEventParams(eventB64, Map.of()));
    String conversationId = event.path("conversation_id").asText();

    // Send: identity and conversation key resolve from the session
    SendPayload payload =
            chat.encryptMessage(new EncryptMessageParams(conversationId, "hi!"));
    // Preview derived from + embedded raw event for validation.
    SendPayload reply =
            chat.encryptReply(new EncryptReplyParams(conversationId, "pong", eventB64));
    SendPayload reaction =
            chat.encryptAddReaction(new EncryptReactionParams(eventB64, "👍"));

    // Files: the message's event, its key map, the media hash key
    Map<String, byte[]> keys = batch.conversationKeys.keys;
    String mediaHashKey = event.path("media_hashes").path(0).path("media_hash_key").asText();
    byte[] media = chat.decryptFile(
            new DecryptFileParams(encryptedMediaBytes, eventB64, keys, mediaHashKey));

    // Send a file: build the message first, then encrypt the file from it.
    // newMediaHashKey comes from starting the upload with encryptedFileSize.
    long size = ChatXdkUtilities.encryptedFileSize(photo.length);
    EncryptMessageParams photoParams = new EncryptMessageParams(conversationId, "a photo");
    photoParams.attachments = List.of(
            AttachmentDescriptor.media(newMediaHashKey, width, height, size, "photo.jpg", 1, null));
    SendPayload photoMessage = chat.encryptMessage(photoParams);
    byte[] encryptedPhoto = chat.encryptFile(
            new EncryptFileParams(photo, photoMessage.eventB64, newMediaHashKey));
    // … finish the upload with encryptedPhoto, then send photoMessage …
}
```

```bash
# From repo root (see crates/jvm/README.md)
make jvm-test
```

---

## Types

### PublicKeys

Returned by `setup()` and `get_public_keys()`.

```typescript
interface PublicKeys {
  identity: string;  // Base64-encoded identity public key (P-256 SEC1)
  signing: string;   // Base64-encoded signing public key (P-256 SEC1)
  version?: string;  // Key version identifier (may be empty)
}
```

```python
# Python — same fields: .identity, .signing, .version (str; may be "")
```

### PublicKeyRegistrationPayload

Returned by `generate_keypairs()`. POST this to the X API, then call
`set_identity` with the `public_key_version` the response returns.

```typescript
// JS/WASM — camelCase. Non-JS bindings (Python/Go/.NET/JVM) use the
// snake_case wire names (public_key, identity_public_key_signature, …).
interface PublicKeyRegistrationPayload {
  publicKey: {
    identityPublicKeySignature: string;   // Raw r||s ECDSA signature
    publicKey: string;                    // Base64 SPKI-encoded identity key
    publicKeyFingerprint?: string;        // URL-safe base64 SHA-256 of SPKI key
    registrationMethod: string;           // "CustomPin"
    signingPublicKey: string;             // Base64 SPKI-encoded signing key
    signingPublicKeySignature?: string;
  };
}
```

The `publicKeyFingerprint` (`public_key_fingerprint` on non-JS bindings) is `URL_SAFE_NO_PAD(SHA-256(SPKI_bytes))` — a 43-character string users can compare out-of-band to verify key authenticity. Also available via `get_public_key_fingerprint()` at any time after keys are loaded.

### Event

Returned by `decrypt_event()` and `decrypt_events()`. Uses `type` field to distinguish variants.

> **Casing differs by platform:**
> - **JS/WASM**: camelCase types and fields — `"message"`, `senderId`
> - **Python**: PascalCase types, snake_case fields — `"Message"`, `sender_id`
> - **.NET** (`JsonElement` from `DecryptEvent` / `DecryptEvents`): same JSON as Go/Rust FFI — PascalCase `type` strings (`"Message"`, `"KeyChange"`, …) and snake_case field names (`sender_id`, `conversation_id`, …).
> - **JVM**: Native JSON from `decryptEvent` / `DecryptEventsResult` uses **snake_case** fields (e.g. `"Message"`, `sender_id`) — inspect with Jackson `JsonNode` or bind to POJOs with `@JsonProperty` if you prefer camelCase in your code.
>
> ⚠️ **JS is the only binding that camelCases enum discriminator *values***,
> not just field names: `type: 'message' | 'keyChange' | …`,
> `contentType: 'text' | 'reactionRemoved' | …`,
> `attachmentType: 'unifiedCard'`, failure `'internalError'`. Every other
> binding uses PascalCase values (`"Message"`, `"KeyChange"`, `"Text"`,
> `"UnifiedCard"`, `"InternalError"`). **Porting warning:** code that
> switches on these strings must be re-cased when moved to or from JS —
> a comparison like `event.type === "Message"` silently never matches in JS.

```typescript
// JS/WASM — all camelCase
interface Event {
  type: 'message' | 'keyChange' | 'groupChange' |
        'messageDeleted' | 'conversationDeleted' |
        'typing' | 'readReceipt' | 'markedUnread' |
        'failure' | 'settingsChange' | 'memberDeleted' | 'unknown';
  // Meta fields are flattened to top level:
  sequenceId?: string;
  id?: string;
  senderId?: string;
  conversationId?: string;
  createdAtMsec?: number;
  // Additional fields depend on type (see below)
}
```

```python
# Python — PascalCase types, snake_case fields
event["type"]            # "Message", "KeyChange", etc.
event["sequence_id"]     # str
event["sender_id"]       # str
event["conversation_id"] # str
event["created_at_msec"] # int
```

### Message

The payload when `type` is `"message"` (JS) / `"Message"` (Python).

```typescript
// JS/WASM
interface MessageEvent {
  type: 'message';
  sequenceId?: string;
  id?: string;
  senderId?: string;
  conversationId?: string;
  createdAtMsec?: number;
  content: MessageContent;
  keyVersion?: string;          // null for unencrypted messages
  verified: boolean;            // always false for unencrypted messages
  shouldNotify?: boolean;
  ttlMsec?: number;
  attachments?: AttachmentInfo[];
  mediaHashes?: MediaHashReference[];
  replyPreviewValidation?: 'valid' | 'invalid';  // absent when no preview /
                                                 // preview embeds no raw event
}
```

```python
# Python
event["content"]       # dict
event["key_version"]   # str or None
event["verified"]      # bool
event["attachments"]   # list[dict]
event["media_hashes"]  # list[dict]
event["reply_preview_validation"]  # "Valid" or "Invalid"; absent when no
                                   # preview / preview embeds no raw event
```

**Reply preview validation**: when a decrypted message carries a reply
preview that embeds the raw signed original event, the SDK verifies that
event's signature, decrypts it, and compares the preview's claims against the
original; the outcome is reported in `reply_preview_validation`. The field's
values are `"Valid"`/`"Invalid"` in Rust/Python/Go/.NET/JVM; the JS type layer
camelCases them to `'valid'`/`'invalid'`. It is **absent** when the message
carries no preview or the preview embeds no raw event. Treat `Invalid` (and
absent-on-a-preview) as an untrusted preview — render the claim only from the
validated original. The validation contract is specified in
[CRYPTO.md — Reply preview validation](CRYPTO.md#reply-preview-validation).

**Unencrypted messages**: When `keyVersion` is `null`, the message was delivered without encryption. Because there is no signature to verify, the default reject-unverified policy **rejects** these messages (`decryptEvent` throws; `decryptEvents` records them in `errors`); they are returned only after `setRejectUnverified(false)`, with `verified: false`. When returned, the `content` is parsed identically to encrypted messages.

### MessageContent

The `content` field of a Message. Uses `contentType` (JS) / `content_type` (Python) for discrimination.

```typescript
// JS/WASM
type MessageContent =
  | { contentType: 'text';
      text: string;
      entities?: RichTextEntity[];
      attachments?: MessageAttachment[];
      replyingToPreview?: ReplyingToPreview;
      forwardedMessage?: ForwardedMessage;
      sentFrom?: SentFromSurface;
      quickReply?: QuickReply;
      ctas?: CallToAction[];
    }
  | { contentType: 'reaction'; emoji: string; targetMessageId: string }
  | { contentType: 'reactionRemoved'; emoji: string; targetMessageId: string }
  | { contentType: 'edit'; targetMessageId: string; newText: string; entities?: RichTextEntity[] }
  | { contentType: 'markRead' }
  | { contentType: 'markUnread' }
  | { contentType: 'unknown'; typeId?: number };
```

For reactions and edits, `targetMessageId` is the message **sequenceId**.

### SendPayload

Returned by `encrypt_message()` and all `encrypt_*()` methods. The fields the
send request takes carry its names: send `message_id`,
`encoded_message_create_event` and `encoded_message_event_signature` as they
are (JS returns them camelCased, as `messageId`,
`encodedMessageCreateEvent` and `encodedMessageEventSignature`).

The SDK generates the `message_id` (a UUID) and embeds it in the signed
event: derived from its files for a v1 message with files (see
[Message Encryption](#message-encryption)), random otherwise. Send it as
the message's `message_id`, keep it to dedup and to anchor replies, and reuse
the same encrypted payload on retries so a message is never sent twice under
two ids.

`event_b64` is the outgoing message as a base64 event — what recipients
receive, without the fields the server adds on delivery. Pass it to
`encrypt_file` / `file_encryptor` to encrypt the message's files. It is not a
field of the send request.

`xdk_version` is the version of the SDK that built the payload.

```rust
// Rust
pub struct SendPayload {
    pub message_id: String,              // UUID, also embedded in the signed event
    pub event_b64: String,               // the outgoing message as a base64 event
    pub encoded_message_create_event: String,    // Base64-encoded Thrift MessageCreateEvent
    pub signature: String,                       // Base64-encoded ECDSA signature
    pub encoded_message_event_signature: String, // Base64-encoded Thrift MessageEventSignature
    pub signature_info: SignatureInfo,   // { public_key_version, signature_version: "7" (v0) or "10" (v1) }
    pub conversation_key_version: String,
    pub should_notify: bool,
    pub xdk_version: String,             // SDK version
}

// Python (SendPayload class attributes)
// message_id: str
// event_b64: str
// encoded_message_create_event: str
// signature: str
// encoded_message_event_signature: str
// signature_info: SignatureInfo
// conversation_key_version: str
// should_notify: bool
// xdk_version: str
```

### EntityDescriptor (Rust, .NET, JVM) / EntityTuple (Go, JS) / tuple (Python)

Describes a rich-text entity to embed in a message. The `start` and `end` byte offsets refer to positions within the message text. Rust, .NET, and JVM expose an `EntityDescriptor` struct/class; Go and JS use an `EntityTuple` (`[start, end, type]`); Python takes plain `(start, end, entity_type)` tuples.

```rust
// Rust
pub struct EntityDescriptor {
    pub start: i32,          // Start byte offset in the message text
    pub end: i32,            // End byte offset in the message text
    pub entity_type: String, // One of the types below, e.g. "url", "mention"
}
```

```typescript
// JS: EntityTuple = [start, end, type]
const entities: EntityTuple[] = [[0, 23, 'url'], [25, 30, 'mention']];
```

```python
# Python: represented as a tuple (start: int, end: int, entity_type: str)
# Example: [(0, 23, "url"), (25, 30, "mention")]
```

Supported entity types:

| Type | Description |
|------|-------------|
| `"url"` | A URL in the message text |
| `"mention"` | An @mention in the message text |
| `"hashtag"` | A #hashtag in the message text |
| `"cashtag"` | A $cashtag in the message text |
| `"email"` | An email address in the message text |
| `"address"` | A physical address in the message text |
| `"phone_number"` | A phone number in the message text (the camelCase spelling `"phoneNumber"` is accepted too) |

Both the `"phone_number"` and `"phoneNumber"` spellings are accepted by every
binding (the conversion happens in core). **Unrecognized entity-type tokens
are silently dropped** — the message encrypts without that entity and no
error is raised — so double-check tokens when porting entity lists between
bindings.

### AttachmentDescriptor (send side)

Describes an attachment to embed when encrypting a message
(`encrypt_message`/`encrypt_reply`). Lists mixing attachment types are
temporarily rejected on encrypt — only image/gif/video media may appear in
multiples (up to 10); everything else must be the sole attachment (see the
note under `encrypt_message` above). Unlike most types, the field names stay
**snake_case in every binding** — they mirror the wire protocol, so the same
object shape passes through JS, Python dicts, and the Go/JVM/.NET structs
(which add their own idiomatic casing on the struct fields but serialize to
the snake_case keys below).

```typescript
type AttachmentDescriptor =
  | { attachment_type: 'media'; media_hash_key: string; width: number; height: number; filesize_bytes: number; filename: string; media_type?: number; duration_millis?: number }
  | { attachment_type: 'url'; url: string; display_title?: string; banner_image?: UrlAttachmentImageDescriptor; favicon_image?: UrlAttachmentImageDescriptor }
  | { attachment_type: 'post'; rest_id?: string; post_url?: string };

interface UrlAttachmentImageDescriptor {
  media_hash_key: string;   // the media hash key the image's upload started with
  filesize_bytes: number;   // encrypted size: encryptedFileSize(image size)
  filename: string;         // receivers key their decrypted-file cache on it
  width?: number;
  height?: number;
}
```

`media_hash_key`, `filesize_bytes`, and `filename` are all **required**:
first-party clients share an ingest path that silently discards the whole
preview image when any of the three is missing on the wire, so an optional
field here would be an invisible no-banner failure for callers. `width`/
`height` are optional and currently ignored by receiving clients (emitted
for wire fidelity).

**URL cards ("clickable images").** A `url` attachment with only a `url`
renders as a bare link on some clients: clients only auto-fetch missing card
details for their *own* messages (an IP-leak guard), so previews for received
messages must be embedded by the sender. To make every client render a full
clickable preview card, hydrate the card yourself:

1. Fetch/render your preview image (e.g. the page's OpenGraph image).
2. Start its upload to the conversation's media store
   (`POST /2/chat/media/upload/initialize`, with `total_bytes` set to
   `encryptedFileSize` of the image's size) and keep the returned
   `media_hash_key`.
3. Reference it as `banner_image` (plus a `display_title`) on the `url`
   attachment, with the encrypted size as `filesize_bytes` and the image's
   `filename`, and encrypt the message.
4. Encrypt the image with `encryptFile`/`fileEncryptor` from the payload's
   `eventB64` and the image's `media_hash_key`, finish its upload
   (`append` → `finalize`), and send the message.

Receivers see the image hashes on the decrypted message (`AttachmentInfo`
`bannerImageMediaHashKey` and `media_hashes` entries with source
`"url_banner"`/`"url_favicon"`), download them, and pass the message's event,
key map and image hash key to `decryptFile` like any media attachment. Keep
banners small (a few hundred KB): clients honor data-usage thresholds when
deciding whether to auto-load media.

Rust, .NET, and JVM expose typed variants/factories
(`AttachmentDescriptor::Url { … }`, `AttachmentDescriptor.UrlCard(url,
displayTitle, bannerImage, faviconImage)`, `Types.AttachmentDescriptor
.urlCard(url, displayTitle, bannerImage, faviconImage)`); Go uses the flat
`AttachmentDescriptor` struct with `BannerImage`/`FaviconImage` pointer
fields (`URLAttachmentImageDescriptor`); JS and Python pass the plain
object/dict shape above.

### QuickReply

The optional `quick_reply` of `EncryptMessageParams` / `EncryptReplyParams`,
and the `quick_reply` (`quickReply` in JS) of decrypted text content. A
**request** offers selectable options; a **response** reports the option the
user picked. Every binding uses one typed shape for both directions, so a
received value can be passed back to `encrypt_message` / `encrypt_reply`
unchanged. Omitting it sends no quick reply. A value with neither `request`
nor `response`, or with both, fails with an "Invalid quick reply" error.

| Type | Fields |
|------|--------|
| `QuickReply` | exactly one of `request: QuickReplyRequest`, `response: QuickReplyResponse` |
| `QuickReplyRequest` | `options: QuickReplyOptionsRequest` |
| `QuickReplyResponse` | `options: QuickReplyOptionsResponse` |
| `QuickReplyOptionsRequest` | `id?`, `options?: QuickReplyOption[]` |
| `QuickReplyOptionsResponse` | `request_id?`, `metadata?`, `selected_option_id?` |
| `QuickReplyOption` | `id?`, `label?`, `metadata?`, `description?` |

Each binding names these types the same way, in its own idiom:

| Binding | Shape | Field casing |
|---------|-------|--------------|
| Rust | `QuickReply::Request { request }` / `QuickReply::Response { response }` enum | snake_case |
| JS/WASM | `{ request: QuickReplyRequest } \| { response: QuickReplyResponse }` union | camelCase (`requestId`, `selectedOptionId`) |
| Python | `QuickReply` `TypedDict` (and the nested `TypedDict`s), exported from `chat_xdk` | snake_case keys |
| Go | `*chatxdk.QuickReply` struct with `Request` / `Response` pointer fields; `TextContent.QuickReply` decodes into the same type | Go field names, snake_case JSON |
| .NET | `QuickReply` class with `Request` / `Response` properties; decrypted JSON deserializes with `JsonSerializer.Deserialize<QuickReply>` | PascalCase properties, snake_case JSON |
| JVM | `Types.QuickReply` with `request` / `response` fields and `QuickReply.request(...)` / `QuickReply.response(...)` factories; decrypted JSON converts with `ObjectMapper.treeToValue(node, QuickReply.class)` | camelCase fields, snake_case JSON |

```python
from chat_xdk import EncryptMessageParams, QuickReply, QuickReplyOption

# Ask a question with two options...
chat.encrypt_message(EncryptMessageParams(conversation_id, "Continue?", quick_reply=QuickReply(
    request={"options": {"id": "qr-1", "options": [
        QuickReplyOption(id="yes", label="Yes", metadata="m-yes"),
        QuickReplyOption(id="no", label="No", metadata="m-no"),
    ]}},
)))

# ...and answer it.
chat.encrypt_message(EncryptMessageParams(conversation_id, "Yes", quick_reply=QuickReply(
    response={"options": {
        "request_id": "qr-1", "metadata": "m-yes", "selected_option_id": "yes",
    }},
)))
```

```typescript
chat.encryptMessage({
  conversationId,
  text: 'Yes',
  quickReply: { response: { options: { requestId: 'qr-1', metadata: 'm-yes', selectedOptionId: 'yes' } } },
});
```

```go
str := func(s string) *string { return &s }
p := chatxdk.EncryptMessageParams{
    ConversationID: conversationID,
    Text:           "Yes",
    QuickReply: &chatxdk.QuickReply{Response: &chatxdk.QuickReplyResponse{
        Options: chatxdk.QuickReplyOptionsResponse{
            RequestID: str("qr-1"), Metadata: str("m-yes"), SelectedOptionID: str("yes"),
        },
    }},
}
```

```csharp
var p = new EncryptMessageParams(conversationId, "Yes")
{
    QuickReply = new QuickReply
    {
        Response = new QuickReplyResponse
        {
            Options = new QuickReplyOptionsResponse { RequestId = "qr-1", Metadata = "m-yes", SelectedOptionId = "yes" },
        },
    },
};
```

```java
QuickReplyOptionsResponse selected = new QuickReplyOptionsResponse();
selected.requestId = "qr-1";
selected.metadata = "m-yes";
selected.selectedOptionId = "yes";
EncryptMessageParams p = new EncryptMessageParams(conversationId, "Yes");
p.quickReply = QuickReply.response(selected);
```

### KeyChangeEvent

Payload when `type` is `"keyChange"` (JS) / `"KeyChange"` (Python).

```typescript
// JS/WASM
interface KeyChangeEvent {
  type: 'keyChange';
  // Flattened meta fields...
  keyVersion: string;
  verified: boolean;
  participantKeys: ParticipantKey[];
}

interface ParticipantKey {
  userId: string;
  encryptedKey: string;
  publicKeyVersion: string;
}
```

### GroupChange

Payload when `type` is `"groupChange"` (JS) / `"GroupChange"` (Python).

```typescript
// JS/WASM
type GroupChange =
  | { changeType: 'created'; memberIds: string[]; adminIds: string[]; title?: string; avatarUrl?: string }
  | { changeType: 'titleChanged'; newTitle: string }
  | { changeType: 'avatarChanged'; newAvatarUrl: string }
  | { changeType: 'adminsAdded'; adminIds: string[] }
  | { changeType: 'adminsRemoved'; adminIds: string[] }
  | { changeType: 'membersAdded'; memberIds: string[]; currentMemberIds: string[]; currentAdminIds: string[] }
  | { changeType: 'membersRemoved'; memberIds: string[] }
  | { changeType: 'inviteEnabled'; inviteUrl: string; expiresAtMsec?: number }
  | { changeType: 'inviteDisabled'; disabledBy?: string }
  | { changeType: 'joinRequested'; userId: string }
  | { changeType: 'joinRejected'; userIds: string[] }
  | { changeType: 'unknown' };
```

### SettingsChange

Payload when `type` is `"settingsChange"` (JS) / `"SettingsChange"` (Python).

```typescript
// JS/WASM
type SettingsChange =
  | { setting: 'messageDuration'; ttlMsec: number; applyToAll: boolean }
  | { setting: 'messageDurationRemoved' }
  | { setting: 'muted' }
  | { setting: 'unmuted' }
  | { setting: 'screenCaptureDetectionEnabled' }
  | { setting: 'screenCaptureDetectionDisabled' }
  | { setting: 'screenCaptureBlockingEnabled' }
  | { setting: 'screenCaptureBlockingDisabled' }
  | { setting: 'unknown' };
```

### FailureType

Payload when `type` is `"failure"` (JS) / `"Failure"` (Python).

```typescript
// JS/WASM (camelCase values)
type FailureType =
  | 'emptyDetail'
  | 'internalError'
  | 'contentsTooLarge'
  | 'tooManyMessages'
  | 'invalidSenderSignature'
  | 'nonLatestKeyVersion'
  | 'recipientNotTrusted'
  | 'recipientKeyChanged'
  | 'onlyEncryptedMessagesAllowed'
  | 'requesterNotAdmin'
  | 'flaggedAsSpam'
  | 'rateLimitUpsell'
  | 'signatureFailedToVerifyAgainstPublicKey'
  | 'genericError'
  | 'senderNotGroupMember'
  | 'invalidSignatureVersion'
  | 'invalidPinRequest'
  | 'tooManyPins'
  | 'unknown';

type RateLimitTier =
  | 'free'
  | 'verifiedPhone'
  | 'premium'
  | 'premiumPlus'
  | 'premiumBusiness'
  | 'unknown';
```

Failure events include an optional `rateLimitTier` (JS) / `rate_limit_tier`
(Python) when the failure type is `rateLimitUpsell` (JS) / `RateLimitUpsell`
(other bindings).

### AttachmentInfo

Parsed from decrypted message content. Uses `attachmentType` (JS) / `attachment_type` (Python) for discrimination.

```typescript
// JS/WASM
type AttachmentInfo =
  | { attachmentType: 'media'; mediaHashKey?: string; dimensions?: { width?: number; height?: number }; mediaType?: string; durationMillis?: number; filesizeBytes?: number; filename?: string; attachmentId?: string }
  | { attachmentType: 'url'; url?: string; bannerImageMediaHashKey?: string; faviconImageMediaHashKey?: string; displayTitle?: string; attachmentId?: string }
  | { attachmentType: 'post'; restId?: string; postUrl?: string; attachmentId?: string }
  | { attachmentType: 'unifiedCard'; url?: string; attachmentId?: string }
  | { attachmentType: 'money'; fallbackText?: string };
```
