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
| 1 | **new** | `Chat::new(config: JuiceboxConfig)` | `new Chat()` (config via `createChat(opts)`; `juiceboxConfig` optional) | `Chat(config_json?: str)` | `New() *Chat` (free with `Close()`) | `new Chat()` (free with `close()` / `try-with-resources`) | `new Chat()` then `UpdateConfig(string)` (free with `Dispose()` / `using`) |
| 2 | **update_config** | `update_config(&mut self, config)` | `updateConfig(config: string)` | `update_config(config_json: str)` | `UpdateConfig(configJSON string) error` | `updateConfig(String)` | `UpdateConfig(string)` |
| 3 | **set_reject_unverified** | `set_reject_unverified(&mut self, reject: bool)` | `setRejectUnverified(reject: boolean)` | `set_reject_unverified(reject: bool)` | `SetRejectUnverified(reject bool)` | `setRejectUnverified(boolean)` | `SetRejectUnverified(bool)` |

The config JSON accepted by the constructor, `update_config`, `setup`, and
`unlock` supports three shapes, checked in this order:

1. **Direct SDK config** — `{"sdk_config": "<json string>", "tokens": {realm_id: token}, "max_guess_count": N}`;
   `sdk_config` goes straight to the Juicebox SDK. Default guesses: 20.
2. **X API `juicebox_config` object** — the `juicebox_config` field from
   `GET /2/users/:id/public_keys` (your own user), passed through as-is:
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
account's `juicebox_config` is created by `POST /2/users/:id/public_keys`, so
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
| 15 | **import_keys** | `import_keys(&[u8])`; `import_keys_with_version(&[u8], version: &str)` | not exposed¹ | `import_keys(keys: bytes, version: str \| None = None)` | `ImportKeys([]byte) error`; `ImportKeysWithVersion(keys []byte, version string) error` | `importKeys(byte[])`; `importKeys(byte[], String version)` | `ImportKeys(byte[], string? version = null)` |
| 16 | **set_identity** | `set_identity(user_id, signing_key_version)` | `setIdentity(userId: string, signingKeyVersion: string)` | `set_identity(user_id: str, signing_key_version: str)` | `SetIdentity(userID, signingKeyVersion string) error` | `setIdentity(String userId, String signingKeyVersion)` | `SetIdentity(string userId, string signingKeyVersion)` |

¹ By design: the public JS surface (`createChat()`/`ChatWithJuicebox`) does
not expose raw key export/import, so raw private key material stays inside
the wasm boundary; keys are managed through `setup`/`unlock` instead.

`export_keys` returns **unencrypted** private key material — handle with
care (Python returns a mutable `bytearray` so callers can zero it after
use). It requires a loaded identity key (the signing key is optional,
giving a 32-byte export); Python/Go/.NET/JVM return `None`/`nil`/`null`
when no identity key is loaded, while Rust errors.

The SDK needs to know the version the X API reports for your registered
public key, so KeyChange participant entries targeting other key versions are
skipped. Set it in either of two equivalent ways: pass the optional `version`
to `import_keys` (Python/.NET/JVM) or call `import_keys_with_version`
(Rust/Go); or call `set_identity`, which sets it together with the user id.

`set_identity(user_id, signing_key_version)` stores the **session identity**.
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

### Conversation Keys

| # | Method | Rust | JS | Python | Go | JVM | .NET |
|---|--------|------|-----|--------|-----|------|------|
| 17 | **decrypt_conversation_key** | `(encrypted_b64: &str) → XChatConversationKey` | `decryptConversationKey(b64: string) → Uint8Array` | `decrypt_conversation_key(b64: str) → bytes` | `DecryptConversationKey(encryptedKeyB64 string) ([]byte, error)` | `decryptConversationKey(String)` → `byte[]` | `DecryptConversationKey(string)` → `byte[]` |
| 18 | **prepare_conversation_key_change** | `prepare_conversation_key_change(ConversationKeyChangeParams) → PreparedConversationChange` | `prepareConversationKeyChange(params: ConversationKeyChangeParams) → PreparedConversationChange` | `prepare_conversation_key_change([dict], *, conversation_id=None, sender_id=None, signing_key_version=None) → dict` | `PrepareConversationKeyChange(ConversationKeyChangeParams) (*PreparedConversationChange, error)` | `prepareConversationKeyChange(ConversationKeyChangeParams)` | `PrepareConversationKeyChange(ConversationKeyChangeParams)` |
| 19 | **prepare_group_members_change** | `prepare_group_members_change(GroupMembersChangeParams) → PreparedConversationChange` | `prepareGroupMembersChange(params: GroupMembersChangeParams) → PreparedConversationChange` | `prepare_group_members_change([dict], conversation_id, ids…, *, sender_id=None, signing_key_version=None, current_title=None, current_avatar_url=None, current_ttl_msec=None, current_screen_capture_blocking_enabled=None) → dict` | `PrepareGroupMembersChange(GroupMembersChangeParams) (*PreparedConversationChange, error)` | `prepareGroupMembersChange(GroupMembersChangeParams)` | `PrepareGroupMembersChange(GroupMembersChangeParams)` |
| 20 | **prepare_group_create** | `prepare_group_create(GroupCreateParams) → PreparedConversationChange` | `prepareGroupCreate(params: GroupCreateParams) → PreparedConversationChange` | `prepare_group_create([dict], conversation_id, member_ids, admin_ids, *, sender_id=None, signing_key_version=None, title=None, avatar_url=None, ttl_msec=None) → dict` | `PrepareGroupCreate(GroupCreateParams) (*PreparedConversationChange, error)` | `prepareGroupCreate(GroupCreateParams)` | `PrepareGroupCreate(GroupCreateParams)` |

Every language except Python takes a single params struct/object per method
(Rust `chat_xdk_core::*Params`, JS plain objects matching the exported
interfaces, Go/JVM/.NET the `*Params` types); Python takes positional required
arguments plus keyword-only optionals. Field names follow each language's
idiom: `snake_case` in Rust/Python (`sender_id`), `camelCase` in JS/JVM
(`senderId`), `PascalCase` in Go/.NET (`SenderID` / `SenderId`).

On all three prepare methods, `sender_id` / `signing_key_version` are optional
overrides: omitted values (unset / `None` / `null` / empty string) resolve
from the session identity set via `set_identity`.

### Events

| # | Method | Rust | JS | Python | Go | JVM | .NET |
|---|--------|------|-----|--------|-----|------|------|
| 21 | **extract_conversation_keys** | `(events: &[&str]) → ConversationKeyResult` | `extractConversationKeys(string[]) → ConversationKeyResult` | `extract_conversation_keys(list[str]) → dict` | `ExtractConversationKeys(events []string) (*ConversationKeyBundle, error)` | `extractConversationKeys(List<String>)` | `ExtractConversationKeys(IEnumerable<string>)` |
| 22 | **set_cache_keys** | `set_cache_keys(enabled: bool)` | `setCacheKeys(enabled: boolean)` | `set_cache_keys(enabled: bool)` | `SetCacheKeys(enabled bool)` | `setCacheKeys(boolean)` | `SetCacheKeys(bool)` |
| 23 | **set_signing_keys** | `set_signing_keys(Vec<SigningKeyEntry>)` | `setSigningKeys(signingKeys: SigningKeyEntry[])` | `set_signing_keys(list[dict])` | `SetSigningKeys(keys []SigningKeyEntry) error` | `setSigningKeys(List<SigningKeyEntry>)` | `SetSigningKeys(IReadOnlyList<SigningKeyEntry>)` |
| 24 | **decrypt_events** | `(events, &[SigningKeyEntry]) → DecryptEventsResult` | `decryptEvents(string[], SigningKeyEntry[]?) → DecryptEventsResult` | `decrypt_events(list[str], list?=None) → dict` | `DecryptEvents(events []string, signingKeys []SigningKeyEntry) (*DecryptEventsResult, error)` | `decryptEvents(List<String>, List<SigningKeyEntry>)` | `DecryptEvents(IEnumerable<string>, IEnumerable<SigningKeyEntry>? = null)` |
| 25 | **decrypt_event** | `(b64, &HashMap<version, Key>, &[SigningKeyEntry]) → Event` | `decryptEvent(b64, ConversationKeyMap?, SigningKeyEntry[]?) → Event` | `decrypt_event(b64, dict?, list?) → dict` | `DecryptEvent(eventB64 string, conversationKeys map[string][]byte, signingKeys []SigningKeyEntry) (*Event, error)` | `decryptEvent(String, Map<String, byte[]>/ConversationKeyBundle, List<SigningKeyEntry>)` | `DecryptEvent(string, ConversationKeyBundle/dictionary? = null, IEnumerable<SigningKeyEntry>? = null)` |

**Session stores for the decrypt/encrypt paths.** Both decrypt methods accept
omitted/empty key arguments and fall back to two opt-in session stores:

- `set_signing_keys(entries)` stores signing keys that `decrypt_events` and
  `decrypt_event` use when their signing-keys argument is omitted (or `[]` /
  `nil` / `null`). Each call replaces the previous set. Only this explicit
  call populates the store — a key carried inside an event is never trusted
  for verification.
- `set_cache_keys(enabled)` enables the conversation-key cache (**off by
  default**). While enabled, `decrypt_events` caches, per conversation, the
  key whose key change carried a valid signature at the highest version seen;
  `decrypt_event` falls back to it when its conversation-keys argument is
  omitted/empty; and the `encrypt_*` methods resolve an omitted
  `conversation_key` / `conversation_key_version` pair from it. Disabling
  clears the cache; the cached keys zeroize on drop.

  Only `decrypt_events` populates the cache, and only from KeyChange events
  in its own batch whose signature verified. `extract_conversation_keys`
  never feeds it: that method adopts every decryptable key without signature
  checks, and the cache holds verified keys only. To use its result, pass
  the returned key map to `decrypt_event` explicitly.

An explicit non-empty argument always wins over the stores. The two decrypt
contracts are unchanged: `decrypt_events` never throws (per-event errors are
collected in the result) and `decrypt_event` throws on failure.

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
2. Use `decryptEvents(events)` on first load — it extracts conversation keys and returns them (and, with caching on, retains each conversation's latest verified key)
3. When new events arrive individually (webhooks, polling), use `decryptEvent(eventB64)` — the omitted key arguments resolve from the session stores. Alternatively, cache `result.conversationKeys` client-side and pass it explicitly.

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
  participantKeys: EncryptedKeyForRecipient[];  // ready to POST
  actionSignatures: ActionSignature[];          // ready to POST
}
```

```python
# Python
{
    "conversation_id": "17380288:1491585161162473473",
    "conversation_key": b"...",              # raw 32 bytes
    "conversation_key_version": "171000...", # timestamp string
    "participant_keys": [ {"user_id": "111", "encrypted_key": "...", "public_key_version": "v1"} ],
    "action_signatures": [ {"message_id": "...", "signature": "...", ...} ],
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
    conversationParticipantKeys: result.participantKeys,
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

**Params:**

| Param | JS | Python | Rust | Go | JVM | .NET | Description |
|---|---|---|---|---|---|---|---|
| events | `string[]` | `list[str]` | `&[&str]` | `[]string` | `List<String>` | `IEnumerable<string>` | All base64-encoded raw events. **Must include KeyChange events** — without them, messages depending on those keys will land in `errors`. The events endpoint returns KeyChange events in **`meta.conversation_key_events`**, separate from the `data` array; concatenate both into this argument. |
| signingKeys | `SigningKeyEntry[]` | `list[dict]` | `&[SigningKeyEntry]` | `[]SigningKeyEntry` or `nil` | `List<SigningKeyEntry>` or `null` | `IEnumerable<SigningKeyEntry>?` | Signing keys for **all participants**. The SDK extracts each event's `senderId` internally and filters to the matching keys. Omitting the parameter (or passing `[]` / `nil` / `null`) falls back to the keys stored via `setSigningKeys`; if none are stored either, under the default reject-unverified policy every **signed** event fails decryption and lands in `errors`. Only after `setRejectUnverified(false)` are such events returned with `verified: false`. |

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
  { userId: "111", publicKeyVersion: "v1", publicKey: "BASE64...", identityPublicKey: "BASE64...", identityPublicKeySignature: "BASE64..." },
  { userId: "111", publicKeyVersion: "v2", publicKey: "BASE64...", identityPublicKey: "BASE64...", identityPublicKeySignature: "BASE64..." },
  { userId: "222", publicKeyVersion: "v1", publicKey: "BASE64...", identityPublicKey: "BASE64...", identityPublicKeySignature: "BASE64..." },
];

const result = chat.decryptEvents(rawEvents, signingKeys);

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
result = chat.decrypt_events(raw_events, signing_keys)

for dm in result["messages"]:
    evt = dm["event"]
    if evt["type"] == "Message":
        print(evt["sender_id"], evt["content"]["text"])

# Cache for later
cached_keys = result["conversation_keys"]
```

**Go example:**
```go
result, err := chat.DecryptEvents(rawEvents, signingKeys)
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
DecryptEventsResult result = chat.decryptEvents(rawEvents, signingKeys);

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
var result = chat.DecryptEvents(rawEvents, signingKeys);

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

Decrypts a single event using conversation keys you already have — cached from a prior `decryptEvents` or `extractConversationKeys` call, or resolved from the opt-in key cache (`setCacheKeys`) when the argument is omitted.

**Params:**

| Param | JS | Python | Rust | Go | JVM | .NET | Description |
|---|---|---|---|---|---|---|---|
| eventB64 | `string` | `str` | `&str` | `string` | `String` | `string` | One base64-encoded raw event. |
| conversationKeys | `ConversationKeyMap` | `dict` | `&HashMap<String, Key>` | `map[string][]byte` | `Map<String, byte[]>` or `ConversationKeyBundle` | `Dictionary<string, byte[]>` or `ConversationKeyBundle` | Pre-extracted keys: **version → raw 32-byte key**. Every binding passes raw key bytes. Omitting it (or passing `{}` / `None` / `nil` / `null`) falls back to the opt-in key cache (`setCacheKeys`); non-message events (typing, read receipts) need no keys at all. |
| signingKeys | `SigningKeyEntry[]` | `list[dict]` | `&[SigningKeyEntry]` | `[]SigningKeyEntry` or `nil` | `List<SigningKeyEntry>` or `null` | `IEnumerable<SigningKeyEntry>?` | Signing keys for **the event's sender**. The SDK matches by `publicKeyVersion` against the version in the event's signature. Omitting the parameter (or passing `[]` / `nil` / `null`) falls back to the keys stored via `setSigningKeys`; if none are stored either, under the default reject-unverified policy every **signed** event fails with an error. Only after `setRejectUnverified(false)` are such events returned with `verified: false`. |

**Returns: `Event`** directly — or **throws/raises** on failure (unlike `decryptEvents` which collects errors).

```typescript
// JS — returns Event, throws on error
decryptEvent(
  eventB64: string,
  conversationKeys?: ConversationKeyMap | null,  // omitted ⇒ opt-in key cache
                                                 // (setCacheKeys)
  signingKeys?: SigningKeyEntry[]  // omitted ⇒ keys from setSigningKeys; if none
                                   // stored, signed events throw, unless
                                   // setRejectUnverified(false) was called
): Event
```

```python
# Python — returns dict, raises on error
decrypt_event(
    event_b64: str,
    conversation_keys: dict | None = None,  # { version: bytes }; None ⇒ opt-in
                                            # key cache (set_cache_keys)
    signing_keys: list[dict] | None = None  # None ⇒ keys from set_signing_keys;
                                            # if none stored, signed events raise,
                                            # unless set_reject_unverified(False)
) -> dict
```

**JS example:**
```typescript
// You cached keys from a previous decryptEvents call
const cachedKeys = previousResult.conversationKeys.keys;

// A new event arrives via webhook
const event = chat.decryptEvent(
  webhookEventB64,
  cachedKeys,
  [{ userId: "111", publicKeyVersion: "v2", publicKey: "BASE64...", identityPublicKey: "BASE64...", identityPublicKeySignature: "BASE64..." }]
);

console.log(event.type);             // "message"
console.log(event.senderId);         // "111"
console.log(event.content.text);     // "hello"
console.log(event.verified);         // true
```

**Python example:**
```python
event = chat.decrypt_event(event_b64, cached_keys, sender_signing_keys)
if event["type"] == "Message":
    print(event["content"]["text"])
```

**Go example:**
```go
event, err := chat.DecryptEvent(eventB64, cachedKeys, senderSigningKeys)
if err != nil {
    panic(err)
}
fmt.Println(event.Type)
```

**JVM example:**
```java
JsonNode event = chat.decryptEvent(eventB64, cachedKeys, senderSigningKeys);
if ("Message".equals(event.path("type").asText())) {
    System.out.println(event.path("content").path("text").asText());
}
```

**.NET example:**
```csharp
var eventJson = chat.DecryptEvent(eventB64, cachedKeys, senderSigningKeys);
if (eventJson.GetProperty("type").GetString() == "Message")
    Console.WriteLine(eventJson.GetProperty("content").GetProperty("text").GetString());
```

---

#### Side-by-side comparison

| | `decryptEvent` | `decryptEvents` |
|---|---|---|
| **Input** | 1 event (`string`) | N events (`string[]`) |
| **Conversation keys** | Caller provides (`ConversationKeyMap`); omitted ⇒ opt-in key cache (`setCacheKeys`) | SDK extracts from KeyChange events internally |
| **Signing keys** | For the **sender only**, matched by `publicKeyVersion`; omitted ⇒ `setSigningKeys` store | For **all participants**, SDK filters by `userId` per event; omitted ⇒ `setSigningKeys` store |
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
  "public_key_version": "v1",
  "public_key": "BASE64...",                    # signing public key
  "identity_public_key": "BASE64...",
  "identity_public_key_signature": "BASE64...",
}
```

The SDK verifies each entry's identity binding (`identityPublicKeySignature`)
before trusting it for signature verification, so all fields are required.

**ConversationKeyMap** — the keys param for `decryptEvent`, and the `keys` field of `ConversationKeyResult`:
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
| 26 | **encrypt_message** | `encrypt_message(EncryptMessageParams) → SendPayload` | `encryptMessage(params: EncryptMessageParams) → SendPayload` | `encrypt_message(conversation_id, text, *, sender_id=None, signing_key_version=None, conversation_key=None, conversation_key_version=None, entities=None, attachments=None, should_notify=None, ttl_msec=None) → SendPayload` | `EncryptMessage(params EncryptMessageParams) (*SendPayload, error)` | `encryptMessage(EncryptMessageParams)` | `EncryptMessage(EncryptMessageParams)` |
| 27 | **encrypt_reply** | `encrypt_reply(EncryptReplyParams) → SendPayload` | `encryptReply(params: EncryptReplyParams) → SendPayload` | `encrypt_reply(conversation_id, text, reply_to_event=None, *, reply_to_edit_event=None, reply_to_ckces=None, reply_to_sequence_id=None, reply_to_sender_id=None, reply_to_text=None, reply_to_entities=None, reply_to_attachments=None, …encrypt_message keyword optionals…) → SendPayload` | `EncryptReply(params EncryptReplyParams) (*SendPayload, error)` | `encryptReply(EncryptReplyParams)` | `EncryptReply(EncryptReplyParams)` |
| 28 | **encrypt_add_reaction** | `encrypt_add_reaction(&EncryptReactionParams) → SendPayload` | `encryptAddReaction(params: EncryptReactionParams) → SendPayload` | `encrypt_add_reaction(target_event, emoji, *, conversation_id=None, target_message_sequence_id=None, sender_id=None, signing_key_version=None, conversation_key=None, conversation_key_version=None) → SendPayload` | `EncryptAddReaction(params EncryptReactionParams) (*SendPayload, error)` | `encryptAddReaction(EncryptReactionParams)` | `EncryptAddReaction(EncryptReactionParams)` |
| 29 | **encrypt_remove_reaction** | `encrypt_remove_reaction(&EncryptReactionParams) → SendPayload` | `encryptRemoveReaction(params: EncryptReactionParams) → SendPayload` | `encrypt_remove_reaction(…same args as encrypt_add_reaction…) → SendPayload` | `EncryptRemoveReaction(params EncryptReactionParams) (*SendPayload, error)` | `encryptRemoveReaction(EncryptReactionParams)` | `EncryptRemoveReaction(EncryptReactionParams)` |
| 30 | **encrypt_edit** | `encrypt_edit(&EncryptEditParams) → SendPayload` | `encryptEdit(params: EncryptEditParams) → SendPayload` | `encrypt_edit(target_event, updated_text, *, entities=None, conversation_id=None, target_message_sequence_id=None, sender_id=None, signing_key_version=None, conversation_key=None, conversation_key_version=None) → SendPayload` | `EncryptEdit(params EncryptEditParams) (*SendPayload, error)` | `encryptEdit(EncryptEditParams)` | `EncryptEdit(EncryptEditParams)` |
| 31 | **prepare_message_delete** | `prepare_message_delete(&MessageDeleteParams) → ActionSignature` | `prepareMessageDelete(params: MessageDeleteParams) → ActionSignature` | `prepare_message_delete(conversation_id, sequence_ids, delete_for_all, *, sender_id=None, signing_key_version=None) → dict` | `PrepareMessageDelete(params MessageDeleteParams) (*ActionSignature, error)` | `prepareMessageDelete(MessageDeleteParams)` | `PrepareMessageDelete(MessageDeleteParams)` |

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
- `entities`, `attachments`, `should_notify` (defaults to true), `ttl_msec`.

An omitted value and its explicit equivalent produce byte-identical signed
output for the same logical inputs (Rust: `params.with_identity(…)` /
`params.with_conversation_key(…)`).
The SDK generates the `message_id` itself and returns it on the `SendPayload`
(see below); callers never pass one in.
The `entities` parameter shape is split by binding: **Rust, .NET, and JVM**
take structured `EntityDescriptor` objects (`{ start, end, entity_type }`),
while **JS, Python, and Go** take positional `[start, end, type]` tuples
(`EntityTuple` in JS/Go, plain tuples in Python). Same wire format underneath
— see the [EntityDescriptor / EntityTuple](#entitydescriptor-rust-net-jvm--entitytuple-go-js--tuple-python)
type section.
The `attachments` parameter takes media, URL-card (optionally with encrypted
banner/favicon preview images), and post descriptors — see
[AttachmentDescriptor (send side)](#attachmentdescriptor-send-side).
**Temporary restriction:** `encrypt_message` and `encrypt_reply` reject
attachment lists that current first-party clients cannot render — multiple
attachments are allowed only when every one is image/gif/video media
(`media_type` 1/2/3, or omitted, which defaults to image), up to 10 per
message; everything else — audio, file, svg, or unrecognized media types, URL
cards, and posts — must be the sole attachment. Disallowed combinations fail
with an "Invalid state: disallowed attachment combination…" (or "…too many
attachments…") error in every binding rather than producing a message that
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
different key version than this reply. The explicit preview fields —
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
omitting them clears any entities the original carried. The edit is
encrypted and signed like a regular message (the identity/key overrides
above apply) and returns a `SendPayload` with its own fresh `message_id`.

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
`prepare_message_delete` returns a single `ActionSignature` (the same shape
as the prepare methods' `actionSignatures` entries, with its
`signature_payload` populated) whose `encodedMessageEventDetail` carries the
`MessageDeleteEvent`, ready to submit alongside the delete request. The
optional `sender_id` / `signing_key_version` overrides resolve from the
session identity, and a one-to-one id is signed in its canonical colon form,
as everywhere.

The Rust structs pair a `new(…required…)` constructor with public optional
fields:

```rust
// Rust — session identity + key cache resolve the omitted fields
chat.set_identity(my_user_id, signing_key_version);
chat.set_cache_keys(true); // filled by decrypt_events

let mut params = EncryptMessageParams::new(conversation_id, "Hello");
params.ttl_msec = Some(86_400_000);
let payload = chat.encrypt_message(params)?;
let message_id = payload.message_id; // generated by the SDK

// Reply / react by handing back the raw event being answered
let reply = chat.encrypt_reply(EncryptReplyParams::new(
    conversation_id, "pong", original_event_b64,
))?;
let reaction =
    chat.encrypt_add_reaction(&EncryptReactionParams::new(original_event_b64, "👍"))?;
```

```typescript
// JS
chat.setIdentity(myUserId, signingKeyVersion);
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
# Python — positional required args, keyword-only optionals
chat.set_identity(my_user_id, signing_key_version)
chat.set_cache_keys(True)

payload = chat.encrypt_message(conversation_id, "Hello", ttl_msec=86_400_000)
message_id = payload.message_id  # generated by the SDK

reply = chat.encrypt_reply(conversation_id, "pong", original_event_b64)
reaction = chat.encrypt_add_reaction(original_event_b64, "👍")
```

### Streams (Media)

| # | Method | Rust | JS | Python | Go | JVM | .NET |
|---|--------|------|-----|--------|-----|------|------|
| 32 | **encrypt_stream** | `(&[u8], &Key) → Vec<u8>` | `(Uint8Array, Uint8Array) → Uint8Array` | `(bytes, bytes) → bytes` | `EncryptStream(plaintext, conversationKey []byte) ([]byte, error)` | `encryptStream(byte[], byte[])` → `byte[]` | `EncryptStream(byte[], byte[])` → `byte[]` |
| 33 | **decrypt_stream** | `(&[u8], &Key) → Vec<u8>` | `(Uint8Array, Uint8Array) → Uint8Array` | `(bytes, bytes) → bytes` | `DecryptStream(encrypted, conversationKey []byte) ([]byte, error)` | `decryptStream(byte[], byte[])` → `byte[]` | `DecryptStream(byte[], byte[])` → `byte[]` |
| 34 | **stream_encryptor** | `(&Key) → StreamEncryptor` | `streamEncryptor(Uint8Array) → StreamEncryptor` | `stream_encryptor(bytes) → StreamEncryptor` | `StreamEncryptor(conversationKey []byte) (*StreamEncryptor, error)` | `streamEncryptor(byte[]) → StreamEncryptor` | `StreamEncryptor(byte[]) → StreamEncryptor` |
| 35 | **stream_decryptor** | `(&Key) → StreamDecryptor` | `streamDecryptor(Uint8Array) → StreamDecryptor` | `stream_decryptor(bytes) → StreamDecryptor` | `StreamDecryptor(conversationKey []byte) (*StreamDecryptor, error)` | `streamDecryptor(byte[]) → StreamDecryptor` | `StreamDecryptor(byte[]) → StreamDecryptor` |

Methods 32/33 take the **decrypted** conversation key (raw bytes) and process the whole payload in memory.

Methods 34/35 return an incremental object for large payloads: feed chunks with `push`, then call `finish` once. `finish` errors if the stream ended before its final frame (truncation detection), so output from `push` must not be treated as complete until `finish` succeeds. The native bindings (Go, JVM, .NET) free the object via `Close`/`close`/`Dispose`. In JS/WASM, `finish()` consumes and frees the object; call `free()` only when abandoning a stream without finishing it (calling it after `finish()` throws).

**Picking the key.** A conversation can have multiple key versions over its lifetime, and every payload decrypts only with the key of the version it was encrypted under. Each decrypted message event carries that version (`keyVersion` / `key_version`), and `decryptEvents` returns the full version → key map — always select the key by the event's version rather than assuming a single conversation key:

```js
const key = result.conversationKeys.keys[message.keyVersion];
const plaintext = chat.decryptStream(encryptedMedia, key);
```

### Generic Encrypt / Decrypt

| # | Method | Rust | JS | Python | Go | JVM | .NET |
|---|--------|------|-----|--------|-----|------|------|
| 36 | **encrypt** | `(&str, &Key) → String` | `(string, Uint8Array) → string` | `(str, bytes) → str` | `Encrypt(plaintext string, conversationKey []byte) (string, error)` — returns base64 ciphertext | `encrypt(String, byte[])` → `String` | `Encrypt(string, byte[])` → `string` |
| 37 | **decrypt** | `(&str, &Key) → String` | `(string, Uint8Array) → string` | `(str, bytes) → str` | `Decrypt(ciphertextB64 string, conversationKey []byte) (string, error)` — UTF-8 plaintext | `decrypt(String, byte[])` → `String` | `Decrypt(string, byte[])` → `string` |

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
| 38 | **sign** | `(&[u8]) → Vec<u8>` | `(Uint8Array) → Uint8Array` | `(bytes) → bytes` | `Sign(data []byte) ([]byte, error)` | `sign(byte[])` → `byte[]` | `Sign(byte[])` → `byte[]` |
| 39 | **verify** | `(pk_b64, &[u8] sig, &[u8] data) → bool` | `(pk_b64, Uint8Array sig, Uint8Array data) → boolean` | `(pk_b64, bytes sig, bytes data) → bool` | `Verify(publicKeyB64 string, signature, data []byte) (bool, error)` | `verify(String publicKeyB64, byte[] signature, byte[] data)` | `Verify(string publicKeyB64, byte[] signature, byte[] data)` |
| 40 | **verify_key_binding** | `(identity_b64, signing_b64, sig_b64) → bool` | `verifyKeyBinding(identityB64, signingB64, sigB64) → boolean` | `verify_key_binding(identity_b64, signing_b64, sig_b64) → bool` | `VerifyKeyBinding(identityB64, signingB64, sigB64 string) (bool, error)` | `verifyKeyBinding(String, String, String)` | `VerifyKeyBinding(string, string, string)` |
| 41 | **matches_registered_key** | `(public_key_b64) → bool` | `matchesRegisteredKey(publicKeyB64) → boolean` | `matches_registered_key(public_key_b64) → bool` | `MatchesRegisteredKey(publicKeyB64 string) (bool, error)` | `matchesRegisteredKey(String)` | `MatchesRegisteredKey(string)` |

Conversation-key changes, group creates, and group member-adds are signed by the
one-call prepare methods (`prepare_conversation_key_change`,
`prepare_group_create`, `prepare_group_members_change`), which return the
`actionSignatures` ready to POST. Group create and member-add each return two
signatures (a conversation-key change plus the group change). Message deletes
are signed by `prepare_message_delete`, which returns a single `ActionSignature`.

### Utilities

Common helpers exported as module-level functions (Rust crate root / JS module / Python module / **Go `chatxdk` package** / **JVM and .NET `ChatXdkUtilities` classes**):

| # | Function | Rust | JS | Python | Go | JVM | .NET |
|---|----------|------|-----|--------|-----|------|------|
| 42 | **bytes_to_base64** | `(&[u8]) → String` | `bytesToBase64(Uint8Array) → string` | `bytes_to_base64(bytes) → str` | `BytesToBase64(data []byte) (string, error)` | `ChatXdkUtilities.bytesToBase64(byte[])` | `ChatXdkUtilities.BytesToBase64(ReadOnlySpan<byte>)` |
| 43 | **base64_to_bytes** | `(&str) → Option<Vec<u8>>` | `base64ToBytes(string) → Uint8Array?` | `base64_to_bytes(str) → bytes?` | `Base64ToBytes(b64 string) ([]byte, error)` | `ChatXdkUtilities.base64ToBytes(String)` | `ChatXdkUtilities.Base64ToBytes(string)` |
| 44 | **bytes_to_hex** | `(&[u8]) → String` | `bytesToHex(Uint8Array) → string` | `bytes_to_hex(bytes) → str` | `BytesToHex(data []byte) (string, error)` | `ChatXdkUtilities.bytesToHex(byte[])` | `ChatXdkUtilities.BytesToHex(ReadOnlySpan<byte>)` |
| 45 | **hex_to_bytes** | `(&str) → Option<Vec<u8>>` | `hexToBytes(string) → Uint8Array?` | `hex_to_bytes(str) → bytes?` | `HexToBytes(hex string) ([]byte, error)` | `ChatXdkUtilities.hexToBytes(String)` | `ChatXdkUtilities.HexToBytes(string)` |
| 46 | **detect_mime_type** | `(&[u8]) → Option<&str>` | `detectMimeType(Uint8Array) → string?` | `detect_mime_type(bytes) → str?` | `DetectMimeType(data []byte) (mime string, err error)` — empty string if unknown | `ChatXdkUtilities.detectMimeType(byte[])` → `String` or `null` | `ChatXdkUtilities.DetectMimeType(ReadOnlySpan<byte>)` → `string?` |
| 47 | **detect_image_dimensions** | `(&[u8]) → Option<ImageDimensions>` | `detectImageDimensions(Uint8Array) → {width, height}?` | `detect_image_dimensions(bytes) → (w, h)?` | `DetectImageDimensions(data []byte) (*ImageDimensions, error)` — nil if unknown | `ChatXdkUtilities.detectImageDimensions(byte[])` → `ImageDimensions` or `null` | `ChatXdkUtilities.DetectImageDimensions(ReadOnlySpan<byte>)` → `ImageDimensions?` |

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

First boot — `juicebox_config` is created by `POST /2/users/:id/public_keys`,
so a brand-new user creates the chat without one:

```typescript
import { createChat } from '@xdevplatform/chat-xdk';

const chat = await createChat({
  getAuthToken: async (realmId) => await backend.getToken(realmId),
});
const payload = chat.generateKeypairs();
// … POST payload to /2/users/:id/public_keys, GET juicebox_config back …
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
chat.setIdentity(myUserId, mySigningKeyVersion);
chat.setCacheKeys(true);
chat.setSigningKeys([
  { userId: "111", publicKeyVersion: "v1", publicKey: "BASE64...", identityPublicKey: "BASE64...", identityPublicKeySignature: "BASE64..." },
  { userId: "222", publicKeyVersion: "v1", publicKey: "BASE64...", identityPublicKey: "BASE64...", identityPublicKeySignature: "BASE64..." },
]);

// ── Initial load: use decryptEvents ──
// The SDK extracts conversation keys, matches signing keys automatically,
// and (with the cache on) retains each conversation's latest verified key.
const result = chat.decryptEvents(rawEvents);

for (const dm of result.messages) {
  if (dm.event.type === "message") {
    console.log(dm.event.senderId, dm.event.content.text);
  }
}

// ── New event arrives (webhook / poll): use decryptEvent ──
// Omitted arguments resolve from the key cache and signing-key store.
const event = chat.decryptEvent(webhookEventB64);
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

// ── Media (whole-buffer) ──
const decrypted: Uint8Array = chat.decryptStream(encryptedBytes, convKey);

// ── Media (incremental, for large files) ──
// Decrypt chunk-by-chunk as bytes arrive, e.g. from a fetch() body stream,
// without holding the whole payload in memory.
const dec = chat.streamDecryptor(convKey);
const reader = response.body.getReader();
const parts: Uint8Array[] = [];
for (;;) {
  const { done, value } = await reader.read();
  if (done) break;
  parts.push(dec.push(value));
}
// finish() consumes and frees the decryptor (do not call free() after it);
// it throws if the stream was truncated.
parts.push(dec.finish());
```

### Python

```python
from chat_xdk import Chat

chat = Chat(config_json)
chat.unlock("2580")

# ── Set the session once ──
chat.set_identity(my_user_id, my_signing_key_version)
chat.set_cache_keys(True)
chat.set_signing_keys(signing_keys)  # all participants

# ── Initial load: use decrypt_events ──
result = chat.decrypt_events(raw_events)
for dm in result["messages"]:
    if dm["event"]["type"] == "Message":
        print(dm["event"]["sender_id"], dm["event"]["content"]["text"])

# ── New event arrives: use decrypt_event ──
# Omitted arguments resolve from the key cache and signing-key store.
event = chat.decrypt_event(event_b64)
if event["type"] == "Message":
    print(event["content"]["text"])

# ── Send: identity and conversation key resolve from the session ──
payload = chat.encrypt_message(event["conversation_id"], "hi!")
reply = chat.encrypt_reply(event["conversation_id"], "pong", event_b64)
reaction = chat.encrypt_add_reaction(event_b64, "👍")

# ── Metadata (group name, avatar, description) ──
group_name = chat.decrypt(conversation["group_name"], conv_key)

# ── Media ──
decrypted = chat.decrypt_stream(encrypted_bytes, conv_key)
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
    chat.SetIdentity(myUserID, mySigningKeyVersion)
    chat.SetCacheKeys(true)
    _ = chat.SetSigningKeys(signingKeys) // all participants

    // ── Initial load: use DecryptEvents (nil = stored signing keys) ──
    result, err := chat.DecryptEvents(rawEvents, nil)
    if err != nil {
        panic(err)
    }
    for _, dm := range result.Messages {
        if dm.Event.Type == "Message" {
            fmt.Println(dm.Event.AsMessage().Text())
        }
    }

    // ── New event arrives: use DecryptEvent ──
    // nil arguments resolve from the key cache and signing-key store.
    event, err := chat.DecryptEvent(eventB64, nil, nil)
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

    // Raw 32-byte conversation key for the metadata/media calls below,
    // e.g. from DecryptConversationKey or result.ConversationKeys.Keys.
    convKey := result.ConversationKeys.Keys[keyVersion]

    // ── Metadata (group name, avatar, description) ──
    groupName, err := chat.Decrypt(conversationGroupNameB64, convKey)
    _ = groupName

    // ── Media (raw bytes in, raw bytes out) ──
    decrypted, err := chat.DecryptStream(encryptedMedia, convKey)
    _ = decrypted
}
```

### Rust

```rust
use chat_xdk_core::{Chat, EncryptMessageParams, EncryptReactionParams, EncryptReplyParams, Event};
use chat_xdk_core::keys::juicebox::JuiceboxConfig;

let config = JuiceboxConfig::from_json(config_json);
let chat = Chat::new(config);
chat.unlock(b"2580").await?;

// ── Set the session once ──
chat.set_identity(my_user_id, my_signing_key_version);
chat.set_cache_keys(true);
chat.set_signing_keys(signing_keys); // all participants

// ── Initial load: use decrypt_events (empty slice = stored signing keys) ──
let result = chat.decrypt_events(&raw_events, &[]);
for dm in &result.messages {
    if let Event::Message(msg) = &dm.event {
        println!("{}: {}", msg.meta.sender_id.as_deref().unwrap_or("?"), msg.text().unwrap_or(""));
    }
}

// ── New event arrives: use decrypt_event ──
// Empty arguments resolve from the key cache and signing-key store.
let event = chat.decrypt_event(event_b64, &Default::default(), &[])?;

// ── Send: identity and conversation key resolve from the session ──
let payload = chat.encrypt_message(EncryptMessageParams::new(conversation_id, "hi!"))?;
let reply = chat.encrypt_reply(EncryptReplyParams::new(conversation_id, "pong", event_b64))?;
let reaction = chat.encrypt_add_reaction(&EncryptReactionParams::new(event_b64, "👍"))?;

// ── Metadata (group name, avatar, description) ──
let group_name = chat.decrypt(&conversation.group_name, &conv_key)?;

// ── Media ──
let decrypted = chat.decrypt_stream(&encrypted_bytes, &conv_key)?;
```

### .NET (C#)

Decrypted events are returned as `System.Text.Json.JsonElement` (snake_case property names in the JSON). Use `GetProperty` / `GetString` as in the examples below, or deserialize into your own models.

```csharp
using ChatXdk;

using var chat = new Chat();
chat.UpdateConfig(juiceboxConfigJson);
chat.Unlock(pin, juiceboxConfigJson);

// Set the session once: identity, opt-in key cache, signing-key store.
chat.SetIdentity(myUserId, mySigningKeyVersion);
chat.SetCacheKeys(true);
chat.SetSigningKeys(signingKeys); // all participants

// Initial load — omitted signing keys come from the store.
var result = chat.DecryptEvents(rawEvents);
foreach (var dm in result.Messages)
{
    if (dm.Event.GetProperty("type").GetString() == "Message")
        Console.WriteLine(dm.Event.GetProperty("content").GetProperty("text").GetString());
}

// Single event — omitted arguments resolve from the session stores.
var evt = chat.DecryptEvent(webhookB64);
var conversationId = evt.GetProperty("conversation_id").GetString()!;

// Send: identity and conversation key resolve from the session.
var payload = chat.EncryptMessage(new EncryptMessageParams(conversationId, "hi!"));
// Preview derived from + embedded raw event for validation.
var reply = chat.EncryptReply(new EncryptReplyParams(conversationId, "pong", webhookB64));
var reaction = chat.EncryptAddReaction(new EncryptReactionParams(webhookB64, "👍"));

var groupName = chat.Decrypt(conversationGroupNameB64, convKeyBytes);
var mediaPlain = chat.DecryptStream(encryptedMediaBytes, convKeyBytes);
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

import java.util.Map;

try (Chat chat = new Chat()) {
    chat.unlock("2580", juiceboxConfigJson);

    // Set the session once: identity, opt-in key cache, signing-key store.
    chat.setIdentity(myUserId, mySigningKeyVersion);
    chat.setCacheKeys(true);
    chat.setSigningKeys(signingKeys); // all participants

    // Initial load — null signing keys fall back to the store
    DecryptEventsResult batch = chat.decryptEvents(rawEvents, null);
    for (DecryptedMessage dm : batch.messages) {
        JsonNode evt = dm.event;
        if (evt != null && "Message".equals(evt.path("type").asText())) {
            String text = evt.path("content").path("text").asText();
            // …
        }
    }

    // Single event — null arguments resolve from the session stores
    JsonNode event = chat.decryptEvent(eventB64, (Map<String, byte[]>) null, null);
    String conversationId = event.path("conversation_id").asText();

    // Send: identity and conversation key resolve from the session
    SendPayload payload =
            chat.encryptMessage(new EncryptMessageParams(conversationId, "hi!"));
    // Preview derived from + embedded raw event for validation.
    SendPayload reply =
            chat.encryptReply(new EncryptReplyParams(conversationId, "pong", eventB64));
    SendPayload reaction =
            chat.encryptAddReaction(new EncryptReactionParams(eventB64, "👍"));
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

Returned by `generate_keypairs()`. POST this to the X API.

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
  version?: string;         // Timestamp-based version
  generateVersion: boolean; // true
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

Returned by `encrypt_message()` and all `encrypt_*()` methods.

The `message_id` is generated by the SDK (a UUID) and embedded in the signed
event. Send it as the message's `message_id`, keep it to dedup and to anchor
replies, and reuse the same encrypted payload on retries so an id is never
minted twice.

```rust
// Rust
pub struct SendPayload {
    pub message_id: String,              // SDK-generated UUID, also embedded in the signed event
    pub encrypted_content: String,       // Base64-encoded Thrift MessageCreateEvent
    pub signature: String,               // Base64-encoded ECDSA signature
    pub encoded_event_signature: String, // Base64-encoded Thrift MessageEventSignature
    pub signature_info: SignatureInfo,   // { public_key_version, signature_version: "7" }
    pub conversation_key_version: String,
    pub should_notify: bool,
}

// Python (SendPayload class attributes)
// message_id: str
// encrypted_content: str
// signature: str
// encoded_event_signature: str
// signature_info: SignatureInfo
// conversation_key_version: str
// should_notify: bool
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
  media_hash_key: string;   // from the media upload of the encrypted image
  filesize_bytes: number;   // size of the encrypted blob in bytes
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
2. Encrypt it with `encryptStream`/`streamEncryptor` using the conversation key.
3. Upload the ciphertext to the conversation's media store
   (`POST /2/chat/media/upload/initialize` → `append` → `finalize`) and keep
   the returned `media_hash_key`.
4. Reference it as `banner_image` (plus a `display_title`) on the `url`
   attachment, with the encrypted blob's size as `filesize_bytes` and the
   image's `filename`.

Receivers see the image hashes on the decrypted message (`AttachmentInfo`
`bannerImageMediaHashKey` and `media_hashes` entries with source
`"url_banner"`/`"url_favicon"`) and can download + `decryptStream` them like
any media attachment. Keep banners small (a few hundred KB): clients honor
data-usage thresholds when deciding whether to auto-load media.

Rust, .NET, and JVM expose typed variants/factories
(`AttachmentDescriptor::Url { … }`, `AttachmentDescriptor.UrlCard(url,
displayTitle, bannerImage, faviconImage)`, `Types.AttachmentDescriptor
.urlCard(url, displayTitle, bannerImage, faviconImage)`); Go uses the flat
`AttachmentDescriptor` struct with `BannerImage`/`FaviconImage` pointer
fields (`URLAttachmentImageDescriptor`); JS and Python pass the plain
object/dict shape above.

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
