# Changelog

## [Unreleased]

## [0.7.0] - 2026-10-27

To move code from 0.5.x, follow your binding's guide in
[docs/migrating-0.7](docs/migrating-0.7/README.md): each lists its changes
with before/after code, and [Why 0.7.0 changes](docs/migrating-0.7/why.md)
explains why each change was made. API.md, the guides, the READMEs and the
doc comments in every binding describe this API: their code examples compile
against it, and the Rust crate's examples build as doctests.

### Added

Group and conversation-metadata actions are signed before they are sent:
recipients on the default policy drop one that isn't. Each call takes one
params object and returns `action_signatures` for the request.

`prepare_group_members_remove` removes members and rotates the conversation
key, so the members removed don't receive the key the group encrypts under
next. `GroupMembersRemoveParams` takes the public keys of every member who
stays, the caller's included, the conversation id and the members to
remove, and the result is a `PreparedConversationChange`: the new key, the
remaining members' participant keys, and the request's signatures — the
removal, signed at signature version 11 and bound to the new key version,
then the key change. The group's title and description are encrypted under
the conversation key, so the removal takes the ones the group has as
plaintext (`title`, `description`), encrypts each under the new key, and
signs each change between the removal and the key change, marked as a
key-rotation re-encryption (`for_key_rotation`), which recipients' decrypt
drops (see Other breaking changes). The key cache adopts the new key once
`decrypt_events` verifies the removal's key change; until then the app
passes the new key and version to the encrypt calls. The result carries no
ratchet tree and no rewrapped pin-key bundle.

`prepare_group_leave` signs leaving a group: a removal of the sender, at
signature version 11, an admin add when `promote_admin_id` names the member
to promote, and a conversation delete. Leave does not rotate the
conversation key.

`prepare_group_title_change` and `prepare_group_description_change` take the
new value as plaintext and encrypt it under the conversation key, which
resolves as for `encrypt_message`: the params' key and version, or the key
cache. Each returns a `PreparedGroupMetadataChange`: the `encrypted_value`
the request sends, the `conversation_key_version` it is encrypted under, and
its signature at signature version 7. `decrypt_event` and `decrypt_events`
decrypt a received title or description change, and a description change
decrypts to `GroupChange::DescriptionChanged` (`descriptionChanged`
in JS) with its `new_description`.

`prepare_group_avatar_change` signs a group avatar: the media URL of the
image, as is, and the `conversation_key_version` of the key the image is
encrypted under. An avatar URL is not encrypted; the app encrypts the image
under the conversation key, uploads it to the group's media, and passes the
URL. It returns a `PreparedAction`, and a received `AvatarChanged` change
carries the URL with its `conversation_key_version`.

Admin, invite, and join changes, message-TTL changes, and screen-capture
setting changes each return a `PreparedAction` signed at signature version
7. Screen-capture blocking signs `EnableScreenCaptureBlocking` and
`DisableScreenCaptureBlocking`. Detection signs
`EnableScreenCaptureDetection` and `DisableScreenCaptureDetection`.

A decrypted v1 edit carries the signed message id of the message it edits
as `target_message_id` (`targetMessageId` in JS), next to that message's
`target_message_sequence_id`; a v0 edit carries the sequence id only.

- The bindings fetch the feature switches from
  `GET https://api.x.com/2/chat/features` in the background, without
  delaying or failing anything; there is nothing to call. Each chat reads
  them once, when it is created, and keeps the answer for its lifetime;
  chats created while a request is in flight share it. The request is
  anonymous: it carries no credentials or query parameters, sends and stores
  no cookies, and follows no redirect, so a cookie the endpoint sets never
  reaches a later chat's request and a redirect counts as an answer other
  than 200. Until it answers, and for the chat's lifetime if it fails or is
  blocked, sends stay v0. See "Network access" in the README.
- Rust and the C ABI: `ChatCore::set_feature_switches` and
  `Chat::set_feature_switches`, and
  `chat_xdk_set_feature_switches(chat, status, body, body_len)`, take the
  status and body of a `GET /2/chat/features` the caller made, as the
  crate's `FEATURES_ENDPOINT`, `FEATURES_TIMEOUT_MS` and `FEATURES_MAX_BODY`
  describe it, and `chat_xdk.h`'s `CHAT_XDK_FEATURES_ENDPOINT`,
  `CHAT_XDK_FEATURES_TIMEOUT_MS` and `CHAT_XDK_FEATURES_MAX_BODY`. A chat
  takes one answer for its lifetime, and every switch stays off unless a 200
  answer of at most `FEATURES_MAX_BODY` bytes turns it on.
- JS: `importKeys` and `exportKeys`, as in every binding.
- Python: `SigningKeyEntry`, `PublicKeyInput`, `ConversationKeyResult`,
  `DecryptEventsResult`, `DecryptedEvent`, `PreparedAction`,
  `PreparedGroupMetadataChange`, `PreparedConversationChange`,
  `ActionSignature`, `MessageEventSignature` and
  `ConversationParticipantKey` type the dicts the calls take and return.
- `SendPayload` carries `xdk_version`, the SDK version that built it
  (`xdkVersion` in JS, `XdkVersion` in Go and .NET).
- Messages encrypted under per-message keys (`contents_encryption_version`
  1 or more) decrypt, as do their reply previews, edits and files. A reply
  to such a message carries the original's key, and a v1 edit names the
  message it edits.
- Signatures verify at versions 8 through 11, in the payload layout of the
  version each carries. Versions above 11 are rejected.
- Read receipts are signed. `prepare_mark_conversation_read` takes
  `MarkConversationReadParams`: `conversation_id`, `seen_until_sequence_id`
  (the sequence id of the newest event read) and a `seen_at_msec`, which
  defaults to the current time. It returns a `PreparedAction`, whose
  `action_signatures` the mark-read request
  (`POST /2/chat/conversations/{id}/read`) sends as they are, nested as the
  conversation-change requests nest theirs. Recipients on the default policy
  drop an unsigned receipt; `decrypt_event` returns a signed receipt as a
  verified `ReadReceipt`. The C ABI adds
  `chat_xdk_prepare_mark_conversation_read`.
- The JVM jar and the .NET package bundle the native library for 64-bit ARM
  Linux (`linux-arm64`) too, so both bindings run there without a library of
  your own.

### Breaking changes

#### Sends can use per-message keys

Every encrypted send (message, reply, reaction and edit) is in one of two
wire formats, and the SDK picks which:

- **v0**, the 0.5.x format: contents are encrypted under the conversation
  key, `contents_encryption_version` is unset, and the send is signed at
  signature version 7. Message ids are random, attachments carry no id, and
  an edit does not name the message it edits, as in 0.5.x.
- **v1**, per-message keys: contents are encrypted under a key derived from
  the conversation key, the sender id and the message id, the
  `MessageCreateEvent` carries `contents_encryption_version` 1, and the send
  is signed at signature version 10, which covers that field. A message with
  files takes an id derived from them, each attachment carries an id, and an
  edit names the message it edits.

Sends are v0 unless the X API's `v1_send` feature switch turns v1 on for the
chat. The bindings read the switches themselves; a Rust chat, or one called
through the C ABI directly, sends v1 once it's handed an answer that turns
the switch on (`set_feature_switches`, `chat_xdk_set_feature_switches`).
Readers need per-message-key support for v1 sends: 0.5.x rejects each one as
a signature verification failure (an ECDSA mismatch), so upgrade readers
first. Other signed actions (conversation-key changes, group changes and
deletes) still sign at version 7.

`sender_id` must be the sender's numeric user id, and
`conversation_key_version` an integer as its key-change event carries it.
Other values are rejected in both formats, since v1 recipients derive
the key from the numeric id and look it up by the version.

#### Key registration sends only the public key

`generate_keypairs` returns a `PublicKeyRegistrationPayload` that carries
only `public_key`, in every binding. POST the payload as returned.
`PublicKeys`, which `get_public_keys` and `setup` return, holds the two
public keys, `identity` and `signing`.

`generate_keypairs` sets no signing-key version. After you register the
keys, call `set_identity` with your user id and the `public_key_version`
the registration returns, or pass that version as `signing_key_version` in
`ImportKeysParams` when you load saved keys. A signed action without a
version fails in the SDK with `signing_key_version is not set: pass it
explicitly or call set_identity() first`, rather than reaching the X API,
which accepts only the registered version.

In the snippets, `api.post(path, body)` stands for your HTTP client: it
POSTs `body` as JSON to `https://api.x.com` + `path` and returns the parsed
response. The JS one writes keys in snake_case, and in Python `public_key`
is the `public_key` object you build from `registration.public_key`.

```js
const registration = chat.generateKeypairs();
const response = await api.post(`/2/users/${userId}/public_keys`, { public_key: registration.publicKey });
chat.setIdentity({ userId, signingKeyVersion: response.data.public_key_version });
```

```python
registration = chat.generate_keypairs()
response = api.post(f"/2/users/{user_id}/public_keys", {"public_key": public_key})
chat.set_identity(SetIdentityParams(user_id, response["data"]["public_key_version"]))
```

Go, .NET, JVM and Rust call `SetIdentity` / `setIdentity` / `set_identity`
the same way; each binding's guide in
[docs/migrating-0.7](docs/migrating-0.7/README.md) shows its request and the
0.5.x code to change.

#### A message with files is built before its files are encrypted

In v1 each file of a message is encrypted under its own key, derived from
the message's key and the file's attachment; in v0 every file is under the
conversation key, as in 0.5.x. Either way the file calls take the key from
the message, so the message comes first:

1. Start each file's upload with `POST /2/chat/media/upload/initialize`
   and keep the `session_id` and `media_hash_key` it returns. The upload's
   `total_bytes` is `encrypted_file_size` of the file's size.
2. Encrypt the message (`encrypt_message` / `encrypt_reply`) with
   attachments that name those media hash keys. `SendPayload` carries
   `event_b64`: the message as recipients receive it.
3. Encrypt each file with `encrypt_file` (whole file) or
   `file_encryptor` (incremental `push` / `finish`), passing the payload's
   `event_b64` and the file's media hash key. As `encrypt_message` does, the
   file calls take the conversation key the message was encrypted under and
   its version (`conversation_key` + `conversation_key_version`, set
   together), or resolve both from the key cache when neither is set.
4. Upload each encrypted file with
   `POST /2/chat/media/upload/{session_id}/append` and finish it with
   `POST /2/chat/media/upload/{session_id}/finalize`, then send the message.

The file calls need no session identity: the sender, message id
and key version come from `event_b64`. In v1 the SDK derives the id of a
message with files from the conversation key and its version, the sender,
the conversation and the files' media hash keys, so building the same
message again gives the same id and its encrypted files stay valid; v0
messages, and messages without files, take a random id, as in 0.5.x. Upload
each file for one message only: the text does not affect the id, so a second
message that reuses the first one's uploads gets its id, and recipients drop
it as a repeat. A message that lists an empty media hash
key, or one media hash key in two attachments, is rejected, and the file
calls' errors say what to pass instead.

In the snippets, `api.post(path, body)` stands for your HTTP client, as in
the key registration entry above, and `photo_attachment` for your code that
builds a photo's attachment descriptor. The `append` and `finalize`
requests come after `encrypt_file`, which produces the bytes they upload:

Rust

```rust
let total_bytes = utils::encrypted_file_size(photo.len() as u64).ok_or("file too large")?;
let upload = api.post("/2/chat/media/upload/initialize", &serde_json::json!({
    "conversation_id": conversation_id, "total_bytes": total_bytes,
}))?;
let session_id = upload["data"]["session_id"].as_str().ok_or("no session_id")?;
let media_hash_key = upload["data"]["media_hash_key"].as_str().ok_or("no media_hash_key")?;
let mut params = EncryptMessageParams::new(conversation_id, "a photo");
params.attachments = Some(vec![photo_attachment(media_hash_key)]);
let payload = chat.encrypt_message(&params)?;
let encrypted = chat.encrypt_file(&EncryptFileParams::new(photo, &payload.event_b64, media_hash_key))?;
api.post(&format!("/2/chat/media/upload/{session_id}/append"), &serde_json::json!({
    "conversation_id": conversation_id, "media_hash_key": media_hash_key,
    "segment_index": 0, "media": utils::bytes_to_base64(&encrypted),
}))?;
api.post(&format!("/2/chat/media/upload/{session_id}/finalize"), &serde_json::json!({
    "conversation_id": conversation_id, "media_hash_key": media_hash_key, "num_parts": "1",
}))?;
```

Python

```python
upload = api.post("/2/chat/media/upload/initialize", {
    "conversation_id": conversation_id, "total_bytes": encrypted_file_size(len(photo)),
})["data"]
media_hash_key = upload["media_hash_key"]
payload = chat.encrypt_message(
    EncryptMessageParams(conversation_id, "a photo", attachments=[photo_attachment(media_hash_key)])
)
encrypted = chat.encrypt_file(EncryptFileParams(photo, payload.event_b64, media_hash_key))
api.post(f"/2/chat/media/upload/{upload['session_id']}/append", {
    "conversation_id": conversation_id, "media_hash_key": media_hash_key,
    "segment_index": 0, "media": bytes_to_base64(encrypted),
})
api.post(f"/2/chat/media/upload/{upload['session_id']}/finalize", {
    "conversation_id": conversation_id, "media_hash_key": media_hash_key, "num_parts": "1",
})
```

JS / TypeScript

```js
const { data: upload } = await api.post("/2/chat/media/upload/initialize", {
  conversation_id: conversationId, total_bytes: encryptedFileSize(photo.length),
});
const mediaHashKey = upload.media_hash_key;
const payload = chat.encryptMessage({
  conversationId, text: "a photo", attachments: [photoAttachment(mediaHashKey)],
});
const encrypted = chat.encryptFile({ file: photo, eventB64: payload.eventB64, mediaHashKey });
await api.post(`/2/chat/media/upload/${upload.session_id}/append`, {
  conversation_id: conversationId, media_hash_key: mediaHashKey,
  segment_index: 0, media: bytesToBase64(encrypted),
});
await api.post(`/2/chat/media/upload/${upload.session_id}/finalize`, {
  conversation_id: conversationId, media_hash_key: mediaHashKey, num_parts: "1",
});
```

Go

```go
size, err := chatxdk.EncryptedFileSize(uint64(len(photo)))
response, err := api.Post("/2/chat/media/upload/initialize", map[string]any{
    "conversation_id": conversationID, "total_bytes": size,
})
upload := response["data"].(map[string]any)
sessionID, mediaHashKey := upload["session_id"].(string), upload["media_hash_key"].(string)
payload, err := chat.EncryptMessage(chatxdk.EncryptMessageParams{
    ConversationID: conversationID, Text: "a photo",
    Attachments: []chatxdk.AttachmentDescriptor{photoAttachment(mediaHashKey)},
})
encrypted, err := chat.EncryptFile(chatxdk.EncryptFileParams{
    File: photo, EventB64: payload.EventB64, MediaHashKey: mediaHashKey,
})
_, err = api.Post("/2/chat/media/upload/"+sessionID+"/append", map[string]any{
    "conversation_id": conversationID, "media_hash_key": mediaHashKey,
    "segment_index": 0, "media": base64.StdEncoding.EncodeToString(encrypted),
})
_, err = api.Post("/2/chat/media/upload/"+sessionID+"/finalize", map[string]any{
    "conversation_id": conversationID, "media_hash_key": mediaHashKey, "num_parts": "1",
})
```

.NET (C#)

```csharp
var upload = api.Post("/2/chat/media/upload/initialize", new
{
    conversation_id = conversationId,
    total_bytes = ChatXdkUtilities.EncryptedFileSize((ulong)photo.Length),
}).GetProperty("data");
var sessionId = upload.GetProperty("session_id").GetString();
var mediaHashKey = upload.GetProperty("media_hash_key").GetString()!;
var payload = chat.EncryptMessage(new EncryptMessageParams(conversationId, "a photo")
{
    Attachments = new[] { PhotoAttachment(mediaHashKey) },
});
var encrypted = chat.EncryptFile(new EncryptFileParams(photo, payload.EventB64, mediaHashKey));
api.Post($"/2/chat/media/upload/{sessionId}/append", new
{
    conversation_id = conversationId, media_hash_key = mediaHashKey,
    segment_index = 0, media = Convert.ToBase64String(encrypted),
});
api.Post($"/2/chat/media/upload/{sessionId}/finalize", new
{
    conversation_id = conversationId, media_hash_key = mediaHashKey, num_parts = "1",
});
```

JVM (Java)

```java
JsonNode upload = api.post("/2/chat/media/upload/initialize", Map.of(
        "conversation_id", conversationId,
        "total_bytes", ChatXdkUtilities.encryptedFileSize(photo.length))).path("data");
String sessionId = upload.path("session_id").asText();
String mediaHashKey = upload.path("media_hash_key").asText();
EncryptMessageParams params = new EncryptMessageParams(conversationId, "a photo");
params.attachments = List.of(photoAttachment(mediaHashKey));
SendPayload payload = chat.encryptMessage(params);
byte[] encrypted = chat.encryptFile(new EncryptFileParams(photo, payload.eventB64, mediaHashKey));
api.post("/2/chat/media/upload/" + sessionId + "/append", Map.of(
        "conversation_id", conversationId, "media_hash_key", mediaHashKey,
        "segment_index", 0, "media", Base64.getEncoder().encodeToString(encrypted)));
api.post("/2/chat/media/upload/" + sessionId + "/finalize", Map.of(
        "conversation_id", conversationId, "media_hash_key", mediaHashKey, "num_parts", "1"));
```

For a large file, use
`file_encryptor(FileEncryptorParams(event_b64, media_hash_key))` instead of
`encrypt_file` and feed it with `push` / `finish`. See
[docs/API.md — Files (Media)](docs/API.md#files-media).

#### Files are decrypted from the message that carries them

`decrypt_file` and `file_decryptor` take the base64
event of the message that carries the file and the conversation's key map —
the same two values `decrypt_event` takes — plus the file's media hash key
from the decrypted message: one of its media attachments, a link card's
banner or favicon (both listed in `media_hashes`), or media quoted in its
reply preview. The SDK finds that attachment in the event and derives its
key, including for messages that encrypt each attachment under its own key.
Errors say what to pass when the key version is missing from the map, the
media hash key is not in the event, the event is not an encrypted message
with files, or the bytes are wrong or truncated.

```rust
// Rust
let plaintext = chat.decrypt_file(&DecryptFileParams::new(
    encrypted, event_b64.clone(), conversation_keys.clone(), media_hash_key.clone(),
))?;
let decryptor = chat.file_decryptor(&FileDecryptorParams::new(event_b64, conversation_keys, media_hash_key))?;
```

```python
# Python
plaintext = chat.decrypt_file(DecryptFileParams(encrypted, event_b64, conversation_keys, media_hash_key))
decryptor = chat.file_decryptor(FileDecryptorParams(event_b64, conversation_keys, media_hash_key))
```

```js
// JS / TypeScript
const plaintext = chat.decryptFile({ encrypted, eventB64, conversationKeys, mediaHashKey });
const decryptor = chat.fileDecryptor({ eventB64, conversationKeys, mediaHashKey });
```

```go
// Go
plaintext, err := chat.DecryptFile(chatxdk.DecryptFileParams{
    Encrypted: encrypted, EventB64: eventB64, ConversationKeys: conversationKeys, MediaHashKey: mediaHashKey,
})
decryptor, err := chat.FileDecryptor(chatxdk.FileDecryptorParams{
    EventB64: eventB64, ConversationKeys: conversationKeys, MediaHashKey: mediaHashKey,
})
```

```csharp
// .NET (C#)
var plaintext = chat.DecryptFile(new DecryptFileParams(encrypted, eventB64, conversationKeys, mediaHashKey));
using var decryptor = chat.FileDecryptor(new FileDecryptorParams(eventB64, conversationKeys, mediaHashKey));
```

```java
// JVM (Java)
byte[] plaintext = chat.decryptFile(new DecryptFileParams(encrypted, eventB64, conversationKeys, mediaHashKey));
FileDecryptor decryptor = chat.fileDecryptor(new FileDecryptorParams(eventB64, conversationKeys, mediaHashKey));
```

#### `decrypt_events` and `decrypt_event` take params objects

`decrypt_events` takes `DecryptEventsParams` (`events`, optional
`signing_keys`) and `decrypt_event` takes `DecryptEventParams` (`event_b64`,
optional `conversation_keys`, optional `signing_keys`), named the same in
every binding. Omitted (or, in Rust, empty), the conversation keys come from
the opt-in key cache. In .NET and the JVM, a `ConversationKeyBundle`'s
`Keys` / `keys` map is the key map they take. `decrypt_events` collects a
failure in an event in its `errors` instead of throwing, and throws only for
invalid params; `decrypt_event` throws on failure. The result holds the
decrypted events, of every event type, in `events`, each a `DecryptedEvent`
(`event`, and `original_b64` for a message). Its
`conversation_keys.latest_version`, the version to encrypt with, is the
newest version whose key change verified, monotonic for the chat's
lifetime, and absent until a key change verifies; a key change that doesn't
verify still adds its key to `conversation_keys.keys`, for decrypting.

```rust
// Rust
let result = chat.decrypt_events(&DecryptEventsParams::new(events).with_signing_keys(signing_keys.clone()));
let event = chat.decrypt_event(&DecryptEventParams::new(event_b64, keys).with_signing_keys(signing_keys))?;
```

```python
# Python
result = chat.decrypt_events(DecryptEventsParams(events, signing_keys=signing_keys))
event = chat.decrypt_event(DecryptEventParams(event_b64))
```

```js
// JS / TypeScript
const result = chat.decryptEvents({ events, signingKeys });
const event = chat.decryptEvent({ eventB64, conversationKeys: keys, signingKeys });
```

```go
// Go
result, err := chat.DecryptEvents(chatxdk.DecryptEventsParams{Events: events, SigningKeys: signingKeys})
event, err := chat.DecryptEvent(chatxdk.DecryptEventParams{EventB64: eventB64, ConversationKeys: keys, SigningKeys: signingKeys})
```

```csharp
// .NET (C#)
var result = chat.DecryptEvents(new DecryptEventsParams(events) { SigningKeys = signingKeys });
var evt = chat.DecryptEvent(new DecryptEventParams(eventB64, keys) { SigningKeys = signingKeys });
```

```java
// JVM (Java)
DecryptEventsParams batch = new DecryptEventsParams(events);
batch.signingKeys = signingKeys;
DecryptEventsResult result = chat.decryptEvents(batch);
DecryptEventParams one = new DecryptEventParams(eventB64, keys);
one.signingKeys = signingKeys;
JsonNode event = chat.decryptEvent(one);
```

#### Python takes a params class for every params method

`encrypt_message`, `encrypt_reply`, `encrypt_add_reaction`,
`encrypt_remove_reaction`, `encrypt_edit`, `prepare_conversation_key_change`,
`prepare_group_members_change`, `prepare_group_create` and
`prepare_message_delete` take a params class, as in the other bindings:
`EncryptMessageParams`, `EncryptReplyParams`, `EncryptReactionParams`,
`EncryptEditParams`, `ConversationKeyChangeParams`,
`GroupMembersChangeParams`, `GroupCreateParams` and `MessageDeleteParams`.
Each class takes its required fields positionally, as it does the event a
reply, reaction or edit targets, and the rest as keywords, and exposes every
field as a read/write attribute.

```python
payload = chat.encrypt_message(EncryptMessageParams(conversation_id, "hi", ttl_msec=60_000))
reply = chat.encrypt_reply(EncryptReplyParams(conversation_id, "pong", event_b64))
reaction = chat.encrypt_add_reaction(EncryptReactionParams(event_b64, "👍"))
edit = chat.encrypt_edit(EncryptEditParams(event_b64, "fixed text"))
prepared = chat.prepare_conversation_key_change(
    ConversationKeyChangeParams(public_keys, conversation_id=conversation_id)
)
```

#### File names and the C ABI

- The incremental file classes are `FileEncryptor` and `FileDecryptor` in
  every binding, each with `push` and `finish`.
- `encrypted_file_size` (`encryptedFileSize`, `EncryptedFileSize`) gives the
  size an upload declares before the file is encrypted.
- Rust: `crypto::encryption::{encrypt_file, decrypt_file,
  encrypted_file_size}` take a conversation key directly.
- One C ABI crate, `chat-xdk-ffi`, builds the native library of every
  binding over it: `libchat_xdk_ffi.a`, which Go links from
  `go/chatxdk/libs/<os>_<arch>/`, and `chat_xdk_ffi`
  (`libchat_xdk_ffi.so`, `libchat_xdk_ffi.dylib`, `chat_xdk_ffi.dll`),
  which the .NET package and the JVM jar load.
- The C ABI is versioned: `chat_xdk.h` defines `CHAT_XDK_ABI_VERSION` (1),
  and `chat_xdk_abi_version()` returns the library's, so a caller compares
  the two at startup. Every function returns an `FfiResult`, apart from
  `chat_xdk_abi_version` and the `_free` functions: booleans come back as
  `true` or `false` in `data` (`chat_xdk_is_unlocked`,
  `chat_xdk_has_identity_key`, `chat_xdk_verify`,
  `chat_xdk_verify_key_binding`, `chat_xdk_matches_registered_key`), and
  an error as a JSON document in `error`: `{"kind", "message"}`, plus
  `guesses_remaining` after a wrong PIN.
- `chat_xdk_new(juicebox_config_json, &chat)` creates a chat with its
  Juicebox config, or NULL for none, and writes the handle to its
  out-parameter. The Juicebox functions (`chat_xdk_update_config`,
  `chat_xdk_setup`, `chat_xdk_unlock`, `chat_xdk_change_pin`,
  `chat_xdk_delete`) are declared when `CHAT_XDK_JUICEBOX` is defined, and
  take PINs as bytes and length.
- The calls that take one params JSON document are `chat_xdk_set_identity`,
  `chat_xdk_import_keys` (the key bytes by pointer and length, beside the
  document), `chat_xdk_decrypt_events`, `chat_xdk_decrypt_event`, the
  encrypt and prepare calls, and the file calls;
  `chat_xdk_file_encryptor_new` and `chat_xdk_file_decryptor_new` write the
  handle to an out-parameter. [C ABI](docs/migrating-0.7/c-abi.md) lists
  the calls whose arguments or results differ from 0.5.x.

#### Errors carry their kind

Every failure has a kind, named the same in every binding: invalid input,
invalid state, parse, decryption, verification, invalid PIN, Juicebox, or
internal. Rust reports it as `SdkError::kind()`, an `ErrorKind`; Python as
the exception class, a `ChatXdkError` (a `ValueError`) subclass:
`InvalidInputError`, `InvalidStateError`, `ParseError`, `DecryptionError`,
`VerificationError`, `InvalidPinError` or `JuiceboxError`, each with
`kind`; JS as the `kind` of a `ChatXdkError` (`invalidInput`, …); Go as the
`Kind` of a `*chatxdk.Error`, read with `errors.As`; .NET and the JVM as the
`Kind` / `getKind()` of a `ChatXdkException`; and the C ABI as the `kind` of
its error document. After a wrong PIN, the attempts Juicebox reports left
come with the error: `guesses_remaining()` in Rust, `guesses_remaining` in
Python and the C ABI, `guessesRemaining` in JS, `GuessesRemaining` in Go
and .NET, and `getGuessesRemaining()` in the JVM.

A missing or invalid parameter fails with an error of the invalid-input
kind whose message names the value, such as `Invalid sender_id 'user-1': …`
or `too many attachments: …`, without an `Invalid state:` prefix; in Rust it
is `SdkError::InvalidInput`. That covers a key or signature `verify`,
`verify_key_binding` or `matches_registered_key` can't decode, a
conversation key or key blob of the wrong length, and an empty
`public_keys`. `SdkError::InvalidState` is left for values neither passed
nor set on the chat, such as a missing session identity, an empty key cache
or a missing Juicebox config. `export_keys` fails with an invalid-state
error when no identity key is loaded, in every binding.

#### Juicebox key storage

A chat that keeps its keys in Juicebox takes the Juicebox config the X API
returns when it's created, in every binding: `Chat::new(config)` in Rust,
`Chat(config_json)` in Python, `createChat({ juiceboxConfig, getAuthToken })`
in JS, `NewWithJuiceboxConfig(config)` in Go, `new Chat(config)` in .NET and
the JVM, and `chat_xdk_new(config, &chat)` in the C ABI. `update_config`
sets or replaces it, for first boot or refreshed tokens, and setup and
unlock take only the PIN. A chat created without a config (`Chat::default()`
in Rust, `Chat()` in Python, `createChat({ getAuthToken })` in JS, `New()`
in Go, `new Chat()` in .NET and the JVM, and `chat_xdk_new(NULL, &chat)` in
the C ABI) runs every crypto call, and until it has one, setup, unlock,
`change_pin` and `delete` fail with the same invalid-state error in every
binding: `Invalid state: no Juicebox config: pass the juicebox_config the X
API returns when you create the chat, or call update_config() first`. An
empty or blank config string is no config: creating a chat with one, or
passing one to `update_config`, fails with that error in every binding, and
Rust's `JuiceboxConfig::from_x_api_json` returns it as an `SdkError`, as it
returns an invalid-input one for a malformed config. Go,
.NET, the JVM and the C ABI take PINs as bytes the caller can zero. Python
(`setup_async`, `unlock_async`, `change_pin_async`, `delete_async`), .NET
(`SetupAsync`, …) and the JVM (`setupAsync`, …) run the Juicebox calls off
the calling thread. The PIN guess budget is the config's `max_guess_count`
in every binding. In JS, the SDK reads the config, checks a new PIN and
words a Juicebox failure as every binding does, and a chat created without
`getAuthToken` keeps its keys with `importKeys` and `exportKeys`, without
juicebox-sdk.

#### Other breaking changes

- Rust: `SendPayload` carries `event_b64` and `xdk_version` and is
  `#[non_exhaustive]`, so code outside the SDK reads its fields but can't
  build it with a struct literal.
- `SendPayload`'s encoded fields are `encoded_message_create_event` and
  `encoded_message_event_signature`, the send request's field names, in every
  binding (`encodedMessageCreateEvent` / `encodedMessageEventSignature` in JS
  and the JVM, `EncodedMessageCreateEvent` / `EncodedMessageEventSignature`
  in Go and .NET), so the request takes them as they are.
- Participant keys take the X API's names, on send and on receive. A
  prepared change carries `conversation_participant_keys`, each entry with
  `user_id`, `encrypted_conversation_key` and `public_key_version`: the
  field names the X API uses in every request that takes participant keys
  (`POST /2/chat/conversations/{id}/keys`, `/group` and `/{id}/members`, and
  `PUT /2/chat/conversations/{id}`), so apps pass the keys through
  unchanged. A decrypted `KeyChange` event carries its keys under the same
  names, as Thrift's `ConversationKeyChangeEvent` does, and one type,
  `ConversationParticipantKey`, holds them in both directions (Python
  returns dicts with those keys). The names are
  `conversationParticipantKeys` / `encryptedConversationKey` in JS and the
  JVM, and `ConversationParticipantKeys` / `EncryptedConversationKey` in Go
  and .NET.
- A `PublicKeyInput`, one participant a new conversation key is encrypted
  to, holds `user_id`, `identity_public_key` and `public_key_version`, as a
  `SigningKeyEntry` names them (`identityPublicKey` / `publicKeyVersion` in
  JS and the JVM, `IdentityPublicKey` / `PublicKeyVersion` in Go and .NET).
- Decrypted events use the names the calls take, in every binding.
  Messages and key changes carry their conversation key version as
  `conversation_key_version`, the name the X API's events and Thrift give it
  (`conversationKeyVersion` in JS, `ConversationKeyVersion` in Go). Fields
  that hold sequence ids say so, as the params that send them do: reactions
  and edits name their target `target_message_sequence_id`, deletions their
  messages `sequence_ids`, and read receipts and unread markers their
  position `seen_until_sequence_id` (`targetMessageSequenceId`,
  `sequenceIds` and `seenUntilSequenceId` in JS; `TargetMessageSequenceID`
  and `SeenUntilSequenceID` in Go). An edit's text is `updated_text`
  (`updatedText` in JS).
- Group titles and descriptions are plaintext in the API, and the SDK
  encrypts and decrypts them. `prepare_group_create` encrypts its title
  under the conversation key it creates, signs the ciphertext, and returns
  it on its `PreparedConversationChange` as `encrypted_title`
  (`encryptedTitle` in JS, `EncryptedTitle` in Go): the `group_name` the
  create request sends. `prepare_group_members_change` takes the group's
  `current_title` and `current_description` as plaintext, encrypts each
  under the key it rotates to, signs the ciphertext, and returns them as
  `encrypted_title` and `encrypted_description`; an add that carries a
  description signs at signature version 8. Titles and descriptions are
  signed as base64 ciphertext, so they may contain a comma. The title and
  description prepare calls and a member removal take the plaintext too. A
  create sets no avatar: an avatar is an image the app encrypts and
  uploads, and `prepare_group_avatar_change` signs its media URL, which no
  call encrypts. A decrypted `Created` change carries its `title`, and a
  `TitleChanged` or `DescriptionChanged` change its `new_title` or
  `new_description` (`newTitle`, `newDescription` in JS), as a `GroupText`:
  the text, decrypted with the conversation key the event names or as
  carried when it names none, or unavailable with the raw value when that
  key isn't there or the value doesn't decrypt. The event still decrypts
  either way. 0.5.x apps sent titles as plaintext while naming a key
  version, so show the raw value when a title isn't decryptable. A
  `Created` or `AvatarChanged` change carries the avatar URL as is, with
  its `conversation_key_version`. `decrypt` opens the encrypted
  `group_name` and `group_description` the X API returns with a
  conversation.
- `decrypt_event` and `decrypt_events` drop a group change that re-encrypts
  the group's title or description for a key rotation (`for_key_rotation`),
  as a member removal sends one under the new key: it carries the same text
  and isn't a change. They drop it under either reject-unverified setting,
  after verifying it, as they drop an unverified event: `decrypt_events`
  leaves it out of `events` and records it in `errors`, and `decrypt_event`
  fails with an invalid-input error. The removal itself, its key change,
  avatar changes and every title or description change without the mark
  decrypt as before. The mark sits outside the signed payload, so a relay
  that sets it on a title change can only hide that change, as it could by
  withholding the event.
- Rust: every method takes its params by reference, the decrypt and file
  calls included: `encrypt_message(&params)`, `decrypt_events(&params)`,
  `decrypt_file(&params)` and so on. `set_signing_keys` takes a slice.
  Every `ChatCore` and `Chat` method takes `&self`, `set_reject_unverified`
  and `Chat::update_config` included.
- `set_identity` and `import_keys` take a params object, as every call with
  more than one input does: `SetIdentityParams` (`user_id`,
  `signing_key_version`) and `ImportKeysParams` (`keys`, optional
  `signing_key_version`), named the same in every binding, so the
  signing-key version of imported keys goes in `ImportKeysParams`.
  `set_identity` reports invalid input (Rust returns `Result`).
- Every user id is a string of digits, validated as `sender_id` is: the
  `set_identity` user id, `reply_to_sender_id`, the `user_id` of each public
  key, and group member, admin and pending-member ids. Anything else fails
  with an error naming the field. `reply_to_sender_id` is a string of digits
  in every binding.
- Every key version takes one form, a non-negative integer as a string of
  digits, as the X API returns it: signing-key versions (in `set_identity`,
  `import_keys`, per-call `signing_key_version`, and each public key's
  `public_key_version`) are checked as `conversation_key_version` is, and a
  negative `conversation_key_version` fails. Anything else fails with an
  error naming the field.
- Action signatures come in the shape a request's `action_signatures`
  carries them: `message_id`, `encoded_message_event_detail`, and the
  signature nested under `message_event_signature` (`signature`,
  `signature_version`, `public_key_version` and `signing_public_key`, your
  signing public key as `get_public_keys` returns it). Pass
  `action_signatures` through as returned; the signed payload stays inside
  the SDK. The `MessageEventSignature` type holds the nested signature in
  every binding. `prepare_message_delete` and
  `prepare_mark_conversation_read` return a `PreparedAction`
  (`action_signatures`, one entry); read the action's `message_id` from that
  entry.
- Every binding but Rust and the C ABI makes an outbound HTTPS request when
  a chat is created: `GET https://api.x.com/2/chat/features`, in the
  background (see Added). Allow it through egress filters for v1 sends;
  blocked, sends stay v0. A chat sends v0 until the answer arrives, so its
  first sends can be v0 while the switch is on. In Node before 20.16 a
  request still in flight can delay exit until it ends, at most 2 seconds.
- .NET params documents omit a field left `null`, so an unset optional
  resolves from the session identity or key cache and an unset required
  field fails with an error naming it. .NET: `EntityDescriptor` takes its
  start, end and type, and `UrlAttachmentImageDescriptor` its media hash
  key, size and filename, in its constructor, read-only, and an
  `AttachmentDescriptor` comes only from `Media`, `UrlCard` or `Post`, so
  no descriptor defaults a required value to `""` or `0`. JVM:
  `EntityDescriptor`, `UrlAttachmentImageDescriptor`, `SigningKeyEntry` and
  `PublicKeyInput` take their required values in their constructor and keep
  them in final fields (an image's `width` and `height` stay settable), and
  an `AttachmentDescriptor` comes only from `media`, `urlCard` or `post`,
  with final fields; a `null` required value throws `NullPointerException`.
- An entity of a type the SDK doesn't know, an empty one included, fails
  the call with an invalid-input error naming it (`Invalid entity_type
  'user_mention': pass url, mention, hashtag, cashtag, email, address or
  phone_number`) instead of being left out of the message, for a message's,
  a reply's, a reply preview's and an edit's entities. A file a message
  carries, a media attachment or a URL card's banner or favicon, with an
  empty `filename` or a `filesize_bytes` of 0 or less fails the send with an
  invalid-input error naming its media hash key, since receiving clients
  discard such a file, and so does one with a negative `width` or `height`.
  Entity offsets count bytes of the text's UTF-8 encoding, `start` inclusive
  and `end` exclusive: an entity whose offsets are negative, end before they
  start or run past the end of its text fails with an invalid-input error
  naming them (`Invalid entity offsets 3..8: end is past the end of the text,
  which is 7 bytes of UTF-8`); a reply preview's entities, which index the
  quoted message's text, are checked for all but the end. A URL card with an
  empty `url` and a post attachment with neither `rest_id` nor `post_url`
  fail the same way.
- JS typings declare only what the module exports: `Chat` and `ChatCrypto`
  aren't importable, and `FileEncryptor` / `FileDecryptor`, which the module
  returns but doesn't export, are interfaces. `ChatXdkError`,
  `ChatXdkErrorKind`, `ImportKeysParams` and `DecryptedEvent` are declared.

### Fixed

- A `verify` error names the input that failed, in every binding: the public
  key, which must be a base64 P-256 public key, or the signature, which must
  be the 64-byte raw signature. Verifying needs no loaded keys.
- JS: a millisecond field (`ttlMsec`, `currentTtlMsec`, `seenAtMsec`,
  `expiresAtMsec`) takes a finite number within the safe integer range. NaN,
  an infinity or a number past that range names no instant or duration, so
  the call throws an `Invalid <method> params` error rather than signing some
  other value. A fraction is truncated toward zero.
- The Python type stub names the byte parameter of `bytes_to_base64`,
  `bytes_to_hex`, `detect_mime_type` and `detect_image_dimensions` `bytes`,
  as the functions take it, so a type checker accepts exactly the keyword the
  call accepts.
- `chat-xdk-core`'s build script watches only the `CHAT_XDK_BINDINGS`
  variable it reads, so Cargo rebuilds the crate only when its sources or
  that variable change, in this repository and in crates that depend on it.

### Security

- `decrypt_events` reports as `latest_version`, the version to encrypt with,
  only a key change whose signature verified. A key change that doesn't
  verify still adds its key for decrypting, but can't set the version a
  chat encrypts under.
- JS: where `fetch` performs the feature-switch request, the body is read as
  a stream and capped while it streams; a body the runtime can't stream is
  never read whole, and the request fails.
- The JSON of a prepared conversation change leaves out its conversation
  key in the Go, JavaScript, JVM and .NET bindings, so a request body
  serialized from the returned object never carries the key. The key stays
  on the object (`ConversationKey` / `conversationKey`) for the app to keep.
  The X API requests that take a prepared change read its participant keys,
  key version and action signatures, never the key itself. Rust's
  `PreparedConversationChange` doesn't serialize the key, Python's result is
  a dict that `json.dumps` refuses to encode because the key is bytes, and
  the C ABI returns the key in its JSON result, as the only way it hands the
  key to the caller.
- Juicebox realm requests (setup, unlock, and key deletion) go out through an
  HTTP client in `chat-xdk-core` on reqwest 0.12.28, rustls 0.23.46 (ring),
  rustls-webpki 0.103.16, webpki-roots 1.0.11, and h2 0.4.20. juicebox-sdk's
  `reqwest` feature stays off, so the build does not include reqwest 0.11.27,
  rustls 0.21.12, rustls-webpki 0.101.7, webpki-roots 0.25.4, or h2 0.3.27.
  That closes CVE-2026-111943
  ([RUSTSEC-2026-0381](https://rustsec.org/advisories/RUSTSEC-2026-0381.html),
  [RUSTSEC-2026-0382](https://rustsec.org/advisories/RUSTSEC-2026-0382.html))
  along with
  [RUSTSEC-2026-0346](https://rustsec.org/advisories/RUSTSEC-2026-0346.html),
  [RUSTSEC-2026-0349](https://rustsec.org/advisories/RUSTSEC-2026-0349.html),
  and [RUSTSEC-2026-0258](https://rustsec.org/advisories/RUSTSEC-2026-0258.html).
  The client:
  - offers HTTP/2 and HTTP/1.1 over TLS (ALPN);
  - verifies servers against the Mozilla roots bundled in webpki-roots 1.0.11
    (rustls-webpki 0.103.16 rejects the distrusted emSign intermediate keys);
  - takes proxies from `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` / `NO_PROXY`,
    then from the system proxy settings on macOS and Windows;
  - sends `X-Juicebox-Version: <juicebox version>` and
    `User-Agent: juicebox_networking/<juicebox version>` on every request;
  - applies the timeout juicebox-sdk sets on each request, or 30 seconds when
    it sets none.
- `sign` refuses data that only the SDK signs: a payload recipients verify
  as a signed event (a message, conversation-key change, group or
  conversation-metadata change, delete or read receipt), and a P-256 public
  key, whose signature by the signing key binds it as an identity key. An
  app that signed data an attacker chose could otherwise hand back a
  signature that verifies as one of those events, such as a key change to a
  key the attacker knows. The refusal is the invalid-input error each
  binding raises for a bad argument (`SdkError::InvalidInput` in Rust,
  `InvalidInputError` in Python, a `ChatXdkError` of kind `invalidInput` in
  JS, an error of kind `ErrorKindInvalidInput` in Go, a `ChatXdkException`
  of kind `InvalidInput` / `INVALID_INPUT` in .NET and the JVM, and an
  `invalid_input` error document in the C ABI).
  Any other data signs to the same signature bytes, and the SDK signs events
  on its own path, which this does not touch.

[Unreleased]: https://github.com/xdevplatform/chat-xdk/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/xdevplatform/chat-xdk/compare/v0.5.2...v0.7.0
