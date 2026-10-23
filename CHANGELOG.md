# Changelog

## Unreleased

To move code from 0.5.x, follow your binding's guide in
[docs/migrating-0.6](docs/migrating-0.6/README.md): each lists its changes
with before/after code, and [Why 0.6.0 changes](docs/migrating-0.6/why.md)
explains why each change was made.

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

Sends are v0 unless the X API turns v1 on, and always v0 from the Rust
crate, which does not fetch the switch. Readers need per-message-key support
for v1 sends: 0.5.x rejects each one as a signature verification failure (an
ECDSA mismatch), so upgrade readers first. Other signed actions
(conversation-key changes, group changes and deletes) still sign at version
7.

`sender_id` must be the sender's numeric user id, and
`conversation_key_version` an integer as its key-change event carries it.
Other values are now rejected in both formats, since v1 recipients derive
the key from the numeric id and look it up by the version.

#### Key registration sends only the public key

`generate_keypairs` returns a `PublicKeyRegistrationPayload` that carries
only `public_key`: `version` and `generate_version` are removed in every
binding (`Version` / `GenerateVersion` in Go and .NET, `generateVersion` in
JS). POST the payload as returned. Rust:
`ChatCore::generate_keypairs_with_version` is removed; use
`generate_keypairs`.

`generate_keypairs` no longer sets a signing-key version. After you register
the keys, call `set_identity` with your user id and the `public_key_version`
the registration returns, or pass that version as `signing_key_version` in
`ImportKeysParams` when you load saved keys. A signed action without a version fails in the SDK with
`signing_key_version is not set: pass it explicitly or call set_identity()
first`. In 0.5.x, `generate_keypairs` set a local timestamp as the version,
and signed actions were rejected unless the app called `set_identity` with
the registered version.

In the snippets, `api.post(path, body)` stands for your HTTP client: it
POSTs `body` as JSON to `https://api.x.com` + `path` and returns the parsed
response. The JS one writes keys in snake_case, and in Python `public_key`
is the `public_key` object you build from `registration.public_key`.

```js
// Before
const registration = chat.generateKeypairs();
const response = await api.post(`/2/users/${userId}/public_keys`, {
  public_key: registration.publicKey,
  version: registration.version,
  generate_version: registration.generateVersion,
});
chat.setIdentity(userId, response.data.public_key_version);
// After
const registration = chat.generateKeypairs();
const response = await api.post(`/2/users/${userId}/public_keys`, { public_key: registration.publicKey });
chat.setIdentity({ userId, signingKeyVersion: response.data.public_key_version });
```

```python
# After
registration = chat.generate_keypairs()
response = api.post(f"/2/users/{user_id}/public_keys", {"public_key": public_key})
chat.set_identity(SetIdentityParams(user_id, response["data"]["public_key_version"]))
```

Go, .NET, JVM and Rust call `SetIdentity` / `setIdentity` / `set_identity`
the same way; each binding's guide in
[docs/migrating-0.6](docs/migrating-0.6/README.md) shows its request.

#### A message with files is built before its files are encrypted

In v1 each file of a message is encrypted under its own key, derived from
the message's key and the file's attachment; in v0 every file is under the
conversation key, as in 0.5.x. Either way the file calls take the key from
the message, so the message comes first:

1. Start each file's upload with `POST /2/chat/media/upload/initialize`
   and keep the `session_id` and `media_hash_key` it returns. The upload's
   `total_bytes` is `encrypted_file_size` of the file's size.
2. Encrypt the message (`encrypt_message` / `encrypt_reply`) with
   attachments that name those media hash keys. `SendPayload` gains
   `event_b64`: the message as recipients receive it.
3. Encrypt each file with the new `encrypt_file` (whole file) or
   `file_encryptor` (incremental `push` / `finish`), passing the payload's
   `event_b64` and the file's media hash key. As `encrypt_message` does, the
   file calls take the conversation key the message was encrypted under and
   its version (`conversation_key` + `conversation_key_version`, set
   together), or resolve both from the key cache when neither is set.
4. Upload each encrypted file with
   `POST /2/chat/media/upload/{session_id}/append` and finish it with
   `POST /2/chat/media/upload/{session_id}/finalize`, then send the message.

`encrypt_stream` and `stream_encryptor`, which took only a conversation key,
are removed. The file calls need no session identity: the sender, message id
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

Migration — `api.post(path, body)` stands for your HTTP client, as in the
key registration entry above, and `photo_attachment` for your code that
builds a photo's attachment descriptor. The `append` and `finalize`
requests don't change, but they come after `encrypt_file`, which produces
the bytes they upload:

Rust

```rust
// Before
let encrypted = chat.encrypt_stream(&photo, &conversation_key)?;
let upload = api.post("/2/chat/media/upload/initialize", &serde_json::json!({
    "conversation_id": conversation_id, "total_bytes": encrypted.len(),
}))?;
let media_hash_key = upload["data"]["media_hash_key"].as_str().ok_or("no media_hash_key")?;
let mut params = EncryptMessageParams::new(conversation_id, "a photo");
params.attachments = Some(vec![photo_attachment(media_hash_key)]);
let payload = chat.encrypt_message(params)?;
// After
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
# Before
encrypted = chat.encrypt_stream(photo, conversation_key)
upload = api.post("/2/chat/media/upload/initialize", {
    "conversation_id": conversation_id, "total_bytes": len(encrypted),
})["data"]
media_hash_key = upload["media_hash_key"]
payload = chat.encrypt_message(conversation_id, "a photo", attachments=[photo_attachment(media_hash_key)])
# After
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
// Before
const encrypted = chat.encryptStream(photo, conversationKey);
const { data: upload } = await api.post("/2/chat/media/upload/initialize", {
  conversation_id: conversationId, total_bytes: encrypted.length,
});
const payload = chat.encryptMessage({
  conversationId, text: "a photo", attachments: [photoAttachment(upload.media_hash_key)],
});
// After
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
// Before
encrypted, err := chat.EncryptStream(photo, conversationKey)
response, err := api.Post("/2/chat/media/upload/initialize", map[string]any{
    "conversation_id": conversationID, "total_bytes": len(encrypted),
})
mediaHashKey := response["data"].(map[string]any)["media_hash_key"].(string)
payload, err := chat.EncryptMessage(chatxdk.EncryptMessageParams{
    ConversationID: conversationID, Text: "a photo",
    Attachments: []chatxdk.AttachmentDescriptor{photoAttachment(mediaHashKey)},
})
// After
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
// Before
var encrypted = chat.EncryptStream(photo, conversationKey);
var upload = api.Post("/2/chat/media/upload/initialize", new
{
    conversation_id = conversationId, total_bytes = encrypted.Length,
}).GetProperty("data");
var mediaHashKey = upload.GetProperty("media_hash_key").GetString()!;
var payload = chat.EncryptMessage(new EncryptMessageParams(conversationId, "a photo")
{
    Attachments = new[] { PhotoAttachment(mediaHashKey) },
});
// After
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
// Before
byte[] encrypted = chat.encryptStream(photo, conversationKey);
JsonNode upload = api.post("/2/chat/media/upload/initialize", Map.of(
        "conversation_id", conversationId, "total_bytes", encrypted.length)).path("data");
String mediaHashKey = upload.path("media_hash_key").asText();
EncryptMessageParams params = new EncryptMessageParams(conversationId, "a photo");
params.attachments = List.of(photoAttachment(mediaHashKey));
SendPayload payload = chat.encryptMessage(params);
// After
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

For a large file, replace `encrypt_file` with
`file_encryptor(FileEncryptorParams(event_b64, media_hash_key))` and feed it
with `push` / `finish` as before. See
[docs/API.md — Files (Media)](docs/API.md#files-media).

#### Files are decrypted from the message that carries them

`decrypt_stream` and `stream_decryptor`, which took only a conversation key,
are replaced by `decrypt_file` and `file_decryptor`. They take the base64
event of the message that carries the file and the conversation's key map —
the same two values `decrypt_event` takes — plus the file's media hash key
from the decrypted message: one of its media attachments, a link card's
banner or favicon (both listed in `media_hashes`), or media quoted in its
reply preview. The SDK finds that attachment in the event and derives its
key, including for messages that encrypt each attachment under its own key.
Errors say what to pass when the key version is missing from the map, the
media hash key is not in the event, the event is not an encrypted message
with files, or the bytes are wrong or truncated.

Migration:

```rust
// Rust
let plaintext = chat.decrypt_stream(&encrypted, &conversation_key)?;                 // before
let plaintext = chat.decrypt_file(DecryptFileParams::new(
    encrypted, event_b64, conversation_keys, media_hash_key,
))?;                                                                                 // after
let decryptor = chat.file_decryptor(FileDecryptorParams::new(event_b64, conversation_keys, media_hash_key))?;
```

```python
# Python
plaintext = chat.decrypt_stream(encrypted, conversation_key)  # before
plaintext = chat.decrypt_file(DecryptFileParams(encrypted, event_b64, conversation_keys, media_hash_key))  # after
decryptor = chat.file_decryptor(FileDecryptorParams(event_b64, conversation_keys, media_hash_key))
```

```js
// JS / TypeScript
const plaintext = chat.decryptStream(encrypted, conversationKey); // before
const plaintext = chat.decryptFile({ encrypted, eventB64, conversationKeys, mediaHashKey }); // after
const decryptor = chat.fileDecryptor({ eventB64, conversationKeys, mediaHashKey });
```

```go
// Go
plaintext, err := chat.DecryptStream(encrypted, conversationKey) // before
plaintext, err := chat.DecryptFile(chatxdk.DecryptFileParams{ // after
    Encrypted: encrypted, EventB64: eventB64, ConversationKeys: conversationKeys, MediaHashKey: mediaHashKey,
})
decryptor, err := chat.FileDecryptor(chatxdk.FileDecryptorParams{
    EventB64: eventB64, ConversationKeys: conversationKeys, MediaHashKey: mediaHashKey,
})
```

```csharp
// .NET (C#)
var plaintext = chat.DecryptStream(encrypted, conversationKey); // before
var plaintext = chat.DecryptFile(new DecryptFileParams(encrypted, eventB64, conversationKeys, mediaHashKey)); // after
using var decryptor = chat.FileDecryptor(new FileDecryptorParams(eventB64, conversationKeys, mediaHashKey));
```

```java
// JVM (Java)
byte[] plaintext = chat.decryptStream(encrypted, conversationKey); // before
byte[] plaintext = chat.decryptFile(new DecryptFileParams(encrypted, eventB64, conversationKeys, mediaHashKey)); // after
FileDecryptor decryptor = chat.fileDecryptor(new FileDecryptorParams(eventB64, conversationKeys, mediaHashKey));
```

#### `decrypt_events` and `decrypt_event` take params objects

`decrypt_events` takes `DecryptEventsParams` (`events`, optional
`signing_keys`) and `decrypt_event` takes `DecryptEventParams` (`event_b64`,
optional `conversation_keys`, optional `signing_keys`), named the same in
every binding. Omitted (or, in Rust, empty), the conversation keys come from
the opt-in key cache. The .NET and JVM `decryptEvent` overloads that
took a `ConversationKeyBundle` are removed; pass `bundle.Keys` /
`bundle.keys`. The contracts are as before: `decrypt_events` never throws
and `decrypt_event` throws on failure.

```rust
// Rust
let result = chat.decrypt_events(&events, &signing_keys); // before
let result = chat.decrypt_events(DecryptEventsParams::new(events).with_signing_keys(signing_keys)); // after
let event = chat.decrypt_event(event_b64, &keys, &signing_keys)?; // before
let event = chat.decrypt_event(DecryptEventParams::new(event_b64, keys).with_signing_keys(signing_keys))?; // after
```

```python
# Python
result = chat.decrypt_events(events, signing_keys)  # before
result = chat.decrypt_events(DecryptEventsParams(events, signing_keys=signing_keys))  # after
event = chat.decrypt_event(event_b64)  # before
event = chat.decrypt_event(DecryptEventParams(event_b64))  # after
```

```js
// JS / TypeScript
const result = chat.decryptEvents(events, signingKeys); // before
const result = chat.decryptEvents({ events, signingKeys }); // after
const event = chat.decryptEvent(eventB64, keys, signingKeys); // before
const event = chat.decryptEvent({ eventB64, conversationKeys: keys, signingKeys }); // after
```

```go
// Go
result, err := chat.DecryptEvents(events, signingKeys) // before
result, err := chat.DecryptEvents(chatxdk.DecryptEventsParams{Events: events, SigningKeys: signingKeys}) // after
event, err := chat.DecryptEvent(eventB64, keys, signingKeys) // before
event, err := chat.DecryptEvent(chatxdk.DecryptEventParams{EventB64: eventB64, ConversationKeys: keys, SigningKeys: signingKeys}) // after
```

```csharp
// .NET (C#)
var result = chat.DecryptEvents(events, signingKeys); // before
var result = chat.DecryptEvents(new DecryptEventsParams(events) { SigningKeys = signingKeys }); // after
var evt = chat.DecryptEvent(eventB64, keys, signingKeys); // before
var evt = chat.DecryptEvent(new DecryptEventParams(eventB64, keys) { SigningKeys = signingKeys }); // after
```

```java
// JVM (Java)
DecryptEventsResult result = chat.decryptEvents(events, signingKeys); // before
DecryptEventsParams batch = new DecryptEventsParams(events); // after
batch.signingKeys = signingKeys;
DecryptEventsResult result = chat.decryptEvents(batch);
JsonNode event = chat.decryptEvent(eventB64, keys, signingKeys); // before
DecryptEventParams one = new DecryptEventParams(eventB64, keys); // after
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
Each class takes the arguments its method took, in the same order and with
the same names and defaults, and exposes every field as a read/write
attribute.

```python
# Before
payload = chat.encrypt_message(conversation_id, "hi", ttl_msec=60_000)
reply = chat.encrypt_reply(conversation_id, "pong", event_b64)
reaction = chat.encrypt_add_reaction(event_b64, "👍")
edit = chat.encrypt_edit(event_b64, "fixed text")
prepared = chat.prepare_conversation_key_change(public_keys, conversation_id=conversation_id)
# After
payload = chat.encrypt_message(EncryptMessageParams(conversation_id, "hi", ttl_msec=60_000))
reply = chat.encrypt_reply(EncryptReplyParams(conversation_id, "pong", event_b64))
reaction = chat.encrypt_add_reaction(EncryptReactionParams(event_b64, "👍"))
edit = chat.encrypt_edit(EncryptEditParams(event_b64, "fixed text"))
prepared = chat.prepare_conversation_key_change(
    ConversationKeyChangeParams(public_keys, conversation_id=conversation_id)
)
```

#### Renames

- `StreamEncryptor` / `StreamDecryptor` are `FileEncryptor` /
  `FileDecryptor` in every binding; `push` and `finish` are unchanged.
- `encrypted_stream_size` is `encrypted_file_size` (`encryptedFileSize`,
  `EncryptedFileSize`).
- Rust: `crypto::encryption::{encrypt_stream, decrypt_stream,
  encrypted_stream_size}` are `{encrypt_file, decrypt_file,
  encrypted_file_size}`.
- C ABI: `chat_xdk_encrypt_stream`, `chat_xdk_decrypt_stream`,
  `chat_xdk_encrypted_stream_size`, `chat_xdk_stream_encryptor_*` and
  `chat_xdk_stream_decryptor_*` are `chat_xdk_encrypt_file`,
  `chat_xdk_decrypt_file`, `chat_xdk_encrypted_file_size`,
  `chat_xdk_file_encryptor_*` and `chat_xdk_file_decryptor_*`.
  `chat_xdk_decrypt_events` and `chat_xdk_decrypt_event` are
  `chat_xdk_decrypt_events_params` and `chat_xdk_decrypt_event_params`, so a
  stale header or library fails to link instead of misreading arguments. They
  and the file calls take one params JSON document, and
  `chat_xdk_file_encryptor_new` / `chat_xdk_file_decryptor_new` return a
  result and write the handle to an out-parameter.

#### Other breaking changes

- Rust: `SendPayload` gains `event_b64` and `xdk_version` and is
  `#[non_exhaustive]`, so code outside the SDK reads its fields but no longer
  builds it with a struct literal.
- `SendPayload`'s `encrypted_content` and `encoded_event_signature` are
  `encoded_message_create_event` and `encoded_message_event_signature`, the
  send request's field names, in every binding
  (`encodedMessageCreateEvent` / `encodedMessageEventSignature` in JS and
  the JVM, `EncodedMessageCreateEvent` / `EncodedMessageEventSignature` in
  Go and .NET), so the request takes them as they are.
- Participant keys take the X API's names, on send and on receive. A
  prepared change's `participant_keys` is `conversation_participant_keys`,
  and each entry's `encrypted_key` is `encrypted_conversation_key`: the
  field names the X API uses in every request that takes participant keys
  (`POST /2/chat/conversations/{id}/keys`, `/group` and `/{id}/members`, and
  `PUT /2/chat/conversations/{id}`), so apps pass the keys through unchanged
  instead of renaming them. A decrypted `KeyChange` event carries its keys
  under the same names, as Thrift's `ConversationKeyChangeEvent` does.
  `ParticipantKey` (Rust, Go, TypeScript) and `EncryptedKeyForRecipient`
  (every binding but Python) are one type, `ConversationParticipantKey`, in
  both directions. The names are `conversationParticipantKeys` /
  `encryptedConversationKey` in JS and the JVM, and
  `ConversationParticipantKeys` / `EncryptedConversationKey` in Go and .NET.
- Decrypted messages and key changes carry their conversation key version
  as `conversation_key_version`, the name the X API's events and Thrift give
  it: `key_version` is `conversation_key_version` in every binding
  (`conversationKeyVersion` in JS, `ConversationKeyVersion` in Go).
- Rust: every encrypt and prepare method takes its params by reference:
  `encrypt_message(&params)` and `encrypt_reply(&params)`, like the reaction,
  edit, delete and mark-read methods, and also `encrypt_file`,
  `file_encryptor`, `prepare_conversation_key_change`, `prepare_group_create`
  and `prepare_group_members_change` (and their `_with_version` forms). Add
  `&` at each call.
- `set_identity` and `import_keys` take a params object, as every call with
  more than one input does: `SetIdentityParams` (`user_id`,
  `signing_key_version`) and `ImportKeysParams` (`keys`, optional
  `signing_key_version`), named the same in every binding.
  `import_keys_with_version` (Rust), `ImportKeysWithVersion` (Go) and the
  version overloads of `importKeys` / `ImportKeys` (JVM, .NET) are removed,
  and Python's `import_keys` takes the version as `signing_key_version` in
  the params. `set_identity` reports invalid input (Rust returns `Result`).
  C ABI: `chat_xdk_set_identity` is `chat_xdk_set_identity_params`, and
  `chat_xdk_import_keys` and `chat_xdk_import_keys_with_version` are
  `chat_xdk_import_keys_params`, which takes the key bytes by pointer and
  the version as a params JSON document.
- Every user id is a string of digits, validated as `sender_id` is: the
  `set_identity` user id, `reply_to_sender_id`, the `user_id` of each public
  key, and group member, admin and pending-member ids. Anything else fails
  with an error naming the field. `reply_to_sender_id` is a string in every
  binding (it was an integer: `i64`, `int`, `*int64`, `long?`, `Long`, and
  `string | number` in JS).
- Every key version takes one form, a non-negative integer as a string of
  digits, as the X API returns it: signing-key versions (in `set_identity`,
  `import_keys`, per-call `signing_key_version`, and each public key's
  `key_version`) are now checked as `conversation_key_version` is, and
  `conversation_key_version` no longer accepts a negative value. Anything
  else fails with an error naming the field.
- Action signatures come in the shape a request's `action_signatures`
  carries them: `message_id`, `encoded_message_event_detail`, the signature
  nested under `message_event_signature` (`signature`, `signature_version`,
  `public_key_version` and the new `signing_public_key`, your signing public
  key as `get_public_keys` returns it), and `signature_payload` when it is
  not withheld. They were flat, with no signing public key, and apps
  re-nested them: pass `action_signatures` through as returned instead.
  The new `MessageEventSignature` type holds the nested signature in every
  binding. `prepare_message_delete` and `prepare_mark_conversation_read`
  return the new `PreparedAction` (`action_signatures`, one entry) instead
  of a single `ActionSignature`; read the action's `message_id` from that
  entry. Go, .NET and the JVM omit an absent `signature_payload` when
  serializing (.NET `SignaturePayload` is `string?` and the JVM field is
  `null` when absent).
- A missing or invalid parameter fails with the message alone, such as
  `Invalid sender_id 'user-1': …` or `too many attachments: …`, without the
  `Invalid state:` prefix; in Rust it is the new `SdkError::InvalidInput`.
  `SdkError::InvalidState` is left for values neither passed nor set on the
  chat, such as a missing session identity or an empty key cache.
- Every binding but Rust now makes an outbound HTTPS request when a chat is
  created: `GET https://api.x.com/2/chat/features`, in the background (see
  Added). Allow it through egress filters for v1 sends; blocked, sends stay
  v0. In Node before 20.16 a request still in flight can delay exit until it
  ends, at most 2 seconds.
- JS typings export only what the module exports. `Chat` and `ChatCrypto`,
  which the module never exported, no longer import, and `FileEncryptor` /
  `FileDecryptor`, which it returns but does not export, are interfaces.

### Added

- The bindings fetch the feature switches from
  `GET https://api.x.com/2/chat/features` in the background, without
  delaying or failing anything; there is nothing to call. Each chat reads
  them once, when it is created, and keeps the answer for its lifetime;
  chats created while a request is in flight share it. The request is
  anonymous; until it answers, and for the chat's lifetime if it fails or is
  blocked, sends stay v0. See "Network access" in the README.
- `SendPayload` carries `xdk_version`, the SDK version that built it
  (`xdkVersion` in JS, `XdkVersion` in Go and .NET).
- Messages encrypted under per-message keys (`contents_encryption_version`
  1 or more) decrypt, as do their reply previews, edits and files. A reply
  to such a message carries the original's key, and a v1 edit names the
  message it edits.
- Signatures verify at versions 8 through 11, in the payload layout of the
  version each carries. Versions above 11 are rejected.
- Read receipts can be signed. `prepare_mark_conversation_read` takes
  `MarkConversationReadParams`: `conversation_id`, `seen_until_sequence_id`
  (the sequence id of the newest event read) and an optional
  `seen_at_msec`, which defaults to the current time. It returns a
  `PreparedAction` whose `action_signatures` the mark-read request
  (`POST /2/chat/conversations/{id}/read`) takes as they are, nested as the
  conversation-change requests nest theirs.
  Recipients' `decrypt_event` returns a signed receipt as a verified
  `ReadReceipt`. The C ABI adds `chat_xdk_prepare_mark_conversation_read`.
- The JVM jar and the .NET package bundle the native library for 64-bit ARM
  Linux (`linux-arm64`) too, so both bindings run there without a library of
  your own.

### Security

- Juicebox realm requests run on reqwest 0.12 with rustls 0.23.46,
  rustls-webpki 0.103.16 and webpki-roots 1.0.11, replacing the reqwest 0.11
  stack that juicebox-sdk's `reqwest` feature brings in (rustls 0.21,
  rustls-webpki 0.101, webpki-roots 0.25). This fixes CVE-2026-111943
  ([RUSTSEC-2026-0381](https://rustsec.org/advisories/RUSTSEC-2026-0381.html),
  [RUSTSEC-2026-0382](https://rustsec.org/advisories/RUSTSEC-2026-0382.html))
  and [RUSTSEC-2026-0346](https://rustsec.org/advisories/RUSTSEC-2026-0346.html) /
  [RUSTSEC-2026-0349](https://rustsec.org/advisories/RUSTSEC-2026-0349.html).
  Requests carry the same headers and timeout as before.
