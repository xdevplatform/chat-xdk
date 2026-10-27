# Changelog

## Unreleased

### Fixed

The documentation matches the code: API.md, the migration guides, the
READMEs and the doc comments in every binding. Their code examples compile
against the 0.6.0 API, and the Rust crate's examples build as doctests.

The .NET `Verify` and JVM `verify` errors ask you to check the inputs that
failed: the public key, which must be a base64 P-256 signing key, and the
signature. Verifying needs no loaded keys.

In JavaScript, a millisecond field (`ttlMsec`, `currentTtlMsec`,
`seenAtMsec`, `expiresAtMsec`) takes a finite number within the safe integer
range. NaN, an infinity or a number past that range names no instant or
duration, so the call throws an `Invalid <method> params` error rather than
signing some other value. A fraction is truncated toward zero.

In every binding the feature-switch request sends and stores no cookies and
follows no redirect. A cookie the endpoint sets never reaches a later chat's
request, and a redirect counts as an answer other than 200, so the chat's
sends stay v0.

The Python type stub names the byte parameter of `bytes_to_base64`,
`bytes_to_hex`, `detect_mime_type` and `detect_image_dimensions` `bytes`, as
the functions take it, so a type checker accepts exactly the keyword the call
accepts.

### Added

Group and conversation-metadata actions should be signed before they are sent.
Each call takes one params object and returns `action_signatures` for the
request.

`prepare_group_members_remove` signs a member removal at signature version
11, binding the conversation-key version (or the literal `null` when the
call does not name one). Pass the remaining members' public keys to rotate
the conversation key in the same call. The result is a
`PreparedConversationChange`: the new key, the remaining members'
participant keys, and signatures for the removal and then the key change.
Without those keys the same type comes back with only the removal signature.
Pass them on every removal, so the removed members can't decrypt later
messages.

`prepare_group_leave` signs leaving a group: a removal of the sender, an
admin add when `promote_admin_id` names the member to promote, and a
conversation delete. Leave does not rotate the conversation key.

Title, avatar, description, admin, invite, and join changes, message-TTL
changes, and screen-capture setting changes each return a `PreparedAction`
signed at signature version 7. Screen-capture blocking signs
`EnableScreenCaptureBlocking` and `DisableScreenCaptureBlocking`. Detection
signs `EnableScreenCaptureDetection` and `DisableScreenCaptureDetection`.

A member-removal result that rotates a key carries the new conversation key
and the remaining members' participant keys. It carries no ratchet tree and
no rewrapped pin-key bundle. Sign a title, avatar, or description under the
new key with that action's prepare call, and place the signature between the
removal and the key change.

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
Other values are rejected in both formats, since v1 recipients derive
the key from the numeric id and look it up by the version.

#### Key registration sends only the public key

`generate_keypairs` returns a `PublicKeyRegistrationPayload` that carries
only `public_key`, in every binding. POST the payload as returned.

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
[docs/migrating-0.6](docs/migrating-0.6/README.md) shows its request and the
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
let plaintext = chat.decrypt_file(DecryptFileParams::new(
    encrypted, event_b64.clone(), conversation_keys.clone(), media_hash_key.clone(),
))?;
let decryptor = chat.file_decryptor(FileDecryptorParams::new(event_b64, conversation_keys, media_hash_key))?;
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
invalid params; `decrypt_event` throws on failure.

```rust
// Rust
let result = chat.decrypt_events(DecryptEventsParams::new(events).with_signing_keys(signing_keys.clone()));
let event = chat.decrypt_event(DecryptEventParams::new(event_b64, keys).with_signing_keys(signing_keys))?;
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

#### File and C ABI names

- The incremental file classes are `FileEncryptor` and `FileDecryptor` in
  every binding, each with `push` and `finish`.
- `encrypted_file_size` (`encryptedFileSize`, `EncryptedFileSize`) gives the
  size an upload declares before the file is encrypted.
- Rust: `crypto::encryption::{encrypt_file, decrypt_file,
  encrypted_file_size}` take a conversation key directly.
- C ABI: an entry point whose arguments differ from 0.5.x takes a new name,
  so a stale header or library fails to link instead of misreading its
  arguments. The file calls are `chat_xdk_encrypt_file`,
  `chat_xdk_decrypt_file`, `chat_xdk_encrypted_file_size`,
  `chat_xdk_file_encryptor_*` and `chat_xdk_file_decryptor_*`, and the
  decrypt calls are `chat_xdk_decrypt_events_params` and
  `chat_xdk_decrypt_event_params`. They and the file calls take one params
  JSON document, and `chat_xdk_file_encryptor_new` /
  `chat_xdk_file_decryptor_new` return a result and write the handle to an
  out-parameter. [C ABI](docs/migrating-0.6/c-abi.md) lists the calls that
  keep their names but take or return different JSON.

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
- Decrypted messages and key changes carry their conversation key version
  as `conversation_key_version`, the name the X API's events and Thrift give
  it (`conversationKeyVersion` in JS, `ConversationKeyVersion` in Go).
- Rust: the encrypt, prepare and file-encrypt methods take their params by
  reference: `encrypt_message(&params)` and `encrypt_reply(&params)`, like the
  reaction, edit, delete and mark-read methods, and also `encrypt_file`,
  `file_encryptor`, `prepare_conversation_key_change`, `prepare_group_create`
  and `prepare_group_members_change` (and their `_with_version` forms). Add
  `&` at each call. `decrypt_events`, `decrypt_event`, `decrypt_file` and
  `file_decryptor` take their params by value.
- `set_identity` and `import_keys` take a params object, as every call with
  more than one input does: `SetIdentityParams` (`user_id`,
  `signing_key_version`) and `ImportKeysParams` (`keys`, optional
  `signing_key_version`), named the same in every binding, so the
  signing-key version of imported keys goes in `ImportKeysParams`.
  `set_identity` reports invalid input (Rust returns `Result`). C ABI:
  `chat_xdk_set_identity_params` and `chat_xdk_import_keys_params` take a
  params JSON document, and `chat_xdk_import_keys_params` takes the key
  bytes by pointer.
- Every user id is a string of digits, validated as `sender_id` is: the
  `set_identity` user id, `reply_to_sender_id`, the `user_id` of each public
  key, and group member, admin and pending-member ids. Anything else fails
  with an error naming the field. `reply_to_sender_id` is a string of digits
  in every binding.
- Every key version takes one form, a non-negative integer as a string of
  digits, as the X API returns it: signing-key versions (in `set_identity`,
  `import_keys`, per-call `signing_key_version`, and each public key's
  `key_version`) are checked as `conversation_key_version` is, and a
  negative `conversation_key_version` fails. Anything else fails with an
  error naming the field.
- Action signatures come in the shape a request's `action_signatures`
  carries them: `message_id`, `encoded_message_event_detail`, the signature
  nested under `message_event_signature` (`signature`, `signature_version`,
  `public_key_version` and `signing_public_key`, your signing public key as
  `get_public_keys` returns it), and `signature_payload` when it is not
  withheld. Pass `action_signatures` through as returned. The
  `MessageEventSignature` type holds the nested signature in every binding.
  `prepare_message_delete` and `prepare_mark_conversation_read` return a
  `PreparedAction` (`action_signatures`, one entry); read the action's
  `message_id` from that entry. Go, .NET and the JVM omit an absent
  `signature_payload` when serializing (.NET `SignaturePayload` is `string?`
  and the JVM field is `null` when absent).
- A missing or invalid parameter fails with the message alone, such as
  `Invalid sender_id 'user-1': …` or `too many attachments: …`, without the
  `Invalid state:` prefix; in Rust it is the new `SdkError::InvalidInput`.
  `SdkError::InvalidState` is left for values neither passed nor set on the
  chat, such as a missing session identity or an empty key cache.
- Every binding but Rust makes an outbound HTTPS request when a chat is
  created: `GET https://api.x.com/2/chat/features`, in the background (see
  Added). Allow it through egress filters for v1 sends; blocked, sends stay
  v0. A chat sends v0 until the answer arrives, so its first sends can be v0
  while the switch is on. In Node before 20.16 a request still in flight can
  delay exit until it ends, at most 2 seconds.
- JS typings declare only what the module exports: `Chat` and `ChatCrypto`
  aren't importable, and `FileEncryptor` / `FileDecryptor`, which the module
  returns but doesn't export, are interfaces.

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
- Read receipts should be signed. `prepare_mark_conversation_read` takes
  `MarkConversationReadParams`: `conversation_id`, `seen_until_sequence_id`
  (the sequence id of the newest event read) and a `seen_at_msec`, which
  defaults to the current time. It returns a `PreparedAction`. Apps should
  send its `action_signatures` on the mark-read request
  (`POST /2/chat/conversations/{id}/read`) as they are, nested as the
  conversation-change requests nest theirs. Recipients on the default policy
  reject an unsigned receipt; `decrypt_event` returns a signed receipt as a
  verified `ReadReceipt`. The C ABI adds
  `chat_xdk_prepare_mark_conversation_read`.
- The JVM jar and the .NET package bundle the native library for 64-bit ARM
  Linux (`linux-arm64`) too, so both bindings run there without a library of
  your own.

### Security

- The JSON of a prepared conversation change leaves out its conversation
  key in the Go, JavaScript, JVM and .NET bindings, so a request body
  serialized from the returned object never carries the key. The key stays
  on the object (`ConversationKey` / `conversationKey`) for the app to keep.
  The X API requests that take a prepared change read its participant keys,
  key version and action signatures, never the key itself. Rust, whose
  `PreparedConversationChange` never serialized the key, and Python, whose
  result is a dict that `json.dumps` refuses to encode because the key is
  bytes, are unchanged. The C ABI returns the key in its JSON result, as the
  only way it hands the key to the caller.
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
  `ValueError` in Python, a thrown `Error` in JS, a returned `error` in Go,
  `ChatXdkException` in .NET and the JVM, `FfiResult.error` in the C ABI).
  Any other data signs to the same signature bytes, and the SDK signs events
  on its own path, which this does not touch.
