# Changelog

## Unreleased

### Breaking changes

#### Sends can use per-message keys

Every encrypted send (message, reply, reaction and edit) is in one of two
wire formats, and the SDK picks which:

- **v0**, the 0.5.x format: contents are encrypted under the conversation
  key, `contents_encryption_version` is unset, and the send is signed at
  signature version 7.
- **v1**, per-message keys: contents are encrypted under a key derived from
  the conversation key, the sender id and the message id, the
  `MessageCreateEvent` carries `contents_encryption_version` 1, and the send
  is signed at signature version 10, which covers that field.

Sends are v0 unless the X API turns v1 on. Readers need per-message-key
support for v1 sends, and 0.5.x returns a decryption error for each of them,
so upgrade readers first. Other signed actions (conversation-key changes,
group changes and deletes) still sign at version 7.

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
the registration returns, or pass that version to `import_keys` when you
load saved keys. A signed action without a version fails in the SDK with
`signing_key_version is not set: pass it explicitly or call set_identity()
first`. In 0.5.x, `generate_keypairs` set a local timestamp as the version,
and signed actions were rejected unless the app called `set_identity` with
the registered version.

```js
// Before
const payload = chat.generateKeypairs(); // carried version and generateVersion
await registerPublicKey(userId, payload);
// After
const payload = chat.generateKeypairs(); // carries publicKey only
const publicKeyVersion = await registerPublicKey(userId, payload); // the public_key_version the X API returns
chat.setIdentity(userId, publicKeyVersion);
```

```python
# After
payload = chat.generate_keypairs()
public_key_version = register_public_key(user_id, payload)
chat.set_identity(user_id, public_key_version)
```

Go, .NET, JVM and Rust call `SetIdentity` / `setIdentity` / `set_identity`
the same way.

#### A message with files is built before its files are encrypted

Each file of a message is encrypted under its own key, derived from the
message's key and the file's attachment, so the message comes first:

1. Start each file's upload and keep its media hash key. The upload's total
   size is `encrypted_file_size` of the file's size.
2. Encrypt the message (`encrypt_message` / `encrypt_reply`) with
   attachments that name those media hash keys. `SendPayload` gains
   `event_b64`: the message as recipients receive it.
3. Encrypt each file with the new `encrypt_file` (whole file) or
   `file_encryptor` (incremental `push` / `finish`), passing the payload's
   `event_b64`, the conversation's key map and the file's media hash key.
4. Finish the uploads and send the message.

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

Migration — `start_upload` / `finish_upload` stand for your media upload
calls (initialize, then append and finalize):

Rust

```rust
// Before
let encrypted = chat.encrypt_stream(&photo, &conversation_key)?;
let media_hash_key = upload(&encrypted)?;
let mut params = EncryptMessageParams::new(conversation_id, "a photo");
params.attachments = Some(photo_attachments(&media_hash_key));
let payload = chat.encrypt_message(params)?;
// After
let size = chat_xdk_core::utils::encrypted_file_size(photo.len() as u64).unwrap();
let (session, media_hash_key) = start_upload(size)?;
let mut params = EncryptMessageParams::new(conversation_id, "a photo");
params.attachments = Some(photo_attachments(&media_hash_key));
let payload = chat.encrypt_message(params)?;
let encrypted = chat.encrypt_file(EncryptFileParams::new(
    photo, &payload.event_b64, conversation_keys, &media_hash_key,
))?;
finish_upload(session, &encrypted)?;
```

Python

```python
# Before
encrypted = chat.encrypt_stream(photo, conversation_key)
media_hash_key = upload(encrypted)
payload = chat.encrypt_message(conversation_id, "a photo", attachments=photo_attachments(media_hash_key))
# After
session, media_hash_key = start_upload(encrypted_file_size(len(photo)))
payload = chat.encrypt_message(
    EncryptMessageParams(conversation_id, "a photo", attachments=photo_attachments(media_hash_key))
)
encrypted = chat.encrypt_file(EncryptFileParams(photo, payload.event_b64, conversation_keys, media_hash_key))
finish_upload(session, encrypted)
```

JS / TypeScript

```js
// Before
const encrypted = chat.encryptStream(photo, conversationKey);
const mediaHashKey = await upload(encrypted);
const payload = chat.encryptMessage({ conversationId, text: "a photo", attachments: photoAttachments(mediaHashKey) });
// After
const { session, mediaHashKey } = await startUpload(encryptedFileSize(photo.length));
const payload = chat.encryptMessage({ conversationId, text: "a photo", attachments: photoAttachments(mediaHashKey) });
const encrypted = chat.encryptFile({ file: photo, eventB64: payload.eventB64, conversationKeys, mediaHashKey });
await finishUpload(session, encrypted);
```

Go

```go
// Before
encrypted, err := chat.EncryptStream(photo, conversationKey)
mediaHashKey, err := upload(encrypted)
payload, err := chat.EncryptMessage(chatxdk.EncryptMessageParams{
    ConversationID: conversationID, Text: "a photo", Attachments: photoAttachments(mediaHashKey),
})
// After
size, err := chatxdk.EncryptedFileSize(uint64(len(photo)))
session, mediaHashKey, err := startUpload(size)
payload, err := chat.EncryptMessage(chatxdk.EncryptMessageParams{
    ConversationID: conversationID, Text: "a photo", Attachments: photoAttachments(mediaHashKey),
})
encrypted, err := chat.EncryptFile(chatxdk.EncryptFileParams{
    File: photo, EventB64: payload.EventB64, ConversationKeys: conversationKeys, MediaHashKey: mediaHashKey,
})
err = finishUpload(session, encrypted)
```

.NET (C#)

```csharp
// Before
var encrypted = chat.EncryptStream(photo, conversationKey);
var mediaHashKey = await UploadAsync(encrypted);
var payload = chat.EncryptMessage(new EncryptMessageParams(conversationId, "a photo") { Attachments = PhotoAttachments(mediaHashKey) });
// After
var (session, mediaHashKey) = await StartUploadAsync(ChatXdkUtilities.EncryptedFileSize((ulong)photo.Length));
var payload = chat.EncryptMessage(new EncryptMessageParams(conversationId, "a photo") { Attachments = PhotoAttachments(mediaHashKey) });
var encrypted = chat.EncryptFile(new EncryptFileParams(photo, payload.EventB64, conversationKeys, mediaHashKey));
await FinishUploadAsync(session, encrypted);
```

JVM (Java)

```java
// Before
byte[] encrypted = chat.encryptStream(photo, conversationKey);
String mediaHashKey = upload(encrypted);
EncryptMessageParams params = new EncryptMessageParams(conversationId, "a photo");
params.attachments = photoAttachments(mediaHashKey);
SendPayload payload = chat.encryptMessage(params);
// After
Upload upload = startUpload(ChatXdkUtilities.encryptedFileSize(photo.length));
EncryptMessageParams params = new EncryptMessageParams(conversationId, "a photo");
params.attachments = photoAttachments(upload.mediaHashKey());
SendPayload payload = chat.encryptMessage(params);
byte[] encrypted = chat.encryptFile(
        new EncryptFileParams(photo, payload.eventB64, conversationKeys, upload.mediaHashKey()));
finishUpload(upload, encrypted);
```

For a large file, replace `encrypt_file` with
`file_encryptor(FileEncryptorParams(event_b64, conversation_keys, media_hash_key))`
and feed it with `push` / `finish` as before. See
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
`conversation_keys`, optional `signing_keys`), named the same in every
binding. The conversation key map is required: pass an empty map to fall
back to the opt-in key cache. The .NET and JVM `decryptEvent` overloads that
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
event = chat.decrypt_event(DecryptEventParams(event_b64, {}))  # after
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
Each class takes the required fields positionally and the optional ones as
keywords, with the names the methods took, and exposes every field as a
read/write attribute.

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

### Added

- Each chat fetches its feature switches from `GET /2/chat/features` in the
  background, without delaying or failing anything; there is nothing to call.
- `SendPayload` carries `xdk_version`, the SDK version that built it
  (`xdkVersion` in JS, `XdkVersion` in Go and .NET). Do not send it yet: the
  send request takes it as an optional `xdk_version` field only once the X
  API documents that field.
- Messages encrypted under per-message keys (`contents_encryption_version`
  1 or more) decrypt, as do their reply previews, edits and files. A reply
  to such a message carries the original's key, and an edit names the
  message it edits.
- Signatures verify at versions 8 through 11, in the payload layout of the
  version each carries. Versions above 11 are rejected.
- Read receipts can be signed. `prepare_mark_conversation_read` takes
  `MarkConversationReadParams`: `conversation_id`, `seen_until_sequence_id`
  (the sequence id of the newest event read) and an optional
  `seen_at_msec`, which defaults to the current time. It returns an
  `ActionSignature`; send it with the mark-read request, as you send a
  message delete's signature. Recipients' `decrypt_event` returns the
  receipt as a verified `ReadReceipt`. The C ABI adds
  `chat_xdk_prepare_mark_conversation_read`.
