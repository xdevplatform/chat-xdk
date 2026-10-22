# Migrating from 0.5.x to 0.6.0

This guide moves code written against chat-xdk 0.5.0, 0.5.1 or 0.5.2 to
0.6.0 in every binding: Rust, Python, JavaScript/WASM, Go, JVM, .NET and the
C ABI. The [CHANGELOG](../CHANGELOG.md) lists every change; this guide groups
them by task and shows the code. The API itself is documented in
[API.md](API.md).

- [Before you upgrade](#before-you-upgrade)
- [The changes at a glance](#the-changes-at-a-glance)
- [Send formats: v0 and v1](#send-formats-v0-and-v1)
- [Key registration](#key-registration)
- [Session identity and saved keys](#session-identity-and-saved-keys)
- [User ids and key versions](#user-ids-and-key-versions)
- [Decrypting events](#decrypting-events)
- [Sending messages](#sending-messages)
- [Files](#files)
- [Key changes, groups and deletes](#key-changes-groups-and-deletes)
- [Signed read receipts (new, pending)](#signed-read-receipts-new-pending)
- [Errors](#errors)
- [The feature-switch request](#the-feature-switch-request)
- [Binding by binding](#binding-by-binding): [Rust](#rust),
  [Python](#python), [JavaScript / WASM](#javascript--wasm), [Go](#go),
  [JVM](#jvm), [.NET](#net), [C ABI](#c-abi)

## Before you upgrade

1. **Upgrade every app that reads your conversations before v1 sends
   start.** 0.6.0 can send in a new format (v1, per-message keys) once the X
   API turns it on, and 0.5.x rejects v1 sends. See
   [Send formats](#send-formats-v0-and-v1).
2. **Decide about egress.** Every binding except Rust and the raw C ABI now
   makes an anonymous background request to `api.x.com`. Blocking it keeps
   your sends v0. See [The feature-switch request](#the-feature-switch-request).
3. **Plan the media change.** A message with files is now built before its
   files are encrypted, and each file is encrypted from that message. This
   reorders your upload code. See [Files](#files).
4. **Check the ids and versions you pass.** User ids must be strings of
   digits and key versions integers written as strings; anything else is
   now rejected. See [User ids and key versions](#user-ids-and-key-versions).

## The changes at a glance

| Area | What changes | Bindings |
|---|---|---|
| Key registration | The registration payload carries only `public_key`; call `set_identity` with the version the X API returns | all |
| Identity and keys | `set_identity` and `import_keys` take params objects | all |
| Ids and versions | User ids are digit strings and key versions integer strings, validated everywhere; `reply_to_sender_id` is a string | all |
| Decrypting | `decrypt_events` and `decrypt_event` take params objects | all |
| Sending | Python takes a params class for every params method; Rust takes `&params`; `SendPayload`'s fields take the send request's names | all |
| Files | The message comes first; `encrypt_file` / `decrypt_file` and the `File*` encryptors replace the stream calls | all |
| Signed actions | Signatures come nested under `message_event_signature`, with your signing public key; deletes return a `PreparedAction` | all |
| Errors | Invalid input fails with the message alone (`SdkError::InvalidInput` in Rust) | all |
| Network | Each chat fetches feature switches in the background; release chats when you're done | all but Rust and the C ABI |
| New | Signed read receipts (the X API route is pending), `xdk_version` (don't send it yet) | all |

## Send formats: v0 and v1

0.6.0 sends every encrypted message, reply, reaction and edit in one of two
formats:

- **v0** is the format 0.5.x sends: contents are encrypted under the
  conversation key and signed at signature version 7. Message ids are
  random, attachments carry no id, and an edit does not name the message it
  edits.
- **v1** encrypts contents under a per-message key derived from the
  conversation key, the sender id and the message id. The
  `MessageCreateEvent` carries `contents_encryption_version` 1 and the send
  is signed at signature version 10. A message with files takes an id
  derived from them, each attachment carries an id, and an edit names the
  message it edits.

A chat sends v0 unless the X API's `v1_send` feature switch is on (see
[The feature-switch request](#the-feature-switch-request)). The Rust crate
and direct C ABI callers never fetch the switch, so they always send v0.
Until the X API serves the switch, every binding sends v0.

0.6.0 reads both formats, and verifies signatures up to version 11; higher
versions are rejected. 0.5.x rejects a v1 send as a signature verification
failure, so in a 0.5.x reader's logs v1 sends look like forged messages.
Upgrade readers first.

To see which format a send used, read the payload's
`signature_info.signature_version`: `"7"` for v0, `"10"` for v1. Other signed
actions (key changes, group changes, deletes and read receipts) are signed at
version 7.

## Key registration

`generate_keypairs` returns a `PublicKeyRegistrationPayload` that carries only
`public_key`. Its `version` and `generate_version` fields are removed
(`Version` / `GenerateVersion` in Go and .NET, `version` / `generateVersion`
in JS and the JVM). POST the payload to `POST /2/users/:id/public_keys` as
returned.

0.6.0 doesn't set a signing-key version when it generates keys. After you
register, call `set_identity` with your user id and the `public_key_version`
the registration returns; a signed call without a version fails with an
error naming `signing_key_version`. In Rust,
`ChatCore::generate_keypairs_with_version` is removed; use
`generate_keypairs`.

```python
registration = chat.generate_keypairs()  # carries public_key only
public_key_version = register_public_key(user_id, registration)  # the version the X API returns
chat.set_identity(SetIdentityParams(user_id, public_key_version))
```

```js
const registration = chat.generateKeypairs(); // carries publicKey only
const publicKeyVersion = await registerPublicKey(userId, registration); // the version the X API returns
chat.setIdentity({ userId, signingKeyVersion: publicKeyVersion });
```

Rust, Go, the JVM and .NET call `set_identity` / `SetIdentity` / `setIdentity`
the same way, with a `SetIdentityParams` (see the next section).

## Session identity and saved keys

`set_identity` takes a `SetIdentityParams` (`user_id`, `signing_key_version`)
and `import_keys` takes an `ImportKeysParams` (`keys`, optional
`signing_key_version`), named the same in every binding. Both validate the
user id and the version (see the next section); Rust's `set_identity` now
returns a `Result`.

| Binding | 0.5.x | 0.6.0 |
|---|---|---|
| Rust | `chat.set_identity(user_id, version)` | `chat.set_identity(&SetIdentityParams::new(user_id, version))?` |
| | `chat.import_keys_with_version(&keys, version)?` | `chat.import_keys(&ImportKeysParams::new(keys).with_signing_key_version(version))?` |
| Python | `chat.set_identity(user_id, version)` | `chat.set_identity(SetIdentityParams(user_id, version))` |
| | `chat.import_keys(keys, version)` | `chat.import_keys(ImportKeysParams(keys, signing_key_version=version))` |
| JS | `chat.setIdentity(userId, version)` | `chat.setIdentity({ userId, signingKeyVersion: version })` |
| Go | `chat.SetIdentity(userID, version)` | `chat.SetIdentity(chatxdk.SetIdentityParams{UserID: userID, SigningKeyVersion: version})` |
| | `chat.ImportKeysWithVersion(keys, version)` | `chat.ImportKeys(chatxdk.ImportKeysParams{Keys: keys, SigningKeyVersion: version})` |
| JVM | `chat.setIdentity(userId, version)` | `chat.setIdentity(new SetIdentityParams(userId, version))` |
| | `chat.importKeys(keys, version)` | `chat.importKeys(new ImportKeysParams(keys, version))` |
| .NET | `chat.SetIdentity(userId, version)` | `chat.SetIdentity(new SetIdentityParams(userId, version))` |
| | `chat.ImportKeys(keys, version)` | `chat.ImportKeys(new ImportKeysParams(keys) { SigningKeyVersion = version })` |
| C ABI | `chat_xdk_set_identity(chat, user_id, version)` | `chat_xdk_set_identity_params(chat, "{\"user_id\":\"…\",\"signing_key_version\":\"…\"}")` |
| | `chat_xdk_import_keys_with_version(chat, keys, len, version)` | `chat_xdk_import_keys_params(chat, keys, len, "{\"signing_key_version\":\"…\"}")` |

Importing keys without a version still works (`ImportKeysParams(keys)`,
`ImportKeysParams{Keys: keys}`, `"{}"` in the C ABI); set the identity before
the first signed call. The JS package loads keys through `unlock(pin)`, which
doesn't change. Rust's `import_keys(&[u8])` and the C ABI's
`chat_xdk_import_keys(chat, keys_b64)` are replaced by the same params forms.

## User ids and key versions

**Every user id is a string of digits**: the `set_identity` user id,
`sender_id`, `reply_to_sender_id`, the `user_id` of each public key, and group
member, admin and pending-member ids. Each must be a positive integer written
without a sign or leading zeros; anything else fails with an error naming the
field, such as `Invalid sender_id 'user-1': pass a numeric user id (digits
only)`.

**Every key version is a non-negative integer written as a string of
digits**, as the X API returns it: the signing-key version (in
`set_identity`, `import_keys`, per call, and each public key's `key_version`)
and the `conversation_key_version`. A negative conversation key version is
no longer accepted.

`reply_to_sender_id` changes type in every binding:

| Rust | Python | JS | Go | JVM | .NET |
|---|---|---|---|---|---|
| `Option<i64>` → `Option<String>` | `int` → `str` | `string \| number` → `string` | `*int64` → `string` | `Long` → `String` | `long?` → `string?` |

JS rejects a number for any user id: ids pass 2^53, where JS numbers stop
being exact.

## Decrypting events

`decrypt_events` takes a `DecryptEventsParams` (`events`, optional
`signing_keys`) and `decrypt_event` a `DecryptEventParams` (`event_b64`,
optional `conversation_keys`, optional `signing_keys`), named the same in every
binding. The contracts don't change: `decrypt_events` never throws and
collects per-event errors, and `decrypt_event` throws on failure.

- Omitted conversation keys (an empty map in Rust, `nil` in Go) come from the
  opt-in key cache (`set_cache_keys`), and omitted signing keys from the keys
  `set_signing_keys` stored, as before.
- The .NET and JVM `DecryptEvent` / `decryptEvent` overloads that took a
  `ConversationKeyBundle` are removed: pass `bundle.Keys` / `bundle.keys`.
- In Python, `signing_keys` is keyword-only:
  `DecryptEventParams(event_b64, keys, signing_keys=signing_keys)`.
- The C ABI's `chat_xdk_decrypt_events` and `chat_xdk_decrypt_event` are
  `chat_xdk_decrypt_events_params` and `chat_xdk_decrypt_event_params`, each
  taking one params JSON document.

Both calls also read v1 messages and their reply previews, edits and files.

## Sending messages

**Params.** Python's encrypt and prepare methods take a params class, like the
other bindings (see [Python](#python)). Rust's `encrypt_message`,
`encrypt_reply`, `encrypt_file`, `file_encryptor` and the
`prepare_*` methods (and their `_with_version` forms) take the params by
reference: add `&`. The other bindings' encrypt calls keep their shape.

**`SendPayload`** fields take the send request's names, with each binding's
casing:

| 0.5.x | 0.6.0 | The send request's field |
|---|---|---|
| `encrypted_content` | `encoded_message_create_event` | `encoded_message_create_event` |
| `encoded_event_signature` | `encoded_message_event_signature` | `encoded_message_event_signature` |

JS and the JVM name them `encodedMessageCreateEvent` /
`encodedMessageEventSignature`, and Go and .NET `EncodedMessageCreateEvent` /
`EncodedMessageEventSignature`. Send `message_id` with them as before.

`SendPayload` also gains two fields:

- `event_b64`: the outgoing message as a base64 event, what recipients
  receive. Keep it to encrypt the message's files (see [Files](#files)); it
  is not a field of the send request.
- `xdk_version`: the SDK version that built the payload. Don't send it yet:
  the send request takes it as an optional field only once the X API
  documents that field.

In Rust, `SendPayload` is `#[non_exhaustive]`: code outside the SDK reads its
fields but can no longer build it with a struct literal.

**Payloads you stored.** A payload serialized under the 0.5.x names still
deserializes: Rust (serde aliases), Go (`json.Unmarshal`), .NET
(`System.Text.Json`) and the JVM (Jackson) read `encrypted_content` and
`encoded_event_signature` into the new fields, and leave `event_b64` and
`xdk_version` empty. The Python and JS SDKs never read a payload back, so
rename the keys in anything you stored yourself.

Message ids are unchanged for v0: each send gets a random id. In v1 a message
with files takes an id derived from them (see [Files](#files)).

## Files

### Sending a file

The message is built before its files are encrypted, and each file is
encrypted under a key derived from the message and its attachment:

1. Start each file's upload and keep its media hash key. Declare the
   upload's total size as `encrypted_file_size` of the file's size
   (`encryptedFileSize` / `EncryptedFileSize`).
2. Encrypt the message (`encrypt_message` / `encrypt_reply`) with
   attachments that name those media hash keys.
3. Encrypt each file with `encrypt_file` (whole file) or `file_encryptor`
   (incremental `push` / `finish`), passing the payload's `event_b64`, the
   file's media hash key, and the conversation key and version the message
   was encrypted under (or neither, to resolve them from the key cache).
4. Finish the uploads, then send the message.

`encrypt_stream` and `stream_encryptor`, which took only a conversation key,
are removed. The file calls need no session identity: the sender, message id
and key version come from `event_b64`.

Upload each file for one message only. In v1 the id of a message with files
is derived from the conversation key and its version, the sender, the
conversation and the files' media hash keys, not from the text: building the
same message again gives the same id, so files you already encrypted for it
stay valid, but a second message that reuses the first one's uploads gets
the same id, and recipients drop it as a repeat. A message that lists an
empty media hash key, or one media hash key in two attachments, is rejected.

### Receiving a file

`decrypt_stream` and `stream_decryptor` are replaced by `decrypt_file` and
`file_decryptor`. Pass the downloaded bytes, the base64 event of the message
that carries the file and the conversation's key map (the two values
`decrypt_event` takes), and the file's media hash key from the decrypted
message: one of its media attachments, a link card's banner or favicon (both
listed in `media_hashes`), or media quoted in its reply preview. The SDK finds
that attachment in the event and derives the file's key; it doesn't check the
message's signature, so use `verified` from `decrypt_event`.

### Renames

| 0.5.x | 0.6.0 |
|---|---|
| `StreamEncryptor` / `StreamDecryptor` | `FileEncryptor` / `FileDecryptor` (`push` and `finish` unchanged) |
| `encrypted_stream_size` (added in 0.5.1) | `encrypted_file_size` (`encryptedFileSize`, `EncryptedFileSize`) |
| Rust `crypto::encryption::{encrypt_stream, decrypt_stream, encrypted_stream_size}` | `{encrypt_file, decrypt_file, encrypted_file_size}` |
| Rust `utils::encrypted_stream_size` | `utils::encrypted_file_size` |

The C ABI's file entry points are listed under [C ABI](#c-abi).

## Key changes, groups and deletes

**Action signatures come in the request's shape.** Every prepare method
returns its signed actions as `action_signatures` entries shaped like this,
which the request takes as they are:

```json
{
  "message_id": "…",
  "encoded_message_event_detail": "…",
  "message_event_signature": {
    "signature": "…",
    "signature_version": "7",
    "public_key_version": "…",
    "signing_public_key": "…"
  },
  "signature_payload": "…"
}
```

In 0.5.x an entry carried `signature`, `signature_version` and
`public_key_version` flat, without the signing public key, and apps nested
them. Drop that code and pass the entries through.

- `signing_public_key` is your signing public key as `get_public_keys`
  returns it.
- `signature_payload` (the signed payload, a debugging aid) is omitted for
  conversation-key changes, whose payload embeds the plaintext key. Go,
  .NET and the JVM omit it when serializing too: .NET's `SignaturePayload` is
  a `string?` and the JVM field is `null` when it is absent.
- The nested signature is a new `MessageEventSignature` type in every binding
  (`signatures::MessageEventSignature` in Rust).
- JS returns these objects camelCased (`actionSignatures`,
  `messageEventSignature`, `signingPublicKey`), as everywhere in JS; a
  hand-built JSON body uses the snake_case names above.

**Deletes return a `PreparedAction`.** `prepare_message_delete` returns a
`PreparedAction` (`action_signatures` with one entry) instead of a single
`ActionSignature`. Read the action's `message_id` from that entry
(`action_signatures[0].message_id`).

**Participant keys are unchanged.** A prepared change's `participant_keys`
entries are still `user_id`, `encrypted_key` and `public_key_version`. The key
change request names the list `conversation_participant_keys` and the key
`encrypted_conversation_key`, so keep mapping them as in 0.5.x.

## Signed read receipts (new, pending)

`prepare_mark_conversation_read` signs a read receipt. It takes a
`MarkConversationReadParams` (`conversation_id`, `seen_until_sequence_id` —
the sequence id of the newest event read — and an optional `seen_at_msec`,
which defaults to the current time) and returns a `PreparedAction`, nested as
the conversation-change requests nest theirs. A recipient's `decrypt_event`
returns a signed receipt as a verified `ReadReceipt`.

**Pending:** the X API's mark-read route does not take `action_signatures`
yet, so the shape of that request may change when it does. Check the X API
reference before sending them.

```python
receipt = chat.prepare_mark_conversation_read(MarkConversationReadParams(conversation_id, seen_until_sequence_id))
action_signatures = receipt["action_signatures"]  # pending: the mark-read route doesn't take them yet
```

```js
const receipt = chat.prepareMarkConversationRead({ conversationId, seenUntilSequenceId });
const actionSignatures = receipt.actionSignatures; // pending: the mark-read route doesn't take them yet
```

The method is `prepare_mark_conversation_read` in Rust,
`PrepareMarkConversationRead` in Go and .NET, and
`prepareMarkConversationRead` on the JVM, each with a
`MarkConversationReadParams`; the C ABI adds
`chat_xdk_prepare_mark_conversation_read`.

## Errors

- A missing or invalid parameter fails with the message alone, such as
  `Invalid sender_id 'user-1': …` or `too many attachments: …`, without the
  `Invalid state:` prefix. In Rust it is the new `SdkError::InvalidInput`;
  `SdkError::InvalidState` is left for values neither passed nor set on the
  chat, such as a missing session identity or an empty key cache. Update any
  code that matches on the prefix.
- Each binding raises the same error type as before: Python `ValueError`, JS a
  thrown `Error`, Go a returned `error`, .NET and the JVM `ChatXdkException`.
- JVM: the new file calls (`encryptFile`, `decryptFile`, `fileEncryptor`,
  `fileDecryptor`) declare no checked exceptions, like the stream calls they
  replace, and throw the unchecked `ChatXdkException`. `setIdentity` and
  `importKeys` also throw it, on invalid input. Methods that declared
  `throws Exception` in 0.5.x still do.

## The feature-switch request

Each chat in the Python, JS, Go, JVM and .NET bindings makes one kind of
request: an anonymous `GET https://api.x.com/2/chat/features`, which reads
the X API's feature switches. Nothing calls it; it runs in the background:

- when a chat is created, again once keys load (with a `bucket` query
  parameter, 0–9999, derived from the identity public key), and every
  5 minutes after that;
- chats in one process that ask for the same bucket at the same time share
  one request;
- it carries no credentials, and never delays or fails an SDK call;
- if it fails or is blocked, every switch stays off and sends stay v0; a
  failed request is retried with a backoff that grows to 5 minutes;
- the 5-minute re-checks can only turn a switch off: a chat that is already
  running picks up a switch turning on only when it is created again.

**Pending:** the X API doesn't serve this route yet. Until it does, the
request fails and every send is v0.

**Egress.** Allow outbound HTTPS to `api.x.com` for this route if you want
your sends to follow the switch; block it to keep them v0. In browsers the
request is a cross-origin `GET`, and a failed one keeps sends v0 too.

**Release each chat when you're done with it** to stop its requests: `free()`
in JS, `close()` in Python and the JVM, `Close()` in Go, `Dispose()` in .NET.
A garbage-collected chat stops too. The request never keeps a process alive,
except in Node before 20.16, where one in flight can delay exit by a few
seconds unless you call `free()`. In Python, `chat_xdk.Chat` is a Python
subclass of the native class, and each instance runs a daemon thread for the
request; the new `Chat.close()` stops it.

The Rust crate and the raw C ABI never make the request, so their sends are
always v0.

## Binding by binding

Each section lists what changed in that binding, then shows the main paths
in 0.5.x and in 0.6.0: loading keys and setting the identity, decrypting,
sending a message and a reply, sending and receiving a file, preparing a key
change, and preparing a delete.

The snippets use placeholders for your data: the private key bytes, the user
id and its registered signing-key version, a batch of events with the
participants' signing keys, a delivered event (`event_b64`), a conversation
key with its version, the participants' public keys, and the sequence ids to
delete. `start_upload`, `upload`, `finish_upload` and `photo_attachment`
stand for your media upload calls and your attachment descriptor, which
doesn't change. `downloaded`, `file_event_b64` and `file_hash_key` are a
downloaded file, the event of the message that carries it, and its media
hash key. Building the HTTP requests is up to your code, as before.

### Rust

| 0.5.x | 0.6.0 |
|---|---|
| `import_keys(&[u8])`, `import_keys_with_version(&[u8], &str)` | `import_keys(&ImportKeysParams)` |
| `set_identity(user_id, version)` | `set_identity(&SetIdentityParams) -> Result<(), SdkError>` |
| `ChatCore::generate_keypairs_with_version(&str)` | removed |
| `decrypt_events(&[&str], &[SigningKeyEntry])` | `decrypt_events(DecryptEventsParams)` |
| `decrypt_event(&str, &HashMap<…>, &[SigningKeyEntry])` | `decrypt_event(DecryptEventParams)` |
| `encrypt_message(params)`, `encrypt_reply(params)` | `encrypt_message(&params)`, `encrypt_reply(&params)` |
| `prepare_conversation_key_change`, `prepare_group_create`, `prepare_group_members_change` (and `_with_version`) by value | by reference |
| `encrypt_stream(&[u8], &XChatConversationKey)`, `stream_encryptor(&XChatConversationKey)` | `encrypt_file(&EncryptFileParams)`, `file_encryptor(&FileEncryptorParams)` |
| `decrypt_stream(&[u8], &XChatConversationKey)`, `stream_decryptor(&XChatConversationKey)` | `decrypt_file(DecryptFileParams)`, `file_decryptor(FileDecryptorParams)` |
| `prepare_message_delete(&MessageDeleteParams) -> ActionSignature` | `-> PreparedAction` |
| `ActionSignature { signature, signature_version, public_key_version, .. }` | `ActionSignature { message_event_signature: MessageEventSignature, .. }` |
| `SendPayload { encrypted_content, encoded_event_signature, .. }` | `encoded_message_create_event`, `encoded_message_event_signature`, plus `event_b64` and `xdk_version`; `#[non_exhaustive]` |
| `PublicKeyRegistrationPayload { version, generate_version, .. }` | removed fields |
| `EncryptReplyParams::reply_to_sender_id: Option<i64>` | `Option<String>` |
| `SdkError::InvalidState` for invalid input | `SdkError::InvalidInput` |
| — | `prepare_mark_conversation_read(&MarkConversationReadParams)` |

`Chat` (with Juicebox) has the same methods as `ChatCore`, plus its key
storage calls (`setup`, `unlock` and the rest). The crate never fetches
feature switches, so it always sends v0.

0.5.x:

```rust
use chat_xdk_core::{
    ChatCore, ConversationKeyChangeParams, EncryptMessageParams, EncryptReplyParams,
    MessageDeleteParams,
};

let chat = ChatCore::new();
chat.import_keys_with_version(&private_keys, signing_key_version)?;
chat.set_identity(user_id, signing_key_version);

// Decrypt
let result = chat.decrypt_events(&events, &signing_keys);
let keys = result.conversation_keys.keys.clone();
let event = chat.decrypt_event(event_b64, &keys, &signing_keys)?;

// Send
let payload = chat.encrypt_message(
    EncryptMessageParams::new(conversation_id, "hello")
        .with_conversation_key(conversation_key.clone(), conversation_key_version),
)?;
let body = serde_json::json!({
    "message_id": payload.message_id,
    "encoded_message_create_event": payload.encrypted_content,
    "encoded_message_event_signature": payload.encoded_event_signature,
});
let reply = chat.encrypt_reply(
    EncryptReplyParams::new(conversation_id, "pong", event_b64)
        .with_conversation_key(conversation_key.clone(), conversation_key_version),
)?;

// Send a file: encrypt it under the conversation key, upload it, then build the message
let encrypted = chat.encrypt_stream(&photo, &keys[conversation_key_version])?;
let media_hash_key = upload(&encrypted);
let mut photo_params = EncryptMessageParams::new(conversation_id, "a photo")
    .with_conversation_key(conversation_key.clone(), conversation_key_version);
photo_params.attachments = Some(vec![photo_attachment(&media_hash_key)]);
let photo_message = chat.encrypt_message(photo_params)?;

// Receive a file: the conversation key of the message's version
let plaintext = chat.decrypt_stream(&downloaded, &keys[conversation_key_version])?;

// Key change: re-nest each signature under message_event_signature
let mut key_change = ConversationKeyChangeParams::new(public_keys);
key_change.conversation_id = Some(conversation_id.to_string());
let prepared = chat.prepare_conversation_key_change(key_change)?;
let action_signatures: Vec<serde_json::Value> = prepared
    .action_signatures
    .iter()
    .map(|sig| {
        serde_json::json!({
            "message_id": sig.message_id,
            "encoded_message_event_detail": sig.encoded_message_event_detail,
            "message_event_signature": {
                "signature": sig.signature,
                "signature_version": sig.signature_version,
                "public_key_version": sig.public_key_version,
                "signing_public_key": signing_public_key,
            },
        })
    })
    .collect();

// Delete: one flat action signature
let deletion = chat.prepare_message_delete(&MessageDeleteParams::new(conversation_id, sequence_ids, false))?;
```

0.6.0:

```rust
use chat_xdk_core::utils::encrypted_file_size;
use chat_xdk_core::{
    ChatCore, ConversationKeyChangeParams, DecryptEventParams, DecryptEventsParams,
    DecryptFileParams, EncryptFileParams, EncryptMessageParams, EncryptReplyParams,
    ImportKeysParams, MessageDeleteParams, SetIdentityParams,
};

let chat = ChatCore::new();
chat.import_keys(&ImportKeysParams::new(private_keys).with_signing_key_version(signing_key_version))?;
chat.set_identity(&SetIdentityParams::new(user_id, signing_key_version))?;

// Decrypt
let result = chat.decrypt_events(DecryptEventsParams::new(events).with_signing_keys(signing_keys.clone()));
let keys = result.conversation_keys.keys.clone();
let event = chat.decrypt_event(DecryptEventParams::new(event_b64, keys.clone()).with_signing_keys(signing_keys))?;

// Send
let payload = chat.encrypt_message(
    &EncryptMessageParams::new(conversation_id, "hello")
        .with_conversation_key(conversation_key.clone(), conversation_key_version),
)?;
let body = serde_json::json!({
    "message_id": payload.message_id,
    "encoded_message_create_event": payload.encoded_message_create_event,
    "encoded_message_event_signature": payload.encoded_message_event_signature,
});
let reply = chat.encrypt_reply(
    &EncryptReplyParams::new(conversation_id, "pong", event_b64)
        .with_conversation_key(conversation_key.clone(), conversation_key_version),
)?;

// Send a file: start the upload, build the message, then encrypt the file from it
let media_hash_key = start_upload(encrypted_file_size(photo.len() as u64).unwrap());
let mut photo_params = EncryptMessageParams::new(conversation_id, "a photo")
    .with_conversation_key(conversation_key.clone(), conversation_key_version);
photo_params.attachments = Some(vec![photo_attachment(&media_hash_key)]);
let photo_message = chat.encrypt_message(&photo_params)?;
let encrypted = chat.encrypt_file(
    &EncryptFileParams::new(photo.clone(), &photo_message.event_b64, &media_hash_key)
        .with_conversation_key(conversation_key.clone(), conversation_key_version),
)?;
finish_upload(&media_hash_key, &encrypted);

// Receive a file: the message's event and key map, as decrypt_event takes them
let plaintext = chat.decrypt_file(DecryptFileParams::new(downloaded, file_event_b64, keys, file_hash_key))?;

// Key change: the action signatures are already in the request's shape
let mut key_change = ConversationKeyChangeParams::new(public_keys);
key_change.conversation_id = Some(conversation_id.to_string());
let prepared = chat.prepare_conversation_key_change(&key_change)?;
let action_signatures = serde_json::to_value(&prepared.action_signatures)?;

// Delete: a PreparedAction holding the request's action_signatures (one entry)
let deletion = chat.prepare_message_delete(&MessageDeleteParams::new(conversation_id, sequence_ids, false))?;
let delete_signatures = serde_json::to_value(&deletion.action_signatures)?;
```

### Python

| 0.5.x | 0.6.0 |
|---|---|
| `import_keys(keys, version)` | `import_keys(ImportKeysParams(keys, signing_key_version=version))` |
| `set_identity(user_id, version)` | `set_identity(SetIdentityParams(user_id, version))` |
| `decrypt_events(events, signing_keys)` | `decrypt_events(DecryptEventsParams(events, signing_keys=signing_keys))` |
| `decrypt_event(event_b64, keys, signing_keys)` | `decrypt_event(DecryptEventParams(event_b64, keys, signing_keys=signing_keys))` |
| `encrypt_message(conversation_id, text, …)` | `encrypt_message(EncryptMessageParams(conversation_id, text, …))` |
| `encrypt_reply(conversation_id, text, reply_to_event, …)` | `encrypt_reply(EncryptReplyParams(conversation_id, text, reply_to_event, …))` |
| `encrypt_add_reaction(target_event, emoji, …)`, `encrypt_remove_reaction(…)` | `encrypt_add_reaction(EncryptReactionParams(target_event, emoji, …))`, likewise for remove |
| `encrypt_edit(target_event, updated_text, …)` | `encrypt_edit(EncryptEditParams(target_event, updated_text, …))` |
| `prepare_conversation_key_change(public_keys, …)` | `prepare_conversation_key_change(ConversationKeyChangeParams(public_keys, …))` |
| `prepare_group_create(public_keys, conversation_id, member_ids, admin_ids, …)` | `prepare_group_create(GroupCreateParams(…))` |
| `prepare_group_members_change(public_keys, conversation_id, …)` | `prepare_group_members_change(GroupMembersChangeParams(…))` |
| `prepare_message_delete(conversation_id, sequence_ids, delete_for_all, …)` | `prepare_message_delete(MessageDeleteParams(…))`, returning `{"action_signatures": [...]}` |
| `encrypt_stream(file, key)`, `stream_encryptor(key)` | `encrypt_file(EncryptFileParams(…))`, `file_encryptor(FileEncryptorParams(…))` |
| `decrypt_stream(encrypted, key)`, `stream_decryptor(key)` | `decrypt_file(DecryptFileParams(…))`, `file_decryptor(FileDecryptorParams(…))` |
| `encrypted_stream_size(n)` | `encrypted_file_size(n)` |
| `StreamEncryptor`, `StreamDecryptor` | `FileEncryptor`, `FileDecryptor` |
| `SendPayload.encrypted_content`, `.encoded_event_signature` | `.encoded_message_create_event`, `.encoded_message_event_signature` |
| `PublicKeyRegistrationPayload.version`, `.generate_version` | removed |
| — | `prepare_mark_conversation_read(MarkConversationReadParams(…))`, `Chat.close()` |

Each params class takes the arguments its method took, with the same names,
order and defaults, apart from three: `DecryptEventsParams` and
`DecryptEventParams` take `signing_keys` by keyword only, and
`ImportKeysParams` takes the version as the keyword `signing_key_version`.
Every field is a read/write attribute. `reply_to_sender_id` is a `str`.
Prepare results stay dicts, with each action signature nested as shown in
[Key changes, groups and deletes](#key-changes-groups-and-deletes).

0.5.x:

```python
from chat_xdk import Chat

chat = Chat()
chat.import_keys(private_keys, signing_key_version)
chat.set_identity(user_id, signing_key_version)

# Decrypt
result = chat.decrypt_events(events, signing_keys)
keys = result["conversation_keys"]["keys"]
event = chat.decrypt_event(event_b64, keys, signing_keys)

# Send
payload = chat.encrypt_message(
    conversation_id, "hello",
    conversation_key=conversation_key, conversation_key_version=conversation_key_version,
)
body = {
    "message_id": payload.message_id,
    "encoded_message_create_event": payload.encrypted_content,
    "encoded_message_event_signature": payload.encoded_event_signature,
}
reply = chat.encrypt_reply(
    conversation_id, "pong", event_b64,
    conversation_key=conversation_key, conversation_key_version=conversation_key_version,
)

# Send a file: encrypt it under the conversation key, upload it, then build the message
encrypted = chat.encrypt_stream(photo, conversation_key)
media_hash_key = upload(encrypted)
photo_message = chat.encrypt_message(
    conversation_id, "a photo", attachments=[photo_attachment(media_hash_key)],
    conversation_key=conversation_key, conversation_key_version=conversation_key_version,
)

# Receive a file: the conversation key of the message's version
plaintext = chat.decrypt_stream(downloaded, keys[conversation_key_version])

# Key change: re-nest each signature under message_event_signature
prepared = chat.prepare_conversation_key_change(public_keys, conversation_id=conversation_id)
action_signatures = [
    {
        "message_id": sig["message_id"],
        "encoded_message_event_detail": sig["encoded_message_event_detail"],
        "message_event_signature": {
            "signature": sig["signature"],
            "signature_version": sig["signature_version"],
            "public_key_version": sig["public_key_version"],
            "signing_public_key": signing_public_key,
        },
    }
    for sig in prepared["action_signatures"]
]

# Delete: one flat action signature
deletion = chat.prepare_message_delete(conversation_id, sequence_ids, False)
```

0.6.0:

```python
from chat_xdk import (
    Chat,
    ConversationKeyChangeParams,
    DecryptEventParams,
    DecryptEventsParams,
    DecryptFileParams,
    EncryptFileParams,
    EncryptMessageParams,
    EncryptReplyParams,
    ImportKeysParams,
    MessageDeleteParams,
    SetIdentityParams,
    encrypted_file_size,
)

chat = Chat()
chat.import_keys(ImportKeysParams(private_keys, signing_key_version=signing_key_version))
chat.set_identity(SetIdentityParams(user_id, signing_key_version))

# Decrypt
result = chat.decrypt_events(DecryptEventsParams(events, signing_keys=signing_keys))
keys = result["conversation_keys"]["keys"]
event = chat.decrypt_event(DecryptEventParams(event_b64, keys, signing_keys=signing_keys))

# Send
payload = chat.encrypt_message(EncryptMessageParams(
    conversation_id, "hello",
    conversation_key=conversation_key, conversation_key_version=conversation_key_version,
))
body = {
    "message_id": payload.message_id,
    "encoded_message_create_event": payload.encoded_message_create_event,
    "encoded_message_event_signature": payload.encoded_message_event_signature,
}
reply = chat.encrypt_reply(EncryptReplyParams(
    conversation_id, "pong", event_b64,
    conversation_key=conversation_key, conversation_key_version=conversation_key_version,
))

# Send a file: start the upload, build the message, then encrypt the file from it
media_hash_key = start_upload(encrypted_file_size(len(photo)))
photo_message = chat.encrypt_message(EncryptMessageParams(
    conversation_id, "a photo", attachments=[photo_attachment(media_hash_key)],
    conversation_key=conversation_key, conversation_key_version=conversation_key_version,
))
encrypted = chat.encrypt_file(EncryptFileParams(
    photo, photo_message.event_b64, media_hash_key,
    conversation_key=conversation_key, conversation_key_version=conversation_key_version,
))
finish_upload(media_hash_key, encrypted)

# Receive a file: the message's event and key map, as decrypt_event takes them
plaintext = chat.decrypt_file(DecryptFileParams(downloaded, file_event_b64, keys, file_hash_key))

# Key change: the action signatures are already in the request's shape
prepared = chat.prepare_conversation_key_change(
    ConversationKeyChangeParams(public_keys, conversation_id=conversation_id)
)
action_signatures = prepared["action_signatures"]

# Delete: a PreparedAction holding the request's action_signatures (one entry)
deletion = chat.prepare_message_delete(MessageDeleteParams(conversation_id, sequence_ids, False))
delete_signatures = deletion["action_signatures"]

chat.close()
```

### JavaScript / WASM

| 0.5.x | 0.6.0 |
|---|---|
| `setIdentity(userId, version)` | `setIdentity({ userId, signingKeyVersion })` |
| `decryptEvents(events, signingKeys)` | `decryptEvents({ events, signingKeys })` |
| `decryptEvent(eventB64, conversationKeys, signingKeys)` | `decryptEvent({ eventB64, conversationKeys, signingKeys })` |
| `encryptStream(file, key)`, `streamEncryptor(key)` | `encryptFile({ file, eventB64, mediaHashKey, conversationKey, conversationKeyVersion })`, `fileEncryptor({ … })` |
| `decryptStream(encrypted, key)`, `streamDecryptor(key)` | `decryptFile({ encrypted, eventB64, conversationKeys, mediaHashKey })`, `fileDecryptor({ … })` |
| `encryptedStreamSize(n)` | `encryptedFileSize(n)` |
| `prepareMessageDelete(…)` returning `ActionSignature` | returning `PreparedAction` (`actionSignatures`) |
| `SendPayload.encryptedContent`, `.encodedEventSignature` | `.encodedMessageCreateEvent`, `.encodedMessageEventSignature` |
| `PublicKeyRegistrationPayload.version`, `.generateVersion` | removed |
| `replyToSenderId?: string \| number` | `replyToSenderId?: string` |
| — | `prepareMarkConversationRead({ conversationId, seenUntilSequenceId })` |

The typings export only what the package exports: `Chat` and `ChatCrypto`,
which the module never exported, can no longer be imported, and
`FileEncryptor` / `FileDecryptor`, which the module returns but doesn't
export, are interfaces. `createChat`, `unlock` and the other key storage
calls don't change.

0.5.x:

```js
import { createChat } from "@xdevplatform/chat-xdk";

const chat = await createChat({ getAuthToken });
await chat.unlock(pin);
chat.setIdentity(userId, signingKeyVersion);

// Decrypt
const result = chat.decryptEvents(events, signingKeys);
const keys = result.conversationKeys.keys;
const event = chat.decryptEvent(eventB64, keys, signingKeys);

// Send
const payload = chat.encryptMessage({ conversationId, text: "hello", conversationKey, conversationKeyVersion });
const body = {
  message_id: payload.messageId,
  encoded_message_create_event: payload.encryptedContent,
  encoded_message_event_signature: payload.encodedEventSignature,
};
const reply = chat.encryptReply({
  conversationId, text: "pong", replyToEvent: eventB64, conversationKey, conversationKeyVersion,
});

// Send a file: encrypt it under the conversation key, upload it, then build the message
const encrypted = chat.encryptStream(photo, conversationKey);
const mediaHashKey = await upload(encrypted);
const photoMessage = chat.encryptMessage({
  conversationId, text: "a photo", attachments: [photoAttachment(mediaHashKey)],
  conversationKey, conversationKeyVersion,
});

// Receive a file: the conversation key of the message's version
const plaintext = chat.decryptStream(downloaded, keys[conversationKeyVersion]);

// Key change: re-nest each signature under messageEventSignature
const prepared = chat.prepareConversationKeyChange({ publicKeys, conversationId });
const actionSignatures = prepared.actionSignatures.map((sig) => ({
  messageId: sig.messageId,
  encodedMessageEventDetail: sig.encodedMessageEventDetail,
  messageEventSignature: {
    signature: sig.signature,
    signatureVersion: sig.signatureVersion,
    publicKeyVersion: sig.publicKeyVersion,
    signingPublicKey,
  },
}));

// Delete: one flat action signature
const deletion = chat.prepareMessageDelete({ conversationId, sequenceIds, deleteForAll: false });

chat.free();
```

0.6.0:

```js
import { createChat, encryptedFileSize } from "@xdevplatform/chat-xdk";

const chat = await createChat({ getAuthToken });
await chat.unlock(pin);
chat.setIdentity({ userId, signingKeyVersion });

// Decrypt
const result = chat.decryptEvents({ events, signingKeys });
const keys = result.conversationKeys.keys;
const event = chat.decryptEvent({ eventB64, conversationKeys: keys, signingKeys });

// Send
const payload = chat.encryptMessage({ conversationId, text: "hello", conversationKey, conversationKeyVersion });
const body = {
  message_id: payload.messageId,
  encoded_message_create_event: payload.encodedMessageCreateEvent,
  encoded_message_event_signature: payload.encodedMessageEventSignature,
};
const reply = chat.encryptReply({
  conversationId, text: "pong", replyToEvent: eventB64, conversationKey, conversationKeyVersion,
});

// Send a file: start the upload, build the message, then encrypt the file from it
const mediaHashKey = await startUpload(encryptedFileSize(photo.length));
const photoMessage = chat.encryptMessage({
  conversationId, text: "a photo", attachments: [photoAttachment(mediaHashKey)],
  conversationKey, conversationKeyVersion,
});
const encrypted = chat.encryptFile({
  file: photo, eventB64: photoMessage.eventB64, mediaHashKey, conversationKey, conversationKeyVersion,
});
await finishUpload(mediaHashKey, encrypted);

// Receive a file: the message's event and key map, as decryptEvent takes them
const plaintext = chat.decryptFile({
  encrypted: downloaded, eventB64: fileEventB64, conversationKeys: keys, mediaHashKey: fileHashKey,
});

// Key change: the action signatures are already in the request's shape
const prepared = chat.prepareConversationKeyChange({ publicKeys, conversationId });
const actionSignatures = prepared.actionSignatures;

// Delete: a PreparedAction holding the request's actionSignatures (one entry)
const deletion = chat.prepareMessageDelete({ conversationId, sequenceIds, deleteForAll: false });
const deleteSignatures = deletion.actionSignatures;

chat.free();
```

### Go

| 0.5.x | 0.6.0 |
|---|---|
| `ImportKeys(keys)`, `ImportKeysWithVersion(keys, version)` | `ImportKeys(ImportKeysParams{Keys, SigningKeyVersion})` |
| `SetIdentity(userID, version)` | `SetIdentity(SetIdentityParams{UserID, SigningKeyVersion})` |
| `DecryptEvents(events, signingKeys)` | `DecryptEvents(DecryptEventsParams{Events, SigningKeys})` |
| `DecryptEvent(eventB64, keys, signingKeys)` | `DecryptEvent(DecryptEventParams{EventB64, ConversationKeys, SigningKeys})` |
| `EncryptStream(file, key)`, `StreamEncryptor(key)` | `EncryptFile(EncryptFileParams{…})`, `FileEncryptor(FileEncryptorParams{…})` |
| `DecryptStream(encrypted, key)`, `StreamDecryptor(key)` | `DecryptFile(DecryptFileParams{…})`, `FileDecryptor(FileDecryptorParams{…})` |
| `EncryptedStreamSize(n)` | `EncryptedFileSize(n)` |
| `PrepareMessageDelete(…) (*ActionSignature, error)` | `(*PreparedAction, error)` |
| `ActionSignature.Signature`, `.SignatureVersion`, `.PublicKeyVersion` | `ActionSignature.MessageEventSignature` (with `SigningPublicKey`); `SignaturePayload` is `omitempty` |
| `SendPayload.EncryptedContent`, `.EncodedEventSignature` | `.EncodedMessageCreateEvent`, `.EncodedMessageEventSignature` |
| `PublicKeyRegistrationPayload.Version`, `.GenerateVersion` | removed |
| `EncryptReplyParams.ReplyToSenderID *int64` | `string` |
| — | `PrepareMarkConversationRead(MarkConversationReadParams{…})` |

The snippets use `must(err)` for brevity; handle errors as your code does.
`SendPayload` unmarshals from JSON under either the 0.6.0 or the 0.5.x
field names.

0.5.x:

```go
chat := chatxdk.New()
defer chat.Close()
must(chat.ImportKeysWithVersion(privateKeys, signingKeyVersion))
must(chat.SetIdentity(userID, signingKeyVersion))

// Decrypt
result, err := chat.DecryptEvents(events, signingKeys)
must(err)
keys := result.ConversationKeys.Keys
event, err := chat.DecryptEvent(eventB64, keys, signingKeys)
must(err)

// Send
payload, err := chat.EncryptMessage(chatxdk.EncryptMessageParams{
	ConversationID: conversationID, Text: "hello",
	ConversationKey: conversationKey, ConversationKeyVersion: conversationKeyVersion,
})
must(err)
body := map[string]string{
	"message_id":                      payload.MessageID,
	"encoded_message_create_event":    payload.EncryptedContent,
	"encoded_message_event_signature": payload.EncodedEventSignature,
}
reply, err := chat.EncryptReply(chatxdk.EncryptReplyParams{
	ConversationID: conversationID, Text: "pong", ReplyToEvent: eventB64,
	ConversationKey: conversationKey, ConversationKeyVersion: conversationKeyVersion,
})
must(err)

// Send a file: encrypt it under the conversation key, upload it, then build the message
encrypted, err := chat.EncryptStream(photo, conversationKey)
must(err)
mediaHashKey := upload(encrypted)
photoMessage, err := chat.EncryptMessage(chatxdk.EncryptMessageParams{
	ConversationID: conversationID, Text: "a photo",
	Attachments:     []chatxdk.AttachmentDescriptor{photoAttachment(mediaHashKey)},
	ConversationKey: conversationKey, ConversationKeyVersion: conversationKeyVersion,
})
must(err)

// Receive a file: the conversation key of the message's version
plaintext, err := chat.DecryptStream(downloaded, keys[conversationKeyVersion])
must(err)

// Key change: re-nest each signature under message_event_signature
prepared, err := chat.PrepareConversationKeyChange(chatxdk.ConversationKeyChangeParams{
	PublicKeys: publicKeys, ConversationID: conversationID,
})
must(err)
actionSignatures := make([]map[string]any, 0, len(prepared.ActionSignatures))
for _, sig := range prepared.ActionSignatures {
	actionSignatures = append(actionSignatures, map[string]any{
		"message_id":                   sig.MessageID,
		"encoded_message_event_detail": sig.EncodedMessageEventDetail,
		"message_event_signature": map[string]any{
			"signature":          sig.Signature,
			"signature_version":  sig.SignatureVersion,
			"public_key_version": sig.PublicKeyVersion,
			"signing_public_key": signingPublicKey,
		},
	})
}

// Delete: one flat action signature
deletion, err := chat.PrepareMessageDelete(chatxdk.MessageDeleteParams{
	ConversationID: conversationID, SequenceIDs: sequenceIDs, DeleteForAll: false,
})
must(err)
```

0.6.0:

```go
chat := chatxdk.New()
defer chat.Close()
must(chat.ImportKeys(chatxdk.ImportKeysParams{Keys: privateKeys, SigningKeyVersion: signingKeyVersion}))
must(chat.SetIdentity(chatxdk.SetIdentityParams{UserID: userID, SigningKeyVersion: signingKeyVersion}))

// Decrypt
result, err := chat.DecryptEvents(chatxdk.DecryptEventsParams{Events: events, SigningKeys: signingKeys})
must(err)
keys := result.ConversationKeys.Keys
event, err := chat.DecryptEvent(chatxdk.DecryptEventParams{
	EventB64: eventB64, ConversationKeys: keys, SigningKeys: signingKeys,
})
must(err)

// Send
payload, err := chat.EncryptMessage(chatxdk.EncryptMessageParams{
	ConversationID: conversationID, Text: "hello",
	ConversationKey: conversationKey, ConversationKeyVersion: conversationKeyVersion,
})
must(err)
body := map[string]string{
	"message_id":                      payload.MessageID,
	"encoded_message_create_event":    payload.EncodedMessageCreateEvent,
	"encoded_message_event_signature": payload.EncodedMessageEventSignature,
}
reply, err := chat.EncryptReply(chatxdk.EncryptReplyParams{
	ConversationID: conversationID, Text: "pong", ReplyToEvent: eventB64,
	ConversationKey: conversationKey, ConversationKeyVersion: conversationKeyVersion,
})
must(err)

// Send a file: start the upload, build the message, then encrypt the file from it
size, err := chatxdk.EncryptedFileSize(uint64(len(photo)))
must(err)
mediaHashKey := startUpload(size)
photoMessage, err := chat.EncryptMessage(chatxdk.EncryptMessageParams{
	ConversationID: conversationID, Text: "a photo",
	Attachments:     []chatxdk.AttachmentDescriptor{photoAttachment(mediaHashKey)},
	ConversationKey: conversationKey, ConversationKeyVersion: conversationKeyVersion,
})
must(err)
encrypted, err := chat.EncryptFile(chatxdk.EncryptFileParams{
	File: photo, EventB64: photoMessage.EventB64, MediaHashKey: mediaHashKey,
	ConversationKey: conversationKey, ConversationKeyVersion: conversationKeyVersion,
})
must(err)
finishUpload(mediaHashKey, encrypted)

// Receive a file: the message's event and key map, as DecryptEvent takes them
plaintext, err := chat.DecryptFile(chatxdk.DecryptFileParams{
	Encrypted: downloaded, EventB64: fileEventB64, ConversationKeys: keys, MediaHashKey: fileHashKey,
})
must(err)

// Key change: the action signatures are already in the request's shape
prepared, err := chat.PrepareConversationKeyChange(chatxdk.ConversationKeyChangeParams{
	PublicKeys: publicKeys, ConversationID: conversationID,
})
must(err)
actionSignatures := prepared.ActionSignatures

// Delete: a PreparedAction holding the request's action_signatures (one entry)
deletion, err := chat.PrepareMessageDelete(chatxdk.MessageDeleteParams{
	ConversationID: conversationID, SequenceIDs: sequenceIDs, DeleteForAll: false,
})
must(err)
deleteSignatures := deletion.ActionSignatures
```

### JVM

| 0.5.x | 0.6.0 |
|---|---|
| `importKeys(byte[])`, `importKeys(byte[], String)` | `importKeys(ImportKeysParams)` |
| `setIdentity(String, String)` | `setIdentity(SetIdentityParams)` |
| `decryptEvents(List<String>, List<SigningKeyEntry>)` | `decryptEvents(DecryptEventsParams)` |
| `decryptEvent(String, Map \| ConversationKeyBundle, List<SigningKeyEntry>)` | `decryptEvent(DecryptEventParams)`; pass `bundle.keys` for a bundle |
| `encryptStream(byte[], byte[])`, `streamEncryptor(byte[])` | `encryptFile(EncryptFileParams)`, `fileEncryptor(FileEncryptorParams)` |
| `decryptStream(byte[], byte[])`, `streamDecryptor(byte[])` | `decryptFile(DecryptFileParams)`, `fileDecryptor(FileDecryptorParams)` |
| `ChatXdkUtilities.encryptedStreamSize(long)` | `ChatXdkUtilities.encryptedFileSize(long)` |
| `prepareMessageDelete(…)` returning `ActionSignature` | returning `PreparedAction` |
| `ActionSignature.signature`, `.signatureVersion`, `.publicKeyVersion` | `ActionSignature.messageEventSignature` (with `signingPublicKey`); `signaturePayload` is `null` when absent |
| `SendPayload.encryptedContent`, `.encodedEventSignature` | `.encodedMessageCreateEvent`, `.encodedMessageEventSignature` |
| `PublicKeyRegistrationPayload.version`, `.generateVersion` | removed |
| `EncryptReplyParams.replyToSenderId` (`Long`) | `String` |
| — | `prepareMarkConversationRead(MarkConversationReadParams)` |

The file calls declare no checked exceptions (see [Errors](#errors)). If you
call the JNA interface `ChatNative` directly, its methods follow the C ABI
renames below.

0.5.x:

```java
Chat chat = new Chat();
chat.importKeys(privateKeys, signingKeyVersion);
chat.setIdentity(userId, signingKeyVersion);

// Decrypt
DecryptEventsResult result = chat.decryptEvents(events, signingKeys);
Map<String, byte[]> keys = result.conversationKeys.keys;
JsonNode event = chat.decryptEvent(eventB64, keys, signingKeys);

// Send
EncryptMessageParams message = new EncryptMessageParams(conversationId, "hello");
message.conversationKey = conversationKey;
message.conversationKeyVersion = conversationKeyVersion;
SendPayload payload = chat.encryptMessage(message);
Map<String, String> body = Map.of(
        "message_id", payload.messageId,
        "encoded_message_create_event", payload.encryptedContent,
        "encoded_message_event_signature", payload.encodedEventSignature);
EncryptReplyParams replyParams = new EncryptReplyParams(conversationId, "pong", eventB64);
replyParams.conversationKey = conversationKey;
replyParams.conversationKeyVersion = conversationKeyVersion;
SendPayload reply = chat.encryptReply(replyParams);

// Send a file: encrypt it under the conversation key, upload it, then build the message
byte[] encrypted = chat.encryptStream(photo, conversationKey);
String mediaHashKey = upload(encrypted);
EncryptMessageParams photoParams = new EncryptMessageParams(conversationId, "a photo");
photoParams.conversationKey = conversationKey;
photoParams.conversationKeyVersion = conversationKeyVersion;
photoParams.attachments = List.of(photoAttachment(mediaHashKey));
SendPayload photoMessage = chat.encryptMessage(photoParams);

// Receive a file: the conversation key of the message's version
byte[] plaintext = chat.decryptStream(downloaded, keys.get(conversationKeyVersion));

// Key change: re-nest each signature under message_event_signature
ConversationKeyChangeParams keyChange = new ConversationKeyChangeParams(publicKeys);
keyChange.conversationId = conversationId;
PreparedConversationChange prepared = chat.prepareConversationKeyChange(keyChange);
List<Map<String, Object>> actionSignatures = new ArrayList<>();
for (ActionSignature sig : prepared.actionSignatures) {
    actionSignatures.add(Map.of(
            "message_id", sig.messageId,
            "encoded_message_event_detail", sig.encodedMessageEventDetail,
            "message_event_signature", Map.of(
                    "signature", sig.signature,
                    "signature_version", sig.signatureVersion,
                    "public_key_version", sig.publicKeyVersion,
                    "signing_public_key", signingPublicKey)));
}

// Delete: one flat action signature
ActionSignature deletion = chat.prepareMessageDelete(new MessageDeleteParams(conversationId, sequenceIds, false));

chat.close();
```

0.6.0:

```java
Chat chat = new Chat();
chat.importKeys(new ImportKeysParams(privateKeys, signingKeyVersion));
chat.setIdentity(new SetIdentityParams(userId, signingKeyVersion));

// Decrypt
DecryptEventsParams batch = new DecryptEventsParams(events);
batch.signingKeys = signingKeys;
DecryptEventsResult result = chat.decryptEvents(batch);
Map<String, byte[]> keys = result.conversationKeys.keys;
DecryptEventParams one = new DecryptEventParams(eventB64, keys);
one.signingKeys = signingKeys;
JsonNode event = chat.decryptEvent(one);

// Send
EncryptMessageParams message = new EncryptMessageParams(conversationId, "hello");
message.conversationKey = conversationKey;
message.conversationKeyVersion = conversationKeyVersion;
SendPayload payload = chat.encryptMessage(message);
Map<String, String> body = Map.of(
        "message_id", payload.messageId,
        "encoded_message_create_event", payload.encodedMessageCreateEvent,
        "encoded_message_event_signature", payload.encodedMessageEventSignature);
EncryptReplyParams replyParams = new EncryptReplyParams(conversationId, "pong", eventB64);
replyParams.conversationKey = conversationKey;
replyParams.conversationKeyVersion = conversationKeyVersion;
SendPayload reply = chat.encryptReply(replyParams);

// Send a file: start the upload, build the message, then encrypt the file from it
String mediaHashKey = startUpload(ChatXdkUtilities.encryptedFileSize(photo.length));
EncryptMessageParams photoParams = new EncryptMessageParams(conversationId, "a photo");
photoParams.conversationKey = conversationKey;
photoParams.conversationKeyVersion = conversationKeyVersion;
photoParams.attachments = List.of(photoAttachment(mediaHashKey));
SendPayload photoMessage = chat.encryptMessage(photoParams);
EncryptFileParams fileParams = new EncryptFileParams(photo, photoMessage.eventB64, mediaHashKey);
fileParams.conversationKey = conversationKey;
fileParams.conversationKeyVersion = conversationKeyVersion;
byte[] encrypted = chat.encryptFile(fileParams);
finishUpload(mediaHashKey, encrypted);

// Receive a file: the message's event and key map, as decryptEvent takes them
byte[] plaintext = chat.decryptFile(new DecryptFileParams(downloaded, fileEventB64, keys, fileHashKey));

// Key change: the action signatures are already in the request's shape
ConversationKeyChangeParams keyChange = new ConversationKeyChangeParams(publicKeys);
keyChange.conversationId = conversationId;
PreparedConversationChange prepared = chat.prepareConversationKeyChange(keyChange);
List<ActionSignature> actionSignatures = prepared.actionSignatures;

// Delete: a PreparedAction holding the request's action_signatures (one entry)
PreparedAction deletion = chat.prepareMessageDelete(new MessageDeleteParams(conversationId, sequenceIds, false));
List<ActionSignature> deleteSignatures = deletion.actionSignatures;

chat.close();
```

### .NET

| 0.5.x | 0.6.0 |
|---|---|
| `ImportKeys(byte[] keys, string? version = null)` | `ImportKeys(ImportKeysParams)` |
| `SetIdentity(string, string)` | `SetIdentity(SetIdentityParams)` |
| `DecryptEvents(IEnumerable<string>, IEnumerable<SigningKeyEntry>?)` | `DecryptEvents(DecryptEventsParams)` |
| `DecryptEvent(string, Dictionary<…>? \| ConversationKeyBundle, …)` | `DecryptEvent(DecryptEventParams)`; pass `bundle.Keys` for a bundle |
| `EncryptStream(byte[], byte[])`, `StreamEncryptor(byte[])` | `EncryptFile(EncryptFileParams)`, `FileEncryptor(FileEncryptorParams)` |
| `DecryptStream(byte[], byte[])`, `StreamDecryptor(byte[])` | `DecryptFile(DecryptFileParams)`, `FileDecryptor(FileDecryptorParams)` |
| `ChatXdkUtilities.EncryptedStreamSize(ulong)` | `ChatXdkUtilities.EncryptedFileSize(ulong)` |
| `PrepareMessageDelete(…)` returning `ActionSignature` | returning `PreparedAction` |
| `ActionSignature.Signature`, `.SignatureVersion`, `.PublicKeyVersion` | `ActionSignature.MessageEventSignature` (with `SigningPublicKey`); `SignaturePayload` is `string?` |
| `SendPayload.EncryptedContent`, `.EncodedEventSignature` | `.EncodedMessageCreateEvent`, `.EncodedMessageEventSignature` |
| `PublicKeyRegistrationPayload.Version`, `.GenerateVersion` | removed |
| `EncryptReplyParams.ReplyToSenderId` (`long?`) | `string?` |
| — | `PrepareMarkConversationRead(MarkConversationReadParams)` |

0.5.x:

```csharp
using var chat = new Chat();
chat.ImportKeys(privateKeys, signingKeyVersion);
chat.SetIdentity(userId, signingKeyVersion);

// Decrypt
var result = chat.DecryptEvents(events, signingKeys);
var keys = result.ConversationKeys.Keys;
var evt = chat.DecryptEvent(eventB64, keys, signingKeys);

// Send
var payload = chat.EncryptMessage(new EncryptMessageParams(conversationId, "hello")
{
    ConversationKey = conversationKey,
    ConversationKeyVersion = conversationKeyVersion,
});
var body = new Dictionary<string, string>
{
    ["message_id"] = payload.MessageId,
    ["encoded_message_create_event"] = payload.EncryptedContent,
    ["encoded_message_event_signature"] = payload.EncodedEventSignature,
};
var reply = chat.EncryptReply(new EncryptReplyParams(conversationId, "pong", eventB64)
{
    ConversationKey = conversationKey,
    ConversationKeyVersion = conversationKeyVersion,
});

// Send a file: encrypt it under the conversation key, upload it, then build the message
var encrypted = chat.EncryptStream(photo, conversationKey);
var mediaHashKey = Upload(encrypted);
var photoMessage = chat.EncryptMessage(new EncryptMessageParams(conversationId, "a photo")
{
    ConversationKey = conversationKey,
    ConversationKeyVersion = conversationKeyVersion,
    Attachments = new[] { PhotoAttachment(mediaHashKey) },
});

// Receive a file: the conversation key of the message's version
var plaintext = chat.DecryptStream(downloaded, keys[conversationKeyVersion]);

// Key change: re-nest each signature under message_event_signature
var prepared = chat.PrepareConversationKeyChange(
    new ConversationKeyChangeParams(publicKeys) { ConversationId = conversationId });
var actionSignatures = prepared.ActionSignatures.Select(sig => new Dictionary<string, object>
{
    ["message_id"] = sig.MessageId,
    ["encoded_message_event_detail"] = sig.EncodedMessageEventDetail,
    ["message_event_signature"] = new Dictionary<string, string>
    {
        ["signature"] = sig.Signature,
        ["signature_version"] = sig.SignatureVersion,
        ["public_key_version"] = sig.PublicKeyVersion,
        ["signing_public_key"] = signingPublicKey,
    },
}).ToList();

// Delete: one flat action signature
var deletion = chat.PrepareMessageDelete(new MessageDeleteParams(conversationId, sequenceIds, deleteForAll: false));
```

0.6.0:

```csharp
using var chat = new Chat();
chat.ImportKeys(new ImportKeysParams(privateKeys) { SigningKeyVersion = signingKeyVersion });
chat.SetIdentity(new SetIdentityParams(userId, signingKeyVersion));

// Decrypt
var result = chat.DecryptEvents(new DecryptEventsParams(events) { SigningKeys = signingKeys });
var keys = result.ConversationKeys.Keys;
var evt = chat.DecryptEvent(new DecryptEventParams(eventB64, keys) { SigningKeys = signingKeys });

// Send
var payload = chat.EncryptMessage(new EncryptMessageParams(conversationId, "hello")
{
    ConversationKey = conversationKey,
    ConversationKeyVersion = conversationKeyVersion,
});
var body = new Dictionary<string, string>
{
    ["message_id"] = payload.MessageId,
    ["encoded_message_create_event"] = payload.EncodedMessageCreateEvent,
    ["encoded_message_event_signature"] = payload.EncodedMessageEventSignature,
};
var reply = chat.EncryptReply(new EncryptReplyParams(conversationId, "pong", eventB64)
{
    ConversationKey = conversationKey,
    ConversationKeyVersion = conversationKeyVersion,
});

// Send a file: start the upload, build the message, then encrypt the file from it
var mediaHashKey = StartUpload(ChatXdkUtilities.EncryptedFileSize((ulong)photo.Length));
var photoMessage = chat.EncryptMessage(new EncryptMessageParams(conversationId, "a photo")
{
    ConversationKey = conversationKey,
    ConversationKeyVersion = conversationKeyVersion,
    Attachments = new[] { PhotoAttachment(mediaHashKey) },
});
var encrypted = chat.EncryptFile(new EncryptFileParams(photo, photoMessage.EventB64, mediaHashKey)
{
    ConversationKey = conversationKey,
    ConversationKeyVersion = conversationKeyVersion,
});
FinishUpload(mediaHashKey, encrypted);

// Receive a file: the message's event and key map, as DecryptEvent takes them
var plaintext = chat.DecryptFile(new DecryptFileParams(downloaded, fileEventB64, keys, fileHashKey));

// Key change: the action signatures are already in the request's shape
var prepared = chat.PrepareConversationKeyChange(
    new ConversationKeyChangeParams(publicKeys) { ConversationId = conversationId });
var actionSignatures = prepared.ActionSignatures;

// Delete: a PreparedAction holding the request's action_signatures (one entry)
var deletion = chat.PrepareMessageDelete(new MessageDeleteParams(conversationId, sequenceIds, deleteForAll: false));
var deleteSignatures = deletion.ActionSignatures;
```

### C ABI

The header is `go/chatxdk/include/chat_xdk.h`; the native libraries in the
.NET and JVM packages export the same functions. Entry points whose
arguments changed are renamed, so a stale header or library fails to link:

| 0.5.x | 0.6.0 |
|---|---|
| `chat_xdk_set_identity(chat, user_id, version)` | `chat_xdk_set_identity_params(chat, params_json)` |
| `chat_xdk_import_keys(chat, keys_b64)`, `chat_xdk_import_keys_with_version(chat, keys, len, version)` | `chat_xdk_import_keys_params(chat, keys, len, params_json)` |
| `chat_xdk_decrypt_events(chat, events_json, signing_keys_json)` | `chat_xdk_decrypt_events_params(chat, params_json)` |
| `chat_xdk_decrypt_event(chat, event_b64, conversation_keys_json, signing_keys_json)` | `chat_xdk_decrypt_event_params(chat, params_json)` |
| `chat_xdk_encrypt_stream(chat, plaintext_b64, key_b64)` | `chat_xdk_encrypt_file(chat, params_json)` |
| `chat_xdk_decrypt_stream(chat, encrypted_b64, key_b64)` | `chat_xdk_decrypt_file(chat, params_json)` |
| `chat_xdk_stream_encryptor_new(key_b64)` returning a handle | `chat_xdk_file_encryptor_new(chat, params_json, &out)` returning a result |
| `chat_xdk_stream_decryptor_new(key_b64)` returning a handle | `chat_xdk_file_decryptor_new(chat, params_json, &out)` returning a result |
| `chat_xdk_stream_encryptor_push` / `_finish` / `_free` | `chat_xdk_file_encryptor_push` / `_finish` / `_free` |
| `chat_xdk_stream_decryptor_push` / `_finish` / `_free` | `chat_xdk_file_decryptor_push` / `_finish` / `_free` |
| `chat_xdk_encrypted_stream_size(size)` | `chat_xdk_encrypted_file_size(size)` |
| — | `chat_xdk_prepare_mark_conversation_read(chat, params_json)` |

The params documents use the snake_case field names of the params types in
[API.md](API.md), with byte fields (`file`, `encrypted`, `conversation_key`
and the values of `conversation_keys`) as base64 strings.
`chat_xdk_import_keys_params` takes the key bytes by pointer and only the
optional `signing_key_version` in its JSON.

Functions that keep their names change what they take or return:

- `chat_xdk_generate_keypairs` returns a payload without `version` and
  `generate_version`.
- The encrypt calls take `reply_to_sender_id` as a string, check user ids and
  key versions, and return a `SendPayload` with `encoded_message_create_event`,
  `encoded_message_event_signature`, `event_b64` and `xdk_version`.
- `chat_xdk_prepare_conversation_key_change`, `chat_xdk_prepare_group_create`
  and `chat_xdk_prepare_group_members_change` return nested action
  signatures, and `chat_xdk_prepare_message_delete` returns
  `{"action_signatures": [...]}`.

The C ABI never fetches feature switches, so direct callers always send v0.
In the snippets, `take(r)` stands for your error handling: it returns
`r.data` (free it with `chat_xdk_free_string`) and handles `r.error`. The
`*_json` values are params documents your code builds, and
`encrypt_file_json(photo_message)` stands for building the file's params
from the payload's `event_b64`.

0.5.x:

```c
ChatHandle *chat = chat_xdk_new();
take(chat_xdk_import_keys_with_version(chat, keys, keys_len, "1"));
take(chat_xdk_set_identity(chat, "1111", "1"));

/* Decrypt: separate arguments */
char *batch = take(chat_xdk_decrypt_events(chat, events_json, signing_keys_json));
char *event = take(chat_xdk_decrypt_event(chat, event_b64, conversation_keys_json, signing_keys_json));

/* Send: the payload carries encrypted_content and encoded_event_signature */
char *payload = take(chat_xdk_encrypt_message(chat, message_json));

/* Send a file: encrypt it under the conversation key, then upload it and build the message */
char *encrypted = take(chat_xdk_encrypt_stream(chat, photo_b64, conversation_key_b64));
StreamEncryptorHandle *encryptor = chat_xdk_stream_encryptor_new(conversation_key_b64);
char *head = take(chat_xdk_stream_encryptor_push(encryptor, photo_b64));
char *tail = take(chat_xdk_stream_encryptor_finish(encryptor));
chat_xdk_stream_encryptor_free(encryptor);
char *photo_message = take(chat_xdk_encrypt_message(chat, photo_message_json));

/* Receive a file: the conversation key of the message's version */
char *plaintext = take(chat_xdk_decrypt_stream(chat, downloaded_b64, conversation_key_b64));

/* Delete: returns one flat action signature */
char *deletion = take(chat_xdk_prepare_message_delete(chat, delete_json));

chat_xdk_free(chat);
```

0.6.0:

```c
ChatHandle *chat = chat_xdk_new();
take(chat_xdk_import_keys_params(chat, keys, keys_len, "{\"signing_key_version\":\"1\"}"));
take(chat_xdk_set_identity_params(chat, "{\"user_id\":\"1111\",\"signing_key_version\":\"1\"}"));

/* Decrypt: {"events":[...],"signing_keys":[...]} and
   {"event_b64":"...","conversation_keys":{"<version>":"<base64 key>"},"signing_keys":[...]} */
char *batch = take(chat_xdk_decrypt_events_params(chat, decrypt_events_json));
char *event = take(chat_xdk_decrypt_event_params(chat, decrypt_event_json));

/* Send: the payload's fields carry the send request's names */
char *payload = take(chat_xdk_encrypt_message(chat, message_json));

/* Send a file: build the message, then encrypt the file from the payload's event_b64:
   {"file":"<base64>","event_b64":"...","media_hash_key":"...",
    "conversation_key":"<base64 key>","conversation_key_version":"..."} */
char *photo_message = take(chat_xdk_encrypt_message(chat, photo_message_json));
char *encrypted = take(chat_xdk_encrypt_file(chat, encrypt_file_json(photo_message)));
FileEncryptorHandle *encryptor = NULL;
take(chat_xdk_file_encryptor_new(chat, file_encryptor_json(photo_message), &encryptor));
char *head = take(chat_xdk_file_encryptor_push(encryptor, photo_b64));
char *tail = take(chat_xdk_file_encryptor_finish(encryptor));
chat_xdk_file_encryptor_free(encryptor);

/* Receive a file: {"encrypted":"<base64>","event_b64":"...","conversation_keys":{...},"media_hash_key":"..."} */
char *plaintext = take(chat_xdk_decrypt_file(chat, decrypt_file_json));

/* Delete: returns {"action_signatures":[{..., "message_event_signature":{...}}]} */
char *deletion = take(chat_xdk_prepare_message_delete(chat, delete_json));

chat_xdk_free(chat);
```
