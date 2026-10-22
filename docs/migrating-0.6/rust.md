# Migrating Rust code to chat-xdk 0.6.0

This page lists every change that Rust code written for `chat-xdk-core`
0.5.x (0.5.0, 0.5.1 or 0.5.2) runs into in 0.6.0, each with the lines to
change. [Why 0.6.0 changes](why.md) explains why each change was made, and
the [index](README.md) lists the other bindings' pages. [API.md](../API.md)
documents every call, and the [CHANGELOG](../../CHANGELOG.md) lists every
change.

## Checklist

- [ ] [Upgrade every app that reads your conversations first](#upgrade-readers-before-v1-sends-start)
- [ ] [Register keys with the public key only](#register-keys-with-the-public-key-only)
- [ ] [Pass a `&SetIdentityParams` to `set_identity` and handle its `Result`](#set_identity-takes-setidentityparams)
- [ ] [Pass an `&ImportKeysParams` to `import_keys`](#import_keys-takes-importkeysparams)
- [ ] [Pass user ids as strings of digits](#user-ids-are-strings-of-digits)
- [ ] [Pass key versions as the X API returns them](#key-versions-are-integers-written-as-strings)
- [ ] [Pass a `DecryptEventsParams` to `decrypt_events`](#decrypt_events-takes-decrypteventsparams)
- [ ] [Pass a `DecryptEventParams` to `decrypt_event`](#decrypt_event-takes-decrypteventparams)
- [ ] [Pass params by reference to every encrypt and prepare method](#encrypt-and-prepare-methods-take-params-by-reference)
- [ ] [Read `SendPayload` under the send request's field names](#sendpayload-fields-take-the-send-requests-names)
- [ ] [Build a message before you encrypt its files](#encrypt-a-file-from-its-message)
- [ ] [Decrypt a file with the event of its message](#decrypt-a-file-with-its-messages-event)
- [ ] [Use `file_encryptor` and `file_decryptor` for large files](#encrypt-and-decrypt-large-files-in-chunks)
- [ ] [Pass action signatures through as returned](#action-signatures-come-nested)
- [ ] [Read a delete's signature from its `PreparedAction`](#deletes-return-a-preparedaction)
- [ ] [Match `SdkError::InvalidInput` for invalid input](#invalid-input-errors)
- [ ] [Optional: sign read receipts](#signed-read-receipts)

## About the snippets

Each snippet shows the lines that change, first as 0.5.x code writes them
and then as 0.6.0 code writes them. `chat` is a `ChatCore` with your keys
loaded; `Chat`, which adds Juicebox key storage, has the same methods. The
other names stand for your own values: ids, versions, keys and events as the
X API returns them, `keys` for the conversation key map `decrypt_events`
returns, `payload` for a `SendPayload`, `prepared` for a
`PreparedConversationChange`, `key_change` for a
`ConversationKeyChangeParams` and `err` for an `SdkError`.
`api.post(path, &body)` stands for your HTTP client: it POSTs `body`, a
`serde_json::Value`, to `https://api.x.com` + `path` with your user access
token and returns the parsed JSON response as a `serde_json::Value`.
`photo_attachment(media_hash_key)` stands for your code that builds a
photo's `AttachmentDescriptor`. Every type and module the snippets use
imports from `chat_xdk_core`, except `SdkError`, which imports from
`chat_xdk_core::error`.

## Upgrade readers before v1 sends start

0.6.0 reads messages, replies, reactions and edits in two formats. v0 is the
format 0.5.x sends. v1 encrypts each message under its own key, derived from
the conversation key, the sender and the message id, and signs it at
signature version 10. The Rust crate doesn't fetch the X API's feature
switches, so it always sends v0. The Python, JavaScript, Go, JVM and .NET
bindings send v1 while the X API's `v1_send` feature switch is on.

0.5.x rejects every v1 send as a signature verification failure, so upgrade
every app that reads your conversations, Rust ones included, to 0.6.0 before
any sender can send v1. 0.6.0 reads both formats, including v1 reply
previews, edits and files. There's no code to change: to see which format a
send used, read `signature_info.signature_version`, `"7"` for v0 and `"10"`
for v1.

## Register keys with the public key only

`generate_keypairs` returns a `PublicKeyRegistrationPayload` that holds only
`public_key`. Send it as the only field of the
`POST /2/users/{id}/public_keys` body. 0.6.0 doesn't take or pick a
signing-key version for new keys: call `set_identity` with the
`public_key_version` the request returns. A signed call made without a
version fails with `SdkError::InvalidState`: `signing_key_version is not
set: pass it explicitly or call set_identity() first`.

```rust
// 0.5.x
let registration = chat.generate_keypairs()?;
let body = serde_json::json!({
    "public_key": registration.public_key,
    "version": registration.version,
    "generate_version": registration.generate_version,
});
let response = api.post(&format!("/2/users/{user_id}/public_keys"), &body)?;
let public_key_version = response["data"]["public_key_version"].as_str().ok_or("no version")?;
chat.set_identity(user_id, public_key_version);

// 0.6.0
let registration = chat.generate_keypairs()?;
let body = serde_json::json!({ "public_key": registration.public_key });
let response = api.post(&format!("/2/users/{user_id}/public_keys"), &body)?;
let public_key_version = response["data"]["public_key_version"].as_str().ok_or("no version")?;
chat.set_identity(&SetIdentityParams::new(user_id, public_key_version))?;
```

`ChatCore` generates keys with `generate_keypairs` too, without a version:

```rust
// 0.5.x
let registration = chat.generate_keypairs_with_version(signing_key_version)?;

// 0.6.0
let registration = chat.generate_keypairs()?;
```

## `set_identity` takes `SetIdentityParams`

Pass the user id and the signing-key version in a `SetIdentityParams`.
`set_identity` returns `Result<(), SdkError>`, an `SdkError::InvalidInput`
when either value is invalid (see
[user ids](#user-ids-are-strings-of-digits) and
[key versions](#key-versions-are-integers-written-as-strings)).

```rust
// 0.5.x
chat.set_identity(user_id, signing_key_version);

// 0.6.0
chat.set_identity(&SetIdentityParams::new(user_id, signing_key_version))?;
```

## `import_keys` takes `ImportKeysParams`

Pass the saved key bytes in an `ImportKeysParams`, and optionally the
signing-key version they were registered under with
`with_signing_key_version`. Without a version, call `set_identity` before
the first signed call.

```rust
// 0.5.x
chat.import_keys(&private_keys)?;
chat.import_keys_with_version(&private_keys, signing_key_version)?;

// 0.6.0
chat.import_keys(&ImportKeysParams::new(private_keys.clone()))?;
chat.import_keys(&ImportKeysParams::new(private_keys).with_signing_key_version(signing_key_version))?;
```

## User ids are strings of digits

Every user id is a `String` of digits: the `SetIdentityParams` user id,
`sender_id`, `reply_to_sender_id`, the `user_id` of each `PublicKeyInput`
and `SigningKeyEntry`, and group member, admin and pending-member ids. Each
must be a positive integer written without a sign or leading zeros; anything
else fails with `SdkError::InvalidInput` naming the field, such as
`Invalid sender_id 'user-1': pass a numeric user id (digits only)`.
`EncryptReplyParams::reply_to_sender_id` is an `Option<String>`:

```rust
// 0.5.x
let mut reply = EncryptReplyParams::new(conversation_id, "pong", event_b64);
reply.reply_to_sender_id = Some(4201);

// 0.6.0
let mut reply = EncryptReplyParams::new(conversation_id, "pong", event_b64);
reply.reply_to_sender_id = Some("4201".to_string());
```

## Key versions are integers written as strings

Every key version is a non-negative integer written as a string of digits,
as the X API returns it: the signing-key version (in `SetIdentityParams`,
`ImportKeysParams`, a call's `signing_key_version` and each
`PublicKeyInput::key_version`) and `conversation_key_version`. Anything else
fails with `SdkError::InvalidInput` naming the field, such as
`Invalid signing_key_version 'v1': pass the key version as the X API returns
it, an integer in digits`. There's no code to change if you pass the
versions the X API returns.

## `decrypt_events` takes `DecryptEventsParams`

Pass the events, a `Vec<String>`, in a `DecryptEventsParams`, and the
signing keys with `with_signing_keys`. Without signing keys, the ones
`set_signing_keys` stored verify the events. The call still returns a
`DecryptEventsResult` that collects errors per event.

```rust
// 0.5.x
let result = chat.decrypt_events(&events, &signing_keys);

// 0.6.0
let result = chat.decrypt_events(DecryptEventsParams::new(events).with_signing_keys(signing_keys));
```

## `decrypt_event` takes `DecryptEventParams`

Pass the event and the conversation key map in a `DecryptEventParams`, and
the signing keys with `with_signing_keys`. An empty key map resolves the
key from the key cache (`set_cache_keys(true)`), and without signing keys
the ones `set_signing_keys` stored verify the event.

```rust
// 0.5.x
let event = chat.decrypt_event(event_b64, &keys, &signing_keys)?;

// 0.6.0
let event = chat.decrypt_event(DecryptEventParams::new(event_b64, keys).with_signing_keys(signing_keys))?;
```

## Encrypt and prepare methods take params by reference

Every encrypt and prepare method takes its params by reference. Add `&` to
`encrypt_message`, `encrypt_reply`, `prepare_conversation_key_change`,
`prepare_group_create` and `prepare_group_members_change`, and to the
`ChatCore` methods' `_with_version` forms. Calls to
`encrypt_add_reaction`, `encrypt_remove_reaction`, `encrypt_edit` and
`prepare_message_delete` stay as they are, and the file and read-receipt
methods take `&params` too.

```rust
// 0.5.x
let payload = chat.encrypt_message(EncryptMessageParams::new(conversation_id, "hello"))?;
let reply = chat.encrypt_reply(EncryptReplyParams::new(conversation_id, "pong", event_b64))?;
let prepared = chat.prepare_conversation_key_change(key_change)?;

// 0.6.0
let payload = chat.encrypt_message(&EncryptMessageParams::new(conversation_id, "hello"))?;
let reply = chat.encrypt_reply(&EncryptReplyParams::new(conversation_id, "pong", event_b64))?;
let prepared = chat.prepare_conversation_key_change(&key_change)?;
```

## `SendPayload` fields take the send request's names

The two encoded fields carry the names of the fields of the send request,
`POST /2/chat/conversations/{id}/messages`, so the request takes them as
they are:

```rust
// 0.5.x
let body = serde_json::json!({
    "message_id": payload.message_id,
    "encoded_message_create_event": payload.encrypted_content,
    "encoded_message_event_signature": payload.encoded_event_signature,
});

// 0.6.0
let body = serde_json::json!({
    "message_id": payload.message_id,
    "encoded_message_create_event": payload.encoded_message_create_event,
    "encoded_message_event_signature": payload.encoded_message_event_signature,
});
```

`SendPayload` also carries `event_b64`, the message as recipients receive
it. It isn't part of the send request: keep it to encrypt the message's
files (see [Encrypt a file from its message](#encrypt-a-file-from-its-message)).

`SendPayload` is `#[non_exhaustive]`: code outside the SDK reads its fields
but can't build one with a struct literal. A payload that 0.5.x serialized
still deserializes into the new fields, with `event_b64` and `xdk_version`
empty.

## Encrypt a file from its message

Each file is encrypted from the message that carries it, so build the
message first:

1. Start each file's upload with `POST /2/chat/media/upload/initialize`,
   declaring `utils::encrypted_file_size` of the file's size as
   `total_bytes`, and keep the `session_id` and `media_hash_key` it returns.
2. Encrypt the message with attachments that name those media hash keys.
3. Encrypt each file with `encrypt_file`, passing the payload's `event_b64`
   and the file's media hash key.
4. Upload each encrypted file with `POST
   /2/chat/media/upload/{session_id}/append` and finish it with `POST
   /2/chat/media/upload/{session_id}/finalize`, then send the message.

```rust
// 0.5.x
let encrypted = chat.encrypt_stream(&photo, &keys[conversation_key_version])?;
let upload = api.post("/2/chat/media/upload/initialize", &serde_json::json!({
    "conversation_id": conversation_id, "total_bytes": encrypted.len(),
}))?;
let media_hash_key = upload["data"]["media_hash_key"].as_str().ok_or("no media_hash_key")?;
let mut params = EncryptMessageParams::new(conversation_id, "a photo");
params.attachments = Some(vec![photo_attachment(media_hash_key)]);
let payload = chat.encrypt_message(params)?;

// 0.6.0
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

The `append` and `finalize` requests don't change, but they come after
`encrypt_file`, which produces the bytes they upload. The upload requests
take `conversation_id` in its colon form, as the SDK does. The snippet
uploads the file in one segment; a larger file goes up in several `append`
requests, `segment_index` 0, 1 and so on (the examples send 3 MB segments),
with their count as `num_parts`.

Like `encrypt_message`, `EncryptFileParams` takes the conversation key and
its version with `with_conversation_key` (or resolves both from the key
cache when it's not called), and they must be the ones the message was
encrypted under. The file call needs no session identity: it reads the
sender, the message id and the key version from `event_b64`.

Upload each file for one message only. In v1 the id of a message with files
is derived from its conversation key and version, its sender, its
conversation and its files' media hash keys, but not its text: encrypting
the same message again gives the same id, so files you already encrypted
for it stay valid, and a second message that reuses the first one's uploads
gets the same id, so recipients drop it as a repeat. A message that lists an
empty media hash key, or one media hash key twice, is rejected.

## Decrypt a file with its message's event

Pass the downloaded bytes, the base64 event of the message that carries the
file and the conversation key map (the values `decrypt_event` takes), and
the file's media hash key from the decrypted message: one of its media
attachments, a link card's banner or favicon (both listed in
`media_hashes`), or media quoted in its reply preview. The SDK finds the
file in the event and derives its key. It doesn't check the message's
signature: use `verified` from `decrypt_event` for that.

```rust
// 0.5.x
let plaintext = chat.decrypt_stream(&downloaded, &keys[conversation_key_version])?;

// 0.6.0
let plaintext = chat.decrypt_file(DecryptFileParams::new(downloaded, file_event_b64, keys, file_hash_key))?;
```

## Encrypt and decrypt large files in chunks

`file_encryptor` and `file_decryptor` take the same values as
`encrypt_file` and `decrypt_file`, without the file bytes, and return a
`FileEncryptor` or a `FileDecryptor`; `push` and `finish` are unchanged.
Size an upload with `utils::encrypted_file_size`.

```rust
// 0.5.x
let size = chat_xdk_core::utils::encrypted_stream_size(photo.len() as u64);
let encryptor = chat.stream_encryptor(&keys[conversation_key_version])?;
let decryptor = chat.stream_decryptor(&keys[conversation_key_version])?;

// 0.6.0
let size = chat_xdk_core::utils::encrypted_file_size(photo.len() as u64);
let encryptor = chat.file_encryptor(&FileEncryptorParams::new(&payload.event_b64, &media_hash_key))?;
let decryptor = chat.file_decryptor(FileDecryptorParams::new(file_event_b64, keys, file_hash_key))?;
```

The functions in `crypto::encryption` that take a conversation key directly
take the same arguments under the file names:

```rust
// 0.5.x
use chat_xdk_core::crypto::encryption::{
    decrypt_stream, encrypt_stream, encrypted_stream_size, StreamDecryptor, StreamEncryptor,
};

// 0.6.0
use chat_xdk_core::crypto::encryption::{
    decrypt_file, encrypt_file, encrypted_file_size, FileDecryptor, FileEncryptor,
};
```

## Action signatures come nested

The prepare methods return each `ActionSignature` in the shape a request's
`action_signatures` takes: `message_id`, `encoded_message_event_detail`, the
signature in `message_event_signature` (a `signatures::MessageEventSignature`
with `signing_public_key`, your signing public key as `get_public_keys`
returns it) and, except for conversation-key changes, `signature_payload`.
Serialize them as returned:

```rust
// 0.5.x
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

// 0.6.0
let action_signatures = serde_json::to_value(&prepared.action_signatures)?;
```

A prepared change's `participant_keys` keep their shape (`user_id`,
`encrypted_key`, `public_key_version`): map them to the key-change request's
`conversation_participant_keys` as you do today.

## Deletes return a `PreparedAction`

`prepare_message_delete` returns a `PreparedAction` whose
`action_signatures` hold one entry, shaped as the previous section shows.
Read the action's `message_id` from that entry, and serialize
`action_signatures` as returned:

```rust
// 0.5.x
let deletion = chat.prepare_message_delete(&MessageDeleteParams::new(conversation_id, sequence_ids, false))?;
let message_id = deletion.message_id;

// 0.6.0
let deletion = chat.prepare_message_delete(&MessageDeleteParams::new(conversation_id, sequence_ids, false))?;
let message_id = deletion.action_signatures[0].message_id.clone();
```

## Invalid input errors

A missing or invalid parameter fails with `SdkError::InvalidInput`, whose
message names the value, such as `Invalid sender_id 'user-1': pass a numeric
user id (digits only)` or `too many attachments: at most 10 per message`.
`SdkError::InvalidState` is left for values the chat lacks, such as a
missing session identity or an empty key cache. Add an arm for the new
variant to any exhaustive `match` on `SdkError`, and match it where your
code checks for invalid input:

```rust
// 0.5.x
let invalid_input = matches!(err, SdkError::InvalidState(_));

// 0.6.0
let invalid_input = matches!(err, SdkError::InvalidInput(_));
```

## Signed read receipts

`prepare_mark_conversation_read` signs a read receipt for the newest event
you read. It takes a `MarkConversationReadParams` (the conversation id, that
event's sequence id, and an optional `seen_at_msec` that defaults to now)
and returns a `PreparedAction`, one entry shaped as
[Action signatures come nested](#action-signatures-come-nested) shows. Send
its `action_signatures` as those of the mark-read request,
`POST /2/chat/conversations/{id}/read`, whose path takes the conversation id
in its hyphen form. A recipient's `decrypt_event` returns a signed receipt
as a verified `ReadReceipt` event.

```rust
// 0.6.0
let receipt = chat.prepare_mark_conversation_read(&MarkConversationReadParams::new(
    conversation_id,
    seen_until_sequence_id,
))?;
let path = format!("/2/chat/conversations/{}/read", conversation_id.replace(':', "-"));
api.post(&path, &serde_json::json!({ "action_signatures": receipt.action_signatures }))?;
```
