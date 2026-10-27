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
- [ ] [Pass params by reference to every method](#methods-take-params-by-reference)
- [ ] [Build params with `new` and `with_*`, and give matches on SDK enums a wildcard arm](#types-are-non_exhaustive)
- [ ] [Read `SendPayload` under the send request's field names and send `xdk_version`](#sendpayload-fields-take-the-send-requests-names)
- [ ] [Build a message before you encrypt its files](#encrypt-a-file-from-its-message)
- [ ] [Decrypt a file with the event of its message](#decrypt-a-file-with-its-messages-event)
- [ ] [Use `file_encryptor` and `file_decryptor` for large files](#encrypt-and-decrypt-large-files-in-chunks)
- [ ] [Pass action signatures through as returned](#action-signatures-come-nested)
- [ ] [Pass participant keys through as returned](#participant-keys-take-the-key-requests-names)
- [ ] [Read received participant keys under the same names](#received-participant-keys-take-the-same-names)
- [ ] [Read decrypted events under the names the calls take](#decrypted-events-use-the-names-the-calls-take)
- [ ] [Read a delete's signature from its `PreparedAction`](#deletes-return-a-preparedaction)
- [ ] [Match `SdkError::InvalidInput` for invalid input](#invalid-input-errors)
- [ ] [Group actions should be signed](#group-actions-should-be-signed)
- [ ] [Pass group titles and descriptions as plaintext, read them as `GroupText`, and sign an avatar by its media URL](#creating-a-group)
- [ ] [Sign read receipts](#read-receipts-should-be-signed)

## About the snippets

Each snippet shows the lines that change, first as 0.5.x code writes them
and then as 0.6.0 code writes them. `chat` is a `ChatCore` with your keys
loaded; `Chat`, which adds Juicebox key storage, has the same methods. The
other names stand for your own values: ids, versions, keys and events as the
X API returns them, `keys` for the conversation key map `decrypt_events`
returns, `payload` for a `SendPayload`, `prepared` for a
`PreparedConversationChange`, `key_change` for a
`ConversationKeyChangeParams`, `received_key_change`, `message`, `deleted`,
`receipt` and `group_change` for a decrypted `KeyChangeEvent`, `Message`,
`MessageDeletedEvent`, `ReadReceiptEvent` and `GroupChangeEvent`, and `err`
for an `SdkError`. `api.post(path, &body)` stands for your HTTP client: it
POSTs `body`, a `serde_json::Value`, to `https://api.x.com` + `path` with
your user access token and returns the parsed JSON response as a
`serde_json::Value`. `photo_attachment(media_hash_key)` stands for your code
that builds a photo's `AttachmentDescriptor`, and `show_edit`, `show_title`,
`show_description` and `show_avatar` for your code that displays an edit, or
a group's title, description or avatar. Every type and module the snippets
use imports from `chat_xdk_core`, except `SdkError`, which imports from
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
let reply = EncryptReplyParams::new(conversation_id, "pong", event_b64).with_reply_to_sender_id("4201");
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
let result = chat.decrypt_events(&DecryptEventsParams::new(events).with_signing_keys(signing_keys));
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
let event = chat.decrypt_event(&DecryptEventParams::new(event_b64, keys).with_signing_keys(signing_keys))?;
```

## Methods take params by reference

Every method takes its params by reference. Add `&` to `encrypt_message`,
`encrypt_reply`, `prepare_conversation_key_change`, `prepare_group_create`
and `prepare_group_members_change`, and to the `ChatCore` methods'
`_with_version` forms. Calls to `encrypt_add_reaction`,
`encrypt_remove_reaction`, `encrypt_edit` and `prepare_message_delete` stay
as they are; `decrypt_events`, `decrypt_event`, `encrypt_file`,
`file_encryptor`, `decrypt_file`, `file_decryptor` and
`prepare_mark_conversation_read` take `&params` too, and
`set_signing_keys` takes a slice.

```rust
// 0.5.x
let payload = chat.encrypt_message(EncryptMessageParams::new(conversation_id, "hello"))?;
let reply = chat.encrypt_reply(EncryptReplyParams::new(conversation_id, "pong", event_b64))?;
let prepared = chat.prepare_conversation_key_change(key_change)?;
chat.set_signing_keys(signing_keys);

// 0.6.0
let payload = chat.encrypt_message(&EncryptMessageParams::new(conversation_id, "hello"))?;
let reply = chat.encrypt_reply(&EncryptReplyParams::new(conversation_id, "pong", event_b64))?;
let prepared = chat.prepare_conversation_key_change(&key_change)?;
chat.set_signing_keys(&signing_keys);
```

## Types are `#[non_exhaustive]`

Every public enum, params struct and result struct is `#[non_exhaustive]`,
so a later release can add a variant or a field without breaking your code.
Code outside the SDK can't build one with a struct literal:

- Build params with `new`, which takes the required fields, and set the
  optional ones with the `with_*` methods or by assigning the field.
- Build `PublicKeyInput`, `SigningKeyEntry`, `EntityDescriptor` and
  `UrlAttachmentImageDescriptor` with `new`, and the quick-reply options with
  `new` and their `with_*` methods.
- Read result types such as `SendPayload` and `PreparedConversationChange`
  by field.
- Give a `match` on an SDK enum, `SdkError` included, a wildcard arm, and end
  a pattern on a variant with named fields, such as `MessageContent::Edit`,
  in `..`.

```rust
// 0.5.x
let signing_key = SigningKeyEntry {
    user_id: user_id.to_string(),
    public_key_version: public_key_version.to_string(),
    public_key: signing_public_key.to_string(),
    identity_public_key: identity_public_key.to_string(),
    identity_public_key_signature: identity_public_key_signature.to_string(),
};
let mut params = EncryptMessageParams::new(conversation_id, "@user hello");
params.entities = Some(vec![EntityDescriptor { start: 0, end: 5, entity_type: "mention".to_string() }]);
params.ttl_msec = Some(86_400_000);

// 0.6.0
let signing_key = SigningKeyEntry::new(
    user_id,
    public_key_version,
    signing_public_key,
    identity_public_key,
    identity_public_key_signature,
);
let params = EncryptMessageParams::new(conversation_id, "@user hello")
    .with_entities(vec![EntityDescriptor::new(0, 5, "mention")])
    .with_ttl_msec(86_400_000);
```

## `SendPayload` fields take the send request's names

The two encoded fields carry the names of the fields of the send request,
`POST /2/chat/conversations/{id}/messages`, so the request takes them as
they are. The request also takes the payload's `xdk_version`, the version
of the SDK that built it:

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
    "xdk_version": payload.xdk_version,
});
```

`SendPayload` also carries `event_b64`, the message as recipients receive
it. It isn't part of the send request: keep it to encrypt the message's
files (see [Encrypt a file from its message](#encrypt-a-file-from-its-message)).

Read payloads under the new names wherever your code reads one, including
code that stores payloads.

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
let params = EncryptMessageParams::new(conversation_id, "a photo")
    .with_attachments(vec![photo_attachment(media_hash_key)]);
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
let plaintext = chat.decrypt_file(&DecryptFileParams::new(downloaded, file_event_b64, keys, file_hash_key))?;
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
let decryptor = chat.file_decryptor(&FileDecryptorParams::new(file_event_b64, keys, file_hash_key))?;
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

## Participant keys take the key requests' names

A prepared change's participant keys carry the names the X API gives them in
every request that takes them (`POST /2/chat/conversations/{id}/keys`,
`/group` and `/{id}/members`, and `PUT /2/chat/conversations/{id}`):
`conversation_participant_keys`, each entry a `ConversationParticipantKey`
with `user_id`, `encrypted_conversation_key` and `public_key_version`, the
type a received key change uses too
(see [Received participant keys take the same names](#received-participant-keys-take-the-same-names)). Drop the renaming
and pass them through as returned:

```rust
// 0.5.x
let conversation_participant_keys: Vec<serde_json::Value> = prepared
    .participant_keys
    .iter()
    .map(|key| {
        serde_json::json!({
            "user_id": key.user_id,
            "encrypted_conversation_key": key.encrypted_key,
            "public_key_version": key.public_key_version,
        })
    })
    .collect();

// 0.6.0
let conversation_participant_keys = &prepared.conversation_participant_keys;
```

## Received participant keys take the same names

A decrypted `KeyChangeEvent` carries its participant keys under the names
Thrift's `ConversationKeyChangeEvent` gives them, the same names a prepared
change uses: `conversation_participant_keys`, each entry with `user_id`,
`encrypted_conversation_key` and `public_key_version`. Received and prepared
keys are one type, `ConversationParticipantKey`:

```rust
// 0.5.x
let key: &ParticipantKey = &received_key_change.participant_keys[0];
let encrypted = &key.encrypted_key;

// 0.6.0
let key: &ConversationParticipantKey = &received_key_change.conversation_participant_keys[0];
let encrypted = &key.encrypted_conversation_key;
```

## Decrypted events use the names the calls take

`Message` and `KeyChangeEvent` carry their conversation key version as
`conversation_key_version`, the name the X API's events and the Thrift
events give it, and the name the encrypt params take:

```rust
// 0.5.x
let message_version = message.key_version.as_deref();
let key_change_version = received_key_change.key_version.as_str();

// 0.6.0
let message_version = message.conversation_key_version.as_deref();
let key_change_version = received_key_change.conversation_key_version.as_str();
```

Fields that hold sequence ids take the names of the params that send them.
`MessageContent::Reaction`, `ReactionRemoved` and `Edit` name their target
`target_message_sequence_id`, as `EncryptReactionParams` and
`EncryptEditParams` do. `MessageDeletedEvent` names its messages
`sequence_ids`, as `MessageDeleteParams` does, and `ReadReceiptEvent` and
`MarkedUnreadEvent` name their position `seen_until_sequence_id`, as
`MarkConversationReadParams` does. An edit's text is `updated_text`, as
`EncryptEditParams` names it, and a v1 edit carries the signed `message_id`
of the message it edits as `target_message_id`, `None` for a v0 edit:

```rust
// 0.5.x
if let MessageContent::Edit { target_message_id, new_text, .. } = &message.content {
    show_edit(target_message_id, new_text);
}
let deleted_sequence_ids = &deleted.message_ids;
let seen_until = receipt.seen_until_id.as_deref();

// 0.6.0
if let MessageContent::Edit { target_message_sequence_id, updated_text, .. } = &message.content {
    show_edit(target_message_sequence_id, updated_text);
}
let deleted_sequence_ids = &deleted.sequence_ids;
let seen_until = receipt.seen_until_sequence_id.as_deref();
```

## Deletes return a `PreparedAction`

`prepare_message_delete` returns a `PreparedAction` whose
`action_signatures` hold one entry, shaped as [Action signatures come
nested](#action-signatures-come-nested) shows. Read the action's
`message_id` from that entry, and serialize `action_signatures` as returned:

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
missing session identity or an empty key cache. Match the new variant where
your code checks for invalid input; a `match` on `SdkError` takes a wildcard
arm (see [Types are `#[non_exhaustive]`](#types-are-non_exhaustive)):

```rust
// 0.5.x
let invalid_input = matches!(err, SdkError::InvalidState(_));

// 0.6.0
let invalid_input = matches!(err, SdkError::InvalidInput(_));
```

## Group actions should be signed

Apps should sign each group update below. The sender comes from
`set_identity`. Each returns `action_signatures` shaped as
[Action signatures come nested](#action-signatures-come-nested) shows. Send
those entries on the update's request.

### Creating a group

`prepare_group_create` encrypts the group's title under the conversation key
it creates, so pass it as plaintext. The result is a
`PreparedConversationChange` that also carries it encrypted, as
`encrypted_title` (`None` when unset): send that as the create request's
`group_name`, next to its participant keys and signatures. The create signs
the encrypted value, which is base64, so a title may contain a comma; a
value signed as is, such as an avatar URL, can't. A create sets no avatar:
set one afterwards with an [avatar change](#changing-the-avatar), with the
image encrypted under the key the create returns.

```rust
// 0.5.x
let mut create = GroupCreateParams::new(public_keys, conversation_id, member_ids, admin_ids);
create.title = Some(title.to_string());
create.avatar_url = Some(avatar_url.to_string());
let prepared = chat.prepare_group_create(create)?;
let body = serde_json::json!({ "group_name": title, "group_avatar_url": avatar_url });

// 0.6.0
let create = GroupCreateParams::new(public_keys, conversation_id, member_ids, admin_ids).with_title(title);
let prepared = chat.prepare_group_create(&create)?;
let body = serde_json::json!({ "group_name": prepared.encrypted_title });
```

`decrypt_event` returns a received group create with its title decrypted
with the key for the version the create names, from the call's key map or
the key cache: `GroupChange::Created`'s `title` is a `GroupText`. `Text`
holds the title. `Unavailable` holds the value as the create carries it,
when that key isn't there or the value doesn't decrypt under it, and the
rest of the create still decrypts. 0.5.x signed a create's title as the app
passed it, so a 0.5.x app's create with a plaintext title arrives as
`Unavailable` with the title in `raw`: show `raw` when a title isn't
decryptable. A create that names no key version carries its title as
plaintext, and arrives as `Text`. The encrypted `group_name` and
`group_description` the X API returns with a conversation still open with
`decrypt`.

```rust
// 0.5.x
if let GroupChange::Created { title: Some(title), .. } = &group_change.change {
    show_title(&chat.decrypt(title, &keys[conversation_key_version])?);
}

// 0.6.0
if let GroupChange::Created { title: Some(title), .. } = &group_change.change {
    match title {
        GroupText::Text { text, .. } => show_title(text),
        GroupText::Unavailable { raw, .. } => show_title(raw),
        _ => {}
    }
}
```

`Created` also carries the create's `conversation_key_version`, and the
`avatar_url` a create from another client may set: a media URL whose image
is encrypted under that key version.

### Adding members

`prepare_group_members_change` rotates the conversation key, so it
re-encrypts the group's title and description under the key it generates:
pass them as plaintext, with `with_current_title` and
`with_current_description`, not as values your code encrypted. The result
carries them encrypted, as `encrypted_title` and `encrypted_description`
(`None` when unset). Send `encrypted_title` as the add-members request's
`encrypted_title`; the description travels in the signed member add.

```rust
// 0.5.x
let mut add = GroupMembersChangeParams::new(public_keys, conversation_id, new_member_ids, member_ids, admin_ids, vec![]);
add.current_title = Some(title.to_string());
let prepared = chat.prepare_group_members_change(add)?;

// 0.6.0
let add = GroupMembersChangeParams::new(public_keys, conversation_id, new_member_ids, member_ids, admin_ids, vec![])
    .with_current_title(title)
    .with_current_description(description);
let prepared = chat.prepare_group_members_change(&add)?;
let body = serde_json::json!({ "encrypted_title": prepared.encrypted_title });
```

Passing a description makes the add sign at signature version 8, the first
version whose member-add payload covers one, and 0.5.x readers can't verify
a version-8 add. Until every app that reads your groups runs 0.6.0, leave
the description out, so the add signs at version 7 as in 0.5.x; the new
members can read the description once a description change sets it under the
new key.

The avatar isn't re-encrypted: `with_current_avatar_url` takes its media
URL, signed as is, and the image stays encrypted under the key it was
uploaded with, which the new members never receive. To keep the avatar
readable for them, encrypt the image under the key the add returns, upload
it, and send an [avatar change](#changing-the-avatar) naming the new key
version.

### Removing members

`prepare_group_members_remove` removes `user_ids` and rotates the
conversation key, so the members removed don't receive the key the group
encrypts under next. `GroupMembersRemoveParams::new` takes the identity keys
of the members who stay, the conversation id and the members to remove; a
key for a member being removed is rejected. The group's title and
description are encrypted under the conversation key: pass the ones the
group has, as plaintext, with `with_title` and `with_description`, and the
call encrypts each under the new key and signs it as a key-rotation
re-encryption, which X clients don't show as a change. A rotation leaves the
avatar alone: its image stays encrypted under the key it was uploaded with,
which the members who stay hold.

The result is a `PreparedConversationChange`: the new conversation key,
`conversation_participant_keys` for the members who stay, and
`action_signatures` in request order — the removal, a title change and a
description change for the ones passed, then the conversation-key change.
Store the new key as you store the key a key change returns.

The removal signs at signature version 11, the first whose removal payload
covers the key version, and 0.5.x readers can't verify it: upgrade every app
that reads your groups before you remove members.

POST `/2/chat/conversations/{id}/members/remove` with `user_ids`, the
signatures, and `group_key_rotation_data` holding the new
`conversation_key_version` and `conversation_participant_keys`.

```rust
// 0.6.0
let removal = GroupMembersRemoveParams::new(remaining_public_keys, conversation_id, user_ids.clone())
    .with_title(title);
let prepared = chat.prepare_group_members_remove(&removal)?;
let path = format!("/2/chat/conversations/{conversation_id}/members/remove");
api.post(&path, &serde_json::json!({
    "user_ids": user_ids,
    "action_signatures": prepared.action_signatures,
    "group_key_rotation_data": {
        "conversation_key_version": prepared.conversation_key_version,
        "conversation_participant_keys": prepared.conversation_participant_keys,
    },
}))?;
```

### Leaving a group

`prepare_group_leave` signs the sender's removal and does not rotate the
conversation key. `action_signatures` are the removal, then a
`GroupAdminAddChange` when `promote_admin_id` is set, then a
`ConversationDeleteEvent`. It returns a `PreparedAction`.

```rust
// 0.6.0
let leave = GroupLeaveParams::new(conversation_id).with_promote_admin_id(promote_admin_id);
let left = chat.prepare_group_leave(&leave)?;
// left.action_signatures: removal, GroupAdminAddChange, ConversationDeleteEvent
```

### Changing the title

`prepare_group_title_change` takes the new title as plaintext, encrypts it
under the conversation key and signs it. Like `EncryptMessageParams`,
`GroupTitleChangeParams` takes the key and its version with
`with_conversation_key`, or resolves both from the key cache when it's not
called. The result is a `PreparedGroupMetadataChange`: the
`encrypted_value` the request sends as the title, the
`conversation_key_version` it's encrypted under, and the
`action_signatures` to send with it.

```rust
// 0.5.x
let encrypted_title = chat.encrypt(title, &keys[conversation_key_version])?;

// 0.6.0
let prepared = chat.prepare_group_title_change(&GroupTitleChangeParams::new(conversation_id, title))?;
let encrypted_title = prepared.encrypted_value;
```

`decrypt_event` returns a received title change decrypted: the `new_title`
of `GroupChange::TitleChanged` is a `GroupText`, as a create's `title` is.
It decrypts with the key for the version the change names, from the call's
key map or the key cache. Without that key, or when the value isn't
ciphertext under it, as for a plaintext title an app signed with a key
version, it is `Unavailable` with the value as carried, and the event still
decrypts.

```rust
// 0.5.x
if let GroupChange::TitleChanged { new_title } = &group_change.change {
    show_title(&chat.decrypt(new_title, &keys[conversation_key_version])?);
}

// 0.6.0
if let GroupChange::TitleChanged { new_title, .. } = &group_change.change {
    match new_title {
        GroupText::Text { text, .. } => show_title(text),
        GroupText::Unavailable { raw, .. } => show_title(raw),
        _ => {}
    }
}
```

### Changing the avatar

An avatar URL is not encrypted; the image is. Encrypt the image bytes under
the conversation key, upload them to the group's media, and pass the image's
media URL to `prepare_group_avatar_change`, with the version of the key the
image is encrypted under. The call signs both as they are and returns a
`PreparedAction`; send its `action_signatures` with the URL. A URL
containing a comma is rejected, since signatures join their fields with
commas.

```rust
// 0.5.x
let encrypted_avatar_url = chat.encrypt(avatar_url, &keys[conversation_key_version])?;

// 0.6.0
let prepared = chat.prepare_group_avatar_change(&GroupAvatarChangeParams::new(
    conversation_id,
    avatar_url,
    conversation_key_version,
))?;
```

A received `GroupChange::AvatarChanged` holds `new_avatar_url` as sent and
its `conversation_key_version`: download the image and decrypt it with the
key for that version.

```rust
// 0.6.0
if let GroupChange::AvatarChanged { new_avatar_url, conversation_key_version, .. } = &group_change.change {
    show_avatar(new_avatar_url, conversation_key_version.as_deref());
}
```

### Changing the description

`prepare_group_description_change` takes the new description as plaintext
and returns a `PreparedGroupMetadataChange`, as the title change does.

```rust
// 0.5.x
let encrypted_description = chat.encrypt(description, &keys[conversation_key_version])?;

// 0.6.0
let prepared = chat.prepare_group_description_change(&GroupDescriptionChangeParams::new(
    conversation_id,
    description,
))?;
let encrypted_description = prepared.encrypted_value;
```

A received description change is a `GroupChange::DescriptionChanged` holding
`new_description` as a `GroupText`; read it as a title change's `new_title`:

```rust
// 0.6.0
if let GroupChange::DescriptionChanged { new_description, .. } = &group_change.change {
    match new_description {
        GroupText::Text { text, .. } => show_description(text),
        GroupText::Unavailable { raw, .. } => show_description(raw),
        _ => {}
    }
}
```

### Adding admins

```rust
// 0.6.0
let added = chat.prepare_group_admins_add(&GroupAdminsAddParams::new(conversation_id, user_ids))?;
```

### Removing admins

```rust
// 0.6.0
let removed = chat.prepare_group_admins_remove(
    &GroupAdminsRemoveParams::new(conversation_id, user_ids),
)?;
```

### Enabling an invite

An omitted `expires_at_msec` or `affiliate_id` signs `null`.

```rust
// 0.6.0
let invite = chat.prepare_group_invite_enable(
    &GroupInviteEnableParams::new(conversation_id, invite_url),
)?;
```

### Disabling an invite

`disabled_by` defaults to the sender.

```rust
// 0.6.0
let disabled = chat.prepare_group_invite_disable(&GroupInviteDisableParams::new(conversation_id))?;
```

### Requesting to join

`requesting_user_id` defaults to the sender. An invite token is not part of
the signature.

```rust
// 0.6.0
let request = chat.prepare_group_join_request(&GroupJoinRequestParams::new(conversation_id))?;
```

### Rejecting join requests

```rust
// 0.6.0
let rejected = chat.prepare_group_join_reject(
    &GroupJoinRejectParams::new(conversation_id, user_ids),
)?;
```

### Changing the message TTL

The signature covers `ttl_msec` only.

```rust
// 0.6.0
let ttl = chat.prepare_message_ttl_change(
    &MessageTtlChangeParams::new(conversation_id, ttl_msec),
)?;
```

### Removing the message TTL

```rust
// 0.6.0
let cleared = chat.prepare_message_ttl_remove(&MessageTtlRemoveParams::new(conversation_id))?;
```

### Changing screen capture

`change` is a `ScreenCaptureChange`: `BlockingEnabled`,
`BlockingDisabled`, `DetectionEnabled`, or `DetectionDisabled`.

```rust
// 0.6.0
let capture = chat.prepare_screen_capture(&ScreenCaptureParams::new(
    conversation_id,
    ScreenCaptureChange::BlockingEnabled,
))?;
```

## Read receipts should be signed

Apps should sign a read receipt with `prepare_mark_conversation_read` and
send the `PreparedAction`'s `action_signatures` on
`POST /2/chat/conversations/{id}/read`. Recipients on the default policy
reject an unsigned receipt. The call takes a `MarkConversationReadParams`
(the conversation id, the sequence id of the newest event read, and a
`seen_at_msec` that defaults to now) and returns a `PreparedAction`, one
entry shaped as
[Action signatures come nested](#action-signatures-come-nested) shows. The
path takes the conversation id in its hyphen form. A recipient's
`decrypt_event` returns a signed receipt as a verified `ReadReceipt` event.

```rust
// 0.6.0
let receipt = chat.prepare_mark_conversation_read(&MarkConversationReadParams::new(
    conversation_id,
    seen_until_sequence_id,
))?;
let path = format!("/2/chat/conversations/{}/read", conversation_id.replace(':', "-"));
api.post(&path, &serde_json::json!({ "action_signatures": receipt.action_signatures }))?;
```
