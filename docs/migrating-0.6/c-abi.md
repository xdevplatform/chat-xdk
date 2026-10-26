# Migrating C ABI callers to chat-xdk 0.6.0

This page lists every change that code calling the chat-xdk C ABI directly
runs into in 0.6.0, coming from 0.5.x (0.5.0, 0.5.1 or 0.5.2). The ABI is
declared in
[`go/chatxdk/include/chat_xdk.h`](../../go/chatxdk/include/chat_xdk.h), and
the native libraries in the .NET and JVM packages export the same functions.
[Why 0.6.0 changes](why.md) explains why each change was made, and the
[index](README.md) lists the language bindings' pages.

Every entry point whose arguments changed takes a new name, so a stale
header or library fails to link instead of misreading its arguments.

## Checklist

- [ ] [Upgrade every app that reads your conversations first](#upgrade-readers-before-v1-sends-start)
- [ ] [Register keys with the public key only](#register-keys-with-the-public-key-only)
- [ ] [Set the identity with `chat_xdk_set_identity_params`](#set-the-identity-with-a-params-document)
- [ ] [Import keys with `chat_xdk_import_keys_params`](#import-keys-with-a-params-document)
- [ ] [Pass user ids and key versions as strings of digits](#user-ids-and-key-versions-are-strings-of-digits)
- [ ] [Decrypt with `chat_xdk_decrypt_events_params` and `chat_xdk_decrypt_event_params`](#decrypt-with-params-documents)
- [ ] [Read the send payload under the send request's field names and send `xdk_version`](#the-send-payload-takes-the-send-requests-field-names)
- [ ] [Build a message before you encrypt its files](#encrypt-a-file-from-its-message)
- [ ] [Decrypt a file with the event of its message](#decrypt-a-file-with-its-messages-event)
- [ ] [Use the file encryptor and decryptor for large files](#encrypt-and-decrypt-large-files-in-chunks)
- [ ] [Pass action signatures through as returned](#action-signatures-come-nested)
- [ ] [Pass participant keys through as returned](#participant-keys-take-the-key-requests-names)
- [ ] [Read received participant keys under the same names](#received-participant-keys-take-the-same-names)
- [ ] [Read decrypted events under the names the calls take](#decrypted-events-use-the-names-the-calls-take)
- [ ] [Check code that reads error messages](#invalid-input-errors)
- [ ] [Group actions should be signed](#group-actions-should-be-signed)
- [ ] [Pass group titles, avatars and descriptions as plaintext, and read them decrypted](#changing-the-title)
- [ ] [Sign read receipts](#read-receipts-should-be-signed)

## About the snippets

Each snippet shows the lines that change, first as 0.5.x code writes them
and then as 0.6.0 code writes them. `chat` is a `ChatHandle *` with your
keys loaded, and `keys`, `keys_len` and `keys_b64` are your saved private
keys. `take(r)` stands for your error handling: it returns `r.data` (free it
with `chat_xdk_free_string`) and handles `r.error`. The `*_json` and `*_b64`
values are documents and base64 strings your code builds, `title`,
`avatar_url`, `description` and `new_title` are UTF-8 strings it holds, and
`encrypt_file_json(photo_message)` and `file_encryptor_json(photo_message)`
stand for building a file's params from a send payload's `event_b64`.

The params documents use the snake_case field names of the params types in
[API.md](../API.md), with byte fields (`file`, `encrypted`,
`conversation_key` and the values of `conversation_keys`) as base64
strings.

## Upgrade readers before v1 sends start

0.6.0 reads messages, replies, reactions and edits in two formats. v0 is the
format 0.5.x sends. v1 encrypts each message under its own key, derived from
the conversation key, the sender and the message id, and signs it at
signature version 10. The C ABI doesn't fetch the X API's feature switches,
so direct callers always send v0. The Python, JavaScript, Go, JVM and .NET
bindings send v1 while the X API's `v1_send` feature switch is on.

0.5.x rejects every v1 send as a signature verification failure, so upgrade
every app that reads your conversations to 0.6.0 before any sender can send
v1. 0.6.0 reads both formats, including v1 reply previews, edits and files.
There's no code to change: to see which format a send used, read the send
payload's `signature_info.signature_version`, `"7"` for v0 and `"10"` for
v1.

## Register keys with the public key only

`chat_xdk_generate_keypairs` returns a document that holds only
`public_key`. Send it as returned as the body of
`POST /2/users/{id}/public_keys`. 0.6.0 doesn't pick a signing-key version
for new keys: set the identity with the `public_key_version` the request
returns (see the next section). A signed call made without a version fails with `Invalid state:
signing_key_version is not set: pass it explicitly or call set_identity()
first`.

## Set the identity with a params document

`chat_xdk_set_identity_params` takes the user id and the signing-key
version as one document. It fails when either value is invalid (see
[user ids and key versions](#user-ids-and-key-versions-are-strings-of-digits)).

```c
// 0.5.x
take(chat_xdk_set_identity(chat, "4201", "1"));

// 0.6.0
take(chat_xdk_set_identity_params(chat, "{\"user_id\":\"4201\",\"signing_key_version\":\"1\"}"));
```

## Import keys with a params document

`chat_xdk_import_keys_params` takes the key bytes by pointer and length,
and a document with the optional signing-key version they were registered
under. Without a version, pass `"{}"` and set the identity before the first
signed call.

```c
// 0.5.x
take(chat_xdk_import_keys(chat, keys_b64));
take(chat_xdk_import_keys_with_version(chat, keys, keys_len, "1"));

// 0.6.0
take(chat_xdk_import_keys_params(chat, keys, keys_len, "{}"));
take(chat_xdk_import_keys_params(chat, keys, keys_len, "{\"signing_key_version\":\"1\"}"));
```

## User ids and key versions are strings of digits

Every user id in a document is a string of digits: the identity's
`user_id`, `sender_id`, `reply_to_sender_id` (a JSON string, not a number),
the `user_id` of each public key and signing key, and group member, admin
and pending-member ids. Each must be a positive integer written without a
sign or leading zeros. Every key version is a non-negative integer written
as a string of digits, as the X API returns it: the signing-key version
and `conversation_key_version`. Anything else fails with an error that
names the field, such as
`Invalid sender_id 'user-1': pass a numeric user id (digits only)`.

## Decrypt with params documents

`chat_xdk_decrypt_events_params` and `chat_xdk_decrypt_event_params` each
take one document. Leave out `signing_keys` to verify with the keys
`chat_xdk_set_signing_keys` stored, and `conversation_keys` to resolve the
key from the key cache.

```c
// 0.5.x
char *batch = take(chat_xdk_decrypt_events(chat, events_json, signing_keys_json));
char *event = take(chat_xdk_decrypt_event(chat, event_b64, conversation_keys_json, signing_keys_json));

// 0.6.0
// {"events":[...],"signing_keys":[...]}
char *batch = take(chat_xdk_decrypt_events_params(chat, decrypt_events_json));
// {"event_b64":"...","conversation_keys":{"<version>":"<base64 key>"},"signing_keys":[...]}
char *event = take(chat_xdk_decrypt_event_params(chat, decrypt_event_json));
```

## The send payload takes the send request's field names

The encrypt calls keep their names, and the send payload they return names
its two encoded fields `encoded_message_create_event` and
`encoded_message_event_signature`, the field names of the send request,
`POST /2/chat/conversations/{id}/messages`, so the request takes them as
they are, along with the payload's `xdk_version`, the version of the SDK
that built it. The payload also carries `event_b64`, the message as
recipients receive it: keep it to encrypt the message's files (see
[Encrypt a file from its message](#encrypt-a-file-from-its-message)).

## Encrypt a file from its message

Each file is encrypted from the message that carries it, so build the
message first:

1. Start each file's upload with `POST /2/chat/media/upload/initialize`,
   declaring `chat_xdk_encrypted_file_size` of the file's size as
   `total_bytes`, and keep the `session_id` and `media_hash_key` it returns.
2. Encrypt the message with attachments that name those media hash keys.
3. Encrypt each file with `chat_xdk_encrypt_file`, passing the payload's
   `event_b64` and the file's media hash key.
4. Upload each encrypted file with `POST
   /2/chat/media/upload/{session_id}/append` (`conversation_id`,
   `media_hash_key`, `segment_index` and the base64 bytes as `media`) and
   finish it with `POST /2/chat/media/upload/{session_id}/finalize`
   (`conversation_id`, `media_hash_key` and the segment count as
   `num_parts`), then send the message.

Like the message, the file takes `conversation_key` and
`conversation_key_version` (both, or neither to resolve them from the key
cache), and they must be the ones the message was encrypted under.

```c
// 0.5.x
char *encrypted = take(chat_xdk_encrypt_stream(chat, photo_b64, conversation_key_b64));
char *photo_message = take(chat_xdk_encrypt_message(chat, photo_message_json));

// 0.6.0
// {"file":"<base64>","event_b64":"...","media_hash_key":"...",
//  "conversation_key":"<base64 key>","conversation_key_version":"..."}
char *photo_message = take(chat_xdk_encrypt_message(chat, photo_message_json));
char *encrypted = take(chat_xdk_encrypt_file(chat, encrypt_file_json(photo_message)));
```

Upload each file for one message only. In v1 the id of a message with files
is derived from its conversation key and version, its sender, its
conversation and its files' media hash keys, but not its text: encrypting
the same message again gives the same id, so files you already encrypted
for it stay valid, and a second message that reuses the first one's uploads
gets the same id, so recipients drop it as a repeat. A message that lists an
empty media hash key, or one media hash key twice, is rejected.

## Decrypt a file with its message's event

`chat_xdk_decrypt_file` takes the downloaded bytes, the base64 event of the
message that carries the file, the conversation key map and the file's
media hash key from the decrypted message. The SDK finds the file in the
event and derives its key. It doesn't check the message's signature: use
`verified` from `chat_xdk_decrypt_event_params` for that.

```c
// 0.5.x
char *plaintext = take(chat_xdk_decrypt_stream(chat, downloaded_b64, conversation_key_b64));

// 0.6.0
// {"encrypted":"<base64>","event_b64":"...","conversation_keys":{...},"media_hash_key":"..."}
char *plaintext = take(chat_xdk_decrypt_file(chat, decrypt_file_json));
```

## Encrypt and decrypt large files in chunks

`chat_xdk_file_encryptor_new` and `chat_xdk_file_decryptor_new` take the
chat and the same document as `chat_xdk_encrypt_file` and
`chat_xdk_decrypt_file` without the file bytes. They return an `FfiResult`
and write the handle to their last argument. The push, finish and free
calls and `chat_xdk_encrypted_file_size` take the same arguments under the
file names.

```c
// 0.5.x
char *size = take(chat_xdk_encrypted_stream_size(1100));
StreamEncryptorHandle *encryptor = chat_xdk_stream_encryptor_new(conversation_key_b64);
char *head = take(chat_xdk_stream_encryptor_push(encryptor, photo_b64));
char *tail = take(chat_xdk_stream_encryptor_finish(encryptor));
chat_xdk_stream_encryptor_free(encryptor);

// 0.6.0
char *size = take(chat_xdk_encrypted_file_size(1100));
FileEncryptorHandle *encryptor = NULL;
take(chat_xdk_file_encryptor_new(chat, file_encryptor_json(photo_message), &encryptor));
char *head = take(chat_xdk_file_encryptor_push(encryptor, photo_b64));
char *tail = take(chat_xdk_file_encryptor_finish(encryptor));
chat_xdk_file_encryptor_free(encryptor);
```

The decryptor follows the same pattern: `chat_xdk_file_decryptor_new(chat,
params_json, &decryptor)`, then `chat_xdk_file_decryptor_push`, `_finish`
and `_free`.

## Action signatures come nested

`chat_xdk_prepare_conversation_key_change`, `chat_xdk_prepare_group_create`
and `chat_xdk_prepare_group_members_change` return each action signature in
the shape a request's `action_signatures` takes, with the signature nested
under `message_event_signature` alongside your `signing_public_key`.
`chat_xdk_prepare_message_delete` returns a document with
`action_signatures` holding one entry:

```c
// 0.5.x
// {"message_id":"...","encoded_message_event_detail":"...","signature":"...",...}
char *deletion = take(chat_xdk_prepare_message_delete(chat, delete_json));

// 0.6.0
// {"action_signatures":[{"message_id":"...","encoded_message_event_detail":"...",
//   "message_event_signature":{"signature":"...","signature_version":"7",
//   "public_key_version":"...","signing_public_key":"..."},"signature_payload":"..."}]}
char *deletion = take(chat_xdk_prepare_message_delete(chat, delete_json));
```

Send those entries as the request's `action_signatures`; the
`signature_payload` (the signed payload, a debugging aid) is left out for
conversation-key changes.

## Participant keys take the key requests' names

`chat_xdk_prepare_conversation_key_change`, `chat_xdk_prepare_group_create`
and `chat_xdk_prepare_group_members_change` name the participant keys as the
X API does in every request that takes them
(`POST /2/chat/conversations/{id}/keys`, `/group` and `/{id}/members`, and
`PUT /2/chat/conversations/{id}`): `conversation_participant_keys`, each
entry with `user_id`, `encrypted_conversation_key` and `public_key_version`,
the names a decrypted key change uses too
(see [Received participant keys take the same names](#received-participant-keys-take-the-same-names)). Send them as
returned, without renaming:

```c
// 0.5.x
// {...,"participant_keys":[{"user_id":"...","encrypted_key":"...",
//   "public_key_version":"..."}],...}
char *prepared = take(chat_xdk_prepare_conversation_key_change(chat, key_change_json));

// 0.6.0
// {...,"conversation_participant_keys":[{"user_id":"...",
//   "encrypted_conversation_key":"...","public_key_version":"..."}],...}
char *prepared = take(chat_xdk_prepare_conversation_key_change(chat, key_change_json));
```

## Received participant keys take the same names

`chat_xdk_decrypt_event_params` and `chat_xdk_decrypt_events_params` return
a key change's participant keys under the names Thrift's
`ConversationKeyChangeEvent` gives them, the same names a prepared change
uses: `conversation_participant_keys`, each entry with `user_id`,
`encrypted_conversation_key` and `public_key_version`:

```c
// 0.5.x
// {"type":"KeyChange",...,"participant_keys":[{"user_id":"...",
//   "encrypted_key":"...","public_key_version":"..."}]}
char *key_change = take(chat_xdk_decrypt_event(chat, key_change_b64, conversation_keys_json, signing_keys_json));

// 0.6.0
// {"type":"KeyChange",...,"conversation_participant_keys":[{"user_id":"...",
//   "encrypted_conversation_key":"...","public_key_version":"..."}]}
char *key_change = take(chat_xdk_decrypt_event_params(chat, decrypt_key_change_json));
```

## Decrypted events use the names the calls take

The decrypt calls return a message's or key change's conversation key
version as `conversation_key_version`, the name the X API's events and the
Thrift events give it, and the name the encrypt params take:

```c
// 0.5.x
// {"type":"Message",...,"key_version":"...",...}
char *message = take(chat_xdk_decrypt_event(chat, event_b64, conversation_keys_json, signing_keys_json));

// 0.6.0
// {"type":"Message",...,"conversation_key_version":"...",...}
char *message = take(chat_xdk_decrypt_event_params(chat, decrypt_event_json));
```

Fields that hold sequence ids take the names of the params that send them.
`Reaction`, `ReactionRemoved` and `Edit` content names its target
`target_message_sequence_id`, as the reaction and edit params do. A
`MessageDeleted` event names its messages `sequence_ids`, as the delete
params do, and a `ReadReceipt` or `MarkedUnread` event names its position
`seen_until_sequence_id`, as the read-receipt params do. An edit's text is
`updated_text`, as the edit params name it, and a v1 edit carries the
signed message id of the message it edits as `target_message_id`, absent
for a v0 edit:

```c
// 0.5.x
// {"type":"Message",...,"content":{"content_type":"Edit","target_message_id":"7","new_text":"..."}}
// {"type":"MessageDeleted",...,"message_ids":["7"],...}
// {"type":"ReadReceipt",...,"seen_until_id":"7",...}
char *event = take(chat_xdk_decrypt_event(chat, event_b64, conversation_keys_json, signing_keys_json));

// 0.6.0
// {"type":"Message",...,"content":{"content_type":"Edit","target_message_sequence_id":"7","updated_text":"..."}}
// {"type":"MessageDeleted",...,"sequence_ids":["7"],...}
// {"type":"ReadReceipt",...,"seen_until_sequence_id":"7",...}
char *event = take(chat_xdk_decrypt_event_params(chat, decrypt_event_json));
```

## Invalid input errors

A missing or invalid parameter fails with an error whose message names the
value, such as `Invalid sender_id 'user-1': pass a numeric user id (digits
only)` or `too many attachments: at most 10 per message`, without an
`Invalid state:` prefix. If your code looks for that prefix on these errors,
match the message instead. Errors about state the chat lacks, such as a
missing session identity or an empty key cache, keep their prefix.

## Group actions should be signed

Apps should sign each group update below. The sender comes from
`chat_xdk_set_identity_params`. Each returns JSON whose
`action_signatures` are shaped as
[Action signatures come nested](#action-signatures-come-nested) shows. Send
those entries on the update's request.

### Removing members

`chat_xdk_prepare_group_members_remove` removes `user_ids` and rotates the
conversation key, so the members removed don't receive the key the group
encrypts under next. `public_keys` are the identity keys of the members who
stay; a key for a member being removed is an error. The group's title,
avatar and description are encrypted under the conversation key: pass the
ones the group has, as plaintext, as `title`, `avatar_url` and
`description`, and the call encrypts each under the new key.

The result is a `PreparedConversationChange`: the new
`conversation_key` (base64), `conversation_participant_keys` for the
members who stay, and `action_signatures` in request order — the removal, a
change for each title, avatar and description passed, then the
conversation-key change. Store the new key as you store the key a key
change returns.

POST `/2/chat/conversations/{id}/members/remove` with `user_ids`, the
signatures, and `group_key_rotation_data` holding the new
`conversation_key_version` and `conversation_participant_keys`.

```c
// 0.6.0
// {"public_keys":[{"user_id":"111","public_key":"...","key_version":"1"}],
//  "conversation_id":"g1","user_ids":["222"],"title":"Team"}
char *prepared = take(chat_xdk_prepare_group_members_remove(chat, remove_json));
// POST /2/chat/conversations/g1/members/remove
// {"user_ids":["222"],
//  "action_signatures": <prepared.action_signatures>,
//  "group_key_rotation_data": {
//    "conversation_key_version": <prepared.conversation_key_version>,
//    "conversation_participant_keys": <prepared.conversation_participant_keys>}}
```

### Leaving a group

`chat_xdk_prepare_group_leave` signs the sender's removal and does not
rotate the conversation key. `action_signatures` are the removal, then a
`GroupAdminAddChange` when `promote_admin_id` is set, then a
`ConversationDeleteEvent`. It returns a `PreparedAction`.

```c
// 0.6.0
// {"conversation_id":"g1","promote_admin_id":"333"}
char *left = take(chat_xdk_prepare_group_leave(chat, leave_json));
// action_signatures: removal, GroupAdminAddChange, ConversationDeleteEvent
```

### Changing the title

`chat_xdk_prepare_group_title_change` takes the new title as plaintext,
encrypts it under the conversation key and signs it. Like the message
params, its params take the key and its version as `conversation_key`
(base64) and `conversation_key_version`, or resolve both from the key cache
without them. The result is a `PreparedGroupMetadataChange`: the
`encrypted_value` the request sends as the title, the
`conversation_key_version` it's encrypted under, and the
`action_signatures` to send with it.

```c
// 0.5.x
char *encrypted_title = take(chat_xdk_encrypt(chat, title, conversation_key_b64));

// 0.6.0
// {"conversation_id":"g1","new_title":"Team"}
char *title = take(chat_xdk_prepare_group_title_change(chat, title_json));
// {"encrypted_value":"...","conversation_key_version":"...","action_signatures":[...]}
```

The decrypt calls return a received title change decrypted: the
`new_title` of a `TitleChanged` change is the plaintext. They decrypt with
the key version the change names, from the call's key map or the key
cache, and fail without that key, as for a message.

```c
// 0.5.x
// {"type":"GroupChange",...,"change":{"change_type":"TitleChanged","new_title":"<ciphertext>"}}
char *event = take(chat_xdk_decrypt_event(chat, event_b64, conversation_keys_json, signing_keys_json));
char *title = take(chat_xdk_decrypt(chat, new_title, conversation_key_b64));

// 0.6.0
// {"type":"GroupChange",...,"change":{"change_type":"TitleChanged","new_title":"Team"}}
char *event = take(chat_xdk_decrypt_event_params(chat, decrypt_event_json));
```

### Changing the avatar

`chat_xdk_prepare_group_avatar_change` takes the new avatar URL as
plaintext and returns a `PreparedGroupMetadataChange`, as the title change
does. A received `AvatarChanged` change holds the decrypted
`new_avatar_url`.

```c
// 0.5.x
char *encrypted_avatar_url = take(chat_xdk_encrypt(chat, avatar_url, conversation_key_b64));

// 0.6.0
// {"conversation_id":"g1","new_avatar_url":"https://..."}
char *avatar = take(chat_xdk_prepare_group_avatar_change(chat, avatar_json));
```

### Changing the description

`chat_xdk_prepare_group_description_change` takes the new description as
plaintext and returns a `PreparedGroupMetadataChange`, as the title change
does. A received description change is a `DescriptionChanged` change
holding the decrypted `new_description`.

```c
// 0.5.x
char *encrypted_description = take(chat_xdk_encrypt(chat, description, conversation_key_b64));

// 0.6.0
// {"conversation_id":"g1","new_description":"..."}
char *description = take(chat_xdk_prepare_group_description_change(chat, description_json));
// {"type":"GroupChange",...,"change":{"change_type":"DescriptionChanged","new_description":"..."}}
```

### Adding admins

```c
// 0.6.0
// {"conversation_id":"g1","user_ids":["333"]}
char *added = take(chat_xdk_prepare_group_admins_add(chat, admins_json));
```

### Removing admins

```c
// 0.6.0
// {"conversation_id":"g1","user_ids":["333"]}
char *removed = take(chat_xdk_prepare_group_admins_remove(chat, admins_json));
```

### Enabling an invite

An omitted `expires_at_msec` or `affiliate_id` signs `null`. A negative
`expires_at_msec` signs `null` too.

```c
// 0.6.0
// {"conversation_id":"g1","invite_url":"https://example/invite","expires_at_msec":1700000000000}
char *invite = take(chat_xdk_prepare_group_invite_enable(chat, invite_json));
```

### Disabling an invite

An omitted `disabled_by` uses the sender.

```c
// 0.6.0
// {"conversation_id":"g1"}
char *disabled = take(chat_xdk_prepare_group_invite_disable(chat, invite_json));
```

### Requesting to join

An omitted `requesting_user_id` uses the sender. An invite token is not
part of the signature.

```c
// 0.6.0
// {"conversation_id":"g1"}
char *request = take(chat_xdk_prepare_group_join_request(chat, join_json));
```

### Rejecting join requests

```c
// 0.6.0
// {"conversation_id":"g1","user_ids":["444"]}
char *rejected = take(chat_xdk_prepare_group_join_reject(chat, join_json));
```

### Changing the message TTL

The signature covers `ttl_msec` only.

```c
// 0.6.0
// {"conversation_id":"g1","ttl_msec":86400000}
char *ttl = take(chat_xdk_prepare_message_ttl_change(chat, ttl_json));
```

### Removing the message TTL

```c
// 0.6.0
// {"conversation_id":"g1"}
char *cleared = take(chat_xdk_prepare_message_ttl_remove(chat, ttl_json));
```

### Changing screen capture

`change` is `BlockingEnabled`, `BlockingDisabled`, `DetectionEnabled`, or
`DetectionDisabled`.

```c
// 0.6.0
// {"conversation_id":"g1","change":"BlockingEnabled"}
char *capture = take(chat_xdk_prepare_screen_capture(chat, capture_json));
```

## Read receipts should be signed

Apps should sign a read receipt with
`chat_xdk_prepare_mark_conversation_read` and send the `PreparedAction`'s
`action_signatures` on `POST /2/chat/conversations/{id}/read`. Recipients on
the default policy reject an unsigned receipt. The call takes a document
with `conversation_id`, `seen_until_sequence_id` (the sequence id of the
newest event read) and a `seen_at_msec` that defaults to now, and returns
`action_signatures` as a delete does. The path takes the conversation id in
its hyphen form. A recipient's `chat_xdk_decrypt_event_params` returns a
signed receipt as a verified `ReadReceipt` event.

```c
// 0.6.0
// {"conversation_id":"...","seen_until_sequence_id":"..."}
char *receipt = take(chat_xdk_prepare_mark_conversation_read(chat, mark_read_json));
```
