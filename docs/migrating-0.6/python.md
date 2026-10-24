# Migrating Python code to chat-xdk 0.6.0

This page lists every change that Python code written for chat-xdk 0.5.x
(0.5.0, 0.5.1 or 0.5.2) runs into in 0.6.0, each with the lines to change.
[Why 0.6.0 changes](why.md) explains why each change was made, and the
[index](README.md) lists the other bindings' pages. [API.md](../API.md)
documents every call, and the [CHANGELOG](../../CHANGELOG.md) lists every
change.

## Checklist

- [ ] [Upgrade every app that reads your conversations first](#upgrade-readers-before-v1-sends-start)
- [ ] [Allow or block the feature-switch request](#the-feature-switch-request)
- [ ] [Register keys with the public key only](#register-keys-with-the-public-key-only)
- [ ] [Pass a `SetIdentityParams` to `set_identity`](#set_identity-takes-setidentityparams)
- [ ] [Pass an `ImportKeysParams` to `import_keys`](#import_keys-takes-importkeysparams)
- [ ] [Pass user ids as strings of digits](#user-ids-are-strings-of-digits)
- [ ] [Pass key versions as the X API returns them](#key-versions-are-integers-written-as-strings)
- [ ] [Pass a `DecryptEventsParams` to `decrypt_events`](#decrypt_events-takes-decrypteventsparams)
- [ ] [Pass a `DecryptEventParams` to `decrypt_event`](#decrypt_event-takes-decrypteventparams)
- [ ] [Pass a params class to every encrypt and prepare method](#encrypt-and-prepare-methods-take-params-classes)
- [ ] [Read `SendPayload` under the send request's field names and send `xdk_version`](#sendpayload-fields-take-the-send-requests-names)
- [ ] [Build a message before you encrypt its files](#encrypt-a-file-from-its-message)
- [ ] [Decrypt a file with the event of its message](#decrypt-a-file-with-its-messages-event)
- [ ] [Use `file_encryptor` and `file_decryptor` for large files](#encrypt-and-decrypt-large-files-in-chunks)
- [ ] [Pass action signatures through as returned](#action-signatures-come-nested)
- [ ] [Pass participant keys through as returned](#participant-keys-take-the-key-requests-names)
- [ ] [Read received participant keys under the same names](#received-participant-keys-take-the-same-names)
- [ ] [Read `conversation_key_version` on decrypted events](#decrypted-events-name-the-conversation-key-version-as-the-x-api-does)
- [ ] [Read a delete's signature from its `PreparedAction`](#deletes-return-a-preparedaction)
- [ ] [Check code that reads error messages](#invalid-input-errors)
- [ ] [Group actions should be signed](#group-actions-should-be-signed)
- [ ] [Optional: sign read receipts](#signed-read-receipts)

## About the snippets

Each snippet shows the lines that change, first as 0.5.x code writes them
and then as 0.6.0 code writes them. `chat` is a `Chat` with your keys
loaded, and the other names stand for your own values: ids, versions, keys
and events as the X API returns them, `keys` for the conversation key map
`decrypt_events` returns, `payload` for a `SendPayload`, `prepared` for
the dict a prepare method returns, and `key_change` and `message` for a
decrypted key change and message. `api.post(path, body)` stands for your
HTTP client: it POSTs `body` as JSON to `https://api.x.com` + `path` with
your user access token and returns the parsed JSON response.
`photo_attachment(media_hash_key)` stands for your code that builds a
photo's attachment descriptor. Every class and function the snippets use
imports from `chat_xdk`.

## Upgrade readers before v1 sends start

0.6.0 sends each message, reply, reaction and edit in one of two formats.
v0 is the format 0.5.x sends. v1 encrypts each message under its own key,
derived from the conversation key, the sender and the message id, and signs
it at signature version 10. A chat sends v1 while the X API's `v1_send`
feature switch is on for it, and v0 otherwise (see
[The feature-switch request](#the-feature-switch-request)).

0.5.x rejects every v1 send as a signature verification failure, so upgrade
every app that reads your conversations to 0.6.0 before your senders can
send v1. 0.6.0 reads both formats, including v1 reply previews, edits and
files. There's no code to change: to see which format a send used, read
`payload.signature_info.signature_version`, `"7"` for v0 and `"10"` for v1.

## The feature-switch request

Chats read the X API's feature switches with one anonymous request,
`GET https://api.x.com/2/chat/features`, which runs in the background:

- a chat reads them once, when it is created, and keeps the answer for its
  lifetime; chats created while a request is in flight share it;
- it carries no credentials and no query parameters, and never delays or
  fails a call;
- every switch is off until the answer arrives, so a chat's first sends can
  be v0;
- if the request fails or is blocked, every switch stays off for the chat's
  lifetime and its sends stay v0; a failed request is not repeated;
- a switch that changes reaches the chats created after it.

Allow outbound HTTPS to `api.x.com` if you want your sends to follow the
switch, or block it to keep them v0. The request runs on a daemon thread,
and one still under way at exit is cut short, so it never keeps the process
alive. There's no code to change.

## Register keys with the public key only

`generate_keypairs()` returns a payload that holds only `public_key`. Build
the request's `public_key` object from it as you do today (its
`public_key`, `signing_public_key`, `identity_public_key_signature`,
`signing_public_key_signature` and `registration_method`; `public_key` in
the snippet), and send it as the only field of the
`POST /2/users/{id}/public_keys` body. 0.6.0 doesn't pick a signing-key
version for new keys: call `set_identity` with the `public_key_version` the
request returns (see the next section). A signed call made without a version
raises `ValueError: Invalid state: signing_key_version is not set: pass it
explicitly or call set_identity() first`.

```python
# 0.5.x
registration = chat.generate_keypairs()
response = api.post(f"/2/users/{user_id}/public_keys", {
    "public_key": public_key,
    "version": registration.version,
    "generate_version": registration.generate_version,
})
chat.set_identity(user_id, response["data"]["public_key_version"])

# 0.6.0
registration = chat.generate_keypairs()
response = api.post(f"/2/users/{user_id}/public_keys", {"public_key": public_key})
chat.set_identity(SetIdentityParams(user_id, response["data"]["public_key_version"]))
```

## `set_identity` takes `SetIdentityParams`

Pass the user id and the signing-key version in a `SetIdentityParams`. It
raises `ValueError` when either value is invalid (see
[user ids](#user-ids-are-strings-of-digits) and
[key versions](#key-versions-are-integers-written-as-strings)).

```python
# 0.5.x
chat.set_identity(user_id, signing_key_version)

# 0.6.0
chat.set_identity(SetIdentityParams(user_id, signing_key_version))
```

## `import_keys` takes `ImportKeysParams`

Pass the saved key bytes, and optionally the signing-key version they were
registered under as the keyword argument `signing_key_version`. Without a
version, call `set_identity` before the first signed call.

```python
# 0.5.x
chat.import_keys(private_keys)
chat.import_keys(private_keys, signing_key_version)

# 0.6.0
chat.import_keys(ImportKeysParams(private_keys))
chat.import_keys(ImportKeysParams(private_keys, signing_key_version=signing_key_version))
```

## User ids are strings of digits

Every user id is a `str` of digits: the `SetIdentityParams` user id,
`sender_id`, `reply_to_sender_id`, the `user_id` of each public key and
signing key, and group member, admin and pending-member ids. Each must be a
positive integer written without a sign or leading zeros; anything else
raises `ValueError` naming the field, such as
`Invalid sender_id 'user-1': pass a numeric user id (digits only)`.
`reply_to_sender_id` takes a `str`:

```python
# 0.5.x
reply = chat.encrypt_reply(
    conversation_id, "pong", reply_to_sequence_id="7", reply_to_sender_id=4201, reply_to_text="ping",
)

# 0.6.0
reply = chat.encrypt_reply(EncryptReplyParams(
    conversation_id, "pong", reply_to_sequence_id="7", reply_to_sender_id="4201", reply_to_text="ping",
))
```

## Key versions are integers written as strings

Every key version is a non-negative integer written as a string of digits,
as the X API returns it: the signing-key version (in `SetIdentityParams`,
`ImportKeysParams`, a call's `signing_key_version` and each public key's
`key_version`) and `conversation_key_version`. Anything else raises
`ValueError` naming the field, such as `Invalid signing_key_version 'v1':
pass the key version as the X API returns it, an integer in digits`. There's
no code to change if you pass the versions the X API returns.

## `decrypt_events` takes `DecryptEventsParams`

Pass the events in a `DecryptEventsParams`. `signing_keys` is optional and
keyword-only; without it, the keys `set_signing_keys` stored verify the
events. The result is the same dict, and the call still never raises: errors
are collected per event.

```python
# 0.5.x
result = chat.decrypt_events(events, signing_keys)

# 0.6.0
result = chat.decrypt_events(DecryptEventsParams(events, signing_keys=signing_keys))
```

## `decrypt_event` takes `DecryptEventParams`

Pass the event in a `DecryptEventParams`, with the conversation key map
positionally and `signing_keys` by keyword. Both are optional: without them,
the conversation keys come from the key cache (`set_cache_keys(True)`) and
the signing keys from `set_signing_keys`. The call still raises on failure.

```python
# 0.5.x
event = chat.decrypt_event(event_b64, keys, signing_keys)

# 0.6.0
event = chat.decrypt_event(DecryptEventParams(event_b64, keys, signing_keys=signing_keys))
```

## Encrypt and prepare methods take params classes

Each encrypt and prepare method takes one params object. Each class takes
the arguments its method took, with the same names, order and defaults, and
exposes every field as a read/write attribute:

| Method | Params class |
|---|---|
| `encrypt_message` | `EncryptMessageParams` |
| `encrypt_reply` | `EncryptReplyParams` |
| `encrypt_add_reaction`, `encrypt_remove_reaction` | `EncryptReactionParams` |
| `encrypt_edit` | `EncryptEditParams` |
| `prepare_conversation_key_change` | `ConversationKeyChangeParams` |
| `prepare_group_create` | `GroupCreateParams` |
| `prepare_group_members_change` | `GroupMembersChangeParams` |
| `prepare_message_delete` | `MessageDeleteParams` |

```python
# 0.5.x
payload = chat.encrypt_message(conversation_id, "hello", ttl_msec=60_000)
reaction = chat.encrypt_add_reaction(event_b64, "👍")
edit = chat.encrypt_edit(event_b64, "fixed text")
prepared = chat.prepare_conversation_key_change(public_keys, conversation_id=conversation_id)

# 0.6.0
payload = chat.encrypt_message(EncryptMessageParams(conversation_id, "hello", ttl_msec=60_000))
reaction = chat.encrypt_add_reaction(EncryptReactionParams(event_b64, "👍"))
edit = chat.encrypt_edit(EncryptEditParams(event_b64, "fixed text"))
prepared = chat.prepare_conversation_key_change(
    ConversationKeyChangeParams(public_keys, conversation_id=conversation_id)
)
```

## `SendPayload` fields take the send request's names

The two encoded fields carry the names of the fields of the send request,
`POST /2/chat/conversations/{id}/messages`, so the request takes them as
they are. Read them under those names wherever your code reads a payload,
including code that stores payloads. The request also takes the payload's
`xdk_version`, the version of the SDK that built it:

```python
# 0.5.x
body = {
    "message_id": payload.message_id,
    "encoded_message_create_event": payload.encrypted_content,
    "encoded_message_event_signature": payload.encoded_event_signature,
}

# 0.6.0
body = {
    "message_id": payload.message_id,
    "encoded_message_create_event": payload.encoded_message_create_event,
    "encoded_message_event_signature": payload.encoded_message_event_signature,
    "xdk_version": payload.xdk_version,
}
```

A payload also carries `event_b64`, the message as recipients receive it.
It isn't part of the send request: keep it to encrypt the message's files
(see [Encrypt a file from its message](#encrypt-a-file-from-its-message)).

## Encrypt a file from its message

Each file is encrypted from the message that carries it, so build the
message first:

1. Start each file's upload with `POST /2/chat/media/upload/initialize`,
   declaring `encrypted_file_size` of the file's size as `total_bytes`, and
   keep the `session_id` and `media_hash_key` it returns.
2. Encrypt the message with attachments that name those media hash keys.
3. Encrypt each file with `encrypt_file`, passing the payload's `event_b64`
   and the file's media hash key.
4. Upload each encrypted file with `POST
   /2/chat/media/upload/{session_id}/append` and finish it with `POST
   /2/chat/media/upload/{session_id}/finalize`, then send the message.

```python
# 0.5.x
encrypted = chat.encrypt_stream(photo, conversation_key)
upload = api.post("/2/chat/media/upload/initialize", {
    "conversation_id": conversation_id, "total_bytes": len(encrypted),
})["data"]
media_hash_key = upload["media_hash_key"]
payload = chat.encrypt_message(conversation_id, "a photo", attachments=[photo_attachment(media_hash_key)])

# 0.6.0
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

The `append` and `finalize` requests don't change, but they come after
`encrypt_file`, which produces the bytes they upload. The upload requests
take `conversation_id` in its colon form, as the SDK does. The snippet
uploads the file in one segment; a larger file goes up in several `append`
requests, `segment_index` 0, 1 and so on (the examples send 3 MB segments),
with their count as `num_parts`.

Like `encrypt_message`, `EncryptFileParams` takes the conversation key and
its version as the keyword arguments `conversation_key` and
`conversation_key_version` (pass both, or neither to resolve them from the
key cache), and they must be the ones the message was encrypted under. The
file call needs no session identity: it reads the sender, the message id
and the key version from `event_b64`.

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

```python
# 0.5.x
plaintext = chat.decrypt_stream(downloaded, keys[conversation_key_version])

# 0.6.0
plaintext = chat.decrypt_file(DecryptFileParams(downloaded, file_event_b64, keys, file_hash_key))
```

## Encrypt and decrypt large files in chunks

`file_encryptor` and `file_decryptor` take the same values as
`encrypt_file` and `decrypt_file`, without the file bytes, and return a
`FileEncryptor` or a `FileDecryptor`; `push` and `finish` are unchanged.
Size an upload with `encrypted_file_size`.

```python
# 0.5.x
size = encrypted_stream_size(len(photo))
encryptor = chat.stream_encryptor(conversation_key)
decryptor = chat.stream_decryptor(keys[conversation_key_version])

# 0.6.0
size = encrypted_file_size(len(photo))
encryptor = chat.file_encryptor(FileEncryptorParams(payload.event_b64, media_hash_key))
decryptor = chat.file_decryptor(FileDecryptorParams(file_event_b64, keys, file_hash_key))
```

## Action signatures come nested

The prepare methods return each signed action in the shape a request's
`action_signatures` takes: `message_id`, `encoded_message_event_detail`, the
signature nested under `message_event_signature` (with `signing_public_key`,
your signing public key as `get_public_keys` returns it) and, except for
conversation-key changes, `signature_payload`. Pass them through as
returned:

```python
# 0.5.x
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

# 0.6.0
action_signatures = prepared["action_signatures"]
```

## Participant keys take the key requests' names

A prepared change's participant keys carry the names the X API gives them in
every request that takes them (`POST /2/chat/conversations/{id}/keys`,
`/group` and `/{id}/members`, and `PUT /2/chat/conversations/{id}`):
`conversation_participant_keys`, each entry with `user_id`,
`encrypted_conversation_key` and `public_key_version`, the names a received
key change uses too
(see [Received participant keys take the same names](#received-participant-keys-take-the-same-names)). Drop the renaming
and pass them through as returned:

```python
# 0.5.x
conversation_participant_keys = [
    {
        "user_id": key["user_id"],
        "encrypted_conversation_key": key["encrypted_key"],
        "public_key_version": key["public_key_version"],
    }
    for key in prepared["participant_keys"]
]

# 0.6.0
conversation_participant_keys = prepared["conversation_participant_keys"]
```

## Received participant keys take the same names

A decrypted key change carries its participant keys under the names Thrift's
`ConversationKeyChangeEvent` gives them, the same names a prepared change
uses: `conversation_participant_keys`, each entry with `user_id`,
`encrypted_conversation_key` and `public_key_version`. Read them under those
names:

```python
# 0.5.x
encrypted = key_change["participant_keys"][0]["encrypted_key"]

# 0.6.0
encrypted = key_change["conversation_participant_keys"][0]["encrypted_conversation_key"]
```

## Decrypted events name the conversation key version as the X API does

Decrypted messages and key changes carry their conversation key version as
`conversation_key_version`, the name the X API's events and the Thrift
events give it, and the name the encrypt methods take:

```python
# 0.5.x
message_version = message["key_version"]
key_change_version = key_change["key_version"]

# 0.6.0
message_version = message["conversation_key_version"]
key_change_version = key_change["conversation_key_version"]
```

## Deletes return a `PreparedAction`

`prepare_message_delete` returns a dict with `action_signatures` holding
one entry, shaped as the previous section shows. Read the action's
`message_id` from that entry, and send `action_signatures` as returned:

```python
# 0.5.x
deletion = chat.prepare_message_delete(conversation_id, sequence_ids, False)
message_id = deletion["message_id"]

# 0.6.0
deletion = chat.prepare_message_delete(MessageDeleteParams(conversation_id, sequence_ids, False))
message_id = deletion["action_signatures"][0]["message_id"]
```

## Invalid input errors

A missing or invalid argument raises `ValueError` with a message that names
the value, such as `Invalid sender_id 'user-1': pass a numeric user id
(digits only)` or `too many attachments: at most 10 per message`, without an
`Invalid state:` prefix. If your code looks for that prefix on these errors,
match the message instead. Errors about state the chat lacks, such as a
missing session identity or an empty key cache, keep their prefix.

## Group actions should be signed

Apps should sign each group update below. The sender comes from
`set_identity`. Each returns `action_signatures` shaped as
[Action signatures come nested](#action-signatures-come-nested) shows. Send
those entries on the update's request.

### Removing members

`prepare_group_members_remove` removes `user_ids` and rotates the
conversation key for the members who stay. Pass their identity keys as
`public_keys`. The result is a `PreparedConversationChange` dict: the new
conversation key, `conversation_participant_keys` for those members, and
`action_signatures` in this order — the removal, then the conversation-key
change.

POST `/2/chat/conversations/{id}/members/remove` with `user_ids`, both
signatures, and `group_key_rotation_data` holding the new
`conversation_key_version` and `conversation_participant_keys`.

```python
# 0.6.0
prepared = chat.prepare_group_members_remove(
    GroupMembersRemoveParams(conversation_id, user_ids, public_keys=remaining_public_keys)
)
api.post(f"/2/chat/conversations/{conversation_id}/members/remove", {
    "user_ids": user_ids,
    "action_signatures": prepared["action_signatures"],
    "group_key_rotation_data": {
        "conversation_key_version": prepared["conversation_key_version"],
        "conversation_participant_keys": prepared["conversation_participant_keys"],
    },
})
```

### Leaving a group

`prepare_group_leave` signs the sender's removal and does not rotate the
conversation key. `action_signatures` are the removal, then a
`GroupAdminAddChange` when `promote_admin_id` is set, then a
`ConversationDeleteEvent`. It returns a `PreparedAction` dict.

```python
# 0.6.0
left = chat.prepare_group_leave(
    GroupLeaveParams(conversation_id, promote_admin_id=promote_admin_id)
)
# left["action_signatures"]: removal, GroupAdminAddChange, ConversationDeleteEvent
```

### Changing the title

`custom_title` is the ciphertext the request sends. The result is a
`PreparedAction` dict; send its `action_signatures` on the request.

```python
# 0.6.0
title = chat.prepare_group_title_change(
    GroupTitleChangeParams(conversation_id, conversation_key_version, custom_title)
)
```

### Changing the avatar

```python
# 0.6.0
avatar = chat.prepare_group_avatar_change(
    GroupAvatarChangeParams(conversation_id, conversation_key_version, custom_avatar_url)
)
```

### Changing the description

`custom_description` is the ciphertext the request sends.

```python
# 0.6.0
description = chat.prepare_group_description_change(
    GroupDescriptionChangeParams(conversation_id, conversation_key_version, custom_description)
)
```

### Adding admins

```python
# 0.6.0
added = chat.prepare_group_admins_add(GroupAdminsAddParams(conversation_id, user_ids))
```

### Removing admins

```python
# 0.6.0
removed = chat.prepare_group_admins_remove(GroupAdminsRemoveParams(conversation_id, user_ids))
```

### Enabling an invite

An omitted `expires_at_msec` or `affiliate_id` signs `null`.

```python
# 0.6.0
invite = chat.prepare_group_invite_enable(
    GroupInviteEnableParams(conversation_id, invite_url, expires_at_msec=expires_at_msec)
)
```

### Disabling an invite

`disabled_by` defaults to the sender.

```python
# 0.6.0
disabled = chat.prepare_group_invite_disable(GroupInviteDisableParams(conversation_id))
```

### Requesting to join

`requesting_user_id` defaults to the sender. An invite token is not part of
the signature.

```python
# 0.6.0
request = chat.prepare_group_join_request(GroupJoinRequestParams(conversation_id))
```

### Rejecting join requests

```python
# 0.6.0
rejected = chat.prepare_group_join_reject(GroupJoinRejectParams(conversation_id, user_ids))
```

### Changing the message TTL

The signature covers `ttl_msec` only.

```python
# 0.6.0
ttl = chat.prepare_message_ttl_change(MessageTtlChangeParams(conversation_id, ttl_msec))
```

### Removing the message TTL

```python
# 0.6.0
cleared = chat.prepare_message_ttl_remove(MessageTtlRemoveParams(conversation_id))
```

### Changing screen capture

`change` is a `ScreenCaptureChange`: `BlockingEnabled`,
`BlockingDisabled`, `DetectionEnabled`, or `DetectionDisabled`.

```python
# 0.6.0
capture = chat.prepare_screen_capture(
    ScreenCaptureParams(conversation_id, ScreenCaptureChange.BlockingEnabled)
)
```

## Signed read receipts

`prepare_mark_conversation_read` signs a read receipt for the newest event
you read. It takes a `MarkConversationReadParams` (the conversation id, that
event's sequence id, and an optional `seen_at_msec` that defaults to now)
and returns a dict with `action_signatures`, one entry shaped as
[Action signatures come nested](#action-signatures-come-nested) shows. Send
them as the `action_signatures` of the mark-read request,
`POST /2/chat/conversations/{id}/read`, whose path takes the conversation id
in its hyphen form. A recipient's `decrypt_event` returns a signed receipt
as a verified `ReadReceipt` event.

```python
# 0.6.0
receipt = chat.prepare_mark_conversation_read(
    MarkConversationReadParams(conversation_id, seen_until_sequence_id)
)
api.post(f"/2/chat/conversations/{conversation_id.replace(':', '-')}/read", {
    "action_signatures": receipt["action_signatures"],
})
```
