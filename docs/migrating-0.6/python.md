# Migrating Python code to chat-xdk 0.6.0

This page moves Python code written for chat-xdk 0.5.x (0.5.0, 0.5.1 or
0.5.2) to 0.6.0. Work through it top to bottom: [Before you
start](#0-before-you-start) sets up the upgrade, the [symbol
index](#1-symbol-index) maps every 0.5.x name to its 0.6.0 form,
[Compile-time changes](#2-compile-time-changes) and [Runtime
changes](#3-runtime-and-behavior-changes) show each line to change, [Group
and receipt signing](#4-group-and-receipt-signing) gives every signed
request, and [Verify](#5-verify) checks the result. [Why 0.6.0
changes](why.md) explains each change, and the [index](README.md) lists the
other bindings' pages. [API.md](../API.md) documents every call.

## Checklist

Each item is tagged with what it takes: `[rollout]` is a deployment step,
`[compile]` a change a type checker (mypy, pyright) or the first call
reports, `[runtime]` a change in behavior that nothing reports, and `[new]`
a 0.6.0 call to adopt.

- [ ] `[rollout]` [Install 0.6.0](#install-060)
- [ ] `[rollout]` [Upgrade every app that reads your conversations first](#upgrade-readers-first)
- [ ] `[rollout]` [Allow or block the feature-switch request](#the-feature-switch-request)
- [ ] `[compile]` [Keep keys in Juicebox with the config the chat is created with](#keys-stored-in-juicebox)
- [ ] `[compile]` [Register keys with the public key only](#register-keys-with-the-public-key-only)
- [ ] `[compile]` [Pass a `SetIdentityParams` to `set_identity`](#set_identity-takes-setidentityparams)
- [ ] `[compile]` [Pass an `ImportKeysParams` to `import_keys`](#import_keys-takes-importkeysparams)
- [ ] `[compile]` [Pass a `DecryptEventsParams` to `decrypt_events` and read its `events`](#decrypt_events-takes-decrypteventsparams)
- [ ] `[compile]` [Pass a `DecryptEventParams` to `decrypt_event`](#decrypt_event-takes-decrypteventparams)
- [ ] `[compile]` [Pass a params class to every encrypt and prepare method](#encrypt-and-prepare-methods-take-params-classes)
- [ ] `[compile]` [Annotate key lists and results with the types the package exports](#key-entries-and-results-have-named-types)
- [ ] `[compile]` [Read `SendPayload` under the send request's field names and send `xdk_version`](#sendpayload-fields-take-the-send-requests-names)
- [ ] `[compile]` [Build a message before you encrypt its files](#encrypt-a-file-from-its-message)
- [ ] `[compile]` [Decrypt a file with the event of its message](#decrypt-a-file-with-its-messages-event)
- [ ] `[compile]` [Use `file_encryptor` and `file_decryptor` for large files](#encrypt-and-decrypt-large-files-in-chunks)
- [ ] `[compile]` [Pass action signatures through as returned](#action-signatures-come-nested)
- [ ] `[compile]` [Name a public key input's fields `identity_public_key` and `public_key_version`](#public-key-inputs-name-the-identity-key-and-its-version)
- [ ] `[compile]` [Pass participant keys through as returned](#participant-keys-take-the-key-requests-names)
- [ ] `[compile]` [Read received participant keys under the same names](#received-participant-keys-take-the-same-names)
- [ ] `[compile]` [Read a delete's signature from its `PreparedAction`](#deletes-return-a-preparedaction)
- [ ] `[compile]` [Read decrypted events under the names the calls take](#decrypted-events-use-the-names-the-calls-take)
- [ ] `[compile]` [Catch errors by class, and read a wrong PIN's attempts from `guesses_remaining`](#errors-carry-their-kind)
- [ ] `[runtime]` [Pass user ids as strings of digits](#user-ids-are-strings-of-digits)
- [ ] `[runtime]` [Pass key versions as the X API returns them](#key-versions-are-integers-written-as-strings)
- [ ] `[runtime]` [Pass entities, files, URL cards and posts the SDK accepts](#entities-files-url-cards-and-posts-are-checked)
- [ ] `[runtime]` [Store every participant's signing keys, and handle a `latest_version` of `None`](#latest_version-comes-from-a-verified-key-change)
- [ ] `[runtime]` [Rename every read of `target_message_id` to `target_message_sequence_id`](#target_message_id-holds-a-different-value)
- [ ] `[runtime]` [Keep a prepared change's key from the dict](#a-prepared-changes-json-leaves-out-its-key)
- [ ] `[runtime]` [Sign only your own data with `sign`](#sign-refuses-data-only-the-sdk-signs)
- [ ] `[runtime]` [Skip the events `decrypt_event` drops](#decrypt-drops-a-removals-title-and-description-re-encryptions)
- [ ] `[runtime]` [Check for keys before `export_keys`](#export_keys-raises-without-keys)
- [ ] `[runtime]` [Sign every group change and read receipt](#4-group-and-receipt-signing)
- [ ] `[runtime]` [Send each delete's `action_signatures` as returned](#deleting-messages)
- [ ] `[runtime]` [Sign read receipts](#read-receipts-are-signed)
- [ ] `[runtime]` [Sign group creates, member adds, title, description and avatar changes](#group-changes-are-signed)
- [ ] `[runtime]` [Remove members with a key rotation, and encrypt under the new key](#removing-members)
- [ ] `[new]` [Sign leaves, admin, invite, join, message-TTL and screen-capture changes](#leaving-a-group)
- [ ] `[rollout]` [Verify the migration](#5-verify)

## About the snippets

Each snippet shows the lines that change, first as 0.5.x code writes them,
under `# 0.5.x`, and then as 0.6.0 code writes them, under `# 0.6.0`. A
snippet with only a `# 0.6.0` half shows code 0.6.0 adds. CI runs the
0.6.0 half of every snippet on this page against 0.6.0
([`scripts/check_doc_snippets.py`](../../scripts/check_doc_snippets.py)),
so each one runs as written.

`chat` is a `Chat` with your keys loaded. The other names stand for your own
values: ids, versions, keys and events as the X API returns them, `keys`
for the conversation key map `decrypt_events` returns, `payload` for a
`SendPayload`, `prepared` for the dict a prepare method returns, and
`key_change`, `message`, `deleted`, `receipt` and `group_change` for a
decrypted key change, message, deletion, read receipt and group change.
`page` is a page of `GET /2/chat/conversations/{id}/events`.
`api.post(path, body)`, `api.put(path, body)` and `api.delete(path, body)`
stand for your HTTP client: each sends `body` as JSON to
`https://api.x.com` + `path` with your user access token and returns the
parsed JSON response. `path_id` is the conversation id as a request path
takes it: a group's `g…` id as is, and a one-to-one's in its hyphen form,
`conversation_id.replace(":", "-")`. `photo_attachment(media_hash_key)`
stands for your code that builds a photo's attachment descriptor;
`show_edit`, `show_title`, `show_description` and `show_avatar` for your code
that displays an edit, or a group's title, description or avatar;
`handle(event)` for your code that handles a decrypted event;
`log_skipped(event_b64, err)` for your code that logs an event it skips; and
`store_conversation_key(conversation_id, version, key)` for your code that
stores a conversation key. Every class and function the snippets use
imports from `chat_xdk`.

## 0. Before you start

### Install 0.6.0

Pin the package at 0.6.0 in your requirements file, then install it:

```sh
pip install chatxdk==0.6.0
```

The package imports as `chat_xdk`, as 0.5.x does, and needs Python 3.10 or
newer. Every app that shares conversations with yours reads the formats
0.6.0 sends only once it runs 0.6.0 too, so plan the rollout below before
you deploy.

### Upgrade readers first

0.6.0 sends each message, reply, reaction and edit in one of two formats.
v0 is the format 0.5.x sends. v1 encrypts each message under its own key,
derived from the conversation key, the sender and the message id, and signs
it at signature version 10. A chat sends v1 while the X API's `v1_send`
feature switch is on for it, and v0 otherwise (see [The feature-switch
request](#the-feature-switch-request)). Two group changes also sign at
versions 0.5.x can't verify: a member removal signs at version 11, and a
member add that carries a description at version 8.

0.5.x rejects each of these as a signature verification failure, so upgrade
every app that reads your conversations to 0.6.0 before:

- any of your senders can send v1, that is, before the X API turns
  `v1_send` on for them;
- you remove a member from a group with
  [`prepare_group_members_remove`](#removing-members);
- you pass a description to [`prepare_group_members_change`](#adding-members).

0.6.0 reads both formats, including v1 reply previews, edits and files.
There's no code to change: to see which format a send used, read
`payload.signature_info.signature_version`, `"7"` for v0 and `"10"` for v1.

### The feature-switch request

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

## 1. Symbol index

Every 0.5.x name that changes, with its 0.6.0 form and the section that
shows the change. A name not listed here keeps its 0.5.x form. Search your
code for each name in the first column; [Verify](#5-verify) gives the
search as one command.

| 0.5.x | 0.6.0 | Section |
|---|---|---|
| `chat.set_identity(user_id, signing_key_version)` | `chat.set_identity(SetIdentityParams(user_id, signing_key_version))` | [set_identity](#set_identity-takes-setidentityparams) |
| `chat.import_keys(keys, version=...)` | `chat.import_keys(ImportKeysParams(keys, signing_key_version=...))` | [import_keys](#import_keys-takes-importkeysparams) |
| `registration.version`, `registration.generate_version` | Removed: the registration request returns the version (`public_key_version`) | [Registration](#register-keys-with-the-public-key-only) |
| `PublicKeys.version` | Removed: the `public_key_version` the registration request returns | [Registration](#register-keys-with-the-public-key-only) |
| `guesses_remaining(err)` | `err.guesses_remaining` on an `InvalidPinError` | [Juicebox](#keys-stored-in-juicebox) |
| `chat.decrypt_events(events, signing_keys)` | `chat.decrypt_events(DecryptEventsParams(events, signing_keys=...))` | [decrypt_events](#decrypt_events-takes-decrypteventsparams) |
| `result["messages"]` | `result["events"]` | [decrypt_events](#decrypt_events-takes-decrypteventsparams) |
| `chat.decrypt_event(event_b64, keys, signing_keys)` | `chat.decrypt_event(DecryptEventParams(event_b64, keys, signing_keys=...))` | [decrypt_event](#decrypt_event-takes-decrypteventparams) |
| `chat.encrypt_message(conversation_id, text, ...)` | `chat.encrypt_message(EncryptMessageParams(conversation_id, text, ...))` | [Params classes](#encrypt-and-prepare-methods-take-params-classes) |
| `chat.encrypt_reply(...)` | `chat.encrypt_reply(EncryptReplyParams(...))` | [Params classes](#encrypt-and-prepare-methods-take-params-classes) |
| `chat.encrypt_add_reaction(...)`, `chat.encrypt_remove_reaction(...)` | `...(EncryptReactionParams(...))` | [Params classes](#encrypt-and-prepare-methods-take-params-classes) |
| `chat.encrypt_edit(...)` | `chat.encrypt_edit(EncryptEditParams(...))` | [Params classes](#encrypt-and-prepare-methods-take-params-classes) |
| `chat.prepare_conversation_key_change(public_keys, ...)` | `...(ConversationKeyChangeParams(public_keys, ...))` | [Params classes](#encrypt-and-prepare-methods-take-params-classes) |
| `chat.prepare_group_create(public_keys, ...)` | `...(GroupCreateParams(public_keys, ...))` | [Creating a group](#creating-a-group) |
| `prepare_group_create(..., avatar_url=...)` | Removed: set the avatar with `prepare_group_avatar_change` | [Creating a group](#creating-a-group) |
| `chat.prepare_group_members_change(public_keys, ...)` | `...(GroupMembersChangeParams(public_keys, ...))` | [Adding members](#adding-members) |
| `chat.prepare_message_delete(conversation_id, sequence_ids, delete_for_all)` | `...(MessageDeleteParams(conversation_id, sequence_ids, delete_for_all))` | [Deletes](#deletes-return-a-preparedaction) |
| `deletion["message_id"]` and the flat signature fields | `deletion["action_signatures"][0]` | [Deletes](#deletes-return-a-preparedaction) |
| `payload.encrypted_content` | `payload.encoded_message_create_event` | [SendPayload](#sendpayload-fields-take-the-send-requests-names) |
| `payload.encoded_event_signature` | `payload.encoded_message_event_signature` | [SendPayload](#sendpayload-fields-take-the-send-requests-names) |
| `chat.encrypt_stream(plaintext, key)` | `chat.encrypt_file(EncryptFileParams(file, event_b64, media_hash_key))` | [Files](#encrypt-a-file-from-its-message) |
| `chat.decrypt_stream(encrypted, key)` | `chat.decrypt_file(DecryptFileParams(encrypted, event_b64, keys, media_hash_key))` | [Files](#decrypt-a-file-with-its-messages-event) |
| `chat.stream_encryptor(key)`, `chat.stream_decryptor(key)` | `chat.file_encryptor(FileEncryptorParams(...))`, `chat.file_decryptor(FileDecryptorParams(...))` | [Large files](#encrypt-and-decrypt-large-files-in-chunks) |
| `StreamEncryptor`, `StreamDecryptor` | `FileEncryptor`, `FileDecryptor` | [Large files](#encrypt-and-decrypt-large-files-in-chunks) |
| `encrypted_stream_size(n)` | `encrypted_file_size(n)` | [Files](#encrypt-a-file-from-its-message) |
| `chat.encrypt(plaintext, key)` | Removed: titles and descriptions go through `prepare_group_title_change`, `prepare_group_description_change` and the group creates and member adds; avatar URLs aren't encrypted; files go through `encrypt_file` | [Changing the title](#changing-the-title) |
| Action signature `signature`, `signature_version`, `public_key_version` | Nested under `message_event_signature`; pass `action_signatures` as returned | [Action signatures](#action-signatures-come-nested) |
| Public key input `public_key`, `key_version` | `identity_public_key`, `public_key_version` | [Public key inputs](#public-key-inputs-name-the-identity-key-and-its-version) |
| `prepared["participant_keys"]`, `encrypted_key` | `prepared["conversation_participant_keys"]`, `encrypted_conversation_key` | [Participant keys](#participant-keys-take-the-key-requests-names) |
| `key_change["participant_keys"]`, `encrypted_key` | `key_change["conversation_participant_keys"]`, `encrypted_conversation_key` | [Received keys](#received-participant-keys-take-the-same-names) |
| `message["key_version"]`, `key_change["key_version"]` | `conversation_key_version` | [Event names](#decrypted-events-use-the-names-the-calls-take) |
| Reaction and edit `target_message_id` | `target_message_sequence_id` | [Event names](#decrypted-events-use-the-names-the-calls-take) |
| Edit `new_text` | `updated_text` | [Event names](#decrypted-events-use-the-names-the-calls-take) |
| Deletion `message_ids` | `sequence_ids` | [Event names](#decrypted-events-use-the-names-the-calls-take) |
| Read receipt and unread marker `seen_until_id` | `seen_until_sequence_id` | [Event names](#decrypted-events-use-the-names-the-calls-take) |
| Group title and description strings (`title`, `new_title`) | `GroupText` dicts | [Creating a group](#creating-a-group) |
| `reply_to_sender_id=4201` (an `int`) | `reply_to_sender_id="4201"` | [User ids](#user-ids-are-strings-of-digits) |
| `except ValueError` and reading the message | `except InvalidInputError`, `InvalidStateError`, ... | [Errors](#errors-carry-their-kind) |

## 2. Compile-time changes

These changes are in the order an app meets them: creating the chat,
registering, loading keys, decrypting, encrypting and sending, files,
prepared changes, decrypted events and errors.

### Keys stored in Juicebox

`Chat(config_json)` keeps your keys in Juicebox under the Juicebox config
the X API returns, as in 0.5.x, and `Chat()` manages them with
`import_keys` and `export_keys` alone, or takes the config later from
`update_config`, on first boot. `setup`, `unlock`, `change_pin` and
`delete` block on their Juicebox round trips; `setup_async`,
`unlock_async`, `change_pin_async` and `delete_async` run the same calls on
a worker thread, for an `asyncio` event loop. A wrong PIN raises
`InvalidPinError`, whose `guesses_remaining` holds the attempts Juicebox
reports left, `0` once the stored keys are locked and `None` when Juicebox
reports no count:

```python
# 0.5.x
try:
    chat.unlock(pin)
except ValueError as err:
    guesses_left = guesses_remaining(err)

# 0.6.0
try:
    chat.unlock(pin)
except InvalidPinError as err:
    guesses_left = err.guesses_remaining
```

Until a chat has a config, the Juicebox calls raise `InvalidStateError` (see
[An empty Juicebox config fails](#an-empty-juicebox-config-fails)).

### Register keys with the public key only

`generate_keypairs()` returns a payload that holds only `public_key`. Build
the request's `public_key` object from it as you do today (its
`public_key`, `signing_public_key`, `identity_public_key_signature`,
`signing_public_key_signature` and `registration_method`; `public_key` in
the snippet), and send it as the only field of the
`POST /2/users/{id}/public_keys` body. 0.6.0 doesn't pick a signing-key
version for new keys: call `set_identity` with the `public_key_version` the
request returns (see the next section). A signed call made without a version
raises `InvalidStateError: Invalid state: signing_key_version is not set:
pass it explicitly or call set_identity() first`.

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

`PublicKeys`, which `get_public_keys()` and `setup()` return, holds the two
public keys, `identity` and `signing`, and no `version`: their version is
the `public_key_version` the registration request returns.

### `set_identity` takes `SetIdentityParams`

Pass the user id and the signing-key version in a `SetIdentityParams`. It
raises `InvalidInputError` when either value is invalid (see
[user ids](#user-ids-are-strings-of-digits) and
[key versions](#key-versions-are-integers-written-as-strings)).

```python
# 0.5.x
chat.set_identity(user_id, signing_key_version)

# 0.6.0
chat.set_identity(SetIdentityParams(user_id, signing_key_version))
```

### `import_keys` takes `ImportKeysParams`

Pass the saved key bytes, and optionally the signing-key version they were
registered under as the keyword argument `signing_key_version`. Without a
version, call `set_identity` before the first signed call. `export_keys`
returns the key bytes as in 0.5.x (see [`export_keys` raises without
keys](#export_keys-raises-without-keys) for a chat without keys).

```python
# 0.5.x
chat.import_keys(private_keys)
chat.import_keys(private_keys, version=signing_key_version)

# 0.6.0
chat.import_keys(ImportKeysParams(private_keys))
chat.import_keys(ImportKeysParams(private_keys, signing_key_version=signing_key_version))
```

### `decrypt_events` takes `DecryptEventsParams`

Pass the events in a `DecryptEventsParams`. `signing_keys` is optional and
keyword-only; without it, the keys `set_signing_keys` stored verify the
events. An event that fails, or one decrypt drops, is collected in the
result's `errors` rather than raised; the call raises only for invalid
params, such as a signing key entry without `public_key_version`
(`InvalidInputError`) or `events` that is not a list (`TypeError`). The
result holds the decrypted events, of every event type, under `events`:

```python
# 0.5.x
result = chat.decrypt_events(events, signing_keys)
decrypted = result["messages"]

# 0.6.0
result = chat.decrypt_events(DecryptEventsParams(events, signing_keys=signing_keys))
decrypted = result["events"]
```

The version to encrypt with, `result["conversation_keys"]["latest_version"]`,
comes only from a key change that verified (see [`latest_version` comes from
a verified key change](#latest_version-comes-from-a-verified-key-change)).

### `decrypt_event` takes `DecryptEventParams`

Pass the event in a `DecryptEventParams`, with the conversation key map
positionally and `signing_keys` by keyword. Both are optional: without them,
the conversation keys come from the key cache (`set_cache_keys(True)`) and
the signing keys from `set_signing_keys`. The call still raises on failure,
and for an event decrypt drops (see [Decrypt drops a removal's title and
description re-encryptions](#decrypt-drops-a-removals-title-and-description-re-encryptions)).

```python
# 0.5.x
event = chat.decrypt_event(event_b64, keys, signing_keys)

# 0.6.0
event = chat.decrypt_event(DecryptEventParams(event_b64, keys, signing_keys=signing_keys))
```

### Encrypt and prepare methods take params classes

Each encrypt and prepare method takes one params object. Each class takes
the arguments its method took, with the same names, order and defaults,
except where [Creating a group](#creating-a-group) says otherwise, and
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

### Key entries and results have named types

The package exports a `TypedDict` for each dict the calls take or return, so
a type checker reads them: `SigningKeyEntry` for each signing key that
`set_signing_keys` and the decrypt params take, `PublicKeyInput` for each
public key the prepare params take, and `ConversationKeyResult`,
`DecryptEventsResult` and `DecryptedEvent`, `PreparedAction`,
`PreparedGroupMetadataChange` and `PreparedConversationChange`, with
`ActionSignature`, `MessageEventSignature` and `ConversationParticipantKey`,
for the results. They're plain dicts at runtime, so there's no code to
change; annotate with them where you held `dict`. The stubs also name the
argument of `bytes_to_base64`, `bytes_to_hex`, `detect_mime_type` and
`detect_image_dimensions` `bytes`, the keyword the functions take:

```python
# 0.5.x
result: dict = chat.decrypt_events(events, signing_keys)
prepared: dict = chat.prepare_conversation_key_change(public_keys, conversation_id=conversation_id)

# 0.6.0
result: DecryptEventsResult = chat.decrypt_events(DecryptEventsParams(events, signing_keys=signing_keys))
prepared: PreparedConversationChange = chat.prepare_conversation_key_change(
    ConversationKeyChangeParams(public_keys, conversation_id=conversation_id)
)
```

### `SendPayload` fields take the send request's names

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

### Encrypt a file from its message

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
the same message again gives the same id, so files you already encrypted for
it stay valid, and a second message that reuses the first one's uploads gets
the same id, so recipients drop it as a repeat. The file fields the SDK
checks are listed under [Entities, files, URL cards and posts are
checked](#entities-files-url-cards-and-posts-are-checked).

### Decrypt a file with its message's event

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

### Encrypt and decrypt large files in chunks

`file_encryptor` and `file_decryptor` take the same values as
`encrypt_file` and `decrypt_file`, without the file bytes, and return a
`FileEncryptor` or a `FileDecryptor`; `push` and `finish` keep their 0.5.x
form. Name the classes `FileEncryptor` and `FileDecryptor` in imports and
type hints too. Size an upload with `encrypted_file_size`.

```python
# 0.5.x
from chat_xdk import StreamDecryptor, StreamEncryptor

size = encrypted_stream_size(len(photo))
encryptor: StreamEncryptor = chat.stream_encryptor(conversation_key)
decryptor: StreamDecryptor = chat.stream_decryptor(keys[conversation_key_version])

# 0.6.0
from chat_xdk import FileDecryptor, FileEncryptor

size = encrypted_file_size(len(photo))
encryptor: FileEncryptor = chat.file_encryptor(FileEncryptorParams(payload.event_b64, media_hash_key))
decryptor: FileDecryptor = chat.file_decryptor(FileDecryptorParams(file_event_b64, keys, file_hash_key))
```

### Action signatures come nested

The prepare methods return each signed action in the shape a request's
`action_signatures` takes: `message_id`, `encoded_message_event_detail`, the
signature nested under `message_event_signature` (with `signing_public_key`,
your signing public key as `get_public_keys` returns it), and nothing else:
the signed payload stays inside the SDK. Pass them through as returned:

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

### Public key inputs name the identity key and its version

Each public key the prepare params take, one participant a conversation key
is encrypted to, names its key `identity_public_key` and the key's version
`public_key_version`, as a signing key entry does: the `public_key` the X
API returns for a user is their identity key:

```python
# 0.5.x
public_keys = [{"user_id": user_id, "public_key": identity_public_key, "key_version": public_key_version}]

# 0.6.0
public_keys: list[PublicKeyInput] = [
    {"user_id": user_id, "identity_public_key": identity_public_key, "public_key_version": public_key_version}
]
```

### Participant keys take the key requests' names

A prepared change's participant keys carry the names the X API gives them in
every request that takes them (`POST /2/chat/conversations/{id}/keys`,
`/group` and `/{id}/members`, and `PUT /2/chat/conversations/{id}`):
`conversation_participant_keys`, each entry with `user_id`,
`encrypted_conversation_key` and `public_key_version`, the names a received
key change uses too (see [Received participant keys take the same
names](#received-participant-keys-take-the-same-names)). Drop the renaming
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

### Received participant keys take the same names

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

### Deletes return a `PreparedAction`

`prepare_message_delete` returns a dict with `action_signatures` holding one
entry, shaped as [Action signatures come
nested](#action-signatures-come-nested) shows. Read the action's
`message_id` from that entry, and send `action_signatures` as returned (see
[Deleting messages](#deleting-messages) for the request):

```python
# 0.5.x
deletion = chat.prepare_message_delete(conversation_id, sequence_ids, False)
message_id = deletion["message_id"]

# 0.6.0
deletion = chat.prepare_message_delete(MessageDeleteParams(conversation_id, sequence_ids, False))
message_id = deletion["action_signatures"][0]["message_id"]
```

### Decrypted events use the names the calls take

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

Keys that hold sequence ids take the names of the params that send them. A
`Reaction`, `ReactionRemoved` or `Edit` content names its target
`target_message_sequence_id`, as `EncryptReactionParams` and
`EncryptEditParams` do. A `MessageDeleted` event names its messages
`sequence_ids`, as `MessageDeleteParams` does, and a `ReadReceipt` or
`MarkedUnread` event names its position `seen_until_sequence_id`, as
`MarkConversationReadParams` does. An edit's text is `updated_text`, as
`EncryptEditParams` names it, and a v1 edit carries the signed `message_id`
of the message it edits as `target_message_id`, absent for a v0 edit.

**Rename every read of `target_message_id` to `target_message_sequence_id`.
Don't keep `target_message_id`: in 0.6.0 it names a different value, and
reading it raises no error** (see [`target_message_id` holds a different
value](#target_message_id-holds-a-different-value)).

```python
# 0.5.x
content = message["content"]
if content["content_type"] == "Edit":
    show_edit(content["target_message_id"], content["new_text"])
deleted_sequence_ids = deleted["message_ids"]
seen_until = receipt["seen_until_id"]

# 0.6.0
content = message["content"]
if content["content_type"] == "Edit":
    show_edit(content["target_message_sequence_id"], content["updated_text"])
deleted_sequence_ids = deleted["sequence_ids"]
seen_until = receipt["seen_until_sequence_id"]
```

A group create's `title`, and a title or description change's `new_title`
or `new_description`, is a `GroupText` dict rather than a string (see
[Creating a group](#creating-a-group)).

### Errors carry their kind

Every SDK failure raises a `ChatXdkError`, a `ValueError`, of the subclass
that names its kind the same way in every binding: `InvalidInputError`,
`InvalidStateError`, `ParseError`, `DecryptionError`, `VerificationError`,
`InvalidPinError` or `JuiceboxError`, and `ChatXdkError` itself for a
failure inside the SDK. Each carries the kind as `kind`
(`"invalid_input"`, `"invalid_state"`, ...) and `guesses_remaining`, set
on an `InvalidPinError` (see [Keys stored in Juicebox](#keys-stored-in-juicebox)).

A missing or invalid argument raises `InvalidInputError` with a message that
names the value, such as `Invalid sender_id 'user-1': pass a numeric user id
(digits only)` or `too many attachments: at most 10 per message`, without an
`Invalid state:` prefix. That covers a key or signature that `verify`,
`verify_key_binding` or `matches_registered_key` can't decode. A call
missing a required argument, or given one of the wrong type, still raises
`TypeError`. Errors about state the chat lacks, such as a missing session
identity or an empty key cache, raise `InvalidStateError` and keep their
prefix. Catch the class rather than reading the message:

```python
# 0.5.x
try:
    chat.set_identity(user_id, signing_key_version)
except ValueError as err:
    if str(err).startswith("Invalid state:"):
        raise

# 0.6.0
try:
    chat.set_identity(SetIdentityParams(user_id, signing_key_version))
except InvalidInputError:
    pass
```

## 3. Runtime and behavior changes

Nothing reports these changes before the code runs: each one is a value the
SDK checks, a value with a new meaning, or an event handled differently.

### User ids are strings of digits

Every user id is a `str` of digits: the `SetIdentityParams` user id,
`sender_id`, `reply_to_sender_id`, the `user_id` of each public key and
signing key, and the ids of a group's members and admins
(`member_ids`, `admin_ids`, `new_member_ids`, `current_member_ids`,
`current_admin_ids`, `current_pending_member_ids` and `user_ids`). Each must be a
positive integer written without a sign or leading zeros; anything else
raises `InvalidInputError` naming the field, such as
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

### Key versions are integers written as strings

Every key version is a non-negative integer written as a string of digits,
as the X API returns it: the signing-key version (in `SetIdentityParams`,
`ImportKeysParams`, a call's `signing_key_version` and each public key's
`public_key_version`) and `conversation_key_version`. Anything else raises
`InvalidInputError` naming the field, such as `Invalid signing_key_version 'v1':
pass the key version as the X API returns it, an integer in digits`. There's
no code to change if you pass the versions the X API returns.

### Entities, files, URL cards and posts are checked

The encrypt calls check what a message carries before they encrypt it, and
raise `InvalidInputError` naming the value, where 0.5.x sent it:

- An entity of a type the SDK doesn't know, an empty one included, fails
  with `Invalid entity_type 'user_mention': pass url, mention, hashtag,
  cashtag, email, address or phone_number`, for a message's, a reply's, a
  reply preview's and an edit's entities.
- Entity offsets count bytes of the text's UTF-8 encoding, the start
  inclusive and the end exclusive. An entity whose offsets are negative,
  end before they start or run past the end of the text fails, such as
  `Invalid entity offsets 3..8: end is past the end of the text, which is
  7 bytes of UTF-8`. A reply preview's entities, which index the quoted
  message's text, are checked for all but the end.
- A file a message carries, a media attachment or a URL card's banner or
  favicon, fails with an empty `filename`, a `filesize_bytes` of 0 or less,
  or a negative `width` or `height`, since receiving clients discard such a
  file. Give each file its name and the encrypted size `encrypted_file_size`
  gives.
- A message that lists an empty media hash key, or one media hash key in
  two attachments, fails.
- A URL card with an empty `url`, and a post attachment with neither
  `rest_id` nor `post_url`, fail.

Count an entity's offsets in bytes of UTF-8 when the text holds characters
outside ASCII:

```python
# 0.6.0
text = "café @bob"
start = len(text[: text.index("@bob")].encode("utf-8"))
payload = chat.encrypt_message(
    EncryptMessageParams(conversation_id, text, entities=[(start, start + len("@bob".encode("utf-8")), "mention")])
)
```

### `latest_version` comes from a verified key change

`result["conversation_keys"]["latest_version"]`, the version to encrypt
with, is the newest version whose key change verified, and it never moves
back for the chat's lifetime. A key change verifies only against its
sender's signing key, so give the chat every participant's signing keys,
your own included, before you decrypt. It's `None` until a key change
verifies: a key change the SDK can't verify still adds its key to
`result["conversation_keys"]["keys"]`, for decrypting, but never becomes the
version you encrypt with. Where 0.5.x returned the batch's highest version,
0.6.0 can return `None`: fetch the missing signing keys or the
conversation's key-change events and decrypt again, rather than encrypting
under the highest key in `keys`:

```python
# 0.5.x
result = chat.decrypt_events(events, signing_keys)
version = result["conversation_keys"]["latest_version"]

# 0.6.0
chat.set_signing_keys(signing_keys)
result = chat.decrypt_events(DecryptEventsParams(events))
version = result["conversation_keys"]["latest_version"]
if version is None:
    # No key change verified: fetch every participant's signing keys
    # (GET /2/users/{id}/public_keys) and the conversation's key changes
    # (meta.conversation_key_events of GET /2/chat/conversations/{id}/events),
    # then decrypt again.
    pass
```

### `target_message_id` holds a different value

**In 0.5.x a reaction's or edit's `target_message_id` held the target's
sequence id. In 0.6.0 that value is `target_message_sequence_id`, and
`target_message_id` holds the edited message's signed message id, present
only on a v1 edit.** Code that keeps reading `target_message_id` raises no
error: it gets the wrong id, or none. Rename every read, as [Decrypted
events use the names the calls
take](#decrypted-events-use-the-names-the-calls-take) shows, and use
`target_message_id` only to match a v1 edit to the `message_id` you
deduplicate on.

### A prepared change's JSON leaves out its key

Nothing changes in Python. A prepared change is a dict whose
`conversation_key` holds the raw key as bytes; keep it from the dict, as in
0.5.x. The request bodies take only its participant keys, key version and
action signatures.

### `sign` refuses data only the SDK signs

`sign` raises `InvalidInputError` for a payload recipients would verify as
a signed event (a message, conversation-key change, group or
conversation-metadata change, delete or read receipt) and for a P-256
public key, whose signature by the signing key binds it as an identity key.
Sign only your own application data with `sign`; the SDK signs events
itself. Any other data signs as in 0.5.x:

```python
# 0.6.0
try:
    signature = chat.sign(data)
except InvalidInputError:
    signature = None   # the data reads as an event or a public key, which only the SDK signs
```

### Decrypt drops a removal's title and description re-encryptions

A member removal rotates the conversation key and re-encrypts the group's
title and description under the new key, marked as key-rotation
re-encryptions. They are the same text, not changes, so `decrypt_events`
and `decrypt_event` drop them under either `reject_unverified` setting, the
way they drop an unverified event: `decrypt_events` leaves each one out of
`events` and records it in `errors`, and `decrypt_event` raises
`InvalidInputError`: `GroupChange re-encrypts the group's title for a key
rotation (for_key_rotation), not a title change: decrypt does not return
it`. The removal itself (`MembersRemoved`), its key change, avatar changes
and every title or description change without the mark decrypt as before.
In 0.5.x, a removal by an X client arrived as a `TitleChanged` carrying
the group's unchanged title:

```python
# 0.5.x
for item in result["messages"]:
    change = item["event"].get("change", {})
    if change.get("change_type") == "TitleChanged":
        show_title(chat.decrypt(change["new_title"], keys[conversation_key_version]))

# 0.6.0
result = chat.decrypt_events(DecryptEventsParams(events))
for item in result["events"]:
    change = item["event"].get("change", {})
    if change.get("change_type") == "TitleChanged":
        new_title = change["new_title"]
        show_title(new_title["text"] if new_title["kind"] == "Text" else new_title["raw"])
```

A loop over single events catches the error, as it catches an unverified
event's, and moves on to the next event:

```python
# 0.6.0
for item in page["data"]:
    try:
        event = chat.decrypt_event(DecryptEventParams(item["encoded_event"], keys))
    except ChatXdkError as err:
        log_skipped(item["encoded_event"], err)
        continue
    handle(event)
```

### `export_keys` raises without keys

`export_keys` raises `InvalidStateError` when no identity key is loaded:

```python
# 0.5.x
private_keys = chat.export_keys()

# 0.6.0
private_keys = chat.export_keys() if chat.has_identity_key() else None
```

### An empty Juicebox config fails

Until a chat has a Juicebox config, `setup`, `unlock`, `change_pin` and
`delete` (and their `_async` forms) raise `InvalidStateError`: `Invalid
state: no Juicebox config: pass the juicebox_config the X API returns when
you create the chat, or call update_config() first`, the error every
binding gives. `Chat` and `update_config` raise it for an empty or blank
config string, at once, rather than at the first Juicebox call.

## 4. Group and receipt signing

Recipients on the default `reject_unverified` policy drop a read receipt or
group change that isn't signed, as 0.5.x recipients did: sign each one, or
recipients never see it. The sender comes from `set_identity`. Each prepare
call returns `action_signatures` shaped as [Action signatures come
nested](#action-signatures-come-nested) shows; send them in the request as
returned.

### The requests

Each request below takes the conversation id in its path as `path_id`, and
the prepare call's `action_signatures` as returned. The paths and body
fields are the X API's, as its OpenAPI description
(`https://api.x.com/2/openapi.json`) gives them.

| Action | Call | Request | Body |
|---|---|---|---|
| Send a message, reply, reaction or edit | `encrypt_message`, `encrypt_reply`, `encrypt_add_reaction`, `encrypt_remove_reaction`, `encrypt_edit` | `POST /2/chat/conversations/{id}/messages` | `message_id`, `encoded_message_create_event`, `encoded_message_event_signature`, `xdk_version`: the payload's fields of those names |
| Delete messages | `prepare_message_delete` | `POST /2/chat/conversations/{id}/messages/delete` | `sequence_ids`; `delete_message_action`, `"delete_for_all"` or `"delete_for_self"` as the params' `delete_for_all` says; `action_signatures` |
| Mark read | `prepare_mark_conversation_read` | `POST /2/chat/conversations/{id}/read` | `action_signatures` |
| Start a one-to-one or rotate its key | `prepare_conversation_key_change` | `POST /2/chat/conversations/{id}/keys` | `conversation_key_version`, `conversation_participant_keys`, `action_signatures` |
| Create a group | `prepare_group_create` | `POST /2/chat/conversations/group` | `conversation_id`, `group_members`, `group_admins`, `group_name` (the result's `encrypted_title`), `conversation_key_version`, `conversation_participant_keys`, `action_signatures` |
| Add members | `prepare_group_members_change` | `POST /2/chat/conversations/{id}/members` | `user_ids`, `encrypted_title`, `conversation_key_version`, `conversation_participant_keys`, `action_signatures` |
| Remove members | `prepare_group_members_remove` | `POST /2/chat/conversations/{id}/members/remove` | `user_ids`, `action_signatures`, `group_key_rotation_data` with `conversation_key_version` and `conversation_participant_keys` |
| Leave | `prepare_group_leave` | `POST /2/chat/conversations/{id}/members/remove` | `user_ids` (your own id), `action_signatures` |
| Change the title | `prepare_group_title_change` | `PUT /2/chat/conversations/{id}` | `group_name` (the result's `encrypted_value`), `conversation_key_version`, `modified_fields: ["group_name"]`, `action_signatures` |
| Change the description | `prepare_group_description_change` | `PUT /2/chat/conversations/{id}` | `group_description` (the result's `encrypted_value`), `conversation_key_version`, `modified_fields: ["group_description"]`, `action_signatures` |
| Change the avatar | `prepare_group_avatar_change` | `PUT /2/chat/conversations/{id}` | `group_avatar_url` (the media URL), `conversation_key_version`, `modified_fields: ["group_avatar_url"]`, `action_signatures` |
| Add admins | `prepare_group_admins_add` | `POST /2/chat/conversations/{id}/admins` | `user_ids`, `action_signatures` |
| Remove admins | `prepare_group_admins_remove` | `POST /2/chat/conversations/{id}/admins/remove` | `user_ids`, `action_signatures` |
| Turn the invite link on | `prepare_group_invite_enable` | `POST /2/chat/conversations/{id}/invite` | `invite_url`; `validity_expiry_timestamp_msec` (the params' `expires_at_msec`) and `affiliate_user_id` (the params' `affiliate_id`) when set; `action_signatures` |
| Turn the invite link off | `prepare_group_invite_disable` | `DELETE /2/chat/conversations/{id}/invite` | `action_signatures` |
| Ask to join | `prepare_group_join_request` | `POST /2/chat/conversations/{id}/join_requests` | `token` (the invite link's last 10 characters), `action_signatures` |
| Reject join requests | `prepare_group_join_reject` | `POST /2/chat/conversations/{id}/join_requests/reject` | `user_ids`, `action_signatures` |
| Set the message TTL | `prepare_message_ttl_change` | `PUT /2/chat/conversations/{id}/message_ttl` | `message_ttl_ms` (the params' `ttl_msec`, as a string), `action_signatures` |
| Clear the message TTL | `prepare_message_ttl_remove` | `DELETE /2/chat/conversations/{id}/message_ttl` | `action_signatures` |
| Change screen capture | `prepare_screen_capture` | `PUT /2/chat/conversations/{id}/screen_capture` | `blocking` (`True` for `BlockingEnabled`, `False` for `BlockingDisabled`) and `blocking_action_signatures`, or `detection` and `detection_action_signatures` |

A group's `conversation_id` is the `g…` id that
`POST /2/chat/conversations/group/initialize` returns as
`data.conversation_id`.

### Deleting messages

`prepare_message_delete` returns the action's signature nested, as every
prepare call does: send `action_signatures` as returned, next to the
sequence ids and the delete action the params signed.

```python
# 0.5.x
deletion = chat.prepare_message_delete(conversation_id, sequence_ids, True)
api.post(f"/2/chat/conversations/{path_id}/messages/delete", {
    "sequence_ids": sequence_ids,
    "delete_message_action": "delete_for_all",
    "action_signatures": [{
        "message_id": deletion["message_id"],
        "encoded_message_event_detail": deletion["encoded_message_event_detail"],
        "message_event_signature": {
            "signature": deletion["signature"],
            "signature_version": deletion["signature_version"],
            "public_key_version": deletion["public_key_version"],
            "signing_public_key": signing_public_key,
        },
    }],
})

# 0.6.0
deletion = chat.prepare_message_delete(MessageDeleteParams(conversation_id, sequence_ids, True))
api.post(f"/2/chat/conversations/{path_id}/messages/delete", {
    "sequence_ids": sequence_ids,
    "delete_message_action": "delete_for_all",
    "action_signatures": deletion["action_signatures"],
})
```

A recipient's `decrypt_event` returns the delete as a verified
`MessageDeleted` event with its `sequence_ids` and `delete_for_all`.

### Read receipts are signed

Sign a read receipt with `prepare_mark_conversation_read` and send the
`PreparedAction`'s `action_signatures` on
`POST /2/chat/conversations/{id}/read`. The call takes a
`MarkConversationReadParams` (the conversation id, the sequence id of the
newest event read, and a `seen_at_msec` that defaults to now) and returns a
dict with `action_signatures`, one entry. Without it the X API sends an
unsigned receipt, which recipients drop.

```python
# 0.5.x
api.post(f"/2/chat/conversations/{path_id}/read", {})

# 0.6.0
receipt = chat.prepare_mark_conversation_read(
    MarkConversationReadParams(conversation_id, seen_until_sequence_id)
)
api.post(f"/2/chat/conversations/{path_id}/read", {
    "action_signatures": receipt["action_signatures"],
})
```

A recipient's `decrypt_event` returns a signed receipt as a verified
`ReadReceipt` event, its position in `seen_until_sequence_id`.

### Group changes are signed

Every group change below returns `action_signatures` for its request in
[The requests](#the-requests). A group's title and description travel
encrypted under the conversation key, and the SDK encrypts them: the
creates, member adds, removals and title and description changes take them
as plaintext and return the encrypted values to send. An avatar is an image
the app encrypts and uploads; its URL is signed as is.

### Creating a group

`prepare_group_create` encrypts the group's title under the conversation key
it creates, so pass it as plaintext. The result dict also carries it
encrypted, as `encrypted_title` (absent when unset): send that as the create
request's `group_name`, next to its participant keys and signatures. The
create signs the encrypted value, which is base64, so a title may contain a
comma; a value signed as is, such as an avatar URL, can't. A create sets no
avatar: set one afterwards with an [avatar change](#changing-the-avatar),
with the image encrypted under the key the create returns.

```python
# 0.5.x
prepared = chat.prepare_group_create(
    public_keys, conversation_id, member_ids, admin_ids, title=title, avatar_url=avatar_url
)
body = {"group_name": title, "group_avatar_url": avatar_url}

# 0.6.0
prepared = chat.prepare_group_create(
    GroupCreateParams(public_keys, conversation_id, member_ids, admin_ids, title=title)
)
api.post("/2/chat/conversations/group", {
    "conversation_id": conversation_id,
    "group_members": member_ids,
    "group_admins": admin_ids,
    "group_name": prepared["encrypted_title"],
    "conversation_key_version": prepared["conversation_key_version"],
    "conversation_participant_keys": prepared["conversation_participant_keys"],
    "action_signatures": prepared["action_signatures"],
})
store_conversation_key(conversation_id, prepared["conversation_key_version"], prepared["conversation_key"])
```

`decrypt_event` returns a received group create with its title decrypted
with the key for the version the create names, from the call's key map or
the key cache: a `Created` change's `title` is a `GroupText` dict (the
`TypedDict` `chat_xdk` exports). `"kind": "Text"` holds the title in `text`.
`"kind": "Unavailable"` holds, in `raw`, the value as the create carries it,
when that key isn't there or the value doesn't decrypt under it, and the
rest of the create still decrypts. 0.5.x signed a create's title as the app
passed it, so a 0.5.x app's create with a plaintext title arrives as
`Unavailable` with the title in `raw`: show `raw` when a title isn't
decryptable. A create that names no key version carries its title as
plaintext, and arrives as `Text`. The encrypted `group_name` and
`group_description` the X API returns with a conversation open with
`decrypt`.

```python
# 0.5.x
change = group_change["change"]
if change["change_type"] == "Created" and change["title"]:
    show_title(chat.decrypt(change["title"], keys[conversation_key_version]))

# 0.6.0
change = group_change["change"]
if change["change_type"] == "Created" and change["title"]:
    title = change["title"]
    show_title(title["text"] if title["kind"] == "Text" else title["raw"])
```

A `Created` change also carries the create's `conversation_key_version`, and
the `avatar_url` a create from another client may set: a media URL whose
image is encrypted under that key version.

### Adding members

`prepare_group_members_change` rotates the conversation key, so it
re-encrypts the group's title and description under the key it generates:
pass them as plaintext, as `current_title` and `current_description`, not as
values your code encrypted. The result dict carries them encrypted, as
`encrypted_title` and `encrypted_description` (absent when unset). Send
`encrypted_title` as the add-members request's `encrypted_title`; the
description travels in the signed member add. Encrypt under the new key from
here on, as [Removing members](#removing-members) shows for a removal.

```python
# 0.5.x
prepared = chat.prepare_group_members_change(
    public_keys, conversation_id, new_member_ids, member_ids, admin_ids, [], current_title=title
)

# 0.6.0
prepared = chat.prepare_group_members_change(
    GroupMembersChangeParams(
        public_keys, conversation_id, new_member_ids, member_ids, admin_ids, [],
        current_title=title, current_description=description,
    )
)
api.post(f"/2/chat/conversations/{path_id}/members", {
    "user_ids": new_member_ids,
    "encrypted_title": prepared["encrypted_title"],
    "conversation_key_version": prepared["conversation_key_version"],
    "conversation_participant_keys": prepared["conversation_participant_keys"],
    "action_signatures": prepared["action_signatures"],
})
store_conversation_key(conversation_id, prepared["conversation_key_version"], prepared["conversation_key"])
```

Passing a description makes the add sign at signature version 8, the first
version whose member-add payload covers one, and 0.5.x readers can't verify
a version-8 add. Until every app that reads your groups runs 0.6.0, leave
the description out, so the add signs at version 7 as in 0.5.x; the new
members can read the description once a description change sets it under the
new key.

The avatar isn't re-encrypted: `current_avatar_url` takes its media URL,
signed as is, and the image stays encrypted under the key it was uploaded
with, which the new members never receive. To keep the avatar readable for
them, encrypt the image under the key the add returns, upload it, and send
an [avatar change](#changing-the-avatar) naming the new key version.

A recipient's `decrypt_event` returns the add as a verified `MembersAdded`
change with `member_ids`, `current_member_ids` and `current_admin_ids`.

### Removing members

`prepare_group_members_remove` removes `user_ids` and rotates the
conversation key, so the members removed don't receive the key the group
encrypts under next. `GroupMembersRemoveParams` takes:

- `public_keys`: the identity key of every member who stays, yours
  included, as `GET /2/users/{id}/public_keys` returns them. The SDK
  encrypts the new key to each member's newest key version; a member left
  out, you included, can't read what the group sends under the new key.
  The SDK doesn't check that the list is complete. A key for a member being
  removed raises `InvalidInputError`.
- `conversation_id` and `user_ids`, the members to remove.
- `title` and `description`: the group's current title and description, as
  plaintext. Pass each one the group has; the call encrypts each under the
  new key and signs it as a key-rotation re-encryption, which recipients'
  decrypt drops rather than shows as a change. A rotation leaves the avatar
  alone: its image stays encrypted under the key it was uploaded with,
  which the members who stay hold.

The result is a `PreparedConversationChange` dict: the new
`conversation_key` and `conversation_key_version`,
`conversation_participant_keys` for the members who stay, and
`action_signatures` in request order: the removal, a title change and a
description change for the ones passed, then the conversation-key change.
The removal signs at signature version 11, which 0.5.x readers can't verify
(see [Upgrade readers first](#upgrade-readers-first)).

```python
# 0.5.x
api.post(f"/2/chat/conversations/{path_id}/members/remove", {"user_ids": user_ids})

# 0.6.0
prepared = chat.prepare_group_members_remove(
    GroupMembersRemoveParams(
        remaining_public_keys, conversation_id, user_ids, title=title, description=description
    )
)
api.post(f"/2/chat/conversations/{path_id}/members/remove", {
    "user_ids": user_ids,
    "action_signatures": prepared["action_signatures"],
    "group_key_rotation_data": {
        "conversation_key_version": prepared["conversation_key_version"],
        "conversation_participant_keys": prepared["conversation_participant_keys"],
    },
})
```

**Encrypt under the new key as soon as the request succeeds.** The removed
members hold the old key, so a message encrypted under it is one they can
read. The key cache (`set_cache_keys(True)`) adopts the new key only once
`decrypt_events` decrypts the removal's key change from the conversation's
events, and only if that key change verifies against your own signing key;
until then an encrypt call that omits the key resolves the old one. Store
the new key and version, and pass them to every encrypt and prepare call
until the cache holds them:

```python
# 0.6.0
store_conversation_key(conversation_id, prepared["conversation_key_version"], prepared["conversation_key"])
payload = chat.encrypt_message(EncryptMessageParams(
    conversation_id, "hello",
    conversation_key=prepared["conversation_key"],
    conversation_key_version=prepared["conversation_key_version"],
))
```

The same holds after any call that rotates the key:
`prepare_conversation_key_change`, `prepare_group_create` and
`prepare_group_members_change`.

On the receiving side, `decrypt_events` returns the removal as a verified
`MembersRemoved` change with its `member_ids`, and the key change as a
`KeyChange` event that adds the new key to `conversation_keys` and moves
`latest_version` to it once it verifies. The title and description
re-encryptions are in `errors`, not `events` (see [Decrypt drops a
removal's title and description
re-encryptions](#decrypt-drops-a-removals-title-and-description-re-encryptions)):

```python
# 0.6.0
result = chat.decrypt_events(DecryptEventsParams(events))
for item in result["events"]:
    event = item["event"]
    if event["type"] == "GroupChange" and event["change"]["change_type"] == "MembersRemoved":
        removed = event["change"]["member_ids"]
version = result["conversation_keys"]["latest_version"]
```

### Leaving a group

`prepare_group_leave` signs the sender's removal and does not rotate the
conversation key. `action_signatures` are the removal, at signature version
11 as a member removal's, then a `GroupAdminAddChange` when
`promote_admin_id` is set, then a `ConversationDeleteEvent`. It returns a
`PreparedAction` dict. Send it as a removal of your own id:

```python
# 0.5.x
api.post(f"/2/chat/conversations/{path_id}/members/remove", {"user_ids": [my_user_id]})

# 0.6.0
left = chat.prepare_group_leave(
    GroupLeaveParams(conversation_id, promote_admin_id=promote_admin_id)
)
api.post(f"/2/chat/conversations/{path_id}/members/remove", {
    "user_ids": [my_user_id],
    "action_signatures": left["action_signatures"],
})
```

### Changing the title

`prepare_group_title_change` takes the new title as plaintext, encrypts it
under the conversation key and signs it. Like `EncryptMessageParams`,
`GroupTitleChangeParams` takes the key and its version as the
`conversation_key` and `conversation_key_version` keywords, or resolves
both from the key cache without them. The result is a
`PreparedGroupMetadataChange` dict: the `encrypted_value` the request sends
as `group_name`, the `conversation_key_version` it's encrypted under, and
the `action_signatures` to send with it.

```python
# 0.5.x
api.put(f"/2/chat/conversations/{path_id}", {
    "group_name": chat.encrypt(title, keys[conversation_key_version]),
    "conversation_key_version": conversation_key_version,
    "modified_fields": ["group_name"],
})

# 0.6.0
prepared = chat.prepare_group_title_change(GroupTitleChangeParams(conversation_id, title))
api.put(f"/2/chat/conversations/{path_id}", {
    "group_name": prepared["encrypted_value"],
    "conversation_key_version": prepared["conversation_key_version"],
    "modified_fields": ["group_name"],
    "action_signatures": prepared["action_signatures"],
})
```

`decrypt_event` returns a received title change decrypted: the `new_title`
of a `TitleChanged` change is a `GroupText` dict, as a create's `title` is.
It decrypts with the key for the version the change names, from the call's
key map or the key cache. Without that key, or when the value isn't
ciphertext under it, as for a plaintext title an app signed with a key
version, it is `Unavailable` with the value as carried, and the event still
decrypts. A removal's re-encrypted title never arrives as a `TitleChanged`.

```python
# 0.5.x
change = group_change["change"]
if change["change_type"] == "TitleChanged":
    show_title(chat.decrypt(change["new_title"], keys[conversation_key_version]))

# 0.6.0
change = group_change["change"]
if change["change_type"] == "TitleChanged":
    new_title = change["new_title"]
    show_title(new_title["text"] if new_title["kind"] == "Text" else new_title["raw"])
```

### Changing the description

`prepare_group_description_change` takes the new description as plaintext
and returns a `PreparedGroupMetadataChange` dict, as the title change does;
the request sends its `encrypted_value` as `group_description`.

```python
# 0.5.x
api.put(f"/2/chat/conversations/{path_id}", {
    "group_description": chat.encrypt(description, keys[conversation_key_version]),
    "conversation_key_version": conversation_key_version,
    "modified_fields": ["group_description"],
})

# 0.6.0
prepared = chat.prepare_group_description_change(
    GroupDescriptionChangeParams(conversation_id, description)
)
api.put(f"/2/chat/conversations/{path_id}", {
    "group_description": prepared["encrypted_value"],
    "conversation_key_version": prepared["conversation_key_version"],
    "modified_fields": ["group_description"],
    "action_signatures": prepared["action_signatures"],
})
```

A received description change is a `DescriptionChanged` change holding
`new_description` as a `GroupText` dict; read it as a title change's
`new_title`. A removal's re-encrypted description never arrives as one:

```python
# 0.6.0
change = group_change["change"]
if change["change_type"] == "DescriptionChanged":
    new_description = change["new_description"]
    show_description(
        new_description["text"] if new_description["kind"] == "Text" else new_description["raw"]
    )
```

### Changing the avatar

An avatar URL is not encrypted; the image is. Encrypt the image bytes under
the conversation key, upload them to the group's media, and pass the image's
media URL to `prepare_group_avatar_change`, with the version of the key the
image is encrypted under. The call signs both as they are and returns a
`PreparedAction` dict; send its `action_signatures` with the URL. A URL
containing a comma is rejected, since signatures join their fields with
commas.

```python
# 0.5.x
api.put(f"/2/chat/conversations/{path_id}", {
    "group_avatar_url": chat.encrypt(avatar_url, keys[conversation_key_version]),
    "conversation_key_version": conversation_key_version,
    "modified_fields": ["group_avatar_url"],
})

# 0.6.0
prepared = chat.prepare_group_avatar_change(
    GroupAvatarChangeParams(conversation_id, avatar_url, conversation_key_version)
)
api.put(f"/2/chat/conversations/{path_id}", {
    "group_avatar_url": avatar_url,
    "conversation_key_version": conversation_key_version,
    "modified_fields": ["group_avatar_url"],
    "action_signatures": prepared["action_signatures"],
})
```

A received `AvatarChanged` change holds `new_avatar_url` as sent and its
`conversation_key_version`: download the image and decrypt it with the key
for that version.

```python
# 0.6.0
change = group_change["change"]
if change["change_type"] == "AvatarChanged":
    show_avatar(change["new_avatar_url"], change["conversation_key_version"])
```

### Admins, invites, join requests, message TTL and screen capture

Each of these calls returns a `PreparedAction` dict with one signature, at
signature version 7, for the request [The requests](#the-requests) names.
0.5.x apps sent these requests without signatures; recipients drop them
unsigned. A recipient's `decrypt_event` returns admin, invite and join
changes as verified `GroupChange` events (`AdminsAdded`, `AdminsRemoved`,
`InviteEnabled`, `InviteDisabled`, `JoinRequested`, `JoinRejected`) and TTL
and screen-capture changes as verified `SettingsChange` events.

```python
# 0.5.x
api.post(f"/2/chat/conversations/{path_id}/admins", {"user_ids": user_ids})

# 0.6.0
added = chat.prepare_group_admins_add(GroupAdminsAddParams(conversation_id, user_ids))
api.post(f"/2/chat/conversations/{path_id}/admins", {
    "user_ids": user_ids, "action_signatures": added["action_signatures"],
})
removed = chat.prepare_group_admins_remove(GroupAdminsRemoveParams(conversation_id, user_ids))
api.post(f"/2/chat/conversations/{path_id}/admins/remove", {
    "user_ids": user_ids, "action_signatures": removed["action_signatures"],
})
```

An invite signs its URL, its expiry and its affiliate; an omitted
`expires_at_msec` or `affiliate_id` signs `null`. The request sends the
expiry as `validity_expiry_timestamp_msec`, and only with the same value the
params signed:

```python
# 0.6.0
invite = chat.prepare_group_invite_enable(
    GroupInviteEnableParams(conversation_id, invite_url, expires_at_msec=expires_at_msec)
)
api.post(f"/2/chat/conversations/{path_id}/invite", {
    "invite_url": invite_url,
    "validity_expiry_timestamp_msec": str(expires_at_msec),
    "action_signatures": invite["action_signatures"],
})
disabled = chat.prepare_group_invite_disable(GroupInviteDisableParams(conversation_id))
api.delete(f"/2/chat/conversations/{path_id}/invite", {
    "action_signatures": disabled["action_signatures"],
})
```

A join request signs the requesting user, who defaults to the sender; the
invite token travels in the request but not in the signature:

```python
# 0.6.0
request = chat.prepare_group_join_request(GroupJoinRequestParams(conversation_id))
api.post(f"/2/chat/conversations/{path_id}/join_requests", {
    "token": invite_token, "action_signatures": request["action_signatures"],
})
rejected = chat.prepare_group_join_reject(GroupJoinRejectParams(conversation_id, user_ids))
api.post(f"/2/chat/conversations/{path_id}/join_requests/reject", {
    "user_ids": user_ids, "action_signatures": rejected["action_signatures"],
})
```

A TTL change signs `ttl_msec` only; a negative one is rejected:

```python
# 0.6.0
ttl = chat.prepare_message_ttl_change(MessageTtlChangeParams(conversation_id, ttl_msec))
api.put(f"/2/chat/conversations/{path_id}/message_ttl", {
    "message_ttl_ms": str(ttl_msec), "action_signatures": ttl["action_signatures"],
})
cleared = chat.prepare_message_ttl_remove(MessageTtlRemoveParams(conversation_id))
api.delete(f"/2/chat/conversations/{path_id}/message_ttl", {
    "action_signatures": cleared["action_signatures"],
})
```

A screen-capture change is one of `ScreenCaptureChange.BlockingEnabled`,
`BlockingDisabled`, `DetectionEnabled` or `DetectionDisabled`. The request
names its signatures after the setting, `blocking_action_signatures` or
`detection_action_signatures`, not `action_signatures`:

```python
# 0.6.0
capture = chat.prepare_screen_capture(
    ScreenCaptureParams(conversation_id, ScreenCaptureChange.BlockingEnabled)
)
api.put(f"/2/chat/conversations/{path_id}/screen_capture", {
    "blocking": True, "blocking_action_signatures": capture["action_signatures"],
})
```

## 5. Verify

### Build and type-check

Run your type checker (mypy or pyright) over the app: the package's stubs
flag every call that still passes 0.5.x arguments. Then run your tests.

### Find the 0.5.x names

Search the app for the names in the symbol index's 0.5.x column. Each hit is
a line to change, unless it is your own code that shares the name:

```sh
grep -rnE "encrypt_stream|decrypt_stream|stream_(en|de)cryptor|Stream(En|De)cryptor|encrypted_stream_size|guesses_remaining\(|\.encrypt\(|encrypted_content|encoded_event_signature|generate_version|new_text|message_ids|seen_until_id|avatar_url=|[\"'](messages|participant_keys|encrypted_key|key_version|public_key)[\"']" --include='*.py' .
grep -rn "target_message_id" --include='*.py' .
```

Every `target_message_id` the second search finds should read a v1 edit's
signed message id; rename the rest to `target_message_sequence_id`. The
first search's `"public_key"` matches registration code too, which keeps the
name: change only the public key inputs.

### Run a round trip

This round trip runs offline, with two chats standing in for two users. It
registers both, starts a conversation, sends a message and decrypts it with
`reject_unverified` on, the default, so the signature has to verify:

```python
# 0.6.0
alice, bob = Chat(), Chat()
alice_keys = alice.generate_keypairs().public_key
bob_keys = bob.generate_keypairs().public_key
alice.set_identity(SetIdentityParams("1001", "1"))
bob.set_identity(SetIdentityParams("1002", "1"))

change = alice.prepare_conversation_key_change(ConversationKeyChangeParams([
    {"user_id": "1001", "identity_public_key": alice_keys.public_key, "public_key_version": "1"},
    {"user_id": "1002", "identity_public_key": bob_keys.public_key, "public_key_version": "1"},
]))
payload = alice.encrypt_message(EncryptMessageParams(
    change["conversation_id"], "hello",
    conversation_key=change["conversation_key"],
    conversation_key_version=change["conversation_key_version"],
))

bob_entry = next(k for k in change["conversation_participant_keys"] if k["user_id"] == "1002")
bob_key = bob.decrypt_conversation_key(bob_entry["encrypted_conversation_key"])
alice_signing_key: SigningKeyEntry = {
    "user_id": "1001",
    "public_key_version": "1",
    "public_key": alice_keys.signing_public_key,
    "identity_public_key": alice_keys.public_key,
    "identity_public_key_signature": alice_keys.identity_public_key_signature,
}
event = bob.decrypt_event(DecryptEventParams(
    payload.event_b64, {change["conversation_key_version"]: bob_key}, signing_keys=[alice_signing_key]
))
assert event["verified"] and event["content"]["text"] == "hello"
assert payload.signature_info.signature_version in ("7", "10")
assert payload.xdk_version == "0.6.0"
```

`signature_version` is `"7"` for a v0 send and `"10"` for v1, as the
`v1_send` switch decides. `xdk_version` is the version the X API receives
with each send.

Then run the same flows against a test conversation on the X API: send a
text, a file, a reply, an edit and a delete, mark the conversation read,
and create a group, add a member and remove one. Fetch the conversation's
events with `GET /2/chat/conversations/{id}/events`, pass `data[].encoded_event`
and `meta.conversation_key_events` to `decrypt_events` with every
participant's signing keys, and check that every event in `events` has
`verified` set and that `errors` holds only the removal's title and
description re-encryptions.
