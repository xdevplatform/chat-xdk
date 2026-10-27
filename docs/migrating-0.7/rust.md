# Migrating Rust code to chat-xdk 0.7.0

This page moves Rust code written for `chat-xdk-core` 0.5.x (0.5.0, 0.5.1
or 0.5.2) to 0.7.0. Work through it top to bottom: [Before you
start](#0-before-you-start) sets up the upgrade, the [symbol
index](#1-symbol-index) maps every 0.5.x name to its 0.7.0 form,
[Compile-time changes](#2-compile-time-changes) and [Runtime
changes](#3-runtime-and-behavior-changes) show each line to change, [Group
and receipt signing](#4-group-and-receipt-signing) gives every signed
request, and [Verify](#5-verify) checks the result. [Why 0.7.0
changes](why.md) explains each change, and the [index](README.md) lists the
other bindings' pages. [API.md](../API.md) documents every call.

## Checklist

Each item is tagged with what it takes: `[rollout]` is a deployment step,
`[compile]` a change the compiler reports, `[runtime]` a change in behavior
that nothing reports, and `[new]` a 0.7.0 call to adopt.

- [ ] `[rollout]` [Install 0.7.0](#install-070)
- [ ] `[rollout]` [Upgrade every app that reads your conversations first](#upgrade-readers-first)
- [ ] `[new]` [Hand a chat the X API's feature switches to send v1](#the-feature-switch-request)
- [ ] `[compile]` [Keep keys in Juicebox, and read a config error as an `SdkError`](#keys-stored-in-juicebox)
- [ ] `[compile]` [Register keys with the public key only](#register-keys-with-the-public-key-only)
- [ ] `[compile]` [Pass a `&SetIdentityParams` to `set_identity` and handle its `Result`](#set_identity-takes-setidentityparams)
- [ ] `[compile]` [Pass an `&ImportKeysParams` to `import_keys`](#import_keys-takes-importkeysparams)
- [ ] `[compile]` [Pass a `DecryptEventsParams` to `decrypt_events` and read its `events`](#decrypt_events-takes-decrypteventsparams)
- [ ] `[compile]` [Pass a `DecryptEventParams` to `decrypt_event`](#decrypt_event-takes-decrypteventparams)
- [ ] `[compile]` [Pass params by reference to every method](#methods-take-params-by-reference)
- [ ] `[compile]` [Build params with `new` and `with_*`, and give matches on SDK enums a wildcard arm](#types-are-non_exhaustive)
- [ ] `[compile]` [Read `SendPayload` under the send request's field names and send `xdk_version`](#sendpayload-fields-take-the-send-requests-names)
- [ ] `[compile]` [Build a message before you encrypt its files](#encrypt-a-file-from-its-message)
- [ ] `[compile]` [Decrypt a file with the event of its message](#decrypt-a-file-with-its-messages-event)
- [ ] `[compile]` [Use `file_encryptor` and `file_decryptor` for large files](#encrypt-and-decrypt-large-files-in-chunks)
- [ ] `[compile]` [Pass action signatures through as returned](#action-signatures-come-nested)
- [ ] `[compile]` [Build a `PublicKeyInput` with `identity_public_key` and `public_key_version`](#public-key-inputs-name-the-identity-key-and-its-version)
- [ ] `[compile]` [Pass participant keys through as returned](#participant-keys-take-the-key-requests-names)
- [ ] `[compile]` [Read received participant keys under the same names](#received-participant-keys-take-the-same-names)
- [ ] `[compile]` [Read a delete's signature from its `PreparedAction`](#deletes-return-a-preparedaction)
- [ ] `[compile]` [Read decrypted events under the names the calls take](#decrypted-events-use-the-names-the-calls-take)
- [ ] `[compile]` [Tell errors apart by `kind()`, and read a wrong PIN's attempts from `guesses_remaining()`](#errors-carry-their-kind)
- [ ] `[runtime]` [Pass user ids as strings of digits](#user-ids-are-strings-of-digits)
- [ ] `[runtime]` [Pass key versions as the X API returns them](#key-versions-are-integers-written-as-strings)
- [ ] `[runtime]` [Pass entities, files, URL cards and posts the SDK accepts](#entities-files-url-cards-and-posts-are-checked)
- [ ] `[runtime]` [Store every participant's signing keys, and handle a `latest_version` of `None`](#latest_version-comes-from-a-verified-key-change)
- [ ] `[runtime]` [Rename every read of `target_message_id` to `target_message_sequence_id`](#target_message_id-holds-a-different-value)
- [ ] `[runtime]` [Keep a prepared change's key from the struct](#a-prepared-changes-json-leaves-out-its-key)
- [ ] `[runtime]` [Sign only your own data with `sign`](#sign-refuses-data-only-the-sdk-signs)
- [ ] `[runtime]` [Skip the events `decrypt_event` drops](#decrypt-drops-a-removals-title-and-description-re-encryptions)
- [ ] `[runtime]` [Expect an empty Juicebox config to fail](#an-empty-juicebox-config-fails)
- [ ] `[runtime]` [Sign every group change and read receipt](#4-group-and-receipt-signing)
- [ ] `[runtime]` [Send each delete's `action_signatures` as returned](#deleting-messages)
- [ ] `[runtime]` [Sign read receipts](#read-receipts-are-signed)
- [ ] `[runtime]` [Sign group creates, member adds, title, description and avatar changes](#group-changes-are-signed)
- [ ] `[runtime]` [Remove members with a key rotation, and encrypt under the new key](#removing-members)
- [ ] `[new]` [Sign leaves, admin, invite, join, message-TTL and screen-capture changes](#leaving-a-group)
- [ ] `[rollout]` [Verify the migration](#5-verify)

## About the snippets

Each snippet shows the lines that change, first as 0.5.x code writes them,
under `// 0.5.x`, and then as 0.7.0 code writes them, under `// 0.7.0`. A
snippet with only a `// 0.7.0` half shows code 0.7.0 adds. CI compiles the
0.7.0 half of every snippet on this page against 0.7.0
([`scripts/check_doc_snippets.py`](../../scripts/check_doc_snippets.py)),
as the body of a function that returns `Result<(), Box<dyn std::error::Error>>`.

`chat` is a `ChatCore` with your keys loaded; `Chat`, which adds Juicebox
key storage, has the same methods. The other names stand for your own
values: ids, versions, keys and events as the X API returns them, `keys` for
the conversation key map `decrypt_events` returns, `payload` for a
`SendPayload`, `prepared` for a `PreparedConversationChange`, `key_change`
for a `ConversationKeyChangeParams`, `received_key_change`, `message`,
`deleted`, `receipt` and `group_change` for a decrypted `KeyChangeEvent`,
`Message`, `MessageDeletedEvent`, `ReadReceiptEvent` and
`GroupChangeEvent`, `err` for an `SdkError`, `juicebox_config` for the
Juicebox config the X API returns, as a `String`, and `page` for a page of
`GET /2/chat/conversations/{id}/events`, as a `serde_json::Value`.
`api.post(path, &body)`, `api.put(path, &body)` and `api.delete(path,
&body)` stand for your HTTP client: each sends `body`, a
`serde_json::Value`, to `https://api.x.com` + `path` with your user access
token and returns the parsed JSON response as a `serde_json::Value`.
`path_id` is the conversation id as a request path takes it: a group's
`g…` id as is, and a one-to-one's in its hyphen form,
`conversation_id.replace(':', "-")`. `http_get(url, timeout_ms, max_bytes)`
stands for your HTTP client's anonymous GET: it returns the response's
status and at most `max_bytes` of its body. `photo_attachment(media_hash_key)`
stands for your code that builds a photo's `AttachmentDescriptor`;
`show_edit`, `show_title`, `show_description` and `show_avatar` for your code
that displays an edit, or a group's title, description or avatar;
`handle(&event)` for your code that handles a decrypted event;
`log_skipped(event_b64, &err)` for your code that logs an event it skips;
and `store_conversation_key(conversation_id, version, &key)` for your code
that stores a conversation key. Every type and module the snippets use
imports from `chat_xdk_core`, except `SdkError` and `ErrorKind`, which
import from `chat_xdk_core::error`, and `JuiceboxConfig`, from
`chat_xdk_core::keys::juicebox`.

## 0. Before you start

### Install 0.7.0

Set the dependency to 0.7.0 in `Cargo.toml`:

```toml
[dependencies]
chat-xdk-core = "0.7.0"
```

The `juicebox` feature, on by default, adds `Chat` and Juicebox key storage;
`default-features = false` builds `ChatCore` without it, as in 0.5.x. Every
app that shares conversations with yours reads the formats 0.7.0 sends only
once it runs 0.7.0 too, so plan the rollout below before you deploy.

### Upgrade readers first

0.7.0 sends each message, reply, reaction and edit in one of two formats.
v0 is the format 0.5.x sends. v1 encrypts each message under its own key,
derived from the conversation key, the sender and the message id, and signs
it at signature version 10. A chat sends v1 once you hand it the X API's
`v1_send` feature switch, on, and v0 otherwise (see [The feature-switch
request](#the-feature-switch-request)). Two group changes also sign at
versions 0.5.x can't verify: a member removal signs at version 11, and a
member add that carries a description at version 8.

0.5.x rejects each of these as a signature verification failure, so upgrade
every app that reads your conversations to 0.7.0, Rust ones included,
before:

- any of your senders can send v1;
- you remove a member from a group with
  [`prepare_group_members_remove`](#removing-members);
- you pass a description to [`prepare_group_members_change`](#adding-members).

0.7.0 reads both formats, including v1 reply previews, edits and files.
There's no code to change: to see which format a send used, read
`signature_info.signature_version`, `"7"` for v0 and `"10"` for v1.

### The feature-switch request

The language bindings read the X API's feature switches with one anonymous
request, `GET https://api.x.com/2/chat/features`, when a chat is created.
The Rust crate never makes the request: a chat sends v0 until you make it
and hand the answer to `set_feature_switches`, which `ChatCore` and `Chat`
both have. Make the request once, when you create the chat, as the crate's
constants say: GET `FEATURES_ENDPOINT` without credentials or query
parameters, within `FEATURES_TIMEOUT_MS` milliseconds, reading at most one
byte past `FEATURES_MAX_BODY`:

```rust
// 0.7.0
let (status, body) = http_get(FEATURES_ENDPOINT, FEATURES_TIMEOUT_MS, FEATURES_MAX_BODY + 1)?;
chat.set_feature_switches(status, &body);
```

A chat takes one answer for its lifetime: a later call changes nothing.
Every switch stays off when the status isn't 200 or the body is larger than
`FEATURES_MAX_BODY` or isn't a `{"features": {...}}` object, so a chat whose
request fails keeps sending v0. Without the call there's no code to change.

## 1. Symbol index

Every 0.5.x name that changes, with its 0.7.0 form and the section that
shows the change. A name not listed here keeps its 0.5.x form. Search your
code for each name in the first column; [Verify](#5-verify) gives the
search as one command.

| 0.5.x | 0.7.0 | Section |
|---|---|---|
| `JuiceboxConfig::from_x_api_json` returning `Result<_, String>` | Returns `Result<_, SdkError>` | [Juicebox](#keys-stored-in-juicebox) |
| `SdkError::Juicebox(JuiceboxError::InvalidPin { guesses_remaining })` | `err.guesses_remaining()` | [Errors](#errors-carry-their-kind) |
| `matches!(err, SdkError::InvalidState(_))` to spot bad input | `err.kind() == ErrorKind::InvalidInput` | [Errors](#errors-carry-their-kind) |
| `generate_keypairs_with_version(version)` | `generate_keypairs()`, then `set_identity` with the registered version | [Registration](#register-keys-with-the-public-key-only) |
| `registration.version`, `registration.generate_version` | Removed: the registration request returns the version (`public_key_version`) | [Registration](#register-keys-with-the-public-key-only) |
| `PublicKeys::version` | Removed: the `public_key_version` the registration request returns | [Registration](#register-keys-with-the-public-key-only) |
| `chat.set_identity(user_id, signing_key_version)` | `chat.set_identity(&SetIdentityParams::new(user_id, signing_key_version))?` | [set_identity](#set_identity-takes-setidentityparams) |
| `chat.import_keys(&keys)` | `chat.import_keys(&ImportKeysParams::new(keys))?` | [import_keys](#import_keys-takes-importkeysparams) |
| `chat.import_keys_with_version(&keys, version)` | `chat.import_keys(&ImportKeysParams::new(keys).with_signing_key_version(version))?` | [import_keys](#import_keys-takes-importkeysparams) |
| `chat.decrypt_events(&events, &signing_keys)` | `chat.decrypt_events(&DecryptEventsParams::new(events).with_signing_keys(signing_keys))` | [decrypt_events](#decrypt_events-takes-decrypteventsparams) |
| `result.messages`, `DecryptedMessage` | `result.events`, `DecryptedEvent` | [decrypt_events](#decrypt_events-takes-decrypteventsparams) |
| `chat.decrypt_event(event_b64, &keys, &signing_keys)` | `chat.decrypt_event(&DecryptEventParams::new(event_b64, keys).with_signing_keys(signing_keys))` | [decrypt_event](#decrypt_event-takes-decrypteventparams) |
| `encrypt_message(params)`, `encrypt_reply(params)`, `prepare_conversation_key_change(params)`, `prepare_group_create(params)`, `prepare_group_members_change(params)` | The same calls with `&params` | [By reference](#methods-take-params-by-reference) |
| `chat.set_signing_keys(vec)` | `chat.set_signing_keys(&slice)` | [By reference](#methods-take-params-by-reference) |
| `set_reject_unverified(&mut self, ..)`, `Chat::update_config(&mut self, ..)` | Take `&self` | [By reference](#methods-take-params-by-reference) |
| Struct literals for `SigningKeyEntry`, `EntityDescriptor`, `PublicKeyInput`, params | `new` and `with_*` | [non_exhaustive](#types-are-non_exhaustive) |
| `payload.encrypted_content` | `payload.encoded_message_create_event` | [SendPayload](#sendpayload-fields-take-the-send-requests-names) |
| `payload.encoded_event_signature` | `payload.encoded_message_event_signature` | [SendPayload](#sendpayload-fields-take-the-send-requests-names) |
| `chat.encrypt_stream(&plaintext, &key)` | `chat.encrypt_file(&EncryptFileParams::new(file, &event_b64, media_hash_key))` | [Files](#encrypt-a-file-from-its-message) |
| `chat.decrypt_stream(&encrypted, &key)` | `chat.decrypt_file(&DecryptFileParams::new(encrypted, event_b64, keys, media_hash_key))` | [Files](#decrypt-a-file-with-its-messages-event) |
| `chat.stream_encryptor(&key)`, `chat.stream_decryptor(&key)` | `chat.file_encryptor(&FileEncryptorParams::new(..))`, `chat.file_decryptor(&FileDecryptorParams::new(..))` | [Large files](#encrypt-and-decrypt-large-files-in-chunks) |
| `utils::encrypted_stream_size` | `utils::encrypted_file_size` | [Files](#encrypt-a-file-from-its-message) |
| `crypto::encryption::{encrypt_stream, decrypt_stream, encrypted_stream_size, StreamEncryptor, StreamDecryptor}` | `{encrypt_file, decrypt_file, encrypted_file_size, FileEncryptor, FileDecryptor}` | [Large files](#encrypt-and-decrypt-large-files-in-chunks) |
| `chat.encrypt(plaintext, &key)` | Removed: titles and descriptions go through `prepare_group_title_change`, `prepare_group_description_change` and the group creates and member adds; avatar URLs aren't encrypted; files go through `encrypt_file` | [Changing the title](#changing-the-title) |
| `ActionSignature { signature, signature_version, public_key_version, signature_payload }` | `message_event_signature: MessageEventSignature`; serialize `action_signatures` as returned | [Action signatures](#action-signatures-come-nested) |
| `PublicKeyInput { public_key, key_version, .. }` | `PublicKeyInput::new(user_id, identity_public_key, public_key_version)` | [Public key inputs](#public-key-inputs-name-the-identity-key-and-its-version) |
| `prepared.participant_keys`, `EncryptedKeyForRecipient`, `encrypted_key` | `prepared.conversation_participant_keys`, `ConversationParticipantKey`, `encrypted_conversation_key` | [Participant keys](#participant-keys-take-the-key-requests-names) |
| `received_key_change.participant_keys`, `ParticipantKey`, `encrypted_key` | `conversation_participant_keys`, `ConversationParticipantKey`, `encrypted_conversation_key` | [Received keys](#received-participant-keys-take-the-same-names) |
| `prepare_message_delete` returning an `ActionSignature` | Returns a `PreparedAction`: `deletion.action_signatures[0]` | [Deletes](#deletes-return-a-preparedaction) |
| `Message::key_version`, `KeyChangeEvent::key_version` | `conversation_key_version` | [Event names](#decrypted-events-use-the-names-the-calls-take) |
| `MessageContent::Reaction`, `ReactionRemoved` and `Edit` `target_message_id` | `target_message_sequence_id` | [Event names](#decrypted-events-use-the-names-the-calls-take) |
| `MessageContent::Edit` `new_text` | `updated_text` | [Event names](#decrypted-events-use-the-names-the-calls-take) |
| `MessageDeletedEvent::message_ids` | `sequence_ids` | [Event names](#decrypted-events-use-the-names-the-calls-take) |
| `ReadReceiptEvent::seen_until_id`, `MarkedUnreadEvent::seen_until_id` | `seen_until_sequence_id` | [Event names](#decrypted-events-use-the-names-the-calls-take) |
| `GroupChange::Created { title: Option<String> }`, `TitleChanged { new_title: String }` | `Option<GroupText>`, `GroupText` | [Creating a group](#creating-a-group) |
| `GroupCreateParams::avatar_url` | Removed: set the avatar with `prepare_group_avatar_change` | [Creating a group](#creating-a-group) |
| `EncryptReplyParams::reply_to_sender_id: Option<i64>` | `Option<String>`, set with `with_reply_to_sender_id` | [User ids](#user-ids-are-strings-of-digits) |

## 2. Compile-time changes

These changes are in the order an app meets them: creating the chat,
registering, loading keys, decrypting, encrypting and sending, files,
prepared changes, decrypted events and errors.

### Keys stored in Juicebox

`Chat::new(config)` keeps your keys in Juicebox under the Juicebox config
the X API returns, as in 0.5.x, and `Chat::default()` creates one without a
config, which manages its keys with `import_keys` and `export_keys` or takes
the config later from `update_config`, on first boot. `update_config` takes
`&self`. `JuiceboxConfig::from_x_api_json`, which reads the config the X API
returns, returns an `SdkError`: an `InvalidState` error for an empty or
blank string (see [An empty Juicebox config
fails](#an-empty-juicebox-config-fails)), and an `InvalidInput` error naming
the problem for a malformed one, where 0.5.x returned a `String`:

```rust
// 0.5.x
let config: Result<JuiceboxConfig, String> = JuiceboxConfig::from_x_api_json(&juicebox_config);

// 0.7.0
let config: Result<JuiceboxConfig, SdkError> = JuiceboxConfig::from_x_api_json(&juicebox_config);
```

A wrong PIN fails with an error of kind `ErrorKind::InvalidPin`, whose
`guesses_remaining()` holds the attempts Juicebox reports left, `Some(0)`
once the stored keys are locked (see [Errors carry their
kind](#errors-carry-their-kind)).

### Register keys with the public key only

`generate_keypairs` returns a `PublicKeyRegistrationPayload` that holds only
`public_key`. Send it as the only field of the
`POST /2/users/{id}/public_keys` body. 0.7.0 doesn't take or pick a
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

// 0.7.0
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

// 0.7.0
let registration = chat.generate_keypairs()?;
```

`PublicKeys`, which `get_public_keys` and `setup` return, holds the two
public keys, `identity` and `signing`, and no version: their version is the
`public_key_version` the registration request returns.

### `set_identity` takes `SetIdentityParams`

Pass the user id and the signing-key version in a `SetIdentityParams`.
`set_identity` returns `Result<(), SdkError>`, an `SdkError::InvalidInput`
when either value is invalid (see
[user ids](#user-ids-are-strings-of-digits) and
[key versions](#key-versions-are-integers-written-as-strings)).

```rust
// 0.5.x
chat.set_identity(user_id, signing_key_version);

// 0.7.0
chat.set_identity(&SetIdentityParams::new(user_id, signing_key_version))?;
```

### `import_keys` takes `ImportKeysParams`

Pass the saved key bytes in an `ImportKeysParams`, and optionally the
signing-key version they were registered under with
`with_signing_key_version`. Without a version, call `set_identity` before
the first signed call. `export_keys` keeps its 0.5.x signature; without an
identity key loaded it fails with an error of kind `ErrorKind::InvalidState`.

```rust
// 0.5.x
chat.import_keys(&private_keys)?;
chat.import_keys_with_version(&private_keys, signing_key_version)?;

// 0.7.0
chat.import_keys(&ImportKeysParams::new(private_keys.clone()))?;
chat.import_keys(&ImportKeysParams::new(private_keys).with_signing_key_version(signing_key_version))?;
```

### `decrypt_events` takes `DecryptEventsParams`

Pass the events, a `Vec<String>`, in a `DecryptEventsParams`, and the
signing keys with `with_signing_keys`. Without signing keys, the ones
`set_signing_keys` stored verify the events. The call still returns a
`DecryptEventsResult` that collects errors per event, events decrypt drops
included, and it holds the decrypted events, of every event type, in
`events`, each a `DecryptedEvent`:

```rust
// 0.5.x
let result = chat.decrypt_events(&events, &signing_keys);
let first: Option<&DecryptedMessage> = result.messages.first();

// 0.7.0
let result = chat.decrypt_events(&DecryptEventsParams::new(events).with_signing_keys(signing_keys));
let first: Option<&DecryptedEvent> = result.events.first();
```

The version to encrypt with, `result.conversation_keys.latest_version`,
comes only from a key change that verified (see [`latest_version` comes from
a verified key change](#latest_version-comes-from-a-verified-key-change)).

### `decrypt_event` takes `DecryptEventParams`

Pass the event and the conversation key map in a `DecryptEventParams`, and
the signing keys with `with_signing_keys`. An empty key map resolves the
key from the key cache (`set_cache_keys(true)`), and without signing keys
the ones `set_signing_keys` stored verify the event. The call still fails on
an event it can't decrypt, and on one decrypt drops (see [Decrypt drops a
removal's title and description
re-encryptions](#decrypt-drops-a-removals-title-and-description-re-encryptions)).

```rust
// 0.5.x
let event = chat.decrypt_event(event_b64, &keys, &signing_keys)?;

// 0.7.0
let event = chat.decrypt_event(&DecryptEventParams::new(event_b64, keys).with_signing_keys(signing_keys))?;
```

### Methods take params by reference

Every method takes its params by reference. Add `&` to `encrypt_message`,
`encrypt_reply`, `prepare_conversation_key_change`, `prepare_group_create`
and `prepare_group_members_change`, and to the `ChatCore` methods'
`_with_version` forms. Calls to `encrypt_add_reaction`,
`encrypt_remove_reaction`, `encrypt_edit` and `prepare_message_delete` stay
as they are; `decrypt_events`, `decrypt_event`, `encrypt_file`,
`file_encryptor`, `decrypt_file`, `file_decryptor` and
`prepare_mark_conversation_read` take `&params` too, and
`set_signing_keys` takes a slice. Every `ChatCore` and `Chat` method takes
`&self`, `set_reject_unverified` and `Chat::update_config` included, so one
chat serves every thread without a lock.

```rust
// 0.5.x
let payload = chat.encrypt_message(EncryptMessageParams::new(conversation_id, "hello"))?;
let reply = chat.encrypt_reply(EncryptReplyParams::new(conversation_id, "pong", event_b64))?;
let prepared = chat.prepare_conversation_key_change(key_change)?;
chat.set_signing_keys(signing_keys);

// 0.7.0
let payload = chat.encrypt_message(&EncryptMessageParams::new(conversation_id, "hello"))?;
let reply = chat.encrypt_reply(&EncryptReplyParams::new(conversation_id, "pong", event_b64))?;
let prepared = chat.prepare_conversation_key_change(&key_change)?;
chat.set_signing_keys(&signing_keys);
```

### Types are `#[non_exhaustive]`

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

// 0.7.0
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

### `SendPayload` fields take the send request's names

The two encoded fields carry the names of the fields of the send request,
`POST /2/chat/conversations/{id}/messages`, so the request takes them as
they are. Read payloads under the new names wherever your code reads one,
including code that stores payloads. The request also takes the payload's
`xdk_version`, the version of the SDK that built it:

```rust
// 0.5.x
let body = serde_json::json!({
    "message_id": payload.message_id,
    "encoded_message_create_event": payload.encrypted_content,
    "encoded_message_event_signature": payload.encoded_event_signature,
});

// 0.7.0
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

### Encrypt a file from its message

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

// 0.7.0
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

```rust
// 0.5.x
let plaintext = chat.decrypt_stream(&downloaded, &keys[conversation_key_version])?;

// 0.7.0
let plaintext = chat.decrypt_file(&DecryptFileParams::new(downloaded, file_event_b64, keys, file_hash_key))?;
```

### Encrypt and decrypt large files in chunks

`file_encryptor` and `file_decryptor` take the same values as
`encrypt_file` and `decrypt_file`, without the file bytes, and return a
`FileEncryptor` or a `FileDecryptor`; `push` and `finish` keep their 0.5.x
form. Size an upload with `utils::encrypted_file_size`.

```rust
// 0.5.x
let size = chat_xdk_core::utils::encrypted_stream_size(photo.len() as u64);
let encryptor = chat.stream_encryptor(&keys[conversation_key_version])?;
let decryptor = chat.stream_decryptor(&keys[conversation_key_version])?;

// 0.7.0
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

// 0.7.0
use chat_xdk_core::crypto::encryption::{
    decrypt_file, encrypt_file, encrypted_file_size, FileDecryptor, FileEncryptor,
};
```

### Action signatures come nested

The prepare methods return each `ActionSignature` in the shape a request's
`action_signatures` takes: `message_id`, `encoded_message_event_detail`, the
signature in `message_event_signature` (a `signatures::MessageEventSignature`
with `signing_public_key`, your signing public key as `get_public_keys`
returns it), and nothing else: the signed payload stays inside the SDK.
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

// 0.7.0
let action_signatures = serde_json::to_value(&prepared.action_signatures)?;
```

### Public key inputs name the identity key and its version

A `PublicKeyInput`, one participant a conversation key is encrypted to,
names its key `identity_public_key` and the key's version
`public_key_version`, as `SigningKeyEntry` does: the `public_key` the X API
returns for a user is their identity key. Build it with `new`, which takes
the user id, the key and its version in that order:

```rust
// 0.5.x
let input = PublicKeyInput {
    user_id: user_id.to_string(),
    public_key: identity_public_key.to_string(),
    key_version: public_key_version.to_string(),
};
let version = &input.key_version;

// 0.7.0
let input = PublicKeyInput::new(user_id, identity_public_key, public_key_version);
let version = &input.public_key_version;
```

### Participant keys take the key requests' names

A prepared change's participant keys carry the names the X API gives them in
every request that takes them (`POST /2/chat/conversations/{id}/keys`,
`/group` and `/{id}/members`, and `PUT /2/chat/conversations/{id}`):
`conversation_participant_keys`, each entry a `ConversationParticipantKey`
with `user_id`, `encrypted_conversation_key` and `public_key_version`, the
type a received key change uses too (see [Received participant keys take
the same names](#received-participant-keys-take-the-same-names)). Drop the
renaming and pass the keys through as returned:

```rust
// 0.5.x
let participant_keys: &[EncryptedKeyForRecipient] = &prepared.participant_keys;
let conversation_participant_keys: Vec<serde_json::Value> = participant_keys
    .iter()
    .map(|key| {
        serde_json::json!({
            "user_id": key.user_id,
            "encrypted_conversation_key": key.encrypted_key,
            "public_key_version": key.public_key_version,
        })
    })
    .collect();

// 0.7.0
let conversation_participant_keys: &[ConversationParticipantKey] = &prepared.conversation_participant_keys;
```

### Received participant keys take the same names

A decrypted `KeyChangeEvent` carries its participant keys under the names
Thrift's `ConversationKeyChangeEvent` gives them, the same names a prepared
change uses: `conversation_participant_keys`, each entry with `user_id`,
`encrypted_conversation_key` and `public_key_version`. Received and prepared
keys are one type, `ConversationParticipantKey`:

```rust
// 0.5.x
let key: &ParticipantKey = &received_key_change.participant_keys[0];
let encrypted = &key.encrypted_key;

// 0.7.0
let key: &ConversationParticipantKey = &received_key_change.conversation_participant_keys[0];
let encrypted = &key.encrypted_conversation_key;
```

### Deletes return a `PreparedAction`

`prepare_message_delete` returns a `PreparedAction` whose
`action_signatures` hold one entry, shaped as [Action signatures come
nested](#action-signatures-come-nested) shows. Read the action's
`message_id` from that entry, and serialize `action_signatures` as returned
(see [Deleting messages](#deleting-messages) for the request):

```rust
// 0.5.x
let deletion = chat.prepare_message_delete(&MessageDeleteParams::new(conversation_id, sequence_ids, false))?;
let message_id = deletion.message_id;

// 0.7.0
let deletion = chat.prepare_message_delete(&MessageDeleteParams::new(conversation_id, sequence_ids, false))?;
let message_id = deletion.action_signatures[0].message_id.clone();
```

### Decrypted events use the names the calls take

`Message` and `KeyChangeEvent` carry their conversation key version as
`conversation_key_version`, the name the X API's events and the Thrift
events give it, and the name the encrypt params take:

```rust
// 0.5.x
let message_version = message.key_version.as_deref();
let key_change_version = received_key_change.key_version.as_str();

// 0.7.0
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
of the message it edits as `target_message_id`, `None` for a v0 edit.

**Rename every read of `target_message_id` to `target_message_sequence_id`.
Don't keep `target_message_id`: in 0.7.0 it names a different value** (see
[`target_message_id` holds a different
value](#target_message_id-holds-a-different-value)).

```rust
// 0.5.x
if let MessageContent::Edit { target_message_id, new_text, .. } = &message.content {
    show_edit(target_message_id, new_text);
}
let deleted_sequence_ids = &deleted.message_ids;
let seen_until = receipt.seen_until_id.as_deref();

// 0.7.0
if let MessageContent::Edit { target_message_sequence_id, updated_text, .. } = &message.content {
    show_edit(target_message_sequence_id, updated_text);
}
let deleted_sequence_ids = &deleted.sequence_ids;
let seen_until = receipt.seen_until_sequence_id.as_deref();
```

A group create's `title`, and a title or description change's `new_title`
or `new_description`, is a `GroupText` rather than a `String` (see
[Creating a group](#creating-a-group)).

### Errors carry their kind

Every `SdkError` reports its `kind()`, an `ErrorKind` that names the failure
the same way in every binding: `InvalidInput`, `InvalidState`, `Parse`,
`Decryption`, `Verification`, `InvalidPin`, `Juicebox` or `Internal`.

A missing or invalid parameter fails with `SdkError::InvalidInput`, of kind
`InvalidInput`, whose message names the value, such as `Invalid sender_id
'user-1': pass a numeric user id (digits only)` or `too many attachments: at
most 10 per message`. That covers a key or signature that `verify`,
`verify_key_binding` or `matches_registered_key` can't decode, a
conversation key or key blob of the wrong length, and an empty
`public_keys`. `SdkError::InvalidState` is left for values the chat lacks,
such as a missing session identity, an empty key cache, or the Juicebox
config of a `Chat` made with `Chat::default()`. After a wrong PIN,
`guesses_remaining()` holds the attempts Juicebox reports left, `Some(0)`
once the stored keys are locked. Tell failures apart by kind; a `match` on
`ErrorKind` or `SdkError` takes a wildcard arm (see [Types are
`#[non_exhaustive]`](#types-are-non_exhaustive)):

```rust
// 0.5.x
let invalid_input = matches!(err, SdkError::InvalidState(_));
let guesses_left = match &err {
    SdkError::Juicebox(JuiceboxError::InvalidPin { guesses_remaining }) => *guesses_remaining,
    _ => None,
};

// 0.7.0
let invalid_input = err.kind() == ErrorKind::InvalidInput;
let guesses_left = err.guesses_remaining();
```

## 3. Runtime and behavior changes

Nothing reports these changes before the code runs: each one is a value the
SDK checks, a value with a new meaning, or an event handled differently.

### User ids are strings of digits

Every user id is a `String` of digits: the `SetIdentityParams` user id,
`sender_id`, `reply_to_sender_id`, the `user_id` of each `PublicKeyInput`
and `SigningKeyEntry`, and the ids of a group's members and admins
(`member_ids`, `admin_ids`, `new_member_ids`, `current_member_ids`,
`current_admin_ids`, `current_pending_member_ids` and `user_ids`). Each must
be a positive integer written without a sign or leading zeros; anything else
fails with `SdkError::InvalidInput` naming the field, such as `Invalid
sender_id 'user-1': pass a numeric user id (digits only)`.
`EncryptReplyParams::reply_to_sender_id` is an `Option<String>`:

```rust
// 0.5.x
let mut reply = EncryptReplyParams::new(conversation_id, "pong", event_b64);
reply.reply_to_sender_id = Some(4201);

// 0.7.0
let reply = EncryptReplyParams::new(conversation_id, "pong", event_b64).with_reply_to_sender_id("4201");
```

### Key versions are integers written as strings

Every key version is a non-negative integer written as a string of digits,
as the X API returns it: the signing-key version (in `SetIdentityParams`,
`ImportKeysParams`, a call's `signing_key_version` and each
`PublicKeyInput::public_key_version`) and `conversation_key_version`.
Anything else fails with `SdkError::InvalidInput` naming the field, such as
`Invalid signing_key_version 'v1': pass the key version as the X API returns
it, an integer in digits`. There's no code to change if you pass the
versions the X API returns.

### Entities, files, URL cards and posts are checked

The encrypt calls check what a message carries before they encrypt it, and
fail with `SdkError::InvalidInput` naming the value, where 0.5.x sent it:

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
  file. Give each file its name and the encrypted size
  `utils::encrypted_file_size` gives.
- A message that lists an empty media hash key, or one media hash key in
  two attachments, fails.
- A URL card with an empty `url`, and a post attachment with neither
  `rest_id` nor `post_url`, fail.

A Rust string's byte offsets are already UTF-8 offsets:

```rust
// 0.7.0
let text = "café @bob";
let start = text.find("@bob").ok_or("no mention")?;
let end = start + "@bob".len();
let params = EncryptMessageParams::new(conversation_id, text)
    .with_entities(vec![EntityDescriptor::new(i32::try_from(start)?, i32::try_from(end)?, "mention")]);
```

### `latest_version` comes from a verified key change

`result.conversation_keys.latest_version`, the version to encrypt with, is
the newest version whose key change verified, and it never moves back for
the chat's lifetime. A key change verifies only against its sender's
signing key, so give the chat every participant's signing keys, your own
included, before you decrypt. It's `None` until a key change verifies: a key
change the SDK can't verify still adds its key to `conversation_keys.keys`,
for decrypting, but never becomes the version you encrypt with. Where 0.5.x
returned the batch's highest version, 0.7.0 can return `None`: fetch the
missing signing keys or the conversation's key-change events and decrypt
again, rather than encrypting under the highest key in `keys`:

```rust
// 0.5.x
let result = chat.decrypt_events(&events, &signing_keys);
let version = result.conversation_keys.latest_version;

// 0.7.0
chat.set_signing_keys(&signing_keys);
let result = chat.decrypt_events(&DecryptEventsParams::new(events));
let Some(version) = result.conversation_keys.latest_version else {
    // No key change verified: fetch every participant's signing keys
    // (GET /2/users/{id}/public_keys) and the conversation's key changes
    // (meta.conversation_key_events of GET /2/chat/conversations/{id}/events),
    // then decrypt again.
    return Ok(());
};
```

### `target_message_id` holds a different value

**In 0.5.x a reaction's or edit's `target_message_id` held the target's
sequence id. In 0.7.0 that value is `target_message_sequence_id`, and
`target_message_id` holds the edited message's signed message id,
`Some` only on a v1 edit.** The compiler catches a pattern that binds the
reaction's field, but not code that serializes events and reads
`target_message_id` from the JSON: that code gets the wrong id, or none.
Rename every read, as [Decrypted events use the names the calls
take](#decrypted-events-use-the-names-the-calls-take) shows, and use
`target_message_id` only to match a v1 edit to the `message_id` you
deduplicate on.

### A prepared change's JSON leaves out its key

Nothing changes in Rust: `PreparedConversationChange` skips its
`conversation_key` when serialized, as in 0.5.x. Keep the key from the
struct; the request bodies take only its participant keys, key version and
action signatures.

### `sign` refuses data only the SDK signs

`sign` fails with `SdkError::InvalidInput` for a payload recipients would
verify as a signed event (a message, conversation-key change, group or
conversation-metadata change, delete or read receipt) and for a P-256
public key, whose signature by the signing key binds it as an identity key.
Sign only your own application data with `sign`; the SDK signs events
itself. Any other data signs as in 0.5.x:

```rust
// 0.7.0
let signature = match chat.sign(&data) {
    Ok(signature) => Some(signature),
    // The data reads as an event or a public key, which only the SDK signs.
    Err(err) if err.kind() == ErrorKind::InvalidInput => None,
    Err(err) => return Err(err.into()),
};
```

### Decrypt drops a removal's title and description re-encryptions

A member removal rotates the conversation key and re-encrypts the group's
title and description under the new key, marked as key-rotation
re-encryptions. They are the same text, not changes, so `decrypt_events`
and `decrypt_event` drop them under either `reject_unverified` setting, the
way they drop an unverified event: `decrypt_events` leaves each one out of
`events` and records it in `errors`, and `decrypt_event` fails with an
`SdkError::InvalidInput`: `GroupChange re-encrypts the group's title for a
key rotation (for_key_rotation), not a title change: decrypt does not return
it`. The removal itself (`GroupChange::MembersRemoved`), its key change,
avatar changes and every title or description change without the mark
decrypt as before. In 0.5.x, a removal by an X client arrived as a
`TitleChanged` carrying the group's unchanged title:

```rust
// 0.5.x
for item in &result.messages {
    if let Event::GroupChange(change) = &item.event {
        if let GroupChange::TitleChanged { new_title } = &change.change {
            show_title(&chat.decrypt(new_title, &keys[conversation_key_version])?);
        }
    }
}

// 0.7.0
let result = chat.decrypt_events(&DecryptEventsParams::new(events));
for item in &result.events {
    if let Event::GroupChange(change) = &item.event {
        if let GroupChange::TitleChanged { new_title, .. } = &change.change {
            match new_title {
                GroupText::Text { text, .. } => show_title(text),
                GroupText::Unavailable { raw, .. } => show_title(raw),
                _ => {}
            }
        }
    }
}
```

A loop over single events handles the error, as it handles an unverified
event's, and moves on to the next event:

```rust
// 0.7.0
for item in page["data"].as_array().into_iter().flatten() {
    let Some(event_b64) = item["encoded_event"].as_str() else { continue };
    match chat.decrypt_event(&DecryptEventParams::new(event_b64, keys.clone())) {
        Ok(event) => handle(&event),
        Err(err) => log_skipped(event_b64, &err),
    }
}
```

### An empty Juicebox config fails

Until a `Chat` has a Juicebox config, `setup`, `unlock`, `change_pin` and
`delete` fail with `SdkError::InvalidState`: `Invalid state: no Juicebox
config: pass the juicebox_config the X API returns when you create the chat,
or call update_config() first`, the error every binding gives.
`JuiceboxConfig::from_x_api_json` returns it for an empty or blank config
string, at once, rather than at the chat's first Juicebox call.

## 4. Group and receipt signing

Recipients on the default `reject_unverified` policy drop a read receipt or
group change that isn't signed, as 0.5.x recipients did: sign each one, or
recipients never see it. The sender comes from `set_identity`. Each prepare
call returns `action_signatures` shaped as [Action signatures come
nested](#action-signatures-come-nested) shows; serialize them into the
request as returned.

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
| Change screen capture | `prepare_screen_capture` | `PUT /2/chat/conversations/{id}/screen_capture` | `blocking` (`true` for `BlockingEnabled`, `false` for `BlockingDisabled`) and `blocking_action_signatures`, or `detection` and `detection_action_signatures` |

A group's `conversation_id` is the `g…` id that
`POST /2/chat/conversations/group/initialize` returns as
`data.conversation_id`.

### Deleting messages

`prepare_message_delete` returns the action's signature nested, as every
prepare call does: send `action_signatures` as returned, next to the
sequence ids and the delete action the params signed.

```rust
// 0.5.x
let deletion = chat.prepare_message_delete(&MessageDeleteParams::new(conversation_id, sequence_ids.clone(), true))?;
api.post(&format!("/2/chat/conversations/{path_id}/messages/delete"), &serde_json::json!({
    "sequence_ids": sequence_ids,
    "delete_message_action": "delete_for_all",
    "action_signatures": [{
        "message_id": deletion.message_id,
        "encoded_message_event_detail": deletion.encoded_message_event_detail,
        "message_event_signature": {
            "signature": deletion.signature,
            "signature_version": deletion.signature_version,
            "public_key_version": deletion.public_key_version,
            "signing_public_key": signing_public_key,
        },
    }],
}))?;

// 0.7.0
let deletion = chat.prepare_message_delete(&MessageDeleteParams::new(conversation_id, sequence_ids.clone(), true))?;
api.post(&format!("/2/chat/conversations/{path_id}/messages/delete"), &serde_json::json!({
    "sequence_ids": sequence_ids,
    "delete_message_action": "delete_for_all",
    "action_signatures": deletion.action_signatures,
}))?;
```

A recipient's `decrypt_event` returns the delete as a verified
`Event::MessageDeleted` with its `sequence_ids` and `delete_for_all`.

### Read receipts are signed

Sign a read receipt with `prepare_mark_conversation_read` and send the
`PreparedAction`'s `action_signatures` on
`POST /2/chat/conversations/{id}/read`. The call takes a
`MarkConversationReadParams` (the conversation id, the sequence id of the
newest event read, and a `seen_at_msec` that defaults to now) and returns a
`PreparedAction`, one entry. Without it the X API sends an unsigned
receipt, which recipients drop.

```rust
// 0.5.x
api.post(&format!("/2/chat/conversations/{path_id}/read"), &serde_json::json!({}))?;

// 0.7.0
let receipt = chat.prepare_mark_conversation_read(&MarkConversationReadParams::new(
    conversation_id,
    seen_until_sequence_id,
))?;
api.post(
    &format!("/2/chat/conversations/{path_id}/read"),
    &serde_json::json!({ "action_signatures": receipt.action_signatures }),
)?;
```

A recipient's `decrypt_event` returns a signed receipt as a verified
`Event::ReadReceipt`, its position in `seen_until_sequence_id`.

### Group changes are signed

Every group change below returns `action_signatures` for its request in
[The requests](#the-requests). A group's title and description travel
encrypted under the conversation key, and the SDK encrypts them: the
creates, member adds, removals and title and description changes take them
as plaintext and return the encrypted values to send. An avatar is an image
the app encrypts and uploads; its URL is signed as is.

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

// 0.7.0
let create = GroupCreateParams::new(public_keys, conversation_id, member_ids.clone(), admin_ids.clone())
    .with_title(title);
let prepared = chat.prepare_group_create(&create)?;
api.post("/2/chat/conversations/group", &serde_json::json!({
    "conversation_id": conversation_id,
    "group_members": member_ids,
    "group_admins": admin_ids,
    "group_name": prepared.encrypted_title,
    "conversation_key_version": prepared.conversation_key_version,
    "conversation_participant_keys": prepared.conversation_participant_keys,
    "action_signatures": prepared.action_signatures,
}))?;
if let Some(key) = &prepared.conversation_key {
    store_conversation_key(conversation_id, &prepared.conversation_key_version, key);
}
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
`group_description` the X API returns with a conversation open with
`decrypt`.

```rust
// 0.5.x
if let GroupChange::Created { title: Some(title), .. } = &group_change.change {
    show_title(&chat.decrypt(title, &keys[conversation_key_version])?);
}

// 0.7.0
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
Encrypt under the new key from here on, as [Removing
members](#removing-members) shows for a removal.

```rust
// 0.5.x
let mut add = GroupMembersChangeParams::new(public_keys, conversation_id, new_member_ids, member_ids, admin_ids, vec![]);
add.current_title = Some(title.to_string());
let prepared = chat.prepare_group_members_change(add)?;

// 0.7.0
let add = GroupMembersChangeParams::new(public_keys, conversation_id, new_member_ids.clone(), member_ids, admin_ids, vec![])
    .with_current_title(title)
    .with_current_description(description);
let prepared = chat.prepare_group_members_change(&add)?;
api.post(&format!("/2/chat/conversations/{path_id}/members"), &serde_json::json!({
    "user_ids": new_member_ids,
    "encrypted_title": prepared.encrypted_title,
    "conversation_key_version": prepared.conversation_key_version,
    "conversation_participant_keys": prepared.conversation_participant_keys,
    "action_signatures": prepared.action_signatures,
}))?;
if let Some(key) = &prepared.conversation_key {
    store_conversation_key(conversation_id, &prepared.conversation_key_version, key);
}
```

Passing a description makes the add sign at signature version 8, the first
version whose member-add payload covers one, and 0.5.x readers can't verify
a version-8 add. Until every app that reads your groups runs 0.7.0, leave
the description out, so the add signs at version 7 as in 0.5.x; the new
members can read the description once a description change sets it under the
new key.

The avatar isn't re-encrypted: `with_current_avatar_url` takes its media
URL, signed as is, and the image stays encrypted under the key it was
uploaded with, which the new members never receive. To keep the avatar
readable for them, encrypt the image under the key the add returns, upload
it, and send an [avatar change](#changing-the-avatar) naming the new key
version.

A recipient's `decrypt_event` returns the add as a verified
`GroupChange::MembersAdded` with `member_ids`, `current_member_ids` and
`current_admin_ids`.

### Removing members

`prepare_group_members_remove` removes `user_ids` and rotates the
conversation key, so the members removed don't receive the key the group
encrypts under next. `GroupMembersRemoveParams::new` takes:

- `public_keys`: the identity key of every member who stays, yours
  included, as `GET /2/users/{id}/public_keys` returns them. The SDK
  encrypts the new key to each member's newest key version; a member left
  out, you included, can't read what the group sends under the new key.
  The SDK doesn't check that the list is complete. A key for a member being
  removed is rejected.
- `conversation_id` and `user_ids`, the members to remove.

Pass the group's current title and description, as plaintext, with
`with_title` and `with_description`, each one the group has: the call
encrypts each under the new key and signs it as a key-rotation
re-encryption, which recipients' decrypt drops rather than shows as a
change. A rotation leaves the avatar alone: its image stays encrypted under
the key it was uploaded with, which the members who stay hold.

The result is a `PreparedConversationChange`: the new `conversation_key`
and `conversation_key_version`, `conversation_participant_keys` for the
members who stay, and `action_signatures` in request order: the removal, a
title change and a description change for the ones passed, then the
conversation-key change. The removal signs at signature version 11, which
0.5.x readers can't verify (see [Upgrade readers
first](#upgrade-readers-first)).

```rust
// 0.5.x
api.post(
    &format!("/2/chat/conversations/{path_id}/members/remove"),
    &serde_json::json!({ "user_ids": user_ids }),
)?;

// 0.7.0
let removal = GroupMembersRemoveParams::new(remaining_public_keys, conversation_id, user_ids.clone())
    .with_title(title)
    .with_description(description);
let prepared = chat.prepare_group_members_remove(&removal)?;
api.post(&format!("/2/chat/conversations/{path_id}/members/remove"), &serde_json::json!({
    "user_ids": user_ids,
    "action_signatures": prepared.action_signatures,
    "group_key_rotation_data": {
        "conversation_key_version": prepared.conversation_key_version,
        "conversation_participant_keys": prepared.conversation_participant_keys,
    },
}))?;
```

**Encrypt under the new key as soon as the request succeeds.** The removed
members hold the old key, so a message encrypted under it is one they can
read. The key cache (`set_cache_keys(true)`) adopts the new key only once
`decrypt_events` decrypts the removal's key change from the conversation's
events, and only if that key change verifies against your own signing key;
until then an encrypt call that omits the key resolves the old one. Store
the new key and version, and pass them to every encrypt and prepare call
until the cache holds them:

```rust
// 0.7.0
let key = prepared.conversation_key.as_ref().ok_or("no conversation key")?;
store_conversation_key(conversation_id, &prepared.conversation_key_version, key);
let payload = chat.encrypt_message(
    &EncryptMessageParams::new(conversation_id, "hello")
        .with_conversation_key(key.to_bytes(), &prepared.conversation_key_version),
)?;
```

The same holds after any call that rotates the key:
`prepare_conversation_key_change`, `prepare_group_create` and
`prepare_group_members_change`.

On the receiving side, `decrypt_events` returns the removal as a verified
`GroupChange::MembersRemoved` with its `member_ids`, and the key change as
an `Event::KeyChange` that adds the new key to `conversation_keys` and moves
`latest_version` to it once it verifies. The title and description
re-encryptions are in `errors`, not `events` (see [Decrypt drops a
removal's title and description
re-encryptions](#decrypt-drops-a-removals-title-and-description-re-encryptions)):

```rust
// 0.7.0
let result = chat.decrypt_events(&DecryptEventsParams::new(events));
for item in &result.events {
    if let Event::GroupChange(change) = &item.event {
        if let GroupChange::MembersRemoved { member_ids, .. } = &change.change {
            let removed = member_ids;
        }
    }
}
let version = result.conversation_keys.latest_version;
```

### Leaving a group

`prepare_group_leave` signs the sender's removal and does not rotate the
conversation key. `action_signatures` are the removal, at signature version
11 as a member removal's, then a `GroupAdminAddChange` when
`promote_admin_id` is set, then a `ConversationDeleteEvent`. It returns a
`PreparedAction`. Send it as a removal of your own id:

```rust
// 0.5.x
api.post(
    &format!("/2/chat/conversations/{path_id}/members/remove"),
    &serde_json::json!({ "user_ids": [my_user_id] }),
)?;

// 0.7.0
let leave = GroupLeaveParams::new(conversation_id).with_promote_admin_id(promote_admin_id);
let left = chat.prepare_group_leave(&leave)?;
api.post(&format!("/2/chat/conversations/{path_id}/members/remove"), &serde_json::json!({
    "user_ids": [my_user_id],
    "action_signatures": left.action_signatures,
}))?;
```

### Changing the title

`prepare_group_title_change` takes the new title as plaintext, encrypts it
under the conversation key and signs it. Like `EncryptMessageParams`,
`GroupTitleChangeParams` takes the key and its version with
`with_conversation_key`, or resolves both from the key cache when it's not
called. The result is a `PreparedGroupMetadataChange`: the
`encrypted_value` the request sends as `group_name`, the
`conversation_key_version` it's encrypted under, and the
`action_signatures` to send with it.

```rust
// 0.5.x
api.put(&format!("/2/chat/conversations/{path_id}"), &serde_json::json!({
    "group_name": chat.encrypt(title, &keys[conversation_key_version])?,
    "conversation_key_version": conversation_key_version,
    "modified_fields": ["group_name"],
}))?;

// 0.7.0
let prepared = chat.prepare_group_title_change(&GroupTitleChangeParams::new(conversation_id, title))?;
api.put(&format!("/2/chat/conversations/{path_id}"), &serde_json::json!({
    "group_name": prepared.encrypted_value,
    "conversation_key_version": prepared.conversation_key_version,
    "modified_fields": ["group_name"],
    "action_signatures": prepared.action_signatures,
}))?;
```

`decrypt_event` returns a received title change decrypted: the `new_title`
of `GroupChange::TitleChanged` is a `GroupText`, as a create's `title` is.
It decrypts with the key for the version the change names, from the call's
key map or the key cache. Without that key, or when the value isn't
ciphertext under it, as for a plaintext title an app signed with a key
version, it is `Unavailable` with the value as carried, and the event still
decrypts. A removal's re-encrypted title never arrives as a `TitleChanged`.

```rust
// 0.5.x
if let GroupChange::TitleChanged { new_title } = &group_change.change {
    show_title(&chat.decrypt(new_title, &keys[conversation_key_version])?);
}

// 0.7.0
if let GroupChange::TitleChanged { new_title, .. } = &group_change.change {
    match new_title {
        GroupText::Text { text, .. } => show_title(text),
        GroupText::Unavailable { raw, .. } => show_title(raw),
        _ => {}
    }
}
```

### Changing the description

`prepare_group_description_change` takes the new description as plaintext
and returns a `PreparedGroupMetadataChange`, as the title change does; the
request sends its `encrypted_value` as `group_description`.

```rust
// 0.5.x
api.put(&format!("/2/chat/conversations/{path_id}"), &serde_json::json!({
    "group_description": chat.encrypt(description, &keys[conversation_key_version])?,
    "conversation_key_version": conversation_key_version,
    "modified_fields": ["group_description"],
}))?;

// 0.7.0
let prepared = chat.prepare_group_description_change(&GroupDescriptionChangeParams::new(
    conversation_id,
    description,
))?;
api.put(&format!("/2/chat/conversations/{path_id}"), &serde_json::json!({
    "group_description": prepared.encrypted_value,
    "conversation_key_version": prepared.conversation_key_version,
    "modified_fields": ["group_description"],
    "action_signatures": prepared.action_signatures,
}))?;
```

A received description change is a `GroupChange::DescriptionChanged`
holding `new_description` as a `GroupText`; read it as a title change's
`new_title`. A removal's re-encrypted description never arrives as one:

```rust
// 0.7.0
if let GroupChange::DescriptionChanged { new_description, .. } = &group_change.change {
    match new_description {
        GroupText::Text { text, .. } => show_description(text),
        GroupText::Unavailable { raw, .. } => show_description(raw),
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
api.put(&format!("/2/chat/conversations/{path_id}"), &serde_json::json!({
    "group_avatar_url": chat.encrypt(avatar_url, &keys[conversation_key_version])?,
    "conversation_key_version": conversation_key_version,
    "modified_fields": ["group_avatar_url"],
}))?;

// 0.7.0
let prepared = chat.prepare_group_avatar_change(&GroupAvatarChangeParams::new(
    conversation_id,
    avatar_url,
    conversation_key_version,
))?;
api.put(&format!("/2/chat/conversations/{path_id}"), &serde_json::json!({
    "group_avatar_url": avatar_url,
    "conversation_key_version": conversation_key_version,
    "modified_fields": ["group_avatar_url"],
    "action_signatures": prepared.action_signatures,
}))?;
```

A received `GroupChange::AvatarChanged` holds `new_avatar_url` as sent and
its `conversation_key_version`: download the image and decrypt it with the
key for that version.

```rust
// 0.7.0
if let GroupChange::AvatarChanged { new_avatar_url, conversation_key_version, .. } = &group_change.change {
    show_avatar(new_avatar_url, conversation_key_version.as_deref());
}
```

### Admins, invites, join requests, message TTL and screen capture

Each of these calls returns a `PreparedAction` with one signature, at
signature version 7, for the request [The requests](#the-requests) names.
0.5.x apps sent these requests without signatures; recipients drop them
unsigned. A recipient's `decrypt_event` returns admin, invite and join
changes as verified `GroupChange` events (`AdminsAdded`, `AdminsRemoved`,
`InviteEnabled`, `InviteDisabled`, `JoinRequested`, `JoinRejected`) and TTL
and screen-capture changes as verified `Event::SettingsChange` events.

```rust
// 0.5.x
api.post(
    &format!("/2/chat/conversations/{path_id}/admins"),
    &serde_json::json!({ "user_ids": user_ids }),
)?;

// 0.7.0
let added = chat.prepare_group_admins_add(&GroupAdminsAddParams::new(conversation_id, user_ids.clone()))?;
api.post(&format!("/2/chat/conversations/{path_id}/admins"), &serde_json::json!({
    "user_ids": user_ids, "action_signatures": added.action_signatures,
}))?;
let removed = chat.prepare_group_admins_remove(&GroupAdminsRemoveParams::new(conversation_id, user_ids.clone()))?;
api.post(&format!("/2/chat/conversations/{path_id}/admins/remove"), &serde_json::json!({
    "user_ids": user_ids, "action_signatures": removed.action_signatures,
}))?;
```

An invite signs its URL, its expiry and its affiliate; an omitted
`expires_at_msec` or `affiliate_id` signs `null`. The request sends the
expiry as `validity_expiry_timestamp_msec`, and only with the same value the
params signed:

```rust
// 0.7.0
let mut enable = GroupInviteEnableParams::new(conversation_id, invite_url);
enable.expires_at_msec = Some(expires_at_msec);
let invite = chat.prepare_group_invite_enable(&enable)?;
api.post(&format!("/2/chat/conversations/{path_id}/invite"), &serde_json::json!({
    "invite_url": invite_url,
    "validity_expiry_timestamp_msec": expires_at_msec.to_string(),
    "action_signatures": invite.action_signatures,
}))?;
let disabled = chat.prepare_group_invite_disable(&GroupInviteDisableParams::new(conversation_id))?;
api.delete(
    &format!("/2/chat/conversations/{path_id}/invite"),
    &serde_json::json!({ "action_signatures": disabled.action_signatures }),
)?;
```

A join request signs the requesting user, who defaults to the sender; the
invite token travels in the request but not in the signature:

```rust
// 0.7.0
let request = chat.prepare_group_join_request(&GroupJoinRequestParams::new(conversation_id))?;
api.post(&format!("/2/chat/conversations/{path_id}/join_requests"), &serde_json::json!({
    "token": invite_token, "action_signatures": request.action_signatures,
}))?;
let rejected = chat.prepare_group_join_reject(&GroupJoinRejectParams::new(conversation_id, user_ids.clone()))?;
api.post(&format!("/2/chat/conversations/{path_id}/join_requests/reject"), &serde_json::json!({
    "user_ids": user_ids, "action_signatures": rejected.action_signatures,
}))?;
```

A TTL change signs `ttl_msec` only; a negative one is rejected:

```rust
// 0.7.0
let ttl = chat.prepare_message_ttl_change(&MessageTtlChangeParams::new(conversation_id, ttl_msec))?;
api.put(&format!("/2/chat/conversations/{path_id}/message_ttl"), &serde_json::json!({
    "message_ttl_ms": ttl_msec.to_string(), "action_signatures": ttl.action_signatures,
}))?;
let cleared = chat.prepare_message_ttl_remove(&MessageTtlRemoveParams::new(conversation_id))?;
api.delete(
    &format!("/2/chat/conversations/{path_id}/message_ttl"),
    &serde_json::json!({ "action_signatures": cleared.action_signatures }),
)?;
```

A screen-capture change is one of `ScreenCaptureChange::BlockingEnabled`,
`BlockingDisabled`, `DetectionEnabled` or `DetectionDisabled`. The request
names its signatures after the setting, `blocking_action_signatures` or
`detection_action_signatures`, not `action_signatures`:

```rust
// 0.7.0
let capture = chat.prepare_screen_capture(&ScreenCaptureParams::new(
    conversation_id,
    ScreenCaptureChange::BlockingEnabled,
))?;
api.put(&format!("/2/chat/conversations/{path_id}/screen_capture"), &serde_json::json!({
    "blocking": true, "blocking_action_signatures": capture.action_signatures,
}))?;
```

## 5. Verify

### Build

Run `cargo build` and `cargo test`. With `-D warnings` (or
`cargo clippy -- -D warnings`), a `mut` that `set_reject_unverified` or
`update_config` no longer needs shows up too.

### Find the 0.5.x names

Search the app for the names in the symbol index's 0.5.x column. Each hit is
a line to change, unless it is your own code that shares the name:

```sh
grep -rnE "encrypt_stream|decrypt_stream|stream_(en|de)cryptor|Stream(En|De)cryptor|encrypted_stream_size|import_keys_with_version|generate_keypairs_with_version|DecryptedMessage|EncryptedKeyForRecipient|\bParticipantKey\b|\.encrypt\(|encrypted_content|encoded_event_signature|generate_version|new_text|message_ids|seen_until_id|\.messages\b|\.participant_keys\b|\.encrypted_key\b|\.key_version\b|\bkey_version:" --include='*.rs' .
grep -rn "target_message_id" --include='*.rs' .
```

Every `target_message_id` the second search finds should read a v1 edit's
signed message id; rename the rest to `target_message_sequence_id`. The
compiler reports the rest of the index once the dependency is 0.7.0.

### Run a round trip

This round trip runs offline, with two chats standing in for two users. It
registers both, starts a conversation, sends a message and decrypts it with
`reject_unverified` on, the default, so the signature has to verify:

```rust
// 0.7.0
let alice = ChatCore::new();
let bob = ChatCore::new();
let alice_keys = alice.generate_keypairs()?.public_key;
let bob_keys = bob.generate_keypairs()?.public_key;
alice.set_identity(&SetIdentityParams::new("1001", "1"))?;
bob.set_identity(&SetIdentityParams::new("1002", "1"))?;

let change = alice.prepare_conversation_key_change(&ConversationKeyChangeParams::new(vec![
    PublicKeyInput::new("1001", &alice_keys.public_key, "1"),
    PublicKeyInput::new("1002", &bob_keys.public_key, "1"),
]))?;
let key = change.conversation_key.as_ref().ok_or("no conversation key")?;
let payload = alice.encrypt_message(
    &EncryptMessageParams::new(&change.conversation_id, "hello")
        .with_conversation_key(key.to_bytes(), &change.conversation_key_version),
)?;

let bob_entry = change
    .conversation_participant_keys
    .iter()
    .find(|entry| entry.user_id == "1002")
    .ok_or("no key for bob")?;
let bob_key = bob.decrypt_conversation_key(&bob_entry.encrypted_conversation_key)?;
let alice_signing_key = SigningKeyEntry::new(
    "1001",
    "1",
    &alice_keys.signing_public_key,
    &alice_keys.public_key,
    &alice_keys.identity_public_key_signature,
);
let event = bob.decrypt_event(
    &DecryptEventParams::new(
        payload.event_b64.clone(),
        HashMap::from([(change.conversation_key_version.clone(), bob_key)]),
    )
    .with_signing_keys(vec![alice_signing_key]),
)?;
let Event::Message(message) = event else {
    return Err("expected a message".into());
};
assert!(message.verified);
assert_eq!(message.text(), Some("hello"));
assert!(["7", "10"].contains(&payload.signature_info.signature_version.as_str()));
assert!(payload.xdk_version.starts_with("0.7."));
```

`signature_version` is `"7"` for a v0 send and `"10"` for v1, as the
`v1_send` switch decides. `xdk_version` is the version of `chat-xdk-core`
that built the send, a 0.7 release, which the X API receives with each
send.

Then run the same flows against a test conversation on the X API: send a
text, a file, a reply, an edit and a delete, mark the conversation read,
and create a group, add a member and remove one. Fetch the conversation's
events with `GET /2/chat/conversations/{id}/events`, pass `data[].encoded_event`
and `meta.conversation_key_events` to `decrypt_events` with every
participant's signing keys, and check that every event in `events` has
`verified` set and that `errors` holds only the removal's title and
description re-encryptions.
