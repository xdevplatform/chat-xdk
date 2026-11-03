# Migrating C ABI callers to chat-xdk 0.7.2

This page moves code that calls the chat-xdk C ABI directly, written for
0.5.x (0.5.0, 0.5.1 or 0.5.2), to 0.7.2. The ABI is declared in
[`go/chatxdk/include/chat_xdk.h`](../../go/chatxdk/include/chat_xdk.h), and
the native libraries in the Go module and the .NET and JVM packages export
the same functions. Work through the page top to bottom: [Before you
start](#0-before-you-start) sets up the upgrade, the [symbol
index](#1-symbol-index) maps every 0.5.x prototype and document field to its
0.7.2 form, [Compile-time changes](#2-compile-time-changes) and [Runtime
changes](#3-runtime-and-behavior-changes) show each line to change, [Group
and receipt signing](#4-group-and-receipt-signing) gives every signed
request, and [Verify](#5-verify) checks the result. [Why 0.7.2
changes](why.md) explains each change, and the [index](README.md) lists the
language bindings' pages. [API.md](../API.md) documents every call.

## Checklist

Each item is tagged with what it takes: `[rollout]` is a deployment step,
`[compile]` a changed prototype, which the compiler reports, `[runtime]` a
changed document or value, which only a call reports, and `[new]` a 0.7.2
call to adopt.

- [ ] `[rollout]` [Install 0.7.2: swap the header and the library](#install-072)
- [ ] `[rollout]` [Upgrade every app that reads your conversations first](#upgrade-readers-first)
- [ ] `[rollout]` [Hand a chat the X API's feature switches to send v1](#the-feature-switch-request)
- [ ] `[rollout]` [Check the ABI version](#check-the-abi-version)
- [ ] `[compile]` [Read every result from an `FfiResult`, booleans as `true` or `false`](#every-call-returns-an-ffiresult)
- [ ] `[compile]` [Create the chat with its Juicebox config, define `CHAT_XDK_JUICEBOX`, and pass PINs as bytes](#keys-stored-in-juicebox)
- [ ] `[runtime]` [Register keys with the public key only](#register-keys-with-the-public-key-only)
- [ ] `[compile]` [Set the identity with a params document](#set-the-identity-with-a-params-document)
- [ ] `[compile]` [Import keys with a params document](#import-keys-with-a-params-document)
- [ ] `[compile]` [Decrypt with params documents, and read a batch's `events`](#decrypt-with-params-documents)
- [ ] `[runtime]` [Read the send payload under the send request's field names and send `xdk_version`](#the-send-payload-takes-the-send-requests-field-names)
- [ ] `[compile]` [Build a message before you encrypt its files](#encrypt-a-file-from-its-message)
- [ ] `[compile]` [Decrypt a file with the event of its message](#decrypt-a-file-with-its-messages-event)
- [ ] `[compile]` [Encrypt a file no message carries, such as a group avatar, with `chat_xdk_encrypt_file_with_key`](#encrypt-a-file-under-a-key-you-hold)
- [ ] `[compile]` [Use the file encryptor and decryptor for large files](#encrypt-and-decrypt-large-files-in-chunks)
- [ ] `[runtime]` [Pass action signatures through as returned](#action-signatures-come-nested)
- [ ] `[runtime]` [Name a public key's fields `identity_public_key` and `public_key_version`](#public-key-inputs-name-the-identity-key-and-its-version)
- [ ] `[runtime]` [Pass participant keys through as returned](#participant-keys-take-the-key-requests-names)
- [ ] `[runtime]` [Read received participant keys under the same names](#received-participant-keys-take-the-same-names)
- [ ] `[runtime]` [Read a delete's signature from its `action_signatures`](#deletes-return-action_signatures)
- [ ] `[runtime]` [Read decrypted events under the names the calls take](#decrypted-events-use-the-names-the-calls-take)
- [ ] `[runtime]` [Read errors as documents with a `kind`](#errors-carry-their-kind)
- [ ] `[runtime]` [Pass user ids and key versions as strings of digits](#user-ids-and-key-versions-are-strings-of-digits)
- [ ] `[runtime]` [Pass entities, files, URL cards and posts the SDK accepts](#entities-files-url-cards-and-posts-are-checked)
- [ ] `[runtime]` [Store every participant's signing keys, and handle a `null` `latest_version`](#latest_version-comes-from-a-verified-key-change)
- [ ] `[runtime]` [Rename every read of `target_message_id` to `target_message_sequence_id`](#target_message_id-holds-a-different-value)
- [ ] `[runtime]` [Reply with `reply_to_event`, whose preview recipients check exactly](#a-reply-preview-quotes-its-message-exactly)
- [ ] `[runtime]` [Keep a prepared change's key from its JSON](#a-prepared-changes-json-keeps-its-key)
- [ ] `[runtime]` [Sign only your own data with `chat_xdk_sign`](#chat_xdk_sign-refuses-data-only-the-sdk-signs)
- [ ] `[runtime]` [Skip the events decrypt drops](#decrypt-drops-a-removals-title-and-description-re-encryptions)
- [ ] `[runtime]` [Check for keys before `chat_xdk_export_keys`](#chat_xdk_export_keys-fails-without-keys)
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
under `// 0.5.x`, and then as 0.7.2 code writes them, under `// 0.7.2`. A
snippet with only a `// 0.7.2` half shows code 0.7.2 adds. CI compiles the
0.7.2 half of every snippet on this page with `gcc` against the 0.7.2
`chat_xdk.h`, and passes every params document a 0.7.2 half shows to its
call in the 0.7.2 library, failing on a document the library can't parse
([`scripts/check_doc_snippets.py`](../../scripts/check_doc_snippets.py)).

`chat` is a `struct ChatHandle *` with your keys loaded. `take(r)` stands
for your error handling: it returns `r.data`, which you free with
`chat_xdk_free_string`, and handles `r.error`. The comment directly above a
call shows, as JSON, the params document the call takes, with `"..."`
standing for your values: the `*_json` variable the call passes holds that
document, which your code builds with its JSON library. Other `*_json` and
`*_b64` names are documents and base64 strings your code holds, and
`prepared` is the document a prepare call returned. `api_post(path, body_json)`, `api_put(path, body_json)` and
`api_delete(path, body_json)` stand for your HTTP client: each sends the
body, the JSON document the comment above it shows, to `https://api.x.com`
+ `path` with your user access token, and returns the response body; a
`<prepared.action_signatures>` in a body stands for that field of a result,
copied as is. A path takes a group's `g…` id as is, and a one-to-one's in
its hyphen form, `1001-1002` for `1001:1002`. `json_get(json, path)` stands
for your JSON library's lookup of the value at `path`, object keys and
array indices joined with dots: a string's contents, or a number or boolean
as JSON writes it, as a copy you free, or `NULL` for a missing or `null`
value. `http_get(url, timeout_ms, max_bytes, &body, &body_len)` stands for
your HTTP client's anonymous GET: it returns the response's status, or 0
when no response arrived, and sets `body` to a `malloc`ed buffer holding at
most `max_bytes` of the response's body and `body_len` to its length.
`handle(event_json)` stands for your code that handles a decrypted event,
`log_skipped(event_b64, error_json)` for your code that logs an event it
skips, and `store_conversation_key(conversation_id, prepared_json)` for
your code that stores the key a prepared change returns. `keys` and
`keys_len` are your saved private keys, `pin` and `pin_len` the PIN's
bytes, `data` and `data_len` bytes to sign, and `juicebox_config_json` the
Juicebox config the X API returns. The snippets leave out the frees.

The params documents use the snake_case field names of the params types in
[API.md](../API.md), with byte fields (`file`, `encrypted`, `key`,
`conversation_key` and the values of `conversation_keys`) as base64 strings
and entities as `[start, end, "type"]` arrays. A document may carry fields
a call doesn't take, which it ignores, but a missing required field or a
value of the wrong JSON type fails with an `invalid_input` error such as
``Invalid params JSON: missing field `identity_public_key` ``.

## 0. Before you start

### Install 0.7.2

Swap your copy of `chat_xdk.h` for the 0.7.2 header,
`go/chatxdk/include/chat_xdk.h` in the 0.7.2 release, and link the 0.7.2
library. Its name differs from the 0.5.x library's (see the [symbol
index](#1-symbol-index)), so change the name your build links or loads:

- `libchat_xdk_ffi.a`, the static library the Go module carries under
  `go/chatxdk/libs/<os>_<arch>/`;
- or `chat_xdk_ffi` (`libchat_xdk_ffi.so`, `libchat_xdk_ffi.dylib`,
  `chat_xdk_ffi.dll`), the shared library the .NET package and the JVM jar
  carry.

`cargo build -p chat-xdk-ffi --release` builds both from the 0.7.2 source.
The libraries are built with Juicebox, and the header declares the Juicebox
functions only when `CHAT_XDK_JUICEBOX` is defined, so define it to call
them (see [Keys stored in Juicebox](#keys-stored-in-juicebox)). On Linux:

```sh
cc -DCHAT_XDK_JUICEBOX -I go/chatxdk/include app.c \
  go/chatxdk/libs/linux_amd64/libchat_xdk_ffi.a -lm -ldl -lpthread
```

On macOS, link `-framework Security -framework CoreFoundation -framework
SystemConfiguration -lresolv` in place of `-lm -ldl -lpthread`. Every app
that shares conversations with yours reads the formats 0.7.2 sends only
once it runs a 0.7 release too, so plan the rollout below before you deploy.

### Upgrade readers first

0.7.2 sends each message, reply, reaction and edit in one of two formats. v0
is the format 0.5.x sends. v1 encrypts each message under its own key,
derived from the conversation key, the sender and the message id, and signs
it at signature version 10. A chat sends v1 while the X API's `v1_send`
feature switch is on for it, and v0 otherwise (see [The feature-switch
request](#the-feature-switch-request)). While a chat sends v1, its key
changes, group changes, deletes and read receipts sign at version 10 too, as
X clients' do; while it sends v0 they sign at version 7, as in 0.5.x, apart
from a member add that carries a description, which signs at version 8. A
conversation-key change never signs below the highest version of a key
change the chat has signed or verified in that conversation, so while it
sends v0 it can sign one above 7, which 0.5.x readers can't verify. The chat
holds that floor in memory, so after a restart decrypt a conversation's key
changes again before you change its key.

0.5.x rejects each of these as a signature verification failure, so upgrade
every app that reads your conversations to 0.7.2 before:

- any of your senders can send v1, that is, before you hand your chats a
  `v1_send` switch that is on;
- you pass a description to
  [`chat_xdk_prepare_group_members_change`](#adding-members).

0.7.2 reads both formats, including v1 reply previews, edits and files.
There's no code to change: to see which format a send used, read the send
payload's `signature_info.signature_version`, `"7"` for v0 and `"10"` for
v1.

### The feature-switch request

The language bindings read the X API's feature switches with one anonymous
request, `GET https://api.x.com/2/chat/features`, when a chat is created,
again once `chat_xdk_set_identity` gives it a sender, and again every 5
minutes, and retry it when it fails. The C ABI never makes the request: a
chat sends v0 until you make it and hand the answer to
`chat_xdk_set_feature_switches`. Make the request once you have called
`chat_xdk_set_identity`, as the header's constants say: GET the URL
`chat_xdk_feature_switches_url` returns, `CHAT_XDK_FEATURES_ENDPOINT` with
the sender's bucket, the last four digits of the user id, without
credentials, within `CHAT_XDK_FEATURES_TIMEOUT_MS` milliseconds, reading at
most one byte past `CHAT_XDK_FEATURES_MAX_BODY`. Pass its status, 0 when no
response arrived, and the bytes of the body you read:

```c
// 0.7.2
char *url = take(chat_xdk_feature_switches_url(chat));
uint8_t *body = NULL;
size_t body_len = 0;
int32_t status = http_get(url, CHAT_XDK_FEATURES_TIMEOUT_MS, CHAT_XDK_FEATURES_MAX_BODY + 1,
                          &body, &body_len);
take(chat_xdk_set_feature_switches(chat, status, body, body_len));
free(body);
chat_xdk_free_string(url);
```

Make it again every `CHAT_XDK_FEATURES_REFRESH_MS` milliseconds (5
minutes), so a change at the X API reaches the running chat. Each answer
whose status is 200 and whose body is a `{"features": {...}}` object no
larger than `CHAT_XDK_FEATURES_MAX_BODY` replaces the one before. Any other
answer changes nothing, so retry a request that fails, as the bindings retry
theirs: 1 second later, then after twice the previous wait, at most 5
minutes apart. A chat that never gets an answer keeps sending v0. Without
the call there's no code to change, and the chat sends v0.

### Check the ABI version

The header defines `CHAT_XDK_ABI_VERSION`, the version of the functions and
the shapes of their arguments and results, and `chat_xdk_abi_version()`
returns the library's. Some functions keep their 0.5.x names but take or
return different values, so compare the two before the first call: a
header and a library of different versions don't match.

```c
// 0.7.2
if (chat_xdk_abi_version() != CHAT_XDK_ABI_VERSION) abort();
```

## 1. Symbol index

Every 0.5.x prototype and document field that changes, with its 0.7.2 form
and the section that shows the change. A function or field not listed here
keeps its 0.5.x form. The compiler reports each changed prototype; search
your code for each document field in the first column, since only a call
reports those. [Verify](#5-verify) gives the search as one command.

| 0.5.x | 0.7.2 | Section |
|---|---|---|
| `libchat_xdk_go.a`, `chat_xdk_dotnet` | `libchat_xdk_ffi.a`, `chat_xdk_ffi` | [Install](#install-072) |
| `struct ChatHandle *chat_xdk_new(void)` | `struct FfiResult chat_xdk_new(const char *juicebox_config_json, struct ChatHandle **out_chat)` | [Juicebox](#keys-stored-in-juicebox) |
| `chat_xdk_setup(handle, const char *pin, const char *config_json)`, `chat_xdk_unlock(handle, const char *pin, const char *config_json)` | `chat_xdk_setup(handle, const uint8_t *pin, uintptr_t pin_len)`, `chat_xdk_unlock(handle, const uint8_t *pin, uintptr_t pin_len)` | [Juicebox](#keys-stored-in-juicebox) |
| `chat_xdk_change_pin(handle, const char *old_pin, const char *new_pin)` | `chat_xdk_change_pin(handle, const uint8_t *old_pin, uintptr_t old_pin_len, const uint8_t *new_pin, uintptr_t new_pin_len)` | [Juicebox](#keys-stored-in-juicebox) |
| `chat_xdk_update_config`, `chat_xdk_delete`, `chat_xdk_setup`, `chat_xdk_unlock`, `chat_xdk_change_pin` on a `struct ChatHandle *`, always declared | The same on a `const struct ChatHandle *`, declared when `CHAT_XDK_JUICEBOX` is defined | [Juicebox](#keys-stored-in-juicebox) |
| `int32_t chat_xdk_is_unlocked`, `chat_xdk_has_identity_key`, `chat_xdk_matches_registered_key`, `chat_xdk_verify`, `chat_xdk_verify_key_binding` | `struct FfiResult`, `data` `"true"` or `"false"` | [FfiResult](#every-call-returns-an-ffiresult) |
| `void chat_xdk_lock`, `chat_xdk_set_cache_keys`, `chat_xdk_set_reject_unverified` | `struct FfiResult`, no `data` | [FfiResult](#every-call-returns-an-ffiresult) |
| Registration document's `version`, `generate_version` | Removed: the registration request returns the version (`public_key_version`) | [Registration](#register-keys-with-the-public-key-only) |
| `chat_xdk_set_identity(handle, user_id, signing_key_version)` | `chat_xdk_set_identity(handle, params_json)` | [Identity](#set-the-identity-with-a-params-document) |
| `chat_xdk_import_keys(handle, keys_b64)`, `chat_xdk_import_keys_with_version(handle, keys, keys_len, version)` | `chat_xdk_import_keys(handle, keys, keys_len, params_json)` | [Import](#import-keys-with-a-params-document) |
| `chat_xdk_export_keys` returning `NULL` data without keys | An `invalid_state` error | [Export](#chat_xdk_export_keys-fails-without-keys) |
| `chat_xdk_decrypt_events(handle, events_json, signing_keys_json)` | `chat_xdk_decrypt_events(handle, params_json)` | [Decrypt](#decrypt-with-params-documents) |
| A batch result's `messages` | `events` | [Decrypt](#decrypt-with-params-documents) |
| `chat_xdk_decrypt_event(handle, event_b64, conversation_keys_json, signing_keys_json)` | `chat_xdk_decrypt_event(handle, params_json)` | [Decrypt](#decrypt-with-params-documents) |
| Send payload's `encrypted_content`, `encoded_event_signature` | `encoded_message_create_event`, `encoded_message_event_signature` | [Send payload](#the-send-payload-takes-the-send-requests-field-names) |
| `chat_xdk_encrypt_stream`, `chat_xdk_decrypt_stream`, a message's file | `chat_xdk_encrypt_file`, `chat_xdk_decrypt_file` | [Files](#encrypt-a-file-from-its-message) |
| `chat_xdk_encrypt_stream`, `chat_xdk_decrypt_stream`, any other file, such as a group avatar | `chat_xdk_encrypt_file_with_key`, `chat_xdk_decrypt_file_with_key` | [Files under a key](#encrypt-a-file-under-a-key-you-hold) |
| `chat_xdk_stream_encryptor_new`, `_push`, `_finish`, `_free`, `chat_xdk_stream_decryptor_*`, `StreamEncryptorHandle`, `StreamDecryptorHandle`, a message's file | `chat_xdk_file_encryptor_new(handle, params_json, &encryptor)`, `_push`, `_finish`, `_free`, `chat_xdk_file_decryptor_*`, `FileEncryptorHandle`, `FileDecryptorHandle` | [Large files](#encrypt-and-decrypt-large-files-in-chunks) |
| `chat_xdk_stream_encryptor_*`, `chat_xdk_stream_decryptor_*`, any other file | `chat_xdk_encrypt_file_with_key` and `chat_xdk_decrypt_file_with_key` over the whole file | [Large files](#encrypt-and-decrypt-large-files-in-chunks) |
| `chat_xdk_encrypted_stream_size` | `chat_xdk_encrypted_file_size` | [Files](#encrypt-a-file-from-its-message) |
| `chat_xdk_encrypt` | Removed: titles and descriptions go through `chat_xdk_prepare_group_title_change`, `chat_xdk_prepare_group_description_change` and the group creates and member adds; avatar URLs aren't encrypted; files go through `chat_xdk_encrypt_file` or `chat_xdk_encrypt_file_with_key` | [Changing the title](#changing-the-title) |
| Action signature's `signature`, `signature_version`, `public_key_version`, `signature_payload` beside `message_id` | Nested under `message_event_signature`, with `signing_public_key`; the signed payload stays inside the SDK | [Action signatures](#action-signatures-come-nested) |
| Public key's `public_key`, `key_version` | `identity_public_key`, `public_key_version` | [Public keys](#public-key-inputs-name-the-identity-key-and-its-version) |
| Prepared change's `participant_keys`, `encrypted_key` | `conversation_participant_keys`, `encrypted_conversation_key` | [Participant keys](#participant-keys-take-the-key-requests-names) |
| Key change's `participant_keys`, `encrypted_key` | `conversation_participant_keys`, `encrypted_conversation_key` | [Received keys](#received-participant-keys-take-the-same-names) |
| `chat_xdk_prepare_message_delete` returning one action signature | `{"action_signatures": [...]}`, one entry | [Deletes](#deletes-return-action_signatures) |
| Event's `key_version` | `conversation_key_version` | [Event names](#decrypted-events-use-the-names-the-calls-take) |
| Event's `target_message_id`, `new_text`, `message_ids`, `seen_until_id` | `target_message_sequence_id`, `updated_text`, `sequence_ids`, `seen_until_sequence_id` | [Event names](#decrypted-events-use-the-names-the-calls-take) |
| Group title and description strings (`title`, `new_title`) | `GroupText` objects | [Creating a group](#creating-a-group) |
| Group create's `avatar_url` | Removed: set the avatar with `chat_xdk_prepare_group_avatar_change` | [Creating a group](#creating-a-group) |
| `reply_to_sender_id` as a JSON number | A JSON string | [User ids](#user-ids-and-key-versions-are-strings-of-digits) |
| `error` as a string | `error` as a document: `kind`, `message`, `guesses_remaining` | [Errors](#errors-carry-their-kind) |

The 0.7.2 header adds `chat_xdk_abi_version`, `chat_xdk_feature_switches_url`,
`chat_xdk_set_feature_switches` and the prepare calls for group changes and
read receipts; the [requests](#the-requests) table lists the prepare calls.

## 2. Compile-time changes

These changes are in the order an app meets them: creating the chat,
registering, loading keys, decrypting, encrypting and sending, files,
prepared changes, decrypted events and errors. The compiler reports a
changed prototype; a document is a string, so a call reports a wrong one
when it runs, as an `invalid_input` error or as a field your code doesn't
find.

### Every call returns an `FfiResult`

Every function returns an `FfiResult`, apart from `chat_xdk_abi_version`
and the `_free` functions. A boolean comes back as `true` or `false` in
`data`: `chat_xdk_is_unlocked`, `chat_xdk_has_identity_key`,
`chat_xdk_verify`, `chat_xdk_verify_key_binding` and
`chat_xdk_matches_registered_key` return one, and an input they can't read,
such as a key that isn't base64, is an error naming it. `chat_xdk_lock`,
`chat_xdk_set_reject_unverified` and `chat_xdk_set_cache_keys` return an
`FfiResult` too, with no `data`:

```c
// 0.5.x
int32_t valid = chat_xdk_verify(chat, public_key_b64, signature_b64, data, data_len);
chat_xdk_set_cache_keys(chat, 1);

// 0.7.2
char *verified = take(chat_xdk_verify(chat, public_key_b64, signature_b64, data, data_len));
bool valid = strcmp(verified, "true") == 0;
take(chat_xdk_set_cache_keys(chat, 1));
```

### Keys stored in Juicebox

`chat_xdk_new` takes the Juicebox config the X API returns, or `NULL` for a
chat that manages its keys with `chat_xdk_import_keys` and
`chat_xdk_export_keys` alone, and writes the handle to its out-parameter.
`chat_xdk_update_config` sets the config later, on first boot, before the
account has one, or again to refresh it. `chat_xdk_setup` and `chat_xdk_unlock`
take only the PIN, and every PIN is bytes and a length, so you can zero
yours once the call returns. The header declares the Juicebox functions
(`chat_xdk_update_config`, `chat_xdk_setup`, `chat_xdk_unlock`,
`chat_xdk_change_pin` and `chat_xdk_delete`) when `CHAT_XDK_JUICEBOX` is
defined, so define it before you include `chat_xdk.h`, or pass
`-DCHAT_XDK_JUICEBOX`:

```c
// 0.5.x
struct ChatHandle *chat = chat_xdk_new();
take(chat_xdk_unlock(chat, "2580", juicebox_config_json));

// 0.7.2
struct ChatHandle *chat = NULL;
take(chat_xdk_new(juicebox_config_json, &chat));
take(chat_xdk_unlock(chat, pin, pin_len));
```

Calls on one handle may run on any thread at once,
`chat_xdk_update_config` included; free the handle once every call on it
has returned. A wrong PIN fails with an `invalid_pin` error (see [Errors
carry their kind](#errors-carry-their-kind)), and a chat without a config
fails its Juicebox calls (see [An empty Juicebox config
fails](#an-empty-juicebox-config-fails)).

### Register keys with the public key only

`chat_xdk_generate_keypairs` returns a document that holds only
`public_key`. Send it as returned as the body of
`POST /2/users/{id}/public_keys`. 0.7.2 doesn't pick a signing-key version
for new keys: set the identity with the `public_key_version` the request
returns (see the next section). A signed call made without a version fails
with `Invalid state: signing_key_version is not set: pass it explicitly or
call set_identity() first`. `chat_xdk_get_public_keys` returns the two
public keys, `{"identity": "...", "signing": "..."}`, without a version.

```c
// 0.5.x
// {"public_key": {...}, "version": "...", "generate_version": true}
char *registration = take(chat_xdk_generate_keypairs(chat));

// 0.7.2
// {"public_key": {"public_key": "...", "signing_public_key": "...", "identity_public_key_signature": "...", ...}}
char *registration = take(chat_xdk_generate_keypairs(chat));
char *response = api_post("/2/users/4201/public_keys", registration);
char *public_key_version = json_get(response, "data.public_key_version");
```

### Set the identity with a params document

`chat_xdk_set_identity` takes the user id and the signing-key version as
one document. It fails when either value is invalid (see [user ids and key
versions](#user-ids-and-key-versions-are-strings-of-digits)).

```c
// 0.5.x
take(chat_xdk_set_identity(chat, "4201", "1"));

// 0.7.2
take(chat_xdk_set_identity(chat, "{\"user_id\":\"4201\",\"signing_key_version\":\"1\"}"));
```

### Import keys with a params document

`chat_xdk_import_keys` takes the key bytes by pointer and length, and a
document with the optional signing-key version they were registered under.
Without a version, pass `"{}"` and set the identity before the first signed
call. `chat_xdk_export_keys` keeps its prototype (see
[`chat_xdk_export_keys` fails without
keys](#chat_xdk_export_keys-fails-without-keys)).

```c
// 0.5.x
take(chat_xdk_import_keys(chat, keys_b64));
take(chat_xdk_import_keys_with_version(chat, keys, keys_len, "1"));

// 0.7.2
take(chat_xdk_import_keys(chat, keys, keys_len, "{}"));
take(chat_xdk_import_keys(chat, keys, keys_len, "{\"signing_key_version\":\"1\"}"));
```

### Decrypt with params documents

`chat_xdk_decrypt_events` and `chat_xdk_decrypt_event` each take one
document. Leave out `signing_keys` to verify with the keys
`chat_xdk_set_signing_keys` stored, and `conversation_keys` to resolve the
key from the key cache. A batch's result holds the decrypted events, of
every event type, under `events`, and the events left out under `errors`,
events decrypt drops included; `chat_xdk_decrypt_event` fails for one.

```c
// 0.5.x
// {"messages": [{"event": {...}}], "conversation_keys": {...}, "errors": {}}
char *batch = take(chat_xdk_decrypt_events(chat, events_json, signing_keys_json));
char *event = take(chat_xdk_decrypt_event(chat, event_b64, conversation_keys_json, signing_keys_json));

// 0.7.2
// {"events": ["..."], "signing_keys": [{"user_id": "4201", "public_key_version": "1", "public_key": "...",
//  "identity_public_key": "...", "identity_public_key_signature": "..."}]}
char *batch = take(chat_xdk_decrypt_events(chat, decrypt_events_json));
// {"event_b64": "...", "conversation_keys": {"1": "..."}, "signing_keys": [{"user_id": "4201",
//  "public_key_version": "1", "public_key": "...", "identity_public_key": "...",
//  "identity_public_key_signature": "..."}]}
char *event = take(chat_xdk_decrypt_event(chat, decrypt_event_json));
```

The batch result is `{"events": [{"event": {...}}], "conversation_keys":
{"keys": {...}, "latest_version": ...}, "errors": {...}}`. Its
`latest_version` comes only from a key change that verified (see
[`latest_version` comes from a verified key
change](#latest_version-comes-from-a-verified-key-change)).

### The send payload takes the send request's field names

The encrypt calls keep their names, and the send payload they return names
its two encoded fields `encoded_message_create_event` and
`encoded_message_event_signature`, the field names of the send request,
`POST /2/chat/conversations/{id}/messages`, so the request takes them as
they are, along with the payload's `xdk_version`, the version of the SDK
that built it. The payload also carries `event_b64`, the message as
recipients receive it: keep it to encrypt the message's files (see
[Encrypt a file from its message](#encrypt-a-file-from-its-message)).

```c
// 0.5.x
// {"message_id": "...", "encrypted_content": "...", "signature": "...", "encoded_event_signature": "...", ...}
char *payload = take(chat_xdk_encrypt_message(chat, message_json));

// 0.7.2
// {"conversation_id": "1001:1002", "text": "hello"}
char *payload = take(chat_xdk_encrypt_message(chat, message_json));
// POST /2/chat/conversations/1001-1002/messages
// {"message_id": <payload.message_id>,
//  "encoded_message_create_event": <payload.encoded_message_create_event>,
//  "encoded_message_event_signature": <payload.encoded_message_event_signature>,
//  "xdk_version": <payload.xdk_version>}
api_post("/2/chat/conversations/1001-1002/messages", send_json);
```

A v1 payload's encoded fields carry what X clients' v1 sends carry:
`encoded_message_event_signature` lists the signing keys the message relies
on, by user id and key version (the sender's own and, for a reply, those of
the quoted message's sender and of its edit's), and
`encoded_message_create_event` asks for a notification for a reaction only
in a one-to-one conversation, and never for a reaction removal or an edit.
Send both as returned.

### Encrypt a file from its message

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

```c
// 0.5.x
char *encrypted = take(chat_xdk_encrypt_stream(chat, photo_b64, conversation_key_b64));
char *photo_message = take(chat_xdk_encrypt_message(chat, photo_message_json));

// 0.7.2
char *total_bytes = take(chat_xdk_encrypted_file_size(24000));
// {"conversation_id": "1001:1002", "text": "a photo", "attachments": [{"attachment_type": "media",
//  "media_hash_key": "...", "width": 1200, "height": 630, "filesize_bytes": 24432, "filename": "photo.jpg"}]}
char *photo_message = take(chat_xdk_encrypt_message(chat, photo_message_json));
// {"file": "...", "event_b64": "...", "media_hash_key": "..."}
char *encrypted = take(chat_xdk_encrypt_file(chat, encrypt_file_json));
```

The upload requests take `conversation_id` in its colon form, as the SDK
does. Like the message, the file takes `conversation_key` and
`conversation_key_version` (both, or neither to resolve them from the key
cache), and they must be the ones the message was encrypted under.

Upload each file for one message only. In v1 the id of a message with files
is derived from its conversation key and version, its sender, its
conversation and its files' media hash keys, but not its text: encrypting
the same message again gives the same id, so files you already encrypted for
it stay valid, and a second message that reuses the first one's uploads gets
the same id, so recipients drop it as a repeat. The file fields the SDK
checks are listed under [Entities, files, URL cards and posts are
checked](#entities-files-url-cards-and-posts-are-checked).

### Decrypt a file with its message's event

`chat_xdk_decrypt_file` takes the downloaded bytes, the base64 event of the
message that carries the file, the conversation key map and the file's
media hash key from the decrypted message: one of its media attachments, a
link card's banner or favicon (both listed in `media_hashes`), or media
quoted in its reply preview. The SDK finds the file in the event and
derives its key. It doesn't check the message's signature: use `verified`
from `chat_xdk_decrypt_event` for that.

```c
// 0.5.x
char *plaintext = take(chat_xdk_decrypt_stream(chat, downloaded_b64, conversation_key_b64));

// 0.7.2
// {"encrypted": "...", "event_b64": "...", "conversation_keys": {"1": "..."}, "media_hash_key": "..."}
char *plaintext = take(chat_xdk_decrypt_file(chat, decrypt_file_json));
```

### Encrypt a file under a key you hold

`chat_xdk_encrypt_stream` and `chat_xdk_decrypt_stream` take a key from the
app for every file. A file a message carries takes its key from the
message, as the two sections above show. A file no message carries keeps
the key you hold, and goes through `chat_xdk_encrypt_file_with_key` and
`chat_xdk_decrypt_file_with_key`: a group's avatar image, which X clients
encrypt under the conversation key whose version the avatar change signs
next to the avatar URL (see [Changing the avatar](#changing-the-avatar)),
or your app's own files at rest. Each takes the chat and a params document
with the file (`file` or `encrypted`) and the raw 32-byte key
`chat_xdk_encrypt_stream` took, as `key`, both base64, and returns the
result base64. They write the format `chat_xdk_encrypt_stream` writes:
files 0.5.x encrypted with `chat_xdk_encrypt_stream` or a stream encryptor
decrypt with `chat_xdk_decrypt_file_with_key`, and 0.5.x
`chat_xdk_decrypt_stream` decrypts what `chat_xdk_encrypt_file_with_key`
returns, so files you stored need no re-encryption. A key that isn't 32
bytes fails with an error of kind `invalid_input`, and bytes that aren't a
complete file encrypted under the key with one of kind `decryption`.

```c
// 0.5.x
char *encrypted = take(chat_xdk_encrypt_stream(chat, file_b64, conversation_key_b64));
char *plaintext = take(chat_xdk_decrypt_stream(chat, downloaded_b64, conversation_key_b64));

// 0.7.2
// {"file": "...", "key": "..."}
char *encrypted = take(chat_xdk_encrypt_file_with_key(chat, encrypt_file_with_key_json));
// {"encrypted": "...", "key": "..."}
char *plaintext = take(chat_xdk_decrypt_file_with_key(chat, decrypt_file_with_key_json));
```

To move a `chat_xdk_encrypt_stream` or `chat_xdk_decrypt_stream` call, look
at its file. A file one of a message's attachments names (a photo, a video,
a link card's banner or favicon) moves to `chat_xdk_encrypt_file` and
`chat_xdk_decrypt_file`, with the message; any other file moves to
`chat_xdk_encrypt_file_with_key` and `chat_xdk_decrypt_file_with_key`, with
the same key.

### Encrypt and decrypt large files in chunks

`chat_xdk_file_encryptor_new` and `chat_xdk_file_decryptor_new` take the
chat and the same document as `chat_xdk_encrypt_file` and
`chat_xdk_decrypt_file` without the file bytes. They return an `FfiResult`
and write the handle to their last argument. The push, finish and free
calls take the same arguments as 0.5.x's, under the file names, and
`chat_xdk_encrypted_file_size` sizes an upload. A file under a key you hold
has no chunked form: read it whole and pass it to
`chat_xdk_encrypt_file_with_key` or `chat_xdk_decrypt_file_with_key` (see
[Encrypt a file under a key you hold](#encrypt-a-file-under-a-key-you-hold)).

```c
// 0.5.x
char *size = take(chat_xdk_encrypted_stream_size(1100));
StreamEncryptorHandle *encryptor = chat_xdk_stream_encryptor_new(conversation_key_b64);
char *head = take(chat_xdk_stream_encryptor_push(encryptor, photo_b64));
char *tail = take(chat_xdk_stream_encryptor_finish(encryptor));
chat_xdk_stream_encryptor_free(encryptor);

// 0.7.2
char *size = take(chat_xdk_encrypted_file_size(1100));
struct FileEncryptorHandle *encryptor = NULL;
// {"event_b64": "...", "media_hash_key": "..."}
take(chat_xdk_file_encryptor_new(chat, file_encryptor_json, &encryptor));
char *head = take(chat_xdk_file_encryptor_push(encryptor, photo_b64));
char *tail = take(chat_xdk_file_encryptor_finish(encryptor));
chat_xdk_file_encryptor_free(encryptor);
struct FileDecryptorHandle *decryptor = NULL;
// {"event_b64": "...", "conversation_keys": {"1": "..."}, "media_hash_key": "..."}
take(chat_xdk_file_decryptor_new(chat, file_decryptor_json, &decryptor));
char *plain = take(chat_xdk_file_decryptor_push(decryptor, downloaded_b64));
char *rest = take(chat_xdk_file_decryptor_finish(decryptor));
chat_xdk_file_decryptor_free(decryptor);
```

### Action signatures come nested

The prepare calls return each action signature in the shape a request's
`action_signatures` takes: `message_id`, `encoded_message_event_detail`,
and the signature nested under `message_event_signature`, with your
`signing_public_key`. The signed payload stays inside the SDK. Send the
entries as the request's `action_signatures` as returned:

```c
// 0.5.x
// {..., "action_signatures": [{"message_id": "...", "encoded_message_event_detail": "...",
//  "signature": "...", "signature_version": "7", "public_key_version": "1", "signature_payload": "..."}]}
char *prepared = take(chat_xdk_prepare_conversation_key_change(chat, key_change_json));

// 0.7.2
// {"public_keys": [{"user_id": "4201", "identity_public_key": "...", "public_key_version": "1"},
//  {"user_id": "4202", "identity_public_key": "...", "public_key_version": "1"}]}
char *prepared = take(chat_xdk_prepare_conversation_key_change(chat, key_change_json));
// {..., "action_signatures": [{"message_id": "...", "encoded_message_event_detail": "...",
//  "message_event_signature": {"signature": "...", "signature_version": "7",
//  "public_key_version": "1", "signing_public_key": "..."}}]}
```

### Public key inputs name the identity key and its version

Each public key a prepare document takes, one participant a conversation
key is encrypted to, names its key `identity_public_key` and the key's
version `public_key_version`, as a signing key does: the `public_key` the X
API returns for a user is their identity key. A document with the 0.5.x
names fails with ``Invalid params JSON: missing field
`identity_public_key` ``:

```c
// 0.5.x
// {"public_keys": [{"user_id": "4201", "public_key": "...", "key_version": "1"}]}
char *prepared = take(chat_xdk_prepare_conversation_key_change(chat, key_change_json));

// 0.7.2
// {"public_keys": [{"user_id": "4201", "identity_public_key": "...", "public_key_version": "1"},
//  {"user_id": "4202", "identity_public_key": "...", "public_key_version": "1"}]}
char *prepared = take(chat_xdk_prepare_conversation_key_change(chat, key_change_json));
```

### Participant keys take the key requests' names

`chat_xdk_prepare_conversation_key_change`, `chat_xdk_prepare_group_create`,
`chat_xdk_prepare_group_members_change` and
`chat_xdk_prepare_group_members_remove` name the participant keys as the X
API does in every request that takes them
(`POST /2/chat/conversations/{id}/keys`, `/group`, `/{id}/members` and
`/{id}/members/remove`, and `PUT /2/chat/conversations/{id}`):
`conversation_participant_keys`, each entry with `user_id`,
`encrypted_conversation_key` and `public_key_version`, the names a
decrypted key change uses too (see [Received participant keys take the same
names](#received-participant-keys-take-the-same-names)). Send them as
returned, without renaming:

```c
// 0.5.x
// {..., "participant_keys": [{"user_id": "...", "encrypted_key": "...", "public_key_version": "..."}]}
char *prepared = take(chat_xdk_prepare_conversation_key_change(chat, key_change_json));

// 0.7.2
// {"public_keys": [{"user_id": "4201", "identity_public_key": "...", "public_key_version": "1"},
//  {"user_id": "4202", "identity_public_key": "...", "public_key_version": "1"}]}
char *prepared = take(chat_xdk_prepare_conversation_key_change(chat, key_change_json));
// POST /2/chat/conversations/4201-4202/keys
// {"conversation_key_version": <prepared.conversation_key_version>,
//  "conversation_participant_keys": <prepared.conversation_participant_keys>,
//  "action_signatures": <prepared.action_signatures>}
api_post("/2/chat/conversations/4201-4202/keys", key_change_request_json);
```

### Received participant keys take the same names

`chat_xdk_decrypt_event` and `chat_xdk_decrypt_events` return a key
change's participant keys under the names Thrift's
`ConversationKeyChangeEvent` gives them, the same names a prepared change
uses: `conversation_participant_keys`, each entry with `user_id`,
`encrypted_conversation_key` and `public_key_version`:

```c
// 0.5.x
// {"type": "KeyChange", ..., "participant_keys": [{"user_id": "...", "encrypted_key": "...", ...}]}
char *encrypted = json_get(key_change_json, "participant_keys.0.encrypted_key");

// 0.7.2
// {"type": "KeyChange", ..., "conversation_participant_keys": [{"user_id": "...",
//  "encrypted_conversation_key": "...", "public_key_version": "..."}]}
char *encrypted = json_get(key_change_json, "conversation_participant_keys.0.encrypted_conversation_key");
```

### Deletes return `action_signatures`

`chat_xdk_prepare_message_delete` returns a document whose
`action_signatures` hold one entry, shaped as [Action signatures come
nested](#action-signatures-come-nested) shows. Read the action's
`message_id` from that entry, and send `action_signatures` as returned (see
[Deleting messages](#deleting-messages) for the request):

```c
// 0.5.x
// {"message_id": "...", "encoded_message_event_detail": "...", "signature": "...", ...}
char *deletion = take(chat_xdk_prepare_message_delete(chat, delete_json));
char *message_id = json_get(deletion, "message_id");

// 0.7.2
// {"conversation_id": "1001:1002", "sequence_ids": ["7"], "delete_for_all": false}
char *deletion = take(chat_xdk_prepare_message_delete(chat, delete_json));
char *message_id = json_get(deletion, "action_signatures.0.message_id");
```

### Decrypted events use the names the calls take

The decrypt calls return a message's or key change's conversation key
version as `conversation_key_version`, the name the X API's events and the
Thrift events give it, and the name the encrypt params take:

```c
// 0.5.x
char *message_version = json_get(message_json, "key_version");

// 0.7.2
char *message_version = json_get(message_json, "conversation_key_version");
```

Fields that hold sequence ids take the names of the params that send them.
`Reaction`, `ReactionRemoved` and `Edit` content names its target
`target_message_sequence_id`, as the reaction and edit params do. A
`MessageDeleted` event names its messages `sequence_ids`, as the delete
params do, and a `ReadReceipt` or `MarkedUnread` event names its position
`seen_until_sequence_id`, as the read-receipt params do. An edit's text is
`updated_text`, as the edit params name it, and a v1 edit carries the
signed message id of the message it edits as `target_message_id`, absent
for a v0 edit.

**Rename every read of `target_message_id` to `target_message_sequence_id`.
Don't keep `target_message_id`: in 0.7.2 it names a different value, and
reading it compiles and runs** (see [`target_message_id` holds a different
value](#target_message_id-holds-a-different-value)).

```c
// 0.5.x
// {"type": "Message", ..., "content": {"content_type": "Edit", "target_message_id": "7", "new_text": "..."}}
char *target = json_get(message_json, "content.target_message_id");
char *text = json_get(message_json, "content.new_text");
char *deleted = json_get(deleted_json, "message_ids.0");
char *seen_until = json_get(receipt_json, "seen_until_id");

// 0.7.2
// {"type": "Message", ..., "content": {"content_type": "Edit", "target_message_sequence_id": "7", "updated_text": "..."}}
char *target = json_get(message_json, "content.target_message_sequence_id");
char *text = json_get(message_json, "content.updated_text");
char *deleted = json_get(deleted_json, "sequence_ids.0");
char *seen_until = json_get(receipt_json, "seen_until_sequence_id");
```

A group create's `title`, and a title or description change's `new_title`
or `new_description`, is a `GroupText` object rather than a string (see
[Creating a group](#creating-a-group)).

### Errors carry their kind

An `FfiResult`'s `error` is a JSON document: `kind`, which names the
failure the same way in every binding (`invalid_input`, `invalid_state`,
`parse`, `decryption`, `verification`, `invalid_pin`, `juicebox` or
`internal`), `message`, and, after a wrong PIN, `guesses_remaining`, the
attempts Juicebox reports left (`0` once the stored keys are locked):

```c
// 0.5.x
// "Juicebox error: Invalid PIN: guesses_remaining=2"
struct FfiResult r = chat_xdk_unlock(chat, "2580", juicebox_config_json);

// 0.7.2
// {"kind": "invalid_pin", "message": "Juicebox error: Invalid PIN: guesses_remaining=2", "guesses_remaining": 2}
struct FfiResult r = chat_xdk_unlock(chat, pin, pin_len);
char *kind = r.error != NULL ? json_get(r.error, "kind") : NULL;
```

A missing or invalid parameter fails with an error of kind `invalid_input`
whose message names the value, such as `Invalid sender_id 'user-1': pass a
numeric user id (digits only)` or `too many attachments: at most 10 per
message`, without an `Invalid state:` prefix. Errors about state the chat
lacks, such as a missing session identity or an empty key cache, are of
kind `invalid_state` and keep their prefix. Match the kind rather than the
message.

## 3. Runtime and behavior changes

Nothing reports these changes before the code runs: each one is a value the
SDK checks, a value with a new meaning, or an event handled differently.

### User ids and key versions are strings of digits

Every user id in a document is a string of digits: the identity's
`user_id`, `sender_id`, `reply_to_sender_id` (a JSON string, not a number),
the `user_id` of each public key and signing key, and the ids of a group's
members and admins (`member_ids`, `admin_ids`, `new_member_ids`,
`current_member_ids`, `current_admin_ids`, `current_pending_member_ids` and
`user_ids`). Each must be a positive integer written without a sign or
leading zeros. Every key version is a non-negative integer written as a
string of digits, as the X API returns it: the signing-key version and
`conversation_key_version`. Anything else fails with an error that names
the field, such as `Invalid sender_id 'user-1': pass a numeric user id
(digits only)`.

```c
// 0.5.x
// {"conversation_id": "...", "text": "pong", "reply_to_sender_id": 4201, ...}
char *reply = take(chat_xdk_encrypt_reply(chat, reply_json));

// 0.7.2
// {"conversation_id": "1001:1002", "text": "pong", "reply_to_sequence_id": "7", "reply_to_sender_id": "4201",
//  "reply_to_text": "ping", "reply_to_message_id": "0b4f7c2e-5a1d-4e8b-9c3f-6d2a1b8e7f90"}
char *reply = take(chat_xdk_encrypt_reply(chat, reply_json));
```

A reply built from these fields also names the quoted message's
`message_id` as `reply_to_message_id` (see [A reply preview quotes its
message exactly](#a-reply-preview-quotes-its-message-exactly)).

### Entities, files, URL cards and posts are checked

The encrypt calls check what a message carries before they encrypt it, and
fail with an `invalid_input` error naming the value, where 0.5.x sent it:

- An entity of a type the SDK doesn't know, an empty one included, fails
  with `Invalid entity_type 'user_mention': pass url, mention, hashtag,
  cashtag, email, address or phone_number`, for a message's, a reply's, a
  reply preview's and an edit's entities.
- Entity offsets count bytes of the text's UTF-8 encoding, the start
  inclusive and the end exclusive. An entity whose offsets are negative,
  end before they start or run past the end of the text fails, such as
  `Invalid entity offsets 3..8: end is past the end of the text, which is 7
  bytes of UTF-8`. A reply preview's entities, which index the quoted
  message's text, are checked for all but the end.
- A file a message carries, a media attachment or a URL card's banner or
  favicon, fails with an empty `filename`, a `filesize_bytes` of 0 or less,
  or a negative `width` or `height`, since receiving clients discard such a
  file. Give each file its name and the encrypted size
  `chat_xdk_encrypted_file_size` gives.
- A message that lists an empty media hash key, or one media hash key in
  two attachments, fails.
- A URL card with an empty `url`, and a post attachment with neither
  `rest_id` nor `post_url`, fail.

```c
// 0.7.2
// {"conversation_id": "1001:1002", "text": "café @bob", "entities": [[6, 10, "mention"]]}
char *sent = take(chat_xdk_encrypt_message(chat, mention_json));
```

### `latest_version` comes from a verified key change

A batch's `conversation_keys.latest_version`, the version to encrypt with,
is the newest version whose key change verified, and it never moves back
for the chat's lifetime. A key change verifies only against its sender's
signing key, so give the chat every participant's signing keys, your own
included, before you decrypt. It's `null` until a key change verifies: a
key change the SDK can't verify still adds its key to
`conversation_keys.keys`, for decrypting, but never becomes the version you
encrypt with. Where 0.5.x returned the batch's highest version, 0.7.2 can
return `null`: fetch the missing signing keys or the conversation's
key-change events and decrypt again, rather than encrypting under the
highest key in `keys`:

```c
// 0.5.x
char *batch = take(chat_xdk_decrypt_events(chat, events_json, signing_keys_json));
char *version = json_get(batch, "conversation_keys.latest_version");

// 0.7.2
// [{"user_id": "4201", "public_key_version": "1", "public_key": "...", "identity_public_key": "...",
//  "identity_public_key_signature": "..."}]
take(chat_xdk_set_signing_keys(chat, signing_keys_json));
// {"events": ["..."]}
char *batch = take(chat_xdk_decrypt_events(chat, decrypt_events_json));
char *version = json_get(batch, "conversation_keys.latest_version");
if (version == NULL) {
    // No key change verified: fetch every participant's signing keys
    // (GET /2/users/{id}/public_keys) and the conversation's key changes
    // (meta.conversation_key_events of GET /2/chat/conversations/{id}/events),
    // then decrypt again.
    return;
}
```

### `target_message_id` holds a different value

**In 0.5.x a reaction's or edit's `target_message_id` held the target's
sequence id. In 0.7.2 that value is `target_message_sequence_id`, and
`target_message_id` holds the edited message's signed message id, present
only on a v1 edit.** Decrypted events are JSON documents, so code that keeps
reading `target_message_id` compiles and runs: it gets the wrong id, or
none. Rename every read, as [Decrypted events use the names the calls
take](#decrypted-events-use-the-names-the-calls-take) shows, and use
`target_message_id` only to match a v1 edit to the `message_id` you
deduplicate on.

An edit you build names the edited message the same way: set the edit
document's `target_message_id` to its signed `message_id`, which a v1 edit
built from the conversation id and the target sequence id needs. With
`target_event`, the SDK takes the id from the event, and a
`target_message_id` other than it fails with an `invalid_input` error.

### A reply preview quotes its message exactly

A received reply that embeds the message it quotes has its preview checked
against that message: the decrypted message's `reply_preview_validation` is
`"Valid"` only when the first 140 characters of the preview's text, counted
in UTF-16 code units as X clients count them, are those of the quoted text,
and its entities are exactly the quoted message's, or its edit's when the
reply embeds the edit. 0.5.x accepted any start of the quoted text, and
entities among the quoted message's. `chat_xdk_encrypt_reply` builds such a
preview from `reply_to_event`, and from `reply_to_edit_event` when the
message was edited, so pass them when you hold them. In v1, X clients check
a reply against the message it names and mark a reply that names none
invalid, so a reply built from the explicit preview fields names the quoted
message's `message_id` as `reply_to_message_id`. With `reply_to_event`, the
SDK takes the id from the event, and a `reply_to_message_id` other than it
fails with an `invalid_input` error.

A reply carries no key change. Recipients open the quoted message with their
own conversation keys, or with the message key a reply carries for a v1
message, and decrypt ignores a key change embedded in a reply.
`reply_to_ckces` still opens a message under a key version your chat doesn't
hold yet, for `chat_xdk_encrypt_reply` to quote it, but the reply doesn't
carry those key changes.

### A prepared change's JSON keeps its key

There's no code to change. A prepared change's document carries the new
key as `conversation_key`, base64, as in 0.5.x, and it is where you read
the key from to store it. The request bodies take only its participant
keys, key version and action signatures, never the key itself.

### `chat_xdk_sign` refuses data only the SDK signs

`chat_xdk_sign` fails with an `invalid_input` error for a payload
recipients would verify as a signed event (a message, conversation-key
change, group or conversation-metadata change, delete or read receipt) and
for a P-256 public key, whose signature by the signing key binds it as an
identity key: `data is an event signature payload or a public key, which
only the SDK signs: pass your application's own data`. Sign only your own
application data with it; the SDK signs events itself. Any other data signs
as in 0.5.x:

```c
// 0.7.2
struct FfiResult signed_data = chat_xdk_sign(chat, data, data_len);
if (signed_data.error != NULL) {
    // An invalid_input error: the data reads as an event or a public key,
    // which only the SDK signs.
    chat_xdk_free_string(signed_data.error);
}
```

### Decrypt drops a removal's title and description re-encryptions

A member removal rotates the conversation key and re-encrypts the group's
title and description under the new key, marked as key-rotation
re-encryptions. They are the same text, not changes, so
`chat_xdk_decrypt_events` and `chat_xdk_decrypt_event` drop them under
either `chat_xdk_set_reject_unverified` setting, the way they drop an
unverified event: a batch leaves each one out of `events` and records it in
`errors`, and `chat_xdk_decrypt_event` fails with an `invalid_input` error:
`GroupChange re-encrypts the group's title for a key rotation
(for_key_rotation), not a title change: decrypt does not return it`. The
removal itself (`MembersRemoved`), its key change, avatar changes and every
title or description change without the mark decrypt as before. In 0.5.x,
a removal by an X client arrived as a `TitleChanged` carrying the group's
unchanged title:

```c
// 0.5.x
// {"messages": [{"event": {"type": "GroupChange", ..., "change": {"change_type": "TitleChanged",
//  "new_title": "<ciphertext>"}}}], ...}
char *batch = take(chat_xdk_decrypt_events(chat, events_json, signing_keys_json));

// 0.7.2
// {"events": ["..."]}
char *batch = take(chat_xdk_decrypt_events(chat, decrypt_events_json));
// {"events": [...], "conversation_keys": {...},
//  "errors": {"1": "GroupChange re-encrypts the group's title for a key rotation (for_key_rotation), ..."}}
```

A loop over single events reads the error, as it reads an unverified
event's, and moves on to the next event:

```c
// 0.7.2
// {"event_b64": "...", "conversation_keys": {"2": "..."}}
struct FfiResult r = chat_xdk_decrypt_event(chat, decrypt_event_json);
if (r.error != NULL) {
    log_skipped(event_b64, r.error);
    chat_xdk_free_string(r.error);
} else {
    handle(r.data);
    chat_xdk_free_string(r.data);
}
```

### `chat_xdk_export_keys` fails without keys

`chat_xdk_export_keys` fails with an `invalid_state` error when no identity
key is loaded, where 0.5.x returned `NULL` data without an error; check
`chat_xdk_has_identity_key` first where that can happen:

```c
// 0.5.x
struct FfiResult exported = chat_xdk_export_keys(chat);
if (exported.data == NULL && exported.error == NULL) {
    // no keys
}

// 0.7.2
char *has_keys = take(chat_xdk_has_identity_key(chat));
char *exported = strcmp(has_keys, "true") == 0 ? take(chat_xdk_export_keys(chat)) : NULL;
```

### An empty Juicebox config fails

Until a chat has a Juicebox config, `chat_xdk_setup`, `chat_xdk_unlock`,
`chat_xdk_change_pin` and `chat_xdk_delete` fail with an `invalid_state`
error, `Invalid state: no Juicebox config: pass the juicebox_config the X
API returns when you create the chat, or call update_config() first`, the
error every binding gives. `chat_xdk_new` and `chat_xdk_update_config` fail
with it for an empty or blank config, at once, rather than at the first
Juicebox call; `chat_xdk_new(NULL, &chat)` creates a chat without one.

## 4. Group and receipt signing

Recipients on the default `chat_xdk_set_reject_unverified` policy drop a
read receipt or group change that isn't signed, as 0.5.x recipients did:
sign each one, or recipients never see it. The sender comes from
`chat_xdk_set_identity`. Each prepare call returns `action_signatures`
shaped as [Action signatures come nested](#action-signatures-come-nested)
shows; copy them into the request as returned.

### The requests

Each request below takes the conversation id in its path, and the prepare
call's `action_signatures` as returned, as `action_signatures`. The paths
and body fields are the X API's, as its OpenAPI description
(`https://api.x.com/2/openapi.json`) gives them.

| Action | Call | Request | Body |
|---|---|---|---|
| Send a message, reply, reaction or edit | `chat_xdk_encrypt_message`, `chat_xdk_encrypt_reply`, `chat_xdk_encrypt_add_reaction`, `chat_xdk_encrypt_remove_reaction`, `chat_xdk_encrypt_edit` | `POST /2/chat/conversations/{id}/messages` | `message_id`, `encoded_message_create_event`, `encoded_message_event_signature`, `xdk_version`, from the payload's fields of the same names |
| Delete messages | `chat_xdk_prepare_message_delete` | `POST /2/chat/conversations/{id}/messages/delete` | `sequence_ids`; `delete_message_action`, `"delete_for_all"` or `"delete_for_self"` as the params' `delete_for_all` says; `action_signatures` |
| Mark read | `chat_xdk_prepare_mark_conversation_read` | `POST /2/chat/conversations/{id}/read` | `action_signatures` |
| Start a one-to-one or rotate its key | `chat_xdk_prepare_conversation_key_change` | `POST /2/chat/conversations/{id}/keys` | `conversation_key_version`, `conversation_participant_keys`, `action_signatures` |
| Create a group | `chat_xdk_prepare_group_create` | `POST /2/chat/conversations/group` | `conversation_id`, `group_members`, `group_admins`, `group_name` (the result's `encrypted_title`), `conversation_key_version`, `conversation_participant_keys`, `action_signatures` |
| Add members | `chat_xdk_prepare_group_members_change` | `POST /2/chat/conversations/{id}/members` | `user_ids`, `encrypted_title`, `conversation_key_version`, `conversation_participant_keys`, `action_signatures` |
| Remove members | `chat_xdk_prepare_group_members_remove` | `POST /2/chat/conversations/{id}/members/remove` | `user_ids`, `action_signatures`, `group_key_rotation_data` with `conversation_key_version` and `conversation_participant_keys` |
| Leave | `chat_xdk_prepare_group_leave` | `POST /2/chat/conversations/{id}/members/remove` | `user_ids` (your own id), `action_signatures` |
| Change the title | `chat_xdk_prepare_group_title_change` | `PUT /2/chat/conversations/{id}` | `group_name` (the result's `encrypted_value`), `conversation_key_version`, `modified_fields: ["group_name"]`, `action_signatures` |
| Change the description | `chat_xdk_prepare_group_description_change` | `PUT /2/chat/conversations/{id}` | `group_description` (the result's `encrypted_value`), `conversation_key_version`, `modified_fields: ["group_description"]`, `action_signatures` |
| Change the avatar | `chat_xdk_prepare_group_avatar_change` | `PUT /2/chat/conversations/{id}` | `group_avatar_url` (the media URL), `conversation_key_version`, `modified_fields: ["group_avatar_url"]`, `action_signatures` |
| Add admins | `chat_xdk_prepare_group_admins_add` | `POST /2/chat/conversations/{id}/admins` | `user_ids`, `action_signatures` |
| Remove admins | `chat_xdk_prepare_group_admins_remove` | `POST /2/chat/conversations/{id}/admins/remove` | `user_ids`, `action_signatures` |
| Turn the invite link on | `chat_xdk_prepare_group_invite_enable` | `POST /2/chat/conversations/{id}/invite` | `invite_url`; `validity_expiry_timestamp_msec` (the params' `expires_at_msec`) and `affiliate_user_id` (the params' `affiliate_id`) when set; `action_signatures` |
| Turn the invite link off | `chat_xdk_prepare_group_invite_disable` | `DELETE /2/chat/conversations/{id}/invite` | `action_signatures` |
| Ask to join | `chat_xdk_prepare_group_join_request` | `POST /2/chat/conversations/{id}/join_requests` | `token` (the invite link's last 10 characters), `action_signatures` |
| Reject join requests | `chat_xdk_prepare_group_join_reject` | `POST /2/chat/conversations/{id}/join_requests/reject` | `user_ids`, `action_signatures` |
| Set the message TTL | `chat_xdk_prepare_message_ttl_change` | `PUT /2/chat/conversations/{id}/message_ttl` | `message_ttl_ms` (the params' `ttl_msec`, as a string), `action_signatures` |
| Clear the message TTL | `chat_xdk_prepare_message_ttl_remove` | `DELETE /2/chat/conversations/{id}/message_ttl` | `action_signatures` |
| Change screen capture | `chat_xdk_prepare_screen_capture` | `PUT /2/chat/conversations/{id}/screen_capture` | `blocking` (`true` for `BlockingEnabled`, `false` for `BlockingDisabled`) and `blocking_action_signatures`, or `detection` and `detection_action_signatures` |

A group's `conversation_id` is the `g…` id that
`POST /2/chat/conversations/group/initialize` returns as
`data.conversation_id`.

### Deleting messages

`chat_xdk_prepare_message_delete` returns the action's signature nested,
as every prepare call does: send `action_signatures` as returned, next to
the sequence ids and the delete action the params signed.

```c
// 0.5.x
// {"conversation_id": "1001:1002", "sequence_ids": ["7"], "delete_for_all": true}
char *deletion = take(chat_xdk_prepare_message_delete(chat, delete_json));
// POST /2/chat/conversations/1001-1002/messages/delete
// {"sequence_ids": ["7"], "delete_message_action": "delete_for_all",
//  "action_signatures": [{"message_id": <deletion.message_id>,
//   "encoded_message_event_detail": <deletion.encoded_message_event_detail>,
//   "message_event_signature": {"signature": <deletion.signature>,
//    "signature_version": <deletion.signature_version>, "public_key_version": <deletion.public_key_version>,
//    "signing_public_key": "..."}}]}
api_post("/2/chat/conversations/1001-1002/messages/delete", delete_request_json);

// 0.7.2
// {"conversation_id": "1001:1002", "sequence_ids": ["7"], "delete_for_all": true}
char *deletion = take(chat_xdk_prepare_message_delete(chat, delete_json));
// POST /2/chat/conversations/1001-1002/messages/delete
// {"sequence_ids": ["7"], "delete_message_action": "delete_for_all",
//  "action_signatures": <deletion.action_signatures>}
api_post("/2/chat/conversations/1001-1002/messages/delete", delete_request_json);
```

A recipient's `chat_xdk_decrypt_event` returns the delete as a verified
`MessageDeleted` event with its `sequence_ids` and `delete_for_all`.

### Read receipts are signed

Sign a read receipt with `chat_xdk_prepare_mark_conversation_read` and send
its `action_signatures` as the `action_signatures` of
`POST /2/chat/conversations/{id}/read`. The call takes a document with
`conversation_id`, `seen_until_sequence_id` (the sequence id of the newest
event read) and a `seen_at_msec` that defaults to now, and returns
`action_signatures`, one entry, as a delete does. Without it the X API
sends an unsigned receipt, which recipients drop.

```c
// 0.5.x
api_post("/2/chat/conversations/1001-1002/read", "{}");

// 0.7.2
// {"conversation_id": "1001:1002", "seen_until_sequence_id": "7"}
char *receipt = take(chat_xdk_prepare_mark_conversation_read(chat, mark_read_json));
// POST /2/chat/conversations/1001-1002/read
// {"action_signatures": <receipt.action_signatures>}
api_post("/2/chat/conversations/1001-1002/read", read_request_json);
```

A recipient's `chat_xdk_decrypt_event` returns a signed receipt as a
verified `ReadReceipt` event, its position in `seen_until_sequence_id`.

### Group changes are signed

Every group change below returns `action_signatures` for its request in
[The requests](#the-requests). A group's title and description travel
encrypted under the conversation key, and the SDK encrypts them: the
creates, member adds, removals and title and description changes take them
as plaintext and return the encrypted values to send. An avatar is an image
the app encrypts with `chat_xdk_encrypt_file_with_key` and uploads; its URL
is signed as is.

### Creating a group

`chat_xdk_prepare_group_create` encrypts the group's title under the
conversation key it creates, so pass it as plaintext. The result is a
prepared change that also carries it encrypted, as `encrypted_title`
(absent when unset): send that as the create request's `group_name`, next
to its participant keys and signatures. The create signs the encrypted
value, which is base64, so a title may contain a comma; a value signed as
is, such as an avatar URL, can't. A create sets no avatar, and its params
document takes no avatar URL: set the avatar afterwards with an [avatar
change](#changing-the-avatar), with the image encrypted under the key the
create returns.

```c
// 0.5.x
// {"public_keys": [...], "conversation_id": "g1", "member_ids": ["111", "222"], "admin_ids": ["111"],
//  "title": "Team", "avatar_url": "https://..."}
char *prepared = take(chat_xdk_prepare_group_create(chat, create_json));
// POST /2/chat/conversations/group {..., "group_name": "Team", "group_avatar_url": "https://..."}

// 0.7.2
// {"public_keys": [{"user_id": "111", "identity_public_key": "...", "public_key_version": "1"},
//  {"user_id": "222", "identity_public_key": "...", "public_key_version": "1"}],
//  "conversation_id": "g1", "member_ids": ["111", "222"], "admin_ids": ["111"], "title": "Team"}
char *prepared = take(chat_xdk_prepare_group_create(chat, create_json));
store_conversation_key("g1", prepared);
// POST /2/chat/conversations/group
// {"conversation_id": "g1", "group_members": ["111", "222"], "group_admins": ["111"],
//  "group_name": <prepared.encrypted_title>,
//  "conversation_key_version": <prepared.conversation_key_version>,
//  "conversation_participant_keys": <prepared.conversation_participant_keys>,
//  "action_signatures": <prepared.action_signatures>}
api_post("/2/chat/conversations/group", create_request_json);
```

The decrypt calls return a received group create with its title decrypted
with the key for the version the create names, from the call's key map or
the key cache: a `Created` change's `title` is a `GroupText` object.
`{"kind": "Text", "text": ...}` holds the title.
`{"kind": "Unavailable", "raw": ...}` holds the value as the create carries
it, when that key isn't there or the value doesn't decrypt under it, and
the rest of the create still decrypts. 0.5.x signed a create's title as the
app passed it, so a 0.5.x app's create with a plaintext title arrives as
`Unavailable` with the title in `raw`: show `raw` when a title isn't
decryptable. A create that names no key version carries its title as
plaintext, and arrives as `Text`. The encrypted `group_name` and
`group_description` the X API returns with a conversation open with
`chat_xdk_decrypt`.

```c
// 0.5.x
// {"type": "GroupChange", ..., "change": {"change_type": "Created", ..., "title": "<ciphertext>"}}
char *title = take(chat_xdk_decrypt(chat, json_get(group_change_json, "change.title"), conversation_key_b64));

// 0.7.2
// {"type": "GroupChange", ..., "change": {"change_type": "Created", ...,
//  "title": {"kind": "Text", "text": "Team"}, "avatar_url": null, "conversation_key_version": "..."}}
char *kind = json_get(group_change_json, "change.title.kind");
char *title = json_get(group_change_json, strcmp(kind, "Text") == 0 ? "change.title.text" : "change.title.raw");
```

A `Created` change also carries the create's `conversation_key_version`, and
the `avatar_url` a create from another client may set: a media URL whose
image is encrypted under that key version, which
`chat_xdk_decrypt_file_with_key` opens with that version's key.

### Adding members

`chat_xdk_prepare_group_members_change` rotates the conversation key, so it
re-encrypts the group's title and description under the key it generates:
pass them as plaintext, as `current_title` and `current_description`, not
as values your code encrypted. The result carries them encrypted, as
`encrypted_title` and `encrypted_description` (absent when unset). Send
`encrypted_title` as the add-members request's `encrypted_title`; the
description travels in the signed member add. Encrypt under the new key
from here on, as [Removing members](#removing-members) shows for a
removal.

```c
// 0.5.x
// {"public_keys": [...], "conversation_id": "g1", "new_member_ids": ["333"], "current_member_ids": ["111", "222"],
//  "current_admin_ids": ["111"], "current_pending_member_ids": [], "current_title": "Team"}
char *prepared = take(chat_xdk_prepare_group_members_change(chat, add_json));

// 0.7.2
// {"public_keys": [{"user_id": "111", "identity_public_key": "...", "public_key_version": "1"},
//  {"user_id": "222", "identity_public_key": "...", "public_key_version": "1"},
//  {"user_id": "333", "identity_public_key": "...", "public_key_version": "1"}],
//  "conversation_id": "g1", "new_member_ids": ["333"], "current_member_ids": ["111", "222"],
//  "current_admin_ids": ["111"], "current_pending_member_ids": [], "current_title": "Team",
//  "current_description": "About"}
char *prepared = take(chat_xdk_prepare_group_members_change(chat, add_json));
store_conversation_key("g1", prepared);
// POST /2/chat/conversations/g1/members
// {"user_ids": ["333"], "encrypted_title": <prepared.encrypted_title>,
//  "conversation_key_version": <prepared.conversation_key_version>,
//  "conversation_participant_keys": <prepared.conversation_participant_keys>,
//  "action_signatures": <prepared.action_signatures>}
api_post("/2/chat/conversations/g1/members", add_request_json);
```

While the chat sends v0, passing a description makes the add sign at
signature version 8, the first version whose member-add payload covers one,
and 0.5.x readers can't verify a version-8 add. Until every app that reads
your groups runs 0.7.2, leave the description out, so the add signs at
version 7 as in 0.5.x; the new members can read the description once a
description change sets it under the new key. While the chat sends v1, the
add signs at version 10, with a description or without.

The add doesn't re-encrypt the avatar: `current_avatar_url` takes its media
URL, signed as is, and the image stays encrypted under the key it was
uploaded with, which the new members never receive. X clients re-encrypt the
avatar on every key rotation: encrypt the image under the key the add
returns with `chat_xdk_encrypt_file_with_key`, upload it, and send an
[avatar change](#changing-the-avatar) naming the new key version.

A recipient's `chat_xdk_decrypt_event` returns the add as a verified
`MembersAdded` change with `member_ids`, `current_member_ids` and
`current_admin_ids`.

### Removing members

`chat_xdk_prepare_group_members_remove` removes `user_ids` and rotates the
conversation key, so the members removed don't receive the key the group
encrypts under next. Its document takes:

- `public_keys`: the identity key of every member who stays, yours
  included, as `GET /2/users/{id}/public_keys` returns them. The SDK
  encrypts the new key to each member's newest key version; a member left
  out, you included, can't read what the group sends under the new key. The
  SDK doesn't check that the list is complete. A key for a member being
  removed is an `invalid_input` error.
- `conversation_id` and `user_ids`, the members to remove.
- `title` and `description`: the group's current title and description, as
  plaintext. Pass each one the group has; the call encrypts each under the
  new key and signs it as a key-rotation re-encryption, which recipients'
  decrypt drops rather than shows as a change. The avatar is an image you
  encrypt, so the call doesn't re-encrypt it: X clients re-encrypt the
  avatar on every key rotation, so once the removal succeeds, encrypt the
  image under the new key with `chat_xdk_encrypt_file_with_key`, upload it,
  and send an [avatar change](#changing-the-avatar) naming the new key
  version.

The result is a prepared change: the new `conversation_key` (base64) and
`conversation_key_version`, `conversation_participant_keys` for the members
who stay, and `action_signatures` in request order: the removal, a title
change and a description change for the ones passed, then the
conversation-key change. Each signs at signature version 7 while the chat
sends v0, as 0.5.x readers verify, and at version 10 while it sends v1 (see
[Upgrade readers first](#upgrade-readers-first)).

```c
// 0.5.x
api_post("/2/chat/conversations/g1/members/remove", "{\"user_ids\":[\"222\"]}");

// 0.7.2
// {"public_keys": [{"user_id": "111", "identity_public_key": "...", "public_key_version": "1"},
//  {"user_id": "333", "identity_public_key": "...", "public_key_version": "1"}],
//  "conversation_id": "g1", "user_ids": ["222"], "title": "Team", "description": "About"}
char *prepared = take(chat_xdk_prepare_group_members_remove(chat, remove_json));
// POST /2/chat/conversations/g1/members/remove
// {"user_ids": ["222"], "action_signatures": <prepared.action_signatures>,
//  "group_key_rotation_data": {"conversation_key_version": <prepared.conversation_key_version>,
//   "conversation_participant_keys": <prepared.conversation_participant_keys>}}
api_post("/2/chat/conversations/g1/members/remove", remove_request_json);
```

**Encrypt under the new key as soon as the request succeeds.** The removed
members hold the old key, so a message encrypted under it is one they can
read. The key cache (`chat_xdk_set_cache_keys(chat, 1)`) adopts the new key
only once `chat_xdk_decrypt_events` decrypts the removal's key change from
the conversation's events, and only if that key change verifies against
your own signing key; until then an encrypt call that omits the key
resolves the old one. Store the new key and version, and pass them to every
encrypt and prepare call until the cache holds them:

```c
// 0.7.2
store_conversation_key("g1", prepared);

// {"conversation_id": "g1", "text": "hello", "conversation_key": "...", "conversation_key_version": "2"}
char *sent = take(chat_xdk_encrypt_message(chat, next_message_json));
```

The same holds after any call that rotates the key:
`chat_xdk_prepare_conversation_key_change`, `chat_xdk_prepare_group_create`
and `chat_xdk_prepare_group_members_change`.

On the receiving side, a batch returns the removal as a verified
`MembersRemoved` change with its `member_ids`, and the key change as a
`KeyChange` event that adds the new key to `conversation_keys` and moves
`latest_version` to it once it verifies. The title and description
re-encryptions are in `errors`, not `events` (see [Decrypt drops a
removal's title and description
re-encryptions](#decrypt-drops-a-removals-title-and-description-re-encryptions)):

```c
// 0.7.2
// {"events": ["...", "...", "...", "..."]}
char *batch = take(chat_xdk_decrypt_events(chat, decrypt_events_json));
// {"events": [{"event": {"type": "GroupChange", ..., "change": {"change_type": "MembersRemoved",
//  "member_ids": ["222"], ...}}}, {"event": {"type": "KeyChange", ...}}],
//  "conversation_keys": {"keys": {...}, "latest_version": "2"}, "errors": {"1": "...", "2": "..."}}
char *version = json_get(batch, "conversation_keys.latest_version");
```

### Leaving a group

`chat_xdk_prepare_group_leave` signs the sender's removal and does not
rotate the conversation key. `action_signatures` are the removal, then a
`GroupAdminAddChange` when `promote_admin_id` is set, then a
`ConversationDeleteEvent`, each at signature version 7, or 10 while the chat
sends v1. Send them as a removal of your own id:

```c
// 0.5.x
api_post("/2/chat/conversations/g1/members/remove", "{\"user_ids\":[\"111\"]}");

// 0.7.2
// {"conversation_id": "g1", "promote_admin_id": "333"}
char *left = take(chat_xdk_prepare_group_leave(chat, leave_json));
// POST /2/chat/conversations/g1/members/remove
// {"user_ids": ["111"], "action_signatures": <left.action_signatures>}
api_post("/2/chat/conversations/g1/members/remove", leave_request_json);
```

### Changing the title

`chat_xdk_prepare_group_title_change` takes the new title as plaintext,
encrypts it under the conversation key and signs it. Like the message
params, its params take the key and its version as `conversation_key`
(base64) and `conversation_key_version`, or resolve both from the key cache
without them. The result holds the `encrypted_value` the request sends as
`group_name`, the `conversation_key_version` it's encrypted under, and the
`action_signatures` to send with it.

```c
// 0.5.x
char *encrypted_title = take(chat_xdk_encrypt(chat, title, conversation_key_b64));
// PUT /2/chat/conversations/g1
// {"group_name": <encrypted_title>, "conversation_key_version": "2", "modified_fields": ["group_name"]}
api_put("/2/chat/conversations/g1", title_request_json);

// 0.7.2
// {"conversation_id": "g1", "new_title": "Team"}
char *prepared = take(chat_xdk_prepare_group_title_change(chat, title_json));
// PUT /2/chat/conversations/g1
// {"group_name": <prepared.encrypted_value>, "conversation_key_version": <prepared.conversation_key_version>,
//  "modified_fields": ["group_name"], "action_signatures": <prepared.action_signatures>}
api_put("/2/chat/conversations/g1", title_request_json);
```

The decrypt calls return a received title change decrypted: the `new_title`
of a `TitleChanged` change is a `GroupText` object, as a create's `title`
is. They decrypt with the key for the version the change names, from the
call's key map or the key cache. Without that key, or when the value isn't
ciphertext under it, as for a plaintext title an app signed with a key
version, it is `Unavailable` with the value as carried, and the event still
decrypts. A removal's re-encrypted title never arrives as a `TitleChanged`.
A change that removes the title decrypts to an empty title.

```c
// 0.5.x
// {"type": "GroupChange", ..., "change": {"change_type": "TitleChanged", "new_title": "<ciphertext>"}}
char *title = take(chat_xdk_decrypt(chat, json_get(group_change_json, "change.new_title"), conversation_key_b64));

// 0.7.2
// {"type": "GroupChange", ..., "change": {"change_type": "TitleChanged", "new_title": {"kind": "Text", "text": "Team"}}}
char *kind = json_get(group_change_json, "change.new_title.kind");
char *title = json_get(group_change_json, strcmp(kind, "Text") == 0 ? "change.new_title.text" : "change.new_title.raw");
```

### Changing the description

`chat_xdk_prepare_group_description_change` takes the new description as
plaintext and returns what the title change does; the request sends its
`encrypted_value` as `group_description`. A received description change is
a `DescriptionChanged` change holding `new_description` as a `GroupText`
object; read it as a title change's `new_title`. A change that removes the
description decrypts to an empty description. A removal's re-encrypted
description never arrives as one.

```c
// 0.5.x
char *encrypted_description = take(chat_xdk_encrypt(chat, description, conversation_key_b64));

// 0.7.2
// {"conversation_id": "g1", "new_description": "About"}
char *prepared = take(chat_xdk_prepare_group_description_change(chat, description_json));
// PUT /2/chat/conversations/g1
// {"group_description": <prepared.encrypted_value>,
//  "conversation_key_version": <prepared.conversation_key_version>,
//  "modified_fields": ["group_description"], "action_signatures": <prepared.action_signatures>}
api_put("/2/chat/conversations/g1", description_request_json);
```

### Changing the avatar

An avatar URL is not encrypted; the image is. Encrypt the image bytes under
the conversation key with `chat_xdk_encrypt_file_with_key`, as X clients
do, upload them to the group's media, and pass the image's media URL to
`chat_xdk_prepare_group_avatar_change` as `new_avatar_url`, with
`conversation_key_version`, the version of the key the image is encrypted
under. Unlike the title change, it takes no `conversation_key`: the image
is encrypted before the call. The call signs both as they are and returns
`action_signatures`; send them with the URL. A URL containing a comma is
rejected, since signatures join their fields with commas. Send an avatar
change after every key rotation too, with the image encrypted under the new
key, as X clients do. A received `AvatarChanged` change holds
`new_avatar_url` as sent and its `conversation_key_version`: download the
image and decrypt it with `chat_xdk_decrypt_file_with_key` under the key
for that version, as the snippet's last call does. A change that removes the
avatar holds an empty `new_avatar_url`.

```c
// 0.5.x
char *encrypted = take(chat_xdk_encrypt_stream(chat, image_b64, conversation_key_b64));
char *encrypted_avatar_url = take(chat_xdk_encrypt(chat, avatar_url, conversation_key_b64));

// 0.7.2
// {"file": "...", "key": "..."}
char *encrypted = take(chat_xdk_encrypt_file_with_key(chat, encrypt_avatar_json));
// {"conversation_id": "g1", "new_avatar_url": "https://ton.x.com/...", "conversation_key_version": "2"}
char *avatar = take(chat_xdk_prepare_group_avatar_change(chat, avatar_json));
// PUT /2/chat/conversations/g1
// {"group_avatar_url": "https://ton.x.com/...", "conversation_key_version": "2",
//  "modified_fields": ["group_avatar_url"], "action_signatures": <avatar.action_signatures>}
api_put("/2/chat/conversations/g1", avatar_request_json);
// {"encrypted": "...", "key": "..."}
char *image = take(chat_xdk_decrypt_file_with_key(chat, decrypt_avatar_json));
```

### Admins, invites, join requests, message TTL and screen capture

Each of these calls returns `action_signatures` with one entry, at signature
version 7, or 10 while the chat sends v1, for the request [The
requests](#the-requests) names. 0.5.x apps sent these requests without
signatures; recipients drop them unsigned. A recipient's decrypt returns
admin, invite and join changes as verified `GroupChange` events
(`AdminsAdded`, `AdminsRemoved`, `InviteEnabled`, `InviteDisabled`,
`JoinRequested`, `JoinRejected`) and TTL and screen-capture changes as
verified `SettingsChange` events.

```c
// 0.5.x
api_post("/2/chat/conversations/g1/admins", "{\"user_ids\":[\"333\"]}");

// 0.7.2
// {"conversation_id": "g1", "user_ids": ["333"]}
char *added = take(chat_xdk_prepare_group_admins_add(chat, admins_json));
// POST /2/chat/conversations/g1/admins {"user_ids": ["333"], "action_signatures": <added.action_signatures>}
api_post("/2/chat/conversations/g1/admins", admins_request_json);
// {"conversation_id": "g1", "user_ids": ["333"]}
char *removed = take(chat_xdk_prepare_group_admins_remove(chat, admins_json));
// POST /2/chat/conversations/g1/admins/remove {"user_ids": ["333"], "action_signatures": <removed.action_signatures>}
api_post("/2/chat/conversations/g1/admins/remove", admins_request_json);
```

An invite signs its URL, its expiry and its affiliate; an omitted
`expires_at_msec` or `affiliate_id` signs `null`. The request sends the
expiry as `validity_expiry_timestamp_msec`, and only with the same value
the params signed:

```c
// 0.7.2
// {"conversation_id": "g1", "invite_url": "https://x.com/i/chat/group_join/g1/abcdefghij",
//  "expires_at_msec": 1700000000000}
char *invite = take(chat_xdk_prepare_group_invite_enable(chat, invite_json));
// POST /2/chat/conversations/g1/invite
// {"invite_url": "https://x.com/i/chat/group_join/g1/abcdefghij",
//  "validity_expiry_timestamp_msec": "1700000000000", "action_signatures": <invite.action_signatures>}
api_post("/2/chat/conversations/g1/invite", invite_request_json);
// {"conversation_id": "g1"}
char *disabled = take(chat_xdk_prepare_group_invite_disable(chat, disable_json));
// DELETE /2/chat/conversations/g1/invite {"action_signatures": <disabled.action_signatures>}
api_delete("/2/chat/conversations/g1/invite", disable_request_json);
```

A join request signs the requesting user, who defaults to the sender; the
invite token travels in the request but not in the signature:

```c
// 0.7.2
// {"conversation_id": "g1"}
char *request = take(chat_xdk_prepare_group_join_request(chat, join_json));
// POST /2/chat/conversations/g1/join_requests {"token": "abcdefghij", "action_signatures": <request.action_signatures>}
api_post("/2/chat/conversations/g1/join_requests", join_request_json);
// {"conversation_id": "g1", "user_ids": ["444"]}
char *rejected = take(chat_xdk_prepare_group_join_reject(chat, reject_json));
// POST /2/chat/conversations/g1/join_requests/reject
// {"user_ids": ["444"], "action_signatures": <rejected.action_signatures>}
api_post("/2/chat/conversations/g1/join_requests/reject", reject_request_json);
```

A TTL change signs `ttl_msec` only; a negative one is rejected:

```c
// 0.7.2
// {"conversation_id": "g1", "ttl_msec": 86400000}
char *ttl = take(chat_xdk_prepare_message_ttl_change(chat, ttl_json));
// PUT /2/chat/conversations/g1/message_ttl {"message_ttl_ms": "86400000", "action_signatures": <ttl.action_signatures>}
api_put("/2/chat/conversations/g1/message_ttl", ttl_request_json);
// {"conversation_id": "g1"}
char *cleared = take(chat_xdk_prepare_message_ttl_remove(chat, ttl_remove_json));
// DELETE /2/chat/conversations/g1/message_ttl {"action_signatures": <cleared.action_signatures>}
api_delete("/2/chat/conversations/g1/message_ttl", ttl_remove_request_json);
```

A screen-capture change's `change` is `BlockingEnabled`,
`BlockingDisabled`, `DetectionEnabled` or `DetectionDisabled`. The request
names its signatures after the setting, `blocking_action_signatures` or
`detection_action_signatures`, not `action_signatures`:

```c
// 0.7.2
// {"conversation_id": "g1", "change": "BlockingEnabled"}
char *capture = take(chat_xdk_prepare_screen_capture(chat, capture_json));
// PUT /2/chat/conversations/g1/screen_capture
// {"blocking": true, "blocking_action_signatures": <capture.action_signatures>}
api_put("/2/chat/conversations/g1/screen_capture", capture_request_json);
```

## 5. Verify

### Build

Compile with the 0.7.2 header and `-DCHAT_XDK_JUICEBOX` if you call the
Juicebox functions, and `-Wall -Werror`: the compiler flags every call that
still passes 0.5.x arguments and every 0.5.x function the header no longer
declares. Documents are strings, which the compiler doesn't check: the
search below finds their 0.5.x fields, and a call reports the rest.

### Find the 0.5.x names

Search the app for the names in the symbol index's 0.5.x column. Each hit is
a line to change, unless it is your own code that shares the name:

```sh
grep -rnE "chat_xdk_(encrypt|encrypt_stream|decrypt_stream|encrypted_stream_size|import_keys_with_version|stream_(en|de)cryptor_\w+)\b|Stream(En|De)cryptorHandle|libchat_xdk_go|chat_xdk_dotnet|\b(encrypted_content|encoded_event_signature|generate_version|participant_keys|encrypted_key|key_version|new_text|message_ids|seen_until_id|signature_payload)\b|\"messages\b" --include='*.c' --include='*.h' --include='*.cc' --include='*.cpp' .
grep -rn "target_message_id" --include='*.c' --include='*.h' --include='*.cc' --include='*.cpp' .
```

Every `target_message_id` the second search finds should read a v1 edit's
signed message id or set it on an edit you build; rename the rest to
`target_message_sequence_id`. Each `chat_xdk_encrypt_stream` and
`chat_xdk_decrypt_stream` the first finds is a message's file or a file
under a key you hold, and [Encrypt a file under a key you
hold](#encrypt-a-file-under-a-key-you-hold) says which call each moves to.

### Run a round trip

This round trip runs offline, with two chats standing in for two users. It
registers both, starts a conversation, sends a message and decrypts it with
`chat_xdk_set_reject_unverified` on, the default, so the signature has to
verify. The documents hold only base64, ids and digits, so `snprintf`
builds them:

```c
// 0.7.2
struct ChatHandle *alice = NULL;
struct ChatHandle *bob = NULL;
take(chat_xdk_new(NULL, &alice));
take(chat_xdk_new(NULL, &bob));
char *alice_keys = take(chat_xdk_generate_keypairs(alice));
char *bob_keys = take(chat_xdk_generate_keypairs(bob));
take(chat_xdk_set_identity(alice, "{\"user_id\":\"1001\",\"signing_key_version\":\"1\"}"));
take(chat_xdk_set_identity(bob, "{\"user_id\":\"1002\",\"signing_key_version\":\"1\"}"));

char doc[8192];
snprintf(doc, sizeof doc,
         "{\"public_keys\":[{\"user_id\":\"1001\",\"identity_public_key\":\"%s\",\"public_key_version\":\"1\"},"
         "{\"user_id\":\"1002\",\"identity_public_key\":\"%s\",\"public_key_version\":\"1\"}]}",
         json_get(alice_keys, "public_key.public_key"), json_get(bob_keys, "public_key.public_key"));
char *change = take(chat_xdk_prepare_conversation_key_change(alice, doc));
char *version = json_get(change, "conversation_key_version");
snprintf(doc, sizeof doc,
         "{\"conversation_id\":\"%s\",\"text\":\"hello\",\"conversation_key\":\"%s\",\"conversation_key_version\":\"%s\"}",
         json_get(change, "conversation_id"), json_get(change, "conversation_key"), version);
char *sent = take(chat_xdk_encrypt_message(alice, doc));

char *bob_key = NULL;
for (int i = 0; i < 2 && bob_key == NULL; i++) {
    char path[64];
    snprintf(path, sizeof path, "conversation_participant_keys.%d.user_id", i);
    if (strcmp(json_get(change, path), "1002") == 0) {
        snprintf(path, sizeof path, "conversation_participant_keys.%d.encrypted_conversation_key", i);
        bob_key = take(chat_xdk_decrypt_conversation_key(bob, json_get(change, path)));
    }
}
snprintf(doc, sizeof doc,
         "{\"event_b64\":\"%s\",\"conversation_keys\":{\"%s\":\"%s\"},\"signing_keys\":[{\"user_id\":\"1001\","
         "\"public_key_version\":\"1\",\"public_key\":\"%s\",\"identity_public_key\":\"%s\","
         "\"identity_public_key_signature\":\"%s\"}]}",
         json_get(sent, "event_b64"), version, bob_key, json_get(alice_keys, "public_key.signing_public_key"),
         json_get(alice_keys, "public_key.public_key"),
         json_get(alice_keys, "public_key.identity_public_key_signature"));
char *received = take(chat_xdk_decrypt_event(bob, doc));
if (strcmp(json_get(received, "verified"), "true") != 0 || strcmp(json_get(received, "content.text"), "hello") != 0) {
    abort();
}
char *signature_version = json_get(sent, "signature_info.signature_version");
if (strcmp(signature_version, "7") != 0 && strcmp(signature_version, "10") != 0) {
    abort();
}
if (strncmp(json_get(sent, "xdk_version"), "0.7.", 4) != 0) {
    abort();
}
chat_xdk_free(alice);
chat_xdk_free(bob);
```

`signature_info.signature_version` is `"7"` for a v0 send and `"10"` for
v1, as the `v1_send` switch you hand the chat decides. `xdk_version` is the
version of the library that built the send, a 0.7 release, which the X API
receives with each send.

Then run the same flows against a test conversation on the X API: send a
text, a file, a reply, an edit and a delete, mark the conversation read,
and create a group, set its avatar, add a member and remove one. Fetch the
conversation's events with `GET /2/chat/conversations/{id}/events`, pass
`data[].encoded_event` and `meta.conversation_key_events` to
`chat_xdk_decrypt_events` with every participant's signing keys, and check
that every event in `events` has `verified` set and that `errors` holds
only the removal's title and description re-encryptions.
