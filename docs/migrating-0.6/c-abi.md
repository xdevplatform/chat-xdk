# Migrating C ABI callers to chat-xdk 0.6.0

This page lists every change that code calling the chat-xdk C ABI directly
runs into in 0.6.0, coming from 0.5.x (0.5.0, 0.5.1 or 0.5.2). The ABI is
declared in
[`go/chatxdk/include/chat_xdk.h`](../../go/chatxdk/include/chat_xdk.h), and
the native libraries in the .NET and JVM packages export the same functions.
The language bindings have their own pages, listed in the
[index](README.md).

Every entry point whose arguments changed takes a new name, so a stale
header or library fails to link instead of misreading its arguments.

## Checklist

- [ ] [Upgrade every app that reads your conversations first](#upgrade-readers-before-v1-sends-start)
- [ ] [Register keys with the public key only](#register-keys-with-the-public-key-only)
- [ ] [Set the identity with `chat_xdk_set_identity_params`](#set-the-identity-with-a-params-document)
- [ ] [Import keys with `chat_xdk_import_keys_params`](#import-keys-with-a-params-document)
- [ ] [Pass user ids and key versions as strings of digits](#user-ids-and-key-versions-are-strings-of-digits)
- [ ] [Decrypt with `chat_xdk_decrypt_events_params` and `chat_xdk_decrypt_event_params`](#decrypt-with-params-documents)
- [ ] [Read the send payload under the send request's field names](#the-send-payload-takes-the-send-requests-field-names)
- [ ] [Don't send `xdk_version` yet](#xdk_version-dont-send-it-yet)
- [ ] [Build a message before you encrypt its files](#encrypt-a-file-from-its-message)
- [ ] [Decrypt a file with the event of its message](#decrypt-a-file-with-its-messages-event)
- [ ] [Use the file encryptor and decryptor for large files](#encrypt-and-decrypt-large-files-in-chunks)
- [ ] [Pass action signatures through as returned](#action-signatures-come-nested)
- [ ] [Check code that reads error messages](#invalid-input-errors)
- [ ] [Optional: sign read receipts (pending)](#signed-read-receipts-new-pending)

## About the snippets

Each snippet shows the lines that change, first as 0.5.x code writes them
and then as 0.6.0 code writes them. `chat` is a `ChatHandle *` with your
keys loaded, and `keys`, `keys_len` and `keys_b64` are your saved private
keys. `take(r)` stands for your error handling: it returns `r.data` (free it
with `chat_xdk_free_string`) and handles `r.error`. The `*_json` and `*_b64`
values are documents and base64 strings your code builds, and
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
bindings send v1 once the X API turns on its `v1_send` feature switch.

0.5.x rejects every v1 send as a signature verification failure, so upgrade
every app that reads your conversations to 0.6.0 before any sender can send
v1. 0.6.0 reads both formats, including v1 reply previews, edits and files.
There's no code to change: to see which format a send used, read the send
payload's `signature_info.signature_version`, `"7"` for v0 and `"10"` for
v1.

## Register keys with the public key only

`chat_xdk_generate_keypairs` returns a document that holds only
`public_key`. POST it to `POST /2/users/:id/public_keys` as returned. 0.6.0
doesn't pick a signing-key version for new keys: after you register, set the
identity with the `public_key_version` the X API returns (see the next
section). A signed call made without a version fails with `Invalid state:
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
`encoded_message_event_signature`, the send request's field names, so the
request takes them as they are. It also carries `event_b64`, the message as
recipients receive it: keep it to encrypt the message's files (see
[Encrypt a file from its message](#encrypt-a-file-from-its-message)).

## `xdk_version`: don't send it yet

The send payload's `xdk_version` is the version of the SDK that built it.
Don't add it to the send request yet: the request takes it as an optional
field only once the X API documents that field.

## Encrypt a file from its message

Each file is encrypted from the message that carries it, so build the
message first: start each file's upload, declaring
`chat_xdk_encrypted_file_size` of the file's size, encrypt the message with
attachments that name the media hash keys, then encrypt each file with
`chat_xdk_encrypt_file`, passing the payload's `event_b64` and the file's
media hash key. Like the message, the file takes `conversation_key` and
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
under `message_event_signature` alongside your `signing_public_key`. A
prepared change's `participant_keys` keep their shape.
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

## Invalid input errors

A missing or invalid parameter fails with an error whose message names the
value, such as `Invalid sender_id 'user-1': pass a numeric user id (digits
only)` or `too many attachments: at most 10 per message`, without an
`Invalid state:` prefix. If your code looks for that prefix on these errors,
match the message instead. Errors about state the chat lacks, such as a
missing session identity or an empty key cache, keep their prefix.

## Signed read receipts (new, pending)

`chat_xdk_prepare_mark_conversation_read` signs a read receipt for the
newest event you read. It takes a document with `conversation_id`,
`seen_until_sequence_id` (that event's sequence id) and an optional
`seen_at_msec` that defaults to now, and returns `action_signatures` as a
delete does. A recipient's `chat_xdk_decrypt_event_params` returns a signed
receipt as a verified `ReadReceipt` event.

**Pending:** the X API's mark-read route doesn't take `action_signatures`
yet, so the shape of that request may change when it does.

```c
// 0.6.0
// {"conversation_id":"...","seen_until_sequence_id":"..."}
char *receipt = take(chat_xdk_prepare_mark_conversation_read(chat, mark_read_json));
```
