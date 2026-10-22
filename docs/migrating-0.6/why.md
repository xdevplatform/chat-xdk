# Why 0.6.0 changes

This page explains why each change in chat-xdk 0.6.0 was made, and links to
the lines to change in each binding's guide. The [index](README.md) lists
the guides, and the [CHANGELOG](../../CHANGELOG.md) lists every change.

## Sends can use per-message keys

0.6.0 sends each message, reply, reaction and edit in one of two formats.
v0 is the format 0.5.x sends: contents encrypted under the conversation key,
signed at signature version 7. v1 encrypts each message under its own
message key, derived with HKDF-SHA256 from the conversation key, the sender
id and the message id, sets `contents_encryption_version` 1 and signs at
signature version 10 ([CRYPTO.md](../CRYPTO.md#message-keys)). Every event
that carries message contents then has its own key, so a reply to a v1
message carries that message's key, for recipients to open the preview, and
never the conversation key. Version 10 signs `contents_encryption_version`,
so a message's choice of key can't be changed or stripped without breaking
its signature. Message keys derive from the conversation key, so the
protocol's [known limitations](../CRYPTO.md#known-limitations), no forward
secrecy and no post-compromise security, still apply. 0.6.0 reads both
formats.

## v0 is the default, and the X API's `v1_send` switch turns on v1

0.5.x decrypts message contents with the conversation key and doesn't know
signature version 10, so it rejects every v1 send as a signature
verification failure. 0.6.0 therefore sends v0, which every reader opens,
and a chat sends v1 only while the X API's `v1_send` feature switch is on
for it. The X API decides when v1 sends start, with no app release, and a
chat that can't read the switch keeps sending v0. No public API turns v1
on, and the Rust crate and the C ABI make no requests, so they always send
v0. Upgrade the apps that read your conversations first:
[Rust](rust.md#upgrade-readers-before-v1-sends-start),
[Python](python.md#upgrade-readers-before-v1-sends-start),
[JavaScript](javascript.md#upgrade-readers-before-v1-sends-start),
[Go](go.md#upgrade-readers-before-v1-sends-start),
[JVM](jvm.md#upgrade-readers-before-v1-sends-start),
[.NET](dotnet.md#upgrade-readers-before-v1-sends-start),
[C ABI](c-abi.md#upgrade-readers-before-v1-sends-start).

## The feature-switch request

The bindings read the switches with one anonymous request,
`GET https://api.x.com/2/chat/features`, in the background. It carries no
credentials and no query parameters. Each chat reads the switches once, when
it is created, and keeps the answer for its lifetime, so a change to a switch
reaches the chats created after it; chats created while a request is in
flight share it. The request never delays or fails a call, and any failure
leaves every switch off for the chat's lifetime, so its sends stay in v0, the
format every reader opens:
[Python](python.md#the-feature-switch-request),
[JavaScript](javascript.md#the-feature-switch-request),
[Go](go.md#the-feature-switch-request),
[JVM](jvm.md#the-feature-switch-request),
[.NET](dotnet.md#the-feature-switch-request).

## User ids and key versions take one form

Signatures cover user ids as the sender wrote them, while recipients rebuild
the signed payload from the numeric ids of the delivered event, and derive
v1 message keys from the sender's. Recipients look keys up by the key version
as the event carries it, while signatures from version 8 on cover its
integer value, so `01` and `1` sign alike but name different keys. Any
other spelling yields a send no recipient can verify or decrypt, so 0.6.0
checks every user id and key version, in both formats, and fails with an
error naming the field:
[Rust](rust.md#user-ids-are-strings-of-digits),
[Python](python.md#user-ids-are-strings-of-digits),
[JavaScript](javascript.md#user-ids-are-strings-of-digits),
[Go](go.md#user-ids-are-strings-of-digits),
[JVM](jvm.md#user-ids-are-strings-of-digits),
[.NET](dotnet.md#user-ids-are-strings-of-digits),
[C ABI](c-abi.md#user-ids-and-key-versions-are-strings-of-digits).

## Key registration sends only the public key

The X API registers keys under the `public_key_version` its response to
`POST /2/users/{id}/public_keys` returns, and that is the version every
signed action must carry. So the registration payload holds only the public
key, the SDK picks no version for new keys, and the app sets the one the
registration returns. A signed call made without a version fails in the SDK
rather than sending one the X API rejects:
[Rust](rust.md#register-keys-with-the-public-key-only),
[Python](python.md#register-keys-with-the-public-key-only),
[JavaScript](javascript.md#register-keys-with-the-public-key-only),
[Go](go.md#register-keys-with-the-public-key-only),
[JVM](jvm.md#register-keys-with-the-public-key-only),
[.NET](dotnet.md#register-keys-with-the-public-key-only),
[C ABI](c-abi.md#register-keys-with-the-public-key-only).

## A file is encrypted from its message

In v1 each file is encrypted under a key derived from the message key and
the file's attachment, so a file's key depends on the message that carries
it. `encrypt_file` takes the message's `event_b64` and the file's media hash
key, finds the attachment in the message and derives its key. That sets the
order: start the upload, whose `media_hash_key` names the file in the
message and whose size `encrypted_file_size` gives before encryption, build
the message, then encrypt and upload the file. A v1 message with files takes
an id derived from them, so building the same message again gives the same
id and keeps its encrypted files valid. `decrypt_file` takes the event of the
message that carries the file, which gives the key for the message's format
and version and covers media quoted in a reply preview. v0 files use the
conversation key, and the same calls handle both formats:
[Rust](rust.md#encrypt-a-file-from-its-message),
[Python](python.md#encrypt-a-file-from-its-message),
[JavaScript](javascript.md#encrypt-a-file-from-its-message),
[Go](go.md#encrypt-a-file-from-its-message),
[JVM](jvm.md#encrypt-a-file-from-its-message),
[.NET](dotnet.md#encrypt-a-file-from-its-message),
[C ABI](c-abi.md#encrypt-a-file-from-its-message).

## Calls take params objects

Every call with more than one input takes one params value, with the same
name and fields in every binding (`SetIdentityParams`,
`DecryptEventsParams`, `EncryptFileParams` and so on), so the bindings stay
symmetric, and optional inputs are named fields that fall back to the chat's
state (identity, key cache, signing keys) when unset. Rust takes every
params value by reference, and Python takes a params class for every encrypt
and prepare method:
[Rust](rust.md#set_identity-takes-setidentityparams),
[Python](python.md#set_identity-takes-setidentityparams),
[JavaScript](javascript.md#setidentity-takes-a-params-object),
[Go](go.md#setidentity-takes-setidentityparams),
[JVM](jvm.md#setidentity-takes-setidentityparams),
[.NET](dotnet.md#setidentity-takes-setidentityparams),
[C ABI](c-abi.md#set-the-identity-with-a-params-document).

## Action signatures come nested

The requests that carry signed actions (conversation-key changes, group
changes, deletes and read receipts) take each `action_signatures` entry with
the signature nested under `message_event_signature`, next to the signer's
`signing_public_key`. The prepare methods return that shape, so apps send
the entries as returned; deletes and read receipts return a
`PreparedAction`, one entry in the same shape. Only the JSON shape is
nested; what is signed is the same:
[Rust](rust.md#action-signatures-come-nested),
[Python](python.md#action-signatures-come-nested),
[JavaScript](javascript.md#action-signatures-come-nested),
[Go](go.md#action-signatures-come-nested),
[JVM](jvm.md#action-signatures-come-nested),
[.NET](dotnet.md#action-signatures-come-nested),
[C ABI](c-abi.md#action-signatures-come-nested).

## `SendPayload` uses the send request's field names

`SendPayload`'s encoded fields are `encoded_message_create_event` and
`encoded_message_event_signature`, the field names of
`POST /2/chat/conversations/{id}/messages`, so the payload maps onto the
request field for field. It also carries `event_b64`, the message as
recipients receive it, which the file calls take, and `xdk_version`, the
version of the SDK that built it:
[Rust](rust.md#sendpayload-fields-take-the-send-requests-names),
[Python](python.md#sendpayload-fields-take-the-send-requests-names),
[JavaScript](javascript.md#sendpayload-fields-take-the-send-requests-names),
[Go](go.md#sendpayload-fields-take-the-send-requests-names),
[JVM](jvm.md#sendpayload-fields-take-the-send-requests-names),
[.NET](dotnet.md#sendpayload-fields-take-the-send-requests-names),
[C ABI](c-abi.md#the-send-payload-takes-the-send-requests-field-names).

## Signatures verify at versions 8 through 11

Each signature carries its version, and each version signs its own payload
layout: version 8 signs key versions as integers, 9 appends the signature
version, 10 covers `contents_encryption_version`, and 11 adds the key
version to group member removals. 0.6.0 rebuilds each payload in the layout
of the version its signature carries, so events signed at 8 through 11
verify, including the v1 sends it signs at 10. Versions above 11 are
rejected, since their layout is unknown
([CRYPTO.md](../CRYPTO.md#verifying-newer-versions)). There's no code to
change.

## Read receipts can be signed

Under the default policy, `decrypt_event` rejects an unverified read
receipt. `prepare_mark_conversation_read` signs one: its `PreparedAction`
goes in the `action_signatures` of the mark-read request,
`POST /2/chat/conversations/{id}/read`, and recipients' `decrypt_event`
returns the receipt as a verified `ReadReceipt`:
[Rust](rust.md#signed-read-receipts),
[Python](python.md#signed-read-receipts),
[JavaScript](javascript.md#signed-read-receipts),
[Go](go.md#signed-read-receipts),
[JVM](jvm.md#signed-read-receipts),
[.NET](dotnet.md#signed-read-receipts),
[C ABI](c-abi.md#signed-read-receipts).

## Invalid input has its own error

A missing or invalid parameter fails with an error that names the value
(`SdkError::InvalidInput` in Rust), without the `Invalid state:` prefix,
which is left for state the chat lacks, such as a missing identity or an
empty key cache. Callers can tell a bad argument from missing setup:
[Rust](rust.md#invalid-input-errors),
[Python](python.md#invalid-input-errors),
[JavaScript](javascript.md#invalid-input-errors),
[Go](go.md#invalid-input-errors),
[JVM](jvm.md#invalid-input-errors),
[.NET](dotnet.md#invalid-input-errors),
[C ABI](c-abi.md#invalid-input-errors).

## Smaller changes

- The TypeScript typings declare only what the package exports, so a type
  that compiles names something that exists at run time
  ([JavaScript](javascript.md#typescript-import-the-types-the-package-exports)).
- The JVM file methods throw the unchecked `ChatXdkException` and declare no
  checked exceptions ([JVM](jvm.md#exceptions)).
- C ABI entry points whose arguments differ from 0.5.x take new names, so a
  stale header or library fails to link instead of misreading its arguments
  ([C ABI](c-abi.md)).
- Rust's `SendPayload` is `#[non_exhaustive]`, so a field can be added to it
  without breaking code that reads it
  ([Rust](rust.md#sendpayload-fields-take-the-send-requests-names)).
- The JVM and .NET packages bundle the native library for 64-bit ARM Linux,
  so apps there need no copy of their own; a library built for 0.5.x doesn't
  export the entry points 0.6.0 calls
  ([JVM](jvm.md#the-jar-bundles-the-linux-arm64-native-library),
  [.NET](dotnet.md#the-package-bundles-the-linux-arm64-native-library)).
