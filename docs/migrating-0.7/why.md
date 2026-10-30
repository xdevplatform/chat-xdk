# Why 0.7.2 changes

This page explains why each change from 0.5.x to chat-xdk 0.7.2 was made,
and links to the lines to change in each binding's guide. The
[index](README.md) lists the guides, and the [CHANGELOG](../../CHANGELOG.md)
lists every change.

## Sends can use per-message keys

0.7.2 sends each message, reply, reaction and edit in one of two formats.
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
secrecy and no post-compromise security, still apply. A v1 send carries what
X clients' v1 sends carry: its encoded signature lists the signing keys the
message relies on, by user id and key version, its sender's and, for a
reply, those of the quoted message's sender and of its edit's, and a
reaction asks for a notification only in a one-to-one conversation, a
reaction removal or an edit never. 0.7.2 reads both formats.

## v0 is the default, and the X API's `v1_send` switch turns on v1

0.5.x decrypts message contents with the conversation key and doesn't know
signature version 10, so it rejects every v1 send as a signature
verification failure. 0.7.2 therefore sends v0, which every reader opens,
and a chat sends v1 only while the X API's `v1_send` feature switch is on
for it. The X API decides when v1 sends start, with no app release, and a
chat that can't read the switch keeps sending v0. The Rust crate and the C
ABI make no requests: a Rust app, or code that calls the C ABI directly,
makes the request itself and hands the chat its answer, under the same rules
the bindings follow, so it sends v1 when the switch says so too. The switch
sets the version of every event a chat signs, as X clients sign each event
at the version their messages sign at: while a chat sends v1, its key
changes, group changes, deletes and read receipts sign at version 10 too,
and while it sends v0 they sign at version 7, which 0.5.x verifies, apart
from a member add that carries a description, which signs at version 8, the
first that covers one. A member removal or a leave signs at those versions
too, as X clients' do, so its signature doesn't cover the key version the
removal names, which version 11 is the first to sign; the key change that
carries the new key signs its version. Upgrade the apps that read your
conversations first: [Rust](rust.md#upgrade-readers-first),
[Python](python.md#upgrade-readers-first),
[JavaScript](javascript.md#upgrade-readers-first),
[Go](go.md#upgrade-readers-first),
[JVM](jvm.md#upgrade-readers-first),
[.NET](dotnet.md#upgrade-readers-first),
[C ABI](c-abi.md#upgrade-readers-first).

## The feature-switch request

The bindings read the switches with one anonymous request,
`GET https://api.x.com/2/chat/features`, in the background. It carries no
credentials and no query parameters. Each chat reads the switches when it is
created and keeps the first answer for its lifetime, so a change to a switch
reaches the chats created after it; chats created while a request is in
flight, or waiting to be retried, share it. Every switch is off until an
answer arrives, so a chat whose `v1_send` switch is on sends v0 first and v1
from then on. Files encrypted from a v0 build of a message don't open with a
v1 build of it, so encrypt each file from the payload you send. The request
never delays or fails a call. One that fails is retried in the background
while a chat waits for its answer, 1 second later, then after twice the
previous wait, at most 5 minutes apart and 10 times, so a chat created while
the X API is briefly out of reach still follows the switch, and an endpoint
that stays blocked gets a bounded number of requests. Until an answer
arrives, and for the chat's lifetime if none does, every switch stays off,
so its sends stay in v0, the format every reader opens. The SDK decides when
to retry and what an answer means in one place, its Rust core: a binding
only performs the requests, and a body is read only up to its size limit,
never whole first. A Rust app, or code that calls the C ABI directly, hands
the core the answer to a request it made, and to each retry it makes on the
same schedule, and the core applies the same rules to it:
[Rust](rust.md#the-feature-switch-request),
[Python](python.md#the-feature-switch-request),
[JavaScript](javascript.md#the-feature-switch-request),
[Go](go.md#the-feature-switch-request),
[JVM](jvm.md#the-feature-switch-request),
[.NET](dotnet.md#the-feature-switch-request),
[C ABI](c-abi.md#the-feature-switch-request).

## User ids and key versions take one form

Signatures cover user ids as the sender wrote them, while recipients rebuild
the signed payload from the numeric ids of the delivered event, and derive
v1 message keys from the sender's. Recipients look keys up by the key
version as the event carries it, while the signatures of messages and key
changes cover its integer value, so `01` and `1` sign alike but name
different keys. Any other spelling yields a send no recipient can verify or
decrypt, so 0.7.2 checks every user id and key version, in both formats, and
fails with an error naming the field:
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
id and keeps its encrypted files valid. A file with an empty filename or a
size of 0 or less fails before anything is encrypted, since receiving
clients discard it, and so does one with a negative width or height. An
attachment without an id of its own is keyed by its position in the message,
counted as X clients count it, without payment receipts.
`decrypt_file` takes the event of the message that carries the file, which
gives the key for the message's format and version and covers media quoted
in a reply preview. v0 files use the conversation key, and the same calls
handle both formats:
[Rust](rust.md#encrypt-a-file-from-its-message),
[Python](python.md#encrypt-a-file-from-its-message),
[JavaScript](javascript.md#encrypt-a-file-from-its-message),
[Go](go.md#encrypt-a-file-from-its-message),
[JVM](jvm.md#encrypt-a-file-from-its-message),
[.NET](dotnet.md#encrypt-a-file-from-its-message),
[C ABI](c-abi.md#encrypt-a-file-from-its-message).

0.5.x `encrypt_stream` and `decrypt_stream` took any bytes and a key, so an
app picked the key for a message's file itself. Deriving it from the message
takes that choice away for files a message carries, the ones whose key
depends on the message. A file no message carries has no message to derive a
key from: a group's avatar image, which X clients encrypt under the
conversation key whose version the avatar change signs next to the avatar
URL, or an app's own files at rest. `encrypt_file_with_key` and
`decrypt_file_with_key` take the raw 32-byte key for those and encrypt the
file under it in the same file format, the one `encrypt_stream` wrote, so
files from either release open with the other's calls:
[Rust](rust.md#encrypt-a-file-under-a-key-you-hold),
[Python](python.md#encrypt-a-file-under-a-key-you-hold),
[JavaScript](javascript.md#encrypt-a-file-under-a-key-you-hold),
[Go](go.md#encrypt-a-file-under-a-key-you-hold),
[JVM](jvm.md#encrypt-a-file-under-a-key-you-hold),
[.NET](dotnet.md#encrypt-a-file-under-a-key-you-hold),
[C ABI](c-abi.md#encrypt-a-file-under-a-key-you-hold).

## Calls take params objects

Every call with more than one input takes one params value, with the same
name and fields in every binding (`SetIdentityParams`,
`DecryptEventsParams`, `EncryptFileParams` and so on), so the bindings stay
symmetric, and optional inputs are named fields that fall back to the chat's
state (identity, key cache, signing keys) when unset. Rust takes every
params value by reference and builds it with `new`, which takes the required
fields, and `with_*` methods for the optional ones, so a field can be added
without breaking callers. Python takes a params class for every encrypt and
prepare method:
[Rust](rust.md#set_identity-takes-setidentityparams),
[Python](python.md#set_identity-takes-setidentityparams),
[JavaScript](javascript.md#setidentity-takes-a-params-object),
[Go](go.md#setidentity-takes-setidentityparams),
[JVM](jvm.md#setidentity-takes-setidentityparams),
[.NET](dotnet.md#setidentity-takes-setidentityparams),
[C ABI](c-abi.md#set-the-identity-with-a-params-document).

## A key change sets the version to encrypt with only once it verifies

`decrypt_events` returns, with the keys it decrypts, the version to encrypt
new messages with. A key change carries the key it introduces whether or not
its signature verifies, and a reader that can't verify one (no signing key
for its sender yet, or a forged change) still needs its key to read
messages sent under it. Only a verified key change can set the version to
encrypt with, and that version never moves back for the chat's lifetime: a
key change from someone who can't sign for the conversation can't steer a
chat's sends to a key they chose, and a replayed older change can't roll the
version back. Every binding's `decrypt_events` result works this way:
[Rust](rust.md#decrypt_events-takes-decrypteventsparams),
[Python](python.md#decrypt_events-takes-decrypteventsparams),
[JavaScript](javascript.md#decryptevents-takes-a-params-object),
[Go](go.md#decryptevents-takes-decrypteventsparams),
[JVM](jvm.md#decryptevents-takes-decrypteventsparams),
[.NET](dotnet.md#decryptevents-takes-decrypteventsparams),
[C ABI](c-abi.md#decrypt-with-params-documents).

## Keys stored in Juicebox take their config when the chat is created

The bindings took the Juicebox config in different places: some at creation,
some on each setup and unlock call, and JS through its own options. Every
binding now takes it when the chat is created, or with `update_config` on
first boot, before the account has one, so setup and unlock take only the
PIN. Until a chat has a config, the SDK core fails its Juicebox calls before
any request, with one `invalid_state` error worded the same in every
binding. An empty or blank config string counts as none, so creating a chat
with one, or passing one to `update_config`, fails with that error at once,
in every binding, rather than at the chat's first Juicebox call. PINs are
bytes in every binding whose language can hold them that way, so an app can
zero its copy once a call returns, and the bindings whose apps run event
loops or UI threads add async forms of the Juicebox calls, which wait on
network round trips. The JS binding runs the Juicebox client itself, but the
SDK core still decides what a config means, which PINs a new registration
accepts, how many guesses a registration allows (the config's
`max_guess_count`), and how a failure reads, so every binding behaves the
same. JS also loads keys with `importKeys` and saves them with `exportKeys`,
as every binding does, without Juicebox:
[Python](python.md#keys-stored-in-juicebox),
[JavaScript](javascript.md#keys-stored-in-juicebox),
[Go](go.md#keys-stored-in-juicebox),
[JVM](jvm.md#keys-stored-in-juicebox),
[.NET](dotnet.md#keys-stored-in-juicebox),
[C ABI](c-abi.md#keys-stored-in-juicebox).

## Action signatures come nested

The requests that carry signed actions (conversation-key changes, group
changes, deletes and read receipts) take each `action_signatures` entry with
the signature nested under `message_event_signature`, next to the signer's
`signing_public_key`. The prepare methods return that shape, so apps send
the entries as returned; deletes and read receipts return a
`PreparedAction`, one entry in the same shape. Only the JSON shape is
nested; what is signed is the same, and the signed payload itself stays
inside the SDK, so a request never carries it:
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
request field for field. Its `xdk_version`, the version of the SDK that
built it, is a field of the same request. It also carries `event_b64`, the
message as recipients receive it, which the file calls take:
[Rust](rust.md#sendpayload-fields-take-the-send-requests-names),
[Python](python.md#sendpayload-fields-take-the-send-requests-names),
[JavaScript](javascript.md#sendpayload-fields-take-the-send-requests-names),
[Go](go.md#sendpayload-fields-take-the-send-requests-names),
[JVM](jvm.md#sendpayload-fields-take-the-send-requests-names),
[.NET](dotnet.md#sendpayload-fields-take-the-send-requests-names),
[C ABI](c-abi.md#the-send-payload-takes-the-send-requests-field-names).

## Participant keys take the X API's names, sent and received

The SDK names participant keys as the X API and the Thrift events do, in
both directions. A prepared change's keys are
`conversation_participant_keys`, each entry with
`encrypted_conversation_key`, the names the X API gives them in every
request that takes them (`POST /2/chat/conversations/{id}/keys`, `/group`
and `/{id}/members`, and `PUT /2/chat/conversations/{id}`), so apps pass
them through unchanged, as they pass the action signatures, instead of
renaming them. A decrypted key change carries its keys under the
same names, the ones Thrift's `ConversationKeyChangeEvent` uses, and one
type, `ConversationParticipantKey`, holds them in both directions. Sent keys:
[Rust](rust.md#participant-keys-take-the-key-requests-names),
[Python](python.md#participant-keys-take-the-key-requests-names),
[JavaScript](javascript.md#participant-keys-take-the-key-requests-names),
[Go](go.md#participant-keys-take-the-key-requests-names),
[JVM](jvm.md#participant-keys-take-the-key-requests-names),
[.NET](dotnet.md#participant-keys-take-the-key-requests-names),
[C ABI](c-abi.md#participant-keys-take-the-key-requests-names).
Received keys:
[Rust](rust.md#received-participant-keys-take-the-same-names),
[Python](python.md#received-participant-keys-take-the-same-names),
[JavaScript](javascript.md#received-participant-keys-take-the-same-names),
[Go](go.md#received-participant-keys-take-the-same-names),
[JVM](jvm.md#received-participant-keys-take-the-same-names),
[.NET](dotnet.md#received-participant-keys-take-the-same-names),
[C ABI](c-abi.md#received-participant-keys-take-the-same-names).

## A prepared change's JSON leaves out its key

A prepared change carries the new conversation key, which the app stores,
next to the participant keys, key version and action signatures its request
sends. No request takes the key itself, and a type that serializes the key
with the rest writes it into whatever it's serialized for: a request body,
a log, a queue. So the Go, JavaScript, JVM and .NET types keep the key on
the object and leave it out of their JSON (`json:"-"`, a `toJSON` without
it, `WRITE_ONLY` and `[JsonIgnore]`), as the Rust type does. Code that
stored a prepared change as JSON stores the key from the object instead.
Python returns the key in its dict, and the C ABI in its result document,
the only way the key reaches a C caller:
[Rust](rust.md#a-prepared-changes-json-leaves-out-its-key),
[Python](python.md#a-prepared-changes-json-leaves-out-its-key),
[JavaScript](javascript.md#a-prepared-changes-json-leaves-out-its-key),
[Go](go.md#a-prepared-changes-json-leaves-out-its-key),
[JVM](jvm.md#a-prepared-changes-json-leaves-out-its-key),
[.NET](dotnet.md#a-prepared-changes-json-leaves-out-its-key),
[C ABI](c-abi.md#a-prepared-changes-json-keeps-its-key).

## Public key inputs name the identity key and its version

The public keys a key change or group change encrypts a new conversation
key to name their fields `identity_public_key` and `public_key_version`, as
the signing key entries the decrypt calls take do, so one name holds one
value in every key list an app builds: the key a user's `public_key` is,
their identity key, and the version the X API gives it:
[Rust](rust.md#public-key-inputs-name-the-identity-key-and-its-version),
[Python](python.md#public-key-inputs-name-the-identity-key-and-its-version),
[JavaScript](javascript.md#public-key-inputs-name-the-identity-key-and-its-version),
[Go](go.md#public-key-inputs-name-the-identity-key-and-its-version),
[JVM](jvm.md#public-key-inputs-name-the-identity-key-and-its-version),
[.NET](dotnet.md#public-key-inputs-name-the-identity-key-and-its-version),
[C ABI](c-abi.md#public-key-inputs-name-the-identity-key-and-its-version).

## Decrypted events use the names the calls take

A decrypted event names each value as the calls that send it do, so one name
follows a value from the events an app reads to the calls it makes.
Messages and key changes carry their conversation key version as
`conversation_key_version`: the name the X API's events and the Thrift
events give it, and the name the encrypt calls take. Fields that hold
sequence ids say so, because apps deduplicate and anchor on a message's
signed `message_id`, and a field named for a message id must hold one: a
reaction or an edit names its target as `target_message_sequence_id`, a
deletion its messages as `sequence_ids`, and a read receipt or unread
marker its position as `seen_until_sequence_id`, the names the reaction,
edit, delete and read-receipt params take. An edit's text is
`updated_text`, as the edit params name it, and a v1 edit, which signs the
`message_id` of the message it edits, carries that id as
`target_message_id`:
[Rust](rust.md#decrypted-events-use-the-names-the-calls-take),
[Python](python.md#decrypted-events-use-the-names-the-calls-take),
[JavaScript](javascript.md#decrypted-events-use-the-names-the-calls-take),
[Go](go.md#decrypted-events-use-the-names-the-calls-take),
[JVM](jvm.md#decrypted-events-use-the-names-the-calls-take),
[.NET](dotnet.md#decrypted-events-use-the-names-the-calls-take),
[C ABI](c-abi.md#decrypted-events-use-the-names-the-calls-take).

## A reply preview quotes its message exactly

A reply carries a preview of the message it quotes inside its encrypted
contents, where only recipients can check it, and embeds the quoted
message's signed event so they can. X clients mark a preview invalid unless
the first 140 characters of its text, counted in UTF-16 code units, are
those of the quoted text, and its entities are exactly the quoted message's,
or its edit's. 0.5.x accepted any start of the quoted text and entities
among the quoted message's, so it showed previews as valid that X clients
mark invalid, such as one that quotes a message's first word as all of it.
0.7.2 checks a preview as X clients do, and the previews it builds pass that
check. X clients also check a v1 reply against the message it names, so each
guide builds replies from the event they quote, and a reply built from the
explicit preview fields names the quoted message by its `message_id`, as
`reply_to_message_id`. A reply embeds no key change, as X
clients' replies don't: every member receives the conversation's key
changes, so recipients open the quoted message with their own conversation
keys, or with the message key a reply carries for a v1 message, and decrypt
reads no key from inside a reply:
[Rust](rust.md#a-reply-preview-quotes-its-message-exactly),
[Python](python.md#a-reply-preview-quotes-its-message-exactly),
[JavaScript](javascript.md#a-reply-preview-quotes-its-message-exactly),
[Go](go.md#a-reply-preview-quotes-its-message-exactly),
[JVM](jvm.md#a-reply-preview-quotes-its-message-exactly),
[.NET](dotnet.md#a-reply-preview-quotes-its-message-exactly),
[C ABI](c-abi.md#a-reply-preview-quotes-its-message-exactly).

## Signatures verify at versions 8 through 11

Each signature carries its version, and each version signs its own payload
layout: version 8 adds a group's description to member adds, 9 appends the
signature version and a group create's type, 10 covers
`contents_encryption_version` and a group create's TTL, and 11 adds the key
version to group member removals. Every version signs the key version of a
message or key change as an integer, a message's as `null` when it isn't
one, and a removed group title, description or avatar as `null`, as X
clients sign them. 0.7.2 rebuilds each payload in the layout of the version
its signature carries, so events signed at 8 through 11 verify, including
the events it signs at 10 while it sends v1 and the member adds with a
description it signs at 8. Versions above 11 are rejected, since their
layout is unknown ([CRYPTO.md](../CRYPTO.md#verifying-newer-versions)), and
so is a signature without a version, or with one that isn't an integer,
which 0.5.x verified as version 7: the version picks the layout, so a
missing one names none. There's no code to change to read them. 0.5.x
readers rebuild the layouts up to 7 only, so they can't verify what a chat
signs while it sends v1, or member adds with a description while it sends
v0: each guide says to upgrade readers first.

## Read receipts are signed

Recipients on the default policy drop an unsigned read receipt, as 0.5.x
recipients did, so a receipt the X API sends without a signature never
reaches them. `prepare_mark_conversation_read` signs it: send the
`PreparedAction`'s `action_signatures` on
`POST /2/chat/conversations/{id}/read`, and a recipient's `decrypt_event`
returns the receipt as a verified `ReadReceipt`:
[Rust](rust.md#read-receipts-are-signed),
[Python](python.md#read-receipts-are-signed),
[JavaScript](javascript.md#read-receipts-are-signed),
[Go](go.md#read-receipts-are-signed),
[JVM](jvm.md#read-receipts-are-signed),
[.NET](dotnet.md#read-receipts-are-signed),
[C ABI](c-abi.md#read-receipts-are-signed).

## Group changes are signed

Recipients on the default policy drop a group change that isn't signed, as
0.5.x recipients did, so each group change carries the signatures of the
actions it performs, and each guide gives every change's request, with its
X API method, path and body. Removing members rotates the conversation key,
so the members removed don't receive the key the group encrypts under next:
`prepare_group_members_remove` takes the public keys of every member who
stays, the remover's included, and returns a `PreparedConversationChange`
with the new key, and `POST /2/chat/conversations/{id}/members/remove` sends
`group_key_rotation_data` with its signatures. Leaving signs the sender's
removal, then an admin add when `promote_admin_id` is set, then a
conversation delete, and does not rotate the key. Admin, invite, and join
changes, message-TTL changes, and screen-capture changes each return a
`PreparedAction`.

A group's title and description are encrypted under the conversation key,
and the SDK encrypts them: a group create, a member add, the title and
description changes, and a removal take the plaintext and return the
encrypted values with their signatures, so an app never encrypts a title
itself and no plaintext title reaches the X API. A create encrypts its title
under the key it creates and returns it for its request's `group_name`. The
changes resolve the key as `encrypt_message` does. A member add and a
removal rotate the key, so each re-encrypts the title and description the
app passes under the new key. An add signs both in the member add, so the
new members can read them, and returns the title for its request. A removal
signs each between the removal and the key change, marked as a key-rotation
re-encryption, which decrypt drops (see [Decrypt drops a removal's title and
description
re-encryptions](#decrypt-drops-a-removals-title-and-description-re-encryptions)).

An avatar is an image, and X clients encrypt the image, not its URL: the app
encrypts the image under the conversation key with `encrypt_file_with_key`
and uploads it to the group's media, and the X API checks the URL against
that media. So the avatar change signs the media URL as is, with the version
of the key the image is encrypted under, and the decrypt calls return both
for a received avatar change. The image is the app's to encrypt, so the
calls that rotate the key don't re-encrypt it; X clients re-encrypt the
avatar under the new key on every rotation, and an app does the same: it
encrypts the image under the new key, uploads it, and sends an avatar change
naming the new key version. A create sets no avatar, as X clients' creates
normally don't; the app sets one with an avatar change.

`decrypt_event` and `decrypt_events` decrypt a received create's title and a
received title or description change into a `GroupText`. A value they can't
decrypt, because its key is missing or it doesn't decrypt under it, comes
back unavailable with the value as carried instead of failing the event, so
the rest of the event, such as a create's members and admins, still reads.
0.5.x apps signed titles as plaintext while naming a key version, so an app
shows the raw value when a title isn't decryptable. A change that removes
the title, description or avatar, which X clients sign with `null` in its
place, decrypts to an empty value. Each guide shows the calls and how to
read a `GroupText`: [Rust](rust.md#group-changes-are-signed),
[Python](python.md#group-changes-are-signed),
[JavaScript](javascript.md#group-changes-are-signed),
[Go](go.md#group-changes-are-signed),
[JVM](jvm.md#group-changes-are-signed),
[.NET](dotnet.md#group-changes-are-signed), [C
ABI](c-abi.md#group-changes-are-signed).

## Decrypt drops a removal's title and description re-encryptions

A member removal rotates the conversation key, and the remover re-encrypts
the group's title and description under the new key, so the members who
stay can still read them. Each re-encryption is a title or description
change that carries the same text as before, marked `for_key_rotation`. It
isn't a change, and an app that shows every title change would show each
removal as a rename, so `decrypt_events` and `decrypt_event` drop these
events the way they drop an unverified one: `decrypt_events` leaves each
out of `events` and records it in `errors`, and `decrypt_event` fails with
an invalid-input error that says why. Nothing else is dropped: the removal
itself, the key change that carries the new key and moves the version to
encrypt with, avatar changes, and every title or description change without
the mark decrypt as before.

The mark sits outside the signed payload: a group change's signature covers
its event name, message id, sender, conversation, key version and encrypted
value, not `for_key_rotation`. Dropping on it is still safe. Decrypt
verifies an event before it reads the mark, so an event that doesn't verify
fails as unverified. A relay that sets the mark on a real title change only
hides that change, which it can do anyway by not delivering the event, and
a relay that clears it on a re-encryption makes the event show as a title
change to the same text, as 0.5.x showed it. The drop applies under either
`reject_unverified` setting, since it concerns what the event is rather
than whether it verified:
[Rust](rust.md#decrypt-drops-a-removals-title-and-description-re-encryptions),
[Python](python.md#decrypt-drops-a-removals-title-and-description-re-encryptions),
[JavaScript](javascript.md#decrypt-drops-a-removals-title-and-description-re-encryptions),
[Go](go.md#decrypt-drops-a-removals-title-and-description-re-encryptions),
[JVM](jvm.md#decrypt-drops-a-removals-title-and-description-re-encryptions),
[.NET](dotnet.md#decrypt-drops-a-removals-title-and-description-re-encryptions),
[C ABI](c-abi.md#decrypt-drops-a-removals-title-and-description-re-encryptions).

## The app passes a new key until its key change returns

A call that rotates the conversation key (a member removal, a member add, a
group create or a key change) returns the new key, and the app sends the
key change in its request. The key cache (`set_cache_keys`) holds only the
key of a key change that verified, at the newest version that verified, so
a key change from someone who can't sign for the conversation, or an older
one replayed, can't steer a chat's sends to a key they chose. A prepare
call's key is in no verified key change yet: it reaches the conversation
once the X API accepts the request, and the chat's cache adopts it once
`decrypt_events` decrypts that key change and verifies it. Until then an
encrypt call that leaves out the key resolves the old one, which the
members a removal removed still hold. So each guide stores the new key and
version and passes them to the encrypt and prepare calls until the cache
holds them:
[Rust](rust.md#removing-members),
[Python](python.md#removing-members),
[JavaScript](javascript.md#removing-members),
[Go](go.md#removing-members),
[JVM](jvm.md#removing-members),
[.NET](dotnet.md#removing-members),
[C ABI](c-abi.md#removing-members).

## Errors carry their kind

Apps react differently to a bad argument, missing setup, a forged event and
a wrong PIN, and reading that from a message's text breaks when the text
changes. Every error has a kind, which the SDK core assigns once and every
binding reports the same way: an exception class in Python, a kind on the
error in the other bindings, and a `kind` in the C ABI's error document. A
wrong PIN carries the attempts Juicebox reports left as a number, not text
to parse. A missing or invalid parameter fails with an error that names the
value (`SdkError::InvalidInput` in Rust), without the `Invalid state:`
prefix, which is left for state the chat lacks, such as a missing identity
or an empty key cache. An entity of a type the protocol doesn't have fails
the same way: dropping it, as 0.5.x did, sent a message that differed from
the one the app built, without saying so. So do entity offsets outside the
text, counted in bytes of its UTF-8 encoding, a URL card without a url and a
post attachment without an id or a URL, which receivers can't place or open.
Calls that answered with a bare result, such as `verify` and `export_keys`,
report the core's error too, rather than a generic failure or no value:
[Rust](rust.md#errors-carry-their-kind),
[Python](python.md#errors-carry-their-kind),
[JavaScript](javascript.md#errors-carry-their-kind),
[Go](go.md#errors-carry-their-kind),
[JVM](jvm.md#errors-carry-their-kind),
[.NET](dotnet.md#errors-carry-their-kind),
[C ABI](c-abi.md#errors-carry-their-kind).

## `sign` refuses data only the SDK signs

The signing key signs every event an app sends: messages, key changes,
group and conversation changes, deletes and read receipts. A recipient
verifies each by rebuilding its payload from the event and checking the
signature over those bytes. A signature that `sign` returned over bytes
that read as such a payload would verify as that event, and one over a
P-256 public key would bind it as an identity key, the binding recipients
check before they trust a key pair. So `sign` refuses both with an
invalid-input error and signs any other data as before; the SDK signs
events on its own path:
[Rust](rust.md#sign-refuses-data-only-the-sdk-signs),
[Python](python.md#sign-refuses-data-only-the-sdk-signs),
[JavaScript](javascript.md#sign-refuses-data-only-the-sdk-signs),
[Go](go.md#sign-refuses-data-only-the-sdk-signs),
[JVM](jvm.md#sign-refuses-data-only-the-sdk-signs),
[.NET](dotnet.md#sign-refuses-data-only-the-sdk-signs),
[C ABI](c-abi.md#chat_xdk_sign-refuses-data-only-the-sdk-signs).

## Smaller changes

- The TypeScript typings declare only what the package exports, so a type
  that compiles names something that exists at run time
  ([JavaScript](javascript.md#typescript-import-the-types-the-package-exports)).
- The JVM file methods throw the unchecked `ChatXdkException` and declare no
  checked exceptions ([JVM](jvm.md#exceptions)).
- One crate, `chat-xdk-ffi`, builds the C ABI library of every binding over
  it, so Go, .NET and the JVM call the same functions with the same
  behavior. The ABI has a version, which the library reports, every call
  returns its result and error the same way, and the header declares the
  Juicebox calls only for a library built with them
  ([C ABI](c-abi.md#check-the-abi-version)).
- Python types the dicts its calls take and return with exported
  `TypedDict`s, so a type checker reads them
  ([Python](python.md#key-entries-and-results-have-named-types)).
- .NET params documents omit a field left `null`, so a missing value fails
  with an error that names it
  ([.NET](dotnet.md#a-params-property-left-null-is-left-out)), and .NET and
  JVM descriptors and the JVM's
  key entries take their required values in their constructors, so leaving
  one out doesn't compile: no stand-in `""` or `0` reaches the core
  ([JVM](jvm.md#descriptors-and-key-entries-take-their-values-in-constructors),
  [.NET](dotnet.md#entities-and-preview-images-take-their-values-in-the-constructor)).
- Rust's public enums, params structs and result structs, `SendPayload`
  among them, are `#[non_exhaustive]`, so a variant or field can be added
  without breaking code that builds params with `new` and `with_*`, reads
  results, and matches enums with a wildcard arm
  ([Rust](rust.md#types-are-non_exhaustive)).
- The JVM and .NET packages bundle the native library for 64-bit ARM Linux,
  so apps there need no copy of their own; a library built for 0.5.x doesn't
  export the entry points 0.7.2 calls
  ([JVM](jvm.md#the-jar-bundles-the-linux-arm64-native-library),
  [.NET](dotnet.md#the-package-bundles-the-linux-arm64-native-library)).
