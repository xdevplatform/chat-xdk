# Migrating Go code to chat-xdk 0.7.2

This page moves Go code written for
`github.com/xdevplatform/chat-xdk/go/chatxdk` 0.5.x (0.5.0, 0.5.1 or 0.5.2)
to 0.7.2. Work through it top to bottom: [Before you
start](#0-before-you-start) sets up the upgrade, the [symbol
index](#1-symbol-index) maps every 0.5.x name to its 0.7.2 form,
[Compile-time changes](#2-compile-time-changes) and [Runtime
changes](#3-runtime-and-behavior-changes) show each line to change, [Group
and receipt signing](#4-group-and-receipt-signing) gives every signed
request, and [Verify](#5-verify) checks the result. [Why 0.7.2
changes](why.md) explains each change, and the [index](README.md) lists the
other bindings' pages. [API.md](../API.md) documents every call.

## Checklist

Each item is tagged with what it takes: `[rollout]` is a deployment step,
`[compile]` a change the compiler reports, `[runtime]` a change in behavior
that nothing reports, and `[new]` a 0.7.2 call to adopt.

- [ ] `[rollout]` [Install 0.7.2](#install-072)
- [ ] `[rollout]` [Upgrade every app that reads your conversations first](#upgrade-readers-first)
- [ ] `[rollout]` [Allow or block the feature-switch request](#the-feature-switch-request)
- [ ] `[compile]` [Create a Juicebox chat with `NewWithJuiceboxConfig`, and pass `Setup` and `Unlock` only the PIN](#keys-stored-in-juicebox)
- [ ] `[compile]` [Register keys with the public key only](#register-keys-with-the-public-key-only)
- [ ] `[compile]` [Pass a `SetIdentityParams` to `SetIdentity`](#setidentity-takes-setidentityparams)
- [ ] `[compile]` [Pass an `ImportKeysParams` to `ImportKeys`](#importkeys-takes-importkeysparams)
- [ ] `[compile]` [Pass a `DecryptEventsParams` to `DecryptEvents` and read its `Events`](#decryptevents-takes-decrypteventsparams)
- [ ] `[compile]` [Pass a `DecryptEventParams` to `DecryptEvent`](#decryptevent-takes-decrypteventparams)
- [ ] `[compile]` [Read `SendPayload` under the send request's field names and send `xdk_version`](#sendpayload-fields-take-the-send-requests-names)
- [ ] `[compile]` [Build a message before you encrypt its files](#encrypt-a-file-from-its-message)
- [ ] `[compile]` [Decrypt a file with the event of its message](#decrypt-a-file-with-its-messages-event)
- [ ] `[compile]` [Encrypt a file no message carries, such as a group avatar, with `EncryptFileWithKey`](#encrypt-a-file-under-a-key-you-hold)
- [ ] `[compile]` [Use `FileEncryptor` and `FileDecryptor` for large files](#encrypt-and-decrypt-large-files-in-chunks)
- [ ] `[compile]` [Pass action signatures through as returned](#action-signatures-come-nested)
- [ ] `[compile]` [Name a `PublicKeyInput`'s fields `IdentityPublicKey` and `PublicKeyVersion`](#public-key-inputs-name-the-identity-key-and-its-version)
- [ ] `[compile]` [Pass participant keys through as returned](#participant-keys-take-the-key-requests-names)
- [ ] `[compile]` [Read received participant keys under the same names](#received-participant-keys-take-the-same-names)
- [ ] `[compile]` [Read a delete's signature from its `PreparedAction`](#deletes-return-a-preparedaction)
- [ ] `[compile]` [Read decrypted events under the names the calls take](#decrypted-events-use-the-names-the-calls-take)
- [ ] `[compile]` [Read an error's kind and a wrong PIN's attempts from `*chatxdk.Error` with `errors.As`](#errors-carry-their-kind)
- [ ] `[runtime]` [Pass user ids as strings of digits](#user-ids-are-strings-of-digits)
- [ ] `[runtime]` [Pass key versions as the X API returns them](#key-versions-are-integers-written-as-strings)
- [ ] `[runtime]` [Pass entities, files, URL cards and posts the SDK accepts](#entities-files-url-cards-and-posts-are-checked)
- [ ] `[runtime]` [Store every participant's signing keys, and handle a nil `LatestVersion`](#latestversion-comes-from-a-verified-key-change)
- [ ] `[runtime]` [Rename every read of `target_message_id` to `target_message_sequence_id`](#target_message_id-holds-a-different-value)
- [ ] `[runtime]` [Reply with `ReplyToEvent`, whose preview recipients check exactly](#a-reply-preview-quotes-its-message-exactly)
- [ ] `[runtime]` [Store a prepared change's key yourself, not through `json.Marshal`](#a-prepared-changes-json-leaves-out-its-key)
- [ ] `[runtime]` [Sign only your own data with `Sign`](#sign-refuses-data-only-the-sdk-signs)
- [ ] `[runtime]` [Skip the events `DecryptEvent` drops](#decrypt-drops-a-removals-title-and-description-re-encryptions)
- [ ] `[runtime]` [Check for keys before `ExportKeys`](#exportkeys-fails-without-keys)
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
0.7.2 half of every snippet on this page against 0.7.2 with `go vet`
([`scripts/check_doc_snippets.py`](../../scripts/check_doc_snippets.py)).

`chat` is a `*chatxdk.Chat` with your keys loaded, and the other names stand
for your own values: ids, versions, keys and events as the X API returns
them, `keys` for the conversation key map `DecryptEvents` returns, `payload`
for a `*SendPayload`, `prepared` for a `*PreparedConversationChange`,
`keyChange`, `message`, `receipt` and `groupChange` for a decrypted
`*KeyChangeEvent`, `*Message`, `ReadReceiptEvent` and `*GroupChangeEvent`,
`event` for a decrypted `*Event`, and `page` for a page of
`GET /2/chat/conversations/{id}/events`, decoded into a struct whose `Data`
holds each event's `ID` and `EncodedEvent`. `must(err)` stands for your
error handling. `api.Post(path, body)`, `api.Put(path, body)` and
`api.Delete(path, body)` stand for your HTTP client: each sends `body` as
JSON to `https://api.x.com` + `path` with your user access token and returns
the parsed JSON response as a `map[string]any`. `pathID` is the conversation
id as a request path takes it: a group's `g…` id as is, and a one-to-one's
in its hyphen form, `strings.ReplaceAll(conversationID, ":", "-")`.
`photoAttachment(mediaHashKey)` stands for your code that builds a photo's
`AttachmentDescriptor`; `showReaction`, `showTitle`, `showDescription`,
`showAvatar`, `showEvent` and `showGuessesLeft` for your code that displays
a reaction, a group's title, description or avatar, a decrypted event, or
the PIN attempts left; `handle(event)` for your code that handles a
decrypted event; `logSkipped(eventB64, err)` for your code that logs an
event it skips; and `storeConversationKey(conversationID, version, key)`
for your code that stores a conversation key. `pin` is the PIN's bytes and
`juiceboxConfig` the Juicebox config the X API returns. `base64`
(`encoding/base64`), `errors`, `fmt`, `json` (`encoding/json`) and
`strings` are the standard library's.

## 0. Before you start

### Install 0.7.2

Require the module at v0.7.2:

```sh
go get github.com/xdevplatform/chat-xdk/go/chatxdk@v0.7.2
```

It needs Go 1.21 or newer and cgo: the module links the prebuilt static
library it ships for your platform. Every app that shares conversations with
yours reads the formats 0.7.2 sends only once it runs a 0.7 release too, so
plan the rollout below before you deploy.

### Upgrade readers first

0.7.2 sends each message, reply, reaction and edit in one of two formats.
v0 is the format 0.5.x sends. v1 encrypts each message under its own key,
derived from the conversation key, the sender and the message id, and signs
it at signature version 10. A chat sends v1 while the X API's `v1_send`
feature switch is on for it, and v0 otherwise (see [The feature-switch
request](#the-feature-switch-request)). While a chat sends v1, its key
changes, group changes, deletes and read receipts sign at version 10 too, as
X clients' do; while it sends v0 they sign at version 7, as in 0.5.x, apart
from a member add that carries a description, which signs at version 8.

0.5.x rejects each of these as a signature verification failure, so upgrade
every app that reads your conversations to 0.7.2 before:

- any of your senders can send v1, that is, before the X API turns
  `v1_send` on for them;
- you pass a description to [`PrepareGroupMembersChange`](#adding-members).

0.7.2 reads both formats, including v1 reply previews, edits and files.
There's no code to change: to see which format a send used, read
`payload.SignatureInfo.SignatureVersion`, `"7"` for v0 and `"10"` for v1.

### The feature-switch request

Chats read the X API's feature switches with one anonymous request,
`GET https://api.x.com/2/chat/features`, which runs in the background:

- a chat reads them when it is created, and keeps the first answer for its
  lifetime; chats created while a request is in flight, or waiting to be
  retried, share it;
- it carries no credentials and no query parameters, and never delays or
  fails a call;
- every switch is off until an answer arrives, so a chat's first sends can
  be v0;
- a request that fails is retried in the background while a chat waits for
  its answer: 1 second later, then after twice the previous wait, at most 5
  minutes apart and 10 times; if every attempt fails or is blocked, every
  switch stays off for the chat's lifetime and its sends stay v0;
- a switch that changes reaches the chats created after it.

Allow outbound HTTPS to `api.x.com` if you want your sends to follow the
switch, or block it to keep them v0. There's no code to change.

## 1. Symbol index

Every 0.5.x name that changes, with its 0.7.2 form and the section that
shows the change. A name not listed here keeps its 0.5.x form. Search your
code for each name in the first column; [Verify](#5-verify) gives the
search as one command.

| 0.5.x | 0.7.2 | Section |
|---|---|---|
| `chatxdk.New()`, then `chat.Setup(pin, configJSON)` and `chat.Unlock(pin, configJSON)` | `chatxdk.NewWithJuiceboxConfig(configJSON)`, then `chat.Setup(pin)` and `chat.Unlock(pin)` | [Juicebox](#keys-stored-in-juicebox) |
| `chatxdk.GuessesRemaining(err)` | `GuessesRemaining` of a `*chatxdk.Error`, read with `errors.As` | [Errors](#errors-carry-their-kind) |
| `registration.Version`, `registration.GenerateVersion` | Removed: the registration request returns the version (`public_key_version`) | [Registration](#register-keys-with-the-public-key-only) |
| `PublicKeys.Version` | Removed: the `public_key_version` the registration request returns | [Registration](#register-keys-with-the-public-key-only) |
| `chat.SetIdentity(userID, signingKeyVersion)` | `chat.SetIdentity(chatxdk.SetIdentityParams{UserID: ..., SigningKeyVersion: ...})` | [SetIdentity](#setidentity-takes-setidentityparams) |
| `chat.ImportKeys(keys)` | `chat.ImportKeys(chatxdk.ImportKeysParams{Keys: keys})` | [ImportKeys](#importkeys-takes-importkeysparams) |
| `chat.ImportKeysWithVersion(keys, version)` | `chat.ImportKeys(chatxdk.ImportKeysParams{Keys: keys, SigningKeyVersion: version})` | [ImportKeys](#importkeys-takes-importkeysparams) |
| `chat.DecryptEvents(events, signingKeys)` | `chat.DecryptEvents(chatxdk.DecryptEventsParams{Events: events, SigningKeys: signingKeys})` | [DecryptEvents](#decryptevents-takes-decrypteventsparams) |
| `result.Messages`, `DecryptedEventMessage` | `result.Events`, `DecryptedEvent` | [DecryptEvents](#decryptevents-takes-decrypteventsparams) |
| `chat.DecryptEvent(eventB64, keys, signingKeys)` | `chat.DecryptEvent(chatxdk.DecryptEventParams{EventB64: ..., ConversationKeys: ..., SigningKeys: ...})` | [DecryptEvent](#decryptevent-takes-decrypteventparams) |
| `payload.EncryptedContent` | `payload.EncodedMessageCreateEvent` | [SendPayload](#sendpayload-fields-take-the-send-requests-names) |
| `payload.EncodedEventSignature` | `payload.EncodedMessageEventSignature` | [SendPayload](#sendpayload-fields-take-the-send-requests-names) |
| `chat.EncryptStream(plaintext, key)`, a message's file | `chat.EncryptFile(chatxdk.EncryptFileParams{File: ..., EventB64: ..., MediaHashKey: ...})` | [Files](#encrypt-a-file-from-its-message) |
| `chat.EncryptStream(plaintext, key)`, any other file, such as a group avatar | `chat.EncryptFileWithKey(chatxdk.EncryptFileWithKeyParams{File: ..., Key: ...})` | [Files under a key](#encrypt-a-file-under-a-key-you-hold) |
| `chat.DecryptStream(encrypted, key)`, a message's file | `chat.DecryptFile(chatxdk.DecryptFileParams{...})` | [Files](#decrypt-a-file-with-its-messages-event) |
| `chat.DecryptStream(encrypted, key)`, any other file | `chat.DecryptFileWithKey(chatxdk.DecryptFileWithKeyParams{Encrypted: ..., Key: ...})` | [Files under a key](#encrypt-a-file-under-a-key-you-hold) |
| `chat.StreamEncryptor(key)`, `chat.StreamDecryptor(key)`, `*StreamEncryptor`, `*StreamDecryptor`, a message's file | `chat.FileEncryptor(chatxdk.FileEncryptorParams{...})`, `chat.FileDecryptor(chatxdk.FileDecryptorParams{...})`, `*FileEncryptor`, `*FileDecryptor` | [Large files](#encrypt-and-decrypt-large-files-in-chunks) |
| `chat.StreamEncryptor(key)`, `chat.StreamDecryptor(key)`, any other file | `EncryptFileWithKey` and `DecryptFileWithKey` over the whole file | [Large files](#encrypt-and-decrypt-large-files-in-chunks) |
| `chatxdk.EncryptedStreamSize(n)` | `chatxdk.EncryptedFileSize(n)` | [Files](#encrypt-a-file-from-its-message) |
| `chat.Encrypt(plaintext, key)` | Removed: titles and descriptions go through `PrepareGroupTitleChange`, `PrepareGroupDescriptionChange` and the group creates and member adds; avatar URLs aren't encrypted; files go through `EncryptFile` or `EncryptFileWithKey` | [Changing the title](#changing-the-title) |
| `ActionSignature.Signature`, `SignatureVersion`, `PublicKeyVersion`, `SignaturePayload` | `ActionSignature.MessageEventSignature`; pass `ActionSignatures` as returned | [Action signatures](#action-signatures-come-nested) |
| `PublicKeyInput{PublicKey: ..., KeyVersion: ...}` | `PublicKeyInput{IdentityPublicKey: ..., PublicKeyVersion: ...}` | [Public key inputs](#public-key-inputs-name-the-identity-key-and-its-version) |
| `prepared.ParticipantKeys`, `EncryptedKeyForRecipient`, `EncryptedKey` | `prepared.ConversationParticipantKeys`, `ConversationParticipantKey`, `EncryptedConversationKey` | [Participant keys](#participant-keys-take-the-key-requests-names) |
| `keyChange.ParticipantKeys`, `ParticipantKey`, `EncryptedKey` | `keyChange.ConversationParticipantKeys`, `ConversationParticipantKey`, `EncryptedConversationKey` | [Received keys](#received-participant-keys-take-the-same-names) |
| `PrepareMessageDelete` returning an `*ActionSignature` | Returns a `*PreparedAction`: `deletion.ActionSignatures[0]` | [Deletes](#deletes-return-a-preparedaction) |
| `message.KeyVersion`, `keyChange.KeyVersion` | `ConversationKeyVersion` | [Event names](#decrypted-events-use-the-names-the-calls-take) |
| `ReactionContent.TargetMessageID` | `TargetMessageSequenceID` | [Event names](#decrypted-events-use-the-names-the-calls-take) |
| `ReadReceiptEvent.SeenUntilID` | `SeenUntilSequenceID` | [Event names](#decrypted-events-use-the-names-the-calls-take) |
| JSON `target_message_id`, `new_text`, `message_ids`, `seen_until_id` | `target_message_sequence_id`, `updated_text`, `sequence_ids`, `seen_until_sequence_id` | [Event names](#decrypted-events-use-the-names-the-calls-take) |
| Group title and description JSON strings (`title`, `new_title`) | `chatxdk.GroupText` | [Creating a group](#creating-a-group) |
| `GroupCreateParams.AvatarURL` | Removed: set the avatar with `PrepareGroupAvatarChange` | [Creating a group](#creating-a-group) |
| `EncryptReplyParams.ReplyToSenderID` (`*int64`) | `string` | [User ids](#user-ids-are-strings-of-digits) |

## 2. Compile-time changes

These changes are in the order an app meets them: creating the chat,
registering, loading keys, decrypting, encrypting and sending, files,
prepared changes, decrypted events and errors.

### Keys stored in Juicebox

A chat that keeps its keys in Juicebox takes the Juicebox config the X API
returns when it's created, with `NewWithJuiceboxConfig`, or later with
`UpdateConfig`, on first boot, before the account has one. `Setup` and
`Unlock` take only the PIN, as `ChangePin` and `Delete` take no config, and
`New` creates a chat that manages its keys with `ImportKeys` and
`ExportKeys` alone:

```go
// 0.5.x
chat := chatxdk.New()
_, err := chat.Setup(pin, juiceboxConfig)
must(err)
must(chat.Unlock(pin, juiceboxConfig))

// 0.7.2
chat, err := chatxdk.NewWithJuiceboxConfig(juiceboxConfig)
must(err)
_, err = chat.Setup(pin)
must(err)
must(chat.Unlock(pin))
```

The PINs are `[]byte`, so you can zero yours once the call returns. Every
method of a `*chatxdk.Chat`, `UpdateConfig` included, is safe to call from
several goroutines at once; a Juicebox call already under way keeps the
config it started with. A wrong PIN returns an error of kind
`ErrorKindInvalidPin` (see [Errors carry their kind](#errors-carry-their-kind)),
and a chat without a config fails its Juicebox calls (see [An empty Juicebox
config fails](#an-empty-juicebox-config-fails)).

### Register keys with the public key only

`GenerateKeypairs` returns a `*PublicKeyRegistrationPayload` that holds only
`PublicKey`. Send it as the only field of the
`POST /2/users/{id}/public_keys` body, `public_key`. 0.7.2 doesn't pick a
signing-key version for new keys: call `SetIdentity` with the
`public_key_version` the request returns (see the next section). A signed
call made without a version returns the error `Invalid state:
signing_key_version is not set: pass it explicitly or call set_identity()
first`.

```go
// 0.5.x
registration, err := chat.GenerateKeypairs()
must(err)
response, err := api.Post("/2/users/"+userID+"/public_keys", map[string]any{
	"public_key":       registration.PublicKey,
	"version":          registration.Version,
	"generate_version": registration.GenerateVersion,
})
must(err)
publicKeyVersion := response["data"].(map[string]any)["public_key_version"].(string)
must(chat.SetIdentity(userID, publicKeyVersion))

// 0.7.2
registration, err := chat.GenerateKeypairs()
must(err)
response, err := api.Post("/2/users/"+userID+"/public_keys", map[string]any{"public_key": registration.PublicKey})
must(err)
publicKeyVersion := response["data"].(map[string]any)["public_key_version"].(string)
must(chat.SetIdentity(chatxdk.SetIdentityParams{UserID: userID, SigningKeyVersion: publicKeyVersion}))
```

`PublicKeys`, which `GetPublicKeys` and `Setup` return, holds the two public
keys, `Identity` and `Signing`, and no `Version`: their version is the
`public_key_version` the registration request returns.

### `SetIdentity` takes `SetIdentityParams`

Pass the user id and the signing-key version in a `SetIdentityParams`. It
returns an error when either value is invalid (see
[user ids](#user-ids-are-strings-of-digits) and
[key versions](#key-versions-are-integers-written-as-strings)).

```go
// 0.5.x
must(chat.SetIdentity(userID, signingKeyVersion))

// 0.7.2
must(chat.SetIdentity(chatxdk.SetIdentityParams{UserID: userID, SigningKeyVersion: signingKeyVersion}))
```

### `ImportKeys` takes `ImportKeysParams`

Pass the saved key bytes in an `ImportKeysParams`, and optionally the
signing-key version they were registered under as `SigningKeyVersion`.
Without a version, call `SetIdentity` before the first signed call.
`ExportKeys` keeps its 0.5.x signature (see [`ExportKeys` fails without
keys](#exportkeys-fails-without-keys) for a chat without keys).

```go
// 0.5.x
must(chat.ImportKeys(privateKeys))
must(chat.ImportKeysWithVersion(privateKeys, signingKeyVersion))

// 0.7.2
must(chat.ImportKeys(chatxdk.ImportKeysParams{Keys: privateKeys}))
must(chat.ImportKeys(chatxdk.ImportKeysParams{Keys: privateKeys, SigningKeyVersion: signingKeyVersion}))
```

### `DecryptEvents` takes `DecryptEventsParams`

Pass the events in a `DecryptEventsParams`. `SigningKeys` is optional;
`nil` verifies with the keys `SetSigningKeys` stored. Per-event errors,
events decrypt drops included, are still collected in the result's `Errors`,
and the call returns an error only for invalid params. The result holds the
decrypted events, of every event type, in `Events`, each a
`DecryptedEvent`:

```go
// 0.5.x
result, err := chat.DecryptEvents(events, signingKeys)
must(err)
for _, decrypted := range result.Messages {
	showEvent(decrypted.Event)
}

// 0.7.2
result, err := chat.DecryptEvents(chatxdk.DecryptEventsParams{Events: events, SigningKeys: signingKeys})
must(err)
for _, decrypted := range result.Events {
	showEvent(decrypted.Event)
}
```

The version to encrypt with, `result.ConversationKeys.LatestVersion`, comes
only from a key change that verified (see [`LatestVersion` comes from a
verified key change](#latestversion-comes-from-a-verified-key-change)).

### `DecryptEvent` takes `DecryptEventParams`

Pass the event in a `DecryptEventParams`. Both key fields are optional: a
`nil` `ConversationKeys` resolves the key from the key cache
(`SetCacheKeys(true)`), and `nil` `SigningKeys` verifies with the keys
`SetSigningKeys` stored. It still returns an error on failure, and for an
event decrypt drops (see [Decrypt drops a removal's title and description
re-encryptions](#decrypt-drops-a-removals-title-and-description-re-encryptions)).

```go
// 0.5.x
event, err := chat.DecryptEvent(eventB64, keys, signingKeys)
must(err)

// 0.7.2
event, err := chat.DecryptEvent(chatxdk.DecryptEventParams{
	EventB64: eventB64, ConversationKeys: keys, SigningKeys: signingKeys,
})
must(err)
```

### `SendPayload` fields take the send request's names

The two encoded fields carry the names of the fields of the send request,
`POST /2/chat/conversations/{id}/messages`, so the request takes them as
they are. Read them under those names wherever your code reads a payload,
including code that stores payloads. The request also takes the payload's
`XdkVersion`, the version of the SDK that built it, as `xdk_version`:

```go
// 0.5.x
body := map[string]string{
	"message_id":                      payload.MessageID,
	"encoded_message_create_event":    payload.EncryptedContent,
	"encoded_message_event_signature": payload.EncodedEventSignature,
}

// 0.7.2
body := map[string]string{
	"message_id":                      payload.MessageID,
	"encoded_message_create_event":    payload.EncodedMessageCreateEvent,
	"encoded_message_event_signature": payload.EncodedMessageEventSignature,
	"xdk_version":                     payload.XdkVersion,
}
```

A payload also carries `EventB64`, the message as recipients receive it. It
isn't part of the send request: keep it to encrypt the message's files (see
[Encrypt a file from its message](#encrypt-a-file-from-its-message)).

A v1 payload's encoded fields carry what X clients' v1 sends carry:
`EncodedMessageEventSignature` lists the signing keys the message relies on,
by user id and key version (the sender's own and, for a reply, those of the
quoted message's sender and of its edit's), and `EncodedMessageCreateEvent`
asks for a notification for a reaction only in a one-to-one conversation,
and never for a reaction removal or an edit. Send both as returned.

### Encrypt a file from its message

Each file is encrypted from the message that carries it, so build the
message first:

1. Start each file's upload with `POST /2/chat/media/upload/initialize`,
   declaring `EncryptedFileSize` of the file's size as `total_bytes`, and
   keep the `session_id` and `media_hash_key` it returns.
2. Encrypt the message with attachments that name those media hash keys.
3. Encrypt each file with `EncryptFile`, passing the payload's `EventB64`
   and the file's media hash key.
4. Upload each encrypted file with `POST
   /2/chat/media/upload/{session_id}/append` and finish it with `POST
   /2/chat/media/upload/{session_id}/finalize`, then send the message.

```go
// 0.5.x
encrypted, err := chat.EncryptStream(photo, conversationKey)
must(err)
response, err := api.Post("/2/chat/media/upload/initialize", map[string]any{
	"conversation_id": conversationID, "total_bytes": len(encrypted),
})
must(err)
mediaHashKey := response["data"].(map[string]any)["media_hash_key"].(string)
payload, err := chat.EncryptMessage(chatxdk.EncryptMessageParams{
	ConversationID: conversationID, Text: "a photo",
	Attachments: []chatxdk.AttachmentDescriptor{photoAttachment(mediaHashKey)},
})
must(err)

// 0.7.2
size, err := chatxdk.EncryptedFileSize(uint64(len(photo)))
must(err)
response, err := api.Post("/2/chat/media/upload/initialize", map[string]any{
	"conversation_id": conversationID, "total_bytes": size,
})
must(err)
upload := response["data"].(map[string]any)
sessionID, mediaHashKey := upload["session_id"].(string), upload["media_hash_key"].(string)
payload, err := chat.EncryptMessage(chatxdk.EncryptMessageParams{
	ConversationID: conversationID, Text: "a photo",
	Attachments: []chatxdk.AttachmentDescriptor{photoAttachment(mediaHashKey)},
})
must(err)
encrypted, err := chat.EncryptFile(chatxdk.EncryptFileParams{
	File: photo, EventB64: payload.EventB64, MediaHashKey: mediaHashKey,
})
must(err)
_, err = api.Post("/2/chat/media/upload/"+sessionID+"/append", map[string]any{
	"conversation_id": conversationID, "media_hash_key": mediaHashKey,
	"segment_index": 0, "media": base64.StdEncoding.EncodeToString(encrypted),
})
must(err)
_, err = api.Post("/2/chat/media/upload/"+sessionID+"/finalize", map[string]any{
	"conversation_id": conversationID, "media_hash_key": mediaHashKey, "num_parts": "1",
})
must(err)
```

The `append` and `finalize` requests don't change, but they come after
`EncryptFile`, which produces the bytes they upload. The upload requests
take `conversation_id` in its colon form, as the SDK does. The snippet
uploads the file in one segment; a larger file goes up in several `append`
requests, `segment_index` 0, 1 and so on (the examples send 3 MB segments),
with their count as `num_parts`.

Like `EncryptMessage`, `EncryptFileParams` takes `ConversationKey` and
`ConversationKeyVersion` (set both, or neither to resolve them from the key
cache), and they must be the ones the message was encrypted under. The file
call needs no session identity: it reads the sender, the message id and the
key version from `EventB64`.

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
file and the conversation key map (the values `DecryptEvent` takes), and
the file's media hash key from the decrypted message: one of its media
attachments, a link card's banner or favicon (both listed in
`media_hashes`), or media quoted in its reply preview. The SDK finds the
file in the event and derives its key. It doesn't check the message's
signature: use `Verified` from `DecryptEvent` for that.

```go
// 0.5.x
plaintext, err := chat.DecryptStream(downloaded, keys[conversationKeyVersion])
must(err)

// 0.7.2
plaintext, err := chat.DecryptFile(chatxdk.DecryptFileParams{
	Encrypted: downloaded, EventB64: fileEventB64, ConversationKeys: keys, MediaHashKey: fileHashKey,
})
must(err)
```

### Encrypt a file under a key you hold

`EncryptStream` and `DecryptStream` take a key from the app for every file.
A file a message carries takes its key from the message, as the two
sections above show. A file no message carries keeps the key you hold, and
goes through `EncryptFileWithKey` and `DecryptFileWithKey`: a group's avatar
image, which X clients encrypt under the conversation key whose version the
avatar change signs next to the avatar URL (see [Changing the
avatar](#changing-the-avatar)), or your app's own files at rest. Each takes
the raw 32-byte key `EncryptStream` took, as `Key` in its params struct, and
writes the format `EncryptStream` writes: files 0.5.x encrypted with
`EncryptStream` or a stream encryptor decrypt with `DecryptFileWithKey`, and
0.5.x `DecryptStream` decrypts what `EncryptFileWithKey` returns, so files
you stored need no re-encryption. A key that isn't 32 bytes fails with an
`*Error` of kind `ErrorKindInvalidInput`, and bytes that aren't a complete
file encrypted under the key with one of kind `ErrorKindDecryption`.

```go
// 0.5.x
encrypted, err := chat.EncryptStream(data, conversationKey)
must(err)
plaintext, err := chat.DecryptStream(downloaded, conversationKey)
must(err)

// 0.7.2
encrypted, err := chat.EncryptFileWithKey(chatxdk.EncryptFileWithKeyParams{File: data, Key: conversationKey})
must(err)
plaintext, err := chat.DecryptFileWithKey(chatxdk.DecryptFileWithKeyParams{Encrypted: downloaded, Key: conversationKey})
must(err)
```

To move an `EncryptStream` or `DecryptStream` call, look at its file. A file
one of a message's attachments names (a photo, a video, a link card's banner
or favicon) moves to `EncryptFile` and `DecryptFile`, with the message; any
other file moves to `EncryptFileWithKey` and `DecryptFileWithKey`, with the
same key.

### Encrypt and decrypt large files in chunks

`FileEncryptor` and `FileDecryptor` take the same values as `EncryptFile`
and `DecryptFile`, without the file bytes, and return a `*FileEncryptor` or
a `*FileDecryptor`; `Push`, `Finish` and `Close` keep their 0.5.x form.
Size an upload with `EncryptedFileSize`. A file under a key you hold has no
chunked form: read it whole and pass it to `EncryptFileWithKey` or
`DecryptFileWithKey` (see [Encrypt a file under a key you
hold](#encrypt-a-file-under-a-key-you-hold)).

```go
// 0.5.x
size, err := chatxdk.EncryptedStreamSize(uint64(len(photo)))
must(err)
encryptor, err := chat.StreamEncryptor(conversationKey)
must(err)
decryptor, err := chat.StreamDecryptor(keys[conversationKeyVersion])
must(err)

// 0.7.2
size, err := chatxdk.EncryptedFileSize(uint64(len(photo)))
must(err)
encryptor, err := chat.FileEncryptor(chatxdk.FileEncryptorParams{
	EventB64: payload.EventB64, MediaHashKey: mediaHashKey,
})
must(err)
decryptor, err := chat.FileDecryptor(chatxdk.FileDecryptorParams{
	EventB64: fileEventB64, ConversationKeys: keys, MediaHashKey: fileHashKey,
})
must(err)
```

### Action signatures come nested

The prepare methods return each `ActionSignature` in the shape a request's
`action_signatures` takes: `MessageID`, `EncodedMessageEventDetail`, the
signature in `MessageEventSignature` (with `SigningPublicKey`, your signing
public key as `GetPublicKeys` returns it), and nothing else: the signed
payload stays inside the SDK. Their JSON tags are the request's snake_case
names, so marshal them as returned:

```go
// 0.5.x
actionSignatures := make([]map[string]any, 0, len(prepared.ActionSignatures))
for _, sig := range prepared.ActionSignatures {
	actionSignatures = append(actionSignatures, map[string]any{
		"message_id":                   sig.MessageID,
		"encoded_message_event_detail": sig.EncodedMessageEventDetail,
		"message_event_signature": map[string]any{
			"signature":          sig.Signature,
			"signature_version":  sig.SignatureVersion,
			"public_key_version": sig.PublicKeyVersion,
			"signing_public_key": signingPublicKey,
		},
	})
}

// 0.7.2
actionSignatures := prepared.ActionSignatures
```

### Public key inputs name the identity key and its version

A `PublicKeyInput`, one participant a conversation key is encrypted to,
names its key `IdentityPublicKey` and the key's version `PublicKeyVersion`,
as `SigningKeyEntry` does: the `public_key` the X API returns for a user is
their identity key:

```go
// 0.5.x
publicKeys = append(publicKeys, chatxdk.PublicKeyInput{UserID: userID, PublicKey: identityPublicKey, KeyVersion: publicKeyVersion})

// 0.7.2
publicKeys = append(publicKeys, chatxdk.PublicKeyInput{UserID: userID, IdentityPublicKey: identityPublicKey, PublicKeyVersion: publicKeyVersion})
```

### Participant keys take the key requests' names

A prepared change's participant keys carry the names the X API gives them in
every request that takes them (`POST /2/chat/conversations/{id}/keys`,
`/group` and `/{id}/members`, and `PUT /2/chat/conversations/{id}`):
`ConversationParticipantKeys`, a slice of `ConversationParticipantKey` whose
fields (`UserID`, `EncryptedConversationKey`, `PublicKeyVersion`) marshal as
`user_id`, `encrypted_conversation_key` and `public_key_version`, the type a
received key change uses too (see [Received participant keys take the same
names](#received-participant-keys-take-the-same-names)). Drop the renaming
and pass them through as returned:

```go
// 0.5.x
conversationParticipantKeys := make([]map[string]string, 0, len(prepared.ParticipantKeys))
for _, key := range prepared.ParticipantKeys {
	conversationParticipantKeys = append(conversationParticipantKeys, map[string]string{
		"user_id":                    key.UserID,
		"encrypted_conversation_key": key.EncryptedKey,
		"public_key_version":         key.PublicKeyVersion,
	})
}

// 0.7.2
conversationParticipantKeys := prepared.ConversationParticipantKeys
```

### Received participant keys take the same names

A decrypted `KeyChangeEvent` carries its participant keys under the names
Thrift's `ConversationKeyChangeEvent` gives them, the same names a prepared
change uses: `ConversationParticipantKeys`, each with `UserID`,
`EncryptedConversationKey` and `PublicKeyVersion` (`user_id`,
`encrypted_conversation_key` and `public_key_version` in JSON). Received and
prepared keys are one type, `ConversationParticipantKey`:

```go
// 0.5.x
var key chatxdk.ParticipantKey = keyChange.ParticipantKeys[0]
encrypted := key.EncryptedKey

// 0.7.2
var key chatxdk.ConversationParticipantKey = keyChange.ConversationParticipantKeys[0]
encrypted := key.EncryptedConversationKey
```

### Deletes return a `PreparedAction`

`PrepareMessageDelete` returns a `*PreparedAction` whose `ActionSignatures`
hold one entry, shaped as [Action signatures come
nested](#action-signatures-come-nested) shows. Read the action's `MessageID`
from that entry, and send `ActionSignatures` as returned (see [Deleting
messages](#deleting-messages) for the request):

```go
// 0.5.x
deletion, err := chat.PrepareMessageDelete(chatxdk.MessageDeleteParams{
	ConversationID: conversationID, SequenceIDs: sequenceIDs,
})
must(err)
messageID := deletion.MessageID

// 0.7.2
deletion, err := chat.PrepareMessageDelete(chatxdk.MessageDeleteParams{
	ConversationID: conversationID, SequenceIDs: sequenceIDs,
})
must(err)
messageID := deletion.ActionSignatures[0].MessageID
```

### Decrypted events use the names the calls take

`Message` and `KeyChangeEvent` carry their conversation key version as
`ConversationKeyVersion` (`conversation_key_version` in JSON), the name the
X API's events and the Thrift events give it, and the name the encrypt
params take:

```go
// 0.5.x
messageVersion := *message.KeyVersion
keyChangeVersion := keyChange.KeyVersion

// 0.7.2
messageVersion := *message.ConversationKeyVersion
keyChangeVersion := keyChange.ConversationKeyVersion
```

Fields that hold sequence ids take the names of the params that send them.
`ReactionContent` names its target `TargetMessageSequenceID`, as
`EncryptReactionParams` does, and `ReadReceiptEvent` names its position
`SeenUntilSequenceID`, as `MarkConversationReadParams` does:

```go
// 0.5.x
showReaction(message.Content.ReactionContent.TargetMessageID, message.Content.ReactionContent.Emoji)
seenUntil := *receipt.SeenUntilID

// 0.7.2
showReaction(message.Content.ReactionContent.TargetMessageSequenceID, message.Content.ReactionContent.Emoji)
seenUntil := *receipt.SeenUntilSequenceID
```

Events and content without a Go type follow the same rule in their JSON,
which `Event.Raw` returns: an `Edit` content names its target
`target_message_sequence_id` and its text `updated_text`, as
`EncryptEditParams` does, a `MessageDeleted` event names its messages
`sequence_ids`, as `MessageDeleteParams` does, and a `MarkedUnread` event
names its position `seen_until_sequence_id`. A v1 edit also carries the
signed message id of the message it edits as `target_message_id`, absent
for a v0 edit.

**Rename every read of `target_message_id` to `target_message_sequence_id`,
in struct tags and in code that reads `Event.Raw`. Don't keep
`target_message_id`: in 0.7.2 it names a different value, and decoding it
returns no error** (see [`target_message_id` holds a different
value](#target_message_id-holds-a-different-value)).

```go
// 0.5.x
var deleted struct {
	MessageIDs []string `json:"message_ids"`
}
must(json.Unmarshal(event.Raw(), &deleted))

// 0.7.2
var deleted struct {
	SequenceIDs []string `json:"sequence_ids"`
}
must(json.Unmarshal(event.Raw(), &deleted))
```

A group create's `title`, and a title or description change's `new_title`
or `new_description`, decodes into a `chatxdk.GroupText` rather than a
string (see [Creating a group](#creating-a-group)).

### Errors carry their kind

Every error a call returns is a `*chatxdk.Error`, whose `Kind` names the
failure the same way in every binding: `ErrorKindInvalidInput`,
`ErrorKindInvalidState`, `ErrorKindParse`, `ErrorKindDecryption`,
`ErrorKindVerification`, `ErrorKindInvalidPin`, `ErrorKindJuicebox` or
`ErrorKindInternal`. Read it with `errors.As`. After a wrong PIN, its
`GuessesRemaining` holds the attempts Juicebox reports left, `0` once the
stored keys are locked and `nil` when Juicebox reports no count:

```go
// 0.5.x
err := chat.Unlock(pin, juiceboxConfig)
showGuessesLeft(chatxdk.GuessesRemaining(err))

// 0.7.2
err := chat.Unlock(pin)
var chatErr *chatxdk.Error
if errors.As(err, &chatErr) && chatErr.GuessesRemaining != nil {
	showGuessesLeft(*chatErr.GuessesRemaining, true)
}
```

A missing or invalid parameter returns an error of kind
`ErrorKindInvalidInput` whose message names the value, such as `Invalid
sender_id 'user-1': pass a numeric user id (digits only)` or `too many
attachments: at most 10 per message`, without an `Invalid state:` prefix.
That covers a key or signature that `Verify`, `VerifyKeyBinding` or
`MatchesRegisteredKey` can't decode: they return the SDK's error, which
names the input, rather than a generic one. Errors about state the chat
lacks, such as a missing session identity or an empty key cache, are of
kind `ErrorKindInvalidState` and keep their prefix. Match the kind rather
than the message.

## 3. Runtime and behavior changes

Nothing reports these changes before the code runs: each one is a value the
SDK checks, a value with a new meaning, or an event handled differently.

### User ids are strings of digits

Every user id is a string of digits: the `SetIdentityParams` user id,
`SenderID`, `ReplyToSenderID`, the `UserID` of each `PublicKeyInput` and
`SigningKeyEntry`, and the ids of a group's members and admins
(`MemberIDs`, `AdminIDs`, `NewMemberIDs`, `CurrentMemberIDs`,
`CurrentAdminIDs`, `CurrentPendingMemberIDs` and `UserIDs`). Each must be a
positive integer written without a sign or leading zeros; anything else
returns an error that names the field, such as `Invalid sender_id 'user-1':
pass a numeric user id (digits only)`. `EncryptReplyParams.ReplyToSenderID`
is a `string`:

```go
// 0.5.x
replyTo := int64(4201)
params := chatxdk.EncryptReplyParams{
	ConversationID: conversationID, Text: "pong", ReplyToEvent: eventB64, ReplyToSenderID: &replyTo,
}

// 0.7.2
params := chatxdk.EncryptReplyParams{
	ConversationID: conversationID, Text: "pong", ReplyToEvent: eventB64, ReplyToSenderID: "4201",
}
```

### Key versions are integers written as strings

Every key version is a non-negative integer written as a string of digits,
as the X API returns it: the signing-key version (in `SetIdentityParams`,
`ImportKeysParams`, a call's `SigningKeyVersion` and each public key's
`PublicKeyVersion`) and `ConversationKeyVersion`. Anything else returns an
error that names the field, such as `Invalid signing_key_version 'v1': pass
the key version as the X API returns it, an integer in digits`. There's no
code to change if you pass the versions the X API returns.

### Entities, files, URL cards and posts are checked

The encrypt calls check what a message carries before they encrypt it, and
return an error of kind `ErrorKindInvalidInput` naming the value, where
0.5.x sent it:

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
  favicon, fails with an empty `Filename`, a `FilesizeBytes` of 0 or less,
  or a negative `Width` or `Height`, since receiving clients discard such a
  file. Give each file its name and the encrypted size
  `chatxdk.EncryptedFileSize` gives.
- A message that lists an empty media hash key, or one media hash key in
  two attachments, fails.
- A URL card with an empty `URL`, and a post attachment with neither
  `RestID` nor `PostURL`, fail.

A Go string's byte offsets are already UTF-8 offsets:

```go
// 0.7.2
text := "café @bob"
start := strings.Index(text, "@bob")
payload, err := chat.EncryptMessage(chatxdk.EncryptMessageParams{
	ConversationID: conversationID, Text: text,
	Entities: []chatxdk.EntityTuple{chatxdk.NewEntity(start, start+len("@bob"), "mention")},
})
must(err)
```

### `LatestVersion` comes from a verified key change

`result.ConversationKeys.LatestVersion`, the version to encrypt with, is
the newest version whose key change verified, and it never moves back for
the chat's lifetime. A key change verifies only against its sender's
signing key, so give the chat every participant's signing keys, your own
included, before you decrypt. It's `nil` until a key change verifies: a key
change the SDK can't verify still adds its key to
`result.ConversationKeys.Keys`, for decrypting, but never becomes the
version you encrypt with. Where 0.5.x returned the batch's highest version,
0.7.2 can return `nil`: fetch the missing signing keys or the conversation's
key-change events and decrypt again, rather than encrypting under the
highest key in `Keys`:

```go
// 0.5.x
result, err := chat.DecryptEvents(events, signingKeys)
must(err)
version := *result.ConversationKeys.LatestVersion

// 0.7.2
must(chat.SetSigningKeys(signingKeys))
result, err := chat.DecryptEvents(chatxdk.DecryptEventsParams{Events: events})
must(err)
if result.ConversationKeys.LatestVersion == nil {
	// No key change verified: fetch every participant's signing keys
	// (GET /2/users/{id}/public_keys) and the conversation's key changes
	// (meta.conversation_key_events of GET /2/chat/conversations/{id}/events),
	// then decrypt again.
	return
}
version := *result.ConversationKeys.LatestVersion
```

### `target_message_id` holds a different value

**In 0.5.x a reaction's or edit's `target_message_id` held the target's
sequence id. In 0.7.2 that value is `target_message_sequence_id`, and
`target_message_id` holds the edited message's signed message id, present
only on a v1 edit.** The compiler catches the renamed `ReactionContent`
field, but not a struct tag or a `map[string]any` that reads
`target_message_id` from `Event.Raw`: that code
gets the wrong id, or none. Rename every read, as [Decrypted events use the
names the calls take](#decrypted-events-use-the-names-the-calls-take) shows,
and use `target_message_id` only to match a v1 edit to the `message_id` you
deduplicate on.

### A reply preview quotes its message exactly

A received reply that embeds the message it quotes has its preview checked
against that message: `ReplyPreviewValidation` is `"Valid"` only when the
first 140 characters of the preview's text, counted in UTF-16 code units as
X clients count them, are those of the quoted text, and its entities are
exactly the quoted message's, or its edit's when the reply embeds the edit.
0.5.x accepted any start of the quoted text, and entities among the quoted
message's. `EncryptReply` builds such a preview from `ReplyToEvent`, and
from `ReplyToEditEvent` when the message was edited, so pass them when you
hold them. In v1, X clients check a reply against the message it names and
mark a reply that names none invalid, so a reply built from the explicit
preview fields names the quoted message's `message_id` as
`ReplyToMessageID`.

A reply carries no key change. Recipients open the quoted message with their
own conversation keys, or with the message key a reply carries for a v1
message, and decrypt ignores a key change embedded in a reply.
`ReplyToCkces` still opens a message under a key version your chat doesn't
hold yet, for `EncryptReply` to quote it, but the reply doesn't carry those
key changes.

### A prepared change's JSON leaves out its key

A `PreparedConversationChange`'s `ConversationKey` field is tagged
`json:"-"`, where 0.5.x marshaled it as `conversation_key`. The key stays on
the struct, but `json.Marshal` leaves it out: code that saved or queued a
prepared change as JSON loses the key, and with it the conversation. Store
the key yourself, and marshal the rest:

```go
// 0.5.x
saved, err := json.Marshal(prepared)
must(err)

// 0.7.2
storeConversationKey(prepared.ConversationID, prepared.ConversationKeyVersion, prepared.ConversationKey)
saved, err := json.Marshal(prepared)
must(err)
```

The request bodies take only a change's participant keys, key version and
action signatures, never the key itself.

### `Sign` refuses data only the SDK signs

`Sign` returns an error of kind `ErrorKindInvalidInput` for a payload
recipients would verify as a signed event (a message, conversation-key
change, group or conversation-metadata change, delete or read receipt) and
for a P-256 public key, whose signature by the signing key binds it as an
identity key. Sign only your own application data with `Sign`; the SDK
signs events itself. Any other data signs as in 0.5.x:

```go
// 0.7.2
signature, err := chat.Sign(data)
var chatErr *chatxdk.Error
if errors.As(err, &chatErr) && chatErr.Kind == chatxdk.ErrorKindInvalidInput {
	// The data reads as an event or a public key, which only the SDK signs.
	signature = nil
} else {
	must(err)
}
```

### Decrypt drops a removal's title and description re-encryptions

A member removal rotates the conversation key and re-encrypts the group's
title and description under the new key, marked as key-rotation
re-encryptions. They are the same text, not changes, so `DecryptEvents`
and `DecryptEvent` drop them under either `SetRejectUnverified` setting,
the way they drop an unverified event: `DecryptEvents` leaves each one out
of `Events` and records it in `Errors`, and `DecryptEvent` returns an error
of kind `ErrorKindInvalidInput`: `GroupChange re-encrypts the group's title
for a key rotation (for_key_rotation), not a title change: decrypt does not
return it`. The removal itself (`MembersRemoved`), its key change, avatar
changes and every title or description change without the mark decrypt as
before. In 0.5.x, a removal by an X client arrived as a `TitleChanged`
carrying the group's unchanged title:

```go
// 0.5.x
result, err := chat.DecryptEvents(events, signingKeys)
must(err)
for _, decrypted := range result.Messages {
	if change := decrypted.Event.AsGroupChange(); change != nil {
		var titleChange struct {
			ChangeType string `json:"change_type"`
			NewTitle   string `json:"new_title"`
		}
		must(json.Unmarshal(change.Change, &titleChange))
		if titleChange.ChangeType == "TitleChanged" {
			title, err := chat.Decrypt(titleChange.NewTitle, keys[conversationKeyVersion])
			must(err)
			showTitle(title)
		}
	}
}

// 0.7.2
result, err := chat.DecryptEvents(chatxdk.DecryptEventsParams{Events: events})
must(err)
for _, decrypted := range result.Events {
	if change := decrypted.Event.AsGroupChange(); change != nil {
		var titleChange struct {
			ChangeType string            `json:"change_type"`
			NewTitle   chatxdk.GroupText `json:"new_title"`
		}
		must(json.Unmarshal(change.Change, &titleChange))
		if titleChange.ChangeType == "TitleChanged" {
			if titleChange.NewTitle.Kind == "Text" {
				showTitle(titleChange.NewTitle.Text)
			} else {
				showTitle(titleChange.NewTitle.Raw)
			}
		}
	}
}
```

A loop over single events handles the error, as it handles an unverified
event's, and moves on to the next event:

```go
// 0.7.2
for _, item := range page.Data {
	event, err := chat.DecryptEvent(chatxdk.DecryptEventParams{EventB64: item.EncodedEvent, ConversationKeys: keys})
	if err != nil {
		logSkipped(item.EncodedEvent, err)
		continue
	}
	handle(event)
}
```

### `ExportKeys` fails without keys

`ExportKeys` returns an error of kind `ErrorKindInvalidState` when no
identity key is loaded, where 0.5.x returned no keys and no error; check
`HasIdentityKey` first where that can happen:

```go
// 0.7.2
if chat.HasIdentityKey() {
	privateKeys, err := chat.ExportKeys()
	must(err)
	_ = privateKeys
}
```

### An empty Juicebox config fails

Until a chat has a Juicebox config, `Setup`, `Unlock`, `ChangePin` and
`Delete` return an error of kind `ErrorKindInvalidState`, `Invalid state:
no Juicebox config: pass the juicebox_config the X API returns when you
create the chat, or call update_config() first`, the error every binding
gives. `NewWithJuiceboxConfig` and `UpdateConfig` return it for an empty or
blank config, at once, rather than at the first Juicebox call; `New`
creates a chat without one.

## 4. Group and receipt signing

Recipients on the default `SetRejectUnverified` policy drop a read receipt
or group change that isn't signed, as 0.5.x recipients did: sign each one,
or recipients never see it. The sender comes from `SetIdentity`. Each
prepare call returns `ActionSignatures` shaped as [Action signatures come
nested](#action-signatures-come-nested) shows; marshal them into the
request as returned.

### The requests

Each request below takes the conversation id in its path as `pathID`, and
the prepare call's `ActionSignatures` as returned, as `action_signatures`.
The paths and body fields are the X API's, as its OpenAPI description
(`https://api.x.com/2/openapi.json`) gives them.

| Action | Call | Request | Body |
|---|---|---|---|
| Send a message, reply, reaction or edit | `EncryptMessage`, `EncryptReply`, `EncryptAddReaction`, `EncryptRemoveReaction`, `EncryptEdit` | `POST /2/chat/conversations/{id}/messages` | `message_id`, `encoded_message_create_event`, `encoded_message_event_signature`, `xdk_version`: the payload's `MessageID`, `EncodedMessageCreateEvent`, `EncodedMessageEventSignature` and `XdkVersion` |
| Delete messages | `PrepareMessageDelete` | `POST /2/chat/conversations/{id}/messages/delete` | `sequence_ids`; `delete_message_action`, `"delete_for_all"` or `"delete_for_self"` as the params' `DeleteForAll` says; `action_signatures` |
| Mark read | `PrepareMarkConversationRead` | `POST /2/chat/conversations/{id}/read` | `action_signatures` |
| Start a one-to-one or rotate its key | `PrepareConversationKeyChange` | `POST /2/chat/conversations/{id}/keys` | `conversation_key_version`, `conversation_participant_keys`, `action_signatures` |
| Create a group | `PrepareGroupCreate` | `POST /2/chat/conversations/group` | `conversation_id`, `group_members`, `group_admins`, `group_name` (the result's `EncryptedTitle`), `conversation_key_version`, `conversation_participant_keys`, `action_signatures` |
| Add members | `PrepareGroupMembersChange` | `POST /2/chat/conversations/{id}/members` | `user_ids`, `encrypted_title`, `conversation_key_version`, `conversation_participant_keys`, `action_signatures` |
| Remove members | `PrepareGroupMembersRemove` | `POST /2/chat/conversations/{id}/members/remove` | `user_ids`, `action_signatures`, `group_key_rotation_data` with `conversation_key_version` and `conversation_participant_keys` |
| Leave | `PrepareGroupLeave` | `POST /2/chat/conversations/{id}/members/remove` | `user_ids` (your own id), `action_signatures` |
| Change the title | `PrepareGroupTitleChange` | `PUT /2/chat/conversations/{id}` | `group_name` (the result's `EncryptedValue`), `conversation_key_version`, `modified_fields: ["group_name"]`, `action_signatures` |
| Change the description | `PrepareGroupDescriptionChange` | `PUT /2/chat/conversations/{id}` | `group_description` (the result's `EncryptedValue`), `conversation_key_version`, `modified_fields: ["group_description"]`, `action_signatures` |
| Change the avatar | `PrepareGroupAvatarChange` | `PUT /2/chat/conversations/{id}` | `group_avatar_url` (the media URL), `conversation_key_version`, `modified_fields: ["group_avatar_url"]`, `action_signatures` |
| Add admins | `PrepareGroupAdminsAdd` | `POST /2/chat/conversations/{id}/admins` | `user_ids`, `action_signatures` |
| Remove admins | `PrepareGroupAdminsRemove` | `POST /2/chat/conversations/{id}/admins/remove` | `user_ids`, `action_signatures` |
| Turn the invite link on | `PrepareGroupInviteEnable` | `POST /2/chat/conversations/{id}/invite` | `invite_url`; `validity_expiry_timestamp_msec` (the params' `ExpiresAtMsec`) and `affiliate_user_id` (the params' `AffiliateID`) when set; `action_signatures` |
| Turn the invite link off | `PrepareGroupInviteDisable` | `DELETE /2/chat/conversations/{id}/invite` | `action_signatures` |
| Ask to join | `PrepareGroupJoinRequest` | `POST /2/chat/conversations/{id}/join_requests` | `token` (the invite link's last 10 characters), `action_signatures` |
| Reject join requests | `PrepareGroupJoinReject` | `POST /2/chat/conversations/{id}/join_requests/reject` | `user_ids`, `action_signatures` |
| Set the message TTL | `PrepareMessageTtlChange` | `PUT /2/chat/conversations/{id}/message_ttl` | `message_ttl_ms` (the params' `TTLMsec`, as a string), `action_signatures` |
| Clear the message TTL | `PrepareMessageTtlRemove` | `DELETE /2/chat/conversations/{id}/message_ttl` | `action_signatures` |
| Change screen capture | `PrepareScreenCapture` | `PUT /2/chat/conversations/{id}/screen_capture` | `blocking` (`true` for `BlockingEnabled`, `false` for `BlockingDisabled`) and `blocking_action_signatures`, or `detection` and `detection_action_signatures` |

A group's `conversation_id` is the `g…` id that
`POST /2/chat/conversations/group/initialize` returns as
`data.conversation_id`.

### Deleting messages

`PrepareMessageDelete` returns the action's signature nested, as every
prepare call does: send `ActionSignatures` as returned, next to the
sequence ids and the delete action the params signed.

```go
// 0.5.x
deletion, err := chat.PrepareMessageDelete(chatxdk.MessageDeleteParams{
	ConversationID: conversationID, SequenceIDs: sequenceIDs, DeleteForAll: true,
})
must(err)
_, err = api.Post("/2/chat/conversations/"+pathID+"/messages/delete", map[string]any{
	"sequence_ids":          sequenceIDs,
	"delete_message_action": "delete_for_all",
	"action_signatures": []map[string]any{{
		"message_id":                   deletion.MessageID,
		"encoded_message_event_detail": deletion.EncodedMessageEventDetail,
		"message_event_signature": map[string]any{
			"signature":          deletion.Signature,
			"signature_version":  deletion.SignatureVersion,
			"public_key_version": deletion.PublicKeyVersion,
			"signing_public_key": signingPublicKey,
		},
	}},
})
must(err)

// 0.7.2
deletion, err := chat.PrepareMessageDelete(chatxdk.MessageDeleteParams{
	ConversationID: conversationID, SequenceIDs: sequenceIDs, DeleteForAll: true,
})
must(err)
_, err = api.Post("/2/chat/conversations/"+pathID+"/messages/delete", map[string]any{
	"sequence_ids":          sequenceIDs,
	"delete_message_action": "delete_for_all",
	"action_signatures":     deletion.ActionSignatures,
})
must(err)
```

A recipient's `DecryptEvent` returns the delete as a verified
`MessageDeleted` event whose JSON holds `sequence_ids` and
`delete_for_all`.

### Read receipts are signed

Sign a read receipt with `PrepareMarkConversationRead` and send the
`PreparedAction`'s `ActionSignatures` as the `action_signatures` of
`POST /2/chat/conversations/{id}/read`. The call takes a
`MarkConversationReadParams` (`ConversationID`, `SeenUntilSequenceID`, the
sequence id of the newest event read, and a `SeenAtMsec` that defaults to
now) and returns a `*PreparedAction`, one entry. Without it the X API sends
an unsigned receipt, which recipients drop.

```go
// 0.5.x
_, err := api.Post("/2/chat/conversations/"+pathID+"/read", map[string]any{})
must(err)

// 0.7.2
receipt, err := chat.PrepareMarkConversationRead(chatxdk.MarkConversationReadParams{
	ConversationID: conversationID, SeenUntilSequenceID: seenUntilSequenceID,
})
must(err)
_, err = api.Post("/2/chat/conversations/"+pathID+"/read", map[string]any{
	"action_signatures": receipt.ActionSignatures,
})
must(err)
```

A recipient's `DecryptEvent` returns a signed receipt as a verified
`ReadReceipt` event, its position in `SeenUntilSequenceID`.

### Group changes are signed

Every group change below returns `ActionSignatures` for its request in
[The requests](#the-requests). A group's title and description travel
encrypted under the conversation key, and the SDK encrypts them: the
creates, member adds, removals and title and description changes take them
as plaintext and return the encrypted values to send. An avatar is an image
the app encrypts with `EncryptFileWithKey` and uploads; its URL is signed as
is.

### Creating a group

`PrepareGroupCreate` encrypts the group's title under the conversation key
it creates, so set it as plaintext. The result is a
`*PreparedConversationChange` that also carries it encrypted, as
`EncryptedTitle` (nil when unset): send that as the create request's
`group_name`, next to its participant keys and signatures. The create signs
the encrypted value, which is base64, so a title may contain a comma; a
value signed as is, such as an avatar URL, can't. A create sets no avatar:
set one afterwards with an [avatar change](#changing-the-avatar), with the
image encrypted under the key the create returns.

```go
// 0.5.x
prepared, err := chat.PrepareGroupCreate(chatxdk.GroupCreateParams{
	PublicKeys:     publicKeys,
	ConversationID: conversationID,
	MemberIDs:      memberIDs,
	AdminIDs:       adminIDs,
	Title:          title,
	AvatarURL:      avatarURL,
})
must(err)
body := map[string]any{"group_name": title, "group_avatar_url": avatarURL}

// 0.7.2
prepared, err := chat.PrepareGroupCreate(chatxdk.GroupCreateParams{
	PublicKeys:     publicKeys,
	ConversationID: conversationID,
	MemberIDs:      memberIDs,
	AdminIDs:       adminIDs,
	Title:          title,
})
must(err)
_, err = api.Post("/2/chat/conversations/group", map[string]any{
	"conversation_id":               conversationID,
	"group_members":                 memberIDs,
	"group_admins":                  adminIDs,
	"group_name":                    prepared.EncryptedTitle,
	"conversation_key_version":      prepared.ConversationKeyVersion,
	"conversation_participant_keys": prepared.ConversationParticipantKeys,
	"action_signatures":             prepared.ActionSignatures,
})
must(err)
storeConversationKey(conversationID, prepared.ConversationKeyVersion, prepared.ConversationKey)
```

`DecryptEvent` returns a received group create with its title decrypted with
the key for the version the create names, from the call's key map or the key
cache: a `Created` change's `title`, in the `Change` JSON, decodes into a
`chatxdk.GroupText`. `Kind` `"Text"` holds the title in `Text`. `Kind`
`"Unavailable"` holds, in `Raw`, the value as the create carries it, when
that key isn't there or the value doesn't decrypt under it, and the rest of
the create still decrypts. 0.5.x signed a create's title as the app passed
it, so a 0.5.x app's create with a plaintext title arrives as
`"Unavailable"` with the title in `Raw`: show `Raw` when a title isn't
decryptable. A create that names no key version carries its title as
plaintext, and arrives as `"Text"`. The encrypted `group_name` and
`group_description` the X API returns with a conversation open with
`Decrypt`.

```go
// 0.5.x
var created struct {
	ChangeType string `json:"change_type"`
	Title      string `json:"title"`
}
must(json.Unmarshal(groupChange.Change, &created))
if created.ChangeType == "Created" && created.Title != "" {
	title, err := chat.Decrypt(created.Title, keys[conversationKeyVersion])
	must(err)
	showTitle(title)
}

// 0.7.2
var created struct {
	ChangeType string             `json:"change_type"`
	Title      *chatxdk.GroupText `json:"title"`
}
must(json.Unmarshal(groupChange.Change, &created))
if created.ChangeType == "Created" && created.Title != nil {
	if created.Title.Kind == "Text" {
		showTitle(created.Title.Text)
	} else {
		showTitle(created.Title.Raw)
	}
}
```

A `Created` change also carries the create's `conversation_key_version`, and
the `avatar_url` a create from another client may set: a media URL whose
image is encrypted under that key version, which `DecryptFileWithKey` opens
with that version's key.

### Adding members

`PrepareGroupMembersChange` rotates the conversation key, so it re-encrypts
the group's title and description under the key it generates: set them as
plaintext, in `CurrentTitle` and `CurrentDescription`, not as values your
code encrypted. The result carries them encrypted, as `EncryptedTitle` and
`EncryptedDescription` (nil when unset). Send `EncryptedTitle` as the
add-members request's `encrypted_title`; the description travels in the
signed member add. Encrypt under the new key from here on, as [Removing
members](#removing-members) shows for a removal.

```go
// 0.5.x
prepared, err := chat.PrepareGroupMembersChange(chatxdk.GroupMembersChangeParams{
	PublicKeys:       publicKeys,
	ConversationID:   conversationID,
	NewMemberIDs:     newMemberIDs,
	CurrentMemberIDs: memberIDs,
	CurrentAdminIDs:  adminIDs,
	CurrentTitle:     title,
})
must(err)

// 0.7.2
prepared, err := chat.PrepareGroupMembersChange(chatxdk.GroupMembersChangeParams{
	PublicKeys:         publicKeys,
	ConversationID:     conversationID,
	NewMemberIDs:       newMemberIDs,
	CurrentMemberIDs:   memberIDs,
	CurrentAdminIDs:    adminIDs,
	CurrentTitle:       title,
	CurrentDescription: description,
})
must(err)
_, err = api.Post("/2/chat/conversations/"+pathID+"/members", map[string]any{
	"user_ids":                      newMemberIDs,
	"encrypted_title":               prepared.EncryptedTitle,
	"conversation_key_version":      prepared.ConversationKeyVersion,
	"conversation_participant_keys": prepared.ConversationParticipantKeys,
	"action_signatures":             prepared.ActionSignatures,
})
must(err)
storeConversationKey(conversationID, prepared.ConversationKeyVersion, prepared.ConversationKey)
```

While the chat sends v0, passing a description makes the add sign at
signature version 8, the first version whose member-add payload covers one,
and 0.5.x readers can't verify a version-8 add. Until every app that reads
your groups runs 0.7.2, leave the description out, so the add signs at
version 7 as in 0.5.x; the new members can read the description once a
description change sets it under the new key. While the chat sends v1, the
add signs at version 10, with a description or without.

The add doesn't re-encrypt the avatar: `CurrentAvatarURL` takes its media
URL, signed as is, and the image stays encrypted under the key it was
uploaded with, which the new members never receive. X clients re-encrypt the
avatar on every key rotation: encrypt the image under the key the add
returns with `EncryptFileWithKey`, upload it, and send an [avatar
change](#changing-the-avatar) naming the new key version.

A recipient's `DecryptEvent` returns the add as a verified `MembersAdded`
change with `member_ids`, `current_member_ids` and `current_admin_ids`.

### Removing members

`PrepareGroupMembersRemove` removes `UserIDs` and rotates the conversation
key, so the members removed don't receive the key the group encrypts under
next. `GroupMembersRemoveParams` takes:

- `PublicKeys`: the identity key of every member who stays, yours included,
  as `GET /2/users/{id}/public_keys` returns them. The SDK encrypts the new
  key to each member's newest key version; a member left out, you included,
  can't read what the group sends under the new key. The SDK doesn't check
  that the list is complete. A key for a member being removed returns an
  error.
- `ConversationID` and `UserIDs`, the members to remove.
- `Title` and `Description`: the group's current title and description, as
  plaintext. Set each one the group has; the call encrypts each under the
  new key and signs it as a key-rotation re-encryption, which recipients'
  decrypt drops rather than shows as a change. The avatar is an image you
  encrypt, so the call doesn't re-encrypt it: X clients re-encrypt the
  avatar on every key rotation, so once the removal succeeds, encrypt the
  image under the new key with `EncryptFileWithKey`, upload it, and send an
  [avatar change](#changing-the-avatar) naming the new key version.

The result is a `*PreparedConversationChange`: the new `ConversationKey`
and `ConversationKeyVersion`, `ConversationParticipantKeys` for the members
who stay, and `ActionSignatures` in request order: the removal, a title
change and a description change for the ones set, then the conversation-key
change. Each signs at signature version 7 while the chat sends v0, as 0.5.x
readers verify, and at version 10 while it sends v1 (see [Upgrade readers
first](#upgrade-readers-first)).

```go
// 0.5.x
_, err := api.Post("/2/chat/conversations/"+pathID+"/members/remove", map[string]any{"user_ids": userIDs})
must(err)

// 0.7.2
prepared, err := chat.PrepareGroupMembersRemove(chatxdk.GroupMembersRemoveParams{
	PublicKeys:     remainingPublicKeys,
	ConversationID: conversationID,
	UserIDs:        userIDs,
	Title:          title,
	Description:    description,
})
must(err)
_, err = api.Post("/2/chat/conversations/"+pathID+"/members/remove", map[string]any{
	"user_ids":          userIDs,
	"action_signatures": prepared.ActionSignatures,
	"group_key_rotation_data": map[string]any{
		"conversation_key_version":      prepared.ConversationKeyVersion,
		"conversation_participant_keys": prepared.ConversationParticipantKeys,
	},
})
must(err)
```

**Encrypt under the new key as soon as the request succeeds.** The removed
members hold the old key, so a message encrypted under it is one they can
read. The key cache (`SetCacheKeys(true)`) adopts the new key only once
`DecryptEvents` decrypts the removal's key change from the conversation's
events, and only if that key change verifies against your own signing key;
until then an encrypt call that omits the key resolves the old one. Store
the new key and version, and pass them to every encrypt and prepare call
until the cache holds them:

```go
// 0.7.2
storeConversationKey(conversationID, prepared.ConversationKeyVersion, prepared.ConversationKey)
payload, err := chat.EncryptMessage(chatxdk.EncryptMessageParams{
	ConversationID:         conversationID,
	Text:                   "hello",
	ConversationKey:        prepared.ConversationKey,
	ConversationKeyVersion: prepared.ConversationKeyVersion,
})
must(err)
```

The same holds after any call that rotates the key:
`PrepareConversationKeyChange`, `PrepareGroupCreate` and
`PrepareGroupMembersChange`.

On the receiving side, `DecryptEvents` returns the removal as a verified
`MembersRemoved` change with its `member_ids`, and the key change as a
`KeyChange` event that adds the new key to `ConversationKeys` and moves
`LatestVersion` to it once it verifies. The title and description
re-encryptions are in `Errors`, not `Events` (see [Decrypt drops a
removal's title and description
re-encryptions](#decrypt-drops-a-removals-title-and-description-re-encryptions)):

```go
// 0.7.2
result, err := chat.DecryptEvents(chatxdk.DecryptEventsParams{Events: events})
must(err)
for _, decrypted := range result.Events {
	if change := decrypted.Event.AsGroupChange(); change != nil {
		var removal struct {
			ChangeType string   `json:"change_type"`
			MemberIDs  []string `json:"member_ids"`
		}
		must(json.Unmarshal(change.Change, &removal))
		if removal.ChangeType == "MembersRemoved" {
			removed := removal.MemberIDs
			_ = removed
		}
	}
}
version := result.ConversationKeys.LatestVersion
```

### Leaving a group

`PrepareGroupLeave` signs the sender's removal and does not rotate the
conversation key. `ActionSignatures` are the removal, then a
`GroupAdminAddChange` when `PromoteAdminID` is set, then a
`ConversationDeleteEvent`, each at signature version 7, or 10 while the chat
sends v1. It returns a `*PreparedAction`. Send it as a removal of your own
id:

```go
// 0.5.x
_, err := api.Post("/2/chat/conversations/"+pathID+"/members/remove", map[string]any{"user_ids": []string{myUserID}})
must(err)

// 0.7.2
left, err := chat.PrepareGroupLeave(chatxdk.GroupLeaveParams{
	ConversationID: conversationID,
	PromoteAdminID: promoteAdminID,
})
must(err)
_, err = api.Post("/2/chat/conversations/"+pathID+"/members/remove", map[string]any{
	"user_ids":          []string{myUserID},
	"action_signatures": left.ActionSignatures,
})
must(err)
```

### Changing the title

`PrepareGroupTitleChange` takes the new title as plaintext, encrypts it
under the conversation key and signs it. Like `EncryptMessageParams`,
`GroupTitleChangeParams` takes the key and its version in
`ConversationKey` and `ConversationKeyVersion`, or resolves both from the
key cache when they're empty. The result is a
`*PreparedGroupMetadataChange`: the `EncryptedValue` the request sends as
`group_name`, the `ConversationKeyVersion` it's encrypted under, and the
`ActionSignatures` to send with it.

```go
// 0.5.x
encryptedTitle, err := chat.Encrypt(title, keys[conversationKeyVersion])
must(err)
_, err = api.Put("/2/chat/conversations/"+pathID, map[string]any{
	"group_name":               encryptedTitle,
	"conversation_key_version": conversationKeyVersion,
	"modified_fields":          []string{"group_name"},
})
must(err)

// 0.7.2
prepared, err := chat.PrepareGroupTitleChange(chatxdk.GroupTitleChangeParams{
	ConversationID: conversationID,
	NewTitle:       title,
})
must(err)
_, err = api.Put("/2/chat/conversations/"+pathID, map[string]any{
	"group_name":               prepared.EncryptedValue,
	"conversation_key_version": prepared.ConversationKeyVersion,
	"modified_fields":          []string{"group_name"},
	"action_signatures":        prepared.ActionSignatures,
})
must(err)
```

`DecryptEvent` returns a received title change decrypted: the `new_title` of
a `TitleChanged` change, in the `Change` JSON, decodes into a
`chatxdk.GroupText`, as a create's `title` does. It decrypts with the key
for the version the change names, from the call's key map or the key cache.
Without that key, or when the value isn't ciphertext under it, as for a
plaintext title an app signed with a key version, it is `"Unavailable"` with
the value as carried, and the event still decrypts. A removal's re-encrypted
title never arrives as a `TitleChanged`. A change that removes the title
decrypts to an empty title.

```go
// 0.5.x
var change struct {
	ChangeType string `json:"change_type"`
	NewTitle   string `json:"new_title"`
}
must(json.Unmarshal(groupChange.Change, &change))
if change.ChangeType == "TitleChanged" {
	title, err := chat.Decrypt(change.NewTitle, keys[conversationKeyVersion])
	must(err)
	showTitle(title)
}

// 0.7.2
var change struct {
	ChangeType string            `json:"change_type"`
	NewTitle   chatxdk.GroupText `json:"new_title"`
}
must(json.Unmarshal(groupChange.Change, &change))
if change.ChangeType == "TitleChanged" {
	if change.NewTitle.Kind == "Text" {
		showTitle(change.NewTitle.Text)
	} else {
		showTitle(change.NewTitle.Raw)
	}
}
```

### Changing the description

`PrepareGroupDescriptionChange` takes the new description as plaintext and
returns a `*PreparedGroupMetadataChange`, as the title change does; the
request sends its `EncryptedValue` as `group_description`.

```go
// 0.5.x
encryptedDescription, err := chat.Encrypt(description, keys[conversationKeyVersion])
must(err)
_, err = api.Put("/2/chat/conversations/"+pathID, map[string]any{
	"group_description":        encryptedDescription,
	"conversation_key_version": conversationKeyVersion,
	"modified_fields":          []string{"group_description"},
})
must(err)

// 0.7.2
prepared, err := chat.PrepareGroupDescriptionChange(chatxdk.GroupDescriptionChangeParams{
	ConversationID: conversationID,
	NewDescription: description,
})
must(err)
_, err = api.Put("/2/chat/conversations/"+pathID, map[string]any{
	"group_description":        prepared.EncryptedValue,
	"conversation_key_version": prepared.ConversationKeyVersion,
	"modified_fields":          []string{"group_description"},
	"action_signatures":        prepared.ActionSignatures,
})
must(err)
```

A received description change is a `DescriptionChanged` change holding
`new_description` as a `chatxdk.GroupText`; read it as a title change's
`new_title`. A change that removes the description decrypts to an empty
description. A removal's re-encrypted description never arrives as one:

```go
// 0.7.2
var change struct {
	ChangeType     string            `json:"change_type"`
	NewDescription chatxdk.GroupText `json:"new_description"`
}
must(json.Unmarshal(groupChange.Change, &change))
if change.ChangeType == "DescriptionChanged" {
	if change.NewDescription.Kind == "Text" {
		showDescription(change.NewDescription.Text)
	} else {
		showDescription(change.NewDescription.Raw)
	}
}
```

### Changing the avatar

An avatar URL is not encrypted; the image is. Encrypt the image bytes under
the conversation key with `EncryptFileWithKey`, as X clients do, upload them
to the group's media, and pass the image's media URL to
`PrepareGroupAvatarChange`, with the version of the key the image is
encrypted under. The call signs both as they are and returns a
`*PreparedAction`; send its `ActionSignatures` with the URL. A URL
containing a comma is rejected, since signatures join their fields with
commas. Send an avatar change after every key rotation too, with the image
encrypted under the new key, as X clients do.

```go
// 0.5.x
encrypted, err := chat.EncryptStream(photo, keys[conversationKeyVersion])
must(err)
encryptedAvatarURL, err := chat.Encrypt(avatarURL, keys[conversationKeyVersion])
must(err)
_, err = api.Put("/2/chat/conversations/"+pathID, map[string]any{
	"group_avatar_url":         encryptedAvatarURL,
	"conversation_key_version": conversationKeyVersion,
	"modified_fields":          []string{"group_avatar_url"},
})
must(err)

// 0.7.2
encrypted, err := chat.EncryptFileWithKey(chatxdk.EncryptFileWithKeyParams{
	File: photo, Key: keys[conversationKeyVersion],
})
must(err)
prepared, err := chat.PrepareGroupAvatarChange(chatxdk.GroupAvatarChangeParams{
	ConversationID:         conversationID,
	NewAvatarURL:           avatarURL,
	ConversationKeyVersion: conversationKeyVersion,
})
must(err)
_, err = api.Put("/2/chat/conversations/"+pathID, map[string]any{
	"group_avatar_url":         avatarURL,
	"conversation_key_version": conversationKeyVersion,
	"modified_fields":          []string{"group_avatar_url"},
	"action_signatures":        prepared.ActionSignatures,
})
must(err)
```

In both, `avatarURL` is the media URL of the uploaded `encrypted` image. A
received `AvatarChanged` change holds `new_avatar_url` as sent and its
`conversation_key_version`: download the image and decrypt it with
`DecryptFileWithKey` under the key for that version. A change that removes
the avatar holds an empty `new_avatar_url`.

```go
// 0.7.2
var change struct {
	ChangeType             string  `json:"change_type"`
	NewAvatarURL           string  `json:"new_avatar_url"`
	ConversationKeyVersion *string `json:"conversation_key_version"`
}
must(json.Unmarshal(groupChange.Change, &change))
if change.ChangeType == "AvatarChanged" && change.ConversationKeyVersion != nil {
	image, err := chat.DecryptFileWithKey(chatxdk.DecryptFileWithKeyParams{
		Encrypted: downloaded, Key: keys[*change.ConversationKeyVersion],
	})
	must(err)
	showAvatar(image)
}
```

### Admins, invites, join requests, message TTL and screen capture

Each of these calls returns a `*PreparedAction` with one signature, at
signature version 7, or 10 while the chat sends v1, for the request [The
requests](#the-requests) names. 0.5.x apps sent these requests without
signatures; recipients drop them unsigned. A recipient's `DecryptEvent`
returns admin, invite and join changes as verified `GroupChange` events
(`AdminsAdded`, `AdminsRemoved`, `InviteEnabled`, `InviteDisabled`,
`JoinRequested`, `JoinRejected`) and TTL and screen-capture changes as
verified `SettingsChange` events.

```go
// 0.5.x
_, err := api.Post("/2/chat/conversations/"+pathID+"/admins", map[string]any{"user_ids": userIDs})
must(err)

// 0.7.2
added, err := chat.PrepareGroupAdminsAdd(chatxdk.GroupAdminsAddParams{
	ConversationID: conversationID, UserIDs: userIDs,
})
must(err)
_, err = api.Post("/2/chat/conversations/"+pathID+"/admins", map[string]any{
	"user_ids": userIDs, "action_signatures": added.ActionSignatures,
})
must(err)
removed, err := chat.PrepareGroupAdminsRemove(chatxdk.GroupAdminsRemoveParams{
	ConversationID: conversationID, UserIDs: userIDs,
})
must(err)
_, err = api.Post("/2/chat/conversations/"+pathID+"/admins/remove", map[string]any{
	"user_ids": userIDs, "action_signatures": removed.ActionSignatures,
})
must(err)
```

An invite signs its URL, its expiry and its affiliate; a nil
`ExpiresAtMsec` or an empty `AffiliateID` signs `null`. The request sends
the expiry as `validity_expiry_timestamp_msec`, and only with the same value
the params signed:

```go
// 0.7.2
invite, err := chat.PrepareGroupInviteEnable(chatxdk.GroupInviteEnableParams{
	ConversationID: conversationID, InviteURL: inviteURL, ExpiresAtMsec: &expiresAtMsec,
})
must(err)
_, err = api.Post("/2/chat/conversations/"+pathID+"/invite", map[string]any{
	"invite_url":                     inviteURL,
	"validity_expiry_timestamp_msec": fmt.Sprint(expiresAtMsec),
	"action_signatures":              invite.ActionSignatures,
})
must(err)
disabled, err := chat.PrepareGroupInviteDisable(chatxdk.GroupInviteDisableParams{
	ConversationID: conversationID,
})
must(err)
_, err = api.Delete("/2/chat/conversations/"+pathID+"/invite", map[string]any{
	"action_signatures": disabled.ActionSignatures,
})
must(err)
```

A join request signs the requesting user, who defaults to the sender; the
invite token travels in the request but not in the signature:

```go
// 0.7.2
request, err := chat.PrepareGroupJoinRequest(chatxdk.GroupJoinRequestParams{
	ConversationID: conversationID,
})
must(err)
_, err = api.Post("/2/chat/conversations/"+pathID+"/join_requests", map[string]any{
	"token": inviteToken, "action_signatures": request.ActionSignatures,
})
must(err)
rejected, err := chat.PrepareGroupJoinReject(chatxdk.GroupJoinRejectParams{
	ConversationID: conversationID, UserIDs: userIDs,
})
must(err)
_, err = api.Post("/2/chat/conversations/"+pathID+"/join_requests/reject", map[string]any{
	"user_ids": userIDs, "action_signatures": rejected.ActionSignatures,
})
must(err)
```

A TTL change signs `TTLMsec` only; a negative one is rejected:

```go
// 0.7.2
ttl, err := chat.PrepareMessageTtlChange(chatxdk.MessageTtlChangeParams{
	ConversationID: conversationID, TTLMsec: ttlMsec,
})
must(err)
_, err = api.Put("/2/chat/conversations/"+pathID+"/message_ttl", map[string]any{
	"message_ttl_ms": fmt.Sprint(ttlMsec), "action_signatures": ttl.ActionSignatures,
})
must(err)
cleared, err := chat.PrepareMessageTtlRemove(chatxdk.MessageTtlRemoveParams{
	ConversationID: conversationID,
})
must(err)
_, err = api.Delete("/2/chat/conversations/"+pathID+"/message_ttl", map[string]any{
	"action_signatures": cleared.ActionSignatures,
})
must(err)
```

A screen-capture change is one of `chatxdk.BlockingEnabled`,
`BlockingDisabled`, `DetectionEnabled` or `DetectionDisabled`. The request
names its signatures after the setting, `blocking_action_signatures` or
`detection_action_signatures`, not `action_signatures`:

```go
// 0.7.2
capture, err := chat.PrepareScreenCapture(chatxdk.ScreenCaptureParams{
	ConversationID: conversationID,
	Change:         chatxdk.BlockingEnabled,
})
must(err)
_, err = api.Put("/2/chat/conversations/"+pathID+"/screen_capture", map[string]any{
	"blocking": true, "blocking_action_signatures": capture.ActionSignatures,
})
must(err)
```

## 5. Verify

### Build

Run `go build ./... && go vet ./...` and your tests: the compiler flags
every call that still passes 0.5.x arguments and every renamed field.

### Find the 0.5.x names

Search the app for the names in the symbol index's 0.5.x column. Each hit is
a line to change, unless it is your own code that shares the name:

```sh
grep -rnE "EncryptStream|DecryptStream|Stream(En|De)cryptor|EncryptedStreamSize|ImportKeysWithVersion|GuessesRemaining\(|\.Encrypt\(|EncryptedContent|EncodedEventSignature|GenerateVersion|\.Messages\b|DecryptedEventMessage|EncryptedKeyForRecipient|\bParticipantKey\b|\.ParticipantKeys\b|\.EncryptedKey\b|\.KeyVersion\b|\bKeyVersion:|SeenUntilID\b|\.TargetMessageID\b|\bAvatarURL:|\.(Setup|Unlock)\([^)]*,|\"(message_ids|new_text|seen_until_id)\"" --include='*.go' .
grep -rn "target_message_id" --include='*.go' .
```

Every `target_message_id` the second search finds should read a v1 edit's
signed message id; rename the rest to `target_message_sequence_id`. Each
`EncryptStream` and `DecryptStream` the first finds is a message's file or a
file under a key you hold, and [Encrypt a file under a key you
hold](#encrypt-a-file-under-a-key-you-hold) says which call each moves to.

### Run a round trip

This round trip runs offline, with two chats standing in for two users. It
registers both, starts a conversation, sends a message and decrypts it with
`SetRejectUnverified` on, the default, so the signature has to verify:

```go
// 0.7.2
alice, bob := chatxdk.New(), chatxdk.New()
defer alice.Close()
defer bob.Close()
aliceRegistration, err := alice.GenerateKeypairs()
must(err)
bobRegistration, err := bob.GenerateKeypairs()
must(err)
aliceKeys, bobKeys := aliceRegistration.PublicKey, bobRegistration.PublicKey
must(alice.SetIdentity(chatxdk.SetIdentityParams{UserID: "1001", SigningKeyVersion: "1"}))
must(bob.SetIdentity(chatxdk.SetIdentityParams{UserID: "1002", SigningKeyVersion: "1"}))

change, err := alice.PrepareConversationKeyChange(chatxdk.ConversationKeyChangeParams{
	PublicKeys: []chatxdk.PublicKeyInput{
		{UserID: "1001", IdentityPublicKey: aliceKeys.PublicKey, PublicKeyVersion: "1"},
		{UserID: "1002", IdentityPublicKey: bobKeys.PublicKey, PublicKeyVersion: "1"},
	},
})
must(err)
payload, err := alice.EncryptMessage(chatxdk.EncryptMessageParams{
	ConversationID:         change.ConversationID,
	Text:                   "hello",
	ConversationKey:        change.ConversationKey,
	ConversationKeyVersion: change.ConversationKeyVersion,
})
must(err)

var bobKey []byte
for _, entry := range change.ConversationParticipantKeys {
	if entry.UserID == "1002" {
		bobKey, err = bob.DecryptConversationKey(entry.EncryptedConversationKey)
		must(err)
	}
}
event, err := bob.DecryptEvent(chatxdk.DecryptEventParams{
	EventB64:         payload.EventB64,
	ConversationKeys: map[string][]byte{change.ConversationKeyVersion: bobKey},
	SigningKeys: []chatxdk.SigningKeyEntry{{
		UserID:                     "1001",
		PublicKeyVersion:           "1",
		PublicKey:                  aliceKeys.SigningPublicKey,
		IdentityPublicKey:          aliceKeys.PublicKey,
		IdentityPublicKeySignature: aliceKeys.IdentityPublicKeySignature,
	}},
})
must(err)
message := event.AsMessage()
if message == nil || !message.Verified || message.Text() != "hello" {
	panic("round trip failed")
}
if v := payload.SignatureInfo.SignatureVersion; v != "7" && v != "10" {
	panic("unknown format " + v)
}
if !strings.HasPrefix(payload.XdkVersion, "0.7.") {
	panic("xdk version " + payload.XdkVersion)
}
```

`SignatureVersion` is `"7"` for a v0 send and `"10"` for v1, as the
`v1_send` switch decides. `XdkVersion` is the version of the module that
built the send, a 0.7 release, which the X API receives with each send.

Then run the same flows against a test conversation on the X API: send a
text, a file, a reply, an edit and a delete, mark the conversation read,
and create a group, set its avatar, add a member and remove one. Fetch the
conversation's events with `GET /2/chat/conversations/{id}/events`, pass
`data[].encoded_event` and `meta.conversation_key_events` to
`DecryptEvents` with every participant's signing keys, and check that every
event in `Events` has `Verified` set and that `Errors` holds only the
removal's title and description re-encryptions.
