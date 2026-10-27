# Migrating Go code to chat-xdk 0.6.0

This page lists every change that Go code written for
`github.com/xdevplatform/chat-xdk/go/chatxdk` 0.5.x (0.5.0, 0.5.1 or 0.5.2)
runs into in 0.6.0, each with the lines to change.
[Why 0.6.0 changes](why.md) explains why each change was made, and the
[index](README.md) lists the other bindings' pages. [API.md](../API.md)
documents every call, and the [CHANGELOG](../../CHANGELOG.md) lists every
change.

## Checklist

- [ ] [Upgrade every app that reads your conversations first](#upgrade-readers-before-v1-sends-start)
- [ ] [Allow or block the feature-switch request](#the-feature-switch-request)
- [ ] [Register keys with the public key only](#register-keys-with-the-public-key-only)
- [ ] [Pass a `SetIdentityParams` to `SetIdentity`](#setidentity-takes-setidentityparams)
- [ ] [Pass an `ImportKeysParams` to `ImportKeys`](#importkeys-takes-importkeysparams)
- [ ] [Create a Juicebox chat with `NewWithJuiceboxConfig`, and pass `Setup` and `Unlock` only the PIN](#keys-stored-in-juicebox)
- [ ] [Pass user ids as strings of digits](#user-ids-are-strings-of-digits)
- [ ] [Pass key versions as the X API returns them](#key-versions-are-integers-written-as-strings)
- [ ] [Pass a `DecryptEventsParams` to `DecryptEvents` and read its `Events`](#decryptevents-takes-decrypteventsparams)
- [ ] [Pass a `DecryptEventParams` to `DecryptEvent`](#decryptevent-takes-decrypteventparams)
- [ ] [Read `SendPayload` under the send request's field names and send `xdk_version`](#sendpayload-fields-take-the-send-requests-names)
- [ ] [Build a message before you encrypt its files](#encrypt-a-file-from-its-message)
- [ ] [Decrypt a file with the event of its message](#decrypt-a-file-with-its-messages-event)
- [ ] [Use `FileEncryptor` and `FileDecryptor` for large files](#encrypt-and-decrypt-large-files-in-chunks)
- [ ] [Pass action signatures through as returned](#action-signatures-come-nested)
- [ ] [Name a `PublicKeyInput`'s fields `IdentityPublicKey` and `PublicKeyVersion`](#public-key-inputs-name-the-identity-key-and-its-version)
- [ ] [Pass participant keys through as returned](#participant-keys-take-the-key-requests-names)
- [ ] [Read received participant keys under the same names](#received-participant-keys-take-the-same-names)
- [ ] [Read decrypted events under the names the calls take](#decrypted-events-use-the-names-the-calls-take)
- [ ] [Read a delete's signature from its `PreparedAction`](#deletes-return-a-preparedaction)
- [ ] [Read an error's kind and a wrong PIN's attempts from `*chatxdk.Error` with `errors.As`](#errors-carry-their-kind)
- [ ] [Group actions should be signed](#group-actions-should-be-signed)
- [ ] [Pass group titles and descriptions as plaintext, read them as `GroupText`, and sign an avatar by its media URL](#creating-a-group)
- [ ] [Sign read receipts](#read-receipts-should-be-signed)

## About the snippets

Each snippet shows the lines that change, first as 0.5.x code writes them
and then as 0.6.0 code writes them. `chat` is a `*chatxdk.Chat` with your
keys loaded, and the other names stand for your own values: ids, versions,
keys and events as the X API returns them, `keys` for the conversation key
map `DecryptEvents` returns, `payload` for a `*SendPayload`, `prepared` for
a `*PreparedConversationChange`, `keyChange`, `message`, `receipt` and
`groupChange` for a decrypted `*KeyChangeEvent`, `*Message`,
`ReadReceiptEvent` and `*GroupChangeEvent`, and `event` for a decrypted
`*Event`. `must(err)` stands for your error handling. `api.Post(path, body)`
stands for your HTTP client: it POSTs `body` as JSON to `https://api.x.com`
+ `path` with your user access token and returns the parsed JSON response as
a `map[string]any`. `photoAttachment(mediaHashKey)` stands for your code
that builds a photo's `AttachmentDescriptor`, and `showReaction`,
`showTitle`, `showDescription`, `showAvatar`, `showEvent` and
`showGuessesLeft` for your code that displays a reaction, a group's title,
description or avatar, a decrypted event, or the PIN attempts left. `pin`
is the PIN's bytes and `juiceboxConfig` the Juicebox config the X API
returns. `base64` (`encoding/base64`), `errors`, `json` (`encoding/json`)
and `strings` are the standard library's.

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
`payload.SignatureInfo.SignatureVersion`, `"7"` for v0 and `"10"` for v1.

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
switch, or block it to keep them v0. There's no code to change.

## Register keys with the public key only

`GenerateKeypairs` returns a `*PublicKeyRegistrationPayload` that holds only
`PublicKey`. Send it as the only field of the
`POST /2/users/{id}/public_keys` body, `public_key`. 0.6.0 doesn't pick a
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

// 0.6.0
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

## `SetIdentity` takes `SetIdentityParams`

Pass the user id and the signing-key version in a `SetIdentityParams`. It
returns an error when either value is invalid (see
[user ids](#user-ids-are-strings-of-digits) and
[key versions](#key-versions-are-integers-written-as-strings)).

```go
// 0.5.x
must(chat.SetIdentity(userID, signingKeyVersion))

// 0.6.0
must(chat.SetIdentity(chatxdk.SetIdentityParams{UserID: userID, SigningKeyVersion: signingKeyVersion}))
```

## `ImportKeys` takes `ImportKeysParams`

Pass the saved key bytes in an `ImportKeysParams`, and optionally the
signing-key version they were registered under as `SigningKeyVersion`.
Without a version, call `SetIdentity` before the first signed call.

```go
// 0.5.x
must(chat.ImportKeys(privateKeys))
must(chat.ImportKeysWithVersion(privateKeys, signingKeyVersion))

// 0.6.0
must(chat.ImportKeys(chatxdk.ImportKeysParams{Keys: privateKeys}))
must(chat.ImportKeys(chatxdk.ImportKeysParams{Keys: privateKeys, SigningKeyVersion: signingKeyVersion}))
```

`ExportKeys` returns an error of kind `ErrorKindInvalidState` when no
identity key is loaded, where it returned no keys and no error; check
`HasIdentityKey` first where that can happen.

## Keys stored in Juicebox

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

// 0.6.0
chat, err := chatxdk.NewWithJuiceboxConfig(juiceboxConfig)
must(err)
_, err = chat.Setup(pin)
must(err)
must(chat.Unlock(pin))
```

The PINs are `[]byte`, so you can zero yours once the call returns. Every
method of a `*chatxdk.Chat`, `UpdateConfig` included, is safe to call from
several goroutines at once; a Juicebox call already under way keeps the
config it started with. Until a chat has a config, `Setup`, `Unlock`,
`ChangePin` and `Delete` return an error of kind `ErrorKindInvalidState`,
`Invalid state: no Juicebox config: pass the juicebox_config the X API
returns when you create the chat, or call update_config() first`, the error
every binding gives, and a wrong PIN returns one of kind
`ErrorKindInvalidPin` (see [Errors carry their kind](#errors-carry-their-kind)).

## User ids are strings of digits

Every user id is a string of digits: the `SetIdentityParams` user id,
`SenderID`, `ReplyToSenderID`, the `UserID` of each `PublicKeyInput` and
`SigningKeyEntry`, and group member, admin and pending-member ids. Each must
be a positive integer written without a sign or leading zeros; anything else
returns an error that names the field, such as
`Invalid sender_id 'user-1': pass a numeric user id (digits only)`.
`EncryptReplyParams.ReplyToSenderID` is a `string`:

```go
// 0.5.x
replyTo := int64(4201)
params := chatxdk.EncryptReplyParams{
	ConversationID: conversationID, Text: "pong", ReplyToEvent: eventB64, ReplyToSenderID: &replyTo,
}

// 0.6.0
params := chatxdk.EncryptReplyParams{
	ConversationID: conversationID, Text: "pong", ReplyToEvent: eventB64, ReplyToSenderID: "4201",
}
```

## Key versions are integers written as strings

Every key version is a non-negative integer written as a string of digits,
as the X API returns it: the signing-key version (in `SetIdentityParams`,
`ImportKeysParams`, a call's `SigningKeyVersion` and each public key's
`PublicKeyVersion`) and `ConversationKeyVersion`. Anything else returns an error
that names the field, such as `Invalid signing_key_version 'v1': pass the
key version as the X API returns it, an integer in digits`. There's no code
to change if you pass the versions the X API returns.

## `DecryptEvents` takes `DecryptEventsParams`

Pass the events in a `DecryptEventsParams`. `SigningKeys` is optional;
`nil` verifies with the keys `SetSigningKeys` stored. Per-event errors are
still collected in the result, and the call returns an error only for
invalid params. The result holds the decrypted events, of every event type,
in `Events`, each a `DecryptedEvent`:

```go
// 0.5.x
result, err := chat.DecryptEvents(events, signingKeys)
must(err)
for _, decrypted := range result.Messages {
	showEvent(decrypted.Event)
}

// 0.6.0
result, err := chat.DecryptEvents(chatxdk.DecryptEventsParams{Events: events, SigningKeys: signingKeys})
must(err)
for _, decrypted := range result.Events {
	showEvent(decrypted.Event)
}
```

`result.ConversationKeys.LatestVersion`, the version to encrypt with, is
the newest version whose key change verified, and it never moves back for
the chat's lifetime. It's `nil` until a key change verifies: a key change
the SDK can't verify still adds its key to `result.ConversationKeys.Keys`,
for decrypting, but never becomes the version you encrypt with.

## `DecryptEvent` takes `DecryptEventParams`

Pass the event in a `DecryptEventParams`. Both key fields are optional: a
`nil` `ConversationKeys` resolves the key from the key cache
(`SetCacheKeys(true)`), and `nil` `SigningKeys` verifies with the keys
`SetSigningKeys` stored. It still returns an error on failure.

```go
// 0.5.x
event, err := chat.DecryptEvent(eventB64, keys, signingKeys)
must(err)

// 0.6.0
event, err := chat.DecryptEvent(chatxdk.DecryptEventParams{
	EventB64: eventB64, ConversationKeys: keys, SigningKeys: signingKeys,
})
must(err)
```

## `SendPayload` fields take the send request's names

The two encoded fields carry the names of the fields of the send request,
`POST /2/chat/conversations/{id}/messages`, so the request takes them as
they are. The request also takes the payload's `XdkVersion`, the version of
the SDK that built it, as `xdk_version`:

```go
// 0.5.x
body := map[string]string{
	"message_id":                      payload.MessageID,
	"encoded_message_create_event":    payload.EncryptedContent,
	"encoded_message_event_signature": payload.EncodedEventSignature,
}

// 0.6.0
body := map[string]string{
	"message_id":                      payload.MessageID,
	"encoded_message_create_event":    payload.EncodedMessageCreateEvent,
	"encoded_message_event_signature": payload.EncodedMessageEventSignature,
	"xdk_version":                     payload.XdkVersion,
}
```

Read them under those names wherever your code reads a payload, including
code that stores payloads. A payload also carries `EventB64`, the message
as recipients receive it. It isn't part of the send request: keep it to
encrypt the message's files (see
[Encrypt a file from its message](#encrypt-a-file-from-its-message)).

## Encrypt a file from its message

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

// 0.6.0
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
the same id, so recipients drop it as a repeat. A message that lists an
empty media hash key, or one media hash key twice, is rejected, and so is a
file whose `Filename` is empty or whose `FilesizeBytes` is 0 or less, which
receiving clients would discard: give each file its name and the encrypted
size `chatxdk.EncryptedFileSize` gives.

## Decrypt a file with its message's event

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

// 0.6.0
plaintext, err := chat.DecryptFile(chatxdk.DecryptFileParams{
	Encrypted: downloaded, EventB64: fileEventB64, ConversationKeys: keys, MediaHashKey: fileHashKey,
})
must(err)
```

## Encrypt and decrypt large files in chunks

`FileEncryptor` and `FileDecryptor` take the same values as `EncryptFile`
and `DecryptFile`, without the file bytes, and return a `*FileEncryptor` or
a `*FileDecryptor`; `Push`, `Finish` and `Close` are unchanged. Size an
upload with `EncryptedFileSize`.

```go
// 0.5.x
size, err := chatxdk.EncryptedStreamSize(uint64(len(photo)))
must(err)
encryptor, err := chat.StreamEncryptor(conversationKey)
must(err)
decryptor, err := chat.StreamDecryptor(keys[conversationKeyVersion])
must(err)

// 0.6.0
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

## Action signatures come nested

The prepare methods return each `ActionSignature` in the shape a request's
`action_signatures` takes: `MessageID`, `EncodedMessageEventDetail`, the
signature in `MessageEventSignature` (with `SigningPublicKey`, your signing
public key as `GetPublicKeys` returns it), and nothing else: the signed
payload stays inside the SDK. Marshal them as returned:

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

// 0.6.0
actionSignatures := prepared.ActionSignatures
```

## Public key inputs name the identity key and its version

A `PublicKeyInput`, one participant a conversation key is encrypted to,
names its key `IdentityPublicKey` and the key's version `PublicKeyVersion`,
as `SigningKeyEntry` does: the `public_key` the X API returns for a user is
their identity key:

```go
// 0.5.x
publicKeys = append(publicKeys, chatxdk.PublicKeyInput{UserID: userID, PublicKey: identityPublicKey, KeyVersion: publicKeyVersion})

// 0.6.0
publicKeys = append(publicKeys, chatxdk.PublicKeyInput{UserID: userID, IdentityPublicKey: identityPublicKey, PublicKeyVersion: publicKeyVersion})
```

## Participant keys take the key requests' names

A prepared change's participant keys carry the names the X API gives them in
every request that takes them (`POST /2/chat/conversations/{id}/keys`,
`/group` and `/{id}/members`, and `PUT /2/chat/conversations/{id}`):
`ConversationParticipantKeys`, a slice of `ConversationParticipantKey` whose
fields (`UserID`, `EncryptedConversationKey`, `PublicKeyVersion`) marshal as
`user_id`, `encrypted_conversation_key` and `public_key_version`, the type a
received key change uses too
(see [Received participant keys take the same names](#received-participant-keys-take-the-same-names)). Drop the renaming
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

// 0.6.0
conversationParticipantKeys := prepared.ConversationParticipantKeys
```

## Received participant keys take the same names

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

// 0.6.0
var key chatxdk.ConversationParticipantKey = keyChange.ConversationParticipantKeys[0]
encrypted := key.EncryptedConversationKey
```

## Decrypted events use the names the calls take

`Message` and `KeyChangeEvent` carry their conversation key version as
`ConversationKeyVersion` (`conversation_key_version` in JSON), the name the
X API's events and the Thrift events give it, and the name the encrypt
params take:

```go
// 0.5.x
messageVersion := *message.KeyVersion
keyChangeVersion := keyChange.KeyVersion

// 0.6.0
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

// 0.6.0
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
for a v0 edit:

```go
// 0.5.x
var deleted struct {
	MessageIDs []string `json:"message_ids"`
}
must(json.Unmarshal(event.Raw(), &deleted))

// 0.6.0
var deleted struct {
	SequenceIDs []string `json:"sequence_ids"`
}
must(json.Unmarshal(event.Raw(), &deleted))
```

## Deletes return a `PreparedAction`

`PrepareMessageDelete` returns a `*PreparedAction` whose `ActionSignatures`
hold one entry, shaped as [Action signatures come
nested](#action-signatures-come-nested) shows. Read the action's `MessageID`
from that entry, and send `ActionSignatures` as returned:

```go
// 0.5.x
deletion, err := chat.PrepareMessageDelete(chatxdk.MessageDeleteParams{
	ConversationID: conversationID, SequenceIDs: sequenceIDs,
})
must(err)
messageID := deletion.MessageID

// 0.6.0
deletion, err := chat.PrepareMessageDelete(chatxdk.MessageDeleteParams{
	ConversationID: conversationID, SequenceIDs: sequenceIDs,
})
must(err)
messageID := deletion.ActionSignatures[0].MessageID
```

## Errors carry their kind

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

// 0.6.0
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
names the input, rather than a generic one. An entity of a type the SDK
doesn't know, an empty one included, fails the same way, with `Invalid
entity_type 'user_mention': pass url, mention, hashtag, cashtag, email,
address or phone_number`, where 0.5.x sent the message without that entity.
Errors about state the chat lacks, such as a missing session identity or an
empty key cache, are of kind `ErrorKindInvalidState` and keep their prefix.
Match the kind rather than the message.

## Group actions should be signed

Apps should sign each group update below. The sender comes from `SetIdentity`.
Each returns `ActionSignatures` shaped as
[Action signatures come nested](#action-signatures-come-nested) shows. Send
those entries on the update's request.

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

// 0.6.0
prepared, err := chat.PrepareGroupCreate(chatxdk.GroupCreateParams{
	PublicKeys:     publicKeys,
	ConversationID: conversationID,
	MemberIDs:      memberIDs,
	AdminIDs:       adminIDs,
	Title:          title,
})
must(err)
body := map[string]any{"group_name": prepared.EncryptedTitle}
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
`group_description` the X API returns with a conversation still open with
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

// 0.6.0
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
image is encrypted under that key version.

### Adding members

`PrepareGroupMembersChange` rotates the conversation key, so it re-encrypts
the group's title and description under the key it generates: set them as
plaintext, in `CurrentTitle` and `CurrentDescription`, not as values your
code encrypted. The result carries them encrypted, as `EncryptedTitle` and
`EncryptedDescription` (nil when unset). Send `EncryptedTitle` as the
add-members request's `encrypted_title`; the description travels in the
signed member add.

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

// 0.6.0
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
body := map[string]any{"encrypted_title": prepared.EncryptedTitle}
```

Passing a description makes the add sign at signature version 8, the first
version whose member-add payload covers one, and 0.5.x readers can't verify
a version-8 add. Until every app that reads your groups runs 0.6.0, leave
the description out, so the add signs at version 7 as in 0.5.x; the new
members can read the description once a description change sets it under the
new key.

The avatar isn't re-encrypted: `CurrentAvatarURL` takes its media URL,
signed as is, and the image stays encrypted under the key it was uploaded
with, which the new members never receive. To keep the avatar readable for
them, encrypt the image under the key the add returns, upload it, and send
an [avatar change](#changing-the-avatar) naming the new key version.

### Removing members

`PrepareGroupMembersRemove` removes `UserIDs` and rotates the conversation
key, so the members removed don't receive the key the group encrypts under
next. `PublicKeys` are the identity keys of the members who stay; a key for
a member being removed returns an error. The group's title and description
are encrypted under the conversation key: set the ones the group has, as
plaintext, in `Title` and `Description`, and the call encrypts each under
the new key and signs it as a key-rotation re-encryption, which X clients
don't show as a change. A rotation leaves the avatar alone: its image stays
encrypted under the key it was uploaded with, which the members who stay
hold.

The result is a `*PreparedConversationChange`: the new `ConversationKey`,
`ConversationParticipantKeys` for the members who stay, and
`ActionSignatures` in request order — the removal, a title change and a
description change for the ones set, then the conversation-key change. Store
the new key as you store the key a key change returns.

The removal signs at signature version 11, the first whose removal payload
covers the key version, and 0.5.x readers can't verify it: upgrade every app
that reads your groups before you remove members.

POST `/2/chat/conversations/{id}/members/remove` with `user_ids`, the
signatures, and `group_key_rotation_data` holding the new
`conversation_key_version` and `conversation_participant_keys`.

```go
// 0.6.0
prepared, err := chat.PrepareGroupMembersRemove(chatxdk.GroupMembersRemoveParams{
	PublicKeys:     remainingPublicKeys,
	ConversationID: conversationID,
	UserIDs:        userIDs,
	Title:          title,
})
must(err)
path := "/2/chat/conversations/" + conversationID + "/members/remove"
_, err = api.Post(path, map[string]any{
	"user_ids":          userIDs,
	"action_signatures": prepared.ActionSignatures,
	"group_key_rotation_data": map[string]any{
		"conversation_key_version":      prepared.ConversationKeyVersion,
		"conversation_participant_keys": prepared.ConversationParticipantKeys,
	},
})
must(err)
```

### Leaving a group

`PrepareGroupLeave` signs the sender's removal and does not rotate the
conversation key. `ActionSignatures` are the removal, then a
`GroupAdminAddChange` when `PromoteAdminID` is set, then a
`ConversationDeleteEvent`. It returns a `*PreparedAction`.

```go
// 0.6.0
left, err := chat.PrepareGroupLeave(chatxdk.GroupLeaveParams{
	ConversationID: conversationID,
	PromoteAdminID: promoteAdminID,
})
must(err)
// left.ActionSignatures: removal, GroupAdminAddChange, ConversationDeleteEvent
```

### Changing the title

`PrepareGroupTitleChange` takes the new title as plaintext, encrypts it
under the conversation key and signs it. Like `EncryptMessageParams`,
`GroupTitleChangeParams` takes the key and its version in
`ConversationKey` and `ConversationKeyVersion`, or resolves both from the
key cache when they're empty. The result is a
`*PreparedGroupMetadataChange`: the `EncryptedValue` the request sends as
the title, the `ConversationKeyVersion` it's encrypted under, and the
`ActionSignatures` to send with it.

```go
// 0.5.x
encryptedTitle, err := chat.Encrypt(title, keys[conversationKeyVersion])
must(err)

// 0.6.0
prepared, err := chat.PrepareGroupTitleChange(chatxdk.GroupTitleChangeParams{
	ConversationID: conversationID,
	NewTitle:       title,
})
must(err)
encryptedTitle := prepared.EncryptedValue
```

`DecryptEvent` returns a received title change decrypted: the `new_title` of
a `TitleChanged` change, in the `Change` JSON, decodes into a
`chatxdk.GroupText`, as a create's `title` does. It decrypts with the key
for the version the change names, from the call's key map or the key cache.
Without that key, or when the value isn't ciphertext under it, as for a
plaintext title an app signed with a key version, it is `"Unavailable"` with
the value as carried, and the event still decrypts.

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

// 0.6.0
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

### Changing the avatar

An avatar URL is not encrypted; the image is. Encrypt the image bytes under
the conversation key, upload them to the group's media, and pass the image's
media URL to `PrepareGroupAvatarChange`, with the version of the key the
image is encrypted under. The call signs both as they are and returns a
`*PreparedAction`; send its `ActionSignatures` with the URL. A URL
containing a comma is rejected, since signatures join their fields with
commas.

```go
// 0.5.x
encryptedAvatarURL, err := chat.Encrypt(avatarURL, keys[conversationKeyVersion])
must(err)

// 0.6.0
prepared, err := chat.PrepareGroupAvatarChange(chatxdk.GroupAvatarChangeParams{
	ConversationID:         conversationID,
	NewAvatarURL:           avatarURL,
	ConversationKeyVersion: conversationKeyVersion,
})
must(err)
```

A received `AvatarChanged` change holds `new_avatar_url` as sent and its
`conversation_key_version`: download the image and decrypt it with the key
for that version.

```go
// 0.6.0
var change struct {
	ChangeType             string `json:"change_type"`
	NewAvatarURL           string `json:"new_avatar_url"`
	ConversationKeyVersion string `json:"conversation_key_version"`
}
must(json.Unmarshal(groupChange.Change, &change))
if change.ChangeType == "AvatarChanged" {
	showAvatar(change.NewAvatarURL, change.ConversationKeyVersion)
}
```

### Changing the description

`PrepareGroupDescriptionChange` takes the new description as plaintext and
returns a `*PreparedGroupMetadataChange`, as the title change does.

```go
// 0.5.x
encryptedDescription, err := chat.Encrypt(description, keys[conversationKeyVersion])
must(err)

// 0.6.0
prepared, err := chat.PrepareGroupDescriptionChange(chatxdk.GroupDescriptionChangeParams{
	ConversationID: conversationID,
	NewDescription: description,
})
must(err)
encryptedDescription := prepared.EncryptedValue
```

A received description change is a `DescriptionChanged` change holding
`new_description` as a `chatxdk.GroupText`; read it as a title change's
`new_title`:

```go
// 0.6.0
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

### Adding admins

```go
// 0.6.0
added, err := chat.PrepareGroupAdminsAdd(chatxdk.GroupAdminsAddParams{
	ConversationID: conversationID,
	UserIDs:        userIDs,
})
must(err)
```

### Removing admins

```go
// 0.6.0
removed, err := chat.PrepareGroupAdminsRemove(chatxdk.GroupAdminsRemoveParams{
	ConversationID: conversationID,
	UserIDs:        userIDs,
})
must(err)
```

### Enabling an invite

A nil `ExpiresAtMsec` or an empty `AffiliateID` signs `null`.

```go
// 0.6.0
invite, err := chat.PrepareGroupInviteEnable(chatxdk.GroupInviteEnableParams{
	ConversationID: conversationID,
	InviteURL:      inviteURL,
})
must(err)
```

### Disabling an invite

An empty `DisabledBy` uses the sender.

```go
// 0.6.0
disabled, err := chat.PrepareGroupInviteDisable(chatxdk.GroupInviteDisableParams{
	ConversationID: conversationID,
})
must(err)
```

### Requesting to join

An empty `RequestingUserID` uses the sender. An invite token is not part of
the signature.

```go
// 0.6.0
request, err := chat.PrepareGroupJoinRequest(chatxdk.GroupJoinRequestParams{
	ConversationID: conversationID,
})
must(err)
```

### Rejecting join requests

```go
// 0.6.0
rejected, err := chat.PrepareGroupJoinReject(chatxdk.GroupJoinRejectParams{
	ConversationID: conversationID,
	UserIDs:        userIDs,
})
must(err)
```

### Changing the message TTL

The signature covers `TTLMsec` only.

```go
// 0.6.0
ttl, err := chat.PrepareMessageTtlChange(chatxdk.MessageTtlChangeParams{
	ConversationID: conversationID,
	TTLMsec:        ttlMsec,
})
must(err)
```

### Removing the message TTL

```go
// 0.6.0
cleared, err := chat.PrepareMessageTtlRemove(chatxdk.MessageTtlRemoveParams{
	ConversationID: conversationID,
})
must(err)
```

### Changing screen capture

`Change` is a `ScreenCaptureChange`: `BlockingEnabled`,
`BlockingDisabled`, `DetectionEnabled`, or `DetectionDisabled`.

```go
// 0.6.0
capture, err := chat.PrepareScreenCapture(chatxdk.ScreenCaptureParams{
	ConversationID: conversationID,
	Change:         chatxdk.BlockingEnabled,
})
must(err)
```

## Read receipts should be signed

Apps should sign a read receipt with `PrepareMarkConversationRead` and send
the `PreparedAction`'s `ActionSignatures` as the `action_signatures` of
`POST /2/chat/conversations/{id}/read`. Recipients on the default policy
reject an unsigned receipt. The call takes a `MarkConversationReadParams`
(`ConversationID`, `SeenUntilSequenceID`, the sequence id of the newest
event read, and a `SeenAtMsec` that defaults to now) and returns a
`*PreparedAction`, one entry shaped as
[Action signatures come nested](#action-signatures-come-nested) shows. The
path takes the conversation id in its hyphen form. A recipient's
`DecryptEvent` returns a signed receipt as a verified `ReadReceipt` event.

```go
// 0.6.0
receipt, err := chat.PrepareMarkConversationRead(chatxdk.MarkConversationReadParams{
	ConversationID: conversationID, SeenUntilSequenceID: seenUntilSequenceID,
})
must(err)
path := "/2/chat/conversations/" + strings.ReplaceAll(conversationID, ":", "-") + "/read"
_, err = api.Post(path, map[string]any{"action_signatures": receipt.ActionSignatures})
must(err)
```
