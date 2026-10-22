# Migrating Go code to chat-xdk 0.6.0

This page lists every change that Go code written for
`github.com/xdevplatform/chat-xdk/go/chatxdk` 0.5.x (0.5.0, 0.5.1 or 0.5.2)
runs into in 0.6.0, each with the lines to change. The other bindings have
their own pages, listed in the [index](README.md). [API.md](../API.md)
documents every call, and the [CHANGELOG](../../CHANGELOG.md) lists every
change.

## Checklist

- [ ] [Upgrade every app that reads your conversations first](#upgrade-readers-before-v1-sends-start)
- [ ] [Allow or block the feature-switch request, and close chats you're done with](#the-feature-switch-request)
- [ ] [Register keys with the public key only](#register-keys-with-the-public-key-only)
- [ ] [Pass a `SetIdentityParams` to `SetIdentity`](#setidentity-takes-setidentityparams)
- [ ] [Pass an `ImportKeysParams` to `ImportKeys`](#importkeys-takes-importkeysparams)
- [ ] [Pass user ids as strings of digits](#user-ids-are-strings-of-digits)
- [ ] [Pass key versions as the X API returns them](#key-versions-are-integers-written-as-strings)
- [ ] [Pass a `DecryptEventsParams` to `DecryptEvents`](#decryptevents-takes-decrypteventsparams)
- [ ] [Pass a `DecryptEventParams` to `DecryptEvent`](#decryptevent-takes-decrypteventparams)
- [ ] [Read `SendPayload` under the send request's field names](#sendpayload-fields-take-the-send-requests-names)
- [ ] [Don't send `XdkVersion` yet](#xdkversion-dont-send-it-yet)
- [ ] [Build a message before you encrypt its files](#encrypt-a-file-from-its-message)
- [ ] [Decrypt a file with the event of its message](#decrypt-a-file-with-its-messages-event)
- [ ] [Use `FileEncryptor` and `FileDecryptor` for large files](#encrypt-and-decrypt-large-files-in-chunks)
- [ ] [Pass action signatures through as returned](#action-signatures-come-nested)
- [ ] [Read a delete's signature from its `PreparedAction`](#deletes-return-a-preparedaction)
- [ ] [Check code that reads error messages](#invalid-input-errors)
- [ ] [Optional: sign read receipts (pending)](#signed-read-receipts-new-pending)

## About the snippets

Each snippet shows the lines that change, first as 0.5.x code writes them
and then as 0.6.0 code writes them. `chat` is a `*chatxdk.Chat` with your
keys loaded, and the other names stand for your own values: ids, versions,
keys and events as the X API returns them, `keys` for the conversation key
map `DecryptEvents` returns, `payload` for a `*SendPayload` and `prepared`
for a `*PreparedConversationChange`. `must(err)` stands for your error
handling, and `startUpload`, `upload`, `finishUpload`, `photoAttachment` and
`registerPublicKey` for your own upload and request code.

## Upgrade readers before v1 sends start

0.6.0 sends each message, reply, reaction and edit in one of two formats.
v0 is the format 0.5.x sends. v1 encrypts each message under its own key,
derived from the conversation key, the sender and the message id, and signs
it at signature version 10. A chat sends v1 only once the X API turns on its
`v1_send` feature switch (see
[The feature-switch request](#the-feature-switch-request)); until then every
send is v0.

0.5.x rejects every v1 send as a signature verification failure, so upgrade
every app that reads your conversations to 0.6.0 before your senders can
send v1. 0.6.0 reads both formats, including v1 reply previews, edits and
files. There's no code to change: to see which format a send used, read
`payload.SignatureInfo.SignatureVersion`, `"7"` for v0 and `"10"` for v1.

## The feature-switch request

Each `Chat` reads the X API's feature switches with one anonymous request,
`GET https://api.x.com/2/chat/features`, which runs in the background:

- when the chat is created, again once its keys load (with a `bucket` query
  parameter, 0–9999, derived from the identity public key), and every
  5 minutes after that;
- chats in one process that ask for the same bucket at the same time share
  one request;
- it carries no credentials, and never delays or fails a call;
- if it fails or is blocked, every switch stays off and sends stay v0; a
  failed request is retried with a backoff that grows to 5 minutes;
- the 5-minute re-checks can only turn a switch off: a chat picks up a switch
  turning on only when it is created again.

**Pending:** the X API doesn't serve this route yet. Until it does, the
request fails and every send is v0.

Allow outbound HTTPS to `api.x.com` if you want your sends to follow the
switch, or block it to keep them v0. Close each chat when you're done with
it to stop its requests; a chat that is garbage-collected stops them too:

```go
// 0.6.0
chat := chatxdk.New()
defer chat.Close()
```

## Register keys with the public key only

`GenerateKeypairs` returns a `*PublicKeyRegistrationPayload` that holds only
`PublicKey`. Send it as the only field of the
`POST /2/users/:id/public_keys` body, `public_key`. 0.6.0 doesn't pick a
signing-key version for new keys: after you register, call `SetIdentity`
with the `public_key_version` the X API returns (see the next section). A
signed call made without a version returns the error `Invalid state:
signing_key_version is not set: pass it explicitly or call set_identity()
first`.

```go
// 0.5.x
registration, err := chat.GenerateKeypairs()
must(err)
body := map[string]any{
	"public_key":       registration.PublicKey,
	"version":          registration.Version,
	"generate_version": registration.GenerateVersion,
}
publicKeyVersion := registerPublicKey(userID, body)
must(chat.SetIdentity(userID, publicKeyVersion))

// 0.6.0
registration, err := chat.GenerateKeypairs()
must(err)
body := map[string]any{"public_key": registration.PublicKey}
publicKeyVersion := registerPublicKey(userID, body)
must(chat.SetIdentity(chatxdk.SetIdentityParams{UserID: userID, SigningKeyVersion: publicKeyVersion}))
```

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
`KeyVersion`) and `ConversationKeyVersion`. Anything else returns an error
that names the field, such as `Invalid signing_key_version 'v1': pass the
key version as the X API returns it, an integer in digits`. There's no code
to change if you pass the versions the X API returns.

## `DecryptEvents` takes `DecryptEventsParams`

Pass the events in a `DecryptEventsParams`. `SigningKeys` is optional;
`nil` verifies with the keys `SetSigningKeys` stored. The result is
unchanged, and per-event errors are still collected in it.

```go
// 0.5.x
result, err := chat.DecryptEvents(events, signingKeys)
must(err)

// 0.6.0
result, err := chat.DecryptEvents(chatxdk.DecryptEventsParams{Events: events, SigningKeys: signingKeys})
must(err)
```

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

The two encoded fields carry the names of the send request's fields, so the
request takes them as they are:

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
}
```

A `SendPayload` that 0.5.x code marshaled to JSON still unmarshals into the
new fields, with `EventB64` and `XdkVersion` empty. A payload also carries
`EventB64`, the message as recipients receive it. It isn't part of the send
request: keep it to encrypt the message's files (see
[Encrypt a file from its message](#encrypt-a-file-from-its-message)).

## `XdkVersion`: don't send it yet

`payload.XdkVersion` is the version of the SDK that built the payload.
Don't add it to the send request yet: the request takes it as an optional
`xdk_version` field only once the X API documents that field.

## Encrypt a file from its message

Each file is encrypted from the message that carries it, so build the
message first:

1. Start each file's upload, declaring `EncryptedFileSize` of the file's
   size, and keep its media hash key.
2. Encrypt the message with attachments that name those media hash keys.
3. Encrypt each file with `EncryptFile`, passing the payload's `EventB64`
   and the file's media hash key.
4. Finish the uploads, then send the message.

```go
// 0.5.x
encrypted, err := chat.EncryptStream(photo, conversationKey)
must(err)
mediaHashKey := upload(encrypted)
payload, err := chat.EncryptMessage(chatxdk.EncryptMessageParams{
	ConversationID: conversationID, Text: "a photo",
	Attachments: []chatxdk.AttachmentDescriptor{photoAttachment(mediaHashKey)},
})
must(err)

// 0.6.0
size, err := chatxdk.EncryptedFileSize(uint64(len(photo)))
must(err)
mediaHashKey := startUpload(size)
payload, err := chat.EncryptMessage(chatxdk.EncryptMessageParams{
	ConversationID: conversationID, Text: "a photo",
	Attachments: []chatxdk.AttachmentDescriptor{photoAttachment(mediaHashKey)},
})
must(err)
encrypted, err := chat.EncryptFile(chatxdk.EncryptFileParams{
	File: photo, EventB64: payload.EventB64, MediaHashKey: mediaHashKey,
})
must(err)
finishUpload(mediaHashKey, encrypted)
```

Like `EncryptMessage`, `EncryptFileParams` takes `ConversationKey` and
`ConversationKeyVersion` (set both, or neither to resolve them from the key
cache), and they must be the ones the message was encrypted under. The file
call needs no session identity: it reads the sender, the message id and the
key version from `EventB64`.

Upload each file for one message only. In v1 the id of a message with files
is derived from its conversation key and version, its sender, its
conversation and its files' media hash keys, but not its text: encrypting
the same message again gives the same id, so files you already encrypted
for it stay valid, and a second message that reuses the first one's uploads
gets the same id, so recipients drop it as a repeat. A message that lists an
empty media hash key, or one media hash key twice, is rejected.

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
public key as `GetPublicKeys` returns it) and, except for conversation-key
changes, `SignaturePayload`, which is left out of the JSON when empty.
Marshal them as returned:

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

A prepared change's `ParticipantKeys` keep their shape (`UserID`,
`EncryptedKey`, `PublicKeyVersion`): map them to the key-change request's
`conversation_participant_keys` as you do today.

## Deletes return a `PreparedAction`

`PrepareMessageDelete` returns a `*PreparedAction` whose `ActionSignatures`
hold one entry, shaped as the previous section shows. Read the action's
`MessageID` from that entry, and send `ActionSignatures` as returned:

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

## Invalid input errors

A missing or invalid parameter returns an error whose message names the
value, such as `Invalid sender_id 'user-1': pass a numeric user id (digits
only)` or `too many attachments: at most 10 per message`, without an
`Invalid state:` prefix. If your code looks for that prefix on these errors,
match the message instead. Errors about state the chat lacks, such as a
missing session identity or an empty key cache, keep their prefix.

## Signed read receipts (new, pending)

`PrepareMarkConversationRead` signs a read receipt for the newest event you
read. It takes a `MarkConversationReadParams` (`ConversationID`,
`SeenUntilSequenceID`, that event's sequence id, and an optional
`SeenAtMsec` that defaults to now) and returns a `*PreparedAction`. A
recipient's `DecryptEvent` returns a signed receipt as a verified
`ReadReceipt` event.

**Pending:** the X API's mark-read route doesn't take `action_signatures`
yet, so the shape of that request may change when it does.

```go
// 0.6.0
receipt, err := chat.PrepareMarkConversationRead(chatxdk.MarkConversationReadParams{
	ConversationID: conversationID, SeenUntilSequenceID: seenUntilSequenceID,
})
must(err)
actionSignatures := receipt.ActionSignatures
```
