# Migrating .NET code to chat-xdk 0.6.0

This page lists every change that C# and other .NET code written for
`XDevPlatform.ChatXdk` 0.5.x (0.5.0, 0.5.1 or 0.5.2) runs into in 0.6.0,
each with the lines to change. [Why 0.6.0 changes](why.md) explains why each
change was made, and the [index](README.md) lists the other bindings' pages.
[API.md](../API.md) documents every call, and the
[CHANGELOG](../../CHANGELOG.md) lists every change.

## Checklist

- [ ] [Upgrade every app that reads your conversations first](#upgrade-readers-before-v1-sends-start)
- [ ] [Allow or block the feature-switch request](#the-feature-switch-request)
- [ ] [Register keys with the public key only](#register-keys-with-the-public-key-only)
- [ ] [Pass a `SetIdentityParams` to `SetIdentity`](#setidentity-takes-setidentityparams)
- [ ] [Pass an `ImportKeysParams` to `ImportKeys`](#importkeys-takes-importkeysparams)
- [ ] [Pass user ids as strings of digits](#user-ids-are-strings-of-digits)
- [ ] [Pass key versions as the X API returns them](#key-versions-are-integers-written-as-strings)
- [ ] [Pass a `DecryptEventsParams` to `DecryptEvents`](#decryptevents-takes-decrypteventsparams)
- [ ] [Pass a `DecryptEventParams` to `DecryptEvent`](#decryptevent-takes-decrypteventparams)
- [ ] [Read `SendPayload` under the send request's field names](#sendpayload-fields-take-the-send-requests-names)
- [ ] [Build a message before you encrypt its files](#encrypt-a-file-from-its-message)
- [ ] [Decrypt a file with the event of its message](#decrypt-a-file-with-its-messages-event)
- [ ] [Use `FileEncryptor` and `FileDecryptor` for large files](#encrypt-and-decrypt-large-files-in-chunks)
- [ ] [Pass action signatures through as returned](#action-signatures-come-nested)
- [ ] [Pass participant keys through as returned](#participant-keys-take-the-key-requests-names)
- [ ] [Read received participant keys under the same names](#received-participant-keys-take-the-same-names)
- [ ] [Read `conversation_key_version` on decrypted events](#decrypted-events-name-the-conversation-key-version-as-the-x-api-does)
- [ ] [Read a delete's signature from its `PreparedAction`](#deletes-return-a-preparedaction)
- [ ] [Check code that reads error messages](#invalid-input-errors)
- [ ] [On ARM64 Linux, drop any native library you built for 0.5.x](#the-package-bundles-the-linux-arm64-native-library)
- [ ] [Optional: sign read receipts](#signed-read-receipts)

## About the snippets

Each snippet shows the lines that change, first as 0.5.x code writes them
and then as 0.6.0 code writes them. `chat` is a `Chat` with your keys
loaded, and the other names stand for your own values: ids, versions, keys
and events as the X API returns them, `keys` for the conversation key map
`DecryptEvents` returns, `bundle` for a `ConversationKeyBundle`, `payload`
for a `SendPayload`, `prepared` for a `PreparedConversationChange`, and
`keyChange` and `message` for a decrypted key change and message, as
`JsonElement`s.
`api.Post(path, body)` stands for your HTTP client: it POSTs `body`,
serialized with `System.Text.Json`'s default options, to
`https://api.x.com` + `path` with your user access token and returns the
parsed JSON response as a `JsonElement`. `PhotoAttachment(mediaHashKey)`
stands for your code that builds a photo's `AttachmentDescriptor`. The types
are in the `ChatXdk` namespace.

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

`GenerateKeypairs` returns a `PublicKeyRegistrationPayload` that holds only
`PublicKey`. Send it as the only field of the
`POST /2/users/{id}/public_keys` body, `public_key`. 0.6.0 doesn't pick a
signing-key version for new keys: call `SetIdentity` with the
`public_key_version` the request returns (see the next section). A signed
call made without a version throws `Invalid state: signing_key_version is
not set: pass it explicitly or call set_identity() first`.

```csharp
// 0.5.x
var registration = chat.GenerateKeypairs();
var response = api.Post($"/2/users/{userId}/public_keys", new
{
    public_key = registration.PublicKey,
    version = registration.Version,
    generate_version = registration.GenerateVersion,
});
chat.SetIdentity(userId, response.GetProperty("data").GetProperty("public_key_version").GetString()!);

// 0.6.0
var registration = chat.GenerateKeypairs();
var response = api.Post($"/2/users/{userId}/public_keys", new { public_key = registration.PublicKey });
chat.SetIdentity(new SetIdentityParams(userId, response.GetProperty("data").GetProperty("public_key_version").GetString()!));
```

## `SetIdentity` takes `SetIdentityParams`

Pass the user id and the signing-key version in a `SetIdentityParams`. It
throws `ChatXdkException` when either value is invalid (see
[user ids](#user-ids-are-strings-of-digits) and
[key versions](#key-versions-are-integers-written-as-strings)).

```csharp
// 0.5.x
chat.SetIdentity(userId, signingKeyVersion);

// 0.6.0
chat.SetIdentity(new SetIdentityParams(userId, signingKeyVersion));
```

## `ImportKeys` takes `ImportKeysParams`

Pass the saved key bytes in an `ImportKeysParams`, and optionally the
signing-key version they were registered under as `SigningKeyVersion`.
Without a version, call `SetIdentity` before the first signed call.

```csharp
// 0.5.x
chat.ImportKeys(privateKeys);
chat.ImportKeys(privateKeys, signingKeyVersion);

// 0.6.0
chat.ImportKeys(new ImportKeysParams(privateKeys));
chat.ImportKeys(new ImportKeysParams(privateKeys) { SigningKeyVersion = signingKeyVersion });
```

## User ids are strings of digits

Every user id is a string of digits: the `SetIdentityParams` user id,
`SenderId`, `ReplyToSenderId`, the `UserId` of each `PublicKeyInput` and
`SigningKeyEntry`, and group member, admin and pending-member ids. Each must
be a positive integer written without a sign or leading zeros; anything else
throws `ChatXdkException` naming the field, such as
`Invalid sender_id 'user-1': pass a numeric user id (digits only)`.
`EncryptReplyParams.ReplyToSenderId` is a `string?`:

```csharp
// 0.5.x
var reply = new EncryptReplyParams(conversationId, "pong", eventB64) { ReplyToSenderId = 4201 };

// 0.6.0
var reply = new EncryptReplyParams(conversationId, "pong", eventB64) { ReplyToSenderId = "4201" };
```

## Key versions are integers written as strings

Every key version is a non-negative integer written as a string of digits,
as the X API returns it: the signing-key version (in `SetIdentityParams`,
`ImportKeysParams`, a call's `SigningKeyVersion` and each public key's
`KeyVersion`) and `ConversationKeyVersion`. Anything else throws
`ChatXdkException` naming the field, such as `Invalid signing_key_version
'v1': pass the key version as the X API returns it, an integer in digits`.
There's no code to change if you pass the versions the X API returns.

## `DecryptEvents` takes `DecryptEventsParams`

Pass the events, an `IReadOnlyList<string>` such as an array or a list, in
a `DecryptEventsParams`, and the signing keys as `SigningKeys`. Left
`null`, the keys `SetSigningKeys` stored verify the events. The result is
unchanged, and per-event errors are still collected in it.

```csharp
// 0.5.x
var result = chat.DecryptEvents(events, signingKeys);

// 0.6.0
var result = chat.DecryptEvents(new DecryptEventsParams(events) { SigningKeys = signingKeys });
```

## `DecryptEvent` takes `DecryptEventParams`

Pass the event and the conversation key map in a `DecryptEventParams`, and
the signing keys as `SigningKeys`. `new DecryptEventParams(eventB64)`
resolves the key from the key cache (`SetCacheKeys(true)`), and `null`
signing keys verify with the keys `SetSigningKeys` stored. For a
`ConversationKeyBundle`, pass its `Keys`.

```csharp
// 0.5.x
var evt = chat.DecryptEvent(eventB64, keys, signingKeys);
var fromBundle = chat.DecryptEvent(eventB64, bundle, signingKeys);

// 0.6.0
var evt = chat.DecryptEvent(new DecryptEventParams(eventB64, keys) { SigningKeys = signingKeys });
var fromBundle = chat.DecryptEvent(
    new DecryptEventParams(eventB64, bundle.Keys) { SigningKeys = signingKeys });
```

## `SendPayload` fields take the send request's names

The two encoded fields carry the names of the fields of the send request,
`POST /2/chat/conversations/{id}/messages`, so the request takes them as
they are:

```csharp
// 0.5.x
var body = new Dictionary<string, string>
{
    ["message_id"] = payload.MessageId,
    ["encoded_message_create_event"] = payload.EncryptedContent,
    ["encoded_message_event_signature"] = payload.EncodedEventSignature,
};

// 0.6.0
var body = new Dictionary<string, string>
{
    ["message_id"] = payload.MessageId,
    ["encoded_message_create_event"] = payload.EncodedMessageCreateEvent,
    ["encoded_message_event_signature"] = payload.EncodedMessageEventSignature,
};
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
   declaring `ChatXdkUtilities.EncryptedFileSize` of the file's size as
   `total_bytes`, and keep the `session_id` and `media_hash_key` it returns.
2. Encrypt the message with attachments that name those media hash keys.
3. Encrypt each file with `EncryptFile`, passing the payload's `EventB64`
   and the file's media hash key.
4. Upload each encrypted file with `POST
   /2/chat/media/upload/{session_id}/append` and finish it with `POST
   /2/chat/media/upload/{session_id}/finalize`, then send the message.

```csharp
// 0.5.x
var encrypted = chat.EncryptStream(photo, conversationKey);
var upload = api.Post("/2/chat/media/upload/initialize", new
{
    conversation_id = conversationId, total_bytes = encrypted.Length,
}).GetProperty("data");
var mediaHashKey = upload.GetProperty("media_hash_key").GetString()!;
var payload = chat.EncryptMessage(new EncryptMessageParams(conversationId, "a photo")
{
    Attachments = new[] { PhotoAttachment(mediaHashKey) },
});

// 0.6.0
var upload = api.Post("/2/chat/media/upload/initialize", new
{
    conversation_id = conversationId,
    total_bytes = ChatXdkUtilities.EncryptedFileSize((ulong)photo.Length),
}).GetProperty("data");
var sessionId = upload.GetProperty("session_id").GetString();
var mediaHashKey = upload.GetProperty("media_hash_key").GetString()!;
var payload = chat.EncryptMessage(new EncryptMessageParams(conversationId, "a photo")
{
    Attachments = new[] { PhotoAttachment(mediaHashKey) },
});
var encrypted = chat.EncryptFile(new EncryptFileParams(photo, payload.EventB64, mediaHashKey));
api.Post($"/2/chat/media/upload/{sessionId}/append", new
{
    conversation_id = conversationId, media_hash_key = mediaHashKey,
    segment_index = 0, media = Convert.ToBase64String(encrypted),
});
api.Post($"/2/chat/media/upload/{sessionId}/finalize", new
{
    conversation_id = conversationId, media_hash_key = mediaHashKey, num_parts = "1",
});
```

The `append` and `finalize` requests don't change, but they come after
`EncryptFile`, which produces the bytes they upload. The upload requests
take `conversation_id` in its colon form, as the SDK does. The snippet
uploads the file in one segment; a larger file goes up in several `append`
requests, `segment_index` 0, 1 and so on (the examples send 3 MB segments),
with their count as `num_parts`.

Like `EncryptMessageParams`, `EncryptFileParams` takes `ConversationKey`
and `ConversationKeyVersion` (set both, or neither to resolve them from the
key cache), and they must be the ones the message was encrypted under. The
file call needs no session identity: it reads the sender, the message id
and the key version from `EventB64`.

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
signature: use `verified` from `DecryptEvent` for that.

```csharp
// 0.5.x
var plaintext = chat.DecryptStream(downloaded, keys[conversationKeyVersion]);

// 0.6.0
var plaintext = chat.DecryptFile(new DecryptFileParams(downloaded, fileEventB64, keys, fileHashKey));
```

## Encrypt and decrypt large files in chunks

`FileEncryptor` and `FileDecryptor` take the same values as `EncryptFile`
and `DecryptFile`, without the file bytes, and return a `FileEncryptor` or
a `FileDecryptor`; `Push`, `Finish` and `Dispose` are unchanged. Size an
upload with `ChatXdkUtilities.EncryptedFileSize`.

```csharp
// 0.5.x
var size = ChatXdkUtilities.EncryptedStreamSize((ulong)photo.Length);
using var encryptor = chat.StreamEncryptor(conversationKey);
using var decryptor = chat.StreamDecryptor(keys[conversationKeyVersion]);

// 0.6.0
var size = ChatXdkUtilities.EncryptedFileSize((ulong)photo.Length);
using var encryptor = chat.FileEncryptor(new FileEncryptorParams(payload.EventB64, mediaHashKey));
using var decryptor = chat.FileDecryptor(new FileDecryptorParams(fileEventB64, keys, fileHashKey));
```

## Action signatures come nested

The prepare methods return each `ActionSignature` in the shape a request's
`action_signatures` takes: `MessageId`, `EncodedMessageEventDetail`, the
signature in `MessageEventSignature` (with `SigningPublicKey`, your signing
public key as `GetPublicKeys` returns it) and, except for conversation-key
changes, `SignaturePayload`, a `string?` that is left out of the JSON when
absent. Serialize them as returned:

```csharp
// 0.5.x
var actionSignatures = prepared.ActionSignatures.Select(sig => new Dictionary<string, object>
{
    ["message_id"] = sig.MessageId,
    ["encoded_message_event_detail"] = sig.EncodedMessageEventDetail,
    ["message_event_signature"] = new Dictionary<string, string>
    {
        ["signature"] = sig.Signature,
        ["signature_version"] = sig.SignatureVersion,
        ["public_key_version"] = sig.PublicKeyVersion,
        ["signing_public_key"] = signingPublicKey,
    },
}).ToList();

// 0.6.0
var actionSignatures = prepared.ActionSignatures;
```

## Participant keys take the key requests' names

A prepared change's participant keys carry the names of the requests the
change goes into (`POST /2/chat/conversations/{id}/keys`, `/group` and
`/{id}/members`): `ConversationParticipantKeys`, a list of
`ConversationParticipantKey` whose properties (`UserId`,
`EncryptedConversationKey`, `PublicKeyVersion`) serialize as `user_id`,
`encrypted_conversation_key` and `public_key_version`, the names a received
key change uses too
(see [Received participant keys take the same names](#received-participant-keys-take-the-same-names)). Drop the renaming
and pass them through as returned:

```csharp
// 0.5.x
var conversationParticipantKeys = prepared.ParticipantKeys
    .Select(key => new Dictionary<string, string>
    {
        ["user_id"] = key.UserId,
        ["encrypted_conversation_key"] = key.EncryptedKey,
        ["public_key_version"] = key.PublicKeyVersion,
    })
    .ToList();

// 0.6.0
var conversationParticipantKeys = prepared.ConversationParticipantKeys;
```

## Received participant keys take the same names

A decrypted key change carries its participant keys under the names Thrift's
`ConversationKeyChangeEvent` gives them, the same names a prepared change
uses: `conversation_participant_keys`, each entry with `user_id`,
`encrypted_conversation_key` and `public_key_version`, which deserializes
into `ConversationParticipantKey`. Read them under those names:

```csharp
// 0.5.x
var encrypted = keyChange.GetProperty("participant_keys")[0].GetProperty("encrypted_key").GetString();

// 0.6.0
var encrypted = keyChange.GetProperty("conversation_participant_keys")[0]
    .GetProperty("encrypted_conversation_key").GetString();
```

## Decrypted events name the conversation key version as the X API does

A decrypted message or key change carries its conversation key version as
`conversation_key_version`, the name the X API's events and the Thrift
events give it, and the name the encrypt params serialize to:

```csharp
// 0.5.x
var messageVersion = message.GetProperty("key_version").GetString();
var keyChangeVersion = keyChange.GetProperty("key_version").GetString();

// 0.6.0
var messageVersion = message.GetProperty("conversation_key_version").GetString();
var keyChangeVersion = keyChange.GetProperty("conversation_key_version").GetString();
```

## Deletes return a `PreparedAction`

`PrepareMessageDelete` returns a `PreparedAction` whose `ActionSignatures`
hold one entry, shaped as the previous section shows. Read the action's
`MessageId` from that entry, and send `ActionSignatures` as returned:

```csharp
// 0.5.x
var deletion = chat.PrepareMessageDelete(
    new MessageDeleteParams(conversationId, sequenceIds, deleteForAll: false));
var messageId = deletion.MessageId;

// 0.6.0
var deletion = chat.PrepareMessageDelete(
    new MessageDeleteParams(conversationId, sequenceIds, deleteForAll: false));
var messageId = deletion.ActionSignatures[0].MessageId;
```

## Invalid input errors

A missing or invalid parameter throws `ChatXdkException` with a message that
names the value, such as `Invalid sender_id 'user-1': pass a numeric user id
(digits only)` or `too many attachments: at most 10 per message`, without an
`Invalid state:` prefix. If your code looks for that prefix on these errors,
match the message instead. Errors about state the chat lacks, such as a
missing session identity or an empty key cache, keep their prefix.

## The package bundles the linux-arm64 native library

The package bundles the native library for 64-bit ARM Linux (`linux-arm64`)
as well, under `runtimes/linux-arm64/native/`, so apps on ARM64 Linux need
no copy of their own. There's no code to change. If you shipped a library
you built to run 0.5.x there, remove it: a 0.5.x build doesn't export the
entry points 0.6.0 calls (see [C ABI](c-abi.md)).

## Signed read receipts

`PrepareMarkConversationRead` signs a read receipt for the newest event you
read. It takes a `MarkConversationReadParams` (the conversation id, that
event's sequence id, and an optional `SeenAtMsec` that defaults to now) and
returns a `PreparedAction`, one entry shaped as
[Action signatures come nested](#action-signatures-come-nested) shows. Send
its `ActionSignatures` as the `action_signatures` of the mark-read request,
`POST /2/chat/conversations/{id}/read`, whose path takes the conversation id
in its hyphen form. A recipient's `DecryptEvent` returns a signed receipt as
a verified `ReadReceipt` event.

```csharp
// 0.6.0
var receipt = chat.PrepareMarkConversationRead(
    new MarkConversationReadParams(conversationId, seenUntilSequenceId));
api.Post($"/2/chat/conversations/{conversationId.Replace(':', '-')}/read",
    new { action_signatures = receipt.ActionSignatures });
```
