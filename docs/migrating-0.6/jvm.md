# Migrating JVM code to chat-xdk 0.6.0

This page lists every change that Java and other JVM code written for
`com.x:chatxdk` 0.5.x (0.5.0, 0.5.1 or 0.5.2) runs into in 0.6.0, each with
the lines to change. [Why 0.6.0 changes](why.md) explains why each change
was made, and the [index](README.md) lists the other bindings' pages.
[API.md](../API.md) documents every call, and the
[CHANGELOG](../../CHANGELOG.md) lists every change.

## Checklist

- [ ] [Upgrade every app that reads your conversations first](#upgrade-readers-before-v1-sends-start)
- [ ] [Allow or block the feature-switch request](#the-feature-switch-request)
- [ ] [Register keys with the public key only](#register-keys-with-the-public-key-only)
- [ ] [Pass a `SetIdentityParams` to `setIdentity`](#setidentity-takes-setidentityparams)
- [ ] [Pass an `ImportKeysParams` to `importKeys`](#importkeys-takes-importkeysparams)
- [ ] [Pass user ids as strings of digits](#user-ids-are-strings-of-digits)
- [ ] [Pass key versions as the X API returns them](#key-versions-are-integers-written-as-strings)
- [ ] [Pass a `DecryptEventsParams` to `decryptEvents`](#decryptevents-takes-decrypteventsparams)
- [ ] [Pass a `DecryptEventParams` to `decryptEvent`](#decryptevent-takes-decrypteventparams)
- [ ] [Read `SendPayload` under the send request's field names](#sendpayload-fields-take-the-send-requests-names)
- [ ] [Build a message before you encrypt its files](#encrypt-a-file-from-its-message)
- [ ] [Decrypt a file with the event of its message](#decrypt-a-file-with-its-messages-event)
- [ ] [Use `fileEncryptor` and `fileDecryptor` for large files](#encrypt-and-decrypt-large-files-in-chunks)
- [ ] [Pass action signatures through as returned](#action-signatures-come-nested)
- [ ] [Pass participant keys through as returned](#participant-keys-take-the-key-requests-names)
- [ ] [Read received participant keys under the same names](#received-participant-keys-take-the-same-names)
- [ ] [Read `conversation_key_version` on decrypted events](#decrypted-events-name-the-conversation-key-version-as-the-x-api-does)
- [ ] [Read a delete's signature from its `PreparedAction`](#deletes-return-a-preparedaction)
- [ ] [Check code that reads error messages](#invalid-input-errors)
- [ ] [Know which calls throw `ChatXdkException`](#exceptions)
- [ ] [If you call `ChatNative` directly, follow the C ABI changes](#chatnative)
- [ ] [On ARM64 Linux, drop any native library you built for 0.5.x](#the-jar-bundles-the-linux-arm64-native-library)
- [ ] [Optional: sign read receipts](#signed-read-receipts)

## About the snippets

Each snippet shows the lines that change, first as 0.5.x code writes them
and then as 0.6.0 code writes them. `chat` is a `Chat` with your keys
loaded, and the other names stand for your own values: ids, versions, keys
and events as the X API returns them, `keys` for the conversation key map
`decryptEvents` returns, `bundle` for a `ConversationKeyBundle`, `payload`
for a `SendPayload`, `prepared` for a `PreparedConversationChange`, and
`keyChange` and `message` for a decrypted key change and message, as
`JsonNode`s.
`api.post(path, body)` stands for your HTTP client: it POSTs `body`,
serialized with Jackson, to `https://api.x.com` + `path` with your user
access token and returns the parsed JSON response as a `JsonNode`.
`photoAttachment(mediaHashKey)` stands for your code that builds a photo's
`AttachmentDescriptor`. The types import from `com.x.chatxdk`,
`com.x.chatxdk.Types` and `java.util`.

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
`payload.signatureInfo.signatureVersion`, `"7"` for v0 and `"10"` for v1.

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

`generateKeypairs` returns a `PublicKeyRegistrationPayload` that holds only
`publicKey`. Send it as the only field of the
`POST /2/users/{id}/public_keys` body, `public_key`. 0.6.0 doesn't pick a
signing-key version for new keys: call `setIdentity` with the
`public_key_version` the request returns (see the next section). A signed
call made without a version throws `Invalid state: signing_key_version is
not set: pass it explicitly or call set_identity() first`.

```java
// 0.5.x
PublicKeyRegistrationPayload registration = chat.generateKeypairs();
JsonNode response = api.post("/2/users/" + userId + "/public_keys", Map.of(
        "public_key", registration.publicKey,
        "version", registration.version,
        "generate_version", registration.generateVersion));
chat.setIdentity(userId, response.path("data").path("public_key_version").asText());

// 0.6.0
PublicKeyRegistrationPayload registration = chat.generateKeypairs();
JsonNode response = api.post("/2/users/" + userId + "/public_keys", Map.of("public_key", registration.publicKey));
chat.setIdentity(new SetIdentityParams(userId, response.path("data").path("public_key_version").asText()));
```

## `setIdentity` takes `SetIdentityParams`

Pass the user id and the signing-key version in a `SetIdentityParams`. It
throws `ChatXdkException` when either value is invalid (see
[user ids](#user-ids-are-strings-of-digits) and
[key versions](#key-versions-are-integers-written-as-strings)).

```java
// 0.5.x
chat.setIdentity(userId, signingKeyVersion);

// 0.6.0
chat.setIdentity(new SetIdentityParams(userId, signingKeyVersion));
```

## `importKeys` takes `ImportKeysParams`

Pass the saved key bytes in an `ImportKeysParams`, and optionally the
signing-key version they were registered under. Without a version, call
`setIdentity` before the first signed call.

```java
// 0.5.x
chat.importKeys(privateKeys);
chat.importKeys(privateKeys, signingKeyVersion);

// 0.6.0
chat.importKeys(new ImportKeysParams(privateKeys));
chat.importKeys(new ImportKeysParams(privateKeys, signingKeyVersion));
```

## User ids are strings of digits

Every user id is a string of digits: the `SetIdentityParams` user id,
`senderId`, `replyToSenderId`, the `userId` of each `PublicKeyInput` and
`SigningKeyEntry`, and group member, admin and pending-member ids. Each must
be a positive integer written without a sign or leading zeros; anything else
throws `ChatXdkException` naming the field, such as
`Invalid sender_id 'user-1': pass a numeric user id (digits only)`.
`EncryptReplyParams.replyToSenderId` is a `String`:

```java
// 0.5.x
EncryptReplyParams reply = new EncryptReplyParams(conversationId, "pong", eventB64);
reply.replyToSenderId = 4201L;

// 0.6.0
EncryptReplyParams reply = new EncryptReplyParams(conversationId, "pong", eventB64);
reply.replyToSenderId = "4201";
```

## Key versions are integers written as strings

Every key version is a non-negative integer written as a string of digits,
as the X API returns it: the signing-key version (in `SetIdentityParams`,
`ImportKeysParams`, a call's `signingKeyVersion` and each public key's
`keyVersion`) and `conversationKeyVersion`. Anything else throws
`ChatXdkException` naming the field, such as `Invalid signing_key_version
'v1': pass the key version as the X API returns it, an integer in digits`.
There's no code to change if you pass the versions the X API returns.

## `decryptEvents` takes `DecryptEventsParams`

Pass the events in a `DecryptEventsParams`, and the signing keys in its
`signingKeys` field. Left `null`, the keys `setSigningKeys` stored verify
the events. The result is unchanged, and per-event errors are still
collected in it.

```java
// 0.5.x
DecryptEventsResult result = chat.decryptEvents(events, signingKeys);

// 0.6.0
DecryptEventsParams batch = new DecryptEventsParams(events);
batch.signingKeys = signingKeys;
DecryptEventsResult result = chat.decryptEvents(batch);
```

## `decryptEvent` takes `DecryptEventParams`

Pass the event and the conversation key map in a `DecryptEventParams`, and
the signing keys in its `signingKeys` field. `new DecryptEventParams(eventB64)`
resolves the key from the key cache (`setCacheKeys(true)`), and `null`
signing keys verify with the keys `setSigningKeys` stored. For a
`ConversationKeyBundle`, pass its `keys`.

```java
// 0.5.x
JsonNode event = chat.decryptEvent(eventB64, keys, signingKeys);
JsonNode fromBundle = chat.decryptEvent(eventB64, bundle, signingKeys);

// 0.6.0
DecryptEventParams one = new DecryptEventParams(eventB64, keys);
one.signingKeys = signingKeys;
JsonNode event = chat.decryptEvent(one);
DecryptEventParams fromBundleParams = new DecryptEventParams(eventB64, bundle.keys);
fromBundleParams.signingKeys = signingKeys;
JsonNode fromBundle = chat.decryptEvent(fromBundleParams);
```

## `SendPayload` fields take the send request's names

The two encoded fields carry the names of the fields of the send request,
`POST /2/chat/conversations/{id}/messages`, camelCased, so the request takes
them as they are:

```java
// 0.5.x
Map<String, String> body = Map.of(
        "message_id", payload.messageId,
        "encoded_message_create_event", payload.encryptedContent,
        "encoded_message_event_signature", payload.encodedEventSignature);

// 0.6.0
Map<String, String> body = Map.of(
        "message_id", payload.messageId,
        "encoded_message_create_event", payload.encodedMessageCreateEvent,
        "encoded_message_event_signature", payload.encodedMessageEventSignature);
```

Read them under those names wherever your code reads a payload, including
code that stores payloads. A payload also carries `eventB64`, the message
as recipients receive it. It isn't part of the send request: keep it to
encrypt the message's files (see
[Encrypt a file from its message](#encrypt-a-file-from-its-message)).

## Encrypt a file from its message

Each file is encrypted from the message that carries it, so build the
message first:

1. Start each file's upload with `POST /2/chat/media/upload/initialize`,
   declaring `ChatXdkUtilities.encryptedFileSize` of the file's size as
   `total_bytes`, and keep the `session_id` and `media_hash_key` it returns.
2. Encrypt the message with attachments that name those media hash keys.
3. Encrypt each file with `encryptFile`, passing the payload's `eventB64`
   and the file's media hash key.
4. Upload each encrypted file with `POST
   /2/chat/media/upload/{session_id}/append` and finish it with `POST
   /2/chat/media/upload/{session_id}/finalize`, then send the message.

```java
// 0.5.x
byte[] encrypted = chat.encryptStream(photo, conversationKey);
JsonNode upload = api.post("/2/chat/media/upload/initialize", Map.of(
        "conversation_id", conversationId, "total_bytes", encrypted.length)).path("data");
String mediaHashKey = upload.path("media_hash_key").asText();
EncryptMessageParams params = new EncryptMessageParams(conversationId, "a photo");
params.attachments = List.of(photoAttachment(mediaHashKey));
SendPayload payload = chat.encryptMessage(params);

// 0.6.0
JsonNode upload = api.post("/2/chat/media/upload/initialize", Map.of(
        "conversation_id", conversationId,
        "total_bytes", ChatXdkUtilities.encryptedFileSize(photo.length))).path("data");
String sessionId = upload.path("session_id").asText();
String mediaHashKey = upload.path("media_hash_key").asText();
EncryptMessageParams params = new EncryptMessageParams(conversationId, "a photo");
params.attachments = List.of(photoAttachment(mediaHashKey));
SendPayload payload = chat.encryptMessage(params);
byte[] encrypted = chat.encryptFile(new EncryptFileParams(photo, payload.eventB64, mediaHashKey));
api.post("/2/chat/media/upload/" + sessionId + "/append", Map.of(
        "conversation_id", conversationId, "media_hash_key", mediaHashKey,
        "segment_index", 0, "media", Base64.getEncoder().encodeToString(encrypted)));
api.post("/2/chat/media/upload/" + sessionId + "/finalize", Map.of(
        "conversation_id", conversationId, "media_hash_key", mediaHashKey, "num_parts", "1"));
```

The `append` and `finalize` requests don't change, but they come after
`encryptFile`, which produces the bytes they upload. The upload requests
take `conversation_id` in its colon form, as the SDK does. The snippet
uploads the file in one segment; a larger file goes up in several `append`
requests, `segment_index` 0, 1 and so on (the examples send 3 MB segments),
with their count as `num_parts`.

Like `EncryptMessageParams`, `EncryptFileParams` takes `conversationKey`
and `conversationKeyVersion` (set both, or neither to resolve them from the
key cache), and they must be the ones the message was encrypted under. The
file call needs no session identity: it reads the sender, the message id
and the key version from `eventB64`.

Upload each file for one message only. In v1 the id of a message with files
is derived from its conversation key and version, its sender, its
conversation and its files' media hash keys, but not its text: encrypting
the same message again gives the same id, so files you already encrypted
for it stay valid, and a second message that reuses the first one's uploads
gets the same id, so recipients drop it as a repeat. A message that lists an
empty media hash key, or one media hash key twice, is rejected.

## Decrypt a file with its message's event

Pass the downloaded bytes, the base64 event of the message that carries the
file and the conversation key map (the values `decryptEvent` takes), and
the file's media hash key from the decrypted message: one of its media
attachments, a link card's banner or favicon (both listed in
`media_hashes`), or media quoted in its reply preview. The SDK finds the
file in the event and derives its key. It doesn't check the message's
signature: use `verified` from `decryptEvent` for that.

```java
// 0.5.x
byte[] plaintext = chat.decryptStream(downloaded, keys.get(conversationKeyVersion));

// 0.6.0
byte[] plaintext = chat.decryptFile(new DecryptFileParams(downloaded, fileEventB64, keys, fileHashKey));
```

## Encrypt and decrypt large files in chunks

`fileEncryptor` and `fileDecryptor` take the same values as `encryptFile`
and `decryptFile`, without the file bytes, and return a `FileEncryptor` or
a `FileDecryptor`; `push`, `finish` and `close` are unchanged. Size an
upload with `ChatXdkUtilities.encryptedFileSize`.

```java
// 0.5.x
long size = ChatXdkUtilities.encryptedStreamSize(photo.length);
StreamEncryptor encryptor = chat.streamEncryptor(conversationKey);
StreamDecryptor decryptor = chat.streamDecryptor(keys.get(conversationKeyVersion));

// 0.6.0
long size = ChatXdkUtilities.encryptedFileSize(photo.length);
FileEncryptor encryptor = chat.fileEncryptor(new FileEncryptorParams(payload.eventB64, mediaHashKey));
FileDecryptor decryptor = chat.fileDecryptor(new FileDecryptorParams(fileEventB64, keys, fileHashKey));
```

## Action signatures come nested

The prepare methods return each `ActionSignature` in the shape a request's
`action_signatures` takes: `messageId`, `encodedMessageEventDetail`, the
signature in `messageEventSignature` (a `MessageEventSignature` with
`signingPublicKey`, your signing public key as `getPublicKeys` returns it)
and, except for conversation-key changes, `signaturePayload`, which is
`null` and left out of the JSON when absent. Serialize them as returned:

```java
// 0.5.x
List<Map<String, Object>> actionSignatures = new ArrayList<>();
for (ActionSignature sig : prepared.actionSignatures) {
    actionSignatures.add(Map.of(
            "message_id", sig.messageId,
            "encoded_message_event_detail", sig.encodedMessageEventDetail,
            "message_event_signature", Map.of(
                    "signature", sig.signature,
                    "signature_version", sig.signatureVersion,
                    "public_key_version", sig.publicKeyVersion,
                    "signing_public_key", signingPublicKey)));
}

// 0.6.0
List<ActionSignature> actionSignatures = prepared.actionSignatures;
```

## Participant keys take the key requests' names

A prepared change's participant keys carry the names the X API gives them in
every request that takes them (`POST /2/chat/conversations/{id}/keys`,
`/group` and `/{id}/members`, and `PUT /2/chat/conversations/{id}`):
`conversationParticipantKeys`, a list of `ConversationParticipantKey` whose
fields (`userId`, `encryptedConversationKey`, `publicKeyVersion`) serialize
as `user_id`, `encrypted_conversation_key` and `public_key_version`, the
names a received key change uses too
(see [Received participant keys take the same names](#received-participant-keys-take-the-same-names)). Drop the renaming
and pass them through as returned:

```java
// 0.5.x
List<Map<String, String>> conversationParticipantKeys = new ArrayList<>();
for (EncryptedKeyForRecipient key : prepared.participantKeys) {
    conversationParticipantKeys.add(Map.of(
            "user_id", key.userId,
            "encrypted_conversation_key", key.encryptedKey,
            "public_key_version", key.publicKeyVersion));
}

// 0.6.0
List<ConversationParticipantKey> conversationParticipantKeys = prepared.conversationParticipantKeys;
```

## Received participant keys take the same names

A decrypted key change carries its participant keys under the names Thrift's
`ConversationKeyChangeEvent` gives them, the same names a prepared change
uses: `conversation_participant_keys`, each entry with `user_id`,
`encrypted_conversation_key` and `public_key_version`, which deserializes
into `ConversationParticipantKey`. Read them under those names:

```java
// 0.5.x
String encrypted = keyChange.path("participant_keys").get(0).path("encrypted_key").asText();

// 0.6.0
String encrypted = keyChange.path("conversation_participant_keys").get(0)
        .path("encrypted_conversation_key").asText();
```

## Decrypted events name the conversation key version as the X API does

A decrypted message or key change carries its conversation key version as
`conversation_key_version`, the name the X API's events and the Thrift
events give it, and the name the encrypt params serialize to:

```java
// 0.5.x
String messageVersion = message.path("key_version").asText();
String keyChangeVersion = keyChange.path("key_version").asText();

// 0.6.0
String messageVersion = message.path("conversation_key_version").asText();
String keyChangeVersion = keyChange.path("conversation_key_version").asText();
```

## Deletes return a `PreparedAction`

`prepareMessageDelete` returns a `PreparedAction` whose `actionSignatures`
hold one entry, shaped as the previous section shows. Read the action's
`messageId` from that entry, and send `actionSignatures` as returned:

```java
// 0.5.x
ActionSignature deletion = chat.prepareMessageDelete(
        new MessageDeleteParams(conversationId, sequenceIds, false));
String messageId = deletion.messageId;

// 0.6.0
PreparedAction deletion = chat.prepareMessageDelete(
        new MessageDeleteParams(conversationId, sequenceIds, false));
String messageId = deletion.actionSignatures.get(0).messageId;
```

## Invalid input errors

A missing or invalid parameter throws `ChatXdkException` with a message that
names the value, such as `Invalid sender_id 'user-1': pass a numeric user id
(digits only)` or `too many attachments: at most 10 per message`, without an
`Invalid state:` prefix. If your code looks for that prefix on these errors,
match the message instead. Errors about state the chat lacks, such as a
missing session identity or an empty key cache, keep their prefix.

## Exceptions

There's no code to change. `ChatXdkException` is unchecked. `setIdentity`
and `importKeys` throw it on invalid input, and the file methods
(`encryptFile`, `decryptFile`, `fileEncryptor`, `fileDecryptor`) declare no
checked exceptions and throw it too. The methods that declare
`throws Exception` keep that clause.

## `ChatNative`

`ChatNative`, the JNA interface to the native library, follows the C ABI:
if your code calls it directly, apply the changes in [C ABI](c-abi.md).

## The jar bundles the linux-arm64 native library

The jar bundles the native library for 64-bit ARM Linux (`linux-arm64`) as
well, and on ARM64 Linux loads it ahead of any copy on `jna.library.path`.
There's no code to change. If you built a library to run 0.5.x there,
remove it: a 0.5.x build doesn't export the entry points 0.6.0 calls (see
[C ABI](c-abi.md)).

## Signed read receipts

`prepareMarkConversationRead` signs a read receipt for the newest event you
read. It takes a `MarkConversationReadParams` (the conversation id, that
event's sequence id, and an optional `seenAtMsec` that defaults to now) and
returns a `PreparedAction`, one entry shaped as
[Action signatures come nested](#action-signatures-come-nested) shows. Send
its `actionSignatures` as the `action_signatures` of the mark-read request,
`POST /2/chat/conversations/{id}/read`, whose path takes the conversation id
in its hyphen form. A recipient's `decryptEvent` returns a signed receipt as
a verified `ReadReceipt` event.

```java
// 0.6.0
PreparedAction receipt = chat.prepareMarkConversationRead(
        new MarkConversationReadParams(conversationId, seenUntilSequenceId));
api.post("/2/chat/conversations/" + conversationId.replace(':', '-') + "/read",
        Map.of("action_signatures", receipt.actionSignatures));
```
