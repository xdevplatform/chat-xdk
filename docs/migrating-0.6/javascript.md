# Migrating JavaScript and TypeScript code to chat-xdk 0.6.0

This page lists every change that code written for `@xdevplatform/chat-xdk`
0.5.x (0.5.0, 0.5.1 or 0.5.2) runs into in 0.6.0, each with the lines to
change. It covers Node and browsers alike. [Why 0.6.0 changes](why.md)
explains why each change was made, and the [index](README.md) lists the
other bindings' pages. [API.md](../API.md) documents every call, and the
[CHANGELOG](../../CHANGELOG.md) lists every change.

## Checklist

- [ ] [Upgrade every app that reads your conversations first](#upgrade-readers-before-v1-sends-start)
- [ ] [Allow or block the feature-switch request](#the-feature-switch-request)
- [ ] [Register keys with the public key only](#register-keys-with-the-public-key-only)
- [ ] [Pass `{ userId, signingKeyVersion }` to `setIdentity`](#setidentity-takes-a-params-object)
- [ ] [Pass user ids as strings of digits](#user-ids-are-strings-of-digits)
- [ ] [Pass key versions as the X API returns them](#key-versions-are-integers-written-as-strings)
- [ ] [Pass a params object to `decryptEvents`](#decryptevents-takes-a-params-object)
- [ ] [Pass a params object to `decryptEvent`](#decryptevent-takes-a-params-object)
- [ ] [Read `SendPayload` under the send request's field names and send `xdk_version`](#sendpayload-fields-take-the-send-requests-names)
- [ ] [Build a message before you encrypt its files](#encrypt-a-file-from-its-message)
- [ ] [Decrypt a file with the event of its message](#decrypt-a-file-with-its-messages-event)
- [ ] [Use `fileEncryptor` and `fileDecryptor` for large files](#encrypt-and-decrypt-large-files-in-chunks)
- [ ] [Pass action signatures through as returned](#action-signatures-come-nested)
- [ ] [Pass participant keys through as returned](#participant-keys-take-the-key-requests-names)
- [ ] [Read received participant keys under the same names](#received-participant-keys-take-the-same-names)
- [ ] [Read `conversationKeyVersion` on decrypted events](#decrypted-events-name-the-conversation-key-version-as-the-x-api-does)
- [ ] [Read a delete's signature from its `PreparedAction`](#deletes-return-a-preparedaction)
- [ ] [Check code that reads error messages](#invalid-input-errors)
- [ ] [TypeScript: import the types the package exports](#typescript-import-the-types-the-package-exports)
- [ ] [Sign group actions](#group-actions-can-be-signed)
- [ ] [Optional: sign read receipts](#signed-read-receipts)

## About the snippets

Each snippet shows the lines that change, first as 0.5.x code writes them
and then as 0.6.0 code writes them. `chat` is the `ChatWithJuicebox` that
`createChat` returns, unlocked, and the other names stand for your own
values: ids, versions, keys and events as the X API returns them, `keys` for
the conversation key map `decryptEvents` returns, `payload` for a
`SendPayload`, `prepared` for a `PreparedConversationChange`, and
`keyChange` and `message` for a decrypted keyChange and message event.
`api.post(path, body)` stands for your HTTP client: it POSTs `body` as JSON
to `https://api.x.com` + `path` with your user access token, writing every
key in snake_case as the X API takes them (the package returns camelCase),
and resolves to the parsed JSON response. `photoAttachment(mediaHashKey)`
stands for your code that builds a photo's attachment descriptor. Functions
such as `encryptedFileSize` and `bytesToBase64` import from
`@xdevplatform/chat-xdk`.

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
switch, or block it to keep them v0. In a browser the request is a
cross-origin `GET`, and a failed one keeps sends v0 too. The request never
keeps a process alive, except in Node before 20.16, where one still in flight
can delay exit until it ends, at most 2 seconds. There's no code to change.

## Register keys with the public key only

`generateKeypairs()` returns a payload that holds only `publicKey`. Send it
as the only field of the `POST /2/users/{id}/public_keys` body,
`public_key`. 0.6.0 doesn't pick a signing-key version for new keys: call
`setIdentity` with the `public_key_version` the request returns (see the
next section). A signed call made without a version throws `Invalid state:
signing_key_version is not set: pass it explicitly or call set_identity()
first`.

```js
// 0.5.x
const registration = chat.generateKeypairs();
const response = await api.post(`/2/users/${userId}/public_keys`, {
  public_key: registration.publicKey,
  version: registration.version,
  generate_version: registration.generateVersion,
});
chat.setIdentity(userId, response.data.public_key_version);

// 0.6.0
const registration = chat.generateKeypairs();
const response = await api.post(`/2/users/${userId}/public_keys`, { public_key: registration.publicKey });
chat.setIdentity({ userId, signingKeyVersion: response.data.public_key_version });
```

## `setIdentity` takes a params object

Pass the user id and the signing-key version as `{ userId,
signingKeyVersion }`. It throws when either value is invalid (see
[user ids](#user-ids-are-strings-of-digits) and
[key versions](#key-versions-are-integers-written-as-strings)).

```js
// 0.5.x
chat.setIdentity(userId, signingKeyVersion);

// 0.6.0
chat.setIdentity({ userId, signingKeyVersion });
```

## User ids are strings of digits

Every user id is a string of digits: the `setIdentity` user id, `senderId`,
`replyToSenderId`, the `userId` of each public key and signing key, and group
member, admin and pending-member ids. Each must be a positive integer
written without a sign or leading zeros; anything else throws an error that
names the field, such as
`Invalid sender_id 'user-1': pass a numeric user id (digits only)`.
`replyToSenderId` takes a string and rejects a number, since ids pass 2^53,
where JavaScript numbers stop being exact:

```js
// 0.5.x
const reply = chat.encryptReply({
  conversationId, text: "pong", replyToSequenceId: "7", replyToSenderId: 4201, replyToText: "ping",
});

// 0.6.0
const reply = chat.encryptReply({
  conversationId, text: "pong", replyToSequenceId: "7", replyToSenderId: "4201", replyToText: "ping",
});
```

## Key versions are integers written as strings

Every key version is a non-negative integer written as a string of digits,
as the X API returns it: the signing-key version (in `setIdentity`, a call's
`signingKeyVersion` and each public key's `keyVersion`) and
`conversationKeyVersion`. Anything else throws an error that names the
field, such as `Invalid signing_key_version 'v1': pass the key version as
the X API returns it, an integer in digits`. There's no code to change if
you pass the versions the X API returns.

## `decryptEvents` takes a params object

Pass `{ events, signingKeys }`. `signingKeys` is optional; without it, the
keys `setSigningKeys` stored verify the events. The result is unchanged, and
the call still never throws: errors are collected per event.

```js
// 0.5.x
const result = chat.decryptEvents(events, signingKeys);

// 0.6.0
const result = chat.decryptEvents({ events, signingKeys });
```

## `decryptEvent` takes a params object

Pass `{ eventB64, conversationKeys, signingKeys }`. Both key fields are
optional: without them, the conversation keys come from the key cache
(`setCacheKeys(true)`) and the signing keys from `setSigningKeys`. The call
still throws on failure.

```js
// 0.5.x
const event = chat.decryptEvent(eventB64, keys, signingKeys);

// 0.6.0
const event = chat.decryptEvent({ eventB64, conversationKeys: keys, signingKeys });
```

## `SendPayload` fields take the send request's names

The two encoded fields carry the names of the fields of the send request,
`POST /2/chat/conversations/{id}/messages`, camelCased, so the request takes
them as they are. The request also takes the payload's `xdkVersion`, the
version of the SDK that built it, as `xdk_version`:

```js
// 0.5.x
const body = {
  message_id: payload.messageId,
  encoded_message_create_event: payload.encryptedContent,
  encoded_message_event_signature: payload.encodedEventSignature,
};

// 0.6.0
const body = {
  message_id: payload.messageId,
  encoded_message_create_event: payload.encodedMessageCreateEvent,
  encoded_message_event_signature: payload.encodedMessageEventSignature,
  xdk_version: payload.xdkVersion,
};
```

Read them under those names wherever your code reads a payload, including
code that stores payloads. A payload also carries `eventB64`, the message as
recipients receive it. It isn't part of the send request: keep it to
encrypt the message's files (see
[Encrypt a file from its message](#encrypt-a-file-from-its-message)).

## Encrypt a file from its message

Each file is encrypted from the message that carries it, so build the
message first:

1. Start each file's upload with `POST /2/chat/media/upload/initialize`,
   declaring `encryptedFileSize` of the file's size as `total_bytes`, and
   keep the `session_id` and `media_hash_key` it returns.
2. Encrypt the message with attachments that name those media hash keys.
3. Encrypt each file with `encryptFile`, passing the payload's `eventB64`
   and the file's media hash key.
4. Upload each encrypted file with `POST
   /2/chat/media/upload/{session_id}/append` and finish it with `POST
   /2/chat/media/upload/{session_id}/finalize`, then send the message.

```js
// 0.5.x
const encrypted = chat.encryptStream(photo, conversationKey);
const { data: upload } = await api.post("/2/chat/media/upload/initialize", {
  conversation_id: conversationId, total_bytes: encrypted.length,
});
const payload = chat.encryptMessage({
  conversationId, text: "a photo", attachments: [photoAttachment(upload.media_hash_key)],
});

// 0.6.0
const { data: upload } = await api.post("/2/chat/media/upload/initialize", {
  conversation_id: conversationId, total_bytes: encryptedFileSize(photo.length),
});
const mediaHashKey = upload.media_hash_key;
const payload = chat.encryptMessage({
  conversationId, text: "a photo", attachments: [photoAttachment(mediaHashKey)],
});
const encrypted = chat.encryptFile({ file: photo, eventB64: payload.eventB64, mediaHashKey });
await api.post(`/2/chat/media/upload/${upload.session_id}/append`, {
  conversation_id: conversationId, media_hash_key: mediaHashKey,
  segment_index: 0, media: bytesToBase64(encrypted),
});
await api.post(`/2/chat/media/upload/${upload.session_id}/finalize`, {
  conversation_id: conversationId, media_hash_key: mediaHashKey, num_parts: "1",
});
```

The `append` and `finalize` requests don't change, but they come after
`encryptFile`, which produces the bytes they upload. The upload requests
take `conversation_id` in its colon form, as the SDK does. The snippet
uploads the file in one segment; a larger file goes up in several `append`
requests, `segment_index` 0, 1 and so on (the examples send 3 MB segments),
with their count as `num_parts`.

Like `encryptMessage`, `encryptFile` takes `conversationKey` and
`conversationKeyVersion` (pass both, or neither to resolve them from the
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
`mediaHashes`), or media quoted in its reply preview. The SDK finds the file
in the event and derives its key. It doesn't check the message's signature:
use `verified` from `decryptEvent` for that.

```js
// 0.5.x
const plaintext = chat.decryptStream(downloaded, keys[conversationKeyVersion]);

// 0.6.0
const plaintext = chat.decryptFile({
  encrypted: downloaded, eventB64: fileEventB64, conversationKeys: keys, mediaHashKey: fileHashKey,
});
```

## Encrypt and decrypt large files in chunks

`fileEncryptor` and `fileDecryptor` take the same values as `encryptFile`
and `decryptFile`, without the file bytes, and return a `FileEncryptor` or a
`FileDecryptor`; `push`, `finish` and `free` are unchanged. Size an upload
with `encryptedFileSize`.

```js
// 0.5.x
const size = encryptedStreamSize(photo.length);
const encryptor = chat.streamEncryptor(conversationKey);
const decryptor = chat.streamDecryptor(keys[conversationKeyVersion]);

// 0.6.0
const size = encryptedFileSize(photo.length);
const encryptor = chat.fileEncryptor({ eventB64: payload.eventB64, mediaHashKey });
const decryptor = chat.fileDecryptor({
  eventB64: fileEventB64, conversationKeys: keys, mediaHashKey: fileHashKey,
});
```

## Action signatures come nested

The prepare methods return each signed action in the shape a request's
`action_signatures` takes, camelCased as everything the package returns is:
`messageId`, `encodedMessageEventDetail`, the signature nested under
`messageEventSignature` (with `signingPublicKey`, your signing public key as
`getPublicKeys` returns it) and, except for conversation-key changes,
`signaturePayload`. Use them as returned, and write their keys in snake_case
when you build the request body, as you do for the other fields:

```js
// 0.5.x
const actionSignatures = prepared.actionSignatures.map((sig) => ({
  messageId: sig.messageId,
  encodedMessageEventDetail: sig.encodedMessageEventDetail,
  messageEventSignature: {
    signature: sig.signature,
    signatureVersion: sig.signatureVersion,
    publicKeyVersion: sig.publicKeyVersion,
    signingPublicKey,
  },
}));

// 0.6.0
const actionSignatures = prepared.actionSignatures;
```

## Participant keys take the key requests' names

A prepared change's participant keys carry the names the X API gives them in
every request that takes them (`POST /2/chat/conversations/{id}/keys`,
`/group` and `/{id}/members`, and `PUT /2/chat/conversations/{id}`),
camelCased as everything the package returns is:
`conversationParticipantKeys`, each entry a `ConversationParticipantKey`
with `userId`, `encryptedConversationKey` and `publicKeyVersion`, the names a
received keyChange event uses too
(see [Received participant keys take the same names](#received-participant-keys-take-the-same-names)). Drop the renaming
and use them as returned, writing their keys in snake_case when you build
the request body, as you do for the other fields:

```js
// 0.5.x
const conversationParticipantKeys = prepared.participantKeys.map((key) => ({
  userId: key.userId,
  encryptedConversationKey: key.encryptedKey,
  publicKeyVersion: key.publicKeyVersion,
}));

// 0.6.0
const conversationParticipantKeys = prepared.conversationParticipantKeys;
```

## Received participant keys take the same names

A decrypted keyChange event carries its participant keys under the names
Thrift's `ConversationKeyChangeEvent` gives them, camelCased, the same names
a prepared change uses: `conversationParticipantKeys`, each entry with
`userId`, `encryptedConversationKey` and `publicKeyVersion`. Read them under
those names:

```js
// 0.5.x
const [mine] = keyChange.participantKeys ?? [];
const encrypted = mine.encryptedKey;

// 0.6.0
const [mine] = keyChange.conversationParticipantKeys ?? [];
const encrypted = mine.encryptedConversationKey;
```

In TypeScript, received and prepared keys are one type,
`ConversationParticipantKey`:

```ts
// 0.5.x
import type { EncryptedKeyForRecipient, ParticipantKey } from "@xdevplatform/chat-xdk";
const sent: EncryptedKeyForRecipient[] = prepared.participantKeys;
const received: ParticipantKey[] = keyChange.participantKeys ?? [];

// 0.6.0
import type { ConversationParticipantKey } from "@xdevplatform/chat-xdk";
const sent: ConversationParticipantKey[] = prepared.conversationParticipantKeys;
const received: ConversationParticipantKey[] = keyChange.conversationParticipantKeys ?? [];
```

## Decrypted events name the conversation key version as the X API does

Decrypted message and keyChange events carry their conversation key version
as `conversationKeyVersion`, the X API's `conversation_key_version`
camelCased, and the name the encrypt methods take:

```js
// 0.5.x
const messageVersion = message.keyVersion;
const keyChangeVersion = keyChange.keyVersion;

// 0.6.0
const messageVersion = message.conversationKeyVersion;
const keyChangeVersion = keyChange.conversationKeyVersion;
```

## Deletes return a `PreparedAction`

`prepareMessageDelete` returns a `PreparedAction` whose `actionSignatures`
hold one entry, shaped as the previous section shows. Read the action's
`messageId` from that entry, and send `actionSignatures` as returned:

```js
// 0.5.x
const deletion = chat.prepareMessageDelete({ conversationId, sequenceIds, deleteForAll: false });
const messageId = deletion.messageId;

// 0.6.0
const deletion = chat.prepareMessageDelete({ conversationId, sequenceIds, deleteForAll: false });
const messageId = deletion.actionSignatures[0].messageId;
```

## Invalid input errors

A missing or invalid parameter throws an `Error` whose message names the
value, such as `Invalid sender_id 'user-1': pass a numeric user id (digits
only)` or `too many attachments: at most 10 per message`, without an
`Invalid state:` prefix. If your code looks for that prefix on these errors,
match the message instead. Errors about state the chat lacks, such as a
missing session identity or an empty key cache, keep their prefix.

## TypeScript: import the types the package exports

The typings declare only what the package exports. Type a chat as
`ChatWithJuicebox`, the class `createChat` returns, and the file encryptors
as the `FileEncryptor` and `FileDecryptor` interfaces:

```ts
// 0.5.x
import type { Chat, StreamEncryptor } from "@xdevplatform/chat-xdk";
let session: Chat;
let encryptor: StreamEncryptor;

// 0.6.0
import type { ChatWithJuicebox, FileEncryptor } from "@xdevplatform/chat-xdk";
let session: ChatWithJuicebox;
let encryptor: FileEncryptor;
```

## Group actions can be signed

Each call below signs one group update. The sender comes from
`setIdentity`. Each returns `actionSignatures` shaped as
[Action signatures come nested](#action-signatures-come-nested) shows. Send
those entries on the update's request, in snake_case, as this page's other
`api.post` calls do.

### Removing members

`prepareGroupMembersRemove` removes `userIds` and rotates the conversation
key for the members who stay. Pass their identity keys as `publicKeys`.
The result is a `PreparedConversationChange`: the new conversation key,
`conversationParticipantKeys` for those members, and `actionSignatures` in
this order — the removal, then the conversation-key change.

POST `/2/chat/conversations/{id}/members/remove` with `user_ids`, both
signatures, and `group_key_rotation_data` holding the new
`conversation_key_version` and `conversation_participant_keys`.

```js
// 0.6.0
const prepared = chat.prepareGroupMembersRemove({
  conversationId,
  userIds,
  publicKeys: remainingPublicKeys,
});
await api.post(`/2/chat/conversations/${conversationId}/members/remove`, {
  user_ids: userIds,
  action_signatures: prepared.actionSignatures,
  group_key_rotation_data: {
    conversation_key_version: prepared.conversationKeyVersion,
    conversation_participant_keys: prepared.conversationParticipantKeys,
  },
});
```

### Leaving a group

`prepareGroupLeave` signs the sender's removal and does not rotate the
conversation key. `actionSignatures` are the removal, then a
`GroupAdminAddChange` when `promoteAdminId` is set, then a
`ConversationDeleteEvent`. It returns a `PreparedAction`.

```js
// 0.6.0
const left = chat.prepareGroupLeave({ conversationId, promoteAdminId });
// left.actionSignatures: removal, GroupAdminAddChange, ConversationDeleteEvent
```

### Changing the title

`customTitle` is the ciphertext the request sends. The result is a
`PreparedAction`; send its `actionSignatures` on the request.

```js
// 0.6.0
const title = chat.prepareGroupTitleChange({
  conversationId,
  conversationKeyVersion,
  customTitle,
});
```

### Changing the avatar

```js
// 0.6.0
const avatar = chat.prepareGroupAvatarChange({
  conversationId,
  conversationKeyVersion,
  customAvatarUrl,
});
```

### Changing the description

`customDescription` is the ciphertext the request sends.

```js
// 0.6.0
const description = chat.prepareGroupDescriptionChange({
  conversationId,
  conversationKeyVersion,
  customDescription,
});
```

### Adding admins

```js
// 0.6.0
const added = chat.prepareGroupAdminsAdd({ conversationId, userIds });
```

### Removing admins

```js
// 0.6.0
const removed = chat.prepareGroupAdminsRemove({ conversationId, userIds });
```

### Enabling an invite

An omitted `expiresAtMsec` or `affiliateId` signs `null`.

```js
// 0.6.0
const invite = chat.prepareGroupInviteEnable({ conversationId, inviteUrl, expiresAtMsec });
```

### Disabling an invite

`disabledBy` defaults to the sender.

```js
// 0.6.0
const disabled = chat.prepareGroupInviteDisable({ conversationId });
```

### Requesting to join

`requestingUserId` defaults to the sender. An invite token is not part of
the signature.

```js
// 0.6.0
const request = chat.prepareGroupJoinRequest({ conversationId });
```

### Rejecting join requests

```js
// 0.6.0
const rejected = chat.prepareGroupJoinReject({ conversationId, userIds });
```

### Changing the message TTL

The signature covers `ttlMsec` only.

```js
// 0.6.0
const ttl = chat.prepareMessageTtlChange({ conversationId, ttlMsec });
```

### Removing the message TTL

```js
// 0.6.0
const cleared = chat.prepareMessageTtlRemove({ conversationId });
```

### Changing screen capture

`change` is a `ScreenCaptureChange`: `"blockingEnabled"`,
`"blockingDisabled"`, `"detectionEnabled"`, or `"detectionDisabled"`.

```js
// 0.6.0
const capture = chat.prepareScreenCapture({ conversationId, change: "blockingEnabled" });
```

## Signed read receipts

`prepareMarkConversationRead` signs a read receipt for the newest event you
read. It takes `{ conversationId, seenUntilSequenceId }` (that event's
sequence id) and an optional `seenAtMsec` that defaults to now, and returns
a `PreparedAction`, one entry shaped as
[Action signatures come nested](#action-signatures-come-nested) shows. Send
its `actionSignatures` as the `action_signatures` of the mark-read request,
`POST /2/chat/conversations/{id}/read`, whose path takes the conversation id
in its hyphen form. A recipient's `decryptEvent` returns a signed receipt as
a verified `ReadReceipt` event.

```js
// 0.6.0
const receipt = chat.prepareMarkConversationRead({ conversationId, seenUntilSequenceId });
await api.post(`/2/chat/conversations/${conversationId.replaceAll(":", "-")}/read`, {
  action_signatures: receipt.actionSignatures,
});
```
