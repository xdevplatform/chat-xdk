# Migrating JavaScript and TypeScript code to chat-xdk 0.7.2

This page moves code written for `@xdevplatform/chat-xdk` 0.5.x (0.5.0,
0.5.1 or 0.5.2) to 0.7.2, in Node and browsers alike. Work through it top to
bottom: [Before you start](#0-before-you-start) sets up the upgrade, the
[symbol index](#1-symbol-index) maps every 0.5.x name to its 0.7.2 form,
[Compile-time changes](#2-compile-time-changes) and [Runtime
changes](#3-runtime-and-behavior-changes) show each line to change, [Group
and receipt signing](#4-group-and-receipt-signing) gives every signed
request, and [Verify](#5-verify) checks the result. [Why 0.7.2
changes](why.md) explains each change, and the [index](README.md) lists the
other bindings' pages. [API.md](../API.md) documents every call.

## Checklist

Each item is tagged with what it takes: `[rollout]` is a deployment step,
`[compile]` a change TypeScript reports (and plain JavaScript meets on the
first call), `[runtime]` a change in behavior that nothing reports, and
`[new]` a 0.7.2 call to adopt.

- [ ] `[rollout]` [Install 0.7.2](#install-072)
- [ ] `[rollout]` [Upgrade every app that reads your conversations first](#upgrade-readers-first)
- [ ] `[rollout]` [Allow or block the feature-switch request](#the-feature-switch-request)
- [ ] `[compile]` [Put the PIN guess budget in the Juicebox config](#keys-stored-in-juicebox)
- [ ] `[compile]` [Register keys with the public key only](#register-keys-with-the-public-key-only)
- [ ] `[compile]` [Pass `{ userId, signingKeyVersion }` to `setIdentity`](#setidentity-takes-a-params-object)
- [ ] `[new]` [Keep keys yourself with `importKeys` and `exportKeys`](#importkeys-and-exportkeys)
- [ ] `[compile]` [Pass a params object to `decryptEvents` and read its `events`](#decryptevents-takes-a-params-object)
- [ ] `[compile]` [Pass a params object to `decryptEvent`](#decryptevent-takes-a-params-object)
- [ ] `[compile]` [Read `SendPayload` under the send request's field names and send `xdk_version`](#sendpayload-fields-take-the-send-requests-names)
- [ ] `[compile]` [Build a message before you encrypt its files](#encrypt-a-file-from-its-message)
- [ ] `[compile]` [Decrypt a file with the event of its message](#decrypt-a-file-with-its-messages-event)
- [ ] `[compile]` [Encrypt a file no message carries, such as a group avatar, with `encryptFileWithKey`](#encrypt-a-file-under-a-key-you-hold)
- [ ] `[compile]` [Use `fileEncryptor` and `fileDecryptor` for large files](#encrypt-and-decrypt-large-files-in-chunks)
- [ ] `[compile]` [Pass action signatures through as returned](#action-signatures-come-nested)
- [ ] `[compile]` [Name a public key input's fields `identityPublicKey` and `publicKeyVersion`](#public-key-inputs-name-the-identity-key-and-its-version)
- [ ] `[compile]` [Pass participant keys through as returned](#participant-keys-take-the-key-requests-names)
- [ ] `[compile]` [Read received participant keys under the same names](#received-participant-keys-take-the-same-names)
- [ ] `[compile]` [Read a delete's signature from its `PreparedAction`](#deletes-return-a-preparedaction)
- [ ] `[compile]` [Read decrypted events under the names the calls take](#decrypted-events-use-the-names-the-calls-take)
- [ ] `[compile]` [Tell errors apart by `kind`, and read a wrong PIN's attempts from `guessesRemaining`](#errors-carry-their-kind)
- [ ] `[compile]` [TypeScript: import the types the package exports](#typescript-import-the-types-the-package-exports)
- [ ] `[runtime]` [Write every request body in snake_case](#request-bodies-take-snake_case)
- [ ] `[runtime]` [Pass user ids as strings of digits](#user-ids-are-strings-of-digits)
- [ ] `[runtime]` [Pass key versions as the X API returns them](#key-versions-are-integers-written-as-strings)
- [ ] `[runtime]` [Pass millisecond values as safe integers](#millisecond-values-are-safe-integers)
- [ ] `[runtime]` [Pass entities, files, URL cards and posts the SDK accepts](#entities-files-url-cards-and-posts-are-checked)
- [ ] `[runtime]` [Store every participant's signing keys, and handle a `latestVersion` of `null`](#latestversion-comes-from-a-verified-key-change)
- [ ] `[runtime]` [Rename every read of `targetMessageId` to `targetMessageSequenceId`](#targetmessageid-holds-a-different-value)
- [ ] `[runtime]` [Reply with `replyToEvent`, whose preview recipients check exactly](#a-reply-preview-quotes-its-message-exactly)
- [ ] `[runtime]` [Store a prepared change's key yourself, not through `JSON.stringify`](#a-prepared-changes-json-leaves-out-its-key)
- [ ] `[runtime]` [Sign only your own data with `sign`](#sign-refuses-data-only-the-sdk-signs)
- [ ] `[runtime]` [Skip the events `decryptEvent` drops](#decrypt-drops-a-removals-title-and-description-re-encryptions)
- [ ] `[runtime]` [Check for keys before `exportKeys`](#exportkeys-throws-without-keys)
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
snippet with only a `// 0.7.2` half shows code 0.7.2 adds. CI type-checks
the 0.7.2 half of every snippet on this page against the package's typings
with `strict` on
([`scripts/check_doc_snippets.py`](../../scripts/check_doc_snippets.py)).

`chat` is the `ChatWithJuicebox` that `createChat` returns, unlocked, and
the other names stand for your own values: ids, versions, keys and events as
the X API returns them, `keys` for the conversation key map `decryptEvents`
returns, `payload` for a `SendPayload`, `prepared` for a
`PreparedConversationChange`, `keyChange`, `message`, `deleted`, `receipt`
and `groupChange` for a decrypted keyChange, message, messageDeleted,
readReceipt and groupChange event, `err` for an error a call threw, and
`page` for a page of `GET /2/chat/conversations/{id}/events`.
`api.post(path, body)`, `api.put(path, body)` and `api.delete(path, body)`
stand for your HTTP client: each sends `body` as JSON to `https://api.x.com`
+ `path` with your user access token, and resolves to the parsed JSON
response. `pathId` is the conversation id as a request path takes it: a
group's `g…` id as is, and a one-to-one's in its hyphen form,
`conversationId.replaceAll(":", "-")`. `photoAttachment(mediaHashKey)`
stands for your code that builds a photo's attachment descriptor;
`showEdit`, `showTitle`, `showDescription`, `showAvatar` and
`showGuessesLeft` for your code that displays an edit, a group's title,
description or avatar, or the PIN attempts left; `handle(event)` for your
code that handles a decrypted event; `logSkipped(eventB64, err)` for your
code that logs an event it skips; and `storeConversationKey(conversationId,
version, key)` for your code that stores a conversation key.
`ChatXdkError`, `createChat` and functions such as `encryptedFileSize` and
`bytesToBase64` import from `@xdevplatform/chat-xdk`.

The package returns camelCase objects, and the X API takes snake_case keys.
The snippets write each request body's own keys in snake_case and pass the
objects the package returns through `toSnake`, the converter the
[examples](../../examples/js/src/x-api.mjs) use:

```js
// 0.7.2
/** CamelCase object keys to the snake_case the X API reads. */
function toSnake(value) {
  if (Array.isArray(value)) return value.map(toSnake);
  if (value instanceof Uint8Array) return value;
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [
        key.replace(/[A-Z]/g, (ch) => `_${ch.toLowerCase()}`),
        toSnake(item),
      ]),
    );
  }
  return value;
}
```

## 0. Before you start

### Install 0.7.2

Pin the package at 0.7.2 in `package.json`, then install it:

```sh
npm install @xdevplatform/chat-xdk@0.7.2
```

It needs Node 18 or newer, or a browser bundler that loads WebAssembly.
Every app that shares conversations with yours reads the formats 0.7.2 sends
only once it runs a 0.7 release too, so plan the rollout below before you
deploy.

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

- any of your senders can send v1, that is, before the X API turns
  `v1_send` on for them;
- you pass a description to [`prepareGroupMembersChange`](#adding-members).

0.7.2 reads both formats, including v1 reply previews, edits and files.
There's no code to change: to see which format a send used, read
`payload.signatureInfo.signatureVersion`, `"7"` for v0 and `"10"` for v1.

### The feature-switch request

Chats read the X API's feature switches with one anonymous request,
`GET https://api.x.com/2/chat/features`, which runs in the background:

- a chat reads them when it is created, again once `setIdentity` gives it
  a sender, and again 5 minutes after each answer, so a switch that changes
  reaches running chats; each answer replaces the one before;
- with a sender set, the request carries its bucket, the last four digits
  of the user id (`?bucket=1234`), so every chat of one sender gets the same
  answer; chats that read the same URL share one request;
- it carries no credentials and no other user data, and never delays or
  fails a call;
- every switch is off until an answer for the chat's URL arrives, so a
  chat's first sends can be v0;
- a request that fails is retried in the background while a chat waits for
  its answer: 1 second later, then after twice the previous wait, at most 5
  minutes apart; a failure keeps the answer a chat already has, and if every
  attempt fails or is blocked, every switch stays off and its sends stay v0.

Allow outbound HTTPS to `api.x.com` if you want your sends to follow the
switch, or block it to keep them v0. In a browser the request is a
cross-origin `GET`, and one the browser blocks fails like any other. The
requests never keep a process alive, except in Node before 20.16, where one
still in flight can delay exit until it ends, at most 2 seconds. There's no
code to change.

## 1. Symbol index

Every 0.5.x name that changes, with its 0.7.2 form and the section that
shows the change. A name not listed here keeps its 0.5.x form. Search your
code for each name in the first column; [Verify](#5-verify) gives the
search as one command.

| 0.5.x | 0.7.2 | Section |
|---|---|---|
| `createChat({ ..., maxGuessCount })` | `max_guess_count` in the Juicebox config | [Juicebox](#keys-stored-in-juicebox) |
| `guessesRemaining(err)` | `err.guessesRemaining` on a `ChatXdkError` | [Juicebox](#keys-stored-in-juicebox) |
| `registration.version`, `registration.generateVersion` | Removed: the registration request returns the version (`public_key_version`) | [Registration](#register-keys-with-the-public-key-only) |
| `PublicKeys.version` | Removed: the `public_key_version` the registration request returns | [Registration](#register-keys-with-the-public-key-only) |
| `chat.setIdentity(userId, signingKeyVersion)` | `chat.setIdentity({ userId, signingKeyVersion })` | [setIdentity](#setidentity-takes-a-params-object) |
| `chat.decryptEvents(events, signingKeys)` | `chat.decryptEvents({ events, signingKeys })` | [decryptEvents](#decryptevents-takes-a-params-object) |
| `result.messages`, `DecryptedMessage` | `result.events`, `DecryptedEvent` | [decryptEvents](#decryptevents-takes-a-params-object) |
| `chat.decryptEvent(eventB64, keys, signingKeys)` | `chat.decryptEvent({ eventB64, conversationKeys: keys, signingKeys })` | [decryptEvent](#decryptevent-takes-a-params-object) |
| `payload.encryptedContent` | `payload.encodedMessageCreateEvent` | [SendPayload](#sendpayload-fields-take-the-send-requests-names) |
| `payload.encodedEventSignature` | `payload.encodedMessageEventSignature` | [SendPayload](#sendpayload-fields-take-the-send-requests-names) |
| `chat.encryptStream(plaintext, key)`, a message's file | `chat.encryptFile({ file, eventB64, mediaHashKey })` | [Files](#encrypt-a-file-from-its-message) |
| `chat.encryptStream(plaintext, key)`, any other file, such as a group avatar | `chat.encryptFileWithKey({ file, key })` | [Files under a key](#encrypt-a-file-under-a-key-you-hold) |
| `chat.decryptStream(encrypted, key)`, a message's file | `chat.decryptFile({ encrypted, eventB64, conversationKeys, mediaHashKey })` | [Files](#decrypt-a-file-with-its-messages-event) |
| `chat.decryptStream(encrypted, key)`, any other file | `chat.decryptFileWithKey({ encrypted, key })` | [Files under a key](#encrypt-a-file-under-a-key-you-hold) |
| `chat.streamEncryptor(key)`, `chat.streamDecryptor(key)`, a message's file | `chat.fileEncryptor({ eventB64, mediaHashKey })`, `chat.fileDecryptor({ eventB64, conversationKeys, mediaHashKey })` | [Large files](#encrypt-and-decrypt-large-files-in-chunks) |
| `chat.streamEncryptor(key)`, `chat.streamDecryptor(key)`, any other file | `encryptFileWithKey` and `decryptFileWithKey` over the whole file | [Large files](#encrypt-and-decrypt-large-files-in-chunks) |
| `StreamEncryptor`, `StreamDecryptor` | `FileEncryptor`, `FileDecryptor` (interfaces) | [TypeScript](#typescript-import-the-types-the-package-exports) |
| `encryptedStreamSize(n)` | `encryptedFileSize(n)` | [Files](#encrypt-a-file-from-its-message) |
| `chat.encrypt(plaintext, key)` | Removed: titles and descriptions go through `prepareGroupTitleChange`, `prepareGroupDescriptionChange` and the group creates and member adds; avatar URLs aren't encrypted; files go through `encryptFile` or `encryptFileWithKey` | [Changing the title](#changing-the-title) |
| Action signature `signature`, `signatureVersion`, `publicKeyVersion`, `signaturePayload` | Nested under `messageEventSignature`; pass `actionSignatures` as returned | [Action signatures](#action-signatures-come-nested) |
| Public key input `publicKey`, `keyVersion` | `identityPublicKey`, `publicKeyVersion` | [Public key inputs](#public-key-inputs-name-the-identity-key-and-its-version) |
| `prepared.participantKeys`, `EncryptedKeyForRecipient`, `encryptedKey` | `prepared.conversationParticipantKeys`, `ConversationParticipantKey`, `encryptedConversationKey` | [Participant keys](#participant-keys-take-the-key-requests-names) |
| `keyChange.participantKeys`, `ParticipantKey`, `encryptedKey` | `keyChange.conversationParticipantKeys`, `ConversationParticipantKey`, `encryptedConversationKey` | [Received keys](#received-participant-keys-take-the-same-names) |
| `prepareMessageDelete` returning an `ActionSignature` | Returns a `PreparedAction`: `deletion.actionSignatures[0]` | [Deletes](#deletes-return-a-preparedaction) |
| `message.keyVersion`, `keyChange.keyVersion` | `conversationKeyVersion` | [Event names](#decrypted-events-use-the-names-the-calls-take) |
| Reaction and edit `targetMessageId` | `targetMessageSequenceId` | [Event names](#decrypted-events-use-the-names-the-calls-take) |
| Edit `newText` | `updatedText` | [Event names](#decrypted-events-use-the-names-the-calls-take) |
| `deleted.messageIds` | `sequenceIds` | [Event names](#decrypted-events-use-the-names-the-calls-take) |
| `receipt.seenUntilId` | `seenUntilSequenceId` | [Event names](#decrypted-events-use-the-names-the-calls-take) |
| Group title and description strings (`title`, `newTitle`) | `GroupText` | [Creating a group](#creating-a-group) |
| `prepareGroupCreate({ ..., avatarUrl })` | Removed: set the avatar with `prepareGroupAvatarChange` | [Creating a group](#creating-a-group) |
| `replyToSenderId: 4201` (a number) | `replyToSenderId: "4201"` | [User ids](#user-ids-are-strings-of-digits) |
| `err.message.startsWith("Invalid state:")` | `err instanceof ChatXdkError && err.kind === "invalidInput"` | [Errors](#errors-carry-their-kind) |
| `import type { Chat }`, `import type { ChatCrypto }` | `import type { ChatWithJuicebox }` | [TypeScript](#typescript-import-the-types-the-package-exports) |

## 2. Compile-time changes

These changes are in the order an app meets them: creating the chat,
registering, loading keys, decrypting, encrypting and sending, files,
prepared changes, decrypted events and errors. TypeScript reports each one;
plain JavaScript meets most of them as a `ChatXdkError` or a `TypeError` on
the first call.

### Keys stored in Juicebox

`createChat` keeps your keys in Juicebox when you pass `getAuthToken`, with
the Juicebox config the X API returns as `juiceboxConfig`, or set later with
`updateConfig` on first boot. The PIN guess budget is the config's
`max_guess_count`, as in every binding. To register under another budget,
set it in the config:

```js
// 0.5.x
const chat = await createChat({ juiceboxConfig, getAuthToken, maxGuessCount: 10 });

// 0.7.2
const chat = await createChat({
  juiceboxConfig: JSON.stringify({ ...JSON.parse(juiceboxConfig), max_guess_count: 10 }),
  getAuthToken,
});
```

The SDK reads the config, so a malformed one throws a `ChatXdkError` of kind
`invalidInput` naming what's wrong, such as `Invalid Juicebox config:
Missing token_map or sdk_config`, and a Juicebox failure throws one of kind
`juicebox` with the message every binding gives it, such as `Juicebox
error: Transient error - retry`. A wrong PIN throws one of kind
`invalidPin`, whose `guessesRemaining` holds the attempts Juicebox reports
left, `0` once the stored keys are locked and `null` when Juicebox reports
no count:

```js
// 0.5.x
try {
  await chat.unlock(pin);
} catch (err) {
  showGuessesLeft(guessesRemaining(err));
}

// 0.7.2
try {
  await chat.unlock(pin);
} catch (err) {
  showGuessesLeft(err instanceof ChatXdkError ? err.guessesRemaining : null);
}
```

Until a chat has a config, the Juicebox calls throw (see [An empty Juicebox
config fails](#an-empty-juicebox-config-fails)).

### Register keys with the public key only

`generateKeypairs()` returns a payload that holds only `publicKey`. Send it
as the only field of the `POST /2/users/{id}/public_keys` body,
`public_key`. 0.7.2 doesn't pick a signing-key version for new keys: call
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

// 0.7.2
const registration = chat.generateKeypairs();
const response = await api.post(`/2/users/${userId}/public_keys`, {
  public_key: toSnake(registration.publicKey),
});
chat.setIdentity({ userId, signingKeyVersion: response.data.public_key_version });
```

The public keys `getPublicKeys()` and `setup()` return hold the two keys,
`identity` and `signing`, and no `version`: their version is the
`public_key_version` the registration request returns.

### `setIdentity` takes a params object

Pass the user id and the signing-key version as `{ userId,
signingKeyVersion }`. It throws when either value is invalid (see
[user ids](#user-ids-are-strings-of-digits) and
[key versions](#key-versions-are-integers-written-as-strings)).

```js
// 0.5.x
chat.setIdentity(userId, signingKeyVersion);

// 0.7.2
chat.setIdentity({ userId, signingKeyVersion });
```

### `importKeys` and `exportKeys`

Without `getAuthToken`, `createChat()` returns a chat that keeps its keys
outside Juicebox and loads no juicebox-sdk: `importKeys` loads the keys
`exportKeys` returned, as in every binding, with the signing-key version
they were registered under. `exportKeys` returns the raw private keys, so
store them only where private keys belong and zero the bytes once stored;
it throws when no identity key is loaded (see [`exportKeys` throws without
keys](#exportkeys-throws-without-keys)):

```js
// 0.7.2
const chat = await createChat();
chat.importKeys({ keys: privateKeys, signingKeyVersion });
```

### `decryptEvents` takes a params object

Pass `{ events, signingKeys }`. `signingKeys` is optional; without it, the
keys `setSigningKeys` stored verify the events. An event that fails, or one
decrypt drops, is collected in the result's `errors` rather than thrown;
the call throws only for invalid params, such as `events` that is not an
array of strings or a malformed `signingKeys` entry. The result holds the
decrypted events, of every event type, in `events`:

```js
// 0.5.x
const result = chat.decryptEvents(events, signingKeys);
const decrypted = result.messages;

// 0.7.2
const result = chat.decryptEvents({ events, signingKeys });
const decrypted = result.events;
```

The version to encrypt with, `result.conversationKeys.latestVersion`, comes
only from a key change that verified (see [`latestVersion` comes from a
verified key change](#latestversion-comes-from-a-verified-key-change)).

### `decryptEvent` takes a params object

Pass `{ eventB64, conversationKeys, signingKeys }`. Both key fields are
optional: without them, the conversation keys come from the key cache
(`setCacheKeys(true)`) and the signing keys from `setSigningKeys`. The call
still throws on failure, and for an event decrypt drops (see [Decrypt drops
a removal's title and description
re-encryptions](#decrypt-drops-a-removals-title-and-description-re-encryptions)).
A `conversationKeys` entry that is not a 32-byte `Uint8Array` throws an
error naming its version, where 0.5.x skipped it: pass the `keys` map
`decryptEvents` or `extractConversationKeys` returns.

```js
// 0.5.x
const event = chat.decryptEvent(eventB64, keys, signingKeys);

// 0.7.2
const event = chat.decryptEvent({ eventB64, conversationKeys: keys, signingKeys });
```

### `SendPayload` fields take the send request's names

The two encoded fields carry the names of the fields of the send request,
`POST /2/chat/conversations/{id}/messages`, camelCased, so the request takes
them as they are. Read them under those names wherever your code reads a
payload, including code that stores payloads. The request also takes the
payload's `xdkVersion`, the version of the SDK that built it, as
`xdk_version`:

```js
// 0.5.x
const body = {
  message_id: payload.messageId,
  encoded_message_create_event: payload.encryptedContent,
  encoded_message_event_signature: payload.encodedEventSignature,
};

// 0.7.2
const body = {
  message_id: payload.messageId,
  encoded_message_create_event: payload.encodedMessageCreateEvent,
  encoded_message_event_signature: payload.encodedMessageEventSignature,
  xdk_version: payload.xdkVersion,
};
```

A payload also carries `eventB64`, the message as recipients receive it. It
isn't part of the send request: keep it to encrypt the message's files (see
[Encrypt a file from its message](#encrypt-a-file-from-its-message)).

A v1 payload's encoded fields carry what X clients' v1 sends carry:
`encodedMessageEventSignature` lists the signing keys the message relies on,
by user id and key version (the sender's own and, for a reply, those of the
quoted message's sender and of its edit's), and `encodedMessageCreateEvent`
asks for a notification for a reaction only in a one-to-one conversation,
and never for a reaction removal or an edit. Send both as returned.

### Encrypt a file from its message

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

// 0.7.2
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
the same message again gives the same id, so files you already encrypted for
it stay valid, and a second message that reuses the first one's uploads gets
the same id, so recipients drop it as a repeat. The file fields the SDK
checks are listed under [Entities, files, URL cards and posts are
checked](#entities-files-url-cards-and-posts-are-checked).

### Decrypt a file with its message's event

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

// 0.7.2
const plaintext = chat.decryptFile({
  encrypted: downloaded, eventB64: fileEventB64, conversationKeys: keys, mediaHashKey: fileHashKey,
});
```

### Encrypt a file under a key you hold

`encryptStream` and `decryptStream` take a key from the app for every file.
A file a message carries takes its key from the message, as the two
sections above show. A file no message carries keeps the key you hold, and
goes through `encryptFileWithKey` and `decryptFileWithKey`: a group's avatar
image, which X clients encrypt under the conversation key whose version the
avatar change signs next to the avatar URL (see [Changing the
avatar](#changing-the-avatar)), or your app's own files at rest. Each takes
the raw 32-byte key `encryptStream` took, as `key` in its params object, and
writes the format `encryptStream` writes: files 0.5.x encrypted with
`encryptStream` or a stream encryptor decrypt with `decryptFileWithKey`, and
0.5.x `decryptStream` decrypts what `encryptFileWithKey` returns, so files
you stored need no re-encryption. A key that isn't 32 bytes throws a
`ChatXdkError` of kind `invalidInput`, and bytes that aren't a complete file
encrypted under the key one of kind `decryption`.

```js
// 0.5.x
const encrypted = chat.encryptStream(data, conversationKey);
const plaintext = chat.decryptStream(downloaded, conversationKey);

// 0.7.2
const encrypted = chat.encryptFileWithKey({ file: data, key: conversationKey });
const plaintext = chat.decryptFileWithKey({ encrypted: downloaded, key: conversationKey });
```

To move an `encryptStream` or `decryptStream` call, look at its file. A file
one of a message's attachments names (a photo, a video, a link card's banner
or favicon) moves to `encryptFile` and `decryptFile`, with the message; any
other file moves to `encryptFileWithKey` and `decryptFileWithKey`, with the
same key.

### Encrypt and decrypt large files in chunks

`fileEncryptor` and `fileDecryptor` take the same values as `encryptFile`
and `decryptFile`, without the file bytes, and return a `FileEncryptor` or a
`FileDecryptor`; `push`, `finish` and `free` keep their 0.5.x form. Size an
upload with `encryptedFileSize`. A file under a key you hold has no chunked
form: read it whole and pass it to `encryptFileWithKey` or
`decryptFileWithKey` (see [Encrypt a file under a key you
hold](#encrypt-a-file-under-a-key-you-hold)).

```js
// 0.5.x
const size = encryptedStreamSize(photo.length);
const encryptor = chat.streamEncryptor(conversationKey);
const decryptor = chat.streamDecryptor(keys[conversationKeyVersion]);

// 0.7.2
const size = encryptedFileSize(photo.length);
const encryptor = chat.fileEncryptor({ eventB64: payload.eventB64, mediaHashKey });
const decryptor = chat.fileDecryptor({
  eventB64: fileEventB64, conversationKeys: keys, mediaHashKey: fileHashKey,
});
```

### Action signatures come nested

The prepare methods return each signed action in the shape a request's
`action_signatures` takes, camelCased as everything the package returns is:
`messageId`, `encodedMessageEventDetail`, the signature nested under
`messageEventSignature` (with `signingPublicKey`, your signing public key as
`getPublicKeys` returns it), and nothing else: the signed payload stays
inside the SDK. Use them as returned, and convert them with `toSnake` when
you build the request body (see [Request bodies take
snake_case](#request-bodies-take-snake_case)):

```js
// 0.5.x
const actionSignatures = prepared.actionSignatures.map((sig) => ({
  message_id: sig.messageId,
  encoded_message_event_detail: sig.encodedMessageEventDetail,
  message_event_signature: {
    signature: sig.signature,
    signature_version: sig.signatureVersion,
    public_key_version: sig.publicKeyVersion,
    signing_public_key: signingPublicKey,
  },
}));

// 0.7.2
const actionSignatures = toSnake(prepared.actionSignatures);
```

### Public key inputs name the identity key and its version

Each public key the prepare params take, one participant a conversation key
is encrypted to, names its key `identityPublicKey` and the key's version
`publicKeyVersion`, as a signing key entry does: the `public_key` the X API
returns for a user is their identity key:

```js
// 0.5.x
const publicKeys = [{ userId, publicKey: identityPublicKey, keyVersion: publicKeyVersion }];

// 0.7.2
const publicKeys = [{ userId, identityPublicKey, publicKeyVersion }];
```

### Participant keys take the key requests' names

A prepared change's participant keys carry the names the X API gives them in
every request that takes them (`POST /2/chat/conversations/{id}/keys`,
`/group` and `/{id}/members`, and `PUT /2/chat/conversations/{id}`),
camelCased as everything the package returns is:
`conversationParticipantKeys`, each entry a `ConversationParticipantKey`
with `userId`, `encryptedConversationKey` and `publicKeyVersion`, the names
a received keyChange event uses too (see [Received participant keys take
the same names](#received-participant-keys-take-the-same-names)). Drop the
renaming, and convert them with `toSnake` when you build the request body:

```js
// 0.5.x
const conversationParticipantKeys = prepared.participantKeys.map((key) => ({
  user_id: key.userId,
  encrypted_conversation_key: key.encryptedKey,
  public_key_version: key.publicKeyVersion,
}));

// 0.7.2
const conversationParticipantKeys = toSnake(prepared.conversationParticipantKeys);
```

### Received participant keys take the same names

A decrypted keyChange event carries its participant keys under the names
Thrift's `ConversationKeyChangeEvent` gives them, camelCased, the same names
a prepared change uses: `conversationParticipantKeys`, each entry with
`userId`, `encryptedConversationKey` and `publicKeyVersion`. Read them under
those names:

```js
// 0.5.x
const [mine] = keyChange.participantKeys ?? [];
const encrypted = mine.encryptedKey;

// 0.7.2
const [mine] = keyChange.conversationParticipantKeys ?? [];
const encrypted = mine?.encryptedConversationKey;
```

In TypeScript, received and prepared keys are one type,
`ConversationParticipantKey`:

```ts
// 0.5.x
import type { EncryptedKeyForRecipient, ParticipantKey } from "@xdevplatform/chat-xdk";
const sent: EncryptedKeyForRecipient[] = prepared.participantKeys;
const received: ParticipantKey[] = keyChange.participantKeys ?? [];

// 0.7.2
import type { ConversationParticipantKey } from "@xdevplatform/chat-xdk";
const sent: ConversationParticipantKey[] = prepared.conversationParticipantKeys;
const received: ConversationParticipantKey[] = keyChange.conversationParticipantKeys ?? [];
```

### Deletes return a `PreparedAction`

`prepareMessageDelete` returns a `PreparedAction` whose `actionSignatures`
hold one entry, shaped as [Action signatures come
nested](#action-signatures-come-nested) shows. Read the action's `messageId`
from that entry, and send `actionSignatures` as returned (see [Deleting
messages](#deleting-messages) for the request):

```js
// 0.5.x
const deletion = chat.prepareMessageDelete({ conversationId, sequenceIds, deleteForAll: false });
const messageId = deletion.messageId;

// 0.7.2
const deletion = chat.prepareMessageDelete({ conversationId, sequenceIds, deleteForAll: false });
const messageId = deletion.actionSignatures[0].messageId;
```

### Decrypted events use the names the calls take

Decrypted message and keyChange events carry their conversation key version
as `conversationKeyVersion`, the X API's `conversation_key_version`
camelCased, and the name the encrypt methods take:

```js
// 0.5.x
const messageVersion = message.keyVersion;
const keyChangeVersion = keyChange.keyVersion;

// 0.7.2
const messageVersion = message.conversationKeyVersion;
const keyChangeVersion = keyChange.conversationKeyVersion;
```

Fields that hold sequence ids take the names of the params that send them.
`reaction`, `reactionRemoved` and `edit` content names its target
`targetMessageSequenceId`, as the reaction and edit params do. A
messageDeleted event names its messages `sequenceIds`, as
`prepareMessageDelete` does, and a readReceipt or markedUnread event names
its position `seenUntilSequenceId`, as `prepareMarkConversationRead` does.
An edit's text is `updatedText`, as `encryptEdit` names it, and a v1 edit
carries the signed message id of the message it edits as `targetMessageId`,
absent for a v0 edit.

**Rename every read of `targetMessageId` to `targetMessageSequenceId`.
Don't keep `targetMessageId`: in 0.7.2 it names a different value, and
reading it throws no error** (see [`targetMessageId` holds a different
value](#targetmessageid-holds-a-different-value)).

```js
// 0.5.x
if (message.content.contentType === 'edit') {
  showEdit(message.content.targetMessageId, message.content.newText);
}
const deletedSequenceIds = deleted.messageIds;
const seenUntil = receipt.seenUntilId;

// 0.7.2
const content = message.content;
if (content?.contentType === 'edit' && content.targetMessageSequenceId && content.updatedText) {
  showEdit(content.targetMessageSequenceId, content.updatedText);
}
const deletedSequenceIds = deleted.sequenceIds;
const seenUntil = receipt.seenUntilSequenceId;
```

A group create's `title`, and a title or description change's `newTitle`
or `newDescription`, is a `GroupText` rather than a string (see [Creating a
group](#creating-a-group)).

### Errors carry their kind

Every call throws a `ChatXdkError`, an `Error` whose `kind` names the
failure the same way in every binding: `invalidInput`, `invalidState`,
`parse`, `decryption`, `verification`, `invalidPin`, `juicebox` or
`internal`. Its `guessesRemaining` is set after a wrong PIN (see
[Keys stored in Juicebox](#keys-stored-in-juicebox)).

A missing or invalid parameter throws one of kind `invalidInput` whose
message names the value, such as `Invalid sender_id 'user-1': pass a numeric
user id (digits only)` or `too many attachments: at most 10 per message`,
without an `Invalid state:` prefix. That covers a key or signature that
`verify`, `verifyKeyBinding` or `matchesRegisteredKey` can't decode. A
params object the call can't read throws one that names the call, such as
`Invalid encryptMessage params: ...`. Errors about state the chat lacks,
such as a missing session identity or an empty key cache, are of kind
`invalidState` and keep their prefix. Tell failures apart by kind rather
than by message:

```js
// 0.5.x
const invalidInput = !err.message.startsWith("Invalid state:");

// 0.7.2
const invalidInput = err instanceof ChatXdkError && err.kind === "invalidInput";
```

### TypeScript: import the types the package exports

The typings declare only what the package exports. Type a chat as
`ChatWithJuicebox`, the class `createChat` returns, and the file encryptors
as the `FileEncryptor` and `FileDecryptor` interfaces:

```ts
// 0.5.x
import type { Chat, ChatCrypto, StreamEncryptor } from "@xdevplatform/chat-xdk";
let session: Chat;
let crypto: ChatCrypto;
let encryptor: StreamEncryptor;

// 0.7.2
import type { ChatWithJuicebox, FileEncryptor } from "@xdevplatform/chat-xdk";
let session: ChatWithJuicebox;
let crypto: ChatWithJuicebox;
let encryptor: FileEncryptor;
```

The typings also declare `ChatXdkError` with its `ChatXdkErrorKind`,
`ImportKeysParams` for `importKeys`, and `DecryptedEvent` for each entry of
a `decryptEvents` result.

## 3. Runtime and behavior changes

Nothing reports these changes before the code runs: each one is a value the
SDK checks, a value with a new meaning, or an event handled differently.

### Request bodies take snake_case

The package returns camelCase objects, nested ones included: an action
signature is `{ messageId, encodedMessageEventDetail, messageEventSignature:
{ signature, signatureVersion, publicKeyVersion, signingPublicKey } }`. The
X API reads snake_case keys at every level and rejects a body whose nested
keys are camelCase. Write each body's own keys in snake_case, and pass every
object the package returns through `toSnake` (see [About the
snippets](#about-the-snippets)). Build each body field by field: a prepared
change passed whole through `toSnake` would carry its `conversationKey`.

```js
// 0.7.2
await api.post(`/2/chat/conversations/${pathId}/keys`, {
  conversation_key_version: prepared.conversationKeyVersion,
  conversation_participant_keys: toSnake(prepared.conversationParticipantKeys),
  action_signatures: toSnake(prepared.actionSignatures),
});
```

### User ids are strings of digits

Every user id is a string of digits: the `setIdentity` user id, `senderId`,
`replyToSenderId`, the `userId` of each public key and signing key, and the
ids of a group's members and admins (`memberIds`, `adminIds`,
`newMemberIds`, `currentMemberIds`, `currentAdminIds`,
`currentPendingMemberIds` and `userIds`). Each must be a positive integer
written without a sign or leading zeros; anything else throws an error that
names the field, such as `Invalid sender_id 'user-1': pass a numeric user id
(digits only)`. `replyToSenderId` takes a string and rejects a number, since
ids pass 2^53, where JavaScript numbers stop being exact:

```js
// 0.5.x
const reply = chat.encryptReply({
  conversationId, text: "pong", replyToSequenceId: "7", replyToSenderId: 4201, replyToText: "ping",
});

// 0.7.2
const reply = chat.encryptReply({
  conversationId, text: "pong", replyToSequenceId: "7", replyToSenderId: "4201", replyToText: "ping",
  replyToMessageId: "0b4f7c2e-5a1d-4e8b-9c3f-6d2a1b8e7f90",
});
```

A reply built from these fields also names the quoted message's
`message_id` as `replyToMessageId` (see [A reply preview quotes its message
exactly](#a-reply-preview-quotes-its-message-exactly)).

### Key versions are integers written as strings

Every key version is a non-negative integer written as a string of digits,
as the X API returns it: the signing-key version (in `setIdentity`, a call's
`signingKeyVersion` and each public key's `publicKeyVersion`) and
`conversationKeyVersion`. Anything else throws an error that names the
field, such as `Invalid signing_key_version 'v1': pass the key version as
the X API returns it, an integer in digits`. There's no code to change if
you pass the versions the X API returns.

### Millisecond values are safe integers

A millisecond field (`ttlMsec`, `currentTtlMsec`, `seenAtMsec`,
`expiresAtMsec`) takes a finite number within the safe integer range. NaN,
an infinity or a number past that range names no instant or duration, so
the call throws an `Invalid <method> params` error rather than signing some
other value. A fraction is truncated toward zero.

### Entities, files, URL cards and posts are checked

The encrypt calls check what a message carries before they encrypt it, and
throw a `ChatXdkError` of kind `invalidInput` naming the value, where 0.5.x
sent it:

- An entity of a type the SDK doesn't know, an empty one included, fails
  with `Invalid entity_type 'user_mention': pass url, mention, hashtag,
  cashtag, email, address or phone_number`, for a message's, a reply's, a
  reply preview's and an edit's entities.
- Entity offsets count bytes of the text's UTF-8 encoding, the start
  inclusive and the end exclusive, not the UTF-16 units of a JavaScript
  string. An entity whose offsets are negative, end before they start or
  run past the end of the text fails, such as `Invalid entity offsets 3..8:
  end is past the end of the text, which is 7 bytes of UTF-8`. A reply
  preview's entities, which index the quoted message's text, are checked
  for all but the end.
- A file a message carries, a media attachment or a URL card's banner or
  favicon, fails with an empty `filename`, a `filesize_bytes` of 0 or less,
  or a negative `width` or `height`, since receiving clients discard such a
  file. Give each file its name and the encrypted size `encryptedFileSize`
  gives.
- A message that lists an empty media hash key, or one media hash key in
  two attachments, fails.
- A URL card with an empty `url`, and a post attachment with neither
  `rest_id` nor `post_url`, fail.

Count an entity's offsets in bytes of UTF-8 when the text holds characters
outside ASCII:

```js
// 0.7.2
const utf8Length = (text) => new TextEncoder().encode(text).length;
const text = "café @bob";
const start = utf8Length(text.slice(0, text.indexOf("@bob")));
const payload = chat.encryptMessage({
  conversationId, text, entities: [[start, start + utf8Length("@bob"), "mention"]],
});
```

### `latestVersion` comes from a verified key change

`result.conversationKeys.latestVersion`, the version to encrypt with, is the
newest version whose key change verified, and it never moves back for the
chat's lifetime. A key change verifies only against its sender's signing
key, so give the chat every participant's signing keys, your own included,
before you decrypt. It's `null` until a key change verifies: a key change
the SDK can't verify still adds its key to `result.conversationKeys.keys`,
for decrypting, but never becomes the version you encrypt with. Where 0.5.x
returned the batch's highest version, 0.7.2 can return `null`: fetch the
missing signing keys or the conversation's key-change events and decrypt
again, rather than encrypting under the highest key in `keys`:

```js
// 0.5.x
const result = chat.decryptEvents(events, signingKeys);
const version = result.conversationKeys.latestVersion;

// 0.7.2
chat.setSigningKeys(signingKeys);
const result = chat.decryptEvents({ events });
const version = result.conversationKeys.latestVersion;
if (version === null) {
  // No key change verified: fetch every participant's signing keys
  // (GET /2/users/{id}/public_keys) and the conversation's key changes
  // (meta.conversation_key_events of GET /2/chat/conversations/{id}/events),
  // then decrypt again.
}
```

### `targetMessageId` holds a different value

**In 0.5.x a reaction's or edit's `targetMessageId` held the target's
sequence id. In 0.7.2 that value is `targetMessageSequenceId`, and
`targetMessageId` holds the edited message's signed message id, present
only on a v1 edit.** Code that keeps reading `targetMessageId` throws no
error, and TypeScript accepts it: it gets the wrong id, or none. Rename
every read, as [Decrypted events use the names the calls
take](#decrypted-events-use-the-names-the-calls-take) shows, and use
`targetMessageId` only to match a v1 edit to the `messageId` you deduplicate
on.

An edit you build names the edited message the same way: set `encryptEdit`'s
`targetMessageId` to its signed `message_id`, which a v1 edit built from the
conversation id and the target sequence id needs. With `targetEvent`, the
SDK takes the id from the event, and a `targetMessageId` other than it
throws a `ChatXdkError` of kind `invalidInput`.

### A reply preview quotes its message exactly

A received reply that embeds the message it quotes has its preview checked
against that message: `replyPreviewValidation` is `'valid'` only when the
first 140 characters of the preview's text, counted in UTF-16 code units as
X clients count them, are those of the quoted text, and its entities are
exactly the quoted message's, or its edit's when the reply embeds the edit.
0.5.x accepted any start of the quoted text, and entities among the quoted
message's. `encryptReply` builds such a preview from `replyToEvent`, and
from `replyToEditEvent` when the message was edited, so pass them when you
hold them. In v1, X clients check a reply against the message it names and
mark a reply that names none invalid, so a reply built from the explicit
preview fields names the quoted message's `message_id` as
`replyToMessageId`. With `replyToEvent`, the SDK takes the id from the
event, and a `replyToMessageId` other than it throws a `ChatXdkError` of
kind `invalidInput`.

A reply carries no key change. Recipients open the quoted message with their
own conversation keys, or with the message key a reply carries for a v1
message, and decrypt ignores a key change embedded in a reply.
`replyToCkces` still opens a message under a key version your chat doesn't
hold yet, for `encryptReply` to quote it, but the reply doesn't carry those
key changes.

### A prepared change's JSON leaves out its key

`JSON.stringify` of a `PreparedConversationChange` leaves out its
`conversationKey`, where 0.5.x serialized it. The key stays on the object,
and keys, spreads and copies still carry it. Code that saved or queued a
prepared change as JSON loses the key, and with it the conversation: store
the key yourself, and serialize the rest:

```js
// 0.5.x
const saved = JSON.stringify(prepared);

// 0.7.2
storeConversationKey(prepared.conversationId, prepared.conversationKeyVersion, prepared.conversationKey);
const saved = JSON.stringify(prepared);
```

The request bodies take only a change's participant keys, key version and
action signatures, never the key itself.

### `sign` refuses data only the SDK signs

`sign` throws a `ChatXdkError` of kind `invalidInput` for a payload
recipients would verify as a signed event (a message, conversation-key
change, group or conversation-metadata change, delete or read receipt) and
for a P-256 public key, whose signature by the signing key binds it as an
identity key. Sign only your own application data with `sign`; the SDK
signs events itself. Any other data signs as in 0.5.x:

```js
// 0.7.2
function signOwnData(data) {
  try {
    return chat.sign(data);
  } catch (err) {
    // The data reads as an event or a public key, which only the SDK signs.
    if (err instanceof ChatXdkError && err.kind === "invalidInput") return null;
    throw err;
  }
}
```

### Decrypt drops a removal's title and description re-encryptions

A member removal rotates the conversation key and re-encrypts the group's
title and description under the new key, marked as key-rotation
re-encryptions. They are the same text, not changes, so `decryptEvents`
and `decryptEvent` drop them under either `setRejectUnverified` setting,
the way they drop an unverified event: `decryptEvents` leaves each one out
of `events` and records it in `errors`, and `decryptEvent` throws a
`ChatXdkError` of kind `invalidInput`: `GroupChange re-encrypts the group's
title for a key rotation (for_key_rotation), not a title change: decrypt
does not return it`. The removal itself (`membersRemoved`), its key change,
avatar changes and every title or description change without the mark
decrypt as before. In 0.5.x, a removal by an X client arrived as a
`titleChanged` carrying the group's unchanged title:

```js
// 0.5.x
for (const { event } of result.messages) {
  if (event.change?.changeType === "titleChanged") {
    showTitle(chat.decrypt(event.change.newTitle, keys[conversationKeyVersion]));
  }
}

// 0.7.2
const result = chat.decryptEvents({ events });
for (const { event } of result.events) {
  if (event.change?.changeType === "titleChanged") {
    const newTitle = event.change.newTitle;
    showTitle(newTitle.kind === "text" ? newTitle.text : newTitle.raw);
  }
}
```

A loop over single events catches the error, as it catches an unverified
event's, and moves on to the next event:

```js
// 0.7.2
for (const item of page.data) {
  let event;
  try {
    event = chat.decryptEvent({ eventB64: item.encoded_event, conversationKeys: keys });
  } catch (err) {
    logSkipped(item.encoded_event, err);
    continue;
  }
  handle(event);
}
```

### `exportKeys` throws without keys

`exportKeys` throws a `ChatXdkError` of kind `invalidState` when no identity
key is loaded:

```js
// 0.7.2
const privateKeys = chat.hasIdentityKey() ? chat.exportKeys() : null;
```

### An empty Juicebox config fails

Until a chat has a Juicebox config, `setup`, `unlock`, `changePin` and
`delete` throw a `ChatXdkError` of kind `invalidState`, `Invalid state: no
Juicebox config: pass the juicebox_config the X API returns when you create
the chat, or call update_config() first`, the error every binding gives, and
`createChat` and `updateConfig` throw it for an empty or blank
`juiceboxConfig`, at once, rather than at the first Juicebox call.

## 4. Group and receipt signing

Recipients on the default `setRejectUnverified` policy drop a read receipt
or group change that isn't signed, as 0.5.x recipients did: sign each one,
or recipients never see it. The sender comes from `setIdentity`. Each
prepare call returns `actionSignatures` shaped as [Action signatures come
nested](#action-signatures-come-nested) shows; send them in the request
through `toSnake`.

### The requests

Each request below takes the conversation id in its path as `pathId`, and
the prepare call's `actionSignatures`, through `toSnake`, as
`action_signatures`. The paths and body fields are the X API's, as its
OpenAPI description (`https://api.x.com/2/openapi.json`) gives them.

| Action | Call | Request | Body |
|---|---|---|---|
| Send a message, reply, reaction or edit | `encryptMessage`, `encryptReply`, `encryptAddReaction`, `encryptRemoveReaction`, `encryptEdit` | `POST /2/chat/conversations/{id}/messages` | `message_id`, `encoded_message_create_event`, `encoded_message_event_signature`, `xdk_version`: the payload's `messageId`, `encodedMessageCreateEvent`, `encodedMessageEventSignature` and `xdkVersion` |
| Delete messages | `prepareMessageDelete` | `POST /2/chat/conversations/{id}/messages/delete` | `sequence_ids`; `delete_message_action`, `"delete_for_all"` or `"delete_for_self"` as the params' `deleteForAll` says; `action_signatures` |
| Mark read | `prepareMarkConversationRead` | `POST /2/chat/conversations/{id}/read` | `action_signatures` |
| Start a one-to-one or rotate its key | `prepareConversationKeyChange` | `POST /2/chat/conversations/{id}/keys` | `conversation_key_version`, `conversation_participant_keys`, `action_signatures` |
| Create a group | `prepareGroupCreate` | `POST /2/chat/conversations/group` | `conversation_id`, `group_members`, `group_admins`, `group_name` (the result's `encryptedTitle`), `conversation_key_version`, `conversation_participant_keys`, `action_signatures` |
| Add members | `prepareGroupMembersChange` | `POST /2/chat/conversations/{id}/members` | `user_ids`, `encrypted_title`, `conversation_key_version`, `conversation_participant_keys`, `action_signatures` |
| Remove members | `prepareGroupMembersRemove` | `POST /2/chat/conversations/{id}/members/remove` | `user_ids`, `action_signatures`, `group_key_rotation_data` with `conversation_key_version` and `conversation_participant_keys` |
| Leave | `prepareGroupLeave` | `POST /2/chat/conversations/{id}/members/remove` | `user_ids` (your own id), `action_signatures` |
| Change the title | `prepareGroupTitleChange` | `PUT /2/chat/conversations/{id}` | `group_name` (the result's `encryptedValue`), `conversation_key_version`, `modified_fields: ["group_name"]`, `action_signatures` |
| Change the description | `prepareGroupDescriptionChange` | `PUT /2/chat/conversations/{id}` | `group_description` (the result's `encryptedValue`), `conversation_key_version`, `modified_fields: ["group_description"]`, `action_signatures` |
| Change the avatar | `prepareGroupAvatarChange` | `PUT /2/chat/conversations/{id}` | `group_avatar_url` (the media URL), `conversation_key_version`, `modified_fields: ["group_avatar_url"]`, `action_signatures` |
| Add admins | `prepareGroupAdminsAdd` | `POST /2/chat/conversations/{id}/admins` | `user_ids`, `action_signatures` |
| Remove admins | `prepareGroupAdminsRemove` | `POST /2/chat/conversations/{id}/admins/remove` | `user_ids`, `action_signatures` |
| Turn the invite link on | `prepareGroupInviteEnable` | `POST /2/chat/conversations/{id}/invite` | `invite_url`; `validity_expiry_timestamp_msec` (the params' `expiresAtMsec`) and `affiliate_user_id` (the params' `affiliateId`) when set; `action_signatures` |
| Turn the invite link off | `prepareGroupInviteDisable` | `DELETE /2/chat/conversations/{id}/invite` | `action_signatures` |
| Ask to join | `prepareGroupJoinRequest` | `POST /2/chat/conversations/{id}/join_requests` | `token` (the invite link's last 10 characters), `action_signatures` |
| Reject join requests | `prepareGroupJoinReject` | `POST /2/chat/conversations/{id}/join_requests/reject` | `user_ids`, `action_signatures` |
| Set the message TTL | `prepareMessageTtlChange` | `PUT /2/chat/conversations/{id}/message_ttl` | `message_ttl_ms` (the params' `ttlMsec`, as a string), `action_signatures` |
| Clear the message TTL | `prepareMessageTtlRemove` | `DELETE /2/chat/conversations/{id}/message_ttl` | `action_signatures` |
| Change screen capture | `prepareScreenCapture` | `PUT /2/chat/conversations/{id}/screen_capture` | `blocking` (`true` for `"blockingEnabled"`, `false` for `"blockingDisabled"`) and `blocking_action_signatures`, or `detection` and `detection_action_signatures` |

A group's `conversation_id` is the `g…` id that
`POST /2/chat/conversations/group/initialize` returns as
`data.conversation_id`.

### Deleting messages

`prepareMessageDelete` returns the action's signature nested, as every
prepare call does: send its `actionSignatures` through `toSnake`, next to
the sequence ids and the delete action the params signed.

```js
// 0.5.x
const deletion = chat.prepareMessageDelete({ conversationId, sequenceIds, deleteForAll: true });
await api.post(`/2/chat/conversations/${pathId}/messages/delete`, {
  sequence_ids: sequenceIds,
  delete_message_action: "delete_for_all",
  action_signatures: [{
    message_id: deletion.messageId,
    encoded_message_event_detail: deletion.encodedMessageEventDetail,
    message_event_signature: {
      signature: deletion.signature,
      signature_version: deletion.signatureVersion,
      public_key_version: deletion.publicKeyVersion,
      signing_public_key: signingPublicKey,
    },
  }],
});

// 0.7.2
const deletion = chat.prepareMessageDelete({ conversationId, sequenceIds, deleteForAll: true });
await api.post(`/2/chat/conversations/${pathId}/messages/delete`, {
  sequence_ids: sequenceIds,
  delete_message_action: "delete_for_all",
  action_signatures: toSnake(deletion.actionSignatures),
});
```

A recipient's `decryptEvent` returns the delete as a verified
`messageDeleted` event with its `sequenceIds` and `deleteForAll`.

### Read receipts are signed

Sign a read receipt with `prepareMarkConversationRead` and send the
`PreparedAction`'s `actionSignatures` as the `action_signatures` of
`POST /2/chat/conversations/{id}/read`. It takes `{ conversationId,
seenUntilSequenceId }` (the sequence id of the newest event read) and a
`seenAtMsec` that defaults to now, and returns a `PreparedAction`, one
entry. Without it the X API sends an unsigned receipt, which recipients
drop.

```js
// 0.5.x
await api.post(`/2/chat/conversations/${pathId}/read`, {});

// 0.7.2
const receipt = chat.prepareMarkConversationRead({ conversationId, seenUntilSequenceId });
await api.post(`/2/chat/conversations/${pathId}/read`, {
  action_signatures: toSnake(receipt.actionSignatures),
});
```

A recipient's `decryptEvent` returns a signed receipt as a verified
`readReceipt` event, its position in `seenUntilSequenceId`.

### Group changes are signed

Every group change below returns `actionSignatures` for its request in
[The requests](#the-requests). A group's title and description travel
encrypted under the conversation key, and the SDK encrypts them: the
creates, member adds, removals and title and description changes take them
as plaintext and return the encrypted values to send. An avatar is an image
the app encrypts with `encryptFileWithKey` and uploads; its URL is signed as
is.

### Creating a group

`prepareGroupCreate` encrypts the group's title under the conversation key
it creates, so pass it as plaintext. The result is a
`PreparedConversationChange` that also carries it encrypted, as
`encryptedTitle` (absent when unset): send that as the create request's
`group_name`, next to its participant keys and signatures. The create signs
the encrypted value, which is base64, so a title may contain a comma; a
value signed as is, such as an avatar URL, can't. A create sets no avatar:
set one afterwards with an [avatar change](#changing-the-avatar), with the
image encrypted under the key the create returns.

```js
// 0.5.x
const prepared = chat.prepareGroupCreate({ publicKeys, conversationId, memberIds, adminIds, title, avatarUrl });
const body = { group_name: title, group_avatar_url: avatarUrl };

// 0.7.2
const prepared = chat.prepareGroupCreate({ publicKeys, conversationId, memberIds, adminIds, title });
await api.post("/2/chat/conversations/group", {
  conversation_id: conversationId,
  group_members: memberIds,
  group_admins: adminIds,
  group_name: prepared.encryptedTitle,
  conversation_key_version: prepared.conversationKeyVersion,
  conversation_participant_keys: toSnake(prepared.conversationParticipantKeys),
  action_signatures: toSnake(prepared.actionSignatures),
});
storeConversationKey(conversationId, prepared.conversationKeyVersion, prepared.conversationKey);
```

`decryptEvent` returns a received group create with its title decrypted with
the key for the version the create names, from the call's key map or the key
cache: a `created` change's `title` is a `GroupText`, a type the package
exports. `{ kind: 'text', text }` holds the title.
`{ kind: 'unavailable', raw }` holds the value as the create carries it,
when that key isn't there or the value doesn't decrypt under it, and the
rest of the create still decrypts. 0.5.x signed a create's title as the app
passed it, so a 0.5.x app's create with a plaintext title arrives as
`unavailable` with the title in `raw`: show `raw` when a title isn't
decryptable. A create that names no key version carries its title as
plaintext, and arrives as `text`. The encrypted `group_name` and
`group_description` the X API returns with a conversation open with
`decrypt`.

```js
// 0.5.x
if (groupChange.change.changeType === 'created' && groupChange.change.title) {
  showTitle(chat.decrypt(groupChange.change.title, keys[conversationKeyVersion]));
}

// 0.7.2
const change = groupChange.change;
if (change.changeType === 'created' && change.title) {
  showTitle(change.title.kind === 'text' ? change.title.text : change.title.raw);
}
```

A `created` change also carries the create's `conversationKeyVersion`, and
the `avatarUrl` a create from another client may set: a media URL whose
image is encrypted under that key version, which `decryptFileWithKey` opens
with that version's key.

### Adding members

`prepareGroupMembersChange` rotates the conversation key, so it re-encrypts
the group's title and description under the key it generates: pass them as
plaintext, as `currentTitle` and `currentDescription`, not as values your
code encrypted. The result carries them encrypted, as `encryptedTitle` and
`encryptedDescription` (absent when unset). Send `encryptedTitle` as the
add-members request's `encrypted_title`; the description travels in the
signed member add. Encrypt under the new key from here on, as [Removing
members](#removing-members) shows for a removal.

```js
// 0.5.x
const prepared = chat.prepareGroupMembersChange({
  publicKeys, conversationId, newMemberIds,
  currentMemberIds: memberIds, currentAdminIds: adminIds, currentPendingMemberIds: [],
  currentTitle: title,
});

// 0.7.2
const prepared = chat.prepareGroupMembersChange({
  publicKeys, conversationId, newMemberIds,
  currentMemberIds: memberIds, currentAdminIds: adminIds, currentPendingMemberIds: [],
  currentTitle: title, currentDescription: description,
});
await api.post(`/2/chat/conversations/${pathId}/members`, {
  user_ids: newMemberIds,
  encrypted_title: prepared.encryptedTitle,
  conversation_key_version: prepared.conversationKeyVersion,
  conversation_participant_keys: toSnake(prepared.conversationParticipantKeys),
  action_signatures: toSnake(prepared.actionSignatures),
});
storeConversationKey(conversationId, prepared.conversationKeyVersion, prepared.conversationKey);
```

While the chat sends v0, passing a description makes the add sign at
signature version 8, the first version whose member-add payload covers one,
and 0.5.x readers can't verify a version-8 add. Until every app that reads
your groups runs 0.7.2, leave the description out, so the add signs at
version 7 as in 0.5.x; the new members can read the description once a
description change sets it under the new key. While the chat sends v1, the
add signs at version 10, with a description or without.

The add doesn't re-encrypt the avatar: `currentAvatarUrl` takes its media
URL, signed as is, and the image stays encrypted under the key it was
uploaded with, which the new members never receive. X clients re-encrypt the
avatar on every key rotation: encrypt the image under the key the add
returns with `encryptFileWithKey`, upload it, and send an [avatar
change](#changing-the-avatar) naming the new key version.

A recipient's `decryptEvent` returns the add as a verified `membersAdded`
change with `memberIds`, `currentMemberIds` and `currentAdminIds`.

### Removing members

`prepareGroupMembersRemove` removes `userIds` and rotates the conversation
key, so the members removed don't receive the key the group encrypts under
next. It takes:

- `publicKeys`: the identity key of every member who stays, yours included,
  as `GET /2/users/{id}/public_keys` returns them. The SDK encrypts the new
  key to each member's newest key version; a member left out, you included,
  can't read what the group sends under the new key. The SDK doesn't check
  that the list is complete. A key for a member being removed throws.
- `conversationId` and `userIds`, the members to remove.
- `title` and `description`: the group's current title and description, as
  plaintext. Pass each one the group has; the call encrypts each under the
  new key and signs it as a key-rotation re-encryption, which recipients'
  decrypt drops rather than shows as a change. The avatar is an image you
  encrypt, so the call doesn't re-encrypt it: X clients re-encrypt the
  avatar on every key rotation, so once the removal succeeds, encrypt the
  image under the new key with `encryptFileWithKey`, upload it, and send an
  [avatar change](#changing-the-avatar) naming the new key version.

The result is a `PreparedConversationChange`: the new `conversationKey` and
`conversationKeyVersion`, `conversationParticipantKeys` for the members who
stay, and `actionSignatures` in request order: the removal, a title change
and a description change for the ones passed, then the conversation-key
change. Each signs at signature version 7 while the chat sends v0, as 0.5.x
readers verify, and at version 10 while it sends v1 (see [Upgrade readers
first](#upgrade-readers-first)).

```js
// 0.5.x
await api.post(`/2/chat/conversations/${pathId}/members/remove`, { user_ids: userIds });

// 0.7.2
const prepared = chat.prepareGroupMembersRemove({
  publicKeys: remainingPublicKeys,
  conversationId,
  userIds,
  title,
  description,
});
await api.post(`/2/chat/conversations/${pathId}/members/remove`, {
  user_ids: userIds,
  action_signatures: toSnake(prepared.actionSignatures),
  group_key_rotation_data: {
    conversation_key_version: prepared.conversationKeyVersion,
    conversation_participant_keys: toSnake(prepared.conversationParticipantKeys),
  },
});
```

**Encrypt under the new key as soon as the request succeeds.** The removed
members hold the old key, so a message encrypted under it is one they can
read. The key cache (`setCacheKeys(true)`) adopts the new key only once
`decryptEvents` decrypts the removal's key change from the conversation's
events, and only if that key change verifies against your own signing key;
until then an encrypt call that omits the key resolves the old one. Store
the new key and version, and pass them to every encrypt and prepare call
until the cache holds them:

```js
// 0.7.2
storeConversationKey(conversationId, prepared.conversationKeyVersion, prepared.conversationKey);
const payload = chat.encryptMessage({
  conversationId,
  text: "hello",
  conversationKey: prepared.conversationKey,
  conversationKeyVersion: prepared.conversationKeyVersion,
});
```

The same holds after any call that rotates the key:
`prepareConversationKeyChange`, `prepareGroupCreate` and
`prepareGroupMembersChange`.

On the receiving side, `decryptEvents` returns the removal as a verified
`membersRemoved` change with its `memberIds`, and the key change as a
`keyChange` event that adds the new key to `conversationKeys` and moves
`latestVersion` to it once it verifies. The title and description
re-encryptions are in `errors`, not `events` (see [Decrypt drops a
removal's title and description
re-encryptions](#decrypt-drops-a-removals-title-and-description-re-encryptions)):

```js
// 0.7.2
const result = chat.decryptEvents({ events });
for (const { event } of result.events) {
  if (event.type === "groupChange" && event.change.changeType === "membersRemoved") {
    const removed = event.change.memberIds;
  }
}
const version = result.conversationKeys.latestVersion;
```

### Leaving a group

`prepareGroupLeave` signs the sender's removal and does not rotate the
conversation key. `actionSignatures` are the removal, then a
`GroupAdminAddChange` when `promoteAdminId` is set, then a
`ConversationDeleteEvent`, each at signature version 7, or 10 while the chat
sends v1. It returns a `PreparedAction`. Send it as a removal of your own
id:

```js
// 0.5.x
await api.post(`/2/chat/conversations/${pathId}/members/remove`, { user_ids: [myUserId] });

// 0.7.2
const left = chat.prepareGroupLeave({ conversationId, promoteAdminId });
await api.post(`/2/chat/conversations/${pathId}/members/remove`, {
  user_ids: [myUserId],
  action_signatures: toSnake(left.actionSignatures),
});
```

### Changing the title

`prepareGroupTitleChange` takes the new title as plaintext, encrypts it
under the conversation key and signs it. Like `encryptMessage`, it takes
the key and its version as `conversationKey` and `conversationKeyVersion`,
or resolves both from the key cache without them. The result is a
`PreparedGroupMetadataChange`: the `encryptedValue` the request sends as
`group_name`, the `conversationKeyVersion` it's encrypted under, and the
`actionSignatures` to send with it.

```js
// 0.5.x
await api.put(`/2/chat/conversations/${pathId}`, {
  group_name: chat.encrypt(title, keys[conversationKeyVersion]),
  conversation_key_version: conversationKeyVersion,
  modified_fields: ["group_name"],
});

// 0.7.2
const prepared = chat.prepareGroupTitleChange({ conversationId, newTitle: title });
await api.put(`/2/chat/conversations/${pathId}`, {
  group_name: prepared.encryptedValue,
  conversation_key_version: prepared.conversationKeyVersion,
  modified_fields: ["group_name"],
  action_signatures: toSnake(prepared.actionSignatures),
});
```

`decryptEvent` returns a received title change decrypted: the `newTitle` of
a `titleChanged` change is a `GroupText`, as a create's `title` is. It
decrypts with the key for the version the change names, from the call's key
map or the key cache. Without that key, or when the value isn't ciphertext
under it, as for a plaintext title an app signed with a key version, it is
`unavailable` with the value as carried, and the event still decrypts. A
removal's re-encrypted title never arrives as a `titleChanged`. A change
that removes the title decrypts to an empty title.

```js
// 0.5.x
if (groupChange.change.changeType === 'titleChanged') {
  showTitle(chat.decrypt(groupChange.change.newTitle, keys[conversationKeyVersion]));
}

// 0.7.2
const { changeType, newTitle } = groupChange.change;
if (changeType === 'titleChanged') {
  showTitle(newTitle.kind === 'text' ? newTitle.text : newTitle.raw);
}
```

### Changing the description

`prepareGroupDescriptionChange` takes the new description as plaintext and
returns a `PreparedGroupMetadataChange`, as the title change does; the
request sends its `encryptedValue` as `group_description`.

```js
// 0.5.x
await api.put(`/2/chat/conversations/${pathId}`, {
  group_description: chat.encrypt(description, keys[conversationKeyVersion]),
  conversation_key_version: conversationKeyVersion,
  modified_fields: ["group_description"],
});

// 0.7.2
const prepared = chat.prepareGroupDescriptionChange({ conversationId, newDescription: description });
await api.put(`/2/chat/conversations/${pathId}`, {
  group_description: prepared.encryptedValue,
  conversation_key_version: prepared.conversationKeyVersion,
  modified_fields: ["group_description"],
  action_signatures: toSnake(prepared.actionSignatures),
});
```

A received description change is a `descriptionChanged` change holding
`newDescription` as a `GroupText`; read it as a title change's `newTitle`. A
change that removes the description decrypts to an empty description. A
removal's re-encrypted description never arrives as one:

```js
// 0.7.2
const { changeType, newDescription } = groupChange.change;
if (changeType === 'descriptionChanged') {
  showDescription(newDescription.kind === 'text' ? newDescription.text : newDescription.raw);
}
```

### Changing the avatar

An avatar URL is not encrypted; the image is. Encrypt the image bytes under
the conversation key with `encryptFileWithKey`, as X clients do, upload them
to the group's media, and pass the image's media URL to
`prepareGroupAvatarChange`, with the version of the key the image is
encrypted under. The call signs both as they are and returns a
`PreparedAction`; send its `actionSignatures` with the URL. A URL containing
a comma is rejected, since signatures join their fields with commas. Send an
avatar change after every key rotation too, with the image encrypted under
the new key, as X clients do.

```js
// 0.5.x
const encrypted = chat.encryptStream(photo, keys[conversationKeyVersion]);
await api.put(`/2/chat/conversations/${pathId}`, {
  group_avatar_url: chat.encrypt(avatarUrl, keys[conversationKeyVersion]),
  conversation_key_version: conversationKeyVersion,
  modified_fields: ["group_avatar_url"],
});

// 0.7.2
const encrypted = chat.encryptFileWithKey({ file: photo, key: keys[conversationKeyVersion] });
const prepared = chat.prepareGroupAvatarChange({
  conversationId,
  newAvatarUrl: avatarUrl,
  conversationKeyVersion,
});
await api.put(`/2/chat/conversations/${pathId}`, {
  group_avatar_url: avatarUrl,
  conversation_key_version: conversationKeyVersion,
  modified_fields: ["group_avatar_url"],
  action_signatures: toSnake(prepared.actionSignatures),
});
```

In both, `avatarUrl` is the media URL of the uploaded `encrypted` image. A
received `avatarChanged` change holds `newAvatarUrl` as sent and its
`conversationKeyVersion`: download the image and decrypt it with
`decryptFileWithKey` under the key for that version. A change that removes
the avatar holds an empty `newAvatarUrl`.

```js
// 0.7.2
const change = groupChange.change;
if (change.changeType === 'avatarChanged' && change.conversationKeyVersion) {
  const image = chat.decryptFileWithKey({ encrypted: downloaded, key: keys[change.conversationKeyVersion] });
  showAvatar(image);
}
```

### Admins, invites, join requests, message TTL and screen capture

Each of these calls returns a `PreparedAction` with one signature, at
signature version 7, or 10 while the chat sends v1, for the request [The
requests](#the-requests) names. 0.5.x apps sent these requests without
signatures; recipients drop them unsigned. A recipient's `decryptEvent`
returns admin, invite and join changes as verified `groupChange` events
(`adminsAdded`, `adminsRemoved`, `inviteEnabled`, `inviteDisabled`,
`joinRequested`, `joinRejected`) and TTL and screen-capture changes as
verified `settingsChange` events.

```js
// 0.5.x
await api.post(`/2/chat/conversations/${pathId}/admins`, { user_ids: userIds });

// 0.7.2
const added = chat.prepareGroupAdminsAdd({ conversationId, userIds });
await api.post(`/2/chat/conversations/${pathId}/admins`, {
  user_ids: userIds, action_signatures: toSnake(added.actionSignatures),
});
const removed = chat.prepareGroupAdminsRemove({ conversationId, userIds });
await api.post(`/2/chat/conversations/${pathId}/admins/remove`, {
  user_ids: userIds, action_signatures: toSnake(removed.actionSignatures),
});
```

An invite signs its URL, its expiry and its affiliate; an omitted
`expiresAtMsec` or `affiliateId` signs `null`. The request sends the expiry
as `validity_expiry_timestamp_msec`, and only with the same value the params
signed:

```js
// 0.7.2
const invite = chat.prepareGroupInviteEnable({ conversationId, inviteUrl, expiresAtMsec });
await api.post(`/2/chat/conversations/${pathId}/invite`, {
  invite_url: inviteUrl,
  validity_expiry_timestamp_msec: String(expiresAtMsec),
  action_signatures: toSnake(invite.actionSignatures),
});
const disabled = chat.prepareGroupInviteDisable({ conversationId });
await api.delete(`/2/chat/conversations/${pathId}/invite`, {
  action_signatures: toSnake(disabled.actionSignatures),
});
```

A join request signs the requesting user, who defaults to the sender; the
invite token travels in the request but not in the signature:

```js
// 0.7.2
const request = chat.prepareGroupJoinRequest({ conversationId });
await api.post(`/2/chat/conversations/${pathId}/join_requests`, {
  token: inviteToken, action_signatures: toSnake(request.actionSignatures),
});
const rejected = chat.prepareGroupJoinReject({ conversationId, userIds });
await api.post(`/2/chat/conversations/${pathId}/join_requests/reject`, {
  user_ids: userIds, action_signatures: toSnake(rejected.actionSignatures),
});
```

A TTL change signs `ttlMsec` only; a negative one is rejected:

```js
// 0.7.2
const ttl = chat.prepareMessageTtlChange({ conversationId, ttlMsec });
await api.put(`/2/chat/conversations/${pathId}/message_ttl`, {
  message_ttl_ms: String(ttlMsec), action_signatures: toSnake(ttl.actionSignatures),
});
const cleared = chat.prepareMessageTtlRemove({ conversationId });
await api.delete(`/2/chat/conversations/${pathId}/message_ttl`, {
  action_signatures: toSnake(cleared.actionSignatures),
});
```

A screen-capture change is one of `"blockingEnabled"`,
`"blockingDisabled"`, `"detectionEnabled"` or `"detectionDisabled"`. The
request names its signatures after the setting,
`blocking_action_signatures` or `detection_action_signatures`, not
`action_signatures`:

```js
// 0.7.2
const capture = chat.prepareScreenCapture({ conversationId, change: "blockingEnabled" });
await api.put(`/2/chat/conversations/${pathId}/screen_capture`, {
  blocking: true, blocking_action_signatures: toSnake(capture.actionSignatures),
});
```

## 5. Verify

### Type-check

Run `tsc --noEmit` over a TypeScript app: the typings flag every call that
still passes 0.5.x arguments and every renamed field. Then run your tests.

### Find the 0.5.x names

Search the app for the names in the symbol index's 0.5.x column. Each hit is
a line to change, unless it is your own code that shares the name:

```sh
grep -rnE "encryptStream|decryptStream|stream(En|De)cryptor|Stream(En|De)cryptor|encryptedStreamSize|guessesRemaining\(|maxGuessCount|\.encrypt\(|encryptedContent|encodedEventSignature|generateVersion|newText|messageIds|seenUntilId\b|\.messages\b|\bparticipantKeys\b|\bencryptedKey\b|\bkeyVersion\b|DecryptedMessage|EncryptedKeyForRecipient|\bParticipantKey\b|ChatCrypto|import type \{[^}]*\bChat\b" --include='*.js' --include='*.mjs' --include='*.ts' --include='*.tsx' .
grep -rn "targetMessageId" --include='*.js' --include='*.mjs' --include='*.ts' --include='*.tsx' .
```

Every `targetMessageId` the second search finds should read a v1 edit's
signed message id or set it on an edit you build; rename the rest to
`targetMessageSequenceId`. Each `encryptStream` and `decryptStream` the
first finds is a message's file or a file under a key you hold, and [Encrypt
a file under a key you hold](#encrypt-a-file-under-a-key-you-hold) says
which call each moves to. Check every request body too: each object the
package returns goes through `toSnake`.

### Run a round trip

This round trip runs offline, with two chats standing in for two users. It
registers both, starts a conversation, sends a message and decrypts it with
`setRejectUnverified` on, the default, so the signature has to verify:

```js
// 0.7.2
const alice = await createChat();
const bob = await createChat();
const aliceKeys = alice.generateKeypairs().publicKey;
const bobKeys = bob.generateKeypairs().publicKey;
alice.setIdentity({ userId: "1001", signingKeyVersion: "1" });
bob.setIdentity({ userId: "1002", signingKeyVersion: "1" });

const change = alice.prepareConversationKeyChange({
  publicKeys: [
    { userId: "1001", identityPublicKey: aliceKeys.publicKey, publicKeyVersion: "1" },
    { userId: "1002", identityPublicKey: bobKeys.publicKey, publicKeyVersion: "1" },
  ],
});
const payload = alice.encryptMessage({
  conversationId: change.conversationId,
  text: "hello",
  conversationKey: change.conversationKey,
  conversationKeyVersion: change.conversationKeyVersion,
});

const bobEntry = change.conversationParticipantKeys.find((key) => key.userId === "1002");
if (!bobEntry) throw new Error("no key for bob");
const bobKey = bob.decryptConversationKey(bobEntry.encryptedConversationKey);
const event = bob.decryptEvent({
  eventB64: payload.eventB64,
  conversationKeys: { [change.conversationKeyVersion]: bobKey },
  signingKeys: [{
    userId: "1001",
    publicKeyVersion: "1",
    publicKey: aliceKeys.signingPublicKey,
    identityPublicKey: aliceKeys.publicKey,
    identityPublicKeySignature: aliceKeys.identityPublicKeySignature,
  }],
});
if (!event.verified || event.content?.text !== "hello") throw new Error("round trip failed");
if (!["7", "10"].includes(payload.signatureInfo.signatureVersion)) throw new Error("unknown format");
if (!payload.xdkVersion.startsWith("0.7.")) throw new Error(`xdkVersion ${payload.xdkVersion}`);
```

`signatureVersion` is `"7"` for a v0 send and `"10"` for v1, as the
`v1_send` switch decides. `xdkVersion` is the version of the package that
built the send, a 0.7 release, which the X API receives with each send.

Then run the same flows against a test conversation on the X API: send a
text, a file, a reply, an edit and a delete, mark the conversation read,
and create a group, set its avatar, add a member and remove one. Fetch the
conversation's events with `GET /2/chat/conversations/{id}/events`, pass
`data[].encoded_event` and `meta.conversation_key_events` to
`decryptEvents` with every participant's signing keys, and check that every
event in `events` has `verified` set and that `errors` holds only the
removal's title and description re-encryptions.
