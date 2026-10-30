# Migrating JVM code to chat-xdk 0.7.2

This page moves Java and other JVM code written for `com.x:chatxdk` 0.5.x
(0.5.0, 0.5.1 or 0.5.2) to 0.7.2. Work through it top to bottom: [Before
you start](#0-before-you-start) sets up the upgrade, the [symbol
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
- [ ] `[rollout]` [Remove a native library you built for 0.5.x](#the-jar-bundles-the-linux-arm64-native-library)
- [ ] `[rollout]` [Upgrade every app that reads your conversations first](#upgrade-readers-first)
- [ ] `[rollout]` [Allow or block the feature-switch request](#the-feature-switch-request)
- [ ] `[compile]` [Pass the Juicebox config to `new Chat(config)`, and PINs as `byte[]`](#keys-stored-in-juicebox)
- [ ] `[compile]` [Register keys with the public key only](#register-keys-with-the-public-key-only)
- [ ] `[compile]` [Pass a `SetIdentityParams` to `setIdentity`](#setidentity-takes-setidentityparams)
- [ ] `[compile]` [Pass an `ImportKeysParams` to `importKeys`](#importkeys-takes-importkeysparams)
- [ ] `[compile]` [Pass a `DecryptEventsParams` to `decryptEvents` and read its `events`](#decryptevents-takes-decrypteventsparams)
- [ ] `[compile]` [Pass a `DecryptEventParams` to `decryptEvent`](#decryptevent-takes-decrypteventparams)
- [ ] `[compile]` [Read `SendPayload` under the send request's field names and send `xdk_version`](#sendpayload-fields-take-the-send-requests-names)
- [ ] `[compile]` [Build descriptors and key entries with their constructors](#descriptors-and-key-entries-take-their-values-in-constructors)
- [ ] `[compile]` [Build a message before you encrypt its files](#encrypt-a-file-from-its-message)
- [ ] `[compile]` [Decrypt a file with the event of its message](#decrypt-a-file-with-its-messages-event)
- [ ] `[compile]` [Encrypt a file no message carries, such as a group avatar, with `encryptFileWithKey`](#encrypt-a-file-under-a-key-you-hold)
- [ ] `[compile]` [Use `fileEncryptor` and `fileDecryptor` for large files](#encrypt-and-decrypt-large-files-in-chunks)
- [ ] `[compile]` [Pass action signatures through as returned](#action-signatures-come-nested)
- [ ] `[compile]` [Pass a `PublicKeyInput` the identity key and its version](#public-key-inputs-name-the-identity-key-and-its-version)
- [ ] `[compile]` [Pass participant keys through as returned](#participant-keys-take-the-key-requests-names)
- [ ] `[compile]` [Read received participant keys under the same names](#received-participant-keys-take-the-same-names)
- [ ] `[compile]` [Read a delete's signature from its `PreparedAction`](#deletes-return-a-preparedaction)
- [ ] `[compile]` [Read decrypted events under the names the calls take](#decrypted-events-use-the-names-the-calls-take)
- [ ] `[compile]` [Tell exceptions apart by `getKind()`](#errors-carry-their-kind)
- [ ] `[compile]` [Know which calls throw `ChatXdkException`](#exceptions)
- [ ] `[compile]` [If you call `ChatNative` directly, follow the C ABI changes](#chatnative)
- [ ] `[runtime]` [Serialize request bodies with Jackson](#serialize-request-bodies-with-jackson)
- [ ] `[runtime]` [Pass user ids as strings of digits](#user-ids-are-strings-of-digits)
- [ ] `[runtime]` [Pass key versions as the X API returns them](#key-versions-are-integers-written-as-strings)
- [ ] `[runtime]` [Pass entities, files, URL cards and posts the SDK accepts](#entities-files-url-cards-and-posts-are-checked)
- [ ] `[runtime]` [Store every participant's signing keys, and handle a `null` `latestVersion`](#latestversion-comes-from-a-verified-key-change)
- [ ] `[runtime]` [Rename every read of `target_message_id` to `target_message_sequence_id`](#target_message_id-holds-a-different-value)
- [ ] `[runtime]` [Reply with `replyToEvent`, whose preview recipients check exactly](#a-reply-preview-quotes-its-message-exactly)
- [ ] `[runtime]` [Store a prepared change's key yourself, not through Jackson](#a-prepared-changes-json-leaves-out-its-key)
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
snippet with only a `// 0.7.2` half shows code 0.7.2 adds. CI compiles the
0.7.2 half of every snippet on this page against 0.7.2 with `javac`
([`scripts/check_doc_snippets.py`](../../scripts/check_doc_snippets.py)), as
the body of a method that declares `throws Exception`.

`chat` is a `Chat` with your keys loaded, and the other names stand for
your own values: ids, versions, keys and events as the X API returns them,
`keys` for the conversation key map `decryptEvents` returns, `bundle` for a
`ConversationKeyBundle`, `payload` for a `SendPayload`, `prepared` for a
`PreparedConversationChange`, `keyChange`, `message`, `deleted`, `receipt`
and `groupChange` for a decrypted key change, message, deletion, read
receipt and group change, as `JsonNode`s, and `page` for a page of
`GET /2/chat/conversations/{id}/events`, as a `JsonNode`. `api.post(path,
body)`, `api.put(path, body)` and `api.delete(path, body)` stand for your
HTTP client: each serializes `body` with Jackson, sends it to
`https://api.x.com` + `path` with your user access token, and returns the
parsed JSON response as a `JsonNode`. `pathId` is the conversation id as a
request path takes it: a group's `g…` id as is, and a one-to-one's in its
hyphen form, `conversationId.replace(':', '-')`.
`photoAttachment(mediaHashKey)` stands for your code that builds a photo's
`AttachmentDescriptor`; `showEdit`, `showTitle`, `showDescription`,
`showAvatar` and `showGuessesLeft` for your code that displays an edit, a
group's title, description or avatar, or the PIN attempts left;
`handle(event)` for your code that handles a decrypted event;
`logSkipped(eventB64, error)` for your code that logs an event it skips; and
`storeConversationKey(conversationId, version, key)` for your code that
stores a conversation key. `pin` is the PIN's bytes, `juiceboxConfig` the
Juicebox config the X API returns, and `e` a `ChatXdkException` a call
threw. The types import from `com.x.chatxdk`, `com.x.chatxdk.Types`,
`com.fasterxml.jackson.databind`, `java.nio.charset` and `java.util`.

## 0. Before you start

### Install 0.7.2

Set the dependency to 0.7.2. With Maven:

```xml
<dependency>
  <groupId>com.x</groupId>
  <artifactId>chatxdk</artifactId>
  <version>0.7.2</version>
</dependency>
```

With Gradle, `implementation("com.x:chatxdk:0.7.2")`. It needs Java 17 or
newer. Every app that shares conversations with yours reads the formats
0.7.2 sends only once it runs a 0.7 release too, so plan the rollout below
before you deploy.

### The jar bundles the linux-arm64 native library

The jar bundles the native library for 64-bit ARM Linux (`linux-arm64`) as
well, and on ARM64 Linux loads it ahead of any copy on `jna.library.path`.
There's no code to change. If you built a library to run 0.5.x there,
remove it: a 0.5.x build doesn't export the entry points 0.7.2 calls (see
[C ABI](c-abi.md)). The native library is `chat_xdk_ffi`
(`libchat_xdk_ffi.so`, `libchat_xdk_ffi.dylib`, `chat_xdk_ffi.dll`), built
from the `chat-xdk-ffi` crate: name one you build yourself for another
platform the same way.

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
- you pass a description to [`prepareGroupMembersChange`](#adding-members).

0.7.2 reads both formats, including v1 reply previews, edits and files.
There's no code to change: to see which format a send used, read
`payload.signatureInfo.signatureVersion`, `"7"` for v0 and `"10"` for v1.

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
| `new Chat()`, then `chat.setup(pin, configJson)` and `chat.unlock(pin, configJson)` with a `String` PIN | `new Chat(configJson)`, then `chat.setup(pin)` and `chat.unlock(pin)` with a `byte[]` PIN | [Juicebox](#keys-stored-in-juicebox) |
| `chat.changePin(String, String)` | `chat.changePin(byte[], byte[])` | [Juicebox](#keys-stored-in-juicebox) |
| `registration.version`, `registration.generateVersion` | Removed: the registration request returns the version (`public_key_version`) | [Registration](#register-keys-with-the-public-key-only) |
| `PublicKeys.version` | Removed: the `public_key_version` the registration request returns | [Registration](#register-keys-with-the-public-key-only) |
| `chat.setIdentity(userId, signingKeyVersion)` | `chat.setIdentity(new SetIdentityParams(userId, signingKeyVersion))` | [setIdentity](#setidentity-takes-setidentityparams) |
| `chat.importKeys(keys)`, `chat.importKeys(keys, version)` | `chat.importKeys(new ImportKeysParams(keys))`, `new ImportKeysParams(keys, version)` | [importKeys](#importkeys-takes-importkeysparams) |
| `chat.decryptEvents(events, signingKeys)` | `chat.decryptEvents(new DecryptEventsParams(events))` with `signingKeys` set | [decryptEvents](#decryptevents-takes-decrypteventsparams) |
| `result.messages`, `DecryptedMessage` | `result.events`, `DecryptedEvent` | [decryptEvents](#decryptevents-takes-decrypteventsparams) |
| `chat.decryptEvent(eventB64, keys, signingKeys)`, `chat.decryptEvent(eventB64, bundle, signingKeys)` | `chat.decryptEvent(new DecryptEventParams(eventB64, keys))` with `signingKeys` set | [decryptEvent](#decryptevent-takes-decrypteventparams) |
| `payload.encryptedContent` | `payload.encodedMessageCreateEvent` | [SendPayload](#sendpayload-fields-take-the-send-requests-names) |
| `payload.encodedEventSignature` | `payload.encodedMessageEventSignature` | [SendPayload](#sendpayload-fields-take-the-send-requests-names) |
| `new EntityDescriptor()`, `UrlAttachmentImageDescriptor.of(..)`, `new SigningKeyEntry()`, `new PublicKeyInput()` with fields set | The constructors that take the required values | [Constructors](#descriptors-and-key-entries-take-their-values-in-constructors) |
| `chat.encryptStream(plaintext, key)`, a message's file | `chat.encryptFile(new EncryptFileParams(file, eventB64, mediaHashKey))` | [Files](#encrypt-a-file-from-its-message) |
| `chat.encryptStream(plaintext, key)`, any other file, such as a group avatar | `chat.encryptFileWithKey(new EncryptFileWithKeyParams(file, key))` | [Files under a key](#encrypt-a-file-under-a-key-you-hold) |
| `chat.decryptStream(encrypted, key)`, a message's file | `chat.decryptFile(new DecryptFileParams(encrypted, eventB64, keys, mediaHashKey))` | [Files](#decrypt-a-file-with-its-messages-event) |
| `chat.decryptStream(encrypted, key)`, any other file | `chat.decryptFileWithKey(new DecryptFileWithKeyParams(encrypted, key))` | [Files under a key](#encrypt-a-file-under-a-key-you-hold) |
| `chat.streamEncryptor(key)`, `chat.streamDecryptor(key)`, `StreamEncryptor`, `StreamDecryptor`, a message's file | `chat.fileEncryptor(new FileEncryptorParams(..))`, `chat.fileDecryptor(new FileDecryptorParams(..))`, `FileEncryptor`, `FileDecryptor` | [Large files](#encrypt-and-decrypt-large-files-in-chunks) |
| `chat.streamEncryptor(key)`, `chat.streamDecryptor(key)`, any other file | `encryptFileWithKey` and `decryptFileWithKey` over the whole file | [Large files](#encrypt-and-decrypt-large-files-in-chunks) |
| `ChatXdkUtilities.encryptedStreamSize(n)` | `ChatXdkUtilities.encryptedFileSize(n)` | [Files](#encrypt-a-file-from-its-message) |
| `chat.encrypt(plaintext, key)` | Removed: titles and descriptions go through `prepareGroupTitleChange`, `prepareGroupDescriptionChange` and the group creates and member adds; avatar URLs aren't encrypted; files go through `encryptFile` or `encryptFileWithKey` | [Changing the title](#changing-the-title) |
| `ActionSignature.signature`, `signatureVersion`, `publicKeyVersion`, `signaturePayload` | `ActionSignature.messageEventSignature`; pass `actionSignatures` as returned | [Action signatures](#action-signatures-come-nested) |
| `PublicKeyInput.publicKey`, `keyVersion` | `identityPublicKey`, `publicKeyVersion` | [Public key inputs](#public-key-inputs-name-the-identity-key-and-its-version) |
| `prepared.participantKeys`, `EncryptedKeyForRecipient`, `encryptedKey` | `prepared.conversationParticipantKeys`, `ConversationParticipantKey`, `encryptedConversationKey` | [Participant keys](#participant-keys-take-the-key-requests-names) |
| JSON `participant_keys`, `encrypted_key` of a key change | `conversation_participant_keys`, `encrypted_conversation_key` | [Received keys](#received-participant-keys-take-the-same-names) |
| `prepareMessageDelete` returning an `ActionSignature` | Returns a `PreparedAction`: `deletion.actionSignatures.get(0)` | [Deletes](#deletes-return-a-preparedaction) |
| JSON `key_version` | `conversation_key_version` | [Event names](#decrypted-events-use-the-names-the-calls-take) |
| JSON `target_message_id`, `new_text`, `message_ids`, `seen_until_id` | `target_message_sequence_id`, `updated_text`, `sequence_ids`, `seen_until_sequence_id` | [Event names](#decrypted-events-use-the-names-the-calls-take) |
| Group title and description JSON strings (`title`, `new_title`) | `Types.GroupText` | [Creating a group](#creating-a-group) |
| `GroupCreateParams.avatarUrl` | Removed: set the avatar with `prepareGroupAvatarChange` | [Creating a group](#creating-a-group) |
| `EncryptReplyParams.replyToSenderId` (a `Long`) | A `String` | [User ids](#user-ids-are-strings-of-digits) |
| `e.getMessage().startsWith("Invalid state:")` | `e.getKind() == ChatXdkException.Kind.INVALID_INPUT` | [Errors](#errors-carry-their-kind) |

## 2. Compile-time changes

These changes are in the order an app meets them: creating the chat,
registering, loading keys, decrypting, encrypting and sending, files,
prepared changes, decrypted events and errors.

### Keys stored in Juicebox

A chat that keeps its keys in Juicebox takes the Juicebox config the X API
returns when it's created, with `new Chat(juiceboxConfig)`, or later with
`updateConfig`, on first boot, before the account has one. `setup` and
`unlock` take only the PIN, as `changePin` and `delete` take no config, and
every PIN is a `byte[]`, so you can zero it once the call returns.
`setupAsync`, `unlockAsync`, `changePinAsync` and `deleteAsync` return a
`CompletableFuture` that runs the same call off the calling thread, and
`new Chat()` creates a chat that manages its keys with `importKeys` and
`exportKeys` alone:

```java
// 0.5.x
Chat chat = new Chat();
chat.unlock(new String(pin, StandardCharsets.UTF_8), juiceboxConfig);

// 0.7.2
Chat chat = new Chat(juiceboxConfig);
chat.unlockAsync(pin).join();
Arrays.fill(pin, (byte) 0);
```

Every method of a `Chat`, `updateConfig` included, is safe to call from
several threads at once; a Juicebox call already under way keeps the config
it started with. A wrong PIN throws a `ChatXdkException` of kind
`INVALID_PIN` (see [Errors carry their kind](#errors-carry-their-kind)), and
a chat without a config fails its Juicebox calls (see [An empty Juicebox
config fails](#an-empty-juicebox-config-fails)).

### Register keys with the public key only

`generateKeypairs` returns a `PublicKeyRegistrationPayload` that holds only
`publicKey`. Send it as the only field of the
`POST /2/users/{id}/public_keys` body, `public_key`. 0.7.2 doesn't pick a
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

// 0.7.2
PublicKeyRegistrationPayload registration = chat.generateKeypairs();
JsonNode response = api.post("/2/users/" + userId + "/public_keys", Map.of("public_key", registration.publicKey));
chat.setIdentity(new SetIdentityParams(userId, response.path("data").path("public_key_version").asText()));
```

`PublicKeys`, which `getPublicKeys` and `setup` return, holds the two public
keys, `identity` and `signing`, and no `version`: their version is the
`public_key_version` the registration request returns.

### `setIdentity` takes `SetIdentityParams`

Pass the user id and the signing-key version in a `SetIdentityParams`. It
throws `ChatXdkException` when either value is invalid (see
[user ids](#user-ids-are-strings-of-digits) and
[key versions](#key-versions-are-integers-written-as-strings)).

```java
// 0.5.x
chat.setIdentity(userId, signingKeyVersion);

// 0.7.2
chat.setIdentity(new SetIdentityParams(userId, signingKeyVersion));
```

### `importKeys` takes `ImportKeysParams`

Pass the saved key bytes in an `ImportKeysParams`, and optionally the
signing-key version they were registered under. Without a version, call
`setIdentity` before the first signed call. `exportKeys` keeps its 0.5.x
signature (see [`exportKeys` throws without
keys](#exportkeys-throws-without-keys) for a chat without keys).

```java
// 0.5.x
chat.importKeys(privateKeys);
chat.importKeys(privateKeys, signingKeyVersion);

// 0.7.2
chat.importKeys(new ImportKeysParams(privateKeys));
chat.importKeys(new ImportKeysParams(privateKeys, signingKeyVersion));
```

### `decryptEvents` takes `DecryptEventsParams`

Pass the events in a `DecryptEventsParams`, and the signing keys in its
`signingKeys` field. Left `null`, the keys `setSigningKeys` stored verify
the events. Per-event errors, events decrypt drops included, are still
collected in the result's `errors`, and the call throws only for invalid
params. The result holds the decrypted events, of every event type, in
`events`, each a `DecryptedEvent`:

```java
// 0.5.x
DecryptEventsResult result = chat.decryptEvents(events, signingKeys);
for (DecryptedMessage decrypted : result.messages) handle(decrypted.event);

// 0.7.2
DecryptEventsParams batch = new DecryptEventsParams(events);
batch.signingKeys = signingKeys;
DecryptEventsResult result = chat.decryptEvents(batch);
for (DecryptedEvent decrypted : result.events) handle(decrypted.event);
```

The version to encrypt with, `result.conversationKeys.latestVersion`, comes
only from a key change that verified (see [`latestVersion` comes from a
verified key change](#latestversion-comes-from-a-verified-key-change)).

### `decryptEvent` takes `DecryptEventParams`

Pass the event and the conversation key map in a `DecryptEventParams`, and
the signing keys in its `signingKeys` field. `new DecryptEventParams(eventB64)`
resolves the key from the key cache (`setCacheKeys(true)`), and `null`
signing keys verify with the keys `setSigningKeys` stored. For a
`ConversationKeyBundle`, pass its `keys`. The call still throws on failure,
and for an event decrypt drops (see [Decrypt drops a removal's title and
description re-encryptions](#decrypt-drops-a-removals-title-and-description-re-encryptions)).

```java
// 0.5.x
JsonNode event = chat.decryptEvent(eventB64, keys, signingKeys);
JsonNode fromBundle = chat.decryptEvent(eventB64, bundle, signingKeys);

// 0.7.2
DecryptEventParams one = new DecryptEventParams(eventB64, keys);
one.signingKeys = signingKeys;
JsonNode event = chat.decryptEvent(one);
DecryptEventParams fromBundleParams = new DecryptEventParams(eventB64, bundle.keys);
fromBundleParams.signingKeys = signingKeys;
JsonNode fromBundle = chat.decryptEvent(fromBundleParams);
```

### `SendPayload` fields take the send request's names

The two encoded fields carry the names of the fields of the send request,
`POST /2/chat/conversations/{id}/messages`, camelCased, so the request takes
them as they are. Read them under those names wherever your code reads a
payload, including code that stores payloads. The request also takes the
payload's `xdkVersion`, the version of the SDK that built it, as
`xdk_version`:

```java
// 0.5.x
Map<String, String> body = Map.of(
        "message_id", payload.messageId,
        "encoded_message_create_event", payload.encryptedContent,
        "encoded_message_event_signature", payload.encodedEventSignature);

// 0.7.2
Map<String, String> body = Map.of(
        "message_id", payload.messageId,
        "encoded_message_create_event", payload.encodedMessageCreateEvent,
        "encoded_message_event_signature", payload.encodedMessageEventSignature,
        "xdk_version", payload.xdkVersion);
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

### Descriptors and key entries take their values in constructors

An `EntityDescriptor`, a `UrlAttachmentImageDescriptor`, a `SigningKeyEntry`
and a `PublicKeyInput` take their required values in their constructor and
keep them in final fields; a preview image's `width` and `height` stay
settable. An `AttachmentDescriptor` comes from `media`, `urlCard` or `post`
and has final fields. None can be built without its required values, and a
`null` one throws `NullPointerException`:

```java
// 0.5.x
EntityDescriptor mention = new EntityDescriptor();
mention.start = 0;
mention.end = 5;
mention.entityType = "mention";
UrlAttachmentImageDescriptor banner = UrlAttachmentImageDescriptor.of(
        mediaHashKey, ChatXdkUtilities.encryptedStreamSize(photo.length), "banner.jpg");
banner.width = 1200L;
SigningKeyEntry signingKey = new SigningKeyEntry();
signingKey.userId = userId;
signingKey.publicKeyVersion = publicKeyVersion;
signingKey.publicKey = signingPublicKey;
signingKey.identityPublicKey = identityPublicKey;
signingKey.identityPublicKeySignature = identityPublicKeySignature;

// 0.7.2
EntityDescriptor mention = new EntityDescriptor(0, 5, "mention");
UrlAttachmentImageDescriptor banner = new UrlAttachmentImageDescriptor(
        mediaHashKey, ChatXdkUtilities.encryptedFileSize(photo.length), "banner.jpg");
banner.width = 1200L;
SigningKeyEntry signingKey = new SigningKeyEntry(
        userId, publicKeyVersion, signingPublicKey, identityPublicKey, identityPublicKeySignature);
```

### Encrypt a file from its message

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

// 0.7.2
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
`media_hashes`), or media quoted in its reply preview. The SDK finds the
file in the event and derives its key. It doesn't check the message's
signature: use `verified` from `decryptEvent` for that.

```java
// 0.5.x
byte[] plaintext = chat.decryptStream(downloaded, keys.get(conversationKeyVersion));

// 0.7.2
byte[] plaintext = chat.decryptFile(new DecryptFileParams(downloaded, fileEventB64, keys, fileHashKey));
```

### Encrypt a file under a key you hold

`encryptStream` and `decryptStream` take a key from the app for every file.
A file a message carries takes its key from the message, as the two
sections above show. A file no message carries keeps the key you hold, and
goes through `encryptFileWithKey` and `decryptFileWithKey`: a group's avatar
image, which X clients encrypt under the conversation key whose version the
avatar change signs next to the avatar URL (see [Changing the
avatar](#changing-the-avatar)), or your app's own files at rest. Each takes
the raw 32-byte key `encryptStream` took, as `key` in its params class, and
writes the format `encryptStream` writes: files 0.5.x encrypted with
`encryptStream` or a stream encryptor decrypt with `decryptFileWithKey`, and
0.5.x `decryptStream` decrypts what `encryptFileWithKey` returns, so files
you stored need no re-encryption. A key that isn't 32 bytes throws a
`ChatXdkException` of kind `INVALID_INPUT`, and bytes that aren't a complete
file encrypted under the key one of kind `DECRYPTION`.

```java
// 0.5.x
byte[] encrypted = chat.encryptStream(data, conversationKey);
byte[] plaintext = chat.decryptStream(downloaded, conversationKey);

// 0.7.2
byte[] encrypted = chat.encryptFileWithKey(new EncryptFileWithKeyParams(data, conversationKey));
byte[] plaintext = chat.decryptFileWithKey(new DecryptFileWithKeyParams(downloaded, conversationKey));
```

To move an `encryptStream` or `decryptStream` call, look at its file. A file
one of a message's attachments names (a photo, a video, a link card's banner
or favicon) moves to `encryptFile` and `decryptFile`, with the message; any
other file moves to `encryptFileWithKey` and `decryptFileWithKey`, with the
same key.

### Encrypt and decrypt large files in chunks

`fileEncryptor` and `fileDecryptor` take the same values as `encryptFile`
and `decryptFile`, without the file bytes, and return a `FileEncryptor` or
a `FileDecryptor`; `push`, `finish` and `close` keep their 0.5.x form.
Size an upload with `ChatXdkUtilities.encryptedFileSize`. A file under a key
you hold has no chunked form: read it whole and pass it to
`encryptFileWithKey` or `decryptFileWithKey` (see [Encrypt a file under a
key you hold](#encrypt-a-file-under-a-key-you-hold)).

```java
// 0.5.x
long size = ChatXdkUtilities.encryptedStreamSize(photo.length);
StreamEncryptor encryptor = chat.streamEncryptor(conversationKey);
StreamDecryptor decryptor = chat.streamDecryptor(keys.get(conversationKeyVersion));

// 0.7.2
long size = ChatXdkUtilities.encryptedFileSize(photo.length);
FileEncryptor encryptor = chat.fileEncryptor(new FileEncryptorParams(payload.eventB64, mediaHashKey));
FileDecryptor decryptor = chat.fileDecryptor(new FileDecryptorParams(fileEventB64, keys, fileHashKey));
```

### Action signatures come nested

The prepare methods return each `ActionSignature` in the shape a request's
`action_signatures` takes: `messageId`, `encodedMessageEventDetail`, the
signature in `messageEventSignature` (a `MessageEventSignature` with
`signingPublicKey`, your signing public key as `getPublicKeys` returns it),
and nothing else: the signed payload stays inside the SDK. Their Jackson
names are the request's snake_case names, so serialize them as returned
(see [Serialize request bodies with
Jackson](#serialize-request-bodies-with-jackson)):

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

// 0.7.2
List<ActionSignature> actionSignatures = prepared.actionSignatures;
```

### Public key inputs name the identity key and its version

A `PublicKeyInput`, one participant a conversation key is encrypted to,
names its key `identityPublicKey` and the key's version `publicKeyVersion`,
as `SigningKeyEntry` does: the `public_key` the X API returns for a user is
their identity key. Its constructor takes the user id, the key and the
version (see [Descriptors and key entries take their values in
constructors](#descriptors-and-key-entries-take-their-values-in-constructors)):

```java
// 0.5.x
PublicKeyInput input = new PublicKeyInput();
input.userId = userId;
input.publicKey = identityPublicKey;
input.keyVersion = publicKeyVersion;

// 0.7.2
PublicKeyInput input = new PublicKeyInput(userId, identityPublicKey, publicKeyVersion);
```

### Participant keys take the key requests' names

A prepared change's participant keys carry the names the X API gives them in
every request that takes them (`POST /2/chat/conversations/{id}/keys`,
`/group` and `/{id}/members`, and `PUT /2/chat/conversations/{id}`):
`conversationParticipantKeys`, a list of `ConversationParticipantKey` whose
fields (`userId`, `encryptedConversationKey`, `publicKeyVersion`) serialize
as `user_id`, `encrypted_conversation_key` and `public_key_version`, the
names a received key change uses too (see [Received participant keys take
the same names](#received-participant-keys-take-the-same-names)). Drop the
renaming and pass them through as returned:

```java
// 0.5.x
List<Map<String, String>> conversationParticipantKeys = new ArrayList<>();
for (EncryptedKeyForRecipient key : prepared.participantKeys) {
    conversationParticipantKeys.add(Map.of(
            "user_id", key.userId,
            "encrypted_conversation_key", key.encryptedKey,
            "public_key_version", key.publicKeyVersion));
}

// 0.7.2
List<ConversationParticipantKey> conversationParticipantKeys = prepared.conversationParticipantKeys;
```

### Received participant keys take the same names

A decrypted key change carries its participant keys under the names Thrift's
`ConversationKeyChangeEvent` gives them, the same names a prepared change
uses: `conversation_participant_keys`, each entry with `user_id`,
`encrypted_conversation_key` and `public_key_version`, which deserializes
into `ConversationParticipantKey`. Read them under those names:

```java
// 0.5.x
String encrypted = keyChange.path("participant_keys").get(0).path("encrypted_key").asText();

// 0.7.2
String encrypted = keyChange.path("conversation_participant_keys").get(0)
        .path("encrypted_conversation_key").asText();
```

### Deletes return a `PreparedAction`

`prepareMessageDelete` returns a `PreparedAction` whose `actionSignatures`
hold one entry, shaped as [Action signatures come
nested](#action-signatures-come-nested) shows. Read the action's `messageId`
from that entry, and send `actionSignatures` as returned (see [Deleting
messages](#deleting-messages) for the request):

```java
// 0.5.x
ActionSignature deletion = chat.prepareMessageDelete(
        new MessageDeleteParams(conversationId, sequenceIds, false));
String messageId = deletion.messageId;

// 0.7.2
PreparedAction deletion = chat.prepareMessageDelete(
        new MessageDeleteParams(conversationId, sequenceIds, false));
String messageId = deletion.actionSignatures.get(0).messageId;
```

### Decrypted events use the names the calls take

A decrypted message or key change carries its conversation key version as
`conversation_key_version`, the name the X API's events and the Thrift
events give it, and the name the encrypt params serialize to:

```java
// 0.5.x
String messageVersion = message.path("key_version").asText();
String keyChangeVersion = keyChange.path("key_version").asText();

// 0.7.2
String messageVersion = message.path("conversation_key_version").asText();
String keyChangeVersion = keyChange.path("conversation_key_version").asText();
```

Fields that hold sequence ids take the names of the params that send them,
as those params serialize. `Reaction`, `ReactionRemoved` and `Edit`
content names its target `target_message_sequence_id`, as
`EncryptReactionParams` and `EncryptEditParams` do. A `MessageDeleted`
event names its messages `sequence_ids`, as `MessageDeleteParams` does, and
a `ReadReceipt` or `MarkedUnread` event names its position
`seen_until_sequence_id`, as `MarkConversationReadParams` does. An edit's
text is `updated_text`, as `EncryptEditParams` names it, and a v1 edit
carries the signed message id of the message it edits as
`target_message_id`, absent for a v0 edit.

**Rename every read of `target_message_id` to `target_message_sequence_id`.
Don't keep `target_message_id`: in 0.7.2 it names a different value, and
reading it from a `JsonNode` throws no error** (see [`target_message_id`
holds a different value](#target_message_id-holds-a-different-value)).

```java
// 0.5.x
JsonNode content = message.path("content");
if (content.path("content_type").asText().equals("Edit")) {
    showEdit(content.path("target_message_id").asText(), content.path("new_text").asText());
}
JsonNode deletedSequenceIds = deleted.path("message_ids");
String seenUntil = receipt.path("seen_until_id").asText();

// 0.7.2
JsonNode content = message.path("content");
if (content.path("content_type").asText().equals("Edit")) {
    showEdit(content.path("target_message_sequence_id").asText(), content.path("updated_text").asText());
}
JsonNode deletedSequenceIds = deleted.path("sequence_ids");
String seenUntil = receipt.path("seen_until_sequence_id").asText();
```

A group create's `title`, and a title or description change's `new_title`
or `new_description`, is a `GroupText` object rather than a string (see
[Creating a group](#creating-a-group)).

### Errors carry their kind

Every SDK failure throws a `ChatXdkException`, whose `getKind()`, a
`ChatXdkException.Kind`, names the failure the same way in every binding:
`INVALID_INPUT`, `INVALID_STATE`, `PARSE`, `DECRYPTION`, `VERIFICATION`,
`INVALID_PIN`, `JUICEBOX` or `INTERNAL`. After a wrong PIN, its
`getGuessesRemaining()` holds the attempts Juicebox reports left, `0` once
the stored keys are locked and `null` when Juicebox reports no count.

A missing or invalid parameter throws one of kind `INVALID_INPUT` with a
message that names the value, such as `Invalid sender_id 'user-1': pass a
numeric user id (digits only)` or `too many attachments: at most 10 per
message`, without an `Invalid state:` prefix. Errors about state the chat
lacks, such as a missing session identity or an empty key cache, are of
kind `INVALID_STATE` and keep their prefix. Tell them apart by kind rather
than by message:

```java
// 0.5.x
boolean invalidInput = !e.getMessage().startsWith("Invalid state:");

// 0.7.2
boolean invalidInput = e.getKind() == ChatXdkException.Kind.INVALID_INPUT;
showGuessesLeft(e.getGuessesRemaining());
```

### Exceptions

There's no code to change. `ChatXdkException` is unchecked. `setIdentity`
and `importKeys` throw it on invalid input; `verify`, `verifyKeyBinding` and
`matchesRegisteredKey` throw it for a key or signature they can't decode,
naming it; and the file methods (`encryptFile`, `decryptFile`,
`fileEncryptor`, `fileDecryptor`) declare no checked exceptions and throw it
too. The methods that declare `throws Exception` keep that clause.

### `ChatNative`

`ChatNative`, the JNA interface to the native library, follows the C ABI:
if your code calls it directly, apply the changes in [C ABI](c-abi.md).

## 3. Runtime and behavior changes

Nothing reports these changes before the code runs: each one is a value the
SDK checks, a value with a new meaning, or an event handled differently.

### Serialize request bodies with Jackson

The SDK's types carry Jackson `@JsonProperty` names, the X API's snake_case
ones: an `ActionSignature` serializes as `message_id`,
`encoded_message_event_detail` and `message_event_signature`. Serialize
request bodies with Jackson, as the snippets do. A serializer that ignores
Jackson's annotations, such as Gson, writes the Java field names,
camelCase, which the X API rejects, and writes a prepared change's
`conversationKey`, which Jackson leaves out (see [A prepared change's JSON
leaves out its key](#a-prepared-changes-json-leaves-out-its-key)).

### User ids are strings of digits

Every user id is a string of digits: the `SetIdentityParams` user id,
`senderId`, `replyToSenderId`, the `userId` of each `PublicKeyInput` and
`SigningKeyEntry`, and the ids of a group's members and admins
(`memberIds`, `adminIds`, `newMemberIds`, `currentMemberIds`,
`currentAdminIds`, `currentPendingMemberIds` and `userIds`). Each must be a
positive integer written without a sign or leading zeros; anything else
throws `ChatXdkException` naming the field, such as `Invalid sender_id
'user-1': pass a numeric user id (digits only)`.
`EncryptReplyParams.replyToSenderId` is a `String`:

```java
// 0.5.x
EncryptReplyParams reply = new EncryptReplyParams(conversationId, "pong", eventB64);
reply.replyToSenderId = 4201L;

// 0.7.2
EncryptReplyParams reply = new EncryptReplyParams(conversationId, "pong", eventB64);
reply.replyToSenderId = "4201";
```

### Key versions are integers written as strings

Every key version is a non-negative integer written as a string of digits,
as the X API returns it: the signing-key version (in `SetIdentityParams`,
`ImportKeysParams`, a call's `signingKeyVersion` and each public key's
`publicKeyVersion`) and `conversationKeyVersion`. Anything else throws
`ChatXdkException` naming the field, such as `Invalid signing_key_version
'v1': pass the key version as the X API returns it, an integer in digits`.
There's no code to change if you pass the versions the X API returns.

### Entities, files, URL cards and posts are checked

The encrypt calls check what a message carries before they encrypt it, and
throw a `ChatXdkException` of kind `INVALID_INPUT` naming the value, where
0.5.x sent it:

- An entity of a type the SDK doesn't know, an empty one included, fails
  with `Invalid entity_type 'user_mention': pass url, mention, hashtag,
  cashtag, email, address or phone_number`, for a message's, a reply's, a
  reply preview's and an edit's entities.
- Entity offsets count bytes of the text's UTF-8 encoding, the start
  inclusive and the end exclusive, not the UTF-16 units of a Java string.
  An entity whose offsets are negative, end before they start or run past
  the end of the text fails, such as `Invalid entity offsets 3..8: end is
  past the end of the text, which is 7 bytes of UTF-8`. A reply preview's
  entities, which index the quoted message's text, are checked for all but
  the end.
- A file a message carries, a media attachment or a URL card's banner or
  favicon, fails with an empty `filename`, a `filesizeBytes` of 0 or less,
  or a negative `width` or `height`, since receiving clients discard such a
  file. Give each file its name and the encrypted size
  `ChatXdkUtilities.encryptedFileSize` gives.
- A message that lists an empty media hash key, or one media hash key in
  two attachments, fails.
- A URL card with an empty `url`, and a post attachment with neither
  `restId` nor `postUrl`, fail.

Count an entity's offsets in bytes of UTF-8 when the text holds characters
outside ASCII:

```java
// 0.7.2
String text = "café @bob";
int start = text.substring(0, text.indexOf("@bob")).getBytes(StandardCharsets.UTF_8).length;
int end = start + "@bob".getBytes(StandardCharsets.UTF_8).length;
EncryptMessageParams mentionParams = new EncryptMessageParams(conversationId, text);
mentionParams.entities = List.of(new EntityDescriptor(start, end, "mention"));
SendPayload sent = chat.encryptMessage(mentionParams);
```

### `latestVersion` comes from a verified key change

`result.conversationKeys.latestVersion`, the version to encrypt with, is
the newest version whose key change verified, and it never moves back for
the chat's lifetime. A key change verifies only against its sender's
signing key, so give the chat every participant's signing keys, your own
included, before you decrypt. It's `null` until a key change verifies: a key
change the SDK can't verify still adds its key to
`result.conversationKeys.keys`, for decrypting, but never becomes the
version you encrypt with. Where 0.5.x returned the batch's highest version,
0.7.2 can return `null`: fetch the missing signing keys or the
conversation's key-change events and decrypt again, rather than encrypting
under the highest key in `keys`:

```java
// 0.5.x
DecryptEventsResult result = chat.decryptEvents(events, signingKeys);
String version = result.conversationKeys.latestVersion;

// 0.7.2
chat.setSigningKeys(signingKeys);
DecryptEventsResult result = chat.decryptEvents(new DecryptEventsParams(events));
String version = result.conversationKeys.latestVersion;
if (version == null) {
    // No key change verified: fetch every participant's signing keys
    // (GET /2/users/{id}/public_keys) and the conversation's key changes
    // (meta.conversation_key_events of GET /2/chat/conversations/{id}/events),
    // then decrypt again.
    return;
}
```

### `target_message_id` holds a different value

**In 0.5.x a reaction's or edit's `target_message_id` held the target's
sequence id. In 0.7.2 that value is `target_message_sequence_id`, and
`target_message_id` holds the edited message's signed message id, present
only on a v1 edit.** Decrypted events are `JsonNode`s, so code that keeps
reading `target_message_id` compiles and throws no error: it gets the wrong
id, or none. Rename every read, as [Decrypted events use the names the calls
take](#decrypted-events-use-the-names-the-calls-take) shows, and use
`target_message_id` only to match a v1 edit to the `message_id` you
deduplicate on.

### A reply preview quotes its message exactly

A received reply that embeds the message it quotes has its preview checked
against that message: `reply_preview_validation` is `"Valid"` only when the
first 140 characters of the preview's text, counted in UTF-16 code units as
X clients count them, are those of the quoted text, and its entities are
exactly the quoted message's, or its edit's when the reply embeds the edit.
0.5.x accepted any start of the quoted text, and entities among the quoted
message's. `encryptReply` builds such a preview from `replyToEvent`, and
from `replyToEditEvent` when the message was edited, so pass them when you
hold them. In v1, X clients check a reply against the message it names and
mark a reply that names none invalid, so a reply built from the explicit
preview fields names the quoted message's `message_id` as
`replyToMessageId`.

A reply carries no key change. Recipients open the quoted message with their
own conversation keys, or with the message key a reply carries for a v1
message, and decrypt ignores a key change embedded in a reply.
`replyToCkces` still opens a message under a key version your chat doesn't
hold yet, for `encryptReply` to quote it, but the reply doesn't carry those
key changes.

### A prepared change's JSON leaves out its key

A `PreparedConversationChange`'s `conversationKey` is
`@JsonProperty(access = WRITE_ONLY)`, where 0.5.x serialized it as
`conversation_key`. The key stays on the object, but Jackson leaves it out
of the JSON: code that saved or queued a prepared change as JSON loses the
key, and with it the conversation. Store the key yourself, and serialize
the rest:

```java
// 0.5.x
String saved = new ObjectMapper().writeValueAsString(prepared);

// 0.7.2
storeConversationKey(prepared.conversationId, prepared.conversationKeyVersion, prepared.conversationKey);
String saved = new ObjectMapper().writeValueAsString(prepared);
```

The request bodies take only a change's participant keys, key version and
action signatures, never the key itself.

### `sign` refuses data only the SDK signs

`sign` throws a `ChatXdkException` of kind `INVALID_INPUT` for a payload
recipients would verify as a signed event (a message, conversation-key
change, group or conversation-metadata change, delete or read receipt) and
for a P-256 public key, whose signature by the signing key binds it as an
identity key. Sign only your own application data with `sign`; the SDK
signs events itself. Any other data signs as in 0.5.x:

```java
// 0.7.2
byte[] signature;
try {
    signature = chat.sign(data);
} catch (ChatXdkException refused) {
    if (refused.getKind() != ChatXdkException.Kind.INVALID_INPUT) throw refused;
    // The data reads as an event or a public key, which only the SDK signs.
    signature = null;
}
```

### Decrypt drops a removal's title and description re-encryptions

A member removal rotates the conversation key and re-encrypts the group's
title and description under the new key, marked as key-rotation
re-encryptions. They are the same text, not changes, so `decryptEvents`
and `decryptEvent` drop them under either `setRejectUnverified` setting,
the way they drop an unverified event: `decryptEvents` leaves each one out
of `events` and records it in `errors`, and `decryptEvent` throws a
`ChatXdkException` of kind `INVALID_INPUT`: `GroupChange re-encrypts the
group's title for a key rotation (for_key_rotation), not a title change:
decrypt does not return it`. The removal itself (`MembersRemoved`), its key
change, avatar changes and every title or description change without the
mark decrypt as before. In 0.5.x, a removal by an X client arrived as a
`TitleChanged` carrying the group's unchanged title:

```java
// 0.5.x
for (DecryptedMessage decrypted : result.messages) {
    JsonNode change = decrypted.event.path("change");
    if (change.path("change_type").asText().equals("TitleChanged")) {
        showTitle(chat.decrypt(change.path("new_title").asText(), keys.get(conversationKeyVersion)));
    }
}

// 0.7.2
DecryptEventsResult result = chat.decryptEvents(new DecryptEventsParams(events));
for (DecryptedEvent decrypted : result.events) {
    JsonNode change = decrypted.event.path("change");
    if (change.path("change_type").asText().equals("TitleChanged")) {
        GroupText newTitle = new ObjectMapper().treeToValue(change.path("new_title"), GroupText.class);
        showTitle(newTitle.kind.equals("Text") ? newTitle.text : newTitle.raw);
    }
}
```

A loop over single events catches the exception, as it catches an
unverified event's, and moves on to the next event:

```java
// 0.7.2
for (JsonNode item : page.path("data")) {
    String eventB64 = item.path("encoded_event").asText();
    JsonNode event;
    try {
        event = chat.decryptEvent(new DecryptEventParams(eventB64, keys));
    } catch (ChatXdkException skipped) {
        logSkipped(eventB64, skipped);
        continue;
    }
    handle(event);
}
```

### `exportKeys` throws without keys

`exportKeys` throws a `ChatXdkException` of kind `INVALID_STATE` when no
identity key is loaded, where 0.5.x returned `null`; check
`hasIdentityKey` first where that can happen:

```java
// 0.5.x
byte[] exported = chat.exportKeys();

// 0.7.2
byte[] exported = chat.hasIdentityKey() ? chat.exportKeys() : null;
```

### An empty Juicebox config fails

Until a chat has a Juicebox config, `setup`, `unlock`, `changePin` and
`delete` and their async forms throw a `ChatXdkException` of kind
`INVALID_STATE`, `Invalid state: no Juicebox config: pass the
juicebox_config the X API returns when you create the chat, or call
update_config() first`, the error every binding gives. `new Chat(config)`
and `updateConfig` throw it for an empty or blank config, at once, rather
than at the first Juicebox call; `new Chat()` creates a chat without one.

## 4. Group and receipt signing

Recipients on the default `setRejectUnverified` policy drop a read receipt
or group change that isn't signed, as 0.5.x recipients did: sign each one,
or recipients never see it. The sender comes from `setIdentity`. Each
prepare call returns `actionSignatures` shaped as [Action signatures come
nested](#action-signatures-come-nested) shows; serialize them into the
request as returned, with Jackson.

### The requests

Each request below takes the conversation id in its path as `pathId`, and
the prepare call's `actionSignatures` as returned, as `action_signatures`.
The paths and body fields are the X API's, as its OpenAPI description
(`https://api.x.com/2/openapi.json`) gives them.

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
| Change screen capture | `prepareScreenCapture` | `PUT /2/chat/conversations/{id}/screen_capture` | `blocking` (`true` for `BlockingEnabled`, `false` for `BlockingDisabled`) and `blocking_action_signatures`, or `detection` and `detection_action_signatures` |

A group's `conversation_id` is the `g…` id that
`POST /2/chat/conversations/group/initialize` returns as
`data.conversation_id`.

### Deleting messages

`prepareMessageDelete` returns the action's signature nested, as every
prepare call does: send `actionSignatures` as returned, next to the
sequence ids and the delete action the params signed.

```java
// 0.5.x
ActionSignature deletion = chat.prepareMessageDelete(new MessageDeleteParams(conversationId, sequenceIds, true));
api.post("/2/chat/conversations/" + pathId + "/messages/delete", Map.of(
        "sequence_ids", sequenceIds,
        "delete_message_action", "delete_for_all",
        "action_signatures", List.of(Map.of(
                "message_id", deletion.messageId,
                "encoded_message_event_detail", deletion.encodedMessageEventDetail,
                "message_event_signature", Map.of(
                        "signature", deletion.signature,
                        "signature_version", deletion.signatureVersion,
                        "public_key_version", deletion.publicKeyVersion,
                        "signing_public_key", signingPublicKey)))));

// 0.7.2
PreparedAction deletion = chat.prepareMessageDelete(new MessageDeleteParams(conversationId, sequenceIds, true));
api.post("/2/chat/conversations/" + pathId + "/messages/delete", Map.of(
        "sequence_ids", sequenceIds,
        "delete_message_action", "delete_for_all",
        "action_signatures", deletion.actionSignatures));
```

A recipient's `decryptEvent` returns the delete as a verified
`MessageDeleted` event with its `sequence_ids` and `delete_for_all`.

### Read receipts are signed

Sign a read receipt with `prepareMarkConversationRead` and send the
`PreparedAction`'s `actionSignatures` as the `action_signatures` of
`POST /2/chat/conversations/{id}/read`. The call takes a
`MarkConversationReadParams` (the conversation id, the sequence id of the
newest event read, and a `seenAtMsec` that defaults to now) and returns a
`PreparedAction`, one entry. Without it the X API sends an unsigned
receipt, which recipients drop.

```java
// 0.5.x
api.post("/2/chat/conversations/" + pathId + "/read", Map.of());

// 0.7.2
PreparedAction receipt = chat.prepareMarkConversationRead(
        new MarkConversationReadParams(conversationId, seenUntilSequenceId));
api.post("/2/chat/conversations/" + pathId + "/read",
        Map.of("action_signatures", receipt.actionSignatures));
```

A recipient's `decryptEvent` returns a signed receipt as a verified
`ReadReceipt` event, its position in `seen_until_sequence_id`.

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
it creates, so set it as plaintext. The result is a
`PreparedConversationChange` that also carries it encrypted, as
`encryptedTitle` (null when unset): send that as the create request's
`group_name`, next to its participant keys and signatures. The create signs
the encrypted value, which is base64, so a title may contain a comma; a
value signed as is, such as an avatar URL, can't. A create sets no avatar:
set one afterwards with an [avatar change](#changing-the-avatar), with the
image encrypted under the key the create returns.

```java
// 0.5.x
GroupCreateParams create = new GroupCreateParams(publicKeys, conversationId, memberIds, adminIds);
create.title = title;
create.avatarUrl = avatarUrl;
PreparedConversationChange prepared = chat.prepareGroupCreate(create);
Map<String, Object> body = Map.of("group_name", title, "group_avatar_url", avatarUrl);

// 0.7.2
GroupCreateParams create = new GroupCreateParams(publicKeys, conversationId, memberIds, adminIds);
create.title = title;
PreparedConversationChange prepared = chat.prepareGroupCreate(create);
api.post("/2/chat/conversations/group", Map.of(
        "conversation_id", conversationId,
        "group_members", memberIds,
        "group_admins", adminIds,
        "group_name", prepared.encryptedTitle,
        "conversation_key_version", prepared.conversationKeyVersion,
        "conversation_participant_keys", prepared.conversationParticipantKeys,
        "action_signatures", prepared.actionSignatures));
storeConversationKey(conversationId, prepared.conversationKeyVersion, prepared.conversationKey);
```

`decryptEvent` returns a received group create with its title decrypted with
the key for the version the create names, from the call's key map or the key
cache: a `Created` change's `title` converts to a `Types.GroupText` with
Jackson's `treeToValue`. `kind` `"Text"` holds the title in `text`. `kind`
`"Unavailable"` holds, in `raw`, the value as the create carries it, when
that key isn't there or the value doesn't decrypt under it, and the rest of
the create still decrypts. 0.5.x signed a create's title as the app passed
it, so a 0.5.x app's create with a plaintext title arrives as
`"Unavailable"` with the title in `raw`: show `raw` when a title isn't
decryptable. A create that names no key version carries its title as
plaintext, and arrives as `"Text"`. The encrypted `group_name` and
`group_description` the X API returns with a conversation open with
`decrypt`.

```java
// 0.5.x
JsonNode change = groupChange.path("change");
if (change.path("change_type").asText().equals("Created") && change.hasNonNull("title")) {
    showTitle(chat.decrypt(change.path("title").asText(), keys.get(conversationKeyVersion)));
}

// 0.7.2
JsonNode change = groupChange.path("change");
if (change.path("change_type").asText().equals("Created") && change.hasNonNull("title")) {
    GroupText groupTitle = new ObjectMapper().treeToValue(change.path("title"), GroupText.class);
    showTitle(groupTitle.kind.equals("Text") ? groupTitle.text : groupTitle.raw);
}
```

A `Created` change also carries the create's `conversation_key_version`, and
the `avatar_url` a create from another client may set: a media URL whose
image is encrypted under that key version, which `decryptFileWithKey` opens
with that version's key.

### Adding members

`prepareGroupMembersChange` rotates the conversation key, so it re-encrypts
the group's title and description under the key it generates: set them as
plaintext, in `currentTitle` and `currentDescription`, not as values your
code encrypted. The result carries them encrypted, as `encryptedTitle` and
`encryptedDescription` (null when unset). Send `encryptedTitle` as the
add-members request's `encrypted_title`; the description travels in the
signed member add. Encrypt under the new key from here on, as [Removing
members](#removing-members) shows for a removal.

```java
// 0.5.x
GroupMembersChangeParams add = new GroupMembersChangeParams(
        publicKeys, conversationId, newMemberIds, memberIds, adminIds, List.of());
add.currentTitle = title;
PreparedConversationChange prepared = chat.prepareGroupMembersChange(add);

// 0.7.2
GroupMembersChangeParams add = new GroupMembersChangeParams(
        publicKeys, conversationId, newMemberIds, memberIds, adminIds, List.of());
add.currentTitle = title;
add.currentDescription = description;
PreparedConversationChange prepared = chat.prepareGroupMembersChange(add);
api.post("/2/chat/conversations/" + pathId + "/members", Map.of(
        "user_ids", newMemberIds,
        "encrypted_title", prepared.encryptedTitle,
        "conversation_key_version", prepared.conversationKeyVersion,
        "conversation_participant_keys", prepared.conversationParticipantKeys,
        "action_signatures", prepared.actionSignatures));
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

A recipient's `decryptEvent` returns the add as a verified `MembersAdded`
change with `member_ids`, `current_member_ids` and `current_admin_ids`.

### Removing members

`prepareGroupMembersRemove` removes `userIds` and rotates the conversation
key, so the members removed don't receive the key the group encrypts under
next. `GroupMembersRemoveParams` takes:

- `publicKeys`: the identity key of every member who stays, yours included,
  as `GET /2/users/{id}/public_keys` returns them. The SDK encrypts the new
  key to each member's newest key version; a member left out, you included,
  can't read what the group sends under the new key. The SDK doesn't check
  that the list is complete. A key for a member being removed throws
  `ChatXdkException`.
- `conversationId` and `userIds`, the members to remove.
- `title` and `description`: the group's current title and description, as
  plaintext. Set each one the group has; the call encrypts each under the
  new key and signs it as a key-rotation re-encryption, which recipients'
  decrypt drops rather than shows as a change. The avatar is an image you
  encrypt, so the call doesn't re-encrypt it: X clients re-encrypt the
  avatar on every key rotation, so once the removal succeeds, encrypt the
  image under the new key with `encryptFileWithKey`, upload it, and send an
  [avatar change](#changing-the-avatar) naming the new key version.

The result is a `PreparedConversationChange`: the new `conversationKey` and
`conversationKeyVersion`, `conversationParticipantKeys` for the members who
stay, and `actionSignatures` in request order: the removal, a title change
and a description change for the ones set, then the conversation-key change.
Each signs at signature version 7 while the chat sends v0, as 0.5.x readers
verify, and at version 10 while it sends v1 (see [Upgrade readers
first](#upgrade-readers-first)).

```java
// 0.5.x
api.post("/2/chat/conversations/" + pathId + "/members/remove", Map.of("user_ids", userIds));

// 0.7.2
GroupMembersRemoveParams removal = new GroupMembersRemoveParams(remainingPublicKeys, conversationId, userIds);
removal.title = title;
removal.description = description;
PreparedConversationChange prepared = chat.prepareGroupMembersRemove(removal);
api.post("/2/chat/conversations/" + pathId + "/members/remove", Map.of(
        "user_ids", userIds,
        "action_signatures", prepared.actionSignatures,
        "group_key_rotation_data", Map.of(
                "conversation_key_version", prepared.conversationKeyVersion,
                "conversation_participant_keys", prepared.conversationParticipantKeys)));
```

**Encrypt under the new key as soon as the request succeeds.** The removed
members hold the old key, so a message encrypted under it is one they can
read. The key cache (`setCacheKeys(true)`) adopts the new key only once
`decryptEvents` decrypts the removal's key change from the conversation's
events, and only if that key change verifies against your own signing key;
until then an encrypt call that omits the key resolves the old one. Store
the new key and version, and pass them to every encrypt and prepare call
until the cache holds them:

```java
// 0.7.2
storeConversationKey(conversationId, prepared.conversationKeyVersion, prepared.conversationKey);
EncryptMessageParams next = new EncryptMessageParams(conversationId, "hello");
next.conversationKey = prepared.conversationKey;
next.conversationKeyVersion = prepared.conversationKeyVersion;
SendPayload sent = chat.encryptMessage(next);
```

The same holds after any call that rotates the key:
`prepareConversationKeyChange`, `prepareGroupCreate` and
`prepareGroupMembersChange`.

On the receiving side, `decryptEvents` returns the removal as a verified
`MembersRemoved` change with its `member_ids`, and the key change as a
`KeyChange` event that adds the new key to `conversationKeys` and moves
`latestVersion` to it once it verifies. The title and description
re-encryptions are in `errors`, not `events` (see [Decrypt drops a
removal's title and description
re-encryptions](#decrypt-drops-a-removals-title-and-description-re-encryptions)):

```java
// 0.7.2
DecryptEventsResult result = chat.decryptEvents(new DecryptEventsParams(events));
for (DecryptedEvent decrypted : result.events) {
    JsonNode change = decrypted.event.path("change");
    if (change.path("change_type").asText().equals("MembersRemoved")) {
        JsonNode removed = change.path("member_ids");
    }
}
String version = result.conversationKeys.latestVersion;
```

### Leaving a group

`prepareGroupLeave` signs the sender's removal and does not rotate the
conversation key. `actionSignatures` are the removal, then a
`GroupAdminAddChange` when `promoteAdminId` is set, then a
`ConversationDeleteEvent`, each at signature version 7, or 10 while the chat
sends v1. It returns a `PreparedAction`. Send it as a removal of your own
id:

```java
// 0.5.x
api.post("/2/chat/conversations/" + pathId + "/members/remove", Map.of("user_ids", List.of(myUserId)));

// 0.7.2
GroupLeaveParams leave = new GroupLeaveParams(conversationId);
leave.promoteAdminId = promoteAdminId;
PreparedAction left = chat.prepareGroupLeave(leave);
api.post("/2/chat/conversations/" + pathId + "/members/remove", Map.of(
        "user_ids", List.of(myUserId),
        "action_signatures", left.actionSignatures));
```

### Changing the title

`prepareGroupTitleChange` takes the new title as plaintext, encrypts it
under the conversation key and signs it. Like `EncryptMessageParams`,
`GroupTitleChangeParams` takes the key and its version in
`conversationKey` and `conversationKeyVersion`, or resolves both from the
key cache when they're null. The result is a `PreparedGroupMetadataChange`:
the `encryptedValue` the request sends as `group_name`, the
`conversationKeyVersion` it's encrypted under, and the `actionSignatures`
to send with it.

```java
// 0.5.x
api.put("/2/chat/conversations/" + pathId, Map.of(
        "group_name", chat.encrypt(title, keys.get(conversationKeyVersion)),
        "conversation_key_version", conversationKeyVersion,
        "modified_fields", List.of("group_name")));

// 0.7.2
PreparedGroupMetadataChange prepared = chat.prepareGroupTitleChange(
        new GroupTitleChangeParams(conversationId, title));
api.put("/2/chat/conversations/" + pathId, Map.of(
        "group_name", prepared.encryptedValue,
        "conversation_key_version", prepared.conversationKeyVersion,
        "modified_fields", List.of("group_name"),
        "action_signatures", prepared.actionSignatures));
```

`decryptEvent` returns a received title change decrypted: the `new_title` of
a `TitleChanged` change converts to a `GroupText`, as a create's `title`
does. It decrypts with the key for the version the change names, from the
call's key map or the key cache. Without that key, or when the value isn't
ciphertext under it, as for a plaintext title an app signed with a key
version, it is `"Unavailable"` with the value as carried, and the event
still decrypts. A removal's re-encrypted title never arrives as a
`TitleChanged`. A change that removes the title decrypts to an empty title.

```java
// 0.5.x
JsonNode change = groupChange.path("change");
if (change.path("change_type").asText().equals("TitleChanged")) {
    showTitle(chat.decrypt(change.path("new_title").asText(), keys.get(conversationKeyVersion)));
}

// 0.7.2
JsonNode change = groupChange.path("change");
if (change.path("change_type").asText().equals("TitleChanged")) {
    GroupText newTitle = new ObjectMapper().treeToValue(change.path("new_title"), GroupText.class);
    showTitle(newTitle.kind.equals("Text") ? newTitle.text : newTitle.raw);
}
```

### Changing the description

`prepareGroupDescriptionChange` takes the new description as plaintext and
returns a `PreparedGroupMetadataChange`, as the title change does; the
request sends its `encryptedValue` as `group_description`.

```java
// 0.5.x
api.put("/2/chat/conversations/" + pathId, Map.of(
        "group_description", chat.encrypt(description, keys.get(conversationKeyVersion)),
        "conversation_key_version", conversationKeyVersion,
        "modified_fields", List.of("group_description")));

// 0.7.2
PreparedGroupMetadataChange prepared = chat.prepareGroupDescriptionChange(
        new GroupDescriptionChangeParams(conversationId, description));
api.put("/2/chat/conversations/" + pathId, Map.of(
        "group_description", prepared.encryptedValue,
        "conversation_key_version", prepared.conversationKeyVersion,
        "modified_fields", List.of("group_description"),
        "action_signatures", prepared.actionSignatures));
```

A received description change is a `DescriptionChanged` change holding
`new_description`, which converts to a `GroupText`; read it as a title
change's `new_title`. A change that removes the description decrypts to an
empty description. A removal's re-encrypted description never arrives as
one:

```java
// 0.7.2
JsonNode change = groupChange.path("change");
if (change.path("change_type").asText().equals("DescriptionChanged")) {
    GroupText newDescription =
            new ObjectMapper().treeToValue(change.path("new_description"), GroupText.class);
    showDescription(newDescription.kind.equals("Text") ? newDescription.text : newDescription.raw);
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

```java
// 0.5.x
byte[] encrypted = chat.encryptStream(photo, keys.get(conversationKeyVersion));
api.put("/2/chat/conversations/" + pathId, Map.of(
        "group_avatar_url", chat.encrypt(avatarUrl, keys.get(conversationKeyVersion)),
        "conversation_key_version", conversationKeyVersion,
        "modified_fields", List.of("group_avatar_url")));

// 0.7.2
byte[] encrypted = chat.encryptFileWithKey(
        new EncryptFileWithKeyParams(photo, keys.get(conversationKeyVersion)));
PreparedAction prepared = chat.prepareGroupAvatarChange(
        new GroupAvatarChangeParams(conversationId, avatarUrl, conversationKeyVersion));
api.put("/2/chat/conversations/" + pathId, Map.of(
        "group_avatar_url", avatarUrl,
        "conversation_key_version", conversationKeyVersion,
        "modified_fields", List.of("group_avatar_url"),
        "action_signatures", prepared.actionSignatures));
```

In both, `avatarUrl` is the media URL of the uploaded `encrypted` image. A
received `AvatarChanged` change holds `new_avatar_url` as sent and its
`conversation_key_version`: download the image and decrypt it with
`decryptFileWithKey` under the key for that version. A change that removes
the avatar holds an empty `new_avatar_url`.

```java
// 0.7.2
JsonNode change = groupChange.path("change");
if (change.path("change_type").asText().equals("AvatarChanged") && change.hasNonNull("conversation_key_version")) {
    String version = change.get("conversation_key_version").asText();
    byte[] image = chat.decryptFileWithKey(new DecryptFileWithKeyParams(downloaded, keys.get(version)));
    showAvatar(image);
}
```

### Admins, invites, join requests, message TTL and screen capture

Each of these calls returns a `PreparedAction` with one signature, at
signature version 7, or 10 while the chat sends v1, for the request [The
requests](#the-requests) names. 0.5.x apps sent these requests without
signatures; recipients drop them unsigned. A recipient's `decryptEvent`
returns admin, invite and join changes as verified `GroupChange` events
(`AdminsAdded`, `AdminsRemoved`, `InviteEnabled`, `InviteDisabled`,
`JoinRequested`, `JoinRejected`) and TTL and screen-capture changes as
verified `SettingsChange` events.

```java
// 0.5.x
api.post("/2/chat/conversations/" + pathId + "/admins", Map.of("user_ids", userIds));

// 0.7.2
PreparedAction added = chat.prepareGroupAdminsAdd(new GroupAdminsAddParams(conversationId, userIds));
api.post("/2/chat/conversations/" + pathId + "/admins", Map.of(
        "user_ids", userIds, "action_signatures", added.actionSignatures));
PreparedAction removed = chat.prepareGroupAdminsRemove(new GroupAdminsRemoveParams(conversationId, userIds));
api.post("/2/chat/conversations/" + pathId + "/admins/remove", Map.of(
        "user_ids", userIds, "action_signatures", removed.actionSignatures));
```

An invite signs its URL, its expiry and its affiliate; a null
`expiresAtMsec` or `affiliateId` signs `null`. The request sends the expiry
as `validity_expiry_timestamp_msec`, and only with the same value the params
signed:

```java
// 0.7.2
GroupInviteEnableParams enable = new GroupInviteEnableParams(conversationId, inviteUrl);
enable.expiresAtMsec = expiresAtMsec;
PreparedAction invite = chat.prepareGroupInviteEnable(enable);
api.post("/2/chat/conversations/" + pathId + "/invite", Map.of(
        "invite_url", inviteUrl,
        "validity_expiry_timestamp_msec", Long.toString(expiresAtMsec),
        "action_signatures", invite.actionSignatures));
PreparedAction disabled = chat.prepareGroupInviteDisable(new GroupInviteDisableParams(conversationId));
api.delete("/2/chat/conversations/" + pathId + "/invite",
        Map.of("action_signatures", disabled.actionSignatures));
```

A join request signs the requesting user, who defaults to the sender; the
invite token travels in the request but not in the signature:

```java
// 0.7.2
PreparedAction request = chat.prepareGroupJoinRequest(new GroupJoinRequestParams(conversationId));
api.post("/2/chat/conversations/" + pathId + "/join_requests", Map.of(
        "token", inviteToken, "action_signatures", request.actionSignatures));
PreparedAction rejected = chat.prepareGroupJoinReject(new GroupJoinRejectParams(conversationId, userIds));
api.post("/2/chat/conversations/" + pathId + "/join_requests/reject", Map.of(
        "user_ids", userIds, "action_signatures", rejected.actionSignatures));
```

A TTL change signs `ttlMsec` only; a negative one is rejected:

```java
// 0.7.2
PreparedAction ttl = chat.prepareMessageTtlChange(new MessageTtlChangeParams(conversationId, ttlMsec));
api.put("/2/chat/conversations/" + pathId + "/message_ttl", Map.of(
        "message_ttl_ms", Long.toString(ttlMsec), "action_signatures", ttl.actionSignatures));
PreparedAction cleared = chat.prepareMessageTtlRemove(new MessageTtlRemoveParams(conversationId));
api.delete("/2/chat/conversations/" + pathId + "/message_ttl",
        Map.of("action_signatures", cleared.actionSignatures));
```

A screen-capture change is one of `ScreenCaptureChange.BlockingEnabled`,
`BlockingDisabled`, `DetectionEnabled` or `DetectionDisabled`. The request
names its signatures after the setting, `blocking_action_signatures` or
`detection_action_signatures`, not `action_signatures`:

```java
// 0.7.2
PreparedAction capture = chat.prepareScreenCapture(
        new ScreenCaptureParams(conversationId, ScreenCaptureChange.BlockingEnabled));
api.put("/2/chat/conversations/" + pathId + "/screen_capture", Map.of(
        "blocking", true, "blocking_action_signatures", capture.actionSignatures));
```

## 5. Verify

### Build

Run `mvn compile` (or `gradle build`) and your tests: the compiler flags
every call that still passes 0.5.x arguments and every renamed field of the
SDK's types. Fields of decrypted events are `JsonNode` paths, which the
compiler doesn't check: the search below finds them.

### Find the 0.5.x names

Search the app for the names in the symbol index's 0.5.x column. Each hit is
a line to change, unless it is your own code that shares the name:

```sh
grep -rnE "encryptStream|decryptStream|stream(En|De)cryptor|Stream(En|De)cryptor|encryptedStreamSize|\.encrypt\(|encryptedContent|encodedEventSignature|generateVersion|\.messages\b|DecryptedMessage|EncryptedKeyForRecipient|\.participantKeys\b|\.encryptedKey\b|\.keyVersion\b|\.avatarUrl\b|\"(participant_keys|encrypted_key|key_version|new_text|message_ids|seen_until_id)\"" --include='*.java' --include='*.kt' .
grep -rn "target_message_id" --include='*.java' --include='*.kt' .
```

Every `target_message_id` the second search finds should read a v1 edit's
signed message id; rename the rest to `target_message_sequence_id`. Each
`encryptStream` and `decryptStream` the first finds is a message's file or a
file under a key you hold, and [Encrypt a file under a key you
hold](#encrypt-a-file-under-a-key-you-hold) says which call each moves to.

### Run a round trip

This round trip runs offline, with two chats standing in for two users. It
registers both, starts a conversation, sends a message and decrypts it with
`setRejectUnverified` on, the default, so the signature has to verify:

```java
// 0.7.2
try (Chat alice = new Chat(); Chat bob = new Chat()) {
    PublicKeyRegistration aliceKeys = alice.generateKeypairs().publicKey;
    PublicKeyRegistration bobKeys = bob.generateKeypairs().publicKey;
    alice.setIdentity(new SetIdentityParams("1001", "1"));
    bob.setIdentity(new SetIdentityParams("1002", "1"));

    PreparedConversationChange change = alice.prepareConversationKeyChange(new ConversationKeyChangeParams(List.of(
            new PublicKeyInput("1001", aliceKeys.publicKey, "1"),
            new PublicKeyInput("1002", bobKeys.publicKey, "1"))));
    EncryptMessageParams send = new EncryptMessageParams(change.conversationId, "hello");
    send.conversationKey = change.conversationKey;
    send.conversationKeyVersion = change.conversationKeyVersion;
    SendPayload sent = alice.encryptMessage(send);

    ConversationParticipantKey bobEntry = change.conversationParticipantKeys.stream()
            .filter(key -> key.userId.equals("1002"))
            .findFirst()
            .orElseThrow();
    byte[] bobKey = bob.decryptConversationKey(bobEntry.encryptedConversationKey);
    DecryptEventParams receive = new DecryptEventParams(sent.eventB64, Map.of(change.conversationKeyVersion, bobKey));
    receive.signingKeys = List.of(new SigningKeyEntry(
            "1001", "1", aliceKeys.signingPublicKey, aliceKeys.publicKey, aliceKeys.identityPublicKeySignature));
    JsonNode event = bob.decryptEvent(receive);
    if (!event.path("verified").asBoolean() || !event.path("content").path("text").asText().equals("hello")) {
        throw new IllegalStateException("round trip failed");
    }
    if (!List.of("7", "10").contains(sent.signatureInfo.signatureVersion)) {
        throw new IllegalStateException("unknown format " + sent.signatureInfo.signatureVersion);
    }
    if (!sent.xdkVersion.startsWith("0.7.")) {
        throw new IllegalStateException("xdk version " + sent.xdkVersion);
    }
}
```

`signatureVersion` is `"7"` for a v0 send and `"10"` for v1, as the
`v1_send` switch decides. `xdkVersion` is the version of the library that
built the send, a 0.7 release, which the X API receives with each send.

Then run the same flows against a test conversation on the X API: send a
text, a file, a reply, an edit and a delete, mark the conversation read,
and create a group, set its avatar, add a member and remove one. Fetch the
conversation's events with `GET /2/chat/conversations/{id}/events`, pass
`data[].encoded_event` and `meta.conversation_key_events` to
`decryptEvents` with every participant's signing keys, and check that every
event in `events` has `verified` set and that `errors` holds only the
removal's title and description re-encryptions.
