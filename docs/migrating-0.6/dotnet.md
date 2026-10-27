# Migrating .NET code to chat-xdk 0.6.0

This page moves C# and other .NET code written for `XDevPlatform.ChatXdk`
0.5.x (0.5.0, 0.5.1 or 0.5.2) to 0.6.0. Work through it top to bottom:
[Before you start](#0-before-you-start) sets up the upgrade, the [symbol
index](#1-symbol-index) maps every 0.5.x name to its 0.6.0 form,
[Compile-time changes](#2-compile-time-changes) and [Runtime
changes](#3-runtime-and-behavior-changes) show each line to change, [Group
and receipt signing](#4-group-and-receipt-signing) gives every signed
request, and [Verify](#5-verify) checks the result. [Why 0.6.0
changes](why.md) explains each change, and the [index](README.md) lists the
other bindings' pages. [API.md](../API.md) documents every call.

## Checklist

Each item is tagged with what it takes: `[rollout]` is a deployment step,
`[compile]` a change the compiler reports, `[runtime]` a change in behavior
that nothing reports, and `[new]` a 0.6.0 call to adopt.

- [ ] `[rollout]` [Install 0.6.0](#install-060)
- [ ] `[rollout]` [Remove a native library you built for 0.5.x](#the-package-bundles-the-linux-arm64-native-library)
- [ ] `[rollout]` [Upgrade every app that reads your conversations first](#upgrade-readers-first)
- [ ] `[rollout]` [Allow or block the feature-switch request](#the-feature-switch-request)
- [ ] `[compile]` [Pass the Juicebox config to `new Chat(config)`, and PINs as `byte[]`](#keys-stored-in-juicebox)
- [ ] `[compile]` [Register keys with the public key only](#register-keys-with-the-public-key-only)
- [ ] `[compile]` [Pass a `SetIdentityParams` to `SetIdentity`](#setidentity-takes-setidentityparams)
- [ ] `[compile]` [Pass an `ImportKeysParams` to `ImportKeys`](#importkeys-takes-importkeysparams)
- [ ] `[compile]` [Pass a `DecryptEventsParams` to `DecryptEvents` and read its `Events`](#decryptevents-takes-decrypteventsparams)
- [ ] `[compile]` [Pass a `DecryptEventParams` to `DecryptEvent`](#decryptevent-takes-decrypteventparams)
- [ ] `[compile]` [Read `SendPayload` under the send request's field names and send `xdk_version`](#sendpayload-fields-take-the-send-requests-names)
- [ ] `[compile]` [Build descriptors with their constructors and factories](#entities-and-preview-images-take-their-values-in-the-constructor)
- [ ] `[compile]` [Build a message before you encrypt its files](#encrypt-a-file-from-its-message)
- [ ] `[compile]` [Decrypt a file with the event of its message](#decrypt-a-file-with-its-messages-event)
- [ ] `[compile]` [Use `FileEncryptor` and `FileDecryptor` for large files](#encrypt-and-decrypt-large-files-in-chunks)
- [ ] `[compile]` [Pass action signatures through as returned](#action-signatures-come-nested)
- [ ] `[compile]` [Name a `PublicKeyInput`'s properties `IdentityPublicKey` and `PublicKeyVersion`](#public-key-inputs-name-the-identity-key-and-its-version)
- [ ] `[compile]` [Pass participant keys through as returned](#participant-keys-take-the-key-requests-names)
- [ ] `[compile]` [Read received participant keys under the same names](#received-participant-keys-take-the-same-names)
- [ ] `[compile]` [Read a delete's signature from its `PreparedAction`](#deletes-return-a-preparedaction)
- [ ] `[compile]` [Read decrypted events under the names the calls take](#decrypted-events-use-the-names-the-calls-take)
- [ ] `[compile]` [Tell exceptions apart by `Kind`](#errors-carry-their-kind)
- [ ] `[runtime]` [Serialize request bodies with `System.Text.Json`](#serialize-request-bodies-with-systemtextjson)
- [ ] `[runtime]` [Know that a params property left `null` is left out](#a-params-property-left-null-is-left-out)
- [ ] `[runtime]` [Pass user ids as strings of digits](#user-ids-are-strings-of-digits)
- [ ] `[runtime]` [Pass key versions as the X API returns them](#key-versions-are-integers-written-as-strings)
- [ ] `[runtime]` [Pass entities, files, URL cards and posts the SDK accepts](#entities-files-url-cards-and-posts-are-checked)
- [ ] `[runtime]` [Store every participant's signing keys, and handle a `null` `LatestVersion`](#latestversion-comes-from-a-verified-key-change)
- [ ] `[runtime]` [Rename every read of `target_message_id` to `target_message_sequence_id`](#target_message_id-holds-a-different-value)
- [ ] `[runtime]` [Store a prepared change's key yourself, not through its JSON](#a-prepared-changes-json-leaves-out-its-key)
- [ ] `[runtime]` [Sign only your own data with `Sign`](#sign-refuses-data-only-the-sdk-signs)
- [ ] `[runtime]` [Skip the events `DecryptEvent` drops](#decrypt-drops-a-removals-title-and-description-re-encryptions)
- [ ] `[runtime]` [Check for keys before `ExportKeys`](#exportkeys-throws-without-keys)
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
under `// 0.5.x`, and then as 0.6.0 code writes them, under `// 0.6.0`. A
snippet with only a `// 0.6.0` half shows code 0.6.0 adds. CI compiles the
0.6.0 half of every snippet on this page against 0.6.0 with `dotnet build`
([`scripts/check_doc_snippets.py`](../../scripts/check_doc_snippets.py)), as
the body of an `async` method, with nullable reference types and implicit
usings on.

`chat` is a `Chat` with your keys loaded, and the other names stand for
your own values: ids, versions, keys and events as the X API returns them,
`keys` for the conversation key map `DecryptEvents` returns, `bundle` for a
`ConversationKeyBundle`, `payload` for a `SendPayload`, `prepared` for a
`PreparedConversationChange`, `keyChange`, `message`, `deleted`, `receipt`
and `groupChange` for a decrypted key change, message, deletion, read
receipt and group change, as `JsonElement`s, and `page` for a page of
`GET /2/chat/conversations/{id}/events`, as a `JsonElement`.
`api.Post(path, body)`, `api.Put(path, body)` and `api.Delete(path, body)`
stand for your HTTP client: each serializes `body` with `System.Text.Json`,
sends it to `https://api.x.com` + `path` with your user access token, and
returns the parsed JSON response as a `JsonElement`. `pathId` is the
conversation id as a request path takes it: a group's `g…` id as is, and a
one-to-one's in its hyphen form, `conversationId.Replace(':', '-')`.
`PhotoAttachment(mediaHashKey)` stands for your code that builds a photo's
`AttachmentDescriptor`; `ShowEdit`, `ShowTitle`, `ShowDescription`,
`ShowAvatar` and `ShowGuessesLeft` for your code that displays an edit, a
group's title, description or avatar, or the PIN attempts left;
`Handle(evt)` for your code that handles a decrypted event;
`LogSkipped(eventB64, error)` for your code that logs an event it skips; and
`StoreConversationKey(conversationId, version, key)` for your code that
stores a conversation key. `pin` is the PIN's bytes, `juiceboxConfig` the
Juicebox config the X API returns, `signingKeyQuery` an
`IEnumerable<SigningKeyEntry>`, and `e` a `ChatXdkException` a call threw.
The types are in the `ChatXdk`, `System.Text` and `System.Text.Json`
namespaces.

## 0. Before you start

### Install 0.6.0

Set the package reference to 0.6.0:

```sh
dotnet add package XDevPlatform.ChatXdk --version 0.6.0
```

or, in the project file, `<PackageReference Include="XDevPlatform.ChatXdk"
Version="0.6.0" />`. It targets .NET 8 (`net8.0`). Every app that shares
conversations with yours reads the formats 0.6.0 sends only once it runs
0.6.0 too, so plan the rollout below before you deploy.

### The package bundles the linux-arm64 native library

The package bundles the native library for 64-bit ARM Linux (`linux-arm64`)
as well, under `runtimes/linux-arm64/native/`, so apps on ARM64 Linux need
no copy of their own. There's no code to change. If you shipped a library
you built to run 0.5.x there, remove it: a 0.5.x build doesn't export the
entry points 0.6.0 calls (see [C ABI](c-abi.md)). The native library is
`chat_xdk_ffi` (`libchat_xdk_ffi.so`, `libchat_xdk_ffi.dylib`,
`chat_xdk_ffi.dll`), built from the `chat-xdk-ffi` crate: name one you
build yourself for another platform the same way.

### Upgrade readers first

0.6.0 sends each message, reply, reaction and edit in one of two formats.
v0 is the format 0.5.x sends. v1 encrypts each message under its own key,
derived from the conversation key, the sender and the message id, and signs
it at signature version 10. A chat sends v1 while the X API's `v1_send`
feature switch is on for it, and v0 otherwise (see [The feature-switch
request](#the-feature-switch-request)). Two group changes also sign at
versions 0.5.x can't verify: a member removal signs at version 11, and a
member add that carries a description at version 8.

0.5.x rejects each of these as a signature verification failure, so upgrade
every app that reads your conversations to 0.6.0 before:

- any of your senders can send v1, that is, before the X API turns
  `v1_send` on for them;
- you remove a member from a group with
  [`PrepareGroupMembersRemove`](#removing-members);
- you pass a description to [`PrepareGroupMembersChange`](#adding-members).

0.6.0 reads both formats, including v1 reply previews, edits and files.
There's no code to change: to see which format a send used, read
`payload.SignatureInfo.SignatureVersion`, `"7"` for v0 and `"10"` for v1.

### The feature-switch request

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

## 1. Symbol index

Every 0.5.x name that changes, with its 0.6.0 form and the section that
shows the change. A name not listed here keeps its 0.5.x form. Search your
code for each name in the first column; [Verify](#5-verify) gives the
search as one command.

| 0.5.x | 0.6.0 | Section |
|---|---|---|
| `new Chat()`, then `chat.Setup(pin, configJson)` and `chat.Unlock(pin, configJson)` with a `string` PIN | `new Chat(configJson)`, then `chat.Setup(pin)` and `chat.Unlock(pin)`, or `SetupAsync` and `UnlockAsync`, with a `byte[]` PIN | [Juicebox](#keys-stored-in-juicebox) |
| `chat.ChangePin(string, string)` | `chat.ChangePin(byte[], byte[])` | [Juicebox](#keys-stored-in-juicebox) |
| `registration.Version`, `registration.GenerateVersion` | Removed: the registration request returns the version (`public_key_version`) | [Registration](#register-keys-with-the-public-key-only) |
| `PublicKeys.Version` | Removed: the `public_key_version` the registration request returns | [Registration](#register-keys-with-the-public-key-only) |
| `chat.SetIdentity(userId, signingKeyVersion)` | `chat.SetIdentity(new SetIdentityParams(userId, signingKeyVersion))` | [SetIdentity](#setidentity-takes-setidentityparams) |
| `chat.ImportKeys(keys)`, `chat.ImportKeys(keys, version)` | `chat.ImportKeys(new ImportKeysParams(keys))`, `new ImportKeysParams(keys) { SigningKeyVersion = version }` | [ImportKeys](#importkeys-takes-importkeysparams) |
| `chat.ExportKeys()` returning `null` without keys | Throws `ChatXdkException` of kind `InvalidState` | [ExportKeys](#exportkeys-throws-without-keys) |
| `chat.DecryptEvents(events, signingKeys)` | `chat.DecryptEvents(new DecryptEventsParams(events) { SigningKeys = signingKeys })` | [DecryptEvents](#decryptevents-takes-decrypteventsparams) |
| `result.Messages`, `DecryptedMessage` | `result.Events`, `DecryptedEvent` | [DecryptEvents](#decryptevents-takes-decrypteventsparams) |
| `chat.DecryptEvent(eventB64, keys, signingKeys)`, `chat.DecryptEvent(eventB64, bundle, signingKeys)` | `chat.DecryptEvent(new DecryptEventParams(eventB64, keys) { SigningKeys = signingKeys })` | [DecryptEvent](#decryptevent-takes-decrypteventparams) |
| `payload.EncryptedContent` | `payload.EncodedMessageCreateEvent` | [SendPayload](#sendpayload-fields-take-the-send-requests-names) |
| `payload.EncodedEventSignature` | `payload.EncodedMessageEventSignature` | [SendPayload](#sendpayload-fields-take-the-send-requests-names) |
| `new EntityDescriptor { Start = .., End = .., EntityType = .. }`, `new UrlAttachmentImageDescriptor { MediaHashKey = .., FilesizeBytes = .., Filename = .. }` | `new EntityDescriptor(start, end, entityType)`, `new UrlAttachmentImageDescriptor(mediaHashKey, filesizeBytes, filename)` | [Constructors](#entities-and-preview-images-take-their-values-in-the-constructor) |
| `new AttachmentDescriptor { AttachmentType = .., .. }` | `AttachmentDescriptor.Media(..)`, `UrlCard(..)` or `Post(..)` | [Constructors](#entities-and-preview-images-take-their-values-in-the-constructor) |
| `chat.EncryptStream(plaintext, key)` | `chat.EncryptFile(new EncryptFileParams(file, eventB64, mediaHashKey))` | [Files](#encrypt-a-file-from-its-message) |
| `chat.DecryptStream(encrypted, key)` | `chat.DecryptFile(new DecryptFileParams(encrypted, eventB64, keys, mediaHashKey))` | [Files](#decrypt-a-file-with-its-messages-event) |
| `chat.StreamEncryptor(key)`, `chat.StreamDecryptor(key)`, `StreamEncryptor`, `StreamDecryptor` | `chat.FileEncryptor(new FileEncryptorParams(..))`, `chat.FileDecryptor(new FileDecryptorParams(..))`, `FileEncryptor`, `FileDecryptor` | [Large files](#encrypt-and-decrypt-large-files-in-chunks) |
| `ChatXdkUtilities.EncryptedStreamSize(n)` | `ChatXdkUtilities.EncryptedFileSize(n)` | [Files](#encrypt-a-file-from-its-message) |
| `chat.Encrypt(plaintext, key)` | Removed: titles and descriptions go through `PrepareGroupTitleChange`, `PrepareGroupDescriptionChange` and the group creates and member adds; avatar URLs aren't encrypted; files go through `EncryptFile` | [Changing the title](#changing-the-title) |
| `ActionSignature.Signature`, `SignatureVersion`, `PublicKeyVersion`, `SignaturePayload` | `ActionSignature.MessageEventSignature`; pass `ActionSignatures` as returned | [Action signatures](#action-signatures-come-nested) |
| `PublicKeyInput.PublicKey`, `KeyVersion` | `IdentityPublicKey`, `PublicKeyVersion` | [Public key inputs](#public-key-inputs-name-the-identity-key-and-its-version) |
| `prepared.ParticipantKeys`, `EncryptedKeyForRecipient`, `EncryptedKey` | `prepared.ConversationParticipantKeys`, `ConversationParticipantKey`, `EncryptedConversationKey` | [Participant keys](#participant-keys-take-the-key-requests-names) |
| JSON `participant_keys`, `encrypted_key` of a key change | `conversation_participant_keys`, `encrypted_conversation_key` | [Received keys](#received-participant-keys-take-the-same-names) |
| `PrepareMessageDelete` returning an `ActionSignature` | Returns a `PreparedAction`: `deletion.ActionSignatures[0]` | [Deletes](#deletes-return-a-preparedaction) |
| JSON `key_version` | `conversation_key_version` | [Event names](#decrypted-events-use-the-names-the-calls-take) |
| JSON `target_message_id`, `new_text`, `message_ids`, `seen_until_id` | `target_message_sequence_id`, `updated_text`, `sequence_ids`, `seen_until_sequence_id` | [Event names](#decrypted-events-use-the-names-the-calls-take) |
| Group title and description JSON strings (`title`, `new_title`) | `GroupText` | [Creating a group](#creating-a-group) |
| `GroupCreateParams.AvatarUrl` | Removed: set the avatar with `PrepareGroupAvatarChange` | [Creating a group](#creating-a-group) |
| `EncryptReplyParams.ReplyToSenderId` (a `long?`) | A `string?` | [User ids](#user-ids-are-strings-of-digits) |
| `e.Message.StartsWith("Invalid state:")` | `e.Kind == ChatXdkErrorKind.InvalidInput` | [Errors](#errors-carry-their-kind) |
| `new ChatXdkException(message)` | `new ChatXdkException(kind, message)` | [Errors](#errors-carry-their-kind) |

## 2. Compile-time changes

These changes are in the order an app meets them: creating the chat,
registering, loading keys, decrypting, encrypting and sending, files,
prepared changes, decrypted events and errors.

### Keys stored in Juicebox

A chat that keeps its keys in Juicebox takes the Juicebox config the X API
returns when it's created, with `new Chat(juiceboxConfig)`, or later with
`UpdateConfig`, on first boot, before the account has one. `Setup` and
`Unlock` take only the PIN, as `ChangePin` and `Delete` take no config, and
every PIN is a `byte[]`, so you can zero it once the call returns.
`SetupAsync`, `UnlockAsync`, `ChangePinAsync` and `DeleteAsync` run the same
calls off the calling thread, and `new Chat()` creates a chat that manages
its keys with `ImportKeys` and `ExportKeys` alone:

```csharp
// 0.5.x
using var chat = new Chat();
chat.Unlock(Encoding.UTF8.GetString(pin), juiceboxConfig);

// 0.6.0
using var chat = new Chat(juiceboxConfig);
await chat.UnlockAsync(pin);
Array.Clear(pin);
```

Every method of a `Chat`, `UpdateConfig` included, is safe to call from
several threads at once; a Juicebox call already under way keeps the config
it started with. A wrong PIN throws a `ChatXdkException` of kind
`InvalidPin` (see [Errors carry their kind](#errors-carry-their-kind)), and
a chat without a config fails its Juicebox calls (see [An empty Juicebox
config fails](#an-empty-juicebox-config-fails)).

### Register keys with the public key only

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

`PublicKeys`, which `GetPublicKeys` and `Setup` return, holds the two public
keys, `Identity` and `Signing`, and no `Version`: their version is the
`public_key_version` the registration request returns.

### `SetIdentity` takes `SetIdentityParams`

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

### `ImportKeys` takes `ImportKeysParams`

Pass the saved key bytes in an `ImportKeysParams`, and optionally the
signing-key version they were registered under as `SigningKeyVersion`.
Without a version, call `SetIdentity` before the first signed call.
`ExportKeys` still takes no arguments, and returns a `byte[]` that is never
`null` (see [`ExportKeys` throws without
keys](#exportkeys-throws-without-keys) for a chat without keys).

```csharp
// 0.5.x
chat.ImportKeys(privateKeys);
chat.ImportKeys(privateKeys, signingKeyVersion);

// 0.6.0
chat.ImportKeys(new ImportKeysParams(privateKeys));
chat.ImportKeys(new ImportKeysParams(privateKeys) { SigningKeyVersion = signingKeyVersion });
```

### `DecryptEvents` takes `DecryptEventsParams`

Pass the events, an `IReadOnlyList<string>` such as an array or a list, in
a `DecryptEventsParams`, and the signing keys as `SigningKeys`. Left
`null`, the keys `SetSigningKeys` stored verify the events. Per-event
errors, events decrypt drops included, are still collected in the result's
`Errors`, and the call throws only for invalid params. The result holds the
decrypted events, of every event type, in `Events`, each a
`DecryptedEvent`. The events of `DecryptEvents` and the signing keys of
both decrypt calls are `IReadOnlyList`s, where 0.5.x took any
`IEnumerable`, so call `ToList()` on a LINQ query:

```csharp
// 0.5.x
var result = chat.DecryptEvents(events, signingKeys);
foreach (var decrypted in result.Messages) Handle(decrypted.Event);
var fromQuery = chat.DecryptEvents(events, signingKeyQuery);

// 0.6.0
var result = chat.DecryptEvents(new DecryptEventsParams(events) { SigningKeys = signingKeys });
foreach (var decrypted in result.Events) Handle(decrypted.Event);
var fromQuery = chat.DecryptEvents(new DecryptEventsParams(events) { SigningKeys = signingKeyQuery.ToList() });
```

The version to encrypt with, `result.ConversationKeys.LatestVersion`, comes
only from a key change that verified (see [`LatestVersion` comes from a
verified key change](#latestversion-comes-from-a-verified-key-change)).

### `DecryptEvent` takes `DecryptEventParams`

Pass the event and the conversation key map in a `DecryptEventParams`, and
the signing keys as `SigningKeys`. `new DecryptEventParams(eventB64)`
resolves the key from the key cache (`SetCacheKeys(true)`), and `null`
signing keys verify with the keys `SetSigningKeys` stored. For a
`ConversationKeyBundle`, pass its `Keys`. The call still throws on failure,
and for an event decrypt drops (see [Decrypt drops a removal's title and
description re-encryptions](#decrypt-drops-a-removals-title-and-description-re-encryptions)).

```csharp
// 0.5.x
var evt = chat.DecryptEvent(eventB64, keys, signingKeys);
var fromBundle = chat.DecryptEvent(eventB64, bundle, signingKeys);

// 0.6.0
var evt = chat.DecryptEvent(new DecryptEventParams(eventB64, keys) { SigningKeys = signingKeys });
var fromBundle = chat.DecryptEvent(new DecryptEventParams(eventB64, bundle.Keys) { SigningKeys = signingKeys });
```

### `SendPayload` fields take the send request's names

The two encoded fields carry the names of the fields of the send request,
`POST /2/chat/conversations/{id}/messages`, so the request takes them as
they are. Read them under those names wherever your code reads a payload,
including code that stores payloads. The request also takes the payload's
`XdkVersion`, the version of the SDK that built it, as `xdk_version`:

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
    ["xdk_version"] = payload.XdkVersion,
};
```

A payload also carries `EventB64`, the message as recipients receive it. It
isn't part of the send request: keep it to encrypt the message's files (see
[Encrypt a file from its message](#encrypt-a-file-from-its-message)).

### Entities and preview images take their values in the constructor

An `EntityDescriptor` takes its start, end and type in its constructor, and
a `UrlAttachmentImageDescriptor` its media hash key, size and filename, with
`Width` and `Height` set in an initializer. Those values are read-only, and
an `AttachmentDescriptor` comes only from `AttachmentDescriptor.Media`,
`UrlCard` or `Post`, so none of them can leave a required value at `""` or
`0`:

```csharp
// 0.5.x
var mention = new EntityDescriptor { Start = 0, End = 5, EntityType = "mention" };
var banner = new UrlAttachmentImageDescriptor
{
    MediaHashKey = mediaHashKey,
    FilesizeBytes = (long)ChatXdkUtilities.EncryptedStreamSize((ulong)photo.Length),
    Filename = "banner.jpg",
    Width = 1200,
};

// 0.6.0
var mention = new EntityDescriptor(0, 5, "mention");
var banner = new UrlAttachmentImageDescriptor(
    mediaHashKey, (long)ChatXdkUtilities.EncryptedFileSize((ulong)photo.Length), "banner.jpg")
{
    Width = 1200,
};
var card = AttachmentDescriptor.UrlCard("https://example.com", "Example", banner);
```

### Encrypt a file from its message

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
signature: use `verified` from `DecryptEvent` for that.

```csharp
// 0.5.x
var plaintext = chat.DecryptStream(downloaded, keys[conversationKeyVersion]);

// 0.6.0
var plaintext = chat.DecryptFile(new DecryptFileParams(downloaded, fileEventB64, keys, fileHashKey));
```

### Encrypt and decrypt large files in chunks

`FileEncryptor` and `FileDecryptor` take the same values as `EncryptFile`
and `DecryptFile`, without the file bytes, and return a `FileEncryptor` or
a `FileDecryptor`, classes that keep the 0.5.x `Push`, `Finish` and
`Dispose`. Size an upload with `ChatXdkUtilities.EncryptedFileSize`.

```csharp
// 0.5.x
var size = ChatXdkUtilities.EncryptedStreamSize((ulong)photo.Length);
using StreamEncryptor encryptor = chat.StreamEncryptor(conversationKey);
using StreamDecryptor decryptor = chat.StreamDecryptor(keys[conversationKeyVersion]);

// 0.6.0
var size = ChatXdkUtilities.EncryptedFileSize((ulong)photo.Length);
using FileEncryptor encryptor = chat.FileEncryptor(new FileEncryptorParams(payload.EventB64, mediaHashKey));
using FileDecryptor decryptor = chat.FileDecryptor(new FileDecryptorParams(fileEventB64, keys, fileHashKey));
```

### Action signatures come nested

The prepare methods return each `ActionSignature` in the shape a request's
`action_signatures` takes: `MessageId`, `EncodedMessageEventDetail`, the
signature in `MessageEventSignature` (a `MessageEventSignature` with
`SigningPublicKey`, your signing public key as `GetPublicKeys` returns it),
and nothing else: the signed payload stays inside the SDK. Their JSON names
are the request's snake_case names, so serialize them as returned (see
[Serialize request bodies with
`System.Text.Json`](#serialize-request-bodies-with-systemtextjson)):

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

### Public key inputs name the identity key and its version

A `PublicKeyInput`, one participant a conversation key is encrypted to,
names its key `IdentityPublicKey` and the key's version `PublicKeyVersion`,
as `SigningKeyEntry` does: the `public_key` the X API returns for a user is
their identity key. All three properties stay `required`:

```csharp
// 0.5.x
var input = new PublicKeyInput { UserId = userId, PublicKey = identityPublicKey, KeyVersion = publicKeyVersion };

// 0.6.0
var input = new PublicKeyInput { UserId = userId, IdentityPublicKey = identityPublicKey, PublicKeyVersion = publicKeyVersion };
```

### Participant keys take the key requests' names

A prepared change's participant keys carry the names the X API gives them in
every request that takes them (`POST /2/chat/conversations/{id}/keys`,
`/group` and `/{id}/members`, and `PUT /2/chat/conversations/{id}`):
`ConversationParticipantKeys`, a list of `ConversationParticipantKey` whose
properties (`UserId`, `EncryptedConversationKey`, `PublicKeyVersion`)
serialize as `user_id`, `encrypted_conversation_key` and
`public_key_version`, the names a received key change uses too (see
[Received participant keys take the same
names](#received-participant-keys-take-the-same-names)). Drop the renaming
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

### Received participant keys take the same names

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

### Deletes return a `PreparedAction`

`PrepareMessageDelete` returns a `PreparedAction` whose `ActionSignatures`
hold one entry, shaped as [Action signatures come
nested](#action-signatures-come-nested) shows. Read the action's `MessageId`
from that entry, and send `ActionSignatures` as returned (see [Deleting
messages](#deleting-messages) for the request):

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

### Decrypted events use the names the calls take

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
Don't keep `target_message_id`: in 0.6.0 it names a different value, and
reading it from a `JsonElement` compiles** (see [`target_message_id` holds
a different value](#target_message_id-holds-a-different-value)).

```csharp
// 0.5.x
var content = message.GetProperty("content");
if (content.GetProperty("content_type").GetString() == "Edit")
{
    ShowEdit(content.GetProperty("target_message_id").GetString(), content.GetProperty("new_text").GetString());
}
var deletedSequenceIds = deleted.GetProperty("message_ids");
var seenUntil = receipt.GetProperty("seen_until_id").GetString();

// 0.6.0
var content = message.GetProperty("content");
if (content.GetProperty("content_type").GetString() == "Edit")
{
    ShowEdit(content.GetProperty("target_message_sequence_id").GetString(), content.GetProperty("updated_text").GetString());
}
var deletedSequenceIds = deleted.GetProperty("sequence_ids");
var seenUntil = receipt.GetProperty("seen_until_sequence_id").GetString();
```

A group create's `title`, and a title or description change's `new_title`
or `new_description`, is a `GroupText` object rather than a string (see
[Creating a group](#creating-a-group)).

### Errors carry their kind

Every SDK failure throws a `ChatXdkException`, whose `Kind`, a
`ChatXdkErrorKind`, names the failure the same way in every binding:
`InvalidInput`, `InvalidState`, `Parse`, `Decryption`, `Verification`,
`InvalidPin`, `Juicebox` or `Internal`. After a wrong PIN, its
`GuessesRemaining` holds the attempts Juicebox reports left, `0` once the
stored keys are locked and `null` when Juicebox reports no count. Its
constructor takes the kind first, for code that throws one itself.

A missing or invalid parameter throws one of kind `InvalidInput` with a
message that names the value, such as `Invalid sender_id 'user-1': pass a
numeric user id (digits only)` or `too many attachments: at most 10 per
message`, without an `Invalid state:` prefix. That covers a key or
signature that `Verify`, `VerifyKeyBinding` or `MatchesRegisteredKey` can't
decode. Errors about state the chat lacks, such as a missing session
identity or an empty key cache, are of kind `InvalidState` and keep their
prefix. Tell them apart by kind rather than by message:

```csharp
// 0.5.x
var invalidInput = !e.Message.StartsWith("Invalid state:");

// 0.6.0
var invalidInput = e.Kind == ChatXdkErrorKind.InvalidInput;
ShowGuessesLeft(e.GuessesRemaining);
```

## 3. Runtime and behavior changes

Nothing reports these changes before the code runs: each one is a value the
SDK checks, a value with a new meaning, or an event handled differently.

### Serialize request bodies with `System.Text.Json`

The SDK's types carry `System.Text.Json` `[JsonPropertyName]` names, the X
API's snake_case ones: an `ActionSignature` serializes as `message_id`,
`encoded_message_event_detail` and `message_event_signature`. Serialize
request bodies with `System.Text.Json`, as the snippets do and as
`HttpClient`'s `PostAsJsonAsync` does. A serializer that ignores its
attributes, such as Newtonsoft.Json, writes the .NET property names,
PascalCase, which the X API rejects, and writes a prepared change's
`ConversationKey`, which `System.Text.Json` leaves out (see [A prepared
change's JSON leaves out its key](#a-prepared-changes-json-leaves-out-its-key)).

### A params property left `null` is left out

Each call hands its params to the native library as a JSON document, which
leaves out every property left `null`, where 0.5.x wrote it as JSON `null`.
An optional property left `null` still resolves from the session identity,
the key cache or the stored signing keys. A required one left `null`, which
the compiler's nullable warnings flag, fails with a `ChatXdkException` of
kind `InvalidInput` that names it, such as `` Invalid params JSON: missing
field `conversation_id` ``. There's no code to change.

### User ids are strings of digits

Every user id is a string of digits: the `SetIdentityParams` user id,
`SenderId`, `ReplyToSenderId`, the `UserId` of each `PublicKeyInput` and
`SigningKeyEntry`, and the ids of a group's members and admins
(`MemberIds`, `AdminIds`, `NewMemberIds`, `CurrentMemberIds`,
`CurrentAdminIds`, `CurrentPendingMemberIds` and `UserIds`). Each must be a
positive integer written without a sign or leading zeros; anything else
throws `ChatXdkException` naming the field, such as `Invalid sender_id
'user-1': pass a numeric user id (digits only)`.
`EncryptReplyParams.ReplyToSenderId` is a `string?`:

```csharp
// 0.5.x
var reply = new EncryptReplyParams(conversationId, "pong", eventB64) { ReplyToSenderId = 4201 };

// 0.6.0
var reply = new EncryptReplyParams(conversationId, "pong", eventB64) { ReplyToSenderId = "4201" };
```

### Key versions are integers written as strings

Every key version is a non-negative integer written as a string of digits,
as the X API returns it: the signing-key version (in `SetIdentityParams`,
`ImportKeysParams`, a call's `SigningKeyVersion` and each public key's
`PublicKeyVersion`) and `ConversationKeyVersion`. Anything else throws
`ChatXdkException` naming the field, such as `Invalid signing_key_version
'v1': pass the key version as the X API returns it, an integer in digits`.
There's no code to change if you pass the versions the X API returns.

### Entities, files, URL cards and posts are checked

The encrypt calls check what a message carries before they encrypt it, and
throw a `ChatXdkException` of kind `InvalidInput` naming the value, where
0.5.x sent it:

- An entity of a type the SDK doesn't know, an empty one included, fails
  with `Invalid entity_type 'user_mention': pass url, mention, hashtag,
  cashtag, email, address or phone_number`, for a message's, a reply's, a
  reply preview's and an edit's entities.
- Entity offsets count bytes of the text's UTF-8 encoding, the start
  inclusive and the end exclusive, not the UTF-16 units of a .NET string.
  An entity whose offsets are negative, end before they start or run past
  the end of the text fails, such as `Invalid entity offsets 3..8: end is
  past the end of the text, which is 7 bytes of UTF-8`. A reply preview's
  entities, which index the quoted message's text, are checked for all but
  the end.
- A file a message carries, a media attachment or a URL card's banner or
  favicon, fails with an empty `Filename`, a `FilesizeBytes` of 0 or less,
  or a negative `Width` or `Height`, since receiving clients discard such a
  file. Give each file its name and the encrypted size
  `ChatXdkUtilities.EncryptedFileSize` gives.
- A message that lists an empty media hash key, or one media hash key in
  two attachments, fails.
- A URL card with an empty `Url`, and a post attachment with neither
  `RestId` nor `PostUrl`, fail.

Count an entity's offsets in bytes of UTF-8 when the text holds characters
outside ASCII:

```csharp
// 0.6.0
var text = "café @bob";
var start = Encoding.UTF8.GetByteCount(text[..text.IndexOf("@bob")]);
var end = start + Encoding.UTF8.GetByteCount("@bob");
var sent = chat.EncryptMessage(new EncryptMessageParams(conversationId, text)
{
    Entities = new[] { new EntityDescriptor(start, end, "mention") },
});
```

### `LatestVersion` comes from a verified key change

`result.ConversationKeys.LatestVersion`, the version to encrypt with, is
the newest version whose key change verified, and it never moves back for
the chat's lifetime. A key change verifies only against its sender's
signing key, so give the chat every participant's signing keys, your own
included, before you decrypt. It's `null` until a key change verifies: a
key change the SDK can't verify still adds its key to
`result.ConversationKeys.Keys`, for decrypting, but never becomes the
version you encrypt with. Where 0.5.x returned the batch's highest version,
0.6.0 can return `null`: fetch the missing signing keys or the
conversation's key-change events and decrypt again, rather than encrypting
under the highest key in `Keys`:

```csharp
// 0.5.x
var result = chat.DecryptEvents(events, signingKeys);
var version = result.ConversationKeys.LatestVersion;

// 0.6.0
chat.SetSigningKeys(signingKeys);
var result = chat.DecryptEvents(new DecryptEventsParams(events));
var version = result.ConversationKeys.LatestVersion;
if (version is null)
{
    // No key change verified: fetch every participant's signing keys
    // (GET /2/users/{id}/public_keys) and the conversation's key changes
    // (meta.conversation_key_events of GET /2/chat/conversations/{id}/events),
    // then decrypt again.
    return;
}
```

### `target_message_id` holds a different value

**In 0.5.x a reaction's or edit's `target_message_id` held the target's
sequence id. In 0.6.0 that value is `target_message_sequence_id`, and
`target_message_id` holds the edited message's signed message id, present
only on a v1 edit.** Decrypted events are `JsonElement`s, so code that
keeps reading `target_message_id` compiles: it gets the wrong id, or throws
`KeyNotFoundException` where the property is absent. Rename every read, as
[Decrypted events use the names the calls
take](#decrypted-events-use-the-names-the-calls-take) shows, and use
`target_message_id` only to match a v1 edit to the `message_id` you
deduplicate on.

### A prepared change's JSON leaves out its key

A `PreparedConversationChange`'s `ConversationKey` is `[JsonIgnore]`, where
0.5.x serialized it as `conversation_key`. The key stays on the object, a
`byte[]` that is never `null`, but `System.Text.Json` leaves it out of the
JSON: code that saved or queued a prepared change as JSON loses the key,
and with it the conversation. Store the key yourself, and serialize the
rest:

```csharp
// 0.5.x
var saved = JsonSerializer.Serialize(prepared);

// 0.6.0
StoreConversationKey(prepared.ConversationId, prepared.ConversationKeyVersion, prepared.ConversationKey);
var saved = JsonSerializer.Serialize(prepared);
```

The request bodies take only a change's participant keys, key version and
action signatures, never the key itself.

### `Sign` refuses data only the SDK signs

`Sign` throws a `ChatXdkException` of kind `InvalidInput` for a payload
recipients would verify as a signed event (a message, conversation-key
change, group or conversation-metadata change, delete or read receipt) and
for a P-256 public key, whose signature by the signing key binds it as an
identity key. Sign only your own application data with `Sign`; the SDK
signs events itself. Any other data signs as in 0.5.x:

```csharp
// 0.6.0
byte[]? signature;
try
{
    signature = chat.Sign(data);
}
catch (ChatXdkException refused) when (refused.Kind == ChatXdkErrorKind.InvalidInput)
{
    // The data reads as an event or a public key, which only the SDK signs.
    signature = null;
}
```

### Decrypt drops a removal's title and description re-encryptions

A member removal rotates the conversation key and re-encrypts the group's
title and description under the new key, marked as key-rotation
re-encryptions. They are the same text, not changes, so `DecryptEvents`
and `DecryptEvent` drop them under either `SetRejectUnverified` setting,
the way they drop an unverified event: `DecryptEvents` leaves each one out
of `Events` and records it in `Errors`, and `DecryptEvent` throws a
`ChatXdkException` of kind `InvalidInput`: `GroupChange re-encrypts the
group's title for a key rotation (for_key_rotation), not a title change:
decrypt does not return it`. The removal itself (`MembersRemoved`), its key
change, avatar changes and every title or description change without the
mark decrypt as before. In 0.5.x, a removal by an X client arrived as a
`TitleChanged` carrying the group's unchanged title:

```csharp
// 0.5.x
foreach (var decrypted in result.Messages)
{
    if (decrypted.Event.TryGetProperty("change", out var change)
        && change.GetProperty("change_type").GetString() == "TitleChanged")
    {
        ShowTitle(chat.Decrypt(change.GetProperty("new_title").GetString()!, keys[conversationKeyVersion]));
    }
}

// 0.6.0
var result = chat.DecryptEvents(new DecryptEventsParams(events));
foreach (var decrypted in result.Events)
{
    if (decrypted.Event.TryGetProperty("change", out var change)
        && change.GetProperty("change_type").GetString() == "TitleChanged")
    {
        var newTitle = change.GetProperty("new_title").Deserialize<GroupText>()!;
        ShowTitle(newTitle.Kind == "Text" ? newTitle.Text! : newTitle.Raw!);
    }
}
```

A loop over single events catches the exception, as it catches an
unverified event's, and moves on to the next event:

```csharp
// 0.6.0
foreach (var item in page.GetProperty("data").EnumerateArray())
{
    var eventB64 = item.GetProperty("encoded_event").GetString()!;
    JsonElement evt;
    try
    {
        evt = chat.DecryptEvent(new DecryptEventParams(eventB64, keys));
    }
    catch (ChatXdkException skipped)
    {
        LogSkipped(eventB64, skipped);
        continue;
    }
    Handle(evt);
}
```

### `ExportKeys` throws without keys

`ExportKeys` returns a `byte[]` and throws a `ChatXdkException` of kind
`InvalidState` when no identity key is loaded, where 0.5.x returned `null`;
check `HasIdentityKey` first where that can happen:

```csharp
// 0.5.x
var exported = chat.ExportKeys();

// 0.6.0
var exported = chat.HasIdentityKey ? chat.ExportKeys() : null;
```

### An empty Juicebox config fails

Until a chat has a Juicebox config, `Setup`, `Unlock`, `ChangePin` and
`Delete` and their async forms throw a `ChatXdkException` of kind
`InvalidState`, `Invalid state: no Juicebox config: pass the
juicebox_config the X API returns when you create the chat, or call
update_config() first`, the error every binding gives. `new Chat(config)`
and `UpdateConfig` throw it for an empty or blank config, at once, rather
than at the first Juicebox call; `new Chat()` creates a chat without one.

## 4. Group and receipt signing

Recipients on the default `SetRejectUnverified` policy drop a read receipt
or group change that isn't signed, as 0.5.x recipients did: sign each one,
or recipients never see it. The sender comes from `SetIdentity`. Each
prepare call returns `ActionSignatures` shaped as [Action signatures come
nested](#action-signatures-come-nested) shows; serialize them into the
request as returned, with `System.Text.Json`.

### The requests

Each request below takes the conversation id in its path as `pathId`, and
the prepare call's `ActionSignatures` as returned, as `action_signatures`.
The paths and body fields are the X API's, as its OpenAPI description
(`https://api.x.com/2/openapi.json`) gives them.

| Action | Call | Request | Body |
|---|---|---|---|
| Send a message, reply, reaction or edit | `EncryptMessage`, `EncryptReply`, `EncryptAddReaction`, `EncryptRemoveReaction`, `EncryptEdit` | `POST /2/chat/conversations/{id}/messages` | `message_id`, `encoded_message_create_event`, `encoded_message_event_signature`, `xdk_version`: the payload's `MessageId`, `EncodedMessageCreateEvent`, `EncodedMessageEventSignature` and `XdkVersion` |
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
| Turn the invite link on | `PrepareGroupInviteEnable` | `POST /2/chat/conversations/{id}/invite` | `invite_url`; `validity_expiry_timestamp_msec` (the params' `ExpiresAtMsec`) and `affiliate_user_id` (the params' `AffiliateId`) when set; `action_signatures` |
| Turn the invite link off | `PrepareGroupInviteDisable` | `DELETE /2/chat/conversations/{id}/invite` | `action_signatures` |
| Ask to join | `PrepareGroupJoinRequest` | `POST /2/chat/conversations/{id}/join_requests` | `token` (the invite link's last 10 characters), `action_signatures` |
| Reject join requests | `PrepareGroupJoinReject` | `POST /2/chat/conversations/{id}/join_requests/reject` | `user_ids`, `action_signatures` |
| Set the message TTL | `PrepareMessageTtlChange` | `PUT /2/chat/conversations/{id}/message_ttl` | `message_ttl_ms` (the params' `TtlMsec`, as a string), `action_signatures` |
| Clear the message TTL | `PrepareMessageTtlRemove` | `DELETE /2/chat/conversations/{id}/message_ttl` | `action_signatures` |
| Change screen capture | `PrepareScreenCapture` | `PUT /2/chat/conversations/{id}/screen_capture` | `blocking` (`true` for `BlockingEnabled`, `false` for `BlockingDisabled`) and `blocking_action_signatures`, or `detection` and `detection_action_signatures` |

A group's `conversation_id` is the `g…` id that
`POST /2/chat/conversations/group/initialize` returns as
`data.conversation_id`.

### Deleting messages

`PrepareMessageDelete` returns the action's signature nested, as every
prepare call does: send `ActionSignatures` as returned, next to the
sequence ids and the delete action the params signed.

```csharp
// 0.5.x
var deletion = chat.PrepareMessageDelete(new MessageDeleteParams(conversationId, sequenceIds, deleteForAll: true));
api.Post($"/2/chat/conversations/{pathId}/messages/delete", new
{
    sequence_ids = sequenceIds,
    delete_message_action = "delete_for_all",
    action_signatures = new[]
    {
        new
        {
            message_id = deletion.MessageId,
            encoded_message_event_detail = deletion.EncodedMessageEventDetail,
            message_event_signature = new
            {
                signature = deletion.Signature,
                signature_version = deletion.SignatureVersion,
                public_key_version = deletion.PublicKeyVersion,
                signing_public_key = signingPublicKey,
            },
        },
    },
});

// 0.6.0
var deletion = chat.PrepareMessageDelete(new MessageDeleteParams(conversationId, sequenceIds, deleteForAll: true));
api.Post($"/2/chat/conversations/{pathId}/messages/delete", new
{
    sequence_ids = sequenceIds,
    delete_message_action = "delete_for_all",
    action_signatures = deletion.ActionSignatures,
});
```

A recipient's `DecryptEvent` returns the delete as a verified
`MessageDeleted` event with its `sequence_ids` and `delete_for_all`.

### Read receipts are signed

Sign a read receipt with `PrepareMarkConversationRead` and send the
`PreparedAction`'s `ActionSignatures` as the `action_signatures` of
`POST /2/chat/conversations/{id}/read`. The call takes a
`MarkConversationReadParams` (the conversation id, the sequence id of the
newest event read, and a `SeenAtMsec` that defaults to now) and returns a
`PreparedAction`, one entry. Without it the X API sends an unsigned
receipt, which recipients drop.

```csharp
// 0.5.x
api.Post($"/2/chat/conversations/{pathId}/read", new { });

// 0.6.0
var receipt = chat.PrepareMarkConversationRead(
    new MarkConversationReadParams(conversationId, seenUntilSequenceId));
api.Post($"/2/chat/conversations/{pathId}/read", new { action_signatures = receipt.ActionSignatures });
```

A recipient's `DecryptEvent` returns a signed receipt as a verified
`ReadReceipt` event, its position in `seen_until_sequence_id`.

### Group changes are signed

Every group change below returns `ActionSignatures` for its request in
[The requests](#the-requests). A group's title and description travel
encrypted under the conversation key, and the SDK encrypts them: the
creates, member adds, removals and title and description changes take them
as plaintext and return the encrypted values to send. An avatar is an image
the app encrypts and uploads; its URL is signed as is.

### Creating a group

`PrepareGroupCreate` encrypts the group's title under the conversation key
it creates, so set it as plaintext. The result is a
`PreparedConversationChange` that also carries it encrypted, as
`EncryptedTitle` (null when unset): send that as the create request's
`group_name`, next to its participant keys and signatures. The create signs
the encrypted value, which is base64, so a title may contain a comma; a
value signed as is, such as an avatar URL, can't. A create sets no avatar:
set one afterwards with an [avatar change](#changing-the-avatar), with the
image encrypted under the key the create returns.

```csharp
// 0.5.x
var prepared = chat.PrepareGroupCreate(
    new GroupCreateParams(publicKeys, conversationId, memberIds, adminIds) { Title = title, AvatarUrl = avatarUrl });
var body = new { group_name = title, group_avatar_url = avatarUrl };

// 0.6.0
var prepared = chat.PrepareGroupCreate(
    new GroupCreateParams(publicKeys, conversationId, memberIds, adminIds) { Title = title });
api.Post("/2/chat/conversations/group", new
{
    conversation_id = conversationId,
    group_members = memberIds,
    group_admins = adminIds,
    group_name = prepared.EncryptedTitle,
    conversation_key_version = prepared.ConversationKeyVersion,
    conversation_participant_keys = prepared.ConversationParticipantKeys,
    action_signatures = prepared.ActionSignatures,
});
StoreConversationKey(conversationId, prepared.ConversationKeyVersion, prepared.ConversationKey);
```

`DecryptEvent` returns a received group create with its title decrypted with
the key for the version the create names, from the call's key map or the key
cache: a `Created` change's `title` deserializes to a `GroupText` with
`Deserialize<GroupText>()`. `Kind` `"Text"` holds the title in `Text`.
`Kind` `"Unavailable"` holds, in `Raw`, the value as the create carries it,
when that key isn't there or the value doesn't decrypt under it, and the
rest of the create still decrypts. 0.5.x signed a create's title as the app
passed it, so a 0.5.x app's create with a plaintext title arrives as
`"Unavailable"` with the title in `Raw`: show `Raw` when a title isn't
decryptable. A create that names no key version carries its title as
plaintext, and arrives as `"Text"`. The encrypted `group_name` and
`group_description` the X API returns with a conversation open with
`Decrypt`.

```csharp
// 0.5.x
var change = groupChange.GetProperty("change");
if (change.GetProperty("change_type").GetString() == "Created"
    && change.GetProperty("title").GetString() is string encryptedTitle)
{
    ShowTitle(chat.Decrypt(encryptedTitle, keys[conversationKeyVersion]));
}

// 0.6.0
var change = groupChange.GetProperty("change");
if (change.GetProperty("change_type").GetString() == "Created"
    && change.GetProperty("title").Deserialize<GroupText>() is GroupText groupTitle)
{
    ShowTitle(groupTitle.Kind == "Text" ? groupTitle.Text! : groupTitle.Raw!);
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
`EncryptedDescription` (null when unset). Send `EncryptedTitle` as the
add-members request's `encrypted_title`; the description travels in the
signed member add. Encrypt under the new key from here on, as [Removing
members](#removing-members) shows for a removal.

```csharp
// 0.5.x
var prepared = chat.PrepareGroupMembersChange(
    new GroupMembersChangeParams(publicKeys, conversationId, newMemberIds, memberIds, adminIds, new List<string>())
    {
        CurrentTitle = title,
    });

// 0.6.0
var prepared = chat.PrepareGroupMembersChange(
    new GroupMembersChangeParams(publicKeys, conversationId, newMemberIds, memberIds, adminIds, new List<string>())
    {
        CurrentTitle = title,
        CurrentDescription = description,
    });
api.Post($"/2/chat/conversations/{pathId}/members", new
{
    user_ids = newMemberIds,
    encrypted_title = prepared.EncryptedTitle,
    conversation_key_version = prepared.ConversationKeyVersion,
    conversation_participant_keys = prepared.ConversationParticipantKeys,
    action_signatures = prepared.ActionSignatures,
});
StoreConversationKey(conversationId, prepared.ConversationKeyVersion, prepared.ConversationKey);
```

Passing a description makes the add sign at signature version 8, the first
version whose member-add payload covers one, and 0.5.x readers can't verify
a version-8 add. Until every app that reads your groups runs 0.6.0, leave
the description out, so the add signs at version 7 as in 0.5.x; the new
members can read the description once a description change sets it under the
new key.

The avatar isn't re-encrypted: `CurrentAvatarUrl` takes its media URL,
signed as is, and the image stays encrypted under the key it was uploaded
with, which the new members never receive. To keep the avatar readable for
them, encrypt the image under the key the add returns, upload it, and send
an [avatar change](#changing-the-avatar) naming the new key version.

A recipient's `DecryptEvent` returns the add as a verified `MembersAdded`
change with `member_ids`, `current_member_ids` and `current_admin_ids`.

### Removing members

`PrepareGroupMembersRemove` removes `UserIds` and rotates the conversation
key, so the members removed don't receive the key the group encrypts under
next. `GroupMembersRemoveParams` takes:

- `publicKeys`: the identity key of every member who stays, yours included,
  as `GET /2/users/{id}/public_keys` returns them. The SDK encrypts the new
  key to each member's newest key version; a member left out, you included,
  can't read what the group sends under the new key. The SDK doesn't check
  that the list is complete. A key for a member being removed throws
  `ChatXdkException`.
- `conversationId` and `userIds`, the members to remove.
- `Title` and `Description`: the group's current title and description, as
  plaintext. Set each one the group has; the call encrypts each under the
  new key and signs it as a key-rotation re-encryption, which recipients'
  decrypt drops rather than shows as a change. A rotation leaves the avatar
  alone: its image stays encrypted under the key it was uploaded with,
  which the members who stay hold.

The result is a `PreparedConversationChange`: the new `ConversationKey` and
`ConversationKeyVersion`, `ConversationParticipantKeys` for the members who
stay, and `ActionSignatures` in request order: the removal, a title change
and a description change for the ones set, then the conversation-key
change. The removal signs at signature version 11, which 0.5.x readers
can't verify (see [Upgrade readers first](#upgrade-readers-first)).

```csharp
// 0.5.x
api.Post($"/2/chat/conversations/{pathId}/members/remove", new { user_ids = userIds });

// 0.6.0
var prepared = chat.PrepareGroupMembersRemove(
    new GroupMembersRemoveParams(remainingPublicKeys, conversationId, userIds)
    {
        Title = title,
        Description = description,
    });
api.Post($"/2/chat/conversations/{pathId}/members/remove", new
{
    user_ids = userIds,
    action_signatures = prepared.ActionSignatures,
    group_key_rotation_data = new
    {
        conversation_key_version = prepared.ConversationKeyVersion,
        conversation_participant_keys = prepared.ConversationParticipantKeys,
    },
});
```

**Encrypt under the new key as soon as the request succeeds.** The removed
members hold the old key, so a message encrypted under it is one they can
read. The key cache (`SetCacheKeys(true)`) adopts the new key only once
`DecryptEvents` decrypts the removal's key change from the conversation's
events, and only if that key change verifies against your own signing key;
until then an encrypt call that omits the key resolves the old one. Store
the new key and version, and pass them to every encrypt and prepare call
until the cache holds them:

```csharp
// 0.6.0
StoreConversationKey(conversationId, prepared.ConversationKeyVersion, prepared.ConversationKey);
var sent = chat.EncryptMessage(new EncryptMessageParams(conversationId, "hello")
{
    ConversationKey = prepared.ConversationKey,
    ConversationKeyVersion = prepared.ConversationKeyVersion,
});
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

```csharp
// 0.6.0
var result = chat.DecryptEvents(new DecryptEventsParams(events));
foreach (var decrypted in result.Events)
{
    if (decrypted.Event.TryGetProperty("change", out var change)
        && change.GetProperty("change_type").GetString() == "MembersRemoved")
    {
        var removed = change.GetProperty("member_ids");
    }
}
var version = result.ConversationKeys.LatestVersion;
```

### Leaving a group

`PrepareGroupLeave` signs the sender's removal and does not rotate the
conversation key. `ActionSignatures` are the removal, then a
`GroupAdminAddChange` when `PromoteAdminId` is set, then a
`ConversationDeleteEvent`. It returns a `PreparedAction`. Send it as a
removal of your own id:

```csharp
// 0.5.x
api.Post($"/2/chat/conversations/{pathId}/members/remove", new { user_ids = new[] { myUserId } });

// 0.6.0
var left = chat.PrepareGroupLeave(new GroupLeaveParams(conversationId) { PromoteAdminId = promoteAdminId });
api.Post($"/2/chat/conversations/{pathId}/members/remove", new
{
    user_ids = new[] { myUserId },
    action_signatures = left.ActionSignatures,
});
```

### Changing the title

`PrepareGroupTitleChange` takes the new title as plaintext, encrypts it
under the conversation key and signs it. Like `EncryptMessageParams`,
`GroupTitleChangeParams` takes the key and its version in
`ConversationKey` and `ConversationKeyVersion`, or resolves both from the
key cache when they're null. The result is a `PreparedGroupMetadataChange`:
the `EncryptedValue` the request sends as `group_name`, the
`ConversationKeyVersion` it's encrypted under, and the `ActionSignatures`
to send with it.

```csharp
// 0.5.x
api.Put($"/2/chat/conversations/{pathId}", new
{
    group_name = chat.Encrypt(title, keys[conversationKeyVersion]),
    conversation_key_version = conversationKeyVersion,
    modified_fields = new[] { "group_name" },
});

// 0.6.0
var prepared = chat.PrepareGroupTitleChange(new GroupTitleChangeParams(conversationId, title));
api.Put($"/2/chat/conversations/{pathId}", new
{
    group_name = prepared.EncryptedValue,
    conversation_key_version = prepared.ConversationKeyVersion,
    modified_fields = new[] { "group_name" },
    action_signatures = prepared.ActionSignatures,
});
```

`DecryptEvent` returns a received title change decrypted: the `new_title` of
a `TitleChanged` change deserializes to a `GroupText`, as a create's `title`
does. It decrypts with the key for the version the change names, from the
call's key map or the key cache. Without that key, or when the value isn't
ciphertext under it, as for a plaintext title an app signed with a key
version, it is `"Unavailable"` with the value as carried, and the event
still decrypts. A removal's re-encrypted title never arrives as a
`TitleChanged`.

```csharp
// 0.5.x
var change = groupChange.GetProperty("change");
if (change.GetProperty("change_type").GetString() == "TitleChanged")
{
    ShowTitle(chat.Decrypt(change.GetProperty("new_title").GetString()!, keys[conversationKeyVersion]));
}

// 0.6.0
var change = groupChange.GetProperty("change");
if (change.GetProperty("change_type").GetString() == "TitleChanged")
{
    var newTitle = change.GetProperty("new_title").Deserialize<GroupText>()!;
    ShowTitle(newTitle.Kind == "Text" ? newTitle.Text! : newTitle.Raw!);
}
```

### Changing the description

`PrepareGroupDescriptionChange` takes the new description as plaintext and
returns a `PreparedGroupMetadataChange`, as the title change does; the
request sends its `EncryptedValue` as `group_description`.

```csharp
// 0.5.x
api.Put($"/2/chat/conversations/{pathId}", new
{
    group_description = chat.Encrypt(description, keys[conversationKeyVersion]),
    conversation_key_version = conversationKeyVersion,
    modified_fields = new[] { "group_description" },
});

// 0.6.0
var prepared = chat.PrepareGroupDescriptionChange(new GroupDescriptionChangeParams(conversationId, description));
api.Put($"/2/chat/conversations/{pathId}", new
{
    group_description = prepared.EncryptedValue,
    conversation_key_version = prepared.ConversationKeyVersion,
    modified_fields = new[] { "group_description" },
    action_signatures = prepared.ActionSignatures,
});
```

A received description change is a `DescriptionChanged` change holding
`new_description`, which deserializes to a `GroupText`; read it as a title
change's `new_title`. A removal's re-encrypted description never arrives as
one:

```csharp
// 0.6.0
var change = groupChange.GetProperty("change");
if (change.GetProperty("change_type").GetString() == "DescriptionChanged")
{
    var newDescription = change.GetProperty("new_description").Deserialize<GroupText>()!;
    ShowDescription(newDescription.Kind == "Text" ? newDescription.Text! : newDescription.Raw!);
}
```

### Changing the avatar

An avatar URL is not encrypted; the image is. Encrypt the image bytes under
the conversation key, upload them to the group's media, and pass the image's
media URL to `PrepareGroupAvatarChange`, with the version of the key the
image is encrypted under. The call signs both as they are and returns a
`PreparedAction`; send its `ActionSignatures` with the URL. A URL containing
a comma is rejected, since signatures join their fields with commas.

```csharp
// 0.5.x
api.Put($"/2/chat/conversations/{pathId}", new
{
    group_avatar_url = chat.Encrypt(avatarUrl, keys[conversationKeyVersion]),
    conversation_key_version = conversationKeyVersion,
    modified_fields = new[] { "group_avatar_url" },
});

// 0.6.0
var prepared = chat.PrepareGroupAvatarChange(
    new GroupAvatarChangeParams(conversationId, avatarUrl, conversationKeyVersion));
api.Put($"/2/chat/conversations/{pathId}", new
{
    group_avatar_url = avatarUrl,
    conversation_key_version = conversationKeyVersion,
    modified_fields = new[] { "group_avatar_url" },
    action_signatures = prepared.ActionSignatures,
});
```

A received `AvatarChanged` change holds `new_avatar_url` as sent and its
`conversation_key_version`: download the image and decrypt it with the key
for that version.

```csharp
// 0.6.0
var change = groupChange.GetProperty("change");
if (change.GetProperty("change_type").GetString() == "AvatarChanged")
{
    ShowAvatar(
        change.GetProperty("new_avatar_url").GetString()!,
        change.GetProperty("conversation_key_version").GetString());
}
```

### Admins, invites, join requests, message TTL and screen capture

Each of these calls returns a `PreparedAction` with one signature, at
signature version 7, for the request [The requests](#the-requests) names.
0.5.x apps sent these requests without signatures; recipients drop them
unsigned. A recipient's `DecryptEvent` returns admin, invite and join
changes as verified `GroupChange` events (`AdminsAdded`, `AdminsRemoved`,
`InviteEnabled`, `InviteDisabled`, `JoinRequested`, `JoinRejected`) and TTL
and screen-capture changes as verified `SettingsChange` events.

```csharp
// 0.5.x
api.Post($"/2/chat/conversations/{pathId}/admins", new { user_ids = userIds });

// 0.6.0
var added = chat.PrepareGroupAdminsAdd(new GroupAdminsAddParams(conversationId, userIds));
api.Post($"/2/chat/conversations/{pathId}/admins", new
{
    user_ids = userIds,
    action_signatures = added.ActionSignatures,
});
var removed = chat.PrepareGroupAdminsRemove(new GroupAdminsRemoveParams(conversationId, userIds));
api.Post($"/2/chat/conversations/{pathId}/admins/remove", new
{
    user_ids = userIds,
    action_signatures = removed.ActionSignatures,
});
```

An invite signs its URL, its expiry and its affiliate; a null
`ExpiresAtMsec` or `AffiliateId` signs `null`. The request sends the expiry
as `validity_expiry_timestamp_msec`, and only with the same value the params
signed:

```csharp
// 0.6.0
var invite = chat.PrepareGroupInviteEnable(
    new GroupInviteEnableParams(conversationId, inviteUrl) { ExpiresAtMsec = expiresAtMsec });
api.Post($"/2/chat/conversations/{pathId}/invite", new
{
    invite_url = inviteUrl,
    validity_expiry_timestamp_msec = expiresAtMsec.ToString(),
    action_signatures = invite.ActionSignatures,
});
var disabled = chat.PrepareGroupInviteDisable(new GroupInviteDisableParams(conversationId));
api.Delete($"/2/chat/conversations/{pathId}/invite", new { action_signatures = disabled.ActionSignatures });
```

A join request signs the requesting user, who defaults to the sender; the
invite token travels in the request but not in the signature:

```csharp
// 0.6.0
var request = chat.PrepareGroupJoinRequest(new GroupJoinRequestParams(conversationId));
api.Post($"/2/chat/conversations/{pathId}/join_requests", new
{
    token = inviteToken,
    action_signatures = request.ActionSignatures,
});
var rejected = chat.PrepareGroupJoinReject(new GroupJoinRejectParams(conversationId, userIds));
api.Post($"/2/chat/conversations/{pathId}/join_requests/reject", new
{
    user_ids = userIds,
    action_signatures = rejected.ActionSignatures,
});
```

A TTL change signs `TtlMsec` only; a negative one is rejected:

```csharp
// 0.6.0
var ttl = chat.PrepareMessageTtlChange(new MessageTtlChangeParams(conversationId, ttlMsec));
api.Put($"/2/chat/conversations/{pathId}/message_ttl", new
{
    message_ttl_ms = ttlMsec.ToString(),
    action_signatures = ttl.ActionSignatures,
});
var cleared = chat.PrepareMessageTtlRemove(new MessageTtlRemoveParams(conversationId));
api.Delete($"/2/chat/conversations/{pathId}/message_ttl", new { action_signatures = cleared.ActionSignatures });
```

A screen-capture change is one of `ScreenCaptureChange.BlockingEnabled`,
`BlockingDisabled`, `DetectionEnabled` or `DetectionDisabled`. The request
names its signatures after the setting, `blocking_action_signatures` or
`detection_action_signatures`, not `action_signatures`:

```csharp
// 0.6.0
var capture = chat.PrepareScreenCapture(
    new ScreenCaptureParams(conversationId, ScreenCaptureChange.BlockingEnabled));
api.Put($"/2/chat/conversations/{pathId}/screen_capture", new
{
    blocking = true,
    blocking_action_signatures = capture.ActionSignatures,
});
```

## 5. Verify

### Build

Run `dotnet build` and your tests: the compiler flags every call that still
passes 0.5.x arguments and every renamed property of the SDK's types.
Properties of decrypted events are `JsonElement` lookups, which the
compiler doesn't check: the search below finds them.

### Find the 0.5.x names

Search the app for the names in the symbol index's 0.5.x column. Each hit is
a line to change, unless it is your own code that shares the name:

```sh
grep -rnE "EncryptStream|DecryptStream|StreamEncryptor|StreamDecryptor|EncryptedStreamSize|\.Encrypt\(|EncryptedContent|EncodedEventSignature|GenerateVersion|\.Messages\b|DecryptedMessage|EncryptedKeyForRecipient|\.ParticipantKeys\b|\.EncryptedKey\b|\bKeyVersion\b|\bAvatarUrl\s*=[^=]|AttachmentType\s*=[^=]|\"(participant_keys|encrypted_key|key_version|new_text|message_ids|seen_until_id)\"" --include='*.cs' .
grep -rn "target_message_id" --include='*.cs' .
```

Every `target_message_id` the second search finds should read a v1 edit's
signed message id; rename the rest to `target_message_sequence_id`.

### Run a round trip

This round trip runs offline, with two chats standing in for two users. It
registers both, starts a conversation, sends a message and decrypts it with
`SetRejectUnverified` on, the default, so the signature has to verify:

```csharp
// 0.6.0
using var alice = new Chat();
using var bob = new Chat();
var aliceKeys = alice.GenerateKeypairs().PublicKey;
var bobKeys = bob.GenerateKeypairs().PublicKey;
alice.SetIdentity(new SetIdentityParams("1001", "1"));
bob.SetIdentity(new SetIdentityParams("1002", "1"));

var change = alice.PrepareConversationKeyChange(new ConversationKeyChangeParams(new[]
{
    new PublicKeyInput { UserId = "1001", IdentityPublicKey = aliceKeys.PublicKey, PublicKeyVersion = "1" },
    new PublicKeyInput { UserId = "1002", IdentityPublicKey = bobKeys.PublicKey, PublicKeyVersion = "1" },
}));
var sent = alice.EncryptMessage(new EncryptMessageParams(change.ConversationId, "hello")
{
    ConversationKey = change.ConversationKey,
    ConversationKeyVersion = change.ConversationKeyVersion,
});

var bobEntry = change.ConversationParticipantKeys.First(key => key.UserId == "1002");
var bobKey = bob.DecryptConversationKey(bobEntry.EncryptedConversationKey);
var received = bob.DecryptEvent(new DecryptEventParams(
    sent.EventB64, new Dictionary<string, byte[]> { [change.ConversationKeyVersion] = bobKey })
{
    SigningKeys = new[]
    {
        new SigningKeyEntry
        {
            UserId = "1001",
            PublicKeyVersion = "1",
            PublicKey = aliceKeys.SigningPublicKey,
            IdentityPublicKey = aliceKeys.PublicKey,
            IdentityPublicKeySignature = aliceKeys.IdentityPublicKeySignature,
        },
    },
});
if (!received.GetProperty("verified").GetBoolean()
    || received.GetProperty("content").GetProperty("text").GetString() != "hello")
{
    throw new InvalidOperationException("round trip failed");
}
if (sent.SignatureInfo.SignatureVersion is not ("7" or "10"))
{
    throw new InvalidOperationException($"unknown format {sent.SignatureInfo.SignatureVersion}");
}
if (sent.XdkVersion != "0.6.0")
{
    throw new InvalidOperationException($"xdk version {sent.XdkVersion}");
}
```

`SignatureVersion` is `"7"` for a v0 send and `"10"` for v1, as the
`v1_send` switch decides. `XdkVersion` is the version the X API receives
with each send.

Then run the same flows against a test conversation on the X API: send a
text, a file, a reply, an edit and a delete, mark the conversation read,
and create a group, add a member and remove one. Fetch the conversation's
events with `GET /2/chat/conversations/{id}/events`, pass `data[].encoded_event`
and `meta.conversation_key_events` to `DecryptEvents` with every
participant's signing keys, and check that every event in `Events` has
`verified` set and that `Errors` holds only the removal's title and
description re-encryptions.
