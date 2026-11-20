# chat-xdk .NET bindings

.NET bindings for the X Chat SDK — encryption for X Direct Messages.

## Architecture

```
C# (ChatXdk) → P/Invoke → Rust cdylib (chat_xdk_ffi) → chat-xdk-core
```

Complex values cross the FFI boundary as JSON strings. P/Invoke entry points are generated with csbindgen from `src/lib.rs` into `dotnet/ChatXdk/NativeMethods.g.cs`.

## Prerequisites

- **.NET 8+** SDK
- **Rust** (stable) to build the native `chat_xdk_ffi` library

## Setup

From the repo root, build the native library:

```bash
cargo build -p chat-xdk-ffi --release
```

Then build the managed wrapper:

```bash
cd crates/dotnet/dotnet/ChatXdk
dotnet build -c Release
```

The published `XDevPlatform.ChatXdk` package bundles the native library for macOS (arm64, x64), Linux (x64, arm64, musl-x64) and Windows (x64) under `runtimes/<rid>/native/`. With a wrapper you build yourself, place the native library (`libchat_xdk_ffi.dylib` / `.so` / `chat_xdk_ffi.dll`) on the loader path next to your app. `NativeMethods.g.cs` is generated from the C ABI in `crates/ffi` by its build script, so building the native library regenerates it.

## Quick Start

```csharp
using ChatXdk;

using var chat = new Chat(juiceboxConfigJson);
await chat.UnlockAsync(pinBytes); // the PIN's UTF-8 bytes; zero them afterwards
// Or create the chat with new Chat() and load a local key blob + its
// registered version instead of Juicebox:
// chat.ImportKeys(new ImportKeysParams(privateKeyBytes) { SigningKeyVersion = registeredKeyVersion });

// Set the session once: your user id + registered signing-key version,
// the opt-in conversation-key cache, and the participants' signing keys.
// The cache keeps the key of every key change that verifies in DecryptEvents
// or DecryptEvent, and of every key change this chat prepares.
chat.SetIdentity(new SetIdentityParams(myUserId, registeredKeyVersion));
chat.SetCacheKeys(true);
chat.SetSigningKeys(signingKeys);
// SetSigningKeys replaces the stored keys; AddSigningKeys adds to them,
// such as the keys of a member who joins later.
chat.AddSigningKeys(newMemberSigningKeys);

// Batch load — signing keys come from the store; the verified conversation
// keys populate the cache.
var batch = chat.DecryptEvents(new DecryptEventsParams(rawEventB64List));
foreach (var dm in batch.Events)
{
    if (dm.Event.GetProperty("type").GetString() == "Message")
        Console.WriteLine(dm.Event.GetProperty("sender_id").GetString());
}

// A key change verifies with the signing keys of the member who made it. One
// that did not verify is here, by its index in the batch; when its key was
// dropped, the messages under it are in batch.Errors. For MissingSigningKey,
// add the public keys of change.SenderId (GET /2/users/{id}/public_keys) and
// decrypt again.
foreach (var (index, change) in batch.UnverifiedKeyChanges)
    Console.WriteLine($"{index} {change.Reason} {change.SenderId} {change.KeyDropped}");
// Key changes whose key this chat could not decrypt, and signing keys left
// out because their identity binding does not verify, are reported the same
// way: batch.UndecryptableKeyChanges, batch.RejectedSigningKeys.

// The version to encrypt with: for a batch of one conversation,
// batch.ConversationKeys.LatestVersion; for any batch,
// batch.ConversationKeys.LatestVersions[conversationId].

// Individual events: the empty key map and unset signing keys resolve from
// the session stores (pass conversation/signing keys explicitly to override).
var evt = chat.DecryptEvent(new DecryptEventParams(eventB64, new Dictionary<string, byte[]>()));
var conversationId = evt.GetProperty("conversation_id").GetString()!;

// Sending resolves the identity and conversation key from the session too.
var payload = chat.EncryptMessage(new EncryptMessageParams(conversationId, "hi!"));
// Reply / react by handing back the raw event being answered.
var reply = chat.EncryptReply(new EncryptReplyParams(conversationId, "pong", eventB64));
var reaction = chat.EncryptAddReaction(new EncryptReactionParams(eventB64, "👍"));

var plaintext = chat.Decrypt(encryptedGroupNameB64, convKeyBytes);
```

With the key cache on, calls that omit their conversation key read it from
the cache: the encrypt methods and the group title, description and avatar
changes use the conversation's newest key, and `DecryptEvent`, `DecryptFile`
and `FileDecryptor` the key at the version the event names. So
`DecryptFileParams` and `FileDecryptorParams` can be created without a key
map, and `GroupAvatarChangeParams` without a key version. A value that is
passed is used as is. The cache keeps every key version of a conversation,
so a message or file sent before a key change still decrypts after it.
`PrepareConversationKeyChange`, `PrepareGroupCreate`,
`PrepareGroupMembersChange` and `PrepareGroupMembersRemove` cache the key
they make as the conversation's newest, so a send right after one of them
uses that key.

Stateless helpers (base64/hex, MIME sniffing, image dimensions) live on **`ChatXdkUtilities`**.

## Other users' public keys

`DecryptEvents` verifies each event with its sender's signing key, and the
four prepare calls that make a conversation key (`PrepareGroupCreate`,
`PrepareGroupMembersChange`, `PrepareGroupMembersRemove`,
`PrepareConversationKeyChange`) encrypt it to each member's identity key.
Both are in the records `GET /2/users/{id}/public_keys` returns. Set
`ResolvePublicKeys` to a hook that fetches those records, and the `Async`
form of each of those calls gets the keys it is missing by itself:

```csharp
chat.ResolvePublicKeys = async userIds =>
{
    var records = new Dictionary<string, IReadOnlyList<PublicKeyRecord>>();
    foreach (var userId in userIds)
    {
        // The "data" array of GET /2/users/{id}/public_keys, fetched with
        // your X API client.
        JsonElement data = await FetchPublicKeysAsync(userId);
        records[userId] = data.Deserialize<List<PublicKeyRecord>>()!;
    }
    return records;
};

// No signing keys passed: the chat calls the hook for the users whose keys
// the page is missing, stores what it returns, and decrypts once more.
var page = await chat.DecryptEventsAsync(new DecryptEventsParams(rawEventB64List));

// No public keys passed: the chat calls the hook for the members it has no
// stored keys for, then encrypts the new key to the stored keys.
var created = await chat.PrepareGroupCreateAsync(
    new GroupCreateParams(groupId, memberIds, adminIds));
```

- Only `DecryptEventsAsync`, `PrepareConversationKeyChangeAsync`,
  `PrepareGroupCreateAsync`, `PrepareGroupMembersChangeAsync` and
  `PrepareGroupMembersRemoveAsync` call the hook, at most once per call. An
  exception it throws is thrown by that call. The synchronous methods never
  call it.
- Setting a hook turns the key cache on (`SetCacheKeys(true)`).
- `page.MissingSigningKeys` lists, by event index, the user id and key
  version of each signing key the page still lacks. A lookup that did not
  bring its key is not repeated for a minute, so the hook is not called with
  every page for a key it cannot find.
- Without a hook, do the same by hand: `chat.MissingPublicKeys(page)` returns
  the users to fetch, `chat.AddPublicKeys(records)` stores their records, and
  a second `DecryptEvents` reads them.
- With no `PublicKeys`, the prepare calls, synchronous or `Async`, read the
  stored keys of `MemberIds` and `AdminIds` (create), `CurrentMemberIds` and
  `NewMemberIds` (members change), `RemainingMemberIds` (members remove), and
  `MemberIds` or the two users of a one-to-one `ConversationId` (key change).
  A member with no stored key fails the call with a `ChatXdkException` of
  kind `InvalidInput` that names the member.
- A call that passes `SigningKeys` or `PublicKeys` uses them as is and never
  calls the hook.

### Many users, many conversations

- **One chat per signed-in user.** A chat holds one user's private keys and
  signs as that user. Keep one for each signed-in user and use it for all of
  that user's conversations; never create one per conversation. The chat
  keeps conversation keys by conversation and public keys by user id.
- **One hook function for every chat.** Give each chat the same function,
  over one cache of `GET /2/users/{id}/public_keys` answers for the whole
  process. Have the cache share a lookup that is under way, drop a lookup
  that failed so the next call tries again, and expire each answer after a
  few minutes so a key a user registers later is picked up.
  [`examples/dotnet/ChatBot/MultiUser.cs`](../../examples/dotnet/ChatBot/MultiUser.cs)
  has one (`SharedPublicKeys`), with `UserChats` for the chats.
- **Add keys, don't replace them.** `SetSigningKeys` replaces every stored
  key, the ones the hook fetched included, and the chat then waits a minute
  before it asks the hook for them again. With a hook set, add keys with
  `AddSigningKeys` or `AddPublicKeys`.

See [Many users, many
conversations](../../docs/API.md#many-users-many-conversations).

## API

See the **.NET** column of the unified tables in [`docs/API.md`](../../docs/API.md) for the full method list, parameters, and return types. Files (media) are covered under [Files (Media)](../../docs/API.md#files-media).

## Network access

Each chat makes one kind of request itself: an anonymous
`GET https://api.x.com/2/chat/features` in the background, which reads the X
API's feature switches that pick the format the SDK sends in. A chat reads
them when it is created, again once `SetIdentity` gives it a sender, and
again 5 minutes after each answer, so a change reaches a running chat. The
sender's request carries its bucket, the last four digits of the user id
(`?bucket=1234`), so every chat of one sender gets the same answer; before
that, the X API buckets the request by its address. Chats that read the same
URL share one request, and a chat that joins it takes its latest answer at
once. The answer stays for 5 minutes after it arrives, so a chat created in
that time takes it at once even when no other chat is alive: an app that
creates a chat for each send makes one request per URL every 5 minutes. The
request carries no credentials and never delays or fails a call.
One that fails is retried in the background, 1 second later, then after
twice the previous wait, at most 5 minutes apart. Each answer replaces the
one before; until an answer for the chat's URL arrives, sends stay in v0,
the format 0.5.x sends. A process that reaches the X API under another host
name sets the `CHAT_XDK_API_BASE_URL` environment variable to its base URL,
in place of `https://api.x.com`, before it creates its chats.

## Security limitations

The underlying protocol provides **no forward secrecy and no post-compromise
security**: compromise of an identity private key exposes all conversation
keys ever encrypted to that public key — and therefore all past and future
messages in those conversations. Key rotation does not retroactively protect
messages encrypted under a previous key. See
[docs/CRYPTO.md — Known Limitations](../../docs/CRYPTO.md#known-limitations).

## License

MIT — see the repo [`LICENSE`](../../LICENSE). Third-party notices:
[`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md).
