# chat-xdk .NET bindings

.NET bindings for the X Chat SDK — encryption for X Direct Messages.

## Architecture

```
C# (ChatXdk) → P/Invoke → Rust cdylib (chat_xdk_dotnet) → chat-xdk-core
```

Complex values cross the FFI boundary as JSON strings. P/Invoke entry points are generated with csbindgen from `src/lib.rs` into `dotnet/ChatXdk/NativeMethods.g.cs`.

## Prerequisites

- **.NET 8+** SDK
- **Rust** (stable) to build the native `chat_xdk_dotnet` library

## Setup

From the repo root, build the native library:

```bash
cargo build -p chat-xdk-dotnet --release
```

Then build the managed wrapper:

```bash
cd crates/dotnet/dotnet/ChatXdk
dotnet build -c Release
```

Place the native library (`libchat_xdk_dotnet.dylib` / `.so` / `chat_xdk_dotnet.dll`) on the loader path next to your app. After changing FFI exports in `src/lib.rs`, regenerate `NativeMethods.g.cs` with your csbindgen workflow.

## Quick Start

```csharp
using ChatXdk;

using var chat = new Chat();
chat.UpdateConfig(juiceboxConfigJson);
chat.Unlock(pin, juiceboxConfigJson);
// Or load a local key blob + its registered version instead of Juicebox:
// chat.ImportKeys(new ImportKeysParams(privateKeyBytes) { SigningKeyVersion = registeredKeyVersion });

// Set the session once: your user id + registered signing-key version,
// the opt-in conversation-key cache, and the participants' signing keys.
chat.SetIdentity(new SetIdentityParams(myUserId, registeredKeyVersion));
chat.SetCacheKeys(true);
chat.SetSigningKeys(signingKeys);

// Batch load — signing keys come from the store; the verified conversation
// keys populate the cache.
var batch = chat.DecryptEvents(new DecryptEventsParams(rawEventB64List));
foreach (var dm in batch.Messages)
{
    if (dm.Event.GetProperty("type").GetString() == "Message")
        Console.WriteLine(dm.Event.GetProperty("sender_id").GetString());
}

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

Stateless helpers (base64/hex, MIME sniffing, image dimensions) live on **`ChatXdkUtilities`**.

## API

See the **.NET** column of the unified tables in [`docs/API.md`](../../docs/API.md) for the full method list, parameters, and return types. Files (media) are covered under [Files (Media)](../../docs/API.md#files-media).

Moving code from 0.5.x? [docs/migrating-0.6/dotnet.md](../../docs/migrating-0.6/dotnet.md) lists every change with the lines to change.

## Network access

Each chat makes one kind of request itself: an anonymous
`GET https://api.x.com/2/chat/features` in the background, which reads the X
API's feature switches that pick the format the SDK sends in. It runs when the
chat is created, again once keys load, and every 5 minutes after that, and
chats asking for the same thing at once share one request. It carries no
credentials and never delays or fails a call; if it fails or is blocked,
sends stay in v0, the format 0.5.x sends. Dispose the chat (`using`, or `chat.Dispose()`) when you're done with it to stop its requests; a finalized chat stops too.

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
