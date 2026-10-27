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

Place the native library (`libchat_xdk_ffi.dylib` / `.so` / `chat_xdk_ffi.dll`) on the loader path next to your app. `NativeMethods.g.cs` is generated from the C ABI in `crates/ffi` by its build script, so building the native library regenerates it.

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
chat.SetIdentity(new SetIdentityParams(myUserId, registeredKeyVersion));
chat.SetCacheKeys(true);
chat.SetSigningKeys(signingKeys);

// Batch load — signing keys come from the store; the verified conversation
// keys populate the cache.
var batch = chat.DecryptEvents(new DecryptEventsParams(rawEventB64List));
foreach (var dm in batch.Events)
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

## Network access

Each chat makes one kind of request itself: an anonymous
`GET https://api.x.com/2/chat/features` in the background, which reads the X
API's feature switches that pick the format the SDK sends in. A chat reads
them once, when it is created, and keeps the answer for its lifetime; chats
created while a request is in flight share it. The request carries no
credentials and never delays or fails a call; until it answers, and for the
chat's lifetime if it fails or is blocked, sends stay in v0, the format 0.5.x
sends.

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
