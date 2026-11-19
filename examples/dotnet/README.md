# chat-xdk example bot (.NET)

An encrypted chat bot built on the **`ChatXdk`** .NET binding
(P/Invoke over the Rust core). It reads incoming DMs, decrypts them, generates a
reply, encrypts + signs it, and sends it back. Keys come from a local blob (or
are generated + registered on first run); conversation state is in memory.

## Layout

| File | Purpose |
|------|---------|
| [`ChatBot/ChatCore.cs`](ChatBot/ChatCore.cs) | All encryption logic — the only file that touches `ChatXdk`. |
| [`ChatBot/XChatClient.cs`](ChatBot/XChatClient.cs) | The X Chat API I/O layer (plain HTTP). |
| [`ChatBot/Bot.cs`](ChatBot/Bot.cs) | The receive → decrypt → reply → encrypt → send loop. |
| [`ChatBot/MultiUser.cs`](ChatBot/MultiUser.cs) | Many signed-in users in one process: one chat per user, one shared public-key lookup. |
| [`ChatBot/Program.cs`](ChatBot/Program.cs) | Entrypoint: config, key load/generate, run (and the `register` dispatch). |
| [`ChatBot/Register.cs`](ChatBot/Register.cs) | One-time public-key registration (`dotnet run --project ChatBot register`). |
| [`ChatBot.Tests/ChatCoreTests.cs`](ChatBot.Tests/ChatCoreTests.cs) | Offline tests driving the real binding (no mocks). |
| [`ChatBot.Tests/MultiUserTests.cs`](ChatBot.Tests/MultiUserTests.cs) | Offline tests of the multi-user helpers, on the real binding. |

## Prerequisites

- .NET 8+ SDK
- The native `chat_xdk_ffi` library, built once from the repo root:

```bash
cargo build -p chat-xdk-ffi --release
```

Place the resulting `libchat_xdk_ffi.dylib` / `.so` / `chat_xdk_ffi.dll`
next to the built app (or on the loader path) so P/Invoke can find it.

## Run it

```bash
cp .env.example .env
# First run with no keys prints a registration payload + a private blob:
dotnet run --project ChatBot
# Paste CHAT_PRIVATE_KEYS_B64 into .env, register the public key with the X API,
# set CHAT_SIGNING_KEY_VERSION to the public_key_version it returns, set
# X_ACCESS_TOKEN + CHAT_CONVERSATION_ID, then re-run.
dotnet run --project ChatBot
```

The bot echoes messages back (`pong` for `ping`, otherwise `You said: …`).
Customize `Bot.GenerateReply` in [`ChatBot/Bot.cs`](ChatBot/Bot.cs) to change the reply logic.

The bot keeps no list of other users' public keys. Its constructor gives the
SDK a hook (`ChatCore.FetchPublicKeysWith`) that reads
`GET /2/users/{id}/public_keys` for one user. Every page of events goes through
`ChatCore.DecryptBatchAsync`, key changes and messages together, and the SDK
calls the hook for the signing keys the page needs and does not hold, those of
a member who changed a group's key and sent no message included. It stores what
arrives, and the result's `MissingSigningKeys` lists what did not.

## Many signed-in users in one process

A chat holds one user's private keys and signs as that user. A server with
several signed-in users keeps **one chat per user**, for all of that user's
conversations, and never one per conversation: the chat keeps its
conversation keys by conversation, and the public keys it has met by user id.

Other users' public keys are the same whichever chat asks, so the chats share
**one `ResolvePublicKeys` hook**. [`ChatBot/MultiUser.cs`](ChatBot/MultiUser.cs)
has both parts:

- `new SharedPublicKeys(fetchPublicKeys, ttl)` holds that hook: its
  `ResolveAsync` method. It keeps the answers of
  `GET /2/users/{id}/public_keys` by user id for the whole process, so two
  chats that meet the same user cost one request. Calls that ask for a user
  whose lookup is under way wait for that lookup. A lookup that fails is
  dropped, so the next call tries again. An answer is served for `ttl` (5
  minutes unless you say otherwise) and then fetched again, so a key a user
  registers later is picked up.
- `UserChats` keeps one `ChatCore` per signed-in user, each with that hook:
  `chats.ChatFor(userId, privateKeysB64, signingKeyVersion)`.
  `chats.Close(userId)` signs a user out.

```csharp
var shared = new SharedPublicKeys(api.GetPublicKeysAsync);
var chats = new UserChats(shared.ResolveAsync);

// On each request, for the signed-in user it belongs to:
var chat = chats.ChatFor(userId, privateKeysB64, signingKeyVersion);
var page = await chat.DecryptBatchAsync(eventsB64);
```

With a hook set, add keys you already hold with the SDK's `AddSigningKeys` or
`AddPublicKeys`. `SetSigningKeys` replaces every stored key, the fetched ones
included, and the chat then waits a minute before it asks the hook for them
again.

## Registering your key (one-time)

Before a bot can send or receive, its public key must be registered on the
account. This is a **rate-limited** write (only a few per 24h), so run it
**once**:

```bash
X_ACCESS_TOKEN=... dotnet run --project ChatBot register --confirm
```

It generates the identity, saves the private-key blob under `state/` (mode
600) **before** the network call, then POSTs the public key. If it is
interrupted, re-running resumes the same saved identity rather than minting a
new one; if the key is already on the account it adopts that version and skips
the POST; on HTTP 429 it stops and tells you when the window resets rather than
retrying. Set `CHAT_PIN` to additionally back the keys up in Juicebox
(best-effort — the local blob is already saved). When it finishes it prints the
`CHAT_PRIVATE_KEYS_B64` and `CHAT_SIGNING_KEY_VERSION` lines to paste into
`.env`. `state/` is gitignored — never commit key blobs.

## Test it (offline, no credentials)

```bash
cargo build -p chat-xdk-ffi --release   # build the native lib first
dotnet test
```

The tests import the fixture private keys, check the binding reproduces the
committed public-key/signature vectors, and run a real encrypt → decrypt
round-trip plus a conversation-key ECIES round-trip. They also decrypt a page
whose key change was signed by a member who sent no message: it decrypts once
the SDK has fetched that member's keys through the hook. The multi-user tests
sign two users in, and check that their chats fetch the keys of a user they
both meet once, that one chat serves two conversations, and that the shared
lookup shares a fetch under way, retries a failure and fetches again after its
TTL.

## License

MIT
