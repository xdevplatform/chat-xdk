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
| [`ChatBot/Program.cs`](ChatBot/Program.cs) | Entrypoint: config, key load/generate, run (and the `register` dispatch). |
| [`ChatBot/Register.cs`](ChatBot/Register.cs) | One-time public-key registration (`dotnet run --project ChatBot register`). |
| [`ChatBot.Tests/ChatCoreTests.cs`](ChatBot.Tests/ChatCoreTests.cs) | Offline test driving the real binding (no mocks). |

## Prerequisites

- .NET 8+ SDK
- The native `chat_xdk_dotnet` library, built once from the repo root:

```bash
cargo build -p chat-xdk-dotnet --release
```

Place the resulting `libchat_xdk_dotnet.dylib` / `.so` / `chat_xdk_dotnet.dll`
next to the built app (or on the loader path) so P/Invoke can find it.

## Run it

```bash
cp .env.example .env
# First run with no keys prints a registration payload + a private blob:
dotnet run --project ChatBot
# Paste CHAT_PRIVATE_KEYS_B64 into .env, register the public key with the X API,
# set X_ACCESS_TOKEN + CHAT_CONVERSATION_ID, then re-run.
dotnet run --project ChatBot
```

The bot echoes messages back (`pong` for `ping`, otherwise `You said: …`).
Customize `Bot.GenerateReply` in [`ChatBot/Bot.cs`](ChatBot/Bot.cs) to change the reply logic.

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
cargo build -p chat-xdk-dotnet --release   # build the native lib first
dotnet test
```

The test imports the fixture private keys, checks the binding reproduces the
committed public-key/signature vectors, and runs a real encrypt → decrypt
round-trip plus a conversation-key ECIES round-trip.

## License

MIT
