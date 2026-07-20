# chat-xdk example bot (Go)

An encrypted chat bot built on the **`chatxdk`** Go binding (cgo over
the Rust core). It reads incoming DMs, decrypts them, generates a reply, encrypts
+ signs it, and sends it back. Keys come from a local blob (or are generated +
registered on first run); conversation state is in memory.

## Layout

| File | Purpose |
|------|---------|
| [`chatcore.go`](chatcore.go) | All encryption logic — the only file that touches `chatxdk`. |
| [`xapi.go`](xapi.go) | The X Chat API I/O layer (plain HTTP). |
| [`bot.go`](bot.go) | The receive → decrypt → reply → encrypt → send loop. |
| [`main.go`](main.go) | Entrypoint: config, key load/generate, run. |
| [`register/main.go`](register/main.go) | One-time public-key registration (`go run ./register`). |
| [`chatcore_test.go`](chatcore_test.go) | Offline test driving the real binding (no mocks). |

## Prerequisites

- Go 1.21+ with cgo enabled (a C toolchain)
- The binding ships prebuilt static libraries (`libchat_xdk_go.a`) for common
  platforms, so no Rust build is required to use it.

## Run it

```bash
cp .env.example .env
# First run with no keys prints a registration payload + a private blob:
go run .
# Paste CHAT_PRIVATE_KEYS_B64 into .env, register the public key with the X API,
# set X_ACCESS_TOKEN + CHAT_CONVERSATION_ID, then re-run.
go run .
```

The bot echoes messages back (`pong` for `ping`, otherwise `You said: …`).
Customize `generateReply` in [`bot.go`](bot.go) to change the reply logic.

## Registering your key (one-time)

Before a bot can send or receive, its public key must be registered on the
account. This is a **rate-limited** write (only a few per 24h), so run it
**once**:

```bash
X_ACCESS_TOKEN=... go run ./register --confirm
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
CGO_ENABLED=1 go test ./...
```

The test imports the fixture private keys, checks the binding reproduces the
committed public-key/signature vectors, and runs a real encrypt → decrypt
round-trip plus a conversation-key ECIES round-trip.

## License

MIT
