# chat-xdk example bot (Rust)

An encrypted chat bot built on the **`chat-xdk-core`** Rust crate. It
reads incoming DMs, decrypts them, generates a reply, encrypts + signs it, and
sends it back. Keys come from a local blob (or are generated + registered on
first run); conversation state is in memory.

## Layout

| File | Purpose |
|------|---------|
| [`src/chat_core.rs`](src/chat_core.rs) | All encryption logic — the only file that touches `chat_xdk_core`. |
| [`src/x_api.rs`](src/x_api.rs) | The X Chat API I/O layer (the `ChatApi` trait + an HTTP client, `ureq`). |
| [`src/bot.rs`](src/bot.rs) | The receive → decrypt → reply → encrypt → send loop. |
| [`src/main.rs`](src/main.rs) | Entrypoint: config, key load/generate, run. |
| [`src/bin/register.rs`](src/bin/register.rs) | One-time public-key registration (`cargo run --bin register`). |
| [`tests/chat_core.rs`](tests/chat_core.rs) | Offline test driving the real binding (no mocks). |

## Prerequisites

- Rust (stable)
- The example depends on the `chat-xdk-core` crate by path; for a standalone
  project, depend on the published crate instead.

## Run it

```bash
cp .env.example .env
# First run with no keys prints a registration payload + a private blob:
cargo run
# Paste CHAT_PRIVATE_KEYS_B64 into .env, register the public key with the X API,
# set X_ACCESS_TOKEN + CHAT_CONVERSATION_ID, then re-run.
cargo run
```

The bot echoes messages back (`pong` for `ping`, otherwise `You said: …`).
Customize `generate_reply` in [`src/bot.rs`](src/bot.rs) to change the reply logic.

The HTTP client is behind the default `http` feature. To build only the crypto
core (no network stack), use `cargo build --no-default-features`.

## Registering your key (one-time)

Before a bot can send or receive, its public key must be registered on the
account. This is a **rate-limited** write (only a few per 24h), so run it
**once**:

```bash
X_ACCESS_TOKEN=... cargo run --bin register -- --confirm
```

It generates the identity, saves the private-key blob under `state/`
(owner-only) **before** the network call, then POSTs the public key. If it is
interrupted, re-running resumes the same saved identity rather than minting a
new one; if the key is already on the account it adopts that version and skips
the POST; on HTTP 429 it stops and tells you when the window resets rather than
retrying. A marker under `state/` records that registration is done (`--force`
mints a new identity). When it finishes it prints the `CHAT_PRIVATE_KEYS_B64`
and `CHAT_SIGNING_KEY_VERSION` lines to paste into `.env`. `state/` is
gitignored — never commit key blobs.

## Test it (offline, no credentials)

```bash
cargo test
```

The test imports the fixture private keys, checks the binding reproduces the
committed public-key/signature vectors, and runs a real encrypt → decrypt
round-trip plus a conversation-key ECIES round-trip.

## License

MIT
