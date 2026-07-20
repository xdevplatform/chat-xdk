# chat-xdk example: browser app + bot (JavaScript / WASM)

Two encrypted chat clients built on the **chat-xdk WASM binding**: an
interactive browser app and a headless bot. Encryption runs in JavaScript (in
the browser, or in Node for the bot); REST calls go through the **XDK**
(`@xdevplatform/xdk`).

- **Browser app** ([`public/`](public)) — an interactive encrypted chat client.
  All crypto runs in the browser via WASM; a tiny dev server
  ([`server.mjs`](server.mjs)) relays encrypted blobs to the X Chat API with the
  XDK, so the access token never reaches the page.
- **Headless bot** ([`src/bot.mjs`](src/bot.mjs)) — the automated counterpart
  that auto-replies.

## Layout

| File | Purpose |
|------|---------|
| [`src/chat-core.mjs`](src/chat-core.mjs) | All encryption logic — the only file that touches the WASM binding. |
| [`src/x-api.mjs`](src/x-api.mjs) | The X Chat API I/O layer (XDK client). |
| [`src/bot.mjs`](src/bot.mjs) | The receive → decrypt → reply → encrypt → send loop. |
| [`src/register.mjs`](src/register.mjs) | One-time public-key registration (Juicebox-backed). |
| [`server.mjs`](server.mjs) | Dev server: serves the browser app + proxies the X API. |
| [`public/`](public) | The browser chat UI. |
| [`test/chat-core.test.mjs`](test/chat-core.test.mjs) | Offline test driving the real binding (no mocks). |

## Prerequisites

- Node.js 18+
- Rust + [`wasm-pack`](https://rustwasm.github.io/wasm-pack/) to build the WASM
  package (`crates/wasm/pkg/` is not committed): run `npm run build:wasm` once
  before the offline test or the browser app. The example then imports the
  chat-xdk WASM wrapper from this repo by relative path; for a standalone
  project, install the package and import from `@xdevplatform/chat-xdk`
  instead. The REST client uses `@xdevplatform/xdk`
  (`npm install @xdevplatform/xdk`).

## Test it (offline, no credentials)

```bash
npm run build:wasm     # once per Rust change; needs Rust + wasm-pack
node --test
```

The test imports the fixture private keys, checks the binding reproduces the
committed public-key/signature vectors, and runs a real encrypt → decrypt
round-trip plus a conversation-key ECIES round-trip.

## Run the browser app

```bash
cp .env.example .env   # set X_ACCESS_TOKEN
npm run build:wasm     # build a browser (web-target) WASM package
npm start              # serve on http://localhost:8787
```

Paste a private key blob (or generate one in the page — see the note below),
enter a conversation ID, and chat.

## Run the headless bot

```bash
cp .env.example .env   # set X_ACCESS_TOKEN, CHAT_CONVERSATION_ID, CHAT_PRIVATE_KEYS_B64
npm run bot
```

The bot echoes messages back (`pong` for `ping`, otherwise `You said: …`).
Customize `generateReply` in [`src/bot.mjs`](src/bot.mjs) to change the reply logic.

## Registering your key (one-time)

Before a bot can send or receive, its public key must be registered on the
account. This is a **rate-limited** write (only a few per 24h), so run it
**once**:

```bash
npm run build:wasm                                    # once per Rust change
X_ACCESS_TOKEN=... CHAT_PIN=... npm run register -- --confirm
```

The browser-safe WASM binding has no key export, so — unlike the other
language examples — this persists the identity in **Juicebox** under `CHAT_PIN`
(required) instead of a local blob; the bot then recovers it with `unlock(pin)`.
It needs the optional `juicebox-sdk` peer dependency installed, and the account
must already have a Juicebox realm config — if it does not, register the first
identity with a native binding (which stores a local key blob). Before POSTing,
it checks whether the key is already on the account and skips the write if so;
on HTTP 429 it stops and prints when the window resets rather than retrying. A
marker under `state/` records that registration is done (`--force` overrides to
mint a new identity). `state/` is gitignored — never commit key material.

## Key generation in the browser

The `wasm32-unknown-unknown` target has no system clock, so the binding reads the
key version from JavaScript's `Date.now()`. Key generation (`generateKeypairs`),
conversation-key creation (`prepareConversationKeyChange`), encryption, and both
decrypt paths therefore all run directly in the browser — the sample is fully
self-contained and never needs another language to mint keys.

## License

MIT
