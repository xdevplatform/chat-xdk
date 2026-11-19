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
| [`src/multi-user.mjs`](src/multi-user.mjs) | Many signed-in users in one process: one chat per user, one shared public-key lookup. |
| [`src/multi-bot.mjs`](src/multi-bot.mjs) | One bot per signed-in user, run with those helpers. |
| [`src/register.mjs`](src/register.mjs) | One-time public-key registration (Juicebox-backed). |
| [`server.mjs`](server.mjs) | Dev server: serves the browser app + proxies the X API. |
| [`public/`](public) | The browser chat UI. |
| [`test/chat-core.test.mjs`](test/chat-core.test.mjs) | Offline test driving the real binding (no mocks). |
| [`test/multi-user.test.mjs`](test/multi-user.test.mjs) | Offline test of the multi-user helpers, on the real binding. |

## Prerequisites

- Node.js 18+
- Rust + [`wasm-pack`](https://rustwasm.github.io/wasm-pack/) to build the WASM
  package (`crates/wasm/pkg/` is not committed): run `npm run build:wasm` once
  before the offline test or the browser app. The example then imports the
  chat-xdk WASM packages from this repo by relative path; for a standalone
  project, install the packages and import from them instead: the bot, which
  keeps its keys in a local blob, from `@xdevplatform/chat-xdk-server`, and
  `register.mjs`, which keeps them in Juicebox, from `@xdevplatform/chat-xdk`.
  The REST client uses `@xdevplatform/xdk` (`npm install @xdevplatform/xdk`).

## Message format

The bot imports its raw private-key blob into a chat from the server
package's `createChat()`, which reads the X API's feature switches in the
background and keeps them
current, and sends v1 while they turn `v1_send` on. The browser app drives
the lower-level WASM `Chat` from `crates/wasm/pkg/`, which doesn't read the
switches, so its messages go out in the v0 format.

## Other users' public keys

The SDK verifies each event with its sender's public keys, and encrypts a new
conversation key to its members' public keys. The bot does not fetch them
itself. `ChatCore.fetchPublicKeysWith` sets the chat's `resolvePublicKeys`
hook to the X API client's `getPublicKeys`, and the SDK calls the hook for the
users whose keys it lacks, from `decryptEventsAsync` and the `prepare…Async`
calls. A user whose fetch fails is logged and left out.

The browser app's lower-level `Chat` has no hook, so
[`public/app.js`](public/app.js) does the same steps by hand: after a batch
decrypt it asks `missingPublicKeys` which users to fetch, stores their records
with `addPublicKeys`, and decrypts the page again.

## Many signed-in users in one process

A chat holds one user's private keys and signs as that user. A server with
several signed-in users keeps **one chat per user**, for all of that user's
conversations, and never one per conversation: the chat keeps its
conversation keys by conversation, and the public keys it has met by user id.

Other users' public keys are the same whichever chat asks, so the chats share
**one `resolvePublicKeys` function**. [`src/multi-user.mjs`](src/multi-user.mjs)
has both parts:

- `sharedPublicKeys(getPublicKeys, { ttlMs })` returns that function. It keeps
  the answers of `GET /2/users/{id}/public_keys` by user id for the whole
  process, so two chats that meet the same user cost one request. Calls that
  ask for a user whose lookup is under way wait for that lookup. A lookup
  that fails is dropped, so the next call tries again. An answer is served
  for `ttlMs` (5 minutes unless you say otherwise) and then fetched again, so
  a key a user registers later is picked up.
- `UserChats` keeps one `ChatCore` per signed-in user, each created with that
  function as its hook: `await chats.chatFor({ userId, privateKeysB64,
  signingKeyVersion })`. `chats.close(userId)` signs a user out.

```js
import { sharedPublicKeys, UserChats } from "./src/multi-user.mjs";

const resolvePublicKeys = sharedPublicKeys((userId) => api.getPublicKeys(userId));
const chats = new UserChats(resolvePublicKeys);

// On each request, for the signed-in user it belongs to:
const chat = await chats.chatFor(user);
const page = await chat.decryptBatchAsync(eventsB64);
```

With a hook set, add keys you already hold with the SDK's `addSigningKeys` or
`addPublicKeys`. `setSigningKeys` replaces every stored key, the fetched ones
included, and the chat then waits a minute before it asks the hook for them
again.

[`src/multi-bot.mjs`](src/multi-bot.mjs) runs one bot per signed-in user this
way. List the users in a JSON file (each entry has `accessToken`,
`privateKeysB64`, `signingKeyVersion` and `conversationIds`) and run:

```bash
CHAT_USERS_FILE=users.json npm run bots
```

## Test it (offline, no credentials)

```bash
npm run build:wasm     # once per Rust change; needs Rust + wasm-pack
node --test
```

The test imports the fixture private keys, checks the binding reproduces the
committed public-key/signature vectors, and runs a real encrypt → decrypt
round-trip plus a conversation-key ECIES round-trip. It also decrypts a page
whose key change was signed by a member who sent no message, with that
member's keys fetched through the hook. The multi-user test signs two users
in, and checks that their chats fetch the keys of a user they both meet once,
that one chat serves two conversations, and that the shared lookup retries a
failure and fetches again after its TTL.

## Run the browser app

```bash
cp .env.example .env   # set X_ACCESS_TOKEN
npm run build:wasm     # build a browser (web-target) WASM package
npm start              # serve on http://localhost:8787
```

Paste a private key blob and its key version (the `public_key_version` the X
API returned when the key was registered), or generate one in the page — see
the note below. Then enter a conversation ID and chat.

## Run the headless bot

```bash
cp .env.example .env   # set X_ACCESS_TOKEN, CHAT_CONVERSATION_ID, CHAT_PRIVATE_KEYS_B64,
                       # and CHAT_SIGNING_KEY_VERSION (the key's public_key_version)
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

Unlike the other language examples, this script shows the Juicebox flow: it
persists the identity in **Juicebox** under `CHAT_PIN` (required) instead of a
local blob, and recovers it with `unlock(pin)`.
It needs the optional `juicebox-sdk` peer dependency installed. A brand-new
account works too: the account's `juicebox_config` is created by the
public-key POST itself, so the script creates the chat with no config,
generates keys, POSTs the public key, then fetches the config and stores the
keys with `updateConfig` + `setup(pin)`. Before POSTing, it checks whether the
key is already on the account and skips the write if so; on HTTP 429 it stops
and prints when the window resets rather than retrying. A marker under
`state/` records that registration is done (`--force` overrides to mint a new
identity). `state/` is gitignored — never commit key material.

## Key generation in the browser

The `wasm32-unknown-unknown` target has no system clock, so the binding reads
conversation key versions from JavaScript's `Date.now()`. Key generation
(`generateKeypairs`), conversation-key creation (`prepareConversationKeyChange`),
encryption, and both decrypt paths therefore all run directly in the browser —
the sample is fully self-contained and never needs another language to mint keys.

## License

MIT
