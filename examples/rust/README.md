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
| [`src/multi_user.rs`](src/multi_user.rs) | Many signed-in users in one process: one chat per user, one shared public-key lookup. |
| [`src/main.rs`](src/main.rs) | Entrypoint: config, key load/generate, run. |
| [`src/bin/register.rs`](src/bin/register.rs) | One-time public-key registration (`cargo run --bin register`). |
| [`tests/chat_core.rs`](tests/chat_core.rs) | Offline tests driving the real binding (no mocks), the bot loop over a fake X API included. |
| [`tests/multi_user.rs`](tests/multi_user.rs) | Offline tests of the multi-user helpers, on the real binding. |
| [`tests/common/mod.rs`](tests/common/mod.rs) | What the two offline tests share: users with fresh keys, and a group's events as delivered. |

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
# set CHAT_SIGNING_KEY_VERSION to the public_key_version it returns, set
# X_ACCESS_TOKEN + CHAT_CONVERSATION_ID, then re-run.
cargo run
```

The bot echoes messages back (`pong` for `ping`, otherwise `You said: …`).
Customize `generate_reply` in [`src/bot.rs`](src/bot.rs) to change the reply logic.

The bot keeps no list of other users' public keys. `Bot::new` gives the SDK a
hook (`ChatCore::fetch_public_keys_with`) that reads
`GET /2/users/{id}/public_keys` for one user. Every page of events goes through
`ChatCore::decrypt_batch`, key changes and messages together, and the SDK calls
the hook for the signing keys the page needs and does not hold, those of a
member who changed a group's key and sent no message included. It stores what
arrives, and the result's `missing_signing_keys` lists what did not.

The HTTP client is behind the default `http` feature. To build only the crypto
core (no network stack), use `cargo build --no-default-features`.

## Many signed-in users in one process

A chat holds one user's private keys and signs as that user. A server with
several signed-in users keeps **one chat per user**, for all of that user's
conversations, and never one per conversation: the chat keeps its
conversation keys by conversation, and the public keys it has met by user id.

Other users' public keys are the same whichever chat asks, so the chats share
**one public-key hook**. [`src/multi_user.rs`](src/multi_user.rs) has both
parts:

- `SharedPublicKeys::new(fetch)` is the cache behind that hook. `fetch`
  returns one user's records, as `ChatCore::fetch_public_keys_with` takes it.
  The cache keeps the answers of `GET /2/users/{id}/public_keys` by user id
  for the whole process, so two chats that meet the same user cost one
  request. Calls that ask for a user whose lookup is under way wait for that
  lookup, whichever thread they run on. A lookup that fails is dropped, so
  the next call tries again. An answer is served for 5 minutes (`with_ttl`
  sets another time) and then fetched again, so a key a user registers later
  is picked up. Its `resolve` has the shape of the SDK's hook, and `hook()`
  returns it as one.
- `UserChats` keeps one `ChatCore` per signed-in user, each with that hook:
  `chats.chat_for(user_id, private_keys_b64, signing_key_version)?` returns
  the user's chat in an `Arc`. `chats.close(user_id)` signs a user out.

```rust
use std::sync::Arc;
use chatbot_rs::multi_user::{SharedPublicKeys, UserChats};

let public_keys = SharedPublicKeys::new(move |user_id: &str| api.get_public_keys(user_id));
let chats = UserChats::new(Arc::new(public_keys));

// On each request, for the signed-in user it belongs to:
let chat = chats.chat_for(user_id, private_keys_b64, signing_key_version)?;
let page = chat.decrypt_batch(&events);
```

With a hook set, add keys you already hold with the SDK's `add_signing_keys`
or `add_public_keys`. `set_signing_keys` replaces every stored key, the
fetched ones included, and the chat then waits a minute before it asks the
hook for them again.

A `Bot` serves one signed-in user, in any number of conversations: it owns
its chat and sets that chat's hook itself.

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

The tests import the fixture private keys, check the binding reproduces the
committed public-key/signature vectors, and run a real encrypt → decrypt
round-trip plus a conversation-key ECIES round-trip. They also run the bot over
a fake X API: a page whose key change was signed by a member who sent no
message decrypts once the SDK has fetched that member's keys, and the bot
replies. The multi-user tests sign two users in, and check that their chats
fetch the keys of a user they both meet once, that one chat serves two
conversations, and that the shared lookup serves two threads with one fetch,
retries a failure and fetches again after its TTL.

## License

MIT
