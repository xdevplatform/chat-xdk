# chat-xdk example bot (JVM)

An encrypted chat bot built on the **`com.x.chatxdk`** JVM
binding (JNA over the Rust core). It reads incoming DMs, decrypts them, generates
a reply, encrypts + signs it, and sends it back. Keys come from a local blob (or
are generated + registered on first run); conversation state is in memory.

## Layout

| File | Purpose |
|------|---------|
| [`ChatCore.java`](src/main/java/com/example/chatbot/ChatCore.java) | All encryption logic — the only file that touches `chatxdk`. |
| [`XChatClient.java`](src/main/java/com/example/chatbot/XChatClient.java) | The X Chat API I/O layer (plain HTTP). |
| [`Bot.java`](src/main/java/com/example/chatbot/Bot.java) | The receive → decrypt → reply → encrypt → send loop. |
| [`SharedPublicKeys.java`](src/main/java/com/example/chatbot/SharedPublicKeys.java) | Many signed-in users in one process: one shared public-key lookup. |
| [`UserChats.java`](src/main/java/com/example/chatbot/UserChats.java) | Many signed-in users in one process: one chat per user. |
| [`Main.java`](src/main/java/com/example/chatbot/Main.java) | Entrypoint: config, key load/generate, run. |
| [`Register.java`](src/main/java/com/example/chatbot/Register.java) | One-time public-key registration (own `main`). |
| [`ChatCoreTest.java`](src/test/java/com/example/chatbot/ChatCoreTest.java) | Offline test driving the real binding (no mocks). |
| [`MultiUserTest.java`](src/test/java/com/example/chatbot/MultiUserTest.java) | Offline test of the multi-user helpers, on the real binding. |

## Prerequisites

- JDK 17+ and Maven
- The native `chat_xdk_ffi` library and the installed `chatxdk` artifact:

```bash
# From the repo root: build the native library...
cargo build -p chat-xdk-ffi --release
# ...and install the JVM binding into your local Maven repo:
cd crates/jvm/java/chatxdk && mvn install
```

The example's `pom.xml` points JNA at `../../target/release` for the native lib.

## Run it

```bash
cp .env.example .env
# First run with no keys prints a registration payload + a private blob:
mvn exec:java
# Paste CHAT_PRIVATE_KEYS_B64 into .env, register the public key with the X API,
# set CHAT_SIGNING_KEY_VERSION to the public_key_version it returns, set
# X_ACCESS_TOKEN + CHAT_CONVERSATION_ID, then re-run.
mvn exec:java
```

The bot echoes messages back (`pong` for `ping`, otherwise `You said: …`).
Customize `Bot.generateReply` in [`Bot.java`](src/main/java/com/example/chatbot/Bot.java) to change the reply logic.

## Registering your key (one-time)

Before a bot can send or receive, its public key must be registered on the
account. This is a **rate-limited** write (only a few per 24h), so run it
**once**:

```bash
X_ACCESS_TOKEN=... mvn exec:java -Dexec.mainClass=com.example.chatbot.Register -Dexec.args="--confirm"
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

## Many signed-in users in one process

A chat holds one user's private keys and signs as that user. A server with
several signed-in users keeps **one chat per user**, for all of that user's
conversations, and never one per conversation: the chat keeps its
conversation keys by conversation, and the public keys it has met by user id.

Other users' public keys are the same whichever chat asks, so the chats share
**one public-key resolver**. The example has both parts:

- [`SharedPublicKeys`](src/main/java/com/example/chatbot/SharedPublicKeys.java)
  is that resolver: `new SharedPublicKeys(fetcher)`, or
  `new SharedPublicKeys(fetcher, ttl, clockMs)`. It keeps the answers of
  `GET /2/users/{id}/public_keys` by user id for the whole process, so two
  chats that meet the same user cost one request. Calls that ask for a user
  whose lookup is under way wait for that lookup. A lookup that fails is
  dropped, so the next call tries again. An answer is served for `ttl`
  (5 minutes unless you say otherwise) and then fetched again, so a key a
  user registers later is picked up.
- [`UserChats`](src/main/java/com/example/chatbot/UserChats.java) keeps one
  `ChatCore` per signed-in user, each with that resolver set:
  `chats.chatFor(userId, privateKeysB64, signingKeyVersion)`.
  `chats.close(userId)` signs a user out.

```java
SharedPublicKeys publicKeys = new SharedPublicKeys(api::getPublicKeys);
UserChats chats = new UserChats(publicKeys);

// On each request, for the signed-in user it belongs to:
ChatCore chat = chats.chatFor(userId, privateKeysB64, signingKeyVersion);
DecryptEventsResult page = chat.decryptBatch(eventsB64);
```

With a resolver set, add keys you already hold with the SDK's `addSigningKeys`
or `addPublicKeys`. `setSigningKeys` replaces every stored key, the fetched
ones included, and the chat then waits a minute before it asks the resolver
for them again.

## Test it (offline, no credentials)

```bash
mvn test
```

The test imports the fixture private keys, checks the binding reproduces the
committed public-key/signature vectors, and runs a real encrypt → decrypt
round-trip plus a conversation-key ECIES round-trip. The multi-user test signs
two users in, and checks that their chats fetch the keys of a user they both
meet once, that one chat serves two conversations, and that
`SharedPublicKeys` runs one fetch for callers that ask at the same time,
retries a failure and fetches again after its TTL.

## License

MIT
