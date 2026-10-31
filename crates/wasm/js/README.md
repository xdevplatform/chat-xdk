# chat-xdk JavaScript/WASM bindings

JavaScript/WASM bindings for the X Chat SDK — encryption for X Direct Messages.

## Architecture

```
JavaScript (chat-xdk) → wasm-bindgen → Rust WASM (chat_xdk_wasm) → chat-xdk-core
```

The Rust WASM layer is a pure crypto engine; Juicebox key-storage lifecycle is orchestrated in the JS wrapper (`index.js`).

## Prerequisites

- **Node.js 18+**

## Install

```bash
npm install @xdevplatform/chat-xdk
```

The compiled WASM engine ships inside the package (`pkg/`) — no build step.

Juicebox PIN-based key storage is an optional peer dependency:

```bash
npm install juicebox-sdk   # only needed for setup()/unlock()/changePin()
```

## Developing in this repo

Working from a chat-xdk checkout (instead of the npm package) requires staging
the WASM build that `index.js` resolves at `./pkg/`:

```bash
make wasm   # from the repo root; builds --target web and stages js/pkg/
```

## Quick Start

First boot — the account's `juicebox_config` is created by
`POST /2/users/{id}/public_keys`, so a brand-new user has none yet. Create the
chat without it, generate and POST the keys, then wire up Juicebox:

```typescript
import { createChat } from "@xdevplatform/chat-xdk";

const chat = await createChat({
  getAuthToken: async (realmId) => await myBackend.getToken(realmId),
});
const payload = chat.generateKeypairs();
// … POST payload to /2/users/{id}/public_keys, GET juicebox_config back …
chat.updateConfig(configJson);
await chat.setup("2580");
```

After registering the keys, call `setIdentity()` with the
`public_key_version` the registration returns.

Later sessions pass the config up front and unlock:

```typescript
import { createChat } from "@xdevplatform/chat-xdk";

const chat = await createChat({
  juiceboxConfig: configJson,
  getAuthToken: async (realmId) => await myBackend.getToken(realmId),
});
await chat.unlock("2580");

// Set the session once: your user id + the public_key_version of your
// registered keys, the participants' signing keys, and the opt-in
// conversation-key cache.
chat.setIdentity({ userId: "111", signingKeyVersion: "1" });
chat.setCacheKeys(true);
// Each signing-key entry carries all five fields from the X API
// public keys response.
chat.setSigningKeys([
  {
    userId: "111",
    publicKeyVersion: "1",
    publicKey: "BASE64...",
    identityPublicKey: "BASE64...",
    identityPublicKeySignature: "BASE64...",
  },
  {
    userId: "222",
    publicKeyVersion: "1",
    publicKey: "BASE64...",
    identityPublicKey: "BASE64...",
    identityPublicKeySignature: "BASE64...",
  },
]);

// Initial load — batch decrypt with automatic key extraction. Signing keys
// come from the store; the verified conversation keys populate the cache.
const result = chat.decryptEvents({ events: rawEvents });

for (const dm of result.events) {
  if (dm.event.type === "message") {
    console.log(dm.event.senderId, dm.event.content.text);
  }
}

// Individual events after the initial load: the empty key map resolves from
// the cache and the unset signing keys from the store (pass either
// explicitly to override).
const event = chat.decryptEvent({ eventB64: webhookEventB64 });

// Sending resolves the identity and conversation key from the session too.
const payload = chat.encryptMessage({ conversationId: event.conversationId, text: "hi!" });
// Reply / react by handing back the raw event being answered.
const reply = chat.encryptReply({
  conversationId: event.conversationId,
  text: "pong",
  replyToEvent: webhookEventB64,
});
const reaction = chat.encryptAddReaction({ emoji: "👍", targetEvent: webhookEventB64 });
```

## API

See the **JS** column of the unified tables in [`docs/API.md`](../../../docs/API.md) for the full method list, parameters, and return types. Files (media) are covered under [Files (Media)](../../../docs/API.md#files-media).

## Network access

Each chat makes one kind of request itself: an anonymous
`GET https://api.x.com/2/chat/features` in the background, which reads the X
API's feature switches that pick the format the SDK sends in. A chat reads
them when it is created, again once `setIdentity` gives it a sender, and
again 5 minutes after each answer, so a change reaches a running chat. The
sender's request carries its bucket, the last four digits of the user id
(`?bucket=1234`), so every chat of one sender gets the same answer; before
that, the X API buckets the request by its address. Chats that read the same
URL share one request, and a chat that joins it takes its latest answer at
once. The request carries no credentials and never delays or fails a call.
One that fails is retried in the background, 1 second later, then after
twice the previous wait, at most 5 minutes apart. Each answer replaces the
one before; until an answer for the chat's URL arrives, sends stay in v0,
the format 0.5.x sends. From Node 20.16 these requests, and the waits before
them, never keep the process alive; before it, a request in flight can delay
exit until it ends, at most 2 seconds. In a browser, the request is a simple
cross-origin GET made with `fetch`.

## Security limitations

The underlying protocol provides **no forward secrecy and no post-compromise
security**: compromise of an identity private key exposes all conversation
keys ever encrypted to that public key — and therefore all past and future
messages in those conversations. Key rotation does not retroactively protect
messages encrypted under a previous key. See
[docs/CRYPTO.md — Known Limitations](../../../docs/CRYPTO.md#known-limitations).

### Exported keys are unencrypted

`exportKeys()` returns unencrypted private key material, as in every
binding: any script that can reach the chat instance, including code injected
via XSS or a compromised dependency, could take the identity with it. In a
browser, keep keys in Juicebox (`setup`/`unlock`), which needs no export;
where you do export them, store the bytes only where private keys belong and
zero them with `fill(0)` once stored.

## License

MIT — see [`LICENSE`](LICENSE). Third-party notices:
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
