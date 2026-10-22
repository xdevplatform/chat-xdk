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

for (const dm of result.messages) {
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
them once, when it is created, and keeps the answer for its lifetime; chats
created while a request is in flight share it. The request carries no
credentials and never delays or fails a call; until it answers, and for the
chat's lifetime if it fails or is blocked, sends stay in v0, the format 0.5.x
sends.
From Node 20.16 the request never keeps the process alive; before it, the
request can delay exit until it ends, at most 2 seconds.
In a browser, the request is a simple cross-origin GET made with `fetch`.

## Security limitations

The underlying protocol provides **no forward secrecy and no post-compromise
security**: compromise of an identity private key exposes all conversation
keys ever encrypted to that public key — and therefore all past and future
messages in those conversations. Key rotation does not retroactively protect
messages encrypted under a previous key. See
[docs/CRYPTO.md — Known Limitations](../../../docs/CRYPTO.md#known-limitations).

### Key export is not exposed in the browser build

Raw private-key export and import are not part of this binding's public API.
`exportKeys()` would return unencrypted private key material to page
JavaScript, where any script that can reach the chat instance — including code
injected via XSS or a compromised dependency — could exfiltrate the identity
permanently. Keys are managed inside the Juicebox layer (`setup`/`unlock`)
instead, so raw key bytes never cross into application JavaScript.

## License

MIT — see [`LICENSE`](LICENSE). Third-party notices:
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
