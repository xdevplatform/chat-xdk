# chat-xdk for JavaScript servers

`@xdevplatform/chat-xdk-server` is the X Chat SDK — encryption for X Direct
Messages — for **Node servers that keep their own private keys**: webhook
handlers, bots, AWS Lambda functions and other server-side integrations.

It has the API of [`@xdevplatform/chat-xdk`](../js/README.md) and runs the
same WebAssembly engine. The one difference is the chat `createChat` returns:
a `ServerChat`, which also has `importKeys` and `exportKeys`, so a server can
export its keys once, keep them in its own secret store, and load them into
each process without a Juicebox round trip per request.

## Server only

`exportKeys` returns the raw private keys, so anything that can reach a
`ServerChat` can take the identity with it. **Never bundle this package into
a browser app**, or into any other page or client an attacker can script; a
browser app uses `@xdevplatform/chat-xdk`, which keeps its keys in Juicebox
and has no method that returns them.

The package resolves only under the `node` export condition, so a bundler
building for browsers fails to resolve it rather than bundling it.

## Prerequisites

- **Node.js 18+**

## Install

```bash
npm install @xdevplatform/chat-xdk-server
```

The compiled WASM engine ships inside the package (`pkg/`), so there is no
build step. Juicebox PIN-based key storage is an optional peer dependency,
needed only to `setup`, `unlock`, `changePin` or `delete`:

```bash
npm install juicebox-sdk
```

## Keep keys in your secret store

Export the keys once, from a chat that holds them: one that unlocked them
from Juicebox, as below, or one that generated and registered them. Store
the bytes where your server keeps its secrets (AWS Secrets Manager, KMS-
encrypted storage, Vault, …), never in logs or source control, and zero
your copy:

```typescript
import { createChat } from "@xdevplatform/chat-xdk-server";

const chat = await createChat({ juiceboxConfig, getAuthToken });
await chat.unlock(pin);
const keys = chat.exportKeys();
await secretStore.put("chat-keys", keys);
keys.fill(0);
chat.free();
```

Then each process (a Lambda cold start, a worker) loads them, with the
`public_key_version` the X API returned when the keys were registered, and
needs neither Juicebox nor juicebox-sdk:

```typescript
import { createChat } from "@xdevplatform/chat-xdk-server";

const chat = await createChat();
chat.importKeys({ keys: await secretStore.get("chat-keys"), signingKeyVersion });
chat.setIdentity({ userId: myUserId, signingKeyVersion });
chat.setSigningKeys(signingKeys);

const event = chat.decryptEvent({ eventB64: webhookEventB64, conversationKeys });
const reply = chat.encryptReply({
  conversationId: event.conversationId,
  text: "pong",
  replyToEvent: webhookEventB64,
});
```

`exportKeys` throws a `ChatXdkError` of kind `invalidState` when no identity
key is loaded, and `importKeys` one of kind `invalidInput` for bytes that
aren't keys. The SDK zeroizes its own copy of the bytes `importKeys` takes;
zero yours with `fill(0)`.

## API

Every other call is that of `@xdevplatform/chat-xdk`: see its
[README](../js/README.md) and the **JS** column of
[`docs/API.md`](../../../docs/API.md). The package exports the same names,
and `ServerChat` extends its `ChatWithJuicebox`.

## Network access

Each chat makes the one request a chat from `@xdevplatform/chat-xdk` makes:
an anonymous `GET https://api.x.com/2/chat/features` in the background,
which reads the feature switches that pick the format the SDK sends in. See
"Network access" in its [README](../js/README.md#network-access).

## Security limitations

The protocol provides **no forward secrecy and no post-compromise
security**: whoever obtains the identity private key can read every
conversation key ever encrypted to its public key, past and future. See
[docs/CRYPTO.md — Known Limitations](../../../docs/CRYPTO.md#known-limitations).

## License

MIT — see [`LICENSE`](LICENSE). Third-party notices:
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
