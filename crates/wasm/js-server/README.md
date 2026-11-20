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
chat.setSigningKeys(signingKeys); // or addSigningKeys, to keep the keys stored before

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

`conversationKeys` is the conversation's key map from `decryptEvents`. A
process that stays up can turn on the key cache instead
(`chat.setCacheKeys(true)`): it keeps the key of each key change that
verifies in `decryptEvents` or `decryptEvent`, and of each key change the
chat prepares, and `decryptEvent`, `decryptFile`, `fileDecryptor` and the
encrypt calls then need no key passed.

## Signing keys for key changes

The signing keys a chat verifies with must include those of every member who
made a key change in the events you decrypt, not only of the members whose
messages you read. A group's key changes are signed by whoever created the
group, changed its members or rotated its key, and a recent key change that
does not verify has its key dropped: every message under it then lands in
`errors`.

Set a hook that fetches users' public keys, and decrypt with
`decryptEventsAsync`. It fetches the keys of every sender the batch needs
and the chat has none for, then decrypts the batch again:

```typescript
import { createChat } from "@xdevplatform/chat-xdk-server";

const chat = await createChat({
  resolvePublicKeys: async (userIds) => {
    const records = {};
    for (const userId of userIds) {
      // The `data` array of GET /2/users/{id}/public_keys, as the API sends it.
      records[userId] = await xApi.getPublicKeys(userId);
    }
    return records;
  },
});

const result = await chat.decryptEventsAsync({ events });
```

The hook also supplies the keys a new conversation key is encrypted to:
`prepareConversationKeyChangeAsync`, `prepareGroupCreateAsync`,
`prepareGroupMembersChangeAsync` and `prepareGroupMembersRemoveAsync` need no
`publicKeys`, only the members' user ids. Only these five `Async` methods
call the hook. Setting it turns the key cache on, and a lookup that did not
bring a key is not repeated for a minute. `setResolvePublicKeys` sets or
removes the hook on a chat that exists. See
["Other users' public keys"](../js/README.md#other-users-public-keys) in the
`@xdevplatform/chat-xdk` README, which also covers `missingPublicKeys` and
`addPublicKeys` for fetching the keys without a hook.

With a hook set, give a chat keys you already hold with `addSigningKeys` or
`addPublicKeys`. `setSigningKeys` replaces every stored key, the ones the
hook fetched included, and the chat then waits a minute before it asks the
hook for them again.

## Many users, many conversations

A server that signs many users in keeps **one chat per signed-in user**: a
chat holds one user's private keys and signs as that user. Use that chat
for all of the user's conversations, and never create one per conversation:
it keeps conversation keys by conversation and public keys by user id.

Give every chat **the same `resolvePublicKeys` function**, over one cache of
`GET /2/users/{id}/public_keys` answers for the whole process, so two chats
that meet the same user cost one request. The cache shares a lookup that is
under way, drops a lookup that failed so the next call tries again, and
expires each answer after a few minutes so a key a user registers later is
picked up:

```js
import { createChat } from "@xdevplatform/chat-xdk-server";

const KEY_TTL_MS = 5 * 60_000;
const keyCache = new Map(); // userId -> { records: Promise<records | null>, expires }
const resolvePublicKeys = async (ids) => {
  const out = {};
  await Promise.all(ids.map(async (id) => {
    let entry = keyCache.get(id);
    if (!entry || entry.expires <= Date.now()) {
      const fresh = { expires: Date.now() + KEY_TTL_MS };
      // A failed lookup is dropped, so the next call fetches again.
      fresh.records = xApi.getPublicKeys(id).catch(() => {
        if (keyCache.get(id) === fresh) keyCache.delete(id);
        return null;
      });
      keyCache.set(id, (entry = fresh));
    }
    const recs = await entry.records;
    if (recs) out[id] = recs;
  }));
  return out;
};

const chats = new Map(); // localUserId -> Promise<ServerChat>
function chatFor(user) {
  if (!chats.has(user.id)) chats.set(user.id, openChat(user));
  return chats.get(user.id);
}
async function openChat(user) {
  const chat = await createChat({ resolvePublicKeys });
  chat.importKeys({ keys: await secretStore.get(user.id), signingKeyVersion: user.signingKeyVersion });
  chat.setIdentity({ userId: user.id, signingKeyVersion: user.signingKeyVersion });
  return chat;
}

// For a request of a signed-in user:
const chat = await chatFor(user);
const result = await chat.decryptEventsAsync({ events });
```

`xApi.getPublicKeys(id)` stands for your call to
`GET /2/users/{id}/public_keys`, which resolves to the `data` array of the
response. `chats` keeps the promise of each chat, so two requests of one
user that arrive together share one chat. When a user signs out, take the
chat out of `chats` and call `free()` on it.

Before 0.7.6, wait for a process's first `createChat` call to return before
you make the next. Chats created at the same time on first use shared one
chat's keys and identity.

[`examples/js/src/multi-user.mjs`](../../../examples/js/src/multi-user.mjs)
has this pattern as code that runs, with tests. See
[Many users, many conversations](../../../docs/API.md#many-users-many-conversations)
for what a chat keeps and when a key a user registers later is picked up.

The result reports what the batch still could not use, each map keyed as
`errors` is, by the event's index in the batch: `missingSigningKeys`, the
events whose sender's signing key the call did not have;
`unverifiedKeyChanges`, the key changes whose signature did not verify; and
`undecryptableKeyChanges`, the key changes whose key this chat could not
decrypt. `rejectedSigningKeys` holds the signing keys left out because their
identity binding does not verify, by signing key index.

The keys and the version to encrypt with are reported per conversation, by
the conversation id events carry: `result.conversationKeys.keysByConversation`
and `result.conversationKeys.latestVersions`. `conversationKeys.keys` and
`conversationKeys.latestVersion` hold the same for a batch of one
conversation; `latestVersion` is `null` for a batch of more than one. See
[`docs/API.md`](../../../docs/API.md#signing-keys-for-key-changes).

## API

Every other call is that of `@xdevplatform/chat-xdk`: see its
[README](../js/README.md) and the **JS** column of
[`docs/API.md`](../../../docs/API.md). The package exports the same names,
and `ServerChat` extends its `ChatWithJuicebox`.

## Network access

Each chat makes the one request a chat from `@xdevplatform/chat-xdk` makes:
an anonymous `GET https://api.x.com/2/chat/features` in the background,
which reads the feature switches that pick the format the SDK sends in. A
process that reaches the X API under another host name sets the
`CHAT_XDK_API_BASE_URL` environment variable to its base URL. See
"Network access" in its [README](../js/README.md#network-access).

## Security limitations

The protocol provides **no forward secrecy and no post-compromise
security**: whoever obtains the identity private key can read every
conversation key ever encrypted to its public key, past and future. See
[docs/CRYPTO.md — Known Limitations](../../../docs/CRYPTO.md#known-limitations).

## License

MIT — see [`LICENSE`](LICENSE). Third-party notices:
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
