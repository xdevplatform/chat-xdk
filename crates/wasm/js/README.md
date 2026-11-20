# chat-xdk JavaScript/WASM bindings

JavaScript/WASM bindings for the X Chat SDK — encryption for X Direct Messages.

## Architecture

```
JavaScript (chat-xdk) → wasm-bindgen → Rust WASM (chat_xdk_wasm) → chat-xdk-core
```

The Rust WASM layer is a pure crypto engine; Juicebox key-storage lifecycle is orchestrated in the JS wrapper (`chat.js`, exported by `index.js`).

A chat from this package keeps its private keys in Juicebox and has no
method that returns them. A Node server that keeps its keys in its own
secret store uses [`@xdevplatform/chat-xdk-server`](../js-server/README.md)
instead: the same API, with `importKeys` and `exportKeys`.

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
the WASM build that `chat.js` resolves at `./pkg/`:

```bash
make wasm   # from the repo root; builds --target web, stages js/pkg/ and the js-server/ package
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
// public keys response. setSigningKeys replaces the stored keys;
// addSigningKeys adds to them.
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

// A key change verifies with the signing keys of the member who made it. One
// that did not verify is here, by its index in the batch; when its key was
// dropped, the messages under it are in result.errors. With a public-key
// hook, decryptEventsAsync fetches the keys a batch is missing: see "Other
// users' public keys" below.
for (const [index, change] of Object.entries(result.unverifiedKeyChanges)) {
  console.warn(index, change.reason, change.senderId, change.keyDropped);
}
// Three more maps are reported the same way: result.missingSigningKeys, the
// events whose sender's signing key the call did not have;
// result.undecryptableKeyChanges, the key changes whose key this chat could
// not decrypt; and result.rejectedSigningKeys, the signing keys left out
// because their identity binding does not verify.

// The version to encrypt with: for a batch of one conversation,
// result.conversationKeys.latestVersion; for any batch,
// result.conversationKeys.latestVersions[conversationId].

// Individual events after the initial load: the empty key map resolves from
// the cache and the unset signing keys from the store (pass either
// explicitly to override). A key change that verifies here is cached as one
// in a batch is.
const event = chat.decryptEvent({ eventB64: webhookEventB64 });
// The message's files decrypt from the cache too, with no key map.
for (const { mediaHashKey } of event.mediaHashes ?? []) {
  const encrypted = await download(mediaHashKey);
  const file = chat.decryptFile({ encrypted, eventB64: webhookEventB64, mediaHashKey });
}

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

While the key cache is on, it keeps every key version of a conversation
whose key change verified in `decryptEvents` or `decryptEvent`, and every key
the chat made itself with `prepareConversationKeyChange`,
`prepareGroupCreate`, `prepareGroupMembersChange` or
`prepareGroupMembersRemove`. A call that omits its conversation key reads it
from there: the encrypt calls and the group title, description and avatar
changes use the conversation's newest key (`prepareGroupAvatarChange` needs
no `conversationKeyVersion`), and `decryptEvent`, `decryptFile` and
`fileDecryptor` the version the event names. A prepared key is cached before
its request is sent: if the X API rejects the request, prepare the change
again.

## Other users' public keys

A chat verifies events with the signing keys of the users who sent them, and
encrypts a new conversation key to its members' identity keys. Both are in
the records `GET /2/users/{id}/public_keys` returns. Set a hook that fetches
them, and the chat asks it for the keys it is missing:

```typescript
import { createChat, type PublicKeyRecords } from "@xdevplatform/chat-xdk";

const chat = await createChat({
  getAuthToken,
  resolvePublicKeys: async (userIds) => {
    const records: PublicKeyRecords = {};
    for (const userId of userIds) {
      // The `data` array of GET /2/users/{id}/public_keys, as the API sends it.
      records[userId] = await xApi.getPublicKeys(userId);
    }
    return records;
  },
});

// Verifies with the stored keys, after fetching the keys of the senders it
// has none for.
const result = await chat.decryptEventsAsync({ events: rawEvents });

// Encrypts the new key to the stored keys of the members named, after
// fetching the ones it has none for. No publicKeys needed.
const group = await chat.prepareGroupCreateAsync({
  conversationId: "g123",
  memberIds: ["111", "222"],
  adminIds: ["111"],
});
```

- The hook takes user ids and returns, or resolves to, each user's records
  by user id. Leave out a user it has nothing for. What it throws rejects
  the call that asked.
- Only five methods call the hook: `decryptEventsAsync`,
  `prepareConversationKeyChangeAsync`, `prepareGroupCreateAsync`,
  `prepareGroupMembersChangeAsync` and `prepareGroupMembersRemoveAsync`.
  Each returns a Promise of what the method it is named after returns. The
  other methods never call it.
- `decryptEventsAsync` calls the hook only when it is passed no
  `signingKeys`, and the prepare methods only when they are passed no
  `publicKeys`.
- `chat.setResolvePublicKeys(hook)` sets or replaces the hook later, and
  `chat.setResolvePublicKeys(null)` removes it.
- Setting a hook turns the key cache on (`setCacheKeys(true)`). Removing the
  hook leaves the cache on.
- A lookup that did not bring a key is not repeated for a minute, so a user
  without keys does not cost a request with every batch.

With `publicKeys` omitted, a prepare call encrypts to the stored keys of the
members its params name, and throws when one of them has none:

| Call | Members it reads keys for |
|---|---|
| `prepareGroupCreate` | `memberIds` and `adminIds` |
| `prepareGroupMembersChange` | `currentMemberIds` and `newMemberIds` |
| `prepareGroupMembersRemove` | `remainingMemberIds`: the members who stay, you included |
| `prepareConversationKeyChange` | `memberIds`: every participant, you included. For a one-to-one, `conversationId` is enough |

To fetch the keys yourself instead, without a hook, use the two calls the
hook is built on. `decryptEvents` reports each event whose sender's signing
key it did not have in `missingSigningKeys`, by the event's index in the
batch; `missingPublicKeys` lists those senders, and `addPublicKeys` stores
their records, keeping the keys already stored:

```typescript
let result = chat.decryptEvents({ events: rawEvents });
const userIds = chat.missingPublicKeys(result);
if (userIds.length > 0) {
  chat.addPublicKeys(await fetchPublicKeys(userIds)); // { [userId]: records }
  result = chat.decryptEvents({ events: rawEvents });
}
```

`missingPublicKeys` also remembers what it returned: it does not list the
same missing key again for a minute.

`addPublicKeys` and `addSigningKeys` add to the stored keys, where
`setSigningKeys` replaces them all. With a hook set, add: `setSigningKeys`
also drops the keys the hook fetched, and the chat waits a minute before it
asks the hook for them again.

### Many users, many conversations

A server often has many users signed in at once, each in many conversations.

- **One chat per signed-in user.** A chat holds one user's private keys and
  signs as that user. Keep one for each signed-in user and use it for all of
  that user's conversations; never create one per conversation. The chat
  keeps conversation keys by conversation and public keys by user id.
- **One hook function for every chat.** Each chat stores only the keys it
  was given, so give every chat the same `resolvePublicKeys`, over one cache
  of `GET /2/users/{id}/public_keys` answers for the whole process. Then two
  chats that meet the same user cost one request. Have the cache share a
  lookup that is under way, drop a lookup that failed so the next call tries
  again, and expire each answer after a few minutes so a key a user
  registers later is picked up.
- **Add keys, don't replace them**, as above.

```js
import { createChat } from "@xdevplatform/chat-xdk";

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

const chats = new Map(); // localUserId -> Promise<chat>
function chatFor(user) {
  if (!chats.has(user.id)) chats.set(user.id, openChat(user));
  return chats.get(user.id);
}
async function openChat(user) {
  const chat = await createChat({
    juiceboxConfig: user.juiceboxConfig,
    getAuthToken: user.getAuthToken,
    resolvePublicKeys,
  });
  await chat.unlock(user.pin);
  chat.setIdentity({ userId: user.id, signingKeyVersion: user.signingKeyVersion });
  return chat;
}

// For a request of a signed-in user:
const chat = await chatFor(user);
const result = await chat.decryptEventsAsync({ events: rawEvents });
```

`xApi.getPublicKeys(id)` stands for your call to
`GET /2/users/{id}/public_keys`, which resolves to the `data` array of the
response. `chats` keeps the promise of each chat, so two requests of one
user that arrive together share one chat. Run `unlock` and the other
Juicebox calls one chat at a time: juicebox-sdk reads its auth-token callback
from one place in the process. When a user signs out, take the chat out of
`chats` and call `free()` on it.

Before 0.7.6, wait for a process's first `createChat` call to return before
you make the next. Chats created at the same time on first use shared one
chat's keys and identity.

[`examples/js/src/multi-user.mjs`](../../../examples/js/src/multi-user.mjs)
has this pattern as code that runs, with tests, and
[Many users, many conversations](../../../docs/API.md#many-users-many-conversations)
says when a key a user registers later is picked up.

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
once. The answer stays for 5 minutes after it arrives, so a chat created in
that time takes it at once even when no other chat is alive: an app that
creates a chat for each send makes one request per URL every 5 minutes. The
request carries no credentials and never delays or fails a call.
One that fails is retried in the background, 1 second later, then after
twice the previous wait, at most 5 minutes apart. Each answer replaces the
one before; until an answer for the chat's URL arrives, sends stay in v0,
the format 0.5.x sends. From Node 20.16 these requests, and the waits before
them, never keep the process alive; before it, a request in flight can delay
exit until it ends, at most 2 seconds. In a browser, the request is a simple
cross-origin GET made with `fetch`. A Node process that reaches the X API
under another host name sets the `CHAT_XDK_API_BASE_URL` environment variable
to its base URL, in place of `https://api.x.com`, before it creates its
chats.

## Security limitations

The underlying protocol provides **no forward secrecy and no post-compromise
security**: compromise of an identity private key exposes all conversation
keys ever encrypted to that public key — and therefore all past and future
messages in those conversations. Key rotation does not retroactively protect
messages encrypted under a previous key. See
[docs/CRYPTO.md — Known Limitations](../../../docs/CRYPTO.md#known-limitations).

### No method returns the private keys

A chat from this package has no `importKeys` or `exportKeys`, and no method
that returns its private keys: `setup` hands them to Juicebox and `unlock`
loads them back, inside the SDK. A script that gets hold of the chat,
including code injected via XSS or a compromised dependency, has no call
that hands it the keys.

That is not isolation. Script running in the page can still use the chat
while it runs (decrypt, sign and send as you, and make its Juicebox calls)
and can reach what the page's memory holds, including the keys as `setup`
and `unlock` pass them to and from Juicebox. Keep untrusted script out of
pages that unlock a chat. Servers that keep keys themselves use
[`@xdevplatform/chat-xdk-server`](../js-server/README.md); never bundle it
into a browser app.

## License

MIT — see [`LICENSE`](LICENSE). Third-party notices:
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
