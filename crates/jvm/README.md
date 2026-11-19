# chat-xdk JVM bindings

JVM bindings for the X Chat SDK — encryption for X Direct Messages.

## Architecture

```
JVM (com.x.chatxdk) → JNA → Rust cdylib (libchat_xdk_ffi) → chat-xdk-core
```

The native library is `libchat_xdk_ffi`, the C ABI shared library built from `crates/ffi` and loaded via JNA. Complex values cross the FFI boundary as JSON UTF-8 strings.

## Prerequisites

- **JDK 17+** and **Maven**
- **Rust** (stable) to build the native `chat_xdk_ffi` library

## Setup

From the repo root, build the native library:

```bash
cargo build -p chat-xdk-ffi --release
```

Run the JVM tests (builds the cdylib, then `mvn test` with `jna.library.path` pointing at `target/release`):

```bash
make jvm-test
```

For your app, depend on the `com.x:chatxdk` artifact. The published jar bundles `chat_xdk_ffi` for macOS (arm64, x64), Linux (x64, arm64) and Windows (x64) and loads it from the jar. A jar you build with `mvn install` from `crates/jvm/java/chatxdk` bundles none, so JNA loads the library from `jna.library.path` (or the system library path).

## Quick Start

```java
import com.fasterxml.jackson.databind.JsonNode;
import com.x.chatxdk.*;
import com.x.chatxdk.Types.*;

import java.util.Map;

try (Chat chat = new Chat()) {
    // Load a key blob + its registered version, then set the session once:
    // identity, the opt-in conversation-key cache, and the signing-key store.
    // The cache keeps the key of every key change that verifies in
    // decryptEvents or decryptEvent, and of every key change this chat
    // prepares.
    chat.importKeys(new ImportKeysParams(exportedBytes, registeredKeyVersion));
    chat.setIdentity(new SetIdentityParams(myUserId, registeredKeyVersion));
    chat.setCacheKeys(true);
    chat.setSigningKeys(signingKeys);
    // setSigningKeys replaces the stored keys; addSigningKeys adds to them,
    // such as the keys of a member who joins later.
    chat.addSigningKeys(newMemberSigningKeys);

    // Batch load — unset (null) signing keys fall back to the store; the
    // verified conversation keys populate the cache.
    DecryptEventsResult batch = chat.decryptEvents(new DecryptEventsParams(rawEventB64List));

    // A key change verifies with the signing keys of the member who made it.
    // One that did not verify is here, by its index in the batch; when its key
    // was dropped, the messages under it are in batch.errors. For
    // MissingSigningKey, add the public keys of change.senderId
    // (GET /2/users/{id}/public_keys) and decrypt again.
    batch.unverifiedKeyChanges.forEach((index, change) ->
            System.err.println(index + " " + change.reason + " " + change.senderId));
    // Key changes whose key this chat could not decrypt, and signing keys
    // left out because their identity binding does not verify, are reported
    // the same way: batch.undecryptableKeyChanges, batch.rejectedSigningKeys.

    // The version to encrypt with: for a batch of one conversation,
    // batch.conversationKeys.latestVersion; for any batch,
    // batch.conversationKeys.latestVersions.get(conversationId).

    // Individual events: the empty key map and unset signing keys resolve
    // from the session stores.
    JsonNode event = chat.decryptEvent(new DecryptEventParams(eventB64, Map.of()));
    String conversationId = event.path("conversation_id").asText();

    // Sending resolves the identity and conversation key from the session too.
    SendPayload payload =
            chat.encryptMessage(new EncryptMessageParams(conversationId, "hi!"));
    // Reply / react by handing back the raw event being answered.
    SendPayload reply =
            chat.encryptReply(new EncryptReplyParams(conversationId, "pong", eventB64));
    SendPayload reaction =
            chat.encryptAddReaction(new EncryptReactionParams(eventB64, "👍"));
}
```

With the key cache on, calls that omit their conversation key read it from
the cache: the encrypt methods and the group title, description and avatar
changes use the conversation's newest key, and `decryptEvent`, `decryptFile`
and `fileDecryptor` the key at the version the event names. So
`DecryptFileParams` and `FileDecryptorParams` can be created without a key
map, and `GroupAvatarChangeParams` without a key version. A value that is
passed is used as is.

## Other users' public keys

`decryptEvents` verifies each event with its sender's signing key, and the
four prepare calls that make a conversation key (`prepareGroupCreate`,
`prepareGroupMembersChange`, `prepareGroupMembersRemove`,
`prepareConversationKeyChange`) encrypt it to each member's identity key.
Both are in the records `GET /2/users/{id}/public_keys` returns. Set a
resolver that fetches those records, and the chat gets the keys it is
missing by itself:

```java
ObjectMapper mapper = new ObjectMapper();
chat.setResolvePublicKeys(userIds -> {
    Map<String, List<PublicKeyRecord>> records = new HashMap<>();
    for (String userId : userIds) {
        // The "data" array of GET /2/users/{id}/public_keys, fetched with
        // your X API client.
        JsonNode data = fetchPublicKeys(userId);
        records.put(userId, List.of(mapper.treeToValue(data, PublicKeyRecord[].class)));
    }
    return records;
});

// No signing keys passed: the chat calls the resolver for the users whose
// keys the page is missing, stores what it returns, and decrypts once more.
DecryptEventsResult page = chat.decryptEvents(new DecryptEventsParams(rawEventB64List));

// No public keys passed: the chat calls the resolver for the members it has
// no stored keys for, then encrypts the new key to the stored keys.
PreparedConversationChange created =
        chat.prepareGroupCreate(new GroupCreateParams(groupId, memberIds, adminIds));
```

- Setting a resolver turns the key cache on (`setCacheKeys(true)`). The
  resolver runs on the calling thread, at most once per call, and an
  exception it throws is thrown by the decrypt or prepare call.
- `page.missingSigningKeys` lists, by event index, the user id and key
  version of each signing key the page still lacks. A lookup that did not
  bring its key is not repeated for a minute, so the resolver is not called
  with every page for a key it cannot find.
- Without a resolver, do the same by hand: `chat.missingPublicKeys(page)`
  returns the users to fetch, `chat.addPublicKeys(records)` stores their
  records, and a second `decryptEvents` reads them.
- With no `publicKeys`, the prepare calls read the stored keys of
  `memberIds` and `adminIds` (create), `currentMemberIds` and `newMemberIds`
  (members change), `remainingMemberIds` (members remove), and `memberIds`
  or the two users of a one-to-one `conversationId` (key change). A member
  with no stored key fails the call with an `INVALID_INPUT` error that names
  the member.
- A call that passes `signingKeys` or `publicKeys` uses them as is and never
  calls the resolver.

Stateless helpers (base64/hex, MIME sniff, image dimensions) live on **`ChatXdkUtilities`**.

## API

See the **JVM** column of the unified tables in [`docs/API.md`](../../docs/API.md) for the full method list, parameters, and return types. Files (media) are covered under [Files (Media)](../../docs/API.md#files-media).

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
the format 0.5.x sends. A process that reaches the X API under another host
name sets the `CHAT_XDK_API_BASE_URL` environment variable to its base URL,
in place of `https://api.x.com`, before it creates its chats.

## Security limitations

The underlying protocol provides **no forward secrecy and no post-compromise
security**: compromise of an identity private key exposes all conversation
keys ever encrypted to that public key — and therefore all past and future
messages in those conversations. Key rotation does not retroactively protect
messages encrypted under a previous key. See
[docs/CRYPTO.md — Known Limitations](../../docs/CRYPTO.md#known-limitations).

## License

MIT — see the repo [`LICENSE`](../../LICENSE). Third-party notices:
[`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md)
(also packed under `META-INF/` in the Maven jar).
