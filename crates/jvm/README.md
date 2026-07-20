# chat-xdk JVM bindings

JVM bindings for the X Chat SDK — encryption for X Direct Messages.

## Architecture

```
JVM (com.x.chatxdk) → JNA → Rust cdylib (libchat_xdk_dotnet) → chat-xdk-core
```

The native library is `libchat_xdk_dotnet`, the Rust cdylib built by `crates/dotnet` and loaded via JNA. Complex values cross the FFI boundary as JSON UTF-8 strings.

## Prerequisites

- **JDK 17+** and **Maven**
- **Rust** (stable) to build the native `chat_xdk_dotnet` library

## Setup

From the repo root, build the native library:

```bash
cargo build -p chat-xdk-dotnet --release
```

Run the JVM tests (builds the cdylib, then `mvn test` with `jna.library.path` pointing at `target/release`):

```bash
make jvm-test
```

For your app, depend on the `chatxdk` artifact (`mvn install` from `crates/jvm/java/chatxdk` or publish to your registry) and ensure JNA can load `chat_xdk_dotnet` (place the shared library next to the JVM or set `jna.library.path`).

## Quick Start

```java
import com.fasterxml.jackson.databind.JsonNode;
import com.x.chatxdk.*;
import com.x.chatxdk.Types.*;

import java.util.Map;

try (Chat chat = new Chat()) {
    // Load a key blob + its registered version, then set the session once:
    // identity, the opt-in conversation-key cache, and the signing-key store.
    chat.importKeys(exportedBytes, registeredKeyVersion);
    chat.setIdentity(myUserId, registeredKeyVersion);
    chat.setCacheKeys(true);
    chat.setSigningKeys(signingKeys);

    // Batch load — null signing keys fall back to the store; the verified
    // conversation keys populate the cache.
    DecryptEventsResult batch = chat.decryptEvents(rawEventB64List, null);

    // Individual events: null arguments resolve from the session stores.
    JsonNode event = chat.decryptEvent(eventB64, (Map<String, byte[]>) null, null);
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

Stateless helpers (base64/hex, MIME sniff, image dimensions) live on **`ChatXdkUtilities`**.

## API

See the **JVM** column of the unified tables in [`docs/API.md`](../../docs/API.md) for the full method list, parameters, and return types.

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
