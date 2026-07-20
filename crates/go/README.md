# chat-xdk Go bindings

Go bindings for the X Chat SDK — encryption for X Direct Messages.

## Architecture

```
Go (chatxdk) → cgo → C FFI (chat_xdk.h) → Rust static lib (libchat_xdk_go.a) → chat-xdk-core
```

Complex values cross the FFI boundary as JSON strings and are unmarshaled into idiomatic Go structs.

## Prerequisites

- **Go** 1.21+
- **C compiler** (clang/gcc; Xcode on macOS, `build-essential` on Linux)
- Rust is **not** required for consumers — precompiled static libraries are committed under `libs/`.

## Setup

Add the module — the static library for your platform is already committed:

```bash
go get github.com/xdevplatform/chat-xdk/go/chatxdk
```

Supported platforms:

| OS | Arch | Directory |
|----|------|-----------|
| macOS | arm64 (Apple Silicon) | `libs/darwin_arm64/` |
| macOS | amd64 (Intel) | `libs/darwin_amd64/` |
| Linux | amd64 (glibc) | `libs/linux_amd64/` |
| Linux | amd64 (musl/Alpine) | `libs/linux_amd64_musl/` |

Contributors modifying the Rust core rebuild the static library with `make prebuilt` (requires Rust). See [docs/go-prebuilts.md](../../docs/go-prebuilts.md) for the prebuilt and CI workflow.

## Quick Start

```go
package main

import (
    "fmt"

    "github.com/xdevplatform/chat-xdk/go/chatxdk"
)

func main() {
    chat := chatxdk.New()
    defer chat.Close()

    // Import keys + registered version, then set the session stores once:
    // the identity used to sign, the signing keys used to verify, and the
    // opt-in conversation-key cache filled by the batch decrypt path.
    _ = chat.ImportKeysWithVersion(privateKeyBytes, registeredKeyVersion)
    chat.SetIdentity(myUserID, registeredKeyVersion)
    chat.SetCacheKeys(true)
    _ = chat.SetSigningKeys(signingKeyEntries)

    // Batch load: decrypt many events at once (nil = stored signing keys)
    batch, err := chat.DecryptEvents(rawEventB64List, nil)
    if err != nil {
        panic(err)
    }

    for _, row := range batch.Messages {
        if row.Event.Type == "Message" {
            fmt.Println(row.Event.AsMessage().Text())
        }
    }

    // Single webhook: nil maps resolve from the session stores
    event, err := chat.DecryptEvent(eventB64, nil, nil)
    if err != nil {
        panic(err)
    }
    _ = event

    // Sender and conversation key resolve from the session; explicit
    // SenderID/SigningKeyVersion and ConversationKey/ConversationKeyVersion
    // fields remain as overrides.
    payload, err := chat.EncryptMessage(chatxdk.EncryptMessageParams{
        ConversationID: "…",
        Text:           "Hello from Go!",
    })
    if err != nil {
        panic(err)
    }
    // The SDK generates the message id; read it back from payload.MessageID.
    _ = payload
}
```

## API

See the **Go** column of the unified tables in [`docs/API.md`](../../docs/API.md) for the full method list, parameters, and return types. Method names use **PascalCase**; raw-byte parameters cross the FFI boundary as **base64 strings**.

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
(also shipped under `go/chatxdk/`).
