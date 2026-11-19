# chat-xdk Go bindings

Go bindings for the X Chat SDK — encryption for X Direct Messages.

## Architecture

```
Go (chatxdk) → cgo → C FFI (chat_xdk.h) → Rust static lib (libchat_xdk_ffi.a) → chat-xdk-core
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
    // opt-in conversation-key cache. The cache keeps the key of every key
    // change that verifies in DecryptEvents or DecryptEvent, and of every
    // key change this chat prepares.
    _ = chat.ImportKeys(chatxdk.ImportKeysParams{Keys: privateKeyBytes, SigningKeyVersion: registeredKeyVersion})
    chat.SetIdentity(chatxdk.SetIdentityParams{UserID: myUserID, SigningKeyVersion: registeredKeyVersion})
    chat.SetCacheKeys(true)
    _ = chat.SetSigningKeys(signingKeyEntries)
    // SetSigningKeys replaces the stored keys; AddSigningKeys adds to them,
    // such as the keys of a member who joins later.
    _ = chat.AddSigningKeys(newMemberSigningKeyEntries)

    // Or let the chat ask for the public keys it lacks, in place of
    // SetSigningKeys and AddSigningKeys: see "Public keys" below.
    chat.SetResolvePublicKeys(fetchPublicKeys)

    // Batch load: decrypt many events at once (unset SigningKeys = stored signing keys)
    batch, err := chat.DecryptEvents(chatxdk.DecryptEventsParams{Events: rawEventB64List})
    if err != nil {
        panic(err)
    }

    for _, row := range batch.Events {
        if row.Event.Type == "Message" {
            fmt.Println(row.Event.AsMessage().Text())
        }
    }

    // A key change verifies with the signing keys of the member who made it.
    // One that did not verify is here, by its index in the batch; when its
    // key was dropped, the messages under it are in batch.Errors.
    for index, change := range batch.UnverifiedKeyChanges {
        fmt.Println(index, change.Reason, change.KeyDropped)
    }
    // Each signed event whose sender's signing key the call lacked is in
    // batch.MissingSigningKeys, with the user and key version to fetch.
    // Key changes whose key this chat could not decrypt, and signing keys
    // left out because their identity binding does not verify, are reported
    // the same way: batch.UndecryptableKeyChanges, batch.RejectedSigningKeys.

    // The version to encrypt with: for a batch of one conversation,
    // batch.ConversationKeys.LatestVersion; for any batch,
    // batch.ConversationKeys.LatestVersions[conversationID].

    // Single webhook: the empty key map and unset signing keys resolve from
    // the session stores
    event, err := chat.DecryptEvent(chatxdk.DecryptEventParams{EventB64: eventB64})
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

With the key cache on, calls that omit their conversation key read it from
the cache: the encrypt methods and the group title, description and avatar
changes use the conversation's newest key, and `DecryptEvent`, `DecryptFile`
and `FileDecryptor` the key at the version the event names. So
`DecryptFileParams.ConversationKeys`, `FileDecryptorParams.ConversationKeys`
and `GroupAvatarChangeParams.ConversationKeyVersion` may be left unset. A
value that is passed is used as is.

## Public keys

A chat verifies events with other users' signing keys and encrypts a new
conversation key to their identity keys. Both are in the records
`GET /2/users/{id}/public_keys` returns in `data`: a `PublicKeyRecord`
unmarshals from one as the API sends it.

Set a hook and the chat asks for the keys it lacks:

```go
chat.SetResolvePublicKeys(func(userIDs []string) (map[string][]chatxdk.PublicKeyRecord, error) {
    records := make(map[string][]chatxdk.PublicKeyRecord)
    for _, userID := range userIDs {
        // GET /2/users/{userID}/public_keys with your X API client.
        var response struct {
            Data []chatxdk.PublicKeyRecord `json:"data"`
        }
        if err := getJSON("/2/users/"+userID+"/public_keys", &response); err != nil {
            continue // a user left out is reported as still missing
        }
        records[userID] = response.Data
    }
    return records, nil
})
```

With a hook set:

- `DecryptEvents`, when `SigningKeys` is nil, calls the hook for the senders
  whose signing keys the batch lacked, stores what it returns, and decrypts
  the batch once more. What is still missing is in the result's
  `MissingSigningKeys`.
- `PrepareConversationKeyChange`, `PrepareGroupCreate`,
  `PrepareGroupMembersChange` and `PrepareGroupMembersRemove`, when
  `PublicKeys` is nil, call the hook for the members with no stored key and
  encrypt the new key to the stored keys. The members are the users in
  `MemberIDs` and `AdminIDs` for a create, in `CurrentMemberIDs` and
  `NewMemberIDs` for a member add, in `RemainingMemberIDs` for a removal, and
  in `MemberIDs` for a key change; a key change of a one-to-one needs only
  its `ConversationID`. A member who still has no stored key fails the call
  with an error that names the user.

Setting a hook turns the key cache on (`SetCacheKeys`). An error the hook
returns is returned by the call that ran it. A lookup is not repeated for a
minute: a user the hook was called for and whose key did not arrive is left
out of the next calls until then.

Without a hook, the same steps are calls of their own:

```go
batch, _ := chat.DecryptEvents(chatxdk.DecryptEventsParams{Events: rawEventB64List})
userIDs, _ := chat.MissingPublicKeys(batch) // the users to fetch, once a minute each
records, _ := fetchPublicKeys(userIDs)      // the hook's function, called by hand
_ = chat.AddPublicKeys(records)
batch, _ = chat.DecryptEvents(chatxdk.DecryptEventsParams{Events: rawEventB64List})
```

`AddPublicKeys` adds to the keys `SetSigningKeys` and `AddSigningKeys`
store. Signing keys and public keys that a call is passed are used as they
are, and the hook is not called for that call.

## API

See the **Go** column of the unified tables in [`docs/API.md`](../../docs/API.md) for the full method list, parameters, and return types. Files (media) are covered under [Files (Media)](../../docs/API.md#files-media). Method names use **PascalCase**; raw-byte parameters cross the FFI boundary as **base64 strings**.

## Network access

Each chat makes one kind of request itself: an anonymous
`GET https://api.x.com/2/chat/features` in the background, which reads the X
API's feature switches that pick the format the SDK sends in. A chat reads
them when it is created, again once `SetIdentity` gives it a sender, and
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
(also shipped under `go/chatxdk/`).
