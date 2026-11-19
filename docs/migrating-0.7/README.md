# Migrating to chat-xdk 0.7.x

0.7.x, the 0.7 release line, changes the API of every binding. Each guide
below moves one binding's code written for 0.5.x (0.5.0, 0.5.1 or 0.5.2) to
0.7.x on its own, and every guide has the same sections:

0. **Before you start**: the install line, the readers to upgrade first, and
   the feature-switch request.
1. **Symbol index**: every 0.5.x name that changes, with its 0.7.x form.
2. **Compile-time changes**, in the order an app meets them.
3. **Runtime and behavior changes**, which nothing reports before the code
   runs.
4. **Group and receipt signing**: every signed request, with its X API
   method, path and body.
5. **Verify**: the build, a search for 0.5.x names, and a round trip.

A checklist at the top of each guide tags every item `[rollout]`,
`[compile]`, `[runtime]` or `[new]`. CI compiles the 0.7.x half of every
snippet in the guides against the newest 0.7.x source. [Why 0.7.x
changes](why.md) explains why each change was made.

| Binding | Package | Migration guide |
|---|---|---|
| Rust | `chat-xdk-core` | [Rust](rust.md) |
| Python | `chatxdk` | [Python](python.md) |
| JavaScript and TypeScript (WASM) | `@xdevplatform/chat-xdk`, or `@xdevplatform/chat-xdk-server` on a Node server that keeps its own keys | [JavaScript](javascript.md) |
| Go | `github.com/xdevplatform/chat-xdk/go/chatxdk` | [Go](go.md) |
| JVM | `com.x:chatxdk` | [JVM](jvm.md) |
| .NET | `XDevPlatform.ChatXdk` | [.NET](dotnet.md) |
| C ABI, called directly | `chat_xdk.h` | [C ABI](c-abi.md) |

One step applies across bindings: upgrade every app that reads your
conversations before any sender can send v1, the format with per-message
keys, and before you add group members with a description, because 0.5.x
rejects those signatures. Each guide explains it under
"Upgrade readers first".

## Install the newest 0.7.x release

The guides describe the newest 0.7.x release, not 0.7.0, so install 0.7.5
or a later 0.7.x release. Each guide's "Install 0.7.x" section gives the
line for its package manager: one that takes the newest 0.7.x release where
the package manager resolves a range (Cargo, pip, npm and Go), and the
release's own number where it takes a single version (Maven, Gradle and
NuGet). Every binding is released under one version number, so the newest
release is the same in each.

## What each 0.7.x release changed

An app that moves from 0.5.x to the newest 0.7.x release follows its guide,
which covers every row below. An app that already runs a 0.7.x release
reads the rows after its own: each says what that release changed and what
the app does about it. The [CHANGELOG](../../CHANGELOG.md) lists every
change by release.

| Release | What changed | What an app on an earlier 0.7.x release does |
|---|---|---|
| 0.7.0 | The API the guides migrate to: calls take params objects, sends can use per-message keys (v1) once the X API's `v1_send` switch turns them on, a message's files are encrypted from the message, and group changes and read receipts are signed. | Follows its binding's guide from 0.5.x. |
| 0.7.1 | Adds `encrypt_file_with_key` and `decrypt_file_with_key`, which encrypt and decrypt a file under a key the app holds, such as a group's avatar image, in the format 0.5.x `encrypt_stream` wrote. The guides say to re-encrypt a group's avatar under the new conversation key after every key rotation. | Moves each `encrypt_stream` and `decrypt_stream` call for a file no message carries to them, and re-encrypts the avatar after a rotation ([why](why.md#a-file-is-encrypted-from-its-message), with each binding's section). |
| 0.7.2 | The reply params take `reply_to_message_id` and the edit params `target_message_id`, the signed `message_id` of the message quoted or edited, and a media attachment descriptor takes `plaintext_sha256`. While a chat sends v1, every event it signs takes signature version 10; while it sends v0 they sign at version 7, apart from a member add with a description, at version 8. A reply preview validates only when it quotes its message exactly, and a reply embeds no key change. The bindings read the feature switches again 5 minutes after each answer, with the sender's bucket, and retry a request that fails. | Names the quoted or edited message in a reply or edit built without that message's event ([why](why.md#a-reply-preview-quotes-its-message-exactly)). After a restart, decrypts a conversation's key changes again before changing its key ([why](why.md#v0-is-the-default-and-the-x-apis-v1_send-switch-turns-on-v1)). Rust: adds `plaintext_sha256` to an `AttachmentDescriptor::Media` struct literal ([Rust](rust.md#types-are-non_exhaustive)). Rust and the C ABI: requests the URL `feature_switches_url` (`chat_xdk_feature_switches_url`) returns, again every `FEATURES_REFRESH_MS` (`CHAT_XDK_FEATURES_REFRESH_MS`) ([Rust](rust.md#the-feature-switch-request), [C ABI](c-abi.md#the-feature-switch-request)). |
| 0.7.3 | JavaScript only. The chat `@xdevplatform/chat-xdk` creates no longer has `importKeys` and `exportKeys`: from 0.7.0 through 0.7.2 any script that could reach a chat in a page could call `exportKeys` and take its private keys. `@xdevplatform/chat-xdk-server`, a new package for Node servers that keep their own keys, has both calls. | A server that calls `importKeys` or `exportKeys` imports `createChat`, and `ImportKeysParams` in TypeScript, from `@xdevplatform/chat-xdk-server`. A browser app keeps its keys in Juicebox with `setup` and `unlock` ([JavaScript](javascript.md#importkeys-and-exportkeys-on-a-server)). |
| 0.7.4 | The `CHAT_XDK_API_BASE_URL` environment variable names the X API's base URL for a process that reaches it under another host name. A feature-switch answer stays for 5 minutes after it arrives, so an app that creates a chat for each send follows `v1_send`, where it sent v0 before. Python sends the feature-switch request through the proxy the environment names, and reads the switches again in a forked child. | Changes no code. An app that creates a chat for each send starts sending v1 once `v1_send` is on for it, so its readers upgrade first. A process that reaches the X API under another host name sets `CHAT_XDK_API_BASE_URL`, and a Python app under uWSGI creates its chat in each worker ([why](why.md#the-feature-switch-request), [Python](python.md#the-feature-switch-request)). |
| 0.7.5 | `decrypt_file` and `file_decryptor` open media a reply quotes when the reply's preview names the quoted message without embedding it, as replies from X clients can. 0.7.0 through 0.7.4 failed with `the reply does not embed the message it quotes`. | Passes the conversation's whole key map with the reply's event, and treats a file opened this way as what the reply claims to quote: nothing checks it against the quoted message ([why](why.md#media-a-reply-quotes-opens-with-the-replys-event)). |
| 0.7.6 | A chat can fetch other users' public keys through a `resolve_public_keys` hook: JavaScript and .NET call it from new `Async` forms of `decrypt_events` and of the four prepare calls that make a conversation key, and the other bindings from the methods they had. `add_public_keys`, `missing_public_keys` and the batch result's `missing_signing_keys` are the calls the hook is built from, `add_signing_keys` adds to the stored signing keys, and those four prepare calls take `public_keys` as optional. The key cache is filled by `decrypt_event` and by the prepare calls as well as by `decrypt_events`, and keeps every key version, so `decrypt_file`, `file_decryptor` and `prepare_group_avatar_change` take their key map or key version as optional. `decrypt_events` reports the key changes that did not verify or that the chat could not decrypt and the signing keys it rejected, and reports keys and the version to encrypt with by conversation (`keys_by_conversation`, `latest_versions`). | Reads `latest_versions[conversation_id]` where it read `latest_version` from a batch of more than one conversation, which is now null, and `keys_by_conversation` for a key version two conversations of one batch share, which `keys` leaves out. Updates any code that matches the text of a verification error: `signature missing or no matching signing key` is now one of five messages that say why. With the key cache on, expects a send that omits its key right after a prepare call to use the prepared key, and prepares the change again when its request fails. Changes nothing else. It can set a hook and leave out the keys it passed ([why](why.md#the-chat-can-fetch-public-keys-and-keep-keys), with each binding's section), and a server with many signed-in users keeps one chat per user and one hook function for all of them ([API.md](../API.md#many-users-many-conversations)). |

[API.md](../API.md) documents the API of the newest release.
