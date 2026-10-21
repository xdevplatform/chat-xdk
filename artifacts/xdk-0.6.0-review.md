# Chat XDK 0.6.0 stack: final pre-merge review

- **Stack, bottom to top:** [#38](https://github.com/xdevplatform/chat-xdk/pull/38) → [#39](https://github.com/xdevplatform/chat-xdk/pull/39) → [#40](https://github.com/xdevplatform/chat-xdk/pull/40) → [#41](https://github.com/xdevplatform/chat-xdk/pull/41) → [#47](https://github.com/xdevplatform/chat-xdk/pull/47) → [#49](https://github.com/xdevplatform/chat-xdk/pull/49) → [#48](https://github.com/xdevplatform/chat-xdk/pull/48) → [#50](https://github.com/xdevplatform/chat-xdk/pull/50). The tip is `62c347c`: `main` (`4f06a02`) plus 83 commits. No open PR is based on #50.
- **Baseline:** tag `v0.5.2` (`cf1b03f`). `main` differs from it only in comments, `release.yml`, the `go.mod` retract comment and the prebuilt Go archives (`git diff --stat v0.5.2 origin/main`), so the API baseline is the same.
- **Open PRs outside the stack:** [#34](https://github.com/xdevplatform/chat-xdk/pull/34)–[#37](https://github.com/xdevplatform/chat-xdk/pull/37), [#22](https://github.com/xdevplatform/chat-xdk/pull/22) and [#19](https://github.com/xdevplatform/chat-xdk/pull/19). See S15.
- **Conventions:** paths are at the tip unless marked `@v0.5.2`. "Probe" means a throwaway program I ran; its output is in Appendix A. "Prior agent" means the transcripts of the two agents named in the task, cited by message index; those claims are UNVERIFIED unless I reproduced them.

## 1. Verdict

It is not safe to merge the whole stack yet. The code itself is in good shape: every suite I ran passes at both revisions with no failures (911 → 1,186 tests), a failed or 404 features fetch keeps sends on v0, and the released 0.5.0 and 0.5.2 wheels read all seven v0 send kinds I tested; but it is a large breaking release, with 85 compile errors across six languages in a small 0.5.x consumer, plus runtime breaks. Three things must change before merge: the `bindings` Cargo feature hands any Rust caller a working v1 switch (B1); the default v0 send still differs from 0.5.x for messages with files and for edits built from an event, which the compat gate skips (B2); and `AGENTS.md` and `ARCHITECTURE.md` still forbid the HTTP client that all five bindings now ship (B3). Before release, also fix the docs that say to send `xdk_version` (S2), the Node exit delay (S1) and the Python and JVM threads that outlive their chat (S3). Then get reviews (none of the 8 PRs has one), bump the version from 0.5.2, and keep v1 off until the server route exists (it returns 404 today).

## 2. Blocking and should-fix issues, ranked

| # | Severity | Issue | Where (file:line) | PR | One-line fix |
|---|---|---|---|---|---|
| B1 | Blocking | **Public feature-switch API.** The Cargo feature `bindings` exposes `bindings::FeatureSwitches::apply_feature_config`. A downstream crate that enables it turns v1 on, and its sends switch from signature version 7 to 10 (probe A4.3). This contradicts "no public feature-switch API". Rustdoc hides it (`#[doc(hidden)]`), so `cargo public-api` does not list it. | `crates/core/Cargo.toml:68`, `crates/core/src/lib.rs:139-141`, `crates/core/src/bindings.rs:9-35` | #50 | Replace the Cargo feature with a mechanism downstream `Cargo.toml` files cannot enable, for example a `--cfg` that only this repo's binding builds set. |
| B2 | Blocking | **Default v0 is not the 0.5.x send shape.** Flags off, the tip changes three things. A message with files gets a derived id and an `attachment_id` stamped on each attachment (probe A4.2: id `bbc4516e-…` also appears as `attachment_id`). An edit built from its target event carries `MessageEdit.message_id`. `v0_sends_match_0_5_on_the_wire` builds only message, entities, reactions and a field-built edit; it skips the reply case and never builds files. The 0.5.0/0.5.2 wheels read these sends (A4.6), but native clients are UNVERIFIED. | `crates/core/src/core.rs:1850-1864`, `1915-1929`, `2063-2074`; `crates/core/src/pipeline.rs:589-608`; `crates/core/src/core/compat_v05_tests.rs:131-160`; `CHANGELOG.md:12-14` | #47, #40, #50 | In v0, use a random id and omit `attachment_id` and `MessageEdit.message_id`. Add message-with-file, reply and edit-from-event cases to the wire gate. |
| B3 | Blocking (rulebook) | **The repo's rules contradict the code.** `AGENTS.md` says the SDK "does **not** do networking" and "Do not add an HTTP client … to any crate under `crates/`". `ARCHITECTURE.md` puts HTTP in the developer's code with the SDK not involved. All five bindings now make HTTP requests. | `AGENTS.md:11,22`; `docs/ARCHITECTURE.md:37,91`; `crates/wasm/js/index.js:523-690`; `crates/pyo3/python/chat_xdk/__init__.py:71-171`; `go/chatxdk/features.go:1-199` | #50 | Amend AGENTS.md §1 and ARCHITECTURE.md §1 with a narrow carve-out for the anonymous, fail-closed `GET /2/chat/features`. |
| P | Blocking (process) | **Process gaps.** None of the 8 PRs has a review. `license/cla` is pending (bot commits). The version is still 0.5.2, so `xdk_version` reports `"0.5.2"` (probe A4.1). The features route returns 404 (A5.1). | `Cargo.toml:13`; `gh pr view` (A5.2) | all | Review bottom-up, stamp 0.6.0 with `scripts/version.sh set` in the release commit, and don't ramp v1 until the route is live. |
| S1 | Should-fix (high) | **Node scripts exit late.** A script that creates a chat waits for the background fetch before the process exits: 323 ms against api.x.com versus 45 ms at v0.5.2, and 6,039 ms when the endpoint hangs (A4.4). The abort timer and the open socket hold the event loop. `free()` avoids the wait (52 ms), but its doc doesn't say so. | `crates/wasm/js/index.js:598,678-690`; `crates/wasm/js/index.d.ts:1247-1252` | #50 | `unref()` the request timer and socket, or fetch lazily on the first send, and document `free()`. |
| S2 | Should-fix (high) | **The `xdk_version` docs say "Send it" now.** Every binding and API.md tell integrators to send the field. The CHANGELOG says to forward it only "once the X API accepts it", and the examples deliberately don't send it. Per the prior agent, the send route passes unknown body keys to the backend unless the strip is deployed (bc-6a35 [11990], UNVERIFIED). | `crates/core/src/types.rs:1078-1079`; `crates/wasm/js/index.d.ts:70`; `go/chatxdk/types.go:46-47`; `crates/dotnet/dotnet/ChatXdk/Types.cs:119-121`; `crates/jvm/java/chatxdk/src/main/java/com/x/chatxdk/Types.java:131-132`; `crates/pyo3/src/lib.rs:422-423`; `docs/API.md:1852`; `CHANGELOG.md:385-387` | #50 | Reword all of them to "do not send yet; forward it once the X API accepts `xdk_version`". |
| S3 | Should-fix | **Fetch threads outlive their chat.** A dropped Python chat (Python has no close API) or an unclosed JVM chat keeps its daemon thread asleep until the next re-check, up to 300 s. Probe A4.5: 50 dropped Python chats left 50 live threads 5 s later. | `crates/pyo3/python/chat_xdk/__init__.py:101-106,171`; `crates/jvm/java/chatxdk/src/main/java/com/x/chatxdk/FeatureSwitches.java:159`; `Chat.java:113-114` | #50 | Wait on an event set by `weakref.finalize` (Python) or a `Cleaner` action (JVM) instead of sleeping, and add a Python `close()`. |
| S4 | Should-fix | **Messages that share an upload share an id.** The id of a message with files ignores its text, so two different messages that reuse one upload in a conversation get the same `message_id`; this happens in v0 too (probe A4.2). 0.5.x allowed reusing an upload. | `crates/core/src/core.rs:663-690` | #47 | Document "one upload per message" prominently, and use a random id in v0 (see B2). |
| S5 | Should-fix | **CHANGELOG errors and omissions.** 0.5.2 rejects a v1 send with "Signature verification failed … ECDSA mismatch", not the "decryption error" the CHANGELOG describes (A4.6). v0 is called "the 0.5.x format" (see B2). Missing: JVM checked exceptions (S6), the Python `Chat` subclass and its thread, the outbound request (process exit, egress), the Rust `SendPayload` struct-literal break, and the same-name C ABI change (S7). Signed read receipts are promised, but per the prior agent the prod route drops `action_signatures` (UNVERIFIED). | `CHANGELOG.md:12-14,20-23,383-387,394-401` | #50, #47, #49 | Correct those lines and list the omissions under Breaking changes. |
| S6 | Should-fix | **JVM file calls declare `throws Exception`.** The 0.5.x stream calls declared nothing, and `ChatXdkException` is unchecked. This adds a compile break beyond the rename. | `crates/jvm/java/chatxdk/src/main/java/com/x/chatxdk/Chat.java:876,895,913,930`; `Chat.java@v0.5.2:693,712` | #47 | Drop `throws Exception`, or declare `ChatXdkException`. |
| S7 | Should-fix | **Same-name C ABI change.** `chat_xdk_decrypt_event` and `chat_xdk_decrypt_events` keep their names but go from 4 to 2 and from 3 to 2 arguments. A stale header or native library then misbehaves at run time instead of failing to link. | `go/chatxdk/include/chat_xdk.h:268,351` | #47 | Rename them (for example with a `_params` suffix), as was done for the file calls. |
| S8 | Should-fix | **`event_b64` breaks persisted payloads.** `SendPayload.event_b64` has no `#[serde(default)]` (`xdk_version` has one), so a payload that 0.5.x persisted for retries no longer deserializes in Rust. The two new fields also break struct literals (A2). | `crates/core/src/types.rs:1054,1080-1081` | #47 | Add `#[serde(default)]`, and mark `SendPayload` `#[non_exhaustive]` while breaking anyway. |
| S9 | Should-fix | **Python DX regressions.** `Chat`'s runtime signature becomes `(*args, **kwargs)` (A3). `EncryptReplyParams`, `EncryptReactionParams` and `EncryptEditParams` require a positional `None` for the optional `reply_to_event`/`target_event`, contrary to the CHANGELOG's "the optional ones as keywords" (A4.1). | `crates/pyo3/python/chat_xdk/__init__.py:84-90`; `crates/pyo3/src/lib.rs:589,701,778`; `CHANGELOG.md:342-344` | #50, #47 | Give `Chat.__init__` an explicit `config_json=None`, and make those fields keyword-only with default `None`. |
| S10 | Should-fix | **Rust callers never send v1.** The core never fetches, so `ChatCore` and `Chat` always send v0 unless the B1 feature is used, and the docs don't say so. | `crates/core/src/features.rs:3-4`; `crates/core/src/bindings.rs:3-7` | #50 | State it in API.md's Rust section, or fetch in `Chat`. |
| S11 | Should-fix | **Body caps and timeouts are uneven.** JS and the JVM read the whole body before comparing it with 64 KiB. Python's 2 s timeout applies per socket operation, not in total, and doesn't cover DNS. | `crates/wasm/js/index.js:685-686`; `FeatureSwitches.java:187-190`; `crates/pyo3/python/chat_xdk/__init__.py:117-120` | #50 | Read with a byte limit, as Go (`features.go:194`) and .NET (`FeatureSwitches.cs:167-174`) do, and use a total deadline in Python. |
| S12 | Should-fix | **Fetches aren't shared, and failures retry forever.** Every chat fetches on creation (retrying once), again when keys load, and every 300 s after. Once keys are loaded, an unreachable endpoint is retried at least every 60 s for the chat's lifetime. Only the CHANGELOG mentions the outbound call. | `crates/wasm/js/index.js:596-636` (same in each binding); `CHANGELOG.md:383-384` | #50 | Share one fetcher per process and bucket, cap retries, and document the request (endpoint, and that failure means v0) in the README. |
| S13 | Nit | **`{}` means "use the cache".** `decryptEvent` requires `conversationKeys`, but an empty map means "fall back to the key cache". | `crates/wasm/js/index.d.ts:539-545` | #47 | Make the field optional again. |
| S14 | Nit (pre-existing) | **`Chat` exists only in the typings.** The JS typings export `Chat` and `ChatCrypto`, but the module doesn't export `Chat` at run time: `import { Chat }` typechecks and is `undefined` (A4.7). | `crates/wasm/js/index.d.ts:924,1132`; `crates/wasm/js/index.js:814-822` | (v0.5.2) | Stop exporting the internal declarations (for example `export {}`). |
| S15 | Scope | **Off-stack PRs conflict with the tip.** #34 (15 conflicted files), #35 (44), #36 (44), #37 (47) and #22 (20) don't merge onto the tip; #19 merges cleanly (A5.3). #37's "attachments the SDK sends carry no `attachment_id`" is false at the tip (B2). | `git merge-tree` (A5.3) | #34–#37, #22 | Decide whether they are in 0.6.0. If so, rebase them onto the tip with params classes and v0/v1 send. |
| S16 | Nit | **Misleading error prefix.** Input validation errors read `Invalid state: Invalid sender_id 'user-1': …` (A4.1). | `crates/core/src/pipeline.rs:309-336` | #47 | Use an input-error variant instead of `SdkError::InvalidState`. |
| S17 | Nit | **New public Rust items aren't in the CHANGELOG:** `signatures::MESSAGE_SIGNATURE_VERSION` and `signatures::build_mark_conversation_read_signature`. | `crates/core/src/signatures.rs:20,290` | #47, #49 | List them, or make them `pub(crate)`. |
| S18 | UNVERIFIED | **Browser CORS.** Per the prior agent, a CORS preflight to `/2/chat/features` gets 405. The SDK sends a simple request, but whether the response carries `Access-Control-Allow-Origin` is unknown, so browser apps may stay on v0 and log CORS errors on every retry. | `crates/wasm/js/index.js:679-683`; prior agent bc-6a35 [14769] | #50 | Confirm the header on the route before ramping v1 for web clients. |

## 3. API change table

"All" means Rust, JS, Python, Go, .NET and JVM, each with its own casing. "Breaking" means a 0.5.2 caller either fails to compile or behaves differently.

**Client construction and config**

| Symbol | Before (0.5.2) | After (tip) | Kind | Breaking |
|---|---|---|---|---|
| `createChat` / `Chat()` / `New()` / `new Chat()` | constructs the chat; no network | also starts a background `GET https://api.x.com/2/chat/features` (`index.js:341`, `__init__.py:84-90`, `chat.go:79`, `Chat.cs:94`, `Chat.java:106`) | behavior | no |
| Python `Chat` | native class, `Chat(config_json=None)` | Python subclass, runtime signature `(*args, **kwargs)`; adds `_feature_bucket`, `_apply_feature_config`, `_is_enabled`, `_feature_refetch_due` (`pyo3/src/lib.rs:1489-1519`) | behavior | no |
| `free()` (JS), `Close()` (Go), `Dispose()` (.NET), `close()` (JVM) | release the handle | also stop the fetch worker (`index.js:517`, `chat.go:93-95`, `Chat.cs:119-120`, `Chat.java:114`) | behavior | no |
| Rust Cargo features | `juicebox`, `js`, `internals` | adds `bindings`, which enables the doc-hidden `bindings::{FeatureSwitches, FeatureApply, FEATURES_ENDPOINT, V1_SEND}` (B1) | added | no |
| `CHAT_XDK_FEATURES_ENDPOINT` env var | — | overrides the endpoint in every binding; an undocumented test hook (`index.js:547`, `__init__.py:76`, `features.go:21`, `FeatureSwitches.cs:16`, `FeatureSwitches.java:21`) | added | no |

**Keys and crypto**

| Symbol | Before | After | Kind | Breaking |
|---|---|---|---|---|
| `generateKeypairs()` → `PublicKeyRegistrationPayload` | `{publicKey, version, generateVersion}`; stores a local timestamp as the signing version (`core.rs@v0.5.2:126-128`) | `{publicKey}`; stores no signing version (`types.rs:1218-1222`, `core.rs:134`) | removed fields + behavior | **yes** |
| Rust `ChatCore::generate_keypairs_with_version(&str)` | present (`core.rs@v0.5.2:133`) | removed | removed | **yes** |
| signing before `setIdentity` | signed with the timestamp version | fails: `signing_key_version is not set…` (`core.rs:273-278`) | behavior | **yes** (runtime) |
| `senderId` on every send | any comma-free string | must be a canonical positive decimal (`pipeline.rs:309-326`) | behavior | **yes** (runtime) |
| `conversationKeyVersion` on every send | any comma-free string | must be a canonical integer (`pipeline.rs:328-336`) | behavior | **yes** (runtime) |
| signature verification | up to version 7 | versions 2–11, each in its own payload layout (`signatures.rs:30`, `core.rs:3116`) | behavior (added) | no |
| Rust `signatures::{MESSAGE_SIGNATURE_VERSION, build_mark_conversation_read_signature}` | — | added (`signatures.rs:20,290`) | added | no |
| Rust `crypto::encryption::{encrypt_stream, decrypt_stream, encrypted_stream_size, StreamEncryptor, StreamDecryptor}` | present | renamed to `{encrypt_file, decrypt_file, encrypted_file_size, FileEncryptor, FileDecryptor}` | renamed | **yes** |
| `encryptedStreamSize(n)` (all) | present | renamed to `encryptedFileSize(n)` | renamed | **yes** |

**Send**

| Symbol | Before | After | Kind | Breaking |
|---|---|---|---|---|
| `encryptMessage`, `encryptReply` (Rust, JS, Go, .NET, JVM) | params object | same signature | — | no (compile) |
| order of a message and its files | encrypt the file, upload it, then reference its `media_hash_key` | start the upload, reference its `media_hash_key`, call `encryptMessage`, then encrypt the file from `payload.eventB64` | behavior | **yes** |
| message id | random UUID | derived from the key, key version, sender, conversation and media hash keys when the message has files; random otherwise (`core.rs:663-690`) | behavior | **yes** (S4) |
| outgoing attachments | sent as given | `attachment_id` stamped on each (the message id, then `<id>#<n>`), in v0 too (`core.rs:1864`, `pipeline.rs:589-608`) | behavior (wire) | the 0.5.0/0.5.2 wheels read it (A4.6) |
| media hash keys | not checked | an empty key, or one key in two attachments, is rejected (`pipeline.rs:635`) | behavior | **yes** (runtime) |
| send format | conversation key, signature version 7 | v0 (the default) as before; v1 while `v1_send` is on: message key, `contents_encryption_version` 1, signature version 10 (`pipeline.rs:212-230`, `core.rs:518-524`) | behavior | no by default |
| `encryptEdit` built from a target event | no message id in the edit | carries the edited message's id (`MessageEdit.message_id`, `core.rs:2063-2074`) | behavior (wire) | the 0.5.0/0.5.2 wheels read it (A4.6) |
| Python `encrypt_message`, `encrypt_reply`, `encrypt_add_reaction`, `encrypt_remove_reaction`, `encrypt_edit` | positional arguments + keywords | one params class each | signature | **yes** |
| `SendPayload` | 7 fields | adds `eventB64` (`types.rs:1054`) and `xdkVersion` (`types.rs:1080-1081`) | added | Rust struct literals only |
| `encryptStream(file, key)`, `streamEncryptor(key)` (all) | present | removed; replaced by `encryptFile({file, eventB64, conversationKeys, mediaHashKey})` and `fileEncryptor({eventB64, conversationKeys, mediaHashKey})` (`core.rs:2830,2845`) | removed + replacement | **yes** |
| `prepareMarkConversationRead(MarkConversationReadParams)` → `ActionSignature` | — | added (`core.rs:2168`) | added | no |

**Receive and decrypt**

| Symbol | Before | After | Kind | Breaking |
|---|---|---|---|---|
| `decryptEvents` | `(events, signingKeys?)` | `({events, signingKeys?})` (`core.rs:1392`) | signature | **yes** |
| `decryptEvent` | `(eventB64, conversationKeys?, signingKeys?)` | `({eventB64, conversationKeys, signingKeys?})`; keys are now required, and `{}` means the cache (`core.rs:1505`) | signature | **yes** |
| .NET/JVM `DecryptEvent(eventB64, ConversationKeyBundle, …)` | present | removed; pass `bundle.Keys` | removed | **yes** |
| `decryptStream(bytes, key)`, `streamDecryptor(key)` | conversation key only | `decryptFile({encrypted, eventB64, conversationKeys, mediaHashKey})` and `fileDecryptor({…})` (`core.rs:2869,2886`) | removed + replacement | **yes** |
| messages with `contents_encryption_version` ≥ 1, their previews, edits and files | not decryptable | decrypted (`message_keys.rs:23,31`, `core.rs:2319-2340`) | behavior (added) | no |

**Conversations and listing**

The SDK has no listing or HTTP API in either version (`AGENTS.md:10-25`).

| Symbol | Before | After | Kind | Breaking |
|---|---|---|---|---|
| `prepareConversationKeyChange`, `prepareGroupCreate`, `prepareGroupMembersChange`, `prepareMessageDelete` (Rust, JS, Go, .NET, JVM) | params object | unchanged | — | no |
| Python `prepare_conversation_key_change`, `prepare_group_create`, `prepare_group_members_change`, `prepare_message_delete` | positional arguments + keywords | params classes | signature | **yes** |
| `extractConversationKeys(events)`, `decryptConversationKey(b64)` | positional | unchanged | — | no |

**Errors**

| Symbol | Before | After | Kind | Breaking |
|---|---|---|---|---|
| error type per binding | `ValueError` / `Error` / `error` / `ChatXdkException` | unchanged | — | no |
| JVM `encryptFile`, `decryptFile`, `fileEncryptor`, `fileDecryptor` | the stream calls declared no checked exception (`Chat.java@v0.5.2:693,712`) | `throws Exception` (`Chat.java:876-930`) | signature | **yes** (JVM) |
| new runtime errors | — | `signing_key_version is not set…`, `Invalid sender_id '…'`, `Invalid conversation_key_version '…'`, `media_hash_key '…' is in more than one attachment…`, and the file-call errors | behavior | **yes** (runtime) |
| feature fetch failures | — | swallowed; flags stay off (`index.js:686-690`, `__init__.py:124`, `features.go:180-198`, `FeatureSwitches.cs:176-179`, `FeatureSwitches.java:194-198`) | added | no |

**Exported types and ABI**

| Symbol | Before | After | Kind | Breaking |
|---|---|---|---|---|
| `StreamEncryptor`, `StreamDecryptor` (all) | present | renamed to `FileEncryptor`, `FileDecryptor` | renamed | **yes** |
| params types (all bindings) | — | `DecryptEventParams`, `DecryptEventsParams`, `EncryptFileParams`, `FileEncryptorParams`, `DecryptFileParams`, `FileDecryptorParams`, `MarkConversationReadParams` | added | no |
| Python params classes | — | `EncryptMessageParams`, `EncryptReplyParams`, `EncryptReactionParams`, `EncryptEditParams`, `ConversationKeyChangeParams`, `GroupCreateParams`, `GroupMembersChangeParams`, `MessageDeleteParams` | added | part of the Python break |
| C ABI (`chat_xdk.h`) | stream functions; multi-argument `decrypt_event(s)` | 11 names removed and 12 added; `chat_xdk_decrypt_event(s)` keep their names but take a params JSON (`chat_xdk.h:268,351`); `chat_xdk_internal_*` are exported but not declared in the header (A4.8) | renamed + signature | **yes** |
| JVM `ChatNative` (a public JNA interface since 0.5.x) | 0.5.x natives | methods renamed and with different arity (A3) | signature | **yes** |

## 4. Consistency matrix

Rows are the X API endpoint each group of SDK calls serves. ✓ means consistent and ✗ means inconsistent.

| Endpoint ← SDK calls | Naming | Parameter shape | Return shape | Pagination | Error type | Sync/async | Id/time types |
|---|---|---|---|---|---|---|---|
| `POST /2/users/:id/public_keys` ← `generateKeypairs`, `setIdentity`, `importKeys` | ✓ casing only | ✗ `setIdentity(userId, version)` and `importKeys(keys, version?)` stay positional with two inputs, while the params rule exempts only one-input calls (`AGENTS.md:60-64`) | ✓ `PublicKeyRegistrationPayload {publicKey}` in all six | n/a | ✓ per binding | ✓ sync | ✗ the signing `public_key_version` may be any string (`core.rs:269-279`), but `conversation_key_version` must be an integer (`pipeline.rs:328-336`) |
| `POST /2/chat/conversations/:id/messages` ← `encryptMessage`, `encryptReply` | ✓ | ✓ one params object in all six (Python since #47) | ✗ `SendPayload` names differ from the request body (`encryptedContent` vs `encoded_message_create_event`, `examples/python/x_api.py:250`); `eventB64` must not be sent | n/a | ✓ | ✓ sync | ✗ `senderId` is a digits-only string (`pipeline.rs:309-326`) but `replyToSenderId` is an integer (`params.rs:201`; JS `string \| number`, `index.d.ts:332`) |
| same endpoint ← `encryptAddReaction`, `encryptRemoveReaction`, `encryptEdit` | ✓ | ✗ Rust takes `&params` here but message/reply take params by value (`core.rs:1966,2044` vs `1830,1898`); Python's `target_event` is optional yet positional (`pyo3/src/lib.rs:701,778`) | ✓ `SendPayload` | n/a | ✓ | ✓ | ✓ sequence ids are strings |
| delete and mark-read actions ← `prepareMessageDelete`, `prepareMarkConversationRead` | ✓ `prepare*` | ✓ params object (Rust `&params` for both) | ✓ `ActionSignature` | n/a | ✓ errors name the empty field (`core.rs:2101-2115,2172-2181`) | ✓ | ✓ `seenAtMsec` and `ttlMsec` are int64 ms (JS `number`) |
| key change and groups ← `prepareConversationKeyChange`, `prepareGroupCreate`, `prepareGroupMembersChange` | ✓ | ✓ params object (Python since #47) | ✓ `PreparedConversationChange` | n/a | ✓ | ✓ | ✓ |
| media upload ← `encryptedFileSize`, `encryptFile`, `fileEncryptor` | ✓ `File*` everywhere | ✗ takes a key map, `conversationKeys`, while the message it belongs to took one `conversationKey` plus `conversationKeyVersion` | ✓ bytes / `FileEncryptor` | n/a | ✗ the JVM declares `throws Exception` (`Chat.java:876,913`) | ✓ | ✓ sizes are u64 (JS `number`) |
| conversation events ← `decryptEvents`, `decryptEvent`, `extractConversationKeys` | ✓ | ✗ `decryptEvent` requires `conversationKeys`, but `{}` means "use the cache" (`index.d.ts:539-545`) | ✗ typed `Event` in Rust, JS and Go vs `JsonElement`, `JsonNode` and `dict` (a documented exception, `AGENTS.md` §4) | ✓ by design: the caller pages; `decryptEvents` takes one page; no cursor | ✓ the batch call never throws and the single call throws (unchanged) | ✓ | ✓ |
| media download ← `decryptFile`, `fileDecryptor` | ✓ | ✓ the same values as `decryptEvent`, plus `mediaHashKey` | ✓ | n/a | ✗ the JVM declares `throws Exception` (`Chat.java:895,930`) | ✓ | ✓ |
| `GET /2/chat/features` (internal, every binding) | ✓ same URL and `?bucket=` everywhere (`index.js:665`, `features.go:169`, `FeatureSwitches.cs:147`, `FeatureSwitches.java:173`, `__init__.py:115`) | ✓ no auth; `Accept: application/json` | ✓ parsed once in the core (`features.rs:101-114`) | n/a | ✓ every failure is swallowed, so sends stay v0 | ✗ the worker's lifetime and timeouts differ per binding (S1, S3, S11) | ✓ bucket is a u16 in 0–9999 everywhere (`features.rs:120-127`) |

## 5. DX findings

**Migration effort**
- A 0.5.x consumer that covers setup, keys, decrypt, send and media hits 12 compile errors in TypeScript, 19 in Python, 12 in Go, 13 in Rust, 14 in C# and 15 in Java (A2).
  - Half of the 85 (43) come from the media API, 21 from the decrypt params objects, 13 from key registration, 7 from Python's params classes, and 1 from the Rust struct literal.
- Most fixes are mechanical. The exception is media, which needs restructuring: the app has to start the upload before encrypting, declare `encryptedFileSize(n)` up front, and keep the message's `eventB64` until each file is encrypted (`CHANGELOG.md:70-91`).
- There are also runtime-only steps: call `setIdentity` with the registered version, pass numeric sender ids and integer key versions, and use one upload per attachment and per message (A4.1, A4.2).

**Footguns**
- Node scripts wait up to ~6 s to exit unless they call `free()` (S1).
- The `xdk_version` docs say "send it" (S2).
- Reusing an upload gives two messages the same id (S4). Changing the text before resending also keeps the id. That makes retries safe, but it also means different messages that share files aren't told apart.
- Fetch threads outlive their chat in Python and the JVM (S3).
- One message flow needs the key in two shapes: one key plus a version to send, and a key map to encrypt its files (§4).
- In `decryptEvent`, `{}` means "use the cache" (S13). In Python, `None` must be passed positionally for an optional event (S9).
- Re-checks only ever turn flags off, so a long-running process picks up a v1 ramp-up only in a new chat, while a rollback reaches it within 300 s (`features.rs:78-82`).
- The fetch is silent: there is no log or metric hook. Only `signatureInfo.signatureVersion` ("7" or "10") shows which format a send used.
- Every chat contacts api.x.com. Once keys are loaded, an unreachable endpoint is retried at least every 60 s (S12).
- Rust callers always send v0 unless they enable `bindings` (S10, B1).

**Defaults**
- v0 is the default, and every flag reads off until a response applies (`features.rs:89-95`).
- An answer bucketed by IP is ignored once keys load, until the keyed re-fetch lands (`features.rs:85-91`).
- Timings: 2 s timeout, 64 KiB body cap, 300 s re-check, and 1–60 s backoff for the keyed retry (`index.js:528-552`).
- `reject_unverified` still defaults to on.

**Naming**
- The Stream → File rename is applied in every binding.
- `prepareMarkConversationRead` follows `prepareMessageDelete`.
- The params types have the same names everywhere (A3).
- Nit: `CURRENT_SIGNATURE_VERSION = 7` sits next to `MESSAGE_SIGNATURE_VERSION = 10` (`signatures.rs:12-20`), which reads as if 7 were current for messages.

**Error messages**
- Good: they name the value and say what to pass (`pipeline.rs:309-336`, `core.rs:273-278`).
- Nit: they carry an `Invalid state:` prefix (S16).
- Ops: a 0.5.x reader reports a v1 send as a signature failure (A4.6), so alerts will look like forgery.

**Drift between docs and code**
- B3: AGENTS.md and ARCHITECTURE.md.
- S2: the `xdk_version` docs.
- S5: the CHANGELOG.
- The `free()` doc (`index.d.ts:1247-1252`) doesn't mention that it stops the fetch.
- README and API.md never mention the outbound request; only `CHANGELOG.md:383-384` does.
- #50's body says "v0 matches 0.5.x on the wire"; the gate doesn't cover files, replies or edits built from an event (B2).
- #37's body is stale (S15).
- No 0.5.x calls remain in README, `docs/`, the binding READMEs or `examples/` (grep for `encryptStream`, `decryptStream`, `generateVersion` and positional `decryptEvent` finds none).

## 6. Before/after snippets

TypeScript covers every main path, and Python shows the binding with the largest change. Each "before" file typechecks against `v0.5.2` and each "after" file against the tip with 0 errors. Cross-checked against the other revision, they fail with 5–11 errors (A2.3). They were typechecked, not executed.

### TypeScript, 0.5.2 (before)

```ts
import { createChat, encryptedStreamSize, type SigningKeyEntry } from "@xdevplatform/chat-xdk";

// Your own X API calls.
declare function registerPublicKey(userId: string, body: object): Promise<{ public_key_version: string }>;
declare function uploadMedia(encrypted: Uint8Array): Promise<string>; // returns the media_hash_key
declare function postMessage(conversationId: string, body: Record<string, string>): Promise<void>;

export async function v052(events: string[], signingKeys: SigningKeyEntry[], photo: Uint8Array, downloaded: Uint8Array) {
  // Setup / init
  const chat = await createChat({ getAuthToken: async () => "realm-token" });

  // Key management (first boot)
  const registration = chat.generateKeypairs(); // { publicKey, version, generateVersion }
  const { public_key_version } = await registerPublicKey("1001", registration);
  chat.setIdentity("1001", public_key_version);

  // Receive / decrypt
  const batch = chat.decryptEvents(events, signingKeys);
  const keys = batch.conversationKeys.keys;
  const version = batch.conversationKeys.latestVersion!;
  const event = chat.decryptEvent(events[0], keys, signingKeys);

  // Send a message with a photo: encrypt and upload the file first
  const encrypted = chat.encryptStream(photo, keys[version]);
  const mediaHashKey = await uploadMedia(encrypted);
  const payload = chat.encryptMessage({
    conversationId: "1001:2002", text: "a photo", conversationKey: keys[version], conversationKeyVersion: version,
    attachments: [{ attachment_type: "media", media_hash_key: mediaHashKey, width: 640, height: 480,
                    filesize_bytes: encryptedStreamSize(photo.length), filename: "a.jpg", media_type: 1 }],
  });
  await postMessage("1001-2002", { message_id: payload.messageId,
    encoded_message_create_event: payload.encryptedContent,
    encoded_message_event_signature: payload.encodedEventSignature });

  // Receive a file
  const plaintext = chat.decryptStream(downloaded, keys[version]);
  return { event, plaintext };
}
```

### TypeScript, 0.6.0 tip (after)

```ts
import { createChat, encryptedFileSize, type SigningKeyEntry } from "@xdevplatform/chat-xdk";

// Your own X API calls.
declare function registerPublicKey(userId: string, body: object): Promise<{ public_key_version: string }>;
declare function startUpload(totalBytes: number): Promise<{ session: string; mediaHashKey: string }>;
declare function finishUpload(session: string, encrypted: Uint8Array): Promise<void>;
declare function postMessage(conversationId: string, body: Record<string, string>): Promise<void>;

export async function v060(events: string[], signingKeys: SigningKeyEntry[], photo: Uint8Array, downloaded: Uint8Array) {
  // Setup / init (also starts the background GET /2/chat/features)
  const chat = await createChat({ getAuthToken: async () => "realm-token" });

  // Key management (first boot): the payload carries only publicKey
  const registration = chat.generateKeypairs();
  const { public_key_version } = await registerPublicKey("1001", registration);
  chat.setIdentity("1001", public_key_version); // required: nothing signs without it

  // Receive / decrypt: one params object per call
  const batch = chat.decryptEvents({ events, signingKeys });
  const keys = batch.conversationKeys.keys;
  const version = batch.conversationKeys.latestVersion!;
  const event = chat.decryptEvent({ eventB64: events[0], conversationKeys: keys, signingKeys });

  // Send a message with a photo: start the upload, build the message, then encrypt the file
  const size = encryptedFileSize(photo.length);
  const { session, mediaHashKey } = await startUpload(size);
  const payload = chat.encryptMessage({
    conversationId: "1001:2002", text: "a photo", conversationKey: keys[version], conversationKeyVersion: version,
    attachments: [{ attachment_type: "media", media_hash_key: mediaHashKey, width: 640, height: 480,
                    filesize_bytes: size, filename: "a.jpg", media_type: 1 }],
  });
  const encrypted = chat.encryptFile({ file: photo, eventB64: payload.eventB64, conversationKeys: keys, mediaHashKey });
  await finishUpload(session, encrypted);
  await postMessage("1001-2002", { message_id: payload.messageId,
    encoded_message_create_event: payload.encryptedContent,
    encoded_message_event_signature: payload.encodedEventSignature }); // not eventB64; xdkVersion only once the API accepts it

  // Receive a file: pass the event that carries it
  const plaintext = chat.decryptFile({ encrypted: downloaded, eventB64: events[0], conversationKeys: keys, mediaHashKey });

  chat.free(); // also stops the feature fetch, so a short Node script exits promptly
  return { event, plaintext };
}
```

### Python, 0.5.2 (before) and 0.6.0 tip (after)

```python
# before (typechecks against v0.5.2)
from chat_xdk import Chat


def register_public_key(user_id: str, payload: object) -> str: ...  # your X API call


def v052(events: list[str], signing_keys: list[dict[str, str]], photo: bytes) -> None:
    chat = Chat()
    registration = chat.generate_keypairs()  # .public_key, .version, .generate_version
    chat.set_identity("1001", register_public_key("1001", registration))

    batch = chat.decrypt_events(events, signing_keys)
    keys: dict[str, bytes] = batch["conversation_keys"]["keys"]
    version: str = batch["conversation_keys"]["latest_version"]
    event = chat.decrypt_event(events[0], keys, signing_keys)

    payload = chat.encrypt_message("1001:2002", "hi", conversation_key=keys[version],
                                   conversation_key_version=version, ttl_msec=60_000)
    reply = chat.encrypt_reply("1001:2002", "pong", events[0])
    reaction = chat.encrypt_add_reaction(events[0], "+1")
    deletion = chat.prepare_message_delete("1001:2002", ["7"], False)
    encrypted = chat.encrypt_stream(photo, keys[version])
    print(event, payload.message_id, reply, reaction, deletion, encrypted)
```

```python
# after (typechecks against the tip)
from chat_xdk import (
    Chat,
    DecryptEventParams,
    DecryptEventsParams,
    EncryptFileParams,
    EncryptMessageParams,
    EncryptReactionParams,
    EncryptReplyParams,
    MessageDeleteParams,
)


def register_public_key(user_id: str, payload: object) -> str: ...  # your X API call


def v060(events: list[str], signing_keys: list[dict[str, str]], photo: bytes, media_hash_key: str) -> None:
    chat = Chat()  # also starts a daemon thread that fetches GET /2/chat/features
    registration = chat.generate_keypairs()  # .public_key only
    chat.set_identity("1001", register_public_key("1001", registration))  # required before signing

    batch = chat.decrypt_events(DecryptEventsParams(events, signing_keys=signing_keys))
    keys: dict[str, bytes] = batch["conversation_keys"]["keys"]
    version: str = batch["conversation_keys"]["latest_version"]
    event = chat.decrypt_event(DecryptEventParams(events[0], keys, signing_keys=signing_keys))

    payload = chat.encrypt_message(EncryptMessageParams(
        "1001:2002", "hi", conversation_key=keys[version], conversation_key_version=version, ttl_msec=60_000))
    reply = chat.encrypt_reply(EncryptReplyParams("1001:2002", "pong", events[0]))
    reaction = chat.encrypt_add_reaction(EncryptReactionParams(events[0], "+1"))
    deletion = chat.prepare_message_delete(MessageDeleteParams("1001:2002", ["7"], False))
    # A file belongs to a message that lists its media_hash_key; encrypt it from that message's event_b64.
    encrypted = chat.encrypt_file(EncryptFileParams(photo, payload.event_b64, keys, media_hash_key))
    print(event, payload.message_id, reply, reaction, deletion, encrypted)
```

### Call order: developer-facing calls first, then the key internal sequence

- **Setup and init**
  - Before: `createChat` → `new ChatWithJuicebox`. No network until a Juicebox call.
  - After: `createChat` (`index.js:729`) → `new ChatWithJuicebox` → `startFeatureSwitches` (`index.js:341,561`) → `GET /2/chat/features` with no bucket, retried once (`index.js:598`) → check for keys every 1 s → once keys load, `GET …?bucket=<0–9999>` (the first 8 bytes of SHA-256 of the identity SPKI, top bit cleared, mod 10000; `features.rs:120-127`) → full apply (`features.rs:70-77`) → a re-check every 300 s that can only turn flags off (`features.rs:78-82`).
- **Key management**
  - Before: `generateKeypairs` → `generate_keypairs_with_version(now_millis())` (`core.rs@v0.5.2:126-128`) → payload `{public_key, version, generate_version}`, with the timestamp stored as the signing version.
  - After: `generateKeypairs` (`core.rs:134`) → keypairs with no signing version → the app POSTs `{public_key}` → the app reads `public_key_version` from the response (server side UNVERIFIED, A6) → `setIdentity` (`core.rs:210`). Every signer resolves the version from there or fails (`core.rs:269-279`).
- **Send**
  - Before: `encryptStream` (secretstream under the conversation key) → upload → `encryptMessage` (random UUID) → XSalsa20-Poly1305 under the conversation key → ECDSA signature, version 7 → POST.
  - After: `encryptMessage` (`core.rs:1830`) → resolve the sender, signing version and conversation key → validate the attachments and media hash keys (`core.rs:1850-1853`) → `outgoing_message_id` (`core.rs:668-690`) → `build_message_attachments` (`pipeline.rs:593`) → `encrypt_and_sign`, using `send_version()` (`core.rs:518-524`) → validate the sender id and key version (`pipeline.rs:209-210`).
    - v0: the conversation key, signature version 7.
    - v1: an HKDF message key, `contents_encryption_version` 1, signature version 10 (`pipeline.rs:212-230`).
    - Then ECDSA → `SendPayload` with `eventB64` and `xdkVersion` → `encryptFile` (`core.rs:2830`; finds the attachment by media hash key; v0 uses the conversation key, v1 a per-attachment key) → finish the upload → POST three fields.
- **Receive and decrypt**
  - Before: `decryptEvents(events, signingKeys?)`, `decryptEvent(b64, conversationKeys?, signingKeys?)` and `decryptStream(bytes, conversationKey)`.
  - After: `decryptEvents` (`core.rs:1392`) → bounded Thrift parse → unwrap conversation keys from key changes → verify each signature in the layout of its own version (≤ 11, `core.rs:3116`) against the caller's signing keys → pick the key by `conversation_key_version` → a message key if `contents_encryption_version` ≥ 1 (`message_keys.rs:23`, `core.rs:2319-2340`) → decrypt.
  - Files: `decryptFile` (`core.rs:2869`) → find the attachment in the event by media hash key → derive its key → secretstream decrypt.

## 7. Suggested migration note for users

- **Upgrade readers first.** 0.6.0 sends v0 by default, and switches to per-message keys (v1) only while the X API turns `v1_send` on. 0.5.x rejects v1 sends, so upgrade every reader before v1 is turned on.
- **Register keys, then set the identity.** POST the `generateKeypairs()` payload as returned (it no longer has `version`). Then call `setIdentity(userId, public_key_version)` with the version the API returns, or `importKeys(keys, version)` for saved keys. Signing fails without it.
- **Pass canonical ids.** Use the sender's numeric user id, and the conversation key version as the integer its key-change event carries.
- **Decrypt calls take one params object.** Use `decryptEvents({ events, signingKeys })` and `decryptEvent({ eventB64, conversationKeys, signingKeys })`; pass `{}` to use the key cache. On .NET and the JVM, pass `bundle.Keys`.
- **Media.** Start the upload first, declaring `encryptedFileSize(n)` as its size. List its `media_hash_key` in the message, call `encryptMessage`, then `encryptFile({ file, eventB64: payload.eventB64, conversationKeys, mediaHashKey })`, and finish the upload. Use one upload per attachment and per message. Decrypt with `decryptFile({ encrypted, eventB64, conversationKeys, mediaHashKey })`.
- **Renames.** `StreamEncryptor`/`StreamDecryptor` → `FileEncryptor`/`FileDecryptor`, and `encryptedStreamSize` → `encryptedFileSize`. In Rust, `crypto::encryption::*_stream` → `*_file`.
- **Python.** Wrap arguments in params classes: `EncryptMessageParams(...)`, `EncryptReplyParams(conversation_id, text, reply_to_event)`, `EncryptReactionParams(target_event, emoji)`, `MessageDeleteParams(...)`, and so on.
- **Request body.** Don't put `eventB64` in the send request, and don't send `xdkVersion` until the X API documents it.
- **Background request.** Every chat now makes a request to `https://api.x.com/2/chat/features`. If it fails, sends stay v0. In Node, call `chat.free()` when you're done so scripts exit promptly; `Close()`, `Dispose()` and `close()` stop it in Go, .NET and the JVM.
- **JVM.** The file calls declare `throws Exception`.

---

## Appendix A: evidence

### A1. Build and test results

Runs were on Linux x86_64 with Rust 1.91.1, Node 22, Python 3.12, Go 1.22, JDK 17 and .NET 8. Base is `v0.5.2` and tip is `62c347c`. `CHAT_XDK_FEATURES_ENDPOINT` was set to a closed local port, as CI does (`.github/workflows/ci.yml:12`).

| Suite | Base | Tip |
|---|---|---|
| `cargo fmt --check` / `cargo clippy --workspace --all-targets -D warnings` | pass / pass | pass / pass |
| `cargo test --workspace` (core unit + `sdk_vectors` + `signatures_test`) | **566 passed**, 0 failed (549 + 7 + 10), 9 doc-tests ignored | **698 passed**, 0 failed (671 + 17 + 10), 9 ignored |
| Python (`unittest`) | 65 OK | 102 OK |
| JS: `sdk_vectors`, `api`, `wrapper`, `features` (assertion scripts with no counts; `assert` call sites in brackets) | 3/3 pass [50, 142, 110] | 4/4 pass [84, 174, 110, 38] |
| Go (`make test-go`, top-level tests) | 79 pass | 108 pass |
| JVM (`mvn test`) | 63 pass | 94 pass |
| .NET binding (unmodified test sources under a local xunit stand-in; nuget.org is blocked here) | 78 pass | 114 pass |
| Examples: Rust / Python / JS / JVM / .NET / Go | 12 / 12 / 13 / 11 (+1 skipped) / 12 / ok | 14 / 14 / 15 / 13 (+1 skipped) / 14 / ok |
| **Counted total** | **911 passed, 0 failed** | **1,186 passed, 0 failed** |
| compat gate: released 0.5.0 and 0.5.2 wheels read the tip's v0 sends | n/a | 7 send kinds + the file read by both (A4.6) |

Not run here: the macOS job, the Node 18 rerun, and `cargo deny` (`Cargo.lock` is unchanged from base to tip, so the license graph is the same).

### A2. 0.5.x consumer compiled against the tip: the ground truth

One consumer per language exercises the same checklist with 0.5.2 calls: setup, key registration, `setIdentity`, `decryptEvents`, `decryptEvent` (keys, cache and error paths), message, reply, reaction, edit and delete sends, `SendPayload` fields, and the stream API. Each compiles cleanly against `v0.5.2` and fails against the tip as follows.

| Change (row of table 3) | TS | Py | Go | Rust | C# | Java | Total |
|---|---|---|---|---|---|---|---|
| Stream → file API (removed calls and types, size rename) | 7 | 7 | 7 | 6 | 7 | 9 | 43 |
| `decryptEvents`/`decryptEvent` params objects (+ .NET/JVM bundle overload) | 3 | 3 | 3 | 3 | 5 | 4 | 21 |
| Registration payload fields, Rust `generate_keypairs_with_version` | 2 | 2 | 2 | 3 | 2 | 2 | 13 |
| Python params classes for `encrypt_*` and `prepare_*` | – | 7 | – | – | – | – | 7 |
| Rust `SendPayload` struct literal (`event_b64`, `xdk_version`) | – | – | – | 1 | – | – | 1 |
| **Compile errors** | **12** | **19** | **12** | **13** | **14** | **15** | **85** |

**Reconciliation.** Every compile error maps to a breaking row in table 3. The breaking rows that produce no compile error are runtime-only:
- `setIdentity` is now required.
- Sender ids must be numeric, and key versions integers.
- Media hash keys must be unique.
- Files come after the message.
- Ids of messages with files are derived.
- The JVM's checked exceptions stay hidden until a caller adopts the file calls.
- The C ABI arity change affects only raw C callers.

The Python `Chat` subclass, its thread and the outbound request are behavior changes, not breaks (A4).

<details><summary>A2.1 Every compile error, by language</summary>

- **TypeScript** (`tsc --strict`, 12):
  - `4` no export `encryptedStreamSize`; `6` no export `StreamEncryptor`; `7` no export `StreamDecryptor`.
  - `22` no `version` on `PublicKeyRegistrationPayload`; `23` no `generateVersion`.
  - `29` `decryptEvents` expected 1 argument, got 2; `31` `decryptEvent` expected 1, got 3; `32` `string` is not assignable to `DecryptEventParams`.
  - `47` no `encryptStream`; `48` no `decryptStream`; `49` no `streamEncryptor`; `51` no `streamDecryptor`.
- **Python** (pyright, 19):
  - `9-11` unknown imports `StreamDecryptor`, `StreamEncryptor`, `encrypted_stream_size`.
  - `21-22` no `version` or `generate_version`.
  - `26` `prepare_conversation_key_change`: no parameter named `conversation_id`.
  - `29` `decrypt_events`, `31` `decrypt_event`: expected 1 positional argument; `32` `str` is not `DecryptEventParams`.
  - Expected 1 positional argument: `35` `encrypt_message`, `39` `encrypt_reply`, `40` `encrypt_add_reaction`, `41` `encrypt_remove_reaction`, `42` `encrypt_edit`, `43` `prepare_message_delete`.
  - `48-53` no `encrypt_stream`, `decrypt_stream`, `stream_encryptor` or `stream_decryptor`.
- **Go** (`go build -gcflags=-e`, 12):
  - `20` `reg.Version` and `21` `reg.GenerateVersion` undefined.
  - Too many arguments: `29` `DecryptEvents`, `34` `DecryptEvent`, `38` `DecryptEvent(…, nil, nil)`.
  - `55` `EncryptedStreamSize` undefined; `56` `EncryptStream`; `57` `DecryptStream`.
  - `58` and `63`: types `StreamEncryptor` and `StreamDecryptor` undefined. `59` and `64`: methods `StreamEncryptor` and `StreamDecryptor` undefined.
- **Rust** (`cargo check`, 13):
  - E0432 `StreamDecryptor`, `StreamEncryptor`; E0425 `utils::encrypted_stream_size`.
  - E0609 `version`, `generate_version`; E0599 `generate_keypairs_with_version`.
  - E0061 ×3 for `decrypt_events` / `decrypt_event` arity.
  - E0063 missing `event_b64` and `xdk_version` in a `SendPayload` literal.
  - E0599 `encrypt_stream`, `decrypt_stream`, `stream_encryptor`, `stream_decryptor`.
- **C#** (`dotnet build`, 14):
  - CS1061 `Version`, `GenerateVersion`.
  - CS1501 `DecryptEvents` with 2 arguments; `DecryptEvent` with 3 arguments (dictionary, and the bundle overload).
  - CS1503 `DecryptEvent(string)` ×2.
  - CS0117 `EncryptedStreamSize`; CS1061 `EncryptStream`, `DecryptStream`.
  - CS0246 and CS1061 for both the types and the methods `StreamEncryptor`/`StreamDecryptor`.
- **Java** (`javac`, 15):
  - Imports `StreamDecryptor`, `StreamEncryptor`; fields `version`, `generateVersion`.
  - `decryptEvents(List, List)`; `decryptEvent` with (`Map`), (`ConversationKeyBundle`) and (`Map`, `null`).
  - `encryptedStreamSize`, `encryptStream`, `decryptStream`.
  - Types and methods `StreamEncryptor`/`streamEncryptor` and `StreamDecryptor`/`streamDecryptor`.

</details>

**A2.3 Section 6 snippets.** `before_v052.ts` has 0 errors against base and 5 against the tip; `after_v060.ts` has 0 against the tip and 6 against base. `before_v052.py` has 0 against base and 7 against the tip; `after_v060.py` has 0 against the tip and 11 against base. I used TypeScript 5.9.3 (`--strict`) and pyright 1.1.414.

### A3. Mechanical public-surface diffs (`v0.5.2` → tip)

| Binding | Tool | Surface lines | Removed / added lines |
|---|---|---|---|
| Rust `chat-xdk-core` (default features) | `cargo public-api` 0.52 (nightly rustdoc JSON) | 4,422 → 4,577 | 79 / 234 (including auto-trait impls) |
| JS `index.d.ts` | TypeScript compiler API walk of the exports | 362 → 396 | 29 / 63 |
| Python, runtime | `inspect` over `chat_xdk` | 183 → 334 | 30 / 181 |
| Go `go/chatxdk` | `go/ast` exported declarations | 313 → 345 | 17 / 49 |
| .NET `ChatXdk.dll` | reflection over the exported types | 292 → 330 | 18 / 56 |
| JVM `chatxdk` jar | `javap -public` | 374 → 422 | 32 / 80 |
| C ABI `chat_xdk.h` | function declarations | — | 11 names removed, 12 added, 2 same-name signature changes |

**Findings beyond the CHANGELOG**
- Rust: `signatures::MESSAGE_SIGNATURE_VERSION` and `signatures::build_mark_conversation_read_signature` (S17).
- Python: `Chat(*args, **kwargs)` and the four `Chat._feature_*` methods.
- JVM: the `ChatNative` method changes and `throws Exception` on the file calls.
- No feature-switch symbol is in the JS typings, Go, .NET or JVM public surface. .NET `FeatureSwitches` is `internal`, and JVM `FeatureSwitches`/`FeatureNative` are package-private (javap shows them without `public`).
- The wasm methods `__featureBucket`, `__applyFeatureConfig`, `__isEnabled` and `__featureRefetchDue` are `skip_typescript` (`crates/wasm/src/lib.rs:229-259`). The package export map is `"."` only (`crates/wasm/js/package.json`), so they can't be reached through the package entry point.
- The Rust `bindings` module is `#[doc(hidden)]`, so it is absent from the rustdoc dump. A4.3 proves it can be reached.

### A4. Runtime probes, base vs tip

1. **Python behavior probe.**
   - Signing right after `generate_keypairs()`: base signs with the timestamp version `1792560491556`. The tip fails: `Invalid state: signing_key_version is not set: pass it explicitly or call set_identity() first`.
   - `sender_id='user-1'`: base OK; the tip says `Invalid sender_id 'user-1': pass the sender's numeric user id …`.
   - `conversation_key_version='v1'`: base OK; the tip says `Invalid conversation_key_version 'v1' …`.
   - Two image attachments with one `media_hash_key`: base OK; the tip says `media_hash_key 'same' is in more than one attachment …`.
   - A default send has signature version `7` at both revisions. The tip's `xdk_version` is `0.5.2`.
   - The private `chat._apply_feature_config('{"features":{"v1_send":true}}', bucket)` makes the next send signature version `10`.
   - `EncryptReplyParams("1001:2002", "re", reply_to_sequence_id="5")` raises `TypeError: missing 1 required positional argument: 'reply_to_event'`.
   - `Chat()` starts 0 threads at base and 1 at the tip.
2. **v0 wire probe.** Flags off, a message with a media attachment was sent and then decrypted.
   - Base: the message id changes when rebuilt with different text.
   - Tip: the same id `bbc4516e-4b8b-4694-8109-f7561445e6f4` for `"photo"` and `"photo, edited text"`. The decrypted attachment has `"attachment_id": "bbc4516e-…"`, and there is no `contents_encryption_version`.
3. **Rust `bindings` probe.** A downstream crate with `chat-xdk-core = { features = ["bindings"] }` sends with `signature_version 7` by default. After `apply_feature_config(r#"{"features":{"v1_send":true}}"#, FeatureApply::Full, bucket)`, `is_enabled(v1_send)` is true and sends use `signature_version 10`.
4. **Node process exit** (wall time from `createChat` plus `generateKeypairs` to process exit):

   | Endpoint | Base | Tip |
   |---|---|---|
   | real api.x.com (404) | 45 ms | 323 ms |
   | closed local port | 40 ms | 43 ms |
   | local server that accepts and never answers | 42 ms | 6,039 ms |
   | the same, with `chat.free()` before exit | — | 52 ms |

   Python under the hanging endpoint exits in 59 ms (daemon thread).
5. **Python thread lifetime.** With a local server returning `{"features":{"v1_send":false}}`: 50 live chats had 50 feature threads; 5 s after dropping all 50 and running `gc.collect()`, 50 were still alive.
6. **Released readers.**
   - `tests/compat_v05/write_v0_sends.py` was run at the tip. The released `chatxdk==0.5.0` and `chatxdk==0.5.2` (PyPI) then ran `verify_with_v05.py`, and both printed "reads" for `message`, `message_with_entities`, `message_with_file`, `reply`, `reaction_add`, `reaction_remove`, `edit` and the file.
   - A v1 send forced through the private Python hook and read by 0.5.2 gives `Crypto error: Signature verification failed: Message signature verification failed: ECDSA mismatch`.
7. **JS typings.** `import { Chat } from "@xdevplatform/chat-xdk"` typechecks at both revisions. At run time the module's exports are `ChatWithJuicebox`, `createChat`, `encryptedFileSize`, … and `Chat` is `undefined`.
8. **Native symbols.** `nm -D target/release/libchat_xdk_dotnet.so` and `nm go/chatxdk/libs/linux_amd64/libchat_xdk_go.a` both show `T chat_xdk_internal_{apply_feature_config, feature_bucket, feature_refetch_due, is_enabled}`.

### A5. Server, CI and merge checks

1. **Live endpoint.** On 2026-10-21, `curl -H 'Accept: application/json' https://api.x.com/2/chat/features` returned `HTTP/2 404`, with or without `?bucket=1234`, and no CORS headers.
2. **PR CI** (`gh pr view`). All 8 PRs are `MERGEABLE`, and none has a review. #50 has 17 successful and 4 skipped checks, including both `compat with released chatxdk 0.5.x` jobs, with `license/cla` pending. #38, #39, #41, #47, #48 and #49 are `UNSTABLE` only because `license/cla` is pending; #40 is `CLEAN`.
3. **Off-stack merges** (`git merge-tree --write-tree` onto `62c347c`): #34 has 15 conflicted files, #35 44, #36 44, #37 47 and #22 20. #19 has none.

### A6. UNVERIFIED

- **Server contract for `GET /2/chat/features`.** I couldn't read Origin PR 1003067: the `origin` CLI isn't authenticated on this VM, and a web fetch timed out. The prior agent describes an open route that returns a flat boolean map under `"features"`, buckets by public-key hash or client IP, and reads `v1_send` from a decider that is off by default (bc-6a35 [14769]). That matches the SDK parser (`features.rs:101-114`). The query parameter name `bucket` and the status codes are unconfirmed.
- **Send route and `xdk_version`.** The prior agent says the change that strips `xdk_version` has merged (bc-6a35 [14770]); deployment is unconfirmed.
- **Key registration without `version`.** The prior agent says it is deployed to prod, but no real registration has exercised it (bc-a864 [5720], [5817]).
- **Mark-read route.** The prior agent says prod drops `action_signatures` (bc-a864 [5817]).
- **Native clients.** How they handle v0 sends that carry `attachment_id` and `MessageEdit.message_id` is unconfirmed (B2).
- **Duplicate message ids.** The server's behavior on a duplicate `message_id` is unconfirmed (S4).
- **Browser CORS** (S18).
- **Not run here:** macOS, Node 18, `cargo deny` and the Go darwin archives. The .NET results come from a local xunit stand-in, not `dotnet test`.
