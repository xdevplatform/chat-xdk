# AGENTS.md — working in chat-xdk

One Rust core (`chat-xdk-core`) plus thin bindings for **Python, JavaScript/WASM,
Go, .NET, JVM**. Three tenets govern every change: **it is a cryptography
library, not a bot SDK**; **all bindings stay at parity**; **the public API stays
small and uniform**. The rest of this file is the invariants that keep those true.

## 1. Crypto-only boundary

This SDK turns plaintext + keys into encrypted blobs + signatures, and back. It
does **not** do networking (apart from the one fetch below), messaging, or
application logic. Per
[`crates/core/src/lib.rs`](crates/core/src/lib.rs) and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md §1), the SDK does **not** own:

- HTTP / REST calls to `/2/chat/*` — the caller's code
- webhook servers, polling loops, retries
- message persistence, ordering, and replay dedup (the caller dedups on the
  signed `messageId`; `sequence_id`/`created_at` are unsigned backend metadata)
- key persistence
- OAuth / token management

Do not add an HTTP client, a transport, a "bot" helper, or anything that knows
about endpoints to any crate under `crates/`. That code belongs in the caller
(see `examples/`, which are demos — not part of the shipped SDK). If a task seems
to need networking inside the core, it is in the wrong layer.

**The one exception is the feature-switch fetch.** The SDK fetches
`GET /2/chat/features` in the background so it can pick its send format
([`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#feature-switches)).
`crates/core` holds all of its policy (when to fetch, sharing, validation) but
never makes the request: each language binding performs the GET the core
hands it, with its own HTTP stack, and hands back the status and body
unparsed. It is anonymous: no credentials and no query parameters. It is
bounded (2 s per request, 64 KiB per body), runs once when a chat is created,
never blocks or fails an SDK call, and is fail-closed: any failure leaves
every switch off for the chat's lifetime, so its sends stay v0. Don't widen
it: no other endpoint, no auth, no user data, no repeated or periodic fetch,
nothing whose failure can change a call's result, and no fetch policy in a
binding.

## 2. Binding parity

`chat-xdk-core` is the **single source of truth**. Bindings marshal arguments
and delegate; they must **not** reimplement crypto, key handling, or protocol
logic. A change that lands in one binding but not the others is incomplete.

When you add or change SDK behavior:

1. Implement it once in `crates/core` (`ChatCore`, or `Chat` for Juicebox).
2. Surface it in **every** binding with matching behavior and signatures:
   Python `crates/pyo3`, JS/WASM `crates/wasm`, Go `crates/go` → `go/chatxdk`,
   .NET + JVM (both over the `chat_xdk_dotnet` cdylib in `crates/dotnet`,
   `crates/jvm`).
3. Use each language's idiom for naming only: `snake_case` (Rust/Python),
   `camelCase` (JS/Java), `PascalCase` methods (.NET/Go).
4. Update the per-binding tables in [`docs/API.md`](docs/API.md) in lockstep.
5. Extend the parallel per-binding test suites so the new surface is covered
   everywhere (see §6).

## 3. Clean API

Keep the public surface small and uniform. The flow every binding exposes:
key management (`import`/`export`, `setup`/`unlock`), conversation keys
(`prepareConversationKeyChange` / `decryptConversationKey`), `encryptMessage`/reply,
the file calls (`encryptFile` / `fileEncryptor` / `decryptFile` / `fileDecryptor`),
and two decrypt paths whose contracts are **identical across bindings**:

- `decryptEvents({ events, signingKeys })` — batch (initial load / pagination).
  Self-extracts conversation keys from `KeyChange` events, **never throws**
  (per-event errors collected in the result).
- `decryptEvent({ eventB64, conversationKeys, signingKeys })` — single event
  with pre-cached keys. **Throws** on failure.

Each `prepare*`, message `encrypt*`, `decryptEvent(s)` and file method, and
`setIdentity` and `importKeys`, takes one params type, named the same in
every binding (`DecryptEventParams`, `EncryptFileParams`, `SetIdentityParams`,
…), so fields can be added without breaking callers. One-input calls
(`extractConversationKeys`, `encryptedFileSize`) stay positional.

Don't add speculative configurability or one-off helpers.

## 4. Symmetric public API

The public API is **symmetric across bindings** (the same concept has the same
type, shape and names in every language) and **within each binding** (a value
the caller sends and the same value the SDK returns use one type). Asymmetry is
a bug even when every binding "works".

**Rules**

- **One type per concept, named the same everywhere.** A quick reply is
  `QuickReply` / `QuickReplyRequest` / `QuickReplyResponse` /
  `QuickReplyOptionsRequest` / `QuickReplyOptionsResponse` / `QuickReplyOption`
  in Rust, JS, Python, Go, .NET and JVM. Only the casing follows the language
  (§2); the structure and the type names do not change.
- **Input and output share the type.** When a binding types its decrypt output,
  the output field uses the same type as the input (Go `TextContent.QuickReply`
  and `EncryptMessageParams.QuickReply` are both `*QuickReply`; JS
  `MessageContent.quickReply` and `EncryptMessageParams.quickReply` are both
  `QuickReply`). Where a binding returns decrypt output as JSON (.NET
  `JsonElement`, JVM `JsonNode`, Python `dict`), the input type must
  deserialize from that JSON unchanged, and a test must prove it by sending a
  decrypted value back.
- **Nested inputs are typed when their siblings are.** If entities and
  attachments are typed on a params type, a new nested field is typed too:
  never `JsonElement`, `JsonNode`, `json.RawMessage`, `unknown`, or a bare
  `dict` next to typed siblings.
- **Wire keys stay snake_case, except JS.** Every binding serializes to the
  core's snake_case JSON; JS/WASM is camelCase throughout (field names *and*
  enum tag values, via `JsCamelCase`). The one documented exception is
  `AttachmentDescriptor`, whose snake_case keys mirror the wire protocol in
  every binding, JS included.
- **Optional fields follow one style per binding:** Rust `Option<T>`; JS
  `field?: T | null`; Python `Optional[T]` keyword arguments and
  `TypedDict(total=False)` keys; Go pointer + `omitempty`; .NET nullable +
  `JsonIgnore(WhenWritingNull)`; JVM boxed/reference field + `@JsonInclude(NON_NULL)`.
  Unset optionals are **omitted**, not sent as `null`: core enums such as
  `QuickReply` are untagged with `deny_unknown_fields`, so a stray
  `"response": null` next to `"request"` is rejected.
- **Errors follow one style per binding.** Invalid input fails in the core with
  a message naming the value (`Invalid quick reply: …`), surfaced as the
  binding's error type: Python `ValueError`, JS a thrown `Error`, Go a returned
  `error`, .NET and JVM `ChatXdkException`. Never return a partial result or
  silently drop the bad value.

**Known exceptions** (do not copy these patterns into new surface; fix them
when touching the area): Go `TextContent` nested fields other than quick reply,
`Message.Attachments` and `GroupChangeEvent.Change` are `json.RawMessage`;
.NET and JVM decrypt output is untyped JSON; several JS `MessageContent`
nested fields are `unknown`; Python attachments are `list[dict]`; entities are
a struct in Rust/.NET/JVM but a tuple in Go/JS/Python; JS attachment inputs are
snake_case while decrypted `AttachmentInfo` is camelCase; JS wraps invalid
params as `Invalid encryptMessage params: …` instead of the core message.

**Checklist — adding a field or a type**

1. Define it once in `crates/core` (with `JsCamelCase` for JS and a
   camelCase test in `crates/core/src/types.rs` if it holds enum tags or
   struct-variant fields).
2. Add the typed equivalent to every binding, under the same type and field
   names: Rust, JS `index.d.ts` + the wasm params mirror, Python `__init__.py`
   + `__init__.pyi`, Go `go/chatxdk/types.go`, .NET `Types.cs`, JVM
   `Types.java`.
3. Use it on **both** sides: every params type that accepts it, and every typed
   output that returns it.
4. Apply the binding's optional-field style so unset values are omitted.
5. Test every binding: encrypt → decrypt round trip, resend the decrypted
   value unchanged, and the invalid-input error.
6. Update `docs/API.md` (per-binding table and examples) and any example that
   passes the value.
7. Grep the bindings for raw-JSON types on the touched params
   (`JsonElement`, `JsonNode`, `RawMessage`, `unknown`, `dict`) before opening
   the PR.

## 5. Security invariants — never weaken to make something pass

- **Verification is not optional.** `decryptEvent` rejects unverified events by
  default; a below-floor key version must never verify; an invalid signature must
  never yield plaintext. Verify against caller-supplied signing keys — **never** a
  key carried inside the event. Verification covers every signed event type, not
  just messages. Signature mismatches are bugs to investigate, not checks to silence.
- **Key downgrade protection is automatic.** Conversation-key versions move
  forward only (monotonic high-water mark held for the `Chat` lifetime); the
  ordering authority is the *signed* key version, not backend sequence numbers.
  Never accept an older version over a newer one, and never add an API that can
  lower the floor.
- **Wire formats are frozen.** The bytes the SDK produces and consumes stay
  compatible with other X Chat clients and with previously stored ciphertext and
  keys. Do not change a wire format — nonce sizes, AAD, HKDF `info`, key
  derivation, secretbox/secretstream layout, the signature payload, or Juicebox
  `UserInfo` — even when the change looks more standards-correct; it breaks
  interop and decryption of stored data. A format change is valid only as a
  versioned, dual-read migration (e.g. a new `signature_version`).
- **All wire parsing is bounded and runs before any crypto.** Untrusted Thrift
  goes through the bounded reader (`crates/core/src/protocol/safe_reader.rs`):
  reject negative/oversized lengths and container counts, never panic on unknown
  union variants or field IDs. Don't route parsing around it, relax the caps, or
  replace the pinned patched `thrift` fork with upstream. New parsing paths get a
  fuzz target.
- **Known protocol limitations are documented, not re-litigated.** No forward
  secrecy / PCS, message encryption without context-binding AAD, and
  single-shared-key group conversations are intentional protocol-level
  constraints recorded in [`docs/CRYPTO.md`](docs/CRYPTO.md) (Known Limitations).
  Don't "fix" them in a binding or claim guarantees the protocol doesn't provide;
  closing them requires a versioned protocol change.
- **No forward secrecy / no post-compromise security** — by protocol design.
  Don't claim otherwise in code or docs.
- **Private key material is zeroized on drop and redacts to `[REDACTED]`.** Never
  log, print, persist, or commit raw private keys, `.env` files, or key blobs.
- Crypto suite: ECIES (ECDH P-256 + AES-128-GCM) for conversation keys;
  XSalsa20-Poly1305 for messages; `crypto_secretstream_xchacha20poly1305` for
  media; ECDSA P-256 signatures; HKDF-SHA256. See [`docs/CRYPTO.md`](docs/CRYPTO.md).

## 6. Testing

- **Drive the real binding — never mock the SDK.** A passing test must fail if
  the shipped code breaks: no hardcoded expected values, no re-implementing the
  code under test.
- Use [`tests/fixtures/sdk_vectors.json`](tests/fixtures/sdk_vectors.json) for
  deterministic cross-binding checks. Keep the parallel suites
  (`crates/*/tests`, `crates/wasm/js/tests`, `go/chatxdk/*_test.go`) in parity.
- `make ci` (fmt-check + clippy `-D warnings` + Rust workspace tests) must pass
  before pushing. `.github/workflows/ci.yml` additionally runs the binding
  suites (Python, JS/WASM, Go, JVM, .NET); run `make test-sdks`,
  `make jvm-test`, and `make dotnet-test` to match it locally.

## 7. Platform invariants

- **Determinism comes from inputs, not ambient state.** Any core function whose
  result derives from the clock (e.g. timestamp-string key versions) exposes a
  `*_with_version` variant taking the value as an argument. `wasm32-unknown-unknown`
  has no system clock and panics on `SystemTime::now()`, so the WASM wrapper must
  call the explicit-version variant; native bindings may read the clock.
- **`conversation_id` is signed in its canonical colon form (`A:B`).** The core
  normalizes before signing; only I/O code may rehyphenate to `A-B` for URL
  paths. Never sign or verify the hyphen form.

## 8. Generated & prebuilt artifacts

- `crates/core/src/thrift/*.rs` are generated by `make codegen` from
  `thrift/*.thrift`. **Do not hand-edit** — change the schema and regenerate.
- Committed Go static libs (`go/chatxdk/libs/<os>_<arch>/*.a`) go stale after any
  `crates/core` change; regenerate (`make prebuilt-all`) or call it out in the PR.
  CI rebuilds Python `_native*.so` and WASM `pkg/` fresh; those are gitignored.

## 9. Style & dependencies

- Comments explain **this** code's intent and gotchas — not lineage, tickets,
  ports, or "mirrors X" (see the code-comments skill). No commented-out code.
- Minimal complexity: no error handling for impossible states, no abstractions
  the task doesn't require.
- `juicebox_sdk` is a path dependency at `../juicebox-sdk` (CI checks out
  `juicebox-systems/juicebox-sdk` as a sibling).
- **One release version for every binding.** The canonical version is
  `[workspace.package] version` in the root `Cargo.toml`; `scripts/version.sh
  set` stamps it into the npm/PyPI/NuGet/Maven manifests in lockstep, and the
  release workflow publishes all registries (and the Go module tags) from that
  single value. Never bump or publish a binding out of step with the others.
- Registry auth is OIDC trusted publishing wherever the registry supports it
  (PyPI, npm, NuGet, crates.io); no long-lived publish tokens. Maven Central is
  the exception (Central Portal user token) until Sonatype ships OIDC.

## 10. Repo layout

```
crates/core/     chat-xdk-core: engine, crypto/, keys/, thrift/ (generated)
crates/pyo3/     Python        crates/wasm/   WASM (+ js/ wrapper)
crates/go/       cdylib → go/chatxdk        crates/dotnet/ + crates/jvm/  (over chat_xdk_dotnet)
docs/            API.md, ARCHITECTURE.md, CRYPTO.md
examples/        clone-and-run demo bots (NOT shipped SDK code)
tests/fixtures/  sdk_vectors.json — cross-binding vectors
```
