# Changelog

## [Unreleased]

### Added

- .NET: build and bundle the `linux-musl-x64` native library in the NuGet package, enabling deployment on Alpine Linux and other musl-based .NET runtimes (#21).

## [0.7.7] - 2026-11-24

### Added

- `prepare_conversation_archive` (`prepareConversationArchive`,
  `PrepareConversationArchive`) signs archiving or unarchiving a conversation,
  group or one-to-one, so API clients can pass `action_signatures` to
  `POST` / `DELETE /2/chat/conversations/{id}/archive`. It takes a
  `ConversationArchiveParams` (`conversation_id`, `archived`, and the usual
  optional `sender_id` / `signing_key_version`) in every binding, and returns a
  `PreparedAction` with one signature, signed as X clients sign an archive: a
  `ConversationMetadataChangeEvent` with an `ArchiveConversation` or
  `UnarchiveConversation` change and no ids. The C ABI gains
  `chat_xdk_prepare_conversation_archive`.
  [API.md](docs/API.md#prepare_conversation_archive) shows the call in every
  binding, and each example's crypto core wraps it with an offline test.
- `decrypt_events` and `decrypt_event` verify archive and unarchive events and
  return them as a `SettingsChange` of `archived` or `unarchived`, where they
  came back as `unknown` and, on the default policy, failed verification.
- `prepare_conversation_mute` (`prepareConversationMute`,
  `PrepareConversationMute`) signs muting or unmuting a conversation, group or
  one-to-one, for the signer alone, so API clients can pass
  `action_signatures` with a mute or unmute request. It takes a
  `ConversationMuteParams` (`conversation_id`, `muted`, and the usual optional
  `sender_id` / `signing_key_version`) in every binding, and returns a
  `PreparedAction` with one signature, signed as X clients sign a mute: a
  `ConversationMetadataChangeEvent` with a `MuteConversation` or
  `UnmuteConversation` change naming the conversation, in canonical colon form
  for a one-to-one, sent in the signer's own `{sender_id}:{sender_id}`
  conversation. The request has to name the conversation in that same form.
  The C ABI gains `chat_xdk_prepare_conversation_mute`.
  [API.md](docs/API.md#prepare_conversation_mute) shows the call in every
  binding.
- Replies and reactions can target one attachment of a message, such as one
  photo of an album: `reply_to_attachment_id` on `EncryptReplyParams` and
  `target_attachment_id` on `EncryptReactionParams`, in every binding
  (`replyToAttachmentId` / `targetAttachmentId` in JS and the JVM,
  `ReplyToAttachmentID` / `TargetAttachmentID` in Go, `ReplyToAttachmentId` /
  `TargetAttachmentId` in .NET). Each needs the raw event, which the SDK
  decrypts to check the attachment is in it; an id it does not carry fails
  with an invalid-input error that lists the ids it does. A reply to one
  attachment quotes only that attachment, and recipients mark its preview
  invalid when the original doesn't carry it. Decrypted reactions and
  reaction removals carry `target_attachment_id`, and reply previews
  `replying_to_attachment_id`, when set.
- `encrypt_forward` (`encryptForward` in JS and the JVM, `EncryptForward` in
  Go and .NET) sends an existing message on as a new message, as the X apps'
  forward sheet does. `EncryptForwardParams` takes the conversation to
  forward to and the original's full text, plus its entities, an optional
  comment with its own entities, and the original's attachments uploaded
  again to this conversation. The original travels as the message's
  `forwarded_message` and the message is marked as sent from the forward
  sheet. A forward with no text and no attachments fails with
  `InvalidInput`.

## [0.7.6] - 2026-11-19

### Added

- `decrypt_events` says what it could not use. Its result has three new maps,
  each keyed by an index as `errors` is (a string in the bindings where the
  keys of `errors` are strings) and empty when it has nothing to report, so
  callers that don't read them see no change:
  - `unverified_key_changes` (`unverifiedKeyChanges` in JS and the JVM,
    `UnverifiedKeyChanges` in Go and .NET), by event index: each key change
    whose key the chat decrypted but whose signature did not verify, with a
    `reason`, whether its key was dropped (`key_dropped`), its
    `conversation_id` and `conversation_key_version`, and the `sender_id` and
    `public_key_version` of the signing key it names. The reason is
    `MissingSigningKey` when the signer's signing key was not among the keys
    the call verified with, `RejectedSigningKey` when it was among them but
    its identity binding does not verify, `InvalidSignature` when the
    signature does not verify against it, and `Unverifiable` when the key
    change carries no signature the SDK can check.
  - `undecryptable_key_changes`, by event index: each key change whose
    conversation key this identity could not decrypt, with a `reason`
    (`Locked`, `NotARecipient`, `OtherKeyVersion` or `DecryptionFailed`), its
    `conversation_id`, `conversation_key_version` and `sender_id`. Such a key
    change was skipped without a trace; a wrong key version given to
    `set_identity` skips every key change.
  - `rejected_signing_keys`, by the signing key's index among the signing
    keys the call verified with: each one left out because its identity
    binding does not verify, with its `user_id` and `public_key_version`.
    Such a key was dropped without a trace, and the events it signed then
    failed as if no key had been passed.
- A key change is signed by the member who made it, who need not have written
  any message in the batch. The chat needs that member's public keys
  (`GET /2/users/{id}/public_keys`): set a public-keys hook, below, or pass
  them with the other signing keys. A key change sequenced since late June
  2026 that does not verify has its key dropped, as before; until now nothing
  in the result said so, and every message under that key failed with an
  error that asked for the key change events the batch already held.
- `decrypt_events` and `extract_conversation_keys` report keys and key
  versions per conversation. `conversation_keys` has two new maps keyed by
  conversation id, in the form events carry (a group's `g…` id; a
  one-to-one's two user ids ordered numerically and colon-separated):
  - `keys_by_conversation` (`keysByConversation`, `KeysByConversation`):
    conversation id → key version → key.
  - `latest_versions` (`latestVersions`, `LatestVersions`): conversation id →
    the version to encrypt with. From `decrypt_events` it holds the newest
    version whose key change verified.

  `keys` and `latest_version` hold the same without the conversation id, for
  a batch whose events all belong to one conversation.
- `add_signing_keys` (`addSigningKeys`, `AddSigningKeys`,
  `chat_xdk_add_signing_keys`) adds signing keys to the stored set: an entry
  replaces the stored entry of the same user and key version, and any other
  is added. `set_signing_keys` still replaces the whole set.
- The key cache serves more calls. All of it applies only while the cache is
  on (`set_cache_keys(true)`, off by default), and a key or key version that
  a call is passed is used as before:
  - `decrypt_file` and `file_decryptor` take `conversation_keys` as
    optional. Left out or empty, the key map is the conversation's keys in
    the cache.
  - `prepare_group_avatar_change` takes `conversation_key_version` as
    optional. Left out or empty, it signs the version of the conversation's
    newest cached key, and fails with an invalid-state error when the cache
    holds none.
- A `resolve_public_keys` hook fetches other users' public keys when a call
  lacks them. The hook takes user ids and returns each user's records from
  `GET /2/users/{id}/public_keys`, as the API sent them, by user id. It
  lives in each language's own code: the Rust core stays synchronous and
  calls nothing back.
  - JS: `createChat({ resolvePublicKeys })` or `setResolvePublicKeys`, and
    new methods that call it: `decryptEventsAsync`,
    `prepareConversationKeyChangeAsync`, `prepareGroupCreateAsync`,
    `prepareGroupMembersChangeAsync` and `prepareGroupMembersRemoveAsync`.
    .NET: the `ResolvePublicKeys` property and the same five methods in
    PascalCase. The existing methods of both never call the hook.
  - Python (`set_resolve_public_keys`), Go (`SetResolvePublicKeys`), the JVM
    (`setResolvePublicKeys`) and Rust (`set_resolve_public_keys`): a
    blocking hook, called from the existing `decrypt_events` and prepare
    methods.
  - With a hook set, a decrypt that is passed no signing keys asks it for
    the users whose keys the batch lacked, adds what it returns, and
    decrypts the batch once more. Setting a hook turns the key cache on.
  - A lookup that did not bring the key it was made for is not repeated for
    a minute, per user and key version.

  With no hook set, nothing changes.
- The pieces the hook is built from are public, for a caller that fetches
  keys itself:
  - `missing_signing_keys` on the `decrypt_events` result
    (`missingSigningKeys`, `MissingSigningKeys`), by event index: each
    event, of any signed type, whose sender's signing key was not among the
    keys the call verified with, with the `user_id` and `public_key_version`
    to fetch. Empty when nothing is missing.
  - `missing_public_keys(result)`: the users to fetch, once each.
  - `add_public_keys(records)`: adds the API's records, by user id, to the
    stored signing keys. Go, .NET and the JVM have a `PublicKeyRecord` type
    that unmarshals from the API's JSON.
  - C ABI: `chat_xdk_add_public_keys`, `chat_xdk_missing_public_keys`,
    `chat_xdk_missing_public_keys_for`. Rust: `missing_public_keys_for`
    with a `KeyChangeCall`, for the members a prepare call has no key for.
- `prepare_conversation_key_change`, `prepare_group_create`,
  `prepare_group_members_change` and `prepare_group_members_remove` take
  `public_keys` as optional. Left out or empty, the call encrypts its key to
  the stored public keys of the members its params name, fetched through the
  hook first when one is set: `member_ids` and `admin_ids` for a create, the
  current and new members for an add, the new optional
  `remaining_member_ids` for a removal, and the new optional `member_ids`,
  or the two users of a one-to-one id, for a key change. Only a stored key
  whose identity binding verifies is used. Public keys that are passed are
  used as before.
- The docs say how to run the SDK for many signed-in users in many
  conversations ([API.md](docs/API.md#many-users-many-conversations)): one
  chat per signed-in user, never one per conversation, and one public-keys
  hook function for every chat, over one cache of public keys for the
  process. Each example has both as code with an offline test:
  `SharedPublicKeys`, a hook that shares a lookup under way, retries a failed
  one and fetches an answer again after a TTL, and `UserChats`, one chat per
  user. The six example bots fetch public keys through the hook, and the
  JavaScript example runs one bot per signed-in user (`multi-bot.mjs`).

### Changed

- The key cache is filled on every path and keeps every key version. It was
  filled by `decrypt_events` alone, with one key per conversation: the
  newest whose key change verified. While the cache is on:
  - `decrypt_event` records a key change that verifies as `decrypt_events`
    does: its version becomes the conversation's newest verified one unless
    a newer is known, and its key is cached. A chat that receives events one
    at a time no longer needs a batch call to pick up a new key.
  - `prepare_conversation_key_change`, `prepare_group_create`,
    `prepare_group_members_change` and `prepare_group_members_remove` cache
    the key they make as the conversation's newest. A send that omits its
    key right after one of them uses the new key; it used the previous key,
    or failed for a new conversation, until the key change came back in the
    conversation's events. The key is cached before its request is sent: if
    the X API rejects the request, prepare the change again or pass the key
    to encrypt with explicitly.
  - The cache keeps every key it is given per conversation, by version.
    Sends use the newest. `decrypt_event` with no key map decrypts a message
    under an older cached key, which failed before.

  With the cache off, nothing changes.
- A prepare call that makes a conversation key and is passed no public keys
  no longer fails outright. Where its params name members, it reads their
  stored keys, and a member with none fails it with `public_keys is empty
  and no public keys are stored for user(s) <ids>: …`, an invalid-input
  error as `public_keys must not be empty` was. Where they name none, the
  errors are the ones it gave before. In JS and the C ABI, leaving
  `publicKeys` out of the params was a missing-field error and now reaches
  those errors.
- `latest_version` is null for a batch whose events belong to more than one
  conversation, from `decrypt_events` and from `extract_conversation_keys`.
  It was the highest version across the batch: verified, from
  `decrypt_events`; unverified, from `extract_conversation_keys`. That is
  another conversation's key version for every conversation of the batch but
  one, and encrypting with it sends a message its recipients cannot read.
  Read `latest_versions[conversation_id]`. A batch of one conversation
  reports `latest_version` as before.
- Two conversations whose keys have the same version no longer collide in a
  batch. `keys` kept one key per version, the last in the batch: the other
  conversation's key change was then checked against the wrong key and failed
  to verify, and its messages failed to decrypt. Each key change is now
  checked against its own conversation's key and each message decrypted with
  its own conversation's key, both kept in `keys_by_conversation`. `keys`
  leaves out a version that key changes of more than one conversation of the
  batch carry, because a lookup by version alone cannot say which
  conversation's key it wants. A batch of one conversation, and a batch whose
  conversations use different versions, get the same `keys` as before.
- A one-to-one conversation is one conversation whichever way an event
  writes its id. Events carry the two user ids ordered numerically and
  colon-separated; an id in the other order or with a hyphen is read as that
  one, so its keys and versions are cached and reported under one id.
- Errors for an event whose signature could not be verified say why. `…
  signature could not be verified: signature missing or no matching signing
  key` is now one of `… the event carries no signature`, `… no signing key
  for sender <id> at public_key_version <version> among the signing keys
  given; pass that user's public keys as signing keys`, `… the signing key
  given for sender <id> at public_key_version <version> was rejected: its
  identity binding does not verify`, `… it signs the conversation key, which
  this chat could not decrypt from the event` (a key change), or `… its
  signed payload cannot be rebuilt from the event`. In a `decrypt_events`
  batch, a message whose key change gave the batch no key fails with `Message
  encrypted with key version '<version>' but no matching key found: the key
  change for that version, event <index> of the batch, did not verify, so its
  key was dropped: <why>` or `… holds no key this chat can decrypt: <why>`.
  The errors' kinds are unchanged.

### Fixed

- JS: the first chats of a process are separate chats when they are created
  at the same time. `createChat` loaded the WebAssembly module again on each
  call until one load had finished. Calls made at the same time before that,
  such as `Promise.all(users.map(openChat))` when a server starts, each
  loaded the module, and their chats then shared the memory of one of them:
  every such chat held the keys and identity of the same chat, so a chat
  created for one user could sign and decrypt as another. A process whose
  first `createChat` call returned before it made the next was not affected.
  `createChat` now loads the module once, in `@xdevplatform/chat-xdk` and in
  `@xdevplatform/chat-xdk-server`.

## [0.7.5] - 2026-11-16

### Changed

- Media quoted in a reply opens from the reply alone. `decrypt_file` and
  `file_decryptor` failed with `the reply does not embed the message it
  quotes` when the reply's preview named the quoted message without
  embedding it, as replies from X clients can, for v0 and v1 media alike.
  The SDK now tries each key the preview's sender, message id and attachment
  id give, under each key in `conversation_keys` (the reply's own key
  version first): a v1 message's attachment key, then the conversation key
  that v0 media is under. Only the file's own key authenticates it. No call,
  type or field changes, and a reply that embeds the quoted message opens as
  before.
  - Pass the conversation's whole key map: the quoted message can be under
    an older key version than the reply. When no key opens the file, the
    error names the media hash key and says what to pass.
  - A file opened this way is not tied to the quoted message:
    `reply_preview_validation` stays absent, and any member of the
    conversation can upload a file that opens this way. To check that a file
    belongs to the quoted message, decrypt it with that message's own event
    ([CRYPTO.md](docs/CRYPTO.md#media-keys)).
- The migration guides in `docs/migrating-0.7/` cover the 0.7.x release line
  instead of a single patch: they install the newest 0.7.x, list what each
  release from 0.7.0 to 0.7.5 changed, and describe opening quoted media.

## [0.7.4] - 2026-11-16

### Added

- The `CHAT_XDK_API_BASE_URL` environment variable names the base URL of the
  X API to read the feature switches from, in place of `https://api.x.com`,
  for a process that reaches the X API under another host name. With
  `CHAT_XDK_API_BASE_URL=https://api.example.com` a chat requests
  `https://api.example.com/2/chat/features`; nothing else about the request
  changes. A chat takes the variable when it is created and when its
  identity is set. A value that is not an `https://` or `http://` URL with a
  host, or that carries credentials, a query or a fragment, is ignored.
  Python, Go, .NET and the JVM follow it, Node does too (a browser has no
  environment), and so does the URL `feature_switches_url`
  (`chat_xdk_feature_switches_url`) returns to a Rust app or a C caller.

### Fixed

- An app that creates a chat for each send, or closes its chats between
  sends, now follows the `v1_send` switch. A chat got its switches only if
  it was alive when the answer to its request arrived, so a chat that sent
  and went away within that time sent v0, and so did every chat after it,
  each starting a request of its own. Now the latest answer for a URL stays
  for 5 minutes after it arrives: a chat created in that time takes it at
  once, in every binding, and reads the URL again when the refresh is due.
  Such an app sends v0 only until its first answer, and makes one request
  per URL every 5 minutes instead of one or two per chat. An answer older
  than 5 minutes that no chat holds is not used, so a switch that is turned
  off still stops v1 sends within the refresh interval.
- Python: the feature-switch request goes through the `http://` proxy that
  `HTTPS_PROXY` names (`HTTP_PROXY` for a plain URL, else `ALL_PROXY`),
  unless `NO_PROXY` exempts the host, with the credentials in the proxy's URL
  sent to the proxy alone. It connected directly whatever the environment
  said, so a host that reaches the X API only through a proxy never read the
  switches and its sends stayed v0. Go and .NET already followed these
  variables, the JVM its `https.proxyHost` properties, and Node its own
  `NODE_USE_ENV_PROXY`.
- Python: a process that forks with `os.fork` reads the switches again in
  the child. The threads that perform and schedule the requests stay in the
  parent, so the chats a forked worker inherited (under `gunicorn --preload`,
  a Celery prefork pool or `multiprocessing`) kept the switches they had at
  the fork for good.
- Python: a fork no longer finds a feature-switch request halfway. A process
  that forked while one was under way, as a preloading server does right
  after its app creates a chat, could get a child that hung the first time it
  resolved a host name or opened a TLS connection, its own HTTP calls
  included: the request's thread was importing Python's idna codec, or held
  a lock of the resolver's or of OpenSSL's. Importing the package now
  imports the codec, and `os.fork` waits for the requests under way, at most
  2 seconds. uWSGI forks without telling Python unless `py-call-osafterfork`
  is set, so under uWSGI create the chat in each worker (`lazy-apps`, or a
  post-fork hook) and set `enable-threads`.
- Python: the requests waiting for their time share one daemon thread
  instead of holding one each, so a process whose chats read many buckets
  keeps one waiting thread, not one per bucket.

## [0.7.3] - 2026-11-05

### Security

- JS: the chat `@xdevplatform/chat-xdk` creates no longer has `importKeys`
  and `exportKeys`, as in 0.5.x. From 0.7.0 through 0.7.2 any script that
  could reach a chat, such as code injected into a page through XSS or a
  compromised dependency, could call `exportKeys` and take its private keys.
  The chat keeps its keys in Juicebox: `setup`, `unlock` and `changePin` move
  them between the WebAssembly engine and Juicebox inside the SDK, and no
  method returns them. A script that reaches the chat can still use it while
  the page runs, so keep untrusted script out of pages that unlock one.

### Added

- `@xdevplatform/chat-xdk-server`, the JS package for Node servers that keep
  their own keys: the API of `@xdevplatform/chat-xdk` over the same
  WebAssembly engine, whose `createChat` returns a `ServerChat`, a
  `ChatWithJuicebox` with `importKeys` and `exportKeys`, as in every other
  binding. A server exports its keys once, keeps them in its secret store,
  and imports them in each process (a Lambda cold start, a webhook worker)
  with no Juicebox round trip per request. It declares `ImportKeysParams`,
  runs on Node 18 and later, and resolves only under the `node` export
  condition, so a bundler building for browsers can't include it. It is
  versioned and released with every other binding.

### Breaking changes

- JS: code that calls `importKeys` or `exportKeys` on a chat from
  `@xdevplatform/chat-xdk` runs on a server with
  `@xdevplatform/chat-xdk-server` instead, which needs only the import
  changed: `import { createChat } from "@xdevplatform/chat-xdk-server"`. A
  browser app keeps its keys in Juicebox with `setup` and `unlock`.
  TypeScript code imports `ImportKeysParams` from the server package too.

## [0.7.2] - 2026-11-02

### Added

- `EncryptReplyParams` takes `reply_to_message_id`, the signed `message_id`
  of the message a reply quotes, in every binding (`replyToMessageId` in JS
  and on the JVM, `ReplyToMessageID` in Go, `ReplyToMessageId` in .NET). A
  reply built from the explicit preview fields needs it: in v1, X clients
  mark a reply that names no original invalid. With `reply_to_event`, the id
  comes from the event, and a `reply_to_message_id` other than it fails with
  an invalid-input error.
- `EncryptEditParams` takes `target_message_id`, the signed `message_id` of
  the message an edit replaces (`targetMessageId` in JS and on the JVM,
  `TargetMessageID` in Go, `TargetMessageId` in .NET). A v1 edit names the
  message it edits, as X clients' edits do, so a v1 edit built from
  `conversation_id` and `target_message_sequence_id` needs it; with
  `target_event`, the id comes from the event, and a `target_message_id`
  other than it fails with an invalid-input error. A v0 edit names none, as
  in 0.5.x.
- A media attachment descriptor takes `plaintext_sha256`, the base64
  SHA-256 of the file's plaintext bytes, which the message carries and signs
  as X clients' messages do. The message is built before its files are
  encrypted, so the caller hashes the file. One that is not the base64 of 32
  bytes fails the send with an invalid-input error. Decrypted media
  attachments return it as `plaintext_sha256` (`plaintextSha256` in JS),
  `null` when the sender sent none. The JVM and .NET add an eight-argument
  `media` / `Media` factory that takes it; Go adds
  `AttachmentDescriptor.PlaintextSHA256`.
- Rust: `AttachmentDescriptor::Media` gains the `plaintext_sha256:
  Option<String>` field, so code that builds the variant with a struct
  literal adds `plaintext_sha256: None` (or the hash), and a pattern that
  lists every field adds it or ends in `..`.
- Rust: `ChatCore::feature_switches_url` and `Chat::feature_switches_url`
  return the URL of a chat's feature switches, `FEATURES_ENDPOINT` with the
  sender's bucket once `set_identity` has set it, and `FEATURES_REFRESH_MS`
  is how long after an answer to read them again. The C ABI adds
  `chat_xdk_feature_switches_url` and `CHAT_XDK_FEATURES_REFRESH_MS`.

### Changed

- While a chat sends v1, every event it signs takes signature version 10, as
  X clients sign each event at the version their messages sign at:
  conversation-key changes, group creates (whose payload then covers the
  group type and TTL), member adds, removals and leaves, the other group and
  conversation-metadata changes, deletes and read receipts. While it sends
  v0 they sign at version 7, as in 0.5.x, apart from a member add that
  carries a description, which signs at version 8. A member removal and the
  removal a leave signs follow the same rule instead of signing at version
  11, so 0.5.x readers verify them while the chat sends v0; their
  signatures don't cover the key version the removal names, and a member
  removal's key change signs the new key version. A conversation-key change
  never signs below the highest version of a key change the chat has signed
  or verified in that conversation, since X clients that enforce a
  key-change floor reject one signed below the newest before it. A key
  change raised above 7 this way is one 0.5.x readers can't verify, like
  the one that raised it.
  The chat holds that floor in memory, so after a restart decrypt the
  conversation's key changes again before changing its key.
- The bindings read the feature switches again 5 minutes after each answer
  while a chat lives, so a change at the X API reaches running chats with
  no restart and no new chat; each answer replaces the one before. Once
  `set_identity` sets the sender, the request carries the sender's bucket,
  the last four digits of the user id (`?bucket=1234`), so a ramp of
  `v1_send` picks the same senders wherever they run; before that the X API
  buckets the request by its address, as in 0.7.1. Chats that read the same
  URL share one request. A request that fails is retried in the background
  while a chat waits for it: 1 second later, then after twice the previous
  wait, at most 5 minutes apart. A failure keeps the answer the chats have;
  until one arrives, every switch stays off and the chat sends v0. The Rust
  core sets the schedule and every binding follows it.
- Rust and the C ABI: each answer handed to `set_feature_switches` or
  `chat_xdk_set_feature_switches` that is a 200 with a features object
  replaces the one before, and any other answer changes nothing. Request the
  URL `feature_switches_url` (`chat_xdk_feature_switches_url`) returns, and
  again every `FEATURES_REFRESH_MS` (`CHAT_XDK_FEATURES_REFRESH_MS`), as the
  bindings do.
- A v1 send's encoded signature lists the signing keys the message relies
  on, by user id and key version (`message_signing_key_info_list`): its
  sender's and, for a reply, those of the quoted message's sender and of its
  edit's, as X clients' v1 sends do.
- A v1 reaction asks for a notification (`should_notify`) only in a
  one-to-one conversation, and a v1 reaction removal or edit asks for none,
  as X clients' v1 sends do. v0 reactions, removals and edits ask for one,
  as 0.5.x's do.
- A reply embeds no key change (`raw_event_ckces`), and decrypt reads none
  from a received reply: recipients open the quoted message with their own
  conversation keys, or with the message key a reply carries for a v1
  message. `reply_to_ckces` still opens an original under a key version the
  sender's chat doesn't hold.

### Fixed

- A reply preview validates only when the first 140 characters of its text,
  counted in UTF-16 code units as X clients count them, are those of the
  quoted text, and its entities are exactly the quoted message's, or its
  edit's when the reply embeds the edit.
- A group change that removes the title, description or avatar verifies: X
  clients sign `null` in the value's place, and so does the verifier. It
  decrypts to an empty title, description or avatar URL.
- An event whose signature carries no signature version, or one that isn't
  an integer, fails verification. Every version signs a message's
  conversation-key version as an integer, `null` when missing or not an
  integer, and a key change's as an integer, as X clients sign them.
- `decrypt_file` and `file_decryptor` number a message's attachments as X
  clients do, leaving out payment receipts, so a v1 file whose attachment
  carries no id opens from a message that also carries a payment receipt.

## [0.7.1] - 2026-10-28

### Added

`encrypt_file_with_key` and `decrypt_file_with_key` encrypt and decrypt a
file under a key the app already holds, rather than a file a message
carries: a group's avatar image, which X clients encrypt under the
conversation key whose version the avatar change signs next to the avatar
URL, or an app's own files at rest. Every binding has them in its own idiom
(`encryptFileWithKey`, `EncryptFileWithKey`, and
`chat_xdk_encrypt_file_with_key` and `chat_xdk_decrypt_file_with_key` in the
C ABI), taking `EncryptFileWithKeyParams` (`file`, `key`) and
`DecryptFileWithKeyParams` (`encrypted`, `key`) with the raw 32-byte key.
They write the file format of a message's files, the one 0.5.x
`encrypt_stream` wrote: files 0.5.x encrypted with `encrypt_stream` or a
stream encryptor decrypt with `decrypt_file_with_key`, and 0.5.x
`decrypt_stream` decrypts what `encrypt_file_with_key` returns. A key that
isn't 32 bytes fails with `invalid_input`, and bytes that aren't a complete
file encrypted under the key with `decryption`. The migration guides move
each `encrypt_stream` and `decrypt_stream` call to `encrypt_file` or
`encrypt_file_with_key` by the file it encrypts.

### Fixed

- API.md, the migration guides and why.md say to re-encrypt a group's avatar
  under the new conversation key after every key rotation, as X clients do:
  encrypt the image with `encrypt_file_with_key`, upload it, and send an
  avatar change naming the new key version.

## [0.7.0] - 2026-10-27

To move code from 0.5.x, follow your binding's guide in
[docs/migrating-0.7](docs/migrating-0.7/README.md): each lists its changes
with before/after code, and [Why 0.7.0 changes](docs/migrating-0.7/why.md)
explains why each change was made. API.md, the guides, the READMEs and the
doc comments in every binding describe this API: their code examples compile
against it, and the Rust crate's examples build as doctests.

### Added

Group and conversation-metadata actions are signed before they are sent:
recipients on the default policy drop one that isn't. Each call takes one
params object and returns `action_signatures` for the request.

`prepare_group_members_remove` removes members and rotates the conversation
key, so the members removed don't receive the key the group encrypts under
next. `GroupMembersRemoveParams` takes the public keys of every member who
stays, the caller's included, the conversation id and the members to
remove, and the result is a `PreparedConversationChange`: the new key, the
remaining members' participant keys, and the request's signatures — the
removal, signed at signature version 11 and bound to the new key version,
then the key change. The group's title and description are encrypted under
the conversation key, so the removal takes the ones the group has as
plaintext (`title`, `description`), encrypts each under the new key, and
signs each change between the removal and the key change, marked as a
key-rotation re-encryption (`for_key_rotation`), which recipients' decrypt
drops (see Other breaking changes). The key cache adopts the new key once
`decrypt_events` verifies the removal's key change; until then the app
passes the new key and version to the encrypt calls. The result carries no
ratchet tree and no rewrapped pin-key bundle.

`prepare_group_leave` signs leaving a group: a removal of the sender, at
signature version 11, an admin add when `promote_admin_id` names the member
to promote, and a conversation delete. Leave does not rotate the
conversation key.

`prepare_group_title_change` and `prepare_group_description_change` take the
new value as plaintext and encrypt it under the conversation key, which
resolves as for `encrypt_message`: the params' key and version, or the key
cache. Each returns a `PreparedGroupMetadataChange`: the `encrypted_value`
the request sends, the `conversation_key_version` it is encrypted under, and
its signature at signature version 7. `decrypt_event` and `decrypt_events`
decrypt a received title or description change, and a description change
decrypts to `GroupChange::DescriptionChanged` (`descriptionChanged`
in JS) with its `new_description`.

`prepare_group_avatar_change` signs a group avatar: the media URL of the
image, as is, and the `conversation_key_version` of the key the image is
encrypted under. An avatar URL is not encrypted; the app encrypts the image
under the conversation key, uploads it to the group's media, and passes the
URL. It returns a `PreparedAction`, and a received `AvatarChanged` change
carries the URL with its `conversation_key_version`.

Admin, invite, and join changes, message-TTL changes, and screen-capture
setting changes each return a `PreparedAction` signed at signature version
7. Screen-capture blocking signs `EnableScreenCaptureBlocking` and
`DisableScreenCaptureBlocking`. Detection signs
`EnableScreenCaptureDetection` and `DisableScreenCaptureDetection`.

A decrypted v1 edit carries the signed message id of the message it edits
as `target_message_id` (`targetMessageId` in JS), next to that message's
`target_message_sequence_id`; a v0 edit carries the sequence id only.

- The bindings fetch the feature switches from
  `GET https://api.x.com/2/chat/features` in the background, without
  delaying or failing anything; there is nothing to call. Each chat reads
  them once, when it is created, and keeps the answer for its lifetime;
  chats created while a request is in flight share it. The request is
  anonymous: it carries no credentials or query parameters, sends and stores
  no cookies, and follows no redirect, so a cookie the endpoint sets never
  reaches a later chat's request and a redirect counts as an answer other
  than 200. Until it answers, and for the chat's lifetime if it fails or is
  blocked, sends stay v0. See "Network access" in the README.
- Rust and the C ABI: `ChatCore::set_feature_switches` and
  `Chat::set_feature_switches`, and
  `chat_xdk_set_feature_switches(chat, status, body, body_len)`, take the
  status and body of a `GET /2/chat/features` the caller made, as the
  crate's `FEATURES_ENDPOINT`, `FEATURES_TIMEOUT_MS` and `FEATURES_MAX_BODY`
  describe it, and `chat_xdk.h`'s `CHAT_XDK_FEATURES_ENDPOINT`,
  `CHAT_XDK_FEATURES_TIMEOUT_MS` and `CHAT_XDK_FEATURES_MAX_BODY`. A chat
  takes one answer for its lifetime, and every switch stays off unless a 200
  answer of at most `FEATURES_MAX_BODY` bytes turns it on.
- JS: `importKeys` and `exportKeys`, as in every binding.
- Python: `SigningKeyEntry`, `PublicKeyInput`, `ConversationKeyResult`,
  `DecryptEventsResult`, `DecryptedEvent`, `PreparedAction`,
  `PreparedGroupMetadataChange`, `PreparedConversationChange`,
  `ActionSignature`, `MessageEventSignature` and
  `ConversationParticipantKey` type the dicts the calls take and return.
- `SendPayload` carries `xdk_version`, the SDK version that built it
  (`xdkVersion` in JS, `XdkVersion` in Go and .NET).
- Messages encrypted under per-message keys (`contents_encryption_version`
  1 or more) decrypt, as do their reply previews, edits and files. A reply
  to such a message carries the original's key, and a v1 edit names the
  message it edits.
- Signatures verify at versions 8 through 11, in the payload layout of the
  version each carries. Versions above 11 are rejected.
- Read receipts are signed. `prepare_mark_conversation_read` takes
  `MarkConversationReadParams`: `conversation_id`, `seen_until_sequence_id`
  (the sequence id of the newest event read) and a `seen_at_msec`, which
  defaults to the current time. It returns a `PreparedAction`, whose
  `action_signatures` the mark-read request
  (`POST /2/chat/conversations/{id}/read`) sends as they are, nested as the
  conversation-change requests nest theirs. Recipients on the default policy
  drop an unsigned receipt; `decrypt_event` returns a signed receipt as a
  verified `ReadReceipt`. The C ABI adds
  `chat_xdk_prepare_mark_conversation_read`.
- The JVM jar and the .NET package bundle the native library for 64-bit ARM
  Linux (`linux-arm64`) too, so both bindings run there without a library of
  your own.

### Breaking changes

#### Sends can use per-message keys

Every encrypted send (message, reply, reaction and edit) is in one of two
wire formats, and the SDK picks which:

- **v0**, the 0.5.x format: contents are encrypted under the conversation
  key, `contents_encryption_version` is unset, and the send is signed at
  signature version 7. Message ids are random, attachments carry no id, and
  an edit does not name the message it edits, as in 0.5.x.
- **v1**, per-message keys: contents are encrypted under a key derived from
  the conversation key, the sender id and the message id, the
  `MessageCreateEvent` carries `contents_encryption_version` 1, and the send
  is signed at signature version 10, which covers that field. A message with
  files takes an id derived from them, each attachment carries an id, and an
  edit names the message it edits.

Sends are v0 unless the X API's `v1_send` feature switch turns v1 on for the
chat. The bindings read the switches themselves; a Rust chat, or one called
through the C ABI directly, sends v1 once it's handed an answer that turns
the switch on (`set_feature_switches`, `chat_xdk_set_feature_switches`).
Readers need per-message-key support for v1 sends: 0.5.x rejects each one as
a signature verification failure (an ECDSA mismatch), so upgrade readers
first. Other signed actions (conversation-key changes, group changes and
deletes) still sign at version 7.

`sender_id` must be the sender's numeric user id, and
`conversation_key_version` an integer as its key-change event carries it.
Other values are rejected in both formats, since v1 recipients derive
the key from the numeric id and look it up by the version.

#### Key registration sends only the public key

`generate_keypairs` returns a `PublicKeyRegistrationPayload` that carries
only `public_key`, in every binding. POST the payload as returned.
`PublicKeys`, which `get_public_keys` and `setup` return, holds the two
public keys, `identity` and `signing`.

`generate_keypairs` sets no signing-key version. After you register the
keys, call `set_identity` with your user id and the `public_key_version`
the registration returns, or pass that version as `signing_key_version` in
`ImportKeysParams` when you load saved keys. A signed action without a
version fails in the SDK with `signing_key_version is not set: pass it
explicitly or call set_identity() first`, rather than reaching the X API,
which accepts only the registered version.

In the snippets, `api.post(path, body)` stands for your HTTP client: it
POSTs `body` as JSON to `https://api.x.com` + `path` and returns the parsed
response. The JS one writes keys in snake_case, and in Python `public_key`
is the `public_key` object you build from `registration.public_key`.

```js
const registration = chat.generateKeypairs();
const response = await api.post(`/2/users/${userId}/public_keys`, { public_key: registration.publicKey });
chat.setIdentity({ userId, signingKeyVersion: response.data.public_key_version });
```

```python
registration = chat.generate_keypairs()
response = api.post(f"/2/users/{user_id}/public_keys", {"public_key": public_key})
chat.set_identity(SetIdentityParams(user_id, response["data"]["public_key_version"]))
```

Go, .NET, JVM and Rust call `SetIdentity` / `setIdentity` / `set_identity`
the same way; each binding's guide in
[docs/migrating-0.7](docs/migrating-0.7/README.md) shows its request and the
0.5.x code to change.

#### A message with files is built before its files are encrypted

In v1 each file of a message is encrypted under its own key, derived from
the message's key and the file's attachment; in v0 every file is under the
conversation key, as in 0.5.x. Either way the file calls take the key from
the message, so the message comes first:

1. Start each file's upload with `POST /2/chat/media/upload/initialize`
   and keep the `session_id` and `media_hash_key` it returns. The upload's
   `total_bytes` is `encrypted_file_size` of the file's size.
2. Encrypt the message (`encrypt_message` / `encrypt_reply`) with
   attachments that name those media hash keys. `SendPayload` carries
   `event_b64`: the message as recipients receive it.
3. Encrypt each file with `encrypt_file` (whole file) or
   `file_encryptor` (incremental `push` / `finish`), passing the payload's
   `event_b64` and the file's media hash key. As `encrypt_message` does, the
   file calls take the conversation key the message was encrypted under and
   its version (`conversation_key` + `conversation_key_version`, set
   together), or resolve both from the key cache when neither is set.
4. Upload each encrypted file with
   `POST /2/chat/media/upload/{session_id}/append` and finish it with
   `POST /2/chat/media/upload/{session_id}/finalize`, then send the message.

The file calls need no session identity: the sender, message id
and key version come from `event_b64`. In v1 the SDK derives the id of a
message with files from the conversation key and its version, the sender,
the conversation and the files' media hash keys, so building the same
message again gives the same id and its encrypted files stay valid; v0
messages, and messages without files, take a random id, as in 0.5.x. Upload
each file for one message only: the text does not affect the id, so a second
message that reuses the first one's uploads gets its id, and recipients drop
it as a repeat. A message that lists an empty media hash
key, or one media hash key in two attachments, is rejected, and the file
calls' errors say what to pass instead.

In the snippets, `api.post(path, body)` stands for your HTTP client, as in
the key registration entry above, and `photo_attachment` for your code that
builds a photo's attachment descriptor. The `append` and `finalize`
requests come after `encrypt_file`, which produces the bytes they upload:

Rust

```rust
let total_bytes = utils::encrypted_file_size(photo.len() as u64).ok_or("file too large")?;
let upload = api.post("/2/chat/media/upload/initialize", &serde_json::json!({
    "conversation_id": conversation_id, "total_bytes": total_bytes,
}))?;
let session_id = upload["data"]["session_id"].as_str().ok_or("no session_id")?;
let media_hash_key = upload["data"]["media_hash_key"].as_str().ok_or("no media_hash_key")?;
let mut params = EncryptMessageParams::new(conversation_id, "a photo");
params.attachments = Some(vec![photo_attachment(media_hash_key)]);
let payload = chat.encrypt_message(&params)?;
let encrypted = chat.encrypt_file(&EncryptFileParams::new(photo, &payload.event_b64, media_hash_key))?;
api.post(&format!("/2/chat/media/upload/{session_id}/append"), &serde_json::json!({
    "conversation_id": conversation_id, "media_hash_key": media_hash_key,
    "segment_index": 0, "media": utils::bytes_to_base64(&encrypted),
}))?;
api.post(&format!("/2/chat/media/upload/{session_id}/finalize"), &serde_json::json!({
    "conversation_id": conversation_id, "media_hash_key": media_hash_key, "num_parts": "1",
}))?;
```

Python

```python
upload = api.post("/2/chat/media/upload/initialize", {
    "conversation_id": conversation_id, "total_bytes": encrypted_file_size(len(photo)),
})["data"]
media_hash_key = upload["media_hash_key"]
payload = chat.encrypt_message(
    EncryptMessageParams(conversation_id, "a photo", attachments=[photo_attachment(media_hash_key)])
)
encrypted = chat.encrypt_file(EncryptFileParams(photo, payload.event_b64, media_hash_key))
api.post(f"/2/chat/media/upload/{upload['session_id']}/append", {
    "conversation_id": conversation_id, "media_hash_key": media_hash_key,
    "segment_index": 0, "media": bytes_to_base64(encrypted),
})
api.post(f"/2/chat/media/upload/{upload['session_id']}/finalize", {
    "conversation_id": conversation_id, "media_hash_key": media_hash_key, "num_parts": "1",
})
```

JS / TypeScript

```js
const { data: upload } = await api.post("/2/chat/media/upload/initialize", {
  conversation_id: conversationId, total_bytes: encryptedFileSize(photo.length),
});
const mediaHashKey = upload.media_hash_key;
const payload = chat.encryptMessage({
  conversationId, text: "a photo", attachments: [photoAttachment(mediaHashKey)],
});
const encrypted = chat.encryptFile({ file: photo, eventB64: payload.eventB64, mediaHashKey });
await api.post(`/2/chat/media/upload/${upload.session_id}/append`, {
  conversation_id: conversationId, media_hash_key: mediaHashKey,
  segment_index: 0, media: bytesToBase64(encrypted),
});
await api.post(`/2/chat/media/upload/${upload.session_id}/finalize`, {
  conversation_id: conversationId, media_hash_key: mediaHashKey, num_parts: "1",
});
```

Go

```go
size, err := chatxdk.EncryptedFileSize(uint64(len(photo)))
response, err := api.Post("/2/chat/media/upload/initialize", map[string]any{
    "conversation_id": conversationID, "total_bytes": size,
})
upload := response["data"].(map[string]any)
sessionID, mediaHashKey := upload["session_id"].(string), upload["media_hash_key"].(string)
payload, err := chat.EncryptMessage(chatxdk.EncryptMessageParams{
    ConversationID: conversationID, Text: "a photo",
    Attachments: []chatxdk.AttachmentDescriptor{photoAttachment(mediaHashKey)},
})
encrypted, err := chat.EncryptFile(chatxdk.EncryptFileParams{
    File: photo, EventB64: payload.EventB64, MediaHashKey: mediaHashKey,
})
_, err = api.Post("/2/chat/media/upload/"+sessionID+"/append", map[string]any{
    "conversation_id": conversationID, "media_hash_key": mediaHashKey,
    "segment_index": 0, "media": base64.StdEncoding.EncodeToString(encrypted),
})
_, err = api.Post("/2/chat/media/upload/"+sessionID+"/finalize", map[string]any{
    "conversation_id": conversationID, "media_hash_key": mediaHashKey, "num_parts": "1",
})
```

.NET (C#)

```csharp
var upload = api.Post("/2/chat/media/upload/initialize", new
{
    conversation_id = conversationId,
    total_bytes = ChatXdkUtilities.EncryptedFileSize((ulong)photo.Length),
}).GetProperty("data");
var sessionId = upload.GetProperty("session_id").GetString();
var mediaHashKey = upload.GetProperty("media_hash_key").GetString()!;
var payload = chat.EncryptMessage(new EncryptMessageParams(conversationId, "a photo")
{
    Attachments = new[] { PhotoAttachment(mediaHashKey) },
});
var encrypted = chat.EncryptFile(new EncryptFileParams(photo, payload.EventB64, mediaHashKey));
api.Post($"/2/chat/media/upload/{sessionId}/append", new
{
    conversation_id = conversationId, media_hash_key = mediaHashKey,
    segment_index = 0, media = Convert.ToBase64String(encrypted),
});
api.Post($"/2/chat/media/upload/{sessionId}/finalize", new
{
    conversation_id = conversationId, media_hash_key = mediaHashKey, num_parts = "1",
});
```

JVM (Java)

```java
JsonNode upload = api.post("/2/chat/media/upload/initialize", Map.of(
        "conversation_id", conversationId,
        "total_bytes", ChatXdkUtilities.encryptedFileSize(photo.length))).path("data");
String sessionId = upload.path("session_id").asText();
String mediaHashKey = upload.path("media_hash_key").asText();
EncryptMessageParams params = new EncryptMessageParams(conversationId, "a photo");
params.attachments = List.of(photoAttachment(mediaHashKey));
SendPayload payload = chat.encryptMessage(params);
byte[] encrypted = chat.encryptFile(new EncryptFileParams(photo, payload.eventB64, mediaHashKey));
api.post("/2/chat/media/upload/" + sessionId + "/append", Map.of(
        "conversation_id", conversationId, "media_hash_key", mediaHashKey,
        "segment_index", 0, "media", Base64.getEncoder().encodeToString(encrypted)));
api.post("/2/chat/media/upload/" + sessionId + "/finalize", Map.of(
        "conversation_id", conversationId, "media_hash_key", mediaHashKey, "num_parts", "1"));
```

For a large file, use
`file_encryptor(FileEncryptorParams(event_b64, media_hash_key))` instead of
`encrypt_file` and feed it with `push` / `finish`. See
[docs/API.md — Files (Media)](docs/API.md#files-media).

#### Files are decrypted from the message that carries them

`decrypt_file` and `file_decryptor` take the base64
event of the message that carries the file and the conversation's key map —
the same two values `decrypt_event` takes — plus the file's media hash key
from the decrypted message: one of its media attachments, a link card's
banner or favicon (both listed in `media_hashes`), or media quoted in its
reply preview. The SDK finds that attachment in the event and derives its
key, including for messages that encrypt each attachment under its own key.
Errors say what to pass when the key version is missing from the map, the
media hash key is not in the event, the event is not an encrypted message
with files, or the bytes are wrong or truncated.

```rust
// Rust
let plaintext = chat.decrypt_file(&DecryptFileParams::new(
    encrypted, event_b64.clone(), conversation_keys.clone(), media_hash_key.clone(),
))?;
let decryptor = chat.file_decryptor(&FileDecryptorParams::new(event_b64, conversation_keys, media_hash_key))?;
```

```python
# Python
plaintext = chat.decrypt_file(DecryptFileParams(encrypted, event_b64, conversation_keys, media_hash_key))
decryptor = chat.file_decryptor(FileDecryptorParams(event_b64, conversation_keys, media_hash_key))
```

```js
// JS / TypeScript
const plaintext = chat.decryptFile({ encrypted, eventB64, conversationKeys, mediaHashKey });
const decryptor = chat.fileDecryptor({ eventB64, conversationKeys, mediaHashKey });
```

```go
// Go
plaintext, err := chat.DecryptFile(chatxdk.DecryptFileParams{
    Encrypted: encrypted, EventB64: eventB64, ConversationKeys: conversationKeys, MediaHashKey: mediaHashKey,
})
decryptor, err := chat.FileDecryptor(chatxdk.FileDecryptorParams{
    EventB64: eventB64, ConversationKeys: conversationKeys, MediaHashKey: mediaHashKey,
})
```

```csharp
// .NET (C#)
var plaintext = chat.DecryptFile(new DecryptFileParams(encrypted, eventB64, conversationKeys, mediaHashKey));
using var decryptor = chat.FileDecryptor(new FileDecryptorParams(eventB64, conversationKeys, mediaHashKey));
```

```java
// JVM (Java)
byte[] plaintext = chat.decryptFile(new DecryptFileParams(encrypted, eventB64, conversationKeys, mediaHashKey));
FileDecryptor decryptor = chat.fileDecryptor(new FileDecryptorParams(eventB64, conversationKeys, mediaHashKey));
```

#### `decrypt_events` and `decrypt_event` take params objects

`decrypt_events` takes `DecryptEventsParams` (`events`, optional
`signing_keys`) and `decrypt_event` takes `DecryptEventParams` (`event_b64`,
optional `conversation_keys`, optional `signing_keys`), named the same in
every binding. Omitted (or, in Rust, empty), the conversation keys come from
the opt-in key cache. In .NET and the JVM, a `ConversationKeyBundle`'s
`Keys` / `keys` map is the key map they take. `decrypt_events` collects a
failure in an event in its `errors` instead of throwing, and throws only for
invalid params; `decrypt_event` throws on failure. The result holds the
decrypted events, of every event type, in `events`, each a `DecryptedEvent`
(`event`, and `original_b64` for a message). Its
`conversation_keys.latest_version`, the version to encrypt with, is the
newest version whose key change verified, monotonic for the chat's
lifetime, and absent until a key change verifies; a key change that doesn't
verify still adds its key to `conversation_keys.keys`, for decrypting.

```rust
// Rust
let result = chat.decrypt_events(&DecryptEventsParams::new(events).with_signing_keys(signing_keys.clone()));
let event = chat.decrypt_event(&DecryptEventParams::new(event_b64, keys).with_signing_keys(signing_keys))?;
```

```python
# Python
result = chat.decrypt_events(DecryptEventsParams(events, signing_keys=signing_keys))
event = chat.decrypt_event(DecryptEventParams(event_b64))
```

```js
// JS / TypeScript
const result = chat.decryptEvents({ events, signingKeys });
const event = chat.decryptEvent({ eventB64, conversationKeys: keys, signingKeys });
```

```go
// Go
result, err := chat.DecryptEvents(chatxdk.DecryptEventsParams{Events: events, SigningKeys: signingKeys})
event, err := chat.DecryptEvent(chatxdk.DecryptEventParams{EventB64: eventB64, ConversationKeys: keys, SigningKeys: signingKeys})
```

```csharp
// .NET (C#)
var result = chat.DecryptEvents(new DecryptEventsParams(events) { SigningKeys = signingKeys });
var evt = chat.DecryptEvent(new DecryptEventParams(eventB64, keys) { SigningKeys = signingKeys });
```

```java
// JVM (Java)
DecryptEventsParams batch = new DecryptEventsParams(events);
batch.signingKeys = signingKeys;
DecryptEventsResult result = chat.decryptEvents(batch);
DecryptEventParams one = new DecryptEventParams(eventB64, keys);
one.signingKeys = signingKeys;
JsonNode event = chat.decryptEvent(one);
```

#### Python takes a params class for every params method

`encrypt_message`, `encrypt_reply`, `encrypt_add_reaction`,
`encrypt_remove_reaction`, `encrypt_edit`, `prepare_conversation_key_change`,
`prepare_group_members_change`, `prepare_group_create` and
`prepare_message_delete` take a params class, as in the other bindings:
`EncryptMessageParams`, `EncryptReplyParams`, `EncryptReactionParams`,
`EncryptEditParams`, `ConversationKeyChangeParams`,
`GroupMembersChangeParams`, `GroupCreateParams` and `MessageDeleteParams`.
Each class takes its required fields positionally, as it does the event a
reply, reaction or edit targets, and the rest as keywords, and exposes every
field as a read/write attribute.

```python
payload = chat.encrypt_message(EncryptMessageParams(conversation_id, "hi", ttl_msec=60_000))
reply = chat.encrypt_reply(EncryptReplyParams(conversation_id, "pong", event_b64))
reaction = chat.encrypt_add_reaction(EncryptReactionParams(event_b64, "👍"))
edit = chat.encrypt_edit(EncryptEditParams(event_b64, "fixed text"))
prepared = chat.prepare_conversation_key_change(
    ConversationKeyChangeParams(public_keys, conversation_id=conversation_id)
)
```

#### File names and the C ABI

- The incremental file classes are `FileEncryptor` and `FileDecryptor` in
  every binding, each with `push` and `finish`.
- `encrypted_file_size` (`encryptedFileSize`, `EncryptedFileSize`) gives the
  size an upload declares before the file is encrypted.
- Rust: `crypto::encryption::{encrypt_file, decrypt_file,
  encrypted_file_size}` take a conversation key directly.
- One C ABI crate, `chat-xdk-ffi`, builds the native library of every
  binding over it: `libchat_xdk_ffi.a`, which Go links from
  `go/chatxdk/libs/<os>_<arch>/`, and `chat_xdk_ffi`
  (`libchat_xdk_ffi.so`, `libchat_xdk_ffi.dylib`, `chat_xdk_ffi.dll`),
  which the .NET package and the JVM jar load.
- The C ABI is versioned: `chat_xdk.h` defines `CHAT_XDK_ABI_VERSION` (1),
  and `chat_xdk_abi_version()` returns the library's, so a caller compares
  the two at startup. Every function returns an `FfiResult`, apart from
  `chat_xdk_abi_version` and the `_free` functions: booleans come back as
  `true` or `false` in `data` (`chat_xdk_is_unlocked`,
  `chat_xdk_has_identity_key`, `chat_xdk_verify`,
  `chat_xdk_verify_key_binding`, `chat_xdk_matches_registered_key`), and
  an error as a JSON document in `error`: `{"kind", "message"}`, plus
  `guesses_remaining` after a wrong PIN.
- `chat_xdk_new(juicebox_config_json, &chat)` creates a chat with its
  Juicebox config, or NULL for none, and writes the handle to its
  out-parameter. The Juicebox functions (`chat_xdk_update_config`,
  `chat_xdk_setup`, `chat_xdk_unlock`, `chat_xdk_change_pin`,
  `chat_xdk_delete`) are declared when `CHAT_XDK_JUICEBOX` is defined, and
  take PINs as bytes and length.
- The calls that take one params JSON document are `chat_xdk_set_identity`,
  `chat_xdk_import_keys` (the key bytes by pointer and length, beside the
  document), `chat_xdk_decrypt_events`, `chat_xdk_decrypt_event`, the
  encrypt and prepare calls, and the file calls;
  `chat_xdk_file_encryptor_new` and `chat_xdk_file_decryptor_new` write the
  handle to an out-parameter. [C ABI](docs/migrating-0.7/c-abi.md) lists
  the calls whose arguments or results differ from 0.5.x.

#### Errors carry their kind

Every failure has a kind, named the same in every binding: invalid input,
invalid state, parse, decryption, verification, invalid PIN, Juicebox, or
internal. Rust reports it as `SdkError::kind()`, an `ErrorKind`; Python as
the exception class, a `ChatXdkError` (a `ValueError`) subclass:
`InvalidInputError`, `InvalidStateError`, `ParseError`, `DecryptionError`,
`VerificationError`, `InvalidPinError` or `JuiceboxError`, each with
`kind`; JS as the `kind` of a `ChatXdkError` (`invalidInput`, …); Go as the
`Kind` of a `*chatxdk.Error`, read with `errors.As`; .NET and the JVM as the
`Kind` / `getKind()` of a `ChatXdkException`; and the C ABI as the `kind` of
its error document. After a wrong PIN, the attempts Juicebox reports left
come with the error: `guesses_remaining()` in Rust, `guesses_remaining` in
Python and the C ABI, `guessesRemaining` in JS, `GuessesRemaining` in Go
and .NET, and `getGuessesRemaining()` in the JVM.

A missing or invalid parameter fails with an error of the invalid-input
kind whose message names the value, such as `Invalid sender_id 'user-1': …`
or `too many attachments: …`, without an `Invalid state:` prefix; in Rust it
is `SdkError::InvalidInput`. That covers a key or signature `verify`,
`verify_key_binding` or `matches_registered_key` can't decode, a
conversation key or key blob of the wrong length, and an empty
`public_keys`. `SdkError::InvalidState` is left for values neither passed
nor set on the chat, such as a missing session identity, an empty key cache
or a missing Juicebox config. `export_keys` fails with an invalid-state
error when no identity key is loaded, in every binding.

#### Juicebox key storage

A chat that keeps its keys in Juicebox takes the Juicebox config the X API
returns when it's created, in every binding: `Chat::new(config)` in Rust,
`Chat(config_json)` in Python, `createChat({ juiceboxConfig, getAuthToken })`
in JS, `NewWithJuiceboxConfig(config)` in Go, `new Chat(config)` in .NET and
the JVM, and `chat_xdk_new(config, &chat)` in the C ABI. `update_config`
sets or replaces it, for first boot or refreshed tokens, and setup and
unlock take only the PIN. A chat created without a config (`Chat::default()`
in Rust, `Chat()` in Python, `createChat({ getAuthToken })` in JS, `New()`
in Go, `new Chat()` in .NET and the JVM, and `chat_xdk_new(NULL, &chat)` in
the C ABI) runs every crypto call, and until it has one, setup, unlock,
`change_pin` and `delete` fail with the same invalid-state error in every
binding: `Invalid state: no Juicebox config: pass the juicebox_config the X
API returns when you create the chat, or call update_config() first`. An
empty or blank config string is no config: creating a chat with one, or
passing one to `update_config`, fails with that error in every binding, and
Rust's `JuiceboxConfig::from_x_api_json` returns it as an `SdkError`, as it
returns an invalid-input one for a malformed config. Go,
.NET, the JVM and the C ABI take PINs as bytes the caller can zero. Python
(`setup_async`, `unlock_async`, `change_pin_async`, `delete_async`), .NET
(`SetupAsync`, …) and the JVM (`setupAsync`, …) run the Juicebox calls off
the calling thread. The PIN guess budget is the config's `max_guess_count`
in every binding. In JS, the SDK reads the config, checks a new PIN and
words a Juicebox failure as every binding does, and a chat created without
`getAuthToken` keeps its keys with `importKeys` and `exportKeys`, without
juicebox-sdk.

#### Other breaking changes

- Rust: `SendPayload` carries `event_b64` and `xdk_version` and is
  `#[non_exhaustive]`, so code outside the SDK reads its fields but can't
  build it with a struct literal.
- `SendPayload`'s encoded fields are `encoded_message_create_event` and
  `encoded_message_event_signature`, the send request's field names, in every
  binding (`encodedMessageCreateEvent` / `encodedMessageEventSignature` in JS
  and the JVM, `EncodedMessageCreateEvent` / `EncodedMessageEventSignature`
  in Go and .NET), so the request takes them as they are.
- Participant keys take the X API's names, on send and on receive. A
  prepared change carries `conversation_participant_keys`, each entry with
  `user_id`, `encrypted_conversation_key` and `public_key_version`: the
  field names the X API uses in every request that takes participant keys
  (`POST /2/chat/conversations/{id}/keys`, `/group` and `/{id}/members`, and
  `PUT /2/chat/conversations/{id}`), so apps pass the keys through
  unchanged. A decrypted `KeyChange` event carries its keys under the same
  names, as Thrift's `ConversationKeyChangeEvent` does, and one type,
  `ConversationParticipantKey`, holds them in both directions (Python
  returns dicts with those keys). The names are
  `conversationParticipantKeys` / `encryptedConversationKey` in JS and the
  JVM, and `ConversationParticipantKeys` / `EncryptedConversationKey` in Go
  and .NET.
- A `PublicKeyInput`, one participant a new conversation key is encrypted
  to, holds `user_id`, `identity_public_key` and `public_key_version`, as a
  `SigningKeyEntry` names them (`identityPublicKey` / `publicKeyVersion` in
  JS and the JVM, `IdentityPublicKey` / `PublicKeyVersion` in Go and .NET).
- Decrypted events use the names the calls take, in every binding.
  Messages and key changes carry their conversation key version as
  `conversation_key_version`, the name the X API's events and Thrift give it
  (`conversationKeyVersion` in JS, `ConversationKeyVersion` in Go). Fields
  that hold sequence ids say so, as the params that send them do: reactions
  and edits name their target `target_message_sequence_id`, deletions their
  messages `sequence_ids`, and read receipts and unread markers their
  position `seen_until_sequence_id` (`targetMessageSequenceId`,
  `sequenceIds` and `seenUntilSequenceId` in JS; `TargetMessageSequenceID`
  and `SeenUntilSequenceID` in Go). An edit's text is `updated_text`
  (`updatedText` in JS).
- Group titles and descriptions are plaintext in the API, and the SDK
  encrypts and decrypts them. `prepare_group_create` encrypts its title
  under the conversation key it creates, signs the ciphertext, and returns
  it on its `PreparedConversationChange` as `encrypted_title`
  (`encryptedTitle` in JS, `EncryptedTitle` in Go): the `group_name` the
  create request sends. `prepare_group_members_change` takes the group's
  `current_title` and `current_description` as plaintext, encrypts each
  under the key it rotates to, signs the ciphertext, and returns them as
  `encrypted_title` and `encrypted_description`; an add that carries a
  description signs at signature version 8. Titles and descriptions are
  signed as base64 ciphertext, so they may contain a comma. The title and
  description prepare calls and a member removal take the plaintext too. A
  create sets no avatar: an avatar is an image the app encrypts and
  uploads, and `prepare_group_avatar_change` signs its media URL, which no
  call encrypts. A decrypted `Created` change carries its `title`, and a
  `TitleChanged` or `DescriptionChanged` change its `new_title` or
  `new_description` (`newTitle`, `newDescription` in JS), as a `GroupText`:
  the text, decrypted with the conversation key the event names or as
  carried when it names none, or unavailable with the raw value when that
  key isn't there or the value doesn't decrypt. The event still decrypts
  either way. 0.5.x apps sent titles as plaintext while naming a key
  version, so show the raw value when a title isn't decryptable. A
  `Created` or `AvatarChanged` change carries the avatar URL as is, with
  its `conversation_key_version`. `decrypt` opens the encrypted
  `group_name` and `group_description` the X API returns with a
  conversation.
- `decrypt_event` and `decrypt_events` drop a group change that re-encrypts
  the group's title or description for a key rotation (`for_key_rotation`),
  as a member removal sends one under the new key: it carries the same text
  and isn't a change. They drop it under either reject-unverified setting,
  after verifying it, as they drop an unverified event: `decrypt_events`
  leaves it out of `events` and records it in `errors`, and `decrypt_event`
  fails with an invalid-input error. The removal itself, its key change,
  avatar changes and every title or description change without the mark
  decrypt as before. The mark sits outside the signed payload, so a relay
  that sets it on a title change can only hide that change, as it could by
  withholding the event.
- Rust: every method takes its params by reference, the decrypt and file
  calls included: `encrypt_message(&params)`, `decrypt_events(&params)`,
  `decrypt_file(&params)` and so on. `set_signing_keys` takes a slice.
  Every `ChatCore` and `Chat` method takes `&self`, `set_reject_unverified`
  and `Chat::update_config` included.
- `set_identity` and `import_keys` take a params object, as every call with
  more than one input does: `SetIdentityParams` (`user_id`,
  `signing_key_version`) and `ImportKeysParams` (`keys`, optional
  `signing_key_version`), named the same in every binding, so the
  signing-key version of imported keys goes in `ImportKeysParams`.
  `set_identity` reports invalid input (Rust returns `Result`).
- Every user id is a string of digits, validated as `sender_id` is: the
  `set_identity` user id, `reply_to_sender_id`, the `user_id` of each public
  key, and group member, admin and pending-member ids. Anything else fails
  with an error naming the field. `reply_to_sender_id` is a string of digits
  in every binding.
- Every key version takes one form, a non-negative integer as a string of
  digits, as the X API returns it: signing-key versions (in `set_identity`,
  `import_keys`, per-call `signing_key_version`, and each public key's
  `public_key_version`) are checked as `conversation_key_version` is, and a
  negative `conversation_key_version` fails. Anything else fails with an
  error naming the field.
- Action signatures come in the shape a request's `action_signatures`
  carries them: `message_id`, `encoded_message_event_detail`, and the
  signature nested under `message_event_signature` (`signature`,
  `signature_version`, `public_key_version` and `signing_public_key`, your
  signing public key as `get_public_keys` returns it). Pass
  `action_signatures` through as returned; the signed payload stays inside
  the SDK. The `MessageEventSignature` type holds the nested signature in
  every binding. `prepare_message_delete` and
  `prepare_mark_conversation_read` return a `PreparedAction`
  (`action_signatures`, one entry); read the action's `message_id` from that
  entry.
- Every binding but Rust and the C ABI makes an outbound HTTPS request when
  a chat is created: `GET https://api.x.com/2/chat/features`, in the
  background (see Added). Allow it through egress filters for v1 sends;
  blocked, sends stay v0. A chat sends v0 until the answer arrives, so its
  first sends can be v0 while the switch is on. In Node before 20.16 a
  request still in flight can delay exit until it ends, at most 2 seconds.
- .NET params documents omit a field left `null`, so an unset optional
  resolves from the session identity or key cache and an unset required
  field fails with an error naming it. .NET: `EntityDescriptor` takes its
  start, end and type, and `UrlAttachmentImageDescriptor` its media hash
  key, size and filename, in its constructor, read-only, and an
  `AttachmentDescriptor` comes only from `Media`, `UrlCard` or `Post`, so
  no descriptor defaults a required value to `""` or `0`. JVM:
  `EntityDescriptor`, `UrlAttachmentImageDescriptor`, `SigningKeyEntry` and
  `PublicKeyInput` take their required values in their constructor and keep
  them in final fields (an image's `width` and `height` stay settable), and
  an `AttachmentDescriptor` comes only from `media`, `urlCard` or `post`,
  with final fields; a `null` required value throws `NullPointerException`.
- An entity of a type the SDK doesn't know, an empty one included, fails
  the call with an invalid-input error naming it (`Invalid entity_type
  'user_mention': pass url, mention, hashtag, cashtag, email, address or
  phone_number`) instead of being left out of the message, for a message's,
  a reply's, a reply preview's and an edit's entities. A file a message
  carries, a media attachment or a URL card's banner or favicon, with an
  empty `filename` or a `filesize_bytes` of 0 or less fails the send with an
  invalid-input error naming its media hash key, since receiving clients
  discard such a file, and so does one with a negative `width` or `height`.
  Entity offsets count bytes of the text's UTF-8 encoding, `start` inclusive
  and `end` exclusive: an entity whose offsets are negative, end before they
  start or run past the end of its text fails with an invalid-input error
  naming them (`Invalid entity offsets 3..8: end is past the end of the text,
  which is 7 bytes of UTF-8`); a reply preview's entities, which index the
  quoted message's text, are checked for all but the end. A URL card with an
  empty `url` and a post attachment with neither `rest_id` nor `post_url`
  fail the same way.
- JS typings declare only what the module exports: `Chat` and `ChatCrypto`
  aren't importable, and `FileEncryptor` / `FileDecryptor`, which the module
  returns but doesn't export, are interfaces. `ChatXdkError`,
  `ChatXdkErrorKind`, `ImportKeysParams` and `DecryptedEvent` are declared.

### Fixed

- A `verify` error names the input that failed, in every binding: the public
  key, which must be a base64 P-256 public key, or the signature, which must
  be the 64-byte raw signature. Verifying needs no loaded keys.
- JS: a millisecond field (`ttlMsec`, `currentTtlMsec`, `seenAtMsec`,
  `expiresAtMsec`) takes a finite number within the safe integer range. NaN,
  an infinity or a number past that range names no instant or duration, so
  the call throws an `Invalid <method> params` error rather than signing some
  other value. A fraction is truncated toward zero.
- The Python type stub names the byte parameter of `bytes_to_base64`,
  `bytes_to_hex`, `detect_mime_type` and `detect_image_dimensions` `bytes`,
  as the functions take it, so a type checker accepts exactly the keyword the
  call accepts.
- `chat-xdk-core`'s build script watches only the `CHAT_XDK_BINDINGS`
  variable it reads, so Cargo rebuilds the crate only when its sources or
  that variable change, in this repository and in crates that depend on it.

### Security

- `decrypt_events` reports as `latest_version`, the version to encrypt with,
  only a key change whose signature verified. A key change that doesn't
  verify still adds its key for decrypting, but can't set the version a
  chat encrypts under.
- JS: where `fetch` performs the feature-switch request, the body is read as
  a stream and capped while it streams; a body the runtime can't stream is
  never read whole, and the request fails.
- The JSON of a prepared conversation change leaves out its conversation
  key in the Go, JavaScript, JVM and .NET bindings, so a request body
  serialized from the returned object never carries the key. The key stays
  on the object (`ConversationKey` / `conversationKey`) for the app to keep.
  The X API requests that take a prepared change read its participant keys,
  key version and action signatures, never the key itself. Rust's
  `PreparedConversationChange` doesn't serialize the key, Python's result is
  a dict that `json.dumps` refuses to encode because the key is bytes, and
  the C ABI returns the key in its JSON result, as the only way it hands the
  key to the caller.
- Juicebox realm requests (setup, unlock, and key deletion) go out through an
  HTTP client in `chat-xdk-core` on reqwest 0.12.28, rustls 0.23.46 (ring),
  rustls-webpki 0.103.16, webpki-roots 1.0.11, and h2 0.4.20. juicebox-sdk's
  `reqwest` feature stays off, so the build does not include reqwest 0.11.27,
  rustls 0.21.12, rustls-webpki 0.101.7, webpki-roots 0.25.4, or h2 0.3.27.
  That closes CVE-2026-111943
  ([RUSTSEC-2026-0381](https://rustsec.org/advisories/RUSTSEC-2026-0381.html),
  [RUSTSEC-2026-0382](https://rustsec.org/advisories/RUSTSEC-2026-0382.html))
  along with
  [RUSTSEC-2026-0346](https://rustsec.org/advisories/RUSTSEC-2026-0346.html),
  [RUSTSEC-2026-0349](https://rustsec.org/advisories/RUSTSEC-2026-0349.html),
  and [RUSTSEC-2026-0258](https://rustsec.org/advisories/RUSTSEC-2026-0258.html).
  The client:
  - offers HTTP/2 and HTTP/1.1 over TLS (ALPN);
  - verifies servers against the Mozilla roots bundled in webpki-roots 1.0.11
    (rustls-webpki 0.103.16 rejects the distrusted emSign intermediate keys);
  - takes proxies from `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` / `NO_PROXY`,
    then from the system proxy settings on macOS and Windows;
  - sends `X-Juicebox-Version: <juicebox version>` and
    `User-Agent: juicebox_networking/<juicebox version>` on every request;
  - applies the timeout juicebox-sdk sets on each request, or 30 seconds when
    it sets none.
- `sign` refuses data that only the SDK signs: a payload recipients verify
  as a signed event (a message, conversation-key change, group or
  conversation-metadata change, delete or read receipt), and a P-256 public
  key, whose signature by the signing key binds it as an identity key. An
  app that signed data an attacker chose could otherwise hand back a
  signature that verifies as one of those events, such as a key change to a
  key the attacker knows. The refusal is the invalid-input error each
  binding raises for a bad argument (`SdkError::InvalidInput` in Rust,
  `InvalidInputError` in Python, a `ChatXdkError` of kind `invalidInput` in
  JS, an error of kind `ErrorKindInvalidInput` in Go, a `ChatXdkException`
  of kind `InvalidInput` / `INVALID_INPUT` in .NET and the JVM, and an
  `invalid_input` error document in the C ABI).
  Any other data signs to the same signature bytes, and the SDK signs events
  on its own path, which this does not touch.

[Unreleased]: https://github.com/xdevplatform/chat-xdk/compare/v0.7.7...HEAD
[0.7.7]: https://github.com/xdevplatform/chat-xdk/compare/v0.7.6...v0.7.7
[0.7.6]: https://github.com/xdevplatform/chat-xdk/compare/v0.7.5...v0.7.6
[0.7.5]: https://github.com/xdevplatform/chat-xdk/compare/v0.7.4...v0.7.5
[0.7.4]: https://github.com/xdevplatform/chat-xdk/compare/v0.7.3...v0.7.4
[0.7.3]: https://github.com/xdevplatform/chat-xdk/compare/v0.7.2...v0.7.3
[0.7.2]: https://github.com/xdevplatform/chat-xdk/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/xdevplatform/chat-xdk/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/xdevplatform/chat-xdk/compare/v0.5.2...v0.7.0
