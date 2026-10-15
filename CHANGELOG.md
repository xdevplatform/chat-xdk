# Changelog

## Unreleased

### Breaking changes

#### Messages are sent under per-message keys

Every encrypted send (message, reply, reaction and edit) now encrypts its
contents under a key derived from the conversation key, the sender id and
the message id. It sets `contents_encryption_version` 1 on the
`MessageCreateEvent` and signs at signature version 10, which covers that
field. Other signed actions (conversation-key changes, group changes and
deletes) still sign at version 7.

Readers need per-message-key support to read these sends. chat-xdk 0.5.x
and earlier decrypt every message with the conversation key, so they return
a decryption error for each message, reply, reaction and edit this release
sends. Native clients that predate per-message keys cannot read them either.
Upgrade readers before senders.

`sender_id` must be the sender's numeric user id, and
`conversation_key_version` an integer as its key-change event carries it.
Other values are now rejected, since recipients derive the key from the
numeric id and look it up by the version.

#### Media is encrypted for the message that carries it

`encrypt_stream` and `stream_encryptor` take the message's id and the
file's position in its `attachments` as well as the conversation key, and
encrypt each file under that attachment's own key. A message with media
therefore takes its id first, from the new `new_message_id()`, and passes
the same id as `message_id` to `encrypt_message` or `encrypt_reply`. Both
require it when the attachments include media: a media attachment, or a URL
card with a banner or favicon image. A link card's banner and favicon both
take the card's position. The SDK writes each attachment's id into the
message, so recipients derive the same keys.

Media keys also derive from the sender's user id, taken from the session
identity: `encrypt_stream` and `stream_encryptor` require `set_identity`,
and `encrypt_message` and `encrypt_reply` reject a message with media whose
`sender_id` is another id. Errors name the value to fix when the message id
is not a lowercase hyphenated UUID or the position is outside 0–9.

The C ABI changes to match. `chat_xdk_new_message_id` is new,
`chat_xdk_encrypt_stream` takes the message id and attachment index, and
`chat_xdk_stream_encryptor_new` takes the chat handle, the conversation key,
the message id and the attachment index and returns a result, writing the
handle to an out-parameter (`ChatNative` on the JVM declares all three).

Migration — take the message id before encrypting the files, pass it with
each file's position, then send the message with it:

Rust

```rust
// Before
let encrypted = chat.encrypt_stream(&photo, &conversation_key)?;
let encryptor = chat.stream_encryptor(&conversation_key)?;
let params = EncryptMessageParams::new(conversation_id, "a photo");
// After
let message_id = chat.new_message_id();
let encrypted = chat.encrypt_stream(&photo, &conversation_key, &message_id, 0)?;
let encryptor = chat.stream_encryptor(&conversation_key, &message_id, 0)?;
let params = EncryptMessageParams::new(conversation_id, "a photo").with_message_id(message_id);
```

Python

```python
# Before
encrypted = chat.encrypt_stream(photo, conversation_key)
encryptor = chat.stream_encryptor(conversation_key)
payload = chat.encrypt_message(conversation_id, "a photo", attachments=attachments)
# After
message_id = chat.new_message_id()
encrypted = chat.encrypt_stream(photo, conversation_key, message_id, 0)
encryptor = chat.stream_encryptor(conversation_key, message_id, 0)
payload = chat.encrypt_message(conversation_id, "a photo", message_id=message_id, attachments=attachments)
```

JS / TypeScript

```js
// Before
const encrypted = chat.encryptStream(photo, conversationKey);
const encryptor = chat.streamEncryptor(conversationKey);
const payload = chat.encryptMessage({ conversationId, text: "a photo", attachments });
// After
const messageId = chat.newMessageId();
const encrypted = chat.encryptStream(photo, conversationKey, messageId, 0);
const encryptor = chat.streamEncryptor(conversationKey, messageId, 0);
const payload = chat.encryptMessage({ conversationId, text: "a photo", messageId, attachments });
```

Go

```go
// Before
encrypted, err := chat.EncryptStream(photo, conversationKey)
encryptor, err := chat.StreamEncryptor(conversationKey)
payload, err := chat.EncryptMessage(chatxdk.EncryptMessageParams{ConversationID: conversationID, Text: "a photo", Attachments: attachments})
// After
messageID, err := chat.NewMessageID()
encrypted, err := chat.EncryptStream(photo, conversationKey, messageID, 0)
encryptor, err := chat.StreamEncryptor(conversationKey, messageID, 0)
payload, err := chat.EncryptMessage(chatxdk.EncryptMessageParams{ConversationID: conversationID, Text: "a photo", MessageID: messageID, Attachments: attachments})
```

.NET (C#)

```csharp
// Before
var encrypted = chat.EncryptStream(photo, conversationKey);
using var encryptor = chat.StreamEncryptor(conversationKey);
var payload = chat.EncryptMessage(new EncryptMessageParams(conversationId, "a photo") { Attachments = attachments });
// After
var messageId = chat.NewMessageId();
var encrypted = chat.EncryptStream(photo, conversationKey, messageId, 0);
using var encryptor = chat.StreamEncryptor(conversationKey, messageId, 0);
var payload = chat.EncryptMessage(new EncryptMessageParams(conversationId, "a photo") { MessageId = messageId, Attachments = attachments });
```

JVM (Java)

```java
// Before
byte[] encrypted = chat.encryptStream(photo, conversationKey);
StreamEncryptor encryptor = chat.streamEncryptor(conversationKey);
EncryptMessageParams params = new EncryptMessageParams(conversationId, "a photo");
// After
String messageId = chat.newMessageId();
byte[] encrypted = chat.encryptStream(photo, conversationKey, messageId, 0);
StreamEncryptor encryptor = chat.streamEncryptor(conversationKey, messageId, 0);
EncryptMessageParams params = new EncryptMessageParams(conversationId, "a photo");
params.messageId = messageId;
```

See [docs/API.md — Streams (Media)](docs/API.md#streams-media).

#### Media decryption takes the message's event, key map and media hash key

`decrypt_stream` and `stream_decryptor` no longer take a conversation key.
They take the base64 event of the message that carries the media and the
conversation's key map — the same two arguments `decrypt_event` takes — plus
the media's hash key from the decrypted message: one of its media
attachments, a link card's banner or favicon (both listed in
`media_hashes`), or media quoted in its reply preview. The SDK finds that
attachment in the event and derives its key, including for messages that
encrypt each attachment under its own key. Errors say what to pass when the
key version is missing from the map, the media hash key is not in the event,
the event is not an encrypted message with media, or the bytes are wrong or
truncated.

The C ABI changes to match: `chat_xdk_decrypt_stream` takes the event, the
key-map JSON and the media hash key, and `chat_xdk_stream_decryptor_new`
takes the same and returns a result, writing the handle to an out-parameter
(`ChatNative` on the JVM declares both).

Migration — pass the event, the key map and the media hash key instead of
the key:

Rust

```rust
// Before
let plaintext = chat.decrypt_stream(&encrypted, &conversation_key)?;
let decryptor = chat.stream_decryptor(&conversation_key)?;
// After
let plaintext = chat.decrypt_stream(&encrypted, event_b64, &conversation_keys, media_hash_key)?;
let decryptor = chat.stream_decryptor(event_b64, &conversation_keys, media_hash_key)?;
```

Python

```python
# Before
plaintext = chat.decrypt_stream(encrypted, conversation_key)
decryptor = chat.stream_decryptor(conversation_key)
# After
plaintext = chat.decrypt_stream(encrypted, event_b64, conversation_keys, media_hash_key)
decryptor = chat.stream_decryptor(event_b64, conversation_keys, media_hash_key)
```

JS / TypeScript

```js
// Before
const plaintext = chat.decryptStream(encrypted, conversationKey);
const decryptor = chat.streamDecryptor(conversationKey);
// After
const plaintext = chat.decryptStream(encrypted, eventB64, conversationKeys, mediaHashKey);
const decryptor = chat.streamDecryptor(eventB64, conversationKeys, mediaHashKey);
```

Go

```go
// Before
plaintext, err := chat.DecryptStream(encrypted, conversationKey)
decryptor, err := chat.StreamDecryptor(conversationKey)
// After
plaintext, err := chat.DecryptStream(encrypted, eventB64, conversationKeys, mediaHashKey)
decryptor, err := chat.StreamDecryptor(eventB64, conversationKeys, mediaHashKey)
```

.NET (C#)

```csharp
// Before
var plaintext = chat.DecryptStream(encrypted, conversationKey);
using var decryptor = chat.StreamDecryptor(conversationKey);
// After
var plaintext = chat.DecryptStream(encrypted, eventB64, conversationKeys, mediaHashKey);
using var decryptor = chat.StreamDecryptor(eventB64, conversationKeys, mediaHashKey);
```

JVM (Java)

```java
// Before
byte[] plaintext = chat.decryptStream(encrypted, conversationKey);
StreamDecryptor decryptor = chat.streamDecryptor(conversationKey);
// After
byte[] plaintext = chat.decryptStream(encrypted, eventB64, conversationKeys, mediaHashKey);
StreamDecryptor decryptor = chat.streamDecryptor(eventB64, conversationKeys, mediaHashKey);
```

See [docs/API.md — Streams (Media)](docs/API.md#streams-media).
