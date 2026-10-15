# Changelog

## Unreleased

### Breaking changes

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
truncated. Encryption (`encrypt_stream`, `stream_encryptor`) is unchanged.

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
