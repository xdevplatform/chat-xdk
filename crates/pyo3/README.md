# chat-xdk Python bindings

Python bindings for the X Chat SDK — encryption for X Direct Messages.

## Install

```bash
pip install chatxdk
```

The PyPI distribution is `chatxdk`; import it as `chat_xdk`.

## Architecture

```
Python (chat_xdk) → PyO3 → chat-xdk-core (Rust)
```

## Prerequisites

- **Python 3.10+**
- **Rust** (stable) and [maturin](https://www.maturin.rs/)

## Setup

From source (editable install):

```bash
cd crates/pyo3
pip install maturin
maturin develop
```

Release wheel:

```bash
maturin build --release
pip install target/wheels/*.whl
```

## Quick Start

```python
from chat_xdk import (
    Chat,
    DecryptEventParams,
    DecryptEventsParams,
    EncryptMessageParams,
    EncryptReactionParams,
    EncryptReplyParams,
    ImportKeysParams,
    SetIdentityParams,
)

chat = Chat(config_json)
chat.unlock("2580")
# Or load a local key blob + its registered version instead of Juicebox:
# chat.import_keys(ImportKeysParams(private_key_bytes, signing_key_version=registered_key_version))

# Set the session once: your user id + registered signing-key version,
# the opt-in conversation-key cache, and the participants' signing keys.
# Each signing-key entry must include the identity public key and its binding
# signature so the SDK can verify the signing key is authentic.
chat.set_identity(SetIdentityParams("111", "v1"))
chat.set_cache_keys(True)
chat.set_signing_keys([
    {
        "user_id": "111",
        "public_key_version": "v1",
        "public_key": "BASE64...",
        "identity_public_key": "BASE64...",
        "identity_public_key_signature": "BASE64...",
    },
    {
        "user_id": "222",
        "public_key_version": "v1",
        "public_key": "BASE64...",
        "identity_public_key": "BASE64...",
        "identity_public_key_signature": "BASE64...",
    },
])

# Initial load — batch decrypt with automatic key extraction. Signing keys
# come from the store; the verified conversation keys populate the cache.
result = chat.decrypt_events(DecryptEventsParams(raw_events))

for dm in result["messages"]:
    if dm["event"]["type"] == "Message":
        print(dm["event"]["sender_id"], dm["event"]["content"]["text"])

# Individual events after the initial load: the empty key map resolves from
# the cache and the unset signing keys from the store (pass either
# explicitly to override).
event = chat.decrypt_event(DecryptEventParams(new_event_b64, {}))

# Sending resolves the identity and conversation key from the session too.
payload = chat.encrypt_message(EncryptMessageParams(event["conversation_id"], "hi!"))
# Reply / react by handing back the raw event being answered.
reply = chat.encrypt_reply(EncryptReplyParams(event["conversation_id"], "pong", new_event_b64))
reaction = chat.encrypt_add_reaction(EncryptReactionParams(new_event_b64, "👍"))
```

Every method with a params object takes a params class (`EncryptMessageParams`,
`DecryptEventParams`, `EncryptFileParams`, …): required fields are
positional, optional ones are keywords, and every field is a read/write
attribute, so a params object can be built once and adjusted.

## API

See the **Python** column of the unified tables in [`docs/API.md`](../../docs/API.md) for the full method list, parameters, and return types. Files (media) are covered under [Files (Media)](../../docs/API.md#files-media).

## Network access

Each chat makes one kind of request itself: an anonymous
`GET https://api.x.com/2/chat/features` in the background, which reads the X
API's feature switches that pick the format the SDK sends in. It runs when the
chat is created, again once keys load, and every 5 minutes after that, and
chats asking for the same thing at once share one request. It carries no
credentials and never delays or fails a call; if it fails or is blocked,
sends stay in v0, the format 0.5.x sends. Call `chat.close()` when you're done with a chat to stop its requests; a garbage-collected chat stops too.

## Security limitations

The underlying protocol provides **no forward secrecy and no post-compromise
security**: compromise of an identity private key exposes all conversation
keys ever encrypted to that public key — and therefore all past and future
messages in those conversations. Key rotation does not retroactively protect
messages encrypted under a previous key. See
[docs/CRYPTO.md — Known Limitations](../../docs/CRYPTO.md#known-limitations).

## License

MIT — see the repo [`LICENSE`](../../LICENSE). Third-party notices:
[`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md).
