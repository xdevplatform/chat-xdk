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
from chat_xdk import Chat

chat = Chat(config_json)
chat.unlock("2580")
# Or load a local key blob + its registered version instead of Juicebox:
# chat.import_keys(private_key_bytes, version=registered_key_version)

# Set the session once: your user id + registered signing-key version,
# the opt-in conversation-key cache, and the participants' signing keys.
# Each signing-key entry must include the identity public key and its binding
# signature so the SDK can verify the signing key is authentic.
chat.set_identity("111", "v1")
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
result = chat.decrypt_events(raw_events)

for dm in result["messages"]:
    if dm["event"]["type"] == "Message":
        print(dm["event"]["sender_id"], dm["event"]["content"]["text"])

# Individual events after the initial load: conversation keys resolve from
# the cache and signing keys from the store (pass either explicitly to
# override).
event = chat.decrypt_event(new_event_b64)

# Sending resolves the identity and conversation key from the session too.
payload = chat.encrypt_message(event["conversation_id"], "hi!")
# Reply / react by handing back the raw event being answered.
reply = chat.encrypt_reply(event["conversation_id"], "pong", new_event_b64)
reaction = chat.encrypt_add_reaction(new_event_b64, "👍")
```

## API

See the **Python** column of the unified tables in [`docs/API.md`](../../docs/API.md) for the full method list, parameters, and return types.

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
