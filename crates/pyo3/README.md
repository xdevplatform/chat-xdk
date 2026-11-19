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
chat.set_identity(SetIdentityParams("111", "1"))
chat.set_cache_keys(True)
chat.set_signing_keys([
    {
        "user_id": "111",
        "public_key_version": "1",
        "public_key": "BASE64...",
        "identity_public_key": "BASE64...",
        "identity_public_key_signature": "BASE64...",
    },
    {
        "user_id": "222",
        "public_key_version": "1",
        "public_key": "BASE64...",
        "identity_public_key": "BASE64...",
        "identity_public_key_signature": "BASE64...",
    },
])
# set_signing_keys replaces the stored keys; add_signing_keys adds to them,
# such as the keys of a member who joins later.
chat.add_signing_keys(new_member_signing_keys)

# Initial load — batch decrypt with automatic key extraction. Signing keys
# come from the store; the key of every key change that verifies goes into
# the cache.
result = chat.decrypt_events(DecryptEventsParams(raw_events))

for dm in result["events"]:
    if dm["event"]["type"] == "Message":
        print(dm["event"]["sender_id"], dm["event"]["content"]["text"])

# A key change verifies with the signing keys of the member who made it. One
# that did not verify is here, by its index in the batch; when its key was
# dropped, the messages under it are in result["errors"]. For
# "MissingSigningKey", add the public keys of change["sender_id"]
# (GET /2/users/{id}/public_keys) and decrypt again, or set a hook that
# does: see "Other users' public keys" below.
for index, change in result["unverified_key_changes"].items():
    print(index, change["reason"], change["sender_id"], change["key_dropped"])
# Key changes whose key this chat could not decrypt, and signing keys left
# out because their identity binding does not verify, are reported the same
# way: result["undecryptable_key_changes"], result["rejected_signing_keys"].

# The version to encrypt with: for a batch of one conversation,
# result["conversation_keys"]["latest_version"]; for any batch,
# result["conversation_keys"]["latest_versions"][conversation_id].

# Individual events after the initial load: the empty key map resolves from
# the cache and the unset signing keys from the store (pass either
# explicitly to override). A key change that verifies here is cached too.
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

### The key cache

While `set_cache_keys(True)` is on, the cache keeps, per conversation and by
key version, the key of every key change that verifies in `decrypt_events`
or `decrypt_event`, and of every key change this chat prepares
(`prepare_conversation_key_change`, `prepare_group_create`,
`prepare_group_members_change`, `prepare_group_members_remove`). A call that
leaves out its conversation key reads it from there: the encrypt methods and
the group title and description changes use the conversation's newest key,
the avatar change signs that key's version, and `decrypt_event`,
`decrypt_file` and `file_decryptor` use the key at the version the event
names. So the key map of `DecryptFileParams` and `FileDecryptorParams` and
the key version of `GroupAvatarChangeParams` can be left out; a value that is
passed is used as is.

```python
# media_hash_key goes by keyword when the key map before it is left out.
photo = chat.decrypt_file(
    DecryptFileParams(downloaded, file_event_b64, media_hash_key=file_hash_key)
)
avatar = chat.prepare_group_avatar_change(GroupAvatarChangeParams(conversation_id, avatar_url))
```

A prepared key is cached when the prepare call returns, before its request
is sent. If the X API rejects the request, no one else holds that key:
prepare the change again, or pass the key to encrypt with explicitly, until
a newer key change verifies.

### Other users' public keys

A chat uses other users' public keys (`GET /2/users/{id}/public_keys`) twice:
their signing keys verify the events they sign, and their identity keys are
what a new conversation key is encrypted to. Set a hook that fetches them,
and the chat asks it for the keys it lacks:

```python
def resolve_public_keys(user_ids):
    # User id -> the records in "data" of GET /2/users/{id}/public_keys.
    return {user_id: fetch_public_keys(user_id) for user_id in user_ids}

chat.set_resolve_public_keys(resolve_public_keys)

# No signing keys passed: the hook fetches the keys of the senders the batch
# names, the members who signed its key changes included.
result = chat.decrypt_events(DecryptEventsParams(raw_events))

# No public_keys passed: the hook fetches the keys of the members named.
created = chat.prepare_group_create(
    GroupCreateParams(conversation_id=group_id, member_ids=["111", "222"], admin_ids=["111"])
)
```

- `decrypt_events`, when it is passed no signing keys, calls the hook for
  the users whose keys its result was missing, adds the records the hook
  returns, and decrypts the batch once more.
- `prepare_conversation_key_change`, `prepare_group_create`,
  `prepare_group_members_change` and `prepare_group_members_remove`, when
  they are passed no `public_keys`, call the hook for the members who have
  no stored key.

The hook is called with a list of user ids and returns a dict from user id
to that user's records, leaving out a user it has nothing for. A record is
read as the X API sends it; other fields, such as `juicebox_config`, are
ignored. An exception the hook raises reaches the caller. Setting a hook
turns the key cache on. A lookup that brought no key is not repeated for a
minute.

`public_keys` is optional on the params of those four prepare methods. Left
out, the new key is encrypted to the stored public keys of the members the
params name:

| Params | Members |
| --- | --- |
| `GroupCreateParams` | `member_ids` and `admin_ids` |
| `GroupMembersChangeParams` | `current_member_ids` and `new_member_ids` |
| `GroupMembersRemoveParams` | `remaining_member_ids`: the members who stay, you included |
| `ConversationKeyChangeParams` | `member_ids`: every participant, you included. Without it, the two users of the one-to-one conversation `conversation_id` names |

A member with no stored key raises `InvalidInputError`, which names the user.

Without a hook, the same steps by hand:

```python
result = chat.decrypt_events(DecryptEventsParams(raw_events))
# result["missing_signing_keys"] maps the index of each event whose sender's
# signing key the call lacked to {"user_id", "public_key_version"}.
user_ids = chat.missing_public_keys(result)
if user_ids:
    chat.add_public_keys({user_id: fetch_public_keys(user_id) for user_id in user_ids})
    result = chat.decrypt_events(DecryptEventsParams(raw_events))
```

`missing_public_keys` lists each user once, in batch order, and does not
list a user again for a minute when the lookup brought no key.
`add_public_keys` adds to the stored signing keys, as `add_signing_keys`
does.

## API

See the **Python** column of the unified tables in [`docs/API.md`](../../docs/API.md) for the full method list, parameters, and return types. Files (media) are covered under [Files (Media)](../../docs/API.md#files-media).

## Network access

Each chat makes one kind of request itself: an anonymous
`GET https://api.x.com/2/chat/features` in the background, which reads the X
API's feature switches that pick the format the SDK sends in. A chat reads
them when it is created, again once `set_identity` gives it a sender, and
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
the format 0.5.x sends.

The request goes through the `http://` proxy that `HTTPS_PROXY` (or
`ALL_PROXY`) names, unless `NO_PROXY` exempts `api.x.com`. A process that
reaches the X API under another host name sets the `CHAT_XDK_API_BASE_URL`
environment variable to its base URL before it creates its chats: with
`https://api.example.com` there, the request goes to
`https://api.example.com/2/chat/features`. A process that
creates a chat, sends once and exits has no answer yet, so it sends v0: keep
one chat alive, or one process running, to follow the switch.

Requests run on daemon threads. A process that forks with `os.fork` (gunicorn
with `--preload`, a Celery prefork pool, `multiprocessing`) waits for the
requests under way, at most 2 seconds, and reads the switches again in the
child for the chats it inherited. uWSGI forks without telling Python and
runs no threads by default: set `enable-threads`, and create the chat in each
worker with `lazy-apps` or a post-fork hook.

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
