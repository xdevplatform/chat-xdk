# chat-xdk example bot (Python)

An encrypted chat bot built on the **`chat_xdk`** Python binding. It
reads incoming DMs, decrypts them, generates a reply, encrypts + signs it, and
sends it back. Keys come from a local blob (or are generated + registered on
first run); conversation state is in memory.

## Layout

| File | Purpose |
|------|---------|
| [`chat_core.py`](chat_core.py) | All encryption logic — the only file that touches `chat_xdk`. |
| [`x_api.py`](x_api.py) | The X Chat API I/O layer (XDK `xdk` client). |
| [`bot.py`](bot.py) | The receive → decrypt → reply → encrypt → send loop. |
| [`multi_user.py`](multi_user.py) | Many signed-in users in one process: one chat per user, one shared public-key lookup. |
| [`run.py`](run.py) | Entrypoint: config, key load/generate, run. |
| [`register.py`](register.py) | One-time public-key registration (`python register.py --confirm`). |
| [`tests/test_chat_core.py`](tests/test_chat_core.py) | Offline test driving the real binding (no mocks). |
| [`tests/test_multi_user.py`](tests/test_multi_user.py) | Offline test of the multi-user helpers, on the real binding. |

## Prerequisites

- Python 3.10+
- Install the dependencies: `pip install -r requirements.txt`

To build the `chat_xdk` binding from this repo instead of a release:

```bash
cd ../../crates/pyo3 && maturin develop
```

## Run it

```bash
cp .env.example .env
# First run with no keys prints a registration payload + a private blob:
python run.py
# Paste CHAT_PRIVATE_KEYS_B64 into .env, register the public key with the X API,
# set CHAT_SIGNING_KEY_VERSION to the public_key_version it returns, set
# X_ACCESS_TOKEN + CHAT_CONVERSATION_ID, then re-run.
python run.py
```

The bot echoes messages back (`pong` for `ping`, otherwise `You said: …`).
Customize `generate_reply` in [`bot.py`](bot.py) to change the reply logic.

The bot keeps no list of other users' public keys. `ChatBot` gives the SDK a
hook (`ChatCore.fetch_public_keys_with`) that reads
`GET /2/users/{id}/public_keys` for one user. Every page of events goes through
`ChatCore.decrypt_batch`, key changes and messages together, and the SDK calls
the hook for the signing keys the page needs and does not hold, those of a
member who changed a group's key and sent no message included. It stores what
arrives, and the result's `missing_signing_keys` lists what did not.

## Many signed-in users in one process

A chat holds one user's private keys and signs as that user. A server with
several signed-in users keeps **one chat per user**, for all of that user's
conversations, and never one per conversation: the chat keeps its
conversation keys by conversation, and the public keys it has met by user id.

Other users' public keys are the same whichever chat asks, so the chats share
**one public-key hook**. [`multi_user.py`](multi_user.py) has both parts:

- `SharedPublicKeys(fetch, ttl_seconds=300.0)` has that hook as its `resolve`
  method. It keeps the answers of `GET /2/users/{id}/public_keys` by user id
  for the whole process, so two chats that meet the same user cost one
  request. Calls that ask for a user whose lookup is under way wait for that
  lookup. A lookup that fails is dropped, so the next call tries again. An
  answer is served for `ttl_seconds` (5 minutes unless you say otherwise) and
  then fetched again, so a key a user registers later is picked up.
- `UserChats` keeps one `ChatCore` per signed-in user, each with that hook:
  `chats.chat_for(user_id, private_keys_b64, signing_key_version)`.
  `chats.close(user_id)` signs a user out.

Both are safe to use from several threads.

```python
from multi_user import SharedPublicKeys, UserChats

public_keys = SharedPublicKeys(api.get_public_keys)
chats = UserChats(public_keys.resolve)

# On each request, for the signed-in user it belongs to:
chat = chats.chat_for(user_id, private_keys_b64, signing_key_version)
page = chat.decrypt_batch(events_b64)
```

With a hook set, add keys you already hold with the SDK's `add_signing_keys`
or `add_public_keys`. `set_signing_keys` replaces every stored key, the
fetched ones included, and the chat then waits a minute before it asks the
hook for them again.

## Registering your key (one-time)

Before a bot can send or receive, its public key must be registered on the
account. This is a **rate-limited** write (only a few per 24h), so run it
**once**:

```bash
X_ACCESS_TOKEN=... python register.py --confirm
```

It generates the identity, saves the private-key blob under `state/` (mode
600) **before** the network call, then POSTs the public key. If it is
interrupted, re-running resumes the same saved identity rather than minting a
new one; if the key is already on the account it adopts that version and skips
the POST; on HTTP 429 it stops and tells you when the window resets rather than
retrying. Set `CHAT_PIN` to additionally back the keys up in Juicebox
(best-effort — the local blob is already saved). When it finishes it prints the
`CHAT_PRIVATE_KEYS_B64` and `CHAT_SIGNING_KEY_VERSION` lines to paste into
`.env`. `state/` is gitignored — never commit key blobs.

## Test it (offline, no credentials)

```bash
PYTHONPATH=../../crates/pyo3/python:. python3 -m unittest discover -s tests -v
```

The test imports the fixture private keys, checks the binding reproduces the
committed public-key/signature vectors, and runs a real encrypt → decrypt
round-trip plus a conversation-key ECIES round-trip. It also decrypts a page
whose key change was signed by a member who sent no message, once the SDK has
fetched that member's keys through the hook. The multi-user test signs two
users in, and checks that their chats fetch the keys of a user they both meet
once, that one chat serves two conversations, and that the shared lookup
retries a failure and fetches again after its TTL.

## License

MIT
