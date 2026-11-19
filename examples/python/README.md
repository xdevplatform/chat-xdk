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
| [`run.py`](run.py) | Entrypoint: config, key load/generate, run. |
| [`register.py`](register.py) | One-time public-key registration (`python register.py --confirm`). |
| [`tests/test_chat_core.py`](tests/test_chat_core.py) | Offline test driving the real binding (no mocks). |

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
fetched that member's keys through the hook.

## License

MIT
