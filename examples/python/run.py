"""Entrypoint for the ChatBot example bot.

Reads configuration from the environment (see ``.env.example``), loads or
generates the bot's keys, and runs the receive -> decrypt -> reply -> encrypt
-> send loop against one conversation.

    python run.py
"""

from __future__ import annotations

import json
import logging
import os
import sys

from bot import ChatBot
from chat_core import ChatCore
from x_api import XChatClient


def _load_dotenv(path: str = ".env") -> None:
    """Tiny .env loader so the example has no extra dependencies."""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    _load_dotenv()

    access_token = os.environ.get("X_ACCESS_TOKEN")
    conversation_id = os.environ.get("CHAT_CONVERSATION_ID")
    private_keys_b64 = os.environ.get("CHAT_PRIVATE_KEYS_B64")
    signing_key_version = os.environ.get("CHAT_SIGNING_KEY_VERSION", "1")
    pin = os.environ.get("CHAT_PIN")

    core = ChatCore()

    if pin and access_token:
        # Production key storage: recover the private keys from Juicebox.
        api = XChatClient(access_token)
        bot_id = os.environ.get("CHAT_BOT_USER_ID") or api.get_my_user_id()
        juicebox_config, version = api.get_juicebox_config(bot_id)
        core.unlock(juicebox_config, pin, version)
    elif private_keys_b64:
        core.load_keys(private_keys_b64, signing_key_version)
    else:
        # First run: generate keys, print the registration payload to POST to
        # the X API, and the private blob to save in CHAT_PRIVATE_KEYS_B64.
        info = core.generate_and_register()
        print("No CHAT_PRIVATE_KEYS_B64 set — generated a new identity.\n")
        print("1) Register this public key with the X API (one-time provisioning):")
        print(json.dumps(info["registration"], indent=2))
        print("\n2) Save the private key in your .env so the bot reuses the identity:")
        print(f"CHAT_PRIVATE_KEYS_B64={info['private_keys_b64']}")
        print("\nThen re-run.")
        sys.exit(0)

    if not access_token or not conversation_id:
        print("Set X_ACCESS_TOKEN and CHAT_CONVERSATION_ID in .env to run the bot.")
        sys.exit(1)

    api = XChatClient(access_token)
    bot_user_id = os.environ.get("CHAT_BOT_USER_ID") or api.get_my_user_id()

    bot = ChatBot(core, api, bot_user_id)
    bot.run(conversation_id)


if __name__ == "__main__":
    main()
