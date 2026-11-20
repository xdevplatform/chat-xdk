"""ChatBot example bot.

Flow (encrypt on send, decrypt on receive):

  1. Load keys (import a private-key blob, or generate + register a new one).
  2. On startup, batch-decrypt the conversation backlog (``decrypt_events``)
     to seed the conversation-key cache.
  3. Poll for new events; batch-decrypt each page, its key changes and its
     data events together (``decrypt_events``).
  4. For each incoming text message, generate a reply, encrypt + sign it,
     and send it back via the X Chat API.

The SDK fetches the public keys it lacks through a hook the bot sets once:
the bot keeps no signing keys of its own.

One bot serves one signed-in user, in any number of conversations. A process
with several signed-in users keeps one chat per user and gives each the same
public-key resolver (see ``multi_user.py``).

Conversation state is held in memory, one entry per conversation.
Run it with ``python run.py`` after filling in ``.env``.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from chat_core import ChatCore, message_text
from x_api import XChatClient

logger = logging.getLogger("chatbot")


def generate_reply(text: str) -> str:
    """Turn an incoming message into a reply (a simple echo)."""
    text = text.strip()
    if text.lower() in {"!ping", "ping"}:
        return "pong"
    return f"You said: {text}"


@dataclass
class ConversationState:
    """In-memory state for one conversation. Its conversation keys live in
    the SDK's cache."""

    seen_event_ids: set[str] = field(default_factory=set)
    pagination_token: str | None = None


class ChatBot:
    def __init__(self, core: ChatCore, api: XChatClient, bot_user_id: str) -> None:
        self.core = core
        self.api = api
        self.bot_user_id = bot_user_id
        self.state: dict[str, ConversationState] = {}
        # One-time session setup: the bot signs as itself everywhere, and the
        # SDK caches each conversation's latest verified key so the encrypt
        # calls below need no key arguments.
        self.core.set_identity(bot_user_id)
        self.core.set_cache_keys(True)
        # The SDK fetches the public keys it lacks through the API client:
        # the signing keys of whoever signed a page's events, the members who
        # made its key changes included. The decrypt calls need no
        # signing_keys argument.
        self.core.fetch_public_keys_with(api.get_public_keys)

    def _state(self, conversation_id: str) -> ConversationState:
        return self.state.setdefault(conversation_id, ConversationState())

    def _decrypt_page(self, conversation_id: str, page: dict[str, Any]) -> dict[str, Any]:
        """Batch-decrypt one page of events and log what it could not use.

        KeyChange events arrive in meta.conversation_key_events, separate
        from data. They carry the conversation keys the messages decrypt
        under, so they go into the same decrypt_events batch as the data
        events.
        """
        key_events_b64 = page.get("meta", {}).get("conversation_key_events") or []
        events_b64 = list(key_events_b64) + [
            e["encoded_event"] for e in page.get("data") or [] if e.get("encoded_event")
        ]
        batch = self.core.decrypt_batch(events_b64)
        for index, key in batch["missing_signing_keys"].items():
            logger.warning(
                "signing_key_missing conv=%s event=%s user=%s version=%s",
                conversation_id,
                index,
                key["user_id"],
                key["public_key_version"],
            )
        for index, change in batch["unverified_key_changes"].items():
            logger.warning(
                "key_change_unverified conv=%s event=%s reason=%s signer=%s key_dropped=%s",
                conversation_id,
                index,
                change["reason"],
                change["sender_id"],
                change["key_dropped"],
            )
        for index, change in batch["undecryptable_key_changes"].items():
            logger.warning(
                "key_change_undecryptable conv=%s event=%s reason=%s",
                conversation_id,
                index,
                change["reason"],
            )
        for index, key in batch["rejected_signing_keys"].items():
            logger.warning(
                "signing_key_rejected index=%s user=%s version=%s",
                index,
                key["user_id"],
                key["public_key_version"],
            )
        return batch

    def load_backlog(self, conversation_id: str) -> None:
        """Initial load: batch-decrypt the backlog (decrypt_events path),
        which fills the SDK's conversation-key cache from its key changes."""
        st = self._state(conversation_id)
        page = self.api.get_events(conversation_id, max_results=100)
        batch = self._decrypt_page(conversation_id, page)
        st.pagination_token = page.get("meta", {}).get("next_token")
        logger.info(
            "backlog_loaded conv=%s messages=%d keys=%d",
            conversation_id,
            len(batch["events"]),
            len(batch["conversation_keys"].get("keys") or {}),
        )

    def poll_once(self, conversation_id: str) -> None:
        """Fetch a page of new events, batch-decrypt it (decrypt_events
        path), and reply to each new incoming message it holds."""
        st = self._state(conversation_id)
        page = self.api.get_events(
            conversation_id, max_results=50, pagination_token=st.pagination_token
        )
        batch = self._decrypt_page(conversation_id, page)
        for index, error in batch["errors"].items():
            logger.warning("decrypt_failed conv=%s event=%s err=%s", conversation_id, index, error)

        for decrypted in batch["events"]:
            self._maybe_reply(conversation_id, decrypted["event"])

        st.pagination_token = page.get("meta", {}).get("next_token") or st.pagination_token

    def _maybe_reply(self, conversation_id: str, event: dict[str, Any]) -> None:
        event_id = str(event.get("id") or "")
        sender_id = str(event.get("sender_id") or "")
        st = self._state(conversation_id)

        if not event_id or event_id in st.seen_event_ids:
            return
        st.seen_event_ids.add(event_id)
        if sender_id == self.bot_user_id:
            return

        text = message_text(event)
        if not text:
            return

        # The message signature covers the conversation_id, so sign with the
        # canonical id carried inside the event (the X API uses a different
        # separator in its URL paths than the form embedded in events).
        reply_conv_id = str(event.get("conversation_id") or conversation_id)
        reply = generate_reply(text)
        try:
            # Short form: the sender comes from set_identity, the conversation
            # key from the SDK's verified-key cache.
            body = self.core.encrypt_reply(conversation_id=reply_conv_id, text=reply)
        except ValueError:
            logger.warning("no_conversation_key conv=%s", conversation_id)
            return
        self.api.send_message(reply_conv_id, body)
        logger.info("reply_sent conv=%s len=%d", reply_conv_id, len(reply))

    def run(self, conversation_id: str, poll_interval: float = 3.0) -> None:
        self.load_backlog(conversation_id)
        logger.info("bot_running conv=%s — polling every %.1fs", conversation_id, poll_interval)
        while True:
            try:
                self.poll_once(conversation_id)
            except Exception:
                logger.exception("poll_error conv=%s", conversation_id)
            time.sleep(poll_interval)
