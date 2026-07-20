"""ChatBot example bot.

Flow (encrypt on send, decrypt on receive):

  1. Load keys (import a private-key blob, or generate + register a new one).
  2. On startup, batch-decrypt the conversation backlog (``decrypt_events``)
     to seed the conversation-key cache.
  3. Poll for new events; decrypt each one individually (``decrypt_event``).
  4. For each incoming text message, generate a reply, encrypt + sign it,
     and send it back via the X Chat API.

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
    """In-memory state for one conversation."""

    conversation_keys: dict[str, bytes] = field(default_factory=dict)
    latest_key_version: str | None = None
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
        # Signing keys accumulate here and are pushed to the SDK's store, so
        # the decrypt calls need no signing_keys argument either.
        self._signing_keys: list[dict[str, str]] = []
        self._known_senders: set[str] = set()

    def _state(self, conversation_id: str) -> ConversationState:
        return self.state.setdefault(conversation_id, ConversationState())

    def _register_signing_keys(self, events: list[dict[str, Any]]) -> None:
        """Fetch new senders' public keys into the SDK's signing-key store.

        Pulled from the X API per unique sender. Each entry must carry the
        identity public key + its binding signature for verification. The
        store is replaced wholesale, so the accumulated roster is re-sent.
        """
        senders = {
            str(e.get("sender_id"))
            for e in events
            if e.get("sender_id") and str(e.get("sender_id")) != self.bot_user_id
        } - self._known_senders
        for sender_id in senders:
            try:
                for pk in self.api.get_public_keys(sender_id):
                    self._signing_keys.append(
                        {
                            "user_id": sender_id,
                            "public_key_version": str(pk.get("public_key_version") or ""),
                            "public_key": pk.get("signing_public_key") or "",
                            "identity_public_key": pk.get("public_key") or "",
                            "identity_public_key_signature": pk.get(
                                "identity_public_key_signature"
                            )
                            or "",
                        }
                    )
                self._known_senders.add(sender_id)
            except Exception:
                logger.warning("public_keys_fetch_failed sender=%s", sender_id)
        if senders:
            self.core.set_signing_keys(self._signing_keys)

    def load_backlog(self, conversation_id: str) -> None:
        """Initial load: batch-decrypt the backlog (decrypt_events path)."""
        st = self._state(conversation_id)
        page = self.api.get_events(conversation_id, max_results=100)
        raw = page.get("data") or []
        events_b64 = [e["encoded_event"] for e in raw if e.get("encoded_event")]
        self._register_signing_keys(raw)

        batch = self.core.decrypt_batch(events_b64)
        keys = batch["conversation_keys"].get("keys") or {}
        st.conversation_keys.update(keys)
        st.latest_key_version = batch["conversation_keys"].get("latest_version")
        st.pagination_token = page.get("meta", {}).get("next_token")
        logger.info(
            "backlog_loaded conv=%s messages=%d keys=%d",
            conversation_id,
            len(batch["messages"]),
            len(keys),
        )

    def poll_once(self, conversation_id: str) -> None:
        """Fetch new events and reply to each new incoming message.

        Uses the single-event decrypt path (decrypt_event) with the cached
        conversation keys from the initial backlog load.
        """
        st = self._state(conversation_id)
        page = self.api.get_events(
            conversation_id, max_results=50, pagination_token=st.pagination_token
        )
        raw = page.get("data") or []
        self._register_signing_keys(raw)

        for item in raw:
            event_b64 = item.get("encoded_event")
            if not event_b64:
                continue
            event = self.core.decrypt_one(event_b64, st.conversation_keys)

            # A KeyChange rotates the conversation key. Route it through the
            # batch path: that verifies the change, feeds the SDK's key cache
            # (used by the encrypt calls), and returns the decrypted key for
            # this loop's own decrypt_one lookups.
            if event.get("type") == "KeyChange":
                rotated = self.core.decrypt_batch([event_b64])
                st.conversation_keys.update(rotated["conversation_keys"].get("keys") or {})
                st.latest_key_version = (
                    rotated["conversation_keys"].get("latest_version")
                    or st.latest_key_version
                )
                continue

            self._maybe_reply(conversation_id, event)

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
