"""Crypto core for the chatbot example bot.

A thin, network-free wrapper around the ``chat_xdk`` binding. Everything
that touches the SDK lives here so it can be unit-tested directly (see
``tests/test_chat_core.py``). The bot's I/O layer (``x_api.py``) and main loop
(``bot.py``) call into this module.

The four core feature touchpoints of the chat-xdk flow are all here:

* key management        -> ``load_keys`` / ``generate_and_register``
* conversation keys     -> ``prepare_conversation_key_change`` / ``decrypt_conversation_key``
* message encryption    -> ``encrypt_reply``
* event decryption      -> ``decrypt_batch`` (decrypt_events) and
                           ``decrypt_one`` (decrypt_event)
"""

from __future__ import annotations

import base64
from typing import Any

from chat_xdk import Chat


def _b64decode(data: str) -> bytes:
    return base64.b64decode(data)


def _as_dict(obj: Any) -> dict[str, Any]:
    """Decrypted events come back as native objects; normalise to a dict."""
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    try:
        return dict(obj)
    except Exception:
        return {}


class ChatCore:
    """Wraps a single unlocked ``chat_xdk.Chat`` instance for one bot identity."""

    def __init__(self, chat: Chat | None = None) -> None:
        self.chat = chat or Chat()
        # The version the X API reports for our registered public key. Set after
        # loading/generating keys; used as the signing key version when sending.
        self.signing_key_version: str = "1"

    # -- Key management -----------------------------------------------------

    def load_keys(self, private_keys_b64: str, signing_key_version: str = "1") -> None:
        """Import an existing private-key blob (identity[+signing]) and unlock.

        ``private_keys_b64`` is the base64 of 32 bytes (identity only) or 64
        bytes (identity + signing) — the same blob ``export_keys`` produces.

        This is the quickstart key-storage path. For production key storage see
        ``unlock`` / ``setup`` (Juicebox).
        """
        self.chat.import_keys(_b64decode(private_keys_b64), version=signing_key_version)
        self.signing_key_version = signing_key_version

    def unlock(self, juicebox_config_json: str, pin: str, signing_key_version: str = "1") -> None:
        """Production key storage: recover the private keys from Juicebox.

        Use this instead of ``load_keys`` when keys are stored in Juicebox rather
        than a local blob. ``juicebox_config_json`` comes from the X API
        public-keys response; ``pin`` is the user's recovery PIN. Nothing secret
        is written to disk.
        """
        self.chat = Chat(juicebox_config_json)
        self.chat.unlock(pin)
        self.signing_key_version = signing_key_version

    def set_identity(self, user_id: str) -> None:
        """Set the session identity once the bot's own user id is known.

        Every signed action after this resolves its sender and signing-key
        version from the session, so the encrypt calls stay short.
        """
        self.chat.set_identity(user_id, self.signing_key_version)

    def set_signing_keys(self, signing_keys: list[dict[str, str]]) -> None:
        """Store participants' signing keys for decrypt calls that omit them.

        Each call replaces the previous set, so pass the full known roster.
        """
        self.chat.set_signing_keys(signing_keys)

    def set_cache_keys(self, enabled: bool) -> None:
        """Opt in to the SDK's verified conversation-key cache.

        While enabled, ``decrypt_batch`` feeds the cache and the encrypt
        methods can omit the conversation key pair entirely.
        """
        self.chat.set_cache_keys(enabled)

    def setup(self, juicebox_config_json: str, pin: str) -> dict[str, Any]:
        """First-time Juicebox provisioning: generate keys and store them under a PIN.

        Returns the registration payload to register the public key with the X
        API (see ``generate_and_register``). After this, future sessions recover
        the keys with ``unlock`` — no local blob needed.
        """
        self.chat = Chat(juicebox_config_json)
        payload = self.chat.generate_keypairs()
        self.chat.setup(pin)
        return {
            "public_key": payload.public_key.public_key,
            "signing_public_key": payload.public_key.signing_public_key,
            "identity_public_key_signature": payload.public_key.identity_public_key_signature,
            "registration_method": payload.public_key.registration_method,
        }

    def generate_and_register(self) -> dict[str, Any]:
        """Generate fresh keypairs for a brand-new bot identity.

        Returns the registration payload to POST to ``POST /2/users/public_keys``
        and the exported private-key blob to persist locally (e.g. in ``.env``).
        """
        payload = self.chat.generate_keypairs()
        exported = self.chat.export_keys()
        return {
            "registration": {
                "public_key": payload.public_key.public_key,
                "signing_public_key": payload.public_key.signing_public_key,
                "identity_public_key_signature": payload.public_key.identity_public_key_signature,
                "registration_method": payload.public_key.registration_method,
            },
            "version": payload.version,
            "private_keys_b64": base64.b64encode(bytes(exported)).decode("ascii")
            if exported
            else "",
        }

    def public_keys(self) -> dict[str, str]:
        keys = self.chat.get_public_keys()
        return {"identity": keys.identity, "signing": keys.signing}

    # -- Conversation keys --------------------------------------------------

    def prepare_conversation_key_change(
        self,
        public_keys: list[dict[str, str]],
        conversation_id: str | None = None,
    ) -> dict[str, Any]:
        """Generate, encrypt, and sign a conversation-key change.

        ``public_keys`` is the flat list returned by the X API's public-keys
        endpoint: ``[{"user_id", "public_key", "key_version"}, ...]``. Omit
        ``conversation_id`` for a one-to-one to derive it; pass it for a group.
        The change is signed with the ``set_identity`` session identity.
        """
        return self.chat.prepare_conversation_key_change(
            public_keys, conversation_id=conversation_id
        )

    def decrypt_conversation_key(self, encrypted_key_b64: str) -> bytes:
        """ECIES-decrypt one conversation key with our identity private key."""
        return self.chat.decrypt_conversation_key(encrypted_key_b64)

    # -- Decryption: the two paths -----------------------------------------

    def decrypt_batch(
        self,
        events_b64: list[str],
        signing_keys: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        """Batch path — used on initial conversation load.

        ``decrypt_events`` extracts conversation keys from any KeyChange events
        in the batch, then decrypts every message. Returns the decrypted
        messages plus the conversation-key cache to reuse for single events.
        Omit ``signing_keys`` to verify with the ``set_signing_keys`` store.
        """
        result = self.chat.decrypt_events(events_b64, signing_keys)
        messages = [
            {"event": _as_dict(m["event"]), "original_b64": m.get("original_b64")}
            for m in result.get("messages", [])
        ]
        return {
            "messages": messages,
            "conversation_keys": result.get("conversation_keys", {}),
            "errors": result.get("errors", {}),
        }

    def decrypt_one(
        self,
        event_b64: str,
        conversation_keys: dict[str, bytes],
        signing_keys: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        """Single-event path. ``conversation_keys`` is the cache from ``decrypt_batch``.

        Omit ``signing_keys`` to verify with the ``set_signing_keys`` store.
        """
        return _as_dict(self.chat.decrypt_event(event_b64, conversation_keys, signing_keys))

    # -- Message encryption -------------------------------------------------

    def encrypt_reply(
        self,
        *,
        conversation_id: str,
        text: str,
        conversation_key: bytes | None = None,
        conversation_key_version: str | None = None,
        reply_to_event: str | None = None,
        reply_to_sequence_id: str | None = None,
        entities: list[tuple[int, int, str]] | None = None,
        attachments: list[dict[str, Any]] | None = None,
        ttl_msec: int | None = None,
    ) -> dict[str, str]:
        """Encrypt + sign a message, returning fields ready for the X API send.

        Without a reply target this sends a fresh message via
        ``encrypt_message``; with ``reply_to_event`` (the raw encoded event
        being answered — preferred, the SDK derives and embeds the validated
        preview) or ``reply_to_sequence_id``, the SDK's ``encrypt_reply``
        builds a *threaded* reply. Omit the conversation key pair to resolve
        it from the SDK's verified-key cache (``set_cache_keys``).
        ``entities`` are ``(start, end, type)`` byte ranges; ``attachments``
        are attachment descriptors (e.g. a media reference); ``ttl_msec``
        makes the message disappear after the given lifetime. Signed with the
        ``set_identity`` session identity.
        """
        if reply_to_event is None and reply_to_sequence_id is None:
            payload = self.chat.encrypt_message(
                conversation_id,
                text,
                conversation_key=conversation_key,
                conversation_key_version=conversation_key_version,
                entities=entities,
                attachments=attachments,
                ttl_msec=ttl_msec,
            )
        else:
            payload = self.chat.encrypt_reply(
                conversation_id,
                text,
                reply_to_event,
                reply_to_sequence_id=reply_to_sequence_id,
                conversation_key=conversation_key,
                conversation_key_version=conversation_key_version,
                entities=entities,
                attachments=attachments,
                ttl_msec=ttl_msec,
            )
        return {
            # The SDK generates the message id and returns it in the payload.
            "message_id": payload.message_id,
            "encoded_message_create_event": payload.encrypted_content,
            "encoded_message_event_signature": payload.encoded_event_signature,
        }

    def encrypt_reaction(
        self,
        *,
        add: bool,
        conversation_id: str,
        target_message_sequence_id: str,
        emoji: str,
        conversation_key: bytes,
        conversation_key_version: str,
    ) -> dict[str, str]:
        """Encrypt + sign a reaction add/remove targeting a message sequence id.

        Signed with the ``set_identity`` session identity.
        """
        method = self.chat.encrypt_add_reaction if add else self.chat.encrypt_remove_reaction
        payload = method(
            None,
            emoji,
            conversation_id=conversation_id,
            target_message_sequence_id=target_message_sequence_id,
            conversation_key=conversation_key,
            conversation_key_version=conversation_key_version,
        )
        return {
            # The SDK generates the message id and returns it in the payload.
            "message_id": payload.message_id,
            "encoded_message_create_event": payload.encrypted_content,
            "encoded_message_event_signature": payload.encoded_event_signature,
        }

    # -- Group management -----------------------------------------------------

    def prepare_group_create(
        self,
        public_keys: list[dict[str, str]],
        conversation_id: str,
        member_ids: list[str],
        admin_ids: list[str],
    ) -> dict[str, Any]:
        """Prepare a group creation: fresh key + the two required signatures.

        Signed with the ``set_identity`` session identity.
        """
        return self.chat.prepare_group_create(
            public_keys,
            conversation_id,
            member_ids,
            admin_ids,
        )

    def prepare_group_members_change(
        self,
        public_keys: list[dict[str, str]],
        conversation_id: str,
        new_member_ids: list[str],
        current_member_ids: list[str],
        current_admin_ids: list[str],
    ) -> dict[str, Any]:
        """Prepare a member add: rotated key + the two required signatures.

        Signed with the ``set_identity`` session identity.
        """
        return self.chat.prepare_group_members_change(
            public_keys,
            conversation_id,
            new_member_ids,
            current_member_ids,
            current_admin_ids,
            [],
        )

    # -- Media streaming -----------------------------------------------------

    MEDIA_CHUNK = 1024 * 1024

    def encrypt_media(self, plaintext: bytes, conversation_key: bytes) -> bytes:
        """Encrypt a media blob with the incremental stream API.

        Feeding fixed-size chunks through ``push`` keeps memory bounded no
        matter how large the file is; ``finish`` emits the final frame that
        seals the stream (decryption fails without it).
        """
        enc = self.chat.stream_encryptor(conversation_key)
        out = bytearray()
        for offset in range(0, len(plaintext), self.MEDIA_CHUNK):
            out += enc.push(plaintext[offset : offset + self.MEDIA_CHUNK])
        out += enc.finish()
        return bytes(out)

    def decrypt_media(self, ciphertext: bytes, conversation_key: bytes) -> bytes:
        """Decrypt a media blob with the incremental stream API.

        ``finish`` raises if the stream was truncated, so plaintext from
        ``push`` must not be treated as complete until it succeeds.
        """
        dec = self.chat.stream_decryptor(conversation_key)
        out = bytearray()
        for offset in range(0, len(ciphertext), self.MEDIA_CHUNK):
            out += dec.push(ciphertext[offset : offset + self.MEDIA_CHUNK])
        out += dec.finish()
        return bytes(out)

    # -- Generic helpers (handy for metadata + tests) -----------------------

    def encrypt(self, plaintext: str, conversation_key: bytes) -> str:
        return self.chat.encrypt(plaintext, conversation_key)

    def decrypt(self, ciphertext_b64: str, conversation_key: bytes) -> str:
        return self.chat.decrypt(ciphertext_b64, conversation_key)


def message_text(event: dict[str, Any]) -> str | None:
    """Pull the plain text out of a decrypted Message event, or None."""
    if event.get("type") != "Message":
        return None
    content = event.get("content") or {}
    return content.get("text")


def prep_to_request(prep: dict[str, Any], signing_public_key: str) -> dict[str, Any]:
    """Map a prepared conversation change into the X API request shape.

    Works for 1:1 key changes (one signature) and group create / member add
    (two signatures). ``signing_public_key`` is the sender's own signing key,
    which the API expects alongside each signature.
    """
    body: dict[str, Any] = {
        "conversation_key_version": prep["conversation_key_version"],
        "conversation_participant_keys": [
            {
                "user_id": str(pk["user_id"]),
                "encrypted_conversation_key": pk["encrypted_key"],
                "public_key_version": str(pk["public_key_version"]),
            }
            for pk in prep["participant_keys"]
        ],
        "action_signatures": [
            {
                "message_id": sig["message_id"],
                "encoded_message_event_detail": sig["encoded_message_event_detail"],
                "message_event_signature": {
                    "signature": sig["signature"],
                    "signature_version": sig["signature_version"],
                    "public_key_version": sig["public_key_version"],
                    "signing_public_key": signing_public_key,
                },
                **(
                    {"signature_payload": sig["signature_payload"]}
                    if sig.get("signature_payload")
                    else {}
                ),
            }
            for sig in prep["action_signatures"]
        ],
    }
    return body
