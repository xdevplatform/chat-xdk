"""Crypto core for the chatbot example bot.

A thin, network-free wrapper around the ``chat_xdk`` binding. Everything
that touches the SDK lives here so it can be unit-tested directly (see
``tests/test_chat_core.py``). The bot's I/O layer (``x_api.py``) and main loop
(``bot.py``) call into this module.

The four core feature touchpoints of the chat-xdk flow are all here:

* key management        -> ``load_keys`` / ``generate_and_register``
* conversation keys     -> ``prepare_conversation_key_change`` / ``decrypt_conversation_key``
* message encryption    -> ``encrypt_reply``, then ``encrypt_media`` for its files
* event decryption      -> ``decrypt_batch`` (decrypt_events) and
                           ``decrypt_one`` (decrypt_event)

Other users' public keys reach the SDK through one hook,
``fetch_public_keys_with``: the SDK calls it for the keys a decrypt or a key
change lacks, and stores what it returns.
"""

from __future__ import annotations

import base64
import logging
from typing import Any, Callable

from chat_xdk import (
    Chat,
    ConversationArchiveParams,
    ConversationKeyChangeParams,
    ConversationMuteParams,
    DecryptEventParams,
    DecryptEventsParams,
    EncryptMessageParams,
    EncryptReactionParams,
    EncryptReplyParams,
    FileDecryptorParams,
    FileEncryptorParams,
    GroupCreateParams,
    GroupMembersChangeParams,
    GroupMembersRemoveParams,
    GroupTitleChangeParams,
    QuickReply,
    ImportKeysParams,
    SetIdentityParams,
)

logger = logging.getLogger("chatbot")


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
        # The version the X API reports for our registered public key. Set by
        # load_keys / unlock; used as the signing key version when sending.
        self.signing_key_version: str | None = None

    # -- Key management -----------------------------------------------------

    def load_keys(self, private_keys_b64: str, signing_key_version: str) -> None:
        """Import an existing private-key blob (identity[+signing]) and unlock.

        ``private_keys_b64`` is the base64 of 32 bytes (identity only) or 64
        bytes (identity + signing) — the same blob ``export_keys`` produces.
        ``signing_key_version`` is the ``public_key_version`` the X API
        returned when the keys were registered.

        This is the quickstart key-storage path. For production key storage see
        ``unlock`` / ``setup`` (Juicebox).
        """
        self.chat.import_keys(
            ImportKeysParams(_b64decode(private_keys_b64), signing_key_version=signing_key_version)
        )
        self.signing_key_version = signing_key_version

    def unlock(self, juicebox_config_json: str, pin: str, signing_key_version: str) -> None:
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
        if not self.signing_key_version:
            raise ValueError(
                "signing key version unknown: pass load_keys or unlock the "
                "public_key_version the X API returned when the keys were registered"
            )
        self.chat.set_identity(SetIdentityParams(user_id, self.signing_key_version))

    def fetch_public_keys_with(self, fetch: Callable[[str], list[dict[str, Any]]]) -> None:
        """Have the SDK fetch the public keys it lacks with ``fetch``, which
        returns one user's records from ``GET /2/users/{id}/public_keys``.

        This sets the SDK's public-key hook. ``decrypt_batch`` then fetches
        the signing keys a page's events name and the SDK does not hold,
        those of the members who made its key changes as well as those of
        the senders of its messages, and decrypts the page once more. The
        prepare calls that make a conversation key fetch their members'
        identity keys when they are passed no public keys. The SDK stores
        what arrives, and waits a minute before it asks again for a key a
        lookup did not bring. Setting the hook also turns the SDK's key
        cache on.

        A user whose fetch fails is logged and left out, so the keys of the
        other users still arrive.
        """

        def resolve(user_ids: list[str]) -> dict[str, list[dict[str, Any]]]:
            records = {}
            for user_id in user_ids:
                try:
                    records[user_id] = fetch(user_id)
                except Exception as err:
                    logger.warning("public_keys_fetch_failed user=%s err=%s", user_id, err)
            return records

        self.chat.set_resolve_public_keys(resolve)

    def resolve_public_keys_with(
        self, resolve: Callable[[list[str]], dict[str, list[dict[str, Any]]]]
    ) -> None:
        """Set the SDK's public-key hook to ``resolve`` as it is: a function
        that takes user ids and returns each user's records, by user id.

        A process with several signed-in users gives every chat the same
        function, so they share its lookups (see ``multi_user.py``).
        """
        self.chat.set_resolve_public_keys(resolve)

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
        public_keys: list[dict[str, str]] | None = None,
        conversation_id: str | None = None,
    ) -> dict[str, Any]:
        """Generate, encrypt, and sign a conversation-key change.

        ``public_keys`` is the flat list returned by the X API's public-keys
        endpoint: ``[{"user_id", "identity_public_key", "public_key_version"}, ...]``. Omit
        ``conversation_id`` for a one-to-one to derive it; pass it for a group.
        Pass no ``public_keys`` for a one-to-one that ``conversation_id``
        names, by its id or by the other user's id alone: the SDK reads both
        users' keys from the public keys it holds, fetching the ones it lacks
        through ``fetch_public_keys_with``.
        The change is signed with the ``set_identity`` session identity.
        """
        return self.chat.prepare_conversation_key_change(
            ConversationKeyChangeParams(public_keys, conversation_id=conversation_id)
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
        """Batch path — every page of events goes through it, the key changes
        and the data events together.

        ``decrypt_events`` extracts conversation keys from any KeyChange events
        in the batch, caches those of the key changes that verify, then
        decrypts every event. Returns the decrypted events, the conversation
        keys it extracted, and what it could not use.

        Omit ``signing_keys`` to verify with the public keys the SDK holds.
        The ones the page lacks are then fetched through
        ``fetch_public_keys_with``; the result's ``missing_signing_keys``
        lists those that did not arrive.
        """
        result = self.chat.decrypt_events(DecryptEventsParams(events_b64, signing_keys=signing_keys))
        events = [
            {"event": _as_dict(e["event"]), "original_b64": e.get("original_b64")}
            for e in result.get("events", [])
        ]
        return {
            "events": events,
            "conversation_keys": result.get("conversation_keys", {}),
            "errors": result.get("errors", {}),
            "unverified_key_changes": result.get("unverified_key_changes", {}),
            "undecryptable_key_changes": result.get("undecryptable_key_changes", {}),
            "rejected_signing_keys": result.get("rejected_signing_keys", {}),
            "missing_signing_keys": result.get("missing_signing_keys", {}),
        }

    def decrypt_one(
        self,
        event_b64: str,
        conversation_keys: dict[str, bytes],
        signing_keys: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        """Single-event path. ``conversation_keys`` is the key map from
        ``decrypt_batch``; with the key cache on, a version it lacks comes
        from the cache.

        Omit ``signing_keys`` to verify with the public keys the SDK holds.
        This path fetches none: an event whose sender's keys the SDK may lack
        goes through ``decrypt_batch``.
        """
        return _as_dict(
            self.chat.decrypt_event(
                DecryptEventParams(event_b64, conversation_keys, signing_keys=signing_keys)
            )
        )

    # -- Message encryption -------------------------------------------------

    def encrypt_reply(
        self,
        *,
        conversation_id: str,
        text: str,
        conversation_key: bytes | None = None,
        conversation_key_version: str | None = None,
        reply_to_event: str | None = None,
        reply_to_ckces: list[str] | None = None,
        reply_to_sequence_id: str | None = None,
        reply_to_message_id: str | None = None,
        reply_to_attachment_id: str | None = None,
        entities: list[tuple[int, int, str]] | None = None,
        attachments: list[dict[str, Any]] | None = None,
        quick_reply: QuickReply | None = None,
        ttl_msec: int | None = None,
    ) -> dict[str, str]:
        """Encrypt + sign a message, returning fields ready for the X API send.

        Without a reply target this sends a fresh message via
        ``encrypt_message``; with ``reply_to_event`` (the raw encoded event
        being answered — preferred, the SDK derives and embeds the validated
        preview) or ``reply_to_sequence_id``, the SDK's ``encrypt_reply``
        builds a *threaded* reply. ``reply_to_ckces`` are the raw key-change
        events that open an original sent under an older key version. A
        reply by ``reply_to_sequence_id`` also needs ``reply_to_message_id``,
        the quoted message's ``id``: recipients treat a v1 reply that names no
        original as invalid. ``reply_to_attachment_id`` replies to one
        attachment of ``reply_to_event``, such as one photo of an album: its
        ``attachment_id``, which the preview quotes alone. Omit the
        conversation key pair to resolve it from the SDK's verified-key cache
        (``set_cache_keys``).
        ``entities`` are ``(start, end, type)`` byte ranges; ``attachments``
        are attachment descriptors, each file naming the media hash key its
        upload started with; ``quick_reply`` offers selectable options or
        answers them; ``ttl_msec`` makes the message disappear after the
        given lifetime. Signed with the ``set_identity`` session identity.

        The result also carries ``event_b64``, the outgoing message as an
        event: it is not sent, but ``encrypt_media`` takes it to encrypt the
        message's files.
        """
        if reply_to_event is None and reply_to_sequence_id is None and reply_to_attachment_id is None:
            payload = self.chat.encrypt_message(
                EncryptMessageParams(
                    conversation_id,
                    text,
                    conversation_key=conversation_key,
                    conversation_key_version=conversation_key_version,
                    entities=entities,
                    attachments=attachments,
                    quick_reply=quick_reply,
                    ttl_msec=ttl_msec,
                )
            )
        else:
            payload = self.chat.encrypt_reply(
                EncryptReplyParams(
                    conversation_id,
                    text,
                    reply_to_event,
                    reply_to_ckces=reply_to_ckces,
                    reply_to_sequence_id=reply_to_sequence_id,
                    reply_to_message_id=reply_to_message_id,
                    reply_to_attachment_id=reply_to_attachment_id,
                    conversation_key=conversation_key,
                    conversation_key_version=conversation_key_version,
                    entities=entities,
                    attachments=attachments,
                    quick_reply=quick_reply,
                    ttl_msec=ttl_msec,
                )
            )
        return {
            # The SDK generates the message id and returns it in the payload.
            "message_id": payload.message_id,
            "encoded_message_create_event": payload.encoded_message_create_event,
            "encoded_message_event_signature": payload.encoded_message_event_signature,
            "xdk_version": payload.xdk_version,
            "event_b64": payload.event_b64,
        }

    def encrypt_reaction(
        self,
        *,
        add: bool,
        emoji: str,
        conversation_key: bytes,
        conversation_key_version: str,
        conversation_id: str | None = None,
        target_message_sequence_id: str | None = None,
        target_event: str | None = None,
        target_attachment_id: str | None = None,
    ) -> dict[str, str]:
        """Encrypt + sign a reaction add/remove.

        The target is ``conversation_id`` and ``target_message_sequence_id``,
        or ``target_event``, the raw event being reacted to, from which the
        SDK derives both. ``target_attachment_id`` reacts to one attachment
        of ``target_event``, such as one photo of an album: its
        ``attachment_id``, which the SDK checks against the decrypted event.
        Remove the reaction with the same ``target_attachment_id``. Signed
        with the ``set_identity`` session identity.

        The result also carries ``event_b64``, the reaction as an event.
        """
        method = self.chat.encrypt_add_reaction if add else self.chat.encrypt_remove_reaction
        payload = method(
            EncryptReactionParams(
                target_event,
                emoji,
                conversation_id=conversation_id,
                target_message_sequence_id=target_message_sequence_id,
                conversation_key=conversation_key,
                conversation_key_version=conversation_key_version,
                target_attachment_id=target_attachment_id,
            )
        )
        return {
            # The SDK generates the message id and returns it in the payload.
            "message_id": payload.message_id,
            "encoded_message_create_event": payload.encoded_message_create_event,
            "encoded_message_event_signature": payload.encoded_message_event_signature,
            "xdk_version": payload.xdk_version,
            "event_b64": payload.event_b64,
        }

    # -- Group management -----------------------------------------------------

    def prepare_group_create(
        self,
        public_keys: list[dict[str, str]] | None,
        conversation_id: str,
        member_ids: list[str],
        admin_ids: list[str],
        title: str | None = None,
    ) -> dict[str, Any]:
        """Prepare a group creation: fresh key + the two required signatures.

        Signed with the ``set_identity`` session identity. A plaintext
        ``title`` is encrypted under the new key; send the result's
        ``encrypted_title`` as the request's ``group_name``.

        Pass ``None`` as ``public_keys`` to have the SDK read the identity
        keys of ``member_ids`` and ``admin_ids`` from the public keys it
        holds, fetching the ones it lacks through ``fetch_public_keys_with``.
        """
        return self.chat.prepare_group_create(
            GroupCreateParams(public_keys, conversation_id, member_ids, admin_ids, title=title)
        )

    def prepare_group_members_change(
        self,
        public_keys: list[dict[str, str]] | None,
        conversation_id: str,
        new_member_ids: list[str],
        current_member_ids: list[str],
        current_admin_ids: list[str],
    ) -> dict[str, Any]:
        """Prepare a member add: rotated key + the two required signatures.

        Signed with the ``set_identity`` session identity.

        Pass ``None`` as ``public_keys`` to have the SDK read the identity
        keys of ``current_member_ids`` and ``new_member_ids`` from the public
        keys it holds, fetching the ones it lacks.
        """
        return self.chat.prepare_group_members_change(
            GroupMembersChangeParams(
                public_keys,
                conversation_id,
                new_member_ids,
                current_member_ids,
                current_admin_ids,
                [],
            )
        )

    def prepare_group_members_remove(
        self,
        public_keys: list[dict[str, str]] | None,
        conversation_id: str,
        user_ids: list[str],
        remaining_member_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """Prepare a member removal that rotates the key for who stays.

        ``public_keys`` are the identity keys of the members who remain.
        Pass ``None``, and name those members in ``remaining_member_ids``, to
        have the SDK read their keys from the public keys it holds, fetching
        the ones it lacks; with ``public_keys`` passed,
        ``remaining_member_ids`` is not read.
        Signed with the ``set_identity`` session identity.
        """
        return self.chat.prepare_group_members_remove(
            GroupMembersRemoveParams(
                public_keys,
                conversation_id,
                user_ids,
                remaining_member_ids=remaining_member_ids,
            )
        )

    # -- Media files ----------------------------------------------------------

    MEDIA_CHUNK = 1024 * 1024

    def encrypt_media(
        self,
        plaintext: bytes,
        event_b64: str,
        conversation_key: bytes,
        conversation_key_version: str,
        media_hash_key: str,
    ) -> bytes:
        """Encrypt a media file of an outgoing message with the incremental API.

        ``event_b64`` is the ``event_b64`` that ``encrypt_reply`` returned for
        the message, ``conversation_key`` and ``conversation_key_version`` the
        key the message was encrypted under, and ``media_hash_key`` the hash
        key its upload started with, as listed in the message's attachments;
        the SDK encrypts the file under that attachment's key. Feeding
        fixed-size chunks through ``push`` keeps memory bounded no matter how
        large the file is; ``finish`` emits the final frame that seals the
        file (decryption fails without it).
        """
        enc = self.chat.file_encryptor(
            FileEncryptorParams(
                event_b64,
                media_hash_key,
                conversation_key=conversation_key,
                conversation_key_version=conversation_key_version,
            )
        )
        out = bytearray()
        for offset in range(0, len(plaintext), self.MEDIA_CHUNK):
            out += enc.push(plaintext[offset : offset + self.MEDIA_CHUNK])
        out += enc.finish()
        return bytes(out)

    def decrypt_media(
        self,
        ciphertext: bytes,
        event_b64: str,
        conversation_keys: dict[str, bytes],
        media_hash_key: str,
    ) -> bytes:
        """Decrypt a downloaded media file with the incremental API.

        ``event_b64`` is the raw event of the message that carries the media and
        ``conversation_keys`` its conversation's key map, as passed to
        ``decrypt_one``; the SDK finds ``media_hash_key`` in the event and
        derives that file's key. ``finish`` raises if the file was truncated,
        so bytes from ``push`` must not be treated as complete until it
        succeeds.
        """
        dec = self.chat.file_decryptor(
            FileDecryptorParams(event_b64, conversation_keys, media_hash_key)
        )
        out = bytearray()
        for offset in range(0, len(ciphertext), self.MEDIA_CHUNK):
            out += dec.push(ciphertext[offset : offset + self.MEDIA_CHUNK])
        out += dec.finish()
        return bytes(out)

    # -- Group metadata -------------------------------------------------------

    def prepare_group_title_change(
        self,
        conversation_id: str,
        title: str,
        conversation_key: bytes,
        conversation_key_version: str,
    ) -> dict[str, Any]:
        """Prepare a group title change.

        The SDK encrypts the plaintext ``title`` under the conversation key and
        signs it. Send ``encrypted_value`` as the group's name and
        ``action_signatures`` on the request.
        """
        return self.chat.prepare_group_title_change(
            GroupTitleChangeParams(
                conversation_id,
                title,
                conversation_key=conversation_key,
                conversation_key_version=conversation_key_version,
            )
        )

    def decrypt(self, ciphertext_b64: str, conversation_key: bytes) -> str:
        """Decrypt a group title or description the X API returns."""
        return self.chat.decrypt(ciphertext_b64, conversation_key)

    # -- Conversation archive -------------------------------------------------

    def prepare_conversation_archive(self, conversation_id: str, archived: bool) -> dict[str, Any]:
        """Sign archiving (``archived=True``) or unarchiving (``False``) a
        conversation, group or one-to-one.

        Send the result's ``action_signatures`` on
        ``POST /2/chat/conversations/{id}/archive`` to archive, or on
        ``DELETE`` of the same path to unarchive. Signed with the
        ``set_identity`` session identity.
        """
        return self.chat.prepare_conversation_archive(
            ConversationArchiveParams(conversation_id, archived)
        )

    # -- Conversation mute ----------------------------------------------------

    def prepare_conversation_mute(self, conversation_id: str, muted: bool) -> dict[str, Any]:
        """Sign muting (``muted`` True) or unmuting (False) a conversation,
        group or one-to-one, for this bot alone.

        The event is signed in the bot's own ``{user_id}:{user_id}``
        conversation and names ``conversation_id`` in canonical colon form;
        send ``action_signatures`` with a mute or unmute request that names
        the conversation in that same form. Signed with the ``set_identity``
        session identity.
        """
        return self.chat.prepare_conversation_mute(ConversationMuteParams(conversation_id, muted))

    def close(self) -> None:
        """Clear the keys from memory, when the chat's user signs out. The
        core must not be used afterwards."""
        self.chat.lock()


def message_text(event: dict[str, Any]) -> str | None:
    """Pull the plain text out of a decrypted Message event, or None."""
    if event.get("type") != "Message":
        return None
    content = event.get("content") or {}
    return content.get("text")


def prep_to_request(prep: dict[str, Any]) -> dict[str, Any]:
    """Map a prepared conversation change into the X API request shape.

    Works for 1:1 key changes (one signature) and group create / member add
    (two signatures). The participant keys and action signatures already have
    the request's shape.
    """
    return {
        "conversation_key_version": prep["conversation_key_version"],
        "conversation_participant_keys": prep["conversation_participant_keys"],
        "action_signatures": prep["action_signatures"],
    }


def removal_to_request(user_ids: list[str], prep: dict[str, Any]) -> dict[str, Any]:
    """Map a rotating member removal into the members/remove request.

    Both signatures go in ``action_signatures``. The new key version and the
    participant keys for the members who stay go in ``group_key_rotation_data``.
    """
    return {
        "user_ids": user_ids,
        "action_signatures": prep["action_signatures"],
        "group_key_rotation_data": {
            "conversation_key_version": prep["conversation_key_version"],
            "conversation_participant_keys": prep["conversation_participant_keys"],
        },
    }
