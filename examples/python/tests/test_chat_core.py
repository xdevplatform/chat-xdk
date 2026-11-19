"""Offline tests for the ChatBot example's crypto core.

These drive the REAL ``chat_xdk`` binding through the same ``ChatCore`` the bot
uses — no mocking of the SDK. They prove an actual encrypt -> decrypt round-trip
and that the binding reproduces the committed key/signature vectors.

Run from this directory:

    PYTHONPATH=../../crates/pyo3/python:.. python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import base64
import json
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_EXAMPLE = os.path.dirname(_HERE)
# repo root: examples/python/tests -> examples/python -> examples -> repo
_REPO_ROOT = os.path.abspath(os.path.join(_EXAMPLE, "..", ".."))

# Make the example importable, and fall back to the in-repo chat_xdk build so
# the test runs without a separate `pip install` / `maturin develop`.
for p in (_EXAMPLE, os.path.join(_REPO_ROOT, "crates", "pyo3", "python")):
    if p not in sys.path:
        sys.path.insert(0, p)


def _load_vectors() -> dict:
    path = os.path.join(_REPO_ROOT, "tests", "fixtures", "sdk_vectors.json")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _string_field(field_id: int, value: str) -> bytes:
    """A Thrift string field: its id, then the value's length and bytes."""
    data = value.encode("utf-8")
    return b"\x0b" + field_id.to_bytes(2, "big") + len(data).to_bytes(4, "big") + data


def _delivered(event_b64: str, sequence_id: str) -> str:
    """``event_b64`` as delivered: with the sequence id the server assigns,
    prepended as Thrift string field 1."""
    event = _string_field(1, sequence_id) + base64.b64decode(event_b64)
    return base64.b64encode(event).decode("ascii")


def _delivered_action(action: dict, sender_id: str, conversation_id: str, sequence_id: str) -> str:
    """A signed action as delivered: the event the server relays for
    ``action``, an entry of a prepared change's ``action_signatures``, from
    ``sender_id`` in ``conversation_id``, with the sequence id the server
    assigns."""
    signed = action["message_event_signature"]
    signature = (
        _string_field(1, signed["signature"])
        + _string_field(2, signed["public_key_version"])
        + _string_field(3, signed["signature_version"])
        + b"\x00"
    )
    detail = base64.b64decode(action["encoded_message_event_detail"])
    event = (
        _string_field(1, sequence_id)
        + _string_field(2, action["message_id"])
        + _string_field(3, sender_id)
        + _string_field(4, conversation_id)
        + b"\x0c\x00\x07"
        + detail
        + b"\x0c\x00\x09"
        + signature
        + b"\x00"
    )
    return base64.b64encode(event).decode("ascii")


class _Party:
    """A core with fresh keys as user ``user_id``, and the keys others hold
    for it."""

    def __init__(self, user_id: str):
        from chat_core import ChatCore

        self.core = ChatCore()
        self.user_id = user_id
        generated = self.core.generate_and_register()
        self.core.load_keys(generated["private_keys_b64"], signing_key_version="1")
        self.core.set_identity(user_id)
        registration = generated["registration"]
        self.public_key = {
            "user_id": user_id,
            "identity_public_key": registration["public_key"],
            "public_key_version": "1",
        }
        # The record GET /2/users/{id}/public_keys returns for these keys.
        self.public_key_record = {
            "public_key_version": "1",
            "public_key": registration["public_key"],
            "signing_public_key": registration["signing_public_key"],
            "identity_public_key_signature": registration["identity_public_key_signature"],
            "juicebox_config": None,
        }


def _group_page(admin: _Party, member: _Party, bot: _Party) -> list[str]:
    """A page of group ``g900`` as ``bot`` receives it: the key change
    ``admin`` made, then a message ``member`` sent under its key. The admin
    signed the key change and sent no message."""
    prepared = admin.core.prepare_conversation_key_change(
        [admin.public_key, member.public_key, bot.public_key], "g900"
    )
    key_change = _delivered_action(
        prepared["action_signatures"][0], admin.user_id, "g900", "2100000000000000000"
    )
    body = member.core.encrypt_reply(
        conversation_id="g900",
        text="hello group",
        conversation_key=prepared["conversation_key"],
        conversation_key_version=prepared["conversation_key_version"],
    )
    return [key_change, _delivered(body["event_b64"], "2100000000000000001")]


class TestChatCore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from chat_core import ChatCore  # noqa: F401
        except Exception as e:  # pragma: no cover
            raise unittest.SkipTest(f"chat_xdk not importable: {e!r}")
        cls.vectors = _load_vectors()

    def _loaded_core(self):
        from chat_core import ChatCore

        core = ChatCore()
        core.load_keys(self.vectors["private_keys_concat_b64"], signing_key_version="1")
        return core

    def test_load_keys_matches_fixture_public_keys(self):
        # Importing the fixture private keys must reproduce the exact public
        # keys recorded in the vector file — proves the real binding crypto.
        core = self._loaded_core()
        keys = core.public_keys()
        self.assertEqual(keys["identity"], self.vectors["identity_public_b64"])
        self.assertEqual(keys["signing"], self.vectors["signing_public_b64"])

    def test_set_identity_needs_the_registered_version(self):
        # Freshly generated keys have no registered version yet, so the bot
        # cannot sign as itself until load_keys / unlock provide one.
        from chat_core import ChatCore

        core = ChatCore()
        core.generate_and_register()
        with self.assertRaisesRegex(ValueError, "signing key version unknown"):
            core.set_identity("12345")

    def test_group_title_change_encrypts_the_title_it_signs(self):
        # A real round-trip through the SDK: the title change signs the
        # encrypted title, which decrypts back to the original (not a
        # hardcoded echo).
        core = self._loaded_core()
        core.set_identity(self.vectors["event_sender_id"])
        conv_key = base64.b64decode(self.vectors["conversation_key_b64"])
        title = "hello from the chatbot example"
        prepared = core.prepare_group_title_change("g123", title, conv_key, "1")
        self.assertNotEqual(prepared["encrypted_value"], title)
        self.assertEqual(prepared["conversation_key_version"], "1")
        self.assertEqual(core.decrypt(prepared["encrypted_value"], conv_key), title)

    def test_conversation_key_prepare_and_decrypt_roundtrip(self):
        # Conversation-key handling: prepare a fresh key for ourselves, then
        # ECIES-decrypt the per-participant blob back to the same raw key.
        core = self._loaded_core()
        core.set_identity("910002")
        public_keys = [
            {
                "user_id": "910002",
                "identity_public_key": self.vectors["identity_public_b64"],
                "public_key_version": "1",
            }
        ]
        prepared = core.prepare_conversation_key_change(public_keys, "conv-1")
        conv_key = prepared["conversation_key"]
        self.assertEqual(len(conv_key), 32)
        encrypted = prepared["conversation_participant_keys"][0]["encrypted_conversation_key"]
        self.assertEqual(core.decrypt_conversation_key(encrypted), conv_key)

    def test_encrypt_reply_produces_sendable_payload(self):
        # The encrypt path the bot uses for outgoing replies: the sender is
        # the session identity set once at startup.
        core = self._loaded_core()
        core.set_identity("12345")
        conv_key = base64.b64decode(self.vectors["conversation_key_b64"])
        body = core.encrypt_reply(
            conversation_id="6789:12345",
            text="pong",
            conversation_key=conv_key,
            conversation_key_version="1710000000000",
        )
        self.assertTrue(body["encoded_message_create_event"])
        self.assertTrue(body["encoded_message_event_signature"])
        self.assertTrue(body["message_id"])
        self.assertTrue(body["xdk_version"])

    def test_encrypt_reply_threaded_from_raw_event(self):
        # Replying to the fixture's raw encoded event: the SDK derives the
        # preview from the event itself and embeds it for validation.
        core = self._loaded_core()
        core.set_identity(self.vectors["event_sender_id"])
        body = core.encrypt_reply(
            conversation_id=self.vectors["event_conversation_id"],
            text="pong",
            conversation_key=base64.b64decode(self.vectors["conversation_key_b64"]),
            conversation_key_version=self.vectors["event_conversation_key_version"],
            reply_to_event=self.vectors["event_message_b64"],
        )
        self.assertTrue(body["encoded_message_create_event"])
        self.assertTrue(body["message_id"])
        self.assertTrue(body["xdk_version"])

    def test_decrypt_batch_empty_is_safe(self):
        # Drives the real decrypt_events entry point (batch path) — an empty
        # batch yields no messages and no errors.
        core = self._loaded_core()
        result = core.decrypt_batch([], signing_keys=[])
        self.assertEqual(result["events"], [])
        self.assertEqual(result.get("errors") or {}, {})

    def test_decrypt_one_rejects_garbage(self):
        # Drives the real decrypt_event entry point (single path) — invalid
        # base64 must raise rather than silently succeed.
        core = self._loaded_core()
        with self.assertRaises(Exception):
            core.decrypt_one("not-valid-base64!!!", {}, [])

    def test_a_page_whose_key_change_signer_sent_no_message_decrypts_through_the_hook(self):
        from chat_core import message_text

        admin, member, bot = _Party("5001"), _Party("5002"), _Party("5003")
        events = _group_page(admin, member, bot)

        # Without the signers' keys the key change does not verify: its key is
        # dropped and the message does not decrypt.
        unverified = bot.core.decrypt_batch(events)
        self.assertEqual(unverified["events"], [])
        self.assertEqual(
            unverified["missing_signing_keys"],
            {
                "0": {"user_id": "5001", "public_key_version": "1"},
                "1": {"user_id": "5002", "public_key_version": "1"},
            },
        )

        records = {"5001": [admin.public_key_record], "5002": [member.public_key_record]}
        asked = []

        def fetch(user_id):
            asked.append(user_id)
            return records[user_id]

        # The SDK asks for the keys of the admin, who made the key change, as
        # well as for those of the member who sent the message.
        bot.core.fetch_public_keys_with(fetch)
        batch = bot.core.decrypt_batch(events)
        self.assertEqual(asked, ["5001", "5002"])
        self.assertEqual(batch["errors"], {})
        self.assertEqual(batch["missing_signing_keys"], {})
        self.assertEqual(batch["unverified_key_changes"], {})
        self.assertEqual(
            [message_text(decrypted["event"]) for decrypted in batch["events"]],
            [None, "hello group"],
        )

        # The SDK holds the keys it fetched: the page needs no further fetch.
        bot.core.decrypt_batch(events)
        self.assertEqual(asked, ["5001", "5002"])

    def test_a_user_whose_public_key_fetch_fails_is_logged_and_left_out(self):
        admin, member, bot = _Party("5001"), _Party("5002"), _Party("5003")
        events = _group_page(admin, member, bot)

        def fetch(user_id):
            if user_id == "5002":
                raise RuntimeError("HTTP 503")
            return [admin.public_key_record]

        bot.core.fetch_public_keys_with(fetch)
        with self.assertLogs("chatbot", level="WARNING") as logs:
            batch = bot.core.decrypt_batch(events)

        self.assertTrue(
            any("public_keys_fetch_failed user=5002" in line for line in logs.output),
            logs.output,
        )
        # The admin's keys arrived, so the key change verifies; the member's
        # key is the one still missing.
        self.assertEqual(batch["unverified_key_changes"], {})
        self.assertEqual(
            batch["missing_signing_keys"],
            {"1": {"user_id": "5002", "public_key_version": "1"}},
        )

    def test_prepare_calls_get_their_public_keys_through_the_hook(self):
        admin, member = _Party("5001"), _Party("5002")
        records = {"5001": [admin.public_key_record], "5002": [member.public_key_record]}
        asked = []

        def fetch(user_id):
            asked.append(user_id)
            return records[user_id]

        def recipients(prepared):
            return sorted(key["user_id"] for key in prepared["conversation_participant_keys"])

        admin.core.fetch_public_keys_with(fetch)
        created = admin.core.prepare_group_create(None, "g901", ["5001", "5002"], ["5001"])
        self.assertEqual(recipients(created), ["5001", "5002"])
        self.assertEqual(asked, ["5001", "5002"])

        # The SDK holds both users' keys: the calls that follow fetch none.
        rotated = admin.core.prepare_conversation_key_change(conversation_id="5002")
        self.assertEqual(recipients(rotated), ["5001", "5002"])
        removed = admin.core.prepare_group_members_remove(
            None, "g901", ["5002"], remaining_member_ids=["5001"]
        )
        self.assertEqual(recipients(removed), ["5001"])
        self.assertEqual(asked, ["5001", "5002"])


if __name__ == "__main__":
    unittest.main()


class TestPreparedChanges(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from chat_core import ChatCore  # noqa: F401
        except Exception as e:  # pragma: no cover
            raise unittest.SkipTest(f"chat_xdk not importable: {e!r}")
        cls.vectors = _load_vectors()

    def _core_and_keys(self):
        from chat_core import ChatCore

        core = ChatCore()
        core.load_keys(self.vectors["private_keys_concat_b64"], signing_key_version="1")
        core.set_identity("1000")
        keys = [
            {
                "user_id": "1000",
                "identity_public_key": self.vectors["identity_public_b64"],
                "public_key_version": "1",
            }
        ]
        return core, keys

    def test_prep_to_request_maps_the_rest_shape(self):
        # The mapper output is exactly what the X API's write endpoints take;
        # a drifted field name here breaks every flow in the live e2e.
        from chat_core import prep_to_request

        core, keys = self._core_and_keys()
        prep = core.prepare_conversation_key_change(keys, conversation_id="1000:2000")
        body = prep_to_request(prep)

        self.assertEqual(body["conversation_key_version"], prep["conversation_key_version"])
        (pk,) = body["conversation_participant_keys"]
        self.assertEqual(
            sorted(pk), ["encrypted_conversation_key", "public_key_version", "user_id"]
        )
        (sig,) = body["action_signatures"]
        self.assertEqual(sig["message_id"], prep["action_signatures"][0]["message_id"])
        self.assertTrue(sig["encoded_message_event_detail"])
        inner = sig["message_event_signature"]
        self.assertEqual(inner["signing_public_key"], core.public_keys()["signing"])
        self.assertTrue(inner["signature"] and inner["public_key_version"])

    def test_removal_to_request_rotates_for_members_who_stay(self):
        from chat_core import removal_to_request

        core, keys = self._core_and_keys()
        prep = core.prepare_group_members_remove(keys, "g123", ["2000"])
        body = removal_to_request(["2000"], prep)

        self.assertEqual(body["user_ids"], ["2000"])
        self.assertEqual(len(body["action_signatures"]), 2)
        self.assertEqual(
            body["action_signatures"],
            prep["action_signatures"],
        )
        rotation = body["group_key_rotation_data"]
        self.assertEqual(
            rotation["conversation_key_version"], prep["conversation_key_version"]
        )
        (pk,) = rotation["conversation_participant_keys"]
        self.assertEqual(pk["user_id"], "1000")
        self.assertEqual(
            sorted(pk), ["encrypted_conversation_key", "public_key_version", "user_id"]
        )
        self.assertNotIn("conversation_key_version", body)
        self.assertNotIn("conversation_participant_keys", body)

    def test_prepare_group_create_yields_two_signatures(self):
        core, keys = self._core_and_keys()
        title = "hello from the python example"
        prep = core.prepare_group_create(keys, "g123", ["1000"], ["1000"], title=title)
        self.assertEqual(len(prep["action_signatures"]), 2)
        self.assertTrue(prep["conversation_key"])
        # The title goes out encrypted under the new key: the group_name the
        # create request sends.
        encrypted_title = prep["encrypted_title"]
        self.assertEqual(core.decrypt(encrypted_title, bytes(prep["conversation_key"])), title)

    def test_encrypt_reaction_produces_sendable_payload(self):
        core, _ = self._core_and_keys()
        conv_key = base64.b64decode(self.vectors["conversation_key_b64"])
        body = core.encrypt_reaction(
            add=True,
            conversation_id="1000:2000",
            target_message_sequence_id="42",
            emoji="\U0001f44d",
            conversation_key=conv_key,
            conversation_key_version="1",
        )
        self.assertEqual(
            sorted(body),
            [
                "encoded_message_create_event",
                "encoded_message_event_signature",
                "message_id",
                "xdk_version",
            ],
        )

    def test_threaded_reply_with_entities_and_ttl(self):
        core, _ = self._core_and_keys()
        conv_key = base64.b64decode(self.vectors["conversation_key_b64"])
        body = core.encrypt_reply(
            conversation_id="1000:2000",
            text="@user hello",
            conversation_key=conv_key,
            conversation_key_version="1",
            reply_to_sequence_id="42",
            reply_to_message_id="6f1c0a4e-6a4b-4f8e-9c3d-2b7a5e9d1c0f",
            entities=[(0, 5, "mention")],
            ttl_msec=60_000,
        )
        self.assertTrue(body["encoded_message_create_event"])
        # A reply built from a sequence id names the original by its id too.
        sent = core.decrypt_one(
            body["event_b64"],
            {"1": conv_key},
            [
                {
                    "user_id": "1000",
                    "public_key_version": "1",
                    "public_key": self.vectors["signing_public_b64"],
                    "identity_public_key": self.vectors["identity_public_b64"],
                    "identity_public_key_signature": self.vectors["identity_public_key_signature_b64"],
                }
            ],
        )
        preview = sent["content"]["replying_to_preview"]
        self.assertEqual(preview["replying_to_message_sequence_id"], "42")
        self.assertEqual(preview["replying_to_message_id"], "6f1c0a4e-6a4b-4f8e-9c3d-2b7a5e9d1c0f")

    def test_media_encrypt_decrypt_roundtrip(self):
        # The message-first media flow: the message names the file by the
        # media hash key its upload started with, the file is encrypted from
        # the message's event_b64 in chunks, and it decrypts through that
        # event. A truncated file is detected.
        from chat_xdk import encrypted_file_size

        core, _ = self._core_and_keys()
        conv_key = base64.b64decode(self.vectors["conversation_key_b64"])
        conv_keys = {"1": conv_key}
        plaintext = bytes((i * 31 + 7) % 256 for i in range(300_000))
        body = core.encrypt_reply(
            conversation_id="1000:2000",
            text="a photo",
            conversation_key=conv_key,
            conversation_key_version="1",
            attachments=[
                {
                    "attachment_type": "media",
                    "media_hash_key": "photo",
                    "width": 4,
                    "height": 3,
                    "filesize_bytes": encrypted_file_size(len(plaintext)),
                    "filename": "photo.bin",
                    "media_type": 5,
                }
            ],
        )
        self.assertTrue(body["event_b64"])

        ciphertext = core.encrypt_media(plaintext, body["event_b64"], conv_key, "1", "photo")
        self.assertEqual(len(ciphertext), encrypted_file_size(len(plaintext)))
        self.assertEqual(
            core.decrypt_media(ciphertext, body["event_b64"], conv_keys, "photo"), plaintext
        )
        with self.assertRaises(ValueError) as ctx:
            core.decrypt_media(ciphertext[:-4], body["event_b64"], conv_keys, "photo")
        self.assertIn("truncated", str(ctx.exception))

    def test_media_from_the_fixture_message_opens(self):
        # Media encrypted by another client opens through its message's event.
        core, _ = self._core_and_keys()
        v = self.vectors
        conv_keys = {
            v["message_key_conversation_key_version"]: bytes.fromhex(
                v["message_key_conversation_key_hex"]
            )
        }
        for name in ("first", "second"):
            self.assertEqual(
                core.decrypt_media(
                    base64.b64decode(v[f"media_{name}_encrypted_b64"]),
                    v["event_message_key_b64"],
                    conv_keys,
                    v[f"media_{name}_hash_key"],
                ),
                base64.b64decode(v[f"media_{name}_plaintext_b64"]),
            )
