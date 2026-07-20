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

    def test_generic_encrypt_decrypt_roundtrip(self):
        # A real round-trip through the SDK: encrypt then decrypt must return
        # the original plaintext (not a hardcoded echo).
        core = self._loaded_core()
        conv_key = base64.b64decode(self.vectors["conversation_key_b64"])
        plaintext = "hello from the chatbot example"
        ciphertext = core.encrypt(plaintext, conv_key)
        self.assertNotEqual(ciphertext, plaintext)
        self.assertEqual(core.decrypt(ciphertext, conv_key), plaintext)

    def test_conversation_key_prepare_and_decrypt_roundtrip(self):
        # Conversation-key handling: prepare a fresh key for ourselves, then
        # ECIES-decrypt the per-participant blob back to the same raw key.
        core = self._loaded_core()
        core.set_identity("me")
        public_keys = [
            {
                "user_id": "me",
                "public_key": self.vectors["identity_public_b64"],
                "key_version": "1",
            }
        ]
        prepared = core.prepare_conversation_key_change(public_keys, "conv-1")
        conv_key = prepared["conversation_key"]
        self.assertEqual(len(conv_key), 32)
        encrypted = prepared["participant_keys"][0]["encrypted_key"]
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

    def test_decrypt_batch_empty_is_safe(self):
        # Drives the real decrypt_events entry point (batch path) — an empty
        # batch yields no messages and no errors.
        core = self._loaded_core()
        result = core.decrypt_batch([], signing_keys=[])
        self.assertEqual(result["messages"], [])
        self.assertEqual(result.get("errors") or {}, {})

    def test_decrypt_one_rejects_garbage(self):
        # Drives the real decrypt_event entry point (single path) — invalid
        # base64 must raise rather than silently succeed.
        core = self._loaded_core()
        with self.assertRaises(Exception):
            core.decrypt_one("not-valid-base64!!!", {}, [])


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
                "public_key": self.vectors["identity_public_b64"],
                "key_version": "1",
            }
        ]
        return core, keys

    def test_prep_to_request_maps_the_rest_shape(self):
        # The mapper output is exactly what the X API's write endpoints take;
        # a drifted field name here breaks every flow in the live e2e.
        from chat_core import prep_to_request

        core, keys = self._core_and_keys()
        prep = core.prepare_conversation_key_change(keys, conversation_id="1000:2000")
        body = prep_to_request(prep, core.public_keys()["signing"])

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
        # CKCE signature payloads are withheld (they embed the plaintext key).
        self.assertNotIn("signature_payload", sig)

    def test_prepare_group_create_yields_two_signatures(self):
        core, keys = self._core_and_keys()
        prep = core.prepare_group_create(keys, "g123", ["1000"], ["1000"])
        self.assertEqual(len(prep["action_signatures"]), 2)
        self.assertTrue(prep["conversation_key"])

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
            ["encoded_message_create_event", "encoded_message_event_signature", "message_id"],
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
            entities=[(0, 5, "mention")],
            ttl_msec=60_000,
        )
        self.assertTrue(body["encoded_message_create_event"])

    def test_media_stream_encrypt_decrypt_roundtrip(self):
        # The chunked stream path the media flow uses: multi-chunk payload in,
        # identical bytes out, and truncation is detected.
        core, _ = self._core_and_keys()
        conv_key = base64.b64decode(self.vectors["conversation_key_b64"])
        plaintext = bytes((i * 31 + 7) % 256 for i in range(300_000))

        ciphertext = core.encrypt_media(plaintext, conv_key)
        self.assertNotEqual(ciphertext[: len(plaintext)], plaintext)
        self.assertEqual(core.decrypt_media(ciphertext, conv_key), plaintext)

        with self.assertRaises(Exception):
            core.decrypt_media(ciphertext[:-4], conv_key)
