"""``decrypt_events`` and the members who sign a batch's key changes: a key
change needs its signer's keys to verify, the result says which key changes
did not verify and why, and the version to encrypt with is reported per
conversation."""

import base64
import os
import sys
import unittest

# A sequence id past the cut-over, where a key change that does not verify
# has its key dropped.
ENFORCED_SEQUENCE = "2100000000000000000"
GROUP = "g900"
OTHER_GROUP = "g901"
KEY_VERSION = "1"


def _repo_root() -> str:
    # .../crates/pyo3/python/tests/test_key_change_signers.py -> repo root is 4 levels up
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))


def _string_field(field_id: int, value: str) -> bytes:
    """A Thrift string field: its id, then the value's length and bytes."""
    data = value.encode("utf-8")
    return b"\x0b" + field_id.to_bytes(2, "big") + len(data).to_bytes(4, "big") + data


def _struct_field(field_id: int, struct: bytes) -> bytes:
    """A Thrift struct field: its id, then the struct as already serialized."""
    return b"\x0c" + field_id.to_bytes(2, "big") + struct


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
    event = (
        _string_field(1, sequence_id)
        + _string_field(2, action["message_id"])
        + _string_field(3, sender_id)
        + _string_field(4, conversation_id)
        + _struct_field(7, base64.b64decode(action["encoded_message_event_detail"]))
        + _struct_field(9, signature)
        + b"\x00"
    )
    return base64.b64encode(event).decode("ascii")


class _Party:
    """A chat with fresh keys as user ``user_id``, and the keys others hold
    for it."""

    def __init__(self, user_id: str):
        from chat_xdk import Chat

        self.chat = Chat()
        self.user_id = user_id
        registration = self.chat.generate_keypairs().public_key
        self.signing_key = {
            "user_id": user_id,
            "public_key_version": KEY_VERSION,
            "public_key": registration.signing_public_key,
            "identity_public_key": registration.public_key,
            "identity_public_key_signature": registration.identity_public_key_signature,
        }
        self.public_key = {
            "user_id": user_id,
            "identity_public_key": registration.public_key,
            "public_key_version": KEY_VERSION,
        }


class _KeyChange:
    """The key change ``signer`` makes in ``conversation_id`` for
    ``members``, as delivered, with its key."""

    def __init__(self, signer: _Party, members: list, conversation_id: str):
        from chat_xdk import ConversationKeyChangeParams

        prepared = signer.chat.prepare_conversation_key_change(
            ConversationKeyChangeParams(
                [member.public_key for member in members],
                conversation_id=conversation_id,
                sender_id=signer.user_id,
                signing_key_version=KEY_VERSION,
            )
        )
        self.event_b64 = _delivered_action(
            prepared["action_signatures"][0], signer.user_id, conversation_id, ENFORCED_SEQUENCE
        )
        self.key = prepared["conversation_key"]
        self.version = prepared["conversation_key_version"]


def _message(author: _Party, conversation_id: str, change: _KeyChange, text: str) -> str:
    """The message ``author`` sends in ``conversation_id`` under the key of
    ``change``, as delivered."""
    from chat_xdk import EncryptMessageParams

    payload = author.chat.encrypt_message(
        EncryptMessageParams(
            conversation_id,
            text,
            sender_id=author.user_id,
            signing_key_version=KEY_VERSION,
            conversation_key=change.key,
            conversation_key_version=change.version,
        )
    )
    return _delivered(payload.event_b64, "2100000000000000001")


class TestKeyChangeSigners(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        py_src = os.path.join(_repo_root(), "crates", "pyo3", "python")
        if py_src not in sys.path:
            sys.path.insert(0, py_src)

        try:
            from chat_xdk import Chat  # noqa: F401
        except Exception as e:  # pragma: no cover
            raise unittest.SkipTest(f"chat_xdk extension not importable in this Python: {e!r}")
        from features_support import keep_offline

        keep_offline()

    def setUp(self):
        # An admin rotates a group's key, a member sends a message under it,
        # and the bot receives both.
        self.admin = _Party("5001")
        self.member = _Party("5002")
        self.bot = _Party("5003")
        self.change = _KeyChange(self.admin, [self.admin, self.member, self.bot], GROUP)
        self.events = [
            self.change.event_b64,
            _message(self.member, GROUP, self.change, "hello group"),
        ]

    def _decrypt(self, events: list, *signers: _Party) -> dict:
        """The bot's ``decrypt_events`` of ``events`` with the signing keys
        of ``signers``."""
        from chat_xdk import DecryptEventsParams

        return self.bot.chat.decrypt_events(
            DecryptEventsParams(events, signing_keys=[signer.signing_key for signer in signers])
        )

    def test_key_change_without_its_signers_keys_is_reported_and_its_key_dropped(self):
        # The bot holds the keys of the member who wrote the message, not of
        # the admin who made the key change.
        result = self._decrypt(self.events, self.member)

        self.assertEqual(result["events"], [])
        self.assertEqual(result["conversation_keys"]["keys"], {})
        self.assertIsNone(result["conversation_keys"]["latest_version"])
        self.assertEqual(result["conversation_keys"]["latest_versions"], {})
        self.assertEqual(
            result["unverified_key_changes"],
            [
                {
                    "index": 0,
                    "reason": "MissingSigningKey",
                    "key_dropped": True,
                    "conversation_id": GROUP,
                    "conversation_key_version": self.change.version,
                    "sender_id": "5001",
                    "public_key_version": KEY_VERSION,
                }
            ],
        )
        self.assertIn(
            "no signing key for sender 5001 at public_key_version 1", result["errors"]["0"]
        )
        self.assertIn(
            "no matching key found: the key change for that version, event 0 of the batch, "
            "did not verify",
            result["errors"]["1"],
        )

    def test_key_change_checked_with_another_key_is_reported_invalid(self):
        # A signing key under the admin's user id and key version that is not
        # the key the admin signed with.
        other_key = _Party(self.admin.user_id)
        result = self._decrypt(self.events, self.member, other_key)

        self.assertEqual(result["events"], [])
        self.assertEqual(len(result["unverified_key_changes"]), 1)
        unverified = result["unverified_key_changes"][0]
        self.assertEqual(unverified["reason"], "InvalidSignature")
        self.assertTrue(unverified["key_dropped"])
        self.assertIn("ECDSA mismatch", result["errors"]["0"])

    def test_key_change_with_its_signers_keys_verifies_and_its_messages_decrypt(self):
        result = self._decrypt(self.events, self.member, self.admin)

        self.assertEqual(result["errors"], {})
        self.assertEqual(result["unverified_key_changes"], [])
        events = [decrypted["event"] for decrypted in result["events"]]
        self.assertEqual([event["type"] for event in events], ["KeyChange", "Message"])
        self.assertEqual(events[1]["content"]["text"], "hello group")
        self.assertEqual(result["conversation_keys"]["latest_version"], self.change.version)
        self.assertEqual(
            result["conversation_keys"]["latest_versions"], {GROUP: self.change.version}
        )

    def test_latest_versions_are_reported_per_conversation(self):
        other = _KeyChange(self.admin, [self.admin, self.bot], OTHER_GROUP)
        while other.version == self.change.version:
            other = _KeyChange(self.admin, [self.admin, self.bot], OTHER_GROUP)
        events = [self.change.event_b64, other.event_b64]
        versions = {GROUP: self.change.version, OTHER_GROUP: other.version}

        # Each conversation has its own version to encrypt with, and no
        # single one stands for both.
        result = self._decrypt(events, self.admin)
        self.assertEqual(result["errors"], {})
        self.assertEqual(result["conversation_keys"]["latest_versions"], versions)
        self.assertIsNone(result["conversation_keys"]["latest_version"])

        result = self._decrypt([other.event_b64], self.admin)
        self.assertEqual(result["conversation_keys"]["latest_version"], other.version)
        self.assertEqual(
            result["conversation_keys"]["latest_versions"], {OTHER_GROUP: other.version}
        )

        # extract_conversation_keys checks no signature: its latest_version
        # is the batch's highest, and latest_versions each conversation's.
        extracted = self.bot.chat.extract_conversation_keys(events)
        self.assertEqual(extracted["latest_versions"], versions)
        self.assertEqual(
            extracted["latest_version"],
            str(max(int(self.change.version), int(other.version))),
        )


if __name__ == "__main__":
    unittest.main()
