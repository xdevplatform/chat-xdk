"""``decrypt_events`` and the key changes of a batch: a key change needs its
signer's keys to verify, the result says which key changes did not verify or
could not be decrypted and why, and keys and the version to encrypt with are
reported per conversation."""

import base64
import os
import sys
import types
import unittest

# A sequence id past the cut-over, where a key change that does not verify
# has its key dropped, and one before it, where the key is kept.
ENFORCED_SEQUENCE = "2100000000000000000"
UNENFORCED_SEQUENCE = "100"
GROUP = "g900"
OTHER_GROUP = "g901"
THIRD_GROUP = "g902"
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
        self.signer = signer
        self.conversation_id = conversation_id
        self.action = prepared["action_signatures"][0]
        self.event_b64 = _delivered_action(
            self.action, signer.user_id, conversation_id, ENFORCED_SEQUENCE
        )
        self.key = prepared["conversation_key"]
        self.version = prepared["conversation_key_version"]

    def at_version(self, version: str) -> types.SimpleNamespace:
        """This key change as delivered before the cut-over with its key
        version rewritten to ``version``. The signature no longer verifies,
        and the key is kept."""
        assert len(version) == len(self.version)
        detail = base64.b64decode(self.action["encoded_message_event_detail"])
        assert self.version.encode() in detail
        detail = detail.replace(self.version.encode(), version.encode(), 1)
        action = dict(self.action, encoded_message_event_detail=base64.b64encode(detail).decode())
        return types.SimpleNamespace(
            event_b64=_delivered_action(
                action, self.signer.user_id, self.conversation_id, UNENFORCED_SEQUENCE
            ),
            key=self.key,
            version=version,
        )


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

    def _decrypt(self, events: list, *signing_keys) -> dict:
        """The bot's ``decrypt_events`` of ``events`` with ``signing_keys``:
        parties, for their signing keys, or signing key entries."""
        return self._decrypt_as(self.bot, events, *signing_keys)

    @staticmethod
    def _decrypt_as(party: _Party, events: list, *signing_keys) -> dict:
        from chat_xdk import DecryptEventsParams

        entries = [key.signing_key if isinstance(key, _Party) else key for key in signing_keys]
        return party.chat.decrypt_events(DecryptEventsParams(events, signing_keys=entries))

    @staticmethod
    def _texts(result: dict) -> list:
        """The text of each message among a result's events."""
        events = [decrypted["event"] for decrypted in result["events"]]
        return [event["content"]["text"] for event in events if event["type"] == "Message"]

    def _unverified(self, reason: str) -> dict:
        """``unverified_key_changes`` when the page's key change did not
        verify for ``reason`` and lost its key."""
        return {
            "0": {
                "reason": reason,
                "key_dropped": True,
                "conversation_id": GROUP,
                "conversation_key_version": self.change.version,
                "sender_id": "5001",
                "public_key_version": KEY_VERSION,
            }
        }

    def test_key_change_without_its_signers_keys_is_reported_and_its_key_dropped(self):
        # The bot holds the keys of the member who wrote the message, not of
        # the admin who made the key change.
        result = self._decrypt(self.events, self.member)

        self.assertEqual(result["events"], [])
        self.assertEqual(result["conversation_keys"]["keys"], {})
        self.assertEqual(result["conversation_keys"]["keys_by_conversation"], {})
        self.assertIsNone(result["conversation_keys"]["latest_version"])
        self.assertEqual(result["conversation_keys"]["latest_versions"], {})
        self.assertEqual(result["unverified_key_changes"], self._unverified("MissingSigningKey"))
        self.assertEqual(result["undecryptable_key_changes"], {})
        self.assertEqual(result["rejected_signing_keys"], {})
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
        self.assertEqual(result["unverified_key_changes"], self._unverified("InvalidSignature"))
        self.assertIn("ECDSA mismatch", result["errors"]["0"])

    def test_signing_key_with_an_invalid_binding_is_reported_rejected(self):
        # The admin's signing key with a binding signature that is not its
        # signature over the identity key.
        unbound = dict(
            self.admin.signing_key,
            identity_public_key_signature=self.member.signing_key["identity_public_key_signature"],
        )
        result = self._decrypt(self.events, self.member, unbound)

        self.assertEqual(result["events"], [])
        self.assertEqual(
            result["rejected_signing_keys"],
            {"1": {"user_id": "5001", "public_key_version": KEY_VERSION}},
        )
        self.assertEqual(result["unverified_key_changes"], self._unverified("RejectedSigningKey"))
        self.assertIn(
            "the signing key given for sender 5001 at public_key_version 1 was rejected: "
            "its identity binding does not verify",
            result["errors"]["0"],
        )

    def test_key_change_with_its_signers_keys_verifies_and_its_messages_decrypt(self):
        result = self._decrypt(self.events, self.member, self.admin)

        self.assertEqual(result["errors"], {})
        self.assertEqual(result["unverified_key_changes"], {})
        self.assertEqual(result["undecryptable_key_changes"], {})
        self.assertEqual(result["rejected_signing_keys"], {})
        events = [decrypted["event"] for decrypted in result["events"]]
        self.assertEqual([event["type"] for event in events], ["KeyChange", "Message"])
        self.assertEqual(self._texts(result), ["hello group"])
        keys = result["conversation_keys"]
        self.assertEqual(keys["latest_version"], self.change.version)
        self.assertEqual(keys["latest_versions"], {GROUP: self.change.version})
        self.assertEqual(keys["keys"], {self.change.version: self.change.key})
        self.assertEqual(
            keys["keys_by_conversation"], {GROUP: {self.change.version: self.change.key}}
        )

    def test_key_change_this_chat_cannot_decrypt_is_reported_with_why(self):
        from chat_xdk import SetIdentityParams

        # A key change made for the admin and the member only: a chat whose
        # identity is the bot's finds no key for its user in it.
        outsider = _Party(self.bot.user_id)
        outsider.chat.set_identity(SetIdentityParams(self.bot.user_id, KEY_VERSION))
        change = _KeyChange(self.admin, [self.admin, self.member], GROUP)
        events = [change.event_b64, _message(self.member, GROUP, change, "not for the bot")]
        result = self._decrypt_as(outsider, events, self.member, self.admin)

        self.assertEqual(result["events"], [])
        self.assertEqual(result["unverified_key_changes"], {})
        self.assertEqual(
            result["undecryptable_key_changes"],
            {
                "0": {
                    "reason": "NotARecipient",
                    "conversation_id": GROUP,
                    "conversation_key_version": change.version,
                    "sender_id": "5001",
                }
            },
        )
        self.assertIn(
            "event 0 of the batch, holds no key this chat can decrypt: "
            "it holds no key for this chat's user",
            result["errors"]["1"],
        )

    def test_keys_and_latest_versions_are_reported_per_conversation(self):
        other = _KeyChange(self.admin, [self.admin, self.bot], OTHER_GROUP)
        while other.version == self.change.version:
            other = _KeyChange(self.admin, [self.admin, self.bot], OTHER_GROUP)
        events = [self.change.event_b64, other.event_b64]
        versions = {GROUP: self.change.version, OTHER_GROUP: other.version}
        keys_by_conversation = {
            GROUP: {self.change.version: self.change.key},
            OTHER_GROUP: {other.version: other.key},
        }

        # Each conversation has its own keys and its own version to encrypt
        # with, and no single version stands for both.
        keys = self._decrypt(events, self.admin)["conversation_keys"]
        self.assertEqual(keys["latest_versions"], versions)
        self.assertIsNone(keys["latest_version"])
        self.assertEqual(keys["keys_by_conversation"], keys_by_conversation)
        self.assertEqual(
            keys["keys"], {self.change.version: self.change.key, other.version: other.key}
        )

        keys = self._decrypt([other.event_b64], self.admin)["conversation_keys"]
        self.assertEqual(keys["latest_version"], other.version)
        self.assertEqual(keys["latest_versions"], {OTHER_GROUP: other.version})

        # A batch of two conversations has no single version even when only
        # one of them has a verified key change.
        stray = _message(self.admin, THIRD_GROUP, other, "hello third group")
        keys = self._decrypt([self.change.event_b64, stray], self.admin)["conversation_keys"]
        self.assertIsNone(keys["latest_version"])
        self.assertEqual(keys["latest_versions"], {GROUP: self.change.version})

        # extract_conversation_keys checks no signature, and reports the
        # same way.
        extracted = self.bot.chat.extract_conversation_keys(events)
        self.assertEqual(extracted["latest_versions"], versions)
        self.assertIsNone(extracted["latest_version"])
        self.assertEqual(extracted["keys_by_conversation"], keys_by_conversation)
        extracted = self.bot.chat.extract_conversation_keys([other.event_b64])
        self.assertEqual(extracted["latest_version"], other.version)

    def test_keys_of_two_conversations_at_one_version_stay_apart(self):
        other = _KeyChange(self.admin, [self.admin, self.bot], OTHER_GROUP)
        while other.version == self.change.version:
            other = _KeyChange(self.admin, [self.admin, self.bot], OTHER_GROUP)
        same_version = other.at_version(self.change.version)
        events = [
            self.change.event_b64,
            same_version.event_b64,
            _message(self.admin, GROUP, self.change, "hello group"),
            _message(self.admin, OTHER_GROUP, same_version, "hello other group"),
        ]

        # Each message decrypts under its own conversation's key, and a
        # lookup by version alone finds neither.
        result = self._decrypt(events, self.admin)
        self.assertEqual(self._texts(result), ["hello group", "hello other group"])
        self.assertEqual(list(result["errors"]), ["1"])
        self.assertEqual(
            result["conversation_keys"]["keys_by_conversation"],
            {
                GROUP: {self.change.version: self.change.key},
                OTHER_GROUP: {self.change.version: other.key},
            },
        )
        self.assertEqual(result["conversation_keys"]["keys"], {})
        unverified = result["unverified_key_changes"]["1"]
        self.assertEqual(unverified["reason"], "InvalidSignature")
        self.assertFalse(unverified["key_dropped"])


if __name__ == "__main__":
    unittest.main()
