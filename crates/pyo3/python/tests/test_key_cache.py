"""The conversation-key cache and the signing-key store: what fills them and
which calls read them."""

import base64
import os
import sys
import types
import unittest

from features_support import keep_offline
from test_key_change_signers import GROUP, KEY_VERSION, _KeyChange, _message, _Party, _repo_root

_PY_SRC = os.path.join(_repo_root(), "crates", "pyo3", "python")
if _PY_SRC not in sys.path:
    sys.path.insert(0, _PY_SRC)

# The tests are skipped where the extension is not built, so the import may
# fail here without failing the run.
try:
    import chat_xdk
except Exception as e:  # pragma: no cover
    chat_xdk = None
    _IMPORT_ERROR = e

AVATAR_URL = "https://ton.x.com/xchat_media/g900/avatar"


def _signed_in(user_id: str) -> _Party:
    """A party with a session identity."""
    party = _Party(user_id)
    party.chat.set_identity(chat_xdk.SetIdentityParams(user_id, KEY_VERSION))
    return party


def _caching(user_id: str) -> _Party:
    """A party with a session identity whose key cache is on."""
    party = _signed_in(user_id)
    party.chat.set_cache_keys(True)
    return party


def _send_version(sender: _Party, conversation_id: str) -> str:
    """The key version ``sender`` encrypts under in ``conversation_id`` when
    the call passes no key."""
    payload = sender.chat.encrypt_message(chat_xdk.EncryptMessageParams(conversation_id, "hello"))
    return payload.conversation_key_version


def _read(receiver: _Party, message: str, author: _Party) -> str:
    """The text of ``message`` from ``author``, as ``receiver`` decrypts it
    on its own with no key map."""
    event = receiver.chat.decrypt_event(
        chat_xdk.DecryptEventParams(message, signing_keys=[author.signing_key])
    )
    return event["content"]["text"]


def _rotate(admin: _Party, conversation_id: str) -> dict:
    """The key change ``admin`` prepares for itself in ``conversation_id``,
    relying on its session identity."""
    return admin.chat.prepare_conversation_key_change(
        chat_xdk.ConversationKeyChangeParams([admin.public_key], conversation_id=conversation_id)
    )


def _under(prepared: dict) -> types.SimpleNamespace:
    """The key of a prepared change and its version, as ``_message`` takes
    them."""
    return types.SimpleNamespace(
        key=prepared["conversation_key"], version=prepared["conversation_key_version"]
    )


def _signs_avatar_version(admin: _Party, prepared: dict, version: str) -> bool:
    """Whether the change to ``AVATAR_URL`` that ``admin`` prepared for
    ``GROUP`` signs key version ``version``: its signature verifies over the
    fields an avatar change signs, which end with the key version and the
    URL."""
    action = prepared["action_signatures"][0]
    signed = action["message_event_signature"]
    signature = signed["signature"]
    payload = (
        f"GroupChangeEvent.GroupAvatarUrlChange,{action['message_id']},"
        f"{admin.user_id},{GROUP},{version},{AVATAR_URL}"
    )
    return admin.chat.verify(
        signed["signing_public_key"],
        base64.b64decode(signature + "=" * (-len(signature) % 4)),
        payload.encode(),
    )


class TestKeyCache(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if chat_xdk is None:  # pragma: no cover
            raise unittest.SkipTest(
                f"chat_xdk extension not importable in this Python: {_IMPORT_ERROR!r}"
            )
        keep_offline()

    def _assert_no_key(self, sender: _Party, conversation_id: str = GROUP):
        """An encrypt of ``sender`` that passes no key finds none cached for
        ``conversation_id``."""
        with self.assertRaisesRegex(
            chat_xdk.InvalidStateError, f"no cached conversation key for '{conversation_id}'"
        ):
            _send_version(sender, conversation_id)

    def test_decrypt_event_caches_the_key_of_a_key_change_that_verifies(self):
        admin = _Party("5001")
        member = _Party("5002")
        bot = _caching("5003")
        change = _KeyChange(admin, [admin, member, bot], GROUP)
        message = _message(member, GROUP, change, "hello group")

        # Nothing is cached yet: neither a send nor the message finds a key.
        self._assert_no_key(bot)
        with self.assertRaises(chat_xdk.ChatXdkError):
            _read(bot, message, member)

        event = bot.chat.decrypt_event(
            chat_xdk.DecryptEventParams(change.event_b64, signing_keys=[admin.signing_key])
        )
        self.assertEqual(event["type"], "KeyChange")
        self.assertTrue(event["verified"])

        self.assertEqual(_send_version(bot, GROUP), change.version)
        self.assertEqual(_read(bot, message, member), "hello group")
        # A later batch reports the version the single call recorded.
        batch = bot.chat.decrypt_events(
            chat_xdk.DecryptEventsParams([message], signing_keys=[member.signing_key])
        )
        self.assertEqual(batch["conversation_keys"]["latest_version"], change.version)

    def test_decrypt_event_does_not_cache_a_key_change_that_does_not_verify(self):
        admin = _Party("5001")
        bot = _caching("5003")
        bot.chat.set_reject_unverified(False)
        change = _KeyChange(admin, [admin, bot], GROUP)

        # Without the admin's signing keys the key change is returned
        # unverified.
        event = bot.chat.decrypt_event(chat_xdk.DecryptEventParams(change.event_b64))
        self.assertEqual(event["type"], "KeyChange")
        self.assertFalse(event["verified"])
        self._assert_no_key(bot)

    def test_prepare_calls_cache_the_key_they_make(self):
        admin = _caching("5001")
        member = _Party("5002")
        joiner = _Party("5004")
        both = [admin.public_key, member.public_key]
        # A conversation for each call: a key version is the time in
        # milliseconds, so two calls for one conversation can make the same
        # version.
        prepares = {
            "g910": lambda group: admin.chat.prepare_group_create(
                chat_xdk.GroupCreateParams(both, group, ["5001", "5002"], ["5001"])
            ),
            "g911": lambda group: admin.chat.prepare_group_members_change(
                chat_xdk.GroupMembersChangeParams(
                    both + [joiner.public_key], group, ["5004"], ["5001", "5002"], ["5001"], []
                )
            ),
            "g912": lambda group: admin.chat.prepare_group_members_remove(
                chat_xdk.GroupMembersRemoveParams(both, group, ["5004"])
            ),
            "g913": lambda group: admin.chat.prepare_conversation_key_change(
                chat_xdk.ConversationKeyChangeParams(both, conversation_id=group)
            ),
        }
        for group, prepare in prepares.items():
            with self.subTest(group):
                self._assert_no_key(admin, group)
                prepared = prepare(group)

                self.assertEqual(
                    _send_version(admin, group), prepared["conversation_key_version"]
                )
                # The key stays cached: a message under it decrypts with no
                # key map.
                message = _message(member, group, _under(prepared), "under the new key")
                self.assertEqual(_read(admin, message, member), "under the new key")

    def test_prepared_keys_are_not_cached_while_the_cache_is_off(self):
        admin = _signed_in("5001")
        _rotate(admin, GROUP)

        self._assert_no_key(admin)
        # Turning the cache on later does not bring the key back.
        admin.chat.set_cache_keys(True)
        self._assert_no_key(admin)

    def test_cache_keeps_every_verified_version_and_sends_use_the_newest(self):
        admin = _Party("5001")
        member = _Party("5002")
        bot = _caching("5003")
        members = [admin, member, bot]
        first = _KeyChange(admin, members, GROUP)
        second = _KeyChange(admin, members, GROUP)
        while int(second.version) <= int(first.version):
            second = _KeyChange(admin, members, GROUP)

        # The older key change arrives last: it is kept for decryption and
        # does not become the key sends use.
        for change in (second, first):
            event = bot.chat.decrypt_event(
                chat_xdk.DecryptEventParams(change.event_b64, signing_keys=[admin.signing_key])
            )
            self.assertTrue(event["verified"])
            self.assertEqual(_send_version(bot, GROUP), second.version)

        for change in (first, second):
            message = _message(member, GROUP, change, change.version)
            self.assertEqual(_read(bot, message, member), change.version)

    def test_files_decrypt_with_the_cached_keys_when_no_key_map_is_passed(self):
        sender = _caching("5001")
        version = _rotate(sender, GROUP)["conversation_key_version"]
        photo = b"photo bytes"
        payload = sender.chat.encrypt_message(
            chat_xdk.EncryptMessageParams(
                GROUP,
                "a photo",
                attachments=[
                    {
                        "attachment_type": "media",
                        "media_hash_key": "photo",
                        "width": 1,
                        "height": 1,
                        "filesize_bytes": len(photo),
                        "filename": "photo.jpg",
                        "media_type": 1,
                    }
                ],
            )
        )
        event_b64 = payload.event_b64
        encrypted = sender.chat.encrypt_file(chat_xdk.EncryptFileParams(photo, event_b64, "photo"))

        # No key map, left out, None or empty: the keys come from the cache.
        for params in (
            chat_xdk.DecryptFileParams(encrypted, event_b64, media_hash_key="photo"),
            chat_xdk.DecryptFileParams(encrypted, event_b64, None, "photo"),
            chat_xdk.DecryptFileParams(encrypted, event_b64, {}, "photo"),
        ):
            self.assertEqual(sender.chat.decrypt_file(params), photo)
        for params in (
            chat_xdk.FileDecryptorParams(event_b64, media_hash_key="photo"),
            chat_xdk.FileDecryptorParams(event_b64, None, "photo"),
            chat_xdk.FileDecryptorParams(event_b64, {}, "photo"),
        ):
            decryptor = sender.chat.file_decryptor(params)
            streamed = decryptor.push(encrypted)
            streamed += decryptor.finish()
            self.assertEqual(streamed, photo)

        # A key map that is passed is the only source: one without the
        # message's version fails though the cache holds that version.
        other_version = {"9": bytes(range(32))}
        missing = f"conversation_keys has no key for version '{version}'"
        with self.assertRaisesRegex(chat_xdk.DecryptionError, missing):
            sender.chat.decrypt_file(
                chat_xdk.DecryptFileParams(encrypted, event_b64, other_version, "photo")
            )
        with self.assertRaisesRegex(chat_xdk.DecryptionError, missing):
            sender.chat.file_decryptor(
                chat_xdk.FileDecryptorParams(event_b64, other_version, "photo")
            )

        # With the cache off there are no keys to read.
        sender.chat.set_cache_keys(False)
        with self.assertRaisesRegex(chat_xdk.DecryptionError, missing):
            sender.chat.decrypt_file(
                chat_xdk.DecryptFileParams(encrypted, event_b64, media_hash_key="photo")
            )

    def test_avatar_change_signs_the_newest_cached_version_when_none_is_passed(self):
        admin = _caching("5001")
        # The key version left out, None and empty.
        omitted = (
            chat_xdk.GroupAvatarChangeParams(GROUP, AVATAR_URL),
            chat_xdk.GroupAvatarChangeParams(GROUP, AVATAR_URL, None),
            chat_xdk.GroupAvatarChangeParams(GROUP, AVATAR_URL, ""),
        )

        for params in omitted:
            with self.assertRaisesRegex(
                chat_xdk.InvalidStateError,
                f"conversation_key_version is not set and no conversation key is cached "
                f"for '{GROUP}'",
            ):
                admin.chat.prepare_group_avatar_change(params)

        older = _rotate(admin, GROUP)["conversation_key_version"]
        newest = _rotate(admin, GROUP)["conversation_key_version"]
        while int(newest) <= int(older):
            newest = _rotate(admin, GROUP)["conversation_key_version"]

        # The version signed is the one sends use.
        self.assertEqual(_send_version(admin, GROUP), newest)
        for params in omitted:
            prepared = admin.chat.prepare_group_avatar_change(params)
            self.assertTrue(_signs_avatar_version(admin, prepared, newest))
            self.assertFalse(_signs_avatar_version(admin, prepared, older))
        # A version that is passed is signed as is.
        prepared = admin.chat.prepare_group_avatar_change(
            chat_xdk.GroupAvatarChangeParams(GROUP, AVATAR_URL, older)
        )
        self.assertTrue(_signs_avatar_version(admin, prepared, older))
        self.assertFalse(_signs_avatar_version(admin, prepared, newest))

    def test_add_signing_keys_merges_by_user_and_version(self):
        alice = _Party("5001")
        bob = _Party("5002")
        reader = _Party("5003")
        key = types.SimpleNamespace(key=os.urandom(32), version="7")

        def reads(author: _Party) -> bool:
            """Whether ``reader`` verifies a message from ``author`` with the
            signing keys it stores. The conversation key is passed."""
            message = _message(author, GROUP, key, "hi")
            try:
                event = reader.chat.decrypt_event(
                    chat_xdk.DecryptEventParams(message, {key.version: key.key})
                )
            except chat_xdk.VerificationError:
                return False
            self.assertEqual(event["content"]["text"], "hi")
            return event["verified"]

        reader.chat.set_signing_keys([alice.signing_key])
        self.assertTrue(reads(alice))
        self.assertFalse(reads(bob))

        # Adding keeps what is stored.
        reader.chat.add_signing_keys([bob.signing_key])
        self.assertTrue(reads(alice))
        self.assertTrue(reads(bob))

        # set_signing_keys still replaces the whole set.
        reader.chat.set_signing_keys([bob.signing_key])
        self.assertFalse(reads(alice))
        self.assertTrue(reads(bob))

        # An entry for a stored user and version replaces that entry alone.
        reader.chat.add_signing_keys([alice.signing_key])
        self.assertTrue(reads(alice))
        reader.chat.add_signing_keys([dict(bob.signing_key, user_id=alice.user_id)])
        self.assertFalse(reads(alice))
        self.assertTrue(reads(bob))

    def test_the_key_map_and_the_avatar_key_version_can_be_left_out(self):
        keys = {"7": bytes(range(32))}

        # The positional forms keep their meaning.
        whole = chat_xdk.DecryptFileParams(b"file", "event", keys, "photo")
        self.assertEqual(whole.conversation_keys, keys)
        self.assertEqual(whole.media_hash_key, "photo")
        streamed = chat_xdk.FileDecryptorParams("event", keys, "photo")
        self.assertEqual(streamed.conversation_keys, keys)
        self.assertEqual(streamed.media_hash_key, "photo")
        avatar = chat_xdk.GroupAvatarChangeParams(GROUP, AVATAR_URL, "4", sender_id="5001")
        self.assertEqual(avatar.conversation_key_version, "4")
        self.assertEqual(avatar.sender_id, "5001")

        whole = chat_xdk.DecryptFileParams(b"file", "event", media_hash_key="photo")
        self.assertIsNone(whole.conversation_keys)
        self.assertEqual(whole.media_hash_key, "photo")
        streamed = chat_xdk.FileDecryptorParams("event", media_hash_key="photo")
        self.assertIsNone(streamed.conversation_keys)
        self.assertEqual(streamed.media_hash_key, "photo")
        self.assertIsNone(
            chat_xdk.GroupAvatarChangeParams(GROUP, AVATAR_URL).conversation_key_version
        )

        # The media hash key stays required.
        for make in (
            lambda: chat_xdk.DecryptFileParams(b"file", "event"),
            lambda: chat_xdk.DecryptFileParams(b"file", "event", keys),
            lambda: chat_xdk.FileDecryptorParams("event"),
            lambda: chat_xdk.FileDecryptorParams("event", keys),
        ):
            with self.assertRaisesRegex(TypeError, "missing required argument: 'media_hash_key'"):
                make()


if __name__ == "__main__":
    unittest.main()
