"""Other users' public keys: the signing keys a batch reports missing, the
records ``add_public_keys`` stores, the keys the prepare calls read from the
store, and the hook that fetches what is missing."""

import os
import sys
import unittest

from features_support import keep_offline
from test_key_cache import _send_version, _signed_in
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


def _record(party: _Party) -> dict:
    """The record the X API returns for ``party``'s keys, with a field the
    SDK does not read."""
    key = party.signing_key
    return {
        "public_key_version": KEY_VERSION,
        "public_key": key["identity_public_key"],
        "signing_public_key": key["public_key"],
        "identity_public_key_signature": key["identity_public_key_signature"],
        "juicebox_config": {"realms": [{"id": "realm-1", "address": "https://realm.example"}]},
    }


def _records(*parties: _Party) -> dict:
    """The records of ``parties``, by user id."""
    return {party.user_id: [_record(party)] for party in parties}


class _Directory:
    """A hook that answers from the records of ``parties`` and keeps the
    user ids of each call it gets."""

    def __init__(self, *parties: _Party):
        self.records = _records(*parties)
        self.calls = []

    def __call__(self, user_ids: list) -> dict:
        self.calls.append(list(user_ids))
        return {user_id: self.records[user_id] for user_id in user_ids if user_id in self.records}


def _texts(result: dict) -> list:
    """The text of each message among a result's events."""
    events = [decrypted["event"] for decrypted in result["events"]]
    return [event["content"]["text"] for event in events if event["type"] == "Message"]


def _recipients(prepared: dict) -> list:
    """The users a prepared change encrypted its key to, sorted."""
    return sorted(key["user_id"] for key in prepared["conversation_participant_keys"])


# Each prepare call that makes a conversation key, as user 5001 makes it with
# the public keys it is given, and the users it names to encrypt the key to.
# A conversation for each call: a key version is the time in milliseconds, so
# two calls for one conversation can make the same version.
_PREPARES = {
    "group create": (
        lambda chat, public_keys: chat.prepare_group_create(
            chat_xdk.GroupCreateParams(public_keys, "g910", ["5001", "5002"], ["5001"])
        ),
        ["5001", "5002"],
    ),
    "member add": (
        lambda chat, public_keys: chat.prepare_group_members_change(
            chat_xdk.GroupMembersChangeParams(
                public_keys, "g911", ["5004"], ["5001", "5002"], ["5001"], []
            )
        ),
        ["5001", "5002", "5004"],
    ),
    "member removal": (
        lambda chat, public_keys: chat.prepare_group_members_remove(
            chat_xdk.GroupMembersRemoveParams(
                public_keys, "g912", ["5004"], remaining_member_ids=["5001", "5002"]
            )
        ),
        ["5001", "5002"],
    ),
    "key change": (
        lambda chat, public_keys: chat.prepare_conversation_key_change(
            chat_xdk.ConversationKeyChangeParams(
                public_keys, conversation_id="g913", member_ids=["5001", "5002"]
            )
        ),
        ["5001", "5002"],
    ),
    # A one-to-one names its two users by its id: here the other user's id.
    "one-to-one key change": (
        lambda chat, public_keys: chat.prepare_conversation_key_change(
            chat_xdk.ConversationKeyChangeParams(public_keys, conversation_id="5002")
        ),
        ["5001", "5002"],
    ),
}


class _PublicKeysTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if chat_xdk is None:  # pragma: no cover
            raise unittest.SkipTest(
                f"chat_xdk extension not importable in this Python: {_IMPORT_ERROR!r}"
            )
        keep_offline()


class TestMissingPublicKeys(_PublicKeysTest):
    def setUp(self):
        # An admin rotates a group's key, a member sends a message under it,
        # and the bot receives both.
        self.admin = _Party("5001")
        self.member = _Party("5002")
        self.bot = _signed_in("5003")
        self.change = _KeyChange(self.admin, [self.admin, self.member, self.bot], GROUP)
        self.events = [
            self.change.event_b64,
            _message(self.member, GROUP, self.change, "hello group"),
        ]

    def _decrypt(self, signing_keys=None) -> dict:
        """The bot's ``decrypt_events`` of the page with ``signing_keys``."""
        return self.bot.chat.decrypt_events(
            chat_xdk.DecryptEventsParams(self.events, signing_keys=signing_keys)
        )

    def _missing(self, index: str, party: _Party) -> dict:
        """``missing_signing_keys`` when only the event at ``index`` lacked
        its signing key, ``party``'s."""
        return {index: {"user_id": party.user_id, "public_key_version": KEY_VERSION}}

    def test_a_batch_reports_the_signing_keys_it_lacked_and_whose_keys_to_fetch(self):
        result = self._decrypt()

        self.assertEqual(result["events"], [])
        self.assertEqual(
            result["missing_signing_keys"],
            {**self._missing("0", self.admin), **self._missing("1", self.member)},
        )
        self.assertEqual(self.bot.chat.missing_public_keys(result), ["5001", "5002"])
        # Nothing was added: asked again at once, neither user is listed.
        self.assertEqual(self.bot.chat.missing_public_keys(result), [])

        # With the member's keys given, only the admin's is missing.
        result = self._decrypt([self.member.signing_key])
        self.assertEqual(result["missing_signing_keys"], self._missing("0", self.admin))

    def test_missing_public_keys_reads_the_missing_signing_keys_in_batch_order(self):
        missing = {
            "10": {"user_id": "5002", "public_key_version": "1"},
            "2": {"user_id": "5001", "public_key_version": "1"},
            "3": {"user_id": "5002", "public_key_version": "1"},
        }
        # The order is that of the event indices as numbers, each user once.
        self.assertEqual(self.bot.chat.missing_public_keys(missing), ["5001", "5002"])
        self.assertEqual(self.bot.chat.missing_public_keys({}), [])
        with self.assertRaises(chat_xdk.InvalidInputError):
            self.bot.chat.missing_public_keys({"0": "5001"})

    def test_add_public_keys_stores_the_records_the_api_returns(self):
        bot = self.bot.chat
        # A record without its signing key is left out.
        bot.add_public_keys({"5001": [dict(_record(self.admin), signing_public_key=None)]})
        self.assertEqual(self._decrypt()["events"], [])

        # A key version may be a number.
        bot.add_public_keys(
            {
                "5001": [_record(self.admin)],
                "5002": [dict(_record(self.member), public_key_version=int(KEY_VERSION))],
            }
        )
        bot.add_public_keys(None)
        result = self._decrypt()
        self.assertEqual(result["errors"], {})
        self.assertEqual(result["missing_signing_keys"], {})
        self.assertEqual(_texts(result), ["hello group"])

        with self.assertRaises(chat_xdk.InvalidInputError):
            bot.add_public_keys([_record(self.admin)])

    def test_decrypt_events_fetches_missing_keys_through_the_hook_and_decrypts_once_more(self):
        hook = _Directory(self.admin, self.member)
        self.bot.chat.set_resolve_public_keys(hook)

        result = self._decrypt()
        self.assertEqual(result["errors"], {})
        self.assertEqual(result["missing_signing_keys"], {})
        self.assertEqual(_texts(result), ["hello group"])
        self.assertEqual(hook.calls, [["5001", "5002"]])

        # Setting the hook turned the key cache on: a send finds the key of
        # the key change that verified.
        self.assertEqual(_send_version(self.bot, GROUP), self.change.version)

        # The keys are stored: the next batch needs no lookup.
        self._decrypt()
        self.assertEqual(len(hook.calls), 1)

    def test_the_hook_is_not_called_for_keys_that_were_passed_or_that_it_could_not_find(self):
        # The hook knows the admin alone.
        hook = _Directory(self.admin)
        self.bot.chat.set_resolve_public_keys(hook)

        # Signing keys that are passed are what the call verifies with.
        result = self._decrypt([self.member.signing_key])
        self.assertEqual(result["missing_signing_keys"], self._missing("0", self.admin))
        self.assertEqual(hook.calls, [])

        # The member's keys are not found: the result says so, and the next
        # call does not ask again.
        result = self._decrypt()
        self.assertEqual(result["missing_signing_keys"], self._missing("1", self.member))
        self.assertEqual(hook.calls, [["5001", "5002"]])
        self._decrypt()
        self.assertEqual(len(hook.calls), 1)

    def test_a_hook_that_returns_none_adds_nothing(self):
        calls = []
        self.bot.chat.set_resolve_public_keys(calls.append)

        result = self._decrypt()
        self.assertEqual(len(result["missing_signing_keys"]), 2)
        self.assertEqual(calls, [["5001", "5002"]])

    def test_an_error_the_hook_raises_reaches_the_caller(self):
        def failing(user_ids):
            raise LookupError("directory down")

        self.bot.chat.set_resolve_public_keys(failing)
        with self.assertRaisesRegex(LookupError, "directory down"):
            self._decrypt()

        admin = _signed_in("5001")
        admin.chat.set_resolve_public_keys(failing)
        prepare, _ = _PREPARES["group create"]
        with self.assertRaisesRegex(LookupError, "directory down"):
            prepare(admin.chat, None)

    def test_a_hook_is_a_callable_or_none_and_removing_it_leaves_the_key_cache_on(self):
        bot = self.bot.chat
        with self.assertRaises(TypeError):
            bot.set_resolve_public_keys("5001")
        hook = _Directory(self.admin, self.member)
        bot.set_resolve_public_keys(hook)
        bot.set_resolve_public_keys(None)

        # Without a hook the batch is decrypted once, with the stored keys.
        result = self._decrypt()
        self.assertEqual(len(result["missing_signing_keys"]), 2)
        self.assertEqual(hook.calls, [])

        # The cache the hook turned on is still on: a key change that
        # verifies has its key cached.
        bot.add_public_keys(_records(self.admin, self.member))
        self._decrypt()
        self.assertEqual(_send_version(self.bot, GROUP), self.change.version)


class TestPreparePublicKeys(_PublicKeysTest):
    def test_public_keys_are_optional_and_the_fields_after_them_stay_required(self):
        create = chat_xdk.GroupCreateParams(conversation_id="g1", member_ids=["1"], admin_ids=["1"])
        self.assertIsNone(create.public_keys)
        self.assertIsNone(chat_xdk.GroupCreateParams(None, "g1", ["1"], ["1"]).public_keys)

        rotate = chat_xdk.ConversationKeyChangeParams(member_ids=["1", "2"])
        self.assertIsNone(rotate.public_keys)
        self.assertEqual(rotate.member_ids, ["1", "2"])
        self.assertIsNone(chat_xdk.ConversationKeyChangeParams([]).member_ids)

        remove = chat_xdk.GroupMembersRemoveParams(
            conversation_id="g1", user_ids=["3"], remaining_member_ids=["1"]
        )
        self.assertEqual(remove.remaining_member_ids, ["1"])
        remove.remaining_member_ids = ["1", "2"]
        self.assertEqual(remove.remaining_member_ids, ["1", "2"])
        self.assertIsNone(chat_xdk.GroupMembersRemoveParams([], "g1", ["3"]).remaining_member_ids)

        missing_required = [
            lambda: chat_xdk.GroupCreateParams(member_ids=["1"], admin_ids=["1"]),
            lambda: chat_xdk.GroupCreateParams(conversation_id="g1", admin_ids=["1"]),
            lambda: chat_xdk.GroupMembersChangeParams(
                conversation_id="g1", new_member_ids=[], current_member_ids=[], current_admin_ids=[]
            ),
            lambda: chat_xdk.GroupMembersRemoveParams(conversation_id="g1"),
            lambda: chat_xdk.GroupMembersRemoveParams(user_ids=["3"]),
        ]
        for make in missing_required:
            with self.assertRaises(TypeError):
                make()

    def test_prepare_calls_take_public_keys_from_the_store_when_none_are_passed(self):
        admin = _signed_in("5001")
        member = _Party("5002")
        joiner = _Party("5004")
        admin.chat.add_public_keys(_records(admin, member, joiner))

        for name, (prepare, members) in _PREPARES.items():
            with self.subTest(name):
                self.assertEqual(_recipients(prepare(admin.chat, None)), members)
                # An empty list is no public keys either.
                self.assertEqual(_recipients(prepare(admin.chat, [])), members)

        # The member decrypts the key a change holds for it.
        prepare, _ = _PREPARES["group create"]
        created = prepare(admin.chat, None)
        for_member = next(
            key for key in created["conversation_participant_keys"] if key["user_id"] == "5002"
        )
        key = member.chat.decrypt_conversation_key(for_member["encrypted_conversation_key"])
        self.assertEqual(bytes(key), bytes(created["conversation_key"]))

        prepare, _ = _PREPARES["one-to-one key change"]
        self.assertEqual(prepare(admin.chat, None)["conversation_id"], "5001:5002")

    def test_a_prepare_call_names_the_members_whose_public_keys_are_not_stored(self):
        admin = _signed_in("5001")
        admin.chat.add_public_keys(_records(admin))

        for name, (prepare, _) in _PREPARES.items():
            with self.subTest(name):
                with self.assertRaisesRegex(
                    chat_xdk.InvalidInputError,
                    r"no public keys are stored for user\(s\) 5002",
                ):
                    prepare(admin.chat, None)

        # Without members to read keys for, a call reports its empty public
        # keys as it does without a store.
        with self.assertRaisesRegex(
            chat_xdk.ChatXdkError,
            "public_keys is empty: pass the public keys of the remaining members",
        ):
            admin.chat.prepare_group_members_remove(
                chat_xdk.GroupMembersRemoveParams(None, GROUP, ["5004"])
            )
        with self.assertRaisesRegex(chat_xdk.ChatXdkError, "public_keys must not be empty"):
            admin.chat.prepare_conversation_key_change(
                chat_xdk.ConversationKeyChangeParams(conversation_id=GROUP)
            )

    def test_missing_public_keys_for_names_the_members_a_prepare_call_would_lack(self):
        admin = _signed_in("5001")
        admin.chat.add_public_keys(_records(admin))
        params = chat_xdk.GroupCreateParams(
            conversation_id=GROUP, member_ids=["5001", "5002"], admin_ids=["5001"]
        )

        self.assertEqual(admin.chat._missing_public_keys_for("group_create", params), ["5002"])
        # Nothing was added: asked again at once, the user is not listed.
        self.assertEqual(admin.chat._missing_public_keys_for("group_create", params), [])

        # A call that passes its public keys is missing none.
        params.public_keys = [admin.public_key]
        self.assertEqual(admin.chat._missing_public_keys_for("group_create", params), [])

        with self.assertRaises(chat_xdk.InvalidInputError):
            admin.chat._missing_public_keys_for("group_rename", params)
        with self.assertRaises(TypeError):
            admin.chat._missing_public_keys_for("conversation_key_change", params)

    def test_the_hook_supplies_the_public_keys_of_prepare_calls_that_pass_none(self):
        member = _Party("5002")
        joiner = _Party("5004")

        for name, (prepare, members) in _PREPARES.items():
            with self.subTest(name):
                admin = _signed_in("5001")
                hook = _Directory(admin, member, joiner)
                admin.chat.set_resolve_public_keys(hook)

                self.assertEqual(_recipients(prepare(admin.chat, None)), members)
                self.assertEqual(hook.calls, [members])

                # The keys are stored: the next call needs no lookup.
                prepare(admin.chat, None)
                self.assertEqual(len(hook.calls), 1)

    def test_public_keys_that_are_passed_are_used_without_the_hook(self):
        admin = _signed_in("5001")
        member = _Party("5002")
        hook = _Directory()
        admin.chat.set_resolve_public_keys(hook)
        passed = [admin.public_key, member.public_key]

        for name, (prepare, _) in _PREPARES.items():
            with self.subTest(name):
                self.assertEqual(_recipients(prepare(admin.chat, passed)), ["5001", "5002"])
                self.assertEqual(hook.calls, [])


if __name__ == "__main__":
    unittest.main()
