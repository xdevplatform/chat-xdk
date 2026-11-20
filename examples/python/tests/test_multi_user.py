"""Offline tests for the example's multi-user helpers: one chat per signed-in
user, all fetching public keys through one hook over one cache.

Like ``test_chat_core.py``, these drive the REAL ``chat_xdk`` binding.

Run from the example's directory:

    PYTHONPATH=../../crates/pyo3/python:. python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

# test_chat_core.py, next to this file, has the helpers that build users and
# signed events. Importing it also makes the example and the in-repo
# chat_xdk build importable.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from test_chat_core import _group_page, _Party  # noqa: E402

# The tests are skipped where chat_xdk is not built. Only that import may
# fail without failing the run: the example's own modules must import.
try:
    import chat_xdk  # noqa: F401
except ImportError as e:  # pragma: no cover
    _IMPORT_ERROR = e
else:
    _IMPORT_ERROR = None
    from chat_core import ChatCore, message_text
    from multi_user import SharedPublicKeys, UserChats


def _sign_in(chats: UserChats, party: _Party) -> ChatCore:
    """The chat ``chats`` keeps for ``party``, signed in with its keys."""
    return chats.chat_for(party.user_id, party.private_keys_b64, "1")


class _Clock:
    """A clock that a test moves by hand."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class TestMultiUser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if _IMPORT_ERROR is not None:  # pragma: no cover
            raise unittest.SkipTest(f"chat_xdk not importable: {_IMPORT_ERROR!r}")

    def test_the_chats_of_two_signed_in_users_fetch_the_keys_of_a_user_they_both_meet_once(self):
        admin, member, alice, bob = map(_Party, ("5001", "5002", "5003", "5004"))
        records = {"5001": [admin.public_key_record], "5002": [member.public_key_record]}
        asked = []

        def fetch(user_id):
            asked.append(user_id)
            return records[user_id]

        chats = UserChats(SharedPublicKeys(fetch).resolve)
        events = _group_page(admin, member, alice, bob)

        for signed_in in (alice, bob):
            page = _sign_in(chats, signed_in).decrypt_batch(events)
            self.assertEqual(page["errors"], {})
            self.assertEqual(page["missing_signing_keys"], {})
            self.assertEqual(
                [message_text(decrypted["event"]) for decrypted in page["events"]],
                [None, "hello group"],
            )
        # Each chat needed the keys of the admin and the member: the second
        # chat took them from the cache the first one filled.
        self.assertEqual(asked, ["5001", "5002"])

    def test_a_signed_in_user_has_one_chat_which_serves_every_conversation_of_the_user(self):
        admin, member, alice, bob = map(_Party, ("5001", "5002", "5003", "5004"))
        records = {"5001": [admin.public_key_record], "5002": [member.public_key_record]}
        chats = UserChats(SharedPublicKeys(lambda user_id: records[user_id]).resolve)

        chat = _sign_in(chats, alice)
        self.assertIs(_sign_in(chats, alice), chat)
        self.assertIsNot(_sign_in(chats, bob), chat)

        for conversation_id in ("g900", "g901"):
            events = _group_page(admin, member, alice, conversation_id=conversation_id)
            page = chat.decrypt_batch(events)
            self.assertEqual(page["errors"], {})
            # The reply takes the conversation's key from the chat's key cache.
            body = chat.encrypt_reply(conversation_id=conversation_id, text="hi")
            self.assertTrue(body["encoded_message_create_event"])
        # The chat holds no key for a conversation it has not read.
        with self.assertRaisesRegex(ValueError, "no cached conversation key for 'g902'"):
            chat.encrypt_reply(conversation_id="g902", text="hi")

        # A sign-out clears the chat's keys, and the next sign-in makes
        # another chat.
        chats.close(alice.user_id)
        self.assertFalse(chat.chat.is_unlocked())
        self.assertIsNot(_sign_in(chats, alice), chat)

    def test_shared_public_keys_shares_a_lookup_retries_a_failure_and_expires_answers(self):
        clock = _Clock()
        asked = []
        failing = {"7"}
        started, release = threading.Event(), threading.Event()

        def fetch(user_id):
            asked.append(user_id)
            version = str(len(asked))
            if user_id == "5" and not started.is_set():
                # The first lookup of user 5 says that it is under way, and
                # waits to be let go.
                started.set()
                release.wait(10)
            if user_id in failing:
                raise RuntimeError("HTTP 503")
            return [{"public_key_version": version}]

        shared = SharedPublicKeys(fetch, ttl_seconds=100.0, clock=clock)

        # Two calls at once: user 5 is fetched once, and both calls get the
        # answer. The second call starts while the first one's fetch is under
        # way, and finds either that lookup or its answer.
        with ThreadPoolExecutor(max_workers=2) as pool:
            first_call = pool.submit(shared.resolve, ["5"])
            self.assertTrue(started.wait(10))
            second_call = pool.submit(shared.resolve, ["5", "6"])
            release.set()
            first, second = first_call.result(10), second_call.result(10)
        self.assertEqual(asked, ["5", "6"])
        self.assertEqual(first, {"5": [{"public_key_version": "1"}]})
        self.assertEqual(
            second,
            {"5": [{"public_key_version": "1"}], "6": [{"public_key_version": "2"}]},
        )

        # A lookup that fails is logged, leaves its user out of the answer
        # and is not kept: the next call fetches again.
        with self.assertLogs("chatbot", level="WARNING") as logs:
            self.assertEqual(shared.resolve(["7", "6"]), {"6": [{"public_key_version": "2"}]})
        self.assertIn("public_keys_fetch_failed user=7", logs.output[0])
        failing.clear()
        self.assertEqual(shared.resolve(["7"]), {"7": [{"public_key_version": "4"}]})
        self.assertEqual(asked, ["5", "6", "7", "7"])

        # An answer is served until its time is up, then fetched again.
        clock.now += 99.0
        self.assertEqual(shared.resolve(["5"]), first)
        self.assertEqual(len(asked), 4)
        clock.now += 1.0
        self.assertEqual(shared.resolve(["5"]), {"5": [{"public_key_version": "5"}]})


if __name__ == "__main__":
    unittest.main()
