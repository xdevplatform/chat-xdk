import base64
import gc
import json
import os
import subprocess
import sys
import textwrap
import time
import unittest


def _repo_root() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))


def _load_vectors() -> dict:
    path = os.path.join(_repo_root(), "tests", "fixtures", "sdk_vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


class TestFeatureSwitches(unittest.TestCase):
    """The feature switches (GET /2/chat/features) through the real package:
    nothing is called, and each chat reads from a local server through the
    internal hook."""

    @classmethod
    def setUpClass(cls):
        py_src = os.path.join(_repo_root(), "crates", "pyo3", "python")
        if py_src not in sys.path:
            sys.path.insert(0, py_src)
        try:
            import chat_xdk  # noqa: F401
        except Exception as e:  # pragma: no cover
            raise unittest.SkipTest(f"chat_xdk extension not importable in this Python: {e!r}")
        from features_support import keep_offline

        keep_offline()

    def setUp(self):
        from features_support import FeatureServer

        self.server = FeatureServer()
        self.vectors = _load_vectors()

    def tearDown(self):
        self.server.close()

    def _chat(self, timeout=2.0, url=None, refresh=300.0, user_id=None):
        """A chat with keys that reads ``url`` (the test server's by default)
        within ``timeout`` seconds, again ``refresh`` seconds after each
        answer. With ``user_id`` it sets that session identity, so it reads
        its sender's bucket."""
        from chat_xdk import ImportKeysParams, SetIdentityParams
        from features_support import reading

        chat = reading(url or self.server.url, timeout, refresh)
        chat.import_keys(ImportKeysParams(base64.b64decode(self.vectors["private_keys_concat_b64"])))
        if user_id is not None:
            chat.set_identity(SetIdentityParams(user_id, "1"))
        return chat

    def _send(self, chat):
        """The signature version of a send: "7" for v0, "10" for v1."""
        from chat_xdk import EncryptMessageParams

        return chat.encrypt_message(
            EncryptMessageParams(
                "conv-1",
                "hello",
                sender_id="1001",
                signing_key_version="1",
                conversation_key=base64.b64decode(self.vectors["conversation_key_b64"]),
                conversation_key_version="1",
            )
        ).signature_info.signature_version

    def _wait_for(self, predicate, timeout=10.0):
        from features_support import wait_for

        return wait_for(predicate, timeout)

    def test_feature_switches_are_not_public_api(self):
        import chat_xdk

        public = [name for name in dir(chat_xdk.Chat()) + dir(chat_xdk) if not name.startswith("_")]
        self.assertEqual([name for name in public + chat_xdk.__all__ if "feature" in name.lower()], [])

    def test_a_chat_reads_its_senders_bucket_once_its_identity_is_set(self):
        from chat_xdk import SetIdentityParams

        chat = self._chat()
        self.assertTrue(self._wait_for(lambda: len(self.server.queries) == 1), self.server.queries)
        self.assertEqual(self.server.queries[0], "", "no identity: no bucket")
        self.assertTrue(self._wait_for(lambda: self._send(chat) == "10"))
        chat.set_identity(SetIdentityParams("1234561001", "1"))
        self.assertTrue(self._wait_for(lambda: len(self.server.queries) == 2), self.server.queries)
        self.assertEqual(self.server.queries[1], "bucket=1001", "the user id's last four digits")
        self.assertTrue(self._wait_for(lambda: self._send(chat) == "10"))
        chat.set_identity(SetIdentityParams("9991001", "1"))
        for _ in range(5):
            self._send(chat)
        time.sleep(0.3)
        self.assertEqual(len(self.server.queries), 2, "the same bucket: no new read")

    def test_chats_of_one_sender_share_their_buckets_read(self):
        self.server.delay = 0.5
        first = self._chat(user_id="1001")
        second = self._chat(user_id="51001")
        other = self._chat(user_id="2002")
        self.assertTrue(self._wait_for(lambda: all(self._send(c) == "10" for c in (first, second, other))))
        bucketed = sorted(query for query in self.server.queries if query)
        self.assertEqual(bucketed, ["bucket=1001", "bucket=2002"], self.server.queries)

    def test_a_refresh_reaches_a_running_chat(self):
        chat = self._chat(refresh=0.3)
        self.assertTrue(self._wait_for(lambda: self._send(chat) == "10"))
        self.server.body = '{"features":{}}'
        self.assertTrue(self._wait_for(lambda: self._send(chat) == "7"), "the refresh turned v1 off")
        self.server.body = '{"features":{"v1_send":true}}'
        self.assertTrue(self._wait_for(lambda: self._send(chat) == "10"), "and on again")

    def test_the_public_constructor_reads_the_default_endpoint(self):
        import chat_xdk
        from chat_xdk import ImportKeysParams, SetIdentityParams
        from features_support import keep_offline

        chat_xdk._native._feature_set_default_endpoint(self.server.url)
        try:
            chat = chat_xdk.Chat()
            self.assertTrue(self._wait_for(lambda: len(self.server.queries) == 1))
            chat.import_keys(ImportKeysParams(base64.b64decode(self.vectors["private_keys_concat_b64"])))
            chat.set_identity(SetIdentityParams("1001", "1"))
            self.assertTrue(self._wait_for(lambda: self._send(chat) == "10"))
        finally:
            keep_offline()

    def test_a_send_never_waits_for_the_request(self):
        self.server.delay = 2.0
        chat = self._chat(timeout=3.0)
        started = time.monotonic()
        self.assertEqual(self._send(chat), "7")
        self.assertLess(time.monotonic() - started, 1.0)

    def test_chats_created_while_a_request_is_in_flight_share_it(self):
        self.server.delay = 0.8
        chats = [self._chat() for _ in range(4)]
        self.assertTrue(self._wait_for(lambda: all(self._send(c) == "10" for c in chats)))
        self.assertEqual(len(self.server.queries), 1, self.server.queries)

        later = self._chat()
        self.assertEqual(self._send(later), "10", "a later chat takes the latest answer at once")
        time.sleep(0.2)
        self.assertEqual(len(self.server.queries), 1, self.server.queries)

    def test_a_read_that_cannot_start_leaves_the_next_chat_its_own(self):
        import types
        from unittest import mock

        import chat_xdk

        class Unstartable(chat_xdk._threading.Thread):
            def start(self):
                raise RuntimeError("can't start new thread")

        with mock.patch.object(chat_xdk, "_threading", types.SimpleNamespace(Thread=Unstartable)):
            stranded = self._chat()
        self.assertEqual(self._send(stranded), "7", "a read that never started leaves sends on v0")
        later = self._chat()
        self.assertTrue(self._wait_for(lambda: self._send(later) == "10"), "the next chat reads for itself")
        self.assertEqual(len(self.server.queries), 1, self.server.queries)
        self.assertEqual(self._send(stranded), "10", "the next chat's read answers the stranded chat")

    def test_the_answer_holds_until_the_next_refresh(self):
        chat = self._chat()
        self.assertTrue(self._wait_for(lambda: self._send(chat) == "10"))
        self.server.body = '{"features":{}}'
        other = self._chat()
        time.sleep(0.3)
        self.assertEqual(len(self.server.queries), 1, self.server.queries)
        self.assertEqual(self._send(other), "10", "the later chat takes the latest answer")
        self.assertEqual(self._send(chat), "10", "the answer holds until the refresh")

    def test_any_failure_leaves_sends_on_v0(self):
        cases = [
            (404, '{"features":{"v1_send":true}}', 0.0),
            (500, '{"features":{"v1_send":true}}', 0.0),
            (200, "not json", 0.0),
            (200, '{"v1_send":true}', 0.0),
            (200, '{"features":{"v1_send":"true"}}', 0.0),
            (200, '{"features":{"v1_send":true}}' + " " * (64 * 1024), 0.0),
            (200, '{"features":{"v1_send":true}}', 1.0),
        ]
        from features_support import FeatureServer

        for status, body, delay in cases:
            with self.subTest(status=status, body=body[:40], size=len(body), delay=delay):
                self.server.close()
                self.server = FeatureServer(body)
                self.server.status, self.server.delay = status, delay
                chat = self._chat(timeout=0.5)
                self.assertTrue(self._wait_for(lambda: len(self.server.queries) == 1))
                time.sleep(delay + 0.2)
                self.assertEqual(self._send(chat), "7")

    def test_a_failed_read_is_retried_and_the_retrys_answer_turns_v1_on(self):
        self.server.status = 503
        chat = self._chat()
        self.assertTrue(self._wait_for(lambda: len(self.server.queries) == 1))
        self.server.status = 200
        self.assertEqual(self._send(chat), "7", "the failed read leaves sends on v0")
        self.assertTrue(self._wait_for(lambda: self._send(chat) == "10"), "the retry's answer turns v1 on")
        self.assertEqual(len(self.server.queries), 2, self.server.queries)

    def test_the_read_sends_no_cookies_or_credentials(self):
        self.server.set_cookie = "session=from-the-first-answer; Path=/"
        chat = self._chat(refresh=0.2)
        self.assertTrue(self._wait_for(lambda: self._send(chat) == "10"))
        self.assertTrue(self._wait_for(lambda: len(self.server.queries) >= 2), "a refresh after the cookie")
        for headers in self.server.headers:
            names = {name.lower() for name in headers}
            self.assertNotIn("cookie", names, "the read sends no cookie")
            self.assertNotIn("authorization", names, "the read sends no credentials")

    def test_a_redirect_is_not_followed(self):
        from features_support import REDIRECT_TARGET

        self.server.status, self.server.location = 302, self.server.origin + REDIRECT_TARGET
        chat = self._chat(timeout=0.5)
        self.assertTrue(self._wait_for(lambda: len(self.server.queries) == 1))
        time.sleep(0.7)
        self.assertEqual(self._send(chat), "7", "a redirect is a failed read")
        self.assertEqual(self.server.followed, 0, "the redirect is not followed")

    def test_an_unreachable_endpoint_leaves_sends_on_v0(self):
        url = self.server.url
        self.server.close()
        chat = self._chat(timeout=0.5, url=url)
        time.sleep(0.7)
        self.assertEqual(self._send(chat), "7")
        from features_support import FeatureServer

        self.server = FeatureServer()

    def test_a_request_still_open_at_its_timeout_fails(self):
        self.server.delay = 3.0
        chat = self._chat(timeout=0.3)
        time.sleep(1.0)
        self.assertEqual(self._send(chat), "7")
        self.assertEqual(len(self.server.queries), 1)

    def test_a_request_ends_safely_for_a_collected_chat(self):
        self.server.delay = 0.8
        self._chat()
        gc.collect()
        kept = self._chat()
        self.assertTrue(self._wait_for(lambda: self._send(kept) == "10"))
        self.assertEqual(len(self.server.queries), 1)

    def test_exit_cuts_short_a_request_under_way(self):
        # In a process of its own, since the exit hook ends every request.
        self.server.delay = 30.0
        script = textwrap.dedent(
            """
            import sys, time
            import chat_xdk
            from features_support import keep_offline, reading, wait_for

            keep_offline()
            chat = reading(sys.argv[1], 60.0)
            assert wait_for(lambda: len(chat_xdk._requests) == 1), "no request under way"
            (request,) = list(chat_xdk._requests)
            started = time.monotonic()
            chat_xdk._end_feature_requests()
            assert time.monotonic() - started < 1.0, time.monotonic() - started
            assert not request.is_alive() and not chat_xdk._requests
            print("ok")
            """
        )
        tests_dir = os.path.dirname(os.path.abspath(__file__))
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(
            [os.path.join(_repo_root(), "crates", "pyo3", "python"), tests_dir, env.get("PYTHONPATH", "")]
        )
        result = subprocess.run(
            [sys.executable, "-c", script, self.server.url],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "ok")


if __name__ == "__main__":
    unittest.main()
