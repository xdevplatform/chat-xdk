import base64
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
    nothing is called, and each chat is pointed at a local server through the
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

    def _chat(self, timeout=2.0, recheck=3600.0, first_retry=0.05, keys=None):
        from chat_xdk import Chat, ImportKeysParams, SetIdentityParams

        chat = Chat()
        chat._configure_features(self.server.url, timeout, recheck, first_retry)
        if keys is None:
            keys = base64.b64decode(self.vectors["private_keys_concat_b64"])
        chat.import_keys(ImportKeysParams(keys))
        chat.set_identity(SetIdentityParams("1001", "1"))
        return chat

    def _send(self, chat):
        """The signature version of a send: "7" for v0, "10" for v1."""
        from chat_xdk import EncryptMessageParams

        return chat.encrypt_message(
            EncryptMessageParams(
                "conv-1",
                "hello",
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

    def test_no_request_is_made_until_the_first_send(self):
        chat = self._chat()
        time.sleep(0.3)
        self.assertEqual(self.server.buckets, [])

        self.assertEqual(self._send(chat), "7", "the first send does not wait for the answer")
        self.assertTrue(self._wait_for(lambda: len(self.server.buckets) == 1), self.server.buckets)
        bucket = int(self.server.buckets[0])
        self.assertTrue(0 <= bucket < 10000)

    def test_v1_starts_once_the_answer_turns_it_on(self):
        chat = self._chat()
        self.assertEqual(self._send(chat), "7")
        self.assertTrue(self._wait_for(lambda: self._send(chat) == "10"))
        self.assertEqual(len(self.server.buckets), 1)

    def test_a_send_never_waits_for_the_request(self):
        self.server.delay = 2.0
        chat = self._chat()
        started = time.monotonic()
        self.assertEqual(self._send(chat), "7")
        self.assertLess(time.monotonic() - started, 1.0)

    def test_chats_with_one_key_share_one_request(self):
        self.server.delay = 0.3
        chats = [self._chat() for _ in range(4)]
        for chat in chats:
            self.assertEqual(self._send(chat), "7")
        self.assertTrue(self._wait_for(lambda: all(self._send(c) == "10" for c in chats)))
        self.assertEqual(len(self.server.buckets), 1, self.server.buckets)

        later = self._chat()
        self.assertEqual(self._send(later), "10", "a later chat takes the answer at hand")
        self.assertEqual(len(self.server.buckets), 1)

    def test_chats_with_different_keys_ask_separately(self):
        from chat_xdk import Chat

        other_keys = Chat()
        other_keys.generate_keypairs()
        first = self._chat()
        second = self._chat(keys=bytes(other_keys.export_keys()))
        self._send(first)
        self._send(second)
        self.assertTrue(self._wait_for(lambda: len(self.server.buckets) == 2), self.server.buckets)
        self.assertNotEqual(self.server.buckets[0], self.server.buckets[1])

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
                # A server of its own: chats share an answer per endpoint and
                # bucket, and the case before may have left one.
                self.server.close()
                self.server = FeatureServer(body)
                self.server.status, self.server.delay = status, delay
                chat = self._chat(timeout=0.5, first_retry=60.0)
                self.assertEqual(self._send(chat), "7")
                self.assertTrue(self._wait_for(lambda: len(self.server.buckets) == 1))
                time.sleep(1.2 if delay else 0.2)
                self.assertEqual(self._send(chat), "7")

    def test_an_unreachable_endpoint_leaves_sends_on_v0(self):
        from chat_xdk import Chat, ImportKeysParams, SetIdentityParams

        url = self.server.url
        self.server.close()
        chat = Chat()
        chat._configure_features(url, 0.5, 3600.0, 0.05)
        chat.import_keys(ImportKeysParams(base64.b64decode(self.vectors["private_keys_concat_b64"])))
        chat.set_identity(SetIdentityParams("1001", "1"))
        self.assertEqual(self._send(chat), "7")
        time.sleep(0.5)
        self.assertEqual(self._send(chat), "7")
        from features_support import FeatureServer

        self.server = FeatureServer()

    def test_a_request_still_open_at_its_timeout_fails_and_is_retried(self):
        self.server.delay = 3.0
        chat = self._chat(timeout=0.3, first_retry=0.2)
        started = time.monotonic()
        self.assertEqual(self._send(chat), "7")
        self.assertTrue(self._wait_for(lambda: len(self.server.buckets) >= 2, timeout=2.5))
        self.assertLess(time.monotonic() - started, 2.5)
        self.assertEqual(self._send(chat), "7")

    def test_the_recheck_turns_v1_off_and_never_back_on(self):
        chat = self._chat(recheck=0.3)
        self._send(chat)
        self.assertTrue(self._wait_for(lambda: self._send(chat) == "10"))

        self.server.body = '{"features":{}}'
        self.assertTrue(self._wait_for(lambda: self._send(chat) == "7"))

        self.server.body = '{"features":{"v1_send":true}}'
        seen = len(self.server.buckets)
        self.assertTrue(self._wait_for(lambda: len(self.server.buckets) >= seen + 2))
        self.assertEqual(self._send(chat), "7", "a running chat never sees it turn on")
        self.assertEqual(self._send(self._chat(recheck=0.3)), "10", "a new chat takes the latest answer")

    def test_a_failed_recheck_changes_nothing(self):
        chat = self._chat(recheck=0.3)
        self._send(chat)
        self.assertTrue(self._wait_for(lambda: self._send(chat) == "10"))
        self.server.status = 503
        seen = len(self.server.buckets)
        self.assertTrue(self._wait_for(lambda: len(self.server.buckets) >= seen + 2))
        self.assertEqual(self._send(chat), "10")

    def test_close_keeps_the_format_and_stops_the_requests(self):
        chat = self._chat(recheck=0.3)
        self._send(chat)
        self.assertTrue(self._wait_for(lambda: self._send(chat) == "10"))
        chat.close()
        seen = len(self.server.buckets)
        time.sleep(1.0)
        self.assertEqual(len(self.server.buckets), seen, "no request after close()")
        self.assertEqual(self._send(chat), "10")

    def test_a_chat_closed_before_sending_never_asks(self):
        chat = self._chat()
        chat.close()
        self.assertEqual(self._send(chat), "7")
        time.sleep(0.3)
        self.assertEqual(self.server.buckets, [])

    def test_the_driver_ends_with_the_last_chat(self):
        # In a process of its own, so no chat of another test keeps the driver
        # running.
        script = textwrap.dedent(
            """
            import base64, gc, json, sys, threading, time
            from chat_xdk import Chat, EncryptMessageParams, ImportKeysParams, SetIdentityParams
            from features_support import FeatureServer, keep_offline, wait_for

            keep_offline()
            vectors = json.load(open(sys.argv[1]))
            server = FeatureServer()

            def drivers():
                return [t for t in threading.enumerate() if t.name == "chat-xdk-features"]

            def send(chat):
                return chat.encrypt_message(EncryptMessageParams(
                    "conv-1", "hello",
                    conversation_key=base64.b64decode(vectors["conversation_key_b64"]),
                    conversation_key_version="1",
                )).signature_info.signature_version

            assert not drivers(), "no driver before a send"
            chats = []
            for _ in range(3):
                chat = Chat()
                chat._configure_features(server.url, 2.0, 0.3, 0.05)
                chat.import_keys(ImportKeysParams(base64.b64decode(vectors["private_keys_concat_b64"])))
                chat.set_identity(SetIdentityParams("1001", "1"))
                chats.append(chat)
            for chat in chats:
                send(chat)
            assert wait_for(lambda: all(send(c) == "10" for c in chats))
            assert len(drivers()) == 1, drivers()
            assert wait_for(lambda: len(server.buckets) >= 3), "re-checks run while chats remain"

            chats[0].close()
            del chat, chats
            gc.collect()
            assert wait_for(lambda: not drivers(), timeout=3.0), drivers()
            seen = len(server.buckets)
            time.sleep(1.0)
            assert len(server.buckets) == seen, "no request once no chat remains"
            print("ok")
            """
        )
        tests_dir = os.path.dirname(os.path.abspath(__file__))
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(
            [os.path.join(_repo_root(), "crates", "pyo3", "python"), tests_dir, env.get("PYTHONPATH", "")]
        )
        vectors = os.path.join(_repo_root(), "tests", "fixtures", "sdk_vectors.json")
        result = subprocess.run(
            [sys.executable, "-c", script, vectors], env=env, capture_output=True, text=True, timeout=60
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "ok")

    def test_a_script_that_never_sends_makes_no_request(self):
        script = textwrap.dedent(
            """
            import base64, json, sys
            import chat_xdk
            from chat_xdk import Chat, ImportKeysParams, SetIdentityParams
            chat_xdk._native._feature_set_default_endpoint(sys.argv[2])
            vectors = json.load(open(sys.argv[1]))
            chat = Chat()
            chat.import_keys(ImportKeysParams(base64.b64decode(vectors["private_keys_concat_b64"])))
            chat.set_identity(SetIdentityParams("1001", "1"))
            """
        )
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(
            [os.path.join(_repo_root(), "crates", "pyo3", "python"), env.get("PYTHONPATH", "")]
        )
        vectors = os.path.join(_repo_root(), "tests", "fixtures", "sdk_vectors.json")
        result = subprocess.run(
            [sys.executable, "-c", script, vectors, self.server.url],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.server.buckets, [])

if __name__ == "__main__":
    unittest.main()
