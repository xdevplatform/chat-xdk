import base64
import gc
import http.server
import json
import os
import sys
import threading
import time
import unittest
import urllib.parse
from unittest import mock

# Keep every chat's automatic feature fetch off the network unless a test
# points it at its own server.
os.environ.setdefault("CHAT_XDK_FEATURES_ENDPOINT", "http://127.0.0.1:9/2/chat/features")


def _repo_root() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))


def _load_vectors() -> dict:
    path = os.path.join(_repo_root(), "tests", "fixtures", "sdk_vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


class _FeatureServer:
    """A local GET /2/chat/features that records each request's bucket."""

    def __init__(self):
        self.status = 200
        self.body = '{"features":{"v1_send":true}}'
        self.delay = 0.0
        self.buckets = []
        server = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                # The answer is fixed before the request is recorded, so a
                # test that sees the request can change the next answer.
                status, body = server.status, server.body.encode("utf-8")
                query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                server.buckets.append(query.get("bucket", [None])[0])
                if server.delay:
                    time.sleep(server.delay)
                try:
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, *args):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.url = "http://127.0.0.1:%d/2/chat/features" % self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def _wait_for(predicate, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


class TestFeatureSwitches(unittest.TestCase):
    """Every Chat fetches GET /2/chat/features by itself; nothing is called."""

    @classmethod
    def setUpClass(cls):
        py_src = os.path.join(_repo_root(), "crates", "pyo3", "python")
        if py_src not in sys.path:
            sys.path.insert(0, py_src)
        try:
            import chat_xdk  # noqa: F401
        except Exception as e:  # pragma: no cover
            raise unittest.SkipTest(f"chat_xdk extension not importable in this Python: {e!r}")

    def setUp(self):
        import chat_xdk

        self.server = _FeatureServer()
        self.vectors = _load_vectors()
        # The internal test hooks: the endpoint and shorter timings.
        patches = [
            mock.patch.dict(os.environ, {"CHAT_XDK_FEATURES_ENDPOINT": self.server.url}),
            mock.patch.object(chat_xdk, "_FEATURE_TIMEOUT_SECONDS", 0.5),
            mock.patch.object(chat_xdk, "_FEATURE_REFRESH_SECONDS", 3600.0),
            mock.patch.object(chat_xdk, "_FEATURE_KEY_POLL_SECONDS", 0.02),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def tearDown(self):
        self.server.close()

    def _chat(self, with_keys=True):
        from chat_xdk import Chat

        chat = Chat()
        if with_keys:
            self._import_keys(chat)
        return chat

    def _import_keys(self, chat):
        chat.import_keys(base64.b64decode(self.vectors["private_keys_concat_b64"]))
        chat.set_identity("1001", "1")

    def _keyed_request(self, chat):
        """Wait for a request carrying ``chat``'s key bucket."""
        bucket = str(chat._feature_bucket())
        self.assertTrue(_wait_for(lambda: bucket in self.server.buckets), self.server.buckets)

    def _send(self, chat):
        from chat_xdk import EncryptMessageParams

        return chat.encrypt_message(
            EncryptMessageParams(
                "conv-1",
                "hello",
                conversation_key=base64.b64decode(self.vectors["conversation_key_b64"]),
                conversation_key_version="1",
            )
        )

    def test_feature_switches_are_not_public_api(self):
        import chat_xdk

        chat = self._chat(with_keys=False)
        for name in [
            "load_feature_config",
            "is_enabled",
            "feature_bucket",
            "apply_feature_config",
            "feature_refetch_due",
        ]:
            self.assertFalse(hasattr(chat, name), name)
        for name in ["FEATURES_ENDPOINT", "LoadFeatureConfigParams"]:
            self.assertFalse(hasattr(chat_xdk, name), name)
            self.assertNotIn(name, chat_xdk.__all__)

    def test_creating_a_chat_never_waits_for_the_fetch(self):
        self.server.delay = 2.0
        started = time.monotonic()
        chat = self._chat()
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertEqual(self._send(chat).signature_info.signature_version, "7")

    def test_every_flag_is_off_and_sends_are_v0_until_a_response_applies(self):
        self.server.status = 503
        chat = self._chat()
        self._keyed_request(chat)
        self.assertFalse(chat._is_enabled("v1_send"))
        payload = self._send(chat)
        self.assertEqual(payload.signature_info.signature_version, "7")
        self.assertTrue(payload.xdk_version)

    def test_a_chat_fetches_on_creation_and_again_with_the_key_bucket(self):
        chat = self._chat(with_keys=False)
        self.assertIsNone(chat._feature_bucket())
        self.assertTrue(_wait_for(lambda: self.server.buckets == [None]), self.server.buckets)

        self._import_keys(chat)
        bucket = chat._feature_bucket()
        self.assertIsInstance(bucket, int)
        self.assertTrue(0 <= bucket < 10000)
        self._keyed_request(chat)
        self.assertTrue(_wait_for(lambda: chat._is_enabled("v1_send")))
        self.assertFalse(chat._feature_refetch_due())
        self.assertEqual(self._send(chat).signature_info.signature_version, "10")

    def test_the_key_bucket_answer_replaces_the_ip_answer(self):
        # An IP-bucketed "on" reads off once keys load, and the key's own
        # answer decides.
        chat = self._chat(with_keys=False)
        self.assertTrue(_wait_for(lambda: chat._is_enabled("v1_send")))
        self.server.body = '{"features":{"v1_send":false}}'
        self._import_keys(chat)
        self.assertFalse(chat._is_enabled("v1_send"))
        self._keyed_request(chat)
        self.assertTrue(_wait_for(lambda: not chat._feature_refetch_due()))
        self.assertFalse(chat._is_enabled("v1_send"))

        # ...and the key's answer can turn a flag on that the IP answer left off.
        self.server.body = '{"features":{"v1_send":false}}'
        chat2 = self._chat(with_keys=False)
        self.assertTrue(_wait_for(lambda: len(self.server.buckets) >= 3))
        self.server.body = '{"features":{"v1_send":true}}'
        self._import_keys(chat2)
        self.assertTrue(_wait_for(lambda: chat2._is_enabled("v1_send")))

    def test_unknown_keys_are_readable_and_missing_keys_are_off(self):
        self.server.body = '{"features":{"later_flag":true,"v1_send":"yes"},"extra":1}'
        chat = self._chat()
        self.assertTrue(_wait_for(lambda: chat._is_enabled("later_flag")))
        self.assertFalse(chat._is_enabled("v1_send"))
        self.assertFalse(chat._is_enabled("missing"))

    def test_any_failure_leaves_every_flag_off(self):
        cases = [
            (404, '{"features":{"v1_send":true}}', 0.0),
            (500, '{"features":{"v1_send":true}}', 0.0),
            (200, "not json", 0.0),
            (200, '{"v1_send":true}', 0.0),
            (200, '{"features":{"v1_send":true}}', 1.5),
        ]
        for status, body, delay in cases:
            with self.subTest(status=status, body=body, delay=delay):
                self.server.status, self.server.body, self.server.delay = status, body, delay
                self.server.buckets.clear()
                chat = self._chat()
                self._keyed_request(chat)
                time.sleep(0.6 if delay else 0.1)
                self.assertFalse(chat._is_enabled("v1_send"))
                self.assertEqual(self._send(chat).signature_info.signature_version, "7")

    def test_an_unreachable_endpoint_leaves_every_flag_off(self):
        url = self.server.url
        self.server.close()
        self.server = _FeatureServer()
        with mock.patch.dict(os.environ, {"CHAT_XDK_FEATURES_ENDPOINT": url}):
            chat = self._chat()
        time.sleep(0.3)
        self.assertFalse(chat._is_enabled("v1_send"))
        self.assertTrue(chat._feature_refetch_due())
        self.assertEqual(self._send(chat).signature_info.signature_version, "7")

    def test_the_recheck_turns_flags_off_but_never_on(self):
        import chat_xdk

        with mock.patch.object(chat_xdk, "_FEATURE_REFRESH_SECONDS", 0.3):
            chat = self._chat()
        self.assertTrue(_wait_for(lambda: chat._is_enabled("v1_send")))

        self.server.body = '{"features":{}}'
        self.assertTrue(_wait_for(lambda: not chat._is_enabled("v1_send")))
        self.assertEqual(self._send(chat).signature_info.signature_version, "7")

        self.server.body = '{"features":{"v1_send":true}}'
        seen = len(self.server.buckets)
        self.assertTrue(_wait_for(lambda: len(self.server.buckets) >= seen + 2))
        self.assertFalse(chat._is_enabled("v1_send"))

    def test_a_failed_recheck_changes_nothing(self):
        import chat_xdk

        with mock.patch.object(chat_xdk, "_FEATURE_REFRESH_SECONDS", 0.3):
            chat = self._chat()
        self.assertTrue(_wait_for(lambda: chat._is_enabled("v1_send")))
        self.server.status = 503
        seen = len(self.server.buckets)
        self.assertTrue(_wait_for(lambda: len(self.server.buckets) >= seen + 2))
        self.assertTrue(chat._is_enabled("v1_send"))

    def test_the_refresher_ends_with_the_chat(self):
        import chat_xdk

        with mock.patch.object(chat_xdk, "_FEATURE_REFRESH_SECONDS", 0.3):
            chat = self._chat()
        self.assertTrue(_wait_for(lambda: chat._is_enabled("v1_send")))
        del chat
        gc.collect()
        time.sleep(0.8)
        seen = len(self.server.buckets)
        time.sleep(1.2)
        self.assertEqual(len(self.server.buckets), seen)

    def test_a_malformed_body_is_rejected_and_changes_nothing(self):
        # The fetch never applies anything, so only the calls below change
        # the flags.
        self.server.status = 503
        chat = self._chat()
        self._keyed_request(chat)
        bucket = chat._feature_bucket()
        chat._apply_feature_config('{"features":{"v1_send":true}}', bucket)
        with self.assertRaises(ValueError):
            chat._apply_feature_config("[]", bucket, True)
        self.assertTrue(chat._is_enabled("v1_send"))
        chat._apply_feature_config('{"features":{}}', bucket, True)
        self.assertFalse(chat._is_enabled("v1_send"))


if __name__ == "__main__":
    unittest.main()
