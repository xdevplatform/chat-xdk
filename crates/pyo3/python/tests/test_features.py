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
                query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                server.buckets.append(query.get("bucket", [None])[0])
                if server.delay:
                    time.sleep(server.delay)
                body = server.body.encode("utf-8")
                try:
                    self.send_response(server.status)
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
        time.sleep(0.05)
    return predicate()


class TestFeatureSwitches(unittest.TestCase):
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
        self.server = _FeatureServer()
        self.vectors = _load_vectors()

    def tearDown(self):
        self.server.close()

    def _params(self, **kwargs):
        from chat_xdk import LoadFeatureConfigParams

        kwargs.setdefault("timeout_ms", 1000)
        kwargs.setdefault("refresh_seconds", 0)
        return LoadFeatureConfigParams(endpoint=self.server.url, **kwargs)

    def _chat(self, with_keys=True):
        from chat_xdk import Chat

        chat = Chat()
        if with_keys:
            self._import_keys(chat)
        return chat

    def _import_keys(self, chat):
        chat.import_keys(base64.b64decode(self.vectors["private_keys_concat_b64"]))
        chat.set_identity("1001", "1")

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

    def test_every_flag_is_off_and_sends_are_v0_before_any_load(self):
        chat = self._chat()
        self.assertFalse(chat.is_enabled("v1_send"))
        payload = self._send(chat)
        self.assertEqual(payload.signature_info.signature_version, "7")
        self.assertTrue(payload.xdk_version)

    def test_a_load_after_keys_sends_the_key_bucket_and_switches_to_v1(self):
        chat = self._chat()
        bucket = chat.feature_bucket()
        self.assertIsInstance(bucket, int)
        self.assertTrue(0 <= bucket < 10000)

        self.assertTrue(chat.load_feature_config(self._params()))
        self.assertEqual(self.server.buckets, [str(bucket)])
        self.assertTrue(chat.is_enabled("v1_send"))
        self.assertEqual(self._send(chat).signature_info.signature_version, "10")

    def test_unknown_keys_are_readable_and_missing_keys_are_off(self):
        self.server.body = '{"features":{"later_flag":true,"v1_send":"yes"},"extra":1}'
        chat = self._chat()
        self.assertTrue(chat.load_feature_config(self._params()))
        self.assertTrue(chat.is_enabled("later_flag"))
        self.assertFalse(chat.is_enabled("v1_send"))
        self.assertFalse(chat.is_enabled("missing"))

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
                chat = self._chat()
                self.assertFalse(chat.load_feature_config(self._params(timeout_ms=300)))
                self.assertFalse(chat.is_enabled("v1_send"))
                self.assertEqual(self._send(chat).signature_info.signature_version, "7")

    def test_an_unreachable_endpoint_leaves_every_flag_off(self):
        from chat_xdk import LoadFeatureConfigParams

        url = self.server.url
        self.server.close()
        self.server = _FeatureServer()
        chat = self._chat()
        params = LoadFeatureConfigParams(endpoint=url, timeout_ms=300, refresh_seconds=0)
        self.assertFalse(chat.load_feature_config(params))
        self.assertFalse(chat.is_enabled("v1_send"))

    def test_a_load_before_keys_refetches_once_with_the_key_bucket(self):
        chat = self._chat(with_keys=False)
        self.assertIsNone(chat.feature_bucket())
        self.assertTrue(chat.load_feature_config(self._params()))
        self.assertEqual(self.server.buckets, [None])
        self.assertTrue(chat.is_enabled("v1_send"))

        self.server.body = '{"features":{"v1_send":false}}'
        self._import_keys(chat)
        bucket = str(chat.feature_bucket())
        self.assertTrue(_wait_for(lambda: bucket in self.server.buckets))
        self.assertTrue(_wait_for(lambda: not chat.feature_refetch_due()))
        self.assertFalse(chat.is_enabled("v1_send"))

        self.server.body = '{"features":{"v1_send":true}}'
        chat2 = self._chat(with_keys=False)
        self.server.body = '{"features":{"v1_send":false}}'
        self.assertTrue(chat2.load_feature_config(self._params()))
        self.server.body = '{"features":{"v1_send":true}}'
        self._import_keys(chat2)
        self.assertFalse(chat2.is_enabled("v1_send"))
        self.assertTrue(_wait_for(lambda: chat2.is_enabled("v1_send")))

    def test_the_recheck_turns_flags_off_but_never_on(self):
        chat = self._chat()
        self.assertTrue(chat.load_feature_config(self._params(refresh_seconds=1)))
        self.assertTrue(chat.is_enabled("v1_send"))

        self.server.body = '{"features":{}}'
        self.assertTrue(_wait_for(lambda: not chat.is_enabled("v1_send")))
        self.assertEqual(self._send(chat).signature_info.signature_version, "7")

        self.server.body = '{"features":{"v1_send":true}}'
        seen = len(self.server.buckets)
        self.assertTrue(_wait_for(lambda: len(self.server.buckets) >= seen + 2))
        self.assertFalse(chat.is_enabled("v1_send"))

    def test_a_failed_recheck_changes_nothing(self):
        chat = self._chat()
        self.assertTrue(chat.load_feature_config(self._params(refresh_seconds=1)))
        self.server.status = 503
        seen = len(self.server.buckets)
        self.assertTrue(_wait_for(lambda: len(self.server.buckets) >= seen + 2))
        self.assertTrue(chat.is_enabled("v1_send"))

    def test_the_refresher_ends_with_the_chat(self):
        chat = self._chat()
        self.assertTrue(chat.load_feature_config(self._params(refresh_seconds=1)))
        del chat
        gc.collect()
        time.sleep(1.5)
        seen = len(self.server.buckets)
        time.sleep(2.5)
        self.assertEqual(len(self.server.buckets), seen)

    def test_apply_feature_config_rejects_a_malformed_body(self):
        chat = self._chat()
        chat.apply_feature_config('{"features":{"v1_send":true}}', chat.feature_bucket())
        with self.assertRaises(ValueError):
            chat.apply_feature_config("[]", chat.feature_bucket(), True)
        self.assertTrue(chat.is_enabled("v1_send"))
        chat.apply_feature_config('{"features":{}}', chat.feature_bucket(), True)
        self.assertFalse(chat.is_enabled("v1_send"))


if __name__ == "__main__":
    unittest.main()
