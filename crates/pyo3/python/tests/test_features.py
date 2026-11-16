import base64
import gc
import json
import os
import subprocess
import sys
import tempfile
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

    def _run(self, script, *args, env=None):
        """Run ``script`` in a Python process of its own, for a test that sets
        environment variables, forks or exits: what it printed. The script
        has ``keyed(chat)``, which gives a chat its keys, and ``send(chat)``,
        the signature version of a send; ``env`` replaces every proxy
        variable of this process."""
        prelude = textwrap.dedent(
            """
            import base64, os, sys, time
            import chat_xdk
            from chat_xdk import EncryptMessageParams, ImportKeysParams
            from features_support import FeatureServer, keep_offline, reading, wait_for

            keep_offline()

            def keyed(chat):
                chat.import_keys(ImportKeysParams(base64.b64decode(os.environ["TEST_PRIVATE_KEYS"])))
                return chat

            def send(chat):
                return chat.encrypt_message(
                    EncryptMessageParams(
                        "conv-1",
                        "hello",
                        sender_id="1001",
                        signing_key_version="1",
                        conversation_key=bytes(32),
                        conversation_key_version="1",
                    )
                ).signature_info.signature_version
            """
        )
        tests_dir = os.path.dirname(os.path.abspath(__file__))
        environment = {name: value for name, value in os.environ.items() if not name.lower().endswith("_proxy")}
        environment["PYTHONPATH"] = os.pathsep.join(
            [os.path.join(_repo_root(), "crates", "pyo3", "python"), tests_dir, environment.get("PYTHONPATH", "")]
        )
        environment["TEST_PRIVATE_KEYS"] = self.vectors["private_keys_concat_b64"]
        environment.update(env or {})
        result = subprocess.run(
            [sys.executable, "-c", prelude + textwrap.dedent(script), *args],
            env=environment,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

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
        script = """
            chat = reading(sys.argv[1], 60.0)
            assert wait_for(lambda: len(chat_xdk._requests) == 1), "no request under way"
            (request,) = list(chat_xdk._requests)
            started = time.monotonic()
            chat_xdk._end_feature_requests()
            assert time.monotonic() - started < 1.0, time.monotonic() - started
            assert not request.is_alive() and not chat_xdk._requests
            print("ok")
            """
        self.assertEqual(self._run(script, self.server.url), "ok")

    def test_a_chat_created_after_the_last_one_is_gone_takes_its_answer(self):
        self.server.delay = 0.3
        first = self._chat()
        self.assertEqual(self._send(first), "7", "sent before the answer")
        del first
        gc.collect()
        time.sleep(0.8)
        for _ in range(5):
            chat = self._chat()
            self.assertEqual(self._send(chat), "10", "the first send of a chat created after the answer")
            del chat
            gc.collect()
        time.sleep(0.2)
        self.assertEqual(len(self.server.queries), 1, self.server.queries)

    def test_a_chat_that_takes_a_kept_answer_follows_its_refresh(self):
        self.server.delay = 0.2
        self._chat(refresh=1.0)
        gc.collect()
        time.sleep(0.6)
        chat = self._chat(refresh=1.0)
        self.assertEqual(self._send(chat), "10")
        self.assertEqual(len(self.server.queries), 1, "no request before the refresh is due")
        self.server.body = '{"features":{}}'
        self.assertTrue(self._wait_for(lambda: self._send(chat) == "7"), "the refresh reached it")
        self.assertEqual(len(self.server.queries), 2, self.server.queries)

    def test_a_kept_answer_ages_out_at_the_refresh_interval(self):
        self.server.delay = 0.2
        self._chat(refresh=0.5)
        gc.collect()
        time.sleep(1.2)
        self.assertEqual(len(self.server.queries), 1, "no chat, no refresh")
        late = self._chat(refresh=0.5)
        self.assertEqual(self._send(late), "7", "an answer older than the refresh interval is none")
        self.assertTrue(self._wait_for(lambda: self._send(late) == "10"), "its own read answers")
        self.assertEqual(len(self.server.queries), 2, self.server.queries)

    def test_many_waiting_reads_hold_one_thread(self):
        import threading

        from features_support import FeatureServer

        servers = [FeatureServer() for _ in range(8)]
        try:
            chats = [self._chat(url=server.url) for server in servers]
            self.assertTrue(self._wait_for(lambda: all(self._send(chat) == "10" for chat in chats)))
            time.sleep(0.2)
            waiting = [thread.name for thread in threading.enumerate() if thread.name.startswith("chat-xdk-features")]
            self.assertEqual(waiting, ["chat-xdk-features-timer"], "one thread waits for every refresh")
        finally:
            for server in servers:
                server.close()

    def test_the_read_goes_through_the_proxy_the_environment_names(self):
        from features_support import PROXY_ONLY_HOST, RecordingProxy

        proxy = RecordingProxy({PROXY_ONLY_HOST: self.server.port})
        self.addCleanup(proxy.close)
        url = "http://%s%s" % (PROXY_ONLY_HOST, self.server.path)
        script = """
            chat = keyed(reading(sys.argv[1], 2.0))
            print(wait_for(lambda: send(chat) == "10", float(sys.argv[2])))
            """
        self.assertEqual(self._run(script, url, "1.0"), "False", "no proxy, no route to the endpoint")
        self.assertEqual(proxy.requests, [])
        for variable in ("HTTP_PROXY", "http_proxy", "ALL_PROXY"):
            with self.subTest(variable=variable):
                del proxy.requests[:], proxy.headers[:], self.server.headers[:]
                proxied = {variable: "http://user:p%40ss@" + proxy.address}
                self.assertEqual(self._run(script, url, "5.0", env=proxied), "True")
                self.assertEqual(proxy.requests, ["GET %s HTTP/1.1" % url])
                credentials = base64.b64encode(b"user:p@ss").decode()
                self.assertEqual(proxy.headers[0].get("proxy-authorization"), "Basic " + credentials)
                names = {name.lower() for name in self.server.headers[0]}
                self.assertFalse({"authorization", "proxy-authorization", "cookie"} & names, names)

    def test_no_proxy_exempts_the_endpoint(self):
        from features_support import RecordingProxy

        proxy = RecordingProxy()
        self.addCleanup(proxy.close)
        script = """
            chat = keyed(reading(sys.argv[1], 2.0))
            print(wait_for(lambda: send(chat) == "10", float(sys.argv[2])))
            """
        exempt = {"HTTP_PROXY": proxy.url, "NO_PROXY": "example.com,127.0.0.1"}
        self.assertEqual(self._run(script, self.server.url, "5.0", env=exempt), "True")
        self.assertEqual(proxy.requests, [], "the read connects directly")
        self.assertEqual(self._run(script, self.server.url, "1.0", env={"HTTP_PROXY": proxy.url}), "False")
        self.assertEqual(
            set(proxy.requests),
            {"GET %s HTTP/1.1" % self.server.url},
            "without the exemption each attempt asks the proxy, which has no route",
        )

    def test_an_https_read_tunnels_through_the_proxy(self):
        from features_support import PROXY_ONLY_HOST, FeatureServer, RecordingProxy, self_signed_certificate

        with tempfile.TemporaryDirectory() as directory:
            tls = self_signed_certificate(directory, PROXY_ONLY_HOST)
            if tls is None:
                self.skipTest("the openssl command can't make a certificate here")
            server = FeatureServer(tls=tls)
            self.addCleanup(server.close)
            proxy = RecordingProxy({PROXY_ONLY_HOST: server.port})
            self.addCleanup(proxy.close)
            script = """
                chat = keyed(reading(sys.argv[1], 2.0))
                print(wait_for(lambda: send(chat) == "10", 5.0))
                """
            url = "https://%s%s" % (PROXY_ONLY_HOST, server.path)
            tunnelled = {"HTTPS_PROXY": "http://user:secret@" + proxy.address, "SSL_CERT_FILE": tls[0]}
            self.assertEqual(self._run(script, url, env=tunnelled), "True")
        self.assertEqual(proxy.requests, ["CONNECT %s:443 HTTP/1.1" % PROXY_ONLY_HOST])
        credentials = base64.b64encode(b"user:secret").decode()
        self.assertEqual(proxy.headers[0].get("proxy-authorization"), "Basic " + credentials)
        self.assertEqual(server.queries, [""], "the request itself travels inside the tunnel")
        names = {name.lower() for name in server.headers[0]}
        self.assertFalse({"authorization", "proxy-authorization", "cookie"} & names, names)

    def test_a_proxy_that_refuses_leaves_sends_on_v0(self):
        from features_support import PROXY_ONLY_HOST, RecordingProxy

        proxy = RecordingProxy(refuse=403)
        self.addCleanup(proxy.close)
        script = """
            chat = keyed(reading(sys.argv[1], 2.0))
            time.sleep(0.7)
            print(send(chat))
            """
        refused = {"HTTP_PROXY": proxy.url, "HTTPS_PROXY": proxy.url}
        for scheme in ("http", "https"):
            with self.subTest(scheme=scheme):
                url = "%s://%s%s" % (scheme, PROXY_ONLY_HOST, self.server.path)
                self.assertEqual(self._run(script, url, env=refused), "7")
        self.assertEqual([request.split(" ")[0] for request in proxy.requests], ["GET", "CONNECT"])
        self.assertEqual(self.server.queries, [])

    def test_a_request_imports_no_module_on_its_thread(self):
        # A fork while a request's thread imports a module leaves the child
        # waiting for that import for good; host names need the idna codec.
        script = """
            imported = set(sys.modules)
            chat = keyed(reading(sys.argv[1], 2.0))
            assert wait_for(lambda: send(chat) == "10")
            print("encodings.idna" in imported, sorted(set(sys.modules) - imported))
            """
        self.assertEqual(self._run(script, self.server.url.replace("127.0.0.1", "localhost")), "True []")

    @unittest.skipUnless(hasattr(os, "fork"), "needs os.fork")
    def test_a_forked_child_reads_for_the_chats_it_inherited(self):
        self.server.delay = 1.0
        script = """
            chat = keyed(reading(sys.argv[1], 3.0))
            time.sleep(0.3)  # the request is under way, waiting for its answer
            pid = os.fork()
            if pid == 0:
                os._exit(0 if wait_for(lambda: send(chat) == "10", 5.0) else 1)
            _, status = os.waitpid(pid, 0)
            print(os.waitstatus_to_exitcode(status), wait_for(lambda: send(chat) == "10", 5.0))
            """
        self.assertEqual(self._run(script, self.server.url), "0 True")
        self.assertEqual(len(self.server.queries), 2, "the parent's read, and the child's of its own")

    @unittest.skipUnless(hasattr(os, "fork"), "needs os.fork")
    def test_a_forked_child_follows_the_refreshes_of_an_answer_it_inherited(self):
        script = """
            server = FeatureServer()
            chat = keyed(reading(server.url, 2.0, 0.5))
            assert wait_for(lambda: send(chat) == "10")
            pid = os.fork()
            if pid == 0:
                os._exit(0 if wait_for(lambda: send(chat) == "7", 5.0) else 1)
            server.body = '{"features":{}}'
            _, status = os.waitpid(pid, 0)
            print(os.waitstatus_to_exitcode(status), wait_for(lambda: send(chat) == "7", 5.0))
            """
        self.assertEqual(self._run(script), "0 True")


if __name__ == "__main__":
    unittest.main()
