"""A local GET /2/chat/features for the tests, and the internal hooks that
point chats at it."""

import http.server
import itertools
import threading
import time
import urllib.parse

# Nothing listens here: a chat no test points at a server of its own reads its
# feature switches from this endpoint, fails, and stays on v0.
OFFLINE = "http://127.0.0.1:9/2/chat/features"


def keep_offline():
    """Point every chat that does not set its own endpoint at ``OFFLINE``."""
    import chat_xdk

    chat_xdk._native._feature_set_default_endpoint(OFFLINE)


def wait_for(predicate, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


# Each server gets an endpoint of its own: chats created while a GET for their
# endpoint is in flight share it, and a server can get the port of one that
# came before it.
_server_ids = itertools.count(1)


class FeatureServer:
    """A local GET /2/chat/features that records each request's query string."""

    def __init__(self, body='{"features":{"v1_send":true}}'):
        self.status = 200
        self.body = body
        self.delay = 0.0
        self.queries = []
        server = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                # The answer is fixed before the request is recorded, so a
                # test that sees the request can change the next answer.
                status, body, delay = server.status, server.body.encode("utf-8"), server.delay
                server.queries.append(urllib.parse.urlparse(self.path).query)
                if delay:
                    time.sleep(delay)
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
        self.url = "http://127.0.0.1:%d/%d/2/chat/features" % (self.httpd.server_address[1], next(_server_ids))
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def reading(url, timeout=2.0):
    """A chat that reads its feature switches from ``url``, within
    ``timeout`` seconds."""
    from chat_xdk import Chat

    return Chat._reading_features_from(url, timeout)


_v1_server = None


def v1_chat():
    """A chat whose feature switches turn v1_send on, as the X API would: it
    reads them from a local server that answers so. ``wait_for_v1`` waits for
    the answer."""
    global _v1_server
    if _v1_server is None:
        _v1_server = FeatureServer()
    return reading(_v1_server.url)


def wait_for_v1(chat, **identity):
    """Send from ``chat``, which has keys, until a send is v1. ``identity`` is
    the ``sender_id`` / ``signing_key_version`` of a chat without a session
    identity."""
    from chat_xdk import EncryptMessageParams

    params = EncryptMessageParams(
        "feature-switches",
        "wait for v1",
        conversation_key=bytes(32),
        conversation_key_version="1",
        **identity,
    )
    turned_on = wait_for(lambda: chat.encrypt_message(params).signature_info.signature_version == "10")
    assert turned_on, "v1_send never turned on"
