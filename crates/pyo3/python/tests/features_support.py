"""A local GET /2/chat/features for the tests, and the internal hooks that
point chats at it."""

import http.server
import itertools
import threading
import time
import urllib.parse

# Nothing listens here: a chat no test points at a server of its own fetches
# from this endpoint, fails, and stays on v0.
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


# Each server gets an endpoint of its own: the core reuses an answer per
# endpoint and bucket for 5 minutes, and a server can get the port of one that
# came before it.
_server_ids = itertools.count(1)


class FeatureServer:
    """A local GET /2/chat/features that records each request's bucket."""

    def __init__(self, body='{"features":{"v1_send":true}}'):
        self.status = 200
        self.body = body
        self.delay = 0.0
        self.buckets = []
        server = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                # The answer is fixed before the request is recorded, so a
                # test that sees the request can change the next answer.
                status, body, delay = server.status, server.body.encode("utf-8"), server.delay
                query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                server.buckets.append(query.get("bucket", [None])[0])
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


_v1_server = None


def enable_v1_send(chat, **identity):
    """Turn v1_send on for ``chat`` as the X API would: point its feature
    fetch at a local server that answers it, then send until a send is v1.
    ``identity`` is the ``sender_id`` / ``signing_key_version`` of a chat
    without a session identity."""
    global _v1_server
    from chat_xdk import EncryptMessageParams

    if _v1_server is None:
        _v1_server = FeatureServer()
    chat._configure_features(_v1_server.url, 2.0, 3600.0, 0.05)
    params = EncryptMessageParams(
        "feature-switches",
        "turn v1 on",
        conversation_key=bytes(32),
        conversation_key_version="1",
        **identity,
    )
    turned_on = wait_for(lambda: chat.encrypt_message(params).signature_info.signature_version == "10")
    assert turned_on, "v1_send never turned on"
