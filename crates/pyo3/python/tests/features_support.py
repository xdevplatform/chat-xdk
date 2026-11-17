"""A local GET /2/chat/features for the tests, and the internal hooks that
point chats at it."""

import http.server
import itertools
import os
import select
import socket
import socketserver
import ssl
import subprocess
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


# The path of a FeatureServer that answers that v1_send is on.
REDIRECT_TARGET = "/followed/2/chat/features"


class FeatureServer:
    """A local GET /2/chat/features that records each request's query string
    and headers. Set ``location`` to answer with a redirect there; requests
    that reach ``REDIRECT_TARGET`` are counted in ``followed``. A request for
    another path, such as a retried read meant for an earlier server on this
    port, gets a 404 and is not recorded. With ``tls``, a certificate file
    and its key file, it serves HTTPS."""

    def __init__(self, body='{"features":{"v1_send":true}}', tls=None):
        self.status = 200
        self.body = body
        self.delay = 0.0
        self.location = None
        self.set_cookie = None
        self.queries = []
        self.headers = []
        self.followed = 0
        server = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                path = urllib.parse.urlparse(self.path).path
                if path == REDIRECT_TARGET:
                    server.followed += 1
                    answer = b'{"features":{"v1_send":true}}'
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(answer)))
                    self.end_headers()
                    self.wfile.write(answer)
                    return
                if path != server.path:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                # The answer is fixed before the request is recorded, so a
                # test that sees the request can change the next answer.
                status, body, delay = server.status, server.body.encode("utf-8"), server.delay
                location, set_cookie = server.location, server.set_cookie
                server.queries.append(urllib.parse.urlparse(self.path).query)
                server.headers.append(dict(self.headers))
                if delay:
                    time.sleep(delay)
                try:
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    if location:
                        self.send_header("Location", location)
                    if set_cookie:
                        self.send_header("Set-Cookie", set_cookie)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, *args):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(*tls)
            self.httpd.socket = context.wrap_socket(self.httpd.socket, server_side=True)
        self.origin = "%s://127.0.0.1:%d" % ("https" if tls else "http", self.port)
        self.path = "/%d/2/chat/features" % next(_server_ids)
        self.url = self.origin + self.path
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


# A host no resolver knows, so a request for it arrives only through a proxy
# that has a route for it.
PROXY_ONLY_HOST = "features.invalid"


class RecordingProxy:
    """A local HTTP proxy that records each request it is asked to carry: its
    request line in ``requests`` and its headers in ``headers``. ``routes``
    maps the host a request names to the local port that answers for it; a
    host without a route gets a 502. With ``refuse`` set to a status, it
    answers every request with that status instead."""

    def __init__(self, routes=None, refuse=None):
        self.routes = routes or {}
        self.refuse = refuse
        self.requests = []
        self.headers = []
        proxy = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                line = self.rfile.readline().decode("latin-1").strip()
                if not line:
                    return
                headers = {}
                while True:
                    header = self.rfile.readline().decode("latin-1").strip()
                    if not header:
                        break
                    name, _, value = header.partition(":")
                    headers[name.strip().lower()] = value.strip()
                proxy.requests.append(line)
                proxy.headers.append(headers)
                method, target, _ = line.split(" ", 2)
                if method == "CONNECT":
                    host = target.rpartition(":")[0]
                else:
                    host = urllib.parse.urlsplit(target).hostname
                port = proxy.routes.get(host)
                if proxy.refuse or port is None:
                    self.wfile.write(b"HTTP/1.1 %d Refused\r\nContent-Length: 0\r\n\r\n" % (proxy.refuse or 502))
                    return
                with socket.create_connection(("127.0.0.1", port), timeout=10) as upstream:
                    if method == "CONNECT":
                        self.wfile.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        self.wfile.flush()
                        self._tunnel(upstream)
                        return
                    parts = urllib.parse.urlsplit(target)
                    path = parts.path + ("?" + parts.query if parts.query else "")
                    request = "%s %s HTTP/1.1\r\nConnection: close\r\n" % (method, path)
                    for name, value in headers.items():
                        if not name.startswith("proxy-") and name != "connection":
                            request += "%s: %s\r\n" % (name, value)
                    upstream.sendall((request + "\r\n").encode("latin-1"))
                    while chunk := upstream.recv(65536):
                        self.wfile.write(chunk)

            def _tunnel(self, upstream):
                sockets = [self.connection, upstream]
                try:
                    while True:
                        readable, _, _ = select.select(sockets, [], [], 10)
                        if not readable:
                            return
                        for sock in readable:
                            data = sock.recv(65536)
                            if not data:
                                return
                            (upstream if sock is self.connection else self.connection).sendall(data)
                except OSError:
                    return

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        self.server = Server(("127.0.0.1", 0), Handler)
        self.address = "127.0.0.1:%d" % self.server.server_address[1]
        self.url = "http://" + self.address
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def self_signed_certificate(directory, host):
    """A certificate for ``host`` that signs itself, made with the ``openssl``
    command in ``directory``: its certificate file and key file, or None
    where the command can't make one."""
    cert, key = os.path.join(directory, "cert.pem"), os.path.join(directory, "key.pem")
    command = ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2"]
    command += ["-keyout", key, "-out", cert, "-subj", "/CN=" + host, "-addext", "subjectAltName=DNS:" + host]
    try:
        subprocess.run(command, check=True, capture_output=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None
    return cert, key


def reading(url, timeout=2.0, refresh=300.0):
    """A chat that reads its feature switches from ``url``, within
    ``timeout`` seconds, again ``refresh`` seconds after each answer."""
    from chat_xdk import Chat

    return Chat._reading_features_from(url, timeout, refresh)


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
