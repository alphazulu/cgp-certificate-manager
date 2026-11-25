"""Synthetic PowerDNS HTTP transcripts and loopback servers, never providers."""
from contextlib import contextmanager
import io
import json
import socketserver
import threading


def server_info(**changes):
    result = {"type": "Server", "id": "localhost", "daemon_type": "authoritative",
              "version": "5.0.8", "zones_url": "https://unused.invalid/do-not-follow"}
    result.update(changes)
    return result


def zone_info(**changes):
    # A native PowerDNS zone response has no type discriminator.
    result = {"id": "example.com.", "name": "example.com.", "kind": "Native",
              "url": "https://unused.invalid/do-not-follow"}
    result.update(changes)
    return result


def wire(data=None, *, raw=None, status=200, headers=None):
    if raw is None:
        raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
    if headers is None:
        headers = [("Content-Type", "application/json"), ("Content-Length", str(len(raw)))]
    head = "HTTP/1.1 " + str(status) + " Synthetic\r\n"
    head += "".join(name + ": " + value + "\r\n" for name, value in headers)
    return head.encode("ascii") + b"\r\n" + raw


class TranscriptStream(io.BytesIO):
    def close(self):
        if not self.closed:
            self.position_at_close = self.tell()
        super().close()


class TranscriptSocket:
    """Keep actual stdlib HTTP serialization/parsing around a deterministic peer."""
    def __init__(self, response):
        self.stream = TranscriptStream(response)
        self.sent = []
        self.closed = False

    def makefile(self, mode):
        assert mode == "rb"
        return self.stream

    def sendall(self, value):
        self.sent.append(bytes(value))

    def setsockopt(self, *args):
        pass

    def close(self):
        self.closed = True


@contextmanager
def serve(responses, tls_context=None):
    """One response per connection, preserving the literal request for assertions."""
    requests = []
    faults = []
    pending = list(responses)

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                self.request.settimeout(2)
                request = b""
                while b"\r\n\r\n" not in request and len(request) <= 65536:
                    part = self.request.recv(4096)
                    if not part:
                        break
                    request += part
                requests.append(request)
                if not pending:
                    raise AssertionError("Unexpected additional API request")
                self.request.sendall(pending.pop(0))
            except Exception as error:
                faults.append(type(error).__name__)

    with socketserver.TCPServer(("127.0.0.1", 0), Handler) as peer:
        if tls_context is not None:
            peer.socket = tls_context.wrap_socket(peer.socket, server_side=True)
        worker = threading.Thread(target=peer.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        worker.start()
        try:
            yield peer.server_address[1], requests, faults
        finally:
            peer.shutdown()
            worker.join(3)
            assert not worker.is_alive()
