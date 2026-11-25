"""Synthetic AWS XML replies and local TLS, never live AWS resources."""
from contextlib import contextmanager
import http.client
import socketserver
import threading

from tests.powerdns_fixture import TranscriptSocket


ROUTE53_NS = "https://route53.amazonaws.com/doc/2013-04-01/"
STS_NS = "https://sts.amazonaws.com/doc/2011-06-15/"


def xml(operation, children="", namespace=ROUTE53_NS):
    return ('<?xml version="1.0" encoding="UTF-8"?><' + operation + ' xmlns="' + namespace + '">'
            + children + '</' + operation + '>').encode("utf-8")


def identity(account="123456789012"):
    return xml("GetCallerIdentityResponse", "<GetCallerIdentityResult><Arn>arn:aws:iam::"
               + account + ":user/synthetic</Arn><UserId>SYNTHETIC</UserId><Account>"
               + account + "</Account></GetCallerIdentityResult><ResponseMetadata>"
               "<RequestId>00000000-0000-0000-0000-000000000000</RequestId></ResponseMetadata>", STS_NS)


def wire(raw, *, status=200, headers=None):
    if headers is None:
        headers = [("Content-Type", "application/xml"), ("Content-Length", str(len(raw)))]
    head = "HTTP/1.1 " + str(status) + " Synthetic\r\n"
    head += "".join(name + ": " + value + "\r\n" for name, value in headers)
    return head.encode("ascii") + b"\r\n" + raw


class TranscriptConnection(http.client.HTTPConnection):
    """Use the real HTTP parser/serializer; TLS has independent loopback tests."""
    def __init__(self, host, port, *, timeout, context):
        super().__init__(host, port, timeout=timeout)


@contextmanager
def serve(responses, tls_context):
    requests, faults, pending = [], [], list(responses)

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                self.request.settimeout(2)
                request = b""
                while b"\r\n\r\n" not in request:
                    part = self.request.recv(4096)
                    if not part or len(request) > 65536:
                        raise AssertionError("Incomplete fixture request")
                    request += part
                head, body = request.split(b"\r\n\r\n", 1)
                lengths = [line.split(b":", 1)[1].strip() for line in head.split(b"\r\n")
                           if line.lower().startswith(b"content-length:")]
                length = int(lengths[0]) if lengths else 0
                while len(body) < length:
                    part = self.request.recv(length - len(body))
                    if not part:
                        raise AssertionError("Incomplete fixture body")
                    body += part
                requests.append(head + b"\r\n\r\n" + body)
                if not pending:
                    raise AssertionError("Unexpected additional AWS request")
                self.request.sendall(pending.pop(0))
            except Exception as error:
                faults.append(type(error).__name__)

    with socketserver.TCPServer(("127.0.0.1", 0), Handler) as peer:
        peer.socket = tls_context.wrap_socket(peer.socket, server_side=True)
        worker = threading.Thread(target=peer.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        worker.start()
        try:
            yield peer.server_address[1], requests, faults
        finally:
            peer.shutdown()
            worker.join(3)
            assert not worker.is_alive()
