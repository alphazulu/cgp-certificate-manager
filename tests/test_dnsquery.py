import io
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

import dns.edns
import dns.exception
import dns.flags
import dns.message
import dns.opcode
import dns.rcode
import dns.rrset

from cgp_cert_manager import dnsquery as q


def reply(query):
    response = dns.message.make_response(query)
    response.flags |= dns.flags.RA
    return response


class QueryTests(unittest.TestCase):
    def test_canonical_owners_and_bounds(self):
        for value, expected in (("EXAMPLE.COM", "example.com."),
                                ("_acme-challenge.example.com.", "_acme-challenge.example.com."),
                                (".", ".")):
            self.assertEqual(q.name(value), expected)
        for value in (None, "", "a.com..", "*.*", "a..com", "a" * 64 + ".com", "a/evil", "é.com",
                      "a." * 128):
            with self.subTest(value=value), self.assertRaises(q.QueryError):
                q.name(value)

    def test_budget_accounts_for_elapsed_queries(self):
        with patch.object(q.time, "monotonic", side_effect=[10, 12, 14, 16]):
            client = q.Client(timeout=5)
            with patch.object(q, "doh", return_value="recursive") as doh, patch.object(q, "authoritative", return_value="auth") as auth:
                self.assertEqual(client.recursive("example.com", "NS", "google"), "recursive")
                self.assertEqual(doh.call_args.args[-1], 3)
                self.assertEqual(client.authoritative("example.com", "NS", "1.1.1.1"), "auth")
                self.assertEqual(auth.call_args.args[-1], 1)
                with self.assertRaisesRegex(q.QueryError, "dns_timeout"):
                    client.recursive("example.com", "NS", "google")
        with patch.object(q.time, "monotonic", return_value=10):
            client = q.Client(timeout=10, max_queries=1)
            self.assertEqual(client._timeout(), 4)
            with self.assertRaisesRegex(q.QueryError, "dns_query_limit"):
                client._timeout()

    def test_response_identity_flags_and_question(self):
        query = q._message("example.com", "TXT", True)
        self.assertTrue(query.flags & dns.flags.RD)
        self.assertFalse(query.flags & dns.flags.CD)
        self.assertTrue(query.ednsflags & dns.flags.DO)
        self.assertIs(q._checked(query, response := reply(query), True), response)
        response.flags &= ~dns.flags.RA
        self.assertIs(q._checked(query, response, False), response)
        with self.assertRaises(q.QueryError):
            q._checked(query, response, True)
        for mutate in (lambda r: setattr(r, "id", r.id ^ 1),
                       lambda r: setattr(r, "flags", r.flags | dns.flags.CD),
                       lambda r: setattr(r, "flags", r.flags | dns.flags.TC),
                       lambda r: setattr(r, "flags", r.flags & ~dns.flags.QR),
                       lambda r: r.set_opcode(dns.opcode.UPDATE),
                       lambda r: setattr(r, "question", q._message("other.com", "TXT", True).question)):
            response = reply(query)
            mutate(response)
            with self.assertRaisesRegex(q.QueryError, "invalid_dns_response"):
                q._checked(query, response, True)
        # is_response accepts some error messages with an empty question; our
        # transport still requires the original question on every response.
        response = reply(query)
        response.set_rcode(dns.rcode.SERVFAIL)
        response.question = []
        with self.assertRaisesRegex(q.QueryError, "invalid_dns_response"):
            q._checked(query, response, True)

    def test_rcode_and_numeric_ede_not_secret_text(self):
        query = q._message("example.com", "TXT", True)
        response = reply(query)
        response.set_rcode(dns.rcode.NXDOMAIN)
        self.assertIs(q._checked(query, response, True), response)
        response.set_rcode(dns.rcode.SERVFAIL)
        response.use_edns(options=[dns.edns.EDEOption(6, "PRIVATE_SENTINEL"),
                                   dns.edns.GenericOption(65001, b"secret"),
                                   dns.edns.EDEOption(6)])
        with self.assertRaises(q.QueryError) as caught:
            q._checked(query, response, True)
        self.assertEqual(caught.exception.code, "dns_rcode_servfail")
        self.assertEqual(caught.exception.ede, (6,))
        self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
        response.set_rcode(dns.rcode.NOERROR)
        with self.assertRaisesRegex(q.QueryError, "dnssec_bogus_by_resolver"):
            q._checked(query, response, True)

    def test_wire_singletons_preserved_and_multivalues_grouped(self):
        def duplicate(message):
            message.answer = [dns.rrset.from_text("example.com.", 60, "IN", "CNAME", "a.com."),
                              dns.rrset.from_text("example.com.", 60, "IN", "CNAME", "b.com.")]
        connection = self.connection(transform=duplicate)
        with patch.object(q, "_HTTPSConnection", return_value=connection), self.assertRaisesRegex(q.QueryError, "duplicate_dns_singleton"):
            q.doh("example.com", "CAA", "google")
        def caa(message):
            message.answer = [dns.rrset.from_text("example.com.", 60, "IN", "CAA", '0 issue "letsencrypt.org"'),
                              dns.rrset.from_text("example.com.", 30, "IN", "CAA", '0 issue "other.org"')]
        connection = self.connection(transform=caa)
        with patch.object(q, "_HTTPSConnection", return_value=connection):
            result = q.doh("example.com", "CAA", "google")
        self.assertEqual(len(result.answer), 1)
        self.assertEqual(len(result.answer[0]), 2)
        self.assertEqual(result.answer[0].ttl, 30)
        query = q._message("example.com", "TXT", True)
        response = reply(query)
        response.additional = [dns.rrset.from_text("example.com.", 30, "CH", "TXT", '"bad"')]
        with self.assertRaisesRegex(q.QueryError, "invalid_dns_class"):
            q._checked(query, response, True)

    def connection(self, payload=None, transform=None, status=200, content_type="application/dns-message"):
        connection = Mock()
        response = connection.getresponse.return_value
        response.status = status
        response.getheader.return_value = content_type
        def request(method, path, body, headers):
            query = dns.message.from_wire(body)
            message = reply(query)
            if transform:
                transform(message)
            data = message.to_wire() if payload is None else payload
            response.read1.side_effect = io.BytesIO(data).read1
        connection.request.side_effect = request
        return connection

    def test_doh_wire_post_tls_and_no_redirect(self):
        connection = self.connection(content_type="Application/DNS-Message; charset=binary")
        with patch.object(q, "_HTTPSConnection", return_value=connection) as constructor:
            response = q.doh("example.com", "CAA", "google")
        self.assertEqual(response.question[0].rdtype, 257)
        self.assertEqual(constructor.call_args.args[0], "dns.google")
        self.assertEqual(constructor.call_args.args[1], "8.8.8.8")
        context = constructor.call_args.kwargs["context"]
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, q.ssl.CERT_REQUIRED)
        args, kwargs = connection.request.call_args
        self.assertEqual(args, ("POST", "/dns-query"))
        self.assertEqual(kwargs["headers"]["Content-Type"], "application/dns-message")
        connection.close.assert_called_once()
        connection.getresponse.return_value.close.assert_called_once()
        for status, content_type in ((301, "application/dns-message"), (200, "application/json")):
            connection = self.connection(status=status, content_type=content_type)
            with patch.object(q, "_HTTPSConnection", return_value=connection), self.assertRaisesRegex(q.QueryError, "invalid_doh_response"):
                q.doh("example.com", "TXT", "cloudflare")
            connection.close.assert_called_once()

    def test_doh_rejects_wire_corruption_size_and_transport_failures(self):
        for payload, reason in ((b"bad", "dns_transport_failed"),
                                (b"x" * 65536, "dns_response_too_large")):
            connection = self.connection(payload=payload)
            with patch.object(q, "_HTTPSConnection", return_value=connection), self.assertRaisesRegex(q.QueryError, reason):
                q.doh("example.com", "TXT", "google")
            connection.close.assert_called_once()
        connection = self.connection(transform=lambda message: setattr(message, "id", message.id ^ 1))
        with patch.object(q, "_HTTPSConnection", return_value=connection), self.assertRaisesRegex(q.QueryError, "invalid_dns_response"):
            q.doh("example.com", "TXT", "google")
        for error in (OSError("PRIVATE_SENTINEL"), q.http.client.BadStatusLine("PRIVATE_SENTINEL")):
            connection = self.connection()
            connection.connect.side_effect = error
            with patch.object(q, "_HTTPSConnection", return_value=connection), self.assertRaisesRegex(q.QueryError, "^dns_transport_failed$"):
                q.doh("example.com", "TXT", "google")
            connection.close.assert_called_once()

    def test_doh_slow_stream_cannot_extend_deadline(self):
        connection = self.connection()
        with patch.object(q, "_HTTPSConnection", return_value=connection), patch.object(q.time, "monotonic", side_effect=[0, 5]), self.assertRaisesRegex(q.QueryError, "dns_timeout"):
            q.doh("example.com", "TXT", "google", timeout=4)
        connection.close.assert_called_once()

    def test_http_response_close_failure_still_closes_connection(self):
        connection = self.connection()
        connection.getresponse.return_value.close.side_effect = OSError("close failed")
        with patch.object(q, "_HTTPSConnection", return_value=connection), self.assertRaises(OSError):
            q.doh("example.com", "CAA", "google")
        connection.close.assert_called_once()

    def test_trickling_headers_cannot_reset_the_absolute_deadline(self):
        now = [0]

        class Trickle(io.BytesIO):
            def readinto(self, buffer):
                now[0] += 1
                return super().readinto(memoryview(buffer)[:1])

        raw = Trickle(b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n\r\n")
        sock = Mock()
        sock.makefile.return_value = raw
        response = q.http.client.HTTPResponse(q._DeadlineSocket(sock, 3))
        with patch.object(q.time, "monotonic", side_effect=lambda: now[0]):
            with self.assertRaisesRegex(q.QueryError, "dns_timeout"):
                response.begin()
        self.assertEqual(now[0], 3)
        self.assertEqual([call.args[0] for call in sock.settimeout.call_args_list], [3, 2, 1])
        response.close()
        self.assertTrue(raw.closed)

    def test_partial_writes_share_the_same_deadline(self):
        now = [0]
        sock = Mock()

        def partial(data):
            now[0] += 1
            return min(1, len(data))

        sock.send.side_effect = partial
        wrapped = q._DeadlineSocket(sock, 3)
        with patch.object(q.time, "monotonic", side_effect=lambda: now[0]):
            with self.assertRaisesRegex(q.QueryError, "dns_timeout"):
                wrapped.sendall(b"request")
        self.assertEqual(sock.send.call_count, 3)
        now[0] = 0
        with patch.object(q.time, "monotonic", side_effect=lambda: now[0]):
            wrapped.sendall(b"ok")
            sock.send.side_effect = None
            sock.send.return_value = 0
            with self.assertRaisesRegex(OSError, "socket closed"):
                wrapped.sendall(b"x")
        wrapped.close()
        sock.close.assert_called_once()

    def test_reader_cleanup_closes_wrapper_even_if_raw_close_fails(self):
        raw = Mock()
        raw.close.side_effect = OSError("close failure")
        reader = q._DeadlineReader(raw, Mock(), 10)
        with self.assertRaises(OSError):
            reader.close()
        self.assertTrue(reader.closed)

    def test_literal_connect_and_tls_failure_close_socket_without_dns_lookup(self):
        context = ssl.create_default_context()
        for fail in ("connect", "handshake", "interrupt", None):
            with self.subTest(fail=fail):
                plain, tls = Mock(), Mock()
                if fail == "connect":
                    plain.connect.side_effect = OSError("unreachable")
                error = KeyboardInterrupt() if fail == "interrupt" else ssl.SSLError("bad TLS")
                with patch.object(q.time, "monotonic", return_value=0), \
                        patch.object(q.socket, "socket", return_value=plain) as factory, \
                        patch.object(q.socket, "getaddrinfo", side_effect=AssertionError("DNS bootstrap attempted")), \
                        patch.object(context, "wrap_socket", return_value=tls,
                                     side_effect=error if fail in ("handshake", "interrupt") else None) as wrap:
                    connection = q._HTTPSConnection("dns.google", "8.8.8.8", 10, context)
                    if fail:
                        with self.assertRaises(KeyboardInterrupt if fail == "interrupt" else OSError):
                            connection.connect()
                        plain.close.assert_called_once()
                        self.assertIsNone(connection.sock)
                    else:
                        connection.connect()
                        self.assertIs(connection.sock.sock, tls)
                        wrap.assert_called_once_with(plain, server_hostname="dns.google")
                        connection.close()
                        tls.close.assert_called_once()
                factory.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
                plain.connect.assert_called_once_with(("8.8.8.8", 443))

    def test_authoritative_tcp_public_only_and_no_recursion(self):
        def tcp(query, address, timeout, one_rr_per_rrset, ignore_trailing):
            self.assertEqual(query.flags & dns.flags.RD, 0)
            self.assertEqual(address, "1.1.1.1")
            self.assertEqual(timeout, 2)
            self.assertFalse(ignore_trailing)
            self.assertTrue(one_rr_per_rrset)
            response = reply(query)
            response.flags |= dns.flags.AA
            return response
        with patch.object(q.dns.query, "tcp", side_effect=tcp):
            self.assertTrue(q.authoritative("example.com", "SOA", "1.1.1.1", 2).flags & dns.flags.AA)
        for address in ("bad", "127.0.0.1", "::1", "10.0.0.1", "169.254.169.254"):
            with patch.object(q.dns.query, "tcp") as tcp, self.assertRaises(q.QueryError):
                q.authoritative("example.com", "SOA", address)
            tcp.assert_not_called()
        for error in (OSError("SECRET"), dns.exception.Timeout()):
            with patch.object(q.dns.query, "tcp", side_effect=error), self.assertRaisesRegex(q.QueryError, "^dns_transport_failed$"):
                q.authoritative("example.com", "SOA", "1.1.1.1")


class HTTPSWireTests(unittest.TestCase):
    """Real TLS and HTTP response framing, exclusively through loopback."""
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        root = Path(cls.temporary.name)
        cls.certificate, cls.key = root / "resolver.pem", root / "resolver.key"
        subprocess.run([
            "openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-sha256", "-days", "2", "-subj", "/CN=dns.google",
            "-addext", "subjectAltName=DNS:dns.google",
            "-keyout", str(cls.key), "-out", str(cls.certificate),
        ], input=b"", stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=20)

    def local_doh(self, framing, resolver="google"):
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(self.certificate, self.key)
        observed = []
        server_context.set_servername_callback(lambda _sock, name, _context: observed.append(name))
        client_context = ssl.create_default_context(cafile=str(self.certificate))
        real_socket = socket.socket
        listener = real_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(5)
        endpoint = listener.getsockname()
        failures = []
        received = []

        def serve():
            try:
                plain, _ = listener.accept()
                with plain:
                    plain.settimeout(3)
                    try:
                        with server_context.wrap_socket(plain, server_side=True) as stream:
                            data = bytearray()
                            while b"\r\n\r\n" not in data:
                                data.extend(stream.recv(4096))
                            header, body = bytes(data).split(b"\r\n\r\n", 1)
                            length = next(int(line.split(b":", 1)[1]) for line in header.split(b"\r\n")
                                          if line.lower().startswith(b"content-length:"))
                            while len(body) < length:
                                body += stream.recv(4096)
                            received.append(header)
                            query = dns.message.from_wire(body)
                            message = reply(query)
                            message.answer = [dns.rrset.from_text("example.com.", 60, "IN", "CAA", '0 issue "letsencrypt.org"')]
                            payload = message.to_wire()
                            start = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nConnection: close\r\n"
                            if framing == "length":
                                response = start + b"Content-Length: " + str(len(payload)).encode() + b"\r\n\r\n" + payload
                            elif framing == "chunked":
                                response = start + b"Transfer-Encoding: chunked\r\n\r\n" + hex(len(payload))[2:].encode() + b"\r\n" + payload + b"\r\n0\r\n\r\n"
                            else:
                                response = start + b"\r\n" + payload
                            stream.sendall(response)
                    except ssl.SSLError:
                        if resolver == "google":
                            raise
            except BaseException as error:
                failures.append(error)

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        requested = []

        class RoutedSocket(real_socket):
            def connect(self, address):
                requested.append(address)
                return super().connect(endpoint)

        try:
            with patch.object(q.socket, "socket", RoutedSocket), \
                    patch.object(q.socket, "getaddrinfo", side_effect=AssertionError("DNS bootstrap attempted")), \
                    patch.object(q.ssl, "create_default_context", return_value=client_context):
                result = q.doh("example.com", "CAA", resolver, timeout=3)
        finally:
            worker.join(5)
            self.assertFalse(worker.is_alive(), "Loopback HTTPS server did not stop")
            self.assertEqual(failures, [])
        self.assertEqual(requested, [(q.RESOLVERS[resolver][0], 443)])
        self.assertEqual(observed, [q.RESOLVERS[resolver][1]])
        self.assertIn(b"Host: dns.google", received[0])
        return result

    def test_verified_tls_real_wire_and_connection_close_framing(self):
        for framing in ("length", "chunked", "eof"):
            with self.subTest(framing=framing):
                response = self.local_doh(framing)
                self.assertEqual(response.answer[0][0].value, b"letsencrypt.org")

    def test_literal_route_does_not_disable_hostname_verification(self):
        with self.assertRaisesRegex(q.QueryError, "dns_transport_failed"):
            self.local_doh("length", resolver="cloudflare")


if __name__ == "__main__":
    unittest.main()
