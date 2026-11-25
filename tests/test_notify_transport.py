"""Notification configuration and one-attempt transports; no external services."""
from copy import deepcopy
import http.client
import http.server
import io
import json
import os
from pathlib import Path
import smtplib
import socket
import ssl
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from cgp_cert_manager import notify_transport as n


def event():
    return {"schema": 1, "id": "a" * 32, "kind": "alert", "observed_at": 1000.5,
            "status": "critical", "endpoints": [{"id": "mail", "host": "mail.example.com",
            "port": 443, "server_name": "mail.example.com", "protocol": "tls",
            "status": "critical", "code": "certificate_expired", "verified": False,
            "checked_at": 1000.5, "not_after": None, "fingerprint_sha256": None,
            "peer_address": None, "tls_version": None, "days_remaining": None}]}


def smtp(**kwargs):
    result = {"id": "mail", "kind": "smtp", "host": "smtp.example.com",
              "from": "monitor@example.com", "to": ["ops@example.com"]}
    result.update(kwargs)
    return result


def webhook(**kwargs):
    result = {"id": "hook", "kind": "webhook", "url": "https://hooks.example.com/notify"}
    result.update(kwargs)
    return result


class _TranscriptStream(io.BytesIO):
    def close(self):
        if not self.closed:
            self.position_at_close = self.tell()
        super().close()


class _TranscriptSocket:
    """In-memory wire retaining real SMTP/HTTP request and response parsers."""
    def __init__(self, response):
        self.stream = _TranscriptStream(response)
        self.sent = []

    def makefile(self, mode):
        assert mode == "rb"
        return self.stream

    def sendall(self, value):
        self.sent.append(bytes(value))

    def close(self):
        pass


class NotificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert_temp = tempfile.TemporaryDirectory()
        cls.cert_root = Path(cls.cert_temp.name)
        cls.cert = cls.cert_root / "ca.pem"
        cls.key = cls.cert_root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-days", "2", "-subj", "/CN=localhost", "-addext",
                        "subjectAltName=DNS:localhost,IP:127.0.0.1", "-keyout", str(cls.key),
                        "-out", str(cls.cert)], check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        cls.cert.chmod(0o600)

    @classmethod
    def tearDownClass(cls):
        cls.cert_temp.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def secret(self, text="private-password\n", name="secret"):
        path = self.root / name
        path.write_text(text)
        path.chmod(0o600)
        return str(path)

    def assert_invalid(self, config):
        with self.assertRaises(n.NotificationError) as raised:
            n.prepare(config)
        self.assertNotIn("private-password", str(raised.exception))
        self.assertNotIn(str(self.root), str(raised.exception))

    def test_prepared_tls_channel_is_json_safe_and_has_no_file_references(self):
        config = smtp(username="user", password_file=self.secret(" pass with spaces \r\n"),
                      ca_file=str(self.cert))
        result = n.prepare(config)
        self.assertEqual(json.loads(json.dumps(result)), result)
        self.assertEqual(result["security"], "tls")
        self.assertEqual(result["port"], 465)
        self.assertEqual(result["secrets"], {"password": " pass with spaces ",
                                              "ca_pem": self.cert.read_text()})
        self.assertNotIn("password_file", result)
        self.assertNotIn("ca_file", result)
        self.assertEqual(config["password_file"], str(self.root / "secret"))

    def test_defaults_canonical_hosts_and_mailboxes(self):
        prepared = n.prepare(smtp(host="SMTP.EXAMPLE.COM", security="starttls",
                                  **{"from": "monitor@EXAMPLE.COM"}))
        self.assertEqual((prepared["host"], prepared["port"], prepared["from"]),
                         ("smtp.example.com", 587, "monitor@example.com"))
        for host in ("127.0.0.1", "::1"):
            result = n.prepare(smtp(host=host, security="plain_local"))
            self.assertEqual((result["host"], result["port"]), (host, 25))
        self.assertEqual(n.prepare(smtp(host="2001:db8::1"))["host"], "2001:db8::1")

    def test_disabled_channel_never_reads_credentials_or_sends(self):
        raw = {"id": "off", "kind": "smtp", "enabled": False, "password_file": "/missing"}
        with patch.object(n.storage, "open_private") as opened, patch.object(n, "_PlainClient") as sent:
            prepared = n.prepare(raw)
            self.assertEqual(prepared, {"id": "off", "kind": "smtp", "enabled": False})
            self.assertEqual(n.deliver(prepared, event()),
                             {"outcome": "rejected", "code": "channel_disabled"})
        opened.assert_not_called()
        sent.assert_not_called()

    def test_webhook_canonicalization_and_bearer_snapshot(self):
        prepared = n.prepare(webhook(url="https://HOOKS.EXAMPLE.COM:443?tenant=a",
                                     token_file=self.secret("abc._~+/-==\n")))
        self.assertEqual(prepared["url"], "https://hooks.example.com/?tenant=a")
        self.assertEqual(prepared["secrets"], {"token": "abc._~+/-=="})
        self.assertEqual(n.prepare(webhook(url="https://[::1]:8443/hook"))["url"],
                         "https://[::1]:8443/hook")

    def test_channel_shape_and_common_identifiers_fail_closed(self):
        invalid = [None, [], {}, {"id": "mail", "kind": "other"},
                   smtp(extra="private-password"), smtp(id=None), smtp(id="a" * 65),
                   smtp(id="bad id"), smtp(id="é"), smtp(id="x\n"), smtp(enabled=1)]
        for item in invalid:
            with self.subTest(config=type(item).__name__):
                self.assert_invalid(item)

    def test_smtp_routing_validation(self):
        invalid = [smtp(security="none"), smtp(host=""), smtp(host="host..example"),
                   smtp(host="x%zone"), smtp(host="x" * 64 + ".example"),
                   smtp(host="mail.example.com:25"), smtp(host="mail.example.com\r\n"),
                   smtp(port=True), smtp(port="465"), smtp(port=0), smtp(port=65536),
                   smtp(to="ops@example.com"), smtp(to=[]), smtp(to=["a@b"] * 17),
                   smtp(to=["a@EXAMPLE.COM", "a@example.com"]),
                   smtp(to=["Display Name <a@example.com>"]), smtp(to=["a@@example.com"]),
                   smtp(to=["a@bad..example"]), smtp(to=[".a@example.com"]),
                   smtp(to=["a.@example.com"]), smtp(to=["a..b@example.com"]),
                   smtp(to=["a" * 65 + "@example.com"]), smtp(to=["é@example.com"]),
                   smtp(to=["a@example.com\nBcc:private-password@example.com"]),
                   smtp(username="user"), smtp(password_file="/missing"),
                   smtp(username="", password_file="/missing"),
                   smtp(host="localhost", security="plain_local"),
                   smtp(host="127.0.0.2", security="plain_local"),
                   smtp(host="127.0.0.1", security="plain_local", username="u", password_file="/missing"),
                   smtp(host="::1", security="plain_local", ca_file="/missing")]
        for item in invalid:
            with self.subTest(case=invalid.index(item)):
                self.assert_invalid(item)

    def test_webhook_url_validation_and_no_credentials_in_errors(self):
        for url in (None, "", "http://example.com", "https:///path", "https://user:secret@example.com",
                    "https://example.com/#secret", "https://example.com/#", "https://example.com/a b",
                    "https://example.com/\\path", "https://example.com:0/path", "https://example.com:65536",
                    "https://example.com:invalid", "https://example.com:", "https://[bad",
                    "https://example.com/\nAuthorization:private-password", "https://é.example.com",
                    "https://example.com/" + "a" * 2048):
            with self.subTest(kind=type(url).__name__):
                self.assert_invalid(webhook(url=url))

    def test_secret_file_permissions_links_and_missing_refused(self):
        path = Path(self.secret())
        alias = self.root / "alias"
        alias.symlink_to(path)
        self.assert_invalid(webhook(token_file=str(alias)))
        alias.unlink()
        os.link(path, alias)
        self.assert_invalid(webhook(token_file=str(path)))
        alias.unlink()
        path.chmod(0o644)
        self.assert_invalid(webhook(token_file=str(path)))
        for name in (str(self.root / "missing"), "relative", None, "/bad\npath"):
            self.assert_invalid(webhook(token_file=name))

    def test_secret_contents_are_bounded_ascii_and_single_line(self):
        for text in ("", "\n", "has\tcontrol", "has\nnewline\n", "bad\x00value", "é", "x" * (n.MAX_SECRET + 1)):
            self.assert_invalid(smtp(username="u", password_file=self.secret(text)))
        for text in ("bearer token", "bearer:token", "a=b"):
            self.assert_invalid(webhook(token_file=self.secret(text)))
        for text, expected in (("x\n", "x"), ("x\r\n", "x"), ("x", "x"),
                               ("x" * n.MAX_SECRET, "x" * n.MAX_SECRET)):
            prepared = n.prepare(smtp(username="u", password_file=self.secret(text)))
            self.assertEqual(prepared["secrets"]["password"], expected)

    def test_credential_mutation_during_snapshot_refused(self):
        path = self.secret()
        original = os.fstat
        inode = Path(path).stat().st_ino
        calls = 0

        def changed(fd):
            nonlocal calls
            info = original(fd)
            if info.st_ino != inode:
                return info
            calls += 1
            if calls < 3:
                return info
            return SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino, st_size=info.st_size,
                                   st_mtime_ns=info.st_mtime_ns + 1, st_ctime_ns=info.st_ctime_ns)

        with patch.object(n.os, "fstat", side_effect=changed):
            self.assert_invalid(smtp(username="u", password_file=path))

    def test_ca_rejects_private_key_unrelated_text_and_invalid_certificate(self):
        for text in (self.key.read_text(), "not a CA", "-----BEGIN CERTIFICATE-----\naaaa\n-----END CERTIFICATE-----\n"):
            self.assert_invalid(webhook(ca_file=self.secret(text)))

    def test_tls_context_verifies_identity_minimum_version_and_never_creates_keylog(self):
        keylog = self.root / "must-not-exist"
        with patch.dict(os.environ, {"SSLKEYLOGFILE": str(keylog)}):
            for pem in (None, self.cert.read_text()):
                context = n._context(pem)
                self.assertTrue(context.check_hostname)
                self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
                self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
                self.assertIsNone(context.keylog_filename)
        self.assertFalse(keylog.exists())

    def test_event_and_timeout_validation_precede_network(self):
        prepared = n.prepare(smtp())
        invalid = [None, {}, {**event(), "extra": "secret"}, {**event(), "schema": True},
                   {**event(), "schema": 2}, {**event(), "id": 1}, {**event(), "id": "invalid"},
                   {**event(), "kind": "recovery"}, {**event(), "observed_at": True},
                   {**event(), "observed_at": float("inf")}, {**event(), "observed_at": 10 ** 1000},
                   {**event(), "endpoints": {}}, {**event(), "endpoints": [{}] * 17},
                   {**event(), "endpoints": [None]}, {**event(), "endpoints": [{"bad": float("nan")}]},
                   {**event(), "endpoints": [{"bad": object()}]},
                   {**event(), "endpoints": [{"large": "x" * n.MAX_EVENT}]}]
        cyclic = {}
        cyclic["self"] = cyclic
        invalid.append({**event(), "endpoints": [cyclic]})
        with patch.object(n, "_TLSClient") as sent:
            for item in invalid:
                self.assertEqual(n.deliver(prepared, item), {"outcome": "rejected", "code": "invalid_event"})
            for timeout in (True, "15", 0, -1, float("nan"), float("inf"), 10 ** 1000):
                self.assertEqual(n.deliver(prepared, event(), timeout),
                                 {"outcome": "rejected", "code": "invalid_timeout"})
            for channel in (None, {}, {"kind": "unknown"}):
                self.assertEqual(n.deliver(channel, event()), {"outcome": "rejected", "code": "invalid_channel"})
        sent.assert_not_called()

    def test_smtp_tls_accepted_has_stable_message_id_and_explicit_envelope(self):
        prepared = n.prepare(smtp())
        client = MagicMock()
        client.send_message.return_value = {}
        with patch.object(n, "_TLSClient", return_value=client) as constructor:
            for _ in range(2):
                self.assertEqual(n.deliver(prepared, event()), {"outcome": "accepted", "code": None})
        options = constructor.call_args.kwargs
        self.assertEqual(options["local_hostname"], "cgp-monitor.invalid")
        self.assertTrue(options["context"].check_hostname)
        sent = client.send_message.call_args
        self.assertEqual(sent.args[0]["Message-ID"], "<" + "a" * 32 + "@cgp-monitor.invalid>")
        self.assertEqual(json.loads(sent.args[0].get_content()), event())
        self.assertEqual(sent.kwargs, {"from_addr": prepared["from"], "to_addrs": prepared["to"]})
        self.assertEqual(client.send_message.call_count, 2)
        self.assertEqual(client.close.call_count, 2)
        client.quit.assert_not_called()

    def test_starttls_required_before_auth_and_submit(self):
        prepared = n.prepare(smtp(security="starttls", username="user", password_file=self.secret()))
        client = MagicMock()
        client.send_message.return_value = {}
        with patch.object(n, "_PlainClient", return_value=client):
            self.assertEqual(n.deliver(prepared, event())["outcome"], "accepted")
        self.assertEqual([call[0] for call in client.mock_calls],
                         ["starttls", "ehlo_or_helo_if_needed", "login", "send_message", "close"])
        self.assertTrue(client.starttls.call_args.kwargs["context"].check_hostname)
        client.reset_mock()
        client.starttls.side_effect = smtplib.SMTPNotSupportedError("private-password")
        with patch.object(n, "_PlainClient", return_value=client):
            self.assertEqual(n.deliver(prepared, event()),
                             {"outcome": "rejected", "code": "smtp_connection_failed"})
        client.login.assert_not_called()
        client.send_message.assert_not_called()

    def test_smtp_rejection_uncertainty_and_cleanup_do_not_expose_replies(self):
        prepared = n.prepare(smtp(to=["a@example.com", "b@example.com"]))
        failures = [
            (smtplib.SMTPRecipientsRefused({"a@example.com": (550, b"private-password")}), "rejected", "smtp_rejected"),
            (smtplib.SMTPSenderRefused(550, b"private-password", "sender"), "rejected", "smtp_rejected"),
            (smtplib.SMTPDataError(550, b"private-password"), "rejected", "smtp_rejected"),
            (smtplib.SMTPServerDisconnected("private-password"), "uncertain", "smtp_submission_uncertain"),
            (TimeoutError("private-password"), "uncertain", "smtp_submission_uncertain"),
        ]
        for failure, outcome, code in failures:
            client = MagicMock()
            client.send_message.side_effect = failure
            with patch.object(n, "_TLSClient", return_value=client):
                self.assertEqual(n.deliver(prepared, event()), {"outcome": outcome, "code": code})
            client.send_message.assert_called_once()
        client = MagicMock()
        client.send_message.return_value = {"a@example.com": (550, b"private-password")}
        with patch.object(n, "_TLSClient", return_value=client):
            self.assertEqual(n.deliver(prepared, event()), {"outcome": "uncertain", "code": "smtp_partial_refusal"})
        client.send_message.return_value = {}
        client.close.side_effect = OSError("private-password")
        with patch.object(n, "_TLSClient", return_value=client):
            self.assertEqual(n.deliver(prepared, event()), {"outcome": "accepted", "code": None})

    def test_smtp_connection_and_auth_failure_are_rejected_before_submit(self):
        prepared = n.prepare(smtp(username="u", password_file=self.secret()))
        with patch.object(n, "_TLSClient", side_effect=OSError("private-password")):
            self.assertEqual(n.deliver(prepared, event()), {"outcome": "rejected", "code": "smtp_connection_failed"})
        client = MagicMock()
        client.login.side_effect = smtplib.SMTPAuthenticationError(535, b"private-password")
        with patch.object(n, "_TLSClient", return_value=client):
            self.assertEqual(n.deliver(prepared, event())["outcome"], "rejected")
        client.send_message.assert_not_called()

    def test_real_smtp_parser_requires_complete_final_data_acknowledgement(self):
        prepared = n.prepare(smtp(host="127.0.0.1", security="plain_local"))
        before_ack = (b"220 Ready\r\n250 Hello\r\n250 Sender accepted\r\n"
                      b"250 Recipient accepted\r\n354 Begin message\r\n")
        for acknowledgement in (b"250 Message accepted", b"250 Message accepted\r",
                                b"250 Message accepted\n", b"250-Partial\r\n250 Accepted",
                                b"250 Message accepted\r\n"):
            with self.subTest(acknowledgement=acknowledgement):
                wire = _TranscriptSocket(before_ack + acknowledgement)
                with patch.object(n._PlainClient, "_get_socket", return_value=wire) as connect:
                    result = n.deliver(prepared, event())
                expected = {"outcome": "accepted", "code": None} if acknowledgement.endswith(b"\r\n") else {
                    "outcome": "uncertain", "code": "smtp_submission_uncertain"}
                self.assertEqual(result, expected)
                connect.assert_called_once()
                self.assertEqual(wire.sent.count(b"data\r\n"), 1)
                self.assertEqual(sum(b"Message-ID: " in part for part in wire.sent), 1)

    def _webhook_transcript(self, response):
        wire = _TranscriptSocket(response)
        connection = http.client.HTTPSConnection("hooks.example.com", context=n._context())
        connection.connect = lambda: setattr(connection, "sock", wire)
        with patch.object(n.http.client, "HTTPSConnection", return_value=connection):
            result = n.deliver(n.prepare(webhook()), event())
        self.assertEqual(sum(part.startswith(b"POST ") for part in wire.sent), 1)
        return result, wire

    def test_real_http_parser_refuses_incomplete_status_and_header_acknowledgements(self):
        responses = (b"HTTP/1.1 204 Accepted", b"HTTP/1.1 204 Accepted\r\n",
                     b"HTTP/1.1 204 Accepted\r\nX-Test: truncated",
                     b"HTTP/1.1 204 Accepted\r\nX-Test: complete\r\n",
                     b"HTTP/1.1 204 Accepted\n\n",
                     b"HTTP/1.1 204 Accepted\r\nX-Test: bare-lf\n\r\n",
                     b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 Accepted\r\n",
                     b"INVALID\r\n\r\n")
        for response in responses:
            with self.subTest(response=response):
                result, wire = self._webhook_transcript(response)
                self.assertEqual(result, {"outcome": "uncertain", "code": "webhook_submission_uncertain"})
                self.assertTrue(wire.stream.closed)

    def test_real_http_parser_bounds_all_interim_and_final_headers_without_reading_body(self):
        # Split the budget across headers so each line fits the stdlib limit.
        interim = b"HTTP/1.1 100 Continue\r\nX-Interim: yes\r\n\r\n"
        prefix = interim + b"HTTP/1.1 202 Accepted\r\nX-First: " + b"a" * 32000 + b"\r\nX-Last: "
        suffix = b"\r\n\r\n"
        padding = n.MAX_HTTP_HEADERS - len(prefix) - len(suffix)
        complete = prefix + b"b" * padding + suffix
        body = b"unread response body containing private receiver data"
        result, wire = self._webhook_transcript(complete + body)
        self.assertEqual(result, {"outcome": "accepted", "code": None})
        self.assertEqual(wire.stream.position_at_close, len(complete))
        result, wire = self._webhook_transcript(prefix + b"b" * (padding + 1) + suffix + body)
        self.assertEqual(result, {"outcome": "uncertain", "code": "webhook_submission_uncertain"})
        self.assertLessEqual(wire.stream.position_at_close, n.MAX_HTTP_HEADERS + 1)

    def test_plain_local_does_not_create_tls_context(self):
        prepared = n.prepare(smtp(host="127.0.0.1", security="plain_local"))
        client = MagicMock()
        client.send_message.return_value = {}
        with patch.object(n, "_PlainClient", return_value=client), patch.object(n, "_context") as tls:
            self.assertEqual(n.deliver(prepared, event())["outcome"], "accepted")
        tls.assert_not_called()
        client.starttls.assert_not_called()
        client.login.assert_not_called()

    def test_webhook_sends_only_bounded_json_and_no_redirect_or_response_body(self):
        prepared = n.prepare(webhook(url="https://example.com/path?tenant=one", token_file=self.secret("abc")))
        connection = MagicMock()
        connection.getresponse.return_value.status = 202
        with patch.object(n.http.client, "HTTPSConnection", return_value=connection) as constructor:
            self.assertEqual(n.deliver(prepared, event(), 4), {"outcome": "accepted", "code": None})
        self.assertEqual(constructor.call_args.args, ("example.com", 443))
        self.assertEqual(constructor.call_args.kwargs["timeout"], 4)
        request = connection.request.call_args
        self.assertEqual(request.args, ("POST", "/path?tenant=one"))
        self.assertEqual(json.loads(request.kwargs["body"]), event())
        self.assertEqual(request.kwargs["headers"], {"Content-Type": "application/json",
                         "Idempotency-Key": "a" * 32, "Authorization": "Bearer abc"})
        connection.getresponse.return_value.read.assert_not_called()
        connection.getresponse.return_value.close.assert_called_once()
        connection.close.assert_called_once()

    def test_webhook_status_matrix_never_follows_redirects(self):
        prepared = n.prepare(webhook())
        for status in (200, 204, 299, 300, 301, 307, 308, 399, 400, 429, 500):
            connection = MagicMock()
            connection.getresponse.return_value.status = status
            expected = {"outcome": "accepted", "code": None} if status < 300 else {
                "outcome": "rejected", "code": "webhook_redirect_refused" if status < 400 else "webhook_rejected"}
            with patch.object(n.http.client, "HTTPSConnection", return_value=connection) as constructor:
                self.assertEqual(n.deliver(prepared, event()), expected)
            constructor.assert_called_once()
            connection.request.assert_called_once()

    def test_webhook_network_phase_and_cleanup_outcomes(self):
        prepared = n.prepare(webhook())
        with patch.object(n.http.client, "HTTPSConnection", side_effect=OSError("private-password")):
            self.assertEqual(n.deliver(prepared, event()), {"outcome": "rejected", "code": "webhook_connection_failed"})
        for method, outcome, code in (("connect", "rejected", "webhook_connection_failed"),
                                       ("request", "uncertain", "webhook_submission_uncertain"),
                                       ("getresponse", "uncertain", "webhook_submission_uncertain")):
            connection = MagicMock()
            getattr(connection, method).side_effect = TimeoutError("private-password")
            with patch.object(n.http.client, "HTTPSConnection", return_value=connection):
                self.assertEqual(n.deliver(prepared, event()), {"outcome": outcome, "code": code})
        connection = MagicMock()
        connection.getresponse.return_value.status = 204
        connection.getresponse.return_value.close.side_effect = OSError("private-password")
        connection.close.side_effect = OSError("private-password")
        with patch.object(n.http.client, "HTTPSConnection", return_value=connection):
            self.assertEqual(n.deliver(prepared, event()), {"outcome": "accepted", "code": None})

    def https_server(self):
        calls = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                calls.append((self.path, dict(self.headers), self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(202)
                self.end_headers()

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        worker.start()
        self.addCleanup(server.server_close)
        self.addCleanup(worker.join, 3)
        self.addCleanup(server.shutdown)
        return server.server_address[1], calls

    def test_real_loopback_https_verifies_custom_ca_ignores_proxy_and_keylog(self):
        port, calls = self.https_server()
        prepared = n.prepare(webhook(url=f"https://127.0.0.1:{port}/hook", ca_file=str(self.cert),
                                     token_file=self.secret("bearer-secret")))
        keylog = self.root / "keylog"
        with patch.dict(os.environ, {"HTTPS_PROXY": "http://127.0.0.1:1", "SSLKEYLOGFILE": str(keylog)}):
            self.assertEqual(n.deliver(prepared, event(), 2), {"outcome": "accepted", "code": None})
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1]["Authorization"], "Bearer bearer-secret")
        self.assertFalse(keylog.exists())

    def test_real_loopback_https_untrusted_certificate_never_submits(self):
        port, calls = self.https_server()
        prepared = n.prepare(webhook(url=f"https://127.0.0.1:{port}/hook"))
        self.assertEqual(n.deliver(prepared, event(), 2), {"outcome": "rejected", "code": "webhook_connection_failed"})
        self.assertEqual(calls, [])

    def test_real_loopback_https_hostname_mismatch_never_submits(self):
        port, calls = self.https_server()
        prepared = n.prepare(webhook(url=f"https://wrong.example.invalid:{port}/hook", ca_file=str(self.cert)))
        real_getaddrinfo = socket.getaddrinfo
        with patch.object(socket, "getaddrinfo", side_effect=lambda host, port, *args, **kwargs:
                          real_getaddrinfo("127.0.0.1", port, *args, **kwargs)):
            self.assertEqual(n.deliver(prepared, event(), 2),
                             {"outcome": "rejected", "code": "webhook_connection_failed"})
        self.assertEqual(calls, [])

    def smtp_server(self, mode="tls", failure=None):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(3)
        port = listener.getsockname()[1]
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        observed = {"commands": [], "data": [], "errors": []}

        def serve():
            connection = stream = None
            encrypted = mode == "tls"
            try:
                connection, _ = listener.accept()
                connection.settimeout(3)
                if encrypted:
                    connection = context.wrap_socket(connection, server_side=True)
                stream = connection.makefile("rb")
                if failure == "oversized_reply":
                    connection.sendall((b"220-" + b"x" * 7990 + b"\r\n") * 9 + b"220 Ready\r\n")
                else:
                    connection.sendall(b"220 Ready\r\n")
                while True:
                    line = stream.readline(8193)
                    if not line:
                        break
                    command = line.split(b" ", 1)[0].strip().upper()
                    observed["commands"].append((command, encrypted))
                    if command in (b"EHLO", b"HELO"):
                        connection.sendall(b"250-localhost\r\n250-STARTTLS\r\n250 AUTH PLAIN LOGIN\r\n")
                    elif command == b"STARTTLS":
                        connection.sendall(b"220 Begin TLS\r\n")
                        stream.close()
                        connection = context.wrap_socket(connection, server_side=True)
                        stream = connection.makefile("rb")
                        encrypted = True
                    elif command == b"AUTH":
                        connection.sendall(b"235 Authenticated\r\n")
                    elif command == b"MAIL":
                        connection.sendall(b"250 Sender accepted\r\n")
                    elif command == b"RCPT":
                        connection.sendall(b"550 Refused\r\n" if b"bad@example.com" in line else b"250 Recipient accepted\r\n")
                    elif command == b"DATA":
                        connection.sendall(b"354 Begin message\r\n")
                        lines = []
                        while True:
                            data = stream.readline(8193)
                            if data == b".\r\n":
                                break
                            if not data:
                                raise OSError("Unexpected test client disconnect")
                            lines.append(data)
                        observed["data"].append(b"".join(lines))
                        if failure == "drop_after_data":
                            break
                        connection.sendall(b"250 Message accepted\r\n")
                    elif command == b"RSET":
                        connection.sendall(b"250 Reset\r\n")
                    else:
                        raise AssertionError("Unexpected test SMTP command")
            except OSError as exc:
                observed["errors"].append(type(exc).__name__)
            finally:
                if stream is not None:
                    stream.close()
                if connection is not None:
                    connection.close()
                listener.close()

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()

        def finish():
            worker.join(4)
            self.assertFalse(worker.is_alive(), "Loopback SMTP worker did not stop")

        self.addCleanup(finish)
        return port, observed

    def test_real_loopback_smtp_tls_and_starttls_submit_once_after_encryption(self):
        for security in ("tls", "starttls"):
            with self.subTest(security=security):
                port, observed = self.smtp_server(security)
                prepared = n.prepare(smtp(host="127.0.0.1", port=port, security=security,
                                          username="user", password_file=self.secret(), ca_file=str(self.cert)))
                self.assertEqual(n.deliver(prepared, event(), 2), {"outcome": "accepted", "code": None})
                self.assertEqual(len(observed["data"]), 1)
                self.assertIn((b"AUTH", True), observed["commands"])
                self.assertIn((b"DATA", True), observed["commands"])
                self.assertNotIn((b"AUTH", False), observed["commands"])
                self.assertEqual(observed["errors"], [])

    def test_real_loopback_smtp_partial_refusal_remains_uncertain(self):
        port, observed = self.smtp_server()
        prepared = n.prepare(smtp(host="127.0.0.1", port=port, ca_file=str(self.cert),
                                  to=["good@example.com", "bad@example.com"]))
        self.assertEqual(n.deliver(prepared, event(), 2), {"outcome": "uncertain", "code": "smtp_partial_refusal"})
        self.assertEqual(len(observed["data"]), 1)

    def test_real_loopback_smtp_disconnect_after_data_is_not_retried(self):
        port, observed = self.smtp_server(failure="drop_after_data")
        prepared = n.prepare(smtp(host="127.0.0.1", port=port, ca_file=str(self.cert)))
        self.assertEqual(n.deliver(prepared, event(), 2),
                         {"outcome": "uncertain", "code": "smtp_submission_uncertain"})
        self.assertEqual(len(observed["data"]), 1)

    def test_real_loopback_smtp_multiline_reply_bound_prevents_submission(self):
        port, observed = self.smtp_server("plain_local", "oversized_reply")
        prepared = n.prepare(smtp(host="127.0.0.1", port=port, security="plain_local"))
        self.assertEqual(n.deliver(prepared, event(), 2),
                         {"outcome": "rejected", "code": "smtp_connection_failed"})
        self.assertEqual(observed["data"], [])


if __name__ == "__main__":
    unittest.main()
