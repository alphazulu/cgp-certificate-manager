"""Telegram Bot API fixtures use memory transcripts or verified loopback TLS."""
from copy import deepcopy
import http.client
import http.server
import io
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from cgp_cert_manager import notify_telegram as t, notify_transport as n


TOKEN = "123456789:" + "A" * 35


def event():
    return {"schema": 1, "id": "a" * 32, "kind": "alert", "observed_at": 1000.5,
            "status": "critical", "endpoints": [
                {"id": "mail", "status": "critical", "code": "tls_expired"},
                {"id": "imap", "status": "warning", "code": None},
                {"id": "smtp", "status": "ok", "code": None}]}


def acknowledgement(text=None, chat=-1001234567890, **extra):
    result = {"message_id": 42, "date": 1001, "chat": {"id": chat, "type": "supergroup"},
              "text": text if text is not None else t._message(event())}
    result.update(extra)
    return {"ok": True, "result": result}


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode()


def response(raw, status=200, headers=None):
    if headers is None:
        headers = b"Content-Length: " + str(len(raw)).encode() + b"\r\n"
    return b"HTTP/1.1 " + str(status).encode() + b" Fixture\r\n" + headers + b"\r\n" + raw


class TranscriptSocket:
    def __init__(self, wire):
        self.stream = io.BytesIO(wire)
        self.sent = []
        self.closed = False

    def makefile(self, mode):
        assert mode == "rb"
        return self.stream

    def sendall(self, value):
        self.sent.append(bytes(value))

    def close(self):
        self.closed = True


class TelegramTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert_temp = tempfile.TemporaryDirectory()
        cls.cert = Path(cls.cert_temp.name) / "ca.pem"
        cls.key = Path(cls.cert_temp.name) / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                        "-keyout", str(cls.key), "-out", str(cls.cert)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.cert.chmod(0o600)

    @classmethod
    def tearDownClass(cls):
        cls.cert_temp.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.token_file = self.root / "token"
        self.token_file.write_text(TOKEN + "\n")
        self.token_file.chmod(0o600)
        self.raw = {"id": "telegram", "kind": "telegram", "token_file": str(self.token_file),
                    "chat_id": "-1001234567890"}
        self.prepared = t.prepare(self.raw)

    def transcript(self, wire, prepared=None, observation=None):
        sock = TranscriptSocket(wire)

        def connect(connection):
            connection.sock = sock

        with patch.object(http.client.HTTPSConnection, "connect", connect):
            result = n.deliver(prepared or self.prepared, observation or event(), 2)
        self.assertTrue(sock.closed)
        self.assertTrue(sock.stream.closed)
        self.assertNotIn(TOKEN, json.dumps(result))
        self.assertNotIn(str(self.root), json.dumps(result))
        return result, b"".join(sock.sent)

    def assert_uncertain(self, wire):
        result, _ = self.transcript(wire)
        self.assertEqual(result["outcome"], "uncertain")
        self.assertIn(result["code"], t.CODES)

    def test_default_prepared_snapshot_and_route_canonicalization(self):
        self.assertEqual(self.prepared, {"id": "telegram", "kind": "telegram", "enabled": True,
                         "api_url": "https://api.telegram.org/", "chat_id": -1001234567890,
                         "secrets": {"token": TOKEN}})
        self.assertEqual(json.loads(json.dumps(self.prepared)), self.prepared)
        raw = {**self.raw, "api_url": "https://[::1]:8443/", "chat_id": "@Ops_Channel",
               "message_thread_id": 11, "ca_file": str(self.cert)}
        prepared = n.prepare(raw)
        self.assertEqual(prepared["api_url"], "https://[::1]:8443/")
        self.assertEqual(prepared["chat_id"], "@Ops_Channel")
        self.assertEqual(prepared["message_thread_id"], 11)
        self.assertEqual(prepared["secrets"]["ca_pem"], self.cert.read_text())
        self.assertNotIn("token_file", prepared)
        self.assertNotIn("ca_file", prepared)
        self.token_file.write_text("changed-after-prepare")
        self.assertEqual(prepared["secrets"]["token"], TOKEN)
        for value in (1, -1, t.MAX_CHAT_ID, -t.MAX_CHAT_ID, "0001"):
            with self.subTest(chat=value), patch.object(n, "_line_secret", return_value=TOKEN):
                self.assertEqual(t.prepare({**self.raw, "chat_id": value})["chat_id"], int(value))

    def test_disabled_channel_never_opens_files_or_connects(self):
        with patch.object(n, "_secret") as secret, patch.object(http.client, "HTTPSConnection") as connect:
            prepared = n.prepare({"id": "off", "kind": "telegram", "enabled": False,
                                  "token_file": "/missing"})
            self.assertEqual(prepared, {"id": "off", "kind": "telegram", "enabled": False})
            self.assertEqual(n.deliver(prepared, event()), {"outcome": "rejected", "code": "channel_disabled"})
        secret.assert_not_called()
        connect.assert_not_called()

    def test_configuration_rejects_unsafe_routing_and_types_without_secret_output(self):
        invalid = [None, [], {}, {**self.raw, "extra": "secret"}, {**self.raw, "kind": "smtp"},
                   {**self.raw, "id": "bad id"}, {**self.raw, "id": None}, {**self.raw, "enabled": 1}]
        invalid += [{**self.raw, "chat_id": value} for value in
                    (None, True, 0, 1.2, "", "+123", "0", "-0", "@", "@bad/slash", "@a" * 33,
                     "@name\n", t.MAX_CHAT_ID + 1, -t.MAX_CHAT_ID - 1, "9" * 100)]
        invalid += [{**self.raw, "message_thread_id": value} for value in
                    (None, False, 0, -1, "12", 1.5, 2**31)]
        invalid += [{**self.raw, "api_url": value} for value in
                    ("http://127.0.0.1", "https://api.telegram.org/path", "https://api.telegram.org/?",
                     "https://api.telegram.org/?a=b", "https://u:p@api.telegram.org/",
                     "https://api.telegram.org/#", "https://api.telegram.org/\n", "https://api.telegram.org/%2f")]
        for channel in invalid:
            with self.subTest(channel=channel), self.assertRaises(n.NotificationError) as raised:
                t.prepare(channel)
            self.assertNotIn(TOKEN, str(raised.exception))
            self.assertNotIn(str(self.root), str(raised.exception))

    def test_token_is_private_bounded_and_url_path_safe(self):
        for token in ("", "123", "0:abc", "123:a/b", "123:a?b", "123:a#b", "123:a b",
                      "123:a\nb", "123:a%2fb", "1" * 21 + ":a", "1:" + "A" * 201,
                      "123:é", "123:a\n\n"):
            self.token_file.write_text(token)
            with self.subTest(token=repr(token[:20])), self.assertRaises(n.NotificationError):
                t.prepare(self.raw)
        self.token_file.write_text("123:abc_DEF-012\r\n")
        self.assertEqual(t.prepare(self.raw)["secrets"]["token"], "123:abc_DEF-012")
        self.token_file.chmod(0o644)
        with self.assertRaises(n.NotificationError):
            t.prepare(self.raw)
        self.token_file.unlink()
        with self.assertRaises(n.NotificationError):
            t.prepare(self.raw)

    def test_plaintext_contains_stable_id_and_all_endpoint_reasons(self):
        text = t._message(event())
        self.assertEqual(text, "CGP external TLS: alert critical\nEvent: " + "a" * 32
                         + "\nmail: critical; reason=tls_expired"
                         + "\nimap: warning; reason=expiry_threshold\nsmtp: ok; reason=verified")
        result, request = self.transcript(response(encoded(acknowledgement())))
        self.assertEqual(result, {"outcome": "accepted", "code": None})
        header, body = request.split(b"\r\n\r\n", 1)
        self.assertTrue(header.startswith(("POST /bot" + TOKEN + "/sendMessage HTTP/1.1").encode()))
        self.assertEqual(json.loads(body), {"chat_id": -1001234567890, "text": text})
        self.assertNotIn(b"parse_mode", body)

    def test_message_bound_is_checked_before_any_network_and_no_split_or_truncation(self):
        with patch.object(t, "_message", return_value="x" * 4096):
            result, request = self.transcript(response(encoded(acknowledgement(text="x" * 4096))))
        self.assertEqual(result["outcome"], "accepted")
        self.assertEqual(len(json.loads(request.split(b"\r\n\r\n", 1)[1])["text"]), 4096)
        with patch.object(t, "_message", return_value="x" * 4097), patch.object(http.client, "HTTPSConnection") as opened:
            self.assertEqual(n.deliver(self.prepared, event()),
                             {"outcome": "rejected", "code": "telegram_message_too_long"})
        opened.assert_not_called()

    def test_maximum_endpoint_rows_are_all_present_in_one_message(self):
        observation = event()
        observation["endpoints"] = [{"id": str(index).zfill(2) + "x" * 62,
                                     "status": "critical", "code": "e" * 128} for index in range(16)]
        text = t._message(observation)
        self.assertLessEqual(len(text), 4096)
        result, request = self.transcript(response(encoded(acknowledgement(text=text))), observation=observation)
        self.assertEqual(result["outcome"], "accepted")
        payload = json.loads(request.split(b"\r\n\r\n", 1)[1])
        self.assertEqual(payload["text"], text)
        self.assertEqual(len(text.splitlines()), 18)
        for row in observation["endpoints"]:
            self.assertIn(row["id"] + ": critical; reason=" + row["code"], text)
        self.assertEqual(request.count(b"POST "), 1)

    def test_invalid_endpoint_format_never_submits(self):
        invalid = [{}, {"id": None, "status": "ok", "code": None},
                   {"id": "bad\nname", "status": "ok", "code": None},
                   {"id": "bad name", "status": "ok", "code": None},
                   {"id": "name", "status": "unknown", "code": None},
                   {"id": "name", "status": "ok", "code": []},
                   {"id": "name", "status": "critical", "code": "bad reason"}]
        for row in invalid:
            observation = {**event(), "endpoints": [row]}
            with self.subTest(row=row), patch.object(http.client, "HTTPSConnection") as opened:
                self.assertEqual(n.deliver(self.prepared, observation),
                                 {"outcome": "rejected", "code": "invalid_event"})
            opened.assert_not_called()
        with patch.object(http.client, "HTTPSConnection") as opened:
            self.assertEqual(t.deliver(self.prepared, {"kind": None}, b"", 2)["code"], "invalid_event")
        opened.assert_not_called()

    def test_thread_and_named_chat_acknowledgements(self):
        prepared = t.prepare({**self.raw, "chat_id": "@ops", "message_thread_id": 11})
        result, request = self.transcript(response(encoded(acknowledgement(chat=123, message_thread_id=11))), prepared)
        self.assertEqual(result["outcome"], "accepted")
        payload = json.loads(request.split(b"\r\n\r\n", 1)[1])
        self.assertEqual(payload["message_thread_id"], 11)
        self.assertEqual(payload["chat_id"], "@ops")
        for thread in (None, 12, True):
            ack = acknowledgement(chat=123, message_thread_id=thread)
            result, _ = self.transcript(response(encoded(ack)), prepared)
            self.assertEqual(result["outcome"], "uncertain")
        result, _ = self.transcript(response(encoded(acknowledgement(message_thread_id=11))))
        self.assertEqual(result["outcome"], "accepted")

    def test_positive_http_is_not_enough_and_wrong_message_is_not_acknowledged(self):
        changes = [{"message_id": value} for value in (None, False, 0, -1, 1.5, 2**63)]
        changes += [{"date": value} for value in (None, False, 0, -1, 1.5)]
        changes += [{"text": value} for value in (None, "different text")]
        changes += [{"chat": value} for value in (None, [], {}, {"id": True, "type": "private"},
                    {"id": 0, "type": "private"}, {"id": t.MAX_CHAT_ID + 1, "type": "private"},
                    {"id": -1001234567890, "type": "other"}, {"id": 1, "type": "supergroup"})]
        changes += [{"message_thread_id": value} for value in (False, 0, "1", 2**31)]
        for change in changes:
            with self.subTest(change=change):
                data = acknowledgement()
                data["result"].update(change)
                self.assert_uncertain(response(encoded(data)))
        for data in ({"ok": True}, {"ok": True, "result": None}, {"ok": True, "result": []},
                     {**acknowledgement(), "parameters": {}}, {**acknowledgement(), "error_code": 400},
                     {"ok": 1, "result": acknowledgement()["result"]}, [], None):
            with self.subTest(data=data):
                self.assert_uncertain(response(encoded(data)))
        self.assert_uncertain(response(encoded(acknowledgement()), status=400))

    def test_explicit_api_rejections_and_server_uncertainty(self):
        for status in (200, 400, 401, 403, 404, 409):
            data = {"ok": False, "error_code": 400, "description": "PRIVATE response text",
                    "parameters": {"migrate_to_chat_id": -123}}
            result, _ = self.transcript(response(encoded(data), status))
            self.assertEqual(result, {"outcome": "rejected", "code": "telegram_rejected"})
        for status in (500, 502, 503):
            result, _ = self.transcript(response(encoded(acknowledgement()), status))
            self.assertEqual(result, {"outcome": "uncertain", "code": "telegram_server_error"})
        data = {"ok": False, "error_code": 500, "description": "internal"}
        result, _ = self.transcript(response(encoded(data)))
        self.assertEqual(result, {"outcome": "uncertain", "code": "telegram_server_error"})

    def test_malformed_negative_response_cannot_confirm_rejection(self):
        base = {"ok": False, "error_code": 400, "description": "failed"}
        for changes in ({"error_code": None}, {"error_code": True}, {"error_code": 0},
                        {"description": None}, {"description": ""}, {"result": {}}, {"parameters": []}):
            with self.subTest(changes=changes):
                self.assert_uncertain(response(encoded({**base, **changes}), 400))
        with self.assertRaises(ValueError):
            t._answer(101, encoded(base), self.prepared, t._message(event()))

    def test_rate_limit_hint_is_bounded_and_only_from_explicit_429(self):
        base = {"ok": False, "error_code": 429, "description": "retry"}
        result, _ = self.transcript(response(encoded(base), 429))
        self.assertEqual(result, {"outcome": "rejected", "code": "telegram_rate_limited"})
        for seconds in (1, 60, 2**31 - 1):
            data = {**base, "parameters": {"retry_after": seconds}}
            for status in (200, 429):
                result, _ = self.transcript(response(encoded(data), status))
                self.assertEqual(result, {"outcome": "rejected", "code": "telegram_rate_limited",
                                         "retry_after_seconds": seconds})
        for seconds in (None, False, 0, -1, 1.5, "60", 2**31):
            with self.subTest(seconds=seconds):
                self.assert_uncertain(response(encoded({**base, "parameters": {"retry_after": seconds}}), 429))
        self.assert_uncertain(response(encoded({**base, "error_code": 400}), 429))
        result, _ = self.transcript(response(encoded({**base, "parameters": {"retry_after": 60}}), 400))
        self.assertEqual(result, {"outcome": "rejected", "code": "telegram_rejected"})

    def test_redirects_are_refused_without_followup(self):
        for status in (301, 302, 303, 307, 308):
            result, request = self.transcript(response(b"", status, b"Location: https://other.invalid/\r\n"))
            self.assertEqual(result, {"outcome": "rejected", "code": "telegram_redirect_refused"})
            self.assertEqual(request.count(b"POST "), 1)
            self.assertNotIn(b"other.invalid", request)

    def test_strict_json_rejects_duplicate_nonfinite_and_truncated_documents(self):
        valid = encoded(acknowledgement())
        bad = [b"", b"{", b"\xff", valid + b"extra", b'{"ok":true,"ok":false}',
               valid.replace(b'"message_id":42', b'"message_id":42,"message_id":42'),
               b'{"ok":false,"error_code":400,"description":"x","x":' + b"1" * 5000 + b"}",
               valid[:-1] + b',"x":' + b"[" * 1500 + b"0" + b"]" * 1500 + b"}"]
        bad += [valid[:-1] + b',"x":' + value + b"}" for value in
                (b"NaN", b"Infinity", b"-Infinity", b"1e999", b"-1e999")]
        for raw in bad:
            with self.subTest(prefix=raw[:40]):
                self.assert_uncertain(response(raw))
        result, _ = self.transcript(response(valid[:-1] + b',"unused":1.25}'))
        self.assertEqual(result["outcome"], "accepted")

    def test_response_structure_has_independent_depth_and_node_limits(self):
        data = acknowledgement()
        nested = 0
        for _ in range(31):
            nested = [nested]
        data["unused"] = nested
        result, _ = self.transcript(response(encoded(data)))
        self.assertEqual(result["outcome"], "accepted")
        data["unused"] = [nested]
        self.assert_uncertain(response(encoded(data)))
        data["unused"] = [0] * 4096
        self.assert_uncertain(response(encoded(data)))

    def test_content_length_requires_complete_unambiguous_bounded_framing(self):
        raw = encoded(acknowledgement())
        length = str(len(raw)).encode()
        invalid = [b"", b"Content-Length: -1\r\n", b"Content-Length: nope\r\n",
                   b"Content-Length: 999999999\r\n", b"Content-Length: 65537\r\n",
                   b"Content-Length: " + str(len(raw) + 1).encode() + b"\r\n",
                   b"Content-Length: " + length + b"\r\nContent-Length: " + length + b"\r\n",
                   b"Content-Length: " + length + b"\r\nTransfer-Encoding: chunked\r\n",
                   b"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
                   b"Transfer-Encoding: gzip\r\n", b"Transfer-Encoding: chunked \r\n",
                   b"Content-Length: " + length + b"\r\nContent-Encoding: gzip\r\n",
                   b"Content-Length: " + length + b"\r\nContent-Encoding: identity\r\nContent-Encoding: identity\r\n",
                   b"Content-Length: " + length + b"\r\nMalformed header\r\n"]
        for headers in invalid:
            with self.subTest(headers=headers):
                self.assert_uncertain(response(raw, headers=headers))
        result, _ = self.transcript(response(raw, headers=b"Content-Length: \t" + length
                                             + b" \r\nContent-Encoding: identity\r\n"))
        self.assertEqual(result["outcome"], "accepted")

    def test_truncated_http_headers_and_status_never_acknowledge(self):
        raw = encoded(acknowledgement())
        for wire in (b"", b"HTTP/1.1 200 OK", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n",
                     b"HTTP/1.1 200 OK\nContent-Length: 0\n\n", b"HTTP/1.1 200 OK\r\n" + b"x" * 65537,
                     response(raw)[:-3]):
            with self.subTest(prefix=wire[:60]):
                self.assert_uncertain(wire)

    def test_complete_chunked_acknowledgement_with_multiple_chunks_and_trailers(self):
        raw = encoded(acknowledgement())
        first, second = raw[:20], raw[20:]
        body = (f"{len(first):x};fixture=yes\r\n".encode() + first + b"\r\n"
                + f"{len(second):x}\r\n".encode() + second + b"\r\n0\r\nX-Fixture: ok\r\n\r\n")
        result, _ = self.transcript(response(body, headers=b"Transfer-Encoding: chunked\r\n"))
        self.assertEqual(result, {"outcome": "accepted", "code": None})

    def test_chunked_framing_rejects_eof_bad_delimiters_sizes_and_trailers(self):
        raw = encoded(acknowledgement())
        prefix = f"{len(raw):x}\r\n".encode() + raw
        invalid = [prefix, prefix + b"\r\n", prefix + b"\r\n0\r\n", prefix + b"\r\n0\r\nX: y\r\n",
                   prefix + b"xx0\r\n\r\n", prefix + b"\n\n0\r\n\r\n", b"-1\r\n", b"z\r\n",
                   b"10001\r\n", b"1\n", b"1" * 65537,
                   prefix + b"\r\n0\r\nbad trailer\r\n\r\n",
                   prefix + b"\r\n0\r\nContent-Length: 1\r\n\r\n",
                   prefix + b"\r\n0\r\nTransfer-Encoding: chunked\r\n\r\n",
                   prefix + b"\r\n0\r\nContent-Encoding: identity\r\n\r\n"]
        for body in invalid:
            with self.subTest(prefix=body[:40]):
                self.assert_uncertain(response(body, headers=b"Transfer-Encoding: chunked\r\n"))

    def test_exact_response_cap_and_oversized_chunked_body(self):
        data = {**acknowledgement(), "padding": ""}
        base = encoded(data)
        data["padding"] = "x" * (t.MAX_RESPONSE - len(base))
        raw = encoded(data)
        self.assertEqual(len(raw), 65536)
        result, _ = self.transcript(response(raw))
        self.assertEqual(result["outcome"], "accepted")
        raw += b" "
        chunks = raw[:32768], raw[32768:]
        body = b"".join(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n" for chunk in chunks) + b"0\r\n\r\n"
        self.assert_uncertain(response(body, headers=b"Transfer-Encoding: chunked\r\n"))

    def test_connect_failure_is_rejected_but_submission_failure_is_uncertain(self):
        with patch.object(http.client, "HTTPSConnection", side_effect=OSError(TOKEN)):
            self.assertEqual(n.deliver(self.prepared, event()),
                             {"outcome": "rejected", "code": "telegram_connection_failed"})
        with patch.object(http.client.HTTPSConnection, "connect", side_effect=OSError(TOKEN)):
            self.assertEqual(n.deliver(self.prepared, event()),
                             {"outcome": "rejected", "code": "telegram_connection_failed"})
        with patch.object(http.client.HTTPSConnection, "connect"), \
                patch.object(http.client.HTTPSConnection, "request", side_effect=TimeoutError(TOKEN)):
            self.assertEqual(n.deliver(self.prepared, event()),
                             {"outcome": "uncertain", "code": "telegram_submission_uncertain"})

    def test_cleanup_failure_cannot_erase_observed_acknowledgement(self):
        sock = TranscriptSocket(response(encoded(acknowledgement())))

        def connect(connection):
            connection.sock = sock

        with patch.object(http.client.HTTPSConnection, "connect", connect), \
                patch.object(http.client.HTTPSConnection, "close", side_effect=OSError(TOKEN)), \
                patch.object(t._Response, "close", side_effect=OSError(TOKEN)):
            self.assertEqual(n.deliver(self.prepared, event()), {"outcome": "accepted", "code": None})

    def https_server(self):
        calls = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                calls.append((self.path, dict(self.headers), json.loads(body)))
                request = calls[-1][2]
                data = acknowledgement(text=request["text"], chat=request["chat_id"])
                if "message_thread_id" in request:
                    data["result"]["message_thread_id"] = request["message_thread_id"]
                raw = encoded(data)
                self.send_response(200)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 3)
        self.addCleanup(server.shutdown)
        return server.server_address[1], calls

    def test_public_dispatch_real_tls_loopback_acknowledges_exact_message_once(self):
        port, calls = self.https_server()
        prepared = n.prepare({**self.raw, "api_url": f"https://127.0.0.1:{port}",
                              "ca_file": str(self.cert), "message_thread_id": 11})
        keylog = self.root / "keylog"
        with patch.dict(os.environ, {"HTTPS_PROXY": "http://127.0.0.1:1", "SSLKEYLOGFILE": str(keylog)}):
            self.assertEqual(n.deliver(prepared, event(), 2), {"outcome": "accepted", "code": None})
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "/bot" + TOKEN + "/sendMessage")
        self.assertEqual(calls[0][2], {"chat_id": -1001234567890, "text": t._message(event()), "message_thread_id": 11})
        self.assertFalse(keylog.exists())

    def test_real_tls_untrusted_or_wrong_name_never_sends_token(self):
        port, calls = self.https_server()
        prepared = n.prepare({**self.raw, "api_url": f"https://127.0.0.1:{port}"})
        self.assertEqual(n.deliver(prepared, event(), 2),
                         {"outcome": "rejected", "code": "telegram_connection_failed"})
        prepared = n.prepare({**self.raw, "api_url": f"https://wrong.example.invalid:{port}", "ca_file": str(self.cert)})
        resolve = socket.getaddrinfo
        with patch.object(socket, "getaddrinfo", side_effect=lambda host, port, *args, **kwargs:
                          resolve("127.0.0.1", port, *args, **kwargs)):
            self.assertEqual(n.deliver(prepared, event(), 2),
                             {"outcome": "rejected", "code": "telegram_connection_failed"})
        self.assertEqual(calls, [])
