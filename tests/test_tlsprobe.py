"""Synthetic endpoint contracts and genuine TLS on loopback only."""
import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from cgp_cert_manager import core, storage, tlsprobe as probe


def endpoint(**changes):
    return dict({"host": "127.0.0.1", "port": 443,
                 "server_name": "mail.example.test"}, **changes)


def prepared(**changes):
    return dict({"host": "127.0.0.1", "port": 443, "server_name": "mail.example.test",
                 "protocol": "tls", "ca_pem": None}, **changes)


def address(value="127.0.0.1", port=443):
    if ":" in value:
        return socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (value, port, 0, 0)
    return socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (value, port)


class BytesSocket:
    """Deterministic fragmented network input, with no real network calls."""
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.commands = []
        self.timeouts = []

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def recv(self, size):
        if not self.chunks:
            return b""
        value = self.chunks.pop(0)
        if len(value) > size:
            self.chunks.insert(0, value[size:])
        return value[:size]

    def sendall(self, value):
        self.commands.append(value)


class TLSProbeContractTests(unittest.TestCase):
    def assert_error(self, result, code):
        self.assertEqual(set(result), {"status", "code", "peer_address", "not_after",
                                      "fingerprint_sha256", "tls_version"})
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], code)
        self.assertIn(code, probe.ERROR_CODES)
        for name in ("not_after", "fingerprint_sha256", "tls_version"):
            self.assertIsNone(result[name])

    def test_prepare_normalizes_dns_idna_ipv4_ipv6_and_defaults(self):
        value = endpoint(host="MÜNICH.Example.", server_name="MAIL.Example.")
        original = dict(value)
        result = probe.prepare(value)
        self.assertEqual(value, original)
        self.assertEqual(result, prepared(host="xn--mnich-kva.example", server_name="mail.example"))
        self.assertEqual(json.loads(json.dumps(result)), result)
        self.assertEqual(probe.prepare(endpoint(host="2001:0db8::1", server_name="::1")),
                         prepared(host="2001:db8::1", server_name="::1"))

    def test_invalid_endpoint_is_rejected_before_files_or_network(self):
        values = [None, [], {}, dict(endpoint(), extra="PRIVATE"),
                  {"host": "127.0.0.1", "port": 443}, endpoint(protocol="unknown"), endpoint(protocol=[])]
        for port in (True, False, 0, -1, 65536, 443.0, "443", None):
            values.append(endpoint(port=port))
        for name in (None, 1, "", " ", "example", "bad host.example", "*.example.test", "a" * 254,
                     " example.test", "example.test\n", "https://example.test", "[::1]", "fe80::1%lo"):
            values.extend((endpoint(host=name), endpoint(server_name=name)))
        with patch.object(storage, "open_private") as read, patch.object(socket, "getaddrinfo") as resolve:
            for value in values:
                with self.subTest(value=value), self.assertRaisesRegex(probe.ProbeError, "^invalid_endpoint$"):
                    probe.prepare(value)
            read.assert_not_called()
            resolve.assert_not_called()

    def test_invalid_prepared_data_and_timeout_never_open_a_connection(self):
        values = [endpoint(), dict(prepared(), ca_file="PRIVATE"), None]
        values += [{key: value for key, value in prepared().items() if key != missing}
                   for missing in ("protocol", "ca_pem")]
        with patch.object(probe, "_connect") as connect:
            for value in values:
                self.assert_error(probe.observe(value), "invalid_endpoint")
            for timeout in (None, True, 0, -1, 61, float("nan"), float("inf"), "15"):
                with self.subTest(timeout=timeout):
                    self.assert_error(probe.observe(prepared(), timeout), "invalid_endpoint")
            connect.assert_not_called()

    def test_missing_unsafe_or_nonabsolute_ca_path_is_sanitized(self):
        for path in (1, [], "relative.pem", "/missing/PRIVATE-CA.pem", "/bad\0PRIVATE.pem"):
            with self.subTest(path=path), self.assertRaisesRegex(probe.ProbeError, "^ca_unavailable$"):
                probe.prepare(endpoint(ca_file=path))
        with patch.object(storage, "open_private", side_effect=PermissionError("PRIVATE path")), \
                self.assertRaisesRegex(probe.ProbeError, "^ca_unavailable$"):
            probe.prepare(endpoint(ca_file="/a.pem"))

    def test_strict_ca_pem_refuses_noncertificate_content_and_bad_base64(self):
        def pem(body):
            return "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----\n"
        values = [[], 1, "", "PRIVATE", "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----",
                  pem("A"), pem("A==="), pem("AB=="), pem(" \n"), pem("YQ=="),
                  pem("AA==") + "PRIVATE", " " * (probe.MAX_CA_BYTES + 1)]
        with patch.object(probe, "_connect") as connect:
            for value in values:
                with self.subTest(value=str(value)[:60]):
                    self.assert_error(probe.observe(prepared(ca_pem=value)), "ca_unavailable")
            connect.assert_not_called()

    def test_system_context_requires_trust_hostname_tls12_and_disables_cn_fallback(self):
        context = probe._context(None)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertFalse(context.hostname_checks_common_name)
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertIsNone(context.keylog_filename)
        with patch.object(probe.ssl, "SSLContext", side_effect=OSError("PRIVATE trust failure")):
            self.assert_error(probe.observe(prepared()), "ca_unavailable")

    def test_connection_retries_only_tcp_failure_and_closes_failed_sockets(self):
        first, second = Mock(), Mock()
        first.connect.side_effect = ConnectionRefusedError("PRIVATE")
        records = [address(), address(), (socket.AF_UNIX, socket.SOCK_STREAM, 0, "", "unused"),
                   (socket.AF_INET, socket.SOCK_DGRAM, 0, "", ("127.0.0.1", 443)), address("::1")]
        with patch.object(probe.socket, "getaddrinfo", return_value=records) as resolve, \
                patch.object(probe.socket, "socket", side_effect=[first, second]) as create:
            connection, peer = probe._connect(endpoint(), time.monotonic() + 15)
        self.assertIs(connection, second)
        self.assertEqual(peer, "::1")
        self.assertEqual(create.call_count, 2)
        first.close.assert_called_once()
        second.close.assert_not_called()
        resolve.assert_called_once_with("127.0.0.1", 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
        self.assertLessEqual(second.settimeout.call_args.args[0], probe.CONNECT_TIMEOUT)

    def test_address_limit_caps_connection_attempts(self):
        connection = Mock()
        connection.connect.side_effect = ConnectionRefusedError()
        values = [address("127.0.0." + str(index)) for index in range(1, 11)]
        with patch.object(probe, "_context"), patch.object(probe.socket, "getaddrinfo", return_value=values), \
                patch.object(probe.socket, "socket", return_value=connection) as create:
            self.assert_error(probe.observe(prepared()), "connect_failed")
        self.assertEqual(create.call_count, 8)
        self.assertEqual(connection.close.call_count, 8)

    def test_dns_error_and_no_supported_addresses(self):
        with patch.object(probe, "_context"):
            for value in ([], [(socket.AF_UNIX, socket.SOCK_STREAM, 0, "", "unused")]):
                with patch.object(socket, "getaddrinfo", return_value=value):
                    self.assert_error(probe.observe(prepared()), "dns_failed")
            with patch.object(socket, "getaddrinfo", side_effect=socket.gaierror("PRIVATE DNS failure")):
                self.assert_error(probe.observe(prepared()), "dns_failed")

    def test_tcp_timeout_creation_failure_and_global_deadline(self):
        connection = Mock()
        connection.connect.side_effect = TimeoutError("PRIVATE")
        with patch.object(probe, "_context"), patch.object(socket, "getaddrinfo", return_value=[address()]):
            with patch.object(socket, "socket", return_value=connection):
                self.assert_error(probe.observe(prepared()), "timeout")
            with patch.object(socket, "socket", side_effect=OSError("PRIVATE")):
                self.assert_error(probe.observe(prepared()), "connect_failed")
        with patch.object(probe.time, "monotonic", return_value=10), \
                self.assertRaisesRegex(probe.ProbeError, "^timeout$"):
            probe._remaining(10)

    def test_deadline_or_interrupt_after_socket_creation_closes_it(self):
        for failure in (probe.ProbeError("timeout"), KeyboardInterrupt()):
            connection = Mock()
            connection.settimeout.side_effect = failure
            with patch.object(socket, "getaddrinfo", return_value=[address()]), \
                    patch.object(socket, "socket", return_value=connection), \
                    self.assertRaises(type(failure)):
                probe._connect(endpoint(), time.monotonic() + 15)
            connection.close.assert_called_once()

    def reader(self, chunks):
        return probe._Plaintext(BytesSocket(chunks), time.monotonic() + 15)

    def test_fragmented_lines_preserve_buffer_and_bound_each_socket_operation(self):
        reader = self.reader([b"220 hel", b"lo\r", b"\n250 hi\r\n"])
        self.assertEqual(reader.line(), b"220 hello")
        self.assertEqual(reader.line(), b"250 hi")
        reader.send(b"STARTTLS")
        self.assertEqual(reader.connection.commands, [b"STARTTLS\r\n"])
        self.assertTrue(all(0 < timeout <= 15 for timeout in reader.connection.timeouts))
        reader.finish()

    def test_plaintext_truncation_control_bytes_and_line_limits(self):
        values = [[], [b"220 incomplete"], [b"220 bare\n"], [b"220 nul\0\r\n"],
                  [b"220 del\x7f\r\n"], [b"220 interior\rtext\r\n"],
                  [b"x" * probe.MAX_LINE], [b"x" * (probe.MAX_LINE - 1) + b"\r\n"]]
        for chunks in values:
            with self.subTest(chunks=str(chunks)[:40]), self.assertRaisesRegex(probe.ProbeError, "^protocol_error$"):
                self.reader(chunks).line()
        reader = self.reader([b"\r\n" * (probe.MAX_LINES + 1)])
        for _ in range(probe.MAX_LINES):
            reader.line()
        with self.assertRaisesRegex(probe.ProbeError, "^protocol_error$"):
            reader.line()

    def test_total_plaintext_bound_and_buffered_upgrade_bytes(self):
        reader = self.reader([b"x" * 4094 + b"\r\n"] * 9)
        for _ in range(8):
            reader.line()
        with self.assertRaisesRegex(probe.ProbeError, "^protocol_error$"):
            reader.line()
        reader = self.reader([b"220 go\r\nPRIVATE leftover"])
        self.assertEqual(reader.line(), b"220 go")
        with self.assertRaisesRegex(probe.ProbeError, "^protocol_error$"):
            reader.finish()

    def test_plaintext_deadline_is_not_reset_by_slow_progress(self):
        now = [0]
        connection = BytesSocket([b"2", b"2", b"0", b"\r\n"])
        original = connection.recv
        def receive(size):
            now[0] += 2
            return original(size)
        connection.recv = receive
        reader = probe._Plaintext(connection, 5)
        with patch.object(probe.time, "monotonic", side_effect=lambda: now[0]), \
                self.assertRaisesRegex(probe.ProbeError, "^timeout$"):
            reader.line()
        self.assertEqual(connection.timeouts, [5, 3, 1])

    def test_smtp_multiline_codes_capabilities_and_rejection(self):
        successful = self.reader([b"220\r\n250-mail\r\n250-STARTTLS\r\n250 SIZE 10\r\n220\r\n"])
        probe._smtp(successful)
        self.assertEqual(successful.connection.commands, [b"EHLO probe.invalid\r\n", b"STARTTLS\r\n"])
        cases = [(b"500 nope\r\n", "protocol_error"),
                 (b"220 hi\r\n500 no EHLO\r\n", "starttls_unavailable"),
                 (b"220 hi\r\n250 STARTTLS forbidden_parameter\r\n", "starttls_unavailable"),
                 (b"220 hi\r\n250 SIZE 10\r\n", "starttls_unavailable"),
                 (b"220 hi\r\n250 STARTTLS\r\n454 PRIVATE\r\n", "starttls_rejected")]
        for transcript, code in cases:
            with self.subTest(code=code), self.assertRaisesRegex(probe.ProbeError, "^" + code + "$"):
                probe._smtp(self.reader([transcript]))
        for line in (b"22\r\n", b"abc reply\r\n", b"220Xreply\r\n", b"250-first\r\n220 last\r\n"):
            with self.assertRaisesRegex(probe.ProbeError, "^protocol_error$"):
                probe._smtp_reply(self.reader([line]))

    def test_imap_requires_unauthenticated_greeting_and_matching_tagged_responses(self):
        reader = self.reader([b"* OK hello\r\n* OK notice\r\n* CAPABILITY IMAP4rev1 starttls\r\n"
                              b"cgp1 ok complete\r\ncgp2 OK begin\r\n"])
        probe._imap(reader)
        self.assertEqual(reader.connection.commands, [b"cgp1 CAPABILITY\r\n", b"cgp2 STARTTLS\r\n"])
        for greeting in (b"\r\n", b"+ OK hi\r\n", b"* PREAUTH hi\r\n"):
            with self.assertRaisesRegex(probe.ProbeError, "^protocol_error$"):
                probe._imap(self.reader([greeting]))
        for line in (b"\r\n", b"* BYE PRIVATE\r\n", b"wrong OK done\r\n", b"cgp1 WHAT done\r\n"):
            with self.assertRaisesRegex(probe.ProbeError, "^protocol_error$"):
                probe._imap_reply(self.reader([line]), b"cgp1")
        for capability in (b"cgp1 NO unavailable\r\n", b"* CAPABILITY IMAP4rev1\r\ncgp1 OK done\r\n"):
            with self.assertRaisesRegex(probe.ProbeError, "^starttls_unavailable$"):
                probe._imap(self.reader([b"* OK greeting\r\n" + capability]))
        with self.assertRaisesRegex(probe.ProbeError, "^starttls_rejected$"):
            probe._imap(self.reader([b"* OK hi\r\n* CAPABILITY STARTTLS\r\ncgp1 OK done\r\ncgp2 BAD PRIVATE\r\n"]))

    def test_pop3_capability_termination_exact_tokens_and_upgrade_rejection(self):
        reader = self.reader([b"+OK hi\r\n+ok list\r\nPIPELINING\r\nSTLS\r\n.\r\n+OK go\r\n"])
        probe._pop3(reader)
        self.assertEqual(reader.connection.commands, [b"CAPA\r\n", b"STLS\r\n"])
        for data, code in ((b"-ERR greeting\r\n", "protocol_error"),
                           (b"+OK hi\r\n-ERR no CAPA\r\n", "starttls_unavailable"),
                           (b"+OK hi\r\n+OK list\r\n..STLS\r\nSTLS invalid\r\n.\r\n", "starttls_unavailable"),
                           (b"+OK hi\r\n+OK list\r\nSTLS\r\n.\r\n-ERR PRIVATE\r\n", "starttls_rejected")):
            with self.subTest(code=code), self.assertRaisesRegex(probe.ProbeError, "^" + code + "$"):
                probe._pop3(self.reader([data]))
        self.assertFalse(probe._pop_ok(b"+OKsomething"))

    @contextmanager
    def fake_tls(self, **changes):
        plain, secure, context = Mock(), Mock(), Mock()
        context.wrap_socket.return_value = secure
        secure.getpeercert.side_effect = [b"DER certificate", {"notAfter": "Nov 24 12:00:00 2030 GMT"}]
        secure.version.return_value = "TLSv1.3"
        for name, value in changes.items():
            setattr(secure, name, value)
        with patch.object(probe, "_context", return_value=context), \
                patch.object(probe, "_connect", return_value=(plain, "127.0.0.1")) as connect:
            yield plain, secure, context, connect

    def test_observe_fixed_schema_metadata_and_socket_cleanup(self):
        with self.fake_tls() as (plain, secure, context, connect):
            result = probe.observe(prepared())
        self.assertEqual(result, {"status": "ok", "code": None, "peer_address": "127.0.0.1",
                         "not_after": ssl.cert_time_to_seconds("Nov 24 12:00:00 2030 GMT"),
                         "fingerprint_sha256": hashlib.sha256(b"DER certificate").hexdigest(), "tls_version": "TLSv1.3"})
        context.wrap_socket.assert_called_once_with(plain, server_hostname="mail.example.test")
        secure.close.assert_called_once()
        connect.assert_called_once()

    def test_certificate_metadata_refuses_absence_oversize_or_invalid_expiry(self):
        for der in (None, "DER", b"", b"x" * (probe.MAX_CERTIFICATE_BYTES + 1)):
            with self.fake_tls() as (_, secure, _, _):
                secure.getpeercert.side_effect = [der, {}]
                self.assert_error(probe.observe(prepared()), "certificate_unreadable")
        for info in ({}, None, {"notAfter": "PRIVATE invalid date"}):
            with self.fake_tls() as (_, secure, _, _):
                secure.getpeercert.side_effect = [b"DER", info]
                self.assert_error(probe.observe(prepared()), "certificate_unreadable")
        for expiry in (None, True, float("nan"), float("inf")):
            with self.fake_tls(), patch.object(ssl, "cert_time_to_seconds", return_value=expiry):
                self.assert_error(probe.observe(prepared()), "certificate_unreadable")
        with self.fake_tls() as (_, secure, _, _):
            secure.version.return_value = "TLSv1"
            self.assert_error(probe.observe(prepared()), "tls_handshake_failed")

    def test_verification_codes_are_fixed_and_never_retry_unverified(self):
        cases = [(9, "tls_not_yet_valid"), (10, "tls_expired"), (62, "tls_hostname_mismatch"),
                 (64, "tls_hostname_mismatch"), (18, "tls_untrusted"), (19, "tls_untrusted"),
                 (20, "tls_untrusted"), (21, "tls_untrusted"), (999, "tls_verification_failed")]
        for numeric, code in cases:
            with self.subTest(numeric=numeric), self.fake_tls() as (plain, _, context, connect):
                error = ssl.SSLCertVerificationError("PRIVATE provider message")
                error.verify_code = numeric
                context.wrap_socket.side_effect = error
                result = probe.observe(prepared())
                self.assert_error(result, code)
                self.assertNotIn("PRIVATE", json.dumps(result))
                context.wrap_socket.assert_called_once()
                connect.assert_called_once()
                plain.close.assert_called_once()

    def test_transport_internal_and_close_errors_do_not_leak_details(self):
        for error, code in ((TimeoutError("PRIVATE"), "timeout"), (ssl.SSLError("PRIVATE"), "tls_handshake_failed"),
                            (OSError("PRIVATE"), "connect_failed"), (RuntimeError("PRIVATE"), "worker_failed")):
            with self.fake_tls() as (plain, _, context, _):
                context.wrap_socket.side_effect = error
                self.assert_error(probe.observe(prepared()), code)
                plain.close.assert_called_once()
        with self.fake_tls() as (_, secure, _, _):
            secure.close.side_effect = OSError("PRIVATE close failure")
            self.assert_error(probe.observe(prepared()), "worker_failed")


class TLSProbeLoopbackTests(unittest.TestCase):
    assert_error = TLSProbeContractTests.assert_error
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        def openssl(*arguments):
            return subprocess.run(["openssl", *map(str, arguments)], input=b"", check=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20).stdout
        cls.openssl = staticmethod(openssl)
        cls.ca = cls.directory / "root.pem"
        cls.key = cls.directory / "leaf.key"
        root_key = cls.directory / "root.key"
        openssl("req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "3",
                "-subj", "/CN=Disposable TLS Probe Root", "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", root_key, "-out", cls.ca)
        cls.ca.chmod(0o600)
        csr = cls.directory / "leaf.csr"
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256", "-subj", "/CN=legacy.example.test",
                "-keyout", cls.key, "-out", csr)
        extensions = cls.directory / "leaf.ext"
        extensions.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                              "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:mail.example.test,IP:127.0.0.1\n"
                              "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
        openssl("x509", "-req", "-in", csr, "-CA", cls.ca, "-CAkey", root_key, "-set_serial", "2",
                "-days", "2", "-sha256", "-extfile", extensions, "-out", cls.directory / "valid.pem")
        openssl("x509", "-req", "-in", csr, "-CA", cls.ca, "-CAkey", root_key, "-set_serial", "3",
                "-days", "2", "-sha256", "-out", cls.directory / "cn-only.pem")
        (cls.directory / "index").write_text("")
        (cls.directory / "serial").write_text("10\n")
        config = cls.directory / "ca.cnf"
        config.write_text("[ca]\ndefault_ca=test\n[test]\n"
                          f"database={cls.directory / 'index'}\nserial={cls.directory / 'serial'}\n"
                          f"new_certs_dir={cls.directory}\ncertificate={cls.ca}\nprivate_key={root_key}\n"
                          "default_md=sha256\ndefault_days=2\npolicy=policy\nunique_subject=no\nx509_extensions=leaf\n"
                          "[policy]\ncommonName=supplied\n[leaf]\n" + extensions.read_text())
        for name, start, end in (("expired", "20000101000000Z", "20010101000000Z"),
                                 ("future", (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y%m%d%H%M%SZ"),
                                  (datetime.now(timezone.utc) + timedelta(days=2)).strftime("%Y%m%d%H%M%SZ"))):
            openssl("ca", "-batch", "-notext", "-config", config, "-startdate", start, "-enddate", end,
                    "-in", csr, "-out", cls.directory / (name + ".pem"))
        cls.ca_pem = cls.ca.read_text()
        der = openssl("x509", "-in", cls.directory / "valid.pem", "-outform", "DER")
        cls.fingerprint = hashlib.sha256(der).hexdigest()
        cls.expiry = ssl.cert_time_to_seconds(openssl("x509", "-in", cls.directory / "valid.pem", "-noout", "-enddate")
                                             .decode().strip().split("=", 1)[1])

    @contextmanager
    def server(self, protocol="tls", certificate="valid", transcript=None, hang=False, upgrade=True):
        scripts = {
            "tls": [],
            "smtp_starttls": [(None, b"220 fixture\r\n"), (b"EHLO probe.invalid", b"250-fixture\r\n250 STARTTLS\r\n"),
                              (b"STARTTLS", b"220 begin TLS\r\n")],
            "imap_starttls": [(None, b"* OK fixture\r\n"), (b"cgp1 CAPABILITY", b"* CAPABILITY IMAP4rev1 STARTTLS\r\ncgp1 OK done\r\n"),
                              (b"cgp2 STARTTLS", b"cgp2 OK begin TLS\r\n")],
            "pop3_starttls": [(None, b"+OK fixture\r\n"), (b"CAPA", b"+OK list\r\nSTLS\r\n.\r\n"),
                              (b"STLS", b"+OK begin TLS\r\n")],
        }
        script = scripts[protocol] if transcript is None else transcript
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.directory / (certificate + ".pem"), self.key)
        seen = {"commands": [], "sni": [], "tls_started": False}
        context.set_servername_callback(lambda connection, name, current: seen["sni"].append(name))
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(3)
        stop = threading.Event()
        failures = []
        def serve():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(2)
                    for command, response in script:
                        if command is not None:
                            line = b""
                            while not line.endswith(b"\r\n"):
                                chunk = connection.recv(1)
                                if not chunk:
                                    return
                                line += chunk
                            seen["commands"].append(line[:-2])
                            if line[:-2] != command:
                                raise AssertionError("Unexpected fixture command")
                        connection.sendall(response)
                    if hang:
                        stop.wait(2)
                        return
                    if not upgrade:
                        return
                    seen["tls_started"] = True
                    with context.wrap_socket(connection, server_side=True) as secure:
                        secure.recv(1)
            except (ssl.SSLError, OSError):
                pass  # Expected on failed validation or early protocol refusal.
            except Exception as error:
                failures.append(type(error).__name__)
        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        try:
            yield endpoint(port=listener.getsockname()[1], protocol=protocol, ca_file=str(self.ca)), seen
        finally:
            stop.set()
            listener.close()
            worker.join(4)
            self.assertFalse(worker.is_alive(), "Local TLS server did not stop")
            self.assertEqual(failures, [])

    def test_all_four_protocols_verify_real_certificate_and_send_only_probe_commands(self):
        for protocol in probe.PROTOCOLS:
            with self.subTest(protocol=protocol), self.server(protocol) as (value, seen):
                result = probe.observe(probe.prepare(value))
                self.assertEqual(result["status"], "ok", result)
                self.assertEqual(result["fingerprint_sha256"], self.fingerprint)
                self.assertEqual(result["not_after"], self.expiry)
                self.assertEqual(result["peer_address"], "127.0.0.1")
                self.assertEqual(seen["sni"], ["mail.example.test"])
                self.assertTrue(seen["tls_started"])
                self.assertFalse(any(command.split()[0] in (b"AUTH", b"LOGIN", b"USER", b"PASS", b"MAIL", b"RCPT", b"DATA")
                                     for command in seen["commands"]))

    def test_real_ip_identity_uses_ip_san_and_omits_dns_sni(self):
        with self.server() as (value, seen):
            value["server_name"] = "127.0.0.1"
            self.assertEqual(probe.observe(probe.prepare(value))["status"], "ok")
            self.assertEqual(seen["sni"], [None])

    def test_real_wrong_hostname_untrusted_expired_future_and_cn_only_fail(self):
        cases = [("valid", "wrong.example.test", True, "tls_hostname_mismatch"),
                 ("valid", "mail.example.test", False, "tls_untrusted"),
                 ("expired", "mail.example.test", True, "tls_expired"),
                 ("future", "mail.example.test", True, "tls_not_yet_valid"),
                 ("cn-only", "legacy.example.test", True, "tls_hostname_mismatch")]
        for certificate, name, explicit, code in cases:
            with self.subTest(certificate=certificate, name=name), self.server(certificate=certificate) as (value, seen):
                value["server_name"] = name
                if not explicit:
                    value.pop("ca_file")
                self.assert_error(probe.observe(probe.prepare(value)), code)
                self.assertEqual(len(seen["sni"]), 1)

    def test_real_starttls_unavailable_rejected_truncated_and_hung(self):
        cases = [("smtp_starttls", [(None, b"220 fixture\r\n"), (b"EHLO probe.invalid", b"250 SIZE 10\r\n")], "starttls_unavailable"),
                 ("imap_starttls", [(None, b"* OK fixture\r\n"), (b"cgp1 CAPABILITY", b"* CAPABILITY STARTTLS\r\ncgp1 OK done\r\n"),
                                    (b"cgp2 STARTTLS", b"cgp2 BAD PRIVATE response\r\n")], "starttls_rejected"),
                 ("pop3_starttls", [(None, b"+OK fixture\r\n"), (b"CAPA", b"+OK list\r\n.\r\n")], "starttls_unavailable")]
        for protocol, transcript, code in cases:
            with self.subTest(protocol=protocol), self.server(protocol, transcript=transcript) as (value, _):
                result = probe.observe(probe.prepare(value))
                self.assert_error(result, code)
                self.assertNotIn("PRIVATE", json.dumps(result))
        for protocol in ("tls", "smtp_starttls"):
            with self.server(protocol, transcript=[], hang=True) as (value, _):
                began = time.monotonic()
                self.assert_error(probe.observe(probe.prepare(value), 0.15), "timeout")
                self.assertLess(time.monotonic() - began, 2)
        with self.server("smtp_starttls", transcript=[(None, b"220 unfinished")], upgrade=False) as (value, _):
            self.assert_error(probe.observe(probe.prepare(value)), "protocol_error")

    def test_prepared_ca_snapshot_avoids_reopen_and_no_manager_side_effects(self):
        with self.server() as (value, _):
            ready = probe.prepare(value)
            self.assertNotIn("ca_file", ready)
            self.assertEqual(ready["ca_pem"], self.ca_pem)
            with patch.object(storage, "open_private", side_effect=AssertionError("Reopened configuration")), \
                    patch.object(core, "cli", side_effect=AssertionError("CGP called")), \
                    patch.object(core, "run", side_effect=AssertionError("OpenSSL/Certbot called")), \
                    patch.object(core, "atomic", side_effect=AssertionError("State written")):
                self.assertEqual(probe.observe(ready)["status"], "ok")

    def test_environment_keylog_is_ignored_and_explicit_ca_does_not_load_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "keys.log"
            with patch.dict(os.environ, {"SSLKEYLOGFILE": str(target)}):
                self.assertIsNone(probe._context(None).keylog_filename)
                with self.server() as (value, _), \
                        patch.object(ssl.SSLContext, "load_default_certs", side_effect=AssertionError("Unexpected system trust")):
                    self.assertEqual(probe.observe(probe.prepare(value))["status"], "ok")
            self.assertFalse(target.exists())

    def test_ca_file_permissions_links_content_size_and_mutation_are_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ca.pem"
            path.write_text(self.ca_pem)
            path.chmod(0o644)
            with self.assertRaisesRegex(probe.ProbeError, "^ca_unavailable$"):
                probe.prepare(endpoint(ca_file=str(path)))
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)
            path.chmod(0o600)
            alias = Path(tmp) / "alias.pem"
            alias.symlink_to(path)
            with self.assertRaisesRegex(probe.ProbeError, "^ca_unavailable$"):
                probe.prepare(endpoint(ca_file=str(alias)))
            path.write_bytes(b"\xff")
            with self.assertRaisesRegex(probe.ProbeError, "^ca_unavailable$"):
                probe.prepare(endpoint(ca_file=str(path)))
            path.write_bytes(b"x" * (probe.MAX_CA_BYTES + 1))
            with self.assertRaisesRegex(probe.ProbeError, "^ca_unavailable$"):
                probe.prepare(endpoint(ca_file=str(path)))
            path.write_text(self.ca_pem)
            original = storage.open_private
            @contextmanager
            def changed(filename):
                with original(filename) as stream:
                    class ChangingStream:
                        def fileno(self):
                            return stream.fileno()
                        def read(self, limit):
                            contents = stream.read(limit)
                            info = path.stat()
                            os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 1_000_000))
                            return contents
                    yield ChangingStream()
            with patch.object(storage, "open_private", side_effect=changed), \
                    self.assertRaisesRegex(probe.ProbeError, "^ca_unavailable$"):
                probe.prepare(endpoint(ca_file=str(path)))


if __name__ == "__main__":
    unittest.main()
