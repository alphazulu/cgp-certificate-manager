"""Read-only PowerDNS identity checks with protected files and real HTTP parsing."""
from copy import deepcopy
import http.client
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from cgp_cert_manager import powerdns as p, powerdns_config as config
from tests.powerdns_fixture import TranscriptSocket, serve, server_info, wire, zone_info


class PowerDNSTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = "synthetic-private-api-key"
        self.secret = self.root / "api.json"
        self.secret.write_text(json.dumps({"api_key": self.key}))
        self.secret.chmod(0o600)
        self.entry = {"zone": "example.com", "endpoint": "http://127.0.0.1:8081",
                      "server_id": "localhost", "zone_id": "example.com.",
                      "credentials": str(self.secret), "nameservers": ["ns1.example.com"]}
        self.cfg = {"powerdns": {"zones": [self.entry]}}

    def transcript(self, *responses):
        sockets = [TranscriptSocket(response) for response in responses]
        with patch.object(http.client.socket, "create_connection", side_effect=sockets) as connect:
            report = p.check(self.cfg)
        for sock in sockets:
            self.assertTrue(sock.closed)
            self.assertTrue(sock.stream.closed)
        return report, sockets, connect

    def assert_error(self, report, reason):
        self.assertFalse(report["complete"])
        self.assertFalse(report["issuance_supported"])
        self.assertEqual(report["zones"][0],
                         {"zone": "example.com", "binding": config.validate(self.cfg)[0]["binding"],
                          "status": "error", "reason": reason,
                          "server_version": None, "zone_kind": None})
        rendered = json.dumps(report)
        for private in (self.key, str(self.secret), self.entry["endpoint"], "do-not-follow"):
            self.assertNotIn(private, rendered)

    def test_actual_loopback_gets_only_expected_paths_and_does_not_follow_provider_urls(self):
        original = deepcopy(self.cfg)
        with serve([wire(server_info()), wire(zone_info())]) as (port, requests, faults):
            self.entry["endpoint"] = "http://127.0.0.1:" + str(port)
            with patch.dict(os.environ, {"HTTP_PROXY": "http://unused.invalid:1",
                                         "HTTPS_PROXY": "http://unused.invalid:1", "NO_PROXY": ""}):
                report = p.check(self.cfg)
        self.assertEqual(faults, [])
        self.assertEqual(len(requests), 2)
        self.assertTrue(requests[0].startswith(b"GET /api/v1/servers/localhost HTTP/1.1\r\n"))
        self.assertTrue(requests[1].startswith(
            b"GET /api/v1/servers/localhost/zones/example.com.?rrsets=false HTTP/1.1\r\n"))
        for request in requests:
            self.assertIn(b"X-API-Key: " + self.key.encode() + b"\r\n", request)
            self.assertIn(b"Accept: application/json\r\n", request)
            self.assertIn(b"Accept-Encoding: identity\r\n", request)
            self.assertIn(b"Connection: close\r\n", request)
            self.assertNotIn(b"unused.invalid", request)
        self.assertTrue(report["complete"])
        self.assertEqual(set(report), {"schema", "provider", "mode", "complete", "issuance_supported", "zones"})
        self.assertEqual((report["schema"], report["provider"], report["mode"], report["issuance_supported"]),
                         (1, "powerdns", "read_only", False))
        self.assertEqual(report["zones"][0],
                         {"zone": "example.com", "binding": config.validate(self.cfg)[0]["binding"],
                          "status": "observed", "reason": "api_identity_observed",
                          "server_version": "5.0.8", "zone_kind": "Native"})
        self.entry["endpoint"] = original["powerdns"]["zones"][0]["endpoint"]
        self.assertEqual(self.cfg, original)
        self.assertEqual({item.name for item in self.root.iterdir()}, {"api.json"})

    def test_all_configuration_validates_before_any_private_file_or_network_access(self):
        second = {**self.entry, "zone": "another.example", "endpoint": "http://unsafe.example"}
        self.cfg["powerdns"]["zones"].append(second)
        with patch.object(config, "read_secret") as opened, patch.object(p, "_get") as sent:
            with self.assertRaisesRegex(config.ConfigError, "^Invalid PowerDNS configuration$"):
                p.check(self.cfg)
        opened.assert_not_called()
        sent.assert_not_called()

    def test_private_credential_failure_is_per_zone_and_has_no_network_effect(self):
        self.secret.chmod(0o644)
        with patch.object(p, "_get") as sent:
            report = p.check(self.cfg)
        sent.assert_not_called()
        self.assert_error(report, "credential_unavailable")

    def test_partial_results_continue_after_credential_failure_without_leaking_metadata(self):
        first = {**self.entry, "credentials": str(self.root / "missing")}
        second = {**self.entry, "zone": "other.example", "zone_id": "opaque=2Eid"}
        self.cfg["powerdns"]["zones"] = [first, second]
        with patch.object(p, "_get", side_effect=[server_info(), zone_info(id="opaque=2Eid", name="other.example.")]) as get:
            report = p.check(self.cfg)
        self.assertFalse(report["complete"])
        self.assertEqual([row["status"] for row in report["zones"]], ["error", "observed"])
        self.assertEqual(report["zones"][0]["reason"], "credential_unavailable")
        self.assertEqual(get.call_args_list[1].args[2],
                         "/api/v1/servers/localhost/zones/opaque%3D2Eid?rrsets=false")
        self.assertNotIn(str(self.root), json.dumps(report))

    def test_configured_server_and_zone_ids_are_encoded_as_individual_path_segments(self):
        self.entry.update(server_id="proxy=2Fone", zone_id="example.com.=2Fview")
        with patch.object(p, "_get", side_effect=[server_info(id=self.entry["server_id"]),
                                                  zone_info(id=self.entry["zone_id"])]) as get:
            report = p.check(self.cfg)
        self.assertTrue(report["complete"])
        self.assertEqual([call.args[2] for call in get.call_args_list],
                         ["/api/v1/servers/proxy%3D2Fone",
                          "/api/v1/servers/proxy%3D2Fone/zones/example.com.%3D2Fview?rrsets=false"])

    def test_known_zone_kinds_and_observed_versions_do_not_enable_issuance(self):
        for kind in ("Native", "Master", "Slave", "Producer", "Consumer"):
            with self.subTest(kind=kind), patch.object(p, "_get", side_effect=[
                    server_info(version="0.0.12345.0.master.gabc+distribution~1"),
                    zone_info(name="EXAMPLE.COM.", type="Zone", kind=kind)]):
                report = p.check(self.cfg)
            self.assertTrue(report["complete"])
            self.assertFalse(report["issuance_supported"])
            self.assertEqual(report["zones"][0]["zone_kind"], kind)

    def test_server_identity_mismatch_prevents_zone_request(self):
        for data in (server_info(id="other"), server_info(id=None), server_info(daemon_type="recursor"),
                     server_info(daemon_type=None)):
            with self.subTest(data=data), patch.object(p, "_get", return_value=data) as get:
                report = p.check(self.cfg)
            self.assertEqual(get.call_count, 1)
            self.assert_error(report, "server_identity_mismatch")

    def test_server_shapes_and_versions_fail_closed_without_raw_output(self):
        for data in (None, [], {}, server_info(type="Zone"), server_info(version=None),
                     server_info(version=""), server_info(version="1." + "a" * 128),
                     server_info(version=self.key), server_info(version="5.0.8\nsecret"),
                     server_info(version="5.0.8\u202e"), server_info(version="5")):
            with self.subTest(data=data), patch.object(p, "_get", return_value=data):
                report = p.check(self.cfg)
            self.assert_error(report, "invalid_api_response")

    def test_zone_identity_is_exact_and_ascii_with_required_absolute_dns_name(self):
        for data in (zone_info(id="another"), zone_info(id=None), zone_info(name=None),
                     zone_info(name="foreign.example."), zone_info(name="example.com"),
                     zone_info(name="examp\u212ae.com.")):
            with self.subTest(data=data), patch.object(p, "_get", side_effect=[server_info(), data]):
                report = p.check(self.cfg)
            self.assert_error(report, "zone_identity_mismatch")

    def test_zone_shape_discriminators_and_unknown_kind_fail_closed(self):
        for data in (None, [], {}, zone_info(type="Server"), zone_info(type=None),
                     zone_info(kind=None), zone_info(kind=[]), zone_info(kind="All"), zone_info(kind=self.key)):
            with self.subTest(data=data), patch.object(p, "_get", side_effect=[server_info(), data]):
                report = p.check(self.cfg)
            self.assert_error(report, "invalid_api_response")

    def test_http_errors_and_redirects_are_never_followed_or_retried(self):
        for status in (201, 204, 301, 302, 307, 308, 401, 403, 404, 422, 429, 500, 503):
            with self.subTest(status=status):
                report, sockets, connect = self.transcript(wire(raw=self.key.encode(), status=status,
                    headers=[("Location", "https://unused.invalid/steal"), ("Content-Length", str(len(self.key)))]))
                self.assert_error(report, "api_request_failed")
                self.assertEqual(connect.call_count, 1)
                self.assertEqual(len(sockets[0].sent), 1)

    def test_socket_failure_is_fixed_and_uses_finite_timeout(self):
        with patch.object(http.client.socket, "create_connection", side_effect=OSError(self.key)) as connect:
            report = p.check(self.cfg)
        self.assert_error(report, "api_request_failed")
        self.assertEqual(connect.call_count, 1)
        self.assertEqual(connect.call_args.args[:2], (("127.0.0.1", 8081), 10))

    def test_close_failure_does_not_expose_exception_or_leave_raw_response_open(self):
        sock = TranscriptSocket(wire(server_info()))
        client = http.client.HTTPConnection("127.0.0.1", 8081)
        original_close = client.close
        def failed_close():
            original_close()
            raise OSError(self.key)
        with patch.object(p.http.client, "HTTPConnection", return_value=client), \
                patch.object(client, "_create_connection", return_value=sock), \
                patch.object(client, "close", side_effect=failed_close):
            report = p.check(self.cfg)
        self.assert_error(report, "api_request_failed")
        self.assertTrue(sock.closed)
        self.assertTrue(sock.stream.closed)

    def test_json_is_strict_utf8_finite_and_duplicate_free(self):
        invalid = [b"", b"not-json", b"{} trailing", b'\xff', b'\xef\xbb\xbf{}',
                   b'{"a":1,"a":2}', b'{"a":{"b":1,"b":2}}', b'{"a":NaN}',
                   b'{"a":Infinity}', b'{"a":-Infinity}', b'{"a":1e999}',
                   b'{"a":-1e999}', b'[' * 1100 + b']' * 1100, b'{"a":' + b'9' * 5000 + b'}']
        for body in invalid:
            with self.subTest(body=body[:30]):
                report, _, _ = self.transcript(wire(raw=body))
                self.assert_error(report, "invalid_api_response")

    def test_valid_json_parameters_finite_numbers_and_interim_reply(self):
        body = json.dumps(server_info(extra={"float": 1.25})).encode()
        first = b"HTTP/1.1 100 Continue\r\nX-Info: synthetic\r\n\r\n" + wire(raw=body,
            headers=[("content-type", 'Application/JSON; charset="UTF-8"'), ("content-length", str(len(body)))])
        report, _, _ = self.transcript(first, wire(zone_info()))
        self.assertTrue(report["complete"])

    def test_ambiguous_or_unsupported_http_headers_are_refused(self):
        length = str(len(json.dumps(server_info(), separators=(",", ":")).encode()))
        variants = [[], [("Content-Type", "text/html")], [("Content-Type", "application/json; charset=latin1")],
                    [("Content-Type", "application/json"), ("Content-Type", "application/json")],
                    [("Content-Type", "application/json"), ("Content-Encoding", "gzip")],
                    [("Content-Type", "application/json"), ("Content-Encoding", "identity")],
                    [("Content-Type", "application/json"), ("Content-Length", length), ("Content-Length", length)],
                    [("Content-Type", "application/json"), ("Transfer-Encoding", "chunked"), ("Content-Length", length)],
                    [("Content-Type", "application/json"), ("Transfer-Encoding", "chunked"), ("Transfer-Encoding", "chunked")],
                    [("Content-Type", "application/json"), ("Transfer-Encoding", "gzip")],
                    [("Content-Type", "application/json"), ("Content-Length", "-1")],
                    [("Content-Type", "application/json"), ("Content-Length", "invalid")],
                    [("Content-Type", "application/json"), ("Content-Length", "1, 1")],
                    [("Content-Type", "application/json"), ("Content-Length", "0" * 11)]]
        for headers in variants:
            with self.subTest(headers=headers):
                report, _, _ = self.transcript(wire(server_info(), headers=headers))
                self.assert_error(report, "invalid_api_response")

    def test_body_bound_applies_with_and_without_declared_length(self):
        for headers in ([("Content-Type", "application/json"), ("Content-Length", str(p.MAX_BODY + 1))],
                        [("Content-Type", "application/json")]):
            report, _, _ = self.transcript(wire(raw=b"x" * (p.MAX_BODY + 1), headers=headers))
            self.assert_error(report, "invalid_api_response")
        raw = json.dumps(server_info()).encode()
        raw += b" " * (p.MAX_BODY - len(raw))
        report, _, _ = self.transcript(wire(raw=raw), wire(zone_info()))
        self.assertTrue(report["complete"])

    def test_incomplete_body_is_refused_despite_valid_json_prefix(self):
        raw = json.dumps(server_info()).encode()
        report, _, _ = self.transcript(wire(raw=raw, headers=[("Content-Type", "application/json"),
                                                             ("Content-Length", str(len(raw) + 1))]))
        self.assert_error(report, "invalid_api_response")

    def test_complete_close_delimited_json_response(self):
        raw = json.dumps(server_info()).encode()
        report, _, _ = self.transcript(wire(raw=raw, headers=[("Content-Type", "application/json")]),
                                       wire(zone_info()))
        self.assertTrue(report["complete"])

    def test_chunked_framing_and_trailers_are_refused_before_reading_body(self):
        raw = b"0\r\n" + b"X-Trailer: unbounded\r\n" * 10000 + b"\r\n"
        response = wire(raw=raw, headers=[("Content-Type", "application/json"),
                                         ("Transfer-Encoding", "chunked")])
        report, sockets, _ = self.transcript(response)
        self.assert_error(report, "invalid_api_response")
        self.assertEqual(sockets[0].stream.position_at_close, response.index(b"\r\n\r\n") + 4)

    def test_incomplete_oversized_or_malformed_protocol_replies_close_and_fail(self):
        replies = [b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n",
                   b"HTTP/1.1 200 OK\nContent-Type: application/json\n\n{}",
                   b"HTTP/1.1 nonsense\r\n\r\n",
                   b"HTTP/1.1 200 OK\r\n" + b"X-Pad: " + b"x" * 65536 + b"\r\n\r\n",
                   b"HTTP/1.1 200 OK\r\n" + b"X-Pad: padding\r\n" * 102 + b"\r\n"]
        for response in replies:
            with self.subTest(response=response[:45]):
                report, _, _ = self.transcript(response)
                self.assert_error(report, "api_request_failed")

    def test_tls_context_verifies_hosts_and_ignores_keylog_environment(self):
        keylog = self.root / "must-not-exist"
        self.entry["endpoint"] = "https://api.example.com:8443"
        client = MagicMock()
        client.getresponse.side_effect = OSError(self.key)
        with patch.dict(os.environ, {"SSLKEYLOGFILE": str(keylog)}), \
                patch.object(p.http.client, "HTTPSConnection", return_value=client) as factory:
            report = p.check(self.cfg)
        self.assert_error(report, "api_request_failed")
        self.assertEqual(factory.call_args.args, ("api.example.com", 8443))
        self.assertEqual(factory.call_args.kwargs["timeout"], 10)
        context = factory.call_args.kwargs["context"]
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertIsNone(context.keylog_filename)
        self.assertFalse(keylog.exists())
        client.close.assert_called_once_with()
        self.assertEqual(client.request.call_args.args[:2], ("GET", "/api/v1/servers/localhost"))

    def test_actual_tls_loopback_verifies_trust_and_succeeds_with_valid_local_anchor(self):
        cert = self.root / "cert.pem"
        key = self.root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                        "-keyout", str(key), "-out", str(cert)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        peer_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        peer_context.load_cert_chain(cert, key)
        with serve([], peer_context) as (port, requests, faults):
            self.entry["endpoint"] = "https://127.0.0.1:" + str(port)
            report = p.check(self.cfg)
        self.assert_error(report, "api_request_failed")
        self.assertEqual(requests, [])
        self.assertEqual(faults, [])
        context = p._context(cert.read_text())
        with serve([wire(server_info()), wire(zone_info())], peer_context) as (port, requests, faults):
            self.entry["endpoint"] = "https://127.0.0.1:" + str(port)
            with patch.object(p, "_context", return_value=context):
                report = p.check(self.cfg)
        self.assertTrue(report["complete"])
        self.assertEqual(len(requests), 2)
        self.assertEqual(faults, [])


if __name__ == "__main__":
    unittest.main()
