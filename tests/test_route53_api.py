"""Independent SigV4 goldens, hostile HTTP/XML and real TLS on loopback."""
from contextlib import contextmanager
from copy import deepcopy
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import traceback
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from cgp_cert_manager import route53_api as api, route53_config as config
from tests.route53_api_fixture import (ROUTE53_NS, STS_NS, TranscriptConnection, TranscriptSocket,
                                       identity, serve, wire, xml)


class SignatureTests(unittest.TestCase):
    def test_official_aws_botocore_signature_vectors(self):
        # Literal expected signatures from the AWS-maintained suite, not this
        # implementation: https://github.com/boto/botocore/tree/develop/tests/unit/auth/aws4_testsuite
        secret = {"access_key_id": "AKIDEXAMPLE", "secret_access_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}
        token = ("AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQWLWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUu"
                 "wthAx7mSEI/qkPpKPi/kMcGdQrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU9HFvlRd8Tx6q6fE8YQ"
                 "cHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz+scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA==")
        cases = [
            ("get-vanilla", "GET", (), b"", None, secret, "host;x-amz-date",
             "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"),
            ("get-vanilla-query-order-key", "GET", (("Param1", "value2"), ("Param1", "Value1")), b"", None,
             secret, "host;x-amz-date", "eedbc4e291e521cf13422ffca22be7d2eb8146eecf653089df300a15b2382bd1"),
            ("post-x-www-form-urlencoded", "POST", (), b"Param1=value1", "application/x-www-form-urlencoded",
             secret, "content-type;host;x-amz-date", "ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a"),
            ("post-sts-token/post-sts-header-before", "POST", (), b"", None, {**secret, "session_token": token},
             "host;x-amz-date;x-amz-security-token", "85d96828115b5dc0cfc3bd16ad9e210dd772bbebba041836c64533a82be05ead"),
        ]
        for label, method, parameters, body, content_type, credentials, names, expected in cases:
            with self.subTest(vector=label):
                headers = api._signed_headers(credentials, "service", "example.amazonaws.com", method, "/",
                                              api._query(parameters), body, "20150830T123600Z", content_type)
                self.assertEqual(headers["Authorization"], "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, "
                                 "SignedHeaders=" + names + ", Signature=" + expected)
        self.assertEqual(headers["X-Amz-Security-Token"], token)

    def test_canonical_query_uses_encoded_pair_order_and_never_plus_for_spaces(self):
        self.assertEqual(api._query((("z", "a b+c/"), ("a", "~"), ("a", "A"), ("é", "v"), ("empty", ""))),
                         "%C3%A9=v&a=A&a=~&empty=&z=a%20b%2Bc%2F")


class APITests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.secret = {"access_key_id": "AKIASYNTHETICEXAMPLE1", "secret_access_key": "a" * 40,
                       "session_token": "synthetic+/=session-token"}
        self.path = self.root / "credentials.json"
        self.path.write_text(json.dumps(self.secret))
        self.path.chmod(0o600)
        self.zone = config.validate({"route53": {"zones": [{"zone": "example.com", "hosted_zone_id": "Z123EXAMPLE",
                                   "account_id": "123456789012", "credentials": str(self.path),
                                   "nameservers": ["ns1.example.net"]}]}})[0]

    @contextmanager
    def transcripts(self, *responses):
        sockets = [TranscriptSocket(response) for response in responses]
        with patch.object(api, "_context", return_value=object()), \
                patch.object(http.client, "HTTPSConnection", side_effect=TranscriptConnection) as factory, \
                patch.object(http.client.socket, "create_connection", side_effect=sockets) as connect:
            try:
                yield sockets, factory, connect
            finally:
                for sock in sockets:
                    self.assertTrue(sock.closed)
                    self.assertTrue(sock.stream.closed)

    def request(self, raw):
        with self.transcripts(raw) as transport:
            result = api._request(self.secret, "route53", "GET", "/2013-04-01/hostedzone/Z123EXAMPLE", "GetHostedZoneResponse")
        return result, transport

    def assert_api_error(self, callable_):
        try:
            callable_()
        except api.APIError as error:
            self.assertEqual(str(error), "Route53 API request failed")
            rendered = "".join(traceback.format_exception(type(error), error, error.__traceback__))
            for value in (*self.secret.values(), str(self.path), "malicious-private-value"):
                self.assertNotIn(value, rendered)
        else:
            self.fail("Expected a fixed APIError")

    def test_client_uses_one_explicit_snapshot_and_only_fixed_signed_targets(self):
        saved = deepcopy(self.zone)
        responses = [wire(identity()), wire(xml("GetHostedZoneResponse")),
                     wire(xml("ListResourceRecordSetsResponse")), wire(xml("ListResourceRecordSetsResponse"))]
        with self.transcripts(*responses) as (sockets, factory, connect), \
                patch.object(config, "read_secret", wraps=config.read_secret) as opened, \
                patch.dict(os.environ, {"AWS_ACCESS_KEY_ID": "ENVKEY", "AWS_SECRET_ACCESS_KEY": "ENVSECRET",
                                         "AWS_SESSION_TOKEN": "ENVTOKEN", "AWS_PROFILE": "unused",
                                         "AWS_SHARED_CREDENTIALS_FILE": str(self.root / "missing"),
                                         "HTTPS_PROXY": "https://unused.invalid:1", "HTTP_PROXY": "http://unused.invalid:1"}):
            client = api.Client(self.zone)
            self.path.write_text(json.dumps({"access_key_id": "AKIANEWEXAMPLE1234567", "secret_access_key": "b" * 40}))
            self.assertEqual(client.get_zone().tag, "{" + ROUTE53_NS + "}GetHostedZoneResponse")
            self.assertEqual(client.records("_acme-challenge.example.com").tag,
                             "{" + ROUTE53_NS + "}ListResourceRecordSetsResponse")
            client.records("_acme-challenge.example.com.")
        opened.assert_called_once_with(str(self.path))
        self.assertEqual(self.zone, saved)
        self.assertEqual([call.args[:2] for call in factory.call_args_list],
                         [("sts.us-east-1.amazonaws.com", 443)] + [("route53.amazonaws.com", 443)] * 3)
        self.assertEqual([call.kwargs["timeout"] for call in factory.call_args_list], [10] * 4)
        self.assertEqual(connect.call_count, 4)
        requests = [b"".join(sock.sent) for sock in sockets]
        self.assertTrue(requests[0].startswith(b"POST / HTTP/1.1\r\n"))
        self.assertTrue(requests[0].endswith(b"Action=GetCallerIdentity&Version=2011-06-15"))
        self.assertIn(b"Host: sts.us-east-1.amazonaws.com\r\n", requests[0])
        self.assertIn(b"/us-east-1/sts/aws4_request", requests[0])
        self.assertIn(b"Content-Type: application/x-www-form-urlencoded\r\n", requests[0])
        self.assertTrue(requests[1].startswith(b"GET /2013-04-01/hostedzone/Z123EXAMPLE HTTP/1.1\r\n"))
        for request in requests[2:]:
            self.assertTrue(request.startswith(b"GET /2013-04-01/hostedzone/Z123EXAMPLE/rrset?maxitems=1&name=_acme-challenge.example.com.&type=TXT HTTP/1.1\r\n"))
        for index, request in enumerate(requests):
            self.assertIn(b"Credential=" + self.secret["access_key_id"].encode() + b"/", request)
            self.assertIn(b"X-Amz-Security-Token: " + self.secret["session_token"].encode() + b"\r\n", request)
            self.assertIn(b";x-amz-security-token, Signature=", request)
            self.assertIn(b"Accept-Encoding: identity\r\n", request)
            self.assertIn(b"Connection: close\r\n", request)
            self.assertNotIn(b"ENV", request)
            self.assertNotIn(b"AKIANEW", request)
            self.assertNotIn(self.secret["secret_access_key"].encode(), request)
            if index:
                self.assertIn(b"Host: route53.amazonaws.com\r\n", request)
                self.assertIn(b"/us-east-1/route53/aws4_request", request)

    def test_changes_preserve_exact_delete_values_and_order_without_upsert(self):
        cases = [((), ('"new"',)), (('"old"', '"other<&>"'), ('"old"', '"new"')),
                 (('"old"',), ())]
        with self.transcripts(wire(identity()), *[wire(xml("ChangeResourceRecordSetsResponse")) for _ in cases]) as (sockets, _, _):
            client = api.Client(self.zone)
            for before, after in cases:
                self.assertEqual(client.change("_acme-challenge.example.com.", 60, before, after).tag,
                                 "{" + ROUTE53_NS + "}ChangeResourceRecordSetsResponse")
        ns = {"r": ROUTE53_NS}
        for sock, (before, after) in zip(sockets[1:], cases):
            request = b"".join(sock.sent)
            head, body = request.split(b"\r\n\r\n", 1)
            self.assertTrue(head.startswith(b"POST /2013-04-01/hostedzone/Z123EXAMPLE/rrset/ HTTP/1.1\r\n"))
            self.assertIn(b"Content-Type: application/xml\r\n", head + b"\r\n")
            self.assertNotIn(b"UPSERT", body)
            tree = ET.fromstring(body)
            self.assertEqual(tree.tag, "{" + ROUTE53_NS + "}ChangeResourceRecordSetsRequest")
            changes = tree.findall("r:ChangeBatch/r:Changes/r:Change", ns)
            expected = [(action, values) for action, values in (("DELETE", before), ("CREATE", after)) if values]
            self.assertEqual(len(changes), len(expected))
            for change, (action, values) in zip(changes, expected):
                self.assertEqual(change.findtext("r:Action", namespaces=ns), action)
                record = change.find("r:ResourceRecordSet", ns)
                self.assertEqual(record.findtext("r:Name", namespaces=ns), "_acme-challenge.example.com.")
                self.assertEqual(record.findtext("r:Type", namespaces=ns), "TXT")
                self.assertEqual(record.findtext("r:TTL", namespaces=ns), "60")
                self.assertEqual(tuple(item.text for item in record.findall("r:ResourceRecords/r:ResourceRecord/r:Value", ns)), values)

    def test_unsafe_credential_has_no_network_fallback(self):
        self.path.chmod(0o644)
        with patch.object(api, "_request") as sent:
            with self.assertRaisesRegex(config.ConfigError, "^Invalid Route53 credentials$"):
                api.Client(self.zone)
        sent.assert_not_called()

    def test_sts_identity_requires_one_direct_plain_exact_account(self):
        cases = [
            "", "<Account>123456789012</Account>",
            "<Wrapper><GetCallerIdentityResult><Account>123456789012</Account></GetCallerIdentityResult></Wrapper>",
            "<GetCallerIdentityResult/><GetCallerIdentityResult/>",
            "<GetCallerIdentityResult/>",
            "<GetCallerIdentityResult><Account>123456789012</Account><Account>123456789012</Account></GetCallerIdentityResult>",
            "<GetCallerIdentityResult><Wrapper><Account>123456789012</Account></Wrapper></GetCallerIdentityResult>",
            "<GetCallerIdentityResult><Account value='private'>123456789012</Account></GetCallerIdentityResult>",
            "<GetCallerIdentityResult><Account>123456789012<Extra/></Account></GetCallerIdentityResult>",
        ]
        cases += ["<GetCallerIdentityResult><Account>" + value + "</Account></GetCallerIdentityResult>"
                  for value in ("", "000000000000", "12345678901", "1234567890123", " 123456789012", "123456789012\n", "１２３４５６７８９０１２")]
        for children in cases:
            with self.subTest(children=children), self.transcripts(wire(xml("GetCallerIdentityResponse", children, STS_NS))) as (_, _, connect):
                self.assert_api_error(lambda: api.Client(self.zone))
                self.assertEqual(connect.call_count, 1)

    def test_non_success_statuses_never_follow_redirects_retry_or_expose_response(self):
        for status in (201, 301, 302, 307, 308, 400, 401, 403, 429, 500, 503):
            with self.subTest(status=status), self.transcripts(wire(b"malicious-private-value", status=status,
                   headers=[("Location", "https://unused.invalid/private"), ("Content-Length", "23")])) as (sockets, _, connect):
                self.assert_api_error(lambda: api._request(self.secret, "route53", "GET", "/", "GetHostedZoneResponse"))
                self.assertEqual(connect.call_count, 1)
                expected_head = wire(b"", status=status, headers=[("Location", "https://unused.invalid/private"),
                                                                  ("Content-Length", "23")])
                self.assertEqual(sockets[0].stream.position_at_close, len(expected_head))

    def test_rejects_ambiguous_unbounded_compressed_and_non_xml_response_framing(self):
        body = xml("GetHostedZoneResponse")
        valid = [("Content-Type", "application/xml"), ("Content-Length", str(len(body)))]
        cases = [valid + [("Content-Length", str(len(body)))],
                 valid + [("Transfer-Encoding", "chunked")], valid + [("Transfer-Encoding", "identity")],
                 valid + [("Content-Encoding", "gzip")], valid + [("Content-Encoding", "identity")],
                 valid + [("Content-Type", "text/xml")], [("Content-Length", str(len(body)))],
                 [("Content-Type", "text/plain")], [("Content-Type", "application/xml; charset=iso-8859-1")]]
        cases += [[("Content-Type", "application/xml"), ("Content-Length", value)]
                  for value in ("-1", "x", "", "99999999999", str(api.MAX_BODY + 1), str(len(body) + 10))]
        for headers in cases:
            with self.subTest(headers=headers):
                self.assert_api_error(lambda: self.request(wire(body, headers=headers)))
        # A close-delimited response is bounded even without Content-Length.
        self.assert_api_error(lambda: self.request(wire(b" " * (api.MAX_BODY + 2), headers=[("Content-Type", "text/xml")])))

    def test_accepts_native_xml_media_types_and_exact_body_boundary(self):
        body = xml("GetHostedZoneResponse")
        for media in ("application/xml", "text/xml; charset=utf-8", 'APPLICATION/XML; CHARSET="UTF-8"'):
            with self.subTest(media=media):
                root, _ = self.request(wire(body, headers=[("Content-Type", media)]))
                self.assertEqual(root.tag, "{" + ROUTE53_NS + "}GetHostedZoneResponse")
        body += b" " * (api.MAX_BODY - len(body))
        self.assertEqual(self.request(wire(body))[0].tag, "{" + ROUTE53_NS + "}GetHostedZoneResponse")

    def test_rejects_invalid_xml_dtd_entities_encoding_and_operation(self):
        cases = [b"\xff", b"<broken>", xml("WrongResponse"), xml("GetHostedZoneResponse", namespace="urn:wrong"),
                 b'<!DOCTYPE root [<!ENTITY private "malicious-private-value">]><root>&private;</root>',
                 b'<!ENTITY private "malicious-private-value"><root/>',
                 xml("GetHostedZoneResponse").replace(b'encoding="UTF-8"', b'encoding="ISO-8859-1"')]
        for body in cases:
            with self.subTest(body=body[:80]):
                self.assert_api_error(lambda: self.request(wire(body)))
        # No declaration and a BOM are both native UTF-8 representations.
        body = ('<GetHostedZoneResponse xmlns="' + ROUTE53_NS + '"/>').encode()
        self.assertEqual(self.request(wire(b"\xef\xbb\xbf" + body))[0].tag, "{" + ROUTE53_NS + "}GetHostedZoneResponse")

    def test_xml_structure_limits_are_enforced_before_an_oversized_tree_is_built(self):
        for count in (api.MAX_XML_NODES - 1, api.MAX_XML_NODES):
            body = xml("GetHostedZoneResponse", "<Item/>" * count)
            if count == api.MAX_XML_NODES:
                self.assert_api_error(lambda: self.request(wire(body)))
            else:
                self.assertEqual(len(self.request(wire(body))[0]), count)
        for depth in (api.MAX_XML_DEPTH - 1, api.MAX_XML_DEPTH):
            body = xml("GetHostedZoneResponse", "<Item>" * depth + "</Item>" * depth)
            if depth == api.MAX_XML_DEPTH:
                self.assert_api_error(lambda: self.request(wire(body)))
            else:
                self.assertEqual(sum(1 for _ in self.request(wire(body))[0].iter()), depth + 1)

    def test_header_budget_covers_interim_responses_and_requires_complete_crlf(self):
        cases = [b"HTTP/1.1 200 OK\n\n", b"HTTP/1.1 200 OK\r\n", b"HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\n",
                 b"HTTP/1.1 200 OK\r\nX-Large: " + b"a" * 65536 + b"\r\n\r\n",
                 b"HTTP/1.1 200 OK\r\n" + (b"X-Large: " + b"a" * 1000 + b"\r\n") * 70 + b"\r\n",
                 b"HTTP/1.1 100 Continue\r\n\r\n" * 3000 + wire(xml("GetHostedZoneResponse"))]
        for response in cases:
            with self.subTest(response=response[:70]), self.transcripts(response) as (sockets, _, _):
                self.assert_api_error(lambda: api._request(self.secret, "route53", "GET", "/", "GetHostedZoneResponse"))
                self.assertLessEqual(sockets[0].stream.position_at_close, 65537)

    def test_socket_tls_and_response_errors_are_sanitized_without_retry(self):
        for error in (OSError("malicious-private-value"), TimeoutError("malicious-private-value"),
                      ssl.SSLError("malicious-private-value")):
            with self.subTest(error=type(error).__name__), patch.object(api, "_context", return_value=object()), \
                    patch.object(http.client, "HTTPSConnection", side_effect=TranscriptConnection), \
                    patch.object(socket, "create_connection", side_effect=error) as connect:
                self.assert_api_error(lambda: api._request(self.secret, "route53", "GET", "/", "GetHostedZoneResponse"))
                connect.assert_called_once()
        with patch.object(api, "_context", side_effect=OSError("malicious-private-value")), \
                patch.object(http.client, "HTTPSConnection") as factory:
            self.assert_api_error(lambda: api._request(self.secret, "route53", "GET", "/", "GetHostedZoneResponse"))
        factory.assert_not_called()
        malformed = b"malicious-private-value\r\n"
        self.assert_api_error(lambda: self.request(malformed))

    def test_close_failure_does_not_override_a_valid_accepted_response(self):
        original = TranscriptConnection.close
        def fail_close(connection):
            original(connection)
            raise OSError("malicious-private-value")
        with patch.object(TranscriptConnection, "close", fail_close):
            self.assertEqual(self.request(wire(xml("GetHostedZoneResponse")))[0].tag,
                             "{" + ROUTE53_NS + "}GetHostedZoneResponse")

    def test_oversized_mutation_is_rejected_before_network(self):
        with self.transcripts(wire(identity())):
            client = api.Client(self.zone)
        with patch.object(http.client, "HTTPSConnection") as factory:
            self.assert_api_error(lambda: client.change("_acme-challenge.example.com", 60, (), ('"' + "a" * api.MAX_BODY + '"',)))
        factory.assert_not_called()

    def test_real_tls_checks_trust_and_hostname_and_ignores_keylog_and_proxies(self):
        key, cert = self.root / "peer.key", self.root / "peer.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                        "-subj", "/CN=synthetic-aws.invalid", "-addext",
                        "subjectAltName=DNS:sts.us-east-1.amazonaws.com,DNS:route53.amazonaws.com",
                        "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        real_connect = socket.create_connection
        keylog = self.root / "must-not-exist.keylog"
        with patch.dict(os.environ, {"SSLKEYLOGFILE": str(keylog), "HTTPS_PROXY": "https://unused.invalid:1",
                                     "HTTP_PROXY": "http://unused.invalid:1", "NO_PROXY": ""}):
            with serve([], context) as (port, requests, faults), patch.object(socket, "create_connection",
                    side_effect=lambda address, *args, **kwargs: real_connect(("127.0.0.1", port), *args, **kwargs)):
                self.assert_api_error(lambda: api.Client(self.zone))
            self.assertEqual(requests, [])
            self.assertEqual(faults, [])
            trusted = api._context(cert.read_text())
            self.assertTrue(trusted.check_hostname)
            self.assertEqual(trusted.verify_mode, ssl.CERT_REQUIRED)
            self.assertEqual(trusted.minimum_version, ssl.TLSVersion.TLSv1_2)
            with serve([wire(identity()), wire(xml("GetHostedZoneResponse")), wire(xml("ChangeResourceRecordSetsResponse"))], context) as (port, requests, faults), \
                    patch.object(socket, "create_connection", side_effect=lambda address, *args, **kwargs:
                                 real_connect(("127.0.0.1", port), *args, **kwargs)) as connect, \
                    patch.object(api, "_context", return_value=trusted):
                client = api.Client(self.zone)
                client.get_zone()
                client.change("_acme-challenge.example.com", 60, (), ('"synthetic-token"',))
            self.assertEqual(faults, [])
            self.assertEqual([call.args[0] for call in connect.call_args_list],
                             [("sts.us-east-1.amazonaws.com", 443), ("route53.amazonaws.com", 443), ("route53.amazonaws.com", 443)])
            self.assertEqual(len(requests), 3)
            self.assertTrue(requests[-1].endswith(b"</ChangeResourceRecordSetsRequest>"))
            # With this trusted certificate, an unrelated hostname must fail.
            with serve([], context) as (port, requests, faults):
                with real_connect(("127.0.0.1", port), timeout=2) as sock:
                    with self.assertRaises(ssl.SSLCertVerificationError):
                        trusted.wrap_socket(sock, server_hostname="wrong.invalid")
            self.assertEqual(requests, [])
            self.assertEqual(faults, [])
        self.assertFalse(keylog.exists())
