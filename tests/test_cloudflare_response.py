"""Only explicit bounded provider rejection can clear a DNS create intent."""
import io
import json
from urllib.error import HTTPError
import unittest
from unittest.mock import Mock, patch

from cgp_cert_manager import core


SECRET = "PRIVATE_PROVIDER_RESPONSE"
REJECTION = {"success": False, "result": None,
             "errors": [{"code": 10000, "message": SECRET}]}


class CloudflareResponseTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(core, "token", return_value="PRIVATE_API_TOKEN"))
        self.transport = Mock()
        self.enterContext(patch.object(core, "opener", return_value=self.transport))

    def request(self, payload=None, status=200, raw=None, read_error=None):
        data = json.dumps(payload).encode() if raw is None else raw
        stream = io.BytesIO(data)
        if status != 200:
            self.error = HTTPError("https://api.example.invalid/", status, SECRET, {}, stream)
            self.transport.open.side_effect = self.error
        else:
            self.transport.open.side_effect = None
            self.transport.open.return_value.__enter__ = Mock(return_value=stream)
            self.transport.open.return_value.__exit__ = Mock(return_value=False)
        if read_error is not None:
            stream.read = Mock(side_effect=read_error)
        return core.cf("credentials.ini", "zones/abc/dns_records", method="POST", data={"type": "TXT"})

    def uncertain(self, *args, **kwargs):
        with self.assertRaises(core.Error) as caught:
            self.request(*args, **kwargs)
        self.assertNotIsInstance(caught.exception, core.CloudflareRejected)
        self.assertNotIn(SECRET, str(caught.exception))
        self.assertNotIn("PRIVATE_API_TOKEN", str(caught.exception))

    def test_explicit_rejection_http_statuses_and_successful_http(self):
        for status in (200, 400, 401, 403, 422):
            for include_result in (True, False):
                with self.subTest(status=status, result=include_result):
                    payload = dict(REJECTION)
                    if not include_result:
                        payload.pop("result")
                    payload["errors"] = [dict(payload["errors"][0], documentation_url="https://example.invalid/")]
                    with self.assertRaises(core.CloudflareRejected) as caught:
                        self.request(payload, status)
                    self.assertNotIn(SECRET, str(caught.exception))
                    self.assertNotIn("PRIVATE_API_TOKEN", str(caught.exception))
                    if status != 200:
                        self.assertTrue(self.error.fp.closed)

    def test_unsupported_error_statuses_preserve_http_error_without_reading(self):
        for status in (404, 408, 409, 429, 500, 502, 503, 599):
            with self.subTest(status=status):
                stream = Mock()
                error = HTTPError("https://api.example.invalid/", status, SECRET, {}, stream)
                self.transport.open.side_effect = error
                try:
                    with self.assertRaises(HTTPError) as caught:
                        core.cf("credentials.ini", "zones/abc/dns_records", method="POST")
                    self.assertIs(caught.exception, error)
                    stream.read.assert_not_called()
                    stream.close.assert_not_called()
                finally:
                    error.close()

    def test_ambiguous_or_invalid_rejection_envelopes_are_not_definite(self):
        variants = [
            {}, {"success": None}, {"success": 0}, {"success": 1},
            {"success": "false"}, {"success": "true"},
            dict(REJECTION, result={}), dict(REJECTION, result=[]),
            dict(REJECTION, errors=None), dict(REJECTION, errors={}),
            dict(REJECTION, errors=[]), dict(REJECTION, errors=["bad"]),
            dict(REJECTION, errors=[{}]),
            dict(REJECTION, errors=[{"code": True, "message": SECRET}]),
            dict(REJECTION, errors=[{"code": "10000", "message": SECRET}]),
            dict(REJECTION, errors=[{"code": 1.0, "message": SECRET}]),
            dict(REJECTION, errors=[{"code": 1}]),
            dict(REJECTION, errors=[{"code": 1, "message": False}]),
            dict(REJECTION, errors=[REJECTION["errors"][0], {}]),
        ]
        for status in (200, 403):
            for payload in variants:
                with self.subTest(status=status, payload=payload):
                    self.uncertain(payload, status)
        self.uncertain({"success": True, "result": []}, 400)

    def test_success_is_strictly_true_and_request_shape_is_unchanged(self):
        payload = {"success": True, "result": {"id": "abc"}, "errors": []}
        self.assertEqual(self.request(payload), payload)
        request = self.transport.open.call_args.args[0]
        self.assertEqual(request.method, "POST")
        self.assertEqual(json.loads(request.data), {"type": "TXT"})
        self.assertEqual(request.get_header("Authorization"), "Bearer PRIVATE_API_TOKEN")
        self.assertEqual(self.transport.open.call_args.kwargs, {"timeout": 40})
        self.transport.open.return_value.__enter__.return_value = io.BytesIO(json.dumps(payload).encode())
        self.assertEqual(core.cf("credentials.ini", "zones", params={"page": 2}), payload)
        self.assertTrue(self.transport.open.call_args.args[0].full_url.endswith("zones?page=2"))

    def test_malformed_nonobject_duplicate_nonfinite_or_unicode_json_is_uncertain(self):
        payloads = [b"", b"{", b"null", b"true", b"[]", b'"text"', b"42", b"\xff",
                    b'{"success":false,"success":true,"errors":[{"code":1,"message":"x"}]}',
                    b'{"success":false,"errors":[{"code":1,"code":2,"message":"x"}]}',
                    b'{"success":false,"result":NaN,"errors":[{"code":1,"message":"x"}]}',
                    b'{"success":false,"errors":[{"code":1,"message":"x"}],"extra":Infinity}',
                    b'{"success":false,"errors":[{"code":1,"message":"x"}],"extra":-Infinity}',
                    b'{"success":false,"errors":[{"code":1,"message":"x"}]}TRAILING',
                    b"[" * 2000 + b"0" + b"]" * 2000]
        for status in (200, 403):
            for raw in payloads:
                with self.subTest(status=status, raw=raw[:80]):
                    self.uncertain(status=status, raw=raw)
                    if status != 200:
                        self.assertTrue(self.error.fp.closed)

    def test_bounded_reader_accepts_boundary_and_refuses_excess(self):
        prefix = b'{"success":true,"padding":"'
        raw = prefix + b"x" * (core.MAX_CF_RESPONSE - len(prefix) - 2) + b'"}'
        self.assertTrue(self.request(raw=raw)["success"])
        for status in (200, 403):
            with self.subTest(status=status):
                self.uncertain(status=status, raw=raw + b" ")
        stream = Mock()
        stream.read.return_value = b'{"success":true}'
        self.assertEqual(core._cf_payload(stream), {"success": True})
        stream.read.assert_called_once_with(core.MAX_CF_RESPONSE + 1)

    def test_interrupted_response_read_is_uncertain_and_safe(self):
        for status in (200, 403):
            with self.subTest(status=status):
                self.uncertain(REJECTION, status, read_error=OSError(SECRET))


if __name__ == "__main__":
    unittest.main()
