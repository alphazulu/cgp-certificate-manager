"""RFC2136 configuration identity and bounded private-secret contracts."""
import base64
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cgp_cert_manager import core, rfc2136_config as config, storage


def zone(**changes):
    return {"zone": "example.com", "server": "192.0.2.53", "credentials": "/etc/cgp-letsencrypt/key.json",
            "key_name": "acme.example.com", "nameservers": ["ns1.example.com", "ns2.example.com"], **changes}


def settings(*entries):
    return {"dns_provider": "rfc2136", "rfc2136": {"zones": list(entries or [zone()])}}


class ConfigurationTests(unittest.TestCase):
    def test_pure_normalization_preserves_source_and_account_order(self):
        cfg = settings(zone(zone="EXAMPLE.COM.", server="2001:0DB8:0:0::0053", port=5353,
                            credentials="/etc//cgp-letsencrypt/./key.json", key_name="ACME.",
                            nameservers=["NS2.Example.Com.", "NS1.Example.Com"]),
                       zone(zone="example.net", nameservers=["ns1.example.net"]))
        cfg["unrelated"] = {"private": "PRIVATE_CONFIG"}
        before = deepcopy(cfg)
        with patch.object(storage, "open_private", side_effect=AssertionError("No credential read")), \
                patch.object(core, "cf", side_effect=AssertionError("No DNS request")):
            result = config.validate(cfg)
        self.assertIsInstance(result, tuple)
        self.assertEqual(cfg, before)
        self.assertEqual([item["zone"] for item in result], ["example.com", "example.net"])
        self.assertEqual({key: value for key, value in result[0].items() if key != "binding"},
                         {"zone": "example.com", "server": "2001:db8::53", "port": 5353,
                          "credentials": "/etc/cgp-letsencrypt/key.json", "key_name": "acme",
                          "algorithm": "hmac-sha256", "nameservers": ["ns2.example.com", "ns1.example.com"]})
        self.assertRegex(result[0]["binding"], r"^[0-9a-f]{64}$")
        result[0]["nameservers"].append("extra.example.com")
        self.assertEqual(cfg, before)

    def test_binding_covers_target_and_key_identity_but_allows_ns_changes(self):
        original = config.validate(settings())[0]["binding"]
        changes = ({"zone": "example.net"}, {"server": "192.0.2.54"}, {"port": 54},
                   {"credentials": "/etc/cgp-letsencrypt/other.json"}, {"key_name": "other.example.com"})
        for change in changes:
            with self.subTest(change=change):
                self.assertNotEqual(config.validate(settings(zone(**change)))[0]["binding"], original)
        for change in ({"nameservers": ["other.example.net"]},
                       {"zone": "EXAMPLE.COM.", "key_name": "ACME.EXAMPLE.COM.",
                        "port": 53, "algorithm": "hmac-sha256", "credentials": "/etc//cgp-letsencrypt/./key.json"}):
            with self.subTest(change=change):
                self.assertEqual(config.validate(settings(zone(**change)))[0]["binding"], original)

    def test_valid_boundaries_unicode_names_and_minimal_section(self):
        cfg = {"rfc2136": {"zones": [zone(zone=f"zone{i}.example", port=1 if i == 0 else 65535,
                                              key_name="key" if i == 0 else "123",
                                              nameservers=[f"ns{n}.example" for n in range(16)])
                                    for i in range(128)]}}
        self.assertEqual(len(config.validate(cfg)), 128)
        normalized = config.validate(settings(zone(zone="пример.рф", nameservers=["ns.пример.рф"])))[0]
        self.assertEqual(normalized["zone"], "xn--e1afmkfd.xn--p1ai")
        self.assertEqual(normalized["nameservers"], ["ns.xn--e1afmkfd.xn--p1ai"])

    def assert_invalid(self, value):
        with self.assertRaisesRegex(config.ConfigError, "^Invalid RFC2136 configuration$"):
            config.validate(value)

    def test_strict_section_and_entry_shape(self):
        cases = [None, [], "PRIVATE", {}, {"rfc2136": None}, {"rfc2136": []},
                 {"rfc2136": {"zones": [], "extra": "PRIVATE"}},
                 {"rfc2136": {"zones": []}}, {"rfc2136": {"zones": ()}},
                 {"rfc2136": {"zones": [zone()] * 129}}]
        cases.extend(settings(entry) for entry in (None, [], "PRIVATE", {**zone(), "extra": "PRIVATE"}))
        cases.extend(settings({key: value for key, value in zone().items() if key != omitted})
                     for omitted in ("zone", "server", "credentials", "key_name", "nameservers"))
        for value in cases:
            with self.subTest(value=value):
                self.assert_invalid(value)

    def test_names_reject_ambiguous_invalid_and_duplicate_canonical_values(self):
        invalid = (None, False, [], "", "PRIVATE NAME.example", "private\n.example", "hidden\u200b.example",
                   "a" * 255, "a" * 64 + ".example", ".", "example.com..", "*.example.com",
                   "-first.example", "last-.example", "under_score.example", "bad..example",
                   "\ufffd.example", "a." + ".".join(["b" * 63] * 4))
        for field in ("zone", "key_name", "nameservers"):
            for value in invalid:
                with self.subTest(field=field, value=value):
                    self.assert_invalid(settings(zone(**{field: [value] if field == "nameservers" else value})))
        for value in ("localhost", "192.0.2.53", "example.123"):
            self.assert_invalid(settings(zone(zone=value)))
            self.assert_invalid(settings(zone(nameservers=[value])))
        self.assert_invalid(settings(zone(), zone(zone="EXAMPLE.COM.")))
        self.assert_invalid(settings(zone(nameservers=["ns.example.com", "NS.EXAMPLE.COM."])))

    def test_endpoint_port_algorithm_and_nameserver_bounds(self):
        for value in (None, False, [], "", "ns.example.com", "192.0.2.053", "[::1]", "fe80::1%eth0", " ::1", "::1\x00"):
            with self.subTest(server=value):
                self.assert_invalid(settings(zone(server=value)))
        for value in (None, False, "53", 0, 65536, 53.0):
            with self.subTest(port=value):
                self.assert_invalid(settings(zone(port=value)))
        for value in (None, False, [], "", "hmac-sha1", "hmac-sha256.", "HMAC-SHA256"):
            with self.subTest(algorithm=value):
                self.assert_invalid(settings(zone(algorithm=value)))
        for value in (None, False, "ns.example.com", (), [], [f"ns{n}.example" for n in range(17)]):
            with self.subTest(nameservers=value):
                self.assert_invalid(settings(zone(nameservers=value)))

    def test_credentials_must_be_absolute_normalized_safe_paths(self):
        for value in (None, False, [], "", "relative/key.json", "/", "//etc/key.json", "/etc/../key.json",
                      "/etc/key\x00.json", "/etc/key\n.json", "/etc/key\u200b.json", "/" + "a" * 4096):
            with self.subTest(value=value):
                self.assert_invalid(settings(zone(credentials=value)))
        self.assertEqual(config.validate(settings(zone(credentials="/etc/private keys/key.json")))[0]["credentials"],
                         "/etc/private keys/key.json")


class SecretTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = self.root / "key.json"
        self.raw = b"x" * 32
        self.secret = base64.b64encode(self.raw).decode("ascii")
        self.write(json.dumps({"secret": self.secret}))

    def write(self, value):
        self.path.write_text(value)
        self.path.chmod(0o600)

    def assert_invalid(self, text=None):
        if text is not None:
            self.write(text)
        with self.assertRaisesRegex(config.ConfigError, "^Invalid RFC2136 credentials$") as raised:
            config.read_secret(self.path)
        self.assertNotIn(str(self.path), str(raised.exception))
        self.assertNotIn(self.secret, str(raised.exception))

    def test_exact_private_secret_and_rotation(self):
        for length in (32, 64, 128):
            value = bytes(range(length))
            self.write(json.dumps({"secret": base64.b64encode(value).decode("ascii")}))
            self.assertEqual(config.read_secret(self.path), value)

    def test_strict_json_keys_duplicate_constants_and_structure(self):
        values = ("null", "[]", "true", '"PRIVATE"', "{}", "{", '\ufeff{}',
                  json.dumps({"secret": self.secret, "extra": "PRIVATE"}),
                  '{"secret":"' + self.secret + '","secret":"' + self.secret + '"}',
                  '{"secret":NaN}', '{"secret":Infinity}', '{"secret":-Infinity}')
        for value in values:
            with self.subTest(value=value):
                self.assert_invalid(value)
        for value in (None, False, 42, [], {}, "PRIVATE", "", self.secret + "\n", self.secret[:-2] + "h=",
                      base64.b64encode(b"x" * 31).decode(), base64.b64encode(b"x" * 129).decode(), "\u00e9"):
            with self.subTest(secret=value):
                self.assert_invalid(json.dumps({"secret": value}))

    def test_file_limit_exact_boundary_and_no_unbounded_read(self):
        valid = json.dumps({"secret": self.secret})
        self.write(valid + " " * (4096 - len(valid)))
        self.assertEqual(config.read_secret(self.path), self.raw)
        self.assert_invalid(valid + " " * (4097 - len(valid)))

        class LimitedStream(io.StringIO):
            def read(self, size=-1):
                if not 0 <= size <= 4097:
                    raise AssertionError("Unbounded secret read")
                return super().read(size)

        stream = LimitedStream(valid)
        with patch.object(storage, "open_private", return_value=stream):
            self.assertEqual(config.read_secret(self.path), self.raw)
        self.assertTrue(stream.closed)

    def test_unsafe_missing_unreadable_and_invalid_utf8_files_are_secret_safe(self):
        self.path.chmod(0o644)
        self.assert_invalid()
        self.path.chmod(0o600)
        target = self.root / "target.json"
        self.path.rename(target)
        self.path.symlink_to(target)
        self.assert_invalid()
        self.path.unlink()
        self.assert_invalid()
        self.path.write_bytes(b'\xff')
        self.path.chmod(0o600)
        self.assert_invalid()
        with patch.object(storage, "open_private", side_effect=OSError("PRIVATE_PATH_AND_SECRET")):
            self.assert_invalid()


if __name__ == "__main__":
    unittest.main()
