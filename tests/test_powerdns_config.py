"""Explicit read-only PowerDNS target identities and protected API keys."""
from copy import deepcopy
import io
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from cgp_cert_manager import powerdns_config as config, storage


def zone(**changes):
    return {"zone": "example.com", "endpoint": "https://dns-api.example.com", "server_id": "localhost",
            "zone_id": "example.com.", "credentials": "/etc/cgp-letsencrypt/powerdns.json",
            "nameservers": ["ns1.example.com", "ns2.example.com"], **changes}


def settings(*entries):
    return {"powerdns": {"zones": list(entries or [zone()])}}


class ConfigurationTests(unittest.TestCase):
    def test_pure_normalization_preserves_input_order_and_unrelated_settings(self):
        cfg = settings(zone(zone="EXAMPLE.COM.", endpoint="HTTPS://DNS-API.EXAMPLE.COM:443/",
                            credentials="/etc//cgp-letsencrypt/./powerdns.json",
                            nameservers=["NS2.EXAMPLE.COM.", "NS1.EXAMPLE.COM."]),
                       zone(zone="example.net", endpoint="https://[2001:0DB8:0::1]:8443/",
                            server_id="OTHER", zone_id="opaque=2Fid"))
        cfg["dns_provider"] = "cloudflare"
        cfg["unrelated"] = {"private": "PRIVATE_CONFIG"}
        before = deepcopy(cfg)
        with patch.object(storage, "open_private", side_effect=AssertionError("No secret reads")), \
                patch.object(socket, "socket", side_effect=AssertionError("No network")), \
                patch.object(socket, "getaddrinfo", side_effect=AssertionError("No DNS lookup")):
            result = config.validate(cfg)
        self.assertIsInstance(result, tuple)
        self.assertEqual(cfg, before)
        self.assertEqual([item["zone"] for item in result], ["example.com", "example.net"])
        self.assertEqual({key: value for key, value in result[0].items() if key != "binding"}, zone(
            nameservers=["ns2.example.com", "ns1.example.com"]))
        self.assertEqual(result[1]["endpoint"], "https://[2001:db8::1]:8443")
        self.assertEqual(result[1]["server_id"], "OTHER")
        self.assertEqual(result[1]["zone_id"], "opaque=2Fid")
        self.assertRegex(result[0]["binding"], r"^[0-9a-f]{64}$")
        result[0]["nameservers"].append("other.example.com")
        self.assertEqual(cfg, before)

    def test_binding_covers_explicit_target_but_allows_nameserver_adjustment(self):
        original = config.validate(settings())[0]["binding"]
        for changes in ({"zone": "example.net"}, {"endpoint": "https://other.example.com"},
                        {"endpoint": "https://dns-api.example.com:8443"}, {"server_id": "other"},
                        {"zone_id": "opaque"}, {"credentials": "/etc/cgp-letsencrypt/other.json"}):
            with self.subTest(changes=changes):
                self.assertNotEqual(config.validate(settings(zone(**changes)))[0]["binding"], original)
        for changes in ({"nameservers": ["other.example.net"]},
                        {"zone": "EXAMPLE.COM.", "endpoint": "https://DNS-API.EXAMPLE.COM:443/",
                         "credentials": "/etc//cgp-letsencrypt/./powerdns.json"}):
            with self.subTest(changes=changes):
                self.assertEqual(config.validate(settings(zone(**changes)))[0]["binding"], original)

    def test_valid_bounds_idna_names_and_opaque_case_sensitive_ids(self):
        cfg = settings(*(zone(zone=f"zone{i}.example", zone_id=f"Zone{i}.",
                              nameservers=[f"ns{j}.example" for j in range(16)]) for i in range(128)))
        self.assertEqual(len(config.validate(cfg)), 128)
        item = config.validate(settings(zone(zone="пример.рф", endpoint="https://пример.рф",
                         server_id="a" * 255, zone_id="A._~-=" + "0" * 249,
                         nameservers=["ns.пример.рф"])))[0]
        self.assertEqual(item["zone"], "xn--e1afmkfd.xn--p1ai")
        self.assertEqual(item["endpoint"], "https://xn--e1afmkfd.xn--p1ai")
        self.assertEqual(item["nameservers"], ["ns.xn--e1afmkfd.xn--p1ai"])
        self.assertEqual(item["zone_id"], "A._~-=" + "0" * 249)
        self.assertEqual(config.validate(settings(zone(endpoint="https://localhost")))[0]["endpoint"],
                         "https://localhost")

    def assert_invalid(self, cfg):
        with self.assertRaisesRegex(config.ConfigError, "^Invalid PowerDNS configuration$"):
            config.validate(cfg)

    def test_strict_section_entry_fields_and_counts(self):
        cases = [None, [], "PRIVATE_CONFIG", {}, {"powerdns": None}, {"powerdns": []},
                 {"powerdns": {"zones": [], "extra": "PRIVATE_CONFIG"}},
                 {"powerdns": {"zones": []}}, {"powerdns": {"zones": ()}},
                 settings(*([zone()] * 129))]
        cases.extend(settings(entry) for entry in (None, [], "PRIVATE_CONFIG", {**zone(), "extra": "PRIVATE_CONFIG"}))
        cases.extend(settings({key: value for key, value in zone().items() if key != omitted}) for omitted in zone())
        for cfg in cases:
            with self.subTest(cfg=cfg):
                self.assert_invalid(cfg)

    def test_duplicate_canonical_zone_or_remote_target_is_refused(self):
        self.assert_invalid(settings(zone(), zone(zone="EXAMPLE.COM.", zone_id="other.")))
        self.assert_invalid(settings(zone(), zone(zone="example.net", endpoint="HTTPS://DNS-API.EXAMPLE.COM:443/")))
        # A distinct remote zone may be checked on the same server; identifiers
        # remain opaque and case-sensitive rather than inferred from DNS names.
        result = config.validate(settings(zone(), zone(zone="example.net", zone_id="Example.com.")))
        self.assertEqual(len(result), 2)

    def test_invalid_or_ambiguous_dns_names_and_nameserver_sets(self):
        invalid = (None, False, [], "", "PRIVATE NAME.example", "private\n.example", "hidden\u200b.example",
                   "a" * 255, "a" * 64 + ".example", ".", "example.com..", "*.example.com", "localhost",
                   "192.0.2.1", "example.123", "-first.example", "last-.example", "under_score.example",
                   "bad..example", "\ufffd.example", "a." + ".".join(["b" * 63] * 4))
        for field in ("zone", "nameservers"):
            for value in invalid:
                with self.subTest(field=field, value=value):
                    self.assert_invalid(settings(zone(**{field: [value] if field == "nameservers" else value})))
        for value in (None, False, "ns.example.com", (), [], [f"ns{n}.example" for n in range(17)],
                      ["ns.example.com", "NS.EXAMPLE.COM."]):
            with self.subTest(nameservers=value):
                self.assert_invalid(settings(zone(nameservers=value)))

    def test_https_and_literal_loopback_origins_have_canonical_ports_and_hosts(self):
        cases = {"https://192.0.2.53/": "https://192.0.2.53", "https://dns.example.com:1": "https://dns.example.com:1",
                 "https://dns.example.com:65535": "https://dns.example.com:65535",
                 "https://DNS.EXAMPLE.COM./": "https://dns.example.com",
                 "https://[::1]:443/": "https://[::1]", "http://127.0.0.1:80/": "http://127.0.0.1",
                 "http://127.0.0.1:8081": "http://127.0.0.1:8081", "http://[0:0:0:0:0:0:0:1]/": "http://[::1]",
                 "http://[::1]:8081/": "http://[::1]:8081", "http://127.0.0.1": "http://127.0.0.1"}
        for value, expected in cases.items():
            with self.subTest(endpoint=value):
                self.assertEqual(config.validate(settings(zone(endpoint=value)))[0]["endpoint"], expected)

    def test_endpoints_reject_unsafe_schemes_authorities_paths_and_nonlocal_http(self):
        invalid = (None, False, [], "", "https://" + "a" * 2048, "https://host.example/\n", " https://host.example",
                   "https://host.example\u200b", "https://host.example\u00a0", "https://host.example\\private",
                   "ftp://host.example", "file:///private", "host.example", "https:///host.example",
                   "https://host.example/api/v1", "https://host.example//", "https://host.example?", "https://host.example#",
                   "https://host.example?api_key=PRIVATE", "https://host.example#PRIVATE", "https://user:PRIVATE@host.example",
                   "https://user@host.example", "https://@host.example", "https://host.example:",
                   "https://host.example:0", "https://host.example:65536", "https://host.example:abc", "https://host.example:+443",
                   "https://host.example:443:80", "https://[::1]extra", "https://[::1]:", "https://[v1.fe]",
                   "https://[invalid]", "https://[192.0.2.53]", "https://[::1", "https://::1", "https://[fe80::1%eth0]",
                   "https://192.0.2.053", "https://127.1", "https://2130706433", "https://bad..example", "https://bad_host.example",
                   "http://localhost", "http://localhost.example", "http://127.0.0.2", "http://192.0.2.53", "http://[::2]",
                   "http://[::ffff:127.0.0.1]", "https://\u2100.example")
        for value in invalid:
            with self.subTest(endpoint=value):
                self.assert_invalid(settings(zone(endpoint=value)))

    def test_path_identifiers_are_explicit_bounded_and_single_components(self):
        invalid = (None, False, [], "", ".", "..", "a" * 256, "a/b", "a\\b", "a%2Fb", "a?b", "a#b", "PRIVATE ID",
                   "a\n", "a\x00", "é", "a:b", "a@b")
        for field in ("server_id", "zone_id"):
            for value in invalid:
                with self.subTest(field=field, value=value):
                    self.assert_invalid(settings(zone(**{field: value})))

    def test_private_credential_paths_are_absolute_and_normalized_without_reads(self):
        for value in (None, False, [], "", "relative/key.json", "/", "//etc/key.json", "/etc/../key.json",
                      "/etc/key\x00.json", "/etc/key\n.json", "/etc/key\u200b.json", "/" + "a" * 4096):
            with self.subTest(credentials=value):
                self.assert_invalid(settings(zone(credentials=value)))
        self.assertEqual(config.validate(settings(zone(credentials="/etc/private keys/key.json")))[0]["credentials"],
                         "/etc/private keys/key.json")


class SecretTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = self.root / "powerdns.json"
        self.key = "PRIVATE_API_KEY"
        self.write(json.dumps({"api_key": self.key}))

    def write(self, text):
        self.path.write_text(text, encoding="utf-8")
        self.path.chmod(0o600)

    def assert_invalid(self, text=None):
        if text is not None:
            self.write(text)
        with self.assertRaisesRegex(config.ConfigError, "^Invalid PowerDNS credentials$") as raised:
            config.read_secret(self.path)
        self.assertNotIn(self.key, str(raised.exception))
        self.assertNotIn(str(self.path), str(raised.exception))

    def test_exact_private_key_and_rotation_at_both_size_boundaries(self):
        for key in ("A", "K" * 1024, "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", self.key):
            with self.subTest(length=len(key)):
                self.write(json.dumps({"api_key": key}))
                self.assertEqual(config.read_secret(self.path), key)
        cfg = settings(zone(credentials=str(self.path)))
        binding = config.validate(cfg)[0]["binding"]
        self.write(json.dumps({"api_key": "ROTATED_PRIVATE_KEY"}))
        self.assertEqual(config.validate(cfg)[0]["binding"], binding)
        self.assertEqual(config.read_secret(self.path), "ROTATED_PRIVATE_KEY")

    def test_secret_json_refuses_duplicates_nonfinite_extras_and_wrong_types(self):
        for text in ("null", "[]", "true", '"PRIVATE"', "{}", "{", "\ufeff{}",
                     json.dumps({"api_key": self.key, "extra": "PRIVATE"}),
                     '{"api_key":"PRIVATE","api_key":"OTHER"}', '{"api_key":NaN}',
                     '{"api_key":Infinity}', '{"api_key":-Infinity}'):
            with self.subTest(text=text):
                self.assert_invalid(text)
        for key in (None, False, 42, [], {}, "", "A" * 1025, " PRIVATE", "PRIVATE ", "PRIVATE KEY",
                    "PRIVATE\r\nX-Evil: value", "PRIVATE\tKEY", "PRIVATE\x00", "PRIVATE\x7f", "PRIVATEé"):
            with self.subTest(key=key):
                self.assert_invalid(json.dumps({"api_key": key}))

    def test_secret_limit_counts_bytes_and_never_reads_unbounded_input(self):
        valid = json.dumps({"api_key": self.key}).encode("utf-8")
        self.path.write_bytes(valid + b" " * (4096 - len(valid)))
        self.assertEqual(config.read_secret(self.path), self.key)
        self.path.write_bytes(valid + b" " * (4097 - len(valid)))
        self.assert_invalid()

        class LimitedStream(io.BytesIO):
            def read(self, size=-1):
                if size != 4097:
                    raise AssertionError("Secret read must be bounded")
                return super().read(size)

        raw = LimitedStream(valid)
        stream = io.TextIOWrapper(raw, encoding="utf-8")
        with patch.object(storage, "open_private", return_value=stream):
            self.assertEqual(config.read_secret(self.path), self.key)
        self.assertTrue(stream.closed)

    def test_unsafe_missing_and_invalid_utf8_secret_files_have_fixed_errors(self):
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
        with patch.object(storage, "open_private", side_effect=OSError("PRIVATE_PATH_AND_API_KEY")):
            self.assert_invalid()


if __name__ == "__main__":
    unittest.main()
