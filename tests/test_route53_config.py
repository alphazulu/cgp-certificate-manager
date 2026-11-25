"""Explicit commercial Route53 identity and protected credential contracts."""
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from cgp_cert_manager import route53_config as config, storage


def zone(**changes):
    return {"zone": "example.com", "hosted_zone_id": "Z123456789EXAMPLE", "account_id": "123456789012",
            "credentials": "/etc/cgp-letsencrypt/route53.json",
            "nameservers": ["ns1.example.com", "ns2.example.com"], **changes}


def settings(*entries):
    return {"route53": {"zones": list(entries or [zone()])}}


def credential(**changes):
    return {"access_key_id": "AKIA123456789EXAMPLE1", "secret_access_key": "S" * 40, **changes}


class ConfigurationTests(unittest.TestCase):
    def test_pure_normalization_preserves_config_and_target_order(self):
        cfg = settings(zone(zone="EXAMPLE.COM.", credentials="/etc//cgp-letsencrypt/./route53.json",
                            nameservers=["NS2.EXAMPLE.COM.", "NS1.EXAMPLE.COM"]),
                       zone(zone="example.net", hosted_zone_id="Z2"))
        cfg.update(dns_provider="route53", unrelated={"private": "PRIVATE_CONFIG"})
        before = deepcopy(cfg)
        with patch.object(storage, "open_private", side_effect=AssertionError("No credential reads")), \
                patch.object(socket, "socket", side_effect=AssertionError("No network")), \
                patch.object(socket, "getaddrinfo", side_effect=AssertionError("No DNS lookup")):
            result = config.validate(cfg)
        self.assertIsInstance(result, tuple)
        self.assertEqual(cfg, before)
        self.assertEqual([entry["zone"] for entry in result], ["example.com", "example.net"])
        self.assertEqual({key: value for key, value in result[0].items() if key != "binding"},
                         zone(nameservers=["ns2.example.com", "ns1.example.com"]))
        self.assertRegex(result[0]["binding"], r"^[0-9a-f]{64}$")
        result[0]["nameservers"].append("other.example.com")
        self.assertEqual(cfg, before)

    def test_binding_covers_target_but_allows_ns_and_spelling_normalization(self):
        original = config.validate(settings())[0]["binding"]
        for changes in ({"zone": "example.net"}, {"hosted_zone_id": "Z2"},
                        {"account_id": "000000000001"}, {"credentials": "/etc/cgp-letsencrypt/other.json"}):
            with self.subTest(changes=changes):
                self.assertNotEqual(config.validate(settings(zone(**changes)))[0]["binding"], original)
        for changes in ({"nameservers": ["other.example.net"]},
                        {"zone": "EXAMPLE.COM.", "credentials": "/etc//cgp-letsencrypt/./route53.json"}):
            with self.subTest(changes=changes):
                self.assertEqual(config.validate(settings(zone(**changes)))[0]["binding"], original)

    def test_valid_bounds_idna_and_explicit_same_zone_ids_in_distinct_accounts(self):
        cfg = settings(*(zone(zone=f"zone{i}.example", hosted_zone_id=f"Z{i}",
                              nameservers=[f"ns{j}.example" for j in range(16)]) for i in range(128)))
        self.assertEqual(len(config.validate(cfg)), 128)
        item = config.validate(settings(zone(zone="пример.рф", hosted_zone_id="Z" + "A" * 31,
                                             nameservers=["ns.пример.рф"])))[0]
        self.assertEqual(item["zone"], "xn--e1afmkfd.xn--p1ai")
        self.assertEqual(item["nameservers"], ["ns.xn--e1afmkfd.xn--p1ai"])
        self.assertEqual(item["hosted_zone_id"], "Z" + "A" * 31)
        result = config.validate(settings(zone(), zone(zone="example.net", account_id="000000000001")))
        self.assertEqual(len(result), 2)

    def assert_invalid(self, cfg):
        with self.assertRaisesRegex(config.ConfigError, "^Invalid Route53 configuration$"):
            config.validate(cfg)

    def test_strict_section_entry_fields_and_counts(self):
        cases = [None, [], "PRIVATE_CONFIG", {}, {"route53": None}, {"route53": []},
                 {"route53": {"zones": [], "extra": "PRIVATE_CONFIG"}},
                 {"route53": {"zones": []}}, {"route53": {"zones": ()}}, settings(*([zone()] * 129))]
        cases.extend(settings(entry) for entry in (None, [], "PRIVATE_CONFIG"))
        cases.extend(settings({**zone(), extra: "PRIVATE_CONFIG"})
                     for extra in ("extra", "endpoint", "region", "partition", "profile", "role_arn"))
        cases.extend(settings({key: value for key, value in zone().items() if key != omitted}) for omitted in zone())
        for cfg in cases:
            with self.subTest(cfg=cfg):
                self.assert_invalid(cfg)

    def test_duplicate_normalized_zone_or_account_zone_target_is_refused(self):
        self.assert_invalid(settings(zone(), zone(zone="EXAMPLE.COM.", hosted_zone_id="ZOTHER")))
        self.assert_invalid(settings(zone(), zone(zone="example.net")))

    def test_invalid_names_and_nameserver_sets(self):
        invalid = (None, False, [], "", "PRIVATE NAME.example", "private\n.example", "hidden\u200b.example",
                   "a" * 255, "a" * 64 + ".example", ".", "example.com..", "*.example.com", "localhost",
                   "192.0.2.53", "example.123", "-first.example", "last-.example", "under_score.example",
                   "bad..example", "\ufffd.example", "a." + ".".join(["b" * 63] * 4))
        for field in ("zone", "nameservers"):
            for value in invalid:
                with self.subTest(field=field, value=value):
                    self.assert_invalid(settings(zone(**{field: [value] if field == "nameservers" else value})))
        for value in (None, False, "ns.example.com", (), [], [f"ns{n}.example" for n in range(17)],
                      ["ns.example.com", "NS.EXAMPLE.COM."]):
            with self.subTest(nameservers=value):
                self.assert_invalid(settings(zone(nameservers=value)))

    def test_account_and_zone_ids_are_explicit_bounded_ascii(self):
        for account in (None, False, 123456789012, [], "", "12345678901", "1234567890123", "A23456789012",
                        "１２３４５６７８９０１２", " 123456789012", "123456789012\n"):
            with self.subTest(account=account):
                self.assert_invalid(settings(zone(account_id=account)))
        for identifier in (None, False, [], "", "Z", "z123", "123", "Zabc", "Z" + "A" * 32,
                           "/hostedzone/Z123", "Z123/", "Z123?x", "Z123#x", "Z_123", "Z-123", "Z１２３",
                           "Z123\n", " Z123"):
            with self.subTest(identifier=identifier):
                self.assert_invalid(settings(zone(hosted_zone_id=identifier)))

    def test_credential_paths_are_absolute_normalized_and_control_free(self):
        for value in (None, False, [], "", "relative/key.json", "/", "//etc/key.json", "/etc/../key.json",
                      "/etc/key\x00.json", "/etc/key\n.json", "/etc/key\u200b.json", "/" + "a" * 4096):
            with self.subTest(credentials=value):
                self.assert_invalid(settings(zone(credentials=value)))
        self.assertEqual(config.validate(settings(zone(credentials="/etc/private keys/key.json")))[0]["credentials"],
                         "/etc/private keys/key.json")


class SecretTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = self.root / "route53.json"
        self.secret = credential()
        self.write(json.dumps(self.secret))

    def write(self, text):
        self.path.write_text(text, encoding="utf-8")
        self.path.chmod(0o600)

    def assert_invalid(self, text=None):
        if text is not None:
            self.write(text)
        with self.assertRaisesRegex(config.ConfigError, "^Invalid Route53 credentials$") as raised:
            config.read_secret(self.path)
        for private in (str(self.path), self.secret["access_key_id"], self.secret["secret_access_key"]):
            self.assertNotIn(private, str(raised.exception))

    def test_static_session_and_rotated_credentials_preserve_target_binding(self):
        cfg = settings(zone(credentials=str(self.path)))
        binding = config.validate(cfg)[0]["binding"]
        cases = (credential(access_key_id="A" * 16), credential(access_key_id="Z" * 128),
                 credential(secret_access_key="0aZ+/=" + "Q" * 34),
                 credential(session_token="!"), credential(session_token="T" * 16384),
                 credential(access_key_id="ASIA123456789EXAMPLE1", session_token='PRIVATE_TOKEN/+=:~"\\'))
        for data in cases:
            with self.subTest(access_key_length=len(data["access_key_id"]), session="session_token" in data):
                self.write(json.dumps(data))
                self.assertEqual(config.read_secret(self.path), data)
                self.assertEqual(config.validate(cfg)[0]["binding"], binding)

    def test_strict_json_shape_duplicate_and_nonfinite_fields(self):
        cases = ["null", "[]", "true", '"PRIVATE"', "{}", "{", "\ufeff{}",
                 json.dumps({**self.secret, "extra": "PRIVATE"}),
                 '{"access_key_id":"A","access_key_id":"B","secret_access_key":"PRIVATE"}',
                 '{"access_key_id":NaN,"secret_access_key":"PRIVATE"}',
                 '{"access_key_id":Infinity,"secret_access_key":"PRIVATE"}',
                 '{"access_key_id":-Infinity,"secret_access_key":"PRIVATE"}']
        cases.extend(json.dumps({key: value for key, value in self.secret.items() if key != omit})
                     for omit in self.secret)
        cases.extend(json.dumps({**self.secret, key: "PRIVATE"}) for key in ("profile", "role_arn", "expiration"))
        for text in cases:
            with self.subTest(text=text):
                self.assert_invalid(text)

    def test_supported_access_key_secret_and_session_boundaries(self):
        for value in (None, False, 42, [], {}, "", "A" * 15, "A" * 129, "a" * 20, "A/" + "B" * 18,
                      "A" * 19 + "é", "A" * 19 + "\n", "A" * 19 + " "):
            with self.subTest(access_key_id=value):
                self.assert_invalid(json.dumps(credential(access_key_id=value)))
        for value in (None, False, 42, [], {}, "", "S" * 39, "S" * 41, "S" * 39 + "-",
                      "S" * 39 + "é", "S" * 39 + "\n", "S" * 39 + " "):
            with self.subTest(secret_access_key=value):
                self.assert_invalid(json.dumps(credential(secret_access_key=value)))
        for value in (None, False, 42, [], {}, "", "T" * 16385, " PRIVATE", "PRIVATE ", "PRIVATE TOKEN",
                      "PRIVATE\r\nHeader: value", "PRIVATE\tTOKEN", "PRIVATE\x00", "PRIVATE\x7f", "PRIVATEé"):
            with self.subTest(session_token=value):
                self.assert_invalid(json.dumps(credential(session_token=value)))

    def test_file_limit_is_in_bytes_and_read_is_bounded(self):
        valid = json.dumps(self.secret).encode("utf-8")
        self.path.write_bytes(valid + b" " * (32768 - len(valid)))
        self.assertEqual(config.read_secret(self.path), self.secret)
        self.path.write_bytes(valid + b" " * (32769 - len(valid)))
        self.assert_invalid()

        class LimitedStream(io.BytesIO):
            def read(self, size=-1):
                if size != 32769:
                    raise AssertionError("Credential read must be bounded")
                return super().read(size)

        raw = LimitedStream(valid)
        stream = io.TextIOWrapper(raw, encoding="utf-8")
        with patch.object(storage, "open_private", return_value=stream):
            self.assertEqual(config.read_secret(self.path), self.secret)
        self.assertTrue(stream.closed)

    def test_unsafe_missing_unreadable_and_invalid_utf8_files_are_fixed_errors(self):
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

    def test_environment_credentials_are_never_a_fallback(self):
        self.path.unlink()
        with patch.dict(os.environ, {"AWS_ACCESS_KEY_ID": self.secret["access_key_id"],
                                     "AWS_SECRET_ACCESS_KEY": self.secret["secret_access_key"],
                                     "AWS_SESSION_TOKEN": "PRIVATE_SESSION", "AWS_PROFILE": "default",
                                     "AWS_SHARED_CREDENTIALS_FILE": str(self.path)}, clear=False), \
                patch.object(socket, "socket", side_effect=AssertionError("No metadata or STS requests")), \
                patch.object(socket, "getaddrinfo", side_effect=AssertionError("No metadata lookup")):
            self.assert_invalid()


if __name__ == "__main__":
    unittest.main()
