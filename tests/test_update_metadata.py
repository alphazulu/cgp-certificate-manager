"""Offline signature and update-policy fixtures; no production signing keys."""
import base64
import builtins
from copy import deepcopy
import hashlib
import json
import socket
import subprocess
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from cgp_cert_manager import update_metadata as u


NOW = 1800000000
# Public RFC 8032 test material, deliberately unsuitable as an installed root.
SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
PUBLIC = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def manifest(release="2.3.4", channel="stable", sequence=7):
    return {"schema": 1, "project": u.PROJECT, "channel": channel, "sequence": sequence,
            "version": release, "issued_at": NOW - 60, "expires_at": NOW + 3600,
            "source": {"repository": u.REPOSITORY, "commit": "a" * 40,
                       "tree": "b" * 40, "tag": "v" + release},
            "archive": {"name": u.PROJECT + "-v" + release + ".tar.gz",
                        "size": 1024, "sha256": "c" * 64}}


def ambiguous_base64(encoded):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    index = len(encoded.rstrip("=")) - 1
    return encoded[:index] + alphabet[alphabet.index(encoded[index]) + 1] + encoded[index + 1:]


class UpdateMetadataTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.from_private_bytes(SEED)
        self.key_id = hashlib.sha256(PUBLIC).hexdigest()
        self.trust = {"schema": 1, "project": u.PROJECT, "channel": "stable",
                      "keys": {self.key_id: b64(PUBLIC)}}

    def signature(self, data, key=None, key_id=None, prefix=u.DOMAIN):
        return u.canonical({"schema": 1, "key_id": key_id or self.key_id,
                            "signature": b64((key or self.key).sign(prefix + data))})

    def verify(self, value=None, *, raw=None, signature=None, trust=None, now=NOW,
               current="2.2.0.dev11", previous=None):
        data = u.canonical(value if value is not None else manifest()) if raw is None else raw
        return u.verify(data, self.signature(data) if signature is None else signature,
                        self.trust if trust is None else trust, now=now,
                        current_version=current, previous=previous)

    def assert_code(self, code, operation, *args, **kwargs):
        with self.assertRaises(u.UpdateError) as raised:
            operation(*args, **kwargs)
        self.assertEqual(raised.exception.code, code)
        self.assertEqual(str(raised.exception), code)
        self.assertIn(code, u.CODES)
        self.assertNotIn("PRIVATE", str(raised.exception))

    def test_rfc8032_backend_vector_and_real_signed_manifest(self):
        signature = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
                                  "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        public = Ed25519PublicKey.from_public_bytes(PUBLIC)
        self.assertIsNone(public.verify(signature, b""))
        with self.assertRaises(InvalidSignature):
            public.verify(signature, b"altered")
        data = u.canonical(manifest())
        expected_hash = hashlib.sha256(data).hexdigest()
        result = self.verify()
        self.assertEqual(result, {"manifest": manifest(), "manifest_sha256": expected_hash,
                         "key_id": self.key_id, "floor": {"sequence": 7, "manifest_sha256": expected_hash,
                                                           "version": "2.3.4", "checked_at": NOW}})
        self.assertEqual(json.loads(json.dumps(result)), result)

    def test_canonical_encoding_and_safe_failures(self):
        self.assertEqual(u.canonical({"z": 1, "a": "é"}), b'{"a":"\\u00e9","z":1}\n')
        self.assertEqual(u.canonical({"a": "é", "z": 1}), u.canonical({"z": 1, "a": "é"}))
        cycle = []
        cycle.append(cycle)
        for value in (b"PRIVATE", {"PRIVATE"}, float("nan"), float("inf"), 10**5000, cycle):
            with self.subTest(kind=type(value).__name__):
                self.assert_code("invalid_manifest", u.canonical, value)

    def test_trust_is_json_safe_independent_and_requires_no_crypto_or_io(self):
        raw = json.dumps(self.trust, indent=2).encode("ascii")
        original_import = builtins.__import__

        def guarded_import(name, *args, **kwargs):
            if name.startswith("cryptography"):
                raise AssertionError("Trust parsing must not import crypto")
            return original_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", guarded_import), \
                patch.object(builtins, "open") as opened, patch.object(socket, "socket") as connected, \
                patch.object(subprocess, "run") as spawned:
            trusted = u.parse_trust(raw)
        self.assertEqual(trusted, self.trust)
        trusted["keys"].clear()
        self.assertEqual(len(self.trust["keys"]), 1)
        opened.assert_not_called()
        connected.assert_not_called()
        spawned.assert_not_called()
        self.assertEqual(u.parse_trust(b" " * (u.MAX_TRUST - len(raw)) + raw), self.trust)

    def test_multiple_operator_authorized_keys_do_not_reset_rollback_floor(self):
        alternate = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        public = alternate.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        identifier = hashlib.sha256(public).hexdigest()
        trusted = deepcopy(self.trust)
        trusted["keys"][identifier] = b64(public)
        trusted = u.parse_trust(u.canonical(trusted))
        prior = self.verify()["floor"]
        value = manifest(sequence=8)
        raw = u.canonical(value)
        result = self.verify(value, signature=self.signature(raw, alternate, identifier), trust=trusted, previous=prior)
        self.assertEqual(result["key_id"], identifier)
        value = manifest(sequence=6)
        raw = u.canonical(value)
        self.assert_code("rollback", self.verify, value, signature=self.signature(raw, alternate, identifier),
                         trust=trusted, previous=prior)
        raw = u.canonical(manifest())
        self.assert_code("invalid_signature", self.verify, signature=self.signature(raw, key_id=identifier), trust=trusted)

    def test_trust_shape_scope_and_key_count_are_strict(self):
        invalid = [None, [], {}, {**self.trust, "extra": "PRIVATE"}, {**self.trust, "schema": True},
                   {**self.trust, "schema": 2}, {**self.trust, "channel": "development"},
                   {**self.trust, "channel": []}, {**self.trust, "keys": None}, {**self.trust, "keys": {}},
                   {**self.trust, "keys": {"bad": b64(PUBLIC)}},
                   {**self.trust, "keys": {"a" * 64: b64(PUBLIC)}},
                   {**self.trust, "keys": {self.key_id.upper(): b64(PUBLIC)}}]
        many = {hashlib.sha256(bytes([i]) * 32).hexdigest(): b64(bytes([i]) * 32) for i in range(17)}
        invalid.append({**self.trust, "keys": many})
        for value in invalid:
            with self.subTest(value=value):
                self.assert_code("invalid_trust", u.parse_trust, u.canonical(value))
        trusted = {**self.trust, "keys": dict(list(many.items())[:16])}
        self.assertEqual(u.parse_trust(u.canonical(trusted)), trusted)
        self.assert_code("wrong_project", u.parse_trust, u.canonical({**self.trust, "project": "PRIVATE-other"}))
        self.assert_code("invalid_trust", self.verify, trust={**self.trust, "extra": "PRIVATE"})

    def test_public_key_base64_is_exact_and_canonical(self):
        valid = b64(PUBLIC)
        invalid = [None, 1, "", valid + "\n", "!" + valid[1:], "é" + valid[1:],
                   "A" * len(valid), ambiguous_base64(valid), b64(PUBLIC[:-1]), b64(PUBLIC + b"x")]
        self.assertEqual(base64.b64decode(ambiguous_base64(valid)), PUBLIC)
        for value in invalid:
            with self.subTest(value=value):
                data = {**self.trust, "keys": {self.key_id: value}}
                self.assert_code("invalid_trust", u.parse_trust, u.canonical(data))

    def test_bounded_json_rejects_duplicate_nonfinite_noninteger_and_bad_structure(self):
        invalid = [None, "{}", bytearray(b"{}"), b"", b"\xff", b"\xef\xbb\xbf{}", b"{",
                   b'{"x":1,"x":2}', b'{"x":{"k":1,"k":1}}', b'{}PRIVATE', b'{"x":"\x00"}',
                   b'{"x":' + b"1" * 5000 + b"}", b'{"x":' + b"[" * 9 + b"0" + b"]" * 9 + b"}",
                   b'{"x":[' + b"0," * 256 + b"0]}", b" " * (u.MAX_TRUST + 1)]
        invalid += [b'{"x":' + number + b"}" for number in (b"1.0", b"NaN", b"Infinity", b"-Infinity", b"1e999")]
        for raw in invalid:
            with self.subTest(kind=type(raw).__name__, size=len(raw) if raw is not None else None):
                self.assert_code("invalid_trust", u.parse_trust, raw)
        # Malformed containers within limits still reach exact-schema validation.
        for raw in (b"[]", b"null", b"true", b"42", b'{"unused":[{},[]]}'):
            self.assert_code("invalid_trust", u.parse_trust, raw)

    def test_supported_version_order_and_invalid_spellings(self):
        ordered = ["0.0.0.dev0", "0.0.0.dev2", "0.0.0.dev10", "0.0.0rc0", "0.0.0rc2",
                   "0.0.0rc10", "0.0.0", "0.0.1.dev0", "0.1.0", "1.0.0", "2.0.0", "10.0.0"]
        self.assertEqual(sorted(ordered, key=u.version), ordered)
        self.assertEqual(u.version("2.3.4rc5"), (2, 3, 4, 1, 5))
        self.assertEqual(u.version("2.3.4"), (2, 3, 4, 2, 0))
        for value in (None, True, 123, "", "1.2", "v1.2.3", "01.2.3", "1.02.3", "1.2.03", "1.2.3rc01",
                      "1.2.3.dev01", "1.2.3+local", "1.2.3.post1", "1.2.3a1", "1.2.3rc", "1.2.3.dev",
                      "1.2.3\n", "１.2.3", "9" * 65):
            with self.subTest(value=value):
                self.assert_code("invalid_version", u.version, value)
        self.assert_code("invalid_version", u.version, "1.2.3.dev1", allow_dev=False)
        self.assert_code("invalid_version", self.verify, current="PRIVATE")

    def test_stable_and_candidate_channels_and_current_version_guards(self):
        candidate = {**self.trust, "channel": "candidate"}
        for release, current in (("2.3.4rc0", "2.3.4.dev99"), ("2.3.4rc2", "2.3.4rc1"),
                                 ("2.3.4", "2.3.4rc99")):
            value = manifest(release, "candidate")
            self.assertEqual(self.verify(value, trust=candidate, current=current)["manifest"], value)
        self.assertEqual(self.verify(manifest(), current="2.3.4rc99")["manifest"]["version"], "2.3.4")
        self.assert_code("wrong_channel", self.verify, manifest("2.3.4rc1"))
        self.assert_code("wrong_channel", self.verify, manifest("2.3.4rc1", "candidate"))
        self.assert_code("wrong_channel", self.verify, manifest(), trust=candidate)
        self.assert_code("invalid_version", self.verify, manifest("2.3.4.dev12", "candidate"), trust=candidate)
        for release, current in (("2.3.4", "2.3.4"), ("2.3.3", "2.3.4.dev0"), ("2.3.4rc1", "2.3.4rc2"),
                                 ("2.3.4rc999", "2.3.4")):
            with self.subTest(release=release, current=current):
                self.assert_code("downgrade", self.verify, manifest(release, "candidate"), trust=candidate, current=current)

    def test_manifest_must_be_exact_canonical_bytes_even_with_valid_signature(self):
        value = manifest()
        raw = u.canonical(value)
        variants = [raw[:-1], raw + b"\n", b" " + raw, raw.replace(b"\n", b"\r\n"),
                    json.dumps(value, indent=2).encode(), json.dumps(value, separators=(",", ":")).encode() + b"\n",
                    raw.replace(b'"schema":1', b'"schema":1,"schema":1')]
        for altered in variants:
            with self.subTest(size=len(altered)):
                self.assert_code("invalid_manifest", self.verify, raw=altered)
        self.assert_code("invalid_manifest", self.verify, raw=b"x" * (u.MAX_MANIFEST + 1))
        self.assert_code("invalid_manifest", self.verify, raw=b"[]")

    def test_every_source_and_archive_binding_is_authenticated(self):
        original = u.canonical(manifest())
        signature = self.signature(original)
        variants = []
        for field, new in (("sequence", 8), ("issued_at", NOW - 61), ("expires_at", NOW + 3601), ("channel", "candidate")):
            value = manifest()
            value[field] = new
            variants.append(value)
        for section, field, new in (("source", "commit", "d" * 40), ("source", "tree", "e" * 40),
                                     ("archive", "size", 1025), ("archive", "sha256", "f" * 64)):
            value = manifest()
            value[section][field] = new
            variants.append(value)
        variants.append(manifest("2.3.5"))
        for value in variants:
            with self.subTest(value=value):
                self.assert_code("invalid_signature", self.verify, value, signature=signature)
        self.assert_code("wrong_project", self.verify, {**manifest(), "project": "PRIVATE-other"}, signature=signature)

    def test_manifest_shapes_types_and_fixed_source_identity(self):
        invalid = [None, [], {}, {**manifest(), "extra": "PRIVATE"}, {**manifest(), "schema": True},
                   {**manifest(), "schema": 2}, {**manifest(), "channel": "dev"}]
        for field in ("sequence", "issued_at", "expires_at"):
            invalid += [{**manifest(), field: value} for value in (None, True, "1", -1, 1.0)]
        invalid += [{**manifest(), "sequence": 0}, {**manifest(), "sequence": u.MAX_SEQUENCE + 1},
                    {**manifest(), "issued_at": u.MAX_TIME + 1}, {**manifest(), "expires_at": u.MAX_TIME + 1}]
        for value in invalid:
            with self.subTest(value=value):
                self.assert_code("invalid_manifest", self.verify, raw=u.canonical(value))
        for section in ("source", "archive"):
            for value in (None, [], {}, {**manifest()[section], "extra": "PRIVATE"}):
                self.assert_code("invalid_manifest", self.verify, {**manifest(), section: value})
        for field, new in (("commit", "../PRIVATE"), ("commit", "A" * 40), ("tree", "b" * 64),
                           ("tree", None), ("tag", "v2.3.5")):
            value = manifest()
            value["source"][field] = new
            self.assert_code("invalid_manifest", self.verify, value)
        value = manifest()
        value["source"]["repository"] = "PRIVATE/other"
        self.assert_code("wrong_project", self.verify, value)
        value = manifest()
        value["source"].update(commit="a" * 64, tree="b" * 64)
        self.assertEqual(self.verify(value)["manifest"]["source"], value["source"])
        for field, new in (("name", "../PRIVATE.tar.gz"), ("size", None), ("size", True), ("size", 0),
                           ("size", u.MAX_ARCHIVE + 1), ("sha256", "C" * 64), ("sha256", "f" * 63)):
            value = manifest()
            value["archive"][field] = new
            self.assert_code("invalid_manifest", self.verify, value)
        for size in (1, u.MAX_ARCHIVE):
            value = manifest(sequence=u.MAX_SEQUENCE)
            value["archive"]["size"] = size
            self.assertEqual(self.verify(value)["manifest"]["archive"]["size"], size)

    def test_signature_shape_base64_and_unknown_authority(self):
        raw = u.canonical(manifest())
        valid = json.loads(self.signature(raw))
        invalid = [None, [], {}, {**valid, "schema": True}, {**valid, "schema": 2},
                   {**valid, "algorithm": "PRIVATE"}, {**valid, "key_id": "A" * 64}, {**valid, "key_id": None}]
        invalid += [{**valid, "signature": value} for value in
                    (None, "", valid["signature"] + "\n", "!" + valid["signature"][1:],
                     "é" + valid["signature"][1:], "A" * 88, ambiguous_base64(valid["signature"]),
                     b64(b"a" * 63), b64(b"a" * 65))]
        for value in invalid:
            with self.subTest(value=value):
                self.assert_code("invalid_signature", self.verify, signature=u.canonical(value))
        self.assert_code("invalid_signature", self.verify, signature=b" " * (u.MAX_SIGNATURE + 1))
        self.assert_code("invalid_signature", self.verify, signature=b'{"schema":1,"schema":1}')
        self.assert_code("untrusted_key", self.verify, signature=u.canonical({**valid, "key_id": "f" * 64}))
        pretty = json.dumps(valid, indent=2).encode()
        padded = b" " * (u.MAX_SIGNATURE - len(pretty)) + pretty
        self.assertEqual(self.verify(signature=padded)["key_id"], self.key_id)

    def test_signature_domain_and_message_are_not_interchangeable(self):
        raw = u.canonical(manifest())
        for prefix in (b"", b"PRIVATE-domain\n", u.DOMAIN + u.DOMAIN):
            with self.subTest(prefix=prefix):
                self.assert_code("invalid_signature", self.verify, signature=self.signature(raw, prefix=prefix))
        prehashed = self.key.sign(hashlib.sha256(u.DOMAIN + raw).digest())
        self.assert_code("invalid_signature", self.verify,
                         signature=u.canonical({"schema": 1, "key_id": self.key_id, "signature": b64(prehashed)}))
        forged = self.key.sign(u.DOMAIN + raw)
        forged = forged[:-1] + bytes([forged[-1] ^ 1])
        self.assert_code("invalid_signature", self.verify,
                         signature=u.canonical({"schema": 1, "key_id": self.key_id, "signature": b64(forged)}))

    def test_clock_and_expiration_edges_are_explicit(self):
        for now in (None, True, NOW + 0.5, float("nan"), float("inf"), -1, u.MAX_TIME + 1):
            with self.subTest(now=now):
                self.assert_code("invalid_clock", self.verify, now=now)
        value = manifest()
        value.update(issued_at=NOW, expires_at=NOW + u.MAX_VALIDITY)
        self.assertEqual(self.verify(value)["floor"]["checked_at"], NOW)
        self.assert_code("future_manifest", self.verify, value, now=NOW - 1)
        self.assert_code("expired_manifest", self.verify, value, now=value["expires_at"])
        for expires in (NOW, NOW - 1, NOW + u.MAX_VALIDITY + 1):
            self.assert_code("invalid_manifest", self.verify, {**value, "expires_at": expires})
        value.update(issued_at=0, expires_at=1)
        self.assertEqual(self.verify(value, now=0)["floor"]["checked_at"], 0)
        value.update(issued_at=u.MAX_TIME - 10, expires_at=u.MAX_TIME)
        self.assertEqual(self.verify(value, now=u.MAX_TIME - 1)["floor"]["checked_at"], u.MAX_TIME - 1)
        self.assert_code("expired_manifest", self.verify, value, now=u.MAX_TIME)
        # An unauthenticated expiry claim is a signature failure, not trusted stale metadata.
        expired = {**manifest(), "issued_at": NOW - 100, "expires_at": NOW}
        self.assert_code("invalid_signature", self.verify, expired, signature=self.signature(u.canonical(manifest())))

    def test_floor_validation_is_strict_and_returns_an_independent_value(self):
        floor = self.verify()["floor"]
        copy = u.validate_floor(floor)
        self.assertEqual(copy, floor)
        copy["sequence"] = 12
        self.assertEqual(floor["sequence"], 7)
        invalid = [None, [], {}, {**floor, "extra": "PRIVATE"}, {**floor, "sequence": True},
                   {**floor, "sequence": 0}, {**floor, "sequence": u.MAX_SEQUENCE + 1},
                   {**floor, "manifest_sha256": "F" * 64}, {**floor, "checked_at": False},
                   {**floor, "checked_at": -1}, {**floor, "checked_at": u.MAX_TIME + 1},
                   {**floor, "version": "2.3.4.dev1"}, {**floor, "version": None}]
        for value in invalid:
            with self.subTest(value=value):
                self.assert_code("invalid_floor", u.validate_floor, value)
        self.assert_code("invalid_floor", self.verify, previous={**floor, "checked_at": "PRIVATE"})

    def test_floor_permits_exact_retry_but_refuses_rollback_equivocation_and_clock_regression(self):
        prior = self.verify()["floor"]
        again = self.verify(now=NOW + 1, previous=prior)
        self.assertEqual(again["floor"], {**prior, "checked_at": NOW + 1})
        self.assertEqual(prior["checked_at"], NOW)
        self.assertEqual(self.verify(manifest(sequence=8), previous=prior)["floor"]["sequence"], 8)
        self.assertEqual(self.verify(manifest("2.3.5", sequence=8), previous=prior)["floor"]["version"], "2.3.5")
        self.assert_code("rollback", self.verify, manifest("2.3.5", sequence=6), previous=prior)
        self.assert_code("rollback", self.verify, manifest("2.3.3", sequence=8), previous=prior)
        self.assert_code("rollback", self.verify, {**manifest(), "expires_at": NOW + 3601}, previous=prior)
        self.assert_code("rollback", self.verify, previous={**prior, "version": "2.3.3"})
        self.assert_code("clock_moved_backwards", self.verify, previous={**prior, "checked_at": NOW + 1})

    def test_missing_or_unsupported_crypto_is_safe_and_never_falls_back(self):
        original_import = builtins.__import__
        for failure in (ImportError("PRIVATE missing dependency"), OSError("PRIVATE backend unavailable")):
            def unavailable(name, *args, **kwargs):
                if name.startswith("cryptography"):
                    raise failure
                return original_import(name, *args, **kwargs)

            with patch.object(builtins, "__import__", unavailable):
                self.assert_code("verifier_unavailable", self.verify)
        for failure, code in ((UnsupportedAlgorithm("PRIVATE backend"), "unsupported_crypto"),
                               (ValueError("PRIVATE provider"), "invalid_signature")):
            with patch.object(Ed25519PublicKey, "from_public_bytes", side_effect=failure):
                self.assert_code(code, self.verify)

    def test_success_never_fetches_writes_executes_or_mutates_caller_inputs(self):
        original = deepcopy(self.trust)
        prior = self.verify()["floor"]
        prior_copy = dict(prior)
        with patch.object(builtins, "open") as opened, patch.object(socket, "socket") as connected, \
                patch.object(subprocess, "run") as spawned:
            result = self.verify(previous=prior)
        opened.assert_not_called()
        connected.assert_not_called()
        spawned.assert_not_called()
        self.assertEqual(original, self.trust)
        self.assertEqual(prior, prior_copy)
        self.assertEqual(result["manifest"]["source"]["repository"], u.REPOSITORY)
