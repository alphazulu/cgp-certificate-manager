"""RFC2136 identities remain bound across receipt inspection and recovery."""
import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import dns.name
import dns.opcode
import dns.rcode
import dns.rdatatype
import dns.tsig

from cgp_cert_manager import core, dnsauth, recovery, storage
from cgp_cert_manager.rfc2136 import GENERATION_PREFIX, OWNER_PREFIX
from rfc2136_fixture import FakePrimary


VALUE = "A" * 43


class RFC2136ReceiptBindingTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.state = self.root / "state"
        self.enterContext(patch.object(core, "STATE", self.state))
        self.keys = [self.root / name for name in ("first.json", "second.json")]
        for path in self.keys:
            storage.atomic_json(path, {"secret": base64.b64encode(b"S" * 32).decode()})
        self.cfg = {
            "communigate": {"url": "http://127.0.0.1:106/CLI/"},
            "dns_provider": "rfc2136",
            "dns_propagation": {"mode": "adaptive"},
            "rfc2136": {"zones": [
                {"zone": "example.com", "server": "192.0.2.53", "credentials": str(self.keys[0]),
                 "key_name": "acme.example.com", "nameservers": ["ns1.example.com", "ns2.example.com"]},
                {"zone": "example.net", "server": "2001:db8::53", "credentials": str(self.keys[1]),
                 "key_name": "acme.example.net", "nameservers": ["ns1.example.net"]},
            ]},
        }
        self.tcp = self.enterContext(patch("dns.query.tcp", side_effect=AssertionError("No provider networking")))
        self.cf = self.enterContext(patch.object(core, "cf", side_effect=AssertionError("No Cloudflare request")))
        self.zones = core.zones(self.cfg)

    def save(self, nonce="1" * 32, zone="example.com", phase="created"):
        storage.ensure_private_directory(self.state)
        directory = self.state / "dns-challenges"
        storage.ensure_private_directory(directory)
        source = self.zones[zone]
        record = {"schema": 2, "provider": "rfc2136", "identity": recovery.server_identity(self.cfg),
                  "attempt": "a" * 32, "owner": "cgp-certificate-manager:" + nonce,
                  "credentials": source["credentials"], "zone": source["id"],
                  "name": "_acme-challenge." + zone, "value": VALUE,
                  "record": None if phase == "intent" else nonce, "phase": phase}
        path = directory / (nonce + ".json")
        storage.atomic_json(path, record)
        return path, record

    def refuse(self, operation):
        with self.assertRaises(dnsauth.DNSAuthError) as raised:
            operation()
        for private in (VALUE, base64.b64encode(b"S" * 32).decode(), "PRIVATE_RESPONSE"):
            self.assertNotIn(private, str(raised.exception))

    def test_schema_two_keeps_exact_public_fields_and_no_remote_record_id_claim(self):
        path, record = self.save()
        self.assertEqual(len(record["zone"]), 64)
        self.assertEqual(record["record"], path.stem)
        self.assertEqual(set(record), {"schema", "provider", "identity", "attempt", "owner",
                                       "credentials", "zone", "name", "value", "record", "phase"})
        before = path.read_bytes()
        rows = dnsauth.status(self.cfg)
        self.assertEqual(rows, [{"id": path.stem, "name": "_acme-challenge.example.com", "phase": "created",
                                 "owned": True, "zone": self.zones["example.com"]["id"]}])
        self.assertNotIn(str(self.keys[0]), json.dumps(rows))
        self.assertNotIn(VALUE, json.dumps(rows))
        self.assertEqual(path.read_bytes(), before)
        self.tcp.assert_not_called()
        self.cf.assert_not_called()

    def test_endpoint_port_key_zone_and_credential_changes_cannot_redirect_receipt(self):
        path, _ = self.save()
        original = path.read_bytes()
        alternatives = [{"server": "192.0.2.54"}, {"port": 5353},
                        {"key_name": "rotated.example.com"}, {"zone": "new.example.com"},
                        {"credentials": str(self.keys[1])}]
        for changes in alternatives:
            cfg = copy.deepcopy(self.cfg)
            cfg["rfc2136"]["zones"][0].update(changes)
            with self.subTest(changes=changes), \
                    patch("cgp_cert_manager.rfc2136_config.read_secret", side_effect=AssertionError("No key read")):
                self.refuse(lambda: dnsauth.status(cfg))
                self.refuse(lambda: dnsauth.cleanup_pending(cfg))
            self.assertEqual(path.read_bytes(), original)
        self.tcp.assert_not_called()
        self.cf.assert_not_called()

    def test_receipt_requires_its_exact_zone_credential_pair(self):
        path, record = self.save()
        for changes in ({"credentials": str(self.keys[1])},
                        {"zone": self.zones["example.net"]["id"]},
                        {"name": "_acme-challenge.mail.example.net"}):
            with self.subTest(changes=changes):
                storage.atomic_json(path, dict(record, **changes))
                before = path.read_bytes()
                self.refuse(lambda: dnsauth.status(self.cfg))
                self.refuse(lambda: dnsauth.cleanup_pending(self.cfg))
                self.assertEqual(path.read_bytes(), before)
        self.tcp.assert_not_called()

    def test_synthetic_record_identity_must_match_its_ownership_nonce(self):
        path, record = self.save()
        for phase in ("created", "borrowed", "complete"):
            with self.subTest(phase=phase):
                storage.atomic_json(path, dict(record, phase=phase, record="2" * 32))
                self.refuse(lambda: dnsauth.status(self.cfg))
                self.refuse(lambda: dnsauth.cleanup_pending(self.cfg))
                self.assertTrue(path.exists())
        self.tcp.assert_not_called()

    def test_all_provider_bindings_validate_before_retiring_any_receipt(self):
        first, _ = self.save(phase="complete")
        last, record = self.save(nonce="2" * 32, zone="example.net")
        storage.atomic_json(last, dict(record, credentials=str(self.keys[0])))
        before = {path: path.read_bytes() for path in (first, last)}
        self.refuse(lambda: dnsauth.cleanup_pending(self.cfg))
        self.assertEqual({path: path.read_bytes() for path in (first, last)}, before)
        self.tcp.assert_not_called()

    def test_legacy_cloudflare_receipts_are_never_reinterpreted_as_rfc2136(self):
        path, record = self.save()
        del record["provider"]
        record["schema"] = 1
        storage.atomic_json(path, record)
        before = path.read_bytes()
        self.refuse(lambda: dnsauth.status(self.cfg))
        self.refuse(lambda: dnsauth.cleanup_pending(self.cfg))
        self.assertEqual(path.read_bytes(), before)
        self.tcp.assert_not_called()
        self.cf.assert_not_called()

    def test_switching_to_cloudflare_cannot_reinterpret_rfc2136_receipt(self):
        path, _ = self.save()
        cfg = {**self.cfg, "dns_provider": "cloudflare", "cloudflare_credentials": str(self.keys[0])}
        before = path.read_bytes()
        self.refuse(lambda: dnsauth.status(cfg))
        self.refuse(lambda: dnsauth.cleanup_pending(cfg))
        self.assertEqual(path.read_bytes(), before)
        self.tcp.assert_not_called()
        self.cf.assert_not_called()

    def test_status_does_not_open_missing_keys_or_bind_rotating_secret_contents(self):
        path, _ = self.save()
        before = path.read_bytes()
        self.keys[0].unlink()
        with patch("cgp_cert_manager.rfc2136_config.read_secret", side_effect=AssertionError("No key read")):
            self.assertEqual(dnsauth.status(self.cfg)[0]["phase"], "created")
        storage.atomic_json(self.keys[0], {"secret": base64.b64encode(b"R" * 64).decode()})
        self.assertEqual(core.zones(self.cfg), self.zones)
        self.assertEqual(dnsauth.status(self.cfg)[0]["phase"], "created")
        self.assertEqual(path.read_bytes(), before)
        self.tcp.assert_not_called()

    def test_nameserver_metadata_change_preserves_cleanup_identity(self):
        path, _ = self.save(phase="complete")
        cfg = copy.deepcopy(self.cfg)
        cfg["rfc2136"]["zones"][0]["nameservers"] = ["new.example.com"]
        self.assertEqual(core.zones(cfg)["example.com"]["id"], self.zones["example.com"]["id"])
        dnsauth.cleanup_pending(cfg)
        self.assertFalse(path.exists())
        self.tcp.assert_not_called()

    def test_invalid_new_zone_binding_refuses_before_key_or_state_access(self):
        session = dnsauth.Session(self.cfg)
        alternatives = [{"credentials": str(self.keys[1])},
                        {"id": self.zones["example.net"]["id"]}]
        for changes in alternatives:
            zones = copy.deepcopy(self.zones)
            zones["example.com"].update(changes)
            with self.subTest(changes=changes), patch.object(storage, "check_private_file") as private_file, \
                    patch.object(storage, "ensure_private_directory") as directory:
                self.refuse(lambda: session.create("example.com", VALUE, zones))
                private_file.assert_not_called()
                directory.assert_not_called()
        self.assertFalse(self.state.exists())
        self.tcp.assert_not_called()


class RFC2136ReceiptLifecycleTests(unittest.TestCase):
    # Share only fixture setup, so the binding tests are not counted twice.
    setUp = RFC2136ReceiptBindingTests.setUp
    refuse = RFC2136ReceiptBindingTests.refuse

    def primary(self):
        server = FakePrimary(key_name="acme.example.com", secret=b"S" * 32)
        server.put("_acme-challenge.example.com", '"foreign" " value"')
        self.tcp.side_effect = server
        return server

    def receipts(self):
        return {path: json.loads(path.read_text())
                for path in sorted((self.state / "dns-challenges").glob("*.json"))}

    def only_receipt(self):
        records = self.receipts()
        self.assertEqual(len(records), 1)
        return next(iter(records.items()))

    def create(self, value=VALUE, identifier="example.com"):
        dnsauth.Session(self.cfg).create(identifier, value, self.zones)

    def test_durable_intent_precedes_atomic_create_and_cleanup_preserves_foreign_wire_value(self):
        server = self.primary()
        owner = "_acme-challenge.example.com"
        foreign = next(iter(server.records[(dns.name.from_text(owner), dns.rdatatype.TXT)]))

        def before(query):
            if query.opcode() == dns.opcode.UPDATE and query.update:
                self.assertEqual(self.only_receipt()[1]["phase"], "intent")
        server.before = before
        self.create()
        path, receipt = self.only_receipt()
        self.assertEqual((receipt["schema"], receipt["provider"], receipt["phase"]), (2, "rfc2136", "created"))
        self.assertEqual(receipt["record"], path.stem)
        before_generation = {value for value in server.txt(owner) if value.startswith(GENERATION_PREFIX)}
        self.assertEqual(len(before_generation), 1)
        self.assertIn(OWNER_PREFIX + path.stem.encode(), server.txt(owner))
        self.assertIn(VALUE.encode(), server.txt(owner))
        server.before = None
        dnsauth.cleanup_pending(self.cfg)
        self.assertEqual(self.receipts(), {})
        self.assertEqual(len(server.mutations), 2)
        after_generation = {value for value in server.txt(owner) if value.startswith(GENERATION_PREFIX)}
        self.assertEqual(len(after_generation), 1)
        self.assertNotEqual(before_generation, after_generation)
        self.assertEqual(server.txt(owner), {b"foreign value"} | after_generation)
        self.assertIn(foreign, server.records[(dns.name.from_text(owner), dns.rdatatype.TXT)])

    def test_borrowed_foreign_value_is_never_mutated_or_given_an_owner_marker(self):
        server = self.primary()
        owner = "_acme-challenge.example.com"
        server.put(owner, '"foreign value"', '"' + VALUE + '"')
        original = copy.deepcopy(server.records)
        self.create()
        self.assertEqual(self.only_receipt()[1]["phase"], "borrowed")
        self.tcp.reset_mock()
        dnsauth.cleanup_pending(self.cfg)
        self.assertEqual(self.receipts(), {})
        self.assertEqual(server.records, original)
        self.assertEqual(server.mutations, [])
        self.tcp.assert_not_called()

    def test_apex_and_wildcard_values_keep_independent_ownership_in_one_rrset(self):
        server = self.primary()
        self.create()
        self.create(value="B" * 43, identifier="*.example.com")
        receipts = self.receipts()
        self.assertEqual(len(receipts), 2)
        self.assertEqual({record["name"] for record in receipts.values()}, {"_acme-challenge.example.com"})
        self.assertEqual(len({record["record"] for record in receipts.values()}), 2)
        dnsauth.cleanup_pending(self.cfg)
        values = server.txt("_acme-challenge.example.com")
        self.assertEqual(len(values), 2)
        self.assertIn(b"foreign value", values)
        self.assertEqual(sum(value.startswith(GENERATION_PREFIX) for value in values), 1)
        self.assertEqual(len(server.mutations), 4)
        self.assertEqual(self.receipts(), {})

    def test_applied_create_followed_by_signed_prerequisite_error_keeps_recoverable_intent(self):
        server = self.primary()

        def refuse_after_apply(query, response):
            if query.opcode() == dns.opcode.UPDATE and query.update:
                # Model a replay winning first, followed by a signed failure
                # for the original identical conditional request.
                response.set_rcode(dns.rcode.NXRRSET)
        server.after = refuse_after_apply
        self.refuse(self.create)
        path, receipt = self.only_receipt()
        self.assertEqual(receipt["phase"], "intent")
        self.assertIsNone(receipt["record"])
        self.assertIn(OWNER_PREFIX + path.stem.encode(), server.txt(receipt["name"]))
        server.after = None
        dnsauth.cleanup_pending(self.cfg)
        self.assertEqual(self.receipts(), {})
        self.assertEqual(len(server.mutations), 2)
        self.assertEqual(sum(value.startswith(GENERATION_PREFIX)
                             for value in server.txt(receipt["name"])), 1)
        self.assertNotIn(VALUE.encode(), server.txt(receipt["name"]))
        self.assertIn(b"foreign value", server.txt(receipt["name"]))

    def test_lost_delete_response_requires_absence_proof_without_second_mutation(self):
        server = self.primary()
        self.create()
        path, receipt = self.only_receipt()

        def lose_response(query, response):
            if query.opcode() == dns.opcode.UPDATE and query.update:
                raise OSError("PRIVATE_RESPONSE")
        server.after = lose_response
        self.refuse(lambda: dnsauth.cleanup_pending(self.cfg))
        self.assertEqual(json.loads(path.read_text())["phase"], "created")
        remaining = server.txt(receipt["name"])
        self.assertNotIn(VALUE.encode(), remaining)
        self.assertNotIn(OWNER_PREFIX + path.stem.encode(), remaining)
        server.after = None
        dnsauth.cleanup_pending(self.cfg)
        self.assertEqual(self.receipts(), {})
        self.assertEqual(server.txt(receipt["name"]), remaining)
        self.assertEqual(len(server.mutations), 2)
        self.assertTrue(any(query.opcode() == dns.opcode.UPDATE and not query.update
                            for query in server.requests))

    def test_changed_owned_value_marker_or_generation_retains_receipt_and_remote_state(self):
        server = self.primary()
        self.create()
        path, receipt = self.only_receipt()
        original = copy.deepcopy(server.records)
        original_receipt = path.read_bytes()
        for remove in (lambda value: value == VALUE.encode(),
                       lambda value: value.startswith(OWNER_PREFIX),
                       lambda value: value.startswith(GENERATION_PREFIX)):
            server.records = copy.deepcopy(original)
            rrset = server.records[(dns.name.from_text(receipt["name"]), dns.rdatatype.TXT)]
            for rd in list(rrset):
                if remove(b"".join(rd.strings)):
                    rrset.discard(rd)
            changed = copy.deepcopy(server.records)
            self.refuse(lambda: dnsauth.cleanup_pending(self.cfg))
            self.assertEqual(path.read_bytes(), original_receipt)
            self.assertEqual(server.records, changed)
            self.assertEqual(len(server.mutations), 1)

    def test_rotated_secret_at_same_bound_path_authenticates_cleanup(self):
        server = self.primary()
        self.create()
        path, record = self.only_receipt()
        original_binding = record["zone"]
        secret = b"R" * 64
        storage.atomic_json(self.keys[0], {"secret": base64.b64encode(secret).decode()})
        server.key = dns.tsig.Key("acme.example.com", secret, algorithm="hmac-sha256")
        self.assertEqual(dnsauth.status(self.cfg)[0]["zone"], original_binding)
        dnsauth.cleanup_pending(self.cfg)
        self.assertFalse(path.exists())
        self.assertEqual(len(server.mutations), 2)
        self.assertNotIn(VALUE.encode(), server.txt(record["name"]))


if __name__ == "__main__":
    unittest.main()
