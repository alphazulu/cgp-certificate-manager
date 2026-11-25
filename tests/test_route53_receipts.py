"""Route53 receipt binding, uncertain responses and independent TXT ownership."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cgp_cert_manager import core, dnsauth, recovery, route53, route53_config, storage
from route53_fixture import FakeRoute53


VALUE = "A" * 43
FOREIGN = '"operator" "-owned\\344"'
OWNER = route53.OWNER_PREFIX.decode("ascii")
GENERATION = route53.GENERATION_PREFIX.decode("ascii")


class Route53ReceiptBindingTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.state = self.root / "state"
        self.enterContext(patch.object(core, "STATE", self.state))
        self.keys = [self.root / name for name in ("first.json", "second.json")]
        for path in self.keys:
            storage.atomic_json(path, {"access_key_id": "AKIA123456789EXAMPLE1", "secret_access_key": "S" * 40})
        self.cfg = {
            "communigate": {"url": "http://127.0.0.1:106/CLI/"},
            "dns_provider": "route53", "dns_propagation": {"mode": "adaptive"},
            "route53": {"zones": [
                {"zone": "example.com", "hosted_zone_id": "ZEXAMPLECOM", "account_id": "123456789012",
                 "credentials": str(self.keys[0]), "nameservers": ["ns1.example.com", "ns2.example.com"]},
                {"zone": "example.net", "hosted_zone_id": "ZEXAMPLENET", "account_id": "210987654321",
                 "credentials": str(self.keys[1]), "nameservers": ["ns1.example.net"]},
            ]},
        }
        self.client = self.enterContext(patch.object(route53.route53_api, "Client",
                                                    side_effect=AssertionError("No AWS client")))
        self.cf = self.enterContext(patch.object(core, "cf", side_effect=AssertionError("No Cloudflare request")))
        self.tcp = self.enterContext(patch("dns.query.tcp", side_effect=AssertionError("No RFC2136 request")))
        self.zones = core.zones(self.cfg)

    def save(self, nonce="1" * 32, zone="example.com", phase="created"):
        storage.ensure_private_directory(self.state)
        directory = self.state / "dns-challenges"
        storage.ensure_private_directory(directory)
        source = self.zones[zone]
        record = {"schema": 2, "provider": "route53", "identity": recovery.server_identity(self.cfg),
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
        for private in (VALUE, "S" * 40, "PRIVATE_RESPONSE", str(self.keys[0]), "AKIA123456789EXAMPLE1"):
            self.assertNotIn(private, str(raised.exception))

    def test_schema_two_nonce_identity_and_read_only_public_status(self):
        path, record = self.save()
        self.assertRegex(record["zone"], r"^[0-9a-f]{64}$")
        self.assertEqual(record["record"], path.stem)
        self.assertEqual(set(record), {"schema", "provider", "identity", "attempt", "owner", "credentials",
                                      "zone", "name", "value", "record", "phase"})
        before = path.read_bytes()
        rows = dnsauth.status(self.cfg)
        self.assertEqual(rows, [{"id": path.stem, "name": "_acme-challenge.example.com", "phase": "created",
                                 "owned": True, "zone": self.zones["example.com"]["id"]}])
        for private in (str(self.keys[0]), VALUE, "ZEXAMPLECOM", "123456789012"):
            self.assertNotIn(private, json.dumps(rows))
        self.assertEqual(path.read_bytes(), before)
        self.client.assert_not_called()
        self.cf.assert_not_called()
        self.tcp.assert_not_called()

    def test_account_hosted_zone_name_and_credential_path_cannot_redirect_receipt(self):
        path, _ = self.save()
        original = path.read_bytes()
        for changes in ({"account_id": "000000000001"}, {"hosted_zone_id": "ZOTHER"},
                        {"zone": "new.example.com"}, {"credentials": str(self.keys[1])}):
            cfg = copy.deepcopy(self.cfg)
            cfg["route53"]["zones"][0].update(changes)
            with self.subTest(changes=changes), \
                    patch.object(route53_config, "read_secret", side_effect=AssertionError("No credential read")):
                self.refuse(lambda: dnsauth.status(cfg))
                self.refuse(lambda: dnsauth.cleanup_pending(cfg))
            self.assertEqual(path.read_bytes(), original)
        self.client.assert_not_called()

    def test_receipt_requires_exact_zone_credential_name_and_nonce_binding(self):
        path, original = self.save()
        changes = ({"credentials": str(self.keys[1])}, {"zone": self.zones["example.net"]["id"]},
                   {"name": "_acme-challenge.mail.example.net"}, {"record": "2" * 32})
        for change in changes:
            with self.subTest(change=change):
                storage.atomic_json(path, dict(original, **change))
                before = path.read_bytes()
                self.refuse(lambda: dnsauth.status(self.cfg))
                self.refuse(lambda: dnsauth.cleanup_pending(self.cfg))
                self.assertEqual(path.read_bytes(), before)
        self.client.assert_not_called()

    def test_nonce_binding_is_validated_even_for_borrowed_and_complete_receipts(self):
        path, original = self.save()
        for phase in ("borrowed", "complete"):
            with self.subTest(phase=phase):
                storage.atomic_json(path, dict(original, phase=phase, record="2" * 32))
                self.refuse(lambda: dnsauth.status(self.cfg))
                self.refuse(lambda: dnsauth.cleanup_pending(self.cfg))
                self.assertTrue(path.exists())
        self.client.assert_not_called()

    def test_all_bindings_validate_before_any_completed_receipt_is_retired(self):
        first, _ = self.save(phase="complete")
        last, record = self.save(nonce="2" * 32, zone="example.net")
        storage.atomic_json(last, dict(record, credentials=str(self.keys[0])))
        before = {path: path.read_bytes() for path in (first, last)}
        self.refuse(lambda: dnsauth.cleanup_pending(self.cfg))
        self.assertEqual({path: path.read_bytes() for path in (first, last)}, before)
        self.client.assert_not_called()

    def test_legacy_and_other_provider_receipts_are_never_reinterpreted(self):
        path, record = self.save()
        variants = [dict(record, provider=provider) for provider in ("cloudflare", "rfc2136", "powerdns")]
        legacy = dict(record, schema=1)
        del legacy["provider"]
        variants.append(legacy)
        for other in variants:
            with self.subTest(provider=other.get("provider", "legacy")):
                storage.atomic_json(path, other)
                before = path.read_bytes()
                self.refuse(lambda: dnsauth.status(self.cfg))
                self.refuse(lambda: dnsauth.cleanup_pending(self.cfg))
                self.assertEqual(path.read_bytes(), before)
        self.client.assert_not_called()
        self.cf.assert_not_called()
        self.tcp.assert_not_called()

    def test_switching_provider_cannot_reinterpret_route53_receipt(self):
        path, _ = self.save()
        cfg = {**self.cfg, "dns_provider": "cloudflare", "cloudflare_credentials": str(self.keys[0])}
        before = path.read_bytes()
        self.refuse(lambda: dnsauth.status(cfg))
        self.refuse(lambda: dnsauth.cleanup_pending(cfg))
        self.assertEqual(path.read_bytes(), before)
        self.client.assert_not_called()
        self.cf.assert_not_called()

    def test_status_is_independent_of_missing_and_rotating_secret_bytes(self):
        path, _ = self.save()
        before = path.read_bytes()
        self.keys[0].unlink()
        with patch.object(route53_config, "read_secret", side_effect=AssertionError("No credential read")):
            self.assertEqual(dnsauth.status(self.cfg)[0]["phase"], "created")
        storage.atomic_json(self.keys[0], {"access_key_id": "ASIA123456789EXAMPLE1", "secret_access_key": "R" * 40,
                                         "session_token": "ROTATED_SESSION_TOKEN"})
        self.assertEqual(core.zones(self.cfg), self.zones)
        self.assertEqual(dnsauth.status(self.cfg)[0]["phase"], "created")
        self.assertEqual(path.read_bytes(), before)
        self.client.assert_not_called()

    def test_nameserver_metadata_preserves_binding_and_completed_receipt_can_retire(self):
        path, _ = self.save(phase="complete")
        cfg = copy.deepcopy(self.cfg)
        cfg["route53"]["zones"][0]["nameservers"] = ["new.example.com"]
        self.assertEqual(core.zones(cfg)["example.com"]["id"], self.zones["example.com"]["id"])
        dnsauth.cleanup_pending(cfg)
        self.assertFalse(path.exists())
        self.client.assert_not_called()

    def test_invalid_new_zone_binding_refuses_before_credentials_or_state_access(self):
        session = dnsauth.Session(self.cfg)
        for changes in ({"credentials": str(self.keys[1])}, {"id": self.zones["example.net"]["id"]}):
            zones = copy.deepcopy(self.zones)
            zones["example.com"].update(changes)
            with self.subTest(changes=changes), patch.object(storage, "check_private_file") as private, \
                    patch.object(storage, "ensure_private_directory") as directory:
                self.refuse(lambda: session.create("example.com", VALUE, zones))
                private.assert_not_called()
                directory.assert_not_called()
        self.assertFalse(self.state.exists())
        self.client.assert_not_called()


class Route53ReceiptLifecycleTests(unittest.TestCase):
    setUp = Route53ReceiptBindingTests.setUp
    refuse = Route53ReceiptBindingTests.refuse

    def service(self):
        service = FakeRoute53()
        service.values = (FOREIGN,)
        service.ttl = 321
        self.client.side_effect = service
        return service

    def receipts(self):
        return {path: json.loads(path.read_text())
                for path in sorted((self.state / "dns-challenges").glob("*.json"))}

    def only_receipt(self):
        records = self.receipts()
        self.assertEqual(len(records), 1)
        return next(iter(records.items()))

    def create(self, value=VALUE, identifier="example.com"):
        dnsauth.Session(self.cfg).create(identifier, value, self.zones)

    def generations(self, service):
        return {value for value in service.values if value.startswith('"' + GENERATION)}

    def test_durable_intent_precedes_atomic_create_and_cleanup_preserves_raw_foreign_value(self):
        service = self.service()

        def before(_name, _ttl, _old, _new):
            self.assertEqual(self.only_receipt()[1]["phase"], "intent")
        service.before_change = before
        self.create()
        path, receipt = self.only_receipt()
        self.assertEqual((receipt["schema"], receipt["provider"], receipt["phase"]), (2, "route53", "created"))
        self.assertEqual(receipt["record"], path.stem)
        generation = self.generations(service)
        self.assertEqual(len(generation), 1)
        self.assertIn('"' + OWNER + path.stem + '"', service.values)
        self.assertIn('"' + VALUE + '"', service.values)
        self.assertIn(FOREIGN, service.values)
        service.before_change = None
        dnsauth.cleanup_pending(self.cfg)
        self.assertEqual(self.receipts(), {})
        self.assertEqual(len(service.mutations), 2)
        after = self.generations(service)
        self.assertEqual(len(after), 1)
        self.assertNotEqual(generation, after)
        self.assertEqual(set(service.values), {FOREIGN} | after)
        self.assertEqual(service.ttl, 321)

    def test_existing_semantic_txt_value_is_borrowed_without_remote_cleanup(self):
        service = self.service()
        same = '"\\101' + VALUE[1:18] + '" "' + VALUE[18:] + '"'
        service.values += (same,)
        original = service.values
        self.create()
        self.assertEqual(self.only_receipt()[1]["phase"], "borrowed")
        self.client.reset_mock()
        dnsauth.cleanup_pending(self.cfg)
        self.assertEqual(self.receipts(), {})
        self.assertEqual(service.values, original)
        self.assertEqual(service.mutations, [])
        self.client.assert_not_called()

    def test_apex_and_wildcard_keep_independent_pairs_in_one_rrset(self):
        service = self.service()
        self.create()
        self.create(value="B" * 43, identifier="*.example.com")
        receipts = self.receipts()
        self.assertEqual(len(receipts), 2)
        self.assertEqual({record["name"] for record in receipts.values()}, {"_acme-challenge.example.com"})
        self.assertEqual(len({record["record"] for record in receipts.values()}), 2)
        dnsauth.cleanup_pending(self.cfg)
        self.assertEqual(set(service.values), {FOREIGN} | self.generations(service))
        self.assertEqual(len(service.values), 2)
        self.assertEqual(len(service.mutations), 4)
        self.assertEqual(self.receipts(), {})

    def test_applied_create_with_lost_change_id_keeps_intent_recoverable_by_exact_pair(self):
        service = self.service()

        def lost(*_args):
            raise OSError("PRIVATE_RESPONSE")
        service.after_change = lost
        self.refuse(self.create)
        path, receipt = self.only_receipt()
        self.assertEqual(receipt["phase"], "intent")
        self.assertIsNone(receipt["record"])
        self.assertIn('"' + OWNER + path.stem + '"', service.values)
        self.assertEqual(len(service.mutations), 1)
        service.after_change = None
        dnsauth.cleanup_pending(self.cfg)
        self.assertEqual(self.receipts(), {})
        self.assertEqual(len(service.mutations), 2)
        self.assertEqual(set(service.values), {FOREIGN} | self.generations(service))
        self.assertEqual(len(self.generations(service)), 1)

    def test_lost_delete_response_requires_current_absence_without_a_second_change(self):
        service = self.service()
        self.create()
        path, _ = self.only_receipt()

        def lost(*_args):
            raise OSError("PRIVATE_RESPONSE")
        service.after_change = lost
        self.refuse(lambda: dnsauth.cleanup_pending(self.cfg))
        self.assertEqual(json.loads(path.read_text())["phase"], "created")
        remaining = service.values
        self.assertEqual(set(remaining), {FOREIGN} | self.generations(service))
        service.after_change = None
        dnsauth.cleanup_pending(self.cfg)
        self.assertEqual(self.receipts(), {})
        self.assertEqual(service.values, remaining)
        self.assertEqual(len(service.mutations), 2)

    def test_changed_owned_value_marker_generation_or_whole_rrset_retains_receipt(self):
        service = self.service()
        self.create()
        path, _ = self.only_receipt()
        original, receipt = service.values, path.read_bytes()
        changed_sets = [tuple(value for value in original if not remove(value)) for remove in (
            lambda value: value == '"' + VALUE + '"',
            lambda value: value.startswith('"' + OWNER),
            lambda value: value.startswith('"' + GENERATION))]
        changed_sets.append(())
        for values in changed_sets:
            with self.subTest(values=values):
                service.values = values
                self.refuse(lambda: dnsauth.cleanup_pending(self.cfg))
                self.assertEqual(path.read_bytes(), receipt)
                self.assertEqual(service.values, values)
                self.assertEqual(len(service.mutations), 1)

    def test_concurrent_same_value_cas_failure_leaves_unresolved_intent_and_foreign_value(self):
        service = self.service()

        def insert_foreign(_name, _ttl, _before, _after):
            service.values += ('"' + VALUE + '"',)
            service.before_change = None
        service.before_change = insert_foreign
        self.refuse(self.create)
        path, receipt = self.only_receipt()
        self.assertEqual(receipt["phase"], "intent")
        original = path.read_bytes()
        self.refuse(lambda: dnsauth.cleanup_pending(self.cfg))
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(service.values, (FOREIGN, '"' + VALUE + '"'))
        self.assertEqual(service.mutations, [])
        self.refuse(lambda: dnsauth.assert_clear(self.cfg))

    def test_remote_failure_before_apply_does_not_allow_new_issuance_or_retire_intent(self):
        service = self.service()

        def not_delivered(*_args):
            raise OSError("PRIVATE_RESPONSE")
        service.before_change = not_delivered
        self.refuse(self.create)
        path, receipt = self.only_receipt()
        self.assertEqual(receipt["phase"], "intent")
        original = path.read_bytes()
        service.before_change = None
        self.refuse(lambda: dnsauth.cleanup_pending(self.cfg))
        self.refuse(lambda: dnsauth.assert_clear(self.cfg))
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(service.values, (FOREIGN,))
        self.assertEqual(service.mutations, [])

    def test_rotated_secret_at_same_bound_path_can_authenticate_cleanup(self):
        service = self.service()
        self.create()
        path, record = self.only_receipt()
        observed = []

        def authenticated(entry):
            observed.append(route53_config.read_secret(entry["credentials"]))
            return service(entry)
        self.client.side_effect = authenticated
        rotated = {"access_key_id": "ASIA123456789EXAMPLE1", "secret_access_key": "R" * 40,
                   "session_token": "ROTATED_SESSION_TOKEN"}
        storage.atomic_json(self.keys[0], rotated)
        self.assertEqual(dnsauth.status(self.cfg)[0]["zone"], record["zone"])
        dnsauth.cleanup_pending(self.cfg)
        self.assertFalse(path.exists())
        self.assertTrue(observed)
        self.assertTrue(all(item == rotated for item in observed))
        self.assertEqual(len(service.mutations), 2)


if __name__ == "__main__":
    unittest.main()
