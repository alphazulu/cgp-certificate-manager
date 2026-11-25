"""Synthetic Route53 atomic ownership, bounded evidence and failure contracts."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cgp_cert_manager import route53
from cgp_cert_manager.dnsproviders import ProviderError, ProviderRejected
from route53_fixture import FakeRoute53, element


def find(root, path):
    return root.find("/".join("{" + route53.route53_api.NS + "}" + part for part in path.split("/")))


class Route53Tests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.secret = self.root / "aws.json"
        self.secret.write_text(json.dumps({"access_key_id": "A" * 20, "secret_access_key": "s" * 40}))
        self.secret.chmod(0o600)
        self.cfg = {"dns_provider": "route53", "route53": {"zones": [
            {"zone": "example.com", "hosted_zone_id": "Z12345678", "account_id": "123456789012",
             "credentials": str(self.secret), "nameservers": ["ns1.example.net", "ns2.example.net"]}]}}
        self.service = FakeRoute53()
        self.provider = route53.Route53Provider(self.cfg, client_factory=self.service)
        self.receipt = {"zone": next(iter(self.provider._bindings)), "credentials": str(self.secret),
                        "name": "_acme-challenge.example.com", "value": "A" * 43, "record": None,
                        "owner": "cgp-certificate-manager:" + "a" * 32}

    def create(self, receipt=None):
        receipt = self.receipt if receipt is None else receipt
        remote = self.provider.create_txt(receipt)
        receipt["record"] = self.provider.record_id(remote)
        return remote

    def generations(self):
        return {value for value in self.service.values if value.startswith('"' + route53.GENERATION_PREFIX.decode())}

    def transform(self, operation, mutation):
        def apply(actual, root):
            if actual == operation:
                mutation(root)
        self.service.transform = apply

    def rejected(self, operation=None):
        operation = self.provider.list_records if operation is None else operation
        with self.assertRaisesRegex(ProviderError, "Route53 evidence is unavailable or changed") as raised:
            operation(self.receipt)
        self.assertNotIsInstance(raised.exception, ProviderRejected)

    def test_pure_inventory_credentials_and_explicit_capabilities(self):
        before = copy.deepcopy(self.cfg)
        with patch.object(route53.route53_config, "read_secret") as reader:
            provider = route53.Route53Provider(self.cfg)
            self.assertEqual(provider.credentials(self.cfg), (str(self.secret),))
            self.assertEqual(provider.credentials(self.cfg, absolute=True), (str(self.secret),))
            self.assertEqual(provider.zones(self.cfg), {"example.com": {
                "id": self.receipt["zone"], "credentials": str(self.secret),
                "ns": ["ns1.example.net", "ns2.example.net"], "provider": "route53"}})
            for capability in ("fixed_native", "fixed_hooks", "other", None, []):
                with self.subTest(capability=capability), self.assertRaises(ProviderError):
                    provider.require(capability)
            reader.assert_not_called()
        provider.validate_credentials(self.cfg)
        self.assertEqual(self.cfg, before)
        self.assertEqual(self.service.requests, [])

    def test_receipt_validation_precedes_client_and_credential_access(self):
        cases = [{"zone": []}, {"zone": "f" * 64}, {"credentials": "/other"},
                 {"owner": "private"}, {"owner": None}, {"name": "_acme-challenge.example.net"},
                 {"name": "_acme-challenge.EXAMPLE.com"}, {"name": "_acme-challenge.example.com."},
                 {"name": "example.com"}, {"name": "www.example.com"}, {"name": 3},
                 {"value": None}, {"value": "bad"}, {"record": "b" * 32},
                 {"name": "_acme-challenge.a!b.example.com"}]
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(ProviderError):
                self.provider.list_records({**self.receipt, **changes})
        self.assertEqual(self.service.clients, [])
        self.assertFalse(self.provider.valid_zone_id([]))
        self.assertFalse(self.provider.valid_zone_id("unknown"))
        self.assertTrue(self.provider.valid_zone_id(self.receipt["zone"]))
        for value in (None, {}, [], {"id": 3}, {"id": "A" * 32}):
            with self.subTest(value=value), self.assertRaises(ProviderError):
                self.provider.record_id(value)
        remote = {"id": "a" * 32, "name": self.receipt["name"], "value": self.receipt["value"], "owner": None}
        self.assertEqual(self.provider.record_id(remote), "a" * 32)
        self.assertTrue(self.provider.matches(remote, self.receipt))
        self.assertFalse(self.provider.matches(remote, self.receipt, owned=True))
        self.assertFalse(self.provider.matches({**remote, "name": "other"}, self.receipt))
        self.assertFalse(self.provider.matches({**remote, "value": "other"}, self.receipt))

    def test_default_factory_and_single_authenticated_session_per_mutation(self):
        with patch.object(route53.route53_api, "Client", side_effect=self.service) as factory:
            provider = route53.Route53Provider(self.cfg)
            self.receipt["record"] = provider.record_id(provider.create_txt(self.receipt))
            self.assertEqual(factory.call_count, 1)
            self.assertEqual([row[0] for row in self.service.requests], ["zone", "records", "change", "records"])
            self.assertEqual({row[1] for row in self.service.requests}, {1})
            self.service.requests.clear()
            provider.delete_record(self.receipt)
            self.assertEqual(factory.call_count, 2)
            self.assertEqual({row[1] for row in self.service.requests}, {2})

    def test_full_lifecycle_and_old_create_replay_leave_generation_fence(self):
        self.assertEqual(self.provider.list_records(self.receipt), [])
        remote = self.create()
        self.assertTrue(self.provider.matches(remote, self.receipt, owned=True))
        self.assertEqual(len(self.service.values), 3)
        first = self.generations()
        create = self.service.mutations[0]
        self.provider.delete_record(self.receipt)
        self.assertNotEqual(self.generations(), first)
        self.assertEqual(set(self.service.values), self.generations())
        self.assertIsNone(self.provider.get_record(self.receipt))
        before = copy.deepcopy(self.service.mutations)
        self.provider.confirm_absent(self.receipt)
        self.assertEqual(self.service.mutations, before)
        with self.assertRaises(RuntimeError):
            self.service.apply(**create)
        self.assertEqual(set(self.service.values), self.generations())

    def test_foreign_raw_values_chunks_octal_quotes_backslashes_and_ttl_survive(self):
        old = ('"foreign"   " chunks"', '"\\344\\000\\040"', '"quote\\\" and slash\\\\"', '""')
        self.service.values, self.service.ttl = old, 900
        self.create()
        self.assertEqual(self.service.mutations[0]["before"], old)
        self.assertEqual(self.service.ttl, 900)
        self.provider.delete_record(self.receipt)
        self.assertTrue(set(old).issubset(self.service.values))
        self.assertEqual(len(self.service.values), len(old) + 1)
        self.assertEqual(self.service.ttl, 900)

    def test_multiple_receipts_share_one_generation_and_remove_only_their_pair(self):
        self.create()
        second = {**self.receipt, "owner": "cgp-certificate-manager:" + "b" * 32,
                  "value": "B" * 43, "record": None}
        self.create(second)
        self.assertEqual(len(self.generations()), 1)
        self.assertEqual(len(self.service.values), 5)
        self.provider.delete_record(self.receipt)
        self.assertTrue(self.provider.matches(self.provider.get_record(second), second, owned=True))
        self.provider.delete_record(second)
        self.assertEqual(len(self.service.values), 1)

    def test_semantic_existing_values_are_borrowed_without_claiming_or_deleting(self):
        for value in ('"' + "A" * 43 + '"', '"AAA" "' + "A" * 40 + '"',
                      '"\\101' + "A" * 42 + '"'):
            self.service.values = (value,)
            with self.subTest(value=value):
                remote = self.provider.list_records(self.receipt)[0]
                self.assertIsNone(remote["owner"])
                self.assertEqual(remote, self.provider.get_record(self.receipt))
                with self.assertRaises(ProviderRejected):
                    self.provider.create_txt(self.receipt)
                self.rejected(self.provider.delete_record)
        self.assertEqual(self.service.mutations, [])

    def test_existing_owned_pair_is_never_blindly_recreated(self):
        self.create()
        before = list(self.service.mutations)
        self.rejected(self.provider.create_txt)
        self.assertEqual(self.service.mutations, before)

    def test_missing_and_reencoded_owned_values_are_conflicts(self):
        marker = '"' + self.provider._marker(self.receipt).decode() + '"'
        generation = '"' + route53.GENERATION_PREFIX.decode() + "d" * 32 + '"'
        for values in ((marker, generation),
                       (marker, generation, '"AAA" "' + "A" * 40 + '"'),
                       (marker, generation, '"\\101' + "A" * 42 + '"')):
            self.service.values = values
            for operation in (self.provider.list_records, self.provider.get_record,
                              self.provider.delete_record, self.provider.confirm_absent):
                with self.subTest(values=values, operation=operation):
                    self.rejected(operation)
        self.assertEqual(self.service.mutations, [])

    def test_generation_namespace_is_canonical_unique_and_required_with_owners(self):
        gp, op = route53.GENERATION_PREFIX.decode(), route53.OWNER_PREFIX.decode()
        cases = [(f'"{gp}bad"',), (f'"{gp}' + "D" * 32 + '"',),
                 (f'"{op}bad"',), (f'"{gp}" "' + "d" * 32 + '"',),
                 (f'"{op}' + "d" * 32 + '"',),
                 (f'"{gp}' + "d" * 32 + '"', f'"{gp}' + "e" * 32 + '"'),
                 ('"\\143' + gp[1:] + "d" * 32 + '"',)]
        for values in cases:
            self.service.values = values
            with self.subTest(values=values):
                self.rejected()

    def test_absence_without_retained_generation_is_unresolved(self):
        for values in ((), ('"foreign"',)):
            self.service.values = values
            for operation in (self.provider.get_record, self.provider.confirm_absent):
                with self.subTest(values=values, operation=operation):
                    self.rejected(operation)
        self.create()
        self.rejected(self.provider.confirm_absent)

    def test_octal_parser_rejects_invalid_unbounded_or_ambiguous_values(self):
        cases = ('', 'x', 'unquoted', ' "leading"', '"trailing" ', '"open', '"\\',
                 '"\\400"', '"\\999"', '"\\12"', '"\\x"', '"a"x', '"a""b"',
                 '"a"  x', '"\u00e4"', '"\n"', '"' + "z" * 256 + '"', '"' + "z" * 3999 + '"')
        for value in cases:
            self.service.values = (value,)
            with self.subTest(value=value[:50]):
                self.rejected()
        self.service.values = ('"A"', '"\\101"')
        self.rejected()
        self.service.values = ('"same"', '"same"')
        self.rejected()

    def test_snapshot_count_and_combined_character_bounds(self):
        for values in (tuple('"%s"' % i for i in range(129)),
                       tuple('"' + (str(i) + "z" * 252) + '"' for i in range(128))):
            self.service.values = values
            self.rejected()
        self.assertEqual(self.service.mutations, [])

    def test_create_capacity_reserves_metadata_and_exact_old_plus_new_budget(self):
        self.service.values = tuple('"%s"' % i for i in range(126))
        with self.assertRaises(ProviderRejected):
            self.provider.create_txt(self.receipt)
        self.service.values = tuple('"' + str(i) + "z" * 250 + '"' for i in range(63))
        self.assertEqual(self.provider.list_records(self.receipt), [])
        with self.assertRaises(ProviderRejected):
            self.provider.create_txt(self.receipt)
        self.service.values = ()
        with patch.object(route53, "MAX_BATCH_RECORDS", 2), self.assertRaises(ProviderRejected):
            self.provider.create_txt(self.receipt)
        self.assertEqual(self.service.mutations, [])

    def test_existing_generation_collision_is_uncertain_before_send(self):
        self.service.values = ('"' + route53.GENERATION_PREFIX.decode() + "d" * 32 + '"',)
        with patch.object(route53.secrets, "token_hex", return_value="d" * 32):
            self.rejected(self.provider.create_txt)
        self.assertEqual(self.service.mutations, [])

    def test_cleanup_budget_failure_preserves_owned_and_foreign_values(self):
        self.create()
        self.service.values += tuple('"' + str(i) + "z" * 250 + '"' for i in range(64))
        before = self.service.values
        self.rejected(self.provider.delete_record)
        self.assertEqual(self.service.values, before)
        self.assertEqual(len(self.service.mutations), 1)

    def test_concurrent_foreign_identical_value_and_ttl_changes_reject_whole_batch(self):
        for mode in ("foreign", "identical", "ttl"):
            self.service.values, self.service.ttl = ('"preexisting"',), 120
            def race(name, ttl, before, after):
                if mode == "ttl":
                    self.service.ttl = 900
                else:
                    self.service.values += ('"' + ("A" * 43 if mode == "identical" else "foreign") + '"',)
            self.service.before_change = race
            with self.subTest(mode=mode):
                self.rejected(self.provider.create_txt)
                self.assertFalse(any(route53.OWNER_PREFIX.decode() in value for value in self.service.values))
        self.assertEqual(self.service.mutations, [])

    def test_absent_create_race_and_cname_conflict_have_no_remote_partial_effect(self):
        self.service.before_change = lambda *args: setattr(self.service, "values", ('"new foreign"',))
        self.rejected(self.provider.create_txt)
        self.assertEqual(self.service.values, ('"new foreign"',))
        self.service.before_change, self.service.values, self.service.conflict = None, (), True
        self.rejected(self.provider.create_txt)
        self.assertEqual(self.service.values, ())
        self.assertEqual(self.service.mutations, [])

    def test_concurrent_foreign_write_during_cleanup_is_preserved(self):
        self.create()
        self.service.before_change = lambda *args: setattr(self.service, "values", self.service.values + ('"new foreign"',))
        self.rejected(self.provider.delete_record)
        self.assertIn('"new foreign"', self.service.values)
        self.assertTrue(self.provider.matches(self.provider.get_record(self.receipt), self.receipt, owned=True))
        self.assertEqual(len(self.service.mutations), 1)

    def test_lost_create_reply_is_recoverable_and_never_retried(self):
        def lose(*args):
            raise TimeoutError("PRIVATE")
        self.service.after_change = lose
        self.rejected(self.provider.create_txt)
        self.assertEqual(len(self.service.mutations), 1)
        self.service.after_change = None
        recovered = self.provider.list_records(self.receipt, require_complete=True)[0]
        self.assertTrue(self.provider.matches(recovered, self.receipt, owned=True))
        self.provider.delete_record(self.receipt)

    def test_lost_cleanup_reply_can_be_resolved_by_bound_absence(self):
        self.create()
        def lose(*args):
            raise TimeoutError("PRIVATE")
        self.service.after_change = lose
        self.rejected(self.provider.delete_record)
        self.service.after_change = None
        self.assertIsNone(self.provider.get_record(self.receipt))
        self.provider.confirm_absent(self.receipt)
        self.assertEqual(len(self.service.mutations), 2)

    def test_client_and_read_failures_are_fixed_safe_uncertain_errors(self):
        def fail(*args):
            raise ValueError("PRIVATE")
        self.provider._client_factory = fail
        self.rejected()
        self.provider._client_factory = self.service
        for operation in ("zone", "records"):
            self.transform(operation, fail)
            with self.subTest(operation=operation):
                self.rejected()
        self.assertEqual(self.service.mutations, [])

    def test_post_create_readback_requires_owned_pair_and_generation(self):
        generation = '"' + route53.GENERATION_PREFIX.decode() + "d" * 32 + '"'
        for values in ((), ('"foreign"',), (generation,), (generation, '"' + "A" * 43 + '"'),
                       ('"' + "A" * 43 + '"', '"' + self.provider._marker(self.receipt).decode() + '"')):
            self.service.values = ()
            self.service.after_change = lambda *args: setattr(self.service, "values", values)
            with self.subTest(values=values):
                self.rejected(self.provider.create_txt)

    def test_post_delete_readback_does_not_finish_with_missing_generation_or_pair(self):
        for mode in ("empty", "pair"):
            self.service.values, self.service.after_change = (), None
            self.create()
            old = self.service.values
            self.service.after_change = lambda *args: setattr(self.service, "values", () if mode == "empty" else old)
            with self.subTest(mode=mode):
                self.rejected(self.provider.delete_record)

    def test_zone_identity_private_flag_nameservers_and_counts_are_checked(self):
        changes = [("HostedZone/Id", "/hostedzone/ZOTHER"), ("HostedZone/Name", "other.example."),
                   ("HostedZone/Config/PrivateZone", "true"), ("HostedZone/Config/PrivateZone", "0"),
                   ("HostedZone/CallerReference", "x" * 129), ("HostedZone/ResourceRecordSetCount", "-1"),
                   ("HostedZone/ResourceRecordSetCount", str(2 ** 63)),
                   ("DelegationSet/NameServers/NameServer", "other.example.")]
        for path, value in changes:
            self.transform("zone", lambda root: setattr(find(root, path), "text", value))
            with self.subTest(path=path, value=value):
                self.rejected(self.provider.create_txt)
        self.transform("zone", lambda root: find(root, "DelegationSet/NameServers").append(
            copy.deepcopy(find(root, "DelegationSet/NameServers/NameServer"))))
        self.rejected()
        self.assertEqual(self.service.mutations, [])

    def test_optional_zone_metadata_and_nameserver_root_dots_are_safe(self):
        def metadata(root):
            element("Comment", parent=find(root, "HostedZone/Config"))
            element("Id", "/delegationset/N123", find(root, "DelegationSet"))
            element("CallerReference", "fixture", find(root, "DelegationSet"))
            for row in find(root, "DelegationSet/NameServers"):
                row.text += "."
        self.transform("zone", metadata)
        self.create()

    def test_zone_xml_duplicates_unknown_fields_attributes_text_and_namespaces_refuse(self):
        def duplicate(root):
            root.append(copy.deepcopy(find(root, "HostedZone")))
        def missing(root):
            root.remove(find(root, "DelegationSet"))
        changes = [lambda root: setattr(root, "tag", "GetHostedZoneResponse"),
                   lambda root: setattr(root, "attrib", {"unknown": "x"}),
                   lambda root: setattr(root, "text", "private"),
                   lambda root: setattr(find(root, "HostedZone"), "tail", "private"),
                   duplicate, missing, lambda root: element("Unknown", parent=root),
                   lambda root: setattr(find(root, "HostedZone/Id"), "text", None),
                   lambda root: element("Nested", parent=find(root, "HostedZone/Id")),
                   lambda root: setattr(find(root, "HostedZone/Name"), "attrib", {"bad": "x"}),
                   lambda root: setattr(find(root, "DelegationSet/NameServers/NameServer"), "tag", "NameServer")]
        for mutation in changes:
            self.transform("zone", mutation)
            with self.subTest(mutation=mutation):
                self.rejected()
        self.service.transform = lambda actual, root: "not XML" if actual == "zone" else None
        self.rejected()

    def test_targeted_list_can_prove_absence_from_a_later_name(self):
        self.service.values = ('"foreign"',)
        self.transform("records", lambda root: setattr(find(root, "ResourceRecordSets/ResourceRecordSet/Name"),
                                                       "text", "later.example.com."))
        self.assertEqual(self.provider.list_records(self.receipt), [])
        self.assertEqual(self.service.mutations, [])

    def later_neighbor(self, root, style):
        rows = find(root, "ResourceRecordSets")
        rows.clear()
        row = element("ResourceRecordSet", parent=rows)
        element("Name", "later.example.com.", row)
        element("Type", "A", row)
        if style == "alias":
            alias = element("AliasTarget", parent=row)
            element("DNSName", "load-balancer.example.net.", alias)
            element("EvaluateTargetHealth", "false", alias)
            element("HostedZoneId", "ZALIAS123", alias)
        else:
            element("SetIdentifier", "blue", row)
            element("Weight", "50", row)
            element("TTL", "120", row)
            record = element("ResourceRecord", parent=element("ResourceRecords", parent=row))
            element("Value", "192.0.2.5", record)
        return row

    def test_first_issuance_accepts_later_alias_and_weighted_neighbors(self):
        for style in ("alias", "weighted"):
            self.service.values = ()
            self.service.next_record = ("later.example.com.", "A", "green") if style == "weighted" else None
            self.receipt["record"] = None
            def neighbor(root):
                if not len(find(root, "ResourceRecordSets")):
                    self.later_neighbor(root, style)
            self.transform("records", neighbor)
            with self.subTest(style=style):
                self.assertEqual(self.provider.list_records(self.receipt), [])
                self.create()
                self.assertEqual(self.service.mutations[-1]["before"], ())
                self.assertEqual(self.service.mutations[-1]["name"], self.receipt["name"])
                self.provider.delete_record(self.receipt)
                self.provider.confirm_absent(self.receipt)
                self.assertEqual(len(self.service.values), 1)

    def test_later_neighbor_identity_must_be_direct_unique_and_in_namespace(self):
        mutations = [lambda row: row.append(copy.deepcopy(find(row, "Name"))),
                     lambda row: row.append(copy.deepcopy(find(row, "Type"))),
                     lambda row: row.remove(find(row, "Name")),
                     lambda row: row.remove(find(row, "Type")),
                     lambda row: setattr(find(row, "Name"), "tag", "Name"),
                     lambda row: setattr(find(row, "Type"), "tag", "{urn:other}Type"),
                     lambda row: setattr(find(row, "Name"), "attrib", {"unexpected": "value"}),
                     lambda row: element("Nested", parent=find(row, "Name")),
                     lambda row: setattr(find(row, "Name"), "text", ""),
                     lambda row: setattr(row, "attrib", {"unexpected": "value"}),
                     lambda row: setattr(row, "text", "mixed text")]
        for mutation in mutations:
            def neighbor(root):
                mutation(self.later_neighbor(root, "alias"))
            self.transform("records", neighbor)
            with self.subTest(mutation=mutation):
                self.rejected(self.provider.create_txt)
        self.assertEqual(self.service.mutations, [])

    def test_later_weighted_continuation_requires_valid_unambiguous_cursor(self):
        self.transform("records", lambda root: self.later_neighbor(root, "weighted"))
        for cursor in (("later.example.com.", "A"), ("before.example.com.", "A", "green"),
                       ("later.example.com.", "A", ""), ("later.example.com.", "A", "g" * 129),
                       ("later.example.com", "A", "green"), ("later.example.com.", "UNKNOWN", "green")):
            self.service.next_record = cursor
            with self.subTest(cursor=cursor):
                self.rejected()
        self.service.next_record = ("later.example.com.", "A", "green")
        def duplicate(root):
            self.later_neighbor(root, "weighted")
            root.append(copy.deepcopy(find(root, "NextRecordName")))
        self.transform("records", duplicate)
        self.rejected()
        self.assertEqual(self.service.mutations, [])

    def test_list_rejects_earlier_names_non_txt_target_and_unknown_types(self):
        self.service.values = ('"foreign"',)
        changes = [("Name", "example.com."), ("Name", "_acme-challenge.example.com"),
                   ("Name", "a" * 255 + "."), ("Type", "A"), ("Type", "UNKNOWN"),
                   ("TTL", "-1"), ("TTL", str(2 ** 31)), ("TTL", "01")]
        for field, value in changes:
            self.transform("records", lambda root: setattr(find(root, "ResourceRecordSets/ResourceRecordSet/" + field),
                                                           "text", value))
            with self.subTest(field=field, value=value):
                self.rejected()

    def test_non_simple_txt_policies_aliases_and_unknown_attributes_refuse(self):
        self.service.values = ('"foreign"',)
        for field in ("SetIdentifier", "Weight", "AliasTarget", "HealthCheckId", "Region", "Failover",
                      "GeoLocation", "GeoProximityLocation", "CidrRoutingConfig", "TrafficPolicyInstanceId"):
            self.transform("records", lambda root: element(field, "x", find(root, "ResourceRecordSets/ResourceRecordSet")))
            with self.subTest(field=field):
                self.rejected()
        self.transform("records", lambda root: element("MultiValueAnswer", "true", find(root, "ResourceRecordSets/ResourceRecordSet")))
        self.rejected()
        self.transform("records", lambda root: element("MultiValueAnswer", "false", find(root, "ResourceRecordSets/ResourceRecordSet")))
        self.create()

    def test_record_wrappers_and_value_shapes_are_strict(self):
        self.service.values = ('"foreign"',)
        mutations = [lambda root: find(root, "ResourceRecordSets").append(copy.deepcopy(find(root, "ResourceRecordSets/ResourceRecordSet"))),
                     lambda root: find(root, "ResourceRecordSets/ResourceRecordSet/ResourceRecords").clear(),
                     lambda root: element("Other", parent=find(root, "ResourceRecordSets/ResourceRecordSet/ResourceRecords")),
                     lambda root: element("Other", parent=find(root, "ResourceRecordSets/ResourceRecordSet/ResourceRecords/ResourceRecord")),
                     lambda root: setattr(find(root, "ResourceRecordSets/ResourceRecordSet/ResourceRecords/ResourceRecord/Value"), "text", None)]
        for mutation in mutations:
            self.transform("records", mutation)
            with self.subTest(mutation=mutation):
                self.rejected()

    def test_pagination_metadata_is_bounded_and_never_treated_as_an_exact_filter(self):
        self.service.values = ('"foreign"',)
        self.service.next_record = ("later.example.com.", "TXT", "weighted-next")
        self.assertEqual(self.provider.list_records(self.receipt), [])
        for next_record in (("example.com.", "TXT"), (self.receipt["name"] + ".", "TXT"),
                            ("later.example.com", "TXT"), ("later.example.com.", "UNKNOWN"),
                            ("later.example.com.", "TXT", "x" * 129), ("later.example.com.", "TXT", "")):
            self.service.next_record = next_record
            with self.subTest(next_record=next_record):
                self.rejected()
        self.service.next_record = ("later.example.com.", "TXT")
        self.service.values = ()
        self.rejected()

    def test_positive_simple_txt_is_complete_before_a_different_type_at_same_name(self):
        self.service.values = ('"foreign"',)
        self.service.next_record = (self.receipt["name"] + ".", "A", "weighted-other-type")
        self.create()
        self.provider.delete_record(self.receipt)
        self.assertIn('"foreign"', self.service.values)
        self.service.next_record = (self.receipt["name"] + ".", "TXT", "another-txt")
        self.rejected()

    def test_incomplete_contradictory_and_false_pagination_metadata_refuse(self):
        self.service.values = ('"foreign"',)
        for field, value in (("MaxItems", "2"), ("IsTruncated", "TRUE"), ("IsTruncated", "true")):
            self.transform("records", lambda root: setattr(find(root, field), "text", value))
            with self.subTest(field=field, value=value):
                self.rejected()
        self.transform("records", lambda root: element("NextRecordName", "later.example.com.", root))
        self.rejected()

    def test_pending_and_insync_acknowledgements_with_optional_comment(self):
        def acknowledge(root):
            find(root, "ChangeInfo/Status").text = "INSYNC"
            find(root, "ChangeInfo/SubmittedAt").text = "2026-11-25T01:02:03Z"
            element("Comment", parent=find(root, "ChangeInfo"))
        self.transform("change", acknowledge)
        self.create()
        self.provider.delete_record(self.receipt)

    def test_invalid_acknowledgements_keep_remote_effect_uncertain(self):
        changes = [("Id", "/change/other"), ("Status", "SUCCESS"), ("SubmittedAt", "yesterday"),
                   ("SubmittedAt", "2026-13-25T01:02:03Z")]
        for field, value in changes:
            self.service.values = ()
            self.transform("change", lambda root: setattr(find(root, "ChangeInfo/" + field), "text", value))
            with self.subTest(field=field, value=value):
                self.rejected(self.provider.create_txt)
                self.assertIn('"' + self.receipt["value"] + '"', self.service.values)
        self.assertEqual(len(self.service.mutations), len(changes))


if __name__ == "__main__":
    unittest.main()
