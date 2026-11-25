"""Real signed wire and conservative RFC2136 state-machine contracts."""
import base64
import copy
import json
from pathlib import Path
import socketserver
import tempfile
import threading
import unittest
from unittest.mock import patch

import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rdataclass
import dns.rdatatype
import dns.rcode
import dns.rrset
import dns.tsig

from cgp_cert_manager import rfc2136
from cgp_cert_manager.dnsproviders import ProviderError, ProviderRejected
from rfc2136_fixture import FakePrimary


class RFC2136Tests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.secret = self.root / "key.json"
        self.secret.write_text(json.dumps({"secret": base64.b64encode(b"s" * 32).decode()}))
        self.secret.chmod(0o600)
        self.cfg = {"dns_provider": "rfc2136", "rfc2136": {"zones": [
            {"zone": "example.com", "server": "192.0.2.53", "credentials": str(self.secret),
             "key_name": "manager-key", "nameservers": ["ns1.example.net", "ns2.example.net"]}]}}
        self.server = FakePrimary()
        self.provider = rfc2136.RFC2136Provider(self.cfg, tcp=self.server)
        self.receipt = self.make_receipt(self.provider)

    def make_receipt(self, provider):
        return {"zone": next(iter(provider._bindings)), "credentials": str(self.secret),
                "name": "_acme-challenge.example.com", "value": "A" * 43, "record": None,
                "owner": "cgp-certificate-manager:" + "a" * 32}

    def create(self, receipt=None):
        receipt = self.receipt if receipt is None else receipt
        remote = self.provider.create_txt(receipt)
        receipt["record"] = self.provider.record_id(remote)
        return remote

    def generations(self):
        return {v for v in self.server.txt(self.receipt["name"]) if v.startswith(rfc2136.GENERATION_PREFIX)}

    def test_discovery_credentials_capabilities_and_pure_selection(self):
        before = copy.deepcopy(self.cfg)
        with patch.object(rfc2136.rfc2136_config, "read_secret") as secret:
            provider = rfc2136.RFC2136Provider(self.cfg)
            self.assertEqual(provider.credentials(self.cfg), (str(self.secret),))
            self.assertEqual(provider.credentials(self.cfg, absolute=True), (str(self.secret),))
            self.assertEqual(provider.zones(self.cfg), {"example.com": {
                "id": self.receipt["zone"], "credentials": str(self.secret),
                "ns": ["ns1.example.net", "ns2.example.net"], "provider": "rfc2136"}})
            for cap in ("fixed_native", "fixed_hooks", "unknown", [], None):
                with self.subTest(cap=cap), self.assertRaises(ProviderError):
                    provider.require(cap)
            secret.assert_not_called()
        self.provider.validate_credentials(self.cfg)
        self.assertEqual(self.cfg, before)
        self.assertEqual(self.server.requests, [])

    def test_receipt_binding_refuses_before_secrets_or_network(self):
        cases = [{"zone": []}, {"zone": "f" * 64}, {"credentials": "elsewhere"},
                 {"owner": "private"}, {"owner": None}, {"name": "_acme-challenge.example.net"},
                 {"name": "_acme-challenge.EXAMPLE.com"}, {"name": "_acme-challenge.example.com."},
                 {"name": "example.com"}, {"name": "www.example.com"},
                 {"name": 1}, {"value": None}, {"value": "bad"}, {"record": "b" * 32}]
        for changes in cases:
            receipt = {**self.receipt, **changes}
            with self.subTest(changes=changes), patch.object(rfc2136.rfc2136_config, "read_secret") as secret:
                with self.assertRaisesRegex(ProviderError, "RFC2136 evidence is unavailable or changed"):
                    self.provider.list_records(receipt)
                secret.assert_not_called()
        self.assertEqual(self.server.requests, [])
        self.assertFalse(self.provider.valid_zone_id([]))
        self.assertFalse(self.provider.valid_zone_id("unknown"))
        self.assertTrue(self.provider.valid_zone_id(self.receipt["zone"]))

    def test_record_identity_and_matching_are_explicit(self):
        for bad in (None, {}, [], {"id": 1}, {"id": "A" * 32}):
            with self.subTest(bad=bad), self.assertRaises(ProviderError):
                self.provider.record_id(bad)
        remote = {"id": "a" * 32, "name": self.receipt["name"], "value": self.receipt["value"], "owner": None}
        self.assertEqual(self.provider.record_id(remote), "a" * 32)
        self.assertTrue(self.provider.matches(remote, self.receipt))
        self.assertFalse(self.provider.matches(remote, self.receipt, owned=True))
        self.assertFalse(self.provider.matches({**remote, "name": "other"}, self.receipt))
        self.assertFalse(self.provider.matches({**remote, "value": "other"}, self.receipt))

    def test_signed_create_delete_and_absence_proof_leave_one_replay_fence(self):
        self.assertEqual(self.provider.list_records(self.receipt), [])
        remote = self.create()
        self.assertTrue(self.provider.matches(remote, self.receipt, owned=True))
        self.assertEqual(len(self.server.txt(self.receipt["name"])), 3)
        first_generation = self.generations()
        create_wire = next(w for w, q in zip(self.server.wires, self.server.requests)
                           if q.opcode() == dns.opcode.UPDATE)
        self.provider.delete_record(self.receipt)
        second_generation = self.generations()
        self.assertEqual(len(second_generation), 1)
        self.assertNotEqual(first_generation, second_generation)
        self.assertEqual(self.server.txt(self.receipt["name"]), second_generation)
        self.assertIsNone(self.provider.get_record(self.receipt))
        self.provider.confirm_absent(self.receipt)
        self.assertEqual(self.generations(), second_generation)
        self.assertFalse(self.server.requests[-1].update)
        # Replay the exact previously accepted signed CREATE after cleanup.
        original = dns.message.from_wire(create_wire, keyring=self.server.key)
        response = dns.message.from_wire(self.server.handle(create_wire), keyring=self.server.key,
                                         request_mac=original.mac)
        self.assertEqual(response.rcode(), dns.rcode.YXRRSET)
        self.assertEqual(self.server.txt(self.receipt["name"]), second_generation)

    def test_foreign_raw_txt_and_ttl_survive_updates(self):
        name = self.receipt["name"]
        self.server.put(name, '"foreign" " chunks"', '"unrelated"', ttl=900)
        old = set(self.server.records[(dns.name.from_text(name), dns.rdatatype.TXT)])
        self.create()
        update = self.server.mutations[0]
        txt_prerequisite = [rr for rr in update.prerequisite if rr.rdtype == dns.rdatatype.TXT][0]
        self.assertEqual({rd for rr in update.prerequisite if rr.rdtype == dns.rdatatype.TXT for rd in rr}, old)
        self.assertEqual(txt_prerequisite.ttl, 0)
        self.assertTrue(all(rr.ttl == 900 for rr in update.update if rr.deleting is None))
        self.provider.delete_record(self.receipt)
        remaining = self.server.records[(dns.name.from_text(name), dns.rdatatype.TXT)]
        self.assertTrue(old.issubset(set(remaining)))
        self.assertEqual(remaining.ttl, 900)
        self.assertEqual(len(remaining), 3)

    def test_two_owned_values_share_one_generation_and_clean_independently(self):
        self.create()
        second = {**self.receipt, "owner": "cgp-certificate-manager:" + "b" * 32,
                  "value": "B" * 43, "record": None}
        self.create(second)
        self.assertEqual(len(self.generations()), 1)
        self.assertEqual(len(self.server.txt(self.receipt["name"])), 5)
        self.provider.delete_record(self.receipt)
        self.assertTrue(self.provider.matches(self.provider.get_record(second), second, owned=True))
        self.provider.delete_record(second)
        self.assertEqual(len(self.server.txt(self.receipt["name"])), 1)

    def test_preexisting_joined_value_is_borrowed_without_mutation(self):
        self.server.put(self.receipt["name"], '"AAA" "' + "A" * 40 + '"')
        rows = self.provider.list_records(self.receipt)
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["owner"])
        self.assertEqual(self.provider.get_record(self.receipt), rows[0])
        with self.assertRaises(ProviderRejected):
            self.provider.create_txt(self.receipt)
        with self.assertRaises(ProviderError):
            self.provider.delete_record(self.receipt)
        self.assertFalse(self.server.mutations)

    def test_existing_owned_pair_does_not_blindly_recreate(self):
        self.create()
        before = len(self.server.mutations)
        with self.assertRaises(ProviderError):
            self.provider.create_txt(self.receipt)
        self.assertEqual(len(self.server.mutations), before)

    def test_partial_or_reencoded_owned_pair_is_a_conflict(self):
        marker = self.provider._marker(self.receipt).decode()
        generation = (rfc2136.GENERATION_PREFIX + b"d" * 32).decode()
        for texts in ((f'"{marker}"', f'"{generation}"'),
                      (f'"{marker}"', f'"{generation}"', '"AAA" "' + "A" * 40 + '"')):
            self.server.put(self.receipt["name"], *texts)
            with self.subTest(texts=texts):
                for operation in (self.provider.list_records, self.provider.get_record,
                                  self.provider.delete_record, self.provider.confirm_absent):
                    with self.assertRaises(ProviderError):
                        operation(self.receipt)
        self.assertFalse(self.server.mutations)

    def test_absence_requires_retained_generation_and_atomically_checks_cut(self):
        for operation in (self.provider.get_record, self.provider.confirm_absent):
            with self.assertRaises(ProviderError):
                operation(self.receipt)
        self.create()
        self.provider.delete_record(self.receipt)
        self.server.before = lambda q: self.server.put(self.receipt["name"], "ns1.example.net.", kind="NS") \
            if q.opcode() == dns.opcode.UPDATE else None
        with self.assertRaises(ProviderError):
            self.provider.confirm_absent(self.receipt)
        self.assertEqual(len(self.server.mutations), 2)

    def test_generation_and_owner_namespace_are_strict_and_bounded(self):
        gp = rfc2136.GENERATION_PREFIX.decode()
        op = rfc2136.OWNER_PREFIX.decode()
        cases = [(f'"{gp}bad"',), (f'"{gp}' + "D" * 32 + '"',),
                 (f'"{op}bad"',), (f'"{gp}" "' + "d" * 32 + '"',),
                 (f'"{op}' + "d" * 32 + '"',),
                 (f'"{gp}' + "d" * 32 + '"', f'"{gp}' + "e" * 32 + '"')]
        for texts in cases:
            self.server.put(self.receipt["name"], *texts)
            with self.subTest(texts=texts), self.assertRaises(ProviderError):
                self.provider.list_records(self.receipt)
        self.server.put(self.receipt["name"], *(f'"{i}"' for i in range(129)))
        with self.assertRaises(ProviderError):
            self.provider.list_records(self.receipt)
        self.server.put(self.receipt["name"], " ".join('"' + "z" * 255 + '"' for _ in range(129)))
        with self.assertRaises(ProviderError):
            self.provider.list_records(self.receipt)

    def test_local_capacity_and_generation_collision_fail_before_send(self):
        self.server.put(self.receipt["name"], *(f'"{i}"' for i in range(126)))
        with self.assertRaises(ProviderRejected):
            self.provider.create_txt(self.receipt)
        self.assertFalse(self.server.mutations)
        self.server.records.clear()
        self.server.put(self.receipt["name"], '"' + rfc2136.GENERATION_PREFIX.decode() + "d" * 32 + '"')
        with patch.object(rfc2136.secrets, "token_hex", return_value="d" * 32), self.assertRaises(ProviderError):
            self.provider.create_txt(self.receipt)
        self.assertFalse(self.server.mutations)

    def test_every_remote_update_error_keeps_uncertainty_even_after_effect(self):
        for code in (dns.rcode.FORMERR, dns.rcode.REFUSED, dns.rcode.NOTAUTH, dns.rcode.NOTZONE,
                     dns.rcode.NXDOMAIN, dns.rcode.YXDOMAIN, dns.rcode.NXRRSET, dns.rcode.YXRRSET,
                     dns.rcode.SERVFAIL, dns.rcode.NOTIMP):
            self.server.records.clear()
            self.server.after = lambda q, r: r.set_rcode(code) if q.opcode() == dns.opcode.UPDATE else None
            with self.subTest(code=code), self.assertRaises(ProviderError) as raised:
                self.provider.create_txt(self.receipt)
            self.assertNotIsInstance(raised.exception, ProviderRejected)
            self.assertIn(self.receipt["value"].encode(), self.server.txt(self.receipt["name"]))

    def test_byte_capacity_reserves_space_for_owned_values_before_mutation(self):
        # Valid existing input must not become permanently unreadable after
        # this adapter adds its ownership values and persistent generation.
        large = " ".join('"' + "z" * 255 + '"' for _ in range(128)) + ' "' + "z" * 100 + '"'
        self.server.put(self.receipt["name"], large)
        before = self.server.txt(self.receipt["name"])
        self.assertEqual(self.provider.list_records(self.receipt), [])
        with self.assertRaises(ProviderRejected):
            self.provider.create_txt(self.receipt)
        self.assertFalse(self.server.mutations)
        self.assertEqual(self.server.txt(self.receipt["name"]), before)

    def test_lost_reply_and_cas_conflict_do_not_repeat_update(self):
        def lose(query, response):
            if query.opcode() == dns.opcode.UPDATE:
                raise TimeoutError("PRIVATE")
        self.server.after = lose
        with self.assertRaisesRegex(ProviderError, "RFC2136 evidence is unavailable or changed"):
            self.provider.create_txt(self.receipt)
        self.assertEqual(len(self.server.mutations), 1)
        self.server.after = None
        self.assertTrue(self.provider.matches(self.provider.list_records(self.receipt)[0], self.receipt, owned=True))

    def test_cname_dname_and_delegation_races_refuse_atomic_creation(self):
        for owner, kind, text in ((self.receipt["name"], "CNAME", "other.example.com."),
                                  ("example.com", "DNAME", "example.net."),
                                  (self.receipt["name"], "NS", "ns1.example.net.")):
            self.server.records.clear()
            self.server.before = lambda q: self.server.put(owner, text, kind=kind) \
                if q.opcode() == dns.opcode.UPDATE else None
            with self.subTest(kind=kind), self.assertRaises(ProviderError):
                self.provider.create_txt(self.receipt)
        self.assertFalse(self.server.mutations)

    def test_missing_post_create_pair_or_generation_keeps_intent_unresolved(self):
        for mode in ("empty", "foreign", "no_generation"):
            self.server.records.clear()
            def after(q, r):
                if q.opcode() != dns.opcode.UPDATE:
                    return
                if mode == "empty":
                    self.server.records.clear()
                elif mode == "foreign":
                    self.server.put(self.receipt["name"], '"foreign"')
                else:
                    self.server.put(self.receipt["name"], '"' + self.receipt["value"] + '"',
                                    '"' + self.provider._marker(self.receipt).decode() + '"')
            self.server.after = after
            with self.subTest(mode=mode), self.assertRaises(ProviderError):
                self.provider.create_txt(self.receipt)

    def test_bad_signed_query_shapes_refuse_without_mutation(self):
        owner = self.receipt["name"]
        modifications = [lambda r: r.set_rcode(dns.rcode.REFUSED),
                         lambda r: setattr(r, "flags", r.flags & ~dns.flags.AA),
                         lambda r: r.question.append(copy.deepcopy(r.question[0])),
                         lambda r: setattr(r, "answer", [dns.rrset.from_text(owner, 120, "IN", "CNAME", "elsewhere.example.com.")]),
                         lambda r: setattr(r, "answer", [dns.rrset.from_text(owner, 120, "IN", "DNAME", "elsewhere.example.com.")]),
                         lambda r: setattr(r, "authority", [dns.rrset.from_text("child.example.com", 120, "IN", "SOA", "ns. a. 1 1 1 1 1")]),
                         lambda r: setattr(r, "authority", [dns.rrset.from_text("example.com", 120, "IN", "NS", "ns1.example.net.")]),
                         lambda r: setattr(r, "authority", []),
                         lambda r: r.authority.append(dns.rrset.from_text("other.example.com", 120, "IN", "SOA", "ns. a. 1 1 1 1 1"))]
        for change in modifications:
            self.server.after = lambda q, r: change(r)
            with self.subTest(change=change), self.assertRaises(ProviderError):
                self.provider.list_records(self.receipt)
        self.assertFalse(self.server.mutations)

    def test_bad_positive_query_shapes_refuse(self):
        owner = self.receipt["name"]
        self.server.put(owner, '"foreign"')
        changes = [lambda r: r.set_rcode(dns.rcode.NXDOMAIN),
                   lambda r: r.answer.append(dns.rrset.from_text("elsewhere.example.com", 1, "IN", "TXT", '"x"')),
                   lambda r: setattr(r.answer[0], "name", dns.name.from_text("elsewhere.example.com")),
                   lambda r: setattr(r, "answer", [dns.rrset.from_text(owner, 1, "CH", "TXT", '"x"')]),
                   lambda r: setattr(r, "answer", [dns.rrset.from_text(owner, 1, "IN", "A", "192.0.2.1")]),
                   lambda r: r.authority.append(copy.deepcopy(self.server.soa))]
        for change in changes:
            self.server.after = lambda q, r: change(r)
            with self.subTest(change=change), self.assertRaises(ProviderError):
                self.provider.list_records(self.receipt)

    def test_signed_envelope_and_explicit_legacy_unsigned_guard(self):
        def modified(change):
            def exchange(q, *args, **kwargs):
                response = self.server(q, *args, **kwargs)
                change(response)
                return response
            return exchange
        changes = [lambda r: setattr(r, "tsig", None),
                   lambda r: setattr(r.tsig, "name", dns.name.from_text("other-key")),
                   lambda r: r.use_tsig(dns.tsig.Key("manager-key", b"s" * 32, "hmac-sha512")),
                   lambda r: r.use_tsig(self.server.key, tsig_error=18),
                   lambda r: setattr(r, "id", r.id ^ 1),
                   lambda r: r.set_opcode(dns.opcode.UPDATE),
                   lambda r: setattr(r, "flags", r.flags | dns.flags.TC),
                   lambda r: setattr(r, "flags", r.flags & ~dns.flags.QR)]
        for change in changes:
            provider = rfc2136.RFC2136Provider(self.cfg, tcp=modified(change))
            with self.subTest(change=change), self.assertRaises(ProviderError):
                provider.list_records(self.receipt)

    def test_real_wire_unsigned_and_bad_mac_are_rejected(self):
        for mode in ("unsigned", "bad_mac"):
            def exchange(query, *args, **kwargs):
                wire = self.server.handle(query.to_wire())
                response = dns.message.from_wire(wire, keyring=query.keyring, request_mac=query.mac)
                if mode == "unsigned":
                    response.tsig = None
                    wire = response.to_wire()
                else:
                    location = wire.index(response.mac)
                    wire = wire[:location] + bytes([wire[location] ^ 1]) + wire[location + 1:]
                return dns.message.from_wire(wire, keyring=query.keyring, request_mac=query.mac)
            provider = rfc2136.RFC2136Provider(self.cfg, tcp=exchange)
            with self.subTest(mode=mode), self.assertRaises(ProviderError):
                provider.list_records(self.receipt)

    def test_actual_loopback_tcp_signed_lifecycle_and_unsigned_refusal(self):
        fake = self.server
        errors = []
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    self.request.settimeout(3)
                    def read(count):
                        result = b""
                        while len(result) < count:
                            part = self.request.recv(count - len(result))
                            if not part:
                                raise EOFError
                            result += part
                        return result
                    length = int.from_bytes(read(2), "big")
                    response = fake.handle(read(length))
                    self.request.sendall(len(response).to_bytes(2, "big") + response)
                except Exception as error:
                    errors.append(error)
        with socketserver.TCPServer(("127.0.0.1", 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
            thread.start()
            try:
                cfg = copy.deepcopy(self.cfg)
                cfg["rfc2136"]["zones"][0].update(server="127.0.0.1", port=server.server_address[1])
                provider = rfc2136.RFC2136Provider(cfg)
                receipt = self.make_receipt(provider)
                receipt["record"] = provider.record_id(provider.create_txt(receipt))
                provider.delete_record(receipt)
                provider.confirm_absent(receipt)
                fake.after = lambda q, r: setattr(r, "tsig", None)
                with self.assertRaises(ProviderError):
                    provider.list_records(receipt)
            finally:
                server.shutdown()
                thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])

    def test_signed_empty_update_acknowledgements_support_full_lifecycle(self):
        self.server.after = lambda q, r: r.question.clear() if q.opcode() == dns.opcode.UPDATE else None
        self.create()
        self.provider.delete_record(self.receipt)
        self.provider.confirm_absent(self.receipt)
        self.assertEqual(len(self.server.mutations), 2)

    def test_signed_full_echo_preserves_wire_identity_across_rrset_grouping(self):
        self.server.put(self.receipt["name"], '"foreign" " chunks"', '"other"')
        def echo(q, r):
            if q.opcode() == dns.opcode.UPDATE:
                r.question = copy.deepcopy(q.question)
                r.answer = copy.deepcopy(q.answer)
                r.authority = copy.deepcopy(q.authority)
        self.server.after = echo
        self.create()
        self.provider.delete_record(self.receipt)
        self.provider.confirm_absent(self.receipt)
        self.assertIn(b"foreign chunks", self.server.txt(self.receipt["name"]))
        self.assertEqual(len(self.server.mutations), 2)

    def test_signed_wrong_or_duplicate_zone_acknowledgements_are_uncertain(self):
        mutations = [lambda r: setattr(r.question[0], "name", dns.name.from_text("elsewhere.example")),
                     lambda r: r.question.append(copy.deepcopy(r.question[0]))]
        for mutate in mutations:
            self.server.records.clear()
            self.server.after = lambda q, r: mutate(r) if q.opcode() == dns.opcode.UPDATE else None
            with self.subTest(mutate=mutate), self.assertRaises(ProviderError) as raised:
                self.provider.create_txt(self.receipt)
            self.assertNotIsInstance(raised.exception, ProviderRejected)
            self.assertIn(self.receipt["value"].encode(), self.server.txt(self.receipt["name"]))

    def test_signed_stray_or_partial_update_echo_is_not_an_acknowledgement(self):
        foreign = dns.rrset.from_text("elsewhere.example.com", 120, "IN", "TXT", '"foreign"')
        for mode in ("answer", "authority", "additional", "opt", "partial", "no_zone"):
            self.server.records.clear()
            def bad(q, r):
                if q.opcode() != dns.opcode.UPDATE:
                    return
                if mode == "opt":
                    r.use_edns(0)
                elif mode == "partial":
                    r.answer = copy.deepcopy(q.answer)
                elif mode == "no_zone":
                    r.question.clear()
                    r.answer = copy.deepcopy(q.answer)
                    r.authority = copy.deepcopy(q.authority)
                else:
                    getattr(r, mode).append(copy.deepcopy(foreign))
            self.server.after = bad
            with self.subTest(mode=mode), self.assertRaises(ProviderError):
                self.provider.create_txt(self.receipt)

    def test_signed_full_echo_must_preserve_ttl_metavalues_and_multiplicity(self):
        for mode in ("ttl", "deleting", "duplicate", "txt_bytes"):
            self.server.records.clear()
            self.server.put(self.receipt["name"], '"foreign" " chunks"')
            def changed(q, r):
                if q.opcode() != dns.opcode.UPDATE:
                    return
                r.answer = copy.deepcopy(q.answer)
                r.authority = copy.deepcopy(q.authority)
                if mode == "ttl":
                    r.answer[0].ttl = 1
                elif mode == "deleting":
                    r.answer[0].deleting = dns.rdataclass.NONE
                elif mode == "duplicate":
                    r.answer.append(copy.deepcopy(r.answer[0]))
                else:
                    r.answer[0] = dns.rrset.from_text(self.receipt["name"], 0, "IN", "TXT", '"foreign chunks"')
            self.server.after = changed
            with self.subTest(mode=mode), self.assertRaises(ProviderError):
                self.provider.create_txt(self.receipt)


if __name__ == "__main__":
    unittest.main()
