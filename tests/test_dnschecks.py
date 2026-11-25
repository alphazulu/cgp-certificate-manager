import copy
import unittest
from unittest.mock import Mock, patch

import dns.flags
import dns.message
import dns.rcode
import dns.rrset

from cgp_cert_manager import core, dnschecks as d, dnsquery


def message(owner, kind, *, answer=(), authority=(), aa=False, ad=False, rcode=0):
    response = dns.message.make_response(dns.message.make_query(d.name(owner), kind))
    response.flags |= dns.flags.RA | (dns.flags.AA if aa else 0) | (dns.flags.AD if ad else 0)
    response.set_rcode(rcode)
    for section, records in ((response.answer, answer), (response.authority, authority)):
        for record_owner, record_type, values in records:
            section.append(dns.rrset.from_text(d.name(record_owner), 60, "IN", record_type, *values))
    return response


def soa(owner="example.com"):
    return owner, "SOA", ["ns1.provider.net. hostmaster.example.com. 1 3600 600 86400 60"]


SERVERS = ["ns1.provider.net", "ns2.provider.net"]
ZONES = {"example.com": {"ns": SERVERS, "id": "a" * 32, "credentials": "/private/credentials"}}
DOMAIN = {"cgp_domain": "example.com", "names": ["example.com", "*.example.com"], "unavailable": []}


class World:
    """A parent zone, two child NS and independently addressed recursive views."""
    ips = {"ns.parent.net.": "8.8.8.8", "ns1.provider.net.": "1.1.1.1", "ns2.provider.net.": "1.0.0.1"}

    def __init__(self):
        self.calls = []
        self.overrides = {}
        self.deadline = 1000
        self.txt = ['"token"', '"wild"', '"unrelated"']

    def recursive(self, owner, kind, resolver):
        return self.answer(owner, kind, resolver)

    def authoritative(self, owner, kind, address):
        return self.answer(owner, kind, address)

    def answer(self, owner, kind, observer):
        owner = d.name(owner)
        self.calls.append((owner, kind, observer))
        key = (owner, kind, observer)
        if key in self.overrides:
            value = self.overrides[key]
            if isinstance(value, Exception):
                raise value
            return value
        auth = observer not in dnsquery.RESOLVERS
        if kind == "A":
            return message(owner, kind, answer=[(owner, "A", [self.ips[owner]])])
        if kind == "AAAA":
            return message(owner, kind, authority=[soa("provider.net")])
        if kind == "SOA":
            zone = "com" if owner == "com." else "example.com"
            return message(owner, kind, **({"answer": [soa(zone)]} if owner == d.name(zone) else {"authority": [soa(zone)]}), aa=auth)
        if kind == "NS":
            if owner == "com.":
                return message(owner, kind, answer=[("com", "NS", ["ns.parent.net."])])
            ns = ("example.com", "NS", [server + "." for server in SERVERS])
            return message(owner, kind, **({"authority": [ns]} if observer == "8.8.8.8" else {"answer": [ns]}), aa=auth and observer != "8.8.8.8")
        if kind == "DS":
            return message(owner, kind, authority=[soa("com")], ad=True)
        if kind == "DNSKEY":
            return message(owner, kind, authority=[soa()], aa=auth)
        if kind == "CAA":
            return message(owner, kind, authority=[soa("com" if owner == "com." else "example.com")])
        if kind == "TXT":
            return message(owner, kind, answer=[(owner, kind, self.txt)], aa=auth)
        raise AssertionError(kind)


class DNSChecksTests(unittest.TestCase):
    def test_full_unsigned_preflight_checks_every_parent_child_and_resolver(self):
        world = World()
        with patch.object(d.dnsquery, "Client", return_value=world):
            report = d.inspect(DOMAIN, ZONES)
        self.assertTrue(report["ready"], report)
        self.assertEqual(len(report["checks"]), 8)
        self.assertEqual({item["resolver"] for item in report["checks"]}, {"cloudflare", "google"})
        self.assertTrue(all(item["evidence"] == "no_ds_by_resolver" for item in report["checks"] if item["check"] == "dnssec"))
        for address in World.ips.values():
            self.assertIn(("example.com.", "NS", address), world.calls)
        for address in ("1.1.1.1", "1.0.0.1"):
            self.assertIn(("_acme-challenge.example.com.", "SOA", address), world.calls)
        self.assertNotIn("credentials", str(report))

    def test_parent_referrals_do_not_require_aa_but_child_must_be_authoritative(self):
        for owner, kind, observer, response, reason in (
            ("example.com.", "NS", "8.8.8.8", message("example.com", "NS", authority=[("example.com", "NS", ["elsewhere.net."])]), "parent_delegation_mismatch"),
            ("example.com.", "NS", "cloudflare", message("example.com", "NS", answer=[("example.com", "NS", ["elsewhere.net."])]), "recursive_delegation_mismatch"),
            ("example.com.", "NS", "1.1.1.1", message("example.com", "NS", answer=[("example.com", "NS", ["elsewhere.net."])], aa=True), "child_nameservers_mismatch"),
            ("example.com.", "SOA", "1.1.1.1", message("example.com", "SOA", answer=[soa()]), "child_not_authoritative"),
            ("_acme-challenge.example.com.", "SOA", "1.1.1.1", message("_acme-challenge.example.com", "SOA", answer=[soa("_acme-challenge.example.com")], aa=True), "challenge_delegation_unsupported"),
            ("_acme-challenge.example.com.", "SOA", "cloudflare", message("_acme-challenge.example.com", "SOA", answer=[soa("_acme-challenge.example.com")]), "challenge_delegation_unsupported"),
            ("_acme-challenge.example.com.", "SOA", "1.1.1.1", message("_acme-challenge.example.com", "SOA", answer=[("_acme-challenge.example.com", "CNAME", ["other.com."])], aa=True), "challenge_alias_unsupported"),
        ):
            with self.subTest(reason=reason):
                world = World()
                world.overrides[(owner, kind, observer)] = response
                with patch.object(d.dnsquery, "Client", return_value=world):
                    report = d.inspect(DOMAIN, ZONES)
                self.assertFalse(report["ready"])
                self.assertEqual(report["reason"], reason)

    def test_lame_missing_and_ambiguous_zone_data(self):
        for response in (message("x.example.com", "SOA"),
                         message("x.example.com", "SOA", authority=[soa("other.com")]),
                         message("x.example.com", "SOA", authority=[soa(), soa("com")])):
            with self.assertRaisesRegex(d.QueryError, "dns_zone_cut_unknown"):
                d._soa(response, "x.example.com")
        for response in (message("example.com", "NS"),
                         message("example.com", "NS", answer=[("example.com", "NS", SERVERS)], rcode=dns.rcode.NXDOMAIN)):
            with self.assertRaisesRegex(d.QueryError, "dns_nameservers_unknown"):
                d._ns(response, "example.com")
        with self.assertRaisesRegex(d.QueryError, "provider_nameservers_unknown"):
            d.delegation(Mock(), "example.com", [], [])
        world = World()
        world.overrides[("ns.parent.net.", "A", "cloudflare")] = message("ns.parent.net", "A")
        with self.assertRaisesRegex(d.QueryError, "dns_nameserver_addresses_unknown"):
            d.View(world, "cloudflare").authoritative("example.com", "NS", "ns.parent.net.")
        world = World()
        world.overrides[("example.com.", "NS", "8.8.8.8")] = d.QueryError("dns_transport_failed")
        with patch.object(d.dnsquery, "Client", return_value=world):
            self.assertEqual(d.inspect(DOMAIN, ZONES)["reason"], "authoritative_nameserver_unreachable")

    def test_shared_parent_child_server_or_cached_answer_is_not_parent_proof(self):
        ns = ("example.com", "NS", [server + "." for server in SERVERS])
        for response in (message("example.com", "NS", answer=[ns], aa=True),
                         message("example.com", "NS", answer=[ns]),
                         message("example.com", "NS", authority=[ns], aa=True)):
            world = World()
            world.overrides[("example.com.", "NS", "8.8.8.8")] = response
            with patch.object(d.dnsquery, "Client", return_value=world):
                self.assertEqual(d.inspect(DOMAIN, ZONES)["reason"], "parent_delegation_unproven")

    def test_negative_child_apex_is_not_existing_apex_proof(self):
        for rcode in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
            world = World()
            world.overrides[("example.com.", "SOA", "1.1.1.1")] = message("example.com", "SOA", authority=[soa()], aa=True, rcode=rcode)
            with patch.object(d.dnsquery, "Client", return_value=world):
                self.assertEqual(d.inspect(DOMAIN, ZONES)["reason"], "child_apex_unproven")

    def test_nameserver_address_fallback_and_cache(self):
        world = World()
        view = d.View(world, "google")
        view.addresses["ns.parent.net."] = ["8.8.4.4", "8.8.8.8"]
        world.overrides[("example.com.", "NS", "8.8.4.4")] = d.QueryError("dns_transport_failed")
        response = view.authoritative("example.com", "NS", "ns.parent.net.")
        self.assertEqual(d._ns(response, "example.com", True), {d.name(server) for server in SERVERS})
        self.assertEqual(len(world.calls), 2)

    def test_dnssec_secure_unsigned_unconfirmed_and_broken(self):
        signed_ds = ("example.com", "DS", ["12345 13 2 " + "ab" * 32])
        signed_key = ("example.com", "DNSKEY", ["257 3 13 YWJjZA=="])
        for ds_ad, key_ad, keys, expected in ((True, True, [signed_key], "secure_by_resolver"),
                                            (False, True, [signed_key], None),
                                            (True, False, [signed_key], None),
                                            (True, True, [], None)):
            view = Mock(resolver="google")
            view.query.side_effect = [message("example.com", "DS", answer=[signed_ds], ad=ds_ad),
                                      message("example.com", "DNSKEY", answer=keys, ad=key_ad)]
            if expected:
                self.assertEqual(d.dnssec(view, "example.com")["evidence"], expected)
            else:
                with self.assertRaisesRegex(d.QueryError, "dnssec_chain_not_authenticated"):
                    d.dnssec(view, "example.com")
        view = Mock(resolver="google")
        view.query.side_effect = [message("example.com", "DS", authority=[soa("com")]), message("example.com", "DNSKEY", authority=[soa()])]
        result = d.dnssec(view, "example.com")
        self.assertEqual(result["evidence"], "not_authenticated")
        self.assertFalse(result["local_validation"])
        view.query.side_effect = [message("example.com", "DS", ad=True), message("example.com", "DNSKEY")]
        with self.assertRaisesRegex(d.QueryError, "dns_zone_cut_unknown"):
            d.dnssec(view, "example.com")
        for bad_kind in ("DS", "DNSKEY"):
            view.query.side_effect = [message("example.com", "DS", rcode=3 if bad_kind == "DS" else 0),
                                      message("example.com", "DNSKEY", rcode=3 if bad_kind == "DNSKEY" else 0)]
            with self.assertRaisesRegex(d.QueryError, "dnssec_zone_not_found"):
                d.dnssec(view, "example.com")

    def test_dnssec_denial_must_come_from_parent_and_answer_must_match(self):
        signature = "DS 13 2 60 20300101000000 20200101000000 1 example.com. YWJjZA=="
        for response, expected in (
            (message("example.com", "DS", authority=[soa()], ad=True), "dnssec_parent_denial_unproven"),
            (message("example.com", "DS", answer=[("example.com", "RRSIG", [signature])], authority=[soa("com")], ad=True), "dnssec_parent_denial_unproven"),
            (message("example.com", "DS", answer=[("elsewhere.com", "DS", ["1 13 2 " + "ab" * 32])]), "dnssec_unexpected_answer"),
            (message("example.com", "DS", answer=[("example.com", "A", ["1.1.1.1"])]), "dnssec_unexpected_answer"),
            (message("example.com", "DS", answer=[("example.com", "RRSIG", [signature.replace("DS ", "A ", 1)])]), "dnssec_unexpected_answer"),
        ):
            view = Mock(resolver="google")
            view.query.side_effect = [response, message("example.com", "DNSKEY", authority=[soa()])]
            with self.subTest(expected=expected), self.assertRaisesRegex(d.QueryError, expected):
                d.dnssec(view, "example.com")

    def test_provider_unavailable_invalid_and_empty_names_fail_before_network(self):
        for updates, zones, reason in (({"unavailable": ["other.com"]}, ZONES, "cloudflare_identifiers_unavailable"),
                                       ({"names": ["EXAMPLE.COM"]}, ZONES, "invalid_certificate_identifier"),
                                       ({"names": ["*.other.com"]}, ZONES, "cloudflare_zone_unavailable"),
                                       ({"names": []}, ZONES, "no_certificate_identifiers"),
                                       ({"names": ["bad"]}, ZONES, "invalid_certificate_identifier")):
            with self.subTest(reason=reason), patch.object(d.dnsquery, "Client") as client:
                result = d.inspect(dict(DOMAIN, **updates), zones, {"dns_preflight": False})
            self.assertFalse(result["preflight_enabled"])
            self.assertEqual(result["reason"], reason)
            client.assert_not_called()

    def test_caa_denial_and_transport_error_stop_readiness(self):
        world = World()
        world.overrides[("example.com.", "CAA", "cloudflare")] = message("example.com", "CAA", answer=[("example.com", "CAA", ['0 issue "other.org"'])])
        with patch.object(d.dnsquery, "Client", return_value=world):
            self.assertEqual(d.inspect(DOMAIN, ZONES)["reason"], "caa_denied")
        world.overrides[("com.", "SOA", "cloudflare")] = d.QueryError("dns_rcode_servfail", [6])
        with patch.object(d.dnsquery, "Client", return_value=world):
            result = d.inspect(DOMAIN, ZONES)
        self.assertEqual(result["checks"][-1]["ede_codes"], [6])

    def test_diagnostic_discovery_filter_and_gate(self):
        with patch.object(d.core, "zones", return_value=ZONES), patch.object(d.core, "discover", return_value=[DOMAIN]), patch.object(d, "inspect", return_value={"ready": True}) as inspect:
            self.assertEqual(d.reports({}, "example.com"), [{"ready": True}])
            self.assertEqual(d.reports({}), [{"ready": True}])
            with self.assertRaisesRegex(core.Error, "domain not found"):
                d.reports({}, "missing.com")
            inspect.assert_any_call(DOMAIN, ZONES, {})
        with patch.object(d, "inspect", return_value={"ready": True}):
            self.assertIsNone(d.require_ready(DOMAIN, ZONES))
        with patch.object(d, "inspect", return_value={"ready": False, "reason": "caa_denied"}), self.assertRaisesRegex(core.Error, "DNS preflight blocked: caa_denied"):
            d.require_ready(DOMAIN, ZONES)

    def test_txt_chunks_membership_and_wrong_owners(self):
        response = message("_acme-challenge.example.com", "TXT", answer=[("_acme-challenge.example.com", "TXT", ['"tok" "en"', '"wild"']), ("other.com", "TXT", ['"wrong"'])], aa=True)
        self.assertEqual(d._txt(response, "_acme-challenge.example.com", True), {b"token", b"wild"})
        response.flags &= ~dns.flags.AA
        with self.assertRaisesRegex(d.QueryError, "txt_not_authoritative"):
            d._txt(response, "_acme-challenge.example.com", True)
        response.set_rcode(dns.rcode.NXDOMAIN)
        self.assertEqual(d._txt(response, "_acme-challenge.example.com"), set())

    def test_poll_requires_two_fresh_complete_passes_for_both_values_every_observer(self):
        world = World()
        with patch.object(d.dnsquery, "Client", return_value=world), patch.object(d.dnsquery.time, "monotonic", return_value=0), patch.object(d.time, "sleep") as sleep:
            d.wait_for_txt([("example.com", "token"), ("*.example.com", "wild")], ZONES)
        sleep.assert_called_once_with(5)
        for observer in ("cloudflare", "google", "1.1.1.1", "1.0.0.1"):
            self.assertGreaterEqual(world.calls.count(("_acme-challenge.example.com.", "TXT", observer)), 2)

    def test_poll_resets_success_after_stale_view_and_keeps_other_txt(self):
        world = World()
        passes = []
        def sleep(seconds):
            passes.append(seconds)
            # Passes: successful, stale, successful, successful.
            world.txt = ['"wrong"'] if len(passes) == 1 else ['"token"', '"wild"', '"other"']
        with patch.object(d.dnsquery, "Client", return_value=world), patch.object(d.dnsquery.time, "monotonic", return_value=0), patch.object(d.time, "sleep", side_effect=sleep):
            d.wait_for_txt([("example.com", "token")], ZONES)
        self.assertEqual(passes, [5, 5, 5])

    def test_poll_timeout_and_errors_do_not_become_empty_success(self):
        world = World()
        world.deadline = 6
        world.overrides[("_acme-challenge.example.com.", "TXT", "cloudflare")] = d.QueryError("dns_rcode_servfail", [6])
        ticks = [0]
        def sleep(seconds):
            ticks[0] += seconds
        with patch.object(d.dnsquery, "Client", return_value=world), patch.object(d.dnsquery.time, "monotonic", side_effect=lambda: ticks[0]), patch.object(d.time, "sleep", side_effect=sleep), self.assertRaisesRegex(d.QueryError, "dns_timeout"):
            d.wait_for_txt([("example.com", "token")], ZONES)
        self.assertEqual(ticks[0], 6)
        self.assertNotIn("token", str(world.calls))

    def test_poll_rejects_invalid_values_and_missing_provider_nameservers(self):
        for value in ("", None, "неascii"):
            with self.assertRaisesRegex(d.QueryError, "invalid_challenge_value"):
                d.wait_for_txt([("example.com", value)], ZONES)
        with patch.object(d.dnsquery, "Client", return_value=World()), self.assertRaisesRegex(d.QueryError, "provider_nameservers_unknown"):
            d.wait_for_txt([("example.com", "token")], {"example.com": {"ns": []}})


if __name__ == "__main__":
    unittest.main()
