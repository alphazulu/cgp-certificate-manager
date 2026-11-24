"""CAA preflight tests use synthetic DNS messages and never perform I/O."""
import unittest
from unittest.mock import patch

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from cgp_cert_manager import caa, core


DOMAIN = "mail.example.test."
ALLOW = '0 issue "letsencrypt.org"'


def rr(owner, kind, *values, rdclass="IN"):
    return dns.rrset.from_text(owner, 60, rdclass, kind, *values)


def reply(name=DOMAIN, answer=(), authority=None, ad=True, status="NOERROR"):
    result = dns.message.make_response(dns.message.make_query(name, "CAA"))
    result.flags |= dns.flags.RA
    if ad:
        result.flags |= dns.flags.AD
    result.set_rcode(dns.rcode.from_text(status))
    result.answer = list(answer)
    if authority is None:
        authority = [] if answer else [soa(dns.name.from_text(name).parent().to_text())]
    result.authority = list(authority)
    return result


def soa(owner="example.test."):
    return rr(owner, "SOA", "ns.example.test. hostmaster.example.test. 1 60 60 60 60")


class CAATests(unittest.TestCase):
    def setUp(self):
        self.responses = {}
        self.calls = []

    def query(self, name, kind):
        self.calls.append((name, kind))
        self.assertEqual(kind, "CAA")
        value = self.responses.get(name, reply(name))
        if isinstance(value, Exception):
            raise value
        return value

    def policy(self, *values, wildcard=False, account_uri=None):
        self.responses[DOMAIN] = reply(answer=[rr(DOMAIN, "CAA", *values)])
        return caa.check(("*." if wildcard else "") + DOMAIN, self.query, account_uri)

    def test_allow_report_and_case_normalized_identifier(self):
        self.responses[DOMAIN] = reply(answer=[rr(DOMAIN.upper(), "CAA", ALLOW)])
        result = caa.check("MAIL.Example.TEST", self.query)
        self.assertEqual(result, {
            "decision": "allowed", "reason": "issuer_authorized",
            "lookup_name": DOMAIN, "rrset_owner": DOMAIN, "alias_chain": [],
            "dnssec": "secure_by_resolver",
        })
        self.assertEqual(self.calls, [(DOMAIN, "CAA")])

    def test_parent_walk_to_tld_but_not_root(self):
        self.responses["example.test."] = reply("example.test.", ad=False)
        result = caa.check(DOMAIN, self.query)
        self.assertEqual(result["decision"], "not_restricted")
        self.assertEqual(result["reason"], "no_caa")
        self.assertIsNone(result["lookup_name"])
        self.assertIsNone(result["rrset_owner"])
        self.assertEqual(result["dnssec"], "not_authenticated")
        self.assertEqual([name for name, _ in self.calls], [DOMAIN, "example.test.", "test."])

    def test_parent_policy_and_any_closest_rrset_stops_walk(self):
        self.responses[DOMAIN] = reply(status="NXDOMAIN")
        self.responses["example.test."] = reply("example.test.", [rr("example.test.", "CAA", ALLOW)])
        result = caa.check(DOMAIN, self.query)
        self.assertEqual(result["lookup_name"], "example.test.")
        self.assertEqual(result["rrset_owner"], "example.test.")
        self.assertEqual(result["decision"], "allowed")
        self.calls.clear()
        self.responses[DOMAIN] = reply(answer=[rr(DOMAIN, "CAA", '0 iodef "mailto:ops@example.test"')])
        result = caa.check(DOMAIN, self.query)
        self.assertEqual(result["reason"], "no_applicable_policy")
        self.assertEqual(len(self.calls), 1)

    def test_wildcard_precedence_and_case_insensitive_property_tags(self):
        cases = [
            ((ALLOW,), True, "allowed"),
            ((ALLOW, '0 issuewild ";"'), True, "denied"),
            (('0 issue ";"', '0 ISSUEWILD "letsencrypt.org"'), True, "allowed"),
            ((ALLOW, '0 issuewild "malformed %%%"'), True, "denied"),
            (('0 issuewild ";"',), False, "not_restricted"),
            (('0 issuewild "letsencrypt.org"', '0 issue ";"'), False, "denied"),
            (('0 IsSuE "letsencrypt.org"',), False, "allowed"),
        ]
        for values, wildcard, decision in cases:
            with self.subTest(values=values, wildcard=wildcard):
                self.assertEqual(self.policy(*values, wildcard=wildcard)["decision"], decision)

    def test_critical_flags_and_known_non_tls_properties(self):
        for flag in (1, 128, 129, 255):
            with self.subTest(flag=flag):
                self.assertEqual(self.policy(ALLOW, f'{flag} future "value"')["reason"],
                                 "unknown_critical_property")
        for flag in (0, 2, 4, 64, 126):
            with self.subTest(flag=flag):
                self.assertEqual(self.policy(ALLOW, f'{flag} future "value"')["decision"], "allowed")
        for tag in ("iodef", "issuemail", "issuevmc"):
            with self.subTest(tag=tag):
                self.assertEqual(self.policy(f'128 {tag} "irrelevant"')["decision"], "not_restricted")

    def test_empty_and_malformed_grants_are_additive(self):
        for value in ("", ";", "%%%%%", "other.test", "letsencrypt.org.",
                      "LETSENCRYPT.ORG", "letsencrypt.org; bad", "letsencrypt.org;;"):
            with self.subTest(value=value):
                record = f'0 issue "{value}"'
                self.assertEqual(self.policy(record)["decision"], "denied")
                self.assertEqual(self.policy(record, ALLOW)["decision"], "allowed")

    def test_parameters_whitespace_and_dns01_method(self):
        permitted = ["letsencrypt.org;", "  letsencrypt.org  ;  ",
                     "letsencrypt.org; validationmethods=dns-01",
                     "letsencrypt.org; validationmethods=http-01,dns-01,tls-alpn-01",
                     "letsencrypt.org; validationmethods=ca-new,dns-01"]
        rejected = ["letsencrypt.org; validationmethods=", "letsencrypt.org; validationmethods=http-01",
                    "letsencrypt.org; validationmethods=DNS-01", "letsencrypt.org; validationmethods=dns-01,",
                    "letsencrypt.org; validationmethods=dns-01, bad", "letsencrypt.org; validationmethods=dns-01,,x",
                    "letsencrypt.org; validationmethods=dns-01; validationmethods=dns-01",
                    "letsencrypt.org; -bad=value", "letsencrypt.org; bad-=value",
                    "letsencrypt.org; bad_tag=value", "letsencrypt.org; bad=with space",
                    "letsencrypt.org; validationmethods=dns-01;", "letsencrypt.org; validationmethods=dns-01,%%"]
        for value in permitted + rejected:
            with self.subTest(value=value):
                self.assertEqual(self.policy(f'0 issue "{value}"')["decision"],
                                 "allowed" if value in permitted else "denied")
        # A wire octet need not be valid ASCII even when the DNS RR is well formed.
        self.assertEqual(self.policy('0 issue "letsencrypt.org\\255"')["decision"], "denied")

    def test_account_uri_is_exact_and_never_guessed(self):
        uri = "https://acme-v02.api.letsencrypt.org/acme/acct/12"
        record = f'0 issue "letsencrypt.org;accounturi={uri};validationmethods=dns-01"'
        self.assertEqual(self.policy(record)["reason"], "account_unknown")
        self.assertEqual(self.policy(record, account_uri=uri)["decision"], "allowed")
        for other in (uri + "3", uri.replace("acme-v02.", "acme-staging-v02.")):
            self.assertEqual(self.policy(record, account_uri=other)["decision"], "denied")
        self.assertEqual(self.policy(record, ALLOW)["decision"], "allowed")
        for value in ("", "relative", "https:", "https://[broken", uri + ";accounturi=" + uri):
            with self.subTest(value=value):
                self.assertEqual(self.policy(f'0 issue "letsencrypt.org;accounturi={value}"')["decision"], "denied")
        self.assertEqual(self.policy('0 issue "letsencrypt.org;accounturi=urn:account:12"')["reason"], "account_unknown")

    def test_unknown_parameters_do_not_grant_or_override_known_mismatch(self):
        for parameter in ("future=a=b", "ACCOUNTURI=https://ca.test/1", "Validationmethods=dns-01"):
            with self.subTest(parameter=parameter):
                value = f'0 issue "letsencrypt.org;{parameter}"'
                self.assertEqual(self.policy(value)["reason"], "unsupported_parameter")
                self.assertEqual(self.policy(value, ALLOW)["decision"], "allowed")
                denied = f'0 issue "letsencrypt.org;{parameter};validationmethods=http-01"'
                self.assertEqual(self.policy(denied)["decision"], "denied")
        records = ('0 issue "letsencrypt.org;future=x"',
                   '0 issue "letsencrypt.org;accounturi=https://ca.test/1"')
        self.assertEqual(self.policy(*records)["reason"], self.policy(*reversed(records))["reason"])

    def test_aliases_in_one_response_are_bound_to_the_final_owner(self):
        self.responses[DOMAIN] = reply(answer=[
            rr(DOMAIN, "CNAME", "FIRST.other.test."),
            rr("first.other.test.", "CNAME", "final._caa.other.test."),
            rr("final._caa.other.test.", "CAA", ALLOW),
        ])
        result = caa.check(DOMAIN, self.query)
        self.assertEqual(result["decision"], "allowed")
        self.assertEqual(result["lookup_name"], DOMAIN)
        self.assertEqual(result["rrset_owner"], "final._caa.other.test.")
        self.assertEqual(result["alias_chain"], [
            {"from": DOMAIN, "to": "first.other.test.", "type": "CNAME"},
            {"from": "first.other.test.", "to": "final._caa.other.test.", "type": "CNAME"},
        ])
        self.assertEqual(len(self.calls), 1)

    def test_alias_only_reply_queries_target_then_original_parent(self):
        target = "target.other.test."
        self.responses[DOMAIN] = reply(answer=[rr(DOMAIN, "CNAME", target)])
        self.responses[target] = reply(target, ad=False)
        self.responses["other.test."] = reply("other.test.", [rr("other.test.", "CAA", '0 issue ";"')])
        self.responses["example.test."] = reply("example.test.", [rr("example.test.", "CAA", ALLOW)])
        result = caa.check(DOMAIN, self.query)
        self.assertEqual(result["decision"], "allowed")
        self.assertEqual(result["dnssec"], "not_authenticated")
        self.assertEqual([name for name, _ in self.calls], [DOMAIN, target, "example.test."])

    def test_negative_alias_answer_still_walks_original_parents(self):
        target = "target.other.test."
        for status, authority in (("NXDOMAIN", [soa("other.test.")]), ("NOERROR", [soa("other.test.")])):
            with self.subTest(status=status):
                self.calls.clear()
                self.responses[DOMAIN] = reply(answer=[rr(DOMAIN, "CNAME", target)],
                                               status=status, authority=authority)
                result = caa.check(DOMAIN, self.query)
                self.assertEqual(result["reason"], "no_caa")
                self.assertEqual([name for name, _ in self.calls], [DOMAIN, "example.test.", "test."])

    def test_dname_substitution_and_matching_synthesized_cname(self):
        for synthetic in ([], [rr(DOMAIN, "CNAME", "mail.other.test.")]):
            with self.subTest(synthetic=bool(synthetic)):
                self.responses[DOMAIN] = reply(answer=[rr("example.test.", "DNAME", "other.test.")]
                                               + synthetic + [rr("mail.other.test.", "CAA", ALLOW)])
                result = caa.check(DOMAIN, self.query)
                self.assertEqual(result["decision"], "allowed")
                self.assertEqual(result["alias_chain"], [
                    {"from": DOMAIN, "to": "mail.other.test.", "type": "DNAME"}])

    def test_dname_inconsistent_multiple_or_overflow_refuses(self):
        huge = ".".join(["a" * 63] * 3 + ["b" * 60]) + "."
        cases = [
            [rr("example.test.", "DNAME", "other.test."), rr(DOMAIN, "CNAME", "wrong.test.")],
            [rr("example.test.", "DNAME", "one.test."), rr("example.test.", "DNAME", "two.test.")],
            [rr("example.test.", "DNAME", "other.test."), rr("test.", "DNAME", "another.")],
            [rr("example.test.", "DNAME", huge)],
            [rr(DOMAIN, "DNAME", "other.test.")],
        ]
        for answer in cases:
            with self.subTest(answer=answer):
                self.responses[DOMAIN] = reply(answer=answer)
                self.assertEqual(caa.check(DOMAIN, self.query)["reason"], "invalid_response")

    def test_alias_cycles_and_budgets_fail_closed(self):
        self.responses[DOMAIN] = reply(answer=[rr(DOMAIN, "CNAME", DOMAIN)])
        self.assertEqual(caa.check(DOMAIN, self.query)["reason"], "alias_loop")
        self.responses[DOMAIN] = reply(answer=[rr(DOMAIN, "CNAME", "next.test.")])
        self.responses["next.test."] = reply("next.test.", [rr("next.test.", "CNAME", DOMAIN)])
        self.assertEqual(caa.check(DOMAIN, self.query)["reason"], "alias_loop")
        self.responses["next.test."] = reply("next.test.", [rr("next.test.", "CNAME", "third.test.")])
        with patch.object(caa, "MAX_ALIASES", 1):
            result = caa.check(DOMAIN, self.query)
        self.assertEqual(result["reason"], "alias_limit")
        self.assertEqual(result["dnssec"], "not_authenticated")
        self.responses.clear()
        with patch.object(caa, "MAX_QUERIES", 1):
            self.assertEqual(caa.check(DOMAIN, self.query)["reason"], "lookup_limit")

    def test_unrelated_or_contradictory_answer_never_grants_permission(self):
        empty = dns.rrset.RRset(dns.name.from_text(DOMAIN), dns.rdataclass.IN, dns.rdatatype.CAA)
        cases = [
            [rr("unrelated.test.", "CAA", ALLOW)],
            [rr(DOMAIN, "CAA", ALLOW), rr("unrelated.test.", "CNAME", "elsewhere.test.")],
            [rr(DOMAIN, "CAA", ALLOW), rr(DOMAIN, "CNAME", "alias.test.")],
            [rr(DOMAIN, "CAA", ALLOW), rr("example.test.", "DNAME", "other.test.")],
            [rr(DOMAIN, "CAA", ALLOW), rr(DOMAIN, "CAA", '0 iodef "x"')],
            [rr(DOMAIN, "CNAME", "one.test."), rr(DOMAIN, "CNAME", "two.test.")],
            [rr(DOMAIN, "TXT", '"letsencrypt.org"')],
            [rr(DOMAIN, "CAA", ALLOW, rdclass="CH")],
            [empty],
        ]
        for answer in cases:
            with self.subTest(answer=answer):
                self.responses[DOMAIN] = reply(answer=answer)
                self.assertEqual(caa.check(DOMAIN, self.query)["reason"], "invalid_response")
        self.responses[DOMAIN] = reply(answer=[rr(DOMAIN, "CAA", ALLOW)], status="NXDOMAIN")
        self.assertEqual(caa.check(DOMAIN, self.query)["reason"], "invalid_response")

    def test_bad_alias_names_are_not_reported(self):
        for target in (".", "bad\\032name.test."):
            with self.subTest(target=target):
                self.responses[DOMAIN] = reply(answer=[rr(DOMAIN, "CNAME", target)])
                result = caa.check(DOMAIN, self.query)
                self.assertEqual(result["reason"], "invalid_response")
                self.assertEqual(result["alias_chain"], [])
        relative = rr(DOMAIN, "CAA", ALLOW)
        relative.name = dns.name.from_text("relative", origin=None)
        self.responses[DOMAIN] = reply(answer=[relative])
        self.assertEqual(caa.check(DOMAIN, self.query)["reason"], "invalid_response")

    def test_referral_and_unrelated_negative_soa_are_not_absence(self):
        self.responses[DOMAIN] = reply(authority=[rr("example.test.", "NS", "ns.example.test.")])
        self.assertEqual(caa.check(DOMAIN, self.query)["reason"], "incomplete_referral")
        self.responses[DOMAIN] = reply(authority=[soa("unrelated.test.")])
        self.assertEqual(caa.check(DOMAIN, self.query)["reason"], "invalid_response")
        self.responses[DOMAIN] = reply(authority=[soa(), soa("test.")])
        self.assertEqual(caa.check(DOMAIN, self.query)["reason"], "invalid_response")
        wrong_class = soa()
        wrong_class.rdclass = dns.rdataclass.CH
        self.responses[DOMAIN] = reply(authority=[wrong_class])
        self.assertEqual(caa.check(DOMAIN, self.query)["reason"], "invalid_response")
        self.responses[DOMAIN] = reply(authority=[soa(), rr("example.test.", "NS", "ns.example.test."),
                                               rr(DOMAIN, "CAA", '0 issue ";"')])
        self.assertEqual(caa.check(DOMAIN, self.query)["reason"], "no_caa")

    def test_negative_without_zone_evidence_is_indeterminate(self):
        for status in ("NOERROR", "NXDOMAIN"):
            with self.subTest(status=status):
                self.responses[DOMAIN] = reply(authority=[], status=status)
                result = caa.check(DOMAIN, self.query)
                self.assertEqual(result["reason"], "incomplete_negative_response")
                self.assertEqual(result["dnssec"], "not_authenticated")
        self.responses[DOMAIN] = reply(answer=[rr(DOMAIN, "CNAME", "target.test.")],
                                       authority=[], status="NXDOMAIN")
        self.assertEqual(caa.check(DOMAIN, self.query)["reason"], "incomplete_negative_response")

    def test_rrsig_is_not_mistaken_for_caa_or_local_validation(self):
        signature = rr(DOMAIN, "RRSIG", "CAA 8 3 60 20301101000000 20201101000000 1 example.test. YQ==")
        self.responses[DOMAIN] = reply(answer=[signature, rr(DOMAIN, "CAA", ALLOW)], ad=False)
        result = caa.check(DOMAIN, self.query)
        self.assertEqual(result["decision"], "allowed")
        self.assertEqual(result["dnssec"], "not_authenticated")

    def test_record_budget_and_transport_errors_are_safe(self):
        with patch.object(caa, "MAX_CAA_RECORDS", 1):
            self.assertEqual(self.policy(ALLOW, '0 iodef "ops"')["reason"], "record_limit")
        self.responses[DOMAIN] = core.Error("PRIVATE_SECRET\nspoofed-success")
        result = caa.check(DOMAIN, self.query)
        self.assertEqual(result["reason"], "lookup_failed")
        self.assertEqual(result["dnssec"], "not_authenticated")
        self.assertNotIn("PRIVATE_SECRET", str(result))

    def test_invalid_identifiers_do_not_query(self):
        for name in (None, 42, "", "localhost", "192.0.2.1", "bad..example.test", "a/b.test", "*.*.example.test"):
            with self.subTest(name=name):
                result = caa.check(name, self.query)
                self.assertEqual(result["reason"], "invalid_identifier")
                self.assertEqual(result["dnssec"], "not_authenticated")
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
