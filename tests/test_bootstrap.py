"""Read-only bootstrap diagnostics use synthetic, non-certificate secrets."""

import base64
import itertools
import json
import subprocess
import unittest
from unittest.mock import call, patch

from cgp_cert_manager import bootstrap, cgpdata, core, storage


def block(text):
    return "[" + base64.b64encode(text.encode()).decode() + "]"


def dictionary(values, extra=""):
    return "{" + "".join(name + "=" + value + ";"
                         for name, value in values.items()) + extra + "}"


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.domain = "example.test"
        self.secret = "SYNTHETIC_PRIVATE_MATERIAL_NEVER_DISPLAY"
        self.cfg = {"communigate": {
            "url": "http://127.0.0.1:8100/CLI/",
            "username": "test-admin", "password": "SYNTHETIC_PASSWORD"}}
        self.fields = {
            "PrivateSecureKey": block(self.secret),
            "SecureCertificate": block("synthetic expired certificate"),
            "CAChain": block("synthetic chain"),
            "CertificateType": "YES",
        }
        # A diagnostic must not accidentally reach storage, locks, issuance,
        # DNS, TLS, notifications through discovery, or any subprocess.
        for module, names in (
                (core, ("cf", "run", "issue", "update", "backup", "atomic", "array",
                        "discover", "cert_info", "probe_tls", "verify_tls")),
                (storage, ("operation_lock", "atomic_json", "atomic_text",
                           "open_private", "read_text", "validate_tree")),
                (subprocess, ("run",))):
            for name in names:
                mock = self.enterContext(patch.object(
                    module, name, side_effect=AssertionError("Unexpected side effect")))
                self.addCleanup(mock.assert_not_called)

    def inspect_values(self, explicit, effective):
        values = [dictionary(explicit), dictionary(effective)] * 2
        return self.inspect_responses(values)

    def inspect_responses(self, responses):
        with patch.object(core, "cli", side_effect=responses) as cli:
            result = bootstrap.inspect(self.cfg, self.domain)
        expected = [call(self.cfg, command + " " + self.domain) for command in
                    ("GETDOMAINSETTINGS", "GETDOMAINEFFECTIVESETTINGS") * 2]
        self.assertEqual(cli.call_args_list, expected[:cli.call_count])
        self.assertFalse(result.report["automatic_bootstrap"])
        self.assertNotIn(self.secret, repr(result))
        self.assertNotIn(self.fields["PrivateSecureKey"], repr(result))
        return result

    def assert_unknown(self, result, status, reason):
        self.assertEqual(result.report["response_status"], status)
        self.assertEqual(result.report["blocking_reason"], reason)
        self.assertEqual(result.report["origin"], dict.fromkeys(core.FIELDS, "unknown"))
        self.assertIsNone(result.report["missing_explicit_fields"])
        self.assertIsNone(result.report["missing_effective_fields"])
        self.assertEqual(result.report["unreadable_fields"], [])
        self.assertEqual(result.report["empty_fields"], [])
        self.assertFalse(result.report["snapshot_complete"])
        self.assertFalse(result.report["explicit_snapshot_complete"])
        self.assertFalse(result.report["deployment_ready"])
        self.assertEqual(result.settings, {})

    def test_complete_explicit_snapshot_has_only_fixed_public_keys(self):
        result = self.inspect_values(self.fields, self.fields)
        self.assertEqual(result.settings, self.fields)
        self.assertEqual(set(result.report), {
            "domain", "response_status", "origin", "missing_explicit_fields",
            "missing_effective_fields", "unreadable_fields", "empty_fields",
            "snapshot_complete", "explicit_snapshot_complete", "deployment_ready",
            "automatic_bootstrap", "blocking_reason"})
        self.assertEqual(result.report["domain"], self.domain)
        self.assertEqual(result.report["response_status"], "ok")
        self.assertEqual(result.report["origin"], dict.fromkeys(core.FIELDS, "explicit"))
        for name in ("missing_explicit_fields", "missing_effective_fields",
                     "unreadable_fields", "empty_fields"):
            self.assertEqual(result.report[name], [])
        self.assertTrue(result.report["snapshot_complete"])
        self.assertTrue(result.report["explicit_snapshot_complete"])
        self.assertTrue(result.report["deployment_ready"])
        self.assertIsNone(result.report["blocking_reason"])
        self.assertNotIn("settings", json.dumps(result.report))

    def test_all_explicit_and_effective_absence_combinations(self):
        for raw_mask, effective_mask in itertools.product(range(16), repeat=2):
            with self.subTest(explicit=raw_mask, effective=effective_mask):
                explicit = {name: self.fields[name] for index, name in enumerate(core.FIELDS)
                            if raw_mask & (1 << index)}
                effective = {name: self.fields[name] for index, name in enumerate(core.FIELDS)
                             if effective_mask & (1 << index)}
                result = self.inspect_values(explicit, effective)
                origin = {
                    name: ("explicit" if name in effective else "inconsistent")
                    if name in explicit else
                    ("effective_only" if name in effective else "absent")
                    for name in core.FIELDS}
                missing_raw = [name for name in core.FIELDS if name not in explicit]
                missing_effective = [name for name in core.FIELDS if name not in effective]
                self.assertEqual(result.report["origin"], origin)
                self.assertEqual(result.report["missing_explicit_fields"], missing_raw)
                self.assertEqual(result.report["missing_effective_fields"], missing_effective)
                self.assertEqual(result.report["snapshot_complete"], effective_mask == 15)
                self.assertEqual(result.report["explicit_snapshot_complete"], raw_mask == 15)
                self.assertEqual(result.report["deployment_ready"], raw_mask == effective_mask == 15)
                self.assertEqual(result.settings, effective)
                if "inconsistent" in origin.values():
                    expected_reason = "inconsistent"
                elif missing_effective:
                    expected_reason = "missing_effective_fields"
                elif missing_raw:
                    expected_reason = "missing_explicit_fields"
                else:
                    expected_reason = None
                self.assertEqual(result.report["blocking_reason"], expected_reason)

    def test_explicit_effective_disagreement_is_not_ready(self):
        for name in core.FIELDS:
            effective = dict(self.fields)
            effective[name] = "NO" if name == "CertificateType" else block("other value")
            with self.subTest(field=name):
                result = self.inspect_values(self.fields, effective)
                self.assertTrue(result.report["snapshot_complete"])
                self.assertTrue(result.report["explicit_snapshot_complete"])
                self.assertFalse(result.report["deployment_ready"])
                self.assertEqual(result.report["origin"][name], "inconsistent")
                self.assertEqual(result.report["blocking_reason"], "inconsistent")

    def test_matching_text_in_different_types_is_inconsistent(self):
        effective = dict(self.fields, PrivateSecureKey='"' + self.fields["PrivateSecureKey"][1:-1] + '"')
        result = self.inspect_values(self.fields, effective)
        self.assertEqual(result.report["origin"]["PrivateSecureKey"], "inconsistent")
        self.assertEqual(result.report["unreadable_fields"], ["PrivateSecureKey"])
        self.assertEqual(result.report["blocking_reason"], "inconsistent")

    def test_empty_datablock_is_distinct_from_missing(self):
        for name in core.FIELDS[:3]:
            values = dict(self.fields, **{name: "[]"})
            with self.subTest(field=name):
                result = self.inspect_values(values, values)
                self.assertEqual(result.report["origin"][name], "explicit")
                self.assertEqual(result.report["missing_explicit_fields"], [])
                self.assertEqual(result.report["missing_effective_fields"], [])
                self.assertEqual(result.report["unreadable_fields"], [])
                self.assertEqual(result.report["empty_fields"], [name])
                self.assertEqual(result.settings[name], "[]")
                self.assertFalse(result.report["snapshot_complete"])
                self.assertFalse(result.report["explicit_snapshot_complete"])
                self.assertEqual(result.report["blocking_reason"], "empty_fields")

    def test_empty_certificate_type_is_empty_but_not_capturable(self):
        values = dict(self.fields, CertificateType='""')
        result = self.inspect_values(values, values)
        self.assertEqual(result.report["empty_fields"], ["CertificateType"])
        self.assertEqual(result.report["unreadable_fields"], [])
        self.assertNotIn("CertificateType", result.settings)
        self.assertEqual(result.report["blocking_reason"], "empty_fields")

    def test_empty_and_unreadable_fields_have_fixed_field_order(self):
        values = {"CertificateType": "#NULL#", "CAChain": "[]",
                  "SecureCertificate": "#17", "PrivateSecureKey": "[]"}
        result = self.inspect_values(values, values)
        self.assertEqual(result.report["empty_fields"], ["PrivateSecureKey", "CAChain"])
        self.assertEqual(result.report["unreadable_fields"], ["SecureCertificate", "CertificateType"])
        self.assertEqual(result.report["blocking_reason"], "unreadable_fields")

    def test_unsupported_typed_values_are_present_and_never_disclosed(self):
        unsupported = ('"' + self.secret + '"', "(" + self.secret + ")",
                       "{Nested=" + self.secret + ";}", "#NULL#", "#17")
        for name, value in itertools.product(core.FIELDS[:3], unsupported):
            with self.subTest(field=name, kind=value[:1]):
                values = dict(self.fields, **{name: value})
                result = self.inspect_values(values, values)
                self.assertEqual(result.report["origin"][name], "explicit")
                self.assertEqual(result.report["unreadable_fields"], [name])
                self.assertEqual(result.report["missing_effective_fields"], [])
                self.assertEqual(result.report["empty_fields"], [])
                self.assertNotIn(name, result.settings)
                self.assertEqual(result.report["blocking_reason"], "unreadable_fields")
                self.assertFalse(result.report["snapshot_complete"])

    def test_bad_padding_and_noncanonical_base64_are_unreadable(self):
        for bad in ("[A]", "[A===]", "[YQ=]", "[YQ===]", "[YQ==Yg==]", "[YR==]"):
            values = dict(self.fields, PrivateSecureKey=bad)
            with self.subTest(value=bad):
                result = self.inspect_values(values, values)
                self.assertEqual(result.report["response_status"], "ok")
                self.assertEqual(result.report["unreadable_fields"], ["PrivateSecureKey"])
                self.assertEqual(result.report["blocking_reason"], "unreadable_fields")

    def test_certificate_type_has_no_implicit_enable_or_expiry_validation(self):
        for mode in ("YES", "yes", "NO", "Disabled", "Test", "Test_v2-1", '"YES"', '"yes"'):
            values = dict(self.fields, CertificateType=mode)
            with self.subTest(mode=mode):
                result = self.inspect_values(values, values)
                self.assertTrue(result.report["deployment_ready"])
                self.assertEqual(result.settings["CertificateType"], mode.strip('"'))
                # The synthetic material is not even a real certificate.  This
                # intentionally proves readiness does not attempt cryptography.
                self.assertEqual(result.settings["SecureCertificate"], self.fields["SecureCertificate"])

    def test_certificate_type_rejects_default_and_unsafe_values(self):
        for mode in ("default", '"DEFAULT"', r'"de\102ault"', '"has space"',
                     '"secret; ADMIN_COMMAND"', r'"line\nvalue"', '"1YES"',
                     '"_YES"', "#1", "#NULL#", "(YES)", "{Mode=YES;}", "[WUVT]"):
            values = dict(self.fields, CertificateType=mode)
            with self.subTest(mode=mode):
                result = self.inspect_values(values, values)
                self.assertEqual(result.report["unreadable_fields"], ["CertificateType"])
                self.assertFalse(result.report["deployment_ready"])
                self.assertNotIn("CertificateType", result.settings)

    def test_read_errors_at_any_position_are_generic_and_unknown(self):
        text = dictionary(self.fields)
        for position in range(4):
            for error_type in (core.Error, OSError, ValueError):
                responses = [text] * 4
                responses[position] = error_type(self.secret + " SYNTHETIC_PASSWORD")
                with self.subTest(position=position, error=error_type.__name__):
                    result = self.inspect_responses(responses)
                    self.assert_unknown(result, "unavailable", "response_unavailable")
                    self.assertNotIn("SYNTHETIC_PASSWORD", repr(result))

    def test_interrupt_is_not_converted_to_read_failure(self):
        with patch.object(core, "cli", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                bootstrap.inspect(self.cfg, self.domain)

    def test_invalid_whole_response_does_not_claim_absence(self):
        text = dictionary(self.fields)
        invalid = ("", "()", "#NULL#", "<html>" + self.secret + "</html>",
                   text + self.secret, text[:-1],
                   dictionary(self.fields, "Unrelated={MissingSemicolon=YES};"),
                   dictionary(self.fields, "CertificateType=NO;"),
                   dictionary(dict(self.fields, CAChain="[!!!!]")))
        for response in invalid:
            for position in range(4):
                responses = [text] * 4
                responses[position] = response
                with self.subTest(response=response[:20], position=position):
                    result = self.inspect_responses(responses)
                    self.assert_unknown(result, "invalid_response", "invalid_response")

    def test_certificate_race_in_either_projection_erases_known_origins(self):
        text = dictionary(self.fields)
        for position in range(4):
            responses = [text] * 4
            responses[position] = dictionary(dict(self.fields, CAChain=block("changed")))
            with self.subTest(position=position):
                result = self.inspect_responses(responses)
                self.assert_unknown(result, "changed", "changed")

    def test_unsupported_value_races_are_not_dropped_by_normalization(self):
        before = dict(self.fields, PrivateSecureKey='{Value="' + self.secret + '";}')
        after = dict(before, PrivateSecureKey='("' + self.secret + '")')
        for side in (0, 1):
            responses = [dictionary(before)] * 4
            responses[side + 2] = dictionary(after)
            with self.subTest(side=side):
                self.assert_unknown(self.inspect_responses(responses), "changed", "changed")

    def test_presence_race_is_detected_even_when_effective_values_stay_equal(self):
        inherited = dict(self.fields)
        del inherited["PrivateSecureKey"]
        result = self.inspect_responses([
            dictionary(inherited), dictionary(self.fields),
            dictionary(self.fields), dictionary(self.fields)])
        self.assert_unknown(result, "changed", "changed")

    def test_unrelated_settings_changes_do_not_block_snapshot(self):
        before = dictionary(self.fields, "Unrelated={Nested=(One,{Value=Two;});};")
        after = dictionary(self.fields, "Unrelated=(Three,#NULL#);Other=Four;")
        result = self.inspect_responses([before, before, after, after])
        self.assertTrue(result.report["deployment_ready"])

    def test_equivalent_quoted_and_whitespace_representations_are_stable(self):
        formatted = dict(self.fields, CertificateType='"YES"', CAChain="[\n" + self.fields["CAChain"][1:-1] + "\t ]")
        result = self.inspect_responses([
            dictionary(self.fields), dictionary(formatted),
            dictionary(formatted), dictionary(self.fields)])
        self.assertTrue(result.report["deployment_ready"])
        self.assertEqual(result.settings, self.fields)

    def test_invalid_domain_never_reaches_cli(self):
        for domain in ("", "../example.test", "x;LISTDOMAINS", "x\nexample.test"):
            with self.subTest(domain=domain), patch.object(core, "cli") as cli:
                with self.assertRaisesRegex(core.Error, "Invalid identifier"):
                    bootstrap.inspect(self.cfg, domain)
                cli.assert_not_called()

    def test_require_ready_returns_settings_and_blocks_with_fixed_reason(self):
        with patch.object(core, "cli", return_value=dictionary(self.fields)):
            self.assertEqual(bootstrap.require_ready(self.cfg, self.domain), self.fields)
        with patch.object(core, "cli", side_effect=OSError(self.secret)):
            with self.assertRaises(core.Error) as raised:
                bootstrap.require_ready(self.cfg, self.domain)
        self.assertEqual(str(raised.exception),
                         "Certificate deployment blocked (response_unavailable); "
                         "run --bootstrap-check for diagnostics")
        self.assertNotIn(self.secret, str(raised.exception))

    def test_reports_explicit_domain_skips_discovery(self):
        with patch.object(core, "cli", return_value=dictionary(self.fields)) as cli:
            reports = bootstrap.reports(self.cfg, self.domain)
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0]["domain"], self.domain)
        self.assertTrue(reports[0]["deployment_ready"])
        self.assertNotIn("settings", reports[0])
        self.assertEqual(cli.call_count, 4)
        self.assertNotIn(call(self.cfg, "LISTDOMAINS"), cli.call_args_list)

    def test_reports_discovers_sorted_unique_domains_without_other_discovery(self):
        def respond(cfg, command):
            self.assertIs(cfg, self.cfg)
            return '(z.example, "a.example", z.example)' if command == "LISTDOMAINS" else dictionary(self.fields)
        with patch.object(core, "cli", side_effect=respond) as cli:
            reports = bootstrap.reports(self.cfg)
        self.assertEqual([report["domain"] for report in reports], ["a.example", "z.example"])
        expected = [call(self.cfg, "LISTDOMAINS")]
        for domain in ("a.example", "z.example"):
            expected.extend(call(self.cfg, command + " " + domain) for command in
                            ("GETDOMAINSETTINGS", "GETDOMAINEFFECTIVESETTINGS") * 2)
        self.assertEqual(cli.call_args_list, expected)
        self.assertNotIn(self.fields["PrivateSecureKey"], json.dumps(reports))

    def test_reports_empty_domain_list(self):
        with patch.object(core, "cli", return_value="()") as cli:
            self.assertEqual(bootstrap.reports(self.cfg), [])
        cli.assert_called_once_with(self.cfg, "LISTDOMAINS")

    def test_reports_validates_every_name_before_reading_any_domain(self):
        for response in ('(a.example, "z;'+self.secret+'")', "(a.example, z..example)",
                         "(a.example, z.example.)", "(a.example, ../z)", "{}", ""):
            with self.subTest(response=response), patch.object(core, "cli", return_value=response) as cli:
                with self.assertRaisesRegex(core.Error, "^Cannot list CGP domains for bootstrap diagnostics$"):
                    bootstrap.reports(self.cfg)
                cli.assert_called_once_with(self.cfg, "LISTDOMAINS")

    def test_reports_requires_complete_array_of_strings(self):
        for response in ('(a.example, "unterminated)', '(a.example) {}',
                         '(a.example, #12)', '(a.example, (z.example))',
                         '(a.example, {Domain=z.example;})',
                         '(a.example, [eg==])', '(a.example, #NULL#)'):
            with self.subTest(response=response), patch.object(core, "cli", return_value=response) as cli:
                with self.assertRaisesRegex(core.Error, "^Cannot list CGP domains for bootstrap diagnostics$"):
                    bootstrap.reports(self.cfg)
                cli.assert_called_once_with(self.cfg, "LISTDOMAINS")

    def test_reports_masks_list_failure_and_propagates_interrupt(self):
        with patch.object(core, "cli", side_effect=OSError(self.secret)):
            with self.assertRaisesRegex(core.Error, "^Cannot list CGP domains for bootstrap diagnostics$"):
                bootstrap.reports(self.cfg)
        with patch.object(core, "cli", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                bootstrap.reports(self.cfg)

    def test_reports_invalid_requested_domain_never_lists(self):
        with patch.object(core, "cli") as cli:
            with self.assertRaises(core.Error):
                bootstrap.reports(self.cfg, "bad;example")
            cli.assert_not_called()


class CertificateFieldTests(unittest.TestCase):
    def test_normalizes_only_top_level_recognized_fields(self):
        parsed = cgpdata.parse_dictionary(
            '{Unrelated={SecureCertificate=[Yg==];}; PrivateSecureKey=[ YQ== ];'
            'SecureCertificate=[Yg==]; CAChain=[]; CertificateType="yES";}')
        self.assertEqual(bootstrap.certificate_fields(parsed), {
            "PrivateSecureKey": "[YQ==]", "SecureCertificate": "[Yg==]",
            "CAChain": "[]", "CertificateType": "yES"})
        self.assertEqual(bootstrap.certificate_fields(cgpdata.parse_dictionary(
            "{Unrelated={SecureCertificate=[Yg==];};}")), {})

    def test_present_unsupported_fields_raise_fixed_safe_errors(self):
        for name, value in (("PrivateSecureKey", '"secret material"'),
                            ("SecureCertificate", "[A]"), ("CAChain", "[YR==]"),
                            ("CertificateType", "default"), ("CertificateType", '""'),
                            ("CertificateType", "#NULL#")):
            with self.subTest(field=name, value=value):
                with self.assertRaisesRegex(core.Error, "^Unsupported certificate field value$"):
                    bootstrap.certificate_fields(cgpdata.parse_dictionary(
                        dictionary({name: value})))
