"""Synthetic pip-audit payloads; no network, real advisories or package changes."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import patch

from repo_tools import audit


def evaluate(*args, **kwargs):
    evidence = {"inventory_log": "", "scanner_log": "", "inventory_exit": 0}
    evidence.update(kwargs)
    return audit.evaluate(*args, **evidence)


def advisory(identifier="TEST-001", fixes=None, aliases=None):
    return {"id": identifier, "fix_versions": ["1.1"] if fixes is None else fixes,
            "aliases": ["TEST-ALIAS-001"] if aliases is None else aliases,
            "description": "Synthetic fixture only; not a real advisory."}


def dependency(name="example-pkg", version="1.0", vulns=None):
    return {"name": name, "version": version, "vulns": [] if vulns is None else vulns}


def report(*dependencies):
    return {"dependencies": list(dependencies) or [dependency()], "fixes": []}


def inventory(*dependencies):
    return [{"name": item["name"], "version": item["version"]}
            for item in dependencies or (dependency(),)]


class AuditPolicyTests(unittest.TestCase):
    def test_clean_audit_is_complete_in_both_profiles_without_mutating_inputs(self):
        payload, installed = report(), inventory()
        before = copy.deepcopy((payload, installed))
        for profile in audit.PROFILES:
            with self.subTest(profile=profile):
                result = evaluate(payload, installed, 0, profile)
                self.assertEqual(result["status"], "clean")
                self.assertTrue(result["complete"])
                self.assertEqual(result["exit_code"], 0)
                self.assertEqual(result["expected_dependencies"], 1)
                self.assertEqual(result["reported_dependencies"], 1)
                self.assertEqual(result["audited_dependencies"], 1)
                self.assertEqual(result["findings"], [])
                self.assertEqual(result["problems"], [])
        self.assertEqual((payload, installed), before)

    def test_current_findings_block_even_without_a_known_fix(self):
        payload = report(dependency(vulns=[advisory(fixes=[])]))
        result = evaluate(payload, inventory(), 1, "current")
        self.assertEqual(result["status"], "findings")
        self.assertEqual(result["policy"], "blocking")
        self.assertTrue(result["complete"])
        self.assertEqual(result["exit_code"], 1)
        self.assertEqual(result["vulnerable_dependencies"], 1)
        self.assertEqual(result["vulnerability_records"], 1)
        self.assertEqual(result["vulnerabilities"], 1)
        self.assertEqual(result["findings"][0]["fix_versions"], [])

    def test_compatibility_findings_are_explicitly_informational_never_clean(self):
        result = evaluate(report(dependency(vulns=[advisory()])), inventory(), 1, "compat")
        self.assertEqual(result["status"], "findings")
        self.assertEqual(result["policy"], "informational-findings")
        self.assertTrue(result["complete"])
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["findings"][0]["id"], "TEST-001")

    def test_repeated_advisory_ids_preserve_occurrences_aliases_and_fixes_per_package(self):
        repeated = [advisory(fixes=["1.1"], aliases=["TEST-B"]),
                    advisory(fixes=["1.2", "1.1"], aliases=["TEST-A", "TEST-B"]),
                    advisory("TEST-002", fixes=[], aliases=[])]
        alpha = dependency("Alpha_Pkg", vulns=repeated)
        beta = dependency("beta-pkg", "2.0", [advisory()])
        payload, installed = report(beta, alpha), inventory(alpha, beta)
        before = copy.deepcopy((payload, installed))
        result = evaluate(payload, installed, 1, "current")
        self.assertEqual(result["vulnerability_records"], 4)
        self.assertEqual(result["vulnerabilities"], 3)
        self.assertEqual(result["vulnerable_dependencies"], 2)
        self.assertEqual(result["findings"][0], {
            "name": "alpha-pkg", "version": "1.0", "id": "TEST-001",
            "fix_versions": ["1.1", "1.2"], "aliases": ["TEST-A", "TEST-B"], "occurrences": 2})
        self.assertEqual(result["findings"][2]["name"], "beta-pkg")
        self.assertNotIn("description", json.dumps(result))
        self.assertEqual((payload, installed), before)

    def test_package_name_canonicalization_matches_the_resolved_inventory(self):
        result = evaluate(report(dependency("Some.Pkg_Name")),
                                inventory(dependency("some-pkg-name")), 0, "current")
        self.assertEqual(result["status"], "clean")

    def test_skips_fail_closed_in_both_profiles_even_alongside_findings(self):
        skipped = {"name": "skipped-pkg", "skip_reason": "PRIVATE_REASON_MUST_NOT_ESCAPE"}
        installed = inventory(dependency("skipped-pkg"), dependency())
        for profile in audit.PROFILES:
            for code in (0, 1):
                with self.subTest(profile=profile, code=code):
                    result = evaluate(report(skipped, dependency(vulns=[advisory()])),
                                            installed, code, profile)
                    self.assertEqual(result["status"], "incomplete")
                    self.assertFalse(result["complete"])
                    self.assertEqual(result["exit_code"], 2)
                    self.assertEqual(result["skipped_dependencies"], ["skipped-pkg"])
                    self.assertEqual(result["audited_dependencies"], 1)
                    self.assertEqual(result["version_mismatches"], [])
                    self.assertEqual(result["vulnerabilities"], 1)
                    self.assertNotIn("PRIVATE_REASON", json.dumps(result))

    def test_missing_unexpected_or_changed_versions_are_incomplete_not_clean(self):
        cases = [
            ({"dependencies": [], "fixes": []}, inventory(), "missing_dependencies", "example-pkg"),
            (report(dependency(), dependency("extra")), inventory(), "unexpected_dependencies", "extra"),
            (report(dependency(version="1.1")), inventory(), "version_mismatches", "example-pkg"),
        ]
        for profile in audit.PROFILES:
            for payload, installed, field, name in cases:
                with self.subTest(profile=profile, field=field):
                    result = evaluate(payload, installed, 0, profile)
                    self.assertEqual(result["status"], "incomplete")
                    self.assertEqual(result[field], [name])
                    self.assertIn(field, result["problems"])
                    self.assertEqual(result["exit_code"], 2)

    def test_unexpected_scanner_status_never_passes_even_with_valid_json(self):
        for profile in audit.PROFILES:
            for code in (2, 124, -15):
                with self.subTest(profile=profile, code=code):
                    result = evaluate(report(), inventory(), code, profile)
                    self.assertEqual(result["status"], "scanner_error")
                    self.assertEqual(result["problems"], ["scanner_exit_error"])
                    self.assertFalse(result["complete"])
                    self.assertEqual(result["exit_code"], 2)

    def test_exit_code_and_complete_result_must_agree(self):
        for profile in audit.PROFILES:
            for payload, code in ((report(), 1), (report(dependency(vulns=[advisory()])), 0)):
                with self.subTest(profile=profile, code=code):
                    result = evaluate(payload, inventory(), code, profile)
                    self.assertEqual(result["status"], "scanner_error")
                    self.assertEqual(result["problems"], ["scanner_exit_mismatch"])
                    self.assertEqual(result["exit_code"], 2)

    def test_api_rejects_invalid_profile_and_noninteger_exit_code(self):
        with self.assertRaisesRegex(audit.AuditError, "^invalid_profile$"):
            evaluate(report(), inventory(), 0, "anything")
        for code in (True, None, "0"):
            result = evaluate(report(), inventory(), code, "current")
            self.assertEqual(result["status"], "invalid")
            self.assertEqual(result["problems"], ["invalid_scanner_exit"])
            self.assertEqual(result["exit_code"], 2)

    def test_empty_or_malformed_inventory_cannot_establish_a_complete_audit(self):
        cases = [(None, "invalid_inventory"), ([], "invalid_inventory"),
                 ({}, "invalid_inventory"), ([None], "invalid_inventory_entry"),
                 ([{"name": "example-pkg"}], "invalid_inventory_entry"),
                 ([{"name": "example-pkg", "version": "1", "editable_project_location": "/tmp/pkg"}],
                  "invalid_inventory_entry"),
                 (inventory(dependency("Example_Pkg"), dependency("example-pkg")),
                  "duplicate_inventory_dependency")]
        for installed, code in cases:
            with self.subTest(installed=installed):
                result = evaluate(report(), installed, 0, "compat")
                self.assertEqual(result["status"], "invalid")
                self.assertEqual(result["problems"], [code])
                self.assertEqual(result["exit_code"], 2)

    def test_unsupported_report_schema_and_any_fix_attempt_fail_closed(self):
        cases = [(None, "invalid_report"), ([], "invalid_report"),
                 ({"dependencies": []}, "invalid_report"),
                 ({"dependencies": [], "fixes": [], "extra": []}, "invalid_report"),
                 ({"dependencies": None, "fixes": []}, "invalid_dependencies"),
                 ({"dependencies": [], "fixes": None}, "unexpected_fixes"),
                 ({"dependencies": [], "fixes": [{"name": "example-pkg", "new_version": "2"}]},
                  "unexpected_fixes")]
        for payload, code in cases:
            with self.subTest(payload=payload):
                result = evaluate(payload, inventory(), 0, "compat")
                self.assertEqual(result["status"], "invalid")
                self.assertEqual(result["problems"], [code])
                self.assertEqual(result["exit_code"], 2)

    def test_dependency_and_skipped_dependency_shapes_are_strict(self):
        cases = [([None], "invalid_dependency"), ([{"name": "pkg"}], "invalid_dependency"),
                 ([dependency(vulns={})], "invalid_vulnerabilities"),
                 ([dependency("Pkg_Name"), dependency("pkg-name")], "duplicate_report_dependency"),
                 ([{"name": "pkg", "skip_reason": "",}], "invalid_skip_reason"),
                 ([{"name": "pkg", "skip_reason": None}], "invalid_skip_reason"),
                 ([{"name": "pkg", "skip_reason": "reason", "vulns": []}], "invalid_skipped_dependency")]
        for dependencies, code in cases:
            with self.subTest(dependencies=dependencies):
                result = evaluate({"dependencies": dependencies, "fixes": []}, inventory(), 1, "compat")
                self.assertEqual(result["problems"], [code])
                self.assertEqual(result["status"], "invalid")

    def test_names_and_versions_cannot_inject_terminal_or_structured_output(self):
        tokens = (None, True, 1, "", "x" * 256, "caf\u00e9", "line\n", "a b", "\x1b[31m")
        for value in tokens:
            with self.subTest(value=value):
                result = evaluate(report(dependency(version=value)), inventory(), 0, "current")
                self.assertEqual(result["problems"], ["invalid_identifier"])
        for name in ("-pkg", "pkg/other", "pkg.", "pkg$"):
            with self.subTest(name=name):
                result = evaluate(report(dependency(name)), inventory(), 0, "current")
                self.assertEqual(result["problems"], ["invalid_package_name"])

    def test_vulnerability_objects_and_identifier_lists_are_validated(self):
        cases = [(None, "invalid_vulnerability"), ({"id": "TEST"}, "invalid_vulnerability")]
        for field, value, code in (
            ("fix_versions", None, "invalid_identifier_list"),
            ("aliases", {}, "invalid_identifier_list"),
            ("fix_versions", [None], "invalid_identifier"),
            ("aliases", ["bad\n"], "invalid_identifier"),
            ("id", "", "invalid_identifier"),
            ("description", None, "invalid_description"),
        ):
            item = advisory()
            item[field] = value
            cases.append((item, code))
        for item, code in cases:
            with self.subTest(item=item):
                result = evaluate(report(dependency(vulns=[item])), inventory(), 1, "compat")
                self.assertEqual(result["problems"], [code])
                self.assertEqual(result["exit_code"], 2)

    def test_descriptions_are_retained_only_in_raw_report_not_summary(self):
        item = advisory()
        item["description"] = "RAW_DESCRIPTION\n\u041e\u043f\u0438\u0441\u0430\u043d\u0438\u0435\x1b[31m"
        payload = report(dependency(vulns=[item]))
        result = evaluate(payload, inventory(), 1, "compat")
        self.assertEqual(result["status"], "findings")
        self.assertNotIn("RAW_DESCRIPTION", json.dumps(result))
        self.assertEqual(payload["dependencies"][0]["vulns"][0]["description"], item["description"])

    def test_pip_warning_cannot_make_matching_reduced_inventories_look_complete(self):
        # Reproduced with pip 26.3 and pip-audit 2.10.1 PipSource: both omit
        # malformed dist-info before --strict ever sees a SkippedDependency.
        warnings = (
            "WARNING: Skipping /private/broken.dist-info due to invalid metadata entry 'name'\n",
            "WARNING: Ignoring incompletely removed distribution ~broken-1.0.dist-info (/private/site)\n",
        )
        for profile in audit.PROFILES:
            for warning in warnings:
                with self.subTest(profile=profile, warning=warning):
                    result = evaluate(report(), inventory(), 0, profile, inventory_log=warning)
                    self.assertEqual(result["status"], "incomplete")
                    self.assertFalse(result["complete"])
                    self.assertEqual(result["exit_code"], 2)
                    self.assertEqual(result["problems"], ["inventory_log_diagnostics"])
                    self.assertNotIn("/private", json.dumps(result))

    def test_scanner_diagnostics_fail_both_profiles_and_preserve_known_findings(self):
        payload = report(dependency(vulns=[advisory()]))
        for profile in audit.PROFILES:
            for level in ("WARNING", "error", "CRITICAL", "Fatal"):
                with self.subTest(profile=profile, level=level):
                    result = evaluate(payload, inventory(), 1, profile,
                                      scanner_log="Found 1 known vulnerability\n" + level + ": PRIVATE_DETAIL\n")
                    self.assertEqual(result["status"], "incomplete")
                    self.assertEqual(result["exit_code"], 2)
                    self.assertEqual(result["problems"], ["scanner_log_diagnostics"])
                    self.assertEqual(result["vulnerabilities"], 1)
                    self.assertNotIn("PRIVATE_DETAIL", json.dumps(result))
        result = evaluate(payload, inventory(), 1, "compat", inventory_log="WARNING: one\n", scanner_log="ERROR: two\n")
        self.assertEqual(result["problems"], ["inventory_log_diagnostics", "scanner_log_diagnostics"])

    def test_inventory_failure_and_missing_evidence_never_produce_a_clean_result(self):
        for profile in audit.PROFILES:
            for exit_code in (1, 2, -15):
                result = evaluate(report(), inventory(), 0, profile, inventory_exit=exit_code)
                self.assertEqual(result["status"], "inventory_error")
                self.assertEqual(result["problems"], ["inventory_exit_error"])
                self.assertEqual(result["exit_code"], 2)
        evidence = {"inventory_log": "", "scanner_log": "", "inventory_exit": 0}
        for omitted in evidence:
            with self.subTest(omitted=omitted), self.assertRaises(TypeError):
                audit.evaluate(report(), inventory(), 0, "current", **{key: value for key, value in evidence.items() if key != omitted})
        for value in (True, None, "PRIVATE_EXIT"):
            result = evaluate(report(), inventory(), 0, "current", inventory_exit=value)
            self.assertEqual(result["problems"], ["invalid_inventory_exit"])
            self.assertIsNone(result["inventory_exit"])
            self.assertNotIn("PRIVATE_EXIT", json.dumps(result))
        result = evaluate(report(), inventory(), "PRIVATE_SCANNER_EXIT", "current")
        self.assertIsNone(result["scanner_exit"])
        self.assertNotIn("PRIVATE_SCANNER_EXIT", json.dumps(result))

    def test_log_text_is_bounded_printable_utf8_and_never_echoed(self):
        for name in ("inventory_log", "scanner_log"):
            for value in (None, b"bytes", 1, "\ud800", "PRIVATE\x00TEXT", "PRIVATE\x1b[0m", "PRIVATE\u202eTEXT"):
                with self.subTest(name=name, value=repr(value)):
                    result = evaluate(report(), inventory(), 0, "current", **{name: value})
                    self.assertEqual(result["problems"], [name + "_invalid_text"])
                    self.assertEqual(result["exit_code"], 2)
                    self.assertNotIn("PRIVATE", json.dumps(result))
            for text in ("x" * 17, "é" * 9):
                with patch.object(audit, "MAX_LOG_BYTES", 16):
                    result = evaluate(report(), inventory(), 0, "compat", **{name: text})
                self.assertEqual(result["problems"], [name + "_oversized"])
        result = evaluate(report(), inventory(), 0, "current", inventory_log="[notice] local inventory\n",
                          scanner_log="No known vulnerabilities found\n\tОбработка завершена\r\n")
        self.assertTrue(result["complete"])


class AuditInputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.inventory = self.root / "inventory.json"
        self.report = self.root / "report.json"
        self.inventory_log = self.root / "inventory.log"
        self.scanner_log = self.root / "scanner.log"
        self.inventory.write_text(json.dumps(inventory()))
        self.report.write_text(json.dumps(report()))
        self.inventory_log.write_text("")
        self.scanner_log.write_text("No known vulnerabilities found\n")

    def args(self, profile="current", code=0):
        return ["--profile", profile, "--inventory", str(self.inventory),
                "--report", str(self.report), "--inventory-log", str(self.inventory_log),
                "--scanner-log", str(self.scanner_log), "--inventory-exit", "0",
                "--scanner-exit", str(code)]

    def invoke(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = audit.main(self.args(*args))
        self.assertEqual(stderr.getvalue(), "")
        return code, json.loads(stdout.getvalue())

    def test_valid_json_file_is_read_without_changes(self):
        before = self.report.read_bytes()
        self.assertEqual(audit.read_json(self.report), report())
        self.assertEqual(self.report.read_bytes(), before)

    def test_duplicate_keys_and_nonfinite_constants_are_rejected(self):
        for text, code in (("{\"dependencies\":[],\"dependencies\":[]}", "duplicate_json_key"),
                           ("{\"x\":{\"a\":1,\"a\":2}}", "duplicate_json_key"),
                           ("[NaN]", "nonfinite_json"), ("[Infinity]", "nonfinite_json"),
                           ("[-Infinity]", "nonfinite_json")):
            with self.subTest(text=text):
                self.report.write_text(text)
                with self.assertRaisesRegex(audit.AuditError, "^" + code + "$"):
                    audit.read_json(self.report)

    def test_malformed_encoding_and_truncation_are_invalid(self):
        for content in (b"\xff", b'{"dependencies":'):
            with self.subTest(size=len(content)):
                self.report.write_bytes(content)
                with self.assertRaisesRegex(audit.AuditError, "^invalid_json$"):
                    audit.read_json(self.report)

    def test_json_parser_recursion_failure_is_reported_without_input_details(self):
        with patch.object(audit.json, "loads", side_effect=RecursionError("PRIVATE_INPUT")):
            with self.assertRaisesRegex(audit.AuditError, "^invalid_json$"):
                audit.read_json(self.report)

    def test_oversized_integer_report_and_inventory_produce_fixed_summaries(self):
        previous_limit = sys.get_int_max_str_digits()
        sys.set_int_max_str_digits(640)
        try:
            for kind in ("report", "inventory"):
                path = getattr(self, kind)
                before = path.read_bytes()
                path.write_text('{"PRIVATE_METADATA":' + "9" * 641 + "}")
                code, result = self.invoke("compat", 0)
                self.assertEqual(code, 2)
                self.assertEqual(result["status"], "invalid")
                self.assertFalse(result["complete"])
                self.assertEqual(result["problems"], [kind + "_invalid_json"])
                self.assertNotIn("PRIVATE_METADATA", json.dumps(result))
                path.write_bytes(before)
        finally:
            sys.set_int_max_str_digits(previous_limit)

    def test_oversized_input_is_not_truncated_into_a_valid_report(self):
        self.report.write_text("{}" + " " * 30)
        with patch.object(audit, "MAX_JSON_BYTES", 16):
            with self.assertRaisesRegex(audit.AuditError, "^oversized_json$"):
                audit.read_json(self.report)
        self.assertEqual(self.report.read_text(), "{}" + " " * 30)

    def test_missing_input_is_an_explicit_read_failure(self):
        self.report.unlink()
        with self.assertRaisesRegex(audit.AuditError, "^unreadable_json$"):
            audit.read_json(self.report)

    def test_cli_keeps_original_report_inventory_and_all_known_findings(self):
        self.report.write_text(json.dumps(report(dependency(vulns=[advisory()]))))
        before = self.report.read_bytes(), self.inventory.read_bytes()
        code, result = self.invoke("current", 1)
        self.assertEqual(code, 1)
        self.assertEqual(result["status"], "findings")
        self.assertEqual(result["findings"][0]["id"], "TEST-001")
        self.assertEqual((self.report.read_bytes(), self.inventory.read_bytes()), before)

    def test_cli_compatibility_changes_only_findings_policy(self):
        code, result = self.invoke("compat", 0)
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "clean")
        self.report.write_text(json.dumps(report(dependency(vulns=[advisory()]))))
        code, result = self.invoke("compat", 1)
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "findings")
        self.assertEqual(result["vulnerabilities"], 1)

    def test_no_report_after_failed_scanner_is_not_an_informational_pass(self):
        self.report.unlink()
        code, result = self.invoke("compat", 1)
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "scanner_error")
        self.assertEqual(result["problems"], ["report_unreadable_json"])

    def test_bad_report_or_inventory_outputs_fixed_diagnostic_without_raw_text(self):
        for kind in ("report", "inventory"):
            with self.subTest(kind=kind):
                path = getattr(self, kind)
                old = path.read_bytes()
                path.write_text("PRIVATE_MALFORMED_CONTENT")
                code, result = self.invoke("compat", 0)
                self.assertEqual(code, 2)
                self.assertEqual(result["status"], "invalid")
                self.assertEqual(result["problems"], [kind + "_invalid_json"])
                self.assertNotIn("PRIVATE_MALFORMED", json.dumps(result))
                path.write_bytes(old)

    def test_missing_inventory_cannot_be_substituted_with_report_contents(self):
        self.inventory.unlink()
        code, result = self.invoke("compat", 0)
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "invalid")
        self.assertEqual(result["problems"], ["inventory_unreadable_json"])

    def test_cli_diagnostic_evidence_is_required_and_preserved(self):
        self.inventory_log.write_text("WARNING: Skipping /PRIVATE_PATH/broken.dist-info\n")
        before = self.inventory_log.read_bytes(), self.scanner_log.read_bytes()
        code, result = self.invoke("compat", 0)
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "incomplete")
        self.assertNotIn("PRIVATE_PATH", json.dumps(result))
        self.assertEqual((self.inventory_log.read_bytes(), self.scanner_log.read_bytes()), before)
        for flag in ("--inventory-log", "--scanner-log", "--inventory-exit"):
            argv = self.args()
            index = argv.index(flag)
            del argv[index:index + 2]
            with contextlib.redirect_stderr(io.StringIO()), patch.object(audit, "read_json") as read, \
                    self.assertRaises(SystemExit) as error:
                audit.main(argv)
            self.assertEqual(error.exception.code, 2)
            read.assert_not_called()

    def test_missing_bad_encoding_and_oversized_logs_fail_closed(self):
        for kind in ("inventory_log", "scanner_log"):
            path = getattr(self, kind)
            before = path.read_bytes()
            path.unlink()
            code, result = self.invoke("compat", 0)
            self.assertEqual(code, 2)
            self.assertEqual(result["problems"], [kind + "_unreadable_log"])
            path.write_bytes(b"PRIVATE\xffCONTENT")
            code, result = self.invoke("current", 0)
            self.assertEqual(code, 2)
            self.assertEqual(result["problems"], [kind + "_invalid_log_encoding"])
            self.assertNotIn("PRIVATE", json.dumps(result))
            path.write_bytes(b"x" * 40)
            with patch.object(audit, "MAX_LOG_BYTES", 32):
                code, result = self.invoke("compat", 0)
            self.assertEqual(code, 2)
            self.assertEqual(result["problems"], [kind + "_oversized_log"])
            path.write_bytes(before)
        self.scanner_log.write_bytes(b"x" * 32)
        with patch.object(audit, "MAX_LOG_BYTES", 32):
            self.assertEqual(audit.read_log(self.scanner_log), "x" * 32)

    def test_evidence_readers_reject_symlinks_and_special_files_without_blocking(self):
        target = self.root / "target"
        target.write_text("[]")
        for path_kind in ("symlink", "directory", "fifo"):
            path = self.root / path_kind
            if path_kind == "symlink":
                path.symlink_to(target)
            elif path_kind == "directory":
                path.mkdir()
            else:
                os.mkfifo(path)
            for reader, code in ((audit.read_json, "unreadable_json"), (audit.read_log, "unreadable_log")):
                with self.subTest(path_kind=path_kind, reader=reader.__name__), self.assertRaisesRegex(audit.AuditError, "^" + code + "$"):
                    reader(path)
        with self.assertRaisesRegex(audit.AuditError, "^unreadable_log$"):
            audit.read_log("PRIVATE\0PATH")

    def test_evidence_read_failures_close_descriptor_and_hide_raw_details(self):
        before = len(list(Path("/proc/self/fd").iterdir()))
        for operation in ("fstat", "fdopen"):
            with patch.object(audit.os, operation, side_effect=OSError("PRIVATE_DETAIL")), \
                    self.assertRaisesRegex(audit.AuditError, "^unreadable_log$"):
                audit.read_log(self.scanner_log)
            self.assertEqual(len(list(Path("/proc/self/fd").iterdir())), before)

    def test_invalid_cli_arguments_fail_before_input_read(self):
        for argv in ([], ["--profile", "production"], self.args()[:-1] + ["not-an-integer"]):
            with self.subTest(argv=argv), patch.object(audit, "read_json") as read:
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as error:
                        audit.main(argv)
                self.assertEqual(error.exception.code, 2)
                read.assert_not_called()

    def test_module_entrypoint_returns_the_policy_exit_code(self):
        self.report.write_text(json.dumps(report(dependency(vulns=[advisory()]))))
        stdout = io.StringIO()
        with patch.object(sys, "argv", ["audit"] + self.args("current", 1)), contextlib.redirect_stdout(stdout):
            with self.assertRaises(SystemExit) as error:
                runpy.run_path(audit.__file__, run_name="__main__")
        self.assertEqual(error.exception.code, 1)
        self.assertEqual(json.loads(stdout.getvalue())["status"], "findings")


if __name__ == "__main__":
    unittest.main()
