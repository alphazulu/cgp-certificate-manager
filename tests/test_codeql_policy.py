"""Synthetic SARIF policy tests; native CodeQL execution belongs to CI."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from repo_tools import codeql


ROOT = Path(__file__).resolve().parents[1]


def report(name="CodeQL"):
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": name}}, "results": []}]}


class CodeQLPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def write(self, value=None, name="python.sarif"):
        path = self.directory / name
        path.write_text(json.dumps(report() if value is None else value))
        return path

    def assert_rejected(self, code):
        summary = codeql.assess(self.directory, analysis_status="success")
        self.assertFalse(summary["passed"])
        self.assertFalse(summary["complete"])
        self.assertIn(code, summary["errors"])
        return summary

    def test_clean_codeql_report_with_optional_metadata_absent(self):
        self.write()
        self.assertEqual(codeql.assess(self.directory, analysis_status="success"), {
            "schema": 1, "reports": 1, "runs": 1, "findings": 0,
            "errors": [], "complete": True, "passed": True})

    def test_clean_reports_never_override_unsuccessful_native_analysis(self):
        self.write()
        for outcome in ("failure", "skipped", "cancelled", "unknown", None, "SUCCESS"):
            with self.subTest(outcome=outcome):
                summary = codeql.assess(self.directory, analysis_status=outcome)
                self.assertEqual(summary, {
                    "schema": 1, "reports": 1, "runs": 1, "findings": 0,
                    "errors": ["analysis_not_successful"], "complete": False, "passed": False})
        self.assertEqual(codeql.assess(self.directory)["errors"], ["analysis_not_successful"])

    def test_native_failure_keeps_missing_and_malformed_report_diagnostics(self):
        for outcome in ("failure", "skipped"):
            with self.subTest(outcome=outcome):
                summary = codeql.assess(self.directory, analysis_status=outcome)
                self.assertFalse(summary["passed"])
                self.assertFalse(summary["complete"])
                self.assertEqual(summary["errors"], ["analysis_not_successful", "missing_reports"])
        (self.directory / "python.sarif").write_text("invalid")
        summary = codeql.assess(self.directory, analysis_status="failure")
        self.assertFalse(summary["passed"])
        self.assertEqual(summary["errors"], ["analysis_not_successful", "invalid_json"])

    def test_cli_requires_explicit_success_even_with_clean_native_report(self):
        self.write()
        for outcome in (None, "failure", "skipped", "cancelled", "unknown"):
            with self.subTest(outcome=outcome):
                arguments = ["--reports", str(self.directory)]
                if outcome is not None:
                    arguments.extend(("--analysis-status", outcome))
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    status = codeql.main(arguments)
                self.assertEqual(status, 1)
                self.assertEqual(json.loads(output.getvalue())["errors"], ["analysis_not_successful"])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as invalid:
            codeql.main(["--reports", str(self.directory), "--analysis-status", "unexpected"])
        self.assertEqual(invalid.exception.code, 2)

    def test_cli_toolchain_driver_multiple_reports_and_runs_are_counted(self):
        self.write(report("CodeQL command-line toolchain"))
        second = report()
        second["runs"].append(copy.deepcopy(second["runs"][0]))
        self.write(second, "other.sarif")
        self.write({"not": "a report"}, "ignored.json")
        summary = codeql.assess(self.directory, analysis_status="success")
        self.assertTrue(summary["passed"])
        self.assertEqual((summary["reports"], summary["runs"]), (2, 3))

    def test_any_findings_fail_including_low_level_and_suppressed_results(self):
        for results in ([{"ruleId": "py/example", "level": "note"}],
                        [{"ruleId": "py/example", "suppressions": [{"kind": "inSource"}]}],
                        [{"ruleId": "py/a"}, {"ruleId": "py/b"}]):
            with self.subTest(results=results):
                document = report()
                document["runs"][0]["results"] = results
                self.write(document)
                summary = codeql.assess(self.directory, analysis_status="success")
                self.assertTrue(summary["complete"])
                self.assertFalse(summary["passed"])
                self.assertEqual(summary["findings"], len(results))
                self.assertEqual(summary["errors"], [])

    def test_document_version_and_run_shapes_fail_closed(self):
        for value, error in (([], "invalid_sarif_version"),
                             ({}, "invalid_sarif_version"),
                             ({"version": "2.2.0", "runs": []}, "invalid_sarif_version"),
                             ({"version": "2.1.0"}, "invalid_runs"),
                             ({"version": "2.1.0", "runs": {}}, "invalid_runs"),
                             ({"version": "2.1.0", "runs": []}, "invalid_runs"),
                             ({"version": "2.1.0", "runs": [None]}, "invalid_run")):
            with self.subTest(value=value):
                self.write(value)
                self.assert_rejected(error)

    def test_other_tools_and_malformed_results_cannot_look_clean(self):
        for mutate, error in ((lambda run: run.pop("tool"), "invalid_tool"),
                              (lambda run: run.update(tool=[]), "invalid_tool"),
                              (lambda run: run.update(tool={}), "invalid_tool"),
                              (lambda run: run.update(tool={"driver": "CodeQL"}), "invalid_tool"),
                              (lambda run: run["tool"]["driver"].update(name="other scanner"), "invalid_tool"),
                              (lambda run: run.pop("results"), "invalid_results"),
                              (lambda run: run.update(results={}), "invalid_results"),
                              (lambda run: run.update(results=[None]), "invalid_results")):
            with self.subTest(error=error, mutate=mutate):
                document = report()
                mutate(document["runs"][0])
                self.write(document)
                self.assert_rejected(error)

    def test_successful_invocations_and_note_notifications_are_allowed(self):
        document = report()
        document["runs"][0]["invocations"] = [
            {"executionSuccessful": True},
            {"executionSuccessful": True, "exitCode": 0,
             "toolExecutionNotifications": [{"level": "note", "message": {"text": "information"}}],
             "toolConfigurationNotifications": [{"level": "none"}]}]
        self.write(document)
        self.assertTrue(codeql.assess(self.directory, analysis_status="success")["passed"])

    def test_failed_missing_or_nonboolean_invocation_success_is_incomplete(self):
        for invocation in ({}, {"executionSuccessful": False}, {"executionSuccessful": 1},
                           {"executionSuccessful": "true"}, {"executionSuccessful": None},
                           {"executionSuccessful": True, "exitCode": 1},
                           {"executionSuccessful": True, "exitCode": False},
                           {"executionSuccessful": True, "exitCode": "0"}):
            with self.subTest(invocation=invocation):
                document = report()
                document["runs"][0]["invocations"] = [invocation]
                self.write(document)
                self.assert_rejected("analysis_incomplete")

    def test_invocation_shapes_are_not_silently_ignored(self):
        for value in (None, {}, "", [None]):
            with self.subTest(value=value):
                document = report()
                document["runs"][0]["invocations"] = value
                self.write(document)
                self.assert_rejected("invalid_invocations")

    def test_error_warning_and_implicit_warning_notifications_block(self):
        for field in ("toolExecutionNotifications", "toolConfigurationNotifications"):
            for notification in ({"level": "error"}, {"level": "warning"}, {}):
                with self.subTest(field=field, notification=notification):
                    document = report()
                    document["runs"][0]["invocations"] = [{"executionSuccessful": True, field: [notification]}]
                    self.write(document)
                    self.assert_rejected("analysis_notification")

    def test_malformed_notifications_block(self):
        for value in (None, {}, [None], [{"level": "unknown"}], [{"level": 1}]):
            with self.subTest(value=value):
                document = report()
                document["runs"][0]["invocations"] = [{"executionSuccessful": True, "toolExecutionNotifications": value}]
                self.write(document)
                self.assert_rejected("invalid_notifications")

    def test_malformed_json_utf8_duplicate_keys_and_nonfinite_numbers(self):
        for value in (b"", b"{", b"\xff", b'{"version":"2.1.0","version":"2.1.0"}',
                      b'{"value":NaN}', b'{"value":Infinity}', b'{"value":1e999}'):
            with self.subTest(value=value[:40]):
                (self.directory / "python.sarif").write_bytes(value)
                self.assert_rejected("invalid_json")
        self.write()
        with mock.patch.object(codeql.json, "loads", side_effect=RecursionError("private parser detail")):
            self.assert_rejected("invalid_json")

    def test_finite_extra_numeric_metadata_is_supported(self):
        document = report()
        document["properties"] = {"elapsed": 1.25}
        self.write(document)
        self.assertTrue(codeql.assess(self.directory, analysis_status="success")["passed"])

    def test_no_reports_or_only_unrelated_files_fails(self):
        self.assert_rejected("missing_reports")
        self.write(name="not-a-report.json")
        self.assert_rejected("missing_reports")

    def test_invalid_missing_or_unreadable_reports_directory(self):
        ordinary = self.write(name="file")
        for path, error in ((ordinary, "invalid_reports_directory"),
                            (self.directory / "absent", "unreadable_reports_directory"),
                            ("bad\x00path", "unreadable_reports_directory")):
            with self.subTest(path=path):
                summary = codeql.assess(path, analysis_status="success")
                self.assertFalse(summary["passed"])
                self.assertEqual(summary["errors"], [error])
        with mock.patch.object(Path, "iterdir", side_effect=PermissionError("private-directory")):
            self.assert_rejected("unreadable_reports_directory")

    def test_symlink_directory_and_report_are_rejected_without_following(self):
        original = self.write(name="original.json")
        alias = self.directory / "alias"
        alias.symlink_to(self.directory, target_is_directory=True)
        self.assertEqual(codeql.assess(alias, analysis_status="success")["errors"], ["invalid_reports_directory"])
        (self.directory / "python.sarif").symlink_to(original)
        self.assert_rejected("unreadable_report")

    def test_special_report_types_cannot_block_the_checker(self):
        path = self.directory / "python.sarif"
        path.mkdir()
        self.assert_rejected("unsafe_report_type")
        path.rmdir()
        os.mkfifo(path)
        self.assert_rejected("unsafe_report_type")

    def test_report_size_bound_and_growth_between_stat_and_read(self):
        path = self.write()
        size = path.stat().st_size
        with mock.patch.object(codeql, "MAX_REPORT_BYTES", size):
            self.assertTrue(codeql.assess(self.directory, analysis_status="success")["passed"])
        with mock.patch.object(codeql, "MAX_REPORT_BYTES", size - 1):
            self.assert_rejected("report_too_large")
        info = mock.Mock(st_mode=stat.S_IFREG | 0o600, st_size=1)
        with mock.patch.object(codeql, "MAX_REPORT_BYTES", size - 1), mock.patch.object(codeql.os, "fstat", return_value=info):
            self.assert_rejected("report_too_large")

    def test_bounded_report_count_and_directory_entries(self):
        self.write()
        with mock.patch.object(codeql, "MAX_REPORT_FILES", 1):
            self.assertTrue(codeql.assess(self.directory, analysis_status="success")["passed"])
            self.write(name="second.sarif")
            self.assert_rejected("too_many_reports")
        with mock.patch.object(codeql, "MAX_DIRECTORY_ENTRIES", 2):
            self.assertTrue(codeql.assess(self.directory, analysis_status="success")["passed"])
            self.write(name="ignored.json")
            self.assert_rejected("too_many_directory_entries")

    def test_file_read_errors_do_not_leak_details_and_always_close_descriptor(self):
        self.write()
        real_close = os.close
        with mock.patch.object(codeql.os, "fstat", side_effect=OSError("private-file-detail")), \
                mock.patch.object(codeql.os, "close", wraps=real_close) as close:
            summary = self.assert_rejected("unreadable_report")
            close.assert_called_once()
        self.assertNotIn("private-file-detail", json.dumps(summary))
        with mock.patch.object(codeql.os, "open", side_effect=PermissionError("private-path")):
            self.assert_rejected("unreadable_report")

    def test_one_bad_report_cannot_be_masked_by_a_clean_report(self):
        self.write()
        (self.directory / "a.sarif").write_text("invalid")
        (self.directory / "b.sarif").write_text("invalid")
        summary = self.assert_rejected("invalid_json")
        self.assertEqual(summary["reports"], 3)
        self.assertEqual(summary["runs"], 1)
        self.assertEqual(summary["errors"], ["invalid_json"])

    def test_read_only_summary_does_not_expose_finding_or_notification_text(self):
        document = report()
        document["runs"][0]["results"] = [{"message": {"text": "secret-source-text"}, "ruleId": "py/example"}]
        path = self.write(document)
        before = (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode)
        summary = codeql.assess(self.directory, analysis_status="success")
        self.assertNotIn("secret-source-text", json.dumps(summary))
        self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode), before)
        document["runs"][0]["invocations"] = [{"executionSuccessful": True,
            "toolExecutionNotifications": [{"level": "error", "message": {"text": "secret-notification"}}]}]
        self.write(document)
        self.assertNotIn("secret-notification", json.dumps(codeql.assess(self.directory, analysis_status="success")))

    def test_main_outputs_json_and_distinct_pass_or_failure_status(self):
        self.write()
        for clean in (True, False):
            if not clean:
                (self.directory / "python.sarif").write_text("invalid")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = codeql.main(["--reports", str(self.directory), "--analysis-status", "success"])
            self.assertEqual(status, 0 if clean else 1)
            self.assertEqual(json.loads(output.getvalue())["passed"], clean)

    def test_real_cli_preserves_report_and_returns_json_without_stderr(self):
        path = self.write()
        before = path.read_bytes()
        process = subprocess.run([sys.executable, "-m", "repo_tools.codeql", "--reports", str(self.directory), "--analysis-status", "success"],
                                 cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(process.returncode, 0)
        self.assertEqual(process.stderr, "")
        self.assertTrue(json.loads(process.stdout)["passed"])
        self.assertEqual(path.read_bytes(), before)
        process = subprocess.run([sys.executable, "-m", "repo_tools.codeql", "--reports", str(self.directory)],
                                 cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(process.returncode, 1)
        self.assertEqual(process.stderr, "")
        self.assertEqual(json.loads(process.stdout)["errors"], ["analysis_not_successful"])
        path.unlink()
        process = subprocess.run([sys.executable, "-m", "repo_tools.codeql", "--reports", str(self.directory), "--analysis-status", "success"],
                                 cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(process.returncode, 1)
        self.assertEqual(json.loads(process.stdout)["errors"], ["missing_reports"])

    def test_module_entry_point_and_required_cli_argument(self):
        self.write()
        with mock.patch.object(sys, "argv", ["codeql", "--reports", str(self.directory), "--analysis-status", "success"]), \
                contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as stopped:
            runpy.run_path(str(ROOT / "repo_tools/codeql.py"), run_name="__main__")
        self.assertEqual(stopped.exception.code, 0)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as missing:
            codeql.main([])
        self.assertEqual(missing.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
