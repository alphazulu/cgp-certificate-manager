"""Fail-closed policy for CodeQL's SARIF output, without changing the reports.

Pass the actual native CodeQL step outcome. This checks its reports and requires
an explicit successful outcome; it does not execute CodeQL, authenticate the
producer or caller's outcome claim, or replace source analysis.
The default precise suite must have zero results, including suppressed results.
Execution/configuration warnings and errors need review, not silent acceptance.
Optional invocation metadata is checked when supplied by the producer.
"""
import argparse
import json
import math
import os
from pathlib import Path
import stat


MAX_REPORT_BYTES = 32 * 1024 * 1024
MAX_REPORT_FILES = 16
MAX_DIRECTORY_ENTRIES = 256
DRIVERS = ("CodeQL", "CodeQL command-line toolchain")


class PolicyError(ValueError):
    """A fixed diagnostic code safe to include in the JSON policy summary."""


def _object(pairs):
    value = {}
    for name, item in pairs:
        if name in value:
            raise PolicyError("invalid_json")
        value[name] = item
    return value


def _constant(_value):
    raise PolicyError("invalid_json")


def _float(value):
    number = float(value)
    if not math.isfinite(number):
        raise PolicyError("invalid_json")
    return number


def _read(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise PolicyError("unsafe_report_type")
        if info.st_size > MAX_REPORT_BYTES:
            raise PolicyError("report_too_large")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            contents = stream.read(MAX_REPORT_BYTES + 1)
        if len(contents) > MAX_REPORT_BYTES:
            raise PolicyError("report_too_large")
    finally:
        os.close(descriptor)
    try:
        return json.loads(contents.decode("utf-8"), object_pairs_hook=_object,
                          parse_constant=_constant, parse_float=_float)
    except (ValueError, UnicodeError, RecursionError):
        raise PolicyError("invalid_json") from None


def _notifications(invocation, field):
    notifications = invocation.get(field, [])
    if not isinstance(notifications, list):
        raise PolicyError("invalid_notifications")
    for notification in notifications:
        if not isinstance(notification, dict):
            raise PolicyError("invalid_notifications")
        # SARIF's omitted notification level defaults to warning.
        level = notification.get("level", "warning")
        if level not in ("none", "note", "warning", "error"):
            raise PolicyError("invalid_notifications")
        if level in ("warning", "error"):
            raise PolicyError("analysis_notification")


def _document(document):
    if not isinstance(document, dict) or document.get("version") != "2.1.0":
        raise PolicyError("invalid_sarif_version")
    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        raise PolicyError("invalid_runs")
    findings = 0
    for run in runs:
        if not isinstance(run, dict):
            raise PolicyError("invalid_run")
        tool = run.get("tool")
        if not isinstance(tool, dict):
            raise PolicyError("invalid_tool")
        driver = tool.get("driver")
        if not isinstance(driver, dict) or driver.get("name") not in DRIVERS:
            raise PolicyError("invalid_tool")
        results = run.get("results")
        if not isinstance(results, list):
            raise PolicyError("invalid_results")
        if any(not isinstance(result, dict) for result in results):
            raise PolicyError("invalid_results")
        findings += len(results)
        invocations = run.get("invocations", [])
        if not isinstance(invocations, list):
            raise PolicyError("invalid_invocations")
        for invocation in invocations:
            if not isinstance(invocation, dict):
                raise PolicyError("invalid_invocations")
            if invocation.get("executionSuccessful") is not True:
                raise PolicyError("analysis_incomplete")
            if "exitCode" in invocation and (type(invocation["exitCode"]) is not int or
                                             invocation["exitCode"] != 0):
                raise PolicyError("analysis_incomplete")
            _notifications(invocation, "toolExecutionNotifications")
            _notifications(invocation, "toolConfigurationNotifications")
    return len(runs), findings


def _reports(directory):
    path = Path(directory)
    if not stat.S_ISDIR(path.lstat().st_mode):
        raise PolicyError("invalid_reports_directory")
    reports = []
    for index, entry in enumerate(path.iterdir()):
        if index >= MAX_DIRECTORY_ENTRIES:
            raise PolicyError("too_many_directory_entries")
        if entry.suffix == ".sarif":
            reports.append(entry)
            if len(reports) > MAX_REPORT_FILES:
                raise PolicyError("too_many_reports")
    if not reports:
        raise PolicyError("missing_reports")
    return sorted(reports)


def assess(directory, analysis_status="unknown"):
    """Require native success and return fixed report diagnostics and counts."""
    summary = {"schema": 1, "reports": 0, "runs": 0, "findings": 0,
               "errors": [], "complete": False, "passed": False}
    if analysis_status != "success":
        summary["errors"].append("analysis_not_successful")
    try:
        reports = _reports(directory)
    except PolicyError as error:
        summary["errors"].append(str(error))
        return summary
    except (OSError, ValueError):
        summary["errors"].append("unreadable_reports_directory")
        return summary
    summary["reports"] = len(reports)
    for path in reports:
        try:
            runs, findings = _document(_read(path))
        except PolicyError as error:
            summary["errors"].append(str(error))
        except OSError:
            summary["errors"].append("unreadable_report")
        else:
            summary["runs"] += runs
            summary["findings"] += findings
    summary["errors"] = sorted(set(summary["errors"]))
    summary["complete"] = not summary["errors"]
    summary["passed"] = summary["complete"] and summary["findings"] == 0
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check native CodeQL SARIF reports; no findings or waivers are accepted")
    parser.add_argument("--reports", required=True, help="Directory containing the native .sarif reports")
    parser.add_argument("--analysis-status", default="unknown",
                        choices=("success", "failure", "skipped", "cancelled", "unknown"),
                        help="Actual native analysis step outcome; only success can pass")
    arguments = parser.parse_args(argv)
    summary = assess(arguments.reports, analysis_status=arguments.analysis_status)
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
