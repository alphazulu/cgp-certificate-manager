"""Read-only policy for complete pip-audit 2.10.1 JSON reports.

Audit the resolved target environment separately from scanner tooling.  The
inventory is `pip list --format=json --path` for the same path passed to
pip-audit.  Keep the original report, inventory and scanner log as CI artifacts;
this adapter never changes them or installs/fixes/ignores any dependency.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat


MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_LOG_BYTES = 1024 * 1024
PROFILES = ("current", "compat")
NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")


class AuditError(ValueError):
    """A fixed validation code, without raw report text or descriptions."""


def _require(condition, code):
    if not condition:
        raise AuditError(code)


def _keys(value, expected, code):
    _require(type(value) is dict and set(value) == set(expected), code)


def _token(value):
    _require(type(value) is str and 0 < len(value) <= 255 and
             value.isascii() and value.isprintable() and not any(c.isspace() for c in value),
             "invalid_identifier")
    return value


def _name(value):
    value = _token(value)
    _require(NAME.fullmatch(value) is not None, "invalid_package_name")
    return re.sub(r"[-_.]+", "-", value).lower()


def _tokens(value):
    _require(type(value) is list, "invalid_identifier_list")
    return [_token(item) for item in value]


def _inventory(value):
    _require(type(value) is list and bool(value), "invalid_inventory")
    result = {}
    for item in value:
        _keys(item, ("name", "version"), "invalid_inventory_entry")
        name = _name(item["name"])
        _require(name not in result, "duplicate_inventory_dependency")
        result[name] = _token(item["version"])
    return result


def _report(value):
    _keys(value, ("dependencies", "fixes"), "invalid_report")
    _require(type(value["dependencies"]) is list, "invalid_dependencies")
    _require(type(value["fixes"]) is list and not value["fixes"], "unexpected_fixes")
    dependencies, skipped, findings = {}, [], {}
    records = 0
    for item in value["dependencies"]:
        _require(type(item) is dict, "invalid_dependency")
        if "skip_reason" in item:
            _keys(item, ("name", "skip_reason"), "invalid_skipped_dependency")
            name = _name(item["name"])
            _require(type(item["skip_reason"]) is str and bool(item["skip_reason"]),
                     "invalid_skip_reason")
            version = None
            skipped.append(name)
        else:
            _keys(item, ("name", "version", "vulns"), "invalid_dependency")
            name, version = _name(item["name"]), _token(item["version"])
            _require(type(item["vulns"]) is list, "invalid_vulnerabilities")
            for vulnerability in item["vulns"]:
                _keys(vulnerability, ("id", "fix_versions", "aliases", "description"),
                      "invalid_vulnerability")
                identifier = _token(vulnerability["id"])
                fixes, aliases = _tokens(vulnerability["fix_versions"]), _tokens(vulnerability["aliases"])
                _require(type(vulnerability["description"]) is str, "invalid_description")
                # Advisory feeds can repeat an ID with different aliases/fixes.
                # Preserve every record in the raw artifact; union summary data.
                key = (name, identifier)
                if key not in findings:
                    findings[key] = {"name": name, "version": version, "id": identifier,
                                     "aliases": set(), "fix_versions": set(), "occurrences": 0}
                findings[key]["aliases"].update(aliases)
                findings[key]["fix_versions"].update(fixes)
                findings[key]["occurrences"] += 1
                records += 1
        _require(name not in dependencies, "duplicate_report_dependency")
        dependencies[name] = version
    ordered = []
    for key in sorted(findings):
        finding = findings[key]
        finding["aliases"] = sorted(finding["aliases"])
        finding["fix_versions"] = sorted(finding["fix_versions"])
        ordered.append(finding)
    return dependencies, sorted(skipped), ordered, records


def _summary(profile, scanner_exit, inventory_exit):
    _require(profile in PROFILES, "invalid_profile")
    return {"schema": 1, "profile": profile,
            "policy": "blocking" if profile == "current" else "informational-findings",
            "status": "invalid", "complete": False,
            "scanner_exit": scanner_exit if type(scanner_exit) is int else None,
            "inventory_exit": inventory_exit if type(inventory_exit) is int else None,
            "expected_dependencies": None, "reported_dependencies": None,
            "audited_dependencies": 0, "skipped_dependencies": [],
            "missing_dependencies": [], "unexpected_dependencies": [],
            "version_mismatches": [], "vulnerable_dependencies": 0,
            "vulnerability_records": 0, "vulnerabilities": 0,
            "findings": [], "problems": [], "exit_code": 2}


def _log(text):
    _require(type(text) is str, "invalid_text")
    _require(len(text) <= MAX_LOG_BYTES, "oversized")
    try:
        encoded = text.encode("utf-8")
    except UnicodeError:
        raise AuditError("invalid_text") from None
    _require(len(encoded) <= MAX_LOG_BYTES, "oversized")
    _require(all(char.isprintable() or char in "\n\r\t" for char in text), "invalid_text")
    # These pinned commands have no legitimate WARNING/ERROR diagnostics on a
    # complete audit. In particular, pip may omit broken metadata with exit 0.
    return re.search(r"\b(?:warning|error|critical|fatal)\b", text, re.IGNORECASE) is not None


def evaluate(report, inventory, scanner_exit, profile, *, inventory_log, scanner_log, inventory_exit):
    """Return a safe summary; only complete compatibility findings are nonblocking.

    Exit 0: clean, or complete findings under the explicit compat policy.
    Exit 1: complete current-profile findings.
    Exit 2: an invalid, incomplete, skipped or failed audit in either profile.
    """
    result = _summary(profile, scanner_exit, inventory_exit)
    try:
        _require(type(scanner_exit) is int, "invalid_scanner_exit")
        _require(type(inventory_exit) is int, "invalid_inventory_exit")
        expected = _inventory(inventory)
        result["expected_dependencies"] = len(expected)
        actual, skipped, findings, records = _report(report)
    except AuditError as error:
        result["problems"] = [str(error)]
        return result
    result.update(reported_dependencies=len(actual), audited_dependencies=len(actual) - len(skipped),
                  skipped_dependencies=skipped, findings=findings, vulnerability_records=records,
                  vulnerabilities=len(findings),
                  vulnerable_dependencies=len({finding["name"] for finding in findings}),
                  missing_dependencies=sorted(set(expected) - set(actual)),
                  unexpected_dependencies=sorted(set(actual) - set(expected)),
                  version_mismatches=sorted(name for name in set(expected) & set(actual)
                                            if actual[name] is not None and actual[name] != expected[name]))
    if inventory_exit != 0:
        result.update(status="inventory_error", problems=["inventory_exit_error"])
        return result
    if scanner_exit not in (0, 1):
        result.update(status="scanner_error", problems=["scanner_exit_error"])
        return result
    for name, text in (("inventory", inventory_log), ("scanner", scanner_log)):
        try:
            diagnostics = _log(text)
        except AuditError as error:
            result["problems"] = [name + "_log_" + str(error)]
            return result
        if diagnostics:
            result["problems"].append(name + "_log_diagnostics")
    for field in ("skipped_dependencies", "missing_dependencies", "unexpected_dependencies", "version_mismatches"):
        if result[field]:
            result["problems"].append(field)
    if result["problems"]:
        result["status"] = "incomplete"
        return result
    if scanner_exit != int(bool(findings)):
        result.update(status="scanner_error", problems=["scanner_exit_mismatch"])
        return result
    result.update(status="findings" if findings else "clean", complete=True,
                  exit_code=int(bool(findings) and profile == "current"))
    return result


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def _constant(_value):
    raise AuditError("nonfinite_json")


def _read(path, limit, suffix):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            _require(stat.S_ISREG(os.fstat(descriptor).st_mode), "unreadable_" + suffix)
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                data = stream.read(limit + 1)
        finally:
            os.close(descriptor)
    except (OSError, ValueError):
        raise AuditError("unreadable_" + suffix) from None
    _require(len(data) <= limit, "oversized_" + suffix)
    return data


def read_json(path):
    """Bound the input and reject duplicate keys or nonstandard JSON constants."""
    try:
        data = _read(path, MAX_JSON_BYTES, "json")
        return json.loads(data.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
    except AuditError:
        raise
    except (ValueError, RecursionError):
        raise AuditError("invalid_json") from None


def read_log(path):
    """Read explicit diagnostic evidence without copying raw text to a summary."""
    data = _read(path, MAX_LOG_BYTES, "log")
    try:
        return data.decode("utf-8")
    except UnicodeError:
        raise AuditError("invalid_log_encoding") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, choices=PROFILES)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--scanner-exit", required=True, type=int)
    parser.add_argument("--inventory-log", required=True, type=Path)
    parser.add_argument("--scanner-log", required=True, type=Path)
    parser.add_argument("--inventory-exit", required=True, type=int)
    args = parser.parse_args(argv)
    inputs = {}
    for kind, path, reader in (("inventory", args.inventory, read_json), ("report", args.report, read_json),
                               ("inventory_log", args.inventory_log, read_log), ("scanner_log", args.scanner_log, read_log)):
        try:
            inputs[kind] = reader(path)
        except AuditError as error:
            result = _summary(args.profile, args.scanner_exit, args.inventory_exit)
            result["problems"] = [kind + "_" + str(error)]
            if kind == "report" and str(error) == "unreadable_json":
                result["status"] = "scanner_error"
            break
    else:
        result = evaluate(inputs["report"], inputs["inventory"], args.scanner_exit, args.profile,
                          inventory_log=inputs["inventory_log"], scanner_log=inputs["scanner_log"],
                          inventory_exit=args.inventory_exit)
    print(json.dumps(result, indent=2, sort_keys=True))
    return result["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
