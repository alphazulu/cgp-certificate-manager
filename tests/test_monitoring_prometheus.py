"""Artifact contracts only; the pinned real promtool evaluates the PromQL in CI."""
from pathlib import Path
import re
import unittest

import yaml

from cgp_cert_manager import monitoring_formats


ASSETS = Path(__file__).resolve().parents[1] / "monitoring" / "prometheus"
FIRING_COUNT = 'count(ALERTS{component="cgp-certificate-manager", alertstate="firing"})'


class PrometheusArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = yaml.safe_load((ASSETS / "alerts.yml").read_text())
        cls.fixtures = yaml.safe_load((ASSETS / "alerts.test.yml").read_text())
        cls.rows = [row for group in cls.rules["groups"] for row in group["rules"]]
        cls.alerts = {row["alert"]: row for row in cls.rows if "alert" in row}

    def test_rules_have_unique_identifiers_and_resolvable_recording_dependencies(self):
        seen = set()
        self.assertEqual(set(self.rules), {"groups"})
        for group in self.rules["groups"]:
            self.assertEqual(set(group), {"name", "interval", "rules"})
            self.assertEqual(group["interval"], "1m")
            for row in group["rules"]:
                self.assertEqual(int("record" in row) + int("alert" in row), 1)
                name = row.get("record", row.get("alert"))
                self.assertNotIn(name, seen)
                references = set(re.findall(r"\bcgp_manager:[a-z_]+\b", row["expr"]))
                self.assertLessEqual(references, seen)
                seen.add(name)
                self.assertIsInstance(row["expr"], str)
                self.assertTrue(row["expr"].strip())

    def test_raw_metric_selectors_are_exported_and_explicitly_opted_in(self):
        snapshot = {
            "complete": False, "generated_at": 1,
            "sources": {name: {"status": "missing"}
                        for name in monitoring_formats.SOURCES},
            "pending": dict.fromkeys(monitoring_formats.PENDING_KINDS),
            "domains": [],
        }
        exported = set(re.findall(r"^# TYPE (\w+) gauge$",
                                  monitoring_formats.prometheus(snapshot), re.MULTILINE))
        used = set()
        for row in self.rows:
            expression = row["expr"]
            for match in re.finditer(r"\b(cgp_manager_[a-z_]+|up)\b", expression):
                metric = match.group()
                self.assertIn(metric, exported | {"up"})
                selector = re.match(r"\s*\{([^}]*)\}", expression[match.end():])
                self.assertIsNotNone(selector, msg="Unscoped metric: " + metric)
                self.assertRegex(selector.group(1), r'(?:^|,)\s*cgp_manager="true"\s*(?:,|$)')
                used.add(metric)
        self.assertIn("up", used)
        self.assertIn("cgp_manager_collection_success", used)
        self.assertIn("cgp_manager_collection_timestamp_seconds", used)
        self.assertIn("cgp_manager_local_certificate_status", used)
        self.assertNotIn("cgp_manager_retry_timestamp_seconds", used)

    def test_all_source_gate_tracks_exact_public_source_contract(self):
        row = next(row for row in self.rows
                   if row.get("record") == "cgp_manager:local_sources_complete")
        source_pattern = re.search(r'source=~"([a-z_|]+)"', row["expr"]).group(1)
        self.assertEqual(set(source_pattern.split("|")), set(monitoring_formats.SOURCES))
        count = len(monitoring_formats.SOURCES)
        self.assertRegex(row["expr"], r"== " + str(count) + r"\) / " + str(count))

    def test_alerts_distinguish_observation_local_certificate_and_saved_history(self):
        self.assertEqual(len(self.alerts), 13)
        for name, row in self.alerts.items():
            self.assertEqual(set(row), {"alert", "expr", "for", "labels", "annotations"})
            self.assertEqual(set(row["labels"]), {"component", "scope", "severity"})
            self.assertEqual(row["labels"]["component"], "cgp-certificate-manager")
            self.assertIn(row["labels"]["severity"], {"info", "warning", "critical"})
            self.assertIn(row["labels"]["scope"], {
                "observation", "local_certificate", "retained_artifacts", "historical"})
            self.assertEqual(set(row["annotations"]), {"summary", "description"})
            self.assertTrue(all(row["annotations"].values()))
            delay = "15m" if name in {
                "CGPManagerCollectionBusy", "CGPManagerPendingArtifacts",
                "CGPManagerRecordedFailure"} else "5m"
            self.assertEqual(row["for"], delay)
        historical = self.alerts["CGPManagerRecordedFailure"]
        self.assertEqual(historical["labels"]["scope"], "historical")
        self.assertEqual(historical["labels"]["severity"], "info")
        self.assertEqual(self.alerts["CGPManagerLocalCertificateReadError"]
                         ["labels"]["scope"], "observation")
        self.assertEqual(self.alerts["CGPManagerLocalCertificateExpiryCritical"]
                         ["labels"]["scope"], "local_certificate")

    def test_real_promtool_fixture_entrypoint_and_named_scenarios(self):
        self.assertEqual(set(self.fixtures), {"rule_files", "evaluation_interval", "tests"})
        self.assertEqual(self.fixtures["rule_files"], ["alerts.yml"])
        self.assertEqual(self.fixtures["evaluation_interval"], "1m")
        names = [case["name"] for case in self.fixtures["tests"]]
        self.assertEqual(len(names), len(set(names)))
        self.assertGreaterEqual(len(names), 25)
        self.assertLessEqual({
            "healthy_snapshot_and_legitimate_future_retry",
            "disabled_domains_do_not_raise_certificate_or_historical_alerts",
            "expected_targets_with_absent_or_partial_metadata",
            "no_expected_target_no_fictional_absence_or_certificate_alert",
            "freshness_lower_boundary_zero_age",
            "freshness_upper_boundary_900_seconds_inclusive",
            "snapshot_901_seconds_old_suppresses_operational_alerts",
            "future_timestamp_one_second_is_not_fresh",
            "busy_collection_waits_fifteen_minutes_without_false_failure",
            "explicit_local_read_error_is_observation_failure_on_incomplete_snapshot",
            "local_read_error_requires_all_seven_noncertificate_sources",
            "expiry_thresholds_are_inclusive_and_warning_is_disjoint",
            "retained_artifact_kinds_are_independent_not_a_unique_operation_total",
            "saved_failure_is_informational_history_not_current_tls_failure",
            "multihost_multijob_and_multidomain_gates_do_not_cross_contaminate",
        }, set(names))

    def test_each_alert_has_real_positive_fixture_and_no_unlisted_companion_alerts(self):
        covered = set()
        for case in self.fixtures["tests"]:
            total = 0
            at = set()
            for assertion in case.get("alert_rule_test", []):
                name = assertion["alertname"]
                self.assertIn(name, self.alerts)
                self.assertTrue(assertion["exp_alerts"])
                covered.add(name)
                at.add(assertion["eval_time"])
                total += len(assertion["exp_alerts"])
                for expected in assertion["exp_alerts"]:
                    labels = expected["exp_labels"]
                    self.assertTrue(labels["job"])
                    self.assertTrue(labels["instance"])
                    self.assertEqual(expected["exp_annotations"], self.alerts[name]["annotations"])
                    for key, value in self.alerts[name]["labels"].items():
                        self.assertEqual(labels[key], value)
            checks = [check for check in case["promql_expr_test"]
                      if check["expr"] == FIRING_COUNT]
            self.assertEqual(len(checks), 1)
            check = checks[0]
            self.assertEqual(check["exp_samples"],
                             [{"labels": "{}", "value": total}] if total else [])
            self.assertLessEqual(at, {check["eval_time"]})
        self.assertEqual(covered, set(self.alerts))

    def test_fixtures_have_unique_series_and_explicit_missing_data_cases(self):
        absent_status = False
        missing_expiry = False
        for case in self.fixtures["tests"]:
            series = [row["series"] for row in case["input_series"]]
            self.assertEqual(len(series), len(set(series)), msg=case["name"])
            self.assertEqual(case["interval"], "1m")
            for row in case["input_series"]:
                self.assertEqual(set(row), {"series", "values"})
                self.assertIsInstance(row["values"], str)
                self.assertIn('job="', row["series"])
                self.assertIn('instance="', row["series"])
            if case["name"] == "unknown_certificate_status_and_unknown_counts_do_not_become_zero":
                absent_status = True
                self.assertFalse(any(item.startswith("cgp_manager_local_certificate_status{")
                                     for item in series))
                self.assertFalse(any(item.startswith("cgp_manager_pending_artifacts{")
                                     for item in series))
            if case["name"] == "known_certificate_status_without_expiry_is_not_zero_expiry":
                missing_expiry = True
                self.assertTrue(any(item.startswith("cgp_manager_local_certificate_status{")
                                    for item in series))
                self.assertFalse(any(item.startswith("cgp_manager_local_certificate_not_after")
                                     for item in series))
        self.assertTrue(absent_status)
        self.assertTrue(missing_expiry)

    def test_isolation_fixture_reuses_instance_and_domain_across_different_jobs(self):
        case = next(case for case in self.fixtures["tests"]
                    if case["name"] == "multihost_multijob_and_multidomain_gates_do_not_cross_contaminate")
        targets = set()
        domain_targets = set()
        for row in case["input_series"]:
            labels = dict(re.findall(r'(\w+)="([^"]*)"', row["series"]))
            targets.add((labels["job"], labels["instance"]))
            if "domain" in labels:
                domain_targets.add((labels["job"], labels["instance"], labels["domain"]))
        self.assertIn(("node-a", "one:9100"), targets)
        self.assertIn(("node-b", "one:9100"), targets)
        self.assertIn(("node-a", "two:9100"), targets)
        self.assertIn(("node-c", "two:9100"), targets)
        self.assertIn(("node-a", "four:9100", "example.com"), domain_targets)
        self.assertIn(("node-a", "four:9100", "other.example.com"), domain_targets)


if __name__ == "__main__":
    unittest.main()
