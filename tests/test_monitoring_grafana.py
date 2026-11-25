"""Contracts for the importable, read-only local-monitoring dashboard.

PromQL syntax and data semantics are exercised by real promtool in the assets
CI job; these tests protect the Grafana model and interpretation of each field.
"""
import json
from pathlib import Path
import re
import subprocess
import sys
import unittest

from cgp_cert_manager import monitoring_formats


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "monitoring/grafana/cgp-manager.json"
CHECKER = ROOT / "tests/integration/check_monitoring_assets.py"
DS = {"type": "prometheus", "uid": "${datasource}"}


class GrafanaMonitoringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dashboard = json.loads(DASHBOARD.read_text())
        cls.panels = {panel["id"]: panel for panel in cls.dashboard["panels"]}
        cls.variables = {var["name"]: var for var in cls.dashboard["templating"]["list"]}

    def test_classic_import_metadata_and_version_contract(self):
        data = self.dashboard
        self.assertIsNone(data["id"])
        self.assertEqual(data["schemaVersion"], 39)
        self.assertEqual(data["version"], 1)
        self.assertEqual(data["uid"], "cgp-manager-local")
        self.assertIn("Local monitoring", data["title"])
        requirements = {(value["type"], value["id"]): value for value in data["__requires"]}
        self.assertEqual(requirements[("grafana", "grafana")]["version"], "11.0.0")
        self.assertEqual(data["__inputs"], [{
            "name": "DS_PROMETHEUS", "label": "Prometheus",
            "description": 'Prometheus scraping opted-in node exporter targets with cgp_manager="true".',
            "type": "datasource", "pluginId": "prometheus", "pluginName": "Prometheus"}])
        self.assertIn("Import through the UI", data["description"])

    def test_datasource_input_seeds_a_changeable_dashboard_variable(self):
        source = self.variables["datasource"]
        self.assertEqual(source["type"], "datasource")
        self.assertEqual(source["query"], "prometheus")
        self.assertEqual(source["current"]["value"], "${DS_PROMETHEUS}")
        self.assertFalse(source["multi"])
        for panel in self.panels.values():
            if panel["type"] != "text":
                self.assertEqual(panel["datasource"], DS)
                for target in panel["targets"]:
                    self.assertEqual(target["datasource"], DS)
        for name in ("job", "instance", "domain"):
            self.assertEqual(self.variables[name]["datasource"], DS)

    def test_expected_targets_remain_selectable_without_manager_metrics(self):
        self.assertEqual(list(self.variables), ["datasource", "job", "instance", "domain"])
        self.assertEqual(self.variables["job"]["query"]["query"],
                         'query_result(group by (job) (up{cgp_manager="true"}))')
        self.assertEqual(self.variables["instance"]["query"]["query"],
                         'query_result(group by (instance) (up{cgp_manager="true",job=~"${job:regex}"}))')
        self.assertIn("cgp_manager_domain_info", self.variables["domain"]["query"]["query"])
        self.assertNotIn("domain=~", self.variables["domain"]["query"]["query"])
        for name in ("job", "instance", "domain"):
            variable = self.variables[name]
            self.assertTrue(variable["multi"])
            self.assertTrue(variable["includeAll"])
            self.assertEqual(variable["allValue"], ".*")
            self.assertEqual(variable["query"]["qryType"], 3)
            self.assertEqual(variable["definition"], variable["query"]["query"])
            self.assertEqual(variable["refresh"], 1)

    def test_panel_ids_grid_bounds_and_nonoverlapping_layout(self):
        self.assertEqual(len(self.panels), len(self.dashboard["panels"]))
        self.assertEqual(set(self.panels), set(range(1, 12)))
        rectangles = []
        for panel in self.panels.values():
            grid = panel["gridPos"]
            self.assertTrue(all(type(grid[k]) is int for k in ("x", "y", "w", "h")))
            x, y, width, height = (grid[k] for k in ("x", "y", "w", "h"))
            self.assertGreaterEqual(x, 0)
            self.assertGreaterEqual(y, 0)
            self.assertGreater(width, 0)
            self.assertGreater(height, 0)
            self.assertLessEqual(x + width, 24)
            for ox, oy, ow, oh in rectangles:
                self.assertTrue(x >= ox + ow or ox >= x + width or
                                y >= oy + oh or oy >= y + height, panel["title"])
            rectangles.append((x, y, width, height))

    def test_every_selector_is_scoped_and_uses_only_exported_metrics(self):
        snapshot = {"complete": True, "generated_at": 1, "pending": {
            kind: 0 for kind in monitoring_formats.PENDING_KINDS},
            "sources": {source: {"status": "ok", "mtime": 1}
                        for source in monitoring_formats.SOURCES},
            "domains": [{"domain": "example.test", "cert_name": "example.test", "enabled": True,
                         "in_inventory": True, "local_certificate": {"status": "ok", "not_after": 2},
                         "last_success": 1, "failures": 0, "retry_at": 0}]}
        known = set(re.findall(r"^# HELP (\w+) ", monitoring_formats.prometheus(snapshot), re.M)) | {"up"}
        expressions = [target["expr"] for panel in self.panels.values()
                       for target in panel.get("targets", [])]
        expressions += [var["query"]["query"] for var in self.variables.values() if var["type"] == "query"]
        for expression in expressions:
            for name in ("job", "instance", "domain"):
                expression = expression.replace("${" + name + ":regex}", ".*")
            self.assertNotIn("$", expression)
            # This inspects metric/label contracts only; real promtool parses PromQL.
            selectors = re.findall(r"\b(cgp_manager_\w+|up)\{([^}]*)\}", expression)
            self.assertTrue(selectors)
            for metric, labels in selectors:
                self.assertIn(metric, known)
                self.assertIn('cgp_manager="true"', labels)
            self.assertNotIn("vector(0)", expression)
            self.assertNotRegex(expression, r"\b(rate|increase|last_over_time)\(")
        for panel in self.panels.values():
            for target in panel.get("targets", []):
                self.assertIn('job=~"${job:regex}"', target["expr"])
                self.assertIn('instance=~"${instance:regex}"', target["expr"])
                if panel["id"] >= 7:
                    self.assertIn('domain=~"${domain:regex}"', target["expr"])

    def test_operational_values_require_fresh_complete_enabled_observations(self):
        for panel_id in (6, 8, 9, 10, 11):
            expression = self.panels[panel_id]["targets"][0]["expr"]
            self.assertIn("and on (job, instance)", expression)
            self.assertRegex(expression, r"up\{[^\n]+?\} == 1")
            self.assertIn(">= 0)", expression)
            self.assertIn("<= 900)", expression)
            self.assertRegex(expression, r"cgp_manager_collection_success\{[^\n]+?\} == 1")
            if panel_id != 6:
                self.assertIn("and on (job, instance, domain)", expression)
                self.assertRegex(expression, r"cgp_manager_domain_enabled\{[^\n]+?\} == 1")
        self.assertIn('status="ok"', self.panels[8]["targets"][0]["expr"])
        # Diagnostic panels must still explain an incomplete or stale collection.
        for panel_id in (5, 7):
            self.assertNotIn("collection_success", self.panels[panel_id]["targets"][0]["expr"])
        for panel_id in (3, 4):
            self.assertNotIn("<= 900", self.panels[panel_id]["targets"][0]["expr"])
        self.assertNotIn("clamp_min", self.panels[4]["targets"][0]["expr"])

    def test_nulls_and_gaps_never_become_healthy_zeroes(self):
        for panel in self.panels.values():
            if panel["type"] == "text":
                continue
            defaults = panel["fieldConfig"]["defaults"]
            self.assertEqual(defaults["noValue"], "Unknown")
            null = next(value for value in defaults["mappings"] if value["type"] == "special")
            self.assertEqual(null["options"], {"match": "null", "result": {"text": "Unknown", "color": "gray"}})
            if panel["type"] == "stat":
                self.assertEqual(panel["options"]["reduceOptions"]["calcs"], ["last"])
                self.assertTrue(panel["targets"][0]["instant"])
                self.assertFalse(panel["targets"][0]["range"])
        history = self.panels[9]
        self.assertFalse(history["fieldConfig"]["defaults"]["custom"]["spanNulls"])
        self.assertEqual(history["options"]["legend"]["calcs"], [])
        self.assertTrue(history["targets"][0]["range"])
        self.assertFalse(history["targets"][0]["instant"])
        self.assertNotIn('"green"', json.dumps(self.dashboard))

    def test_expiry_units_and_warning_boundaries_match_alert_contract(self):
        expiry = self.panels[8]
        self.assertIn("ceil((cgp_manager_local_certificate_not_after_timestamp_seconds", expiry["targets"][0]["expr"])
        self.assertIn("/ 86400)", expiry["targets"][0]["expr"])
        field = expiry["fieldConfig"]["defaults"]
        self.assertEqual(field["unit"], "d")
        self.assertEqual(field["decimals"], 0)
        self.assertEqual(field["thresholds"]["steps"], [
            {"color": "red", "value": None}, {"color": "orange", "value": 8},
            {"color": "blue", "value": 22}])
        self.assertEqual(self.panels[4]["fieldConfig"]["defaults"]["unit"], "s")
        self.assertIn("exactly 900 seconds remains eligible", self.panels[4]["description"])
        self.assertEqual(self.panels[4]["fieldConfig"]["defaults"]["thresholds"]["steps"][0],
                         {"color": "red", "value": None})
        self.assertEqual(self.panels[10]["fieldConfig"]["defaults"]["unit"], "s")
        retry = self.panels[11]
        self.assertEqual(retry["fieldConfig"]["defaults"]["unit"], "dateTimeAsIso")
        self.assertIn(" * 1000", retry["targets"][0]["expr"])
        self.assertEqual(retry["fieldConfig"]["defaults"]["mappings"][1]["options"]["0"]["text"], "Cleared")

    def test_local_scope_and_saved_state_limitations_are_visible(self):
        banner = self.panels[1]["options"]["content"]
        self.assertEqual(self.panels[1]["options"]["mode"], "markdown")
        self.assertIn("not the certificate served by CGP", banner)
        self.assertIn("Unknown / No data", banner)
        self.assertIn("enabled domains", banner)
        self.assertIn("may overlap", self.panels[6]["description"])
        self.assertIn("not a cumulative counter", self.panels[9]["description"])
        self.assertIn("unchanged check", self.panels[10]["description"])
        self.assertIn("not a promise", self.panels[11]["description"])

    def test_import_creates_no_schedules_alerts_links_or_actions(self):
        self.assertEqual(self.dashboard["refresh"], "")
        self.assertEqual(self.dashboard["timepicker"]["refresh_intervals"], [])
        self.assertEqual(self.dashboard["annotations"]["list"], [])
        self.assertEqual(self.dashboard["links"], [])
        text = json.dumps(self.dashboard)
        for field in ('"url":', '"alert":', '"actions":', '"alertRule":', '"libraryPanel":'):
            self.assertNotIn(field, text)
        for panel in self.panels.values():
            self.assertIn(panel["type"], ("text", "stat", "table", "timeseries"))

    def test_real_promtool_fixture_covers_all_queries_and_failure_semantics(self):
        output = subprocess.run([sys.executable, str(CHECKER)], check=True, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        fixture = json.loads(output.stdout)
        self.assertEqual(output.stderr, "")
        self.assertEqual(fixture["rule_files"], [])
        cases = fixture["tests"]
        self.assertEqual(len(cases), 17)
        empty = cases[0]
        self.assertEqual(empty["input_series"], [])
        self.assertEqual(len(empty["promql_expr_test"]), 13)
        self.assertTrue(all(entry["exp_samples"] == [] for entry in empty["promql_expr_test"]))
        for case in cases:
            for entry in case["promql_expr_test"]:
                self.assertNotIn("$", entry["expr"])
                self.assertNotIn("query_result", entry["expr"])
                self.assertEqual(entry["eval_time"], "1h")
        names = " ".join(case["name"] for case in cases)
        for meaning in ("without manager metrics", "exporter down", "future timestamp", "901 second", "900 second",
                        "read error", "missing local leaf", "disabled domain", "missing saved fields",
                        "cleared retry", "cross-host", "selection", "same instance in different jobs",
                        "different enabled domain", "7 and 21 day"):
            self.assertIn(meaning, names)
        shared = next(case for case in cases if "same instance in different jobs" in case["name"])
        shared_targets = [row["series"] for row in shared["input_series"] if row["series"].startswith("up{")]
        self.assertEqual(len(shared_targets), 2)
        self.assertTrue(all('instance="shared:9100"' in row for row in shared_targets))
        self.assertTrue(any('job="primary"' in row for row in shared_targets))
        self.assertTrue(any('job="secondary"' in row for row in shared_targets))
        mismatch = next(case for case in cases if "different enabled domain" in case["name"])
        for entry in mismatch["promql_expr_test"]:
            if "cgp_manager_domain_enabled" in entry["expr"]:
                self.assertEqual(entry["exp_samples"], [])


if __name__ == "__main__":
    unittest.main()
