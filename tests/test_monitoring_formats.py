"""Public monitoring contracts: omission, ordering, escaping and discovery safety."""
import copy
import json
import unittest
from unittest.mock import patch

from cgp_cert_manager import core, monitoring_formats as formats


def snapshot():
    return {
        "schema": 1, "generated_at": 1700000000.25, "complete": True,
        "sources": {name: {"status": "ok"} for name in formats.SOURCES},
        "pending": {"transactions": 2, "resolutions": 1, "dns_challenges": 0},
        "domains": [
            {"domain": "z.example.com", "cert_name": "lineage-z", "enabled": False,
             "in_inventory": False, "local_certificate": {"status": "missing"},
             "last_success": None, "failures": None, "retry_at": None},
            {"domain": "a.example.com", "cert_name": "lineage-a", "enabled": True,
             "in_inventory": True,
             "local_certificate": {"status": "ok", "not_after": 1800000000.0},
             "last_success": 1699999999.5, "failures": 0, "retry_at": 0},
        ],
    }


class MonitoringFormatTests(unittest.TestCase):
    def samples(self, text):
        return [line for line in text.splitlines() if not line.startswith("#")]

    def test_complete_snapshot_preserves_meaning_and_publishes_only_allowlist(self):
        data = snapshot()
        data["sources"]["state"]["mtime"] = 1699999990.0
        data["config"] = {"password": "PASSWORD_MUST_NOT_ESCAPE"}
        data["pending"]["secret"] = "KEY_MUST_NOT_ESCAPE"
        data["domains"][1].update(result="RAW_ERROR_MUST_NOT_ESCAPE",
                                  fingerprint="CERTIFICATE_HASH_MUST_NOT_ESCAPE",
                                  private_key="PRIVATE_KEY_MUST_NOT_ESCAPE")
        before = copy.deepcopy(data)
        with patch.object(formats, "__version__", "2.2.0.dev-test"):
            text = formats.prometheus(data)
        self.assertEqual(data, before)
        self.assertTrue(text.endswith("\n"))
        self.assertIn('cgp_manager_build_info{version="2.2.0.dev-test"} 1\n', text)
        self.assertIn("cgp_manager_collection_success 1\n", text)
        self.assertIn("cgp_manager_collection_timestamp_seconds 1700000000.25\n", text)
        self.assertIn('cgp_manager_source_mtime_seconds{source="state"} 1699999990.0\n', text)
        self.assertIn('cgp_manager_pending_artifacts{kind="transactions"} 2\n', text)
        self.assertIn('cgp_manager_pending_artifacts{kind="resolutions"} 1\n', text)
        self.assertIn('cgp_manager_pending_artifacts{kind="dns_challenges"} 0\n', text)
        self.assertIn('cgp_manager_domain_enabled{domain="z.example.com"} 0\n', text)
        self.assertIn('cgp_manager_domain_in_inventory{domain="a.example.com"} 1\n', text)
        self.assertIn('cgp_manager_local_certificate_status{domain="z.example.com",status="missing"} 1\n', text)
        self.assertIn('cgp_manager_local_certificate_not_after_timestamp_seconds{domain="a.example.com"} 1800000000.0\n', text)
        self.assertIn('cgp_manager_last_success_timestamp_seconds{domain="a.example.com"} 1699999999.5\n', text)
        self.assertIn('cgp_manager_recorded_failures{domain="a.example.com"} 0\n', text)
        self.assertIn('cgp_manager_retry_timestamp_seconds{domain="a.example.com"} 0\n', text)
        self.assertNotIn("MUST_NOT_ESCAPE", text)
        self.assertNotIn("fingerprint", text)
        self.assertNotIn('cgp_manager_last_success_timestamp_seconds{domain="z.example.com"}', text)
        self.assertNotIn('cgp_manager_local_certificate_not_after_timestamp_seconds{domain="z.example.com"}', text)
        self.assertLess(text.index('cert_name="lineage-a"'), text.index('cert_name="lineage-z"'))

    def test_partial_snapshot_omits_unknown_quantities_and_exposes_fixed_failure_statuses(self):
        data = snapshot()
        data["complete"] = False
        data["sources"]["config"]["status"] = "error"
        data["sources"]["inventory"]["status"] = "missing"
        data["sources"]["lock"]["status"] = "busy"
        data["pending"] = {kind: None for kind in formats.PENDING_KINDS}
        data["domains"][0]["in_inventory"] = None
        data["domains"][1]["local_certificate"] = {"status": "error"}
        text = formats.prometheus(data)
        self.assertIn("cgp_manager_collection_success 0\n", text)
        for source, state in (("config", "error"), ("inventory", "missing"), ("lock", "busy")):
            self.assertIn('cgp_manager_source_status{source="' + source + '",status="' + state + '"} 1\n', text)
        samples = self.samples(text)
        self.assertFalse(any(line.startswith("cgp_manager_pending_artifacts") for line in samples))
        self.assertFalse(any(line.startswith("cgp_manager_local_certificate_not_after") for line in samples))
        self.assertNotIn('cgp_manager_domain_in_inventory{domain="z.example.com"}', text)
        self.assertIn('cgp_manager_local_certificate_status{domain="a.example.com",status="error"} 1', samples)

    def test_metrics_group_metadata_have_unique_series_and_no_sample_timestamps(self):
        text = formats.prometheus(snapshot())
        helped, typed, series, finished = set(), set(), set(), set()
        current = None
        for line in text.splitlines():
            if line.startswith("#"):
                parts = line.split(" ", 3)
                kind, name = parts[1:3]
                if kind == "HELP":
                    self.assertNotIn(name, helped)
                    helped.add(name)
                else:
                    self.assertEqual(kind, "TYPE")
                    self.assertEqual(parts[3], "gauge")
                    self.assertNotIn(name, typed)
                    typed.add(name)
                continue
            identity, number = line.split(" ")
            float(number)
            self.assertNotIn(identity, series)
            series.add(identity)
            name = identity.split("{", 1)[0]
            self.assertIn(name, helped & typed)
            if name != current:
                self.assertNotIn(name, finished)
                finished.add(current)
                current = name
        self.assertEqual(helped, typed)
        self.assertEqual(len(helped), 14)

    def test_label_escaping_and_stable_order(self):
        data = snapshot()
        data["domains"] = []
        with patch.object(formats, "__version__", 'test\\build"\nline'):
            text = formats.prometheus(data)
        self.assertIn('cgp_manager_build_info{version="test\\\\build\\"\\nline"} 1\n', text)
        with patch.object(formats, "__version__", 'test\\build"\nline'):
            self.assertEqual(text, formats.prometheus(data))

    def test_invalid_numbers_cannot_produce_nonfinite_or_injected_samples(self):
        for value in (True, "0\ninjected 1", None, float("nan"), float("inf"),
                      -float("inf"), 10 ** 400):
            with self.subTest(value=repr(value)):
                data = snapshot()
                data["generated_at"] = value
                with self.assertRaisesRegex(core.Error, "^Invalid monitoring numeric value$"):
                    formats.prometheus(data)

    def test_past_expiry_and_nonzero_failure_count_remain_measurements(self):
        data = snapshot()
        row = data["domains"][1]
        row["local_certificate"]["not_after"] = -10
        row["failures"] = 7
        row["retry_at"] = 1800000001
        text = formats.prometheus(data)
        self.assertIn('cgp_manager_local_certificate_not_after_timestamp_seconds{domain="a.example.com"} -10\n', text)
        self.assertIn('cgp_manager_recorded_failures{domain="a.example.com"} 7\n', text)
        self.assertIn('cgp_manager_retry_timestamp_seconds{domain="a.example.com"} 1800000001\n', text)
        self.assertIn("cgp_manager_collection_success 1\n", text)

    def test_zabbix_native_array_sorted_disabled_included_and_allowlisted(self):
        data = snapshot()
        data["domains"][0]["password"] = "MUST_NOT_ESCAPE"
        result = formats.zabbix_discovery(data)
        self.assertEqual(json.loads(json.dumps(result)), [
            {"{#CGP_DOMAIN}": "a.example.com", "{#CGP_CERT_NAME}": "lineage-a", "{#CGP_ENABLED}": 1},
            {"{#CGP_DOMAIN}": "z.example.com", "{#CGP_CERT_NAME}": "lineage-z", "{#CGP_ENABLED}": 0},
        ])
        self.assertNotIn("MUST_NOT_ESCAPE", json.dumps(result))

    def test_discovery_refuses_every_partial_snapshot_even_with_nonempty_rows(self):
        for rows in ([], snapshot()["domains"]):
            data = snapshot()
            data.update(complete=False, domains=rows)
            with self.assertRaisesRegex(core.Error, "^Monitoring discovery is incomplete$"):
                formats.zabbix_discovery(data)

    def test_complete_empty_inventory_is_an_explicit_empty_discovery(self):
        data = snapshot()
        data["domains"] = []
        self.assertEqual(formats.zabbix_discovery(data), [])
        self.assertIn("cgp_manager_collection_success 1\n", formats.prometheus(data))
