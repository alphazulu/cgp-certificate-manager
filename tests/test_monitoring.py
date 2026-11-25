"""Offline snapshots must preserve unknowns and never recover or disclose data."""

from contextlib import contextmanager
import copy
import fcntl
import json
import math
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

from cgp_cert_manager import core, deployment, dnsauth, monitoring, recovery, resolution, storage
from cgp_cert_manager.transactions import Journal


class MonitoringTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.state = self.root / "state"
        self.config = self.root / "config.json"
        self.credentials = self.root / "cloudflare.ini"
        self.enterContext(patch.object(core, "STATE", self.state))
        self.enterContext(patch.object(core, "CONFIG", self.config))
        self.identity = "f" * 64
        self.enterContext(patch.object(recovery, "server_identity", return_value=self.identity))
        self.cfg = {"schema_version": 2, "domains": [{"cgp_domain": "example.com"}],
                    "communigate": {"url": "http://127.0.0.1:106/CLI/", "password": "PRIVATE_PASSWORD"},
                    "cloudflare_credentials": str(self.credentials)}
        self.inventory = [{"cgp_domain": "example.com", "cert_name": "example.com", "enabled": True}]
        storage.atomic_json(self.config, self.cfg)
        storage.atomic_text(self.credentials, "dns_cloudflare_api_token = PRIVATE_TOKEN\n")
        storage.ensure_private_directory(self.state)
        storage.atomic_text(self.state / "run.lock", "")
        storage.atomic_json(self.state / "domains.json", self.inventory)
        storage.atomic_json(self.state / "state.json", {})
        certificates = types.ModuleType("cgp_cert_manager.monitoring_certificates")
        self.inspect = certificates.inspect = Mock(return_value={"status": "missing"})
        self.enterContext(patch.dict(sys.modules, {certificates.__name__: certificates}))
        self.forbidden = []
        for module, names in ((core, ("cli", "cf", "token", "current", "update", "discover", "issue", "deploy")),
                              (deployment, ("transaction_status", "recover_pending")),
                              (resolution, ("pending_status", "assert_no_incomplete")),
                              (recovery, ("verify_snapshot", "recover")),
                              (dnsauth, ("cleanup_pending",))):
            for name in names:
                blocked = self.enterContext(patch.object(module, name, side_effect=AssertionError("Forbidden operation")))
                self.forbidden.append(blocked)
                self.addCleanup(blocked.assert_not_called)

    def collect(self):
        with patch.object(storage.os, "fsync", side_effect=AssertionError("Unexpected fsync")) as sync, \
                patch.object(storage, "atomic_json", side_effect=AssertionError("Unexpected write")) as write, \
                patch.object(storage, "operation_lock", side_effect=AssertionError("Unexpected creating lock")) as lock:
            snapshot = monitoring.collect(now=1800000000)
        for blocked in (sync, write, lock):
            blocked.assert_not_called()
        serialized = json.dumps(snapshot, allow_nan=False)
        for secret in ("PRIVATE_PASSWORD", "PRIVATE_TOKEN", "PRIVATE_ERROR", "PRIVATE_REASON", "A" * 43):
            self.assertNotIn(secret, serialized)
        self.assertNotIn(str(self.root), serialized)
        return snapshot

    def journal(self, name="pending.example.com", phase="prepared", identity=None):
        journal = Journal(self.state / "transactions")
        settings = dict.fromkeys(core.FIELDS, "[YQ==]")
        settings["CertificateType"] = "YES"
        record = journal.prepare(name, settings, dict(settings, SecureCertificate="[Yg==]"),
                                 [{"port": 443, "sni": name}], identity or self.identity)
        record["phase"] = phase
        storage.atomic_json(journal.path(name), record)
        return journal

    def authorization(self, name="approval.example.com", completed=False, pending=False):
        journal = self.journal(name)
        witness = journal.read_snapshot(name)
        token = resolution._token(witness)
        authorization = {"schema": 1, "decision": resolution.DECISION, "domain": name,
                         "config_identity": self.identity, "confirmation_token": token,
                         "journal": witness["record"], "witness": witness["witness"],
                         "reason": "PRIVATE_REASON", "uid": os.geteuid(),
                         "authorized_at": "2026-11-24T00:00:00+00:00", "tls": "unverified"}
        bundle = self.state / "resolutions" / token
        storage.atomic_json(bundle / "authorization.json", authorization)
        if completed:
            resolution._write_completion(bundle, authorization)
        if not pending:
            journal.path(name).unlink()
        return bundle

    def dns_receipt(self, nonce="a" * 32, phase="created", identity=None):
        path = self.state / "dns-challenges" / (nonce + ".json")
        record = {"schema": 1, "identity": identity or self.identity, "attempt": "b" * 32,
                  "owner": "cgp-certificate-manager:" + nonce,
                  "credentials": str(self.credentials), "zone": "c" * 32,
                  "name": "_acme-challenge.example.com", "value": "A" * 43,
                  "record": None if phase == "intent" else "d" * 32, "phase": phase}
        storage.atomic_json(path, record)
        return path

    def test_complete_empty_pending_snapshot_is_strictly_local_and_preserves_files(self):
        before = {path: (path.read_bytes(), path.stat().st_mtime_ns)
                  for path in self.root.rglob("*") if path.is_file()}
        snapshot = self.collect()
        self.assertEqual(set(snapshot), {"schema", "generated_at", "complete", "sources", "pending", "domains"})
        self.assertEqual(snapshot["schema"], 1)
        self.assertEqual(snapshot["generated_at"], 1800000000.0)
        self.assertIs(snapshot["complete"], True)
        self.assertEqual(snapshot["pending"], dict.fromkeys(monitoring.PENDING, 0))
        self.assertTrue(all(source["status"] == "ok" for source in snapshot["sources"].values()))
        self.assertEqual({name for name, source in snapshot["sources"].items() if "mtime" in source},
                         {"config", "inventory", "state"})
        self.assertEqual(snapshot["domains"], [{"domain": "example.com", "cert_name": "example.com",
            "enabled": True, "in_inventory": True, "local_certificate": {"status": "missing"},
            "last_success": None, "failures": None, "retry_at": None}])
        after = {path: (path.read_bytes(), path.stat().st_mtime_ns)
                 for path in self.root.rglob("*") if path.is_file()}
        self.assertEqual(before, after)

    def test_current_configuration_overrides_cached_policy_and_lineage(self):
        self.cfg.update(auto_enable_new_domains=False, domains=[
            {"cgp_domain": "override.example.com", "cert_name": "current-lineage", "enabled": True},
            {"cgp_domain": "example.com"}, {"cgp_domain": "configured.example.com", "enabled": False}])
        storage.atomic_json(self.config, self.cfg)
        inventory = [{"cgp_domain": name, "cert_name": "obsolete-lineage", "enabled": True}
                     for name in ("cached.example.com", "example.com", "override.example.com")]
        storage.atomic_json(self.state / "domains.json", inventory)
        storage.atomic_json(self.state / "state.json", {
            "example.com": {"last_success": 123.5, "failures": 2, "retry_at": 456,
                            "result": "PRIVATE_ERROR", "alert": "PRIVATE_PASSWORD"},
            "discovery": {"alert": "PRIVATE_ERROR"}})
        self.inspect.return_value = {"status": "ok", "not_after": 1900000000}
        rows = self.collect()["domains"]
        self.assertEqual([row["domain"] for row in rows],
                         ["cached.example.com", "configured.example.com", "example.com", "override.example.com"])
        self.assertEqual([row["cert_name"] for row in rows],
                         ["cached.example.com", "configured.example.com", "example.com", "current-lineage"])
        self.assertEqual([row["enabled"] for row in rows], [False, False, False, True])
        self.assertEqual([row["in_inventory"] for row in rows], [True, False, True, True])
        self.assertEqual((rows[2]["last_success"], rows[2]["failures"], rows[2]["retry_at"]), (123.5, 2, 456))
        self.assertEqual([call.args[0] for call in self.inspect.call_args_list], [row["cert_name"] for row in rows])

    def test_missing_certificate_is_known_absence_but_parse_error_is_incomplete(self):
        self.assertTrue(self.collect()["complete"])
        self.inspect.return_value = {"status": "error"}
        snapshot = self.collect()
        self.assertFalse(snapshot["complete"])
        self.assertTrue(all(source["status"] == "ok" for source in snapshot["sources"].values()))

    def test_absent_state_or_lock_is_not_created_and_quantities_stay_unknown(self):
        with patch.object(core, "STATE", self.root / "not-created"):
            snapshot = self.collect()
        self.assertFalse((self.root / "not-created").exists())
        self.assertFalse(snapshot["complete"])
        self.assertEqual(snapshot["sources"]["lock"], {"status": "missing"})
        self.assertEqual(snapshot["pending"], dict.fromkeys(monitoring.PENDING))
        self.assertIsNone(snapshot["domains"][0]["in_inventory"])
        (self.state / "run.lock").unlink()
        snapshot = self.collect()
        self.assertFalse((self.state / "run.lock").exists())
        self.assertEqual(snapshot["sources"]["state"], {"status": "missing"})
        self.assertIsNone(snapshot["domains"][0]["last_success"])

    def test_busy_lock_skips_saved_state_but_keeps_configured_local_certificates(self):
        with storage.open_private(self.state / "run.lock") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            snapshot = self.collect()
        self.assertFalse(snapshot["complete"])
        for name in ("lock", "inventory", "state", *monitoring.PENDING):
            self.assertEqual(snapshot["sources"][name], {"status": "busy"})
        self.assertEqual(snapshot["pending"], dict.fromkeys(monitoring.PENDING))
        self.inspect.assert_called_once_with("example.com")

    def test_unsafe_lock_or_state_is_an_error_and_is_not_repaired(self):
        for path in (self.state, self.state / "run.lock"):
            mode = path.stat().st_mode & 0o777
            path.chmod(0o755 if path.is_dir() else 0o644)
            snapshot = self.collect()
            self.assertEqual(snapshot["sources"]["lock"], {"status": "error"})
            self.assertEqual(snapshot["pending"], dict.fromkeys(monitoring.PENDING))
            self.assertEqual(path.stat().st_mode & 0o777, 0o755 if path.is_dir() else 0o644)
            path.chmod(mode)

    def test_shared_lock_protects_saved_reads_and_is_released_before_certificate_parsing(self):
        read = monitoring._json
        def read_saved(path):
            if path == self.state / "domains.json":
                with storage.open_private(self.state / "run.lock") as other:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(other.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return read(path)
        def inspect(lineage):
            with storage.open_private(self.state / "run.lock") as other:
                fcntl.flock(other.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return {"status": "missing"}
        self.inspect.side_effect = inspect
        with patch.object(monitoring, "_json", side_effect=read_saved):
            self.assertTrue(self.collect()["complete"])

    def test_missing_inventory_and_state_are_visible_without_inventing_zero_outcomes(self):
        (self.state / "domains.json").unlink()
        (self.state / "state.json").unlink()
        snapshot = self.collect()
        self.assertFalse(snapshot["complete"])
        self.assertEqual(snapshot["sources"]["inventory"], {"status": "missing"})
        self.assertEqual(snapshot["sources"]["state"], {"status": "missing"})
        self.assertEqual(snapshot["pending"], dict.fromkeys(monitoring.PENDING, 0))
        self.assertIsNone(snapshot["domains"][0]["failures"])
        self.assertIsNone(snapshot["domains"][0]["retry_at"])

    def test_invalid_configuration_never_exports_partial_domain_identities(self):
        invalid = [None, [], "PRIVATE_ERROR", {"auto_enable_new_domains": 1}, {"domains": {}},
                   {"domains": [None]}, {"domains": [{"cgp_domain": None}]},
                   {"domains": [{"cgp_domain": "unsafe\nPRIVATE_ERROR"}]},
                   {"domains": [{"cgp_domain": "x" * 254}]},
                   {"domains": [{"cgp_domain": "example.com", "cert_name": "../PRIVATE_PASSWORD"}]},
                   {"domains": [{"cgp_domain": "example.com", "enabled": "true"}]},
                   {"domains": [{"cgp_domain": "example.com"}] * 2}]
        for value in invalid:
            with self.subTest(value=value):
                storage.atomic_json(self.config, value)
                snapshot = self.collect()
                self.assertEqual(snapshot["sources"]["config"], {"status": "error"})
                self.assertEqual(snapshot["domains"], [])
                self.assertFalse(snapshot["complete"])
        self.inspect.assert_not_called()

    def test_missing_configuration_leaves_no_inferred_domains(self):
        self.config.unlink()
        snapshot = self.collect()
        self.assertEqual(snapshot["sources"]["config"], {"status": "missing"})
        self.assertEqual(snapshot["domains"], [])
        self.inspect.assert_not_called()

    def test_strict_bounded_json_rejects_duplicates_nonfinite_encoding_and_trailing_data(self):
        raw_values = (b'{"domains":[],"domains":[]}',
                      b'{"nested":{"PRIVATE_PASSWORD":1,"PRIVATE_PASSWORD":2}}',
                      b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}',
                      b'{"domains":[]}TRAILING', b'\xff', b'{',
                      b'[' * 2000 + b'0' + b']' * 2000,
                      b' ' * (monitoring.MAX_JSON + 1))
        for raw in raw_values:
            with self.subTest(raw=raw[:40]):
                self.config.write_bytes(raw)
                snapshot = self.collect()
                self.assertEqual(snapshot["sources"]["config"], {"status": "error"})
                self.assertEqual(snapshot["domains"], [])
        self.config.write_bytes(b'{}' + b' ' * (monitoring.MAX_JSON - 2))
        self.assertEqual(self.collect()["sources"]["config"]["status"], "ok")

    def test_json_changed_during_read_is_not_reported_as_valid(self):
        open_private = storage.open_private
        @contextmanager
        def changing(path, *args, **kwargs):
            with open_private(path, *args, **kwargs) as stream:
                if path == self.config:
                    buffer = stream.buffer
                    def read(size):
                        data = buffer.read(size)
                        with self.config.open("ab") as update:
                            update.write(b" ")
                        return data
                    yield types.SimpleNamespace(fileno=stream.fileno, buffer=types.SimpleNamespace(read=read))
                else:
                    yield stream
        with patch.object(storage, "open_private", side_effect=changing):
            self.assertEqual(self.collect()["sources"]["config"], {"status": "error"})

    def test_numeric_exponent_overflow_is_rejected_even_in_unused_fields(self):
        sources = (("config", self.config, '{"domains":[],"PRIVATE_ERROR":%s}'),
                   ("inventory", self.state / "domains.json",
                    '[{"cgp_domain":"example.com","PRIVATE_ERROR":%s}]'),
                   ("state", self.state / "state.json",
                    '{"example.com":{"last_success":123.25,"PRIVATE_ERROR":%s}}'))
        for name, path, template in sources:
            original = path.read_bytes()
            for number in ("1e999", "-1e999"):
                with self.subTest(source=name, number=number):
                    path.write_text(template % number)
                    snapshot = self.collect()
                    self.assertEqual(snapshot["sources"][name], {"status": "error"})
                    self.assertFalse(snapshot["complete"])
            path.write_bytes(original)
        for _, path, template in sources:
            path.write_text(template % "1.25")
        snapshot = self.collect()
        self.assertTrue(snapshot["complete"])
        self.assertEqual(snapshot["domains"][0]["last_success"], 123.25)

    def test_json_growing_after_size_check_remains_bounded(self):
        open_private = storage.open_private
        @contextmanager
        def growing(path, *args, **kwargs):
            with open_private(path, *args, **kwargs) as stream:
                if path == self.config:
                    buffer = stream.buffer
                    def read(size):
                        self.assertEqual(size, monitoring.MAX_JSON + 1)
                        with self.config.open("ab") as update:
                            update.write(b" " * monitoring.MAX_JSON)
                        return buffer.read(size)
                    yield types.SimpleNamespace(fileno=stream.fileno, buffer=types.SimpleNamespace(read=read))
                else:
                    yield stream
        with patch.object(storage, "open_private", side_effect=growing):
            self.assertEqual(self.collect()["sources"]["config"], {"status": "error"})

    def test_corrupt_inventory_does_not_hide_current_configured_domains(self):
        storage.atomic_json(self.state / "domains.json", [{"cgp_domain": "bad/PRIVATE_ERROR"}])
        snapshot = self.collect()
        self.assertEqual(snapshot["sources"]["inventory"], {"status": "error"})
        self.assertEqual([row["domain"] for row in snapshot["domains"]], ["example.com"])
        self.assertIsNone(snapshot["domains"][0]["in_inventory"])

    def test_inventory_and_config_limits_prevent_unbounded_certificate_work(self):
        storage.atomic_json(self.state / "domains.json", [{"cgp_domain": "other.example.com"}])
        with patch.object(monitoring, "MAX_ITEMS", 1):
            snapshot = self.collect()
        self.assertEqual(snapshot["sources"]["inventory"], {"status": "error"})
        self.assertEqual([row["domain"] for row in snapshot["domains"]], ["example.com"])
        self.assertIsNone(snapshot["domains"][0]["in_inventory"])
        self.cfg["domains"].append({"cgp_domain": "other.example.com"})
        storage.atomic_json(self.config, self.cfg)
        with patch.object(monitoring, "MAX_ITEMS", 1):
            self.assertEqual(self.collect()["sources"]["config"], {"status": "error"})

    def test_invalid_state_quantities_remain_unknown_and_do_not_leak_results(self):
        cases = [[], {"example.com": []}, {"bad\nname": {}},
                 *({"example.com": {key: value, "result": "PRIVATE_ERROR"}}
                   for key, value in (("last_success", True), ("last_success", -1),
                                      ("last_success", math.inf), ("failures", 1.5),
                                      ("failures", "PRIVATE_PASSWORD"), ("retry_at", -5)))]
        for value in cases:
            with self.subTest(value=value):
                storage.atomic_json(self.state / "state.json", value)
                snapshot = self.collect()
                self.assertEqual(snapshot["sources"]["state"], {"status": "error"})
                self.assertTrue(all(snapshot["domains"][0][key] is None
                                    for key in ("last_success", "failures", "retry_at")))
        storage.atomic_json(self.state / "state.json", {"example.com": {}, "other.example.com": {}})
        with patch.object(monitoring, "MAX_ITEMS", 1):
            self.assertEqual(self.collect()["sources"]["state"], {"status": "error"})

    def test_pending_counts_include_terminal_journals_and_foreign_transactions(self):
        for index, phase in enumerate(("prepared", "applying", "applied", "verifying", "restoring", "committed", "restored")):
            self.journal(f"pending{index}.example.com", phase=phase, identity="foreign-server")
        snapshot = self.collect()
        self.assertTrue(snapshot["complete"])
        self.assertEqual(snapshot["pending"]["transactions"], 7)
        self.assertEqual([row["domain"] for row in snapshot["domains"]], ["example.com"])

    def test_pending_resolution_counts_incomplete_authorizations_without_deduplication(self):
        self.authorization("with-journal.example.com", pending=True)
        self.authorization("without-journal.example.com")
        self.authorization("finished.example.com", completed=True)
        storage.ensure_private_directory(self.state / "resolutions" / ("e" * 64))
        snapshot = self.collect()
        self.assertTrue(snapshot["complete"])
        self.assertEqual(snapshot["pending"], {"transactions": 1, "resolutions": 2, "dns_challenges": 0})

    def test_pending_dns_count_includes_borrowed_intent_and_complete_receipts(self):
        for index, phase in enumerate(("intent", "created", "borrowed", "complete")):
            self.dns_receipt(f"{index:032x}", phase)
        snapshot = self.collect()
        self.assertTrue(snapshot["complete"])
        self.assertEqual(snapshot["pending"]["dns_challenges"], 4)

    def test_corrupt_pending_source_never_becomes_zero(self):
        journal = self.journal()
        storage.atomic_text(journal.path("pending.example.com"), "PRIVATE_ERROR")
        bundle = self.authorization()
        storage.atomic_json(bundle / "authorization.json", None)
        path = self.dns_receipt()
        path.chmod(0o644)
        snapshot = self.collect()
        self.assertFalse(snapshot["complete"])
        self.assertEqual(snapshot["pending"], dict.fromkeys(monitoring.PENDING))
        for name in monitoring.PENDING:
            self.assertEqual(snapshot["sources"][name], {"status": "error"})

    def test_foreign_dns_receipt_is_unknown_not_zero_or_deleted(self):
        path = self.dns_receipt(identity="foreign-server")
        before = path.read_bytes()
        snapshot = self.collect()
        self.assertEqual(snapshot["sources"]["dns_challenges"], {"status": "error"})
        self.assertIsNone(snapshot["pending"]["dns_challenges"])
        self.assertEqual(path.read_bytes(), before)

    def test_disappearing_transaction_is_unknown(self):
        self.journal()
        with patch.object(Journal, "read", return_value=None):
            snapshot = self.collect()
        self.assertIsNone(snapshot["pending"]["transactions"])
        self.assertEqual(snapshot["sources"]["transactions"], {"status": "error"})

    def test_pending_source_limits_bound_counts_files_and_total_bytes(self):
        self.journal("one.example.com")
        self.journal("two.example.com")
        self.authorization("one-approval.example.com")
        self.authorization("two-approval.example.com")
        self.dns_receipt("a" * 32)
        self.dns_receipt("b" * 32)
        with patch.object(monitoring, "MAX_ITEMS", 1):
            snapshot = self.collect()
        self.assertEqual(snapshot["pending"], dict.fromkeys(monitoring.PENDING))
        with patch.object(monitoring, "MAX_FILES", 1):
            snapshot = self.collect()
        self.assertEqual(snapshot["pending"], dict.fromkeys(monitoring.PENDING))
        with patch.object(monitoring, "MAX_SOURCE_BYTES", 1):
            snapshot = self.collect()
        self.assertEqual(snapshot["pending"], dict.fromkeys(monitoring.PENDING))
        path = self.state / "transactions" / "one.example.com.json"
        path.write_bytes(b" " * (monitoring.MAX_JSON + 1))
        self.assertIsNone(self.collect()["pending"]["transactions"])

    def test_invalid_generated_time_is_rejected_and_default_time_is_observation_only(self):
        for now in (True, -1, math.nan, math.inf, "PRIVATE_ERROR"):
            with self.subTest(now=now), self.assertRaises(ValueError):
                monitoring.collect(now=now)
        with patch.object(monitoring.time, "time", return_value=123.5):
            snapshot = monitoring.collect()
        self.assertEqual(snapshot["generated_at"], 123.5)
        self.assertIsNone(snapshot["domains"][0]["last_success"])


if __name__ == "__main__":
    unittest.main()
