"""Operator authorization must remain a global certificate-mutation boundary."""
from contextlib import ExitStack
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cgp_cert_manager import cli, core, deployment, recovery, resolution, storage
from cgp_cert_manager.transactions import Journal


class ResolutionIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.stack.enter_context(patch.object(core, "STATE", self.root))
        self.stack.enter_context(patch.object(cli, "STATE", self.root))
        self.stack.enter_context(patch.object(recovery, "server_identity", return_value="server"))
        self.cfg = {"schema_version": 2, "email": "admin@example.com"}
        self.name = "z.example.com"
        self.previous = dict.fromkeys(core.FIELDS, "[YQ==]")
        self.previous["CertificateType"] = "YES"
        self.intended = dict(self.previous, SecureCertificate="[Yg==]")
        self.endpoints = [{"port": 443, "sni": self.name}]
        self.journal = Journal(self.root / "transactions")
        self.journal.prepare(self.name, self.previous, self.intended, self.endpoints, "server")
        self.current = self.stack.enter_context(patch.object(core, "current", return_value=self.previous))
        self.update = self.stack.enter_context(patch.object(core, "update"))
        self.verify = self.stack.enter_context(patch.object(recovery, "verify_snapshot"))
        self.reason = "Expired previous certificate; administrator accepts the unverified state"
        self.token = resolution.preview(self.cfg, self.name)["confirmation_token"]

    def acknowledge(self):
        return resolution.acknowledge(self.cfg, self.name, self.token, self.reason)

    def interrupt_after_unlink(self):
        atomic_json = storage.atomic_json

        def fail_completion(path, data):
            if Path(path).name == "completion.json":
                raise OSError("Simulated completion publication failure")
            return atomic_json(path, data)

        with patch.object(storage, "atomic_json", side_effect=fail_completion):
            with self.assertRaises(OSError):
                self.acknowledge()
        self.assertIsNone(self.journal.read(self.name))
        self.assertTrue((self.root / "resolutions" / self.token / "authorization.json").exists())
        self.current.reset_mock()

    def test_authorization_without_completion_blocks_all_entry_points(self):
        self.interrupt_after_unlink()
        other = "a.example.com"
        self.journal.prepare(other, self.previous, self.intended, self.endpoints, "server")
        operations = (
            deployment.assert_no_pending,
            lambda: deployment.recover_pending(self.cfg),
            lambda: deployment.recover_pending(self.cfg, other),
            lambda: recovery.recover(self.journal, other, self.cfg, "server"),
            lambda: deployment.apply(self.cfg, other, self.previous, self.intended,
                                     self.endpoints, self.endpoints),
        )
        for operation in operations:
            with self.subTest(operation=operation), self.assertRaises(core.Error):
                operation()
        self.current.assert_not_called()
        self.update.assert_not_called()
        self.verify.assert_not_called()
        self.assertEqual(self.journal.read(other)["phase"], "prepared")

    def test_normal_cli_stops_before_discovery_or_issuance(self):
        self.interrupt_after_unlink()
        config = self.root / "config.json"
        core.atomic(config, self.cfg)
        with patch.object(cli, "CONFIG", config), patch.object(cli.os, "umask"), \
                patch.object(cli, "zones") as zones, patch.object(cli, "issue") as issue, \
                patch.object(cli, "deploy") as deploy, patch.object(cli, "notify") as notify, \
                patch.object(cli.sys, "argv", ["cgp-letsencrypt"]):
            with self.assertRaises(core.Error):
                cli.main()
            zones.assert_not_called()
            issue.assert_not_called()
            deploy.assert_not_called()
            notify.assert_not_called()
        self.assertFalse((self.root / "state.json").exists())
        self.assertFalse((self.root / "history.jsonl").exists())

    def test_status_merges_orphan_authorization_and_pending_domains_read_only(self):
        self.interrupt_after_unlink()
        other = "a.example.com"
        self.journal.prepare(other, self.previous, self.intended, self.endpoints, "server")
        with patch.object(storage.os, "fsync") as sync:
            rows = deployment.transaction_status(self.cfg)
            sync.assert_not_called()
        self.assertEqual([row["domain"] for row in rows], [other, self.name])
        self.assertEqual(rows[1]["phase"], "acknowledging")
        self.assertEqual(rows[1]["state"], "previous")
        self.assertTrue(rows[1]["server_matches"])
        self.assertNotIn("previous", rows[1])
        self.assertNotIn("reason", rows[1])
        self.assertEqual(deployment.transaction_status(self.cfg, other)[0]["domain"], other)
        self.assertEqual(deployment.transaction_status(self.cfg, "absent.example.com"), [])
        self.update.assert_not_called()

    def test_foreign_orphan_authorization_never_contacts_cgp(self):
        self.interrupt_after_unlink()
        with patch.object(recovery, "server_identity", return_value="another-server"):
            rows = deployment.transaction_status(self.cfg)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["state"], "foreign")
        self.assertFalse(rows[0]["server_matches"])
        self.current.assert_not_called()

    def test_explicit_retry_releases_guard_without_claiming_tls_success(self):
        self.interrupt_after_unlink()
        pending = resolution.preview(self.cfg, self.name)
        self.assertEqual(pending["phase"], "acknowledging")
        self.assertEqual(pending["confirmation_token"], self.token)
        result = self.acknowledge()
        self.assertEqual(result["result"], "acknowledged_unverified")
        self.assertEqual(result["tls"], "unverified")
        self.assertEqual(deployment.transaction_status(self.cfg), [])
        self.assertEqual(deployment.recover_pending(self.cfg), [])
        deployment.assert_no_pending()
        self.verify.assert_not_called()
        self.update.assert_not_called()
        # A later ordinary deployment still performs its own TLS verification.
        with patch.object(core, "validate_backup"):
            result = deployment.apply(self.cfg, "a.example.com", self.previous, self.previous,
                                      self.endpoints, self.endpoints)
        self.assertEqual(result, "unchanged")
        self.verify.assert_called_once_with(self.previous, self.endpoints)

    def test_completed_evidence_sync_failure_blocks_before_remote_work(self):
        self.acknowledge()
        completion = self.root / "resolutions" / self.token / "completion.json"
        identity = completion.stat()
        fsync = os.fsync

        def fail_completion(fd):
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) == (identity.st_dev, identity.st_ino):
                raise OSError("Simulated completion fsync failure")
            return fsync(fd)

        self.current.reset_mock()
        with patch.object(storage.os, "fsync", side_effect=fail_completion):
            with self.assertRaises(OSError):
                deployment.apply(self.cfg, "a.example.com", self.previous, self.intended,
                                 self.endpoints, self.endpoints)
        self.current.assert_not_called()
        self.update.assert_not_called()
        self.verify.assert_not_called()
        self.assertTrue(completion.exists())


if __name__ == "__main__":
    unittest.main()
