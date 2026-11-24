"""Stateful transaction tests: real journal/backup files, isolated CGP adapter."""
import contextlib
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cgp_cert_manager import core, deployment as d, recovery
from cgp_cert_manager.transactions import Journal, JournalError


NAME = "example.com"
OLD = dict.fromkeys(core.FIELDS, "[YQ==]")
OLD["CertificateType"] = "YES"
NEW = dict(OLD, SecureCertificate="[Yg==]")
OTHER = dict(OLD, SecureCertificate="[Yw==]")
ENDPOINTS = [{"port": 443, "sni": "new.example.com"}]
PREVIOUS_ENDPOINTS = [{"port": 443, "sni": "old.example.com"}]


class TransactionDeploymentTests(unittest.TestCase):
    def setUp(self):
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        self.root = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        stack.enter_context(patch.object(core, "STATE", self.root))
        self.identity = stack.enter_context(patch.object(recovery, "server_identity", return_value="server"))
        self.validate = stack.enter_context(patch.object(core, "validate_backup"))
        self.verify = stack.enter_context(patch.object(recovery, "verify_snapshot"))
        self.actual = dict(OLD)
        self.current = stack.enter_context(patch.object(core, "current", side_effect=lambda *_: copy.deepcopy(self.actual)))
        self.update = stack.enter_context(patch.object(core, "update", side_effect=self.remote_write))
        self.journal = Journal(self.root / "transactions")

    def remote_write(self, cfg, name, settings):
        self.actual = copy.deepcopy(settings)

    def apply(self, previous=OLD, intended=NEW):
        return d.apply({}, NAME, previous, intended, ENDPOINTS, PREVIOUS_ENDPOINTS)

    def prepare(self, name=NAME, identity="server"):
        return self.journal.prepare(name, OLD, NEW, ENDPOINTS, identity,
                                    previous_endpoints=PREVIOUS_ENDPOINTS)

    def test_durable_journal_before_remote_write_and_retention(self):
        backups = self.root / "backups" / NAME
        backups.mkdir(parents=True)
        for number in range(6):
            (backups / ("2000%d.json" % number)).write_text("{}")

        def write(cfg, name, settings):
            record = self.journal.read(name)
            self.assertEqual(record["phase"], "applying")
            self.assertEqual(record["previous"], OLD)
            self.assertEqual(record["intended"], NEW)
            self.assertEqual(record["previous_endpoints"], PREVIOUS_ENDPOINTS)
            self.assertEqual(self.journal.path(name).stat().st_mode & 0o777, 0o600)
            self.remote_write(cfg, name, settings)

        self.update.side_effect = write
        self.assertEqual(self.apply(), "installed")
        self.assertIsNone(self.journal.read(NAME))
        self.assertEqual(len(list(backups.glob("*.json"))), 5)
        self.verify.assert_called_once_with(NEW, ENDPOINTS)
        self.validate.assert_called_once_with(NEW)

    def test_pending_transaction_blocks_even_unchanged(self):
        self.prepare()
        with self.assertRaisesRegex(JournalError, "Pending transaction"):
            self.apply(OLD, OLD)
        self.update.assert_not_called()
        self.validate.assert_not_called()

    def test_other_domain_pending_also_blocks_new_deployment(self):
        self.prepare("other.example.com")
        with self.assertRaisesRegex(JournalError, "Pending transaction"):
            self.apply()
        self.update.assert_not_called()
        self.validate.assert_not_called()

    def test_invalid_target_never_prepares_or_writes(self):
        self.validate.side_effect = core.Error("Invalid key")
        with self.assertRaisesRegex(core.Error, "Invalid key"):
            self.apply()
        self.update.assert_not_called()
        self.assertFalse((self.root / "transactions").exists())
        self.assertFalse((self.root / "backups").exists())

    def test_unchanged_snapshot_verified_without_backup(self):
        self.assertEqual(self.apply(OLD, OLD), "unchanged")
        self.verify.assert_called_once_with(OLD, ENDPOINTS)
        self.update.assert_not_called()
        self.assertFalse((self.root / "backups").exists())

    def test_unchanged_snapshot_concurrent_change_reported(self):
        self.verify.side_effect = lambda *_: setattr(self, "actual", OTHER)
        with self.assertRaisesRegex(JournalError, "changed during snapshot"):
            self.apply(OLD, OLD)
        self.update.assert_not_called()
        self.assertEqual(self.actual, OTHER)

    def test_changed_before_preparation_never_written(self):
        self.actual = OTHER
        with self.assertRaisesRegex(JournalError, "changed before deployment"):
            self.apply()
        self.update.assert_not_called()
        self.assertFalse((self.root / "transactions").exists())

    def test_change_during_preparation_retains_record(self):
        prepare = Journal.prepare

        def changed(journal, *args, **kwargs):
            result = prepare(journal, *args, **kwargs)
            self.actual = dict(NEW)  # Even a known target is unexpected before applying.
            return result

        with patch.object(Journal, "prepare", new=changed):
            with self.assertRaisesRegex(JournalError, "CRITICAL"):
                self.apply()
        self.update.assert_not_called()
        self.assertEqual(self.journal.read(NAME)["phase"], "prepared")

    def test_change_during_applying_fsync_never_overwritten(self):
        transition = Journal.transition

        def changed(journal, name, phase):
            result = transition(journal, name, phase)
            if phase == "applying":
                self.actual = OTHER
            return result

        with patch.object(Journal, "transition", new=changed):
            with self.assertRaisesRegex(JournalError, "CRITICAL"):
                self.apply()
        self.update.assert_not_called()
        self.assertEqual(self.actual, OTHER)
        self.assertEqual(self.journal.read(NAME)["phase"], "applying")

    def test_update_error_after_server_acceptance_uses_readback(self):
        def lost_reply(*args):
            self.remote_write(*args)
            raise OSError("connection closed")

        self.update.side_effect = lost_reply
        self.assertEqual(self.apply(), "installed")
        self.assertEqual(self.actual, NEW)
        self.update.assert_called_once()

    def test_write_not_applied_verifies_previous_without_duplicate_write(self):
        self.update.side_effect = None
        with self.assertRaisesRegex(JournalError, "previous settings restored and TLS verified"):
            self.apply()
        self.update.assert_called_once()
        self.verify.assert_called_once_with(OLD, PREVIOUS_ENDPOINTS)
        self.assertIsNone(self.journal.read(NAME))

    def test_unknown_readback_is_retained_without_blind_rollback(self):
        self.update.side_effect = lambda *_: setattr(self, "actual", OTHER)
        with self.assertRaisesRegex(JournalError, "CRITICAL"):
            self.apply()
        self.update.assert_called_once()
        self.assertEqual(self.actual, OTHER)
        self.assertEqual(self.journal.read(NAME)["phase"], "applying")

    def test_failed_tls_restores_previous_with_previous_sni(self):
        self.verify.side_effect = [core.Error("bad TLS"), None]
        with self.assertRaisesRegex(JournalError, "previous settings restored"):
            self.apply()
        self.assertEqual(self.actual, OLD)
        self.assertEqual(self.update.call_count, 2)
        self.assertEqual(self.verify.call_args.args, (OLD, PREVIOUS_ENDPOINTS))
        self.assertIsNone(self.journal.read(NAME))

    def test_interrupt_also_restores_and_verifies(self):
        self.verify.side_effect = [KeyboardInterrupt(), None]
        with self.assertRaisesRegex(JournalError, "previous settings restored"):
            self.apply()
        self.assertEqual(self.actual, OLD)
        self.assertIsNone(self.journal.read(NAME))

    def test_failed_previous_tls_keeps_restoring_record_and_backups(self):
        self.verify.side_effect = core.Error("TLS unavailable")
        with self.assertRaisesRegex(JournalError, "CRITICAL"):
            self.apply()
        self.assertEqual(self.actual, OLD)
        self.assertEqual(self.journal.read(NAME)["phase"], "restoring")
        self.assertEqual(len(list((self.root / "backups" / NAME).glob("*.json"))), 1)

    def test_changed_during_tls_is_not_overwritten(self):
        self.verify.side_effect = lambda *_: setattr(self, "actual", OTHER)
        with self.assertRaisesRegex(JournalError, "CRITICAL"):
            self.apply()
        self.update.assert_called_once()
        self.assertEqual(self.actual, OTHER)
        self.assertEqual(self.journal.read(NAME)["phase"], "verifying")

    def test_prepare_fsync_failure_never_writes(self):
        with patch.object(Journal, "prepare", side_effect=OSError("disk error")):
            with self.assertRaises(OSError):
                self.apply()
        self.update.assert_not_called()

    def test_applying_phase_failure_recovers_prepared_without_remote_write(self):
        transition = Journal.transition

        def fail_once(journal, name, phase):
            if phase == "applying":
                raise OSError("disk error")
            return transition(journal, name, phase)

        with patch.object(Journal, "transition", new=fail_once):
            with self.assertRaisesRegex(JournalError, "previous settings restored"):
                self.apply()
        self.update.assert_not_called()
        self.assertIsNone(self.journal.read(NAME))

    def test_commit_failure_keeps_verified_target_for_restart(self):
        transition = Journal.transition

        def fail_commit(journal, name, phase):
            if phase == "committed":
                raise OSError("disk error")
            return transition(journal, name, phase)

        with patch.object(Journal, "transition", new=fail_commit):
            with self.assertRaises(OSError):
                self.apply()
        self.assertEqual(self.actual, NEW)
        self.assertEqual(self.journal.read(NAME)["phase"], "verifying")
        self.assertEqual(d.recover_pending({}), [{"domain": NAME, "result": "committed"}])
        self.update.assert_called_once()

    def test_cleanup_failure_does_not_rollback_committed_certificate(self):
        with patch.object(Journal, "finish", side_effect=OSError("disk error")):
            with self.assertRaises(OSError):
                self.apply()
        self.assertEqual(self.journal.read(NAME)["phase"], "committed")
        self.assertEqual(self.actual, NEW)
        d.recover_pending({})
        self.update.assert_called_once()
        self.assertIsNone(self.journal.read(NAME))

    def test_empty_status_and_recovery_need_no_configuration_or_writes(self):
        self.assertEqual(d.transaction_status({}), [])
        self.assertEqual(d.recover_pending({}), [])
        self.identity.assert_not_called()
        self.current.assert_not_called()
        self.assertFalse((self.root / "transactions").exists())

    def test_status_is_readonly_and_omits_sensitive_settings(self):
        self.prepare()
        path = self.journal.path(NAME)
        before = path.read_bytes(), path.stat().st_mtime_ns
        with patch("cgp_cert_manager.transactions.os.fsync") as sync:
            rows = d.transaction_status({}, NAME)
        self.assertEqual(rows, [{"domain": NAME, "phase": "prepared", "state": "previous", "server_matches": True}])
        self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), before)
        self.assertNotIn("PrivateSecureKey", json.dumps(rows))
        sync.assert_not_called()
        self.update.assert_not_called()

    def test_foreign_status_does_not_contact_another_server(self):
        self.prepare(identity="different")
        self.assertEqual(d.transaction_status({})[0]["state"], "foreign")
        self.assertFalse(d.transaction_status({})[0]["server_matches"])
        self.current.assert_not_called()

    def test_scoped_recovery_and_preflight_all_identities(self):
        self.prepare()
        self.prepare("other.example.com", "different")
        with self.assertRaisesRegex(JournalError, "another server"):
            d.recover_pending({})
        self.verify.assert_not_called()
        self.update.assert_not_called()
        self.assertEqual(d.transaction_status({}, "absent.example.com"), [])
        self.assertEqual(d.recover_pending({}, NAME), [{"domain": NAME, "result": "restored"}])
        self.assertEqual(self.journal.domains(), ["other.example.com"])

    def test_invalid_domain_filter_is_rejected(self):
        with self.assertRaises(core.Error):
            d.transaction_status({}, "../outside")


class SnapshotEndpointTests(unittest.TestCase):
    def endpoints(self, names, domain):
        with patch.object(core, "installed_info", return_value={"names": names}):
            return d.snapshot_endpoints(domain, OLD)

    def test_default_uses_previous_sans_and_known_wildcard_aliases(self):
        endpoints = self.endpoints(["old.example.com", "*.example.net"],
                                  {"cgp_domain": NAME, "aliases": ["mail.example.net", "bad.example.org"]})
        self.assertEqual([e["sni"] for e in endpoints], ["mail.example.net", "old.example.com"])

    def test_explicit_matching_sni_preserved_and_new_only_sni_replaced(self):
        templates = [{"port": 993, "sni": "old.example.com"},
                     {"host": "127.0.0.1", "port": 25, "starttls": "smtp", "sni": "new.example.com"},
                     {"port": 443}]
        result = self.endpoints(["old.example.com"], {"cgp_domain": NAME, "tls": templates})
        self.assertEqual([e["sni"] for e in result], ["old.example.com"] * 3)
        self.assertEqual(result[1]["starttls"], "smtp")
        self.assertEqual(templates[1]["sni"], "new.example.com")

    def test_known_domain_covered_by_wildcard_is_usable(self):
        result = self.endpoints(["*.example.com"], {"cgp_domain": "mail.example.com"})
        self.assertEqual(result[0]["sni"], "mail.example.com")

    def test_wildcard_without_known_concrete_name_is_refused(self):
        with self.assertRaisesRegex(JournalError, "No known hostname"):
            self.endpoints(["*.example.net"], {"cgp_domain": NAME})

    def test_missing_certificate_is_refused(self):
        with patch.object(core, "installed_info", return_value=None):
            with self.assertRaisesRegex(JournalError, "No certificate"):
                d.snapshot_endpoints({"cgp_domain": NAME}, {})
