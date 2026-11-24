"""Explicit acknowledgement protocol, corruption and persistence regressions."""
import contextlib
import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cgp_cert_manager import core, recovery, resolution as r, storage
from cgp_cert_manager.transactions import Journal, JournalError


NAME = "example.com"
OLD = dict.fromkeys(core.FIELDS, "[YQ==]")
OLD["CertificateType"] = "YES"
NEW = dict(OLD, PrivateSecureKey="[Yg==]")
EP = [{"port": 443, "sni": NAME}]
REASON = "Previous settings accepted; listener repair is tracked separately"


class ResolutionTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.stack.enter_context(patch.object(core, "STATE", self.root))
        self.identity = self.stack.enter_context(patch.object(recovery, "server_identity", return_value="server"))
        self.actual = dict(OLD)
        self.current = self.stack.enter_context(patch.object(core, "current", side_effect=lambda *_: copy.deepcopy(self.actual)))
        self.update = self.stack.enter_context(patch.object(core, "update", side_effect=AssertionError("No CGP writes allowed")))
        self.verify = self.stack.enter_context(patch.object(recovery, "verify_snapshot", side_effect=AssertionError("No TLS proof permitted")))
        self.cfg = {}
        self.journal = Journal(self.root / "transactions")
        self.journal.prepare(NAME, OLD, NEW, EP, "server")

    def token(self):
        return r.preview(self.cfg, NAME)["confirmation_token"]

    def acknowledge(self, token=None, reason=REASON):
        return r.acknowledge(self.cfg, NAME, self.token() if token is None else token, reason)

    def bundle(self, token):
        return self.root / "resolutions" / token

    def authorization(self, token):
        return core.load(self.bundle(token) / "authorization.json")

    def interrupted(self, absent=False):
        token = self.token()
        hook = "_write_completion" if absent else "_sync_audit"
        with patch.object(r, hook, side_effect=OSError("injected disk failure")):
            with self.assertRaises(OSError): self.acknowledge(token)
        return token

    def test_preview_has_no_writes_or_secret_fields(self):
        before = self.journal.read_snapshot(NAME)
        with patch.object(storage.os, "fsync") as sync, patch.object(storage, "ensure_private_directory") as ensure:
            row = r.preview(self.cfg, NAME)
        self.assertEqual(row["state"], "previous")
        self.assertEqual(row["phase"], "prepared")
        self.assertTrue(row["pending_journal"])
        self.assertFalse(row["authorization_recorded"])
        self.assertEqual(row["tls"], "unverified")
        self.assertRegex(row["confirmation_token"], r"^[0-9a-f]{64}$")
        self.assertNotIn("PrivateSecureKey", json.dumps(row))
        self.assertEqual(self.journal.read_snapshot(NAME), before)
        sync.assert_not_called()
        ensure.assert_not_called()

    def test_acknowledgement_preserves_full_evidence_and_binds_completion(self):
        snapshot = self.journal.read_snapshot(NAME)
        token = self.token()
        result = self.acknowledge(token, "  Исправление TLS запланировано  ")
        self.assertEqual(result, {"domain": NAME, "result": "acknowledged_unverified", "tls": "unverified", "confirmation_token": token})
        auth = self.authorization(token)
        self.assertEqual(auth["journal"], snapshot["record"])
        self.assertEqual(auth["witness"], snapshot["witness"])
        self.assertEqual(auth["reason"], "Исправление TLS запланировано")
        self.assertEqual(auth["uid"], os.geteuid())
        self.assertEqual(auth["decision"], r.DECISION)
        self.assertEqual(auth["tls"], "unverified")
        marker = core.load(self.bundle(token) / "completion.json")
        self.assertEqual(marker["authorization_digest"], r._digest(auth))
        self.assertEqual(marker["tls"], "unverified")
        self.assertIsNone(self.journal.read(NAME))
        self.assertEqual(self.bundle(token).stat().st_mode & 0o777, 0o700)
        for path in self.bundle(token).iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.update.assert_not_called()
        self.verify.assert_not_called()

    def test_restoring_and_identical_snapshots_are_eligible(self):
        self.journal.path(NAME).unlink()
        self.journal.prepare(NAME, OLD, OLD, EP, "server")
        self.journal.transition(NAME, "restoring")
        self.assertEqual(r.preview(self.cfg, NAME)["state"], "both")
        self.acknowledge()
        self.verify.assert_not_called()

    def test_inactive_and_unparseable_previous_needs_no_crypto(self):
        self.journal.path(NAME).unlink()
        previous = dict(OLD, CertificateType="NO", SecureCertificate="[]")
        self.actual = previous
        self.journal.prepare(NAME, previous, NEW, EP, "server")
        with patch.object(core, "installed_info", side_effect=AssertionError("Must not parse old certificate")):
            self.acknowledge()
        self.update.assert_not_called()

    def test_other_phase_requires_recovery_before_acknowledgement(self):
        self.journal.transition(NAME, "applying")
        token = r._token(self.journal.read_snapshot(NAME))
        for operation in (lambda: r.preview(self.cfg, NAME), lambda: self.acknowledge(token)):
            with self.assertRaisesRegex(JournalError, "Run --recover"): operation()
        self.assertFalse((self.root / "resolutions").exists())

    def test_unknown_or_intended_cgp_state_never_authorized(self):
        token = self.token()
        for actual in ({}, NEW):
            self.actual = actual
            for operation in (lambda: r.preview(self.cfg, NAME), lambda: self.acknowledge(token)):
                with self.assertRaisesRegex(JournalError, "exactly match"): operation()
        self.assertFalse((self.root / "resolutions").exists())

    def test_foreign_server_never_contacted(self):
        token = self.token()
        self.identity.return_value = "foreign"
        self.current.reset_mock()
        for operation in (lambda: r.preview(self.cfg, NAME), lambda: self.acknowledge(token)):
            with self.assertRaisesRegex(JournalError, "another server"): operation()
        self.current.assert_not_called()

    def test_invalid_tokens_and_reasons_are_rejected_before_side_effects(self):
        token = self.token()
        self.current.reset_mock()
        for invalid in (None, "", "A" * 64, "a" * 63, "z" * 64):
            with self.subTest(token=invalid), self.assertRaises(JournalError):
                r.acknowledge(self.cfg, NAME, invalid, REASON)
        for invalid in (None, "", "   ", "x" * 501, "\nreason", "reason\t", "a\nb", "\x1b[31mred"):
            with self.subTest(reason=invalid), self.assertRaises(JournalError):
                self.acknowledge(token, invalid)
        self.current.assert_not_called()
        self.assertFalse((self.root / "resolutions").exists())

    def test_token_is_bound_to_inode_and_phase(self):
        first = self.token()
        self.journal.path(NAME).unlink()
        self.journal.prepare(NAME, OLD, NEW, EP, "server")
        self.assertNotEqual(first, self.token())
        with self.assertRaisesRegex(JournalError, "instance changed"): self.acknowledge(first)
        current = self.token()
        self.journal.transition(NAME, "restoring")
        with self.assertRaisesRegex(JournalError, "instance changed"): self.acknowledge(current)

    def test_snapshot_rejects_file_changed_during_read(self):
        load = json.load

        def changing(stream):
            value = load(stream)
            info = os.stat(stream.fileno())
            os.utime(self.journal.path(NAME), ns=(info.st_atime_ns, info.st_mtime_ns + 1))
            return value

        with patch("cgp_cert_manager.transactions.json.load", side_effect=changing):
            with self.assertRaisesRegex(JournalError, "while being read"):
                self.journal.read_snapshot(NAME)

    def test_authorization_retry_is_immutable_and_durable_before_unlink(self):
        token = self.interrupted()
        auth_path = self.bundle(token) / "authorization.json"
        original = auth_path.read_bytes()
        self.assertTrue(r.preview(self.cfg, NAME)["authorization_recorded"])
        with self.assertRaisesRegex(JournalError, "explicit retry"): r.assert_no_incomplete()
        synced = []
        fsync = os.fsync
        auth_inode = auth_path.stat().st_ino
        audit_inode = self.bundle(token).stat().st_ino
        unlink = Path.unlink

        def syncing(fd):
            fsync(fd)
            synced.append(os.fstat(fd).st_ino)

        def removing(path, *args, **kwargs):
            if path == self.journal.path(NAME):
                self.assertIn(auth_inode, synced)
                self.assertIn(audit_inode, synced)
            return unlink(path, *args, **kwargs)

        with patch.object(storage.os, "fsync", side_effect=syncing), patch.object(Path, "unlink", new=removing):
            self.acknowledge(token)
        self.assertEqual(auth_path.read_bytes(), original)
        r.assert_no_incomplete()

    def test_different_reason_or_domain_cannot_replace_authorization(self):
        token = self.interrupted()
        original = (self.bundle(token) / "authorization.json").read_bytes()
        for domain, reason in ((NAME, "different reason"), ("other.example.com", REASON)):
            with self.assertRaisesRegex(JournalError, "another domain or reason"):
                r.acknowledge(self.cfg, domain, token, reason)
        self.assertEqual((self.bundle(token) / "authorization.json").read_bytes(), original)
        self.assertIsNotNone(self.journal.read(NAME))

    def test_absent_pending_requires_explicit_retry_and_reports_status(self):
        token = self.interrupted(absent=True)
        row = r.preview(self.cfg, NAME)
        self.assertEqual(row["phase"], "acknowledging")
        self.assertFalse(row["pending_journal"])
        self.assertTrue(row["authorization_recorded"])
        self.assertEqual(row["confirmation_token"], token)
        with self.assertRaisesRegex(JournalError, "explicit retry"):
            r.assert_no_incomplete(state=self.root)
        with patch.object(storage.os, "fsync") as sync:
            rows = r.pending_status(self.cfg, NAME)
            self.assertEqual(r.pending_status(self.cfg, "other.example.com"), [])
        sync.assert_not_called()
        self.assertEqual(rows[0]["state"], "previous")
        self.actual = {}
        self.assertEqual(r.pending_status(self.cfg)[0]["state"], "unknown")
        with self.assertRaises(JournalError): self.acknowledge(token)
        self.actual = dict(OLD)
        self.acknowledge(token)
        self.assertEqual(r.pending_status(self.cfg), [])

    def test_foreign_orphan_status_does_not_contact_server(self):
        self.interrupted(absent=True)
        self.identity.return_value = "foreign"
        self.current.reset_mock()
        row = r.pending_status(self.cfg)[0]
        self.assertFalse(row["server_matches"])
        self.assertEqual(row["state"], "foreign")
        self.current.assert_not_called()

    def test_status_omits_incomplete_approval_with_existing_journal(self):
        self.interrupted()
        self.assertEqual(r.pending_status(self.cfg), [])

    def test_completed_receipt_replay_preserves_both_files(self):
        token = self.token()
        self.acknowledge(token)
        before = {path.name: path.read_bytes() for path in self.bundle(token).iterdir()}
        self.acknowledge(token)
        self.assertEqual({path.name: path.read_bytes() for path in self.bundle(token).iterdir()}, before)
        with self.assertRaisesRegex(JournalError, "No pending"): r.preview(self.cfg, NAME)
        self.journal.prepare(NAME, OLD, NEW, EP, "server")
        r.assert_no_incomplete()  # A different instance is handled by normal WAL recovery.
        with self.assertRaisesRegex(JournalError, "instance changed"): self.acknowledge(token)

    def test_completed_receipt_cannot_release_matching_pending(self):
        token = self.interrupted()
        r._write_completion(self.bundle(token), self.authorization(token))
        for operation in (r.assert_no_incomplete, lambda: r.preview(self.cfg, NAME), lambda: self.acknowledge(token)):
            with self.assertRaisesRegex(JournalError, "Completed acknowledgement"): operation()
        self.assertIsNotNone(self.journal.read(NAME))

    def test_remote_change_after_authorization_retains_both_evidence_and_pending(self):
        token = self.token()
        sync = r._sync_audit

        def change(*args, **kwargs):
            sync(*args, **kwargs)
            self.actual = {}

        with patch.object(r, "_sync_audit", side_effect=change):
            with self.assertRaisesRegex(JournalError, "exactly match"): self.acknowledge(token)
        self.assertIsNotNone(self.journal.read(NAME))
        self.assertTrue((self.bundle(token) / "authorization.json").exists())
        self.assertFalse((self.bundle(token) / "completion.json").exists())

    def test_journal_change_after_authorization_is_not_accepted(self):
        token = self.token()
        sync = r._sync_audit

        def change(*args, **kwargs):
            sync(*args, **kwargs)
            self.journal.transition(NAME, "restoring")

        with patch.object(r, "_sync_audit", side_effect=change):
            with self.assertRaisesRegex(JournalError, "instance changed"): self.acknowledge(token)
        with self.assertRaisesRegex(JournalError, "changed after authorization"): r.preview(self.cfg, NAME)
        with self.assertRaisesRegex(JournalError, "Another unfinished"):
            self.acknowledge(r._token(self.journal.read_snapshot(NAME)))

    def test_retry_cannot_remove_newly_appeared_transaction(self):
        token = self.interrupted(absent=True)
        sync = r._sync_audit

        def new_transaction(*args, **kwargs):
            sync(*args, **kwargs)
            self.journal.prepare(NAME, OLD, NEW, EP, "server")

        with patch.object(r, "_sync_audit", side_effect=new_transaction):
            with self.assertRaisesRegex(JournalError, "instance changed"): self.acknowledge(token)
        self.assertIsNotNone(self.journal.read(NAME))

    def test_missing_state_and_empty_audit_directories_create_nothing(self):
        absent = self.root / "missing"
        r.assert_no_incomplete(state=absent)
        self.assertFalse(absent.exists())
        token = "a" * 64
        storage.ensure_private_directory(self.bundle(token))
        r.assert_no_incomplete()
        self.assertEqual(r.pending_status(self.cfg), [])
        self.journal.path(NAME).unlink()
        with self.assertRaisesRegex(JournalError, "No matching"): self.acknowledge(token)

    def test_invalid_directory_name_and_completion_without_authorization(self):
        directory = self.root / "resolutions" / "invalid"
        storage.ensure_private_directory(directory)
        with self.assertRaisesRegex(JournalError, "directory name"): r.assert_no_incomplete()
        directory.rmdir()
        storage.atomic_json(self.bundle("a" * 64) / "completion.json", {})
        with self.assertRaisesRegex(JournalError, "no authorization"): r.assert_no_incomplete()

    def test_null_authorization_and_completion_are_corrupt_not_missing(self):
        token = self.interrupted(absent=True)
        path = self.bundle(token) / "authorization.json"
        original = path.read_bytes()
        storage.atomic_json(path, None)
        with self.assertRaisesRegex(JournalError, "authorization schema"): r.assert_no_incomplete()
        path.write_bytes(original)
        storage.atomic_json(self.bundle(token) / "completion.json", None)
        with self.assertRaisesRegex(JournalError, "completion schema"): r.assert_no_incomplete()

    def test_unparseable_audit_is_refused_without_changing_evidence(self):
        token = self.interrupted(absent=True)
        path = self.bundle(token) / "authorization.json"
        for invalid in (b'{"schema":', b'\xff'):
            path.write_bytes(invalid)
            with self.assertRaisesRegex(JournalError, "Corrupt resolution audit"): r.assert_no_incomplete()
            self.assertEqual(path.read_bytes(), invalid)

    def test_invalid_authorization_metadata_fails_closed(self):
        token = self.interrupted(absent=True)
        path = self.bundle(token) / "authorization.json"
        auth = self.authorization(token)
        cases = [
            [], dict(auth, extra=True), dict(auth, schema=True), dict(auth, schema=2),
            dict(auth, decision="force"), dict(auth, tls="verified"), dict(auth, confirmation_token="f" * 64),
            dict(auth, domain=1), dict(auth, domain="../bad"),
            dict(auth, journal=dict(auth["journal"], phase="applying")), dict(auth, config_identity="other"),
            dict(auth, witness=None), dict(auth, witness={}),
            dict(auth, witness=dict(auth["witness"], ino=-1)), dict(auth, witness=dict(auth["witness"], ino=True)),
            dict(auth, witness=dict(auth["witness"], ino=auth["witness"]["ino"] + 1)),
            dict(auth, reason=" padded "), dict(auth, uid=True), dict(auth, uid=-1),
            dict(auth, authorized_at=None), dict(auth, authorized_at="bad+00:00"), dict(auth, authorized_at="2026-01-01T00:00:00+01:00"),
        ]
        for invalid in cases:
            with self.subTest(invalid=invalid):
                storage.atomic_json(path, invalid)
                with self.assertRaises(core.Error): r.assert_no_incomplete()
                self.assertEqual(core.load(path), invalid)

    def test_invalid_completion_metadata_fails_closed(self):
        token = self.token()
        self.acknowledge(token)
        path = self.bundle(token) / "completion.json"
        marker = core.load(path)
        for invalid in ([], dict(marker, extra=True), dict(marker, schema=True), dict(marker, schema=2),
                        dict(marker, confirmation_token="f" * 64), dict(marker, domain="other.example.com"),
                        dict(marker, authorization_digest="wrong"), dict(marker, tls="verified"), dict(marker, completed_at="bad")):
            with self.subTest(invalid=invalid):
                storage.atomic_json(path, invalid)
                with self.assertRaises(JournalError): r.assert_no_incomplete()

    def test_multiple_unfinished_approvals_require_investigation(self):
        first = self.interrupted()
        auth = self.authorization(first)
        self.journal.path(NAME).unlink()
        self.journal.prepare(NAME, OLD, NEW, EP, "server")
        snapshot = self.journal.read_snapshot(NAME)
        token = r._token(snapshot)
        second = dict(auth, journal=snapshot["record"], witness=snapshot["witness"], confirmation_token=token)
        storage.atomic_json(self.bundle(token) / "authorization.json", second)
        for operation in (lambda: r.preview(self.cfg, NAME), lambda: self.acknowledge(token)):
            with self.assertRaisesRegex(JournalError, "Multiple unfinished"): operation()

    def test_unsafe_audit_metadata_is_rejected(self):
        token = self.interrupted(absent=True)
        path = self.bundle(token) / "authorization.json"
        path.chmod(0o644)
        with self.assertRaises(storage.StorageError): r.assert_no_incomplete()
