"""Independent regressions for global undo preflight and durable completion."""
import json
import os
import unittest
from unittest.mock import patch

from cgp_cert_manager import storage, update_apply as apply, update_files as files
from test_update_apply import ApplyFixture


class UpdateApplyReviewTests(ApplyFixture, unittest.TestCase):
    def fully_applied_pending(self):
        # Two changed targets are essential: reverse undo would otherwise touch
        # only the app and accidentally conceal a missing global recheck.
        self.layout.targets()["monitor_service"].chmod(0o600)
        self.prepare()
        token = self.review()
        with patch.object(apply.services, "reload", side_effect=OSError("reload interrupted")):
            result = self.apply(token)
        self.assertEqual(result["status"], "recovery_required", result)
        record = self.record()
        self.assertEqual(files.capture(self.layout.app)[0], record["spec"]["targets"]["application"]["after"])
        self.assertEqual(files.capture(self.layout.targets()["monitor_service"])[0],
                         record["spec"]["targets"]["monitor_service"]["after"])
        return record

    def assert_no_undo_of_other_target(self, result, record):
        self.assertEqual(result["status"], "recovery_required", result)
        self.assertEqual(result["error"], "filesystem_unknown", result)
        self.assertEqual(files.capture(self.layout.targets()["monitor_service"])[0],
                         record["spec"]["targets"]["monitor_service"]["after"])
        self.assertEqual((self.layout.app / "cgp_cert_manager/payload.py").read_bytes(), b"manual edit\n")
        self.assertTrue((self.layout.state / "pending.json").exists())

    def test_unknown_app_introduced_during_stop_blocks_all_rollback_writes(self):
        record = self.fully_applied_pending()
        stop = self.stop.side_effect

        def changed(**kwargs):
            result = stop(**kwargs)
            self.write(self.layout.app / "cgp_cert_manager/payload.py", b"manual edit\n")
            return result

        with patch.object(apply.services, "stop", side_effect=changed), \
                patch.object(files.os, "rename", side_effect=AssertionError("unknown state must not undo another target")):
            result = apply.recover(**self.options)
        self.assert_no_undo_of_other_target(result, record)

    def test_unknown_app_after_durable_restoring_blocks_all_rollback_writes(self):
        record = self.fully_applied_pending()
        persist = apply._persist

        def changed(value, phase):
            persist(value, phase)
            if phase == "restoring":
                self.write(self.layout.app / "cgp_cert_manager/payload.py", b"manual edit\n")

        with patch.object(apply, "_persist", side_effect=changed), \
                patch.object(files.os, "rename", side_effect=AssertionError("unknown state must not undo another target")):
            result = apply.recover(**self.options)
        self.assert_no_undo_of_other_target(result, record)

    def test_unknown_app_during_final_reload_does_not_commit_or_release_gate(self):
        self.prepare()
        token = self.review()
        reload_units = self.reload.side_effect

        def changed(**kwargs):
            result = reload_units(**kwargs)
            self.write(self.layout.app / "cgp_cert_manager/payload.py", b"manual edit\n")
            return result

        with patch.object(apply.services, "reload", side_effect=changed):
            result = self.apply(token)
        self.assertEqual(result["status"], "recovery_required", result)
        self.assertEqual(result["error"], "filesystem_unknown", result)
        self.assertNotIn(self.record()["phase"], apply.TERMINAL)
        self.assertTrue((self.layout.state / "pending.json").exists())

    def test_unknown_app_during_terminal_persist_retains_blocking_evidence(self):
        self.prepare()
        token = self.review()
        persist = apply._persist

        def changed(value, phase):
            persist(value, phase)
            if phase == "applied":
                self.write(self.layout.app / "cgp_cert_manager/payload.py", b"manual edit\n")

        with patch.object(apply, "_persist", side_effect=changed):
            result = self.apply(token)
        self.assertEqual(result["status"], "recovery_required", result)
        self.assertEqual(result["error"], "filesystem_unknown", result)
        self.assertTrue((self.layout.state / "pending.json").exists())
        self.assertEqual(apply.recover(**self.options)["error"], "filesystem_unknown")

    def uncertain_terminal(self):
        self.prepare()
        token = self.review()
        real_replace, real_sync = os.replace, os.fsync
        fail = [None]

        def replaced(source, destination, *args, **kwargs):
            result = real_replace(source, destination, *args, **kwargs)
            if destination == "journal.json":
                parent = kwargs["dst_dir_fd"]
                with open("/proc/self/fd/" + str(parent) + "/journal.json") as stream:
                    current = json.load(stream)
                if current["phase"] == "applied":
                    info = os.fstat(parent)
                    fail[0] = (info.st_dev, info.st_ino)
            return result

        def sync(descriptor):
            info = os.fstat(descriptor)
            if fail[0] == (info.st_dev, info.st_ino):
                fail[0] = None
                raise OSError("terminal journal rename visible but parent sync failed")
            return real_sync(descriptor)

        with patch.object(storage.os, "replace", side_effect=replaced), patch.object(storage.os, "fsync", side_effect=sync):
            result = self.apply(token)
        self.assertEqual(result["status"], "recovery_required", result)
        record = self.record()
        self.assertEqual(record["phase"], "applied")
        return record

    def test_visible_terminal_is_resynced_before_pending_unlink(self):
        record = self.uncertain_terminal()
        journal = apply._directory(record["transaction_id"]) / "journal.json"
        required = {(path.stat().st_dev, path.stat().st_ino) for path in (journal, journal.parent)}
        synced, cleared = set(), []
        real_sync, real_unlink = os.fsync, os.unlink

        def sync(descriptor):
            result = real_sync(descriptor)
            info = os.fstat(descriptor)
            synced.add((info.st_dev, info.st_ino))
            return result

        def unlink(path, *args, **kwargs):
            if path == "pending.json":
                self.assertTrue(required <= synced, "completion file and parent must be durable before releasing gate")
                cleared.append(path)
            return real_unlink(path, *args, **kwargs)

        with patch.object(storage.os, "fsync", side_effect=sync), patch.object(storage.os, "unlink", side_effect=unlink):
            result = apply.recover(**self.options)
        self.assertEqual(result["status"], "applied", result)
        self.assertEqual(cleared, ["pending.json"])
        self.assertFalse((self.layout.state / "pending.json").exists())
        self.assertEqual(files.capture(self.layout.app)[0], record["spec"]["targets"]["application"]["after"])

    def test_terminal_recovery_reload_change_keeps_pending(self):
        record = self.uncertain_terminal()
        reload_units = self.reload.side_effect

        def changed(**kwargs):
            result = reload_units(**kwargs)
            self.write(self.layout.app / "cgp_cert_manager/payload.py", b"manual edit\n")
            return result

        with patch.object(apply.services, "reload", side_effect=changed):
            result = apply.recover(**self.options)
        self.assertEqual(result["status"], "recovery_required", result)
        self.assertEqual(result["error"], "filesystem_unknown", result)
        self.assertTrue((self.layout.state / "pending.json").exists())
        self.assertEqual(self.record()["transaction_id"], record["transaction_id"])

    def test_null_installation_pointer_cannot_reset_approval_replay_history(self):
        old_token = self.interrupted()
        self.assertEqual(apply.recover(**self.options)["status"], "rolled_back")
        # Restoring the operator's original timer state is legitimate. The
        # previous receipt, rather than unrelated timer drift, must stop replay.
        self.observation["timers"] = {name: "active" for name in self.observation["timers"]}
        storage.atomic_text(self.layout.state / "installation.json", "null\n")
        with patch.object(files, "prepare_slot", side_effect=AssertionError("corrupt pointer must not start a transaction")):
            review = apply.review(**self.options)
            result = self.apply(old_token)
        self.assertEqual(review["error"], "journal_invalid", review)
        self.assertIsNone(review["plan"])
        self.assertEqual(result["error"], "journal_invalid", result)
        self.assertEqual((self.layout.state / "installation.json").read_text(), "null\n")

    def test_null_pending_marker_is_corrupt_evidence_not_a_completed_recovery(self):
        self.prepare()
        self.assertEqual(self.apply(self.review())["status"], "applied")
        storage.atomic_text(self.layout.state / "pending.json", "null\n")
        with patch.object(files.os, "rename", side_effect=AssertionError("corrupt evidence must not mutate targets")):
            result = apply.recover(**self.options)
        self.assertEqual(result["status"], "recovery_required", result)
        self.assertEqual(result["error"], "journal_invalid", result)
        self.assertEqual((self.layout.state / "pending.json").read_text(), "null\n")

    def test_lost_pointer_with_retained_journal_cannot_reset_replay_history(self):
        old_token = self.interrupted()
        self.assertEqual(apply.recover(**self.options)["status"], "rolled_back")
        journal = apply._directory(self.record()["transaction_id"]) / "journal.json"
        self.observation["timers"] = {name: "active" for name in self.observation["timers"]}
        (self.layout.state / "installation.json").unlink()
        sentinel = self.root / "unrelated-private-evidence"
        self.write(sentinel, b"must not follow or replace\n", 0o600)
        for kind in ("valid", "corrupt", "symlink"):
            if kind == "corrupt":
                journal.write_bytes(b"{broken")
            elif kind == "symlink":
                journal.unlink()
                journal.symlink_to(sentinel)
            with self.subTest(kind=kind), \
                    patch.object(files, "prepare_slot", side_effect=AssertionError("lost history cannot become a fresh apply")):
                self.assertEqual(apply.review(**self.options)["error"], "journal_missing")
                self.assertEqual(self.apply(old_token)["error"], "journal_missing")
                self.assertEqual(apply.recover(**self.options)["error"], "journal_missing")
                self.assertEqual(apply.status(**self.options)["status"], "recovery_required")
            self.assertFalse((self.layout.state / "installation.json").exists())
            self.assertEqual(sentinel.read_bytes(), b"must not follow or replace\n")


if __name__ == "__main__":
    unittest.main()
