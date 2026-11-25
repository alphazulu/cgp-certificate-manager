"""Real local snapshots, rename boundaries and refusal of ambiguous recovery."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from cgp_cert_manager import storage, update_files as files
from cgp_cert_manager.update_metadata import UpdateError


class Interrupted(Exception):
    pass


class UpdateFilesTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.serial = 0

    def write(self, path, data=b"old", mode=0o640, stamp=1700000000123456789):
        path.write_bytes(data)
        path.chmod(mode)
        os.utime(path, ns=(stamp, stamp))
        return path

    def tree(self, path, data):
        path.mkdir(mode=0o755)
        (path / "empty").mkdir(mode=0o700)
        (path / "nested").mkdir(mode=0o750)
        self.write(path / "nested" / "value", data, 0o600)
        self.write(path / "ёж.txt", data, 0o644)
        for name in (path / "empty", path / "nested", path):
            os.utime(name, ns=(123456789, 123456789))

    def transaction(self, tree=False, missing=False):
        parent = self.root / str(self.serial)
        self.serial += 1
        parent.mkdir(mode=0o755)
        live, candidate, slot = parent / "live", parent / "candidate", parent / ".slot"
        if tree:
            if not missing:
                self.tree(live, b"old")
            self.tree(candidate, b"intended")
        else:
            if not missing:
                self.write(live)
            self.write(candidate, b"intended", 0o750, -123456789)
        before, old_blobs = files.capture(live)
        after, new_blobs = files.capture(candidate)
        files.prepare_slot(live, slot, after, new_blobs)
        return live, slot, before, after, old_blobs | new_blobs

    def bad(self, function, *args, code=None):
        with self.assertRaises(UpdateError) as caught:
            function(*args)
        self.assertIn(caught.exception.code, files.CODES)
        self.assertEqual(str(caught.exception), caught.exception.code)
        if code:
            self.assertEqual(caught.exception.code, code)

    def test_capture_is_read_only_complete_deduplicated_and_stable(self):
        source = self.root / "tree"
        self.tree(source, b"duplicate")
        with patch.object(files.os, "fsync", side_effect=AssertionError("read only")), \
                patch.object(files.os, "mkdir", side_effect=AssertionError("read only")):
            snapshot, blobs = files.capture(source)
            self.assertTrue(files.matches(source, snapshot))
            self.assertEqual(files.capture(self.root / "absent"), ({"kind": "missing", "entries": []}, {}))
            self.assertEqual(files.capture(self.root / "absent" / "child")[0]["kind"], "missing")
        self.assertEqual([row["path"] for row in snapshot["entries"]], [".", "empty", "nested", "nested/value", "ёж.txt"])
        self.assertEqual(len(blobs), 1)
        self.assertEqual(snapshot["entries"][0]["mtime_ns"], 123456789)
        self.assertEqual(files.fingerprint(snapshot), hashlib.sha256(files.metadata.canonical(snapshot)).hexdigest())
        normalized = files.validate_snapshot(snapshot)
        normalized["entries"][0]["mode"] = 0
        self.assertEqual(snapshot["entries"][0]["mode"], 0o755)
        self.write(source / "ёж.txt", b"changed")
        self.assertFalse(files.matches(source, snapshot))

    def test_materialize_preserves_complete_tree_and_file_metadata(self):
        source = self.root / "source"
        self.tree(source, b"payload")
        snapshot, blobs = files.capture(source)
        destination = self.root / "copy"
        files.materialize(destination, snapshot, blobs)
        self.assertEqual(files.capture(destination), (snapshot, blobs))
        single, data = files.capture(source / "ёж.txt")
        files.materialize(self.root / "single", single, data)
        self.assertEqual(files.capture(self.root / "single"), (single, data))
        missing = {"kind": "missing", "entries": []}
        files.materialize(self.root / "still-absent", missing, {})
        self.assertFalse((self.root / "still-absent").exists())
        self.bad(files.materialize, destination, snapshot, blobs, code="filesystem_unknown")
        self.assertEqual(files.capture(destination)[0], snapshot)

    def test_snapshot_schema_rejects_incomplete_ambiguous_and_unsafe_records(self):
        source = self.write(self.root / "file")
        snapshot, blobs = files.capture(source)
        cases = [None, [], {}, {**snapshot, "extra": True}, {"kind": [], "entries": []},
                 {"kind": "missing", "entries": snapshot["entries"]}, {"kind": "directory", "entries": []},
                 {"kind": "file", "entries": {}}, {"kind": "file", "entries": [None]},
                 {"kind": "file", "entries": [{"kind": []}]},
                 {"kind": "file", "entries": [{"kind": "socket"}]}]
        for key, values in {"path": ["a", [], ".."], "kind": ["directory"], "mode": [True, -1, 0o777, 0o4644],
                            "uid": [True, -1, 2**32, os.geteuid() + 1], "gid": [-1, False, 2**32],
                            "mtime_ns": [False, -(2**63) - 1, 2**63], "size": [-1, False, files.MAX_FILE + 1],
                            "sha256": [None, "A" * 64, "a" * 63]}.items():
            for value in values:
                changed = copy.deepcopy(snapshot)
                changed["entries"][0][key] = value
                cases.append(changed)
        changed = copy.deepcopy(snapshot)
        del changed["entries"][0]["size"]
        cases.append(changed)
        for value in cases:
            with self.subTest(value=value):
                self.bad(files.validate_snapshot, value, code="snapshot_invalid")
        tree = self.root / "tree"
        self.tree(tree, b"abc")
        valid, _ = files.capture(tree)
        for name in ("/absolute", "a//b", "a/../b", "a\\b", "bad\nname", "\ud800", "a/" * 65 + "b", "a" * 4097):
            changed = copy.deepcopy(valid)
            changed["entries"][1]["path"] = name
            self.bad(files.validate_snapshot, changed, code="snapshot_invalid")
        for mutate in (lambda rows: rows.append(dict(rows[1])), lambda rows: rows.reverse(),
                       lambda rows: rows.pop(2), lambda rows: rows[1].update(path="unknown/child"),
                       lambda rows: rows[2].update(kind="file", size=0, sha256=hashlib.sha256(b"").hexdigest())):
            changed = copy.deepcopy(valid)
            mutate(changed["entries"])
            self.bad(files.validate_snapshot, changed, code="snapshot_invalid")
        with patch.object(files, "MAX_ENTRIES", 1):
            self.bad(files.validate_snapshot, valid, code="snapshot_invalid")
        with patch.object(files, "MAX_TOTAL", 1):
            self.bad(files.validate_snapshot, snapshot, code="snapshot_invalid")

    def test_unsafe_absolute_and_relative_paths_never_create_destinations(self):
        for path in (None, 12, "relative", "/", "//tmp/file", str(self.root / ".." / "file"),
                     str(self.root / "secret\nname"), str(self.root / "\ud800")):
            self.bad(files.capture, path, code="filesystem_unsafe")
        link = self.root / "link"
        link.symlink_to(self.root, target_is_directory=True)
        self.bad(files.capture, link / "unknown", code="filesystem_unsafe")

    def test_links_special_files_permissions_and_extended_attributes_are_refused(self):
        source = self.write(self.root / "source")
        link = self.root / "link"
        link.symlink_to(source)
        self.bad(files.capture, link, code="filesystem_unsafe")
        link.unlink()
        os.link(source, link)
        self.bad(files.capture, source, code="filesystem_unsafe")
        link.unlink()
        for mode in (0o666, 0o4644):
            source.chmod(mode)
            self.bad(files.capture, source, code="filesystem_unsafe")
        source.chmod(0o600)
        with patch.object(files.os, "listxattr", return_value=["user.private"]):
            self.bad(files.capture, source, code="filesystem_unsafe")
        fifo = self.root / "fifo"
        os.mkfifo(fifo, 0o600)
        self.bad(files.capture, fifo, code="filesystem_unsafe")
        directory = self.root / "directory"
        directory.mkdir()
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            self.bad(files._checked, descriptor, os.fstat(descriptor).st_dev + 1, code="filesystem_unsafe")
        finally:
            os.close(descriptor)

    def test_capture_enforces_limits_and_rejects_unrepresentable_names(self):
        source = self.write(self.root / "file", b"123")
        for setting, limit in (("MAX_FILE", 2), ("MAX_TOTAL", 2), ("MAX_ENTRIES", 0)):
            with patch.object(files, setting, limit):
                self.bad(files.capture, source, code="filesystem_limits")
        tree = self.root / "tree"
        self.tree(tree, b"123")
        with patch.object(files, "MAX_ENTRIES", 2):
            self.bad(files.capture, tree, code="filesystem_limits")
        with patch.object(files, "MAX_DEPTH", 1):
            self.bad(files.capture, tree, code="filesystem_unsafe")
        invalid = os.fsencode(tree) + b"/\xff"
        descriptor = os.open(invalid, os.O_WRONLY | os.O_CREAT, 0o600)
        os.close(descriptor)
        self.bad(files.capture, tree, code="filesystem_unsafe")

    def test_read_mutation_and_replaced_namespace_are_not_coherent_snapshots(self):
        source = self.write(self.root / "file")
        original = files.os.fdopen
        def changing(descriptor, *args, **kwargs):
            stream = original(descriptor, *args, **kwargs)
            read = stream.read
            def changed(*values):
                result = read(*values)
                self.write(source, b"new")
                return result
            stream.read = changed
            return stream
        with patch.object(files.os, "fdopen", side_effect=changing):
            self.bad(files.capture, source, code="filesystem_changed")
        def short(descriptor, *args, **kwargs):
            stream = original(descriptor, *args, **kwargs)
            stream.read = lambda *values: b""
            return stream
        with patch.object(files.os, "fdopen", side_effect=short):
            self.bad(files.capture, source, code="filesystem_changed")
        parent = self.root / "parent"
        parent.mkdir()
        target = self.write(parent / "target")
        def renamed(descriptor, *args, **kwargs):
            stream = original(descriptor, *args, **kwargs)
            read = stream.read
            def changed(*values):
                data = read(*values)
                parent.rename(self.root / "moved")
                parent.mkdir()
                self.write(parent / "target", b"foreign")
                return data
            stream.read = changed
            return stream
        with patch.object(files.os, "fdopen", side_effect=renamed):
            self.bad(files.capture, target, code="filesystem_changed")
        self.assertEqual(target.read_bytes(), b"foreign")

    def test_creation_failures_retain_partial_owned_data_and_close_descriptors(self):
        snapshot, blobs = files.capture(self.write(self.root / "source"))
        initial = len(os.listdir("/proc/self/fd"))
        with patch.object(files.os, "fdopen", side_effect=OSError("secret detail")):
            self.bad(files.materialize, self.root / "partial", snapshot, blobs, code="filesystem_storage_error")
        self.assertTrue((self.root / "partial").exists())
        self.assertEqual(len(os.listdir("/proc/self/fd")), initial)
        with patch.object(files.os, "fsync", side_effect=OSError("secret path")):
            self.bad(files.materialize, self.root / "unsynced", snapshot, blobs, code="filesystem_storage_error")
        self.assertEqual(len(os.listdir("/proc/self/fd")), initial)
        with patch.object(files, "_attributes", return_value=None):
            self.bad(files.materialize, self.root / "wrong-metadata", snapshot, blobs, code="filesystem_changed")

    def test_backups_are_private_verified_durable_and_reusable_without_overwrite(self):
        first, a = files.capture(self.write(self.root / "one", b"one"))
        second, b = files.capture(self.write(self.root / "two", b"two"))
        directory = self.root / "blobs"
        files.save_blobs(directory, a | b)
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        for path in directory.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        before = {path.name: path.stat().st_ino for path in directory.iterdir()}
        with patch.object(files.os, "fsync", wraps=os.fsync) as sync:
            files.save_blobs(directory, a | b)
            self.assertGreaterEqual(sync.call_count, 4)
        self.assertEqual(before, {path.name: path.stat().st_ino for path in directory.iterdir()})
        self.assertEqual(files.load_blobs(directory, [first, second, first, {"kind": "missing", "entries": []}]), a | b)
        self.assertEqual(files.load_blobs(directory, []), {})
        last = sorted(directory.iterdir())[-1]
        last.write_bytes(b"corrupt")
        self.bad(files.load_blobs, directory, [first, second], code="backup_invalid")
        self.bad(files.save_blobs, directory, a | b, code="backup_invalid")
        self.assertEqual(last.read_bytes(), b"corrupt")

    def test_backup_schema_limits_missing_bytes_and_unsafe_files_fail_before_use(self):
        snapshot, blobs = files.capture(self.write(self.root / "source"))
        digest = next(iter(blobs))
        for value in (None, [], {"invalid": b"data"}, {digest: "old"}, {digest: b"different"}):
            self.bad(files.save_blobs, self.root / "never", value, code="backup_invalid")
            self.assertFalse((self.root / "never").exists())
        for constant in ("MAX_FILE", "MAX_BLOBS", "MAX_ENTRIES"):
            with patch.object(files, constant, 0):
                self.bad(files.save_blobs, self.root / "never", blobs, code="backup_invalid")
        self.bad(files.materialize, self.root / "never", snapshot, {}, code="backup_invalid")
        different = copy.deepcopy(snapshot)
        different["entries"][0]["size"] += 1
        self.bad(files.materialize, self.root / "never", different, blobs, code="backup_invalid")
        self.bad(files.load_blobs, self.root / "never", [snapshot, different], code="snapshot_invalid")
        for value in (None, {}, [snapshot] * 65):
            self.bad(files.load_blobs, self.root / "never", value, code="snapshot_invalid")
        with patch.object(files, "MAX_BLOBS", 0):
            self.bad(files.load_blobs, self.root / "never", [snapshot], code="filesystem_limits")
        directory = self.root / "blobs"
        files.save_blobs(directory, blobs)
        self.bad(files.load_blobs, directory, [different], code="backup_invalid")
        with patch.object(files, "MAX_FILE", 2):
            self.bad(files._blob, directory, digest, code="backup_invalid")
        (directory / digest).chmod(0o644)
        self.bad(files.load_blobs, directory, [snapshot], code="filesystem_unsafe")
        (directory / digest).unlink()
        self.bad(files.load_blobs, directory, [snapshot], code="filesystem_storage_error")
        (directory / digest).symlink_to(self.root / "source")
        self.bad(files.save_blobs, directory, blobs, code="filesystem_unsafe")

    def test_backup_write_failure_retains_evidence_and_closes_descriptor(self):
        _, blobs = files.capture(self.write(self.root / "source"))
        directory = self.root / "blobs"
        initial = len(os.listdir("/proc/self/fd"))
        with patch.object(files.os, "fdopen", side_effect=OSError("private error")):
            self.bad(files.save_blobs, directory, blobs, code="filesystem_storage_error")
        self.assertEqual(len(os.listdir("/proc/self/fd")), initial)
        self.assertEqual(len(list(directory.iterdir())), 1)

    def test_all_real_forward_and_reverse_states_preserve_preimages(self):
        for tree in (False, True):
            for missing in (False, True):
                with self.subTest(tree=tree, missing=missing):
                    live, slot, before, after, _ = self.transaction(tree, missing)
                    self.assertEqual(files.classify(live, slot, before, after), "ready")
                    files.restore_target(live, slot, before, after)
                    events = []
                    files.apply_target(live, slot, before, after, events.append)
                    self.assertEqual(files.classify(live, slot, before, after), "applied")
                    self.assertEqual(files.capture(live)[0], after)
                    self.assertEqual(files.capture(slot / "old")[0], before)
                    self.assertEqual(events, [prefix + move for move in
                                     (("install_new",) if missing else ("park_old", "install_new"))
                                     for prefix in ("before_", "after_", "synced_")])
                    files.apply_target(live, slot, before, after)
                    files.restore_target(live, slot, before, after)
                    self.assertEqual(files.classify(live, slot, before, after), "restored")
                    self.assertEqual(files.capture(live)[0], before)
                    self.assertEqual(files.capture(slot / "undo")[0], after)
                    files.restore_target(live, slot, before, after)
                    self.bad(files.apply_target, live, slot, before, after, code="filesystem_unknown")

    def test_every_forward_rename_boundary_can_be_explicitly_restored(self):
        for event in (prefix + move for move in ("park_old", "install_new")
                      for prefix in ("before_", "after_", "synced_")):
            live, slot, before, after, _ = self.transaction(tree=True)
            def stop(actual):
                if actual == event:
                    raise Interrupted(actual)
            with self.assertRaises(Interrupted):
                files.apply_target(live, slot, before, after, stop)
            expected = "ready" if event == "before_park_old" else (
                "applied" if event in ("after_install_new", "synced_install_new") else "parked")
            self.assertEqual(files.classify(live, slot, before, after), expected)
            files.restore_target(live, slot, before, after)
            self.assertEqual(files.capture(live)[0], before)

    def test_every_reverse_rename_boundary_is_idempotently_resumable(self):
        for event in (prefix + move for move in ("park_undo", "restore_old")
                      for prefix in ("before_", "after_", "synced_")):
            live, slot, before, after, _ = self.transaction(tree=True)
            files.apply_target(live, slot, before, after)
            def stop(actual):
                if actual == event:
                    raise Interrupted(actual)
            with self.assertRaises(Interrupted):
                files.restore_target(live, slot, before, after, stop)
            expected = "applied" if event == "before_park_undo" else (
                "restored" if event in ("after_restore_old", "synced_restore_old") else "undo_parked")
            self.assertEqual(files.classify(live, slot, before, after), expected)
            files.restore_target(live, slot, before, after)
            self.assertEqual(files.capture(live)[0], before)

    def test_parked_forward_state_can_resume_application(self):
        live, slot, before, after, _ = self.transaction()
        os.rename(live, slot / "old")
        self.assertEqual(files.classify(live, slot, before, after), "parked")
        files.apply_target(live, slot, before, after)
        self.assertEqual(files.capture(live)[0], after)

    def test_process_death_recovers_without_installed_application_or_candidate(self):
        live, slot, before, after, _ = self.transaction(tree=True)
        spec = self.root / "spec.json"
        spec.write_text(json.dumps([str(live), str(slot), before, after]))
        program = ("import json,os,sys;from cgp_cert_manager import update_files as f;"
                   "args=json.load(open(sys.argv[1]));"
                   "f.apply_target(*args,checkpoint=lambda event:os._exit(73) if event=='after_park_old' else None)")
        result = subprocess.run([sys.executable, "-c", program, str(spec)], capture_output=True)
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertFalse(live.exists())
        shutil.rmtree(live.parent / "candidate")
        result = subprocess.run([sys.executable, "-c", "import json,sys;from cgp_cert_manager import update_files as f;"
                                 "f.restore_target(*json.load(open(sys.argv[1])))", str(spec)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(files.capture(live)[0], before)

    def test_unknown_states_and_post_checkpoint_changes_never_overwrite(self):
        for change in ("live", "missing", "extra", "new", "old"):
            live, slot, before, after, _ = self.transaction()
            if change == "live":
                self.write(live, b"manual")
            elif change == "missing":
                live.unlink()
            elif change == "extra":
                self.write(slot / "unrecorded", b"foreign")
            elif change == "new":
                self.write(slot / "new", b"foreign")
            else:
                self.write(slot / "old", b"foreign")
            self.assertEqual(files.classify(live, slot, before, after), "unknown")
            with patch.object(files.os, "rename", side_effect=AssertionError("no write")):
                self.bad(files.apply_target, live, slot, before, after, code="filesystem_unknown")
                self.bad(files.restore_target, live, slot, before, after, code="filesystem_unknown")
        live, slot, before, after, _ = self.transaction()
        def changed(event):
            if event == "before_park_old":
                self.write(live, b"manual")
        self.bad(files.apply_target, live, slot, before, after, changed, code="filesystem_unknown")
        self.assertEqual(live.read_bytes(), b"manual")
        self.assertFalse((slot / "old").exists())

    def test_slot_contract_rejects_unsupported_or_unsafe_layouts(self):
        live, slot, before, after, blobs = self.transaction()
        self.bad(files.prepare_slot, live, slot, after, blobs, code="filesystem_unknown")
        self.bad(files.classify, live, live, before, after, code="filesystem_unsafe")
        self.bad(files.classify, live, self.root / "other", before, after, code="filesystem_unsafe")
        self.bad(files.classify, live, slot, after, after, code="snapshot_invalid")
        missing = {"kind": "missing", "entries": []}
        self.bad(files.classify, live, slot, before, missing, code="snapshot_invalid")
        self.bad(files.prepare_slot, live, live.parent / "empty", missing, {}, code="snapshot_invalid")
        self.bad(files.prepare_slot, live, live.parent / "empty", after, {}, code="backup_invalid")
        slot.chmod(0o755)
        self.bad(files.classify, live, slot, before, after, code="filesystem_unsafe")

    def test_fsync_failure_after_rename_retains_recognizable_state(self):
        live, slot, before, after, _ = self.transaction()
        def failing(event):
            if event == "after_park_old":
                self.enterContext(patch.object(files.os, "fsync", side_effect=OSError("I/O private detail")))
        self.bad(files.apply_target, live, slot, before, after, failing, code="filesystem_storage_error")
        self.assertEqual(files.classify(live, slot, before, after), "parked")
        self.assertEqual(files.capture(slot / "old")[0], before)


if __name__ == "__main__":
    unittest.main()
