"""Private storage policy and filesystem fault tests with disposable paths."""
import contextlib
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cgp_cert_manager import core, storage as s


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def file(self, name="private.json", text="original", mode=0o600):
        path = self.root / name
        path.write_text(text)
        path.chmod(mode)
        return path

    def test_private_directory_creation_checks_each_new_component(self):
        path = self.root / "state" / "backups" / "example.com"
        s.ensure_private_directory(path)
        for directory in (path, path.parent, path.parent.parent):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            self.assertEqual(directory.stat().st_uid, os.geteuid())
        self.assertTrue(s.check_private_directory(path))

    def test_existing_directory_is_not_repaired(self):
        path = self.root / "state"
        path.mkdir(mode=0o755)
        before = path.stat().st_mode
        for operation in (s.check_private_directory, s.ensure_private_directory):
            with self.assertRaisesRegex(s.StorageError, "private directory"):
                operation(path)
        self.assertEqual(path.stat().st_mode, before)
        self.assertEqual(list(path.iterdir()), [])

    def test_missing_directory_policy_has_no_read_side_effects(self):
        missing = self.root / "missing" / "state"
        self.assertFalse(s.check_private_directory(missing, missing_ok=True))
        self.assertEqual(s.private_files(missing), [])
        s.validate_tree(missing)
        self.assertFalse(missing.parent.exists())
        with self.assertRaises(FileNotFoundError):
            s.check_private_directory(missing)
        with self.assertRaises(FileNotFoundError):
            s.private_files(missing, missing_ok=False)

    def test_directory_symlinks_and_parent_traversal_rejected(self):
        real = self.root / "real"
        real.mkdir(mode=0o700)
        alias = self.root / "alias"
        alias.symlink_to(real, target_is_directory=True)
        for path in (alias, alias / "new"):
            with self.assertRaises(s.StorageError):
                s.ensure_private_directory(path)
        with self.assertRaisesRegex(s.StorageError, "Parent traversal"):
            s.ensure_private_directory(real / ".." / "new")
        self.assertEqual(list(real.iterdir()), [])

    def test_unsafe_ancestor_refuses_creation(self):
        parent = self.root / "writable"
        parent.mkdir(mode=0o777)
        parent.chmod(0o777)
        with self.assertRaisesRegex(s.StorageError, "ancestor"):
            s.ensure_private_directory(parent / "private")
        self.assertFalse((parent / "private").exists())
        self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o777)

    def test_trusted_sticky_ancestor_allows_owned_private_child(self):
        parent = self.root / "sticky"
        parent.mkdir(mode=0o1777)
        parent.chmod(0o1777)
        s.ensure_private_directory(parent / "private")
        self.assertEqual(stat.S_IMODE((parent / "private").stat().st_mode), 0o700)

    def test_foreign_owner_rejected_for_private_and_ancestor_directory(self):
        actual_fstat = os.fstat
        bad = self.root / "foreign"
        bad.mkdir(mode=0o700)
        inode = bad.stat().st_ino

        def fstat(fd):
            info = actual_fstat(fd)
            if info.st_ino == inode:
                return SimpleNamespace(st_mode=info.st_mode, st_uid=os.geteuid()+1)
            return info

        with patch.object(s.os, "fstat", side_effect=fstat):
            for path in (bad, bad / "child"):
                with self.assertRaises(s.StorageError):
                    s.ensure_private_directory(path)
        self.assertFalse((bad / "child").exists())

    def test_directory_metadata_type_guard(self):
        path = self.file()
        with self.assertRaisesRegex(s.StorageError, "Not a directory"):
            s._check_directory(path.stat(), path, True)
        with self.assertRaises(s.StorageError):
            s.check_private_directory(path)

    def test_directory_creation_race_still_validates_winner(self):
        mkdir = os.mkdir
        path = self.root / "raced"

        def raced(name, mode=0o777, **kwargs):
            mkdir(name, mode, **kwargs)
            raise FileExistsError()

        with patch.object(s.os, "mkdir", side_effect=raced):
            s.ensure_private_directory(path)
        self.assertTrue(s.check_private_directory(path))

    def test_created_directory_fsync_failure_does_not_leak_descriptors(self):
        before = len(os.listdir("/proc/self/fd"))
        fsync = os.fsync
        inode = self.root.stat().st_ino
        def fail_parent(fd):
            if os.fstat(fd).st_ino == inode:
                raise OSError("disk error")
            return fsync(fd)
        with patch.object(s.os, "fsync", side_effect=fail_parent):
            with self.assertRaises(OSError):
                s.ensure_private_directory(self.root / "new")
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)
        self.assertTrue((self.root / "new").is_dir())
        synced = []
        with patch.object(s.os, "fsync", side_effect=lambda fd: synced.append(os.fstat(fd).st_ino)):
            s.ensure_private_directory(self.root / "new")
        self.assertIn(inode, synced)

    def test_root_directory_is_never_treated_as_private(self):
        with self.assertRaises(s.StorageError):
            s.check_private_directory(Path(self.root.anchor))

    def test_read_and_missing_private_files(self):
        path = self.file(text="секрет")
        self.assertEqual(s.read_text(path), "секрет")
        self.assertTrue(s.check_private_file(path))
        self.assertFalse(s.check_private_file(self.root / "absent", missing_ok=True))
        with self.assertRaises(FileNotFoundError):
            s.check_private_file(self.root / "absent")
        self.assertFalse((self.root / "absent").exists())

    def test_private_file_modes_are_checked_without_chmod_or_truncation(self):
        path = self.file()
        for mode in (0o644, 0o660, 0o601, 0o700, 0o4600):
            with self.subTest(mode=oct(mode)):
                path.chmod(mode)
                for operation in (lambda: s.read_text(path),
                                  lambda: self.write_direct(path, "changed"),
                                  lambda: s.atomic_text(path, "changed")):
                    with self.assertRaises(s.StorageError):
                        operation()
                self.assertEqual(path.read_text(), "original")
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
        path.chmod(0o400)
        self.assertEqual(s.read_text(path), "original")

    def write_direct(self, path, text):
        with s.open_private(path, "w", create=True) as stream:
            stream.write(text)

    def test_file_append_and_truncate_only_after_validation(self):
        path = self.root / "history.jsonl"
        with s.open_private(path, "a", create=True) as stream:
            stream.write("one\n")
        with s.open_private(path, "a") as stream:
            stream.write("two\n")
        self.assertEqual(path.read_text(), "one\ntwo\n")
        self.write_direct(path, "short")
        self.assertEqual(path.read_text(), "short")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        with self.assertRaises(ValueError):
            with s.open_private(path, "invalid"):
                pass

    def test_leaf_symlink_hardlink_fifo_and_directory_are_refused(self):
        target = self.file("target", "unchanged")
        link = self.root / "symlink"
        link.symlink_to(target)
        dangling = self.root / "dangling"
        dangling.symlink_to(self.root / "missing")
        hardlink = self.root / "hardlink"
        os.link(target, hardlink)
        fifo = self.root / "fifo"
        os.mkfifo(fifo, 0o600)
        directory = self.root / "directory"
        directory.mkdir(mode=0o700)
        for path in (link, dangling, hardlink, target, fifo, directory):
            with self.subTest(path=path.name):
                with self.assertRaises(s.StorageError):
                    s.read_text(path)
                with self.assertRaises(s.StorageError):
                    s.atomic_text(path, "changed")
        self.assertEqual(target.read_text(), "unchanged")
        self.assertFalse((self.root / "missing").exists())
        self.assertFalse(list(self.root.glob(".cgp-*")))

    def test_file_owner_checked_on_opened_inode(self):
        path = self.file()
        inode = path.stat().st_ino
        fstat = os.fstat

        def foreign(fd):
            info = fstat(fd)
            if info.st_ino == inode:
                return SimpleNamespace(st_mode=info.st_mode, st_uid=os.geteuid()+1, st_nlink=1)
            return info

        before = len(os.listdir("/proc/self/fd"))
        with patch.object(s.os, "fstat", side_effect=foreign):
            with self.assertRaises(s.StorageError):
                s.read_text(path)
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_private_file_in_trusted_public_directory_is_allowed(self):
        directory = self.root / "config"
        directory.mkdir(mode=0o755)
        path = directory / "config.json"
        s.atomic_json(path, {"schema": 2})
        self.assertEqual(core.load(path), {"schema": 2})
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o755)

    def test_ancestor_symlink_never_creates_or_reads_private_file(self):
        directory = self.root / "real"
        directory.mkdir(mode=0o700)
        path = directory / "config.json"
        s.atomic_json(path, {"old": True})
        alias = self.root / "alias"
        alias.symlink_to(directory, target_is_directory=True)
        with self.assertRaises(s.StorageError):
            s.read_text(alias / path.name)
        with self.assertRaises(s.StorageError):
            s.atomic_json(alias / path.name, {"changed": True})
        self.assertEqual(core.load(path), {"old": True})

    def test_atomic_unicode_json_and_nested_private_parents(self):
        path = self.root / "a" / "b" / "data.json"
        core.atomic(path, {"label": "тест"})
        self.assertEqual(core.load(path), {"label": "тест"})
        self.assertTrue(path.read_text().endswith("\n"))
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(path.parent.parent.stat().st_mode), 0o700)
        self.assertEqual(list(path.parent.iterdir()), [path])

    def test_atomic_serialization_failure_preserves_old_file(self):
        path = self.file(text='{"old": true}')
        with self.assertRaises(TypeError):
            s.atomic_json(path, {"bad": object()})
        self.assertEqual(core.load(path), {"old": True})
        self.assertEqual(list(self.root.iterdir()), [path])

    def test_stream_construction_failure_closes_descriptors_and_preserves_data(self):
        path = self.file()
        for operation in (lambda: s.read_text(path), lambda: s.atomic_text(path, "new")):
            before = len(os.listdir("/proc/self/fd"))
            with patch.object(s.os, "fdopen", side_effect=OSError("stream failure")):
                with self.assertRaises(OSError):
                    operation()
            self.assertEqual(len(os.listdir("/proc/self/fd")), before)
            self.assertEqual(path.read_text(), "original")
            self.assertEqual(list(self.root.iterdir()), [path])

    def test_atomic_file_fsync_or_replace_failure_preserves_old_file(self):
        path = self.file()
        for operation in ("fsync", "replace"):
            with patch.object(s.os, operation, side_effect=OSError("disk error")):
                with self.assertRaises(OSError):
                    s.atomic_text(path, "new")
            self.assertEqual(path.read_text(), "original")
            self.assertEqual(list(self.root.iterdir()), [path])

    def test_atomic_directory_fsync_failure_keeps_inspectable_new_file(self):
        path = self.file()
        fsync = os.fsync

        def fail_directory(fd):
            if os.fstat(fd).st_ino == path.parent.stat().st_ino:
                raise OSError("directory sync failed")
            return fsync(fd)

        with patch.object(s.os, "fsync", side_effect=fail_directory):
            with self.assertRaises(OSError):
                s.atomic_text(path, "new")
        self.assertEqual(s.read_text(path), "new")
        self.assertEqual(list(self.root.iterdir()), [path])

    def test_atomic_revalidates_changed_target_before_replace(self):
        path = self.file()

        def write(stream):
            stream.write("new")
            path.chmod(0o644)

        with self.assertRaises(s.StorageError):
            s._atomic(path, write)
        self.assertEqual(path.read_text(), "original")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
        self.assertEqual(list(self.root.iterdir()), [path])

    def test_private_files_validate_all_before_return(self):
        first = self.file("a.json")
        last = self.file("z.json")
        other = self.file("notes.txt")
        self.assertEqual(s.private_files(self.root), [first, last])
        self.assertEqual(s.private_files(self.root, suffix=".txt"), [other])
        last.chmod(0o644)
        with self.assertRaises(s.StorageError):
            s.private_files(self.root)
        self.assertTrue(first.exists())
        self.assertTrue(last.exists())

    def test_tree_checks_every_private_entry_without_reading(self):
        nested = self.root / "backups"
        nested.mkdir(mode=0o700)
        path = nested / "copy.json"
        s.atomic_text(path, "not even JSON")
        with patch.object(s, "read_text", side_effect=AssertionError("content read")):
            s.validate_tree(self.root)
        path.chmod(0o644)
        with self.assertRaises(s.StorageError):
            s.validate_tree(self.root)
        path.chmod(0o600)
        nested.chmod(0o755)
        with self.assertRaises(s.StorageError):
            s.validate_tree(self.root)

    def test_lock_is_exclusive_keeps_content_and_releases_on_exception(self):
        state = self.root / "state"
        with s.operation_lock(state) as lock:
            lock.write("kept")
            lock.flush()
            with self.assertRaises(BlockingIOError):
                with s.operation_lock(state):
                    pass
        with self.assertRaisesRegex(RuntimeError, "interrupted"):
            with s.operation_lock(state):
                raise RuntimeError("interrupted")
        with s.operation_lock(state):
            self.assertEqual(s.read_text(state / "run.lock"), "kept")
        self.assertEqual(stat.S_IMODE((state / "run.lock").stat().st_mode), 0o600)

    def test_load_default_applies_only_to_missing_files(self):
        path = self.root / "missing"
        self.assertEqual(core.load(path, {}), {})
        with self.assertRaises(FileNotFoundError):
            core.load(path)
        path.symlink_to(self.root / "elsewhere")
        with self.assertRaises(s.StorageError):
            core.load(path, {})
        path.unlink()
        path.write_text("not JSON")
        path.chmod(0o600)
        with self.assertRaises(ValueError):
            core.load(path, {})

    def test_credentials_checked_before_token_parsing(self):
        path = self.file("cloudflare.ini", "dns_cloudflare_api_token = dummy\n", 0o644)
        with self.assertRaises(s.StorageError):
            core.token(path)
        path.chmod(0o600)
        self.assertEqual(core.token(path), "dummy")
        alias = self.root / "credentials-link"
        alias.symlink_to(path)
        with self.assertRaises(s.StorageError):
            core.token(alias)

    def test_issuance_checks_credentials_before_dns_or_subprocess(self):
        good = self.file("good.ini", "dns_cloudflare_api_token = dummy\n")
        bad = self.file("bad.ini", "dns_cloudflare_api_token = dummy\n", 0o644)
        alias = self.root / "link.ini"
        alias.symlink_to(good)
        domain = {"cert_name": "example.com", "names": ["example.com", "example.net"]}
        args = SimpleNamespace(force_renew=False, dry_run=False)
        for unsafe in (bad, alias):
            zones = {"example.com": {"credentials": str(good)}, "example.net": {"credentials": str(unsafe)}}
            with patch.object(core, "local_info") as local, patch.object(core, "dns_preflight") as dns, patch.object(core.subprocess, "run") as process:
                with self.assertRaises(s.StorageError):
                    core.issue({"email": "admin@example.com"}, domain, zones, args)
                local.assert_not_called()
                dns.assert_not_called()
                process.assert_not_called()

    def test_backup_paths_are_validated_and_returned_newest_first(self):
        state = self.root / "state"
        with patch.object(core, "STATE", state):
            self.assertEqual(core.backup_files("example.com"), [])
            state.mkdir(mode=0o700)
            self.assertEqual(core.backup_files("example.com"), [])
            path = core.backup("example.com", {"saved": 1})
            other = path.with_name("19000101T000000000000Z.json")
            s.atomic_json(other, {"saved": 0})
            self.assertEqual(core.backup_files("example.com"), [path, other])
            for directory in (path.parent, path.parent.parent, state):
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            self.assertEqual(core.load(path), {"saved": 1})
            other.chmod(0o644)
            before = set(path.parent.iterdir())
            with self.assertRaises(s.StorageError):
                core.backup("example.com", {"saved": 2})
            self.assertEqual(set(path.parent.iterdir()), before)
