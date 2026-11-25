"""Offline coordinator exercises real signatures, archives, files and locks."""
from copy import deepcopy
import fcntl
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cgp_cert_manager import storage, update_archive as archive, update_metadata as metadata, update_plan as p
from test_update_metadata import NOW, PUBLIC, SEED, b64


class UpdatePlanTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.installed = self.root / "installed"
        (self.installed / "cgp_cert_manager").mkdir(parents=True)
        self.version_file = self.installed / "cgp_cert_manager" / "__init__.py"
        self.version_file.write_text("__version__ = '2.2.0.dev11'\n")
        self.version_file.chmod(0o644)
        self.state = self.root / "state"
        self.trust_path = self.root / "trust.json"
        self.key = Ed25519PrivateKey.from_private_bytes(SEED)
        self.key_id = hashlib.sha256(PUBLIC).hexdigest()
        self.trust = {"schema": 1, "project": metadata.PROJECT, "channel": "stable",
                      "keys": {self.key_id: b64(PUBLIC)}}
        self.trust_path.write_bytes(metadata.canonical(self.trust))
        self.trust_path.chmod(0o600)
        self.options = {"manifest_path": self.root / "manifest.json", "signature_path": self.root / "signature.json",
                        "archive_path": self.root / "release.tar.gz", "trust_path": self.trust_path,
                        "installed_root": self.installed, "state_dir": self.state}
        self.status_options = {key: self.options[key] for key in ("trust_path", "installed_root", "state_dir")}
        self.enterContext(patch.object(p.time, "time", return_value=NOW + 0.75))
        self.package()

    def package(self, release="2.3.4", sequence=7, channel="stable"):
        prefix = metadata.PROJECT + "-v" + release
        distribution = "cgp_certbot_dns-" + release + ".dist-info"
        self.files = {"README.md": (b"source\n", 0o644), "docs/ёж.txt": (b"unicode path\n", 0o644),
                      "cgp_cert_manager/__init__.py": (("__version__ = " + repr(release) + "\n").encode(), 0o644),
                      distribution + "/METADATA": (("Metadata-Version: 2.1\nName: cgp-certbot-dns\nVersion: " + release + "\n\n").encode(), 0o644),
                      distribution + "/entry_points.txt": (b"[certbot.plugins]\ncgp-dns = cgp_cert_manager.certbot_dns:Authenticator\n", 0o644),
                      distribution + "/top_level.txt": (b"cgp_cert_manager\n", 0o644),
                      "install.sh": (("#!/bin/sh\ntouch " + str(self.root / "EXECUTED") + "\n").encode(), 0o755)}
        stream = io.BytesIO()
        with gzip.GzipFile(filename="", fileobj=stream, mode="wb", mtime=0, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as package:
                directory = tarfile.TarInfo(prefix + "/")
                directory.mode, directory.type = 0o755, tarfile.DIRTYPE
                package.addfile(directory)
                for path, (data, mode) in sorted(self.files.items(), key=lambda item: item[0].encode("utf-8")):
                    info = tarfile.TarInfo(prefix + "/" + path)
                    info.mode, info.size = mode, len(data)
                    package.addfile(info, io.BytesIO(data))
        self.data = stream.getvalue()
        self.manifest = {"schema": 1, "project": metadata.PROJECT, "channel": channel, "sequence": sequence,
                         "version": release, "issued_at": NOW - 60, "expires_at": NOW + 3600,
                         "source": {"repository": metadata.REPOSITORY, "commit": "a" * 40, "tree": "b" * 40,
                                    "tag": "v" + release},
                         "archive": {"name": prefix + ".tar.gz", "size": len(self.data),
                                     "sha256": hashlib.sha256(self.data).hexdigest()}}
        self.options["archive_path"].write_bytes(self.data)
        self.sign()
        for key in ("manifest_path", "signature_path", "archive_path"):
            self.options[key].chmod(0o644)

    def sign(self):
        raw = metadata.canonical(self.manifest)
        signature = {"schema": 1, "key_id": self.key_id, "signature": b64(self.key.sign(metadata.DOMAIN + raw))}
        self.options["manifest_path"].write_bytes(raw)
        self.options["signature_path"].write_bytes(metadata.canonical(signature))

    def checkpoint(self):
        return json.loads((self.state / "checkpoint.json").read_text())

    def write_checkpoint(self, value):
        path = self.state / "checkpoint.json"
        path.write_bytes(metadata.canonical(value))
        path.chmod(0o600)

    def result(self, action, **changes):
        options = self.status_options if action == "status" else self.options
        return getattr(p, action)(**{**options, **changes})

    def assert_failure(self, action, code, status="invalid", **changes):
        result = self.result(action, **changes)
        self.assertEqual(result, {"schema": 1, "action": action, "status": status, "plan": None, "error": code})
        self.assertNotIn(str(self.root), json.dumps(result))
        return result

    def make_lock(self):
        self.state.mkdir(mode=0o700, exist_ok=True)
        path = self.state / "run.lock"
        path.touch(mode=0o600)
        return path

    def stage_directory(self):
        return self.state / "staged" / self.checkpoint()["prepared"]["stage"]

    def test_check_is_read_only_and_public_plan_is_complete(self):
        with patch.object(storage, "atomic_json") as written, patch.object(archive, "stage") as staged, \
                patch.object(os, "fsync", side_effect=AssertionError("read-only")), \
                patch.object(socket, "socket", side_effect=AssertionError("no network")), \
                patch.object(subprocess, "run", side_effect=AssertionError("no execution")):
            result = self.result("check")
        self.assertEqual((result["schema"], result["action"], result["status"], result["error"]), (1, "check", "verified", None))
        expected = {"plan_id", "project", "channel", "sequence", "installed_version", "target_version", "key_id",
                    "manifest_sha256", "archive_sha256", "archive_size", "source_commit", "source_tree", "release_tag",
                    "issued_at", "expires_at", "file_count", "total_bytes", "inventory_sha256", "created_at", "apply_supported"}
        self.assertEqual(set(result["plan"]), expected)
        self.assertEqual(result["plan"]["file_count"], len(self.files))
        self.assertEqual(result["plan"]["total_bytes"], sum(len(data) for data, mode in self.files.values()))
        self.assertEqual(result["plan"]["created_at"], NOW)
        self.assertIs(result["plan"]["apply_supported"], False)
        self.assertEqual(result["plan"]["installed_version"], "2.2.0.dev11")
        self.assertNotIn(str(self.root), json.dumps(result))
        self.assertNotIn(b64(PUBLIC), json.dumps(result))
        self.assertFalse(self.state.exists())
        self.assertFalse((self.root / "EXECUTED").exists())
        written.assert_not_called()
        staged.assert_not_called()

    def test_prepare_durable_record_and_read_only_status_without_source_artifacts(self):
        checked = self.result("check")["plan"]
        prepared = self.result("prepare")
        self.assertEqual(prepared["status"], "prepared")
        self.assertEqual(prepared["plan"], checked)
        checkpoint = self.checkpoint()
        self.assertEqual(set(checkpoint), {"schema", "floors", "prepared"})
        self.assertEqual(checkpoint["floors"]["stable"]["manifest_sha256"], prepared["plan"]["manifest_sha256"])
        self.assertEqual(stat.S_IMODE((self.state / "checkpoint.json").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)
        self.assertNotIn(b64(PUBLIC), (self.state / "checkpoint.json").read_text())
        self.assertNotIn(str(self.trust_path), (self.state / "checkpoint.json").read_text())
        before = (self.state / "checkpoint.json").read_bytes()
        for key in ("manifest_path", "signature_path", "archive_path"):
            self.options[key].unlink()
        with patch.object(os, "fsync", side_effect=AssertionError("read-only")), \
                patch.object(storage, "atomic_json", side_effect=AssertionError("no writes")):
            status = self.result("status")
        self.assertEqual(status, {**prepared, "action": "status"})
        self.assertEqual(before, (self.state / "checkpoint.json").read_bytes())
        self.assertFalse((self.root / "EXECUTED").exists())

    def test_existing_empty_state_is_initialized_only_by_prepare(self):
        self.assert_failure("status", "state_missing", "missing")
        self.state.mkdir(mode=0o700)
        self.assert_failure("check", "lock_missing", "missing")
        self.assert_failure("status", "lock_missing", "missing")
        self.assertEqual(list(self.state.iterdir()), [])
        self.assertEqual(self.result("prepare")["status"], "prepared")

    def test_lock_without_checkpoint_has_no_prepared_plan(self):
        self.make_lock()
        self.assert_failure("status", "prepared_missing", "missing")
        self.assertEqual(self.result("check")["status"], "verified")
        self.assertFalse((self.state / "checkpoint.json").exists())

    def test_shared_readers_and_exclusive_preparer_obey_real_nonblocking_lock(self):
        lock_path = self.make_lock()
        with lock_path.open("rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            for action in ("check", "prepare", "status"):
                self.assert_failure(action, "state_busy", "busy")
            fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            self.assertEqual(self.result("check")["status"], "verified")
            self.assert_failure("prepare", "state_busy", "busy")
        self.assertFalse((self.state / "checkpoint.json").exists())

    def test_same_plan_reuses_stage_and_advances_only_floor_observation_time(self):
        first = self.result("prepare")
        stage = self.stage_directory()
        before = sorted(path.name for path in (self.state / "staged").iterdir())
        with patch.object(p.time, "time", return_value=NOW + 2.9), patch.object(archive, "stage") as created:
            second = self.result("prepare")
        self.assertEqual(first, second)
        self.assertEqual(self.checkpoint()["floors"]["stable"]["checked_at"], NOW + 2)
        self.assertEqual(self.checkpoint()["prepared"]["created_at"], NOW)
        self.assertEqual(sorted(path.name for path in (self.state / "staged").iterdir()), before)
        self.assertEqual(self.stage_directory(), stage)
        created.assert_not_called()

    def test_plan_identity_binds_signature_trust_and_installed_file_but_not_clock(self):
        first = self.result("check")["plan"]["plan_id"]
        with patch.object(p.time, "time", return_value=NOW + 1):
            self.assertEqual(self.result("check")["plan"]["plan_id"], first)
        signature = json.loads(self.options["signature_path"].read_text())
        self.options["signature_path"].write_text(json.dumps(signature, indent=2))
        second = self.result("check")["plan"]["plan_id"]
        self.assertNotEqual(first, second)
        self.sign()
        self.trust_path.write_text(json.dumps(self.trust, indent=2))
        self.assertEqual(self.result("check")["plan"]["plan_id"], first)
        self.version_file.write_text("# same version, different baseline bytes\n__version__='2.2.0.dev11'\n")
        self.assertNotEqual(self.result("check")["plan"]["plan_id"], first)

    def test_invalid_authentication_and_archive_never_create_state(self):
        self.options["signature_path"].write_text("PRIVATE malformed signature")
        self.assert_failure("prepare", "invalid_signature")
        self.assertFalse(self.state.exists())
        self.sign()
        self.options["archive_path"].write_bytes(b"PRIVATE changed archive")
        self.assert_failure("prepare", "archive_mismatch")
        self.assertFalse(self.state.exists())

    def test_archive_is_captured_once_and_not_reopened_after_validation(self):
        inspect = archive.inspect_archive
        seen = []
        snapshot = p._snapshot

        def read(path, *args, **kwargs):
            seen.append(path)
            return snapshot(path, *args, **kwargs)

        def inspected(data, manifest):
            inventory = inspect(data, manifest)
            self.options["archive_path"].write_bytes(b"PRIVATE replacement")
            return inventory

        with patch.object(archive, "inspect_archive", side_effect=inspected), patch.object(p, "_snapshot", side_effect=read):
            result = self.result("prepare")
        self.assertEqual(result["status"], "prepared")
        self.assertEqual(seen.count(self.options["archive_path"]), 1)
        self.assertEqual(self.result("status")["status"], "prepared")

    def test_current_trust_and_installed_baseline_changes_invalidate_saved_plan(self):
        self.assertEqual(self.result("prepare")["status"], "prepared")
        self.trust["channel"] = "candidate"
        self.trust_path.write_bytes(metadata.canonical(self.trust))
        self.assert_failure("status", "configuration_changed", "configuration_changed")
        self.trust["channel"] = "stable"
        self.trust_path.write_bytes(metadata.canonical(self.trust))
        self.version_file.write_text("__version__ = '2.2.0.dev12'\n")
        self.assert_failure("status", "configuration_changed", "configuration_changed")
        self.version_file.write_text("__version__ = '2.2.0.dev11'\n")
        alternate = self.root / "other-installation"
        (alternate / "cgp_cert_manager").mkdir(parents=True)
        (alternate / "cgp_cert_manager" / "__init__.py").write_bytes(self.version_file.read_bytes())
        self.assert_failure("status", "configuration_changed", "configuration_changed", installed_root=alternate)

    def test_recheck_before_commit_detects_changes_and_retains_private_orphan(self):
        stage = archive.stage

        def changed(data, manifest, parent):
            result = stage(data, manifest, parent)
            self.version_file.write_text("__version__='2.2.0.dev12'\n")
            return result

        with patch.object(archive, "stage", side_effect=changed):
            self.assert_failure("prepare", "configuration_changed", "configuration_changed")
        self.assertFalse((self.state / "checkpoint.json").exists())
        self.assertEqual(len(list((self.state / "staged").iterdir())), 1)
        self.assertEqual(stat.S_IMODE(next((self.state / "staged").iterdir()).stat().st_mode), 0o700)

    def test_existing_stage_corruption_is_detected_and_never_silently_rebuilt(self):
        self.assertEqual(self.result("prepare")["status"], "prepared")
        before = (self.state / "checkpoint.json").read_bytes()
        leaf = self.stage_directory() / self.manifest["archive"]["name"].removesuffix(".tar.gz") / "README.md"
        leaf.write_text("changed")
        with patch.object(archive, "stage") as rebuilt:
            self.assert_failure("prepare", "archive_invalid")
            self.assert_failure("status", "archive_invalid")
        rebuilt.assert_not_called()
        self.assertEqual(before, (self.state / "checkpoint.json").read_bytes())

    def test_expiry_and_clock_regression_leave_checkpoint_unchanged(self):
        self.assertEqual(self.result("prepare")["status"], "prepared")
        before = (self.state / "checkpoint.json").read_bytes()
        with patch.object(p.time, "time", return_value=self.manifest["expires_at"]):
            self.assert_failure("status", "expired_manifest", "expired")
            self.assert_failure("prepare", "expired_manifest", "expired")
        with patch.object(p.time, "time", return_value=NOW - 1):
            self.assert_failure("status", "clock_moved_backwards")
            self.assert_failure("prepare", "clock_moved_backwards")
        self.assertEqual(before, (self.state / "checkpoint.json").read_bytes())

    def test_key_and_channel_rotation_preserve_independent_high_water_floors(self):
        self.assertEqual(self.result("prepare")["status"], "prepared")
        stable = deepcopy(self.checkpoint()["floors"]["stable"])
        self.trust["channel"] = "candidate"
        self.trust_path.write_bytes(metadata.canonical(self.trust))
        self.package("2.4.0rc1", 3, "candidate")
        self.assertEqual(self.result("prepare")["status"], "prepared")
        self.assertEqual(self.checkpoint()["floors"]["stable"], stable)
        self.assertEqual(self.checkpoint()["floors"]["candidate"]["sequence"], 3)
        self.trust["channel"] = "stable"
        other_public = bytes(range(32))
        self.trust["keys"][hashlib.sha256(other_public).hexdigest()] = b64(other_public)
        self.trust_path.write_bytes(metadata.canonical(self.trust))
        self.package("2.3.4", 6)
        self.assert_failure("prepare", "rollback")
        self.package("2.3.4", 7)
        self.assertEqual(self.result("prepare")["status"], "prepared")
        self.assertIn("candidate", self.checkpoint()["floors"])

    def test_floor_is_reloaded_under_exclusive_lock(self):
        self.assertEqual(self.result("prepare")["status"], "prepared")
        checkpoint = self.checkpoint()
        self.package("2.3.5", 8)
        inspect = archive.inspect_archive

        def concurrently_advanced(data, manifest):
            value = inspect(data, manifest)
            checkpoint["prepared"] = None
            checkpoint["floors"]["stable"]["sequence"] = 9
            self.write_checkpoint(checkpoint)
            return value

        with patch.object(archive, "inspect_archive", side_effect=concurrently_advanced):
            self.assert_failure("prepare", "rollback")
        self.assertEqual(self.checkpoint()["floors"]["stable"]["sequence"], 9)
        self.assertEqual(len(list((self.state / "staged").iterdir())), 1)

    def test_four_retained_stages_are_capped_without_pruning_or_blocking_reuse(self):
        for sequence in range(7, 11):
            self.package(sequence=sequence)
            self.assertEqual(self.result("prepare")["status"], "prepared")
        directories = set((self.state / "staged").iterdir())
        self.assertEqual(len(directories), 4)
        self.assertEqual(self.result("prepare")["status"], "prepared")
        checkpoint = (self.state / "checkpoint.json").read_bytes()
        self.package(sequence=11)
        self.assert_failure("prepare", "stage_limit")
        self.assertEqual(set((self.state / "staged").iterdir()), directories)
        self.assertEqual(checkpoint, (self.state / "checkpoint.json").read_bytes())

    def test_unexpected_or_unsafe_stage_entry_refuses_new_staging(self):
        self.make_lock()
        parent = self.state / "staged"
        parent.mkdir(mode=0o700)
        unexpected = parent / "PRIVATE-unrecognized"
        unexpected.mkdir()
        self.assert_failure("prepare", "state_invalid")
        unexpected.rmdir()
        child = parent / "release-abcdefgh"
        child.mkdir(mode=0o755)
        self.assert_failure("prepare", "state_invalid")
        self.assertFalse((self.state / "checkpoint.json").exists())

    def test_atomic_write_failure_preserves_old_checkpoint_and_new_orphan(self):
        self.assertEqual(self.result("prepare")["status"], "prepared")
        before = (self.state / "checkpoint.json").read_bytes()
        self.package(sequence=8)
        with patch.object(storage, "atomic_json", side_effect=OSError("PRIVATE write failure")):
            self.assert_failure("prepare", "state_write_failed", "error")
        self.assertEqual(before, (self.state / "checkpoint.json").read_bytes())
        self.assertEqual(len(list((self.state / "staged").iterdir())), 2)

    def test_directory_sync_failure_after_replace_never_deletes_referenced_stage(self):
        real_fsync = os.fsync

        def failed_after_replace(descriptor):
            info = os.fstat(descriptor)
            if ((self.state / "checkpoint.json").exists() and stat.S_ISDIR(info.st_mode)
                    and info.st_ino == self.state.stat().st_ino):
                raise OSError("PRIVATE post-replace failure")
            return real_fsync(descriptor)

        with patch.object(os, "fsync", side_effect=failed_after_replace):
            self.assert_failure("prepare", "state_write_failed", "error")
        directory = self.stage_directory()
        self.assertTrue(directory.is_dir())
        self.assertEqual(self.result("status")["status"], "prepared")
        self.assertEqual(self.result("prepare")["status"], "prepared")
        self.assertEqual(self.stage_directory(), directory)

    def test_saved_checkpoint_size_limit_keeps_private_orphan_without_commit(self):
        with patch.object(p, "MAX_CHECKPOINT", 100):
            self.assert_failure("prepare", "state_invalid")
        self.assertFalse((self.state / "checkpoint.json").exists())
        self.assertEqual(len(list((self.state / "staged").iterdir())), 1)

    def test_paths_and_all_protected_namespaces_reject_overlap_before_side_effects(self):
        for value in (None, 1, Path("relative"), self.root / "x" / ".." / "state", "/tmp/PRIVATE\0state"):
            with self.subTest(value=value):
                self.assert_failure("prepare", "invalid_path", state_dir=value)
        protected = [self.installed, p.SOURCE_ROOT, p.core.STATE, p.core.CONFIG.parent, p.core.LIVE.parent,
                     p.monitor_config.STATE, p.monitor_config.CONFIG.parent, self.trust_path,
                     self.options["manifest_path"], self.options["signature_path"], self.options["archive_path"]]
        for path in protected:
            for state in (path, path / "child"):
                with self.subTest(path=state):
                    self.assert_failure("prepare", "unsafe_state_path", state_dir=state)
        self.assert_failure("prepare", "unsafe_state_path", state_dir=self.root)
        self.assert_failure("prepare", "invalid_path", state_dir=Path("/" + str(self.installed)) / "updater-state")
        self.assert_failure("prepare", "invalid_path", state_dir="//var/lib/cgp-letsencrypt/updater-state")
        self.assertFalse(self.state.exists())

    def test_expiry_and_clock_reversal_during_inspection_create_no_state(self):
        inspect = archive.inspect_archive
        for action in ("check", "prepare"):
            for value, code, status in ((NOW + 3600, "expired_manifest", "expired"),
                                         (NOW - 1, "clock_moved_backwards", "invalid")):
                def delayed(data, manifest):
                    result = inspect(data, manifest)
                    p.time.time.return_value = value
                    return result

                with patch.object(p.time, "time", return_value=NOW), patch.object(archive, "inspect_archive", side_effect=delayed):
                    self.assert_failure(action, code, status)
                self.assertFalse(self.state.exists())

    def test_fresh_clock_under_lock_and_after_staging_prevents_stale_commit(self):
        with patch.object(p.time, "time", side_effect=[NOW, NOW, NOW - 1]):
            self.assert_failure("prepare", "clock_moved_backwards")
        self.assertFalse((self.state / "checkpoint.json").exists())
        stage = archive.stage
        for value, code, status in ((NOW + 3600, "expired_manifest", "expired"),
                                     (NOW - 1, "clock_moved_backwards", "invalid")):
            def delayed(data, manifest, parent):
                result = stage(data, manifest, parent)
                p.time.time.return_value = value
                return result

            with patch.object(p.time, "time", return_value=NOW), patch.object(archive, "stage", side_effect=delayed):
                self.assert_failure("prepare", code, status)
            self.assertFalse((self.state / "checkpoint.json").exists())
        self.assertEqual(len(list((self.state / "staged").iterdir())), 2)

    def test_status_rechecks_time_and_baseline_after_full_stage_verification(self):
        self.assertEqual(self.result("prepare")["status"], "prepared")
        before = (self.state / "checkpoint.json").read_bytes()
        validate = archive.validate_stage
        for value, code, status in ((NOW + 3600, "expired_manifest", "expired"),
                                     (NOW - 1, "clock_moved_backwards", "invalid")):
            def delayed(directory, inventory):
                validate(directory, inventory)
                p.time.time.return_value = value

            with patch.object(p.time, "time", return_value=NOW), patch.object(archive, "validate_stage", side_effect=delayed):
                self.assert_failure("status", code, status)

        def changed(directory, inventory):
            validate(directory, inventory)
            self.version_file.write_text("__version__ = '2.2.0.dev12'\n")

        with patch.object(archive, "validate_stage", side_effect=changed):
            self.assert_failure("status", "configuration_changed", "configuration_changed")
        self.assertEqual(before, (self.state / "checkpoint.json").read_bytes())

    def test_public_input_modes_links_types_and_missing_files_fail_closed(self):
        path = self.options["manifest_path"]
        raw = path.read_bytes()
        for mode in (0o666, 0o664, 0o4644, 0o2644, 0o1644):
            path.chmod(mode)
            self.assert_failure("check", "input_unsafe")
        path.chmod(0o644)
        hardlink = self.root / "link"
        os.link(path, hardlink)
        self.assert_failure("check", "input_unsafe")
        hardlink.unlink()
        path.unlink()
        path.symlink_to(self.trust_path)
        self.assert_failure("check", "input_unsafe")
        path.unlink()
        os.mkfifo(path, 0o600)
        self.assert_failure("check", "input_unsafe")
        path.unlink()
        self.assert_failure("check", "input_missing", "missing")
        path.mkdir()
        self.assert_failure("check", "input_unsafe")
        path.rmdir()
        path.write_bytes(raw)
        self.trust_path.chmod(0o644)
        self.assert_failure("check", "input_unsafe")
        self.assertFalse(self.state.exists())

    def test_unsafe_ancestor_or_state_and_fdopen_failure_do_not_leak_descriptors(self):
        parent = self.root / "untrusted"
        parent.mkdir(mode=0o777)
        parent.chmod(0o777)
        path = parent / "manifest"
        path.write_bytes(self.options["manifest_path"].read_bytes())
        self.assert_failure("check", "input_unsafe", manifest_path=path)
        self.state.mkdir(mode=0o755)
        self.assert_failure("status", "state_invalid")
        before = len(os.listdir("/proc/self/fd"))
        with patch.object(os, "fdopen", side_effect=OSError("PRIVATE stream error")):
            self.assert_failure("check", "input_unavailable", "error")
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_coherent_snapshot_rejects_in_place_mutation_and_growth(self):
        path = self.options["manifest_path"]
        inode = path.stat().st_ino
        real_fstat = os.fstat
        for growth in (False, True):
            self.sign()
            calls = 0

            def changed(descriptor):
                nonlocal calls
                info = real_fstat(descriptor)
                if info.st_ino == inode:
                    calls += 1
                    if calls == (2 if growth else 3):
                        path.write_bytes(b"x" * (metadata.MAX_MANIFEST + 1) if growth else b"changed")
                        if not growth:
                            return real_fstat(descriptor)
                return info

            with patch.object(os, "fstat", side_effect=changed):
                self.assert_failure("check", "input_limits" if growth else "input_changed")
        self.sign()
        path.write_bytes(b"x" * (metadata.MAX_MANIFEST + 1))
        self.assert_failure("check", "input_limits")

    def test_installed_version_is_parsed_as_one_literal_assignment_never_imported(self):
        invalid = [b"PRIVATE syntax !", b"\xff", b"\0", b"", b"__version__: str = '2.1.0'\n",
                   b"other = '2.1.0'\n", b"__version__ = alias = '2.1.0'\n", b"__version__ = str(2)\n",
                   b"__version__ = True\n", b"__version__ = 'not-a-version'\n",
                   b"__version__ = '2.1.0'\nraise RuntimeError('PRIVATE must not run')\n"]
        for data in invalid:
            self.version_file.write_bytes(data)
            self.assert_failure("check", "installed_invalid")
        self.assertFalse(self.state.exists())

    def test_invalid_clocks_return_fixed_diagnostics_without_state(self):
        for value in (None, True, float("nan"), float("inf"), -1, metadata.MAX_TIME + 1, 10**1000):
            with patch.object(p.time, "time", return_value=value):
                self.assert_failure("prepare", "invalid_clock")
        self.assertFalse(self.state.exists())

    def test_corrupt_checkpoint_documents_never_become_missing_or_fresh(self):
        self.make_lock()
        path = self.state / "checkpoint.json"
        documents = [b"null", b"{}", b"[]", b"\xff", b"{", b'{"schema":1,"schema":1}',
                     b'{"schema":1,"floors":{},"prepared":null,"x":NaN}',
                     b'{"schema":1,"floors":{},"prepared":null,"x":1.0}', b'{"x":' + b"1" * 5000 + b"}"]
        for raw in documents:
            path.write_bytes(raw)
            path.chmod(0o600)
            self.assert_failure("status", "state_invalid")
            self.assert_failure("check", "state_invalid")

    def test_saved_record_and_floor_validation_rejects_all_inconsistent_evidence(self):
        self.assertEqual(self.result("prepare")["status"], "prepared")
        original = self.checkpoint()
        invalid = [{**original, "schema": True}, {**original, "floors": []},
                   {**original, "floors": {"other": original["floors"]["stable"]}},
                   {**original, "floors": {"stable": {**original["floors"]["stable"], "version": "2.3.4rc1"}}}]
        changes = [("manifest", None), ("manifest", "é"), ("signature", None), ("signature", "{}"),
                   ("trust_sha256", "bad"), ("installed_root", "relative"),
                   ("installed_root", str(self.installed) + "/"), ("installed_version", "2.3.4"),
                   ("stage", "../PRIVATE"), ("created_at", True), ("created_at", NOW - 61),
                   ("plan_id", "f" * 64), ("inventory", {})]
        for field, value in changes:
            changed = deepcopy(original)
            changed["prepared"][field] = value
            invalid.append(changed)
        changed = deepcopy(original)
        changed["prepared"]["extra"] = "PRIVATE"
        invalid.append(changed)
        for changes in ({"schema": True}, {"key_id": "PRIVATE"}, {"signature": "invalid"}):
            changed = deepcopy(original)
            signature = json.loads(changed["prepared"]["signature"])
            signature.update(changes)
            changed["prepared"]["signature"] = metadata.canonical(signature).decode()
            invalid.append(changed)
        for field, value in (("sequence", 8), ("manifest_sha256", "f" * 64), ("version", "2.3.5"), ("checked_at", NOW - 1)):
            changed = deepcopy(original)
            changed["floors"]["stable"][field] = value
            invalid.append(changed)
        changed = deepcopy(original)
        changed["floors"] = {}
        invalid.append(changed)
        for value in invalid:
            self.write_checkpoint(value)
            self.assert_failure("status", "state_invalid")

    def test_stage_api_mismatch_and_unexpected_exceptions_are_sanitized(self):
        stage = archive.stage

        def mismatched(data, manifest, parent):
            result = stage(data, manifest, parent)
            result["inventory"] = {}
            return result

        with patch.object(archive, "stage", side_effect=mismatched):
            self.assert_failure("prepare", "state_invalid")
        for failure in (RuntimeError("PRIVATE exception"), metadata.UpdateError("PRIVATE"), metadata.UpdateError([])):
            with patch.object(p, "_inputs", side_effect=failure):
                self.assert_failure("check", "update_failed", "error")
        with patch.object(p, "_inputs", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.result("check")

    def test_changed_state_namespace_before_commit_preserves_foreign_checkpoint(self):
        stage = archive.stage
        moved = self.root / "moved-state"
        sentinel = b"PRIVATE foreign checkpoint"

        def replaced(data, manifest, parent):
            result = stage(data, manifest, parent)
            self.state.rename(moved)
            self.state.mkdir(mode=0o700)
            (self.state / "run.lock").touch(mode=0o600)
            (self.state / "checkpoint.json").write_bytes(sentinel)
            (self.state / "checkpoint.json").chmod(0o600)
            return result

        with patch.object(archive, "stage", side_effect=replaced):
            self.assert_failure("prepare", "state_changed")
        self.assertEqual((self.state / "checkpoint.json").read_bytes(), sentinel)
        self.assertFalse((moved / "checkpoint.json").exists())
        self.assertEqual(len(list((moved / "staged").iterdir())), 1)

    def test_changed_lock_inode_or_missing_state_prevents_commit(self):
        stage = archive.stage

        def replaced_lock(data, manifest, parent):
            result = stage(data, manifest, parent)
            (self.state / "run.lock").rename(self.state / "previous.lock")
            (self.state / "run.lock").touch(mode=0o600)
            return result

        with patch.object(archive, "stage", side_effect=replaced_lock):
            self.assert_failure("prepare", "state_changed")
        self.assertFalse((self.state / "checkpoint.json").exists())

        def missing_state(data, manifest, parent):
            result = stage(data, manifest, parent)
            self.state.rename(self.root / "removed-state")
            return result

        with patch.object(archive, "stage", side_effect=missing_state):
            self.assert_failure("prepare", "state_changed")
        self.assertFalse(self.state.exists())

    def test_post_save_state_replacement_preserves_saved_stage(self):
        save = p._save
        moved = self.root / "saved-state"

        def replaced(state, checkpoint):
            save(state, checkpoint)
            state.rename(moved)
            state.mkdir(mode=0o700)
            (state / "run.lock").touch(mode=0o600)
            (state / "foreign").write_text("sentinel")

        with patch.object(p, "_save", side_effect=replaced):
            self.assert_failure("prepare", "state_changed")
        checkpoint = json.loads((moved / "checkpoint.json").read_text())
        self.assertTrue((moved / "staged" / checkpoint["prepared"]["stage"]).is_dir())
        self.assertEqual((self.state / "foreign").read_text(), "sentinel")
        self.assertFalse((self.state / "checkpoint.json").exists())
