"""Real signed preparation, installation snapshots, journals and conservative undo."""
from copy import deepcopy
import fcntl
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cgp_cert_manager import (storage, update_apply as a, update_files as f,
                              update_metadata as m, update_plan as p, update_gate, update_services)
from test_update_metadata import NOW, PUBLIC, SEED, b64


class ApplyFixture:
    """Only temporary roots and synthetic signatures; systemd is an in-memory fake."""
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.layout = a.Layout(self.root)
        self.enterContext(patch.object(a, "LAYOUT", self.layout))
        self.enterContext(patch.object(a, "EXECUTOR_ROOT", self.layout.runtime))
        self.enterContext(patch.object(p.time, "time", return_value=NOW + 0.5))
        self.enterContext(patch.object(socket, "socket", side_effect=AssertionError("No external network")))
        self.observation = {"timers": {name: "active" for name in update_services.TIMERS},
                            "services": {name: "inactive" for name in update_services.SERVICES}}
        self.service_calls = []

        def observe():
            self.service_calls.append("observe")
            return deepcopy(self.observation)

        def stop(*, recovery=False, missing_units=()):
            self.service_calls.append("stop")
            self.observation["timers"] = {name: "inactive" for name in update_services.TIMERS}
            return deepcopy(self.observation)

        def reload_units(*, recovery=False):
            self.service_calls.append("reload")
            self.assertEqual(set(self.observation["timers"].values()), {"inactive"})
            return deepcopy(self.observation)

        self.observe = self.enterContext(patch.object(a.services, "observe", side_effect=observe))
        self.stop = self.enterContext(patch.object(a.services, "stop", side_effect=stop))
        self.reload = self.enterContext(patch.object(a.services, "reload", side_effect=reload_units))
        for state in self.layout.locks:
            with storage.operation_lock(state):
                pass
        for state in self.layout.locks[:2]:
            self.write(state / "evidence.json", b'{"retain":"runtime recovery evidence"}\n', 0o600)
        self.version = "2.2.0.dev12"
        self.write(self.layout.app / "cgp_cert_manager/__init__.py", ("__version__ = " + repr(self.version) + "\n").encode())
        self.write(self.layout.app / "cgp_cert_manager/payload.py", b"old = True\n")
        self.write(self.layout.app / "cgp_cert_manager/__pycache__/old.pyc", b"old bytecode\n")
        self.write(self.layout.app / ("cgp_certbot_dns-" + self.version + ".dist-info/METADATA"), b"old metadata\n")
        self.write(self.layout.app / "-local/data", b"operator-owned adjacent file\n")
        (self.layout.app / "empty").mkdir()
        self.write(self.layout.runtime / "cgp_cert_manager/update_gate.py", b"# synthetic trusted gate\n")
        self.write(self.layout.runtime / "cgp_update_gate.py", b"# synthetic trusted gate\n")
        self.templates = {}
        for name in ("launcher", "certbot-launcher", "monitor-launcher", "update-launcher"):
            self.templates[name] = ("#!/usr/bin/python3\n# trusted " + name + "\n").encode()
        for name in a.UNITS.values():
            self.templates["systemd/" + name] = ("# trusted unit " + name + "\n").encode()
        for name, data in self.templates.items():
            self.write(self.layout.runtime / "templates" / name, data)
        for key, (name, source) in a.LAUNCHERS.items():
            self.write(self.layout.targets()[key], self.templates[source], 0o750)
        self.write(self.layout.preserved()["update_launcher"], self.templates["update-launcher"], 0o750)
        for key, name in a.UNITS.items():
            self.write(self.layout.targets()[key], self.templates["systemd/" + name])
        self.write(self.layout.preserved()["machine"], b"0" * 32 + b"\n")
        self.write(self.layout.preserved()["manager_config"], b'{"schema_version":2}\n', 0o600)
        self.trust_path = self.root / "etc/cgp-update/trust.json"
        self.key = Ed25519PrivateKey.from_private_bytes(SEED)
        self.key_id = hashlib.sha256(PUBLIC).hexdigest()
        self.trust = {"schema": 1, "project": m.PROJECT, "channel": "stable", "keys": {self.key_id: b64(PUBLIC)}}
        self.write(self.trust_path, m.canonical(self.trust), 0o600)
        self.options = {"trust_path": self.trust_path, "installed_root": self.layout.app, "state_dir": self.layout.state}
        self.artifacts = {"manifest_path": self.root / "manifest.json", "signature_path": self.root / "signature.json",
                          "archive_path": self.root / "release.tar.gz"}
        self.source = {
            **{name: (data, 0o755 if name.endswith("launcher") else 0o644) for name, data in self.templates.items()},
            "update-install.json": (m.canonical(a.DESCRIPTOR), 0o644),
            "cgp_cert_manager/__init__.py": (b"__version__ = '2.3.4'\n", 0o644),
            "cgp_cert_manager/payload.py": (b"raise AssertionError('Candidate must never execute')\n", 0o644),
            "cgp_certbot_dns-2.3.4.dist-info/METADATA": (b"Metadata-Version: 2.1\nName: cgp-certbot-dns\nVersion: 2.3.4\n\n", 0o644),
            "cgp_certbot_dns-2.3.4.dist-info/entry_points.txt": (b"[certbot.plugins]\ncgp-dns = cgp_cert_manager.certbot_dns:Authenticator\n", 0o644),
            "cgp_certbot_dns-2.3.4.dist-info/top_level.txt": (b"cgp_cert_manager\n", 0o644),
            "install.sh": (b"#!/bin/sh\nexit 99\n", 0o755),
            "docs/ignored.txt": (b"Not an application target\n", 0o644)}
        self.package()

    def write(self, path, data, mode=0o644):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)

    def package(self):
        prefix = m.PROJECT + "-v2.3.4"
        stream = io.BytesIO()
        with gzip.GzipFile(filename="", fileobj=stream, mode="wb", mtime=0, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                directory = tarfile.TarInfo(prefix + "/")
                directory.mode, directory.type = 0o755, tarfile.DIRTYPE
                archive.addfile(directory)
                for path, (data, mode) in sorted(self.source.items(), key=lambda item: item[0].encode("utf-8")):
                    info = tarfile.TarInfo(prefix + "/" + path)
                    info.mode, info.size = mode, len(data)
                    archive.addfile(info, io.BytesIO(data))
        data = stream.getvalue()
        manifest = {"schema": 1, "project": m.PROJECT, "channel": "stable", "sequence": 7,
                    "version": "2.3.4", "issued_at": NOW - 60, "expires_at": NOW + 3600,
                    "source": {"repository": m.REPOSITORY, "commit": "a" * 40, "tree": "b" * 40, "tag": "v2.3.4"},
                    "archive": {"name": prefix + ".tar.gz", "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}}
        raw = m.canonical(manifest)
        signature = {"schema": 1, "key_id": self.key_id, "signature": b64(self.key.sign(m.DOMAIN + raw))}
        self.write(self.artifacts["manifest_path"], raw)
        self.write(self.artifacts["signature_path"], m.canonical(signature))
        self.write(self.artifacts["archive_path"], data)

    def prepare(self):
        result = p.prepare(**self.options, **self.artifacts)
        self.assertEqual(result["status"], "prepared", result)
        return result

    def review(self):
        result = a.review(**self.options)
        self.assertEqual(result["status"], "review_ready", result)
        self.assertIsNone(result["plan"]["transaction_id"])
        return result["plan"]["confirmation_token"]

    def apply(self, token):
        return a.apply(**self.options, confirmation_token=token)

    def record(self):
        pointer = json.loads((self.layout.state / "installation.json").read_text())
        return json.loads((self.layout.state / "installations" / pointer["transaction_id"] / "journal.json").read_text())

    def save_record(self, value):
        a._validate(value)
        storage.atomic_text(a._directory(value["transaction_id"]) / "journal.json", m.canonical(value).decode())

    def interrupted(self, event="synced_install_new"):
        self.prepare()
        token = self.review()
        original = f.apply_target

        def fail_after(target, slot, before, after, checkpoint):
            def fault(point):
                checkpoint(point)
                if point == event:
                    raise OSError("synthetic abrupt boundary")
            return original(target, slot, before, after, checkpoint=fault)

        with patch.object(f, "apply_target", side_effect=fail_after):
            result = self.apply(token)
        self.assertEqual(result["status"], "recovery_required", result)
        return token


class UpdateApplyTests(ApplyFixture, unittest.TestCase):
    def test_review_is_read_only_and_confirmation_is_separate_from_package_plan(self):
        package = self.prepare()
        old = f.capture(self.layout.app)[0]
        with patch.object(storage, "atomic_json", side_effect=AssertionError("read only")), \
                patch.object(storage, "atomic_text", side_effect=AssertionError("read only")), \
                patch.object(os, "fsync", side_effect=AssertionError("read only")):
            token = self.review()
            self.assertEqual(token, self.review())
        self.assertNotEqual(token, package["plan"]["plan_id"])
        self.assertEqual(f.capture(self.layout.app)[0], old)
        self.assertFalse((self.layout.state / "installations").exists())
        self.assertEqual(set(self.service_calls), {"observe"})

    def test_apply_full_readback_preserves_configuration_runtime_evidence_and_extra_files(self):
        self.prepare()
        before = {key: f.capture(path)[0] for key, path in self.layout.preserved().items()}
        evidence = {state: f.capture(state)[0] for state in self.layout.locks[:2]}
        token = self.review()
        result = self.apply(token)
        self.assertEqual(result["status"], "applied", result)
        self.assertFalse((self.layout.state / "pending.json").exists())
        self.assertEqual(p._installed(self.layout.app)["installed_version"], "2.3.4")
        self.assertFalse((self.layout.app / "cgp_cert_manager/__pycache__").exists())
        self.assertTrue((self.layout.app / "-local/data").is_file())
        self.assertTrue((self.layout.app / "empty").is_dir())
        self.assertFalse((self.layout.app / "docs").exists())
        self.assertEqual({key: f.capture(path)[0] for key, path in self.layout.preserved().items()}, before)
        self.assertEqual({state: f.capture(state)[0] for state in self.layout.locks[:2]}, evidence)
        self.assertEqual(self.service_calls[-2:], ["stop", "reload"])
        self.assertEqual(a.status(**self.options)["status"], "applied")
        self.assertEqual(a.recover(**self.options)["status"], "applied")
        self.assertEqual(p._installed(self.layout.app)["installed_version"], "2.3.4")

    def test_wrong_token_and_changed_preimage_refuse_before_backups_or_timer_mutation(self):
        self.prepare()
        token = self.review()
        for value in (None, "x", "0" * 64):
            self.assertEqual(self.apply(value)["error"], "confirmation_mismatch")
        self.write(self.layout.app / "local-change", b"manual change\n")
        self.assertEqual(self.apply(token)["error"], "confirmation_mismatch")
        self.assertFalse((self.layout.state / "installations").exists())
        self.assertNotIn("stop", self.service_calls)

    def test_recovery_returns_exact_preimages_and_old_approval_cannot_replay(self):
        before = {key: f.capture(path)[0] for key, path in self.layout.targets().items()}
        token = self.interrupted()
        self.assertEqual(a.status(**self.options)["status"], "recovery_required")
        self.assertEqual(a.review(**self.options)["error"], "installation_pending")
        self.assertEqual(p.prepare(**self.options, **self.artifacts)["error"], "update_pending")
        result = a.recover(**self.options)
        self.assertEqual(result["status"], "rolled_back", result)
        self.assertEqual({key: f.capture(path)[0] for key, path in self.layout.targets().items()}, before)
        self.assertEqual(a.recover(**self.options)["status"], "rolled_back")
        self.assertEqual(self.apply(token)["error"], "confirmation_mismatch")
        self.assertNotEqual(self.review(), token)
        self.assertEqual(self.apply(self.review())["status"], "applied")

    def test_recovery_needs_no_original_artifact_trust_freshness_or_staged_package(self):
        self.interrupted("synced_park_old")
        self.trust_path.unlink()
        for path in self.artifacts.values():
            path.unlink()
        checkpoint = p._load(self.layout.state)
        stage = self.layout.state / "staged" / checkpoint["prepared"]["stage"]
        os.rename(stage, stage.with_name("retained-outside-checkpoint"))
        with patch.object(p.time, "time", return_value=NOW + 999999):
            self.assertEqual(a.recover(**self.options)["status"], "rolled_back")

    def test_unknown_target_refuses_every_rollback_write_and_keeps_marker(self):
        self.interrupted()
        self.write(self.layout.targets()["monitor_service"], b"manual third state\n")
        before = f.capture(self.layout.app)[0]
        with patch.object(f, "restore_target", side_effect=AssertionError("No partial undo")):
            result = a.recover(**self.options)
        self.assertEqual(result["error"], "filesystem_unknown", result)
        self.assertEqual(f.capture(self.layout.app)[0], before)
        self.assertTrue((self.layout.state / "pending.json").exists())

    def test_corrupt_any_backup_refuses_every_rollback_write(self):
        self.interrupted()
        record = self.record()
        directory = a._directory(record["transaction_id"]) / "blobs"
        next(directory.iterdir()).write_bytes(b"corrupt\n")
        with patch.object(f, "restore_target", side_effect=AssertionError("No partial undo")):
            result = a.recover(**self.options)
        self.assertEqual(result["error"], "backup_invalid", result)
        self.assertTrue((self.layout.state / "pending.json").exists())

    def test_changed_preserved_configuration_or_executor_refuses_recovery(self):
        self.interrupted()
        path = self.layout.preserved()["manager_config"]
        self.write(path, b'{"schema_version":2,"email":"operator@example.invalid"}\n', 0o600)
        with patch.object(f, "restore_target", side_effect=AssertionError("No partial undo")):
            result = a.recover(**self.options)
        self.assertEqual(result["error"], "preserved_changed", result)

    def test_saved_status_is_read_only_and_independent_of_current_configuration(self):
        self.interrupted()
        self.trust_path.unlink()
        with patch.object(storage, "atomic_json", side_effect=AssertionError("read only")), \
                patch.object(storage, "atomic_text", side_effect=AssertionError("read only")), \
                patch.object(os, "fsync", side_effect=AssertionError("read only")):
            result = a.status(**self.options)
        self.assertEqual(result["status"], "recovery_required")
        self.assertNotIn(str(self.root), json.dumps(result))
        self.assertNotIn(b64(PUBLIC), json.dumps(result))

    def test_pending_without_journal_is_not_discarded(self):
        storage.atomic_json(self.layout.state / "pending.json", {"schema": 1, "transaction_id": "a" * 32})
        self.assertEqual(a.status(**self.options)["status"], "recovery_required")
        self.assertEqual(a.recover(**self.options)["error"], "journal_missing")
        self.assertTrue((self.layout.state / "pending.json").exists())

    def test_status_falls_back_only_without_installation_and_selected_layout_matches(self):
        self.assertIsNone(a.status(**self.options))
        self.assertIsNone(a.status(**{**self.options, "state_dir": self.root / "other"}))
        with patch.object(p, "_shared") as shared:
            shared.return_value.__enter__.return_value = False
            self.assertIsNone(a.status(**self.options))

    def test_fixed_layout_and_independent_runtime_are_required(self):
        self.assertEqual(a.review(**{**self.options, "state_dir": self.root / "other"})["error"], "unsupported_layout")
        with patch.object(a, "EXECUTOR_ROOT", self.layout.app):
            self.assertEqual(a.review(**self.options)["error"], "unsupported_baseline")
        self.assertEqual(a.recover(**self.options)["error"], "journal_missing")

    def test_busy_locks_refuse_without_any_files_or_systemd_actions(self):
        self.prepare()
        for state in self.layout.locks:
            with storage.operation_lock(state):
                self.assertEqual(a.review(**self.options)["error"], "state_busy")
        with storage.operation_lock(self.layout.state):
            self.assertEqual(a.status(**self.options)["status"], "busy")
        self.assertEqual(self.service_calls, [])

    def test_missing_lock_or_prepared_plan_refuses_without_creation(self):
        self.assertEqual(a.review(**self.options)["error"], "prepared_missing")
        (self.layout.locks[0] / "run.lock").unlink()
        self.assertEqual(a.review(**self.options)["error"], "state_invalid")
        self.assertFalse((self.layout.locks[0] / "run.lock").exists())

    def test_trust_version_stage_or_expiry_change_blocks_application(self):
        self.prepare()
        token = self.review()
        with patch.object(p.time, "time", return_value=NOW + 3600):
            self.assertEqual(self.apply(token)["error"], "expired_manifest")
        self.write(self.trust_path, m.canonical({**self.trust, "keys": {"1" * 64: b64(b"1" * 32)}}), 0o600)
        self.assertIn(self.apply(token)["error"], ("configuration_changed", "invalid_trust"))
        self.assertFalse((self.layout.state / "installations").exists())


    def test_safe_unit_modes_are_normalized_and_rollback_restores_preimages(self):
        changed = self.layout.targets()["manager_service"]
        changed.chmod(0o600)
        before = {key: f.capture(path)[0] for key, path in self.layout.targets().items()}
        self.prepare()
        token = self.review()
        with patch.object(a.services, "reload", side_effect=update_services.SystemdError("systemd_unavailable")):
            result = self.apply(token)
        self.assertEqual(result["status"], "recovery_required", result)
        self.assertEqual(changed.stat().st_mode & 0o777, 0o644)
        self.assertEqual(a.recover(**self.options)["status"], "rolled_back")
        self.assertEqual({key: f.capture(path)[0] for key, path in self.layout.targets().items()}, before)

    def test_modified_missing_or_nonfile_units_refuse_review_and_apply_before_effects(self):
        self.prepare()
        for key in a.UNITS:
            path = self.layout.targets()[key]
            data, info = path.read_bytes(), path.stat()
            for mutation in ("modified", "missing", "directory"):
                with self.subTest(unit=key, mutation=mutation):
                    token = self.review()
                    if mutation == "modified":
                        path.write_bytes(b"# administrator-modified unit\n")
                    else:
                        path.unlink()
                        if mutation == "directory":
                            path.mkdir()
                    before = {name: f.capture(target)[0] for name, target in self.layout.targets().items()}
                    self.assertEqual(a.review(**self.options)["error"], "unsupported_baseline")
                    self.assertEqual(self.apply(token)["error"], "unsupported_baseline")
                    self.assertEqual({name: f.capture(target)[0] for name, target in self.layout.targets().items()}, before)
                    self.assertFalse((self.layout.state / "installations").exists())
                    self.assertNotIn("stop", self.service_calls)
                    if mutation == "directory":
                        path.rmdir()
                    self.write(path, data, info.st_mode & 0o777)
                    os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))

    def test_configuration_schema_permissions_optional_monitor_and_dropin_are_checked(self):
        self.prepare()
        monitor = self.layout.preserved()["monitor_config"]
        manager = self.layout.preserved()["manager_config"]
        dropin = self.layout.preserved()["timer_dropin"]
        self.write(monitor, b'{"schema":1,"enabled":false,"endpoints":[]}\n', 0o600)
        self.write(dropin, a.schedule.render({}).encode())
        self.review()
        for invalid in (b"{}", b'{"schema_version":true}', b'{"schema_version":1}', b"[]",
                        b'{"schema_version":2,"schedule":{"hour":99}}'):
            self.write(manager, invalid, 0o600)
            self.assertEqual(a.review(**self.options)["error"], "configuration_invalid")
        self.write(manager, b'{"schema_version":2}', 0o644)
        self.assertEqual(a.review(**self.options)["error"], "configuration_invalid")
        manager.chmod(0o600)
        self.write(monitor, b'{"schema":1,"enabled":false,"endpoints":[]}', 0o644)
        self.assertEqual(a.review(**self.options)["error"], "configuration_invalid")
        monitor.chmod(0o600)
        self.write(dropin, b"[Timer]\nUnit=unmanaged.service\n")
        self.assertEqual(a.review(**self.options)["error"], "configuration_invalid")
        self.assertNotIn("stop", self.service_calls)

    def test_configuration_bounds_machine_identity_and_trust_separation(self):
        self.prepare()
        with patch.object(a.monitor_config, "MAX_CONFIG", 2):
            self.assertEqual(a.review(**self.options)["error"], "configuration_invalid")
        self.write(self.layout.preserved()["machine"], b"")
        self.assertEqual(a.review(**self.options)["error"], "unsupported_baseline")
        self.assertEqual(a.review(**{**self.options, "trust_path": self.layout.app / "trust.json"})["error"], "unsupported_layout")

    def test_unsupported_candidate_layout_or_templates_never_create_installation_data(self):
        for name, value in (("update-install.json", None),
                            ("update-install.json", (b'{"schema":1,"layout":2}', 0o644)),
                            ("launcher", (b"unguarded launcher", 0o755)),
                            ("systemd/cgp-monitor.service", (b"arbitrary service", 0o644)),
                            ("cgp_cert_manager/__pycache__/candidate.pyc", (b"bytecode", 0o644))):
            with self.subTest(name=name):
                original = deepcopy(self.source)
                if value is None:
                    self.source.pop(name)
                else:
                    self.source[name] = value
                self.package()
                # Remove only synthetic previous prepare bookkeeping for this
                # independent, unsigned-policy variation before re-preparing.
                checkpoint = self.layout.state / "checkpoint.json"
                if checkpoint.exists():
                    checkpoint.unlink()
                with patch.object(p, "MAX_STAGES", 20):
                    self.prepare()
                self.assertEqual(a.review(**self.options)["error"], "unsupported_layout")
                self.source = original
        self.assertFalse((self.layout.state / "installations").exists())

    def test_unguarded_installed_launchers_or_inconsistent_runtime_refuse_review(self):
        self.prepare()
        launcher = self.layout.targets()["manager_launcher"]
        original = launcher.read_bytes()
        self.write(launcher, b"unmanaged entry\n", 0o750)
        self.assertEqual(a.review(**self.options)["error"], "unsupported_baseline")
        self.write(launcher, original, 0o750)
        self.write(self.layout.runtime / "cgp_update_gate.py", b"different trusted gate copy\n")
        self.assertEqual(a.review(**self.options)["error"], "unsupported_baseline")
        self.assertFalse((self.layout.state / "installations").exists())

    def test_expiry_during_backup_or_timer_stop_never_replaces_application(self):
        self.prepare()
        token = self.review()
        before = f.capture(self.layout.app)[0]
        save = f.save_blobs

        def delayed_save(*args):
            save(*args)
            p.time.time.return_value = NOW + 3600

        with patch.object(f, "save_blobs", side_effect=delayed_save):
            result = self.apply(token)
        self.assertEqual(result["error"], "expired_manifest")
        self.assertEqual(f.capture(self.layout.app)[0], before)
        self.assertFalse((self.layout.state / "installation.json").exists())
        self.assertNotIn("stop", self.service_calls)
        p.time.time.return_value = NOW
        original_stop = self.stop.side_effect

        def delayed_stop():
            result = original_stop()
            p.time.time.return_value = NOW + 3600
            return result

        self.stop.side_effect = delayed_stop
        result = self.apply(token)
        self.assertEqual((result["status"], result["error"]), ("recovery_required", "expired_manifest"))
        self.assertEqual(f.capture(self.layout.app)[0], before)
        self.assertTrue((self.layout.state / "pending.json").exists())
        self.stop.side_effect = original_stop
        self.assertEqual(a.recover(**self.options)["status"], "rolled_back")

    def test_tampering_after_backup_requires_new_review_and_retains_orphan_evidence(self):
        self.prepare()
        token = self.review()
        save = f.save_blobs

        def changed(*args):
            save(*args)
            self.write(self.layout.app / "operator-change", b"preserve manual edit")

        with patch.object(f, "save_blobs", side_effect=changed):
            self.assertEqual(self.apply(token)["error"], "confirmation_mismatch")
        self.assertEqual(p._installed(self.layout.app)["installed_version"], self.version)
        self.assertFalse((self.layout.state / "pending.json").exists())
        self.assertTrue(list((self.layout.state / "installations").iterdir()))
        self.assertTrue(list(self.layout.app.parent.glob(".cgp-update-*")))

    def test_missing_partial_pointer_or_corrupt_journal_remains_recovery_required(self):
        self.interrupted()
        path = a._directory(self.record()["transaction_id"]) / "journal.json"
        original = path.read_bytes()
        for raw in (b"{", b'{"schema":1,"schema":1}', b"[]", b'{"schema":1.0}', b"\xff"):
            with self.subTest(raw=raw):
                self.write(path, raw, 0o600)
                self.assertEqual(a.status(**self.options)["status"], "recovery_required")
                self.assertEqual(a.recover(**self.options)["error"], "journal_invalid")
        self.write(path, original, 0o600)
        storage.atomic_json(self.layout.state / "pending.json", {"schema": 1, "transaction_id": "f" * 32})
        self.assertEqual(a.recover(**self.options)["error"], "journal_invalid")
        self.assertTrue((self.layout.state / "pending.json").exists())

    def test_journal_schema_inventory_and_approval_are_not_trusted_blindly(self):
        self.interrupted()
        record = self.record()
        mutations = [
            lambda v: v.update(schema=True),
            lambda v: v.update(phase="execute_custom_command"),
            lambda v: v.update(confirmation_token="0" * 64),
            lambda v: v.update(step=-1),
            lambda v: v["spec"].update(root="/another-machine"),
            lambda v: v["spec"].update(layout=True),
            lambda v: v["spec"].update(previous="bad digest"),
            lambda v: v["spec"]["package"].update(expires_at=True),
            lambda v: v["spec"]["package"].update(installed_version="9.9.9"),
            lambda v: v["spec"]["package"].update(channel="other"),
            lambda v: v["spec"]["package"].update(sequence=0),
            lambda v: v["spec"]["package"].update(plan_id="bad"),
            lambda v: v["spec"]["targets"].update(foreign={}),
            lambda v: v["spec"]["targets"]["application"].update(extra={}),
            lambda v: v["spec"]["targets"]["application"]["after"]["entries"][1].update(path="../../escape"),
            lambda v: v["spec"]["targets"]["application"].update(after={"kind": "missing", "entries": []}),
            lambda v: v["spec"]["services"]["services"].update({"cgp-letsencrypt.service": "active"}),
            lambda v: v["spec"]["services"]["timers"].update({"cgp-monitor.timer": "activating"}),
        ]
        for mutate in mutations:
            invalid = deepcopy(record)
            mutate(invalid)
            with self.subTest(record=invalid), self.assertRaises(m.UpdateError) as error:
                a._validate(invalid)
            self.assertEqual(error.exception.code, "journal_invalid")
        with patch.object(a, "MAX_JOURNAL", 1), self.assertRaises(m.UpdateError):
            a._persist(record, "applying")

    def test_transaction_retention_cap_invalid_names_and_collision_do_not_prune(self):
        self.prepare()
        token = self.review()
        parent = self.layout.state / "installations"
        parent.mkdir(mode=0o700)
        unknown = parent / "manual-evidence"
        unknown.mkdir(mode=0o700)
        self.assertEqual(self.apply(token)["error"], "journal_invalid")
        unknown.rename(parent / ("a" * 32))
        with patch.object(a, "MAX_TRANSACTIONS", 1):
            self.assertEqual(self.apply(token)["error"], "transaction_limit")
        with patch.object(a.secrets, "token_hex", return_value="a" * 32):
            self.assertEqual(self.apply(token)["error"], "update_failed")
        self.assertTrue((parent / ("a" * 32)).exists())
        self.assertNotIn("stop", self.service_calls)

    def test_prepared_journal_before_pending_is_explicitly_recoverable(self):
        self.prepare()
        token = self.review()
        with patch.object(a, "_pending", side_effect=OSError("power loss before marker")):
            result = self.apply(token)
        self.assertEqual(result["error"], "update_failed")
        self.assertEqual(a.status(**self.options)["status"], "recovery_required")
        self.assertFalse((self.layout.state / "pending.json").exists())
        self.assertEqual(a.recover(**self.options)["status"], "rolled_back")

    def test_terminal_receipt_before_marker_removal_is_finalized_without_undo(self):
        self.prepare()
        token = self.review()
        with patch.object(a, "_clear", side_effect=OSError("crash before final marker removal")):
            result = self.apply(token)
        self.assertEqual(result["status"], "recovery_required", result)
        self.assertEqual(self.record()["phase"], "applied")
        self.assertEqual(a.status(**self.options)["status"], "recovery_required")
        with patch.object(f, "restore_target", side_effect=AssertionError("Committed transaction")):
            self.assertEqual(a.recover(**self.options)["status"], "applied")
        self.assertFalse((self.layout.state / "pending.json").exists())

    def test_busy_systemd_unexpected_errors_and_interrupt_do_not_claim_success(self):
        self.prepare()
        for error, expected in ((update_services.SystemdError("systemd_service_active"), "systemd_service_active"),
                                 (RuntimeError("synthetic secret detail"), "update_failed"),
                                 (m.UpdateError("secret-not-allowed"), "update_failed")):
            with patch.object(a.services, "observe", side_effect=error):
                result = a.review(**self.options)
            self.assertEqual(result["error"], expected)
            self.assertNotIn("secret", json.dumps(result))
        token = self.review()
        with patch.object(a.services, "stop", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            self.apply(token)
        self.assertTrue((self.layout.state / "pending.json").exists())
        self.assertEqual(a.recover(**self.options)["status"], "rolled_back")

    def test_final_read_only_review_and_prewrite_window_reject_expiry_and_clock_regression(self):
        self.prepare()
        observe = self.observe.side_effect

        def late_observation():
            result = observe()
            p.time.time.return_value = NOW + 3600
            return result

        with patch.object(a.services, "observe", side_effect=late_observation):
            self.assertEqual(a.review(**self.options)["error"], "expired_manifest")
        p.time.time.return_value = NOW + 0.5
        token = self.review()
        before = f.capture(self.layout.app)[0]
        check_live = a._check_live

        def late_readback(record, side=None):
            check_live(record, side)
            p.time.time.return_value = NOW + 3600

        with patch.object(a, "_check_live", side_effect=late_readback):
            self.assertEqual(self.apply(token)["error"], "expired_manifest")
        self.assertEqual(f.capture(self.layout.app)[0], before)
        self.assertEqual(a.recover(**self.options)["status"], "rolled_back")
        p.time.time.return_value = NOW + 10
        token = self.review()

        def clock_regression(record, side=None):
            check_live(record, side)
            p.time.time.return_value = NOW + 9

        with patch.object(a, "_check_live", side_effect=clock_regression):
            self.assertEqual(self.apply(token)["error"], "clock_moved_backwards")
        self.assertEqual(f.capture(self.layout.app)[0], before)
        self.assertEqual(a.recover(**self.options)["status"], "rolled_back")

    def test_journal_inode_replacement_is_detected_before_resynchronizing_terminal_receipt(self):
        self.prepare()
        token = self.review()
        with patch.object(a, "_clear", side_effect=OSError("retain terminal marker")):
            self.assertEqual(self.apply(token)["status"], "recovery_required")
        record = self.record()
        path = a._directory(record["transaction_id"]) / "journal.json"
        load = a._json

        def replaced(path, missing=False):
            result = load(path, missing)
            storage.atomic_text(path, m.canonical(result).decode())
            return result

        with patch.object(a, "_json", side_effect=replaced), self.assertRaises(m.UpdateError) as error:
            a._sync_receipt(record)
        self.assertEqual(error.exception.code, "state_changed")
        self.assertTrue((self.layout.state / "pending.json").exists())
        self.assertTrue(path.exists())


if __name__ == "__main__":
    unittest.main()
