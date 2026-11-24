"""Installer storage and lock checks; never executes the real shell payload."""
import contextlib
import fcntl
import io
import os
from pathlib import Path
import runpy
from subprocess import PIPE, run as run_process
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from cgp_cert_manager import core, installer, monitor_config, storage, tui


class InstallerGuardTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.monitor_state = self.root / "monitor-state"
        self.monitor_config = self.root / "monitor-private" / "config.json"
        self.config = self.root / "config.json"
        self.token = self.root / "cloudflare.ini"
        tui.write_token(self.token, "dummy")
        self.cfg = {"schema_version": 2, "email": "admin@example.com",
                    "communigate": {"url": "http://127.0.0.1:8100/CLI/",
                                    "username": "dummy", "password": "dummy"},
                    "cloudflare_credentials": str(self.token), "domains": [],
                    "schedule": {"hour": 3, "random_delay": 900}}
        core.atomic(self.config, self.cfg)
        self.stack.enter_context(patch.object(core, "STATE", self.state))
        self.stack.enter_context(patch.object(core, "CONFIG", self.config))
        self.stack.enter_context(patch.object(installer, "MONITOR_STATE", self.monitor_state))
        self.stack.enter_context(patch.object(installer, "MONITOR_CONFIG", self.monitor_config))
        self.stack.enter_context(patch.object(monitor_config, "STATE", self.monitor_state))
        self.stack.enter_context(patch.object(monitor_config, "CONFIG", self.monitor_config))
        self.stack.enter_context(patch.object(installer.os, "umask"))
        self.errors = self.stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
        self.payload = self.stack.enter_context(patch.object(installer.subprocess, "run",
                                                          return_value=Mock(returncode=0)))

    def test_preflight_accounts_and_default_credentials(self):
        installer.preflight()
        self.cfg["cloudflare_accounts"] = [{"credentials": str(self.token)}]
        core.atomic(self.config, self.cfg)
        installer.preflight()
        self.payload.assert_not_called()

    def test_fixed_dependencies_do_not_require_native_certbot(self):
        with patch.dict(sys.modules, {'certbot.main': None}):
            installer.preflight()
        self.payload.assert_not_called()

    def test_missing_dns_dependency_refuses_before_payload(self):
        with patch.dict(sys.modules, {'dns.message': None}), patch.object(core, 'token') as token:
            self.assertEqual(installer.main([]), 1)
        self.assertIn('DNS runtime dependencies unavailable', self.errors.getvalue())
        token.assert_not_called()
        self.payload.assert_not_called()

    def test_adaptive_requires_discoverable_native_authenticator(self):
        from certbot._internal.plugins.disco import PluginsRegistry
        self.cfg['dns_propagation'] = {'mode': 'adaptive'}
        core.atomic(self.config, self.cfg)
        installer.preflight()
        with patch.object(PluginsRegistry, 'find_all', return_value={}):
            self.assertEqual(installer.main([]), 1)
        self.assertIn('native Certbot and the CGP plugin', self.errors.getvalue())
        self.payload.assert_not_called()

    def test_run_holds_and_passes_lock_until_child_finishes(self):
        def child(command, cwd, pass_fds):
            self.assertEqual(len(pass_fds), 2)
            fd, monitor_fd = pass_fds
            self.assertEqual(command, ["bash", str(cwd / "scripts" / "install-locked.sh"),
                                       str(fd), str(monitor_fd)])
            installer.check_lock(fd, monitor_fd)
            for state, descriptor in ((self.state, fd), (self.monitor_state, monitor_fd)):
                self.assertEqual(os.fstat(descriptor).st_ino, (state / "run.lock").stat().st_ino)
                with storage.open_private(state / "run.lock", "a") as contender:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return Mock(returncode=7)
        self.payload.side_effect = child
        self.assertEqual(installer.main([]), 7)
        with storage.operation_lock(self.state), storage.operation_lock(self.monitor_state):
            pass
        self.assertFalse(self.monitor_config.exists())

    def test_lock_descriptor_reaches_an_independent_checker_process(self):
        def child(command, cwd, pass_fds):
            program = (
                "import sys; from pathlib import Path; "
                "from cgp_cert_manager import core, installer; "
                "core.STATE=Path(sys.argv[1]); core.CONFIG=Path(sys.argv[2]); "
                "installer.MONITOR_STATE=Path(sys.argv[3]); installer.MONITOR_CONFIG=Path(sys.argv[4]); "
                "sys.exit(installer.main(['--check-lock', sys.argv[5], sys.argv[6]]))"
            )
            result = run_process(
                [sys.executable, "-c", program, str(self.state), str(self.config),
                 str(self.monitor_state), str(self.monitor_config), *map(str, pass_fds)],
                cwd=cwd, pass_fds=pass_fds, input=b"", stdout=PIPE, stderr=PIPE, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            return result
        self.payload.side_effect = child
        self.assertEqual(installer.run(), 0)
        with storage.operation_lock(self.state), storage.operation_lock(self.monitor_state):
            pass

    def test_check_lock_rejects_other_file(self):
        with storage.operation_lock(self.state) as lock, storage.operation_lock(self.monitor_state) as monitor_lock, \
                storage.open_private(self.config) as unrelated:
            with self.assertRaisesRegex(core.Error, "not the manager operation lock"):
                installer.check_lock(unrelated.fileno(), monitor_lock.fileno())
            with self.assertRaisesRegex(core.Error, "not the monitor operation lock"):
                installer.check_lock(lock.fileno(), unrelated.fileno())
            with self.assertRaisesRegex(core.Error, "not the manager operation lock"):
                installer.check_lock(monitor_lock.fileno(), lock.fileno())
        self.payload.assert_not_called()

    def test_check_lock_acquires_a_valid_unlocked_inherited_descriptor(self):
        with storage.open_private(self.state / "run.lock", "a", create=True) as inherited, \
                storage.open_private(self.monitor_state / "run.lock", "a", create=True) as monitor_inherited:
            self.assertEqual(installer.main(["--check-lock", str(inherited.fileno()),
                                             str(monitor_inherited.fileno())]), 0)
            for state in (self.state, self.monitor_state):
                with storage.open_private(state / "run.lock", "a") as contender:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with storage.operation_lock(self.state), storage.operation_lock(self.monitor_state):
            pass
        self.payload.assert_not_called()

    def test_busy_lock_refuses_without_payload(self):
        with storage.operation_lock(self.state):
            self.assertEqual(installer.main([]), 1)
        self.assertIn("busy", self.errors.getvalue())
        self.payload.assert_not_called()

    def test_busy_monitor_lock_refuses_and_releases_manager_lock(self):
        with storage.operation_lock(self.monitor_state):
            self.assertEqual(installer.main([]), 1)
            with storage.operation_lock(self.state):
                pass
        self.assertIn("busy", self.errors.getvalue())
        self.payload.assert_not_called()

    def test_unconfigured_monitor_preflight_is_read_only(self):
        with patch.object(monitor_config, "load") as load:
            installer.preflight()
        load.assert_not_called()
        self.assertFalse(self.monitor_config.exists())
        self.assertFalse(self.monitor_state.exists())
        self.payload.assert_not_called()

    def test_optional_monitor_config_and_state_are_preserved(self):
        data = {"schema": 1, "enabled": False, "endpoints": [],
                "notifications": {"enabled": False, "channels": []}}
        storage.atomic_json(self.monitor_config, data)
        evidence = self.monitor_state / "state.json"
        storage.atomic_json(evidence, {"private": "monitor observation and delivery evidence"})
        before = {path: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
                  for path in (self.monitor_config, evidence)}
        self.assertEqual(installer.run(), 0)
        for path, expected in before.items():
            self.assertEqual((path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns), expected)
        self.payload.assert_called_once()

    def test_invalid_monitor_config_refused_before_payload(self):
        storage.atomic_json(self.monitor_config, {"schema": 1, "enabled": True, "endpoints": [],
                                                  "notifications": {"enabled": False, "channels": []}})
        before = self.monitor_config.read_bytes()
        with patch.object(core, "token") as token:
            self.assertEqual(installer.main([]), 1)
        token.assert_not_called()
        self.assertEqual(self.monitor_config.read_bytes(), before)
        self.payload.assert_not_called()

    def test_unsafe_monitor_config_refused_without_permission_repair(self):
        storage.atomic_json(self.monitor_config, {"private": "keep existing contents"})
        self.monitor_config.chmod(0o644)
        before = self.monitor_config.read_bytes()
        self.assertEqual(installer.main([]), 1)
        self.assertEqual(self.monitor_config.read_bytes(), before)
        self.assertEqual(self.monitor_config.stat().st_mode & 0o777, 0o644)
        self.payload.assert_not_called()

    def test_unsafe_monitor_state_and_files_are_not_repaired(self):
        self.monitor_state.mkdir(mode=0o755)
        self.assertEqual(installer.main([]), 1)
        self.assertEqual(self.monitor_state.stat().st_mode & 0o777, 0o755)
        self.assertFalse((self.monitor_state / "run.lock").exists())
        self.monitor_state.chmod(0o700)
        evidence = self.monitor_state / "state.json"
        evidence.write_text('private monitor evidence')
        evidence.chmod(0o644)
        self.assertEqual(installer.main([]), 1)
        self.assertEqual(evidence.read_text(), 'private monitor evidence')
        self.assertEqual(evidence.stat().st_mode & 0o777, 0o644)
        self.payload.assert_not_called()

    def test_monitor_symlink_and_hardlink_lock_are_refused(self):
        self.monitor_state.mkdir(mode=0o700)
        lock = self.monitor_state / "run.lock"
        lock.symlink_to(self.token)
        self.assertEqual(installer.main([]), 1)
        self.assertTrue(lock.is_symlink())
        lock.unlink()
        os.link(self.token, lock)
        self.assertEqual(installer.main([]), 1)
        self.assertEqual(lock.stat().st_nlink, 2)
        self.assertIn("dummy", self.token.read_text())
        self.payload.assert_not_called()

    def test_invalid_dns_options_refuse_before_tokens_or_shell_payload(self):
        self.cfg.update(dns_propagation={'mode': 'adaptive'}, dns_preflight=False)
        core.atomic(self.config, self.cfg)
        with patch.object(core, 'token') as token:
            self.assertEqual(installer.main([]), 1)
        self.assertIn('requires preflight', self.errors.getvalue())
        token.assert_not_called()
        self.payload.assert_not_called()

    def test_unsafe_config_is_not_repaired(self):
        before = self.config.read_bytes()
        self.config.chmod(0o644)
        self.assertEqual(installer.main([]), 1)
        self.assertEqual(self.config.read_bytes(), before)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o644)
        self.payload.assert_not_called()

    def test_unsafe_credential_is_not_repaired(self):
        self.token.chmod(0o644)
        self.assertEqual(installer.main([]), 1)
        self.assertEqual(self.token.stat().st_mode & 0o777, 0o644)
        self.payload.assert_not_called()

    def test_unsafe_state_is_not_repaired(self):
        self.state.chmod(0o755)
        self.assertEqual(installer.main([]), 1)
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o755)
        self.assertFalse((self.state / "run.lock").exists())
        self.payload.assert_not_called()

    def test_unsafe_backup_is_not_repaired(self):
        backups = self.state / "backups"
        backups.mkdir(mode=0o700)
        backup = backups / "example.json"
        backup.write_text("private fixture")
        backup.chmod(0o644)
        self.assertEqual(installer.main([]), 1)
        self.assertEqual(backup.read_text(), "private fixture")
        self.assertEqual(backup.stat().st_mode & 0o777, 0o644)
        self.payload.assert_not_called()

    def test_symlink_and_hardlink_lock_are_refused(self):
        lock = self.state / "run.lock"
        lock.symlink_to(self.token)
        self.assertEqual(installer.main([]), 1)
        self.assertTrue(lock.is_symlink())
        self.assertEqual(core.token(self.token), "dummy")
        lock.unlink()
        os.link(self.token, lock)
        self.assertEqual(installer.main([]), 1)
        self.assertEqual(lock.stat().st_nlink, 2)
        self.payload.assert_not_called()

    def test_invalid_schedule_refused_before_payload(self):
        self.cfg["schedule"]["hour"] = 24
        core.atomic(self.config, self.cfg)
        self.assertEqual(installer.main([]), 1)
        self.payload.assert_not_called()

    def test_closed_lock_descriptor_refused(self):
        with storage.operation_lock(self.state) as lock, storage.operation_lock(self.monitor_state) as monitor_lock:
            for selected in (0, 1):
                descriptors = [lock.fileno(), monitor_lock.fileno()]
                closed = os.dup(descriptors[selected])
                os.close(closed)
                descriptors[selected] = closed
                self.assertEqual(installer.main(["--check-lock", *map(str, descriptors)]), 1)
        self.payload.assert_not_called()

    def test_interrupted_payload_releases_parent_lock(self):
        self.payload.side_effect = KeyboardInterrupt()
        self.assertEqual(installer.main([]), 130)
        with storage.operation_lock(self.state), storage.operation_lock(self.monitor_state):
            pass

    def test_module_entry_checks_lock_only(self):
        with storage.operation_lock(self.state) as lock, storage.operation_lock(self.monitor_state) as monitor_lock, \
                patch.object(installer.sys, "argv", ["installer", "--check-lock", str(lock.fileno()),
                                                      str(monitor_lock.fileno())]):
            with self.assertRaises(SystemExit) as result:
                runpy.run_module("cgp_cert_manager.installer", run_name="__main__")
        self.assertEqual(result.exception.code, 0)
        self.payload.assert_not_called()

    def test_internal_checker_requires_two_descriptors(self):
        with self.assertRaises(SystemExit) as exited:
            installer.main(["--check-lock", "3"])
        self.assertEqual(exited.exception.code, 2)
        self.payload.assert_not_called()
