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

from cgp_cert_manager import core, installer, storage, tui


class InstallerGuardTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
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
            fd = pass_fds[0]
            self.assertEqual(command, ["bash", str(cwd / "scripts" / "install-locked.sh"), str(fd)])
            self.assertEqual(os.fstat(fd).st_ino, (self.state / "run.lock").stat().st_ino)
            installer.check_lock(fd)
            with storage.open_private(self.state / "run.lock", "a") as contender:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return Mock(returncode=7)
        self.payload.side_effect = child
        self.assertEqual(installer.main([]), 7)
        with storage.operation_lock(self.state):
            pass

    def test_lock_descriptor_reaches_an_independent_checker_process(self):
        def child(command, cwd, pass_fds):
            program = (
                "import sys; from pathlib import Path; "
                "from cgp_cert_manager import core, installer; "
                "core.STATE=Path(sys.argv[1]); core.CONFIG=Path(sys.argv[2]); "
                "sys.exit(installer.main(['--check-lock', sys.argv[3]]))"
            )
            result = run_process(
                [sys.executable, "-c", program, str(self.state), str(self.config), str(pass_fds[0])],
                cwd=cwd, pass_fds=pass_fds, input=b"", stdout=PIPE, stderr=PIPE, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            return result
        self.payload.side_effect = child
        self.assertEqual(installer.run(), 0)
        with storage.operation_lock(self.state):
            pass

    def test_check_lock_rejects_other_file(self):
        with storage.operation_lock(self.state), storage.open_private(self.config) as unrelated:
            with self.assertRaisesRegex(core.Error, "not the manager operation lock"):
                installer.check_lock(unrelated.fileno())
        self.payload.assert_not_called()

    def test_check_lock_acquires_a_valid_unlocked_inherited_descriptor(self):
        with storage.open_private(self.state / "run.lock", "a", create=True) as inherited:
            self.assertEqual(installer.main(["--check-lock", str(inherited.fileno())]), 0)
            with storage.open_private(self.state / "run.lock", "a") as contender:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with storage.operation_lock(self.state):
            pass
        self.payload.assert_not_called()

    def test_busy_lock_refuses_without_payload(self):
        with storage.operation_lock(self.state):
            self.assertEqual(installer.main([]), 1)
        self.assertIn("busy", self.errors.getvalue())
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
        with storage.operation_lock(self.state) as lock:
            descriptor = os.dup(lock.fileno())
            os.close(descriptor)
            self.assertEqual(installer.main(["--check-lock", str(descriptor)]), 1)
        self.payload.assert_not_called()

    def test_interrupted_payload_releases_parent_lock(self):
        self.payload.side_effect = KeyboardInterrupt()
        self.assertEqual(installer.main([]), 130)
        with storage.operation_lock(self.state):
            pass

    def test_module_entry_checks_lock_only(self):
        with storage.operation_lock(self.state) as lock, \
                patch.object(installer.sys, "argv", ["installer", "--check-lock", str(lock.fileno())]):
            with self.assertRaises(SystemExit) as result:
                runpy.run_module("cgp_cert_manager.installer", run_name="__main__")
        self.assertEqual(result.exception.code, 0)
        self.payload.assert_not_called()
