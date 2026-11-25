"""Pending application updates exclude supported mutations before any effects."""
import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from cgp_cert_manager import (certbot_runner, cli, console, core, dnsauth, installer,
                             monitor_cli, monitor_config, monitor_runner, storage, tui,
                             update_gate)


ROOT = Path(__file__).resolve().parents[1]


class UpdateGuardIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.state = self.root / 'manager'
        self.monitor = self.root / 'monitor'
        self.updater = self.root / 'updater'
        self.config = self.root / 'private-config' / 'config.json'
        self.cfg = {'schema_version': 2, 'email': 'admin@example.test'}
        core.atomic(self.config, self.cfg)
        for module, name, value in ((core, 'STATE', self.state), (cli, 'STATE', self.state),
                                    (core, 'CONFIG', self.config), (cli, 'CONFIG', self.config),
                                    (installer, 'MONITOR_STATE', self.monitor),
                                    (update_gate, 'STATE_DIR', self.updater)):
            self.stack.enter_context(patch.object(module, name, value))
        self.stack.enter_context(patch.object(os, 'umask'))
        self.errors = self.stack.enter_context(contextlib.redirect_stderr(io.StringIO()))

    def pending(self):
        storage.atomic_text(self.updater / 'pending.json', 'not even valid JSON\n')

    def test_manager_early_refusal_does_not_create_state_or_read_config(self):
        self.pending()
        for arguments in ([], ['--hook-auth'], ['--hook-cleanup'], ['--metrics'], ['--apply-schedule']):
            with self.subTest(arguments=arguments), patch.object(cli.sys, 'argv', ['manager', *arguments]), \
                    patch.object(cli, 'load') as load, patch.object(cli, 'locked_main') as main, \
                    patch.object(cli, 'hook') as hook, patch.object(cli.LOG, 'error') as error:
                self.assertEqual(cli.entry(), 1)
                load.assert_not_called()
                main.assert_not_called()
                hook.assert_not_called()
                error.assert_called_once_with('%s', 'update_pending')
        self.assertFalse(self.state.exists())
        with patch.object(cli.sys, 'argv', ['manager', '--version']), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as exited:
                cli.main()
        self.assertEqual(exited.exception.code, 0)

    def test_manager_rechecks_gate_under_manager_lock_before_dispatch(self):
        original = storage.operation_lock
        @contextlib.contextmanager
        def acquired(state):
            with original(state) as lock:
                self.pending()
                yield lock
        with patch.object(storage, 'operation_lock', acquired), patch.object(cli, 'load') as load, \
                patch.object(cli.sys, 'argv', ['manager']), patch.object(cli.LOG, 'error'):
            self.assertEqual(cli.entry(), 1)
        load.assert_not_called()
        with original(self.state):
            pass

    def test_direct_manual_hooks_refuse_even_cleanup_without_provider_calls(self):
        self.pending()
        with patch.object(cli, 'cf') as provider, patch.object(cli, 'zones') as zones:
            for cleanup in (False, True):
                with self.assertRaisesRegex(update_gate.PendingUpdateError, '^update_pending$'):
                    cli.hook({}, cleanup)
        provider.assert_not_called()
        zones.assert_not_called()

    def test_monitor_refuses_before_worker_state_or_notification_and_after_lock(self):
        cfg = monitor_config.validate({'schema': 1, 'enabled': True, 'endpoints': [
            {'id': 'mail', 'host': '127.0.0.1', 'port': 443, 'server_name': 'example.test'}]})
        original = storage.operation_lock
        @contextlib.contextmanager
        def acquired(state):
            with original(state) as lock:
                self.pending()
                yield lock
        with patch.object(monitor_runner.monitor_worker, 'execute') as worker, \
                patch.object(monitor_runner, '_save') as save:
            with patch.object(storage, 'operation_lock', acquired):
                with self.assertRaisesRegex(update_gate.PendingUpdateError, '^update_pending$'):
                    monitor_runner.run(cfg, self.monitor, send=True)
            worker.assert_not_called()
            save.assert_not_called()
            with patch.object(storage, 'operation_lock') as lock, \
                    patch.object(monitor_config, 'load', return_value=cfg), contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(monitor_cli.main(['--run', '--send', '--json', '--state-dir', str(self.monitor)]), 2)
            lock.assert_not_called()
            self.assertIn('update_pending', out.getvalue())
        with original(self.monitor):
            pass

    def test_wizard_and_direct_save_refuse_without_backups_tokens_or_edits(self):
        self.pending()
        before = self.config.read_bytes()
        with patch.object(tui, 'os', Mock(wraps=os)) as ui_os, patch.object(tui.sys.stdin, 'isatty', return_value=True), \
                patch.object(tui.sys.stdout, 'isatty', return_value=True), patch.object(tui.shutil, 'which', return_value='/whiptail'), \
                patch.object(tui, 'edit') as edit, patch.object(tui, 'write_token') as token:
            ui_os.geteuid.return_value = 0
            self.assertEqual(tui.setup(), 1)
            with self.assertRaisesRegex(update_gate.PendingUpdateError, '^update_pending$'):
                tui.save_config({}, {}, set())
        edit.assert_not_called()
        token.assert_not_called()
        self.assertEqual(self.config.read_bytes(), before)
        self.assertFalse(self.state.exists())

    def test_installer_refuses_before_creating_locks_or_launching_payload(self):
        self.pending()
        with patch.object(installer, 'runtime_dependencies') as dependencies, \
                patch.object(installer.subprocess, 'run') as payload:
            self.assertEqual(installer.main([]), 1)
            self.assertEqual(installer.main(['--check-lock', '-1', '-1']), 1)
            with self.assertRaisesRegex(update_gate.PendingUpdateError, '^update_pending$'):
                installer.preflight()
        dependencies.assert_not_called()
        payload.assert_not_called()
        self.assertFalse(self.state.exists())
        self.assertFalse(self.monitor.exists())
        self.assertIn('update_pending', self.errors.getvalue())

    def test_adaptive_runner_context_and_standalone_cannot_bypass_pending(self):
        self.pending()
        with patch.object(certbot_runner.subprocess, 'Popen') as process, patch.object(dnsauth, 'cleanup_pending') as cleanup:
            self.assertEqual(certbot_runner.main(['renew', '--non-interactive']), 1)
            with self.assertRaisesRegex(update_gate.PendingUpdateError, '^update_pending$'):
                certbot_runner.run(['certbot', 'renew'], self.cfg)
            with storage.operation_lock(self.state) as lock:
                self.assertEqual(certbot_runner.main(['--manager-lock-fd', str(lock.fileno()), 'renew']), 1)
                with patch.object(certbot_runner, '_CONTEXT', (os.getpid(), lock.fileno(), self.cfg)):
                    with self.assertRaisesRegex(update_gate.PendingUpdateError, '^update_pending$'):
                        certbot_runner.require_context()
                with self.assertRaisesRegex(update_gate.PendingUpdateError, '^update_pending$'):
                    certbot_runner._invoke(['renew'], self.config, lock.fileno())
        process.assert_not_called()
        cleanup.assert_not_called()
        self.assertIn('update_pending', self.errors.getvalue())

    def test_console_direct_timer_mutations_hold_manager_lock_and_refuse_pending(self):
        screen = console.Screen.__new__(console.Screen)
        screen.menu = Mock(return_value=2)
        screen.confirm = Mock(return_value=True)
        screen.view = Mock()
        def execute(command, title):
            with self.assertRaises(BlockingIOError), storage.operation_lock(self.state):
                pass
        screen.execute = Mock(side_effect=execute)
        screen.timer_menu()
        screen.execute.assert_called_once()
        self.pending()
        for choice in (2, 3, 4):
            screen.menu.return_value = choice
            screen.timer_menu()
        self.assertEqual(screen.execute.call_count, 1)
        self.assertEqual(screen.view.call_count, 3)
        (self.updater / 'pending.json').unlink()
        with storage.operation_lock(self.state):
            screen.timer_menu()
        self.assertEqual(screen.execute.call_count, 1)
        screen.menu.return_value = 1
        screen.execute.side_effect = None
        with patch.object(storage, 'operation_lock', side_effect=AssertionError('CLI must own its lock')):
            screen.timer_menu()
        self.assertIn('--apply-schedule', screen.execute.call_args.args[0])

    def test_all_normal_launchers_guard_before_any_application_import(self):
        program = '''
from pathlib import Path
import importlib.abc, runpy, sys
runtime, launcher, pending = map(Path, sys.argv[1:])
sys.path.insert(0, str(runtime))
import cgp_update_gate
cgp_update_gate.STATE_DIR = pending
class BlockApplication(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'cgp_cert_manager' or fullname.startswith('cgp_cert_manager.'):
            raise AssertionError('Application imported while update is pending')
sys.meta_path.insert(0, BlockApplication())
try:
    runpy.run_path(str(launcher), run_name='__main__')
except SystemExit as error:
    assert error.code == 1
else:
    raise AssertionError('No refusal')
assert sys.dont_write_bytecode
assert 'cgp_cert_manager' not in sys.modules
'''
        self.pending()
        runtime = self.root / 'runtime'
        runtime.mkdir()
        (runtime / 'cgp_update_gate.py').write_bytes((ROOT / 'cgp_cert_manager/update_gate.py').read_bytes())
        for name in ('launcher', 'certbot-launcher', 'monitor-launcher'):
            result = subprocess.run([sys.executable, '-I', '-B', '-c', program, str(runtime), str(ROOT / name), str(self.updater)],
                                    cwd=self.root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(result.stderr, b'CGP operation refused: update_pending\n')
            self.assertFalse((runtime / '__pycache__').exists())

    def test_outer_installer_guard_runs_before_compile_wizard_or_lock_payload(self):
        source = (ROOT / 'install.sh').read_text()
        guard = source.split("<<'UPDATE_GUARD'\n", 1)[1].split('\nUPDATE_GUARD\n', 1)[0]
        self.assertLess(source.index("<<'UPDATE_GUARD'"), source.index('python3 -m compileall'))
        self.pending()
        with self.assertRaises(SystemExit) as exited:
            exec(compile(guard, '<installer preflight>', 'exec'), {})
        self.assertEqual(exited.exception.code, 1)
        self.assertFalse(self.state.exists())
        self.assertIn('update_pending', self.errors.getvalue())

    def test_absent_application_never_falls_back_to_old_runtime_without_pending(self):
        program = '''
from pathlib import Path
import importlib.util, runpy, sys
runtime, launcher, pending, missing_app = map(Path, sys.argv[1:])
spec = importlib.util.spec_from_file_location('cgp_update_gate', runtime / 'cgp_update_gate.py')
gate = importlib.util.module_from_spec(spec)
sys.modules['cgp_update_gate'] = gate
spec.loader.exec_module(gate)
gate.STATE_DIR = pending
class InstalledPaths(list):
    def insert(self, index, path):
        mapped = {'/opt/cgp-update-runtime': str(runtime),
                  '/opt/cgp-certificate-manager': str(missing_app)}
        super().insert(index, mapped.get(path, path))
sys.path = InstalledPaths(sys.path)
try:
    runpy.run_path(str(launcher), run_name='__main__')
except ModuleNotFoundError as error:
    assert error.name == 'cgp_cert_manager', error
else:
    raise AssertionError('Missing installed app must refuse')
assert str(runtime) not in sys.path
assert 'cgp_cert_manager' not in sys.modules
assert sys.dont_write_bytecode
'''
        runtime = self.root / 'runtime'
        package = runtime / 'cgp_cert_manager'
        package.mkdir(parents=True)
        (runtime / 'cgp_update_gate.py').write_bytes((ROOT / 'cgp_cert_manager/update_gate.py').read_bytes())
        (package / '__init__.py').write_text("raise AssertionError('Old runtime application was executed')\n")
        for name in ('launcher', 'certbot-launcher', 'monitor-launcher'):
            result = subprocess.run([sys.executable, '-I', '-B', '-c', program, str(runtime), str(ROOT / name),
                                     str(self.updater), str(self.root / 'missing-app')],
                                    cwd=self.root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(result.stderr, b'')
            self.assertFalse((runtime / '__pycache__').exists())
            self.assertFalse((package / '__pycache__').exists())


if __name__ == '__main__':
    unittest.main()
