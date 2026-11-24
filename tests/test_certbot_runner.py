"""Adaptive Certbot lock context and process cleanup ordering."""
import contextlib
import ctypes
import io
import os
from pathlib import Path
import runpy
import signal
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import Mock, call, patch

from cgp_cert_manager import certbot_runner as runner, core, dnsauth, storage


class CertbotRunnerTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.state = self.root / 'state'
        self.config = self.root / 'config.json'
        self.cfg = {'schema_version': 2, 'email': 'admin@example.com',
                    'dns_propagation': {'mode': 'adaptive'}}
        core.atomic(self.config, self.cfg)
        self.stack.enter_context(patch.object(core, 'STATE', self.state))
        self.stack.enter_context(patch.object(core, 'CONFIG', self.config))
        self.stack.enter_context(patch.dict(os.environ, {'CGP_CERTBOT_CONFIG': str(self.config)}))
        self.stack.enter_context(patch.object(runner, '_CONTEXT', None))
        self.cleanup = self.stack.enter_context(patch.object(dnsauth, 'cleanup_pending'))
        module = types.ModuleType('certbot.main')
        self.certbot = module.main = Mock(return_value=0)
        self.stack.enter_context(patch.dict(sys.modules, {'certbot.main': module}))
        self.errors = io.StringIO()
        self.stack.enter_context(contextlib.redirect_stderr(self.errors))
        self.process = Mock(pid=87654)
        self.process.wait.return_value = 0
        self.process.poll.return_value = 0
        self.popen = self.stack.enter_context(patch.object(runner.subprocess, 'Popen', return_value=self.process))
        self.group = self.stack.enter_context(patch.object(runner, '_group_exists', return_value=False))

    def assert_locked(self):
        with self.assertRaises(BlockingIOError), storage.operation_lock(self.state):
            pass

    def invoke_child(self, *args):
        with storage.operation_lock(self.state) as lock:
            return runner.main(['--manager-lock-fd', str(lock.fileno()), *args])

    def test_child_context_holds_lock_through_certbot_and_defers_cleanup_to_supervisor(self):
        def certbot(args):
            self.assertEqual(args, ['renew', '--non-interactive'])
            self.assertEqual(runner.require_context(), self.cfg)
            self.assert_locked()
            return 0

        self.certbot.side_effect = certbot
        self.assertEqual(self.invoke_child('renew', '--non-interactive'), 0)
        self.cleanup.assert_not_called()
        with self.assertRaisesRegex(core.Error, 'wrapper'):
            runner.require_context()
        with storage.operation_lock(self.state):
            pass
        self.popen.assert_not_called()

    def test_verified_inherited_descriptor_is_removed_from_certbot_arguments(self):
        with storage.operation_lock(self.state) as lock:
            self.assertEqual(runner.main(['--manager-lock-fd', str(lock.fileno()), 'certonly']), 0)
            self.assert_locked()
        self.certbot.assert_called_once_with(['certonly'])

    def test_other_descriptor_cannot_authorize_context(self):
        with storage.operation_lock(self.state), self.config.open() as other:
            self.assertEqual(runner.main(['--manager-lock-fd', str(other.fileno()), 'renew']), 1)
        self.assertIn('operation lock', self.errors.getvalue())
        self.certbot.assert_not_called()
        self.cleanup.assert_not_called()

    def test_environment_and_inherited_process_state_do_not_authorize_plugin(self):
        with self.assertRaises(core.Error):
            runner.require_context()
        with patch.object(runner, '_CONTEXT', (os.getpid() + 1, 1, self.cfg)):
            with self.assertRaises(core.Error): runner.require_context()
        self.assertFalse(self.state.exists())

    def test_context_rechecks_named_lock_identity(self):
        with storage.operation_lock(self.state) as lock:
            with patch.object(runner, '_CONTEXT', (os.getpid(), lock.fileno(), self.cfg)):
                self.assertEqual(runner.require_context(), self.cfg)
                (self.state / 'run.lock').unlink()
                core.atomic(self.state / 'run.lock', {})
                with self.assertRaisesRegex(core.Error, 'operation lock'):
                    runner.require_context()

    def test_standalone_refuses_busy_lock_and_private_config_faults(self):
        with storage.operation_lock(self.state):
            self.assertEqual(runner.main(['renew']), 1)
        for cfg in ([], {'schema_version': 1}, {'schema_version': 2}):
            core.atomic(self.config, cfg)
            self.assertEqual(runner.main(['renew']), 1)
        core.atomic(self.config, self.cfg)
        self.config.chmod(0o644)
        self.assertEqual(runner.main(['renew']), 1)
        self.certbot.assert_not_called()
        self.cleanup.assert_not_called()

    def test_relative_config_refused_before_state_creation(self):
        with patch.dict(os.environ, {'CGP_CERTBOT_CONFIG': 'relative.json'}):
            self.assertEqual(runner.main(['renew']), 1)
        self.assertIn('must be absolute', self.errors.getvalue())
        self.assertFalse(self.state.exists())

    def test_certbot_failures_cleanup_and_clear_context_without_secret_errors(self):
        for error, status in ((OSError('PRIVATE_SENTINEL'), 1), (core.Error('Safe refusal'), 1),
                              (KeyboardInterrupt(), 130)):
            with self.subTest(error=type(error).__name__):
                self.certbot.side_effect = error
                self.assertEqual(self.invoke_child('renew'), status)
                self.assertIsNone(runner._CONTEXT)
        self.cleanup.assert_not_called()
        self.assertNotIn('PRIVATE_SENTINEL', self.errors.getvalue())
        self.assertIn('Safe refusal', self.errors.getvalue())

    def test_failed_cleanup_is_not_suppressed_and_context_is_cleared(self):
        self.cleanup.side_effect = core.Error('DNS cleanup pending')
        self.assertEqual(runner.main(['renew']), 1)
        self.assertIn('DNS cleanup pending', self.errors.getvalue())
        self.assertIsNone(runner._CONTEXT)

    def test_default_configuration_path_and_module_entry(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(runner.main([]), 0)
        self.popen.assert_called_once()
        self.certbot.assert_not_called()
        with patch.object(runner, 'main', return_value=7) as main:
            with self.assertRaises(SystemExit) as error:
                runpy.run_module('cgp_cert_manager.certbot_runner', run_name='__main__')
        self.assertEqual(error.exception.code, 7)
        main.assert_called_once_with()

    def test_standalone_supervises_child_with_selected_configuration(self):
        alternate = self.root / 'alternate.json'
        core.atomic(alternate, self.cfg)
        def supervise(command, cfg, lock_fd, config_path):
            self.assertEqual(command, ['certbot', 'renew'])
            self.assertEqual(cfg, self.cfg)
            self.assertEqual(config_path, alternate)
            runner._check_lock(lock_fd)
            self.assert_locked()
        with patch.dict(os.environ, {'CGP_CERTBOT_CONFIG': str(alternate)}), \
                patch.object(runner, 'run', side_effect=supervise) as run:
            self.assertEqual(runner.main(['renew']), 0)
            run.assert_called_once()
        self.certbot.assert_not_called()

    def test_exact_help_and_version_do_not_read_configuration_state_or_ledger(self):
        self.config.unlink()
        with patch.object(core, 'load') as load, patch.object(storage, 'operation_lock') as lock:
            for flag in ('--version', '--help', '-h'):
                self.assertEqual(runner.main([flag]), 0)
                self.certbot.assert_called_with([flag])
            with patch.object(runner.sys, 'argv', ['cgp-certbot', '--version']):
                self.assertEqual(runner.main(), 0)
            load.assert_not_called()
            lock.assert_not_called()
        self.cleanup.assert_not_called()
        self.assertFalse(self.state.exists())

    def test_mixed_help_or_version_arguments_do_not_bypass_configuration(self):
        core.atomic(self.config, {'schema_version': 2})
        for args in (['renew', '--version'], ['--help', '--dry-run'], ['-h', 'renew']):
            self.assertEqual(runner.main(args), 1)
        self.certbot.assert_not_called()
        self.cleanup.assert_not_called()

    def test_parent_launch_passes_private_lock_config_and_package_path(self):
        events = []
        def wait(timeout):
            self.assert_locked()
            events.append('wait')
            return 0
        self.process.wait.side_effect = wait
        self.cleanup.side_effect = lambda cfg: events.append('cleanup')
        original_handler = signal.getsignal(signal.SIGTERM)
        runner.run(['certbot', 'certonly', '--authenticator', 'cgp-dns'], self.cfg)
        command = self.popen.call_args.args[0]
        kwargs = self.popen.call_args.kwargs
        self.assertEqual(command[:3], [sys.executable, '-m', 'cgp_cert_manager.certbot_runner'])
        self.assertEqual(command[3], '--manager-lock-fd')
        self.assertEqual(command[5:], ['certonly', '--authenticator', 'cgp-dns'])
        self.assertEqual(kwargs['pass_fds'], (int(command[4]),))
        self.assertEqual(kwargs['env']['CGP_CERTBOT_CONFIG'], str(self.config))
        self.assertEqual(kwargs['env']['PYTHONPATH'], str(Path(runner.__file__).resolve().parents[1]))
        self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
        self.assertTrue(kwargs['start_new_session'])
        self.assertEqual(events, ['wait', 'wait', 'cleanup'])
        self.assertIs(signal.getsignal(signal.SIGTERM), original_handler)

    def test_parent_reuses_existing_lock_and_refuses_changed_configuration(self):
        with storage.operation_lock(self.state) as lock:
            runner.run(['certbot', 'renew'], self.cfg, lock_fd=lock.fileno())
            self.assertEqual(self.popen.call_args.kwargs['pass_fds'], (lock.fileno(),))
            self.assert_locked()
            self.popen.reset_mock()
            with self.assertRaisesRegex(core.Error, 'configuration changed'):
                runner.run(['certbot', 'renew'], dict(self.cfg, email='other@example.com'), lock_fd=lock.fileno())
            self.popen.assert_not_called()

    def test_parent_restores_signal_handler_on_launch_failure(self):
        original_handler = signal.getsignal(signal.SIGTERM)
        self.popen.side_effect = OSError('launch failed')
        with self.assertRaises(OSError): runner.run(['certbot', 'renew'], self.cfg)
        self.assertIs(signal.getsignal(signal.SIGTERM), original_handler)
        self.cleanup.assert_not_called()
        self.popen.reset_mock()
        with patch.object(runner.signal, 'signal', side_effect=ValueError('not main thread')):
            with self.assertRaises(ValueError): runner.run(['certbot', 'renew'], self.cfg)
        self.popen.assert_not_called()

    def test_nonzero_timeout_and_signal_wait_for_quiescence_before_cleanup(self):
        for outcome, expected in ((2, core.Error),
                                  (subprocess.TimeoutExpired('certbot', 3600), core.Error),
                                  (KeyboardInterrupt(), KeyboardInterrupt)):
            with self.subTest(outcome=type(outcome).__name__):
                self.process.wait.side_effect = [outcome, 0]
                self.cleanup.reset_mock()
                with self.assertRaises(expected): runner.run(['certbot', 'renew'], self.cfg)
                self.cleanup.assert_called_once_with(self.cfg)
        with self.assertRaises(KeyboardInterrupt): runner._interrupted(signal.SIGTERM, None)

    def test_normal_leader_exit_still_stops_live_process_group_before_cleanup(self):
        self.group.side_effect = [True, True, False]
        events = []
        self.cleanup.side_effect = lambda cfg: events.append('cleanup')
        with patch.object(runner.os, 'killpg', side_effect=lambda pid, sig: events.append(sig)), \
                patch.object(runner.time, 'monotonic', side_effect=[0, 1]), \
                patch.object(runner.time, 'sleep') as sleep:
            runner.run(['certbot', 'renew'], self.cfg)
        self.assertEqual(events, [signal.SIGTERM, 'cleanup'])
        sleep.assert_called_once_with(0.05)

    def test_term_ignored_escalates_to_kill_and_unresolved_group_preserves_ledger(self):
        self.group.side_effect = [True, True, False]
        with patch.object(runner.os, 'killpg') as kill, \
                patch.object(runner.time, 'monotonic', side_effect=[0, 11, 12]):
            runner.run(['certbot', 'renew'], self.cfg)
        self.assertEqual(kill.call_args_list, [call(self.process.pid, signal.SIGTERM), call(self.process.pid, signal.SIGKILL)])
        self.cleanup.assert_called_once()
        self.cleanup.reset_mock()
        self.group.side_effect = None
        self.group.return_value = True
        with patch.object(runner.os, 'killpg'), patch.object(runner.time, 'monotonic', side_effect=[0, 11, 12, 23]):
            with self.assertRaisesRegex(core.Error, 'cleanup remains pending'):
                runner.run(['certbot', 'renew'], self.cfg)
        self.cleanup.assert_not_called()

    def test_group_can_disappear_between_probe_and_signal(self):
        self.group.side_effect = [True, False]
        with patch.object(runner.os, 'killpg', side_effect=ProcessLookupError):
            runner.run(['certbot', 'renew'], self.cfg)
        self.cleanup.assert_called_once()


class ProcessGroupTests(unittest.TestCase):
    def test_group_probe_distinguishes_absence_from_permission_failure(self):
        with patch.object(runner.os, 'killpg', side_effect=[None, ProcessLookupError(), PermissionError()]):
            self.assertTrue(runner._group_exists(123))
            self.assertFalse(runner._group_exists(123))
            with self.assertRaises(PermissionError): runner._group_exists(123)

    @unittest.skipUnless(sys.platform == 'linux', 'Linux process group integration')
    def test_orphaned_term_ignoring_child_is_killed_before_cleanup_can_run(self):
        # Adopt and reap this fixture's orphan so the test can prove complete
        # process-group disappearance even when the container PID 1 does not reap.
        libc = ctypes.CDLL(None, use_errno=True)
        prior = ctypes.c_int()
        self.assertEqual(libc.prctl(37, ctypes.byref(prior), 0, 0, 0), 0)
        self.assertEqual(libc.prctl(36, 1, 0, 0, 0), 0)
        child_pid = None
        reaper = None
        process = None
        try:
            with tempfile.TemporaryDirectory() as tmp:
                ready = Path(tmp) / 'ready'
                marker = Path(tmp) / 'late-mutation'
                code = ('import os,signal,sys,time\nfrom pathlib import Path\n'
                        'child=os.fork()\n'
                        'if child==0:\n'
                        ' signal.signal(signal.SIGTERM,signal.SIG_IGN)\n'
                        ' Path(sys.argv[1]).touch()\n'
                        ' time.sleep(1)\n'
                        ' Path(sys.argv[2]).touch()\n'
                        ' os._exit(0)\n'
                        'print(child,flush=True)\nos._exit(0)\n')
                process = subprocess.Popen([sys.executable, '-c', code, str(ready), str(marker)],
                                           stdout=subprocess.PIPE, text=True, start_new_session=True)
                child_pid = int(process.stdout.readline())
                process.wait(timeout=2)
                deadline = time.monotonic() + 2
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(ready.exists())
                self.assertTrue(runner._group_exists(process.pid))
                reaper = threading.Thread(target=lambda: os.waitpid(child_pid, 0))
                reaper.start()
                with patch.object(runner, '_STOP_TIMEOUT', 0.1):
                    runner._quiesce(process)
                reaper.join(timeout=2)
                self.assertFalse(reaper.is_alive())
                self.assertFalse(runner._group_exists(process.pid))
                self.assertFalse(marker.exists())
        finally:
            if child_pid is not None and (reaper is None or reaper.is_alive()):
                with contextlib.suppress(ProcessLookupError): os.kill(child_pid, signal.SIGKILL)
            if reaper is not None:
                reaper.join(timeout=2)
            elif child_pid is not None:
                with contextlib.suppress(ChildProcessError): os.waitpid(child_pid, 0)
            if process is not None:
                process.stdout.close()
                with contextlib.suppress(ProcessLookupError): process.kill()
                process.wait(timeout=2)
            self.assertEqual(libc.prctl(36, prior.value, 0, 0, 0), 0)
