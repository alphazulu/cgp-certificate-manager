"""Adaptive Certbot lock context and process cleanup ordering."""
import contextlib
import ctypes
import fcntl
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
        self.real_popen = subprocess.Popen
        self.real_group_exists = runner._group_exists
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

    def test_unlocked_shared_and_separately_opened_fds_cannot_authorize_context(self):
        storage.ensure_private_directory(self.state)
        with storage.open_private(self.state / 'run.lock', 'a', create=True) as unlocked:
            self.assertEqual(runner.main(['--manager-lock-fd', str(unlocked.fileno()), 'renew']), 1)
            with storage.operation_lock(self.state):
                with self.assertRaisesRegex(core.Error, 'already held'):
                    runner._check_lock(unlocked.fileno())
            fcntl.flock(unlocked, fcntl.LOCK_SH | fcntl.LOCK_NB)
            with self.assertRaisesRegex(core.Error, 'already held'):
                runner._check_lock(unlocked.fileno())
        self.certbot.assert_not_called()
        self.cleanup.assert_not_called()

    def test_unavailable_procfs_fails_closed_without_acquiring_lock(self):
        with storage.operation_lock(self.state) as lock:
            with patch.object(runner.Path, 'read_text', side_effect=OSError('PRIVATE_SENTINEL')):
                with self.assertRaisesRegex(core.Error, 'Linux procfs') as error:
                    runner._check_lock(lock.fileno())
            self.assertNotIn('PRIVATE_SENTINEL', str(error.exception))
            self.assert_locked()

    def test_real_subprocess_verifies_inherited_exclusive_lock(self):
        code = ('import sys\nfrom pathlib import Path\n'
                'from cgp_cert_manager import core,certbot_runner\n'
                'core.STATE=Path(sys.argv[1])\n'
                'certbot_runner._check_lock(int(sys.argv[2]))\n'
                'print("verified")\n')
        with storage.operation_lock(self.state) as lock:
            process = self.real_popen([sys.executable, '-c', code, str(self.state), str(lock.fileno())],
                                      pass_fds=(lock.fileno(),), stdin=subprocess.DEVNULL,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, stderr)
            self.assertEqual(stdout.strip(), 'verified')
            self.assert_locked()

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
        original_int = signal.getsignal(signal.SIGINT)
        self.popen.side_effect = OSError('launch failed')
        with self.assertRaises(OSError): runner.run(['certbot', 'renew'], self.cfg)
        self.assertIs(signal.getsignal(signal.SIGTERM), original_handler)
        self.assertIs(signal.getsignal(signal.SIGINT), original_int)
        self.cleanup.assert_not_called()
        self.popen.reset_mock()
        with patch.object(runner.signal, 'signal', side_effect=ValueError('not main thread')):
            with self.assertRaises(ValueError): runner.run(['certbot', 'renew'], self.cfg)
        self.popen.assert_not_called()

    def test_partial_signal_handler_setup_restores_previous_handler(self):
        original_term = signal.getsignal(signal.SIGTERM)
        original_int = signal.getsignal(signal.SIGINT)
        real_signal = signal.signal
        def refuse_int(signum, handler):
            if signum == signal.SIGINT:
                raise ValueError('handler setup failed')
            return real_signal(signum, handler)
        with patch.object(runner.signal, 'signal', side_effect=refuse_int):
            with self.assertRaises(ValueError):
                runner.run(['certbot', 'renew'], self.cfg)
        self.assertIs(signal.getsignal(signal.SIGTERM), original_term)
        self.assertIs(signal.getsignal(signal.SIGINT), original_int)
        self.popen.assert_not_called()

    def test_nonzero_timeout_and_signal_wait_for_quiescence_before_cleanup(self):
        for outcome, expected in ((2, core.Error),
                                  (KeyboardInterrupt(), KeyboardInterrupt)):
            with self.subTest(outcome=type(outcome).__name__):
                self.process.wait.side_effect = [outcome, 0]
                self.cleanup.reset_mock()
                with self.assertRaises(expected): runner.run(['certbot', 'renew'], self.cfg)
                self.cleanup.assert_called_once_with(self.cfg)
        self.cleanup.reset_mock()
        self.process.wait.side_effect = None
        with patch.object(runner.time, 'monotonic', side_effect=[0, 3601]):
            with self.assertRaisesRegex(core.Error, 'timed out'):
                runner.run(['certbot', 'renew'], self.cfg)
        self.cleanup.assert_called_once_with(self.cfg)

    def test_wait_pulses_preserve_total_deadline_and_normal_completion(self):
        self.process.wait.side_effect = [subprocess.TimeoutExpired('certbot', 0.1), 0]
        with patch.object(runner.time, 'monotonic', side_effect=[0, 0, 3599.98]):
            self.assertEqual(runner._wait(self.process, runner._Interrupts()), 0)
        self.assertAlmostEqual(self.process.wait.call_args_list[0].kwargs['timeout'], 0.1)
        self.assertAlmostEqual(self.process.wait.call_args_list[1].kwargs['timeout'], 0.02)

    def test_signal_during_cleanup_is_deferred_until_cleanup_completes(self):
        original_term = signal.getsignal(signal.SIGTERM)
        original_int = signal.getsignal(signal.SIGINT)
        events = []
        def cleanup(cfg):
            events.append('cleanup started')
            os.kill(os.getpid(), signal.SIGINT)
            self.assert_locked()
            events.append('cleanup finished')
        self.cleanup.side_effect = cleanup
        self.assertEqual(runner.main(['renew']), 130)
        self.assertEqual(events, ['cleanup started', 'cleanup finished'])
        self.assertIs(signal.getsignal(signal.SIGTERM), original_term)
        self.assertIs(signal.getsignal(signal.SIGINT), original_int)

    def test_signal_during_launch_keeps_real_child_supervised(self):
        spawned = []
        real_killpg = os.killpg
        def launch_then_signal(command, **kwargs):
            child = self.real_popen([sys.executable, '-c', 'import time; time.sleep(60)'],
                                    start_new_session=True, stdin=subprocess.DEVNULL,
                                    pass_fds=kwargs['pass_fds'])
            spawned.append(child)
            os.kill(os.getpid(), signal.SIGTERM)
            return child
        try:
            with patch.object(runner.subprocess, 'Popen', side_effect=launch_then_signal), \
                    patch.object(runner, '_group_exists', self.real_group_exists):
                with self.assertRaises(KeyboardInterrupt):
                    runner.run(['certbot', 'renew'], self.cfg)
            self.assertIsNotNone(spawned[0].poll())
            self.cleanup.assert_called_once_with(self.cfg)
        finally:
            for child in spawned:
                if child.poll() is None:
                    with contextlib.suppress(ProcessLookupError): real_killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=3)

    def test_second_signal_cannot_abandon_real_term_ignoring_child(self):
        ready = self.root / 'child-ready'
        child = self.real_popen([sys.executable, '-c',
                                'import signal,time,sys; from pathlib import Path; '
                                'signal.signal(signal.SIGTERM,signal.SIG_IGN); '
                                'Path(sys.argv[1]).touch(); time.sleep(60)', str(ready)],
                               start_new_session=True, stdin=subprocess.DEVNULL)
        original_wait = child.wait
        real_killpg = os.killpg
        first = True
        def interrupted_wait(timeout):
            nonlocal first
            if first:
                first = False
                os.kill(os.getpid(), signal.SIGTERM)
            return original_wait(timeout=timeout)
        def interrupt_teardown(pid, sig):
            real_killpg(pid, sig)
            if sig == signal.SIGTERM:
                os.kill(os.getpid(), signal.SIGTERM)
        try:
            deadline = time.monotonic() + 3
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(ready.exists())
            with patch.object(runner.subprocess, 'Popen', return_value=child), \
                    patch.object(runner, '_group_exists', self.real_group_exists), \
                    patch.object(runner.os, 'killpg', side_effect=interrupt_teardown), \
                    patch.object(runner, '_STOP_TIMEOUT', 0.05), \
                    patch.object(child, 'wait', side_effect=interrupted_wait):
                with self.assertRaises(KeyboardInterrupt):
                    runner.run(['certbot', 'renew'], self.cfg)
            self.assertIsNotNone(child.poll())
            self.cleanup.assert_called_once_with(self.cfg)
        finally:
            if child.poll() is None:
                with contextlib.suppress(ProcessLookupError): real_killpg(child.pid, signal.SIGKILL)
            original_wait(timeout=3)

    def test_normal_leader_exit_still_stops_live_process_group_before_cleanup(self):
        self.group.side_effect = [True, True, False]
        events = []
        self.cleanup.side_effect = lambda cfg: events.append('cleanup')
        with patch.object(runner.os, 'killpg', side_effect=lambda pid, sig: events.append(sig)), \
                patch.object(runner.time, 'monotonic', side_effect=[0, 0, 0, 1]), \
                patch.object(runner.time, 'sleep') as sleep:
            runner.run(['certbot', 'renew'], self.cfg)
        self.assertEqual(events, [signal.SIGTERM, 'cleanup'])
        sleep.assert_called_once_with(0.05)

    def test_term_ignored_escalates_to_kill_and_unresolved_group_preserves_ledger(self):
        self.group.side_effect = [True, True, False]
        with patch.object(runner.os, 'killpg') as kill, \
                patch.object(runner.time, 'monotonic', side_effect=[0, 0, 0, 11, 12]):
            runner.run(['certbot', 'renew'], self.cfg)
        self.assertEqual(kill.call_args_list, [call(self.process.pid, signal.SIGTERM), call(self.process.pid, signal.SIGKILL)])
        self.cleanup.assert_called_once()
        self.cleanup.reset_mock()
        self.group.side_effect = None
        self.group.return_value = True
        with patch.object(runner.os, 'killpg'), patch.object(runner.time, 'monotonic', side_effect=[0, 0, 0, 11, 12, 23]):
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
