"""Independent monitor CLI routing, passive diagnostics and safe public output."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import runpy
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch
import warnings

from cgp_cert_manager import (__version__, core, monitor_cli as cli, monitor_config as config,
                              monitor_runner as runner, monitor_worker, notify_transport,
                              storage, tlsprobe)


def endpoint(**changes):
    return dict({'id': 'https', 'host': 'mail.example.test', 'port': 443,
                 'server_name': 'mail.example.test'}, **changes)


def observation():
    common = {'host': 'mail.example.test', 'server_name': 'mail.example.test'}
    return {'schema': 1, 'generated_at': 1000.0, 'completed_at': 1002.0,
            'warning_days': 21, 'critical_days': 7, 'complete': True, 'status': 'critical',
            'endpoints': [
                {'id': 'https', **common, 'port': 443, 'protocol': 'tls', 'status': 'warning',
                 'code': None, 'verified': True, 'checked_at': 1001.0,
                 'not_after': 1001.0 + 20.25 * 86400, 'fingerprint_sha256': 'a' * 64,
                 'peer_address': '203.0.113.1', 'tls_version': 'TLSv1.3', 'days_remaining': 20.25},
                {'id': 'smtp', **common, 'port': 587, 'protocol': 'smtp_starttls', 'status': 'critical',
                 'code': 'tls_hostname_mismatch', 'verified': False, 'checked_at': 1002.0,
                 'not_after': None, 'fingerprint_sha256': None, 'peer_address': None,
                 'tls_version': None, 'days_remaining': None},
            ]}


class MonitorCLITests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.private = self.root / 'private'
        self.private.mkdir(mode=0o700)
        self.path = self.private / 'config.json'
        self.state = self.root / 'monitor-state'
        self.raw = {'schema': 1, 'enabled': False, 'endpoints': []}
        self.save()
        self.enterContext(patch.object(config, 'CONFIG', self.path))
        self.enterContext(patch.object(config, 'STATE', self.state))
        self.out, self.err = io.StringIO(), io.StringIO()
        self.enterContext(redirect_stdout(self.out))
        self.enterContext(redirect_stderr(self.err))
        self.forbidden = [self.enterContext(patch.object(module, name,
                          side_effect=AssertionError('CLI crossed its tested action boundary')))
                          for module, name in (
            (socket, 'socket'), (socket, 'getaddrinfo'), (socket, 'create_connection'),
            (tlsprobe, 'observe'), (notify_transport, 'deliver'), (monitor_worker, 'execute'),
            (storage, 'operation_lock'), (storage, 'ensure_private_directory'),
            (storage, 'atomic_json'), (storage, 'atomic_text'),
            (core, 'cli'), (core, 'cf'), (core, 'issue'), (core, 'update'),
        )]
        self.addCleanup(self.assert_boundaries)

    def save(self):
        self.path.write_text(json.dumps(self.raw), encoding='utf-8')
        self.path.chmod(0o600)

    def enable(self):
        self.raw.update(enabled=True, endpoints=[endpoint()])
        self.save()

    def assert_boundaries(self):
        for call in self.forbidden:
            call.assert_not_called()
        self.assertFalse(self.state.exists(), 'CLI created a state directory during a passive/mocked action')

    def invoke(self, *args):
        for stream in (self.out, self.err):
            stream.seek(0)
            stream.truncate()
        try:
            return cli.main(list(args))
        except SystemExit as exited:
            return exited.code

    def public_json(self):
        self.assertEqual(self.err.getvalue(), '')
        self.assertTrue(self.out.getvalue().endswith('\n'))
        for private in ('PRIVATE_CLI_SECRET', str(self.private), 'password_file', 'token_file'):
            self.assertNotIn(private, self.out.getvalue())
        return json.loads(self.out.getvalue())

    def test_help_and_version_require_neither_configuration_nor_state(self):
        self.path.unlink()
        with patch.object(config, 'load') as load:
            for action in ('--help', '--version'):
                self.assertEqual(self.invoke(action), 0)
                self.assertEqual(self.err.getvalue(), '')
                self.assertIn(__version__ if action == '--version' else '--send', self.out.getvalue())
            load.assert_not_called()

    def test_no_default_action_and_incompatible_modifiers_refuse_before_loading(self):
        bad = ((), ('--send',), ('--json',), ('--run', '--status'),
               ('--check-config', '--send'), ('--probe', '--send'), ('--status', '--send'),
               ('--check-config', '--endpoint', 'https'), ('--status', '--endpoint', 'https'),
               ('--run', '--endpoint', 'https'), ('--probe', '--endpoint'),
               ('--probe', '--config', 'relative.json'),
               ('--probe', '--config', '/tmp/../private/config.json'))
        with patch.object(config, 'load') as load, patch.object(runner, 'run') as run, \
                patch.object(runner, 'probe') as probe, patch.object(runner, 'status') as status:
            for args in bad:
                with self.subTest(args=args):
                    self.assertEqual(self.invoke(*args), 2)
                    self.assertEqual(self.out.getvalue(), '')
                    self.assertIn('error:', self.err.getvalue())
            for call in (load, run, probe, status):
                call.assert_not_called()

    def test_invalid_endpoint_identifier_refuses_before_configuration_read(self):
        with patch.object(config, 'load') as load:
            self.assertEqual(self.invoke('--probe', '--endpoint', 'PRIVATE_CLI_SECRET!', '--json'), 2)
            load.assert_not_called()
        self.assertEqual(self.public_json()['error'], 'invalid_identifier')

    def test_real_check_config_summary_excludes_credentials_and_identity(self):
        self.enable()
        credential = self.private / 'token'
        credential.write_text('PRIVATE_CLI_SECRET', encoding='ascii')
        credential.chmod(0o600)
        self.raw['notifications'] = {'enabled': True, 'channels': [
            {'id': 'ops', 'kind': 'webhook', 'url': 'https://hooks.example.test/notify',
             'token_file': str(credential)}]}
        self.save()
        before = {path: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
                  for path in (self.path, credential)}
        with patch.object(runner, 'run') as run, patch.object(runner, 'probe') as probe:
            self.assertEqual(self.invoke('--check-config', '--json'), 0)
            self.assertEqual(self.public_json(), {'schema': 1, 'action': 'check-config', 'status': 'valid',
                             'enabled': True, 'endpoints': 1, 'channels': 1, 'notifications_enabled': True})
            self.assertEqual(self.invoke('--check-config'), 0)
            text = self.out.getvalue()
            self.assertIn('CGP monitor: valid', text)
            self.assertIn('Enabled: true', text)
            self.assertIn('Configured endpoints: 1', text)
            self.assertIn('Configured notification channels: 1', text)
            self.assertIn('Notification policy enabled: true', text)
            self.assertNotIn('PRIVATE_CLI_SECRET', text)
            self.assertNotIn(str(credential), text)
            run.assert_not_called()
            probe.assert_not_called()
        for path, expected in before.items():
            self.assertEqual((path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns), expected)

    def test_real_disabled_actions_are_passive_even_when_send_is_explicit(self):
        before = self.path.read_bytes(), self.path.stat().st_ino, self.path.stat().st_mtime_ns
        for args in (('--status',), ('--probe',), ('--run',), ('--run', '--send')):
            with self.subTest(args=args):
                self.assertEqual(self.invoke(*args, '--json'), 0)
                result = self.public_json()
                self.assertEqual(result['status'], 'disabled')
                self.assertIsNone(result['observation'])
                self.assertEqual(result['delivery'], [])
        self.assertEqual((self.path.read_bytes(), self.path.stat().st_ino, self.path.stat().st_mtime_ns), before)

    def test_real_status_missing_state_does_not_create_or_probe(self):
        self.enable()
        self.assertEqual(self.invoke('--status', '--json'), 2)
        self.assertEqual(self.public_json()['status'], 'missing')

    def test_installed_custom_state_run_refuses_safely_but_status_remains_read_only(self):
        self.enable()
        custom = self.root / 'custom-observer'
        installed = '/opt/cgp-certificate-manager/cgp_cert_manager/monitor_runner.py'
        before = self.path.read_bytes()
        with patch.object(runner, '__file__', installed):
            self.assertEqual(self.invoke('--run', '--send', '--state-dir', str(custom), '--json'), 2)
            result = self.public_json()
            self.assertEqual(result['status'], 'error')
            self.assertEqual(result['error'], 'installed_state_override')
            self.assertEqual(self.invoke('--status', '--state-dir', str(custom), '--json'), 2)
            self.assertEqual(self.public_json()['status'], 'missing')
        self.assertEqual(self.path.read_bytes(), before)
        self.assertFalse(custom.exists())

    def test_real_endpoint_and_protected_state_refusals_precede_network_and_writes(self):
        self.enable()
        self.raw['endpoints'].append(endpoint(id='off', enabled=False))
        self.save()
        for name, expected in (('missing', 'unknown_endpoint'), ('off', 'endpoint_disabled')):
            self.assertEqual(self.invoke('--probe', '--endpoint', name, '--json'), 2)
            self.assertEqual(self.public_json()['error'], expected)
        for path, expected in (('relative-state', 'invalid_state_path'),
                               (str(core.STATE), 'protected_state_path')):
            for action in ('--run', '--status'):
                self.assertEqual(self.invoke(action, '--state-dir', path, '--json'), 2)
                self.assertEqual(self.public_json()['error'], expected)

    def test_run_routes_normalized_configuration_and_send_only_when_requested(self):
        self.enable()
        normalized = config.load(self.path)
        for send in (False, True):
            args = ('--run', '--send') if send else ('--run',)
            with patch.object(runner, 'run', return_value=runner._result('run', 'ok')) as run:
                self.assertEqual(self.invoke(*args, '--config', str(self.path),
                                             '--state-dir', str(self.state), '--json'), 0)
                run.assert_called_once_with(normalized, self.state, send, self.path)
                self.assertEqual(self.public_json()['action'], 'run')

    def test_probe_routes_optional_selection_without_persistent_state_argument(self):
        self.enable()
        normalized = config.load(self.path)
        for selected in (None, 'https'):
            args = () if selected is None else ('--endpoint', selected)
            with patch.object(runner, 'probe', return_value=runner._result('probe', 'ok')) as probe:
                self.assertEqual(self.invoke('--probe', *args, '--json'), 0)
                probe.assert_called_once_with(normalized, selected)
                self.assertEqual(self.public_json()['action'], 'probe')

    def test_saved_status_routes_custom_path_and_distinguishes_all_exit_classes(self):
        self.enable()
        normalized = config.load(self.path)
        selected = self.root / 'selected-state'
        for state, expected in (('ok', 0), ('disabled', 0), ('warning', 1), ('critical', 1),
                                ('missing', 2), ('busy', 2), ('invalid', 2), ('stale', 2),
                                ('future', 2), ('configuration_changed', 2), ('delivery_failed', 2)):
            with self.subTest(state=state), \
                    patch.object(runner, 'status', return_value=runner._result('status', state)) as status:
                self.assertEqual(self.invoke('--status', '--state-dir', str(selected), '--json'), expected)
                status.assert_called_once_with(normalized, selected)
                self.assertEqual(self.public_json()['status'], state)
        self.assertFalse(selected.exists())

    def test_missing_invalid_and_unsafe_real_configuration_have_sanitized_errors(self):
        self.path.unlink()
        self.assertEqual(self.invoke('--check-config', '--json'), 2)
        self.assertEqual(self.public_json()['error'], 'configuration_missing')
        for data in (b'{"PRIVATE_CLI_SECRET":', b'{"schema":1,"schema":1}', b'\xff'):
            self.path.write_bytes(data)
            self.path.chmod(0o600)
            self.assertEqual(self.invoke('--check-config', '--json'), 2)
            self.assertEqual(self.public_json()['error'], 'configuration_invalid')
        self.save()
        self.path.chmod(0o644)
        self.assertEqual(self.invoke('--check-config', '--json'), 2)
        self.assertEqual(self.public_json()['error'], 'configuration_invalid')
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o644)

    def test_external_exception_text_is_not_exposed_at_either_phase(self):
        with patch.object(config, 'load', side_effect=RuntimeError('PRIVATE_CLI_SECRET')):
            self.assertEqual(self.invoke('--check-config', '--json'), 2)
            self.assertEqual(self.public_json()['error'], 'configuration_invalid')
        for error, expected in ((RuntimeError('PRIVATE_CLI_SECRET'), 'operation_failed'),
                                (FileNotFoundError('PRIVATE_CLI_SECRET'), 'operation_failed'),
                                (BlockingIOError('PRIVATE_CLI_SECRET'), 'busy'),
                                (runner.MonitorError('configuration_changed'), 'configuration_changed'),
                                (ValueError('clock_moved_backwards'), 'clock_moved_backwards')):
            with self.subTest(error=type(error).__name__), patch.object(runner, 'status', side_effect=error):
                self.assertEqual(self.invoke('--status', '--json'), 2)
                self.assertEqual(self.public_json()['error'], expected)
        with patch.object(runner, 'status', side_effect=RuntimeError('PRIVATE_CLI_SECRET')):
            self.assertEqual(self.invoke('--status'), 2)
            self.assertIn('Reason: operation_failed', self.out.getvalue())
            self.assertNotIn('PRIVATE_CLI_SECRET', self.out.getvalue() + self.err.getvalue())

    def test_json_and_text_preserve_expiry_tls_failure_and_delivery_results(self):
        result = runner._result('run', 'delivery_failed', observation(), [
            {'id': 'ops', 'outcome': 'accepted', 'code': None, 'event_id': 'b' * 32},
            {'id': 'hook', 'outcome': 'uncertain', 'code': 'webhook_submission_uncertain', 'event_id': 'c' * 32}])
        with patch.object(runner, 'run', return_value=result):
            self.assertEqual(self.invoke('--run', '--send', '--json'), 2)
            self.assertEqual(self.public_json(), result)
            self.assertEqual(self.invoke('--run', '--send'), 2)
        text = self.out.getvalue()
        self.assertIn('https: warning (20.25 days remaining)', text)
        self.assertIn('smtp: critical (tls_hostname_mismatch)', text)
        self.assertIn('Notification ops: accepted', text)
        self.assertIn('Notification hook: uncertain', text)
        self.assertEqual(self.err.getvalue(), '')

    def test_keyboard_interrupt_returns_130_with_safe_json_or_text(self):
        for flags in ((), ('--json',)):
            with patch.object(runner, 'run', side_effect=KeyboardInterrupt('PRIVATE_CLI_SECRET')):
                self.assertEqual(self.invoke('--run', *flags), 130)
                if flags:
                    self.assertEqual(self.public_json()['error'], 'interrupted')
                else:
                    self.assertIn('Reason: interrupted', self.out.getvalue())
                    self.assertNotIn('PRIVATE_CLI_SECRET', self.out.getvalue())

    def test_module_entrypoint_uses_the_same_public_exit_status(self):
        with patch.object(sys, 'argv', ['cgp-monitor', '--status', '--json']), warnings.catch_warnings():
            warnings.filterwarnings('ignore', category=RuntimeWarning, message='.*monitor_cli.*found in sys.modules.*')
            with self.assertRaises(SystemExit) as exited:
                runpy.run_module('cgp_cert_manager.monitor_cli', run_name='__main__')
        self.assertEqual(exited.exception.code, 0)
        self.assertEqual(self.public_json()['status'], 'disabled')
