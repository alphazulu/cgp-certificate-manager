"""Offline CLI dispatch, explicit publication and fail-closed discovery."""
import contextlib
import fcntl
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cgp_cert_manager import cli, core, monitoring, monitoring_formats, storage


def snapshot():
    return {
        'schema': 1, 'generated_at': 1700000000.25, 'complete': True,
        'sources': {name: {'status': 'ok'} for name in monitoring_formats.SOURCES},
        'pending': {'transactions': 0, 'resolutions': 0, 'dns_challenges': 0},
        'domains': [{'domain': 'example.com', 'cert_name': 'example.com',
                     'enabled': True, 'in_inventory': True,
                     'local_certificate': {'status': 'missing'},
                     'last_success': None, 'failures': 3, 'retry_at': None}],
    }


class MonitoringCLITests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.config = self.root / 'private' / 'config.json'
        self.state = self.root / 'state'
        self.live = self.root / 'letsencrypt' / 'live'
        self.output = self.root / 'collector'
        self.output.mkdir(mode=0o755)
        self.target = self.output / 'cgp.prom'
        core.atomic(self.config, {'schema_version': 1, 'domains': [],
                                  'password': 'PRIVATE_CONFIG_VALUE'})
        core.atomic(self.state / 'domains.json', [])
        core.atomic(self.state / 'state.json', {})
        storage.atomic_text(self.state / 'run.lock', 'keep this lock content\n')
        for module, name, value in ((cli, 'CONFIG', self.config), (core, 'CONFIG', self.config),
                                    (cli, 'STATE', self.state), (core, 'STATE', self.state),
                                    (core, 'LIVE', self.live)):
            self.enterContext(patch.object(module, name, value))
        self.enterContext(patch.object(cli.os, 'umask'))
        self.out, self.err = io.StringIO(), io.StringIO()
        self.enterContext(contextlib.redirect_stdout(self.out))
        self.enterContext(contextlib.redirect_stderr(self.err))
        self.remember()
        self.forbidden = [self.enterContext(patch.object(module, name,
                          side_effect=AssertionError('Observation attempted a forbidden operation')))
                          for module, name in (
            (cli, 'load'), (cli, 'migrate'), (cli, 'atomic'), (cli, 'zones'), (cli, 'discover'),
            (storage, 'operation_lock'), (storage, 'ensure_private_directory'),
            (storage, 'atomic_text'), (storage, 'atomic_json'),
            (core, 'cli'), (core, 'cf'), (core, 'update'), (core.subprocess, 'run'),
            (cli, 'issue'), (cli, 'deploy'), (cli, 'notify'), (cli, 'history'),
            (cli.deployment, 'recover_pending'),
        )]
        self.addCleanup(self.assert_forbidden_not_called)

    def remember(self):
        self.state_names = set(self.state.iterdir()) if self.state.exists() else None
        paths = [self.config, *(self.state_names or [])]
        self.before = {}
        for path in paths:
            info = path.stat()
            self.before[path] = (path.read_bytes(), info.st_mode, info.st_uid,
                                 info.st_ino, info.st_mtime_ns)

    def assert_unchanged(self):
        self.assertEqual(set(self.state.iterdir()) if self.state.exists() else None, self.state_names)
        for path, expected in self.before.items():
            info = path.stat()
            self.assertEqual((path.read_bytes(), info.st_mode, info.st_uid,
                              info.st_ino, info.st_mtime_ns), expected)

    def assert_forbidden_not_called(self):
        for forbidden in self.forbidden:
            forbidden.assert_not_called()

    def invoke(self, *args):
        for stream in (self.out, self.err):
            stream.seek(0)
            stream.truncate()
        with patch.object(cli.sys, 'argv', ['cgp-letsencrypt', *args]):
            return cli.main()

    def test_monitoring_default_and_optional_json_preserve_unknown_measurements(self):
        data = snapshot()
        data['domains'][0]['in_inventory'] = None
        with patch.object(monitoring, 'collect', return_value=data) as collect:
            for args in (('--monitoring',), ('--monitoring', '--json')):
                self.assertEqual(self.invoke(*args), 0)
                self.assertEqual(json.loads(self.out.getvalue()), data)
                self.assertTrue(self.out.getvalue().endswith('\n'))
                self.assertEqual(self.err.getvalue(), '')
            self.assertEqual(collect.call_args.args, ())
        self.assert_unchanged()

    def test_metrics_stdout_contains_failure_representation_when_incomplete(self):
        data = snapshot()
        for complete in (True, False):
            data['complete'] = complete
            with self.subTest(complete=complete), patch.object(monitoring, 'collect', return_value=data):
                self.assertEqual(self.invoke('--metrics'), int(not complete))
                self.assertEqual(self.out.getvalue(), monitoring_formats.prometheus(data))
                self.assertIn('cgp_manager_collection_success ' + str(int(complete)) + '\n', self.out.getvalue())
                self.assertEqual(self.err.getvalue(), '')
        self.assert_unchanged()

    def test_complete_discovery_is_json_array_with_optional_json_flag(self):
        data = snapshot()
        expected = [{'{#CGP_DOMAIN}': 'example.com', '{#CGP_CERT_NAME}': 'example.com',
                     '{#CGP_ENABLED}': 1}]
        with patch.object(monitoring, 'collect', return_value=data):
            for args in (('--zabbix-discovery',), ('--zabbix-discovery', '--json')):
                self.assertEqual(self.invoke(*args), 0)
                self.assertEqual(json.loads(self.out.getvalue()), expected)
                self.assertEqual(self.err.getvalue(), '')
            data['domains'] = []
            self.assertEqual(self.invoke('--zabbix-discovery'), 0)
            self.assertEqual(json.loads(self.out.getvalue()), [])
        self.assert_unchanged()

    def test_incomplete_discovery_never_emits_empty_or_partial_json(self):
        data = snapshot()
        data['complete'] = False
        with patch.object(monitoring, 'collect', return_value=data), \
                patch.object(monitoring_formats, 'zabbix_discovery') as discovery:
            for domains in (data['domains'], []):
                data['domains'] = domains
                self.assertEqual(self.invoke('--zabbix-discovery', '--json'), 1)
                self.assertEqual(self.out.getvalue(), '')
                self.assertEqual(self.err.getvalue(),
                                 'Monitoring snapshot incomplete; Zabbix discovery not emitted\n')
            discovery.assert_not_called()
        self.assert_unchanged()

    def test_collection_rendering_and_json_errors_are_fixed_and_not_partial(self):
        data = snapshot()
        cases = (('--monitoring', monitoring, 'collect'),
                 ('--monitoring', cli.json, 'dumps'),
                 ('--metrics', monitoring_formats, 'prometheus'),
                 ('--zabbix-discovery', monitoring_formats, 'zabbix_discovery'))
        for action, module, name in cases:
            with self.subTest(action=action, failure=name), \
                    patch.object(monitoring, 'collect', return_value=data), \
                    patch.object(module, name, side_effect=core.Error('PRIVATE_FAILURE_DETAILS')):
                self.assertEqual(self.invoke(action), 1)
                self.assertEqual(self.out.getvalue(), '')
                self.assertEqual(self.err.getvalue(), 'Monitoring observation failed\n')
        data['generated_at'] = float('nan')
        with patch.object(monitoring, 'collect', return_value=data):
            self.assertEqual(self.invoke('--monitoring'), 1)
            self.assertEqual(self.out.getvalue(), '')
            self.assertEqual(self.err.getvalue(), 'Monitoring observation failed\n')
        self.assert_unchanged()

    def test_mutation_modifiers_and_domain_fail_before_collection(self):
        modifiers = [('--force-renew',), ('--retry-now',), ('--allow-shrink',),
                     ('--backup-file', ''), ('--confirm-transaction', 'a' * 64),
                     ('--reason', 'PRIVATE_REASON')]
        modifiers += [('--domain', value) for value in ('example.com', '', '../invalid', 'bad\nname')]
        with patch.object(monitoring, 'collect') as collect:
            for action in ('--monitoring', '--metrics', '--zabbix-discovery'):
                for extra in modifiers:
                    with self.subTest(action=action, extra=extra), self.assertRaises(SystemExit) as caught:
                        self.invoke(action, *extra)
                    self.assertEqual(caught.exception.code, 2)
                    self.assertEqual(self.out.getvalue(), '')
            collect.assert_not_called()
        self.assert_unchanged()

    def test_format_file_and_conflicting_action_errors_precede_collection(self):
        cases = (('--metrics', '--json'),
                 ('--metrics-file', str(self.target)),
                 ('--monitoring', '--metrics-file', str(self.target)),
                 ('--zabbix-discovery', '--metrics-file', str(self.target)),
                 ('--monitoring', '--metrics'), ('--metrics', '--zabbix-discovery'),
                 ('--zabbix-discovery', '--monitoring'), ('--monitoring', '--recover'),
                 ('--metrics', '--dry-run'), ('--zabbix-discovery', '--dns-cleanup'))
        with patch.object(monitoring, 'collect') as collect:
            for args in cases:
                with self.subTest(args=args), self.assertRaises(SystemExit) as caught:
                    self.invoke(*args)
                self.assertEqual(caught.exception.code, 2)
                self.assertEqual(self.out.getvalue(), '')
            collect.assert_not_called()
        self.assertFalse(self.target.exists())
        self.assert_unchanged()

    def test_explicit_file_mode_publishes_complete_and_failure_metrics_without_stdout(self):
        data = snapshot()
        for complete in (True, False):
            data['complete'] = complete
            with self.subTest(complete=complete), patch.object(monitoring, 'collect', return_value=data):
                self.assertEqual(self.invoke('--metrics', '--metrics-file', str(self.target)), int(not complete))
                self.assertEqual(self.target.read_text(), monitoring_formats.prometheus(data))
                self.assertEqual(self.target.stat().st_mode & 0o7777, 0o644)
                self.assertEqual(self.out.getvalue(), '')
                self.assertEqual(self.err.getvalue(), '')
        self.assert_unchanged()

    def test_rendering_failure_does_not_replace_previous_metrics_file(self):
        self.target.write_text('previous healthy metrics\n')
        self.target.chmod(0o644)
        data = snapshot()
        data['generated_at'] = float('inf')
        with patch.object(monitoring, 'collect', return_value=data):
            self.assertEqual(self.invoke('--metrics', '--metrics-file', str(self.target)), 1)
        self.assertEqual(self.target.read_text(), 'previous healthy metrics\n')
        self.assertEqual(self.out.getvalue(), '')
        self.assertEqual(self.err.getvalue(), 'Monitoring observation failed\n')
        self.assert_unchanged()

    def test_publication_failure_is_sanitized_and_retains_private_existing_file(self):
        self.target.write_text('PRIVATE_EXISTING_FILE\n')
        self.target.chmod(0o600)
        with patch.object(monitoring, 'collect', return_value=snapshot()):
            self.assertEqual(self.invoke('--metrics', '--metrics-file', str(self.target)), 1)
        self.assertEqual(self.target.read_text(), 'PRIVATE_EXISTING_FILE\n')
        self.assertEqual(self.target.stat().st_mode & 0o7777, 0o600)
        self.assertEqual(self.out.getvalue(), '')
        self.assertEqual(self.err.getvalue(), 'Monitoring observation failed\n')
        self.assert_unchanged()

    def test_real_empty_snapshot_and_missing_state_are_observed_without_creation(self):
        with patch.object(storage.os, 'fsync') as sync:
            self.assertEqual(self.invoke('--monitoring'), 0)
            data = json.loads(self.out.getvalue())
            self.assertTrue(data['complete'])
            self.assertEqual(data['domains'], [])
            self.assertNotIn('PRIVATE_CONFIG_VALUE', self.out.getvalue())
            self.assertEqual(self.invoke('--zabbix-discovery'), 0)
            self.assertEqual(json.loads(self.out.getvalue()), [])
            self.assert_unchanged()
            for path in self.state.iterdir():
                path.unlink()
            self.state.rmdir()
            self.remember()
            self.assertEqual(self.invoke('--monitoring'), 1)
            data = json.loads(self.out.getvalue())
            self.assertFalse(data['complete'])
            self.assertEqual(data['sources']['lock']['status'], 'missing')
            self.assertEqual(self.invoke('--metrics'), 1)
            self.assertIn('cgp_manager_collection_success 0\n', self.out.getvalue())
            self.assertEqual(self.invoke('--zabbix-discovery'), 1)
            self.assertEqual(self.out.getvalue(), '')
            sync.assert_not_called()
        self.assert_unchanged()

    def test_real_exclusive_lock_returns_busy_without_repair_or_recovery(self):
        with storage.open_private(self.state / 'run.lock') as held:
            fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.invoke('--monitoring'), 1)
            data = json.loads(self.out.getvalue())
            self.assertEqual(data['sources']['lock']['status'], 'busy')
            self.assertFalse(data['complete'])
            self.assertEqual(self.invoke('--zabbix-discovery'), 1)
            self.assertEqual(self.out.getvalue(), '')
        self.assert_unchanged()

    def test_real_unsafe_configuration_is_reported_without_secret_or_path(self):
        self.config.chmod(0o644)
        self.remember()
        self.assertEqual(self.invoke('--monitoring'), 1)
        data = json.loads(self.out.getvalue())
        self.assertEqual(data['sources']['config']['status'], 'error')
        self.assertNotIn('PRIVATE_CONFIG_VALUE', self.out.getvalue())
        self.assertNotIn(str(self.config), self.out.getvalue())
        self.assertEqual(self.err.getvalue(), '')
        self.assert_unchanged()
