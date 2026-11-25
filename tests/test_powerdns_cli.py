"""Passive PowerDNS observation routing and unsupported issuance boundaries."""
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import socket
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cgp_cert_manager import (cli, core, dnsauth, dnsconfig, dnsproviders,
                              powerdns, storage, update_gate)


def observation(complete=True):
    result = {'schema': 1, 'provider': 'powerdns', 'mode': 'read_only',
              'complete': complete, 'issuance_supported': False,
              'zones': [{'zone': 'example.com', 'binding': 'a' * 64,
                         'status': 'observed', 'reason': 'api_identity_observed',
                         'server_version': '5.0.2', 'zone_kind': 'Native'}]}
    if not complete:
        result['zones'].append({'zone': 'example.net', 'binding': 'b' * 64,
                                'status': 'error', 'reason': 'api_request_failed',
                                'server_version': None, 'zone_kind': None})
    return result


class PowerDNSCLITests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.state = self.root / 'state'
        self.config = self.root / 'config.json'
        self.secret = self.root / 'api-key.json'
        self.updates = self.root / 'update-state'
        self.cfg = {'powerdns': {'zones': [{
            'zone': 'example.com', 'endpoint': 'https://dns-api.example.com',
            'server_id': 'localhost', 'zone_id': 'example.com.',
            'credentials': str(self.secret), 'nameservers': ['ns1.example.com']}]}}
        self.secret.write_text('{"api_key":"PRIVATE_POWERDNS_API_KEY"}')
        self.secret.chmod(0o600)
        self.save()
        self.secret_before = self.witness(self.secret)
        self.enterContext(patch.object(cli, 'CONFIG', self.config))
        self.enterContext(patch.object(cli, 'STATE', self.state))
        self.enterContext(patch.object(core, 'STATE', self.state))
        self.enterContext(patch.object(update_gate, 'STATE_DIR', self.updates))
        self.enterContext(patch.object(cli.os, 'umask'))
        self.out, self.err = io.StringIO(), io.StringIO()
        self.enterContext(redirect_stdout(self.out))
        self.enterContext(redirect_stderr(self.err))
        self.forbidden = [self.enterContext(patch.object(module, name,
                          side_effect=AssertionError('PowerDNS check crossed its read-only boundary')))
                          for module, name in (
            (storage, 'operation_lock'), (storage, 'ensure_private_directory'),
            (storage, 'atomic_json'), (storage, 'atomic_text'), (storage, 'validate_tree'),
            (cli, 'migrate'), (cli, 'atomic'), (cli, 'notify'), (cli, 'history'),
            (cli, 'issue'), (cli, 'deploy'), (cli, 'current'), (cli, 'locked_main'),
            (cli, 'zones'), (cli, 'discover'), (core, 'cli'), (core, 'cf'), (core, 'update'),
            (cli.deployment, 'recover_pending'), (cli.bootstrap, 'inspect'),
            (core.subprocess, 'run'), (socket, 'socket'), (socket, 'getaddrinfo'),
            (socket, 'create_connection'),
        )]
        self.addCleanup(self.assert_read_only)

    @staticmethod
    def witness(path):
        info = path.stat()
        return path.read_bytes(), info.st_ino, info.st_mtime_ns, info.st_mode

    def save(self):
        self.config.write_text(json.dumps(self.cfg))
        self.config.chmod(0o600)
        self.before = self.witness(self.config)

    def invoke(self, *args, action='--powerdns-check'):
        for stream in (self.out, self.err):
            stream.seek(0)
            stream.truncate()
        with patch.object(cli.sys, 'argv', ['cgp-letsencrypt', action, *args]):
            return cli.main()

    def assert_read_only(self):
        for operation in self.forbidden:
            operation.assert_not_called()
        self.assertFalse(self.state.exists())
        if self.before is None:
            self.assertFalse(self.config.exists())
        else:
            self.assertEqual(self.witness(self.config), self.before)
        self.assertEqual(self.witness(self.secret), self.secret_before)

    def public_report(self):
        self.assertEqual(self.err.getvalue(), '')
        self.assertTrue(self.out.getvalue().endswith('\n'))
        for private in ('PRIVATE_POWERDNS_API_KEY', str(self.secret), 'credentials',
                        'dns-api.example.com', 'api_key'):
            self.assertNotIn(private, self.out.getvalue())
        return json.loads(self.out.getvalue())

    def test_json_report_reads_minimal_configuration_without_migration(self):
        report = observation()
        with patch.object(powerdns, 'check', return_value=report) as check:
            self.assertEqual(self.invoke('--json'), 0)
        check.assert_called_once_with(self.cfg)
        self.assertEqual(self.public_report(), report)
        self.assertFalse(self.public_report()['issuance_supported'])

    def test_text_describes_observation_and_unavailable_issuance(self):
        for complete in (True, False):
            with self.subTest(complete=complete), patch.object(powerdns, 'check', return_value=observation(complete)):
                self.assertEqual(self.invoke(), int(not complete))
                expected = 'example.com: API identity observed; reason=api_identity_observed\n'
                if not complete:
                    expected += 'example.net: API identity error; reason=api_request_failed\n'
                expected += 'Managed TXT issuance: unavailable\n'
                self.assertEqual(self.out.getvalue(), expected)
                self.assertEqual(self.err.getvalue(), '')
                self.assertNotIn('ready', self.out.getvalue().lower())

    def test_partial_json_preserves_every_observation_and_returns_failure(self):
        report = observation(False)
        with patch.object(powerdns, 'check', return_value=report):
            self.assertEqual(self.invoke('--json'), 1)
        self.assertEqual(self.public_report(), report)

    def test_mutation_options_and_domain_refuse_before_configuration_or_guard(self):
        cases = [('--domain', value) for value in ('example.com', '', '../bad')]
        cases += [(flag,) for flag in ('--force-renew', '--retry-now', '--allow-shrink')]
        cases += [(flag, value) for flag in ('--backup-file', '--confirm-transaction', '--reason')
                  for value in ('PRIVATE_OPTION_VALUE', '')]
        cases += [('--metrics-file', 'PRIVATE_METRICS_PATH')]
        with patch.object(cli, 'load') as load, patch.object(powerdns, 'check') as check, \
                patch.object(update_gate, 'require_idle') as guard:
            for args in cases:
                with self.subTest(args=args), self.assertRaises(SystemExit) as exited:
                    self.invoke(*args)
                self.assertEqual(exited.exception.code, 2)
                self.assertEqual(self.out.getvalue(), '')
                self.assertIn('error:', self.err.getvalue())
            for operation in (load, check, guard):
                operation.assert_not_called()

    def test_other_actions_are_mutually_exclusive_before_any_read(self):
        flags = ('--sync', '--list', '--show-domains', '--status', '--plan', '--verify',
                 '--doctor', '--dry-run', '--install-only', '--history', '--hook-auth',
                 '--hook-cleanup', '--reset-backoff', '--discover-listeners',
                 '--verify-listeners', '--repair-chain', '--tui', '--apply-schedule',
                 '--console', '--transactions', '--recover', '--acknowledge-restored',
                 '--bootstrap-check', '--dns-check', '--dns-transactions', '--dns-cleanup',
                 '--monitoring', '--metrics', '--zabbix-discovery', '--migrate')
        cases = [(flag,) for flag in flags] + [('--backups', 'example.com'), ('--rollback', 'example.com')]
        with patch.object(cli, 'load') as load, patch.object(powerdns, 'check') as check:
            for args in cases:
                with self.subTest(args=args), self.assertRaises(SystemExit) as exited:
                    self.invoke(*args)
                self.assertEqual(exited.exception.code, 2)
                self.assertEqual(self.out.getvalue(), '')
            load.assert_not_called()
            check.assert_not_called()

    def test_configuration_read_errors_are_fixed_and_do_not_reveal_contents(self):
        with patch.object(powerdns, 'check') as check:
            for fault in ('invalid_json', 'unsafe', 'missing'):
                with self.subTest(fault=fault):
                    self.save()
                    if fault == 'invalid_json':
                        self.config.write_text('{"PRIVATE_CONFIGURATION_CONTENT":')
                    elif fault == 'unsafe':
                        self.config.chmod(0o644)
                    else:
                        self.config.unlink()
                    self.before = self.witness(self.config) if self.config.exists() else None
                    self.assertEqual(self.invoke('--json'), 1)
                    self.assertEqual(self.out.getvalue(), '')
                    self.assertEqual(self.err.getvalue(), 'PowerDNS observation failed\n')
            check.assert_not_called()

    def test_invalid_powerdns_configuration_refuses_before_api_access(self):
        self.cfg['powerdns']['zones'] = []
        self.save()
        with patch.object(powerdns, '_get') as get:
            self.assertEqual(self.invoke(), 1)
        get.assert_not_called()
        self.assertEqual(self.out.getvalue(), '')
        self.assertEqual(self.err.getvalue(), 'PowerDNS observation failed\n')

    def test_unexpected_observer_exception_is_secret_safe(self):
        with patch.object(powerdns, 'check', side_effect=OSError('PRIVATE_POWERDNS_API_KEY ' + str(self.secret))):
            self.assertEqual(self.invoke(), 1)
        self.assertEqual(self.out.getvalue(), '')
        self.assertEqual(self.err.getvalue(), 'PowerDNS observation failed\n')

    def test_pending_update_guard_precedes_configuration_and_observation(self):
        self.updates.mkdir(mode=0o700)
        (self.updates / 'pending.json').write_text('PRIVATE_UPDATE_MARKER')
        with patch.object(cli, 'load') as load, patch.object(powerdns, 'check') as check:
            with self.assertRaises(update_gate.PendingUpdateError) as caught:
                self.invoke('--json')
            self.assertEqual(caught.exception.code, 'update_pending')
            load.assert_not_called()
            check.assert_not_called()
        self.assertEqual(self.out.getvalue(), '')
        self.assertEqual(self.err.getvalue(), '')

    def test_help_advertises_check_without_configuration_or_observation(self):
        with patch.object(cli, 'load') as load, patch.object(powerdns, 'check') as check:
            with self.assertRaises(SystemExit) as exited:
                self.invoke(action='--help')
            self.assertEqual(exited.exception.code, 0)
            self.assertIn('--powerdns-check', self.out.getvalue())
            load.assert_not_called()
            check.assert_not_called()

    def test_broken_manager_state_is_neither_read_nor_repaired(self):
        self.state.symlink_to(self.root / 'missing-state')
        with patch.object(powerdns, 'check', return_value=observation()):
            self.assertEqual(self.invoke('--json'), 0)
        self.assertTrue(self.state.is_symlink())
        self.assertEqual(self.public_report(), observation())

    def test_real_credential_failure_is_a_public_error_report_without_api_call(self):
        self.secret.chmod(0o644)
        self.secret_before = self.witness(self.secret)
        with patch.object(powerdns, '_get') as get:
            self.assertEqual(self.invoke('--json'), 1)
        get.assert_not_called()
        report = self.public_report()
        self.assertFalse(report['complete'])
        self.assertFalse(report['issuance_supported'])
        self.assertEqual(report['zones'][0]['status'], 'error')
        self.assertEqual(report['zones'][0]['reason'], 'credential_unavailable')
        self.assertIsNone(report['zones'][0]['server_version'])
        self.assertIsNone(report['zones'][0]['zone_kind'])

    def test_real_observation_routes_protected_configuration_and_key_to_exact_targets(self):
        server = {'type': 'Server', 'id': 'localhost', 'daemon_type': 'authoritative', 'version': '5.0.8'}
        zone = {'id': 'example.com.', 'name': 'example.com.', 'kind': 'Native'}
        with patch.object(powerdns, '_get', side_effect=[server, zone]) as get:
            self.assertEqual(self.invoke('--json'), 0)
        report = self.public_report()
        self.assertEqual({key: value for key, value in report.items() if key != 'zones'},
                         {'schema': 1, 'provider': 'powerdns', 'mode': 'read_only',
                          'complete': True, 'issuance_supported': False})
        row = report['zones'][0]
        self.assertEqual({key: value for key, value in row.items() if key != 'binding'},
                         {'zone': 'example.com', 'status': 'observed', 'reason': 'api_identity_observed',
                          'server_version': '5.0.8', 'zone_kind': 'Native'})
        self.assertRegex(row['binding'], r'^[0-9a-f]{64}$')
        self.assertEqual([call.args[2] for call in get.call_args_list],
                         ['/api/v1/servers/localhost',
                          '/api/v1/servers/localhost/zones/example.com.?rrsets=false'])
        for call in get.call_args_list:
            self.assertEqual(call.args[0]['binding'], row['binding'])
            self.assertEqual(call.args[0]['endpoint'], 'https://dns-api.example.com')
            self.assertEqual(call.args[1], 'PRIVATE_POWERDNS_API_KEY')

    def test_real_transport_failure_returns_a_complete_public_error_shape(self):
        with patch.object(powerdns.http.client, 'HTTPSConnection') as connection:
            connection.return_value.request.side_effect = OSError('PRIVATE_POWERDNS_API_KEY from server')
            self.assertEqual(self.invoke('--json'), 1)
        connection.return_value.request.assert_called_once()
        connection.return_value.getresponse.assert_not_called()
        connection.return_value.close.assert_called_once()
        report = self.public_report()
        self.assertFalse(report['complete'])
        self.assertFalse(report['issuance_supported'])
        row = report['zones'][0]
        self.assertEqual(row['status'], 'error')
        self.assertEqual(row['reason'], 'api_request_failed')
        self.assertIsNone(row['server_version'])
        self.assertIsNone(row['zone_kind'])


class PowerDNSIssuanceBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.state = self.root / 'state'
        self.cfg = {'schema_version': 2, 'dns_provider': 'powerdns', 'powerdns': {'zones': []}}
        self.enterContext(patch.object(core, 'STATE', self.state))
        self.enterContext(patch.object(cli, 'STATE', self.state))
        self.enterContext(patch.object(update_gate, 'STATE_DIR', self.root / 'updates'))
        self.enterContext(patch.object(cli.os, 'umask'))
        self.forbidden = [self.enterContext(patch.object(module, name,
                          side_effect=AssertionError('Unsupported issuer crossed a capability boundary')))
                          for module, name in (
            (storage, 'open_private'), (storage, 'check_private_file'),
            (storage, 'ensure_private_directory'), (storage, 'atomic_json'),
            (core, 'token'), (core, 'cf'), (core, 'cli'), (core, 'dns_preflight'),
            (core, 'local_info'), (core.subprocess, 'run'), (powerdns, 'check'),
            (powerdns, '_get'), (socket, 'socket'),
        )]
        self.addCleanup(self.assert_boundaries)

    def assert_boundaries(self):
        for operation in self.forbidden:
            operation.assert_not_called()
        self.assertFalse(self.state.exists())

    def test_selector_configuration_and_inventory_refuse_unregistered_provider(self):
        for mode in ('fixed', 'adaptive'):
            cfg = {**self.cfg, 'dns_propagation': {'mode': mode}}
            for operation in (dnsproviders.get_provider, dnsproviders.credentials,
                              dnsconfig.validate, core.zones, lambda value: core.discover(value, {})):
                with self.subTest(mode=mode, operation=operation):
                    with self.assertRaisesRegex(core.Error, '^Unsupported DNS provider$'):
                        operation(cfg)

    def test_certificate_issuance_refuses_before_preflight_private_files_or_certbot(self):
        args = SimpleNamespace(force_renew=False, dry_run=False)
        domain = {'cgp_domain': 'example.com', 'cert_name': 'example.com', 'names': ['example.com']}
        for mode in ('fixed', 'adaptive'):
            with self.subTest(mode=mode), self.assertRaisesRegex(core.Error, '^Unsupported DNS provider$'):
                core.issue({**self.cfg, 'dns_propagation': {'mode': mode}}, domain, {}, args)

    def test_fixed_hooks_and_entrypoints_refuse_before_state_or_secret_access(self):
        for cleanup in (False, True):
            with self.subTest(cleanup=cleanup):
                with self.assertRaisesRegex(core.Error, '^Unsupported DNS provider$'):
                    cli.hook(self.cfg, cleanup)
                flag = '--hook-cleanup' if cleanup else '--hook-auth'
                with patch.object(cli.sys, 'argv', ['cgp-letsencrypt', flag]), \
                        patch.object(cli, 'load', return_value=deepcopy(self.cfg)):
                    with self.assertRaisesRegex(core.Error, '^Unsupported DNS provider$'):
                        cli.main()

    def test_adaptive_session_refuses_before_creating_a_receipt(self):
        session = dnsauth.Session(self.cfg)
        with self.assertRaisesRegex(dnsauth.DNSAuthError, 'DNS challenge creation failed'):
            session.create('example.com', 'A' * 43, {})


if __name__ == '__main__':
    unittest.main()
