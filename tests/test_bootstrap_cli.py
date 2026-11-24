"""CLI readiness boundaries with the real CGP parser and HTTP adapter.

Only the HTTP response and certificate-processing boundaries are simulated;
configuration permissions, argument routing, readiness inspection, and state
handling run through their production implementations.
"""
import base64
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs
from unittest.mock import Mock, patch

from cgp_cert_manager import bootstrap, cli, core, storage


NAME = 'example.com'
OTHER = 'other.example.com'


def dictionary(values):
    return '{' + ''.join(name + '=' + value + ';' for name, value in values.items()) + '}'


class BootstrapCLITests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.state = self.root / 'state'
        self.config = self.root / 'config.json'
        # The standalone diagnostic must not migrate this legacy configuration.
        self.cfg = {'email': 'admin@example.com', 'communigate': {
            'url': 'http://127.0.0.1:8100/CLI/', 'username': 'admin',
            'password': 'CGP_PASSWORD_MUST_NOT_ESCAPE',
        }}
        core.atomic(self.config, self.cfg)
        self.config_bytes = self.config.read_bytes()
        self.settings = {name: '[' + base64.b64encode((name + '_SECRET').encode()).decode() + ']'
                         for name in core.FIELDS if name != 'CertificateType'}
        self.settings['CertificateType'] = 'YES'
        self.raw = dictionary(self.settings)
        self.responses = {'LISTDOMAINS': '(' + NAME + ')'}
        self.commands = []
        self.events = []
        self.transport = Mock()
        self.transport.open.side_effect = self.http_response
        self.stack.enter_context(patch.object(core, 'opener', return_value=self.transport))
        for module, name, value in ((cli, 'CONFIG', self.config), (cli, 'STATE', self.state),
                                    (core, 'STATE', self.state)):
            self.stack.enter_context(patch.object(module, name, value))
        self.stack.enter_context(patch.object(cli.os, 'umask'))
        self.domain = {'cgp_domain': NAME, 'cert_name': NAME, 'names': [NAME],
                       'enabled': True, 'cloudflare_available': True, 'unavailable': []}
        self.info = {'fingerprint': 'fingerprint', 'days': 80, 'names': [NAME]}
        self.mocks = {}
        for name, value in {'zones': {}, 'discover': [self.domain],
                            'installed_info': self.info, 'local_info': self.info,
                            'issue': None, 'deploy': 'installed', 'notify': None,
                            'history': None, 'verify_tls': None, 'discover_listeners': [],
                            'chain_payload': self.settings['CAChain'][1:-1],
                            'validate_backup': None}.items():
            self.mocks[name] = self.stack.enter_context(patch.object(cli, name, return_value=value))
        self.current = self.stack.enter_context(patch.object(cli, 'current', wraps=core.current))
        self.recover = self.stack.enter_context(patch.object(cli.deployment, 'recover_pending', return_value=[]))
        self.log = self.stack.enter_context(patch.object(cli.LOG, 'error'))
        self.out = io.StringIO()
        self.err = io.StringIO()
        self.stack.enter_context(contextlib.redirect_stdout(self.out))
        self.stack.enter_context(contextlib.redirect_stderr(self.err))
        self.live = self.root / 'live'
        (self.live / NAME).mkdir(parents=True)
        (self.live / NAME / 'chain.pem').write_bytes(b'public chain fixture')
        self.stack.enter_context(patch.object(cli, 'LIVE', self.live))

    def http_response(self, request, timeout):
        self.assertEqual(request.full_url, self.cfg['communigate']['url'])
        self.assertEqual(timeout, 60)
        command = parse_qs(request.data.decode())['command'][0]
        self.assertTrue(command == 'LISTDOMAINS' or command.startswith(
            ('GETDOMAINSETTINGS ', 'GETDOMAINEFFECTIVESETTINGS ')), command)
        self.commands.append(command)
        self.events.append(command.split()[0])
        response = self.responses.get(command, self.raw)
        if isinstance(response, list):
            response = response.pop(0)
        if isinstance(response, Exception):
            raise response
        return io.BytesIO(response.encode())

    def invoke(self, *args):
        self.out.seek(0)
        self.out.truncate()
        with patch.object(cli.sys, 'argv', ['cgp-letsencrypt', *args]):
            return cli.main()

    def output(self):
        return json.loads(self.out.getvalue())

    def assert_no_secrets(self, value):
        text = str(value)
        self.assertNotIn(self.cfg['communigate']['password'], text)
        for name in core.FIELDS[:-1]:
            self.assertNotIn(self.settings[name][1:-1], text)
        self.assertNotIn('PRIVATE_RESPONSE_SENTINEL', text)

    @contextlib.contextmanager
    def pure_diagnostic(self):
        with contextlib.ExitStack() as stack:
            guards = [stack.enter_context(patch.object(module, name)) for module, name in (
                (storage, 'operation_lock'), (storage, 'validate_tree'),
                (storage, 'ensure_private_directory'), (storage.os, 'fsync'),
                (cli, 'atomic'), (cli, 'migrate'), (cli.deployment, 'assert_no_pending'),
            )]
            yield
            for guard in guards:
                guard.assert_not_called()
        for name in ('zones', 'discover', 'installed_info', 'local_info', 'issue',
                     'deploy', 'notify', 'history', 'validate_backup'):
            self.mocks[name].assert_not_called()
        self.current.assert_not_called()
        self.recover.assert_not_called()
        self.assertEqual(self.config.read_bytes(), self.config_bytes)

    def test_standalone_json_uses_secure_config_without_state_or_migration(self):
        with self.pure_diagnostic():
            self.assertEqual(self.invoke('--bootstrap-check', '--domain', NAME, '--json'), 0)
        self.assertFalse(self.state.exists())
        report = self.output()[0]
        self.assertTrue(report['deployment_ready'])
        self.assertTrue(report['snapshot_complete'])
        self.assertTrue(report['explicit_snapshot_complete'])
        self.assertFalse(report['automatic_bootstrap'])
        self.assertEqual(report['origin'], dict.fromkeys(core.FIELDS, 'explicit'))
        self.assertEqual(self.commands, ['GETDOMAINSETTINGS ' + NAME,
                                         'GETDOMAINEFFECTIVESETTINGS ' + NAME] * 2)
        self.assertNotIn('settings', report)
        self.assert_no_secrets(self.out.getvalue())

    def test_all_domain_text_reports_inheritance_without_claiming_bootstrap(self):
        self.responses['LISTDOMAINS'] = '(' + OTHER + ',' + NAME + ')'
        self.responses['GETDOMAINSETTINGS ' + OTHER] = '{}'
        with self.pure_diagnostic():
            self.assertEqual(self.invoke('--bootstrap-check'), 1)
        text = self.out.getvalue()
        for expected in ('Domain: ' + NAME, 'Domain: ' + OTHER, 'Deployment ready: yes',
                         'Deployment ready: no', 'Reason: none', 'missing_explicit_fields',
                         'PrivateSecureKey=effective_only', 'Automatic bootstrap: disabled',
                         'Missing explicit fields: none',
                         'Missing explicit fields: ' + ', '.join(core.FIELDS),
                         'Missing effective fields: none', 'Unreadable fields: none',
                         'Empty fields: none'):
            self.assertIn(expected, text)
        self.assertEqual(self.commands[0], 'LISTDOMAINS')
        self.assertEqual(len(self.commands), 9)
        self.assertFalse(self.state.exists())
        self.assert_no_secrets(text)

    def test_text_identifies_missing_unreadable_and_empty_fields_without_values(self):
        response = '{CAChain=PRIVATE_RESPONSE_SENTINEL; CertificateType="";}'
        self.responses['GETDOMAINSETTINGS ' + NAME] = response
        self.responses['GETDOMAINEFFECTIVESETTINGS ' + NAME] = response
        with self.pure_diagnostic():
            self.assertEqual(self.invoke('--bootstrap-check', '--domain', NAME), 1)
        text = self.out.getvalue()
        for expected in ('Missing explicit fields: PrivateSecureKey, SecureCertificate',
                         'Missing effective fields: PrivateSecureKey, SecureCertificate',
                         'Unreadable fields: CAChain', 'Empty fields: CertificateType'):
            self.assertIn(expected, text)
        self.assert_no_secrets(text)
        self.assertFalse(self.state.exists())

    def test_empty_inventory_is_successful_in_both_formats(self):
        self.responses['LISTDOMAINS'] = '()'
        with self.pure_diagnostic():
            self.assertEqual(self.invoke('--bootstrap-check', '--json'), 0)
            self.assertEqual(self.output(), [])
            self.assertEqual(self.invoke('--bootstrap-check'), 0)
            self.assertEqual(self.out.getvalue(), 'No CGP domains\n')
        self.assertEqual(self.commands, ['LISTDOMAINS', 'LISTDOMAINS'])
        self.assertFalse(self.state.exists())

    def test_transport_and_parse_failures_are_safe_public_failures(self):
        for response, reason in ((OSError('PRIVATE_RESPONSE_SENTINEL'), 'response_unavailable'),
                                 ('PRIVATE_RESPONSE_SENTINEL not a dictionary', 'invalid_response')):
            with self.subTest(reason=reason), self.pure_diagnostic():
                self.responses['GETDOMAINSETTINGS ' + NAME] = response
                self.assertEqual(self.invoke('--bootstrap-check', '--domain', NAME, '--json'), 1)
                report = self.output()[0]
                self.assertEqual(report['blocking_reason'], reason)
                self.assertIsNone(report['missing_explicit_fields'])
                self.assertFalse(report['deployment_ready'])
                self.assert_no_secrets(self.out.getvalue())
                self.assertEqual(self.invoke('--bootstrap-check', '--domain', NAME), 1)
                for expected in ('Missing explicit fields: unknown', 'Missing effective fields: unknown',
                                 'Unreadable fields: none', 'Empty fields: none'):
                    self.assertIn(expected, self.out.getvalue())
                self.assert_no_secrets(self.out.getvalue())
        self.assertFalse(self.state.exists())

    def test_invalid_explicit_domain_is_rejected_before_loading_configuration(self):
        with patch.object(cli, 'load') as load, patch.object(bootstrap, 'reports') as reports:
            for domain in ('', '../elsewhere', 'two domains', NAME + '\n', 'x;LISTDOMAINS'):
                with self.subTest(domain=domain), self.pure_diagnostic(), self.assertRaises(SystemExit) as error:
                    self.invoke('--bootstrap-check', '--domain', domain)
                self.assertEqual(error.exception.code, 2)
            load.assert_not_called()
            reports.assert_not_called()
        self.assertFalse(self.state.exists())
        self.assertEqual(self.commands, [])

    def test_bootstrap_check_cannot_be_combined_with_an_action(self):
        for args in (('--status',), ('--plan',), ('--dry-run',), ('--recover',),
                     ('--transactions',), ('--rollback', NAME), ('--migrate',),
                     ('--acknowledge-restored', '--domain', NAME)):
            with self.subTest(args=args), self.pure_diagnostic(), self.assertRaises(SystemExit):
                self.invoke('--bootstrap-check', *args)
        self.assertFalse(self.state.exists())
        self.assertEqual(self.commands, [])

    def test_diagnostic_still_refuses_an_unsafe_configuration(self):
        self.config.chmod(0o644)
        with self.pure_diagnostic(), self.assertRaises(storage.StorageError):
            self.invoke('--bootstrap-check', '--domain', NAME)
        self.assertEqual(self.commands, [])
        self.assertFalse(self.state.exists())

    def test_diagnostic_does_not_inspect_or_repair_pending_unsafe_state(self):
        target = self.root / 'unsafe-state'
        target.mkdir(mode=0o755)
        evidence = target / 'pending.json'
        evidence.write_text('PRIVATE_RESPONSE_SENTINEL')
        self.state.symlink_to(target, target_is_directory=True)
        with self.pure_diagnostic():
            self.assertEqual(self.invoke('--bootstrap-check', '--domain', NAME, '--json'), 0)
        self.assertTrue(self.state.is_symlink())
        self.assertEqual(evidence.read_text(), 'PRIVATE_RESPONSE_SENTINEL')
        self.assert_no_secrets(self.out.getvalue())

    def test_mutations_block_unsafe_snapshots_before_certificate_readers(self):
        missing = {name: value for name, value in self.settings.items() if name != 'PrivateSecureKey'}
        cases = (
            (dictionary(missing), dictionary(missing), 'missing_effective_fields'),
            ('{}', self.raw, 'missing_explicit_fields'),
            (dictionary(dict(self.settings, PrivateSecureKey='[]')),
             dictionary(dict(self.settings, PrivateSecureKey='[]')), 'empty_fields'),
            (dictionary(dict(self.settings, PrivateSecureKey='wrong_type')),
             dictionary(dict(self.settings, PrivateSecureKey='wrong_type')), 'unreadable_fields'),
            (self.raw, dictionary(dict(self.settings, CertificateType='NO')), 'inconsistent'),
            ([self.raw, dictionary(dict(self.settings, CertificateType='NO'))], self.raw, 'changed'),
            ('{PrivateSecureKey=[YQ==]; PrivateSecureKey=[Yg==];}', self.raw, 'invalid_response'),
            (OSError('PRIVATE_RESPONSE_SENTINEL'), self.raw, 'response_unavailable'),
        )
        for explicit, effective, reason in cases:
            with self.subTest(reason=reason):
                self.responses['GETDOMAINSETTINGS ' + NAME] = explicit
                self.responses['GETDOMAINEFFECTIVESETTINGS ' + NAME] = effective
                self.assertEqual(self.invoke(), 1)
                state = core.load(self.state / 'state.json')
                self.assertIn('(' + reason + ')', state[NAME]['result'])
                self.assert_no_secrets(state)
        for name in ('installed_info', 'local_info', 'issue', 'deploy', 'validate_backup'):
            self.mocks[name].assert_not_called()
        self.current.assert_not_called()
        self.assert_no_secrets(self.log.call_args_list)
        self.assert_no_secrets([args.args[3] for args in self.mocks['notify'].call_args_list])

    def test_force_retry_shrink_and_install_modes_cannot_bypass_readiness(self):
        self.responses['GETDOMAINSETTINGS ' + NAME] = '{}'
        for args in (('--force-renew',), ('--retry-now',), ('--allow-shrink',),
                     ('--force-renew', '--retry-now', '--allow-shrink'),
                     ('--install-only',), ('--repair-chain',)):
            with self.subTest(args=args):
                self.assertEqual(self.invoke(*args), 1)
        for name in ('installed_info', 'local_info', 'issue', 'deploy'):
            self.mocks[name].assert_not_called()

    def test_plan_and_doctor_report_blocked_and_do_not_notify_or_save_state(self):
        self.responses['GETDOMAINSETTINGS ' + NAME] = '{}'
        for action in ('--plan', '--doctor'):
            with self.subTest(action=action):
                self.assertEqual(self.invoke(action, '--json'), 1)
                row = self.output()[0]
                self.assertEqual(row['action'], 'BLOCKED')
                self.assertEqual(row['status'], 'blocked')
                self.assertEqual(row['readiness']['blocking_reason'], 'missing_explicit_fields')
                self.assertFalse(row['readiness']['deployment_ready'])
                self.assertIn('--bootstrap-check', row['error'])
                self.assert_no_secrets(row)
        for name in ('installed_info', 'local_info', 'issue', 'deploy', 'notify', 'history'):
            self.mocks[name].assert_not_called()
        self.recover.assert_not_called()
        for name in ('state.json', 'domains.json', 'history.jsonl', 'transactions', 'backups'):
            self.assertFalse((self.state / name).exists())

    def test_ready_plan_includes_public_readiness_without_claiming_tls(self):
        self.assertEqual(self.invoke('--plan', '--json'), 0)
        row = self.output()[0]
        self.assertTrue(row['readiness']['deployment_ready'])
        self.assertFalse(row['readiness']['automatic_bootstrap'])
        self.assertEqual(row['action'], 'VERIFY/KEEP')
        self.assertNotEqual(row.get('tls'), 'verified')
        self.assert_no_secrets(row)
        self.mocks['issue'].assert_not_called()
        self.mocks['deploy'].assert_not_called()

    def test_status_and_tls_verification_remain_effective_certificate_observations(self):
        self.responses['GETDOMAINSETTINGS ' + NAME] = '{}'
        with patch.object(bootstrap, 'inspect') as inspect:
            for action in ('--status', '--verify', '--verify-listeners'):
                with self.subTest(action=action):
                    self.assertEqual(self.invoke(action, '--json'), 0)
                    self.assertNotIn('readiness', self.output()[0])
            inspect.assert_not_called()
        self.assertEqual(self.commands, ['GETDOMAINEFFECTIVESETTINGS ' + NAME] * 3)
        self.mocks['verify_tls'].assert_called_once()
        self.mocks['issue'].assert_not_called()
        self.mocks['deploy'].assert_not_called()

    def test_dry_run_keeps_staging_issuance_without_readiness_or_deployment(self):
        self.responses['GETDOMAINSETTINGS ' + NAME] = '{}'
        with patch.object(bootstrap, 'inspect') as inspect:
            self.assertEqual(self.invoke('--dry-run'), 0)
            inspect.assert_not_called()
        self.assertEqual(self.commands, ['GETDOMAINEFFECTIVESETTINGS ' + NAME])
        self.mocks['issue'].assert_called_once()
        self.mocks['deploy'].assert_not_called()
        self.mocks['notify'].assert_not_called()
        self.mocks['history'].assert_not_called()
        self.recover.assert_not_called()
        self.assertFalse((self.state / 'state.json').exists())

    def test_disabled_and_unavailable_domains_keep_their_skip_policy(self):
        with patch.object(bootstrap, 'inspect') as inspect:
            for enabled, available, status in ((False, True, 'disabled'), (True, False, 'unavailable')):
                with self.subTest(status=status):
                    self.domain.update(enabled=enabled, cloudflare_available=available)
                    self.assertEqual(self.invoke('--plan', '--json'), 0)
                    row = self.output()[0]
                    self.assertEqual(row['status'], status)
                    self.assertEqual(row['action'], 'SKIP')
                    self.assertNotIn('readiness', row)
                    self.assertEqual(self.invoke(), 0)
            inspect.assert_not_called()
        self.mocks['issue'].assert_not_called()
        self.mocks['deploy'].assert_not_called()

    def test_ready_snapshot_is_reused_before_readers_and_issuance(self):
        self.mocks['installed_info'].side_effect = lambda *_: self.events.append('installed') or self.info
        self.mocks['local_info'].side_effect = lambda *_: self.events.append('local') or self.info
        self.mocks['issue'].side_effect = lambda *_: self.events.append('issue')
        self.mocks['deploy'].side_effect = lambda *_: self.events.append('deploy') or 'installed'
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(self.events, ['GETDOMAINSETTINGS', 'GETDOMAINEFFECTIVESETTINGS'] * 2
                         + ['installed', 'local', 'issue', 'deploy'])
        self.current.assert_not_called()
        self.mocks['installed_info'].assert_called_once_with(self.settings)

    def test_complete_expired_snapshot_does_not_prevent_renewal(self):
        self.info['days'] = -1
        self.assertEqual(self.invoke(), 0)
        self.mocks['issue'].assert_called_once()
        self.mocks['deploy'].assert_called_once()
        self.mocks['validate_backup'].assert_not_called()
        self.mocks['notify'].assert_called_once()
        self.assertIn('expires in less than 7 days', self.mocks['notify'].call_args.args[3])

    def test_manual_rollback_requires_ready_current_after_recovery(self):
        saved = dict(self.settings, SecureCertificate='[YQ==]')
        core.atomic(self.state / 'backups' / NAME / 'saved.json', saved)
        self.responses['GETDOMAINSETTINGS ' + NAME] = '{}'
        with patch.object(cli.deployment, 'apply') as apply:
            with self.assertRaisesRegex(core.Error, 'Certificate deployment blocked.*missing_explicit_fields'):
                self.invoke('--rollback', NAME)
            apply.assert_not_called()
        self.recover.assert_called_once()
        self.mocks['validate_backup'].assert_called_once_with(saved)
        self.mocks['history'].assert_not_called()
        self.current.assert_not_called()
        self.responses['GETDOMAINSETTINGS ' + NAME] = self.raw
        with patch.object(cli.deployment, 'apply') as apply, \
                patch.object(cli.deployment, 'snapshot_endpoints', return_value=[]) as endpoints:
            self.assertEqual(self.invoke('--rollback', NAME), 0)
        self.assertEqual(apply.call_args.args[2:4], (self.settings, saved))
        self.assertEqual([args.args[1] for args in endpoints.call_args_list], [saved, self.settings])
        self.mocks['history'].assert_called_once_with(NAME, 'manual rollback')
        self.mocks['zones'].assert_not_called()

    def test_blocked_domain_does_not_issue_but_an_independent_ready_domain_can_continue(self):
        other = dict(self.domain, cgp_domain=OTHER, cert_name=OTHER, names=[OTHER])
        self.mocks['discover'].return_value = [self.domain, other]
        self.responses['GETDOMAINSETTINGS ' + NAME] = '{}'
        self.assertEqual(self.invoke(), 1)
        self.assertEqual(self.mocks['issue'].call_args.args[1], other)
        self.assertEqual(self.mocks['issue'].call_count, 1)
        self.assertEqual(self.mocks['deploy'].call_args.args[1], other)
        self.assertEqual(self.mocks['deploy'].call_count, 1)
        self.mocks['installed_info'].assert_called_once_with(self.settings)
        state = core.load(self.state / 'state.json')
        self.assertIn('missing_explicit_fields', state[NAME]['result'])
        self.assertEqual(state[OTHER]['result'], 'installed')
