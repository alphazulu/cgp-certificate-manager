"""Transaction CLI routing, mutation ordering and lock exclusion."""
import contextlib
import fcntl
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import call, patch

from cgp_cert_manager import cli, core, storage
from cgp_cert_manager.transactions import Journal


class TransactionCLITests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.live = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.cfg = {'schema_version': 2, 'email': 'admin@example.com'}
        self.config = self.root / 'config.json'
        core.atomic(self.config, self.cfg)
        self.name = 'example.com'
        self.settings = dict.fromkeys(core.FIELDS, '[YQ==]')
        self.settings['CertificateType'] = 'YES'
        self.info = {'fingerprint': 'a', 'names': [self.name], 'days': 80}
        self.domain = {
            'cgp_domain': self.name, 'cert_name': self.name, 'names': [self.name],
            'enabled': True, 'cloudflare_available': True, 'unavailable': [],
        }
        for module, name, value in (
            (cli, 'CONFIG', self.config), (cli, 'STATE', self.root),
            (core, 'STATE', self.root), (cli, 'LIVE', self.live),
        ):
            self.stack.enter_context(patch.object(module, name, value))
        live = self.live / self.name
        live.mkdir(parents=True)
        (live / 'chain.pem').write_bytes(b'dummy')
        self.stack.enter_context(patch.object(cli.os, 'umask'))
        self.out = io.StringIO()
        self.stack.enter_context(contextlib.redirect_stdout(self.out))
        self.stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
        self.mocks = {}
        for name, value in {
            'zones': {}, 'discover': [self.domain], 'current': self.settings,
            'installed_info': self.info, 'local_info': self.info, 'issue': None,
            'deploy': 'installed', 'verify_tls': None, 'chain_payload': 'YQ==',
            'discover_listeners': [], 'cli': '(example.com)',
        }.items():
            self.mocks[name] = self.stack.enter_context(patch.object(cli, name, return_value=value))
        self.recover = self.stack.enter_context(patch.object(cli.deployment, 'recover_pending', return_value=[]))
        self.status = self.stack.enter_context(patch.object(cli.deployment, 'transaction_status', return_value=[]))

    def invoke(self, *args):
        self.out.seek(0)
        self.out.truncate()
        with patch.object(cli.sys, 'argv', ['cgp-letsencrypt', *args]):
            return cli.main()

    def test_status_json_is_scoped_and_does_not_recover_or_discover(self):
        rows = [{'domain': self.name, 'phase': 'applying', 'state': 'intended', 'server_matches': True}]
        self.status.return_value = rows
        self.assertEqual(self.invoke('--transactions', '--domain', self.name, '--json'), 0)
        self.assertEqual(json.loads(self.out.getvalue()), rows)
        self.status.assert_called_once_with(self.cfg, self.name)
        self.recover.assert_not_called()
        self.mocks['zones'].assert_not_called()
        self.mocks['issue'].assert_not_called()
        self.mocks['deploy'].assert_not_called()
        self.assertFalse((self.root / 'state.json').exists())
        self.assertFalse((self.root / 'domains.json').exists())

    def test_status_table_identifies_server_mismatch(self):
        self.status.return_value = [
            {'domain': self.name, 'phase': 'prepared', 'state': 'previous', 'server_matches': True},
            {'domain': 'other.example.com', 'phase': 'restoring', 'state': 'unknown', 'server_matches': False},
        ]
        self.assertEqual(self.invoke('--transactions'), 0)
        text = self.out.getvalue()
        self.assertIn('PHASE', text)
        self.assertIn('previous', text)
        self.assertIn('mismatch', text)
        self.assertIn('match', text.splitlines()[1])

    def test_empty_status_and_recovery(self):
        for command in ('--transactions', '--recover'):
            with self.subTest(command=command):
                self.assertEqual(self.invoke(command), 0)
                self.assertEqual(self.out.getvalue(), 'No pending transactions\n')

    def test_explicit_recovery_formats_and_scope(self):
        rows = [{'domain': self.name, 'result': 'restored'}]
        self.recover.return_value = rows
        self.assertEqual(self.invoke('--recover', '--domain', self.name, '--json'), 0)
        self.assertEqual(json.loads(self.out.getvalue()), rows)
        self.recover.assert_called_once_with(self.cfg, self.name)
        self.assertEqual(self.invoke('--recover'), 0)
        self.assertEqual(self.out.getvalue(), 'example.com: restored\n')
        self.assertEqual(self.recover.call_args, call(self.cfg, None))
        self.status.assert_not_called()
        self.mocks['zones'].assert_not_called()

    def test_pending_recovery_precedes_discovery_and_all_certificate_mutations(self):
        for args in ((), ('--install-only',), ('--repair-chain',), ('--force-renew', '--domain', self.name)):
            with self.subTest(args=args):
                events = []
                self.recover.side_effect = lambda *a: events.append('recover') or []
                self.mocks['zones'].side_effect = lambda *a: events.append('zones') or {}
                self.mocks['issue'].side_effect = lambda *a: events.append('issue')
                self.mocks['deploy'].side_effect = lambda *a: events.append('deploy') or 'installed'
                self.assertEqual(self.invoke(*args), 0)
                self.assertEqual(events[:2], ['recover', 'zones'])
                self.assertEqual(events[-1], 'deploy')
                self.assertEqual(self.recover.call_args, call(self.cfg))

    def test_unresolved_transaction_blocks_discovery_issue_and_deployment(self):
        self.recover.side_effect = core.Error('Unknown CGP state')
        with self.assertRaisesRegex(core.Error, 'Unknown CGP state'):
            self.invoke('--domain', self.name)
        for name in ('zones', 'discover', 'issue', 'deploy'):
            self.mocks[name].assert_not_called()
        for path in ('state.json', 'domains.json', 'history.jsonl'):
            self.assertFalse((self.root / path).exists())

    def test_recovery_failure_returns_error_without_exception_details(self):
        self.recover.side_effect = OSError('private key material must not be logged')
        with patch.object(cli.sys, 'argv', ['cgp-letsencrypt', '--recover']), patch.object(cli.LOG, 'error') as error:
            self.assertEqual(cli.entry(), 1)
        error.assert_called_once_with('%s', 'OSError')
        self.assertNotIn('private key', self.out.getvalue())
        self.mocks['zones'].assert_not_called()

    def test_diagnostics_and_inventory_never_recover(self):
        for args in (
            ('--status',), ('--plan',), ('--doctor',), ('--verify',),
            ('--verify-listeners',), ('--dry-run',), ('--list',),
            ('--show-domains',), ('--history',), ('--backups', self.name),
            ('--discover-listeners',), ('--sync',),
        ):
            with self.subTest(args=args), patch.object(cli.deployment, 'assert_no_pending') as guard:
                self.assertEqual(self.invoke(*args), 0)
                self.recover.assert_not_called()
                guard.assert_not_called()

    def test_new_pending_transaction_stops_later_domains_in_same_batch(self):
        other = dict(self.domain, cgp_domain='other.example.com', cert_name='other.example.com', names=['other.example.com'])
        self.mocks['discover'].return_value = [self.domain, other]
        journal = Journal(self.root / 'transactions')
        replacement = dict(self.settings, PrivateSecureKey='[Yg==]')

        def failed_deployment(cfg, domain):
            journal.prepare(domain['cgp_domain'], self.settings, replacement,
                            [{'port': 443, 'sni': self.name}], 'test-server')
            journal.transition(domain['cgp_domain'], 'applying')
            raise core.Error('CRITICAL: transaction unresolved')

        self.mocks['deploy'].side_effect = failed_deployment
        with self.assertRaisesRegex(core.Error, 'Pending transaction'):
            self.invoke()
        self.mocks['issue'].assert_called_once()
        self.assertEqual(self.mocks['issue'].call_args.args[1], self.domain)
        self.mocks['deploy'].assert_called_once_with(self.cfg, self.domain)
        self.mocks['current'].assert_called_once_with(self.cfg, self.name)
        self.assertEqual(journal.read(self.name)['phase'], 'applying')
        state = core.load(self.root / 'state.json')
        self.assertIn('CRITICAL', state[self.name]['result'])
        self.assertNotIn('other.example.com', state)

    def test_recovery_cannot_bypass_global_lock(self):
        with storage.open_private(self.root / 'run.lock','a',create=True) as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                self.invoke('--recover')
        self.recover.assert_not_called()
        self.assertEqual(self.invoke('--recover'), 0)
        self.recover.assert_called_once_with(self.cfg, None)

    def test_transaction_actions_are_mutually_exclusive(self):
        for args in (('--transactions', '--recover'), ('--recover', '--rollback', self.name), ('--transactions', '--install-only')):
            with self.subTest(args=args), self.assertRaises(SystemExit):
                self.invoke(*args)
        self.recover.assert_not_called()
        self.status.assert_not_called()

    def test_manual_rollback_uses_configured_transport_and_separate_snapshots(self):
        configured = {'cgp_domain': self.name, 'tls': [{'port': 993, 'sni': self.name}]}
        self.cfg['domains'] = [{'cgp_domain': 'other.example.com'}, configured]
        core.atomic(self.config, self.cfg)
        saved = dict(self.settings, PrivateSecureKey='[Yg==]')
        core.atomic(self.root / 'backups' / self.name / 'saved.json', saved)
        previous_endpoints = [{'port': 993, 'sni': 'old.example.com'}]
        intended_endpoints = [{'port': 993, 'sni': self.name}]
        events = []
        self.recover.side_effect = lambda *a: events.append('recover') or []
        self.mocks['current'].side_effect = lambda *a: events.append('current') or self.settings
        with patch.object(cli, 'validate_backup') as validate, patch.object(cli.deployment, 'snapshot_endpoints', side_effect=[intended_endpoints, previous_endpoints]) as endpoints, patch.object(cli.deployment, 'apply', side_effect=lambda *a: events.append('apply') or 'installed') as apply:
            self.assertEqual(self.invoke('--rollback', self.name), 0)
        self.assertEqual(events, ['recover', 'current', 'apply'])
        validate.assert_called_once_with(saved)
        self.assertEqual(endpoints.call_args_list, [call(configured, saved), call(configured, self.settings)])
        apply.assert_called_once_with(self.cfg, self.name, self.settings, saved, intended_endpoints, previous_endpoints)
        self.assertIn('manual rollback', (self.root / 'history.jsonl').read_text())
        self.mocks['zones'].assert_not_called()

    def test_manual_rollback_inherits_global_tls_without_replacing_domain_override(self):
        global_tls = [{'host': '127.0.0.1', 'port': 993}]
        saved = dict(self.settings, PrivateSecureKey='[Yg==]')
        core.atomic(self.root / 'backups' / self.name / 'saved.json', saved)
        for domains, expected in (
            ([], global_tls),
            ([{'cgp_domain': self.name}], global_tls),
            ([{'cgp_domain': self.name, 'tls': []}], []),
        ):
            with self.subTest(domains=domains):
                self.cfg.update(domains=domains, tls=global_tls)
                core.atomic(self.config, self.cfg)
                with patch.object(cli, 'validate_backup'), patch.object(cli.deployment, 'snapshot_endpoints', return_value=[]) as endpoints, patch.object(cli.deployment, 'apply'):
                    self.assertEqual(self.invoke('--rollback', self.name), 0)
                self.assertEqual(endpoints.call_count, 2)
                for args in endpoints.call_args_list:
                    self.assertEqual(args.args[0]['tls'], expected)

