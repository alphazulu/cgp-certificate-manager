"""Explicit operator acknowledgement routing and preview safeguards."""
import contextlib
import io
import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import cgp_cert_manager as package
from cgp_cert_manager import cli, core, storage


class ResolutionCLITests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.state = self.root / 'state'
        self.state.mkdir(mode=0o700)
        self.config = self.root / 'config.json'
        self.cfg = {'schema_version': 2, 'email': 'admin@example.com'}
        core.atomic(self.config, self.cfg)
        self.domain = 'example.com'
        self.token = 'a' * 64
        self.preview = {
            'domain': self.domain, 'phase': 'restoring', 'state': 'previous',
            'server_matches': True, 'confirmation_token': self.token,
            'tls': 'unverified', 'pending_journal': True,
            'authorization_recorded': False,
        }
        self.result = {
            'domain': self.domain, 'result': 'acknowledged_unverified',
            'tls': 'unverified', 'confirmation_token': self.token,
        }
        self.backend = types.ModuleType('cgp_cert_manager.resolution')
        self.backend.preview = Mock(return_value=self.preview)
        self.backend.acknowledge = Mock(return_value=self.result)
        self.stack.enter_context(patch.object(package, 'resolution', self.backend, create=True))
        for module, name, value in ((cli, 'CONFIG', self.config), (cli, 'STATE', self.state), (core, 'STATE', self.state)):
            self.stack.enter_context(patch.object(module, name, value))
        self.stack.enter_context(patch.object(cli.os, 'umask'))
        self.out = io.StringIO()
        self.stack.enter_context(contextlib.redirect_stdout(self.out))
        self.stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
        self.zones = self.stack.enter_context(patch.object(cli, 'zones', return_value={}))
        self.stack.enter_context(patch.object(cli, 'discover', return_value=[]))
        self.issue = self.stack.enter_context(patch.object(cli, 'issue'))
        self.deploy = self.stack.enter_context(patch.object(cli, 'deploy'))
        self.recover = self.stack.enter_context(patch.object(cli.deployment, 'recover_pending', return_value=[]))
        self.stack.enter_context(patch.object(cli.deployment, 'transaction_status', return_value=[]))

    def invoke(self, *args):
        with patch.object(cli.sys, 'argv', ['cgp-letsencrypt', *args]):
            return cli.main()

    def action(self, *args):
        return self.invoke('--acknowledge-restored', '--domain', self.domain, *args)

    def test_preview_json_routes_only_to_readonly_backend(self):
        self.assertEqual(self.action('--json'), 0)
        self.assertEqual(json.loads(self.out.getvalue()), self.preview)
        self.backend.preview.assert_called_once_with(self.cfg, self.domain)
        self.backend.acknowledge.assert_not_called()
        self.recover.assert_not_called()
        self.zones.assert_not_called()
        self.issue.assert_not_called()
        self.deploy.assert_not_called()

    def test_preview_text_exposes_operation_and_unverified_state(self):
        self.assertEqual(self.action(), 0)
        self.assertNotIn('Repeat the original acknowledgement reason.', self.out.getvalue())
        self.out.seek(0); self.out.truncate()
        self.preview.update(phase='acknowledging', state='both', pending_journal=False, authorization_recorded=True)
        self.assertEqual(self.action(), 0)
        output = self.out.getvalue()
        for expected in ('Phase: acknowledging', 'CGP state: both', 'TLS: unverified', self.token, 'Pending journal: False', 'Authorization recorded: True', 'Repeat the original acknowledgement reason.', '--confirm-transaction TOKEN', '--reason TEXT'):
            self.assertIn(expected, output)
        self.backend.acknowledge.assert_not_called()

    def test_acknowledgement_json_passes_exact_token_and_trimmed_reason(self):
        self.assertEqual(self.action('--confirm-transaction', self.token, '--reason', '  Сертификат истёк; требуется продление  ', '--json'), 0)
        self.backend.acknowledge.assert_called_once_with(self.cfg, self.domain, self.token, 'Сертификат истёк; требуется продление')
        self.backend.preview.assert_not_called()
        self.assertEqual(json.loads(self.out.getvalue()), self.result)
        self.assertNotIn('Сертификат', self.out.getvalue())
        self.recover.assert_not_called()
        self.issue.assert_not_called()
        self.deploy.assert_not_called()

    def test_acknowledgement_text_never_claims_verified_tls(self):
        self.assertEqual(self.action('--confirm-transaction', self.token, '--reason', 'Operator checked previous settings'), 0)
        self.assertIn('Result: acknowledged_unverified', self.out.getvalue())
        self.assertIn('CGP settings were not changed. TLS remains unverified.', self.out.getvalue())
        self.assertNotIn('TLS: verified', self.out.getvalue())

    def test_invalid_flags_and_reasons_fail_before_lock_or_backend(self):
        base = ('--acknowledge-restored', '--domain', self.domain)
        cases = [
            ('--acknowledge-restored',),
            ('--acknowledge-restored', '--domain', '../invalid'),
            ('--confirm-transaction', self.token), ('--reason', 'Operator decision'),
            base + ('--confirm-transaction', self.token), base + ('--reason', 'Operator decision'),
            base + ('--recover',), base + ('--transactions',),
        ]
        cases += [base + ('--confirm-transaction', token, '--reason', 'Operator decision') for token in ('a' * 63, 'A' * 64, 'z' * 64)]
        cases += [base + ('--confirm-transaction', self.token, '--reason', reason) for reason in ('', '   ', 'x' * 501, '\ttext', 'text\n', '\nreason', 'reason\t', 'text\x1b', 'text\u200b')]
        with patch.object(storage, 'operation_lock') as lock:
            for args in cases:
                with self.subTest(args=args), self.assertRaises(SystemExit) as exit_code:
                    self.invoke(*args)
                self.assertEqual(exit_code.exception.code, 2)
            lock.assert_not_called()
        self.backend.preview.assert_not_called()
        self.backend.acknowledge.assert_not_called()
        self.assertFalse((self.state / 'run.lock').exists())

    def test_both_preview_and_acknowledgement_respect_operation_lock(self):
        with storage.operation_lock(self.state):
            for args in ((), ('--confirm-transaction', self.token, '--reason', 'Operator decision')):
                with self.subTest(args=args), self.assertRaises(BlockingIOError):
                    self.action(*args)
        self.backend.preview.assert_not_called()
        self.backend.acknowledge.assert_not_called()

    def test_backend_refusal_returns_error_without_automatic_retry(self):
        self.backend.acknowledge.side_effect = core.Error('Preview is stale')
        with patch.object(cli.sys, 'argv', ['cgp-letsencrypt', '--acknowledge-restored', '--domain', self.domain, '--confirm-transaction', self.token, '--reason', 'Operator decision']):
            self.assertEqual(cli.entry(), 1)
        self.backend.acknowledge.assert_called_once()
        self.backend.preview.assert_not_called()
        self.recover.assert_not_called()
        self.assertEqual(self.out.getvalue(), '')

    def test_normal_recovery_and_diagnostics_never_acknowledge(self):
        for args in ((), ('--recover',), ('--transactions',), ('--status', '--json'), ('--dry-run',)):
            with self.subTest(args=args):
                self.assertEqual(self.invoke(*args), 0)
        self.backend.preview.assert_not_called()
        self.backend.acknowledge.assert_not_called()

