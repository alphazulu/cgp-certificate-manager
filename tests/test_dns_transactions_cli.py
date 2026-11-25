"""Operator DNS receipt inspection and explicit cleanup lifecycle."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cgp_cert_manager import cli, core, dnsauth, storage


class DNSTransactionCLITests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.state = self.root / 'state'
        self.config = self.root / 'config.json'
        self.cfg = {'schema_version': 2, 'dns_propagation': {'mode': 'invalid'}}
        core.atomic(self.config, self.cfg)
        for module, name, value in ((cli, 'CONFIG', self.config), (cli, 'STATE', self.state), (core, 'STATE', self.state)):
            self.stack.enter_context(patch.object(module, name, value))
        self.stack.enter_context(patch.object(cli.os, 'umask'))
        self.out = io.StringIO()
        self.stack.enter_context(contextlib.redirect_stdout(self.out))
        self.stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
        self.forbidden = [self.stack.enter_context(patch.object(module, name)) for module, name in (
            (core, 'cf'), (cli, 'zones'), (cli, 'issue'), (cli, 'deploy'),
            (cli, 'history'), (cli, 'notify'), (cli.deployment, 'recover_pending'),
        )]

    def invoke(self, *args):
        self.out.seek(0); self.out.truncate()
        with patch.object(cli.sys, 'argv', ['cgp-letsencrypt', *args]):
            return cli.main()

    def test_empty_status_does_not_create_or_lock_state_and_ignores_dns_options(self):
        with patch.object(storage, 'operation_lock') as lock, patch.object(storage.os, 'fsync') as sync:
            self.assertEqual(self.invoke('--dns-transactions'), 0)
            self.assertEqual(self.out.getvalue(), 'No pending DNS challenges\n')
            self.assertEqual(self.invoke('--dns-transactions', '--json'), 0)
            self.assertEqual(json.loads(self.out.getvalue()), [])
            lock.assert_not_called()
            sync.assert_not_called()
        self.assertFalse(self.state.exists())
        for mock in self.forbidden: mock.assert_not_called()

    def test_status_outputs_public_metadata_in_both_formats(self):
        rows = [{'id': 'a' * 32, 'name': '_acme-challenge.example.com',
                 'phase': 'intent', 'owned': None, 'zone': 'b' * 32}]
        with patch.object(dnsauth, 'status', return_value=rows) as status, \
                patch.object(storage, 'operation_lock') as lock:
            self.assertEqual(self.invoke('--dns-transactions', '--json'), 0)
            self.assertEqual(json.loads(self.out.getvalue()), rows)
            self.assertEqual(self.invoke('--dns-transactions'), 0)
            self.assertIn('_acme-challenge.example.com: intent', self.out.getvalue())
            status.assert_called_with(self.cfg)
            lock.assert_not_called()
        self.assertFalse(self.state.exists())

    def test_cleanup_runs_under_lock_and_reports_success_only_after_backend(self):
        def cleanup(cfg):
            self.assertEqual(cfg, self.cfg)
            with self.assertRaises(BlockingIOError), storage.operation_lock(self.state):
                pass
        with patch.object(dnsauth, 'cleanup_pending', side_effect=cleanup) as clean:
            self.assertEqual(self.invoke('--dns-cleanup'), 0)
            self.assertEqual(self.out.getvalue(), 'DNS challenge cleanup complete\n')
            self.assertEqual(self.invoke('--dns-cleanup', '--json'), 0)
            self.assertEqual(json.loads(self.out.getvalue()), {'result': 'cleaned'})
            self.assertEqual(clean.call_count, 2)
        for mock in self.forbidden: mock.assert_not_called()

    def test_cleanup_cannot_bypass_lock_and_does_not_claim_failed_cleanup_success(self):
        with patch.object(dnsauth, 'cleanup_pending') as clean:
            with storage.operation_lock(self.state), self.assertRaises(BlockingIOError):
                self.invoke('--dns-cleanup')
            clean.assert_not_called()
            clean.side_effect = core.Error('DNS challenge cleanup is pending')
            with self.assertRaisesRegex(core.Error, 'cleanup is pending'):
                self.invoke('--dns-cleanup')
            self.assertEqual(self.out.getvalue(), '')

    def test_global_scope_and_conflicting_actions_are_rejected_before_storage(self):
        for args in (('--dns-transactions', '--domain', 'example.com'),
                     ('--dns-cleanup', '--domain', 'example.com'),
                     ('--dns-cleanup', '--dns-check'), ('--dns-transactions', '--dns-cleanup')):
            with self.subTest(args=args), patch.object(cli, 'load') as load, \
                    patch.object(storage, 'operation_lock') as lock, self.assertRaises(SystemExit):
                self.invoke(*args)
            load.assert_not_called()
            lock.assert_not_called()
        self.assertFalse(self.state.exists())
