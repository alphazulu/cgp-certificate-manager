"""DNS gates and fixed/adaptive Certbot routing without external operations."""
import contextlib
import os
import tempfile
from types import SimpleNamespace
import unittest
from pathlib import Path
from unittest.mock import patch

from cgp_cert_manager import certbot_runner, cli, core, dnsauth, dnschecks, storage


class DNSIssueTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.credentials = self.root / 'cloudflare.ini'
        self.credentials.write_text('dns_cloudflare_api_token = dummy\n')
        self.credentials.chmod(0o600)
        self.cfg = {'schema_version': 2, 'email': 'admin@example.com'}
        self.domain = {'cgp_domain': 'example.com', 'cert_name': 'example.com', 'names': ['example.com']}
        self.zones = {'example.com': {'credentials': str(self.credentials)}}
        self.args = SimpleNamespace(force_renew=False, dry_run=False)
        self.local = self.stack.enter_context(patch.object(core, 'local_info', return_value=None))
        self.check = self.stack.enter_context(patch.object(dnschecks, 'require_ready'))
        self.process = self.stack.enter_context(patch.object(core.subprocess, 'run'))
        self.runner = self.stack.enter_context(patch.object(certbot_runner, 'run'))

    def issue(self):
        return core.issue(self.cfg, self.domain, self.zones, self.args)

    def test_normal_and_staging_preflight_failure_prevents_both_certbot_paths(self):
        self.check.side_effect = core.Error('DNS preflight blocked: caa_denied')
        for mode in ('fixed', 'adaptive'):
            self.cfg['dns_propagation'] = {'mode': mode}
            for staging in (False, True):
                self.args.dry_run = staging
                self.args.force_renew = True
                with self.subTest(mode=mode, staging=staging), self.assertRaisesRegex(core.Error, 'caa_denied'):
                    self.issue()
        self.process.assert_not_called()
        self.runner.assert_not_called()

    def test_invalid_configuration_and_credentials_precede_dns_or_process(self):
        self.cfg['propagation_seconds'] = True
        with self.assertRaises(core.Error): self.issue()
        self.cfg.pop('propagation_seconds')
        self.credentials.chmod(0o644)
        with self.assertRaises(storage.StorageError): self.issue()
        self.local.assert_not_called()
        self.check.assert_not_called()
        self.process.assert_not_called()
        self.runner.assert_not_called()

    def test_fixed_legacy_opt_out_and_propagation_are_preserved(self):
        self.cfg.update(dns_preflight=False, propagation_seconds=90)
        self.issue()
        self.check.assert_not_called()
        command = self.process.call_args.args[0]
        self.assertIn('--dns-cloudflare', command)
        self.assertEqual(command[command.index('--dns-cloudflare-propagation-seconds') + 1], '90')
        self.assertNotIn('--authenticator', command)
        self.runner.assert_not_called()

    def test_fixed_mode_cannot_ignore_adaptive_receipts_after_configuration_change(self):
        self.cfg['dns_preflight'] = False
        with patch.object(dnsauth, 'status', return_value=[{'id': 'pending'}]):
            with self.assertRaisesRegex(core.Error, '--dns-cleanup'):
                self.issue()
        self.local.assert_not_called()
        self.check.assert_not_called()
        self.process.assert_not_called()
        self.runner.assert_not_called()

    def test_adaptive_uses_plugin_for_single_and_multiple_accounts(self):
        self.cfg['dns_propagation'] = {'mode': 'adaptive'}
        for extra in (False, True):
            if extra:
                other = self.root / 'other.ini'
                other.write_text('dns_cloudflare_api_token = dummy_other\n')
                other.chmod(0o600)
                self.domain['names'].append('example.net')
                self.zones['example.net'] = {'credentials': str(other)}
                self.args.operation_lock_fd = 42
            self.args.dry_run = extra
            self.issue()
            command, cfg = self.runner.call_args.args
            self.assertEqual(cfg, self.cfg)
            self.assertEqual(command[command.index('--authenticator') + 1], 'cgp-dns')
            self.assertNotIn('--manual', command)
            self.assertNotIn('--dns-cloudflare', command)
            self.assertEqual('--dry-run' in command, extra)
            self.assertEqual(self.runner.call_args.kwargs['lock_fd'], 42 if extra else None)
        self.assertEqual(self.check.call_count, 2)
        self.process.assert_not_called()

    def test_existing_manual_auth_validates_before_dns_and_cleanup_remains_available(self):
        bad = {'cloudflare_credentials': 'one.ini', 'propagation_seconds': True}
        with patch.dict(os.environ, {'CERTBOT_IDENTIFIER': 'example.com', 'CERTBOT_VALIDATION': 'challenge'}, clear=True), \
                patch.object(cli, 'zones') as zones, patch.object(cli, 'cf') as cf:
            with self.assertRaises(core.Error): cli.hook(bad, False)
            zones.assert_not_called()
            cf.assert_not_called()
        metadata = '{"credentials":"one.ini","zone":"' + 'a' * 32 + '","record":"' + 'b' * 32 + '"}'
        with patch.dict(os.environ, {'CERTBOT_AUTH_OUTPUT': metadata}, clear=True), patch.object(cli, 'cf') as cf:
            cli.hook(bad, True)
        self.assertEqual(cf.call_args.kwargs['method'], 'DELETE')

    def test_cli_passes_held_lock_descriptor_to_issuance_context(self):
        config = self.root / 'config.json'
        state = self.root / 'state'
        core.atomic(config, self.cfg)

        def dispatch(args, cfg):
            fd = args.operation_lock_fd
            self.assertEqual(os.fstat(fd).st_ino, (state / 'run.lock').stat().st_ino)
            with self.assertRaises(BlockingIOError), storage.operation_lock(state):
                pass
            return 0

        with patch.object(cli, 'CONFIG', config), patch.object(cli, 'STATE', state), \
                patch.object(cli, 'locked_main', side_effect=dispatch), patch.object(cli.os, 'umask'), \
                patch.object(cli.sys, 'argv', ['cgp-letsencrypt']):
            self.assertEqual(cli.main(), 0)
