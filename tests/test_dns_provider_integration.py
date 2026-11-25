"""Provider selection reaches existing public flows without external effects."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cgp_cert_manager import certbot_runner, cli, core, dnsproviders, storage


class ProviderRoutingTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(patch.object(core, 'STATE', self.root / 'state'))
        self.files = [self.root / name for name in ('first.ini', 'second.ini')]
        for path in self.files:
            path.write_text('dns_cloudflare_api_token = SYNTHETIC\n')
            path.chmod(0o600)
        self.cfg = {'email': 'admin@example.com', 'cloudflare_accounts':
                    [{'credentials': str(path)} for path in self.files]}
        self.domain = {'cgp_domain': 'example.com', 'cert_name': 'example.com', 'names': ['example.com']}
        self.zones = {'example.com': {'id': 'a' * 32, 'credentials': str(self.files[0])},
                      'example.net': {'id': 'b' * 32, 'credentials': str(self.files[1])}}
        self.args = SimpleNamespace(force_renew=False, dry_run=False)
        self.local = self.enterContext(patch.object(core, 'local_info', return_value=None))
        self.preflight = self.enterContext(patch.object(core, 'dns_preflight'))
        self.process = self.enterContext(patch.object(core.subprocess, 'run'))
        self.runner = self.enterContext(patch.object(certbot_runner, 'run'))
        self.enterContext(patch.object(core, 'opener', side_effect=AssertionError('No external provider')))

    def issue(self):
        core.issue(self.cfg, self.domain, self.zones, self.args)

    def test_explicit_cloudflare_preserves_fixed_and_adaptive_commands(self):
        for mode in ('fixed', 'adaptive'):
            self.cfg['dns_propagation'] = {'mode': mode}
            for multiple in (False, True):
                self.domain['names'] = ['example.com', 'example.net'] if multiple else ['example.com']
                for staging in (False, True):
                    self.args.dry_run = staging
                    with self.subTest(mode=mode, multiple=multiple, staging=staging):
                        self.cfg.pop('dns_provider', None)
                        self.issue()
                        called = self.runner if mode == 'adaptive' else self.process
                        legacy = called.call_args.args[0]
                        self.cfg['dns_provider'] = 'cloudflare'
                        self.issue()
                        self.assertEqual(called.call_args.args[0], legacy)
                        self.assertNotIn('SYNTHETIC', str(legacy))
        self.assertFalse((self.root / 'state').exists())

    def test_unsupported_selection_refuses_discovery_and_issue_before_effects(self):
        for value in ('rfc2136', 'PRIVATE_PROVIDER', '', None, True, [], {}):
            cfg = {**self.cfg, 'dns_provider': value}
            with self.subTest(value=value), patch.object(core, 'cf') as transport, \
                    patch.object(core, 'cli') as cgp, patch.object(core, 'token') as token, \
                    patch.object(storage, 'check_private_file') as check:
                for operation in (lambda: core.zones(cfg),
                                  lambda: core.discover(cfg, self.zones),
                                  lambda: core.issue(cfg, self.domain, self.zones, self.args)):
                    with self.assertRaises(core.Error) as raised:
                        operation()
                    self.assertNotIn('PRIVATE_PROVIDER', str(raised.exception))
                transport.assert_not_called()
                cgp.assert_not_called()
                token.assert_not_called()
                check.assert_not_called()
        self.local.assert_not_called()
        self.preflight.assert_not_called()
        self.process.assert_not_called()
        self.runner.assert_not_called()

    def test_route_capability_refuses_before_private_reads_or_process_creation(self):
        provider_type = type(dnsproviders.get_provider({}))
        original = provider_type.capabilities
        for capability, mode, names in (
                ('fixed_native', 'fixed', ['example.com']),
                ('fixed_hooks', 'fixed', ['example.com', 'example.net']),
                ('owned_txt', 'adaptive', ['example.com'])):
            self.cfg['dns_propagation'] = {'mode': mode}
            self.domain['names'] = names
            with self.subTest(capability=capability), \
                    patch.object(provider_type, 'capabilities', original - {capability}), \
                    patch.object(storage, 'check_private_file') as check:
                with self.assertRaises(core.Error):
                    self.issue()
                check.assert_not_called()
        self.local.assert_not_called()
        self.preflight.assert_not_called()
        self.process.assert_not_called()
        self.runner.assert_not_called()

    def test_foreign_zone_binding_refuses_both_modes_before_credential_read(self):
        for mode in ('fixed', 'adaptive'):
            self.cfg['dns_propagation'] = {'mode': mode}
            for name in ('rfc2136', 'PRIVATE', None, True):
                self.zones['example.com']['provider'] = name
                with self.subTest(mode=mode, name=name), patch.object(storage, 'check_private_file') as check:
                    with self.assertRaisesRegex(core.Error, 'DNS zone provider mismatch'):
                        self.issue()
                    check.assert_not_called()
        self.zones['example.com']['provider'] = 'cloudflare'
        self.issue()
        self.runner.assert_called_once()


class FixedProviderHookTests(unittest.TestCase):
    def setUp(self):
        self.cfg = {'dns_provider': 'cloudflare', 'cloudflare_credentials': 'one.ini',
                    'propagation_seconds': 10}
        self.zone = {'id': 'a' * 32, 'credentials': 'one.ini'}
        self.metadata = {'credentials': 'one.ini', 'zone': 'a' * 32, 'record': 'b' * 32}
        self.enterContext(patch.object(core, 'opener', side_effect=AssertionError('No external provider')))

    def cleanup(self, metadata, cfg=None):
        with patch.dict(os.environ, {'CERTBOT_AUTH_OUTPUT': json.dumps(metadata)}, clear=True):
            cli.hook(self.cfg if cfg is None else cfg, True)

    def test_auth_emits_provider_binding_and_preserves_unowned_fixed_payload(self):
        with patch.dict(os.environ, {'CERTBOT_IDENTIFIER': '*.example.com', 'CERTBOT_VALIDATION': 'challenge'}, clear=True), \
                patch.object(cli, 'zones', return_value={'example.com': self.zone}), \
                patch.object(cli, 'cf', return_value={'result': {'id': 'b' * 32}}) as transport, \
                patch.object(cli.time, 'sleep') as sleep, contextlib.redirect_stdout(io.StringIO()) as output:
            cli.hook(self.cfg, False)
        self.assertEqual(json.loads(output.getvalue()), {**self.metadata, 'provider': 'cloudflare'})
        self.assertEqual(transport.call_args.kwargs['data'],
                         {'type': 'TXT', 'name': '_acme-challenge.example.com', 'content': 'challenge', 'ttl': 120})
        sleep.assert_called_once_with(10)

    def test_legacy_and_bound_cleanup_remain_available_with_bad_propagation(self):
        cfg = {**self.cfg, 'dns_propagation': {'mode': 'invalid'}, 'propagation_seconds': True}
        for metadata in (self.metadata, {**self.metadata, 'provider': 'cloudflare'}):
            with self.subTest(metadata=metadata), patch.object(cli, 'cf') as transport:
                self.cleanup(metadata, cfg)
                transport.assert_called_once_with('one.ini', 'zones/' + 'a' * 32 + '/dns_records/' + 'b' * 32,
                                                  method='DELETE', params=None, data=None)

    def test_unknown_provider_blocks_auth_and_old_cleanup_before_api_or_credentials(self):
        for cleanup in (False, True):
            cfg = {**self.cfg, 'dns_provider': 'PRIVATE_UNKNOWN'}
            with self.subTest(cleanup=cleanup), patch.object(cli, 'cf') as transport, \
                    patch.object(cli, 'zones') as zones, patch.object(core, 'token') as token:
                with patch.dict(os.environ, {'CERTBOT_AUTH_OUTPUT': json.dumps(self.metadata)}, clear=True), \
                        self.assertRaises(core.Error) as raised:
                    cli.hook(cfg, cleanup)
                self.assertNotIn('PRIVATE_UNKNOWN', str(raised.exception))
                transport.assert_not_called()
                zones.assert_not_called()
                token.assert_not_called()

    def test_old_cleanup_path_survives_account_migration_without_affecting_discovery(self):
        cfg = {**self.cfg, 'cloudflare_accounts': [{'credentials': 'two.ini'}, {'credentials': 'three.ini'}]}
        for metadata in (self.metadata, {**self.metadata, 'provider': 'cloudflare'}):
            with self.subTest(metadata=metadata), patch.object(cli, 'cf') as transport:
                self.cleanup(metadata, cfg)
                self.assertEqual(transport.call_args.args[0], 'one.ini')
                self.assertEqual(transport.call_args.kwargs['method'], 'DELETE')
        with patch.object(core, 'cf', return_value={'result': []}) as transport:
            self.assertEqual(core.zones(cfg), {})
        self.assertEqual([call.args[0] for call in transport.call_args_list], ['two.ini', 'three.ini'])

    def test_foreign_ambiguous_or_malformed_cleanup_metadata_never_deletes(self):
        cases = [None, [], 'PRIVATE', {}, {**self.metadata, 'provider': 'rfc2136'},
                 {**self.metadata, 'provider': None}, {**self.metadata, 'extra': 'PRIVATE'},
                 {**self.metadata, 'credentials': []}, {**self.metadata, 'credentials': 'foreign.ini'},
                 {**self.metadata, 'zone': None}, {**self.metadata, 'record': False},
                 {**self.metadata, 'record': 'not-an-id'}]
        for metadata in cases:
            with self.subTest(metadata=metadata), patch.object(cli, 'cf') as transport:
                with self.assertRaisesRegex(core.Error, 'Invalid cleanup metadata'):
                    self.cleanup(metadata)
                transport.assert_not_called()

    def test_auth_refuses_foreign_provider_or_unconfigured_credential_binding(self):
        for updates in ({'provider': 'rfc2136'}, {'provider': None}, {'credentials': 'foreign.ini'}):
            with self.subTest(updates=updates), \
                    patch.dict(os.environ, {'CERTBOT_DOMAIN': 'example.com', 'CERTBOT_VALIDATION': 'challenge'}, clear=True), \
                    patch.object(cli, 'zones', return_value={'example.com': {**self.zone, **updates}}), \
                    patch.object(cli, 'cf') as transport, patch.object(cli.time, 'sleep') as sleep:
                with self.assertRaisesRegex(core.Error, 'Invalid DNS challenge zone'):
                    cli.hook(self.cfg, False)
                transport.assert_not_called()
                sleep.assert_not_called()

    def test_entrypoint_refuses_unsupported_hook_before_creating_state(self):
        cfg = {**self.cfg, 'schema_version': 2, 'dns_provider': 'rfc2136'}
        with patch.object(cli.sys, 'argv', ['cgp-letsencrypt', '--hook-cleanup']), \
                patch.object(cli.os, 'umask') as umask, \
                patch.object(cli, 'load', return_value=cfg), \
                patch.object(storage, 'ensure_private_directory') as create, \
                patch.object(cli, 'cf') as transport, self.assertRaises(core.Error):
            cli.main()
        umask.assert_called_once_with(0o077)
        create.assert_not_called()
        transport.assert_not_called()


if __name__ == '__main__':
    unittest.main()
