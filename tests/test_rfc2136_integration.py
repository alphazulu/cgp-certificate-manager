"""Explicit RFC2136 selection reaches public flows without external effects."""
import base64
from copy import deepcopy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import dns.query

from cgp_cert_manager import (certbot_runner, cli, core, dnschecks, dnsconfig,
                              dnsproviders, installer, rfc2136_config, storage, tui)


class RFC2136IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.secret = self.root / 'tsig.json'
        storage.atomic_json(self.secret, {'secret': base64.b64encode(b'S' * 32).decode('ascii')})
        self.cfg = {'schema_version': 2, 'email': 'admin@example.com', 'domains': [],
                    'communigate': {'url': 'http://127.0.0.1:8100/CLI/', 'username': 'admin', 'password': 'dummy'},
                    'dns_provider': 'rfc2136', 'dns_preflight': True,
                    'dns_propagation': {'mode': 'adaptive'},
                    'rfc2136': {'zones': [{'zone': 'example.com', 'server': '192.0.2.53',
                        'credentials': str(self.secret), 'key_name': 'cgp.example.com',
                        'nameservers': ['ns1.example.com', 'ns2.example.com']}]}}
        self.state = self.root / 'state'
        self.enterContext(patch.object(core, 'STATE', self.state))
        self.enterContext(patch.object(cli, 'STATE', self.state))
        self.transport = self.enterContext(patch.object(dns.query, 'tcp', side_effect=AssertionError('No DNS networking')))
        self.cloudflare = self.enterContext(patch.object(core, 'cf', side_effect=AssertionError('No Cloudflare API')))
        self.cloudflare_token = self.enterContext(patch.object(core, 'token', side_effect=AssertionError('No Cloudflare credentials')))
        self.addCleanup(self.transport.assert_not_called)
        self.addCleanup(self.cloudflare.assert_not_called)
        self.addCleanup(self.cloudflare_token.assert_not_called)

    def test_configured_zone_inventory_is_pure_and_ignores_cloudflare_http_transport(self):
        before = deepcopy(self.cfg)
        self.secret.unlink()
        with patch.object(rfc2136_config, 'read_secret') as secret:
            provider = dnsproviders.get_provider(self.cfg, transport=self.cloudflare)
            zones = core.zones(self.cfg)
            paths = dnsproviders.credentials(self.cfg, absolute=True)
        self.assertEqual(provider.name, 'rfc2136')
        self.assertEqual(provider.capabilities, frozenset({'zone_discovery', 'owned_txt'}))
        self.assertEqual(set(zones), {'example.com'})
        row = zones['example.com']
        self.assertEqual(set(row), {'id', 'credentials', 'ns', 'provider'})
        self.assertEqual(row['provider'], 'rfc2136')
        self.assertEqual(row['credentials'], str(self.secret))
        self.assertEqual(row['ns'], ['ns1.example.com', 'ns2.example.com'])
        self.assertRegex(row['id'], r'^[0-9a-f]{64}$')
        self.assertEqual(paths, (str(self.secret),))
        secret.assert_not_called()
        self.assertEqual(self.cfg, before)
        self.assertFalse(self.state.exists())

    def test_adaptive_configuration_keeps_shared_option_shape_without_secret_reads(self):
        before = deepcopy(self.cfg)
        with patch.object(rfc2136_config, 'read_secret') as secret:
            options = dnsconfig.validate(self.cfg)
        self.assertEqual(options, {'mode': 'adaptive', 'preflight': True,
                                  'propagation_seconds': 60, 'timeout_seconds': 300, 'poll_interval_seconds': 5})
        secret.assert_not_called()
        self.assertEqual(self.cfg, before)

    def test_fixed_modes_and_disabled_preflight_are_refused_before_effects(self):
        for mode in (None, 'fixed'):
            cfg = deepcopy(self.cfg)
            if mode is None:
                del cfg['dns_propagation']
            else:
                cfg['dns_propagation']['mode'] = mode
            with self.subTest(mode=mode), patch.object(rfc2136_config, 'read_secret') as secret:
                with self.assertRaisesRegex(dnsconfig.DNSConfigError, 'RFC2136 requires adaptive'):
                    dnsconfig.validate(cfg)
                secret.assert_not_called()
        cfg = {**self.cfg, 'dns_preflight': False}
        with self.assertRaisesRegex(dnsconfig.DNSConfigError, 'requires preflight'):
            dnsconfig.validate(cfg)
        self.assertFalse(self.state.exists())

    def test_invalid_provider_configuration_refuses_before_discovery_or_credentials(self):
        cfg = {**self.cfg, 'rfc2136': {'zones': []}}
        with patch.object(core, 'cli') as cgp, patch.object(rfc2136_config, 'read_secret') as secret:
            for operation in (dnsproviders.get_provider, dnsproviders.credentials, dnsconfig.validate,
                              core.zones, lambda data: core.discover(data, {})):
                with self.subTest(operation=operation), self.assertRaises(core.Error) as error:
                    operation(cfg)
                self.assertIn('RFC2136', str(error.exception))
            cgp.assert_not_called()
            secret.assert_not_called()
        self.assertFalse(self.state.exists())

    def test_issuance_uses_supervised_adaptive_plugin_and_preserves_staging_boundary(self):
        domain = {'cgp_domain': 'example.com', 'cert_name': 'example.com',
                  'names': ['example.com', '*.example.com']}
        zones = core.zones(self.cfg)
        for staging in (False, True):
            args = SimpleNamespace(force_renew=False, dry_run=staging)
            with self.subTest(staging=staging), patch.object(core, 'local_info', return_value=None), \
                    patch.object(core, 'dns_preflight') as preflight, \
                    patch.object(certbot_runner, 'run') as runner, \
                    patch.object(core.subprocess, 'run') as direct:
                core.issue(self.cfg, domain, zones, args)
                preflight.assert_called_once_with(domain, zones, self.cfg)
                command = runner.call_args.args[0]
                self.assertEqual(command[command.index('--authenticator') + 1], 'cgp-dns')
                self.assertNotIn('--dns-cloudflare', command)
                self.assertNotIn(str(self.secret), command)
                self.assertNotIn('192.0.2.53', command)
                self.assertEqual('--server' in command, staging)
                if staging:
                    self.assertEqual(command[command.index('--server') + 1],
                                     'https://acme-staging-v02.api.letsencrypt.org/directory')
                direct.assert_not_called()
        self.assertFalse(self.state.exists())

    def test_unmarked_or_foreign_zone_source_is_refused_before_private_file_read(self):
        domain = {'cgp_domain': 'example.com', 'names': ['example.com']}
        args = SimpleNamespace(force_renew=False, dry_run=False)
        for provider in (None, 'cloudflare'):
            zones = core.zones(self.cfg)
            if provider is None:
                zones['example.com'].pop('provider')
            else:
                zones['example.com']['provider'] = provider
            with self.subTest(provider=provider), patch.object(storage, 'check_private_file') as private, \
                    patch.object(certbot_runner, 'run') as runner:
                with self.assertRaisesRegex(core.Error, 'DNS zone provider mismatch'):
                    core.issue(self.cfg, domain, zones, args)
                private.assert_not_called()
                runner.assert_not_called()

    def test_fixed_hooks_refuse_rfc2136_before_metadata_or_any_secret_access(self):
        for cleanup in (False, True):
            with self.subTest(cleanup=cleanup), patch.object(rfc2136_config, 'read_secret') as secret:
                with self.assertRaisesRegex(core.Error, 'capability unavailable'):
                    cli.hook(self.cfg, cleanup)
                secret.assert_not_called()

    def test_hook_entrypoint_refuses_unsupported_route_before_creating_state(self):
        with patch.object(cli.sys, 'argv', ['cgp-letsencrypt', '--hook-cleanup']), \
                patch.object(cli, 'load', return_value=self.cfg), patch.object(cli.os, 'umask') as mask, \
                patch.object(storage, 'ensure_private_directory') as create:
            with self.assertRaisesRegex(core.Error, 'capability unavailable'):
                cli.main()
        mask.assert_called_once_with(0o077)
        create.assert_not_called()

    def installer_context(self):
        self.enterContext(patch.object(core, 'load', return_value=self.cfg))
        self.enterContext(patch.object(installer, 'MONITOR_CONFIG', self.root / 'monitor.json'))
        self.enterContext(patch.object(installer, 'MONITOR_STATE', self.root / 'monitor-state'))

    def test_installer_preflight_reads_rfc_secret_without_cloudflare_or_state_creation(self):
        self.installer_context()
        with patch.object(installer, 'runtime_dependencies') as dependencies:
            installer.preflight()
        self.assertEqual(dependencies.call_args.args[0]['mode'], 'adaptive')
        self.assertFalse(self.state.exists())
        self.assertFalse((self.root / 'monitor-state').exists())

    def test_installer_rejects_fixed_rfc_before_runtime_or_secret_checks(self):
        self.installer_context()
        self.cfg['dns_propagation']['mode'] = 'fixed'
        with patch.object(installer, 'runtime_dependencies') as dependencies, \
                patch.object(rfc2136_config, 'read_secret') as secret:
            with self.assertRaisesRegex(core.Error, 'requires adaptive'):
                installer.preflight()
        dependencies.assert_not_called()
        secret.assert_not_called()

    def test_installer_refuses_invalid_secret_without_starting_installation(self):
        self.installer_context()
        storage.atomic_json(self.secret, {'secret': 'PRIVATE_SECRET'})
        with patch.object(installer, 'runtime_dependencies'), patch.object(installer.subprocess, 'run') as payload:
            with self.assertRaises(core.Error) as error:
                installer.preflight()
        self.assertNotIn('PRIVATE_SECRET', str(error.exception))
        payload.assert_not_called()

    def test_cloudflare_wizard_refuses_rfc_configuration_before_menu_or_token_staging(self):
        before = deepcopy(self.cfg)
        with patch.object(core, 'load', return_value=self.cfg), patch.object(tui.tempfile, 'TemporaryDirectory') as temporary, \
                patch.object(tui, 'main_menu') as menu, patch.object(rfc2136_config, 'read_secret') as secret:
            with self.assertRaisesRegex(core.Error, 'manual JSON editing'):
                tui.edit()
        temporary.assert_not_called()
        menu.assert_not_called()
        secret.assert_not_called()
        self.assertEqual(self.cfg, before)

    def test_dns_diagnostics_receive_explicit_inventory_without_secret_reads(self):
        domain = {'cgp_domain': 'example.com', 'names': ['example.com']}
        with patch.object(core, 'discover', return_value=[domain]), \
                patch.object(dnschecks, 'inspect', return_value={'ready': True}) as inspect, \
                patch.object(rfc2136_config, 'read_secret') as secret:
            self.assertEqual(dnschecks.reports(self.cfg), [{'ready': True}])
        self.assertEqual(inspect.call_args.args[1]['example.com']['ns'], ['ns1.example.com', 'ns2.example.com'])
        secret.assert_not_called()


if __name__ == '__main__':
    unittest.main()
