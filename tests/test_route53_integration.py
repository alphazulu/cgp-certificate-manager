"""Route53 selection reaches adaptive public flows without real AWS effects."""
from copy import deepcopy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cgp_cert_manager import (certbot_runner, cli, core, dnschecks, dnsconfig,
                              dnsproviders, installer, route53_api,
                              route53_config, storage, tui)


class Route53IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.secret = self.root / 'aws.json'
        storage.atomic_json(self.secret, {'access_key_id': 'AKIA' + 'A' * 16,
                                         'secret_access_key': 'S' * 40})
        self.cfg = {'schema_version': 2, 'email': 'admin@example.com', 'domains': [],
                    'communigate': {'url': 'http://127.0.0.1:8100/CLI/', 'username': 'admin', 'password': 'dummy'},
                    'dns_provider': 'route53', 'dns_preflight': True,
                    'dns_propagation': {'mode': 'adaptive'},
                    'route53': {'zones': [{'zone': 'example.com', 'hosted_zone_id': 'ZEXAMPLE123',
                        'account_id': '123456789012', 'credentials': str(self.secret),
                        'nameservers': ['ns1.example.com', 'ns2.example.com']}]}}
        self.state = self.root / 'state'
        self.enterContext(patch.object(core, 'STATE', self.state))
        self.enterContext(patch.object(cli, 'STATE', self.state))
        self.aws = self.enterContext(patch.object(route53_api, 'Client', side_effect=AssertionError('No AWS access')))
        self.cf = self.enterContext(patch.object(core, 'cf', side_effect=AssertionError('No Cloudflare API')))
        self.token = self.enterContext(patch.object(core, 'token', side_effect=AssertionError('No Cloudflare key')))
        for operation in (self.aws, self.cf, self.token):
            self.addCleanup(operation.assert_not_called)

    def test_explicit_inventory_and_credentials_are_pure_and_do_not_use_cloudflare_transport(self):
        before = deepcopy(self.cfg)
        self.secret.unlink()
        with patch.object(route53_config, 'read_secret') as secret:
            provider = dnsproviders.get_provider(self.cfg, transport=self.cf)
            zones = core.zones(self.cfg)
            paths = dnsproviders.credentials(self.cfg, absolute=True)
        self.assertEqual(provider.name, 'route53')
        self.assertEqual(provider.provider_id, 'route53')
        self.assertEqual(provider.capabilities, frozenset({'zone_discovery', 'owned_txt'}))
        self.assertEqual(set(zones), {'example.com'})
        self.assertEqual(set(zones['example.com']), {'id', 'credentials', 'ns', 'provider'})
        self.assertEqual(zones['example.com']['provider'], 'route53')
        self.assertRegex(zones['example.com']['id'], r'^[0-9a-f]{64}$')
        self.assertEqual(zones['example.com']['credentials'], str(self.secret))
        self.assertEqual(zones['example.com']['ns'], ['ns1.example.com', 'ns2.example.com'])
        self.assertEqual(paths, (str(self.secret),))
        secret.assert_not_called()
        self.assertEqual(self.cfg, before)
        self.assertFalse(self.state.exists())

    def test_adaptive_config_retains_shared_shape_without_reading_keys(self):
        before = deepcopy(self.cfg)
        with patch.object(route53_config, 'read_secret') as secret:
            result = dnsconfig.validate(self.cfg)
        self.assertEqual(result, {'mode': 'adaptive', 'preflight': True,
                                 'propagation_seconds': 60, 'timeout_seconds': 300,
                                 'poll_interval_seconds': 5})
        self.assertEqual(self.cfg, before)
        secret.assert_not_called()

    def test_fixed_modes_and_disabled_preflight_refuse_before_secret_access(self):
        for mode in (None, 'fixed'):
            cfg = deepcopy(self.cfg)
            if mode is None:
                cfg.pop('dns_propagation')
            else:
                cfg['dns_propagation']['mode'] = mode
            with self.subTest(mode=mode), patch.object(route53_config, 'read_secret') as secret:
                with self.assertRaisesRegex(dnsconfig.DNSConfigError, '^Route53 requires adaptive DNS propagation$'):
                    dnsconfig.validate(cfg)
                secret.assert_not_called()
        with self.assertRaisesRegex(dnsconfig.DNSConfigError, 'requires preflight'):
            dnsconfig.validate({**self.cfg, 'dns_preflight': False})
        self.assertFalse(self.state.exists())

    def test_invalid_target_refuses_factory_config_inventory_and_cgp_discovery(self):
        cfg = {**self.cfg, 'route53': {'zones': []}}
        with patch.object(route53_config, 'read_secret') as secret, patch.object(core, 'cli') as cgp:
            for operation in (dnsproviders.get_provider, dnsproviders.credentials, dnsconfig.validate,
                              core.zones, lambda value: core.discover(value, {})):
                with self.subTest(operation=operation), self.assertRaisesRegex(core.Error, 'Route53'):
                    operation(cfg)
            secret.assert_not_called()
            cgp.assert_not_called()
        self.assertFalse(self.state.exists())

    def test_issuance_uses_supervised_adaptive_plugin_without_exposing_aws_details(self):
        domain = {'cgp_domain': 'example.com', 'cert_name': 'example.com',
                  'names': ['example.com', '*.example.com']}
        zones = core.zones(self.cfg)
        for staging in (False, True):
            with self.subTest(staging=staging), patch.object(core, 'local_info', return_value=None), \
                    patch.object(core, 'dns_preflight') as preflight, patch.object(certbot_runner, 'run') as runner, \
                    patch.object(core.subprocess, 'run') as direct:
                core.issue(self.cfg, domain, zones, SimpleNamespace(force_renew=False, dry_run=staging))
                preflight.assert_called_once_with(domain, zones, self.cfg)
                command = runner.call_args.args[0]
                self.assertEqual(command[command.index('--authenticator') + 1], 'cgp-dns')
                self.assertNotIn('--dns-cloudflare', command)
                for private in (str(self.secret), '123456789012', 'ZEXAMPLE123'):
                    self.assertNotIn(private, command)
                self.assertEqual('--server' in command, staging)
                if staging:
                    self.assertEqual(command[command.index('--server') + 1],
                                     'https://acme-staging-v02.api.letsencrypt.org/directory')
                direct.assert_not_called()
        self.assertFalse(self.state.exists())

    def test_missing_or_foreign_provider_tag_refuses_before_private_access(self):
        domain = {'cgp_domain': 'example.com', 'names': ['example.com']}
        for other in (None, 'cloudflare', 'rfc2136'):
            zones = core.zones(self.cfg)
            if other is None:
                zones['example.com'].pop('provider')
            else:
                zones['example.com']['provider'] = other
            with self.subTest(other=other), patch.object(storage, 'check_private_file') as private, \
                    patch.object(certbot_runner, 'run') as runner:
                with self.assertRaisesRegex(core.Error, 'DNS zone provider mismatch'):
                    core.issue(self.cfg, domain, zones, SimpleNamespace(force_renew=False, dry_run=False))
                private.assert_not_called()
                runner.assert_not_called()

    def test_fixed_hooks_refuse_before_metadata_credentials_or_state(self):
        for cleanup in (False, True):
            with self.subTest(cleanup=cleanup), patch.object(route53_config, 'read_secret') as secret:
                with self.assertRaisesRegex(core.Error, 'capability unavailable'):
                    cli.hook(self.cfg, cleanup)
                secret.assert_not_called()
        with patch.object(cli.sys, 'argv', ['cgp-letsencrypt', '--hook-auth']), \
                patch.object(cli, 'load', return_value=self.cfg), patch.object(cli.os, 'umask'), \
                patch.object(storage, 'ensure_private_directory') as create:
            with self.assertRaisesRegex(core.Error, 'capability unavailable'):
                cli.main()
        create.assert_not_called()
        self.assertFalse(self.state.exists())

    def installer_context(self):
        self.enterContext(patch.object(core, 'load', return_value=self.cfg))
        self.enterContext(patch.object(installer, 'MONITOR_CONFIG', self.root / 'monitor.json'))
        self.enterContext(patch.object(installer, 'MONITOR_STATE', self.root / 'monitor-state'))

    def test_installer_reads_private_aws_json_without_api_or_state_creation(self):
        self.installer_context()
        with patch.object(installer, 'runtime_dependencies') as dependencies:
            installer.preflight()
        self.assertEqual(dependencies.call_args.args[0]['mode'], 'adaptive')
        self.assertFalse(self.state.exists())
        self.assertFalse((self.root / 'monitor-state').exists())

    def test_installer_refuses_fixed_mode_before_dependency_or_secret_checks(self):
        self.installer_context()
        self.cfg['dns_propagation']['mode'] = 'fixed'
        with patch.object(installer, 'runtime_dependencies') as dependencies, \
                patch.object(route53_config, 'read_secret') as secret:
            with self.assertRaisesRegex(core.Error, 'requires adaptive'):
                installer.preflight()
        dependencies.assert_not_called()
        secret.assert_not_called()

    def test_installer_refuses_invalid_keys_without_starting_payload(self):
        self.installer_context()
        storage.atomic_json(self.secret, {'secret_access_key': 'PRIVATE_SECRET'})
        with patch.object(installer, 'runtime_dependencies'), patch.object(installer.subprocess, 'run') as payload:
            with self.assertRaises(core.Error) as error:
                installer.preflight()
        self.assertNotIn('PRIVATE_SECRET', str(error.exception))
        payload.assert_not_called()

    def test_cloudflare_editor_refuses_before_menu_and_temporary_key_staging(self):
        before = deepcopy(self.cfg)
        with patch.object(core, 'load', return_value=self.cfg), \
                patch.object(tui.tempfile, 'TemporaryDirectory') as temporary, \
                patch.object(tui, 'main_menu') as menu, patch.object(route53_config, 'read_secret') as secret:
            with self.assertRaisesRegex(core.Error, 'manual JSON editing'):
                tui.edit()
        temporary.assert_not_called()
        menu.assert_not_called()
        secret.assert_not_called()
        self.assertEqual(self.cfg, before)

    def test_dns_checks_receive_configured_ns_inventory_without_aws_access(self):
        domain = {'cgp_domain': 'example.com', 'names': ['example.com']}
        with patch.object(core, 'discover', return_value=[domain]), \
                patch.object(dnschecks, 'inspect', return_value={'ready': True}) as inspect, \
                patch.object(route53_config, 'read_secret') as secret:
            self.assertEqual(dnschecks.reports(self.cfg), [{'ready': True}])
        self.assertEqual(inspect.call_args.args[1]['example.com']['ns'], ['ns1.example.com', 'ns2.example.com'])
        secret.assert_not_called()


if __name__ == '__main__':
    unittest.main()
