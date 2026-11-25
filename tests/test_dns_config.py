"""DNS configuration validation is deterministic and has no external effects."""
import copy
import unittest
from unittest.mock import Mock, patch

from cgp_cert_manager import core, dnsconfig, dnsproviders, tui


class DNSConfigTests(unittest.TestCase):
    def test_legacy_defaults_and_fixed_opt_out_do_not_modify_input(self):
        cfg = {'unrelated': {'keep': True}}
        before = copy.deepcopy(cfg)
        self.assertEqual(dnsconfig.validate(cfg), {
            'mode': 'fixed', 'preflight': True, 'propagation_seconds': 60,
            'timeout_seconds': 300, 'poll_interval_seconds': 5,
        })
        self.assertEqual(cfg, before)
        self.assertFalse(dnsconfig.validate({'dns_preflight': False})['preflight'])
        self.assertEqual(dnsconfig.validate(tui.default_config())['mode'], 'fixed')

    def test_adaptive_and_numeric_boundaries(self):
        for propagation, timeout, poll in ((10, 30, 1), (3600, 3600, 60)):
            cfg = {'propagation_seconds': propagation, 'dns_propagation': {
                'mode': 'adaptive', 'timeout_seconds': timeout, 'poll_interval_seconds': poll}}
            before = copy.deepcopy(cfg)
            options = dnsconfig.validate(cfg)
            self.assertEqual(options['mode'], 'adaptive')
            self.assertEqual(options['propagation_seconds'], propagation)
            self.assertEqual(options['timeout_seconds'], timeout)
            self.assertEqual(options['poll_interval_seconds'], poll)
            self.assertEqual(cfg, before)

    def test_explicit_cloudflare_preserves_legacy_options_without_credentials_or_io(self):
        for mode in ('fixed', 'adaptive'):
            legacy = {'dns_propagation': {'mode': mode}, 'unrelated': {'retain': True}}
            explicit = {**copy.deepcopy(legacy), 'dns_provider': 'cloudflare'}
            before = copy.deepcopy(explicit)
            with patch.object(core, 'token') as token, patch.object(core, 'cf') as request:
                self.assertEqual(dnsconfig.validate(explicit), dnsconfig.validate(legacy))
            token.assert_not_called()
            request.assert_not_called()
            self.assertEqual(explicit, before)

    def test_unknown_or_malformed_provider_refuses_without_echoing_or_reading_credentials(self):
        values = ('PRIVATE_PROVIDER', '', 'Cloudflare', ' cloudflare', 'cloudflare ',
                  None, True, False, 0, 1, [], {}, {'name': 'cloudflare'})
        with patch.object(core, 'token') as token, patch.object(core, 'cf') as request:
            for value in values:
                cfg = {'dns_provider': value, 'cloudflare_credentials': '/PRIVATE/credentials.ini'}
                before = copy.deepcopy(cfg)
                with self.subTest(value=value), self.assertRaises(dnsconfig.DNSConfigError) as raised:
                    dnsconfig.validate(cfg)
                self.assertEqual(str(raised.exception), 'Unsupported DNS provider')
                self.assertIsInstance(raised.exception, ValueError)
                self.assertEqual(cfg, before)
        token.assert_not_called()
        request.assert_not_called()

    def test_adaptive_requires_ownership_support_but_fixed_routing_is_checked_at_issuance(self):
        provider = Mock()
        provider.require.side_effect = dnsproviders.ProviderError('PRIVATE capability detail')
        with patch.object(dnsproviders, 'get_provider', return_value=provider):
            self.assertEqual(dnsconfig.validate({})['mode'], 'fixed')
            provider.require.assert_not_called()
            with self.assertRaises(dnsconfig.DNSConfigError) as raised:
                dnsconfig.validate({'dns_propagation': {'mode': 'adaptive'}})
        provider.require.assert_called_once_with('owned_txt')
        self.assertEqual(str(raised.exception), 'DNS provider lacks required capability')

    def test_shapes_and_unknown_keys_are_rejected_without_echoing_values(self):
        cases = [None, [], 'PRIVATE_VALUE', {'dns_propagation': None},
                 {'dns_propagation': []}, {'dns_propagation': {'PRIVATE_VALUE': True}}]
        cases += [{'dns_propagation': {'mode': value}}
                  for value in ('PRIVATE_VALUE', None, True, [], {})]
        for cfg in cases:
            with self.subTest(cfg=cfg), self.assertRaises(dnsconfig.DNSConfigError) as error:
                dnsconfig.validate(cfg)
            self.assertIsInstance(error.exception, core.Error)
            self.assertIsInstance(error.exception, ValueError)
            self.assertNotIn('PRIVATE_VALUE', str(error.exception))

    def test_integer_ranges_reject_booleans_coercions_and_nonfinite_numbers(self):
        for name, low, high in (('propagation_seconds', 10, 3600),
                                ('timeout_seconds', 30, 3600),
                                ('poll_interval_seconds', 1, 60)):
            for value in (False, True, str(low), low - 1, high + 1, float(low),
                          float('inf'), None, [], 'PRIVATE_VALUE'):
                cfg = {name: value} if name == 'propagation_seconds' else {'dns_propagation': {name: value}}
                with self.subTest(name=name, value=value), self.assertRaisesRegex(dnsconfig.DNSConfigError, name):
                    dnsconfig.validate(cfg)

    def test_preflight_and_polling_relationships(self):
        for value in (0, 1, 'true', None, [], {}):
            with self.subTest(value=value), self.assertRaisesRegex(dnsconfig.DNSConfigError, 'boolean'):
                dnsconfig.validate({'dns_preflight': value})
        for poll in (30, 60):
            with self.assertRaisesRegex(dnsconfig.DNSConfigError, 'less than timeout'):
                dnsconfig.validate({'dns_propagation': {'timeout_seconds': 30, 'poll_interval_seconds': poll}})
        with self.assertRaisesRegex(dnsconfig.DNSConfigError, 'requires preflight'):
            dnsconfig.validate({'dns_preflight': False, 'dns_propagation': {'mode': 'adaptive'}})

    def test_wizard_validates_json_only_dns_options_and_preserves_them(self):
        cfg = tui.default_config()
        cfg.update(email='admin@example.com', dns_propagation={'mode': 'adaptive'}, dns_provider='cloudflare')
        cfg['communigate'].update(username='admin', password='dummy')
        before = copy.deepcopy(cfg)
        tui.validate(cfg)
        self.assertEqual(cfg, before)
        cfg['dns_preflight'] = False
        with self.assertRaisesRegex(ValueError, 'requires preflight'):
            tui.validate(cfg)
