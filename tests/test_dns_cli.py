"""Read-only DNS CLI dispatch through real configuration and reports routing."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cgp_cert_manager import cli, core, dnschecks, storage


class DNSCLITests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.state = self.root / 'state'
        self.config = self.root / 'config.json'
        self.cfg = {'schema_version': 1, 'email': 'admin@example.com'}
        core.atomic(self.config, self.cfg)
        self.before = self.config.read_bytes()
        for module, name, value in ((cli, 'CONFIG', self.config), (cli, 'STATE', self.state),
                                    (core, 'STATE', self.state)):
            self.stack.enter_context(patch.object(module, name, value))
        self.stack.enter_context(patch.object(cli.os, 'umask'))
        self.out = io.StringIO()
        self.stack.enter_context(contextlib.redirect_stdout(self.out))
        self.stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
        self.zones = self.stack.enter_context(patch.object(core, 'zones', return_value={'example.com': {}}))
        self.discover = self.stack.enter_context(patch.object(core, 'discover', return_value=[{'cgp_domain': 'example.com'}]))
        self.row = {'domain': 'example.com', 'ready': True, 'preflight_enabled': True, 'checks': [], 'reason': None}
        self.inspect = self.stack.enter_context(patch.object(dnschecks, 'inspect', return_value=self.row))
        self.forbidden = [self.stack.enter_context(patch.object(module, name)) for module, name in (
            (storage, 'operation_lock'), (storage, 'validate_tree'), (storage.os, 'fsync'),
            (cli, 'migrate'), (cli, 'atomic'), (cli, 'notify'), (cli, 'history'),
            (cli, 'issue'), (cli, 'deploy'), (cli, 'current'), (core, 'update'),
            (cli.deployment, 'recover_pending'), (cli.bootstrap, 'inspect'),
        )]

    def invoke(self, *args):
        self.out.seek(0); self.out.truncate()
        with patch.object(cli.sys, 'argv', ['cgp-letsencrypt', '--dns-check', *args]):
            return cli.main()

    def assert_read_only(self):
        for forbidden in self.forbidden:
            forbidden.assert_not_called()
        self.assertFalse(self.state.exists())
        self.assertEqual(self.config.read_bytes(), self.before)

    def test_json_is_exact_public_report_and_configuration_is_not_migrated(self):
        self.assertEqual(self.invoke('--domain', 'example.com', '--json'), 0)
        self.assertEqual(json.loads(self.out.getvalue()), [self.row])
        self.inspect.assert_called_once_with({'cgp_domain': 'example.com'}, {'example.com': {}}, self.cfg)
        self.assert_read_only()

    def test_text_ready_blocked_and_empty_results(self):
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(self.out.getvalue(), 'example.com: DNS ready=yes; reason=none\n')
        self.row.update(ready=False, reason='dnssec_bogus')
        self.assertEqual(self.invoke(), 1)
        self.assertEqual(self.out.getvalue(), 'example.com: DNS ready=no; reason=dnssec_bogus\n')
        self.discover.return_value = []
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(self.out.getvalue(), 'No CGP domains\n')
        self.assertEqual(self.invoke('--json'), 0)
        self.assertEqual(json.loads(self.out.getvalue()), [])
        self.assert_read_only()

    def test_domain_and_conflicting_flags_fail_before_configuration_or_network(self):
        cases = [('--domain', name) for name in ('', '../bad', 'bad name', 'bad\n')]
        cases += [(flag,) for flag in ('--bootstrap-check', '--status', '--recover', '--dry-run', '--migrate')]
        with patch.object(cli, 'load') as load:
            for args in cases:
                with self.subTest(args=args), self.assertRaises(SystemExit) as caught:
                    self.invoke(*args)
                self.assertEqual(caught.exception.code, 2)
            load.assert_not_called()
        self.zones.assert_not_called()
        self.assert_read_only()

    def test_invalid_dns_configuration_fails_before_external_reads(self):
        # Write before installing the no-write guards so production validation
        # still reads an actual private file, rather than a mocked configuration.
        self.config.write_text(json.dumps({'dns_propagation': {'mode': 'adaptive'}, 'dns_preflight': False}))
        self.before = self.config.read_bytes()
        with self.assertRaisesRegex(core.Error, 'requires preflight'):
            self.invoke()
        self.zones.assert_not_called()
        self.discover.assert_not_called()
        self.inspect.assert_not_called()
        self.assert_read_only()

    def test_unsafe_configuration_is_rejected(self):
        self.config.chmod(0o644)
        with self.assertRaises(storage.StorageError):
            self.invoke()
        self.zones.assert_not_called()
        self.assert_read_only()

    def test_existing_broken_state_is_not_read_or_repaired(self):
        self.state.symlink_to(self.root / 'missing-state')
        self.assertEqual(self.invoke('--json'), 0)
        self.assertTrue(self.state.is_symlink())
        self.assert_read_only()
