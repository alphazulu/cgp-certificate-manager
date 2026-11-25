"""Explicit offline update CLI routing and safe public failure projection."""
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import runpy
import socket
import subprocess
import sys
from types import ModuleType
import unittest
from unittest.mock import Mock, patch
import warnings

import cgp_cert_manager
from cgp_cert_manager import __version__, update_cli as cli


PLAN = {
    'plan_id': '0' * 64, 'project': 'cgp-certificate-manager', 'channel': 'stable', 'sequence': 1,
    'installed_version': '2.2.0', 'target_version': '2.3.0', 'key_id': '1' * 64,
    'manifest_sha256': '2' * 64, 'archive_sha256': '3' * 64, 'archive_size': 4096,
    'source_commit': '4' * 40, 'source_tree': '5' * 40, 'release_tag': 'v2.3.0',
    'issued_at': 1700000000, 'expires_at': 1700086400, 'file_count': 12,
    'total_bytes': 8192, 'inventory_sha256': '6' * 64, 'created_at': 1700000001,
    'apply_supported': False,
}


def response(action, status, plan=None, error=None):
    return {'schema': 1, 'action': action, 'status': status, 'plan': plan, 'error': error}


class UpdateCLITests(unittest.TestCase):
    def setUp(self):
        self.backend = ModuleType('cgp_cert_manager.update_plan')
        self.backend.check = Mock(return_value=response('check', 'verified', deepcopy(PLAN)))
        self.backend.prepare = Mock(return_value=response('prepare', 'prepared', deepcopy(PLAN)))
        self.backend.status = Mock(return_value=response('status', 'missing'))
        self.enterContext(patch.object(cgp_cert_manager, 'update_plan', self.backend, create=True))
        self.enterContext(patch.dict(sys.modules, {'cgp_cert_manager.update_plan': self.backend}))
        self.forbidden = [self.enterContext(patch.object(owner, name,
                          side_effect=AssertionError('CLI crossed its backend boundary')))
                          for owner, name in ((Path, 'open'), (Path, 'mkdir'),
                                              (socket, 'getaddrinfo'), (socket, 'create_connection'),
                                              (subprocess, 'Popen'))]
        self.addCleanup(self.check_boundaries)
        self.paths = {'manifest_path': Path('/synthetic/update/manifest.json'),
                      'signature_path': Path('/synthetic/update/signature.json'),
                      'archive_path': Path('/synthetic/update/candidate.tar.gz')}
        self.artifacts = ['--manifest', str(self.paths['manifest_path']),
                          '--signature', str(self.paths['signature_path']),
                          '--archive', str(self.paths['archive_path'])]

    def check_boundaries(self):
        for forbidden in self.forbidden:
            forbidden.assert_not_called()

    def invoke(self, *args):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            try:
                code = cli.main(list(args))
            except SystemExit as exited:
                code = exited.code
        self.assertNotIn('PRIVATE_EXTERNAL_DETAIL', output.getvalue() + errors.getvalue())
        return code, output.getvalue(), errors.getvalue()

    def untouched(self):
        for name in ('check', 'prepare', 'status'):
            getattr(self.backend, name).assert_not_called()

    def test_help_and_version_bypass_artifacts_trust_state_and_backend(self):
        for option in ('--help', '--version'):
            with self.subTest(option=option):
                code, output, errors = self.invoke(option)
                self.assertEqual(code, 0)
                self.assertEqual(errors, '')
                self.assertIn(__version__ if option == '--version' else '--prepare', output)
        self.untouched()

    def test_action_and_artifact_combinations_refuse_before_any_backend_call(self):
        cases = [(), ('--json',), ('--check', '--prepare'), ('--status', '--check'),
                 ('--check',), ('--prepare',), ('--apply',),
                 ('--check', '--manifest', '/manifest'),
                 ('--prepare', '--manifest', '/manifest', '--signature', '/signature')]
        cases.extend(('--status', option, '/synthetic/file')
                     for option in ('--manifest', '--signature', '--archive'))
        for arguments in cases:
            with self.subTest(arguments=arguments):
                code, output, errors = self.invoke(*arguments)
                self.assertEqual((code, output), (2, ''))
                self.assertIn('error:', errors)
        self.untouched()

    def test_every_path_requires_absolute_form_without_parent_traversal(self):
        for action in ('check', 'prepare', 'status'):
            names = ['trust-file', 'state-dir', 'installed-root']
            if action != 'status':
                names += ['manifest', 'signature', 'archive']
            for name in names:
                for value in ('relative', '/synthetic/../changed'):
                    with self.subTest(action=action, name=name, value=value):
                        arguments = ['--' + action] + (self.artifacts if action != 'status' else [])
                        code, output, errors = self.invoke(*arguments, '--' + name, value)
                        self.assertEqual((code, output), (2, ''))
                        self.assertIn('--' + name + ' requires an absolute path without parent traversal', errors)
        self.untouched()

    def test_check_and_prepare_forward_exact_paths_and_return_the_public_plan(self):
        for action, status in (('check', 'verified'), ('prepare', 'prepared')):
            with self.subTest(action=action):
                code, output, errors = self.invoke('--' + action, *self.artifacts, '--json')
                self.assertEqual((code, errors), (0, ''))
                self.assertEqual(json.loads(output), response(action, status, PLAN))
                self.assertTrue(output.endswith('\n'))
                getattr(self.backend, action).assert_called_once_with(
                    **self.paths, trust_path=Path('/etc/cgp-update/trust.json'),
                    installed_root=Path('/opt/cgp-certificate-manager'), state_dir=Path('/var/lib/cgp-update'))
        self.backend.status.assert_not_called()

    def test_custom_paths_forward_to_all_actions_without_resolution_or_filesystem_work(self):
        options = ['--trust-file', '/synthetic/private/trust.json',
                   '--state-dir', '/synthetic/private/state', '--installed-root', '/synthetic/installed']
        common = {'trust_path': Path(options[1]), 'state_dir': Path(options[3]),
                  'installed_root': Path(options[5])}
        for action in ('check', 'prepare', 'status'):
            with self.subTest(action=action):
                artifacts = self.artifacts if action != 'status' else []
                code, output, errors = self.invoke('--' + action, *artifacts, *options, '--json')
                self.assertEqual(code, 2 if action == 'status' else 0)
                self.assertEqual(errors, '')
                self.assertEqual(json.loads(output)['action'], action)
                getattr(self.backend, action).assert_called_once_with(
                    **common, **(self.paths if action != 'status' else {}))

    def test_status_is_read_only_and_all_incomplete_states_return_nonzero(self):
        for status in ('missing', 'busy', 'invalid', 'expired', 'configuration_changed', 'error'):
            with self.subTest(status=status):
                expected = response('status', status, error='invalid_plan' if status == 'invalid' else None)
                self.backend.status.return_value = expected
                code, output, errors = self.invoke('--status', '--json')
                self.assertEqual((code, errors), (2, ''))
                self.assertEqual(json.loads(output), expected)
        self.backend.check.assert_not_called()
        self.backend.prepare.assert_not_called()
        for call in self.backend.status.call_args_list:
            self.assertEqual(call.kwargs, {'trust_path': Path('/etc/cgp-update/trust.json'),
                             'installed_root': Path('/opt/cgp-certificate-manager'),
                             'state_dir': Path('/var/lib/cgp-update')})
        for status in ('verified', 'prepared'):
            self.backend.status.return_value = response('status', status, deepcopy(PLAN))
            self.assertEqual(self.invoke('--status', '--json')[0], 0)

    def test_text_renders_only_the_public_status_reason_and_plan(self):
        code, output, errors = self.invoke('--check', *self.artifacts)
        self.assertEqual((code, errors), (0, ''))
        heading, encoded = output.split('Plan:\n', 1)
        self.assertEqual(heading, 'CGP update: verified\n')
        self.assertEqual(json.loads(encoded), PLAN)
        code, output, errors = self.invoke('--status')
        self.assertEqual((code, output, errors), (2, 'CGP update: missing\n', ''))
        self.backend.status.return_value = response('status', 'expired', error='expired_manifest')
        self.assertEqual(self.invoke('--status'),
                         (2, 'CGP update: expired\nReason: expired_manifest\n', ''))

    def test_unexpected_errors_are_projected_without_exception_text_or_tracebacks(self):
        failures = [ValueError('PRIVATE_EXTERNAL_DETAIL'), OSError('PRIVATE_EXTERNAL_DETAIL'),
                    FileNotFoundError('/PRIVATE_EXTERNAL_DETAIL'), PermissionError('PRIVATE_EXTERNAL_DETAIL'),
                    BlockingIOError('PRIVATE_EXTERNAL_DETAIL'), RuntimeError('PRIVATE_EXTERNAL_DETAIL')]
        for action in ('check', 'prepare', 'status'):
            for failure in failures:
                with self.subTest(action=action, failure=type(failure).__name__):
                    getattr(self.backend, action).side_effect = failure
                    artifacts = self.artifacts if action != 'status' else []
                    code, output, errors = self.invoke('--' + action, *artifacts, '--json')
                    self.assertEqual((code, errors), (2, ''))
                    self.assertEqual(json.loads(output), response(action, 'error', error='update_failed'))
            getattr(self.backend, action).side_effect = None
        self.backend.status.side_effect = RuntimeError('PRIVATE_EXTERNAL_DETAIL')
        self.assertEqual(self.invoke('--status'),
                         (2, 'CGP update: error\nReason: update_failed\n', ''))

    def test_rendering_failure_never_emits_a_partial_or_nonfinite_plan(self):
        self.backend.check.return_value = response('check', 'verified', {'value': float('nan')})
        for mode in ((), ('--json',)):
            code, output, errors = self.invoke('--check', *self.artifacts, *mode)
            self.assertEqual((code, errors), (2, ''))
            self.assertNotIn('NaN', output)
            self.assertNotIn('verified', output)
            self.assertNotIn('Plan:', output)
            self.assertIn('update_failed', output)

    def test_interrupt_returns_130_with_a_safe_action_specific_result(self):
        for action in ('check', 'prepare', 'status'):
            getattr(self.backend, action).side_effect = KeyboardInterrupt
            artifacts = self.artifacts if action != 'status' else []
            for mode in ((), ('--json',)):
                with self.subTest(action=action, mode=mode):
                    code, output, errors = self.invoke('--' + action, *artifacts, *mode)
                    self.assertEqual((code, errors), (130, ''))
                    if mode:
                        self.assertEqual(json.loads(output), response(action, 'error', error='interrupted'))
                    else:
                        self.assertEqual(output, 'CGP update: error\nReason: interrupted\n')

    def test_module_entrypoint_uses_the_same_backend_and_exit_status(self):
        self.backend.status.return_value = response('status', 'prepared', deepcopy(PLAN))
        output, errors = io.StringIO(), io.StringIO()
        with patch.object(sys, 'argv', ['update_cli', '--status', '--json']), \
                redirect_stdout(output), redirect_stderr(errors), warnings.catch_warnings():
            warnings.filterwarnings('ignore', category=RuntimeWarning)
            with self.assertRaises(SystemExit) as exited:
                runpy.run_module('cgp_cert_manager.update_cli', run_name='__main__')
        self.assertEqual(exited.exception.code, 0)
        self.assertEqual(json.loads(output.getvalue()), response('status', 'prepared', PLAN))
        self.assertEqual(errors.getvalue(), '')
        self.backend.status.assert_called_once()
