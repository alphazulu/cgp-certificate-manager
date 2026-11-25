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
TOKEN = 'f' * 64


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
        self.installation = ModuleType('cgp_cert_manager.update_apply')
        self.installation.review = Mock(return_value=response('review', 'review_ready', {'confirmation_token': TOKEN}))
        self.installation.apply = Mock(return_value=response('apply', 'applied'))
        self.installation.recover = Mock(return_value=response('recover', 'rolled_back'))
        self.installation.status = Mock(return_value=None)
        self.enterContext(patch.object(cgp_cert_manager, 'update_apply', self.installation, create=True))
        self.enterContext(patch.dict(sys.modules, {'cgp_cert_manager.update_apply': self.installation}))
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
        for name in ('review', 'apply', 'recover', 'status'):
            getattr(self.installation, name).assert_not_called()

    def arguments(self, action):
        if action in ('check', 'prepare'):
            return ['--' + action, *self.artifacts]
        return ['--' + action, *(['--confirm-update', TOKEN] if action == 'apply' else [])]

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
                 ('--review', '--recover'), ('--apply', '--review'), ('--status', '--recover'),
                 ('--check', '--manifest', '/manifest'),
                 ('--prepare', '--manifest', '/manifest', '--signature', '/signature')]
        cases.extend((*self.arguments(action), option, '/synthetic/file')
                     for action in ('status', 'review', 'apply', 'recover')
                     for option in ('--manifest', '--signature', '--archive'))
        for arguments in cases:
            with self.subTest(arguments=arguments):
                code, output, errors = self.invoke(*arguments)
                self.assertEqual((code, output), (2, ''))
                self.assertIn('error:', errors)
        self.untouched()

    def test_every_path_requires_absolute_form_without_parent_traversal(self):
        for action in ('check', 'prepare', 'status', 'review', 'apply', 'recover'):
            names = ['trust-file', 'state-dir', 'installed-root']
            if action in ('check', 'prepare'):
                names += ['manifest', 'signature', 'archive']
            for name in names:
                for value in ('relative', '/synthetic/../changed'):
                    with self.subTest(action=action, name=name, value=value):
                        arguments = self.arguments(action)
                        code, output, errors = self.invoke(*arguments, '--' + name, value)
                        self.assertEqual((code, output), (2, ''))
                        self.assertIn('--' + name + ' requires an absolute path without parent traversal', errors)
        self.untouched()

    def test_confirmation_is_required_exact_and_exclusive_to_apply(self):
        for action in ('check', 'prepare', 'status', 'review', 'recover'):
            with self.subTest(action=action):
                code, output, errors = self.invoke(*self.arguments(action), '--confirm-update', TOKEN)
                self.assertEqual((code, output), (2, ''))
                self.assertIn('--confirm-update requires --apply', errors)
        for value in (None, '', 'f' * 63, 'f' * 65, 'F' * 64, 'g' * 64,
                      ' ' + TOKEN, TOKEN + '\n', '0x' + TOKEN, 'PRIVATE_EXTERNAL_DETAIL'):
            with self.subTest(value=value):
                options = [] if value is None else ['--confirm-update', value]
                code, output, errors = self.invoke('--apply', *options)
                self.assertEqual((code, output), (2, ''))
                self.assertIn('exact lowercase 64-hex token', errors)
        self.untouched()

    def test_new_actions_forward_exact_common_paths_and_explicit_confirmation(self):
        common = {'trust_path': Path('/etc/cgp-update/trust.json'),
                  'installed_root': Path('/opt/cgp-certificate-manager'), 'state_dir': Path('/var/lib/cgp-update')}
        for action, status in (('review', 'review_ready'), ('apply', 'applied'), ('recover', 'rolled_back')):
            with self.subTest(action=action):
                expected = getattr(self.installation, action).return_value
                code, output, errors = self.invoke(*self.arguments(action), '--json')
                self.assertEqual((code, errors), (0, ''))
                self.assertEqual(json.loads(output), expected)
                self.assertEqual(json.loads(output)['status'], status)
                getattr(self.installation, action).assert_called_once_with(
                    **common, **({'confirmation_token': TOKEN} if action == 'apply' else {}))
        for action in ('check', 'prepare', 'status'):
            getattr(self.backend, action).assert_not_called()
        self.installation.status.assert_not_called()

    def test_installation_backend_receives_override_paths_and_refuses_unsupported_layout(self):
        options = ['--trust-file', '/synthetic/trust.json', '--state-dir', '/synthetic/update-state',
                   '--installed-root', '/synthetic/application']
        common = {'trust_path': Path(options[1]), 'state_dir': Path(options[3]),
                  'installed_root': Path(options[5])}
        for action in ('review', 'apply', 'recover'):
            with self.subTest(action=action):
                expected = response(action, 'invalid', error='unsupported_layout')
                getattr(self.installation, action).return_value = expected
                code, output, errors = self.invoke(*self.arguments(action), *options, '--json')
                self.assertEqual((code, errors), (2, ''))
                self.assertEqual(json.loads(output), expected)
                getattr(self.installation, action).assert_called_once_with(
                    **common, **({'confirmation_token': TOKEN} if action == 'apply' else {}))
        self.backend.status.assert_not_called()

    def test_status_reports_installation_before_package_or_trust_failures(self):
        self.backend.status.side_effect = AssertionError('Package validation must not hide an installation record')
        for status, code in (('recovery_required', 2), ('error', 2), ('busy', 2), ('invalid', 2),
                             ('applied', 0), ('rolled_back', 0)):
            with self.subTest(status=status):
                expected = response('status', status, {'phase': 'applying', 'target_version': '2.3.0'})
                self.installation.status.return_value = expected
                actual, output, errors = self.invoke('--status', '--json')
                self.assertEqual((actual, errors), (code, ''))
                self.assertEqual(json.loads(output), expected)
        self.backend.status.assert_not_called()
        self.installation.recover.assert_not_called()
        self.installation.apply.assert_not_called()

    def test_status_falls_back_only_for_explicit_absence_of_an_installation_record(self):
        calls = Mock()
        calls.attach_mock(self.installation.status, 'installation')
        calls.attach_mock(self.backend.status, 'package')
        self.backend.status.return_value = response('status', 'prepared', deepcopy(PLAN))
        code, output, errors = self.invoke('--status', '--json')
        self.assertEqual((code, errors), (0, ''))
        self.assertEqual(json.loads(output), response('status', 'prepared', PLAN))
        self.assertEqual([call[0] for call in calls.mock_calls], ['installation', 'package'])
        self.assertEqual(calls.mock_calls[0].kwargs, calls.mock_calls[1].kwargs)

        self.backend.status.reset_mock()
        for malformed in ({}, False):
            with self.subTest(malformed=malformed):
                self.installation.status.return_value = malformed
                code, output, errors = self.invoke('--status', '--json')
                self.assertEqual((code, errors), (2, ''))
                self.assertEqual(json.loads(output), response('status', 'error', error='update_failed'))
        self.backend.status.assert_not_called()

    def test_refused_or_interrupted_apply_does_not_retry_or_recover_implicitly(self):
        for status, error in (('invalid', 'confirmation_changed'), ('recovery_required', 'installation_incomplete')):
            with self.subTest(status=status):
                expected = response('apply', status, error=error)
                self.installation.apply.return_value = expected
                code, output, errors = self.invoke('--apply', '--confirm-update', PLAN['plan_id'], '--json')
                self.assertEqual((code, errors), (2, ''))
                self.assertEqual(json.loads(output), expected)
                self.assertEqual(self.installation.apply.call_args.kwargs['confirmation_token'], PLAN['plan_id'])
        self.installation.apply.side_effect = KeyboardInterrupt
        code, output, errors = self.invoke(*self.arguments('apply'), '--json')
        self.assertEqual((code, errors), (130, ''))
        self.assertEqual(json.loads(output), response('apply', 'error', error='interrupted'))
        self.assertEqual(self.installation.apply.call_count, 3)
        self.installation.recover.assert_not_called()
        self.installation.review.assert_not_called()
        self.backend.prepare.assert_not_called()

    def test_installation_errors_and_interrupts_are_sanitized_without_fallback(self):
        for action in ('review', 'apply', 'recover', 'status'):
            for failure, code, error in ((OSError('PRIVATE_EXTERNAL_DETAIL'), 2, 'update_failed'),
                                         (RuntimeError('PRIVATE_EXTERNAL_DETAIL'), 2, 'update_failed'),
                                         (KeyboardInterrupt(), 130, 'interrupted')):
                with self.subTest(action=action, failure=type(failure).__name__):
                    getattr(self.installation, action).side_effect = failure
                    actual, output, errors = self.invoke(*self.arguments(action), '--json')
                    self.assertEqual((actual, errors), (code, ''))
                    self.assertEqual(json.loads(output), response(action, 'error', error=error))
            getattr(self.installation, action).side_effect = None
        self.backend.status.assert_not_called()

    def test_review_text_exposes_the_new_token_without_reinterpreting_package_id(self):
        review = {'confirmation_token': TOKEN, 'plan_id': PLAN['plan_id'],
                  'installed_version': PLAN['installed_version'], 'target_version': PLAN['target_version']}
        self.installation.review.return_value = response('review', 'review_ready', review)
        code, output, errors = self.invoke('--review')
        self.assertEqual((code, errors), (0, ''))
        heading, encoded = output.split('Plan:\n', 1)
        self.assertEqual(heading, 'CGP update: review_ready\n')
        self.assertEqual(json.loads(encoded), review)
        self.installation.apply.assert_not_called()
        self.installation.recover.assert_not_called()

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
