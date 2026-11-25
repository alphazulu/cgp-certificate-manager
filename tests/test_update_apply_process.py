"""Abrupt update crashes recovered by the independent runtime in fresh processes.

The children use copied trusted source, an isolated filesystem root and a local
systemctl stub. Candidate source is never imported; no host services or network
endpoints are contacted. These are process-crash tests, not power-loss tests.
"""
import json
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import unittest

from cgp_cert_manager import update_apply as apply, update_files as files
from test_update_apply import ApplyFixture
from test_update_metadata import NOW


CHILD = r'''
import importlib.abc
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
from types import SimpleNamespace

root, action, token, fault_target, fault_event, crash_kind, now = sys.argv[1:]
root = Path(root)
runtime = root / 'opt/cgp-update-runtime'
sys.dont_write_bytecode = True
sys.path.insert(0, str(runtime))

def forbidden(*args, **kwargs):
    raise AssertionError('No external activity in an update crash fixture')

socket.create_connection = socket.getaddrinfo = forbidden
socket.socket.connect = socket.socket.connect_ex = socket.socket.sendto = forbidden
subprocess.Popen = forbidden

class NoRecoveryCrypto(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if action == 'recover' and fullname.partition('.')[0] == 'cryptography':
            raise AssertionError('Recovery must not need signature verification')

sys.meta_path.insert(0, NoRecoveryCrypto())
systemd_path = root / 'fake-systemd.json'

def systemctl(command, **kwargs):
    assert command[:3] == ['/usr/bin/systemctl', '--no-pager', '--no-ask-password'], command
    assert kwargs['stdin'] == subprocess.DEVNULL
    assert kwargs['stderr'] == subprocess.DEVNULL
    state = json.loads(systemd_path.read_text())
    arguments = command[3:]
    state['calls'].append(arguments)
    if arguments[0] == 'show':
        properties = ['--all', '--property=LoadState', '--property=ActiveState',
                      '--property=FragmentPath', '--property=DropInPaths',
                      '--property=NeedDaemonReload']
        process_properties = ['--property=MainPID', '--property=ControlPID', '--property=ControlGroup']
        assert arguments[2:] in (properties, properties + process_properties), arguments
        unit = arguments[1]
        fragment = '/etc/systemd/system/' + unit
        # A reboot discards the manager's cached fragment. An interrupted unit
        # rename can therefore be a genuine not-found unit until restoration.
        missing = state.get('rebooted', False) and not (root / fragment.lstrip('/')).exists()
        output = ('LoadState=' + ('not-found' if missing else 'loaded') +
                  '\nActiveState=' + ('inactive' if missing else state['units'][unit]) +
                  '\nFragmentPath=' + ('' if missing else fragment) +
                  '\nDropInPaths=\nNeedDaemonReload=no\n')
        if arguments[2:] == properties + process_properties:
            assert unit.endswith('.service'), arguments
            process = state['processes'][unit]
            output += ''.join(name + '=' + process[name] + '\n'
                              for name in ('MainPID', 'ControlPID', 'ControlGroup'))
        output = output.encode()
    elif arguments[0] == 'stop':
        assert arguments[1:] and set(arguments[1:]) <= {'cgp-letsencrypt.timer', 'cgp-monitor.timer'}
        for unit in arguments[1:]:
            # Stopping a cache-lost absent timer is an error on the real
            # service manager. Recovery must omit it, not ignore that error.
            assert not state.get('rebooted', False) or (root / 'etc/systemd/system' / unit).is_file()
            state['units'][unit] = 'inactive'
        output = b''
    elif arguments == ['daemon-reload']:
        output = b''
    else:
        raise AssertionError('Unexpected systemctl operation: ' + repr(arguments))
    systemd_path.write_text(json.dumps(state))
    return SimpleNamespace(returncode=0, stdout=output)

subprocess.run = systemctl
from cgp_cert_manager import update_apply as backend, update_cli, update_files, update_plan

assert Path(backend.__file__).resolve().is_relative_to(runtime)
assert backend.EXECUTOR_ROOT == runtime
backend.LAYOUT = backend.Layout(root)
update_plan.time.time = lambda: float(now)

def crash(target, event):
    (root / 'crash.json').write_text(json.dumps({'target': target, 'event': event}))
    if crash_kind == 'kill':
        os.kill(os.getpid(), signal.SIGKILL)
    os._exit(73)

def intercept(original):
    def operation(target, slot, before, after, checkpoint):
        name = next(key for key, path in backend.LAYOUT.targets().items() if path == target)
        def boundary(event):
            # Deliberately die before the post-rename journal callback: recovery
            # must classify the actual namespace rather than trust a step count.
            if name == fault_target and event == fault_event:
                crash(name, event)
            checkpoint(event)
        return original(target, slot, before, after, checkpoint=boundary)
    return operation

update_files.apply_target = intercept(update_files.apply_target)
update_files.restore_target = intercept(update_files.restore_target)
original_clear = backend._clear

def clear(record):
    if fault_event == 'before_clear' and record['phase'] == fault_target:
        crash(record['phase'], 'before_clear')
    return original_clear(record)

backend._clear = clear
arguments = ['--' + action, '--json', '--trust-file', str(root / 'etc/cgp-update/trust.json'),
             '--installed-root', str(backend.LAYOUT.app), '--state-dir', str(backend.LAYOUT.state)]
if action == 'apply':
    arguments.extend(['--confirm-update', token])
raise SystemExit(update_cli.main(arguments))
'''


class UpdateApplyProcessTests(ApplyFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        source = Path(apply.__file__).parent
        shutil.copytree(source, self.layout.runtime / 'cgp_cert_manager', dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '*.pyo'))
        shutil.copyfile(source / 'update_gate.py', self.layout.runtime / 'cgp_update_gate.py')
        # Old unit bytes must already be trusted. Their safe modes can differ;
        # normalization to 0644 exercises each unit's real rename and rollback.
        for name in apply.UNITS:
            self.layout.targets()[name].chmod(0o600)
        self.write(self.layout.preserved()['monitor_config'],
                   b'{"schema":1,"enabled":false,"endpoints":[],"notifications":{"enabled":false,"channels":[]}}\n',
                   0o600)
        self.systemd = self.root / 'fake-systemd.json'
        self.systemd.write_text(json.dumps({
            'units': {**self.observation['timers'], **self.observation['services']},
            'processes': {unit: {'MainPID': '0', 'ControlPID': '0', 'ControlGroup': ''}
                          for unit in self.observation['services']},
            'enabled': {unit: True for unit in self.observation['timers']}, 'calls': []}))
        self.before = {name: files.capture(path)[0] for name, path in self.layout.targets().items()}
        self.preserved = {name: files.capture(path)[0] for name, path in self.layout.preserved().items()}
        self.evidence = {str(path): files.capture(path)[0] for path in self.layout.locks[:2]}
        self.prepare()
        self.token = self.review()

    def child(self, action, target='', event='', kind='exit', expected_code=0):
        result = subprocess.run(
            [sys.executable, '-I', '-B', '-c', CHILD, str(self.root), action, self.token,
             target, event, kind, str(NOW + 0.5)],
            cwd=self.root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=30, check=False)
        if event:
            self.assertEqual(result.returncode, -signal.SIGKILL if kind == 'kill' else 73,
                             (result.stdout, result.stderr))
            self.assertEqual(result.stdout, b'')
            self.assertEqual(json.loads((self.root / 'crash.json').read_text()),
                             {'target': target, 'event': event})
            self.assertTrue((self.layout.state / 'pending.json').is_file())
            return None
        self.assertEqual(result.returncode, expected_code, (result.stdout, result.stderr))
        self.assertEqual(result.stderr, b'')
        return json.loads(result.stdout)

    def remove_verification_inputs(self):
        self.trust_path.unlink()
        for path in self.artifacts.values():
            path.unlink()
        shutil.rmtree(self.layout.state / 'staged')
        # Recovery has no dependency on the package checkpoint, either.
        (self.layout.state / 'checkpoint.json').unlink()

    def assert_preservation(self):
        self.assertEqual({name: files.capture(path)[0]
                          for name, path in self.layout.preserved().items()}, self.preserved)
        self.assertEqual({str(path): files.capture(path)[0] for path in self.layout.locks[:2]}, self.evidence)
        state = json.loads(self.systemd.read_text())
        self.assertEqual({state['units'][unit] for unit in self.observation['timers']}, {'inactive'})
        self.assertLessEqual({state['units'][unit] for unit in self.observation['services']},
                             {'inactive', 'failed'})
        self.assertEqual(state['enabled'], {unit: True for unit in self.observation['timers']})
        self.assertTrue(any(call == ['daemon-reload'] for call in state['calls']))
        self.assertTrue(all(call[0] in ('show', 'stop', 'daemon-reload') for call in state['calls']))
        self.assertFalse((self.layout.state / 'pending.json').exists())
        self.assertTrue((self.layout.state / 'installation.json').is_file())
        self.assertTrue((self.layout.state / 'installations').is_dir())

    def reboot(self):
        """Simulate a fresh manager cache and services rejected by the guard."""
        state = json.loads(self.systemd.read_text())
        state['rebooted'] = True
        for unit in self.observation['timers']:
            exists = (self.root / 'etc/systemd/system' / unit).is_file()
            state['units'][unit] = 'active' if exists and state['enabled'][unit] else 'inactive'
        for unit in self.observation['services']:
            exists = (self.root / 'etc/systemd/system' / unit).is_file()
            state['units'][unit] = 'failed' if exists else 'inactive'
        self.systemd.write_text(json.dumps(state))

    def backup_snapshot(self):
        record = self.record()
        path = self.layout.state / 'installations' / record['transaction_id'] / 'blobs'
        return files.capture(path)[0]

    def assert_rollback(self):
        result = self.child('recover')
        self.assertEqual(result['status'], 'rolled_back', result)
        self.assertEqual({name: files.capture(path)[0]
                          for name, path in self.layout.targets().items()}, self.before)
        self.assertEqual(self.child('status')['status'], 'rolled_back')
        self.assert_preservation()

    def apply_crash_case(self, target, event):
        self.child('apply', target, event, 'kill' if event == 'after_park_old' else 'exit')
        if target == 'application' and event == 'after_park_old':
            self.assertFalse(self.layout.app.exists())
        self.assertEqual(self.child('status', expected_code=2)['status'], 'recovery_required')
        self.remove_verification_inputs()
        self.assert_rollback()

    def recovery_crash_case(self, event):
        # All changed targets have been replaced, but no terminal receipt exists.
        self.child('apply', 'monitor_timer', 'after_install_new')
        self.remove_verification_inputs()
        self.child('recover', 'application', event, 'kill')
        if event == 'after_park_undo':
            self.assertFalse(self.layout.app.exists())
        self.assertEqual(self.child('status', expected_code=2)['status'], 'recovery_required')
        self.assert_rollback()

    def test_recovery_restarts_after_parking_new_application(self):
        self.recovery_crash_case('after_park_undo')

    def test_recovery_restarts_after_restoring_old_application(self):
        self.recovery_crash_case('after_restore_old')

    def test_committed_installation_is_not_rolled_back_after_pending_clear_crash(self):
        self.child('apply', 'applied', 'before_clear', 'kill')
        committed = {name: files.capture(path)[0] for name, path in self.layout.targets().items()}
        self.assertNotEqual(committed['application'], self.before['application'])
        self.assertEqual({committed[name]['entries'][0]['mode'] for name in apply.UNITS}, {0o644})
        self.remove_verification_inputs()
        self.assertEqual(self.child('status', expected_code=2)['status'], 'recovery_required')
        self.assertEqual(self.child('recover')['status'], 'applied')
        self.assertEqual(self.child('recover')['status'], 'applied')
        self.assertEqual({name: files.capture(path)[0]
                          for name, path in self.layout.targets().items()}, committed)
        self.assertEqual(self.child('status')['status'], 'applied')
        self.assert_preservation()

    def test_committed_rollback_only_clears_its_pending_marker_on_retry(self):
        self.child('apply', 'application', 'after_install_new')
        self.remove_verification_inputs()
        self.child('recover', 'rolled_back', 'before_clear')
        self.assertEqual(self.child('status', expected_code=2)['status'], 'recovery_required')
        self.assert_rollback()
        self.assertEqual(self.child('recover')['status'], 'rolled_back')

    def reboot_crash_case(self, target):
        self.child('apply', target, 'after_park_old', 'kill')
        self.assertFalse(self.layout.targets()[target].exists())
        backups = self.backup_snapshot()
        self.remove_verification_inputs()
        self.reboot()
        self.assert_rollback()
        self.assertEqual(self.backup_snapshot(), backups)
        calls = json.loads(self.systemd.read_text())['calls']
        unit = apply.UNITS[target]
        self.assertTrue(any(call[:2] == ['show', unit] for call in calls))
        if unit.endswith('.timer'):
            # Initial apply stopped both. Recovery after cache loss must stop
            # only the still-loaded timer; final reload requires both restored.
            stops = [call for call in calls if call[0] == 'stop']
            self.assertTrue(any(unit not in call for call in stops))

    def test_recovery_after_reboot_keeps_quiescent_failed_services_failed(self):
        self.child('apply', 'application', 'after_install_new', 'kill')
        backups = self.backup_snapshot()
        self.remove_verification_inputs()
        self.reboot()
        self.assert_rollback()
        self.assertEqual(self.backup_snapshot(), backups)
        state = json.loads(self.systemd.read_text())
        self.assertEqual({state['units'][unit] for unit in self.observation['services']}, {'failed'})

    def test_recovery_after_reboot_refuses_residual_service_processes_before_undo(self):
        self.child('apply', 'monitor_timer', 'after_install_new', 'kill')
        self.remove_verification_inputs()
        self.reboot()
        targets = {name: files.capture(path)[0] for name, path in self.layout.targets().items()}
        record = self.record()
        journal = self.layout.state / 'installations' / record['transaction_id'] / 'journal.json'
        pending = self.layout.state / 'pending.json'
        evidence = journal.read_bytes(), pending.read_bytes(), self.backup_snapshot()
        for property_name, value in (('MainPID', '217'), ('ControlPID', '218'),
                                     ('ControlGroup', '/system.slice/cgp-letsencrypt.service')):
            with self.subTest(property=property_name):
                state = json.loads(self.systemd.read_text())
                process = state['processes']['cgp-letsencrypt.service']
                process.update(MainPID='0', ControlPID='0', ControlGroup='')
                process[property_name] = value
                offset = len(state['calls'])
                self.systemd.write_text(json.dumps(state))
                result = self.child('recover', expected_code=2)
                self.assertEqual(result['status'], 'recovery_required', result)
                self.assertEqual(result['error'], 'systemd_service_active', result)
                self.assertEqual({name: files.capture(path)[0]
                                  for name, path in self.layout.targets().items()}, targets)
                self.assertEqual((journal.read_bytes(), pending.read_bytes(), self.backup_snapshot()), evidence)
                calls = json.loads(self.systemd.read_text())['calls'][offset:]
                self.assertTrue(calls)
                self.assertTrue(all(call[0] == 'show' for call in calls), calls)


def _apply_crash_test(target, event):
    def test(self):
        self.apply_crash_case(target, event)
    return test


for _target in ('application', *apply.UNITS):
    for _event in ('after_park_old', 'after_install_new'):
        setattr(UpdateApplyProcessTests, 'test_crash_' + _target + '_' + _event,
                _apply_crash_test(_target, _event))


def _reboot_crash_test(target):
    def test(self):
        self.reboot_crash_case(target)
    return test


for _target in apply.UNITS:
    setattr(UpdateApplyProcessTests, 'test_reboot_after_parking_' + _target, _reboot_crash_test(_target))


if __name__ == '__main__':
    unittest.main()
