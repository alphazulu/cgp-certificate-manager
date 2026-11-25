"""Systemd update policy uses mocked fixed commands, never a real service."""
import json
import os
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cgp_cert_manager import update_services as services


class UpdateServicesTests(unittest.TestCase):
    def setUp(self):
        self.states = {unit: 'inactive' for unit in (*services.TIMERS, *services.SERVICES)}
        self.dropins = {unit: '' for unit in self.states}
        self.fragments = {unit: '/etc/systemd/system/' + unit for unit in self.states}
        self.reload_needed = {unit: 'no' for unit in self.states}
        self.loaded = {unit: 'loaded' for unit in self.states}
        self.processes = {unit: {'MainPID': '0', 'ControlPID': '0', 'ControlGroup': ''}
                          for unit in services.SERVICES}
        self.commands = []
        self.process = self.enterContext(patch.object(services.subprocess, 'run', side_effect=self.command))

    def command(self, command, **kwargs):
        self.commands.append((command, kwargs))
        self.assertEqual(command[:3], ['/usr/bin/systemctl', '--no-pager', '--no-ask-password'])
        self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
        self.assertEqual(kwargs['stdout'], subprocess.PIPE)
        self.assertEqual(kwargs['stderr'], subprocess.DEVNULL)
        self.assertFalse(kwargs['check'])
        self.assertGreater(kwargs['timeout'], 0)
        self.assertLessEqual(kwargs['timeout'], services.TIMEOUT_SECONDS)
        self.assertEqual(kwargs['env'], services._ENV)
        verb = command[3]
        if verb == 'show':
            unit = command[4]
            properties = ['--all', '--property=LoadState', '--property=ActiveState',
                          '--property=FragmentPath', '--property=DropInPaths', '--property=NeedDaemonReload']
            process_fields = ''
            if '--property=MainPID' in command:
                self.assertIn(unit, services.SERVICES)
                properties += ['--property=MainPID', '--property=ControlPID', '--property=ControlGroup']
                process_fields = ''.join(name + '=' + value + '\n' for name, value in self.processes[unit].items())
            self.assertEqual(command[5:], properties)
            return SimpleNamespace(returncode=0, stdout=('ActiveState=' + self.states[unit] + '\nLoadState=' + self.loaded[unit] + '\n'
                                   'FragmentPath=' + self.fragments[unit] + '\nDropInPaths=' + self.dropins[unit] + '\n'
                                   'NeedDaemonReload=' + self.reload_needed[unit] + '\n' + process_fields).encode())
        if verb == 'stop':
            self.assertTrue(command[4:])
            self.assertEqual(command[4:], [unit for unit in services.TIMERS if self.loaded[unit] != 'not-found'])
            for unit in command[4:]:
                self.states[unit] = 'inactive'
        else:
            self.assertEqual(command[3:], ['daemon-reload'])
        return SimpleNamespace(returncode=0, stdout=b'')

    def refused(self, code, operation=services.observe):
        with self.assertRaises(services.SystemdError) as raised:
            operation()
        self.assertEqual(str(raised.exception), code)
        self.assertEqual(raised.exception.code, code)
        self.assertIn(code, services.CODES)

    def test_observe_preserves_timer_states_and_excludes_ambient_environment(self):
        self.states[services.TIMERS[0]] = 'active'
        with patch.dict(os.environ, {'SYSTEMD_HOST': 'untrusted.example', 'PRIVATE': 'secret'}):
            result = services.observe()
        self.assertEqual(result, {'timers': {unit: self.states[unit] for unit in services.TIMERS},
                                  'services': {unit: 'inactive' for unit in services.SERVICES}})
        self.assertEqual(json.loads(json.dumps(result)), result)
        self.assertEqual(len(self.commands), 4)
        self.assertTrue(all(command[3] == 'show' for command, options in self.commands))

    def test_stop_then_reload_verify_both_timers_and_never_change_enablement(self):
        for unit in services.TIMERS:
            self.states[unit] = 'active'
        stopped = services.stop()
        self.assertEqual(stopped['timers'], {unit: 'inactive' for unit in services.TIMERS})
        self.assertEqual(services.reload(), stopped)
        verbs = [command[3] for command, options in self.commands]
        self.assertEqual(verbs.count('stop'), 1)
        self.assertEqual(verbs.count('daemon-reload'), 1)
        self.assertEqual(set(verbs), {'show', 'stop', 'daemon-reload'})

    def test_busy_services_refuse_before_stop_or_reload_side_effects(self):
        for unit in services.SERVICES:
            for state in ('active', 'activating', 'deactivating', 'reloading'):
                self.states[unit] = state
                self.commands.clear()
                self.refused('systemd_service_active', services.stop)
                self.assertTrue(all(command[3] == 'show' for command, options in self.commands))
            self.states[unit] = 'inactive'

    def test_unknown_failed_or_activating_timer_is_not_inactive(self):
        for unit, state in ((services.TIMERS[0], 'activating'), (services.TIMERS[0], 'failed'),
                             (services.SERVICES[0], 'failed'), (services.SERVICES[0], 'unknown')):
            self.states[unit] = state
            self.refused('systemd_invalid_response')
            self.states[unit] = 'inactive'

    def test_incomplete_duplicate_malformed_or_oversized_output_is_refused(self):
        responses = [None, 'text', b'x' * (services.MAX_OUTPUT + 1), b'', b'LoadState=loaded\n',
                     b'LoadState=loaded\nActiveState=inactive', b'PRIVATE invalid line\n', b'\xff\n',
                     b'LoadState=loaded\nLoadState=loaded\n',
                     b'LoadState=loaded\nActiveState=inactive\nExtra=value\n',
                     b'LoadState=not-found\nActiveState=inactive\n',
                     b'LoadState=loaded\nUnexpected=inactive\n']
        for output in responses:
            self.process.side_effect = None
            self.process.return_value = SimpleNamespace(returncode=0, stdout=output)
            self.refused('systemd_invalid_response')

    def test_command_errors_are_fixed_and_do_not_include_captured_data(self):
        for failure in (OSError('PRIVATE systemd error'), subprocess.TimeoutExpired('PRIVATE', 15)):
            self.process.side_effect = failure
            self.refused('systemd_unavailable')
        self.process.side_effect = None
        self.process.return_value = SimpleNamespace(returncode=1, stdout=b'PRIVATE error')
        self.refused('systemd_unavailable')

    def test_only_managed_effective_unit_paths_and_schedule_dropin_are_allowed(self):
        known = '/etc/systemd/system/cgp-letsencrypt.timer.d/90-cgp-manager.conf'
        self.dropins[services.TIMERS[0]] = known
        services.observe()
        for unit in self.states:
            for fragment in ('', '/run/systemd/system/' + unit, '/etc/systemd/system/../foreign.service'):
                self.fragments[unit] = fragment
                self.refused('systemd_invalid_response', services.stop)
            self.fragments[unit] = '/etc/systemd/system/' + unit
            for dropin in ('/etc/systemd/system/service.d/override.conf', known + ' ' + known,
                           '/etc/systemd/system/cgp-letsencrypt.timer.d/91-custom.conf'):
                self.dropins[unit] = dropin
                self.refused('systemd_invalid_response', services.stop)
            if unit != services.TIMERS[0]:
                self.dropins[unit] = known
                self.refused('systemd_invalid_response')
            self.dropins[unit] = ''
        self.assertTrue(all(command[3] == 'show' for command, options in self.commands))

    def test_dirty_cache_refuses_readiness_but_does_not_prevent_recovery_stop(self):
        for unit in self.states:
            self.reload_needed[unit] = 'yes'
            self.states[services.TIMERS[0]] = 'active'
            self.refused('systemd_invalid_response')
            self.assertEqual(services.stop()['timers'], {timer: 'inactive' for timer in services.TIMERS})
            self.assertEqual(self.reload_needed[unit], 'yes')
            # A successful daemon-reload exit alone is insufficient proof.
            self.refused('systemd_invalid_response', services.reload)
            self.reload_needed[unit] = 'no'
        services.observe()
        services.reload()

    def test_unknown_reload_status_fails_closed_including_recovery_stop(self):
        for value in ('', 'true', 'false', 'unknown', 'NO', '0'):
            self.reload_needed[services.SERVICES[0]] = value
            for operation in (services.observe, services.stop, services.reload):
                self.refused('systemd_invalid_response', operation)

    def test_stop_and_reload_require_readback_not_just_zero_exit(self):
        command = self.command
        def ignored_stop(arguments, **kwargs):
            if arguments[3] == 'stop':
                return SimpleNamespace(returncode=0, stdout=b'')
            return command(arguments, **kwargs)
        self.states[services.TIMERS[1]] = 'active'
        self.process.side_effect = ignored_stop
        self.refused('systemd_timers_active', services.stop)
        self.process.side_effect = command
        self.refused('systemd_timers_active', services.reload)

    def test_service_starting_during_stop_is_refused(self):
        command = self.command
        def changed(arguments, **kwargs):
            result = command(arguments, **kwargs)
            if arguments[3] == 'stop':
                self.states[services.SERVICES[1]] = 'active'
            return result
        self.process.side_effect = changed
        self.refused('systemd_service_active', services.stop)

    def test_all_steps_share_one_monotonic_deadline(self):
        with patch.object(services.time, 'monotonic', side_effect=[10, 11, 12, 13, 14]):
            services.observe()
        self.assertEqual([options['timeout'] for command, options in self.commands], [14, 13, 12, 11])
        self.commands.clear()
        with patch.object(services.time, 'monotonic', side_effect=[10, 11, 12, 13, 25]):
            self.refused('systemd_unavailable')
        self.assertEqual(len(self.commands), 3)

    def test_recovery_preserves_failed_service_after_guard_refusal_without_reset_or_start(self):
        for unit in services.SERVICES:
            self.states[unit] = 'failed'
        self.states[services.TIMERS[0]] = 'active'
        self.refused('systemd_invalid_response')
        self.refused('systemd_invalid_response', services.stop)
        stopped = services.stop(recovery=True)
        self.assertEqual(stopped['services'], {unit: 'failed' for unit in services.SERVICES})
        self.assertEqual(stopped['timers'], {unit: 'inactive' for unit in services.TIMERS})
        self.assertEqual(services.reload(recovery=True), stopped)
        self.assertTrue(all(command[3] in ('show', 'stop', 'daemon-reload') for command, _ in self.commands))
        self.refused('systemd_invalid_response')

    def test_recovery_refuses_tracked_or_residual_processes_even_when_state_is_inactive(self):
        for state in ('failed', 'inactive'):
            for unit in services.SERVICES:
                self.states[unit] = state
                for name, value in (('MainPID', '42'), ('ControlPID', '73'),
                                    ('ControlGroup', '/system.slice/' + unit),
                                    ('MainPID', ''), ('ControlPID', 'unknown')):
                    self.processes[unit][name] = value
                    self.commands.clear()
                    self.refused('systemd_service_active', lambda: services.stop(recovery=True))
                    self.assertTrue(all(command[3] == 'show' for command, _ in self.commands))
                    self.refused('systemd_service_active', lambda: services.reload(recovery=True))
                    self.processes[unit][name] = '' if name == 'ControlGroup' else '0'
                self.states[unit] = 'inactive'

    def test_recovery_requires_all_process_fields_and_rechecks_after_stopping_timers(self):
        command = self.command
        def incomplete(arguments, **kwargs):
            result = command(arguments, **kwargs)
            if '--property=MainPID' in arguments:
                result.stdout = result.stdout.replace(b'ControlGroup=\n', b'')
            return result
        self.process.side_effect = incomplete
        self.refused('systemd_invalid_response', lambda: services.stop(recovery=True))
        self.assertTrue(all(arguments[3] == 'show' for arguments, _ in self.commands))
        def lingering(arguments, **kwargs):
            result = command(arguments, **kwargs)
            if arguments[3] == 'stop':
                self.processes[services.SERVICES[1]]['ControlGroup'] = '/system.slice/cgp-monitor.service'
            return result
        self.process.side_effect = lingering
        self.refused('systemd_service_active', lambda: services.stop(recovery=True))

    def test_recovery_only_permits_coordinator_classified_missing_units(self):
        for unit in (*services.TIMERS, *services.SERVICES):
            self.loaded[unit] = 'not-found'
            self.fragments[unit] = ''
            self.refused('systemd_invalid_response')
            self.refused('systemd_invalid_response', lambda: services.stop(recovery=True))
            stopped = services.stop(recovery=True, missing_units=(unit,))
            self.assertEqual(set(stopped['timers'].values()), {'inactive'})
            self.assertEqual(set(stopped['services'].values()), {'inactive'})
            self.refused('systemd_invalid_response', lambda: services.reload(recovery=True))
            for field, values in ((self.fragments, ('/etc/systemd/system/' + unit, '/run/foreign')),
                                  (self.dropins, ('/etc/systemd/system/override.conf',)),
                                  (self.reload_needed, ('yes',)), (self.states, ('active', 'failed'))):
                original = field[unit]
                for value in values:
                    field[unit] = value
                    self.refused('systemd_invalid_response', lambda: services.stop(recovery=True, missing_units=(unit,)))
                field[unit] = original
            self.loaded[unit] = 'loaded'
            self.fragments[unit] = '/etc/systemd/system/' + unit
        self.refused('systemd_invalid_response', lambda: services.stop(missing_units=(services.TIMERS[0],)))
        self.refused('systemd_invalid_response', lambda: services.stop(recovery=True, missing_units=('foreign.timer',)))

    def test_recovery_skips_only_timers_systemd_actually_reports_missing(self):
        for unit in services.TIMERS:
            self.loaded[unit] = 'not-found'
            self.fragments[unit] = ''
        services.stop(recovery=True, missing_units=services.TIMERS)
        self.assertTrue(all(command[3] == 'show' for command, _ in self.commands))
        for unit in services.TIMERS:
            self.loaded[unit] = 'loaded'
            self.fragments[unit] = '/etc/systemd/system/' + unit
            self.states[unit] = 'active'
        self.commands.clear()
        services.stop(recovery=True, missing_units=services.TIMERS)
        self.assertIn(['stop', *services.TIMERS], [command[3:] for command, _ in self.commands])

    def test_recovery_rejects_masked_units_and_unknown_states(self):
        for unit in (*services.TIMERS, *services.SERVICES):
            for state in ('masked', 'error', 'bad-setting'):
                self.loaded[unit] = state
                self.refused('systemd_invalid_response', lambda: services.stop(recovery=True, missing_units=(unit,)))
            self.loaded[unit] = 'loaded'
            for state in ('active', 'activating', 'deactivating', 'reloading', 'unknown'):
                self.states[unit] = state
                if unit in services.SERVICES:
                    expected = 'systemd_invalid_response' if state == 'unknown' else 'systemd_service_active'
                    self.refused(expected, lambda: services.stop(recovery=True))
                elif state != 'active':
                    self.refused('systemd_invalid_response', lambda: services.stop(recovery=True))
                self.states[unit] = 'inactive'


if __name__ == '__main__':
    unittest.main()
