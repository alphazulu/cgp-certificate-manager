"""Installed monitor entrypoint and independent, notification-disabled units."""
import configparser
from pathlib import Path
import runpy
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from cgp_cert_manager import monitor_cli


ROOT = Path(__file__).resolve().parents[1]


class MonitorInstallationTests(unittest.TestCase):
    def unit(self, filename):
        config = configparser.ConfigParser(interpolation=None)
        config.optionxform = str
        config.read(ROOT / 'systemd' / filename)
        return config

    def test_launcher_delegates_only_to_independent_monitor_cli(self):
        with patch.object(sys, 'path', list(sys.path)), patch.object(monitor_cli, 'main', return_value=7) as main:
            with self.assertRaises(SystemExit) as exited:
                runpy.run_path(str(ROOT / 'monitor-launcher'), run_name='__main__')
            self.assertEqual(exited.exception.code, 7)
            self.assertEqual(sys.path[0], '/opt/cgp-certificate-manager')
            main.assert_called_once_with()

    def test_container_entrypoint_fresh_import_preserves_smtp_classes(self):
        source = (ROOT / 'tests/integration/installer.sh').read_text()
        guard = source.split("<<'OFFLINE_GUARD'\n", 1)[1].split('\nOFFLINE_GUARD\n', 1)[0]
        entrypoint = source.split("<<'MONITOR_ENTRYPOINT'\n", 1)[1].split('\nMONITOR_ENTRYPOINT\n', 1)[0]
        program = '''
from pathlib import Path
import sys

application, fixtures = (Path(value) for value in sys.argv[1:])
sys.path.insert(0, str(application))
guard = {'__name__': 'sitecustomize'}
exec(compile((fixtures / 'guard.py').read_text(), 'guard.py', 'exec'), guard)
guard['_attempt_marker'] = fixtures / 'network-attempted'
from cgp_cert_manager import core
core.STATE = fixtures / 'manager-state'
assert {
    'cgp_cert_manager.monitor_cli', 'cgp_cert_manager.monitor_runner',
    'cgp_cert_manager.monitor_state', 'cgp_cert_manager.notify_transport',
}.isdisjoint(sys.modules), 'The installed entrypoint must import the monitor afresh'
sys.argv = [str(fixtures / 'entrypoint.py'), str(application),
            str(application / 'monitor-launcher'), str(fixtures / 'monitor-state')]
try:
    exec(compile((fixtures / 'entrypoint.py').read_text(), 'entrypoint.py', 'exec'),
         {'__name__': '__main__'})
finally:
    sys.setprofile(None)
import smtplib
from cgp_cert_manager import notify_transport
assert issubclass(notify_transport._PlainClient, smtplib.SMTP)
assert issubclass(notify_transport._TLSClient, smtplib.SMTP_SSL)
assert not guard['_attempt_marker'].exists(), 'The entrypoint attempted network access'
'''
        with tempfile.TemporaryDirectory() as directory:
            fixtures = Path(directory)
            (fixtures / 'guard.py').write_text(guard)
            (fixtures / 'entrypoint.py').write_text(entrypoint)
            for name in ('manager-state', 'monitor-state'):
                state = fixtures / name
                state.mkdir(mode=0o700)
                evidence = state / 'observations.json'
                evidence.write_text('{"synthetic": "preserve"}\n')
                evidence.chmod(0o600)
            result = subprocess.run([sys.executable, '-I', '-c', program, str(ROOT), str(fixtures)],
                                    cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_service_requires_explicit_notification_override_and_private_write_scope(self):
        unit = self.unit('cgp-monitor.service')
        service = unit['Service']
        self.assertEqual(shlex.split(service['ExecStart']), ['/usr/local/sbin/cgp-monitor', '--run'])
        self.assertEqual(service['Type'], 'oneshot')
        self.assertEqual(service['User'], 'root')
        self.assertEqual(int(service['UMask'], 8), 0o077)
        self.assertEqual(service['ProtectSystem'], 'strict')
        self.assertEqual(shlex.split(service['ReadWritePaths']), ['/var/lib/cgp-monitor'])
        self.assertEqual(service['NoNewPrivileges'], 'true')
        self.assertEqual(service['ProtectHome'], 'true')
        self.assertEqual(service['PrivateTmp'], 'true')
        self.assertEqual(int(service['TimeoutStartSec']), 900)
        self.assertNotIn('Install', unit)
        self.assertNotIn('cgp-letsencrypt', str(dict(unit['Unit'])))
        self.assertFalse(any(key.startswith('Exec') and key != 'ExecStart' for key in service))

    def test_timer_waits_after_completion_without_catchup_or_certificate_coupling(self):
        unit = self.unit('cgp-monitor.timer')
        timer = unit['Timer']
        self.assertEqual(timer['OnBootSec'], '2min')
        self.assertEqual(timer['OnUnitInactiveSec'], '5min')
        self.assertEqual(timer['RandomizedDelaySec'], '30')
        self.assertEqual(timer['Unit'], 'cgp-monitor.service')
        self.assertNotIn('OnCalendar', timer)
        self.assertNotIn('OnUnitActiveSec', timer)
        self.assertNotIn('Persistent', timer)
        self.assertEqual(unit['Install']['WantedBy'], 'timers.target')
        self.assertNotIn('cgp-letsencrypt', str(dict(unit['Unit'])))

    def test_container_guard_blocks_worker_before_it_drops_ambient_test_guards(self):
        source = (ROOT / 'tests/integration/installer.sh').read_text()
        guard = source.split("<<'OFFLINE_GUARD'\n", 1)[1].split('\nOFFLINE_GUARD\n', 1)[0]
        program = '''
from pathlib import Path
import sys
from unittest.mock import patch
from cgp_cert_manager import monitor_worker

namespace = {'__name__': 'sitecustomize'}
exec(Path(sys.argv[1]).read_text(), namespace)
marker = Path(sys.argv[2])
namespace['_attempt_marker'] = marker
for kind in ('probe', 'notify'):
    sys.setprofile(namespace['block_worker'])
    with patch.object(monitor_worker.subprocess, 'Popen') as spawn:
        try:
            monitor_worker.execute(kind, {}, 1)
        except AssertionError:
            pass  # A swallowed refusal must still leave durable test evidence.
        else:
            raise AssertionError('Worker escaped the installer guard')
        finally:
            sys.setprofile(None)
        spawn.assert_not_called()
    assert marker.read_text() == 'Unexpected installer network operation\\n'
    marker.unlink()
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'guard.py'
            path.write_text(guard)
            result = subprocess.run([sys.executable, '-c', program, str(path), str(Path(directory) / 'attempt')],
                                    cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
