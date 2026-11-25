"""Installed updater delegation and the exact offline container entrypoint gate."""
from pathlib import Path
import runpy
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from cgp_cert_manager import update_cli


ROOT = Path(__file__).resolve().parents[1]


class UpdateInstallationTests(unittest.TestCase):
    def test_launcher_delegates_to_update_cli_without_an_implicit_action(self):
        launcher = ROOT / 'update-launcher'
        self.assertEqual(stat.S_IMODE(launcher.stat().st_mode), 0o755)
        with patch.object(sys, 'path', list(sys.path)), patch.object(update_cli, 'main', return_value=7) as main:
            with self.assertRaises(SystemExit) as exited:
                runpy.run_path(str(launcher), run_name='__main__')
            self.assertEqual(exited.exception.code, 7)
            self.assertEqual(sys.path[0], '/opt/cgp-certificate-manager')
            main.assert_called_once_with()

    def test_exact_container_entrypoint_is_fresh_read_only_and_backend_independent(self):
        source = (ROOT / 'tests/integration/installer.sh').read_text()
        guard = source.split("<<'OFFLINE_GUARD'\n", 1)[1].split('\nOFFLINE_GUARD\n', 1)[0]
        entrypoint = source.split("<<'UPDATE_ENTRYPOINT'\n", 1)[1].split('\nUPDATE_ENTRYPOINT\n', 1)[0]
        program = '''
from pathlib import Path
import sys

application, fixtures = (Path(value) for value in sys.argv[1:3])
action = sys.argv[3]
sys.path.insert(0, str(application))
guard = {'__name__': 'sitecustomize'}
exec(compile((fixtures / 'guard.py').read_text(), 'guard.py', 'exec'), guard)
guard['_attempt_marker'] = fixtures / 'network-attempted'
sys.argv = [str(fixtures / 'entrypoint.py'), str(application),
            str(application / 'update-launcher'), action,
            *[str(fixtures / name) for name in ('trust', 'update-state', 'manager-state', 'monitor-state')]]
try:
    exec(compile((fixtures / 'entrypoint.py').read_text(), 'entrypoint.py', 'exec'),
         {'__name__': '__main__'})
finally:
    sys.setprofile(None)
assert not guard['_attempt_marker'].exists(), 'The installed entrypoint attempted network access'
'''
        for provisioned in (False, True):
            for action in ('--help', '--version'):
                with self.subTest(provisioned=provisioned, action=action), tempfile.TemporaryDirectory() as directory:
                    fixtures = Path(directory)
                    (fixtures / 'guard.py').write_text(guard)
                    (fixtures / 'entrypoint.py').write_text(entrypoint)
                    if provisioned:
                        for name, filename in (('trust', 'trust.json'), ('update-state', 'checkpoint.json'),
                                               ('manager-state', 'state.json'), ('monitor-state', 'state.json')):
                            private = fixtures / name
                            private.mkdir(mode=0o700)
                            evidence = private / filename
                            evidence.write_text('{"synthetic":"retain independently provisioned evidence"}\n')
                            evidence.chmod(0o600)
                    result = subprocess.run([sys.executable, '-I', '-c', program, str(ROOT), str(fixtures), action],
                                            cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr.decode())
