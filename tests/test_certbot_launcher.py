import runpy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from cgp_cert_manager import certbot_runner, update_gate


class CertbotLauncherTests(unittest.TestCase):
    def test_installed_entrypoint_uses_supervised_runner(self):
        launcher = Path(__file__).resolve().parents[1] / "certbot-launcher"
        with patch.object(sys, "path", list(sys.path)), patch.object(sys, 'dont_write_bytecode', False), \
                patch.dict(sys.modules, {'cgp_update_gate': update_gate}), \
                patch.object(certbot_runner, "main", return_value=7) as main:
            with self.assertRaises(SystemExit) as exited:
                runpy.run_path(str(launcher), run_name="__main__")
            self.assertEqual(exited.exception.code, 7)
            self.assertEqual(sys.path[0], "/opt/cgp-certificate-manager")
            self.assertTrue(sys.dont_write_bytecode)
            main.assert_called_once_with()
