import tempfile
import unittest
from pathlib import Path
from cgp_cert_manager import tui, core
from unittest.mock import patch

class TUITests(unittest.TestCase):
    def test_defaults(self):
        self.assertFalse(tui.default_config()['auto_enable_new_domains'])
    def test_names(self):
        self.assertEqual(tui.names('EXAMPLE.com пример.рф'),['example.com','xn--e1afmkfd.xn--p1ai'])
        with self.assertRaises(ValueError): tui.names('127.0.0.1')
    def test_number(self):
        self.assertEqual(tui.number('443',1,65535),443)
        with self.assertRaises(ValueError): tui.number('0',1,65535)
    def test_token(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'token.ini'
            tui.write_token(p,'example_token')
            self.assertEqual(core.token(p),'example_token')
            self.assertEqual(p.stat().st_mode & 0o777,0o600)
            with self.assertRaises(ValueError): tui.write_token(p,'abc\ninjected')
            self.assertEqual(core.token(p),'example_token')
    def test_new_domains_policy(self):
        with patch.object(core,'cli',side_effect=['(example.com)','()']):
            result=core.discover({'auto_enable_new_domains':False},{'example.com':{}})
        self.assertFalse(result[0]['enabled'])
