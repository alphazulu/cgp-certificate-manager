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

    def test_cancel_is_not_no(self):
        with patch.object(tui,'dialog',side_effect=tui.Cancel(255)):
            with self.assertRaises(tui.Cancel): tui.yes('question')
        with patch.object(tui,'dialog',side_effect=tui.Cancel(1)):
            self.assertFalse(tui.yes('question'))
    def test_schedule(self):
        from cgp_cert_manager.schedule import render
        self.assertIn('03,15:00:00',render({}))
        self.assertIn('08,20:00:00',render({'hour':20}))
        with self.assertRaises(ValueError): render({'hour':24})
    def test_global_tls_template(self):
        d={'names':['example.com','alias.net'],'tls':[{'host':'127.0.0.1','port':993}]}
        self.assertEqual([e['sni'] for e in core.tls_endpoints(d)],['alias.net','example.com'])
    def test_failed_save_preserves_old_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            conf=root/'config.json'
            core.atomic(conf,{'old':True})
            stage=root/'staged.ini'
            tui.write_token(stage,'example_token')
            target=root/'new.ini'
            with patch.object(core,'CONFIG',conf), patch.object(core,'STATE',root/'state'), patch.object(core,'atomic',side_effect=OSError('test')):
                with self.assertRaises(OSError):
                    tui.save_config({'new':True},{str(target):stage},{str(target)})
            self.assertEqual(core.load(conf),{'old':True})

    def test_exit_actions_visible_first(self):
        with patch.object(tui,'dialog',return_value='9') as d:
            self.assertEqual(tui.main_menu(),'9')
            args=d.call_args.args
            self.assertEqual(args[5:9],('8','Save and exit','9','Exit without saving'))
            self.assertTrue(d.call_args.kwargs['main_menu'])
    def test_exit_confirmation(self):
        with patch.object(tui,'yes',return_value=False) as q:
            self.assertTrue(tui.confirm_exit(False))
            q.assert_not_called()
            self.assertFalse(tui.confirm_exit(True))
        with patch.object(tui,'yes',side_effect=tui.Cancel(255)):
            self.assertFalse(tui.confirm_exit(True))
    def test_exit_without_save(self):
        for action in ('9',tui.Cancel(1),tui.Cancel(255)):
            with self.subTest(action=action), patch.object(core,'load',return_value=tui.default_config()), patch.object(tui,'main_menu',side_effect=[action]), patch.object(tui,'save_config') as save:
                self.assertEqual(tui.edit(),tui.CANCELLED)
                save.assert_not_called()
    def test_dirty_exit_declined_then_confirmed(self):
        with patch.object(core,'load',return_value=tui.default_config()), patch.object(tui,'main_menu',side_effect=['11','9','9']), patch.object(tui,'dialog',return_value='ru'), patch.object(tui,'yes',side_effect=[False,True]), patch.object(tui,'save_config') as save:
            self.assertEqual(tui.edit(),tui.CANCELLED)
            save.assert_not_called()
