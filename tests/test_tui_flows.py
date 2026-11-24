"""Configuration wizard workflows, with isolated filesystem and mocked dialogs."""
import contextlib
import copy
import io
import os
import runpy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from cgp_cert_manager import tui as t, core as c

class WizardTests(unittest.TestCase):
    def setUp(self):
        self.stack=contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.root=Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.config=self.root/'config.json'
        self.credential=self.root/'cloudflare.ini'
        t.write_token(self.credential,'dummy_old')
        self.cfg=t.default_config()
        self.cfg.update(email='admin@example.com',cloudflare_credentials=str(self.credential))
        self.cfg['communigate'].update(username='admin',password='dummy')
        c.atomic(self.config,self.cfg)
        self.stack.enter_context(patch.object(c,'CONFIG',self.config))
        self.stack.enter_context(patch.object(c,'STATE',self.root/'state'))
        self.stack.enter_context(patch.object(t,'LANGUAGE','en'))
        self.zones=self.stack.enter_context(patch.object(c,'zones',return_value={'example.com':{}}))
        self.discover=self.stack.enter_context(patch.object(c,'discover',return_value=[{'cgp_domain':'example.com','enabled':True,'names':['example.com']}]))
        self.api=self.stack.enter_context(patch.object(c,'cli',return_value='(example.com)'))
        self.message=self.stack.enter_context(patch.object(t,'msg'))
        self.menu=self.stack.enter_context(patch.object(t,'main_menu'))
        self.dialog=self.stack.enter_context(patch.object(t,'dialog'))
        self.ask=self.stack.enter_context(patch.object(t,'ask'))
        self.secret=self.stack.enter_context(patch.object(t,'secret'))
        self.yes=self.stack.enter_context(patch.object(t,'yes',return_value=True))

    def edit(self,*choices):
        self.menu.side_effect=choices
        return t.edit()

    def saved(self): return c.load(self.config)

    def test_connection_keeps_password(self):
        self.ask.side_effect=['http://127.0.0.1:8101/CLI/','newadmin']
        self.secret.return_value=''
        self.assertEqual(self.edit('1','8'),t.SAVED)
        self.assertEqual(self.saved()['communigate'],{'url':'http://127.0.0.1:8101/CLI/','username':'newadmin','password':'dummy'})

    def test_connection_replaces_password(self):
        self.ask.side_effect=['http://127.0.0.1:8100/CLI/','admin']
        self.secret.return_value='new_dummy'
        self.assertEqual(self.edit('1','8'),t.SAVED)
        self.assertEqual(self.saved()['communigate']['password'],'new_dummy')

    def test_cloudflare_add_and_list(self):
        self.dialog.side_effect=['add','list']
        self.ask.return_value='second'
        self.secret.return_value='dummy_new'
        self.assertEqual(self.edit('2','2','8'),t.SAVED)
        accounts=self.saved()['cloudflare_accounts']
        self.assertEqual(len(accounts),2)
        self.assertEqual(c.token(accounts[1]['credentials']),'dummy_new')
        self.assertEqual(c.token(self.credential),'dummy_old')
        self.assertTrue(any('example.com' in str(a) for a in self.message.call_args_list))

    def test_cloudflare_remove(self):
        other=self.root/'other.ini'
        t.write_token(other,'dummy_other')
        self.cfg['cloudflare_accounts']=[{'credentials':str(self.credential)},{'credentials':str(other)}]
        c.atomic(self.config,self.cfg)
        self.dialog.side_effect=['remove',str(other)]
        self.assertEqual(self.edit('2','8'),t.SAVED)
        self.assertEqual(self.saved()['cloudflare_accounts'],[{'credentials':str(self.credential)}])
        self.assertTrue(other.exists())

    def test_cloudflare_remove_last_refused(self):
        self.dialog.side_effect=['remove',str(self.credential)]
        self.assertEqual(self.edit('2','9'),t.CANCELLED)
        self.assertIn('At least one',self.message.call_args.args[0])
        self.assertEqual(self.saved(),self.cfg)

    def test_invalid_account(self):
        self.dialog.return_value='add'
        self.ask.return_value='../bad'
        self.assertEqual(self.edit('2','9'),t.CANCELLED)
        self.secret.assert_not_called()
        self.assertIn('Invalid account',self.message.call_args.args[0])

    def test_staged_token_cancel(self):
        self.dialog.return_value='add'
        self.ask.return_value='new'
        self.secret.return_value='dummy_new'
        self.assertEqual(self.edit('2','9'),t.CANCELLED)
        self.assertEqual(self.saved(),self.cfg)
        self.assertEqual(list(self.root.glob('cloudflare-*.ini')),[])

    def test_domain_with_custom_tls(self):
        self.dialog.return_value='example.com'
        self.ask.side_effect=['alias.com','old.com','127.0.0.1','993','','example.com']
        self.yes.side_effect=[True,False,True,False,True]
        self.assertEqual(self.edit('3','8'),t.SAVED)
        self.assertEqual(self.saved()['domains'],[{'cgp_domain':'example.com','enabled':True,'wildcard':False,'extra_names':['alias.com'],'exclude_names':['old.com'],'tls':[{'host':'127.0.0.1','port':993,'sni':'example.com'}]}])

    def test_edit_existing_domain(self):
        self.cfg['domains']=[{'cgp_domain':'other.com','enabled':True},{'cgp_domain':'example.com','enabled':True,'tls':[{'port':443}]}]
        c.atomic(self.config,self.cfg)
        self.discover.return_value=[{'cgp_domain':'example.com','enabled':False,'names':['example.com']}]
        self.dialog.return_value='example.com'
        self.ask.side_effect=['','']
        self.yes.side_effect=[False,True,False,True]
        self.assertEqual(self.edit('3','8'),t.SAVED)
        self.assertEqual(len(self.saved()['domains']),2)
        self.assertFalse(self.saved()['domains'][1]['enabled'])
        self.assertEqual(self.saved()['domains'][1]['tls'],[{'port':443}])

    def test_no_domains(self):
        self.discover.return_value=[]
        self.assertEqual(self.edit('3','9'),t.CANCELLED)
        self.assertIn('No domains',self.message.call_args.args[0])

    def test_acme_tls_smtp_schedule_language(self):
        self.ask.side_effect=['new@example.com','90','ops@example.com','sender@example.com','127.0.0.1','2525','7','300']
        self.yes.side_effect=[False,True,True,True,True]
        self.dialog.return_value='ru'
        self.assertEqual(self.edit('4','5','6','10','11','8'),t.SAVED)
        cfg=self.saved()
        self.assertEqual(cfg['email'],'new@example.com')
        self.assertEqual(cfg['propagation_seconds'],90)
        self.assertFalse(cfg['dns_preflight'])
        self.assertTrue(cfg['auto_enable_new_domains'])
        self.assertEqual(cfg['tls'],[])
        self.assertEqual(cfg['notifications']['port'],2525)
        self.assertEqual(cfg['schedule'],{'hour':7,'random_delay':300})
        self.assertEqual(cfg['tui_language'],'ru')

    def test_disable_smtp(self):
        self.cfg['notifications']={'to':'ops@example.com'}
        c.atomic(self.config,self.cfg)
        self.yes.side_effect=[False,True]
        self.assertEqual(self.edit('6','8'),t.SAVED)
        self.assertNotIn('notifications',self.saved())

    def test_invalid_smtp(self):
        self.ask.side_effect=['','sender@example.com','localhost','25']
        self.assertEqual(self.edit('6','9'),t.CANCELLED)
        self.assertIn('Sender and recipient',self.message.call_args.args[0])

    def test_diagnostics_and_save_declined(self):
        self.yes.return_value=False
        self.assertEqual(self.edit('7','8','9'),t.CANCELLED)
        self.assertIn('CGP and Cloudflare',self.message.call_args.args[0])
        self.assertEqual(self.saved(),self.cfg)

    def test_saved_message_cancel(self):
        self.message.side_effect=t.Cancel(255)
        self.assertEqual(self.edit('8'),t.SAVED)

    def test_section_cancel(self):
        self.ask.side_effect=t.Cancel(255)
        self.assertEqual(self.edit('1','9'),t.CANCELLED)

    def test_unexpected_main_cancel(self):
        with self.assertRaises(t.Cancel): self.edit(t.Cancel(2))

    def test_api_error_redacted_and_message_cancel(self):
        self.zones.side_effect=OSError('dummy secret')
        self.message.side_effect=t.Cancel(255)
        self.assertEqual(self.edit('7','9'),t.CANCELLED)
        self.assertEqual(self.message.call_args.args[0],'Operation failed: OSError')

    def test_unknown_menu_choice(self):
        self.assertEqual(self.edit('unexpected','9'),t.CANCELLED)
        self.assertEqual(self.saved(),self.cfg)

class WizardHelpers(unittest.TestCase):
    def test_dialog_output_and_buttons(self):
        def fake(args,pass_fds):
            os.write(pass_fds[0],b' value\n')
            return Mock(returncode=0)
        with patch.object(t,'LANGUAGE','ru'),patch.object(t.subprocess,'run',side_effect=fake) as run:
            for kind,args in [('--menu',('Select domain',20,70,4,'1','Back')),('--inputbox',('TLS host',10,70,'localhost')),('--yesno',('Back',10,70)),('--msgbox',('Back',10,70))]:
                self.assertEqual(t.dialog(kind,*args),'value')
            self.assertEqual(t.tr('Back'),'Назад')
            self.assertEqual(t.tr('unknown'),'unknown')
            self.assertEqual(run.call_count,4)
        with patch.object(t.subprocess,'run',return_value=Mock(returncode=255)):
            with self.assertRaises(t.Cancel): t.dialog('--msgbox','text',10,70)

    def test_dialog_wrappers(self):
        with patch.object(t,'dialog',return_value='hello') as dialog:
            self.assertEqual(t.ask('test'),'hello')
            t.msg('test')
            self.assertTrue(t.yes('test'))
            self.assertEqual(dialog.call_count,3)
        with patch.object(t.getpass,'getpass',return_value='dummy') as getpass:
            self.assertEqual(t.secret('Token'),'dummy')
            getpass.assert_called_once_with('Token: ')

    def test_validate(self):
        cfg=t.default_config()
        for field,value in [('url','https://example.com/CLI/'),('url','http://127.0.0.1:8100/CLI/'),('username','admin'),('password','dummy')]:
            cfg['communigate'][field]=value
            with self.assertRaises(ValueError): t.validate(cfg)
        cfg['email']='admin@example.com'
        cfg['domains']=[{'cgp_domain':'example.com','extra_names':['alias.com']}]
        t.validate(cfg)

    def test_tls_modes(self):
        with patch.object(t,'yes',return_value=True):
            self.assertEqual(t.edit_tls([]),[])
        with patch.object(t,'yes',return_value=False):
            with patch.object(t,'ask',side_effect=['localhost','25','smtp','mail.example.com']):
                self.assertEqual(t.edit_tls([], 'example.com'),[{'host':'localhost','port':25,'starttls':'smtp','sni':'mail.example.com'}])
            with patch.object(t,'ask',side_effect=['localhost','443','bad']):
                with self.assertRaises(ValueError): t.edit_tls([])
            with patch.object(t,'ask',side_effect=['localhost','443','','*.example.com']):
                with self.assertRaises(ValueError): t.edit_tls([], 'example.com')
            with patch.object(t,'ask',side_effect=['localhost','443','']):
                self.assertEqual(t.edit_tls([]),[{'host':'localhost','port':443}])

    def test_token_write_failure(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(t.os,'replace',side_effect=OSError()):
            with self.assertRaises(OSError): t.write_token(Path(tmp)/'token.ini','dummy')
            self.assertEqual(list(Path(tmp).iterdir()),[])

    def test_save_new_and_existing_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); conf=root/'config.json'; stage=root/'stage.ini'; target=root/'target.ini'
            t.write_token(stage,'dummy')
            with patch.object(c,'CONFIG',conf),patch.object(c,'STATE',root/'state'):
                t.save_config({'new':1},{str(target):stage},set())
                self.assertFalse(target.exists())
                t.save_config({'new':2},{str(target):stage},{str(target)})
                self.assertTrue(target.exists())
                with self.assertRaises(ValueError):
                    t.save_config({'new':3},{str(target):stage},{str(target)})
                self.assertEqual(c.load(conf),{'new':2})

    def test_save_unknown_commit_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); stage=root/'stage.ini'; target=root/'target.ini'
            t.write_token(stage,'dummy')
            with patch.object(c,'CONFIG',root/'config.json'),patch.object(c,'STATE',root/'state'),patch.object(c,'atomic',side_effect=OSError()),patch.object(c,'load',side_effect=ValueError()):
                with self.assertRaises(OSError): t.save_config({'new':1},{str(target):stage},{str(target)})
            self.assertTrue(target.exists())

    def test_setup(self):
        with contextlib.ExitStack() as stack:
            root=Path(stack.enter_context(tempfile.TemporaryDirectory()))
            stack.enter_context(patch.object(c,'STATE',root))
            stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            uid=stack.enter_context(patch.object(t.os,'geteuid',return_value=1))
            stack.enter_context(patch.object(t.sys.stdin,'isatty',return_value=True))
            stack.enter_context(patch.object(t.sys.stdout,'isatty',return_value=True))
            which=stack.enter_context(patch.object(t.shutil,'which',return_value=None))
            stack.enter_context(patch.object(t.os,'umask'))
            self.assertEqual(t.setup(),1)
            uid.return_value=0
            self.assertEqual(t.setup(),1)
            which.return_value='/usr/bin/whiptail'
            with patch.object(t.fcntl,'flock',side_effect=BlockingIOError()):
                self.assertEqual(t.setup(),1)
            with patch.object(t,'edit',return_value=t.SAVED):
                self.assertEqual(t.setup(),t.SAVED)
            with patch.object(t,'edit',side_effect=KeyboardInterrupt()):
                self.assertEqual(t.setup(),t.CANCELLED)

    def test_main_module(self):
        with patch.object(t.os,'geteuid',return_value=1),patch.object(t.sys,'argv',['tui','--setup']),contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as exc:
                runpy.run_module('cgp_cert_manager.tui',run_name='__main__')
        self.assertEqual(exc.exception.code,1)
