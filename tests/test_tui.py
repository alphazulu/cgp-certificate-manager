import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from cgp_cert_manager import tui, core, storage
from unittest.mock import Mock, patch

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

    def test_unsupported_provider_refuses_before_wizard_or_temporary_credential_staging(self):
        for value in ('PRIVATE_PROVIDER', None, True, {'name': 'cloudflare'}):
            cfg = dict(tui.default_config(), dns_provider=value)
            with self.subTest(provider=value), patch.object(core, 'load', return_value=cfg), \
                    patch.object(tui.tempfile, 'TemporaryDirectory') as temporary, \
                    patch.object(tui, 'main_menu') as menu, patch.object(tui, 'write_token') as token, \
                    patch.object(core, 'zones') as zones, patch.object(tui, 'save_config') as save:
                with self.assertRaises(core.Error) as raised:
                    tui.edit()
                self.assertNotIn('PRIVATE_PROVIDER', str(raised.exception))
                for operation in (temporary, menu, token, zones, save):
                    operation.assert_not_called()

    def test_provider_guard_does_not_prevent_editing_invalid_propagation_settings(self):
        cfg = dict(tui.default_config(), dns_provider='cloudflare', dns_propagation={'mode': 'invalid'})
        with patch.object(core, 'load', return_value=cfg), patch.object(tui, 'main_menu', return_value='9'), \
                patch.object(tui, 'save_config') as save:
            self.assertEqual(tui.edit(), tui.CANCELLED)
        save.assert_not_called()
        self.assertEqual(cfg['dns_provider'], 'cloudflare')
        self.assertEqual(cfg['dns_propagation'], {'mode': 'invalid'})
    def test_dirty_exit_declined_then_confirmed(self):
        with patch.object(core,'load',return_value=tui.default_config()), patch.object(tui,'main_menu',side_effect=['11','9','9']), patch.object(tui,'dialog',return_value='ru'), patch.object(tui,'yes',side_effect=[False,True]), patch.object(tui,'save_config') as save:
            self.assertEqual(tui.edit(),tui.CANCELLED)
            save.assert_not_called()

    def test_localization(self):
        from cgp_cert_manager.localization import translate
        self.assertEqual(translate('Back','ru'),'Назад')
        self.assertEqual(translate('Manage example.com automatically?','ru'),'Обслуживать example.com автоматически?')
        self.assertEqual(translate('Back','en'),'Back')


class WizardPrivateStorageTests(unittest.TestCase):
    def setUp(self):
        self.stack=contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.root=Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.config=self.root/'config.json'
        self.state=self.root/'state'
        self.state.mkdir(mode=0o700)
        self.stage=self.root/'stage.ini'
        self.target=self.root/'new.ini'
        core.atomic(self.config,{'previous':True})
        tui.write_token(self.stage,'dummy')
        self.stack.enter_context(patch.object(core,'CONFIG',self.config))
        self.stack.enter_context(patch.object(core,'STATE',self.state))

    def save(self):
        tui.save_config({'next':True},{str(self.target):self.stage},{str(self.target)})

    def test_token_write_refuses_unsafe_existing_file(self):
        before=self.stage.read_bytes()
        self.stage.chmod(0o644)
        with self.assertRaises(storage.StorageError): tui.write_token(self.stage,'new_dummy')
        self.assertEqual(self.stage.read_bytes(),before)
        self.assertEqual(self.stage.stat().st_mode&0o777,0o644)

    def test_token_write_refuses_symlink_and_unsafe_parent(self):
        self.target.symlink_to(self.stage)
        with self.assertRaises(storage.StorageError): tui.write_token(self.target,'new_dummy')
        self.assertTrue(self.target.is_symlink())
        self.assertEqual(core.token(self.stage),'dummy')
        directory=self.root/'unsafe'
        directory.mkdir(mode=0o777)
        directory.chmod(0o777)
        with self.assertRaises(storage.StorageError): tui.write_token(directory/'token.ini','dummy')
        self.assertEqual(list(directory.iterdir()),[])
        self.assertEqual(directory.stat().st_mode&0o777,0o777)

    def test_unsafe_configuration_is_refused_before_backup(self):
        before=self.config.read_bytes()
        self.config.chmod(0o644)
        with self.assertRaises(storage.StorageError): self.save()
        self.assertEqual(self.config.read_bytes(),before)
        self.assertEqual(self.config.stat().st_mode&0o777,0o644)
        self.assertFalse((self.state/'config-backups').exists())
        self.assertFalse(self.target.exists())

    def test_configuration_symlink_is_refused_before_backup(self):
        original=self.root/'original.json'
        self.config.rename(original)
        self.config.symlink_to(original)
        with self.assertRaises(storage.StorageError): self.save()
        self.assertTrue(self.config.is_symlink())
        self.assertEqual(core.load(original),{'previous':True})
        self.assertFalse((self.state/'config-backups').exists())

    def test_unsafe_backup_directory_is_not_repaired(self):
        directory=self.state/'config-backups'
        directory.mkdir(mode=0o755)
        directory.chmod(0o755)
        with self.assertRaises(storage.StorageError): self.save()
        self.assertEqual(directory.stat().st_mode&0o777,0o755)
        self.assertEqual(list(directory.iterdir()),[])
        self.assertEqual(core.load(self.config),{'previous':True})
        self.assertFalse(self.target.exists())

    def test_backup_directory_symlink_is_refused(self):
        elsewhere=self.root/'elsewhere'
        elsewhere.mkdir(mode=0o700)
        (self.state/'config-backups').symlink_to(elsewhere,target_is_directory=True)
        with self.assertRaises(storage.StorageError): self.save()
        self.assertEqual(list(elsewhere.iterdir()),[])
        self.assertEqual(core.load(self.config),{'previous':True})

    def test_backup_keeps_original_bytes_and_private_modes(self):
        previous=self.config.read_bytes()
        self.save()
        backups=list((self.state/'config-backups').glob('*/config.json'))
        self.assertEqual(len(backups),1)
        self.assertEqual(backups[0].read_bytes(),previous)
        self.assertEqual(backups[0].stat().st_mode&0o777,0o600)
        self.assertEqual(backups[0].parent.stat().st_mode&0o777,0o700)
        self.assertEqual(backups[0].parent.parent.stat().st_mode&0o777,0o700)
        self.assertEqual(core.load(self.config),{'next':True})
        self.assertEqual(core.token(self.target),'dummy')

    def test_dangling_credential_target_is_refused(self):
        missing=self.root/'missing.ini'
        self.target.symlink_to(missing)
        with self.assertRaises(storage.StorageError): self.save()
        self.assertTrue(self.target.is_symlink())
        self.assertFalse(missing.exists())
        self.assertEqual(core.load(self.config),{'previous':True})

    def test_setup_refuses_unsafe_lock_without_editing(self):
        (self.state/'run.lock').symlink_to(self.stage)
        with patch.object(tui,'os',Mock(wraps=os)) as ui_os, \
                patch.object(tui.sys.stdin,'isatty',return_value=True), \
                patch.object(tui.sys.stdout,'isatty',return_value=True), \
                patch.object(tui.shutil,'which',return_value='/usr/bin/whiptail'), \
                patch.object(tui,'edit') as edit,contextlib.redirect_stderr(io.StringIO()) as output:
            ui_os.geteuid.return_value=0
            ui_os.umask.return_value=0o022
            self.assertEqual(tui.setup(),1)
        edit.assert_not_called()
        self.assertIn('Configuration refused',output.getvalue())
        self.assertEqual(core.token(self.stage),'dummy')

    def test_existing_unsafe_backup_blocks_save_and_editor(self):
        directory=self.state/'config-backups'
        directory.mkdir(mode=0o700)
        backup=directory/'old.json'
        backup.write_text('private backup fixture')
        backup.chmod(0o644)
        with self.assertRaises(storage.StorageError): self.save()
        with patch.object(tui,'os',Mock(wraps=os)) as ui_os, \
                patch.object(tui.sys.stdin,'isatty',return_value=True), \
                patch.object(tui.sys.stdout,'isatty',return_value=True), \
                patch.object(tui.shutil,'which',return_value='/usr/bin/whiptail'), \
                patch.object(tui,'edit') as edit,contextlib.redirect_stderr(io.StringIO()):
            ui_os.geteuid.return_value=0
            ui_os.umask.return_value=0o022
            self.assertEqual(tui.setup(),1)
        edit.assert_not_called()
        self.assertEqual(core.load(self.config),{'previous':True})
        self.assertEqual(backup.read_text(),'private backup fixture')
        self.assertEqual(backup.stat().st_mode&0o777,0o644)
        self.assertEqual(list(directory.iterdir()),[backup])
        self.assertFalse(self.target.exists())
