import unittest
from unittest.mock import patch
from cgp_cert_manager import console

class ConsoleTests(unittest.TestCase):
    def test_command_dispatch(self):
        for index,(_,flags,_) in enumerate(console.ACTIONS):
            cmd=console.command_for('example.com',index)
            self.assertEqual(cmd[:len(console.CLI)],console.CLI)
            self.assertIn('example.com',cmd)
            if flags in (('--rollback',),('--backups',)):
                self.assertEqual(cmd[-2:],list(flags)+['example.com'])
            else:
                self.assertIn('--domain',cmd)
        with self.assertRaises(Exception): console.command_for('bad;command',0)

    def test_mutations_confirmed(self):
        for label,flags,confirm in console.ACTIONS:
            if flags not in (('--verify',),('--verify-listeners',),('--backups',),('--transactions',)):
                self.assertTrue(confirm,label)

    def test_transaction_actions_are_appended_and_scoped(self):
        self.assertEqual(console.ACTIONS[7][1],('--rollback',))
        self.assertEqual(console.ACTIONS[9][1],('--retry-now',))
        self.assertEqual(console.command_for('example.com',10),console.CLI+['--domain','example.com','--transactions'])
        self.assertEqual(console.command_for('example.com',11),console.CLI+['--domain','example.com','--recover'])
        self.assertFalse(console.ACTIONS[10][2])
        self.assertTrue(console.ACTIONS[11][2])

    def test_transaction_labels_are_translated(self):
        for label in ('Transaction status','Recover pending transaction','Recover all pending transactions','Pending transactions','F9: inspect or recover pending transactions'):
            self.assertNotEqual(console.translate(label,'ru'),label)
            self.assertEqual(console.translate(label,'en'),label)
        self.assertIn('F9: inspect or recover pending transactions',console.HELP)

    def test_status_parser(self):
        with patch.object(console,'capture',return_value=(0,'[{"domain":"z.com"},{"domain":"a.com"}]','')):
            rows,message=console.read_status()
            self.assertEqual([r['domain'] for r in rows],['a.com','z.com'])
        with patch.object(console,'capture',return_value=(1,'invalid','')):
            self.assertEqual(console.read_status()[0],[])

    def test_control_characters(self):
        self.assertEqual(console.safe_text('x\x1by\nz'),'x y z')

    def test_details(self):
        text='\n'.join(console.details({'domain':'example.com','installed':{'names':['example.com']},'desired':['example.com','alias.com']}))
        self.assertIn('alias.com',text)
        self.assertIn('Installed SANs:',text)

    def test_verify_returns_to_domain_menu(self):
        from unittest.mock import Mock
        screen=console.Screen.__new__(console.Screen)
        screen.rows=[{'domain':'example.com'}]
        screen.selected=0
        screen.menu=Mock(side_effect=[1,None])
        screen.inspect=Mock()
        screen.verify=Mock()
        screen.all_rows=screen.rows
        screen.execute=Mock()
        screen.domain_menu()
        screen.verify.assert_called_once_with('example.com')
        screen.inspect.assert_not_called()
        screen.execute.assert_not_called()
        self.assertEqual(screen.menu.call_count,2)

    def test_inspection_does_not_suspend_curses(self):
        from unittest.mock import Mock
        screen=console.Screen.__new__(console.Screen)
        screen.w=Mock()
        screen.put=Mock()
        screen.view=Mock()
        with patch.object(console,'capture',return_value=(0,'verified','')), patch.object(console.curses,'endwin') as endwin:
            screen.inspect(['example'],'TLS')
        endwin.assert_not_called()
        self.assertIn('Exit code: 0',screen.view.call_args.args[1])

    def test_verification_identity(self):
        row={'domain':'example.com','status':'ready','installed':{'fingerprint':'a'},'local':{'fingerprint':'a'},'desired':['example.com']}
        result=dict(row,tls='verified')
        console.verified_rows([row],[result])
        self.assertEqual(console.row_status(row),'VERIFIED')
        changed=dict(row,installed={'fingerprint':'b'})
        changed.pop('tls')
        console.verified_rows([changed],[result])
        self.assertNotIn('tls',changed)
    def test_backup_path(self):
        self.assertIn('--backup-file',console.backup_command('example.com','20261124T010203123456Z.json'))
        with self.assertRaises(ValueError): console.backup_command('example.com','../../config.json')
    def test_status_priority(self):
        self.assertEqual(console.row_status({'status':'ready','action':'REISSUE','tls':'verified'}),'REISSUE')
        self.assertEqual(console.row_status({'status':'ready','tls':'failed'}),'ERROR')
