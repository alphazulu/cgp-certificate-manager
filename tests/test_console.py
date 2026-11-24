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
            if flags not in (('--verify',),('--verify-listeners',),('--backups',)):
                self.assertTrue(confirm,label)

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
