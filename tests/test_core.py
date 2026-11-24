import unittest
from unittest.mock import patch
from cgp_cert_manager.core import *
from cgp_cert_manager.cli import migrate
class Tests(unittest.TestCase):
    def test_ip(self):
        for n in ['192.168.0.12','[2001:db8::1]','2001:db8::1']: self.assertEqual(dns_name(n)[1],'ip_address')
    def test_idn(self): self.assertEqual(dns_name('пример.рф')[0],'xn--e1afmkfd.xn--p1ai')
    def test_wildcard(self):
        self.assertTrue(covered('mail.example.com','*.example.com')); self.assertFalse(covered('a.mail.example.com','*.example.com'))
    def test_zone(self): self.assertEqual(zone_for('*.x.example.com',{'example.com':1,'x.example.com':2}),'x.example.com')
    def test_shrink(self):
        d={'names':['example.com'],'unavailable':['alias.net']}; old={'names':['example.com','alias.net']}
        self.assertEqual(shrink_block(d,old),['alias.net']); self.assertEqual(shrink_block(d,old,True),[])
        d['unavailable']=[]; self.assertEqual(shrink_block(d,old),[])
    def test_discovery(self):
        cfg={'domains':[]}; z={'example.com':{},'alias.net':{}}
        with patch('cgp_cert_manager.core.cli',side_effect=['(example.com)','(mail.example.com,alias.net,192.168.1.1,nozone.net)']):
            d=discover(cfg,z)[0]
        self.assertEqual(d['names'],['*.example.com','alias.net','example.com']); self.assertEqual(d['skipped_names']['192.168.1.1'],'ip_address')
    def test_migration(self):
        cfg={'domains':[{'cgp_domain':'example.com','names':['example.com','alias.net'],'extra_names':[],'enabled':False}]}
        d=migrate(cfg)['domains'][0]; self.assertEqual(d['extra_names'],[]); self.assertFalse(d['enabled']); self.assertNotIn('names',d)
    def test_fields(self):
        f=fields('{PrivateSecureKey=[YWJj]; SecureCertificate=[YWJj]; CAChain=[YWJj]; CertificateType=Enabled;}'); self.assertEqual(set(f),set(FIELDS)); self.assertEqual(current_fp(f),hashlib.sha256(b'abc').hexdigest())
    def test_array(self): self.assertEqual(array('(a.com,"b.com")'),['a.com','b.com']); self.assertEqual(array('()'),[])
if __name__=='__main__': unittest.main()
