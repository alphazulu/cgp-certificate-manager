import unittest
from unittest.mock import patch
from cgp_cert_manager import core as c
import base64, hashlib

def pem(b):
    return b'-----BEGIN CERTIFICATE-----\n'+base64.b64encode(b)+b'\n-----END CERTIFICATE-----\n'

def block(b): return '['+base64.b64encode(b).decode()+']'

class DeploymentTests(unittest.TestCase):
    def test_chain_padding(self):
        self.assertEqual(base64.b64decode(c.chain_payload(pem(b'a')+pem(b'bc'))),b'abc')
    def test_empty_chain(self):
        with self.assertRaises(c.Error): c.chain_payload(b'')
    def test_full_settings(self):
        f=dict(PrivateSecureKey=block(b'key'),SecureCertificate=block(b'leaf'),CAChain=block(b'abc'),CertificateType='YES')
        self.assertTrue(c.certificate_settings_match(f,f))
        for k,v in [('CAChain',block(b'a')),('PrivateSecureKey',block(b'wrong')),('CertificateType','Enabled'),('SecureCertificate',block(b'wrong'))]:
            self.assertFalse(c.certificate_settings_match(dict(f,**{k:v}),f))
    def test_probe_complete(self):
        data=pem(b'leaf')+pem(b'ca1')+pem(b'ca2')+b'Verify return code: 0 (ok)'
        expected=c.pem_fingerprints(data)
        ep={'port':443,'sni':'example.com'}
        with patch.object(c,'run',return_value=data): c.probe_tls(ep,expected)
        for bad in (b'Verify return code: 0 (ok)',pem(b'leaf')+pem(b'ca1')+b'Verify return code: 0 (ok)',data.replace(b'0 (ok)',b'20 (error)')):
            with patch.object(c,'run',return_value=bad):
                with self.assertRaises(c.Error): c.probe_tls(ep,expected)
    def test_alias_endpoints(self):
        d={'names':['example.com','*.example.com'],'aliases':['mail.example.com','192.168.1.1','bad.net','a.b.example.com']}
        self.assertEqual([x['sni'] for x in c.tls_endpoints(d)],['example.com','mail.example.com'])
    def test_listener_discovery(self):
        with patch.object(c,'run',return_value=b'LISTEN 0 150 0.0.0.0:443 0.0.0.0:* users:(("CGServer",pid=1,fd=1))\nLISTEN 0 150 0.0.0.0:25 0.0.0.0:* users:(("CGServer",pid=1,fd=1))\nLISTEN 0 150 0.0.0.0:993 0.0.0.0:* users:(("other",pid=1,fd=1))'):
            self.assertEqual(c.discover_listeners(),[{'port':25,'starttls':'smtp'},{'port':443,'starttls':None}])
    def test_rollback_after_failed_tls(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); p=root/'example.com'; p.mkdir()
            (p/'cert.pem').write_bytes(pem(b'leaf')); (p/'chain.pem').write_bytes(pem(b'ca1')+pem(b'ca2')); (p/'privkey.pem').write_bytes(b'key')
            old=dict(PrivateSecureKey=block(b'oldkey'),SecureCertificate=block(b'oldleaf'),CAChain=block(b'oldca'),CertificateType='YES')
            new=dict(PrivateSecureKey=block(b'key'),SecureCertificate=block(b'leaf'),CAChain=block(b'ca1ca2'),CertificateType='YES')
            d={'cgp_domain':'example.com','cert_name':'example.com','names':['example.com']}
            def fake_run(*args,**kw):
                return pem(b'key') if args[1]=='rsa' else b'pubkey'
            with patch.object(c,'LIVE',root), patch.object(c,'local_info',return_value={'names':d['names'],'days':80,'fingerprint':'abc'}), patch.object(c,'run',side_effect=fake_run), patch.object(c,'current',side_effect=[old,new,old]), patch.object(c,'backup',return_value=root/'backup.json'), patch.object(c,'update') as update, patch.object(c,'verify_tls',side_effect=c.Error('TLS failed')):
                with self.assertRaisesRegex(c.Error,'previous settings restored'): c.deploy({},d)
                self.assertEqual(update.call_count,2)
                self.assertEqual(update.call_args.args[2],old)
