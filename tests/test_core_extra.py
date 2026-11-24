import argparse
import base64
import hashlib
import io
import json
import runpy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, Mock
from cgp_cert_manager import core as c, cli, localization, schedule, recovery
from test_deployment import pem, block

class CoreExtraTests(unittest.TestCase):
    def test_atomic_failure_cleans_temp(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'config.json'
            c.atomic(path,{'old':1})
            with patch.object(c.os,'replace',side_effect=OSError()):
                with self.assertRaises(OSError): c.atomic(path,{'new':1})
            self.assertEqual(c.load(path),{'old':1})
            self.assertEqual(list(Path(tmp).iterdir()),[path])

    def test_names_invalid(self):
        for name in ('localhost','a.123','-bad.com','a..com','\ud800.com'):
            with self.subTest(name=name):
                self.assertEqual(c.dns_name(name),(None,'invalid_dns_name'))

    def test_identifiers_invalid(self):
        for name in ('../bad','a..b','a.','a;b'):
            with self.assertRaises(c.Error): c.identifier(name)

    def test_cgp_request(self):
        cfg={'communigate':{'url':'http://127.0.0.1:8100/CLI/','username':'user','password':'dummy'}}
        with patch.object(c,'opener') as opener:
            response=opener.return_value.open.return_value.__enter__.return_value
            response.read.return_value=b'(example.com)'
            self.assertEqual(c.cli(cfg,'LISTDOMAINS'),'(example.com)')
            response.read.assert_called_once_with(1024*1024+1)
            req=opener.return_value.open.call_args.args[0]
            self.assertEqual(req.data,b'command=LISTDOMAINS')
            self.assertEqual(req.get_header('Authorization'),'Basic '+base64.b64encode(b'user:dummy').decode())
        self.assertIsNotNone(c.opener())

    def test_cgp_response_size_and_encoding_are_bounded(self):
        cfg={'communigate':{'url':'http://127.0.0.1:8100/CLI/','username':'user','password':'dummy'}}
        with patch.object(c,'opener') as opener:
            response=opener.return_value.open.return_value.__enter__.return_value
            response.read.return_value=b'a'*(1024*1024)
            self.assertEqual(len(c.cli(cfg,'LISTDOMAINS')),1024*1024)
            response.read.return_value=b'a'*(1024*1024+1)
            with self.assertRaisesRegex(c.Error,'size limit'): c.cli(cfg,'LISTDOMAINS')
            response.read.return_value=b'PRIVATE_SENTINEL\xff'
            with self.assertRaisesRegex(c.Error,'response encoding') as caught: c.cli(cfg,'LISTDOMAINS')
            self.assertNotIn('PRIVATE_SENTINEL',str(caught.exception))

    def test_invalid_array(self):
        with self.assertRaises(c.Error): c.array('bad')
        self.assertEqual(c.array('()'),[])

    def test_token_and_cloudflare(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'token.ini'
            path.write_text('# comment\ndns_cloudflare_api_token = dummy\n')
            path.chmod(0o600)
            self.assertEqual(c.token(path),'dummy')
            for success in (True,False):
                with patch.object(c,'opener') as opener:
                    response=opener.return_value.open.return_value.__enter__.return_value
                    response.read.return_value=json.dumps({'success':success,'result':[]}).encode('utf-8')
                    if success:
                        self.assertEqual(c.cf(path,'zones',method='POST',params={'page':1},data={'x':1})['result'],[])
                        req=opener.return_value.open.call_args.args[0]
                        self.assertEqual(req.get_method(),'POST')
                        self.assertEqual(req.get_header('Authorization'),'Bearer dummy')
                        self.assertEqual(json.loads(req.data),{'x':1})
                    else:
                        with self.assertRaises(c.Error): c.cf(path,'zones')
            path.write_text('wrong=value\n')
            with self.assertRaises(c.Error): c.token(path)

    def test_zone_pagination(self):
        replies=[{'result':[{'name':'Example.COM','id':'1'},{'name':'bad','id':'x'}],'result_info':{'total_pages':2}}, {'result':[{'name':'sub.example.com','id':'2','name_servers':['ns.example.net']}]}, {'result':[{'name':'example.com','id':'3'}]}]
        with patch.object(c,'cf',side_effect=replies) as cf:
            zones=c.zones({'cloudflare_accounts':[{'credentials':'a'},{'credentials':'b'}]})
        self.assertEqual(zones['example.com']['id'],'1')
        self.assertEqual(zones['sub.example.com']['id'],'2')
        self.assertEqual(cf.call_args_list[1].kwargs['params']['page'],2)

    def test_discover_limits(self):
        cfg={'domains':[{'cgp_domain':'example.com','wildcard':False,'extra_names':['n%d.example.com'%i for i in range(101)]}]}
        with patch.object(c,'cli',side_effect=['(example.com)','()']):
            with self.assertRaisesRegex(c.Error,'Too many'): c.discover(cfg,{'example.com':{}})
        cfg={'domains':[{'cgp_domain':n,'cert_name':'same.com'} for n in ('a.com','b.com')]}
        with patch.object(c,'cli',side_effect=['(a.com,b.com)','()','()']):
            with self.assertRaisesRegex(c.Error,'Duplicate'): c.discover(cfg,{'a.com':{},'b.com':{}})

    def test_run_failure(self):
        with patch.object(c.subprocess,'run',return_value=Mock(returncode=1)):
            with self.assertRaisesRegex(c.Error,'openssl failed'): c.run('openssl','version')

    def test_malformed_datablock(self):
        self.assertFalse(c.certificate_settings_match({'CertificateType':'YES'},{}))
        f={'CertificateType':'YES','PrivateSecureKey':'bad'}
        self.assertFalse(c.certificate_settings_match(f,f))

    def test_certificate_info(self):
        with patch.object(c,'run',side_effect=[b'der',b'DNS:Example.COM, DNS:alias.com, DNS:example.com',b'notAfter=Nov 24 10:00:00 2099 GMT']):
            info=c.cert_info(b'pem')
        self.assertEqual(info['names'],['alias.com','example.com'])
        self.assertEqual(info['fingerprint'],hashlib.sha256(b'der').hexdigest())
        self.assertEqual(info['expiry'],'2099-11-24T10:00:00+00:00')

    def test_current_installed_local(self):
        with patch.object(c,'cli',return_value='{SecureCertificate=[YQ==];}'):
            self.assertEqual(c.current({},'example.com'),{'SecureCertificate':'[YQ==]'})
        self.assertIsNone(c.installed_info({}))
        with patch.object(c,'run',return_value=b'pem'),patch.object(c,'cert_info',return_value={'days':10}) as info:
            self.assertEqual(c.installed_info({'SecureCertificate':'[YQ==]'}),{'days':10})
            info.assert_called_once_with(b'pem')
        with tempfile.TemporaryDirectory() as tmp,patch.object(c,'LIVE',Path(tmp)):
            d={'cert_name':'example.com'}
            self.assertIsNone(c.local_info(d))
            p=Path(tmp)/'example.com'; p.mkdir()
            (p/'cert.pem').write_bytes(pem(b'leaf'))
            (p/'chain.pem').write_bytes(pem(b'ca'))
            with patch.object(c,'cert_info',return_value={'days':10}):
                self.assertEqual(c.local_info(d),{'days':10})
            self.assertEqual(c.expected_chain(d),[hashlib.sha256(x).hexdigest() for x in (b'leaf',b'ca')])

    def test_dns_preflight(self):
        from cgp_cert_manager import dnschecks
        d={'names':['example.com','*.example.com']}
        z={'example.com':{'ns':['ns.example.net']}}
        with patch.object(dnschecks,'require_ready') as check:
            c.dns_preflight(d,z)
            check.assert_called_once_with(d,z,None)
        with patch.object(dnschecks,'require_ready',side_effect=c.Error('DNS delegation mismatch')):
            with self.assertRaisesRegex(c.Error,'delegation mismatch'): c.dns_preflight(d,z)

    def test_single_account_issue(self):
        d={'cert_name':'example.com','names':['example.com']}
        with tempfile.TemporaryDirectory() as tmp, patch.object(c,'local_info',return_value=None),patch.object(c,'dns_preflight') as pre,patch.object(c.subprocess,'run') as run:
            credentials=Path(tmp)/'one.ini'
            credentials.write_text('dns_cloudflare_api_token = dummy\n'); credentials.chmod(0o600)
            z={'example.com':{'credentials':str(credentials)}}
            c.issue({'email':'a@example.com'},d,z,argparse.Namespace(force_renew=False,dry_run=False))
        pre.assert_called_once_with(d,z,{'email':'a@example.com'})
        cmd=run.call_args.args[0]
        self.assertIn('--dns-cloudflare',cmd)
        self.assertIn('--keep-until-expiring',cmd)
        self.assertNotIn('--dry-run',cmd)

    def test_update_validation(self):
        f=dict.fromkeys(c.FIELDS,'[YQ==]'); f['CertificateType']='YES'
        with patch.object(c,'cli') as api:
            with self.assertRaises(c.Error): c.update({},'example.com',{})
            with self.assertRaises(c.Error): c.update({},'example.com',dict(f,CAChain='bad;'))
            api.assert_not_called()
            c.update({},'example.com',f)
            self.assertTrue(api.call_args.args[1].startswith('UPDATEDOMAINSETTINGS example.com {'))

    def test_tls_explicit_and_starttls(self):
        ep={'port':25,'sni':'example.com','starttls':'smtp'}
        self.assertEqual(c.tls_endpoints({'tls':[ep]}),[ep])
        data=pem(b'leaf')+b'Verify return code: 0 (ok)'
        with patch.object(c,'run',return_value=data) as run:
            c.probe_tls(ep,c.pem_fingerprints(data))
        self.assertIn('-starttls',run.call_args.args)
        with patch.object(c,'expected_chain',return_value=['fp']),patch.object(c,'probe_tls') as probe:
            c.verify_tls({'tls':[ep]},'fp')
            probe.assert_called_once_with(ep,['fp'])
            with self.assertRaises(c.Error): c.verify_tls({'tls':[ep]},'wrong')
            with self.assertRaises(c.Error): c.verify_tls({'names':['*.example.com']},'fp')

    def test_backup_der_validation(self):
        for chain in (b'',b'x',b'\x30\x80',b'\x30\x82\x01'):
            f={'CertificateType':'YES','PrivateSecureKey':block(b'key'),'SecureCertificate':block(b'leaf'),'CAChain':block(chain)}
            with patch.object(c,'run',return_value=b'pubkey'):
                with self.assertRaises(c.Error): c.validate_backup(f)
        f={'CertificateType':'YES','PrivateSecureKey':'bad','SecureCertificate':block(b'leaf'),'CAChain':block(b'ca')}
        with self.assertRaises(c.Error): c.validate_backup(f)

    def test_backup_chain_success(self):
        short=b'\x30\x01a'; long=b'\x30\x81\x80'+b'b'*128
        f={'CertificateType':'YES','PrivateSecureKey':block(b'key'),'SecureCertificate':block(b'leaf'),'CAChain':block(short+long)}
        with patch.object(c,'run',side_effect=[b'pub',b'pub',b'ca1',b'ca2',b'leaf',b'ok']) as run:
            c.validate_backup(f)
        self.assertEqual(run.call_args_list[2].kwargs['data'],short)
        self.assertEqual(run.call_args_list[3].kwargs['data'],long)

class DeploymentExtraTests(unittest.TestCase):
    def setUp(self):
        import contextlib
        stack=contextlib.ExitStack(); self.addCleanup(stack.close)
        self.root=Path(stack.enter_context(tempfile.TemporaryDirectory()))
        p=self.root/'example.com'; p.mkdir()
        (p/'cert.pem').write_bytes(pem(b'leaf'))
        (p/'chain.pem').write_bytes(pem(b'ca'))
        self.old={'PrivateSecureKey':block(b'oldkey'),'SecureCertificate':block(b'oldleaf'),'CAChain':block(b'oldca'),'CertificateType':'YES'}
        self.new={'PrivateSecureKey':block(b'key'),'SecureCertificate':block(b'leaf'),'CAChain':block(b'ca'),'CertificateType':'YES'}
        self.d={'cgp_domain':'example.com','cert_name':'example.com','names':['example.com']}
        stack.enter_context(patch.object(c,'LIVE',self.root))
        stack.enter_context(patch.object(c,'STATE',self.root))
        self.info=stack.enter_context(patch.object(c,'cert_info',return_value={'names':['example.com'],'days':80,'fingerprint':'fp'}))
        self.run=stack.enter_context(patch.object(c,'run',side_effect=lambda *a,**kw:pem(b'key') if a[1]=='rsa' else b'pub'))
        self.actual=dict(self.old)
        self.current=stack.enter_context(patch.object(c,'current',side_effect=lambda *_:dict(self.actual)))
        stack.enter_context(patch.object(c,'cli',side_effect=lambda *_:'{'+''.join(k+'='+v+';' for k,v in self.actual.items())+'}'))
        self.update=stack.enter_context(patch.object(c,'update',side_effect=lambda cfg,name,value:setattr(self,'actual',dict(value))))
        self.verify=stack.enter_context(patch.object(recovery,'verify_snapshot'))
        self.validate=stack.enter_context(patch.object(c,'validate_backup'))
        stack.enter_context(patch.object(recovery,'server_identity',return_value='server'))

    def test_success_and_retention(self):
        path=self.root/'backups'/'example.com'
        path.parent.mkdir(mode=0o700); path.mkdir(mode=0o700)
        for i in range(6): c.atomic(path/('2000%d.json'%i),{})
        self.assertEqual(c.deploy({},self.d),'installed')
        self.assertEqual(len(list(path.glob('*.json'))),5)
        self.update.assert_called_once_with({},'example.com',self.new)
        self.verify.assert_called_once_with(self.new,[{'host':'127.0.0.1','port':443,'sni':'example.com'}])

    def test_unchanged(self):
        self.actual=dict(self.new)
        self.assertEqual(c.deploy({},self.d),'unchanged')
        self.update.assert_not_called()

    def test_bad_local(self):
        for info in (None,{'names':['wrong.com'],'days':80},{'names':['example.com'],'days':0}):
            self.info.return_value=info
            with self.assertRaises(c.Error): c.deploy({},self.d)
        self.update.assert_not_called()

    def test_bad_key(self):
        self.validate.side_effect=c.Error('Backup key mismatch')
        with self.assertRaisesRegex(c.Error,'key mismatch'): c.deploy({},self.d)
        self.update.assert_not_called()

    def test_incomplete_previous_settings(self):
        self.actual={}
        with self.assertRaisesRegex(c.Error,'bootstrap-check'): c.deploy({},self.d)
        self.update.assert_not_called()
        self.run.assert_not_called()

    def test_update_error_but_readback_success(self):
        def lost_reply(cfg,name,settings):
            self.actual=dict(settings)
            raise OSError()
        self.update.side_effect=lost_reply
        self.assertEqual(c.deploy({},self.d),'installed')

    def test_readback_mismatch_recovery(self):
        self.update.side_effect=None
        with self.assertRaisesRegex(c.Error,'previous settings restored'): c.deploy({},self.d)
        self.assertEqual(self.update.call_count,1)

    def test_interrupt_recovery(self):
        self.verify.side_effect=[KeyboardInterrupt(),None]
        with self.assertRaisesRegex(c.Error,'previous settings restored'): c.deploy({},self.d)
        self.assertEqual(self.update.call_count,2)

    def test_recovery_failure(self):
        self.verify.side_effect=c.Error('TLS unavailable')
        with self.assertRaisesRegex(c.Error,'CRITICAL'): c.deploy({},self.d)

    def test_leaf_snapshot_survives_lineage_change(self):
        def read_and_change(pem_data):
            (self.root/'example.com'/'cert.pem').write_bytes(pem(b'other leaf'))
            return {'names':['example.com'],'days':80,'fingerprint':'fp'}
        self.info.side_effect=read_and_change
        self.assertEqual(c.deploy({},self.d),'installed')
        self.assertEqual(self.actual['SecureCertificate'],self.new['SecureCertificate'])

class SmallModuleTests(unittest.TestCase):
    def test_language(self):
        with patch.object(c,'load',return_value={'tui_language':'ru'}):
            self.assertEqual(localization.language(),'ru')
        with patch.object(c,'load',side_effect=ValueError()):
            self.assertEqual(localization.language(),'en')
        self.assertEqual(localization.translate('unknown','ru'),'unknown')

    def test_schedule(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(schedule,'DROPIN',Path(tmp)/'x.conf'),patch.object(schedule,'load',return_value={}),patch.object(schedule.subprocess,'run',return_value=Mock(returncode=0)) as run:
            schedule.apply()
            run.assert_not_called()
            with patch.object(schedule,'load',return_value={'schedule':{'hour':23,'random_delay':3600}}):
                schedule.apply()
            self.assertEqual(run.call_args.args[0],['systemctl','restart','cgp-letsencrypt.timer'])
            self.assertIn('11,23:00:00',schedule.DROPIN.read_text())

    def test_schedule_replace_failure(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(schedule,'DROPIN',Path(tmp)/'x.conf'),patch.object(schedule,'load',return_value={'schedule':{}}),patch.object(schedule.os,'replace',side_effect=OSError()):
            with self.assertRaises(OSError): schedule.apply()
            self.assertEqual(list(Path(tmp).iterdir()),[])

    def test_console_cli_entry(self):
        with patch.object(cli,'entry',return_value=7):
            with self.assertRaises(SystemExit) as e:
                runpy.run_module('cgp_cert_manager.console_cli',run_name='__main__')
        self.assertEqual(e.exception.code,7)
        runpy.run_module('cgp_cert_manager.console_cli',run_name='test_import')

    def test_excluded_domain_alias(self):
        cfg={'domains':[{'cgp_domain':'example.com','exclude_names':['alias.com']}]}
        with patch.object(c,'cli',side_effect=['(example.com)','(alias.com)']):
            result=c.discover(cfg,{'example.com':{},'alias.com':{}})[0]
        self.assertEqual(result['skipped_names']['alias.com'],'excluded_manually')
        self.assertNotIn('alias.com',result['names'])

    def test_malformed_listener_port(self):
        with patch.object(c,'run',return_value=b'LISTEN 0 100 127.0.0.1:invalid users:(("CGServer",pid=1))\n'):
            self.assertEqual(c.discover_listeners(),[])

    def test_truncated_listener_line(self):
        data=b'"CGServer"\nLISTEN "CGServer"\nLISTEN 0 100 127.0.0.1:443 users:(("CGServer",pid=1))\n'
        with patch.object(c,'run',return_value=data):
            self.assertEqual(c.discover_listeners(),[{'port':443,'starttls':None}])
