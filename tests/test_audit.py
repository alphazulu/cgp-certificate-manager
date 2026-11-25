import argparse
import base64
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, Mock
from cgp_cert_manager import core, cli, console, schedule

def block(data):
    return '['+base64.b64encode(data).decode()+']'

class AuditTests(unittest.TestCase):
    def test_missing_readback_not_equal(self):
        self.assertFalse(core.same({},{}))
        self.assertFalse(core.same(dict.fromkeys(core.FIELDS,''),{}))

    def test_cli_rejects_non_loopback(self):
        cfg={'communigate':{'url':'http://example.net/CLI/','username':'a','password':'secret'}}
        with patch.object(core,'opener') as op:
            with self.assertRaises(core.Error): core.cli(cfg,'LISTDOMAINS')
            op.assert_not_called()

    def test_redirect_denied(self):
        self.assertIsNone(core.NoRedirect().redirect_request(None,None,None,None,None,None))

    def test_run_stdin_closed(self):
        with patch.object(core.subprocess,'run',return_value=Mock(returncode=0,stdout=b'ok')) as run:
            self.assertEqual(core.run('openssl','version'),b'ok')
            self.assertEqual(run.call_args.kwargs['input'],b'')

    def test_atomic_and_backup_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            with patch.object(core,'STATE',root):
                p=core.backup('example.com',{'private':'dummy'})
            self.assertEqual(p.stat().st_mode & 0o777,0o600)
            self.assertEqual(core.load(p),{'private':'dummy'})

    def test_mixed_tls_templates_keep_explicit_sni(self):
        d={'names':['example.com','alias.com'],'tls':[{'port':443,'sni':'example.com'},{'port':993}]}
        endpoints=core.tls_endpoints(d)
        self.assertEqual([(e['port'],e['sni']) for e in endpoints],[(443,'example.com'),(993,'alias.com'),(993,'example.com')])

    def test_invalid_backup_mode(self):
        with self.assertRaises(core.Error): core.validate_backup({'CertificateType':'Test'})

    def test_backup_key_mismatch(self):
        fields={'CertificateType':'YES','PrivateSecureKey':block(b'key'),'SecureCertificate':block(b'leaf'),'CAChain':block(b'ca')}
        with patch.object(core,'run',side_effect=[b'a',b'b']):
            with self.assertRaisesRegex(core.Error,'key mismatch'): core.validate_backup(fields)

    def test_backup_der_truncated(self):
        fields={'CertificateType':'YES','PrivateSecureKey':block(b'key'),'SecureCertificate':block(b'leaf'),'CAChain':block(b'\x30\x05a')}
        with patch.object(core,'run',return_value=b'pubkey'):
            with self.assertRaisesRegex(core.Error,'Truncated'): core.validate_backup(fields)

    def test_diagnostic_failure_does_not_notify_or_write(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(cli,'STATE',Path(tmp)), patch.object(cli,'zones',side_effect=OSError()), patch.object(cli,'notify') as notify, patch.object(cli,'atomic') as atomic:
            args=argparse.Namespace(dry_run=False,status=True,plan=False,doctor=False,verify=False,verify_listeners=False,migrate=False,apply_schedule=False,discover_listeners=False,reset_backoff=False,repair_chain=False,list=False,history=False,backups=None,rollback=None,show_domains=False,transactions=False,recover=False,acknowledge_restored=False,dns_cleanup=False)
            self.assertEqual(cli.locked_main(args,{}),1)
            notify.assert_not_called()
            atomic.assert_not_called()

    def test_history_skips_nonobjects(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(core,'STATE',Path(tmp)):
            (Path(tmp)/'history.jsonl').write_text('null\n[]\n{"domain":"example.com","event":"ok"}\n')
            (Path(tmp)/'history.jsonl').chmod(0o600)
            self.assertEqual(console.domain_history('example.com'),[' ok'])

    def test_verification_error_survives_missing_identity(self):
        row={'domain':'example.com','status':'ready','installed':{'fingerprint':'a'}}
        console.verified_rows([row],[{'domain':'example.com','tls':'failed','error':'API unavailable'}])
        self.assertEqual(console.row_status(row),'ERROR')

    def test_schedule_apply_inactive(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'timer.d'/'schedule.conf'
            with patch.object(schedule,'DROPIN',path),patch.object(schedule,'load',return_value={'schedule':{'hour':6,'random_delay':0}}),patch.object(schedule.subprocess,'run',return_value=Mock(returncode=3)) as run:
                schedule.apply()
            self.assertIn('06,18:00:00',path.read_text())
            self.assertEqual(run.call_count,2)

    def test_issue_changed_san(self):
        d={'cert_name':'example.com','names':['example.com','alias.com']}
        args=argparse.Namespace(force_renew=False,dry_run=True)
        with tempfile.TemporaryDirectory() as tmp, patch.object(core,'local_info',return_value={'names':['example.com']}),patch.object(core.subprocess,'run') as run:
            paths=[Path(tmp)/name for name in ('one.ini','two.ini')]
            for path in paths:
                path.write_text('dns_cloudflare_api_token = dummy\n'); path.chmod(0o600)
            zones={name:{'credentials':str(path)} for name,path in zip(('example.com','alias.com'),paths)}
            core.issue({'email':'admin@example.com','dns_preflight':False},d,zones,args)
        cmd=run.call_args.args[0]
        self.assertIn('--manual',cmd)
        self.assertIn('--force-renewal',cmd)
        self.assertIn('--dry-run',cmd)

    def test_dns_preflight_conflict(self):
        from cgp_cert_manager import dnschecks
        d={'names':['example.com']}
        z={'example.com':{'ns':['ns.example.net']}}
        with patch.object(dnschecks,'require_ready',side_effect=core.Error('ACME CNAME requires manual configuration')):
            with self.assertRaisesRegex(core.Error,'CNAME'): core.dns_preflight(d,z)
