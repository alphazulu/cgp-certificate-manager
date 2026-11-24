"""CLI orchestration tests: no actual network, Certbot, or systemd."""
import contextlib
import fcntl
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, Mock
from cgp_cert_manager import cli, core, schedule, console, tui

NAME='example.com'
CERT={'fingerprint':'a','names':[NAME],'days':80}
FIELDS={k:'[YQ==]' for k in core.FIELDS}
FIELDS['CertificateType']='YES'

class CLIFlowTests(unittest.TestCase):
    def setUp(self):
        self.stack=contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.root=Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.cfg={'schema_version':2,'email':'admin@example.com'}
        self.config=self.root/'config.json'
        core.atomic(self.config,self.cfg)
        self.stack.enter_context(patch.object(cli,'CONFIG',self.config))
        self.stack.enter_context(patch.object(cli,'STATE',self.root))
        self.stack.enter_context(patch.object(core,'STATE',self.root))
        self.stack.enter_context(patch.object(cli,'LIVE',self.root/'live'))
        (self.root/'live'/NAME).mkdir(parents=True)
        (self.root/'live'/NAME/'chain.pem').write_bytes(b'dummy')
        self.domain={'cgp_domain':NAME,'cert_name':NAME,'enabled':True,'cloudflare_available':True,'names':[NAME],'unavailable':[]}
        self.m={}
        for name,value in {'zones':{},'discover':[self.domain],'current':dict(FIELDS),'installed_info':dict(CERT),'local_info':dict(CERT),'issue':None,'deploy':'installed','verify_tls':None,'chain_payload':'YQ==','discover_listeners':[{'port':443}],'expected_chain':['a'],'probe_tls':None}.items():
            self.m[name]=self.stack.enter_context(patch.object(cli,name,return_value=value))
        self.recover=self.stack.enter_context(patch.object(cli.deployment,'recover_pending',return_value=[]))
        self.stack.enter_context(patch.object(cli.os,'umask'))
        self.out=io.StringIO()
        self.stack.enter_context(contextlib.redirect_stdout(self.out))
        self.stack.enter_context(contextlib.redirect_stderr(io.StringIO()))

    def invoke(self,*args):
        self.out.seek(0); self.out.truncate(0)
        with patch.object(cli.sys,'argv',['cgp-letsencrypt',*args]):
            return cli.main()

    def output(self): return json.loads(self.out.getvalue())
    def state(self): return core.load(self.root/'state.json',{})
    def set_state(self,s): core.atomic(self.root/'state.json',s)

    def test_status_plan_doctor_sync(self):
        for arg in ('--status','--plan','--doctor','--sync'):
            with self.subTest(arg=arg):
                self.assertEqual(self.invoke(arg,'--json'),0)
                self.assertEqual(len(self.output()),1)
        self.m['issue'].assert_not_called()
        self.m['deploy'].assert_not_called()

    def test_text_status(self):
        self.assertEqual(self.invoke('--status'),0)
        self.assertIn('VERIFY/KEEP',self.out.getvalue())

    def test_plan_variants(self):
        for local,expected in [(None,'ISSUE'),(dict(CERT,names=['other.com']),'REISSUE'),(dict(CERT,days=20),'CHECK/RENEW')]:
            self.m['local_info'].return_value=local
            self.assertEqual(self.invoke('--plan','--json'),0)
            self.assertEqual(self.output()[0]['action'],expected)

    def test_verify_success(self):
        self.assertEqual(self.invoke('--verify','--json'),0)
        self.assertEqual(self.output()[0]['tls'],'verified')
        self.m['verify_tls'].assert_called_once_with(self.domain,'a')
        self.assertFalse((self.root/'state.json').exists())

    def test_verify_fingerprint_mismatch(self):
        self.m['local_info'].return_value=dict(CERT,fingerprint='b')
        self.assertEqual(self.invoke('--verify','--json'),1)
        self.assertEqual(self.output()[0]['tls'],'failed')
        self.m['verify_tls'].assert_not_called()

    def test_verify_pki_disabled(self):
        self.m['current'].return_value=dict(FIELDS,CertificateType='NO')
        self.assertEqual(self.invoke('--verify','--json'),1)
        self.assertIn('PKI not enabled',self.output()[0]['error'])

    def test_verify_chain_mismatch(self):
        self.m['chain_payload'].return_value='different'
        self.assertEqual(self.invoke('--verify','--json'),1)
        self.assertIn('CAChain mismatch',self.output()[0]['error'])

    def test_verify_listeners(self):
        self.m['discover_listeners'].return_value=[{'port':443},{'port':993}]
        self.m['probe_tls'].side_effect=[None,core.Error('bad TLS')]
        self.assertEqual(self.invoke('--verify-listeners'),1)
        self.assertEqual([r['result'] for r in self.output()[0]['listeners']],['OK','FAIL'])

    def test_inspection_failure_reported(self):
        self.m['current'].side_effect=OSError('secret')
        self.assertEqual(self.invoke('--status','--json'),1)
        self.assertEqual(self.output()[0]['error'],'OSError')
        self.assertNotIn('secret',self.out.getvalue())

    def test_missing_domain(self):
        with self.assertRaisesRegex(core.Error,'Domain not found'):
            self.invoke('--status','--domain','other.com')

    def test_success_renewal(self):
        self.assertEqual(self.invoke(),0)
        self.m['issue'].assert_called_once()
        self.m['deploy'].assert_called_once()
        self.assertEqual(self.state()[NAME]['result'],'installed')
        self.assertEqual(self.state()[NAME]['backoff'],{})
        self.assertEqual(self.invoke('--history'),0)
        self.assertIn('installed',self.out.getvalue())

    def test_pending_deployment_does_not_reissue(self):
        self.m['installed_info'].return_value=dict(CERT,fingerprint='old')
        self.assertEqual(self.invoke(),0)
        self.m['issue'].assert_not_called()
        self.m['deploy'].assert_called_once()

    def test_force_reissue_pending(self):
        self.m['installed_info'].return_value=None
        self.assertEqual(self.invoke('--force-renew'),0)
        self.m['issue'].assert_called_once()

    def test_dry_run_never_deploys(self):
        self.assertEqual(self.invoke('--dry-run'),0)
        self.m['issue'].assert_called_once()
        self.m['deploy'].assert_not_called()
        self.assertFalse((self.root/'state.json').exists())

    def test_repair_chain(self):
        self.assertEqual(self.invoke('--repair-chain'),0)
        self.m['issue'].assert_not_called()
        self.m['deploy'].assert_called_once()

    def test_issue_failure_backoff_and_retry(self):
        self.m['issue'].side_effect=core.Error('DNS failure')
        self.assertEqual(self.invoke(),1)
        self.assertEqual(self.state()[NAME]['backoff']['issue']['failures'],1)
        self.m['issue'].reset_mock()
        self.assertEqual(self.invoke(),1)
        self.m['issue'].assert_not_called()
        self.m['issue'].side_effect=None
        self.assertEqual(self.invoke('--retry-now'),0)
        self.assertEqual(self.state()[NAME]['backoff'],{})

    def test_deploy_backoff(self):
        self.m['deploy'].side_effect=core.Error('CGP down')
        self.assertEqual(self.invoke(),1)
        self.assertIn('deploy',self.state()[NAME]['backoff'])
        self.m['deploy'].reset_mock()
        self.assertEqual(self.invoke('--install-only'),1)
        self.m['deploy'].assert_not_called()

    def test_reset_backoff(self):
        self.set_state({NAME:{'failures':3,'backoff':{'issue':{'retry_at':999}}}})
        self.assertEqual(self.invoke('--reset-backoff','--domain',NAME),0)
        self.assertEqual(self.state()[NAME]['failures'],0)
        with self.assertRaises(core.Error): self.invoke('--reset-backoff')
        with self.assertRaises(core.Error): self.invoke('--reset-backoff','--domain','other.com')

    def test_disabled_domain(self):
        self.domain['enabled']=False
        self.assertEqual(self.invoke(),0)
        self.m['issue'].assert_not_called()
        self.m['deploy'].assert_not_called()

    def test_zone_unavailable_expiring(self):
        self.domain['cloudflare_available']=False
        self.m['installed_info'].return_value=dict(CERT,days=10)
        self.assertEqual(self.invoke(),1)
        self.m['issue'].assert_not_called()

    def test_zone_unavailable_valid(self):
        self.domain['cloudflare_available']=False
        self.assertEqual(self.invoke(),0)
        self.m['deploy'].assert_not_called()

    def test_blocked_shrink(self):
        self.domain['unavailable']=['old.com']
        self.m['installed_info'].return_value=dict(CERT,names=[NAME,'old.com'])
        self.assertEqual(self.invoke(),1)
        self.m['deploy'].assert_not_called()

    def test_expiry_notification(self):
        self.m['installed_info'].return_value=dict(CERT,days=5)
        with patch.object(cli,'notify') as notify:
            self.assertEqual(self.invoke(),0)
        notify.assert_called_once()

    def test_discovery_failure(self):
        self.m['zones'].side_effect=OSError()
        self.assertEqual(self.invoke(),1)
        self.assertIn('discovery',self.state())

    def test_auxiliary_commands(self):
        with patch.object(cli,'cli',return_value='(example.com)'):
            self.assertEqual(self.invoke('--list'),0)
            self.assertIn(NAME,self.out.getvalue())
        self.assertEqual(self.invoke('--show-domains'),0)
        self.assertEqual(self.output(),[])
        self.assertEqual(self.invoke('--discover-listeners'),0)
        self.assertEqual(self.output(),[{'port':443}])
        with patch.object(schedule,'apply') as apply:
            self.assertEqual(self.invoke('--apply-schedule'),0)
            apply.assert_called_once()
        self.assertEqual(self.invoke('--migrate'),0)

    def test_lock_released_and_busy(self):
        with (self.root/'run.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                self.invoke('--status')
        self.assertEqual(self.invoke('--status'),0)
        self.assertEqual(self.invoke('--status'),0)

    def test_entrypoints(self):
        with patch.object(console,'entry',return_value=0):
            self.assertEqual(self.invoke('--console'),0)
        with patch.object(tui,'setup',return_value=3):
            self.assertEqual(self.invoke('--tui'),3)
        with self.assertRaises(SystemExit): self.invoke('--backup-file','x')
        with self.assertRaises(SystemExit): self.invoke('--version')

    def test_entry_error(self):
        with patch.object(cli,'main',side_effect=core.Error('test')):
            self.assertEqual(cli.entry(),1)
        with patch.object(cli,'main',return_value=0):
            self.assertEqual(cli.entry(),0)

    def make_backup(self):
        path=self.root/'backups'/NAME/'20261124T010203123456Z.json'
        old=dict(FIELDS,PrivateSecureKey='[Yg==]')
        core.atomic(path,old)
        return path,old

    def test_rollback_selected(self):
        path,old=self.make_backup()
        endpoints=[{'port':443,'sni':NAME}]
        with patch.object(cli,'validate_backup') as validate,patch.object(cli.deployment,'apply') as apply,patch.object(cli.deployment,'snapshot_endpoints',return_value=endpoints):
            self.assertEqual(self.invoke('--rollback',NAME,'--backup-file',path.name),0)
        validate.assert_called_once_with(old)
        apply.assert_called_once_with(self.cfg,NAME,FIELDS,old,endpoints,endpoints)
        self.recover.assert_called_once_with(self.cfg)
        self.assertEqual(self.invoke('--backups',NAME),0)
        self.assertIn(path.name,self.out.getvalue())

    def test_rollback_recovery(self):
        path,old=self.make_backup()
        with patch.object(cli,'validate_backup'),patch.object(cli.deployment,'snapshot_endpoints',return_value=[]),patch.object(cli.deployment,'apply',side_effect=core.Error('Deployment failed; previous settings restored')):
            with self.assertRaisesRegex(core.Error,'previous settings restored'):
                self.invoke('--rollback',NAME)
        self.assertFalse((self.root/'history.jsonl').exists())

    def test_rollback_recovery_failure(self):
        self.make_backup()
        with patch.object(cli,'validate_backup'),patch.object(cli.deployment,'snapshot_endpoints',return_value=[]),patch.object(cli.deployment,'apply',side_effect=core.Error('CRITICAL: recovery pending')):
            with self.assertRaisesRegex(core.Error,'CRITICAL'):
                self.invoke('--rollback',NAME)
        self.assertFalse((self.root/'history.jsonl').exists())

    def test_rollback_invalid_choices(self):
        with self.assertRaisesRegex(core.Error,'No backup'):
            self.invoke('--rollback',NAME)
        path,_=self.make_backup()
        with self.assertRaisesRegex(core.Error,'not found'):
            self.invoke('--rollback',NAME,'--backup-file','../x')
        self.m['installed_info'].return_value=None
        with self.assertRaisesRegex(core.Error,'expired'):
            self.invoke('--rollback',NAME)

    def test_hook_entry_dispatch(self):
        with patch.object(cli,'hook') as hook:
            self.assertEqual(self.invoke('--hook-auth'),0)
            hook.assert_called_once_with(self.cfg,False)
            self.assertEqual(self.invoke('--hook-cleanup'),0)
            self.assertEqual(hook.call_args.args,(self.cfg,True))

    def test_backup_symlink_refused(self):
        path,old=self.make_backup()
        other=self.root/'outside.json'
        core.atomic(other,old)
        path.unlink()
        path.symlink_to(other)
        with self.assertRaisesRegex(core.Error,'Invalid backup path'):
            self.invoke('--rollback',NAME)
        with self.assertRaisesRegex(core.Error,'not found'):
            self.invoke('--rollback',NAME,'--backup-file',path.name)

    def test_incomplete_current_settings(self):
        self.make_backup()
        self.m['current'].return_value={}
        with patch.object(cli,'validate_backup'),patch.object(cli,'update') as update:
            with self.assertRaisesRegex(core.Error,'Cannot back up'):
                self.invoke('--rollback',NAME)
            update.assert_not_called()

    def test_pending_recovery_blocks_manual_rollback(self):
        self.make_backup()
        self.recover.side_effect=core.Error('Unknown CGP state')
        with patch.object(cli,'validate_backup'),patch.object(cli.deployment,'apply') as apply:
            with self.assertRaisesRegex(core.Error,'Unknown CGP state'):
                self.invoke('--rollback',NAME)
        self.m['current'].assert_not_called()
        apply.assert_not_called()

    def test_deferred_issue_continues_next_domain(self):
        second=dict(self.domain,cgp_domain='second.com',cert_name='second.com',names=['second.com'])
        self.m['discover'].return_value=[self.domain,second]
        self.set_state({NAME:{'backoff':{'issue':{'retry_at':4102444800}}}})
        self.assertEqual(self.invoke(),1)
        self.assertEqual(self.m['issue'].call_count,1)
        self.assertEqual(self.m['issue'].call_args.args[1],second)
        self.m['deploy'].assert_called_once_with(self.cfg,second)

    def test_deferred_deploy_continues_next_domain(self):
        second=dict(self.domain,cgp_domain='second.com',cert_name='second.com',names=['second.com'])
        self.m['discover'].return_value=[self.domain,second]
        self.set_state({NAME:{'backoff':{'deploy':{'retry_at':4102444800}}}})
        self.assertEqual(self.invoke('--install-only'),1)
        self.m['issue'].assert_not_called()
        self.m['deploy'].assert_called_once_with(self.cfg,second)

class HookNotifyTests(unittest.TestCase):
    def test_auth_and_cleanup(self):
        z={'example.com':{'id':'a'*32,'credentials':'one.ini'}}
        cfg={'cloudflare_credentials':'one.ini','propagation_seconds':10}
        with patch.dict(os.environ,{'CERTBOT_IDENTIFIER':'*.example.com','CERTBOT_VALIDATION':'challenge'},clear=True),patch.object(cli,'zones',return_value=z),patch.object(cli,'cf',return_value={'result':{'id':'b'*32}}) as cf,patch.object(cli.time,'sleep') as sleep,contextlib.redirect_stdout(io.StringIO()) as out:
            cli.hook(cfg,False)
            self.assertEqual(cf.call_args.kwargs['data']['name'],'_acme-challenge.example.com')
            sleep.assert_called_once_with(10)
            metadata=out.getvalue()
        with patch.dict(os.environ,{'CERTBOT_AUTH_OUTPUT':metadata},clear=True),patch.object(cli,'cf') as cf:
            cli.hook(cfg,True)
            self.assertEqual(cf.call_args.kwargs['method'],'DELETE')

    def test_hook_invalid_inputs(self):
        for env,cleanup in [({},True),({'CERTBOT_AUTH_OUTPUT':'{"credentials":"wrong"}'},True),({'CERTBOT_IDENTIFIER':'127.0.0.1'},False),({'CERTBOT_IDENTIFIER':NAME},False)]:
            with self.subTest(env=env),patch.dict(os.environ,env,clear=True),patch.object(cli,'zones',return_value={}),patch.object(cli,'cf') as cf:
                with self.assertRaises(core.Error): cli.hook({'cloudflare_credentials':'one.ini'},cleanup)
                cf.assert_not_called()

    def test_notify_throttle(self):
        cfg={'email':'admin@example.com','notifications':{'to':'ops@example.com'}}
        state={}
        with patch.object(cli.smtplib,'SMTP') as smtp:
            cli.notify(cfg,state,NAME,'failure')
            cli.notify(cfg,state,NAME,'failure')
            smtp.assert_called_once()
            smtp.return_value.__enter__.return_value.send_message.assert_called_once()
        self.assertEqual(state[NAME]['alert'],'failure')

    def test_notify_error(self):
        cfg={'email':'admin@example.com','notifications':{'to':'ops@example.com'}}
        state={}
        with patch.object(cli.smtplib,'SMTP',side_effect=OSError()):
            cli.notify(cfg,state,NAME,'failure')
        self.assertNotIn('alert',state[NAME])
