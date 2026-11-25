import argparse, shutil, sys, smtplib, socket
from email.message import EmailMessage
from .core import *
from . import __version__, bootstrap, deployment, dnsconfig, dnsproviders, storage, update_gate

def hook(cfg,cleanup):
    update_gate.require_idle()
    provider=dnsproviders.get_provider(cfg,transport=cf)
    provider.require('fixed_hooks')
    if cleanup:
        try: r=json.loads(os.environ['CERTBOT_AUTH_OUTPUT'])
        except (KeyError,ValueError): raise Error('Missing cleanup metadata') from None
        legacy={'credentials','zone','record'}
        if (not isinstance(r,dict) or set(r) not in (legacy,legacy|{'provider'})
                or r.get('provider','cloudflare')!=provider.name
                or not isinstance(r['credentials'],str)
                or r['credentials'] not in provider.fixed_cleanup_credentials(cfg)
                or not all(isinstance(r[k],str) and re.fullmatch(r'[a-f0-9]{32}',r[k]) for k in ('zone','record'))):
            raise Error('Invalid cleanup metadata')
        provider.fixed_delete(r['credentials'],r['zone'],r['record']); return
    options=dnsconfig.validate(cfg)
    name=os.environ.get('CERTBOT_IDENTIFIER') or os.environ['CERTBOT_DOMAIN']; n,e=dns_name(name)
    if not n: raise Error('Invalid challenge domain')
    z=zones(cfg); zone=zone_for(n,z)
    if not zone: raise Error('No Cloudflare zone')
    a=z[zone]; record='_acme-challenge.'+n.removeprefix('*.'); value=os.environ['CERTBOT_VALIDATION']
    if a.get('provider','cloudflare')!=provider.name or a['credentials'] not in provider.credentials(cfg):
        raise Error('Invalid DNS challenge zone')
    record_id=provider.fixed_create(a['credentials'],a['id'],record,value)
    print(json.dumps({'provider':provider.name,'credentials':a['credentials'],'zone':a['id'],'record':record_id}),flush=True)
    time.sleep(options['propagation_seconds'])

def notify(cfg,state,name,message):
    LOG.error('%s: %s',name,message)
    now=time.time(); item=state.setdefault(name,{})
    if item.get('alert')==message and now-item.get('alert_at',0)<86400: return
    n=cfg.get('notifications',{})
    if n.get('to'):
        try:
            msg=EmailMessage(); msg['From']=n.get('from',cfg['email']); msg['To']=n['to']; msg['Subject']='CGP certificates: '+name; msg.set_content(message)
            with smtplib.SMTP(n.get('host','127.0.0.1'),int(n.get('port',25)),timeout=15) as smtp: smtp.send_message(msg)
        except Exception: LOG.error('Notification delivery failed'); return
    item.update(alert=message,alert_at=now)

def history(name,event):
    with storage.open_private(STATE/'history.jsonl','a',create=True) as f: f.write(json.dumps({'time':datetime.now(timezone.utc).isoformat(),'domain':name,'event':event})+'\n')

def migrate(cfg):
    if cfg.get('schema_version')==2: return cfg
    for d in cfg.get('domains',[]):
        if 'extra_names' not in d: d['extra_names']=[n for n in d.get('names',[]) if n not in (d['cgp_domain'],'*.'+d['cgp_domain'])]
        for k in ('aliases','auto_names','names','skipped_names','present_in_cgp','cloudflare_available'): d.pop(k,None)
    cfg['schema_version']=2
    return cfg

def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(); p.add_argument('--version',action='version',version=__version__); p.add_argument('--domain'); p.add_argument('--backup-file'); p.add_argument('--json',action='store_true'); p.add_argument('--allow-shrink',action='store_true'); p.add_argument('--force-renew',action='store_true'); p.add_argument('--retry-now',action='store_true')
    p.add_argument('--confirm-transaction'); p.add_argument('--reason')
    p.add_argument('--metrics-file',metavar='PATH')
    g=p.add_mutually_exclusive_group()
    for x in ('sync','list','show-domains','status','plan','verify','doctor','dry-run','install-only','history','hook-auth','hook-cleanup','reset-backoff','discover-listeners','verify-listeners','repair-chain','tui','apply-schedule','console','transactions','recover','acknowledge-restored','bootstrap-check','dns-check','dns-transactions','dns-cleanup','monitoring','metrics','zabbix-discovery'): g.add_argument('--'+x,action='store_true')
    g.add_argument('--backups',metavar='DOMAIN'); g.add_argument('--rollback',metavar='DOMAIN'); g.add_argument('--migrate',action='store_true')
    a=p.parse_args()
    monitoring_action=a.monitoring or a.metrics or a.zabbix_discovery
    if a.metrics_file is not None and not a.metrics: p.error('--metrics-file requires --metrics')
    if monitoring_action:
        if a.domain is not None: p.error('Monitoring actions are global; omit --domain')
        if (a.force_renew or a.retry_now or a.allow_shrink or a.backup_file is not None
                or a.confirm_transaction is not None or a.reason is not None):
            p.error('Monitoring actions do not accept mutation options')
        if a.metrics and a.json: p.error('--metrics does not accept --json')
    if a.backup_file and not a.rollback: p.error('--backup-file requires --rollback')
    if (a.dns_transactions or a.dns_cleanup) and a.domain is not None:
        p.error('--dns-transactions and --dns-cleanup are global operations; omit --domain')
    if a.acknowledge_restored:
        if not a.domain: p.error('--acknowledge-restored requires --domain')
        try: identifier(a.domain)
        except Error: p.error('Invalid acknowledgement domain')
    elif a.confirm_transaction is not None or a.reason is not None:
        p.error('--confirm-transaction and --reason require --acknowledge-restored')
    if (a.confirm_transaction is None)!=(a.reason is None):
        p.error('--confirm-transaction and --reason must be supplied together')
    if a.confirm_transaction is not None:
        if not re.fullmatch(r'[0-9a-f]{64}',a.confirm_transaction): p.error('Invalid transaction confirmation token')
        if not a.reason.isprintable() or not 1<=len(a.reason.strip())<=500:
            p.error('Reason must contain 1 to 500 printable characters without controls')
        a.reason=a.reason.strip()
    update_gate.require_idle()
    if monitoring_action:
        try:
            from . import monitoring, monitoring_formats
            snapshot=monitoring.collect()
            complete=snapshot['complete']
            if a.zabbix_discovery and not complete:
                print('Monitoring snapshot incomplete; Zabbix discovery not emitted',file=sys.stderr)
                return 1
            if a.metrics:
                output=monitoring_formats.prometheus(snapshot)
                if a.metrics_file is not None:
                    from . import metrics_file
                    metrics_file.write(a.metrics_file,output)
                    return int(not complete)
            else:
                result=monitoring_formats.zabbix_discovery(snapshot) if a.zabbix_discovery else snapshot
                output=json.dumps(result,indent=2,ensure_ascii=False,allow_nan=False)+'\n'
            sys.stdout.write(output)
            return int(not complete)
        except Exception:
            print('Monitoring observation failed',file=sys.stderr)
            return 1
    if a.dns_transactions:
        from . import dnsauth
        rows=dnsauth.status(load(CONFIG))
        if a.json: print(json.dumps(rows,indent=2,ensure_ascii=False))
        elif not rows: print('No pending DNS challenges')
        else:
            for row in rows: print(row['id']+' '+row['name']+': '+row['phase'])
        return 0
    if a.dns_check:
        if a.domain is not None:
            try: identifier(a.domain)
            except Error: p.error('Invalid DNS diagnostic domain')
        from . import dnschecks
        rows=dnschecks.reports(load(CONFIG),a.domain)
        if a.json: print(json.dumps(rows,indent=2,ensure_ascii=False))
        elif not rows: print('No CGP domains')
        else:
            for row in rows:
                print(row['domain']+': DNS ready='+('yes' if row['ready'] else 'no')+'; reason='+(row['reason'] or 'none'))
        return int(any(not row['ready'] for row in rows))
    if a.bootstrap_check:
        if a.domain is not None:
            try: identifier(a.domain)
            except Error: p.error('Invalid bootstrap diagnostic domain')
        rows=bootstrap.reports(load(CONFIG),a.domain)
        if a.json: print(json.dumps(rows,indent=2,ensure_ascii=False))
        elif not rows: print('No CGP domains')
        else:
            for row in rows:
                print('Domain: '+row['domain'])
                print('Deployment ready: '+('yes' if row['deployment_ready'] else 'no'))
                print('Response: '+row['response_status'])
                print('Reason: '+(row['blocking_reason'] or 'none'))
                print('Origin: '+', '.join(name+'='+row['origin'][name] for name in FIELDS))
                for label,key in (('Missing explicit fields','missing_explicit_fields'),('Missing effective fields','missing_effective_fields'),('Unreadable fields','unreadable_fields'),('Empty fields','empty_fields')):
                    values=row[key]
                    print(label+': '+('unknown' if values is None else ', '.join(values) or 'none'))
                print('Automatic bootstrap: disabled')
        return int(any(not row['deployment_ready'] for row in rows))
    if a.console:
        from .console import entry as console_entry
        return console_entry()
    if a.tui:
        from .tui import setup
        return setup()
    # Certbot hooks are children of the process holding this lock.
    if a.hook_auth or a.hook_cleanup:
        cfg=migrate(load(CONFIG))
        dnsproviders.get_provider(cfg).require('fixed_hooks')
        storage.ensure_private_directory(STATE)
        storage.validate_tree(STATE)
        hook(cfg,a.hook_cleanup); return 0
    with storage.operation_lock(STATE) as lock:
        update_gate.require_idle()
        storage.validate_tree(STATE)
        a.operation_lock_fd=lock.fileno()
        return locked_main(a,migrate(load(CONFIG)))

def locked_main(a,cfg):
    if a.dns_cleanup:
        from . import dnsauth
        dnsauth.cleanup_pending(cfg)
        print(json.dumps({'result':'cleaned'}) if a.json else 'DNS challenge cleanup complete')
        return 0
    if a.acknowledge_restored:
        from . import resolution
        if a.confirm_transaction is None:
            result=resolution.preview(cfg,a.domain)
        else:
            result=resolution.acknowledge(cfg,a.domain,a.confirm_transaction,a.reason)
        if a.json: print(json.dumps(result,indent=2,ensure_ascii=False))
        else:
            print('Domain: '+result['domain'])
            print('TLS: '+result['tls'])
            print('Confirmation token: '+result['confirmation_token'])
            if a.confirm_transaction is None:
                print('Phase: '+result['phase'])
                print('CGP state: '+result['state'])
                print('Pending journal: '+str(result['pending_journal']))
                print('Authorization recorded: '+str(result['authorization_recorded']))
                if result['authorization_recorded']: print('Repeat the original acknowledgement reason.')
                print('Acknowledgement keeps the previous CGP settings and permits subsequent certificate work.')
                print('Supply --confirm-transaction TOKEN and --reason TEXT to acknowledge this preview.')
            else:
                print('Result: '+result['result'])
                print('CGP settings were not changed. TLS remains unverified.')
        return 0
    if a.transactions or a.recover:
        rows=deployment.transaction_status(cfg,a.domain) if a.transactions else deployment.recover_pending(cfg,a.domain)
        if a.json: print(json.dumps(rows,indent=2,ensure_ascii=False))
        elif not rows: print('No pending transactions')
        elif a.transactions:
            print(f'{"DOMAIN":25} {"PHASE":12} {"STATE":12} SERVER')
            for row in rows: print(f"{row['domain']:25} {row['phase']:12} {row['state']:12} {'match' if row['server_matches'] else 'mismatch'}")
        else:
            for row in rows: print(f"{row['domain']}: {row['result']}")
        return 0
    if a.migrate: atomic(CONFIG,cfg); return 0
    if a.apply_schedule:
        from .schedule import apply
        apply(); return 0
    if a.discover_listeners:
        print(json.dumps(discover_listeners(),indent=2)); return 0
    if a.reset_backoff:
        if not a.domain: raise Error('--reset-backoff requires --domain')
        state=load(STATE/'state.json',{})
        if a.domain not in state: raise Error('No saved state for domain')
        state[a.domain].update(failures=0,retry_at=0,backoff={})
        atomic(STATE/'state.json',state); return 0
    if a.repair_chain: a.install_only=True

    if a.list: print(cli(cfg,'LISTDOMAINS')); return 0
    if a.history:
        try: print(storage.read_text(STATE/'history.jsonl'),end='')
        except FileNotFoundError: pass
        return 0
    if a.backups or a.rollback:
        name=identifier(a.backups or a.rollback); files=backup_files(name)
        if a.backups: print('\n'.join(x.name for x in files)); return 0
        if not files: raise Error('No backup')
        selected=files[0]
        if a.backup_file:
            selected=next((f for f in files if f.name==a.backup_file),None)
            if selected is None: raise Error('Backup file not found')
        old=load(selected); info=installed_info(old)
        if not info or info['days']<1: raise Error('Backup certificate expired or missing')
        validate_backup(old)
        deployment.recover_pending(cfg)
        cur=bootstrap.require_ready(cfg,name)
        d=next((item for item in cfg.get('domains',[]) if item['cgp_domain']==name),{'cgp_domain':name,'names':info['names']})
        d=dict(d,tls=d.get('tls',cfg.get('tls',[])))
        deployment.apply(cfg,name,cur,old,deployment.snapshot_endpoints(d,old),deployment.snapshot_endpoints(d,cur))
        history(name,'manual rollback'); return 0
    if a.show_domains: print(json.dumps(load(STATE/'domains.json',[]),indent=2,ensure_ascii=False)); return 0
    state=load(STATE/'state.json',{}); failures=0
    read_only=a.dry_run or a.status or a.plan or a.doctor or a.verify or a.verify_listeners
    if not read_only and not a.sync: deployment.recover_pending(cfg)
    try:
        z=zones(cfg); domains=discover(cfg,z)
        if not read_only: atomic(STATE/'domains.json',domains)
    except Exception as e:
        if read_only:
            LOG.error('Discovery failed: %s',type(e).__name__)
        else:
            notify(cfg,state,'discovery',type(e).__name__)
            atomic(STATE/'state.json',state)
        return 1
    if a.sync: print(json.dumps(domains,indent=2,ensure_ascii=False)); return 0
    rows=[]
    for d in domains:
        name=d['cgp_domain']; item=state.setdefault(name,{})
        if a.domain and a.domain!=name: continue
        if not read_only: deployment.assert_no_pending()
        phase='inspection'; row=None
        try:
            readiness=None
            if d['enabled'] and d['cloudflare_available'] and not (a.status or a.verify or a.verify_listeners or a.dry_run):
                inspection=bootstrap.inspect(cfg,name); readiness=inspection.report
                if not readiness['deployment_ready']:
                    row={'action':'BLOCKED','domain':name,'status':'blocked','installed':None,'local':None,'desired':d['names'],'blocked':[],'last_result':item.get('result'),'unavailable':d['unavailable'],'backoff':item.get('backoff',{}),'readiness':readiness}; rows.append(row)
                    raise Error('Certificate deployment blocked ('+readiness['blocking_reason']+'); run --bootstrap-check for diagnostics')
                stored=inspection.settings
            else:
                stored=current(cfg,name)
            old=installed_info(stored); local=local_info(d)
            blocked=sorted(set(shrink_block(d,old,a.allow_shrink)+shrink_block(d,local,a.allow_shrink)))
            status='disabled' if not d['enabled'] else 'blocked' if blocked else 'unavailable' if not d['cloudflare_available'] else 'ready'
            row={'action':('SKIP' if status!='ready' else 'ISSUE' if not local else 'REISSUE' if set(local['names'])!=set(d['names']) else 'CHECK/RENEW' if local['days']<30 else 'VERIFY/KEEP'),'domain':name,'status':status,'installed':old,'local':local,'desired':d['names'],'blocked':blocked,'last_result':item.get('result'),'unavailable':d['unavailable'],'backoff':item.get('backoff',{}),'pki':stored.get('CertificateType')}; rows.append(row)
            if readiness is not None: row['readiness']=readiness
            if a.status or a.plan or a.doctor or a.verify or a.verify_listeners:
                if a.verify and d['enabled'] and d['cloudflare_available']:
                    if not old or not local or old['fingerprint']!=local['fingerprint']: raise Error('Installed fingerprint mismatch')
                    if stored.get('CertificateType','').strip('"').upper()!='YES': raise Error('PKI not enabled')
                    chain=LIVE/d['cert_name']/'chain.pem'
                    if stored.get('CAChain')!='['+chain_payload(chain.read_bytes())+']': raise Error('Stored CAChain mismatch')
                    verify_tls(d,local['fingerprint']); row['tls']='verified'
                if a.verify_listeners and status=='ready':
                    checks=[]
                    for ep in discover_listeners():
                        try: probe_tls(dict(ep,sni=name),expected_chain(d)); checks.append(dict(ep,result='OK'))
                        except Exception: checks.append(dict(ep,result='FAIL')); failures+=1
                    row['listeners']=checks
                continue
            if status!='ready':
                if status=='blocked' or (status=='unavailable' and old and old['days']<21): raise Error('Unavailable Cloudflare identifiers; existing certificate preserved')
                continue
            if not a.dry_run and old and old['days']<7: notify(cfg,state,name,'Certificate expires in less than 7 days')
            def deferred(stage):
                retry=item.get('backoff',{}).get(stage,{}).get('retry_at',0)
                if not (a.dry_run or a.retry_now or a.force_renew) and time.time()<retry:
                    LOG.warning('%s: %s retry deferred until %s',name,stage,datetime.fromtimestamp(retry,timezone.utc).isoformat()); return True
                return False
            issue_deferred=False
            if not a.install_only:
                # If a freshly issued matching certificate is pending deployment, avoid a second issuance.
                pending=local and local['days']>=21 and set(local['names'])==set(d['names']) and (not old or old['fingerprint']!=local['fingerprint'])
                if not pending or a.dry_run or a.force_renew:
                    phase='issue'
                    issue_deferred=deferred(phase)
                    if issue_deferred:
                        failures+=1
                    else:
                        issue(cfg,d,z,a)
                        if not a.dry_run: item.setdefault('backoff',{}).pop(phase,None)
            if not a.dry_run and not issue_deferred:
                phase='deploy'
                if deferred(phase):
                    failures+=1
                else:
                    result=deploy(cfg,d); item.update(result=result,failures=0,retry_at=0,last_success=time.time(),backoff={}); item.pop('alert',None); item.pop('alert_at',None); history(name,result); LOG.info('%s: %s',name,result)
        except Exception as e:
            failures+=1; message=str(e) if isinstance(e,Error) else type(e).__name__; LOG.error('%s: %s',name,message)
            if row is None:
                row={'domain':name,'action':'SKIP','status':'error','installed':None,'local':None,'desired':d.get('names',[]),'blocked':[]}
                rows.append(row)
            row['error']=message; row['tls']='failed' if a.verify else row.get('tls','not checked')
            if not (a.dry_run or a.status or a.plan or a.doctor or a.verify or a.verify_listeners):
                stage=item.setdefault('backoff',{}).setdefault(phase,{}); count=stage.get('failures',0)+1; stage.update(failures=count,retry_at=time.time()+min(86400,900*2**min(count,7))); item.update(result=message,failures=count,retry_at=stage['retry_at']); notify(cfg,state,name,message); history(name,'failure: '+message)
        finally:
            if not (a.dry_run or a.status or a.plan or a.doctor or a.verify or a.verify_listeners): atomic(STATE/'state.json',state)
    if a.domain and not rows: raise Error('Domain not found')
    if a.status or a.plan or a.doctor or a.verify or a.verify_listeners:
        if a.doctor:
            for x in ('certbot','openssl','dig'): print(x+': '+str(shutil.which(x)),file=sys.stderr)
        if a.json or a.verify_listeners: print(json.dumps(rows,indent=2,ensure_ascii=False))
        else:
            print(f'{"DOMAIN":25} {"ACTION":15} {"DAYS":>5} {"SAN":>7} STATUS')
            for row in rows:
                old=row['installed'] or {}; print(f"{row['domain']:25} {row['action']:15} {str(old.get('days','-')):>5} {len(old.get('names',[])):>3}->{len(row['desired']):<3} {row.get('error',row.get('tls',row['status']))}")
    return int(bool(failures))

def entry():
    logging.basicConfig(level=logging.INFO,format='%(asctime)s [%(levelname)s] %(message)s')
    try: return main()
    except Exception as e: LOG.error('%s',str(e) if isinstance(e,(Error,update_gate.PendingUpdateError)) else type(e).__name__); return 1
