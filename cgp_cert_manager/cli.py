import argparse, fcntl, shutil, sys, smtplib, socket
from email.message import EmailMessage
from .core import *
from . import __version__

def hook(cfg,cleanup):
    if cleanup:
        try: r=json.loads(os.environ['CERTBOT_AUTH_OUTPUT']); path=r['credentials']
        except (KeyError,ValueError): raise Error('Missing cleanup metadata')
        allowed={a['credentials'] for a in cfg.get('cloudflare_accounts',[])}|{cfg.get('cloudflare_credentials')}
        if path not in allowed or not all(re.fullmatch(r'[a-f0-9]{32}',r[k]) for k in ('zone','record')): raise Error('Invalid cleanup metadata')
        cf(path,'zones/'+r['zone']+'/dns_records/'+r['record'],method='DELETE'); return
    name=os.environ.get('CERTBOT_IDENTIFIER') or os.environ['CERTBOT_DOMAIN']; n,e=dns_name(name)
    if not n: raise Error('Invalid challenge domain')
    z=zones(cfg); zone=zone_for(n,z)
    if not zone: raise Error('No Cloudflare zone')
    a=z[zone]; record='_acme-challenge.'+n.removeprefix('*.'); value=os.environ['CERTBOT_VALIDATION']
    r=cf(a['credentials'],'zones/'+a['id']+'/dns_records',method='POST',data={'type':'TXT','name':record,'content':value,'ttl':120})['result']
    print(json.dumps({'credentials':a['credentials'],'zone':a['id'],'record':r['id']}),flush=True)
    time.sleep(int(cfg.get('propagation_seconds',60)))

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
    with (STATE/'history.jsonl').open('a') as f: f.write(json.dumps({'time':datetime.now(timezone.utc).isoformat(),'domain':name,'event':event})+'\n')

def migrate(cfg):
    if cfg.get('schema_version')==2: return cfg
    for d in cfg.get('domains',[]):
        if 'extra_names' not in d: d['extra_names']=[n for n in d.get('names',[]) if n not in (d['cgp_domain'],'*.'+d['cgp_domain'])]
        for k in ('aliases','auto_names','names','skipped_names','present_in_cgp','cloudflare_available'): d.pop(k,None)
    cfg['schema_version']=2
    return cfg

def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(); p.add_argument('--version',action='version',version=__version__); p.add_argument('--domain'); p.add_argument('--json',action='store_true'); p.add_argument('--allow-shrink',action='store_true'); p.add_argument('--force-renew',action='store_true'); p.add_argument('--retry-now',action='store_true')
    g=p.add_mutually_exclusive_group()
    for x in ('sync','list','show-domains','status','plan','verify','doctor','dry-run','install-only','history','hook-auth','hook-cleanup','reset-backoff','discover-listeners','verify-listeners','repair-chain'): g.add_argument('--'+x,action='store_true')
    g.add_argument('--backups',metavar='DOMAIN'); g.add_argument('--rollback',metavar='DOMAIN'); g.add_argument('--migrate',action='store_true')
    a=p.parse_args(); cfg=migrate(load(CONFIG)); STATE.mkdir(mode=0o700,parents=True,exist_ok=True)
    if a.hook_auth or a.hook_cleanup: hook(cfg,a.hook_cleanup); return 0
    lock=(STATE/'run.lock').open('a'); fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    if a.migrate: atomic(CONFIG,cfg); return 0
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
        if (STATE/'history.jsonl').exists(): print((STATE/'history.jsonl').read_text(),end='')
        return 0
    if a.backups or a.rollback:
        name=identifier(a.backups or a.rollback); files=sorted((STATE/'backups'/name).glob('*.json'),reverse=True)
        if a.backups: print('\n'.join(x.name for x in files)); return 0
        if not files: raise Error('No backup')
        old=load(files[0]); info=installed_info(old)
        if not info or info['days']<1: raise Error('Backup certificate expired or missing')
        cur=current(cfg,name)
        if set(cur)!=set(FIELDS): raise Error('Cannot back up current settings')
        backup(name,cur); update(cfg,name,old)
        if not same(current(cfg,name),old): raise Error('Rollback not verified')
        history(name,'manual rollback'); return 0
    if a.show_domains: print(json.dumps(load(STATE/'domains.json',[]),indent=2,ensure_ascii=False)); return 0
    state=load(STATE/'state.json',{}); failures=0
    try: z=zones(cfg); domains=discover(cfg,z); atomic(STATE/'domains.json',domains)
    except Exception as e:
        notify(cfg,state,'discovery',type(e).__name__); atomic(STATE/'state.json',state); return 1
    if a.sync: print(json.dumps(domains,indent=2,ensure_ascii=False)); return 0
    rows=[]
    for d in domains:
        name=d['cgp_domain']; item=state.setdefault(name,{})
        if a.domain and a.domain!=name: continue
        phase='inspection'; row=None
        try:
            stored=current(cfg,name); old=installed_info(stored); local=local_info(d)
            blocked=sorted(set(shrink_block(d,old,a.allow_shrink)+shrink_block(d,local,a.allow_shrink)))
            status='disabled' if not d['enabled'] else 'blocked' if blocked else 'unavailable' if not d['cloudflare_available'] else 'ready'
            row={'action':('SKIP' if status!='ready' else 'ISSUE' if not local else 'REISSUE' if set(local['names'])!=set(d['names']) else 'CHECK/RENEW' if local['days']<30 else 'VERIFY/KEEP'),'domain':name,'status':status,'installed':old,'local':local,'desired':d['names'],'blocked':blocked,'last_result':item.get('result'),'unavailable':d['unavailable'],'backoff':item.get('backoff',{}),'pki':stored.get('CertificateType')}; rows.append(row)
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
            if not a.install_only:
                # If a freshly issued matching certificate is pending deployment, avoid a second issuance.
                pending=local and local['days']>=21 and set(local['names'])==set(d['names']) and (not old or old['fingerprint']!=local['fingerprint'])
                if not pending or a.dry_run or a.force_renew:
                    phase='issue'
                    if deferred(phase): failures+=1; continue
                    issue(cfg,d,z,a)
                    if not a.dry_run: item.setdefault('backoff',{}).pop(phase,None)
            if not a.dry_run:
                phase='deploy'
                if deferred(phase): failures+=1; continue
                result=deploy(cfg,d); item.update(result=result,failures=0,retry_at=0,last_success=time.time(),backoff={}); item.pop('alert',None); item.pop('alert_at',None); history(name,result); LOG.info('%s: %s',name,result)
        except Exception as e:
            failures+=1; message=str(e) if isinstance(e,Error) else type(e).__name__; LOG.error('%s: %s',name,message)
            if row is not None: row['error']=message; row['tls']='failed' if a.verify else row.get('tls','not checked')
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
    except Exception as e: LOG.error('%s',str(e) if isinstance(e,Error) else type(e).__name__); return 1
