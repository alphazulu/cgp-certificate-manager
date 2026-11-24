"""Optional whiptail configuration editor. No credentials in process arguments."""
import argparse
import copy
import fcntl
import getpass
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from . import core

class Cancel(Exception):
    pass

def dialog(kind, *args):
    # whiptail writes selections to stderr; use a separate output descriptor
    # so the interface itself stays attached to the terminal.
    with tempfile.TemporaryFile() as output:
        p = subprocess.run(['whiptail', '--title', 'CGP Certificate Manager',
                            '--output-fd', str(output.fileno()), kind, *map(str,args)],
                           pass_fds=(output.fileno(),))
        if p.returncode != 0:
            raise Cancel()
        output.seek(0)
        return output.read().decode().strip()

def msg(text):
    dialog('--msgbox', text, 18, 78)

def ask(text, default=''):
    return dialog('--inputbox', text, 10, 78, default)

def yes(text):
    try:
        dialog('--yesno', text, 10, 78)
        return True
    except Cancel:
        return False

def secret(prompt):
    # getpass uses the controlling terminal, never the child process argv.
    return getpass.getpass(prompt + ': ')

def number(value, lo, hi):
    n = int(value)
    if not lo <= n <= hi:
        raise ValueError('Number outside allowed range')
    return n

def names(value):
    result = []
    for name in value.split():
        normalized, err = core.dns_name(name)
        if err:
            raise ValueError('Invalid DNS name')
        result.append(normalized)
    return sorted(set(result))

def default_config():
    return {'schema_version':2, 'email':'', 'cloudflare_credentials':'/etc/cgp-letsencrypt/cloudflare.ini',
            'propagation_seconds':60, 'dns_preflight':True, 'auto_enable_new_domains':False,
            'communigate':{'url':'http://127.0.0.1:8100/CLI/','username':'','password':''}, 'domains':[]}

def validate(cfg):
    c = cfg['communigate']
    if not re.fullmatch(r'http://127\.0\.0\.1:\d+/CLI/', c['url'], re.I):
        raise ValueError('Use a loopback HTTP CLI URL')
    if not c['username'] or not c['password']:
        raise ValueError('CommuniGate credentials required')
    if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', cfg['email']):
        raise ValueError('Valid ACME email required')
    number(cfg['propagation_seconds'], 10, 3600)
    for d in cfg.get('domains', []):
        core.identifier(d['cgp_domain'])
        for field in ('extra_names','exclude_names'):
            names(' '.join(d.get(field, [])))

def write_token(path, value):
    if not re.fullmatch(r'[A-Za-z0-9_-]+', value):
        raise ValueError('Invalid token syntax')
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as file:
            file.write('dns_cloudflare_api_token = ' + value + '\n')
            file.flush()
            os.fsync(file.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def setup():
    if os.geteuid() != 0 or not sys.stdin.isatty() or not sys.stdout.isatty():
        print('TUI requires root and an interactive terminal', file=sys.stderr)
        return 1
    if not shutil.which('whiptail'):
        print('Install whiptail first: apt install whiptail', file=sys.stderr)
        return 1
    os.umask(0o077)
    core.STATE.mkdir(parents=True, mode=0o700, exist_ok=True)
    with (core.STATE/'run.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('Certificate manager is busy', file=sys.stderr)
            return 1
        return edit()

def edit():
    from .cli import migrate
    cfg = migrate(core.load(core.CONFIG, default_config()))
    cfg.setdefault('auto_enable_new_domains', True)
    # Stage new tokens in a root-only temporary directory. No persistent
    # credential or configuration changes until explicit Save.
    with tempfile.TemporaryDirectory(prefix='cgp-tui-') as tmp:
        pending = {}
        def accounts():
            return cfg.get('cloudflare_accounts') or [{'credentials':cfg['cloudflare_credentials']}]
        def test_config():
            test = copy.deepcopy(cfg)
            test['cloudflare_accounts'] = [
                dict(a, credentials=str(pending.get(a['credentials'], a['credentials'])))
                for a in accounts()]
            return test
        def discover():
            test = test_config()
            return core.discover(test, core.zones(test))
        while True:
            try:
                choice = dialog('--menu','Select a configuration section',22,78,12,
                    '1','CommuniGate connection','2','Cloudflare accounts',
                    '3','Domain selection and SAN settings','4','ACME and DNS settings',
                    '5','TLS verification defaults','6','SMTP notifications',
                    '7','Read-only connection diagnostics','8','Save and exit','9','Discard and exit')
            except Cancel:
                return 1
            try:
                if choice == '1':
                    c = dict(cfg['communigate'])
                    c['url'] = ask('Local CLI URL', c['url'])
                    c['username'] = ask('Administrator login', c['username'])
                    c['password'] = secret('Password (blank keeps current)') or c['password']
                    test = dict(cfg, communigate=c)
                    domains = core.array(core.cli(test,'LISTDOMAINS'))
                    cfg['communigate'] = c
                    msg('Connection OK. Domains: ' + str(len(domains)))
                elif choice == '2':
                    current = accounts()
                    action = dialog('--menu','Cloudflare credentials',16,78,6,
                        'add','Add or replace account','remove','Remove account','list','List accessible zones')
                    if action == 'list':
                        z = core.zones(test_config())
                        msg('\n'.join(sorted(z)) or 'No accessible zones')
                    elif action == 'remove':
                        path = dialog('--menu','Remove account from configuration',18,78,10,
                            *[v for a in current for v in (a['credentials'],'Credential file')])
                        updated = [a for a in current if a['credentials'] != path]
                        if not updated:
                            raise ValueError('At least one account is required')
                        cfg['cloudflare_accounts'] = updated
                    else:
                        label = ask('Account identifier (letters, digits, hyphens)', 'main')
                        if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', label):
                            raise ValueError('Invalid account identifier')
                        path = str(core.CONFIG.parent / ('cloudflare-'+label+'.ini'))
                        value = secret('Cloudflare API token')
                        stage = Path(tmp)/('cloudflare-'+label+'.ini')
                        write_token(stage,value)
                        core.zones({'cloudflare_credentials':str(stage)})
                        pending[path] = stage
                        cfg['cloudflare_accounts'] = [a for a in current if a['credentials'] != path and Path(a['credentials']).is_file()] + [{'credentials':path,'name':label}]
                        # Keep other newly staged accounts too.
                        for other in pending:
                            if other != path and any(a['credentials']==other for a in current) and not any(a['credentials']==other for a in cfg['cloudflare_accounts']):
                                cfg['cloudflare_accounts'].append({'credentials':other})
                        msg('Token accepted; zone read access verified. DNS edit access is tested by Certbot dry-run.')
                elif choice == '3':
                    rows = discover()
                    if not rows:
                        raise ValueError('No domains returned by CommuniGate')
                    chosen = dialog('--menu','Select domain',22,78,12,
                        *[v for d in rows for v in (d['cgp_domain'], ('ON' if d['enabled'] else 'OFF')+' | SAN '+str(len(d['names'])))])
                    row = next(d for d in rows if d['cgp_domain']==chosen)
                    d = copy.deepcopy(next((d for d in cfg['domains'] if d['cgp_domain']==chosen),{'cgp_domain':chosen}))
                    d['enabled'] = yes('Manage '+chosen+' automatically?')
                    d['wildcard'] = yes('Include wildcard for '+chosen+'?')
                    d['extra_names'] = names(ask('Additional SANs (space separated)', ' '.join(d.get('extra_names',[]))))
                    d['exclude_names'] = names(ask('Excluded names (space separated)', ' '.join(d.get('exclude_names',[]))))
                    cfg['domains'] = [x for x in cfg['domains'] if x['cgp_domain']!=chosen]+[d]
                elif choice == '4':
                    email = ask('ACME account email',cfg['email'])
                    delay = number(ask('DNS propagation seconds',str(cfg['propagation_seconds'])),10,3600)
                    preflight = yes('Enable DNS delegation preflight?')
                    auto = yes('Automatically enable newly discovered domains?')
                    cfg.update(email=email,propagation_seconds=delay,dns_preflight=preflight,auto_enable_new_domains=auto)
                elif choice == '5':
                    if yes('Use automatic HTTPS/SNI checks on loopback port 443?'):
                        cfg.pop('tls',None)
                    else:
                        host = ask('TLS host','127.0.0.1')
                        port = number(ask('TLS port','443'),1,65535)
                        sni = names(ask('SNI hostname'))
                        if len(sni)!=1 or sni[0].startswith('*.'):
                            raise ValueError('One concrete hostname required')
                        mode = ask('STARTTLS protocol (empty for direct TLS)','')
                        if mode not in ('','smtp','imap','pop3','ldap','xmpp','xmpp-server'):
                            raise ValueError('Unsupported protocol')
                        ep = {'host':host,'port':port,'sni':sni[0]}
                        if mode: ep['starttls']=mode
                        cfg['tls']=[ep]
                elif choice == '6':
                    if yes('Enable SMTP error notifications?'):
                        old = cfg.get('notifications',{})
                        n = {'to':ask('Recipient',old.get('to','')),
                             'from':ask('Sender',old.get('from',cfg['email'])),
                             'host':ask('Trusted SMTP host',old.get('host','127.0.0.1')),
                             'port':number(ask('SMTP port',str(old.get('port',25))),1,65535)}
                        if not n['to'] or not n['from']: raise ValueError('Sender and recipient required')
                        cfg['notifications']=n
                    else: cfg.pop('notifications',None)
                elif choice == '7':
                    rows=discover()
                    msg('CGP and Cloudflare read access OK.\n'+'\n'.join(d['cgp_domain']+': '+str(len(d['names']))+' SAN' for d in rows))
                elif choice == '8':
                    validate(cfg)
                    discover()
                    if not yes('Save settings? No certificates will be issued or installed.'):
                        continue
                    # New credentials have distinct file names. Existing credentials
                    # and config are backed up before any replacement.
                    from datetime import datetime, timezone
                    backup = core.STATE/'config-backups'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
                    backup.mkdir(parents=True,mode=0o700)
                    if core.CONFIG.exists(): shutil.copy2(core.CONFIG,backup/'config.json')
                    active = {a['credentials'] for a in accounts()}
                    for path, stage in pending.items():
                        if path not in active: continue
                        target=Path(path)
                        if target.exists(): shutil.copy2(target,backup/target.name)
                        write_token(target,core.token(stage))
                    core.atomic(core.CONFIG,cfg)
                    msg('Configuration saved. Run --plan and --verify before enabling the timer.')
                    return 0
                elif choice == '9':
                    if yes('Discard unsaved changes?'): return 1
            except Cancel:
                continue
            except Exception as exc:
                # API exceptions may contain sensitive request data; show type only.
                msg('Operation failed: '+(str(exc) if isinstance(exc,ValueError) else type(exc).__name__))

if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--setup',action='store_true')
    parser.parse_args()
    sys.exit(setup())
