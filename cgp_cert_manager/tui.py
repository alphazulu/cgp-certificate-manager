"""Optional whiptail configuration editor. No credentials in process arguments."""
import argparse
import copy
import getpass
import warnings
import uuid
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from . import core, dnsconfig, dnsproviders, storage, update_gate
from .localization import translate

LANGUAGE='en'

SAVED=0
CANCELLED=3

RU={
'Select a configuration section':'Выберите раздел настроек',
'CommuniGate connection':'Подключение CommuniGate',
'Cloudflare accounts':'Аккаунты Cloudflare',
'Domain selection and SAN settings':'Домены и настройки SAN',
'ACME and DNS settings':'Настройки ACME и DNS',
'TLS verification defaults':'Настройки проверки TLS',
'SMTP notifications':'Уведомления SMTP',
'Read-only connection diagnostics':'Диагностика подключения',
'Save and exit':'Сохранить и выйти',
'Exit without saving':'Выйти без сохранения',
'Exit':'Выход','Back':'Назад','Select':'Выбрать','OK':'ОК',
'Exit without saving changes?':'Выйти без сохранения изменений?',
'Discard and exit':'Отменить и выйти',
'Renewal schedule':'Расписание продления',
'Local CLI URL':'Локальный URL CLI',
'Administrator login':'Логин администратора',
'Password (blank keeps current)':'Пароль (пустой ввод сохраняет текущий)',
'Cloudflare API token':'API-токен Cloudflare',
'Cloudflare credentials':'Учётные данные Cloudflare',
'Add or replace account':'Добавить или заменить аккаунт',
'Remove account':'Удалить аккаунт',
'List accessible zones':'Доступные зоны',
'Select domain':'Выберите домен',
'Additional SANs (space separated)':'Дополнительные SAN через пробел',
'Excluded names (space separated)':'Исключённые имена через пробел',
'ACME account email':'Email аккаунта ACME',
'DNS propagation seconds':'Ожидание DNS в секундах',
'Enable DNS delegation preflight?':'Проверять делегирование DNS?',
'Automatically enable newly discovered domains?':'Автоматически включать новые домены?',
'Use automatic HTTPS/SNI checks on loopback port 443?':'Использовать автоматическую проверку HTTPS/SNI на порту 443?',
'TLS host':'Хост TLS', 'TLS port':'Порт TLS', 'SNI hostname':'Имя SNI',
'STARTTLS protocol (empty for direct TLS)':'Протокол STARTTLS (пусто для прямого TLS)',
'Enable SMTP error notifications?':'Включить уведомления SMTP?',
'Recipient':'Получатель','Sender':'Отправитель','Trusted SMTP host':'Доверенный SMTP-сервер','SMTP port':'Порт SMTP',
'First daily run hour (0-23)':'Час первого запуска (0–23)',
'Random delay in seconds':'Случайная задержка в секундах',
'Save settings? No certificates will be issued or installed.':'Сохранить настройки? Сертификаты не будут выпущены или установлены.',
'Discard unsaved changes?':'Отменить несохранённые изменения?',
'Configuration saved. Run --plan and --verify before enabling the timer.':'Настройки сохранены. Перед включением таймера выполните --plan и --verify.',
}

def tr(text):
    return RU.get(text,translate(text,LANGUAGE)) if LANGUAGE=='ru' else text

class Cancel(Exception):
    pass

def dialog(kind, *args, main_menu=False):
    # whiptail writes selections to stderr; use a separate output descriptor
    # so the interface itself stays attached to the terminal.
    with tempfile.TemporaryFile() as output:
        buttons = []
        if kind == '--menu':
            buttons = ['--ok-button', tr('Select'), '--cancel-button', tr('Exit' if main_menu else 'Back')]
        elif kind == '--inputbox':
            buttons = ['--ok-button', tr('OK'), '--cancel-button', tr('Back')]
        elif kind == '--yesno':
            buttons = ['--yes-button',tr('Yes'),'--no-button',tr('No')]
        p = subprocess.run(['whiptail', '--title', 'CGP Certificate Manager', *buttons,
                            '--output-fd', str(output.fileno()), kind, *[tr(str(a)) if i==0 or (kind=='--menu' and i>=5 and i%2==1) else str(a) for i,a in enumerate(args)]],
                           pass_fds=(output.fileno(),))
        if p.returncode != 0:
            raise Cancel(p.returncode)
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
    except Cancel as exc:
        if exc.args == (1,): return False
        raise

def secret(prompt):
    # getpass uses the controlling terminal, never the child process argv.
    with warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        return getpass.getpass(tr(prompt) + ': ')

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
    dnsconfig.validate(cfg)
    for d in cfg.get('domains', []):
        core.identifier(d['cgp_domain'])
        for field in ('extra_names','exclude_names'):
            names(' '.join(d.get(field, [])))

def write_token(path, value):
    if not re.fullmatch(r'[A-Za-z0-9_-]+', value):
        raise ValueError('Invalid token syntax')
    storage.atomic_text(path, 'dns_cloudflare_api_token = ' + value + '\n')

def edit_tls(existing, domain=None):
    if yes('Use automatic HTTPS/SNI checks on loopback port 443?'):
        return []
    old = existing[0] if existing else {}
    host = ask('TLS host', old.get('host','127.0.0.1'))
    port = number(ask('TLS port',str(old.get('port',443))),1,65535)
    mode = ask('STARTTLS protocol (empty for direct TLS)',old.get('starttls',''))
    if mode not in ('','smtp','imap','pop3','ldap','xmpp','xmpp-server'):
        raise ValueError('Unsupported protocol')
    ep = {'host':host,'port':port}
    if domain:
        sni = names(ask('SNI hostname',old.get('sni',domain)))
        if len(sni)!=1 or sni[0].startswith('*.'):
            raise ValueError('One concrete hostname required')
        ep['sni']=sni[0]
    if mode: ep['starttls']=mode
    return [ep]

def save_config(cfg, pending, active):
    # Immutable credential paths: the old config never references a new token.
    # The single atomic config replacement is the commit point.
    from datetime import datetime, timezone
    update_gate.require_idle()
    storage.validate_tree(core.STATE)
    previous = storage.read_text(core.CONFIG) if storage.check_private_file(core.CONFIG, missing_ok=True) else None
    storage.ensure_private_directory(core.STATE)
    storage.ensure_private_directory(core.STATE/'config-backups')
    backup = core.STATE/'config-backups'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    backup.mkdir(mode=0o700)
    if previous is not None:
        storage.atomic_text(backup/'config.json',previous)
    created=[]
    try:
        for path, stage in pending.items():
            if path not in active: continue
            target=Path(path)
            if storage.check_private_file(target, missing_ok=True): raise ValueError('Credential path already exists')
            write_token(target,core.token(stage))
            created.append(target)
        core.atomic(core.CONFIG,cfg)
    except BaseException:
        # Do not delete credentials if the configuration commit already happened.
        try:
            committed=core.load(core.CONFIG,{})==cfg
        except Exception:
            committed=True
        if not committed:
            for target in created: target.unlink(missing_ok=True)
        raise

def setup():
    if os.geteuid() != 0 or not sys.stdin.isatty() or not sys.stdout.isatty():
        print('TUI requires root and an interactive terminal', file=sys.stderr)
        return 1
    if not shutil.which('whiptail'):
        print('Install whiptail first: apt install whiptail', file=sys.stderr)
        return 1
    os.umask(0o077)
    try:
        update_gate.require_idle()
        with storage.operation_lock(core.STATE):
            update_gate.require_idle()
            storage.validate_tree(core.STATE)
            return edit()
    except BlockingIOError:
        print('Certificate manager is busy', file=sys.stderr)
        return 1
    except (core.Error, update_gate.PendingUpdateError) as exc:
        print('Configuration refused: '+str(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('\nConfiguration cancelled.', file=sys.stderr)
        return CANCELLED

def main_menu():
    # Always place exit actions first and fit smaller terminals.
    size = shutil.get_terminal_size((80,24))
    height = max(10, min(22, size.lines - 2))
    width = max(38, min(78, size.columns - 2))
    return dialog('--menu','Select a configuration section',height,width,max(2,height-8),
                  '8','Save and exit','9','Exit without saving',
                  '1','CommuniGate connection','2','Cloudflare accounts',
                  '3','Domain selection and SAN settings','4','ACME and DNS settings',
                  '5','TLS verification defaults','6','SMTP notifications',
                  '7','Read-only connection diagnostics','10','Renewal schedule',
                  '11','Language / Язык',main_menu=True)

def confirm_exit(dirty):
    if not dirty:
        return True
    try:
        return yes('Exit without saving changes?')
    except Cancel:
        return False

def edit():
    from .cli import migrate
    cfg = migrate(core.load(core.CONFIG, default_config()))
    # Only the configured backend may validate or stage its own credentials.
    # Keep propagation editing available even when those settings are invalid.
    dnsproviders.provider_name(cfg)
    global LANGUAGE
    LANGUAGE=cfg.get('tui_language','en')
    cfg.setdefault('auto_enable_new_domains', True)
    original = copy.deepcopy(cfg)
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
                choice = main_menu()
            except Cancel as exc:
                if exc.args not in ((1,), (255,)):
                    raise
                choice = '9'
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
                        path = str(core.CONFIG.parent / ('cloudflare-'+label+'-'+uuid.uuid4().hex+'.ini'))
                        value = secret('Cloudflare API token')
                        stage = Path(tmp)/Path(path).name
                        write_token(stage,value)
                        core.zones({'cloudflare_credentials':str(stage)})
                        pending[path] = stage
                        cfg['cloudflare_accounts'] = [a for a in current if a.get('name') != label and (Path(a['credentials']).is_file() or a['credentials'] in pending)] + [{'credentials':path,'name':label}]
                        msg('Token accepted; zone read access verified. DNS edit access is tested by Certbot dry-run.')
                elif choice == '3':
                    rows = discover()
                    if not rows:
                        raise ValueError('No domains returned by CommuniGate')
                    chosen = dialog('--menu','Select domain',22,78,12,
                        *[v for d in rows for v in (d['cgp_domain'], ('ON' if d['enabled'] else 'OFF')+' | SAN '+str(len(d['names'])))])
                    d = copy.deepcopy(next((d for d in cfg['domains'] if d['cgp_domain']==chosen),{'cgp_domain':chosen}))
                    d['enabled'] = yes('Manage '+chosen+' automatically?')
                    d['wildcard'] = yes('Include wildcard for '+chosen+'?')
                    d['extra_names'] = names(ask('Additional SANs (space separated)', ' '.join(d.get('extra_names',[]))))
                    d['exclude_names'] = names(ask('Excluded names (space separated)', ' '.join(d.get('exclude_names',[]))))
                    if yes('Configure individual TLS verification for this domain?'):
                        d['tls'] = edit_tls(d.get('tls',[]), chosen)
                    cfg['domains'] = [x for x in cfg['domains'] if x['cgp_domain']!=chosen]+[d]
                elif choice == '4':
                    email = ask('ACME account email',cfg['email'])
                    delay = number(ask('DNS propagation seconds',str(cfg['propagation_seconds'])),10,3600)
                    preflight = yes('Enable DNS delegation preflight?')
                    auto = yes('Automatically enable newly discovered domains?')
                    cfg.update(email=email,propagation_seconds=delay,dns_preflight=preflight,auto_enable_new_domains=auto)
                elif choice == '5':
                    cfg['tls'] = edit_tls(cfg.get('tls',[]))
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
                elif choice == '10':
                    old=cfg.get('schedule',{})
                    hour=number(ask('First daily run hour (0-23)',str(old.get('hour',3))),0,23)
                    delay=number(ask('Random delay in seconds',str(old.get('random_delay',900))),0,3600)
                    cfg['schedule']={'hour':hour,'random_delay':delay}
                elif choice == '11':
                    LANGUAGE=dialog('--menu','Language / Язык',12,60,3,'en','English','ru','Русский')
                    cfg['tui_language']=LANGUAGE
                elif choice == '8':
                    validate(cfg)
                    discover()
                    if not yes('Save settings? No certificates will be issued or installed.'):
                        continue
                    save_config(cfg,pending,{a['credentials'] for a in accounts()})
                    try:
                        msg('Configuration saved. Run --plan and --verify before enabling the timer.')
                    except Cancel:
                        pass
                    return SAVED
                elif choice == '9':
                    if confirm_exit(cfg != original):
                        return CANCELLED
            except Cancel:
                continue
            except Exception as exc:
                # API exceptions may contain sensitive request data; show type only.
                try:
                    msg(('Ошибка: ' if LANGUAGE=='ru' else 'Operation failed: ')+(tr(str(exc)) if isinstance(exc,ValueError) else type(exc).__name__))
                except Cancel:
                    pass

if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--setup',action='store_true')
    parser.parse_args()
    sys.exit(setup())
