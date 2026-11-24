"""Interactive curses front end. All certificate operations use the existing CLI."""
import curses
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from . import __version__, core, storage
from .localization import language, translate

# The module path must refer to the same checkout, even when testing from /tmp.
ROOT = Path(__file__).resolve().parent.parent
CLI = [sys.executable, '-m', 'cgp_cert_manager.console_cli']

ACTIONS = (
    ('Verify certificate / TLS', ('--verify',), False),
    ('Verify all TLS listeners', ('--verify-listeners',), False),
    ('ACME staging dry-run', ('--dry-run',), True),
    ('Renew if necessary', (), True),
    ('Force reissue (ACME limits apply)', ('--force-renew',), True),
    ('Install local certificate / repair chain', ('--repair-chain',), True),
    ('List backups', ('--backups',), False),
    ('Select backup to restore (rollback)', ('--rollback',), True),
    ('Reset retry delay', ('--reset-backoff',), True),
    ('Retry now', ('--retry-now',), True),
    ('Transaction status', ('--transactions',), False),
    ('Recover pending transaction', ('--recover',), True),
    ('Acknowledge previous settings (TLS unverified)', ('--acknowledge-restored',), True),
)

def command_for(domain, index):
    name = core.identifier(domain)
    _, flags, _ = ACTIONS[index]
    if flags in (('--backups',), ('--rollback',)):
        return CLI + list(flags) + [name]
    return CLI + ['--domain', name] + list(flags)

def capture(command, timeout=120):
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                            errors='replace', timeout=timeout)
    return result.returncode, result.stdout, result.stderr

def read_status():
    code, stdout, _ = capture(CLI + ['--status','--json'])
    try:
        rows = json.loads(stdout)
        if not isinstance(rows,list) or not all(isinstance(r,dict) and isinstance(r.get('domain'),str) for r in rows):
            raise ValueError('Unexpected status response')
    except ValueError:
        return [], 'Status unavailable (exit %s)' % code
    return sorted(rows,key=lambda r:r['domain']), ('Inspection reported errors' if code else 'Status loaded')

def timer_status():
    try:
        code, output, _ = capture(['systemctl','is-active','cgp-letsencrypt.timer'],10)
        _, enabled, _ = capture(['systemctl','is-enabled','cgp-letsencrypt.timer'],10)
        _, next_run, _ = capture(['systemctl','show','cgp-letsencrypt.timer','--property=NextElapseUSecRealtime','--value'],10)
        return '%s / %s / next: %s' % (output.strip() or 'unknown', enabled.strip() or 'unknown', next_run.strip() or '-')
    except (OSError, subprocess.TimeoutExpired):
        return 'unavailable'

def row_status(row):
    if row.get('error') or row.get('tls')=='failed': return 'ERROR'
    if row.get('status')=='blocked': return 'BLOCKED'
    if row.get('status') in ('disabled','unavailable'): return 'SKIPPED'
    days=(row.get('installed') or {}).get('days')
    if isinstance(days,int) and days<1: return 'EXPIRED'
    if row.get('action') in ('ISSUE','REISSUE'): return row['action']
    if isinstance(days,int) and days<21: return 'EXPIRING'
    if row.get('tls')=='verified': return 'VERIFIED'
    return 'READY' if row.get('status')=='ready' else row.get('status','unknown')

def identity(row):
    return ((row.get('installed') or {}).get('fingerprint'),
            (row.get('local') or {}).get('fingerprint'),
            row.get('pki'),tuple(row.get('desired',[])))

def verified_rows(rows, results):
    """Keep verification only for matching certificate identity in this session."""
    by_name={r['domain']:r for r in results if isinstance(r,dict) and isinstance(r.get('domain'),str)}
    for row in rows:
        result=by_name.get(row['domain'])
        if result and result.get('tls')=='failed':
            row['tls']='failed'
            row['verified_at']=result.get('verified_at',time.strftime('%Y-%m-%d %H:%M:%S'))
            if result.get('error'): row['verification_error']=result['error']
        elif result and identity(result)==identity(row) and row.get('status')=='ready':
            if result.get('tls') in ('verified','failed'):
                row['tls']=result['tls']
                row['verified_at']=result.get('verified_at',time.strftime('%Y-%m-%d %H:%M:%S'))
                if result.get('error'): row['error']=result['error']
    return rows

def backup_command(domain, filename):
    core.identifier(domain)
    if not re.fullmatch(r'\d{8}T\d{12}Z\.json',filename):
        raise ValueError('Invalid backup filename')
    return CLI+['--rollback',domain,'--backup-file',filename]

def domain_history(name):
    path=core.STATE/'history.jsonl'
    from collections import deque
    lines=deque(maxlen=150)
    try:
        with storage.open_private(path) as stream:
            for line in stream:
                try: item=json.loads(line)
                except ValueError: continue
                if isinstance(item,dict) and item.get('domain')==name:
                    lines.append(str(item.get('time',''))+' '+str(item.get('event','')))
    except FileNotFoundError:
        return []
    except (OSError,UnicodeError,core.Error):
        return ['History unavailable']
    return list(lines)

HELP = [
    'Up / Down: choose domain or action',
    'Enter: open selected domain',
    'F2: configuration wizard',
    'F5: refresh snapshot (not a TLS test)',
    'F6: service journal',
    'F7: systemd timer controls',
    'F8: verify all managed domains',
    'F9: inspect or recover pending transactions',
    'S: cycle sorting (name, expiry, status)',
    'F: cycle filters (all, managed, attention)',
    'F1: help',
    'Escape / Q / F10: back or exit',
    'VERIFIED means TLS was checked during this session.',
    'Refresh invalidates earlier TLS results; verify again.',
    'Operations changing certificates require confirmation.',
    'Acknowledging previous settings does not verify TLS.',
]

def details(row):
    installed = row.get('installed') or {}
    local = row.get('local') or {}
    lines = [
        row['domain'], '',
        'Status: '+str(row_status(row)),
        'Action: '+str(row.get('action','-')),
        'PKI: '+str(row.get('pki','-')),
        'Installed expiry: '+str(installed.get('expiry','-')),
        'Days remaining: '+str(installed.get('days','-')),
        'Installed SHA256: '+str(installed.get('fingerprint','-')),
        'Local SHA256: '+str(local.get('fingerprint','-')),
        'Last result: '+str(row.get('last_result') or '-'),
        'TLS checked: '+str(row.get('verified_at','not checked this session')),
        '', 'Installed SANs:',
        *['  '+str(n) for n in installed.get('names',[])],
        '', 'Desired SANs:',
        *['  '+str(n) for n in row.get('desired',[])],
        '', 'Unavailable names:',
        *['  '+str(n) for n in row.get('unavailable',[])],
        '', 'Blocked removals:',
        *['  '+str(n) for n in row.get('blocked',[])],
    ]
    return lines

def safe_text(value):
    # Never render terminal control characters from logs or remote names.
    return ''.join(c if c.isprintable() else ' ' for c in str(value))

class Screen:
    def __init__(self, window):
        self.w = window
        self.lang=language()
        self.rows = []
        self.selected = 0
        self.offset = 0
        self.message = ''
        self.timer = 'unknown'
        self.updated = '-'
        self.sort_mode=0
        self.filter_mode=0
        self.all_rows=[]
        self.colors={}
        if curses.has_colors():
            try:
                curses.start_color()
                curses.use_default_colors()
                for i,(status,color) in enumerate((('VERIFIED',curses.COLOR_GREEN),('READY',curses.COLOR_CYAN),('EXPIRING',curses.COLOR_YELLOW),('REISSUE',curses.COLOR_YELLOW),('ISSUE',curses.COLOR_YELLOW),('ERROR',curses.COLOR_RED),('BLOCKED',curses.COLOR_RED),('EXPIRED',curses.COLOR_RED),('SKIPPED',curses.COLOR_WHITE)),1):
                    curses.init_pair(i,color,-1)
                    self.colors[status]=curses.color_pair(i)
            except curses.error:
                self.colors={}
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        self.w.keypad(True)

    def put(self,y,x,value,attr=0):
        h,w = self.w.getmaxyx()
        if y<0 or y>=h or x<0 or x>=w-1:
            return
        try:
            self.w.addnstr(y,x,safe_text(translate(str(value),getattr(self,'lang','en'))),w-x-1,attr)
        except curses.error:
            pass

    def refresh_data(self):
        self.message='Refreshing status...'
        self.draw()
        selected = self.rows[self.selected]['domain'] if self.rows else None
        try:
            rows,message=read_status()
            if message.startswith('Status unavailable'):
                self.message=message+'; previous snapshot retained'
            else:
                self.all_rows=rows
                self.message=message
                self.updated=time.strftime('%Y-%m-%d %H:%M:%S')
                self.apply_view(selected)
            self.timer=timer_status()
        except (OSError, subprocess.TimeoutExpired):
            self.message='Refresh failed; previous snapshot retained'

    def apply_view(self,selected=None):
        if selected is None and self.rows:
            selected=self.rows[self.selected]['domain']
        rows=list(self.all_rows)
        if self.filter_mode==1:
            rows=[r for r in rows if r.get('status')!='disabled' and r.get('status')!='unavailable']
        elif self.filter_mode==2:
            rows=[r for r in rows if row_status(r) not in ('READY','VERIFIED','SKIPPED')]
        if self.sort_mode==1:
            rows.sort(key=lambda r:((r.get('installed') or {}).get('days',999999),r['domain']))
        elif self.sort_mode==2:
            rows.sort(key=lambda r:(row_status(r),r['domain']))
        else:
            rows.sort(key=lambda r:r['domain'])
        self.rows=rows
        self.selected=next((i for i,r in enumerate(rows) if r['domain']==selected),0)

    def draw(self):
        self.w.erase()
        h,w=self.w.getmaxyx()
        self.put(0,0,'CGP Certificate Manager '+__version__+' | Console',curses.A_BOLD)
        if h<10 or w<48:
            self.put(2,0,'Enlarge terminal (minimum 48x10). Q / F10 exits.')
            self.w.refresh()
            return
        self.put(1,0,'Timer: '+self.timer)
        ready=sum(r.get('status')=='ready' and not r.get('error') for r in self.rows)
        self.put(2,0,'Domains: %d/%d | Ready: %d | %s'%(len(self.rows),len(self.all_rows),ready,self.updated))
        self.put(3,0,'DOMAIN                    DAYS  SAN     STATUS',curses.A_BOLD)
        visible=max(1,h-8)
        self.offset=max(0,min(self.offset,max(0,len(self.rows)-visible)))
        if self.selected<self.offset: self.offset=self.selected
        if self.selected>=self.offset+visible: self.offset=self.selected-visible+1
        for i,row in enumerate(self.rows[self.offset:self.offset+visible],self.offset):
            installed=row.get('installed') or {}
            text='%-25s %4s  %3d>%3d %s'%(row['domain'][:25],installed.get('days','-'),len(installed.get('names',[])),len(row.get('desired',[])),row_status(row))
            self.put(4+i-self.offset,0,text,self.colors.get(row_status(row),0) | (curses.A_REVERSE if i==self.selected else 0))
        self.put(h-3,0,self.message)
        self.put(h-2,0,'Enter Domain | F2 Settings | F5 Refresh | F6 Logs')
        self.put(h-1,0,'F1 Help | F7 Timer | F8 TLS | F9 Recovery | Q',curses.A_BOLD)
        self.w.refresh()

    def view(self,title,lines,allow_continue=False):
        pos=0
        while True:
            self.w.erase()
            h,w=self.w.getmaxyx()
            self.put(0,0,title,curses.A_BOLD)
            visible=max(1,h-3)
            pos=max(0,min(pos,max(0,len(lines)-visible)))
            for i,line in enumerate(lines[pos:pos+visible],1):
                self.put(i,0,line)
            self.put(h-1,0,'Up/Down | Enter Continue | Esc/Q Cancel' if allow_continue else 'Up/Down PgUp/PgDn | Esc/Q Back')
            self.w.refresh()
            key=self.w.getch()
            if key in (27,ord('q'),ord('Q'),curses.KEY_F10): return False if allow_continue else None
            if allow_continue and key in (10,13,curses.KEY_ENTER): return True
            if key==curses.KEY_UP: pos-=1
            if key==curses.KEY_DOWN: pos+=1
            if key==curses.KEY_PPAGE: pos-=visible
            if key==curses.KEY_NPAGE: pos+=visible

    def input_reason(self):
        text=''; error=''
        try:
            while True:
                self.w.erase()
                h,w=self.w.getmaxyx()
                self.put(0,0,'Reason for acknowledgement',curses.A_BOLD)
                self.put(2,0,'Enter 1 to 500 printable characters; no secrets.')
                self.put(4,0,text[-max(1,w-2):],curses.A_REVERSE)
                self.put(h-2,0,error)
                self.put(h-1,0,'Enter Continue | Esc/F10 Cancel')
                self.w.refresh()
                key=self.w.get_wch()
                if key in ('\x1b','\x03',curses.KEY_F10): return None
                if key in ('\n','\r',curses.KEY_ENTER):
                    if text.strip(): return text.strip()
                    error='A reason is required'
                elif key in ('\b','\x7f',curses.KEY_BACKSPACE):
                    text=text[:-1]; error=''
                elif isinstance(key,str):
                    if not key.isprintable(): error='Use printable characters only'
                    elif len(text)+len(key)>500: error='Maximum reason length is 500 characters'
                    else: text+=key; error=''
        except KeyboardInterrupt:
            return None

    def menu(self,title,options,initial=0):
        pos=max(0,min(initial,len(options)-1))
        while True:
            self.w.erase()
            h,w=self.w.getmaxyx()
            self.put(0,0,title,curses.A_BOLD)
            visible=max(1,h-3)
            offset=max(0,pos-visible+1)
            for i,label in enumerate(options[offset:offset+visible],offset):
                self.put(1+i-offset,0,label,curses.A_REVERSE if i==pos else 0)
            self.put(h-1,0,'Enter Select | Esc/Q Back')
            self.w.refresh()
            key=self.w.getch()
            if key in (27,ord('q'),ord('Q'),curses.KEY_F10): return None
            if key==curses.KEY_UP: pos=max(0,pos-1)
            if key==curses.KEY_DOWN: pos=min(len(options)-1,pos+1)
            if key in (10,13,curses.KEY_ENTER): return pos

    def confirm(self,label):
        return self.menu('Confirm: '+label,['Cancel / No','Proceed / Yes'])==1

    def verify(self,domain=None):
        for row in self.all_rows:
            if domain is None or row['domain']==domain:
                row.pop('tls',None); row.pop('verified_at',None); row.pop('verification_error',None)
        cmd=CLI+['--verify','--json']+(['--domain',domain] if domain else [])
        self.w.erase()
        self.put(0,0,'TLS verification',curses.A_BOLD)
        self.put(2,0,'Verifying certificate and complete CA chain...')
        self.w.refresh()
        try:
            code,out,err=capture(cmd,timeout=900)
            results=json.loads(out)
            if not isinstance(results,list) or not all(isinstance(r,dict) and isinstance(r.get('domain'),str) for r in results): raise ValueError('Invalid verification response')
            verified_rows(self.all_rows,results)
            self.apply_view()
            lines=[]
            for r in results:
                lines.append(str(r.get('domain','?'))+': '+str(row_status(r)))
                if r.get('error'): lines.append('  '+str(r['error']))
            lines+=['','Exit code: '+str(code)]
            if err: lines+=err.splitlines()
        except (ValueError,OSError,subprocess.TimeoutExpired):
            # A failed command never leaves a stale successful verification.
            for r in self.all_rows:
                if domain is None or r['domain']==domain:
                    r.pop('tls',None); r.pop('verified_at',None)
            lines=['Verification unavailable or timed out']
        self.view('TLS verification',lines)

    def choose_backup(self,name):
        try:
            code,out,err=capture(CLI+['--backups',name])
            files=[f for f in out.splitlines() if re.fullmatch(r'\d{8}T\d{12}Z\.json',f)]
            if code or not files:
                self.view('Backups',['No available backups']+err.splitlines())
                return
            choice=self.menu('Select backup for '+name,files+['Back'])
            if choice is None or choice==len(files): return
            if self.confirm('Restore '+name+' from '+files[choice]):
                self.execute(backup_command(name,files[choice]),'Restore backup')
        except (OSError,subprocess.TimeoutExpired):
            self.view('Backups',['Unable to list backups'])

    def inspect(self,cmd,label):
        # Read-only commands never leave curses or hand stdin to a child.
        self.w.erase()
        self.put(0,0,label,curses.A_BOLD)
        self.put(2,0,'Running diagnostic...')
        self.w.refresh()
        try:
            code,out,err=capture(cmd,timeout=900)
            lines=(out+'\n'+err).strip().splitlines()
            lines+=['','Exit code: '+str(code)]
        except (OSError,subprocess.TimeoutExpired):
            lines=['Diagnostic unavailable or timed out']
        self.view(label,lines)

    def execute(self,cmd,label):
        # Leave curses while an operation runs: live Certbot output and prompts
        # remain visible, and no root lock is held by the console itself.
        curses.def_prog_mode()
        curses.endwin()
        try:
            print('\n'+label,flush=True)
            result=subprocess.run(cmd,cwd=ROOT)
            print('\nExit code:',result.returncode)
            try: input('Press Enter to return to console...')
            except (EOFError,KeyboardInterrupt): pass
        except (OSError,KeyboardInterrupt):
            print('\nOperation interrupted or unavailable.')
        finally:
            curses.reset_prog_mode()
            curses.noecho()
            curses.cbreak()
            self.w.keypad(True)
            curses.flushinp()
            self.w.clearok(True)
            self.w.clear()
            self.w.refresh()
        self.lang=language()
        self.refresh_data()

    def domain_menu(self):
        if not self.rows: return
        row=self.rows[self.selected]
        name=row['domain']
        position=0
        while True:
            choice=self.menu(name,['Certificate details']+[x[0] for x in ACTIONS]+['Domain history','Back'],initial=position)
            if choice is None or choice==len(ACTIONS)+2: return
            position=choice
            if choice==len(ACTIONS)+1:
                self.view('Domain history',domain_history(name) or ['No history'])
                continue
            if choice==0:
                self.view(name,details(row))
                continue
            index=choice-1
            label,flags,mutates=ACTIONS[index]
            if flags==('--verify',):
                self.verify(name)
                row=next((r for r in self.all_rows if r['domain']==name),row)
                continue
            if flags==('--rollback',):
                self.choose_backup(name)
                row=next((r for r in self.all_rows if r['domain']==name),row)
                continue
            if flags==('--acknowledge-restored',):
                self.acknowledge_previous(name)
                continue
            if mutates and not self.confirm(label+' for '+name): continue
            command=command_for(name,index)
            if mutates:
                self.execute(command,label+' — '+name)
            else:
                self.inspect(command,label+' — '+name)
            # Stay inside the domain menu. A subsequent Back returns to the
            # domain list, not to the shell.
            row=next((r for r in self.rows if r['domain']==name),None)
            if row is None: return

    def logs(self):
        try:
            _,out,err=capture(['journalctl','-u','cgp-letsencrypt.service','-n','150','--no-pager'],15)
            self.view('Recent service journal',(out or err or 'No entries').splitlines())
        except (OSError,subprocess.TimeoutExpired):
            self.message='Journal unavailable'

    def timer_menu(self):
        options=['Show timer status','Apply saved schedule','Enable and start timer','Stop timer','Disable and stop timer','Back']
        choice=self.menu('Systemd timer',options)
        if choice is None or choice==5: return
        if choice==0:
            self.inspect(['systemctl','status','cgp-letsencrypt.timer','--no-pager'],options[choice])
            return
        if not self.confirm(options[choice]): return
        commands={1:CLI+['--apply-schedule'],2:['systemctl','enable','--now','cgp-letsencrypt.timer'],3:['systemctl','stop','cgp-letsencrypt.timer'],4:['systemctl','disable','--now','cgp-letsencrypt.timer']}
        self.execute(commands[choice],options[choice])

    def transaction_menu(self):
        # Recovery must remain available even when discovery returns no domains.
        options=['Transaction status','Recover all pending transactions','Acknowledge previous settings (TLS unverified)','Back']
        choice=self.menu('Pending transactions',options)
        if choice is None or choice==3: return
        if choice==0:
            self.inspect(CLI+['--transactions'],options[choice])
        elif choice==2:
            self.select_acknowledgement()
        elif self.confirm(options[choice]):
            self.execute(CLI+['--recover'],options[choice])

    def select_acknowledgement(self):
        title='Acknowledge previous settings (TLS unverified)'
        try:
            code,out,err=capture(CLI+['--transactions','--json'])
            if code:
                self.view(title,(err or 'Transaction inspection unavailable').splitlines())
                return
            rows=json.loads(out)
            if not isinstance(rows,list) or not all(isinstance(row,dict) and isinstance(row.get('domain'),str) for row in rows):
                raise ValueError('Invalid transaction response')
            names=sorted({core.identifier(row['domain']) for row in rows})
            if not names:
                self.view(title,['No pending transactions'])
                return
            choice=self.menu('Select pending transaction',names+['Back'])
            if choice is None or choice==len(names): return
            self.acknowledge_previous(names[choice])
        except (ValueError,OSError,subprocess.TimeoutExpired,core.Error):
            self.view(title,['Transaction inspection unavailable'])

    def acknowledge_previous(self,name):
        title='Acknowledge previous settings (TLS unverified)'
        try:
            name=core.identifier(name)
            cmd=CLI+['--acknowledge-restored','--domain',name]
            code,out,err=capture(cmd+['--json'])
            if code:
                self.view(title,(err or 'Acknowledgement preview unavailable').splitlines())
                return
            preview=json.loads(out)
            if (not isinstance(preview,dict) or preview.get('domain')!=name
                    or preview.get('phase') not in ('prepared','restoring','acknowledging')
                    or preview.get('state') not in ('previous','both')
                    or preview.get('server_matches') is not True or preview.get('tls')!='unverified'
                    or type(preview.get('pending_journal')) is not bool
                    or type(preview.get('authorization_recorded')) is not bool
                    or not isinstance(preview.get('confirmation_token'),str)
                    or not re.fullmatch(r'[0-9a-f]{64}',preview['confirmation_token'])):
                raise ValueError('Invalid acknowledgement preview')
            token=preview['confirmation_token']
            lines=['Domain:']+[name[i:i+40] for i in range(0,len(name),40)]
            lines+=['Phase: '+preview['phase'],'CGP state: '+preview['state'],
                    'TLS: unverified','Pending journal: '+str(preview['pending_journal']),
                    'Authorization recorded: '+str(preview['authorization_recorded']),
                    'Confirmation token:',token[:32],token[32:],'',
                    'CGP settings will remain unchanged.',
                    'Subsequent certificate work may resume.']
            if preview['authorization_recorded']: lines+=['Repeat the original acknowledgement reason.']
            if not self.view(title,lines,allow_continue=True): return
            reason=self.input_reason()
            if reason is None: return
            if not self.confirm('Acknowledge '+name+' / '+token[:12]+' (TLS unverified)'): return
            self.execute(cmd+['--confirm-transaction',token,'--reason',reason],title+' — '+name)
        except (ValueError,OSError,subprocess.TimeoutExpired,core.Error,curses.error):
            self.view(title,['Acknowledgement preview unavailable'])

    def loop(self):
        self.refresh_data()
        while True:
            self.draw()
            k=self.w.getch()
            if k in (27,ord('q'),ord('Q'),curses.KEY_F10): return
            if k==curses.KEY_UP: self.selected=max(0,self.selected-1)
            elif k==curses.KEY_DOWN: self.selected=min(max(0,len(self.rows)-1),self.selected+1)
            elif k==curses.KEY_F5: self.refresh_data()
            elif k in (10,13,curses.KEY_ENTER): self.domain_menu()
            elif k==curses.KEY_F2: self.execute(CLI+['--tui'],'Configuration wizard')
            elif k==curses.KEY_F6: self.logs()
            elif k==curses.KEY_F7: self.timer_menu()
            elif k==curses.KEY_F8: self.verify()
            elif k==curses.KEY_F9: self.transaction_menu()
            elif k==curses.KEY_F1: self.view('Help',HELP)
            elif k in (ord('s'),ord('S')):
                self.sort_mode=(self.sort_mode+1)%3
                self.apply_view()
                self.message='Sort: '+('name','expiry','status')[self.sort_mode]
            elif k in (ord('f'),ord('F')):
                self.filter_mode=(self.filter_mode+1)%3
                self.apply_view()
                self.message='Filter: '+('all','managed','attention')[self.filter_mode]

def entry():
    if os.geteuid()!=0 or not sys.stdin.isatty() or not sys.stdout.isatty():
        print('Console requires root and an interactive terminal',file=sys.stderr)
        return 1
    try:
        curses.wrapper(lambda window: Screen(window).loop())
        return 0
    except KeyboardInterrupt:
        return 0
    except curses.error:
        print('Unable to initialize terminal; check TERM and terminal size',file=sys.stderr)
        return 1
    except (OSError,core.Error) as error:
        print('Console unavailable: '+(str(error) if isinstance(error,core.Error) else type(error).__name__),file=sys.stderr)
        return 1

if __name__=='__main__':
    sys.exit(entry())
