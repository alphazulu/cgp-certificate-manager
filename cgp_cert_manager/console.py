"""Interactive curses front end. All certificate operations use the existing CLI."""
import curses
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from . import __version__, core

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
    ('Restore latest backup (rollback)', ('--rollback',), True),
    ('Reset retry delay', ('--reset-backoff',), True),
    ('Retry now', ('--retry-now',), True),
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
    return row.get('error') or row.get('tls') or row.get('status','unknown')

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
        self.rows = []
        self.selected = 0
        self.offset = 0
        self.message = ''
        self.timer = 'unknown'
        self.updated = '-'
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
            self.w.addnstr(y,x,safe_text(value),w-x-1,attr)
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
                self.rows=rows
                self.message=message
                self.updated=time.strftime('%Y-%m-%d %H:%M:%S')
                self.selected=next((i for i,r in enumerate(rows) if r['domain']==selected),0)
            self.timer=timer_status()
        except (OSError, subprocess.TimeoutExpired):
            self.message='Refresh failed; previous snapshot retained'

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
        self.put(2,0,'Domains: %d | Ready: %d | Snapshot: %s'%(len(self.rows),ready,self.updated))
        self.put(3,0,'DOMAIN                    DAYS  SAN     STATUS',curses.A_BOLD)
        visible=max(1,h-8)
        self.offset=max(0,min(self.offset,max(0,len(self.rows)-visible)))
        if self.selected<self.offset: self.offset=self.selected
        if self.selected>=self.offset+visible: self.offset=self.selected-visible+1
        for i,row in enumerate(self.rows[self.offset:self.offset+visible],self.offset):
            installed=row.get('installed') or {}
            text='%-25s %4s  %3d>%3d %s'%(row['domain'][:25],installed.get('days','-'),len(installed.get('names',[])),len(row.get('desired',[])),row_status(row))
            self.put(4+i-self.offset,0,text,curses.A_REVERSE if i==self.selected else 0)
        self.put(h-3,0,self.message)
        self.put(h-2,0,'Enter Domain | F2 Settings | F5 Refresh | F6 Logs')
        self.put(h-1,0,'F7 Timer | F8 Verify all | Q/F10 Exit',curses.A_BOLD)
        self.w.refresh()

    def view(self,title,lines):
        pos=0
        while True:
            self.w.erase()
            h,w=self.w.getmaxyx()
            self.put(0,0,title,curses.A_BOLD)
            visible=max(1,h-3)
            pos=max(0,min(pos,max(0,len(lines)-visible)))
            for i,line in enumerate(lines[pos:pos+visible],1):
                self.put(i,0,line)
            self.put(h-1,0,'Up/Down PgUp/PgDn | Esc/Q Back')
            self.w.refresh()
            key=self.w.getch()
            if key in (27,ord('q'),ord('Q'),curses.KEY_F10): return
            if key==curses.KEY_UP: pos-=1
            if key==curses.KEY_DOWN: pos+=1
            if key==curses.KEY_PPAGE: pos-=visible
            if key==curses.KEY_NPAGE: pos+=visible

    def menu(self,title,options):
        pos=0
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
        self.refresh_data()

    def domain_menu(self):
        if not self.rows: return
        row=self.rows[self.selected]
        name=row['domain']
        while True:
            choice=self.menu(name,['Certificate details']+[x[0] for x in ACTIONS]+['Back'])
            if choice is None or choice==len(ACTIONS)+1: return
            if choice==0:
                self.view(name,details(row))
                continue
            index=choice-1
            label,_,mutates=ACTIONS[index]
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
            elif k==curses.KEY_F8: self.inspect(CLI+['--verify'],'Verify all managed domains')

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

if __name__=='__main__':
    sys.exit(entry())
