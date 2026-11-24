"""Exercise console navigation and rendering without a real terminal."""
import contextlib
import io
import json
import runpy
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from cgp_cert_manager import console as c, core

NAME='example.com'
BACKUP='20261124T010203123456Z.json'

def row(name=NAME,days=80,**kw):
    return dict(domain=name,status='ready',action='VERIFY/KEEP',installed={'days':days,'fingerprint':'a','names':[name]},local={'fingerprint':'a'},desired=[name],pki='YES',**kw)

class ScreenTests(unittest.TestCase):
    def setUp(self):
        self.stack=contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.w=Mock()
        self.w.getmaxyx.return_value=(24,100)
        self.stack.enter_context(patch.object(c,'language',return_value='en'))
        self.stack.enter_context(patch.object(c.curses,'has_colors',return_value=False))
        self.stack.enter_context(patch.object(c.curses,'curs_set'))
        self.screen=c.Screen(self.w)
        self.screen.all_rows=[row()]
        self.screen.apply_view()

    def keys(self,*keys):
        self.w.getch.side_effect=keys

    def test_colors_and_terminal_failure(self):
        with patch.object(c.curses,'has_colors',return_value=True),patch.object(c.curses,'start_color'),patch.object(c.curses,'use_default_colors'),patch.object(c.curses,'init_pair') as pair,patch.object(c.curses,'color_pair',return_value=256):
            s=c.Screen(self.w)
            self.assertEqual(s.colors['VERIFIED'],256)
            self.assertEqual(pair.call_count,9)
        with patch.object(c.curses,'has_colors',return_value=True),patch.object(c.curses,'start_color',side_effect=c.curses.error),patch.object(c.curses,'curs_set',side_effect=c.curses.error):
            self.assertEqual(c.Screen(self.w).colors,{})

    def test_put_bounds_and_error(self):
        for y,x in ((-1,0),(24,0),(0,-1),(0,99)):
            self.screen.put(y,x,'no')
        self.w.addnstr.assert_not_called()
        self.screen.put(0,0,'x\x1by')
        self.w.addnstr.assert_called_once_with(0,0,'x y',99,0)
        self.w.addnstr.side_effect=c.curses.error
        self.screen.put(0,0,'safe')

    def test_refresh_success_and_failure(self):
        s=self.screen
        with patch.object(c,'read_status',return_value=([row('new.com')],'Status loaded')),patch.object(c,'timer_status',return_value='active'):
            s.refresh_data()
            self.assertEqual(s.rows[0]['domain'],'new.com')
            self.assertEqual(s.timer,'active')
        with patch.object(c,'read_status',return_value=([],'Status unavailable (exit 1)')),patch.object(c,'timer_status',return_value='unknown'):
            s.refresh_data()
            self.assertEqual(s.rows[0]['domain'],'new.com')
            self.assertIn('retained',s.message)
        with patch.object(c,'read_status',side_effect=OSError()):
            s.refresh_data()
            self.assertIn('Refresh failed',s.message)

    def test_sort_filter_and_selection(self):
        s=self.screen
        disabled=dict(row('disabled.com'),status='disabled')
        blocked=dict(row('blocked.com'),status='blocked')
        s.all_rows=[row('z.com',30),disabled,blocked,row('a.com',10)]
        s.apply_view('z.com')
        self.assertEqual(s.rows[s.selected]['domain'],'z.com')
        s.sort_mode=1; s.apply_view()
        self.assertEqual(s.rows[0]['domain'],'a.com')
        s.sort_mode=2; s.apply_view()
        self.assertEqual(s.rows[0]['domain'],'blocked.com')
        s.filter_mode=1; s.apply_view()
        self.assertNotIn('disabled.com',[r['domain'] for r in s.rows])
        s.filter_mode=2; s.apply_view()
        self.assertEqual(set(r['domain'] for r in s.rows),{'a.com','blocked.com'})

    def test_draw_small_and_scrolling(self):
        s=self.screen
        self.w.getmaxyx.return_value=(8,40)
        s.draw()
        self.assertTrue(any('Enlarge terminal' in str(a) for a in self.w.addnstr.call_args_list))
        self.w.getmaxyx.return_value=(10,100)
        s.all_rows=[row('d%d.com'%i) for i in range(8)]
        s.apply_view()
        s.selected=7; s.draw()
        self.assertEqual(s.offset,6)
        s.selected=0; s.draw()
        self.assertEqual(s.offset,0)

    def test_view_scroll_and_escape(self):
        self.keys(c.curses.KEY_DOWN,c.curses.KEY_NPAGE,c.curses.KEY_UP,c.curses.KEY_PPAGE,27)
        self.screen.view('Details',[str(i) for i in range(50)])
        self.assertEqual(self.w.getch.call_count,5)

    def test_menu_and_confirmation(self):
        self.keys(c.curses.KEY_DOWN,c.curses.KEY_UP,c.curses.KEY_DOWN,10)
        self.assertEqual(self.screen.menu('Options',['one','two']),1)
        self.keys(27)
        self.assertIsNone(self.screen.menu('Options',['one']))
        self.keys(10)
        self.assertFalse(self.screen.confirm('test'))
        self.keys(c.curses.KEY_DOWN,10)
        self.assertTrue(self.screen.confirm('test'))

    def test_verify_success_and_errors(self):
        s=self.screen
        s.view=Mock()
        result=dict(row(),tls='verified')
        with patch.object(c,'capture',return_value=(0,json.dumps([result]),'diagnostic')) as cap:
            s.verify(NAME)
            self.assertIn('--domain',cap.call_args.args[0])
        self.assertEqual(c.row_status(s.rows[0]),'VERIFIED')
        self.assertIn('diagnostic',s.view.call_args.args[1])
        result=dict(row(),tls='failed',error='TLS failure')
        with patch.object(c,'capture',return_value=(1,json.dumps([result]),'')):
            s.verify()
        self.assertEqual(c.row_status(s.rows[0]),'ERROR')
        with patch.object(c,'capture',return_value=(1,'null','')):
            s.verify()
        self.assertNotIn('tls',s.rows[0])
        self.assertIn('unavailable',s.view.call_args.args[1][0])
        with patch.object(c,'capture',side_effect=subprocess.TimeoutExpired('x',1)):
            s.verify(NAME)

    def test_verify_only_selected_domain(self):
        s=self.screen
        s.all_rows.append(dict(row('other.com'),tls='verified'))
        s.apply_view()
        s.view=Mock()
        with patch.object(c,'capture',return_value=(0,json.dumps([dict(row(),tls='verified')]),'')):
            s.verify(NAME)
        self.assertEqual(s.all_rows[1]['tls'],'verified')

    def test_backup_selection(self):
        s=self.screen
        s.view=Mock(); s.menu=Mock(return_value=0); s.confirm=Mock(return_value=True); s.execute=Mock()
        with patch.object(c,'capture',return_value=(0,BACKUP+'\n../bad\n','')):
            s.choose_backup(NAME)
        s.execute.assert_called_once_with(c.backup_command(NAME,BACKUP),'Restore backup')
        s.execute.reset_mock()
        with patch.object(c,'capture',return_value=(0,BACKUP,'')):
            for choice,confirm in ((None,True),(1,True),(0,False)):
                s.menu.return_value=choice; s.confirm.return_value=confirm
                s.choose_backup(NAME)
        s.execute.assert_not_called()
        with patch.object(c,'capture',return_value=(1,'','error')):
            s.choose_backup(NAME)
        self.assertIn('No available backups',s.view.call_args.args[1])
        with patch.object(c,'capture',side_effect=OSError()):
            s.choose_backup(NAME)
        self.assertIn('Unable to list backups',s.view.call_args.args[1])

    def test_inspect_failure(self):
        self.screen.view=Mock()
        with patch.object(c,'capture',side_effect=OSError()):
            self.screen.inspect(['dummy'],'Inspect')
        self.assertIn('Diagnostic unavailable or timed out',self.screen.view.call_args.args[1])

    def test_execute_restores_terminal(self):
        s=self.screen
        s.refresh_data=Mock()
        with contextlib.ExitStack() as stack:
            methods={n:stack.enter_context(patch.object(c.curses,n)) for n in ('def_prog_mode','endwin','reset_prog_mode','noecho','cbreak','flushinp')}
            run=stack.enter_context(patch.object(c.subprocess,'run',return_value=Mock(returncode=0)))
            ask=stack.enter_context(patch('builtins.input',return_value=''))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            s.execute(['dummy'],'Test')
            methods['reset_prog_mode'].assert_called_once()
            ask.side_effect=EOFError()
            s.execute(['dummy'],'Test')
            run.side_effect=KeyboardInterrupt()
            s.execute(['dummy'],'Test')
            self.assertEqual(methods['reset_prog_mode'].call_count,3)
            self.assertEqual(s.refresh_data.call_count,3)

    def test_domain_menu_actions(self):
        s=self.screen
        s.menu=Mock(side_effect=[0,len(c.ACTIONS)+1,8,3,3,2,None])
        s.view=Mock(); s.choose_backup=Mock(); s.confirm=Mock(side_effect=[False,True]); s.execute=Mock(); s.inspect=Mock()
        with patch.object(c,'domain_history',return_value=[]):
            s.domain_menu()
        s.choose_backup.assert_called_once_with(NAME)
        s.execute.assert_called_once()
        s.inspect.assert_called_once()
        self.assertEqual(s.view.call_count,2)
        s.rows=[]; s.domain_menu()

    def test_domain_disappears(self):
        s=self.screen
        s.menu=Mock(return_value=2)
        s.inspect=Mock(side_effect=lambda *a: s.rows.clear())
        s.domain_menu()
        s.inspect.assert_called_once()

    def test_logs(self):
        s=self.screen; s.view=Mock()
        with patch.object(c,'capture',return_value=(0,'line','')):
            s.logs()
        self.assertEqual(s.view.call_args.args[1],['line'])
        with patch.object(c,'capture',side_effect=OSError()):
            s.logs()
        self.assertEqual(s.message,'Journal unavailable')

    def test_timer_menu(self):
        s=self.screen
        s.menu=Mock(); s.confirm=Mock(return_value=True); s.execute=Mock(); s.inspect=Mock()
        for choice in (None,5,0,1,2,3,4):
            s.menu.return_value=choice
            s.timer_menu()
        s.inspect.assert_called_once()
        self.assertEqual(s.execute.call_count,4)
        s.confirm.return_value=False
        s.timer_menu()
        self.assertEqual(s.execute.call_count,4)

    def test_loop_all_shortcuts(self):
        s=self.screen
        for name in ('refresh_data','draw','domain_menu','execute','logs','timer_menu','verify','view'):
            setattr(s,name,Mock())
        self.keys(c.curses.KEY_DOWN,c.curses.KEY_UP,c.curses.KEY_F5,10,c.curses.KEY_F2,c.curses.KEY_F6,c.curses.KEY_F7,c.curses.KEY_F8,c.curses.KEY_F1,ord('s'),ord('f'),27)
        s.loop()
        self.assertEqual(s.refresh_data.call_count,2)
        for name in ('domain_menu','execute','logs','timer_menu','verify','view'):
            getattr(s,name).assert_called_once()
        self.assertEqual((s.sort_mode,s.filter_mode),(1,1))

class ConsoleHelperTests(unittest.TestCase):
    def test_capture(self):
        with patch.object(c.subprocess,'run',return_value=Mock(returncode=7,stdout='out',stderr='err')):
            self.assertEqual(c.capture(['dummy']),(7,'out','err'))

    def test_status_errors(self):
        with patch.object(c,'capture',return_value=(1,json.dumps([row()]),'')):
            self.assertEqual(c.read_status()[1],'Inspection reported errors')
        with patch.object(c,'capture',return_value=(0,'[null]','')):
            self.assertEqual(c.read_status()[0],[])

    def test_timer(self):
        with patch.object(c,'capture',side_effect=[(0,'active',''),(0,'enabled',''),(0,'tomorrow','')]):
            self.assertEqual(c.timer_status(),'active / enabled / next: tomorrow')
        with patch.object(c,'capture',side_effect=OSError()):
            self.assertEqual(c.timer_status(),'unavailable')

    def test_status_variants(self):
        for r,expected in [(dict(row(),status='blocked'),'BLOCKED'),(dict(row(),status='disabled'),'SKIPPED'),(row(days=0),'EXPIRED'),(row(days=10),'EXPIRING'),(row(),'READY'),({},'unknown')]:
            self.assertEqual(c.row_status(r),expected)

    def test_history(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(core,'STATE',Path(tmp)):
            self.assertEqual(c.domain_history(NAME),[])
            (Path(tmp)/'history.jsonl').write_text('bad JSON\n'+json.dumps({'domain':NAME,'event':'ok'})+'\n')
            self.assertEqual(c.domain_history(NAME),[' ok'])

    def test_entry(self):
        with patch.object(c.os,'geteuid',return_value=1),contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(c.entry(),1)
        with patch.object(c.os,'geteuid',return_value=0),patch.object(c.sys.stdin,'isatty',return_value=True),patch.object(c.sys.stdout,'isatty',return_value=True),patch.object(c.curses,'wrapper') as wrapper,contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(c.entry(),0)
            wrapper.side_effect=KeyboardInterrupt()
            self.assertEqual(c.entry(),0)
            wrapper.side_effect=c.curses.error()
            self.assertEqual(c.entry(),1)

    def test_main_module(self):
        with patch.object(c.os,'geteuid',return_value=1),contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as e:
                runpy.run_module('cgp_cert_manager.console',run_name='__main__')
        self.assertEqual(e.exception.code,1)
