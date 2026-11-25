"""Real filesystem checks at CLI and console boundaries; no service calls."""
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cgp_cert_manager import cli, console, core, localization, schedule, storage


class PrivateCLITests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.state = self.root / 'state'
        self.state.mkdir(mode=0o700)
        self.config = self.root / 'config.json'
        self.cfg = {'schema_version': 2, 'email': 'admin@example.com'}
        core.atomic(self.config, self.cfg)
        for module, name, value in (
            (cli, 'CONFIG', self.config), (core, 'CONFIG', self.config),
            (schedule, 'CONFIG', self.config), (cli, 'STATE', self.state),
            (core, 'STATE', self.state),
        ):
            self.stack.enter_context(patch.object(module, name, value))
        # Creation protections must not depend on the caller's process umask.
        self.stack.enter_context(patch.object(cli.os, 'umask'))
        self.out = io.StringIO()
        self.stack.enter_context(contextlib.redirect_stdout(self.out))

    def invoke(self, *args):
        with patch.object(cli.sys, 'argv', ['cgp-letsencrypt', *args]):
            return cli.main()

    def private_file(self, path, content='unchanged'):
        path.write_text(content)
        path.chmod(0o600)
        return path

    def test_state_directory_permissions_rejected_before_dispatch(self):
        self.state.chmod(0o755)
        with patch.object(cli, 'locked_main') as dispatch, self.assertRaises(storage.StorageError):
            self.invoke('--status')
        dispatch.assert_not_called()
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o755)
        self.assertFalse((self.state / 'run.lock').exists())

    def test_symlink_state_directory_never_creates_lock_in_target(self):
        link = self.root / 'linked-state'
        link.symlink_to(self.state, target_is_directory=True)
        with patch.object(cli, 'STATE', link), patch.object(cli, 'locked_main') as dispatch, self.assertRaises(storage.StorageError):
            self.invoke('--status')
        dispatch.assert_not_called()
        self.assertEqual(list(self.state.iterdir()), [])

    def test_lock_file_symlinks_hardlinks_modes_and_special_files_rejected(self):
        lock = self.state / 'run.lock'
        target = self.private_file(self.root / 'outside.json')
        for kind in ('symlink', 'hardlink', 'mode', 'fifo', 'directory'):
            with self.subTest(kind=kind):
                if kind == 'symlink': lock.symlink_to(target)
                elif kind == 'hardlink': os.link(target, lock)
                elif kind == 'mode':
                    self.private_file(lock)
                    lock.chmod(0o644)
                elif kind == 'fifo': os.mkfifo(lock, 0o600)
                else: lock.mkdir(mode=0o700)
                try:
                    with patch.object(cli, 'locked_main') as dispatch, self.assertRaises(storage.StorageError):
                        self.invoke('--status')
                    dispatch.assert_not_called()
                    self.assertEqual(target.read_text(), 'unchanged')
                finally:
                    if kind == 'directory': lock.rmdir()
                    else: lock.unlink()

    def test_operation_lock_is_exclusive_without_truncating_existing_file(self):
        lock = self.private_file(self.state / 'run.lock', 'lock marker')
        with storage.operation_lock(self.state), patch.object(cli, 'locked_main') as dispatch:
            with self.assertRaises(BlockingIOError): self.invoke('--status')
            dispatch.assert_not_called()
        with patch.object(cli, 'locked_main', return_value=0) as dispatch:
            self.assertEqual(self.invoke('--status'), 0)
        dispatch.assert_called_once()
        self.assertEqual(lock.read_text(), 'lock marker')
        self.assertEqual(lock.stat().st_mode & 0o777, 0o600)

    def test_hooks_validate_private_files_but_do_not_acquire_parent_lock(self):
        with storage.operation_lock(self.state), patch.object(cli, 'hook') as hook:
            self.assertEqual(self.invoke('--hook-auth'), 0)
        hook.assert_called_once_with(self.cfg, False)
        self.config.chmod(0o644)
        with patch.object(cli, 'hook') as hook, self.assertRaises(storage.StorageError):
            self.invoke('--hook-cleanup')
        hook.assert_not_called()

    def test_config_symlink_and_public_permissions_fail_before_dispatch(self):
        actual = self.root / 'actual.json'
        self.config.rename(actual)
        self.config.symlink_to(actual)
        with patch.object(cli, 'locked_main') as dispatch, self.assertRaises(storage.StorageError):
            self.invoke('--history')
        dispatch.assert_not_called()
        self.config.unlink()
        actual.rename(self.config)
        self.config.chmod(0o640)
        with patch.object(cli, 'locked_main') as dispatch, self.assertRaises(storage.StorageError):
            self.invoke('--history')
        dispatch.assert_not_called()
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o640)

    def test_history_created_private_and_read_back_without_following_links(self):
        path = self.state / 'history.jsonl'
        cli.history('example.com', 'installed')
        cli.history('example.com', 'verified')
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.stat().st_nlink, 1)
        self.assertEqual([json.loads(line)['event'] for line in path.read_text().splitlines()], ['installed', 'verified'])
        self.assertEqual(self.invoke('--history'), 0)
        self.assertIn('verified', self.out.getvalue())
        self.assertEqual(len(console.domain_history('example.com')), 2)

    def test_history_unsafe_file_neither_read_nor_appended(self):
        path = self.state / 'history.jsonl'
        target = self.private_file(self.root / 'outside.jsonl', 'PRIVATE SENTINEL')
        for kind in ('symlink', 'hardlink', 'mode'):
            with self.subTest(kind=kind):
                if kind == 'symlink': path.symlink_to(target)
                elif kind == 'hardlink': os.link(target, path)
                else:
                    self.private_file(path)
                    path.chmod(0o640)
                try:
                    with self.assertRaises(storage.StorageError): cli.history('example.com', 'failure')
                    with self.assertRaises(storage.StorageError): self.invoke('--history')
                    self.assertEqual(console.domain_history('example.com'), ['History unavailable'])
                    self.assertNotIn('PRIVATE SENTINEL', self.out.getvalue())
                    self.assertEqual(target.read_text(), 'PRIVATE SENTINEL')
                    if kind == 'mode': self.assertEqual(path.stat().st_mode & 0o777, 0o640)
                finally:
                    path.unlink()

    def test_unsafe_history_preflight_blocks_external_actions_and_hooks(self):
        path = self.private_file(self.state / 'history.jsonl')
        path.chmod(0o640)
        for args in ((), ('--install-only',), ('--hook-auth',)):
            with self.subTest(args=args), patch.object(cli, 'zones') as zones, patch.object(cli, 'issue') as issue, patch.object(cli, 'deploy') as deploy, patch.object(cli, 'hook') as hook:
                with self.assertRaises(storage.StorageError): self.invoke(*args)
                zones.assert_not_called()
                issue.assert_not_called()
                deploy.assert_not_called()
                hook.assert_not_called()
        self.assertEqual(path.read_text(), 'unchanged')
        self.assertEqual(path.stat().st_mode & 0o777, 0o640)

    def test_backup_listing_rejects_unsafe_backup_before_printing(self):
        path = core.backup('example.com', {'marker': 'private backup'})
        path.chmod(0o644)
        with self.assertRaises(storage.StorageError): self.invoke('--backups', 'example.com')
        self.assertEqual(self.out.getvalue(), '')
        self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_unsafe_language_config_does_not_silently_use_defaults(self):
        self.config.chmod(0o644)
        with self.assertRaises(storage.StorageError): localization.language()
        self.assertEqual(localization.translate('History unavailable', 'ru'), 'История недоступна')

    def test_language_access_failure_is_visible_but_missing_file_uses_default(self):
        with patch.object(core, 'load', side_effect=PermissionError()):
            with self.assertRaises(PermissionError): localization.language()
        self.config.unlink()
        self.assertEqual(localization.language(), 'en')

    def test_schedule_rejects_unsafe_config_before_writing_or_systemctl(self):
        self.config.chmod(0o644)
        dropin = self.private_file(self.root / 'schedule.conf', 'unchanged schedule')
        with patch.object(schedule, 'DROPIN', dropin), patch.object(schedule.subprocess, 'run') as run, self.assertRaises(storage.StorageError):
            schedule.apply()
        run.assert_not_called()
        self.assertEqual(dropin.read_text(), 'unchanged schedule')

    def test_console_reports_private_config_failures_without_traceback(self):
        for error, expected in ((storage.StorageError('Unsafe private file'), 'Unsafe private file'), (PermissionError('PRIVATE SENTINEL'), 'PermissionError')):
            with self.subTest(error=type(error).__name__), patch.object(console.os, 'geteuid', return_value=0), patch.object(console.sys.stdin, 'isatty', return_value=True), patch.object(console.sys.stdout, 'isatty', return_value=True), patch.object(console.curses, 'wrapper', side_effect=error), contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(console.entry(), 1)
            self.assertIn('Console unavailable: '+expected, stderr.getvalue())
            self.assertNotIn('PRIVATE SENTINEL', stderr.getvalue())

    def test_console_history_invalid_encoding_is_explicitly_unavailable(self):
        path = self.state / 'history.jsonl'
        path.write_bytes(b'\xff')
        path.chmod(0o600)
        self.assertEqual(console.domain_history('example.com'), ['History unavailable'])

