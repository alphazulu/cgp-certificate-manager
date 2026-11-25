"""Public metrics publication without weakening private manager storage."""
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cgp_cert_manager import core, metrics_file


class MetricsFileTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.directory = self.root / 'collector'
        self.directory.mkdir(mode=0o755)
        self.target = self.directory / 'cgp.prom'
        for name, value in (('CONFIG', self.root / 'private' / 'config.json'),
                            ('STATE', self.root / 'state'),
                            ('LIVE', self.root / 'letsencrypt' / 'live')):
            self.enterContext(patch.object(core, name, value))
        self.old = 'cgp_collector_success 1\n'
        self.new = 'cgp_collector_success 0\n'

    def old_file(self):
        self.target.write_text(self.old)
        self.target.chmod(0o644)

    def refused(self, path=None, text=None):
        with self.assertRaises(metrics_file.MetricsFileError) as caught:
            metrics_file.write(self.target if path is None else path,
                               self.new if text is None else text)
        self.assertEqual(str(caught.exception), 'Metrics file publication failed')

    def assert_old(self):
        self.assertEqual(self.target.read_text(), self.old)
        self.assertEqual(self.target.stat().st_mode & 0o7777, 0o644)
        self.assertEqual(list(self.directory.iterdir()), [self.target])

    def test_new_file_is_public_despite_restrictive_umask_and_only_output_changes(self):
        previous = os.umask(0o077)
        try:
            metrics_file.write(self.target, self.new)
        finally:
            os.umask(previous)
        self.assertEqual(self.target.read_text(), self.new)
        self.assertEqual(self.target.stat().st_mode & 0o7777, 0o644)
        self.assertEqual(self.target.stat().st_uid, os.geteuid())
        self.assertEqual(self.target.stat().st_nlink, 1)
        self.assertEqual(list(self.directory.iterdir()), [self.target])
        self.assertEqual(list(self.root.iterdir()), [self.directory])

    def test_replacement_is_synced_in_order_and_never_truncates_old_inode(self):
        self.old_file()
        order = []
        fsync, replace = os.fsync, os.replace
        with self.target.open() as old:
            old_inode = os.fstat(old.fileno()).st_ino

            def sync(fd):
                order.append('directory' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file')
                fsync(fd)

            def rename(source, destination, **kwargs):
                self.assertFalse(source.endswith('.prom'))
                self.assertEqual(self.target.read_text(), self.old)
                order.append('replace')
                replace(source, destination, **kwargs)

            with patch.object(metrics_file.os, 'fsync', side_effect=sync), \
                    patch.object(metrics_file.os, 'replace', side_effect=rename):
                metrics_file.write(self.target, self.new)
            self.assertEqual(old.read(), self.old)
            self.assertNotEqual(self.target.stat().st_ino, old_inode)
        self.assertEqual(order, ['file', 'replace', 'directory'])
        self.assertEqual(self.target.read_text(), self.new)

    def test_invalid_paths_and_payloads_are_refused_without_replacing_previous(self):
        self.old_file()
        for path in ('relative.prom', '', self.directory / '..' / 'cgp.prom',
                     self.directory / 'config.json', self.directory / '.prom', 123):
            with self.subTest(path=path):
                self.refused(path=path)
                self.assert_old()
        for text in ('', 'no final newline', b'bytes\n', 42, '\ud800\n'):
            with self.subTest(text=repr(text)):
                self.refused(text=text)
                self.assert_old()

    def test_private_and_certbot_trees_are_never_output_targets(self):
        for protected in (core.CONFIG.parent, core.STATE, core.LIVE.parent):
            with self.subTest(protected=protected):
                self.refused(path=protected / 'cgp.prom')
                self.assertFalse(protected.exists())
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_absent_output_parent_is_not_created(self):
        parent = self.root / 'absent'
        self.refused(path=parent / 'cgp.prom')
        self.assertFalse(parent.exists())

    def test_unsafe_ancestors_and_sticky_final_directory_are_refused(self):
        parent = self.root / 'unsafe'
        parent.mkdir(mode=0o777)
        parent.chmod(0o777)
        nested = parent / 'collector'
        nested.mkdir(mode=0o755)
        self.refused(path=nested / 'cgp.prom')
        self.assertEqual(list(nested.iterdir()), [])
        parent.chmod(0o1777)
        self.refused(path=parent / 'cgp.prom')
        self.assertFalse((parent / 'cgp.prom').exists())
        # A trusted sticky directory is permitted as an ancestor only.
        metrics_file.write(nested / 'cgp.prom', self.new)
        self.assertEqual((nested / 'cgp.prom').read_text(), self.new)

    def test_symlink_parent_is_not_followed(self):
        link = self.root / 'linked'
        link.symlink_to(self.directory, target_is_directory=True)
        self.refused(path=link / 'cgp.prom')
        self.assertTrue(link.is_symlink())
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_private_writable_or_executable_existing_file_is_not_repaired(self):
        self.old_file()
        for mode in (0o600, 0o664, 0o666, 0o744, 0o4644):
            with self.subTest(mode=oct(mode)):
                self.target.chmod(mode)
                self.refused()
                self.assertEqual(self.target.read_text(), self.old)
                self.assertEqual(self.target.stat().st_mode & 0o7777, mode)
                self.assertEqual(list(self.directory.iterdir()), [self.target])

    def test_symlink_dangling_symlink_and_extra_hardlink_are_retained(self):
        victim = self.root / 'private-key'
        victim.write_text('PRIVATE_KEY')
        victim.chmod(0o600)
        for destination in (victim, self.root / 'absent'):
            with self.subTest(destination=destination):
                self.target.symlink_to(destination)
                self.refused()
                self.assertTrue(self.target.is_symlink())
                self.assertEqual(victim.read_text(), 'PRIVATE_KEY')
                self.target.unlink()
        self.old_file()
        other = self.root / 'linked-output'
        os.link(self.target, other)
        self.refused()
        self.assertEqual(self.target.stat().st_nlink, 2)
        self.assertEqual(other.read_text(), self.old)

    def test_directory_and_fifo_targets_are_refused_without_open_blocking(self):
        self.target.mkdir()
        self.refused()
        self.assertTrue(self.target.is_dir())
        self.target.rmdir()
        os.mkfifo(self.target, mode=0o600)
        self.refused()
        self.assertTrue(stat.S_ISFIFO(self.target.stat().st_mode))

    def test_foreign_file_and_parent_ownership_are_refused(self):
        self.old_file()
        fstat = os.fstat
        parent_inode = self.directory.stat().st_ino
        for foreign_file in (True, False):
            def foreign(fd):
                info = fstat(fd)
                selected = stat.S_ISREG(info.st_mode) if foreign_file else info.st_ino == parent_inode
                if selected:
                    return SimpleNamespace(st_mode=info.st_mode, st_uid=os.geteuid() + 1,
                                           st_nlink=info.st_nlink)
                return info
            with self.subTest(file=foreign_file), patch.object(metrics_file.os, 'fstat', side_effect=foreign):
                self.refused()
            self.assert_old()

    def test_concurrent_target_creation_or_replacement_preserves_other_writer(self):
        fsync = os.fsync
        for existed in (False, True):
            with self.subTest(existed=existed):
                self.target.unlink(missing_ok=True)
                if existed:
                    self.old_file()

                def replace_target(fd):
                    fsync(fd)
                    other = self.directory / 'other'
                    other.write_text('OTHER_WRITER\n')
                    other.chmod(0o644)
                    os.replace(other, self.target)

                with patch.object(metrics_file.os, 'fsync', side_effect=replace_target):
                    self.refused()
                self.assertEqual(self.target.read_text(), 'OTHER_WRITER\n')
                self.assertEqual(list(self.directory.iterdir()), [self.target])

    def test_target_becoming_private_before_replace_is_retained(self):
        self.old_file()
        fsync = os.fsync

        def privatize(fd):
            fsync(fd)
            self.target.chmod(0o600)

        with patch.object(metrics_file.os, 'fsync', side_effect=privatize):
            self.refused()
        self.assertEqual(self.target.read_text(), self.old)
        self.assertEqual(self.target.stat().st_mode & 0o7777, 0o600)
        self.assertEqual(list(self.directory.iterdir()), [self.target])

    def test_failures_before_replace_leave_previous_file_and_no_temporary(self):
        self.old_file()
        for operation in ('fdopen', 'fchmod', 'fsync', 'replace'):
            with self.subTest(operation=operation), \
                    patch.object(metrics_file.os, operation, side_effect=OSError('PRIVATE_FAILURE')):
                self.refused()
            self.assert_old()

    def test_temporary_collision_does_not_remove_existing_object(self):
        self.old_file()
        occupied = self.directory / '.cgp-metrics-collision'
        occupied.write_text('UNRELATED')
        with patch.object(metrics_file.secrets, 'token_hex', return_value='collision'):
            self.refused()
        self.assertEqual(occupied.read_text(), 'UNRELATED')
        self.assertEqual(self.target.read_text(), self.old)

    def test_directory_sync_failure_reports_uncertain_durability_after_replace(self):
        self.old_file()
        fsync = os.fsync

        def sync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError('PRIVATE_FAILURE')
            fsync(fd)

        with patch.object(metrics_file.os, 'fsync', side_effect=sync):
            self.refused()
        self.assertEqual(self.target.read_text(), self.new)
        self.assertEqual(self.target.stat().st_mode & 0o7777, 0o644)
        self.assertEqual(list(self.directory.iterdir()), [self.target])
