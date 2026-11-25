"""The standalone update gate is read-only and refuses every pending entry."""
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cgp_cert_manager import update_gate as gate


class UpdateGateTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.state = self.root / 'updates'

    def refused(self, code, state=None):
        with self.assertRaises(gate.PendingUpdateError) as raised:
            gate.require_idle(self.state if state is None else state)
        self.assertEqual(raised.exception.code, code)
        self.assertEqual(str(raised.exception), code)
        self.assertIn(code, gate.CODES)

    def test_missing_and_empty_state_do_not_create_anything_or_take_locks(self):
        with patch.object(gate, 'STATE_DIR', self.state), patch.object(gate.os, 'mkdir') as mkdir:
            self.assertIsNone(gate.require_idle())
            self.assertIsNone(gate.require_idle(self.state / 'nested'))
        mkdir.assert_not_called()
        self.assertFalse(self.state.exists())
        self.state.mkdir(mode=0o700)
        before = self.state.stat()
        self.assertIsNone(gate.require_idle(self.state))
        self.assertEqual(list(self.state.iterdir()), [])
        after = self.state.stat()
        self.assertEqual((before.st_ino, before.st_mtime_ns, before.st_ctime_ns),
                         (after.st_ino, after.st_mtime_ns, after.st_ctime_ns))

    def test_any_pending_object_blocks_without_reading_it(self):
        self.state.mkdir(mode=0o700)
        pending = self.state / 'pending.json'
        for value in (b'', b'not JSON', b'{"phase":"completed"}'):
            pending.write_bytes(value)
            pending.chmod(0)
            with patch('builtins.open', side_effect=AssertionError('no pending contents read')):
                self.refused('update_pending')
            pending.unlink()
        pending.symlink_to(self.root / 'absent')
        self.refused('update_pending')
        pending.unlink()
        pending.mkdir()
        self.refused('update_pending')
        pending.rmdir()
        os.mkfifo(pending)
        self.refused('update_pending')

    def test_paths_must_be_absolute_canonical_and_not_follow_symlinks(self):
        for value in ('relative', '/tmp/../updates', '//tmp/updates', '/tmp/\0updates', 42):
            self.refused('update_gate_unsafe', value)
        outside = self.root / 'outside'
        outside.mkdir(mode=0o700)
        self.state.symlink_to(outside, target_is_directory=True)
        self.refused('update_gate_unsafe')
        self.assertEqual(list(outside.iterdir()), [])
        self.state.unlink()
        self.state.write_text('not a directory')
        self.refused('update_gate_unsafe')

    def test_private_state_and_trusted_ancestors_are_checked_without_repair(self):
        self.state.mkdir(mode=0o755)
        self.refused('update_gate_unsafe')
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o755)
        self.state.chmod(0o700)
        self.root.chmod(0o777)
        self.refused('update_gate_unsafe')
        self.root.chmod(0o1777)
        self.assertIsNone(gate.require_idle(self.state))
        self.root.chmod(0o700)
        self.state.chmod(0o500)
        self.assertIsNone(gate.require_idle(self.state))

    def test_untrusted_directory_owner_and_type_are_rejected(self):
        self.state.mkdir(mode=0o700)
        original = os.fstat
        target = self.state.stat().st_ino
        def different_owner(fd):
            info = original(fd)
            if info.st_ino == target:
                return SimpleNamespace(st_mode=info.st_mode, st_uid=os.geteuid() + 1)
            return info
        with patch.object(gate.os, 'fstat', side_effect=different_owner):
            self.refused('update_gate_unsafe')
        with self.assertRaises(gate.PendingUpdateError):
            gate._directory(SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=os.geteuid()), True)
        with self.assertRaises(gate.PendingUpdateError):
            gate._directory(SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=os.geteuid() + 12345), False)

    def test_unreadable_paths_and_marker_are_unknown_not_idle(self):
        with patch.object(gate.os, 'open', side_effect=PermissionError('PRIVATE error')):
            self.refused('update_gate_unsafe')
        self.state.mkdir(mode=0o700)
        with patch.object(gate.os, 'stat', side_effect=PermissionError('PRIVATE marker')):
            self.refused('update_gate_unsafe')
        self.refused('update_gate_unsafe', '/')

    def test_module_can_be_loaded_as_the_standalone_alias_without_application_imports(self):
        source = Path(gate.__file__)
        specification = importlib.util.spec_from_file_location('cgp_update_gate_fixture', source)
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        self.assertEqual(module.CODES, gate.CODES)
        self.assertIsNone(module.require_idle(self.state))


if __name__ == '__main__':
    unittest.main()
