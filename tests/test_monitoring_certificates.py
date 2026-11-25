"""Local monitoring reads only bounded public leaves through trusted paths."""

from datetime import datetime, timezone
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

from cgp_cert_manager import core, monitoring_certificates as certificates, storage


class MonitoringCertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Real public X.509 certificates, with keys generated only in memory.
        # Monitoring parses both through the actual OpenSSL executable below.
        key = ed25519.Ed25519PrivateKey.generate()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'example.invalid')])
        cls.pem = {}
        for year in (2020, 2030):
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                    .public_key(key.public_key()).serial_number(year)
                    .not_valid_before(datetime(2019, 1, 1, tzinfo=timezone.utc))
                    .not_valid_after(datetime(year, 1, 1, tzinfo=timezone.utc))
                    .sign(key, algorithm=None))
            cls.pem[year] = cert.public_bytes(serialization.Encoding.PEM)

    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.live = self.root / 'letsencrypt' / 'live'
        self.archive = self.live.parent / 'archive'
        self.lineage = 'example.invalid'
        self.leaf = self.live / self.lineage / 'cert.pem'
        self.original_run = core.run
        self.run = self.enterContext(patch.object(core, 'run', return_value=b'notAfter=Jan  1 00:00:00 2030 GMT\n'))
        for module, name in ((core, 'cli'), (core, 'cf'), (core, 'token'),
                             (storage, 'operation_lock'), (storage, 'atomic_json'),
                             (storage, 'ensure_private_directory')):
            self.enterContext(patch.object(module, name, side_effect=AssertionError('Monitoring must not mutate or call providers')))

    def regular(self, pem=None):
        self.leaf.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.leaf.write_bytes(self.pem[2030] if pem is None else pem)
        self.leaf.chmod(0o644)
        return self.leaf

    def linked(self, absolute=False):
        self.leaf.parent.mkdir(parents=True, mode=0o700)
        target = self.archive / self.lineage / 'cert1.pem'
        target.parent.mkdir(parents=True, mode=0o700)
        target.write_bytes(self.pem[2030])
        target.chmod(0o600)
        self.leaf.symlink_to(target if absolute else '../../archive/' + self.lineage + '/cert1.pem')
        return target

    def inspect(self):
        return certificates.inspect(self.lineage, self.live)

    def assert_ok(self, year=2030):
        self.assertEqual(self.inspect(), {'status': 'ok',
                         'not_after': int(datetime(year, 1, 1, tzinfo=timezone.utc).timestamp())})

    def test_invalid_lineage_and_root_rejected_before_any_path_lookup(self):
        with patch.object(storage, '_directory') as directories:
            for lineage in (None, [], 1, True, '', '.', '..', '../other', '/absolute',
                            'other/name', 'bad\nname', 'a..b', 'a' * 256):
                self.assertEqual(certificates.inspect(lineage, self.live), {'status': 'error'})
            self.assertEqual(certificates.inspect(self.lineage, 'relative'), {'status': 'error'})
            self.assertEqual(certificates.inspect(self.lineage, 1), {'status': 'error'})
            directories.assert_not_called()
        self.run.assert_not_called()

    def test_default_root_is_selected_at_call_time(self):
        self.regular()
        with patch.object(core, 'LIVE', self.live):
            self.assertEqual(certificates.inspect(self.lineage), self.inspect())
        with patch.object(core, 'LIVE', self.root / 'missing-live'):
            self.assertEqual(certificates.inspect(self.lineage), {'status': 'missing'})

    def test_missing_root_lineage_and_leaf_are_distinct_from_errors(self):
        self.assertEqual(self.inspect(), {'status': 'missing'})
        self.assertFalse(self.live.exists())
        self.live.mkdir(parents=True)
        self.assertEqual(self.inspect(), {'status': 'missing'})
        self.leaf.parent.mkdir()
        self.assertEqual(self.inspect(), {'status': 'missing'})
        self.run.assert_not_called()
        self.assertEqual(list(self.leaf.parent.iterdir()), [])

    def test_regular_public_certificate_uses_one_bounded_stdin_command(self):
        self.regular()
        before = self.leaf.stat()
        self.assert_ok()
        self.run.assert_called_once_with('openssl', 'x509', '-noout', '-enddate',
                                         data=self.pem[2030], timeout=10)
        after = self.leaf.stat()
        self.assertEqual((before.st_mtime_ns, before.st_ctime_ns, before.st_mode),
                         (after.st_mtime_ns, after.st_ctime_ns, after.st_mode))

    def test_standard_relative_archive_link_reads_only_public_leaf(self):
        self.linked()
        for filename in ('privkey.pem', 'chain.pem', 'fullchain.pem'):
            (self.leaf.parent / filename).write_text('PRIVATE_SENTINEL')
        original = os.open
        def observed(path, *args, **kwargs):
            self.assertNotIn(Path(path).name, ('privkey.pem', 'privkey1.pem', 'chain.pem', 'fullchain.pem'))
            return original(path, *args, **kwargs)
        with patch.object(certificates.os, 'open', side_effect=observed):
            self.assert_ok()
        self.run.assert_called_once()
        self.assertNotIn(b'PRIVATE_SENTINEL', self.run.call_args.kwargs['data'])

    def test_exact_absolute_archive_link_is_supported(self):
        self.linked(absolute=True)
        self.assert_ok()

    def test_real_openssl_parses_valid_and_expired_public_certificates(self):
        for year in (2020, 2030):
            with self.subTest(year=year):
                self.regular(self.pem[year])
                with patch.object(core, 'run', wraps=self.original_run) as real:
                    self.assert_ok(year)
                real.assert_called_once()

    def test_empty_malformed_or_multiple_pem_objects_are_errors(self):
        for pem in (b'', b'PRIVATE_SENTINEL', self.pem[2030] + self.pem[2020],
                    self.pem[2030] + b'-----BEGIN PRIVATE KEY-----\nPRIVATE_SENTINEL\n-----END PRIVATE KEY-----'):
            with self.subTest(pem_length=len(pem)):
                self.regular(pem)
                self.assertEqual(self.inspect(), {'status': 'error'})
        self.run.assert_not_called()
        self.regular(b'-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----\n')
        with patch.object(core, 'run', wraps=self.original_run):
            self.assertEqual(self.inspect(), {'status': 'error'})

    def test_parser_and_expiry_failures_are_errors_not_absence(self):
        self.regular()
        for output in (b'', b'PRIVATE_SENTINEL', b'notBefore=Jan  1 00:00:00 2030 GMT',
                       b'notAfter=invalid', b'notAfter=Jan  1 00:00:00 2030 UTC', b'\xff'):
            with self.subTest(output=output), patch.object(core, 'run', return_value=output):
                self.assertEqual(self.inspect(), {'status': 'error'})
        for error in (core.Error('PRIVATE_SENTINEL'), OSError('PRIVATE_SENTINEL'),
                      subprocess.TimeoutExpired('openssl', 10)):
            with self.subTest(error=type(error).__name__), patch.object(core, 'run', side_effect=error):
                self.assertEqual(self.inspect(), {'status': 'error'})
        for expiry in (True, None, float('nan'), float('inf'), float('-inf')):
            with self.subTest(expiry=expiry), patch.object(certificates.ssl, 'cert_time_to_seconds', return_value=expiry):
                self.assertEqual(self.inspect(), {'status': 'error'})

    def test_untrusted_writable_certificate_is_not_read_or_repaired(self):
        self.regular()
        for mode in (0o664, 0o666, 0o622):
            with self.subTest(mode=mode):
                self.leaf.chmod(mode)
                with patch.object(certificates.os, 'read', side_effect=AssertionError('Unsafe file must not be read')):
                    self.assertEqual(self.inspect(), {'status': 'error'})
                self.assertEqual(stat.S_IMODE(self.leaf.stat().st_mode), mode)
        self.run.assert_not_called()

    def test_untrusted_file_owner_is_not_read(self):
        self.regular()
        original = os.fstat
        def wrong_owner(fd):
            info = original(fd)
            if stat.S_ISREG(info.st_mode):
                return SimpleNamespace(st_mode=info.st_mode, st_uid=os.geteuid() + 1)
            return info
        with patch.object(certificates.os, 'fstat', side_effect=wrong_owner), \
                patch.object(certificates.os, 'read', side_effect=AssertionError('Wrong owner must not be read')):
            self.assertEqual(self.inspect(), {'status': 'error'})
        self.run.assert_not_called()

    def test_writable_ancestor_and_parent_traversal_are_errors(self):
        self.regular()
        self.leaf.parent.chmod(0o777)
        self.assertEqual(self.inspect(), {'status': 'error'})
        self.leaf.parent.chmod(0o700)
        self.assertEqual(certificates.inspect(self.lineage, self.live / '..' / 'live'), {'status': 'error'})
        self.run.assert_not_called()

    def test_broken_recognized_archive_link_is_error_not_missing(self):
        target = self.linked()
        target.unlink()
        self.assertEqual(self.inspect(), {'status': 'error'})
        target.parent.rmdir()
        self.assertEqual(self.inspect(), {'status': 'error'})
        self.run.assert_not_called()

    def test_foreign_lineage_escape_and_noncertificate_targets_are_rejected(self):
        self.leaf.parent.mkdir(parents=True)
        targets = ('../../archive/other/cert1.pem', '/etc/shadow',
                   '../../../private.pem', 'cert.pem',
                   '../../archive/' + self.lineage + '/privkey1.pem',
                   '../../archive/' + self.lineage + '/chain1.pem',
                   '../../archive/' + self.lineage + '/cert0.pem',
                   '../../archive/' + self.lineage + '/cert1.pem/../../../private.pem')
        for target in targets:
            with self.subTest(target=target):
                self.leaf.symlink_to(target)
                self.assertEqual(self.inspect(), {'status': 'error'})
                self.leaf.unlink()
        self.run.assert_not_called()

    def test_symlinked_live_or_archive_directories_are_rejected(self):
        target = self.linked()
        for directory in (self.leaf.parent, self.live, target.parent, self.archive):
            with self.subTest(directory=directory.name):
                renamed = directory.with_name(directory.name + '-original')
                directory.rename(renamed)
                directory.symlink_to(renamed, target_is_directory=True)
                self.assertEqual(self.inspect(), {'status': 'error'})
                directory.unlink()
                renamed.rename(directory)
        self.run.assert_not_called()

    def test_archive_leaf_symlink_and_hardlink_are_rejected(self):
        target = self.linked()
        moved = target.with_name('private.pem')
        target.rename(moved)
        target.symlink_to(moved)
        self.assertEqual(self.inspect(), {'status': 'error'})
        target.unlink()
        os.link(moved, target)
        self.assertEqual(self.inspect(), {'status': 'error'})
        self.run.assert_not_called()

    def test_untrusted_and_hardlinked_live_symlinks_are_rejected(self):
        self.linked()
        original = os.stat
        def wrong_owner(path, *args, **kwargs):
            info = original(path, *args, **kwargs)
            if path == 'cert.pem' and kwargs.get('follow_symlinks') is False:
                return SimpleNamespace(st_mode=info.st_mode, st_uid=os.geteuid() + 1)
            return info
        with patch.object(certificates.os, 'stat', side_effect=wrong_owner):
            self.assertEqual(self.inspect(), {'status': 'error'})
        os.link(self.leaf, self.leaf.with_name('duplicate-link'), follow_symlinks=False)
        self.assertEqual(self.inspect(), {'status': 'error'})
        self.run.assert_not_called()

    def test_special_files_fail_without_blocking(self):
        self.leaf.parent.mkdir(parents=True)
        os.mkfifo(self.leaf, 0o600)
        self.assertEqual(self.inspect(), {'status': 'error'})
        self.leaf.unlink()
        self.leaf.mkdir()
        self.assertEqual(self.inspect(), {'status': 'error'})
        self.run.assert_not_called()

    def test_read_limit_accepts_boundary_but_never_reads_oversize_file(self):
        limit = certificates.MAX_CERTIFICATE_BYTES
        self.regular(self.pem[2030] + b'\n' * (limit - len(self.pem[2030])))
        self.assert_ok()
        self.run.reset_mock()
        self.regular(b'X' * (limit + 1))
        with patch.object(certificates.os, 'read', side_effect=AssertionError('Oversize file must not be read')):
            self.assertEqual(self.inspect(), {'status': 'error'})
        self.run.assert_not_called()

    def test_growth_and_short_reads_are_errors(self):
        self.regular()
        with patch.object(certificates.os, 'read', return_value=b'X' * (certificates.MAX_CERTIFICATE_BYTES + 1)) as read:
            self.assertEqual(self.inspect(), {'status': 'error'})
            read.assert_called_once()
        with patch.object(certificates.os, 'read', side_effect=[self.pem[2030][:-1], b'']):
            self.assertEqual(self.inspect(), {'status': 'error'})
        self.run.assert_not_called()

    def test_partial_reads_can_capture_one_unchanged_leaf(self):
        self.regular()
        with patch.object(certificates.os, 'read', side_effect=[self.pem[2030][:20], self.pem[2030][20:], b'']):
            self.assert_ok()

    def test_in_place_certificate_mutation_is_error(self):
        self.regular()
        original = os.read
        first = True
        def changed(fd, size):
            nonlocal first
            value = original(fd, size)
            if first:
                first = False
                os.utime(self.leaf, ns=(1, 1))
            return value
        with patch.object(certificates.os, 'read', side_effect=changed):
            self.assertEqual(self.inspect(), {'status': 'error'})
        self.run.assert_not_called()

    def test_live_link_retargeted_during_read_is_error(self):
        target = self.linked()
        next_target = target.with_name('cert2.pem')
        next_target.write_bytes(self.pem[2020])
        original = os.read
        first = True
        def retargeted(fd, size):
            nonlocal first
            value = original(fd, size)
            if first:
                first = False
                self.leaf.unlink()
                self.leaf.symlink_to('../../archive/' + self.lineage + '/cert2.pem')
            return value
        with patch.object(certificates.os, 'read', side_effect=retargeted):
            self.assertEqual(self.inspect(), {'status': 'error'})
        self.run.assert_not_called()

    def test_leaf_disappearing_after_metadata_check_is_error_not_missing(self):
        self.regular()
        original = os.open
        def disappeared(path, *args, **kwargs):
            if path == 'cert.pem':
                self.leaf.unlink()
            return original(path, *args, **kwargs)
        with patch.object(certificates.os, 'open', side_effect=disappeared):
            self.assertEqual(self.inspect(), {'status': 'error'})
        self.run.assert_not_called()
