"""Signed-byte archive boundaries and private staging, without candidate code."""
import copy
import gzip
import hashlib
import io
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cgp_cert_manager import update_archive as archive, update_metadata
from repo_tools import release


class UpdateArchiveTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.parent = self.root / "stages"
        self.parent.mkdir(mode=0o700)
        self.version = "2.3.4rc1"
        self.prefix = "cgp-certificate-manager-v" + self.version
        self.distribution = "cgp_certbot_dns-" + self.version + ".dist-info"
        self.files = {
            "README.md": (b"source documentation\n", 0o644),
            "binary.dat": (bytes(range(256)), 0o644),
            "cgp_cert_manager/__init__.py": (("__version__ = " + repr(self.version) + "\n").encode(), 0o644),
            self.distribution + "/METADATA": (("Metadata-Version: 2.1\nName: cgp-certbot-dns\nVersion: "
                                              + self.version + "\n\n").encode(), 0o644),
            self.distribution + "/entry_points.txt":
                (b"[certbot.plugins]\ncgp-dns = cgp_cert_manager.certbot_dns:Authenticator\n", 0o644),
            self.distribution + "/top_level.txt": (b"cgp_cert_manager\n", 0o644),
            "docs/" + "long-" * 30 + "/unicode-ёж.txt": ("long UTF-8 path\n".encode(), 0o644),
            "empty.txt": (b"", 0o644),
            "install.sh": (("#!/bin/sh\ntouch " + str(self.root / "EXECUTED") + "\n").encode(), 0o755),
        }
        self.raw = self.tar()
        self.data = self.compress(self.raw)
        self.manifest = self.manifest_for(self.data)

    @staticmethod
    def compress(raw):
        stream = io.BytesIO()
        with gzip.GzipFile(filename="", fileobj=stream, mode="wb", mtime=0, compresslevel=9) as output:
            output.write(raw)
        return stream.getvalue()

    def manifest_for(self, data):
        return {"schema": 1, "project": "cgp-certificate-manager", "channel": "candidate", "sequence": 1,
                "version": self.version, "issued_at": 1700000000, "expires_at": 1700003600,
                "source": {"repository": "alphazulu/cgp-certificate-manager", "commit": "a" * 40,
                           "tree": "b" * 40, "tag": "v" + self.version},
                "archive": {"name": self.prefix + ".tar.gz", "size": len(data),
                            "sha256": hashlib.sha256(data).hexdigest()}}

    @staticmethod
    def record(name, data=b"", mode=0o644, kind=tarfile.REGTYPE, **kwargs):
        info = tarfile.TarInfo(name)
        info.mode, info.size, info.type = mode, len(data), kind
        for key, value in kwargs.items():
            setattr(info, key, value)
        return info.tobuf(format=tarfile.PAX_FORMAT) + data + bytes(-len(data) % 512)

    def tar(self, files=None, records=None, root=True):
        values = self.files if files is None else files
        if records is None:
            records = [self.record(self.prefix + "/" + name, *values[name])
                       for name in sorted(values, key=lambda value: value.encode("utf-8"))]
        raw = (self.record(self.prefix + "/", mode=0o755, kind=tarfile.DIRTYPE) if root else b"")
        raw += b"".join(records) + bytes(1024)
        return raw + bytes(-len(raw) % tarfile.RECORDSIZE)

    def inspect_raw(self, raw):
        data = self.compress(raw)
        return archive.inspect_archive(data, self.manifest_for(data))

    def assert_bad(self, function, *args, code=None):
        with self.assertRaises(update_metadata.UpdateError) as caught:
            function(*args)
        self.assertIn(caught.exception.code, archive.CODES)
        self.assertEqual(str(caught.exception), caught.exception.code)
        if code:
            self.assertEqual(caught.exception.code, code)

    def prepared(self):
        return archive.stage(self.data, self.manifest, self.parent)

    def test_inspection_is_read_only_complete_and_does_not_execute_candidate(self):
        with patch("builtins.open", side_effect=AssertionError("no files")), \
                patch.object(archive.os, "open", side_effect=AssertionError("no descriptors")), \
                patch.object(tarfile, "open", side_effect=AssertionError("no TarFile parser")), \
                patch.object(subprocess, "run", side_effect=AssertionError("no processes")):
            result = archive.inspect_archive(self.data, self.manifest)
        self.assertEqual(set(result), {"version", "prefix", "files", "inventory_sha256", "total_bytes"})
        expected = [{"path": path, "mode": mode, "size": len(value), "sha256": hashlib.sha256(value).hexdigest()}
                    for path, (value, mode) in sorted(self.files.items(), key=lambda item: item[0].encode())]
        self.assertEqual(result["files"], expected)
        self.assertEqual(result["inventory_sha256"], hashlib.sha256(update_metadata.canonical(expected)).hexdigest())
        self.assertEqual(result["total_bytes"], sum(len(data) for data, mode in self.files.values()))
        self.assertEqual(result["prefix"], self.prefix)
        self.assertEqual(result["version"], self.version)
        self.assertFalse((self.root / "EXECUTED").exists())
        self.assertEqual(list(self.parent.iterdir()), [])
        normalized = archive.validate_inventory(result)
        normalized["files"][0]["path"] = "changed"
        self.assertNotEqual(result["files"][0]["path"], "changed")

    def test_real_deterministic_release_builder_fixture_round_trip(self):
        repo = self.root / "repository"
        repo.mkdir()
        environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        environment.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
                           GIT_AUTHOR_DATE="2024-01-01T00:00:00+00:00", GIT_COMMITTER_DATE="2024-01-01T00:00:00+00:00")
        def git(*arguments):
            return subprocess.run(["git", "-C", str(repo), "-c", "user.name=Archive fixture",
                                   "-c", "user.email=archive@example.invalid", "-c", "commit.gpgsign=false", *arguments],
                                  env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, timeout=15, check=True)
        git("init", "-q", "-b", "main")
        for name, (data, mode) in self.files.items():
            path = repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(mode)
        git("add", "-A")
        git("commit", "-qm", "fixture")
        git("tag", "v" + self.version)
        built = release.build("HEAD", self.root / "first", "v" + self.version, repo=repo)
        release.build("HEAD", self.root / "second", "v" + self.version, repo=repo)
        data = (self.root / "first" / built["archive"]["name"]).read_bytes()
        self.assertEqual(data, (self.root / "second" / built["archive"]["name"]).read_bytes())
        manifest = self.manifest_for(data)
        result = archive.stage(data, manifest, self.parent)
        archive.validate_stage(result["directory"], result["inventory"])
        self.assertEqual(result["inventory"], archive.inspect_archive(self.data, self.manifest))
        self.assertFalse((self.root / "EXECUTED").exists())

    def test_snapshot_hash_size_manifest_types_and_candidate_version_guards(self):
        for value in (bytearray(self.data), memoryview(self.data), "archive"):
            with self.subTest(value=type(value).__name__):
                self.assert_bad(archive.inspect_archive, value, self.manifest)
        self.assert_bad(archive.inspect_archive, self.data, [])
        for field, value in (("version", "2.3.4.dev1"), ("version", None), ("version", "wrong"),
                             ("archive", []), ("archive", {})):
            manifest = copy.deepcopy(self.manifest)
            manifest[field] = value
            self.assert_bad(archive.inspect_archive, self.data, manifest)
        for field, values in {"name": ["other.tar.gz"], "size": [True, 0, -1, archive.MAX_ARCHIVE + 1],
                              "sha256": [None, "A" * 64, "z" * 64]}.items():
            for value in values:
                manifest = copy.deepcopy(self.manifest)
                manifest["archive"][field] = value
                self.assert_bad(archive.inspect_archive, self.data, manifest)
        for data in (self.data[:-1], self.data + b"changed", bytes([self.data[0] ^ 1]) + self.data[1:]):
            self.assert_bad(archive.inspect_archive, data, self.manifest, code="archive_mismatch")
        with patch.object(archive, "MAX_ARCHIVE", 10):
            manifest = copy.deepcopy(self.manifest)
            manifest["archive"]["size"] = 10
            self.assert_bad(archive.inspect_archive, self.data, manifest, code="archive_limits")

    def test_gzip_crc_truncation_concatenation_and_bounded_decompression(self):
        variants = [b"not a gzip", self.data[:-3], self.data + self.data,
                    self.data + b"trailing", self.data[:-1] + bytes([self.data[-1] ^ 1]),
                    self.data[:3] + b"\x08" + self.data[4:]]
        for data in variants:
            with self.subTest(length=len(data)):
                self.assert_bad(archive.inspect_archive, data, self.manifest_for(data), code="archive_invalid")
        with patch.object(archive, "MAX_TAR", 1024):
            self.assert_bad(archive.inspect_archive, self.data, self.manifest, code="archive_limits")
        self.assert_bad(self.inspect_raw, self.raw[:-1])

    def test_canonical_root_header_and_end_blocks_are_required(self):
        variants = [self.tar(root=False), self.tar(records=[]), self.raw + bytes(10240),
                    self.raw + self.raw, self.raw[:-1] + b"X"]
        for raw in variants:
            self.assert_bad(self.inspect_raw, raw)
        for arguments in ({"mode": 0o700}, {"mtime": 1}, {"uid": 1}, {"name": "other/"}):
            kwargs = {"name": self.prefix + "/", "mode": 0o755, "kind": tarfile.DIRTYPE, **arguments}
            self.assert_bad(self.inspect_raw, self.record(**kwargs) + self.raw[512:])
        # No final two zero blocks: the last header is truncated, not silently EOF.
        raw = self.raw[:512] + b"x" * (10240 - 512)
        self.assert_bad(self.inspect_raw, raw)
        self.assert_bad(self.inspect_raw, self.raw[:512] + b"\xff" * 512 + self.raw[1024:])

    def test_nonregular_members_modes_and_hidden_metadata_are_refused(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE,
                     tarfile.FIFOTYPE, tarfile.DIRTYPE, tarfile.GNUTYPE_SPARSE,
                     tarfile.GNUTYPE_LONGNAME, tarfile.XGLTYPE, b"V"):
            self.assert_bad(self.inspect_raw, self.tar(records=[self.record(self.prefix + "/unsafe", kind=kind)]))
        for kwargs in ({"mode": 0o600}, {"mode": 0o4755}, {"mode": 0o666}, {"uid": 1000},
                       {"gid": 1000}, {"uname": "owner"}, {"gname": "group"}, {"mtime": 10},
                       {"linkname": "elsewhere"}):
            self.assert_bad(self.inspect_raw, self.tar(records=[self.record(self.prefix + "/unsafe", **kwargs)]))

    def test_paths_traversal_controls_unicode_and_resource_limits(self):
        paths = ["../outside", "/absolute", "a//b", "a/./b", "a/../b", "", "a/", "a\\b",
                 "C:drive", ".git/config", "a/.GIT/config", "a.", "a ", "a\x00b", "a\nname",
                 "a\u202eb", "a\ufeffb"]
        for name in paths:
            with self.subTest(path=repr(name)):
                self.assert_bad(self.inspect_raw, self.tar(records=[self.record(self.prefix + "/" + name)]))
        self.assert_bad(self.inspect_raw, self.tar(records=[self.record("another-prefix/file")]))
        limits = {"MAX_FILES": 1, "MAX_FILE": 1, "MAX_TOTAL": 1, "MAX_PATH": 1,
                  "MAX_DEPTH": 1, "MAX_DIRECTORIES": 1, "MAX_INVENTORY": 1, "MAX_PAX": 1}
        for constant, value in limits.items():
            with self.subTest(limit=constant), patch.object(archive, constant, value):
                self.assert_bad(archive.inspect_archive, self.data, self.manifest, code="archive_limits")
        for name in ("a" * 256, "é" * 128):
            self.assert_bad(self.inspect_raw, self.tar(records=[self.record(self.prefix + "/" + name)]), code="archive_limits")

    def test_duplicate_order_file_parent_and_normalization_collisions(self):
        for names in (("duplicate", "duplicate"), ("z", "a"), ("a", "a/b"),
                      ("A", "a"), ("A/a", "a/b"), ("é", "e\u0301"), ("x/a", "X/b")):
            ordered = names if names == ("z", "a") else sorted(names, key=lambda value: value.encode())
            records = [self.record(self.prefix + "/" + name) for name in ordered]
            self.assert_bad(self.inspect_raw, self.tar(records=records))

    def test_pax_only_canonical_single_path_record_is_accepted(self):
        name = self.prefix + "/" + "long" * 40
        for headers in ({"path": "../../escape"}, {"path": name, "size": "0"},
                        {"path": name, "linkpath": "other"}, {"path": name, "GNU.sparse.map": "0,1"},
                        {"path": name, "mtime": "0"}, {"hdrcharset": "BINARY", "path": name},
                        {"path": self.prefix + "/short"}):
            self.assert_bad(self.inspect_raw, self.tar(records=[self.record(self.prefix + "/short", pax_headers=headers)]))
        # Hand-built physical PAX records exercise invalid lengths, encoding and dangling headers.
        for payload in (b"bad", b"0 path=abc\n", b"015 path=abc\n", b"12 path=abcX", b"12 path=\xff\n"):
            pax = self.record("././@PaxHeader", payload, mode=0, kind=tarfile.XHDTYPE)
            self.assert_bad(self.inspect_raw, self.tar(records=[pax, self.record(name)]))
        payload = b"path=" + name.encode() + b"\n"
        size = len(payload) + len(str(len(payload) + 4)) + 1
        payload = str(size).encode() + b" " + payload
        self.assertEqual(len(payload), size)
        pax = self.record("././@PaxHeader", payload, mode=0, kind=tarfile.XHDTYPE)
        self.assert_bad(self.inspect_raw, self.tar(records=[pax]))
        self.assert_bad(self.inspect_raw, self.tar(records=[pax, pax, self.record(name)]))
        # A correctly counted record with invalid UTF-8 is refused before name use.
        bad = b"10 path=\xff\n"
        self.assertEqual(len(bad), 10)
        self.assert_bad(self.inspect_raw, self.tar(records=[self.record("././@PaxHeader", bad, mode=0,
                                                                      kind=tarfile.XHDTYPE), self.record(name)]))

    def test_body_padding_truncation_and_header_size_limits(self):
        record = self.record(self.prefix + "/short", b"x")
        self.assert_bad(self.inspect_raw, self.tar(records=[record[:-1] + b"X"]))
        info = tarfile.TarInfo(self.prefix + "/large")
        info.size, info.mode = archive.MAX_FILE + 1, 0o644
        self.assert_bad(self.inspect_raw, self.tar(records=[info.tobuf(tarfile.PAX_FORMAT)]), code="archive_limits")
        info.size = len(self.raw) * 2
        self.assert_bad(self.inspect_raw, self.tar(records=[info.tobuf(tarfile.PAX_FORMAT)]))
        info.size = -1
        self.assert_bad(self.inspect_raw, self.tar(records=[info.tobuf(tarfile.GNU_FORMAT)]))

    def test_version_declaration_is_literal_matching_bounded_and_never_executed(self):
        values = [b"", b"__version__ =\n", b"raise RuntimeError('candidate must not run')\n",
                  b"x = '2.3.4rc1'\n", b"__version__ = '2.3.4'\n", b"__version__ = 1\n",
                  b"__version__ = str('2.3.4rc1')\n", b"__version__ = other = '2.3.4rc1'\n",
                  b"thing.__version__ = '2.3.4rc1'\n", b"__version__ = '2.3.4rc1'\npass\n",
                  b"__version__ = '\x00'\n", b"\xff", b"x" * (archive.MAX_METADATA + 1)]
        for value in values:
            files = dict(self.files)
            files["cgp_cert_manager/__init__.py"] = value, 0o644
            self.assert_bad(self.inspect_raw, self.tar(files), code="archive_metadata_invalid")
        files = dict(self.files)
        del files["cgp_cert_manager/__init__.py"]
        self.assert_bad(self.inspect_raw, self.tar(files), code="archive_metadata_invalid")
        self.assertFalse((self.root / "EXECUTED").exists())

    def test_distribution_metadata_and_plugin_registration_are_exact(self):
        values = {
            "/METADATA": [b"malformed header\n", b"Metadata-Version: 2.2\nName: cgp-certbot-dns\nVersion: 2.3.4rc1\n",
                          b"Metadata-Version: 2.1\nName: other\nVersion: 2.3.4rc1\n",
                          b"Metadata-Version: 2.1\nName: cgp-certbot-dns\nVersion: 2.3.4\n",
                          b"Metadata-Version: 2.1\nName: cgp-certbot-dns\nVersion: 2.3.4rc1\nVersion: 2.3.4rc1\n"],
            "/entry_points.txt": [b"invalid", b"[DEFAULT]\nextra = value\n[certbot.plugins]\n",
                                  b"[other]\n", b"[certbot.plugins]\ncgp-dns = malicious:Plugin\n",
                                  b"[certbot.plugins]\ncgp-dns = expected\ncgp-dns = duplicate\n"],
            "/top_level.txt": [b"other\n"]}
        for suffix, candidates in values.items():
            for value in candidates:
                files = dict(self.files)
                files[self.distribution + suffix] = value, 0o644
                self.assert_bad(self.inspect_raw, self.tar(files), code="archive_metadata_invalid")
        for name in (self.distribution + "/METADATA", self.distribution + "/entry_points.txt",
                     self.distribution + "/top_level.txt"):
            files = dict(self.files)
            del files[name]
            self.assert_bad(self.inspect_raw, self.tar(files), code="archive_metadata_invalid")
        files = dict(self.files)
        files["other.dist-info/METADATA"] = b"metadata", 0o644
        self.assert_bad(self.inspect_raw, self.tar(files), code="archive_metadata_invalid")

    def test_inventory_schema_types_digest_totals_and_paths_are_revalidated(self):
        good = archive.inspect_archive(self.data, self.manifest)
        for value in (None, [], {}, {**good, "extra": 1}):
            self.assert_bad(archive.validate_inventory, value)
        for field, values in {"version": ["2.3.4.dev1"], "prefix": [None, "other"], "files": [None, [], [None], [{}]],
                              "inventory_sha256": [None, "a" * 64], "total_bytes": [True, good["total_bytes"] + 1]}.items():
            for value in values:
                changed = copy.deepcopy(good)
                changed[field] = value
                self.assert_bad(archive.validate_inventory, changed)
        for field, values in {"path": [None, "\ud800", "../x"], "mode": [True, 0o600],
                              "size": [True, -1], "sha256": [None, "wrong"]}.items():
            for value in values:
                changed = copy.deepcopy(good)
                changed["files"][0][field] = value
                self.assert_bad(archive.validate_inventory, changed)

    def test_stage_is_unique_private_durable_and_preserves_modes_despite_umask(self):
        old = os.umask(0o277)
        try:
            first = self.prepared()
        finally:
            os.umask(old)
        second = self.prepared()
        self.assertNotEqual(first["directory"], second["directory"])
        self.assertRegex(first["directory"].name, r"^release-[a-z0-9_]{8}$")
        self.assertEqual(stat.S_IMODE(first["directory"].stat().st_mode), 0o700)
        self.assertEqual([path.name for path in first["directory"].iterdir()], [self.prefix])
        for path, (data, mode) in self.files.items():
            actual = first["directory"] / self.prefix / path
            self.assertEqual(actual.read_bytes(), data)
            self.assertEqual(stat.S_IMODE(actual.stat().st_mode), mode)
            self.assertEqual(actual.stat().st_nlink, 1)
        for path in first["directory"].rglob("*"):
            if path.is_dir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o755)
        archive.validate_stage(first["directory"], first["inventory"])
        self.assertFalse((self.root / "EXECUTED").exists())

    def test_stage_rejects_unsafe_parent_before_creating_any_child(self):
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        link = self.root / "link"
        link.symlink_to(outside, target_is_directory=True)
        for parent in (link, self.root / "absent", self.parent / ".." / "stages"):
            self.assert_bad(archive.stage, self.data, self.manifest, parent, code="archive_storage_error")
        self.parent.chmod(0o755)
        self.assert_bad(archive.stage, self.data, self.manifest, self.parent, code="archive_storage_error")
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(list(self.parent.iterdir()), [])
        self.assert_bad(archive.stage, self.data[:-1], self.manifest, self.parent, code="archive_mismatch")

    def test_partial_file_writes_complete_and_all_objects_are_fsynced(self):
        original_write, original_sync = os.write, os.fsync
        synced = []
        def partial(fd, data):
            return original_write(fd, data[:7])
        def sync(fd):
            synced.append((os.fstat(fd).st_ino, stat.S_ISDIR(os.fstat(fd).st_mode)))
            original_sync(fd)
        with patch.object(archive.os, "write", side_effect=partial), patch.object(archive.os, "fsync", side_effect=sync):
            result = self.prepared()
        archive.validate_stage(result["directory"], result["inventory"])
        expected = {path.stat().st_ino for path in result["directory"].rglob("*")}
        expected.update((result["directory"].stat().st_ino, self.parent.stat().st_ino))
        self.assertEqual({inode for inode, directory in synced}, expected)

    def test_stage_failure_cleans_only_new_child_and_interrupt_propagates(self):
        existing = self.prepared()
        for effect in (OSError("private diagnostic"), 0, KeyboardInterrupt()):
            with patch.object(archive.os, "write", side_effect=effect if isinstance(effect, BaseException) else None,
                              return_value=effect):
                if isinstance(effect, KeyboardInterrupt):
                    with self.assertRaises(KeyboardInterrupt):
                        self.prepared()
                else:
                    self.assert_bad(self.prepared, code="archive_storage_error")
            self.assertEqual(list(self.parent.iterdir()), [existing["directory"]])
        archive.validate_stage(existing["directory"], existing["inventory"])
        with patch.object(archive.secrets, "token_hex", side_effect=OSError("random source unavailable")):
            self.assert_bad(self.prepared, code="archive_storage_error")
        self.assertEqual(list(self.parent.iterdir()), [existing["directory"]])

    def test_fsync_failure_never_publishes_ready_and_cleanup_failure_is_visible(self):
        original = os.fsync
        calls = 0
        def fail_once(fd):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("sync failure")
            return original(fd)
        with patch.object(archive.os, "fsync", side_effect=fail_once):
            self.assert_bad(self.prepared, code="archive_storage_error")
        self.assertEqual(list(self.parent.iterdir()), [])
        with patch.object(archive.os, "write", side_effect=OSError("write failed")), \
                patch.object(archive.shutil, "rmtree", side_effect=OSError("cleanup failed")):
            self.assert_bad(self.prepared, code="archive_storage_error")
        leftovers = list(self.parent.iterdir())
        self.assertEqual(len(leftovers), 1)
        self.assertRegex(leftovers[0].name, r"^release-[a-z0-9_]{8}$")
        self.assertEqual(stat.S_IMODE(leftovers[0].stat().st_mode), 0o700)

    def test_validate_stage_rejects_extra_missing_modified_modes_links_and_specials(self):
        def change_file(path, operation):
            if operation in ("symlink", "fifo", "hardlink", "directory"):
                path.unlink()
            if operation == "symlink":
                path.symlink_to(self.root / "outside")
            elif operation == "fifo":
                os.mkfifo(path)
            elif operation == "hardlink":
                os.link(self.root / "outside", path)
            elif operation == "directory":
                path.mkdir()
            elif operation == "content":
                path.write_bytes(b"x" * path.stat().st_size)
            elif operation == "size":
                path.write_bytes(b"short")
            elif operation == "missing":
                path.unlink()
            elif operation == "mode":
                path.chmod(0o600)
        (self.root / "outside").write_bytes(self.files["README.md"][0])
        for operation in ("symlink", "fifo", "hardlink", "directory", "content", "size", "missing", "mode"):
            result = self.prepared()
            path = result["directory"] / self.prefix / "README.md"
            change_file(path, operation)
            with self.subTest(operation=operation):
                self.assert_bad(archive.validate_stage, result["directory"], result["inventory"])
        for operation in ("extra", "directory_mode", "root_mode", "linked_directory"):
            result = self.prepared()
            prefix = result["directory"] / self.prefix
            if operation == "extra":
                (prefix / "unexpected").write_text("extra")
            elif operation == "directory_mode":
                prefix.chmod(0o700)
            elif operation == "root_mode":
                result["directory"].chmod(0o500)
            else:
                shutil.rmtree(prefix / "docs")
                (prefix / "docs").symlink_to(self.root, target_is_directory=True)
            self.assert_bad(archive.validate_stage, result["directory"], result["inventory"])
        self.assertEqual((self.root / "outside").read_bytes(), self.files["README.md"][0])

    def test_validate_stage_file_owner_and_mutation_during_read_are_guarded(self):
        result = self.prepared()
        path = result["directory"] / self.prefix / "README.md"
        inode = path.stat().st_ino
        original_stat, original_read = os.fstat, os.read
        def wrong_owner(fd):
            info = original_stat(fd)
            if info.st_ino == inode:
                return SimpleNamespace(**{key: (info.st_uid + 1 if key == "st_uid" else getattr(info, key))
                                          for key in dir(info) if key.startswith("st_")})
            return info
        with patch.object(archive.os, "fstat", side_effect=wrong_owner):
            self.assert_bad(archive.validate_stage, result["directory"], result["inventory"])
        for operation in ("grow", "shrink", "mtime"):
            path.write_bytes(self.files["README.md"][0])
            changed = False
            def changed_read(fd, size):
                nonlocal changed
                if not changed and original_stat(fd).st_ino == inode:
                    changed = True
                    if operation == "grow":
                        path.write_bytes(self.files["README.md"][0] + b"extra")
                    elif operation == "shrink":
                        path.write_bytes(b"")
                    else:
                        before = path.stat()
                        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 1000000000))
                return original_read(fd, size)
            with patch.object(archive.os, "read", side_effect=changed_read):
                self.assert_bad(archive.validate_stage, result["directory"], result["inventory"])

    def test_stage_creation_cannot_follow_retargeted_parent(self):
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        displaced = self.root / "original-stages"
        mkdir = os.mkdir
        changed = False
        def retarget(name, mode=0o777, **kwargs):
            nonlocal changed
            if not changed and str(name).startswith("release-"):
                changed = True
                self.parent.rename(displaced)
                self.parent.symlink_to(outside, target_is_directory=True)
            return mkdir(name, mode, **kwargs)
        with patch.object(archive.os, "mkdir", side_effect=retarget):
            self.assert_bad(self.prepared, code="archive_storage_error")
        self.assertTrue(changed)
        self.assertEqual(list(outside.iterdir()), [])
        held = list(displaced.iterdir())
        self.assertEqual(len(held), 1)
        self.assertEqual(stat.S_IMODE(held[0].stat().st_mode), 0o700)
        self.assertTrue((held[0] / self.prefix).is_dir())

    def test_failure_cleanup_does_not_remove_same_name_in_retargeted_parent(self):
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        displaced = self.root / "original-stages"
        decoys = []
        def fail_after_retarget(fd, data):
            original = next(self.parent.iterdir())
            self.parent.rename(displaced)
            self.parent.symlink_to(outside, target_is_directory=True)
            decoy = outside / original.name
            decoy.mkdir(mode=0o700)
            (decoy / "unrelated").write_text("independent evidence")
            decoys.append(decoy)
            raise OSError("write failed after parent replacement")
        with patch.object(archive.os, "write", side_effect=fail_after_retarget):
            self.assert_bad(self.prepared, code="archive_storage_error")
        self.assertEqual((decoys[0] / "unrelated").read_text(), "independent evidence")
        self.assertTrue((displaced / decoys[0].name).is_dir())

    def test_success_rechecks_parent_and_named_child_identity_without_deleting_replacements(self):
        for replacement in ("parent", "child", "child_mode"):
            with self.subTest(replacement=replacement):
                parent = self.root / replacement
                parent.mkdir(mode=0o700)
                parent_inode = parent.stat().st_ino
                sync = os.fsync
                changed = False
                evidence = {}
                def retarget_on_parent_sync(fd):
                    nonlocal changed
                    if not changed and os.fstat(fd).st_ino == parent_inode:
                        changed = True
                        original = next(parent.iterdir())
                        evidence["name"] = original.name
                        if replacement == "parent":
                            displaced = self.root / (replacement + "-held")
                            parent.rename(displaced)
                            parent.mkdir(mode=0o700)
                            (parent / "unrelated").write_text("preserve parent replacement")
                            evidence["sentinel"] = parent / "unrelated"
                            evidence["held"] = displaced / original.name
                        elif replacement == "child":
                            displaced = parent / "held-child"
                            original.rename(displaced)
                            original.mkdir(mode=0o700)
                            (original / "unrelated").write_text("preserve child replacement")
                            evidence["sentinel"] = original / "unrelated"
                            evidence["held"] = displaced
                        else:
                            original.chmod(0o500)
                            evidence["held"] = original
                    return sync(fd)
                with patch.object(archive.os, "fsync", side_effect=retarget_on_parent_sync):
                    self.assert_bad(archive.stage, self.data, self.manifest, parent, code="archive_storage_error")
                self.assertTrue(changed)
                self.assertTrue((evidence["held"] / self.prefix).is_dir())
                if "sentinel" in evidence:
                    self.assertTrue(evidence["sentinel"].read_text().startswith("preserve"))

    def test_creation_collisions_are_bounded_and_existing_children_remain_untouched(self):
        existing = self.parent / "release-aaaaaaaa"
        existing.mkdir(mode=0o700)
        (existing / "sentinel").write_text("untouched")
        with patch.object(archive.secrets, "token_hex", side_effect=["aaaaaaaa", "bbbbbbbb"]):
            result = self.prepared()
        self.assertEqual(result["directory"].name, "release-bbbbbbbb")
        archive.validate_stage(result["directory"], result["inventory"])
        with patch.object(archive.secrets, "token_hex", return_value="aaaaaaaa") as choose, \
                patch.object(archive, "MAX_STAGE_ATTEMPTS", 3):
            self.assert_bad(self.prepared, code="archive_storage_error")
        self.assertEqual(choose.call_count, 3)
        self.assertEqual((existing / "sentinel").read_text(), "untouched")
        self.assertEqual({path.name for path in self.parent.iterdir()}, {"release-aaaaaaaa", "release-bbbbbbbb"})

    def test_unidentified_child_is_preserved_and_replacement_between_stat_and_open_is_refused(self):
        original_stat = os.stat
        def failed_stat(name, *args, **kwargs):
            if str(name).startswith("release-"):
                raise OSError("cannot identify newly created child")
            return original_stat(name, *args, **kwargs)
        with patch.object(archive.os, "stat", side_effect=failed_stat):
            self.assert_bad(self.prepared, code="archive_storage_error")
        unknown = next(self.parent.iterdir())
        self.assertEqual(list(unknown.iterdir()), [])
        self.assertEqual(stat.S_IMODE(unknown.stat().st_mode), 0o700)
        original_open = os.open
        changed = False
        evidence = {}
        def changed_open(name, flags, mode=0o777, **kwargs):
            nonlocal changed
            if not changed and str(name).startswith("release-"):
                changed = True
                original = self.parent / name
                original.rename(self.parent / "held-child")
                original.mkdir(mode=0o700)
                (original / "unrelated").write_text("independent directory")
                evidence["path"] = original
            return original_open(name, flags, mode, **kwargs)
        with patch.object(archive.os, "open", side_effect=changed_open):
            self.assert_bad(self.prepared, code="archive_storage_error")
        self.assertEqual((evidence["path"] / "unrelated").read_text(), "independent directory")
        self.assertEqual(list((self.parent / "held-child").iterdir()), [])


if __name__ == "__main__":
    unittest.main()
