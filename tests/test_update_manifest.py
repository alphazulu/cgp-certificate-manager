"""Unsigned publisher manifests describe exact reviewed bytes without signing."""
from contextlib import redirect_stderr, redirect_stdout
import base64
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cgp_cert_manager import storage, update_metadata as metadata
from repo_tools import update_manifest as publisher


class UpdateManifestTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.version = "2.3.4"
        self.prefix = metadata.PROJECT + "-v" + self.version
        distribution = "cgp_certbot_dns-" + self.version + ".dist-info/"
        files = {
            "cgp_cert_manager/__init__.py": "__version__ = '" + self.version + "'\n",
            distribution + "METADATA": "Metadata-Version: 2.1\nName: cgp-certbot-dns\nVersion: " + self.version + "\n",
            distribution + "entry_points.txt": "[certbot.plugins]\ncgp-dns = cgp_cert_manager.certbot_dns:Authenticator\n",
            distribution + "top_level.txt": "cgp_cert_manager\n",
            "install.sh": "#!/bin/sh\ntouch '" + str(self.root / "EXECUTED") + "'\n",
        }
        output = io.BytesIO()
        with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as package:
                root = tarfile.TarInfo(self.prefix + "/")
                root.type, root.mode = tarfile.DIRTYPE, 0o755
                package.addfile(root)
                for path, content in sorted(files.items()):
                    data = content.encode()
                    info = tarfile.TarInfo(self.prefix + "/" + path)
                    info.size, info.mode = len(data), 0o755 if path == "install.sh" else 0o644
                    package.addfile(info, io.BytesIO(data))
        self.archive = output.getvalue()
        self.provenance = {
            "schema": 1, "commit": "a" * 40, "tree": "b" * 40, "version": self.version,
            "release_tag": "v" + self.version, "prefix": self.prefix,
            "archive": {"name": self.prefix + ".tar.gz", "size": len(self.archive),
                        "sha256": hashlib.sha256(self.archive).hexdigest()},
        }
        self.arguments = {"channel": "stable", "sequence": 7,
                          "issued_at": 1700000000, "expires_at": 1700003600}
        self.provenance_path = self.root / "release.provenance.json"
        self.archive_path = self.root / "release.tar.gz"
        self.provenance_path.write_bytes(metadata.canonical(self.provenance))
        self.archive_path.write_bytes(self.archive)
        self.provenance_path.chmod(0o644)
        self.archive_path.chmod(0o600)
        self.argv = ["--provenance", str(self.provenance_path), "--archive", str(self.archive_path),
                     "--channel", "stable", "--sequence", "7", "--issued-at", "1700000000",
                     "--expires-at", "1700003600"]

    def create(self, provenance=None, archive=None, **overrides):
        return publisher.create(metadata.canonical(self.provenance if provenance is None else provenance),
                                self.archive if archive is None else archive, **(self.arguments | overrides))

    def test_exact_canonical_output_is_unsigned_and_has_no_side_effects(self):
        before = {path.name: path.read_bytes() for path in self.root.iterdir()}
        with patch.object(subprocess, "run", side_effect=AssertionError("no execution")), \
                patch.object(socket, "create_connection", side_effect=AssertionError("no network")), \
                patch.object(metadata, "_verify", side_effect=AssertionError("no signing or authentication")), \
                patch.object(storage, "atomic_json", side_effect=AssertionError("no writes")):
            output = self.create()
        manifest = json.loads(output)
        expected = {
            "schema": 1, "project": metadata.PROJECT, "version": self.version,
            **self.arguments,
            "source": {"repository": metadata.REPOSITORY, "commit": "a" * 40,
                       "tree": "b" * 40, "tag": "v" + self.version},
            "archive": self.provenance["archive"],
        }
        self.assertEqual(manifest, expected)
        self.assertEqual(output, metadata.canonical(expected))
        self.assertNotIn("signature", manifest)
        self.assertNotIn("keys", manifest)
        self.assertEqual({path.name: path.read_bytes() for path in self.root.iterdir()}, before)

    def test_real_release_builder_provenance_round_trip(self):
        import test_release
        fixture = test_release.ReleaseTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.prepare("2.3.4rc1")
        fixture.save()
        fixture.git("tag", "v2.3.4rc1")
        provenance = fixture.build(release_tag="v2.3.4rc1")
        archive = (fixture.root / "dist" / provenance["archive"]["name"]).read_bytes()
        source = (fixture.root / "dist" / (provenance["prefix"] + ".provenance.json")).read_bytes()
        output = publisher.create(source, archive, **(self.arguments | {"channel": "candidate"}))
        result = json.loads(output)
        self.assertEqual(result["version"], "2.3.4rc1")
        self.assertEqual(result["source"]["commit"], provenance["commit"])
        self.assertEqual(result["archive"]["sha256"], hashlib.sha256(archive).hexdigest())

    def test_provenance_requires_exact_schema_and_explicit_release_tag(self):
        invalid = [[], None, {}, self.provenance | {"schema": True}, self.provenance | {"schema": 2},
                   self.provenance | {"unexpected": "reject"}, self.provenance | {"release_tag": None},
                   self.provenance | {"release_tag": "v9.9.9"}, self.provenance | {"prefix": "elsewhere"},
                   {key: value for key, value in self.provenance.items() if key != "archive"}]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(metadata.UpdateError):
                publisher.create(metadata.canonical(value), self.archive, **self.arguments)
        for value in (b"", b"{", b'{"schema":1,"schema":1}', b"x" * (metadata.MAX_MANIFEST + 1)):
            with self.subTest(raw=value[:20]), self.assertRaises(metadata.UpdateError):
                publisher.create(value, self.archive, **self.arguments)

    def test_version_identity_channel_sequence_and_time_are_validated_before_inspection(self):
        invalid = [self.provenance | {"version": "2.3.4.dev1"}, self.provenance | {"version": []},
                   self.provenance | {"commit": "a" * 39}, self.provenance | {"tree": "B" * 40},
                   self.provenance | {"archive": self.provenance["archive"] | {"size": True}}]
        with patch.object(publisher.update_archive, "inspect_archive") as inspect:
            for value in invalid:
                with self.subTest(value=value), self.assertRaises(metadata.UpdateError):
                    self.create(provenance=value)
            for options in ({"channel": "preview"}, {"sequence": True}, {"sequence": -1},
                            {"expires_at": self.arguments["issued_at"]}, {"issued_at": float("nan")},
                            {"expires_at": self.arguments["issued_at"] + metadata.MAX_VALIDITY + 1}):
                with self.subTest(options=options), self.assertRaises(metadata.UpdateError):
                    self.create(**options)
            inspect.assert_not_called()

    def test_payload_must_match_size_hash_and_safe_archive_contract(self):
        for data in (self.archive + b"changed", bytes([self.archive[0] ^ 1]) + self.archive[1:]):
            with self.subTest(size=len(data)), self.assertRaises(metadata.UpdateError) as caught:
                self.create(archive=data)
            self.assertEqual(caught.exception.code, "archive_mismatch")
        provenance = copy.deepcopy(self.provenance)
        payload = b"not a tar archive"
        provenance["archive"].update(size=len(payload), sha256=hashlib.sha256(payload).hexdigest())
        with self.assertRaises(metadata.UpdateError) as caught:
            self.create(provenance=provenance, archive=payload)
        self.assertEqual(caught.exception.code, "archive_invalid")
        self.assertFalse((self.root / "EXECUTED").exists())

    def test_bounded_reader_accepts_private_and_public_regular_files_without_changes(self):
        for path in (self.provenance_path, self.archive_path):
            before = path.stat()
            self.assertEqual(publisher._read(path, before.st_size), path.read_bytes())
            after = path.stat()
            self.assertEqual((after.st_ino, after.st_mode, after.st_mtime_ns),
                             (before.st_ino, before.st_mode, before.st_mtime_ns))

    def test_bounded_reader_refuses_traversal_symlinks_fifo_empty_large_and_writable_files(self):
        link = self.root / "link"
        link.symlink_to(self.provenance_path)
        fifo = self.root / "fifo"
        os.mkfifo(fifo, 0o600)
        empty = self.root / "empty"
        empty.touch(mode=0o600)
        writable = self.root / "writable"
        writable.write_bytes(b"x")
        writable.chmod(0o666)
        special = self.root / "special-mode"
        special.write_bytes(b"x")
        special.chmod(0o4600)
        linked = self.root / "hardlinked"
        os.link(self.archive_path, linked)
        parent_link = self.root / "parent-link"
        parent_link.symlink_to(self.root, target_is_directory=True)
        cases = [(Path("/"), 100), (self.root / ".." / self.root.name / "release.provenance.json", 10000),
                 (link, 10000), (fifo, 100), (empty, 100), (writable, 100), (special, 100),
                 (linked, 10000), (self.provenance_path, 1), (self.root, 10000),
                 (parent_link / self.provenance_path.name, 10000)]
        for path, limit in cases:
            with self.subTest(path=path), self.assertRaises((metadata.UpdateError, storage.StorageError, OSError)):
                publisher._read(path, limit)

    def test_bounded_reader_refuses_foreign_owner_and_changed_snapshot(self):
        original = self.provenance_path.stat()
        fields = {name: getattr(original, name) for name in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid",
                                                            "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")}
        changed = SimpleNamespace(**(fields | {"st_mtime_ns": fields["st_mtime_ns"] + 1}))
        real_fstat = os.fstat
        observed = []

        def changing_file(descriptor):
            info = real_fstat(descriptor)
            if stat.S_ISREG(info.st_mode):
                observed.append(descriptor)
                return original if len(observed) == 1 else changed
            return info

        with patch.object(publisher.os, "fstat", side_effect=changing_file), self.assertRaises(metadata.UpdateError) as caught:
            publisher._read(self.provenance_path, 10000)
        self.assertEqual(caught.exception.code, "input_changed")
        for change in ({"st_uid": os.geteuid() + 10000}, {"st_size": original.st_size + 1}):
            def invalid_file(descriptor):
                info = real_fstat(descriptor)
                return SimpleNamespace(**(fields | change)) if stat.S_ISREG(info.st_mode) else info

            with self.subTest(change=change), patch.object(publisher.os, "fstat", side_effect=invalid_file), \
                    self.assertRaises(metadata.UpdateError):
                publisher._read(self.provenance_path, 10000)

    def test_failed_stream_construction_closes_its_descriptor(self):
        captured = []

        def failed(descriptor, mode):
            captured.append(descriptor)
            raise OSError("synthetic stream failure")

        with patch.object(publisher.os, "fdopen", side_effect=failed), self.assertRaises(OSError):
            publisher._read(self.provenance_path, 10000)
        self.assertEqual(len(captured), 1)
        with self.assertRaises(OSError):
            os.fstat(captured[0])

    def test_cli_emits_only_canonical_manifest_and_safe_errors(self):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            self.assertEqual(publisher.main(self.argv), 0)
        self.assertEqual(output.getvalue().encode(), self.create())
        self.assertEqual(errors.getvalue(), "")
        for error in (metadata.UpdateError("private-sensitive-detail"), OSError("credential-secret"),
                      storage.StorageError("private-path"), ValueError("embedded-null")):
            output, errors = io.StringIO(), io.StringIO()
            with patch.object(publisher, "_read", side_effect=error), redirect_stdout(output), redirect_stderr(errors):
                self.assertEqual(publisher.main(self.argv), 2)
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(errors.getvalue(), "Cannot assemble update manifest: invalid or unreadable release artifacts\n")

    def test_cli_parser_and_module_entrypoint_never_create_artifacts(self):
        with patch.object(publisher, "_read") as read:
            for arguments, expected in ((["--help"], 0), ([], 2), (self.argv + ["--sequence", "text"], 2)):
                with self.subTest(arguments=arguments), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()), \
                        self.assertRaises(SystemExit) as exited:
                    publisher.main(arguments)
                self.assertEqual(exited.exception.code, expected)
            read.assert_not_called()
        before = {path.name: path.read_bytes() for path in self.root.iterdir()}
        output = io.StringIO()
        with patch.dict(sys.modules), patch.object(sys, "argv", ["update_manifest", *self.argv]), redirect_stdout(output), \
                self.assertRaises(SystemExit) as exited:
            sys.modules.pop("repo_tools.update_manifest", None)
            runpy.run_module("repo_tools.update_manifest", run_name="__main__")
        self.assertEqual(exited.exception.code, 0)
        self.assertEqual(output.getvalue().encode(), self.create())
        self.assertEqual({path.name: path.read_bytes() for path in self.root.iterdir()}, before)

    def test_publisher_signature_and_real_cli_prepare_status_round_trip(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from cgp_cert_manager import update_cli, update_plan

        # Synthetic RFC 8032 test material, never a production signing key.
        key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
        public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        key_id = hashlib.sha256(public).hexdigest()
        manifest = self.create()
        manifest_path, signature_path, trust_path = (self.root / name for name in
                                                     ("manifest.json", "signature.json", "trust.json"))
        manifest_path.write_bytes(manifest)
        signature_path.write_bytes(metadata.canonical({
            "schema": 1, "key_id": key_id,
            "signature": base64.b64encode(key.sign(metadata.DOMAIN + manifest)).decode("ascii")}))
        trust_path.write_bytes(metadata.canonical({"schema": 1, "project": metadata.PROJECT, "channel": "stable",
                                                  "keys": {key_id: base64.b64encode(public).decode("ascii")}}))
        trust_path.chmod(0o600)
        installed, state = self.root / "installed", self.root / "update-state"
        (installed / "cgp_cert_manager").mkdir(parents=True)
        version = installed / "cgp_cert_manager" / "__init__.py"
        version.write_text("__version__ = '2.1.0'\n")
        common = ["--trust-file", str(trust_path), "--installed-root", str(installed),
                  "--state-dir", str(state), "--json"]
        artifacts = ["--manifest", str(manifest_path), "--signature", str(signature_path),
                     "--archive", str(self.archive_path)]

        def invoke(*arguments):
            output, errors = io.StringIO(), io.StringIO()
            with redirect_stdout(output), redirect_stderr(errors):
                code = update_cli.main([*arguments, *common])
            self.assertEqual(errors.getvalue(), "")
            return code, json.loads(output.getvalue())

        with patch.object(update_plan.time, "time", return_value=self.arguments["issued_at"] + 1), \
                patch.object(subprocess, "run", side_effect=AssertionError("candidate must not execute")), \
                patch.object(socket, "create_connection", side_effect=AssertionError("offline only")):
            code, checked = invoke("--check", *artifacts)
            self.assertEqual((code, checked["status"]), (0, "verified"))
            self.assertFalse(state.exists())
            code, prepared = invoke("--prepare", *artifacts)
            self.assertEqual((code, prepared["status"]), (0, "prepared"))
            self.assertEqual(prepared["plan"]["plan_id"], checked["plan"]["plan_id"])
            self.assertEqual(prepared["plan"]["installed_version"], "2.1.0")
            self.assertEqual(prepared["plan"]["target_version"], self.version)
            self.assertIs(prepared["plan"]["apply_supported"], False)
            for path in (manifest_path, signature_path, self.archive_path):
                path.unlink()
            code, status = invoke("--status")
            self.assertEqual((code, status["status"]), (0, "prepared"))
            self.assertEqual(status["plan"], prepared["plan"])
            saved = (state / "checkpoint.json").read_bytes()
            with patch.object(update_plan.time, "time", return_value=self.arguments["expires_at"]):
                code, expired = invoke("--status")
            self.assertEqual((code, expired["status"], expired["error"]), (2, "expired", "expired_manifest"))
            self.assertIsNone(expired["plan"])
            self.assertEqual((state / "checkpoint.json").read_bytes(), saved)
        self.assertFalse((self.root / "EXECUTED").exists())
        self.assertEqual(version.read_text(), "__version__ = '2.1.0'\n")
        self.assertNotIn(str(self.root), json.dumps(prepared))
        self.assertNotIn(base64.b64encode(public).decode("ascii"), json.dumps(prepared))
