"""Deterministic archives and release context guards use temporary Git objects."""
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from repo_tools import release


@contextmanager
def working_directory(path):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "-q", "-b", "main")
        self.version = "2.3.4.dev5"
        self.prepare()
        self.commit = self.save()

    def git(self, *arguments, data=None, repo=None):
        environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                           GIT_AUTHOR_DATE="2024-01-01T00:00:00+00:00", GIT_COMMITTER_DATE="2024-01-01T00:00:00+00:00")
        return subprocess.run(["git", "-C", str(repo or self.repo), "-c", "user.name=Release fixture",
                               "-c", "user.email=release@example.invalid", "-c", "commit.gpgsign=false",
                               *arguments], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              check=True, timeout=15, env=environment).stdout

    def write(self, name, data):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)
        return path

    @property
    def distribution(self):
        return "cgp_certbot_dns-" + self.version + ".dist-info"

    def prepare(self, version=None):
        if version is not None:
            self.version = version
        for directory in self.repo.glob("*.dist-info"):
            shutil.rmtree(directory)
        self.write("cgp_cert_manager/__init__.py", "__version__ = " + repr(self.version) + "\n")
        self.write(self.distribution + "/METADATA", "Metadata-Version: 2.1\nName: cgp-certbot-dns\nVersion: "
                   + self.version + "\nSummary: Fixture\nRequires-Dist: certbot>=2.9\n\nDescription.\n")
        self.write(self.distribution + "/entry_points.txt", "[certbot.plugins]\ncgp-dns = cgp_cert_manager.certbot_dns:Authenticator\n")
        self.write(self.distribution + "/top_level.txt", "cgp_cert_manager\n")
        self.write("install.sh", "#!/bin/sh\nexit 0\n").chmod(0o755)
        self.write("README.md", "Committed documentation: café.\n")
        self.write("binary.dat", bytes(range(256)))
        self.write("docs/" + "long-" * 30 + "/unicode-ёж.txt", "UTF-8 path\n")
        self.write(".gitattributes", "README.md export-ignore\nbinary.dat export-subst\n")

    def save(self):
        self.git("add", "-A")
        self.git("commit", "-qm", "fixture", "--allow-empty")
        return self.git("rev-parse", "HEAD").decode().strip()

    def build(self, output="dist", **kwargs):
        return release.build("HEAD", self.root / output, repo=self.repo, **kwargs)

    def assert_no_output(self):
        self.assertFalse((self.root / "dist").exists())

    def test_reproducible_archive_manifest_modes_and_dirty_workspace_excluded(self):
        first = self.build("first")
        expected = {entry.path: self.git("show", self.commit + ":" + entry.path)
                    for entry in release._entries(self.repo, self.commit)}
        self.write("cgp_cert_manager/__init__.py", "raise RuntimeError('working copy must not run')\n")
        self.write(self.distribution + "/METADATA", "INVALID WORKING METADATA\n")
        self.write("README.md", "dirty and staged\n")
        self.git("add", "README.md")
        self.write("untracked.txt", "not committed\n")
        (self.repo / "install.sh").chmod(0o600)
        second = self.build("second")
        self.assertEqual(first, second)
        for path in (self.root / "first").iterdir():
            self.assertEqual(path.read_bytes(), (self.root / "second" / path.name).read_bytes())
        archive_name = "cgp-certificate-manager-v" + self.version + ".tar.gz"
        archive = self.root / "first" / archive_name
        compressed = archive.read_bytes()
        self.assertEqual(compressed[4:8], b"\0" * 4)
        self.assertEqual(compressed[3] & 8, 0, "gzip must not include an output filename")
        self.assertEqual(first["archive"], {"name": archive_name, "size": len(compressed),
                                          "sha256": hashlib.sha256(compressed).hexdigest()})
        self.assertEqual(first["commit"], self.commit)
        self.assertEqual(first["tree"], self.git("rev-parse", self.commit + "^{tree}").decode().strip())
        self.assertEqual(first["version"], self.version)
        self.assertIsNone(first["release_tag"])
        self.assertEqual(set(first), {"schema", "commit", "tree", "version", "release_tag", "prefix", "archive"})
        self.assertEqual(json.loads((archive.parent / (first["prefix"] + ".provenance.json")).read_text()), first)
        self.assertEqual((archive.parent / (archive_name + ".sha256")).read_text(), first["archive"]["sha256"] + "  " + archive_name + "\n")
        with tarfile.open(archive, "r:gz") as package:
            members = package.getmembers()
            self.assertEqual(members[0].name, first["prefix"])
            self.assertTrue(members[0].isdir())
            self.assertEqual([member.name for member in members[1:]],
                             [first["prefix"] + "/" + path for path in sorted(expected, key=lambda value: value.encode())])
            for member in members:
                self.assertEqual((member.uid, member.gid, member.uname, member.gname, member.mtime), (0, 0, "", "", 0))
                self.assertTrue(member.isfile() or member.isdir())
                if member.isfile():
                    path = member.name.removeprefix(first["prefix"] + "/")
                    self.assertEqual(package.extractfile(member).read(), expected[path])
                    self.assertEqual(member.mode, 0o755 if path == "install.sh" else 0o644)

    def test_release_and_candidate_existing_tags_are_checked_and_read_only(self):
        for version, annotated in (("2.3.4", False), ("2.3.5rc1", True)):
            with self.subTest(version=version):
                self.prepare(version)
                commit = self.save()
                tag = "v" + version
                self.git("tag", *( ["-a", "-m", "fixture"] if annotated else []), tag)
                self.write("later.txt", version)
                main = self.save()
                self.git("update-ref", "refs/remotes/origin/main", main)
                files_before = {path.relative_to(self.repo): path.read_bytes()
                                for path in self.repo.rglob("*") if path.is_file()}
                result = release.validate(commit, tag, commit, "origin/main", repo=self.repo)
                files_after = {path.relative_to(self.repo): path.read_bytes()
                               for path in self.repo.rglob("*") if path.is_file()}
                self.assertEqual(files_before, files_after)
                self.assertEqual(result["commit"], commit)
                self.assertEqual(result["release_tag"], tag)
                self.assertEqual(result["version"], version)
                output = self.root / version
                self.assertEqual(release.build(commit, output, tag, commit, "origin/main", repo=self.repo)["commit"], commit)

    def test_release_context_refuses_wrong_identity_or_non_main_commit(self):
        before = self.commit
        self.prepare("2.3.4")
        commit = self.save()
        self.git("tag", "v2.3.4")
        cases = [
            {"expected_commit": commit}, {"main_ref": "main"},
            {"expected_commit": commit, "main_ref": "main", "release_tag": None},
            {"expected_commit": "short", "main_ref": "main"},
            {"expected_commit": 1, "main_ref": "main"},
            {"expected_commit": before, "main_ref": "main"},
            {"expected_commit": commit, "main_ref": before},
        ]
        for case in cases:
            options = {"release_tag": "v2.3.4", **case}
            with self.subTest(options=options), self.assertRaises(release.ReleaseError):
                self.build(**options)
            self.assert_no_output()

    def test_release_tags_cannot_be_missing_mismatched_development_or_local_versions(self):
        for tag in ("v2.3.4.dev5", "v2.3.4+private", "2.3.4", "v2.3.04", "v2.3.4", 1):
            with self.subTest(tag=tag), self.assertRaises(release.ReleaseError):
                self.build(release_tag=tag)
            self.assert_no_output()
        self.prepare("2.3.4")
        commit = self.save()
        with self.assertRaises(release.ReleaseError):
            self.build(release_tag="v2.3.4")
        self.git("tag", "v2.3.4")
        self.write("another.txt", "different exact commit, same version\n")
        self.save()
        with self.assertRaisesRegex(release.ReleaseError, "does not identify"):
            self.build(release_tag="v2.3.4")
        self.assertEqual(release.validate(commit, "v2.3.4", repo=self.repo)["commit"], commit)
        self.assert_no_output()

    def test_application_version_is_a_literal_and_candidate_code_never_runs(self):
        marker = self.root / "executed"
        declarations = [
            "", "__version__ =", "__version__: str = '2.3.4'", "a = __version__ = '2.3.4'",
            "(__version__,) = ('2.3.4',)", "version = '2.3.4'", "__version__ = 1",
            "__version__ = '2.3.4'\n__version__ = '2.3.5'",
            "__version__ = __import__('pathlib').Path(" + repr(str(marker)) + ").write_text('executed')",
            "__version__ = " + repr("1" * 65),
            *["__version__ = " + repr(value) for value in ("2.3", "2.3.4+local", "02.3.4", "2.3.4rc01", "2.3.4a1")],
        ]
        for declaration in declarations:
            self.write("cgp_cert_manager/__init__.py", declaration)
            self.save()
            with self.subTest(declaration=declaration), self.assertRaises(release.ReleaseError):
                self.build()
            self.assertFalse(marker.exists())
            self.assert_no_output()

    def test_required_distribution_files_and_unique_version_directory(self):
        for missing in ("cgp_cert_manager/__init__.py", self.distribution + "/METADATA",
                        self.distribution + "/entry_points.txt", self.distribution + "/top_level.txt"):
            self.prepare()
            (self.repo / missing).unlink()
            self.save()
            with self.subTest(missing=missing), self.assertRaisesRegex(release.ReleaseError, "missing"):
                self.build()
        self.prepare()
        (self.repo / self.distribution).rename(self.repo / "cgp_certbot_dns-1.0.0.dist-info")
        self.save()
        with self.assertRaisesRegex(release.ReleaseError, "does not match"):
            self.build()
        self.prepare()
        self.write("extra-1.0.dist-info/METADATA", "Version: 1.0\n")
        self.save()
        with self.assertRaisesRegex(release.ReleaseError, "does not match"):
            self.build()
        self.assert_no_output()

    def test_malformed_duplicate_or_wrong_distribution_headers_are_rejected(self):
        good = (self.repo / self.distribution / "METADATA").read_text()
        for text in ("not a header\n" + good,
                     good.replace("Metadata-Version: 2.1", "Metadata-Version: 2.4"),
                     good.replace("Name: cgp-certbot-dns", "Name: foreign-package"),
                     good.replace("Version: " + self.version, "Version: 9.9.9"),
                     "Name: cgp-certbot-dns\n" + good,
                     "Version: " + self.version + "\n" + good):
            self.write(self.distribution + "/METADATA", text)
            self.save()
            with self.subTest(text=text), self.assertRaisesRegex(release.ReleaseError, "distribution metadata"):
                self.build()
            self.assert_no_output()

    def test_plugin_registration_must_identify_exact_app_local_authenticator(self):
        examples = ["bad syntax\n", "[certbot.plugins]\ncgp-dns=x\ncgp-dns=y\n",
                    "[DEFAULT]\nextra=x\n[certbot.plugins]\ncgp-dns=cgp_cert_manager.certbot_dns:Authenticator\n",
                    "[foreign]\ncgp-dns=cgp_cert_manager.certbot_dns:Authenticator\n",
                    "[certbot.plugins]\ncgp-dns=foreign.module:Authenticator\n"]
        for text in examples:
            self.write(self.distribution + "/entry_points.txt", text)
            self.save()
            with self.subTest(text=text), self.assertRaisesRegex(release.ReleaseError, "plugin registration"):
                self.build()
        self.prepare()
        self.write(self.distribution + "/top_level.txt", "foreign\n")
        self.save()
        with self.assertRaisesRegex(release.ReleaseError, "plugin registration"):
            self.build()
        self.assert_no_output()

    def test_metadata_decode_null_and_size_limits_are_safe(self):
        for value in (b"\xff", b"Summary: private\x00text", b"x" * (release.MAX_METADATA + 1)):
            with self.subTest(length=len(value)), self.assertRaisesRegex(release.ReleaseError, "^Invalid release metadata$"):
                release._text(value)
        self.assertEqual(release._text(b"x" * release.MAX_METADATA), "x" * release.MAX_METADATA)

    def test_real_symlink_and_gitlink_are_refused(self):
        outside = self.root / "outside"
        outside.write_text("private outside file")
        (self.repo / "unsafe-link").symlink_to(outside)
        self.save()
        with self.assertRaises(release.ReleaseError):
            self.build()
        self.assert_no_output()
        self.git("rm", "unsafe-link")
        self.git("update-index", "--add", "--cacheinfo", "160000," + self.commit + ",vendor")
        self.git("commit", "-qm", "gitlink fixture")
        with self.assertRaises(release.ReleaseError):
            self.build()
        self.assertEqual(outside.read_text(), "private outside file")
        self.assert_no_output()

    def test_paths_reject_traversal_metadata_controls_and_non_utf8(self):
        for raw in (b"", b"/absolute", b"../outside", b"a/../b", b"a/./b", b"a//b", b"a/",
                    b".git/config", b"a/.GIT/object", b"a\\b", b"C:drive", b"a\tsecret", b"a\nsecret",
                    b"\xff", b"a" * 4097, "a\u202esecret".encode(), b"trailing ", b"trailing."):
            with self.subTest(path=raw[:20]), self.assertRaisesRegex(release.ReleaseError, "^Unsafe source path$"):
                release._path(raw)
        self.assertEqual(release._path("docs/ёж.txt".encode()), "docs/ёж.txt")
        self.write("bad\\name", "unsafe portable path\n")
        self.save()
        with self.assertRaisesRegex(release.ReleaseError, "Unsafe source path"):
            self.build()
        self.assert_no_output()

    def test_tree_enumeration_refuses_corruption_conflicts_and_resource_limits(self):
        oid = b"a" * 40
        valid = b"100644 blob " + oid + b" 3\tfile\0"
        invalid = [b"", valid[:-1], b"bad\0", b"100644 blob \xff 3\tfile\0",
                   b"100644 blob nope 3\tfile\0", b"100600 blob " + oid + b" 3\tfile\0",
                   b"100644 tree " + oid + b" 3\tfile\0", valid.replace(b" 3\t", b" -1\t"),
                   valid + valid, valid + valid.replace(b"\tfile", b"\tfile/child")]
        for listing in invalid:
            result = subprocess.CompletedProcess([], 0, listing)
            with self.subTest(listing=listing[:80]), patch.object(release, "_git", return_value=result), self.assertRaises(release.ReleaseError):
                release._entries(self.repo, self.commit)
        for limit, value, listing in (("MAX_FILES", 1, valid + valid.replace(b"file", b"other")),
                                      ("MAX_BLOB", 2, valid),
                                      ("MAX_TOTAL", 5, valid + valid.replace(b"file", b"other"))):
            with self.subTest(limit=limit), patch.object(release, limit, value), \
                    patch.object(release, "_git", return_value=subprocess.CompletedProcess([], 0, listing)), \
                    self.assertRaisesRegex(release.ReleaseError, "limits"):
                release._entries(self.repo, self.commit)
        self.git("rm", "-r", ".")
        self.git("commit", "-qm", "empty")
        with self.assertRaisesRegex(release.ReleaseError, "empty"):
            self.build()

    def test_blob_integrity_is_checked_and_sha256_repositories_are_supported(self):
        entry = next(item for item in release._entries(self.repo, self.commit) if item.path == "README.md")
        for data in (b"same size".ljust(entry.size, b"x"), b"short"):
            with patch.object(release, "_git", return_value=subprocess.CompletedProcess([], 0, data)), \
                    self.assertRaisesRegex(release.ReleaseError, "integrity"):
                release._blob(self.repo, entry)
        original_repo = self.repo
        self.repo = self.root / "sha256"
        self.repo.mkdir()
        self.git("init", "-q", "-b", "main", "--object-format=sha256")
        self.prepare()
        commit = self.save()
        result = self.build("sha256-output")
        self.assertEqual(result["commit"], commit)
        self.assertEqual(len(result["commit"]), 64)
        self.assertEqual(len(result["tree"]), 64)
        self.repo = original_repo

    def test_git_replace_and_environment_cannot_redirect_selected_source(self):
        original = self.commit
        self.prepare("9.9.9")
        changed = self.save()
        self.git("replace", original, changed)
        with patch.dict(os.environ, {"GIT_DIR": "/does/not/exist", "GIT_WORK_TREE": "/wrong",
                                     "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.bare",
                                     "GIT_CONFIG_VALUE_0": "true", "GIT_ALLOW_PROTOCOL": "https"}):
            result = release.build(original, self.root / "dist", repo=self.repo)
        self.assertEqual(result["commit"], original)
        self.assertEqual(result["version"], "2.3.4.dev5")

    def test_git_failures_and_reference_output_do_not_disclose_raw_errors(self):
        for error in (OSError("PRIVATE_ERROR"), subprocess.TimeoutExpired("PRIVATE_COMMAND", 60, stderr=b"PRIVATE_ERROR")):
            with patch.object(release.subprocess, "run", side_effect=error), \
                    self.assertRaisesRegex(release.ReleaseError, "^Cannot read Git source$"):
                release.validate(repo=self.repo)
        with self.assertRaisesRegex(release.ReleaseError, "Git source validation failed"):
            release.validate("does-not-exist", repo=self.repo)
        for ref in (None, "", "HEAD\0PRIVATE", "HEAD\nPRIVATE"):
            with self.subTest(ref=ref), self.assertRaisesRegex(release.ReleaseError, "Invalid Git reference"):
                release.validate(ref, repo=self.repo)
        for output in (b"\xff", b"not-an-object\n"):
            with patch.object(release, "_git", return_value=subprocess.CompletedProcess([], 0, output)), \
                    self.assertRaisesRegex(release.ReleaseError, "Invalid Git object identity"):
                release.validate(repo=self.repo)
        with patch.object(release.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"ok")) as run:
            release._git(self.repo, "status")
        environment = run.call_args.kwargs["env"]
        self.assertEqual(environment["GIT_NO_LAZY_FETCH"], "1")
        self.assertEqual(environment["GIT_ALLOW_PROTOCOL"], "")
        self.assertEqual(environment["GIT_OPTIONAL_LOCKS"], "0")
        self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)

    def test_output_collision_never_overwrites_or_removes_existing_evidence(self):
        prefix = "cgp-certificate-manager-v" + self.version
        names = (prefix + ".tar.gz", prefix + ".tar.gz.sha256", prefix + ".provenance.json")
        for index, name in enumerate(names):
            output = self.root / ("collision-" + str(index))
            output.mkdir()
            (output / name).write_bytes(b"KEEP EXISTING")
            with self.subTest(name=name), self.assertRaises(release.ReleaseError):
                release.build("HEAD", output, repo=self.repo)
            self.assertEqual({path.name: path.read_bytes() for path in output.iterdir()}, {name: b"KEEP EXISTING"})
        output = self.root / "symlink-collision"
        output.mkdir()
        target = self.root / "preserve-target"
        target.write_text("keep")
        (output / names[0]).symlink_to(target)
        with self.assertRaises(release.ReleaseError):
            release.build("HEAD", output, repo=self.repo)
        self.assertTrue((output / names[0]).is_symlink())
        self.assertEqual(target.read_text(), "keep")

    def test_output_path_refuses_symlink_ancestors_missing_parents_and_unsafe_permissions(self):
        real = self.root / "real"
        real.mkdir()
        link = self.root / "link"
        link.symlink_to(real, target_is_directory=True)
        regular = self.root / "regular"
        regular.write_text("keep")
        for output in (link, link / "dist", regular, self.root / "missing" / "dist", Path("/"), self.root / ".." / "dist"):
            with self.subTest(output=output), self.assertRaises(release.ReleaseError):
                release.build("HEAD", output, repo=self.repo)
        self.assertEqual(list(real.iterdir()), [])
        self.assertFalse((self.root / "missing").exists())
        real.chmod(0o777)
        with self.assertRaisesRegex(release.ReleaseError, "not writable"):
            release.build("HEAD", real, repo=self.repo)
        real.chmod(0o700)
        with patch.object(release.os, "fstat", return_value=SimpleNamespace(st_uid=os.geteuid() + 1, st_mode=0o700)), \
                self.assertRaisesRegex(release.ReleaseError, "must be owned"):
            release.build("HEAD", real, repo=self.repo)

    def test_preparation_failure_cleans_its_files_and_closes_descriptors(self):
        before = len(list(Path("/proc/self/fd").iterdir()))
        with patch.object(release.os, "fdopen", side_effect=OSError("fdopen failure")), self.assertRaises(release.ReleaseError):
            self.build()
        self.assertEqual(list((self.root / "dist").iterdir()), [])
        self.assertEqual(len(list(Path("/proc/self/fd").iterdir())), before)
        with patch.object(release, "_archive", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            self.build()
        self.assertEqual(list((self.root / "dist").iterdir()), [])
        self.assertEqual(len(list(Path("/proc/self/fd").iterdir())), before)
        with patch.object(release.os, "mkdir", side_effect=OSError("mkdir failure")), self.assertRaises(release.ReleaseError):
            self.build("missing-output")
        self.assertFalse((self.root / "missing-output").exists())
        self.assertEqual(len(list(Path("/proc/self/fd").iterdir())), before)

    def test_sync_and_archive_integrity_failures_leave_no_success_artifacts(self):
        sync = release.os.fsync
        for directory in (False, True):
            def fail(descriptor):
                if stat.S_ISDIR(os.fstat(descriptor).st_mode) == directory:
                    raise OSError("sync failure")
                sync(descriptor)
            with self.subTest(directory=directory), patch.object(release.os, "fsync", side_effect=fail), \
                    self.assertRaises(release.ReleaseError):
                self.build()
            self.assertEqual(list((self.root / "dist").iterdir()), [])
        blob = release._blob
        def corrupt(repo, entry):
            if entry.path == "README.md":
                raise release.ReleaseError("Git blob failed integrity validation")
            return blob(repo, entry)
        with patch.object(release, "_blob", side_effect=corrupt), self.assertRaisesRegex(release.ReleaseError, "integrity"):
            self.build()
        self.assertEqual(list((self.root / "dist").iterdir()), [])

    def test_cli_build_check_only_argument_errors_and_safe_failure(self):
        with working_directory(self.repo), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(release.main(["--ref", "HEAD", "--output", str(self.root / "cli")]), 0)
        self.assertEqual(json.loads(output.getvalue())["commit"], self.commit)
        self.prepare("2.3.4")
        commit = self.save()
        self.git("tag", "v2.3.4")
        command = ["--check-only", "--release-tag", "v2.3.4", "--expected-commit", commit, "--main-ref", "main"]
        with working_directory(self.repo), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(release.main(command), 0)
        self.assertEqual(json.loads(output.getvalue())["commit"], commit)
        self.assertNotIn("archive", json.loads(output.getvalue()))
        for arguments in ([], ["--check-only"], command + ["--output", "dist"]):
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                release.main(arguments)
            self.assertEqual(error.exception.code, 2)
        with working_directory(self.repo), redirect_stderr(io.StringIO()) as error_output, \
                self.assertRaises(SystemExit) as error:
            release.main(["--ref", "missing-private-name", "--output", str(self.root / "bad-cli")])
        self.assertEqual(error.exception.code, 1)
        self.assertEqual(error_output.getvalue(), "release: Git source validation failed\n")
        self.assertFalse((self.root / "bad-cli").exists())

    def test_module_entry_point_builds_without_importing_application(self):
        script = Path(release.__file__)
        argv = [str(script), "--output", str(self.root / "entrypoint")]
        with working_directory(self.repo), patch.object(sys, "argv", argv), redirect_stdout(io.StringIO()) as output, \
                self.assertRaises(SystemExit) as error:
            runpy.run_path(str(script), run_name="__main__")
        self.assertEqual(error.exception.code, 0)
        self.assertEqual(json.loads(output.getvalue())["version"], self.version)

