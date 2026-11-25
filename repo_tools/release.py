"""Prepare deterministic source archives from immutable Git objects.

This module never imports candidate application code, reads candidate working
files, extracts an archive, creates a tag, or publishes anything. Output parents
must already exist; symlinks in an output path and existing artifacts are refused.
"""
import argparse
import ast
import configparser
from contextlib import contextmanager, ExitStack
from dataclasses import dataclass
from email import policy
from email.parser import Parser
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import unicodedata


MAX_FILES = 20000
MAX_BLOB = 32 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
MAX_METADATA = 64 * 1024
VERSION = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:(?:\.dev|rc)(?:0|[1-9][0-9]*))?"
RELEASE_VERSION = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:rc(?:0|[1-9][0-9]*))?"


class ReleaseError(Exception):
    """Fixed, safe diagnostic for an invalid source or failed local preparation."""


@dataclass(frozen=True)
class Entry:
    path: str
    mode: int
    oid: str
    size: int


def _git(repo, *arguments, accepted=(0,)):
    # Ambient Git redirection/replace objects must not change the stated source.
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                       GIT_NO_LAZY_FETCH="1", GIT_ALLOW_PROTOCOL="",
                       GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0")
    try:
        result = subprocess.run(["git", "--no-replace-objects", "-C", os.fspath(repo), *arguments],
                                env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                stdin=subprocess.DEVNULL, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReleaseError("Cannot read Git source") from exc
    if result.returncode not in accepted:
        raise ReleaseError("Git source validation failed")
    return result


def _oid(value):
    return isinstance(value, str) and re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value) is not None


def _resolve(repo, ref, kind):
    if not isinstance(ref, str) or not ref or any(ord(char) < 32 for char in ref):
        raise ReleaseError("Invalid Git reference")
    result = _git(repo, "rev-parse", "--verify", "--end-of-options", ref + "^{" + kind + "}")
    try:
        oid = result.stdout.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise ReleaseError("Invalid Git object identity") from exc
    if not _oid(oid):
        raise ReleaseError("Invalid Git object identity")
    return oid


def _path(raw):
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReleaseError("Unsafe source path") from exc
    parts = value.split("/")
    if (len(raw) > 4096 or "\\" in value or ":" in value
            or any(unicodedata.category(char).startswith("C") for char in value)
            or any(part in ("", ".", "..") or part.casefold() == ".git"
                   or part.endswith((" ", ".")) for part in parts)):
        raise ReleaseError("Unsafe source path")
    return value


def _entries(repo, commit):
    data = _git(repo, "ls-tree", "-rz", "--long", "--full-tree", commit).stdout
    if not data or not data.endswith(b"\0"):
        raise ReleaseError("Invalid or empty source tree")
    records = data[:-1].split(b"\0")
    if len(records) > MAX_FILES:
        raise ReleaseError("Source tree exceeds limits")
    result, total = [], 0
    for record in records:
        try:
            header, raw_path = record.split(b"\t", 1)
            mode, kind, oid, size = header.split()
            oid = oid.decode("ascii")
            size = int(size)
        except (ValueError, UnicodeDecodeError) as exc:
            raise ReleaseError("Invalid source tree entry") from exc
        if mode not in (b"100644", b"100755") or kind != b"blob" or not _oid(oid):
            raise ReleaseError("Source contains unsupported file types")
        total += size
        if size < 0 or size > MAX_BLOB or total > MAX_TOTAL:
            raise ReleaseError("Source tree exceeds limits")
        result.append(Entry(_path(raw_path), 0o755 if mode == b"100755" else 0o644, oid, size))
    paths = {entry.path for entry in result}
    if len(paths) != len(result) or any("/".join(entry.path.split("/")[:index]) in paths
                                      for entry in result for index in range(1, len(entry.path.split("/")))):
        raise ReleaseError("Source contains conflicting paths")
    return sorted(result, key=lambda entry: entry.path.encode("utf-8"))


def _blob(repo, entry):
    data = _git(repo, "cat-file", "blob", entry.oid).stdout
    algorithm = hashlib.sha1 if len(entry.oid) == 40 else hashlib.sha256
    identity = algorithm(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()
    if len(data) != entry.size or identity != entry.oid:
        raise ReleaseError("Git blob failed integrity validation")
    return data


def _text(data):
    if len(data) > MAX_METADATA or b"\0" in data:
        raise ReleaseError("Invalid release metadata")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReleaseError("Invalid release metadata") from exc


def _metadata(repo, entries):
    by_path = {entry.path: entry for entry in entries}

    def read(path):
        if path not in by_path:
            raise ReleaseError("Required release metadata is missing")
        return _text(_blob(repo, by_path[path]))

    try:
        module = ast.parse(read("cgp_cert_manager/__init__.py"))
    except SyntaxError as exc:
        raise ReleaseError("Invalid application version declaration") from exc
    if (len(module.body) != 1 or not isinstance(module.body[0], ast.Assign)
            or len(module.body[0].targets) != 1 or not isinstance(module.body[0].targets[0], ast.Name)
            or module.body[0].targets[0].id != "__version__"
            or not isinstance(module.body[0].value, ast.Constant)):
        raise ReleaseError("Application version must be one literal assignment")
    version = module.body[0].value.value
    if not isinstance(version, str) or len(version) > 64 or re.fullmatch(VERSION, version) is None:
        raise ReleaseError("Unsupported application version")
    directory = "cgp_certbot_dns-" + version + ".dist-info"
    distributions = {entry.path.split("/")[0] for entry in entries
                     if entry.path.split("/")[0].endswith(".dist-info")}
    if distributions != {directory}:
        raise ReleaseError("Application distribution metadata does not match version")
    metadata = Parser(policy=policy.default).parsestr(read(directory + "/METADATA"))
    if (metadata.defects or metadata.get_all("Metadata-Version") != ["2.1"]
            or metadata.get_all("Name") != ["cgp-certbot-dns"]
            or metadata.get_all("Version") != [version]):
        raise ReleaseError("Invalid application distribution metadata")
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str
    try:
        parser.read_string(read(directory + "/entry_points.txt"))
    except configparser.Error as exc:
        raise ReleaseError("Invalid application plugin registration") from exc
    if (parser.defaults() or parser.sections() != ["certbot.plugins"]
            or dict(parser["certbot.plugins"]) != {"cgp-dns": "cgp_cert_manager.certbot_dns:Authenticator"}
            or read(directory + "/top_level.txt").strip() != "cgp_cert_manager"):
        raise ReleaseError("Invalid application plugin registration")
    return version


def _source(ref, release_tag, expected_commit, main_ref, repo):
    commit = _resolve(repo, ref, "commit")
    tree = _resolve(repo, commit, "tree")
    entries = _entries(repo, commit)
    version = _metadata(repo, entries)
    if (expected_commit is None) != (main_ref is None) or (main_ref is not None and release_tag is None):
        raise ReleaseError("Release context guards must be supplied together")
    if release_tag is not None:
        if (not isinstance(release_tag, str) or re.fullmatch("v" + RELEASE_VERSION, release_tag) is None
                or release_tag != "v" + version):
            raise ReleaseError("Release tag does not match a stable or candidate version")
        if _resolve(repo, "refs/tags/" + release_tag, "commit") != commit:
            raise ReleaseError("Release tag does not identify the selected commit")
    if expected_commit is not None:
        if not _oid(expected_commit) or expected_commit != commit:
            raise ReleaseError("Release commit does not match expected workflow identity")
        main = _resolve(repo, main_ref, "commit")
        if _git(repo, "merge-base", "--is-ancestor", commit, main, accepted=(0, 1)).returncode != 0:
            raise ReleaseError("Release commit is not contained in the selected main branch")
    return {"schema": 1, "commit": commit, "tree": tree, "version": version,
            "release_tag": release_tag, "prefix": "cgp-certificate-manager-v" + version}, entries


def validate(ref="HEAD", release_tag=None, expected_commit=None, main_ref=None, repo="."):
    """Validate immutable source and optional release context without writing."""
    return _source(ref, release_tag, expected_commit, main_ref, repo)[0]


@contextmanager
def _directory(output):
    path = Path(output).absolute()
    if len(path.parts) < 2 or ".." in path.parts:
        raise ReleaseError("Unsafe output directory")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(path.anchor, flags)
    try:
        for index, part in enumerate(path.parts[1:]):
            try:
                child = os.open(part, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if index != len(path.parts) - 2:
                    raise
                os.mkdir(part, 0o755, dir_fd=descriptor)
                child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        status = os.fstat(descriptor)
        if status.st_uid != os.geteuid() or status.st_mode & 0o022:
            raise ReleaseError("Output directory must be owned and not writable by other users")
        yield descriptor
    finally:
        os.close(descriptor)


def _archive(stream, repo, entries, prefix):
    with gzip.GzipFile(filename="", mode="wb", fileobj=stream, mtime=0, compresslevel=9) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
            directory = tarfile.TarInfo(prefix + "/")
            directory.type, directory.mode = tarfile.DIRTYPE, 0o755
            archive.addfile(directory)
            for entry in entries:
                data = _blob(repo, entry)
                info = tarfile.TarInfo(prefix + "/" + entry.path)
                info.mode, info.size = entry.mode, entry.size
                archive.addfile(info, io.BytesIO(data))


def build(ref, output, release_tag=None, expected_commit=None, main_ref=None, repo="."):
    """Write a new archive, checksum and provenance; refuse every overwrite."""
    source, entries = _source(ref, release_tag, expected_commit, main_ref, repo)
    archive_name = source["prefix"] + ".tar.gz"
    names = (archive_name, archive_name + ".sha256", source["prefix"] + ".provenance.json")
    try:
        with _directory(output) as directory:
            created = []
            try:
                with ExitStack() as stack:
                    streams = []
                    for name in names:
                        descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                             0o644, dir_fd=directory)
                        created.append(name)
                        try:
                            stream = os.fdopen(descriptor, "w+b")
                        except BaseException:
                            os.close(descriptor)
                            raise
                        streams.append(stack.enter_context(stream))
                    _archive(streams[0], repo, entries, source["prefix"])
                    streams[0].seek(0)
                    digest = hashlib.sha256()
                    for chunk in iter(lambda: streams[0].read(1024 * 1024), b""):
                        digest.update(chunk)
                    source["archive"] = {"name": archive_name, "size": streams[0].tell(), "sha256": digest.hexdigest()}
                    streams[1].write((digest.hexdigest() + "  " + archive_name + "\n").encode("ascii"))
                    streams[2].write((json.dumps(source, sort_keys=True, indent=2) + "\n").encode("utf-8"))
                    for stream in streams:
                        stream.flush()
                        os.fsync(stream.fileno())
                os.fsync(directory)
            except BaseException:
                for name in created:
                    os.unlink(name, dir_fd=directory)
                raise
    except OSError as exc:
        raise ReleaseError("Cannot create release artifacts without overwriting existing files") from exc
    return source


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref", default="HEAD")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--release-tag")
    parser.add_argument("--expected-commit")
    parser.add_argument("--main-ref")
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args(argv)
    if args.check_only:
        if args.output is not None or not all((args.release_tag, args.expected_commit, args.main_ref)):
            parser.error("--check-only requires --release-tag, --expected-commit and --main-ref, and no --output")
    elif args.output is None:
        parser.error("--output is required when building artifacts")
    options = {"ref": args.ref, "release_tag": args.release_tag,
               "expected_commit": args.expected_commit, "main_ref": args.main_ref}
    try:
        result = validate(**options) if args.check_only else build(output=args.output, **options)
    except ReleaseError as exc:
        parser.exit(1, "release: " + str(exc) + "\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
