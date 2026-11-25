"""Inspect and stage the narrow deterministic release format without execution.

The caller authenticates the manifest first. Its whole-archive digest binds all
bytes; the computed inventory binds the subsequently prepared private tree.
Only immutable byte snapshots are accepted. No TarFile iteration/extraction or
candidate imports are used. Same-UID/root concurrent mutation is not a sandbox.
"""
import ast
import configparser
from contextlib import contextmanager
from email import policy
from email.parser import Parser
import hashlib
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import tarfile
import unicodedata
import zlib

from . import storage, update_metadata
from .update_metadata import UpdateError


MAX_ARCHIVE = update_metadata.MAX_ARCHIVE
MAX_TAR = 256 * 1024 * 1024
MAX_FILES = 20000
MAX_DIRECTORIES = 20000
MAX_FILE = 32 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
MAX_METADATA = 64 * 1024
MAX_INVENTORY = 16 * 1024 * 1024
MAX_PAX = 8192
MAX_PATH = 4096
MAX_DEPTH = 64
CHUNK = 64 * 1024
MAX_STAGE_ATTEMPTS = 16
CODES = frozenset({"archive_mismatch", "archive_invalid", "archive_limits",
                   "archive_metadata_invalid", "archive_storage_error"})
_FILE_FIELDS = {"path", "mode", "size", "sha256"}
_INVENTORY_FIELDS = {"version", "prefix", "files", "inventory_sha256", "total_bytes"}


def _require(condition, code="archive_invalid"):
    if not condition:
        raise UpdateError(code)


def _version(value):
    try:
        update_metadata.version(value, allow_dev=False)
    except UpdateError:
        raise UpdateError("archive_metadata_invalid") from None
    return "cgp-certificate-manager-v" + value


def _hex(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _path(value):
    _require(type(value) is str)
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        raise UpdateError("archive_invalid") from None
    parts = value.split("/")
    _require(len(encoded) <= MAX_PATH and len(parts) <= MAX_DEPTH, "archive_limits")
    _require("\\" not in value and ":" not in value
             and not any(unicodedata.category(char).startswith("C") for char in value)
             and all(part not in ("", ".", "..") and part.casefold() != ".git"
                     and not part.endswith((" ", ".")) for part in parts))
    _require(all(len(part.encode("utf-8")) <= 255 for part in parts), "archive_limits")
    return encoded, parts


def _inventory(version, files):
    prefix = _version(version)
    _require(type(files) is list and bool(files))
    _require(len(files) <= MAX_FILES, "archive_limits")
    result, nodes, previous, total, encoded_size, directories = [], {}, b"", 0, 3, 0
    for entry in files:
        _require(type(entry) is dict and set(entry) == _FILE_FIELDS)
        _require(type(entry["mode"]) is int and entry["mode"] in (0o644, 0o755)
                 and type(entry["size"]) is int and entry["size"] >= 0 and _hex(entry["sha256"]))
        raw, parts = _path(entry["path"])
        _require(raw > previous)
        previous = raw
        total += entry["size"]
        _require(entry["size"] <= MAX_FILE and total <= MAX_TOTAL, "archive_limits")
        for index in range(1, len(parts) + 1):
            path, directory = "/".join(parts[:index]), index < len(parts)
            key = unicodedata.normalize("NFC", path).casefold()
            existing = nodes.get(key)
            _require(existing is None or (directory and existing == (path, True)))
            if existing is None and directory:
                directories += 1
            nodes[key] = (path, directory)
        _require(directories <= MAX_DIRECTORIES, "archive_limits")
        item = dict(entry)
        encoded_size += len(update_metadata.canonical(item))
        _require(encoded_size <= MAX_INVENTORY, "archive_limits")
        result.append(item)
    return {"version": version, "prefix": prefix, "files": result,
            "inventory_sha256": hashlib.sha256(update_metadata.canonical(result)).hexdigest(),
            "total_bytes": total}


def validate_inventory(value):
    """Return an independent, exact-schema inventory or a fixed safe error."""
    _require(type(value) is dict and set(value) == _INVENTORY_FIELDS)
    expected = _inventory(value["version"], value["files"])
    _require(type(value["prefix"]) is str and _hex(value["inventory_sha256"])
             and type(value["total_bytes"]) is int and value == expected)
    return expected


def _header(name, mode, size=0, kind=tarfile.REGTYPE):
    info = tarfile.TarInfo(name)
    info.mode, info.size, info.type = mode, size, kind
    return info.tobuf(format=tarfile.PAX_FORMAT, encoding="utf-8", errors="strict")


def _decode_header(block):
    try:
        return tarfile.TarInfo.frombuf(block, "utf-8", "strict")
    except (tarfile.HeaderError, UnicodeError):
        raise UpdateError("archive_invalid") from None


def _payload(raw, offset, size):
    end = offset + size
    following = end + (-size % 512)
    _require(following <= len(raw) and not any(raw[end:following]))
    return memoryview(raw)[offset:end], following


def _pax(payload):
    length, separator, field = bytes(payload).partition(b" ")
    _require(separator == b" " and length == str(len(payload)).encode("ascii")
             and field.startswith(b"path=") and field.endswith(b"\n"))
    try:
        return field[5:-1].decode("utf-8")
    except UnicodeError:
        raise UpdateError("archive_invalid") from None


def _text(data):
    _require(len(data) <= MAX_METADATA and b"\0" not in data, "archive_metadata_invalid")
    try:
        return data.decode("utf-8")
    except UnicodeError:
        raise UpdateError("archive_metadata_invalid") from None


def _metadata(version, files, raw, offsets):
    records = {entry["path"]: (entry, offset) for entry, offset in zip(files, offsets)}

    def read(path):
        _require(path in records, "archive_metadata_invalid")
        entry, offset = records[path]
        _require(entry["size"] <= MAX_METADATA, "archive_metadata_invalid")
        return _text(raw[offset:offset + entry["size"]])

    try:
        module = ast.parse(read("cgp_cert_manager/__init__.py"))
    except (SyntaxError, ValueError, RecursionError):
        raise UpdateError("archive_metadata_invalid") from None
    _require(len(module.body) == 1 and isinstance(module.body[0], ast.Assign)
             and len(module.body[0].targets) == 1 and isinstance(module.body[0].targets[0], ast.Name)
             and module.body[0].targets[0].id == "__version__"
             and isinstance(module.body[0].value, ast.Constant)
             and module.body[0].value.value == version, "archive_metadata_invalid")
    distribution = "cgp_certbot_dns-" + version + ".dist-info"
    _require({name.split("/")[0] for name in records if name.split("/")[0].endswith(".dist-info")}
             == {distribution}, "archive_metadata_invalid")
    metadata = Parser(policy=policy.default).parsestr(read(distribution + "/METADATA"))
    _require(not metadata.defects and metadata.get_all("Metadata-Version") == ["2.1"]
             and metadata.get_all("Name") == ["cgp-certbot-dns"]
             and metadata.get_all("Version") == [version], "archive_metadata_invalid")
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str
    try:
        parser.read_string(read(distribution + "/entry_points.txt"))
    except configparser.Error:
        raise UpdateError("archive_metadata_invalid") from None
    _require(not parser.defaults() and parser.sections() == ["certbot.plugins"]
             and dict(parser["certbot.plugins"]) == {"cgp-dns": "cgp_cert_manager.certbot_dns:Authenticator"}
             and read(distribution + "/top_level.txt").strip() == "cgp_cert_manager",
             "archive_metadata_invalid")


def _parse(data, manifest):
    _require(type(data) is bytes and type(manifest) is dict)
    version = manifest.get("version")
    prefix = _version(version)
    archive = manifest.get("archive")
    _require(type(archive) is dict and set(archive) == {"name", "size", "sha256"})
    _require(archive["name"] == prefix + ".tar.gz" and type(archive["size"]) is int
             and 0 < archive["size"] <= MAX_ARCHIVE and _hex(archive["sha256"]))
    _require(len(data) <= MAX_ARCHIVE, "archive_limits")
    _require(len(data) == archive["size"] and hashlib.sha256(data).hexdigest() == archive["sha256"],
             "archive_mismatch")
    # GzipFile(filename='', mtime=0, compresslevel=9), used by release.build.
    _require(data[:10] == b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff")
    decoder = zlib.decompressobj(31)
    try:
        raw = decoder.decompress(data, MAX_TAR + 1)
    except zlib.error:
        raise UpdateError("archive_invalid") from None
    _require(len(raw) <= MAX_TAR, "archive_limits")
    _require(decoder.eof and not decoder.unused_data and len(raw) % tarfile.RECORDSIZE == 0)
    _require(raw[:512] == _header(prefix + "/", 0o755, kind=tarfile.DIRTYPE))
    files, offsets, offset, total = [], [], 512, 0
    while True:
        start = offset
        block = raw[offset:offset + 512]
        if block == bytes(512):
            _require(len(raw) == ((offset + 1024 + 10239) // 10240) * 10240 and not any(raw[offset:]))
            break
        info = _decode_header(block)
        offset += 512
        name = info.name
        if info.type == tarfile.XHDTYPE:
            _require(0 < info.size <= MAX_PAX, "archive_limits")
            payload, offset = _payload(raw, offset, info.size)
            name = _pax(payload)
            info = _decode_header(raw[offset:offset + 512])
            offset += 512
        _require(info.type == tarfile.REGTYPE and info.mode in (0o644, 0o755) and info.size >= 0)
        total += info.size
        _require(info.size <= MAX_FILE and total <= MAX_TOTAL and len(files) < MAX_FILES, "archive_limits")
        _require(name.startswith(prefix + "/"))
        path = name[len(prefix) + 1:]
        _path(path)
        # A byte-exact comparison forbids all hidden PAX/GNU overrides, owner,
        # timestamp, link, sparse, numeric/header and fallback-name ambiguity.
        _require(raw[start:offset] == _header(name, info.mode, info.size))
        payload, following = _payload(raw, offset, info.size)
        files.append({"path": path, "mode": info.mode, "size": info.size,
                      "sha256": hashlib.sha256(payload).hexdigest()})
        offsets.append(offset)
        offset = following
    inventory = _inventory(version, files)
    _metadata(inventory["version"], files, raw, offsets)
    return inventory, raw, offsets


def inspect_archive(data, manifest):
    """Inspect an authenticated immutable snapshot; perform no filesystem I/O."""
    return _parse(data, manifest)[0]


def _tree(inventory):
    root = {inventory["prefix"]: {}}
    for index, entry in enumerate(inventory["files"]):
        parts = entry["path"].split("/")
        parent = root[inventory["prefix"]]
        for part in parts[:-1]:
            parent = parent.setdefault(part, {})
        parent[parts[-1]] = index
    return root


@contextmanager
def _opened(name, parent, directory=False, create=False):
    flags = os.O_NOFOLLOW | os.O_NONBLOCK
    flags |= os.O_DIRECTORY | os.O_RDONLY if directory else os.O_RDONLY
    if create:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    descriptor = os.open(name, flags, 0o600, dir_fd=parent)
    try:
        yield descriptor
    finally:
        os.close(descriptor)


def _populate(directory, tree, files, raw, offsets):
    for name, item in tree.items():
        if type(item) is dict:
            os.mkdir(name, 0o755, dir_fd=directory)
            with _opened(name, directory, directory=True) as child:
                os.fchmod(child, 0o755)
                _populate(child, item, files, raw, offsets)
        else:
            entry = files[item]
            payload = memoryview(raw)[offsets[item]:offsets[item] + entry["size"]]
            with _opened(name, directory, create=True) as child:
                position = 0
                while position < len(payload):
                    written = os.write(child, payload[position:position + CHUNK])
                    if written <= 0:
                        raise OSError("Incomplete prepared file write")
                    position += written
                os.fchmod(child, entry["mode"])
                os.fsync(child)
    os.fsync(directory)


def _new_stage(directory):
    for attempt in range(MAX_STAGE_ATTEMPTS):
        name = "release-" + secrets.token_hex(4)
        try:
            os.mkdir(name, 0o700, dir_fd=directory)
        except FileExistsError:
            continue
        return name
    raise OSError("Cannot allocate a new preparation directory")


def _identity(info):
    return info.st_dev, info.st_ino


def _location(parent, directory, name, identity):
    # A changed logical path must not produce a successful plan or redirect
    # failure cleanup. All actual mutations remain relative to the retained fd.
    with storage._directory(parent) as current:
        _require(_identity(os.fstat(current)) == _identity(os.fstat(directory)), "archive_storage_error")
    info = os.stat(name, dir_fd=directory, follow_symlinks=False)
    storage._check_directory(info, parent / name, True)
    _require(_identity(info) == identity and stat.S_IMODE(info.st_mode) == 0o700, "archive_storage_error")


def stage(data, manifest, parent):
    """Create one durable private child; never replace/reuse an existing stage."""
    inventory, raw, offsets = _parse(data, manifest)
    try:
        with storage._directory(parent) as directory:
            parent = Path(parent).absolute()
            name, identity = _new_stage(directory), None
            child = parent / name
            try:
                info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                storage._check_directory(info, child, True)
                identity = _identity(info)
                with _opened(name, directory, directory=True) as descriptor:
                    _require(_identity(os.fstat(descriptor)) == identity, "archive_storage_error")
                    os.fchmod(descriptor, 0o700)
                    _populate(descriptor, _tree(inventory), inventory["files"], raw, offsets)
                os.fsync(directory)
                _location(parent, directory, name, identity)
            except BaseException:
                if identity is not None:
                    _location(parent, directory, name, identity)
                    shutil.rmtree(name, dir_fd=directory)
                    os.fsync(directory)
                raise
        return {"directory": child, "inventory": inventory}
    except (OSError, storage.StorageError):
        raise UpdateError("archive_storage_error") from None


def _signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _verify(directory, tree, files):
    _require(set(os.listdir(directory)) == set(tree))
    for name, item in tree.items():
        is_directory = type(item) is dict
        with _opened(name, directory, directory=is_directory) as child:
            before = os.fstat(child)
            _require(before.st_uid == os.geteuid())
            if is_directory:
                _require(stat.S_ISDIR(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o755)
                _verify(child, item, files)
            else:
                entry = files[item]
                _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                         and stat.S_IMODE(before.st_mode) == entry["mode"] and before.st_size == entry["size"])
                digest, size = hashlib.sha256(), 0
                while True:
                    chunk = os.read(child, CHUNK)
                    if not chunk:
                        break
                    size += len(chunk)
                    _require(size <= entry["size"])
                    digest.update(chunk)
                _require(size == entry["size"] and digest.hexdigest() == entry["sha256"]
                         and _signature(before) == _signature(os.fstat(child)))


def validate_stage(directory, inventory):
    """Recheck every prepared path, byte and mode without creating or executing."""
    inventory = validate_inventory(inventory)
    try:
        with storage._directory(directory) as descriptor:
            _require(stat.S_IMODE(os.fstat(descriptor).st_mode) == 0o700, "archive_storage_error")
            _verify(descriptor, _tree(inventory), inventory["files"])
    except (OSError, storage.StorageError):
        raise UpdateError("archive_storage_error") from None
