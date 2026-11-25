"""Bounded filesystem snapshots and explicitly recognized update rename states.

Callers own the operation locks and durable authorization. No candidate code is
executed and no slot or backup is automatically removed. Same-UID namespace
changes are detected when observed; this is not a sandbox against root.
"""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import stat

from . import storage, update_metadata as metadata
from .update_metadata import UpdateError


MAX_ENTRIES = 20000
MAX_DEPTH = 64
MAX_FILE = 32 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
MAX_BLOBS = 256 * 1024 * 1024
CODES = frozenset({"snapshot_invalid", "filesystem_unsafe", "filesystem_changed",
                   "filesystem_limits", "filesystem_unknown", "filesystem_storage_error", "backup_invalid"})
_HEX = re.compile(r"[0-9a-f]{64}")
_BASE = {"path", "kind", "mode", "uid", "gid", "mtime_ns"}
_MISSING = {"kind": "missing", "entries": []}


def _require(condition, code):
    if not condition:
        raise UpdateError(code)


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def _path(value):
    try:
        path = Path(value)
        _require(path.is_absolute() and path.anchor == "/" and ".." not in path.parts
                 and path.name and all(character.isprintable() for character in str(path)), "filesystem_unsafe")
        str(path).encode("utf-8")
        return path
    except (TypeError, ValueError, UnicodeError):
        raise UpdateError("filesystem_unsafe") from None


def _name(value):
    try:
        return (type(value) is str and 0 < len(value.encode("utf-8")) <= 4096
                and "\\" not in value and all(character.isprintable() for character in value)
                and all(part not in ("", ".", "..") for part in value.split("/"))
                and len(value.split("/")) <= MAX_DEPTH)
    except UnicodeError:
        return False


def validate_snapshot(snapshot):
    """Validate and copy a complete inventory, including empty directories."""
    _require(type(snapshot) is dict and set(snapshot) == {"kind", "entries"}, "snapshot_invalid")
    kind, entries = snapshot["kind"], snapshot["entries"]
    _require(type(kind) is str and kind in ("missing", "file", "directory")
             and type(entries) is list and len(entries) <= MAX_ENTRIES, "snapshot_invalid")
    if kind == "missing":
        _require(not entries, "snapshot_invalid")
        return {"kind": "missing", "entries": []}
    _require(bool(entries), "snapshot_invalid")
    seen, result, total = {}, [], 0
    for index, entry in enumerate(entries):
        _require(type(entry) is dict and type(entry.get("kind")) is str
                 and entry["kind"] in ("file", "directory"), "snapshot_invalid")
        is_file = entry["kind"] == "file"
        _require(set(entry) == _BASE | ({"size", "sha256"} if is_file else set()), "snapshot_invalid")
        name = entry["path"]
        _require((index == 0 and name == "." and entry["kind"] == kind)
                 or (index > 0 and _name(name)), "snapshot_invalid")
        _require(name not in seen and _integer(entry["mode"], 0, 0o777)
                 and not entry["mode"] & 0o022 and _integer(entry["uid"], 0, 2**32 - 2)
                 and entry["uid"] in (0, os.geteuid()) and _integer(entry["gid"], 0, 2**32 - 2)
                 and _integer(entry["mtime_ns"], -(2**63), 2**63 - 1), "snapshot_invalid")
        if index:
            parent = name.rpartition("/")[0] or "."
            _require(seen.get(parent) == "directory", "snapshot_invalid")
        if is_file:
            _require(_integer(entry["size"], 0, MAX_FILE) and type(entry["sha256"]) is str
                     and _HEX.fullmatch(entry["sha256"]) is not None, "snapshot_invalid")
            total += entry["size"]
        seen[name] = entry["kind"]
        result.append(dict(entry))
    _require(total <= MAX_TOTAL and [item["path"] for item in result[1:]]
             == sorted(seen.keys() - {"."}, key=lambda name: name.encode("utf-8")), "snapshot_invalid")
    return {"kind": kind, "entries": result}


def fingerprint(snapshot):
    return _digest(metadata.canonical(validate_snapshot(snapshot)))


def _identity(info):
    return info.st_dev, info.st_ino


def _witness(info):
    return (_identity(info), info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _binding(path, descriptor):
    with storage._directory(path, private=False) as named:
        _require(_identity(os.fstat(named)) == _identity(os.fstat(descriptor)), "filesystem_changed")


@contextmanager
def _errors():
    try:
        yield
    except storage.StorageError:
        raise UpdateError("filesystem_unsafe") from None
    except OSError:
        raise UpdateError("filesystem_storage_error") from None


def _checked(descriptor, device):
    info = os.fstat(descriptor)
    _require((stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))
             and info.st_uid in (0, os.geteuid()) and not stat.S_IMODE(info.st_mode) & 0o7022
             and (not stat.S_ISREG(info.st_mode) or info.st_nlink == 1)
             and info.st_dev == device and not os.listxattr(descriptor), "filesystem_unsafe")
    return info


def _read_entry(parent, name, relative, device, entries, blobs, total):
    _require(relative == "." or _name(relative), "filesystem_unsafe")
    _require(len(entries) < MAX_ENTRIES, "filesystem_limits")
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    except OSError:
        raise UpdateError("filesystem_unsafe") from None
    try:
        before = _checked(descriptor, device)
        is_file = stat.S_ISREG(before.st_mode)
        entry = {"path": relative, "kind": "file" if is_file else "directory",
                 "mode": stat.S_IMODE(before.st_mode), "uid": before.st_uid, "gid": before.st_gid,
                 "mtime_ns": before.st_mtime_ns}
        entries.append(entry)
        if is_file:
            _require(before.st_size <= MAX_FILE and total[0] + before.st_size <= MAX_TOTAL, "filesystem_limits")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                data = stream.read(MAX_FILE + 1)
            _require(len(data) == before.st_size, "filesystem_changed")
            total[0] += len(data)
            entry.update(size=len(data), sha256=_digest(data))
            blobs[entry["sha256"]] = data
        else:
            names = os.listdir(descriptor)
            _require(len(names) + len(entries) <= MAX_ENTRIES, "filesystem_limits")
            for child in sorted(names):
                _read_entry(descriptor, child, child if relative == "." else relative + "/" + child,
                            device, entries, blobs, total)
        after = _checked(descriptor, device)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        _require(_witness(before) == _witness(after) == _witness(named), "filesystem_changed")
    finally:
        os.close(descriptor)


def _capture_at(parent, name):
    try:
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return {"kind": "missing", "entries": []}, {}
    entries, blobs = [], {}
    _read_entry(parent, name, ".", os.fstat(parent).st_dev, entries, blobs, [0])
    _require(_identity(info) == _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)), "filesystem_changed")
    entries[1:] = sorted(entries[1:], key=lambda entry: entry["path"].encode("utf-8"))
    snapshot = {"kind": entries[0]["kind"], "entries": entries}
    return validate_snapshot(snapshot), blobs


def capture(path):
    """Read one coherent, named, no-follow snapshot without writing or syncing."""
    path = _path(path)
    with _errors(), storage._directory(path.parent, missing_ok=True, private=False) as parent:
        if parent is None:
            return {"kind": "missing", "entries": []}, {}
        result = _capture_at(parent, path.name)
        _binding(path.parent, parent)
        return result


def matches(path, snapshot):
    return capture(path)[0] == validate_snapshot(snapshot)


def _blobs(blobs):
    _require(type(blobs) is dict and len(blobs) <= MAX_ENTRIES, "backup_invalid")
    total = 0
    for digest, data in blobs.items():
        _require(type(digest) is str and _HEX.fullmatch(digest) is not None and type(data) is bytes
                 and len(data) <= MAX_FILE and _digest(data) == digest, "backup_invalid")
        total += len(data)
    _require(total <= MAX_BLOBS, "backup_invalid")


def _needed(snapshots):
    _require(type(snapshots) in (list, tuple) and len(snapshots) <= 64, "snapshot_invalid")
    needed = {}
    for snapshot in snapshots:
        for entry in validate_snapshot(snapshot)["entries"]:
            if entry["kind"] == "file":
                _require(entry["sha256"] not in needed or needed[entry["sha256"]] == entry["size"], "snapshot_invalid")
                needed[entry["sha256"]] = entry["size"]
    _require(len(needed) <= MAX_ENTRIES and sum(needed.values()) <= MAX_BLOBS, "filesystem_limits")
    return needed


def _attributes(descriptor, entry):
    os.fchown(descriptor, entry["uid"], entry["gid"])
    os.fchmod(descriptor, entry["mode"])
    os.utime(descriptor, ns=(entry["mtime_ns"], entry["mtime_ns"]))
    os.fsync(descriptor)


def _build(parent, name, relative, indexed, children, blobs):
    entry = indexed[relative]
    if entry["kind"] == "directory":
        os.mkdir(name, mode=0o700, dir_fd=parent)
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    else:
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    try:
        if entry["kind"] == "directory":
            for child in children.get(relative, []):
                _build(descriptor, child.rsplit("/", 1)[-1], child, indexed, children, blobs)
        else:
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(blobs[entry["sha256"]])
                stream.flush()
        _attributes(descriptor, entry)
    finally:
        os.close(descriptor)


def _materialize_at(parent, name, snapshot, blobs):
    _require(_capture_at(parent, name)[0]["kind"] == "missing", "filesystem_unknown")
    if snapshot["kind"] == "missing":
        return
    indexed = {entry["path"]: entry for entry in snapshot["entries"]}
    children = {}
    for entry in snapshot["entries"][1:]:
        children.setdefault(entry["path"].rpartition("/")[0] or ".", []).append(entry["path"])
    _build(parent, name, ".", indexed, children, blobs)
    os.fsync(parent)
    _require(_capture_at(parent, name)[0] == snapshot, "filesystem_changed")


def materialize(destination, snapshot, blobs):
    """Create only an absent path. A failed partial creation is retained."""
    destination, snapshot = _path(destination), validate_snapshot(snapshot)
    _blobs(blobs)
    needed = _needed([snapshot])
    _require(all(digest in blobs and len(blobs[digest]) == size for digest, size in needed.items()), "backup_invalid")
    with _errors(), storage._directory(destination.parent, private=False) as parent:
        _binding(destination.parent, parent)
        _materialize_at(parent, destination.name, snapshot, blobs)
        _binding(destination.parent, parent)


def _blob(directory, digest):
    path = directory / digest
    with storage.open_private(path) as stream:
        before = os.fstat(stream.fileno())
        _checked(stream.fileno(), before.st_dev)
        _require(before.st_size <= MAX_FILE, "backup_invalid")
        data = stream.buffer.read(MAX_FILE + 1)
        _require(_witness(before) == _witness(os.fstat(stream.fileno()))
                 and len(data) == before.st_size and _digest(data) == digest, "backup_invalid")
        with storage._directory(directory) as parent:
            _require(_witness(before) == _witness(os.stat(digest, dir_fd=parent, follow_symlinks=False)), "backup_invalid")
        return data


def save_blobs(private_dir, blobs):
    """Persist content-addressed bytes; never replace an existing object."""
    private_dir = _path(private_dir)
    _blobs(blobs)
    with _errors():
        storage.ensure_private_directory(private_dir)
        with storage._directory(private_dir) as directory:
            for digest, data in sorted(blobs.items()):
                try:
                    descriptor = os.open(digest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                         0o600, dir_fd=directory)
                except FileExistsError:
                    _require(_blob(private_dir, digest) == data, "backup_invalid")
                    with storage.open_private(private_dir / digest) as existing:
                        os.fsync(existing.fileno())
                else:
                    try:
                        with os.fdopen(descriptor, "wb", closefd=False) as stream:
                            stream.write(data)
                            stream.flush()
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                os.fsync(directory)
            _binding(private_dir, directory)


def load_blobs(private_dir, snapshots):
    """Verify every requested backup before returning any restoration bytes."""
    private_dir, needed = _path(private_dir), _needed(snapshots)
    result = {}
    with _errors(), storage._directory(private_dir) as directory:
        for digest, size in sorted(needed.items()):
            data = _blob(private_dir, digest)
            _require(len(data) == size, "backup_invalid")
            result[digest] = data
        _binding(private_dir, directory)
    return result


def _pair(target, slot):
    target, slot = _path(target), _path(slot)
    _require(target.parent == slot.parent and target != slot, "filesystem_unsafe")
    return target, slot


def prepare_slot(target, slot, after, blobs):
    target, slot = _pair(target, slot)
    after = validate_snapshot(after)
    _require(after["kind"] != "missing", "snapshot_invalid")
    _blobs(blobs)
    _require(all(digest in blobs and len(blobs[digest]) == size for digest, size in _needed([after]).items()), "backup_invalid")
    with _errors(), storage._directory(target.parent, private=False) as parent:
        _require(_capture_at(parent, slot.name)[0]["kind"] == "missing", "filesystem_unknown")
        os.mkdir(slot.name, mode=0o700, dir_fd=parent)
        os.fsync(parent)
        _binding(target.parent, parent)
        descriptor = os.open(slot.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            _checked(descriptor, os.fstat(parent).st_dev)
            _binding(slot, descriptor)
            _materialize_at(descriptor, "new", after, blobs)
            _binding(slot, descriptor)
        finally:
            os.close(descriptor)


def _spec(before, after):
    before, after = validate_snapshot(before), validate_snapshot(after)
    _require(after["kind"] != "missing" and before != after, "snapshot_invalid")
    return before, after


@contextmanager
def _locations(target, slot):
    with storage._directory(target.parent, private=False) as parent, storage._directory(slot) as directory:
        _checked(directory, os.fstat(parent).st_dev)
        yield parent, directory


def _state(target, slot, before, after, parent, directory):
    _binding(target.parent, parent)
    _binding(slot, directory)
    _checked(directory, os.fstat(parent).st_dev)
    if not set(os.listdir(directory)) <= {"new", "old", "undo"}:
        return "unknown"
    actual = [_capture_at(parent, target.name)[0]]
    actual.extend(_capture_at(directory, name)[0] for name in ("new", "old", "undo"))
    _binding(target.parent, parent)
    _binding(slot, directory)
    states = [("ready", [before, after, _MISSING, _MISSING]),
              ("applied", [after, _MISSING, before, _MISSING]),
              ("restored", [before, _MISSING, _MISSING, after])]
    if before["kind"] != "missing":
        states.extend([("parked", [_MISSING, after, before, _MISSING]),
                       ("undo_parked", [_MISSING, _MISSING, before, after])])
    for label, expected in states:
        if actual == expected:
            return label
    return "unknown"


def classify(target, slot, before, after):
    target, slot = _pair(target, slot)
    before, after = _spec(before, after)
    with _errors(), _locations(target, slot) as (parent, directory):
        return _state(target, slot, before, after, parent, directory)


def _sync(parent, directory):
    os.fsync(directory)
    os.fsync(parent)


def _move(name, source, destination, source_fd, destination_fd, expected, context, checkpoint):
    checkpoint("before_" + name)
    _require(_state(*context) == expected, "filesystem_unknown")
    os.rename(source, destination, src_dir_fd=source_fd, dst_dir_fd=destination_fd)
    checkpoint("after_" + name)
    _sync(source_fd, destination_fd)
    checkpoint("synced_" + name)


def apply_target(target, slot, before, after, checkpoint=lambda event: None):
    target, slot = _pair(target, slot)
    before, after = _spec(before, after)
    with _errors(), _locations(target, slot) as (parent, directory):
        context = target, slot, before, after, parent, directory
        state = _state(*context)
        _require(state in ("ready", "parked", "applied"), "filesystem_unknown")
        if state == "ready" and before["kind"] != "missing":
            _move("park_old", target.name, "old", parent, directory, "ready", context, checkpoint)
            state = "parked"
        if state != "applied":
            _move("install_new", "new", target.name, directory, parent, state, context, checkpoint)
        _sync(parent, directory)
        _require(_state(*context) == "applied", "filesystem_unknown")


def restore_target(target, slot, before, after, checkpoint=lambda event: None):
    target, slot = _pair(target, slot)
    before, after = _spec(before, after)
    with _errors(), _locations(target, slot) as (parent, directory):
        context = target, slot, before, after, parent, directory
        state = _state(*context)
        _require(state in ("ready", "parked", "applied", "undo_parked", "restored"), "filesystem_unknown")
        if state == "applied":
            _move("park_undo", target.name, "undo", parent, directory, "applied", context, checkpoint)
            state = "restored" if before["kind"] == "missing" else "undo_parked"
        if state in ("parked", "undo_parked"):
            _move("restore_old", "old", target.name, directory, parent, state, context, checkpoint)
        _sync(parent, directory)
        _require(_state(*context) in ("ready", "restored"), "filesystem_unknown")
