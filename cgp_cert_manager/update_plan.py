"""Offline authenticated preparation; no installer or candidate code execution.

The updater lock protects its own checkpoint, not the running installation.
The installed baseline is only a coherent version-file snapshot. A prepared
plan is informational and cannot authorize application installation.
"""
import ast
from contextlib import contextmanager
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time

from . import core, monitor_config, storage, update_archive as archive, update_metadata as metadata
from .update_metadata import UpdateError


SOURCE_ROOT = Path(__file__).resolve().parents[1]
MAX_CHECKPOINT = 16 * 1024 * 1024
MAX_STAGES = 4
CODES = metadata.CODES | archive.CODES | frozenset({
    "invalid_path", "unsafe_state_path", "input_missing", "input_unsafe", "input_changed", "input_limits",
    "input_unavailable", "installed_invalid", "state_invalid", "state_missing", "lock_missing",
    "prepared_missing", "state_busy", "state_write_failed", "state_changed", "stage_limit", "configuration_changed", "update_failed",
    "update_pending", "update_gate_unsafe"})
_RECORD_FIELDS = {"manifest", "signature", "trust_sha256", "installed_root", "installed_version",
                  "installed_version_sha256", "stage", "inventory", "created_at", "plan_id"}
_STAGE = re.compile(r"release-[a-z0-9_]{8}")


def _require(condition, code):
    if not condition:
        raise UpdateError(code)


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _path(value):
    try:
        path = Path(value)
        _require(path.is_absolute() and path.anchor == "/" and ".." not in path.parts
                 and "\0" not in str(path), "invalid_path")
        return path
    except (TypeError, ValueError):
        raise UpdateError("invalid_path") from None


def _paths(*, trust_path, installed_root, state_dir, **artifacts):
    paths = {name: _path(value) for name, value in
             dict(trust_path=trust_path, installed_root=installed_root, state_dir=state_dir, **artifacts).items()}
    protected = [paths["installed_root"], SOURCE_ROOT, core.STATE, core.CONFIG.parent, core.LIVE.parent,
                 monitor_config.STATE, monitor_config.CONFIG.parent, paths["trust_path"]]
    protected.extend(paths[name] for name in artifacts)
    state = paths["state_dir"]
    _require(all(state != item and state not in item.parents and item not in state.parents
                 for item in protected), "unsafe_state_path")
    return paths


def _witness(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@contextmanager
def _public(path):
    with storage._directory(path.parent, private=False) as parent:
        try:
            descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        except FileNotFoundError:
            raise
        except OSError:
            raise UpdateError("input_unsafe") from None
        try:
            info = os.fstat(descriptor)
            _require(stat.S_ISREG(info.st_mode) and info.st_uid in (0, os.geteuid())
                     and info.st_nlink == 1 and not stat.S_IMODE(info.st_mode) & 0o7022, "input_unsafe")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                yield stream
        finally:
            os.close(descriptor)


def _snapshot(path, limit, private=False, missing=False):
    try:
        with (storage.open_private(path) if private else _public(path)) as stream:
            before = os.fstat(stream.fileno())
            _require(before.st_size <= limit, "input_limits")
            raw = (stream.buffer if private else stream).read(limit + 1)
            after = os.fstat(stream.fileno())
            _require(len(raw) <= limit, "input_limits")
            _require(_witness(before) == _witness(after) and len(raw) == before.st_size, "input_changed")
            return raw
    except FileNotFoundError:
        if missing:
            return None
        raise UpdateError("input_missing") from None
    except storage.StorageError:
        raise UpdateError("input_unsafe") from None
    except OSError:
        raise UpdateError("input_unavailable") from None


def _installed(root):
    raw = _snapshot(root / "cgp_cert_manager" / "__init__.py", 4096)
    try:
        module = ast.parse(raw.decode("utf-8"))
        _require(len(module.body) == 1 and isinstance(module.body[0], ast.Assign)
                 and len(module.body[0].targets) == 1 and isinstance(module.body[0].targets[0], ast.Name)
                 and module.body[0].targets[0].id == "__version__"
                 and isinstance(module.body[0].value, ast.Constant), "installed_invalid")
        value = module.body[0].value.value
        metadata.version(value)
    except (SyntaxError, UnicodeError, ValueError, RecursionError, UpdateError):
        raise UpdateError("installed_invalid") from None
    return {"installed_root": str(root), "installed_version": value, "installed_version_sha256": _digest(raw)}


def _trust(path):
    value = metadata.parse_trust(_snapshot(path, metadata.MAX_TRUST, private=True))
    return value, _digest(metadata.canonical(value))


def _now():
    value = time.time()
    _require(type(value) in (int, float), "invalid_clock")
    try:
        _require(math.isfinite(value) and 0 <= value <= metadata.MAX_TIME, "invalid_clock")
    except OverflowError:
        raise UpdateError("invalid_clock") from None
    return int(value)


@contextmanager
def _shared(state):
    if not storage.check_private_directory(state, missing_ok=True):
        yield False
        return
    try:
        with storage.open_private(state / "run.lock") as lock:
            fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            yield True
    except FileNotFoundError:
        raise UpdateError("lock_missing") from None


def _plan_id(record):
    identity = {"manifest_sha256": _digest(record["manifest"].encode("ascii")),
                "signature_sha256": _digest(record["signature"].encode("ascii")),
                "trust_sha256": record["trust_sha256"], "installed_root": record["installed_root"],
                "installed_version_sha256": record["installed_version_sha256"],
                "inventory_sha256": record["inventory"]["inventory_sha256"]}
    return _digest(metadata.canonical(identity))


def _record(record):
    _require(type(record) is dict and set(record) == _RECORD_FIELDS, "state_invalid")
    _require(type(record["manifest"]) is str and type(record["signature"]) is str, "state_invalid")
    manifest, target = metadata._manifest(record["manifest"].encode("ascii"))
    signature = metadata._json(record["signature"].encode("ascii"), metadata.MAX_SIGNATURE, "state_invalid")
    metadata._exact(signature, {"schema", "key_id", "signature"}, "state_invalid")
    _require(type(signature["schema"]) is int and signature["schema"] == 1
             and metadata._hex(signature["key_id"]), "state_invalid")
    metadata._base64(signature["signature"], 64, "state_invalid")
    _require(all(metadata._hex(record[key]) for key in
                 ("trust_sha256", "installed_version_sha256", "plan_id")), "state_invalid")
    _require(type(record["installed_root"]) is str and str(_path(record["installed_root"])) == record["installed_root"]
             and metadata.version(record["installed_version"]) < target, "state_invalid")
    _require(type(record["stage"]) is str and _STAGE.fullmatch(record["stage"]) is not None, "state_invalid")
    _require(metadata._integer(record["created_at"], 0, metadata.MAX_TIME)
             and manifest["issued_at"] <= record["created_at"] < manifest["expires_at"], "state_invalid")
    inventory = archive.validate_inventory(record["inventory"])
    _require(inventory["version"] == manifest["version"] and _plan_id(record) == record["plan_id"], "state_invalid")
    return manifest


def _validate(value):
    try:
        _require(type(value) is dict and set(value) == {"schema", "floors", "prepared"}
                 and type(value["schema"]) is int and value["schema"] == 1, "state_invalid")
        floors = value["floors"]
        _require(type(floors) is dict and set(floors) <= {"stable", "candidate"}, "state_invalid")
        for channel, floor in floors.items():
            metadata.validate_floor(floor)
            _require(channel != "stable" or metadata.version(floor["version"], allow_dev=False)[3] == 2, "state_invalid")
        if value["prepared"] is not None:
            record = value["prepared"]
            manifest = _record(record)
            floor = floors.get(manifest["channel"])
            _require(floor is not None and floor["sequence"] == manifest["sequence"]
                     and floor["manifest_sha256"] == _digest(record["manifest"].encode("ascii"))
                     and floor["version"] == manifest["version"] and floor["checked_at"] >= record["created_at"], "state_invalid")
        return value
    except (UpdateError, UnicodeError, ValueError, TypeError, RecursionError):
        raise UpdateError("state_invalid") from None


def _load(state):
    raw = _snapshot(state / "checkpoint.json", MAX_CHECKPOINT, private=True, missing=True)
    if raw is None:
        return {"schema": 1, "floors": {}, "prepared": None}
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=metadata._unique,
                           parse_float=metadata._no_float, parse_constant=metadata._no_float)
    except (ValueError, UnicodeError, RecursionError):
        raise UpdateError("state_invalid") from None
    return _validate(value)


def _save(state, checkpoint):
    _validate(checkpoint)
    encoded = (json.dumps(checkpoint, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    _require(len(encoded) <= MAX_CHECKPOINT, "state_invalid")
    try:
        storage.atomic_json(state / "checkpoint.json", checkpoint)
    except (OSError, storage.StorageError):
        raise UpdateError("state_write_failed") from None


def _public_plan(record, verified):
    manifest = verified["manifest"]
    inventory = record["inventory"]
    return {"plan_id": record["plan_id"], "project": manifest["project"], "channel": manifest["channel"],
            "sequence": manifest["sequence"], "installed_version": record["installed_version"],
            "target_version": manifest["version"], "key_id": verified["key_id"],
            "manifest_sha256": verified["manifest_sha256"], "archive_sha256": manifest["archive"]["sha256"],
            "archive_size": manifest["archive"]["size"], "source_commit": manifest["source"]["commit"],
            "source_tree": manifest["source"]["tree"], "release_tag": manifest["source"]["tag"],
            "issued_at": manifest["issued_at"], "expires_at": manifest["expires_at"],
            "file_count": len(inventory["files"]), "total_bytes": inventory["total_bytes"],
            "inventory_sha256": inventory["inventory_sha256"], "created_at": record["created_at"],
            "apply_supported": False}


def _inputs(paths):
    trust, trust_hash = _trust(paths["trust_path"])
    installed = _installed(paths["installed_root"])
    return {"manifest": _snapshot(paths["manifest_path"], metadata.MAX_MANIFEST),
            "signature": _snapshot(paths["signature_path"], metadata.MAX_SIGNATURE),
            "archive": _snapshot(paths["archive_path"], metadata.MAX_ARCHIVE),
            "trust": trust, "trust_sha256": trust_hash, "installed": installed}


def _verify(inputs, checkpoint, now):
    return metadata.verify(inputs["manifest"], inputs["signature"], inputs["trust"], now=now,
                           current_version=inputs["installed"]["installed_version"],
                           previous=checkpoint["floors"].get(inputs["trust"]["channel"]))


def _fresh(inputs, verified):
    return _verify(inputs, {"floors": {inputs["trust"]["channel"]: verified["floor"]}}, _now())


def _identity(info):
    return info.st_dev, info.st_ino


def _binding(state, state_fd, lock):
    try:
        with storage._directory(state) as current, storage.open_private(state / "run.lock") as named:
            _require(_identity(os.fstat(current)) == _identity(os.fstat(state_fd))
                     and _identity(os.fstat(named.fileno())) == _identity(os.fstat(lock.fileno())), "state_changed")
    except (OSError, storage.StorageError):
        raise UpdateError("state_changed") from None


def _new_record(inputs, inventory, now):
    record = {"manifest": inputs["manifest"].decode("ascii"), "signature": inputs["signature"].decode("ascii"),
              "trust_sha256": inputs["trust_sha256"], **inputs["installed"], "inventory": inventory, "created_at": now}
    record["plan_id"] = _plan_id(record)
    return record


def _capacity(parent):
    with storage._directory(parent) as directory:
        names = os.listdir(directory)
        _require(len(names) < MAX_STAGES, "stage_limit")
        for name in names:
            _require(_STAGE.fullmatch(name) is not None, "state_invalid")
            descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            try:
                storage._check_directory(os.fstat(descriptor), parent / name, True)
            finally:
                os.close(descriptor)


def _recheck(paths, inputs):
    current_trust, trust_hash = _trust(paths["trust_path"])
    current_installed = _installed(paths["installed_root"])
    _require(trust_hash == inputs["trust_sha256"] and current_trust == inputs["trust"]
             and current_installed == inputs["installed"], "configuration_changed")


def _check(paths):
    now = _now()
    inputs = _inputs(paths)
    with _shared(paths["state_dir"]) as locked:
        checkpoint = _load(paths["state_dir"]) if locked else {"schema": 1, "floors": {}, "prepared": None}
        verified = _verify(inputs, checkpoint, now)
        inventory = archive.inspect_archive(inputs["archive"], verified["manifest"])
        _recheck(paths, inputs)
        verified = _fresh(inputs, verified)
    return _public_plan(_new_record(inputs, inventory, now), verified)


def _idle(state):
    from . import update_gate
    try:
        update_gate.require_idle(state)
    except update_gate.PendingUpdateError as exc:
        raise UpdateError(exc.code) from None


def _prepare(paths):
    _idle(paths["state_dir"])
    now = _now()
    inputs = _inputs(paths)
    # Authentication and whole-archive inspection precede every state creation.
    verified = _verify(inputs, {"floors": {}}, now)
    inventory = archive.inspect_archive(inputs["archive"], verified["manifest"])
    verified = _fresh(inputs, verified)
    state = paths["state_dir"]
    with storage.operation_lock(state) as lock, storage._directory(state) as state_fd:
        _binding(state, state_fd, lock)
        _idle(state)
        checkpoint = _load(state)
        now = _now()
        _require(now >= verified["floor"]["checked_at"], "clock_moved_backwards")
        verified = _verify(inputs, checkpoint, now)
        record = _new_record(inputs, inventory, now)
        previous = checkpoint["prepared"]
        if previous is not None and previous["plan_id"] == record["plan_id"]:
            archive.validate_stage(state / "staged" / previous["stage"], previous["inventory"])
            record = previous
        else:
            _binding(state, state_fd, lock)
            parent = state / "staged"
            storage.ensure_private_directory(parent)
            _capacity(parent)
            staged = archive.stage(inputs["archive"], verified["manifest"], parent)
            _require(staged["directory"].parent == parent and staged["inventory"] == inventory, "state_invalid")
            record["stage"] = staged["directory"].name
        _recheck(paths, inputs)
        verified = _fresh(inputs, verified)
        _binding(state, state_fd, lock)
        checkpoint["floors"][inputs["trust"]["channel"]] = verified["floor"]
        checkpoint["prepared"] = record
        _save(state, checkpoint)
        _binding(state, state_fd, lock)
        return _public_plan(record, verified)


def _status(paths):
    now = _now()
    state = paths["state_dir"]
    with _shared(state) as locked:
        _require(locked, "state_missing")
        checkpoint = _load(state)
        record = checkpoint["prepared"]
        _require(record is not None, "prepared_missing")
        trust, trust_hash = _trust(paths["trust_path"])
        installed = _installed(paths["installed_root"])
        _require(trust_hash == record["trust_sha256"]
                 and all(installed[key] == record[key] for key in installed), "configuration_changed")
        verified = metadata.verify(record["manifest"].encode("ascii"), record["signature"].encode("ascii"), trust,
                                   now=now, current_version=installed["installed_version"],
                                   previous=checkpoint["floors"][trust["channel"]])
        archive.validate_stage(state / "staged" / record["stage"], record["inventory"])
        inputs = {"manifest": record["manifest"].encode("ascii"), "signature": record["signature"].encode("ascii"),
                  "trust": trust, "trust_sha256": trust_hash, "installed": installed}
        _recheck(paths, inputs)
        verified = _fresh(inputs, verified)
        return _public_plan(record, verified)


def _run(action, operation, options):
    try:
        plan = operation(_paths(**options))
        return {"schema": 1, "action": action, "status": "verified" if action == "check" else "prepared",
                "plan": plan, "error": None}
    except BlockingIOError:
        code = "state_busy"
    except UpdateError as exc:
        code = exc.code if type(exc.code) is str and exc.code in CODES else "update_failed"
    except storage.StorageError:
        code = "state_invalid"
    except Exception:
        code = "update_failed"
    status = {"expired_manifest": "expired", "configuration_changed": "configuration_changed", "state_busy": "busy",
              "state_missing": "missing", "prepared_missing": "missing", "lock_missing": "missing",
              "input_missing": "missing"}.get(code, "invalid")
    if code in {"input_unavailable", "state_write_failed", "archive_storage_error", "verifier_unavailable",
                "unsupported_crypto", "update_failed"}:
        status = "error"
    return {"schema": 1, "action": action, "status": status, "plan": None, "error": code}


def check(*, manifest_path, signature_path, archive_path, trust_path, installed_root, state_dir):
    return _run("check", _check, locals())


def prepare(*, manifest_path, signature_path, archive_path, trust_path, installed_root, state_dir):
    return _run("prepare", _prepare, locals())


def status(*, trust_path, installed_root, state_dir):
    return _run("status", _status, locals())
