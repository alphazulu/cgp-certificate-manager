"""Read-only local monitoring; no discovery, verification or recovery calls.

The shared lock protects the manager's saved state, not external Certbot writes.
Public leaf certificates are inspected after releasing that lock.  Unknown
quantities remain null and private records never become output fields.
"""

from contextlib import contextmanager, ExitStack
import fcntl
import json
import math
import os
import time

from . import core, dnsauth, resolution, storage
from .transactions import Journal


MAX_JSON = 1024 * 1024
MAX_ITEMS = 1000
MAX_FILES = 4096
MAX_SOURCE_BYTES = 16 * 1024 * 1024
SOURCES = ("config", "inventory", "state", "transactions", "resolutions", "dns_challenges", "lock")
PENDING = ("transactions", "resolutions", "dns_challenges")


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate monitoring source property")
        value[key] = item
    return value


def _constant(value):
    raise ValueError("Non-finite monitoring source value")


def _float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("Non-finite monitoring source value")
    return number


def _json(path):
    with storage.open_private(path) as stream:
        before = os.fstat(stream.fileno())
        if before.st_size > MAX_JSON:
            raise ValueError("Monitoring source exceeds size limit")
        data = stream.buffer.read(MAX_JSON + 1)
        after = os.fstat(stream.fileno())
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if len(data) > MAX_JSON or any(getattr(before, key) != getattr(after, key) for key in fields):
        raise ValueError("Monitoring source changed while being read")
    return json.loads(data.decode("utf-8"), object_pairs_hook=_unique,
                      parse_constant=_constant, parse_float=_float), before.st_mtime


def _identifier(value):
    if not isinstance(value, str) or len(value) > 253:
        raise ValueError("Invalid monitoring identifier")
    return core.identifier(value)


def _domains(value):
    if not isinstance(value, list) or len(value) > MAX_ITEMS:
        raise ValueError("Invalid monitoring inventory")
    result = {}
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("Invalid monitoring domain")
        name = _identifier(item.get("cgp_domain"))
        if name in result:
            raise ValueError("Duplicate monitoring domain")
        _identifier(item.get("cert_name", name))
        if "enabled" in item and type(item["enabled"]) is not bool:
            raise ValueError("Invalid monitoring domain policy")
        result[name] = item
    return result


def _config(value):
    if not isinstance(value, dict) or type(value.get("auto_enable_new_domains", True)) is not bool:
        raise ValueError("Invalid monitoring configuration")
    _domains(value.get("domains", []))
    return value


def _number(value, integer=False):
    if value is None:
        return None
    if (type(value) not in (int, float) or (integer and type(value) is not int)
            or not math.isfinite(value) or value < 0):
        raise ValueError("Invalid monitoring quantity")
    return value


def _state(value):
    if not isinstance(value, dict) or len(value) > MAX_ITEMS:
        raise ValueError("Invalid monitoring state")
    result = {}
    for name, item in value.items():
        _identifier(name)
        if not isinstance(item, dict):
            raise ValueError("Invalid monitoring state entry")
        result[name] = {"last_success": _number(item.get("last_success")),
                        "failures": _number(item.get("failures"), integer=True),
                        "retry_at": _number(item.get("retry_at"))}
    return result


def _load(path, validator):
    try:
        value, modified = _json(path)
        return validator(value), {"status": "ok", "mtime": modified}
    except FileNotFoundError:
        return None, {"status": "missing"}
    except Exception:
        return None, {"status": "error"}


@contextmanager
def _lock(sources):
    stack = ExitStack()
    try:
        storage.check_private_directory(core.STATE)
        stream = stack.enter_context(storage.open_private(core.STATE / "run.lock"))
        fcntl.flock(stream.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
        status = "ok"
    except FileNotFoundError:
        status = "missing"
    except BlockingIOError:
        status = "busy"
    except Exception:
        status = "error"
    sources["lock"] = {"status": status}
    try:
        yield status == "ok"
    finally:
        stack.close()


def _bounded_files(paths):
    if len(paths) > MAX_FILES:
        raise ValueError("Too many monitoring source files")
    total = 0
    for path in paths:
        with storage.open_private(path) as stream:
            size = os.fstat(stream.fileno()).st_size
        total += size
        if size > MAX_JSON or total > MAX_SOURCE_BYTES:
            raise ValueError("Monitoring source exceeds size limit")


def _transactions():
    journal = Journal(core.STATE / "transactions")
    names = journal.domains()
    if len(names) > MAX_ITEMS:
        raise ValueError("Too many pending transactions")
    _bounded_files([journal.path(name) for name in names])
    for name in names:
        if journal.read(name) is None:
            raise ValueError("Transaction disappeared while being read")
    return len(names)


def _resolutions():
    directory = core.STATE / "resolutions"
    if not storage.check_private_directory(directory, missing_ok=True):
        return 0
    bundles = sorted(directory.iterdir())
    if len(bundles) > MAX_ITEMS:
        raise ValueError("Too many operator resolutions")
    files = []
    for bundle in bundles:
        files.extend(storage.private_files(bundle, suffix="", missing_ok=False))
    _bounded_files(files)
    return sum(completion is None for _, _, completion in resolution._audits(core.STATE))


def _dns_challenges(cfg):
    directory = core.STATE / "dns-challenges"
    paths = storage.private_files(directory, suffix="")
    if len(paths) > MAX_ITEMS:
        raise ValueError("Too many DNS challenge receipts")
    _bounded_files(paths)
    return len(dnsauth.status(cfg or {}))


def _pending(snapshot, cfg):
    for name, read in (("transactions", _transactions), ("resolutions", _resolutions),
                       ("dns_challenges", lambda: _dns_challenges(cfg))):
        try:
            snapshot["pending"][name] = read()
            snapshot["sources"][name] = {"status": "ok"}
        except Exception:
            snapshot["sources"][name] = {"status": "error"}


def collect(now=None):
    """Capture bounded local data without creating state or changing saved data."""
    generated = _number(time.time() if now is None else now)
    snapshot = {"schema": 1, "generated_at": float(generated), "complete": False,
                "sources": {name: {"status": "missing"} for name in SOURCES},
                "pending": {name: None for name in PENDING}, "domains": []}
    cfg, snapshot["sources"]["config"] = _load(core.CONFIG, _config)
    inventory, saved = None, None
    with _lock(snapshot["sources"]) as acquired:
        if acquired:
            inventory, snapshot["sources"]["inventory"] = _load(core.STATE / "domains.json", _domains)
            saved, snapshot["sources"]["state"] = _load(core.STATE / "state.json", _state)
            _pending(snapshot, cfg)
        else:
            status = snapshot["sources"]["lock"]["status"]
            for name in ("inventory", "state", *PENDING):
                snapshot["sources"][name] = {"status": status}
    if cfg is not None:
        from .monitoring_certificates import inspect
        overrides = _domains(cfg.get("domains", []))
        names = sorted(set(overrides) | set(inventory or {}))
        if len(names) > MAX_ITEMS:
            snapshot["sources"]["inventory"] = {"status": "error"}
            names = sorted(overrides)
            inventory = None
        for name in names:
            override = overrides.get(name, {})
            lineage = override.get("cert_name", name)
            quantities = (saved or {}).get(name, {})
            snapshot["domains"].append({
                "domain": name, "cert_name": lineage,
                "enabled": override.get("enabled", cfg.get("auto_enable_new_domains", True)),
                "in_inventory": name in inventory if inventory is not None else None,
                "local_certificate": inspect(lineage),
                "last_success": quantities.get("last_success"),
                "failures": quantities.get("failures"), "retry_at": quantities.get("retry_at"),
            })
    snapshot["complete"] = (all(source["status"] == "ok" for source in snapshot["sources"].values())
                            and all(row["local_certificate"]["status"] != "error" for row in snapshot["domains"]))
    return snapshot
