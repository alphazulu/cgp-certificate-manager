"""Explicit data-only installation with independent, conservative recovery.

The installed trusted runtime is outside every replacement target. Recovery
uses durable local preimages, never a candidate import, installer or fresh
signature. Private evidence is retained, including uncertain outcomes. Root or
the same trusted UID can change a namespace between checks; this is not a sandbox.
"""
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets

from . import (dnsconfig, monitor_config, schedule, storage, update_archive,
               update_files as files, update_gate, update_metadata as metadata,
               update_plan as package, update_services as services)
from .update_metadata import UpdateError


DOMAIN = b"CGP-CERTIFICATE-MANAGER-INSTALLATION-V1\n"
EXECUTOR_ROOT = Path(__file__).resolve().parents[1]
MAX_JOURNAL = 32 * 1024 * 1024
MAX_TRANSACTIONS = 4
DESCRIPTOR = {"schema": 1, "project": metadata.PROJECT, "layout": 1, "configuration_schema": 2}
LAUNCHERS = {"manager_launcher": ("cgp-letsencrypt", "launcher"),
             "certbot_launcher": ("cgp-certbot", "certbot-launcher"),
             "monitor_launcher": ("cgp-monitor", "monitor-launcher")}
UNITS = {"manager_service": "cgp-letsencrypt.service", "manager_timer": "cgp-letsencrypt.timer",
         "monitor_service": "cgp-monitor.service", "monitor_timer": "cgp-monitor.timer"}
TARGETS = ("application", *LAUNCHERS, *UNITS)
PRESERVED = ("runtime", "update_launcher", "machine", "manager_config", "monitor_config", "timer_dropin")
PHASES = {"staged", "applying", "restoring", "applied", "rolled_back"}
TERMINAL = {"applied", "rolled_back"}
CODES = package.CODES | files.CODES | services.CODES | frozenset({
    "unsupported_layout", "unsupported_baseline", "confirmation_mismatch", "installation_pending",
    "journal_invalid", "journal_missing", "transaction_limit", "preserved_changed",
    "configuration_invalid", "update_pending", "update_gate_unsafe"})
_PACKAGE_FIELDS = {"plan_id", "manifest_sha256", "archive_sha256", "inventory_sha256", "key_id",
                   "trust_sha256", "installed_version", "target_version", "expires_at", "sequence", "channel"}


@dataclass(frozen=True)
class Layout:
    """Fixed installed paths. An isolated root is injectable only by Python tests."""
    root: Path = Path("/")

    def path(self, relative):
        return self.root / relative

    @property
    def app(self):
        return self.path("opt/cgp-certificate-manager")

    @property
    def runtime(self):
        return self.path("opt/cgp-update-runtime")

    @property
    def state(self):
        return self.path("var/lib/cgp-update")

    @property
    def locks(self):
        return (self.path("var/lib/cgp-letsencrypt"), self.path("var/lib/cgp-monitor"), self.state)

    def targets(self):
        return {"application": self.app,
                **{key: self.path("usr/local/sbin/" + value[0]) for key, value in LAUNCHERS.items()},
                **{key: self.path("etc/systemd/system/" + value) for key, value in UNITS.items()}}

    def preserved(self):
        return {"runtime": self.runtime, "update_launcher": self.path("usr/local/sbin/cgp-update"),
                "machine": self.path("etc/machine-id"),
                "manager_config": self.path("etc/cgp-letsencrypt/config.json"),
                "monitor_config": self.path("etc/cgp-monitor/config.json"),
                "timer_dropin": self.path("etc/systemd/system/cgp-letsencrypt.timer.d/90-cgp-manager.conf")}


LAYOUT = Layout()


def _require(condition, code):
    if not condition:
        raise UpdateError(code)


def _hash(value):
    return hashlib.sha256(metadata.canonical(value)).hexdigest()


def _token(spec):
    return hashlib.sha256(DOMAIN + metadata.canonical(spec)).hexdigest()


def _options(options):
    paths = {name: package._path(value) for name, value in options.items()}
    _require(paths["installed_root"] == LAYOUT.app and paths["state_dir"] == LAYOUT.state,
             "unsupported_layout")
    _require(EXECUTOR_ROOT == LAYOUT.runtime, "unsupported_baseline")
    trust = paths["trust_path"]
    _require(all(trust != path and path not in trust.parents and trust not in path.parents
                 for path in (LAYOUT.app, LAYOUT.runtime, LAYOUT.state, *LAYOUT.targets().values())), "unsupported_layout")
    return paths


@contextmanager
def _locks(exclusive):
    """M -> N -> U, all noncreating and nonblocking; guards never acquire U."""
    with ExitStack() as stack:
        held = []
        for state in LAYOUT.locks:
            directory = stack.enter_context(storage._directory(state))
            stream = stack.enter_context(storage.open_private(state / "run.lock"))
            fcntl.flock(stream, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
            held.append((state, directory, stream))

        def binding():
            for state, directory, stream in held:
                package._binding(state, directory, stream)

        binding()
        yield binding
        binding()


def _json(path, missing=False):
    raw = package._snapshot(path, MAX_JOURNAL, private=True, missing=missing)
    if raw is None:
        return None
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=metadata._unique,
                           parse_float=metadata._no_float, parse_constant=metadata._no_float)
        _require(value is not None, "journal_invalid")
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise UpdateError("journal_invalid") from None


def _pointer(value):
    _require(type(value) is dict and set(value) == {"schema", "transaction_id"}
             and type(value["schema"]) is int and value["schema"] == 1
             and metadata._hex(value["transaction_id"], (32,)), "journal_invalid")
    return value["transaction_id"]


def _directory(identifier):
    return LAYOUT.state / "installations" / identifier


def _slot(identifier, target):
    path = LAYOUT.targets()[target]
    return path.parent / (".cgp-update-" + identifier + "-" + target)


def _validate(record):
    try:
        _require(type(record) is dict and set(record) == {
            "schema", "transaction_id", "spec", "confirmation_token", "phase", "step"}, "journal_invalid")
        _pointer({key: record[key] for key in ("schema", "transaction_id")})
        spec = record["spec"]
        _require(type(spec) is dict and set(spec) == {
            "layout", "root", "package", "targets", "preserved", "services", "previous"}
            and type(spec["layout"]) is int and spec["layout"] == 1
            and spec["root"] == str(LAYOUT.root), "journal_invalid")
        _require(spec["previous"] is None or metadata._hex(spec["previous"]), "journal_invalid")
        pkg = spec["package"]
        _require(type(pkg) is dict and set(pkg) == _PACKAGE_FIELDS, "journal_invalid")
        for key in ("plan_id", "manifest_sha256", "archive_sha256", "inventory_sha256", "key_id", "trust_sha256"):
            _require(metadata._hex(pkg[key]), "journal_invalid")
        _require(metadata.version(pkg["installed_version"]) < metadata.version(pkg["target_version"], allow_dev=False)
                 and metadata._integer(pkg["expires_at"], 0, metadata.MAX_TIME)
                 and metadata._integer(pkg["sequence"], 1, metadata.MAX_SEQUENCE)
                 and pkg["channel"] in ("stable", "candidate"), "journal_invalid")
        for key, names in (("targets", TARGETS), ("preserved", PRESERVED)):
            _require(type(spec[key]) is dict and set(spec[key]) == set(names), "journal_invalid")
        for item in spec["targets"].values():
            _require(type(item) is dict and set(item) == {"before", "after"}, "journal_invalid")
            files.validate_snapshot(item["before"])
            files.validate_snapshot(item["after"])
            _require(item["after"]["kind"] != "missing", "journal_invalid")
        for item in spec["preserved"].values():
            files.validate_snapshot(item)
        observation = spec["services"]
        _require(type(observation) is dict and set(observation) == {"timers", "services"}
                 and observation["services"] == {value: "inactive" for value in UNITS.values() if value.endswith(".service")}
                 and type(observation["timers"]) is dict
                 and set(observation["timers"]) == {"cgp-letsencrypt.timer", "cgp-monitor.timer"}
                 and all(value in ("active", "inactive") for value in observation["timers"].values()), "journal_invalid")
        _require(metadata._hex(record["confirmation_token"])
                 and hmac.compare_digest(record["confirmation_token"], _token(spec))
                 and record["phase"] in PHASES
                 and metadata._integer(record["step"], 0, 10000), "journal_invalid")
        return record
    except (KeyError, TypeError, ValueError, UpdateError, RecursionError):
        raise UpdateError("journal_invalid") from None


def _load():
    pointer = _json(LAYOUT.state / "installation.json", missing=True)
    pending = _json(LAYOUT.state / "pending.json", missing=True)
    if pointer is None:
        _require(pending is None, "journal_missing")
        _orphan_journals()
        return None
    identifier = _pointer(pointer)
    if pending is not None:
        _require(_pointer(pending) == identifier, "journal_invalid")
    record = _validate(_json(_directory(identifier) / "journal.json"))
    _require(record["transaction_id"] == identifier, "journal_invalid")
    _require(pending is not None or record["phase"] in TERMINAL | {"staged"}, "journal_invalid")
    return record


def _orphan_journals():
    """A lost receipt pointer must not reset approval history or choose a winner."""
    parent = LAYOUT.state / "installations"
    with storage._directory(parent, missing_ok=True) as directory:
        if directory is None:
            return
        names = os.listdir(directory)
        _require(len(names) <= MAX_TRANSACTIONS, "transaction_limit")
        for name in names:
            _require(metadata._hex(name, (32,)), "journal_invalid")
            with storage._directory(parent / name) as child:
                try:
                    os.stat("journal.json", dir_fd=child, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise UpdateError("journal_missing")


def _persist(record, phase):
    record["phase"] = phase
    record["step"] += 1
    _validate(record)
    _require(len(metadata.canonical(record)) <= MAX_JOURNAL, "journal_invalid")
    storage.atomic_text(_directory(record["transaction_id"]) / "journal.json",
                        metadata.canonical(record).decode("ascii"))


def _pending(record):
    pointer = {"schema": 1, "transaction_id": record["transaction_id"]}
    storage.atomic_json(LAYOUT.state / "pending.json", pointer)


def _clear(record):
    with storage._directory(LAYOUT.state) as parent:
        pending = _json(LAYOUT.state / "pending.json", missing=True)
        if pending is not None:
            _require(_pointer(pending) == record["transaction_id"], "journal_invalid")
            os.unlink("pending.json", dir_fd=parent)
        os.fsync(parent)


def _sync_receipt(record):
    """A previous replace may have succeeded while its directory fsync failed."""
    directory = _directory(record["transaction_id"])
    with storage._directory(directory) as parent, storage.open_private(directory / "journal.json") as stream:
        _require(_validate(_json(directory / "journal.json")) == record, "journal_invalid")
        named = os.stat("journal.json", dir_fd=parent, follow_symlinks=False)
        _require(package._identity(named) == package._identity(os.fstat(stream.fileno())), "state_changed")
        with storage._directory(directory) as current:
            _require(package._identity(os.fstat(current)) == package._identity(os.fstat(parent)), "state_changed")
        os.fsync(stream.fileno())
        os.fsync(parent)


def _read_file(snapshot, blobs):
    _require(snapshot["kind"] == "file", "unsupported_baseline")
    return blobs[snapshot["entries"][0]["sha256"]]


def _preserved():
    snapshots, data = {}, {}
    for key, path in LAYOUT.preserved().items():
        snapshots[key], blobs = files.capture(path)
        data[key] = blobs
    _require(snapshots["runtime"]["kind"] == "directory", "unsupported_baseline")
    machine = _read_file(snapshots["machine"], data["machine"])
    _require(0 < len(machine) <= 4096, "unsupported_baseline")
    try:
        storage.check_private_file(LAYOUT.preserved()["manager_config"])
        raw = _read_file(snapshots["manager_config"], data["manager_config"])
        _require(len(raw) <= monitor_config.MAX_CONFIG, "configuration_invalid")
        config = monitor_config.decode(raw)
        _require(type(config) is dict and type(config.get("schema_version")) is int
                 and config["schema_version"] == 2, "configuration_invalid")
        dnsconfig.validate(config)
        dropin = schedule.render(config.get("schedule", {})).encode("utf-8")
        if snapshots["timer_dropin"]["kind"] != "missing":
            _require(_read_file(snapshots["timer_dropin"], data["timer_dropin"]) == dropin, "configuration_invalid")
        if snapshots["monitor_config"]["kind"] != "missing":
            storage.check_private_file(LAYOUT.preserved()["monitor_config"])
            raw = _read_file(snapshots["monitor_config"], data["monitor_config"])
            _require(len(raw) <= monitor_config.MAX_CONFIG, "configuration_invalid")
            monitor_config.validate(monitor_config.decode(raw))
    except (ValueError, KeyError, TypeError, UpdateError, storage.StorageError):
        raise UpdateError("configuration_invalid") from None
    return snapshots


def _matches_preserved(record):
    for key, path in LAYOUT.preserved().items():
        _require(files.capture(path)[0] == record["spec"]["preserved"][key], "preserved_changed")


def _prepared(paths):
    checkpoint = package._load(LAYOUT.state)
    record = checkpoint["prepared"]
    _require(record is not None, "prepared_missing")
    trust, trust_hash = package._trust(paths["trust_path"])
    installed = package._installed(LAYOUT.app)
    _require(trust_hash == record["trust_sha256"] and all(installed[key] == record[key] for key in installed),
             "configuration_changed")
    verified = metadata.verify(record["manifest"].encode("ascii"), record["signature"].encode("ascii"), trust,
                               now=package._now(), current_version=installed["installed_version"],
                               previous=checkpoint["floors"][trust["channel"]])
    stage = LAYOUT.state / "staged" / record["stage"]
    update_archive.validate_stage(stage, record["inventory"])
    inputs = {"manifest": record["manifest"].encode("ascii"), "signature": record["signature"].encode("ascii"),
              "trust": trust, "trust_sha256": trust_hash, "installed": installed}
    package._recheck(paths, inputs)
    verified = package._fresh(inputs, verified)
    public = package._public_plan(record, verified)
    public["trust_sha256"] = trust_hash
    return {key: public[key] for key in _PACKAGE_FIELDS}, stage, record["inventory"]


def _entry(path, kind, mode, uid, gid, data=None):
    entry = {"path": path, "kind": kind, "mode": mode, "uid": uid, "gid": gid, "mtime_ns": 0}
    if data is not None:
        entry.update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
    return entry


def _desired_file(before, data, mode, uid, gid):
    entry = _entry(".", "file", mode, uid, gid, data)
    if before["kind"] == "file":
        previous = before["entries"][0]
        compare = {**previous, "mtime_ns": 0}
        if compare == entry:
            entry = previous.copy()
    return {"kind": "file", "entries": [entry]}


def _payload(stage, inventory, before):
    staged = {}
    for item in inventory["files"]:
        data = package._snapshot(stage / inventory["prefix"] / item["path"], update_archive.MAX_FILE)
        _require(len(data) == item["size"] and package._digest(data) == item["sha256"], "archive_mismatch")
        staged[item["path"]] = (item, data)
    _require("update-install.json" in staged, "unsupported_layout")
    descriptor = metadata._json(staged["update-install.json"][1], 4096, "unsupported_layout")
    _require(type(descriptor) is dict and metadata.canonical(descriptor) == metadata.canonical(DESCRIPTOR), "unsupported_layout")
    app = before["application"]
    _require(app["kind"] == "directory", "unsupported_baseline")
    root = app["entries"][0]
    uid, gid = root["uid"], root["gid"]
    entries = [entry.copy() for entry in app["entries"]
               if not (entry["path"].split("/")[0] == "cgp_cert_manager"
                       or re.fullmatch(r"cgp_certbot_dns-.*\.dist-info", entry["path"].split("/")[0]))]
    distribution = "cgp_certbot_dns-" + inventory["version"] + ".dist-info"
    nodes = {entry["path"] for entry in entries}
    blobs, after = {}, {}
    for path, (item, data) in staged.items():
        if path.startswith(("cgp_cert_manager/", distribution + "/")):
            _require("__pycache__" not in Path(path).parts and not path.endswith((".pyc", ".pyo")), "unsupported_layout")
            parts = path.split("/")
            for index in range(1, len(parts)):
                parent = "/".join(parts[:index])
                if parent not in nodes:
                    entries.append(_entry(parent, "directory", 0o755, uid, gid))
                    nodes.add(parent)
            entry = _entry(path, "file", item["mode"], uid, gid, data)
            entries.append(entry)
            blobs[entry["sha256"]] = data
    after["application"] = {"kind": "directory", "entries": [entries[0]] + sorted(entries[1:], key=lambda entry: entry["path"].encode("utf-8"))}
    templates = {**{key: value[1] for key, value in LAUNCHERS.items()},
                 **{key: "systemd/" + value for key, value in UNITS.items()}}
    for key, source in templates.items():
        _require(source in staged, "unsupported_layout")
        trusted = package._snapshot(LAYOUT.runtime / "templates" / source, update_archive.MAX_FILE)
        _require(staged[source][1] == trusted, "unsupported_layout")
        mode = 0o750 if key in LAUNCHERS else 0o644
        after[key] = _desired_file(before[key], trusted, mode, uid, gid)
        blobs[package._digest(trusted)] = trusted
        if key in LAUNCHERS:
            _require(before[key]["kind"] == "file" and before[key]["entries"][0]["sha256"] == package._digest(trusted)
                     and before[key]["entries"][0]["mode"] == mode, "unsupported_baseline")
        else:
            _require(before[key]["kind"] == "file" and before[key]["entries"][0]["sha256"] == package._digest(trusted),
                     "unsupported_baseline")
    launcher = package._snapshot(LAYOUT.runtime / "templates/update-launcher", update_archive.MAX_FILE)
    _require(package._snapshot(LAYOUT.preserved()["update_launcher"], update_archive.MAX_FILE) == launcher,
             "unsupported_baseline")
    _require(package._snapshot(LAYOUT.runtime / "cgp_update_gate.py", update_archive.MAX_FILE)
             == package._snapshot(LAYOUT.runtime / "cgp_cert_manager/update_gate.py", update_archive.MAX_FILE),
             "unsupported_baseline")
    for snapshot in after.values():
        files.validate_snapshot(snapshot)
    return after, blobs


def _review(paths, previous):
    pkg, stage, inventory = _prepared(paths)
    preserved = _preserved()
    before, blobs = {}, {}
    for key, path in LAYOUT.targets().items():
        before[key], data = files.capture(path)
        blobs.update(data)
    after, data = _payload(stage, inventory, before)
    blobs.update(data)
    spec = {"layout": 1, "root": str(LAYOUT.root), "package": pkg,
            "targets": {key: {"before": before[key], "after": after[key]} for key in TARGETS},
            "preserved": preserved, "services": services.observe(),
            "previous": _hash(previous) if previous is not None else None}
    return spec, blobs


def _public(record):
    spec = record["spec"]
    return {"transaction_id": record["transaction_id"], "phase": record["phase"],
            "confirmation_token": record["confirmation_token"], **spec["package"],
            "targets": {key: {side: files.fingerprint(item[side]) for side in ("before", "after")}
                        for key, item in spec["targets"].items()},
            "timers": {"before": spec["services"]["timers"], "after": "stopped", "enablement": "preserved"},
            "configuration": "preserved_without_migration", "automatic_rollback": False}


def _new_record(spec, identifier):
    return {"schema": 1, "transaction_id": identifier, "spec": spec,
            "confirmation_token": _token(spec), "phase": "staged", "step": 0}


def _changed(record):
    return {key: item for key, item in record["spec"]["targets"].items() if item["before"] != item["after"]}


def _check_live(record, side=None):
    changed = _changed(record)
    for key, path in LAYOUT.targets().items():
        item = record["spec"]["targets"][key]
        if side is not None or key not in changed:
            _require(files.capture(path)[0] == item[side or "before"], "filesystem_unknown")
        else:
            _require(files.classify(path, _slot(record["transaction_id"], key), item["before"], item["after"]) != "unknown",
                     "filesystem_unknown")


def _backups(record):
    return files.load_blobs(_directory(record["transaction_id"]) / "blobs",
                            [snapshot for item in record["spec"]["targets"].values() for snapshot in item.values()])


def _capacity():
    parent = LAYOUT.state / "installations"
    storage.ensure_private_directory(parent)
    with storage._directory(parent) as directory:
        names = os.listdir(directory)
        _require(len(names) < MAX_TRANSACTIONS, "transaction_limit")
        _require(all(metadata._hex(name, (32,)) for name in names), "journal_invalid")


def _existing():
    record = _load()
    if record is not None:
        _require(record["phase"] in TERMINAL, "installation_pending")
    update_gate.require_idle(LAYOUT.state)
    return record


def _window(spec, started):
    now = package._now()
    _require(now >= started, "clock_moved_backwards")
    _require(now < spec["package"]["expires_at"], "expired_manifest")


def _finish(record, phase, binding):
    _matches_preserved(record)
    _check_live(record, "after" if phase == "applied" else "before")
    if phase == "rolled_back":
        services.reload(recovery=True)
    else:
        services.reload()
    _matches_preserved(record)
    _check_live(record, "after" if phase == "applied" else "before")
    binding()
    _persist(record, phase)
    _sync_receipt(record)
    _matches_preserved(record)
    _check_live(record, "after" if phase == "applied" else "before")
    binding()
    _clear(record)


def _install(paths, confirmation_token, binding):
    _require(metadata._hex(confirmation_token), "confirmation_mismatch")
    started = package._now()
    previous = _existing()
    spec, blobs = _review(paths, previous)
    _require(hmac.compare_digest(confirmation_token, _token(spec)), "confirmation_mismatch")
    _capacity()
    identifier = secrets.token_hex(16)
    directory = _directory(identifier)
    # Existing directories are never reused, including an interrupted attempt.
    with storage._directory(directory.parent) as parent:
        os.mkdir(identifier, mode=0o700, dir_fd=parent)
        os.fsync(parent)
    record = _new_record(spec, identifier)
    files.save_blobs(directory / "blobs", blobs)
    for key, item in _changed(record).items():
        files.prepare_slot(LAYOUT.targets()[key], _slot(identifier, key), item["after"], blobs)
    _backups(record)
    # Fresh signatures, trust, staged bytes, every preimage and timer observation
    # must still describe the approved installation after potentially slow I/O.
    current, _ = _review(paths, previous)
    _require(hmac.compare_digest(confirmation_token, _token(current)), "confirmation_mismatch")
    binding()
    _window(spec, started)
    _persist(record, "staged")
    storage.atomic_json(LAYOUT.state / "installation.json", {"schema": 1, "transaction_id": identifier})
    _window(spec, started)
    _pending(record)
    services.stop()
    _require(_prepared(paths)[0] == spec["package"], "configuration_changed")
    _matches_preserved(record)
    _check_live(record)
    _window(spec, started)
    for key, item in _changed(record).items():
        binding()
        files.apply_target(LAYOUT.targets()[key], _slot(identifier, key), item["before"], item["after"],
                           checkpoint=lambda _event: _persist(record, "applying"))
    _finish(record, "applied", binding)
    return record


def _recover(binding):
    record = _load()
    _require(record is not None, "journal_missing")
    _matches_preserved(record)
    _backups(record)
    _check_live(record)
    missing_units = tuple(unit for key, unit in UNITS.items()
                          if files.capture(LAYOUT.targets()[key])[0]["kind"] == "missing")
    if record["phase"] in TERMINAL:
        _check_live(record, "after" if record["phase"] == "applied" else "before")
        services.stop(recovery=True, missing_units=missing_units)
        services.reload(recovery=True)
        _sync_receipt(record)
        _matches_preserved(record)
        _check_live(record, "after" if record["phase"] == "applied" else "before")
        binding()
        _clear(record)
        return record
    binding()
    _pending(record)
    services.stop(recovery=True, missing_units=missing_units)
    _persist(record, "restoring")
    _matches_preserved(record)
    _check_live(record)
    for key, item in reversed(list(_changed(record).items())):
        binding()
        files.restore_target(LAYOUT.targets()[key], _slot(record["transaction_id"], key), item["before"], item["after"],
                             checkpoint=lambda _event: _persist(record, "restoring"))
    _finish(record, "rolled_back", binding)
    return record


def _result(action, status, record=None, error=None):
    return {"schema": 1, "action": action, "status": status,
            "plan": _public(record) if record is not None else None, "error": error}


def _run(action, options, token=None):
    try:
        paths = _options(options)
        with _locks(action != "review") as binding:
            if action == "review":
                started = package._now()
                spec, _ = _review(paths, _existing())
                record = _new_record(spec, "0" * 32)
                binding()
                _window(spec, started)
                result = _result(action, "review_ready", record)
                result["plan"].update(transaction_id=None, phase="review_ready")
                return result
            record = _install(paths, token, binding) if action == "apply" else _recover(binding)
            return _result(action, record["phase"], record)
    except BlockingIOError:
        code = "state_busy"
    except (UpdateError, update_gate.PendingUpdateError, services.SystemdError) as exc:
        code = exc.code if type(exc.code) is str and exc.code in CODES else "update_failed"
    except (FileNotFoundError, storage.StorageError):
        code = "state_invalid"
    except Exception:
        code = "update_failed"
    pending = False
    try:
        update_gate.require_idle(LAYOUT.state)
    except update_gate.PendingUpdateError:
        pending = True
    return _result(action, "recovery_required" if pending else "error", error=code)


def review(*, trust_path, installed_root, state_dir):
    return _run("review", locals())


def apply(*, trust_path, installed_root, state_dir, confirmation_token):
    return _run("apply", {"trust_path": trust_path, "installed_root": installed_root, "state_dir": state_dir}, confirmation_token)


def recover(*, trust_path, installed_root, state_dir):
    return _run("recover", locals())


def status(*, trust_path, installed_root, state_dir):
    """Prefer an installation receipt even when trust, stage or app is absent."""
    if Path(installed_root) != LAYOUT.app or Path(state_dir) != LAYOUT.state:
        return None
    try:
        with package._shared(LAYOUT.state) as locked:
            if not locked:
                return None
            record = _load()
            if record is None:
                return None
            pending = package._snapshot(LAYOUT.state / "pending.json", 4096, private=True, missing=True)
            phase = record["phase"] if record["phase"] in TERMINAL and pending is None else "recovery_required"
            return _result("status", phase, record)
    except BlockingIOError:
        return _result("status", "busy", error="state_busy")
    except Exception:
        return _result("status", "recovery_required", error="journal_invalid")
