"""Explicit, audited acceptance of previous settings without TLS proof.

Callers hold the manager operation lock. This module never writes to CGP and
never treats operator acknowledgement as proof of a working certificate.
"""
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from . import core, recovery, storage
from .transactions import Journal, JournalError, classify, sync_directory, validate


DECISION = "acknowledge_previous_unverified"
ELIGIBLE_PHASES = ("prepared", "restoring")
WITNESS_FIELDS = {"dev", "ino", "size", "mtime_ns", "ctime_ns"}
AUTH_FIELDS = {"schema", "decision", "domain", "config_identity", "confirmation_token",
               "journal", "witness", "reason", "uid", "authorized_at", "tls"}
COMPLETION_FIELDS = {"schema", "confirmation_token", "domain", "authorization_digest",
                     "completed_at", "tls"}
_MISSING = object()


def _digest(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def _token(snapshot):
    return _digest({"decision": DECISION, "snapshot": snapshot})


def _valid_token(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _reason(value):
    if not isinstance(value, str):
        raise JournalError("Acknowledgement reason must be text")
    if not value.isprintable():
        raise JournalError("Acknowledgement reason must not contain control characters")
    value = value.strip()
    if not 1 <= len(value) <= 500:
        raise JournalError("Acknowledgement reason must contain 1 to 500 printable characters")
    return value


def _timestamp(value):
    try:
        valid = isinstance(value, str) and value.endswith("+00:00") and datetime.fromisoformat(value).utcoffset() == timezone.utc.utcoffset(None)
    except ValueError:
        valid = False
    if not valid:
        raise JournalError("Invalid resolution audit timestamp")


def _now():
    return datetime.now(timezone.utc).isoformat()


def _read_json(path):
    try:
        with storage.open_private(path) as stream:
            return json.load(stream)
    except FileNotFoundError:
        return _MISSING
    except (ValueError, UnicodeError):
        raise JournalError("Corrupt resolution audit") from None


def _validate_authorization(value, token):
    if not isinstance(value, dict) or set(value) != AUTH_FIELDS or type(value.get("schema")) is not int or value["schema"] != 1:
        raise JournalError("Invalid resolution authorization schema")
    if value["decision"] != DECISION or value["tls"] != "unverified" or value["confirmation_token"] != token:
        raise JournalError("Invalid resolution authorization identity")
    domain = value["domain"]
    if not isinstance(domain, str):
        raise JournalError("Invalid resolution domain")
    core.identifier(domain)
    record = validate(value["journal"], domain)
    if record["phase"] not in ELIGIBLE_PHASES or value["config_identity"] != record["config_identity"]:
        raise JournalError("Invalid resolution transaction binding")
    witness = value["witness"]
    if not isinstance(witness, dict) or set(witness) != WITNESS_FIELDS or any(type(item) is not int or item < 0 for item in witness.values()):
        raise JournalError("Invalid resolution file witness")
    if _token({"record": record, "witness": witness}) != token:
        raise JournalError("Resolution token does not match its evidence")
    if _reason(value["reason"]) != value["reason"] or type(value["uid"]) is not int or value["uid"] < 0:
        raise JournalError("Invalid resolution operator metadata")
    _timestamp(value["authorized_at"])
    return value


def _validate_completion(value, authorization):
    if not isinstance(value, dict) or set(value) != COMPLETION_FIELDS or type(value.get("schema")) is not int or value["schema"] != 1:
        raise JournalError("Invalid resolution completion schema")
    if (value["confirmation_token"] != authorization["confirmation_token"] or value["domain"] != authorization["domain"]
            or value["authorization_digest"] != _digest(authorization) or value["tls"] != "unverified"):
        raise JournalError("Resolution completion does not match authorization")
    _timestamp(value["completed_at"])
    return value


def _audits(state):
    state = Path(state)
    if not storage.check_private_directory(state, missing_ok=True):
        return []
    directory = state / "resolutions"
    if not storage.check_private_directory(directory, missing_ok=True):
        return []
    storage.validate_tree(directory)
    result = []
    for bundle in sorted(directory.iterdir()):
        if not _valid_token(bundle.name):
            raise JournalError("Invalid resolution audit directory name")
        storage.check_private_directory(bundle)
        authorization = _read_json(bundle / "authorization.json")
        completion = _read_json(bundle / "completion.json")
        if authorization is _MISSING:
            if completion is not _MISSING:
                raise JournalError("Resolution completion has no authorization")
            continue  # An interrupted attempt may have created only a directory.
        authorization = _validate_authorization(authorization, bundle.name)
        if completion is not _MISSING:
            completion = _validate_completion(completion, authorization)
        else:
            completion = None
        result.append((bundle, authorization, completion))
    return result


def _sync_audit(bundle, completed=False):
    """Reaffirm existing evidence too: a previous directory fsync may have failed."""
    names = ["authorization.json", "completion.json"] if completed else ["authorization.json"]
    for name in names:
        with storage.open_private(bundle / name) as stream:
            os.fsync(stream.fileno())
    for directory in (bundle, bundle.parent, bundle.parent.parent):
        sync_directory(directory)


def _check_previous(cfg, record, identity):
    if record["config_identity"] != identity:
        raise JournalError("Transaction belongs to another server configuration")
    if record["phase"] not in ELIGIBLE_PHASES:
        raise JournalError("Run --recover before acknowledging this transaction phase")
    state = classify(record, core.current(cfg, record["domain"]))
    if state not in ("previous", "both"):
        raise JournalError("CGP does not exactly match previous settings; acknowledgement refused")
    return state


def _matching_snapshot(journal, domain, token, present):
    snapshot = journal.read_snapshot(domain)
    if (snapshot is not None) != present or (snapshot is not None and _token(snapshot) != token):
        raise JournalError("Transaction instance changed; obtain a new confirmation token")
    return snapshot


def assert_no_incomplete(state=None):
    """Normal runs may only use completed receipts, never finish an approval."""
    state = core.STATE if state is None else Path(state)
    journal = Journal(state / "transactions")
    for bundle, authorization, completion in _audits(state):
        if completion is None:
            raise JournalError("Unfinished operator acknowledgement requires explicit retry")
        snapshot = journal.read_snapshot(authorization["domain"])
        if snapshot is not None and _token(snapshot) == authorization["confirmation_token"]:
            raise JournalError("Completed acknowledgement still has its pending transaction")
        _sync_audit(bundle, completed=True)


def pending_status(cfg, domain=None):
    """Read-only status for incomplete approvals whose pending file is absent."""
    if domain is not None:
        core.identifier(domain)
    rows = []
    journal = Journal(core.STATE / "transactions")
    for _, authorization, completion in _audits(core.STATE):
        name = authorization["domain"]
        if completion is not None or (domain is not None and domain != name) or journal.read_snapshot(name) is not None:
            continue
        matches = authorization["config_identity"] == recovery.server_identity(cfg)
        state = classify(authorization["journal"], core.current(cfg, name)) if matches else "foreign"
        rows.append({"domain": name, "phase": "acknowledging", "state": state,
                     "server_matches": matches, "tls": "unverified"})
    return rows


def preview(cfg, domain):
    """Produce a fresh explicit confirmation token without writing anything."""
    core.identifier(domain)
    audits = [item for item in _audits(core.STATE) if item[1]["domain"] == domain]
    incomplete = [item for item in audits if item[2] is None]
    if len(incomplete) > 1:
        raise JournalError("Multiple unfinished acknowledgements require investigation")
    journal = Journal(core.STATE / "transactions")
    snapshot = journal.read_snapshot(domain)
    if snapshot is None:
        if not incomplete:
            raise JournalError("No pending transaction eligible for acknowledgement")
        authorization = incomplete[0][1]
        record, token = authorization["journal"], authorization["confirmation_token"]
    else:
        record, token = snapshot["record"], _token(snapshot)
        if incomplete and incomplete[0][1]["confirmation_token"] != token:
            raise JournalError("Transaction instance changed after authorization")
        if any(item[2] is not None and item[1]["confirmation_token"] == token for item in audits):
            raise JournalError("Completed acknowledgement cannot be replayed against a pending transaction")
    state = _check_previous(cfg, record, recovery.server_identity(cfg))
    return {"domain": domain, "phase": record["phase"] if snapshot is not None else "acknowledging",
            "state": state, "server_matches": True, "confirmation_token": token, "tls": "unverified",
            "pending_journal": snapshot is not None, "authorization_recorded": bool(incomplete)}


def _write_completion(bundle, authorization):
    completion = {"schema": 1, "confirmation_token": authorization["confirmation_token"],
                  "domain": authorization["domain"], "authorization_digest": _digest(authorization),
                  "completed_at": _now(), "tls": "unverified"}
    storage.atomic_json(bundle / "completion.json", completion)


def acknowledge(cfg, domain, token, reason):
    """Retire exactly one reviewed previous snapshot, with durable audit proof."""
    core.identifier(domain)
    if not _valid_token(token):
        raise JournalError("Invalid confirmation token")
    reason = _reason(reason)
    audits = _audits(core.STATE)
    if sum(item[1]["domain"] == domain and item[2] is None for item in audits) > 1:
        raise JournalError("Multiple unfinished acknowledgements require investigation")
    existing = next((item for item in audits if item[1]["confirmation_token"] == token), None)
    journal = Journal(core.STATE / "transactions")
    snapshot = journal.read_snapshot(domain)
    present = snapshot is not None
    if present and _token(snapshot) != token:
        raise JournalError("Transaction instance changed; obtain a new confirmation token")
    if existing is None:
        if not present:
            raise JournalError("No matching transaction or authorization")
        if any(item[1]["domain"] == domain and item[2] is None for item in audits):
            raise JournalError("Another unfinished acknowledgement requires investigation")
        record = snapshot["record"]
        _check_previous(cfg, record, recovery.server_identity(cfg))
        authorization = {"schema": 1, "decision": DECISION, "domain": domain,
                         "config_identity": record["config_identity"], "confirmation_token": token,
                         "journal": record, "witness": snapshot["witness"], "reason": reason,
                         "uid": os.geteuid(), "authorized_at": _now(), "tls": "unverified"}
        bundle = core.STATE / "resolutions" / token
        storage.ensure_private_directory(bundle)
        storage.atomic_json(bundle / "authorization.json", authorization)
        completion = None
    else:
        bundle, authorization, completion = existing
        if authorization["domain"] != domain or authorization["reason"] != reason:
            raise JournalError("Existing authorization belongs to another domain or reason")
        record = authorization["journal"]
        _check_previous(cfg, record, recovery.server_identity(cfg))
        if completion is not None and present:
            raise JournalError("Completed acknowledgement cannot be replayed against a pending transaction")
    _sync_audit(bundle, completed=completion is not None)
    _matching_snapshot(journal, domain, token, present)
    _check_previous(cfg, record, recovery.server_identity(cfg))
    _matching_snapshot(journal, domain, token, present)
    if completion is None:
        if present:
            journal.path(domain).unlink()
        sync_directory(journal.directory)
        _write_completion(bundle, authorization)
        _sync_audit(bundle, completed=True)
    return {"domain": domain, "result": "acknowledged_unverified", "tls": "unverified",
            "confirmation_token": token}
