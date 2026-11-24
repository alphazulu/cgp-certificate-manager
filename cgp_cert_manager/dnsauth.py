"""Durable ownership receipts for disposable Cloudflare DNS-01 records.

Callers hold the manager operation lock throughout the Certbot attempt.  A lost
create response remains unresolved until the exact ownership marker is found;
an empty lookup is never evidence that an uncertain POST did not take effect.
"""

import json
from pathlib import Path
import re
import secrets
from urllib.error import HTTPError

from . import core, recovery, storage
from .transactions import sync_directory


class DNSAuthError(core.Error):
    """A deliberately secret-free DNS challenge failure."""


_FIELDS = {"schema", "identity", "attempt", "owner", "credentials", "zone", "name", "value",
           "record", "phase"}
_PHASES = {"intent", "created", "borrowed", "complete"}


def _hex(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32}", value) is not None


def _credentials(cfg):
    accounts = cfg.get("cloudflare_accounts") or [{"credentials": cfg.get("cloudflare_credentials")}]
    paths = set()
    for account in accounts:
        path = account["credentials"]
        if not isinstance(path, str) or not path:
            raise DNSAuthError("Invalid DNS credentials configuration")
        paths.add(str(Path(path).absolute()))
    return paths


def challenge_name(identifier, value):
    name, error = core.dns_name(identifier)
    if error or not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
        raise DNSAuthError("Invalid DNS challenge")
    return "_acme-challenge." + name.removeprefix("*.")


def _directory(create=False):
    root = core.STATE / "dns-challenges"
    if create:
        storage.ensure_private_directory(core.STATE)
        storage.ensure_private_directory(root)
    else:
        storage.check_private_directory(core.STATE, missing_ok=True)
    storage.validate_tree(root)
    return root


def _validate(path, record, credentials, identity):
    if (not isinstance(record, dict) or set(record) != _FIELDS
            or type(record["schema"]) is not int or record["schema"] != 1
            or record["identity"] != identity
            or not _hex(path.stem) or not _hex(record["attempt"])
            or record["owner"] != "cgp-certificate-manager:" + path.stem
            or not isinstance(record["credentials"], str) or record["credentials"] not in credentials
            or not _hex(record["zone"])
            or not isinstance(record["name"], str) or not record["name"].startswith("_acme-challenge.")
            or record["name"] != challenge_name(record["name"][16:], record["value"])
            or not isinstance(record["phase"], str) or record["phase"] not in _PHASES
            or (record["record"] is not None and not _hex(record["record"]))
            or (record["phase"] == "intent" and record["record"] is not None)
            or (record["phase"] not in ("intent", "complete") and record["record"] is None)):
        raise DNSAuthError("Invalid DNS challenge receipt")
    return record


def _records(cfg):
    root = _directory()
    paths = storage.private_files(root)
    if not paths:
        return []
    credentials = _credentials(cfg)
    identity = recovery.server_identity(cfg)
    return [(path, _validate(path, json.loads(storage.read_text(path)), credentials, identity))
            for path in paths]


def _api(record, method="GET", record_id=None, params=None, data=None, zone=False):
    endpoint = "zones/" + record["zone"]
    if not zone:
        endpoint += "/dns_records"
    if record_id is not None:
        endpoint += "/" + record_id
    try:
        response = core.cf(record["credentials"], endpoint, method=method, params=params, data=data)
    except core.CloudflareRejected:
        if method == "POST":
            raise
        raise DNSAuthError("DNS provider operation failed") from None
    except HTTPError as error:
        if method == "GET" and record_id is not None and error.code == 404:
            return None
        raise DNSAuthError("DNS provider operation failed") from None
    except Exception:
        raise DNSAuthError("DNS provider operation failed") from None
    if not isinstance(response, dict):
        raise DNSAuthError("Invalid DNS provider response")
    return response


def _matches(remote, receipt, owned=False):
    return (remote.get("type") == "TXT" and remote.get("name") == receipt["name"]
            and remote.get("content") in (receipt["value"], '"' + receipt["value"] + '"')
            and (not owned or remote.get("comment") == receipt["owner"]))


def _listed(receipt, exact_name=True, require_complete=False):
    require_complete = require_complete or not exact_name
    records = []
    page = 1
    expected_pages = None
    expected_count = None
    while True:
        params = {"page": page, "per_page": 100}
        if exact_name:
            params.update(type="TXT", name=receipt["name"])
        response = _api(receipt, params=params)
        values = response.get("result")
        info = response.get("result_info", {})
        pages = info.get("total_pages", 1) if isinstance(info, dict) else None
        if (not isinstance(values, list) or any(not isinstance(value, dict) for value in values)
                or type(pages) is not int or not 0 <= pages <= 100):
            raise DNSAuthError("Invalid DNS provider response")
        if pages == 0:
            if (page != 1 or values
                    or any(type(info.get(key)) is not int for key in ("page", "count", "total_count"))
                    or (info["page"], info["count"], info["total_count"]) != (1, 0, 0)):
                raise DNSAuthError("Invalid empty DNS provider listing")
            pages = 1
        if require_complete:
            count = info.get("total_count")
            if ("total_pages" not in info or type(info.get("page")) is not int
                    or type(info.get("count")) is not int
                    or info["page"] != page or info["count"] != len(values)
                    or type(count) is not int or count < 0
                    or (expected_pages is not None and pages != expected_pages)
                    or (expected_count is not None and count != expected_count)):
                raise DNSAuthError("Incomplete DNS provider listing")
            expected_pages, expected_count = pages, count
        records.extend(values)
        if page >= pages:
            if require_complete and (len(records) != expected_count or
                    len({_record_id(remote) for remote in records}) != len(records)):
                raise DNSAuthError("Incomplete DNS provider listing")
            return records
        page += 1


def _record_id(remote):
    record_id = remote.get("id") if isinstance(remote, dict) else None
    if not _hex(record_id):
        raise DNSAuthError("Invalid DNS provider record identity")
    return record_id


def _remove(path):
    path.unlink(missing_ok=True)
    sync_directory(path.parent)


def _finish(path, record):
    record["phase"] = "complete"
    storage.atomic_json(path, record)
    _remove(path)


def _confirm_absent(record):
    # A generic record GET 404 can also hide a zone or permission failure.
    # Require access to the exact zone and a complete unfiltered record list;
    # filtering on the old TXT name would miss a record renamed by an operator.
    response = _api(record, zone=True)
    if _record_id(response.get("result")) != record["zone"]:
        raise DNSAuthError("DNS challenge zone is unavailable")
    if any(remote["id"] == record["record"] for remote in _listed(record, exact_name=False)):
        raise DNSAuthError("DNS challenge deletion remains unresolved")


def _cleanup_one(path, record):
    if record["phase"] == "complete":
        _remove(path)
        return
    if record["phase"] == "borrowed":
        _finish(path, record)
        return
    if record["phase"] == "intent":
        matches = [remote for remote in _listed(record, require_complete=True)
                   if _matches(remote, record, owned=True)]
        if len(matches) != 1:
            raise DNSAuthError("DNS challenge creation remains unresolved")
        record["record"] = _record_id(matches[0])
        record["phase"] = "created"
        storage.atomic_json(path, record)
    response = _api(record, record_id=record["record"])
    if response is None:
        _confirm_absent(record)
        _finish(path, record)
        return
    remote = response.get("result")
    if (_record_id(remote) != record["record"] or not _matches(remote, record, owned=True)):
        raise DNSAuthError("DNS challenge ownership changed; cleanup is pending")
    deleted = _api(record, method="DELETE", record_id=record["record"])
    if _record_id(deleted.get("result")) != record["record"]:
        raise DNSAuthError("DNS challenge deletion remains unresolved")
    _finish(path, record)


def _cleanup(cfg, attempt=None):
    records = _records(cfg)  # Validate every receipt before any remote deletion.
    failed = False
    for path, record in records:
        if attempt is not None and record["attempt"] != attempt:
            continue
        try:
            _cleanup_one(path, record)
        except Exception:
            failed = True
    root = core.STATE / "dns-challenges"
    if storage.check_private_directory(root, missing_ok=True):
        sync_directory(root)  # Also retry an interrupted final directory sync.
    if failed:
        raise DNSAuthError("DNS challenge cleanup is pending")


def cleanup_pending(cfg):
    """Clean provably owned records; keep uncertain receipts for a later retry."""
    try:
        _cleanup(cfg)
    except Exception:
        raise DNSAuthError("DNS challenge cleanup is pending") from None


def status(cfg):
    """Return validated public receipt metadata without writing or querying DNS."""
    try:
        return [{"id": path.stem, "name": record["name"], "phase": record["phase"],
                 "owned": True if record["phase"] == "created" else
                          False if record["phase"] == "borrowed" else None,
                 "zone": record["zone"]}
                for path, record in _records(cfg)]
    except Exception:
        raise DNSAuthError("DNS challenge receipts are unsafe or unreadable") from None


def assert_clear(cfg):
    """Block every new issuance while a cleanup receipt remains unresolved."""
    if status(cfg):
        raise DNSAuthError("Pending DNS challenges block certificate issuance; "
                           "inspect --dns-transactions and run --dns-cleanup")


class Session:
    """One Certbot batch, including multiple accounts and repeated TXT names."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.attempt = secrets.token_hex(16)

    def create(self, identifier, value, zones):
        """Create one TXT after saving intent, or borrow an existing identical TXT."""
        try:
            name = challenge_name(identifier, value)
            zone = core.zone_for(name[16:], zones)
            if zone is None:
                raise DNSAuthError("No DNS challenge zone")
            source = zones[zone]
            credentials = str(Path(source["credentials"]).absolute())
            if credentials not in _credentials(self.cfg) or not _hex(source["id"]):
                raise DNSAuthError("Invalid DNS challenge zone")
            storage.check_private_file(credentials)
            nonce = secrets.token_hex(16)
            path = _directory(create=True) / (nonce + ".json")
            if storage.check_private_file(path, missing_ok=True):
                raise DNSAuthError("DNS challenge receipt already exists")
            record = {"schema": 1, "identity": recovery.server_identity(self.cfg), "attempt": self.attempt,
                      "owner": "cgp-certificate-manager:" + nonce,
                      "credentials": credentials, "zone": source["id"], "name": name,
                      "value": value, "record": None, "phase": "intent"}
            existing = [remote for remote in _listed(record) if _matches(remote, record)]
            if existing:
                record.update(phase="borrowed", record=_record_id(existing[0]))
                storage.atomic_json(path, record)
                return
            storage.atomic_json(path, record)
            try:
                response = _api(record, method="POST", data={"type": "TXT", "name": name,
                                "content": '"' + value + '"', "ttl": 120, "comment": record["owner"]})
            except core.CloudflareRejected:
                # A validated rejection proves this single-record POST had no
                # effect.  Persist completion before removing its intent so an
                # interrupted unlink can finish without guessing remote state.
                _finish(path, record)
                raise DNSAuthError("DNS provider rejected challenge creation") from None
            remote = response.get("result")
            record_id = _record_id(remote)
            if not _matches(remote, record, owned=True):
                raise DNSAuthError("Invalid DNS provider created record")
            record.update(phase="created", record=record_id)
            storage.atomic_json(path, record)
        except Exception:
            raise DNSAuthError("DNS challenge creation failed; cleanup may be pending") from None

    def cleanup(self):
        try:
            _cleanup(self.cfg, self.attempt)
        except Exception:
            raise DNSAuthError("DNS challenge cleanup is pending") from None
