"""Durable provider-bound ownership receipts for disposable DNS-01 records.

Callers hold the manager operation lock throughout the Certbot attempt.  A lost
create response remains unresolved until the exact ownership marker is found;
an empty lookup is never evidence that an uncertain POST did not take effect.
"""

import json
from pathlib import Path
import re
import secrets

from . import core, dnsproviders, recovery, storage
from .transactions import sync_directory


class DNSAuthError(core.Error):
    """A deliberately secret-free DNS challenge failure."""


_FIELDS = {"schema", "identity", "attempt", "owner", "credentials", "zone", "name", "value",
           "record", "phase"}
_PHASES = {"intent", "created", "borrowed", "complete"}


def _hex(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32}", value) is not None


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


def _validate(path, record, credentials, identity, provider):
    schema = record.get("schema") if isinstance(record, dict) else None
    expected = _FIELDS | ({"provider"} if schema == 2 else set())
    # Legacy receipts were exclusively Cloudflare. Never reinterpret their
    # provider from a later configuration or manufacture a historical binding.
    provider_id = "cloudflare" if schema == 1 else record.get("provider") if isinstance(record, dict) else None
    if (not isinstance(record, dict) or set(record) != expected
            or type(schema) is not int or schema not in (1, 2)
            or provider_id != provider.provider_id
            or record["identity"] != identity
            or not _hex(path.stem) or not _hex(record["attempt"])
            or record["owner"] != "cgp-certificate-manager:" + path.stem
            or not isinstance(record["credentials"], str) or record["credentials"] not in credentials
            or not provider.valid_zone_id(record["zone"])
            or not isinstance(record["name"], str) or not record["name"].startswith("_acme-challenge.")
            or record["name"] != challenge_name(record["name"][16:], record["value"])
            or not isinstance(record["phase"], str) or record["phase"] not in _PHASES
            or (record["record"] is not None and not provider.valid_record_id(record["record"]))
            or (record["phase"] == "intent" and record["record"] is not None)
            or (record["phase"] not in ("intent", "complete") and record["record"] is None)):
        raise DNSAuthError("Invalid DNS challenge receipt")
    return record


def _records(cfg):
    root = _directory()
    paths = storage.private_files(root)
    if not paths:
        return []
    provider = dnsproviders.get_provider(cfg)
    provider.require("owned_txt")
    credentials = dnsproviders.credentials(cfg, absolute=True)
    identity = recovery.server_identity(cfg)
    return [(path, _validate(path, json.loads(storage.read_text(path)), credentials, identity, provider), provider)
            for path in paths]


def _remove(path):
    path.unlink(missing_ok=True)
    sync_directory(path.parent)


def _finish(path, record):
    record["phase"] = "complete"
    storage.atomic_json(path, record)
    _remove(path)


def _cleanup_one(path, record, provider):
    if record["phase"] == "complete":
        _remove(path)
        return
    if record["phase"] == "borrowed":
        _finish(path, record)
        return
    if record["phase"] == "intent":
        matches = [remote for remote in provider.list_records(record, require_complete=True)
                   if provider.matches(remote, record, owned=True)]
        if len(matches) != 1:
            raise DNSAuthError("DNS challenge creation remains unresolved")
        record["record"] = provider.record_id(matches[0])
        record["phase"] = "created"
        storage.atomic_json(path, record)
    remote = provider.get_record(record)
    if remote is None:
        provider.confirm_absent(record)
        _finish(path, record)
        return
    if (provider.record_id(remote) != record["record"] or not provider.matches(remote, record, owned=True)):
        raise DNSAuthError("DNS challenge ownership changed; cleanup is pending")
    provider.delete_record(record)
    _finish(path, record)


def _cleanup(cfg, attempt=None):
    records = _records(cfg)  # Validate every receipt before any remote deletion.
    failed = False
    for path, record, provider in records:
        if attempt is not None and record["attempt"] != attempt:
            continue
        try:
            _cleanup_one(path, record, provider)
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
                for path, record, _provider in _records(cfg)]
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
            provider = dnsproviders.get_provider(self.cfg)
            provider.require("owned_txt")
            zone = core.zone_for(name[16:], zones)
            if zone is None:
                raise DNSAuthError("No DNS challenge zone")
            source = zones[zone]
            credentials = str(Path(source["credentials"]).absolute())
            if (source.get("provider", "cloudflare") != provider.provider_id
                    or credentials not in dnsproviders.credentials(self.cfg, absolute=True)
                    or not provider.valid_zone_id(source["id"])):
                raise DNSAuthError("Invalid DNS challenge zone")
            storage.check_private_file(credentials)
            nonce = secrets.token_hex(16)
            path = _directory(create=True) / (nonce + ".json")
            if storage.check_private_file(path, missing_ok=True):
                raise DNSAuthError("DNS challenge receipt already exists")
            record = {"schema": 2, "provider": provider.provider_id,
                      "identity": recovery.server_identity(self.cfg), "attempt": self.attempt,
                      "owner": "cgp-certificate-manager:" + nonce,
                      "credentials": credentials, "zone": source["id"], "name": name,
                      "value": value, "record": None, "phase": "intent"}
            existing = [remote for remote in provider.list_records(record) if provider.matches(remote, record)]
            if existing:
                record.update(phase="borrowed", record=provider.record_id(existing[0]))
                storage.atomic_json(path, record)
                return
            storage.atomic_json(path, record)
            try:
                remote = provider.create_txt(record)
            except dnsproviders.ProviderRejected:
                # A validated rejection proves this single-record POST had no
                # effect.  Persist completion before removing its intent so an
                # interrupted unlink can finish without guessing remote state.
                _finish(path, record)
                raise DNSAuthError("DNS provider rejected challenge creation") from None
            record_id = provider.record_id(remote)
            if not provider.matches(remote, record, owned=True):
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
