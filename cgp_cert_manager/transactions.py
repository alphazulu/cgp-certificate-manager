"""Durable write-ahead journal. Callers must hold the manager operation lock."""
import json
import os
import re
from pathlib import Path

from . import core, storage

PHASES = {
    "prepared": {"applying", "restoring"},
    "applying": {"applied", "restoring"},
    "applied": {"verifying", "restoring"},
    "verifying": {"committed", "restoring"},
    "restoring": {"restored"},
    "committed": set(),
    "restored": set(),
}
RECORD_FIELDS = {
    "schema", "domain", "phase", "previous", "intended", "endpoints",
    "previous_endpoints", "config_identity",
}

class JournalError(core.Error):
    pass

def sync_directory(path):
    storage.check_private_directory(path)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def durable_json(path, data):
    storage.atomic_json(path, data)

def validate_settings(settings):
    if not isinstance(settings, dict) or set(settings) != set(core.FIELDS):
        raise JournalError("Incomplete transaction settings")
    for value in settings.values():
        if not isinstance(value, str) or not re.fullmatch(
            r'\[[A-Za-z0-9+/=]*\]|[A-Za-z][A-Za-z0-9_-]*|"[A-Za-z][A-Za-z0-9_-]*"', value
        ):
            raise JournalError("Invalid transaction settings")

def validate_endpoints(endpoints):
    if not isinstance(endpoints, list) or not endpoints:
        raise JournalError("Invalid transaction endpoints")
    for ep in endpoints:
        if not isinstance(ep, dict) or not set(ep) <= {"host", "port", "sni", "starttls"}:
            raise JournalError("Invalid transaction endpoint")
        port = ep.get("port")
        if type(port) is not int or not 1 <= port <= 65535:
            raise JournalError("Invalid transaction TLS port")
        sni = ep.get("sni")
        if not isinstance(sni, str) or not core.dns_name(sni)[0] or sni.startswith("*."):
            raise JournalError("Invalid transaction SNI")
        host = ep.get("host", "127.0.0.1")
        if not isinstance(host, str) or not re.fullmatch(r"[A-Za-z0-9.:-]+", host):
            raise JournalError("Invalid transaction TLS host")
        if ep.get("starttls") not in (None, "smtp", "imap", "pop3", "ldap", "xmpp", "xmpp-server"):
            raise JournalError("Invalid transaction STARTTLS protocol")

def validate(record, domain):
    if not isinstance(record, dict) or type(record.get("schema")) is not int or record["schema"] != 2:
        raise JournalError("Unsupported transaction journal schema")
    if set(record) != RECORD_FIELDS:
        raise JournalError("Incomplete or unexpected transaction fields")
    phase = record["phase"]
    if record["domain"] != domain or not isinstance(phase, str) or phase not in PHASES:
        raise JournalError("Invalid transaction identity or phase")
    validate_settings(record["previous"])
    validate_settings(record["intended"])
    validate_endpoints(record["endpoints"])
    validate_endpoints(record["previous_endpoints"])
    if not isinstance(record.get("config_identity"), str) or not record["config_identity"]:
        raise JournalError("Missing server identity")
    return record

class Journal:
    def __init__(self, directory):
        self.directory = Path(directory)

    def path(self, domain):
        return self.directory / (core.identifier(domain) + ".json")

    def ensure_directory(self):
        # The parent is the existing manager state directory.
        try:
            storage.check_private_directory(self.directory.parent)
            storage.ensure_private_directory(self.directory)
        except storage.StorageError as exc:
            raise JournalError(str(exc)) from None

    def check_directory(self):
        """Validate without creating or syncing anything for read-only callers."""
        try:
            if not storage.check_private_directory(self.directory.parent, missing_ok=True):
                return False
            return storage.check_private_directory(self.directory, missing_ok=True)
        except storage.StorageError as exc:
            raise JournalError(str(exc)) from None

    def domains(self):
        """List pending domain names without reading sensitive settings."""
        if not self.check_directory():
            return []
        try:
            files = storage.private_files(self.directory)
        except storage.StorageError as exc:
            raise JournalError(str(exc)) from None
        return sorted(core.identifier(path.stem) for path in files)

    def read(self, domain):
        path = self.path(domain)
        if not self.check_directory():
            return None
        try:
            with storage.open_private(path) as stream:
                try:
                    record = json.load(stream)
                except (ValueError, UnicodeError):
                    raise JournalError("Corrupt transaction journal") from None
        except FileNotFoundError:
            return None
        except storage.StorageError as exc:
            raise JournalError(str(exc)) from None
        return validate(record, domain)

    def prepare(self, domain, previous, intended, endpoints, config_identity, previous_endpoints=None):
        self.ensure_directory()
        if self.read(domain) is not None:
            raise JournalError("Unresolved transaction already exists")
        record = validate({
            "schema": 2, "domain": domain, "phase": "prepared",
            "previous": previous, "intended": intended,
            "endpoints": endpoints, "config_identity": config_identity,
            "previous_endpoints": endpoints if previous_endpoints is None else previous_endpoints,
        }, domain)
        durable_json(self.path(domain), record)
        return record

    def transition(self, domain, phase):
        record = self.read(domain)
        if record is None or not isinstance(phase, str) or phase not in PHASES[record["phase"]]:
            raise JournalError("Invalid transaction transition")
        record["phase"] = phase
        durable_json(self.path(domain), record)
        return record

    def finish(self, domain):
        record = self.read(domain)
        if record is None or record["phase"] not in ("committed", "restored"):
            raise JournalError("Cannot remove unresolved transaction")
        self.path(domain).unlink()
        sync_directory(self.directory)

def classify(record, actual):
    """No remote write is permitted for an unknown state."""
    if core.same(actual, record["previous"]):
        return "both" if core.same(actual, record["intended"]) else "previous"
    if core.same(actual, record["intended"]):
        return "intended"
    return "unknown"
