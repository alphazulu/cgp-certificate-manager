"""Pure commercial-AWS Route53 targets and bounded private credentials.

The binding describes a configured account, hosted zone and credential path.
It excludes rotating secret bytes and nameserver metadata. Only the fixed
commercial endpoints/signing scope are supported; selection never discovers
credentials from profiles, the environment, instance metadata or other sources.
"""
import hashlib
import json
from pathlib import Path
import re
import unicodedata

from . import core, storage


MAX_SECRET_BYTES = 32 * 1024
_FIELDS = {"zone", "hosted_zone_id", "account_id", "credentials", "nameservers"}
_BINDING_FIELDS = ("zone", "hosted_zone_id", "account_id", "credentials")
_BINDING_DOMAIN = (b"cgp-certificate-manager:route53-zone:v1\x00"
                   b"aws\x00route53.amazonaws.com\x00route53\x00us-east-1\x002013-04-01\x00"
                   b"sts.us-east-1.amazonaws.com\x00sts\x00us-east-1\x002011-06-15\x00")
_SECRET_FIELDS = {"access_key_id", "secret_access_key"}


class ConfigError(core.Error):
    """A fixed diagnostic which does not include configuration or secret values."""


def _invalid():
    raise ConfigError("Invalid Route53 configuration")


def _text(value):
    return (type(value) is str and bool(value)
            and not any(unicodedata.category(char).startswith("C") for char in value))


def _name(value):
    if not _text(value) or len(value) > 254:
        _invalid()
    try:
        normalized = value.removesuffix(".").lower().encode("idna").decode("ascii")
    except UnicodeError:
        _invalid()
    labels = normalized.split(".")
    if (len(normalized) > 253 or len(labels) < 2 or labels[-1].isdigit()
            or any(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is None for label in labels)):
        _invalid()
    return normalized


def _credential_path(value):
    if not _text(value) or len(value) > 4096:
        _invalid()
    path = Path(value)
    if path.anchor != "/" or ".." in path.parts or not path.name:
        _invalid()
    return str(path)


def validate(cfg):
    """Normalize explicit targets without reading files or contacting AWS."""
    options = cfg.get("route53") if isinstance(cfg, dict) else None
    if not isinstance(options, dict) or set(options) != {"zones"}:
        _invalid()
    entries = options["zones"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 128:
        _invalid()
    result = []
    seen_zones, seen_targets = set(), set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != _FIELDS:
            _invalid()
        zone = _name(entry["zone"])
        account = entry["account_id"]
        identifier = entry["hosted_zone_id"]
        if (type(account) is not str or re.fullmatch(r"[0-9]{12}", account) is None
                or type(identifier) is not str or re.fullmatch(r"Z[A-Z0-9]{1,31}", identifier) is None):
            _invalid()
        target = (account, identifier)
        if zone in seen_zones or target in seen_targets:
            _invalid()
        seen_zones.add(zone)
        seen_targets.add(target)
        nameservers = entry["nameservers"]
        if not isinstance(nameservers, list) or not 1 <= len(nameservers) <= 16:
            _invalid()
        nameservers = [_name(name) for name in nameservers]
        if len(set(nameservers)) != len(nameservers):
            _invalid()
        normalized = {"zone": zone, "hosted_zone_id": identifier, "account_id": account,
                      "credentials": _credential_path(entry["credentials"]), "nameservers": nameservers}
        binding = json.dumps({field: normalized[field] for field in _BINDING_FIELDS},
                             sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        normalized["binding"] = hashlib.sha256(_BINDING_DOMAIN + binding.encode("utf-8")).hexdigest()
        result.append(normalized)
    return tuple(result)


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate property")
        result[key] = value
    return result


def _constant(value):
    raise ValueError("Non-finite value")


def read_secret(path):
    """Read exactly one protected bounded AWS credential object, without fallback."""
    try:
        with storage.open_private(path) as stream:
            raw = stream.buffer.read(MAX_SECRET_BYTES + 1)
        if len(raw) > MAX_SECRET_BYTES:
            raise ValueError("Credential file exceeds limit")
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
        if (not isinstance(data, dict) or set(data) not in (_SECRET_FIELDS, _SECRET_FIELDS | {"session_token"})
                or type(data["access_key_id"]) is not str
                or re.fullmatch(r"[A-Z0-9]{16,128}", data["access_key_id"]) is None
                or type(data["secret_access_key"]) is not str
                or re.fullmatch(r"[A-Za-z0-9/+=]{40}", data["secret_access_key"]) is None):
            raise ValueError("Invalid credential structure or encoding")
        if "session_token" in data and (type(data["session_token"]) is not str
                                       or re.fullmatch(r"[!-~]{1,16384}", data["session_token"]) is None):
            raise ValueError("Invalid session credential")
        return data
    except Exception:
        raise ConfigError("Invalid Route53 credentials") from None
