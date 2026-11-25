"""Pure RFC2136 zone identities and bounded private TSIG secret parsing."""
import base64
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import unicodedata

from . import core, storage


MAX_SECRET_TEXT = 4096
_ZONE_FIELDS = {"zone", "server", "port", "credentials", "key_name", "algorithm", "nameservers"}
_REQUIRED_FIELDS = _ZONE_FIELDS - {"port", "algorithm"}
_BINDING_FIELDS = ("zone", "server", "port", "credentials", "key_name", "algorithm")
_BINDING_DOMAIN = b"cgp-certificate-manager:rfc2136-zone:v1\x00"


class ConfigError(core.Error):
    """A fixed diagnostic which never includes configuration or secret values."""


def _invalid():
    raise ConfigError("Invalid RFC2136 configuration")


def _text(value):
    return (type(value) is str and bool(value)
            and not any(unicodedata.category(char).startswith("C") for char in value))


def _name(value, key=False):
    if not _text(value) or len(value) > 254:
        _invalid()
    try:
        normalized = value.removesuffix(".").lower().encode("idna").decode("ascii")
    except UnicodeError:
        _invalid()
    labels = normalized.split(".")
    if (len(normalized) > 253
            or any(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is None for label in labels)
            or (not key and (len(labels) < 2 or labels[-1].isdigit()))):
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
    """Return normalized explicit zones without reading credentials or DNS.

    Selection belongs to the provider factory. This function inspects only the
    dedicated ``rfc2136`` section, allowing the manager's other settings to remain
    intact. Names are lowercase ASCII without a trailing root dot; TSIG names
    may also be a single LDH label. Nameservers and rotating secret bytes are
    deliberately outside the stable mutation-target binding.
    """
    options = cfg.get("rfc2136") if isinstance(cfg, dict) else None
    if not isinstance(options, dict) or set(options) != {"zones"}:
        _invalid()
    entries = options["zones"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 128:
        _invalid()
    result = []
    seen = set()
    for entry in entries:
        if (not isinstance(entry, dict) or set(entry) - _ZONE_FIELDS
                or _REQUIRED_FIELDS - set(entry)):
            _invalid()
        zone = _name(entry["zone"])
        if zone in seen:
            _invalid()
        seen.add(zone)
        server = entry["server"]
        if not _text(server) or "%" in server:
            _invalid()
        try:
            server = str(ipaddress.ip_address(server))
        except ValueError:
            _invalid()
        port = entry.get("port", 53)
        if type(port) is not int or not 1 <= port <= 65535:
            _invalid()
        algorithm = entry.get("algorithm", "hmac-sha256")
        if type(algorithm) is not str or algorithm != "hmac-sha256":
            _invalid()
        nameservers = entry["nameservers"]
        if not isinstance(nameservers, list) or not 1 <= len(nameservers) <= 16:
            _invalid()
        nameservers = [_name(name) for name in nameservers]
        if len(set(nameservers)) != len(nameservers):
            _invalid()
        normalized = {"zone": zone, "server": server, "port": port,
                      "credentials": _credential_path(entry["credentials"]),
                      "key_name": _name(entry["key_name"], key=True),
                      "algorithm": algorithm, "nameservers": nameservers}
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
    """Read exactly one canonical base64 secret from a private bounded JSON file."""
    try:
        with storage.open_private(path) as stream:
            text = stream.read(MAX_SECRET_TEXT + 1)
        if len(text) > MAX_SECRET_TEXT:
            raise ValueError("Secret file exceeds limit")
        data = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
        if not isinstance(data, dict) or set(data) != {"secret"} or type(data["secret"]) is not str:
            raise ValueError("Invalid secret structure")
        secret = base64.b64decode(data["secret"], validate=True)
        if not 32 <= len(secret) <= 128 or base64.b64encode(secret).decode("ascii") != data["secret"]:
            raise ValueError("Invalid secret encoding or size")
        return secret
    except Exception:
        raise ConfigError("Invalid RFC2136 credentials") from None
