"""Pure PowerDNS observation targets and bounded protected API-key parsing.

The target binding identifies a configured observation. It does not authorize
an update, establish record ownership or provide an API concurrency guarantee.
"""
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import unicodedata
from urllib.parse import urlsplit

from . import core, storage


MAX_SECRET_BYTES = 4096
_FIELDS = {"zone", "endpoint", "server_id", "zone_id", "credentials", "nameservers"}
_BINDING_FIELDS = ("zone", "endpoint", "server_id", "zone_id", "credentials")
_BINDING_DOMAIN = b"cgp-certificate-manager:powerdns-observation:v1\x00"


class ConfigError(core.Error):
    """A fixed diagnostic which does not contain configuration or secret data."""


def _invalid():
    raise ConfigError("Invalid PowerDNS configuration")


def _text(value):
    return (type(value) is str and bool(value)
            and not any(unicodedata.category(char).startswith("C") for char in value))


def _name(value, single=False):
    if not _text(value) or len(value) > 254:
        _invalid()
    try:
        normalized = value.removesuffix(".").lower().encode("idna").decode("ascii")
    except UnicodeError:
        _invalid()
    labels = normalized.split(".")
    if (len(normalized) > 253
            or any(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is None for label in labels)
            or labels[-1].isdigit() or (not single and len(labels) < 2)):
        _invalid()
    return normalized


def _endpoint(value):
    if (not _text(value) or len(value) > 2048 or "\\" in value
            or any(char.isspace() for char in value)):
        _invalid()
    try:
        parts = urlsplit(value)
        if (parts.scheme not in ("https", "http") or not parts.netloc
                or parts.path not in ("", "/") or "?" in value or "#" in value
                or parts.username is not None or parts.password is not None):
            _invalid()
        # Reparse the complete authority: urlsplit alone accepts text following
        # a closing IPv6 bracket and other ambiguous authority spellings.
        match = re.fullmatch(r"(?:\[([0-9A-Fa-f:.]+)\]|([^:\[\]]+))(?::([0-9]+))?", parts.netloc)
        if match is None:
            _invalid()
        bracketed, plain, port_text = match.groups()
        port = int(port_text) if port_text is not None else (443 if parts.scheme == "https" else 80)
        if not 1 <= port <= 65535:
            _invalid()
        if bracketed is not None:
            host = str(ipaddress.IPv6Address(bracketed))
        else:
            try:
                host = str(ipaddress.IPv4Address(plain))
            except ValueError:
                host = _name(plain, single=True)
        if parts.scheme == "http" and host not in ("127.0.0.1", "::1"):
            _invalid()
        authority = "[" + host + "]" if ":" in host else host
        if port != (443 if parts.scheme == "https" else 80):
            authority += ":" + str(port)
        return parts.scheme + "://" + authority
    except ValueError:
        _invalid()


def _identifier(value):
    # PowerDNS uses '=' escapes inside opaque IDs. They are preserved here;
    # the transport must URL-encode each entire ID as one path component.
    if (type(value) is not str or re.fullmatch(r"[A-Za-z0-9._~=-]{1,255}", value) is None
            or value in (".", "..")):
        _invalid()
    return value


def _credential_path(value):
    if not _text(value) or len(value) > 4096:
        _invalid()
    path = Path(value)
    if path.anchor != "/" or ".." in path.parts or not path.name:
        _invalid()
    return str(path)


def validate(cfg):
    """Normalize explicit read-only targets without opening files or sockets.

    This section is independent of the issuance provider selector. Endpoint,
    server/zone IDs and credential path are explicit; no API IDs are inferred
    from zone names. Rotating key bytes and expected nameservers are outside
    the informational target binding.
    """
    options = cfg.get("powerdns") if isinstance(cfg, dict) else None
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
        endpoint = _endpoint(entry["endpoint"])
        server_id = _identifier(entry["server_id"])
        zone_id = _identifier(entry["zone_id"])
        target = (endpoint, server_id, zone_id)
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
        normalized = {"zone": zone, "endpoint": endpoint, "server_id": server_id, "zone_id": zone_id,
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
    """Read one nonempty printable ASCII API key from protected bounded JSON."""
    try:
        with storage.open_private(path) as stream:
            raw = stream.buffer.read(MAX_SECRET_BYTES + 1)
        if len(raw) > MAX_SECRET_BYTES:
            raise ValueError("Secret file exceeds limit")
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
        if (not isinstance(data, dict) or set(data) != {"api_key"} or type(data["api_key"]) is not str
                or re.fullmatch(r"[!-~]{1,1024}", data["api_key"]) is None):
            raise ValueError("Invalid secret structure or encoding")
        return data["api_key"]
    except Exception:
        raise ConfigError("Invalid PowerDNS credentials") from None
