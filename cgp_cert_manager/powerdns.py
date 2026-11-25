"""Read-only PowerDNS API identity observations, never an issuing provider.

The HTTP API's per-value updates do not supply this manager's ownership
contract. This module therefore has no mutation method or provider capability.
Every configured target is validated before any private credential is opened.
Socket timeouts bound individual operations, not DNS resolution or total time.
"""
import http.client
import json
import math
import re
from urllib.parse import quote, urlsplit

from . import powerdns_config
from .notify_transport import _context, _HTTPResponse


MAX_BODY = 64 * 1024
TIMEOUT = 10
_KINDS = frozenset({"Native", "Master", "Slave", "Producer", "Consumer"})


class _Failure(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate property")
        result[key] = value
    return result


def _constant(value):
    raise ValueError("Non-finite value")


def _float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("Non-finite value")
    return number


def _body(response):
    """Accept one bounded UTF-8 JSON body with unambiguous HTTP framing."""
    lengths = response.headers.get_all("Content-Length", [])
    encodings = response.headers.get_all("Transfer-Encoding", [])
    types = response.headers.get_all("Content-Type", [])
    compressed = response.headers.get_all("Content-Encoding", [])
    # Native PowerDNS emits Content-Length. Reject transfer encodings rather
    # than let stdlib chunk framing/trailers bypass the decoded body budget.
    if (len(lengths) > 1 or encodings or len(types) != 1 or compressed
            or re.fullmatch(r'application/json(?:\s*;\s*charset=(?:utf-8|"utf-8"))?',
                            types[0], re.IGNORECASE) is None):
        raise _Failure("invalid_api_response")
    expected = None
    if lengths:
        if not re.fullmatch(r"[0-9]{1,10}", lengths[0]):
            raise _Failure("invalid_api_response")
        expected = int(lengths[0])
        if expected > MAX_BODY:
            raise _Failure("invalid_api_response")
    raw = response.read(MAX_BODY + 1)
    if len(raw) > MAX_BODY or (expected is not None and len(raw) != expected):
        raise _Failure("invalid_api_response")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                          parse_constant=_constant, parse_float=_float)
    except (ValueError, UnicodeError, RecursionError):
        raise _Failure("invalid_api_response") from None


def _get(entry, key, path):
    """Perform exactly one GET; do not consult proxies or follow redirects."""
    try:
        parts = urlsplit(entry["endpoint"])
        if parts.scheme == "https":
            client = http.client.HTTPSConnection(parts.hostname, parts.port,
                                                 timeout=TIMEOUT, context=_context())
        else:
            client = http.client.HTTPConnection(parts.hostname, parts.port, timeout=TIMEOUT)
        try:
            client.response_class = _HTTPResponse
            client.request("GET", path, headers={"X-API-Key": key, "Accept": "application/json",
                                                "Accept-Encoding": "identity", "Connection": "close"})
            with client.getresponse() as response:
                if response.status != 200:
                    raise _Failure("api_request_failed")
                return _body(response)
        finally:
            client.close()
    except _Failure:
        raise
    except Exception:
        raise _Failure("api_request_failed") from None


def _server(entry, data):
    if not isinstance(data, dict) or data.get("type") != "Server":
        raise _Failure("invalid_api_response")
    if data.get("id") != entry["server_id"] or data.get("daemon_type") != "authoritative":
        raise _Failure("server_identity_mismatch")
    version = data.get("version")
    if (type(version) is not str or not 1 <= len(version) <= 128
            or re.fullmatch(r"[0-9]+(?:\.[0-9]+)+[A-Za-z0-9._+~-]*", version) is None):
        raise _Failure("invalid_api_response")
    return version


def _zone(entry, data):
    # PowerDNS itself omits type in zone responses. A proxy may add the
    # documented Zone discriminator; a different discriminator is refused.
    if (not isinstance(data, dict) or data.get("type", "Zone") != "Zone"
            or type(data.get("kind")) is not str or data["kind"] not in _KINDS):
        raise _Failure("invalid_api_response")
    if (data.get("id") != entry["zone_id"] or type(data.get("name")) is not str
            or not data["name"].isascii() or data["name"].lower() != entry["zone"] + "."):
        raise _Failure("zone_identity_mismatch")
    return data["kind"]


def check(cfg):
    """Observe configured API identities without CGP, DNS or persistent writes."""
    entries = powerdns_config.validate(cfg)
    rows = []
    for entry in entries:
        row = {"zone": entry["zone"], "binding": entry["binding"], "status": "error",
               "reason": "credential_unavailable", "server_version": None, "zone_kind": None}
        try:
            key = powerdns_config.read_secret(entry["credentials"])
        except powerdns_config.ConfigError:
            pass
        else:
            try:
                base = "/api/v1/servers/" + quote(entry["server_id"], safe="")
                version = _server(entry, _get(entry, key, base))
                path = base + "/zones/" + quote(entry["zone_id"], safe="") + "?rrsets=false"
                kind = _zone(entry, _get(entry, key, path))
            except _Failure as error:
                row["reason"] = error.code
            else:
                row.update(status="observed", reason="api_identity_observed",
                           server_version=version, zone_kind=kind)
        rows.append(row)
    return {"schema": 1, "provider": "powerdns", "mode": "read_only",
            "complete": all(row["status"] == "observed" for row in rows),
            "issuance_supported": False, "zones": rows}
