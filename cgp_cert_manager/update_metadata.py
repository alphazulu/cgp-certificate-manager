"""Bounded offline update metadata verification with operator-provided trust.

This is a single-signature protocol, not TUF. It never loads keys from a
candidate, fetches metadata, persists a rollback floor, or executes a release.
The caller must durably retain the returned floor before preparing an update.
"""
import base64
import hashlib
import json
import re

from .core import Error


PROJECT = "cgp-certificate-manager"
REPOSITORY = "alphazulu/cgp-certificate-manager"
DOMAIN = b"CGP-CERTIFICATE-MANAGER-UPDATE-V1\n"
MAX_MANIFEST = 16384
MAX_SIGNATURE = 4096
MAX_TRUST = 16384
MAX_ARCHIVE = 256 * 1024 * 1024
MAX_TIME = 253402300799
MAX_VALIDITY = 30 * 86400
MAX_SEQUENCE = 2**63 - 1
CODES = frozenset({"invalid_manifest", "invalid_signature", "invalid_trust", "untrusted_key",
                   "verifier_unavailable", "unsupported_crypto", "wrong_project", "wrong_channel",
                   "expired_manifest", "future_manifest", "invalid_clock", "invalid_version",
                   "downgrade", "rollback", "clock_moved_backwards", "invalid_floor"})
_VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
                      r"(?:(\.dev|rc)(0|[1-9][0-9]*))?")


class UpdateError(Error):
    """A fixed non-sensitive metadata or trust policy failure."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _require(condition, code):
    if not condition:
        raise UpdateError(code)


def _integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def _hex(value, lengths=(64,)):
    return type(value) is str and len(value) in lengths and re.fullmatch(r"[0-9a-f]+", value) is not None


def _exact(value, fields, code):
    _require(type(value) is dict and set(value) == fields, code)


def canonical(value):
    """Encode canonical JSON bytes; schema validation remains a separate step."""
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    except (TypeError, ValueError, RecursionError, OverflowError):
        raise UpdateError("invalid_manifest") from None


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate metadata member")
        result[key] = value
    return result


def _no_float(value):
    raise ValueError("Metadata numbers must be integers")


def _json(data, limit, code):
    _require(type(data) is bytes and 0 < len(data) <= limit, code)
    try:
        result = json.loads(data.decode("ascii"), object_pairs_hook=_unique,
                            parse_float=_no_float, parse_constant=_no_float)
        pending, count = [(result, 0)], 0
        while pending:
            value, depth = pending.pop()
            count += 1
            if depth > 8 or count > 256:
                raise ValueError("Metadata structure exceeds limits")
            if type(value) is dict:
                pending.extend((item, depth + 1) for item in value.values())
            elif type(value) is list:
                pending.extend((item, depth + 1) for item in value)
        return result
    except (ValueError, UnicodeError, RecursionError):
        raise UpdateError(code) from None


def _base64(value, length, code):
    _require(type(value) is str and len(value) == 4 * ((length + 2) // 3), code)
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, UnicodeError):
        raise UpdateError(code) from None
    _require(len(raw) == length and base64.b64encode(raw).decode("ascii") == value, code)
    return raw


def version(value, allow_dev=True):
    """Return (major, minor, patch, dev/rc/final rank, pre-release number)."""
    _require(type(value) is str and 0 < len(value) <= 64, "invalid_version")
    match = _VERSION.fullmatch(value)
    _require(match is not None, "invalid_version")
    major, minor, patch, stage, number = match.groups()
    _require(allow_dev or stage != ".dev", "invalid_version")
    rank = {".dev": 0, "rc": 1, None: 2}[stage]
    return int(major), int(minor), int(patch), rank, int(number or "0")


def _trust(value):
    _exact(value, {"schema", "project", "channel", "keys"}, "invalid_trust")
    _require(type(value["schema"]) is int and value["schema"] == 1, "invalid_trust")
    _require(value["project"] == PROJECT, "wrong_project")
    _require(value["channel"] in ("stable", "candidate"), "invalid_trust")
    keys = value["keys"]
    _require(type(keys) is dict and 1 <= len(keys) <= 16, "invalid_trust")
    normalized = {}
    for identifier, encoded in keys.items():
        _require(_hex(identifier), "invalid_trust")
        public = _base64(encoded, 32, "invalid_trust")
        _require(hashlib.sha256(public).hexdigest() == identifier, "invalid_trust")
        normalized[identifier] = encoded
    return {"schema": 1, "project": PROJECT, "channel": value["channel"], "keys": normalized}


def parse_trust(data):
    """Parse a local trust file without importing a cryptographic backend."""
    return _trust(_json(data, MAX_TRUST, "invalid_trust"))


def validate_floor(value):
    """Validate a caller-owned, project/channel-partitioned rollback floor."""
    _exact(value, {"sequence", "manifest_sha256", "version", "checked_at"}, "invalid_floor")
    _require(_integer(value["sequence"], 1, MAX_SEQUENCE)
             and _hex(value["manifest_sha256"])
             and _integer(value["checked_at"], 0, MAX_TIME), "invalid_floor")
    try:
        version(value["version"], allow_dev=False)
    except UpdateError:
        raise UpdateError("invalid_floor") from None
    return dict(value)


def _manifest(data):
    value = _json(data, MAX_MANIFEST, "invalid_manifest")
    _exact(value, {"schema", "project", "channel", "sequence", "version", "issued_at", "expires_at",
                   "source", "archive"}, "invalid_manifest")
    _require(type(value["schema"]) is int and value["schema"] == 1, "invalid_manifest")
    _require(canonical(value) == data, "invalid_manifest")
    _require(value["project"] == PROJECT, "wrong_project")
    _require(value["channel"] in ("stable", "candidate"), "invalid_manifest")
    _require(_integer(value["sequence"], 1, MAX_SEQUENCE)
             and _integer(value["issued_at"], 0, MAX_TIME)
             and _integer(value["expires_at"], 0, MAX_TIME), "invalid_manifest")
    _require(0 < value["expires_at"] - value["issued_at"] <= MAX_VALIDITY, "invalid_manifest")
    parsed = version(value["version"], allow_dev=False)
    _require(value["channel"] != "stable" or parsed[3] == 2, "wrong_channel")
    source = value["source"]
    _exact(source, {"repository", "commit", "tree", "tag"}, "invalid_manifest")
    _require(source["repository"] == REPOSITORY, "wrong_project")
    _require(_hex(source["commit"], (40, 64)) and _hex(source["tree"], (40, 64))
             and len(source["commit"]) == len(source["tree"])
             and source["tag"] == "v" + value["version"], "invalid_manifest")
    archive = value["archive"]
    _exact(archive, {"name", "size", "sha256"}, "invalid_manifest")
    _require(archive["name"] == PROJECT + "-v" + value["version"] + ".tar.gz"
             and _integer(archive["size"], 1, MAX_ARCHIVE)
             and _hex(archive["sha256"]), "invalid_manifest")
    return value, parsed


def _signature(data, trust):
    value = _json(data, MAX_SIGNATURE, "invalid_signature")
    _exact(value, {"schema", "key_id", "signature"}, "invalid_signature")
    _require(type(value["schema"]) is int and value["schema"] == 1
             and _hex(value["key_id"]), "invalid_signature")
    signature = _base64(value["signature"], 64, "invalid_signature")
    _require(value["key_id"] in trust["keys"], "untrusted_key")
    public = _base64(trust["keys"][value["key_id"]], 32, "invalid_trust")
    return value["key_id"], public, signature


def _verify(public, signature, data):
    try:
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except (ImportError, OSError):
        raise UpdateError("verifier_unavailable") from None
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, DOMAIN + data)
    except UnsupportedAlgorithm:
        raise UpdateError("unsupported_crypto") from None
    except (InvalidSignature, ValueError):
        raise UpdateError("invalid_signature") from None


def verify(manifest_bytes, signature_bytes, trust, *, now, current_version, previous=None):
    """Authenticate exact metadata and evaluate policy without any side effects."""
    trusted = _trust(trust)
    _require(_integer(now, 0, MAX_TIME), "invalid_clock")
    current = version(current_version)
    if previous is not None:
        previous = validate_floor(previous)
        _require(now >= previous["checked_at"], "clock_moved_backwards")
    manifest, target = _manifest(manifest_bytes)
    key_id, public, signature = _signature(signature_bytes, trusted)
    _verify(public, signature, manifest_bytes)
    _require(manifest["channel"] == trusted["channel"], "wrong_channel")
    _require(manifest["issued_at"] <= now, "future_manifest")
    _require(now < manifest["expires_at"], "expired_manifest")
    _require(target > current, "downgrade")
    digest = hashlib.sha256(manifest_bytes).hexdigest()
    if previous is not None:
        _require(manifest["sequence"] >= previous["sequence"], "rollback")
        prior_version = version(previous["version"], allow_dev=False)
        _require(target >= prior_version, "rollback")
        if manifest["sequence"] == previous["sequence"]:
            _require(digest == previous["manifest_sha256"] and target == prior_version, "rollback")
    floor = {"sequence": manifest["sequence"], "manifest_sha256": digest,
             "version": manifest["version"], "checked_at": now}
    return {"manifest": manifest, "manifest_sha256": digest, "key_id": key_id, "floor": floor}
