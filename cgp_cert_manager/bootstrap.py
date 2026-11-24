"""Read-only eligibility checks for capturing an explicit certificate snapshot.

Readiness here is structural.  It does not establish key/certificate matching,
certificate validity, served TLS identity, or safe restoration of absent fields.
Automatic bootstrap remains disabled until those separate contracts are proven.
"""

import base64
import re
from dataclasses import dataclass, field

from . import cgpdata, core


class ReadinessError(core.Error):
    """A new transaction cannot rely on the observed certificate provenance."""


@dataclass(frozen=True)
class Inspection:
    """Public diagnostics and an internal, potentially secret snapshot."""

    report: dict
    settings: dict = field(repr=False)


def _normalized_field(name, value):
    if name == "CertificateType":
        if (value.kind != "string"
                or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", value.value)
                or value.value.lower() == "default"):
            raise core.Error("Unsupported certificate field value")
        return value.value
    if value.kind != "datablock":
        raise core.Error("Unsupported certificate field value")
    try:
        decoded = base64.b64decode(value.value, validate=True)
    except ValueError:
        raise core.Error("Unsupported certificate field value") from None
    if base64.b64encode(decoded).decode("ascii") != value.value:
        raise core.Error("Unsupported certificate field value")
    return "[" + value.value + "]"


def certificate_fields(parsed):
    """Return supported present certificate fields from a parsed dictionary.

    Missing fields stay missing.  Empty DataBlocks stay ``[]`` for strict
    legacy readers, but are never eligible for a complete deployment snapshot.
    Every present unsupported value raises a fixed, secret-safe error.
    """
    return {name: _normalized_field(name, parsed[name])
            for name in core.FIELDS if name in parsed}


def _unknown(domain, status, reason):
    return Inspection({
        "domain": domain,
        "response_status": status,
        "origin": {name: "unknown" for name in core.FIELDS},
        "missing_explicit_fields": None,
        "missing_effective_fields": None,
        "unreadable_fields": [],
        "empty_fields": [],
        "snapshot_complete": False,
        "explicit_snapshot_complete": False,
        "deployment_ready": False,
        "automatic_bootstrap": False,
        "blocking_reason": reason,
    }, {})


def _projection(parsed):
    # Include typed unsupported values: a race must not disappear merely because
    # a value cannot be represented by the existing certificate snapshot format.
    return {name: parsed[name] for name in core.FIELDS if name in parsed}


def _values(parsed):
    normalized, unreadable, empty = {}, set(), set()
    for name, value in parsed.items():
        expected_kind = "string" if name == "CertificateType" else "datablock"
        is_empty = value.kind == expected_kind and value.value == ""
        if is_empty:
            empty.add(name)
        try:
            normalized[name] = _normalized_field(name, value)
        except core.Error:
            if not is_empty:
                unreadable.add(name)
    complete = len(normalized) == len(core.FIELDS) and not empty
    return normalized, unreadable, empty, complete


def inspect(cfg, domain):
    """Inspect four repeated CGP reads without filesystem or mutation effects.

    All dictionaries must parse fully; only the certificate projections are
    compared for changes.  An eligible snapshot requires all four supported,
    nonempty fields to be explicit and identical to their effective values.
    Expiry, key matching, and TLS verification are deliberately separate checks.
    """
    core.identifier(domain)
    responses = []
    try:
        for command in ("GETDOMAINSETTINGS", "GETDOMAINEFFECTIVESETTINGS") * 2:
            responses.append(_projection(cgpdata.parse_dictionary(
                core.cli(cfg, command + " " + domain))))
    except cgpdata.ParseError:
        return _unknown(domain, "invalid_response", "invalid_response")
    except Exception:
        # Remote errors can contain credentials or the entire settings body.
        return _unknown(domain, "unavailable", "response_unavailable")
    explicit, effective, explicit_again, effective_again = responses
    if explicit != explicit_again or effective != effective_again:
        return _unknown(domain, "changed", "changed")

    _, raw_unreadable, raw_empty, explicit_complete = _values(explicit)
    settings, effective_unreadable, effective_empty, complete = _values(effective)
    origin = {}
    for name in core.FIELDS:
        if name not in explicit:
            origin[name] = "effective_only" if name in effective else "absent"
        elif name not in effective or explicit[name] != effective[name]:
            origin[name] = "inconsistent"
        else:
            origin[name] = "explicit"
    missing_explicit = [name for name in core.FIELDS if name not in explicit]
    missing_effective = [name for name in core.FIELDS if name not in effective]
    unreadable = [name for name in core.FIELDS
                  if name in raw_unreadable | effective_unreadable]
    empty = [name for name in core.FIELDS if name in raw_empty | effective_empty]
    reason = None
    if "inconsistent" in origin.values():
        reason = "inconsistent"
    elif unreadable:
        reason = "unreadable_fields"
    elif empty:
        reason = "empty_fields"
    elif missing_effective:
        reason = "missing_effective_fields"
    elif missing_explicit:
        reason = "missing_explicit_fields"
    return Inspection({
        "domain": domain,
        "response_status": "ok",
        "origin": origin,
        "missing_explicit_fields": missing_explicit,
        "missing_effective_fields": missing_effective,
        "unreadable_fields": unreadable,
        "empty_fields": empty,
        "snapshot_complete": bool(complete),
        "explicit_snapshot_complete": bool(explicit_complete),
        "deployment_ready": reason is None,
        "automatic_bootstrap": False,
        "blocking_reason": reason,
    }, settings)


def require_ready(cfg, domain):
    """Return a stable, explicit structural snapshot or a safe blocking error."""
    result = inspect(cfg, domain)
    if not result.report["deployment_ready"]:
        raise ReadinessError("Certificate deployment blocked ("
                         + result.report["blocking_reason"]
                         + "); run --bootstrap-check for diagnostics")
    return result.settings


def reports(cfg, domain=None):
    """Return public reports; validate every discovered name before any read."""
    if domain is not None:
        names = [core.identifier(domain)]
    else:
        try:
            listed = cgpdata.parse(core.cli(cfg, "LISTDOMAINS"))
            if listed.kind != "array" or any(item.kind != "string" for item in listed.value):
                raise core.Error("Unexpected CGP domain list")
            names = sorted(set(item.value for item in listed.value))
            for name in names:
                core.identifier(name)
        except Exception:
            raise core.Error("Cannot list CGP domains for bootstrap diagnostics") from None
    return [inspect(cfg, name).report for name in names]
