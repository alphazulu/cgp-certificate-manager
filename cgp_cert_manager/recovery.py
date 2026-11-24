"""Recovery engine; requires exclusive operation lock.

No automatic writes to CGP are made for an unrecognized snapshot.
The caller must bind the journal to the configured local server identity.
"""
import base64
import hashlib
import json

from . import core
from .transactions import JournalError, classify

def server_identity(cfg, machine_id):
    """Bind to local machine and CLI endpoint, not passwords or tokens."""
    return hashlib.sha256(json.dumps(
        [machine_id, cfg["communigate"]["url"]], separators=(",", ":")
    ).encode()).hexdigest()

def der_certificates(data):
    """Split a concatenated DER CA chain without consulting Certbot files."""
    parts = []
    while data:
        if len(data) < 2 or data[0] != 0x30:
            raise JournalError("Invalid CA DER sequence")
        length = data[1]
        header = 2
        if length & 128:
            width = length & 127
            if not 1 <= width <= 4 or len(data) < 2 + width:
                raise JournalError("Invalid CA DER length")
            length = int.from_bytes(data[2:2+width], "big")
            header += width
        size = header + length
        if not length or size > len(data):
            raise JournalError("Truncated CA DER certificate")
        parts.append(data[:size])
        data = data[size:]
    if not parts:
        raise JournalError("Empty CA chain")
    return parts

def datablock(value):
    if not value.startswith("[") or not value.endswith("]"):
        raise JournalError("Invalid certificate DataBlock")
    try:
        return base64.b64decode(value[1:-1], validate=True)
    except ValueError:
        raise JournalError("Invalid certificate encoding") from None

def verify_snapshot(settings, endpoints):
    """Check key, validity, CA trust and live TLS against a saved snapshot."""
    core.validate_backup(settings)
    leaf = datablock(settings["SecureCertificate"])
    if not leaf:
        raise JournalError("Empty leaf certificate")
    chain = [leaf] + der_certificates(datablock(settings["CAChain"]))
    expected = [hashlib.sha256(item).hexdigest() for item in chain]
    if not endpoints:
        raise JournalError("No recorded TLS endpoints")
    for endpoint in endpoints:
        core.probe_tls(endpoint, expected)

def recover(journal, domain, cfg, identity, verifier=verify_snapshot):
    """Resolve one journal or raise, retaining evidence on uncertain outcomes.

    A completed phase can only be cleaned up if CGP still matches its snapshot.
    On unsuccessful verification of the intended snapshot, restoration is
    permitted only after a fresh readback confirms a known snapshot.
    """
    record = journal.read(domain)
    if record is None:
        return "none"
    if record["config_identity"] != identity:
        raise JournalError("Transaction belongs to another server configuration")
    actual = core.current(cfg, domain)
    state = classify(record, actual)
    phase = record["phase"]
    if state == "unknown":
        raise JournalError("Unknown CGP state; manual intervention required")
    if phase in ("committed", "restored"):
        expected = "intended" if phase == "committed" else "previous"
        if state != expected:
            raise JournalError("CGP changed after transaction completion")
        journal.finish(domain)
        return phase
    if phase == "prepared" and state == "intended":
        raise JournalError("Unexpected CGP change before applying")
    if state == "intended" and phase != "restoring":
        if phase == "applying":
            journal.transition(domain, "applied")
            phase = "applied"
        if phase == "applied":
            journal.transition(domain, "verifying")
        try:
            verifier(record["intended"], record["endpoints"])
        except Exception:
            # Do not touch an administrator's intervening change.
            return restore(journal, domain, cfg, record, verifier)
        journal.transition(domain, "committed")
        journal.finish(domain)
        return "committed"
    return restore(journal, domain, cfg, record, verifier)

def restore(journal, domain, cfg, record, verifier):
    state = classify(record, core.current(cfg, domain))
    if state == "unknown":
        raise JournalError("CGP changed before recovery; refusing write")
    if journal.read(domain)["phase"] != "restoring":
        journal.transition(domain, "restoring")
    if state == "intended":
        core.update(cfg, domain, record["previous"])
    if not core.same(core.current(cfg, domain), record["previous"]):
        raise JournalError("Recovery readback mismatch")
    # A failed TLS check retains the restoring journal for the administrator.
    verifier(record["previous"], record["endpoints"])
    journal.transition(domain, "restored")
    journal.finish(domain)
    return "restored"
