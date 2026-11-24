"""Recovery engine; requires exclusive operation lock.

No automatic writes to CGP are made for an unrecognized snapshot.
The caller must bind the journal to the configured local server identity.
"""
import base64
import hashlib
import json
import re
from pathlib import Path

from . import core
from .transactions import JournalError, classify

def server_identity(cfg, machine_id=None):
    """Bind to local machine and CLI endpoint, not passwords or tokens."""
    if machine_id is None:
        try:
            machine_id = Path("/etc/machine-id").read_text().strip()
        except OSError:
            raise JournalError("Cannot read local machine identity") from None
    if not isinstance(machine_id, str) or not re.fullmatch(r"[0-9a-fA-F]{32}", machine_id):
        raise JournalError("Invalid local machine identity")
    url = cfg.get("communigate", {}).get("url")
    if not isinstance(url, str) or not re.fullmatch(r"http://127\.0\.0\.1:\d+/CLI/", url, re.I):
        raise JournalError("CGP URL must be loopback")
    return hashlib.sha256(json.dumps(
        [machine_id.lower(), url], separators=(",", ":")
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
    if not isinstance(value, str) or not value.startswith("[") or not value.endswith("]"):
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

def recover(journal, domain, cfg, identity, verifier=None, readback=None):
    """Resolve one journal or raise, retaining evidence on uncertain outcomes.

    A completed phase can only be cleaned up if CGP still matches its snapshot.
    On unsuccessful verification of the intended snapshot, restoration is
    permitted only after a fresh readback confirms a known snapshot.
    New in-process transactions may supply a stricter provenance reader;
    standalone schema-2 recovery keeps its recorded effective-value contract.
    """
    from . import resolution
    resolution.assert_no_incomplete(journal.directory.parent)
    record = journal.read(domain)
    if record is None:
        return "none"
    if record["config_identity"] != identity:
        raise JournalError("Transaction belongs to another server configuration")
    if verifier is None:
        verifier = verify_snapshot
    if readback is None:
        readback = core.current
    actual = readback(cfg, domain)
    state = classify(record, actual)
    phase = record["phase"]
    if state == "unknown":
        raise JournalError("Unknown CGP state; manual intervention required")
    if phase in ("committed", "restored"):
        expected = record["intended"] if phase == "committed" else record["previous"]
        if not core.same(actual, expected):
            raise JournalError("CGP changed after transaction completion")
        journal.finish(domain)
        return phase
    if phase == "prepared" and state == "intended":
        raise JournalError("Unexpected CGP change before applying")
    if state in ("intended", "both") and phase not in ("prepared", "restoring"):
        if phase == "applying":
            journal.transition(domain, "applied")
            phase = "applied"
        if phase == "applied":
            journal.transition(domain, "verifying")
        try:
            verifier(record["intended"], record["endpoints"])
        except Exception:
            # Do not touch an administrator's intervening change.
            return restore(journal, domain, cfg, record, verifier, readback=readback)
        if not core.same(readback(cfg, domain), record["intended"]):
            raise JournalError("CGP changed during transaction verification")
        journal.transition(domain, "committed")
        journal.finish(domain)
        return "committed"
    return restore(journal, domain, cfg, record, verifier, readback=readback)

def restore(journal, domain, cfg, record, verifier, readback=None):
    if readback is None:
        readback = core.current
    state = classify(record, readback(cfg, domain))
    if state == "unknown":
        raise JournalError("CGP changed before recovery; refusing write")
    if journal.read(domain)["phase"] != "restoring":
        journal.transition(domain, "restoring")
        # Persisting a phase may block on fsync; check again before the write.
        state = classify(record, readback(cfg, domain))
        if state == "unknown":
            raise JournalError("CGP changed while preparing recovery; refusing write")
    if state == "intended":
        core.update(cfg, domain, record["previous"])
    if not core.same(readback(cfg, domain), record["previous"]):
        raise JournalError("Recovery readback mismatch")
    # A failed TLS check retains the restoring journal for the administrator.
    verifier(record["previous"], record["previous_endpoints"])
    if not core.same(readback(cfg, domain), record["previous"]):
        raise JournalError("CGP changed during recovery verification")
    journal.transition(domain, "restored")
    journal.finish(domain)
    return "restored"
