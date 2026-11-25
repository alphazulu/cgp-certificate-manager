"""TSIG-authenticated RFC2136 challenges with exact RRset prerequisites.

One persistent generation TXT prevents a finished operation from restoring an
old mutation's prerequisite state. Per-receipt owner TXT records share the
challenge RRset, so a single authoritative read observes the whole ownership
pair. Foreign TXT wire values are never rewritten or deleted.
"""
from collections import Counter
import re
import secrets

import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.query
import dns.rdataclass
import dns.rdatatype
import dns.rcode
import dns.tsig
import dns.update

from . import rfc2136_config
from .dnsproviders import ProviderError, ProviderRejected


OWNER_PREFIX = b"cgp-certificate-manager:owner:"
GENERATION_PREFIX = b"cgp-certificate-manager:generation:"
MAX_RECORDS = 128
MAX_TXT_BYTES = 32768
_HEX = re.compile(r"[0-9a-f]{32}")
_VALUE = re.compile(r"[A-Za-z0-9_-]{43}")


def _failure():
    return ProviderError("RFC2136 evidence is unavailable or changed")


def _section(section):
    """Compare complete wire-record identity, retaining empty metavalues."""
    # Parsing an UPDATE moves the wire class NONE/ANY into ``deleting`` and
    # restores the zone class on the RRset. Compare the emitted class, so
    # constructed and parsed forms retain exactly the same identity.
    return Counter((rr.name, rr.rdclass if rr.deleting is None else rr.deleting,
                    rr.rdtype, rr.ttl,
                    None if rd is None else rd.to_wire())
                   for rr in section for rd in (tuple(rr) or (None,)))


def _update_reply(request, response):
    # RFC2136 permits an empty response or a full request echo. BIND also
    # retains just the matching zone. dnspython's is_response skips these
    # sections for UPDATE, so reject unrelated or partial echoes ourselves.
    question = _section(response.question)
    if (response.additional or response.opt is not None
            or question not in (Counter(), _section(request.question))):
        raise _failure()
    actual = (_section(response.answer), _section(response.authority))
    if any(actual) and (not question or actual != (_section(request.answer), _section(request.authority))):
        raise _failure()


class RFC2136Provider:
    name = provider_id = "rfc2136"
    capabilities = frozenset({"zone_discovery", "owned_txt"})

    def __init__(self, cfg, tcp=None):
        self._zones = rfc2136_config.validate(cfg)
        self._bindings = {zone["binding"]: zone for zone in self._zones}
        self._tcp = tcp

    def require(self, capability):
        if type(capability) is not str or capability not in self.capabilities:
            raise ProviderError("DNS provider capability unavailable")

    def credentials(self, cfg, absolute=False):
        return tuple(zone["credentials"] for zone in rfc2136_config.validate(cfg))

    def validate_credentials(self, cfg):
        for path in self.credentials(cfg):
            rfc2136_config.read_secret(path)

    def zones(self, cfg):
        self.require("zone_discovery")
        return {zone["zone"]: {"id": zone["binding"], "credentials": zone["credentials"],
                               "ns": list(zone["nameservers"]), "provider": self.name}
                for zone in rfc2136_config.validate(cfg)}

    def valid_zone_id(self, value):
        return isinstance(value, str) and value in self._bindings

    @staticmethod
    def valid_record_id(value):
        return isinstance(value, str) and _HEX.fullmatch(value) is not None

    def validate_binding(self, receipt):
        try:
            zone = self._bindings[receipt["zone"]]
            owner = receipt["owner"]
            nonce = owner.removeprefix("cgp-certificate-manager:")
            name = receipt["name"]
            parsed = dns.name.from_text(name)
            apex = dns.name.from_text(zone["zone"])
            if (receipt["credentials"] != zone["credentials"]
                    or owner != "cgp-certificate-manager:" + nonce
                    or not self.valid_record_id(nonce)
                    or name != parsed.canonicalize().to_text(omit_final_dot=True)
                    or not name.startswith("_acme-challenge.")
                    or parsed == apex or not parsed.is_subdomain(apex)
                    or not isinstance(receipt["value"], str) or not _VALUE.fullmatch(receipt["value"])
                    or receipt["record"] not in (None, nonce)):
                raise _failure()
        except Exception:
            raise _failure() from None

    def _zone(self, receipt):
        self.require("owned_txt")
        self.validate_binding(receipt)
        return self._bindings[receipt["zone"]]

    @staticmethod
    def _marker(receipt):
        return OWNER_PREFIX + receipt["owner"].rsplit(":", 1)[1].encode("ascii")

    def record_id(self, remote):
        result = remote.get("id") if isinstance(remote, dict) else None
        if not self.valid_record_id(result):
            raise _failure()
        return result

    @staticmethod
    def matches(remote, receipt, owned=False):
        return (remote.get("name") == receipt["name"] and remote.get("value") == receipt["value"]
                and (not owned or remote.get("owner") == receipt["owner"]))

    def _key(self, zone):
        return dns.tsig.Key(zone["key_name"], rfc2136_config.read_secret(zone["credentials"]),
                            algorithm=zone["algorithm"])

    def _exchange(self, message, zone):
        try:
            response = (self._tcp or dns.query.tcp)(message, zone["server"], timeout=10,
                                                   port=zone["port"])
            # dnspython 2.6 accepts an unsigned reply to a signed request.
            # Explicitly check the authenticated envelope on both profiles.
            if (not response.had_tsig or response.keyname != message.keyname
                    or response.keyalgorithm != message.keyalgorithm
                    or response.tsig_error != 0 or not message.is_response(response)
                    or response.flags & dns.flags.TC):
                raise _failure()
            code = response.rcode()
            if message.opcode() == dns.opcode.UPDATE:
                if code != dns.rcode.NOERROR:
                    raise _failure()
                _update_reply(message, response)
            elif code not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
                raise _failure()
            return response
        except Exception:
            raise _failure() from None

    def _query(self, zone, owner, kind):
        query = dns.message.make_query(owner, kind)
        query.flags = 0
        query.use_tsig(self._key(zone))
        response = self._exchange(query, zone)
        if (not response.flags & dns.flags.AA or len(response.question) != 1
                or response.question != query.question
                or any(rr.rdtype in (dns.rdatatype.CNAME, dns.rdatatype.DNAME)
                       for rr in response.answer + response.authority)):
            raise _failure()
        return response

    @staticmethod
    def _soa(response, zone):
        records = response.answer + response.authority
        if (len(records) != 1 or records[0].name != dns.name.from_text(zone["zone"])
                or records[0].rdclass != dns.rdataclass.IN
                or records[0].rdtype != dns.rdatatype.SOA or len(records[0]) != 1):
            raise _failure()

    def _snapshot(self, receipt):
        zone = self._zone(receipt)
        response = self._query(zone, receipt["name"], dns.rdatatype.TXT)
        if not response.answer:
            self._soa(response, zone)
            return (), 120, None
        if (response.rcode() != dns.rcode.NOERROR or len(response.answer) != 1
                or response.authority or response.answer[0].name != dns.name.from_text(receipt["name"])
                or response.answer[0].rdclass != dns.rdataclass.IN
                or response.answer[0].rdtype != dns.rdatatype.TXT
                or not 1 <= len(response.answer[0]) <= MAX_RECORDS):
            raise _failure()
        rrset = response.answer[0]
        values = tuple(rrset)
        if sum(sum(len(chunk) for chunk in rd.strings) for rd in values) > MAX_TXT_BYTES:
            raise _failure()
        generations = []
        owner_seen = False
        for rd in values:
            text = b"".join(rd.strings)
            for prefix in (GENERATION_PREFIX, OWNER_PREFIX):
                if text.startswith(prefix):
                    tail = text[len(prefix):]
                    if (len(rd.strings) != 1 or len(tail) != 32
                            or any(byte not in b"0123456789abcdef" for byte in tail)):
                        raise _failure()
                    if prefix == GENERATION_PREFIX:
                        generations.append(text)
                    else:
                        owner_seen = True
        if len(generations) > 1 or (owner_seen and not generations):
            raise _failure()
        return values, rrset.ttl, generations[0] if generations else None

    def _evidence(self, receipt, snapshot):
        values, _ttl, _generation = snapshot
        value = receipt["value"].encode("ascii")
        marker = self._marker(receipt)
        owned = any(rd.strings == (marker,) for rd in values)
        canonical = any(rd.strings == (value,) for rd in values)
        exists = any(b"".join(rd.strings) == value for rd in values)
        if owned and not canonical:
            raise _failure()
        if not exists:
            return None
        return {"id": receipt["owner"].rsplit(":", 1)[1], "name": receipt["name"],
                "value": receipt["value"], "owner": receipt["owner"] if owned else None}

    def list_records(self, receipt, exact_name=True, require_complete=False):
        # This one authoritative RRset is the complete ownership namespace;
        # there are no provider pages, remote record IDs or zone transfers.
        evidence = self._evidence(receipt, self._snapshot(receipt))
        return [] if evidence is None else [evidence]

    def get_record(self, receipt):
        snapshot = self._snapshot(receipt)
        evidence = self._evidence(receipt, snapshot)
        if evidence is None and snapshot[2] is None:
            raise _failure()
        return evidence

    def _update(self, receipt, snapshot, operation):
        zone = self._zone(receipt)
        values, ttl, generation = snapshot
        message = dns.update.Update(zone["zone"], keyring=self._key(zone))
        owner = dns.name.from_text(receipt["name"])
        if values:
            message.present(owner, *values)  # Full raw RDATA set, prerequisite TTL 0.
        else:
            message.absent(owner, dns.rdatatype.TXT)
        message.absent(owner, dns.rdatatype.CNAME)
        apex = dns.name.from_text(zone["zone"])
        label = owner
        while True:
            message.absent(label, dns.rdatatype.DNAME)
            if label == apex:
                break
            message.absent(label, dns.rdatatype.NS)
            label = label.parent()
        if operation != "prove":
            next_generation = GENERATION_PREFIX + secrets.token_hex(16).encode("ascii")
            if next_generation == generation:
                raise _failure()
            if generation is not None:
                message.delete(owner, "TXT", '"' + generation.decode("ascii") + '"')
            message.add(owner, ttl, "TXT", '"' + next_generation.decode("ascii") + '"')
            marker = self._marker(receipt).decode("ascii")
            if operation == "create":
                message.add(owner, ttl, "TXT", '"' + receipt["value"] + '"', '"' + marker + '"')
            else:
                message.delete(owner, "TXT", '"' + receipt["value"] + '"', '"' + marker + '"')
        self._exchange(message, zone)

    def create_txt(self, receipt):
        snapshot = self._snapshot(receipt)
        evidence = self._evidence(receipt, snapshot)
        if evidence is not None:
            if self.matches(evidence, receipt, owned=True):
                raise _failure()
            raise ProviderRejected("RFC2136 challenge already exists")
        added_bytes = len(receipt["value"]) + len(self._marker(receipt))
        if snapshot[2] is None:
            added_bytes += len(GENERATION_PREFIX) + 32
        existing_bytes = sum(sum(len(chunk) for chunk in rd.strings) for rd in snapshot[0])
        if (len(snapshot[0]) + (3 if snapshot[2] is None else 2) > MAX_RECORDS
                or existing_bytes + added_bytes > MAX_TXT_BYTES):
            raise ProviderRejected("RFC2136 challenge RRset is full")
        self._update(receipt, snapshot, "create")
        observed = self._snapshot(receipt)
        result = self._evidence(receipt, observed)
        if observed[2] is None or result is None or not self.matches(result, receipt, owned=True):
            raise _failure()
        return result

    def delete_record(self, receipt):
        snapshot = self._snapshot(receipt)
        evidence = self._evidence(receipt, snapshot)
        if (snapshot[2] is None or evidence is None
                or not self.matches(evidence, receipt, owned=True)):
            raise _failure()
        self._update(receipt, snapshot, "delete")

    def confirm_absent(self, receipt):
        snapshot = self._snapshot(receipt)
        if snapshot[2] is None or self._evidence(receipt, snapshot) is not None:
            raise _failure()
        # A signed authoritative answer can come from a newly delegated child.
        # Prerequisite-only UPDATE proves absence inside the configured zone,
        # with cut/alias guards, and makes no change to DNS data or generation.
        self._update(receipt, snapshot, "prove")
