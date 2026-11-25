"""Provider-bound Route53 TXT ownership using atomic exact-preimage batches.

Only simple public-zone TXT sets are supported. An exact DELETE followed by
CREATE conditionally replaces the complete set while preserving foreign raw
values and TTL. One retained generation value prevents old accepted changes
from becoming valid again after their challenge has been cleaned up.
"""
from datetime import datetime
import re
import secrets
import xml.etree.ElementTree as ET

import dns.name

from . import route53_api, route53_config
from .dnsproviders import ProviderError, ProviderRejected


OWNER_PREFIX = b"cgp-certificate-manager:owner:"
GENERATION_PREFIX = b"cgp-certificate-manager:generation:"
MAX_RECORDS = 128
MAX_VALUE_CHARS = 4000
MAX_BATCH_CHARS = 32000
MAX_BATCH_RECORDS = 1000
_HEX = re.compile(r"[0-9a-f]{32}")
_VALUE = re.compile(r"[A-Za-z0-9_-]{43}")
_TYPES = frozenset({"SOA", "A", "TXT", "NS", "CNAME", "MX", "NAPTR", "PTR", "SRV",
                    "SPF", "AAAA", "CAA", "DS", "TLSA", "SSHFP", "SVCB", "HTTPS"})


def _failure():
    return ProviderError("Route53 evidence is unavailable or changed")


def _tag(name):
    return "{" + route53_api.NS + "}" + name


def _container(element):
    if (not isinstance(element, ET.Element) or element.attrib
            or (element.text or "").strip()
            or any((child.tail or "").strip() for child in element)):
        raise _failure()


def _fields(element, required, optional=()):
    _container(element)
    allowed = {_tag(name): name for name in (*required, *optional)}
    result = {}
    for child in element:
        name = allowed.get(child.tag)
        if name is None or name in result:
            raise _failure()
        result[name] = child
    if set(required) - set(result):
        raise _failure()
    return result


def _root(element, name, required, optional=()):
    if not isinstance(element, ET.Element) or element.tag != _tag(name):
        raise _failure()
    return _fields(element, required, optional)


def _text(element, empty=False):
    if element.attrib or len(element) or (not empty and not element.text):
        raise _failure()
    return element.text or ""


def _array(element, name):
    _container(element)
    if any(child.tag != _tag(name) for child in element):
        raise _failure()
    return tuple(element)


def _integer(element, maximum):
    value = _text(element)
    if not re.fullmatch(r"0|[1-9][0-9]{0,19}", value) or int(value) > maximum:
        raise _failure()
    return int(value)


def _dns_order(value):
    # Restrict negative-list evidence to an unambiguous ASCII DNS spelling.
    # Exotic escaped owner names are unsupported, rather than guessed.
    if (len(value) > 254 or not value.endswith(".")
            or any(re.fullmatch(r"[a-z0-9_-]{1,63}", label) is None
                   for label in value[:-1].split("."))):
        raise _failure()
    return ".".join(reversed(value[:-1].split("."))) + "."


def _identity(element):
    """Read only direct unique identity fields before interpreting a row.

    A later owner proves that the requested earlier TXT is absent even when
    the later record uses aliases or routing policies. Its payload is outside
    this adapter's ownership scope and must not limit first issuance.
    """
    _container(element)
    prefix = "{" + route53_api.NS + "}"
    fields = {}
    for child in element:
        if not isinstance(child.tag, str) or not child.tag.startswith(prefix):
            raise _failure()
        name = child.tag[len(prefix):]
        if name in ("Name", "Type"):
            if name in fields:
                raise _failure()
            fields[name] = child
    if set(fields) != {"Name", "Type"}:
        raise _failure()
    return _text(fields["Name"]), _text(fields["Type"])


def _txt(value):
    """Decode AWS TXT chunks, whose documented numeric escapes are octal.

    The original presentation string remains the mutation preimage. Decoding
    is only for collision/ownership evidence, never for rewriting foreign TXT.
    """
    if (not 2 <= len(value) <= MAX_VALUE_CHARS
            or any(not 32 <= ord(char) <= 126 for char in value)):
        raise _failure()
    offset = 0
    chunks = []
    while offset < len(value):
        if value[offset] != '"':
            raise _failure()
        offset += 1
        chunk = bytearray()
        while offset < len(value) and value[offset] != '"':
            char = value[offset]
            offset += 1
            if char == "\\":
                escape = value[offset:offset + 3]
                if re.fullmatch(r"[0-3][0-7]{2}", escape):
                    chunk.append(int(escape, 8))
                    offset += 3
                elif offset < len(value) and value[offset] in ('"', "\\"):
                    chunk.append(ord(value[offset]))
                    offset += 1
                else:
                    raise _failure()
            else:
                chunk.append(ord(char))
        if offset == len(value) or len(chunk) > 255:
            raise _failure()
        chunks.append(bytes(chunk))
        offset += 1
        if offset < len(value):
            if value[offset] != " ":
                raise _failure()
            while offset < len(value) and value[offset] == " ":
                offset += 1
            if offset == len(value):
                raise _failure()
    return tuple(chunks)


class Route53Provider:
    name = provider_id = "route53"
    capabilities = frozenset({"zone_discovery", "owned_txt"})

    def __init__(self, cfg, client_factory=None):
        self._zones = route53_config.validate(cfg)
        self._bindings = {zone["binding"]: zone for zone in self._zones}
        self._client_factory = client_factory

    def require(self, capability):
        if type(capability) is not str or capability not in self.capabilities:
            raise ProviderError("DNS provider capability unavailable")

    def credentials(self, cfg, absolute=False):
        return tuple(zone["credentials"] for zone in route53_config.validate(cfg))

    def validate_credentials(self, cfg):
        for path in self.credentials(cfg):
            route53_config.read_secret(path)

    def zones(self, cfg):
        self.require("zone_discovery")
        return {zone["zone"]: {"id": zone["binding"], "credentials": zone["credentials"],
                               "ns": list(zone["nameservers"]), "provider": self.name}
                for zone in route53_config.validate(cfg)}

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
            _dns_order(name + ".")
        except Exception:
            raise _failure() from None

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

    @staticmethod
    def _call(method, *args):
        try:
            return method(*args)
        except Exception:
            # Even a remote 400 or malformed acknowledgement is uncertain.
            raise _failure() from None

    def _client(self, receipt):
        self.require("owned_txt")
        self.validate_binding(receipt)
        zone = self._bindings[receipt["zone"]]
        client = self._call(self._client_factory or route53_api.Client, zone)
        response = self._call(client.get_zone)
        root = _root(response, "GetHostedZoneResponse", ("HostedZone", "DelegationSet"))
        hosted = _fields(root["HostedZone"], ("Id", "Name", "CallerReference", "Config",
                                             "ResourceRecordSetCount"))
        config = _fields(hosted["Config"], ("PrivateZone",), ("Comment",))
        if (_text(hosted["Id"]) != "/hostedzone/" + zone["hosted_zone_id"]
                or _text(hosted["Name"]) != zone["zone"] + "."
                or _text(config["PrivateZone"]) != "false"
                or len(_text(hosted["CallerReference"])) > 128):
            raise _failure()
        _integer(hosted["ResourceRecordSetCount"], 2 ** 63 - 1)
        if "Comment" in config:
            _text(config["Comment"], empty=True)
        delegation = _fields(root["DelegationSet"], ("NameServers",), ("Id", "CallerReference"))
        for name in ("Id", "CallerReference"):
            if name in delegation:
                _text(delegation[name])
        names = tuple(_text(row).removesuffix(".")
                      for row in _array(delegation["NameServers"], "NameServer"))
        if len(names) != len(set(names)) or set(names) != set(zone["nameservers"]):
            raise _failure()
        return client

    def _snapshot(self, client, receipt):
        root = _root(self._call(client.records, receipt["name"]), "ListResourceRecordSetsResponse",
                     ("ResourceRecordSets", "IsTruncated", "MaxItems"),
                     ("NextRecordName", "NextRecordType", "NextRecordIdentifier"))
        rows = _array(root["ResourceRecordSets"], "ResourceRecordSet")
        truncated = _text(root["IsTruncated"])
        next_fields = set(root) & {"NextRecordName", "NextRecordType", "NextRecordIdentifier"}
        if (_text(root["MaxItems"]) != "1" or len(rows) > 1
                or truncated not in ("true", "false")
                or (truncated == "false" and next_fields)
                or (truncated == "true" and
                    (len(rows) != 1 or not {"NextRecordName", "NextRecordType"} <= next_fields))):
            raise _failure()
        if truncated == "true":
            next_name = _text(root["NextRecordName"])
            _dns_order(next_name)
            next_type = _text(root["NextRecordType"])
            if next_type not in _TYPES:
                raise _failure()
            if "NextRecordIdentifier" in root and len(_text(root["NextRecordIdentifier"])) > 128:
                raise _failure()
        if not rows:
            return (), 120, None, ()
        name, kind = _identity(rows[0])
        order = _dns_order(name)
        target = _dns_order(receipt["name"] + ".")
        if (kind not in _TYPES or order < target or (order == target and kind != "TXT")
                or (truncated == "true" and
                    (_dns_order(next_name) < order or (next_name == name and next_type == kind and
                     (order == target or "NextRecordIdentifier" not in root))))):
            raise _failure()
        if order > target:
            return (), 120, None, ()
        row = _fields(rows[0], ("Name", "Type", "TTL", "ResourceRecords"), ("MultiValueAnswer",))
        if "MultiValueAnswer" in row and _text(row["MultiValueAnswer"]) != "false":
            raise _failure()
        ttl = _integer(row["TTL"], 2 ** 31 - 1)
        raw = tuple(_text(_fields(item, ("Value",))["Value"])
                    for item in _array(row["ResourceRecords"], "ResourceRecord"))
        if not 1 <= len(raw) <= MAX_RECORDS or sum(map(len, raw)) > MAX_BATCH_CHARS:
            raise _failure()
        decoded = tuple(_txt(value) for value in raw)
        if len(set(decoded)) != len(decoded):
            raise _failure()
        generations = []
        owner_seen = False
        for value, chunks in zip(raw, decoded):
            text = b"".join(chunks)
            for prefix in (GENERATION_PREFIX, OWNER_PREFIX):
                if text.startswith(prefix):
                    tail = text[len(prefix):]
                    if (len(tail) != 32 or any(byte not in b"0123456789abcdef" for byte in tail)
                            or value != '"' + text.decode("ascii") + '"'):
                        raise _failure()
                    if prefix == GENERATION_PREFIX:
                        generations.append(value)
                    else:
                        owner_seen = True
        if len(generations) > 1 or (owner_seen and not generations):
            raise _failure()
        return raw, ttl, generations[0] if generations else None, decoded

    def _evidence(self, receipt, snapshot):
        raw, _ttl, _generation, decoded = snapshot
        value = receipt["value"].encode("ascii")
        owned = '"' + self._marker(receipt).decode("ascii") + '"' in raw
        canonical = '"' + receipt["value"] + '"' in raw
        if owned and not canonical:
            raise _failure()
        if not any(b"".join(chunks) == value for chunks in decoded):
            return None
        return {"id": receipt["owner"].rsplit(":", 1)[1], "name": receipt["name"],
                "value": receipt["value"], "owner": receipt["owner"] if owned else None}

    def list_records(self, receipt, exact_name=True, require_complete=False):
        evidence = self._evidence(receipt, self._snapshot(self._client(receipt), receipt))
        return [] if evidence is None else [evidence]

    def get_record(self, receipt):
        snapshot = self._snapshot(self._client(receipt), receipt)
        evidence = self._evidence(receipt, snapshot)
        if evidence is None and snapshot[2] is None:
            raise _failure()
        return evidence

    @staticmethod
    def _ack(response):
        root = _root(response, "ChangeResourceRecordSetsResponse", ("ChangeInfo",))
        info = _fields(root["ChangeInfo"], ("Id", "Status", "SubmittedAt"), ("Comment",))
        if (not re.fullmatch(r"/change/[A-Z0-9]{1,32}", _text(info["Id"]))
                or _text(info["Status"]) not in ("PENDING", "INSYNC")):
            raise _failure()
        when = _text(info["SubmittedAt"])
        if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z", when):
            raise _failure()
        try:
            datetime.fromisoformat(when.replace("Z", "+00:00"))
        except ValueError:
            raise _failure() from None
        if "Comment" in info:
            _text(info["Comment"], empty=True)

    def _update(self, client, receipt, snapshot, create):
        raw, ttl, generation, _decoded = snapshot
        next_generation = '"' + GENERATION_PREFIX.decode("ascii") + secrets.token_hex(16) + '"'
        if next_generation == generation:
            raise _failure()
        pair = ('"' + receipt["value"] + '"', '"' + self._marker(receipt).decode("ascii") + '"')
        remaining = tuple(value for value in raw if value != generation and (create or value not in pair))
        after = remaining + (next_generation,) + (pair if create else ())
        if (len(after) > MAX_RECORDS or len(raw) + len(after) > MAX_BATCH_RECORDS
                or sum(map(len, raw + after)) > MAX_BATCH_CHARS):
            if create:
                raise ProviderRejected("Route53 challenge RRset is full")
            raise _failure()
        self._ack(self._call(client.change, receipt["name"], ttl, raw, after))

    def create_txt(self, receipt):
        client = self._client(receipt)
        snapshot = self._snapshot(client, receipt)
        evidence = self._evidence(receipt, snapshot)
        if evidence is not None:
            if self.matches(evidence, receipt, owned=True):
                raise _failure()
            raise ProviderRejected("Route53 challenge already exists")
        self._update(client, receipt, snapshot, create=True)
        observed = self._snapshot(client, receipt)
        result = self._evidence(receipt, observed)
        if observed[2] is None or result is None or not self.matches(result, receipt, owned=True):
            raise _failure()
        return result

    def delete_record(self, receipt):
        client = self._client(receipt)
        snapshot = self._snapshot(client, receipt)
        evidence = self._evidence(receipt, snapshot)
        if snapshot[2] is None or evidence is None or not self.matches(evidence, receipt, owned=True):
            raise _failure()
        self._update(client, receipt, snapshot, create=False)
        observed = self._snapshot(client, receipt)
        if observed[2] is None or self._evidence(receipt, observed) is not None:
            raise _failure()

    def confirm_absent(self, receipt):
        snapshot = self._snapshot(self._client(receipt), receipt)
        if snapshot[2] is None or self._evidence(receipt, snapshot) is not None:
            raise _failure()
        # The authenticated control-plane lookup is fixed to the configured
        # hosted-zone ID; DNS delegations cannot redirect it to another zone.
