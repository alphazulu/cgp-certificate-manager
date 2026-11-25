"""Bounded, conservative CAA preflight for Let's Encrypt DNS-01 issuance.

The caller supplies a validated DNS wire-response reader.  AD is reported only
as a resolver assertion; this module does not validate DNSSEC signatures.
RFC 8659 parent walking is independent of the alias chain at each lookup.
"""
import re
from urllib.parse import urlsplit

import dns.flags
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype

from . import core


MAX_QUERIES = 64
MAX_ALIASES = 16
MAX_CAA_RECORDS = 128
KNOWN_TAGS = {b"issue", b"issuewild", b"iodef", b"issuemail", b"issuevmc"}
ISSUER = "letsencrypt.org"
LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
ISSUER_NAME = re.compile(LABEL + r"(?:\." + LABEL + r")*")
PARAMETER_TAG = re.compile(LABEL)
PARAMETER_VALUE = re.compile(r"[\x21-\x3a\x3c-\x7e]*")


class _Failure(Exception):
    pass


def _name(name):
    """Allow a bounded printable DNS name, including underscore alias labels."""
    if (not name.is_absolute() or len(name.labels) < 2
            or any(not re.fullmatch(rb"[A-Za-z0-9_-]{1,63}", label)
                   for label in name.labels[:-1])):
        raise _Failure("invalid_response")
    # dns.name.Name enforces the DNS wire-length limits at construction.
    return b".".join(name.labels).decode("ascii").lower()


def _parameters(value):
    try:
        text = value.decode("ascii")
    except UnicodeError:
        return None
    parts = text.split(";")
    issuer = parts[0].strip(" \t")
    if issuer and not ISSUER_NAME.fullmatch(issuer):
        return None
    tail = parts[1:]
    if tail == [] or len(tail) == 1 and not tail[0].strip(" \t"):
        return issuer, []
    parameters = []
    for item in tail:
        pair = item.split("=", 1)
        if len(pair) != 2:
            return None
        tag, parameter = (part.strip(" \t") for part in pair)
        if not PARAMETER_TAG.fullmatch(tag) or not PARAMETER_VALUE.fullmatch(parameter):
            return None
        parameters.append((tag, parameter))
    return issuer, parameters


def _grant(value, account_uri):
    parsed = _parameters(value)
    if parsed is None or parsed[0] != ISSUER:
        return False, None
    parameters = parsed[1]
    accounts = [value for tag, value in parameters if tag == "accounturi"]
    methods = [value for tag, value in parameters if tag == "validationmethods"]
    if len(accounts) > 1 or len(methods) > 1:
        return False, None
    if methods:
        labels = methods[0].split(",")
        if (any(not re.fullmatch(r"[A-Za-z0-9-]+", label) for label in labels)
                or "dns-01" not in labels):
            return False, None
    if accounts:
        try:
            uri = urlsplit(accounts[0])
        except ValueError:
            return False, None
        if not uri.scheme or not (uri.netloc or uri.path):
            return False, None
        if account_uri is not None and accounts[0] != account_uri:
            return False, None
    if any(tag not in ("accounturi", "validationmethods") for tag, _ in parameters):
        return None, "unsupported_parameter"
    if accounts and account_uri is None:
        return None, "account_unknown"
    return True, None


def _policy(records, wildcard, account_uri):
    if len(records) > MAX_CAA_RECORDS:
        raise _Failure("record_limit")
    by_tag = {}
    for record in records:
        # dnspython's CAA constructor validates the wire tag as ASCII alnum.
        tag = record.tag.lower()
        # Boulder deliberately recognizes bit 1 as an alias for critical 128.
        if tag not in KNOWN_TAGS and record.flags & 129:
            return "denied", "unknown_critical_property"
        by_tag.setdefault(tag, []).append(record)
    selected = by_tag.get(b"issuewild" if wildcard and b"issuewild" in by_tag else b"issue", [])
    if not selected:
        return "not_restricted", "no_applicable_policy"
    uncertain = set()
    for record in selected:
        grant, reason = _grant(record.value, account_uri)
        if grant is True:
            return "allowed", "issuer_authorized"
        if grant is None:
            uncertain.add(reason)
    if uncertain:
        return "indeterminate", sorted(uncertain)[0]
    return "denied", "issuer_not_authorized"


class _Search:
    def __init__(self, query):
        self.query = query
        self.queries = 0
        self.authenticated = True
        self.chain = []
        self.lookup = None

    def ask(self, name):
        if self.queries >= MAX_QUERIES:
            raise _Failure("lookup_limit")
        self.queries += 1
        try:
            response = self.query(_name(name), "CAA")
        except core.Error:
            self.authenticated = False
            raise _Failure("lookup_failed") from None
        self.authenticated = self.authenticated and bool(response.flags & dns.flags.AD)
        return response

    def alias(self, current, target, kind, visited):
        target = dns.name.from_text(_name(target)).canonicalize()
        if target in visited:
            raise _Failure("alias_loop")
        if len(visited) > MAX_ALIASES:
            raise _Failure("alias_limit")
        visited.add(target)
        self.chain.append({"from": _name(current), "to": _name(target), "type": kind})
        return target

    def lookup_set(self, original):
        current = original
        visited = {current}
        while True:
            response = self.ask(current)
            relevant = {}
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    continue
                if (rrset.rdclass != dns.rdataclass.IN or not rrset
                        or rrset.rdtype not in (dns.rdatatype.CAA, dns.rdatatype.CNAME, dns.rdatatype.DNAME)):
                    raise _Failure("invalid_response")
                owner = dns.name.from_text(_name(rrset.name)).canonicalize()
                key = owner, rrset.rdtype
                if key in relevant:
                    raise _Failure("invalid_response")
                relevant[key] = rrset
            used = set()
            redirected = False
            while True:
                caa_key = current, dns.rdatatype.CAA
                cname_key = current, dns.rdatatype.CNAME
                caa = relevant.get(caa_key)
                cname = relevant.get(cname_key)
                dnames = [(key, rrset) for key, rrset in relevant.items()
                          if key[1] == dns.rdatatype.DNAME and current != key[0]
                          and current.is_subdomain(key[0])]
                if len(dnames) > 1 or caa is not None and (cname is not None or dnames):
                    raise _Failure("invalid_response")
                if caa is not None:
                    used.add(caa_key)
                    if used != relevant.keys() or response.rcode() != dns.rcode.NOERROR:
                        raise _Failure("invalid_response")
                    return caa, current
                if dnames:
                    key, dname = dnames[0]
                    # DNAME changes only a proper suffix; its synthesized CNAME
                    # must name exactly that substitution when both are present.
                    try:
                        target = dns.name.Name(current.labels[:-len(key[0].labels)] + dname[0].target.labels)
                    except dns.name.NameTooLong:
                        raise _Failure("invalid_response") from None
                    if cname is not None and cname[0].target != target:
                        raise _Failure("invalid_response")
                    used.add(key)
                    kind = "DNAME"
                elif cname is not None:
                    target = cname[0].target
                    kind = "CNAME"
                else:
                    break
                if cname is not None:
                    used.add(cname_key)
                current = self.alias(current, target, kind, visited)
                redirected = True
            if used != relevant.keys():
                raise _Failure("invalid_response")
            soas = [rr for rr in response.authority if rr.rdtype == dns.rdatatype.SOA]
            if len(soas) > 1 or any(rr.rdclass != dns.rdataclass.IN or not current.is_subdomain(rr.name) for rr in soas):
                raise _Failure("invalid_response")
            has_soa = bool(soas)
            if not has_soa and any(rr.rdtype == dns.rdatatype.NS for rr in response.authority):
                raise _Failure("incomplete_referral")
            if has_soa:
                return None, current
            if response.rcode() == dns.rcode.NXDOMAIN or not redirected:
                # Some recursive servers omit SOA from negatives.  That is
                # insufficient evidence for this conservative preflight.
                raise _Failure("incomplete_negative_response")
            # A CNAME-only response has not established absence at its target.
            # Query that target itself, never any of its parents.


def _report(search, decision, reason, owner=None):
    return {"decision": decision, "reason": reason,
            "lookup_name": search.lookup, "rrset_owner": _name(owner) if owner is not None else None,
            "alias_chain": search.chain,
            "dnssec": "secure_by_resolver" if search.queries and search.authenticated else "not_authenticated"}


def check(identifier, query, account_uri=None):
    """Evaluate an identifier using one resolver view and a fixed safe report.

    ``query`` must return a validated matching recursive CAA response with
    RCODE NOERROR/NXDOMAIN and no CD/TC, or raise ``core.Error``.  No account
    identity is guessed.  Unknown parameters or account bindings do not grant
    permission, while an independent satisfiable CAA record still may do so.
    """
    search = _Search(query)
    try:
        normalized, error = core.dns_name(identifier) if isinstance(identifier, str) else (None, True)
        if error:
            raise _Failure("invalid_identifier")
        wildcard = normalized.startswith("*.")
        name = dns.name.from_text(normalized.removeprefix("*.") + ".")
        while name != dns.name.root:
            search.lookup = _name(name)
            records, owner = search.lookup_set(name)
            if records is not None:
                decision, reason = _policy(records, wildcard, account_uri)
                return _report(search, decision, reason, owner)
            name = name.parent()
        search.lookup = None
        return _report(search, "not_restricted", "no_caa")
    except _Failure as error:
        search.authenticated = False
        return _report(search, "indeterminate", str(error))
