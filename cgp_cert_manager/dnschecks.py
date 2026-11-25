"""Conservative DNS-01 preflight and observation-based TXT readiness.

Delegated challenge zones/aliases are diagnosed, not followed by the writer.
Every configured parent and child NS must answer; each NS may have multiple
addresses. These are observations, not a promise about every anycast location.
"""
import time

import dns.flags
import dns.name
import dns.rcode
import dns.rdatatype

from . import caa, core, dnsconfig, dnsquery
from .dnsquery import QueryError, name


def _alias_free(response):
    if any(rr.rdtype in (dns.rdatatype.CNAME, dns.rdatatype.DNAME)
           for rr in response.answer):
        raise QueryError("challenge_alias_unsupported")


def _records(response, owner, kind, authority=False):
    owner = name(owner)
    rdtype = dns.rdatatype.from_text(kind)
    sections = response.answer + (response.authority if authority else [])
    return [record for rrset in sections
            if name(rrset.name.to_text()) == owner and rrset.rdtype == rdtype
            for record in rrset]


def _soa(response, owner):
    _alias_free(response)
    owner = dns.name.from_text(name(owner))
    candidates = {name(rr.name.to_text()) for rr in response.answer + response.authority
                  if rr.rdtype == dns.rdatatype.SOA}
    if len(candidates) != 1:
        raise QueryError("dns_zone_cut_unknown")
    zone = candidates.pop()
    if not owner.is_subdomain(dns.name.from_text(zone)):
        raise QueryError("dns_zone_cut_unknown")
    return zone


def _ns(response, owner, authority=False):
    _alias_free(response)
    servers = {name(record.target.to_text()) for record in _records(response, owner, "NS", authority)}
    if response.rcode() != dns.rcode.NOERROR or not 1 <= len(servers) <= 16:
        raise QueryError("dns_nameservers_unknown")
    return servers


class View:
    def __init__(self, client, resolver):
        self.client = client
        self.resolver = resolver
        self.addresses = {}

    def query(self, owner, kind):
        return self.client.recursive(owner, kind, self.resolver)

    def authoritative(self, owner, kind, server):
        if server not in self.addresses:
            addresses = set()
            for family in ("A", "AAAA"):
                response = self.query(server, family)
                _alias_free(response)
                addresses.update(record.address for record in _records(response, server, family))
            if not 1 <= len(addresses) <= 16:
                raise QueryError("dns_nameserver_addresses_unknown")
            self.addresses[server] = sorted(addresses)
        for address in self.addresses[server]:
            try:
                return self.client.authoritative(owner, kind, address)
            except QueryError:
                pass
        raise QueryError("authoritative_nameserver_unreachable")


def delegation(view, zone, servers, owners):
    """Check parent referral, child apex and the actual challenge zone cut."""
    zone = name(zone)
    expected = {name(server) for server in servers}
    if not 1 <= len(expected) <= 16:
        raise QueryError("provider_nameservers_unknown")
    parent_name = dns.name.from_text(zone).parent().to_text()
    parent_zone = _soa(view.query(parent_name, "SOA"), parent_name)
    parent_servers = _ns(view.query(parent_zone, "NS"), parent_zone)
    for server in sorted(parent_servers):
        response = view.authoritative(zone, "NS", server)
        # A server hosting both zones may return its child-apex answer here.
        # That cannot establish what the parent actually delegates.
        if response.flags & dns.flags.AA or response.answer:
            raise QueryError("parent_delegation_unproven")
        if _ns(response, zone, authority=True) != expected:
            raise QueryError("parent_delegation_mismatch")
    if _ns(view.query(zone, "NS"), zone) != expected:
        raise QueryError("recursive_delegation_mismatch")
    for server in sorted(expected):
        for owner, kind in [(zone, "SOA"), (zone, "NS")] + [(owner, "SOA") for owner in sorted(owners)]:
            response = view.authoritative(owner, kind, server)
            if not response.flags & dns.flags.AA:
                raise QueryError("child_not_authoritative")
            if owner == zone and kind == "SOA" and (
                    response.rcode() != dns.rcode.NOERROR
                    or len(_records(response, zone, "SOA")) != 1):
                raise QueryError("child_apex_unproven")
            if kind == "NS":
                if _ns(response, zone) != expected:
                    raise QueryError("child_nameservers_mismatch")
            elif _soa(response, owner) != zone:
                raise QueryError("challenge_delegation_unsupported")
    for owner in sorted(owners):
        if _soa(view.query(owner, "SOA"), owner) != zone:
            raise QueryError("challenge_delegation_unsupported")
    return {"check": "delegation", "resolver": view.resolver, "zone": zone,
            "parent_zone": parent_zone, "nameservers": sorted(expected), "ready": True}


def dnssec(view, zone):
    """Report the selected validators' evidence without claiming local validation."""
    ds = view.query(zone, "DS")
    keys = view.query(zone, "DNSKEY")
    _alias_free(ds)
    _alias_free(keys)
    if ds.rcode() != dns.rcode.NOERROR or keys.rcode() != dns.rcode.NOERROR:
        raise QueryError("dnssec_zone_not_found")
    for response, kind in ((ds, "DS"), (keys, "DNSKEY")):
        rdtype = dns.rdatatype.from_text(kind)
        if any(name(rr.name.to_text()) != name(zone)
               or rr.rdtype not in (rdtype, dns.rdatatype.RRSIG)
               or (rr.rdtype == dns.rdatatype.RRSIG and rr.covers != rdtype)
               for rr in response.answer):
            raise QueryError("dnssec_unexpected_answer")
    if _records(ds, zone, "DS"):
        if not (ds.flags & keys.flags & dns.flags.AD) or not _records(keys, zone, "DNSKEY"):
            raise QueryError("dnssec_chain_not_authenticated")
        evidence = "secure_by_resolver"
    else:
        # AD=0 cannot distinguish an unsigned zone from missing validation.
        # DS belongs to the parent: a child cannot prove its own delegation
        # is unsigned. Require proper-ancestor negative evidence.
        if ds.answer or _soa(ds, zone) == name(zone):
            raise QueryError("dnssec_parent_denial_unproven")
        evidence = "no_ds_by_resolver" if ds.flags & dns.flags.AD else "not_authenticated"
    return {"check": "dnssec", "resolver": view.resolver, "zone": name(zone),
            "evidence": evidence, "local_validation": False, "ready": True}


def _groups(identifiers, zones):
    groups = {}
    for identifier in identifiers:
        normalized, error = core.dns_name(identifier)
        if error or normalized != identifier:
            raise QueryError("invalid_certificate_identifier")
        zone = core.zone_for(identifier, zones)
        if zone is None:
            raise QueryError("cloudflare_zone_unavailable")
        groups.setdefault(zone, set()).add("_acme-challenge." + identifier.removeprefix("*."))
    if not groups:
        raise QueryError("no_certificate_identifiers")
    return groups


def inspect(domain, zones, cfg=None):
    options = dnsconfig.validate(cfg or {})
    report = {"domain": domain["cgp_domain"], "ready": False,
              "preflight_enabled": options["preflight"], "checks": [], "reason": None}
    try:
        if domain.get("unavailable"):
            raise QueryError("cloudflare_identifiers_unavailable")
        groups = _groups(domain["names"], zones)
        client = dnsquery.Client()
        for resolver in dnsquery.RESOLVERS:
            view = View(client, resolver)
            for zone, owners in groups.items():
                report["checks"].append(delegation(view, zone, zones[zone].get("ns", []), owners))
                report["checks"].append(dnssec(view, zone))
            for identifier in domain["names"]:
                policy = caa.check(identifier, view.query)
                ready = policy["decision"] in ("allowed", "not_restricted")
                report["checks"].append(dict(policy, check="caa", resolver=resolver,
                                             identifier=identifier, ready=ready))
                if not ready:
                    raise QueryError("caa_" + policy["decision"])
        report["ready"] = True
    except QueryError as exc:
        report["reason"] = exc.code
        report["checks"].append({"check": "failure", "ready": False,
                                 "reason": exc.code, "ede_codes": list(exc.ede)})
    return report


def require_ready(domain, zones, cfg=None):
    report = inspect(domain, zones, cfg)
    if not report["ready"]:
        raise core.Error("DNS preflight blocked: " + report["reason"])


def reports(cfg, domain=None):
    dnsconfig.validate(cfg)
    zones = core.zones(cfg)
    domains = core.discover(cfg, zones)
    if domain is not None:
        domains = [item for item in domains if item["cgp_domain"] == domain]
        if not domains:
            raise core.Error("DNS diagnostic domain not found")
    return [inspect(item, zones, cfg) for item in domains]


def _txt(response, owner, authoritative=False):
    _alias_free(response)
    if authoritative and not response.flags & dns.flags.AA:
        raise QueryError("txt_not_authoritative")
    if response.rcode() == dns.rcode.NXDOMAIN:
        return set()
    return {b"".join(record.strings) for record in _records(response, owner, "TXT")}


def wait_for_txt(challenges, zones, timeout_seconds=300, poll_interval_seconds=5):
    """Require two fresh complete passes, under a single monotonic deadline."""
    groups = _groups([identifier for identifier, value in challenges], zones)
    wanted = {}
    for identifier, value in challenges:
        owner = "_acme-challenge." + identifier.removeprefix("*.")
        if not isinstance(value, str) or not value or not value.isascii():
            raise QueryError("invalid_challenge_value")
        wanted.setdefault(owner, set()).add(value.encode("ascii"))
    client = dnsquery.Client(timeout=timeout_seconds, max_queries=100000)
    views = [View(client, resolver) for resolver in dnsquery.RESOLVERS]
    consecutive = 0
    while True:
        complete = True
        for zone, owners in groups.items():
            servers = zones[zone].get("ns", [])
            if not servers:
                raise QueryError("provider_nameservers_unknown")
            for owner in sorted(owners):
                # Check every required observer on every pass. A previous
                # success must not survive an intervening stale/failed pass.
                for view in views:
                    try:
                        for server in sorted(servers):
                            response = view.authoritative(owner, "TXT", name(server))
                            complete &= wanted[owner] <= _txt(response, owner, True)
                        response = view.query(owner, "TXT")
                        complete &= wanted[owner] <= _txt(response, owner)
                    except QueryError:
                        complete = False
        dnsquery.remaining(client.deadline)
        consecutive = consecutive + 1 if complete else 0
        if consecutive == 2:
            return
        time.sleep(min(poll_interval_seconds, dnsquery.remaining(client.deadline)))
