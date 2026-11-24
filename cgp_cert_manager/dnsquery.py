"""Bounded DNS wire queries to named HTTPS validators and authoritative NS.

AD is evidence from the authenticated recursive service, not local DNSSEC
validation. No untrusted DNS presentation/zone-file text is parsed here.
"""
import http.client
import io
import ipaddress
import re
import socket
import ssl
import time

import dns.edns
import dns.exception
import dns.flags
import dns.message
import dns.opcode
import dns.query
import dns.rdataclass
import dns.rdatatype
import dns.rcode

from .core import Error


RESOLVERS = {"cloudflare": ("1.1.1.1", "cloudflare-dns.com"),
             "google": ("8.8.8.8", "dns.google")}
MAX_WIRE = 65535


class QueryError(Error):
    """Public errors contain only a fixed code and optional numeric EDE codes."""
    def __init__(self, code, ede=()):
        self.code = code
        self.ede = tuple(sorted(set(ede)))
        super().__init__(code)


def name(value):
    """Canonical absolute ASCII owner, including root and service labels."""
    if not isinstance(value, str):
        raise QueryError("invalid_dns_owner")
    if not value:
        raise QueryError("invalid_dns_owner")
    value = value.lower().removesuffix(".")
    if len(value) > 253 or (value and any(
            not re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", label)
            for label in value.split("."))):
        raise QueryError("invalid_dns_owner")
    return value + "."


def remaining(deadline):
    left = deadline - time.monotonic()
    if left <= 0:
        raise QueryError("dns_timeout")
    return left


class _DeadlineReader(io.RawIOBase):
    """Refresh an absolute deadline below HTTP's buffered/header parser."""
    def __init__(self, raw, sock, deadline):
        self.raw = raw
        self.sock = sock
        self.deadline = deadline

    def readable(self):
        return True

    def readinto(self, buffer):
        self.sock.settimeout(remaining(self.deadline))
        return self.raw.readinto(buffer)

    def close(self):
        try:
            self.raw.close()
        finally:
            super().close()


class _DeadlineSocket:
    """Only the socket operations used by HTTPConnection/HTTPResponse."""
    def __init__(self, sock, deadline):
        self.sock = sock
        self.deadline = deadline

    def makefile(self, mode):
        # Use the real socket's file reference counting: Connection: close can
        # close HTTPConnection before HTTPResponse has consumed its body.
        return io.BufferedReader(_DeadlineReader(
            self.sock.makefile(mode, buffering=0), self.sock, self.deadline))

    def sendall(self, data):
        pending = memoryview(data)
        while pending:
            self.sock.settimeout(remaining(self.deadline))
            sent = self.sock.send(pending)
            if sent == 0:
                raise OSError("DNS socket closed during send")
            pending = pending[sent:]

    def close(self):
        self.sock.close()


class _HTTPSConnection(http.client.HTTPSConnection):
    """Known literal IPv4 endpoint; normal HTTPS hostname verification/SNI."""
    def __init__(self, hostname, address, deadline, context):
        super().__init__(hostname, timeout=remaining(deadline), context=context)
        self.address = address
        self.deadline = deadline

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.settimeout(remaining(self.deadline))
            self.sock.connect((self.address, 443))
            self.sock.settimeout(remaining(self.deadline))
            self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)
            self.sock = _DeadlineSocket(self.sock, self.deadline)
        except BaseException:
            self.sock.close()
            self.sock = None
            raise


def _message(owner, kind, recursive):
    query = dns.message.make_query(name(owner), kind, want_dnssec=True)
    query.flags = dns.flags.RD if recursive else 0
    return query


def _checked(query, response, recursive):
    if (not query.is_response(response) or response.opcode() != dns.opcode.QUERY
            or response.question != query.question
            or response.flags & (dns.flags.TC | dns.flags.CD)
            or (recursive and not response.flags & dns.flags.RA)):
        raise QueryError("invalid_dns_response")
    ede = [int(option.code) for option in response.options
           if isinstance(option, dns.edns.EDEOption)]
    if response.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
        raise QueryError("dns_rcode_" + dns.rcode.to_text(response.rcode()).lower(), ede)
    if 6 in ede:
        raise QueryError("dnssec_bogus_by_resolver", ede)
    # Parse wire records separately before grouping. dnspython's default
    # grouping replaces a conflicting singleton (e.g. CNAME), hiding it.
    for section in (response.answer, response.authority, response.additional):
        grouped = {}
        for rrset in section:
            key = (rrset.name, rrset.rdtype, rrset.covers)
            if rrset.rdclass != dns.rdataclass.IN:
                raise QueryError("invalid_dns_class")
            if key in grouped:
                if dns.rdatatype.is_singleton(rrset.rdtype):
                    raise QueryError("duplicate_dns_singleton")
                grouped[key].update(rrset)
            else:
                grouped[key] = rrset
        section[:] = grouped.values()
    return response


def doh(owner, kind, resolver, timeout=4):
    """RFC 8484 POST with certificate verification, no redirects or proxies."""
    query = _message(owner, kind, True)
    deadline = time.monotonic() + timeout
    address, hostname = RESOLVERS[resolver]
    connection = _HTTPSConnection(hostname, address, deadline, context=ssl.create_default_context())
    response = None
    try:
        connection.connect()
        connection.request("POST", "/dns-query", body=query.to_wire(), headers={
            "Content-Type": "application/dns-message",
            "Accept": "application/dns-message"})
        response = connection.getresponse()
        if (response.status != 200 or response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
                != "application/dns-message"):
            raise QueryError("invalid_doh_response")
        wire = bytearray()
        while True:
            chunk = response.read1(min(4096, MAX_WIRE + 1 - len(wire)))
            if not chunk:
                break
            wire.extend(chunk)
            if len(wire) > MAX_WIRE:
                raise QueryError("dns_response_too_large")
        result = dns.message.from_wire(bytes(wire), one_rr_per_rrset=True, ignore_trailing=False)
        remaining(deadline)
        return _checked(query, result, True)
    except (OSError, ValueError, dns.exception.DNSException, http.client.HTTPException):
        raise QueryError("dns_transport_failed") from None
    finally:
        try:
            if response is not None:
                response.close()
        finally:
            connection.close()


def authoritative(owner, kind, address, timeout=4):
    """No recursion, TCP only; refuse private/local endpoints learned from DNS."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        raise QueryError("invalid_nameserver_address") from None
    if not ip.is_global:
        raise QueryError("non_public_nameserver_address")
    query = _message(owner, kind, False)
    try:
        response = dns.query.tcp(query, str(ip), timeout=timeout,
                                 one_rr_per_rrset=True, ignore_trailing=False)
    except (OSError, dns.exception.DNSException):
        raise QueryError("dns_transport_failed") from None
    return _checked(query, response, False)


class Client:
    """Shared monotonic budget, including requests and retries in this batch."""
    def __init__(self, timeout=120, max_queries=2048):
        self.deadline = time.monotonic() + timeout
        self.max_queries = max_queries
        self.queries = 0

    def _timeout(self):
        if self.queries >= self.max_queries:
            raise QueryError("dns_query_limit")
        self.queries += 1
        return min(4, remaining(self.deadline))

    def recursive(self, owner, kind, resolver):
        return doh(owner, kind, resolver, self._timeout())

    def authoritative(self, owner, kind, address):
        return authoritative(owner, kind, address, self._timeout())
