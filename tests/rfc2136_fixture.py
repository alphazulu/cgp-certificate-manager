"""Synthetic signed DNS primary for adapter and restart tests; no external I/O."""
import copy
import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rdataclass
import dns.rdatatype
import dns.rcode
import dns.rrset
import dns.tsig


class FakePrimary:
    def __init__(self, zone="example.com", key_name="manager-key", secret=b"s" * 32):
        self.zone = dns.name.from_text(zone)
        self.key = dns.tsig.Key(key_name, secret, algorithm="hmac-sha256")
        self.records = {}
        self.requests = []
        self.wires = []
        self.mutations = []
        self.soa = dns.rrset.from_text(self.zone, 120, "IN", "SOA",
                                      "ns1.example.net. admin.example.com. 1 60 60 600 60")
        self.before = None
        self.after = None

    def put(self, name, *texts, ttl=120, kind="TXT"):
        owner = dns.name.from_text(name)
        self.records[(owner, dns.rdatatype.from_text(kind))] = dns.rrset.from_text(
            owner, ttl, "IN", kind, *texts)

    def txt(self, name):
        values = self.records.get((dns.name.from_text(name), dns.rdatatype.TXT), ())
        return {b"".join(rd.strings) for rd in values}

    def handle(self, wire):
        self.wires.append(wire)
        query = dns.message.from_wire(wire, keyring=self.key)
        self.requests.append(query)
        if self.before:
            self.before(query)
        response = dns.message.make_response(query)
        if query.opcode() == dns.opcode.QUERY:
            response.flags |= dns.flags.AA
            q = query.question[0]
            rrset = self.records.get((q.name, q.rdtype))
            if q.rdtype == dns.rdatatype.SOA and q.name == self.zone:
                response.answer.append(copy.deepcopy(self.soa))
            elif rrset:
                response.answer.append(copy.deepcopy(rrset))
            else:
                response.set_rcode(dns.rcode.NXDOMAIN)
                response.authority.append(copy.deepcopy(self.soa))
        else:
            code = self._update(query)
            response.set_rcode(code)
        if self.after:
            self.after(query, response)
        return response.to_wire()

    def _update(self, query):
        if query.question[0].name != self.zone:
            return dns.rcode.NOTZONE
        exact = {}
        for rr in query.prerequisite:
            current = self.records.get((rr.name, rr.rdtype))
            if rr.deleting == dns.rdataclass.NONE:
                if current:
                    return dns.rcode.YXRRSET
            elif rr.deleting == dns.rdataclass.ANY:
                if not current:
                    return dns.rcode.NXRRSET
            else:
                exact.setdefault((rr.name, rr.rdtype), set()).update(rr)
        for key, wanted in exact.items():
            current = self.records.get(key)
            if current is None or set(current) != wanted:
                return dns.rcode.NXRRSET
        if query.update:
            self.mutations.append(query)
        for rr in query.update:
            key = (rr.name, rr.rdtype)
            current = self.records.get(key)
            if rr.deleting is not None:
                if current is not None:
                    for rd in rr:
                        current.discard(rd)
                    if not current:
                        self.records.pop(key)
            else:
                if current is None:
                    current = dns.rrset.RRset(rr.name, dns.rdataclass.IN, rr.rdtype)
                    self.records[key] = current
                for rd in rr:
                    current.add(rd, rr.ttl)
        return dns.rcode.NOERROR

    def __call__(self, query, server, timeout=10, port=53):
        wire = query.to_wire()
        response = self.handle(wire)
        return dns.message.from_wire(response, keyring=query.keyring, request_mac=query.mac)
