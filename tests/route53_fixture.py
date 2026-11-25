"""Independent atomic Route53 control-plane fixture; never contacts AWS."""
import copy
import xml.etree.ElementTree as ET


NS = "https://route53.amazonaws.com/doc/2013-04-01/"


def element(name, text=None, parent=None):
    tag = "{" + NS + "}" + name
    result = ET.Element(tag) if parent is None else ET.SubElement(parent, tag)
    result.text = text
    return result


class FakeRoute53:
    """A callable Client factory with one shared, immediately visible RRset.

    The CAS validates the old TTL and exact raw set before changing anything.
    It does not invoke production decoding, XML validation or mutation logic.
    Hooks before_change/after_change receive (name, ttl, before, after), with
    after_change running after the remote effect. transform(operation, root)
    can alter or replace a response. Each factory call snapshots its entry.
    """

    def __init__(self):
        self.values = ()
        self.ttl = 120
        self.requests = []
        self.clients = []
        self.mutations = []
        self.before_change = None
        self.after_change = None
        self.transform = None
        self.next_record = None
        self.conflict = False

    def __call__(self, entry):
        self.clients.append(copy.deepcopy(entry))
        return FakeClient(self, self.clients[-1], len(self.clients))

    def finish(self, operation, response):
        if self.transform is not None:
            changed = self.transform(operation, response)
            if changed is not None:
                response = changed
        return response

    def apply(self, name, ttl, before, after):
        before, after = tuple(before), tuple(after)
        if self.before_change is not None:
            self.before_change(name, ttl, before, after)
        # This is a service-side transaction, not a sequence of mutations.
        if (self.conflict or set(before) != set(self.values)
                or (before and ttl != self.ttl) or not after
                or len(set(after)) != len(after)
                or len(before) + len(after) > 1000
                or sum(map(len, before + after)) > 32000):
            raise RuntimeError("PRIVATE InvalidChangeBatch")
        change = {"name": name, "ttl": ttl, "before": before, "after": after}
        self.values, self.ttl = after, ttl
        self.mutations.append(copy.deepcopy(change))
        if self.after_change is not None:
            self.after_change(name, ttl, before, after)


class FakeClient:
    def __init__(self, service, entry, identity):
        self.service = service
        self.entry = entry
        self.identity = identity

    def get_zone(self):
        self.service.requests.append(("zone", self.identity))
        root = element("GetHostedZoneResponse")
        zone = element("HostedZone", parent=root)
        element("Id", "/hostedzone/" + self.entry["hosted_zone_id"], zone)
        element("Name", self.entry["zone"] + ".", zone)
        element("CallerReference", "fixture-zone", zone)
        config = element("Config", parent=zone)
        element("PrivateZone", "false", config)
        element("ResourceRecordSetCount", "2", zone)
        delegation = element("DelegationSet", parent=root)
        nameservers = element("NameServers", parent=delegation)
        for name in self.entry["nameservers"]:
            element("NameServer", name, nameservers)
        return self.service.finish("zone", root)

    def records(self, name):
        self.service.requests.append(("records", self.identity, name))
        root = element("ListResourceRecordSetsResponse")
        records = element("ResourceRecordSets", parent=root)
        if self.service.values:
            row = element("ResourceRecordSet", parent=records)
            element("Name", name + ".", row)
            element("Type", "TXT", row)
            element("TTL", str(self.service.ttl), row)
            values = element("ResourceRecords", parent=row)
            for value in self.service.values:
                record = element("ResourceRecord", parent=values)
                element("Value", value, record)
        element("IsTruncated", "true" if self.service.next_record else "false", root)
        element("MaxItems", "1", root)
        if self.service.next_record:
            element("NextRecordName", self.service.next_record[0], root)
            element("NextRecordType", self.service.next_record[1], root)
            if len(self.service.next_record) == 3:
                element("NextRecordIdentifier", self.service.next_record[2], root)
        return self.service.finish("records", root)

    def change(self, name, ttl, before, after):
        self.service.requests.append(("change", self.identity, name, ttl, before, after))
        self.service.apply(name, ttl, before, after)
        root = element("ChangeResourceRecordSetsResponse")
        info = element("ChangeInfo", parent=root)
        element("Id", "/change/C12345678", info)
        element("Status", "PENDING", info)
        element("SubmittedAt", "2026-11-25T01:02:03.456Z", info)
        return self.service.finish("change", root)
