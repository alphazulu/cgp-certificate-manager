"""One-attempt commercial AWS requests using an explicit credential snapshot.

This deliberately implements only STS caller identity and the three Route53
operations needed by the adapter. Hosts, signing region and API paths are fixed;
there is no SDK credential discovery, proxy use, redirect, retry or token refresh.
The ten-second socket timeout is not a total operation deadline.
"""
from datetime import datetime, timezone
import hashlib
import hmac
import http.client
import re
from urllib.parse import quote
import xml.etree.ElementTree as ET

from . import route53_config
from .core import Error
from .notify_transport import _context, _HTTPResponse


NS = "https://route53.amazonaws.com/doc/2013-04-01/"
STS_NS = "https://sts.amazonaws.com/doc/2011-06-15/"
MAX_BODY = 512 * 1024
MAX_XML_DEPTH = 16
MAX_XML_NODES = 4096
TIMEOUT = 10
_ENDPOINTS = {"route53": ("route53.amazonaws.com", NS),
              "sts": ("sts.us-east-1.amazonaws.com", STS_NS)}


class APIError(Error):
    """A fixed error: remote bodies, credentials and request metadata are private."""


def _query(parameters):
    """Use RFC3986 escaping and sort encoded names and values for SigV4."""
    return "&".join(name + "=" + value for name, value in sorted(
        (quote(name, safe="-_.~"), quote(value, safe="-_.~")) for name, value in parameters))


def _signed_headers(secret, service, host, method, path, query, body, timestamp, content_type=None):
    """Pure SigV4 construction; configuration validation happens before signing."""
    headers = {"Host": host, "X-Amz-Date": timestamp}
    if content_type is not None:
        headers["Content-Type"] = content_type
    if "session_token" in secret:
        headers["X-Amz-Security-Token"] = secret["session_token"]
    canonical = sorted((name.lower(), " ".join(value.split())) for name, value in headers.items())
    names = ";".join(name for name, value in canonical)
    request = "\n".join((method, path, query,
                         "".join(name + ":" + value + "\n" for name, value in canonical),
                         names, hashlib.sha256(body).hexdigest()))
    date = timestamp[:8]
    scope = date + "/us-east-1/" + service + "/aws4_request"
    signing = "\n".join(("AWS4-HMAC-SHA256", timestamp, scope,
                         hashlib.sha256(request.encode("utf-8")).hexdigest()))
    key = ("AWS4" + secret["secret_access_key"]).encode("utf-8")
    for part in (date, "us-east-1", service, "aws4_request"):
        key = hmac.new(key, part.encode("utf-8"), hashlib.sha256).digest()
    signature = hmac.new(key, signing.encode("utf-8"), hashlib.sha256).hexdigest()
    headers["Authorization"] = ("AWS4-HMAC-SHA256 Credential=" + secret["access_key_id"] + "/" + scope
                                + ", SignedHeaders=" + names + ", Signature=" + signature)
    return headers


class _TreeBuilder(ET.TreeBuilder):
    def __init__(self):
        super().__init__()
        self.depth = 0
        self.count = 0

    def start(self, tag, attrs):
        self.depth += 1
        self.count += 1
        if self.depth > MAX_XML_DEPTH or self.count > MAX_XML_NODES:
            raise ValueError("XML structure exceeds limit")
        return super().start(tag, attrs)

    def end(self, tag):
        self.depth -= 1
        return super().end(tag)


def _xml(response, namespace, operation):
    lengths = response.headers.get_all("Content-Length", [])
    types = response.headers.get_all("Content-Type", [])
    if (len(lengths) > 1 or response.headers.get_all("Transfer-Encoding", [])
            or response.headers.get_all("Content-Encoding", []) or len(types) != 1
            or re.fullmatch(r'(?:application|text)/xml(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?\s*',
                            types[0], flags=re.IGNORECASE) is None):
        raise ValueError("Invalid XML framing")
    expected = None
    if lengths:
        if re.fullmatch(r"[0-9]{1,10}", lengths[0]) is None:
            raise ValueError("Invalid body length")
        expected = int(lengths[0])
        if expected > MAX_BODY:
            raise ValueError("Body exceeds limit")
    raw = response.read(MAX_BODY + 1)
    if len(raw) > MAX_BODY or (expected is not None and len(raw) != expected):
        raise ValueError("Incomplete or oversized body")
    text = raw.decode("utf-8")
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise ValueError("XML declarations are unsupported")
    declaration = re.search(r"<\?xml\s[^?]*\bencoding\s*=\s*(['\"])(.*?)\1", text, re.IGNORECASE)
    if declaration is not None and declaration.group(2).lower() != "utf-8":
        raise ValueError("XML encoding is unsupported")
    root = ET.fromstring(text, parser=ET.XMLParser(target=_TreeBuilder()))
    if root.tag != "{" + namespace + "}" + operation:
        raise ValueError("Unexpected XML response")
    return root


def _request(secret, service, method, path, operation, *, query=(), body=b""):
    connection = None
    try:
        if len(body) > MAX_BODY:
            raise ValueError("Request exceeds limit")
        host, namespace = _ENDPOINTS[service]
        query = _query(query)
        content_type = None
        if method == "POST":
            content_type = "application/x-www-form-urlencoded" if service == "sts" else "application/xml"
        headers = _signed_headers(secret, service, host, method, path, query, body,
                                  datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"), content_type)
        headers.update({"Accept": "application/xml, text/xml", "Accept-Encoding": "identity", "Connection": "close"})
        connection = http.client.HTTPSConnection(host, 443, timeout=TIMEOUT, context=_context())
        connection.response_class = _HTTPResponse
        connection.request(method, path + ("?" + query if query else ""), body=body, headers=headers)
        with connection.getresponse() as response:
            if response.status != 200:
                raise ValueError("Request was not accepted")
            return _xml(response, namespace, operation)
    except Exception:
        raise APIError("Route53 API request failed") from None
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass


class Client:
    """Bind one in-memory credential snapshot to a verified explicit AWS account."""
    def __init__(self, zone):
        self._path = "/2013-04-01/hostedzone/" + zone["hosted_zone_id"]
        self._secret = route53_config.read_secret(zone["credentials"])
        identity = _request(self._secret, "sts", "POST", "/", "GetCallerIdentityResponse",
                            body=b"Action=GetCallerIdentity&Version=2011-06-15")
        results = list(identity.iter("{" + STS_NS + "}GetCallerIdentityResult"))
        accounts = list(identity.iter("{" + STS_NS + "}Account"))
        if (len(results) != 1 or results[0] not in identity or len(accounts) != 1
                or accounts[0] not in results[0] or accounts[0].attrib or len(accounts[0])
                or re.fullmatch(r"[0-9]{12}", accounts[0].text or "") is None
                or accounts[0].text != zone["account_id"]):
            raise APIError("Route53 API request failed")

    def get_zone(self):
        return _request(self._secret, "route53", "GET", self._path, "GetHostedZoneResponse")

    def records(self, name):
        return _request(self._secret, "route53", "GET", self._path + "/rrset", "ListResourceRecordSetsResponse",
                        query=(("maxitems", "1"), ("name", name.removesuffix(".") + "."), ("type", "TXT")))

    def change(self, name, ttl, before_raw_values, after_raw_values):
        root = ET.Element("ChangeResourceRecordSetsRequest", xmlns=NS)
        changes = ET.SubElement(ET.SubElement(root, "ChangeBatch"), "Changes")
        for action, values in (("DELETE", before_raw_values), ("CREATE", after_raw_values)):
            if values:
                change = ET.SubElement(changes, "Change")
                ET.SubElement(change, "Action").text = action
                record = ET.SubElement(change, "ResourceRecordSet")
                ET.SubElement(record, "Name").text = name.removesuffix(".") + "."
                ET.SubElement(record, "Type").text = "TXT"
                ET.SubElement(record, "TTL").text = str(ttl)
                records = ET.SubElement(record, "ResourceRecords")
                for value in values:
                    ET.SubElement(ET.SubElement(records, "ResourceRecord"), "Value").text = value
        return _request(self._secret, "route53", "POST", self._path + "/rrset/", "ChangeResourceRecordSetsResponse",
                        body=ET.tostring(root, encoding="utf-8", xml_declaration=True))
