"""Observe an explicitly configured TLS endpoint without manager/provider state.

The caller's supervised worker supplies the hard deadline around system name
resolution. All socket operations share a monotonic budget. Success describes
the verified leaf on one selected TCP connection, not an entire address pool,
revocation status, application login, or delivery of mail.
"""
import base64
import hashlib
import ipaddress
import math
import os
from pathlib import Path
import re
import socket
import ssl
import time

from . import core, storage


PROTOCOLS = ("tls", "smtp_starttls", "imap_starttls", "pop3_starttls")
MAX_CA_BYTES = 1024 * 1024
MAX_CERTIFICATE_BYTES = 64 * 1024
MAX_LINE = 4096
MAX_PLAINTEXT = 32 * 1024
MAX_LINES = 64
MAX_ADDRESSES = 8
CONNECT_TIMEOUT = 3
PEM_BLOCK = r"-----BEGIN CERTIFICATE-----\r?\n([A-Za-z0-9+/= \t\r\n]+)-----END CERTIFICATE-----"
ERROR_CODES = frozenset((
    "invalid_endpoint", "ca_unavailable", "dns_failed", "connect_failed", "timeout",
    "protocol_error", "starttls_unavailable", "starttls_rejected", "tls_expired",
    "tls_not_yet_valid", "tls_hostname_mismatch", "tls_untrusted", "tls_verification_failed",
    "tls_handshake_failed", "certificate_unreadable", "worker_failed"))


class ProbeError(core.Error):
    """A fixed diagnostic that never contains a host, filename or server text."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _name(value):
    if (not isinstance(value, str) or not value or len(value) > 253
            or value != value.strip() or "%" in value):
        raise ProbeError("invalid_endpoint")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        name, error = core.dns_name(value)
        if error or name.startswith("*."):
            raise ProbeError("invalid_endpoint")
        return name


def _endpoint(value, prepared=False):
    required = {"host", "port", "server_name"}
    allowed = required | {"protocol", "ca_pem" if prepared else "ca_file"}
    if (not isinstance(value, dict) or not required <= value.keys() or set(value) - allowed
            or (prepared and set(value) != allowed)):
        raise ProbeError("invalid_endpoint")
    port = value["port"]
    protocol = value.get("protocol", "tls")
    if type(port) is not int or not 1 <= port <= 65535 or protocol not in PROTOCOLS:
        raise ProbeError("invalid_endpoint")
    return {"host": _name(value["host"]), "port": port,
            "server_name": _name(value["server_name"]), "protocol": protocol}


def _ca_pem(value):
    if (not isinstance(value, str) or len(value) > MAX_CA_BYTES or
            re.fullmatch(r"[ \t\r\n]*(?:" + PEM_BLOCK + r"[ \t\r\n]*)+", value) is None):
        raise ProbeError("ca_unavailable")
    for body in re.findall(PEM_BLOCK, value):
        compact = "".join(body.split())
        try:
            data = base64.b64decode(compact, validate=True)
        except ValueError:
            raise ProbeError("ca_unavailable") from None
        if not data or base64.b64encode(data).decode("ascii") != compact:
            raise ProbeError("ca_unavailable")
    return value


def _context(ca_pem):
    try:
        # create_default_context() enables SSLKEYLOGFILE from the environment.
        # The observation worker must never create a TLS key-log file.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.hostname_checks_common_name = False
        if ca_pem is None:
            context.load_default_certs(ssl.Purpose.SERVER_AUTH)
        else:
            context.load_verify_locations(cadata=_ca_pem(ca_pem))
        return context
    except (OSError, ValueError):
        raise ProbeError("ca_unavailable") from None


def _stamp(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def prepare(value):
    """Validate configuration and snapshot an optional private CA file (0600).

    Returns only host, port, server_name, protocol and ca_pem. The source CA path
    is not retained; no configured file needs reopening during observation.
    """
    result = _endpoint(value)
    ca_file = value.get("ca_file")
    ca_pem = None
    if ca_file is not None:
        try:
            if not isinstance(ca_file, str) or not Path(ca_file).is_absolute():
                raise ProbeError("ca_unavailable")
            with storage.open_private(ca_file) as stream:
                before = os.fstat(stream.fileno())
                if before.st_size > MAX_CA_BYTES:
                    raise ProbeError("ca_unavailable")
                ca_pem = stream.read(MAX_CA_BYTES + 1)
                if _stamp(before) != _stamp(os.fstat(stream.fileno())):
                    raise ProbeError("ca_unavailable")
            _context(ca_pem)  # Validate the actual certificates before any network.
        except (core.Error, OSError, ValueError, TypeError):
            raise ProbeError("ca_unavailable") from None
    return dict(result, ca_pem=ca_pem)


def _remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise ProbeError("timeout")
    return value


def _connect(endpoint, deadline):
    _remaining(deadline)
    try:
        resolved = socket.getaddrinfo(endpoint["host"], endpoint["port"],
                                      type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    except OSError:
        _remaining(deadline)
        raise ProbeError("dns_failed") from None
    _remaining(deadline)
    addresses, seen = [], set()
    for family, kind, protocol, _, address in resolved:
        if family not in (socket.AF_INET, socket.AF_INET6) or kind != socket.SOCK_STREAM:
            continue
        identity = (family, address)
        if identity not in seen:
            addresses.append((family, kind, protocol, address))
            seen.add(identity)
            if len(addresses) == MAX_ADDRESSES:
                break
    if not addresses:
        raise ProbeError("dns_failed")
    timed_out = False
    for family, kind, protocol, address in addresses:
        try:
            connection = socket.socket(family, kind, protocol)
        except OSError:
            continue
        try:
            connection.settimeout(min(CONNECT_TIMEOUT, _remaining(deadline)))
            connection.connect(address)
            _remaining(deadline)
            return connection, str(ipaddress.ip_address(address[0]))
        except OSError as error:
            timed_out = timed_out or isinstance(error, TimeoutError)
            connection.close()
        except BaseException:
            connection.close()
            raise
    _remaining(deadline)
    raise ProbeError("timeout" if timed_out else "connect_failed")


class _Plaintext:
    def __init__(self, connection, deadline):
        self.connection = connection
        self.deadline = deadline
        self.buffer = bytearray()
        self.received = 0
        self.lines = 0

    def send(self, command):
        self.connection.settimeout(_remaining(self.deadline))
        self.connection.sendall(command + b"\r\n")

    def line(self):
        while b"\n" not in self.buffer:
            if len(self.buffer) >= MAX_LINE:
                raise ProbeError("protocol_error")
            self.connection.settimeout(_remaining(self.deadline))
            chunk = self.connection.recv(min(4096, MAX_LINE + 1 - len(self.buffer)))
            if not chunk:
                raise ProbeError("protocol_error")
            self.received += len(chunk)
            if self.received > MAX_PLAINTEXT:
                raise ProbeError("protocol_error")
            self.buffer.extend(chunk)
        index = self.buffer.index(b"\n") + 1
        line = bytes(self.buffer[:index])
        del self.buffer[:index]
        self.lines += 1
        if (self.lines > MAX_LINES or len(line) > MAX_LINE or not line.endswith(b"\r\n")
                or any(byte < 32 and byte != 9 or byte == 127 for byte in line[:-2])):
            raise ProbeError("protocol_error")
        return line[:-2]

    def finish(self):
        if self.buffer:
            raise ProbeError("protocol_error")
        _remaining(self.deadline)


def _smtp_reply(reader):
    code, text = None, []
    while True:
        line = reader.line()
        if (len(line) < 3 or not line[:3].isdigit()
                or (len(line) > 3 and line[3] not in (32, 45))):
            raise ProbeError("protocol_error")
        if code is not None and line[:3] != code:
            raise ProbeError("protocol_error")
        code = line[:3]
        text.append(line[4:])
        if len(line) == 3 or line[3] == 32:
            return code, text


def _smtp(reader):
    if _smtp_reply(reader)[0] != b"220":
        raise ProbeError("protocol_error")
    reader.send(b"EHLO probe.invalid")
    code, capabilities = _smtp_reply(reader)
    if code != b"250" or not any(line.upper().split() == [b"STARTTLS"] for line in capabilities):
        raise ProbeError("starttls_unavailable")
    reader.send(b"STARTTLS")
    if _smtp_reply(reader)[0] != b"220":
        raise ProbeError("starttls_rejected")


def _imap_reply(reader, tag):
    capabilities = []
    while True:
        parts = reader.line().split()
        if len(parts) < 2:
            raise ProbeError("protocol_error")
        if parts[0] == b"*":
            if parts[1].upper() == b"BYE":
                raise ProbeError("protocol_error")
            if parts[1].upper() == b"CAPABILITY":
                capabilities.extend(part.upper() for part in parts[2:])
        else:
            if parts[0] != tag or parts[1].upper() not in (b"OK", b"NO", b"BAD"):
                raise ProbeError("protocol_error")
            return parts[1].upper(), capabilities


def _imap(reader):
    greeting = reader.line().split()
    if len(greeting) < 2 or greeting[0] != b"*" or greeting[1].upper() != b"OK":
        raise ProbeError("protocol_error")
    reader.send(b"cgp1 CAPABILITY")
    status, capabilities = _imap_reply(reader, b"cgp1")
    if status != b"OK" or b"STARTTLS" not in capabilities:
        raise ProbeError("starttls_unavailable")
    reader.send(b"cgp2 STARTTLS")
    if _imap_reply(reader, b"cgp2")[0] != b"OK":
        raise ProbeError("starttls_rejected")


def _pop_ok(line):
    return line.upper().split()[:1] == [b"+OK"]


def _pop3(reader):
    if not _pop_ok(reader.line()):
        raise ProbeError("protocol_error")
    reader.send(b"CAPA")
    if not _pop_ok(reader.line()):
        raise ProbeError("starttls_unavailable")
    starttls = False
    while True:
        line = reader.line()
        if line == b".":
            break
        if line.upper().split() == [b"STLS"]:
            starttls = True
    if not starttls:
        raise ProbeError("starttls_unavailable")
    reader.send(b"STLS")
    if not _pop_ok(reader.line()):
        raise ProbeError("starttls_rejected")


def _verification_error(error):
    code = error.verify_code
    if code == 9:
        return "tls_not_yet_valid"
    if code == 10:
        return "tls_expired"
    if code in (62, 64):
        return "tls_hostname_mismatch"
    if code in (18, 19, 20, 21):
        return "tls_untrusted"
    return "tls_verification_failed"


def observe(prepared, timeout_seconds=15):
    """Return safe verified-leaf metadata; never retry with verification disabled.

    The supervisor must additionally bound this call in a worker process because
    libc name resolution does not accept a socket timeout. Configured CA bytes
    are already captured; only system trust may be loaded implicitly here.
    """
    result = {"status": "error", "code": "worker_failed", "peer_address": None,
              "not_after": None, "fingerprint_sha256": None, "tls_version": None}
    connection = None
    try:
        endpoint = _endpoint(prepared, prepared=True)
        if (type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds)
                or not 0 < timeout_seconds <= 60):
            raise ProbeError("invalid_endpoint")
        deadline = time.monotonic() + timeout_seconds
        context = _context(prepared["ca_pem"])
        connection, result["peer_address"] = _connect(endpoint, deadline)
        if endpoint["protocol"] != "tls":
            reader = _Plaintext(connection, deadline)
            {"smtp_starttls": _smtp, "imap_starttls": _imap, "pop3_starttls": _pop3}[endpoint["protocol"]](reader)
            reader.finish()
        connection.settimeout(_remaining(deadline))
        connection = context.wrap_socket(connection, server_hostname=endpoint["server_name"])
        _remaining(deadline)
        der = connection.getpeercert(binary_form=True)
        info = connection.getpeercert()
        if not isinstance(der, bytes) or not der or len(der) > MAX_CERTIFICATE_BYTES:
            raise ProbeError("certificate_unreadable")
        expiry = ssl.cert_time_to_seconds(info["notAfter"])
        if type(expiry) not in (int, float) or not math.isfinite(expiry):
            raise ProbeError("certificate_unreadable")
        version = connection.version()
        if version not in ("TLSv1.2", "TLSv1.3"):
            raise ProbeError("tls_handshake_failed")
        result.update(status="ok", code=None, not_after=expiry,
                      fingerprint_sha256=hashlib.sha256(der).hexdigest(), tls_version=version)
    except ProbeError as error:
        result["code"] = error.code
    except ssl.SSLCertVerificationError as error:
        result["code"] = _verification_error(error)
    except TimeoutError:
        result["code"] = "timeout"
    except ssl.SSLError:
        result["code"] = "tls_handshake_failed"
    except OSError:
        result["code"] = "connect_failed"
    except (KeyError, TypeError, ValueError, OverflowError):
        result["code"] = "certificate_unreadable"
    except Exception:
        result["code"] = "worker_failed"
    finally:
        if connection is not None:
            try:
                connection.close()
            except OSError:
                result.update(status="error", code="worker_failed", not_after=None,
                              fingerprint_sha256=None, tls_version=None)
    return result
