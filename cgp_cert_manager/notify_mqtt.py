"""One MQTT 3.1.1 QoS-1 publication with an explicit protocol acknowledgement.

This is a bounded publisher, not a persistent MQTT client. It never subscribes,
reconnects, retains messages or resumes a session. PUBACK does not establish
publication authorization or subscriber delivery (MQTT-3.3.5-2). The caller
supervises DNS and records durable intent before invoking this transport.
"""
import re
import secrets
import time

from . import notify_transport as common, tlsprobe


CODES = frozenset({"mqtt_connection_failed", "mqtt_rejected", "mqtt_submission_uncertain"})
MAX_TOPIC_BYTES = 1024
MAX_USERNAME_BYTES = 1024
MAX_PACKET = common.MAX_EVENT + MAX_TOPIC_BYTES + 4
_FIELDS = {"id", "kind", "enabled", "host", "port", "security", "topic",
           "username", "password_file", "ca_file"}


def _utf8(value, limit):
    if not isinstance(value, str) or not value or len(value) > limit:
        common._invalid()
    # MQTT-1.5.3: reject mandatory invalid characters and the discouraged
    # control/noncharacter ranges. Preserve every other code point verbatim.
    if any(ord(char) < 0x20 or 0x7f <= ord(char) <= 0x9f
           or 0xd800 <= ord(char) <= 0xdfff or 0xfdd0 <= ord(char) <= 0xfdef
           or ord(char) & 0xffff in (0xfffe, 0xffff) for char in value):
        common._invalid()
    encoded = value.encode("utf-8")
    if len(encoded) > limit:
        common._invalid()
    return encoded


def prepare(channel):
    """Validate one raw channel, capturing private files only in memory."""
    if (not isinstance(channel, dict) or set(channel) - _FIELDS
            or channel.get("kind") != "mqtt" or not common._text(channel.get("id"), 64)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", channel["id"])
            or type(channel.get("enabled", True)) is not bool):
        common._invalid()
    result = {"id": channel["id"], "kind": "mqtt", "enabled": channel.get("enabled", True)}
    if not result["enabled"]:
        return result
    security = channel.get("security", "tls")
    if security not in ("tls", "plain_local"):
        common._invalid()
    host = common._host(channel.get("host"))
    topic = channel.get("topic")
    _utf8(topic, MAX_TOPIC_BYTES)
    if "+" in topic or "#" in topic:
        common._invalid()
    if ("username" in channel) != ("password_file" in channel):
        common._invalid()
    if security == "plain_local" and (channel["host"] not in ("127.0.0.1", "::1")
                                      or "username" in channel or "ca_file" in channel):
        common._invalid()
    result.update(host=host, port=common._port(channel.get("port", 8883 if security == "tls" else 1883)),
                  security=security, topic=topic, secrets={})
    if "username" in channel:
        _utf8(channel["username"], MAX_USERNAME_BYTES)
        result["username"] = channel["username"]
        result["secrets"]["password"] = common._line_secret(channel["password_file"])
    if "ca_file" in channel:
        result["secrets"]["ca_pem"] = common._ca(channel["ca_file"])
    return result


def _string(value):
    encoded = value.encode("utf-8")
    return len(encoded).to_bytes(2, "big") + encoded


def _packet(header, payload):
    length = len(payload)
    if length > MAX_PACKET:
        raise ValueError("MQTT packet exceeds size limit")
    remaining = bytearray()
    while True:
        digit = length % 128
        length //= 128
        remaining.append(digit | (0x80 if length else 0))
        if not length:
            return bytes([header]) + bytes(remaining) + payload


def _connect_packet(channel):
    # MQTT-3.1.3-5 guarantees broker support for 1..23 alphanumeric bytes.
    payload = _string("cgp" + secrets.token_hex(10))
    flags = 0x02  # CleanSession; no Will, username or password by default.
    if "username" in channel:
        flags |= 0xc0
        payload += _string(channel["username"]) + _string(channel["secrets"]["password"])
    # Protocol level 4, KeepAlive 0: this short supervised attempt needs no ping.
    return _packet(0x10, b"\x00\x04MQTT\x04" + bytes([flags]) + b"\x00\x00" + payload)


def _read(connection, length, deadline):
    data = bytearray()
    while len(data) < length:
        connection.settimeout(tlsprobe._remaining(deadline))
        part = connection.recv(length - len(data))
        if not part:
            raise OSError("Incomplete MQTT acknowledgement")
        data.extend(part)
    tlsprobe._remaining(deadline)
    return bytes(data)


def _acknowledgement(connection, header, deadline):
    # These two control packets have exactly two remaining bytes. Reject every
    # other length/flag immediately; never allocate a broker-declared payload.
    if _read(connection, 2, deadline) != bytes([header, 2]):
        raise ValueError("Invalid MQTT acknowledgement")
    return _read(connection, 2, deadline)


def deliver(channel, event, body, timeout):
    """Publish once; only a matching PUBACK permits an accepted outcome.

    The common dispatcher supplies a prepared channel and validates the event
    and timeout. Its bounded JSON body contains the stable event identifier.
    """
    connection = None
    publishing = False
    try:
        if (not common._finite(timeout) or not 0 < timeout <= 60
                or not isinstance(body, bytes) or not 0 < len(body) < common.MAX_EVENT):
            raise ValueError("Invalid MQTT request")
        deadline = time.monotonic() + timeout
        connect = _connect_packet(channel)
        publish = _packet(0x32, _string(channel["topic"]) + b"\x00\x01" + body)
        connection, _peer = tlsprobe._connect(channel, deadline)
        if channel["security"] == "tls":
            context = common._context(channel["secrets"].get("ca_pem"))
            connection.settimeout(tlsprobe._remaining(deadline))
            connection = context.wrap_socket(connection, server_hostname=channel["host"])
        connection.settimeout(tlsprobe._remaining(deadline))
        connection.sendall(connect)
        connack = _acknowledgement(connection, 0x20, deadline)
        if connack[0] != 0 or connack[1] > 5:
            raise ValueError("Invalid MQTT connection acknowledgement")
        if connack[1] != 0:
            return common._result("rejected", "mqtt_rejected")
        connection.settimeout(tlsprobe._remaining(deadline))
        publishing = True
        connection.sendall(publish)
        if _acknowledgement(connection, 0x40, deadline) != b"\x00\x01":
            raise ValueError("Mismatched MQTT publication acknowledgement")
        return common._result("accepted")
    except Exception:
        return common._result("uncertain" if publishing else "rejected",
                              "mqtt_submission_uncertain" if publishing else "mqtt_connection_failed")
    finally:
        if connection is not None:
            try:
                # No Will or persistent session; closing ends this attempt.
                # A close error cannot revoke an already observed PUBACK.
                connection.close()
            except Exception:
                pass
