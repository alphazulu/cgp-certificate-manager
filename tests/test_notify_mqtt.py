"""Bounded MQTT wire contracts and synthetic TLS brokers on loopback only."""
from copy import deepcopy
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from cgp_cert_manager import notify_mqtt as mqtt, notify_transport as transport


def channel(**changes):
    return dict({"id": "broker", "kind": "mqtt", "host": "broker.example.test",
                 "topic": "cgp/monitor/events"}, **changes)


def event():
    return {"schema": 1, "id": "b" * 32, "kind": "alert", "observed_at": 1000,
            "status": "critical", "endpoints": []}


class BytesSocket:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.sent = []
        self.timeouts = []
        self.read_sizes = []
        self.closed = False
        self.on_recv = lambda: None

    def settimeout(self, value):
        self.timeouts.append(value)

    def sendall(self, value):
        self.sent.append(value)

    def recv(self, size):
        self.read_sizes.append(size)
        self.on_recv()
        if not self.chunks:
            return b""
        value = self.chunks.pop(0)
        if isinstance(value, Exception):
            raise value
        if len(value) > size:
            self.chunks.insert(0, value[size:])
        return value[:size]

    def close(self):
        self.closed = True


def packet(raw):
    """Independent wire decoder used only for the publisher's test output."""
    length, multiplier, offset = 0, 1, 1
    while True:
        digit = raw[offset]
        offset += 1
        length += (digit & 127) * multiplier
        if not digit & 128:
            break
        multiplier *= 128
    assert offset <= 5 and len(raw) == offset + length
    return raw[0], raw[offset:]


def string_field(raw):
    length = int.from_bytes(raw[:2], "big")
    return raw[2:2 + length], raw[2 + length:]


class MQTTContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.prepared = mqtt.prepare(channel(host="127.0.0.1", security="plain_local"))

    def secret(self, value="PRIVATE-PASSWORD\n"):
        path = self.root / "password"
        path.write_text(value)
        path.chmod(0o600)
        return str(path)

    def deliver(self, wire, prepared=None, timeout=15, body=None):
        with patch.object(mqtt.tlsprobe, "_connect", return_value=(wire, "127.0.0.1")) as connect:
            result = mqtt.deliver(prepared or self.prepared, event(),
                                  transport._event_body(event()) if body is None else body, timeout)
        connect.assert_called_once()
        self.assertTrue(wire.closed)
        self.assertEqual(set(result), {"outcome", "code"})
        self.assertNotIn("PRIVATE", json.dumps(result))
        return result

    def test_prepare_defaults_canonical_host_and_private_snapshot(self):
        raw = channel(host="BROKER.EXAMPLE.TEST", username="оператор", password_file=self.secret())
        original = deepcopy(raw)
        result = mqtt.prepare(raw)
        self.assertEqual(result, {"id": "broker", "kind": "mqtt", "enabled": True,
            "host": "broker.example.test", "port": 8883, "security": "tls", "topic": "cgp/monitor/events",
            "username": "оператор", "secrets": {"password": "PRIVATE-PASSWORD"}})
        self.assertEqual(json.loads(json.dumps(result)), result)
        self.assertEqual(raw, original)
        self.assertNotIn("password_file", result)
        for host in ("127.0.0.1", "::1"):
            self.assertEqual(mqtt.prepare(channel(host=host, security="plain_local"))["port"], 1883)

    def test_disabled_channel_does_not_open_files_or_validate_unused_destination(self):
        with patch.object(transport, "_line_secret") as secret, patch.object(transport, "_ca") as ca:
            result = mqtt.prepare({"id": "off", "kind": "mqtt", "enabled": False,
                                   "password_file": "/private/missing", "ca_file": "/private/missing"})
        self.assertEqual(result, {"id": "off", "kind": "mqtt", "enabled": False})
        secret.assert_not_called()
        ca.assert_not_called()

    def test_raw_configuration_rejects_extra_keys_invalid_auth_and_plaintext_destinations(self):
        values = [None, [], {}, channel(kind="mqtt5"), channel(id=None), channel(id="bad id"),
                  channel(enabled=1), channel(retain=True), channel(qos=0), channel(client_id="fixed"),
                  channel(host="bad host"), channel(port=0), channel(port=True), channel(port=65536),
                  channel(security="starttls"), channel(username="user"), channel(password_file="/missing"),
                  channel(host="localhost", security="plain_local"),
                  channel(host="127.0.0.2", security="plain_local"),
                  channel(host="0:0:0:0:0:0:0:1", security="plain_local"),
                  channel(host="::1", security="plain_local", ca_file="/missing"),
                  channel(host="127.0.0.1", security="plain_local", username="u", password_file="/missing")]
        for value in values:
            with self.subTest(value=value), self.assertRaises(transport.NotificationError) as failure:
                mqtt.prepare(value)
            self.assertEqual(str(failure.exception), "Invalid notification channel")

    def test_topic_utf8_is_preserved_and_bounded_in_bytes(self):
        for topic in ("/leading//trailing/", "with spaces", "cgp/温度", "\ufefftopic", "é" * 512):
            self.assertEqual(mqtt.prepare(channel(topic=topic))["topic"], topic)
        invalid = [None, 1, "", "a" * 1025, "é" * 513, "one/+", "one/#", "a+b", "a#b"]
        invalid += ["prefix" + chr(value) for value in (0, 1, 31, 127, 159, 0xd800, 0xdfff,
                                                       0xfdd0, 0xfdef, 0xfffe, 0xffff, 0x1ffff, 0x10ffff)]
        for topic in invalid:
            with self.subTest(topic=repr(topic)), self.assertRaises(transport.NotificationError):
                mqtt.prepare(channel(topic=topic))

    def test_username_utf8_limit_and_private_credential_validation(self):
        password = self.secret()
        self.assertEqual(mqtt.prepare(channel(username="é" * 512, password_file=password))["username"], "é" * 512)
        for username in ("", "é" * 513, "user\x00", "user\n", "\ud800"):
            with self.subTest(username=repr(username)), self.assertRaises(transport.NotificationError):
                mqtt.prepare(channel(username=username, password_file=password))
        Path(password).chmod(0o644)
        with self.assertRaises(transport.NotificationError):
            mqtt.prepare(channel(username="user", password_file=password))
        Path(password).chmod(0o600)
        alias = self.root / "alias"
        alias.symlink_to(password)
        with self.assertRaises(transport.NotificationError):
            mqtt.prepare(channel(username="user", password_file=str(alias)))
        for value in ("line\nline", "x" * (transport.MAX_SECRET + 1)):
            with self.assertRaises(transport.NotificationError):
                mqtt.prepare(channel(username="user", password_file=self.secret(value)))

    def test_connect_and_publish_use_fresh_client_ids_and_stable_event_body(self):
        identifiers = []
        for _ in range(2):
            wire = BytesSocket([b"\x20\x02\x00\x00\x40\x02\x00\x01"])
            self.assertEqual(self.deliver(wire), {"outcome": "accepted", "code": None})
            self.assertEqual(len(wire.sent), 2)  # No retry, subscription, ping, Will or retained status.
            header, connect = packet(wire.sent[0])
            self.assertEqual((header, connect[:10]), (0x10, b"\x00\x04MQTT\x04\x02\x00\x00"))
            identifier, rest = string_field(connect[10:])
            self.assertRegex(identifier.decode(), r"^[A-Za-z0-9]{23}$")
            self.assertEqual(rest, b"")
            identifiers.append(identifier)
            header, publish = packet(wire.sent[1])
            topic, rest = string_field(publish)
            self.assertEqual((header, topic, rest[:2]), (0x32, b"cgp/monitor/events", b"\x00\x01"))
            self.assertEqual(rest[2:], transport._event_body(event()))
        self.assertNotEqual(*identifiers)

    def test_packet_remaining_length_vectors_and_upper_bound(self):
        for length, encoded in ((0, b"\x00"), (127, b"\x7f"), (128, b"\x80\x01"),
                                (16383, b"\xff\x7f"), (16384, b"\x80\x80\x01")):
            payload = b"a" * length
            self.assertEqual(mqtt._packet(0x32, payload), b"\x32" + encoded + payload)
        largest = mqtt._packet(0x32, b"a" * mqtt.MAX_PACKET)
        self.assertEqual(len(packet(largest)[1]), mqtt.MAX_PACKET)
        with self.assertRaises(ValueError):
            mqtt._packet(0x32, b"a" * (mqtt.MAX_PACKET + 1))

    def test_invalid_timeout_or_payload_is_refused_before_network(self):
        for timeout in (None, "15", True, 0, -1, 61, float("inf"), float("nan")):
            with patch.object(mqtt.tlsprobe, "_connect") as connect:
                result = mqtt.deliver(self.prepared, event(), b"{}", timeout)
            self.assertEqual(result, {"outcome": "rejected", "code": "mqtt_connection_failed"})
            connect.assert_not_called()
        for body in ("not bytes", b"", b"a" * transport.MAX_EVENT):
            with patch.object(mqtt.tlsprobe, "_connect") as connect:
                self.assertEqual(mqtt.deliver(self.prepared, event(), body, 15)["outcome"], "rejected")
            connect.assert_not_called()

    def test_connack_refusals_are_definite_and_never_publish(self):
        for code in range(1, 6):
            wire = BytesSocket([b"\x20\x02\x00" + bytes([code])])
            self.assertEqual(self.deliver(wire), {"outcome": "rejected", "code": "mqtt_rejected"})
            self.assertEqual(len(wire.sent), 1)

    def test_malformed_or_truncated_connack_is_rejected_without_publishing(self):
        replies = [b"", b"\x20", b"\x20\x02\x00", b"\x21\x02\x00\x00", b"\xd0\x00",
                   b"\x20\x03", b"\x20\x82\x00\x00\x00", b"\x20\xff\xff\xff\xff\x00",
                   b"\x20\x02\x01\x00", b"\x20\x02\x80\x00", b"\x20\x02\x00\x06"]
        for reply in replies:
            with self.subTest(reply=reply):
                wire = BytesSocket([reply])
                self.assertEqual(self.deliver(wire), {"outcome": "rejected", "code": "mqtt_connection_failed"})
                self.assertEqual(len(wire.sent), 1)
                self.assertTrue(all(size <= 2 for size in wire.read_sizes))

    def test_bad_puback_or_read_error_is_uncertain_and_never_retried(self):
        replies = [b"", b"\x40", b"\x40\x02\x00", b"\x40\x02\x00\x00", b"\x40\x02\x00\x02",
                   b"\x41\x02\x00\x01", b"\x40\x00", b"\x40\x03", b"\x40\x82\x00\x00\x01",
                   b"\x40\xff\xff\xff\xff\xff", b"\x30\x02\x00\x01", TimeoutError("PRIVATE reply")]
        for reply in replies:
            with self.subTest(reply=repr(reply)):
                wire = BytesSocket([b"\x20\x02\x00\x00", reply])
                self.assertEqual(self.deliver(wire), {"outcome": "uncertain", "code": "mqtt_submission_uncertain"})
                self.assertEqual(len(wire.sent), 2)
                self.assertTrue(all(size <= 2 for size in wire.read_sizes))

    def test_send_errors_distinguish_prepublication_and_started_publication(self):
        for fail_at, outcome, code in ((1, "rejected", "mqtt_connection_failed"),
                                      (2, "uncertain", "mqtt_submission_uncertain")):
            wire = BytesSocket([b"\x20\x02\x00\x00"])
            original = wire.sendall

            def send(value):
                original(value)
                if len(wire.sent) == fail_at:
                    raise OSError("PRIVATE send error")

            wire.sendall = send
            self.assertEqual(self.deliver(wire), {"outcome": outcome, "code": code})
            self.assertEqual(len(wire.sent), fail_at)

    def test_fragmented_replies_share_one_absolute_deadline(self):
        reply = b"\x20\x02\x00\x00\x40\x02\x00\x01"
        for step, expected in ((0.25, "rejected"), (0.2, "uncertain"), (0.01, "accepted")):
            clock = [100.0]
            wire = BytesSocket([bytes([byte]) for byte in reply])
            wire.on_recv = lambda: clock.__setitem__(0, clock[0] + step)
            with patch.object(mqtt.time, "monotonic", side_effect=lambda: clock[0]):
                result = self.deliver(wire, timeout=1)
            self.assertEqual(result["outcome"], expected)
            self.assertEqual(wire.timeouts, sorted(wire.timeouts, reverse=True))
            self.assertTrue(all(0 < value <= 1 for value in wire.timeouts))

    def test_tcp_and_tls_setup_failures_close_resources_without_publishing(self):
        prepared = mqtt.prepare(channel())
        with patch.object(mqtt.tlsprobe, "_connect", side_effect=OSError("PRIVATE DNS")):
            self.assertEqual(mqtt.deliver(prepared, event(), b"{}", 15),
                             {"outcome": "rejected", "code": "mqtt_connection_failed"})
        for location in ("context", "handshake"):
            raw = BytesSocket([])
            context = Mock()
            context.wrap_socket.side_effect = ssl.SSLError("PRIVATE TLS")
            with patch.object(transport, "_context", side_effect=OSError("PRIVATE CA") if location == "context" else None,
                              return_value=context):
                self.assertEqual(self.deliver(raw, prepared),
                                 {"outcome": "rejected", "code": "mqtt_connection_failed"})
            self.assertEqual(raw.sent, [])

    def test_valid_ack_survives_close_error_and_plain_local_never_loads_trust(self):
        wire = BytesSocket([b"\x20\x02\x00\x00\x40\x02\x00\x01"])

        def close():
            wire.closed = True
            raise OSError("PRIVATE close failure")

        wire.close = close
        with patch.object(transport, "_context") as context:
            self.assertEqual(self.deliver(wire), {"outcome": "accepted", "code": None})
        context.assert_not_called()


class MQTTLoopbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        cls.cert, cls.key = cls.root / "ca.pem", cls.root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                        "-keyout", str(cls.key), "-out", str(cls.cert)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.cert.chmod(0o600)

    def broker(self, *, tls=True, connack=b"\x20\x02\x00\x00", puback=b"\x40\x02\x00\x01", pause=0):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(3)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        observed = {"packets": [], "errors": [], "after_ack": None}

        def exact(connection, size):
            result = b""
            while len(result) < size:
                part = connection.recv(size - len(result))
                if not part:
                    raise OSError("Test client disconnected")
                result += part
            return result

        def read_packet(connection):
            raw = exact(connection, 1)
            length, multiplier = 0, 1
            for _ in range(4):
                digit = exact(connection, 1)[0]
                raw += bytes([digit])
                length += (digit & 127) * multiplier
                if not digit & 128:
                    break
                multiplier *= 128
            if length > mqtt.MAX_PACKET:
                raise OSError("Test packet is too large")
            raw += exact(connection, length)
            return packet(raw)

        def serve():
            connection = None
            try:
                connection, _ = listener.accept()
                connection.settimeout(3)
                if tls:
                    connection = context.wrap_socket(connection, server_side=True)
                observed["packets"].append(read_packet(connection))
                connection.sendall(connack)
                if connack != b"\x20\x02\x00\x00":
                    return
                observed["packets"].append(read_packet(connection))
                if pause:
                    time.sleep(pause)
                if puback is not None:
                    connection.sendall(puback)
                    if puback == b"\x40\x02\x00\x01":
                        observed["after_ack"] = connection.recv(1)
            except OSError as exc:
                observed["errors"].append(type(exc).__name__)
            finally:
                if connection is not None:
                    connection.close()
                listener.close()

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()

        def finish():
            worker.join(4)
            self.assertFalse(worker.is_alive(), "Loopback MQTT broker did not stop")

        self.addCleanup(finish)
        return listener.getsockname()[1], observed, worker

    def test_public_dispatch_publishes_once_over_verified_tls_with_private_auth_snapshot(self):
        port, observed, worker = self.broker()
        password = self.root / "password"
        password.write_text("MQTT-PRIVATE-PASSWORD\n")
        password.chmod(0o600)
        ca_copy = self.root / "captured-ca.pem"
        ca_copy.write_bytes(self.cert.read_bytes())
        ca_copy.chmod(0o600)
        prepared = transport.prepare(channel(host="127.0.0.1", port=port, username="оператор",
                                               password_file=str(password), ca_file=str(ca_copy)))
        ca_copy.unlink()
        password.unlink()
        keylog = self.root / "keylog-must-not-exist"
        with patch.dict(os.environ, {"SSLKEYLOGFILE": str(keylog)}):
            result = transport.deliver(prepared, event(), timeout_seconds=2)
        worker.join(3)
        self.assertEqual(result, {"outcome": "accepted", "code": None})
        self.assertEqual(observed["errors"], [])
        self.assertEqual(len(observed["packets"]), 2)
        header, connect = observed["packets"][0]
        self.assertEqual((header, connect[:10]), (0x10, b"\x00\x04MQTT\x04\xc2\x00\x00"))
        identifier, rest = string_field(connect[10:])
        username, rest = string_field(rest)
        secret, rest = string_field(rest)
        self.assertRegex(identifier.decode(), r"^[A-Za-z0-9]{23}$")
        self.assertEqual((username.decode(), secret, rest), ("оператор", b"MQTT-PRIVATE-PASSWORD", b""))
        header, publish = observed["packets"][1]
        topic, rest = string_field(publish)
        self.assertEqual((header, topic, rest[:2]), (0x32, b"cgp/monitor/events", b"\x00\x01"))
        self.assertEqual(json.loads(rest[2:]), event())
        self.assertNotIn(b"PRIVATE", rest[2:])
        self.assertEqual(observed["after_ack"], b"")
        self.assertFalse(keylog.exists())

    def test_plain_loopback_has_no_auth_or_tls_context_and_accepts_matching_ack(self):
        port, observed, worker = self.broker(tls=False)
        prepared = mqtt.prepare(channel(host="127.0.0.1", port=port, security="plain_local"))
        with patch.object(transport, "_context", side_effect=AssertionError("Plain local TLS")):
            result = mqtt.deliver(prepared, event(), transport._event_body(event()), 2)
        worker.join(3)
        self.assertEqual(result, {"outcome": "accepted", "code": None})
        self.assertEqual(observed["packets"][0][1][7], 2)

    def test_tls_trust_and_hostname_failures_never_send_connect_or_credentials(self):
        real_resolve = socket.getaddrinfo
        for wrong_host in (False, True):
            with self.subTest(wrong_host=wrong_host):
                port, observed, worker = self.broker()
                raw = channel(host="wrong.example.test" if wrong_host else "127.0.0.1", port=port)
                if wrong_host:
                    raw["ca_file"] = str(self.cert)
                prepared = mqtt.prepare(raw)
                with patch.object(socket, "getaddrinfo", side_effect=lambda host, port, *args, **kwargs:
                                  real_resolve("127.0.0.1", port, *args, **kwargs)):
                    result = mqtt.deliver(prepared, event(), transport._event_body(event()), 2)
                worker.join(3)
                self.assertEqual(result, {"outcome": "rejected", "code": "mqtt_connection_failed"})
                self.assertEqual(observed["packets"], [])

    def test_real_connack_refusal_prevents_publish(self):
        port, observed, worker = self.broker(connack=b"\x20\x02\x00\x05")
        prepared = mqtt.prepare(channel(host="127.0.0.1", port=port, ca_file=str(self.cert)))
        result = mqtt.deliver(prepared, event(), transport._event_body(event()), 2)
        worker.join(3)
        self.assertEqual(result, {"outcome": "rejected", "code": "mqtt_rejected"})
        self.assertEqual(len(observed["packets"]), 1)

    def test_real_wrong_puback_drop_and_timeout_remain_uncertain(self):
        for acknowledgement, pause in ((b"\x40\x02\x00\x02", 0), (None, 0), (None, 1.3)):
            with self.subTest(acknowledgement=acknowledgement, pause=pause):
                port, observed, worker = self.broker(puback=acknowledgement, pause=pause)
                prepared = mqtt.prepare(channel(host="127.0.0.1", port=port, ca_file=str(self.cert)))
                result = mqtt.deliver(prepared, event(), transport._event_body(event()), 1 if pause else 2)
                worker.join(3)
                self.assertEqual(result, {"outcome": "uncertain", "code": "mqtt_submission_uncertain"})
                self.assertEqual(len(observed["packets"]), 2)


if __name__ == "__main__":
    unittest.main()
