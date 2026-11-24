"""Explicit, one-attempt notification transports with no persistent side effects.

Prepared channels contain private credential snapshots. They are suitable only
for an in-memory worker request, never logs, status output or durable state.
Socket timeouts are not a total deadline: the caller supervises the worker,
including DNS resolution, and records a durable attempt before calling deliver.
"""
from email.message import EmailMessage
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import smtplib
import ssl
from urllib.parse import urlsplit, urlunsplit

from . import storage
from .core import Error

MAX_SECRET = 16 * 1024
MAX_EVENT = 128 * 1024
MAX_SMTP_REPLY = 64 * 1024
MAX_HTTP_HEADERS = 64 * 1024
CODES = frozenset({"invalid_channel", "channel_disabled", "invalid_timeout", "invalid_event",
                   "smtp_connection_failed", "smtp_rejected", "smtp_partial_refusal", "smtp_submission_uncertain",
                   "webhook_connection_failed", "webhook_redirect_refused", "webhook_rejected",
                   "webhook_submission_uncertain"})
_COMMON = {"id", "kind", "enabled"}
_SMTP = {"host", "port", "security", "from", "to", "username", "password_file", "ca_file"}
_WEBHOOK = {"url", "token_file", "ca_file"}
_EVENT = {"schema", "id", "kind", "observed_at", "status", "endpoints"}


class NotificationError(Error):
    """A fixed, non-sensitive notification configuration error."""


def _invalid():
    raise NotificationError("Invalid notification channel") from None


def _text(value, limit):
    return (isinstance(value, str) and 0 < len(value) <= limit
            and value.isascii() and value.isprintable())


def _finite(value):
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _host(value):
    if not _text(value, 253) or "%" in value:
        _invalid()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                   for label in value.split(".")):
            _invalid()
        return value.lower()


def _port(value):
    if type(value) is not int or not 1 <= value <= 65535:
        _invalid()
    return value


def _mailbox(value):
    if (not _text(value, 254) or value.count("@") != 1
            or not re.fullmatch(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+@[A-Za-z0-9.-]+", value)):
        _invalid()
    local, domain = value.split("@")
    if len(local) > 64 or local.startswith(".") or local.endswith(".") or ".." in local:
        _invalid()
    return local + "@" + _host(domain)


def _witness(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _secret(path):
    if not _text(path, 4096) or not Path(path).is_absolute():
        _invalid()
    try:
        with storage.open_private(path) as stream:
            before = _witness(os.fstat(stream.fileno()))
            raw = stream.buffer.read(MAX_SECRET + 1)
            after = _witness(os.fstat(stream.fileno()))
        if len(raw) > MAX_SECRET or before != after:
            raise NotificationError("Invalid notification credential snapshot")
        return raw.decode("ascii")
    except (OSError, UnicodeError, storage.StorageError):
        raise NotificationError("Notification credential is unavailable or unsafe") from None


def _line_secret(path, bearer=False):
    value = _secret(path)
    if value.endswith("\r\n"):
        value = value[:-2]
    elif value.endswith("\n"):
        value = value[:-1]
    if not _text(value, MAX_SECRET):
        raise NotificationError("Invalid notification credential")
    if bearer and not re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", value):
        raise NotificationError("Invalid notification bearer credential")
    return value


def _context(ca_pem=None):
    # create_default_context() can honor SSLKEYLOGFILE and create a secret file.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if ca_pem is None:
        context.load_default_certs()
    else:
        context.load_verify_locations(cadata=ca_pem)
    return context


def _ca(path):
    pem = _secret(path)
    if not re.fullmatch(r"\s*(?:-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\r\n]+"
                        r"-----END CERTIFICATE-----\s*)+", pem):
        raise NotificationError("Invalid notification trust anchor")
    try:
        _context(pem)
    except (OSError, ValueError):
        raise NotificationError("Invalid notification trust anchor") from None
    return pem


def _url(value):
    if not _text(value, 2048) or " " in value or "\\" in value:
        _invalid()
    try:
        parts = urlsplit(value)
        if (parts.scheme != "https" or not parts.netloc or parts.username is not None
                or parts.password is not None or parts.fragment or "#" in value):
            _invalid()
        host = _host(parts.hostname)
        port = _port(parts.port if parts.port is not None else 443)
        if parts.netloc.endswith(":"):
            _invalid()
    except ValueError:
        _invalid()
    authority = "[" + host + "]" if ":" in host else host
    if port != 443:
        authority += ":" + str(port)
    return urlunsplit(("https", authority, parts.path or "/", parts.query, ""))


def prepare(channel):
    """Validate one configured channel and snapshot its private files locally."""
    if not isinstance(channel, dict):
        _invalid()
    kind = channel.get("kind")
    if kind in ("telegram", "mqtt"):
        # Extensions reuse the private-file and TLS helpers in this module.
        # Import after initialization so direct extension imports also work.
        from . import notify_mqtt, notify_telegram
        return {"telegram": notify_telegram.prepare, "mqtt": notify_mqtt.prepare}[kind](channel)
    allowed = _SMTP if kind == "smtp" else _WEBHOOK
    if (kind not in ("smtp", "webhook") or set(channel) - _COMMON - allowed
            or not _text(channel.get("id"), 64)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", channel["id"])
            or type(channel.get("enabled", True)) is not bool):
        _invalid()
    result = {"id": channel["id"], "kind": kind, "enabled": channel.get("enabled", True)}
    if not result["enabled"]:
        return result
    secrets = {}
    if kind == "smtp":
        security = channel.get("security", "tls")
        if security not in ("tls", "starttls", "plain_local"):
            _invalid()
        host = _host(channel.get("host"))
        recipients = channel.get("to")
        if not isinstance(recipients, list) or not 1 <= len(recipients) <= 16:
            _invalid()
        recipients = [_mailbox(item) for item in recipients]
        if len(set(recipients)) != len(recipients):
            _invalid()
        if ("username" in channel) != ("password_file" in channel):
            _invalid()
        if security == "plain_local" and (channel["host"] not in ("127.0.0.1", "::1")
                                          or "username" in channel or "ca_file" in channel):
            _invalid()
        result.update(host=host, port=_port(channel.get("port", {"tls": 465, "starttls": 587,
                                                               "plain_local": 25}[security])),
                      security=security, to=recipients)
        result["from"] = _mailbox(channel.get("from"))
        if "username" in channel:
            if not _text(channel["username"], 1024):
                _invalid()
            result["username"] = channel["username"]
            secrets["password"] = _line_secret(channel["password_file"])
    else:
        result["url"] = _url(channel.get("url"))
        if "token_file" in channel:
            secrets["token"] = _line_secret(channel["token_file"], bearer=True)
    if "ca_file" in channel:
        secrets["ca_pem"] = _ca(channel["ca_file"])
    result["secrets"] = secrets
    return result


def _event_body(event):
    if (not isinstance(event, dict) or set(event) != _EVENT or type(event.get("schema")) is not int
            or event["schema"] != 1 or not isinstance(event["id"], str)
            or not re.fullmatch(r"[0-9a-f]{32}", event["id"])
            or (event["kind"], event["status"]) not in
            (("alert", "warning"), ("alert", "critical"), ("recovery", "ok"))
            or not _finite(event["observed_at"])
            or not isinstance(event["endpoints"], list) or len(event["endpoints"]) > 16
            or not all(isinstance(item, dict) for item in event["endpoints"])):
        raise ValueError("Invalid notification event")
    body = json.dumps(event, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    if len(body) >= MAX_EVENT:
        raise ValueError("Notification event exceeds size limit")
    return body


def _result(outcome, code=None):
    return {"outcome": outcome, "code": code}


class _ReplyReader:
    """Require complete CRLF lines within one protocol reply's byte budget."""
    def __init__(self, stream, limit):
        self.stream = stream
        self.remaining = limit

    def readline(self, limit):
        line = self.stream.readline(min(limit, self.remaining + 1))
        self.remaining -= len(line)
        if self.remaining < 0 or not line.endswith(b"\r\n"):
            raise OSError("Incomplete or oversized notification reply")
        return line

    def close(self):
        self.stream.close()


class _BoundedReply:
    def getreply(self):
        if self.file is None:
            self.file = self.sock.makefile("rb")
        stream = self.file
        self.file = _ReplyReader(stream, MAX_SMTP_REPLY)
        try:
            return super().getreply()
        finally:
            # smtplib closes and clears self.file when a response is invalid.
            if self.file is not None:
                self.file = stream


class _PlainClient(_BoundedReply, smtplib.SMTP):
    pass


class _TLSClient(_BoundedReply, smtplib.SMTP_SSL):
    pass


class _HTTPResponse(http.client.HTTPResponse):
    def begin(self):
        # The stdlib accepts EOF as the end of headers. Require the terminating
        # blank CRLF line, with one budget for interim and final responses.
        stream = self.fp
        self.fp = _ReplyReader(stream, MAX_HTTP_HEADERS)
        try:
            return super().begin()
        finally:
            # Invalid status lines can close and clear the underlying stream.
            if self.fp is not None:
                self.fp = stream


def _smtp(channel, event, body, timeout):
    client = None
    submitting = False
    try:
        msg = EmailMessage()
        msg["From"] = channel["from"]
        msg["To"] = ", ".join(channel["to"])
        msg["Subject"] = "CGP external TLS: " + event["kind"] + " " + event["status"]
        msg["Message-ID"] = "<" + event["id"] + "@cgp-monitor.invalid>"
        msg.set_content(body.decode("ascii"))
        options = {"timeout": timeout, "local_hostname": "cgp-monitor.invalid"}
        if channel["security"] == "tls":
            client = _TLSClient(channel["host"], channel["port"],
                                context=_context(channel["secrets"].get("ca_pem")), **options)
        else:
            client = _PlainClient(channel["host"], channel["port"], **options)
            if channel["security"] == "starttls":
                client.starttls(context=_context(channel["secrets"].get("ca_pem")))
        client.ehlo_or_helo_if_needed()
        if "username" in channel:
            client.login(channel["username"], channel["secrets"]["password"])
        submitting = True
        refused = client.send_message(msg, from_addr=channel["from"], to_addrs=channel["to"])
        if refused:
            return _result("uncertain", "smtp_partial_refusal")
        return _result("accepted")
    except (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused, smtplib.SMTPDataError):
        return _result("rejected", "smtp_rejected")
    except Exception:
        return _result("uncertain" if submitting else "rejected",
                       "smtp_submission_uncertain" if submitting else "smtp_connection_failed")
    finally:
        if client is not None:
            try:
                # Closing after DATA avoids a QUIT failure changing an observed ACK.
                client.close()
            except Exception:
                pass


def _webhook(channel, event, body, timeout):
    connection = None
    response = None
    submitting = False
    try:
        parts = urlsplit(channel["url"])
        connection = http.client.HTTPSConnection(parts.hostname, parts.port or 443, timeout=timeout,
                                                context=_context(channel["secrets"].get("ca_pem")))
        connection.response_class = _HTTPResponse
        connection.connect()
        headers = {"Content-Type": "application/json", "Idempotency-Key": event["id"]}
        if "token" in channel["secrets"]:
            headers["Authorization"] = "Bearer " + channel["secrets"]["token"]
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        submitting = True
        connection.request("POST", path, body=body, headers=headers)
        response = connection.getresponse()
        if 200 <= response.status < 300:
            return _result("accepted")
        if 300 <= response.status < 400:
            return _result("rejected", "webhook_redirect_refused")
        return _result("rejected", "webhook_rejected")
    except Exception:
        return _result("uncertain" if submitting else "rejected",
                       "webhook_submission_uncertain" if submitting else "webhook_connection_failed")
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass


def deliver(prepared, event, timeout_seconds=15):
    """Attempt once; accepted means protocol acknowledgement, not final delivery."""
    if not isinstance(prepared, dict) or prepared.get("kind") not in ("smtp", "webhook", "telegram", "mqtt"):
        return _result("rejected", "invalid_channel")
    if prepared.get("enabled") is not True:
        return _result("rejected", "channel_disabled")
    if not _finite(timeout_seconds) or timeout_seconds <= 0:
        return _result("rejected", "invalid_timeout")
    try:
        body = _event_body(event)
    except (ValueError, TypeError, RecursionError, OverflowError):
        return _result("rejected", "invalid_event")
    if prepared["kind"] in ("telegram", "mqtt"):
        from . import notify_mqtt, notify_telegram
        operation = {"telegram": notify_telegram.deliver, "mqtt": notify_mqtt.deliver}[prepared["kind"]]
    else:
        operation = _smtp if prepared["kind"] == "smtp" else _webhook
    return operation(prepared, event, body, timeout_seconds)
