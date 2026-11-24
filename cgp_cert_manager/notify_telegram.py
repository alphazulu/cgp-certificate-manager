"""One bounded Telegram Bot API attempt; credentials remain in worker memory.

Telegram has no sendMessage idempotency key. The stable event ID is included in
plaintext for operator correlation; retries can deliver duplicate messages.
"""
import http.client
import json
import math
import re
from urllib.parse import urlsplit

from . import notify_transport as common


MAX_RESPONSE = 64 * 1024
MAX_MESSAGE = 4096
MAX_CHAT_ID = 2**52 - 1
CODES = frozenset({"telegram_connection_failed", "telegram_submission_uncertain",
                   "telegram_invalid_response", "telegram_server_error",
                   "telegram_redirect_refused", "telegram_rejected",
                   "telegram_rate_limited", "telegram_message_too_long"})
_FIELDS = {"id", "kind", "enabled", "token_file", "chat_id", "message_thread_id",
           "api_url", "ca_file"}


def _integer(value, minimum=1, maximum=2**63 - 1):
    return type(value) is int and minimum <= value <= maximum


def _chat(value):
    if isinstance(value, str) and re.fullmatch(r"-?[0-9]{1,16}", value):
        value = int(value)
    if _integer(value, -MAX_CHAT_ID, MAX_CHAT_ID) and value != 0:
        return value
    if isinstance(value, str) and re.fullmatch(r"@[A-Za-z0-9_]{1,32}", value):
        return value
    common._invalid()


def prepare(channel):
    """Validate an explicit channel and snapshot private token/trust files."""
    if (not isinstance(channel, dict) or set(channel) - _FIELDS
            or channel.get("kind") != "telegram" or not common._text(channel.get("id"), 64)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", channel["id"])
            or type(channel.get("enabled", True)) is not bool):
        common._invalid()
    result = {"id": channel["id"], "kind": "telegram", "enabled": channel.get("enabled", True)}
    if not result["enabled"]:
        return result
    url = channel.get("api_url", "https://api.telegram.org")
    origin = common._url(url)
    if urlsplit(origin).path != "/" or "?" in url:
        common._invalid()
    result.update(api_url=origin, chat_id=_chat(channel.get("chat_id")))
    if "message_thread_id" in channel:
        if not _integer(channel["message_thread_id"], maximum=2**31 - 1):
            common._invalid()
        result["message_thread_id"] = channel["message_thread_id"]
    token = common._line_secret(channel.get("token_file"))
    if not re.fullmatch(r"[1-9][0-9]{0,19}:[A-Za-z0-9_-]{1,200}", token):
        common._invalid()
    result["secrets"] = {"token": token}
    if "ca_file" in channel:
        result["secrets"]["ca_pem"] = common._ca(channel["ca_file"])
    return result


def _message(event):
    lines = ["CGP external TLS: " + event["kind"] + " " + event["status"], "Event: " + event["id"]]
    for row in event["endpoints"]:
        name, status, code = row["id"], row["status"], row["code"]
        if (not common._text(name, 64) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name)
                or status not in ("ok", "warning", "critical")
                or (code is not None and (not common._text(code, 128)
                    or not re.fullmatch(r"[a-z][a-z0-9_]*", code)))):
            raise ValueError("Invalid notification event")
        reason = code if code is not None else ("verified" if status == "ok" else "expiry_threshold")
        lines.append(name + ": " + status + "; reason=" + reason)
    return "\n".join(lines)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Invalid Telegram response")
        result[key] = value
    return result


def _constant(value):
    raise ValueError("Invalid Telegram response")


def _float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("Invalid Telegram response")
    return number


def _document(raw):
    data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
                      parse_constant=_constant, parse_float=_float)
    pending, count = [(data, 0)], 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if depth > 32 or count > 4096:
            raise ValueError("Invalid Telegram response structure")
        if isinstance(value, dict):
            pending.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            pending.extend((item, depth + 1) for item in value)
    return data


class _Response(common._HTTPResponse):
    """Require complete chunk delimiters and trailers, beyond stdlib defaults."""
    def begin(self):
        super().begin()
        self._framing = common._ReplyReader(self.fp, common.MAX_HTTP_HEADERS)

    def _get_chunk_left(self):
        if self.chunk_left == 0:
            if self._safe_read(2) != b"\r\n":
                raise ValueError("Invalid Telegram response framing")
            self.chunk_left = None
        return super()._get_chunk_left()

    def _read_next_chunk_size(self):
        line = self._framing.readline(common.MAX_HTTP_HEADERS + 1)
        # Extension contents are not needed; accept bounded visible ASCII only.
        match = re.fullmatch(rb"([0-9A-Fa-f]{1,8})(?:;[ -~]+)?\r\n", line)
        if match is None or int(match[1], 16) > MAX_RESPONSE:
            raise ValueError("Invalid Telegram response framing")
        return int(match[1], 16)

    def _read_and_discard_trailer(self):
        while True:
            line = self._framing.readline(common.MAX_HTTP_HEADERS + 1)
            if line == b"\r\n":
                return
            match = re.fullmatch(rb"([!#$%&'*+.^_`|~0-9A-Za-z-]+):[\t -~]*\r\n", line)
            if match is None or match[1].lower() in (b"content-length", b"transfer-encoding", b"content-encoding"):
                raise ValueError("Invalid Telegram response framing")


def _read_body(response):
    headers = response.headers
    lengths = headers.get_all("Content-Length", [])
    transfers = headers.get_all("Transfer-Encoding", [])
    encodings = headers.get_all("Content-Encoding", [])
    if (headers.defects or len(lengths) > 1 or len(transfers) > 1
            or (lengths and transfers) or len(encodings) > 1
            or (encodings and encodings[0].strip().lower() != "identity")):
        raise ValueError("Invalid Telegram response framing")
    length = None
    if lengths:
        match = re.fullmatch(r"[ \t]*([0-9]{1,8})[ \t]*", lengths[0])
        if match is None or int(match[1]) > MAX_RESPONSE:
            raise ValueError("Invalid Telegram response framing")
        length = int(match[1])
    elif not transfers or transfers[0].strip().lower() != "chunked" or not response.chunked:
        raise ValueError("Invalid Telegram response framing")
    raw = response.read(MAX_RESPONSE + 1)
    if len(raw) > MAX_RESPONSE or (length is not None and len(raw) != length):
        raise ValueError("Invalid Telegram response framing")
    return raw


def _acknowledged(result, channel, text):
    if (not isinstance(result, dict) or not _integer(result.get("message_id"))
            or not _integer(result.get("date")) or result.get("text") != text
            or not isinstance(result.get("chat"), dict)):
        return False
    chat = result["chat"]
    if (not _integer(chat.get("id"), -MAX_CHAT_ID, MAX_CHAT_ID) or chat["id"] == 0
            or chat.get("type") not in ("private", "group", "supergroup", "channel")
            or (type(channel["chat_id"]) is int and channel["chat_id"] != chat["id"])
            or ("message_thread_id" in result and not _integer(result["message_thread_id"], maximum=2**31 - 1))
            or ("message_thread_id" in channel and result.get("message_thread_id") != channel["message_thread_id"])):
        return False
    return True


def _answer(status, raw, channel, text):
    data = _document(raw)
    if not isinstance(data, dict) or type(data.get("ok")) is not bool:
        raise ValueError("Invalid Telegram response")
    if data["ok"]:
        if (not 200 <= status < 300 or "error_code" in data or "parameters" in data
                or not _acknowledged(data.get("result"), channel, text)):
            raise ValueError("Invalid Telegram acknowledgement")
        return common._result("accepted")
    if (not (200 <= status < 300 or 400 <= status < 500)
            or not _integer(data.get("error_code")) or not isinstance(data.get("description"), str)
            or not data["description"] or data.get("result") is not None
            or ("parameters" in data and not isinstance(data["parameters"], dict))):
        raise ValueError("Invalid Telegram rejection")
    if data["error_code"] >= 500:
        return common._result("uncertain", "telegram_server_error")
    if status == 429 and data["error_code"] != 429:
        raise ValueError("Invalid Telegram rate limit")
    if data["error_code"] == 429 and (status == 429 or 200 <= status < 300):
        result = common._result("rejected", "telegram_rate_limited")
        parameters = data.get("parameters", {})
        if "retry_after" in parameters:
            if not _integer(parameters["retry_after"], maximum=2**31 - 1):
                raise ValueError("Invalid Telegram retry interval")
            result["retry_after_seconds"] = parameters["retry_after"]
        return result
    return common._result("rejected", "telegram_rejected")


def deliver(prepared, event, body, timeout):
    """Attempt one sendMessage; the parent owns retry and total deadline policy."""
    try:
        text = _message(event)
    except (KeyError, TypeError, ValueError):
        return common._result("rejected", "invalid_event")
    if len(text) > MAX_MESSAGE:
        return common._result("rejected", "telegram_message_too_long")
    payload = {"chat_id": prepared["chat_id"], "text": text}
    if "message_thread_id" in prepared:
        payload["message_thread_id"] = prepared["message_thread_id"]
    body = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8")
    connection = response = None
    submitting = False
    try:
        parts = urlsplit(prepared["api_url"])
        connection = http.client.HTTPSConnection(parts.hostname, parts.port or 443, timeout=timeout,
                     context=common._context(prepared["secrets"].get("ca_pem")))
        connection.response_class = _Response
        connection.connect()
        submitting = True
        connection.request("POST", "/bot" + prepared["secrets"]["token"] + "/sendMessage", body=body,
                           headers={"Content-Type": "application/json", "Connection": "close"})
        response = connection.getresponse()
        if 300 <= response.status < 400:
            return common._result("rejected", "telegram_redirect_refused")
        if response.status >= 500:
            return common._result("uncertain", "telegram_server_error")
        try:
            return _answer(response.status, _read_body(response), prepared, text)
        except (ValueError, UnicodeError, RecursionError):
            return common._result("uncertain", "telegram_invalid_response")
    except Exception:
        return common._result("uncertain" if submitting else "rejected",
                              "telegram_submission_uncertain" if submitting else "telegram_connection_failed")
    finally:
        for resource in (response, connection):
            if resource is not None:
                try:
                    resource.close()
                except Exception:
                    pass
