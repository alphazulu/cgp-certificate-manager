# Notification channels

The independent `cgp-monitor` observer supports SMTP, HTTPS webhooks, Telegram
Bot API messages and MQTT 3.1.1 publication. Each channel uses the same durable
notification policy: save an intent, attempt once in a bounded worker, and record
the observed acknowledgement. Channels have separate delivery records and retry
deadlines. Acceptance by a protocol peer does not establish that a person or a
downstream application received and processed the event.

This guide describes implemented configuration and automated test contracts.
Real VM, server, Telegram, broker and recipient acceptance remains deferred.
The examples below have not been executed against an external service.

See [External monitoring](EXTERNAL_MONITORING.md) for endpoint probes, CLI exit
codes, the independent service and timer, installer behavior and the complete
configuration schema. [Storage](STORAGE.md) describes private file requirements.

## Explicit authorization and configuration

Configuration defaults to `/etc/cgp-monitor/config.json`; observations and
delivery checkpoints belong to `/var/lib/cgp-monitor`. They are separate from
certificate-manager configuration and renewal state.

Sending requires all of the following: the monitor is enabled, notification
policy is enabled, the selected channel is enabled, and the operator invokes
`cgp-monitor --run --send`. The shipped timer invokes `--run` without `--send`.
Neither installation nor a configuration check sends a test message. The
installer does not enable the timer automatically.

| Action | Network activity | Notification and state effects |
|---|---|---|
| `--check-config` | None | Validates configuration and enabled channels' private files; no state creation or sending |
| `--probe` | Configured TLS observations | No saved checkpoint or notification |
| `--status` | None | Reads saved observations and delivery outcomes; no retry |
| `--run` | Configured TLS observations | Saves observations; retains existing pending delivery without sending |
| `--run --send` | Configured TLS observations and eligible notification attempts | Saves durable per-channel intents and results |

The [complete example](../examples/monitor.example.json) contains four disabled
channels and disabled monitor/notification policies. Disabled channels keep
their ID and kind but do not read their credential files. Enabled channels are
validated even when the global sending policy is disabled.

All channels use these common properties:

| Property | Contract |
|---|---|
| `id` | Unique across the configuration's channels; 1–64 lowercase ASCII letters, digits, `_` or `-`, beginning with a letter or digit |
| `kind` | `smtp`, `webhook`, `telegram` or `mqtt` |
| `enabled` | Boolean; defaults to `true` when omitted, so examples set `false` explicitly |

At most four channels may be configured. Unknown fields are rejected. The
enclosing `notifications` object has `enabled` defaulting to `false`,
`timeout_seconds` defaulting to 15 (range 1–30), `retry_seconds` defaulting to 300
(10–86400), and `repeat_seconds` defaulting to 86400 (60–604800). These settings
are integers; JSON booleans are not numeric substitutes.

Credential and notification CA files must be private regular files owned by the
effective user: mode `0600` or stricter, without symlinks or hard links, under
trusted parents. The installation uses root. Private state directories require
`0700` or stricter. Existing unsafe files are refused, not automatically changed.
Notification credential and CA snapshots are bounded to 16 KiB per file.

Preparation reads the files locally and removes source paths from the prepared
channel. Prepared credentials exist only in memory and in the worker's bounded
private input. They are excluded from event payloads, durable delivery state,
status output and configuration summaries. Routing destinations are likewise
not part of public delivery records. Event observations still contain endpoint
names, addresses and certificate information; choose destinations accordingly.

## Existing SMTP and webhook channels

SMTP supports implicit TLS (default port 465), required STARTTLS (587), and an
explicit unauthenticated `plain_local` mode restricted to literal `127.0.0.1` or
`::1`. SMTP authentication requires both `username` and `password_file`.
Webhooks require HTTPS and support an optional bearer `token_file`. Both support
an optional private `ca_file`.

SMTP uses the stable event ID in `Message-ID`; webhooks use it in
`Idempotency-Key`. SMTP requires a complete submission acknowledgement, while
webhooks require a complete 2xx HTTP response header block. Partial SMTP
recipient refusal remains uncertain. Webhook redirects are refused and response
bodies are not consumed. See the existing
[SMTP and webhook configuration](EXTERNAL_MONITORING.md#optional-notification-channels)
for the full channel fields and acknowledgement boundaries. Telegram and MQTT
do not alter these existing transport rules.

## Telegram

This disabled channel example uses only synthetic identifiers:

```json
{
  "id": "telegram",
  "kind": "telegram",
  "enabled": false,
  "chat_id": "-1001234567890",
  "token_file": "/etc/cgp-monitor/telegram-token"
}
```

| Property | Contract |
|---|---|
| `token_file` | Required for an enabled channel; private ASCII bot token file |
| `chat_id` | Required; nonzero signed integer within the supported 52-bit bound, a corresponding numeric string, or an `@username` destination |
| `message_thread_id` | Optional integer from 1 through `2**31 - 1` identifying the destination topic/thread |
| `api_url` | Defaults to `https://api.telegram.org/`; an HTTPS origin with an empty/root path, without credentials, query or fragment |
| `ca_file` | Optional private PEM trust anchor for the configured API connection |

A numeric chat string is normalized to an integer. A bot token is read from
its private file; it is not configured as an inline value or supplied as a
command argument. An optional final LF or CRLF is accepted. The transport
constructs the Bot API request internally; public results never return its
credential-bearing request URL. A custom `api_url` is an explicit choice of the
API peer and must be trusted with that token and the event text.

Each attempt submits one `sendMessage` request over HTTPS. The notification is
plain text, including a stable event ID and each endpoint's ID, status and
reason. No Markdown or HTML parse mode is used. Text exceeding 4096 characters
is rejected before network activity; it is not split into several messages or
silently truncated. The upstream method and text limit are defined by the
[Telegram `sendMessage` API](https://core.telegram.org/bots/api#sendmessage).

HTTP success alone is insufficient. Acceptance requires a complete bounded JSON
response with a successful API result and a valid returned message. The
acknowledgement must identify a message, date and chat, echo the exact submitted
text and match the requested thread when configured. Numeric destination IDs
are checked against the returned chat. Username destinations delegate name
resolution to the configured API. Redirects are refused. Malformed, truncated,
contradictory or otherwise unverifiable acknowledgements never become accepted.
Response bodies are limited to 64 KiB and require complete `Content-Length` or
chunked framing. Compressed responses, duplicate JSON properties and nonfinite
numbers are refused. Response headers and chunk framing also have fixed bounds.

An accepted result means the API acknowledged the message; it is not a read
receipt. A worker interruption or lost acknowledgement after submission can
leave an uncertain intent. Later retries carry the same event ID in their text,
but Telegram does not receive an application idempotency header from this
transport. Duplicate messages remain possible.

### Telegram rate limits

A validated API flood-control refusal (`ok: false`, `error_code: 429`) on HTTP
429 or a 2xx response is recorded
as `rejected` / `telegram_rate_limited`. An optional API `retry_after` is accepted
only as an integer from 1 through `2**31 - 1`; booleans, fractions and arbitrary
response fields are not trusted as timing instructions. The API documents this
field in [ResponseParameters](https://core.telegram.org/bots/api#responseparameters).

The coordinator sets the retry deadline after the attempt completes:

```text
retry_at = attempt_finished_at + max(configured_retry_seconds, provider_hint)
```

Without a timing hint, the configured retry interval applies. A malformed hint
makes the response unverifiable and therefore uncertain. The raw
hint is not stored in the checkpoint or returned in public CLI results; only
the calculated private `retry_at` remains. There is no sleep or automatic
retry within the transport worker.

The cooldown applies to the whole Telegram channel. Until its deadline,
subsequent authorized runs defer that channel even if the TLS condition changes
or becomes healthy. The old pending event remains as evidence. At or after the
deadline, a new observation determines whether to retry the same event or
supersede it with a changed alert/recovery event. Other channels continue to
apply their independent retry and reminder policies.

## MQTT

This disabled example uses a synthetic broker and topic:

```json
{
  "id": "mqtt",
  "kind": "mqtt",
  "enabled": false,
  "host": "broker.example.com",
  "port": 8883,
  "security": "tls",
  "topic": "cgp/monitor/events",
  "username": "monitor",
  "password_file": "/etc/cgp-monitor/mqtt-password"
}
```

| Property | Contract |
|---|---|
| `host` | Required broker DNS name or IP literal |
| `topic` | Required publication topic; nonempty UTF-8, at most 1024 encoded bytes, without `+` or `#` wildcards |
| `security` | `tls` by default; optional `plain_local` only for literal `127.0.0.1` or `::1` |
| `port` | Integer 1–65535; defaults to 8883 for TLS or 1883 for `plain_local` |
| `username`, `password_file` | Optional pair; username is nonempty UTF-8, at most 1024 encoded bytes; password comes from a private ASCII file |
| `ca_file` | Optional private PEM trust anchor with TLS |

Topic and username validation rejects NUL, C0/C1 controls, surrogate code points
and Unicode noncharacters. `plain_local` permits neither authentication nor a
custom CA. The MQTT transport uses the Python standard library and adds no
MQTT client runtime dependency.

Every attempt establishes a new MQTT 3.1.1 connection with a fresh random
23-character alphanumeric client ID, Clean Session enabled, no Will and Keep
Alive zero. It sends one JSON event as a QoS 1 PUBLISH with DUP clear, retain
false and packet ID 1. The transport does not subscribe, discover brokers,
resume a session, reconnect automatically or retransmit internally. QoS and
retain are fixed behavior, not additional configuration options.

The entire connection, including name resolution, remains inside the monitor
worker's deadline. CONNACK and PUBACK must have the expected complete four-byte
form; the PUBACK must match the publication's packet identifier. A refusal or
failure before publication is rejected. Once publication begins, a missing,
invalid or incomplete acknowledgement is uncertain because the broker may have
received the event.

**MQTT acceptance means a matching PUBACK was observed.** It does not establish
publication authorization, subscriber delivery or application processing.
MQTT 3.1.1 explicitly permits a broker to acknowledge an unauthorized PUBLISH
instead of closing the connection; see section 3.3.5, requirement
`MQTT-3.3.5-2`, in the
[OASIS specification](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html).

The JSON payload retains its stable top-level `id` (event ID) across retries. Consumers can
deduplicate on that ID. The MQTT connection's fresh client ID and packet ID are
not durable application identifiers, and QoS 1 does not provide exactly-once
processing. With retain false, this publication is not a retained latest-state
feed for future subscribers.

## TLS, worker and acknowledgement boundaries

TLS notification connections require TLS 1.2 or newer and hostname verification.
System trust is used unless `ca_file` supplies an explicit replacement trust
store. Notification connections use the normal Python hostname verifier; unlike
the endpoint probe, they do not explicitly disable common-name fallback.
Environment proxy settings are not used to route these transports.

The parent saves durable intent before passing the prepared channel and public
event to a child over bounded stdin. Credentials are not child command-line
arguments. Worker input/output bounds, kernel alarm, parent deadline and process
cleanup also cover the new channels; the worker retains the inherited monitor
lock while it can still act. These mechanisms do not prove what an external
service did after accepting bytes.

| Outcome | Meaning for the coordinator |
|---|---|
| `accepted` | The channel's required acknowledgement was observed; pending intent is cleared after its checkpoint is saved |
| `rejected` | Known refusal or failure before submission; intent remains for a later authorized attempt |
| `uncertain` | Submission may have happened, or the worker could not establish a valid result |
| `deferred` | A pending retry or Telegram channel cooldown has not reached its deadline |
| `suppressed` | No incident needs a notification, or an equivalent accepted event remains within its reminder interval |
| `disabled` | Global notification policy or channel configuration disallows sending |

All nonaccepted results use fixed reason codes, never upstream response text.
Telegram exposes `telegram_connection_failed`, `telegram_submission_uncertain`,
`telegram_invalid_response`, `telegram_server_error`, `telegram_redirect_refused`,
`telegram_rejected`, `telegram_rate_limited` and `telegram_message_too_long`.
MQTT exposes `mqtt_connection_failed`, `mqtt_rejected` and
`mqtt_submission_uncertain`. Shared configuration and worker failures retain
their existing fixed codes.

An acknowledged channel is not resent solely because another channel failed.
Any retained pending delivery keeps the top-level result `delivery_failed`,
including `--run` without `--send`; the separate observation status still
describes current TLS health. `--status` does not clear uncertainty or retry.

## Durable state and configuration rotation

The checkpoint stays at schema 1. Existing SMTP/webhook records need no
migration. New transport codes fit the same pending/accepted/superseded records;
provider response bodies and retry hints are not extra persisted fields.

Pending retries reuse their original event ID and public event payload. When
conditions change, the coordinator retains a compact superseded summary and
creates a new event as needed, subject to the Telegram cooldown described
above. A healthy initial observation sends nothing; a previously attempted
alert can lead to a recovery notification even when that alert was uncertain.

The configuration identity includes effective routing, prepared credentials and
CA contents. Rotating a bot token, chat, broker credentials or topic changes the
generation. Status reports `configuration_changed` until a new run saves the
new generation. One prior generation remains as evidence, and old pending
messages are not retargeted to the new destination. The configuration is also
reloaded before each actual attempt, so a change between channels stops further
sending. See
[configuration rotation](EXTERNAL_MONITORING.md#configuration-rotation).

There is no exactly-once guarantee. A peer can accept a message just before its
acknowledgement is lost or before the local accepted checkpoint fails to save.
The original intent then remains available for a later explicit retry. Deleting
state discards that evidence; it is not an acknowledgement operation.

## Validation and deferred acceptance

Automated tests use synthetic configuration, private temporary files, fake
worker results and protocol fixtures. They exercise state durability,
acknowledgement parsing, mixed-channel outcomes, cooldown boundaries, credential
rotation and absence of secrets in public output. These tests do not establish
that a real bot can reach a selected chat or that a broker authorizes and routes
a publication to the intended consumer.

A local validation command, after preparing an operator-controlled private
configuration, is:

```bash
cgp-monitor --check-config --json
```

The following is an example for a **future, explicitly authorized acceptance
session**. It performs real TLS probes and may send real notifications; it has
not been executed as part of this checkpoint:

```bash
cgp-monitor --run --send --json
cgp-monitor --status --json
```

Acceptance must examine the intended Telegram destination or MQTT consumer as
well as the local acknowledgement. It must also exercise loss of acknowledgement
and duplicate handling with the chosen receivers. Keep production credentials,
private state, raw provider replies and recipient identifiers out of issues,
pull requests and test fixtures. No timer override enabling notification sends
is installed by this change.

## Sources and implementation

- [Telegram Bot API: requests and responses](https://core.telegram.org/bots/api#making-requests),
  [sendMessage](https://core.telegram.org/bots/api#sendmessage),
  [Message](https://core.telegram.org/bots/api#message),
  [Chat](https://core.telegram.org/bots/api#chat) and
  [ResponseParameters](https://core.telegram.org/bots/api#responseparameters).
- [MQTT 3.1.1 Plus Errata 01](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html).
- [Transport dispatch](../cgp_cert_manager/notify_transport.py),
  [Telegram transport](../cgp_cert_manager/notify_telegram.py),
  [MQTT transport](../cgp_cert_manager/notify_mqtt.py),
  [delivery coordinator](../cgp_cert_manager/monitor_runner.py) and
  [checkpoint validation](../cgp_cert_manager/monitor_state.py).
