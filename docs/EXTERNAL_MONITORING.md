# Independent external TLS monitoring

This describes the unreleased `2.2.0.dev12` development checkpoint. `cgp-monitor`
observes explicitly configured network endpoints and can send explicitly enabled
notifications. It has its own configuration, state and lock. It does not discover
CGP domains, contact Cloudflare or ACME, issue or install certificates, or recover
certificate transactions.

The existing `cgp-letsencrypt --monitoring`, `--metrics` and
`--zabbix-discovery` remain local-only observations. Their metric and dashboard
contracts do not silently acquire these external results. See
[local monitoring](MONITORING.md) for that separate interface.

**External acceptance is deferred.** The maintainer has postponed all tests on
real VMs, servers and providers to a separately scheduled session. Network and
service-activation examples below are instructions for that future session;
they have not been executed as part of this checkpoint. Automated synthetic and
loopback tests do not establish live endpoint coverage, notification delivery or
real systemd scheduling. Current automated evidence belongs in
[DEVELOPMENT.md](../DEVELOPMENT.md); the broader deferral is recorded in
[STAGING.md](STAGING.md).

## Independent paths and private storage

| Object | Installed default |
|---|---|
| Entrypoint | `/usr/local/sbin/cgp-monitor` |
| Configuration | `/etc/cgp-monitor/config.json` |
| State directory | `/var/lib/cgp-monitor` |
| Operation lock | `/var/lib/cgp-monitor/run.lock` |
| Saved observation and notification checkpoint | `/var/lib/cgp-monitor/observations.json` |
| Optional service and timer | `cgp-monitor.service`, `cgp-monitor.timer` |

Run as the effective UID that owns the private files. The installed service uses
root. State directories require `0700` or stricter; configuration, credentials,
custom CA files and state files require `0600` or stricter. Files must be regular,
have one hard link and be owned by that UID. Symlinks and unsafe ancestors are
refused. A trusted configuration parent with mode `0755` is permitted, although
`0700` is the recommended setup for a new configuration directory. Existing
ownership and permissions are not repaired automatically. The full rules and
their limits are in [STORAGE.md](STORAGE.md).

Configuration and state paths must be absolute and must not contain `..`.
State cannot overlap the manager configuration/state, Certbot tree or application
source tree, including an ancestor of a protected tree. The installed application
under `/opt/cgp-certificate-manager` requires the default monitor state directory
for an enabled `--run`; an alternative is refused with `installed_state_override`. This
keeps installed runs under the lock used by the installer. A separate source
checkout can use a custom state directory. Read-only `--status` can inspect a
custom safe state directory.

## Commands and exit status

No action is selected implicitly. Exactly one of `--check-config`, `--probe`,
`--status` or `--run` is required, except for `--help` and `--version`.

| Command | Network activity | State behavior | Notifications |
|---|---|---|---|
| `cgp-monitor --check-config` | None | Validates configuration and required private input files; does not create state | None |
| `cgp-monitor --probe` | Observes all enabled TLS endpoints when monitoring is enabled | Does not create a directory, lock or checkpoint | None |
| `cgp-monitor --probe --endpoint https` | Observes one configured, enabled endpoint | Does not persist the result | None |
| `cgp-monitor --status` | None | Reads a saved checkpoint under a nonblocking shared lock, if available; never creates or repairs it | None |
| `cgp-monitor --run` | Observes all enabled endpoints | Holds the separate exclusive monitor lock and saves results | Does not send or retry |
| `cgp-monitor --run --send` | Observes all enabled endpoints, then processes configured notification policy | Saves observation and per-channel delivery checkpoints | Explicitly authorized attempts only |
| `cgp-monitor --help` / `--version` | None | No configuration or state required | None |

`--json` selects structured output for the four actions. `--config PATH` selects
a private configuration; `--state-dir PATH` selects the state location within
the restrictions above. `--endpoint ID` is only valid with `--probe`, and
`--send` only with `--run`. Invalid combinations are refused before configuration
access. An invalid endpoint identifier is refused before loading configuration.

Here, **read-only means no persistent changes or delivery**: `--probe` still
opens network connections and performs the configured TLS/STARTTLS exchange.
It does not acquire the state lock, so it can overlap an upgrade. A concurrent
upgrade can cause a probe to fail; it cannot turn that probe into a state write
or notification attempt. `--check-config` and `--status` are local operations,
but configuration preparation can read custom CA files and enabled channels'
credential files. Globally disabling notification policy does not bypass
validation of an individually enabled channel.

| Exit code | Meaning |
|---|---|
| `0` | `ok`, `valid` or `disabled`, according to the action |
| `1` | An observation has `warning` or `critical` health |
| `2` | Invalid arguments/configuration, missing or unusable state, busy operation, stale/future/configuration-changed state, delivery failure, or another operational error |
| `130` | Interrupted operation |

A valid configuration or disabled monitor returning zero is not evidence of a
successful network observation. Delivery failure takes precedence over the
observation's exit class: an `ok` TLS observation can accompany top-level
`delivery_failed` and exit 2. Retained pending delivery keeps `--run` in this
failure state even without `--send`; it does not cause an implicit retry.

Operational errors use the normal text/JSON result with a fixed safe reason.
Argument parsing errors use usage text on stderr rather than JSON. Raw network
responses, exception text and credentials are not copied into results. The
argument and output contract is implemented in
[monitor_cli.py](../cgp_cert_manager/monitor_cli.py).

## Configuration

The following complete configuration is disabled and performs no observations
or delivery:

```json
{
  "schema": 1,
  "enabled": false,
  "endpoints": [],
  "notifications": {
    "enabled": false,
    "channels": []
  }
}
```

There is no automatic import of the manager's domains, TLS templates, email
address or legacy `notifications` settings. Choose explicit endpoints and
destinations for this monitor. JSON object keys are strict; duplicate keys,
non-finite numbers and unsupported fields are refused. Numeric options below
require integers, not strings, floats or booleans. Configuration is limited to
256 KiB.

| Top-level field | Default | Allowed value / meaning |
|---|---|---|
| `schema` | Required | Integer `1` |
| `enabled` | Required | Boolean; `true` requires at least one enabled endpoint |
| `endpoints` | Required | Array of up to 16 endpoints, including disabled entries |
| `timeout_seconds` | `15` | `1..30`; deadline budget for each probe worker |
| `warning_days` | `21` | `1..365`; remaining days at or below this value are a warning unless critical |
| `critical_days` | `7` | `0..364`, strictly less than `warning_days`; at or below this value is critical |
| `max_age_seconds` | `900` | `30..86400`; maximum saved snapshot age accepted by `--status` |
| `notifications` | Disabled, empty channels | Notification options described below |

Each endpoint has required `id`, `host`, `port` and `server_name` fields.
Endpoint IDs and channel IDs each have their own unique namespace. IDs contain
1–64 lowercase ASCII letters, digits, underscores or hyphens, beginning with a
letter or digit. They are stable labels in observations and delivery records.

| Endpoint field | Meaning |
|---|---|
| `enabled` | Optional boolean, default `true` |
| `host` | Connection destination: a DNS name or an IPv4/IPv6 literal |
| `port` | Required integer `1..65535`; protocol is not inferred from it |
| `server_name` | DNS/IP certificate identity to verify; DNS names also supply TLS SNI |
| `protocol` | `tls` by default; alternatively `smtp_starttls`, `imap_starttls` or `pop3_starttls` |
| `ca_file` | Optional absolute path to a private PEM certificate bundle, at most 1 MiB |

DNS endpoint names are normalized to lowercase IDNA form. Wildcard identities,
IPv6 zone identifiers and surrounding whitespace are refused. An endpoint
marked disabled still needs valid endpoint settings. An explicit selection of
an unknown or disabled endpoint fails rather than choosing another target.

This **future acceptance example** enables two observations, but keeps
notifications disabled. Replace the synthetic names with authorized lab targets
before running a network command:

```json
{
  "schema": 1,
  "enabled": true,
  "timeout_seconds": 15,
  "warning_days": 21,
  "critical_days": 7,
  "max_age_seconds": 900,
  "endpoints": [
    {
      "id": "https",
      "host": "mail.example.test",
      "port": 443,
      "server_name": "mail.example.test",
      "protocol": "tls"
    },
    {
      "id": "smtp",
      "host": "mail.example.test",
      "port": 587,
      "server_name": "mail.example.test",
      "protocol": "smtp_starttls"
    }
  ],
  "notifications": {
    "enabled": false,
    "channels": []
  }
}
```

See [monitor_config.py](../cgp_cert_manager/monitor_config.py) for the complete
schema and normalization rules.

## What an observation establishes

Endpoint probes require TLS 1.2 or newer, a trusted certificate chain and the
configured identity. They disable common-name fallback: the certificate must
match through its subject alternative names. An IP identity needs an appropriate
IP SAN. There is no retry with certificate verification disabled.

Without `ca_file`, the worker uses system trust. An explicit CA bundle replaces
system trust for that connection rather than extending it. Its certificates are
validated and captured from the protected file before the network operation;
the worker receives the captured bytes. The monitor does not read a service's
private key or compare the served chain to a local Certbot lineage.

STARTTLS protocols require the appropriate advertised capability and successful
upgrade response. SMTP uses EHLO/STARTTLS, IMAP uses CAPABILITY/STARTTLS, and POP3
uses CAPA/STLS. These probes do not authenticate, submit email, open a mailbox or
perform an application request. A TLS success on an HTTPS port does not verify
HTTP application health.

Name resolution uses the host's resolver. Up to eight distinct IPv4/IPv6 TCP
addresses are considered, with a three-second connection-attempt cap within the
remaining budget. After the first successful TCP connection, that connection is
the observation: a subsequent protocol/TLS failure is not hidden by trying
another backend. This is one selected DNS/backend observation, not a check of
every address, load-balancer member or resolver view. There is no DNSSEC quorum,
CAA check, revocation check or proof of application availability in this command.

A report contains generation/completion times, thresholds, overall health and
per-endpoint rows. Verified rows include the leaf's expiry, SHA-256 fingerprint,
selected peer address, TLS version and calculated days remaining. Verification
failures have `verified: false`, a fixed error code, and `null` expiry,
fingerprint, TLS version and days remaining; the connected peer address may
still be known. A null value is unknown, not zero days or a healthy certificate.

Health is the worst endpoint level. TLS and transport failures are critical.
A successfully verified certificate can also be critical when its remaining
validity is at or below `critical_days`. `complete: false` identifies worker
failure/timeout/invalid-output observations. `complete: true` can still describe
a fully observed TLS verification failure; it does not mean every endpoint is
healthy.

Useful fixed reasons include `dns_failed`, `connect_failed`, `timeout`,
`starttls_unavailable`, `starttls_rejected`, `protocol_error`, `tls_expired`,
`tls_not_yet_valid`, `tls_hostname_mismatch`, `tls_untrusted`,
`tls_verification_failed`, `tls_handshake_failed`, and worker failure codes.
The probe and public result validators are
[tlsprobe.py](../cgp_cert_manager/tlsprobe.py) and
[monitor_state.py](../cgp_cert_manager/monitor_state.py).

### Saved status and clock changes

`--status` never refreshes the network observation. `missing`, `busy` and
`invalid` describe absent state, a held operation lock or an unusable private
checkpoint. It reports `configuration_changed` when the saved configuration
identity differs from the current prepared configuration. Future observation
completion or recorded successful-delivery times produce `future`.

Freshness uses the observation's **generation/start time**. Age greater than
`max_age_seconds` is `stale`; the exact boundary is still fresh. A result can
include historical endpoint rows while its top-level status is stale, future or
configuration-changed. Consumers must check the top-level result rather than
treating an old `ok` row as current health.

A run refuses backward clock movement relative to saved observations and
accepted deliveries. A new report whose generation time precedes the run's
pre-observation time is rejected before saving. Delivery checks also refuse a
clock earlier than the observation being processed. These checks preserve
evidence rather than resetting timestamps to make a result appear current.

## Optional notification channels

Sending requires all of: monitoring enabled, global notification policy enabled,
the channel enabled, and the explicit `--run --send` action. There is no separate
`--send` action that drains a queue without obtaining a new observation.

| Notification option | Default | Allowed value |
|---|---|---|
| `enabled` | `false` | Boolean; `true` requires at least one enabled channel |
| `channels` | `[]` | Up to 4 channels, including disabled entries |
| `timeout_seconds` | `15` | Integer `1..30`, per delivery worker |
| `repeat_seconds` | `86400` | Integer `60..604800`, suppression period after an accepted equivalent event |
| `retry_seconds` | `300` | Integer `10..86400`, earliest next attempt for an unconfirmed event |

Each channel has `id`, `kind` (`smtp`, `webhook`, `telegram` or `mqtt`) and optional `enabled`
(default `true`). An individually disabled channel does not load its credential
files or send. The following is a **configuration fragment**, not a replacement
for the complete configuration. Both channels remain disabled until a future
acceptance session:

```json
{
  "notifications": {
    "enabled": false,
    "repeat_seconds": 86400,
    "retry_seconds": 300,
    "timeout_seconds": 15,
    "channels": [
      {
        "id": "mail",
        "kind": "smtp",
        "enabled": false,
        "host": "smtp.example.test",
        "port": 587,
        "security": "starttls",
        "from": "monitor@example.test",
        "to": ["ops@example.test"],
        "username": "monitor-user",
        "password_file": "/etc/cgp-monitor/smtp-password"
      },
      {
        "id": "hook",
        "kind": "webhook",
        "enabled": false,
        "url": "https://alerts.example.test/cgp",
        "token_file": "/etc/cgp-monitor/webhook-token"
      }
    ]
  }
}
```

SMTP requires `host`, `from` and a list of 1–16 distinct `to` mailboxes, without
display-name syntax. `security: "tls"` is implicit TLS and defaults to port 465;
`"starttls"` requires the TLS upgrade and defaults to port 587. Explicit
`"plain_local"` defaults to port 25 and permits only the literal `127.0.0.1` or
`::1`, with neither authentication nor a custom CA. A username and
`password_file` must be supplied together. Passwords are read from a private
ASCII file, with one final LF or CRLF permitted; other password spaces are
preserved.

Webhooks require an HTTPS `url`; URL user information and fragments are refused.
An optional `token_file` supplies a private ASCII bearer credential. The request
is a JSON POST with an `Idempotency-Key` equal to the event ID. Redirects are not
followed and response bodies are not used. A complete 2xx acknowledgement is
accepted; complete non-2xx responses are rejected. Truncated or ambiguous
submission responses remain uncertain rather than becoming accepted.

All four channel kinds support an optional private `ca_file`. Notification
credential and CA files are limited to 16 KiB each. Their TLS connections require
at least TLS 1.2 and normal Python hostname verification; unlike endpoint probes,
the notification context does not explicitly disable common-name fallback.
An explicit notification CA replaces system trust for that connection.

SMTP acceptance means a complete submission acknowledgement from the relay,
not receipt by the final mailbox. Partial recipient refusal remains uncertain
because some recipients may already have accepted the message. A connection
failure before submission can be rejected; a disconnect or timeout after
submission begins remains uncertain. SMTP multiline replies and HTTP response
headers are bounded; incomplete acknowledgement framing is not accepted.
See [notify_transport.py](../cgp_cert_manager/notify_transport.py).

The [Telegram and MQTT guide](NOTIFICATION_CHANNELS.md) describes their fields,
protocol acknowledgements, fixed failure reasons, message limits and disabled
examples. Telegram sends one plaintext Bot API message; MQTT publishes the
event JSON once at QoS 1 without retaining it. Neither adds a dependency or
permits implicit delivery. The complete shipped example has all four channels
disabled.

## Durable intent, retries and recovery notifications

For each channel, an authorized send saves a durable intent **before** starting
the delivery worker. The intent includes a stable event ID, the original public
event payload, attempt count, retry time and conservative unconfirmed outcome.
Only a confirmed protocol acknowledgement clears the pending intent and records
an accepted event. A crash after the remote service accepted a submission but
before the local confirmation was saved leaves uncertainty intact.

The next `--run --send` first obtains a new observation. An equivalent pending
event waits until `retry_at`, then retries with its original ID, payload and
observation time. SMTP uses the stable ID in `Message-ID`; the webhook uses it
in `Idempotency-Key`. Telegram includes it in plaintext and MQTT in the JSON
payload. Receivers may use these identifiers to deduplicate, but the
monitor does not promise exactly-once delivery. A retry can duplicate a remotely
accepted submission whose acknowledgement was lost.

Equivalent events have the same kind and endpoint ID/status/error-code
combination. After acceptance, repetitions are suppressed for `repeat_seconds`.
Changes in fingerprint or remaining days alone do not defeat this suppression
while the health classification is unchanged. A changed condition supersedes
the prior pending event, retaining its most recent summary, and creates a new
event ID. The checkpoint is bounded state, not an unlimited event archive.

A valid Telegram rate-limit response can extend the retry deadline by its
`retry_after` interval. The saved deadline is measured from the end of the
attempt using the greater of that interval and `retry_seconds`. It applies to
the entire channel, including changed conditions and recovery, until that
deadline; the next permitted run considers the latest observation. This does
not delay another channel. Only the calculated `retry_at` is stored; the
worker's retry hint is not added to public output or the schema-1 checkpoint.

A channel with a previously attempted alert has an incident until an accepted
recovery event. When observations return to `ok`, an explicit sending run can
send that recovery even if the earlier alert was uncertain. A healthy initial
run with no incident is suppressed. A recovery notification describes observed
TLS health; it never starts CGP certificate recovery.

| Public delivery outcome | Meaning |
|---|---|
| `accepted` | Protocol acknowledgement observed; final recipient delivery is not established |
| `rejected` | A known refusal or pre-submission failure; intent remains available for a later authorized attempt |
| `uncertain` | Submission may have occurred, or the worker could not establish its result |
| `deferred` | An equivalent pending event or Telegram channel cooldown has not reached its retry time |
| `suppressed` | No incident needs a message, or equivalent accepted notification is still within its repeat interval |
| `disabled` | Policy or channel does not authorize sending |

Unresolved pending delivery keeps top-level `delivery_failed`, including a
probe-and-save `--run` without `--send`. The fresh `observation.status` still
records TLS health independently. Use `--status` to inspect saved delivery
outcomes. Neither status inspection nor the default timer retries a message.

### Configuration rotation

The private checkpoint binds to a digest of the prepared configuration,
including credential and CA content. A changed effective configuration causes
read-only status to report `configuration_changed`. The next explicit run
starts a fresh notification generation and retains one previous generation as
evidence. Old pending messages are not automatically retargeted or retried with
new recipients or credentials. Repeated changes replace that one retained
generation; this is not a long-term audit archive.

Before each actual send, the CLI's run reloads its configuration and compares
the prepared identity again. A change during the run stops further sending with
`configuration_changed`; already persisted channel outcomes remain recorded.
Deleting the checkpoint would discard deduplication and uncertainty evidence,
so it is not a delivery acknowledgement mechanism. The coordinator is
[monitor_runner.py](../cgp_cert_manager/monitor_runner.py).

## Worker, locking and data boundaries

Each probe or delivery runs in a short-lived Linux worker with a parent deadline
covering process startup, DNS resolution and the operation. Socket operations
also have timeouts. A worker kernel alarm is explicitly unblocked and armed
before dispatch, including when the parent dies during a blocked resolver call.
The parent supervises process-group termination before returning from handled
failure. Worker failures have fixed public codes; uncertain delivery intent is
retained.

A persistent run holds its own exclusive lock and passes the locked open-file
description to its workers on a dedicated descriptor. Parent death therefore
does not release that lock while its worker is still alive. Status uses the
existing lock read-only and does not create it. These operations do not take the
certificate manager's normal operation lock; the installer holds both locks in
a fixed order during application replacement and handled rollback.

Worker requests use private pipes rather than secret-bearing command-line
arguments or environment variables. The worker environment is restricted and
does not inherit proxy settings, `SSLKEYLOGFILE` or an ambient `PYTHONPATH`.
Prepared credentials and CA bytes stay in memory and the worker request. They
are not saved in the observation/checkpoint, printed in results or copied into
notification events. Public results contain endpoint names/addresses, times,
certificate fingerprints, fixed reasons and event/channel IDs, which can still
be operationally sensitive metadata. The private checkpoint additionally holds
configuration digests and delivery bookkeeping.

Configuration is bounded to 256 KiB, the checkpoint and worker request to 2 MiB,
and the worker response to 128 KiB. Notification event JSON must be smaller
than 128 KiB. TLS leaf certificates are bounded to 64 KiB. STARTTLS input is
bounded by line length, line count and total bytes. These checks and ownership
rules do not isolate the monitor from a malicious root or another process with
the same trusted UID. See
[monitor_worker.py](../cgp_cert_manager/monitor_worker.py) and the storage trust
boundaries.

## Installation and optional scheduling

The full manager installer still requires a valid existing
`/etc/cgp-letsencrypt/config.json` and its manager prerequisites. It is not a
monitor-only bootstrap installer. It can initialize the private monitor state
directory and lock, validates an existing optional monitor configuration, and
preserves monitor configuration and checkpoint contents. It installs the new
launcher and units without creating an active monitor configuration, probing,
sending, or enabling a timer.

An active manager/monitor operation or service prevents replacement. The
installer holds both verified inherited locks through its payload and handled
rollback. The monitor launcher and units participate in application-file
backup/restoration. On a handled failure, previously active timers are restored
only after successful restoration. **Successful installation leaves both the
renewal timer and monitor timer stopped.** Resume renewal scheduling separately
using the normal [manager upgrade procedure](../README.md).

The shipped monitor service runs exactly:

```text
/usr/local/sbin/cgp-monitor --run
```

It does **not** include `--send`. The service uses root, `UMask=0077`,
`ProtectSystem=strict`, `ProtectHome=true`, `NoNewPrivileges=true` and
`PrivateTmp=true`. Its explicit state write exception is
`ReadWritePaths=/var/lib/cgp-monitor`. Private `/tmp` and `/var/tmp` remain
writable, and API filesystems have separate protection semantics; these settings
are not proof of complete filesystem confinement. See the upstream
[systemd.exec documentation](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
for `ProtectSystem`, `PrivateTmp` and `ReadWritePaths`.

The service start timeout is 900 seconds. The timer specifies `OnBootSec=2min`,
`OnUnitInactiveSec=5min` and `RandomizedDelaySec=30`. The recurring interval is
relative to service deactivation. The unit does not override `AccuracySec`, so
systemd's default one-minute accuracy window also applies; this is not a
guaranteed wall-clock cadence. See
[systemd.timer](https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html).

The shipped oneshot service has no `SuccessExitStatus` override. Exits 1 and 2
therefore mark the service failed, including when the monitor successfully
detected a TLS warning, critical condition or unresolved delivery. Read
`cgp-monitor --status --json` and the service output to distinguish these results
from a startup/configuration failure; systemd's `failed` label alone does not
identify the cause. The exit-status rules are documented in
[systemd.service](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html).
Existing operator overrides remain separate from the shipped unit file.

### Deferred operator acceptance: installed service

**Do not treat these examples as completed acceptance or automatic activation.**
For the separately scheduled lab session, first configure authorized endpoints,
enable monitoring in its private configuration, and leave notifications disabled:

```sh
cgp-monitor --check-config --json
cgp-monitor --probe --json
cgp-monitor --probe --endpoint https --json
cgp-monitor --run --json
cgp-monitor --status --json
```

After the intended lab observations and persistence checks have succeeded, the
operator can explicitly enable probe-and-save scheduling:

```sh
# Future acceptance session only; not executed by this checkpoint.
systemctl enable --now cgp-monitor.timer
systemctl list-timers cgp-monitor.timer
```

Notifications require separate destination acceptance, enabling the global
notification policy and the desired channels, and an explicit sending action:

```sh
# Future acceptance session only; may submit real notifications.
cgp-monitor --run --send --json
```

For future scheduled sending, an operator can use
`systemctl edit cgp-monitor.service` and explicitly replace its command:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/sbin/cgp-monitor --run --send
```

Apply the unit change with `systemctl daemon-reload` in that acceptance session.
The override is an intentional authorization for subsequent scheduled sends;
it is not installed or enabled by this project update. Installer CI uses a
`systemctl` stub and cannot establish that a real host's timer, trust store,
SMTP relay, webhook, Telegram bot or MQTT broker behaves as expected.

### Separate monitoring host from a source checkout

A separate Linux host can run the source entrypoint without a running CGP
instance or a CGP manager configuration. Use the supported Python 3.12 runtime
and an appropriate OS trust store, with monitor configuration/state owned by
the invoking UID. Keep the state directory outside the source checkout and
outside protected manager/Certbot trees. For example:

```sh
cd /path/to/cgp-certificate-manager
python3 -m cgp_cert_manager.monitor_cli \
  --config /path/to/private-monitor/config.json \
  --state-dir /path/to/private-monitor/state \
  --check-config --json
```

That action validates locally. Replacing `--check-config` with `--probe`,
`--run`, or `--run --send` is an explicit network/persistence/delivery choice
for the **deferred acceptance session**. It does not install a systemd service,
alter the certificate manager, or establish external acceptance by itself.
