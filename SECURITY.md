# Security

This document describes the trust and data boundaries of the development
branch. See [DEVELOPMENT.md](DEVELOPMENT.md) for the exact implementation,
observed validation and unresolved work, and [ROADMAP.md](ROADMAP.md) for release
status. Development safeguards must not be assumed to exist in an older release.

## Report a vulnerability privately

Open the repository's [Security page](https://github.com/alphazulu/cgp-certificate-manager/security).
**If GitHub offers “Report a vulnerability”, use that private reporting flow.**
This document does not assert that private vulnerability reporting is enabled.

If that option is unavailable and no verified private maintainer contact is
already known, open only a minimal public request for a private contact channel,
for example: “Please provide a private channel to report a security concern.”
Do not include the vulnerability details, reproduction, affected hosts or
attachments in that public request. Wait for a private channel confirmed by a
repository maintainer before sending technical details.

A private report should identify the version or commit, affected component,
required access, expected and observed behavior, and a minimal reproduction
using synthetic data. Never include live tokens, passwords, private keys or
complete production state. If evidence cannot be safely sanitized, describe
what it contains and agree on handling before transferring it.

## Privileges and sensitive data

The installed manager normally runs as root and can change CommuniGate
certificate settings and Cloudflare DNS records using configured credentials.
Trusted application source, the local operating system, its administrators and
the effective UID are part of the trust boundary.

Configuration and Cloudflare credential files contain secrets. Certificate
backups, transaction journals and operator-resolution authorizations can contain
private certificate keys. Adaptive DNS receipts contain challenge values and
account/zone bindings. Treat these files and installation backups as private;
do not attach them to issues, pull requests or public logs.

Private state directories require ownership by the effective UID and mode
`0700` or stricter. Private files must be regular, owned by that UID, mode `0600`
or stricter and have exactly one hard link. Symbolic links and unsafe path
components are refused. Ancestors must be trusted root/effective-UID directories
without group/other write access, apart from permitted trusted sticky directories.
A trusted configuration parent with mode `0755` is allowed when its files meet
the private-file rules. Existing unsafe objects are not automatically repaired
with `chmod` or `chown`. See [the precise storage policy](docs/STORAGE.md).

Those checks do not isolate the manager from root or another process running
under the same trusted UID, audit all ACL/mount/security-label behavior, or
detect earlier disclosure. Certbot's standard `live` symlinks are outside the
manager's private-storage policy and remain Certbot's responsibility.

## Monitoring metadata

The local monitoring collector runs under the identity allowed to read private
manager sources, then exports an explicit allowlist. Domain and lineage names,
numeric saved state, public leaf expiry, source status and retained-artifact
counts are monitoring metadata. Raw configuration, messages, credentials, keys,
receipt values and operator evidence are not exported. Local leaf expiry and a
saved success time do not prove current deployed TLS.

Only an explicit `--metrics --metrics-file` command publishes a readable `0644`
textfile, in a pre-existing trusted directory outside manager private/Certbot
trees. Existing private or unsafe targets are refused. node_exporter needs only
that exported file, not access to private sources or privileged manager commands.
Missing/failed collection is visible; unknown measurements are not zeroes, and
incomplete Zabbix discovery emits no list. See [MONITORING.md](docs/MONITORING.md)
for filesystem, freshness and publication failure semantics.

## External services and recovery

The separate `cgp-monitor` performs network observations only for explicitly
configured endpoints. It uses its own private configuration, state and lock,
without manager credentials, CGP discovery, certificate private keys or local
Certbot lineages. Probes require TLS 1.2+, trusted certificates and a matching
SAN; they never retry with verification disabled. An explicit private CA bundle
replaces the system trust set for that endpoint. A successful observation covers
the connected peer at that time, not every DNS/backend address, application
health or certificate revocation.

Notification routing and credential snapshots stay out of public results and
saved events. SMTP uses verified TLS or STARTTLS; the explicit `plain_local`
option permits only literal `127.0.0.1` or `::1`, without authentication or a CA
override. Webhooks require verified HTTPS, ignore proxy environment variables
and refuse redirects. Only `--run --send` plus enabled configuration permits
delivery. A durable per-channel intent precedes the network attempt; an absent
acknowledgement remains uncertain and may be retried with the same event ID.
SMTP acceptance is not recipient delivery, and a webhook receiver must implement
its own idempotency. Exactly-once delivery is not promised.
Complete protocol framing is required before an acknowledgement is accepted;
truncated SMTP lines or HTTP headers remain uncertain after submission.

Telegram sends through verified HTTPS without proxy inheritance or redirects.
A bounded, completely framed JSON response must confirm the expected message
before acceptance. Bot tokens stay in private snapshots; raw API descriptions
and token-bearing URLs are not included in output. Valid provider rate limits
extend the saved channel cooldown, including across incident changes.
MQTT uses verified TLS by default; its unauthenticated `plain_local` option is
restricted to literal loopback. A matching QoS-1 PUBACK acknowledges the broker
protocol exchange, not subscriber delivery or authorization: MQTT 3.1.1 allows
a broker to acknowledge an unauthorized publication. No retained message,
persistent MQTT session or exactly-once consumer processing is promised. See
the [channel contract and protocol references](docs/NOTIFICATION_CHANNELS.md).

Workers receive secrets through bounded stdin, not command-line arguments or
inherited environment variables. The parent supervises a process group; each
worker also arms its own deadline and retains the monitor lock when applicable.
That bounds a worker stuck in system DNS even after parent death. Local root,
the effective UID, trusted Python/source and the operating system remain trusted.
The shipped monitor service omits `--send`, and installation enables no monitor
timer or destination. See [the complete contract](docs/EXTERNAL_MONITORING.md)
for limits, fresh/unknown state and explicit later activation.
An installed `--run` uses the fixed monitor state directory to coordinate with
the installer; a custom directory is allowed for runs from an isolated source
checkout. Read-only status/probe actions do not acquire the exclusive run lock,
and the stateless probe is not serialized against application replacement.

- **CommuniGate:** the configured HTTP CLI is restricted to loopback URLs and
  redirects are rejected. Local transport and the authorized CGP account remain
  trusted. Snapshot readback and TLS verification are separate checks; neither
  creates a server-side atomic transaction or excludes a concurrent WebAdmin
  change. See [certificate recovery](docs/TRANSACTIONS.md).
- **DNS and ACME:** issuance relies on Cloudflare, the CA and public DNS.
  Preflight uses authenticated HTTPS resolver views; DNSSEC evidence is a
  resolver assertion, not local DNSSEC validation. A successful observation does
  not prove global propagation. Provider read-then-delete is not an atomic
  compare-and-swap. See [DNS trust, ownership and cleanup](docs/DNS.md).
- **Interrupted operations:** the shared lock coordinates cooperating manager
  processes. Durable journals and receipts preserve unresolved effects; an
  unknown state is not permission to overwrite it or discard evidence.
  Filesystem durability depends on the storage stack honoring synchronization.
  Application installation has rollback for handled failures, not guaranteed
  recovery after power loss or `SIGKILL`.
- **Explicit exceptions:** operator acknowledgement of exact previous settings
  records `acknowledged_unverified`; it makes no TLS success claim. Automatic
  bootstrap to absent/inherited certificate fields remains disabled. Read
  [operator resolution](docs/RESOLUTION.md) and
  [bootstrap readiness](docs/BOOTSTRAP.md) before changing those boundaries.

Public diagnostic reports deliberately limit their fields, but Certbot,
third-party plugins, services and surrounding tools maintain their own logs.
The manager does not promise that every third-party log is secret-free. Review
and minimize any excerpt before sharing it; do not publish production logs.

## Dependency and source scanning

The development CI audits complete resolved test environments with pip-audit
and analyzes `cgp_cert_manager` plus `repo_tools` with CodeQL. Current dependency
findings and CodeQL findings block packaging. The deliberately historical
compatibility profile keeps its findings visible under an explicit informational
policy; incomplete, skipped, warning-bearing or failed dependency audits fail
both profiles. Raw reports, inventory, diagnostics and policy summaries are
preserved as CI artifacts. This is not a scan of the installed server or its
distribution-maintained packages.

The security workflow is also manual and weekly once present on the default
branch. New advisories can change a previously clean result. Neither audit
policy applies automatic fixes or silently ignores findings. See
[release and security checks](docs/RELEASING.md) for scope, exact gates and
failure behavior.

Manual release preparation binds an existing reviewed tag to the checked source
and prepares artifact provenance plus an unpublished draft. Checksums and
provenance manifests alone are not trusted signatures. An attestation identifies
the workflow/source of an artifact; it does not itself establish maintainer
approval or production readiness. The workflow does not publish automatically
or replace the deferred real-environment acceptance.

## Validation limits

The project requires tests for new behavior and strict 100% measured statement
and branch coverage. Unit tests, fault injection, process-death recovery and
loopback TLS tests provide evidence about the tested contracts. Coverage is not
a security proof. Installer containers use mocked systemd, and automated tests
do not establish behavior against production CGP, DNS or ACME services. Follow
[CONTRIBUTING.md](CONTRIBUTING.md) for isolated checks and the development
handoff for outstanding validation.
