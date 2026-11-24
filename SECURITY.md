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

## Validation limits

The project requires tests for new behavior and strict 100% measured statement
and branch coverage. Unit tests, fault injection, process-death recovery and
loopback TLS tests provide evidence about the tested contracts. Coverage is not
a security proof. Installer containers use mocked systemd, and automated tests
do not establish behavior against production CGP, DNS or ACME services. Follow
[CONTRIBUTING.md](CONTRIBUTING.md) for isolated checks and the development
handoff for outstanding validation.
