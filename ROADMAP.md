# Roadmap / Дорожная карта

## Working rules
- Stable baseline: v2.1.0, commit fffbeda39a6adbb1c7ab8e924f4ec2c0089a2a5f. 188 unit tests, 100% measured statement and branch coverage, installer integration CI passed. Production upgrade, TLS verification and systemd control run confirmed; actual future renewal not yet observed.
- Develop 2.2 in feature/transactional-deployment, draft PR. Never merge or publish a release until explicit maintainer approval and successful CI.
- Read this file and DEVELOPMENT.md at the start of every resumed session; inspect actual branch HEAD, PR and CI before edits. Update checkboxes and handoff in the same commit as substantive changes. Mark tests passed only from observed results.
- Do not commit real domains, configuration, credentials, private keys or production logs. Use synthetic fixtures. Keep strict 100% coverage gate; no artificial exclusions.

## 2.2 — Reliability (in progress)
- [x] Define transaction design and safety invariants.
- [x] Implement durable per-domain write-ahead journal (atomic replace, file and directory fsync, mode 0600).
- [x] Implement recovery: distinguish previous, intended and unknown CGP state; refuse to overwrite unknown/manual changes.
- [x] Integrate journal with deployment and manual rollback under global lock.
- [x] Verify live TLS using restored backup chain, not current Certbot files.
- [x] Expose read-only transaction status and explicit recovery in CLI/TUI; scheduled recovery before mutation. F9 also works without discovered domains.
- [x] Fault-injection tests at every phase, fresh-process recovery after abrupt termination, corruption, lock exclusion and detected concurrent manual changes. These do not simulate storage power loss or provide remote compare-and-swap.
- [x] Real OpenSSL fixtures and loopback TLS integration tests.
- [ ] Safe bootstrap when previous fields missing; fail closed until CGP semantics established.
- [ ] DNS CAA/DNSSEC/delegation checks and dynamic propagation wait.
- [x] Detect unknown/manual certificate changes, block all subsequent domain mutations while any transaction remains pending, and keep pending snapshots outside backup pruning.
- [ ] Complete ownership/permission validation for parent state directory, lock, configuration and existing backups; journal directory/files already checked.
- [ ] Define safe operator-assisted resolution for invalid/expired previous certificates; current behavior retains the journal when TLS proof is unavailable.
- [ ] Final review, 100% measured coverage, upgrade tests, docs, RC, production validation, approval.

Checkpoint 3: local and GitHub suites passed 303 tests with 100% measured
statements and branches. [CI 45363794396](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45363794396)
passed for implementation commit `458c840`: tests, installer upgrades from stable
2.0.1 and 2.1.0 (including pending-journal preservation), and package. See
DEVELOPMENT.md for exact resume steps and remaining limits. This is still a
development checkpoint, not a production release.

## 2.3 — Monitoring
Zabbix discovery/template; Prometheus textfile; Grafana; external TLS probes; SMTP/webhooks and optional Telegram/MQTT.

## 2.4 — Updates
Explicit administrator-approved update, authenticity verification (signed manifests/trusted keys), safe extraction, rollback and version checks.

## 2.5 — DNS providers
Provider abstraction, Cloudflare compatibility, RFC2136, PowerDNS, Route53, acme-dns and manual workflow.

## 3.0 — Multi-server administration
Separate server identities, least privilege, centralized visibility, independent transactions.

## Repository maintenance
- [ ] License decision by owner; do not assume permission.
- [ ] SECURITY.md, CONTRIBUTING.md, release automation, dependency/security scanning.
- [ ] CI matrix for supported Ubuntu/Debian versions; verify before claiming support.
