# Roadmap / Дорожная карта

## Working rules
- Stable baseline: v2.1.0, commit fffbeda39a6adbb1c7ab8e924f4ec2c0089a2a5f. 188 unit tests, 100% measured statement and branch coverage, installer integration CI passed. Production upgrade, TLS verification and systemd control run confirmed; actual future renewal not yet observed.
- Develop 2.2 in feature/transactional-deployment, draft PR. Never merge or publish a release until explicit maintainer approval and successful CI.
- Read this file and DEVELOPMENT.md at the start of every resumed session; inspect actual branch HEAD, PR and CI before edits. Update checkboxes and handoff in the same commit as substantive changes. Mark tests passed only from observed results.
- Do not commit real domains, configuration, credentials, private keys or production logs. Use synthetic fixtures. Keep strict 100% coverage gate; no artificial exclusions.

## 2.2 — Reliability (in progress)
- [x] Define transaction design and safety invariants.
- [ ] Implement durable per-domain write-ahead journal (atomic replace, file and directory fsync, mode 0600).
- [ ] Implement recovery: distinguish previous, intended and unknown CGP state; refuse to overwrite unknown/manual changes.
- [ ] Integrate journal with deployment and manual rollback under global lock.
- [ ] Verify live TLS using restored backup chain, not current Certbot files.
- [ ] Expose read-only transaction status and explicit recovery in CLI/TUI; scheduled recovery before mutation.
- [ ] Fault-injection tests at every phase, abrupt process termination tests, corruption and concurrency tests.
- [ ] Real OpenSSL fixtures and local TLS integration tests.
- [ ] Safe bootstrap when previous fields missing; fail closed until CGP semantics established.
- [ ] DNS CAA/DNSSEC/delegation checks and dynamic propagation wait.
- [ ] Detect manual changes, validate permissions, backup retention (never remove pending recovery data).
- [ ] Final review, 100% measured coverage, upgrade tests, docs, RC, production validation, approval.

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
