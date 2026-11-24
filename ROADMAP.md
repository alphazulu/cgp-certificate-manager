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
- [x] Add strict explicit/effective readiness diagnostics, bounded full-response parsing and refusal before issuance; repeat provenance checks around new deployment and in-process rollback writes. See docs/BOOTSTRAP.md.
- [ ] Enable safe bootstrap when previous fields are missing/inherited/empty only after field-specific deletion/cascade, restoration and TLS semantics are verified on a disposable CGP instance. Current diagnostics do not enable bootstrap writes.
- [x] Implement CAA/DNSSEC-evidence/delegation checks, read-only DNS diagnostics and opt-in adaptive propagation with a proper Certbot authenticator, server-bound TXT ownership receipts and supervised cleanup. See docs/DNS.md.
- [ ] Validate the new DNS path against disposable Cloudflare/ACME staging accounts and lab domains, including renewal migration, before RC/production use.
- [x] Detect unknown/manual certificate changes, block all subsequent domain mutations while any transaction remains pending, and keep pending snapshots outside backup pruning.
- [x] Complete ownership/permission validation for private state, lock, configuration, credentials, history, journals and existing backups. Reject unsafe paths before normal CLI/TUI/installer side effects; no automatic permission repair. See docs/STORAGE.md.
- [x] Implement operator-assisted resolution: exact-preview confirmation, private authorization/completion evidence, incomplete-decision guard and explicit retry without claiming TLS success. See docs/RESOLUTION.md and checkpoint 5 evidence below.
- [ ] Final review, 100% measured coverage, upgrade tests, docs, RC, production validation, approval.

Checkpoint 7 (`2.2.0.dev4`): **726 tests passed in each of two local dependency
profiles**, with **3511 statements / 1422 branches / 100%**, zero missing/partial.
There are **184 additional tests**. Read-only DNS diagnostics, two HTTPS
validators, actual parent referrals, CAA wildcard/account rules, opt-in adaptive
propagation, durable cleanup, real Certbot contracts and process-death tests are
implemented. Existing fixed-mode settings are preserved. Python compilation,
installer shell syntax and diff checks passed. Implementation CI is pending for
this source revision; record its exact commit/run after all five jobs pass.
See DEVELOPMENT.md for the contract and continuation. No production DNS/ACME/CGP
probe, merge, release or deployment has been performed. Automatic bootstrap remains blocked.

Previous checkpoint 6 (`2.2.0.dev3`): the complete local suite passed **542 tests**, with
**2434 statements / 1012 branches / 100%**, zero missing or partial. New code and
87 additional tests are part of this checkpoint, including secret-safe pure
diagnostics, strict input parsing, explicit/effective races around forward and
rollback fsync/TLS, and a real expired-certificate readiness fixture. Python
compile, installer shell syntax and diff checks passed. Implementation
[`2cefcc7`](https://github.com/alphazulu/cgp-certificate-manager/commit/2cefcc7deac815c9ac992798d3520c94871fa22a)
passed [CI 45374434817](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45374434817):
tests (the same 542 / 2434 / 1012 / 100%), both installer baselines and package.
Both installers passed the preservation and 24 unsafe-path refusal scenarios.
This follow-up records the observed run; inspect current-head checks on resume.
See DEVELOPMENT.md for the full contract and continuation steps. Automatic bootstrap
remains blocked; the next write-enablement step requires a disposable CGP and
the documented experiments. DNS hardening can proceed independently if that
environment is unavailable.

Previous checkpoint 5 (`2.2.0.dev2`): local and GitHub suites passed **455 tests**, with
**2073 statements / 844 branches / 100%**, for implementation `4535444`.
[CI 45370524719](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45370524719)
passed tests, both installer baselines and package, including audit preservation
and 24 unsafe-path refusal cases per baseline. Code and tests are in the same
change, including 11 new process-death/restart cases and an actual expired-
certificate acknowledgement test. This follow-up records that observed run;
inspect current-head checks when resuming. See DEVELOPMENT.md for the contract,
review findings and continuation steps. Its next scope was safe bootstrap with
incomplete previous fields; checkpoint 6 above implements the diagnostic and
guard foundation while preserving the remaining write restriction.

Previous checkpoint 4 (`2.2.0.dev1`): local and GitHub suites passed **386 tests**, with
**1742 statements / 692 branches / 100%**. New private-storage code and tests are
in implementation commit `d2bad6e`.
[CI 45367278665](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45367278665)
passed tests, both installer baselines and package. Each installer job passed
18 new unsafe-path refusal cases and preserved pending journals. This follow-up
documentation commit records the observed result; inspect current-head checks
when resuming. See DEVELOPMENT.md for exact next steps and remaining limits.
Operator-assisted resolution was completed in checkpoint 5; checkpoint 7 is active above.
This remains a development checkpoint, not a production release.

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
