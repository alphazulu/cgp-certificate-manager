# Roadmap / Дорожная карта

## Working rules
- Stable baseline: v2.1.0, commit fffbeda39a6adbb1c7ab8e924f4ec2c0089a2a5f. 188 unit tests, 100% measured statement and branch coverage, installer integration CI passed. Production upgrade, TLS verification and systemd control run confirmed; actual future renewal not yet observed.
- Develop 2.2 in feature/transactional-deployment, draft PR. Never merge or publish a release until explicit maintainer approval and successful CI.
- Read this file and DEVELOPMENT.md at the start of every resumed session; inspect actual branch HEAD, PR and CI before edits. Update checkboxes and handoff in the same commit as substantive changes. Mark tests passed only from observed results.
- Do not commit real domains, configuration, credentials, private keys or production logs. Use synthetic fixtures. Keep strict 100% coverage gate; no artificial exclusions.
- Maintainer decision, 2026-11-24: defer all tests on a real VM or server until later. Continue independent development and automated tests; keep external acceptance pending rather than blocking unrelated roadmap work.

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
- [x] Review DNS recovery uniqueness and process lifetime, add regression tests for incomplete reconciliation and interrupted supervision, and define separate DNS/CGP staging acceptance evidence. See checkpoint 8 and docs/STAGING.md.
- [ ] Validate the new DNS path against disposable Cloudflare/ACME staging accounts and lab domains, including renewal migration, before RC/production use.
- [x] Detect unknown/manual certificate changes, block all subsequent domain mutations while any transaction remains pending, and keep pending snapshots outside backup pruning.
- [x] Complete ownership/permission validation for private state, lock, configuration, credentials, history, journals and existing backups. Reject unsafe paths before normal CLI/TUI/installer side effects; no automatic permission repair. See docs/STORAGE.md.
- [x] Implement operator-assisted resolution: exact-preview confirmation, private authorization/completion evidence, incomplete-decision guard and explicit retry without claiming TLS success. See docs/RESOLUTION.md and checkpoint 5 evidence below.
- [ ] Final review, 100% measured coverage, upgrade tests, docs, RC, production validation, approval.

Checkpoint 16 (`2.2.0.dev13`) implements the DNS provider interface with an
integrated Cloudflare adapter and explicit capabilities. Discovery, fixed
hooks/arguments, adaptive owned TXT lifecycle and installer credentials share
the adapter. Only Cloudflare is enabled; existing settings retain their meaning.
New schema-2 receipts bind their provider; schema 1 remains Cloudflare-only with
no automatic rewrite. Credential-path and token-rotation semantics, fixed-hook
legacy cleanup and public status fields remain compatible. Review fixed retained
fallback credentials after multi-account migration and isolated an entrypoint
test's process umask. Both complete local profiles pass **1478 tests / 7900
statements / 2568 branches / 100%**, with **51 additional tests** and zero
missing/partial/excluded paths. Static and documentation checks pass; current
implementation native CI is pending. See [provider contract](docs/DNS_PROVIDERS.md)
and DEVELOPMENT.md. Next is RFC2136 with its own ownership/recovery design and
isolated tests. All real provider, VM/server and signing acceptance stays deferred.

Previous Checkpoint 15 (`2.2.0.dev12`) implements explicitly approved application
replacement and independent recovery. The trusted runtime lives outside the
replaceable application; a persistent pending marker guards supported operations
before import and under their locks. Approval binds complete before/after file
inventories, package/trust identity, machine, configuration, executor and prior
receipt. Full preimages and same-filesystem rename slots support conservative
rollback after process death; candidate code and migrations are never executed.
Both timers remain stopped after apply/recovery and their enablement is preserved.
Recovery handles verified unit-file rename gaps after systemd cache loss and
failed guarded services only when no tracked process or retained cgroup exists.
Missing or administrator-modified baseline units refuse installation.
Both complete local profiles pass **1427 tests / 7793 statements / 2546 branches
/ 100%**, zero missing/partial/excluded, with **124 additional tests** including
20 fresh-process cases. Python/shell/workflow/documentation checks pass.
Implementation
[`8dba416`](https://github.com/alphazulu/cgp-certificate-manager/commit/8dba416938bbe17ed72cdab0d8830fe688e0e791)
passed [PR CI 45536468319](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45536468319),
all eleven jobs, and push CI 45536461992. Both native full profiles retain the
same counts; all installer combinations, complete audits, zero CodeQL findings,
native monitoring and reproducible packaging passed. This documentation-only
follow-up records that observed implementation run; inspect its own current-head
CI on resume. See DEVELOPMENT.md for evidence and continuation. The next independent
roadmap scope is DNS provider abstraction with Cloudflare compatibility and
isolated contract tests. All real VM/server/signing/production acceptance remains
deferred; no merge, release, signing key or real update is activated.

Previous checkpoint 14 (`2.2.0.dev11`) implements authenticated offline update checking
and preparation. `cgp-update` verifies domain-separated Ed25519 metadata against
separately provisioned trust, preserves per-channel rollback floors, checks the
exact deterministic archive and stages its validated files privately. Read-only
status rechecks trust, installed version, freshness and every staged file.
An unsigned publisher helper assembles signable metadata from reviewed release
provenance and archive bytes. The installer adds the command without creating
trust, updater state or a schedule. Code and unit tests are developed together;
both full coverage profiles and all eleven CI gates remain required.
Both complete local profiles pass **1303 tests / 6833 statements / 2350
branches / 100%**, with **104 new tests** and no missing/partial/excluded paths.
Review fixes have regressions for stage namespace replacement, descriptor
closure, expired-during-operation metadata and double-slash path overlap.
Implementation
[`82c5c63`](https://github.com/alphazulu/cgp-certificate-manager/commit/82c5c63f75a09b547193f939196a4c5c0ae0366c)
passed [CI 45523784100](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45523784100),
all eleven jobs, and push CI 45523774587. Both native full profiles retain the
same counts; all installer combinations, complete audits, zero CodeQL findings,
native monitoring and reproducible packaging passed. This documentation
follow-up records that observed implementation run; inspect its own current-head
CI on resume. Evidence and continuation are in DEVELOPMENT.md. `plan_id` is informational
and `apply_supported` is false. The next independent checkpoint is explicit
installation apply with full preimages, approval binding, shared locking and a
durable journal/recovery protocol; current shell rollback does not survive
arbitrary process death. Real VM/server/signing/update acceptance stays deferred.

Previous checkpoint 13 (`2.2.0.dev10`) implements optional Telegram and MQTT
notification channels in the existing explicit, durable lifecycle. The scope
includes private credential snapshots, bounded protocol acknowledgements,
per-channel outcomes, Telegram rate-limit persistence and MQTT QoS-1
non-retained event JSON. Code, unit/loopback tests and the
[channel guide](docs/NOTIFICATION_CHANNELS.md) are developed together without
new runtime dependencies. Both complete local profiles passed **1199 tests /
5979 statements / 2236 branches / 100%**, zero missing/partial/excluded, with
**59 new tests**. Review fixed an HTTP 2xx/API 429 response that initially lost
the provider retry interval. Implementation
[`5910bde`](https://github.com/alphazulu/cgp-certificate-manager/commit/5910bdea4e3d4a9052b39b635ccc21f4e53edf70)
passed [CI 45510870363](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45510870363),
all eleven jobs, and push CI 45510864744. Both native Python profiles retained
the same counts; all installer combinations, complete dependency audits, zero
CodeQL findings, native monitoring and reproducible packaging passed. This
follow-up records that observed implementation run; inspect its own exact-head
checks on resume. See DEVELOPMENT.md for evidence and continuation. Both
independent 100% coverage gates and all eleven CI jobs remain required. All
real VM/server/recipient/broker acceptance remains deferred. The next
independent scope after this checkpoint is authenticated, explicitly approved
updates; no update, schedule, destination, merge or release is activated here.

Previous checkpoint 12 (`2.2.0.dev9`) implements the independent external TLS monitor and
explicit SMTP/HTTPS webhook delivery. `cgp-monitor` has separate private config,
state and locking; it supports direct TLS and SMTP/IMAP/POP3 STARTTLS with trust,
SAN/name validation and bounded workers, including system DNS deadlines.
Notification intent is durable before sending; per-channel outcomes distinguish
accepted, rejected and uncertain, preserve retry IDs and recovery, and avoid
reusing old destinations after configuration changes. No secrets enter public
results or saved events. The optional timer invokes `--run` without `--send` and
is not enabled by installation. Installer locking, preservation and handled
rollback include the new wrapper/units and independent monitor state.
Both complete local profiles passed **1140 tests / 5665 statements / 2094 branches
/ 100%**, zero missing/partial/excluded, with **190 new tests**. Initial native CI
findings led to tested fixes for a fresh-import installer-fixture conflict and
explicit public-boolean output. Fixed implementation
[`102b007`](https://github.com/alphazulu/cgp-certificate-manager/commit/102b007e35b4bf4254b4e9aae991344bdd0d9a4d)
passed [CI 45422616787](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45422616787),
all eleven jobs: both full profiles with the same counts, all four installer
combinations with 36 unsafe-path refusals each, complete dependency audits,
native monitoring, zero CodeQL findings and reproducible packaging. This
follow-up records that observed implementation run; inspect its own exact
current-head checks on resume. See DEVELOPMENT.md for evidence and
docs/EXTERNAL_MONITORING.md for the contract. Optional Telegram/MQTT channels are
the next independent scope. Real VM/server/observer/receiver/systemd acceptance
remains deferred; no schedule, destination, merge or release has been activated.

Previous checkpoint 11 (`2.2.0.dev8`) implements the independent release-preparation and
security-scanning scope. New repository tools build deterministic source
archives with provenance, enforce complete dependency-audit evidence and check
CodeQL SARIF together with the native analysis outcome. The reusable CI now has
eleven jobs; package creation depends on both dependency profiles, all four
installer combinations, native monitoring checks and all three security jobs.
The manual release workflow requires an existing stable/RC tag on the default
branch, reuses that CI and prepares attestations plus an unpublished draft.
It creates no tags, overwrites no release and performs no production update.
Current dependency findings block; complete historical compatibility findings
remain explicitly informational. Missing or warning-bearing audit evidence
blocks both profiles, including a reproduced pip metadata omission regression.
Both complete local profiles passed **950 tests / 4507 statements / 1746 branches
/ 100%**, zero missing/partial, with 99 new tests. Fresh-cache PyPI audits were
complete: current 22/22 packages with zero findings; compatibility 23/23 with
23 records / 15 package-advisory-ID pairs across four historical dependencies.
Implementation
[`7cd8377`](https://github.com/alphazulu/cgp-certificate-manager/commit/7cd8377f114799a66a2b21cf9e8d16b6b20c970a)
passed [CI 45408950645](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45408950645),
all eleven jobs. Native CodeQL completed with one report/run, zero findings and
zero policy errors; native dependency audits reproduced the counts above.
Both complete test profiles retained the same 950 / 4507 / 1746 / 100% result.
All four installer combinations, native monitoring checks and deterministic
packaging/checksum/upload passed. This follow-up records that observed run;
inspect its own current-head checks on resume. See DEVELOPMENT.md and
docs/RELEASING.md for the evidence and contract. All real VM/server acceptance
and actual privileged release preparation remain deferred. The next independent
scope is separately scheduled external TLS probes and explicit notifications.

Previous checkpoint 10 (`2.2.0.dev7`) adds Prometheus alert rules, a Grafana
dashboard and a Zabbix 7.0 HTTP template with executable synthetic tests. All
three integrations distinguish source failure, missing data, stale/future
snapshots and local certificate expiry. CI gains a required monitoring-assets
job using pinned promtool; both Python jobs execute the JavaScript using pinned
Node.js. Package creation depends on the seven preceding checks; the workflow
has eight jobs. Both complete local
dependency profiles passed **851 tests / 3936 statements / 1566 branches / 100%**,
zero missing/partial, with 24 new Python tests and 105 executable JavaScript
scenarios. Detailed V8 coverage passed for all three preprocessing scripts.
Implementation
[`83ed7d9`](https://github.com/alphazulu/cgp-certificate-manager/commit/83ed7d9b5e2de568aaacd8cec8fc7ffdc68d2192)
passed [CI 45398683411](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45398683411):
both dependency profiles with the same counts, all four installer combinations,
native Prometheus engine validation (25 alert cases and 17 dashboard cases /
209 expressions), and package creation/checksum/upload. The template protects
against cached values after observations disappear and documents Zabbix's
whole-second native clock. This follow-up records the observed implementation
run; inspect its own current-head checks on resume. Real VM/server acceptance
remains deferred; no import, schedule or notification is enabled. The next
independent scope is release automation and dependency/security scanning.

Previous checkpoint 9 (`2.2.0.dev6`) implements the independent local monitoring foundation:
JSON snapshots, Prometheus text/atomic textfile publication and Zabbix domain
discovery. Unknown sources and measurements remain explicit, incomplete LLD
emits no list, and local expiry makes no claim about current deployed TLS.
Both complete local dependency profiles passed **827 tests / 3936 statements /
1566 branches / 100%**, zero missing/partial, with **87 new tests**. Python compile,
shell syntax, documentation and diff checks passed. Implementation
[`d997885`](https://github.com/alphazulu/cgp-certificate-manager/commit/d9978854ec309d74dce9482e34c5637a93f1c481)
passed [CI 45389786314](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45389786314):
both dependency profiles with the same counts, all four installer combinations
and package. The installer checks include installed monitoring, preservation
of private state/evidence and 24 unsafe-path refusals per combination. This
follow-up records that observed run; inspect its current-head checks on resume.
All real VM/server testing is deferred by
the maintainer's decision; continue independent monitoring/template/alert work.
See DEVELOPMENT.md for the next steps and docs/MONITORING.md for the contract.

Previous checkpoint 8 (`2.2.0.dev5`) addresses a reproduced incomplete-pagination recovery
defect, process/signal/descriptor review findings, and explicit staging selection
for manager dry-run despite a custom Certbot server setting, with tests
accompanying each change. The workflow now defines two dependency profiles, four
installer combinations (Ubuntu 24.04 / Debian 13 × baseline 2.0.1 / 2.1.0), and package,
using stable Node 24 Actions pinned by full commit SHA. CONTRIBUTING.md,
SECURITY.md and docs/STAGING.md record test commands, boundaries and exact
external acceptance cases. Both complete local profiles passed **740 tests /
3544 statements / 1430 branches / 100%**, with **14 additional tests** and zero
missing/partial. Python compile, shell syntax and diff checks passed. Implementation
[`4db1f90`](https://github.com/alphazulu/cgp-certificate-manager/commit/4db1f90bea3ec70d860c0fc59b0c881fd4d8a83b)
passed [CI 45385891519](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45385891519):
both dependency profiles with the same counts, all four installer combinations
and package. Every installer passed the installed metadata/procfs checks,
preservation/rollback scenarios and 24 unsafe-path refusals. This follow-up
records that observed run; check its own current-head CI when resuming.
DNS-only staging needs no live CGP, but still requires allocated lab zones and
credentials. Automatic bootstrap remains blocked.

Previous checkpoint 7 (`2.2.0.dev4`): **726 tests passed in each of two local dependency
profiles**, with **3511 statements / 1422 branches / 100%**, zero missing/partial.
There are **184 additional tests**. Read-only DNS diagnostics, two HTTPS
validators, actual parent referrals, CAA wildcard/account rules, opt-in adaptive
propagation, durable cleanup, real Certbot contracts and process-death tests are
implemented. Existing fixed-mode settings are preserved. Python compilation,
installer shell syntax and diff checks passed. Implementation
[`aabe70e`](https://github.com/alphazulu/cgp-certificate-manager/commit/aabe70ef841c4579349d28461e7cd06f755a146f)
passed [CI 45381705447](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45381705447):
both dependency profiles (the same 726 / 3511 / 1422 / 100%), both installer
baselines and package. Each installer
passed preservation checks for certificate journals, operator evidence and DNS
receipts, wrapper installation/rollback, invalid DNS settings and 24 unsafe-path
refusals. This follow-up records the observed implementation run; inspect its
own current-head checks when resuming.
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
Operator-assisted resolution was completed in checkpoint 5; checkpoint 16 is active above.
This remains a development checkpoint, not a production release.

## 2.3 — Monitoring
- [x] Read-only local monitoring snapshot, Prometheus textfile output and Zabbix domain discovery, with unit tests (checkpoint 9; observed validation above).
- [x] Zabbix template and Grafana dashboard with alerting based on explicit freshness and collection health, with actual preprocessing/rule/query tests (checkpoint 10; observed validation above).
- [x] Separately scheduled external TLS probes and explicit SMTP/HTTPS webhook delivery, with independent state, bounded workers and unit/loopback tests (checkpoint 12; current-revision CI evidence tracked above).
- [x] Optional Telegram/MQTT channels using the same explicit, durable notification lifecycle, with protocol-specific acknowledgement/uncertainty tests (checkpoint 13; exact-revision CI evidence tracked above).
- [ ] Real monitoring deployment acceptance on the later VM/server test session; local certificate observations must not be presented as live TLS verification.

## 2.4 — Updates

- [x] Define and implement canonical signed manifests, separate local trusted keys, project/channel/version/expiry checks and per-channel anti-rollback floors, with unit tests (checkpoint 14).
- [x] Inspect exact archive bytes, safely prepare a private source tree, persist an informational plan and revalidate saved status without executing candidate code (checkpoint 14; see docs/UPDATES.md).
- [x] Add the offline command to installer preservation/handled rollback and an unsigned publisher manifest assembler, with unit and container checks (checkpoint 14; observed evidence in DEVELOPMENT.md).
- [x] Implement explicit administrator-approved application replacement with complete preimages, bound approval, shared locks, durable phases, independent restart recovery and refusal of unknown/manual changes (checkpoint 15; both local profiles and all eleven implementation CI jobs passed, evidence above).
- [ ] Select and provision real signing/trust keys, decide rotation/revocation operations and separately authorize release-workflow signing integration. No keys are shipped or generated automatically.
- [ ] Perform deferred real VM/server update, interruption/recovery and trust-rotation acceptance before RC/production use.

## 2.5 — DNS providers
- [x] Provider abstraction and integrated Cloudflare compatibility, with explicit capabilities, provider-bound receipts and isolated contract tests (checkpoint 16; both complete local 100% gates passed, native CI pending).
- [ ] RFC2136 backend with its own ownership/recovery design and isolated tests.
- [ ] PowerDNS, Route53, acme-dns and manual workflow, each with explicit capability and credential boundaries.
- [ ] Real provider acceptance in the later separately scoped test session.

## 3.0 — Multi-server administration
Separate server identities, least privilege, centralized visibility, independent transactions.

## Repository maintenance
- [ ] License decision by owner; do not assume permission.
- [x] SECURITY.md and CONTRIBUTING.md with actual reporting/trust boundaries and isolated test commands.
- [x] Release preparation automation and dependency/source-security scanning, with strict helper/workflow tests and observed native CI (checkpoint 11; evidence above).
- [ ] Execute the manual attestation/draft workflow on a separately approved eligible release tag, inspect provenance and retained artifacts, and obtain publication approval.
- [x] Verify the expanded installer CI matrix on Ubuntu 24.04 and Debian 13 for both upgrade baselines; container checks do not establish full deployment support.
- [x] Refresh GitHub Actions to verified stable Node 24 revisions pinned by commit SHA; retain both strict dependency profiles and all upgrade baselines.
