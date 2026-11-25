# Changelog

## 2.2.0.dev14 — unreleased

- Add an opt-in adaptive RFC2136 provider using explicit primary/zone/key configuration and the existing dnspython dependency. Keep Cloudflare defaults, fixed routes and legacy receipt schemas compatible; refuse RFC fixed hooks and Cloudflare-specific wizard editing before side effects.
- Validate private bounded TSIG secret JSON and pure target identities. Bind schema-2 receipts to zone, primary IP/port, key name/algorithm and credential path without freezing rotating secret contents. Preserve read-only status fields and all-ledger validation before cleanup.
- Authenticate TCP queries and updates with HMAC-SHA256, including an explicit signed-response guard for the compatibility library. Use exact raw TXT RRset prerequisites, alias/delegation guards, nonce ownership and a persistent changing generation marker; retain foreign values and prevent old signed updates from matching a restored preimage.
- Keep remote error responses and lost acknowledgements uncertain. Reconcile the exact owned pair, never blindly replay creation, and require a prerequisite-only update before retiring a previously created pair observed absent. Check metadata count/byte headroom before writes and refuse malformed or lost generation state.
- Add pure configuration, signed-wire, actual loopback TCP, public-flow, binding and fresh-process tests alongside the implementation. Preserve both strict 100% coverage profiles and all native CI gates; exact observed evidence is in DEVELOPMENT.md and ROADMAP.md.
- Document explicit activation, persistent DNS metadata, unsupported modes and deferred real provider/ACME/VM/server acceptance. No new production key, timer, merge, tag, release or deployment is activated.

## 2.2.0.dev13 — unreleased

- Add a static DNS provider interface and integrated Cloudflare adapter with explicit discovery, fixed-native, fixed-hook and owned-TXT capabilities. Route discovery, Certbot arguments/hooks, adaptive lifecycle and installer credential checks through it without adding dependencies or enabling another backend.
- Preserve implicit Cloudflare selection, configured account precedence, native Certbot arguments, fixed delay, fixed-hook cleanup compatibility and existing public diagnostic/status fields. Reject unsupported selectors and mismatched provider bindings before credential use or remote mutation.
- Write adaptive receipt schema 2 with an explicit provider. Keep schema 1 permanently Cloudflare-only and readable without migration. Validate the complete ledger before cleanup; retain exact ownership, uncertainty, borrowed-record and complete-list absence rules. Preserve token rotation at the same configured credential path without claiming a credential-content or remote-account snapshot.
- Add contract, integration, configuration, installer, UI, legacy-receipt and fresh-process tests alongside the implementation. Keep both complete 100% coverage gates and all native CI jobs; observed results and the next checkpoint are recorded in DEVELOPMENT.md and ROADMAP.md.
- Document the provider extension boundary and separate RFC2136 ownership/recovery work. All real VM/server/provider and production acceptance remains deferred; no merge, release or live DNS operation is activated.

## 2.2.0.dev12 — unreleased

- Add explicit `cgp-update --review`, `--apply --confirm-update TOKEN` and `--recover`. Bind approval to the signed package, full installed preimages, trusted executor, preserved configuration, machine and prior receipt. Recheck freshness, trust, staged bytes and installation state before replacement; old preparation IDs remain informational.
- Install the update runtime and pre-import guard outside the replaceable application. Keep a durable pending marker through interruption and restart; serialize manager, monitor and updater operations. Preserve the manager lock in fixed Certbot children and guard direct timer operations.
- Save bounded, complete filesystem inventories and private content-addressed preimages. Use same-filesystem rename slots with directory synchronization, durable phases, full readback and explicit rollback-only recovery. Refuse unknown/manual state before restoration, retain uncertain and orphan evidence, and independently verify every backup.
- Apply only the declared layout-1, configuration-schema-2 data payload. Never execute candidate installers, migration hooks or version commands. Preserve adjacent application files, credentials, manager/monitor recovery evidence, Certbot state and independent update runtime; restore absence, bytes, ownership, modes and modification times on rollback. Unsupported links, special files, cross-device trees and extended metadata are refused.
- Verify managed systemd fragments/drop-ins, stop both timers before replacement and leave them stopped after apply or recovery, preserving enablement. Freshness is checked again after quiescence. Add process-death, recovery, integration and policy tests alongside the implementation; keep both strict 100% gates and every CI job.
- Refuse missing or administrator-modified baseline unit files before installation. During recovery, handle verified rename gaps after systemd cache loss and guarded services left failed after restart; require zero tracked PIDs and no retained cgroup, preserve failure status, and revalidate every restored unit. Cover these cases with fresh-process regressions.
- Keep real VM/server, signing/trust provisioning, merge, privileged release and production update acceptance deferred. DEVELOPMENT.md and ROADMAP.md record observed validation and the exact continuation point.

## 2.2.0.dev11 — unreleased

- Add offline `cgp-update --check`, `--prepare` and `--status` for an authenticated preparation plan. Ed25519 verification uses separately provisioned private local trust, a canonical domain-separated manifest, strict project/channel/version/expiry checks and persistent per-channel anti-rollback floors.
- Bind the exact archive size and SHA-256 before bounded decompression. Accept only the deterministic source format, reject unsafe paths/types/headers and conflicting entries, and validate application/plugin version metadata without importing candidate code. Stage files through private descriptor-based writes and recheck their exact inventory on status.
- Save the signed manifest, trust/baseline identities, inventory and floor atomically under a separate updater lock. Keep check/status read-only, preserve floors across key rotation, refuse changed configuration or expired metadata, reuse an unchanged valid preparation and retain uncertain/orphan stages for explicit inspection.
- Add an unsigned manifest assembler for reviewed release provenance and archive bytes. It creates no signing keys, signatures, trust roots, tags or releases; production signing is not wired into the release workflow.
- Install the `cgp-update` wrapper with handled rollback and native container regressions, without creating updater trust/state or a schedule. Add unit tests alongside all new code and document exact limits. `plan_id` is informational; installation apply, approval binding and crash-safe recovery remain a separate next checkpoint.
- Keep both strict coverage profiles and all CI gates. Real VM/server, signing and update acceptance remain deferred; exact observed evidence is recorded in DEVELOPMENT.md.

## 2.2.0.dev10 — unreleased

- Add optional Telegram Bot API and MQTT 3.1.1 channels to the independent monitor, with private credential snapshots and no new runtime dependencies. Explicit enabled policy, enabled channel and `--run --send` remain required.
- Send one plaintext Telegram message with the stable event ID and all endpoint summaries; validate a bounded, completely framed JSON acknowledgement. Preserve explicit refusal, rate limits, malformed replies and uncertain submission without exposing tokens or raw API errors.
- Honor valid Telegram retry hints using the existing persisted retry deadline. The channel cooldown survives restart and changed observations, including recovery; other channels proceed independently. Public output and schema-1 checkpoint fields remain unchanged.
- Publish MQTT event JSON once at QoS 1 without retention, over verified TLS by default. Require valid CONNACK and matching PUBACK, bound protocol I/O and retain uncertainty after possible submission. Use a fresh client ID and CleanSession; subscriber deduplication is based on event ID, and broker acknowledgement does not prove authorization or recipient delivery.
- Add protocol and cross-channel unit tests together with the implementation, disabled examples and operational documentation. Exact local and native-CI results are recorded in DEVELOPMENT.md. Real Telegram/MQTT, VM/server and production acceptance remains deferred.

## 2.2.0.dev9 — unreleased

- Add an independent `cgp-monitor` command with separate private configuration, state and operation lock. Validate settings, perform read-only probes, inspect saved freshness or explicitly record observations without using CGP, Certbot lineages or provider credentials.
- Observe direct TLS and SMTP/IMAP/POP3 STARTTLS with required trust and SAN/name validation, TLS 1.2+, bounded protocol parsing and a supervised worker deadline covering system DNS. Retain unknown certificate measurements on verification failure.
- Add explicitly configured SMTP and HTTPS webhook channels. Persist each send intent before networking; distinguish accepted, rejected and uncertain outcomes; retry the same event ID, suppress duplicate acknowledgements per channel and record recovery. Configuration changes start a new baseline and retain one previous generation without retrying old destinations.
- Add an optional monitor service/timer, disabled by installation and configured without `--send`. Include both operation locks, the wrapper and units in installer preflight/preservation/handled rollback; leave both timers stopped after successful installation.
- Refuse truncated SMTP/HTTP acknowledgements, preserve pending-delivery failure during observation-only runs, reject clock rollback between preflight and observation, and prevent an installed custom-state run from bypassing the installer lock. Add regression tests with each review fix.
- Preserve real SMTP classes in the installer harness while blocking their constructors; reproduce its exact fresh-import path in a regression. Explicitly project public configuration flags to booleans after a native CodeQL output-flow finding, with private SMTP/webhook input tests and unchanged security gates.
- Add 190 tests, including real loopback TLS/STARTTLS/SMTP/HTTPS, process-death/lock/deadline cases, state fault injection and installer contracts. Both complete local profiles pass 1140 tests, 5665 statements and 2094 branches at 100%; exact revision CI evidence is recorded in DEVELOPMENT.md.
- Document explicit activation and deferred real-environment acceptance. Optional Telegram/MQTT channels remain separate roadmap work; no new schedule, destination, release or production deployment is activated.

## 2.2.0.dev8 — unreleased

- Add a deterministic source-archive builder with safe version/metadata parsing, exact commit/tree provenance, existing-tag checks, default-branch ancestry checks and refusal of unsafe entries or overwrites. Test the builder with real temporary Git repositories.
- Add complete-inventory dependency auditing with pinned pip-audit and explicit current/compatibility policies. Current findings block packaging; historical compatibility findings stay visible. Missing, skipped, malformed or failed audits block both profiles. Update isolated bootstrap pip to verified 26.3.
- Add CodeQL Python analysis and a tested SARIF gate that refuses findings and incomplete reports. Preserve raw scanner reports and summaries as CI artifacts; expand the strict coverage source to include repository tooling.
- Reuse the complete CI for manual release-tag preparation, reproduce archive bytes before upload, attest artifact provenance and prepare an unpublished GitHub draft. Do not create tags, overwrite an existing release or publish automatically.
- Keep real VM/server acceptance, release authorization and production deployment separate. Record exact observed validation and continuation in DEVELOPMENT.md and ROADMAP.md.

## 2.2.0.dev7 — unreleased

- Add optional Prometheus alert rules, a Grafana classic dashboard and a Zabbix 7.0 HTTP template for local monitoring. Keep collection failure, missing data, stale/future snapshots and local certificate state distinct; do not imply current deployed TLS health.
- Add native promtool timelines and dashboard-query checks, executed Zabbix preprocessing tests and Python asset-contract tests. Keep the existing independent 100% Python coverage gates; require the new monitoring-assets CI job before packaging.
- Select Prometheus targets explicitly with `cgp_manager="true"`; preserve incomplete-discovery refusal and disabled-domain semantics. No new privileged agent command, monitoring schedule or notification destination is installed.
- Document artifact formats, thresholds, interpretation and later deployment steps. Real VM/server tests remain deferred; exact observed validation and continuation are recorded in DEVELOPMENT.md and ROADMAP.md.

## 2.2.0.dev6 — unreleased

- Add offline `--monitoring` JSON, Prometheus `--metrics` and Zabbix `--zabbix-discovery`, with unit tests for source failures, missing measurements and no private-data output. Read saved manager state under an existing nonblocking shared lock; do not create state, contact services or perform recovery.
- Observe only the public local leaf certificate through a bounded, validated path. Keep absent, unreadable and expired certificates distinct, and never present local expiry or a saved success timestamp as current deployed TLS verification.
- Add explicit `--metrics-file` atomic publication of readable metadata to a trusted existing directory. Refuse private/unsafe targets, publish collection failure metrics instead of retaining healthy-looking output, and cover publication failure paths with unit tests.
- Keep incomplete Zabbix collections from becoming empty discovery arrays. Document metric meanings, freshness, retained-artifact counts, path permissions and integration limits in docs/MONITORING.md.
- Record the maintainer's decision to defer all real VM/server tests while independent development and isolated automated validation continue. Keep external acceptance and automatic bootstrap prerequisites pending. Exact observed coverage and CI are recorded in DEVELOPMENT.md.
- Both complete local dependency profiles passed 827 tests, 3936 statements and 1566 branches at 100%, including 87 new tests and no missing/partial paths. Python compilation, shell syntax, documentation and diff checks passed; current-revision CI is recorded separately after execution.

## 2.2.0.dev5 — unreleased

- Require a complete, stable provider listing with unique valid record IDs before reconciling an uncertain TXT creation. Inconsistent or truncated pagination retains the intent without deleting a record or retiring its receipt; add regression tests with the fix.
- Harden the adaptive Certbot supervisor against SIGINT/SIGTERM during process creation and repeated interruption during shutdown. Require evidence of an existing exclusive lock on the supplied descriptor, with real subprocess/lock regressions and fail-closed Linux procfs checks.
- Make manager `--dry-run` explicitly select the Let's Encrypt staging directory, including when Certbot's global configuration specifies another server. Test both authenticator paths and actual argument parsing; standalone wrapper commands keep their explicit server semantics.
- Pin GitHub Actions to reviewed stable Node 24 revisions and extend installer CI to Ubuntu 24.04 and Debian 13 for both upgrade baselines. Preserve both dependency profiles and the strict 100% statement/branch gate; exact observed CI results are recorded in DEVELOPMENT.md.
- Keep app-local Certbot metadata and the manager version consistent, checked by the real discovery test.
- Add CONTRIBUTING.md, SECURITY.md and a separate DNS/CGP staging acceptance plan with explicit pending external evidence. Update the roadmap and continuation notes; automatic bootstrap and production release remain separate open steps.
- Both complete local dependency profiles passed 740 tests, 3544 statements and 1430 branches at 100%, with 14 additional tests and no missing/partial paths. Python compilation, shell syntax and diff checks passed; exact CI evidence is recorded in DEVELOPMENT.md after execution.

## 2.2.0.dev4 — unreleased

- Add read-only `--dns-check`, including Let's Encrypt CAA parent/alias/wildcard policy, explicit DNSSEC evidence from two HTTPS validators and actual parent/child/challenge delegation checks. Refuse ambiguous, unavailable or conflicting identifiers before Certbot.
- Parse bounded DNS wire messages with protected HTTPS, absolute request deadlines, public authoritative TCP endpoints and strict identity/flag/class/singleton checks. Keep AD assertions separate from local validation and do not label every SERVFAIL as DNSSEC-bogus.
- Add opt-in adaptive propagation with a proper `cgp-dns` Certbot authenticator: create the current batch, require all expected TXT values in two fresh complete observer passes, and abort before ACME answer on failure. Preserve legacy fixed delay and renewal settings.
- Record durable, server-bound TXT ownership before creation; borrow pre-existing records without deleting them, recover uncertain responses by exact markers, recheck identity before deletion, and retain unresolved/changed/foreign evidence. Add `--dns-transactions` and locked `--dns-cleanup`.
- Supervise adaptive Certbot under a verified inherited operation lock and separate process group, with closed stdin and bounded TERM/KILL handling. Perform final cleanup only after group quiescence. Install an app-local plugin and `cgp-certbot` standalone wrapper with installer rollback.
- Add unit tests with all implementation changes, actual Certbot authorization/entry-point regressions, wire/loopback HTTPS tests, subprocess crash fixtures and installer receipt preservation. Test compatibility/current dependencies independently while retaining the strict 100% statements/branches gate. Exact observed counts and CI are recorded in DEVELOPMENT.md.
- Document trust assumptions, configuration, dependency requirements, renewal compatibility and remaining operational limits in [docs/DNS.md](docs/DNS.md), with English/Russian README guidance. No merge, release, production deployment or automatic bootstrap is enabled by this checkpoint.
- Complete local validation: 726 tests in both compatibility/current dependency profiles, 3511 measured statements and 1422 branches at 100%, with zero missing/partial. Python compile, shell syntax and diff checks passed. Exact implementation CI evidence is tracked separately in DEVELOPMENT.md.

## 2.2.0.dev3 — unreleased

- Add `--bootstrap-check [--domain DOMAIN] [--json]` with private-key-free field provenance, completeness and refusal reports. It reads only configuration and CGP, with no state/lock creation, fsync, Cloudflare, Certbot, recovery or notification.
- Parse complete bounded CGP objects instead of extracting certificate fields with a regular expression. Reject duplicate keys, malformed/truncated replies, trailing content, unsupported values and excessive input; ignore field-like text inside strings or nested objects. Cap HTTP response acquisition before decoding.
- Compare repeated explicit/effective certificate projections. Require complete, explicit, nonempty supported snapshots before ordinary issuance, installation, manual rollback and plan/doctor results; force/retry/shrink flags do not bypass the gate. Preserve status/TLS inspection and staging-only dry-run behavior.
- Repeat provenance checks around durable preparation, the applying transition, readback and TLS. Retain pending evidence without effective-only automatic recovery if readiness is lost; also guard recovery after other in-process failures. Existing schema-2 standalone recovery and operator evidence keep their original semantics.
- Keep expiry, cryptographic checks and TLS separate from structural readiness. Add unit/integration tests with synthetic CGP responses and a real expired-certificate fixture together with implementation. Automatic bootstrap stays disabled pending a field-specific write/restore contract on a disposable CGP instance.
- Document the report, compatibility limits, vendor evidence and required lab experiments in [docs/BOOTSTRAP.md](docs/BOOTSTRAP.md). Exact observed test and CI evidence is recorded in DEVELOPMENT.md.
- Complete local validation: 542 tests, 2434 measured statements and 1012 branches at 100%, with Python compile, shell syntax and diff checks passing. CI execution evidence is tracked separately in DEVELOPMENT.md.

## 2.2.0.dev2 — unreleased

- Add explicit `--acknowledge-restored --domain` preview and exact-token/reason confirmation for previous settings that cannot pass TLS verification. Limit it to `prepared`/`restoring` with matching server identity and all four previous CGP fields; refuse unknown states and stale journal instances.
- Preserve full original evidence in private authorization and completion records. Keep incomplete acknowledgements globally blocking even after the pending journal has been removed; only explicit retry can complete them. Resynchronize existing completed evidence before permitting later mutations.
- Report `acknowledged_unverified` without CGP writes, ACME calls or a TLS-success claim. Bind confirmation to the complete schema-2 journal and securely opened file identity; refuse replay against another transaction.
- Expose the same procedure in domain actions and F9, including domains absent from normal discovery. Add unit, cross-module and process-death coverage together with implementation, plus installer preservation/refusal checks for audit records.
- Document commands, crash semantics, audit confidentiality and remaining limits in [docs/RESOLUTION.md](docs/RESOLUTION.md). Exact observed test and CI results are recorded in DEVELOPMENT.md.
- Complete local validation: 455 tests, 2073 measured statements and 844 branches at 100%; Python compile, shell syntax and diff checks passed. Includes 11 new acknowledgement process-death/restart tests and an actual expired-certificate regression. Container CI evidence is tracked separately in DEVELOPMENT.md.

## 2.2.0.dev1 — unreleased

- Add shared descriptor-based private storage validation for configuration, Cloudflare credentials, state, history, backups and transaction journals. Require effective-UID ownership, private mode limits, regular files and a single hard link; refuse symlinks and unsafe ancestor paths.
- Accept trusted configuration parents with mode `0755` while keeping private state directories at `0700` or stricter and files at `0600` or stricter. Refuse unsafe existing objects without automatic `chmod` or `chown`.
- Validate the state tree under the operation lock before CLI side effects, and check credential files before issuance. Use secure reads, appends and atomic saves in CLI, journal and configuration workflows.
- Run installer preflight before timer or application changes and retain the same validated lock descriptor through the shell payload and handled rollback.
- Report unsafe console history and configuration access errors explicitly. Keep standard Certbot `live` symlinks outside the private-storage rules.
- Document the exact policy and limits in [docs/STORAGE.md](docs/STORAGE.md), including metadata-only diagnostics and the absence of protection against concurrent root/same-UID modification or installer power loss.
- Local and [CI 45367278665](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45367278665) validation: 386 tests, 1,742 statements and 692 branches at 100% coverage; Python compilation, shell syntax and diff checks passed. Both Docker installer baselines, including 18 new refusal cases each, and packaging passed for implementation commit `d2bad6e`. Development artifacts identify themselves as `2.2.0.dev1`.

## 2.2.0.dev0 — unreleased

- Route certificate deployment and manual backup restoration through a durable per-domain transaction journal under the existing global operation lock.
- Record previous and intended settings with separate TLS endpoints before remote writes; bind recovery to the local machine and configured CGP CLI endpoint.
- Recover interrupted work before normal certificate operations. Refuse unknown CGP state and block further domain changes while any transaction is unresolved.
- Verify the recorded key, leaf and complete CA chain, including live TLS, independently of mutable Certbot files. Retain unresolved journals after failed restoration or verification.
- Add read-only `--transactions`, explicit `--recover`, scoped domain actions and a global F9 console menu with recovery confirmation.
- Add fault-injection unit tests, fresh-process crash/recovery tests and real OpenSSL/loopback TLS tests. Keep the 100% statement/branch coverage gate.
- Test installer upgrades from both stable 2.0.1 and 2.1.0, including preservation of pending transaction journals. Development artifacts identify themselves as `2.2.0.dev0`.

## 2.1.0

- Optional whiptail setup and curses administration console with shared Russian/English navigation, domain details, TLS verification, sorting, filters, history, backup selection and timer controls.
- Explicit domain opt-in for new interactive installations, staged credentials and atomic configuration save.
- Configurable TLS endpoints, SMTP notifications and twice-daily renewal schedule.
- Validate rollback backup PKI, key matching, DER chain and trust before writes; improve recovery on handled errors and interruption.
- Serialize configuration loading and installation with the global lock; restore previous application, configuration and units on handled upgrade failures.
- Keep read-only diagnostics free from notification and state writes; preserve failure rows and invalidate stale TLS results.
- 188 unit tests, strict 100% line/branch coverage gate, isolated installer integration checks against 2.0.1.

## 2.0.1

- Correct PKI activation with CertificateType=YES.
- Multi-certificate CAChain encoded as concatenated DER in one Base64 DataBlock.
- Compare all certificate settings and verify readback after deployment.
- Verify complete ordered TLS chain and hostname over HTTPS/SNI.
- Verify aliases and discover CGServer listeners.
- Attempt rollback and verify restored settings.
- Separate issuance and deployment retry delays; add retry and reset commands.
- Improve status output and clear stale alerts on success.
