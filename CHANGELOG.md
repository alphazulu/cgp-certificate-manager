# Changelog

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
