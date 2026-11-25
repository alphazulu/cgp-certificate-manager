# Development checkpoint

Updated 2026-11-25 (Asia/Vladivostok). Branch feature/transactional-deployment; stable base v2.1.0 (fffbeda39a6adbb1c7ab8e924f4ec2c0089a2a5f).

## Current handoff — checkpoint 16 (implementation and local gates passed)

- Development version **`2.2.0.dev13`**, feature branch and draft PR #2. Starting
  clean HEAD `9ba0915bc02c33b9fe5b0982457d982165bab303`, tree
  `d2db699847d248af8ba806fac7c06968e97f6356`. Stable main remains
  `fffbeda39a6adbb1c7ab8e924f4ec2c0089a2a5f` (`2.1.0`). Starting-head PR CI
  45537062889 and push CI 45537056001 passed all eleven jobs; those runs belong
  to checkpoint 15 and are not evidence for this implementation.
- Implemented the 2.5 provider interface and integrated Cloudflare adapter.
  **Only Cloudflare is enabled**; missing `dns_provider` retains its legacy
  meaning. Selection is static and pure. Unknown or malformed selectors refuse
  provider routes before credential access or API use. No dependencies added.
- Routed zone discovery, fixed native Certbot arguments, fixed manual hooks,
  adaptive owned TXT operations and installer credential validation through
  explicit `zone_discovery`, `fixed_native`, `fixed_hooks`, `owned_txt`
  capabilities. Required capabilities and source-zone provider bindings are
  checked before credential reads, preflight or process creation.
- Kept discovery map and pagination behavior, first-account precedence, fixed
  delays, command structure, diagnostic/status fields, exact TXT matching,
  borrowed records, uncertainty handling and complete-list absence proof.
  Cloudflare wire/ID/ownership/pagination logic lives in `dnsproviders.py`;
  `dnsauth` retains the durable generic receipt state machine. HTTP error
  streams close and fixed provider errors do not expose raw responses.
- New adaptive schema-2 receipts explicitly name Cloudflare. Schema 1 always
  means Cloudflare and is readable/cleanable without schema migration. The
  complete ledger is validated before any remote deletion. Credential-path,
  zone, CGP server identity, owner marker and record-ID checks remain intact.
  Token bytes are not fingerprinted; rotation at the same configured path
  remains supported. No inferred or frozen remote-account identity is claimed.
- New fixed-hook metadata names Cloudflare; legacy three-field metadata still
  works. Review caught and fixed a compatibility edge: fixed cleanup continues
  accepting a retained `cloudflare_credentials` fallback after migration to
  `cloudflare_accounts`, while discovery/new authentication/adaptive cleanup
  retain active-account precedence. Regression tests cover both metadata forms.
- Read-only receipt status retains exactly `id`, `name`, `phase`, `owned`,
  `zone`, with no credential-content reads or receipt writes. Independent
  review checked mixed schema-1/schema-2 monitoring after credential removal;
  unsupported selection produces an unknown count/source error without mutation.
- Added **51 tests** alongside code, including adapter contracts, route and
  capability refusals, configuration/UI/installer paths, provider/receipt
  mismatch, legacy recovery and a fresh-process legacy intent case. Fixed a
  test-only process umask leak with scoped mocking; production hardening is
  unchanged. The seven affected tests and both complete suites pass afterward.
- Updated English/Russian README, example configuration, changelog, DNS and
  security documentation. [DNS_PROVIDERS.md](docs/DNS_PROVIDERS.md) defines the
  contract and future backend boundary. Neither the fixed hooks nor schema 2
  gain a remote compare-and-swap or a credential-content snapshot.

### Observed local validation — checkpoint 16

Both complete dependency profiles independently pass **1478 tests / 7900
statements / 2568 branches / 100%**. Missing statements, missing/partial branches
and excluded lines are all zero; each `--fail-under=100` gate passes without
relaxation. Compatibility took **50.089 s**, current **49.186 s**, on Python
**3.12.14**. The adapter itself covers **167 statements / 62 branches / 100%**.

The complete profile commands use the independently provisioned environments:

```bash
COVERAGE_FILE=.coverage.cp16.compat /workspace/scratch/cf31ba780290/cgp-compat-env/bin/python -m coverage run --branch --source=cgp_cert_manager,repo_tools -m unittest discover -s tests -v
COVERAGE_FILE=.coverage.cp16.compat /workspace/scratch/cf31ba780290/cgp-compat-env/bin/python -m coverage report -m --fail-under=100
COVERAGE_FILE=.coverage.cp16.current /workspace/scratch/cf31ba780290/cgp-current-env/bin/python -m coverage run --branch --source=cgp_cert_manager,repo_tools -m unittest discover -s tests -v
COVERAGE_FILE=.coverage.cp16.current /workspace/scratch/cf31ba780290/cgp-current-env/bin/python -m coverage report -m --fail-under=100
```

Evidence logs and independent coverage JSON reports are in
`/workspace/scratch/9e49bdf23b66/cp16-full-{compat,current}.log` and
`/workspace/scratch/9e49bdf23b66/cp16-coverage-{compat,current}.json`; these are
local transient evidence, not required repository inputs. Python source
compilation, three shell entrypoints, all **21 workflow shell blocks**, Markdown
relative links and shell examples, version/plugin metadata, the explicit-provider
example and `git diff --check` passed. Native CI is still pending for this
implementation and must be recorded only after observation.

### Resume checkpoint 16

1. Inspect actual HEAD/tree, draft PR #2 and current-revision CI; preserve any
   worktree changes. Publish this tested implementation and inspect all eleven
   native jobs, including both full coverage profiles, four installer cases,
   both dependency audits, CodeQL, monitoring assets and reproducible packaging.
2. Record exact implementation commit, run IDs and observed native evidence in
   this file, ROADMAP.md and draft PR #2. Publish the handoff follow-up and inspect
   its own CI before declaring the checkpoint complete.
3. Next independent scope is RFC2136: define credentials, explicit zone identity,
   supported routes and its own ownership/recovery evidence before enabling it.
   Add meaningful unit/process tests with every path and preserve both 100% gates.
4. All real VM/server/provider/recipient/broker/signing acceptance remains
   deferred. Do not select production keys, merge, tag, release, deploy or run
   real provider mutations. Automatic CGP bootstrap stays blocked on its separate
   external restoration/deletion evidence.

## Previous handoff — checkpoint 15 (implementation and native CI passed)

- Development version **`2.2.0.dev12`** in draft PR #2, branch
  `feature/transactional-deployment`. This resumes and finishes the prior
  session's uncommitted implementation from starting HEAD
  `eedb690014a37891a4ef50c2ae9ca0c1b0e8500d`, tree
  `54afa33399a64fd292f91898d7a2a6230b811d2e`.
- Starting-head PR CI 45525009407 and push CI 45525001948 passed all eleven
  jobs. Their **1303 / 6833 / 2350 / 100%** result belongs to checkpoint 14;
  it is not evidence for this implementation. The new local evidence is below.
- Implemented scope: data-only application apply with exact review approval,
  complete installed preimages, durable journal, explicit conservative recovery,
  independent trusted runtime, persistent operation guard, coordinated locks,
  unit/process tests, documentation and GitHub plan/handoff updates.
- Fixed production layout: `/opt/cgp-certificate-manager`, independent
  `/opt/cgp-update-runtime`, and `/var/lib/cgp-update`. Tests inject an isolated
  Layout internally; there is no environment or CLI bypass for installed apply.
  The ordinary trusted installer bootstraps runtime and guard-capable launchers;
  this transaction never replaces its own runtime or update launcher.
- Lock order is manager -> monitor -> updater, noncreating/nonblocking for
  review/apply/recovery. Normal guards read the fixed marker without acquiring
  updater locks. A durable marker precedes timer and application changes and
  survives restart; entrypoint guards run before application imports and again
  under operation locks. Fixed-mode Certbot children retain the manager lock;
  direct console timer changes acquire it and check the pending guard.
- `update_files.py` implements bounded full snapshots, content-addressed private
  backups and same-filesystem rename slots. Explicit absence, empty directories,
  all bytes, owners/groups, modes and modification times are preserved. Links,
  special files, hardlinks, cross-device descendants and xattrs/ACLs/capabilities
  are unsupported and refused. Uncertain backup/slot evidence is not pruned.
- `update_apply.py` binds signed package/trust, whole before/after inventories,
  executor, machine, preserved configuration and prior receipt into a separate
  domain-separated confirmation token. It requires the declared layout-1/schema-2
  payload and trusted launcher/unit templates, performs no migration, and never
  executes candidate code. All targets/backups are checked before rollback;
  unknown/manual state refuses restoration. Status/recovery do not need the
  original archive, fresh trust/signature, prepared stage or importable app.
- Both timers are stopped and verified, with no automatic starts or enablement
  changes. Effective unit fragments/drop-ins are restricted to the managed
  layout. Configuration, Certbot data, manager/monitor evidence and independent
  runtime remain outside application rollback. Timers can activate after reboot
  while pending, but managed entrypoints refuse application execution.
- Recovery now permits a unit absent in a verified rename gap to be reported
  `not-found` after systemd cache loss. Only that exact absent managed target
  is allowed, and only unloaded timers are omitted from `stop`; final reload
  requires every unit loaded from its expected path. A guarded service left
  `failed` is accepted only with zero MainPID/ControlPID and no ControlGroup.
  Residual processes/cgroups prevent restoration. Failure state is preserved;
  no `reset-failed`, start or enable is issued. Normal review/apply remain strict.
- Review fixes include stage prefix/root ordering, unknown-state preflight,
  expiry during backup/quiescence, global readback around reload/commit,
  resynchronizing an uncertain terminal receipt before clearing the marker,
  JSON-null and lost-pointer replay protection, reboot/cache-loss recovery and
  strict refusal of missing/modified baseline unit files. Safe unit modes may
  be normalized with exact rollback. Every fix has a regression.

### Observed local validation

Both complete profiles independently pass **1427 tests / 7793 statements /
2546 branches / 100%**, with **124 additional tests** relative to checkpoint 14.
There are zero missing statements, missing/partial branches or excluded lines.
Each independent `--fail-under=100` gate covers `cgp_cert_manager,repo_tools`.
Python is **3.12.14**, Node is **24.22.3**, and every explicitly pinned dependency
matches its profile. Compatibility took **47.858 s**; current **47.047 s**.

The complete commands, using the already provisioned isolated environments, were:

```sh
COVERAGE_FILE=.coverage.final15.compat ../cgp-compat-env/bin/python -m coverage run --branch --source=cgp_cert_manager,repo_tools -m unittest discover -s tests -v
COVERAGE_FILE=.coverage.final15.compat ../cgp-compat-env/bin/python -m coverage report -m --fail-under=100
COVERAGE_FILE=.coverage.final15.current ../cgp-current-env/bin/python -m coverage run --branch --source=cgp_cert_manager,repo_tools -m unittest discover -s tests -v
COVERAGE_FILE=.coverage.final15.current ../cgp-current-env/bin/python -m coverage report -m --fail-under=100
```

The process suite contains **20 tests** using real fresh Python processes,
`SIGKILL`/abrupt exit, private temporary trees and a bounded local systemctl
stub. It covers every changed target's rename boundaries, interruption during
rollback, terminal-marker clearance, four unit-cache-loss cases after restart,
failed guarded services, and refusal of tracked/residual processes before undo.
It removes original trust/artifacts/prepared state and forbids crypto imports
during recovery. Backups, preserved configuration/evidence and timer enablement
remain unchanged. These tests model process crashes and systemd observations;
they do not boot a real VM or establish physical power-loss recovery.

Python compilation, all three installer shell scripts, all **21 workflow run
blocks**, relative Markdown links, fenced shell examples and `git diff --check`
passed. App/plugin metadata both report `2.2.0.dev12`. The installer harness now
has **14 scenario sections**, retains **36 unsafe-path/metadata refusals**, and
adds three pending-marker forms plus independent-runtime preservation/rollback.
Docker, native promtool and CodeQL are unavailable locally; their observed
evidence comes from the exact implementation CI below. No gate was relaxed.

### Observed native CI and packaging

Implementation
[`8dba416`](https://github.com/alphazulu/cgp-certificate-manager/commit/8dba416938bbe17ed72cdab0d8830fe688e0e791)
passed [PR CI 45536468319](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45536468319),
**all eleven jobs**. [Push CI 45536461992](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45536461992)
also succeeded. Both native Python **3.12.16** profiles independently retain
**1427 tests / 7793 statements / 2546 branches / 100%**, with zero missing or
partial coverage: compat **83.732 s**, current **52.870 s**.

| Required check | Observed implementation result |
|---|---|
| Both full test profiles | Complete suites and independent strict coverage gates passed |
| Four installer combinations | Ubuntu 24.04 / Debian 13 x baselines 2.0.1 / 2.1.0; all 14 scenario sections passed, including runtime/guard preservation and 36 unsafe-path/metadata refusals |
| Current dependency audit | Complete 22 expected / 22 reported / 22 audited, zero findings, inventory/scanner/policy exits 0/0/0 |
| Historical compatibility audit | Complete 23/23/23, 23 raw records / 15 package-advisory pairs / 4 historical packages, exits 0/1/0 under the unchanged informational-findings policy |
| Native CodeQL | CLI 2.27.5; analysis/upload/processing complete, 1 SARIF report / 1 run / 0 findings / 0 errors |
| Native monitoring | promtool 3.16.0 validated 19 rules and passed both alert and dashboard-expression fixtures |
| Package | Two identical archive/checksum/provenance sets, SHA-256 validation and artifact upload passed |

Both dependency reports have no missing/skipped/unexpected packages, version
mismatches or diagnostic problems. Compatibility findings stay visible and are
not production dependency recommendations or a scan of distribution backports.
Installer checks use mock systemd inside disposable containers; no real boot,
server, provider or notification acceptance is claimed.

The implementation tree is `eaa3b48ea334298c5a94671f7744b7db3643b714`.
Package provenance records tested PR preview
`9b8fe51e1c673c9a1c8d1122c3e5795c17da3374` with that same tree.
The **582098-byte** archive has SHA-256
`2db050517d9a40ef75a1f9a96007bd43c386079df5a7c7bd373d694f816d5227`,
equal to the locally reproduced archive. It is a development CI artifact, not
a signed update target or published release.

This documentation-only follow-up records observed implementation evidence.
Inspect its own current-head CI when resuming; earlier results do not validate
a later revision. Stable main remains 2.1.0 at
`fffbeda39a6adbb1c7ab8e924f4ec2c0089a2a5f`.

### Continuation after checkpoint 15

1. Inspect actual HEAD/worktree, draft PR #2 and all eleven current-head CI
   jobs. The implementation and its full local/native gates above passed;
   separately verify this documentation follow-up's checks before attributing
   a result to it. Preserve unfinished work and the draft status. Fix later
   findings with regressions and retain every coverage/security/installer gate.
2. The next independent roadmap scope is **2.5 DNS provider abstraction**:
   retain Cloudflare fixed/adaptive behavior and durable ownership receipts,
   define provider capability/credential boundaries and add isolated provider
   contract tests before a new backend. No provider account or live DNS test is
   authorized by this continuation. Explicit update evidence retention/cleanup
   is still outside this checkpoint; the documented four-transaction/stage caps
   remain, with no automatic deletion of recovery evidence.
3. Keep real VM/server/provider/recipient/broker and signing acceptance deferred.
   Safe CGP bootstrap still needs the documented disposable-instance evidence.
   Do not merge, tag, release, dispatch privileged release preparation, choose
   production signing/trust keys or deploy this development code to a server.

## Previous handoff — checkpoint 14

- Development version: **`2.2.0.dev11`**, in the same draft
  [PR #2](https://github.com/alphazulu/cgp-certificate-manager/pull/2).
- Starting HEAD: `c342861f6abbe8ef4b0525b125f3089be114f9ac`, clean on resume.
  Its [PR CI 45511485116](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45511485116)
  and push CI 45511473774 passed all eleven jobs. Both complete profiles reported
  **1199 tests / 5979 statements / 2236 branches / 100%**. Those results belong
  to checkpoint 13, not the new updater implementation.
- Authorized scope: authenticated offline checking and preparation, a saved
  plan/status contract, an unsigned publisher manifest assembler, installed
  command integration, unit tests and documentation. Full application apply is
  deliberately a separate next checkpoint: the existing installer uses shell
  traps and cannot recover after arbitrary process death. No real VM/server,
  signer/trust provisioning, provider/recipient, release or update is activated.
- `update_metadata.py` validates a bounded exact schema and canonical ASCII JSON
  with an explicit signing domain. Lazy Ed25519 verification uses only separate
  local trust, verifies project/repository/channel, requires a newer stable/RC
  target and enforces validity, monotonic sequence/version and same-sequence
  identity. Trust keys are identified by the digest of the raw public key.
  Saved floors are retained per channel across key changes. This is a narrow
  offline protocol, not a complete TUF implementation or proof of latestness.
- `update_archive.py` checks signed archive size/hash before bounded
  decompression and accepts the deterministic release builder's precise format.
  It rejects traversal, links/special entries, duplicate/colliding names, hidden
  header/PAX overrides, malformed framing and resource-limit violations.
  Application/plugin metadata is parsed without importing candidate code.
  Private staging writes, permissions, synchronization and inventory validation
  are independently tested; every staged byte is rehashed for saved status.
- `update_plan.py` keeps trust and public input snapshots separate, reads the
  installed version declaration without importing it, and isolates updater
  state from installation, source, manager, monitor and input trees. Check and
  status use a noncreating shared lock. Prepare authenticates before state
  creation, then rechecks under its own exclusive lock and atomically saves
  signed metadata, inventory, baseline identity and per-channel floors.
  An unchanged valid plan reuses its stage; four retained stage directories are
  the limit. No automatic pruning or deletion follows uncertain persistence.
- The public result includes a bounded allowlist, fixed diagnostic codes and
  `apply_supported: false`. Its plan ID is informational; the installed
  baseline binds only the version file. The updater lock does not serialize
  the existing installer. Same-UID/root namespace mutation is not sandboxed,
  and prepared source is not made immutable or treated as install authorization.
- `repo_tools.update_manifest` validates release-tagged unsigned provenance
  against the exact archive and prints canonical signable metadata. It creates
  no key or signature and does not authenticate the provenance itself. It is
  not wired into the privileged release workflow. Existing GitHub attestations
  remain a separate format and are not accepted in place of the new signature.
- `update_cli.py` provides `--check`, `--prepare` and `--status`; help/version
  avoid backend imports and I/O. The installer preserves/restores the new
  `cgp-update` wrapper without creating updater trust/state or a schedule. The
  native harness tests the exact fresh import path and preservation alongside
  existing monitor/manager recovery fixtures.
- Review reproduced a namespace race in path-based stage creation/cleanup:
  replacing the parent pathname could redirect cleanup to an unrelated child.
  Descriptor-relative creation/removal and identity rechecks replace that
  pathname use, with regressions retaining foreign sentinels. Review also
  found a file-descriptor leak after failed publisher stream construction;
  explicit descriptor closure and a regression accompany the fix. Freshness
  is rechecked after lengthy validation/staging instead of reusing a start time.
  A double-slash absolute-path alias could bypass lexical overlap checks; it
  is rejected, with a regression. State/lock inode rechecks detect observed
  namespace replacement without claiming protection from malicious same-UID
  changes between a check and a subsequent path lookup.
- Both complete local dependency profiles independently passed **1303 tests /
  6833 statements / 2350 branches / 100%**, with zero missing statements,
  missing/partial branches or exclusions. Each separate `--fail-under=100`
  gate covers `cgp_cert_manager,repo_tools`. Compat took **31.592 seconds**;
  current took **31.002 seconds**.
- All **104 additional tests** accompany the implementation: 19 metadata,
  25 archive, 35 coordinator, 11 CLI, 12 publisher and 2 installed-entrypoint
  cases. They include real Ed25519 vectors/signatures, exact archives built from
  temporary Git objects, actual private files/locks, corruption and namespace
  faults, expiry/clock rollback, key/channel changes, idempotent preparation,
  uncertain persistence and fresh native entrypoint imports. A full local
  publisher/signature/CLI round trip checks the plan, prepares it, removes the
  original inputs, inspects saved state and refuses its subsequent expiry.
- Python compilation, all three installer shell scripts, **21 workflow run
  blocks**, **164 relative links and 38 shell examples across 20 Markdown
  files**, the disabled four-channel example and `git diff --check` passed.
  App/plugin metadata both report `2.2.0.dev11`. Updater preparation requires
  Python 3.11+ for descriptor-relative cleanup and the native interpreter's
  optional `cryptography` backend; help/version do not import that backend.
- Implementation
  [`82c5c63`](https://github.com/alphazulu/cgp-certificate-manager/commit/82c5c63f75a09b547193f939196a4c5c0ae0366c)
  passed [PR CI 45523784100](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45523784100),
  **all eleven jobs**, and push CI 45523774587. Both full native Python 3.12.16
  profiles retained **1303 tests / 6833 statements / 2350 branches / 100%**,
  with zero missing/partial paths: compat **49.223 seconds**, current
  **47.511 seconds**. No CI finding or gate relaxation was required.
- Native CodeQL CLI **2.27.5** completed analysis, upload and processing.
  Its policy reports **1 SARIF report / 1 run / 0 findings / 0 errors**,
  complete and passed. The current dependency audit was complete at **22/22/22**
  expected/reported/audited packages with no findings and inventory/scanner/policy
  exits **0/0/0**. Historical compat was complete at **23/23/23**, with
  **23 raw records / 15 package-advisory-ID pairs / 4 historical packages**,
  exits **0/1/0**, under the unchanged explicit `informational-findings` policy.
  Missing/skipped/unexpected dependencies, mismatches and diagnostic problems
  were empty in both. These are test-environment audits, not production scans.
- All four Ubuntu 24.04 / Debian 13 x baseline 2.0.1 / 2.1.0 installer jobs
  passed **13 scenario sections and 36 unsafe-path/metadata refusals each**,
  including the exact fresh updater entrypoint, no default updater state/trust
  creation, wrapper restoration and independently provisioned evidence
  preservation. They use mock systemd; native Certbot was **2.9.0** on Ubuntu
  and **4.0.0** on Debian. Native promtool **3.16.0** accepted all **19 rules**
  and both alert/dashboard-expression fixtures.
- Packaging reproduced two identical archive/checksum/provenance sets and
  verified the checksum before upload. The **531070-byte** archive has SHA-256
  `4db76d079492b9096f3cd59beef3c33352658293b90f432c2e0466a0c7f01e83`.
  Provenance records tested PR preview
  `8a73aefc8540aaff4673312d5ec530b9c7d06d16` and tree
  `b808c54f4ccfea045fe07205e70a3092d99fa506`, equal to the implementation tree.
  This development artifact is not a signed update target or published release.
- This documentation-only follow-up records the observed implementation run.
  Inspect its own exact current-head checks on resume instead of attributing
  earlier CI to a later revision. All eleven gates remain required. Docker,
  native promtool and CodeQL were unavailable locally; their evidence above
  comes from the named CI revision.
- Stable main remains `fffbeda39a6adbb1c7ab8e924f4ec2c0089a2a5f` / **2.1.0**.
  Application/plugin metadata and English/Russian documentation move together;
  the implementation contract is in [UPDATES.md](docs/UPDATES.md).

### Resume from checkpoint 14

1. Inspect actual HEAD, worktree, draft PR and all eleven current-head checks.
   Preserve unfinished files. Read this handoff, ROADMAP.md and UPDATES.md;
   distinguish observed results for each revision from pending validation.
2. The implementation, reviews, both full local coverage profiles and all
   eleven implementation CI jobs pass. Inspect the documentation follow-up's
   own current-head checks before claiming its status. Retain both 100% gates
   and all other checks; resolve any later finding with a regression and record
   the actual successful revision without exclusions or gate relaxation.
3. Next design a full installed preimage and explicit approval contract,
   shared installer/manager/monitor/updater lock ownership and a durable journal
   before application replacement. Revalidate signed freshness, trust, staged
   bytes and installed preimages immediately before writes. Recovery must
   classify old, intended and unknown/manual state and retain unresolved evidence.
   Exercise process-death and restart faults; shell EXIT traps are insufficient.
4. Keep real VM/server and signing acceptance deferred, preserve pending CGP/DNS
   recovery evidence, and leave bootstrap write enablement, signing-key choice,
   license decision, merge and release to their separately authorized sessions.

## Checkpoint 13 — Telegram and MQTT (historical)

- Development version: **`2.2.0.dev10`**, in draft PR
  [#2](https://github.com/alphazulu/cgp-certificate-manager/pull/2).
- Starting HEAD: `04e897623f2525709b58f67b731a2c512691ba90`, clean on resume.
  Its [PR CI 45423540193](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45423540193)
  passed all eleven jobs; push CI 45423518606 also passed. Both complete profiles
  reported **1140 tests / 5665 statements / 2094 branches / 100%**. Those counts
  validate checkpoint 12, not the new code below.
- Authorized independent scope: optional Telegram and MQTT notification
  transports in the existing external monitor. Every new behavior receives unit
  tests; no new runtime dependency is introduced. Real VM/server/provider,
  recipient/broker and systemd acceptance remains deferred. No merge, tag,
  release, privileged workflow dispatch, real send or deployment is included.
- Telegram uses verified HTTPS and one plaintext `sendMessage` request with a
  stable event ID and endpoint summaries. Private token/CA snapshots, bounded
  complete response framing and strict JSON/message acknowledgement distinguish
  explicit rejection from ambiguous submission. A valid rate-limit hint extends
  `retry_at` using the greater of configured retry and provider interval, from
  attempt completion. The cooldown applies across changed conditions/recovery
  and survives restart without adding fields to schema 1 or public output.
  Review reproduced a well-formed API `error_code: 429` inside HTTP 2xx that
  initially lost its retry hint. Both HTTP 429 and successful HTTP envelopes
  carrying that API refusal now preserve the interval, with regression tests.
  JSON is also bounded to depth 32 and 4096 value nodes, independently of bytes.
- MQTT uses a narrow standard-library 3.1.1 publisher: verified TLS by default,
  new short client ID, CleanSession, one QoS-1 non-retained event JSON, matching
  PUBACK required. Literal loopback is the only unauthenticated plain transport.
  It uses the existing bounded TCP dialer and worker supervision. PUBACK does
  not prove authorization, subscriber receipt or processing; downstream
  deduplication uses the stable event ID.
- Each channel retains independent durable intent, outcome and retry identity.
  Existing opt-in and credential/configuration rotation rules apply to all four
  transports. The supplied example keeps the monitor, policy and every channel
  disabled. No credentials, receiver routes or raw peer replies enter saved
  events or public results.
- Implemented files: `notify_telegram.py`, `notify_mqtt.py`, common
  dispatch/state/runner integration and three focused test modules. The
  [channel guide](docs/NOTIFICATION_CHANNELS.md), existing monitor/staging/security
  guidance, version metadata and English/Russian READMEs accompany the code.
- Both full local dependency profiles independently passed **1199 tests /
  5979 statements / 2236 branches / 100%**, zero missing statements, missing
  branches, partial branches or exclusions. `--fail-under=100` passed separately
  over `cgp_cert_manager,repo_tools`. Compat took **31.818 seconds**, current
  **31.684 seconds**. All **59 new tests** accompany the implementation: 25
  Telegram, 20 MQTT and 14 cross-channel/configuration/state/CLI cases.
- Protocol tests use real stdlib parsers and synthetic TLS loopback peers.
  They cover private snapshots, verified connections, malformed/truncated
  acknowledgement framing, body/packet bounds, wrong IDs/text/chat/topic,
  explicit refusals and uncertainty after submission. Cross-channel tests
  cover four mixed outcomes, independent retries, exact cooldown boundaries,
  changed-condition/recovery deferral, restart persistence, schema-1 continuity,
  secret-free output and configuration changes between destinations.
- Python compilation, three installer shell scripts, all **21 workflow run
  blocks** and `git diff --check` passed. Documentation validation passed **152
  relative links and 34 shell examples across 19 Markdown files**. The real
  configuration validator accepts the supplied example with monitor, sending
  policy and all four channels disabled. Application and plugin metadata both
  report `2.2.0.dev10`.
- Implementation
  [`5910bde`](https://github.com/alphazulu/cgp-certificate-manager/commit/5910bdea4e3d4a9052b39b635ccc21f4e53edf70)
  passed [PR CI 45510870363](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45510870363),
  **all eleven jobs**, and push CI 45510864744. Both complete native Python jobs
  retained **1199 tests / 5979 statements / 2236 branches / 100%**, with zero
  missing/partial paths: compat **34.928 seconds**, current **32.316 seconds**.
  No new CI finding, fixture conflict or gate relaxation was needed.
- Native CodeQL CLI **2.27.5** completed analysis, upload and processing. Its
  policy reports **1 SARIF report / 1 run / 0 findings / 0 errors**, complete and
  passed. The current dependency audit was complete at **22/22/22** expected,
  reported and audited packages, with no findings and exits **0/0/0** for
  inventory/scanner/policy. The historical compatibility profile was complete
  at **23/23/23**, with **23 raw records / 15 package-advisory-ID pairs / 4
  historical packages**, exits **0/1/0**, under the existing explicit
  `informational-findings` policy. Missing/skipped/unexpected packages,
  mismatches and diagnostic problems were empty in both. These fixture audits
  do not assess a production installation or distribution backports.
- All four Ubuntu 24.04 / Debian 13 x baseline 2.0.1 / 2.1.0 installer jobs
  passed **13 scenario sections and 36 unsafe-path/metadata refusals each**,
  including fresh monitor imports, lock exclusion, preservation, rollback and
  timer behavior under mock systemd. Native Certbot was **2.9.0** on Ubuntu and
  **4.0.0** on Debian. Native promtool **3.16.0** accepted all **19 rules** and
  both alert/dashboard-expression fixtures.
- Packaging built two byte-identical source artifact sets, verified the archive
  checksum and uploaded archive/checksum/provenance. Archive SHA-256:
  `c991e57470261e71a15c7db0e6e74e52075ed70400051bdfa98d451afe79e37b`.
  The provenance records tested PR merge preview
  `35653da876d548c00f98ca6384a8ab26c373be83` and tree
  `d33e9050ebe2f44ae57ce0ebe18044cc1d63cf44`, equal to the implementation tree.
  Six CI artifacts retain both coverage reports, both audits, CodeQL and the
  source package; this is not a published release.
- This documentation-only follow-up records the observed implementation run.
  Inspect its own exact current-head checks on resume rather than attributing
  earlier CI to a future revision. All eleven gates remain required. Native
  Docker, promtool and CodeQL were unavailable locally; their evidence above
  comes from the named CI revision.
- Stable main remains `fffbeda39a6adbb1c7ab8e924f4ec2c0089a2a5f` / **2.1.0**.
  No destination, schedule, real server, merge, tag or release was activated.

### Resume from checkpoint 13

1. Inspect current HEAD, worktree and draft PR. Preserve in-progress files and
   read this handoff, ROADMAP.md, EXTERNAL_MONITORING.md and NOTIFICATION_CHANNELS.md.
2. The implementation, protocol/cross-channel review, both complete local 100%
   suites and all eleven implementation CI jobs are complete. Inspect all
   eleven checks for the documentation follow-up's actual current HEAD before
   claiming its status. Investigate any failure without relaxing gates and
   keep the draft PR tied to observed results.
3. Preserve explicit send opt-in, per-channel durable intent and event IDs,
   Telegram channel cooldown, strict acknowledgement parsing, secret projection
   and unchanged schema-1 compatibility in subsequent work. Existing SMTP and
   webhook transport semantics and the default observation-only service remain.
4. After this scope passes, the next independent roadmap area is administrator-
   approved authenticated updates. Begin with a concrete trust/rollback design
   and tests; do not execute a real update or choose a signing trust root for
   the owner. Real acceptance, bootstrap write enablement, license decision,
   merge and release remain pending for their separately authorized sessions.

## Checkpoint 12 — external monitoring (historical)

- Development version: **`2.2.0.dev9`**, continuing in draft PR
  [#2](https://github.com/alphazulu/cgp-certificate-manager/pull/2).
- Starting HEAD: `2f3d937b460a0a2b33a85a1bf7796f3b2c7adfb5`, clean on resume.
  Its [PR CI 45409711073](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45409711073)
  passed all eleven jobs; push CI 45409696217 also passed. That historical
  950-test / 4507-statement / 1746-branch result is separate from this checkpoint.
- Authorized independent scope: separately scheduled external TLS observations
  and explicitly configured SMTP/HTTPS webhook delivery. Every new behavior has
  unit tests. The maintainer's real VM/server/provider deferral remains in force;
  no real recipient, destination or production endpoint is used. Optional
  Telegram/MQTT channels remain separate work. No merge, tag, release, privileged
  release-workflow dispatch or production deployment is part of this checkpoint.
- `cgp-monitor` has independent configuration (`/etc/cgp-monitor/config.json`),
  state (`/var/lib/cgp-monitor/observations.json`) and operation lock. It uses no
  CGP discovery, provider credentials, certificate private keys or local Certbot
  lineages. Existing renewal and offline `cgp-letsencrypt --monitoring`/metrics/
  discovery behavior is unchanged. The supplied JSON example is disabled.
- Commands require an explicit action: `--check-config` validates without network
  or state writes; `--probe` observes without saving/sending; `--status` reads
  saved freshness/delivery; `--run` records observations under its own lock.
  Only `--run --send`, enabled policy and enabled channels permit delivery.
  Missing/invalid/busy/stale/future/configuration-changed results remain explicit.
  Both `--run` and `--status` report a retained pending attempt as
  `delivery_failed`, even when TLS is healthy or sending was not requested.
  The observation's own status remains separate from delivery status.
- `tlsprobe` supports direct TLS and SMTP/IMAP/POP3 STARTTLS. It requires TLS 1.2+,
  trust and matching SAN, with explicit SNI/IP SAN and no verification-disabled
  retry. Custom private CA data is captured before use and replaces default
  trust. It bounds DNS candidates, TCP/protocol exchange, response lines and
  certificate data. Successful results contain the connected peer, leaf expiry,
  SHA-256 and TLS version; verification failure retains unknown measurements.
  One connected peer is not a claim about every address, application health,
  revocation or equality to CGP/Certbot settings.
- Each network action runs in a supervised process with bounded stdin/stdout
  and a minimal environment. Secrets are never command-line arguments. A parent
  deadline covers DNS as well as protocol work; the child unblocks and arms its
  own SIGALRM through output flush. It inherits a duplicate of the monitor lock
  above FD 2. Tests reproduce parent SIGKILL while synthetic DNS blocks, verify
  lock retention until the child deadline and exercise FD 0 and a blocked
  inherited SIGALRM mask. Handled interrupts finish process-group cleanup before
  returning and are not lost during descriptor/handler cleanup.
- SMTP supports verified TLS/STARTTLS with optional private password files.
  Explicit `plain_local` is limited to literal loopback, without authentication
  or CA override. HTTPS webhooks reject redirects and bypass proxy environment
  settings. Optional bearer and CA snapshots are private and bounded. TLS key
  logging is not enabled by ambient environment. SMTP/webhook acceptance means
  relay/receiver acknowledgement, not recipient delivery.
- Review reproduced truncated SMTP and HTTP replies that the standard library
  parsers can accept. Transport guards now require complete bounded CRLF framing
  and HTTP header termination before recognizing an acknowledgement. Truncation
  after submission stays uncertain; response bodies are not needed for the
  generic webhook acknowledgement. Real parser regressions accompany the fix.
- Notification intent is durably saved before every network attempt. Each
  channel retains its own acknowledgement, pending event, retry deadline and
  compact superseded-event summary. First healthy observations are suppressed;
  incident changes and recovery create events, unchanged alerts obey reminders,
  and uncertain/rejected attempts retry the same event ID after cooldown. SMTP
  Message-ID and webhook Idempotency-Key are stable for retries; exactly-once
  delivery is not claimed. A receiver must implement webhook idempotency.
- Configuration/credential/CA identity changes start a new notification baseline
  and retain one previous generation without sending old events to changed
  destinations. Configuration is rechecked before each actual send. Saved
  records and public results contain allowlisted observation/event metadata,
  never credentials, receiver routes or prepared secrets. State validation
  rejects unknown fields, malformed outcomes and future event times. Clock
  rollback, including between preflight and observation start, a failed state
  write/fsync and an unconfirmed post-send save cannot
  become successful delivery; failed recovery remains visible with healthy TLS.
- The optional service invokes `cgp-monitor --run`, **without `--send`**. Its
  timer is not enabled or started by installation. The installer validates
  optional existing monitor config/state and holds manager then monitor locks;
  it preserves state/config, installs/restores the wrapper and units and refuses
  an active monitor. It may initialize the empty private monitor state directory
  and lock even without monitor configuration. Success leaves both timers
  stopped; handled failure restores previously active timers after restoration.
  Installed `--run` refuses a custom state directory, so it cannot bypass the
  installer lock; separate source checkouts can use their own state directory.
  Read-only `--status` may inspect a custom directory. `--probe` takes no state
  lock and is not serialized against an application upgrade.
  The full manager installer still requires manager configuration; source use
  of the independent command does not require a running CGP.
- Installer integration expands to **36 unsafe-path/metadata refusals** in each
  existing OS/baseline combination, with new preservation/rollback/lock cases.
  It explicitly blocks monitor worker creation before Popen in addition to the
  existing networking stubs, because the worker intentionally drops inherited
  Python hooks. This harness uses mock systemd and makes no external probe/send.
- Documentation: [external monitoring](docs/EXTERNAL_MONITORING.md), the disabled
  [example](examples/monitor.example.json), both READMEs, contribution/security
  guidance, changelog, local-monitor link and deferred acceptance plan accompany
  the implementation. Telegram/MQTT and actual observer/receiver/systemd
  acceptance are still unchecked roadmap items.
- Both complete local dependency profiles independently passed **1140 tests /
  5665 statements / 2094 branches / 100%**, zero missing statements, missing
  branches, partial branches or exclusions. `--fail-under=100` passed separately
  for manager and repository-tooling sources in each environment. Compat took
  **32.703 seconds**, current **32.475 seconds**. There are **190 additional
  tests**. Real networking was limited to synthetic loopback servers; tests
  also exercise actual files, flock, subprocess termination and durable-write
  failures. Full commands remain in CONTRIBUTING.md.
- Python compilation, installer shell syntax, all **21 workflow run-block**
  syntax checks and `git diff --check` passed. Documentation validation passed
  **135 relative links and 32 shell examples across 18 Markdown files**. The
  shipped monitor example passed the real configuration validator with the
  monitor, notification policy and both channels disabled.
- Initial implementation
  [`7d9271d`](https://github.com/alphazulu/cgp-certificate-manager/commit/7d9271d9eef142da5b4a6109f4e4d855e471986e)
  was published with this handoff. Its
  [CI 45421268959](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45421268959)
  passed both complete profiles at **1138 / 5665 / 2094 / 100%**, both dependency
  audits and native monitoring assets. It failed all four installer jobs and
  the CodeQL result gate; packaging was correctly skipped. Native CodeQL analysis
  itself completed and produced one finding, not an incomplete-analysis error.
- The installer failure was reproduced locally by executing the exact harness
  blocks in a fresh Python process: replacing `smtplib.SMTP`/`SMTP_SSL` with mocks
  broke inheritance during the first monitor import. The harness now blocks
  their constructors while preserving the real classes. A regression executes
  the actual offline guard and installed-entrypoint block without preloading
  monitor modules; network/state guards remain active.
- The CodeQL SARIF traced secret-bearing notification dictionary values into
  the public `notifications_enabled` field. Configuration validation already
  requires this field to be a boolean, and actual private-credential tests did
  not reproduce a disclosure. The CLI now explicitly projects both public flags
  with `is True`. A new regression reads private SMTP/password and webhook/token
  inputs and checks all four enabled-policy combinations, exact JSON/text,
  boolean types, absence of credentials/routes and unchanged files. No finding
  suppression or security-policy change was made.
- The fixed implementation
  [`102b007`](https://github.com/alphazulu/cgp-certificate-manager/commit/102b007e35b4bf4254b4e9aae991344bdd0d9a4d)
  passed [CI 45422616787](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45422616787),
  **all eleven jobs**, and push CI 45422600243. Both complete Python jobs retained
  **1140 tests / 5665 statements / 2094 branches / 100%** with no missing/partial
  paths (compat **27.876 seconds**, current **38.038 seconds**). The tests and
  unchanged native gates confirm the two fixes above.
- Native CodeQL CLI **2.27.5** completed analysis, upload and processing. Its
  policy summary is **1 SARIF report / 1 run / 0 findings / 0 errors**, complete
  and passed. Both dependency audits and native monitoring checks passed;
  promtool **3.16.0** accepted all **19 rules** and both alert/dashboard fixtures.
- Both native dependency audits were complete: current expected/reported/audited
  **22/22/22 packages**, no findings and inventory/scanner/policy exits **0/0/0**;
  compatibility **23/23/23**, **23 raw records / 15 package-advisory-ID pairs /
  4 historical packages**, with exits **0/1/0** under the explicit
  `informational-findings` policy. Affected historical fixtures remain
  cryptography 41.0.7, dnspython 2.6.1, pyOpenSSL 23.2.0 and setuptools 78.1.1.
  Missing/skipped/unexpected dependencies, version mismatches and problems were
  all empty; required diagnostic checks passed. These are test-environment
  inventories, not an audit of the installed server or distribution backports.
- All four Ubuntu 24.04 / Debian 13 x baseline 2.0.1 / 2.1.0 installer jobs
  passed the final success marker. Each executed 13 scenario sections and
  **36 unsafe-path/metadata refusals**, including fresh monitor help/version,
  both locks/services, config/state/evidence preservation, handled rollback,
  previous timer restoration and both timers stopped on successful upgrade.
  Native Certbot was **2.9.0** on Ubuntu and **4.0.0** on Debian. No new network
  guard violation, unexpected traceback or fixture conflict remained.
- Packaging built two byte-identical artifact sets, verified the source archive
  checksum and uploaded archive/checksum/provenance. The archive SHA-256 is
  `d30eac83042492f5c07516c60064b8daaf25a8a8c5ef492b6a338a8b9cf6307b`.
  Its manifest correctly records PR merge preview
  `f0e4e668eb8a5db23cba496730ba734c586ed517` and source tree
  `eb2e6683d2af9521e9a526ab3f177eb3ec31f425`, equal to the fixed implementation
  tree. Six CI artifacts retain both coverage reports, both dependency audits,
  CodeQL evidence and the source package; none is a published release.
- This documentation-only follow-up records observed fixed-implementation CI.
  Inspect its own exact current-head checks on resume; it does not assert a
  future run's result. Docker, native promtool and CodeQL are unavailable locally;
  the native evidence above comes from the named CI revision. All eleven gates
  remain required, with no suppressed findings or relaxed coverage.
- Stable main remains `fffbeda39a6adbb1c7ab8e924f4ec2c0089a2a5f` / **2.1.0**.
  Existing production installation and timer settings have not been changed.

### Resume from checkpoint 12

1. Inspect actual HEAD, working tree, draft PR and all eleven current checks.
   Read this handoff, ROADMAP.md and docs/EXTERNAL_MONITORING.md before editing.
   Preserve any in-progress changes and distinguish local/previous CI evidence
   from the exact current revision.
2. Preserve all eleven gates and the new native-CI regressions. Investigate a
   real failing gate rather than reducing coverage, audit completeness or
   security checks. The fixed-implementation evidence above is historical for
   that exact revision; inspect the documentation follow-up's own current-head
   CI before claiming it passed. Keep PR and handoff tied to observed results.
3. Keep external probe/delivery state separate from renewal and local-exporter
   snapshots. Preserve explicit send opt-in, durable intent, uncertain outcomes,
   retry IDs, bounded workers and tests with every new path.
4. The next independent implementation scope is the optional Telegram/MQTT
   channels in the existing notification lifecycle. Define and test each
   protocol's acknowledgement, timeout, credential and duplicate semantics
   before adding it; do not contact a real recipient or enable a destination.
   Current local-exporter assets do not automatically ingest external results.
5. Keep all real VM/server/observer/receiver/systemd/provider/import acceptance,
   bootstrap write enablement, license decision, release tag/draft trial, merge
   and publication pending for their separately authorized sessions. The cases
   in docs/STAGING.md are a plan, not executed evidence.

## Checkpoint 11 — release preparation and security (historical)

- Development version: **`2.2.0.dev8`**, continuing in draft PR
  [#2](https://github.com/alphazulu/cgp-certificate-manager/pull/2).
- Starting HEAD: `10ebff469b8fc6bef121211e4346131815347fe4`, clean on resume.
  Its [CI 45399220791](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45399220791)
  passed all eight previous jobs. That historical 851-test / 3936-statement /
  1566-branch / 100% result does not validate the new tooling below.
- Authorized independent scope: release preparation automation and dependency /
  source security scanning. Every new helper has unit tests; the full measured
  coverage source now includes both `cgp_cert_manager` and `repo_tools`.
  All real VM/server/provider acceptance stays deferred. No tag, release,
  privileged release-workflow dispatch, merge or production change is authorized
  by this development checkpoint.
- `repo_tools.release` constructs deterministic source archives from immutable
  Git blobs without importing candidate code. It verifies version/plugin
  metadata, supported regular-file paths/modes and blob identity; normalizes
  archive metadata; and writes an archive, checksum and provenance manifest.
  Dirty/staged/untracked files are not inputs. Existing artifacts are not
  overwritten; unsafe output paths and incomplete source objects are refused.
  Real temporary Git repositories exercise SHA-1/SHA-256 objects, annotated and
  lightweight tags, exact source context and failure cleanup.
- A reusable security workflow audits each resolved test environment with
  pip-audit 2.10.1 in a separate scanner environment. Bootstrap pip is pinned to
  26.3. The current profile blocks findings; complete historical compatibility
  findings are explicitly informational and remain in raw artifacts. Missing,
  skipped, mismatched, malformed or failed audits block both profiles.
- Independent review reproduced a false clean result when pip omitted damaged
  distribution metadata with a warning before both inventory and audit. The
  adapter now requires inventory/scanner logs plus both exit statuses and
  rejects warning/error diagnostics. The exact workflow shell block is tested
  through the real adapter for this regression in both profiles. Readers reject
  nonregular/symlink inputs and bound JSON and diagnostic sizes; summaries do
  not repeat raw diagnostic text. Oversized JSON integers are normalized into
  fixed invalid-JSON summaries, with report/inventory CLI regressions.
- CodeQL uses the default Python suite over manager and repository tooling.
  Its tested SARIF gate requires a successful native analyze step, valid reports
  and zero findings; reported execution/configuration warnings and missing
  evidence fail. The native CodeQL run passed in the exact implementation CI
  recorded below; synthetic SARIF tests are separate evidence.
- CI now expands to **eleven jobs**: two full coverage profiles, four installer
  combinations, native monitoring checks, two dependency audits, CodeQL and
  packaging. Package creation depends on every preceding gate and compares two
  complete builds byte for byte before checksum verification and artifact upload.
- The separate manual release workflow is dispatched only on an existing stable
  or RC tag contained in the default branch. It validates exact tag/HEAD/workflow
  commit and version, reuses the same full CI, downloads the same-run artifact,
  checks remote tag identity/existing releases twice, creates GitHub provenance
  attestations and prepares an unpublished draft. RC drafts are prereleases;
  drafts are not selected as latest. The privileged final job checks out no
  candidate code. No tag creation, overwrite, automatic publication or updater
  is implemented. The real attestation/draft path remains unexecuted.
- Independent workflow review made both remote commit lookups explicitly use
  the `tags/` namespace, avoiding ambiguity with a same-named branch. Actual
  shell-block regressions cover both preflights and stable/RC draft flags.
- New external action pins were checked against primary release/tag/manifests:
  CodeQL v4.39.4 `1bd86f2fdb4b86187fa4059f16f31a3202acc9ea`,
  attest v4.2.2 `1e69f48acb82d1966a394da916b4c1698aa569d6`, and
  download-artifact v8.0.2 `9000827ccba6bdab643e8b6fd33ac0654aef8333`.
  Existing checkout/setup/upload/Node/promtool pins are retained. The new
  security schedule becomes active only after the workflow reaches the default
  branch: Monday 03:31 UTC / 13:31 Asia/Vladivostok.
- Local live PyPI auditing first identified vulnerable bootstrap pip 25.0.1.
  Updating test-environment bootstrap to the verified 26.3 release removed those
  current-profile findings. Fresh-cache reruns with the strengthened log policy
  passed: current audited all **22/22** packages, with zero findings and exit
  statuses inventory/scanner/policy **0/0/0**. Compatibility audited **23/23**,
  with **23 raw records / 15 package-advisory-ID pairs / 4 affected packages**
  and statuses **0/1/0** under the explicit informational-findings policy.
  Affected historical packages are cryptography 41.0.7, dnspython 2.6.1,
  pyOpenSSL 23.2.0 and setuptools 78.1.1. Both inventories and reports were
  complete, with no diagnostics/skips/mismatches. Original reports, logs and
  statuses were retained locally; they assess PyPI test environments, not the
  installed mail server or distribution backports. Native CI independently
  reproduced both complete results, as recorded below.
- Documentation: [docs/RELEASING.md](docs/RELEASING.md) defines artifact identity,
  audit policy, permissions, failure behavior and deferred release execution.
  READMEs, CONTRIBUTING.md, SECURITY.md, CHANGELOG.md and the roadmap are updated
  with the implementation. Workflow fixtures require `jq` in addition to Bash,
  Git, coreutils and the existing Python/Node/OpenSSL test prerequisites.
- Both complete local dependency profiles passed **950 tests / 4507 statements
  / 1746 branches / 100%**, zero missing statements and zero partial branches.
  Each independently passed `--fail-under=100` with the expanded manager/tooling
  source. Compat took 26.876 seconds and current 26.568 seconds. There are **99
  new tests**: 21 release-builder, 38 dependency-policy, 27 CodeQL-policy and
  13 workflow-contract tests. The latter execute actual YAML shell blocks with
  controlled external commands and real JSON/checksum/policy adapters.
- Python compilation, installer shell syntax, all 21 workflow run-block shell
  syntax checks and `git diff --check` passed. Documentation validation passed
  110 relative links and 28 shell examples across 17 Markdown files.
- Implementation commit:
  [`7cd8377f114799a66a2b21cf9e8d16b6b20c970a`](https://github.com/alphazulu/cgp-certificate-manager/commit/7cd8377f114799a66a2b21cf9e8d16b6b20c970a).
  [CI 45408950645](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45408950645)
  **passed all eleven jobs**. Both dependency logs confirm **950 tests / 4507
  statements / 1746 branches / 100%**, zero missing/partial, and successful
  `--fail-under=100` (compat 20.699 seconds; current 22.215 seconds).
- Both native dependency audits were complete and matched the local inventory
  and finding counts above. CodeQL used CLI **2.27.5**, extracted the selected
  manager/tooling sources, completed analysis/upload/processing, and produced
  **1 SARIF report / 1 run / 0 findings / 0 policy errors** with `passed=true`.
  Original audit evidence and SARIF/summary were uploaded as CI artifacts.
- All four Ubuntu 24.04 / Debian 13 x baseline 2.0.1 / 2.1.0 installer jobs
  reached their final success marker, including preservation/rollback,
  installed metadata/monitoring and 24 unsafe-path cases per combination.
  Native Certbot was 2.9.0 on Ubuntu and 4.0.0 on Debian. Monitoring checks
  verified promtool 3.16.0, accepted all 19 rules and passed both native alert
  and actual dashboard-expression fixtures.
- Packaging produced two byte-identical source artifact sets, verified the
  archive checksum and uploaded the three-file `release-package` artifact.
  The archive SHA-256 was
  `8682fc84be1db68d2f929509cb765bdb9c8a7d8df1eeee1a901c2a959b9bb14c`.
  Its manifest correctly identifies the tested PR merge preview
  `653d1bcb97a92a5f8da2da65e2dbffe8ae7e84d5`, whose source tree is
  `bee7e96b9ff4485d869aa51da22f6726acd0e41c`, equal to the implementation tree.
  Inspected job logs contain no GitHub warning/error, deprecation or traceback
  markers. Six CI artifacts retain coverage, both audits, CodeQL and packaging.
- This documentation-only follow-up records the observed implementation run
  and completes the repository-automation roadmap item. Inspect its own exact
  current-head checks on resume; no claim of its future result is embedded here.
  The privileged manual attestation/draft path remains unexecuted. Automatic
  weekly scanning will only become active after merge to the default branch.
- Stable main remains `fffbeda39a6adbb1c7ab8e924f4ec2c0089a2a5f` / **2.1.0**.
  No merge, release, tag creation, VM/server/provider test or production change
  was performed. Docker, promtool and native CodeQL remain unavailable locally;
  their observed results above come from the exact implementation CI.

### Resume from checkpoint 11

1. Inspect actual HEAD, working tree, draft PR and current checks; read this
   handoff and ROADMAP.md. The candidate requires all eleven CI jobs.
2. Preserve the expanded strict 100% gate, complete audit evidence and refusal
   regressions. Future advisory or CodeQL findings require investigation;
   disabling a gate or dropping an inventory entry is not a fix. Compatibility
   finding-only policy does not permit incomplete or warning-bearing scans.
3. Keep the current handoff and PR tied to observed exact-revision results.
   The implementation CI above is historical evidence for its precise source;
   the documentation follow-up requires its own current-head CI inspection.
4. The next independent roadmap
   scope is separately scheduled external TLS probes and explicit notification
   configuration, developed with local fixtures and unit tests. Do not silently
   enable a production schedule or destination.
5. Keep real VM/server/provider/import acceptance, bootstrap write enablement,
   license decision, tag preparation, privileged draft trial, merge and release
   publication as explicit remaining work. Synthetic workflow tests are not
   evidence of a real release or production qualification.

## Checkpoint 10 — monitoring integrations (historical)

- Development version: **`2.2.0.dev7`**, continuing in draft PR
  [#2](https://github.com/alphazulu/cgp-certificate-manager/pull/2).
- Starting HEAD: `be96ef06d3391627eaa7b76eaec7db83b2b38f34`, clean on resume.
  Its [CI 45390162690](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45390162690)
  passed the previous seven jobs. The previous 827-test / 3936-statement /
  1566-branch / 100% result does not validate this checkpoint's new assets.
- User instruction to continue is being applied to the next independent roadmap
  scope: Prometheus alert rules, Grafana dashboard and a Zabbix template, with
  automatic tests. All real VM/server acceptance stays deferred under the
  maintainer's 2026-11-24 decision. No collection timer, privileged agent command,
  external notification destination or production import is enabled.
- Artifact contract: monitor local public certificate expiry and saved manager
  observations; require explicit source/freshness semantics and preserve unknown
  data. Default fresh age is 0..900 seconds inclusive; future collection times
  are errors. Local expiry is critical at <=7 days and warning at >7..21 days.
  Disabled domains remain discoverable. Local read-error observations are
  distinct from certificate-health alerts because they make collection incomplete.
- Prometheus enrollment is the explicit scrape-target label
  `cgp_manager="true"`; host identity is `(job, instance)` and domain identity
  adds `domain`. Expected targets come from labelled `up`, including reachable
  exporters with missing manager data. Removed target configuration needs an
  independent expected-target inventory and is not silently inferred.
- Grafana uses the classic schema 39 contract from Grafana 11.0, an imported
  Prometheus datasource, target/domain variables and explicit unknown data.
  Zabbix uses a 7.0 JSON export with an HTTP master for the public exporter,
  native Prometheus-to-JSON preprocessing, dependent observations and guarded
  discovery. Preprocessing JavaScript is shared verbatim with executable tests.
- Independent review added dashboard regressions for the same instance in
  different jobs and mismatched enabled/certificate domains on one host. The
  dashboard fixtures now contain 17 cases and 209 actual expression evaluations.
  Zabbix review identified cached-history risks when a leaf becomes missing or
  an optional saved-failure count disappears, plus fractional timestamps versus
  the native whole-second `now()` clock. Guards and regression tests accompany
  the fixes; original floating timestamps remain available for exact JavaScript
  freshness and observation identity, with native clock resolution documented.
- CI adds a required **monitoring assets** job; package creation depends on it
  and the previous two dependency/four installer jobs, making eight jobs.
  Toolchain pins were checked against primary release/source metadata:
  promtool 3.16.0, linux-amd64 archive SHA-256
  `68727009472a2c02e1ff7f062fd5b3e637285bffc8fc2d340c76fb449d6e0f34`;
  Node.js 24.22.3 through setup-node v7.1.0 commit
  `949feb2413d6458794dcd2491c4babbbce0c15c1` (Node 24 action manifest).
  Both Python test profiles add PyYAML 6.0.3 for asset contracts.
- Local Node.js and PyYAML are available. Direct local download of promtool was
  unavailable, so actual PromQL engine results must come from the pinned CI
  job. Python artifact assertions are not a substitute PromQL engine. Docker
  remains unavailable locally. Actual Grafana/Zabbix import and real monitoring
  deployment are deferred acceptance, not claimed by static or synthetic tests.
- Both complete local dependency profiles passed **851 tests / 3936 statements
  / 1566 branches / 100%**, with zero missing statements and zero partial
  branches. Compat took 19.472 seconds; current took 18.776 seconds. Each
  independently passed `--fail-under=100`. Compatibility was run in a separate
  environment installed from requirements-test-compat.txt after the default
  runtime was found without its test dependencies. There are **24 new Python
  tests**: 8 Prometheus, 11 Grafana and 5 Zabbix artifact/execution contracts.
  Application source changes are limited to the development version and its
  matching app-local Certbot distribution metadata.
- The Zabbix Python suite executes **105 Node scenarios** using the exact
  embedded ES5 bodies. Its required detailed V8 gate passed for all three
  scripts: normalize 20 functions/68 distinct ranges, fresh 2/19 and discovery
  3/6, totaling 25 functions and 93 ranges. Every collected nested byte interval
  has execution coverage; missing Node, missing scripts/coverage or unexecuted
  intervals fail the suite. No coverage exclusions or lowered thresholds.
  Arithmetic substitutions test exported trigger conditions/recovery with
  cached item histories, but do not claim native Zabbix parser/event validation.
- The finished assets contain 13 alerts and 6 recording rules; 10 Grafana data
  panels; and a Zabbix template with 16 items, 1 discovery rule, 9 item prototypes,
  14 global triggers, 6 trigger prototypes, 5 value maps and 7 macros. Native
  promtool fixtures contain 25 alert scenarios plus 17 dashboard scenarios /
  209 dashboard expression evaluations. Their actual engine execution passed
  in the exact implementation CI below, independently of the Python contracts.
- Python compilation, installer shell syntax, all 14 workflow run-block shell
  syntax checks and `git diff --check` passed. Documentation validation passed
  94 relative links and 25 shell blocks across 16 Markdown files. Local Node was
  24.22.3; both test environments use coverage 7.10.7 and PyYAML 6.0.3.
- Implementation commit:
  [`83ed7d9b5e2de568aaacd8cec8fc7ffdc68d2192`](https://github.com/alphazulu/cgp-certificate-manager/commit/83ed7d9b5e2de568aaacd8cec8fc7ffdc68d2192).
  [CI 45398683411](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45398683411)
  **passed all eight jobs**. Both dependency logs confirm **851 tests / 3936
  statements / 1566 branches / 100%**, zero missing/partial, and successful
  `--fail-under=100` (compat 17.029 seconds; current 16.957 seconds). The exact
  embedded-JavaScript execution/coverage test passed in both profiles.
- The monitoring-assets log confirms the archive SHA-256, promtool 3.16.0 at
  revision `e2e28adeee2c5883d000fc82aca6008cfbf7e96d`, acceptance of all 19 rules,
  and successful native evaluation of both the 25-case alert file and generated
  17-case / 209-expression dashboard fixture. All four Ubuntu 24.04 / Debian 13
  x baseline 2.0.1 / 2.1.0 installer jobs reached their final success marker,
  including installed monitoring checks, preservation/handled rollback and
  24 unsafe-path refusals each. Native Certbot was 2.9.0 on Ubuntu and 4.0.0 on
  Debian. Package creation, SHA-256 verification and CI artifact upload passed.
  No GitHub warning/error, deprecation or traceback markers were found in the
  inspected job logs. The artifact is not a published release.
- The workflow checked PR merge preview
  `6f4d7f871898fbb2aac9390f650953ef16b8fd46` against unchanged stable main.
  This documentation-only follow-up records the observed implementation result
  and completes the monitoring integration roadmap checkbox. Inspect its own
  current-head checks on resume; no claim of its future result is embedded here.
- Stable main remains `fffbeda39a6adbb1c7ab8e924f4ec2c0089a2a5f` / **2.1.0**.
  Real VM/server/import acceptance remains deferred. No merge, release,
  production deployment, collection schedule or notification route was enabled.

### Resume from checkpoint 10

1. Inspect actual branch HEAD, working tree, PR and current checks, then read
   this handoff and ROADMAP.md. The new candidate requires eight CI jobs.
2. Preserve tested missing/stale/future/disabled/multihost semantics across
   alerts, dashboard and discovery. Exercise actual embedded JavaScript and
   real promtool; do not replace engine tests with string-only assertions.
3. Complete independent release automation and dependency/security scanning
   after this monitoring integration checkpoint. External probes and notification
   delivery remain separate roadmap work with explicit deployment configuration.
4. Keep real VM/server validation deferred until scheduled by the maintainer.
   Automatic bootstrap writes still require the documented CGP field-removal,
   restoration and TLS experiments; no new semantics are assumed from unit tests.
5. Merge, release and production deployment remain separate maintainer decisions.

## Checkpoint 9 — local monitoring foundation (historical)

- Development version: **`2.2.0.dev6`**, continuing in draft PR
  [#2](https://github.com/alphazulu/cgp-certificate-manager/pull/2).
- Starting HEAD: `1e27e2ee9443f3d65190ade66ca2b6c447f56885`, clean on resume.
  Its [CI 45386355463](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45386355463)
  was inspected and all seven jobs passed. That historical run does not validate
  this checkpoint's changes.
- **Maintainer direction, 2026-11-24: defer all tests on a real VM or server
  until later.** Independent development, unit tests and isolated CI continue.
  External Cloudflare/ACME/CGP acceptance remains pending in docs/STAGING.md;
  it is not a prerequisite for the independent monitoring foundation below.
  Bootstrap write enablement still requires verified CGP field semantics.
- Scope: the monitoring foundation from roadmap 2.3, developed on the current
  unreleased branch. Add `--monitoring` local JSON, `--metrics` Prometheus text,
  explicit atomic `--metrics-file` publication and safe `--zabbix-discovery`.
  No remote observation, notification, recovery, HTTP endpoint or new schedule
  is part of these commands. Current live TLS remains a separate observation.
- The collector reads existing state under a nonblocking shared lock without
  creating it. Missing, busy, unsafe or corrupt sources make the snapshot
  incomplete; unknown measurements are not exported as zero. Current config
  determines domain policy, the saved inventory supplies cached domain names,
  and only validated numeric state fields and retained-artifact counts escape.
  Raw source contents and exception messages are not part of the public schema.
- Public local certificate inspection is bounded, uses the normal Certbot
  live/archive leaf layout and refuses unsafe targets. It reads no private key
  for expiry and distinguishes known absence, read failure and an expired leaf.
- The Prometheus renderer groups fixed gauge families, escapes labels, omits
  unknown samples and provides collection/source status and freshness. The LLD
  renderer refuses an incomplete snapshot rather than returning an empty or
  partial discovery list. Disabled domains remain explicitly discoverable.
- Textfile publication uses an existing trusted directory, a new temporary
  inode, explicit mode 0644, file fsync, atomic replacement and directory fsync.
  Private targets and private manager/Certbot trees are refused. Incomplete
  collection publishes failure metrics; publication failure before replacement
  preserves old output, while post-replacement fsync failure reports uncertainty.
- Documentation: docs/MONITORING.md defines the schema, metric meanings,
  source/freshness limits, publication permissions and LLD failure behavior.
  English/Russian READMEs, CONTRIBUTING.md, CHANGELOG.md, ROADMAP.md and the
  staging deferral are updated together. App-local Certbot metadata moves with
  the manager version and remains covered by the real discovery regression.
- Both complete local dependency profiles passed **827 tests / 3936 statements
  / 1566 branches / 100%**, with zero missing statements and zero partial
  branches. Compat took 20.934 seconds; current took 20.374 seconds. The strict
  `--fail-under=100` gate passed independently in both profiles. **87 new tests**
  accompany the implementation: 25 collection, 24 public certificate, 9 format,
  16 publication and 13 CLI tests. Tests include real flocks, real valid/expired
  OpenSSL certificates, source mutation, finite JSON parsing, unsafe path and
  atomic-publication failures. No exclusions or lowered thresholds.
- Python compilation, installer shell syntax and `git diff --check` passed.
  Documentation validation passed 81 relative links and 24 shell blocks across
  15 Markdown files. Exact implementation CI evidence is recorded below.
- The installer harness now invokes the installed monitoring commands after
  clean installation and upgrade in each existing container combination. It
  guards provider/network/Certbot/notification/recovery calls, checks incomplete
  JSON/metrics/LLD behavior and mode-0644 failure-metrics publication, and compares
  private configuration/state bytes and metadata plus the systemctl log before
  and after. Local shell syntax and embedded Python compilation passed, and all
  four container combinations passed in the implementation CI below. Docker is
  unavailable locally. These checks do not execute the deferred real VM/server
  acceptance.
- Implementation commit:
  [`d9978854ec309d74dce9482e34c5637a93f1c481`](https://github.com/alphazulu/cgp-certificate-manager/commit/d9978854ec309d74dce9482e34c5637a93f1c481).
  [CI 45389786314](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45389786314)
  **passed all seven jobs**. Both dependency logs confirm **827 tests / 3936
  statements / 1566 branches / 100%**, zero missing/partial, with successful
  `--fail-under=100` (compat 16.840 seconds; current 16.378 seconds).
  All four Ubuntu 24.04 / Debian 13 × baseline 2.0.1 / 2.1.0 installer jobs
  reached the final success marker after the installed monitoring checks,
  evidence preservation, handled rollback and 24 unsafe-path refusals each.
  Native Certbot remained 2.9.0 on Ubuntu and 4.0.0 on Debian. Package creation,
  SHA-256 verification and artifact upload passed; this is a CI artifact, not
  a published release. Inspected logs contain no GitHub warning/error, deprecation or
  traceback markers.
- The PR workflow checked merge preview `e1a5c0016ad2f20361d6c979bc05b556c01180fc`
  of that implementation head with unchanged stable main. This follow-up only
  records the observed result in the handoff and roadmap. Inspect its own
  current-head checks on resume; the external acceptance cases remain deferred.
- Stable main remains `fffbeda39a6adbb1c7ab8e924f4ec2c0089a2a5f` / **2.1.0**.
  No merge, release, real VM/server test or production deployment was performed.

### Resume from checkpoint 9

1. Inspect actual branch HEAD, working tree, draft PR and the seven current-head
   CI jobs; read this handoff and the roadmap before making further changes.
2. Preserve local-only observation, nonblocking lock behavior, unknown values,
   no-secret output, atomic-publication failure tests and safe discovery refusal.
   Run both complete coverage profiles as described in CONTRIBUTING.md.
3. Continue the independent monitoring work: Zabbix template, Grafana dashboard
   and alert-rule tests with explicit collection/freshness/missing-data semantics.
   Do not add privileged agent execution or enable schedules implicitly.
4. Keep all real VM/server acceptance deferred until the maintainer schedules
   it. Record each later case against the exact candidate/build rather than
   treating local or container tests as external validation.
5. Keep bootstrap writes blocked until the documented CGP field-removal and
   restoration experiments establish the required semantics. Remaining release
   automation/security scanning can proceed independently of those experiments.
6. Merge, release and production deployment remain separate maintainer decisions.

## Checkpoint 8 — recovery and validation hardening (historical)

- Development version: **`2.2.0.dev5`**, draft PR
  [#2](https://github.com/alphazulu/cgp-certificate-manager/pull/2).
- Starting HEAD: `2f89fe1d28595ed18808e1f5b163ad09bb17ea1c`, clean on resume.
  Its [CI 45382611822](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45382611822)
  passed all five previous jobs, with 726 tests / 3511 statements / 1422 branches
  / 100% in both dependency profiles. That historical run does not validate the
  changes in this checkpoint.
- Targeted review found a concrete recovery defect: a changing/truncated filtered
  Cloudflare listing could look like one uniquely owned record after an uncertain
  POST. Recovery could then delete that record and retire the receipt while a
  second owned record remained. Intent reconciliation now requires the same
  complete, stable pagination and unique valid IDs as absence verification.
  Four new regression tests cover refusal before deletion and successful
  multi-page recovery. Borrow/create lookup retains its distinct non-deletion
  contract.
- Targeted process review reproduced interruption during Popen and repeated
  interruption during shutdown leaving a child alive. The supervisor now
  defers SIGINT/SIGTERM through creation, bounded quiescence and cleanup
  while interrupting normal waiting. Descriptor validation now requires an existing
  exclusive whole-file flock through Linux fdinfo rather than acquiring a new
  lock for an unprotected internal invocation. Real process/signal/descriptor
  tests accompany the fix. This is coordination, not authentication against
  trusted root or same-UID code.
- Staging-plan review found that a global Certbot custom-server setting can
  override the staging default of `--dry-run`. Manager dry-run now explicitly
  selects the Let's Encrypt staging directory for both authenticator paths;
  command and real-parser regressions verify the selection without ACME calls.
  Ordinary issuance and arbitrary standalone wrapper commands keep their prior
  server-selection contract. Hook configuration remains an explicit lab concern.
- CI is configured for **seven jobs**: two dependency profiles, four installer
  combinations (Ubuntu 24.04 / Debian 13 × baseline 2.0.1 / 2.1.0), and package.
  Actions are pinned to verified stable Node 24 commits: checkout v7.0.1
  `3d3c42e5aac5ba805825da76410c181273ba90b1`, setup-python v7.1.0
  `6d4fd22b20465ccc0f7354476588e8df7c9ca0e0`, upload-artifact v7.0.2
  `cf430e030ddbb5b0abf93d22962f4752f3646cd9`. The full coverage gates and package
  dependencies remain in place. Installed-context checks include the real
  descriptor/procfs contract and metadata version. All four container combinations
  passed in the implementation CI below; Docker is unavailable locally. The
  systemctl stub verifies installer sequencing and recovery, not a live systemd
  or CGP deployment.
- Added [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and
  [docs/STAGING.md](docs/STAGING.md). The latter separates a DNS-only lab using
  the supervised wrapper from the CGP experiments and keeps every external
  acceptance case explicitly pending. No reporting address, enabled GitHub
  security setting, support SLA or license has been invented.
- App-local plugin metadata moves with version 2.2.0.dev5. The real entry-point
  discovery test verifies one application distribution and matching manager /
  metadata versions.
- Both complete local profiles passed **740 tests / 3544 statements / 1430
  branches / 100%**, zero missing statements and zero partial branches, with
  successful `--fail-under=100`. Compat (Certbot/ACME 2.9.0, dnspython 2.6.1)
  took 19.074 seconds; current (Certbot/ACME 5.10.0, dnspython 2.9.2) took 18.731
  seconds. Both used Python 3.12 / coverage 7.10.7. **14 additional tests**
  accompany the fixes, and the metadata regression is extended. Python
  compilation, installer shell syntax, documentation shell examples/relative
  links and `git diff --check` passed. No exclusions or lowered thresholds.
- Implementation commit:
  [`4db1f90bea3ec70d860c0fc59b0c881fd4d8a83b`](https://github.com/alphazulu/cgp-certificate-manager/commit/4db1f90bea3ec70d860c0fc59b0c881fd4d8a83b).
  [CI 45385891519](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45385891519)
  **passed all seven jobs**. Both test logs confirm **740 tests / 3544 statements
  / 1430 branches / 100%**, zero missing/partial, with successful `--fail-under=100`
  (compat 16.891 seconds, current 16.060 seconds). All four installer logs reach
  the final success marker after version/procfs assertions, journal/receipt/audit
  preservation, handled rollback and exactly 24 unsafe-path refusal cases each.
  Installed native Certbot reports 2.9.0 on Ubuntu and 4.0.0 on Debian. Package
  creation, SHA-256 verification and artifact upload passed. The inspected logs
  have no GitHub warning/error, deprecation or traceback markers.
- The PR workflow checked merge preview `52b5f59ecb980c57e228d827f3587f4d347def14`
  of the implementation head with unchanged stable main. This follow-up changes
  only the handoff/roadmap to record the observed implementation run; inspect
  its own current-head CI on resume. External Cloudflare/ACME/CGP acceptance
  cases remain unexecuted and pending in docs/STAGING.md.
- Stable main remains `fffbeda39a6adbb1c7ab8e924f4ec2c0089a2a5f` / **2.1.0**.
  No merge, release, production DNS/ACME/CGP probe or deployment is part of this
  checkpoint. Automatic bootstrap still requires the disposable CGP experiments.

### Resume from checkpoint 8

1. Inspect actual branch HEAD, working tree, draft PR and checks. Require all
   seven jobs for the current revision; do not infer a pass from checkpoint 7.
2. Preserve the pagination refusal and process/descriptor regression tests.
   Run complete compat/current coverage independently as described in
   CONTRIBUTING.md. Keep unexecuted environment checks clearly separate.
3. Execute the DNS-only staging track when a disposable VM, allocated test zones
   and scoped Cloudflare credentials are available. Follow docs/STAGING.md;
   do not collect live secrets or raw receipts in the repository. A real CGP
   instance is not required for the standalone authenticator track.
4. For manager discovery/deployment/bootstrap, provision the separate disposable
   CGP lab and record its exact build and permissions. The field-removal and TLS
   experiments in docs/BOOTSTRAP.md remain prerequisites for a new snapshot kind.
5. Keep unknown POST outcomes pending. A future abandonment mechanism requires
   an explicit evidence/authorization design; deleting a receipt is not recovery.
6. Finish the remaining external evidence and release review, then record an
   explicit maintainer decision for merge/release and production validation.

## Checkpoint 7 — DNS implementation (historical)

- Development version: **`2.2.0.dev4`**, draft PR [#2](https://github.com/alphazulu/cgp-certificate-manager/pull/2).
- Starting HEAD: `f7c50dccf94aa4a8f00fa39ce5dbb47276a5188a`, clean on resume;
  starting current-head [CI 45374813140](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45374813140)
  passed all four previous jobs. That historical run does not validate this change.
- DNS implementation and accompanying tests are complete. Both complete local
  dependency profiles passed **726 tests**, with **3511 statements / 1422 branches /
  100%**, zero missing statements and zero partial branches. The compatibility
  profile (Certbot/ACME 2.9.0, dnspython 2.6.1) took 19.046 seconds; the isolated
  current profile (Certbot/ACME 5.10.0, dnspython 2.9.2) took 18.161 seconds.
  Both used Python 3.12 / coverage 7.10.7 and passed `--fail-under=100`.
  **184 additional tests** accompany the changes. Python compilation, installer
  shell syntax and `git diff --check` also passed. No exclusions or lowered gates.
- Implementation commit:
  [`aabe70ef841c4579349d28461e7cd06f755a146f`](https://github.com/alphazulu/cgp-certificate-manager/commit/aabe70ef841c4579349d28461e7cd06f755a146f).
  [CI 45381705447](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45381705447)
  **passed all five jobs**: tests (compat), tests (current), installer (2.0.1),
  installer (2.1.0) and package. Both test logs confirm **726 tests / 3511
  statements / 1422 branches / 100%**, with zero missing/partial and successful
  `--fail-under=100` (compat 15.105 seconds; current 14.946 seconds). The PR run
  checks merge preview `7458f666c21e16ab4295a04e02ca566685387311` of the above
  head with the unchanged stable base. Both installer logs confirm the complete
  scenarios passed, including 24 unsafe-path refusals per baseline, preservation
  of pending certificate journals, operator evidence and DNS receipts, wrapper
  installation/discovery and rollback, and refusal of invalid DNS settings before
  application/timer changes. Docker is unavailable locally; these execution
  results come from CI. This documentation follow-up records that observed run;
  inspect its own current-head checks on resume.
- CI emitted upstream Actions/Node deprecation warnings, including Node 20
  actions running under Node 24. All jobs passed; update the action versions as
  a separate repository-maintenance task, with current-head verification.
- Stable `main` remains `fffbeda39a6adbb1c7ab8e924f4ec2c0089a2a5f` / **2.1.0**.
  This is development only: no merge, release, production DNS/CGP/ACME probe or
  deployment. Automatic CGP bootstrap remains disabled pending a disposable lab.

### Checkpoint 7 contract and completed work

1. `--dns-check [--domain DOMAIN] [--json]` is independent of CGP bootstrap
   readiness and performs no state/lock creation or mutation. It includes all
   unavailable SAN evidence, safe reason codes and explicit preflight setting.
2. Pure DNS configuration validation is shared by CLI issuance/auth hooks,
   wizard Save and installer preflight. Old configurations retain fixed waiting;
   adaptive mode is explicit and requires preflight. Cleanup does not depend on
   valid new waiting options. Force/retry/staging do not bypass an enabled gate.
3. DNS wire transport checks query/response identity, RCODE/flags/class/size and
   duplicate singleton records. Two named HTTPS validators retain normal TLS
   hostname trust while direct IPv4 endpoints avoid local DNS bootstrap. The
   standard HTTP parser uses deadline-aware socket I/O, including header reads.
4. CAA follows original-parent walking and CNAME/DNAME chains, with wildcard
   policy, critical-property handling, method restrictions and conservative
   account/parameter uncertainty. Empty negative responses require ancestral
   SOA evidence. Bounded queries/aliases/records and safe output are tested.
5. Delegation requires actual non-AA parent referrals, child authoritative
   apex NS/SOA and the actual challenge zone cut. A child apex answer cannot
   substitute for a parent referral. Child-side DS denial cannot establish an
   unsigned parent delegation. DNSSEC reports resolver assertions, not local
   validation; unsigned/unknown/bogus/error meanings remain distinct.
6. The proper `cgp-dns` authenticator processes the actual challenge batch, with
   preserved original wildcard CAA intent. Two fresh complete TXT passes cover
   all assigned authoritative NS and both recursive views under one deadline.
   Raising from perform stops before ACME answer; manual-hook exit does not
   establish that guarantee. Legacy fixed hooks remain compatible and separate.
7. Private server-bound receipts precede POST, retain uncertain effects, borrow
   existing TXT without deleting it and revalidate exact record ownership before
   DELETE. A generic GET404 requires confirmed zone access plus complete listing.
   Only a validated definite provider rejection can retire an unused intent.
   Changed/unknown/foreign state stays pending; there is no blind second POST.
8. `--dns-transactions` is read-only; `--dns-cleanup` is global and locked. Fixed
   mode cannot bypass adaptive receipts. Adaptive initialization retries safe
   recovery. The `cgp-certbot` wrapper verifies lock descriptors, supervises the
   process group and closes stdin; final cleanup requires confirmed quiescence.
   Exact help/version calls remain read-only.
9. The installer copies app-local entry-point metadata and the new wrapper,
   backs up/restores both launchers, preserves DNS receipts and rejects invalid
   settings/dependencies before application/timer changes. It does not rewrite
   Certbot renewal configuration, install global Python packages or force issuance.
10. Unit tests accompany every new module. Real Certbot authorization/entry-point
    contracts, real loopback HTTPS framing and process-group behavior supplement
    synthetic DNS/provider fixtures. Four fresh-process DNS restart scenarios
    cover POST/ID-save and DELETE/completion gaps, uncertain absence and manual
    changes. CI tests compatibility/current APIs separately and keeps 100% gates.

### Review issues addressed in checkpoint 7

- Nonzero manual auth-hook exit can still lead to ACME answer: use the plugin's
  batch perform boundary and test the real Certbot AuthHandler.
- Certbot represents wildcard authorization with its base name: retain original
  requested identifiers for CAA and test a wildcard-only issuewild permission.
- Default DNS RRset grouping hides conflicting singleton records: preserve wire
  records before validation and combine only safe non-singletons.
- A socket idle timeout is not a batch deadline: bound each underlying read/send,
  including trickling HTTP headers, and avoid OS hostname lookup for DoH bootstrap.
- Parent/child shared servers, negative apex answers and child DS denial cannot
  serve as positive delegation evidence.
- Bare HTTP404 and any POST error are insufficient evidence of no side effect:
  confirm absence and distinguish validated provider rejection from uncertainty.
- Cloudflare normalizes TXT content to quoted character strings: send canonical
  quoted values and test exact quoted/legacy matching and consistent empty pages.
- Waiting for only the Certbot leader leaves descendant races: confirm the full
  process group is gone before parent cleanup, including normal leader exit.
- Changing modes, credentials or servers must not silently abandon receipts;
  retain server identity and allowed credential binding with explicit inspection.

### Resume from checkpoint 7

1. Fetch actual branch HEAD, draft PR and checks before editing. Expect five jobs:
   tests (compat), tests (current), installer (2.0.1), installer (2.1.0), package.
   Record the exact tested commit and run, not just a historical green status.
2. Read [docs/DNS.md](docs/DNS.md) for the configuration/trust/ownership contract.
   Preserve all new unit tests and strict 100% statement/branch coverage. Use
   separate environments and coverage data for the two dependency profiles.
3. Remaining validation before RC: disposable real Cloudflare/ACME staging
   exercises for CAA/DNSSEC/delegation, one/multiple accounts, timeout/cleanup,
   renewal reconfiguration and wrapper scheduling. Use synthetic lab domains
   only; no production probe or rollout is authorized by this checkpoint.
4. An uncertain POST with no identifiable record intentionally remains blocked.
   Retain evidence and inspect provider audit history; do not fabricate ownership
   or delete receipts to make automation continue. A future explicit abandonment
   protocol needs its own reviewed evidence/authorization contract.
5. Automatic CGP bootstrap is still separate: obtain a disposable CGP instance,
   establish field removal/cascade/restore semantics and then design a new snapshot
   kind. Existing schema-2 certificate journals keep their effective-value meaning.
6. Complete final review, upgrade/staging evidence and release-candidate notes.
   Merge/release and a production validation window need explicit maintainer
   approval. Stable main and the running server remain on 2.1.0.

The DNS observer set is not global propagation proof, AD is not local signature
validation, and GET-then-DELETE is not provider-side compare-and-swap. Process
death is tested, hardware power loss is not. The legacy fixed authenticator path
does not acquire the new adaptive ownership guarantees. See DNS.md for detailed
limits rather than inferring operational readiness solely from 100% coverage.

## Checkpoint 6 — bootstrap diagnostics (historical)

- Development version: **`2.2.0.dev3`**; draft PR [#2](https://github.com/alphazulu/cgp-certificate-manager/pull/2).
- Completed strict CGP response parsing, explicit/effective readiness diagnostics,
  early issuance refusal and repeated provenance checks for new deployments and
  their in-process recovery. **Automatic bootstrap writes remain disabled**:
  field-specific removal/cascade and restoration semantics need a disposable
  CGP instance. The diagnostic is useful independently of that remaining work.
- Observed complete local suite: **542 tests passed**, Python 3.12.14 / coverage
  7.10.7; **2434 statements, 1012 branches, zero missing or partial, 100%**.
  There are 87 additional tests, including strict/adversarial response handling,
  256 presence combinations within table-driven tests, CLI side-effect checks,
  provenance changes around fsync/TLS and a real expired-certificate fixture.
  The complete suite retains 22 process-death/restart tests and now includes
  10 real OpenSSL/TLS fixture tests. Python compile, installer shell syntax and
  `git diff --check` passed. No coverage exclusions or lowered thresholds.
- Implementation commit: [`2cefcc7deac815c9ac992798d3520c94871fa22a`](https://github.com/alphazulu/cgp-certificate-manager/commit/2cefcc7deac815c9ac992798d3520c94871fa22a).
  [CI 45374434817](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45374434817)
  **passed all four jobs**: tests, installer (2.0.1), installer (2.1.0) and
  package. The test log confirms **542 tests / 2434 statements / 1012 branches /
  100%**. Both container logs confirm the installer scenarios passed, including
  24 unsafe-path refusals per baseline and preservation checks for journals and
  resolution evidence. Docker is unavailable locally; those execution results
  come from CI. This follow-up changes only the handoff and roadmap to record
  the observed implementation run; inspect its own current-head CI on resume.
- Starting HEAD: `be8e2a2ec4c26c32c025a131dfd4785b2efb64f4`, clean on resume.
  [CI 45370875060](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45370875060)
  passed all four jobs for that previous checkpoint, with 455 tests and
  2073 statements / 844 branches / 100%. Historical CI does not validate new code.
- Stable `main` remains `fffbeda39a6adbb1c7ab8e924f4ec2c0089a2a5f` / 2.1.0.
  The development branch is not a production installation or release.

### Checkpoint 6 contract

1. `--bootstrap-check [--domain DOMAIN] [--json]` securely reads configuration
   and CGP without state/lock creation, fsync, configuration migration,
   Cloudflare, Certbot, TLS, recovery, notifications or history. A malformed
   explicit domain is refused before config/remote access. Without a domain,
   the complete `LISTDOMAINS` array and all identifiers are validated before
   reading any domain. Output is metadata only; exit 1 means a blocked/error
   report, exit 0 means every reported domain is eligible (or the list is empty).
2. CGP HTTP acquisition and object parsing are bounded. The parser requires a
   complete object, validates typed values and nested unique keys, and rejects
   truncated, duplicate, trailing or unsupported data. Core effective readbacks
   now use it instead of a regex that could match nested/string/error text.
   XML/custom objects and ambiguous non-ASCII decimal escapes fail closed.
3. Read explicit/effective/explicit/effective and compare the four typed field
   projections, including unsupported values. Unrelated settings changes do not
   cause a false race. On invalid, unavailable or changed replies, origins are
   unknown and missing-field lists are null. Never print response bodies or
   upstream error text. `effective_only` does not identify a default source.
4. Readiness requires all four explicit, nonempty, supported fields to match the
   effective snapshot. Missing, empty, unsupported, inconsistent and changed
   states remain distinct. Strict Base64 and safe string representation are
   required; `default` is not treated as a storable previous value. Readiness is
   not DER/key matching, expiry, trust, PKI activation, write authorization or
   TLS proof. A complete expired snapshot remains structurally eligible.
5. Ordinary issuance/install/repair and plan/doctor check readiness before
   certificate readers and Certbot. Force/retry/shrink flags cannot bypass it.
   Disabled/unavailable skip policy and status/verify purposes remain intact.
   Dry-run remains Certbot staging with DNS side effects and no deployment;
   it is not the pure read-only bootstrap diagnostic.
6. Direct deployment checks before LIVE/crypto; shared apply checks before
   backup/journal, after preparation and applying fsync, on write readback and
   after TLS. Lost readiness retains pending evidence without effective-only
   automatic recovery. Other failure recovery also uses the stricter readback
   after restoring fsync, rollback write and rollback TLS. Default readback for
   standalone schema-2 recovery is unchanged; old evidence is not reinterpreted.
7. No bootstrap write, deletion sentinel, full-domain replacement, schema-3
   journal, absence mask or relaxed operator acknowledgement has been added.
   The vendor evidence and remaining server experiments are recorded in
   [docs/BOOTSTRAP.md](docs/BOOTSTRAP.md), with English/Russian README guidance.

### Review issues addressed in checkpoint 6

- Effective values alone do not preserve explicit presence. Reject known
  effective-only snapshots before issuance rather than installing overrides.
- A regex omission cannot prove absence. Require a complete structured reply
  and reject duplicate/nested/text matches before classifying certificate state.
- A permissive CSV parser can accept a truncated domain list. The new diagnostic
  parses the full array and validates every name before per-domain reads.
- Initial provenance checks are insufficient across fsync. Re-read before
  forward and rollback writes, and after TLS. Tests remove raw fields while
  effective bytes remain unchanged and assert retained evidence/no extra write.
- A detected provenance error must not fall into legacy automatic recovery and
  overwrite an inherited value. Use a distinct readiness error and pass the
  strict readback through the in-process recovery path.
- Keep reports and exceptions free of values, including upstream transport
  errors. Cap response bytes before decoding, not only inside the parser.

### Resume from checkpoint 6

1. Fetch actual branch HEAD, draft PR #2 and current-head CI. Inspect newer
   changes before editing. Confirm tests, installer (2.0.1), installer (2.1.0)
   and package, then record exact commit/run and observed counts. A historical
   run does not validate later commits, including documentation follow-ups.
2. For bootstrap writes, first obtain a disposable CGP test instance and record
   its exact build. Use only synthetic domains and keys. Establish field-level
   `default` removal, cascades, raw/effective presence restoration, restricted
   account behavior and actual SNI/chain behavior. Do not run deletion probes
   on production or infer them from the generic CLI reference.
3. Design a new journal snapshot kind only from those results: explicit presence,
   effective context, narrow set/remove operations, unknown-state refusal and
   unresolved TLS outcomes. Existing schema-2 journals/audits keep their
   effective-value meaning. The current acknowledgement cannot accept absence.
4. If no disposable CGP is available, leave bootstrap blocked and continue the
   independent DNS CAA/DNSSEC/delegation/propagation scope. Add meaningful unit
   tests with every implementation change and retain the strict 100% gate.
5. Finish review, upgrade validation, docs and RC before proposing production
   work. Merge/release still requires explicit maintainer approval, with a
   separate production validation window. No automatic deployment is authorized.

Repeated reads are not server-side CAS and cannot prevent every concurrent or
ABA change. Schema 2 has no historical presence bits; a later standalone
recovery still follows effective values. Synthetic replies prove our reader
and guards, not live CGP acceptance of future removal operations. Process-death
tests do not simulate storage power loss; application installation retains its
separate handled-error rollback boundary.

## Checkpoint 5 — operator resolution (historical)

For current work and continuation use checkpoint 7 above.

- Development version: **`2.2.0.dev2`**; draft PR [#2](https://github.com/alphazulu/cgp-certificate-manager/pull/2).
- Completed explicit, audited operator acknowledgement of exact previous
  settings whose TLS cannot be proved. Code, unit tests, process-death tests and
  documentation are in the same checkpoint.
- Observed complete local suite: **455 tests passed**, Python 3.12.14 / coverage
  7.10.7; **2073 statements, 844 branches, zero missing or partial, 100%**.
  Includes 22 process-death/restart tests (11 for acknowledgement) and 9 real
  OpenSSL/loopback TLS tests. Python compile, all installer shell syntax and
  `git diff --check` passed. Docker is unavailable locally; container execution
  evidence comes from the observed CI below.
- Implementation commit: [`453544496fbd15b35711e5348a1a5b928c646317`](https://github.com/alphazulu/cgp-certificate-manager/commit/453544496fbd15b35711e5348a1a5b928c646317).
  [CI 45370524719](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45370524719)
  **passed all four jobs**: tests, installer (2.0.1), installer (2.1.0) and
  package. Its test log confirms **455 tests / 2073 statements / 844 branches /
  100%**. Both installer logs confirm successful scenarios, including byte/mode/
  owner preservation of completed and incomplete audits and 24 unsafe-path
  refusals per baseline. This follow-up changes only the handoff and roadmap
  to record observed evidence; inspect its own current-head checks on resume.
- Starting HEAD: `ddcd63cc2045b7341f8a0240fa18cdfb065944d4`, clean on resume;
  [CI 45367623871](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45367623871)
  passed tests, both installer baselines and package. Baseline: 386 tests,
  1742 statements / 692 branches / 100%. That historical run does not validate
  this checkpoint's new code.
- Stable `main` remains `fffbeda39a6adbb1c7ab8e924f4ec2c0089a2a5f` / 2.1.0.
  Development is not a production installation or release.

### Checkpoint 5 contract

1. `--acknowledge-restored --domain DOMAIN` is a preview. Both
   `--confirm-transaction TOKEN` and `--reason TEXT` are required to act. Preview
   and submit use the operation lock; malformed flags/reasons fail before
   filesystem or external actions. The console exposes the same flow in domain
   actions and F9, including domains absent from discovery.
2. Only valid schema-2 journals in `prepared` or `restoring`, with matching
   machine/CGP identity and all four actual settings matching `previous`/`both`,
   can be acknowledged. No CGP write, TLS verification or ACME operation occurs.
   The explicit result is `acknowledged_unverified`; no `VERIFIED` UI state is
   produced. Missing fields and unknown/manual/foreign states remain refusals.
3. `Journal.read_snapshot()` binds canonical journal content to a stable secure
   descriptor's dev/inode/size/mtime_ns/ctime_ns. The token includes that witness
   and decision name. Same-content replacement changes the token; completed
   tokens cannot retire another pending instance. Schema 2 stays unchanged.
4. Private `resolutions/<token>/authorization.json` preserves the full original
   journal, witness, decision, reason, UID and UTC time. It is immutable evidence
   of authorization, not successful retirement. Fresh readbacks follow durable
   authorization. Pending deletion and its directory fsync precede a separate
   `completion.json` bound to the authorization digest.
5. An authorization without completion blocks normal recovery and mutations even
   when pending is already absent. Explicit same-token/same-reason retry can
   finish it after fresh checks. Ordinary runs never promote an authorization;
   they only validate and resynchronize already completed evidence before
   allowing later mutations. Orphan authorizations remain visible in transaction
   status as `acknowledging`.
6. Existing evidence is checked and resynchronized on retry, never replaced with
   a different reason or snapshot. Full journal evidence remains outside backup
   pruning and survives installer upgrades/rollback. The installer also refuses
   unsafe audit directories/files before installed-system changes.

### Review issues addressed in checkpoint 5

- A content-only token would replay across two identical schema-2 transactions:
  bind to the opened file instance and reject reuse of completed evidence.
- Authorization alone is not proof of completion. A crash after pending unlink
  must not release the mutation guard; retain a separate incomplete-authorization
  guard and require explicit retry.
- A visible completion can follow a failed final directory fsync. Before later
  remote mutations, validate and resynchronize both completed files and their
  directory chain. Read-only status does not perform that sync.
- JSON `null` is corrupt evidence, not an absent file. Keep missing-file handling
  distinct so corrupt authorization cannot make the guard disappear.
- Reject control characters in the original reason before whitespace trimming;
  keep reasons and full snapshots out of normal output and console previews.

### Resume from checkpoint 5

1. Fetch actual HEAD, draft PR #2 and its checks. Inspect newer changes before
   editing; historical CI never validates a later commit.
2. Confirm the complete 100% statement/branch gate, process-death restart cases,
   both installer baselines with audit preservation/refusal, and package. Record
   exact implementation SHA and observed CI for any new changes. The checkpoint
   above passed all four jobs; a later commit still needs its own checks.
3. Next functional scope after this checkpoint: safe bootstrap when previous
   certificate fields are missing. Establish actual CGP semantics before adding
   writes; preserve fail-closed behavior until those semantics are known.
4. Then address DNS CAA/DNSSEC/delegation and propagation, final review, RC and
   production validation. Explicit maintainer approval remains required for
   merge/release; do not install this development branch on the stable server.

The acknowledgement is an administrative decision, not certificate repair or TLS
proof. It does not reset backoff or bypass bootstrap restrictions. Same-UID/root
concurrent changes remain outside the filesystem trust boundary; no remote CAS
is assumed. Stat-based tokens are not permanent global operation IDs. Full
details are in [docs/RESOLUTION.md](docs/RESOLUTION.md). Process-death tests do not
simulate storage power loss, and application installation retains its separate
handled-error rollback boundary.

## Checkpoint 4 — private storage (historical)

For current work and resume steps use checkpoint 7 above.

- Development version: **`2.2.0.dev1`**; draft PR [#2](https://github.com/alphazulu/cgp-certificate-manager/pull/2).
- Completed ownership, permissions and path checks for private state, config,
  credentials, lock, history, journals and backups. New code and unit tests are
  in the same checkpoint; no coverage exclusions or relaxed thresholds.
- Observed local suite: **386 tests passed**, Python 3.12.14 / coverage 7.10.7;
  **1742 statements, 692 branches, zero missing statements or partial branches,
  100%**. Includes the existing 11 process-death/restart and 8 real OpenSSL/TLS
  tests. `compileall`, shell syntax for all three installer scripts and
  `git diff --check` passed.
- Implementation commit: [`d2bad6e1f3f777bb177e6b007ac861fea927781e`](https://github.com/alphazulu/cgp-certificate-manager/commit/d2bad6e1f3f777bb177e6b007ac861fea927781e).
  Observed [CI 45367278665](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45367278665)
  **passed all four jobs**: tests, installer (2.0.1), installer (2.1.0) and
  package. Logs confirm **386 tests / 1742 statements / 692 branches / 100%**,
  and both installer logs confirm the unsafe-path refusal cases passed.
  Docker is unavailable locally; container execution evidence comes from CI.
- The follow-up commit records this observed result in documentation only.
  Inspect that commit's own current checks on resume; the link above identifies
  the exact tested implementation.
- Previous HEAD `903c79369404bd724f3dc5fedddab89a4f5f99c1` passed
  [CI 45364065834](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45364065834):
  tests, installer (2.0.1), installer (2.1.0) and package. That run validates the
  previous checkpoint, not the new permissions changes.
- Stable `main` and release 2.1.0 remain the production baseline. No development
  install, production certificate change, merge or release is part of this work.

### Completed in checkpoint 4

1. `storage.py` walks paths with directory descriptors and `O_NOFOLLOW`, checks
   opened inodes before reading/writing/truncating, rejects unsafe ancestors,
   unexpected owners, public/special modes, nonregular files and extra hard
   links. Private directories require 0700 or stricter, files 0600 or stricter,
   owned by the effective UID (root when installed). Trusted non-writable 0755
   configuration parents remain supported; private state/backups require the
   stricter policy. Existing objects are never silently chmod/chowned. See
   [storage policy](docs/STORAGE.md).
2. Atomic writes validate the destination before writing and again before
   descriptor-relative replacement, fsync the temporary file and directory,
   and sync parents on retries even if a previous mkdir succeeded. Read-only
   storage inspection creates nothing and performs no fsync; command-level
   locking remains separate.
3. CLI and TUI validate all private state under a common secure lock before
   normal work. Hooks retain the parent-lock exemption while validating their
   storage. Config, credentials, history and backups use the same primitives.
   Direct issuance validates credentials before DNS/Certbot; direct deployment
   checks old backups before remote writes. Pruning validates the complete
   selected list before deleting any entry.
4. TUI config/token writes and config backups use secure atomic storage. Unsafe
   history reports an unavailable message; config/access failures are visible
   rather than silently replaced with defaults.
5. A Python installer wrapper holds the secure operation lock until its shell
   payload and handled rollback finish. The payload validates its inherited
   descriptor. Config, credentials and all state are checked before systemctl,
   application backup or installed-file changes. Both installer baselines have
   18 added refusal cases: wrong mode, symlink and wrong owner for config, token,
   state, lock, backup directory and backup file. These assert that application,
   active timer and pending journal remain unchanged.
6. Tests use real files/descriptors for symlinks, hard links, FIFOs, foreign
   ownership, unsafe modes/ancestors, atomic writes, inherited locking, fsync
   failures and descriptor cleanup. Existing fixtures now explicitly create
   private modes; Certbot `LIVE` is separate from private state.

### Review fixes in checkpoint 4

- Close raw descriptors if `os.fdopen` fails; verify no leak in ordinary and
  atomic private-file paths.
- Retry parent fsync after an earlier mkdir succeeded but fsync failed. A full
  transaction regression proves the retry syncs before its first remote write.
  Fault injection targets the intended file/directory, not an earlier ancestor.
- Validate credential files directly in `core.issue()` before DNS or subprocess
  side effects, rather than relying only on the normal discovery path.

### Resume from checkpoint 4

1. Read ROADMAP.md and this handoff; fetch actual HEAD, PR #2 and CI. Inspect any
   newer changes before editing. Historical CI never validates a later commit.
2. Confirm tests, both installer matrix jobs and package for the current HEAD;
   inspect new refusal cases and journal preservation. Fix failures with
   regression coverage, retain the strict 100% gate, and record exact SHA/run.
3. Next task at checkpoint 4 was to define operator-assisted resolution when the previous
   certificate is expired, invalid, inactive or unverifiable. Preserve unknown
   state refusal and audit evidence; do not add an unreviewed force/delete
   escape. Checkpoint 5 implements the selected semantics with unit/fault tests.
4. Then resolve bootstrap semantics and DNS CAA/DNSSEC/delegation/propagation.
   Keep code, tests, docs and progress together. Finish review and upgrade
   validation before an RC; explicit maintainer approval and a separate
   production validation window remain required for merge/release/deployment.

Storage checks protect against other local users; they do not sandbox concurrent
changes by the same trusted UID/root. Standard Certbot `LIVE` symlinks are
outside this policy. Existing unsafe files require administrator investigation;
the code does not apply recursive permission repairs. The remaining transaction,
remote-concurrency and power-loss limits below still apply.

## Checkpoint 3 — integration (historical)

The following records the preceding implementation. For current results and
next actions use checkpoint 7 above.

- Development version: `2.2.0.dev0`; draft PR [#2](https://github.com/alphazulu/cgp-certificate-manager/pull/2). Stable `main` and release 2.1.0 remain the production baseline.
- Deployment and manual rollback now use the journal/recovery engine. New code was implemented with unit tests in the same working change; no coverage exclusions or weakened thresholds were introduced.
- Last completed pre-integration CI: [45350993726](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45350993726), commit `e5e2d007dd5a64939bb7d124df236fc339553bbb`: 215 tests, 100% coverage, installer and package success.
- Current local complete suite: **303 tests passed**, Python 3.12.14 / coverage 7.10.7; **1506 statements, 652 branches, zero missing statements or partial branches, 100%**. Includes 11 process-death tests and 8 real OpenSSL/loopback TLS tests. `compileall`, `bash -n` for installer and integration script, and `git diff --check` passed.
- Integration commit: [`458c840771722b7c0c94e9fd5f1b93ebde25dd37`](https://github.com/alphazulu/cgp-certificate-manager/commit/458c840771722b7c0c94e9fd5f1b93ebde25dd37). Observed GitHub CI [45363794396](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45363794396): **success** for tests, installer (2.0.1), installer (2.1.0) and package. The test log confirms **303 tests**, **1506 statements / 652 branches / 100%**. Both container upgrade paths checked journal preservation. Docker is unavailable in the local workspace, so installer execution evidence comes from CI.
- The follow-up checkpoint commit changes only ROADMAP.md and this file to record that observed run. Inspect its own current checks on resume; the CI link above identifies the exact tested implementation commit.

### Implemented in this checkpoint

1. `deployment.py` owns shared deployment/rollback orchestration. Durable previous/intended snapshots precede any CGP write; uncertain API responses are checked by readback. Successful restoration includes both settings readback and live TLS proof.
2. Snapshot verification uses recorded leaf/key/chain and separate previous/intended endpoints, independent of mutable Certbot `LIVE`. Normal deployment validates and uses the same captured leaf bytes. Manual rollback inherits global TLS templates unless the domain overrides them.
3. Schema-2 journals validate fields/types and bind to real local machine-id plus configured loopback CLI URL. Read-only reads/listing do not mkdir or fsync. Equal snapshots and cleanup of terminal phases are handled explicitly.
4. CLI `--transactions` and `--recover` operate under the existing lock without Cloudflare discovery. Normal certificate runs recover pending work first. A fresh unresolved transaction blocks the next domain in the same run; direct deployment also refuses any pending domain.
5. Console domain actions plus global **F9** expose inspection and confirmed recovery, including when the discovered domain list is empty. English/Russian labels and minimum-width footer are tested.
6. Fault tests cover file/directory persistence failure, corrupt journals, identity mismatch, interrupted operations, uncertain updates, changed remote settings before/after verification, and retention. Nine subprocess crash checkpoints cover all journal phases plus the gaps after applying/restoring remote settings; two further restart tests refuse corruption and manual third states.
7. Real OpenSSL tests generate disposable certificates/keys and a loopback TLS listener. They cover correct old-chain verification, changed leaf, extra/missing chain, wrong SNI, wrong key, expired certificate and wrong issuer without modifying system trust.
8. Installer CI now tests source-pinned 2.0.1 and 2.1.0 upgrades, reads candidate/baseline versions from source, and asserts pending-journal bytes, owner and modes survive success, rollback and blocked attempts. Tests use synthetic values only.
9. READMEs, CHANGELOG and [docs/TRANSACTIONS.md](docs/TRANSACTIONS.md) describe the new behavior, operational commands, failure semantics and limits.

### Review findings resolved

- A single pre-run recovery pass was insufficient: a later unresolved transaction could allow issuance for another domain. Added a read-only pending guard outside the per-domain exception handler, a guard in direct deployment and a two-domain regression.
- Manual rollback initially omitted global TLS defaults. Added inheritance and tests for configured, missing-domain and explicit-empty overrides.
- Previous-specific SNI, identical snapshots, read-only journal side effects and actual machine-id binding from checkpoint 2 are resolved. Readback is repeated after durable phase transitions and after live TLS checks.

### Resume from here

1. Read ROADMAP.md and this handoff; fetch actual branch HEAD, draft PR #2 and associated CI. Inspect any newer changes before editing. Never assume a historical CI result validates a later commit.
2. Confirm current-head tests, both installer matrix jobs and package job. The implementation checkpoint passed all four jobs; a later commit still needs its own successful checks. Fix any failures with regression tests, retaining the 100% branch/statement gate.
3. Historical next scope was parent state/lock/config/backup permissions (completed in checkpoint 4). Invalid/expired-prior operator resolution, bootstrap semantics and DNS checks/propagation remain open.
4. Run final review and upgrade validation, prepare an RC, then obtain explicit maintainer approval for merge/release and a separate production validation window. Do not install this branch on the stable server as part of development.

### Limits to preserve in future work

- Unknown CGP state is never overwritten. The API has no assumed atomic compare-and-swap, so a WebAdmin write can still race the last readback and update.
- An expired, invalid or inactive previous certificate, or an unavailable old listener, can leave exact settings restored but TLS unverified. Ordinary recovery keeps its journal blocking. Checkpoint 5 adds an explicit audited acknowledgement for exact previous settings; it never treats that decision as TLS proof. Unknown/foreign states still cannot be forced or adopted.
- At checkpoint 3, only journal ownership/mode/path checks were complete. Checkpoint 4 above adds parent state, global lock, configuration, credentials, history and older backups.
- Experimental schema 1 is rejected rather than guessed/migrated. No stable release has used these journals.
- Process-death tests exercise fresh interpreters and real filesystem fsync, not actual storage power loss. TLS integration is local; real CommuniGate/ACME behavior and production renewal remain separately validated.
- The application installer is not protected by the certificate transaction protocol against SIGKILL/power loss. Development package version is deliberately distinct from 2.1.0.

## Transaction design
A single pending transaction per domain. Journal must be durable BEFORE any CGP write. Store prior and intended certificate settings in root-only state, no credentials in metadata or logs. Stages: prepared, applying, applied, verifying, committed; recovery records restoring and restored. Keep pending journal until outcome durably recorded. Crash after remote write but before local phase update is expected. Recovery compares actual CGP fields with both recorded snapshots, never blindly overwrites a third state. If unknown, stop and retain evidence. No assumptions of server-side atomicity or compare-and-swap. Manual concurrent WebAdmin writes cannot be fully excluded; document limitation.

Recovery must use recorded TLS endpoints and the recorded certificate chain, independent of mutable Certbot lineage. Prior settings may be invalid/expired or empty: distinguish readback restoration from successful TLS, retain unresolved state when verification cannot succeed. Read-only commands must never trigger writes. Pending transactions prevent normal mutation until resolved. Installer and CLI share existing flock; do not change stable branch.

## Original session log (historical)
- Confirmed stable HEAD and read existing deployment, rollback, installer and CI code.
- Created development branch, documented roadmap and design.
- Next at that time: implement and test journal primitives, then integrate deployment and CLI. Those tasks are complete in the checkpoints above.

## Checkpoint 1 — journal primitives
- Added cgp_cert_manager/transactions.py: root-only per-domain JSON, atomic replacement, file and directory fsync, validated phase transitions, refusal to remove unresolved records, previous/intended/unknown classification.
- Added tests/test_transactions.py for lifecycle, corruption, permissions, symlink, failed writes and state classification.
- No deployment or CLI integration yet; existing production behavior unchanged. CI/coverage not yet observed for these additions.
- Next: inspect CI, fix any uncovered branches, tighten endpoint/schema validation and server identity binding, then integrate journal with deployment and recovery under existing lock. Do not enable production recovery until fault-injection and TLS tests pass.

## Checkpoint 2 — recovery engine
- Checkpoint 1 CI run 45338136105: 199 tests, 100% measured coverage, installer and package passed.
- Added recovery.py: classify remote state, resume verification or restore previous snapshot, refuse unexpected or changed state, retain unresolved journal on readback or TLS failure. Verify recorded DER chain independently of Certbot. Added local machine/CLI endpoint identity helper and stricter endpoint validation.
- Added recovery and malformed endpoint tests. New CI not yet observed. Recovery engine is not yet called by production deployment or CLI; no mutation behavior changed.
- Known next issues: bind identity to machine-id on integration, choose previous-specific TLS endpoints where SAN changed, ensure terminal-state cleanup handles identical snapshots, add true crash subprocess tests and real OpenSSL fixtures. Review before integration. Keep 100% CI gate.
