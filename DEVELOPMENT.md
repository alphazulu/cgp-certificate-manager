# Development checkpoint

Updated 2026-11-24. Branch feature/transactional-deployment; stable base v2.1.0 (fffbeda39a6adbb1c7ab8e924f4ec2c0089a2a5f).

## Current handoff — checkpoint 7

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
- Implementation CI is pending for this source revision. Record the exact
  implementation commit/run after all five GitHub jobs finish; historical green
  runs do not validate this code. Docker is unavailable locally, so execution
  of both disposable installer matrices must be verified from CI.
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
