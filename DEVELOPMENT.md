# Development checkpoint

Updated 2026-11-24. Branch feature/transactional-deployment; stable base v2.1.0 (fffbeda39a6adbb1c7ab8e924f4ec2c0089a2a5f).

## Current handoff — checkpoint 4

- Development version: **`2.2.0.dev1`**; draft PR [#2](https://github.com/alphazulu/cgp-certificate-manager/pull/2).
- Completed ownership, permissions and path checks for private state, config,
  credentials, lock, history, journals and backups. New code and unit tests are
  in the same checkpoint; no coverage exclusions or relaxed thresholds.
- Observed local suite: **386 tests passed**, Python 3.12.14 / coverage 7.10.7;
  **1742 statements, 692 branches, zero missing statements or partial branches,
  100%**. Includes the existing 11 process-death/restart and 8 real OpenSSL/TLS
  tests. `compileall`, shell syntax for all three installer scripts and
  `git diff --check` passed.
- CI for this permissions checkpoint is pending. Docker is unavailable locally;
  do not claim the new container cases passed before observing their CI jobs.
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
3. Next functional task: define operator-assisted resolution when the previous
   certificate is expired, invalid, inactive or unverifiable. Preserve unknown
   state refusal and audit evidence; do not add an unreviewed force/delete
   escape. Implement the selected semantics together with unit/fault tests.
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
next actions use checkpoint 4 above.

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
- An expired, invalid or inactive previous certificate, or an unavailable old listener, can leave exact settings restored but TLS unverified. The pending journal remains blocking, including a crash in `prepared` with an already broken previous certificate. There is no force/adopt/cancel-without-proof mode yet.
- At checkpoint 3, only journal ownership/mode/path checks were complete. Checkpoint 4 above adds parent state, global lock, configuration, credentials, history and older backups.
- Experimental schema 1 is rejected rather than guessed/migrated. No stable release has used these journals.
- Process-death tests exercise fresh interpreters and real filesystem fsync, not actual storage power loss. TLS integration is local; real CommuniGate/ACME behavior and production renewal remain separately validated.
- The application installer is not protected by the certificate transaction protocol against SIGKILL/power loss. Development package version is deliberately distinct from 2.1.0.

## Transaction design
A single pending transaction per domain. Journal must be durable BEFORE any CGP write. Store prior and intended certificate settings in root-only state, no credentials in metadata or logs. Stages: prepared, applying, applied, verifying, committed; recovery records restoring and restored. Keep pending journal until outcome durably recorded. Crash after remote write but before local phase update is expected. Recovery compares actual CGP fields with both recorded snapshots, never blindly overwrites a third state. If unknown, stop and retain evidence. No assumptions of server-side atomicity or compare-and-swap. Manual concurrent WebAdmin writes cannot be fully excluded; document limitation.

Recovery must use recorded TLS endpoints and the recorded certificate chain, independent of mutable Certbot lineage. Prior settings may be invalid/expired or empty: distinguish readback restoration from successful TLS, retain unresolved state when verification cannot succeed. Read-only commands must never trigger writes. Pending transactions prevent normal mutation until resolved. Installer and CLI share existing flock; do not change stable branch.

## Session log
- Confirmed stable HEAD and read existing deployment, rollback, installer and CI code.
- Created development branch, documented roadmap and design.
- Next: implement and test durable journal primitives; then integrate with existing core.deploy and CLI. Do not mark integration complete before tests and CI.

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
