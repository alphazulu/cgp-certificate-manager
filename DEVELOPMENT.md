# Development checkpoint

Updated 2026-11-24. Branch feature/transactional-deployment; stable base v2.1.0 (fffbeda39a6adbb1c7ab8e924f4ec2c0089a2a5f).

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
