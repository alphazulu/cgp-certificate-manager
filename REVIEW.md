# 2.1.0 review / test coverage

Reviewed source at 67cc152f36c9dfe5612f3a32768f5a2e56ca5c17. This is a risk-based review, not a security certification. Final RC commit 6b75b01b5e1f01f20621126695930461f47c65a8 passed both CI jobs (run 45335854496), including 188 unit tests and strict 100% coverage.

## Findings fixed in this change

- High: read config only after acquiring operation lock (except Certbot child hooks).
- High: reject invalid backup PKI, mismatched key, malformed CA DER and untrusted chain before manual rollback.
- High: attempt recovery on KeyboardInterrupt during deployment or manual rollback.
- Medium: avoid notifications/state writes on diagnostic discovery failure; no discovery cache update in diagnostic/dry-run mode.
- Medium: require all fields for exact rollback readback.
- Medium: retain explicit SNI in mixed endpoint templates and close child stdin for OpenSSL.
- Medium: display failed TLS checks even when certificate identity cannot be read, tolerate malformed history entries.
- Test infrastructure: branch/line coverage report and XML artifact in CI.

## Remaining release risks

- No durable transaction journal for SIGKILL/power loss; Ctrl+C handling is best effort.
- Manual rollback checks backup cryptography and API readback but not live TLS automatically.
- First deployment of a domain without all four readable fields still requires manual bootstrap.
- Installer concurrency and handled failure recovery passed isolated container tests; no durable transaction journal for sudden power loss.
- Full DNSSEC/CAA/delegation validation and token lifecycle cleanup remain outside this change.
- Clean install and upgrade passed in disposable Ubuntu with mocked systemd. Actual systemd execution and live CGP/ACME still require deployment verification.
- Coverage is enforced by CI; 100% measured coverage does not prove absence of defects.
