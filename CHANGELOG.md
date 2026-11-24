# Changelog

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
