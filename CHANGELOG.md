# Changelog

## 2.1.0 RC1

- Shared UI language and expanded Russian navigation translations.
- Invalidate stale TLS results before verification.
- Preserve failed inspection rows in JSON output.
- Clean up staged credential files on failed configuration commit.
- Check application syntax before installation.

- Color-coded console status, session TLS results, filters, sorting, help, per-domain history and backup selection.

- Optional curses administration console with domain details, certificate operations, journal and timer controls.

- Optional whiptail setup and post-install configuration editor.
- Explicit domain opt-in for new installations.
- Stage credentials and settings before save; read-only connectivity tests.


## 2.0.1

- Correct PKI activation with CertificateType=YES.
- Multi-certificate CAChain encoded as concatenated DER in one Base64 DataBlock.
- Compare all certificate settings and verify readback after deployment.
- Verify complete ordered TLS chain and hostname over HTTPS/SNI.
- Verify aliases and discover CGServer listeners.
- Attempt rollback and verify restored settings.
- Separate issuance and deployment retry delays; add retry and reset commands.
- Improve status output and clear stale alerts on success.
