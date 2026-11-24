# Changelog

## 2.1.0 (development)

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
