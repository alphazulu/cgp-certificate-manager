# CGP Certificate Manager

Automatic Let's Encrypt TLS certificate management for CommuniGate Pro on Ubuntu using Cloudflare DNS-01 and Certbot.

The manager discovers CommuniGate domains and aliases, filters IP addresses, checks accessible Cloudflare zones, manages SAN and wildcard certificates, deploys certificate keys and complete CA chains through the CommuniGate CLI, and verifies live TLS connections. It supports scheduled renewal with systemd, backups, rollback and diagnostic commands.

Version 2.0.1. Source distribution and detailed installation documentation are being prepared for publication.
