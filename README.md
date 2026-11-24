# CGP Certificate Manager

[![CI](https://github.com/alphazulu/cgp-certificate-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/alphazulu/cgp-certificate-manager/actions/workflows/ci.yml)

Automatic Let's Encrypt certificate management for CommuniGate Pro on Linux using Cloudflare DNS-01 and the CommuniGate HTTP CLI. Designed for multi-domain mail servers, with automatic discovery of domains and aliases, verified deployment, and rollback.

[Русская документация](README.ru.md)

## Why this project exists

A mail server can host many domains and aliases. Renewing certificates manually and importing the correct private key and complete CA chain into every domain is error-prone. This manager connects Certbot to CommuniGate Pro and automates that lifecycle without requesting a server restart. DNS-01 allows wildcard certificates without exposing a separate HTTP challenge listener.

## Features

- Discover primary domains and aliases via LISTDOMAINS and GETDOMAINALIASES.
- Filter IP addresses and invalid DNS names, normalize IDNs to Punycode, remove redundant wildcard-covered names, and match accessible Cloudflare zones.
- Issue and renew RSA certificates with Certbot; support multiple Cloudflare tokens via manual DNS hooks when required.
- Guard against losing existing SANs because a Cloudflare zone became unavailable; compare public DNS delegation and detect challenge CNAMEs.
- Deploy via local HTTP CLI, verify private key, certificate, CA chain and PKI setting; use CertificateType=YES and Base64-encoded concatenated DER for CAChain.
- Verify hostname, trust, and complete ordered TLS chain against local Certbot files over HTTPS/SNI by default.
- Back up prior certificate settings, attempt rollback on failed deployment, verify rollback readback, and retain five recent deployment backups per domain.
- Separate retry backoff for issuance and deployment, optional SMTP error notifications, JSON status and history, systemd scheduling.

## Requirements

Ubuntu 24.04 LTS is the tested deployment environment. Python 3, Certbot, Cloudflare DNS plugin, OpenSSL, dig, iproute2, systemd. A running CommuniGate Pro instance with an accessible local HTTP CLI and authorized account. Cloudflare API tokens need Zone:Read and DNS:Edit for the managed zones. Other CommuniGate versions and distributions should be tested before production use.

    sudo apt update
    sudo apt install certbot python3-certbot-dns-cloudflare python3 openssl ca-certificates dnsutils iproute2
    git clone https://github.com/alphazulu/cgp-certificate-manager.git
    cd cgp-certificate-manager

## Configuration and installation

Create configuration before running the installer. Do not commit real credentials or copy certificate backups into the repository.

    sudo install -d -m 700 /etc/cgp-letsencrypt
    sudo install -m 600 examples/config.example.json /etc/cgp-letsencrypt/config.json
    sudo install -m 600 examples/cloudflare.example.ini /etc/cgp-letsencrypt/cloudflare.ini
    sudoedit /etc/cgp-letsencrypt/config.json
    sudoedit /etc/cgp-letsencrypt/cloudflare.ini
    sudo bash install.sh

For an existing installation, retain its configuration instead of copying the examples over it. The installer backs up the previous installation, migrates configuration, and leaves the timer stopped. It does not issue certificates. Run from a separate checkout, not from /opt/cgp-certificate-manager.

Configure the CommuniGate HTTP CLI on loopback (example http://127.0.0.1:8100/CLI/) and grant the service account permission to read and update managed domain settings. Restrict CLI access; the manager rejects non-loopback URLs and HTTP redirects. Verify the chosen HTTPS listener supports SNI for the managed names.

By default discovered domains are enabled and receive the apex plus first-level wildcard; eligible aliases are included as SANs. Use domains entries to override enabled, wildcard, extra_names, exclude_names, cert_name and tls. Missing Cloudflare zones are skipped; an unavailable primary domain is not issued. A new installation without all four readable previous CGP fields is deliberately blocked by the backup safety guard: bootstrap a working certificate manually in WebAdmin first, then verify before automation. Never paste a CA certificate into the leaf certificate field.

For multiple accounts use cloudflare_accounts as an array of objects with credentials paths. For optional SMTP alerts configure notifications (to, from, host, port), using a trusted local relay. For non-default TLS listeners specify tls as an array of host, port, sni and optional starttls values globally or per domain; the default is loopback HTTPS 443.

## First run and routine operation

    sudo cgp-letsencrypt --sync
    sudo cgp-letsencrypt --doctor
    sudo cgp-letsencrypt --plan
    sudo cgp-letsencrypt --domain example.com --dry-run
    sudo cgp-letsencrypt --domain example.com
    sudo cgp-letsencrypt --verify
    sudo systemctl start cgp-letsencrypt.service
    sudo systemctl enable --now cgp-letsencrypt.timer
    systemctl list-timers cgp-letsencrypt.timer

Replace example.com with a managed domain. Review the plan before enabling automation. Only disable certbot.timer if no other lineages require it. The manager checks twice daily with randomized delay; Certbot decides ordinary renewal eligibility.

| Command | Purpose |
|---|---|
| --list, --sync, --show-domains | Discover and inspect domains |
| --doctor, --plan, --status | Dependencies, planned actions and status |
| --verify | Verify deployed certificates and TLS chains |
| --discover-listeners, --verify-listeners | Diagnose recognized CGServer TLS ports |
| --dry-run | Test issuance against ACME staging |
| --install-only, --repair-chain | Deploy matching local certificates without issuing |
| --domain DOMAIN --retry-now | Bypass retry delay without forcing renewal |
| --domain DOMAIN --reset-backoff | Reset retry delay |
| --backups DOMAIN, --rollback DOMAIN | Inspect backups or restore latest backup |
| --history, --json, --version | History, structured status, version |
| --force-renew, --allow-shrink | Explicit overrides; use with caution |

## Architecture and storage

CGP discovery → Cloudflare zone selection → Certbot DNS-01 → local verification → backup → CGP CLI deployment → readback → TLS verification → success or rollback.

- /opt/cgp-certificate-manager/: application
- /usr/local/sbin/cgp-letsencrypt: CLI launcher
- /etc/cgp-letsencrypt/: private configuration and credentials
- /etc/letsencrypt/: Certbot lineages (not replaced by installer)
- /var/lib/cgp-letsencrypt/: discovered domains, state, history, backups and lock

## Safety and limitations

Backups contain private keys; restrict them to root. Rollback is a best-effort API restoration, not a server-side atomic transaction. A verified readback does not guarantee an old broken certificate will become usable. TLS checks require the configured listener to select the domain certificate via SNI; diagnostic checks of other ports can fail by design. DNS preflight does not perform full DNSSEC or CAA validation. Renewal still depends on DNS and ACME availability. Inspect journals and test changes before enabling unattended operation.

    journalctl -u cgp-letsencrypt.service -n 100 --no-pager
    python3 -m unittest discover -s tests -v

Unit tests mock API/TLS behavior and are not a substitute for a live integration test. Version 2.0.1 has been verified against a live multi-domain CGP deployment.

Independent project; not affiliated with CommuniGate, Cloudflare or Let's Encrypt. No license has been selected yet; repository visibility alone does not grant redistribution rights.

## Optional interactive setup (2.1 development)

Install the optional dependency with sudo apt install whiptail. Run sudo bash install.sh --tui for interactive configuration, or sudo bash install.sh --non-interactive with a pre-created config. Existing installations default to preserving configuration. Run sudo cgp-letsencrypt --tui to edit settings later. The wizard supports local CGP authentication, multiple Cloudflare accounts, domain selection, wildcard/SAN overrides, ACME email, DNS delay, TLS defaults and SMTP notifications. New installations default to explicit domain selection. Changes are staged until Save; secrets are entered through the terminal, not command arguments. The wizard does not issue certificates or activate the timer. DNS write permissions require a separate dry-run. The main menu and common prompts support Russian and English; some diagnostic text remains English. Per-domain TLS endpoints and renewal schedule can be edited. After changing the schedule in an installed system, run sudo cgp-letsencrypt --apply-schedule to apply the systemd drop-in; this does not enable an inactive timer. Installation applies the saved schedule automatically.
