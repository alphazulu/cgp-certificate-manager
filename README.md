# CGP Certificate Manager

[![CI](https://github.com/alphazulu/cgp-certificate-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/alphazulu/cgp-certificate-manager/actions/workflows/ci.yml)

Automatic Let's Encrypt certificate management for CommuniGate Pro on Linux using Cloudflare DNS-01 and the CommuniGate HTTP CLI. Designed for multi-domain mail servers, with automatic discovery of domains and aliases, verified deployment, and rollback.

[Русская документация](README.ru.md)

This branch develops **2.2.0.dev13**. The stable production release is **2.1.0**.
See [ROADMAP.md](ROADMAP.md) and [DEVELOPMENT.md](DEVELOPMENT.md) for completed work,
test evidence and the next checkpoint. The development branch is not a release.
Contributor commands and test boundaries are in [CONTRIBUTING.md](CONTRIBUTING.md).
See [SECURITY.md](SECURITY.md) for reporting and trust boundaries, and the
[staging acceptance plan](docs/STAGING.md) for external validation before RC.
Real VM/server tests are deferred to a later session; independent development
and automated checks continue. The new [local monitoring interface](docs/MONITORING.md)
exports saved state and local certificate expiry without contacting external services.
Optional [monitoring integrations](docs/MONITORING_INTEGRATIONS.md) provide
Prometheus alert rules, a Grafana dashboard and a Zabbix template with synthetic
tests. Their import, collection schedule and notification routing remain
explicit deployment steps.
The separate [external TLS monitor](docs/EXTERNAL_MONITORING.md), `cgp-monitor`,
checks configured TLS and mail STARTTLS endpoints independently of renewal.
It has its own configuration, state and optional timer. SMTP, HTTPS webhook,
[Telegram and MQTT](docs/NOTIFICATION_CHANNELS.md) delivery require explicit
notification settings and `--run --send`; the shipped service does not send,
and installation does not enable its timer.
Repository [release and security checks](docs/RELEASING.md) prepare reproducible
source artifacts, audit resolved dependencies and analyze Python with CodeQL.
The manual release workflow prepares an unpublished draft only after the full
checks; real acceptance and publication remain separate maintainer decisions.
The offline [update command](docs/UPDATES.md), `cgp-update`, verifies and stages
signed packages against separately provisioned local trust. An independent
trusted runtime reviews the complete installed preimage and requires its exact
confirmation token before applying a data-only update. A durable journal and
persistent execution guard support explicit recovery after interruption while
preserving certificate/configuration state. Both timers remain stopped after
apply or recovery. Real signing keys and update activation remain separate
administrator decisions, and real VM/server acceptance is deferred.

The [DNS provider interface](docs/DNS_PROVIDERS.md) now centralizes discovery,
authentication and owned TXT cleanup. Cloudflare is the only enabled provider;
existing configurations keep their meaning without migration. New adaptive
receipts explicitly name Cloudflare, and legacy receipts remain readable.
RFC2136 and other backends are separate roadmap work.

## Why this project exists

A mail server can host many domains and aliases. Renewing certificates manually and importing the correct private key and complete CA chain into every domain is error-prone. This manager connects Certbot to CommuniGate Pro and automates that lifecycle without requesting a server restart. DNS-01 allows wildcard certificates without exposing a separate HTTP challenge listener.

## Features

- Discover primary domains and aliases via LISTDOMAINS and GETDOMAINALIASES.
- Filter IP addresses and invalid DNS names, normalize IDNs to Punycode, remove redundant wildcard-covered names, and match accessible Cloudflare zones.
- Issue and renew RSA certificates with Certbot; support multiple Cloudflare tokens via manual DNS hooks when required.
- Guard against losing existing SANs because a Cloudflare zone became unavailable; compare public DNS delegation and detect challenge CNAMEs.
- Deploy via local HTTP CLI, verify private key, certificate, CA chain and PKI setting; use CertificateType=YES and Base64-encoded concatenated DER for CAChain.
- Verify hostname, trust, and complete ordered TLS chain over HTTPS/SNI by default. Installation and recovery verify captured certificate snapshots; `--verify` compares the live installation with the current Certbot lineage.
- Durably journal prior and intended settings before deployment, recover interrupted transactions, and verify restoration by readback and live TLS. Prune older backups only after a completed installation, retaining five recent backups per domain.
- Validate private configuration, credentials, state, history, backups and lock files; reject unsafe ownership, permissions, links and file types before use.
- Inspect explicit/effective certificate-field readiness without state writes; block incomplete, inherited, empty, unreadable or changing snapshots before ordinary issuance and deployment.
- Separate retry backoff for issuance and deployment, optional SMTP error notifications, JSON status and history, systemd scheduling.

## Requirements

Ubuntu 24.04 LTS is the tested deployment environment. Python 3, dnspython, Certbot, Cloudflare DNS plugin, OpenSSL, iproute2 and systemd are required. Adaptive mode requires native Certbot in the launcher's Python environment and Linux `/proc/self/fdinfo` for held-lock verification; snap Certbot is not supported for that mode. A running CommuniGate Pro instance with an accessible local HTTP CLI and authorized account is required. Cloudflare API tokens need Zone:Read and DNS:Edit for the managed zones. Other CommuniGate versions and distributions should be tested before production use.

Installer CI covers Ubuntu 24.04 and Debian 13 containers with a systemctl stub.
See DEVELOPMENT.md for observed results; this is distinct from live systemd,
CGP and DNS acceptance in the staging plan.

    sudo apt update
    sudo apt install certbot python3-certbot-dns-cloudflare python3-dnspython python3 openssl ca-certificates dnsutils iproute2
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

By default discovered domains are enabled and receive the apex plus first-level wildcard; eligible aliases are included as SANs. Use domains entries to override enabled, wildcard, extra_names, exclude_names, cert_name and tls. Missing Cloudflare zones are skipped; an unavailable primary domain is not issued. The development version requires all four previous certificate fields to be explicit, readable, nonempty and consistent with effective settings before ordinary issuance or installation. Inspect this with `--bootstrap-check`; automatic bootstrap remains disabled. A new domain needs a working certificate prepared by its administrator and verified before automation. Never paste a CA certificate into the leaf certificate field.

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
| --bootstrap-check [--domain DOMAIN] [--json] | Inspect explicit/effective field readiness without state writes, Cloudflare, Certbot or recovery |
| --monitoring | Read-only local JSON snapshot, with explicit missing/error/busy sources |
| --metrics [--metrics-file /absolute/path/cgp-manager.prom] | Prometheus local metrics; optional atomic publication of readable metadata |
| --zabbix-discovery | Zabbix domain discovery; fail without a discovery list if local collection is incomplete |
| --verify | Verify deployed certificates and TLS chains |
| --discover-listeners, --verify-listeners | Diagnose recognized CGServer TLS ports |
| --dry-run | Test issuance against ACME staging |
| --install-only, --repair-chain | Deploy matching local certificates without issuing |
| --domain DOMAIN --retry-now | Bypass retry delay without forcing renewal |
| --domain DOMAIN --reset-backoff | Reset retry delay |
| --backups DOMAIN, --rollback DOMAIN, --backup-file FILENAME | Inspect backups or restore a selected backup |
| --transactions [--domain DOMAIN] [--json] | Inspect pending transaction metadata without recovery |
| --recover [--domain DOMAIN] [--json] | Explicitly recover pending transactions |
| --acknowledge-restored --domain DOMAIN [--json] | Preview acceptance of previous settings with TLS unverified; confirmation requires the preview token and a reason |
| --history, --json, --version | History, structured status, version |
| --force-renew, --allow-shrink | Explicit overrides; use with caution |

## Architecture and storage

The local monitoring commands read existing sources under a nonblocking shared operation
lock and does not perform discovery, recovery or live TLS probes. Unknown
measurements are omitted from Prometheus output; collection failures and source
freshness are explicit. Local leaf expiry does not prove which certificate CGP
serves. See [docs/MONITORING.md](docs/MONITORING.md) for the metric contract,
atomic textfile permissions and discovery failure behavior. No monitoring timer,
Zabbix template or Grafana dashboard is enabled by installation.

`cgp-monitor` observes configured remote endpoints using a separate
`/etc/cgp-monitor/config.json` and `/var/lib/cgp-monitor`. Read
[the external monitoring guide](docs/EXTERNAL_MONITORING.md) and adapt the
[disabled example](examples/monitor.example.json) before the later acceptance
session. `--check-config` validates settings; `--probe` performs a network
observation without saving state or sending; `--status` reads the saved result;
`--run` records a new observation. Only `--run --send` permits configured
notification attempts. These observations do not compare CGP settings or the
served certificate with a local Certbot lineage.

Recover pending work → CGP discovery → Cloudflare zone selection → explicit snapshot readiness → Certbot DNS-01 → captured certificate validation → backup and durable journal → CGP CLI deployment → readback and TLS verification → commit or verified restoration.

### Bootstrap readiness

```sh
cgp-letsencrypt --bootstrap-check --domain example.com --json
```

This development-only command reads the configured loopback CGP without creating
manager state or a lock. It distinguishes fields present explicitly, present
only in effective settings, absent from both replies, inconsistent, and unknown.
It prints field names and fixed reasons, never their values. Invalid or changing
replies do not become claims of absence. Exit status is 1 when any domain is
blocked; an empty or fully eligible list returns 0.

Normal issuance, installation and plan/doctor results require readiness; force
and retry flags cannot bypass it. Direct deployment repeats the checks around
durable transitions and readbacks. A complete expired snapshot is not blocked
merely for expiry, and readiness does not prove live TLS. `--dry-run` keeps its
existing staging/DNS behavior. Automatic first installation remains disabled
pending a disposable-CGP validation of field removal and restoration semantics.
See [bootstrap contract and remaining experiments](docs/BOOTSTRAP.md).

- /opt/cgp-certificate-manager/: application
- /usr/local/sbin/cgp-letsencrypt: CLI launcher
- /usr/local/sbin/cgp-certbot: supervised wrapper for adaptive Certbot operations
- /etc/cgp-letsencrypt/: private configuration and credentials
- /etc/letsencrypt/: Certbot lineages (not replaced by installer)
- /var/lib/cgp-letsencrypt/: discovered domains, state, history, backups and lock
- /var/lib/cgp-letsencrypt/transactions/: pending journals containing private certificate snapshots (directory 0700, files 0600)
- /var/lib/cgp-letsencrypt/resolutions/: private operator authorization and completion evidence, including original transaction snapshots
- /var/lib/cgp-letsencrypt/dns-challenges/: private adaptive TXT ownership and cleanup receipts

### Private-file permissions

The development version requires private state directories to be owned by the process's effective UID with mode `0700` or stricter, and private files to be regular, owned by that UID, mode `0600` or stricter, with one hard link. Installed runs use root. Symbolic links and unsafe ancestor directories are refused. A trusted root-owned configuration parent with mode `0755` remains valid when its private files meet these requirements.

The CLI and installer validate private state before external operations; the installer keeps the validated lock open across its shell payload and handled rollback. Existing unsafe objects are refused without automatic permission or ownership repair. Certbot's standard `live` symlinks are outside this policy. See [private storage policy and metadata-only diagnostics](docs/STORAGE.md) for exact rules and limits before correcting a refused path.

## Interrupted certificate operations

Normal runs, installation-only runs and manual rollback resolve pending transactions before starting new certificate changes. A newly unresolved transaction stops the same batch before another domain can issue or deploy. Read-only diagnostics never trigger recovery. Inspection and explicit recovery also work when Cloudflare discovery is unavailable:

```sh
sudo cgp-letsencrypt --transactions --json
sudo cgp-letsencrypt --recover --domain example.com
sudo cgp-letsencrypt --transactions
```

The global operation lock covers both commands. Transaction inspection prints domain, phase, recognized remote state and server identity match; it does not print private keys. An empty result means no pending journal, not a fresh TLS health check. A successful inspection returns zero even if a row reports `unknown` or `foreign`; recovery failures return nonzero.

Recovery uses the saved settings and saved TLS endpoints, including names from the previous certificate after SAN changes. It never needs the old Certbot lineage. If CGP contains a third, unrecognized set of settings, recovery refuses to overwrite it and retains the journal. If restoration cannot pass TLS verification, its journal also remains pending. See [transaction recovery and limitations](docs/TRANSACTIONS.md) before handling an unresolved operation.

### Accepting previous settings when TLS cannot be proved

For a `prepared` or `restoring` transaction whose actual CGP settings exactly match the recorded previous snapshot, an administrator can explicitly accept the unverified state:

```sh
sudo cgp-letsencrypt --acknowledge-restored --domain example.com --json
sudo cgp-letsencrypt --acknowledge-restored --domain example.com \
  --confirm-transaction TOKEN_FROM_PREVIEW \
  --reason 'Previous certificate expired; administrator accepts unverified settings' --json
```

The first command only previews the decision. The second requires the exact token and a reason, preserves the full journal in private audit storage, and returns `acknowledged_unverified`. It makes no CGP changes and does not claim TLS success. Unknown/foreign states and stale confirmations are refused. An interrupted authorization continues blocking normal recovery and mutations even if its original journal has already been removed; only an explicit retry can finish it. The console exposes the same procedure through domain actions and F9. Read [the full procedure and interruption semantics](docs/RESOLUTION.md) first.

## DNS diagnostics and adaptive propagation

```sh
sudo cgp-letsencrypt --dns-check --json
sudo cgp-letsencrypt --dns-check --domain example.com
sudo cgp-letsencrypt --dns-transactions --json
sudo cgp-letsencrypt --dns-cleanup
```

DNS diagnostics read configuration, discovery and public DNS without creating
state or changing DNS/CGP. Checks cover Let's Encrypt CAA policy, DNSSEC evidence
from Cloudflare/Google over verified HTTPS, actual parent referrals and child
zone/challenge delegation. They do not claim local DNSSEC validation or global
propagation. Unknown account-bound CAA policy, conflicting data and unsupported
challenge aliases/delegations are refused conservatively.

Existing configurations retain fixed waiting. To opt into adaptive mode, add
`"dns_propagation": {"mode": "adaptive", "timeout_seconds": 300,
"poll_interval_seconds": 5}` and keep `dns_preflight` enabled. The authenticator
requires the actual TXT batch at all assigned authoritative NS and both
recursive views for two fresh passes. Timeout stops before ACME challenge
answer. Private receipts preserve exact ownership across interruption; cleanup
does not delete borrowed or manually changed records. The installed
`cgp-certbot` wrapper is required for standalone adaptive renewal.

The update preserves renewal files and does not force issuance or switch the
saved authenticator automatically. Read [the complete configuration, commands,
trust model and recovery limits](docs/DNS.md) before opting in. `--dns-cleanup`
retries cleanup under the manager lock; its two inspection counterparts are
read-only. No production DNS/ACME validation is claimed by the unit suite.

## Safety and limitations

Backups contain private keys; restrict them to root. Rollback is a best-effort API restoration, not a server-side atomic transaction. A verified readback does not guarantee an old broken certificate will become usable. TLS checks require the configured listener to select the domain certificate via SNI; diagnostic checks of other ports can fail by design. CAA preflight is conservative and DNSSEC evidence relies on the selected HTTPS validators; neither replaces the CA's validation. Renewal still depends on DNS and ACME availability. Inspect journals and test changes before enabling unattended operation.

    journalctl -u cgp-letsencrypt.service -n 100 --no-pager
    python3 -m unittest discover -s tests -v

Unit tests isolate CGP, Certbot and systemd. Additional tests exercise real OpenSSL and a local TLS server, and restart recovery in a new process after abrupt termination. These checks do not replace validation against a live CGP instance. Stable 2.1.0 has been checked after a production upgrade; this development version has not.

Independent project; not affiliated with CommuniGate, Cloudflare or Let's Encrypt. No license has been selected yet; repository visibility alone does not grant redistribution rights.

## Optional interactive setup

Install the optional dependency with sudo apt install whiptail. Run sudo bash install.sh --tui for interactive configuration, or sudo bash install.sh --non-interactive with a pre-created config. Existing installations default to preserving configuration. Run sudo cgp-letsencrypt --tui to edit settings later. The wizard supports local CGP authentication, multiple Cloudflare accounts, domain selection, wildcard/SAN overrides, ACME email, DNS delay, TLS defaults and SMTP notifications. New installations default to explicit domain selection. Changes are staged until Save; secrets are entered through the terminal, not command arguments. The wizard does not issue certificates or activate the timer. DNS write permissions require a separate dry-run. The main menu and common prompts support Russian and English; some diagnostic text remains English. Per-domain TLS endpoints and renewal schedule can be edited. After changing the schedule in an installed system, run sudo cgp-letsencrypt --apply-schedule to apply the systemd drop-in; this does not enable an inactive timer. Installation applies the saved schedule automatically.

### Leaving the setup wizard

The first two main-menu entries are Save and exit and Exit without saving. The main-menu Exit button and Escape discard changes only after confirmation when settings have changed. Nested menus have a Back button. Ctrl+C cancels the wizard. Cancelling interactive installation stops before copying application files or systemd units. The standalone editor returns exit status 3 on cancellation, 0 after saving.

## Administrative console

Run `sudo cgp-letsencrypt --console` after installation, or `sudo python3 -m cgp_cert_manager.console` from a checkout. The curses console uses the existing CLI without holding its operation lock. It displays an on-demand status snapshot, systemd timer information, domain details, SANs, and service logs. Enter opens domain actions; F2 opens the whiptail editor; F5 refreshes; F6 opens logs; F7 manages the timer; F8 verifies all domains; F9 opens transaction inspection and recovery; Q, Escape or F10 exits. Certificate mutations, transaction recovery and timer changes require confirmation. Commands execute synchronously with normal terminal output. The console supports English and Russian navigation; actual TLS verification requires an explicit verify action, not merely a ready status.

### Console status and backups

F1 opens help. S cycles sorting and F cycles filters. Colors distinguish ready, verified, expiring, blocked and error states. F8 or the domain verification action records actual TLS results for this console session; refreshing status clears them. Domain history is available in the domain menu. Select a specific backup before confirming rollback, or use `--rollback DOMAIN --backup-file FILENAME`. Rollback now performs live TLS checks against the selected backup; it does not compare that old certificate with a newer Certbot lineage. The domain menu offers scoped transaction actions. F9 also works with an empty domain list and can inspect or recover all pending transactions.

### Installation and upgrade checks

Both terminal interfaces use the saved UI language for common navigation and prompts; technical status codes and some diagnostic text remain English. Run the full test suite, verify the live certificates, and review the installation backup before enabling the timer. The installer checks Python syntax before changing application files. The installer serializes application changes with normal certificate operations and attempts to restore the previous application, configuration and units on handled failures. It leaves the timer stopped after success. The application installer itself is not transactionally recoverable after power loss or SIGKILL; the certificate journal covers certificate operations, not application installation.

## Test suite

Stable 2.1.0 passed 188 unit tests. Development adds unit tests for every new transaction path, process-death/restart scenarios and real OpenSSL/loopback TLS checks. CI enforces `coverage report --fail-under=100` and tests clean installation, upgrades from both 2.0.1 and 2.1.0, rollback, lock handling and journal preservation in disposable Ubuntu containers with mocked systemd. See DEVELOPMENT.md for observed counts and CI results. Coverage does not establish correctness for every live CGP/ACME environment.

The DNS checkpoint adds actual Certbot plugin/authorization tests, DNS wire and
loopback HTTPS tests, process-group supervision and DNS receipt restart cases.
CI tests compatibility and current dependency profiles separately, plus both
installer baselines with certificate/DNS journal and audit preservation.
See [DEVELOPMENT.md](DEVELOPMENT.md) for exact observed counts and CI evidence.
Production validation remains a separate step. Development test requirements
are isolated compatibility fixtures, not production dependency pins.

    python3 -m pip install -r requirements-test-current.txt
    python3 -m coverage run --branch --source=cgp_cert_manager,repo_tools -m unittest discover -s tests -v
    python3 -m coverage report -m --fail-under=100

## Upgrade from 2.0.1

From a separate trusted release checkout, run `sudo bash install.sh --upgrade`, then `sudo cgp-letsencrypt --version`, `--doctor`, `--plan`, and `--verify`. Review the backup path printed by the installer. Only after successful verification run `sudo systemctl enable --now cgp-letsencrypt.timer`. The installer does not issue certificates.
