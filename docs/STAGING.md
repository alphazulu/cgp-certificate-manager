# Staging acceptance and release evidence

This is an executable-by-an-operator test plan for the unreleased 2.2 branch.
**The external scenarios below have not been executed by repository CI.** Keep
their status pending until evidence from the exact candidate and lab is recorded
in [DEVELOPMENT.md](../DEVELOPMENT.md) and [ROADMAP.md](../ROADMAP.md).

**Maintainer scheduling decision, 2026-11-24:** all tests on a real VM or server
are deferred until a later, separately scheduled acceptance session. Continue
independent implementation, unit tests and isolated CI in the meantime. This
deferral does not turn pending external scenarios into passed checks or enable
automatic bootstrap writes before the CGP semantics have been verified.

The test suite covers synthetic provider/DNS responses, real local TLS, real
Certbot interfaces and process termination. The installer containers use a
systemctl stub. Those results do not establish real Cloudflare behavior, public
DNS propagation, ACME acceptance, a running systemd timer or CGP field removal.

## Independent acceptance tracks

| Track | Resources | What it can establish |
|---|---|---|
| DNS and renewal | Disposable Linux VM, native Certbot, dedicated Cloudflare zone(s)/tokens, ACME staging account | Actual provider API, DNS evidence, challenge lifecycle, recovery and renewal migration |
| CGP deployment/bootstrap | Disposable CGP instance with its exact build recorded, synthetic domains/keys and test TLS clients | Field provenance, write/removal cascades, restoration, SNI/chain and real service behavior |
| External TLS monitoring and delivery | Separate observer VM, allocated TLS/STARTTLS test endpoints and approved test-only SMTP/webhook receivers | Observer trust/network view, live systemd scheduling, receiver acknowledgements, retry/recovery and upgrade behavior |

The DNS track can start without a running CGP instance: standalone `cgp-certbot`
loads the protected manager configuration and uses its server identity, but the
authenticator does not perform CGP discovery or deployment. The manager commands
`--dns-check` and `--dry-run` do use CGP discovery; validate those in the second
track. A placeholder loopback endpoint in a DNS-only lab is not CGP evidence.

## Prepare the DNS lab

1. Use a disposable VM with its own machine identity and an empty manager/Certbot
   installation. Record the candidate commit, OS, Python, Certbot, ACME and
   dnspython versions. Keep the source checkout separate from the installed app.
2. Allocate dedicated DNS names that may be changed for this experiment. Give
   the Cloudflare token access only to the lab zones. For the multiple-account
   case use two genuinely separate credential scopes and include both zones in
   one certificate request. Configure the manager's private credentials and
   schema-2 configuration as described in [DNS.md](DNS.md).
3. Select `dns_preflight: true` and `dns_propagation.mode: adaptive`. Keep
   `timeout_seconds` and `poll_interval_seconds` within the validated ranges.
   Use a real lab contact email. Do not copy production Certbot lineages, hooks,
   timers, manager state, CGP credentials or backup directories into this VM.
4. Install the candidate. Verify `cgp-letsencrypt --version`,
   `cgp-certbot --version`, and empty `cgp-letsencrypt --dns-transactions --json`.
   The exact version commands do not start DNS work. Keep renewal timers stopped
   until the scheduling scenario is reached.
5. Confirm the documented outbound HTTPS and authoritative TCP/53 paths. Leave
   normal TLS verification enabled. Record DNSSEC/delegation/CAA observations
   before making a change, including negative-cache TTLs. Keep an untouched
   foreign TXT value at a challenge owner to check preservation.

Record evidence privately with restrictive permissions. Provider record IDs,
account IDs, raw API/Certbot logs and receipt contents need review before sharing.
Publish only a redacted result summary using synthetic labels. A receipt contains
the validation value; its metadata report is suitable for routine inspection.

## Initial staging issuance and renewal

Set `CGP_LAB_DOMAIN` and `CGP_LAB_EMAIL` to the allocated lab values in the lab
shell. These variables intentionally have no defaults. Run the installed wrapper
as the same administrative user that owns the protected configuration:

```sh
cgp-certbot certonly \
  --server https://acme-staging-v02.api.letsencrypt.org/directory \
  --non-interactive --agree-tos --email "${CGP_LAB_EMAIL:?Set the lab email}" \
  --authenticator cgp-dns --no-directory-hooks \
  --key-type rsa --rsa-key-size 2048 --cert-name cgp-dns-lab \
  -d "${CGP_LAB_DOMAIN:?Set the allocated lab domain}" \
  -d "*.${CGP_LAB_DOMAIN:?Set the allocated lab domain}"

cgp-letsencrypt --dns-transactions --json

cgp-certbot renew --cert-name cgp-dns-lab --dry-run \
  --server https://acme-staging-v02.api.letsencrypt.org/directory \
  --non-interactive --no-directory-hooks

cgp-letsencrypt --dns-transactions --json
```

The initial command deliberately persists a staging-only lineage for renewal
tests. It does not install a certificate into CGP. Staging certificates are not
publicly trusted. Keep any test trust store isolated from normal system trust.
`--no-directory-hooks` does not disable hooks explicitly stored in configuration;
the lab must start without production hooks or inherited deployment commands.

For every successful challenge run, verify the actual authenticator invocation,
expected TXT batch, observer passes, ACME outcome and subsequent record cleanup.
An exit-zero "not due" result or reused authorization that skips the authenticator
does not test challenge creation. Use a new allocated lab identifier/account when
needed and record whether the challenge path actually ran. Do not assume a
certificate's successful issuance proves every requested failure scenario.

## DNS acceptance matrix

For each case record candidate SHA, dependency versions, expected result, actual
result, whether the authenticator ran, whether an ACME challenge was answered,
receipt state after the run/restart, and a private evidence reference.

| Case | Required observation | Status |
|---|---|---|
| One account, apex plus wildcard | All current values observed; challenge succeeds; owned TXT removed; unrelated TXT unchanged | Pending |
| Two credentials/zone scopes in one request | Each record created and cleaned using its selected zone/account; no credential crossover | Pending |
| Normal unsigned delegation | Explicit resolver evidence; a valid unsigned zone is not labelled DNSSEC-bogus | Pending |
| Valid signed delegation | Required DS/DNSKEY evidence reported as resolver-authenticated; successful challenge | Pending |
| Broken DNSSEC in a disposable delegated zone | Refusal before ACME answer; no insecure/CD=1 retry | Pending |
| CAA permits DNS-01 and wildcard issuance | Correct original and wildcard policies; successful challenge | Pending |
| CAA denies issuer/method or has an unknown critical property | Refusal; wildcard policy is not evaluated as the base identifier's policy | Pending |
| Account-bound CAA with unavailable account identity | Conservative refusal unless another independent record grants permission | Pending |
| Wrong parent NS, lame child, challenge CNAME/DNAME or delegated challenge zone | Explicit refusal; no record written into a guessed target zone | Pending |
| Delayed visibility or stale observer | Two fresh complete passes required; a failed intervening pass resets success | Pending |
| Propagation timeout | No ACME challenge answer; owned records cleaned or a pending receipt preserved | Pending |
| Definite provider POST rejection | No blind retry; unused intent retired only from validated rejection evidence | Pending |
| Create response lost after provider acceptance | Exact ownership marker reconciled from a complete, stable listing; no second POST | Pending |
| Missing/changing pagination during reconciliation | No deletion or receipt retirement from incomplete uniqueness evidence | Pending |
| Uncertain POST and no identifiable record | Intent remains pending; repeat cleanup does not fabricate proof of absence | Pending |
| Record changed or renamed before cleanup | Changed record survives; unresolved evidence remains inspectable | Pending |
| Termination during create/delete/receipt transitions | Restart retains or resolves evidence according to ownership; unrelated TXT survives | Pending |
| Parent exits while a descendant remains | Cleanup waits for group quiescence; an unprovable stop retains evidence | Pending |
| Borrowed pre-existing exact TXT | Never deleted by adaptive cleanup | Pending |

Some failures cannot be reliably induced through a real public provider. Record
such a case as **not exercised externally**, with the exact synthetic regression
test as separate evidence. A manipulated local fixture is not a Cloudflare API
observation. Do not mark a case passed solely because CI has 100% coverage.

Before retrying an interrupted case, inspect `--dns-transactions --json` and
provider state. Use `--dns-cleanup` only after any active runner has stopped;
the operation lock remains part of the contract. Do not remove or edit receipts
to obtain a clean result. Uncertain absence and manual changes are expected to
remain blocking until the provider history can be reconciled. No automatic
abandonment protocol is implemented.

## Renewal migration and scheduling

Use a second disposable staging lineage originally configured with the legacy
fixed authenticator. Keep a private copy of its renewal settings before changing
the manager mode. Check that application installation alone leaves those settings
unchanged and that a not-yet-due request does not count as plugin migration.

For the tested Certbot generations, select the lineage explicitly and use
Certbot's reconfiguration operation through the supervised wrapper:

```sh
cgp-certbot reconfigure --cert-name cgp-dns-legacy-lab \
  --server https://acme-staging-v02.api.letsencrypt.org/directory \
  --authenticator cgp-dns --non-interactive --no-directory-hooks

cgp-certbot renew --cert-name cgp-dns-legacy-lab --dry-run \
  --server https://acme-staging-v02.api.letsencrypt.org/directory \
  --non-interactive --no-directory-hooks
```

Record that the original lineage points to staging before starting, that the
reconfiguration test succeeds, that the new authenticator is saved, and that a
separate renewal invocation actually uses it. Repeat the case under both tested
Certbot API generations. Do not hand-edit a production renewal file or force a
production renewal to manufacture migration evidence.

Test a lab-only systemd unit for the explicit staging wrapper command with stdin
closed and the real process supervisor. Inspect its exit status, logs, record
cleanup and next timer activation. Then test overlap with another manager
operation: the second operation must not create/delete TXT while the first owns
the lock. Also verify behavior after a VM restart with pending receipt evidence.
The repository's mocked-systemctl installer scenarios do not substitute for this
test. Before scheduling, account for every existing renewal timer; keep exactly
the intended owner of each lab lineage.

## CGP track and manager integration

Follow [BOOTSTRAP.md](BOOTSTRAP.md#vendor-evidence-and-remaining-write-contract)
for the exact field-removal, cascade and restoration experiments. Record the CGP
build, account rights and listener configuration; tests on another build cannot
silently validate this one. All certificate snapshots and raw settings remain
private even when the domains and keys were created only for the lab.

For manager integration, configure only the disposable CGP domains and tokens.
Run `--dns-check --domain LAB_DOMAIN --json`, `--bootstrap-check --domain
LAB_DOMAIN --json`, and then `--domain LAB_DOMAIN --dry-run`. Check their distinct
side effects: DNS diagnostics do not create state or mutate DNS; bootstrap
diagnostics do not call DNS/provider APIs; staging issuance may create and clean
TXT but does not deploy a certificate. The absence of a restorable old snapshot
must continue to block ordinary deployment, regardless of force/retry flags.

Manager dry-run explicitly selects the Let's Encrypt staging directory even
when Certbot's global configuration specifies another server. Record the
effective endpoint. Inspect global/renewal hook settings separately: this manager
path does not pass `--no-directory-hooks`, and dry-run is not a hook sandbox.

Keep automatic bootstrap disabled until the server experiments support a new
snapshot/restore design. A staging certificate and an empty CGP domain alone do
not satisfy that prerequisite. Do not reinterpret schema-2 journals as recording
historical field presence.

## External TLS monitor and notification acceptance — deferred

This track remains **not exercised**. It needs no running CGP or provider
credentials. Use the candidate's [independent monitor](EXTERNAL_MONITORING.md)
and its [disabled example](../examples/monitor.example.json). A source checkout
can run `python3 -m cgp_cert_manager.monitor_cli`; the complete manager installer
still requires its separate manager configuration and dependencies. Allocate
test-only receivers before permitting `--send`; no production destination is
implied by this plan.

Record the following cases separately, with exact candidate, observer OS,
Python/OpenSSL, trust roots and synthetic endpoint labels:

1. Validate private configuration and credentials, disabled behavior and installed
   `--help`/`--version`. Confirm `--check-config`, `--probe` and `--status` do not
   create observation state or deliver messages. Probe does perform networking.
2. Observe direct TLS and SMTP/IMAP/POP3 STARTTLS with DNS SNI and IP SAN cases.
   Exercise trusted, wrong-name, untrusted, expired, not-yet-valid, CN-only and
   missing/rejected STARTTLS endpoints. Confirm no insecure fallback; failed
   verification must not publish trusted expiry or fingerprint measurements.
   Repeat from the intended external observer's actual resolver/network view.
3. Exercise slow DNS, a stalled TCP/TLS/protocol peer, oversized responses and
   parent termination. Confirm bounded completion, inherited lock retention
   until worker exit, no overlapping state writer and no orphan after handled
   interruption. Process tests do not establish storage power-loss durability.
4. Run without `--send`; inspect fresh, stale, future, corrupt, busy and changed-
   configuration results. Verify that observation times and alert thresholds
   match local policy, and that the previous configuration generation is retained
   without retrying its destinations.
5. With approved test receivers only, explicitly enable one channel at a time
   and use `--run --send`. Check first-healthy suppression, warning/critical
   transitions, reminders, accepted/rejected/uncertain outcomes, same-ID retry,
   per-channel independence and recovery. Inject loss after receiver acceptance
   and before state acknowledgement; record any duplicate and the receiver's
   actual idempotency behavior. Confirm that failed recovery delivery remains
   visible even when the latest TLS observation is healthy.
6. Inspect the real systemd unit and any override before activation. The shipped
   service uses `--run` without `--send`; notification scheduling requires an
   explicit reviewed override. Verify timer cadence, service exit statuses,
   writable-path confinement, logs and recipient content. Make no claim of
   recipient delivery from SMTP or HTTP acceptance alone.
7. Upgrade with both timers and independent monitor state present. Verify busy
   monitor exclusion, refusal of installed `--run` with a custom state directory,
   exact configuration/state preservation, new wrapper/unit
   rollback on handled failure, restoration of previous active timers after
   failure, and both timers stopped after success. Re-enable only the schedules
   explicitly accepted in this lab; keep private backup/evidence files private.
8. For Telegram, use an explicitly approved disposable bot/chat and optional
   forum topic. Confirm actual plaintext, stable event ID, expected chat/topic,
   private token handling, custom API origin/trust if configured, and 429
   cooldown across changed conditions and recovery. Observe server errors and
   lost acknowledgements without assuming deduplication or final reading.
9. For MQTT, use an approved isolated TLS broker and subscriber. Inspect the
   actual event JSON, topic ACLs, QoS-1 acknowledgement, non-retained publication,
   fresh client IDs, reconnect/lost-PUBACK behavior and subscriber deduplication
   by event ID. Check subscriber receipt separately from broker acceptance;
   MQTT 3.1.1 can acknowledge a publication that its authorization policy drops.
   Neither case has been executed against a real bot or broker in this checkpoint.

Prometheus/Grafana/Zabbix deployment acceptance remains a separate pending
track: the current local-exporter assets do not ingest these external
observations automatically. Telegram/MQTT implementation and synthetic loopback
tests are described in [NOTIFICATION_CHANNELS.md](NOTIFICATION_CHANNELS.md);
their real recipient/broker acceptance remains pending with this plan.

## Evidence and release decision

Use the following compact record for each executed case; keep raw evidence in
the private lab storage and reference it by a non-secret label:

```text
Case ID:
Candidate commit / PR:
UTC timestamp / OS / Python / Certbot / ACME / dnspython:
CGP build and rights, if applicable:
Lab topology and credential scope (synthetic labels only):
Expected behavior:
Observed behavior and exit status:
Authenticator invoked / ACME challenge answered:
Receipt phases before and after / foreign record preserved:
Private evidence reference:
Result: passed | failed | not exercised
Remaining limitation or issue:
```

A release candidate needs current-head CI, the applicable lab results, reviewed
upgrade/rollback instructions and an explicit maintainer decision on remaining
limits. Record untested distributions, DNS arrangements and server builds rather
than generalizing from a container or a single domain. Merge, release publication
and a production rollout are separate decisions; this document schedules none.

## Primary references

- [Let's Encrypt staging environment](https://letsencrypt.org/docs/staging-environment/): staging endpoint, separate accounts and test-only trust.
- [Certbot renewal reconfiguration](https://eff-certbot.readthedocs.io/en/stable/using.html#modifying-the-renewal-configuration-of-existing-certificates): the explicit reconfigure operation and persistent renewal settings.
- [Certbot user guide](https://eff-certbot.readthedocs.io/en/stable/using.html): dry-run, hook scopes and command-line options.
- [DNS implementation contract](DNS.md), [CGP bootstrap contract](BOOTSTRAP.md), [private storage policy](STORAGE.md).
