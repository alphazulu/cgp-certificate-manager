# DNS preflight and adaptive DNS-01

This describes the unreleased `2.2.0.dev4` development checkpoint. Stable
production remains `2.1.0`. The DNS checks do not enable CGP bootstrap writes
or remove any certificate transaction/readiness gate.

## Operator commands

```bash
cgp-letsencrypt --dns-check
cgp-letsencrypt --dns-check --domain example.com --json
cgp-letsencrypt --dns-transactions --json
cgp-letsencrypt --dns-cleanup
```

`--dns-check` reads the protected manager configuration, Cloudflare zone
metadata, CGP discovery and public DNS. It does not create STATE or a lock,
save discovery, write DNS/CGP, issue certificates, recover transactions or send
notifications. An explicit invalid domain is rejected before configuration or
network access. Exit 0 means all reported domains passed, including an empty
domain list; exit 1 means a blocked report or command failure. Disabled domains
are still included in this requested diagnostic. Unavailable identifiers
prevent a ready result instead of silently validating a reduced SAN set.

Reports contain public DNS names, resolver/evidence labels and fixed reason
codes. They contain no certificate values, TXT validation values, credentials
or raw provider/DNS error text. `preflight_enabled` records whether ordinary
issuance applies the automatic gate; the diagnostic runs even when that flag
is false. Status, TLS verification and bootstrap diagnostics do not start the
new DNS checks.

`--dns-transactions` reads validated receipt metadata without creating state,
locking, DNS/provider calls or cleanup. `--dns-cleanup` is an explicit operation
under the global manager lock; it retries only the evidence-based cleanup
described below. Both commands have global scope and reject `--domain`.

## Configuration and compatibility

Existing configurations keep their fixed delay and existing authenticator:
one credentials file uses `dns-cloudflare`; multiple credentials files retain
the manual hooks. The absence of `dns_propagation` means `fixed`. The wizard's
current prompts and defaults are unchanged. New adaptive mode is selected
explicitly in the protected JSON configuration:

```json
{
  "dns_preflight": true,
  "propagation_seconds": 60,
  "dns_propagation": {
    "mode": "adaptive",
    "timeout_seconds": 300,
    "poll_interval_seconds": 5
  }
}
```

The snippet is a fragment, not a replacement for the complete configuration.
The three propagation object keys are strict. Modes are `fixed` and `adaptive`;
numeric settings require integers, not booleans or strings. Fixed delay is
10–3600 seconds; adaptive timeout is 30–3600; interval is 1–60 and less than
the timeout. `propagation_seconds` retains its fixed-mode meaning; it does not
become an adaptive timeout or an additional sleep. Validation is shared by
issuance, diagnostics, auth hooks, wizard Save and installer preflight.
Cleanup remains available when new DNS settings are invalid.

Fixed mode retains the existing explicit `dns_preflight: false` opt-out.
Adaptive mode requires preflight and rejects that combination before issuing.
Force renewal, retry and staging do not bypass an enabled DNS gate. Install-only
and certificate repair do not issue and therefore do not need DNS preflight.
The gate runs before Certbot, after credential-file validation. It may detect
DNS faults even when a certificate is not yet due for renewal.

The installer never changes existing renewal configuration files or forces a
renewal to select a different plugin. A not-yet-due result does not prove that
Certbot saved new renewal parameters. Test a change in a disposable staging
environment; Certbot's explicit `reconfigure` workflow is a separate operator
operation, not an automatic upgrade step.

## Recursive transport and DNSSEC evidence

Queries use RFC 8484 DNS wire messages through these explicit validating
services:

| View | HTTPS hostname | Direct IPv4 endpoint |
|---|---|---|
| Cloudflare | `cloudflare-dns.com` | `1.1.1.1:443` |
| Google | `dns.google` | `8.8.8.8:443` |

TLS verifies the normal hostname and system CA trust; SNI and Host retain that
hostname. Literal connection addresses avoid an unbounded local DNS bootstrap.
There are no HTTP redirects, proxy inheritance, plaintext fallback or CD=1
retry. A deadline-aware socket reader sits below the standard HTTP parser, so
slow headers/body chunks cannot extend a request's monotonic budget. Response
wire size is limited to 65,535 bytes. The question, ID, QR/opcode, RA, CD/TC,
class and RCODE are checked. Duplicate singleton records are rejected before
non-singleton RRsets are combined; this avoids library normalization hiding a
conflicting CNAME. Untrusted zone-file/presentation text is never parsed.

Each preflight has a 120-second and 2,048-query budget; individual network
queries use at most four seconds and the remaining batch time. These limits
can conservatively reject a large or slow domain set. The present transport
requires IPv4 access to both HTTPS endpoints and TCP/53 access to authoritative
NS. Authoritative addresses are resolved through the HTTPS views; private,
loopback and otherwise non-global addresses are refused. One working address
per NS is sufficient, but every assigned NS must provide a valid observation.

DNSSEC is **not validated locally**. Reports distinguish:

| Evidence | Meaning |
|---|---|
| `secure_by_resolver` | The authenticated recursive service asserted AD for the required evidence. |
| `no_ds_by_resolver` | It asserted AD on a negative DS response from the parent side. |
| `not_authenticated` | AD did not establish authentication; this does not prove an unsigned or bogus zone. |

Signed-delegation evidence requires authenticated DS and DNSKEY answers;
unrelated answers or a child claiming its own lack of parent DS are refused.
Existing unsigned delegations remain usable. SERVFAIL and other DNS errors
block the preflight; they are not automatically labelled DNSSEC-bogus. Numeric
Extended DNS Error codes are retained where available, and EDE 6 is an explicit
resolver-bogus refusal. Merely requesting DNSSEC records is not validation.

## CAA policy

Each requested certificate identifier is evaluated from both recursive views
for Let's Encrypt and `dns-01`. Wildcard policy is evaluated as wildcard policy,
including when Certbot represents the corresponding authorization by its base
domain. The current implementation deliberately does not guess an ACME
account URI from an email, directory path or production/staging choice.

The lookup follows RFC 8659: remove `*.` for DNS lookup, handle CNAME/DNAME,
stop at the first nonempty CAA set, and otherwise walk the original name's
parents. Alias-target parents are not searched. Limits are 64 CAA queries,
16 aliases per lookup and 128 CAA records. Alias loops, contradictory records,
unrelated answer data and incomplete referrals are indeterminate. Terminal
negative answers must contain one ancestral SOA; bare empty NODATA replies
are conservatively refused, even though such replies can occur in DNS.

For wildcard identifiers, any `issuewild` set overrides `issue`. Applicable
records are alternatives; a valid unrestricted permission can authorize even
when another record does not. Unknown critical properties block; the Let's
Encrypt profile recognizes both critical bit 128 and its compatibility bit 1.
The issuer and parameter spelling is not silently normalized into permission.
`validationmethods` must permit `dns-01`. Account-bound permission without the
actual account URI and unsupported parameters are indeterminate unless another
independent applicable record authorizes issuance. A preflight permission is
an observation of policy, not a promise that the CA will issue.

## Delegation and TXT propagation

Checks compare Cloudflare's configured nameservers with every observed parent
referral, the recursive apex NS set and every child NS's authoritative apex
NS/SOA answers. A child-apex answer from a server also hosting the parent does
not prove the parent referral and is refused. Missing provider nameservers,
lame servers, contradictory responses and more-specific challenge zone cuts
cannot produce a ready result. CNAME/DNAME or NS delegation at the challenge
owner is diagnosed as unsupported by this writer; ACME itself can support
such arrangements, but the manager does not write into a guessed target zone.

Adaptive issuance uses the `cgp-dns` Certbot authenticator. It creates the
**actual current batch** of challenges, then checks the expected TXT values at
every assigned authoritative NS and both recursive views. Multiple TXT records
and the separate values for apex/wildcard are supported; unrelated TXT values
remain untouched. Chunks within one TXT record are joined, never different
records. Two consecutive fresh complete passes are required. A stale or failed
pass resets success; NXDOMAIN/NODATA, errors and foreign TXT are never success.
One monotonic deadline covers the whole polling batch, including its queries
and sleeps. There is no second Certbot attempt with a longer delay.

A failure raises from `Authenticator.perform()` before Certbot answers ACME
challenges. This boundary matters: the manual authenticator logs a failing
auth hook and can continue, so nonzero hook exit alone is not a reliable gate.
The fixed legacy hooks retain their old lifecycle; they do not gain the
adaptive mode's ownership/supervision guarantees.

Successful polling means observed readiness at these views and addresses.
It does not prove global propagation across all anycast locations or every CA
vantage point. No production DNS or ACME queries are part of the unit suite.

## Ownership, recovery and process lifetime

Adaptive mode stores private `STATE/dns-challenges/*.json` receipts with the
selected credentials/zone binding, server identity, exact TXT name/value and
a random ownership comment. Values stay in the private receipt, not reports
or command arguments. Files are 0600, directories 0700, with the shared
ownership/link/path checks and atomic file/directory fsync rules.

Intent is durable **before POST**. The returned record ID is durable before
proceeding. A pre-existing identical TXT is borrowed and never deleted. A lost
create response is recovered only by finding the exact name/value/ownership
comment; no blind second POST occurs. A definite validated provider rejection
can retire an unused intent; transport failures, ambiguous/server errors and
an absent result after an uncertain POST keep the receipt pending.

The API receives the 43-character DNS-01 value as one canonical quoted TXT
string. Ownership matching accepts that exact quoted value or its exact legacy
unquoted representation; it does not loosely strip escapes or arbitrary quotes.
An empty provider page may report zero or one total pages; zero is accepted
only with consistent first-page/empty/count-zero metadata.

Before deletion, the API record ID, zone, type, name, value and ownership
comment must still match. A generic GET 404 alone is insufficient evidence of
absence: zone access and a complete bounded listing must confirm it. Changed
records are retained; cleanup continues for other receipts and reports any
unresolved work. Completion is persisted before removing the receipt; repeated
cleanup after a crash is idempotent. A foreign server identity or unsafe receipt
prevents remote cleanup before any API mutation.

Adaptive startup retries safe pending cleanup under the operation lock. Fixed
mode refuses pending adaptive receipts, so changing modes cannot bypass them.
Use `--dns-transactions` and `--dns-cleanup` for explicit inspection/retry.
If an uncertain POST still has no identifiable record, or a record has been
changed manually, retain the receipt and reconcile provider state and its audit
history before further work. There is no automatic abandonment or claim that
an uncertain request never happened. Do not edit receipts to manufacture
ownership or silence a refusal.

The installed `cgp-certbot` wrapper and manager adaptive launch use the same
Python/Certbot environment and hold the manager lock. The internal child must
prove its inherited descriptor names that lock; an environment flag cannot
bypass locking. The parent starts a separate process group with closed stdin,
terminates it with bounded TERM/KILL handling on failure, and performs final
recovery only after the group is gone. If quiescence cannot be established,
cleanup evidence remains pending. Exact help/version invocations are read-only.

For standalone renewal of a lineage configured with `cgp-dns`, use the installed
`cgp-certbot renew` wrapper. The app-local plugin metadata does not install into
global Python site-packages. Plain `certbot renew` or snap Certbot may not see
the plugin and are not substitutes for the wrapper. Native Certbot must be
available in `/usr/bin/python3` for the installed adaptive path. Existing fixed
renewal configuration is preserved. Do not add a second renewal timer blindly.

The receipt is not a distributed lock, and read-then-delete is not provider-side
compare-and-swap. A concurrent administrator can still change DNS between
observations. Same-UID/root modification is outside the private-file boundary.
Process-death tests prove restart handling, not hardware power-loss guarantees.
Certbot and third-party plugins also maintain their own logs; the manager's
secret-free report contract does not promise redaction of every third-party log.

## Validation and references

Tests accompany each implementation module. They cover DNS wire corruption,
real loopback TLS/HTTP framing, slow streams, CAA matrices, parent/child cuts,
TXT batches, definite/uncertain provider failures, exact cleanup, abrupt process
death and actual Certbot challenge/entry-point contracts. CI runs both the
Ubuntu-generation compatibility fixture and current Certbot/dnspython APIs,
with 100% measured statements and branches. The compatibility requirements file
is a test fixture, not a recommendation to pin old packages in production.
Use maintained distribution security updates. Exact observed counts, commits
and CI runs are recorded in [DEVELOPMENT.md](../DEVELOPMENT.md).

- [RFC 8659: CAA](https://www.rfc-editor.org/rfc/rfc8659.html)
- [RFC 8657: account and method bindings](https://www.rfc-editor.org/rfc/rfc8657.html)
- [Let's Encrypt CAA guidance](https://letsencrypt.org/docs/caa/)
- [Let's Encrypt DNS-01 guidance](https://letsencrypt.org/docs/challenge-types/)
- [Boulder CAA implementation](https://github.com/letsencrypt/boulder/blob/main/va/caa.go)
- [Cloudflare DNS wire DoH](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-wireformat/)
- [Google secure transports](https://developers.google.com/speed/public-dns/docs/secure-transports)
- [Certbot plugin development](https://eff-certbot.readthedocs.io/en/stable/contributing.html)
- [Certbot renewal/reconfiguration](https://eff-certbot.readthedocs.io/en/stable/using.html)
- [Cloudflare denied-response envelope](https://developers.cloudflare.com/changelog/post/2026-08-20-contextual-403s/)
- [Cloudflare TXT representation](https://developers.cloudflare.com/dns/manage-dns-records/reference/dns-record-types/#txt)
