# DNS provider contract

The interface introduced in checkpoint 16 preserves Cloudflare compatibility.
Checkpoint 17 adds the explicitly selected [RFC2136 adaptive provider](RFC2136.md).
Checkpoint 18 (`2.2.0.dev15`, unreleased) adds a separate [PowerDNS API
observation](POWERDNS.md), without advertising an issuing capability.
Cloudflare remains the default; PowerDNS HTTP writes, Route53, acme-dns and
another manual workflow remain separate work.
Stable production is `2.1.0`; real provider acceptance remains deferred.

## Selection and credentials

The optional top-level configuration field is:

```json
{"dns_provider": "cloudflare"}
```

Omission has exactly the same Cloudflare meaning. The value is a literal,
case-sensitive string, selected from a fixed implementation; it is never a
module name, command or import path. Unsupported strings and malformed values
refuse before provider or credential use. Selection and credential-path
enumeration do not read token contents, contact an account or mutate settings.

For Cloudflare, existing `cloudflare_accounts` entries retain their order and take precedence
over the legacy `cloudflare_credentials` field for discovery and new work.
When the account list is absent or empty, the legacy field remains the source.
Discovery preserves its existing map of zone name to `id`, `credentials` and
`ns`, with the first configured account winning a duplicate zone. Installer
preflight reads and validates each active credential through the adapter.

Fixed-hook cleanup preserves its older allowlist: a retained legacy
`cloudflare_credentials` path remains allowed alongside active account paths.
That compatibility rule does not make the fallback account participate in
discovery, new authentication or adaptive receipt cleanup.

RFC2136 uses strict `rfc2136.zones` entries for primary, key, private secret path
and public nameservers. See its [configuration and ownership guide](RFC2136.md).
The wizard remains a Cloudflare configuration editor. It refuses other provider
editing before opening the menu or staging token files. It still permits
editing invalid propagation settings. No installer, read-only status operation
or configuration validation automatically inserts the optional selector.

## Capability boundaries

`cgp_cert_manager.dnsproviders.get_provider()` returns the adapter. Its immutable
capability set is checked before the corresponding route is used:

| Capability | Route and contract |
| --- | --- |
| `zone_discovery` | Enumerate configured zones and their assigned nameservers; preserve existing discovery normalization and account precedence. |
| `fixed_native` | Produce the established `dns-cloudflare` arguments for a single credential file and fixed propagation delay. |
| `fixed_hooks` | Create an unowned TXT and clean up through the legacy manual hooks for multiple credentials; retain their original lifecycle. |
| `owned_txt` | Support adaptive receipts, exact record identity and ownership matching, uncertain-create reconciliation, verified deletion and explicit absence proof. |

The issuing route checks the capability it needs before reading credential
files, running preflight or starting Certbot. Adaptive configuration requires
`owned_txt`; fixed configuration selects native or hook capability from the
actual credential set. Source-zone provider tags must match the selected
adapter. Legacy untagged source zones retain their Cloudflare meaning.
Historical public discovery names such as `cloudflare_available` and
`cloudflare_zone_unavailable` are retained for schema compatibility; they
represent availability in the selected provider inventory.

Cloudflare advertises all four capabilities; RFC2136 advertises only
`zone_discovery` (explicit configured inventory) and `owned_txt`. RFC2136 fixed
mode is rejected by shared configuration validation; it uses the existing
supervised adaptive authenticator and propagation checks.

`core.zones()` remains a compatibility entry point. Cloudflare's transport is
`core.cf`, resolved at call time or injected by its caller. The RFC adapter uses
signed DNS TCP and never receives that HTTP transport. Each adapter owns wire
payloads, identities, matching and response interpretation. `dnsauth` retains
the durable state machine and filesystem operations. Its pure
`validate_binding(record)` hook checks provider-specific configuration identity
before credential/state access and validates every saved receipt before cleanup.

## Compatibility of hooks and receipts

| Saved or emitted data | Meaning in this checkpoint |
| --- | --- |
| Fixed metadata with `credentials`, `zone`, `record` | Legacy Cloudflare metadata; accepted only for the configured Cloudflare adapter and an allowed path. |
| Fixed metadata with those fields plus `provider` | Newly emitted metadata; provider must explicitly match Cloudflare. Extra or malformed fields are refused. |
| Adaptive receipt schema 1 | Always Cloudflare, independent of current settings. Read and clean up without migrating its schema. |
| Adaptive receipt schema 2 | The same durable receipt fields plus explicit `provider`; only the supported matching provider is accepted. |

New fixed hooks keep the existing unquoted TXT payload, TTL, delay and
transport-success deletion semantics. They do not acquire the adaptive path's
durable ownership or supervision guarantees. Cleanup remains possible when
propagation options are invalid; an invalid provider or credential binding is
still a refusal.

New adaptive receipts bind the provider, configured absolute credential path,
zone, CGP server identity, exact TXT name/value, attempt and random ownership
marker. Cleanup validates the **complete ledger before any remote deletion**.
A mismatch cannot redirect an old receipt to a newly selected backend. Public
status keeps exactly `id`, `name`, `phase`, `owned` and `zone`; it does not read
credential contents or rewrite receipts.

The credential binding does not hash token bytes or record an inferred remote
account identity. A token can rotate at the same configured path. The current
token must still access the saved zone, and every required remote record and
ownership check must pass. Removing a receipt's path from the active accounts
does not silently transfer its ownership to another credential.

## Cloudflare owned TXT evidence

The existing Cloudflare adaptive invariants are unchanged:

- Save intent before POST. A lost or ambiguous response keeps intent pending;
  an empty search never proves that POST had no effect.
- Borrow an already matching TXT without deleting it later. For uncertain
  creation, require exactly one matching ownership marker in a complete stable
  listing with unique valid IDs before recording the recovered ID.
- Match the exact type, name, value and ownership comment before deletion, then
  require the returned delete acknowledgement to identify the same record.
- Treat only an observed record GET 404 as potential absence. Prove access to
  the exact zone and inspect a complete unfiltered listing before retiring the
  receipt; renamed or foreign records remain visible in that proof.
- Persist completion before removing the receipt. Keep unresolved or unsafe
  evidence for explicit inspection and retry.

Strict listing proof is bounded to 100 pages and checks stable page/count
metadata, total record count and unique IDs. It applies to owned-record
reconciliation and absence proof. Zone discovery retains its previous
pagination behavior and is not a new guarantee of a complete account inventory.
HTTP error streams are closed and provider failures have fixed messages; raw
credential values and provider responses do not enter the manager's errors.

These are local coordination and observation guarantees. They do not create a
provider-side compare-and-swap or prevent a concurrent administrator from
changing a record between observations. See [DNS ownership and process
lifetime](DNS.md) for supervision, propagation and recovery limits.

## RFC2136 ownership and further backends

RFC2136 schema-2 zone IDs bind the configured zone, primary endpoint, key
identity and credential path. Its record reference is an ownership nonce,
not a Cloudflare API ID. It uses an exact full TXT RRset prerequisite, an
in-band owner marker and one persistent generation marker. An old signed
request cannot match a preimage restored by cleanup while that generation
protocol is respected. Remote errors retain uncertainty; absence retirement
also requires an authenticated prerequisite-only update in the original zone.
See [RFC2136.md](RFC2136.md) for complete operational limits and examples.

Further backends must define their own credential/zone identity, supported
routes and durable ownership/recovery evidence. An adapter must not claim
`owned_txt` merely because it can send an update or delete a TXT value.
Cloudflare record IDs/comments and RFC2136 conditional updates are specific
contracts and cannot be assumed for another API.

PowerDNS `EXTEND` and `PRUNE` operate on individual values, but cannot by
themselves distinguish a newly acquired challenge from an identical value
inserted by another writer. An RRset comment or independently added nonce does
not close that race. `--powerdns-check` therefore remains an independent GET-only
observation; `dns_provider: "powerdns"` is not accepted. Its informational target
binding is not a receipt. See the [concrete interleaving and continuation
requirements](POWERDNS.md).

New implementations must reject unsupported routes, preserve foreign TXT
records, handle uncertain mutations and bind receipts to their original
provider. Contract and failure tests must accompany every new path, retain
both full 100% statement/branch gates, and cover legacy Cloudflare behavior.
The static selector should enable a new provider only after its contract is
implemented and tested. Mixed-provider configuration and real provider
acceptance remain separately scoped work.

All current tests use synthetic transports, local files, loopback fixtures and isolated processes;
they do not establish real provider or ACME behavior. Real VM/server/provider
acceptance remains deferred under the maintainer's decision. Exact observed
results and the continuation point are in [DEVELOPMENT.md](../DEVELOPMENT.md)
and [ROADMAP.md](../ROADMAP.md).
