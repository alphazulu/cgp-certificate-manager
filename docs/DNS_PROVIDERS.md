# DNS provider contract

Checkpoint 16 (`2.2.0.dev13`, unreleased) centralizes provider operations while
preserving the existing Cloudflare paths. **Cloudflare is the only enabled
provider.** This checkpoint supplies the extension boundary and its isolated
tests; it does not enable RFC2136, PowerDNS, Route53, acme-dns or a new manual
workflow. Stable production remains `2.1.0`.

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

Existing `cloudflare_accounts` entries retain their order and take precedence
over the legacy `cloudflare_credentials` field for discovery and new work.
When the account list is absent or empty, the legacy field remains the source.
Discovery preserves its existing map of zone name to `id`, `credentials` and
`ns`, with the first configured account winning a duplicate zone. Installer
preflight reads and validates each active credential through the adapter.

Fixed-hook cleanup preserves its older allowlist: a retained legacy
`cloudflare_credentials` path remains allowed alongside active account paths.
That compatibility rule does not make the fallback account participate in
discovery, new authentication or adaptive receipt cleanup.

The wizard remains a Cloudflare configuration editor. It refuses an unsupported
provider before opening the menu or staging token files. It still permits
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

`core.zones()` remains a compatibility entry point. The transport remains
`core.cf`, resolved at call time or explicitly injected by the caller, while
the adapter owns Cloudflare endpoints, wire payloads, record IDs, pagination,
matching and response interpretation. Coordinator code in `dnsauth` owns the
durable state machine and filesystem operations rather than Cloudflare fields.

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

## Owned TXT evidence

The existing adaptive invariants are unchanged:

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

## Adding the next backend

RFC2136 is the next independent roadmap item. Its implementation must first
define credential and zone identity, discovery or explicit zone configuration,
supported authentication routes, and its own durable ownership/recovery
evidence. A new adapter must not claim `owned_txt` merely because it can send
an update or delete a TXT value. Cloudflare record IDs and ownership comments
are specific to this adapter and cannot be assumed for another backend.

New implementations must reject unsupported routes, preserve foreign TXT
records, handle uncertain mutations and bind receipts to their original
provider. Contract and failure tests must accompany every new path, retain
both full 100% statement/branch gates, and cover legacy Cloudflare behavior.
The static selector should enable a new provider only after its contract is
implemented and tested. Mixed-provider configuration and real provider
acceptance remain separately scoped work.

All current tests use synthetic transports, local files and isolated processes;
they do not establish real provider or ACME behavior. Real VM/server/provider
acceptance remains deferred under the maintainer's decision. Exact observed
results and the continuation point are in [DEVELOPMENT.md](../DEVELOPMENT.md)
and [ROADMAP.md](../ROADMAP.md).
