# Bootstrap readiness

Version **2.2.0.dev3** adds diagnostics and early refusal for certificate states
that the existing transaction format cannot safely capture. It does **not**
enable automatic first installation into absent, inherited or empty settings.
That write contract remains an open item in [ROADMAP.md](../ROADMAP.md).

## Inspect a domain without changing manager state

```sh
cgp-letsencrypt --bootstrap-check --domain example.com --json
cgp-letsencrypt --bootstrap-check
```

The first form inspects the named domain. Without `--domain`, the command lists
domains directly from CGP and validates every returned identifier before reading
any domain settings. JSON output is an array, including for a single domain.
Exit status is 0 when every reported domain is eligible (also for an empty list),
1 when any domain is blocked or inspection fails, and 2 for invalid CLI syntax.

Only the private manager configuration and the configured loopback CGP CLI are
needed. This path performs no Cloudflare discovery, DNS query, Certbot invocation,
TLS probe, recovery, notification, history write or configuration migration. It
does not create a state directory, acquire/create `run.lock`, or call `fsync`.
The configuration read still enforces the [private-storage policy](STORAGE.md).

Four reads are made per inspected domain, in this order:

1. Explicit domain settings.
2. Effective domain settings.
3. Explicit settings again.
4. Effective settings again.

The four certificate fields, including their types and presence, must be stable
between repetitions. Changes to unrelated settings do not invalidate that
comparison. Repeated reads are an observation, not a lock, transaction or
server-side compare-and-swap. Another administrator can change settings after
the final read, or change them and back between reads.

## Report contract

Reports expose field names and fixed diagnostic codes. They never contain
private-key values, certificate payloads, raw settings bodies or remote error
messages. The separate internal snapshot is not serialized into the report.

| Field | Meaning |
|---|---|
| `response_status` | `ok`, `invalid_response`, `unavailable` or `changed` |
| `origin` | One classification for each of the four certificate fields |
| `missing_explicit_fields` | Names absent from the complete, stable explicit replies |
| `missing_effective_fields` | Names absent from the complete, stable effective replies |
| `unreadable_fields` | Present fields whose type or encoding cannot be represented safely |
| `empty_fields` | Present empty values, distinguished from missing fields |
| `snapshot_complete` | Effective fields form a complete, supported, nonempty structural snapshot |
| `explicit_snapshot_complete` | Explicit fields independently form such a snapshot |
| `deployment_ready` | Both snapshots are eligible and their four fields agree |
| `automatic_bootstrap` | Always `false` in this checkpoint |
| `blocking_reason` | A fixed refusal code, or `null` for an eligible snapshot |

`origin` has the following values:

| Value | Observation |
|---|---|
| `explicit` | Field appears with the same typed value in both replies |
| `effective_only` | Field appears only in the effective reply; its default source is not identified |
| `absent` | Field appears in neither parsed reply |
| `inconsistent` | Explicit and effective replies disagree on presence or value |
| `unknown` | Responses could not be parsed/read safely, or changed during inspection |

Presence here means presence in replies available to the configured account.
It does not prove that the account can modify a setting or that an omitted value
was not hidden by server access rules. A malformed response never becomes a
claim of absence: both missing-field lists are `null`, origins are `unknown`,
and no internal snapshot is returned.

Refusal codes are `response_unavailable`, `invalid_response`, `changed`,
`inconsistent`, `unreadable_fields`, `empty_fields`, `missing_effective_fields`
and `missing_explicit_fields`. They are safe to retain in operational output.

## What readiness permits

An eligible previous snapshot has all four fields explicitly present, supported,
nonempty, and equal to their effective values:

- `PrivateSecureKey`, `SecureCertificate` and `CAChain` are canonical Base64
  DataBlocks.
- `CertificateType` is a string representable by the existing safe atom syntax.
  The removal sentinel `default` is refused regardless of letter case.

Readiness checks structure and provenance. It does not validate DER, key matching,
certificate expiry, trust, SANs, PKI activation, write permissions or served TLS.
Those checks retain their existing places in inspection, deployment and recovery.
A complete expired or inactive previous snapshot is therefore not rejected
merely because of expiry or activation. Restoring it may still leave TLS
unverified and require the separate [operator-resolution procedure](RESOLUTION.md).

Before ordinary issuance, installation, chain repair or a plan/doctor result,
the CLI checks readiness. An eligible-domain refusal appears as `BLOCKED` and
prevents Certbot and deployment. `--force-renew`, `--retry-now` and
`--allow-shrink` do not bypass it. Disabled or unavailable domains retain their
existing skip policy. Direct deployment and manual rollback also require a
fresh eligible snapshot; shared transaction application checks again before
creating its backup and journal, after durable preparation and the applying
transition, on write readback, and after TLS verification. If provenance is lost
after a journal exists, that journal remains pending and the operation does not
invoke effective-only automatic recovery. A separate readiness check also
guards restoration after other failures, such as a failing TLS probe.
That in-process recovery uses the same strict reader after the restoring-phase
fsync, after the rollback write and after its TLS check. A detected unset during
those steps cannot silently become an explicit override or retire the journal.

`--status`, `--verify` and `--verify-listeners` retain their certificate/TLS
inspection purpose. A successful TLS result is not a readiness result.
`--dry-run` retains its existing Certbot staging behavior, which can create DNS
challenges; it is not equivalent to this read-only diagnostic and does not
perform a deployment-readiness gate.

## Complete parsing and compatibility

CGP HTTP replies are capped at 1 MiB before decoding. The object parser also
limits bytes, nesting and object count. It accepts documented primitive types,
arrays, dictionaries, comments and quoted string escapes. XML and custom runtime
objects are unsupported and cause a safe refusal of the entire response.
Decimal string escapes are limited to `001`–`127`; NUL and ambiguous non-ASCII
decimal escapes are refused. Non-ASCII text must use literal UTF-8 or explicit
Unicode escapes.

Only top-level certificate fields are considered. A field name inside a string,
comment or nested dictionary does not create a certificate field. Truncated
input, duplicate keys, trailing content, invalid encoding and unsafe values are
refused. Explicit `[]` is preserved as an observed empty DataBlock for existing
readers, but is blocked for a new deployment snapshot. It is never interpreted
as deletion or as proof of a restorable empty server state.

The same complete parser now protects effective-setting readbacks in existing
deployment, recovery and operator acknowledgement. Schema-2 journals and audit
records keep their previous meaning. They contain effective values, not explicit
presence bits, and cannot retrospectively prove inheritance. No migration,
absence mask, new unset operation or relaxed acknowledgement was introduced.

Readiness checks prevent starting or continuing a new transaction with a
detected effective-only snapshot. They do not close all races with WebAdmin,
and do not turn a schema-2 journal into a record of explicit field presence.
Standalone recovery of such a journal retains its effective-snapshot contract;
the new in-process refusal does not add historical presence bits to that record.
The remaining bootstrap design must preserve those distinctions through every
write, readback, recovery and acknowledgement step.

## Vendor evidence and remaining write contract

The [official CLI reference](https://doc.communigatepro.ru/development/CLI.html)
distinguishes explicit `GETDOMAINSETTINGS` from default-inclusive
`GETDOMAINEFFECTIVESETTINGS`. `UPDATEDOMAINSETTINGS` preserves omitted entries;
its string `default` removes an explicit setting. A full `SETDOMAINSETTINGS`
replaces the domain dictionary. These generic rules alone do not specify PKI
field side effects, so this manager does not use either removal or replacement
to implement bootstrap.

The [data format reference](https://doc.communigatepro.ru/development/Data.html)
describes typed objects and unique dictionary keys. It does not identify an
empty DataBlock or null as an update deletion operation.

The [PKI guide](https://doc.communigatepro.ru/admin/sysadmin/PKI.html) describes
different disabled/test/enabled behavior and a WebAdmin key-removal operation
that also removes the certificate. That UI behavior is not a field-by-field CLI
contract. The [revision history](https://doc.communigatepro.ru/admin/common/History.html)
also records a 6.5.7 fix for another domain's CA chain being sent when the
SNI-selected domain has no chain. Exact server version and live TLS behavior
therefore matter to this experiment.

Before enabling bootstrap writes, use a disposable CGP instance with synthetic
domains, keys and certificates. Record the exact server build and permissions.
The production server is not a fixture for these destructive experiments.

| Required experiment | Evidence needed |
|---|---|
| Each certificate field absent, explicit or effective-only | Paired raw/effective replies and exact field presence |
| Remove one PKI field using the documented generic sentinel | Exact remaining PKI fields and any cascade into other fields |
| Failure after a partial update and restoration attempt | Previous raw presence and effective values restored, unrelated settings preserved |
| Disabled/test PKI, missing chain, SNI and non-SNI listeners | Actual leaf/chain or failure; no invented main-domain fallback |
| Restricted administrator rights | Refused/ignored changes detected by complete readback |
| Restart between every write and durable local transition | A new journal schema that preserves absence and refuses third states |
| Previous state without provable TLS | Explicit unresolved/unverified outcome and an audited decision path |

Only after these results should a new snapshot schema encode raw presence,
effective context and field-scoped restore operations. Existing schema-2
recovery and acknowledgement must not be silently reinterpreted. Unit tests,
process-death tests and real TLS tests must accompany that implementation.
Current synthetic response tests validate our reader and guards, not the
server's acceptance of future removal commands.
