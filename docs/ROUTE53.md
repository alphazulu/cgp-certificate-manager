# Route53 adaptive DNS-01 and ownership

Checkpoint 19 (`2.2.0.dev16`, unreleased) adds an explicit Route53 provider for
the supervised adaptive `cgp-dns` authenticator. It supports configured public
hosted zones in commercial AWS, protected explicit credentials and signed
HTTPS. Cloudflare remains the default; RFC2136 retains its separate protocol.
Real AWS/DNS/ACME acceptance remains deferred in [STAGING.md](STAGING.md).

## Configuration

Add the following provider fragment to the protected manager JSON, retaining
the other required settings. The [example](../examples/route53.example.json)
contains synthetic account, zone and nameserver values:

```json
{
  "dns_provider": "route53",
  "dns_preflight": true,
  "dns_propagation": {
    "mode": "adaptive",
    "timeout_seconds": 300,
    "poll_interval_seconds": 5
  },
  "route53": {
    "zones": [
      {
        "zone": "example.com",
        "hosted_zone_id": "ZEXAMPLE123",
        "account_id": "123456789012",
        "credentials": "/etc/cgp-letsencrypt/route53.json",
        "nameservers": ["ns1.example.com", "ns2.example.com"]
      }
    ]
  }
}
```

Each entry requires exactly those five fields. The section accepts 1–128 unique
canonical zones and no repeated account/hosted-zone target. Names use lowercase
ASCII IDNA without a trailing root dot. Accounts are explicit twelve-digit IDs;
hosted-zone IDs begin with `Z`, contain uppercase alphanumerics and are at most
32 characters, without `/hostedzone/`. Paths are absolute and normalized. Each
zone requires 1–16 distinct configured nameservers, later checked against AWS.
The complete configuration validates before private-key or network access;
inventory enumeration itself is pure configured data.

Route53 requires adaptive propagation and preflight. Fixed modes/hooks and the
Cloudflare configuration editor refuse this provider. Edit JSON manually.
Installation does not rewrite existing Certbot renewal parameters; use the
separate staging renewal-migration procedure when later authorized.

The stable binding includes the fixed commercial-AWS protocol identity, zone,
hosted-zone ID, expected account and credential path. Rotating key bytes and
nameservers are excluded. Schema-2 receipts store this opaque zone binding and
an ownership nonce as the record reference, not an AWS change ID. Target/path
changes cannot redirect an old receipt's cleanup. Cloudflare/RFC2136 receipt
formats and public status fields remain unchanged.

## Explicit credentials and identity

The protected credential file accepts exactly `access_key_id`,
`secret_access_key`, and an optional `session_token` for temporary credentials:

```json
{"access_key_id": "", "secret_access_key": ""}
```

The [empty secret example](../examples/route53-secret.example.json) deliberately
fails validation. Supported application limits are 32 KiB of UTF-8 JSON,
16–128 uppercase alphanumeric access-ID characters, 40 supported base64-alphabet
secret characters, and 1–16384 visible ASCII characters without whitespace for
a supplied token. AWS does not promise a fixed maximum session-token size;
these are local bounds. Duplicate/extra properties, malformed input and unsafe
file ownership, modes or links fail with fixed errors.

There is no environment, shared profile, SSO, credential-process, ECS/EC2
metadata or automatic role/session discovery. Expired credentials require
explicit rotation at the protected path; no automatic refresh is attempted.

One in-memory credential snapshot is used for an operation's STS identity check
and associated Route53 requests. The expected account must match
GetCallerIdentity. The adapter verifies the exact hosted-zone ID/name, public
zone status and configured nameservers. Keys are never stored in receipts,
command arguments, logs or public status. Same-account/path rotation does not
skip any target or ownership check.

| Service | Fixed HTTPS host | Signing region | SigV4 service |
|---|---|---|---|
| Hosted-zone/record API | `route53.amazonaws.com` | `us-east-1` | `route53` |
| Account identity | `sts.us-east-1.amazonaws.com` | `us-east-1` | `sts` |

Other partitions, arbitrary endpoints and signing regions are unsupported.
The narrow standard-library SigV4 client hashes the exact transmitted bytes and
signs a supplied session token. Independent official signing vectors supplement
synthetic transport tests. No SDK or other runtime dependency is added.

## Permissions

The [IAM example](../examples/route53-policy.example.json) limits reads to one
synthetic hosted zone and changes to one challenge owner within it. Adapt the actual
zone and exact normalized names. Reads use GetHostedZone and
ListResourceRecordSets. ChangeResourceRecordSets is limited to TXT and
CREATE/DELETE; the adapter does not use UPSERT or GetChange. GetCallerIdentity
requires no separate allow permission.

These conditions restrict authorization but do not establish ownership.
Zone-read permissions can expose more records than this client's targeted
queries request. Existing protections, IAM denials and guardrails are
respected; the manager never removes or changes them.

## Conditional ownership and TXT format

Only simple nonalias TXT sets are supported. Routing policies, multivalue
routing, aliases, health checks and traffic-policy records are refused rather
than converted. Existing TTL and foreign raw AWS Value strings are preserved.

Listing is a bounded targeted `maxitems=1` observation. An empty complete page
or a validated later owner can prove absence; unrelated fields of a later
neighbor do not describe our TXT. A simple exact TXT must be complete: a cursor
at the same owner/type is ambiguous and refused. A different type at the exact
requested owner and exotic escaped owner names are conservatively unsupported.
This is stricter than the complete Route53 record model.

An absent set uses CREATE. Every existing-set mutation submits one batch:
**DELETE the exact observed old set, then CREATE its replacement**. AWS requires
matching deletion values and applies a batch all-or-none. A concurrent change
invalidates the preimage deletion and prevents the replacement from silently
removing the new foreign data.

Each managed challenge has a nonce owner marker. One generation TXT persists
at every used challenge owner and changes on creation/cleanup. A conditional
creation introduces the challenge, marker and next generation together.
Cleanup removes only its own pair and the previous generation, preserving all
other values and leaving a new generation. It never restores the original
preimage. Reserved metadata must not be deleted, copied, reused or rolled back
outside the protocol.

If another writer inserts the identical challenge after our read, the
conditional CREATE or exact deletion fails and the whole batch is rejected.
A value found before creation
is borrowed without later deletion. A marker is ownership evidence only with
conditional acquisition and the canonical challenge/generation state.

AWS TXT presentation uses three-digit **octal** escapes, unlike dnspython's
decimal DNS escapes. A dedicated bounded parser recognizes existing challenge
values across quoted chunks and valid escapes; foreign raw strings remain
unchanged in outgoing batches. Owned values and metadata require canonical
plain single-string forms. Unsupported or malformed syntax is a refusal.

Snapshots are limited to 128 values, with at most 4000 presentation characters
per value. The combined old/replacement batch must fit 1000 ResourceRecord
entries and 32000 Value characters, including challenge/metadata headroom.
The manager never trims unrelated data to fit. Later foreign growth can leave
cleanup pending if a safe conditional batch no longer fits.

## Recovery and public propagation

Intent is durable before mutation. Creation requires owned-pair/generation
readback; cleanup requires the pair absent and a valid retained generation.
Lost replies, malformed acknowledgements and all
remote errors preserve uncertainty; there is no blind creation retry. Proven
local pre-send collision/capacity refusals are handled separately.

An uncertain intent without its owned pair remains pending. A previously
created pair observed absent can complete only with valid generation evidence
in its original verified account/zone. Partial pairs, changed ownership or lost
generation retain the receipt. The full ledger validates before any cleanup;
completion remains durable before local removal.

Targeted API listing returns the current **control-plane** state, including
PENDING changes. Accepted mutation and API readback do not prove that every
authoritative server or resolver cache has already updated. A lost change ID
is not reconstructed or used as ownership identity. Existing public preflight
and adaptive propagation checks remain the gate before ACME validation.

API queries stay bound to the hosted-zone ID even if a child delegation changes.
This makes RFC2136's prerequisite-only absence UPDATE unnecessary. The TXT
batch does not atomically guard ancestor NS delegation; public authority is
checked separately. Do not assume RFC2136's delegation prerequisites.

## Transport and trust boundaries

Verified HTTPS uses the system trust store, TLS 1.2 minimum and no
SSLKEYLOGFILE side effect. Connections are direct with no proxy, redirect,
retry or downgrade. The ten-second socket timeout is not a total deadline for
DNS resolution or an entire operation. Headers have a cumulative 64 KiB limit;
XML bodies have a separate 512 KiB limit. Compression and Transfer-Encoding
are refused. Strict UTF-8 XML rejects DTD/entity declarations and excessive
structure; operation roots, namespaces and identity fields are checked.
Errors never echo AWS bodies, Authorization headers, tokens or TXT values.

The contract trusts AWS's authenticated exact-delete validation, transactional
batches and current control-plane listing. Retained generation protects old
preimages while protocol state is respected. Authorized independent writers
can still replace evidence; unknown state causes refusal, not automatic repair.

## Acceptance and sources

Synthetic tests cover conditional races, escaped foreign TXT, lost responses,
retained generation, credentials, signed HTTP/TLS and recovery. Actual AWS
same-name/type DELETE+CREATE, IAM, public propagation, temporary-credential
rotation and interrupted renewal remain pending in [STAGING.md](STAGING.md).

- [Transactional batches and exact deletion](https://docs.aws.amazon.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html)
- [Current control-plane records and listing](https://docs.aws.amazon.com/Route53/latest/APIReference/API_ListResourceRecordSets.html)
- [Hosted-zone identity](https://docs.aws.amazon.com/Route53/latest/APIReference/API_GetHostedZone.html)
- [GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html)
- [Endpoints and signing region](https://docs.aws.amazon.com/general/latest/gr/r53.html)
- [SigV4 construction](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html)
- [TXT format](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html#TXTFormat)
- [Batch quotas](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DNSLimitations.html)
- [IAM conditions](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/specifying-conditions-route53.html)
