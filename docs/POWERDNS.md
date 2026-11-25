# PowerDNS API observation and write boundary

Checkpoint 18 (`2.2.0.dev15`, unreleased) adds a separate **read-only**
`--powerdns-check` command. It validates explicit configuration, reads a private
API key, and checks the configured server and zone identities through the
PowerDNS Authoritative HTTP API. It does not establish DNS propagation, ACME
readiness or permission to change TXT records.

PowerDNS is **not an issuance provider** in this checkpoint. The supported
`dns_provider` selectors remain `cloudflare` and `rfc2136`; selecting
`"powerdns"` for issuance is rejected. Existing Cloudflare and RFC2136
configuration and receipts keep their meaning. No new dependency is required.

## Explicit diagnostic configuration

Add a `powerdns` section to the protected manager configuration without changing
the existing issuance provider. The [configuration example](../examples/powerdns.example.json)
is a diagnostic-only fragment, not a replacement for a working manager setup:

```json
{
  "powerdns": {
    "zones": [
      {
        "zone": "example.com",
        "endpoint": "https://dns-api.example.net",
        "server_id": "localhost",
        "zone_id": "example.com.",
        "credentials": "/etc/cgp-letsencrypt/powerdns.json",
        "nameservers": ["ns1.example.com", "ns2.example.com"]
      }
    ]
  }
}
```

The section and each entry accept only their documented fields. All six fields
above are required. There must be 1–128 unique canonical zones, with no repeated
endpoint/server/zone-ID target. Names and nameservers are normalized to lowercase
ASCII IDNA without a trailing root dot. Each entry requires 1–16 distinct
nameservers; these are configured metadata and are not checked against public
DNS by this command.

| Field | Meaning |
|---|---|
| `zone` | Expected DNS name of the zone, checked against the API response. |
| `endpoint` | Explicit API origin; `/api/v1` is appended by the client. |
| `server_id` | Exact server resource identifier; a native Authoritative server normally uses `localhost`. |
| `zone_id` | Exact API resource identifier, independently configured from the DNS name. |
| `credentials` | Absolute normalized path to a protected API-key JSON file. |
| `nameservers` | Configured public nameservers, retained as configuration metadata only. |

An endpoint accepts verified HTTPS. Plain HTTP is accepted only for the literal
loopback addresses `127.0.0.1` and `::1`, such as `http://127.0.0.1:8081`.
HTTP hostnames, including `localhost`, are refused. URL userinfo, query strings,
fragments, non-root paths, controls, whitespace, backslashes and ambiguous
authorities are refused. A reverse proxy must expose `/api/v1` at the configured
origin; arbitrary URL prefixes are not supported. Default ports and a trailing
root slash are normalized. Identifiers contain 1–255 ASCII letters, digits,
`.`, `_`, `~`, `=`, or `-`; the complete values `.` and `..` are refused. They
are encoded exactly once as path components; response-provided URLs are never
followed.

An informational SHA-256 binding covers the normalized zone, origin, server ID,
zone ID and credential path. Nameservers and API-key bytes are excluded, so key
rotation at the same path and nameserver corrections do not alter that target
label. It is **not** an ownership receipt, remote account fingerprint or future
authorization to mutate DNS. The whole configuration is validated before any
private key is opened or API request is sent.

## Private API key

Create a dedicated protected file with exactly one property:

```json
{"api_key": ""}
```

The empty value in the [secret example](../examples/powerdns-secret.example.json)
deliberately fails validation. Replace it locally with the authorized API key.
The key must contain 1–1024 visible ASCII characters without whitespace. The
4096-byte limit is applied before JSON decoding. The parser rejects duplicate
or additional properties, non-finite
values, malformed encoding and oversized input. Existing private-file rules
reject unsafe ownership, permissions, links and file types. The command does
not repair permissions or store a second copy of the key.

The key is sent only in `X-API-Key` to the explicitly configured origin. The
native PowerDNS API key may authorize more than reads; this client's GET-only
behavior does not turn it into a server-enforced read-only credential. An
administrator can additionally enforce a narrow read-only route at a trusted
gateway, whose configuration and behavior require separate acceptance.

## Running and interpreting the check

```bash
sudo cgp-letsencrypt --powerdns-check
sudo cgp-letsencrypt --powerdns-check --json
```

The command is global and mutually exclusive with other manager actions. It
rejects `--domain` and mutation modifiers before configuration or credential
access. It respects the existing pending-application-update guard, then runs
before the manager operation lock, migration, recovery, state creation, CGP
discovery, Certbot and notification routes.

For every configured target the client performs a server GET, checks the exact
server ID and Authoritative daemon type, then requests the exact zone with
`rrsets=false`. It verifies the zone resource ID and expected DNS name. It does
not enumerate other zones, request TXT data, follow returned URLs, query public
DNS or request API changes. HTTP 200 alone does not establish the expected
identity. Zone kinds are restricted to `Native`, `Master`, `Slave`, `Producer`
and `Consumer`; observing a secondary/consumer does not enable writes. A
returned software version is observation metadata, not a capability test or
a guarantee about the backend.

The JSON report has schema 1, `provider: "powerdns"`, `mode: "read_only"`, an
overall `complete` flag, `issuance_supported: false`, and one result per
configured zone. Results contain the zone, informational binding, fixed status
and reason code, and bounded observed version/kind metadata. They exclude the
API key, credential path, endpoint, raw response and exception text. Failures
remain visible per zone rather than silently reducing the target list.

Exit 0 means every requested API identity was observed. Exit 1 means a partial
report or command failure. Argument errors use the parser's exit 2. A successful
check never means that certificate issuance or automatic TXT cleanup is ready.

The client uses verified TLS with a TLS 1.2 minimum and the system trust store,
without honoring `SSLKEYLOGFILE`. It does not consult proxy settings, follow
redirects, retry requests or downgrade transport. Headers have a cumulative
64 KiB limit; bodies have a separate 64 KiB limit. Only uncompressed
`application/json` with optional UTF-8 charset is accepted. Content-Length and
bounded close-delimited responses are supported; all Transfer-Encoding,
including chunked responses, is refused before reading the body. This avoids
unbounded chunk framing/trailers and has no automatic transport fallback.
JSON is decoded strictly, and errors use fixed diagnostics. Each
connection has a finite socket timeout; this is not an end-to-end deadline for
DNS resolution or a whole multi-zone observation. Plain-loopback HTTP trusts
the local host and the process serving the explicitly configured port.

## Why managed TXT writes are not enabled

The [official Zone API](https://doc.powerdns.com/authoritative/http-api/zone.html)
documents full-RRset `REPLACE`/`DELETE` and single-value `EXTEND`/`PRUNE`.
The latter were added in 4.9.12 and 5.0.2. Comments belong to an RRset, not an
individual value. An already present value makes `EXTEND` a successful no-op;
`PRUNE` removes matching content. Calling the API replacement-only would be
incorrect, but single-value operations still do not prove creation ownership.

The following interleaving is enough to defeat a value-plus-marker design,
even if one PATCH applies its entire batch atomically:

| Step | Manager | Independent writer | TXT state |
|---|---|---|---|
| 1 | Reads challenge value `V` as absent | — | No `V` |
| 2 | — | Adds `V` | `V` belongs to the other writer |
| 3 | Requests `EXTEND V` and `EXTEND M`, where `M` is a new owner marker | — | `V` is unchanged; `M` is added |
| 4 | Reads `V` and `M`, then incorrectly claims ownership of `V` | — | The marker proves only its own creation |
| 5 | Cleans up using `PRUNE V` and `PRUNE M` | — | The other writer's value is removed |

Reading twice or using a local manager lock does not close this gap. Whole-RRset
replacement additionally risks deleting an unrelated value inserted after the
read. A dedicated zone or reserved name is not an enforced fence against other
API clients.

The inspected official `auth-5.0.8` source is pinned at
[`a84b1c7`](https://github.com/PowerDNS/pdns/tree/a84b1c7213f0fbf3760e5900b76e6527d490a36a).
In [ws-auth.cc](https://github.com/PowerDNS/pdns/blob/a84b1c7213f0fbf3760e5900b76e6527d490a36a/pdns/ws-auth.cc),
`applyPruneOrExtend` compares content and `patchZone` applies operations within
a backend transaction. Neither that path nor
[webserver.cc](https://github.com/PowerDNS/pdns/blob/a84b1c7213f0fbf3760e5900b76e6527d490a36a/pdns/webserver.cc)
provides the client-visible ownership precondition needed here. Transactional
batching is not an atomic claim of a previously absent value by this client.

A lost request followed by an empty observation must remain uncertain; this
alone does not make recovery impossible. Do not confuse HTTP request duplication
at an intermediary with network replay of RFC2136 packets: verified HTTPS has
a different transport boundary. The demonstrated same-value ownership race is
the reason this checkpoint does not advertise `owned_txt`.

## Continuation and acceptance

Any later mutating PowerDNS adapter needs a concrete, enforced ownership
acquisition and conditional cleanup contract, target identity, a durable
uncertainty state machine, and tests covering independent writers. An operation
identifier or equivalent fence must have defined server-side behavior; a local
nonce or assumed exclusive access is insufficient. Keep the HTTP write path
pending until those properties are implemented and evidenced.

A PowerDNS deployment that separately supports the required signed conditional
DNS updates may be evaluated through the existing [RFC2136 contract](RFC2136.md).
That is a different configured protocol and does not establish HTTP API
ownership or real-server compatibility automatically.

All tests for this checkpoint use synthetic responses, protected temporary
files and loopback fixtures. Real PowerDNS, API gateways, DNS/ACME, VM and server
acceptance remains deferred in [STAGING.md](STAGING.md). A later API-only lab
should verify server/zone identity, key permissions, verified TLS, HTTP
loopback policy, redirect refusal, malformed responses and unchanged state.
That observation must remain separate from any future write acceptance.

Additional protocol references:

- [PowerDNS server identities](https://doc.powerdns.com/authoritative/http-api/server.html)
- [API authentication and base path](https://doc.powerdns.com/authoritative/http-api/index.html)
- [Provider contract and capability requirements](DNS_PROVIDERS.md)
