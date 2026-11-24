# Local monitoring and discovery

This development checkpoint adds an offline monitoring interface. It reads the
manager's local configuration, saved discovery/state, recovery evidence and
public Certbot leaf certificates. It makes no CGP, DNS, Cloudflare, ACME or SMTP
requests, and does not run recovery, issue certificates or change configuration.
It does not open an HTTP listener or enable a new timer.

**A local certificate is not evidence of the certificate currently served by
CGP.** Expiry below refers to the public local `cert.pem`. Current deployed TLS
must be observed separately. Real VM/server acceptance is deferred by the
maintainer's 2026-11-24 decision in [STAGING.md](STAGING.md).

## Commands and exit status

Run under the administrative identity that owns the protected manager files:

```sh
cgp-letsencrypt --monitoring
cgp-letsencrypt --metrics
cgp-letsencrypt --zabbix-discovery
```

| Command | Output | Incomplete collection |
|---|---|---|
| `--monitoring` | JSON snapshot, schema 1 | Emit the snapshot with `complete: false`; exit 1 |
| `--metrics` | Prometheus text exposition | Emit collection/source failure metrics; exit 1 |
| `--metrics --metrics-file /absolute/path/cgp-manager.prom` | Atomically publish the textfile, no stdout | Publish valid failure metrics, then exit 1 |
| `--zabbix-discovery` | Native JSON array of domain macros | Emit no discovery JSON; fixed diagnostic on stderr; exit 1 |

A complete collection exits 0. This means its required local sources were read,
not that every certificate is healthy or every pending count is zero. An expired
certificate, a known missing certificate or a retained transaction can appear
in a complete snapshot. Argument errors exit 2. Rendering/publication failures
exit nonzero and do not produce a partially rendered stdout document.

These commands are global. `--domain` and mutation modifiers are rejected.
`--json` may accompany the two JSON commands; it is rejected with `--metrics`.
`--metrics-file` requires `--metrics`. Normal issuance and the existing
`--status` / `--verify` workflows retain their behavior.

## What a snapshot means

`generated_at` is the collection's Unix time in seconds. It is not a successful
renewal, discovery or TLS verification timestamp. `sources` contains a status
for each of `config`, `inventory`, `state`, `transactions`, `resolutions`,
`dns_challenges` and `lock`. The fixed states are `ok`, `missing`, `error` and
`busy`. File `mtime`, when available, describes that file's modification time;
touching a file does not create fresh remote evidence.

The collector opens the existing private `run.lock` read-only and attempts a
nonblocking shared lock. It never creates the lock or state directory. A busy,
missing or unsafe lock prevents state-dependent observations and marks the
collection incomplete. It does not wait behind certificate issuance. Validated
manager state is copied while holding the shared lock; public certificate
inspection follows after release. The result is not an atomic snapshot of CGP,
Certbot, the entire filesystem or unrelated administrator commands.

The domain list is the union of current configured overrides and the last saved
discovery inventory. Current configuration determines `enabled` and
`cert_name`; a removed override does not survive merely because an older cache
contains it. A domain's `in_inventory` flag means it occurred in the saved
inventory, not that it still exists in CGP. When that source is unavailable the
flag is `null`, and the corresponding metric is omitted. Configured domains can appear before
discovery, and domains removed from CGP can remain until a normal manager run
refreshes the inventory. Monitoring itself never performs that refresh.

An absent inventory or state file is reported as `missing`, and the overall
snapshot is incomplete. It must not be treated as proof that there are no
managed domains or that no operation has ever failed. Under an existing safe
locked state directory, an absent journal/receipt/audit subdirectory represents
zero retained artifacts of that kind. Corruption, unsafe permissions, invalid
metadata or an unsupported source shape produces `error` and an unknown count.

The public leaf reader distinguishes:

- `ok`: a bounded, safely opened local certificate was parsed; `not_after` is
  its expiry in Unix seconds. An already expired certificate is still readable.
- `missing`: no local public leaf was found at the expected lineage path.
- `error`: the path, certificate or read could not be accepted. Expiry is omitted.

No private key is read to obtain local expiry. Normal Certbot `live` to `archive`
leaf links are supported; arbitrary targets and unsafe file types are refused.
The reader validates the opened public file and bounds its size. It does not
validate the served chain, match its private key or establish current hostname
coverage. A concurrently replaced Certbot lineage is a separate observation from
the manager state.

Collection has explicit input limits: 1 MiB per JSON file, 1,000 domains or
pending records/bundles, and a 16 MiB / 4,096-file preflight cap per pending
source. Public leaf files are limited to 64 KiB and each offline OpenSSL expiry
parse has a 10-second timeout. Oversized or unsupported sources remain errors;
the collector does not truncate them into an apparently complete result.

## Saved results and retained evidence

Only numeric, validated state fields are exported: `last_success`, `failures`
and `retry_at`. A missing field remains unknown (`null` in JSON and no Prometheus
sample). Raw `result` / `alert` messages, history, passwords, credential paths,
private snapshots, TXT values and confirmation tokens are not exported.

`last_success` records the last saved successful deployment or unchanged check
from the normal manager workflow. It is historical evidence, not a guarantee
that CGP still serves that certificate. `failures` is the saved count associated
with the last failed stage and can be reset; it is a gauge, not a lifetime
failure counter. `retry_at` is the saved retry timestamp; zero denotes a cleared
timestamp. Neither field replaces the per-stage backoff policy.

| Pending kind | Counted artifacts |
|---|---|
| `transactions` | Validated retained certificate journals, including terminal phases still awaiting durable removal |
| `resolutions` | Validated operator authorizations without a matching completion record |
| `dns_challenges` | Validated retained DNS receipts, including receipts still present in a completed phase |

These are separate counts, not a total of unique operations: an incomplete
resolution may also have a retained transaction journal. A known count of zero
is different from an unreadable or invalid source. Valid certificate journals
are counted regardless of server binding; this is a retained-file observation,
not an authorization to recover them. A foreign DNS receipt cannot be validated
against the current configuration and makes that source unavailable. Unknown counts are
`null` in JSON and omitted from metrics. Monitoring never removes, repairs,
fsyncs or acknowledges recovery evidence. Inspect operational details through
the existing transaction commands when appropriate.

## Prometheus metrics

All families have the `cgp_manager_` prefix and use gauges. Output uses the
[Prometheus text format](https://prometheus.io/docs/instrumenting/exposition_formats/):
UTF-8, a final newline, escaped label strings, grouped `HELP`/`TYPE` metadata and
unique series. Timestamp measurements are values in seconds. There is no
optional per-sample timestamp field, as required by the
[node_exporter textfile collector](https://github.com/prometheus/node_exporter#textfile-collector).

| Metric suffix | Labels | Meaning |
|---|---|---|
| `build_info` | `version` | Manager development version, value 1 |
| `collection_success` | None | All required local sources collected: 1 or 0 |
| `collection_timestamp_seconds` | None | Collection time, including an incomplete collection |
| `source_status` | `source`, `status` | One-hot status for each required source |
| `source_mtime_seconds` | `source` | File modification time, only when available |
| `pending_artifacts` | `kind` | Known retained-artifact counts; unknown omitted |
| `domain_info` | `domain`, `cert_name` | Current local domain/lineage mapping, value 1 |
| `domain_enabled` | `domain` | Current configuration enables this domain: 1 or 0 |
| `domain_in_inventory` | `domain` | Present in the saved discovery cache: 1 or 0 |
| `local_certificate_status` | `domain`, `status` | One-hot public leaf read status |
| `local_certificate_not_after_timestamp_seconds` | `domain` | Local leaf expiry, only after successful parsing |
| `last_success_timestamp_seconds` | `domain` | Known saved manager success time |
| `recorded_failures` | `domain` | Known saved failure count |
| `retry_timestamp_seconds` | `domain` | Known saved retry timestamp |

Example queries for later monitoring integration:

```promql
cgp_manager_collection_success == 0
time() - cgp_manager_collection_timestamp_seconds > 900
cgp_manager_pending_artifacts > 0
```

For a local certificate approaching expiry on an enabled domain:

```promql
(cgp_manager_local_certificate_not_after_timestamp_seconds - time() < 21 * 24 * 3600)
and on (job, instance, domain) (cgp_manager_domain_enabled == 1)
```

The thresholds are examples to adapt during deployment. Monitor exporter/target
availability and absent series as well as timestamp age; a missing series does
not compare greater than a threshold. Keep collection failure, stale snapshots,
missing certificates and expiry as distinct conditions. Neither a recently
written file nor `collection_success == 1` proves recent issuance or working TLS.

## Atomic textfile publication

Prepare a dedicated, trusted directory for node_exporter's configured
`--collector.textfile.directory` during the later deployment session. The manager
does not create that directory or configure node_exporter. For example:

```sh
cgp-letsencrypt --metrics --metrics-file /var/lib/node_exporter/textfile_collector/cgp-manager.prom
```

The destination must be an absolute `.prom` path with a trusted existing parent.
The final directory must not be group/world writable. Symlinks, hardlinked files,
untrusted owners and nonregular targets are refused. Output cannot target the
manager's private configuration/state or Certbot trees. An existing output must
already have mode `0644`; a private `0600` file is not silently converted to
public data. No existing permissions or ownership are repaired.

The publisher writes a complete rendering to a new temporary file in that same
directory, sets the new inode to `0644`, fsyncs it, rechecks the target, replaces
it atomically and fsyncs the directory. The temporary name is not a `.prom`
file. A pre-replacement failure preserves the old output. If the final directory
fsync fails, the new file may already be visible; the command reports failure
without claiming a rollback.

An incomplete but valid collection deliberately replaces old healthy metrics
with `collection_success 0` and source statuses. A publication failure can leave
the previous file in place, so the collection timestamp must also be monitored.
Do not use `> cgp-manager.prom`, which can expose a truncated file to a scrape.

The exported file is readable metadata and includes domain and lineage names.
Keep access consistent with your monitoring policy. node_exporter does not need
access to the manager's private configuration, state or Certbot private keys;
collect with the administrative identity and expose only this chosen output.
Scheduling is left to an explicit later deployment decision.

## Zabbix low-level discovery

`--zabbix-discovery` emits the native root JSON array described in
[Zabbix custom LLD rules](https://www.zabbix.com/documentation/current/en/manual/discovery/low_level_discovery/custom_rules):

```json
[
  {
    "{#CGP_DOMAIN}": "example.com",
    "{#CGP_CERT_NAME}": "example.com",
    "{#CGP_ENABLED}": 1
  }
]
```

Disabled domains remain in discovery with `CGP_ENABLED` equal to 0. Rows are
sorted by domain and include only those three macros. A complete, valid empty
inventory/configuration can produce `[]`. Any incomplete snapshot instead fails
without discovery JSON. An integration must preserve that failure and must not
replace it with `[]`; otherwise a configured
[lost-resource policy](https://www.zabbix.com/documentation/current/en/manual/discovery/low_level_discovery)
could disable or delete previously discovered objects.

This checkpoint supplies the discovery contract, not an installed Zabbix
template, privileged agent rule, Grafana dashboard or live-server acceptance
result. Those are separate remaining roadmap items.
