# Monitoring integrations

This development checkpoint supplies Prometheus alert rules, a Grafana dashboard
and a Zabbix template for the [local monitoring interface](MONITORING.md).
They observe saved manager state and public local certificate expiry. Deployed
CGP TLS is a separate observation. Importing an asset does not configure the
manager's collection schedule or grant access to its private files.

All real VM/server acceptance remains deferred by the maintainer's decision in
[STAGING.md](STAGING.md). The repository tests asset contracts, preprocessing
and rule/query semantics using synthetic data. Actual import, presentation,
collection scheduling and alert delivery in the chosen deployment remain
separate acceptance steps.

## Assets and tested formats

| Asset | Purpose | Format |
|---|---|---|
| [Prometheus rules](../monitoring/prometheus/alerts.yml) | Collection, freshness, local certificate and retained-artifact alerts | Prometheus rule file; engine checks use pinned promtool 3.16.0 |
| [Prometheus rule tests](../monitoring/prometheus/alerts.test.yml) | Synthetic timelines and expected firing/nonfiring results | Native promtool rule-test file |
| [Grafana dashboard](../monitoring/grafana/cgp-manager.json) | Host health, local certificate expiry and historical manager observations | Classic JSON, schema 39, based on Grafana 11.0 |
| [Zabbix template](../monitoring/zabbix/cgp-manager.json) | HTTP collection and dependent discovery/items/triggers | Zabbix 7.0 export format |

No artifact is installed or enabled by the application installer. The package
contains the source files so they can be reviewed and imported during the later
deployment session. There is no embedded endpoint password, webhook recipient,
production hostname or privileged agent command.

## Shared interpretation

The default fresh-snapshot interval is **0 through 900 seconds old**, inclusive.
A future collection timestamp is a clock/observation problem. The default local
expiry bands are **at most 7 days** for critical and **more than 7 through 21 days**
for warning. These bands do not overlap. Disabled domains remain discoverable
but are excluded from enabled-domain health alerts.

Operational alerts use a fresh complete collection. They do not substitute zero
for an absent measurement. Local certificate read errors are observations in
their own right: such an error makes the whole collection incomplete, so its
own alert cannot require `collection_success == 1`. Historical failure counts
and saved success times retain their original meanings; they do not establish
the current state of served TLS.

Tune thresholds and notification routing during deployment, keeping the three
assets consistent. Configuration of an Alertmanager or Zabbix action is outside
these artifacts; test evaluation does not send a notification.

## Prometheus target selection

The rules and dashboard select only scrape targets explicitly labelled
`cgp_manager="true"`. Add that label to the appropriate existing node_exporter
target; do not create a second scrape of the same exporter merely to add the
label. The following is a synthetic configuration fragment to merge and review
later, not a replacement for an existing Prometheus configuration:

```yaml
scrape_configs:
  - job_name: cgp-node
    static_configs:
      - targets: ['mail.example.invalid:9100']
        labels:
          cgp_manager: 'true'

rule_files:
  - /etc/prometheus/cgp-manager-alerts.yml
```

Publish the manager's `.prom` output into the textfile directory already selected
for that exporter, following [atomic publication](MONITORING.md#atomic-textfile-publication).
The Prometheus target label is attached at scrape time; it is not expected in
the raw node_exporter response used by the Zabbix HTTP template.

Host joins use `(job, instance)` and domain joins add `domain`. These labels must
uniquely identify a target in the selected Prometheus scope. If an aggregation
layer combines colliding job/instance pairs from different clusters, extend the
identity consistently before using the assets there.

The labelled `up` series defines which configured scrape targets are expected.
A reachable exporter with missing manager metadata is different from a down
exporter. A target removed entirely from Prometheus configuration has no `up`
series and requires an independent desired-target inventory to detect removal.
Unlabelled exporters are not implicitly enrolled.

## Prometheus alert rules

The rule group evaluates once per minute. The `for` duration is a continuous
pending interval after an expression becomes true, not the manager collection
interval. For example, a snapshot first becomes stale when its age exceeds
900 seconds; the stale alert fires after that condition persists for five more
minutes. Rules do not create an Alertmanager receiver or notification route.

| Alert | Meaning | Severity | Pending interval |
|---|---|---|---|
| `CGPManagerExporterUnavailable` | An opted-in target has `up = 0` | critical | 5 min |
| `CGPManagerMonitoringMissing` | A reachable target lacks collection success or timestamp metadata | warning | 5 min |
| `CGPManagerMonitoringStale` | Snapshot age exceeds 900 seconds | warning | 5 min |
| `CGPManagerMonitoringTimestampFuture` | Collection timestamp is later than the evaluation clock | warning | 5 min |
| `CGPManagerCollectionFailed` | A fresh collection is incomplete, except while a source is busy | warning | 5 min |
| `CGPManagerSourceUnavailable` | A named source is explicitly missing or rejected | warning | 5 min |
| `CGPManagerCollectionBusy` | A required source remains busy | warning | 15 min |
| `CGPManagerLocalCertificateReadError` | An enabled domain's leaf cannot be read while all seven other sources are available | warning | 5 min |
| `CGPManagerLocalCertificateMissing` | A fresh complete collection confirms no local leaf for an enabled domain | warning | 5 min |
| `CGPManagerLocalCertificateExpiryCritical` | A readable local leaf is expired or has at most 7 days left | critical | 5 min |
| `CGPManagerLocalCertificateExpiryWarning` | A readable local leaf has more than 7 and at most 21 days left | warning | 5 min |
| `CGPManagerPendingArtifacts` | A validated retained-artifact count stays positive | warning | 15 min |
| `CGPManagerRecordedFailure` | An enabled domain's saved failure gauge stays positive | info | 15 min |

The general collection alert can coexist with a specific source or certificate
read alert. This intentionally retains the failed-collection signal and its
available cause. Busy observations use their own longer pending interval.
Alert labels include `component`, `scope`, `severity` and the relevant target,
domain, source or artifact kind so routing can distinguish these observations.

Pending artifact kinds can overlap and do not count unique operations. A
retained journal or DNS receipt does not by itself authorize recovery, deletion
or any other write. The saved-failure alert is historical and informational.

Import the rule file as one group: its six recording rules supply the derived
target, age, freshness, completeness and remaining-lifetime series used by the
alerts. The dashboard evaluates the underlying metrics directly and does not
depend on loading these recording rules.

## Grafana dashboard

During the later deployment session, import `monitoring/grafana/cgp-manager.json`
using Grafana's dashboard import flow and select the existing Prometheus
datasource. The `DS_PROMETHEUS` import input initializes a changeable dashboard
datasource variable. Select `job`, `instance` and optionally `domain`; multiple
selections and All are supported. Job and instance choices come from opted-in
`up` series, including targets whose manager metrics are absent.

The dashboard has ten data panels and a scope explanation. It shows exporter
availability, the last collection result, snapshot age, local source status,
retained artifacts, local leaf read status and expiry, saved failure counts,
age of the last saved success and the saved retry time. The last collection
result is explicitly the recorded result; interpret it with the adjacent age
panel. An old successful result does not make an old snapshot current.

Unknown measurements remain absent or display `Unknown` / `No data`. Charts do
not fill missing intervals with zero. The expiry panel rounds remaining days
upward and uses colour transitions at 8 and 22 so the displayed colour bands
match the exact 7-day and 21-day limits. Age exactly 900 seconds is still fresh;
the orange boundary in the age panel is an early visual cue, not a stale alert.
Negative snapshot age flags a clock discrepancy. A saved retry timestamp of
zero displays `Cleared`, not a date in 1970.

Source diagnostics and known local public-leaf read statuses remain visible for
a fresh incomplete snapshot. Pending counts, local expiry and historical
domain measurements require a fresh complete snapshot; domain panels also
require the domain to be enabled.
The saved-success panel has neutral historical colouring because a previous
success is not a heartbeat or current TLS proof. The JSON contains no alert
receiver, scheduled refresh or administrative action link.

## Zabbix HTTP template

The export defines `CGP Certificate Manager by HTTP` in Zabbix 7.0 format.
During later acceptance, import it and link it to a test host. Set the existing
public exporter URL as seen by the Zabbix server or proxy. The HTTP master uses
GET, requires status 200, refuses redirects and enables peer/hostname
verification for HTTPS. It does not read private manager files or execute an
agent command. No Zabbix action, media recipient or manager collection timer is
included.

| Host macro | Default | Meaning |
|---|---|---|
| `{$CGP.METRICS.URL}` | `http://{HOST.CONN}:9100/metrics` | Existing public node_exporter endpoint; choose HTTPS where available |
| `{$CGP.POLL.INTERVAL}` | `1m` | HTTP polling interval |
| `{$CGP.MAX.AGE.SECONDS}` | `900` | Maximum accepted collection age, inclusive |
| `{$CGP.FUTURE.SKEW.SECONDS}` | `0` | Permitted future clock skew; zero keeps the shared default contract |
| `{$CGP.NODATA}` | `5m` | Missing-observation interval |
| `{$CGP.EXPIRY.CRIT.SECONDS}` | `604800` | Critical local-expiry threshold, initially 7 days |
| `{$CGP.EXPIRY.WARN.SECONDS}` | `1814400` | Warning local-expiry threshold, initially 21 days |

Keep the polling interval below both age and no-data limits. The age and skew
macros are administrator-owned decimal integer seconds inserted into Zabbix
JavaScript. Do not insert quotes or expressions. Maximum age must be positive;
future skew can be zero. The warning expiry threshold must exceed the critical
threshold. A nonzero future allowance intentionally changes Zabbix's default
contract and should be reviewed against the other integrations.

Native `PROMETHEUS_TO_JSON` preprocessing selects `cgp_manager_*` metrics, then
the shared ES5 JavaScript validates series, labels, finite numbers, one-hot
statuses and domain relationships. Unknown optional quantities remain absent.
A separate freshness stage exposes operational fields only for complete
collections. Dependent items use JSONPath; discovered domain names are not
interpolated into executable JavaScript.

Discovery requires a fresh complete snapshot. Malformed, missing, partial,
stale or future data fails preprocessing instead of returning an empty domain
list. Disabled domains remain in discovery. Lost resources use `DELETE_NEVER`
and `DISABLE_NEVER`, preserving observations for manual review; removing a
domain from configuration does not automatically remove its monitoring items.
The template stays within three dependent-item levels.

Zabbix can retain an item's previous history after a failed dependent
preprocessing step. Trigger expressions therefore check collection age and
the accepted collection and current domain observation timestamps rather than
trusting a cached `last()` value alone. Expiry requires a currently readable
leaf; the optional saved-failure gauge has a separate presence flag. Operational
problem recovery also requires new qualifying
evidence; a stale or incomplete collection does not automatically resolve an
existing certificate or retained-artifact problem. Missing observations have
separate availability triggers. The Prometheus `for` durations above are not
implicitly applied to Zabbix: review its trigger and action timing during
acceptance.

Zabbix's native `now()` function has whole-second resolution. The template
uses `floor(timestamp)` for native clock comparisons to avoid treating a valid
fractional timestamp in the current second as future. Original fractional
timestamps remain unchanged for JavaScript freshness checks and observation
identity. Native clock-trigger boundaries therefore have one-second resolution;
the preprocessing stage still refuses an age outside the configured interval.
FLOAT timestamp items retain their numeric value and do not use the
unsigned-only `unixtime` display format.

## Automated validation and continuation

The ordinary Python suites validate asset contracts alongside the existing
manager tests, retaining independent 100% statement/branch coverage gates.
Both Python jobs use the pinned Node.js runtime to execute the embedded Zabbix
preprocessing. The additional monitoring-assets job uses a pinned Prometheus
archive with its verified SHA-256 digest. Package creation depends on this job
as well as both Python profiles and all four installer combinations.

Real promtool evaluates the alert timelines and dashboard expressions; Python
tests do not implement a substitute PromQL engine. Zabbix preprocessing is
executed against synthetic native Prometheus-to-JSON data. Its JavaScript body
is shared with the template, so tests do not exercise a separate handwritten
replacement. Arithmetic regressions also substitute synthetic item histories
into the exported Zabbix expressions; they do not validate the native Zabbix
parser or event engine. Exact commands and observed results are recorded in
[CONTRIBUTING.md](../CONTRIBUTING.md) and [DEVELOPMENT.md](../DEVELOPMENT.md).

Before a later deployment, record the chosen product versions, reviewed asset
revision, target labels, publication interval and notification destinations.
Complete the real-environment acceptance cases when the maintainer schedules
them, including healthy, missing, stale, disabled and clock-skew behavior.

## Format references

- [Prometheus rule and expression unit tests](https://prometheus.io/docs/prometheus/latest/configuration/unit_testing_rules/).
- [Grafana 11 classic dashboard JSON model](https://archive.grafana.com/docs/grafana/v11.0/dashboards/build-dashboards/view-dashboard-json-model/).
- [Zabbix 7.0 Prometheus checks](https://www.zabbix.com/documentation/7.0/en/manual/config/items/itemtypes/http/prometheus)
  and [dependent items](https://www.zabbix.com/documentation/7.0/en/manual/config/items/itemtypes/dependent_items).
- [Zabbix 7.0 preprocessing failure behavior](https://www.zabbix.com/documentation/7.0/en/manual/config/items/preprocessing)
  and [item value types and display units](https://www.zabbix.com/documentation/7.0/en/manual/config/items/item).
