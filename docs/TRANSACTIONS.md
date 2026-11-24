# Certificate transaction recovery (2.2 development)

This document describes the development branch, not stable 2.1.0. Production
validation and release approval remain outstanding. See the repository roadmap
and development checkpoint for observed tests and unfinished work.

## What reaches disk before a write

The CLI holds `/var/lib/cgp-letsencrypt/run.lock` across certificate operations,
inspection and recovery. Certbot challenge hooks retain their existing special
handling because they are children of the process holding that lock.

`transactions/<domain>.json` contains all four previous and intended CGP fields,
separate TLS endpoint lists for those two snapshots, a schema number, a phase
and a server identity. The identity hashes the local `/etc/machine-id` and CGP
CLI URL; passwords and Cloudflare tokens are not included. The journal does
contain private certificate keys. Its directory is 0700 and each file is 0600;
reads reject unexpected owners, types, permissions and symbolic links.

Each replacement is written to a temporary file, flushed and fsynced, atomically
renamed, then followed by a directory fsync. Creating the transaction directory
also fsyncs its existing parent. This uses the filesystem's durability contract;
it cannot guarantee that faulty storage hardware honors flushes.

The current journal schema is **2**. Experimental schema-1 journals from earlier
development commits are deliberately rejected. Neither format has been deployed
as a stable release. Do not manually change schema numbers to bypass validation.

## Phases and recovery decisions

| Phase | Meaning | Recovery when the remote state is recognized |
|---|---|---|
| `prepared` | Both snapshots are durable; no remote write has been authorized yet | Verify the previous snapshot and finish restoration. A different intended snapshot at this phase is unexpected and is refused. |
| `applying` | A remote write may or may not have happened | Read actual settings; verify the intended snapshot if installed, otherwise verify/restore the previous snapshot. |
| `applied` | Intended settings were read back | Repeat TLS verification before committing. |
| `verifying` | Live TLS proof is incomplete or was interrupted | Repeat verification; restore only a recognized previous/intended state if verification fails. |
| `committed` | Intended settings and live TLS were verified and completion was recorded | Check the remote settings still match, then remove the completed journal. |
| `restoring` | Previous settings may or may not have been written back | Re-read before writing; restore if needed, then verify previous settings and TLS. |
| `restored` | Previous settings and live TLS were verified and completion was recorded | Check the remote settings still match, then remove the completed journal. |

For **every phase**, an unrecognized third state blocks recovery writes. Equal
previous and intended snapshots are handled explicitly. Terminal cleanup does
not repeat an already recorded TLS proof; normal `--verify` remains the current
health check against the Certbot lineage.

The manager checks actual CGP settings before a transaction, after preparation,
after the `applying` phase has reached disk, after remote write and after TLS
verification. Restoration likewise checks again after persisting `restoring`
and immediately before writing. These checks detect intervening changes; the
CGP API has no assumed atomic compare-and-swap, so an administrator can still
race the final comparison and write. Avoid concurrent WebAdmin certificate
changes while the manager is operating.

## Independent snapshot verification

Verification checks that the recorded private key matches the leaf, validates
the DER chain and trust/validity with OpenSSL, then compares the complete ordered
chain served by every recorded TLS endpoint. Hostname verification, SNI and
configured STARTTLS transport remain enabled.

The previous certificate's endpoints use its concrete SANs and known aliases.
A configured explicit SNI is preserved when that snapshot covers it. An SNI
belonging only to the replacement is replaced by known names from the previous
snapshot on the same listener. The manager does not invent names for wildcard
certificates; if no suitable known name exists, it refuses the operation.

Both normal installation and manual backup restoration use this mechanism.
Recovery does not read `LIVE`, so a newer Certbot certificate cannot invalidate
verification of a restored older certificate. Normal installation captures the
leaf once and uses the same bytes for SAN/expiry checking and the new payload.
The captured key, leaf and chain are validated together before the remote write.

## Operator commands

```sh
sudo cgp-letsencrypt --transactions --json
sudo cgp-letsencrypt --transactions --domain example.com
sudo cgp-letsencrypt --recover --domain example.com
sudo cgp-letsencrypt --recover
```

`--transactions` performs no recovery, journal modification or TLS probing. It
reads CGP only for journals whose server identity matches and reports a safe
metadata row: domain, phase, `previous`/`intended`/`both`/`unknown`/`foreign`, and
the identity-match boolean. Successful inspection returns 0 regardless of row
state; failures to read or validate data return nonzero. A `foreign` row causes
no contact with a different CGP server.

`--recover` requires the same exclusive lock as regular operations. It resolves
one named domain or all pending domains without contacting Cloudflare. Each
successful outcome is logged as domain and result; later failure in a batch
does not erase those earlier log entries. Explicit recovery prints its results.
Normal runs recover all pending journals before discovery or issuance, even
when `--domain` selects another domain. No new certificate changes proceed while
any journal remains pending. Read-only commands and ACME staging dry-run do not
trigger recovery. Staging dry-run retains its existing ACME/DNS behavior.

In the console, **F9** opens inspection and recovery for all domains, including
when normal discovery found no domains. Domain actions offer scoped inspection
and recovery. Recovery requires confirmation; inspection does not.

## Unresolved outcomes and current limits

Inspect the service journal and actual CGP configuration first. Do not publish
transaction or backup files: they contain private keys. Do not delete a pending
journal merely to unblock a timer. A corrupt file, foreign identity or unknown
remote state requires operator investigation; there is no force/overwrite or
automatic adoption mode.

If the previous certificate is already expired, invalid, inactive, or its
listener is unavailable, exact restoration may be possible while TLS proof is
not. The journal remains `restoring` and blocks subsequent mutations. This also
affects a crash in `prepared` while an already broken previous certificate is
still installed. The current development version has no special cancellation
outcome that waives TLS proof; safe bootstrap and operator-assisted resolution
are still roadmap items. Incomplete previous fields remain an explicit refusal.

Application installation uses the existing lock and preserves transaction
files. Its own crash recovery is separate and not made durable by this feature.
Upgrading or reverting application code does not authorize replaying a journal
with a different machine identity or unsupported schema.

The journal validates its own directory and files. Full ownership/permission
validation of the parent manager state directory, configuration, lock file and
older backups remains outstanding. The normal installer creates the state
directory with mode 0700. The mechanism assumes this parent remains trusted.

Backup pruning runs only after a newly applied transaction commits successfully.
Pending snapshots live in the journal independently of retained backup files.
Recovery and failed operations do not prune backups, so more than five may
remain until a subsequent successful installation.

## Evidence and test boundaries

- Unit tests cover all measured statements and branches, including corrupt
  schemas, permissions, failed file/directory fsync, failed replacement/deletion,
  uncertain remote replies, manual changes and interrupted verification.
- Subprocess tests terminate with `os._exit()` at every journal phase and on
  either side of remote restoration, then recover in a fresh process. A
  persisted fake CGP service models remote state; cryptography is isolated in
  these process-death tests.
- Separate tests generate temporary root/intermediate/leaf certificates and
  keys with real OpenSSL, use a real loopback TLS listener and check success,
  wrong keys, expired certificates, wrong SNI, changed certificates, extra or
  missing chain elements and the independence of old snapshots from `LIVE`.
- Installer CI uses disposable Ubuntu containers and mocked systemd, upgrading
  from stable 2.0.1 and 2.1.0 while checking pending journal bytes and permissions.

Process termination tests do not simulate a disk losing power, and local TLS
tests do not establish all CommuniGate or public ACME behavior. Production
validation and a release decision remain separate steps.
