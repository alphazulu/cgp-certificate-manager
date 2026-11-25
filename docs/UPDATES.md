# Authenticated offline updates

`cgp-update` verifies an administrator-supplied update package, prepares a
validated local staging tree, presents a complete installation review and
applies an explicitly confirmed update with a durable recovery journal. Every
operation is offline. The updater treats candidate files as data: it does not
import or execute the candidate installer, migrations, hooks or application.
Preparation changes only updater staging/state. Installation is a separate
`--apply` action requiring the exact token from `--review`.

The package preparation `plan_id` remains an informational digest and **is not
an installation-authorization token**. Package plans still contain
`apply_supported: false`; a separate installation review determines whether the
prepared package and current installation can be applied. There is no unattended
update job, release download or latest-version lookup. An error after a pending
installation has been recorded requires explicit `--recover`; the updater does
not silently roll back or retry installation.

Real VM/server acceptance, production signing-key selection, a real signing
workflow and deployment remain deferred. No production trust root is bundled
or silently selected. The ordinary trusted installer provisions the independent
runtime and launcher, but does not create updater trust, state, credentials or
scheduling.

## Use the trusted verifier

Use the already installed `cgp-update` launcher. It loads the independent trusted
runtime at `/opt/cgp-update-runtime`, outside the application tree being
replaced. From an independently trusted source checkout, the CLI entrypoint is:

```sh
python3 -m cgp_cert_manager.update_cli --help
```

Source invocation supports package verification/preparation. Installation
review, apply and recovery require the installed trusted runtime and the fixed
managed layout. `cgp-update --version` identifies that runtime; it need not equal
the version of a subsequently installed application. Transactional installation
preserves the runtime and updater launcher.

**Do not run the verifier from the candidate archive it is supposed to check.**
The candidate cannot establish its own authenticity. Verification uses the
current trusted implementation and an administrator-controlled public-key file.
The offline updater requires **Python 3.11 or newer on Linux**. This requirement
is specific to updater actions and does not change the runtime requirement for
other manager features. Safe staging cleanup uses a retained parent-directory
descriptor with `shutil.rmtree(..., dir_fd=...)`; Python added that parameter in
[3.11](https://docs.python.org/3.11/library/shutil.html#shutil.rmtree).
Ed25519 verification requires the native interpreter's `cryptography` package
(`python3-cryptography` on the supported Debian/Ubuntu packaging path).
`--help` and `--version` do not load update metadata, trust, state or the
cryptographic backend.

| Option | Default or requirement |
|---|---|
| `--trust-file` | `/etc/cgp-update/trust.json` |
| `--state-dir` | `/var/lib/cgp-update` |
| `--installed-root` | `/opt/cgp-certificate-manager` |
| `--manifest`, `--signature`, `--archive` | All three required with `--check` or `--prepare`; forbidden with all other actions |
| `--confirm-update TOKEN` | Required only with `--apply`; exactly 64 lowercase hexadecimal characters |
| `--json` | Emit the fixed public JSON result instead of text |

All supplied paths must be absolute and must not contain a `..` component.
A double-slash root (`//...`) is refused.
Filesystem checks remain mandatory after CLI validation. Arguments select local
files and directories; URLs are not accepted as artifact sources.

Manifest, signature and archive inputs are public regular files, normally mode
`0644` or `0600`. Read and execute permission bits are permitted; group/other
write and special permission bits are refused. Files must be owned by root or
the effective UID and have exactly one hard link. Symlinks and nonregular files
are refused. Their parent paths are walked without following symlinks and must
satisfy the trusted-directory checks. The trust document follows separate
private-storage rules: effective-UID ownership and mode `0600` or stricter,
without execute bits, with a trusted parent path. These checks do not
automatically change an existing file's owner or permissions; see
[Storage](STORAGE.md).

The updater state path must not overlap the installed application, the trusted
verifier checkout, manager/monitor configuration or state, Certbot storage, the
trust file or any input artifact. Equal, ancestor and descendant paths are
refused. Keep supplied manifests, signatures and archives outside updater state.

## Commands and outcomes

Exactly one of the following actions is required:

| Action | Effect |
|---|---|
| `--check` | Authenticate metadata and archive, validate archive contents, inspect the installed version and any existing rollback floor; return a plan without creating state or advancing the floor |
| `--prepare` | Validate the inputs, acquire the updater's own exclusive lock, write a private staging tree and atomically publish its checkpoint and rollback floor |
| `--review` | Read the prepared candidate, complete installation preimages, preserved resources and local service state; return the exact confirmation token without writing |
| `--apply --confirm-update TOKEN` | Recompute the review under exclusive locks, require the exact token, save durable recovery data, stop both timers and install the approved payload |
| `--recover` | Restore preimages for a nonterminal installation; for a terminal record, validate its recorded outcome and finish clearing the pending marker |
| `--status` | Report an installation record first; otherwise inspect the prepared package; no repair, installation or recovery |

Inspection never creates a missing state directory or lock. Package inspection
uses the retained manifest, signature and inventory; the original artifact files
are unnecessary. An existing package-state directory without `run.lock` produces
`missing` / `lock_missing`. With no state directory, `--check` evaluates the
supplied candidate without a retained floor, while `--status` reports `missing`.
An invalid installation record takes precedence over package inspection and is
not hidden by an expired signature, missing trust file or damaged application.

The following paths and version are illustrative, not a published release or
a configured trust root. After obtaining artifacts and trust through the
administrator's separately established process, a local check would be:

```sh
cgp-update --check \
  --manifest /srv/offline/cgp-release/update-manifest.json \
  --signature /srv/offline/cgp-release/update-signature.json \
  --archive /srv/offline/cgp-release/cgp-certificate-manager-v2.3.0.tar.gz \
  --json
```

Preparing the same inputs writes only updater staging/state:

```sh
cgp-update --prepare \
  --manifest /srv/offline/cgp-release/update-manifest.json \
  --signature /srv/offline/cgp-release/update-signature.json \
  --archive /srv/offline/cgp-release/cgp-certificate-manager-v2.3.0.tar.gz \
  --json
cgp-update --status --json
```

These examples have not been executed against a real installation or real
release trust. They do not authorize running the staged package's installer.

The following installation commands describe the interface for a later,
separately authorized acceptance session. **Real VM/server acceptance and real
trust/signing remain deferred.** `TOKEN` is a nonworking placeholder, not a
confirmation value:

```sh
cgp-update --review --json
cgp-update --apply --confirm-update TOKEN --json
cgp-update --status --json
```

An administrator must read the complete review before substituting its exact
`confirmation_token`. There is no automatic application after review. If an
installation is pending, inspect it and explicitly request recovery:

```sh
cgp-update --status --json
cgp-update --recover --json
```

Do not remove `pending.json` to unblock normal operation. Recovery validates the
journal and filesystem before it changes anything.

| Exit status | Meaning |
|---|---|
| `0` | The public result is `verified`, `prepared`, `review_ready`, `applied` or `rolled_back` |
| `2` | Invalid CLI usage, or a missing, busy, invalid, expired, changed, failed or `recovery_required` result |
| `130` | Interrupted operation |

Public results contain exactly `schema`, `action`, `status`, `plan` and `error`.
The schema is 1. The backend uses fixed status/error codes; unexpected exceptions
become `update_failed`, without their original text or a traceback. An interrupt
reports `interrupted`. Rendering is completed before output, so a rendering
failure does not print half of a successful plan.

| Public status | Meaning |
|---|---|
| `verified` | `--check` authenticated the supplied candidate and returned a plan |
| `prepared` | `--prepare` published a prepared checkpoint, or `--status` revalidated it |
| `review_ready` | Read-only installation review succeeded; explicit apply is still required |
| `applied` | The installation has a committed applied record |
| `rolled_back` | Explicit recovery completed the recorded rollback |
| `recovery_required` | A pending or invalid installation record needs explicit inspection/recovery |
| `missing` | A required input, state directory, existing lock or prepared record is absent |
| `busy` | The updater lock cannot be acquired immediately |
| `invalid` | A path, permission, schema, signature, archive, version or retained-floor check refused the operation |
| `expired` | The signed manifest has expired |
| `configuration_changed` | The bound trust policy or installed-version snapshot has changed |
| `error` | Verification support, reading, staging, checkpoint publication or an unexpected internal operation failed |

Errors use fixed codes such as `state_busy`, `expired_manifest`,
`confirmation_mismatch` or `state_write_failed`; they do not expose underlying
exception text. `plan` is null when no valid public plan can be returned.
Installation status can include its safe journal projection even while recovery
is required. Invalid CLI syntax is reported by the argument parser on stderr,
including when `--json` was requested, and does not invoke the coordinator.

The schema-1 envelope is unchanged; `plan` is action-specific. A package
check/preparation plan contains:

| Fields | Meaning |
|---|---|
| `plan_id` | Informational local digest; not approval to install |
| `project`, `channel`, `sequence` | Authenticated project/channel and monotonic release sequence |
| `installed_version`, `target_version` | Observed installed version and authenticated candidate version |
| `key_id` | SHA-256 identifier of the trusted public key used for verification |
| `manifest_sha256`, `archive_sha256`, `archive_size` | Exact authenticated metadata/archive identities and compressed size |
| `source_commit`, `source_tree`, `release_tag` | Publisher's authenticated source statements |
| `issued_at`, `expires_at` | Signed UTC epoch-second validity interval |
| `file_count`, `total_bytes`, `inventory_sha256` | Validated extracted-file inventory and payload size |
| `created_at` | Local plan creation time |
| `apply_supported` | Always `false` for the package preparation plan; it is not installation approval |

Public output excludes local paths, key bytes, signatures and raw metadata.
Authenticated commit/tree identifiers are statements from the trusted signer;
the offline verifier does not fetch Git objects or query GitHub to compare them.

An installation review/status plan includes `transaction_id`, `phase`,
`confirmation_token`, package identity fields, `targets` with each managed
resource's before/after fingerprints, and `timers` with the observed activity,
the intended stopped outcome and preserved enablement. It also reports
`configuration: "preserved_without_migration"` and `automatic_rollback: false`.
A review has no allocated transaction ID. An installation status reports the
retained journal outcome; it is not an application health check or a fresh
integrity scan of a completed installation.

## Trust and signature format

The local trust document has exactly these fields:

| Field | Value |
|---|---|
| `schema` | Integer `1` |
| `project` | `cgp-certificate-manager` |
| `channel` | `stable` or `candidate` |
| `keys` | Map of 1–16 trusted key IDs to canonical Base64-encoded raw Ed25519 public keys |

Each public key is 32 bytes. Its key ID is the lowercase SHA-256 of those raw
bytes. A detached signature document has exactly `schema: 1`, `key_id` and
`signature`; the signature is canonical Base64 encoding of 64 bytes. The key ID
must already exist in the local trust document. A public key supplied by an
archive, manifest, URL or signature is not automatically trusted.

The administrator obtains and authenticates public keys through an independent
process and maintains the trust file. No private signing key is needed by the
server, and no private key belongs in its update state. Removing a key affects
subsequent package verification, package status and installation approval.
Inspection and recovery of an existing installation journal do not require the
current trust file: their evidence is the already recorded transaction and local
preimages. There is no automatic key rotation or remote revocation fetch.

Verification uses Ed25519 over the following exact bytes, without prehashing:

```text
b"CGP-CERTIFICATE-MANAGER-UPDATE-V1\n" + manifest_bytes
```

The manifest must use the implementation's canonical encoding: sorted JSON
object keys, compact separators, ASCII escaping, no nonfinite values, and one
final LF. Reformatting a manifest changes its signed bytes and is refused.
Trust and signature documents may be formatted for readability, but still
reject duplicate/unknown fields, floating-point/nonfinite numbers and excessive
structure. This is a single-signature protocol: any one configured key can
authenticate a manifest. It has no threshold-signature or TUF metadata-role
implementation. See [update_metadata.py](../cgp_cert_manager/update_metadata.py),
the [cryptography Ed25519 API](https://cryptography.io/en/50.0.2/hazmat/primitives/asymmetric/ed25519/)
and [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html).

### Signed manifest schema

The manifest contains exactly `schema`, `project`, `channel`, `sequence`,
`version`, `issued_at`, `expires_at`, `source` and `archive`.

- `schema` is integer 1; `project` is `cgp-certificate-manager`.
- `channel` must match the administrator's selected trust channel.
- `sequence` is an integer from 1 through `2**63 - 1`.
- `version` is `X.Y.Z` or `X.Y.ZrcN`; development versions are not signed update
  targets. The stable channel accepts final versions. The candidate channel
  accepts release candidates or final versions.
- `issued_at` and `expires_at` are integer UTC epoch seconds. The validity
  interval must be positive and at most 30 days. The current clock must be at
  or after issuance and strictly before expiry.
- `source` contains exactly `repository`, `commit`, `tree` and `tag`.
  Repository is `alphazulu/cgp-certificate-manager`; commit/tree are lowercase
  hexadecimal Git IDs of matching length, 40 or 64 characters. The tag must be
  `v` followed by the manifest version.
- `archive` contains exactly `name`, `size` and `sha256`. The filename must be
  `cgp-certificate-manager-v<version>.tar.gz`, with the authenticated compressed
  size and lowercase SHA-256 digest.

There is no string-based or lexicographic version comparison. Ordering uses
numeric major/minor/patch components and development, candidate, final ranks.
The installed version may include `.devN` or `rcN`; the target must be strictly
newer. Reinstalling the same version is therefore not accepted as an update.

### Freshness and rollback floor

Prepared state retains a separate floor for each project/channel: sequence,
manifest digest, version and verification time. A lower sequence or lower target
version is refused. Reusing the same sequence requires the exact same manifest
digest and version. Moving the clock behind the retained verification time is
also refused.

`--check` consults an existing floor but never advances it. `--prepare` reloads
the floor under its exclusive lock and publishes it together with the prepared
checkpoint only after staging has been verified and synced. Time and signature
policy are checked again after archive/stage inspection and before publication;
clock regression or expiry during that work is refused. A floor records
accepted update metadata; it is not proof of installation. Do not remove or
reset it to make an older candidate pass.
Changing channels is an explicit local policy change; floors are partitioned
by channel rather than silently overwritten by another channel's sequence.

Offline verification cannot establish that this is the newest release available
or discover a remote key revocation. It enforces the local trust, clock,
installed-version and retained-floor policy against the supplied artifact.

## Bounded archive validation

The whole archive's SHA-256 and compressed size must match the authenticated
manifest. Parsing then requires the deterministic source layout produced by
[repo_tools.release](../repo_tools/release.py): one version-specific top-level
directory and regular files in UTF-8 path order. Only the canonical file modes
`0644` and `0755` are allowed. Long or Unicode names use only the supported
canonical PAX `path` representation.

Links, devices, sparse files, global PAX records, unsupported metadata, path
traversal, duplicate/conflicting paths and Unicode-normalization/casefold
collisions are refused. Additional gzip streams, archive trailers and extra
payload are not accepted as another candidate. Extraction does not use an
unrestricted archive extraction operation.

| Limit | Maximum |
|---|---:|
| Signed manifest | 16 KiB |
| Detached signature document | 4 KiB |
| Trust document | 16 KiB |
| Metadata nesting / visited nodes | 8 levels / 256 nodes |
| Compressed archive | 256 MiB |
| Decompressed tar stream | 256 MiB |
| Total regular-file content | 128 MiB |
| Individual file | 32 MiB |
| Regular files / implicit directories | 20,000 each |
| UTF-8 path / component | 4096 / 255 bytes |
| Path depth | 64 components |
| Application metadata / PAX record | 64 / 8 KiB |
| Canonical computed file inventory | 16 MiB |
| Serialized private checkpoint | 16 MiB |

The candidate's `__version__` is parsed as one literal assignment, without
importing it. It must agree with the signed version and the single corresponding
Certbot distribution metadata directory. Plugin registration must identify the
expected application-local authenticator. The source does not run a compiler,
import hook, setup hook, dependency installer or candidate script during any
update-preparation action.

## Staging, preservation and inspection

`--prepare` initializes updater state when needed. Its exclusive lock is
separate from certificate renewal and monitor operation locks. Package staging
does not acquire the installation locks; it refuses a pending installation
instead. Initial validation completes before a new state directory is created.
The private package state consists of `checkpoint.json` and a private `staged`
parent. Each new `release-xxxxxxxx`
container is `0700`; the validated source directories beneath it are `0755`,
and regular files retain their canonical `0644` or `0755` archive modes. Files,
directories and the containing parent are synced before publishing the
checkpoint.

The package coordinator rechecks trust and the installed-version snapshot before
checkpoint publication. Package inspection uses a shared lock on existing state
and revalidates the signature, expiry, current trust, installed-version snapshot
and every staged file's content and metadata. Missing, extra, altered, linked or
unsafe staged content does not become a prepared result. Status does not silently
repair or restage it. Once an installation receipt exists, `--status` reports that
receipt first; it does not replace it with a package inspection result.

Up to four staged snapshots are retained. Preparing the exact current plan
revalidates and reuses its stage and original `created_at`, while advancing the
floor's verification time. It does not renew the signed expiry. No filesystem
immutable flag is set: the owner can alter a staged tree, and inspection then
refuses the altered snapshot. There is no automatic pruning. A failure while
publishing a checkpoint can leave a verified but unreferenced stage. It remains
available for inspection instead of being silently deleted or treated as
installed. A failure after an atomic replacement may leave the new checkpoint
visible even when its durability could not be confirmed; rerun read-only
inspection rather than assuming no write happened.

Package-stage orphan cleanup is a separate administrator action performed only
while updater operations are idle, after checking which stages the retained
checkpoint references. Do not remove rollback floors, active stages, locks,
installation evidence or pending markers to bypass a refusal. There is no
automatic retention-management command.

The package preparation baseline binds the safely read version file and its
digest. It cannot authorize replacing an installation. `--review` adds the
complete managed-target and preserved-resource snapshots described below and
issues a separate confirmation token. Storage checks do not isolate trusted
code from a concurrent root/same-UID process. See
[Storage boundaries](STORAGE.md#boundaries-of-this-protection).

## Installation review and exact approval

Installation actions support the fixed installed layout. Overriding
`--installed-root` or `--state-dir` does not permit a source checkout to replace
arbitrary files. A trusted ordinary installation must already have provisioned
the independent runtime, launcher templates and manager/monitor lock files.
Package preparation must already have initialized updater state and its own
lock. The runtime and updater launcher are outside all replacement targets.

The candidate must include this exact supported descriptor:

```json
{"configuration_schema":2,"layout":1,"project":"cgp-certificate-manager","schema":1}
```

It is stored as `update-install.json` at the archive root below the release
prefix. The descriptor declares a supported data layout; it is not a script or
a migration permission. The current manager configuration must already use
schema 2, DNS and scheduling configuration must validate, and an optional monitor
configuration must validate. Configuration needing migration is refused.

| Resource | Installation behavior |
|---|---|
| `/opt/cgp-certificate-manager` | Replace as one directory; install the candidate `cgp_cert_manager` package and corresponding Certbot distribution metadata, preserving every other existing root-level file/directory |
| `cgp-letsencrypt`, `cgp-certbot`, `cgp-monitor` launchers | Manage only the three fixed files under `/usr/local/sbin`; require supported trusted baseline launchers |
| Manager/monitor services and timers | Manage the four existing fixed unit files under `/etc/systemd/system`; their baseline bytes must match trusted templates |
| `/opt/cgp-update-runtime` and `cgp-update` launcher | Bind their complete snapshots to approval and preserve them |
| Machine ID, manager configuration, optional monitor configuration and manager timer drop-in | Bind their snapshots or explicit absence to approval; preserve them without migration |
| Manager/monitor transaction and delivery state, credentials and Certbot storage | Outside replacement targets; no rollback or rewriting of their contents |

Candidate launchers and units must be byte-for-byte equal to the current trusted
runtime's templates. The existing three normal launchers and four unit files
must also be present and have those exact trusted bytes. Modified unit contents
or a missing unit are refused as an unsupported baseline. Safe existing unit
modes may differ: apply normalizes them to `0644`, and rollback restores their
recorded modes. Existing launcher mode `0750` is required. Generic snapshot
support for absence does not authorize creating a missing managed unit.

This implementation cannot update trusted templates or its own executor through
candidate code. Other files from the candidate archive,
including its installer and release documentation, are not installed over
operator-maintained files. The updater never invokes the candidate installer,
application, compiler, dependency installer, import hooks or migrations.

`--review` uses shared, noncreating locks in manager → monitor → updater order.
`--apply` and `--recover` acquire the same locks exclusively and nonblockingly.
A busy or missing lock refuses the action. The local systemd observation must
show both services inactive and all four managed units loaded from the expected
unit paths. Unexpected unit fragments/drop-ins are refused; the supported
manager timer drop-in must match the current schedule. Timers may be active or
inactive at review time. Review also requires `NeedDaemonReload=no` for every
managed unit. Recovery may stop timers while that property is `yes`, as expected
after an interrupted unit-file replacement; the final `daemon-reload` must leave
the property `no` and both timers stopped.

Recovery also handles two states caused by an interrupted installation and
restart. A managed unit whose file is in a verified rename gap may appear as
`not-found` after systemd loses its cache. Only that specifically absent target
is permitted to be unloaded, with inactive state and empty fragment/drop-in
paths; an unloaded timer is not passed to `systemctl stop`. After restoration,
the final reload must find every managed unit loaded from its expected path.

A timer that tries the guarded launcher while an update is pending can leave
its service `failed`. Recovery accepts an inactive or failed service only with
`MainPID=0`, `ControlPID=0` and an empty `ControlGroup`. A retained cgroup or
tracked process blocks recovery before target restoration. A failed result is
preserved: recovery does not reset the failure, start a service or change
enablement. Ordinary installation review/apply still requires inactive services
and all managed unit files present with their trusted template bytes.

The installation `confirmation_token` is a domain-separated SHA-256 digest of
the approved package/trust identities, complete before/after managed snapshots,
preserved snapshots, observed timer/service state and previous installation
receipt generation. It is distinct from `plan_id`. Application recomputes these
facts under exclusive locks and requires the exact token. A changed file,
permission, owner, timestamp, empty directory, absence, configuration, runtime,
trust policy or relevant service observation invalidates the approval. A prior
token cannot be replayed after a recorded rollback because the receipt
generation has changed.

There is no separate promised token lifetime. Signed metadata must still meet
the freshness policy and the current installation must still match the exact
review. Administrators must inspect the review themselves; the CLI does not
automatically fetch a new token or retry a stale approval.

Freshness is checked again after full stage validation. Review verifies that
the clock has not moved behind the operation's start and the manifest has not
expired before returning `review_ready`. Apply checks the same time window
before journal/pointer publication, before publishing the pending marker and
after stopping timers and completing its final prepared-package/readback
checks, before the first managed-target rename. Expiry or clock regression
after a pending marker has been written leaves explicit recovery required even
if no managed file has yet been replaced.

### Supported snapshot metadata and limits

Snapshots record regular-file content hashes, complete directory membership,
empty directories, explicit absence, permission modes, numeric UID/GID and
nanosecond modification times. Files have one hard link; symlinks and special
files are refused. Unsupported extended attributes, including ACLs and file
capabilities represented as xattrs, are refused rather than silently discarded.
Modes with group/other write or special permission bits are refused, and owners
must be root or the effective UID. Each target and its retained replacement slot
must remain on the same filesystem.

| Snapshot/recovery limit | Maximum |
|---|---:|
| Entries in one managed/preserved snapshot | 20,000 |
| Directory depth | 64 |
| UTF-8 relative path | 4096 bytes |
| Individual regular file | 32 MiB |
| Regular-file content in one snapshot | 128 MiB |
| Distinct retained backup objects / combined content | 20,000 / 256 MiB |
| Serialized installation journal | 32 MiB |
| Retained installation directories | 4 |

Modification times must fit signed 64-bit nanoseconds. Rollback restores the
recorded content, modes, ownership, membership and modification times; it does
not restore original inode numbers, creation/change times or access times.
Race witnesses such as inode/ctime are checked during capture but are not a
promise to reproduce those filesystem identities. Candidate package bytecode
caches are refused, and the updater does not generate new caches. Existing
baseline caches are captured with the old application and restored on rollback.
Supported launchers suppress new Python bytecode writes.

## Durable installation and explicit recovery

Before replacing a managed target, apply saves and verifies private recovery
objects, materializes the approved new contents in a private sibling slot,
rechecks the approval, and records the installation journal and pending marker.
It then stops both timers, confirms services remain inactive, and performs each
replacement using recorded rename boundaries with file/directory synchronization.
The whole application can temporarily be absent between its two renames.

The private evidence consists of:

- `installation.json`, the current installation pointer;
- `pending.json`, the persistent execution gate;
- `installations/<transaction-id>/journal.json` and content-addressed private
  backup objects;
- `.cgp-update-<transaction-id>-<target>` sibling slots containing the recorded
  old, new or undo contents for each changed target.

The journal distinguishes `staged`, `applying`, `restoring`, `applied` and
`rolled_back`. Completion requires exact installed readback, preserved-resource
verification, `daemon-reload` and stopped-timer verification before a terminal
receipt is saved and the pending marker is cleared. Normal supported launchers
check the independent gate before importing the application and again under
their operation locks. Any pending marker, including an unreadable or malformed
one, blocks normal execution across process exits and reboots.

An error after the pending marker is written leaves recovery explicit. The
updater does not infer success from a process exit, automatically undo a partial
installation or continue a partially applied candidate. `--recover` first
validates the entire journal, required backup objects, all target/slot states
and preserved resources before performing rollback writes. A foreign filesystem
state, changed preserved configuration/runtime or corrupt/missing evidence
causes a refusal and retains the pending marker.

A JSON `null` in an installation pointer, pending marker or journal is
corruption, not an absent file. If `installation.json` is missing, the loader
checks the bounded retained installation directories for any `journal.json`;
finding one refuses review/apply/recovery with `journal_missing` instead of
resetting approval history. It never chooses the newest journal, adopts an
orphan transaction or deletes ambiguous evidence. An interruption after the
first journal save but before pointer publication precedes managed-target
replacement, but still requires manual inspection rather than automatic
recovery selection. Missing pointers are not proof that no earlier replacement
occurred. Retained slots/backups from an attempt that never wrote a journal may
remain within the capacity limits; they do not become an installation receipt.

For a nonterminal journal, recovery restores the recorded preimages in reverse
target order and records `rolled_back`. Repeating recovery after an interruption
classifies the actual supported rename states and resumes restoration. If an
`applied` or `rolled_back` terminal receipt was saved before pending-marker
clearance, recovery validates that recorded outcome and finishes clearance;
it does not turn a committed installation into a rollback.

Recovery runs from `/opt/cgp-update-runtime` even if the application directory is
absent or unusable. It needs the retained private installation evidence, slots,
runtime and preserved-resource identities. It does **not** need the original
archive, manifest/signature files, package checkpoint/stage, current trust file,
a currently valid release signature or the cryptographic backend. This is
recovery of a previously approved local transaction, not approval of another
package. Manual edits to a retained transaction or preserved resources are not
an automatic repair mechanism.

Both timers remain stopped after successful apply or recovery; their enablement
is preserved. Neither operation starts, enables or tests the manager/monitor
services. Reactivation and application acceptance are separate administrator
decisions. No certificate issuance, CGP mutation, DNS mutation or notification
is performed by the updater itself.

Installation directories and sibling slots are retained. The cap of four
installation directories is independent of the four package-stage cap and
includes incomplete attempts created before journal publication. There is no
automatic pruning. Failures before a pending marker may retain unreferenced
slots/backups without changing managed targets. Do not delete recovery evidence
or pointers to evade capacity or integrity checks; a retention/cleanup command
is outside this checkpoint.

These guarantees apply to this explicit update engine. The ordinary shell
installer retains its handled-failure rollback and is not silently converted
into a durable updater. Its shell traps do not recover from `SIGKILL` or power
loss. The update engine uses fsync and a persistent journal, but automated process
crash tests do not establish the behavior of every filesystem or actual storage
device under power loss. Concurrent root/same-UID namespace mutation also remains
outside a security-isolation guarantee.

## Relationship to release preparation

The existing release builder produces an archive, `.sha256` checksum and
`.provenance.json`. That provenance document is not this signed update manifest.
A checksum establishes byte consistency, not signer trust. GitHub artifact
attestations produced by the separate release workflow are a different evidence
format and are not silently substituted for the local Ed25519 protocol.

From a trusted source checkout, [repo_tools.update_manifest](../repo_tools/update_manifest.py)
assembles the unsigned canonical bytes for a separate signing process. It reads
the existing provenance and archive, requires a matching nondevelopment version
and `v<version>` release tag, validates metadata, and checks the complete archive
against its recorded size, digest and source layout. It emits the manifest to
stdout only after those checks succeed. It does not authenticate the unsigned
provenance or verify the publisher's Git statements against a remote repository.

For an illustrative prepared release, set `UPDATE_SEQUENCE`, `ISSUED_AT` and
`EXPIRES_AT` to the administrator-reviewed integer sequence and UTC epoch-second
validity interval before invoking:

```sh
python3 -m repo_tools.update_manifest \
  --provenance /srv/offline/cgp-release/cgp-certificate-manager-v2.3.0.provenance.json \
  --archive /srv/offline/cgp-release/cgp-certificate-manager-v2.3.0.tar.gz \
  --channel stable \
  --sequence "$UPDATE_SEQUENCE" \
  --issued-at "$ISSUED_AT" \
  --expires-at "$EXPIRES_AT" \
  > /srv/offline/cgp-release/update-manifest.json
```

The output redirection is an explicit operator action. Use a new destination
and check the command's exit status before passing its output to a signer;
shell redirection can create an empty file when validation fails. The helper
returns `0` on success and `2` for invalid/unreadable inputs. It does not sign,
create keys or trust, publish a release, or advance a server's rollback floor.
The signer must sign the domain prefix plus these exact bytes using the chosen
external signing process. Signature packaging and production key bootstrap
remain administrator-controlled operations.

The current workflow does not select the owner's update trust keys or supply
an administrator-approved production signing policy. Publishing a release,
choosing signing keys and issuing update manifests remain separately controlled
operations. See [Releasing](RELEASING.md).

## Validation and deferred acceptance

Automated tests use temporary trust roots, synthetic signed manifests, private
directories and generated archive fixtures. They check signature/policy refusal,
version/floor boundaries, archive attacks, staging failures, exact approval,
read-only commands and safe CLI error projection. Fresh-process fault tests
interrupt installation and rollback at rename boundaries, including an absent
application directory, and recover from the independent runtime without the
original verification inputs. They distinguish a terminal receipt from a
partially completed installation and verify preserved manager/monitor evidence.
Systemd is a local stub in these tests; they do not exercise a real boot sequence.
Every added code path is subject to the repository's unit and branch coverage
gates.

Synthetic tests do not establish a real release's authenticity or production
readiness. A later authorized acceptance session must review the selected trust
root, artifact/signing process, supported filesystem and interpreter, and the
apply/recovery and reboot behavior on a disposable VM before a real server
update. No package from this work has been installed on the user's server by
these update commands. Coverage and synthetic crash tests are not proof of
production signing security or universal power-loss recovery.
