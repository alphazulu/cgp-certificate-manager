# Authenticated offline update preparation

`cgp-update` verifies an administrator-supplied update package, prepares a
validated local staging tree and reports a reviewable plan. Every operation is
offline. Candidate code is never imported or executed, and preparation does not
replace the installed application, migrate its configuration, restart services
or activate a timer.

This checkpoint completes verification, preparation and inspection. Executing
an update with durable installation recovery is a separate implementation step.
Every public plan contains `apply_supported: false`; `plan_id` identifies the
plan and **is not an installation-authorization token**. There is no `--apply`
option, unattended update job, release download or latest-version lookup.

Real VM/server acceptance, production signing-key selection, a real signing
workflow and deployment remain deferred. No production trust root is bundled
or silently selected. The ordinary installer adds the launcher, but does not
create updater trust, state, credentials or scheduling.

## Use the trusted verifier

Use the already installed `cgp-update` launcher. From an independently trusted
source checkout, the equivalent entrypoint is:

```sh
python3 -m cgp_cert_manager.update_cli --help
```

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
| `--manifest`, `--signature`, `--archive` | All three required with `--check` or `--prepare`; all forbidden with `--status` |
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
| `--status` | Inspect existing state under a noncreating shared lock, reverify the signature and current policy, and validate the entire staged tree; no repair or installation |

`--status` uses the retained manifest, signature and inventory; the original
artifact files are not required. An existing state directory without its
`run.lock` produces `missing` / `lock_missing`; inspection does not create or
repair the lock. With no state directory, `--check` evaluates the supplied
candidate without a retained floor, while `--status` reports `missing`.

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

| Exit status | Meaning |
|---|---|
| `0` | The public result is `verified` or `prepared` |
| `2` | Invalid CLI usage, or a missing, busy, invalid, expired, changed or failed result |
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
| `missing` | A required input, state directory, existing lock or prepared record is absent |
| `busy` | The updater lock cannot be acquired immediately |
| `invalid` | A path, permission, schema, signature, archive, version or retained-floor check refused the operation |
| `expired` | The signed manifest has expired |
| `configuration_changed` | The bound trust policy or installed-version snapshot has changed |
| `error` | Verification support, reading, staging, checkpoint publication or an unexpected internal operation failed |

Failures return `plan: null` and a fixed error code such as `state_busy`,
`expired_manifest` or `state_write_failed`; they do not expose the underlying
exception text. Invalid CLI syntax is reported by the argument parser on stderr,
including when `--json` was requested, and does not invoke the coordinator.

The plan contains:

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
| `apply_supported` | Always `false` in this checkpoint |

Public output excludes local paths, key bytes, signatures and raw metadata.
Authenticated commit/tree identifiers are statements from the trusted signer;
the offline verifier does not fetch Git objects or query GitHub to compare them.

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
server, and no private key belongs in its update state. Removing a key from the
trust file affects subsequent verification, including `--status`; there is no
automatic key rotation or remote revocation fetch.

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

Only `--prepare` creates updater state. Its exclusive lock is separate from
certificate renewal and monitor operation locks. It does not serialize this
phase with the ordinary installer. Initial validation completes before a new
state directory is created. The private state directory contains
`checkpoint.json` and a private `staged` parent. Each new `release-xxxxxxxx`
container is `0700`; the validated source directories beneath it are `0755`,
and regular files retain their canonical `0644` or `0755` archive modes. Files,
directories and the containing parent are synced before publishing the
checkpoint.

The coordinator rechecks trust and the installed-version snapshot before commit.
Inspection uses a shared lock on existing state and revalidates the signature,
expiry, current trust, installed snapshot and every staged file's content and
metadata. Missing, extra, altered, linked or unsafe staged content does not
become a prepared result. Status does not silently repair or restage it.

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

Orphan cleanup is a separate administrator action performed only while updater
operations are idle, after checking which stages the retained checkpoint
references. Do not remove rollback floors, active stages, locks or unrelated
private evidence to bypass a refusal. Automatic retention management and
installation recovery are later work.

The installed baseline currently binds the safely read version file and its
digest. It is not a fingerprint of all application files, wrappers, units,
configuration or live service state, and it cannot authorize replacing them.
Storage checks do not isolate trusted code from a concurrent root/same-UID
process. See [Storage boundaries](STORAGE.md#boundaries-of-this-protection).

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

## Required next step before installation support

A complete apply operation needs a trusted executor and a durable transaction
contract. Merely wrapping the existing `install.sh` after verification is
insufficient:

1. The executor must verify the exact candidate again under its locks and bind
   explicit confirmation to the target manifest, current trust, complete
   installed preimages and proposed changes. A stale confirmation must fail.
2. Lock order must preserve the existing manager-then-monitor relationship. An
   updater holding both locks cannot call the ordinary installer path, which
   tries to acquire them again; it needs an explicit inherited-descriptor
   interface with inode and `flock` verification.
3. Backups and preimage identities must be durable before modifications. A
   journal must distinguish prepared, approved, applying, restoring and terminal
   outcomes, including interruption before a completion receipt is saved.
4. Recovery must operate from trusted code independent of the candidate being
   installed, verify restored files and preserve configuration, certificate/DNS
   transaction evidence and monitor delivery state. Service/timer reactivation
   must depend on the verified terminal outcome.
5. Restart and power-loss behavior needs an explicit execution gate and tested
   recovery path, rather than assuming an exception or process exit proves
   either installation or rollback completed.

The current installer retains its existing handled-failure rollback. Its shell
traps do not provide recovery after `SIGKILL` or power loss. Those limitations
are already documented in [Storage](STORAGE.md). This checkpoint does not change
that promise or authorize executing the staged installer.

## Validation and deferred acceptance

Automated tests use temporary trust roots, synthetic signed manifests, private
directories and generated archive fixtures. They check signature/policy refusal,
version/floor boundaries, archive attacks, staging failures, unchanged installed
files, read-only commands and safe CLI error projection. Every added code path
is subject to the repository's unit and branch coverage gates.

Synthetic tests do not establish a real release's authenticity or production
readiness. A later authorized acceptance session must review the selected trust
root, artifact/signing process, supported filesystem and interpreter, and the
future apply/recovery behavior on a disposable VM before a real server update.
No package from this work has been installed on the user's server by these
update-preparation commands.
