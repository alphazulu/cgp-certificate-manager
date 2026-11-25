# Private storage policy

This policy describes the checks introduced in **2.2.0.dev1** and extended in
**2.2.0.dev2**. Version **2.2.0.dev3** adds a separate `--bootstrap-check`
diagnostic: it securely reads configuration, but creates no state or operation
lock and performs no fsync. Other command locking remains as documented here.
The stable production release
remains 2.1.0. The implementation is in
[storage.py](../cgp_cert_manager/storage.py); its callers include the CLI,
configuration wizard, transaction journal and installer.

## Files and directories covered

The private storage policy covers manager configuration, Cloudflare credential
files, and the manager's state under `/var/lib/cgp-letsencrypt`. That state
includes `run.lock`, JSON state and discovery files, history, certificate backups,
configuration backups, pending transaction journals and operator-resolution
authorization/completion evidence. Certificate backups, journals and resolution
authorizations contain private keys. See [operator resolution](RESOLUTION.md).

| Object | Required ownership and metadata |
|---|---|
| Private state directory and every directory beneath it | Owned by the process's effective UID; mode `0700` or stricter; no group/other access or special permission bits |
| Configuration, credentials and private state files | Regular file owned by the effective UID; mode `0600` or stricter; no execute or special permission bits; exactly one hard link |
| Ancestor directories of a protected path | Owned by root or the effective UID; not writable by group/others, except for a trusted sticky directory such as `/tmp` |

An installed manager runs as **root**, so the effective-UID checks require root
ownership there. Isolated tests and development may run under another effective
UID. A restrictive mode still needs to allow the access requested by the
operation; for example, an unreadable file can pass a mode limit and then fail
when opened.

Every directory component is opened without following symbolic links. Private
file opens also reject symlinks, including dangling links, and files with more
than one hard link. FIFOs, sockets, devices and directories cannot be used as
private files. Paths containing a `..` component are refused.

The parent of a configuration or credential file is a **trusted ancestor**, not
necessarily a private state directory. An existing root-owned
`/etc/cgp-letsencrypt` directory with mode `0755` is accepted when its ancestors
are trusted and the files themselves satisfy the private-file policy. New
installations should use the `0700` configuration directory shown in the README.
The stricter directory rule applies to `/var/lib/cgp-letsencrypt` and its entire
tree, including backup and transaction directories.

## When validation happens

The CLI acquires the manager's operation lock, validates the existing private
state tree without reading file contents, and loads configuration through the
secure reader before dispatching an operation. Thus an unsafe history file or
backup stops the run before discovery, recovery, issuance or deployment begins.
This applies to diagnostics too: an unsafe state tree is reported rather than
silently ignored. Acquiring the lock can create a missing state directory and
lock file; diagnostic commands do not perform certificate recovery.

Certbot hooks are children of the process holding that lock. They validate state
and configuration but do not acquire a second lock. Cloudflare credentials are
checked when read, and issuance checks the selected credential files before DNS
preflight or launching Certbot. Backup enumeration validates selected files
before listing or restoring them. History is checked before reading or appending;
the console reports `History unavailable` when it cannot safely read it.

The configuration wizard uses the same operation lock and state validation.
Staged token writes, configuration backups and the configuration commit use the
secure storage helpers. Existing unsafe configuration is not replaced with
defaults or silently repaired.

The [installer wrapper](../cgp_cert_manager/installer.py) acquires the same
validated lock and checks existing state, configuration, schedule and configured
credentials before entering the installation payload. It passes the open lock
descriptor to the shell, which verifies that it refers to the current manager
lock file. The descriptor remains open through installation and handled rollback;
the payload does not reopen an unchecked lock path. These checks precede timer
changes and application replacement.

## Writes and refusal behavior

New private directories are created with mode `0700`, and files with mode `0600`,
subject to a more restrictive process umask. Existing unsafe objects are refused.
The storage helpers do not automatically run `chmod` or `chown` to make a failing
check pass.

Private files are validated on their opened descriptors before reading,
appending or truncating. Atomic saves write a new private temporary file in the
validated parent directory, flush and synchronize it, recheck an existing target,
replace the target and synchronize the directory. Directory creation also
synchronizes its parent. A failure after replacement can mean that the new file
is visible while durability remains uncertain; callers must retain recovery
evidence rather than assume that an exception means no write occurred.

The operation lock uses a nonblocking exclusive `flock` on a validated regular
file. Opening it does not truncate existing contents. A busy or unsafe lock stops
the operation. Existing journals are not deleted to bypass permission or recovery
errors.

## Inspecting a refused path

Inspect the exact path named in the error and its parent directories. These
commands show metadata and path components, not file contents:

```sh
sudo stat -c '%A %a %U:%G links=%h %F %n' \
  /etc/cgp-letsencrypt /etc/cgp-letsencrypt/config.json \
  /var/lib/cgp-letsencrypt /var/lib/cgp-letsencrypt/run.lock
sudo namei -l /etc/cgp-letsencrypt/config.json
sudo namei -l /var/lib/cgp-letsencrypt/run.lock
```

For a credential, backup or journal failure, run the same inspection against the
specific reported path. Confirm what the object is, who owns it and whether it
is a link before deciding on a correction. Do not publish its contents. Avoid
recursive permission or ownership changes: they can affect unrelated objects,
hide an unexpected link and destroy useful evidence. The manager deliberately
leaves an unsafe object unchanged for an administrator to investigate.

## Boundaries of this protection

- Standard Certbot paths under `/etc/letsencrypt/live` normally use symlinks into
  the archive. They are **outside this private-storage policy** and remain
  supported. Their ownership, permissions and lifecycle are managed by Certbot;
  certificate and TLS validation remain separate checks.
- Application files, the launcher and public systemd units/drop-ins are not
  private state. Their installed modes are not required to be `0600`/`0700` by
  this helper. The installer must be run from trusted source.
- These checks protect against unsafe filesystem metadata and paths controlled
  by another UID. They do not isolate the manager from root or a concurrent
  process with the same trusted effective UID. `flock` coordinates cooperating
  manager processes; it does not prevent a privileged administrator from
  modifying files or CGP settings outside the manager.
- Validation checks POSIX file type, ownership, mode bits, link count and path
  components. It is not a general filesystem, mount, ACL or security-label audit,
  and it does not detect earlier disclosure of a secret.
- Durable private-file writes and the certificate journal do not make the
  application installer recoverable after power loss or `SIGKILL`. Its rollback
  still covers handled failures. See [certificate transaction boundaries](TRANSACTIONS.md).

## Validation evidence

Checkpoint 4 passed **386 tests**, with **1,742 measured statements and 692
branches at 100% coverage**, plus Python compilation, shell syntax and diff
checks. This includes filesystem refusal tests and unit tests for the inherited
installer lock. [CI 45367278665](https://github.com/alphazulu/cgp-certificate-manager/actions/runs/45367278665)
confirmed the same totals for implementation commit `d2bad6e`; tests, both Docker
installer baselines and packaging passed. Each installer baseline also passed
18 unsafe-path refusal cases. Production validation of 2.2.0.dev1 remains a
separate step. See
[DEVELOPMENT.md](../DEVELOPMENT.md) for subsequent runs and the current handoff.
