# Explicit acknowledgement of previous settings

This procedure belongs to **2.2.0.dev2**, an unreleased development version.
It addresses a specific recovery limit: the four previous CGP certificate
settings are present again, but their certificate is expired, invalid, inactive
or cannot be verified on its recorded TLS listener. Normal recovery retains a
blocking journal because it cannot prove successful TLS restoration.

An administrator can explicitly accept those **unchanged previous settings**
and retire the pending operation while keeping its full evidence. The result
is always **`acknowledged_unverified`**, never `restored` or `verified`. This
operation does not repair a certificate, contact ACME/Cloudflare, write CGP
settings, reset retry backoff or establish TLS health.

## When acknowledgement is allowed

- The journal is valid schema 2, belongs to the current machine/CGP endpoint,
  and has phase `prepared` or `restoring`.
- A fresh CGP readback matches **all four** recorded previous certificate
  settings. `previous` and `both` are allowed; `intended` alone and `unknown`
  are refused. The existing CGP comparison treats quoted/unquoted setting
  values equivalently.
- The operator confirms the exact preview token and supplies a reason.
- Private storage and the audit evidence pass the same ownership, permission,
  type and path checks as other manager files.

Other phases require ordinary recovery first. A foreign identity, corrupt
journal, changed snapshot or unknown remote state cannot be overridden with
this command. There is no batch acknowledgement or force/adopt mode.

## Command sequence

Inspect and attempt normal recovery first:

```sh
sudo cgp-letsencrypt --transactions --domain example.com --json
sudo cgp-letsencrypt --recover --domain example.com
```

If the previous settings are recognized but TLS cannot be proved, inspect the
specific acknowledgement without changing the journal:

```sh
sudo cgp-letsencrypt --acknowledge-restored --domain example.com --json
```

The preview returns the domain, phase, recognized state, server match,
`confirmation_token`, `pending_journal`, `authorization_recorded` and
`tls: "unverified"`. It does not return private keys, complete settings or the
reason from an earlier authorization. Command-level locking still applies;
the preview itself writes no journal or audit record and probes no TLS endpoint.

After reviewing the state, copy the **entire** token into the explicit command:

```sh
sudo cgp-letsencrypt --acknowledge-restored --domain example.com \
  --confirm-transaction TOKEN_FROM_PREVIEW \
  --reason 'Previous certificate expired; administrator accepts unverified settings' \
  --json
```

The reason must contain 1–500 printable characters after trimming surrounding
whitespace. Do not include passwords, tokens or key material. The reason is
kept in the private audit rather than echoed in ordinary command output.
Confirmation and reason must be supplied together, for one named domain.

The backend rechecks the token and remote settings under the operation lock.
A stale preview is refused; neither the CLI nor console silently refreshes its
token and retries the operation.

## Console workflow

The domain menu offers **Acknowledge previous settings (TLS unverified)**.
The F9 transaction menu also allows choosing a pending domain independently of
normal domain discovery. The console obtains a fresh preview, asks for a reason
and presents a confirmation with cancellation selected by default. Confirmation
applies to the exact displayed operation.

A successful acknowledgement does not mark the certificate `VERIFIED`.
Run an ordinary TLS check after repairing the certificate or listener.

## Durable evidence and interrupted acknowledgement

Evidence lives under:

```text
/var/lib/cgp-letsencrypt/resolutions/<confirmation_token>/
```

`authorization.json` records the original full journal, the original file's
identity, the decision, reason, effective UID, UTC time and explicit unverified
TLS status. It is an authorization record, not proof that the journal was
retired. `completion.json` binds to that exact authorization and records
completion separately. The full journal contains private certificate keys;
directories are private and files are `0600` or stricter. Do not publish them.
Ordinary backup retention does not prune these records.

The operation follows this order:

1. Read the journal and CGP settings; validate the supplied confirmation and
   reason.
2. Persist the authorization, including full original evidence, before removing
   anything. An existing authorization must match and is resynchronized rather
   than overwritten with a new reason or new snapshot.
3. Re-read CGP and the journal after persistence. Refuse if either changed.
4. Remove the matching pending journal and synchronize its directory.
5. Persist completion bound to the authorization, then report
   `acknowledged_unverified`.

**An authorization without completion blocks normal recovery and certificate
mutations even if the original pending file is already absent.** Its transaction
status appears as `acknowledging` when only the authorization remains. Ordinary
scheduled runs never complete that authorization on the operator's behalf.

After an interruption, use the preview for the same domain and explicitly
repeat the same token and reason. The backend validates the existing evidence,
rechecks CGP and synchronizes any already performed removal before completing.
If the journal, remote state or evidence changed, it refuses. Never delete an
authorization or recreate the pending journal merely to bypass that refusal.

Before allowing a later ordinary mutation, the manager validates and synchronizes
already completed evidence. A visible completion file may have survived an
earlier exception before its final directory sync. This check does not create a
completion or waive a pending authorization; failed synchronization blocks work.

## Confirmation identity and limits

Schema 2 has no random transaction identifier. A confirmation token binds the
operation name, full canonical journal and the opened file's device, inode,
size, modification time and change time. Replacing or changing the file
invalidates its preview, including replacement with identical JSON. The token
is a freshness check within the trusted-UID model, not a password or signature.
Completed tokens cannot authorize retirement of another pending instance.

Filesystem inode/time metadata is not a permanent globally unique identifier.
The completed-token refusal prevents reuse if a token collides with historical
evidence. The manager does not sandbox concurrent modifications by root or the
same trusted UID; see [private storage policy](STORAGE.md).

CGP provides no assumed compare-and-swap. A WebAdmin change can race the final
readback. This procedure makes no CGP write and preserves the accepted snapshot,
but it cannot make that external state immutable. Avoid concurrent manual
certificate changes while resolving an operation.

Acknowledgement releases a transaction block; it does not solve missing previous
fields or other bootstrap restrictions. Later installation still applies its
ordinary validation and creates a new journal. The completed audit never counts
as a successful TLS check. Process-death tests do not simulate storage power
loss; actual deployment validation remains separate. Observed tests and CI are
recorded in [DEVELOPMENT.md](../DEVELOPMENT.md).
