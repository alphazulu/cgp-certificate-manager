# Contributing

Start with [ROADMAP.md](ROADMAP.md) and the current handoff in
[DEVELOPMENT.md](DEVELOPMENT.md). They record the active scope, observed
validation and work that remains unfinished. The development branch is not a
production release. Merge, release publication and production validation each
require explicit maintainer approval; a successful CI run does not grant it.

For a potential vulnerability, follow [SECURITY.md](SECURITY.md) before opening
an issue or pull request with technical details.

## Resume an existing task

From the repository root, inspect the checkout before editing:

```sh
git status --short
git branch --show-current
git rev-parse HEAD
```

Read the current pull request and checks for that exact revision. Preserve any
existing work and reconcile it with the handoff. A historical green run does
not validate a later commit.

Keep the roadmap checkboxes and development handoff current in the same commit
as substantive changes. Record what changed, the exact commands and observed
results, the tested commit/CI run when available, unresolved limits and the next
concrete step. Leave unexecuted checks explicitly pending. This makes a paused
task resumable without relying on chat history.

## Isolated test environments

Use Linux, Python **3.12** with its `venv` module, Bash and the OpenSSL command-line
tools. The suite includes POSIX file/lock checks, subprocess recovery and local
TLS tests. Run it as an ordinary development user, with synthetic fixtures and
temporary state, rather than against an installed server.

Create both environments from the repository root. The `.venv/` directory and
`.coverage.*` files are ignored by Git. Activation is unnecessary because each
command selects its interpreter explicitly.

### Compatibility profile

```sh
python3.12 -m venv .venv/compat
.venv/compat/bin/python -m pip install -r requirements-test-compat.txt
COVERAGE_FILE=.coverage.compat .venv/compat/bin/python -m coverage run --branch --source=cgp_cert_manager -m unittest discover -s tests -v
COVERAGE_FILE=.coverage.compat .venv/compat/bin/python -m coverage report -m --fail-under=100
```

### Current dependency profile

```sh
python3.12 -m venv .venv/current
.venv/current/bin/python -m pip install -r requirements-test-current.txt
COVERAGE_FILE=.coverage.current .venv/current/bin/python -m coverage run --branch --source=cgp_cert_manager -m unittest discover -s tests -v
COVERAGE_FILE=.coverage.current .venv/current/bin/python -m coverage report -m --fail-under=100
```

The compatibility requirements reproduce an older distribution generation for
API testing; they are not production dependency pins. Keep production packages
on maintained security updates. The current profile tests a separate dependency
set. Both profiles must independently reach **100% measured statement and branch
coverage**. Do not combine their data, lower the gate or add artificial coverage
exclusions to hide an untested path.

Also run the repository checks:

```sh
.venv/current/bin/python -m compileall -q cgp_cert_manager tests
bash -n install.sh scripts/install-locked.sh tests/integration/installer.sh
git diff --check
```

## Tests for a change

Add unit tests with every new behavior or bug fix. Begin with the affected
contract and its failure cases; assert observable outcomes, retained evidence
and whether an external action occurred. A focused iteration can use an
existing test file, for example:

```sh
.venv/current/bin/python -m unittest discover -s tests -p 'test_dnsauth.py' -v
```

Run the two complete coverage commands above before submitting the completed
change. A focused test run is useful evidence for that path, but does not
replace either complete gate.

Preserve the contracts described in these documents:

- [Private storage](docs/STORAGE.md): unsafe paths, metadata and credentials
  must be refused before the protected operation; test the actual filesystem
  checks rather than replacing them with a broad mock.
- [Certificate transactions](docs/TRANSACTIONS.md): persist evidence before
  remote writes, distinguish known snapshots from manual changes, retain
  unresolved work and block subsequent mutations. Include failure injection
  and fresh-process recovery when changing persistence or phase ordering.
- [Operator resolution](docs/RESOLUTION.md): preview, exact confirmation and
  durable audit have separate roles. Stale or interrupted decisions must not
  become an automatic acknowledgement or a TLS success claim.
- [Bootstrap readiness](docs/BOOTSTRAP.md): distinguish explicit and effective
  settings, parse failures and missing fields. Force/retry options must not
  bypass readiness, and diagnostic commands must retain their documented
  read-only behavior.
- [DNS and adaptive propagation](docs/DNS.md): test actual Certbot challenge
  contracts, bounded DNS observations, uncertain provider replies, record
  ownership, process lifetime and cleanup after interruption. Borrowed or
  changed records must not be deleted as owned records.

Automated tests must not contact production CGP, Cloudflare or ACME services,
use production credentials, or alter real DNS. Use synthetic domains, isolated
temporary files and mocked remote boundaries; real loopback servers and locally
generated certificates are appropriate for transport tests. Any external lab
validation needs its own agreed scope and must remain separate from the
automated suite. Coverage is execution evidence, not a security or correctness
proof for every real deployment.

## CI and installer integration

The [workflow](.github/workflows/ci.yml) is configured for seven jobs:

| Jobs | Scope |
|---|---|
| `tests (compat)` and `tests (current)` | Python 3.12, separate dependencies and strict 100% coverage gates |
| Four `installer` combinations | Ubuntu 24.04 and Debian 13, each upgrading source-pinned 2.0.1 and 2.1.0 baselines |
| `package` | Archive and SHA-256 verification after both test profiles and all installer combinations succeed |

The package job uploads a CI artifact; it does not publish a release. Action
versions are pinned to full commit SHAs with version comments. Verify a changed
pin against the upstream release, tag reference and action manifest.

The installer harness writes system paths and requires root. Run it only in
the disposable container setup defined by the workflow, never directly on a
development host or production server. It substitutes a mock `systemctl` to
check command sequencing, failures, rollback, locking and evidence preservation.
It does not boot systemd or prove real timer execution, service lifecycle or
live CGP compatibility. Container success is not production qualification of a
distribution. If Docker is unavailable locally, record that limit and inspect
the exact revision's CI results before marking integration checks complete.

## Pull request and handoff

Explain the concrete problem, the resulting behavior, relevant tests and any
remaining limitations. Link the plan item and update affected operational docs.
Include observed test/coverage results and the relevant CI run; do not describe
a configured but unexecuted job as passed.

Use synthetic examples only. Do not commit production domains, configuration,
credentials, logs, certificate private keys, backups, transaction journals or
DNS receipts, and do not paste them into issues or PRs. Keep merge, release and
production actions pending until the maintainer explicitly authorizes them.
