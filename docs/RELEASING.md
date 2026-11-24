# Release preparation and security checks

This development workflow prepares reviewed source artifacts and an unpublished
GitHub release draft. It does not install an update, create a tag, publish a
release or establish production readiness. The current stage and observed runs
are recorded in [DEVELOPMENT.md](../DEVELOPMENT.md); remaining release decisions
and real-environment acceptance are in [ROADMAP.md](../ROADMAP.md) and
[STAGING.md](STAGING.md).

## Required checks

The [CI workflow](../.github/workflows/ci.yml) is reusable and also runs on pushes
and pull requests. Its eleven jobs include two complete Python profiles, four
installer combinations, native monitoring-expression checks, two dependency
audits, CodeQL and final packaging. Package creation depends on every preceding
check. New repository tooling is included alongside the manager in the strict
100% statement/branch coverage gate.

The [security workflow](../.github/workflows/security.yml) can also be run
manually. Once present on the default branch, it runs every Monday at 03:31 UTC
(13:31 Asia/Vladivostok) so a new advisory can be detected without a source
change. It uses read permissions except for the CodeQL job's security-event
upload. It receives no production configuration or provider credentials.

| Check | Passing condition | Saved evidence |
|---|---|---|
| Current dependency profile | Complete resolved inventory, no warnings/skips, no known-vulnerability findings | Inventory, raw pip-audit JSON, logs, exit statuses and policy summary |
| Compatibility dependency profile | Complete inventory and successful audit execution; historical findings remain informational | The same evidence, including all findings |
| CodeQL Python | Native analysis succeeded; valid reports contain no findings or execution/configuration warning/error | Original SARIF and policy summary |
| Package | Source/metadata validation, two identical builds, checksum verification | Archive, checksum and provenance manifest |

### Dependency audit scope

The scanner is pinned by [requirements-security.txt](../requirements-security.txt)
and runs in its own environment. Each target environment is separately installed
from the corresponding test requirements. The bootstrap pip version is explicitly
26.3. Both `pip list --path` and `pip-audit --path` use that target's site-packages
directory; repository-local metadata and the scanner's dependencies are not
silently mixed into the audited inventory.

The adapter requires every inventory package/version to appear exactly once in
the audit. It rejects skipped, missing, unexpected or mismatched dependencies,
malformed reports, attempted fixes and inconsistent exit codes. Inventory and
scanner diagnostics are also required: pip and pip-audit can both omit damaged
distribution metadata with a warning, leaving apparently matching inventories.
Such warnings must fail the audit instead of producing a false clean result.
An unavailable advisory service is a failed check in either profile.

The compatibility file deliberately exercises historical APIs. Its finding-only
policy is explicit and limited to that profile; it does not suppress advisories
or alter the raw report. Repeated advisory IDs are retained in the raw report
and combined in the summary with occurrence counts and the union of aliases and
fix versions. Counts of records, package/advisory-ID pairs and affected packages
are different quantities. No automatic `--fix`, ignored vulnerability or skipped
dependency is used.

These scans cover the resolved PyPI test environments. They are not an inventory
or vulnerability assessment of the installed mail server, its operating-system
packages or distribution backports. Production package maintenance remains a
separate administrator task. A clean result is an observation against the
advisory service at the time of the run, not a promise about future advisories.

### CodeQL scope and result policy

[The CodeQL configuration](../.github/codeql/config.yml) selects
`cgp_cert_manager` and `repo_tools` for the default Python security suite.
The native action performs analysis without installing or running the candidate
application. Its action revision is pinned; its bundled CLI/query pack version
is recorded by the native job.

The analyze action can succeed while reporting findings. The subsequent
`repo_tools.codeql` gate therefore checks the actual SARIF files. It requires
SARIF 2.1.0, a nonempty list of CodeQL runs and an explicit results list for each
run, and refuses every reported finding, including suppressed findings.
Supplied invocation failures and
warning/error notifications also fail. Missing, unsafe, oversized or malformed
reports cannot pass. Optional SARIF invocation metadata does not replace the
native action outcome: only an explicitly successful analyze step permits a
passing summary. Failed/skipped analysis still produces a failure summary when
the checkout and helper are available.

This is static analysis of the selected source. It does not execute provider
protocols, test real TLS deployment or prove the absence of every vulnerability.

## Deterministic source artifacts

From a checkout with the new tooling, prepare an ordinary CI/development archive:

```sh
python3 -m repo_tools.release --ref HEAD --output dist
```

The builder reads immutable Git objects for the selected commit. Modified,
staged, ignored and untracked working files are not included. It parses the
version declaration as syntax without importing candidate application code,
then verifies the matching app-local Certbot metadata and plugin registration.

Supported source versions are `X.Y.Z`, `X.Y.ZrcN` and `X.Y.Z.devN`, with ordinary
nonnegative decimal components. The version file must contain one literal
`__version__` assignment. Release mode accepts the stable and `rc` forms only;
development versions cannot become release tags through this workflow.

The output contains exactly these three newly created files for the version:

- `cgp-certificate-manager-v<version>.tar.gz`
- `cgp-certificate-manager-v<version>.tar.gz.sha256`
- `cgp-certificate-manager-v<version>.provenance.json`

The archive retains that same single top-level directory. Paths are ordered
stably; timestamps and uid/gid are normalized, executable modes are retained,
and gzip contains no build-time filename or clock value. CI builds twice in
dedicated temporary directories and compares all artifact bytes. Reproduction
assumes the same compression toolchain; a different Python/zlib generation is
not promised to emit identical compressed bytes.

The manifest records schema, full commit and tree IDs, version, optional release
tag, archive prefix, filename, size and SHA-256. It contains no build-time wall
clock. A manifest or checksum alone is not a trusted signature; the separate
attestation below supplies provenance for an authorized release preparation.

Only regular Git blobs with supported modes are accepted. Symlinks, submodules,
unsafe or conflicting paths, oversized source trees, inconsistent metadata and
failed blob-integrity checks are refused. Git reads do not fetch missing objects,
use replace objects, prompt for credentials or honor ambient Git redirection.

Choose a new output directory beneath an existing parent. Symlink components
are refused, and the output directory must be owned by the executing user and
not writable by other users. Existing artifacts are never overwritten. A
handled failure attempts to remove only the files created by that build; a
retry must not blindly delete an existing output set. The builder does not
extract anything or implement the future server update mechanism.

## Manual release-tag preparation

The [release workflow](../.github/workflows/release.yml) must first exist on the
default branch, and the selected release tag must contain that workflow and its
tooling. GitHub's manual dispatch uses the selected ref's workflow definition.
Maintainers remain responsible for reviewing the tag and its source. Tag and
branch protection settings are not changed by this implementation.

After the separate acceptance and maintainer decisions for a candidate, select
an **existing** `vX.Y.Z` or `vX.Y.ZrcN` tag in Actions → Prepare draft release →
Run workflow. An equivalent later command is:

```sh
gh workflow run release.yml --ref v2.2.0rc1 --repo alphazulu/cgp-certificate-manager
```

The example does not create that tag or assert that it exists. Running this
workflow is an explicit release-preparation action, not an ordinary development
test. The current `dev` branch is deliberately ineligible for this command.

The workflow performs these steps:

1. Require a tag dispatch. Verify checked HEAD, the tag's peeled commit and
   GitHub's workflow SHA are identical, and the commit is contained in the
   current default branch.
2. Run the tested metadata/context validator. The exact tag must match the
   source version. No tag is created or moved.
3. Call the same complete CI on that tag, including both coverage profiles,
   every installer combination, native monitoring checks, dependency audits and
   CodeQL. The package builder repeats the tag/context checks.
4. Download only the `release-package` artifact from this same workflow run.
   Recheck its checksum, verify the remote tag still identifies the expected
   commit and refuse any existing draft or published release for the tag.
5. Generate GitHub artifact attestations for the archive, checksum and manifest.
   The dispatched tag context and source SHA match the source being built.
6. Repeat the live tag and existing-release checks, then create an unpublished
   GitHub draft with the reviewed artifacts and generated release notes. `rc`
   tags are marked as prereleases; no draft is selected as the latest release.

The attestation step submits provenance to GitHub before draft creation.
Keeping the release unpublished does not keep its attestation evidence local
or defer that separate provenance publication.

The privileged final job runs no checkout or candidate Python code. Its
permissions are scoped to reading the same-run artifact, attestation/OIDC and
creating the draft. Ordinary PR/test/audit jobs have no release or OIDC write
permission. All external actions use full commit pins. No long-lived signing
key, server password or provider token is needed for artifact attestation.

Existing-release lookup uses GraphQL because a published-release-only REST
lookup is insufficient for drafts. Remote commit checks explicitly select the
`tags/` namespace so a same-named branch cannot stand in for the release tag.
The workflow does not use asset clobbering
or silently resume an existing draft. Concurrent runs of this workflow for the
same ref are serialized. Remote rechecks do not create a server-side atomic
compare-and-swap against an out-of-band tag or release change.

An interrupted upload can leave an incomplete unpublished draft. Inspect it
and the preserved CI artifact before deciding how to proceed; the workflow does
not delete or overwrite it automatically. Public publication, latest-release
selection and production installation remain separate maintainer actions.

## Verification and deferred acceptance

For a downloaded artifact, the checksum checks file integrity. For an attested
candidate, use the GitHub CLI's attestation verification against the expected
repository and review the reported source commit, ref and workflow identity:

```sh
sha256sum --check cgp-certificate-manager-v2.2.0rc1.tar.gz.sha256
gh attestation verify cgp-certificate-manager-v2.2.0rc1.tar.gz --repo alphazulu/cgp-certificate-manager
```

Do not equate a valid attestation with maintainer approval, successful external
acceptance or a production-ready release. Review the exact CI and candidate
against the release plan. The license decision, live CGP/DNS/ACME cases and real
monitoring import/behavior remain recorded separately until completed.

Local tests exercise source construction, refusal paths, actual shell blocks
with fake GitHub responses, audit policy and SARIF policy. Native dependency
audits and CodeQL runs are recorded only after they actually execute. The
manual privileged attestation/draft path remains unexecuted until a separately
authorized eligible release tag is prepared; no synthetic test is claimed as
evidence of a published or installed release.

## Primary format and platform references

- [pip-audit](https://github.com/pypa/pip-audit): native JSON/exit-code and dependency auditing contract.
- [CodeQL SARIF output](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli/sarif-output).
- [Manual and reusable workflow events](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows).
- [GitHub workflow permissions](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax).
- [GitHub artifact attestations](https://github.com/actions/attest) and [release creation](https://cli.github.com/manual/gh_release_create).
