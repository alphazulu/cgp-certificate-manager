"""Workflow contracts and exact shell blocks with offline, fail-closed fixtures.

The fake commands cannot contact GitHub, install packages, create a real tag or
publish a release.  jq/checksums and the audit/SARIF policy adapters are real.
GitHub Actions, CodeQL and attestations themselves still require native CI.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
SHA = "a" * 40
TAG = "v2.3.4"


def workflow(name):
    # GitHub's `on` is a string key, not a YAML 1.1 boolean.
    return yaml.load((WORKFLOWS / (name + ".yml")).read_text(), Loader=yaml.BaseLoader)


def block(document, job, needle):
    values = [step["run"] for step in document["jobs"][job]["steps"]
              if needle in step.get("run", "")]
    if len(values) != 1:
        raise AssertionError("Expected one shell block for " + needle)
    return values[0]


FAKE_COMMAND = r'''
import json
import os
from pathlib import Path
import sys

tool = Path(sys.argv[0])
args = sys.argv[1:]
with open(os.environ['FAKE_LOG'], 'a') as stream:
    stream.write(json.dumps([str(tool), args]) + '\n')

def status(name):
    return int(os.environ.get(name, '0'))

if tool.name == 'gh':
    if args == ['--version']:
        print('gh fixture')
        sys.exit(0)
    if args[:2] == ['api', 'graphql']:
        print(os.environ['FAKE_RELEASE_STATE'])
        sys.exit(status('FAKE_GRAPHQL_EXIT'))
    base = 'repos/' + os.environ['GITHUB_REPOSITORY'] + '/commits/'
    endpoint = base + 'tags/' + os.environ['RELEASE_TAG']
    if args == ['api', endpoint, '--jq', '.sha']:
        print(os.environ.get('FAKE_REMOTE_SHA', os.environ['GITHUB_SHA']))
        sys.exit(status('FAKE_COMMIT_EXIT'))
    # The ambiguous endpoint deliberately resolves the same-name branch.  It
    # must not make the tag regression pass merely by rejecting an old command.
    if args == ['api', base + os.environ['RELEASE_TAG'], '--jq', '.sha']:
        print(os.environ.get('FAKE_SAME_NAME_BRANCH_SHA', os.environ['GITHUB_SHA']))
        sys.exit(0)
    if args[:2] == ['release', 'create']:
        Path(os.environ['FAKE_CREATED']).write_text(json.dumps(args))
        sys.exit(status('FAKE_CREATE_EXIT'))
elif tool.name == 'git':
    if args == ['rev-parse', '--verify', 'HEAD']:
        print(os.environ.get('FAKE_HEAD_SHA', os.environ['GITHUB_SHA']))
        sys.exit(0)
    if args == ['rev-parse', '--verify', '--end-of-options', os.environ['GITHUB_REF'] + '^{commit}']:
        print(os.environ.get('FAKE_TAG_SHA', os.environ['GITHUB_SHA']))
        sys.exit(0)
    if args == ['merge-base', '--is-ancestor', os.environ['GITHUB_SHA'],
                'refs/remotes/origin/' + os.environ['DEFAULT_BRANCH']]:
        sys.exit(status('FAKE_ANCESTRY_EXIT'))
elif 'cgp-audit-target' in tool.parts:
    if args[:1] == ['-c']:
        print(os.environ['FAKE_SITE'])
        sys.exit(0)
    if args[:3] == ['-m', 'pip', 'list']:
        print(os.environ['FAKE_INVENTORY'])
        sys.stderr.write(os.environ.get('FAKE_INVENTORY_LOG', ''))
        sys.exit(status('FAKE_INVENTORY_EXIT'))
elif 'cgp-auditor' in tool.parts and args[:2] == ['-m', 'pip_audit']:
    payload = os.environ.get('FAKE_REPORT')
    if payload is not None and os.environ.get('FAKE_OMIT_REPORT') != '1':
        Path(args[args.index('--output') + 1]).write_text(payload)
    sys.stderr.write(os.environ.get('FAKE_SCANNER_LOG', 'No known vulnerabilities found\n'))
    sys.exit(status('FAKE_SCANNER_EXIT'))
elif tool.name in ('python', 'python3'):
    if args[:2] == ['-m', 'repo_tools.release'] and '--check-only' in args:
        sys.exit(status('FAKE_RELEASE_CHECK_EXIT'))
    if args[:2] in (['-m', 'repo_tools.audit'], ['-m', 'repo_tools.codeql']):
        os.execv(sys.executable, [sys.executable] + args)
sys.stderr.write('Unexpected offline fixture command: ' + tool.name + '\n')
sys.exit(99)
'''


class WorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.documents = {name: workflow(name) for name in ("ci", "security", "release")}

    def test_immutable_action_pins_and_minimal_write_boundaries(self):
        allowed_writes = {
            ("ci", "security", "security-events"),
            ("security", "codeql", "security-events"),
            ("release", "quality", "security-events"),
            ("release", "draft", "contents"),
            ("release", "draft", "id-token"),
            ("release", "draft", "attestations"),
        }
        observed_writes = set()
        for path in sorted(WORKFLOWS.glob("*.yml")):
            name = path.stem
            document = workflow(name)
            self.assertEqual(document["permissions"], {"contents": "read"})
            self.assertNotIn("pull_request_target", document["on"])
            self.assertNotIn("workflow_run", document["on"])
            for job_id, job in document["jobs"].items():
                self.assertNotEqual(job.get("continue-on-error"), "true")
                permissions = job.get("permissions", {})
                self.assertIsInstance(permissions, dict)
                for capability, mode in permissions.items():
                    self.assertIn(mode, {"read", "write", "none"})
                    if mode == "write":
                        observed_writes.add((name, job_id, capability))
                for entry in [job] + job.get("steps", []):
                    self.assertNotEqual(entry.get("continue-on-error"), "true")
                    reference = entry.get("uses")
                    if reference is None:
                        continue
                    if reference.startswith("./"):
                        self.assertTrue((ROOT / reference).is_file())
                    else:
                        self.assertRegex(reference, r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$")
                    if reference.startswith("actions/checkout@"):
                        self.assertEqual(entry["with"]["persist-credentials"], "false")
        self.assertEqual(observed_writes, allowed_writes)

    def test_ci_complete_coverage_and_all_disposable_gates_precede_packaging(self):
        ci = self.documents["ci"]
        jobs = ci["jobs"]
        self.assertEqual(set(jobs["tests"]["strategy"]["matrix"]["dependencies"]), {"compat", "current"})
        command = shlex.split(block(ci, "tests", "coverage run"))
        self.assertIn("--branch", command)
        sources = next(value.split("=", 1)[1] for value in command if value.startswith("--source="))
        self.assertLessEqual({"cgp_cert_manager", "repo_tools"}, set(sources.split(",")))
        self.assertEqual(command[-5:], ["unittest", "discover", "-s", "tests", "-v"])
        self.assertIn("--fail-under=100", shlex.split(block(ci, "tests", "coverage report")))
        matrix = jobs["installer"]["strategy"]["matrix"]
        self.assertEqual(set(matrix["image"]), {"ubuntu:24.04", "debian:13"})
        self.assertEqual({row["version"] for row in matrix["baseline"]}, {"2.0.1", "2.1.0"})
        self.assertNotIn("exclude", matrix)
        for row in matrix["baseline"]:
            self.assertRegex(row["sha"], r"^[0-9a-f]{40}$")
        self.assertEqual(jobs["security"]["uses"], "./.github/workflows/security.yml")
        self.assertEqual(set(jobs["package"]["needs"]), {"tests", "installer", "monitoring-assets", "security"})
        self.assertNotIn("if", jobs["package"])
        self.assertIn("promtool check rules", block(ci, "monitoring-assets", "promtool check rules"))
        self.assertIn("promtool test rules", block(ci, "monitoring-assets", "check_monitoring_assets.py"))

    def test_security_scopes_native_analysis_and_preserves_failure_evidence(self):
        security = self.documents["security"]
        self.assertEqual(set(security["jobs"]["dependencies"]["strategy"]["matrix"]["profile"]),
                         {"compat", "current"})
        config = yaml.load((ROOT / ".github/codeql/config.yml").read_text(), Loader=yaml.BaseLoader)
        self.assertEqual(set(config["paths"]), {"cgp_cert_manager", "repo_tools"})
        self.assertNotIn("paths-ignore", config)
        codeql = security["jobs"]["codeql"]
        initialize = next(step for step in codeql["steps"] if step.get("uses", "").startswith("github/codeql-action/init@"))
        self.assertEqual(initialize["with"]["languages"], "python")
        self.assertEqual(initialize["with"]["build-mode"], "none")
        self.assertEqual(initialize["with"]["config-file"], ".github/codeql/config.yml")
        analyze = next(step for step in codeql["steps"] if step.get("uses", "").startswith("github/codeql-action/analyze@"))
        gate = next(step for step in codeql["steps"] if "repo_tools.codeql" in step.get("run", ""))
        self.assertEqual(gate["if"], "always()")
        self.assertEqual(gate["env"]["ANALYSIS_STATUS"], "${{ steps." + analyze["id"] + ".outcome }}")
        self.assertIn('--analysis-status "$ANALYSIS_STATUS"', gate["run"])
        self.assertEqual(analyze["with"]["wait-for-processing"], "true")
        for job_id in ("dependencies", "codeql"):
            artifacts = [step for step in security["jobs"][job_id]["steps"]
                         if step.get("uses", "").startswith("actions/upload-artifact@")]
            self.assertEqual(len(artifacts), 1)
            self.assertEqual(artifacts[0]["if"], "always()")
            self.assertEqual(artifacts[0]["with"]["if-no-files-found"], "error")
        audit_run = block(security, "dependencies", "repo_tools.audit")
        for forbidden in ("--fix", "--ignore-vuln", "--skip-editable", "--no-deps", "--dry-run"):
            self.assertNotIn(forbidden, audit_run)

    def test_manual_release_uses_gated_same_run_artifacts_and_attests_before_draft(self):
        release, ci = self.documents["release"], self.documents["ci"]
        self.assertEqual(set(release["on"]), {"workflow_dispatch"})
        self.assertEqual(release["concurrency"]["cancel-in-progress"], "false")
        self.assertEqual(release["jobs"]["quality"]["needs"], "validate")
        self.assertEqual(release["jobs"]["quality"]["uses"], "./.github/workflows/ci.yml")
        self.assertEqual(release["jobs"]["draft"]["needs"], "quality")
        self.assertNotIn("if", release["jobs"]["draft"])
        steps = release["jobs"]["draft"]["steps"]
        download = next(step for step in steps if step.get("uses", "").startswith("actions/download-artifact@"))
        self.assertEqual(download["with"], {"name": "release-package", "path": "dist"})
        attest_index = next(i for i, step in enumerate(steps) if step.get("uses", "").startswith("actions/attest@"))
        publish_index = next(i for i, step in enumerate(steps) if "gh release create" in step.get("run", ""))
        self.assertLess(steps.index(download), attest_index)
        self.assertLess(attest_index, publish_index)
        self.assertEqual(steps[attest_index]["with"], {
            "subject-path": "dist/*", "push-to-registry": "false", "create-storage-record": "false"})
        package = block(ci, "package", "repo_tools.release")
        self.assertIn('--expected-commit "$GITHUB_SHA"', package)
        self.assertIn('--main-ref "refs/remotes/origin/$DEFAULT_BRANCH"', package)
        self.assertIn("diff -qr", package)
        self.assertIn("sha256sum --check --strict", package)
        self.assertIn('"$RUNNER_TEMP/release-package"', package)
        upload = next(step for step in ci["jobs"]["package"]["steps"] if "uses" in step and "upload-artifact@" in step["uses"])
        self.assertEqual(upload["with"]["name"], "release-package")
        self.assertEqual(upload["with"]["path"], "${{ runner.temp }}/release-package/")
        combined = "\n".join(step.get("run", "") for step in steps)
        self.assertNotIn("--clobber", combined)
        self.assertNotRegex(combined, r"(?m)^\s*(?:git tag|gh release (?:edit|upload|delete))\b")


class WorkflowShellTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="cgp workflow ")))
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.runner = self.root / "runner temp"
        self.runner.mkdir()
        self.log = self.root / "commands.jsonl"
        self.created = self.root / "created.json"
        self.bash = shutil.which("bash")
        self.assertIsNotNone(self.bash)
        for name in ("cat", "mkdir", "sha256sum", "jq"):
            executable = shutil.which(name)
            self.assertIsNotNone(executable, msg="Workflow fixture requires " + name)
            (self.bin / name).symlink_to(executable)
        for path in ([self.bin / name for name in ("gh", "git", "python", "python3")] +
                     [self.runner / name / "bin/python" for name in ("cgp-auditor", "cgp-audit-target")]):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("#!" + sys.executable + "\n" + FAKE_COMMAND)
            path.chmod(0o755)
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(("GITHUB_", "GH_", "GIT_", "FAKE_"))}
        environment.update(PATH=str(self.bin), PYTHONPATH=str(ROOT), RUNNER_TEMP=str(self.runner),
                           GITHUB_STEP_SUMMARY=str(self.root / "summary.md"), GITHUB_SHA=SHA,
                           GITHUB_REF_TYPE="tag", GITHUB_REF="refs/tags/" + TAG, GITHUB_REF_NAME=TAG,
                           GITHUB_REPOSITORY="fixture/cgp", RELEASE_TAG=TAG, DEFAULT_BRANCH="main",
                           GH_TOKEN="offline-fixture", PROFILE="current", ANALYSIS_STATUS="success",
                           FAKE_LOG=str(self.log), FAKE_CREATED=str(self.created),
                           FAKE_SITE=str(self.runner / "target packages"),
                           FAKE_RELEASE_STATE=json.dumps({"data": {"repository": {"release": None}}}),
                           FAKE_INVENTORY=json.dumps([{"name": "fixture-pkg", "version": "1.0"}]),
                           FAKE_REPORT=json.dumps({"dependencies": [{"name": "fixture-pkg", "version": "1.0", "vulns": []}], "fixes": []}))
        self.environment = environment
        dist = self.root / "dist"
        dist.mkdir()
        self.archive = dist / ("cgp-certificate-manager-" + TAG + ".tar.gz")
        self.archive.write_bytes(b"offline artifact bytes")
        (dist / (self.archive.name + ".sha256")).write_text(
            hashlib.sha256(self.archive.read_bytes()).hexdigest() + "  " + self.archive.name + "\n")

    def execute(self, script, **changes):
        self.assertNotIn("${{", script, "Only Actions environment bindings are substituted in fixtures")
        self.log.unlink(missing_ok=True)
        self.created.unlink(missing_ok=True)
        environment = dict(self.environment, **changes)
        return subprocess.run([self.bash, "--noprofile", "--norc", "-e", "-c", script],
                              cwd=self.root, env=environment, text=True,
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=20)

    def calls(self, name):
        rows = [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
        return [args for path, args in rows if Path(path).name == name]

    def test_exact_tag_validation_refuses_branch_moved_checkout_tag_and_foreign_ancestry(self):
        script = block(workflow("release"), "validate", "--check-only")
        cases = [{"GITHUB_REF_TYPE": "branch"}, {"FAKE_HEAD_SHA": "b" * 40},
                 {"FAKE_TAG_SHA": "b" * 40}, {"FAKE_ANCESTRY_EXIT": "1"},
                 {"FAKE_RELEASE_CHECK_EXIT": "1"}]
        for changes in cases:
            with self.subTest(changes=changes):
                result = self.execute(script, **changes)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.created.exists())
        result = self.execute(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(["merge-base", "--is-ancestor", SHA, "refs/remotes/origin/main"], self.calls("git"))
        self.assertEqual(self.calls("python3"), [["-m", "repo_tools.release", "--check-only", "--ref", "HEAD",
                         "--release-tag", TAG, "--expected-commit", SHA, "--main-ref", "refs/remotes/origin/main"]])

    def test_both_live_release_preflights_refuse_existing_release_bad_api_and_moved_tag(self):
        steps = workflow("release")["jobs"]["draft"]["steps"]
        scripts = [step["run"] for step in steps if "gh api graphql" in step.get("run", "")]
        self.assertEqual(len(scripts), 2, "Recheck both before and after attestation")
        responses = ["not JSON", "{}", '{"data":{"repository":null}}',
                     '{"data":{"repository":{}}}',
                     '{"errors":[{"message":"failure"}],"data":{"repository":{"release":null}}}']
        responses += [json.dumps({"data": {"repository": {
            "release": {"id": "existing", "isDraft": state}}}}) for state in (True, False)]
        cases = [{"FAKE_RELEASE_STATE": value} for value in responses]
        cases += [{"FAKE_GRAPHQL_EXIT": "7"}, {"FAKE_COMMIT_EXIT": "8"}, {"FAKE_REMOTE_SHA": "b" * 40}]
        for index, script in enumerate(scripts):
            for changes in cases:
                with self.subTest(preflight=index, changes=changes):
                    result = self.execute(script, **changes)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertFalse(self.created.exists())

    def test_same_name_branch_cannot_satisfy_either_remote_release_tag_check(self):
        steps = workflow("release")["jobs"]["draft"]["steps"]
        scripts = [step["run"] for step in steps if "gh api graphql" in step.get("run", "")]
        self.assertEqual(len(scripts), 2)
        for index, script in enumerate(scripts):
            for condition in ({"FAKE_REMOTE_SHA": "b" * 40}, {"FAKE_COMMIT_EXIT": "1"}):
                with self.subTest(preflight=index, tag_condition=condition):
                    result = self.execute(script, FAKE_SAME_NAME_BRANCH_SHA=SHA, **condition)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertFalse(self.created.exists())
                    commit_calls = [args for args in self.calls("gh")
                                    if args[:1] == ["api"] and args[1].startswith("repos/")]
                    self.assertEqual(commit_calls, [["api", "repos/fixture/cgp/commits/tags/" + TAG,
                                                     "--jq", ".sha"]])

    def test_final_block_rechecks_after_first_preflight_and_creates_only_a_new_draft(self):
        steps = workflow("release")["jobs"]["draft"]["steps"]
        before = next(step["run"] for step in steps if "sha256sum" in step.get("run", ""))
        publish = next(step["run"] for step in steps if "gh release create" in step.get("run", ""))
        self.assertEqual(self.execute(before).returncode, 0)
        moved = self.execute(publish, FAKE_REMOTE_SHA="b" * 40)
        self.assertNotEqual(moved.returncode, 0)
        self.assertFalse(self.created.exists())
        result = self.execute(publish)
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls("gh")
        self.assertEqual([args[:2] for args in calls[:2]], [
            ["api", "graphql"], ["api", "repos/fixture/cgp/commits/tags/" + TAG]])
        self.assertEqual(calls[-1][:3], ["release", "create", TAG])
        self.assertIn("--verify-tag", calls[-1])
        self.assertIn("--draft", calls[-1])
        self.assertNotIn("--clobber", calls[-1])
        self.assertTrue(self.created.exists())
        failed = self.execute(publish, FAKE_CREATE_EXIT="7")
        self.assertEqual(failed.returncode, 7)

    def test_stable_release_is_a_draft_without_latest_or_prerelease_promotion(self):
        script = block(workflow("release"), "draft", "gh release create")
        result = self.execute(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = self.calls("gh")[-1]
        self.assertEqual(arguments[:3], ["release", "create", TAG])
        self.assertEqual([value for value in arguments if value.startswith("--")], [
            "--repo", "--verify-tag", "--draft", "--latest=false", "--title", "--generate-notes"])

    def test_release_candidate_is_a_prerelease_draft_without_latest_promotion(self):
        candidate = "v2.3.4rc12"
        original = self.archive
        self.archive = original.with_name("cgp-certificate-manager-" + candidate + ".tar.gz")
        original.rename(self.archive)
        original.with_name(original.name + ".sha256").unlink()
        self.archive.with_name(self.archive.name + ".sha256").write_text(
            hashlib.sha256(self.archive.read_bytes()).hexdigest() + "  " + self.archive.name + "\n")
        context = {"RELEASE_TAG": candidate, "GITHUB_REF_NAME": candidate,
                   "GITHUB_REF": "refs/tags/" + candidate}
        release = workflow("release")
        before = self.execute(block(release, "draft", "sha256sum"), **context)
        self.assertEqual(before.returncode, 0, before.stderr)
        result = self.execute(block(release, "draft", "gh release create"), **context)
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = self.calls("gh")[-1]
        self.assertEqual(arguments[:3], ["release", "create", candidate])
        self.assertEqual([value for value in arguments if value.startswith("--")], [
            "--repo", "--verify-tag", "--draft", "--latest=false", "--prerelease", "--title", "--generate-notes"])

    def test_corrupt_archive_stops_before_release_lookup_or_attestation(self):
        script = block(workflow("release"), "draft", "sha256sum")
        self.archive.write_bytes(b"tampered artifact")
        result = self.execute(script)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(args[:1] == ["api"] for args in self.calls("gh")))
        self.assertFalse(self.created.exists())

    def test_exact_audit_block_propagates_scanner_inventory_and_policy_failures(self):
        script = block(workflow("security"), "dependencies", "repo_tools.audit")
        findings = {"dependencies": [{"name": "fixture-pkg", "version": "1.0", "vulns": [
            {"id": "TEST-ONLY-001", "aliases": [], "fix_versions": [], "description": "Synthetic fixture"}]}], "fixes": []}
        cases = [
            ({}, 0, "clean"),
            ({"FAKE_REPORT": json.dumps(findings), "FAKE_SCANNER_EXIT": "1",
              "FAKE_SCANNER_LOG": "Found 1 known vulnerability in 1 package\n"}, 1, "findings"),
            ({"PROFILE": "compat", "FAKE_REPORT": json.dumps(findings), "FAKE_SCANNER_EXIT": "1",
              "FAKE_SCANNER_LOG": "Found 1 known vulnerability in 1 package\n"}, 0, "findings"),
            ({"PROFILE": "compat", "FAKE_REPORT": "invalid JSON", "FAKE_SCANNER_EXIT": "1"}, 2, None),
            ({"PROFILE": "compat", "FAKE_OMIT_REPORT": "1", "FAKE_SCANNER_EXIT": "1"}, 2, None),
            ({"PROFILE": "compat", "FAKE_SCANNER_EXIT": "7"}, 2, None),
            ({"PROFILE": "compat", "FAKE_INVENTORY_EXIT": "3"}, 2, None),
            ({"FAKE_INVENTORY_LOG": "WARNING: Ignoring invalid distribution broken\n"}, 2, None),
            ({"PROFILE": "compat", "FAKE_INVENTORY_LOG": "WARNING: Ignoring invalid distribution broken\n"}, 2, None),
            ({"PROFILE": "compat", "FAKE_SCANNER_LOG": "WARNING: package could not be audited\n"}, 2, None),
        ]
        for changes, code, status in cases:
            with self.subTest(changes=changes):
                directory = self.runner / "dependency-report"
                if directory.exists():
                    shutil.rmtree(directory)
                result = self.execute(script, **changes)
                self.assertEqual(result.returncode, code, result.stderr + result.stdout)
                summary = json.loads((directory / "summary.json").read_text())
                self.assertEqual(summary["exit_code"], code)
                if status is not None:
                    self.assertEqual(summary["status"], status)
                if code == 2:
                    self.assertFalse(summary["complete"])
                self.assertEqual((directory / "scanner.exit").read_text().strip(), changes.get("FAKE_SCANNER_EXIT", "0"))
                self.assertEqual((directory / "inventory.exit").read_text().strip(), changes.get("FAKE_INVENTORY_EXIT", "0"))
                self.assertTrue((directory / "scanner.log").exists())
                self.assertTrue((directory / "inventory.log").exists())
                self.assertIn('"status":', (self.root / "summary.md").read_text())
                calls = self.calls("python")
                inventory_call = next(args for args in calls if args[:3] == ["-m", "pip", "list"])
                scanner_call = next(args for args in calls if args[:2] == ["-m", "pip_audit"])
                self.assertEqual(inventory_call[inventory_call.index("--path") + 1], self.environment["FAKE_SITE"])
                self.assertEqual(scanner_call[scanner_call.index("--path") + 1], self.environment["FAKE_SITE"])
                self.assertIn("--strict", scanner_call)

    def test_exact_codeql_gate_rejects_failed_native_analysis_even_with_empty_sarif(self):
        script = block(workflow("security"), "codeql", "repo_tools.codeql")
        directory = self.runner / "codeql-reports"
        directory.mkdir()
        report = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL"}}, "results": []}]}
        path = directory / "python.sarif"
        for native_status, payload, success in (("success", report, True), ("failure", report, False),
                                                ("skipped", report, False), ("success", {}, False)):
            with self.subTest(native_status=native_status, payload=payload):
                path.write_text(json.dumps(payload))
                result = self.execute(script, ANALYSIS_STATUS=native_status)
                self.assertEqual(result.returncode == 0, success, result.stderr + result.stdout)
                summary = json.loads((self.runner / "codeql-summary.json").read_text())
                self.assertEqual(summary["passed"], success)
                self.assertEqual(json.loads(result.stdout), summary)


if __name__ == "__main__":
    unittest.main()
