"""Abrupt process death during explicit acknowledgement of unverified settings.

The fake CGP readback lives outside manager STATE and survives each process.
Actual journal/audit publication, unlink, fsync, preview and acknowledgement run
in fresh interpreters. Every attempted CGP write or TLS check is a test failure.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
DOMAIN = "example.com"
CRASH_EXIT = 91
REFUSAL_EXIT = 17
PREVIOUS = {
    "PrivateSecureKey": "[b2xkLWtleQ==]",
    "SecureCertificate": "[b2xkLWNlcnQ=]",
    "CAChain": "[Y2E=]",
    "CertificateType": "NO",
}
INTENDED = dict(PREVIOUS, PrivateSecureKey="[bmV3LWtleQ==]",
                SecureCertificate="[bmV3LWNlcnQ=]", CertificateType="YES")
REASON = "Operator accepts the inactive previous certificate without TLS proof"

CHILD = r'''
from contextlib import ExitStack
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

from cgp_cert_manager import core, recovery, resolution, storage
from cgp_cert_manager.transactions import Journal

root, mode, checkpoint = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
fixture = json.loads((root / "fixture.json").read_text())
previous, intended = fixture["previous"], fixture["intended"]
name, reason = fixture["domain"], fixture["reason"]
state = root / "state"
cfg = {"communigate": {"url": "http://127.0.0.1:8100/CLI/"}}
identity = recovery.server_identity(cfg, "a" * 32)
journal = Journal(state / "transactions")
pending = journal.path(name)
token_path = root / "preview.json"
preview = json.loads(token_path.read_text()) if token_path.exists() else None
token = preview["confirmation_token"] if preview else None
bundle = state / "resolutions" / token if token else None
authorization = bundle / "authorization.json" if bundle else None
completion = bundle / "completion.json" if bundle else None


def current(config, domain):
    assert config == cfg and domain == name
    return json.loads((root / "remote.json").read_text())


def forbidden(*args, **kwargs):
    (root / "forbidden-call").write_text("CGP mutation or TLS verification attempted")
    raise AssertionError("Acknowledgement must not write to CGP or require TLS")


original_replace = os.replace
original_unlink = os.unlink
original_fsync = os.fsync


def replace(source, destination, *args, **kwargs):
    result = original_replace(source, destination, *args, **kwargs)
    if mode == "ack":
        name = Path(destination).name
        if (checkpoint == "auth-publish" and name == "authorization.json") or (
                checkpoint == "completion-publish" and name == "completion.json"):
            os._exit(91)
    return result


def unlink(path, *args, **kwargs):
    is_pending = mode == "ack" and Path(path).name == pending.name
    if is_pending and checkpoint == "before-pending-unlink":
        os._exit(91)
    result = original_unlink(path, *args, **kwargs)
    if is_pending and checkpoint == "after-pending-unlink":
        os._exit(91)
    return result


def fsync(fd):
    target = Path(os.readlink("/proc/self/fd/" + str(fd)))
    result = original_fsync(fd)
    if mode == "ack":
        if (checkpoint == "auth-file-fsync" and target.parent == bundle
                and target.name.startswith(".cgp-") and not authorization.exists()):
            os._exit(91)
        if (checkpoint == "auth-directory-fsync" and target == bundle
                and authorization.exists() and not completion.exists()):
            os._exit(91)
        if (checkpoint == "pending-directory-fsync" and target == pending.parent
                and authorization.exists() and not pending.exists()):
            os._exit(91)
        if (checkpoint == "completion-directory-fsync" and target == bundle
                and completion.exists()):
            os._exit(91)
    return result


with ExitStack() as stack:
    for obj, attr, value in (
        (core, "STATE", state),
        (core, "current", current),
        (core, "update", forbidden),
        (recovery, "server_identity", lambda config: identity),
        (recovery, "verify_snapshot", forbidden),
        (os, "replace", replace),
        (os, "unlink", unlink),
        (os, "fsync", fsync),
    ):
        stack.enter_context(patch.object(obj, attr, value))
    try:
        if mode == "setup":
            journal.prepare(name, previous, intended,
                            [{"port": 443, "sni": "new.example.com"}], identity,
                            previous_endpoints=[{"port": 443, "sni": "old.example.com"}])
            result = resolution.preview(cfg, name)
            storage.atomic_json(token_path, result)
        elif mode == "preview":
            result = resolution.preview(cfg, name)
        elif mode == "gate":
            resolution.assert_no_incomplete()
            result = "allowed"
        else:
            result = resolution.acknowledge(cfg, name, token, reason)
    except core.Error as exc:
        print(json.dumps({"error": str(exc)}))
        sys.exit(17)
    print(json.dumps({"result": result}))
'''


class ResolutionProcessCrashTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        (self.path / "state").mkdir(mode=0o700)
        (self.path / "fixture.json").write_text(json.dumps({
            "domain": DOMAIN, "previous": PREVIOUS, "intended": INTENDED, "reason": REASON,
        }))
        (self.path / "remote.json").write_text(json.dumps(PREVIOUS))
        (self.path / "remote.json").chmod(0o600)
        process = self.child("setup")
        self.assertEqual(process.returncode, 0, process.stderr.decode() + process.stdout.decode())
        self.preview = json.loads((self.path / "preview.json").read_text())
        self.token = self.preview["confirmation_token"]
        self.journal = self.path / "state" / "transactions" / (DOMAIN + ".json")
        self.bundle = self.path / "state" / "resolutions" / self.token
        self.authorization = self.bundle / "authorization.json"
        self.completion = self.bundle / "completion.json"

    def child(self, mode, checkpoint=""):
        return subprocess.run(
            [sys.executable, "-c", CHILD, str(self.path), mode, checkpoint],
            cwd=ROOT, input=b"", stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
        )

    def result(self, process):
        self.assertEqual(process.returncode, 0, process.stderr.decode() + process.stdout.decode())
        return json.loads(process.stdout)["result"]

    def assert_unchanged_remote(self):
        self.assertEqual(json.loads((self.path / "remote.json").read_text()), PREVIOUS)
        self.assertFalse((self.path / "forbidden-call").exists())

    def crash_and_resume(self, checkpoint, pending, authorized, completed):
        process = self.child("ack", checkpoint)
        self.assertEqual(process.returncode, CRASH_EXIT, process.stderr.decode() + process.stdout.decode())
        self.assertEqual(self.journal.exists(), pending)
        self.assertEqual(self.authorization.exists(), authorized)
        self.assertEqual(self.completion.exists(), completed)
        self.assert_unchanged_remote()
        evidence = self.authorization.read_bytes() if authorized else None
        if authorized:
            audit = json.loads(evidence)
            self.assertEqual(audit["journal"]["previous"], PREVIOUS)
            self.assertEqual(audit["journal"]["intended"], INTENDED)
            self.assertEqual(audit["reason"], REASON)
            self.assertEqual(audit["tls"], "unverified")
            gate = self.child("gate")
            if completed:
                self.assertEqual(self.result(gate), "allowed")
            else:
                self.assertEqual(gate.returncode, REFUSAL_EXIT, gate.stderr.decode())
                self.assertFalse(self.completion.exists())
                self.assertEqual(self.journal.exists(), pending)
                preview = self.result(self.child("preview"))
                self.assertEqual(preview["confirmation_token"], self.token)
                self.assertEqual(preview["pending_journal"], pending)
                self.assertTrue(preview["authorization_recorded"])
                self.assertEqual(preview["tls"], "unverified")
                if not pending:
                    self.assertEqual(preview["phase"], "acknowledging")
        result = self.result(self.child("retry"))
        self.assertEqual(result, {"domain": DOMAIN, "result": "acknowledged_unverified",
                                  "tls": "unverified", "confirmation_token": self.token})
        self.assertFalse(self.journal.exists())
        self.assertTrue(self.authorization.exists())
        self.assertTrue(self.completion.exists())
        if evidence is not None:
            self.assertEqual(self.authorization.read_bytes(), evidence)
        self.assertEqual(self.result(self.child("gate")), "allowed")
        # A completed retry retains the first authorization and completion.
        accepted = (self.authorization.read_bytes(), self.completion.read_bytes())
        self.assertEqual(self.result(self.child("retry")), result)
        self.assertEqual((self.authorization.read_bytes(), self.completion.read_bytes()), accepted)
        self.assert_unchanged_remote()

    def test_exit_after_authorization_file_sync_before_publication(self):
        self.crash_and_resume("auth-file-fsync", True, False, False)

    def test_exit_after_authorization_publication_before_directory_sync(self):
        self.crash_and_resume("auth-publish", True, True, False)

    def test_exit_after_durable_authorization(self):
        self.crash_and_resume("auth-directory-fsync", True, True, False)

    def test_exit_after_final_readback_before_pending_removal(self):
        self.crash_and_resume("before-pending-unlink", True, True, False)

    def test_exit_after_pending_removal_before_directory_sync(self):
        self.crash_and_resume("after-pending-unlink", False, True, False)

    def test_exit_after_durable_pending_removal(self):
        self.crash_and_resume("pending-directory-fsync", False, True, False)

    def test_exit_after_completion_publication_before_directory_sync(self):
        self.crash_and_resume("completion-publish", False, True, True)

    def test_exit_after_durable_completion(self):
        self.crash_and_resume("completion-directory-fsync", False, True, True)

    def test_restart_refuses_changed_remote_and_retains_authorization(self):
        process = self.child("ack", "after-pending-unlink")
        self.assertEqual(process.returncode, CRASH_EXIT, process.stderr.decode())
        evidence = self.authorization.read_bytes()
        third = dict(PREVIOUS, SecureCertificate="[bWFudWFsLWNlcnQ=]")
        (self.path / "remote.json").write_text(json.dumps(third))
        retry = self.child("retry")
        self.assertEqual(retry.returncode, REFUSAL_EXIT, retry.stderr.decode())
        self.assertEqual(self.authorization.read_bytes(), evidence)
        self.assertFalse(self.completion.exists())
        self.assertEqual(self.child("gate").returncode, REFUSAL_EXIT)
        self.assertEqual(json.loads((self.path / "remote.json").read_text()), third)
        self.assertFalse((self.path / "forbidden-call").exists())

    def test_restart_refuses_replaced_identical_journal(self):
        process = self.child("ack", "auth-directory-fsync")
        self.assertEqual(process.returncode, CRASH_EXIT, process.stderr.decode())
        evidence = self.authorization.read_bytes()
        contents = self.journal.read_bytes()
        replacement = self.journal.with_suffix(".replacement")
        replacement.write_bytes(contents)
        replacement.chmod(0o600)
        replacement.replace(self.journal)
        retry = self.child("retry")
        self.assertEqual(retry.returncode, REFUSAL_EXIT, retry.stderr.decode())
        self.assertEqual(self.journal.read_bytes(), contents)
        self.assertEqual(self.authorization.read_bytes(), evidence)
        self.assertFalse(self.completion.exists())
        self.assertEqual(self.child("gate").returncode, REFUSAL_EXIT)
        self.assert_unchanged_remote()

    def test_restart_refuses_corrupt_authorization(self):
        process = self.child("ack", "auth-directory-fsync")
        self.assertEqual(process.returncode, CRASH_EXIT, process.stderr.decode())
        contents = self.journal.read_bytes()
        self.authorization.write_bytes(b'{"schema":')
        retry = self.child("retry")
        self.assertEqual(retry.returncode, REFUSAL_EXIT, retry.stderr.decode())
        self.assertEqual(self.journal.read_bytes(), contents)
        self.assertEqual(self.authorization.read_bytes(), b'{"schema":')
        self.assertFalse(self.completion.exists())
        self.assertEqual(self.child("gate").returncode, REFUSAL_EXIT)
        self.assert_unchanged_remote()
