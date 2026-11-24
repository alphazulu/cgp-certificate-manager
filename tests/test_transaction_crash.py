"""Process-death tests for durable certificate transaction recovery.

The remote CGP service is represented by a separately persisted JSON file.
Only transport/cryptography are substituted: the deployment, journal, phase
transitions, fsyncs and recovery execute in independent Python processes.
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
    "CertificateType": "YES",
}
INTENDED = dict(PREVIOUS, PrivateSecureKey="[bmV3LWtleQ==]",
                SecureCertificate="[bmV3LWNlcnQ=]")

# A fresh interpreter is essential: os._exit skips exception handlers,
# context-manager cleanup and finally blocks. Recovery cannot rely on mocks,
# objects, buffers or module state from the crashed process.
CHILD = r'''
from contextlib import ExitStack
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

from cgp_cert_manager import core, deployment, recovery
from cgp_cert_manager.transactions import Journal, durable_json

root, mode, checkpoint = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
fixture = json.loads((root / "fixture.json").read_text())
previous, intended = fixture["previous"], fixture["intended"]
name = fixture["domain"]
endpoints = [{"host": "127.0.0.1", "port": 443, "sni": "new.example.com"}]
old_endpoints = [{"host": "127.0.0.1", "port": 443, "sni": "old.example.com"}]
cfg = {"communigate": {"url": "http://127.0.0.1:8100/CLI/"}}
identity = recovery.server_identity(cfg, "a" * 32)
remote = root / "remote.json"
state = root / "state"


def log(event, snapshot):
    with (root / "events.jsonl").open("a") as stream:
        stream.write(json.dumps({"process": mode, "event": event,
                                 "snapshot": snapshot}) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def current(config, domain):
    assert config == cfg and domain == name
    return json.loads(remote.read_text())


def update(config, domain, settings):
    assert config == cfg and domain == name
    assert settings in (previous, intended)
    snapshot = "previous" if settings == previous else "intended"
    durable_json(remote, settings)
    log("write", snapshot)
    if mode == "apply" and ((checkpoint == "remote-write" and snapshot == "intended")
                             or (checkpoint == "restore-write" and snapshot == "previous")):
        os._exit(91)


def verify(settings, selected_endpoints):
    assert settings in (previous, intended)
    snapshot = "previous" if settings == previous else "intended"
    assert selected_endpoints == (old_endpoints if snapshot == "previous" else endpoints)
    assert current(cfg, name) == settings
    log("verify", snapshot)
    if mode == "apply" and snapshot == "intended" and checkpoint in (
            "restoring", "restore-write", "restored"):
        raise core.Error("Simulated intended TLS failure")


prepare = Journal.prepare
transition = Journal.transition


def crashing_prepare(journal, *args, **kwargs):
    record = prepare(journal, *args, **kwargs)
    if mode == "apply" and checkpoint == "prepared":
        os._exit(91)
    return record


def crashing_transition(journal, domain, phase):
    record = transition(journal, domain, phase)
    if mode == "apply" and checkpoint == phase:
        os._exit(91)
    return record


with ExitStack() as stack:
    for obj, attr, value in (
        (core, "STATE", state),
        (core, "current", current),
        (core, "update", update),
        (core, "validate_backup", lambda settings: None),
        (recovery, "server_identity", lambda config: identity),
        (recovery, "verify_snapshot", verify),
        (Journal, "prepare", crashing_prepare),
        (Journal, "transition", crashing_transition),
    ):
        stack.enter_context(patch.object(obj, attr, value))
    try:
        if mode == "apply":
            result = deployment.apply(cfg, name, previous, intended, endpoints, old_endpoints)
        else:
            result = deployment.recover_pending(cfg)
    except core.Error as exc:
        print(json.dumps({"error": str(exc)}))
        sys.exit(17)
    print(json.dumps({"result": result}))
'''


class TransactionProcessCrashTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        (self.path / "state").mkdir(mode=0o700)
        (self.path / "fixture.json").write_text(json.dumps({
            "previous": PREVIOUS, "intended": INTENDED, "domain": DOMAIN,
        }))
        (self.path / "remote.json").write_text(json.dumps(PREVIOUS))
        self.journal = self.path / "state" / "transactions" / (DOMAIN + ".json")

    def child(self, mode, checkpoint=""):
        return subprocess.run(
            [sys.executable, "-c", CHILD, str(self.path), mode, checkpoint],
            cwd=ROOT, input=b"", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=15,
        )

    def remote(self):
        return json.loads((self.path / "remote.json").read_text())

    def events(self, event, process=None):
        path = self.path / "events.jsonl"
        records = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
        return [record["snapshot"] for record in records
                if record["event"] == event and (process is None or record["process"] == process)]

    def assert_crashed(self, checkpoint, phase, remote):
        process = self.child("apply", checkpoint)
        self.assertEqual(process.returncode, CRASH_EXIT, process.stderr.decode() + process.stdout.decode())
        record = json.loads(self.journal.read_text())
        self.assertEqual(record["phase"], phase)
        self.assertEqual(record["previous"], PREVIOUS)
        self.assertEqual(record["intended"], INTENDED)
        self.assertEqual(record["previous_endpoints"][0]["sni"], "old.example.com")
        self.assertEqual(record["endpoints"][0]["sni"], "new.example.com")
        self.assertEqual(self.remote(), remote)

    def assert_recovers(self, outcome, remote, writes, verified):
        process = self.child("recover")
        self.assertEqual(process.returncode, 0, process.stderr.decode() + process.stdout.decode())
        self.assertEqual(json.loads(process.stdout), {"result": [{"domain": DOMAIN, "result": outcome}]})
        self.assertEqual(self.remote(), remote)
        self.assertEqual(self.events("write"), writes)
        self.assertEqual(self.events("verify", "recover"), verified)
        self.assertFalse(self.journal.exists())
        # A second independent recovery is harmless and performs no new write.
        again = self.child("recover")
        self.assertEqual(again.returncode, 0, again.stderr.decode())
        self.assertEqual(json.loads(again.stdout), {"result": []})
        self.assertEqual(self.events("write"), writes)

    def test_exit_after_preparation_preserves_previous(self):
        self.assert_crashed("prepared", "prepared", PREVIOUS)
        self.assert_recovers("restored", PREVIOUS, [], ["previous"])

    def test_exit_before_remote_write_preserves_previous(self):
        self.assert_crashed("applying", "applying", PREVIOUS)
        self.assert_recovers("restored", PREVIOUS, [], ["previous"])

    def test_exit_after_remote_write_resumes_intended(self):
        self.assert_crashed("remote-write", "applying", INTENDED)
        self.assert_recovers("committed", INTENDED, ["intended"], ["intended"])

    def test_exit_after_applied_resumes_verification(self):
        self.assert_crashed("applied", "applied", INTENDED)
        self.assert_recovers("committed", INTENDED, ["intended"], ["intended"])

    def test_exit_after_verifying_repeats_verification(self):
        self.assert_crashed("verifying", "verifying", INTENDED)
        self.assert_recovers("committed", INTENDED, ["intended"], ["intended"])

    def test_exit_after_commit_only_cleans_up(self):
        self.assert_crashed("committed", "committed", INTENDED)
        self.assert_recovers("committed", INTENDED, ["intended"], [])

    def test_exit_before_restoration_resumes_previous_write(self):
        self.assert_crashed("restoring", "restoring", INTENDED)
        self.assert_recovers("restored", PREVIOUS, ["intended", "previous"], ["previous"])

    def test_exit_after_restoration_verifies_without_duplicate_write(self):
        self.assert_crashed("restore-write", "restoring", PREVIOUS)
        self.assert_recovers("restored", PREVIOUS, ["intended", "previous"], ["previous"])

    def test_exit_after_restored_only_cleans_up(self):
        self.assert_crashed("restored", "restored", PREVIOUS)
        self.assert_recovers("restored", PREVIOUS, ["intended", "previous"], [])

    def test_restart_refuses_administrator_change(self):
        self.assert_crashed("remote-write", "applying", INTENDED)
        third = dict(PREVIOUS, SecureCertificate="[bWFudWFsLWNlcnQ=]")
        (self.path / "remote.json").write_text(json.dumps(third))
        evidence = self.journal.read_bytes()
        process = self.child("recover")
        self.assertEqual(process.returncode, REFUSAL_EXIT, process.stderr.decode())
        self.assertIn("Unknown CGP state", json.loads(process.stdout)["error"])
        self.assertEqual(self.remote(), third)
        self.assertEqual(self.journal.read_bytes(), evidence)
        self.assertEqual(self.events("write", "recover"), [])
        self.assertEqual(self.events("verify", "recover"), [])

    def test_restart_refuses_corrupt_journal(self):
        self.assert_crashed("remote-write", "applying", INTENDED)
        self.journal.write_bytes(b'{"schema":')
        process = self.child("recover")
        self.assertEqual(process.returncode, REFUSAL_EXIT, process.stderr.decode())
        self.assertIn("Corrupt transaction journal", json.loads(process.stdout)["error"])
        self.assertEqual(self.remote(), INTENDED)
        self.assertEqual(self.journal.read_bytes(), b'{"schema":')
        self.assertEqual(self.events("write", "recover"), [])
        self.assertEqual(self.events("verify", "recover"), [])
