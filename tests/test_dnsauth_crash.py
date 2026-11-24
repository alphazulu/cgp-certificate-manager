"""Real process death leaves durable DNS ownership evidence for a fresh process.

The Cloudflare boundary is a private, fsynced JSON backend.  No DNS, network,
Certbot, system configuration, or real challenge credentials are accessed.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cgp_cert_manager import storage


CHILD = r'''
import copy
import json
import os
from pathlib import Path
import sys
from urllib.error import HTTPError

from cgp_cert_manager import core, dnsauth, storage

root = Path(sys.argv[1])
action, checkpoint = sys.argv[2:4]
core.STATE = root / "state"
backend = root / "remote.json"
credentials = str(root / "cloudflare.ini")
zone = "a" * 32
cfg = {"communigate": {"url": "http://127.0.0.1:106/CLI/"},
       "cloudflare_credentials": credentials}
zones = {"example.com": {"id": zone, "credentials": credentials}}

def provider(credentials, endpoint, method="GET", params=None, data=None):
    saved = json.loads(storage.read_text(backend))
    saved["calls"].append({"method": method, "endpoint": endpoint, "params": params})
    parts = endpoint.split("/")
    record_id = parts[3] if len(parts) == 4 else None
    if method == "POST":
        if checkpoint == "post_not_delivered":
            storage.atomic_json(backend, saved)
            os._exit(73)
        record_id = f'{saved["next"]:032x}'
        saved["next"] += 1
        remote = dict(data, id=record_id)
        saved["records"][record_id] = remote
        storage.atomic_json(backend, saved)
        if checkpoint == "post_persisted":
            os._exit(73)
        return {"result": copy.deepcopy(remote)}
    if method == "DELETE":
        receipts = [json.loads(storage.read_text(path))
                    for path in (core.STATE / "dns-challenges").glob("*.json")]
        assert any(receipt["phase"] == "created" and receipt["record"] == record_id
                   for receipt in receipts), "DELETE lacked durable ownership identity"
        saved["records"].pop(record_id, None)
        storage.atomic_json(backend, saved)
        if checkpoint == "delete_persisted":
            os._exit(73)
        return {"result": {"id": record_id}}
    storage.atomic_json(backend, saved)
    if len(parts) == 2:
        return {"result": {"id": zone}}
    if record_id is not None:
        if record_id not in saved["records"]:
            raise HTTPError("https://api.invalid/", 404, "missing", {}, None)
        return {"result": copy.deepcopy(saved["records"][record_id])}
    records = [record for record in saved["records"].values()
               if "name" not in params or record["name"] == params["name"]]
    assert params["page"] == 1
    return {"result": records,
            "result_info": {"page": 1, "count": len(records), "total_count": len(records),
                            "total_pages": 1}}

core.cf = provider
try:
    if action == "status":
        print(json.dumps(dnsauth.status(cfg), sort_keys=True))
    elif action == "guard":
        dnsauth.assert_clear(cfg)
    else:
        with storage.operation_lock(core.STATE):
            dnsauth.cleanup_pending(cfg)
            if action == "create":
                dnsauth.Session(cfg).create("example.com", "A" * 43, zones)
except core.Error as error:
    print(str(error))
    sys.exit(17)
'''


class DNSAuthCrashTests(unittest.TestCase):
    def setUp(self):
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(tmp)
        self.backend = self.root / "remote.json"
        self.foreign = {"id": "9" * 32, "type": "TXT", "name": "_acme-challenge.example.com",
                        "content": "C" * 43, "comment": "operator-owned"}
        storage.atomic_text(self.root / "cloudflare.ini", "dns_cloudflare_api_token = SYNTHETIC\n")
        storage.atomic_json(self.backend, {"records": {self.foreign["id"]: self.foreign},
                                           "calls": [], "next": 1})

    def run_child(self, action, checkpoint="none", expected=0):
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1]))
        result = subprocess.run([sys.executable, "-c", CHILD, str(self.root), action, checkpoint],
                                env=env, stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, timeout=15)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        self.assertNotIn("A" * 43, result.stdout + result.stderr)
        self.assertNotIn("SYNTHETIC", result.stdout + result.stderr)
        return result

    def remote(self):
        return json.loads(storage.read_text(self.backend))

    def receipts(self):
        return [json.loads(storage.read_text(path))
                for path in (self.root / "state" / "dns-challenges").glob("*.json")]

    def only_receipt(self):
        receipts = self.receipts()
        self.assertEqual(len(receipts), 1)
        return receipts[0]

    def assert_foreign_preserved(self):
        self.assertEqual(self.remote()["records"], {self.foreign["id"]: self.foreign})

    def test_death_after_post_recovers_exact_owned_marker_in_fresh_process(self):
        self.run_child("create", "post_persisted", expected=73)
        receipt = self.only_receipt()
        self.assertEqual(receipt["phase"], "intent")
        self.assertIsNone(receipt["record"])
        self.assertEqual(len(self.remote()["records"]), 2)
        owned = [record for record in self.remote()["records"].values()
                 if record["comment"] == receipt["owner"]]
        self.assertEqual(owned[0]["content"], '"' + "A" * 43 + '"')
        self.run_child("cleanup")
        self.assert_foreign_preserved()
        self.assertEqual(self.receipts(), [])
        self.assertEqual(json.loads(self.run_child("status").stdout), [])
        calls = self.remote()["calls"]
        self.assertEqual([call["method"] for call in calls], ["GET", "POST", "GET", "GET", "DELETE"])
        self.assertEqual(calls[-2]["endpoint"], calls[-1]["endpoint"])

    def test_death_after_delete_retries_confirmed_absence_without_second_delete(self):
        self.run_child("create")
        self.run_child("cleanup", "delete_persisted", expected=73)
        self.assertEqual(self.only_receipt()["phase"], "created")
        self.assert_foreign_preserved()
        self.run_child("cleanup")
        self.assertEqual(self.receipts(), [])
        self.assert_foreign_preserved()
        calls = self.remote()["calls"]
        self.assertEqual(sum(call["method"] == "DELETE" for call in calls), 1)
        self.assertEqual(calls[-2]["endpoint"], "zones/" + "a" * 32)
        self.assertEqual(calls[-1]["params"], {"page": 1, "per_page": 100})

    def test_uncertain_post_with_no_record_stays_pending_and_blocks_new_issuance(self):
        self.run_child("create", "post_not_delivered", expected=73)
        self.assertEqual(self.only_receipt()["phase"], "intent")
        self.run_child("cleanup", expected=17)
        self.run_child("create", expected=17)
        calls_before_guard = self.remote()["calls"]
        self.run_child("guard", expected=17)
        self.assertEqual(self.remote()["calls"], calls_before_guard)
        self.assertEqual(sum(call["method"] == "POST" for call in calls_before_guard), 1)
        self.assertEqual(self.only_receipt()["phase"], "intent")
        self.assert_foreign_preserved()

    def test_changed_remote_record_is_retained_and_never_deleted_after_restart(self):
        self.run_child("create")
        receipt = self.only_receipt()
        changed = self.remote()
        changed["records"][receipt["record"]]["comment"] = "changed-by-operator"
        storage.atomic_json(self.backend, changed)
        self.run_child("cleanup", expected=17)
        self.run_child("create", expected=17)
        self.assertEqual(self.remote()["records"], changed["records"])
        self.assertEqual(self.only_receipt(), receipt)
        calls = self.remote()["calls"]
        self.assertFalse(any(call["method"] == "DELETE" for call in calls))
        self.assertEqual(sum(call["method"] == "POST" for call in calls), 1)
