"""Real process death leaves durable DNS ownership evidence for a fresh process.

The provider boundaries use private, fsynced JSON backends. RFC2136 messages
also pass through real TSIG wire parsing. No external DNS, network, Certbot,
system configuration or real challenge credentials are accessed.
"""

import base64
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

    def test_legacy_cloudflare_intent_recovers_in_a_fresh_process_without_rebinding(self):
        self.run_child("create", "post_persisted", expected=73)
        path = next((self.root / "state" / "dns-challenges").glob("*.json"))
        receipt = self.only_receipt()
        self.assertEqual(receipt.pop("provider"), "cloudflare")
        receipt["schema"] = 1
        storage.atomic_json(path, receipt)
        before = path.read_bytes()
        self.assertEqual(json.loads(self.run_child("status").stdout)[0]["phase"], "intent")
        self.assertEqual(path.read_bytes(), before)
        self.run_child("cleanup")
        self.assert_foreign_preserved()
        self.assertEqual(self.receipts(), [])
        self.assertEqual(sum(call["method"] == "POST" for call in self.remote()["calls"]), 1)
        self.assertEqual(sum(call["method"] == "DELETE" for call in self.remote()["calls"]), 1)

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


RFC2136_CHILD = r'''
import json
import os
from pathlib import Path
import sys
import dns.opcode
import dns.query
import dns.rcode
import dns.rdatatype

from cgp_cert_manager import core, dnsauth, rfc2136_config, storage
from rfc2136_fixture import FakePrimary

root = Path(sys.argv[1])
action, checkpoint = sys.argv[2:4]
core.STATE = root / "state"
cfg = json.loads(storage.read_text(root / "config.json"))
backend = root / "rfc-primary.json"
saved = json.loads(storage.read_text(backend))
entry = rfc2136_config.validate(cfg)[0]
primary = FakePrimary(zone=entry["zone"], key_name=entry["key_name"],
                      secret=rfc2136_config.read_secret(entry["credentials"]))
for row in saved["records"]:
    primary.put(row["name"], *row["texts"], ttl=row["ttl"], kind=row["kind"])

def persist():
    saved["records"] = [{"name": rr.name.to_text(), "kind": dns.rdatatype.to_text(rr.rdtype),
                          "ttl": rr.ttl, "texts": [rd.to_text() for rd in rr]}
                         for rr in primary.records.values()]
    storage.atomic_json(backend, saved)

def before(query):
    saved["requests"] += 1
    if query.opcode() == dns.opcode.UPDATE and query.update:
        saved["attempts"] += 1
        persist()
        if checkpoint == "create_not_delivered":
            os._exit(73)

def after(query, response):
    mutated = query.opcode() == dns.opcode.UPDATE and query.update and response.rcode() == dns.rcode.NOERROR
    if mutated:
        saved["mutations"] += 1
    persist()
    if mutated and checkpoint in ("create_persisted", "delete_persisted"):
        os._exit(73)

primary.before = before
primary.after = after
dns.query.tcp = primary
try:
    if action == "status":
        print(json.dumps(dnsauth.status(cfg), sort_keys=True))
    elif action == "guard":
        dnsauth.assert_clear(cfg)
    else:
        with storage.operation_lock(core.STATE):
            dnsauth.cleanup_pending(cfg)
            if action == "create":
                dnsauth.Session(cfg).create("example.com", "A" * 43, core.zones(cfg))
except core.Error as error:
    print(str(error))
    sys.exit(17)
'''


class RFC2136CrashTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.backend = self.root / "rfc-primary.json"
        self.key = self.root / "key.json"
        storage.atomic_json(self.key, {"secret": base64.b64encode(b"S" * 32).decode()})
        self.cfg = {"dns_provider": "rfc2136", "dns_propagation": {"mode": "adaptive"},
                    "communigate": {"url": "http://127.0.0.1:106/CLI/"},
                    "rfc2136": {"zones": [{"zone": "example.com", "server": "192.0.2.53",
                        "key_name": "acme.example.com", "credentials": str(self.key),
                        "nameservers": ["ns1.example.com"]}]}}
        storage.atomic_json(self.root / "config.json", self.cfg)
        storage.atomic_json(self.backend, {"requests": 0, "attempts": 0, "mutations": 0,
            "records": [{"name": "_acme-challenge.example.com.", "kind": "TXT", "ttl": 120,
                         "texts": ['"operator" "-owned"']}]})

    def child(self, action, checkpoint="none", expected=0):
        tests = Path(__file__).resolve().parent
        env = dict(os.environ, PYTHONPATH=os.pathsep.join((str(tests.parent), str(tests))))
        result = subprocess.run([sys.executable, "-c", RFC2136_CHILD, str(self.root), action, checkpoint],
                                env=env, stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, timeout=15)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        self.assertNotIn("A" * 43, result.stdout + result.stderr)
        self.assertNotIn(base64.b64encode(b"S" * 32).decode(), result.stdout + result.stderr)
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

    def assert_cleaned(self):
        rows = self.remote()["records"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "_acme-challenge.example.com.")
        self.assertEqual(len(rows[0]["texts"]), 2)
        self.assertIn('"operator" "-owned"', rows[0]["texts"])
        self.assertEqual(sum(text.startswith('"cgp-certificate-manager:generation:')
                             for text in rows[0]["texts"]), 1)

    def test_death_after_conditional_create_recovers_owner_pair_in_fresh_process(self):
        self.child("create", "create_persisted", expected=73)
        receipt = self.only_receipt()
        self.assertEqual((receipt["schema"], receipt["provider"], receipt["phase"]), (2, "rfc2136", "intent"))
        self.assertIsNone(receipt["record"])
        self.assertEqual(self.remote()["mutations"], 1)
        self.child("cleanup")
        self.assert_cleaned()
        self.assertEqual(self.remote()["mutations"], 2)
        self.assertEqual(self.receipts(), [])
        self.assertEqual(json.loads(self.child("status").stdout), [])

    def test_death_after_conditional_delete_proves_absence_without_another_mutation(self):
        self.child("create")
        self.child("cleanup", "delete_persisted", expected=73)
        self.assertEqual(self.only_receipt()["phase"], "created")
        self.assert_cleaned()
        before = self.remote()
        self.child("cleanup")
        self.assertEqual(self.remote()["records"], before["records"])
        self.assertEqual(self.remote()["mutations"], before["mutations"])
        self.assertEqual(self.remote()["attempts"], before["attempts"])
        self.assertEqual(self.receipts(), [])

    def test_uncertain_create_without_remote_effect_stays_pending_and_is_not_retried(self):
        self.child("create", "create_not_delivered", expected=73)
        self.assertEqual(self.only_receipt()["phase"], "intent")
        self.child("cleanup", expected=17)
        self.child("create", expected=17)
        before_guard = self.remote()
        self.child("guard", expected=17)
        self.assertEqual(self.remote(), before_guard)
        self.assertEqual(self.remote()["mutations"], 0)
        self.assertEqual(self.remote()["attempts"], 1)
        self.assertEqual(self.only_receipt()["phase"], "intent")
