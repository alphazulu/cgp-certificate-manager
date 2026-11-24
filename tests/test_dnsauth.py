"""Owned DNS records survive failed API calls and local persistence faults."""

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from cgp_cert_manager import core, dnsauth, recovery, storage


VALUE = "A" * 43
OTHER_VALUE = "B" * 43
ZONE = "a" * 32
OTHER_ZONE = "b" * 32


class FakeCloudflare:
    def __init__(self):
        self.records = {}
        self.calls = []
        self.counter = 0
        self.page_size = 100
        self.empty_pages = 1
        self.before = None

    def add(self, zone=ZONE, name="_acme-challenge.example.com", value=VALUE,
            owner="user-owned", **changes):
        self.counter += 1
        record = dict(id=f"{self.counter:032x}", type="TXT", name=name,
                      content=value, comment=owner)
        record.update(changes)
        self.records[(zone, record["id"])] = record
        return record

    def __call__(self, credentials, endpoint, method="GET", params=None, data=None):
        parts = endpoint.split("/")
        zone = parts[1]
        record_id = parts[3] if len(parts) == 4 else None
        self.calls.append((credentials, zone, record_id, method, copy.deepcopy(params), copy.deepcopy(data)))
        if self.before:
            self.before(method, record_id, data)
        if len(parts) == 2:
            return {"result": {"id": zone}}
        if method == "POST":
            record = self.add(zone, data["name"], data["content"], data["comment"], ttl=data["ttl"])
            return {"result": copy.deepcopy(record)}
        if method == "DELETE":
            self.records.pop((zone, record_id), None)
            return {"result": {"id": record_id}}
        if record_id is not None:
            if (zone, record_id) not in self.records:
                raise HTTPError("https://api.example.invalid/", 404, "missing", {}, None)
            return {"result": copy.deepcopy(self.records[(zone, record_id)])}
        values = [copy.deepcopy(value) for (item_zone, _), value in self.records.items()
                  if item_zone == zone and ("name" not in params or value["name"] == params["name"])]
        start = (params["page"] - 1) * self.page_size
        pages = max(self.empty_pages, (len(values) + self.page_size - 1) // self.page_size)
        selected = values[start:start + self.page_size]
        return {"result": selected,
                "result_info": {"total_pages": pages, "page": params["page"],
                                "count": len(selected), "total_count": len(values)}}


class DNSAuthTests(unittest.TestCase):
    def setUp(self):
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(tmp)
        self.state = self.root / "state"
        self.enterContext(patch.object(core, "STATE", self.state))
        self.credential = self.root / "cloudflare.ini"
        self.other_credential = self.root / "other.ini"
        for path in (self.credential, self.other_credential):
            storage.atomic_text(path, "dns_cloudflare_api_token = PRIVATE_API_TOKEN\n")
        self.cfg = {"communigate": {"url": "http://127.0.0.1:106/CLI/"},
                    "cloudflare_accounts": [{"credentials": str(self.credential)},
                                             {"credentials": str(self.other_credential)}]}
        self.zones = {"example.com": {"id": ZONE, "credentials": str(self.credential)},
                      "example.net": {"id": OTHER_ZONE, "credentials": str(self.other_credential)}}
        self.api = FakeCloudflare()
        self.cf = self.enterContext(patch.object(core, "cf", side_effect=self.api))
        self.session = dnsauth.Session(self.cfg)

    def receipts(self):
        return {path: json.loads(path.read_text())
                for path in sorted((self.state / "dns-challenges").glob("*.json"))}

    def only_receipt(self):
        receipts = self.receipts()
        self.assertEqual(len(receipts), 1)
        return next(iter(receipts.items()))

    def create(self, identifier="example.com", value=VALUE, session=None):
        (session or self.session).create(identifier, value, self.zones)

    def assert_safe_error(self, callable_):
        with self.assertRaises(dnsauth.DNSAuthError) as error:
            callable_()
        message = str(error.exception)
        for secret in (VALUE, OTHER_VALUE, "PRIVATE_API_TOKEN", "PRIVATE_RESPONSE"):
            self.assertNotIn(secret, message)
        return message

    def test_create_intent_is_durable_before_post_then_exact_owned_cleanup(self):
        foreign = self.api.add(value=OTHER_VALUE)
        def before(method, record_id, data):
            if method == "POST":
                path, receipt = self.only_receipt()
                self.assertEqual(receipt["phase"], "intent")
                self.assertIsNone(receipt["record"])
                self.assertEqual(receipt["owner"], data["comment"])
                self.assertEqual(data["content"], '"' + VALUE + '"')
                self.assertEqual(receipt["value"], VALUE)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            if method == "DELETE":
                self.assertEqual(self.only_receipt()[1]["phase"], "created")
        self.api.before = before
        self.create()
        _, receipt = self.only_receipt()
        self.assertEqual(receipt["phase"], "created")
        self.assertEqual(receipt["name"], "_acme-challenge.example.com")
        self.assertEqual(self.api.records[(ZONE, receipt["record"])]["content"], '"' + VALUE + '"')
        self.session.cleanup()
        self.assertEqual(self.receipts(), {})
        self.assertEqual(list(self.api.records.values()), [foreign])

    def test_borrowed_identical_record_is_never_deleted(self):
        foreign = self.api.add()
        self.create()
        self.assertEqual(self.only_receipt()[1]["phase"], "borrowed")
        self.session.cleanup()
        self.assertEqual(list(self.api.records.values()), [foreign])
        self.assertEqual([item[3] for item in self.api.calls], ["GET"])

    def test_borrowed_quoted_record_is_never_deleted(self):
        foreign = self.api.add(value='"' + VALUE + '"')
        self.create()
        self.assertEqual(self.only_receipt()[1]["phase"], "borrowed")
        self.session.cleanup()
        self.assertEqual(list(self.api.records.values()), [foreign])
        self.assertEqual([item[3] for item in self.api.calls], ["GET"])

    def test_wildcard_apex_distinct_values_and_duplicate_value_coexist(self):
        self.create()
        self.create("*.example.com", OTHER_VALUE)
        self.create("*.example.com", VALUE)
        self.assertEqual(len(self.api.records), 2)
        self.assertEqual(len(self.receipts()), 3)
        self.assertEqual({record["name"] for record in self.api.records.values()},
                         {"_acme-challenge.example.com"})
        self.assertEqual({record["content"] for record in self.api.records.values()},
                         {'"' + VALUE + '"', '"' + OTHER_VALUE + '"'})
        self.session.cleanup()
        self.assertEqual(self.api.records, {})
        self.assertEqual(sum(item[3] == "DELETE" for item in self.api.calls), 2)

    def test_multi_account_routes_and_cleanup_uses_saved_binding(self):
        self.create()
        self.create("mail.example.net", OTHER_VALUE)
        self.cfg["cloudflare_accounts"].reverse()
        dnsauth.cleanup_pending(self.cfg)
        posts = [item for item in self.api.calls if item[3] == "POST"]
        deletes = [item for item in self.api.calls if item[3] == "DELETE"]
        self.assertEqual({(item[0], item[1]) for item in posts},
                         {(str(self.credential), ZONE), (str(self.other_credential), OTHER_ZONE)})
        self.assertEqual({(item[0], item[1]) for item in deletes},
                         {(str(self.credential), ZONE), (str(self.other_credential), OTHER_ZONE)})

    def test_cleanup_only_its_own_attempt_then_pending_recovery(self):
        other = dnsauth.Session(self.cfg)
        self.create()
        self.create(value=OTHER_VALUE, session=other)
        self.session.cleanup()
        self.assertEqual(len(self.receipts()), 1)
        self.assertEqual(self.only_receipt()[1]["attempt"], other.attempt)
        dnsauth.cleanup_pending(self.cfg)
        self.assertEqual(self.receipts(), {})

    def test_absent_ledger_is_read_only(self):
        dnsauth.cleanup_pending(self.cfg)
        self.assertEqual(dnsauth.status({}), [])
        dnsauth.assert_clear({})
        self.assertFalse(self.state.exists())
        self.cf.assert_not_called()

    def test_public_status_omits_credentials_and_values_and_blocks_all_issuance(self):
        self.create()
        self.cf.reset_mock()
        before = {path: path.read_bytes() for path in self.receipts()}
        rows = dnsauth.status(self.cfg)
        self.assertEqual(len(rows), 1)
        self.assertEqual(set(rows[0]), {"id", "name", "phase", "owned", "zone"})
        self.assertEqual(rows[0]["owned"], True)
        self.assertEqual(rows[0]["phase"], "created")
        text = json.dumps(rows)
        self.assertNotIn(VALUE, text)
        self.assertNotIn(str(self.credential), text)
        self.assertIn("--dns-transactions", self.assert_safe_error(lambda: dnsauth.assert_clear(self.cfg)))
        self.assertEqual(before, {path: path.read_bytes() for path in self.receipts()})
        self.cf.assert_not_called()

    def test_status_distinguishes_borrowed_unknown_and_complete_receipts(self):
        self.api.add()
        self.create()
        path, receipt = self.only_receipt()
        self.assertIs(dnsauth.status(self.cfg)[0]["owned"], False)
        receipt.update(phase="intent", record=None)
        storage.atomic_json(path, receipt)
        self.assertIsNone(dnsauth.status(self.cfg)[0]["owned"])
        receipt.update(phase="complete", record="c" * 32)
        storage.atomic_json(path, receipt)
        self.assertIsNone(dnsauth.status(self.cfg)[0]["owned"])

    def test_status_never_exposes_malformed_receipt_contents(self):
        self.create()
        path, _ = self.only_receipt()
        storage.atomic_text(path, "PRIVATE_RESPONSE " + VALUE)
        self.cf.reset_mock()
        self.assert_safe_error(lambda: dnsauth.status(self.cfg))
        self.cf.assert_not_called()

    def test_normalized_idn_zone_and_legacy_credentials(self):
        self.zones["xn--bcher-kva.example"] = {"id": ZONE, "credentials": str(self.credential)}
        cfg = {"communigate": self.cfg["communigate"], "cloudflare_credentials": str(self.credential)}
        session = dnsauth.Session(cfg)
        session.create("*.BÜCHER.example.", VALUE, self.zones)
        self.assertEqual(self.only_receipt()[1]["name"], "_acme-challenge.xn--bcher-kva.example")
        dnsauth.cleanup_pending(cfg)

    def test_invalid_challenges_do_not_call_provider(self):
        for identifier, value in (("127.0.0.1", VALUE), ("bad;name", VALUE),
                                  ("example.com", None), ("example.com", "short"),
                                  ("example.com", "A" * 42 + "!")):
            with self.subTest(identifier=identifier):
                self.assert_safe_error(lambda: self.create(identifier, value))
        self.cf.assert_not_called()

    def test_invalid_zone_or_credentials_fail_before_provider(self):
        self.assert_safe_error(lambda: self.create("unknown.test"))
        for changes in ({"id": "wrong"}, {"credentials": str(self.root / "not-allowed")},
                        {"credentials": None}):
            with self.subTest(changes=changes):
                zone = dict(self.zones["example.com"], **changes)
                self.assert_safe_error(lambda: self.session.create("example.com", VALUE, {"example.com": zone}))
        for cfg in ({}, {"cloudflare_credentials": ""}, {"cloudflare_accounts": [{}]}):
            self.assert_safe_error(lambda: dnsauth.Session(cfg).create("example.com", VALUE, self.zones))
        self.credential.chmod(0o644)
        self.assert_safe_error(self.create)
        self.cf.assert_not_called()

    def test_nonce_collision_never_overwrites_existing_receipt(self):
        self.create()
        path, _ = self.only_receipt()
        before = path.read_bytes()
        calls = self.cf.call_count
        with patch.object(dnsauth.secrets, "token_hex", return_value=path.stem):
            self.assert_safe_error(lambda: self.create(value=OTHER_VALUE))
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.cf.call_count, calls)

    def test_pagination_finds_identical_record_after_other_values(self):
        self.api.page_size = 1
        self.api.add(value=OTHER_VALUE)
        self.api.add(value=VALUE)
        self.create()
        self.assertEqual(self.only_receipt()[1]["phase"], "borrowed")
        self.assertEqual([item[4]["page"] for item in self.api.calls], [1, 2])

    def test_uncertain_post_requires_complete_stable_filtered_lookup(self):
        def lost_response(*args, **kwargs):
            result = self.api(*args, **kwargs)
            if kwargs.get("method") == "POST":
                raise OSError("PRIVATE_RESPONSE")
            return result
        with patch.object(core, "cf", side_effect=lost_response):
            self.assert_safe_error(self.create)
        path, receipt = self.only_receipt()
        before = path.read_bytes()
        first = copy.deepcopy(next(iter(self.api.records.values())))
        self.api.add(owner=receipt["owner"])
        def truncated(credentials, endpoint, method="GET", params=None, data=None):
            if params:
                values = [first] if params["page"] == 1 else []
                return {"result": values,
                        "result_info": {"page": params["page"], "count": len(values),
                                        "total_count": 2 if params["page"] == 1 else 1,
                                        "total_pages": 2 if params["page"] == 1 else 1}}
            return self.api(credentials, endpoint, method, params, data)
        with patch.object(core, "cf", side_effect=truncated):
            self.assert_safe_error(self.session.cleanup)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(len(self.api.records), 2)
        self.assertFalse(any(item[3] == "DELETE" for item in self.api.calls))

    def test_uncertain_post_rejects_missing_or_contradictory_listing_evidence(self):
        def lost_response(*args, **kwargs):
            response = self.api(*args, **kwargs)
            if kwargs.get("method") == "POST":
                raise OSError("PRIVATE_RESPONSE")
            return response
        with patch.object(core, "cf", side_effect=lost_response):
            self.assert_safe_error(self.create)
        path, _ = self.only_receipt()
        before = path.read_bytes()
        remote = copy.deepcopy(next(iter(self.api.records.values())))
        info = {"page": 1, "count": 1, "total_count": 1, "total_pages": 1}
        responses = [{"result": [remote]},
                     *({"result": [remote], "result_info": {k: v for k, v in info.items() if k != missing}}
                       for missing in info),
                     *({"result": [remote], "result_info": dict(info, **change)} for change in
                       ({"page": 2}, {"page": True}, {"count": True}, {"count": 0},
                        {"total_count": None}, {"total_count": -1}, {"total_count": True},
                        {"total_count": 0}, {"total_count": 2},
                        {"total_pages": True}, {"total_pages": 0}, {"total_pages": 101})),
                     {"result": [remote, remote],
                      "result_info": dict(info, count=2, total_count=2)},
                     {"result": [remote, {"id": "not-an-id"}],
                      "result_info": dict(info, count=2, total_count=2)}]
        for response in responses:
            with self.subTest(response=response), patch.object(core, "cf", return_value=response) as requests:
                self.assert_safe_error(self.session.cleanup)
                requests.assert_called_once()
                self.assertEqual(requests.call_args.kwargs["params"]["page"], 1)
            self.assertEqual(path.read_bytes(), before)
        self.assertEqual(len(self.api.records), 1)
        self.assertFalse(any(item[3] == "DELETE" for item in self.api.calls))

    def test_uncertain_post_rejects_changed_page_totals_and_page_identity(self):
        def lost_response(*args, **kwargs):
            response = self.api(*args, **kwargs)
            if kwargs.get("method") == "POST":
                raise OSError("PRIVATE_RESPONSE")
            return response
        with patch.object(core, "cf", side_effect=lost_response):
            self.assert_safe_error(self.create)
        path, _ = self.only_receipt()
        before = path.read_bytes()
        remote = copy.deepcopy(next(iter(self.api.records.values())))
        foreign = self.api.add(value=OTHER_VALUE)
        for change in ({"total_pages": 1}, {"total_count": 3}, {"page": 1}):
            def changing(credentials, endpoint, method="GET", params=None, data=None):
                page = params["page"]
                info = {"page": page, "count": 1, "total_count": 2, "total_pages": 2}
                if page == 2:
                    info.update(change)
                return {"result": [remote if page == 1 else foreign], "result_info": info}
            with self.subTest(change=change), patch.object(core, "cf", side_effect=changing) as requests:
                self.assert_safe_error(self.session.cleanup)
                self.assertEqual([call.kwargs["params"]["page"] for call in requests.call_args_list], [1, 2])
            self.assertEqual(path.read_bytes(), before)
        self.assertEqual(len(self.api.records), 2)
        self.assertFalse(any(item[3] == "DELETE" for item in self.api.calls))

    def test_uncertain_post_recovers_unique_owner_from_complete_multiple_pages(self):
        def lost_response(*args, **kwargs):
            response = self.api(*args, **kwargs)
            if kwargs.get("method") == "POST":
                raise OSError("PRIVATE_RESPONSE")
            return response
        with patch.object(core, "cf", side_effect=lost_response):
            self.assert_safe_error(self.create)
        owned_key, owned = self.api.records.popitem()
        foreign = [self.api.add(value=OTHER_VALUE), self.api.add(value=VALUE)]
        self.api.records[owned_key] = owned
        self.api.page_size = 1
        self.api.calls.clear()
        dnsauth.cleanup_pending(self.cfg)
        self.assertEqual([item[4]["page"] for item in self.api.calls if item[4]], [1, 2, 3])
        self.assertEqual([item[2] for item in self.api.calls if item[3] == "DELETE"], [owned["id"]])
        self.assertEqual(list(self.api.records.values()), foreign)
        self.assertEqual(self.receipts(), {})

    def test_invalid_list_responses_do_not_create_any_record(self):
        for response in ("PRIVATE_RESPONSE", {"result": {}}, {"result": [None]},
                         {"result": [], "result_info": None},
                         *({"result": [], "result_info": {"total_pages": pages}}
                           for pages in (0, 101, True, 1.5))):
            with self.subTest(response=response), patch.object(core, "cf", return_value=response):
                self.assert_safe_error(self.create)
        self.assertEqual(self.receipts(), {})

    def test_list_without_optional_pagination_is_accepted(self):
        foreign = self.api.add()
        with patch.object(core, "cf", return_value={"result": [foreign]}):
            self.create()
        self.assertEqual(self.only_receipt()[1]["phase"], "borrowed")

    def test_zero_page_empty_filtered_and_complete_zone_listings_are_supported(self):
        self.api.empty_pages = 0
        self.create()
        _, receipt = self.only_receipt()
        self.api.records.pop((ZONE, receipt["record"]))
        self.session.cleanup()
        self.assertEqual(self.receipts(), {})
        self.assertTrue(any(call[4] == {"page": 1, "per_page": 100} for call in self.api.calls))

    def test_zero_pages_requires_consistent_strict_empty_metadata(self):
        valid = {"page": 1, "count": 0, "total_count": 0, "total_pages": 0}
        responses = [{"result": [], "result_info": dict(valid, **change)} for change in
                     ({"page": None}, {"page": True}, {"page": 2}, {"count": False}, {"count": 1},
                      {"total_count": "0"}, {"total_count": 1})]
        responses += [{"result": [{"id": "f" * 32}], "result_info": valid}]
        for response in responses:
            with self.subTest(response=response), patch.object(core, "cf", return_value=response):
                self.assert_safe_error(self.create)
        self.assertEqual(self.receipts(), {})
        self.create()
        _, receipt = self.only_receipt()
        self.api.records.pop((ZONE, receipt["record"]))
        for response in responses:
            def invalid_empty(credentials, endpoint, **kwargs):
                return response if kwargs.get("params") else self.api(credentials, endpoint, **kwargs)
            with self.subTest(response=response), patch.object(core, "cf", side_effect=invalid_empty):
                self.assert_safe_error(self.session.cleanup)
        self.assertEqual(len(self.receipts()), 1)

    def test_zero_page_marker_after_first_page_is_rejected(self):
        def changing(*args, **kwargs):
            page = kwargs["params"]["page"]
            return {"result": [], "result_info": {"page": 1, "count": 0, "total_count": 0,
                                                   "total_pages": 2 if page == 1 else 0}}
        with patch.object(core, "cf", side_effect=changing) as requests:
            self.assert_safe_error(self.create)
        self.assertEqual(requests.call_count, 2)
        self.assertEqual(self.receipts(), {})

    def test_invalid_borrowed_record_id_never_post_or_delete(self):
        self.api.add(id="not-an-id")
        self.assert_safe_error(self.create)
        self.assertEqual(self.receipts(), {})
        self.assertTrue(all(item[3] == "GET" for item in self.api.calls))

    def test_uncertain_post_recovered_by_exact_marker_and_durable_id(self):
        def lost_response(*args, **kwargs):
            result = self.api(*args, **kwargs)
            if kwargs.get("method") == "POST":
                raise OSError("PRIVATE_RESPONSE " + VALUE)
            return result
        with patch.object(core, "cf", side_effect=lost_response):
            self.assert_safe_error(self.create)
        self.assertEqual(self.only_receipt()[1]["phase"], "intent")
        def check_delete(method, record_id, data):
            if method == "DELETE":
                receipt = self.only_receipt()[1]
                self.assertEqual(receipt["record"], record_id)
                self.assertEqual(receipt["phase"], "created")
        self.api.before = check_delete
        dnsauth.cleanup_pending(self.cfg)
        self.assertEqual(self.api.records, {})
        self.assertEqual(self.receipts(), {})

    def test_uncertain_post_without_match_stays_pending(self):
        def refused(*args, **kwargs):
            if kwargs.get("method") == "POST":
                raise OSError("PRIVATE_RESPONSE")
            return self.api(*args, **kwargs)
        with patch.object(core, "cf", side_effect=refused):
            self.assert_safe_error(self.create)
        self.assert_safe_error(lambda: dnsauth.cleanup_pending(self.cfg))
        self.assertEqual(self.only_receipt()[1]["phase"], "intent")
        self.assertEqual(self.api.records, {})

    def rejected_post(self, *args, **kwargs):
        if kwargs.get("method") == "POST":
            raise core.CloudflareRejected("PRIVATE_RESPONSE")
        return self.api(*args, **kwargs)

    def test_definite_rejected_post_clears_only_its_intent_without_retry(self):
        foreign = self.api.add(value=OTHER_VALUE)
        with patch.object(core, "cf", side_effect=self.rejected_post) as requests:
            self.assert_safe_error(self.create)
        self.assertEqual(sum(call.kwargs.get("method") == "POST" for call in requests.call_args_list), 1)
        self.assertEqual(self.receipts(), {})
        self.assertEqual(list(self.api.records.values()), [foreign])
        dnsauth.assert_clear(self.cfg)

    def test_rejected_post_completion_survives_failed_unlink_without_api_retry(self):
        with patch.object(core, "cf", side_effect=self.rejected_post), \
                patch.object(dnsauth, "_remove", side_effect=OSError("PRIVATE_RESPONSE")):
            self.assert_safe_error(self.create)
        _, receipt = self.only_receipt()
        self.assertEqual(receipt["phase"], "complete")
        self.assertIsNone(receipt["record"])
        self.assertIsNone(dnsauth.status(self.cfg)[0]["owned"])
        self.cf.reset_mock()
        dnsauth.cleanup_pending(self.cfg)
        self.cf.assert_not_called()
        self.assertEqual(self.receipts(), {})

    def test_rejected_post_complete_replace_survives_reported_sync_failure(self):
        write = storage.atomic_json
        def interrupted_save(path, record):
            write(path, record)
            if record["phase"] == "complete":
                raise OSError("PRIVATE_RESPONSE")
        with patch.object(core, "cf", side_effect=self.rejected_post), \
                patch.object(storage, "atomic_json", side_effect=interrupted_save):
            self.assert_safe_error(self.create)
        self.assertEqual(self.only_receipt()[1]["phase"], "complete")
        self.cf.reset_mock()
        dnsauth.cleanup_pending(self.cfg)
        self.cf.assert_not_called()
        self.assertEqual(self.receipts(), {})

    def test_rejection_not_persisted_remains_conservative_intent(self):
        write = storage.atomic_json
        def before_save(path, record):
            if record["phase"] == "complete":
                raise OSError("PRIVATE_RESPONSE")
            write(path, record)
        with patch.object(core, "cf", side_effect=self.rejected_post), \
                patch.object(storage, "atomic_json", side_effect=before_save):
            self.assert_safe_error(self.create)
        self.assertEqual(self.only_receipt()[1]["phase"], "intent")
        self.assert_safe_error(lambda: dnsauth.cleanup_pending(self.cfg))
        self.assertEqual(self.api.records, {})

    def test_rejected_delete_cannot_be_treated_as_confirmed_absence(self):
        self.create()
        def refused_delete(*args, **kwargs):
            if kwargs.get("method") == "DELETE":
                raise core.CloudflareRejected("PRIVATE_RESPONSE")
            return self.api(*args, **kwargs)
        with patch.object(core, "cf", side_effect=refused_delete):
            self.assert_safe_error(self.session.cleanup)
        self.assertEqual(self.only_receipt()[1]["phase"], "created")
        self.assertEqual(len(self.api.records), 1)
        dnsauth.cleanup_pending(self.cfg)
        self.assertEqual(self.receipts(), {})

    def test_ambiguous_owned_lookup_retains_intent_without_deletion(self):
        def lost(*args, **kwargs):
            response = self.api(*args, **kwargs)
            if kwargs.get("method") == "POST":
                self.api.add(owner=kwargs["data"]["comment"])
                raise OSError()
            return response
        with patch.object(core, "cf", side_effect=lost):
            self.assert_safe_error(self.create)
        self.assert_safe_error(self.session.cleanup)
        self.assertEqual(len(self.api.records), 2)
        self.assertFalse(any(item[3] == "DELETE" for item in self.api.calls))

    def test_bad_created_response_preserves_intent_for_reconciliation(self):
        for result in (None, {}, {"id": "bad"}, {"id": "f" * 32, "type": "TXT"}):
            with self.subTest(result=result):
                def response(*args, **kwargs):
                    if kwargs.get("method") == "POST":
                        return {"result": result}
                    return self.api(*args, **kwargs)
                with patch.object(core, "cf", side_effect=response):
                    self.assert_safe_error(self.create)
        self.assertEqual(len(self.receipts()), 4)
        self.assertTrue(all(record["phase"] == "intent" for record in self.receipts().values()))

    def test_http_errors_are_safe_and_record_404_requires_independent_absence(self):
        error = HTTPError("https://api.example.invalid/PRIVATE_RESPONSE", 404, VALUE, {}, None)
        with patch.object(core, "cf", side_effect=error):
            self.assert_safe_error(self.create)
        self.create()
        _, receipt = self.only_receipt()
        self.api.records.pop((ZONE, receipt["record"]))
        self.session.cleanup()
        self.assertEqual(self.receipts(), {})
        self.create()
        def fail_delete(*args, **kwargs):
            if kwargs.get("method") == "DELETE":
                raise error
            return self.api(*args, **kwargs)
        with patch.object(core, "cf", side_effect=fail_delete):
            self.assert_safe_error(self.session.cleanup)
        self.assertEqual(self.only_receipt()[1]["phase"], "created")

    def test_generic_get_404_with_hidden_or_wrong_zone_never_discards_receipt(self):
        self.create()
        error = HTTPError("https://api.example.invalid/", 404, "PRIVATE_RESPONSE", {}, None)
        with patch.object(core, "cf", side_effect=error):
            self.assert_safe_error(self.session.cleanup)
        for response in ({"result": {"id": OTHER_ZONE}}, {"result": None}):
            def wrong_zone(credentials, endpoint, **kwargs):
                if endpoint.count("/") == 3:
                    raise error
                return response
            with patch.object(core, "cf", side_effect=wrong_zone):
                self.assert_safe_error(self.session.cleanup)
        self.assertEqual(len(self.receipts()), 1)
        self.assertFalse(any(item[3] == "DELETE" for item in self.api.calls))

    def test_get_404_but_record_id_in_unfiltered_listing_is_not_absence(self):
        self.create()
        _, receipt = self.only_receipt()
        remote = self.api.records[(ZONE, receipt["record"])]
        remote.update(name="renamed.example.com", type="A", content="192.0.2.1")
        self.api.page_size = 1
        self.api.add(value=OTHER_VALUE)
        def hidden_id(credentials, endpoint, **kwargs):
            if endpoint.endswith("/" + receipt["record"]):
                raise HTTPError("https://api.example.invalid/", 404, "missing", {}, None)
            return self.api(credentials, endpoint, **kwargs)
        with patch.object(core, "cf", side_effect=hidden_id):
            self.assert_safe_error(self.session.cleanup)
        lists = [item[4] for item in self.api.calls if item[4] and "name" not in item[4]]
        self.assertEqual([params["page"] for params in lists], [1, 2])
        self.assertFalse(any(item[3] == "DELETE" for item in self.api.calls))
        self.assertEqual(len(self.receipts()), 1)

    def test_incomplete_or_changing_absence_listing_keeps_receipt(self):
        self.create()
        _, receipt = self.only_receipt()
        self.api.records.pop((ZONE, receipt["record"]))
        base_info = {"page": 1, "count": 0, "total_count": 0, "total_pages": 1}
        responses = ({"result": []},
                     {"result": [], "result_info": {"page": 1, "count": 0, "total_count": 0}},
                     *({"result": [], "result_info": dict(base_info, **change)} for change in
                       ({"page": 2}, {"page": True}, {"count": False}, {"count": 1},
                        {"total_count": None}, {"total_count": -1}, {"total_count": True},
                        {"total_count": 1})),
                     {"result": [{"id": "f" * 32}, {"id": "f" * 32}],
                      "result_info": {"page": 1, "count": 2, "total_count": 2, "total_pages": 1}})
        for response in responses:
            def incomplete(credentials, endpoint, **kwargs):
                if kwargs.get("params"):
                    return response
                return self.api(credentials, endpoint, **kwargs)
            with self.subTest(response=response), patch.object(core, "cf", side_effect=incomplete):
                self.assert_safe_error(self.session.cleanup)
        for changed in ({"total_pages": 1}, {"total_count": 2}):
            def changing(credentials, endpoint, **kwargs):
                params = kwargs.get("params")
                if params:
                    info = {"page": params["page"], "count": 0, "total_count": 0, "total_pages": 2}
                    if params["page"] == 2:
                        info.update(changed)
                    return {"result": [], "result_info": info}
                return self.api(credentials, endpoint, **kwargs)
            with self.subTest(changed=changed), patch.object(core, "cf", side_effect=changing):
                self.assert_safe_error(self.session.cleanup)
        self.assertEqual(len(self.receipts()), 1)
        dnsauth.cleanup_pending(self.cfg)
        self.assertEqual(self.receipts(), {})

    def test_api_non_http_exception_during_cleanup_retains_receipt(self):
        self.create()
        with patch.object(core, "cf", side_effect=ValueError("PRIVATE_RESPONSE " + VALUE)):
            self.assert_safe_error(self.session.cleanup)
        self.assertEqual(len(self.receipts()), 1)

    def test_changed_remote_identity_or_ownership_is_never_deleted(self):
        self.create()
        _, receipt = self.only_receipt()
        original = copy.deepcopy(self.api.records[(ZONE, receipt["record"])])
        for change in ({"id": "f" * 32}, {"type": "A"}, {"name": "different.example.com"},
                       {"content": OTHER_VALUE}, {"comment": "changed-by-user"}):
            with self.subTest(change=change):
                self.api.records[(ZONE, receipt["record"])] = dict(original, **change)
                self.assert_safe_error(self.session.cleanup)
                self.assertEqual(len(self.receipts()), 1)
        self.assertFalse(any(item[3] == "DELETE" for item in self.api.calls))

    def test_escaped_split_double_quoted_and_different_txt_are_not_ownership_matches(self):
        self.create()
        _, receipt = self.only_receipt()
        remote = self.api.records[(ZONE, receipt["record"])]
        malformed = (r'\"' + VALUE + r'\"', '""' + VALUE + '""',
                     '"' + VALUE[:20] + '" "' + VALUE[20:] + '"',
                     '"' + VALUE + '" "' + OTHER_VALUE + '"', '"' + OTHER_VALUE + '"')
        for value in malformed:
            with self.subTest(value=value):
                remote["content"] = value
                self.assert_safe_error(self.session.cleanup)
        self.assertFalse(any(item[3] == "DELETE" for item in self.api.calls))
        self.assertEqual(len(self.receipts()), 1)
        remote["content"] = '"' + VALUE + '"'
        self.session.cleanup()

    def test_invalid_quoted_post_reply_keeps_intent_until_exact_list_and_get_match(self):
        def changed_reply(*args, **kwargs):
            response = self.api(*args, **kwargs)
            if kwargs.get("method") == "POST":
                response["result"]["content"] = '""' + VALUE + '""'
            return response
        with patch.object(core, "cf", side_effect=changed_reply):
            self.assert_safe_error(self.create)
        self.assertEqual(self.only_receipt()[1]["phase"], "intent")
        self.assertEqual(next(iter(self.api.records.values()))["content"], '"' + VALUE + '"')
        self.session.cleanup()
        self.assertEqual(self.receipts(), {})
        self.assertEqual(self.api.records, {})

    def test_missing_or_invalid_remote_result_is_not_assumed_deleted(self):
        self.create()
        for response in ({}, {"result": None}, {"result": {"id": "bad"}}):
            with self.subTest(response=response), patch.object(core, "cf", return_value=response):
                self.assert_safe_error(self.session.cleanup)
        self.assertEqual(len(self.receipts()), 1)

    def test_bad_delete_confirmation_retries_by_readback(self):
        self.create()
        def bad_confirmation(*args, **kwargs):
            result = self.api(*args, **kwargs)
            return {"result": {"id": "f" * 32}} if kwargs.get("method") == "DELETE" else result
        with patch.object(core, "cf", side_effect=bad_confirmation):
            self.assert_safe_error(self.session.cleanup)
        self.assertEqual(self.api.records, {})
        self.assertEqual(len(self.receipts()), 1)
        dnsauth.cleanup_pending(self.cfg)
        self.assertEqual(self.receipts(), {})

    def test_cleanup_continues_other_receipts_after_one_provider_failure(self):
        self.create()
        self.create(value=OTHER_VALUE)
        failing_id = next(record["record"] for record in self.receipts().values() if record["value"] == VALUE)
        def fail_one(*args, **kwargs):
            if args[1].endswith("/" + failing_id):
                raise OSError("PRIVATE_RESPONSE")
            return self.api(*args, **kwargs)
        with patch.object(core, "cf", side_effect=fail_one):
            self.assert_safe_error(lambda: dnsauth.cleanup_pending(self.cfg))
        self.assertEqual(len(self.receipts()), 1)
        self.assertEqual(self.only_receipt()[1]["value"], VALUE)
        self.assertEqual(len(self.api.records), 1)

    def test_persistence_failure_before_post_prevents_remote_create(self):
        with patch.object(storage, "atomic_json", side_effect=OSError("PRIVATE_RESPONSE")):
            self.assert_safe_error(self.create)
        self.assertFalse(any(item[3] == "POST" for item in self.api.calls))

    def test_persistence_failure_after_post_leaves_recoverable_intent(self):
        atomic = storage.atomic_json
        def fail_receipt(path, record):
            if record["phase"] == "created":
                raise OSError("PRIVATE_RESPONSE")
            return atomic(path, record)
        with patch.object(storage, "atomic_json", side_effect=fail_receipt):
            self.assert_safe_error(self.create)
        self.assertEqual(self.only_receipt()[1]["phase"], "intent")
        dnsauth.cleanup_pending(self.cfg)
        self.assertEqual(self.receipts(), {})

    def test_interrupted_final_unlink_retries_without_another_dns_delete(self):
        self.create()
        with patch.object(dnsauth, "_remove", side_effect=OSError()):
            self.assert_safe_error(self.session.cleanup)
        self.assertEqual(self.only_receipt()[1]["phase"], "complete")
        self.cf.reset_mock()
        dnsauth.cleanup_pending(self.cfg)
        self.cf.assert_not_called()
        self.assertEqual(self.receipts(), {})

    def test_final_directory_sync_is_retried_even_when_receipt_is_gone(self):
        self.create()
        real_sync = dnsauth.sync_directory
        with patch.object(dnsauth, "sync_directory", side_effect=[OSError(), None]):
            self.assert_safe_error(self.session.cleanup)
        self.assertEqual(self.receipts(), {})
        with patch.object(dnsauth, "sync_directory", wraps=real_sync) as sync:
            dnsauth.cleanup_pending(self.cfg)
        sync.assert_called_once_with(self.state / "dns-challenges")

    def test_interrupt_after_remote_post_preserves_intent(self):
        def interrupted(*args, **kwargs):
            result = self.api(*args, **kwargs)
            if kwargs.get("method") == "POST":
                raise KeyboardInterrupt
            return result
        with patch.object(core, "cf", side_effect=interrupted), self.assertRaises(KeyboardInterrupt):
            self.create()
        self.assertEqual(self.only_receipt()[1]["phase"], "intent")
        dnsauth.cleanup_pending(self.cfg)
        self.assertEqual(self.api.records, {})

    def test_corrupt_or_unsafe_ledger_blocks_provider_calls(self):
        self.create()
        path, record = self.only_receipt()
        self.cf.reset_mock()
        path.write_text("PRIVATE_RESPONSE")
        self.assert_safe_error(lambda: dnsauth.cleanup_pending(self.cfg))
        storage.atomic_json(path, record)
        path.chmod(0o644)
        self.assert_safe_error(lambda: dnsauth.cleanup_pending(self.cfg))
        path.chmod(0o600)
        path.unlink()
        path.symlink_to(self.credential)
        self.assert_safe_error(lambda: dnsauth.cleanup_pending(self.cfg))
        self.cf.assert_not_called()

    def test_all_receipts_validate_before_any_deletion(self):
        self.create()
        self.create(value=OTHER_VALUE)
        path = sorted(self.receipts())[-1]
        storage.atomic_text(path, "{broken")
        self.cf.reset_mock()
        self.assert_safe_error(lambda: dnsauth.cleanup_pending(self.cfg))
        self.cf.assert_not_called()
        self.assertEqual(len(self.api.records), 2)

    def test_receipts_copied_to_another_server_are_refused_before_api(self):
        self.create()
        before = {path: path.read_bytes() for path in self.receipts()}
        self.cf.reset_mock()
        with patch.object(recovery, "server_identity", return_value="b" * 64):
            self.assert_safe_error(lambda: dnsauth.status(self.cfg))
            self.assert_safe_error(lambda: dnsauth.cleanup_pending(self.cfg))
        self.cf.assert_not_called()
        self.assertEqual(before, {path: path.read_bytes() for path in self.receipts()})
        dnsauth.cleanup_pending(self.cfg)
        self.assertEqual(self.receipts(), {})

    def test_invalid_receipt_schema_identity_value_and_phase_fail_closed(self):
        self.create()
        path, original = self.only_receipt()
        changes = ({"schema": True}, {"schema": 2}, {"extra": "PRIVATE_RESPONSE"},
                   {"attempt": "bad"}, {"owner": "other"}, {"credentials": None},
                   {"credentials": "/not-configured"}, {"zone": "bad"},
                   {"name": None}, {"name": "example.com"},
                   {"name": "_acme-challenge.EXAMPLE.com"},
                   {"name": "_acme-challenge.bad;name"}, {"value": "bad"},
                   {"phase": []}, {"phase": "unknown"}, {"record": "bad"},
                   {"record": None}, {"phase": "intent"})
        self.cf.reset_mock()
        for change in changes:
            with self.subTest(change=change):
                storage.atomic_json(path, dict(original, **change))
                self.assert_safe_error(lambda: dnsauth.cleanup_pending(self.cfg))
        storage.atomic_json(path, [])
        self.assert_safe_error(lambda: dnsauth.cleanup_pending(self.cfg))
        path.unlink()
        storage.atomic_json(path.with_name("bad.json"), original)
        self.assert_safe_error(lambda: dnsauth.cleanup_pending(self.cfg))
        self.cf.assert_not_called()
