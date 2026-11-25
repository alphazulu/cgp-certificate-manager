"""Provider selection, capability boundaries and Cloudflare compatibility."""
from copy import deepcopy
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError

from cgp_cert_manager import core, dnsproviders as providers
from test_dnsauth import FakeCloudflare, VALUE, ZONE


class ProviderContractTests(unittest.TestCase):
    def test_selection_is_explicit_pure_and_preserves_legacy_configuration(self):
        for cfg in ({}, {"cloudflare_credentials": "old.ini"},
                    {"dns_provider": "cloudflare", "cloudflare_accounts": [{"credentials": "a.ini"}]}):
            before = deepcopy(cfg)
            with patch.object(core, "token", side_effect=AssertionError("No credential read")), \
                    patch.object(core, "cf", side_effect=AssertionError("No provider access")):
                driver = providers.get_provider(cfg)
                self.assertEqual(providers.provider_name(cfg), "cloudflare")
                self.assertEqual(driver.name, "cloudflare")
                self.assertEqual(driver.provider_id, "cloudflare")
            self.assertEqual(cfg, before)

    def test_unknown_provider_never_becomes_a_module_path_or_silent_default(self):
        for cfg in (None, [], "PRIVATE_CONFIG", {"dns_provider": None}, {"dns_provider": True},
                    {"dns_provider": "Cloudflare"}, {"dns_provider": "cloudflare "},
                    {"dns_provider": "PRIVATE_MODULE:run"}, {"dns_provider": ["cloudflare"]}):
            with self.subTest(cfg=cfg), patch.object(core, "cf") as request, patch.object(core, "token") as token:
                for operation in (providers.provider_name, providers.get_provider, providers.credentials):
                    with self.assertRaises(providers.ProviderError) as raised:
                        operation(cfg)
                    self.assertNotIn("PRIVATE", str(raised.exception))
                request.assert_not_called()
                token.assert_not_called()

    def test_credential_order_precedence_duplicates_and_absolute_allowlist(self):
        cfg = {"cloudflare_credentials": "ignored.ini", "cloudflare_accounts": [
            {"name": "first", "credentials": "first.ini"},
            {"name": "second", "credentials": "second.ini"},
            {"credentials": "first.ini"}]}
        before = deepcopy(cfg)
        driver = providers.get_provider(cfg)
        with patch.object(core, "token", side_effect=AssertionError("Path inspection is read-only")):
            self.assertEqual(driver.credentials(cfg), ("first.ini", "second.ini", "first.ini"))
            self.assertEqual(providers.credentials(cfg, absolute=True),
                             tuple(str(Path(path).absolute()) for path in driver.credentials(cfg)))
            for accounts in (None, []):
                self.assertEqual(driver.credentials({"cloudflare_accounts": accounts,
                                                     "cloudflare_credentials": "legacy.ini"}), ("legacy.ini",))
        self.assertEqual(cfg, before)

    def test_invalid_credential_configuration_refuses_without_reading_a_secret(self):
        bad = ({}, {"cloudflare_credentials": ""}, {"cloudflare_credentials": 42},
               {"cloudflare_accounts": "PRIVATE_PATH"}, {"cloudflare_accounts": [{}, None]},
               {"cloudflare_accounts": ["PRIVATE_PATH"]}, {"cloudflare_accounts": [{"credentials": []}]})
        for cfg in bad:
            with self.subTest(cfg=cfg), patch.object(core, "token") as token:
                with self.assertRaisesRegex(providers.ProviderError, "Invalid DNS credentials configuration"):
                    providers.credentials(cfg)
                token.assert_not_called()

    def test_fixed_cleanup_allowlist_preserves_active_paths_and_distinct_legacy_fallback(self):
        accounts = [{"credentials": "first.ini"}, {"credentials": "second.ini"},
                    {"credentials": "first.ini"}]
        active = ("first.ini", "second.ini", "first.ini")
        cases = [({}, active)]
        for fallback in (None, False, 42, [], {}, "", "first.ini", "second.ini"):
            cases.append(({"cloudflare_credentials": fallback}, active))
        cases.append(({"cloudflare_credentials": "legacy.ini"}, active + ("legacy.ini",)))
        driver = providers.get_provider({})
        with patch.object(core, "token", side_effect=AssertionError("No credential read")), \
                patch.object(core, "cf", side_effect=AssertionError("No provider access")):
            for extra, expected in cases:
                cfg = {"cloudflare_accounts": deepcopy(accounts), **extra}
                before = deepcopy(cfg)
                with self.subTest(extra=extra):
                    self.assertEqual(driver.fixed_cleanup_credentials(cfg), expected)
                    self.assertEqual(driver.credentials(cfg), active)
                    self.assertEqual(cfg, before)
            self.assertEqual(driver.fixed_cleanup_credentials({"cloudflare_credentials": "legacy.ini"}),
                             ("legacy.ini",))
            with self.assertRaises(providers.ProviderError):
                driver.fixed_cleanup_credentials({"cloudflare_accounts": [{}],
                                                  "cloudflare_credentials": "legacy.ini"})

    def test_installer_validation_reads_each_existing_private_credential(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / name for name in ("first.ini", "second.ini")]
            for path in paths:
                path.write_text("dns_cloudflare_api_token = PRIVATE_TOKEN\n")
                path.chmod(0o600)
            cfg = {"cloudflare_accounts": [{"credentials": str(path)} for path in paths]}
            driver = providers.get_provider(cfg)
            driver.validate_credentials(cfg)
            paths[-1].write_text("unrelated = PRIVATE_TOKEN\n")
            with self.assertRaisesRegex(core.Error, "Cloudflare token missing"):
                driver.validate_credentials(cfg)
            paths[-1].write_text("dns_cloudflare_api_token = PRIVATE_TOKEN\n")
            paths[-1].chmod(0o644)
            with self.assertRaises(core.Error):
                driver.validate_credentials(cfg)

    def test_capabilities_are_immutable_and_refused_before_any_transport(self):
        request = Mock(side_effect=AssertionError("Unsupported operation reached provider"))
        driver = providers.get_provider({}, transport=request)
        self.assertIsInstance(driver.capabilities, frozenset)
        self.assertEqual(driver.capabilities,
                         {"zone_discovery", "fixed_native", "fixed_hooks", "owned_txt"})
        for name in driver.capabilities:
            driver.require(name)
        for name in (None, [], "PRIVATE_CAPABILITY"):
            with self.assertRaisesRegex(providers.ProviderError, "DNS provider capability unavailable"):
                driver.require(name)
        operations = (
            lambda: driver.zones({"cloudflare_credentials": "one.ini"}),
            lambda: driver.native_arguments("one.ini", 60),
            lambda: driver.fixed_create("one.ini", ZONE, "_acme-challenge.example.com", VALUE),
            lambda: driver.fixed_delete("one.ini", ZONE, "b" * 32),
            lambda: driver.list_records({"credentials": "one.ini", "zone": ZONE, "name": "x"}),
        )
        with patch.object(type(driver), "capabilities", frozenset()):
            for operation in operations:
                with self.assertRaises(providers.ProviderError):
                    operation()
        request.assert_not_called()

    def test_native_arguments_keep_exact_fixed_authenticator_flags(self):
        driver = providers.get_provider({})
        self.assertEqual(driver.native_arguments("/private/cloudflare.ini", 90),
                         ["--dns-cloudflare", "--dns-cloudflare-credentials", "/private/cloudflare.ini",
                          "--dns-cloudflare-propagation-seconds", "90"])

    def test_zone_discovery_keeps_pagination_normalization_and_first_account_wins(self):
        replies = [{"result": [{"name": "Example.COM.", "id": "1"}, {"name": "bad", "id": "x"}],
                    "result_info": {"total_pages": 2}},
                   {"result": [{"name": "sub.example.com", "id": "2", "name_servers": ["ns.example.net"]}]},
                   {"result": [{"name": "example.com", "id": "3"}]}]
        request = Mock(side_effect=replies)
        driver = providers.get_provider({}, transport=request)
        cfg = {"cloudflare_accounts": [{"credentials": "first.ini"}, {"credentials": "second.ini"}]}
        self.assertEqual(driver.zones(cfg), {
            "example.com": {"id": "1", "credentials": "first.ini", "ns": []},
            "sub.example.com": {"id": "2", "credentials": "first.ini", "ns": ["ns.example.net"]}})
        self.assertEqual([call.args for call in request.call_args_list],
                         [("first.ini", "zones"), ("first.ini", "zones"), ("second.ini", "zones")])
        self.assertEqual([call.kwargs["params"] for call in request.call_args_list],
                         [{"status": "active", "page": page, "per_page": 50} for page in (1, 2, 1)])

    def test_transport_is_resolved_lazily_and_can_be_injected_without_global_mutation(self):
        driver = providers.get_provider({})
        cfg = {"cloudflare_credentials": "one.ini"}
        for _ in range(2):
            with patch.object(core, "cf", return_value={"result": []}) as request:
                self.assertEqual(driver.zones(cfg), {})
                request.assert_called_once()
        injected = Mock(return_value={"result": []})
        with patch.object(core, "cf", side_effect=AssertionError("Wrong transport")):
            self.assertEqual(providers.get_provider({}, injected).zones(cfg), {})
        injected.assert_called_once()


class CloudflareOperationTests(unittest.TestCase):
    def setUp(self):
        self.api = FakeCloudflare()
        self.driver = providers.get_provider({}, transport=self.api)
        self.receipt = {"credentials": "private.ini", "zone": ZONE, "name": "_acme-challenge.example.com",
                        "value": VALUE, "owner": "cgp-certificate-manager:" + "b" * 32, "record": None}

    def test_owned_record_roundtrip_preserves_other_values_and_verifies_absence(self):
        foreign = self.api.add(value="B" * 43)
        self.assertEqual(self.driver.list_records(self.receipt), [foreign])
        created = self.driver.create_txt(self.receipt)
        self.receipt["record"] = self.driver.record_id(created)
        self.assertTrue(self.driver.matches(created, self.receipt, owned=True))
        self.assertEqual(created["content"], '"' + VALUE + '"')
        self.assertEqual(self.driver.get_record(self.receipt), created)
        self.driver.delete_record(self.receipt)
        self.assertIsNone(self.driver.get_record(self.receipt))
        self.driver.confirm_absent(self.receipt)
        self.assertEqual(list(self.api.records.values()), [foreign])
        self.assertEqual(self.api.calls[-1][4], {"page": 1, "per_page": 100})

    def test_fixed_hooks_keep_unquoted_unowned_txt_and_transport_success_cleanup(self):
        request = Mock(side_effect=[{"result": {"id": "legacy-id"}}, object()])
        driver = providers.get_provider({}, transport=request)
        record_id = driver.fixed_create("private.ini", ZONE, self.receipt["name"], VALUE)
        self.assertEqual(record_id, "legacy-id")
        driver.fixed_delete("private.ini", ZONE, record_id)
        post, deletion = request.call_args_list
        self.assertEqual(post.kwargs["data"],
                         {"type": "TXT", "name": self.receipt["name"], "content": VALUE, "ttl": 120})
        self.assertEqual(deletion.args, ("private.ini", "zones/" + ZONE + "/dns_records/legacy-id"))
        self.assertEqual(deletion.kwargs["method"], "DELETE")
        self.assertIsNone(deletion.kwargs["data"])

    def test_record_identity_is_provider_specific_and_matching_never_unquotes_arbitrary_text(self):
        for value in (None, True, "", "a" * 31, "A" * 32, "../" + "a" * 32):
            self.assertFalse(self.driver.valid_zone_id(value))
            self.assertFalse(self.driver.valid_record_id(value))
            with self.assertRaises(providers.ProviderError):
                self.driver.record_id({"id": value})
        for value in (None, [], "PRIVATE_RESPONSE"):
            with self.assertRaises(providers.ProviderError):
                self.driver.record_id(value)
        self.assertEqual(self.driver.record_id({"id": "1" * 32}), "1" * 32)
        expected = {"id": "1" * 32, "type": "TXT", "name": self.receipt["name"],
                    "content": VALUE, "comment": self.receipt["owner"]}
        self.assertTrue(self.driver.matches(expected, self.receipt, owned=True))
        self.assertTrue(self.driver.matches({**expected, "content": '"' + VALUE + '"'}, self.receipt))
        for change in ({"type": "A"}, {"name": "other.example.com"}, {"content": '""' + VALUE + '""'},
                       {"content": " " + VALUE}, {"content": '"' + VALUE[:20] + '" "' + VALUE[20:] + '"'},
                       {"comment": "foreign"}):
            self.assertFalse(self.driver.matches({**expected, **change}, self.receipt, owned=True))
        self.assertTrue(self.driver.matches({**expected, "comment": "foreign"}, self.receipt))

    def test_only_explicit_rejected_post_can_be_treated_as_definite_creation_failure(self):
        request = Mock(side_effect=core.CloudflareRejected("PRIVATE_RESPONSE"))
        driver = providers.get_provider({}, transport=request)
        with self.assertRaises(providers.ProviderRejected) as raised:
            driver.create_txt(self.receipt)
        self.assertNotIn("PRIVATE_RESPONSE", str(raised.exception))
        for failure in (core.CloudflareRejected("PRIVATE_RESPONSE"), RuntimeError("PRIVATE_RESPONSE")):
            request.side_effect = failure
            with self.assertRaises(providers.ProviderError) as raised:
                driver.list_records(self.receipt)
            self.assertNotIsInstance(raised.exception, providers.ProviderRejected)
            self.assertNotIn("PRIVATE_RESPONSE", str(raised.exception))

    def test_record_404_is_an_observation_not_proof_of_absence_and_error_body_closes(self):
        body = io.BytesIO(b"PRIVATE_PROVIDER_BODY")
        error = HTTPError("https://api.example.invalid/", 404, "PRIVATE_RESPONSE", {}, body)
        self.receipt["record"] = "c" * 32
        request = Mock(side_effect=error)
        driver = providers.get_provider({}, transport=request)
        self.assertIsNone(driver.get_record(self.receipt))
        self.assertTrue(body.closed)
        for method in (driver.list_records, driver.create_txt, driver.delete_record, driver.confirm_absent):
            request.side_effect = HTTPError("https://api.example.invalid/", 404, "PRIVATE_RESPONSE", {}, None)
            with self.assertRaises(providers.ProviderError) as raised:
                method(self.receipt)
            self.assertNotIn("PRIVATE_RESPONSE", str(raised.exception))

    def test_unknown_http_error_or_failed_close_cannot_become_an_absent_record(self):
        self.receipt["record"] = "c" * 32
        for code in (400, 403, 500):
            error = HTTPError("https://api.example.invalid/", code, "PRIVATE_RESPONSE", {}, None)
            with self.assertRaises(providers.ProviderError):
                providers.get_provider({}, Mock(side_effect=error)).get_record(self.receipt)
        error = HTTPError("https://api.example.invalid/", 404, "PRIVATE_RESPONSE", {}, None)
        with patch.object(error, "close", side_effect=OSError("PRIVATE_CLOSE")):
            with self.assertRaises(providers.ProviderError) as raised:
                providers.get_provider({}, Mock(side_effect=error)).get_record(self.receipt)
        self.assertNotIn("PRIVATE_CLOSE", str(raised.exception))

    def test_null_or_invalid_reply_is_not_a_404(self):
        self.receipt["record"] = "c" * 32
        for response in (None, [], "PRIVATE_RESPONSE", {}, {"result": None}, {"result": {"id": "bad"}}):
            with self.subTest(response=response), self.assertRaises(providers.ProviderError):
                providers.get_provider({}, Mock(return_value=response)).get_record(self.receipt)

    def test_complete_listing_keeps_foreign_types_and_rejects_missing_unique_count_evidence(self):
        self.api.page_size = 1
        first = self.api.add()
        second = self.api.add(name="other.example.com", type="A", value="192.0.2.1")
        self.assertEqual(self.driver.list_records(self.receipt, exact_name=False), [first, second])
        self.assertEqual([call[4] for call in self.api.calls],
                         [{"page": 1, "per_page": 100}, {"page": 2, "per_page": 100}])
        bad = ({"result": [first]},
               {"result": [first, first], "result_info": {"page": 1, "count": 2, "total_count": 2, "total_pages": 1}},
               {"result": [first], "result_info": {"page": 1, "count": 1, "total_count": 2, "total_pages": 1}})
        for response in bad:
            with self.assertRaises(providers.ProviderError):
                providers.get_provider({}, Mock(return_value=response)).list_records(self.receipt, require_complete=True)

    def test_owned_delete_requires_exact_acknowledgement(self):
        self.receipt["record"] = "c" * 32
        for response in (None, {"result": {}}, {"result": {"id": "d" * 32}}):
            with self.assertRaises(providers.ProviderError):
                providers.get_provider({}, Mock(return_value=response)).delete_record(self.receipt)

    def test_absence_proof_requires_exact_zone_and_all_records_including_renamed_id(self):
        self.receipt["record"] = "c" * 32
        with self.assertRaisesRegex(providers.ProviderError, "zone is unavailable"):
            providers.get_provider({}, Mock(return_value={"result": {"id": "d" * 32}})).confirm_absent(self.receipt)
        self.api.add(name="renamed.example.com", type="A", value="192.0.2.1", id=self.receipt["record"])
        with self.assertRaisesRegex(providers.ProviderError, "deletion remains unresolved"):
            self.driver.confirm_absent(self.receipt)
        self.assertTrue(all(call[3] == "GET" for call in self.api.calls))


if __name__ == "__main__":
    unittest.main()
