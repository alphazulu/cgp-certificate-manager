"""Provider binding and schema-1 compatibility at the durable DNS boundary."""
import json
import unittest
from unittest.mock import patch

from cgp_cert_manager import core, dnsauth, dnsproviders, storage
import test_dnsauth as fixtures


class DNSProviderReceiptTests(unittest.TestCase):
    # Reuse only the synthetic fixture/helpers, never inherit its test methods.
    setUp = fixtures.DNSAuthTests.setUp
    create = fixtures.DNSAuthTests.create
    receipts = fixtures.DNSAuthTests.receipts
    only_receipt = fixtures.DNSAuthTests.only_receipt
    assert_safe_error = fixtures.DNSAuthTests.assert_safe_error

    def legacy(self, path, record):
        previous = dict(record, schema=1)
        del previous["provider"]
        storage.atomic_json(path, previous)
        return previous

    def test_new_receipts_bind_the_provider_without_changing_public_status(self):
        self.cfg["dns_provider"] = "cloudflare"
        self.zones["example.com"]["provider"] = "cloudflare"
        self.create()
        path, receipt = self.only_receipt()
        self.assertEqual(receipt["schema"], 2)
        self.assertEqual(receipt["provider"], "cloudflare")
        self.assertEqual(set(receipt), {"schema", "provider", "identity", "attempt", "owner",
                                        "credentials", "zone", "name", "value", "record", "phase"})
        self.assertEqual(receipt["credentials"], str(self.credential))
        self.cf.reset_mock()
        before = path.read_bytes()
        rows = dnsauth.status(self.cfg)
        self.assertEqual(set(rows[0]), {"id", "name", "phase", "owned", "zone"})
        self.assertEqual(rows[0]["zone"], fixtures.ZONE)
        self.assertNotIn("provider", rows[0])
        self.assertNotIn(str(self.credential), json.dumps(rows))
        self.assertNotIn(fixtures.VALUE, json.dumps(rows))
        self.assertEqual(path.read_bytes(), before)
        self.cf.assert_not_called()

    def test_legacy_created_and_intent_receipts_are_not_rewritten_by_reading(self):
        for phase in ("created", "intent"):
            with self.subTest(phase=phase):
                self.create()
                path, receipt = self.only_receipt()
                if phase == "intent":
                    receipt.update(phase="intent", record=None)
                self.legacy(path, receipt)
                before = path.read_bytes()
                self.cf.reset_mock()
                self.assertEqual(dnsauth.status(self.cfg)[0]["phase"], phase)
                self.assertEqual(path.read_bytes(), before)
                self.cf.assert_not_called()
                dnsauth.cleanup_pending(self.cfg)
                self.assertEqual(self.receipts(), {})
                self.assertEqual(self.api.records, {})

    def test_legacy_borrowed_and_complete_receipts_finish_without_remote_calls(self):
        for phase in ("borrowed", "complete"):
            with self.subTest(phase=phase):
                foreign = self.api.add()
                self.create()
                path, receipt = self.only_receipt()
                receipt["phase"] = phase
                self.legacy(path, receipt)
                self.cf.reset_mock()
                dnsauth.cleanup_pending(self.cfg)
                self.assertEqual(self.receipts(), {})
                self.assertEqual(list(self.api.records.values()), [foreign])
                self.cf.assert_not_called()
                self.api.records.clear()

    def test_mixed_receipts_preserve_each_schema_and_saved_account_binding(self):
        self.create()
        path, receipt = self.only_receipt()
        self.legacy(path, receipt)
        self.create("mail.example.net", fixtures.OTHER_VALUE)
        self.cfg["cloudflare_accounts"].reverse()
        written = []
        original = storage.atomic_json

        def remember(path, value):
            written.append((value["schema"], value.get("provider"), value["phase"]))
            return original(path, value)

        self.cf.reset_mock()
        with patch.object(storage, "atomic_json", side_effect=remember):
            dnsauth.cleanup_pending(self.cfg)
        self.assertCountEqual(written, [(1, None, "complete"), (2, "cloudflare", "complete")])
        self.assertEqual(self.receipts(), {})
        self.assertEqual({(call[0], call[1]) for call in self.api.calls if call[3] == "DELETE"},
                         {(str(self.credential), fixtures.ZONE), (str(self.other_credential), fixtures.OTHER_ZONE)})

    def test_unsupported_missing_or_ill_typed_provider_binding_retains_receipt(self):
        self.create()
        path, original = self.only_receipt()
        variants = [dict(original, provider=value) for value in
                    (None, "", "Cloudflare", "route53", [], False)]
        variants.extend(({key: value for key, value in original.items() if key != "provider"},
                         dict(original, schema=1), dict(original, schema="2")))
        self.cf.reset_mock()
        for receipt in variants:
            with self.subTest(receipt=receipt):
                storage.atomic_json(path, receipt)
                before = path.read_bytes()
                self.assert_safe_error(lambda: dnsauth.status(self.cfg))
                self.assert_safe_error(lambda: dnsauth.cleanup_pending(self.cfg))
                self.assertEqual(path.read_bytes(), before)
        self.cf.assert_not_called()

    def test_unknown_configured_provider_cannot_reinterpret_old_or_new_receipts(self):
        self.create()
        path, original = self.only_receipt()
        for legacy in (False, True):
            if legacy:
                self.legacy(path, original)
            before = path.read_bytes()
            self.cf.reset_mock()
            self.cfg["dns_provider"] = "route53"
            self.assert_safe_error(lambda: dnsauth.status(self.cfg))
            self.assert_safe_error(lambda: dnsauth.cleanup_pending(self.cfg))
            self.assertEqual(path.read_bytes(), before)
            self.cf.assert_not_called()
            self.cfg.pop("dns_provider")

    def test_legacy_provider_is_fixed_even_if_future_factory_returns_another_driver(self):
        self.create()
        path, receipt = self.only_receipt()
        self.legacy(path, receipt)
        driver = dnsproviders.get_provider(self.cfg)
        before = path.read_bytes()
        self.cf.reset_mock()
        with patch.object(type(driver), "provider_id", "future-provider"), \
                patch.object(dnsproviders, "get_provider", return_value=driver):
            self.assert_safe_error(lambda: dnsauth.status(self.cfg))
            self.assert_safe_error(lambda: dnsauth.cleanup_pending(self.cfg))
        self.assertEqual(path.read_bytes(), before)
        self.cf.assert_not_called()

    def test_mismatched_zone_provider_refuses_before_state_or_provider_operations(self):
        for provider in (None, "route53", "Cloudflare", False):
            with self.subTest(provider=provider):
                self.zones["example.com"]["provider"] = provider
                self.assert_safe_error(self.create)
                self.assertFalse(self.state.exists())
        self.cf.assert_not_called()

    def test_every_provider_binding_validates_before_any_remote_cleanup(self):
        self.create()
        self.create(value=fixtures.OTHER_VALUE)
        first, last = sorted(self.receipts())
        self.legacy(first, json.loads(first.read_text()))
        invalid = json.loads(last.read_text())
        invalid["provider"] = "unrelated-provider"
        storage.atomic_json(last, invalid)
        before = {path: path.read_bytes() for path in self.receipts()}
        self.cf.reset_mock()
        self.assert_safe_error(lambda: dnsauth.cleanup_pending(self.cfg))
        self.assertEqual({path: path.read_bytes() for path in self.receipts()}, before)
        self.assertEqual(len(self.api.records), 2)
        self.cf.assert_not_called()

    def test_owned_record_capability_is_required_before_receipts_or_api(self):
        driver = dnsproviders.get_provider(self.cfg)
        with patch.object(type(driver), "require", side_effect=dnsproviders.ProviderError("unsupported capability")):
            self.assert_safe_error(self.create)
        self.assertFalse(self.state.exists())
        self.cf.assert_not_called()
        self.create()
        before = {path: path.read_bytes() for path in self.receipts()}
        self.cf.reset_mock()
        with patch.object(type(driver), "require", side_effect=dnsproviders.ProviderError("unsupported capability")):
            self.assert_safe_error(lambda: dnsauth.cleanup_pending(self.cfg))
        self.cf.assert_not_called()
        self.assertEqual({path: path.read_bytes() for path in self.receipts()}, before)

    def test_status_never_reads_credentials_and_same_path_token_rotation_remains_supported(self):
        self.create()
        path, _ = self.only_receipt()
        before = path.read_bytes()
        self.credential.unlink()
        self.cf.reset_mock()
        with patch.object(core, "token", side_effect=AssertionError("status must not read credentials")):
            self.assertEqual(dnsauth.status(self.cfg)[0]["phase"], "created")
        self.assertEqual(path.read_bytes(), before)
        self.cf.assert_not_called()
        storage.atomic_text(self.credential, "dns_cloudflare_api_token = ROTATED_SYNTHETIC_TOKEN\n")

        def rotated(credentials, endpoint, **kwargs):
            self.assertEqual(core.token(credentials), "ROTATED_SYNTHETIC_TOKEN")
            return self.api(credentials, endpoint, **kwargs)

        with patch.object(core, "cf", side_effect=rotated):
            dnsauth.cleanup_pending(self.cfg)
        self.assertEqual(self.receipts(), {})
        self.assertEqual(self.api.records, {})

    def test_invalid_propagation_settings_do_not_disable_provider_bound_cleanup(self):
        self.create()
        self.cfg.update(dns_provider="cloudflare", dns_propagation={"mode": "invalid"})
        self.assertEqual(len(dnsauth.status(self.cfg)), 1)
        dnsauth.cleanup_pending(self.cfg)
        self.assertEqual(self.receipts(), {})


if __name__ == "__main__":
    unittest.main()
