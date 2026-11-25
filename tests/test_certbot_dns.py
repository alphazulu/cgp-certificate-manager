"""The actual Certbot authenticator boundary blocks ACME on DNS failure."""

import importlib.metadata
import importlib.util
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import warnings

from acme import challenges, messages
import dns.message
import dns.rrset
from cryptography.hazmat.primitives.asymmetric import rsa
import josepy
from certbot import errors
from certbot._internal.auth_handler import AuthHandler
from certbot._internal.plugins.disco import PluginsRegistry

from cgp_cert_manager import __version__, caa, certbot_dns, certbot_runner, core, dnsauth, dnschecks, storage
from test_dnsauth import FakeCloudflare, VALUE, OTHER_VALUE, ZONE, OTHER_ZONE


def challenge(name, value, modern=False):
    result = SimpleNamespace(chall=challenges.DNS01(token=b"synthetic-token-value"),
                             account_key=object(), challb=object(),
                             validation=Mock(return_value=value),
                             response=Mock(return_value=object()))
    if modern:
        result.identifier = SimpleNamespace(value=name)
    else:
        result.domain = name
    return result


class CertbotDNSTests(unittest.TestCase):
    def setUp(self):
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(tmp)
        self.state = self.root / "state"
        self.enterContext(patch.object(core, "STATE", self.state))
        self.credential = self.root / "cloudflare.ini"
        self.other_credential = self.root / "other.ini"
        for path in (self.credential, self.other_credential):
            storage.atomic_text(path, "dns_cloudflare_api_token = PRIVATE_API_TOKEN\n")
        self.cfg = {"schema_version": 2, "communigate": {"url": "http://127.0.0.1:106/CLI/"},
                    "cloudflare_accounts": [{"credentials": str(self.credential)},
                                             {"credentials": str(self.other_credential)}],
                    "dns_propagation": {"mode": "adaptive", "timeout_seconds": 300,
                                        "poll_interval_seconds": 5}}
        self.lock = self.enterContext(storage.operation_lock(self.state))
        self.enterContext(patch.object(certbot_runner, "_CONTEXT", (os.getpid(), self.lock.fileno(), self.cfg)))
        self.zones = {"example.com": {"id": ZONE, "credentials": str(self.credential)},
                      "example.net": {"id": OTHER_ZONE, "credentials": str(self.other_credential)}}
        self.discover = self.enterContext(patch.object(core, "zones", return_value=self.zones))
        self.ready = self.enterContext(patch.object(dnschecks, "require_ready"))
        self.wait = self.enterContext(patch.object(dnschecks, "wait_for_txt"))
        self.api = FakeCloudflare()
        self.cf = self.enterContext(patch.object(core, "cf", side_effect=self.api))
        self.config = SimpleNamespace(domains=["example.com", "*.example.com", "mail.example.net"])
        self.auth = certbot_dns.Authenticator(self.config, "cgp-dns")

    def assert_safe_error(self, callable_):
        with self.assertRaises(errors.PluginError) as raised:
            callable_()
        for value in (VALUE, OTHER_VALUE, "PRIVATE_API_TOKEN", "PRIVATE_RESPONSE"):
            self.assertNotIn(value, str(raised.exception))

    def handler(self, batch):
        acme = Mock()
        handler = AuthHandler(self.auth, acme, Mock(), ["dns-01"])
        order = SimpleNamespace(authorizations=[SimpleNamespace(body=SimpleNamespace(status=messages.STATUS_VALID))])
        self.enterContext(patch.object(handler, "_choose_challenges", return_value=batch))
        poll = self.enterContext(patch.object(handler, "_poll_authorizations"))
        return handler, acme, order, poll

    def test_entrypoint_is_discovered_by_certbot_and_both_metadata_readers(self):
        application = Path(certbot_dns.__file__).resolve().parents[1]
        distributions = [distribution for distribution in importlib.metadata.distributions(path=[str(application)])
                         if distribution.metadata["Name"] == "cgp-certbot-dns"]
        self.assertEqual(len(distributions), 1)
        self.assertEqual(distributions[0].version, __version__)
        entries = [entry for entry in importlib.metadata.entry_points(group="certbot.plugins")
                   if entry.name == "cgp-dns"]
        self.assertEqual(len(entries), 1)
        self.assertIs(entries[0].load(), certbot_dns.Authenticator)
        self.assertIn("dnspython>=2.6.1,<3", importlib.metadata.requires("cgp-certbot-dns"))
        self.assertIs(PluginsRegistry.find_all()["cgp-dns"].plugin_cls, certbot_dns.Authenticator)
        if importlib.util.find_spec("pkg_resources") is not None:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                import pkg_resources
                legacy = [entry for entry in pkg_resources.iter_entry_points("certbot.plugins")
                          if entry.name == "cgp-dns"]
                self.assertEqual(len(legacy), 1)
                self.assertIs(legacy[0].resolve(), certbot_dns.Authenticator)

    def test_plugin_metadata_and_prepare(self):
        add = Mock()
        self.auth.add_parser_arguments(add)
        add.assert_not_called()
        self.assertIn("DNS", self.auth.more_info())
        self.assertEqual(self.auth.get_chall_pref("example.com"), [challenges.DNS01])
        self.auth.prepare()
        self.cf.assert_not_called()

    def test_generic_certbot_without_verified_wrapper_context_is_refused(self):
        with patch.object(certbot_runner, "_CONTEXT", None):
            self.assert_safe_error(self.auth.prepare)
            self.assert_safe_error(lambda: self.auth.perform([challenge("example.com", VALUE)]))
        self.cf.assert_not_called()
        self.ready.assert_not_called()

    def test_fixed_or_invalid_policy_cannot_use_adaptive_authenticator(self):
        for value in ({"mode": "fixed"}, False):
            with self.subTest(value=value), patch.dict(self.cfg, dns_propagation=value):
                self.assert_safe_error(self.auth.prepare)
        self.cf.assert_not_called()

    def test_prepare_recovers_previous_owned_attempt_before_new_post(self):
        previous = dnsauth.Session(self.cfg)
        previous.create("example.com", VALUE, self.zones)
        self.auth.prepare()
        self.assertEqual(self.api.records, {})
        self.assertEqual(dnsauth.status(self.cfg), [])
        self.assertIsNone(self.auth.session)

    def test_prepare_retains_uncertain_attempt_and_blocks_new_issuance(self):
        def uncertain(*args, **kwargs):
            if kwargs.get("method") == "POST":
                raise OSError("PRIVATE_RESPONSE")
            return self.api(*args, **kwargs)
        with patch.object(core, "cf", side_effect=uncertain):
            with self.assertRaises(core.Error):
                dnsauth.Session(self.cfg).create("example.com", VALUE, self.zones)
        self.assert_safe_error(self.auth.prepare)
        self.assertEqual(dnsauth.status(self.cfg)[0]["phase"], "intent")
        self.assertEqual(self.api.records, {})

    def test_complete_batch_poll_precedes_responses_and_uses_both_accounts(self):
        batch = [challenge("example.com", VALUE), challenge("*.example.com", OTHER_VALUE, modern=True),
                 challenge("mail.example.net", VALUE, modern=True)]
        self.auth.prepare()
        def check_batch(challenges_, zones, timeout, interval):
            self.assertEqual(challenges_, [("example.com", VALUE), ("*.example.com", OTHER_VALUE),
                                           ("mail.example.net", VALUE)])
            self.assertIs(zones, self.zones)
            self.assertEqual((timeout, interval), (300, 5))
            self.assertEqual(len(self.api.records), 3)
            for item in batch:
                item.response.assert_not_called()
        self.wait.side_effect = check_batch
        responses = self.auth.perform(batch)
        self.assertEqual(responses, [item.response.return_value for item in batch])
        self.ready.assert_called_once_with({"names": ["example.com", "*.example.com", "mail.example.net"],
                                           "unavailable": [], "cgp_domain": "example.com"}, self.zones, self.cfg)
        self.auth.cleanup(batch)
        self.assertEqual(self.api.records, {})
        self.assertIsNone(self.auth.session)
        self.auth.cleanup(batch)  # The normal repeated cleanup is harmless.

    def test_real_auth_handler_never_answers_acme_after_poll_failure(self):
        batch = [challenge("example.com", VALUE), challenge("*.example.com", OTHER_VALUE)]
        self.auth.prepare()
        handler, acme, order, poll = self.handler(batch)
        self.wait.side_effect = core.Error("PRIVATE_RESPONSE " + VALUE)
        self.assert_safe_error(lambda: handler.handle_authorizations(order, SimpleNamespace(debug_challenges=False)))
        acme.answer_challenge.assert_not_called()
        poll.assert_not_called()
        self.assertEqual(self.api.records, {})
        self.assertEqual(dnsauth.status(self.cfg), [])

    def test_real_auth_handler_answers_once_per_challenge_after_poll_success(self):
        batch = [challenge("example.com", VALUE), challenge("*.example.com", OTHER_VALUE)]
        self.auth.prepare()
        handler, acme, order, poll = self.handler(batch)
        acme.answer_challenge.side_effect = lambda *_: self.assertEqual(self.wait.call_count, 1)
        self.assertEqual(handler.handle_authorizations(order, SimpleNamespace(debug_challenges=False)),
                         order.authorizations)
        self.assertEqual(acme.answer_challenge.call_count, 2)
        poll.assert_called_once()
        self.assertEqual(self.api.records, {})

    def test_real_auth_handler_cleans_owned_records_on_keyboard_interrupt(self):
        batch = [challenge("example.com", VALUE)]
        self.auth.prepare()
        handler, acme, order, poll = self.handler(batch)
        self.wait.side_effect = KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            handler.handle_authorizations(order, SimpleNamespace(debug_challenges=False))
        acme.answer_challenge.assert_not_called()
        poll.assert_not_called()
        self.assertEqual(self.api.records, {})

    def test_failed_preflight_never_creates_dns_receipt_or_record(self):
        self.ready.side_effect = core.Error("PRIVATE_RESPONSE")
        self.assert_safe_error(lambda: self.auth.perform([challenge("example.com", VALUE)]))
        self.cf.assert_not_called()
        self.wait.assert_not_called()
        self.assertFalse((self.state / "dns-challenges").exists())

    def test_invalid_batch_values_fail_before_zone_discovery(self):
        invalid = challenge("example.com", VALUE)
        invalid.chall = challenges.HTTP01(token=b"synthetic-http-token")
        for batch in ([invalid], [challenge("127.0.0.1", VALUE)], [challenge("example.com", "short")]):
            self.assert_safe_error(lambda: self.auth.perform(batch))
        self.discover.assert_not_called()
        self.cf.assert_not_called()

    def test_empty_batch_is_read_only(self):
        self.assertEqual(self.auth.perform([]), [])
        self.discover.assert_not_called()
        self.cf.assert_not_called()

    def test_requested_identifiers_must_be_present_valid_and_match_batch(self):
        for names in (None, "example.com", [], ["127.0.0.1"], ["other.example.com"]):
            with self.subTest(names=names):
                self.config.domains = names
                self.assert_safe_error(lambda: self.auth.perform([challenge("example.com", VALUE)]))
        self.discover.assert_not_called()
        self.cf.assert_not_called()

    def test_real_wildcard_authorization_preserves_requested_caa_policy(self):
        key = josepy.JWKRSA(key=rsa.generate_private_key(public_exponent=65537, key_size=2048))
        body = messages.Authorization(
            identifier=messages.Identifier(typ=messages.IDENTIFIER_FQDN, value="example.com"),
            challenges=(messages.ChallengeBody(chall=challenges.DNS01(token=b"synthetic-wildcard-token"),
                                              status=messages.STATUS_PENDING,
                                              uri="https://acme.invalid/challenge/1"),),
            status=messages.STATUS_PENDING, wildcard=True)
        authorization = messages.AuthorizationResource(body=body, uri="https://acme.invalid/authz/1")
        handler = AuthHandler(self.auth, Mock(), SimpleNamespace(key=key), ["dns-01"])
        batch = handler._challenge_factory(authorization, [0])
        identifier = batch[0].identifier.value if hasattr(batch[0], "identifier") else batch[0].domain
        self.assertEqual(identifier, "example.com")
        def query(name, kind):
            response = dns.message.make_response(dns.message.make_query(name, kind))
            response.answer.append(dns.rrset.from_text("example.com.", 60, "IN", "CAA",
                                                      '0 issue ";"', '0 issuewild "letsencrypt.org"'))
            return response
        def check_policy(domain, zones, cfg):
            for name in domain["names"]:
                if caa.check(name, query)["decision"] != "allowed":
                    raise core.Error("CAA denies issuance")
        self.ready.side_effect = check_policy
        self.config.domains = ["*.EXAMPLE.com.", "*.example.com"]
        self.auth.perform(batch)
        self.assertEqual(self.ready.call_args[0][0]["names"], ["*.example.com"])
        self.auth.cleanup(batch)
        self.config.domains = ["example.com", "*.example.com"]
        self.cf.reset_mock()
        self.assert_safe_error(lambda: self.auth.perform(batch))
        self.cf.assert_not_called()

    def test_overlapping_batch_is_rejected_until_cleanup(self):
        batch = [challenge("example.com", VALUE)]
        self.auth.perform(batch)
        before = len(self.api.calls)
        self.assert_safe_error(lambda: self.auth.perform(batch))
        self.assertEqual(len(self.api.calls), before)
        self.auth.cleanup(batch)
        self.auth.perform(batch)
        self.auth.cleanup(batch)

    def test_cleanup_failure_is_secret_safe_and_can_be_retried(self):
        batch = [challenge("example.com", VALUE)]
        self.auth.perform(batch)
        def fail_delete(method, record_id, data):
            if method == "DELETE":
                raise OSError("PRIVATE_RESPONSE " + VALUE)
        self.api.before = fail_delete
        self.assert_safe_error(lambda: self.auth.cleanup(batch))
        self.assertIsNotNone(self.auth.session)
        self.assertEqual(dnsauth.status(self.cfg)[0]["phase"], "created")
        self.api.before = None
        self.auth.cleanup(batch)
        self.assertEqual(dnsauth.status(self.cfg), [])

    def test_cleanup_requires_same_verified_lock_context(self):
        batch = [challenge("example.com", VALUE)]
        self.auth.perform(batch)
        calls = self.cf.call_count
        with patch.object(certbot_runner, "_CONTEXT", None):
            self.assert_safe_error(lambda: self.auth.cleanup(batch))
        self.assertEqual(self.cf.call_count, calls)
        self.auth.cleanup(batch)
