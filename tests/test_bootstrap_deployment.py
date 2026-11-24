"""Readiness and strict readback remain enforced outside the CLI planner."""
from contextlib import ExitStack
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cgp_cert_manager import core, deployment, recovery
from cgp_cert_manager.transactions import Journal, JournalError


DOMAIN = "example.com"
PREVIOUS = {
    "PrivateSecureKey": "[b2xkLWtleQ==]",
    "SecureCertificate": "[b2xkLWNlcnQ=]",
    "CAChain": "[Y2E=]",
    "CertificateType": "YES",
}
INTENDED = dict(PREVIOUS, SecureCertificate="[bmV3LWNlcnQ=]")
ENDPOINTS = [{"host": "127.0.0.1", "port": 443, "sni": DOMAIN}]


def reply(settings):
    return "{" + "".join(key + "=" + value + ";" for key, value in settings.items()) + "}"


class BootstrapDeploymentTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.state = self.root / "state"
        self.stack.enter_context(patch.object(core, "STATE", self.state))
        self.stack.enter_context(patch.object(core, "LIVE", self.root / "no-lineage"))
        self.stack.enter_context(patch.object(recovery, "server_identity", return_value="server"))
        self.raw = dict(PREVIOUS)
        self.effective = dict(PREVIOUS)
        self.api = self.stack.enter_context(patch.object(core, "cli", side_effect=self.read))
        self.write = self.stack.enter_context(patch.object(core, "update", side_effect=self.update))
        self.validate = self.stack.enter_context(patch.object(core, "validate_backup"))
        self.verify = self.stack.enter_context(patch.object(recovery, "verify_snapshot"))

    def read(self, cfg, command):
        self.assertIn(command, ("GETDOMAINSETTINGS " + DOMAIN,
                                "GETDOMAINEFFECTIVESETTINGS " + DOMAIN))
        return reply(self.raw if command.startswith("GETDOMAINSETTINGS ") else self.effective)

    def update(self, cfg, name, settings):
        self.assertEqual(name, DOMAIN)
        self.raw = dict(settings)
        self.effective = dict(settings)

    def apply(self):
        return deployment.apply({}, DOMAIN, PREVIOUS, INTENDED, ENDPOINTS, ENDPOINTS)

    def test_direct_deploy_refuses_inherited_snapshot_before_local_crypto(self):
        self.raw = {}
        domain = {"cgp_domain": DOMAIN, "cert_name": DOMAIN, "names": [DOMAIN]}
        with patch.object(core, "run") as run:
            with self.assertRaisesRegex(core.Error, "bootstrap-check"):
                core.deploy({}, domain)
        run.assert_not_called()
        self.write.assert_not_called()
        self.verify.assert_not_called()
        self.assertFalse(self.state.exists())

    def test_direct_apply_rechecks_origin_after_callers_effective_snapshot(self):
        self.assertEqual(core.current({}, DOMAIN), PREVIOUS)
        self.raw.pop("PrivateSecureKey")
        with self.assertRaisesRegex(core.Error, "bootstrap-check"):
            self.apply()
        self.write.assert_not_called()
        self.verify.assert_not_called()
        self.assertFalse(self.state.exists())

    def test_direct_apply_refuses_empty_present_fields_without_journal(self):
        self.raw["CAChain"] = self.effective["CAChain"] = "[]"
        with self.assertRaisesRegex(core.Error, "bootstrap-check"):
            self.apply()
        self.write.assert_not_called()
        self.assertFalse(self.state.exists())

    def test_strict_current_requires_entire_top_level_response(self):
        secret = "PRIVATE_SENTINEL"
        invalid = (
            reply(PREVIOUS) + secret,
            "error " + reply(PREVIOUS),
            reply(PREVIOUS)[:-1],
            reply(PREVIOUS)[:-1] + "SecureCertificate=[YQ==];}",
            "{PrivateSecureKey=\"" + secret + "\";}",
        )
        for response in invalid:
            with self.subTest(response=response), patch.object(core, "cli", return_value=response):
                with self.assertRaises(core.Error) as caught:
                    core.current({}, DOMAIN)
                self.assertNotIn(secret, str(caught.exception))
                self.assertNotIn("b2xkLWtleQ", str(caught.exception))
        self.write.assert_not_called()

    def test_nested_or_quoted_fields_do_not_become_effective_snapshot(self):
        response = '{Nested=' + reply(PREVIOUS) + '; Text="SecureCertificate=[YQ==];";}'
        self.api.return_value = response
        self.api.side_effect = None
        self.assertEqual(core.current({}, DOMAIN), {})
        self.assertEqual(core.fields("{CAChain=[];}"), {"CAChain": "[]"})

    def test_malformed_post_write_readback_keeps_pending_evidence(self):
        def accepted_but_invalid_response(cfg, name, settings):
            self.update(cfg, name, settings)
            self.api.side_effect = None
            self.api.return_value = "CGP error " + reply(settings)

        self.write.side_effect = accepted_but_invalid_response
        with self.assertRaisesRegex(JournalError, "CRITICAL"):
            self.apply()
        self.write.assert_called_once()
        self.verify.assert_not_called()
        journal = Journal(self.state / "transactions")
        self.assertEqual(journal.read(DOMAIN)["phase"], "applying")
        self.assertEqual(journal.read(DOMAIN)["previous"], PREVIOUS)
        self.assertEqual(self.effective, INTENDED)

    def test_unset_during_prepare_or_applying_sync_blocks_first_write(self):
        for checkpoint in ("prepared", "applying"):
            with self.subTest(checkpoint=checkpoint), tempfile.TemporaryDirectory() as temporary:
                state = Path(temporary)
                self.raw = dict(PREVIOUS)
                self.effective = dict(PREVIOUS)
                prepare, transition = Journal.prepare, Journal.transition

                def prepared(journal, *args, **kwargs):
                    result = prepare(journal, *args, **kwargs)
                    if checkpoint == "prepared":
                        self.raw.pop("PrivateSecureKey")
                    return result

                def transitioned(journal, domain, phase):
                    result = transition(journal, domain, phase)
                    if phase == checkpoint:
                        self.raw.pop("PrivateSecureKey")
                    return result

                with patch.object(core, "STATE", state), \
                        patch.object(Journal, "prepare", new=prepared), \
                        patch.object(Journal, "transition", new=transitioned), \
                        patch.object(recovery, "recover") as recover, \
                        patch.object(recovery, "restore") as restore:
                    with self.assertRaisesRegex(JournalError, "CRITICAL"):
                        self.apply()
                recover.assert_not_called()
                restore.assert_not_called()
                self.assertEqual(Journal(state / "transactions").read(DOMAIN)["phase"], checkpoint)
                self.assertEqual(self.effective, PREVIOUS)
        self.write.assert_not_called()
        self.verify.assert_not_called()

    def test_unset_after_target_verification_retains_journal_without_restore(self):
        self.verify.side_effect = lambda *_: self.raw.pop("CAChain")
        with patch.object(recovery, "restore") as restore:
            with self.assertRaisesRegex(JournalError, "CRITICAL"):
                self.apply()
        restore.assert_not_called()
        self.write.assert_called_once()
        self.assertEqual(self.effective, INTENDED)
        self.assertEqual(Journal(self.state / "transactions").read(DOMAIN)["phase"], "verifying")

    def test_unset_during_failing_tls_blocks_automatic_effective_only_recovery(self):
        def verify_failed(*_):
            self.raw.pop("PrivateSecureKey")
            raise core.Error("TLS failed")

        self.verify.side_effect = verify_failed
        with patch.object(recovery, "restore") as restore:
            with self.assertRaisesRegex(JournalError, "CRITICAL"):
                self.apply()
        restore.assert_not_called()
        self.write.assert_called_once()
        self.assertEqual(self.effective, INTENDED)
        self.assertEqual(Journal(self.state / "transactions").read(DOMAIN)["phase"], "verifying")

    def test_unchanged_path_reports_provenance_change_without_creating_journal(self):
        self.verify.side_effect = lambda *_: self.raw.pop("PrivateSecureKey")
        with self.assertRaisesRegex(core.Error, "bootstrap-check"):
            deployment.apply({}, DOMAIN, PREVIOUS, PREVIOUS, ENDPOINTS, ENDPOINTS)
        self.write.assert_not_called()
        self.assertFalse(self.state.exists())

    def test_unset_during_restoring_sync_blocks_rollback_write(self):
        transition = Journal.transition

        def restoring(journal, domain, phase):
            result = transition(journal, domain, phase)
            if phase == "restoring":
                self.raw.pop("PrivateSecureKey")
            return result

        self.verify.side_effect = core.Error("TLS failed")
        with patch.object(Journal, "transition", new=restoring):
            with self.assertRaisesRegex(JournalError, "CRITICAL"):
                self.apply()
        self.write.assert_called_once()
        self.assertEqual(self.effective, INTENDED)
        self.assertEqual(Journal(self.state / "transactions").read(DOMAIN)["phase"], "restoring")

    def test_unset_during_rollback_tls_prevents_journal_cleanup(self):
        def verified(settings, endpoints):
            if settings == INTENDED:
                raise core.Error("Target TLS failed")
            self.raw.pop("CAChain")

        self.verify.side_effect = verified
        with self.assertRaisesRegex(JournalError, "CRITICAL"):
            self.apply()
        self.assertEqual(self.write.call_count, 2)
        self.assertEqual(self.effective, PREVIOUS)
        self.assertEqual(Journal(self.state / "transactions").read(DOMAIN)["phase"], "restoring")

    def test_existing_schema_two_recovery_keeps_effective_snapshot_contract(self):
        self.state.mkdir(mode=0o700)
        journal = Journal(self.state / "transactions")
        journal.prepare(DOMAIN, PREVIOUS, INTENDED, ENDPOINTS, "server")
        self.raw = {}  # An older journal does not contain explicit presence bits.
        result = deployment.recover_pending({})
        self.assertEqual(result, [{"domain": DOMAIN, "result": "restored"}])
        self.assertTrue(all(call.args[1] == "GETDOMAINEFFECTIVESETTINGS " + DOMAIN
                            for call in self.api.call_args_list))
        self.write.assert_not_called()
        self.verify.assert_called_once_with(PREVIOUS, ENDPOINTS)
        self.assertIsNone(journal.read(DOMAIN))

    def test_invalid_effective_reply_blocks_legacy_recovery_without_writes(self):
        self.state.mkdir(mode=0o700)
        journal = Journal(self.state / "transactions")
        journal.prepare(DOMAIN, PREVIOUS, INTENDED, ENDPOINTS, "server")
        self.api.side_effect = None
        self.api.return_value = "{Wrapped=" + reply(INTENDED) + ";}"
        with self.assertRaises(core.Error):
            deployment.recover_pending({})
        self.write.assert_not_called()
        self.verify.assert_not_called()
        self.assertEqual(journal.read(DOMAIN)["phase"], "prepared")


if __name__ == "__main__":
    unittest.main()
