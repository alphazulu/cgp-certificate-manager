"""Durable notification intent and retries with a wholly fake network worker."""
from copy import deepcopy
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from cgp_cert_manager import monitor_cli, monitor_config as config, monitor_runner as r, monitor_state as s, storage
from test_monitor_state import STAMP, checkpoint, event, record, report


ACCEPTED = {"ok": True, "code": None, "value": {"outcome": "accepted", "code": None}}


class MonitorDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "monitor"
        storage.ensure_private_directory(self.directory)
        self.path = self.directory / r.STATE_FILE
        self.channel = {"id": "mail", "kind": "smtp", "enabled": True,
                        "host": "secret-smtp.example.invalid", "port": 465, "security": "tls",
                        "from": "secret-sender@example.invalid", "to": ["secret-recipient@example.invalid"],
                        "username": "secret-user", "secrets": {"password": "DO-NOT-PERSIST-PASSWORD"}}
        self.cfg = {"identity": "c" * 64, "enabled": True, "max_age_seconds": 900, "notifications": {
            "enabled": True, "repeat_seconds": 60, "retry_seconds": 10,
            "timeout_seconds": 2, "channels": [self.channel]}}
        self.value = checkpoint()
        r._save(self.path, self.value)

    def disk(self):
        return s.validate(config.read_json(self.path, s.MAX_STATE))

    def call_send(self, response=ACCEPTED, now=STAMP + 10, checkpoint_value=None, config_path=None):
        value = self.value if checkpoint_value is None else checkpoint_value
        with patch.object(r, "_time", return_value=now), \
                patch.object(r.monitor_worker, "execute", return_value=response) as worker:
            result = r._send(self.cfg, value, self.path, 19, config_path)
        return result, worker

    def assert_no_private_values(self, value):
        text = json.dumps(value, sort_keys=True)
        for secret in ("DO-NOT-PERSIST-PASSWORD", "DO-NOT-PERSIST-TOKEN", "secret-smtp", "secret-sender",
                       "secret-recipient", "secret-user", "secrets", "password", "token_file"):
            self.assertNotIn(secret, text)

    def test_initial_healthy_and_disabled_channels_do_not_send(self):
        self.value["report"] = report("ok")
        result, worker = self.call_send()
        self.assertEqual(result, [{"id": "mail", "outcome": "suppressed", "code": None, "event_id": None}])
        self.assertEqual(self.value["channels"]["mail"], s.channel())
        worker.assert_not_called()
        for disable_global in (True, False):
            self.value["channels"] = {}
            self.cfg["notifications"]["enabled"] = not disable_global
            self.channel["enabled"] = disable_global
            with patch.object(r, "_time", side_effect=AssertionError("Disabled channel read clock")), \
                    patch.object(r.monitor_worker, "execute") as worker:
                result = r._send(self.cfg, self.value, self.path, 19, None)
            self.assertEqual(result, [{"id": "mail", "outcome": "disabled", "code": None, "event_id": None}])
            self.assertEqual(self.value["channels"], {})
            worker.assert_not_called()

    def test_accepted_delivery_has_durable_intent_before_worker_and_no_persisted_secrets(self):
        before = []

        def execute(kind, payload, timeout, descriptor):
            self.assertEqual((kind, timeout, descriptor), ("notify", 2, 19))
            self.assertEqual(payload["channel"], self.channel)
            saved = self.disk()
            before.append(saved)
            intent = saved["channels"]["mail"]["pending"]
            self.assertEqual(intent["event"], payload["event"])
            self.assertEqual((intent["attempts"], intent["outcome"], intent["code"]),
                             (1, "uncertain", "not_confirmed"))
            self.assert_no_private_values(saved)
            return ACCEPTED

        with patch.object(r, "_time", side_effect=[STAMP + 10, STAMP + 11]), \
                patch.object(r.monitor_worker, "execute", side_effect=execute):
            result = r._send(self.cfg, self.value, self.path, 19, None)
        saved = self.disk()["channels"]["mail"]
        self.assertIsNone(saved["pending"])
        self.assertTrue(saved["incident"])
        self.assertEqual(saved["last"]["kind"], "alert")
        self.assertEqual(saved["last"]["at"], STAMP + 11)
        self.assertEqual(saved["last"]["event_id"], before[0]["channels"]["mail"]["pending"]["event"]["id"])
        self.assertEqual(result, [{"id": "mail", "outcome": "accepted", "code": None,
                                  "event_id": saved["last"]["event_id"]}])
        self.assert_no_private_values(self.disk())
        self.assert_no_private_values(result)

    def test_identical_accepted_condition_is_suppressed_until_reminder_boundary(self):
        first, _ = self.call_send(now=STAMP + 10)
        result, worker = self.call_send(now=STAMP + 69)
        self.assertEqual(result[0]["outcome"], "suppressed")
        worker.assert_not_called()
        second, worker = self.call_send(now=STAMP + 70)
        self.assertEqual(second[0]["outcome"], "accepted")
        self.assertNotEqual(first[0]["event_id"], second[0]["event_id"])
        worker.assert_called_once()

    def test_status_or_failure_code_change_notifies_without_waiting_for_reminder(self):
        for first_report, next_report in ((report("critical"), report("warning", stamp=STAMP + 20)),
                                          (report(code="tls_untrusted"), report(code="tls_hostname_mismatch", stamp=STAMP + 20))):
            self.value = checkpoint(first_report)
            first, _ = self.call_send(now=STAMP + 10)
            self.value["report"] = next_report
            second, worker = self.call_send(now=STAMP + 30)
            self.assertEqual(second[0]["outcome"], "accepted")
            self.assertNotEqual(first[0]["event_id"], second[0]["event_id"])
            worker.assert_called_once()

    def test_verified_recovery_is_sent_once_after_incident(self):
        self.call_send(now=STAMP + 10)
        self.value["report"] = report("ok", stamp=STAMP + 20)
        result, worker = self.call_send(now=STAMP + 30)
        self.assertEqual(result[0]["outcome"], "accepted")
        notification = worker.call_args.args[1]["event"]
        self.assertEqual((notification["kind"], notification["status"]), ("recovery", "ok"))
        saved = self.disk()["channels"]["mail"]
        self.assertFalse(saved["incident"])
        self.assertEqual(saved["last"]["kind"], "recovery")
        result, worker = self.call_send(now=STAMP + 1000)
        self.assertEqual(result[0]["outcome"], "suppressed")
        worker.assert_not_called()

    def test_failed_probe_never_turns_incident_into_recovery(self):
        self.call_send(now=STAMP + 10)
        self.value["report"] = report(code="worker_timeout", stamp=STAMP + 20)
        result, worker = self.call_send(now=STAMP + 30)
        self.assertEqual(result[0]["outcome"], "accepted")
        self.assertEqual(worker.call_args.args[1]["event"]["kind"], "alert")
        self.assertTrue(self.disk()["channels"]["mail"]["incident"])

    def test_durable_intent_failure_prevents_worker_call(self):
        original = self.path.read_bytes()
        with patch.object(r, "_time", return_value=STAMP + 10), \
                patch.object(r, "_save", side_effect=OSError("disk full")), \
                patch.object(r.monitor_worker, "execute") as worker:
            with self.assertRaises(OSError):
                r._send(self.cfg, self.value, self.path, 19, None)
        worker.assert_not_called()
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(self.disk()["channels"], {})

    def test_published_intent_directory_sync_failure_never_starts_worker(self):
        replace = os.replace
        fsync = os.fsync
        published = False

        def publish(*args, **kwargs):
            nonlocal published
            replace(*args, **kwargs)
            published = True

        def fail_directory(fd):
            if published and stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("directory sync failed")
            fsync(fd)

        with patch.object(storage.os, "replace", side_effect=publish), \
                patch.object(storage.os, "fsync", side_effect=fail_directory), \
                patch.object(r, "_time", return_value=STAMP + 10), \
                patch.object(r.monitor_worker, "execute") as worker:
            with self.assertRaises(OSError):
                r._send(self.cfg, self.value, self.path, 19, None)
        worker.assert_not_called()
        saved = self.disk()
        intent = saved["channels"]["mail"]["pending"]
        self.assertEqual((intent["outcome"], intent["code"]), ("uncertain", "not_confirmed"))
        result, worker = self.call_send(checkpoint_value=saved, now=STAMP + 20)
        self.assertEqual(result[0]["event_id"], intent["event"]["id"])
        self.assertEqual(result[0]["outcome"], "accepted")
        worker.assert_called_once()

    def test_crash_or_interrupt_during_delivery_retains_uncertain_durable_intent(self):
        for failure in (KeyboardInterrupt(), OSError("worker crashed")):
            self.value = checkpoint()
            with patch.object(r, "_time", return_value=STAMP + 10), \
                    patch.object(r.monitor_worker, "execute", side_effect=failure):
                with self.assertRaises(type(failure)):
                    r._send(self.cfg, self.value, self.path, 19, None)
            item = self.disk()["channels"]["mail"]["pending"]
            self.assertEqual((item["outcome"], item["code"], item["attempts"], item["retry_at"]),
                             ("uncertain", "not_confirmed", 1, STAMP + 20))

    def test_ack_then_failed_checkpoint_is_retried_from_disk_with_same_event_id(self):
        save = r._save
        calls = 0

        def fail_second(path, value):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("failed acknowledgement checkpoint")
            save(path, value)

        with patch.object(r, "_save", side_effect=fail_second), \
                patch.object(r, "_time", return_value=STAMP + 10), \
                patch.object(r.monitor_worker, "execute", return_value=ACCEPTED) as first:
            with self.assertRaises(OSError):
                r._send(self.cfg, self.value, self.path, 19, None)
        self.assertIsNone(self.value["channels"]["mail"]["pending"])
        durable = self.disk()
        intent = durable["channels"]["mail"]["pending"]
        self.assertEqual(intent["code"], "not_confirmed")
        original_event = first.call_args.args[1]["event"]
        self.assertEqual(intent["event"], original_event)
        result, worker = self.call_send(checkpoint_value=durable, now=STAMP + 19)
        self.assertEqual(result[0]["outcome"], "deferred")
        self.assertEqual(result[0]["event_id"], original_event["id"])
        worker.assert_not_called()
        result, worker = self.call_send(checkpoint_value=durable, now=STAMP + 20)
        self.assertEqual(worker.call_args.args[1]["event"], original_event)
        self.assertEqual(result[0]["event_id"], original_event["id"])
        self.assertEqual(result[0]["outcome"], "accepted")

    def test_rejected_and_uncertain_delivery_keep_retry_intent_and_stable_payload(self):
        for outcome, code in (("rejected", "smtp_rejected"), ("uncertain", "smtp_partial_refusal")):
            self.value = checkpoint()
            response = {"ok": True, "code": None, "value": {"outcome": outcome, "code": code}}
            first, worker = self.call_send(response, now=STAMP + 10)
            notification = deepcopy(worker.call_args.args[1]["event"])
            item = self.disk()["channels"]["mail"]["pending"]
            self.assertEqual((item["outcome"], item["code"], item["attempts"], item["retry_at"]),
                             (outcome, code, 1, STAMP + 20))
            self.value["report"] = report(stamp=STAMP + 12)
            self.value["report"]["endpoints"][0]["fingerprint_sha256"] = "e" * 64
            second, worker = self.call_send(response, now=STAMP + 20)
            self.assertEqual(first[0]["event_id"], second[0]["event_id"])
            self.assertEqual(worker.call_args.args[1]["event"], notification)
            self.assertEqual(self.disk()["channels"]["mail"]["pending"]["attempts"], 2)

    def test_pending_failure_is_superseded_by_new_condition_with_compact_history(self):
        failure = {"ok": False, "value": None, "code": "worker_timeout"}
        first, _ = self.call_send(failure, now=STAMP + 10)
        old = self.disk()["channels"]["mail"]["pending"]
        self.value["report"] = report("warning", stamp=STAMP + 11)

        def execute(_kind, payload, _timeout, _descriptor):
            saved = self.disk()["channels"]["mail"]
            self.assertEqual(saved["pending"]["event"], payload["event"])
            self.assertNotEqual(saved["pending"]["event"]["id"], old["event"]["id"])
            self.assertEqual(saved["superseded"], {"event_id": old["event"]["id"], "kind": "alert",
                "outcome": "uncertain", "code": "worker_timeout", "attempts": 1,
                "observed_at": old["event"]["observed_at"]})
            self.assertNotIn("endpoints", saved["superseded"])
            return ACCEPTED

        with patch.object(r, "_time", return_value=STAMP + 15), \
                patch.object(r.monitor_worker, "execute", side_effect=execute):
            second = r._send(self.cfg, self.value, self.path, 19, None)
        self.assertNotEqual(first[0]["event_id"], second[0]["event_id"])
        self.assertEqual(self.disk()["channels"]["mail"]["superseded"]["event_id"], first[0]["event_id"])

    def test_pending_alert_then_healthy_creates_recovery_even_after_uncertain_send(self):
        self.call_send({"ok": False, "value": None, "code": "worker_timeout"}, now=STAMP + 10)
        self.value["report"] = report("ok", stamp=STAMP + 11)
        result, worker = self.call_send(now=STAMP + 15)
        self.assertEqual(result[0]["outcome"], "accepted")
        self.assertEqual(worker.call_args.args[1]["event"]["kind"], "recovery")
        self.assertFalse(self.disk()["channels"]["mail"]["incident"])

    def test_config_change_before_attempt_blocks_any_send_and_preserves_previous_file(self):
        original = self.path.read_bytes()
        with patch.object(r.config, "load", return_value={"identity": "d" * 64}), \
                patch.object(r, "_time", return_value=STAMP + 10), \
                patch.object(r.monitor_worker, "execute") as worker:
            with self.assertRaisesRegex(r.MonitorError, "configuration_changed"):
                r._send(self.cfg, self.value, self.path, 19, self.root_config_path())
        worker.assert_not_called()
        self.assertEqual(self.path.read_bytes(), original)

    def root_config_path(self):
        return Path(self.temp.name) / "config.json"

    def test_config_is_rechecked_between_channels_before_second_send(self):
        self.cfg["notifications"]["channels"].append({"id": "hook", "kind": "webhook", "enabled": True,
            "url": "https://secret-hook.example.invalid/DO-NOT-PERSIST-TOKEN", "secrets": {"token": "DO-NOT-PERSIST-TOKEN"}})
        with patch.object(r.config, "load", side_effect=[{"identity": self.cfg["identity"]}, {"identity": "d" * 64}]), \
                patch.object(r, "_time", return_value=STAMP + 10), \
                patch.object(r.monitor_worker, "execute", return_value=ACCEPTED) as worker:
            with self.assertRaisesRegex(r.MonitorError, "configuration_changed"):
                r._send(self.cfg, self.value, self.path, 19, self.root_config_path())
        worker.assert_called_once()
        self.assertEqual(worker.call_args.args[1]["channel"]["id"], "mail")
        saved = self.disk()
        self.assertIsNotNone(saved["channels"]["mail"]["last"])
        self.assertNotIn("hook", saved["channels"])
        self.assert_no_private_values(saved)

    def test_clock_regression_before_and_after_submission_fails_closed(self):
        with patch.object(r, "_time", return_value=STAMP + 1), \
                patch.object(r.monitor_worker, "execute") as worker:
            with self.assertRaisesRegex(ValueError, "clock_moved_backwards"):
                r._send(self.cfg, self.value, self.path, 19, None)
        worker.assert_not_called()
        with patch.object(r, "_time", side_effect=[STAMP + 10, STAMP + 9]), \
                patch.object(r.monitor_worker, "execute", return_value=ACCEPTED):
            with self.assertRaisesRegex(ValueError, "clock_moved_backwards"):
                r._send(self.cfg, self.value, self.path, 19, None)
        saved = self.disk()["channels"]["mail"]["pending"]
        self.assertEqual((saved["outcome"], saved["code"]), ("uncertain", "not_confirmed"))

    def test_clock_regression_cannot_be_hidden_by_suppression_or_cooldown(self):
        for defer in (False, True):
            self.value = checkpoint(report("critical" if defer else "ok"))
            self.value["channels"]["mail"] = record(self.value["report"]) if defer else s.channel()
            with patch.object(r, "_time", return_value=STAMP + 1), \
                    patch.object(r, "_save") as saved, \
                    patch.object(r.monitor_worker, "execute") as worker:
                with self.assertRaisesRegex(ValueError, "clock_moved_backwards"):
                    r._send(self.cfg, self.value, self.path, 19, None)
            saved.assert_not_called()
            worker.assert_not_called()

    def test_clock_step_after_run_preflight_cannot_suppress_against_a_future_ack(self):
        self.call_send(now=STAMP + 10)
        before = (self.path.read_bytes(), self.path.stat().st_ino, self.path.stat().st_mtime_ns)
        with patch.object(r, "_time", return_value=STAMP + 11) as clock:
            def backwards(*args, **kwargs):
                clock.return_value = STAMP + 6
                return report(stamp=STAMP + 3)

            with patch.object(r, "observe", side_effect=backwards), \
                    patch.object(r, "_save", wraps=r._save) as save, \
                    patch.object(r, "_notification", wraps=r._notification) as decide, \
                    patch.object(r.monitor_worker, "execute") as worker:
                with self.assertRaisesRegex(ValueError, "clock_moved_backwards"):
                    r.run(self.cfg, self.directory, send=True)
        save.assert_not_called()
        decide.assert_not_called()
        worker.assert_not_called()
        self.assertEqual((self.path.read_bytes(), self.path.stat().st_ino, self.path.stat().st_mtime_ns), before)

    def test_worker_results_are_allowlisted_and_raw_values_never_return(self):
        invalid = [None, [], {}, {"outcome": "accepted", "code": None, "private": "secret"},
                   {"outcome": "accepted", "code": "smtp_rejected"},
                   {"outcome": "rejected", "code": None}, {"outcome": "uncertain", "code": []},
                   {"outcome": "uncertain", "code": "RAW-SECRET-REPLY"},
                   {"outcome": "invalid", "code": "smtp_rejected"}]
        for value in invalid:
            with patch.object(r.monitor_worker, "execute", return_value={"ok": True, "value": value, "code": None}):
                self.assertEqual(r._deliver(self.channel, event(), 2, 19),
                                 {"outcome": "uncertain", "code": "worker_invalid_result"})
        for code in s.WORKER_CODES:
            with patch.object(r.monitor_worker, "execute", return_value={"ok": False, "value": None, "code": code}):
                self.assertEqual(r._deliver(self.channel, event(), 2, 19), {"outcome": "uncertain", "code": code})

    def test_channel_retries_are_independent_and_do_not_resend_accepted_channel(self):
        hook = {"id": "hook", "kind": "webhook", "enabled": True,
                "url": "https://secret-hook.example.invalid/DO-NOT-PERSIST-TOKEN",
                "secrets": {"token": "DO-NOT-PERSIST-TOKEN"}}
        self.cfg["notifications"]["channels"].append(hook)
        with patch.object(r, "_time", return_value=STAMP + 10), \
                patch.object(r.monitor_worker, "execute", side_effect=[ACCEPTED,
                    {"ok": False, "value": None, "code": "worker_timeout"}]):
            first = r._send(self.cfg, self.value, self.path, 19, None)
        self.assertEqual([item["outcome"] for item in first], ["accepted", "uncertain"])
        second, worker = self.call_send(now=STAMP + 20)
        self.assertEqual([item["outcome"] for item in second], ["suppressed", "accepted"])
        worker.assert_called_once()
        self.assertEqual(worker.call_args.args[1]["channel"]["id"], "hook")
        self.assertEqual(first[1]["event_id"], second[1]["event_id"])
        self.assert_no_private_values(self.disk())
        self.assert_no_private_values(second)

    def saved_status(self, now=STAMP + 40):
        with storage.operation_lock(self.directory):
            pass
        before = self.path.read_bytes()
        with patch.object(r, "_time", return_value=now), \
                patch.object(r.monitor_worker, "execute") as worker:
            result = r.status(self.cfg, self.directory)
        worker.assert_not_called()
        self.assertEqual(self.path.read_bytes(), before)
        self.assert_no_private_values(result)
        return result

    def test_saved_status_exposes_failed_recovery_despite_healthy_latest_probe(self):
        self.call_send(now=STAMP + 10)
        self.value["report"] = report("ok", stamp=STAMP + 20)
        failure = {"ok": False, "value": None, "code": "worker_timeout"}
        delivery, _ = self.call_send(failure, now=STAMP + 30)
        result = self.saved_status()
        self.assertEqual(result["status"], "delivery_failed")
        self.assertEqual(result["observation"]["status"], "ok")
        self.assertEqual(result["delivery"], delivery)
        self.assertEqual(self.disk()["channels"]["mail"]["pending"]["event"]["kind"], "recovery")

    def test_run_without_send_preserves_pending_recovery_and_matches_status_cli_exit(self):
        raw = {"schema": 1, "enabled": True, "endpoints": [{"id": "mail", "host": "mail.example.com",
               "port": 443, "server_name": "mail.example.com"}], "notifications": {"enabled": True,
               "channels": [{key: value for key, value in self.channel.items() if key not in ("username", "secrets")}]}}
        config_path = self.root_config_path()
        storage.atomic_json(config_path, raw)
        self.cfg = config.load(config_path)
        self.value["identity"] = self.cfg["identity"]
        self.call_send(now=STAMP + 10)
        self.value["report"] = report("ok", stamp=STAMP + 20)
        self.call_send({"ok": False, "value": None, "code": "worker_timeout"}, now=STAMP + 30)
        saved_channels = deepcopy(self.disk()["channels"])
        fresh_report = report("ok", stamp=STAMP + 40)
        outputs = []
        with patch.object(r, "_time", return_value=STAMP + 40) as clock, \
                patch.object(r, "observe", return_value=fresh_report) as observe, \
                patch.object(r.monitor_worker, "execute") as worker:
            for action in ("--run", "--status"):
                stdout, stderr = io.StringIO(), io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    code = monitor_cli.main([action, "--json", "--config", str(config_path),
                                             "--state-dir", str(self.directory)])
                self.assertEqual(code, 2)
                self.assertEqual(stderr.getvalue(), "")
                result = json.loads(stdout.getvalue())
                self.assertEqual(result["status"], "delivery_failed")
                self.assertEqual(result["observation"], fresh_report)
                self.assert_no_private_values(result)
                outputs.append(result)
                clock.return_value = STAMP + 43
        observe.assert_called_once()
        worker.assert_not_called()
        self.assertEqual(outputs[0]["delivery"], [])
        self.assertEqual(outputs[1]["delivery"][0]["event_id"],
                         saved_channels["mail"]["pending"]["event"]["id"])
        self.assertEqual(self.disk()["channels"], saved_channels)
        self.assertEqual(self.disk()["report"], fresh_report)

    def test_saved_status_distinguishes_accepted_and_suppressed(self):
        delivery, _ = self.call_send(now=STAMP + 10)
        result = self.saved_status()
        self.assertEqual(result["status"], "critical")
        self.assertEqual(result["delivery"], delivery)
        self.value = checkpoint(report("ok"))
        delivery, worker = self.call_send(now=STAMP + 10)
        worker.assert_not_called()
        r._save(self.path, self.value)
        result = self.saved_status()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["delivery"], delivery)

    def test_saved_future_acknowledgement_is_not_reported_as_current(self):
        self.call_send(now=STAMP + 10)
        result = self.saved_status(now=STAMP + 5)
        self.assertEqual(result["status"], "future")
        self.assertEqual(result["delivery"], [])

    def test_configuration_generation_retains_only_one_archive_and_never_retries_old_event(self):
        older = checkpoint()
        older["identity"] = "a" * 64
        older.pop("previous")
        self.value["previous"] = older
        self.value["channels"]["mail"] = record(self.value["report"])
        old_id = self.value["channels"]["mail"]["pending"]["event"]["id"]
        r._save(self.path, self.value)
        self.cfg["identity"] = "d" * 64
        self.channel["host"] = "new-secret-smtp.example.invalid"
        with patch.object(r, "_time", side_effect=[STAMP + 10, STAMP + 20, STAMP + 20]), \
                patch.object(r, "observe", return_value=report(stamp=STAMP + 10)), \
                patch.object(r.monitor_worker, "execute", return_value=ACCEPTED) as worker:
            output = r.run(self.cfg, self.directory, send=True)
        self.assertEqual(worker.call_args.args[1]["channel"]["host"], "new-secret-smtp.example.invalid")
        self.assertNotEqual(worker.call_args.args[1]["event"]["id"], old_id)
        saved = self.disk()
        self.assertEqual(saved["identity"], "d" * 64)
        self.assertEqual(saved["previous"]["identity"], "c" * 64)
        self.assertNotIn("previous", saved["previous"])
        self.assertEqual(saved["previous"]["channels"]["mail"]["pending"]["event"]["id"], old_id)
        self.assert_no_private_values(saved)
        self.assert_no_private_values(output)

    def test_corrupt_unhashable_saved_code_reports_invalid(self):
        corrupt = checkpoint(report(code="tls_expired"))
        corrupt["report"]["endpoints"][0]["code"] = []
        storage.atomic_json(self.path, corrupt)
        with storage.operation_lock(self.directory):
            pass
        self.assertEqual(r.status(self.cfg, self.directory),
                         {"schema": 1, "action": "status", "status": "invalid", "observation": None,
                          "delivery": [], "error": None})
