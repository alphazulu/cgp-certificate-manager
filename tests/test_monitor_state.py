"""Strict public evidence and bounded notification-checkpoint validation."""
from copy import deepcopy
import unittest

from cgp_cert_manager import core, monitor_state as s


STAMP = 1700000000.0


def report(status="critical", code=None, stamp=STAMP):
    checked = stamp + 1
    days = {"ok": 90, "warning": 14, "critical": 3}[status]
    row = {"id": "mail", "host": "mail.example.com", "port": 443,
           "server_name": "mail.example.com", "protocol": "tls", "status": status,
           "code": code, "verified": code is None, "checked_at": checked,
           "not_after": checked + days * 86400, "fingerprint_sha256": "a" * 64,
           "peer_address": "192.0.2.1", "tls_version": "TLSv1.3", "days_remaining": days}
    if code is not None:
        row.update(status="critical", not_after=None, fingerprint_sha256=None,
                   peer_address=None, tls_version=None, days_remaining=None)
    return {"schema": 1, "generated_at": stamp, "completed_at": stamp + 2,
            "warning_days": 21, "critical_days": 7,
            "complete": code not in s.WORKER_CODES, "status": row["status"], "endpoints": [row]}


def event(observation=None):
    observation = report() if observation is None else observation
    return {"schema": 1, "id": "b" * 32,
            "kind": "recovery" if observation["status"] == "ok" else "alert",
            "observed_at": observation["completed_at"], "status": observation["status"],
            "endpoints": deepcopy(observation["endpoints"])}


def pending(observation=None):
    notification = event(observation)
    return {"key": s.event_key(notification), "event": notification, "attempts": 1,
            "retry_at": notification["observed_at"] + 30,
            "outcome": "uncertain", "code": "not_confirmed"}


def checkpoint(observation=None):
    observation = report() if observation is None else observation
    return {"schema": 1, "identity": "c" * 64, "report": observation,
            "channels": {}, "previous": None}


def record(observation=None):
    return {"incident": True, "last": None, "pending": pending(observation), "superseded": None}


class MonitorStateTests(unittest.TestCase):
    def invalid_report(self, value):
        with self.assertRaises((ValueError, TypeError, core.Error)):
            s.report(value)

    def invalid_state(self, value):
        with self.assertRaises((ValueError, TypeError, core.Error)):
            s.validate(value)

    def test_threshold_boundaries_and_overall_are_explicit(self):
        for days, expected in ((-1, "critical"), (0, "critical"), (7, "critical"),
                               (7.00001, "warning"), (21, "warning"), (21.00001, "ok")):
            self.assertEqual(s.level(days, 21, 7), expected)
        self.assertEqual(s.overall([{"status": "ok"}, {"status": "warning"}]), "warning")
        self.assertEqual(s.overall([{"status": "critical"}, {"status": "ok"}]), "critical")

    def test_verified_and_failed_reports_preserve_meanings(self):
        for status in ("ok", "warning", "critical"):
            value = report(status)
            self.assertIs(s.report(value), value)
        for code in ("tls_expired", "worker_timeout"):
            value = report(code=code)
            self.assertIs(s.report(value), value)
            value["endpoints"][0]["peer_address"] = "2001:db8::1"
            self.assertIs(s.report(value), value)

    def test_report_schema_and_temporal_consistency(self):
        invalid = []
        for key, value in (("schema", True), ("schema", 2), ("generated_at", -1),
                           ("generated_at", float("inf")), ("completed_at", STAMP - 1),
                           ("warning_days", 0), ("warning_days", 1.5), ("critical_days", 21),
                           ("complete", False), ("complete", 1), ("status", "ok")):
            candidate = report()
            candidate[key] = value
            invalid.append(candidate)
        candidate = report()
        candidate["private"] = "secret"
        invalid.append(candidate)
        candidate = report()
        del candidate["schema"]
        invalid.append(candidate)
        for checked in (STAMP - 1, STAMP + 3):
            candidate = report()
            row = candidate["endpoints"][0]
            row["checked_at"] = checked
            row["not_after"] = checked + row["days_remaining"] * 86400
            invalid.append(candidate)
        for candidate in invalid:
            self.invalid_report(candidate)
        value = report(code="worker_timeout")
        value["complete"] = True
        self.invalid_report(value)

    def test_endpoint_identity_shape_count_and_duplicates(self):
        for endpoints in (None, [], [{}] * 17, [report()["endpoints"][0]] * 2):
            self.invalid_report({**report(), "endpoints": endpoints})
        for key, value in (("id", "Uppercase"), ("id", None), ("host", "bad host"),
                           ("port", True), ("protocol", "unknown"), ("verified", 1),
                           ("status", "unknown"), ("peer_address", "not-an-ip"),
                           ("peer_address", 1), ("peer_address", "x" * 65)):
            candidate = report()
            candidate["endpoints"][0][key] = value
            self.invalid_report(candidate)
        for extra in (True, False):
            candidate = report()
            if extra:
                candidate["endpoints"][0]["raw_response"] = "secret"
            else:
                del candidate["endpoints"][0]["host"]
            self.invalid_report(candidate)

    def test_verified_evidence_cannot_claim_unknown_or_inconsistent_values(self):
        for key, value in (("not_after", None), ("days_remaining", float("nan")),
                           ("days_remaining", 2), ("fingerprint_sha256", "f" * 63),
                           ("fingerprint_sha256", "A" * 64), ("fingerprint_sha256", 1),
                           ("code", "tls_expired"), ("peer_address", None),
                           ("tls_version", "TLSv1.1"), ("status", "warning")):
            candidate = report()
            candidate["endpoints"][0][key] = value
            self.invalid_report(candidate)

    def test_failed_evidence_never_carries_unverified_certificate_claims(self):
        for key, value in (("code", None), ("code", "private-server-reply"), ("code", []),
                           ("status", "warning"), ("not_after", STAMP), ("days_remaining", 3),
                           ("fingerprint_sha256", "a" * 64), ("tls_version", "TLSv1.3")):
            candidate = report(code="tls_expired")
            candidate["endpoints"][0][key] = value
            self.invalid_report(candidate)

    def test_unhashable_reason_fields_are_schema_errors(self):
        value = checkpoint(report(code="tls_expired"))
        value["report"]["endpoints"][0]["code"] = []
        with self.assertRaisesRegex(ValueError, "invalid_configuration"):
            s.validate(value)
        for location in ("pending", "superseded"):
            value = checkpoint()
            item = record(value["report"])
            value["channels"]["mail"] = item
            if location == "superseded":
                item[location] = {"event_id": "e" * 32, "kind": "alert", "attempts": 1,
                                  "outcome": "uncertain", "code": None, "observed_at": STAMP}
            item[location]["code"] = {}
            with self.assertRaisesRegex(ValueError, "invalid_configuration"):
                s.validate(value)

    def test_event_key_tracks_conditions_not_time_or_certificate_rotation(self):
        original = event()
        changed = deepcopy(original)
        changed["observed_at"] += 1
        changed["id"] = "d" * 32
        changed["endpoints"][0]["checked_at"] += 1
        changed["endpoints"][0]["fingerprint_sha256"] = "e" * 64
        self.assertEqual(s.event_key(original), s.event_key(changed))
        changed["endpoints"][0]["status"] = "warning"
        self.assertNotEqual(s.event_key(original), s.event_key(changed))
        changed = deepcopy(original)
        changed["endpoints"][0]["code"] = "tls_untrusted"
        self.assertNotEqual(s.event_key(original), s.event_key(changed))

    def test_event_schema_kind_and_observation_order(self):
        observation = report()
        s.event(event(observation), observation)
        s.event(event(report("ok")), report("ok"))
        for key, value in (("schema", True), ("schema", 2), ("id", "x" * 32),
                           ("kind", "unknown"), ("kind", "recovery"),
                           ("observed_at", STAMP), ("status", "ok")):
            candidate = event(observation)
            candidate[key] = value
            with self.assertRaises(ValueError):
                s.event(candidate, observation)

    def test_future_pending_and_superseded_event_dates_are_corruption(self):
        for location in ("pending", "superseded"):
            value = checkpoint()
            item = record(value["report"])
            value["channels"]["mail"] = item
            if location == "pending":
                item["pending"]["event"]["observed_at"] = STAMP + 100000
                item["pending"]["retry_at"] = STAMP + 100001
            else:
                item["superseded"] = {"event_id": "e" * 32, "kind": "alert", "attempts": 1,
                                      "outcome": "uncertain", "code": "worker_timeout",
                                      "observed_at": STAMP + 100000}
            self.invalid_state(value)

    def test_fresh_state_and_bounded_previous_generation(self):
        value = s.fresh("c" * 64)
        self.assertEqual(value, {"schema": 1, "identity": "c" * 64, "report": None,
                                 "channels": {}, "previous": None})
        self.assertIs(s.validate(value), value)
        self.assertEqual(s.channel(), {"incident": False, "last": None, "pending": None, "superseded": None})
        old = checkpoint()
        old.pop("previous")
        value = s.fresh("d" * 64, old)
        self.assertIs(s.validate(value), value)
        value["previous"]["previous"] = None
        self.invalid_state(value)

    def test_state_shape_identity_channel_limit_and_no_secret_fields(self):
        for key, item in (("schema", 2), ("schema", True), ("identity", "g" * 64),
                          ("identity", 1), ("channels", []),
                          ("channels", {str(i): s.channel() for i in range(5)})):
            value = checkpoint()
            value[key] = item
            self.invalid_state(value)
        value = s.fresh("c" * 64)
        value["channels"]["mail"] = s.channel()
        self.invalid_state(value)
        value = checkpoint()
        value["channels"]["BAD"] = s.channel()
        self.invalid_state(value)
        for location in ("root", "channel"):
            value = checkpoint()
            value["channels"]["mail"] = s.channel()
            (value if location == "root" else value["channels"]["mail"])["password"] = "secret"
            self.invalid_state(value)

    def test_channel_pending_last_and_superseded_records_validate(self):
        value = checkpoint()
        item = record(value["report"])
        item["last"] = {"key": "f" * 64, "at": STAMP - 5, "event_id": "d" * 32, "kind": "alert"}
        item["superseded"] = {"event_id": "e" * 32, "kind": "alert", "attempts": 2,
                              "outcome": "uncertain", "code": "worker_timeout", "observed_at": STAMP - 10}
        value["channels"]["mail"] = item
        self.assertIs(s.validate(value), value)
        item["pending"]["outcome"] = "rejected"
        item["pending"]["code"] = "smtp_rejected"
        self.assertIs(s.validate(value), value)
        item["pending"] = None
        self.assertIs(s.validate(value), value)
        item["last"]["kind"] = "recovery"
        item["incident"] = False
        self.assertIs(s.validate(value), value)

    def test_pending_key_attempt_retry_and_outcome_must_be_consistent(self):
        for key, item in (("key", "f" * 64), ("key", "bad"), ("attempts", 0),
                          ("attempts", True), ("attempts", 2**31), ("retry_at", STAMP),
                          ("outcome", "accepted"), ("outcome", "unknown"),
                          ("code", None), ("code", "private-server-reply")):
            value = checkpoint()
            value["channels"]["mail"] = record(value["report"])
            value["channels"]["mail"]["pending"][key] = item
            self.invalid_state(value)
        for incident in (False, 1):
            value = checkpoint()
            value["channels"]["mail"] = {**record(value["report"]), "incident": incident}
            self.invalid_state(value)
        value = checkpoint()
        value["channels"]["mail"] = {**s.channel(), "incident": True}
        self.invalid_state(value)

    def test_last_and_superseded_enum_bounds(self):
        baseline = checkpoint()
        item = s.channel()
        item["last"] = {"key": "f" * 64, "at": STAMP, "event_id": "d" * 32, "kind": "recovery"}
        item["superseded"] = {"event_id": "e" * 32, "kind": "alert", "attempts": 1,
                              "outcome": "uncertain", "code": "worker_timeout", "observed_at": STAMP}
        baseline["channels"]["mail"] = item
        for name, key, entry in (("last", "kind", "unknown"), ("last", "at", -1),
                                 ("last", "event_id", "x" * 32), ("superseded", "kind", "unknown"),
                                 ("superseded", "outcome", "accepted"), ("superseded", "code", None),
                                 ("superseded", "code", "private-server-reply"),
                                 ("superseded", "attempts", 0), ("superseded", "observed_at", -1)):
            value = deepcopy(baseline)
            value["channels"]["mail"][name][key] = entry
            self.invalid_state(value)
