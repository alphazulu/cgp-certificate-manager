#!/usr/bin/env python3
"""Emit offline promtool cases for the exact shipped Grafana expressions.

Usage from the repository root:
    python tests/integration/check_monitoring_assets.py > /tmp/cgp-dashboard.yml
    promtool test rules /tmp/cgp-dashboard.yml

JSON is a YAML subset accepted by promtool. This helper only substitutes the
three known Grafana regex variables and removes the documented query_result
wrapper around variable queries. Prometheus itself parses and evaluates PromQL;
there is no home-grown PromQL parser and no running monitoring service.
"""
import json
from pathlib import Path
import sys


DASHBOARD = Path(__file__).resolve().parents[2] / "monitoring/grafana/cgp-manager.json"
SELECTION = {"job": ".*", "instance": ".*", "domain": ".*"}
EVAL_SECONDS = 3600


def queries(dashboard, selection=None):
    """Return stable expression IDs, preserving panel PromQL verbatim."""
    selected = dict(SELECTION if selection is None else selection)
    result = {}
    for panel in dashboard["panels"]:
        for target in panel.get("targets", []):
            result["panel_%s_%s" % (panel["id"], target["refId"])] = target["expr"]
    for variable in dashboard["templating"]["list"]:
        if variable["type"] == "query":
            wrapped = variable["query"]["query"]
            assert wrapped.startswith("query_result(") and wrapped.endswith(")")
            result["variable_" + variable["name"]] = wrapped[len("query_result("):-1]
    for key, expression in result.items():
        for name, value in selected.items():
            expression = expression.replace("${" + name + ":regex}", value)
        assert "$" not in expression, "Unsubstituted Grafana variable: " + key
        result[key] = expression
    return result


def labels(metric="", **values):
    return metric + "{" + ",".join(name + "=" + json.dumps(value)
                                     for name, value in sorted(values.items())) + "}"


def sample(value, metric="", **values):
    return {"labels": labels(metric, **values), "value": value}


def input_series(metric, value, **values):
    # One sample per minute through the 1h evaluation time, with no extrapolation.
    return {"series": labels(metric, **values), "values": str(value) + "+0x60"}


def host(instance="node-a:9100", *, job="node", up=1, age=60, complete=1,
         leaf="ok", enabled=1, domain="example.test", opted_in="true",
         expiry_days=7, failures=2, success=3000, retry=4200):
    target = {"cgp_manager": opted_in, "job": job, "instance": instance}
    scoped = dict(target, domain=domain)
    rows = [input_series("up", up, **target),
            input_series("cgp_manager_collection_success", complete, **target),
            input_series("cgp_manager_collection_timestamp_seconds", EVAL_SECONDS - age, **target),
            input_series("cgp_manager_source_status", 1, **target, source="config", status="ok"),
            input_series("cgp_manager_pending_artifacts", 0, **target, kind="transactions"),
            input_series("cgp_manager_domain_info", 1, **scoped, cert_name=domain),
            input_series("cgp_manager_domain_enabled", enabled, **scoped),
            input_series("cgp_manager_local_certificate_status", 1, **scoped, status=leaf)]
    if leaf == "ok":
        rows.append(input_series("cgp_manager_local_certificate_not_after_timestamp_seconds",
                                 EVAL_SECONDS + expiry_days * 86400, **scoped))
    for metric, value in (("recorded_failures", failures),
                          ("last_success_timestamp_seconds", success),
                          ("retry_timestamp_seconds", retry)):
        if value is not None:
            rows.append(input_series("cgp_manager_" + metric, value, **scoped))
    return rows, target, scoped


def expected(target, scoped, *, up=1, age=60, complete=1,
             leaf=0, ready=True, enabled=True, failures=2, success=3000, retry=4200):
    """Independent expected observations for the fixed synthetic host fixture."""
    result = {
        "panel_2_A": [sample(up, "up", **target)],
        "variable_job": [sample(1, job=target["job"])],
        "variable_instance": [sample(1, instance=target["instance"])],
        "variable_domain": [sample(1, domain=scoped["domain"])],
    }
    if up:
        result["panel_3_A"] = [sample(complete, "cgp_manager_collection_success", **target)]
        result["panel_4_A"] = [sample(age, **target)]
    if up and 0 <= age <= 900:
        result["panel_5_A"] = [sample(0, **target, source="config")]
        if enabled:
            result["panel_7_A"] = [sample(leaf, **scoped)]
    if ready:
        result["panel_6_A"] = [sample(0, "cgp_manager_pending_artifacts", **target, kind="transactions")]
        if enabled:
            if leaf == 0:
                result["panel_8_A"] = [sample(7, **scoped)]
            if failures is not None:
                result["panel_9_A"] = [sample(failures, "cgp_manager_recorded_failures", **scoped)]
            if success is not None:
                result["panel_10_A"] = [sample(EVAL_SECONDS - success, **scoped)]
            if retry is not None:
                result["panel_11_A"] = [sample(retry * 1000, **scoped)]
    return result


def case(name, expressions, rows, observations):
    return {"name": name, "interval": "1m", "input_series": rows,
            "promql_expr_test": [{"expr": expression, "eval_time": "1h",
                                  "exp_samples": observations.get(key, [])}
                                 for key, expression in expressions.items()]}


def fixture(dashboard):
    expressions = queries(dashboard)
    cases = [case("no series stays unknown in every panel and variable", expressions, [], {})]
    base = {"cgp_manager": "true", "job": "node", "instance": "node-a:9100"}
    cases.append(case("expected exporter without manager metrics remains selectable", expressions,
                      [input_series("up", 1, **base)], {
                          "panel_2_A": [sample(1, "up", **base)],
                          "variable_job": [sample(1, job="node")],
                          "variable_instance": [sample(1, instance="node-a:9100")]}))

    for name, options, wanted in [
        ("fresh complete local observations", {}, {}),
        ("exporter down hides stale operational observations", {"up": 0}, {"up": 0, "ready": False}),
        ("future timestamp is visible but operational observations are unknown", {"age": -1}, {"age": -1, "ready": False}),
        ("901 second snapshot is stale", {"age": 901}, {"age": 901, "ready": False}),
        ("900 second boundary remains eligible", {"age": 900}, {"age": 900}),
        ("explicit leaf read error remains visible on incomplete collection", {"complete": 0, "leaf": "error"}, {"complete": 0, "leaf": 2, "ready": False}),
        ("missing local leaf is distinct from an expiry of zero", {"leaf": "missing"}, {"leaf": 1}),
        ("disabled domain retains target diagnostics but no domain health", {"enabled": 0}, {"enabled": False}),
        ("missing saved fields stay unknown despite a complete snapshot", {"failures": None, "success": None, "retry": None}, {"failures": None, "success": None, "retry": None}),
        ("known zero failures and cleared retry are explicit values", {"failures": 0, "retry": 0}, {"failures": 0, "retry": 0}),
    ]:
        rows, target, scoped = host(**options)
        cases.append(case(name, expressions, rows, expected(target, scoped, **wanted)))

    rows_a, target_a, scoped_a = host()
    rows_b, target_b, scoped_b = host("node-b:9100", age=901)
    rows_other, _, _ = host("unrelated:9100", opted_in="false")
    observations = expected(target_a, scoped_a)
    for key, samples in expected(target_b, scoped_b, age=901, ready=False).items():
        observations.setdefault(key, [])
        for value in samples:
            if value not in observations[key]:
                observations[key].append(value)
    cases.append(case("cross-host freshness joins and opt-in target isolation", expressions,
                      rows_a + rows_b + rows_other, observations))
    selected = queries(dashboard, {"job": "node", "instance": "node-a:9100", "domain": "example[.]test"})
    selected_expected = expected(target_a, scoped_a)
    # The instance variable intentionally lists all opted-in instances in the job.
    selected_expected["variable_instance"].append(sample(1, instance="node-b:9100"))
    cases.append(case("job instance domain selection applies to data queries", selected,
                      rows_a + rows_b + rows_other, selected_expected))

    rows_primary, target_primary, scoped_primary = host("shared:9100", job="primary")
    rows_secondary, target_secondary, scoped_secondary = host("shared:9100", job="secondary", age=901)
    shared_instance = expected(target_primary, scoped_primary)
    for key, samples in expected(target_secondary, scoped_secondary, age=901, ready=False).items():
        shared_instance.setdefault(key, [])
        for value in samples:
            if value not in shared_instance[key]:
                shared_instance[key].append(value)
    cases.append(case("same instance in different jobs cannot share freshness", expressions,
                      rows_primary + rows_secondary, shared_instance))

    rows, target, scoped = host(domain="certificate.example.test")
    rows = [row for row in rows if not row["series"].startswith("cgp_manager_domain_enabled{")]
    other_domain = "enabled.example.test"
    rows.extend((input_series("cgp_manager_domain_enabled", 1, **target, domain=other_domain),
                 input_series("cgp_manager_domain_info", 1, **target,
                              domain=other_domain, cert_name=other_domain)))
    mismatched_domain = expected(target, scoped, enabled=False)
    mismatched_domain["variable_domain"].append(sample(1, domain=other_domain))
    cases.append(case("different enabled domain cannot authorize certificate observations on the same host",
                      expressions, rows, mismatched_domain))

    boundary_rows = []
    boundary_values = []
    for index, (seconds, days) in enumerate(((7 * 86400, 7), (7 * 86400 + 1, 8),
                                            (21 * 86400, 21), (21 * 86400 + 1, 22),
                                            (0, 0), (-86400, -1))):
        domain = "boundary-%s.example.test" % index
        rows, target, scoped = host(domain=domain, expiry_days=seconds / 86400)
        # Target-wide series are shared by the six domain observations.
        boundary_rows.extend(row for row in rows if 'domain=' in row["series"] or index == 0)
        boundary_values.append(sample(days, **scoped))
    cases.append(case("local expiry display preserves 7 and 21 day boundaries and expired values",
                      {"panel_8_A": expressions["panel_8_A"]}, boundary_rows,
                      {"panel_8_A": boundary_values}))
    return {"rule_files": [], "evaluation_interval": "1m", "tests": cases}


if __name__ == "__main__":
    json.dump(fixture(json.loads(DASHBOARD.read_text())), sys.stdout, indent=2)
    sys.stdout.write("\n")
