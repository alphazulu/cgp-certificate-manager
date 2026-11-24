"""Offline Zabbix 7.0 export contracts and execution of the exact ES5 bodies.

Node is mandatory. These tests do not claim a real Zabbix import or execute any
HTTP request. V8 detailed coverage is required for all three embedded scripts.
"""
import copy
import json
import math
from pathlib import Path
import re
import shutil
import subprocess
import unittest

from cgp_cert_manager import monitoring_formats as formats


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "monitoring" / "zabbix"
NOW = 1700001000
PREFIX = "cgp_manager_"
TEMPLATE_NAME = "CGP Certificate Manager by HTTP"


def snapshot():
    return {
        "schema": 1, "generated_at": NOW - 10, "complete": True,
        "sources": {name: {"status": "ok"} for name in formats.SOURCES},
        "pending": {"transactions": 2, "resolutions": 1, "dns_challenges": 0},
        "domains": [
            {"domain": "z.example.com", "cert_name": "lineage-z", "enabled": False,
             "in_inventory": False, "local_certificate": {"status": "missing"},
             "last_success": None, "failures": None, "retry_at": None},
            {"domain": "a.example.com", "cert_name": "lineage-a", "enabled": True,
             "in_inventory": True,
             "local_certificate": {"status": "ok", "not_after": NOW + 86400 * 30},
             "last_success": NOW - 3600.5, "failures": 0, "retry_at": 0},
        ],
    }


def native_rows(data):
    """Test adapter for documented native PROMETHEUS_TO_JSON objects.

    Input is our real formatter, not a second hand-maintained metric fixture.
    Zabbix's native Prometheus parser itself remains a deployment acceptance check.
    """
    rows = []
    for line in formats.prometheus(data).splitlines():
        if line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z_:][A-Za-z0-9_:]*)(?:\{(.*)\})? ([^ ]+)", line)
        name, labels, value = match.groups()
        row = {"name": name, "value": value, "type": "gauge", "line_raw": line}
        if labels is not None:
            row["labels"] = {
                label: json.loads(quoted)
                for label, quoted in re.findall(r'([a-z_]+)=("(?:[^"\\]|\\.)*")', labels)
            }
        rows.append(row)
    return rows


def row_for(rows, suffix, **labels):
    return next(row for row in rows if row["name"] == PREFIX + suffix
                and row.get("labels", {}) == labels)


def remove(rows, suffix, **labels):
    rows.remove(row_for(rows, suffix, **labels))


def normalized(data):
    """Independent expected projection; absent optional data stays absent."""
    result = {
        "collection_success": int(data["complete"]), "generated_at": data["generated_at"],
        "sources": {key: formats.SOURCE_STATUSES.index(value["status"])
                    for key, value in data["sources"].items()},
        "pending": {key: value for key, value in data["pending"].items() if value is not None},
        "domains": {},
    }
    for source in data["domains"]:
        row = {"cert_name": source["cert_name"], "observed_at": data["generated_at"],
               "enabled": int(source["enabled"]),
               "certificate_status": formats.CERTIFICATE_STATUSES.index(source["local_certificate"]["status"])}
        for source_key, output in (("last_success", "last_success"), ("failures", "failures"),
                                   ("retry_at", "retry_at"), ("in_inventory", "in_inventory")):
            if source[source_key] is not None:
                row[output] = int(source[source_key]) if source_key == "in_inventory" else source[source_key]
        if source["local_certificate"]["status"] == "ok":
            row["not_after"] = source["local_certificate"]["not_after"]
        row["failures_known"] = int(source["failures"] is not None)
        result["domains"][source["domain"]] = row
    return result


NODE_HARNESS = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const inspector = require('node:inspector');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const session = new inspector.Session();
session.connect();
function post(method, args) {
    return new Promise((resolve, reject) => session.post(method, args || {}, (error, result) => {
        if (error) reject(error); else resolve(result);
    }));
}
(async () => {
    await post('Profiler.enable');
    await post('Profiler.startPreciseCoverage', {callCount: true, detailed: true});
    const compiled = new Map();
    function run(script, value, scenario) {
        const age = scenario.maxAge === undefined ? '900' : scenario.maxAge;
        const skew = scenario.futureSkew === undefined ? '0' : scenario.futureSkew;
        const key = script + ':' + age + ':' + skew;
        if (!compiled.has(key)) {
            let body = input.scripts[script];
            body = body.replace('{$CGP.MAX.AGE.SECONDS}', age).replace('{$CGP.FUTURE.SKEW.SECONDS}', skew);
            const context = vm.createContext({clock: 0});
            context.Date = {now: () => context.clock * 1000};
            const fn = new vm.Script('(function(value) {\n' + body + '\n})',
                {filename: 'cgp-zabbix/' + script + '.js'}).runInContext(context);
            compiled.set(key, {fn, context, body});
        }
        const executable = compiled.get(key);
        executable.context.clock = scenario.now === undefined ? input.now : scenario.now;
        return executable.fn(value);
    }
    const results = input.cases.map(scenario => {
        try {
            let value = scenario.value;
            for (const script of scenario.steps) value = run(script, value, scenario);
            return {value: JSON.parse(value)};
        } catch (error) {
            return {error: String(error)};
        }
    });
    const report = await post('Profiler.takePreciseCoverage');
    await post('Profiler.stopPreciseCoverage');
    session.disconnect();
    const coverage = report.result.filter(script => script.url.startsWith('cgp-zabbix/'));
    process.stdout.write(JSON.stringify({results, coverage}));
})().catch(error => { process.stderr.write(String(error)); process.exitCode = 1; });
"""


class MonitoringZabbixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.export = json.loads((ASSETS / "cgp-manager.json").read_text())
        cls.template = cls.export["zabbix_export"]["templates"][0]
        cls.items = {item["key"]: item for item in cls.template["items"]}
        cls.discovery = cls.template["discovery_rules"][0]
        cls.prototypes = {item["key"]: item for item in cls.discovery["item_prototypes"]}
        cls.macros = {row["macro"]: row["value"] for row in cls.template["macros"]}

    def test_versioned_export_schema_identifiers_and_references(self):
        exported = self.export["zabbix_export"]
        self.assertEqual(set(exported), {"version", "template_groups", "templates"})
        self.assertEqual(exported["version"], "7.0")
        self.assertEqual(self.template["template"], TEMPLATE_NAME)
        self.assertEqual(self.template["name"], TEMPLATE_NAME)
        self.assertEqual(self.template["groups"], [{"name": "Templates/Applications"}])
        self.assertEqual(exported["template_groups"][0]["name"], "Templates/Applications")
        objects = exported["template_groups"] + [self.template, self.discovery]
        objects += list(self.items.values()) + list(self.prototypes.values())
        objects += self.template["valuemaps"] + self.discovery["trigger_prototypes"]
        objects += [trigger for item in self.items.values() for trigger in item.get("triggers", [])]
        identifiers = [obj["uuid"] for obj in objects]
        self.assertEqual(len(identifiers), len(set(identifiers)))
        for identifier in identifiers:
            self.assertRegex(identifier, r"^[a-f0-9]{32}$")
        keys = set(self.items) | set(self.prototypes) | {self.discovery["key"]}
        self.assertEqual(len(keys), len(self.items) + len(self.prototypes) + 1)
        maps = {row["name"] for row in self.template["valuemaps"]}
        for item in list(self.items.values()) + list(self.prototypes.values()) + [self.discovery]:
            self.assertIn(item["type"], ("DEPENDENT", "HTTP_AGENT"))
            if item["type"] == "DEPENDENT":
                self.assertEqual(item["delay"], "0")
                self.assertIn(item["master_item"]["key"], self.items)
            if "valuemap" in item:
                self.assertIn(item["valuemap"]["name"], maps)
            for step in item.get("preprocessing", []):
                self.assertIn(step["type"], ("PROMETHEUS_TO_JSON", "JAVASCRIPT", "JSONPATH"))
                self.assertEqual(set(step), {"type", "parameters"})
                self.assertEqual(len(step["parameters"]), 1)
                self.assertIsInstance(step["parameters"][0], str)
        for trigger in [obj for obj in objects if "expression" in obj]:
            self.assertIn(trigger["priority"], ("INFO", "WARNING", "AVERAGE", "HIGH"))
            for expression in (trigger["expression"], trigger.get("recovery_expression", "")):
                references = re.findall(r"(?:last|nodata)\(/" + re.escape(TEMPLATE_NAME) + r"/(.*?)(?:,\{\$CGP.NODATA\})?\)", expression)
                self.assertTrue(references or not expression)
                self.assertTrue(all(key in keys for key in references), references)
            if "recovery_expression" in trigger:
                self.assertEqual(trigger["recovery_mode"], "RECOVERY_EXPRESSION")

    def test_only_existing_public_http_endpoint_and_three_dependency_levels(self):
        raw = self.items["cgp.manager.metrics.raw"]
        self.assertEqual([key for key, item in self.items.items() if item["type"] == "HTTP_AGENT"], [raw["key"]])
        expected = {"url": "{$CGP.METRICS.URL}", "request_method": "GET", "retrieve_mode": "BODY",
                    "output_format": "RAW", "status_codes": "200", "follow_redirects": "NO",
                    "verify_peer": "YES", "verify_host": "YES", "timeout": "10s", "history": "0"}
        for key, value in expected.items():
            self.assertEqual(raw[key], value)
        self.assertEqual(self.macros["{$CGP.METRICS.URL}"], "http://{HOST.CONN}:9100/metrics")
        self.assertNotIn("actions", self.export["zabbix_export"])
        self.assertNotIn("httptests", self.template)
        all_items = list(self.items.values()) + list(self.prototypes.values()) + [self.discovery]
        for item in all_items:
            depth, visited = 0, set()
            while "master_item" in item:
                self.assertNotIn(item["key"], visited)
                visited.add(item["key"])
                item = self.items[item["master_item"]["key"]]
                depth += 1
            self.assertLessEqual(depth, 3)
        self.assertEqual(self.discovery["lifetime_type"], "DELETE_NEVER")
        self.assertEqual(self.discovery["enabled_lifetime_type"], "DISABLE_NEVER")
        self.assertNotIn("filter", self.discovery)
        self.assertNotIn("overrides", self.discovery)

    def test_embedded_sources_exact_and_no_domain_interpolation_in_javascript(self):
        embedded = {
            "normalize": self.items["cgp.manager.snapshot"]["preprocessing"][1]["parameters"][0],
            "fresh": self.items["cgp.manager.snapshot.fresh"]["preprocessing"][0]["parameters"][0],
            "discovery": self.discovery["preprocessing"][0]["parameters"][0],
        }
        for name, body in embedded.items():
            self.assertEqual(body, (ASSETS / (name + ".js")).read_text())
            if name != "discovery":
                self.assertNotIn("{#CGP_DOMAIN}", body)
            self.assertNotRegex(body, r"\b(?:require|fetch|HttpRequest|Zabbix|eval)\s*[.(]")
            self.assertNotRegex(body, r"\b(?:let|const)\s|=>|Object\.assign|Number\.isFinite")
        self.assertEqual(self.items["cgp.manager.snapshot"]["preprocessing"][0], {
            "type": "PROMETHEUS_TO_JSON", "parameters": ['{__name__=~"^cgp_manager_.*$"}']})
        self.assertNotIn('cgp_manager="true"', json.dumps(self.export))
        for name in ("last_success", "failures", "retry_at", "not_after", "in_inventory"):
            item = self.prototypes['cgp.manager.domain.' + name + '["{#CGP_DOMAIN}"]']
            self.assertTrue(item["preprocessing"][0]["parameters"][0].startswith("$.operational.domains"))

    def test_exact_preprocessing_executes_with_full_v8_block_coverage(self):
        node = shutil.which("node")
        self.assertIsNotNone(node, "Node 24 is required; JavaScript execution must not be skipped")
        scripts = {
            "normalize": self.items["cgp.manager.snapshot"]["preprocessing"][1]["parameters"][0],
            "fresh": self.items["cgp.manager.snapshot.fresh"]["preprocessing"][0]["parameters"][0],
            "discovery": self.discovery["preprocessing"][0]["parameters"][0],
        }
        cases, expectations = [], []
        errors = {"normalize": "Invalid CGP monitoring metrics", "fresh": "CGP monitoring observation is not fresh or valid",
                  "discovery": "CGP monitoring discovery is incomplete"}

        def case(label, value, expected=None, error=None, steps=("normalize",), **options):
            cases.append({"label": label, "value": value, "steps": list(steps), **options})
            expectations.append({"error": errors[error]} if error else {"value": expected})

        def valid(label, data, steps=("normalize",), **options):
            result = normalized(data)
            if "fresh" in steps and data["complete"]:
                result["operational"] = {"pending": copy.deepcopy(result["pending"]), "domains": copy.deepcopy(result["domains"])}
            if "discovery" in steps:
                result = formats.zabbix_discovery(data)
            case(label, json.dumps(native_rows(data)), result, steps=steps, **options)

        def bad(label, change):
            rows = native_rows(snapshot())
            change(rows)
            case(label, json.dumps(rows), error="normalize")

        valid("complete", snapshot(), steps=("normalize", "fresh", "discovery"))
        valid("normal projection", snapshot())
        valid("fresh complete operational projection", snapshot(), steps=("normalize", "fresh"))
        for age in (0, 900):
            data = snapshot(); data["generated_at"] = NOW - age
            valid("inclusive freshness " + str(age), data, steps=("normalize", "fresh"))
        for age in (-1, 901):
            data = snapshot(); data["generated_at"] = NOW - age
            case("rejected age " + str(age), json.dumps(native_rows(data)), error="fresh", steps=("normalize", "fresh", "discovery"))
        fractional = snapshot(); fractional["generated_at"] = NOW + 0.5
        valid("fractional present is not a future observation", fractional,
              steps=("normalize", "fresh"), now=NOW + 0.75)
        case("strict fractional future rejection", json.dumps(native_rows(fractional)),
             error="fresh", steps=("normalize", "fresh"), now=NOW + 0.25)
        valid("explicit administrator clock-skew override", fractional,
              steps=("normalize", "fresh"), now=NOW + 0.25, futureSkew="1")
        fractional["generated_at"] = NOW - 899.5
        valid("fractional age exactly 900 is accepted", fractional,
              steps=("normalize", "fresh"), now=NOW + 0.5)
        case("fractional age over 900 is rejected", json.dumps(native_rows(fractional)),
             error="fresh", steps=("normalize", "fresh"), now=NOW + 0.75)
        empty = snapshot(); empty["domains"] = []
        valid("known empty discovery", empty, steps=("normalize", "fresh", "discovery"))
        known_error = snapshot(); known_error["complete"] = False
        known_error["domains"][1]["local_certificate"] = {"status": "error"}
        valid("explicit leaf read error on incomplete snapshot", known_error, steps=("normalize", "fresh"))
        case("incomplete is never empty discovery", json.dumps(native_rows(known_error)), error="discovery", steps=("normalize", "fresh", "discovery"))
        unknown = snapshot(); unknown["complete"] = False
        for source, status in (("inventory", "missing"), ("state", "error"), ("transactions", "busy"),
                               ("resolutions", "missing"), ("dns_challenges", "error"), ("lock", "busy")):
            unknown["sources"][source]["status"] = status
        unknown["pending"] = {kind: None for kind in formats.PENDING_KINDS}
        for row in unknown["domains"]:
            row.update(in_inventory=None, last_success=None, failures=None, retry_at=None)
        valid("unknown omitted rather than zero", unknown, steps=("normalize", "fresh"))
        config_error = copy.deepcopy(unknown); config_error["domains"] = []; config_error["sources"]["config"]["status"] = "error"
        valid("configuration failure has no inferred domains", config_error, steps=("normalize", "fresh"))
        partial = snapshot(); partial["complete"] = False
        valid("explicit incomplete status may be conservative", partial)
        special = snapshot(); special["domains"][1]["domain"] = "constructor"
        special["domains"][1]["local_certificate"]["not_after"] = -10
        special["domains"][1]["failures"] = 2
        valid("prototype-safe name and expired local certificate", special)
        rows = native_rows(snapshot())
        row_for(rows, "collection_timestamp_seconds")["value"] = "+1.70000099e9"
        for row in rows: row.pop("type", None)
        rows.append({"name": "unrelated_total", "labels": {"job": "elsewhere"}, "value": ".5"})
        case("native types optional and valid scientific values", json.dumps(rows), normalized(snapshot()))

        for raw in (None, 1, True, "{", "null", "{}", "1", '"text"', " " * 16777217,
                    json.dumps([{}] * 20001)):
            case("malformed or bounded top-level " + str(type(raw)), raw, error="normalize")
        for row in (None, [], True, "secret", {}):
            bad("malformed row " + repr(row), lambda rows, row=row: rows.append(row))
        for metric_name in (1, "", "bad-name", "cgp_manager_collection_success\nsecret"):
            bad("invalid metric name", lambda rows, metric_name=metric_name: rows.append({"name": metric_name, "value": "1"}))
        for labels in (None, [], "secret", {"version": 1}):
            bad("invalid label shape", lambda rows, labels=labels: rows[0].update(labels=labels))
        for value in (1, True, None, "", "NaN", "Inf", "+Inf", "1e999", "1\nsecret"):
            bad("nonfinite or invalid numeric value " + repr(value), lambda rows, value=value: rows[0].update(value=value))
        bad("duplicate same series", lambda rows: rows.append(copy.deepcopy(rows[0])))
        bad("duplicate labels reordered", lambda rows: rows.append({**copy.deepcopy(row_for(rows, "domain_info", domain="a.example.com", cert_name="lineage-a")), "labels": {"domain": "a.example.com", "cert_name": "lineage-a"}}))
        bad("wrong labels", lambda rows: row_for(rows, "collection_success").update(labels={"extra": "secret"}))
        bad("wrong known metric type", lambda rows: row_for(rows, "collection_success").update(type="counter"))
        bad("missing mandatory scalar", lambda rows: remove(rows, "collection_success"))
        bad("nonbinary success", lambda rows: row_for(rows, "collection_success").update(value="2"))
        bad("negative collection time", lambda rows: row_for(rows, "collection_timestamp_seconds").update(value="-1"))
        bad("missing one-hot member", lambda rows: remove(rows, "source_status", source="config", status="busy"))
        bad("zero one-hot sum", lambda rows: row_for(rows, "source_status", source="config", status="ok").update(value="0"))
        bad("two one-hot bits", lambda rows: row_for(rows, "source_status", source="config", status="error").update(value="1"))
        bad("nonbinary one-hot bit", lambda rows: row_for(rows, "source_status", source="config", status="busy").update(value="0.5"))

        def source_bad(rows, source):
            row_for(rows, "source_status", source=source, status="ok")["value"] = "0"
            row_for(rows, "source_status", source=source, status="error")["value"] = "1"

        bad("complete contradicts source status", lambda rows: source_bad(rows, "config"))
        bad("missing known pending quantity", lambda rows: remove(rows, "pending_artifacts", kind="transactions"))
        for number in ("-1", "0.5", "9007199254740992"):
            bad("invalid pending count " + number, lambda rows, number=number: row_for(rows, "pending_artifacts", kind="transactions").update(value=number))

        def contradictory(rows, source):
            row_for(rows, "collection_success")["value"] = "0"
            source_bad(rows, source)

        for source in ("transactions", "inventory", "state", "config"):
            bad("unavailable source cannot claim a quantity " + source, lambda rows, source=source: contradictory(rows, source))
        bad("domain info value must be one", lambda rows: row_for(rows, "domain_info", domain="a.example.com", cert_name="lineage-a").update(value="0"))
        for identifier in ("a" * 254, "../secret", "a..example", "example.com."):
            bad("unsafe domain identity " + identifier[:20], lambda rows, identifier=identifier: row_for(rows, "domain_info", domain="a.example.com", cert_name="lineage-a")["labels"].update(domain=identifier))
        bad("unsafe lineage", lambda rows: row_for(rows, "domain_info", domain="a.example.com", cert_name="lineage-a")["labels"].update(cert_name="../secret"))
        bad("one domain with multiple lineages", lambda rows: rows.append({"name": PREFIX + "domain_info", "labels": {"domain": "a.example.com", "cert_name": "another"}, "value": "1"}))
        bad("domain limit", lambda rows: rows.extend({"name": PREFIX + "domain_info", "labels": {"domain": "n" + str(i) + ".example", "cert_name": "lineage"}, "value": "1"} for i in range(1000)))
        bad("missing domain enabled", lambda rows: remove(rows, "domain_enabled", domain="a.example.com"))
        bad("missing known inventory membership", lambda rows: remove(rows, "domain_in_inventory", domain="a.example.com"))

        def leaf_error(rows):
            row_for(rows, "local_certificate_status", domain="a.example.com", status="ok")["value"] = "0"
            row_for(rows, "local_certificate_status", domain="a.example.com", status="error")["value"] = "1"

        bad("complete contradicts certificate error", leaf_error)
        bad("missing known expiry", lambda rows: remove(rows, "local_certificate_not_after_timestamp_seconds", domain="a.example.com"))
        bad("absent certificate cannot supply expiry", lambda rows: rows.append({"name": PREFIX + "local_certificate_not_after_timestamp_seconds", "labels": {"domain": "z.example.com"}, "value": "1"}))
        bad("negative saved time", lambda rows: row_for(rows, "last_success_timestamp_seconds", domain="a.example.com").update(value="-1"))
        bad("orphan domain series", lambda rows: rows.append({"name": PREFIX + "domain_enabled", "labels": {"domain": "orphan.example"}, "value": "1"}))
        for source, status in (("unknown", "ok"), ("config", "unknown")):
            bad("unknown source one-hot dimension", lambda rows, source=source, status=status: rows.append({"name": PREFIX + "source_status", "labels": {"source": source, "status": status}, "value": "0"}))
        bad("unknown pending kind", lambda rows: rows.append({"name": PREFIX + "pending_artifacts", "labels": {"kind": "unknown"}, "value": "0"}))
        bad("unknown certificate status", lambda rows: rows.append({"name": PREFIX + "local_certificate_status", "labels": {"domain": "a.example.com", "status": "unknown"}, "value": "0"}))

        good = json.dumps(normalized(snapshot()))
        for option in ({"maxAge": "bad"}, {"maxAge": "000"}, {"futureSkew": "x"}):
            case("invalid numeric macro", good, error="fresh", steps=("fresh",), **option)
        for value in ("{", "null", '"string"', "{}", '{"generated_at":"0"}', '{"generated_at":1e999}'):
            case("invalid fresh-stage input", value, error="fresh", steps=("fresh",))
        for value in ("{", "null", '{"collection_success":0}', '{"collection_success":1}',
                      '{"collection_success":1,"operational":{"domains":null}}'):
            case("discovery never converts failure to empty", value, error="discovery", steps=("discovery",))
        invocation = subprocess.run([node, "-e", NODE_HARNESS], input=json.dumps({"scripts": scripts, "cases": cases, "now": NOW}),
                                    text=True, capture_output=True, timeout=60, check=False)
        self.assertEqual(invocation.returncode, 0, invocation.stderr)
        report = json.loads(invocation.stdout)
        self.assertEqual(len(report["results"]), len(expectations))
        for scenario, actual, expected in zip(cases, report["results"], expectations):
            with self.subTest(scenario=scenario["label"]):
                self.assertEqual(actual, expected)
        coverage = report["coverage"]
        self.assertEqual({entry["url"] for entry in coverage}, {"cgp-zabbix/" + key + ".js" for key in scripts})
        merged = {name: {} for name in scripts}
        for entry in coverage:
            name = entry["url"].removeprefix("cgp-zabbix/").removesuffix(".js")
            self.assertTrue(entry["functions"], "No functions collected for " + name)
            for function in entry["functions"]:
                self.assertTrue(function["isBlockCoverage"], "Detailed V8 block coverage is mandatory")
                root = function["ranges"][0]
                key = (function["functionName"], root["startOffset"], root["endOffset"])
                merged[name].setdefault(key, []).append(function["ranges"])
        for name, functions in merged.items():
            self.assertTrue(functions, "No JavaScript coverage collected for " + name)
            unused = []
            for identity, variants in functions.items():
                boundaries = sorted({edge for ranges in variants for block in ranges
                                     for edge in (block["startOffset"], block["endOffset"])})
                for start, end in zip(boundaries, boundaries[1:]):
                    hits = 0
                    for ranges in variants:
                        # V8 ranges nest: the innermost block overrides its
                        # parent. Merge equivalent macro substitutions by byte
                        # interval, not by exact range shape after early throws.
                        enclosing = [block for block in ranges
                                     if block["startOffset"] <= start and block["endOffset"] >= end]
                        tightest = min(enclosing, key=lambda block: block["endOffset"] - block["startOffset"])
                        hits += tightest["count"]
                    if hits == 0:
                        unused.append((identity, start, end))
            self.assertEqual(unused, [], "Uncovered V8 blocks in " + name + ": " + repr(unused))

    def test_exported_trigger_thresholds_gates_and_recovery_are_executable(self):
        self.assertEqual(self.macros["{$CGP.MAX.AGE.SECONDS}"], "900")
        self.assertEqual(self.macros["{$CGP.FUTURE.SKEW.SECONDS}"], "0")
        self.assertEqual(self.macros["{$CGP.NODATA}"], "5m")
        self.assertEqual(self.macros["{$CGP.EXPIRY.CRIT.SECONDS}"], str(7 * 86400))
        self.assertEqual(self.macros["{$CGP.EXPIRY.WARN.SECONDS}"], str(21 * 86400))
        triggers = self.discovery["trigger_prototypes"]
        critical = next(row for row in triggers if row["priority"] == "HIGH")
        warning = next(row for row in triggers if "expiry warning" in row["name"])
        missing = next(row for row in triggers if "is missing" in row["name"])
        error = next(row for row in triggers if "cannot be read" in row["name"])
        failure = next(row for row in triggers if "Saved stage failures" in row["name"])
        pending = self.items["cgp.manager.pending[transactions]"]["triggers"][0]

        def evaluate(expression, age=0, complete=1, enabled=1, status=0, remaining=30 * 86400,
                     count=0, domain_age=None, accepted_age=None, known=1, now=NOW):
            domain_stamp = now - (age if domain_age is None else domain_age)
            values = {
                "cgp.manager.collection.timestamp": now - age,
                "cgp.manager.collection.accepted": now - (age if accepted_age is None else accepted_age),
                "cgp.manager.collection.success": complete,
                'cgp.manager.domain.observed["a.example.com"]': domain_stamp,
                'cgp.manager.domain.enabled["a.example.com"]': enabled,
                'cgp.manager.domain.certificate_status["a.example.com"]': status,
                'cgp.manager.domain.not_after["a.example.com"]': math.floor(now) + remaining,
                'cgp.manager.domain.failures["a.example.com"]': count,
                'cgp.manager.domain.failures_known["a.example.com"]': known,
                'cgp.manager.pending[transactions]': count,
            }
            expression = expression.replace("{#CGP_DOMAIN}", "a.example.com")
            expression = expression.replace("now()", str(math.floor(now)))
            for macro, value in self.macros.items():
                expression = expression.replace(macro, value)
            expression = re.sub(r"last\(/" + re.escape(TEMPLATE_NAME) + r"/(.*?)\)",
                                lambda match: str(values[match[1]]), expression)
            expression = re.sub(r"floor\((-?[0-9.]+)\)", lambda match: str(math.floor(float(match[1]))), expression)
            expression = expression.replace("<>", "!=")
            expression = re.sub(r"(?<![<>=!])=(?!=)", "==", expression)
            self.assertRegex(expression, r"^[0-9. <>=!()+\-a-z]+$")
            return bool(eval(expression, {"__builtins__": {}}, {}))

        for remaining, is_critical, is_warning in ((-1, True, False), (7 * 86400, True, False),
                                                 (7 * 86400 + 1, False, True), (21 * 86400, False, True),
                                                 (21 * 86400 + 1, False, False)):
            self.assertEqual(evaluate(critical["expression"], remaining=remaining), is_critical)
            self.assertEqual(evaluate(warning["expression"], remaining=remaining), is_warning)
        for trigger, present in ((critical, {"remaining": 1}), (warning, {"remaining": 14 * 86400}),
                                 (missing, {"status": 1}), (failure, {"count": 1}), (pending, {"count": 1})):
            self.assertTrue(evaluate(trigger["expression"], **present))
            for unavailable in ({"age": 901}, {"age": -1}, {"complete": 0}):
                self.assertFalse(evaluate(trigger["expression"], **present, **unavailable))
                self.assertFalse(evaluate(trigger["recovery_expression"], **unavailable))
        self.assertFalse(evaluate(critical["expression"], remaining=1, enabled=0))
        self.assertTrue(evaluate(critical["recovery_expression"], remaining=1, enabled=0))
        self.assertFalse(evaluate(critical["expression"], remaining=1, domain_age=60))
        self.assertFalse(evaluate(critical["recovery_expression"], domain_age=60))
        self.assertTrue(evaluate(error["expression"], complete=0, status=2))
        self.assertFalse(evaluate(error["recovery_expression"], complete=0, status=2))
        self.assertTrue(evaluate(error["recovery_expression"], complete=0, status=0))
        self.assertTrue(evaluate(warning["recovery_expression"], remaining=1))
        self.assertFalse(evaluate(missing["recovery_expression"], status=2))
        # A fresh complete snapshot with a missing leaf cannot reuse the cached
        # expiry to create or recover an expiry problem.
        self.assertFalse(evaluate(critical["expression"], remaining=1, status=1))
        self.assertFalse(evaluate(critical["recovery_expression"], remaining=30 * 86400, status=1))
        self.assertFalse(evaluate(warning["expression"], remaining=14 * 86400, status=1))
        self.assertFalse(evaluate(warning["recovery_expression"], remaining=30 * 86400, status=1))
        self.assertFalse(evaluate(failure["expression"], count=5, known=0))
        self.assertFalse(evaluate(failure["recovery_expression"], count=0, known=0))
        self.assertEqual(failure["priority"], "INFO")
        # Native now() has integer-second resolution; exact acceptance identity
        # prevents cached global data from authorizing a rejected generation.
        self.assertTrue(evaluate(pending["expression"], count=1, now=1000.75, age=0.25))
        self.assertFalse(evaluate(pending["expression"], count=1, now=1000.5, age=-0.3, accepted_age=1.5))
        self.assertFalse(evaluate(pending["recovery_expression"], count=0, now=1000.5, age=-0.3, accepted_age=1.5))

