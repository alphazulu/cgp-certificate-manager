"""Pure, allowlisted representations of the local monitoring snapshot.

These formats describe collection and local files, never a live TLS probe.
Unknown measurements are omitted rather than converted to healthy zeroes.
"""
import math

from . import __version__, core


SOURCES = ("config", "inventory", "state", "transactions", "resolutions",
           "dns_challenges", "lock")
SOURCE_STATUSES = ("ok", "missing", "error", "busy")
PENDING_KINDS = ("transactions", "resolutions", "dns_challenges")
CERTIFICATE_STATUSES = ("ok", "missing", "error")


def _label(value):
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _number(value):
    if type(value) not in (int, float):
        raise core.Error("Invalid monitoring numeric value")
    try:
        finite = math.isfinite(value)
    except OverflowError:
        finite = False
    if not finite:
        raise core.Error("Invalid monitoring numeric value")
    return str(value)


def prometheus(snapshot):
    """Render Prometheus text 0.0.4 with no optional sample timestamps."""
    lines = []

    def family(name, description, samples):
        name = "cgp_manager_" + name
        lines.extend(("# HELP " + name + " " + description,
                      "# TYPE " + name + " gauge"))
        for labels, value in samples:
            suffix = ""
            if labels:
                suffix = "{" + ",".join(key + '="' + _label(value) + '"'
                                         for key, value in sorted(labels.items())) + "}"
            lines.append(name + suffix + " " + _number(value))

    family("build_info", "Manager build information.", [({"version": __version__}, 1)])
    family("collection_success", "Whether all required local sources were collected; not certificate or TLS health.",
           [({}, int(snapshot["complete"]))])
    family("collection_timestamp_seconds", "Unix time of this local collection, not a certificate verification time.",
           [({}, snapshot["generated_at"])])
    family("source_status", "One-hot local source status.",
           [({"source": source, "status": status},
             int(snapshot["sources"][source]["status"] == status))
            for source in SOURCES for status in SOURCE_STATUSES])
    family("source_mtime_seconds", "Source file modification time, not proof of a successful run or a fresh remote observation.",
           [({"source": source}, snapshot["sources"][source]["mtime"])
            for source in SOURCES if "mtime" in snapshot["sources"][source]])
    family("pending_artifacts", "Retained validated artifacts by kind; unknown counts are omitted and kinds may overlap.",
           [({"kind": kind}, snapshot["pending"][kind]) for kind in PENDING_KINDS
            if snapshot["pending"][kind] is not None])

    domains = sorted(snapshot["domains"], key=lambda row: row["domain"])
    family("domain_info", "Known local domain and currently configured certificate lineage.",
           [({"domain": row["domain"], "cert_name": row["cert_name"]}, 1)
            for row in domains])
    family("domain_enabled", "Current local configuration enables this domain.",
           [({"domain": row["domain"]}, int(row["enabled"])) for row in domains])
    family("domain_in_inventory", "Domain appears in the last saved discovery inventory, not a live discovery.",
           [({"domain": row["domain"]}, int(row["in_inventory"])) for row in domains
            if row["in_inventory"] is not None])
    family("local_certificate_status", "One-hot public local leaf certificate read status; does not describe deployed TLS.",
           [({"domain": row["domain"], "status": status},
             int(row["local_certificate"]["status"] == status))
            for row in domains for status in CERTIFICATE_STATUSES])
    family("local_certificate_not_after_timestamp_seconds", "Expiry of the public local leaf certificate in Unix seconds; not the deployed certificate.",
           [({"domain": row["domain"]}, row["local_certificate"]["not_after"])
            for row in domains if row["local_certificate"]["status"] == "ok"])
    family("last_success_timestamp_seconds", "Last saved successful manager deployment or unchanged check, not current TLS proof.",
           [({"domain": row["domain"]}, row["last_success"]) for row in domains
            if row["last_success"] is not None])
    family("recorded_failures", "Saved failure count for the last failed stage, not a cumulative counter.",
           [({"domain": row["domain"]}, row["failures"]) for row in domains
            if row["failures"] is not None])
    family("retry_timestamp_seconds", "Saved retry time in Unix seconds; zero denotes a cleared retry time.",
           [({"domain": row["domain"]}, row["retry_at"]) for row in domains
            if row["retry_at"] is not None])
    return "\n".join(lines) + "\n"


def zabbix_discovery(snapshot):
    """Never turn a failed or partial collection into an empty discovery list."""
    if not snapshot["complete"]:
        raise core.Error("Monitoring discovery is incomplete")
    return [{"{#CGP_DOMAIN}": row["domain"], "{#CGP_CERT_NAME}": row["cert_name"],
             "{#CGP_ENABLED}": int(row["enabled"])}
            for row in sorted(snapshot["domains"], key=lambda row: row["domain"])]
