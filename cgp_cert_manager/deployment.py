"""Certificate transactions. Callers must hold the global operation lock."""

from . import core, recovery
from .transactions import Journal, JournalError, classify


def snapshot_endpoints(domain, settings):
    """Use names from this snapshot, retaining configured listener addresses.

    An explicit SNI that only belongs to the replacement certificate cannot
    verify the previous certificate. For that listener, use the snapshot's
    concrete SANs and known aliases instead. Never invent wildcard hostnames.
    """
    info = core.installed_info(settings)
    if not info:
        raise JournalError("No certificate available for snapshot TLS endpoints")
    names = info["names"]
    templates = []
    for endpoint in domain.get("tls") or [{"host": "127.0.0.1", "port": 443}]:
        endpoint = dict(endpoint)
        sni = endpoint.get("sni")
        if sni and not any(sni == name or core.covered(sni, name) for name in names):
            endpoint.pop("sni")
        templates.append(endpoint)
    aliases = list(domain.get("aliases", [])) + [domain["cgp_domain"]]
    endpoints = core.tls_endpoints(dict(domain, names=names, aliases=aliases, tls=templates))
    if not endpoints:
        raise JournalError("No known hostname for snapshot TLS verification")
    return endpoints


def pending_domains(journal, domain):
    names = journal.domains()
    if domain is not None:
        core.identifier(domain)
        names = [name for name in names if name == domain]
    return names


def transaction_status(cfg, domain=None):
    """Report only non-secret metadata; inspection never alters a journal."""
    journal = Journal(core.STATE / "transactions")
    names = pending_domains(journal, domain)
    if not names:
        return []
    identity = recovery.server_identity(cfg)
    rows = []
    for name in names:
        record = journal.read(name)
        matches = record["config_identity"] == identity
        state = classify(record, core.current(cfg, name)) if matches else "foreign"
        rows.append({"domain": name, "phase": record["phase"],
                     "state": state, "server_matches": matches})
    return rows


def recover_pending(cfg, domain=None):
    """Resolve pending work before Certbot, discovery or another CGP write."""
    journal = Journal(core.STATE / "transactions")
    names = pending_domains(journal, domain)
    if not names:
        return []
    identity = recovery.server_identity(cfg)
    # Validate every selected record before starting any recovery write.
    for name in names:
        if journal.read(name)["config_identity"] != identity:
            raise JournalError("Transaction belongs to another server configuration")
    results = []
    for name in names:
        result = recovery.recover(journal, name, cfg, identity)
        core.LOG.info("%s: transaction recovery %s", name, result)
        results.append({"domain": name, "result": result})
    return results


def assert_no_pending():
    """An unresolved earlier domain blocks every further certificate mutation."""
    if Journal(core.STATE / "transactions").domains():
        raise JournalError("Pending transaction blocks certificate changes; inspect --transactions and run --recover")


def apply(cfg, domain, previous, intended, endpoints, previous_endpoints):
    """Install a snapshot, or restore the saved snapshot after a failed check.

    Both snapshots and their verification endpoints reach durable storage
    before UPDATEDOMAINSETTINGS. Unknown remote changes are never overwritten.
    A journal is retained if recovery, verification or durability is uncertain.
    """
    assert_no_pending()
    journal = Journal(core.STATE / "transactions")
    identity = recovery.server_identity(cfg)
    core.validate_backup(intended)
    if not core.same(core.current(cfg, domain), previous):
        raise JournalError("CGP changed before deployment; refusing write")
    if core.certificate_settings_match(previous, intended):
        recovery.verify_snapshot(intended, endpoints)
        if not core.same(core.current(cfg, domain), previous):
            raise JournalError("CGP changed during snapshot verification")
        return "unchanged"
    saved = core.backup(domain, previous)
    journal.prepare(domain, previous, intended, endpoints, identity,
                    previous_endpoints=previous_endpoints)
    try:
        # Recheck after the potentially slow fsync, before marking any write.
        if not core.same(core.current(cfg, domain), previous):
            raise JournalError("CGP changed after transaction preparation")
        journal.transition(domain, "applying")
        if not core.same(core.current(cfg, domain), previous):
            raise JournalError("CGP changed before transaction write")
        try:
            core.update(cfg, domain, intended)
        except Exception:
            core.LOG.warning("%s: update returned error; checking readback", domain)
        if not core.same(core.current(cfg, domain), intended):
            raise JournalError("CGP readback mismatch")
        journal.transition(domain, "applied")
        journal.transition(domain, "verifying")
        recovery.verify_snapshot(intended, endpoints)
        if not core.same(core.current(cfg, domain), intended):
            raise JournalError("CGP changed during TLS verification")
    except (Exception, KeyboardInterrupt):
        try:
            record = journal.read(domain)
            if record["phase"] == "prepared":
                recovery.recover(journal, domain, cfg, identity)
            else:
                recovery.restore(journal, domain, cfg, record, recovery.verify_snapshot)
        except (Exception, KeyboardInterrupt):
            raise JournalError("CRITICAL: transaction unresolved; inspect --transactions; backup "
                               + str(saved)) from None
        raise JournalError("Deployment failed; previous settings restored and TLS verified") from None
    # A persistence failure here leaves the record for the next recovery run;
    # it must not trigger a fresh rollback of an already verified installation.
    journal.transition(domain, "committed")
    journal.finish(domain)
    for stale in sorted(core.backup_files(domain), reverse=True)[5:]:
        stale.unlink()
    return "installed"
