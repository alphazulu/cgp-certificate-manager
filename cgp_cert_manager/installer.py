"""Private-storage preflight and inherited locks for the shell installer."""
import argparse
import fcntl
import os
from pathlib import Path
import subprocess
import sys

from . import core, dnsconfig, monitor_config, storage
from .cli import migrate
from .monitor_config import CONFIG as MONITOR_CONFIG, STATE as MONITOR_STATE
from .schedule import render


def runtime_dependencies(options):
    """Check the candidate interpreter before changing application or timer."""
    try:
        import dns.message
        if options['mode'] == 'adaptive':
            from certbot.main import main as certbot_main
            from certbot._internal.plugins.disco import PluginsRegistry
            if 'cgp-dns' not in PluginsRegistry.find_all():
                raise ImportError('CGP DNS authenticator missing')
    except Exception:
        raise core.Error('DNS runtime dependencies unavailable: install python3-dnspython; '
                         'adaptive mode also requires native Certbot and the CGP plugin') from None


def preflight():
    """Validate existing secrets and recovery data without changing permissions."""
    storage.validate_tree(core.STATE)
    storage.validate_tree(MONITOR_STATE)
    if storage.check_private_file(MONITOR_CONFIG, missing_ok=True):
        monitor_config.load(MONITOR_CONFIG)
    cfg = migrate(core.load(core.CONFIG))
    runtime_dependencies(dnsconfig.validate(cfg))
    render(cfg.get("schedule", {}))
    accounts = cfg.get("cloudflare_accounts") or [{"credentials": cfg["cloudflare_credentials"]}]
    for account in accounts:
        core.token(account["credentials"])


def check_lock(fd, monitor_fd):
    """Require both inherited descriptors to name the current private locks.

    flock uses the inherited open-file description, so this also locks a valid
    descriptor if the internal payload was invoked directly. The shell retains
    that descriptor after this checker exits.
    """
    for state, descriptor, name in ((core.STATE, fd, "manager"),
                                    (MONITOR_STATE, monitor_fd, "monitor")):
        storage.check_private_directory(state)
        with storage.open_private(state / "run.lock") as named:
            expected = os.fstat(named.fileno())
            actual = os.fstat(descriptor)
            if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
                raise core.Error("Installer descriptor is not the " + name + " operation lock")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    preflight()


def run():
    """Keep both locks alive until installation or shell rollback completes."""
    os.umask(0o077)
    source = Path(__file__).resolve().parents[1]
    with storage.operation_lock(core.STATE) as lock, storage.operation_lock(MONITOR_STATE) as monitor_lock:
        preflight()
        return subprocess.run(
            ["bash", str(source / "scripts" / "install-locked.sh"),
             str(lock.fileno()), str(monitor_lock.fileno())],
            cwd=source, pass_fds=(lock.fileno(), monitor_lock.fileno()),
        ).returncode


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-lock", type=int, nargs=2, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        if args.check_lock is not None:
            check_lock(*args.check_lock)
            return 0
        return run()
    except BlockingIOError:
        print("Certificate manager or monitor busy; retry after completion", file=sys.stderr)
        return 1
    except (core.Error, OSError, ValueError) as exc:
        print("Installation refused: " + str(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Installation interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
