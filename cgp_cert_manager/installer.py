"""Private-storage preflight and an inherited lock for the shell installer."""
import argparse
import fcntl
import os
from pathlib import Path
import subprocess
import sys

from . import core, storage
from .cli import migrate
from .schedule import render


def preflight():
    """Validate existing secrets and recovery data without changing permissions."""
    storage.validate_tree(core.STATE)
    cfg = migrate(core.load(core.CONFIG))
    render(cfg.get("schedule", {}))
    accounts = cfg.get("cloudflare_accounts") or [{"credentials": cfg["cloudflare_credentials"]}]
    for account in accounts:
        core.token(account["credentials"])


def check_lock(fd):
    """Require the inherited descriptor to name the current private lock file.

    flock uses the inherited open-file description, so this also locks a valid
    descriptor if the internal payload was invoked directly. The shell retains
    that descriptor after this checker exits.
    """
    storage.check_private_directory(core.STATE)
    with storage.open_private(core.STATE / "run.lock") as named:
        expected = os.fstat(named.fileno())
        actual = os.fstat(fd)
        if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
            raise core.Error("Installer descriptor is not the manager operation lock")
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    preflight()


def run():
    """Keep the lock alive until installation or shell rollback has completed."""
    os.umask(0o077)
    source = Path(__file__).resolve().parents[1]
    with storage.operation_lock(core.STATE) as lock:
        preflight()
        return subprocess.run(
            ["bash", str(source / "scripts" / "install-locked.sh"), str(lock.fileno())],
            cwd=source, pass_fds=(lock.fileno(),),
        ).returncode


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-lock", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        if args.check_lock is not None:
            check_lock(args.check_lock)
            return 0
        return run()
    except BlockingIOError:
        print("Certificate manager busy; retry after completion", file=sys.stderr)
        return 1
    except (core.Error, OSError, ValueError) as exc:
        print("Installation refused: " + str(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Installation interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
