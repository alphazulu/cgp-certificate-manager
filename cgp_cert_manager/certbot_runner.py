"""Run adaptive Certbot under the manager lock and supervise its process group."""
import argparse
from contextlib import contextmanager
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

from . import core, dnsconfig, storage


_CONTEXT = None
_STOP_TIMEOUT = 10


def _check_lock(fd):
    storage.check_private_directory(core.STATE)
    with storage.open_private(core.STATE / 'run.lock') as named:
        expected = os.fstat(named.fileno())
        actual = os.fstat(fd)
        if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
            raise core.Error('Adaptive Certbot requires the manager operation lock')
    # Linux fdinfo reports locks associated with this open file description.
    # Acquiring flock here would also accept a fresh, previously unlocked FD.
    try:
        information = Path('/proc/self/fdinfo/' + str(fd)).read_text(encoding='ascii')
    except (OSError, UnicodeError):
        raise core.Error('Cannot verify the manager lock through Linux procfs') from None
    if not re.search(r'^lock:\s+\d+:\s+FLOCK\s+ADVISORY\s+WRITE\s+\d+\s+'
                     r'[0-9a-fA-F]+:[0-9a-fA-F]+:\d+\s+0\s+EOF$', information, re.M):
        raise core.Error('Adaptive Certbot requires an already held exclusive manager lock')


def require_context():
    """Expose configuration only while a verified wrapper owns the lock."""
    if _CONTEXT is None or _CONTEXT[0] != os.getpid():
        raise core.Error('Adaptive authenticator requires the cgp-certbot wrapper')
    _, fd, cfg = _CONTEXT
    _check_lock(fd)
    return cfg


def _config_path(path):
    path = Path(path)
    if not path.is_absolute():
        raise core.Error('Adaptive Certbot configuration path must be absolute')
    return path


def _load_config(path):
    cfg = core.load(_config_path(path))
    if not isinstance(cfg, dict) or cfg.get('schema_version') != 2:
        raise core.Error('Adaptive Certbot requires configuration schema version 2')
    if dnsconfig.validate(cfg)['mode'] != 'adaptive':
        raise core.Error('Adaptive Certbot requires adaptive DNS propagation mode')
    return cfg


def _group_exists(pid):
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _quiesce(process):
    process.poll()
    if not _group_exists(process.pid):
        process.wait(timeout=_STOP_TIMEOUT)
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + _STOP_TIMEOUT
        while True:
            process.poll()
            if not _group_exists(process.pid):
                process.wait(timeout=_STOP_TIMEOUT)
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(0.05, remaining))
    raise core.Error('Adaptive Certbot did not stop; DNS cleanup remains pending')


class _Interrupts:
    def __init__(self):
        self.received = False

    def __call__(self, signum, frame):
        self.received = True


@contextmanager
def _signals():
    # Never raise asynchronously during child creation or teardown.  Normal
    # waiting observes this flag within one short pulse and exits safely.
    interrupts = _Interrupts()
    previous_term = signal.signal(signal.SIGTERM, interrupts)
    try:
        previous_int = signal.signal(signal.SIGINT, interrupts)
        try:
            yield interrupts
        finally:
            signal.signal(signal.SIGINT, previous_int)
    finally:
        signal.signal(signal.SIGTERM, previous_term)


def _wait(process, interrupts):
    deadline = time.monotonic() + 3600
    while True:
        if interrupts.received:
            raise KeyboardInterrupt
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(process.args, 3600)
        try:
            return process.wait(timeout=min(0.1, remaining))
        except subprocess.TimeoutExpired:
            pass


def run(cmd, cfg, lock_fd=None, config_path=None):
    """Wait for Certbot to stop before touching its durable DNS cleanup ledger."""
    dnsconfig.validate(cfg)
    path = _config_path(core.CONFIG if config_path is None else config_path)
    if lock_fd is None:
        with storage.operation_lock(core.STATE) as lock:
            return run(cmd, cfg, lock_fd=lock.fileno(), config_path=path)
    _check_lock(lock_fd)
    storage.validate_tree(core.STATE)
    if _load_config(path) != cfg:
        raise core.Error('Adaptive Certbot configuration changed')
    from . import dnsauth
    env = dict(os.environ, CGP_CERTBOT_CONFIG=str(path),
               PYTHONPATH=str(Path(__file__).resolve().parents[1]))
    with _signals() as interrupts:
        try:
            process = subprocess.Popen(
                [sys.executable, '-m', 'cgp_cert_manager.certbot_runner',
                 '--manager-lock-fd', str(lock_fd), *cmd[1:]],
                env=env, pass_fds=(lock_fd,), stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
            try:
                code = _wait(process, interrupts)
            finally:
                _quiesce(process)
                dnsauth.cleanup_pending(cfg)
            if interrupts.received:
                raise KeyboardInterrupt
            if code:
                raise core.Error('Adaptive Certbot failed (' + str(code) + ')')
        except subprocess.TimeoutExpired:
            raise core.Error('Adaptive Certbot timed out') from None


def _invoke(args, path, fd):
    global _CONTEXT
    _check_lock(fd)
    storage.validate_tree(core.STATE)
    cfg = _load_config(path)
    _CONTEXT = (os.getpid(), fd, cfg)
    try:
        from certbot.main import main as certbot_main
        return certbot_main(args)
    finally:
        _CONTEXT = None


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--manager-lock-fd', type=int, help=argparse.SUPPRESS)
    options, args = parser.parse_known_args(arguments)
    try:
        if arguments in (['--version'], ['--help'], ['-h']):
            from certbot.main import main as certbot_main
            return certbot_main(arguments)
        path = _config_path(os.environ.get('CGP_CERTBOT_CONFIG', str(core.CONFIG)))
        if options.manager_lock_fd is None:
            with storage.operation_lock(core.STATE) as lock:
                cfg = _load_config(path)
                run(['certbot', *args], cfg, lock_fd=lock.fileno(), config_path=path)
                return 0
        return _invoke(args, path, options.manager_lock_fd)
    except KeyboardInterrupt:
        print('Adaptive Certbot interrupted', file=sys.stderr)
        return 130
    except Exception as exc:
        print('Adaptive Certbot refused: ' + (str(exc) if isinstance(exc, core.Error)
                                             else type(exc).__name__), file=sys.stderr)
        return 1


if __name__ == '__main__':
    # Certbot imports the plugin through the canonical package name, so its
    # context must live in that same module rather than a second __main__ copy.
    from .certbot_runner import main as entry
    sys.exit(entry())
