"""Bound network operations, including DNS, in a short-lived Linux process."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from . import certbot_runner, monitor_config


MAX_INPUT = 2 * 1024 * 1024
MAX_OUTPUT = 128 * 1024
KINDS = ('probe', 'notify')


def _failure(code):
    return {'ok': False, 'value': None, 'code': code}


def _encoded(value, limit):
    data = json.dumps(value, ensure_ascii=True, allow_nan=False,
                      separators=(',', ':')).encode('ascii')
    monitor_config.require(len(data) <= limit, 'worker_payload_too_large')
    return data


def _dispatch(kind, payload, timeout):
    if kind == 'probe':
        from . import tlsprobe
        return tlsprobe.observe(payload, timeout_seconds=timeout)
    from . import notify_transport
    monitor_config.keys(payload, {'channel', 'event'}, {'channel', 'event'})
    return notify_transport.deliver(payload['channel'], payload['event'], timeout_seconds=timeout)


def main(argv=None):
    """Internal worker: input and output are bounded JSON, never command secrets."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kind', choices=KINDS, required=True)
    parser.add_argument('--timeout', type=float, required=True)
    args = parser.parse_args(argv)
    try:
        monitor_config.number(args.timeout, .05, 60)
        # The kernel's default SIGALRM action also bounds a worker whose parent
        # is killed while libc DNS resolution is blocked. No Python handler is
        # required for the alarm to terminate that process.
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
        signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGALRM})
        signal.setitimer(signal.ITIMER_REAL, args.timeout)
        data = sys.stdin.buffer.read(MAX_INPUT + 1)
        monitor_config.require(len(data) <= MAX_INPUT)
        payload = monitor_config.decode(data)
        monitor_config.require(type(payload) is dict)
        value = _dispatch(args.kind, payload, args.timeout)
        monitor_config.require(type(value) is dict)
        output = _encoded({'ok': True, 'value': value, 'code': None}, MAX_OUTPUT - 1)
    except Exception:
        output = _encoded(_failure('worker_failed'), MAX_OUTPUT - 1)
    try:
        sys.stdout.buffer.write(output + b'\n')
        sys.stdout.buffer.flush()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    return 0


def _execute_process(command, options, data, deadline, interrupts):
    try:
        process = subprocess.Popen(command, **options)
    except OSError:
        return _failure('worker_start_failed')
    try:
        while True:
            if interrupts.received:
                raise KeyboardInterrupt
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return _failure('worker_timeout')
            try:
                output, _ = process.communicate(input=data, timeout=min(.1, remaining))
                break
            except subprocess.TimeoutExpired:
                data = None
        if interrupts.received:
            raise KeyboardInterrupt
        if process.returncode:
            return _failure('worker_timeout' if process.returncode == -signal.SIGALRM
                            else 'worker_failed')
        try:
            monitor_config.require(len(output) <= MAX_OUTPUT)
            result = monitor_config.decode(output)
            monitor_config.keys(result, {'ok', 'value', 'code'}, {'ok', 'value', 'code'})
            monitor_config.require(
                (result['ok'] is True and type(result['value']) is dict and result['code'] is None)
                or (result['ok'] is False and result['value'] is None and result['code'] == 'worker_failed'))
            return result
        except (ValueError, TypeError, RecursionError):
            return _failure('worker_invalid_result')
    finally:
        try:
            certbot_runner._quiesce(process)
        finally:
            try:
                process.stdin.close()
            finally:
                process.stdout.close()


def execute(kind, payload, timeout, lock_fd=None):
    """Return a checked envelope; never leave a child running on handled exit.

    A run passes its already-held monitor lock into the worker. If the parent
    dies, the child retains that lock until completion or its own kernel alarm.
    Delivery timeouts are uncertain outcomes; the coordinator retains intent.
    """
    monitor_config.require(kind in KINDS, 'invalid_worker_kind')
    monitor_config.number(timeout, .05, 60)
    monitor_config.require(lock_fd is None or (type(lock_fd) is int and 0 <= lock_fd <= 2**31 - 1),
                           'invalid_worker_lock')
    data = _encoded(payload, MAX_INPUT)
    source = Path(__file__).resolve().parents[1]
    environment = {'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
                   'PYTHONNOUSERSITE': '1', 'PYTHONPATH': str(source)}
    deadline = time.monotonic() + timeout
    interrupts = None
    try:
        with certbot_runner._signals() as interrupts:
            inherited = None
            try:
                try:
                    if lock_fd is not None:
                        # Popen replaces descriptors 0..2. Retain the same locked
                        # open file description on a dedicated descriptor instead.
                        inherited = fcntl.fcntl(lock_fd, fcntl.F_DUPFD_CLOEXEC, 3)
                except OSError:
                    result = _failure('worker_start_failed')
                else:
                    command = [sys.executable, '-m', 'cgp_cert_manager.monitor_worker',
                               '--kind', kind, '--timeout', str(timeout)]
                    options = dict(stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   cwd=source, env=environment, start_new_session=True,
                                   pass_fds=() if inherited is None else (inherited,))
                    result = _execute_process(command, options, data, deadline, interrupts)
            finally:
                if inherited is not None:
                    os.close(inherited)
    finally:
        # Also observe a signal deferred while previous handlers were restored.
        if interrupts is not None and interrupts.received:
            raise KeyboardInterrupt
    return result


if __name__ == '__main__':
    raise SystemExit(main())
