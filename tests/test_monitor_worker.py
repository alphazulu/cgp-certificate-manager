"""Worker supervision tests; all transport dispatches are local or synthetic."""
import contextlib
import fcntl
import io
import json
import os
from pathlib import Path
import runpy
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from cgp_cert_manager import core, monitor_worker as worker, notify_transport, tlsprobe


ROOT = Path(__file__).resolve().parents[1]
SUCCESS = {"ok": True, "value": {"observed": True}, "code": None}


PARENT_DEATH = r'''
import ctypes, fcntl, json, os, signal, subprocess, sys, time
from pathlib import Path
from cgp_cert_manager import monitor_worker as worker
root = Path(sys.argv[1])
low_fd = sys.argv[2] == 'low'
if sys.argv[2] == 'masked':
    signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0):
    raise RuntimeError('Cannot become fixture subreaper')
lock_path = root / 'run.lock'
marker = root / 'dns.started'
pid_path = root / 'worker.pid'
child_code = """
import os, sys, time
from pathlib import Path
from cgp_cert_manager import monitor_worker as worker, tlsprobe
marker = Path(sys.argv[1])
def blocked_dns(*args, **kwargs):
    marker.write_text('started')
    time.sleep(60)
tlsprobe.socket.getaddrinfo = blocked_dns
worker.main(sys.argv[2:])
"""
parent = os.fork()
if parent == 0:
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    if low_fd:
        os.dup2(fd, 0)
        os.close(fd)
        fd = 0
    original = subprocess.Popen
    def launch(arguments, **kwargs):
        process = original([sys.executable, '-c', child_code, str(marker), *arguments[3:]], **kwargs)
        pid_path.write_text(str(process.pid))
        return process
    worker.subprocess.Popen = launch
    worker.execute('probe', {'host':'127.0.0.1','port':443,'server_name':'mail.example.test',
                             'protocol':'tls','ca_pem':None}, 1.2, lock_fd=fd)
    os._exit(5)
def locked():
    fd = os.open(lock_path, os.O_RDWR)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        return False
    finally:
        os.close(fd)
child = None
try:
    until = time.monotonic() + 5
    while not marker.exists():
        if time.monotonic() >= until:
            raise RuntimeError('Worker did not reach synthetic DNS')
        time.sleep(.01)
    child = int(pid_path.read_text())
    if not locked():
        raise RuntimeError('Parent failed to hold lock')
    os.kill(parent, signal.SIGKILL)
    os.waitpid(parent, 0)
    parent = None
    if not locked():
        raise RuntimeError('Orphaned worker lost inherited lock')
    until = time.monotonic() + 3
    while True:
        waited, status = os.waitpid(child, os.WNOHANG)
        if waited:
            break
        if time.monotonic() >= until:
            raise RuntimeError('Orphan exceeded kernel alarm')
        time.sleep(.01)
    child = None
    if not os.WIFSIGNALED(status) or os.WTERMSIG(status) != signal.SIGALRM:
        raise RuntimeError('Worker did not terminate from its own alarm')
    if locked():
        raise RuntimeError('Reaped worker retained lock')
    print(json.dumps({'alarm':True,'lock_retained':True,'lock_released':True}))
finally:
    for pid in (parent, child):
        if pid is not None:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)
'''


class WorkerTests(unittest.TestCase):
    def fake_process(self, value=SUCCESS, returncode=0):
        process = Mock(pid=12345, returncode=returncode)
        process.communicate.return_value = (json.dumps(value).encode(), None)
        return process

    @contextlib.contextmanager
    def process(self, value=SUCCESS, returncode=0):
        process = self.fake_process(value, returncode)
        with patch.object(worker.subprocess, "Popen", return_value=process) as start, \
                patch.object(worker.certbot_runner, "_quiesce") as stop:
            yield process, start, stop

    def main(self, data=b"{}", value=None, arguments=None, failure=None, output=None):
        output = io.BytesIO() if output is None else output
        arguments = ["--kind", "probe", "--timeout", "1"] if arguments is None else arguments
        with patch.object(worker.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(data))), \
                patch.object(worker.sys, "stdout", SimpleNamespace(buffer=output)), \
                patch.object(worker.signal, "signal") as signals, \
                patch.object(worker.signal, "pthread_sigmask"), \
                patch.object(worker.signal, "setitimer") as timer, \
                patch.object(worker, "_dispatch", return_value={} if value is None else value,
                             side_effect=failure) as dispatch:
            code = worker.main(arguments)
        self.assertEqual(code, 0)
        return json.loads(output.getvalue()), signals, timer, dispatch

    def test_encoding_is_bounded_strict_ascii_json(self):
        value = {"data": "Привет"}
        encoded = worker._encoded(value, 100)
        self.assertTrue(encoded.isascii())
        self.assertEqual(json.loads(encoded), value)
        self.assertEqual(worker._encoded(value, len(encoded)), encoded)
        with self.assertRaisesRegex(ValueError, "worker_payload_too_large"):
            worker._encoded(value, len(encoded) - 1)
        with self.assertRaises(ValueError):
            worker._encoded({"value": float("nan")}, 100)

    def test_dispatch_calls_only_requested_transport_with_explicit_budget(self):
        with patch.object(tlsprobe, "observe", return_value={"status": "ok"}) as probe, \
                patch.object(notify_transport, "deliver", return_value={"outcome": "accepted"}) as notify:
            self.assertEqual(worker._dispatch("probe", {"endpoint": 1}, 2), {"status": "ok"})
            probe.assert_called_once_with({"endpoint": 1}, timeout_seconds=2)
            notify.assert_not_called()
            result = worker._dispatch("notify", {"channel": {"id": "fixture"}, "event": {}}, 3)
            self.assertEqual(result, {"outcome": "accepted"})
            notify.assert_called_once_with({"id": "fixture"}, {}, timeout_seconds=3)
            with self.assertRaises(ValueError):
                worker._dispatch("notify", {"channel": {}, "unexpected": "PRIVATE"}, 3)
            self.assertEqual(notify.call_count, 1)

    def test_main_checks_input_and_wraps_a_successful_dispatch(self):
        value, signals, timer, dispatch = self.main(data=b'{"fixture":true}', value={"observed": True})
        self.assertEqual(value, SUCCESS)
        signals.assert_called_once_with(signal.SIGALRM, signal.SIG_DFL)
        self.assertEqual(timer.call_args_list[0].args, (signal.ITIMER_REAL, 1.0))
        self.assertEqual(timer.call_args_list[-1].args, (signal.ITIMER_REAL, 0))
        dispatch.assert_called_once_with("probe", {"fixture": True}, 1.0)

    def test_main_malformed_duplicate_nonfinite_and_nondictionary_input_never_dispatches(self):
        values = [b"", b"PRIVATE", b"[]", b"null", b"\xff", b'{"x":1,"x":2}',
                  b'{"x":NaN}', b'{"x":1e999}', b'{"x":' + b"9" * 5000 + b'}']
        for data in values:
            with self.subTest(data=data[:30]):
                result, _, _, dispatch = self.main(data=data)
                self.assertEqual(result, worker._failure("worker_failed"))
                dispatch.assert_not_called()
        with patch.object(worker, "MAX_INPUT", 4):
            result, _, _, dispatch = self.main(data=b"{}   ")
            self.assertEqual(result, worker._failure("worker_failed"))
            dispatch.assert_not_called()

    def test_main_dispatch_error_type_and_output_size_are_sanitized(self):
        result, _, _, _ = self.main(failure=RuntimeError("PRIVATE provider error"))
        self.assertEqual(result, worker._failure("worker_failed"))

    def test_output_budget_includes_terminating_newline(self):
        with patch.object(worker, "MAX_OUTPUT", 128):
            empty = {"ok": True, "value": {"padding": ""}, "code": None}
            length = len(worker._encoded(empty, 128))
            padding = "x" * (127 - length)
            output = io.BytesIO()
            result, _, _, _ = self.main(value={"padding": padding}, output=output)
            self.assertTrue(result["ok"])
            self.assertEqual(len(output.getvalue()), 128)
            with self.process() as (process, _, _):
                process.communicate.return_value = (output.getvalue(), None)
                self.assertEqual(worker.execute("probe", {}, 1), result)
            result, _, _, _ = self.main(value={"padding": padding + "x"})
            self.assertEqual(result, worker._failure("worker_failed"))
        result, _, _, _ = self.main(value=[])
        self.assertEqual(result, worker._failure("worker_failed"))
        with patch.object(worker, "MAX_OUTPUT", 128):
            result, _, _, _ = self.main(value={"padding": "PRIVATE" * 100})
        self.assertEqual(result, worker._failure("worker_failed"))

    def test_alarm_stays_armed_during_stdout_write_and_flush(self):
        events = []
        class Output(io.BytesIO):
            def write(self, value):
                events.append("write")
                return super().write(value)
            def flush(self):
                events.append("flush")
                return super().flush()
        output = Output()
        with patch.object(worker.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(b"{}"))), \
                patch.object(worker.sys, "stdout", SimpleNamespace(buffer=output)), \
                patch.object(worker, "_dispatch", return_value={}), patch.object(worker.signal, "signal"), \
                patch.object(worker.signal, "pthread_sigmask", side_effect=lambda *args: events.append("unblocked")), \
                patch.object(worker.signal, "setitimer", side_effect=lambda _, duration: events.append(duration)):
            worker.main(["--kind", "probe", "--timeout", "1"])
        self.assertEqual(events, ["unblocked", 1.0, "write", "flush", 0])

    def test_broken_stdout_still_clears_alarm(self):
        output = Mock()
        output.write.side_effect = BrokenPipeError("PRIVATE")
        with patch.object(worker.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(b"{}"))), \
                patch.object(worker.sys, "stdout", SimpleNamespace(buffer=output)), \
                patch.object(worker, "_dispatch", return_value={}), patch.object(worker.signal, "signal"), \
                patch.object(worker.signal, "pthread_sigmask"), \
                patch.object(worker.signal, "setitimer") as timer, self.assertRaises(BrokenPipeError):
            worker.main(["--kind", "probe", "--timeout", "1"])
        self.assertEqual(timer.call_args_list[-1].args, (signal.ITIMER_REAL, 0))

    def test_main_arguments_and_module_entrypoint(self):
        for timeout in ("0", "61", "nan"):
            result, signals, _, dispatch = self.main(arguments=["--kind", "probe", "--timeout", timeout])
            self.assertEqual(result, worker._failure("worker_failed"))
            signals.assert_not_called()
            dispatch.assert_not_called()
        for arguments in ([], ["--kind", "unknown", "--timeout", "1"]):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as invalid:
                worker.main(arguments)
            self.assertEqual(invalid.exception.code, 2)
        output = io.BytesIO()
        with patch.object(sys, "argv", ["monitor_worker", "--kind", "probe", "--timeout", "1"]), \
                patch.object(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(b"{}"))), \
                patch.object(sys, "stdout", SimpleNamespace(buffer=output)), \
                patch.object(signal, "signal"), patch.object(signal, "pthread_sigmask"), patch.object(signal, "setitimer"), \
                patch.dict(sys.modules), self.assertRaises(SystemExit) as stopped:
            sys.modules.pop("cgp_cert_manager.monitor_worker")
            runpy.run_module("cgp_cert_manager.monitor_worker", run_name="__main__")
        self.assertEqual(stopped.exception.code, 0)
        self.assertEqual(json.loads(output.getvalue())["value"]["code"], "invalid_endpoint")

    def test_execute_validates_kind_budget_descriptor_and_input_before_launch(self):
        cases = [("bad", {}, 1, None), ("probe", {}, True, None), ("probe", {}, .01, None),
                 ("probe", {}, 61, None), ("probe", {}, 1, True), ("probe", {}, 1, -1),
                 ("probe", {}, 1, 2**40)]
        with patch.object(worker.subprocess, "Popen") as start:
            for kind, payload, timeout, fd in cases:
                with self.subTest(kind=kind, timeout=timeout, fd=fd), self.assertRaises(ValueError):
                    worker.execute(kind, payload, timeout, lock_fd=fd)
            with patch.object(worker, "MAX_INPUT", 3), self.assertRaises(ValueError):
                worker.execute("probe", {"too": "large"}, 1)
            start.assert_not_called()

    def test_execute_uses_private_stdin_minimal_environment_and_closes_streams(self):
        secret = "PRIVATE-CREDENTIAL"
        original_handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        with self.process() as (process, start, stop), patch.dict(os.environ, {
                "GH_TOKEN": secret, "CF_TOKEN": secret, "PYTHONPATH": "/PRIVATE/python",
                "SSLKEYLOGFILE": "/PRIVATE/keys", "SSL_CERT_FILE": "/PRIVATE/ca",
                "HTTPS_PROXY": "https://PRIVATE"}):
            self.assertEqual(worker.execute("probe", {"credential": secret}, 1), SUCCESS)
        args, options = start.call_args
        self.assertNotIn(secret, str(args))
        self.assertNotIn(secret, str(options))
        self.assertEqual(options["env"], {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                                         "PYTHONNOUSERSITE": "1", "PYTHONPATH": str(ROOT)})
        self.assertEqual(options["pass_fds"], ())
        self.assertTrue(options["start_new_session"])
        self.assertEqual(options["stderr"], subprocess.DEVNULL)
        self.assertEqual(json.loads(process.communicate.call_args.kwargs["input"]), {"credential": secret})
        stop.assert_called_once_with(process)
        process.stdin.close.assert_called_once()
        process.stdout.close.assert_called_once()
        self.assertEqual({sig: signal.getsignal(sig) for sig in original_handlers}, original_handlers)

    def test_timeout_pulses_do_not_resend_input(self):
        with self.process() as (process, _, _):
            process.communicate.side_effect = [subprocess.TimeoutExpired("worker", .1),
                                               (json.dumps(SUCCESS).encode(), None)]
            self.assertEqual(worker.execute("probe", {"fixture": True}, 1), SUCCESS)
        self.assertIsNotNone(process.communicate.call_args_list[0].kwargs["input"])
        self.assertIsNone(process.communicate.call_args_list[1].kwargs["input"])
        self.assertLessEqual(process.communicate.call_args_list[0].kwargs["timeout"], .1)

    def test_inherited_lock_is_duplicated_and_closed_only_after_child_quiescence(self):
        with tempfile.TemporaryFile() as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            for launch_error in (False, True):
                events, inherited = [], []
                with self.subTest(launch_error=launch_error), self.process() as (process, start, stop):
                    def begin(command, **options):
                        fd, = options["pass_fds"]
                        inherited.append(fd)
                        self.assertGreaterEqual(fd, 3)
                        self.assertNotEqual(fd, lock.fileno())
                        self.assertEqual(os.fstat(fd).st_ino, os.fstat(lock.fileno()).st_ino)
                        if launch_error:
                            raise OSError("PRIVATE")
                        return process
                    start.side_effect = begin
                    stop.side_effect = lambda process: events.append("quiesced")
                    process.stdin.close.side_effect = lambda: events.append("stdin closed")
                    process.stdout.close.side_effect = lambda: events.append("stdout closed")
                    original_close = os.close
                    def close(fd):
                        events.append("lock duplicate closed")
                        original_close(fd)
                    with patch.object(worker.os, "close", side_effect=close):
                        result = worker.execute("probe", {}, 1, lock_fd=lock.fileno())
                    self.assertEqual(result, worker._failure("worker_start_failed") if launch_error else SUCCESS)
                    expected = [] if launch_error else ["quiesced", "stdin closed", "stdout closed"]
                    self.assertEqual(events, expected + ["lock duplicate closed"])
                    with self.assertRaises(OSError):
                        os.fstat(inherited[0])
                    self.assertGreater(os.fstat(lock.fileno()).st_nlink, -1)

    def test_lock_duplication_failure_and_interrupt_after_duplicate_close_are_safe(self):
        with patch.object(worker.fcntl, "fcntl", side_effect=OSError("PRIVATE")), \
                patch.object(worker.subprocess, "Popen") as start:
            self.assertEqual(worker.execute("probe", {}, 1, lock_fd=3), worker._failure("worker_start_failed"))
            start.assert_not_called()
        def failed_duplication(*args):
            os.kill(os.getpid(), signal.SIGTERM)
            raise OSError("PRIVATE")
        with patch.object(worker.fcntl, "fcntl", side_effect=failed_duplication), self.assertRaises(KeyboardInterrupt):
            worker.execute("probe", {}, 1, lock_fd=3)
        with tempfile.TemporaryFile() as lock, self.process() as (_, _, stop):
            original_close = os.close
            def interrupted_close(fd):
                original_close(fd)
                os.kill(os.getpid(), signal.SIGINT)
            with patch.object(worker.os, "close", side_effect=interrupted_close), self.assertRaises(KeyboardInterrupt):
                worker.execute("probe", {}, 1, lock_fd=lock.fileno())
            stop.assert_called_once()

    def test_parent_deadline_and_child_exit_failures_are_not_success(self):
        with self.process() as (process, _, stop), patch.object(worker.time, "monotonic", side_effect=[0, 2]):
            self.assertEqual(worker.execute("probe", {}, 1), worker._failure("worker_timeout"))
            process.communicate.assert_not_called()
            stop.assert_called_once()
        for code, reason in ((-signal.SIGALRM, "worker_timeout"), (1, "worker_failed"), (-signal.SIGKILL, "worker_failed")):
            with self.process(returncode=code):
                self.assertEqual(worker.execute("probe", {}, 1), worker._failure(reason))

    def test_invalid_envelopes_cannot_become_checked_results(self):
        values = [[], {}, {"ok": True, "value": {}, "code": "failure"},
                  {"ok": True, "value": [], "code": None}, {"ok": False, "value": {}, "code": "worker_failed"},
                  {"ok": False, "value": None, "code": "unknown"}, {"ok": 0, "value": None, "code": "worker_failed"},
                  {"ok": 0.0, "value": None, "code": "worker_failed"}, dict(SUCCESS, extra=True)]
        for value in values:
            with self.subTest(value=value), self.process(value):
                self.assertEqual(worker.execute("probe", {}, 1), worker._failure("worker_invalid_result"))
        for raw in (b"PRIVATE malformed", b'{"ok":true,"ok":true}', b'{"x":NaN}', b"\xff"):
            with self.process() as (process, _, _):
                process.communicate.return_value = (raw, None)
                self.assertEqual(worker.execute("probe", {}, 1), worker._failure("worker_invalid_result"))
        with self.process() as (process, _, _):
            process.communicate.return_value = (b"x" * (worker.MAX_OUTPUT + 1), None)
            self.assertEqual(worker.execute("probe", {}, 1), worker._failure("worker_invalid_result"))
        with self.process(worker._failure("worker_failed")):
            self.assertEqual(worker.execute("probe", {}, 1), worker._failure("worker_failed"))

    def test_launch_failure_and_pending_interruption_restore_handlers(self):
        with patch.object(worker.subprocess, "Popen", side_effect=OSError("PRIVATE")):
            self.assertEqual(worker.execute("probe", {}, 1), worker._failure("worker_start_failed"))
        def interrupted(*args, **kwargs):
            os.kill(os.getpid(), signal.SIGTERM)
            raise OSError("PRIVATE")
        with patch.object(worker.subprocess, "Popen", side_effect=interrupted), self.assertRaises(KeyboardInterrupt):
            worker.execute("probe", {}, 1)

    def test_interrupt_during_wait_or_quiescence_or_close_is_not_swallowed(self):
        for when in ("before_wait", "after_wait", "quiesce", "close"):
            with self.subTest(when=when), self.process() as (process, start, stop):
                if when == "before_wait":
                    def begin(*args, **kwargs):
                        os.kill(os.getpid(), signal.SIGINT)
                        return process
                    start.side_effect = begin
                elif when == "after_wait":
                    def answer(*args, **kwargs):
                        os.kill(os.getpid(), signal.SIGTERM)
                        return json.dumps(SUCCESS).encode(), None
                    process.communicate.side_effect = answer
                elif when == "quiesce":
                    stop.side_effect = lambda process: os.kill(os.getpid(), signal.SIGTERM)
                else:
                    process.stdin.close.side_effect = lambda: os.kill(os.getpid(), signal.SIGINT)
                with self.assertRaises(KeyboardInterrupt):
                    worker.execute("probe", {}, 1)
                stop.assert_called_once_with(process)
                process.stdin.close.assert_called_once()
                process.stdout.close.assert_called_once()

    def test_interrupt_during_handler_restoration_is_still_observed(self):
        previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        original_signal = signal.signal
        def restore(signum, handler):
            result = original_signal(signum, handler)
            if signum == signal.SIGINT and handler == previous[signal.SIGINT]:
                # SIGTERM still has its deferring handler at this exact point.
                os.kill(os.getpid(), signal.SIGTERM)
            return result
        with self.process(), patch.object(signal, "signal", side_effect=restore), self.assertRaises(KeyboardInterrupt):
            worker.execute("probe", {}, 1)
        self.assertEqual({sig: signal.getsignal(sig) for sig in previous}, previous)

    def test_failure_to_establish_signal_supervision_never_launches_worker(self):
        with patch.object(worker.certbot_runner, "_signals", side_effect=ValueError("Unavailable signal handling")), \
                patch.object(worker.subprocess, "Popen") as start, self.assertRaises(ValueError):
            worker.execute("probe", {}, 1)
        start.assert_not_called()

    def test_uncertain_quiescence_refuses_return_and_both_streams_close_on_errors(self):
        with self.process() as (process, _, stop):
            stop.side_effect = core.Error("Cannot establish quiescence")
            with self.assertRaises(core.Error):
                worker.execute("probe", {}, 1)
            process.stdin.close.assert_called_once()
            process.stdout.close.assert_called_once()
        with self.process() as (process, _, _):
            process.stdin.close.side_effect = OSError("PRIVATE")
            with self.assertRaises(OSError):
                worker.execute("probe", {}, 1)
            process.stdout.close.assert_called_once()

    def test_real_worker_returns_safe_invalid_endpoint_without_network(self):
        result = worker.execute("probe", {}, 1)
        self.assertTrue(result["ok"])
        self.assertEqual(result["value"]["code"], "invalid_endpoint")

    def test_real_timeout_and_interrupt_reap_worker_process(self):
        original = subprocess.Popen
        for action in ("timeout", "interrupt"):
            created = []
            def launch(arguments, **kwargs):
                process = original([sys.executable, "-c", "import time; time.sleep(60)"], **kwargs)
                created.append(process)
                if action == "interrupt":
                    os.kill(os.getpid(), signal.SIGTERM)
                return process
            with self.subTest(action=action), patch.object(worker.subprocess, "Popen", side_effect=launch):
                if action == "timeout":
                    self.assertEqual(worker.execute("probe", {}, .15), worker._failure("worker_timeout"))
                else:
                    with self.assertRaises(KeyboardInterrupt):
                        worker.execute("probe", {}, .15)
            self.assertIsNotNone(created[0].poll())
            with self.assertRaises(ChildProcessError):
                os.waitpid(created[0].pid, os.WNOHANG)

    def test_kernel_alarm_bounds_blocked_stdout_without_parent_reading(self):
        source = ("from cgp_cert_manager import monitor_worker as w\n"
                  "w._dispatch=lambda *args: {'padding':'x'*(w.MAX_OUTPUT-200)}\n"
                  "w.main(['--kind','probe','--timeout','0.3'])\n")
        with subprocess.Popen([sys.executable, "-c", source], cwd=ROOT,
                              env={"PYTHONPATH": str(ROOT), "PYTHONNOUSERSITE": "1"},
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            process.stdin.write(b"{}")
            process.stdin.close()
            try:
                code = process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
                self.fail("Worker blocked on stdout after cancelling its alarm")
            self.assertEqual(code, -signal.SIGALRM)
            self.assertEqual(process.stderr.read(), b"")
            self.assertGreater(len(process.stdout.read()), 0)

    def test_parent_death_retains_lock_until_kernel_alarm_even_for_stdin_descriptor(self):
        for descriptor in ("normal", "low", "masked"):
            with self.subTest(descriptor=descriptor), tempfile.TemporaryDirectory() as tmp:
                result = subprocess.run([sys.executable, "-c", PARENT_DEATH, tmp, descriptor], cwd=ROOT,
                                        env={"PYTHONPATH": str(ROOT), "PYTHONNOUSERSITE": "1"},
                                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        text=True, timeout=10, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), {"alarm": True, "lock_retained": True, "lock_released": True})


if __name__ == "__main__":
    unittest.main()
