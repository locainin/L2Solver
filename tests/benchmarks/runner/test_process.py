"""Process supervision keeps deadlines and retained logs bounded."""

import json
import os
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import benchmarks.runner.process as process_module
from benchmarks.runner.process import _CapturedStream, run_child


def run_with_group_signal_observer(command, directory, timeout):
    original_popen = process_module.subprocess.Popen
    original_killpg = os.killpg
    children = []
    signal_states = []

    def recording_popen(*args, **kwargs):
        child = original_popen(*args, **kwargs)
        children.append(child)
        return child

    def recording_killpg(process_group, requested_signal):
        if children and process_group == children[0].pid:
            signal_states.append(children[0].returncode)
        return original_killpg(process_group, requested_signal)

    with (
        patch.object(
            process_module.subprocess, "Popen", side_effect=recording_popen
        ),
        patch.object(process_module.os, "killpg", side_effect=recording_killpg),
    ):
        result = run_child(command, directory, timeout)
    return result, signal_states, children[0]


class ProcessTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "linux", "requires Linux process metrics")
    def test_child_cpu_and_io_metrics_cover_analyzer_work(self):
        with tempfile.TemporaryDirectory() as directory:
            payload_size = 262_144
            command = [
                sys.executable,
                "-c",
                textwrap.dedent(
                    f"""
                    import os
                    payload = b'x' * {payload_size}
                    with open('input.bin', 'wb') as target:
                        target.write(payload)
                        target.flush()
                        os.fsync(target.fileno())
                    with open('input.bin', 'rb') as source:
                        observed = source.read()
                    checksum = 0
                    for value in range(500_000):
                        checksum = (checksum + value) & 0xffffffff
                    with open('output.bin', 'wb') as target:
                        target.write(observed)
                        target.flush()
                        os.fsync(target.fileno())
                    """
                ),
            ]

            result = run_child(command, Path(directory), 5)

            self.assertEqual(result[:3], (0, None, None))
            metrics = result[3]
            self.assertGreater(metrics["user_cpu_seconds"], 0)
            self.assertGreaterEqual(metrics["system_cpu_seconds"], 0)
            self.assertEqual(
                metrics["cpu_measurement_scope"],
                "rusage_children_delta_for_waited_children",
            )
            self.assertIsNotNone(metrics["process_io_bytes"])
            self.assertGreaterEqual(metrics["io_samples"], 1)
            self.assertEqual(
                set(metrics["process_io_bytes"]),
                {"rchar_bytes", "wchar_bytes", "read_bytes", "write_bytes"},
            )
            self.assertGreaterEqual(
                metrics["process_io_bytes"]["rchar_bytes"], payload_size
            )
            self.assertGreaterEqual(
                metrics["process_io_bytes"]["wchar_bytes"], payload_size * 2
            )

    def test_exit_drains_all_buffered_chunks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log_path = root / "stdout.log"
            pipe_read, pipe_write = os.pipe()
            os.set_blocking(pipe_read, False)
            with log_path.open("wb") as log:
                stream = _CapturedStream(
                    "stdout", os.fdopen(pipe_read, "rb", buffering=0), log, log_path
                )
                state = {"exited": False, "chunks": 0}
                tail_chunk = b"x" * process_module._LOG_READ_CHUNK_BYTES

                def capture_tail(captured, _maximum, _deadline):
                    if not state["exited"]:
                        return False, None
                    if state["chunks"] < 3:
                        captured.log.write(tail_chunk)
                        captured.log.flush()
                        captured.retained_bytes += len(tail_chunk)
                        state["chunks"] += 1
                        return True, None
                    captured.eof = True
                    return False, None

                class ExitedChild:
                    pid = 1
                    returncode = 0

                def observe_exit(_child):
                    state["exited"] = True
                    return True

                try:
                    with (
                        patch.object(
                            process_module, "_capture_available", side_effect=capture_tail
                        ),
                        patch.object(
                            process_module, "_child_exit_observed", observe_exit
                        ),
                        patch.object(process_module, "sampled_rss", return_value=None),
                        patch.object(process_module, "stop_owned_processes"),
                    ):
                        result = process_module.monitor(
                            ExitedChild(),
                            [stream],
                            time.monotonic() + 5,
                            4 * process_module._LOG_READ_CHUNK_BYTES,
                        )
                finally:
                    stream.pipe.close()
                    os.close(pipe_write)

            self.assertEqual(result[:3], (0, None, None))
            self.assertTrue(result[3]["log_capture_complete"])
            self.assertEqual(state["chunks"], 3)
            self.assertEqual(log_path.stat().st_size, 3 * len(tail_chunk))

    def test_accepted_exits_retain_both_streams(self):
        for code in (0, 3):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                command = [
                    sys.executable,
                    "-c",
                    "import os,sys; os.write(1,b'out'); os.write(2,b'err'); sys.exit("
                    + str(code)
                    + ")",
                ]
                result = run_child(command, Path(directory), 2)

                self.assertEqual(result[:3], (code, None, None))
                self.assertTrue(result[3]["log_capture_complete"])
                self.assertEqual((Path(directory) / "stdout.log").read_bytes(), b"out")
                self.assertEqual((Path(directory) / "stderr.log").read_bytes(), b"err")

    @unittest.skipUnless(
        process_module._HAS_WAITID_WNOWAIT,
        "requires POSIX waitid with WNOWAIT",
    )
    def test_cleanup_signals_before_child_reaping(self):
        with tempfile.TemporaryDirectory() as directory:
            result, signal_states, child = run_with_group_signal_observer(
                [sys.executable, "-c", "pass"], Path(directory), 2
            )

            self.assertEqual(result[:3], (0, None, None))
            self.assertEqual(signal_states, [None])
            self.assertEqual(child.returncode, 0)

    @unittest.skipUnless(
        process_module._HAS_WAITID_WNOWAIT,
        "requires POSIX waitid with WNOWAIT",
    )
    def test_timeout_signals_before_child_reaping(self):
        with tempfile.TemporaryDirectory() as directory:
            result, signal_states, child = run_with_group_signal_observer(
                [sys.executable, "-c", "import time; time.sleep(10)"],
                Path(directory),
                0.05,
            )

            self.assertEqual(result[1], "timeout")
            self.assertEqual(signal_states, [None])
            self.assertIsNotNone(child.returncode)

    def test_logs_enforce_exact_byte_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            exact = run_child(
                [sys.executable, "-c", "import os; os.write(1,b'abcdef')"],
                root,
                2,
                log_prefix="exact",
                max_log_bytes=6,
            )
            self.assertEqual(exact[:3], (0, None, None))
            self.assertEqual((root / "exact.stdout.log").read_bytes(), b"abcdef")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            over = run_child(
                [sys.executable, "-c", "import os; os.write(1,b'abcdefg')"],
                root,
                2,
                max_log_bytes=6,
            )
            self.assertEqual(over[1], "tool_failure")
            self.assertFalse(over[3]["log_capture_complete"])
            self.assertEqual((root / "stdout.log").read_bytes(), b"abcdef")

    def test_exit_drains_large_stdout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            maximum = 4 * 1024 * 1024
            result = run_child(
                [
                    sys.executable,
                    "-c",
                    f"import os; os.write(1,b'x'*{maximum})",
                ],
                root,
                2,
                max_log_bytes=maximum,
            )

            self.assertEqual(result[:3], (0, None, None))
            self.assertTrue(result[3]["log_capture_complete"])
            self.assertEqual((root / "stdout.log").stat().st_size, maximum)

    def test_replaced_logs_cannot_hide_output(self):
        with tempfile.TemporaryDirectory() as directory:
            command = [
                sys.executable,
                "-c",
                "import os; os.unlink('stdout.log'); open('stdout.log','wb').close(); os.write(1,b'x'*(4*1024*1024))",
            ]
            result = run_child(command, Path(directory), 2, max_log_bytes=1024)

            self.assertEqual(result[1], "tool_failure")
            self.assertFalse(result[3]["log_capture_complete"])
            self.assertIn("log", result[2].lower())

    def test_late_completion_counts_as_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            original_sleep = time.sleep

            def delayed_sleep(_seconds):
                original_sleep(0.1)

            with patch(
                "benchmarks.runner.process.time.sleep", side_effect=delayed_sleep
            ):
                result = run_child(
                    [sys.executable, "-c", "import time; time.sleep(0.05)"],
                    Path(directory),
                    0.01,
                )

            self.assertEqual(result[1], "timeout")

    def test_timeout_includes_analyzer_process_startup(self):
        with tempfile.TemporaryDirectory() as directory:
            original_popen = subprocess.Popen

            def delayed_popen(*args, **kwargs):
                time.sleep(0.25)
                return original_popen(*args, **kwargs)

            with patch(
                "benchmarks.runner.process.subprocess.Popen", side_effect=delayed_popen
            ):
                result = run_child(
                    [sys.executable, "-c", "import time; time.sleep(0.02)"],
                    Path(directory),
                    0.1,
                )

            self.assertEqual(result[1], "timeout")

    @unittest.skipUnless(os.name == "posix", "requires POSIX process sessions")
    def test_timeout_bounds_escaped_writer_draining(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = Path(__file__).resolve().parents[3]
            wrapper_code = textwrap.dedent(
                """
                import json, sys, time
                from pathlib import Path
                import benchmarks.runner.process as process_module
                from benchmarks.runner.process import run_child

                directory = Path(sys.argv[1])
                capture_available = process_module._capture_available

                def slowed_capture(*args, **kwargs):
                    result = capture_available(*args, **kwargs)
                    if result[0]:
                        time.sleep(0.001)
                    return result

                process_module._capture_available = slowed_capture
                child_code = r'''import os,time
                with open('analyzer.pid','w') as marker:
                    marker.write(str(os.getpid()))
                pid = os.fork()
                if pid == 0:
                    os.setsid()
                    with open('escaped.pid','w') as marker:
                        marker.write(str(os.getpid()))
                    import threading
                    payload = b'x' * (1024 * 1024)

                    def write_forever():
                        while True:
                            os.write(2, payload)

                    writers = [threading.Thread(target=write_forever) for _ in range(4)]
                    for writer in writers:
                        writer.start()
                    for writer in writers:
                        writer.join()
                time.sleep(10)'''
                result = run_child(
                    [sys.executable, '-c', child_code],
                    directory,
                    0.2,
                    max_log_bytes=1 << 40,
                )
                details = {
                    'result': result[:3],
                    'stderr_bytes': (directory / 'stderr.log').stat().st_size,
                }
                (directory / 'result.json').write_text(json.dumps(details))
                """
            )
            wrapper = subprocess.Popen(
                [sys.executable, "-c", wrapper_code, str(root)],
                cwd=repository,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            started = time.monotonic()
            try:
                try:
                    wrapper.wait(timeout=1.2)
                except subprocess.TimeoutExpired:
                    wrapper.kill()
                    wrapper.wait()
                elapsed = time.monotonic() - started

                self.assertEqual(
                    wrapper.returncode, 0, "run_child cleanup did not return"
                )
                self.assertLess(elapsed, 0.9)
                details = json.loads((root / "result.json").read_text())
                self.assertEqual(details["result"][1], "timeout")
                self.assertGreater(details["stderr_bytes"], 0)
                self.assertTrue((root / "escaped.pid").exists())
            finally:
                if wrapper.poll() is None:
                    wrapper.kill()
                    wrapper.wait()
                for pid_path in (root / "escaped.pid", root / "analyzer.pid"):
                    if pid_path.exists():
                        try:
                            os.kill(int(pid_path.read_text()), signal.SIGKILL)
                        except ProcessLookupError:
                            pass

    @unittest.skipUnless(os.name == "posix", "requires POSIX process sessions")
    def test_escaped_writers_mark_logs_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pid_path = root / "escaped.pid"
            command = [
                sys.executable,
                "-c",
                (
                    "import os,time\n"
                    "pid=os.fork()\n"
                    "if pid == 0:\n"
                    " os.setsid()\n"
                    " with open('escaped.pid','w') as marker: marker.write(str(os.getpid()))\n"
                    " time.sleep(0.2)\n"
                    " os.write(2,b'late')\n"
                    " time.sleep(5)\n"
                    "else:\n"
                    " while not os.path.exists('escaped.pid'): time.sleep(0.001)"
                ),
            ]
            started = time.monotonic()
            try:
                result = run_child(command, root, 2)
                elapsed = time.monotonic() - started

                self.assertEqual(result[0], 0)
                self.assertEqual(result[1], "tool_failure")
                self.assertIn("incomplete", result[2].lower())
                self.assertFalse(result[3]["log_capture_complete"])
                self.assertLess(elapsed, 2)
                self.assertTrue(pid_path.exists())
            finally:
                if pid_path.exists():
                    try:
                        os.kill(int(pid_path.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass


if __name__ == "__main__":
    unittest.main()
