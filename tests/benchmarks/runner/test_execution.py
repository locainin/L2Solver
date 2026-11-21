"""Generated child programs exercise real runner exit and timeout handling."""

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from support import case_for, program, write_sample

from benchmarks.runner import execution as runner_execution
from benchmarks.runner.catalogue import load_catalogue
from benchmarks.runner.execution import run_sample


class ExecutionTests(unittest.TestCase):
    def test_operator_timeout_accepts_long_budgets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, metadata, capture = write_sample(root)
            body = (
                "import pathlib, sys\npathlib.Path(sys.argv[-1]).write_text("
                + repr(json.dumps(case_for(metadata, capture)))
                + ")\n"
            )
            result = run_sample(
                load_catalogue(catalogue)[0], program(root, body), "long-budget", 7200
            )
            self.assertEqual(result["status"], "complete")

    @unittest.skipUnless(os.name == "posix", "owned process groups require POSIX")
    def test_deadline_stops_descendant_evidence_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, sample, _, _ = write_sample(root)
            child = "import pathlib,time;time.sleep(0.8);pathlib.Path('late-write').write_text('unexpected')"
            body = (
                "import pathlib,subprocess,sys,time\nsubprocess.Popen([sys.executable,'-c',"
                + repr(child)
                + "])\npathlib.Path('descendant-started').write_text('ready')\ntime.sleep(10)\n"
            )
            result = run_sample(
                load_catalogue(catalogue)[0],
                program(root, body),
                "descendant-timeout",
                0.4,
            )
            self.assertEqual(result["status"], "timeout")
            run_directory = sample / "runs/descendant-timeout"
            self.assertTrue((run_directory / "descendant-started").exists())
            time.sleep(0.7)
            self.assertFalse((run_directory / "late-write").exists())

    @unittest.skipUnless(
        Path("/proc/self/status").exists(), "RSS sampling requires Linux procfs"
    )
    def test_rss_metrics_describe_analyzer_process(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, _, _ = write_sample(root)
            result = run_sample(
                load_catalogue(catalogue)[0],
                program(
                    root,
                    "import time\nbuffer=bytearray(8*1024*1024)\ntime.sleep(0.15)\n",
                ),
                "memory-sample",
                0.5,
            )
            metrics = result["analyzer_metrics"]
            self.assertGreater(metrics["rss_samples"], 0)
            self.assertGreater(metrics["peak_sampled_rss_bytes"], 0)
            self.assertEqual(metrics["memory_scope"], "analyzer_process_only")

    def test_complete_case_uses_unique_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, sample, metadata, capture = write_sample(root)
            case = case_for(metadata, capture)
            body = (
                "import pathlib, sys\n"
                "print('analyzer output')\n"
                "print('analyzer warning', file=sys.stderr)\n"
                "pathlib.Path(sys.argv[-1]).write_text("
                + repr(json.dumps(case))
                + ")\n"
            )
            binary = program(root, body)
            validate = runner_execution.validate_output

            def slow_validation(*arguments):
                time.sleep(0.05)
                return validate(*arguments)

            with patch(
                "benchmarks.runner.execution.validate_output",
                side_effect=slow_validation,
            ):
                result = run_sample(load_catalogue(catalogue)[0], binary, "run-one", 5)
            self.assertEqual(result["status"], "complete")
            self.assertGreaterEqual(
                result["elapsed_seconds"], result["analyzer_elapsed_seconds"]
            )
            self.assertGreaterEqual(
                result["elapsed_seconds"], result["validation_seconds"]
            )
            self.assertGreaterEqual(
                result["elapsed_seconds"] - result["analyzer_elapsed_seconds"], 0.04
            )
            self.assertGreaterEqual(result["validation_seconds"], 0.04)
            self.assertNotIn("binary_argument", result)
            self.assertEqual(result["validation"]["literal_nodes_checked"], 1)
            self.assertEqual(result["output_bytes"], result["case_bytes"])
            self.assertEqual(result["evidence_bytes"], result["case_bytes"])
            run_directory = sample / "runs/run-one"
            self.assertEqual((run_directory / "stdout.log").read_bytes(), b"analyzer output\n")
            self.assertEqual((run_directory / "stderr.log").read_bytes(), b"analyzer warning\n")
            self.assertEqual(
                result["artifact_bytes"],
                result["output_bytes"] + len(b"analyzer output\n") + len(b"analyzer warning\n"),
            )
            self.assertTrue((sample / "runs/run-one/result.json").is_file())
            with self.assertRaises(FileExistsError):
                run_sample(load_catalogue(catalogue)[0], binary, "run-one", 5)

    def test_changed_or_missing_executable_fails_case_evidence(self):
        for action in ("write_text('changed executable')", "unlink()"):
            for exit_code in (0, 3):
                with (
                    self.subTest(action=action, exit_code=exit_code),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    root = Path(directory)
                    catalogue, sample, metadata, capture = write_sample(root)
                    case = case_for(metadata, capture)
                    case["collection_complete"] = exit_code == 0
                    body = (
                        "import pathlib, sys\n"
                        "pathlib.Path(sys.argv[-1]).write_text("
                        + repr(json.dumps(case))
                        + ")\n"
                        + f"pathlib.Path(__file__).{action}\n"
                        + f"sys.exit({exit_code})\n"
                    )
                    result = run_sample(
                        load_catalogue(catalogue)[0],
                        program(root, body),
                        "binary-changed",
                        5,
                    )

                    self.assertEqual(result["status"], "evidence_failure")
                    self.assertEqual(result["exit_code"], exit_code)
                    self.assertNotIn("validation", result)
                    self.assertTrue(result["error"])
                    if action.startswith("write_text"):
                        self.assertIn("executable changed", result["error"])
                    receipt = json.loads(
                        (sample / "runs/binary-changed/result.json").read_text()
                    )
                    self.assertEqual(receipt, result)

    def test_analyzer_files_named_like_logs_count_toward_output_size(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, metadata, capture = write_sample(root)
            body = (
                "import pathlib, sys\n"
                "pathlib.Path(sys.argv[-1]).write_text("
                + repr(json.dumps(case_for(metadata, capture)))
                + ")\n"
                "pathlib.Path('nested').mkdir()\n"
                "pathlib.Path('nested/stdout.log').write_bytes(b'first')\n"
                "pathlib.Path('nested/stage.stderr.log').write_bytes(b'second')\n"
                "pathlib.Path('report.stdout.log').write_bytes(b'third')\n"
            )
            result = run_sample(
                load_catalogue(catalogue)[0], program(root, body), "nested-output", 5
            )

            self.assertEqual(result["status"], "complete")
            self.assertEqual(result["output_bytes"], result["case_bytes"] + 16)
            self.assertEqual(result["artifact_bytes"], result["output_bytes"])

    def test_unchanged_executable_allows_partial_case(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, metadata, capture = write_sample(root)
            case = case_for(metadata, capture)
            case["collection_complete"] = False
            body = (
                "import pathlib, sys\n"
                "pathlib.Path(sys.argv[-1]).write_text("
                + repr(json.dumps(case))
                + ")\nsys.exit(3)\n"
            )
            result = run_sample(
                load_catalogue(catalogue)[0], program(root, body), "partial", 5
            )

            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["exit_code"], 3)
            self.assertIn("validation", result)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "named pipes require POSIX")
    def test_fifo_or_large_executable_replacement_fails_without_hanging(self):
        for action in (
            "os.unlink(__file__); os.mkfifo(__file__)",
            "os.truncate(__file__, 32 * 1024 ** 3)",
        ):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                catalogue, sample, metadata, capture = write_sample(root)
                body = (
                    "import os, pathlib, sys\n"
                    "pathlib.Path(sys.argv[-1]).write_text("
                    + repr(json.dumps(case_for(metadata, capture)))
                    + ")\n"
                    + action
                    + "\n"
                )
                binary = program(root, body)
                wrapper = (
                    "import json, sys\n"
                    "from benchmarks.runner.catalogue import load_catalogue\n"
                    "from benchmarks.runner.execution import run_sample\n"
                    "result = run_sample(load_catalogue(sys.argv[1])[0], sys.argv[2], 'changed', 1)\n"
                    "print(json.dumps(result))\n"
                )
                completed = subprocess.run(
                    [sys.executable, "-c", wrapper, str(catalogue), str(binary)],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=4,
                )

                result = json.loads(completed.stdout)
                self.assertEqual(result["status"], "evidence_failure")
                self.assertIn("executable", result["error"])
                receipt = json.loads((sample / "runs/changed/result.json").read_text())
                self.assertEqual(receipt, result)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "named pipes require POSIX")
    def test_initial_fifo_executable_is_rejected_without_hanging(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, _, _ = write_sample(root)
            binary = root / "analyzer"
            os.mkfifo(binary)
            wrapper = (
                "import sys\n"
                "from benchmarks.runner.catalogue import load_catalogue\n"
                "from benchmarks.runner.execution import run_sample\n"
                "try:\n"
                "    run_sample(load_catalogue(sys.argv[1])[0], sys.argv[2], 'fifo', 1)\n"
                "except ValueError as error:\n"
                "    print(error)\n"
                "else:\n"
                "    raise AssertionError('FIFO executable was accepted')\n"
            )
            completed = subprocess.run(
                [sys.executable, "-c", wrapper, str(catalogue), str(binary)],
                capture_output=True,
                text=True,
                check=True,
                timeout=4,
            )

            self.assertIn("not a regular file", completed.stdout)

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "no-follow opens are unavailable")
    def test_symlink_executable_replacement_fails_even_with_same_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, metadata, capture = write_sample(root)
            body = (
                "import pathlib, sys\n"
                "pathlib.Path(sys.argv[-1]).write_text("
                + repr(json.dumps(case_for(metadata, capture)))
                + ")\n"
                "current = pathlib.Path(__file__)\n"
                "backup = current.with_name('backup')\n"
                "backup.write_bytes(current.read_bytes())\n"
                "current.unlink()\n"
                "current.symlink_to(backup)\n"
            )
            result = run_sample(
                load_catalogue(catalogue)[0], program(root, body), "symlink", 5
            )

            self.assertEqual(result["status"], "evidence_failure")
            self.assertIn("executable", result["error"])

    def test_unexpected_exit_records_tool_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, _, _ = write_sample(root)
            binary = program(root, "import sys\nsys.exit(2)\n")
            result = run_sample(load_catalogue(catalogue)[0], binary, "failed", 5)
            self.assertEqual(
                (result["status"], result["exit_code"]), ("tool_failure", 2)
            )

    def test_deadline_kills_timed_out_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, _, _ = write_sample(root)
            binary = program(root, "import time\ntime.sleep(10)\n")
            result = run_sample(load_catalogue(catalogue)[0], binary, "timeout", 0.1)
            self.assertEqual(result["status"], "timeout")
            self.assertLess(result["elapsed_seconds"], 3)

    def test_wrong_packet_bounds_fail_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, metadata, capture = write_sample(root)
            case = case_for(metadata, capture)
            case["nodes"][0]["ranges"][0]["offset"] = 24
            binary = program(
                root,
                "import pathlib, sys\npathlib.Path(sys.argv[-1]).write_text("
                + repr(json.dumps(case))
                + ")\n",
            )
            result = run_sample(load_catalogue(catalogue)[0], binary, "wrong", 5)
            self.assertEqual(result["status"], "evidence_failure")
            self.assertIn("packet bounds", result["error"])
