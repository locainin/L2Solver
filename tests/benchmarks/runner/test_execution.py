"""Generated child programs exercise real runner exit and timeout handling."""

import json
import os
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
                "import pathlib, sys\npathlib.Path(sys.argv[-1]).write_text("
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
            self.assertGreaterEqual(result["artifact_bytes"], result["output_bytes"])
            self.assertTrue((sample / "runs/run-one/result.json").is_file())
            with self.assertRaises(FileExistsError):
                run_sample(load_catalogue(catalogue)[0], binary, "run-one", 5)

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
