"""Analyzer provenance must hold before any child command is launched."""

import base64
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from benchmarks.payload_lab.analysis import Analyzer, examine
from benchmarks.runner import process as process_module


class AnalysisTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "requires executable test scripts")
    def test_command_receipts_retain_metrics(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "analyzer"
            binary.write_bytes(b"pinned analyzer executable bytes")
            helper = root / "owned-command"
            helper.write_text(
                "#!/usr/bin/env python3\n"
                "import os, sys\n"
                "os.write(1, b'out:' + b' '.join(arg.encode() for arg in sys.argv[1:]))\n"
                "os.write(2, b'err')\n",
                encoding="utf-8",
            )
            helper.chmod(0o755)

            with patch(
                "benchmarks.payload_lab.analysis.shutil.which",
                return_value=str(helper),
            ):
                analyzer = Analyzer(binary, root)

            analyzer.command("analyzer.run", ["argument"], executable=str(helper))
            self.assertTrue(analyzer.tshark_command("tshark.run", ["-n", "-v"]))

            self.assertEqual(len(analyzer.commands), 2)
            for receipt in analyzer.commands:
                with self.subTest(command=receipt["name"]):
                    self.assertEqual(receipt["exit_code"], 0)
                    self.assertEqual(receipt["failure"], None)
                    self.assertEqual(receipt["error"], None)
                    self.assertEqual(
                        receipt["metrics"]["memory_scope"], "analyzer_process_only"
                    )
                    self.assertEqual(
                        receipt["metrics"]["process_cleanup_scope"],
                        process_module._PROCESS_CLEANUP_SCOPE,
                    )

            self.assertEqual(
                (root / "analyzer.run.stdout.log").read_bytes(), b"out:argument"
            )
            self.assertEqual(
                (root / "tshark.run.stdout.log").read_bytes(), b"out:-n -v"
            )
            self.assertEqual(
                (root / "analyzer.run.stderr.log").read_bytes(), b"err"
            )
            self.assertEqual((root / "tshark.run.stderr.log").read_bytes(), b"err")

    def test_changed_analyzer_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "analyzer"
            binary.write_bytes(b"original executable bytes")
            analyzer = Analyzer(binary, root)
            binary.write_bytes(b"changed executable bytes")
            with self.assertRaisesRegex(ValueError, "executable changed"):
                analyzer.command("changed", [])
            self.assertEqual(analyzer.commands, [])
            self.assertFalse((root / "changed.stdout.log").exists())

    def test_changed_tshark_executable_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "analyzer"
            binary.write_bytes(b"analyzer executable bytes")
            tshark = root / "tshark"
            tshark.write_bytes(b"tshark executable bytes")
            with patch("benchmarks.payload_lab.analysis.shutil.which", return_value=str(tshark)):
                analyzer = Analyzer(binary, root)

            tshark.write_bytes(b"changed tshark executable bytes")

            with self.assertRaisesRegex(ValueError, "TShark executable changed"):
                analyzer.assert_tshark_unchanged()

    def test_scoring_completes_without_optional_tshark(self):
        wire = b"retained offline payload"
        blob_id = "sha256:" + hashlib.sha256(wire).hexdigest()

        class AnalyzerWithoutTshark:
            def __init__(self, directory):
                self.directory = directory
                self.tshark_executable = None
                self.commands = []

            def command(self, name, arguments, executable=None):
                self.commands.append(name)

            def read(self, name):
                if name.endswith(".query.json"):
                    return {"matches": [{
                        "node_id": 7,
                        "blob": blob_id,
                        "packet_numbers": [1],
                        "source_ranges": [],
                        "packet_filters": [],
                    }]}
                if name.endswith(".search.json"):
                    return {"search": {
                        "candidates": [],
                        "search_exhaustive_within_plan": True,
                        "limits": {},
                        "key_tests": 0,
                    }}
                raise AssertionError(f"unexpected report read: {name}")

        with tempfile.TemporaryDirectory() as temporary:
            analyzer = AnalyzerWithoutTshark(Path(temporary))
            sample = SimpleNamespace(
                name="random-control",
                transport="udp",
                wire=wire,
                plan={"families": [], "constraints": []},
                expected=None,
            )
            receiver = {"source": ["127.0.0.1", 10001],
                        "destination": ["127.0.0.1", 10002]}
            case = {"blobs": [{
                "id": blob_id,
                "bytes_base64": base64.b64encode(wire).decode("ascii"),
            }]}

            result = examine(analyzer, sample, receiver, case)

        self.assertEqual(result["result"], "no_match_within_plan")
        self.assertIsNone(result["tshark_payload_frames"])
        self.assertFalse(result["tshark_differential"]["available"])
        self.assertNotIn("random-control.tshark", analyzer.commands)


if __name__ == "__main__":
    unittest.main()
