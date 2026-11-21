"""Analyzer provenance must hold before any child command is launched."""

import base64
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from benchmarks.payload_lab.analysis import Analyzer, captured_payload, examine
from benchmarks.runner import process as process_module
from benchmarks.runner.catalogue import hash_file

RECEIVER = {"source": ["127.0.0.1", 1], "destination": ["127.0.0.1", 2]}


def tshark_analyzer(root, *, change_during_query=False):
    binary, tshark = root / "analyzer", root / "tshark"
    binary.write_bytes(b"analyzer executable bytes")
    tshark.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        f"if '-v' not in sys.argv and {change_during_query!r}:\n"
        "    with open(__file__, 'ab') as executable:\n"
        "        executable.write(b'\\n# changed\\n')\n"
        "print('TShark test version' if '-v' in sys.argv else '1\\t6f6b')\n",
        encoding="utf-8",
    )
    tshark.chmod(0o755)
    with patch("benchmarks.payload_lab.analysis.shutil.which", return_value=str(tshark)):
        return Analyzer(binary, root), tshark


class AnalysisTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "requires executable test scripts")
    def test_command_receipts_retain_metrics(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "analyzer"
            binary.write_text(
                "#!/usr/bin/env python3\n"
                "import os, sys\n"
                "os.write(1, b'out:' + b' '.join(arg.encode() for arg in sys.argv[1:]))\n"
                "os.write(2, b'err')\n",
                encoding="utf-8",
            )
            binary.chmod(0o755)

            with patch(
                "benchmarks.payload_lab.analysis.shutil.which",
                return_value=str(binary),
            ):
                analyzer = Analyzer(binary, root)

            analyzer.command("analyzer.run", ["argument"])
            self.assertTrue(analyzer.tshark_command("tshark.run", ["-n", "-v"]))

            self.assertEqual(len(analyzer.commands), 2)
            self.assertEqual(analyzer.commands[0]["command"], [str(binary.resolve()), "argument"])
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

    def test_tshark_change_before_query(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            analyzer, tshark = tshark_analyzer(root)

            tshark.write_bytes(b"changed tshark executable bytes")

            with self.assertRaisesRegex(ValueError, "TShark executable changed"):
                captured_payload(
                    analyzer,
                    SimpleNamespace(name="changed", transport="udp", wire=b"ok"),
                    RECEIVER,
                )
            self.assertEqual(analyzer.commands, [])
            self.assertFalse((root / "changed.tshark.stdout.log").exists())

    @unittest.skipUnless(os.name == "posix", "requires executable test scripts")
    def test_tshark_change_during_query(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            analyzer, _ = tshark_analyzer(root, change_during_query=True)
            analyzer.tshark_provenance()
            with self.assertRaisesRegex(ValueError, "TShark executable changed"):
                captured_payload(
                    analyzer,
                    SimpleNamespace(name="changed", transport="udp", wire=b"ok"),
                    RECEIVER,
                )
            self.assertEqual(
                [item["name"] for item in analyzer.commands],
                ["tshark.version", "changed.tshark"],
            )

    @unittest.skipUnless(os.name == "posix", "requires executable test scripts")
    def test_tshark_provenance_and_query_hash_boundaries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            analyzer, tshark = tshark_analyzer(root)
            provenance = analyzer.tshark_provenance()
            with patch("benchmarks.payload_lab.analysis.hash_file", wraps=hash_file) as observed_hash:
                for name in ("first", "second"):
                    sample = SimpleNamespace(name=name, transport="udp", wire=b"ok")
                    self.assertEqual(captured_payload(analyzer, sample, RECEIVER), [1])
            analyzer.assert_tshark_unchanged()

            self.assertEqual(provenance["version"], "TShark test version")
            self.assertEqual(provenance["sha256"], hashlib.sha256(tshark.read_bytes()).hexdigest())
            self.assertEqual(
                [item["name"] for item in analyzer.commands],
                ["tshark.version", "first.tshark", "second.tshark"],
            )
            # Two observations bracket each query
            tshark_reads = [call for call in observed_hash.call_args_list if call.args[0] == tshark.resolve()]
            self.assertEqual(len(tshark_reads), 4)

    def test_scoring_completes_without_optional_tshark(self):
        wire = b"retained offline payload"
        blob_id = "sha256:" + hashlib.sha256(wire).hexdigest()

        class AnalyzerWithoutTshark:
            def __init__(self, directory):
                self.directory = directory
                self.tshark_executable = None
                self.commands = []

            def command(self, name, arguments):
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
