"""Stream mode uses the bundle command and independent stream validator."""

import json
import tempfile
import unittest
from pathlib import Path

from support import program, write_sample

from benchmarks.runner.catalogue import load_catalogue
from benchmarks.runner.execution import run_sample

from .stream_support import write_bundle


def bundle_program_body(root, capture, metadata, missing_by_page=None):
    bundle, _, exit_code = write_bundle(
        root / "generated", capture, metadata, [(1, 1, 1)], context_records=0,
        missing_by_page=missing_by_page,
    )
    manifest = (bundle / "manifest.json").read_text(encoding="utf-8")
    page = (bundle / "pages/000001.json").read_text(encoding="utf-8")
    body = (
        "import pathlib, sys\n"
        "assert sys.argv[1:3] == ['workbench', 'stream']\n"
        "assert sys.argv[4:] == ['--directory', 'bundle']\n"
        "assert pathlib.Path(sys.argv[3]).is_file()\n"
        "pathlib.Path('bundle/pages').mkdir(parents=True)\n"
        "pathlib.Path('bundle/manifest.json').write_text(" + repr(manifest) + ", encoding='utf-8')\n"
        "pathlib.Path('bundle/pages/000001.json').write_text(" + repr(page) + ", encoding='utf-8')\n"
    )
    return body, exit_code


class StreamExecutionTests(unittest.TestCase):
    def test_command_writes_validated_manifest_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, sample, metadata, capture = write_sample(root)
            body, _ = bundle_program_body(root, capture, metadata)
            body += "print('stream output')\nprint('stream warning', file=sys.stderr)\n"
            analyzer = program(root, body)

            result = run_sample(load_catalogue(catalogue)[0], analyzer, "stream-one", 5, mode="stream")

            self.assertEqual(result["status"], "complete")
            self.assertEqual(result["mode"], "stream")
            self.assertGreaterEqual(result["elapsed_seconds"], result["analyzer_elapsed_seconds"])
            self.assertGreaterEqual(result["elapsed_seconds"], result["validation_seconds"])
            self.assertNotIn("binary_argument", result)
            self.assertEqual(result["validation"]["pages_checked"], 1)
            self.assertEqual(result["output_bytes"], result["bundle_bytes"])
            self.assertEqual(result["evidence_bytes"], result["bundle_bytes"])
            run_directory = sample / "runs/stream-one"
            self.assertEqual((run_directory / "stdout.log").read_bytes(), b"stream output\n")
            self.assertEqual((run_directory / "stderr.log").read_bytes(), b"stream warning\n")
            self.assertEqual(
                result["artifact_bytes"],
                result["output_bytes"] + len(b"stream output\n") + len(b"stream warning\n"),
            )
            self.assertEqual(result["arguments"][0:2], ["workbench", "stream"])
            self.assertEqual(result["arguments"][-2:], ["--directory", "bundle"])
            self.assertNotIn("--output", result["arguments"])
            self.assertTrue((sample / "runs/stream-one/bundle/manifest.json").is_file())
            self.assertTrue((sample / "runs/stream-one/result.json").is_file())

    def test_changed_or_missing_executable_fails_stream_evidence(self):
        for action in ("write_text('changed executable')", "unlink()"):
            for missing in (None, {1: (1,)}):
                with (
                    self.subTest(action=action, missing=missing),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    root = Path(directory)
                    catalogue, sample, metadata, capture = write_sample(root)
                    body, exit_code = bundle_program_body(root, capture, metadata, missing)
                    body += f"pathlib.Path(__file__).{action}\nsys.exit({exit_code})\n"
                    result = run_sample(
                        load_catalogue(catalogue)[0],
                        program(root, body),
                        "binary-changed",
                        5,
                        mode="stream",
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

    def test_unchanged_executable_allows_partial_stream(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, metadata, capture = write_sample(root)
            body, exit_code = bundle_program_body(root, capture, metadata, {1: (1,)})
            body += f"sys.exit({exit_code})\n"
            result = run_sample(
                load_catalogue(catalogue)[0], program(root, body), "partial", 5, mode="stream"
            )

            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["exit_code"], 3)
            self.assertIn("validation", result)


if __name__ == "__main__":
    unittest.main()
