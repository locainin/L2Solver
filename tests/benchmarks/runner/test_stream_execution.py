"""Stream mode uses the bundle command and independent stream validator."""

import tempfile
import unittest
from pathlib import Path

from support import write_sample

from benchmarks.runner.catalogue import load_catalogue
from benchmarks.runner.execution import run_sample

from .stream_support import write_bundle


def program(root, body):
    path = root / "analyzer"
    path.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
    path.chmod(0o700)
    return path


class StreamExecutionTests(unittest.TestCase):
    def test_command_writes_validated_manifest_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, sample, metadata, capture = write_sample(root)
            bundle, _, _ = write_bundle(
                root / "generated", capture, metadata, [(1, 1, 1)], context_records=0,
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
            self.assertGreaterEqual(result["artifact_bytes"], result["output_bytes"])
            self.assertEqual(result["arguments"][0:2], ["workbench", "stream"])
            self.assertEqual(result["arguments"][-2:], ["--directory", "bundle"])
            self.assertNotIn("--output", result["arguments"])
            self.assertTrue((sample / "runs/stream-one/bundle/manifest.json").is_file())
            self.assertTrue((sample / "runs/stream-one/result.json").is_file())


if __name__ == "__main__":
    unittest.main()
