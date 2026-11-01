"""Exercise disk observation through the real delegated cgroup runner."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from benchmarks.refine_benchmark import run_case
from benchmarks.runner.catalogue import hash_file
from benchmarks.runner.refine_fixtures import FixtureSizes, generate


@unittest.skipUnless(os.environ.get("L2_TEST_DELEGATED_SCOPE") == "1", "requires a dedicated delegated scope")
class RefineCgroupIntegrationTests(unittest.TestCase):
    def test_real_runner_samples_live_unlinked_spool_and_process(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generate(root, FixtureSizes(131072, 4096, 4096, 4096, 4096))
            for name in ("private", "receipts", "output"):
                (root / name).mkdir()
            binary = root / "tiny-workload"
            binary.write_text("#!/usr/bin/env python3\n"
                              "import tempfile,time\n"
                              "with tempfile.TemporaryFile() as spool:\n"
                              " spool.write(b'x' * 8192); spool.flush(); time.sleep(0.8)\n"
                              "raise SystemExit(3)\n")
            binary.chmod(0o700)
            (root / "plan.json").write_text(json.dumps({"source_commit": "c98ac15859d4d4036023364e0a97e0773309b321", "binary_sha256": hash_file(binary)}))
            receipt = run_case(root, binary, "near-eof")
            receipt_dir = root / "receipts" / "near-eof"
            disk = json.loads((receipt_dir / "disk-observation.json").read_text())
            retained = os.environ.get("L2_TEST_RECEIPT_DIR")
            if retained:
                for name in ("cgroup.json", "disk-observation.json"):
                    with (Path(retained) / name).open("x", encoding="utf-8") as target:
                        target.write((receipt_dir / name).read_text())
            self.assertEqual(receipt["exit_code"], 3)
            self.assertIsNone(receipt["status"])
            self.assertEqual(receipt["cgroup"]["memory_max_bytes"], 512 * 1024 * 1024)
            self.assertEqual(receipt["cgroup"]["swap_max_bytes"], 0)
            self.assertEqual(receipt["cgroup"]["oom_kill"], 0)
            self.assertEqual(receipt["monitor"]["memory_scope"], "analyzer_process_only")
            self.assertGreater(receipt["monitor"]["rss_samples"], 0)
            self.assertGreaterEqual(disk["peak_temporary_logical_bytes"], 8192)
            self.assertGreater(disk["samples"], 0)
            self.assertEqual(disk["sampling_errors"], 0)


if __name__ == "__main__":
    unittest.main()
