"""The disk observer counts owned files and live unlinked temporary files."""

import os
import tempfile
import unittest
from pathlib import Path

from benchmarks.runner.refine_disk import DiskObserver


@unittest.skipUnless(Path("/proc/self/fd").is_dir(), "requires Linux procfs")
class DiskObserverTests(unittest.TestCase):
    def test_open_unlinked_spool_and_hard_links_are_counted_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            temporary = root / "tmp"
            temporary.mkdir()
            named = root / "named"
            named.write_bytes(b"x" * 4096)
            os.link(named, root / "another-name")
            with tempfile.TemporaryFile(dir=temporary) as spool:
                spool.write(b"y" * 8192)
                spool.flush()
                observer = DiskObserver(root, temporary, 1 << 30)
                observer.sample([os.getpid()], force=True)
                result = observer.result()
            self.assertEqual(result["samples"], 1)
            self.assertEqual(result["peak_named_logical_bytes"], 4096)
            self.assertEqual(result["peak_temporary_logical_bytes"], 8192)
            self.assertEqual(result["peak_temporary_open_files"], 1)
            self.assertEqual(result["sampling_errors"], 0)
            self.assertTrue(result["peaks_are_lower_bounds"])

    def test_limit_stops_sampling_instead_of_silently_continuing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tmp").mkdir()
            (root / "data").write_bytes(b"x" * 8192)
            observer = DiskObserver(root, root / "tmp", 1)
            with self.assertRaisesRegex(ValueError, "disk"):
                observer.sample([os.getpid()], force=True)
            self.assertTrue(observer.result()["disk_stop_requested"])


if __name__ == "__main__":
    unittest.main()
