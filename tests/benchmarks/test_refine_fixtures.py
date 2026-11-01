"""Exercise small versions of the five file-refinement benchmark fixtures."""

import base64
import gzip
import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from benchmarks.runner.refine_fixtures import FixtureSizes, generate, verify_fixtures


class RefineFixtureTests(unittest.TestCase):
    def test_small_fixtures_have_independently_readable_expected_contents(self):
        sizes = FixtureSizes(near_bytes=262144, archive_member_bytes=32768,
                             encoded_member_bytes=16384, refusal_random_bytes=8192,
                             refusal_zero_bytes=16384)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = generate(root, sizes)
            verify_fixtures(root, report)
            files = root / "fixtures"
            first = (files / "first.png").read_bytes()
            second = (files / "second.png").read_bytes()
            with (files / "near-eof.bin").open("rb") as source:
                source.seek(report["near_eof_offset"])
                self.assertEqual(source.read(len(first)), first)
                self.assertEqual((files / "near-eof.bin").stat().st_size, sizes.near_bytes)
            with zipfile.ZipFile(files / "large-valid.zip") as archive:
                self.assertIsNone(archive.testzip())
                self.assertEqual(archive.read("first.png"), first)
                self.assertEqual(archive.read("second.png"), second)
                self.assertEqual(len(archive.read("large.bin")), sizes.archive_member_bytes)
            with self.assertRaises(zipfile.BadZipFile):
                zipfile.ZipFile(files / "large-corrupt.zip").infolist()
            decoded = gzip.decompress(base64.b64decode((files / "encoded-gzip.txt").read_bytes(), validate=True))
            self.assertEqual(hashlib.sha256(decoded).hexdigest(), report["files"]["encoded-reference.zip"]["sha256"])
            with zipfile.ZipFile(io.BytesIO(decoded)) as archive:
                self.assertIsNone(archive.testzip())
                self.assertEqual(archive.read("first.png"), first)
            expanded = gzip.decompress((files / "output-limit.gz").read_bytes())
            self.assertTrue(expanded.endswith(first))
            self.assertEqual(hashlib.sha256(expanded).hexdigest(), report["expanded_gzip_sha256"])
            for case in ("near-eof.bin", "encoded-gzip.txt", "large-valid.zip", "large-corrupt.zip", "output-limit.gz"):
                with self.subTest(case=case):
                    self.assertEqual(hashlib.sha256((files / case).read_bytes()).hexdigest(), report["files"][case]["sha256"])
            self.assertEqual(json.loads((root / "fixtures.json").read_text()), report)

    def test_changed_fixture_is_rejected_and_existing_data_is_not_overwritten(self):
        sizes = FixtureSizes(near_bytes=131072, archive_member_bytes=4096,
                             encoded_member_bytes=4096, refusal_random_bytes=4096,
                             refusal_zero_bytes=4096)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = generate(root, sizes)
            (root / "fixtures" / "first.png").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "fixture"):
                verify_fixtures(root, report)
            with self.assertRaises((ValueError, FileExistsError)):
                generate(root, sizes)
            self.assertEqual((root / "fixtures" / "first.png").read_bytes(), b"changed")

    def test_near_eof_embedded_zip_is_checked_independently_of_source_hash(self):
        sizes = FixtureSizes(131072, 4096, 4096, 4096, 4096)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = generate(root, sizes)
            path = root / "fixtures" / "near-eof.bin"
            with path.open("r+b") as source:
                source.seek(report["near_eof_offset"] + report["files"]["first.png"]["length"] + 128)
                source.write(b"BAD!")
            report["files"][path.name]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "near-EOF.*ZIP"):
                verify_fixtures(root, report)

    def test_png_crc_is_checked_independently_of_fixture_hash(self):
        sizes = FixtureSizes(131072, 4096, 4096, 4096, 4096)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = generate(root, sizes)
            path = root / "fixtures" / "first.png"
            data = bytearray(path.read_bytes())
            data[29] ^= 1
            path.write_bytes(data)
            report["files"][path.name]["sha256"] = hashlib.sha256(data).hexdigest()
            source_path = root / "fixtures" / "near-eof.bin"
            with source_path.open("r+b") as source:
                source.seek(report["near_eof_offset"])
                source.write(data)
            report["files"][source_path.name]["sha256"] = hashlib.sha256(source_path.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "PNG"):
                verify_fixtures(root, report)


if __name__ == "__main__":
    unittest.main()
