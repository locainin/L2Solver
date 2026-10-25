"""Catalogue checks use generated files and never campaign indicators."""

import json
import tempfile
import unittest
from pathlib import Path

import pytest
from support import write_sample

from benchmarks.runner.catalogue import load_catalogue, local_file, read_json


@pytest.mark.parametrize("maximum", [-2, -1, 0, True, False, 1.0, "64", None])
def test_json_rejects_budgets_before_opening(tmp_path, maximum):
    with pytest.raises(ValueError, match="JSON byte budget"):
        read_json(tmp_path / "absent.json", maximum)


def test_archive_size_is_provenance_only(tmp_path):
    catalogue, sample, metadata, _ = write_sample(tmp_path)
    metadata["archive_bytes"] = 512 * 1024 * 1024
    (sample / "source.json").write_text(json.dumps(metadata))

    entries = load_catalogue(catalogue)

    assert len(entries) == 1
    assert entries[0].metadata["archive_bytes"] == metadata["archive_bytes"]


@pytest.mark.parametrize("archive_bytes", [0, -1, True, False, 1.0, "10", None])
def test_archive_size_requires_positive_integer(tmp_path, archive_bytes):
    catalogue, sample, metadata, _ = write_sample(tmp_path)
    metadata["archive_bytes"] = archive_bytes
    (sample / "source.json").write_text(json.dumps(metadata))

    with pytest.raises(ValueError, match="archive_bytes"):
        load_catalogue(catalogue)


class CatalogueTests(unittest.TestCase):
    def test_valid_relative_capture_is_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            catalogue, sample, source, _ = write_sample(Path(directory))
            entries = load_catalogue(catalogue)
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].capture, sample / "capture.pcap")
            self.assertEqual(entries[0].metadata, source)

    def test_calendar_year_boundaries_are_accepted(self):
        for year in (1, 2015, 9999):
            with self.subTest(year=year), tempfile.TemporaryDirectory() as directory:
                catalogue, _, _, _ = write_sample(Path(directory), year=year)
                entries = load_catalogue(catalogue)
                self.assertEqual(entries[0].metadata["year"], year)

    def test_capture_year_requires_calendar_integer(self):
        for year in (0, 10000, True, 2020.0):
            with self.subTest(year=year), tempfile.TemporaryDirectory() as directory:
                catalogue, sample, source, _ = write_sample(Path(directory))
                source["year"] = year
                (sample / "source.json").write_text(
                    json.dumps(source), encoding="utf-8"
                )
                with self.assertRaisesRegex(ValueError, "source year"):
                    load_catalogue(catalogue)

    def test_capture_hash_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            catalogue, sample, _, _ = write_sample(Path(directory))
            capture = sample / "capture.pcap"
            changed = bytearray(capture.read_bytes())
            changed[-1] ^= 1
            capture.write_bytes(changed)
            with self.assertRaisesRegex(ValueError, "capture hash"):
                load_catalogue(catalogue)

    def test_catalogue_cannot_escape_its_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalogue.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "description": "test",
                        "sources": ["../source.json"],
                    }
                )
            )
            with self.assertRaisesRegex(ValueError, "relative"):
                load_catalogue(path)

    def test_duplicate_sample_ids_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, sample, _, _ = write_sample(root)
            second_catalogue, other, _, _ = write_sample(root, "other")
            metadata = json.loads((other / "source.json").read_text())
            metadata["id"] = "generated"
            (other / "source.json").write_text(json.dumps(metadata))
            second_catalogue.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "description": "test",
                        "sources": [
                            str((sample / "source.json").relative_to(root)),
                            str((other / "source.json").relative_to(root)),
                        ],
                    }
                )
            )
            with self.assertRaisesRegex(ValueError, "duplicate"):
                load_catalogue(catalogue)


def direct_source(metadata):
    fields = (
        "id",
        "capture_file",
        "capture_sha256",
        "capture_bytes",
        "source_url",
        "acquired_utc",
        "description",
    )
    return {
        "schema_version": 2,
        **{field: metadata[field] for field in fields},
        "download_url": "https://example.org/capture.pcap",
        "license": "unknown",
    }


@pytest.mark.parametrize("relative", [None, True, 1, 1.0, [], {}, b"capture.pcap"])
def test_source_paths_reject_nonstring_values(tmp_path, relative):
    # Catalogue field types retain the same error contract as malformed values
    with pytest.raises(ValueError, match="source paths must be relative strings"):
        local_file(tmp_path, relative)


@pytest.mark.parametrize(
    ("version", "field"),
    [(1, "source_url"), (1, "archive_url"), (2, "source_url"), (2, "download_url")],
)
@pytest.mark.parametrize("value", [None, True, 1, 1.0, [], {}, "", "http://example.org/"])
def test_source_urls_preserve_validation_errors(tmp_path, version, field, value):
    catalogue, sample, metadata, _ = write_sample(tmp_path)
    if version == 2:
        metadata = direct_source(metadata)
    metadata[field] = value
    (sample / "source.json").write_text(json.dumps(metadata))

    with pytest.raises(ValueError, match=f"invalid HTTPS {field}"):
        load_catalogue(catalogue)


@pytest.mark.parametrize("field", ["source_url", "download_url", "description", "license"])
def test_direct_provenance_uses_metadata_budget(tmp_path, field):
    catalogue, sample, metadata, _ = write_sample(tmp_path)
    metadata = direct_source(metadata)
    metadata[field] = (
        "https://example.org/" + "x" * 3_000 if field.endswith("url") else "x" * 3_000
    )
    (sample / "source.json").write_text(json.dumps(metadata))

    entries = load_catalogue(catalogue)

    assert entries[0].metadata[field] == metadata[field]


def test_direct_sources_preserve_download_provenance(tmp_path):
    catalogue, sample, metadata, _ = write_sample(tmp_path)
    source = direct_source(metadata)
    (sample / "source.json").write_text(json.dumps(source))
    entries = load_catalogue(catalogue)
    assert entries[0].metadata == source
    assert entries[0].capture == sample / "capture.pcap"
    assert "archive_url" not in entries[0].metadata


def test_schema_versions_reject_boolean_values(tmp_path):
    catalogue, sample, metadata, _ = write_sample(tmp_path)
    metadata["schema_version"] = True
    (sample / "source.json").write_text(json.dumps(metadata))
    with pytest.raises(ValueError, match="source metadata"):
        load_catalogue(catalogue)
    metadata["schema_version"] = 1
    (sample / "source.json").write_text(json.dumps(metadata))
    document = json.loads(catalogue.read_text())
    document["schema_version"] = True
    catalogue.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="catalogue schema"):
        load_catalogue(catalogue)


def test_direct_sources_reject_invalid_fields(
    tmp_path,
):
    catalogue, sample, metadata, _ = write_sample(tmp_path)
    source = direct_source(metadata)
    for changed in (
        {**source, "archive_url": "https://example.org/unknown.zip"},
        {key: value for key, value in source.items() if key != "license"},
        {**source, "license": ""},
        {**source, "download_url": "http://example.org/capture.pcap"},
    ):
        (sample / "source.json").write_text(json.dumps(changed))
        with pytest.raises(ValueError):
            load_catalogue(catalogue)


def test_catalogue_accepts_many_small_sources(tmp_path):
    sources = []
    for index in range(257):
        catalogue, sample, _, _ = write_sample(tmp_path, f"sample-{index}")
        sources.append(str((sample / "source.json").relative_to(tmp_path)))
    document = {"schema_version": 1, "description": "Generated sources", "sources": sources}
    catalogue.write_text(json.dumps(document))

    samples = load_catalogue(catalogue)

    assert len(samples) == len(sources)
    assert len({sample.metadata["id"] for sample in samples}) == len(sources)
    document["sources"] = []
    catalogue.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="catalogue schema"):
        load_catalogue(catalogue)
