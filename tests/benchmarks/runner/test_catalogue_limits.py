"""Input budgets apply to selected physical files before expensive verification."""

import json

import pytest
from support import write_sample

from benchmarks.runner import catalogue as loader


def combined_catalogue(root, paths, name="catalogue.json"):
    path = root / name
    path.write_text(json.dumps({
        "schema_version": 1,
        "description": "Generated catalogue",
        "sources": [str(source.relative_to(root)) for source in paths],
    }))
    return path


@pytest.mark.parametrize("field", ["max_metadata_bytes", "max_capture_bytes", "max_input_bytes"])
@pytest.mark.parametrize("value", [0, -1, True, False, 1.0, "64", None])
def test_limits_reject_invalid_byte_budgets(field, value):
    with pytest.raises(ValueError, match=field):
        loader.CatalogueLimits(**{field: value})


def test_budgets_accept_exact_capture_size(tmp_path):
    catalogue, _, metadata, _ = write_sample(tmp_path)
    size = metadata["capture_bytes"]
    limits = loader.CatalogueLimits(max_capture_bytes=size, max_input_bytes=size)

    samples = loader.load_catalogue(catalogue, limits=limits)

    assert len(samples) == 1


@pytest.mark.parametrize("field", ["max_capture_bytes", "max_input_bytes"])
def test_budgets_reject_before_capture_hashing(tmp_path, monkeypatch, field):
    catalogue, _, metadata, _ = write_sample(tmp_path)
    limits = loader.CatalogueLimits(**{field: metadata["capture_bytes"] - 1})

    def unexpected_hash(_path, **_options):
        pytest.fail("over-budget input must be rejected before hashing")

    monkeypatch.setattr(loader, "hash_file", unexpected_hash)
    with pytest.raises(ValueError, match="byte budget"):
        loader.load_catalogue(catalogue, limits=limits)


def test_selection_skips_unselected_capture_access(tmp_path):
    _, selected, metadata, _ = write_sample(tmp_path, "selected")
    _, excluded, _, _ = write_sample(tmp_path, "excluded")
    (excluded / "capture.pcap").unlink()
    catalogue = combined_catalogue(tmp_path, [selected / "source.json", excluded / "source.json"])
    limits = loader.CatalogueLimits(max_input_bytes=metadata["capture_bytes"])

    samples = loader.load_catalogue(catalogue, limits=limits, selected={"selected"})

    assert [sample.metadata["id"] for sample in samples] == ["selected"]


def test_unknown_selection_rejects_before_access(tmp_path):
    catalogue, sample, _, _ = write_sample(tmp_path)
    (sample / "capture.pcap").unlink()

    with pytest.raises(ValueError, match="unknown sample id"):
        loader.load_catalogue(catalogue, selected={"absent"})


def test_selection_rejects_duplicate_source_ids(tmp_path):
    _, first, _, _ = write_sample(tmp_path, "first")
    _, second, metadata, _ = write_sample(tmp_path, "second")
    metadata["id"] = "first"
    (second / "source.json").write_text(json.dumps(metadata))
    catalogue = combined_catalogue(tmp_path, [first / "source.json", second / "source.json"])

    with pytest.raises(ValueError, match="duplicate sample id"):
        loader.load_catalogue(catalogue, selected={"first"})


def test_metadata_budget_override_preserves_provenance(tmp_path):
    catalogue, sample, metadata, _ = write_sample(tmp_path)
    metadata["description"] = "x" * (64 * 1024)
    path = sample / "source.json"
    path.write_text(json.dumps(metadata))
    with pytest.raises(ValueError, match="JSON size"):
        loader.load_catalogue(catalogue)

    samples = loader.load_catalogue(
        catalogue, limits=loader.CatalogueLimits(max_metadata_bytes=path.stat().st_size)
    )

    assert samples[0].metadata["description"] == metadata["description"]


def test_catalogues_count_each_path_once(tmp_path, monkeypatch):
    catalogue, sample, metadata, _ = write_sample(tmp_path)
    alias = combined_catalogue(tmp_path, [sample / "source.json"], "alias.json")
    original_hash = loader.hash_file
    hashed = []

    def record_hash(path, **options):
        hashed.append(path)
        return original_hash(path, **options)

    monkeypatch.setattr(loader, "hash_file", record_hash)
    groups = loader.load_catalogues(
        [catalogue, alias], limits=loader.CatalogueLimits(max_input_bytes=metadata["capture_bytes"])
    )

    assert [len(group) for group in groups] == [1, 1]
    assert hashed == [sample / "capture.pcap"]


def test_catalogues_count_distinct_paths_separately(tmp_path, monkeypatch):
    first, _, metadata, _ = write_sample(tmp_path / "first")
    second, _, _, _ = write_sample(tmp_path / "second")
    limits = loader.CatalogueLimits(max_input_bytes=metadata["capture_bytes"] * 2 - 1)

    def unexpected_hash(_path, **_options):
        pytest.fail("global byte budget must be checked before hashing any capture")

    monkeypatch.setattr(loader, "hash_file", unexpected_hash)
    with pytest.raises(ValueError, match="input byte budget"):
        loader.load_catalogues([first, second], limits=limits)


@pytest.mark.parametrize("expected", [2, 4])
def test_hash_rejects_changed_capture_length(tmp_path, expected):
    path = tmp_path / "capture.pcap"
    path.write_bytes(b"abc")

    with pytest.raises(ValueError, match="length mismatch"):
        loader.hash_file(path, expected_bytes=expected)


def test_hash_accepts_exact_capture_length(tmp_path):
    import hashlib

    path = tmp_path / "capture.pcap"
    path.write_bytes(b"abc")

    assert loader.hash_file(path, expected_bytes=3) == hashlib.sha256(b"abc").hexdigest()


@pytest.mark.parametrize("expected", [-2, -1, True, False, "3", 1.0])
def test_hash_rejects_invalid_length_budgets(tmp_path, expected):
    with pytest.raises(ValueError, match="expected_bytes"):
        loader.hash_file(tmp_path / "absent", expected_bytes=expected)


@pytest.mark.parametrize("maximum", [2**63 - 1, 2**63, 2**128])
def test_json_handles_large_byte_budgets(tmp_path, maximum):
    path = tmp_path / "metadata.json"
    path.write_text('{}')

    assert loader.read_json(path, maximum) == {}
