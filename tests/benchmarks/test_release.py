"""Release gates compose the existing independent validator and preserve source identity."""

import json
import tempfile
import unittest
from pathlib import Path

import pytest
from support import case_for, program, write_sample

from benchmarks.release import compare_coverage, load_baseline, main


@pytest.mark.parametrize("version", [True, 1.0, "1", None])
def test_baseline_requires_integer_schema_version(tmp_path, version):
    # Keep the coverage valid so rejection depends on the version field
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({
        "schema_version": version,
        "passed": True,
        "coverage": [{
            "sample_id": "generated",
            "source_sha256": "a" * 64,
            "mode": "index",
            "frames_seen": 1,
            "retained_records": 1,
            "retention_complete": True,
            "status": "complete",
        }],
    }))

    with pytest.raises(ValueError, match="version 1 release receipt"):
        load_baseline(baseline, 4096)


class ReleaseTests(unittest.TestCase):
    def test_release_saves_coverage_prevents_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, metadata, capture = write_sample(root)
            binary = program(
                root,
                "import pathlib,sys\npathlib.Path(sys.argv[-1]).write_text("
                + repr(json.dumps(case_for(metadata, capture)))
                + ")\n",
            )
            output = root / "release"
            arguments = [
                "--binary",
                str(binary),
                "--catalogue",
                str(catalogue),
                "--mode",
                "case",
                "--directory",
                str(output),
                "--run-id",
                "release-test",
            ]
            self.assertEqual(main(arguments), 0)
            report = json.loads((output / "release.json").read_text())
            self.assertTrue(report["passed"])
            self.assertEqual(report["coverage"][0]["retained_records"], 1)
            self.assertEqual(
                report["coverage"][0]["source_sha256"], metadata["capture_sha256"]
            )
            self.assertEqual(main(arguments), 2)
            compared = root / "compared"
            self.assertEqual(
                main(
                    [
                        "--binary",
                        str(binary),
                        "--catalogue",
                        str(catalogue),
                        "--mode",
                        "case",
                        "--directory",
                        str(compared),
                        "--run-id",
                        "compared-test",
                        "--baseline",
                        str(output / "release.json"),
                    ]
                ),
                0,
            )

    def test_baseline_comparison_detects_regressions(
        self,
    ):
        baseline = [
            {
                "sample_id": "generated",
                "mode": "stream",
                "source_sha256": "a",
                "retained_records": 10,
                "retention_complete": True,
                "analysis_complete": True,
            }
        ]
        current = [{**baseline[0], "retained_records": 9, "retention_complete": False}]
        issues = compare_coverage(current, baseline)
        self.assertTrue(any("retention" in issue for issue in issues))
        changed = [{**baseline[0], "source_sha256": "b"}]
        self.assertTrue(
            any(
                "source changed" in issue
                for issue in compare_coverage(changed, baseline)
            )
        )

    def test_duplicate_work_rejected_before_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, _, _ = write_sample(root)
            binary = program(root, "raise SystemExit(2)\n")
            output = root / "release"
            self.assertEqual(
                main(
                    [
                        "--binary",
                        str(binary),
                        "--catalogue",
                        str(catalogue),
                        "--catalogue",
                        str(catalogue),
                        "--mode",
                        "case",
                        "--directory",
                        str(output),
                    ]
                ),
                2,
            )
            self.assertFalse(output.exists())

    def test_baseline_matches_aliased_source_identity(self):
        baseline = [
            {
                "sample_id": "old-name",
                "mode": "stream",
                "source_sha256": "a",
                "retained_records": 10,
            }
        ]
        current = [
            {**baseline[0], "sample_id": "renamed"},
            {**baseline[0], "source_sha256": "b", "retained_records": 1},
        ]
        self.assertEqual(compare_coverage(current, baseline), [])

    def test_release_records_owned_artifact_footprint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, metadata, capture = write_sample(root)
            binary = program(
                root,
                "import pathlib,sys\npathlib.Path(sys.argv[-1]).write_text("
                + repr(json.dumps(case_for(metadata, capture)))
                + ")\n",
            )
            output = root / "release"
            self.assertEqual(
                main(
                    [
                        "--binary",
                        str(binary),
                        "--catalogue",
                        str(catalogue),
                        "--mode",
                        "case",
                        "--directory",
                        str(output),
                        "--run-id",
                        "footprint",
                    ]
                ),
                0,
            )
            report = json.loads((output / "release.json").read_text())
            artifacts = list(root.rglob("case.json"))
            self.assertEqual(len(artifacts), 1)
            self.assertEqual(
                report["coverage"][0]["artifact_bytes"],
                sum(
                    path.stat().st_size
                    for path in artifacts[0].parent.rglob("*")
                    if path.is_file() and path.name != "result.json"
                ),
            )

    def test_malformed_baselines_rejected_before_work(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, metadata, capture = write_sample(root)
            binary = program(
                root,
                "import pathlib,sys\npathlib.Path(sys.argv[-1]).write_text("
                + repr(json.dumps(case_for(metadata, capture)))
                + ")\n",
            )
            for index, value in enumerate(
                [
                    {"coverage": []},
                    {"schema_version": 1, "passed": True, "coverage": []},
                    {
                        "schema_version": 1,
                        "passed": True,
                        "coverage": [{"sample_id": "bad", "source_sha256": "bad"}],
                    },
                ]
            ):
                with self.subTest(baseline=value):
                    baseline = root / f"baseline-{index}.json"
                    baseline.write_text(json.dumps(value))
                    output = root / f"release-{index}"
                    self.assertEqual(
                        main(
                            [
                                "--binary",
                                str(binary),
                                "--catalogue",
                                str(catalogue),
                                "--mode",
                                "case",
                                "--directory",
                                str(output),
                                "--run-id",
                                f"invalid-{index}",
                                "--baseline",
                                str(baseline),
                            ]
                        ),
                        2,
                    )
                    self.assertFalse(output.exists())


@pytest.mark.parametrize("receipt", ["result", "stage"])
def test_rejects_receipts_with_different_binary(
    tmp_path, monkeypatch, receipt
):
    from benchmarks import release

    catalogue, _, metadata, capture = write_sample(tmp_path)
    binary = program(
        tmp_path,
        "import pathlib,sys\npathlib.Path(sys.argv[-1]).write_text("
        + repr(json.dumps(case_for(metadata, capture)))
        + ")\n",
    )
    original_main = release.run.main

    def run_with_different_binary_receipt(arguments):
        # Keep the real analyzer and validator path, then simulate a replaced subrun binary
        code = original_main(arguments)
        directory = Path(arguments[arguments.index("--results-directory") + 1])
        run_id = arguments[arguments.index("--run-id") + 1]
        summary = directory / f"{run_id}.json"
        report = json.loads(summary.read_text())
        if receipt == "result":
            report["results"][0]["binary_sha256"] = "0" * 64
        else:
            report["results"][0]["stages"] = {"index": {"binary_sha256": "0" * 64}}
        summary.write_text(json.dumps(report))
        return code

    monkeypatch.setattr(release.run, "main", run_with_different_binary_receipt)
    output = tmp_path / "release"
    assert (
        main(
            [
                "--binary",
                str(binary),
                "--catalogue",
                str(catalogue),
                "--mode",
                "case",
                "--directory",
                str(output),
                "--run-id",
                "binary-receipt",
            ]
        )
        == 1
    )
    report = json.loads((output / "release.json").read_text())
    assert report["passed"] is False
    if receipt == "result":
        assert report["coverage"][0]["binary_sha256"] == "0" * 64
    else:
        assert report["coverage"][0]["stage_binary_sha256s"]["index"] == "0" * 64


def test_rejects_workset_changes_after_preflight(
    tmp_path, monkeypatch
):
    import hashlib

    from benchmarks import release

    catalogue, _, _, _ = write_sample(tmp_path)
    _, alternate, metadata, capture = write_sample(tmp_path / "alternate")
    capture = capture[:-1] + b"g"
    metadata["capture_sha256"] = hashlib.sha256(capture).hexdigest()
    (alternate / "capture.pcap").write_bytes(capture)
    (alternate / "source.json").write_text(json.dumps(metadata))
    binary = program(
        tmp_path,
        "import pathlib,sys\npathlib.Path(sys.argv[-1]).write_text("
        + repr(json.dumps(case_for(metadata, capture)))
        + ")\n",
    )
    original_main = release.run.main

    def run_after_catalogue_replacement(arguments):
        document = json.loads(catalogue.read_text())
        document["sources"] = [str((alternate / "source.json").relative_to(tmp_path))]
        catalogue.write_text(json.dumps(document))
        return original_main(arguments)

    monkeypatch.setattr(release.run, "main", run_after_catalogue_replacement)
    output = tmp_path / "release"
    assert (
        main(
            [
                "--binary",
                str(binary),
                "--catalogue",
                str(catalogue),
                "--mode",
                "case",
                "--directory",
                str(output),
                "--run-id",
                "changed-workset",
            ]
        )
        == 1
    )
    report = json.loads((output / "release.json").read_text())
    assert report["passed"] is False


@pytest.mark.parametrize("mode", ["case", "stream"])
@pytest.mark.parametrize("analysis", ["absent", None])
def test_application_baseline_requires_analysis_coverage(tmp_path, mode, analysis):
    row = {
        "sample_id": "generated",
        "source_sha256": "a" * 64,
        "mode": mode,
        "frames_seen": 1,
        "retained_records": 1,
        "retention_complete": True,
        "status": "partial",
    }
    if analysis != "absent":
        row["analysis_complete"] = analysis
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"schema_version": 1, "passed": True, "coverage": [row]}))

    with pytest.raises(ValueError, match="analysis coverage"):
        load_baseline(path, 4096)


@pytest.mark.parametrize("analysis", ["absent", None])
def test_index_baseline_accepts_absent_analysis(tmp_path, analysis):
    row = {
        "sample_id": "generated",
        "source_sha256": "a" * 64,
        "mode": "index",
        "frames_seen": 1,
        "retained_records": 1,
        "retention_complete": True,
        "status": "complete",
    }
    if analysis != "absent":
        row["analysis_complete"] = analysis
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"schema_version": 1, "passed": True, "coverage": [row]}))

    assert load_baseline(path, 4096)["coverage"] == [row]


def test_analysis_regression_overrides_complete_retention():
    previous = {
        "sample_id": "generated", "mode": "stream", "source_sha256": "a" * 64,
        "retained_records": 1, "analysis_complete": True,
    }
    current = {**previous, "analysis_complete": False}

    assert compare_coverage([current], [previous]) == [
        f"analysis coverage regressed: {('a' * 64, 'stream')}"
    ]


def test_input_budget_checked_before_hashing(tmp_path, monkeypatch):
    from benchmarks.runner import catalogue as loader

    first, _, metadata, _ = write_sample(tmp_path / "first")
    second, _, _, _ = write_sample(tmp_path / "second")
    binary = program(tmp_path, "raise SystemExit(2)\n")
    output = tmp_path / "release"

    def unexpected_hash(_path, **_options):
        pytest.fail("global input budget must be checked before capture verification")

    monkeypatch.setattr(loader, "hash_file", unexpected_hash)
    assert main([
        "--binary", str(binary), "--catalogue", str(first), "--catalogue", str(second),
        "--mode", "case", "--directory", str(output),
        "--max-input-bytes", str(metadata["capture_bytes"] * 2 - 1),
    ]) == 2
    assert not output.exists()


def test_input_budget_deduplicates_shared_paths(tmp_path):
    import shutil

    from tests.benchmarks.runner.stream_support import write_bundle

    catalogue, _, metadata, capture = write_sample(tmp_path)
    alias = tmp_path / "alias.json"
    shutil.copyfile(catalogue, alias)
    bundle, _, _ = write_bundle(tmp_path / "template", capture, metadata, [(1, 1, 1)], context_records=0)
    body = (
        "import pathlib,shutil,sys\n"
        "if sys.argv[2] == 'build':\n"
        "    pathlib.Path(sys.argv[-1]).write_text(" + repr(json.dumps(case_for(metadata, capture))) + ")\n"
        "else:\n"
        "    shutil.copytree(" + repr(str(bundle)) + ", sys.argv[-1])\n"
    )
    binary = program(tmp_path, body)
    output = tmp_path / "release"

    assert main([
        "--binary", str(binary), "--catalogue", str(catalogue), "--catalogue", str(alias),
        "--mode", "case", "--mode", "stream", "--directory", str(output), "--run-id", "budgets",
        "--max-capture-bytes", str(len(capture)), "--max-input-bytes", str(len(capture)),
        "--max-metadata-bytes", "4096",
    ]) == 0
    report = json.loads((output / "release.json").read_text())
    assert len(report["coverage"]) == 2
    assert len(report["duplicate_source_aliases"]) == 2
    assert report["input_limits"] == {
        "max_metadata_bytes": 4096, "max_capture_bytes": len(capture), "max_input_bytes": len(capture),
    }
    for stage in report["stages"]:
        assert "--max-input-bytes" in stage["arguments"]


@pytest.mark.parametrize("analysis", [True, False])
def test_index_baseline_rejects_application_analysis(tmp_path, analysis):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({
        "schema_version": 1, "passed": True,
        "coverage": [{
            "sample_id": "generated", "source_sha256": "a" * 64, "mode": "index",
            "frames_seen": 1, "retained_records": 1, "retention_complete": True,
            "status": "complete", "analysis_complete": analysis,
        }],
    }))

    with pytest.raises(ValueError, match="analysis coverage"):
        load_baseline(path, 4096)


def test_metadata_budget_checked_before_hashing(tmp_path, monkeypatch):
    from benchmarks import release

    catalogue, _, _, _ = write_sample(tmp_path)
    document = json.loads(catalogue.read_text())
    document["description"] = "x" * 2048
    catalogue.write_text(json.dumps(document))
    binary = program(tmp_path, "raise SystemExit(2)\n")
    original_hash = release.hash_file

    def guard_catalogue_hash(path, **options):
        if path == catalogue:
            pytest.fail("oversized catalogue must be rejected before hashing")
        return original_hash(path, **options)

    monkeypatch.setattr(release, "hash_file", guard_catalogue_hash)
    output = tmp_path / "release"
    assert main([
        "--binary", str(binary), "--catalogue", str(catalogue), "--mode", "case",
        "--directory", str(output), "--max-metadata-bytes", "1024",
    ]) == 2
    assert not output.exists()


def test_nonregular_catalogue_rejected_before_hashing(tmp_path, monkeypatch):
    import os

    from benchmarks import release

    if not hasattr(os, "mkfifo"):
        pytest.skip("named pipes are unavailable")
    catalogue = tmp_path / "catalogue.json"
    os.mkfifo(catalogue)
    binary = program(tmp_path, "raise SystemExit(2)\n")
    original_hash = release.hash_file

    def guard_catalogue_hash(path, **options):
        if path == catalogue:
            pytest.fail("nonregular catalogue must be rejected before hashing")
        return original_hash(path, **options)

    monkeypatch.setattr(release, "hash_file", guard_catalogue_hash)
    output = tmp_path / "release"
    assert main([
        "--binary", str(binary), "--catalogue", str(catalogue), "--mode", "case",
        "--directory", str(output),
    ]) == 2
    assert not output.exists()


@pytest.mark.parametrize("change", ["growth", "truncation", "removal", "content"])
def test_bounded_integrity_failures_preserve_receipts(
    tmp_path, monkeypatch, change
):
    from benchmarks import release

    catalogue, sample, metadata, capture = write_sample(tmp_path)
    source = sample / "capture.pcap"
    binary = program(tmp_path, "import pathlib,sys\npathlib.Path(sys.argv[-1]).write_text("
                     + repr(json.dumps(case_for(metadata, capture))) + ")\n")
    original_main = release.run.main
    original_hash = release.hash_file

    def run_then_change_source(arguments):
        code = original_main(arguments)
        if change == "growth":
            with source.open("ab") as stream:
                stream.write(b"x")
        elif change == "truncation":
            source.write_bytes(capture[:-1])
        elif change == "content":
            source.write_bytes(capture[:-1] + b"x")
        else:
            source.unlink()
        return code

    def bounded_source_hash(path, **options):
        if path == source:
            assert options.get("expected_bytes") == len(capture)
        return original_hash(path, **options)

    monkeypatch.setattr(release.run, "main", run_then_change_source)
    monkeypatch.setattr(release, "hash_file", bounded_source_hash)
    output = tmp_path / "release"
    assert main([
        "--binary", str(binary), "--catalogue", str(catalogue), "--mode", "case",
        "--directory", str(output), "--run-id", "changed-source",
    ]) == 1
    receipt = json.loads((output / "release.json").read_text())
    assert receipt["passed"] is False
    integrity = receipt["source_integrity"][0]
    assert integrity["before_sha256"] == metadata["capture_sha256"]
    if change == "content":
        assert integrity["after_sha256"] != metadata["capture_sha256"]
        assert integrity["after_sha256"] is not None
    else:
        assert integrity["after_sha256"] is None
        assert integrity["error"]
