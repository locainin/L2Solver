"""Keep packaged CLI acceptance tied to real outputs and observed status."""

import hashlib

import pytest

from benchmarks.qualification.cli import check_export, check_progress, check_stdout
from benchmarks.qualification.fixture import BODY, http_capture
from benchmarks.runner.capture import packet_index


def test_http_fixture_contains_two_independently_readable_packets():
    capture = http_capture()
    assert packet_index(capture).total == 2
    assert BODY in capture


def valid_output():
    return {
        "artifacts": [
            {"sha256": hashlib.sha256(BODY).hexdigest(), "byte_length": len(BODY)}
        ]
    }


def test_optional_missing_tshark_accepts_exact_native_bytes():
    manifest = {"tshark": {"required": False, "status": "partial"}}
    check_export(valid_output(), manifest, 0, required=False, tshark="partial")


def test_required_missing_tshark_must_return_partial_status():
    manifest = {"tshark": {"required": True, "status": "partial"}}
    check_export(valid_output(), manifest, 3, required=True, tshark="partial")
    with pytest.raises(ValueError, match="status"):
        check_export(valid_output(), manifest, 0, required=True, tshark="partial")


def test_real_tshark_must_report_complete_and_retain_expected_artifact():
    manifest = {"tshark": {"required": True, "status": "complete"}}
    check_export(valid_output(), manifest, 0, required=True, tshark="complete")
    manifest["tshark"]["status"] = "partial"
    with pytest.raises(ValueError, match="TShark"):
        check_export(valid_output(), manifest, 0, required=True, tshark="complete")


def test_missing_or_different_artifact_cannot_pass():
    manifest = {"tshark": {"required": False, "status": "partial"}}
    for artifacts in ([], [{"sha256": "0" * 64, "byte_length": len(BODY)}]):
        with pytest.raises(ValueError, match="artifact"):
            check_export(
                {"artifacts": artifacts}, manifest, 0, required=False, tshark="partial"
            )


def test_progress_requires_complete_json_events_on_stderr(tmp_path):
    path = tmp_path / "stderr.log"
    path.write_text('{"counters": {}, "phases": []}\n', encoding="utf-8")
    assert check_progress(path)["events"] == 1
    path.write_text('{"counters": {}, "phases": []}\nnot-json\n', encoding="utf-8")
    with pytest.raises(ValueError, match="progress"):
        check_progress(path)
    path.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="progress"):
        check_progress(path)


def test_stdout_reports_publication_or_reuse_separately_from_json_progress(tmp_path):
    path = tmp_path / "stdout.log"
    path.write_text("Exported 1 artifact into output\n", encoding="utf-8")
    check_stdout(path, reused=False)
    path.write_text("Reused 1 artifacts in output\n", encoding="utf-8")
    check_stdout(path, reused=True)
    with pytest.raises(ValueError, match="stdout"):
        check_stdout(path, reused=False)
    path.write_text('{"counters": {}}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="stdout"):
        check_stdout(path, reused=False)
