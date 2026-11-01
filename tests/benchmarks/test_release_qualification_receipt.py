"""A candidate receipt must not turn missing work into a release claim."""

import hashlib

import pytest

from benchmarks.qualification import __main__ as qualification
from benchmarks.qualification.receipt import build_receipt, runner_identity_status


def test_passed_candidate_checks_do_not_claim_unrun_release_scenarios():
    receipt = build_receipt(
        {"source_commit": "a" * 40},
        {
            name: {"status": "passed"}
            for name in (
                "source_identity",
                "runner_identity",
                "package",
                "elf",
                "packaged_cli",
            )
        },
    )
    assert receipt["candidate_checks_passed"] is True
    assert receipt["release_qualified"] is False
    assert receipt["external_scenarios"]
    assert all(row["status"] == "blocked" for row in receipt["external_scenarios"])
    assert {row["id"] for row in receipt["external_scenarios"]} >= {
        "cgroup-challenge",
        "interruption-and-crash-recovery",
        "filesystem-failures",
        "concurrent-writers",
        "corrupt-cache-and-algorithm-invalidation",
        "archive-bomb-and-invalid-dimensions",
        "older-evidence-compatibility",
        "heldout-protocols",
        "large-streaming-refinement",
        "fuzzing",
        "mutation-testing",
    }


def test_blocked_or_failed_candidate_checks_cannot_pass_the_candidate_gate():
    for status in ("blocked", "failed"):
        checks = {
            name: {"status": "passed"}
            for name in (
                "source_identity",
                "runner_identity",
                "package",
                "elf",
                "packaged_cli",
            )
        }
        checks["elf"] = {"status": status}
        receipt = build_receipt({}, checks)
        assert receipt["candidate_checks_passed"] is False
        assert receipt["release_qualified"] is False


def test_missing_candidate_check_cannot_pass_the_candidate_gate():
    checks = {
        name: {"status": "passed"}
        for name in ("source_identity", "runner_identity", "package", "elf")
    }
    assert build_receipt({}, checks)["candidate_checks_passed"] is False


def test_hosted_candidate_requires_exact_image_run_and_source_identity():
    runner = {
        "image_os": "ubuntu24",
        "image_version": "20261026.354.1",
        "runner_os": "Linux",
        "runner_arch": "X64",
        "run_id": "1",
        "run_attempt": "2",
        "github_sha": "a" * 40,
    }
    assert runner_identity_status(runner, "a" * 40, hosted=True)["status"] == "passed"
    assert (
        runner_identity_status(
            {**runner, "image_version": None}, "a" * 40, hosted=True
        )["status"]
        == "blocked"
    )
    assert (
        runner_identity_status(
            {**runner, "github_sha": "b" * 40}, "a" * 40, hosted=True
        )["status"]
        == "failed"
    )
    assert (
        runner_identity_status(
            {**runner, "image_os": "ubuntu22"}, "a" * 40, hosted=True
        )["status"]
        == "failed"
    )


def test_local_candidate_does_not_claim_a_hosted_runner_identity():
    assert runner_identity_status({}, "a" * 40, hosted=False)["status"] == "passed"


def test_missing_identity_tool_writes_a_blocked_receipt(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(qualification, "ROOT", tmp_path)

    def missing_compiler():
        raise FileNotFoundError("rustc is unavailable")

    monkeypatch.setattr(qualification, "_identity", missing_compiler)
    receipt = qualification.execute(tmp_path / "package", tmp_path / "receipt")
    assert receipt["candidate_checks"]["source_identity"]["status"] == "blocked"
    assert receipt["release_qualified"] is False
    assert (tmp_path / "receipt/qualification.json").is_file()


@pytest.mark.parametrize("changed_input", ["checksum", "binary", "helper"])
def test_changed_release_input_during_candidate_checks_fails_the_receipt(
    tmp_path, monkeypatch, changed_input
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(qualification, "ROOT", tmp_path)
    package = tmp_path / "package"
    package.mkdir()
    archive = package / qualification.ARCHIVE_NAME
    archive.write_bytes(b"archive")
    archive_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    checksum = package / f"{qualification.ARCHIVE_NAME}.sha256"
    checksum.write_text(f"{archive_digest}  {archive.name}\n")
    binary = tmp_path / "candidate"
    binary.write_bytes(b"executable")
    binary_digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    helper = tmp_path / "helper"
    helper.write_bytes(b"matching helper")
    helper_digest = hashlib.sha256(helper.read_bytes()).hexdigest()
    identity = {
        "source_commit": "a" * 40,
        "lock_sha256": "b" * 64,
        "rustc_version": "rustc sample",
        "cargo_version": "cargo sample",
        "runner": {},
        "hosted": False,
    }
    monkeypatch.setattr(qualification, "_identity", lambda: identity)
    monkeypatch.setattr(
        qualification,
        "unpack_package",
        lambda *args, **kwargs: {
            "binary": binary,
            "active_helper": helper,
            "archive_sha256": archive_digest,
            "archive_bytes": archive.stat().st_size,
            "provenance": {
                "binary": {"sha256": binary_digest, "bytes": binary.stat().st_size},
                "active_helper": {"sha256": helper_digest, "bytes": helper.stat().st_size},
            },
        },
    )
    monkeypatch.setattr(qualification, "inspect_elf", lambda *args: {})

    def change_input(*args):
        selected = {"checksum": checksum, "binary": binary, "helper": helper}[changed_input]
        selected.write_bytes(b"changed\n")
        return {"status": "passed"}

    monkeypatch.setattr(qualification, "run_packaged_cli", change_input)
    receipt = qualification.execute(package, tmp_path / "receipt")
    assert receipt["candidate_checks"]["package"]["status"] == "failed"
    assert receipt["candidate_checks_passed"] is False
