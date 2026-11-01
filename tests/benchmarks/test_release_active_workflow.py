"""The release artifact must include and exercise the native active helper."""

import io
import os
import subprocess
import tarfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_release_build_and_package_include_the_matching_helper():
    workflow = (ROOT / ".github/workflows/release-linux.yml").read_text()
    assert "--package l2-active-linux" in workflow
    assert "--bin l2solver-active-helper" in workflow
    assert "--helper-binary target/x86_64-unknown-linux-gnu/release/l2solver-active-helper" in workflow


def test_release_runs_the_extracted_application_before_upload():
    workflow = (ROOT / ".github/workflows/release-linux.yml").read_text()
    command = "bash benchmarks/check_active_release.sh"
    assert command in workflow
    assert workflow.index("Package build provenance") < workflow.index(command)
    assert workflow.index(command) < workflow.index("Upload review artifact")


def test_release_packet_gate_uses_the_main_executable_and_explicit_parent_tests():
    script = (ROOT / "benchmarks/check_active_release.sh").read_text()
    assert 'L2_TEST_MAIN_BINARY="$qualified/l2solver"' in script
    assert 'L2_TEST_ACTIVE_HELPER="$qualified/l2solver-active-helper"' in script
    assert "tests/vlan/namespace.py" in script
    for parent in (
        "dhcp::dhcp_cli_observes_owned_veth_offer_and_confirms_helper_cleanup",
        "ndp::ndp_cli_observes_owned_veth_advertisement_and_confirms_cleanup",
        "ndp::global_ndp_cli_requires_a_direct_route_and_observes_the_reply",
        "listen::receive_only_cli_commands_observe_owned_veth_frames_and_release_memberships",
        "dot1x::dot1x_cli_observes_owned_veth_request_and_confirms_cleanup",
    ):
        assert parent in script
    assert "--ignored --exact" in script


def test_release_gate_rejects_an_archive_without_a_helper_and_removes_scratch(tmp_path):
    archive = tmp_path / "missing-helper.tar.gz"
    with tarfile.open(archive, "w:gz") as package:
        contents = b"#!/bin/sh\nexit 99\n"
        entry = tarfile.TarInfo("l2solver")
        entry.mode = 0o755
        entry.size = len(contents)
        package.addfile(entry, io.BytesIO(contents))
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    result = subprocess.run(
        ["bash", str(ROOT / "benchmarks/check_active_release.sh"), str(archive)],
        cwd=ROOT,
        env={**os.environ, "TMPDIR": str(scratch)},
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode != 0
    assert "l2solver-active-helper" in result.stderr
    assert list(scratch.iterdir()) == []


def test_release_gate_rejects_missing_archive_argument():
    result = subprocess.run(
        ["bash", str(ROOT / "benchmarks/check_active_release.sh")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 2
    assert "usage:" in result.stderr
