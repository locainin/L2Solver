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
    assert workflow.index(command) < workflow.index("Upload unqualified review candidate")


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
        "first_hop::real_vrrp_cli_observes_claims_without_transmitting_or_leaking_by_default",
        "first_hop::real_hsrp_cli_observes_claims_without_transmitting_or_leaking_by_default",
        "switching::real_dtp_cli_observes_claims_without_transmission_or_raw_disclosure",
        "switching::real_vtp_cli_observes_claims_without_transmission_or_raw_disclosure",
        "switching::real_isl_cli_observes_claims_without_transmission_or_raw_disclosure",
        "mpls::owned_veth_mpls_cli_observes_scoped_frames_and_honors_raw_opt_in",
        "namespace_tests::real_vlan_canary_assessment_observes_forwarding_and_keeps_silence_inconclusive",
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


def test_release_gate_rejects_a_successful_harness_with_no_registered_parent_tests(tmp_path):
    archive = tmp_path / "candidate.tar.gz"
    with tarfile.open(archive, "w:gz") as package:
        for name in ("l2solver", "l2solver-active-helper"):
            contents = b"#!/bin/sh\nexit 99\n"
            entry = tarfile.TarInfo(name)
            entry.mode = 0o750
            entry.size = len(contents)
            package.addfile(entry, io.BytesIO(contents))
    commands = tmp_path / "commands"
    commands.mkdir()
    # Inject a successful empty harness listing without opening a real packet socket
    for name in ("cargo", "python3"):
        command = commands / name
        command.write_text("#!/bin/sh\nexit 0\n")
        command.chmod(0o755)
    result = subprocess.run(
        ["bash", str(ROOT / "benchmarks/check_active_release.sh"), str(archive)],
        cwd=ROOT,
        env={**os.environ, "PATH": f"{commands}{os.pathsep}{os.environ['PATH']}"},
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode != 0
    assert "not registered" in result.stderr
