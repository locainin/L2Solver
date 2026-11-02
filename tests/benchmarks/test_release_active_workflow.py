"""The release artifact must include and exercise the native active helper."""

import io
import os
import subprocess
import tarfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

REQUIRED_PARENTS = (
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
)


def test_release_build_and_package_include_the_matching_helper():
    workflow = (ROOT / ".github/workflows/release-linux.yml").read_text()
    assert "--package l2-active-linux" in workflow
    assert "--bin l2solver-active-helper" in workflow
    assert "--active-binary target/x86_64-unknown-linux-gnu/release/l2solver-active" in workflow
    assert "--helper-binary target/x86_64-unknown-linux-gnu/release/l2solver-active-helper" in workflow


def test_release_runs_the_extracted_application_before_upload():
    workflow = (ROOT / ".github/workflows/release-linux.yml").read_text()
    command = "bash benchmarks/check_active_release.sh"
    assert command in workflow
    assert workflow.index("Package build provenance") < workflow.index(command)
    assert workflow.index(command) < workflow.index("Upload unqualified review candidate")


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


def create_candidate_archive(tmp_path):
    archive = tmp_path / "candidate.tar.gz"
    with tarfile.open(archive, "w:gz") as package:
        for name in ("l2solver", "l2solver-active", "l2solver-active-helper"):
            contents = b"#!/bin/sh\nexit 99\n"
            entry = tarfile.TarInfo(name)
            entry.mode = 0o750
            entry.size = len(contents)
            package.addfile(entry, io.BytesIO(contents))
    return archive


def create_nextest_stubs(tmp_path):
    commands = tmp_path / "commands"
    commands.mkdir()
    # Keep packet tests offline while checking how the gate invokes Nextest
    cargo = commands / "cargo"
    cargo.write_text(
        "#!/bin/sh\n"
        "printf '%s|%s|%s|%s|%s\\n' \"${L2_TEST_MAIN_BINARY:-}\" \"${L2_TEST_ACTIVE_BINARY:-}\" \"$L2_TEST_ACTIVE_HELPER\" \"$CARGO_BUILD_JOBS\" \"$*\" >> \"$CARGO_CALLS\"\n"
        "[ \"$1 $2\" = 'nextest run' ] || exit 91\n"
        "case \" $* \" in *' --no-tests fail '*) ;; *) exit 92;; esac\n"
        "if [ -n \"${MISSING_PARENT:-}\" ]; then\n"
        "  case \"$*\" in *\"test(=$MISSING_PARENT)\"*) echo 'no tests to run' >&2; exit 4;; esac\n"
        "fi\n"
    )
    cargo.chmod(0o755)
    python = commands / "python3"
    python.write_text("#!/bin/sh\nprintf '%s|%s|%s\\n' \"$1\" \"$2\" \"$3\" > \"$PYTHON_CALLS\"\n")
    python.chmod(0o755)
    return commands


def test_release_gate_runs_every_exact_parent_with_the_archived_pair(tmp_path):
    archive = create_candidate_archive(tmp_path)
    commands = create_nextest_stubs(tmp_path)
    calls = tmp_path / "calls.log"
    result = subprocess.run(
        ["bash", str(ROOT / "benchmarks/check_active_release.sh"), str(archive)],
        cwd=ROOT,
        env={
            **os.environ,
            "PATH": f"{commands}{os.pathsep}{os.environ['PATH']}",
            "CARGO_CALLS": str(calls),
            "PYTHON_CALLS": str(tmp_path / "python.log"),
        },
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    entries = calls.read_text().splitlines()
    assert len(entries) == len(REQUIRED_PARENTS) + 1
    python_args = (tmp_path / "python.log").read_text().strip().split("|")
    assert python_args[0] == "crates/l2-active-cli/tests/vlan/namespace.py"
    for parent, entry in zip(REQUIRED_PARENTS, entries[:-1], strict=True):
        main, active, helper, jobs, args = entry.split("|", 4)
        assert Path(main).name == "l2solver"
        assert not active
        assert Path(helper).name == "l2solver-active-helper"
        assert Path(main).parent == Path(helper).parent
        assert python_args[1:] == [main, helper]
        assert jobs == "1"
        assert "--test-threads 1" in args
        assert "--run-ignored" not in args
        assert f"test(={parent})" in args
    main, active, helper, jobs, args = entries[-1].split("|", 4)
    assert not main
    assert Path(active).name == "l2solver-active"
    assert Path(helper).name == "l2solver-active-helper"
    assert Path(active).parent == Path(helper).parent
    assert f"test(={REQUIRED_PARENTS[0]})" in args


def test_release_gate_stops_when_any_exact_parent_is_missing(tmp_path):
    archive = create_candidate_archive(tmp_path)
    commands = create_nextest_stubs(tmp_path)
    calls = tmp_path / "calls.log"
    missing = REQUIRED_PARENTS[3]
    result = subprocess.run(
        ["bash", str(ROOT / "benchmarks/check_active_release.sh"), str(archive)],
        cwd=ROOT,
        env={
            **os.environ,
            "PATH": f"{commands}{os.pathsep}{os.environ['PATH']}",
            "CARGO_CALLS": str(calls),
            "PYTHON_CALLS": str(tmp_path / "python.log"),
            "MISSING_PARENT": missing,
        },
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode != 0
    assert "no tests to run" in result.stderr
    assert len(calls.read_text().splitlines()) == 4
