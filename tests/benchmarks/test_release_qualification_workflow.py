"""A successful review artifact must follow the explicit candidate checks."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_review_upload_follows_candidate_checks_and_is_labeled_unqualified():
    workflow = (ROOT / ".github/workflows/release-linux.yml").read_text()
    package = workflow.index("- name: Package build provenance and checksum")
    candidate = workflow.index(
        "- name: Check packaged executable and record blocked release work"
    )
    upload = workflow.index("- name: Upload unqualified review candidate")
    assert package < candidate < upload
    candidate_step = workflow[candidate:upload]
    assert "benchmarks.qualification" in candidate_step
    assert "--candidate-only" in candidate_step
    upload_step = workflow[upload:]
    assert "unqualified-review" in upload_step
    assert "qualification.json" in upload_step
    assert "l2solver-qualification/elf-*/*.txt" in upload_step
    assert "l2solver-qualification/startup/*/stdout.log" in upload_step
    assert "l2solver-qualification/startup/*/stderr.log" in upload_step
    assert not re.search(r"(?m)^\s*if:\s*", upload_step)


def test_review_workflow_runs_python_doctests_and_warning_checked_rustdoc():
    workflow = (ROOT / ".github/workflows/release-linux.yml").read_text()
    assert "pytest -q tests/benchmarks" in workflow
    assert "python3-pytest-subtests" in workflow
    assert "-p subtests" in workflow
    assert "--ignore=tests/benchmarks/test_cgroup_enforcement.py" not in workflow
    assert "--ignore=tests/benchmarks/test_filesystem_fault_runner.py" not in workflow
    assert "Qualify delegated-scope Python cases" in workflow
    assert "-p Delegate=yes -p CPUQuota=100%" in workflow
    assert "L2_TEST_DELEGATED_SCOPE=1" in workflow
    assert "cargo test --workspace --doc --all-features --locked" in workflow
    assert "cargo doc --workspace --all-features --no-deps --locked" in workflow
    assert workflow.count("RUSTDOCFLAGS: -D warnings") >= 2
