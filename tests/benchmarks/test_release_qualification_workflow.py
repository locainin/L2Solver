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


def test_candidate_upload_requires_a_version_tag_and_excludes_manual_source_checks():
    workflow = (ROOT / ".github/workflows/release-linux.yml").read_text()
    upload_step = workflow[workflow.index("- name: Upload unqualified review candidate"):]
    condition = re.search(r"(?m)^        if: (.+)$", upload_step)
    assert condition is not None
    assert condition.group(1) == (
        "github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')"
    )


def test_workflow_validates_development_pushes_and_pull_requests():
    workflow = (ROOT / ".github/workflows/release-linux.yml").read_text()
    events = workflow.split("\npermissions:", 1)[0]
    assert re.search(r'(?m)^  push:\n    branches:\n      - "dev"\n    tags:\n      - "v\*"$', events)
    assert re.search(r'(?m)^  pull_request:\n    branches:\n      - "dev"$', events)
    assert re.search(r"(?m)^  workflow_dispatch:$", events)


def test_frozen_dependency_checks_fetch_both_locked_workspaces_first():
    workflow = (ROOT / ".github/workflows/release-linux.yml").read_text()
    policy = workflow[workflow.index("- name: Check dependency policy"):]
    policy = policy.split("\n      - name:", 1)[0]
    commands = [line.strip() for line in policy.splitlines()]
    first_check = commands.index("cargo deny --frozen check")
    for command in ("cargo fetch --locked", "cargo fetch --locked --manifest-path fuzz/Cargo.toml"):
        assert command in commands
        assert commands.index(command) < first_check
    assert "cargo deny --frozen --manifest-path fuzz/Cargo.toml check" in commands


def test_network_tests_require_scoped_namespace_permission_and_a_real_probe():
    workflow = (ROOT / ".github/workflows/release-linux.yml").read_text()
    setup = workflow[workflow.index("- name: Permit isolated test namespaces"):]
    setup = setup.split("\n      - name:", 1)[0]
    assert "profile l2solver-ci-unshare /usr/bin/unshare flags=(unconfined)" in setup
    assert "userns," in setup
    load = setup.index('sudo apparmor_parser --replace "$namespace_profile"')
    probe = setup.index(
        "unshare --user --map-root-user --net --mount --pid --mount-proc --fork true"
    )
    assert load < probe
    assert workflow.index(setup) < workflow.index("- name: Run workspace tests with Nextest")
    assert "apparmor_restrict_unprivileged_userns" not in workflow
    assert "systemctl stop apparmor" not in workflow


def test_namespace_labs_have_required_tools_and_nextest_collects_all_failures():
    workflow = (ROOT / ".github/workflows/release-linux.yml").read_text()
    tools = workflow[workflow.index("- name: Install candidate check tools"):]
    tools = tools.split("\n      - name:", 1)[0]
    for required in ("ripgrep", "strace"):
        assert required in tools.split()
    nextest = workflow[workflow.index("- name: Run workspace tests with Nextest"):]
    nextest = nextest.split("\n      - name:", 1)[0]
    assert "--no-fail-fast" in nextest.split()


def test_runner_prerequisites_and_python_fail_before_the_full_rust_suite():
    workflow = (ROOT / ".github/workflows/release-linux.yml").read_text()
    services = workflow.index("- name: Prepare isolated-test user services")
    scopes = workflow.index("- name: Qualify delegated-scope Python cases")
    clippy = workflow.index("- name: Check workspace Clippy")
    release = workflow.index("- name: Build Linux release candidate")
    python = workflow.index("- name: Run Python benchmark regressions")
    nextest = workflow.index("- name: Run workspace tests with Nextest")
    assert services < scopes < clippy
    assert release < python < nextest


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
    assert workflow.index("cargo nextest run") < workflow.index("cargo test --workspace --doc")
    assert "cargo doc --workspace --all-features --no-deps --locked" in workflow
    assert workflow.count("RUSTDOCFLAGS: -D warnings") >= 2
