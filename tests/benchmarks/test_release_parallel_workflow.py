"""Check the release workflow's parallel gates and evidence handling."""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/release-linux.yml"
RUNNER_SETUP = ROOT / ".github/actions/prepare-test-runner/action.yml"
CACHE_SETUP = ROOT / ".github/actions/cache-rust-build/action.yml"


def job(name):
    workflow = WORKFLOW.read_text()
    match = re.search(rf"(?ms)^  {name}:\n(.*?)(?=^  [a-z_]+:\n|\Z)", workflow)
    assert match, f"missing {name} job"
    return match.group(1)


def test_integration_pull_requests_trigger_checks_on_the_merge_revision():
    workflow = WORKFLOW.read_text()
    pull_request = re.search(
        r"(?ms)^  pull_request:\n(.*?)(?=^  [a-z_]+:|^permissions:)",
        workflow,
    )
    assert pull_request, "integration checks require the pull_request event"
    targets = re.findall(r'^      - "([^"]+)"$', pull_request.group(1), re.MULTILINE)
    assert set(targets) == {"dev", "master"}
    # The checkout default uses GitHub's synthetic merge revision for pull requests
    for checkout in re.finditer(
        r"(?ms)^      - name: Check out the requested commit\n(.*?)(?=^      -|\Z)",
        workflow,
    ):
        assert not re.search(r"(?m)^\s+ref:", checkout.group(1))
    assert "permissions:\n  contents: read" in workflow


def test_test_shards_reuse_the_same_complete_archived_build():
    build = job("prepare_tests")
    tests = job("tests")
    assert "cargo nextest archive --workspace --all-targets --all-features --locked" in build
    assert "actions/cache/save@" in build
    # Rerunning only failed jobs must still find the successful build's cache
    assert "github.run_attempt" not in build
    assert "needs: prepare_tests" in tests
    assert "shard: [1, 2, 3, 4, 5, 6, 7, 8]" in tests
    assert "fail-fast: false" in tests
    assert "actions/cache/restore@" in tests
    assert "github.run_attempt" not in tests
    assert "fail-on-cache-miss: true" in tests
    assert "--archive-file" in tests
    assert '--extract-to "$GITHUB_WORKSPACE"' in tests
    assert "--partition hash:${{ matrix.shard }}/8" in tests
    assert "--test-threads 2" in tests
    assert "--no-fail-fast" in tests
    assert "--no-tests fail" in tests
    assert "--status-level slow" in tests
    assert "--final-status-level slow" in tests
    assert "if: always()" in tests
    assert "junit.xml" in tests


def test_python_regressions_run_once_without_waiting_for_the_release_build():
    python = job("python")
    assert "needs:" not in python
    assert "runs-on: ubuntu-24.04" in python
    assert "Check out the requested commit" in python
    assert "persist-credentials: false" in python
    assert "rustup toolchain install 1.99.1 --profile minimal" in python
    assert "rustup default 1.99.1" in python
    assert "uses: ./.github/actions/prepare-test-runner" in python
    assert 'CARGO_INCREMENTAL: "0"' in python

    command = (
        "/usr/bin/python3 -m pytest -q tests/benchmarks tests/scripts tests/crates "
        '-p subtests --junitxml="$RUNNER_TEMP/python-regressions.xml"'
    )
    assert command in " ".join(python.split())
    assert " ".join(WORKFLOW.read_text().split()).count(command) == 1

    receipt_step = python.split("- name: Upload Python test results", 1)[1]
    assert "if: always()" in receipt_step
    assert "actions/upload-artifact@" in receipt_step
    assert "python-regressions.xml" in receipt_step
    assert "if-no-files-found: ignore" in receipt_step


def test_delegated_cgroup_cases_remain_required_during_package_qualification():
    package = job("package")
    assert "for variant in explicit default; do" in package
    assert "test_owned_scope_records_resolved_working_directory[$variant]" in package
    assert "L2_TEST_DELEGATED_SCOPE=1" in package
    assert "test_real_runner_samples_live_unlinked_spool_and_process" in package


def test_package_runs_the_real_binary_installer_after_build_and_rejects_skips():
    package = job("package")
    build = package.index("- name: Build Linux release candidate")
    install = package.index("- name: Qualify real executable installation privately")
    provenance = package.index("- name: Package build provenance and checksum")
    assert build < install < provenance
    step = package[install:provenance]
    assert "L2_TEST_INSTALL_BINARIES:" in step
    assert "target/x86_64-unknown-linux-gnu/release" in step
    assert "test_real_binaries_install_run_upgrade_and_uninstall_in_private_namespace" in step
    assert '--junitxml="$INSTALLER_JUNIT"' in step
    assert 'case.find("skipped")' in step
    assert "installer qualification must execute exactly one passing case" in step
    receipts = package.split("- name: Upload diagnostic receipts", 1)[1]
    assert "real-installer.xml" in receipts


def test_all_validation_jobs_are_required_before_a_tag_candidate_is_uploaded():
    review = job("review")
    assert "needs: [tests, python, quality, compatibility, dependencies, fuzz, package]" in review
    assert "github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')" in review
    assert "Upload unqualified review candidate" in review
    assert "actions/cache/restore@" in review
    assert "github.run_attempt" not in review
    assert "fail-on-cache-miss: true" in review
    assert "unqualified-review" in review
    # Failed package checks must still leave any reports already produced
    package = job("package")
    receipt_step = package.split("- name: Upload diagnostic receipts", 1)[1].split("\n      - name:", 1)[0]
    assert "if: always()" in receipt_step
    assert "qualification.json" in receipt_step
    assert "python-regressions.xml" not in receipt_step
    assert not re.search(r"(?m)^\s*\$\{\{ runner.temp \}\}/l2solver-qualification/$", receipt_step)
    assert "if-no-files-found: ignore" in receipt_step


def test_qualified_and_compatible_compilers_and_excluded_fuzz_tests_are_checked():
    for name in ("prepare_tests", "python", "quality", "dependencies", "package"):
        assert "rustup toolchain install 1.99.1" in job(name)
    compatibility = job("compatibility")
    assert "toolchain: [1.96.0, stable]" in compatibility
    assert "cargo check --workspace --all-targets --all-features --locked" in compatibility
    fuzz = job("fuzz")
    assert "nightly-2026-08-01" in fuzz
    assert "cargo test --manifest-path fuzz/Cargo.toml --tests --locked" in fuzz


def test_registry_cache_and_job_timeouts_have_scoped_keys():
    cache = CACHE_SETUP.read_text()
    # The pinned action keys by compiler, host, manifests and both lockfiles
    assert "Swatinem/rust-cache@d1527c8f67ef9af357290475d4af4b0fab8f12e0" in cache
    assert "shared-key: ${{ inputs.role }}" in cache
    assert 'cache-targets: "true"' in cache
    assert 'cache-bin: "false"' in cache
    assert "save-if: ${{ github.ref == 'refs/heads/dev' }}" in cache
    for name in ("prepare_tests", "quality", "compatibility", "fuzz", "package"):
        assert "uses: ./.github/actions/cache-rust-build" in job(name)
    assert 'workspace: "fuzz -> target"' in job("fuzz")
    for name in ("prepare_tests", "tests", "python", "quality", "compatibility", "dependencies", "fuzz", "package", "review"):
        assert "timeout-minutes: 20" in job(name)


def test_test_and_quality_jobs_use_small_nonincremental_debug_artifacts():
    for name in ("prepare_tests", "tests", "quality"):
        selected_job = job(name)
        assert 'CARGO_PROFILE_DEV_DEBUG: "0"' in selected_job
        assert 'CARGO_PROFILE_TEST_DEBUG: "0"' in selected_job
        assert 'CARGO_INCREMENTAL: "0"' in selected_job
    # The shipping build keeps the release profile declared by the workspace
    assert "CARGO_PROFILE_RELEASE_DEBUG" not in WORKFLOW.read_text()
    assert "CARGO_PROFILE_DEV_DEBUG" not in job("package")


def test_shared_runner_setup_keeps_namespace_and_user_service_preflight():
    setup = RUNNER_SETUP.read_text()
    for name in ("tests", "package"):
        assert "uses: ./.github/actions/prepare-test-runner" in job(name)
    for package in ("apparmor", "dbus-user-session", "ethtool", "fish", "iproute2", "iputils-ping", "libcap2-bin", "libpcap-dev", "python3-pytest-subtests", "python3-scapy", "ripgrep", "strace", "tcpdump", "tshark", "zsh"):
        assert package in setup.split()
    assert "profile l2solver-ci-unshare /usr/bin/unshare flags=(unconfined)" in setup
    assert "sudo apparmor_parser --replace" in setup
    assert "unshare --user --map-root-user --net --mount --pid --mount-proc --fork true" in setup
    assert "sudo systemctl start" in setup
    assert "apparmor_restrict_unprivileged_userns" not in setup
