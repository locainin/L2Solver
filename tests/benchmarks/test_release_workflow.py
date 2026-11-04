"""Exercise the release workflow's generated shell completion checks."""

import os
import re
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SHELLS = ("bash", "zsh", "fish")
missing_shells = [shell for shell in SHELLS if shutil.which(shell) is None]
pytestmark = pytest.mark.skipif(
    bool(missing_shells), reason=f"native shell parsers unavailable: {missing_shells}"
)


@pytest.fixture
def completion_check(tmp_path):
    workflow = (ROOT / ".github/workflows/release-linux.yml").read_text()
    match = re.search(
        r"(?m)^      - name: Check generated completion syntax\n"
        r"        shell: bash\n        run: \|\n((?:          .+\n)+)",
        workflow,
    )
    assert match, "release workflow must run all native completion parsers"
    binary = tmp_path / "target/x86_64-unknown-linux-gnu/release/l2solver"
    binary.parent.mkdir(parents=True)
    # A small fake generator lets each real shell exercise its own syntax errors
    binary.write_text(
        "#!/bin/sh\n"
        'if [ "$2" = "$L2_TEST_BAD_SHELL" ]; then\n'
        '    if [ "$L2_TEST_BAD_MODE" = generator ]; then exit 7; fi\n'
        '    if [ "$L2_TEST_BAD_MODE" = empty ]; then exit 0; fi\n'
        # A condition makes the unfinished block invalid in each supported shell
        "    printf 'if true\\n'\n"
        "else\n"
        "    printf 'echo complete\\n'\n"
        "fi\n"
    )
    binary.chmod(0o755)
    return textwrap.dedent(match.group(1))


def run_check(script, root, *, shell="", mode=""):
    return subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", script],
        cwd=root,
        env={**os.environ, "L2_TEST_BAD_SHELL": shell, "L2_TEST_BAD_MODE": mode},
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )


def test_release_completion_check_accepts_valid_scripts(completion_check, tmp_path):
    result = run_check(completion_check, tmp_path)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("shell", SHELLS)
def test_release_completion_check_rejects_each_shells_invalid_script(
    completion_check, tmp_path, shell
):
    result = run_check(completion_check, tmp_path, shell=shell, mode="syntax")
    assert result.returncode != 0, f"{shell} accepted invalid syntax"


@pytest.mark.parametrize("shell", SHELLS)
def test_release_completion_check_rejects_each_generator_failure(
    completion_check, tmp_path, shell
):
    result = run_check(completion_check, tmp_path, shell=shell, mode="generator")
    assert result.returncode != 0, f"{shell} generator failure was hidden by a pipe"


@pytest.mark.parametrize("shell", SHELLS)
def test_release_completion_check_rejects_each_empty_script(
    completion_check, tmp_path, shell
):
    result = run_check(completion_check, tmp_path, shell=shell, mode="empty")
    assert result.returncode != 0, f"{shell} completion script was empty"


def test_namespace_suite_has_runtime_tools_and_user_manager_before_execution():
    workflow = (ROOT / ".github/workflows/release-linux.yml").read_text()
    requirements = (ROOT / ".github/actions/prepare-test-runner/action.yml").read_text()
    suite = workflow.index("      - name: Run workspace tests with Nextest")
    assert workflow.rindex("uses: ./.github/actions/prepare-test-runner", 0, suite) < suite
    assert "Prepare isolated-test user services" in requirements
    for package in ("iproute2", "python3-scapy", "tcpdump", "iputils-ping", "ethtool", "libcap2-bin", "libpcap-dev", "dbus-user-session"):
        assert package in requirements, f"missing namespace/runtime dependency: {package}"
    assert "libsqlite3-dev" not in requirements
