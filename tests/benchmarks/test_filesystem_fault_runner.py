"""The real-filesystem harness must not accept a binary with no matching tests."""

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def user_namespace():
    try:
        probe = subprocess.run(
            ["unshare", "--user", "--map-root-user", "--mount", "true"],
            capture_output=True,
            timeout=10,
            check=False,
        )
    except FileNotFoundError:
        pytest.skip("unshare is unavailable")
    if probe.returncode:
        pytest.skip("unprivileged user and mount namespaces are unavailable")


@pytest.fixture
def empty_test_binary(tmp_path):
    empty_test_binary = tmp_path / "empty-test-binary"
    empty_test_binary.write_text("#!/bin/sh\nprintf '0 tests, 0 benchmarks\\n'\n")
    empty_test_binary.chmod(0o700)
    return empty_test_binary


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux user namespaces")
def test_missing_test_names_cannot_report_filesystem_qualification(
    tmp_path, user_namespace, empty_test_binary
):
    result = subprocess.run(
        [
            "bash",
            str(ROOT / "tests/run-publish-filesystem-faults.sh"),
            str(empty_test_binary),
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )

    assert result.returncode != 0
    assert "required test" in result.stderr


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux user namespaces")
def test_missing_optional_generation_test_cannot_report_qualification(
    tmp_path, user_namespace, empty_test_binary
):
    publication_binary = tmp_path / "publication-tests"
    publication_binary.write_text(
        '#!/bin/sh\nif [ "$1" = --list ]; then printf \'%s: test\\n\' "$3"; fi\n'
    )
    publication_binary.chmod(0o700)

    result = subprocess.run(
        [
            "bash",
            str(ROOT / "tests/run-publish-filesystem-faults.sh"),
            str(publication_binary),
            str(tmp_path),
            "",
            str(empty_test_binary),
        ],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )

    assert result.returncode != 0
    assert "required test" in result.stderr


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux user namespaces")
def test_missing_optional_case_buffer_test_cannot_report_qualification(
    tmp_path, user_namespace, empty_test_binary
):
    publication_binary = tmp_path / "publication-tests"
    publication_binary.write_text(
        '#!/bin/sh\nif [ "$1" = --list ]; then printf \'%s: test\\n\' "$3"; fi\n'
    )
    publication_binary.chmod(0o700)

    result = subprocess.run(
        [
            "bash",
            str(ROOT / "tests/run-publish-filesystem-faults.sh"),
            str(publication_binary),
            str(tmp_path),
            "",
            "",
            str(empty_test_binary),
        ],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )

    assert result.returncode != 0
    assert "required test" in result.stderr


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux user namespaces")
def test_case_buffer_only_rejects_a_binary_without_the_required_test(
    tmp_path, user_namespace, empty_test_binary
):
    result = subprocess.run(
        [
            "bash",
            str(ROOT / "tests/run-publish-filesystem-faults.sh"),
            "--case-buffer-only",
            str(empty_test_binary),
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )

    assert result.returncode != 0
    assert "real_full_tmpfs_spill_preserves_previous_output_and_cleans_private_files" in result.stderr


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux user namespaces")
def test_case_buffer_only_runs_the_named_test_on_a_private_tmpfs(
    tmp_path, user_namespace
):
    test_binary = tmp_path / "case-buffer-tests"
    test_binary.write_text(
        "#!/bin/bash\n"
        "set -euo pipefail\n"
        'if [[ "$1" == --list ]]; then printf "%s: test\\n" "$3"; exit; fi\n'
        '[[ "$1" == --exact && "$3" == --nocapture ]]\n'
        '[[ $(stat -f -c %T "$L2_TEST_ENOSPC_ROOT") == tmpfs ]]\n'
        '[[ $(readlink /proc/self/ns/mnt) != "$L2_TEST_PARENT_MOUNT_NAMESPACE" ]]\n'
        'printf "%s\\n" "case-buffer fixture invoked"\n'
    )
    test_binary.chmod(0o700)

    result = subprocess.run(
        [
            "bash",
            str(ROOT / "tests/run-publish-filesystem-faults.sh"),
            "--case-buffer-only",
            str(test_binary),
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "case-buffer fixture invoked" in result.stdout
    assert list(tmp_path.glob("l2-publish-faults.*")) == []


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux user namespaces")
def test_failed_filesystem_trial_cleans_its_temporary_mountpoints(
    tmp_path, user_namespace
):
    failing_binary = tmp_path / "failing-tests"
    failing_binary.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = --list ]; then printf \'%s: test\\n\' "$3"; exit 0; fi\n'
        "exit 9\n"
    )
    failing_binary.chmod(0o700)

    result = subprocess.run(
        [
            "bash",
            str(ROOT / "tests/run-publish-filesystem-faults.sh"),
            str(failing_binary),
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )

    assert result.returncode != 0
    assert "unbound variable" not in result.stderr
    assert list(tmp_path.glob("l2-publish-faults.*")) == []
