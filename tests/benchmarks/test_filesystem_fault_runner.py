"""The real-filesystem harness must not accept a binary with no matching tests."""

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux user namespaces")
def test_missing_test_names_cannot_report_filesystem_qualification(tmp_path):
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
    empty_test_binary = tmp_path / "empty-test-binary"
    empty_test_binary.write_text("#!/bin/sh\nprintf '0 tests, 0 benchmarks\\n'\n")
    empty_test_binary.chmod(0o700)

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
