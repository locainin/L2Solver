"""Run real publisher operations inside an isolated disposable root filesystem."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]


def run_private_lifecycle(tmp_path, *extra):
    if os.geteuid() == 0:
        pytest.skip("requires an unprivileged caller for a private mapped user namespace")
    namespace = [
        "unshare", "--user", "--map-root-user", "--map-auto", "--mount", "--propagation", "private", "--net",
        "--pid", "--fork",
    ]
    probe = subprocess.run([*namespace, "true"], text=True, capture_output=True, timeout=10, check=False)
    if probe.returncode != 0:
        pytest.skip(f"private namespaces or subordinate UID/GID mappings unavailable: {probe.stderr.strip()}")
    parent_namespaces = {name: os.stat(f"/proc/self/ns/{name}").st_ino for name in ("user", "mnt", "net", "pid")}
    command = [
        *namespace, sys.executable, "-I", str(ROOT / "tests/scripts/namespace_install.py"),
        str(tmp_path), str(ROOT), str(os.getuid()), json.dumps(parent_namespaces), *extra,
    ]
    result = subprocess.run(command, text=True, capture_output=True, timeout=180, check=False)
    assert result.returncode == 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    return result.stdout


def test_root_lifecycle_and_file_capability_in_private_namespace(tmp_path):
    output = run_private_lifecycle(tmp_path)
    assert "private installer lifecycle passed" in output


def test_real_binaries_install_run_upgrade_and_uninstall_in_private_namespace(tmp_path):
    supplied = os.environ.get("L2_TEST_INSTALL_BINARIES")
    if not supplied:
        pytest.skip("set L2_TEST_INSTALL_BINARIES to qualify the supplied executable set")
    binaries = Path(supplied).resolve()
    for name in ("l2solver", "l2solver-active", "l2solver-active-helper"):
        assert (binaries / name).is_file(), f"missing supplied executable: {binaries / name}"
    output = run_private_lifecycle(tmp_path, str(binaries))
    assert "real executable installer lifecycle passed" in output
