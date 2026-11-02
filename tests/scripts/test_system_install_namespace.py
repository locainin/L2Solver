"""Run real publisher operations inside an isolated disposable root filesystem."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]


def test_root_lifecycle_and_file_capability_in_private_namespace(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("requires an unprivileged caller for a private mapped user namespace")
    namespace = [
        "unshare", "--user", "--map-root-user", "--map-auto", "--mount", "--propagation", "private", "--net",
    ]
    probe = subprocess.run([*namespace, "true"], text=True, capture_output=True, timeout=10, check=False)
    if probe.returncode != 0:
        pytest.skip(f"private namespaces or subordinate UID/GID mappings unavailable: {probe.stderr.strip()}")
    parent_namespaces = {name: os.stat(f"/proc/self/ns/{name}").st_ino for name in ("user", "mnt", "net")}
    command = [
        *namespace, sys.executable, "-I", str(ROOT / "tests/scripts/namespace_install.py"),
        str(tmp_path), str(ROOT), str(os.getuid()), json.dumps(parent_namespaces),
    ]
    result = subprocess.run(command, text=True, capture_output=True, timeout=60, check=False)
    assert result.returncode == 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    assert "private installer lifecycle passed" in result.stdout
