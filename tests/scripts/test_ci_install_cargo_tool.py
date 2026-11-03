"""Exercise failure handling for the pinned CI tool installer."""

import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "scripts/ci/install-cargo-tool.sh"


def test_unknown_tool_is_rejected_before_downloading(tmp_path):
    result = subprocess.run(
        ["bash", str(INSTALLER), "unknown"],
        env={**os.environ, "HOME": str(tmp_path)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "unknown" in result.stderr
    assert not (tmp_path / ".cargo/bin/unknown").exists()


def test_download_with_wrong_checksum_never_installs_a_binary(tmp_path):
    commands = tmp_path / "commands"
    commands.mkdir()
    curl = commands / "curl"
    curl.write_text(
        "#!/bin/sh\n"
        "while [ \"$1\" != --output ]; do shift; done\n"
        "printf invalid > \"$2\"\n"
    )
    curl.chmod(0o755)
    result = subprocess.run(
        ["bash", str(INSTALLER), "nextest"],
        env={**os.environ, "HOME": str(tmp_path), "PATH": f"{commands}{os.pathsep}{os.environ['PATH']}"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "FAILED" in result.stdout or "FAILED" in result.stderr
    assert not (tmp_path / ".cargo/bin/cargo-nextest").exists()
