"""Check the real custom benchmark's discovery contract for both test runners."""
import json
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[4]


@pytest.fixture(scope="module")
def benchmark():
    result = subprocess.run(
        ["cargo", "test", "-p", "l2-cli", "--bench", "offline", "--all-features", "--locked", "--no-run", "--message-format=json"],
        cwd=ROOT, check=True, capture_output=True, text=True,
    )
    return next(
        item["executable"]
        for line in result.stdout.splitlines()
        if (item := json.loads(line)).get("executable") and item.get("target", {}).get("name") == "offline"
    )


@pytest.mark.parametrize("ignored, expected", [(False, "ethernet_lldp: benchmark\n"), (True, "")])
def test_discovery_lists_benchmark_without_running_workload(benchmark, ignored, expected):
    args = [benchmark, "--list", "--format", "terse"]
    if ignored:
        args.append("--ignored")
    result = subprocess.run(args, capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stderr
    assert result.stdout == expected
