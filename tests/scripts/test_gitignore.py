"""Check local-data exclusions without hiding build inputs or test fixtures."""
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def repository(tmp_path):
    subprocess.run(
        ["git", "init", "--quiet", "--template=", str(tmp_path)], check=True,
        capture_output=True,
    )
    shutil.copyfile(ROOT / ".gitignore", tmp_path / ".gitignore")
    return tmp_path


@pytest.mark.parametrize("directory", [
    "pcap_samples", "tests/pcaps", "review", "docs", "notes", "reports", "investigations",
])
def test_private_directories_ignore_arbitrary_nested_files(repository, directory):
    result = subprocess.run(
        ["git", "-c", "core.excludesFile=", "check-ignore", "--no-index",
         f"{directory}/nested/arbitrary.payload"],
        cwd=repository, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr


def test_existing_local_outputs_and_private_files_remain_ignored(repository):
    paths = [
        "target/debug/l2solver", "fuzz/target/debug/harness", "fuzz/corpus/seed",
        "fuzz/artifacts/crash", "benchmarks/cache/data", "benchmarks/results/run",
        "review.zip.sha256", "review-old.zip.sha256", "review-old.manifest",
        "source.zip", "source.bundle", "capture.PCAPNG", "README.md",
        ".env.local", "trace.log", "nested/__pycache__/module.pyc",
        ".pytest_cache/state", ".ruff_cache/state",
    ]
    result = subprocess.run(
        ["git", "-c", "core.excludesFile=", "check-ignore", "--no-index", "--stdin"],
        input="\n".join(paths) + "\n", cwd=repository, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert set(result.stdout.splitlines()) == set(paths)


def test_source_and_deliberate_binary_fixtures_remain_trackable(repository):
    paths = [
        "Cargo.toml", "Cargo.lock", "NOTICE-JEMALLOC.txt", "scripts/install.sh",
        "crates/l2-cli/src/main.rs", "fuzz/fuzz_targets/ethernet.rs",
        "tests/fixtures/captures.rs", "crates/l2-active/tests/dhcp/fixtures/offer.bin",
        "benchmarks/package_release.py", ".github/workflows/release-linux.yml",
        "crates/example/review/input.bin", "crates/example/docs/input.bin",
    ]
    result = subprocess.run(
        ["git", "-c", "core.excludesFile=", "check-ignore", "--no-index", "--stdin"],
        input="\n".join(paths) + "\n", cwd=repository, capture_output=True, text=True,
    )
    assert result.returncode == 1, result.stderr
    assert result.stdout == ""


@pytest.mark.parametrize("path", [
    "sample.pcap", "sample.PCAPNG", "sample.CaP",
    "tests/fixtures/sample.pcap", "crates/example/sample.PcApNg",
    "nested/deeper/sample.cap",
])
def test_capture_files_are_ignored_at_every_directory_depth(repository, path):
    result = subprocess.run(
        ["git", "-c", "core.excludesFile=", "check-ignore", "--no-index", path],
        cwd=repository, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
