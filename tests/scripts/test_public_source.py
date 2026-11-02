"""Keep public commits free of captures and local development material."""
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CHECK = ROOT / "scripts/check_public_source.py"


@pytest.fixture
def repository(tmp_path):
    subprocess.run(["git", "init", "--quiet", "--template=", str(tmp_path)], check=True)
    return tmp_path


def stage(repository, name, data):
    path = repository / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    subprocess.run(["git", "add", "--", name], cwd=repository, check=True)


def check(repository):
    return subprocess.run(
        [sys.executable, str(CHECK)], cwd=repository, capture_output=True, text=True,
        timeout=10, check=False,
    )


def test_public_source_accepts_code_notices_and_generated_protocol_vectors(repository):
    for name, data in [
        ("crates/example/src/lib.rs", b"pub fn parse() {}"),
        ("tests/fixtures/input.rs", b"const INPUT: &[u8] = &[0, 1];"),
        ("NOTICE-JEMALLOC.txt", b"required attribution"),
        ("crates/example/tests/frame.bin", bytes(range(32))),
    ]:
        stage(repository, name, data)
    result = check(repository)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("name,data", [
    ("nested/sample.PCAP", b"capture"),
    ("nested/sample.pcapng.gz", b"archive"),
    ("tests/pcaps/metadata.json", b"{}"),
    ("pcap_samples/source.json", b"{}"),
    ("review/trace.json", b"{}"),
    ("docs/private.txt", b"private"),
    ("README.md", b"documentation"),
    (".env.local", b"setting"),
    ("nested/program.bin", b"\x7fELF\x02\x01"),
    ("nested/input.bin", b"\xd4\xc3\xb2\xa1\x02\x00"),
])
def test_public_source_rejects_forced_capture_or_private_material(repository, name, data):
    stage(repository, name, data)
    result = check(repository)
    assert result.returncode == 1, result.stderr
    assert name in result.stderr
