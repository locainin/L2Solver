"""The Linux release packager writes stable, verifiable artifacts."""

import hashlib
import json
import platform
import tarfile
import zlib

import pytest

from benchmarks import package_release as packager
from benchmarks.package_release import ARCHIVE_NAME, package_release


def create_inputs(directory):
    binary = directory / "l2solver"
    binary.write_bytes(b"#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    lockfile = directory / "Cargo.lock"
    lockfile.write_bytes(b"version = 4\n")
    return binary, lockfile


def test_package_records_provenance_and_one_checksum_per_deliverable(tmp_path):
    binary, lockfile = create_inputs(tmp_path)
    output = tmp_path / "dist"

    archive, checksum = package_release(
        binary,
        lockfile,
        output,
        source_commit="a" * 40,
        rustc_version="rustc 1.99.1 (sample)",
        cargo_version="cargo 1.99.1 (sample)",
    )

    assert archive.name == ARCHIVE_NAME
    archive_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    assert checksum.read_text(encoding="ascii") == f"{archive_digest}  {archive.name}\n"

    with tarfile.open(archive, "r:gz") as package:
        assert package.getnames() == ["l2solver", "PROVENANCE.json"]
        binary_info = package.getmember("l2solver")
        assert binary_info.mode == 0o755
        assert binary_info.mtime == 0
        packaged_binary = package.extractfile(binary_info)
        assert packaged_binary is not None
        assert packaged_binary.read() == binary.read_bytes()

        provenance_file = package.extractfile("PROVENANCE.json")
        assert provenance_file is not None
        provenance = json.load(provenance_file)

    assert provenance == {
        "schema_version": 1,
        "source_commit": "a" * 40,
        "toolchain": {
            "rustc": "rustc 1.99.1 (sample)",
            "cargo": "cargo 1.99.1 (sample)",
        },
        "packager": {
            "python": platform.python_version(),
            "zlib": zlib.ZLIB_VERSION,
        },
        "target": "x86_64-unknown-linux-gnu",
        "dependency_lock": {
            "path": "Cargo.lock",
            "sha256": hashlib.sha256(lockfile.read_bytes()).hexdigest(),
        },
        "build": {
            "command": "cargo build --locked --release --package l2-cli --target x86_64-unknown-linux-gnu"
        },
        "binary": {
            "name": "l2solver",
            "bytes": binary.stat().st_size,
            "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        },
    }


def test_package_archive_is_byte_for_byte_repeatable(tmp_path):
    binary, lockfile = create_inputs(tmp_path)
    metadata = {
        "source_commit": "b" * 40,
        "rustc_version": "rustc 1.99.1 (sample)",
        "cargo_version": "cargo 1.99.1 (sample)",
    }

    first, _ = package_release(binary, lockfile, tmp_path / "first", **metadata)
    second, _ = package_release(binary, lockfile, tmp_path / "second", **metadata)

    assert first.read_bytes() == second.read_bytes()


def test_package_refuses_existing_output_and_symlinked_binary(tmp_path):
    binary, lockfile = create_inputs(tmp_path)
    output = tmp_path / "existing"
    output.mkdir()
    sentinel = output / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")

    with pytest.raises(FileExistsError):
        package_release(
            binary,
            lockfile,
            output,
            source_commit="c" * 40,
            rustc_version="rustc sample",
            cargo_version="cargo sample",
        )
    assert sentinel.read_text(encoding="utf-8") == "keep"

    link = tmp_path / "linked-binary"
    link.symlink_to(binary)
    with pytest.raises(ValueError, match="regular executable file"):
        package_release(
            link,
            lockfile,
            tmp_path / "linked-output",
            source_commit="c" * 40,
            rustc_version="rustc sample",
            cargo_version="cargo sample",
        )


def test_package_removes_partial_artifact_when_input_changes_during_write(
    tmp_path, monkeypatch
):
    binary, lockfile = create_inputs(tmp_path)
    output = tmp_path / "changed-input"
    write_archive = packager._write_archive

    def write_then_change_binary(source, provenance, archive):
        write_archive(source, provenance, archive)
        source.write_bytes(b"changed after archiving")
        source.chmod(0o755)

    monkeypatch.setattr(packager, "_write_archive", write_then_change_binary)
    with pytest.raises(ValueError, match="inputs changed"):
        package_release(
            binary,
            lockfile,
            output,
            source_commit="d" * 40,
            rustc_version="rustc sample",
            cargo_version="cargo sample",
        )

    assert not output.exists()
