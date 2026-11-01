"""The Linux release packager writes stable, verifiable artifacts."""

import hashlib
import json
import platform
import tarfile
import zlib
from pathlib import Path

import pytest

from benchmarks import package_release as packager
from benchmarks.package_release import ARCHIVE_NAME, package_release


def create_inputs(directory):
    binary = directory / "l2solver"
    binary.write_bytes(b"#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    helper = directory / "l2solver-active-helper"
    helper.write_bytes(b"#!/bin/sh\nexit 0\n")
    helper.chmod(0o750)
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
        assert package.getnames() == [
            "l2solver", "l2solver-active-helper", "PROVENANCE.json",
            "NOTICE-JEMALLOC.txt", "INSTALL-ACTIVE.md",
        ]
        binary_info = package.getmember("l2solver")
        assert binary_info.mode == 0o755
        assert binary_info.mtime == 0
        packaged_binary = package.extractfile(binary_info)
        assert packaged_binary is not None
        assert packaged_binary.read() == binary.read_bytes()

        helper = binary.with_name("l2solver-active-helper")
        helper_info = package.getmember(helper.name)
        assert helper_info.mode == 0o750
        assert helper_info.mtime == 0
        assert helper_info.pax_headers == {}
        packaged_helper = package.extractfile(helper_info)
        assert packaged_helper is not None
        assert packaged_helper.read() == helper.read_bytes()
        guide = package.extractfile("INSTALL-ACTIVE.md")
        assert guide is not None
        instructions = guide.read().decode("utf-8")
        assert "cap_net_raw=ep" in instructions
        assert "upgrade" in instructions.lower()
        assert "authorized operators" in instructions

        provenance_file = package.extractfile("PROVENANCE.json")
        assert provenance_file is not None
        provenance = json.load(provenance_file)

        notice_info = package.getmember("NOTICE-JEMALLOC.txt")
        assert notice_info.mode == 0o644
        assert notice_info.mtime == 0
        notices = package.extractfile(notice_info)
        assert notices is not None
        assert notices.read() == (
            Path(__file__).resolve().parents[2] / "NOTICE-JEMALLOC.txt"
        ).read_bytes()

    assert provenance == {
        "schema_version": 2,
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
            "command": "cargo build --locked --release --package l2-cli --package l2-active-linux --bin l2solver --bin l2solver-active-helper --target x86_64-unknown-linux-gnu"
        },
        "binary": {
            "name": "l2solver",
            "bytes": binary.stat().st_size,
            "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        },
        "active_helper": {
            "name": "l2solver-active-helper",
            "bytes": helper.stat().st_size,
            "sha256": hashlib.sha256(helper.read_bytes()).hexdigest(),
            "required_capability": "cap_net_raw",
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

    def write_then_change_binary(source, helper, provenance, archive):
        write_archive(source, helper, provenance, archive)
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


@pytest.mark.parametrize("kind", ["missing", "symlink", "not_executable"])
def test_package_requires_a_regular_executable_active_helper(tmp_path, kind):
    binary, lockfile = create_inputs(tmp_path)
    helper = binary.with_name("l2solver-active-helper")
    helper.unlink()
    if kind == "symlink":
        helper.symlink_to(binary)
    elif kind == "not_executable":
        helper.write_bytes(b"helper")
    output = tmp_path / "dist"
    expected = FileNotFoundError if kind == "missing" else ValueError
    with pytest.raises(expected):
        package_release(binary, lockfile, output, source_commit="a" * 40,
                        rustc_version="rustc sample", cargo_version="cargo sample")
    assert not output.exists()


def test_package_refuses_helper_changes_during_write(tmp_path, monkeypatch):
    binary, lockfile = create_inputs(tmp_path)
    helper = binary.with_name("l2solver-active-helper")
    write_archive = packager._write_archive

    def write_then_change_helper(source, active_helper, provenance, archive):
        write_archive(source, active_helper, provenance, archive)
        active_helper.write_bytes(b"changed helper")

    monkeypatch.setattr(packager, "_write_archive", write_then_change_helper)
    output = tmp_path / "dist"
    with pytest.raises(ValueError, match="inputs changed"):
        package_release(binary, lockfile, output, source_commit="a" * 40,
                        rustc_version="rustc sample", cargo_version="cargo sample")
    assert helper.read_bytes() == b"changed helper"
    assert not output.exists()


@pytest.mark.parametrize("kind", ["missing", "symlink"])
def test_package_requires_regular_allocator_notices(tmp_path, monkeypatch, kind):
    binary, lockfile = create_inputs(tmp_path)
    notices = tmp_path / "allocator-notices"
    if kind == "symlink":
        notices.symlink_to(lockfile)
    monkeypatch.setattr(packager, "NOTICE_PATH", notices)
    output = tmp_path / "dist"

    expected = FileNotFoundError if kind == "missing" else ValueError
    with pytest.raises(expected):
        package_release(
            binary,
            lockfile,
            output,
            source_commit="e" * 40,
            rustc_version="rustc sample",
            cargo_version="cargo sample",
        )

    assert not output.exists()


@pytest.mark.parametrize("byte_length", [0, 64 * 1024 + 1])
def test_package_rejects_empty_or_oversized_allocator_notices(
    tmp_path, monkeypatch, byte_length
):
    binary, lockfile = create_inputs(tmp_path)
    notices = tmp_path / "allocator-notices"
    notices.write_bytes(b"x" * byte_length)
    monkeypatch.setattr(packager, "NOTICE_PATH", notices)
    output = tmp_path / "dist"

    with pytest.raises(ValueError, match="notices must contain"):
        package_release(
            binary,
            lockfile,
            output,
            source_commit="f" * 40,
            rustc_version="rustc sample",
            cargo_version="cargo sample",
        )

    assert not output.exists()
