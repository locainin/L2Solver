"""The Linux release packager writes stable, verifiable artifacts."""

import hashlib
import json
import platform
import subprocess
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
    active = directory / "l2solver-active"
    active.write_bytes(b"#!/bin/sh\nexit 0\n")
    active.chmod(0o755)
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
        source_tree="b" * 40,
        rustc_version="rustc 1.99.1 (sample)",
        cargo_version="cargo 1.99.1 (sample)",
    )

    assert archive.name == ARCHIVE_NAME
    archive_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    assert checksum.read_text(encoding="ascii") == f"{archive_digest}  {archive.name}\n"

    with tarfile.open(archive, "r:gz") as package:
        assert package.getnames() == [
            "l2solver", "l2solver-active", "l2solver-active-helper", "PROVENANCE.json",
            "NOTICE-JEMALLOC.txt", "INSTALL-ACTIVE.md",
        ]
        binary_info = package.getmember("l2solver")
        assert binary_info.mode == 0o755
        assert binary_info.mtime == 0
        packaged_binary = package.extractfile(binary_info)
        assert packaged_binary is not None
        assert packaged_binary.read() == binary.read_bytes()

        active = binary.with_name("l2solver-active")
        active_info = package.getmember(active.name)
        assert active_info.mode == 0o755
        assert package.extractfile(active_info).read() == active.read_bytes()

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
        assert "sha256sum --check" in instructions
        assert "tar -xzf" in instructions
        assert "./l2solver --version" in instructions
        assert "\n./scripts/install.sh" not in instructions
        assert "\nsudo /usr/local/bin/l2solver-uninstall" not in instructions

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

    # Compare with the actual release workflow so its recipe cannot silently drift
    workflow = (
        Path(__file__).resolve().parents[2] / ".github/workflows/release-linux.yml"
    ).read_text()
    build_step = workflow.split("      - name: Build Linux release candidate\n", 1)[
        1
    ].split("\n\n", 1)[0]
    build_recipe = " ".join(line.strip() for line in build_step.splitlines()[1:])

    assert provenance == {
        "schema_version": 3,
        "source_commit": "a" * 40,
        "source_tree": "b" * 40,
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
            "command": build_recipe,
            "command_kind": "rebuild_recipe",
        },
        "binary": {
            "name": "l2solver",
            "bytes": binary.stat().st_size,
            "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        },
        "active_binary": {
            "name": "l2solver-active",
            "bytes": active.stat().st_size,
            "sha256": hashlib.sha256(active.read_bytes()).hexdigest(),
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
        "source_tree": "c" * 40,
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
            source_tree="b" * 40,
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
            source_tree="b" * 40,
            rustc_version="rustc sample",
            cargo_version="cargo sample",
        )


def test_package_removes_partial_artifact_when_input_changes_during_write(
    tmp_path, monkeypatch
):
    binary, lockfile = create_inputs(tmp_path)
    output = tmp_path / "changed-input"
    write_archive = packager._write_archive

    def write_then_change_binary(source, active, helper, provenance, archive):
        write_archive(source, active, helper, provenance, archive)
        source.write_bytes(b"changed after archiving")
        source.chmod(0o755)

    monkeypatch.setattr(packager, "_write_archive", write_then_change_binary)
    with pytest.raises(ValueError, match="inputs changed"):
        package_release(
            binary,
            lockfile,
            output,
            source_commit="d" * 40,
            source_tree="b" * 40,
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
        package_release(binary, lockfile, output, source_commit="a" * 40, source_tree="b" * 40,
                        rustc_version="rustc sample", cargo_version="cargo sample")
    assert not output.exists()


def test_package_refuses_helper_changes_during_write(tmp_path, monkeypatch):
    binary, lockfile = create_inputs(tmp_path)
    helper = binary.with_name("l2solver-active-helper")
    write_archive = packager._write_archive

    def write_then_change_helper(source, active, active_helper, provenance, archive):
        write_archive(source, active, active_helper, provenance, archive)
        active_helper.write_bytes(b"changed helper")

    monkeypatch.setattr(packager, "_write_archive", write_then_change_helper)
    output = tmp_path / "dist"
    with pytest.raises(ValueError, match="inputs changed"):
        package_release(binary, lockfile, output, source_commit="a" * 40, source_tree="b" * 40,
                        rustc_version="rustc sample", cargo_version="cargo sample")
    assert helper.read_bytes() == b"changed helper"
    assert not output.exists()


@pytest.mark.parametrize("kind", ["missing", "symlink", "not_executable"])
def test_package_requires_a_regular_executable_active_binary(tmp_path, kind):
    binary, lockfile = create_inputs(tmp_path)
    active = binary.with_name("l2solver-active")
    active.unlink()
    if kind == "symlink":
        active.symlink_to(binary)
    elif kind == "not_executable":
        active.write_bytes(b"active")
    with pytest.raises(FileNotFoundError if kind == "missing" else ValueError):
        package_release(binary, lockfile, tmp_path / "dist", source_commit="a" * 40,
                        source_tree="b" * 40, rustc_version="rustc sample", cargo_version="cargo sample")
    assert not (tmp_path / "dist").exists()


def test_package_refuses_active_binary_changes_during_write(tmp_path, monkeypatch):
    binary, lockfile = create_inputs(tmp_path)
    write_archive = packager._write_archive

    def write_then_change_active(source, active, helper, provenance, archive):
        write_archive(source, active, helper, provenance, archive)
        active.write_bytes(b"changed active binary")

    monkeypatch.setattr(packager, "_write_archive", write_then_change_active)
    with pytest.raises(ValueError, match="inputs changed"):
        package_release(binary, lockfile, tmp_path / "dist", source_commit="a" * 40,
                        source_tree="b" * 40, rustc_version="rustc sample", cargo_version="cargo sample")
    assert not (tmp_path / "dist").exists()


def test_cli_refuses_to_publish_if_source_identity_changes_while_archiving(tmp_path, monkeypatch):
    binary, lockfile = create_inputs(tmp_path)
    states = iter([
        {"source_commit": "a" * 40, "source_tree": "b" * 40, "rustc_version": "rustc", "cargo_version": "cargo"},
        {"source_commit": "a" * 40, "source_tree": "c" * 40, "rustc_version": "rustc", "cargo_version": "cargo"},
    ])
    monkeypatch.setattr(packager, "_release_metadata", lambda: next(states))
    output = tmp_path / "dist"
    result = packager.main([
        "--binary", str(binary), "--active-binary", str(binary.with_name("l2solver-active")),
        "--helper-binary", str(binary.with_name("l2solver-active-helper")),
        "--lockfile", str(lockfile), "--output-directory", str(output),
    ])
    assert result != 0
    assert not output.exists()


def test_release_metadata_records_clean_commit_and_tree_and_rejects_untracked_source(tmp_path, monkeypatch):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "main.rs").write_text("fn main() {}\n")
    subprocess.run(["git", "add", "main.rs"], cwd=tmp_path, check=True)
    subprocess.run(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                    "commit", "-qm", "fixture"], cwd=tmp_path, check=True)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(packager, "ROOT", tmp_path)
    metadata = packager._release_metadata()
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], text=True).strip()
    assert metadata["source_commit"] == commit
    assert metadata["source_tree"] == tree
    (tmp_path / "extra.rs").write_text("fn extra() {}\n")
    with pytest.raises(ValueError, match="clean working tree"):
        packager._release_metadata()


def test_release_metadata_rejects_a_different_working_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(packager, "ROOT", tmp_path / "expected-checkout")
    with pytest.raises(ValueError, match="repository root"):
        packager._release_metadata()


@pytest.mark.parametrize("source_tree", ["", "abc", "A" * 40, "a" * 39, "a" * 64])
def test_package_requires_full_lowercase_source_tree_identity(tmp_path, source_tree):
    binary, lockfile = create_inputs(tmp_path)
    with pytest.raises(ValueError, match="source tree"):
        package_release(binary, lockfile, tmp_path / "dist", source_commit="a" * 40,
                        source_tree=source_tree, rustc_version="rustc sample", cargo_version="cargo sample")


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
            source_tree="b" * 40,
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
            source_tree="b" * 40,
            rustc_version="rustc sample",
            cargo_version="cargo sample",
        )

    assert not output.exists()
