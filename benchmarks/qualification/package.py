"""Validate and unpack the matching candidate executables for qualification."""

import json
import shutil
import stat
import tarfile
from pathlib import Path

from benchmarks.package_release import (
    ARCHIVE_NAME,
    ACTIVE_NAME,
    HELPER_NAME,
    NOTICE_PATH,
    PROVENANCE_NAME,
    TARGET,
)
from benchmarks.runner.catalogue import hash_file

MAX_BINARY_BYTES = 512 * 1024 * 1024
MAX_METADATA_BYTES = 64 * 1024


def _regular(path):
    path = Path(path)
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError(f"input must be a regular file: {path}")
    return path


def check_checksum(checksum, archive_name, digest):
    """Require one exact checksum line without an unbounded input read."""
    checksum = _regular(checksum)
    with checksum.open("rb") as source:
        content = source.read(257)
    if content != f"{digest}  {archive_name}\n".encode("ascii"):
        raise ValueError("package checksum does not match the archive")


def unpack_package(
    archive,
    checksum,
    destination,
    *,
    source_commit,
    source_tree,
    lock_sha256,
    rustc_version,
    cargo_version,
):
    """Check provenance and unpack executables without extracting archive paths."""
    archive = _regular(archive)
    if archive.name != ARCHIVE_NAME:
        raise ValueError("unexpected package name")
    archive_size = archive.stat().st_size
    if not 0 < archive_size <= 3 * MAX_BINARY_BYTES + 4 * 1024 * 1024:
        raise ValueError("package archive exceeds its size limit")
    # A growing file cannot extend the approved hash read
    digest = hash_file(archive, expected_bytes=archive_size)
    check_checksum(checksum, archive.name, digest)

    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    binary = destination / "l2solver"
    active = destination / ACTIVE_NAME
    helper = destination / HELPER_NAME
    executables = {"l2solver": binary, ACTIVE_NAME: active, HELPER_NAME: helper}
    with tarfile.open(archive, "r:gz") as package:
        expected = {*executables, PROVENANCE_NAME, NOTICE_PATH.name}
        entries = []
        # Stop as soon as the archive has more entries than the package format
        for item in package:
            if len(entries) == len(expected):
                raise ValueError("package has unexpected archive members")
            entries.append(item)
        if (
            len(entries) != len(expected)
            or {item.name for item in entries} != expected
            or any(not item.isfile() for item in entries)
        ):
            raise ValueError("package has unexpected archive members")
        items = {item.name: item for item in entries}
        for name in executables:
            if not 0 < items[name].size <= MAX_BINARY_BYTES or items[name].mode & 0o111 == 0:
                raise ValueError(
                    "package binary or helper is not executable or exceeds its size limit"
                )
        if any(
            not 0 < items[name].size <= MAX_METADATA_BYTES
            for name in expected - executables.keys()
        ):
            raise ValueError("package metadata exceeds its size limit")
        metadata = package.extractfile(items[PROVENANCE_NAME])
        if metadata is None:
            raise ValueError("package members cannot be read")
        with metadata:
            provenance = json.load(metadata)
        for name, executable in executables.items():
            source = package.extractfile(items[name])
            if source is None:
                raise ValueError("package executable cannot be read")
            # Copy the named members only; archive paths never select a destination
            with source, executable.open("xb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
            executable.chmod(0o700)

    expected_fields = (
        isinstance(provenance, dict)
        and isinstance(provenance.get("dependency_lock"), dict)
        and isinstance(provenance.get("toolchain"), dict)
        and isinstance(provenance.get("build"), dict)
        and isinstance(provenance.get("binary"), dict)
        and isinstance(provenance.get("active_binary"), dict)
        and isinstance(provenance.get("active_helper"), dict)
        and type(provenance.get("schema_version")) is int
        and provenance.get("schema_version") == 3
        and provenance.get("target") == TARGET
        and provenance.get("source_commit") == source_commit
        and provenance.get("source_tree") == source_tree
        and provenance.get("build", {}).get("command_kind") == "rebuild_recipe"
        and provenance.get("dependency_lock", {}).get("sha256") == lock_sha256
        and provenance.get("toolchain", {}).get("rustc") == rustc_version
        and provenance.get("toolchain", {}).get("cargo") == cargo_version
    )
    if not expected_fields:
        raise ValueError(
            "package provenance differs from the current source or toolchain"
        )
    for name, key in (
        ("l2solver", "binary"),
        (ACTIVE_NAME, "active_binary"),
        (HELPER_NAME, "active_helper"),
    ):
        executable = executables[name]
        metadata = provenance[key]
        if (
            metadata.get("name") != name
            or type(metadata.get("bytes")) is not int
            or metadata["bytes"] != executable.stat().st_size
            or metadata.get("sha256") != hash_file(executable, expected_bytes=metadata["bytes"])
        ):
            raise ValueError(f"package {key} differs from its provenance")
    if provenance["active_helper"].get("required_capability") != "cap_net_raw":
        raise ValueError("package helper capability differs from its provenance")
    # Detect changes while the archive was being read
    if hash_file(archive, expected_bytes=archive_size) != digest:
        raise ValueError("package checksum changed during inspection")
    check_checksum(checksum, archive.name, digest)
    return {
        "binary": binary,
        "active_binary": active,
        "active_helper": helper,
        "archive_sha256": digest,
        "archive_bytes": archive_size,
        "provenance": provenance,
    }
