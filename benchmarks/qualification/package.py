"""Validate and unpack exactly one candidate executable for qualification."""

import json
import shutil
import stat
import tarfile
from pathlib import Path

from benchmarks.package_release import (
    ARCHIVE_NAME,
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
    lock_sha256,
    rustc_version,
    cargo_version,
):
    """Check provenance and unpack the executable without extracting archive paths."""
    archive = _regular(archive)
    if archive.name != ARCHIVE_NAME:
        raise ValueError("unexpected package name")
    archive_size = archive.stat().st_size
    if not 0 < archive_size <= MAX_BINARY_BYTES + 4 * 1024 * 1024:
        raise ValueError("package archive exceeds its size limit")
    # A growing file cannot extend the approved hash read
    digest = hash_file(archive, expected_bytes=archive_size)
    check_checksum(checksum, archive.name, digest)

    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    binary = destination / "l2solver"
    with tarfile.open(archive, "r:gz") as package:
        expected = {"l2solver", PROVENANCE_NAME, NOTICE_PATH.name}
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
        if (
            not 0 < items["l2solver"].size <= MAX_BINARY_BYTES
            or items["l2solver"].mode & 0o111 == 0
        ):
            raise ValueError(
                "package binary is not executable or exceeds its size limit"
            )
        if any(
            not 0 < items[name].size <= MAX_METADATA_BYTES
            for name in expected - {"l2solver"}
        ):
            raise ValueError("package metadata exceeds its size limit")
        metadata = package.extractfile(items[PROVENANCE_NAME])
        source = package.extractfile(items["l2solver"])
        if metadata is None or source is None:
            raise ValueError("package members cannot be read")
        with metadata, source:
            provenance = json.load(metadata)
            # Copy the named member only; archive paths never select a destination
            with binary.open("xb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
        binary.chmod(0o700)

    expected_fields = (
        isinstance(provenance, dict)
        and isinstance(provenance.get("dependency_lock"), dict)
        and isinstance(provenance.get("toolchain"), dict)
        and isinstance(provenance.get("binary"), dict)
        and type(provenance.get("schema_version")) is int
        and provenance.get("schema_version") == 1
        and provenance.get("target") == TARGET
        and provenance.get("source_commit") == source_commit
        and provenance.get("dependency_lock", {}).get("sha256") == lock_sha256
        and provenance.get("toolchain", {}).get("rustc") == rustc_version
        and provenance.get("toolchain", {}).get("cargo") == cargo_version
    )
    if not expected_fields:
        raise ValueError(
            "package provenance differs from the current source or toolchain"
        )
    metadata = provenance.get("binary", {})
    if (
        metadata.get("name") != "l2solver"
        or type(metadata.get("bytes")) is not int
        or metadata["bytes"] != binary.stat().st_size
        or metadata.get("sha256") != hash_file(binary, expected_bytes=metadata["bytes"])
    ):
        raise ValueError("package binary differs from its provenance")
    # Detect changes while the archive was being read
    if hash_file(archive, expected_bytes=archive_size) != digest:
        raise ValueError("package checksum changed during inspection")
    check_checksum(checksum, archive.name, digest)
    return {
        "binary": binary,
        "archive_sha256": digest,
        "archive_bytes": archive_size,
        "provenance": provenance,
    }
