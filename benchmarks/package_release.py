"""Create a deterministic Linux release archive with embedded build provenance."""

import argparse
import gzip
import hashlib
import io
import json
import os
import platform
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import zlib
from pathlib import Path

TARGET = "x86_64-unknown-linux-gnu"
ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_NAME = f"l2solver-{TARGET}.tar.gz"
PROVENANCE_NAME = "PROVENANCE.json"
NOTICE_PATH = ROOT / "NOTICE-JEMALLOC.txt"
HELPER_NAME = "l2solver-active-helper"
ACTIVE_NAME = "l2solver-active"


def _regular_file(path, description, *, executable=False):
    path = Path(path)
    # Inspect the directory entry itself so a symlink cannot redirect an input
    information = path.lstat()
    if not stat.S_ISREG(information.st_mode):
        qualifier = "executable " if executable else ""
        raise ValueError(f"{description} must be a regular {qualifier}file: {path}")
    if executable and information.st_mode & 0o111 == 0:
        raise ValueError(f"{description} must be executable: {path}")
    return path.resolve(strict=True), information


def _hash_file(path):
    digest = hashlib.sha256()
    # Stream large binaries through a fixed buffer rather than loading them whole
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _provenance(
    binary, binary_information, active, active_information, helper, helper_information,
    lockfile, metadata,
):
    # Keep the target fixed to the release workflow's only supported artifact
    for name in ("source_commit", "source_tree"):
        value = metadata[name]
        if not isinstance(value, str) or re.fullmatch(
            r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value
        ) is None:
            raise ValueError(f"{name.replace('_', ' ')} must be a full lowercase Git object id")
    if len(metadata["source_tree"]) != len(metadata["source_commit"]):
        raise ValueError("source tree and commit must use the same Git object format")

    for name in ("rustc_version", "cargo_version"):
        value = metadata[name]
        if not isinstance(value, str) or not value or "\n" in value or "\r" in value:
            raise ValueError(f"{name.replace('_', ' ')} must be one nonempty line")

    # Record only portable identifiers and digests, never local filesystem paths
    return {
        "schema_version": 3,
        "source_commit": metadata["source_commit"],
        "source_tree": metadata["source_tree"],
        "toolchain": {
            "rustc": metadata["rustc_version"],
            "cargo": metadata["cargo_version"],
        },
        "packager": {
            "python": platform.python_version(),
            "zlib": zlib.ZLIB_VERSION,
        },
        "target": TARGET,
        "dependency_lock": {
            "path": "Cargo.lock",
            "sha256": _hash_file(lockfile),
        },
        "build": {
            "command_kind": "rebuild_recipe",
            "command": (
                "cargo build --locked --release --package l2-cli "
                "--package l2-active-cli --package l2-active-linux "
                "--bin l2solver --bin l2solver-active "
                f"--bin {HELPER_NAME} --target {TARGET}"
            )
        },
        "binary": {
            "name": "l2solver",
            "bytes": binary_information.st_size,
            "sha256": _hash_file(binary),
        },
        "active_binary": {
            "name": ACTIVE_NAME,
            "bytes": active_information.st_size,
            "sha256": _hash_file(active),
        },
        "active_helper": {
            "name": HELPER_NAME,
            "bytes": helper_information.st_size,
            "sha256": _hash_file(helper),
            "required_capability": "cap_net_raw",
        },
    }


def _tar_entry(name, size, mode):
    entry = tarfile.TarInfo(name)
    # Normalize header fields so local owner ids and build times do not leak in
    entry.size = size
    entry.mode = mode
    entry.mtime = 0
    entry.uid = 0
    entry.gid = 0
    entry.uname = ""
    entry.gname = ""
    return entry


def _write_archive(binary, active, helper, provenance, archive):
    provenance_bytes = (json.dumps(provenance, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    # Distribute the native allocator and Rust binding notices with the linked executable
    notice_path, _ = _regular_file(NOTICE_PATH, "allocator notices")
    with notice_path.open("rb") as source:
        notices = source.read(64 * 1024 + 1)
    if not notices or len(notices) > 64 * 1024:
        raise ValueError("allocator notices must contain between 1 and 65536 bytes")

    # Fixed gzip and tar metadata make the package bytes independent of the clock
    with (
        archive.open("xb") as destination,
        gzip.GzipFile(
            filename="", mode="wb", fileobj=destination, compresslevel=9, mtime=0
        ) as compressed,
        tarfile.open(
            fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT
        ) as package,
    ):
        # Archive permissions grant no capabilities and restrict helper execution
        for name, path, mode in (
            ("l2solver", binary, 0o755),
            (ACTIVE_NAME, active, 0o755),
            (HELPER_NAME, helper, 0o750),
        ):
            with path.open("rb") as source:
                package.addfile(_tar_entry(name, path.stat().st_size, mode), source)
        package.addfile(
            _tar_entry(PROVENANCE_NAME, len(provenance_bytes), 0o644),
            io.BytesIO(provenance_bytes),
        )
        package.addfile(
            _tar_entry(NOTICE_PATH.name, len(notices), 0o644),
            io.BytesIO(notices),
        )


def package_release(
    binary,
    lockfile,
    output_directory,
    *,
    active_binary=None,
    helper_binary=None,
    source_commit,
    source_tree,
    rustc_version,
    cargo_version,
    check_source=None,
):
    """Package matching Linux executables with provenance and a SHA-256 sidecar."""
    binary, binary_information = _regular_file(binary, "binary", executable=True)
    active, active_information = _regular_file(
        binary.with_name(ACTIVE_NAME) if active_binary is None else active_binary,
        "active binary", executable=True,
    )
    helper, helper_information = _regular_file(
        binary.with_name(HELPER_NAME) if helper_binary is None else helper_binary,
        "active helper", executable=True,
    )
    lockfile, lockfile_information = _regular_file(lockfile, "dependency lockfile")
    output_directory = Path(output_directory)
    if output_directory.exists() or output_directory.is_symlink():
        raise FileExistsError(f"output directory already exists: {output_directory}")
    output_directory.parent.mkdir(parents=True, exist_ok=True)

    # Hash the input once for provenance, then confirm it stayed fixed during packaging
    provenance = _provenance(
        binary,
        binary_information,
        active,
        active_information,
        helper,
        helper_information,
        lockfile,
        {
            "source_commit": source_commit,
            "source_tree": source_tree,
            "rustc_version": rustc_version,
            "cargo_version": cargo_version,
        },
    )
    with tempfile.TemporaryDirectory(
        prefix=".l2solver-release-", dir=output_directory.parent
    ) as staging_name:
        staging = Path(staging_name)
        archive = staging / ARCHIVE_NAME
        checksum = staging / f"{ARCHIVE_NAME}.sha256"
        _write_archive(binary, active, helper, provenance, archive)

        if (
            _hash_file(binary) != provenance["binary"]["sha256"]
            or binary.stat().st_size != binary_information.st_size
            or _hash_file(active) != provenance["active_binary"]["sha256"]
            or active.stat().st_size != active_information.st_size
            or _hash_file(helper) != provenance["active_helper"]["sha256"]
            or helper.stat().st_size != helper_information.st_size
            or _hash_file(lockfile) != provenance["dependency_lock"]["sha256"]
            or lockfile.stat().st_size != lockfile_information.st_size
        ):
            raise ValueError(
                "release inputs changed while the package was being written"
            )
        if check_source is not None:
            check_source()

        # The archive is the single downloadable artifact covered by this sidecar
        checksum.write_text(
            f"{_hash_file(archive)}  {archive.name}\n", encoding="ascii"
        )
        output_directory.mkdir(exist_ok=False)
        published = []
        try:
            # Link staged files so publication cannot overwrite an existing file
            for staged in (archive, checksum):
                destination = output_directory / staged.name
                os.link(staged, destination, follow_symlinks=False)
                published.append(destination)
        except BaseException:
            for path in published:
                path.unlink(missing_ok=True)
            try:
                output_directory.rmdir()
            except OSError:
                pass
            raise

    return output_directory / ARCHIVE_NAME, output_directory / f"{ARCHIVE_NAME}.sha256"


def _command_output(arguments):
    # Keep command output out of logs and forward only the requested version or id
    result = subprocess.run(
        arguments,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _release_metadata():
    # Reject untracked files before recording this committed checkout
    if Path.cwd().resolve() != ROOT or Path(
        _command_output(["git", "rev-parse", "--show-toplevel"])
    ).resolve() != ROOT:
        raise ValueError("run release packaging from the repository root")
    if _command_output(["git", "status", "--porcelain", "--untracked-files=all"]):
        raise ValueError("release packaging requires a clean working tree")

    toolchain = _command_output(["rustc", "-vV"])
    host = next(
        (
            line.removeprefix("host: ")
            for line in toolchain.splitlines()
            if line.startswith("host: ")
        ),
        None,
    )
    if host != TARGET:
        raise ValueError(f"release packaging requires the {TARGET} host toolchain")

    return {
        "source_commit": _command_output(["git", "rev-parse", "HEAD"]),
        "source_tree": _command_output(["git", "rev-parse", "HEAD^{tree}"]),
        "rustc_version": _command_output(["rustc", "--version"]),
        "cargo_version": _command_output(["cargo", "--version"]),
    }


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--active-binary", type=Path, required=True)
    parser.add_argument("--helper-binary", type=Path, required=True)
    parser.add_argument("--lockfile", type=Path, default=Path("Cargo.lock"))
    parser.add_argument("--output-directory", type=Path, required=True)
    options = parser.parse_args(arguments)

    try:
        metadata = _release_metadata()

        def check_source():
            if _release_metadata() != metadata:
                raise ValueError("source or toolchain changed during packaging")

        archive, checksum = package_release(
            options.binary,
            options.lockfile,
            options.output_directory,
            active_binary=options.active_binary,
            helper_binary=options.helper_binary,
            check_source=check_source,
            **metadata,
        )
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"release package: {error}", file=sys.stderr)
        return 2

    print(f"artifact {archive}")
    print(f"checksum {checksum}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
