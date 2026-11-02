"""Qualify only the exact archive and ELF bytes identified by the build."""

import hashlib
import io
import json
import tarfile

import pytest

from benchmarks.package_release import package_release
from benchmarks.qualification import package as package_checks
from benchmarks.qualification.elf import inspect_elf, parse_elf_inspection
from benchmarks.qualification.package import unpack_package

COMMIT = "a" * 40
RUSTC = "rustc 1.99.1 (test)"
CARGO = "cargo 1.99.1 (test)"


@pytest.fixture
def candidate(tmp_path):
    binary = tmp_path / "l2solver"
    binary.write_bytes(b"sample executable")
    binary.chmod(0o755)
    active = tmp_path / "l2solver-active"
    active.write_bytes(b"sample active executable")
    active.chmod(0o755)
    helper = tmp_path / "l2solver-active-helper"
    helper.write_bytes(b"matching active helper")
    helper.chmod(0o750)
    lock = tmp_path / "Cargo.lock"
    lock.write_bytes(b"version = 4\n")
    archive, checksum = package_release(
        binary,
        lock,
        tmp_path / "dist",
        source_commit=COMMIT,
        source_tree="d" * 40,
        rustc_version=RUSTC,
        cargo_version=CARGO,
    )
    return archive, checksum, binary, lock


def unpack(candidate, tmp_path, **overrides):
    archive, checksum, _, lock = candidate
    expected = {
        "source_commit": COMMIT,
        "source_tree": "d" * 40,
        "lock_sha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
        "rustc_version": RUSTC,
        "cargo_version": CARGO,
    }
    expected.update(overrides)
    return unpack_package(archive, checksum, tmp_path / "unpacked", **expected)


def test_unpack_checks_the_archive_and_the_actual_executable(candidate, tmp_path):
    archive, _, binary, _ = candidate
    result = unpack(candidate, tmp_path)
    assert result["binary"].read_bytes() == binary.read_bytes()
    assert result["active_binary"].read_bytes() == binary.with_name("l2solver-active").read_bytes()
    assert result["binary"].stat().st_mode & 0o111
    helper = binary.with_name("l2solver-active-helper")
    assert result["active_helper"].read_bytes() == helper.read_bytes()
    assert result["active_helper"].stat().st_mode & 0o777 == 0o700
    assert result["archive_sha256"] == hashlib.sha256(archive.read_bytes()).hexdigest()
    assert (
        result["provenance"]["binary"]["sha256"]
        == hashlib.sha256(binary.read_bytes()).hexdigest()
    )


@pytest.mark.parametrize(
    ("field", "wrong"),
    [
        ("source_commit", "b" * 40),
        ("source_tree", "e" * 40),
        ("lock_sha256", "c" * 64),
        ("rustc_version", "rustc another"),
        ("cargo_version", "cargo another"),
    ],
)
def test_unpack_rejects_a_different_source_lock_or_toolchain(
    candidate, tmp_path, field, wrong
):
    with pytest.raises(ValueError, match="provenance"):
        unpack(candidate, tmp_path, **{field: wrong})


def test_unpack_rejects_checksum_mismatch(candidate, tmp_path):
    _, checksum, _, _ = candidate
    checksum.write_text("0" * 64 + "  " + candidate[0].name + "\n")
    with pytest.raises(ValueError, match="checksum"):
        unpack(candidate, tmp_path)


def test_archive_growth_cannot_extend_the_hash_read(candidate, tmp_path, monkeypatch):
    archive, _, _, _ = candidate
    original_hash = package_checks.hash_file
    changed = False

    def grow_archive(path, **kwargs):
        nonlocal changed
        if path == archive and not changed:
            changed = True
            with archive.open("ab") as output:
                output.write(b"new bytes")
        return original_hash(path, **kwargs)

    monkeypatch.setattr(package_checks, "hash_file", grow_archive)
    with pytest.raises(ValueError, match="length mismatch"):
        unpack(candidate, tmp_path)


def test_unpack_rejects_archive_with_unexpected_member(candidate, tmp_path):
    archive, checksum, _, _ = candidate
    with tarfile.open(archive, "r:gz") as package:
        members = [(item, package.extractfile(item).read()) for item in package]
    with tarfile.open(archive, "w:gz") as package:
        for info, data in members:
            package.addfile(info, io.BytesIO(data))
        extra = tarfile.TarInfo("../outside")
        extra.size = 1
        package.addfile(extra, io.BytesIO(b"x"))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    checksum.write_text(f"{digest}  {archive.name}\n")
    with pytest.raises(ValueError, match="members"):
        unpack(candidate, tmp_path)
    assert not (tmp_path / "outside").exists()


@pytest.mark.parametrize("change", ["missing", "duplicate", "symlink", "legacy-guide"])
def test_unpack_requires_exact_regular_archive_members(candidate, tmp_path, change):
    archive, checksum, _, _ = candidate
    with tarfile.open(archive, "r:gz") as package:
        members = [(item, package.extractfile(item).read()) for item in package]

    # Re-sign each changed archive so member checks cannot rely on its checksum
    with tarfile.open(archive, "w:gz") as package:
        for info, data in members:
            if info.name == "NOTICE-JEMALLOC.txt":
                if change == "missing":
                    continue
                if change == "duplicate":
                    info.name = "l2solver"
                if change == "symlink":
                    info.type = tarfile.SYMTYPE
                    info.linkname = "l2solver"
                    info.size = 0
                    data = b""
            package.addfile(info, io.BytesIO(data))
        if change == "legacy-guide":
            guide = tarfile.TarInfo("INSTALL-ACTIVE.md")
            guide.size = 1
            package.addfile(guide, io.BytesIO(b"x"))

    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    checksum.write_text(f"{digest}  {archive.name}\n")
    with pytest.raises(ValueError, match="members"):
        unpack(candidate, tmp_path)


@pytest.mark.parametrize("name", ["l2solver", "l2solver-active", "l2solver-active-helper"])
def test_unpack_rejects_an_executable_that_differs_from_provenance(candidate, tmp_path, name):
    archive, checksum, _, _ = candidate
    with tarfile.open(archive, "r:gz") as package:
        members = [(item, package.extractfile(item).read()) for item in package]
    with tarfile.open(archive, "w:gz") as package:
        for info, data in members:
            if info.name == name:
                data = b"changed executable"
                info.size = len(data)
            package.addfile(info, io.BytesIO(data))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    checksum.write_text(f"{digest}  {archive.name}\n")
    with pytest.raises(ValueError, match="binary|helper"):
        unpack(candidate, tmp_path)


@pytest.mark.parametrize(
    ("field", "value"),
    [("schema_version", True), ("command_kind", None), ("command_kind", "observed")],
)
def test_unpack_rejects_invalid_schema_or_build_command_kind(candidate, tmp_path, field, value):
    archive, checksum, _, _ = candidate
    with tarfile.open(archive, "r:gz") as package:
        members = [(item, package.extractfile(item).read()) for item in package]
    with tarfile.open(archive, "w:gz") as package:
        for info, data in members:
            if info.name == "PROVENANCE.json":
                metadata = json.loads(data)
                if field == "schema_version":
                    metadata[field] = value
                elif value is None:
                    del metadata["build"][field]
                else:
                    metadata["build"][field] = value
                data = json.dumps(metadata).encode()
                info.size = len(data)
            package.addfile(info, io.BytesIO(data))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    checksum.write_text(f"{digest}  {archive.name}\n")
    with pytest.raises(ValueError, match="provenance"):
        unpack(candidate, tmp_path)


HEADER = """\
ELF Header:
  Class:                             ELF64
  Machine:                           Advanced Micro Devices X86-64
"""
DYNAMIC = """\
Dynamic section at offset 0:
 0x0000000000000001 (NEEDED)             Shared library: [libsqlite3.so.0]
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
"""
PROGRAM = """\
  [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
"""
VERSIONS = """\
Version needs section '.gnu.version_r' contains 1 entry:
  000000: Version: 1  File: libc.so.6  Cnt: 3
  0x0010:   Name: GLIBC_2.9  Flags: none  Version: 4
  0x0020:   Name: GLIBC_2.34  Flags: none  Version: 3
  0x0030:   Name: GLIBC_2.2.5  Flags: none  Version: 2
"""


def test_elf_inspection_reports_numeric_glibc_maximum_and_needed_libraries():
    result = parse_elf_inspection(HEADER, PROGRAM, DYNAMIC, VERSIONS)
    assert result["needed"] == ["libsqlite3.so.0", "libc.so.6"]
    assert result["interpreter"] == "/lib64/ld-linux-x86-64.so.2"
    assert result["glibc_requirement"] == "GLIBC_2.34"


def test_elf_inspection_never_invents_a_glibc_requirement():
    result = parse_elf_inspection(HEADER, "", "There is no dynamic section", "")
    assert result["needed"] == []
    assert result["interpreter"] is None
    assert result["glibc_requirement"] is None


def test_elf_inspection_rejects_wrong_machine_and_unparseable_headers():
    with pytest.raises(ValueError, match="ELF64 x86-64"):
        parse_elf_inspection(HEADER.replace("X86-64", "AArch64"), "", "", "")
    with pytest.raises(ValueError, match="ELF64 x86-64"):
        parse_elf_inspection("not an ELF header", "", "", "")


def test_elf_inspection_rejects_missing_library_with_successful_ldd(tmp_path, monkeypatch):
    import subprocess
    outputs = {"-hW": HEADER, "-lW": PROGRAM, "-dW": DYNAMIC, "-VW": VERSIONS}

    def run(command, **kwargs):
        if command[0] == "ldd":
            assert kwargs["env"]["LC_ALL"] == "C"
        output = "libsqlite3.so.0 => not found\n" if command[0] == "ldd" else outputs[command[1]]
        return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

    monkeypatch.setattr("benchmarks.qualification.elf.subprocess.run", run)
    with pytest.raises(ValueError, match="libsqlite3.so.0 => not found"):
        inspect_elf(tmp_path / "binary", tmp_path)


def test_elf_inspection_rejects_linked_system_sqlite_even_if_available(tmp_path, monkeypatch):
    import subprocess
    outputs = {"-hW": HEADER, "-lW": PROGRAM, "-dW": DYNAMIC, "-VW": VERSIONS}

    def run(command, **kwargs):
        output = "libsqlite3.so.0 => /usr/lib/libsqlite3.so.0 (0x0001)\n" if command[0] == "ldd" else outputs[command[1]]
        return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

    monkeypatch.setattr("benchmarks.qualification.elf.subprocess.run", run)
    with pytest.raises(ValueError, match="libsqlite3.so.0"):
        inspect_elf(tmp_path / "binary", tmp_path)
