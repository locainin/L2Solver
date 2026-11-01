"""Create and independently check bounded file-refinement fixtures."""

import base64
import gzip
import hashlib
import io
import json
import os
import random
import shutil
import struct
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path

from .catalogue import hash_file

MIB = 1024 * 1024
BLOCK = 64 * 1024


@dataclass(frozen=True)
class FixtureSizes:
    near_bytes: int = 544 * MIB
    archive_member_bytes: int = 80 * MIB
    encoded_member_bytes: int = 32 * MIB
    refusal_random_bytes: int = 10 * MIB
    refusal_zero_bytes: int = 20 * MIB


def _chunk(kind, data):
    crc = zlib.crc32(data, zlib.crc32(kind)) & 0xffffffff
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", crc)


def _png(pixel):
    return (b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + _chunk(b"IDAT", zlib.compress(b"\0" + pixel)) + _chunk(b"IEND", b""))


def _zip_info(name):
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    return info


def _write_repeated(target, block, count, digest=None):
    while count:
        part = block[:min(count, len(block))]
        target.write(part)
        if digest is not None:
            digest.update(part)
        count -= len(part)


def _write_archive(path, first, second, block, count):
    with zipfile.ZipFile(path, "x", allowZip64=True) as archive:
        archive.writestr(_zip_info("first.png"), first)
        archive.writestr(_zip_info("second.png"), second)
        with archive.open(_zip_info("large.bin"), "w") as member:
            _write_repeated(member, block, count)
    with zipfile.ZipFile(path) as archive:
        return archive.start_dir


def _check_sizes(sizes):
    if (type(sizes.near_bytes) is not int or sizes.near_bytes < 128 * 1024
            or any(type(value) is not int or value <= 0 for value in (
                sizes.archive_member_bytes, sizes.encoded_member_bytes,
                sizes.refusal_random_bytes, sizes.refusal_zero_bytes))):
        raise ValueError("invalid fixture sizes")


def generate(root, sizes):
    root = Path(root)
    _check_sizes(sizes)
    root.mkdir(parents=True, exist_ok=True)
    fixtures = root / "fixtures"
    fixtures.mkdir()
    first, second = _png(b"\xff\0\0"), _png(b"\0\xff\0")
    for name, data in (("first.png", first), ("second.png", second)):
        (fixtures / name).write_bytes(data)

    nested = io.BytesIO()
    with zipfile.ZipFile(nested, "w") as archive:
        archive.writestr(_zip_info("first.png"), first)
        archive.writestr(_zip_info("note.txt"), b"independent member payload")
    embedded = nested.getvalue()
    (fixtures / "embedded.zip").write_bytes(embedded)
    offset = sizes.near_bytes - BLOCK
    with (fixtures / "near-eof.bin").open("xb") as target:
        target.truncate(sizes.near_bytes)
        target.seek(offset)
        target.write(first + b"\0" * 128 + embedded)

    valid = fixtures / "large-valid.zip"
    central_offset = _write_archive(valid, first, second, b"\x91" * BLOCK, sizes.archive_member_bytes)
    corrupt = fixtures / "large-corrupt.zip"
    with valid.open("rb") as source, corrupt.open("xb") as target:
        shutil.copyfileobj(source, target, MIB)
    with corrupt.open("r+b") as target:
        target.seek(central_offset)
        if target.read(4) != b"PK\x01\x02":
            raise ValueError("ZIP central directory signature is missing")
        target.seek(central_offset)
        target.write(b"BAD!")

    random_block = random.Random(6039774).randbytes(BLOCK)
    encoded_zip = fixtures / "encoded-reference.zip"
    _write_archive(encoded_zip, first, second, random_block, sizes.encoded_member_bytes)
    compressed = fixtures / "encoded-reference.gz"
    with encoded_zip.open("rb") as source, compressed.open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=1, mtime=0) as target:
            shutil.copyfileobj(source, target, MIB)
    with compressed.open("rb") as source, (fixtures / "encoded-gzip.txt").open("xb") as target:
        for part in iter(lambda: source.read(3 * BLOCK), b""):
            target.write(base64.b64encode(part))

    expanded = hashlib.sha256()
    with (fixtures / "output-limit.gz").open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=1, mtime=0) as target:
            _write_repeated(target, random_block, sizes.refusal_random_bytes, expanded)
            _write_repeated(target, b"\0" * BLOCK, sizes.refusal_zero_bytes, expanded)
            target.write(first)
            expanded.update(first)
    files = {path.name: {"length": path.stat().st_size, "sha256": hash_file(path)}
             for path in sorted(fixtures.iterdir())}
    report = {"near_eof_offset": offset, "zip_central_directory_offset": central_offset,
              "expanded_gzip_sha256": expanded.hexdigest(),
              "expanded_gzip_length": sizes.refusal_random_bytes + sizes.refusal_zero_bytes + len(first),
              "files": files}
    verify_fixtures(root, report)
    with (root / "fixtures.json").open("x", encoding="utf-8") as target:
        json.dump(report, target, indent=2, sort_keys=True)
        target.write("\n")
    return report


def _check_archive(path, first, second):
    with zipfile.ZipFile(path) as archive:
        if archive.testzip() is not None or archive.read("first.png") != first:
            raise ValueError("fixture ZIP failed independent validation")
        if second is not None and archive.read("second.png") != second:
            raise ValueError("fixture ZIP member changed")


def _check_png(data, pixel):
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("fixture PNG signature is invalid")
    chunks, offset = [], 8
    while offset < len(data):
        if len(data) - offset < 12:
            raise ValueError("fixture PNG chunk is truncated")
        length = struct.unpack_from(">I", data, offset)[0]
        end = offset + 12 + length
        if end > len(data):
            raise ValueError("fixture PNG chunk is truncated")
        kind = data[offset + 4:offset + 8]
        body = data[offset + 8:offset + 8 + length]
        expected = struct.unpack_from(">I", data, offset + 8 + length)[0]
        if zlib.crc32(body, zlib.crc32(kind)) & 0xffffffff != expected:
            raise ValueError("fixture PNG checksum is invalid")
        chunks.append((kind, body))
        offset = end
    if ([kind for kind, _ in chunks] != [b"IHDR", b"IDAT", b"IEND"]
            or chunks[0][1] != struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
            or chunks[2][1] != b""):
        raise ValueError("fixture PNG structure is invalid")
    try:
        pixels = zlib.decompress(chunks[1][1])
    except zlib.error as error:
        raise ValueError("fixture PNG data is invalid") from error
    if pixels != b"\0" + pixel:
        raise ValueError("fixture PNG pixels are invalid")


def verify_fixtures(root, report):
    fixtures = Path(root) / "fixtures"
    for name, expected in report["files"].items():
        path = fixtures / name
        if (Path(name).name != name or path.is_symlink() or not path.is_file()
                or path.stat().st_size != expected["length"] or hash_file(path, expected_bytes=expected["length"]) != expected["sha256"]):
            raise ValueError("fixture bytes or path changed")
    if any((fixtures / name).stat().st_size > 4096 for name in ("first.png", "second.png")):
        raise ValueError("fixture PNG is unexpectedly large")
    first, second = (fixtures / "first.png").read_bytes(), (fixtures / "second.png").read_bytes()
    _check_png(first, b"\xff\0\0")
    _check_png(second, b"\0\xff\0")
    with (fixtures / "near-eof.bin").open("rb") as source:
        source.seek(report["near_eof_offset"])
        if source.read(len(first)) != first:
            raise ValueError("fixture near-EOF PNG is missing")
        source.seek(128, os.SEEK_CUR)
        embedded = (fixtures / "embedded.zip").read_bytes()
        if source.read(len(embedded)) != embedded:
            raise ValueError("fixture near-EOF embedded ZIP changed")
    for name, other in (("embedded.zip", None), ("large-valid.zip", second), ("encoded-reference.zip", second)):
        _check_archive(fixtures / name, first, other)
    try:
        with zipfile.ZipFile(fixtures / "large-corrupt.zip") as archive:
            archive.infolist()
    except zipfile.BadZipFile:
        pass
    else:
        raise ValueError("fixture corrupt ZIP unexpectedly validates")
    decoded, digest = zlib.decompressobj(16 + zlib.MAX_WBITS), hashlib.sha256()
    with (fixtures / "encoded-gzip.txt").open("rb") as source:
        for part in iter(lambda: source.read(4 * BLOCK), b""):
            digest.update(decoded.decompress(base64.b64decode(part, validate=True)))
    digest.update(decoded.flush())
    if not decoded.eof or decoded.unused_data or digest.hexdigest() != report["files"]["encoded-reference.zip"]["sha256"]:
        raise ValueError("fixture encoded gzip did not round trip")
    digest, length = hashlib.sha256(), 0
    with gzip.open(fixtures / "output-limit.gz", "rb") as source:
        for part in iter(lambda: source.read(MIB), b""):
            digest.update(part)
            length += len(part)
    if digest.hexdigest() != report["expanded_gzip_sha256"] or length != report["expanded_gzip_length"]:
        raise ValueError("fixture output-limit gzip did not round trip")
