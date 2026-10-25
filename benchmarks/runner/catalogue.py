"""Load bounded source metadata and verify each local capture before a run."""

import hashlib
import json
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

COMMON_SOURCE_FIELDS = {
    "schema_version",
    "id",
    "capture_file",
    "capture_sha256",
    "capture_bytes",
    "source_url",
    "acquired_utc",
    "description",
}
SOURCE_FIELDS = COMMON_SOURCE_FIELDS | {
    "year",
    "archive_url",
    "archive_sha256",
    "archive_bytes",
    "archive_member",
}
DIRECT_SOURCE_FIELDS = COMMON_SOURCE_FIELDS | {"download_url", "license"}


class _CatalogueInputError(ValueError):
    """Catalogue content or files violate the accepted input contract."""


@dataclass(frozen=True)
class CatalogueLimits:
    # Defaults bound local benchmark work and can be raised explicitly
    max_metadata_bytes: int = 64 * 1024
    max_capture_bytes: int = 256 * 1024 * 1024
    max_input_bytes: int = 2 * 1024 * 1024 * 1024

    def __post_init__(self):
        for field, value in vars(self).items():
            if type(value) is not int or value <= 0:
                raise ValueError(f"{field} must be a positive integer byte budget")


DEFAULT_CATALOGUE_LIMITS = CatalogueLimits()


def add_catalogue_arguments(parser):
    for field, help_text in (
        ("max_metadata_bytes", "Bytes per catalogue or source metadata JSON document"),
        ("max_capture_bytes", "Bytes per selected capture file"),
        ("max_input_bytes", "Total bytes across distinct selected capture paths, independent of mode count"),
    ):
        parser.add_argument(
            "--" + field.replace("_", "-"),
            type=int,
            default=getattr(DEFAULT_CATALOGUE_LIMITS, field),
            help=help_text,
        )


@dataclass(frozen=True)
class Sample:
    capture: Path
    metadata: dict


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise _CatalogueInputError(f"duplicate JSON field: {name}")
        result[name] = value
    return result


def read_json_bytes(path, maximum):
    # Negative read sizes would disable the intended input bound
    if type(maximum) is not int or maximum <= 0:
        raise ValueError("JSON byte budget must be a positive integer")
    # Check the actual read as well as the file metadata
    if not stat.S_ISREG(path.stat().st_mode):
        raise _CatalogueInputError(f"JSON source is not a regular file: {path}")
    raw = bytearray()
    with path.open("rb") as stream:
        while True:
            # Chunked reads also support budgets larger than a single read() argument
            chunk = stream.read(min(1024 * 1024, maximum - len(raw) + 1))
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw) > maximum:
                raise _CatalogueInputError(f"JSON size exceeds {maximum}: {path}")
    return raw


def read_json(path, maximum=64 * 1024):
    return json.loads(read_json_bytes(path, maximum), object_pairs_hook=unique_object)


def hash_file(path, *, expected_bytes=None):
    if expected_bytes is not None and (type(expected_bytes) is not int or expected_bytes < 0):
        raise ValueError("expected_bytes must be a nonnegative integer")
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        while True:
            # A file that grows after preflight cannot extend the approved read budget
            remaining = 1024 * 1024 if expected_bytes is None else min(
                1024 * 1024, expected_bytes - total + 1
            )
            chunk = stream.read(remaining)
            if not chunk:
                break
            total += len(chunk)
            if expected_bytes is not None and total > expected_bytes:
                raise ValueError(f"file length mismatch: {path}")
            digest.update(chunk)
    if expected_bytes is not None and total != expected_bytes:
        raise ValueError(f"file length mismatch: {path}")
    return digest.hexdigest()


def local_file(root, relative):
    if not isinstance(relative, str):
        raise _CatalogueInputError("source paths must be relative strings")
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise _CatalogueInputError(
            "source paths must be relative and stay inside the catalogue directory"
        )
    result = root / path
    if result.is_symlink() or not result.resolve().is_relative_to(root.resolve()):
        raise _CatalogueInputError(
            "source paths must be relative local files without symlink escapes"
        )
    if not stat.S_ISREG(result.stat().st_mode):
        raise _CatalogueInputError(f"source is not a regular file: {result}")
    return result


def _source_metadata(path, limits):
    metadata = read_json(path, limits.max_metadata_bytes)
    if (
        not isinstance(metadata, dict)
        or type(metadata.get("schema_version")) is not int
    ):
        raise _CatalogueInputError(f"unsupported source metadata: {path}")
    version = metadata["schema_version"]
    expected = {1: SOURCE_FIELDS, 2: DIRECT_SOURCE_FIELDS}.get(version)
    if expected is None or set(metadata) != expected:
        raise _CatalogueInputError(f"unsupported source metadata: {path}")
    if not isinstance(metadata["id"], str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", metadata["id"]
    ):
        raise _CatalogueInputError("source id must be a bounded ASCII filename component")
    if version == 1 and (
        type(metadata["year"]) is not int or not 1 <= metadata["year"] <= 9999
    ):
        raise _CatalogueInputError("source year must be a calendar year between 1 and 9999")
    for field in (
        ("capture_sha256", "archive_sha256") if version == 1 else ("capture_sha256",)
    ):
        if not isinstance(metadata[field], str) or not re.fullmatch(
            r"[0-9a-f]{64}", metadata[field]
        ):
            raise _CatalogueInputError(f"invalid {field}")
    if type(metadata["capture_bytes"]) is not int or metadata["capture_bytes"] <= 0:
        raise _CatalogueInputError("invalid capture_bytes")
    # Historical archive size is provenance, not an input consumed by this runner
    if version == 1 and (
        type(metadata["archive_bytes"]) is not int or metadata["archive_bytes"] <= 0
    ):
        raise _CatalogueInputError("invalid archive_bytes")
    for field in ("source_url", "archive_url" if version == 1 else "download_url"):
        if not isinstance(metadata[field], str):
            raise _CatalogueInputError(f"invalid HTTPS {field}")
        url = urlsplit(metadata[field])
        if url.scheme != "https" or not url.hostname or url.username or url.password:
            raise _CatalogueInputError(f"invalid HTTPS {field}")
    for field in (
        "acquired_utc",
        "description",
        "archive_member" if version == 1 else "license",
    ):
        # The enclosing JSON byte budget bounds provenance text without truncation
        if not isinstance(metadata[field], str) or not metadata[field]:
            raise _CatalogueInputError(f"invalid {field}")
    if metadata["capture_file"] not in ("capture.pcap", "capture.pcapng"):
        raise _CatalogueInputError("capture_file must be capture.pcap or capture.pcapng")
    return metadata


def _catalogue_entries(path, limits):
    path = Path(path).resolve()
    document = read_json(path, limits.max_metadata_bytes)
    if not isinstance(document, dict) or set(document) != {
        "schema_version",
        "sources",
        "description",
    }:
        raise _CatalogueInputError("unsupported catalogue fields")
    sources = document["sources"]
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != 1
        or not isinstance(sources, list)
        or not sources
    ):
        raise _CatalogueInputError("unsupported catalogue schema or source count")
    # Validate every identity before selecting captures for byte verification
    entries, ids, directories = [], set(), set()
    for relative in sources:
        source = local_file(path.parent, relative)
        metadata = _source_metadata(source, limits)
        if metadata["id"] in ids or source.parent in directories:
            raise _CatalogueInputError("duplicate sample id or capture directory")
        ids.add(metadata["id"])
        directories.add(source.parent)
        entries.append((source.parent, metadata))
    return entries


def load_catalogues(paths, limits=DEFAULT_CATALOGUE_LIMITS, selected=()):
    """Verify selected inputs under one budget across every requested catalogue."""
    entries = [_catalogue_entries(path, limits) for path in paths]
    selected = set(selected)
    available = {metadata["id"] for group in entries for _, metadata in group}
    if selected - available:
        raise _CatalogueInputError("unknown sample id")
    groups, files = [], {}
    for group in entries:
        samples = []
        for directory, metadata in group:
            if selected and metadata["id"] not in selected:
                continue
            capture = local_file(directory, metadata["capture_file"]).resolve()
            size = capture.stat().st_size
            if size != metadata["capture_bytes"]:
                raise _CatalogueInputError(f"capture length mismatch: {capture}")
            if size > limits.max_capture_bytes:
                raise _CatalogueInputError(f"capture exceeds the byte budget: {capture}")
            previous = files.get(capture)
            identity = (size, metadata["capture_sha256"])
            if previous is not None and previous != identity:
                raise _CatalogueInputError(f"conflicting capture metadata: {capture}")
            files[capture] = identity
            samples.append(Sample(capture, metadata))
        groups.append(samples)
    # Aliases at separate paths still require separate reads; modes do not add inputs
    if sum(size for size, _ in files.values()) > limits.max_input_bytes:
        raise _CatalogueInputError("selected captures exceed the input byte budget")
    for capture, (size, expected_hash) in files.items():
        if hash_file(capture, expected_bytes=size) != expected_hash:
            raise _CatalogueInputError(f"capture hash mismatch: {capture}")
    return groups


def load_catalogue(path, limits=DEFAULT_CATALOGUE_LIMITS, selected=()):
    return load_catalogues([path], limits=limits, selected=selected)[0]
