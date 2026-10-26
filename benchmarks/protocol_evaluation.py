"""Load a blind, family-disjoint protocol evaluation manifest."""

import re
from dataclasses import dataclass
from pathlib import Path

from benchmarks.runner.catalogue import hash_file, local_file, read_json

MANIFEST_FIELDS = {"schema_version", "corpus_id", "cases"}
CASE_FIELDS = {
    "case_id",
    "capture_file",
    "capture_sha256",
    "capture_bytes",
    "message_count",
    "split",
    "grammar_family_id",
    "capture_group_id",
}
SPLITS = {"development", "validation", "heldout", "negative"}
PROTOCOL_SPLITS = SPLITS - {"negative"}
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class _ManifestInputError(ValueError):
    """Manifest metadata or its local capture inputs violate the contract."""


@dataclass(frozen=True)
class BlindEvaluationLimits:
    max_manifest_bytes: int = 1024 * 1024
    max_capture_bytes: int = 256 * 1024 * 1024
    max_input_bytes: int = 2 * 1024 * 1024 * 1024
    max_cases: int = 512

    def __post_init__(self):
        for field, value in vars(self).items():
            if type(value) is not int or value <= 0:
                raise ValueError(f"{field} must be a positive integer")


DEFAULT_LIMITS = BlindEvaluationLimits()


@dataclass(frozen=True)
class BlindCase:
    case_id: str
    capture: Path
    capture_sha256: str
    capture_bytes: int
    message_count: int | None
    split: str


@dataclass(frozen=True)
class BlindManifest:
    corpus_id: str
    cases: tuple[BlindCase, ...]


def load_blind_manifest(path, *, split=None, limits=DEFAULT_LIMITS):
    """Validate every listed capture, then return the requested blind split."""
    path = Path(path).resolve()
    document = read_json(path, limits.max_manifest_bytes)
    if not isinstance(document, dict) or set(document) != MANIFEST_FIELDS:
        raise _ManifestInputError("unsupported manifest fields")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise _ManifestInputError("unsupported manifest schema")
    corpus_id = document["corpus_id"]
    if not isinstance(corpus_id, str) or not IDENTIFIER.fullmatch(corpus_id):
        raise _ManifestInputError("invalid corpus id")
    rows = document["cases"]
    if not isinstance(rows, list) or not rows or len(rows) > limits.max_cases:
        raise _ManifestInputError("invalid case count")
    if split is not None and (not isinstance(split, str) or split not in SPLITS):
        raise ValueError("unsupported split selection")

    cases = []
    case_ids, capture_paths = set(), set()
    family_splits, group_splits = {}, {}
    aggregate_bytes = 0
    root = path.parent
    for row in rows:
        if not isinstance(row, dict) or set(row) != CASE_FIELDS:
            raise _ManifestInputError("unsupported case fields")
        case_id = row["case_id"]
        if not isinstance(case_id, str) or not IDENTIFIER.fullmatch(case_id):
            raise _ManifestInputError("invalid case id")
        if case_id in case_ids:
            raise _ManifestInputError("duplicate case id")
        case_ids.add(case_id)

        split_name = row["split"]
        if not isinstance(split_name, str) or split_name not in SPLITS:
            raise _ManifestInputError("invalid case split")
        family_id = row["grammar_family_id"]
        if split_name in PROTOCOL_SPLITS:
            if not isinstance(family_id, str) or not IDENTIFIER.fullmatch(family_id):
                raise _ManifestInputError("protocol case requires a grammar family id")
            prior = family_splits.setdefault(family_id, split_name)
            if prior != split_name:
                raise _ManifestInputError("grammar family crosses splits")
        elif family_id is not None:
            raise _ManifestInputError("negative controls cannot name a grammar family")

        group_id = row["capture_group_id"]
        if not isinstance(group_id, str) or not IDENTIFIER.fullmatch(group_id):
            raise _ManifestInputError("invalid capture group id")
        prior = group_splits.setdefault(group_id, split_name)
        if prior != split_name:
            raise _ManifestInputError("capture group crosses splits")

        capture_bytes = row["capture_bytes"]
        if type(capture_bytes) is not int or not 0 < capture_bytes <= limits.max_capture_bytes:
            raise _ManifestInputError("invalid or oversized capture_bytes")
        message_count = row["message_count"]
        if split_name in PROTOCOL_SPLITS:
            if type(message_count) is not int or message_count <= 0:
                raise _ManifestInputError("invalid message_count")
        elif message_count is not None:
            raise _ManifestInputError("negative controls must not claim a message count")
        aggregate_bytes += capture_bytes
        if aggregate_bytes > limits.max_input_bytes:
            raise _ManifestInputError("aggregate capture bytes exceed the input limit")

        digest = row["capture_sha256"]
        if not isinstance(digest, str) or not SHA256.fullmatch(digest):
            raise _ManifestInputError("invalid capture_sha256")
        capture = local_file(root, row["capture_file"])
        relative = capture.relative_to(root).as_posix()
        if relative in capture_paths:
            raise _ManifestInputError("duplicate capture path")
        capture_paths.add(relative)
        try:
            actual_digest = hash_file(capture, expected_bytes=capture_bytes)
        except ValueError as error:
            raise _ManifestInputError(f"capture length mismatch: {case_id}") from error
        if actual_digest != digest:
            raise _ManifestInputError(f"capture hash mismatch: {case_id}")

        cases.append(
            BlindCase(
                case_id=case_id,
                capture=capture,
                capture_sha256=digest,
                capture_bytes=capture_bytes,
                message_count=message_count,
                split=split_name,
            )
        )

    selected = tuple(case for case in cases if split is None or case.split == split)
    if not selected:
        raise _ManifestInputError("selected split has no cases")
    return BlindManifest(corpus_id=corpus_id, cases=selected)
