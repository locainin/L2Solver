"""Validate recovery progress, cache state, and published artifact receipts."""

import hashlib
import json
import os
import re
import stat
from pathlib import Path

from .catalogue import read_json
from .process import DEFAULT_MAX_LOG_BYTES

DEFAULT_MAX_OUTPUT_BYTES = 4 * 1024 * 1024 * 1024
DEFAULT_MAX_MANIFEST_BYTES = 64 * 1024 * 1024
PROFILES = ("fast", "normal", "deep")
SEARCH_PHASES = (
    "framing_record_discovery",
    "transform_discovery",
    "assembly_validation",
    "expansion",
)
_CACHE_STAT_LINES = {
    "Cache entries": "entries",
    "Cached stage bytes": "entry_bytes",
    "Job checkpoints": "checkpoints",
}


def build_extract_command(
    binary,
    capture,
    output,
    *,
    profile="normal",
    jobs=None,
    strict_cache=False,
):
    if profile not in PROFILES:
        raise ValueError("profile must be fast, normal, or deep")
    if jobs is not None and (type(jobs) is not int or jobs <= 0):
        raise ValueError("jobs must be a positive integer")
    if type(strict_cache) is not bool:
        raise ValueError("strict_cache must be a boolean")

    command = [
        str(binary),
        "extract",
        str(capture),
        "--output",
        str(output),
        "--profile",
        profile,
        "--progress",
        "json",
    ]
    if jobs is not None:
        command.extend(("--jobs", str(jobs)))
    if strict_cache:
        command.append("--strict-cache")
    return command


def parse_cache_stats(output):
    values = {}
    for line in output.splitlines():
        label, separator, value = line.partition(":")
        key = _CACHE_STAT_LINES.get(label)
        if key is None:
            continue
        if not separator or key in values or not re.fullmatch(r"[0-9]+", value.strip()):
            raise ValueError(f"invalid cache stats line for {label}")
        values[key] = int(value.strip())

    missing = set(_CACHE_STAT_LINES.values()) - values.keys()
    if missing:
        raise ValueError(
            f"cache stats are missing required fields: {', '.join(sorted(missing))}"
        )
    return values


def _decode_progress_event(line):
    try:
        event = json.loads(line)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(event, dict) or not isinstance(event.get("counters"), dict):
        return None
    if not isinstance(event.get("phases"), list):
        return None
    phase = event.get("current_phase")
    if phase is not None and not isinstance(phase, str):
        return None
    return event


def read_progress_log(path, maximum_bytes=DEFAULT_MAX_LOG_BYTES):
    if type(maximum_bytes) is not int or maximum_bytes <= 0:
        raise ValueError("progress log budget must be a positive integer")
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum_bytes:
        raise ValueError("progress log is not a bounded regular file")

    events = []
    ignored_lines = 0
    with path.open("rb") as stream:
        for raw_line in stream:
            try:
                line = raw_line.decode("utf-8").strip()
            except UnicodeDecodeError:
                ignored_lines += 1
                continue
            event = _decode_progress_event(line)
            if event is None:
                if line:
                    ignored_lines += 1
                continue
            events.append(event)

    cache_hits = []
    cache_misses = []
    phases = set()
    for event in events:
        for field, values in (
            ("cache_hits", cache_hits),
            ("cache_misses", cache_misses),
        ):
            value = event["counters"].get(field)
            if type(value) is int and value >= 0:
                values.append(value)
        current = event.get("current_phase")
        if current is not None:
            phases.add(current)

    return {
        "events": len(events),
        "ignored_lines": ignored_lines,
        "cache_hits": max(cache_hits, default=0),
        "cache_misses": max(cache_misses, default=0),
        "phases_seen": sorted(phases),
    }


class ProgressWatcher:
    """Interrupt only after JSON progress records completed work in a search stage."""

    def __init__(
        self, phase, *, minimum_completed=1, maximum_bytes=DEFAULT_MAX_LOG_BYTES
    ):
        if phase not in SEARCH_PHASES:
            raise ValueError(
                "interrupt phase must name an active recovery search stage"
            )
        if type(minimum_completed) is not int or minimum_completed <= 0:
            raise ValueError("minimum completed work must be a positive integer")
        if type(maximum_bytes) is not int or maximum_bytes <= 0:
            raise ValueError("progress log budget must be a positive integer")
        self.phase = phase
        self.minimum_completed = minimum_completed
        self.maximum_bytes = maximum_bytes
        self.offset = 0
        self.pending = b""
        self.trigger_event = None

    def should_interrupt(self, logs):
        if self.trigger_event is not None:
            return True
        path = logs.get("stderr")
        if path is None or not path.exists():
            return False
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size < self.offset:
            raise ValueError("progress log changed while observing recovery")
        if metadata.st_size > self.maximum_bytes:
            raise ValueError("progress log exceeded the configured byte budget")

        with path.open("rb") as stream:
            stream.seek(self.offset)
            self.pending += stream.read()
        self.offset = metadata.st_size

        complete_lines = self.pending.split(b"\n")
        self.pending = complete_lines.pop()
        for raw_line in complete_lines:
            event = _decode_progress_event(
                raw_line.decode("utf-8", errors="replace").strip()
            )
            if event is None or event.get("current_phase") != self.phase:
                continue
            if any(
                isinstance(phase, dict)
                and phase.get("phase") == self.phase
                and phase.get("state") == "in_progress"
                and type(phase.get("completed")) is int
                and phase["completed"] >= self.minimum_completed
                for phase in event["phases"]
            ):
                self.trigger_event = event
                return True
        return False


def _safe_name(value):
    return (
        isinstance(value, str)
        and value not in ("", ".", "..")
        and Path(value).name == value
        and "/" not in value
        and "\\" not in value
        and "\x00" not in value
    )


def _hash_regular_file(path, expected_stat):
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (
            expected_stat.st_dev,
            expected_stat.st_ino,
        ):
            raise ValueError(f"output file changed while opening: {path.name}")
        while chunk := stream.read(1024 * 1024):
            total += len(chunk)
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    if (
        total != expected_stat.st_size
        or (after.st_dev, after.st_ino) != (expected_stat.st_dev, expected_stat.st_ino)
        or after.st_size != expected_stat.st_size
        or after.st_mtime_ns != expected_stat.st_mtime_ns
    ):
        raise ValueError(f"output file changed while hashing: {path.name}")
    return digest.hexdigest()


def validate_export_output(
    directory,
    *,
    exit_code,
    max_output_bytes=DEFAULT_MAX_OUTPUT_BYTES,
    max_manifest_bytes=DEFAULT_MAX_MANIFEST_BYTES,
):
    if type(max_output_bytes) is not int or max_output_bytes <= 0:
        raise ValueError("output byte budget must be a positive integer")
    if type(max_manifest_bytes) is not int or max_manifest_bytes <= 0:
        raise ValueError("manifest byte budget must be a positive integer")
    if not stat.S_ISDIR(directory.lstat().st_mode):
        raise ValueError("export output must be a real directory")

    manifest = read_json(directory / "manifest.json", max_manifest_bytes)
    if (
        not isinstance(manifest, dict)
        or type(manifest.get("schema_version")) is not int
        or manifest["schema_version"] != 1
        or manifest.get("export_status") not in ("complete", "partial")
        or not isinstance(manifest.get("artifacts"), list)
        or not isinstance(manifest.get("evidence"), dict)
    ):
        raise ValueError("export manifest has an unsupported schema")
    if (exit_code == 0 and manifest["export_status"] != "complete") or (
        exit_code == 3 and manifest["export_status"] != "partial"
    ):
        raise ValueError("export status does not match the process exit status")
    if exit_code not in (0, 3):
        raise ValueError("export output can only be validated after status 0 or 3")

    evidence = manifest["evidence"]
    evidence_name = evidence.get("file")
    coverage = evidence.get("coverage")
    if not _safe_name(evidence_name) or not isinstance(coverage, dict):
        raise ValueError("export manifest has invalid evidence metadata")
    retained_evidence_bytes = coverage.get("retained_bytes")
    if type(retained_evidence_bytes) is not int or retained_evidence_bytes < 0:
        raise ValueError("export manifest has an invalid evidence byte count")

    artifacts_by_name = {}
    reserved_names = {"manifest.json", "summary.txt", "limitations.txt", evidence_name}
    for artifact in manifest["artifacts"]:
        if not isinstance(artifact, dict) or not _safe_name(artifact.get("file")):
            raise ValueError("export manifest has an unsafe artifact path")
        name = artifact["file"]
        byte_length = artifact.get("byte_length")
        if type(byte_length) is not int or byte_length < 0:
            raise ValueError("export manifest has an invalid artifact byte length")
        if name in artifacts_by_name or name in reserved_names:
            raise ValueError(
                "export manifest lists a duplicate or reserved artifact path"
            )
        artifacts_by_name[name] = byte_length

    required = {"manifest.json", "summary.txt", evidence_name, *artifacts_by_name}
    optional = {"limitations.txt"}
    inventory = []
    total_bytes = 0
    names = set()
    for entry in directory.iterdir():
        metadata = entry.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("export output contains a non-regular or linked file")
        if entry.name not in required | optional:
            raise ValueError(f"export output contains an unlisted file: {entry.name}")
        names.add(entry.name)
        total_bytes += metadata.st_size
        if total_bytes > max_output_bytes:
            raise ValueError("export output exceeds the configured byte budget")
        inventory.append((entry, metadata))

    if not required.issubset(names):
        missing = sorted(required - names)
        raise ValueError(
            f"export output is missing required files: {', '.join(missing)}"
        )

    files = []
    artifact_hashes = {}
    evidence_file_bytes = None
    for path, metadata in sorted(inventory, key=lambda item: item[0].name):
        digest = _hash_regular_file(path, metadata)
        files.append(
            {"path": path.name, "byte_length": metadata.st_size, "sha256": digest}
        )
        if path.name == evidence_name:
            evidence_file_bytes = metadata.st_size
        if path.name in artifacts_by_name:
            if metadata.st_size != artifacts_by_name[path.name]:
                raise ValueError(
                    f"artifact byte length does not match manifest: {path.name}"
                )
            artifact_hashes[path.name] = digest

    if evidence_file_bytes != retained_evidence_bytes:
        raise ValueError("evidence sidecar byte length does not match manifest")
    artifacts = [
        {
            "file": name,
            "byte_length": artifacts_by_name[name],
            "sha256": artifact_hashes[name],
        }
        for name in sorted(artifacts_by_name)
    ]
    return {
        "export_status": manifest["export_status"],
        "artifact_count": len(artifacts),
        "output_bytes": total_bytes,
        "evidence_sidecar_bytes": evidence_file_bytes,
        "recovered_artifact_bytes": sum(artifacts_by_name.values()),
        "evidence_bytes": evidence_file_bytes + sum(artifacts_by_name.values()),
        "files": files,
        "artifacts": artifacts,
    }


def directory_snapshot(directory):
    try:
        root_stat = directory.lstat()
    except FileNotFoundError:
        return {
            "exists": False,
            "file_count": 0,
            "file_bytes": 0,
            "metadata_sha256": hashlib.sha256(b"[]").hexdigest(),
        }
    if not stat.S_ISDIR(root_stat.st_mode):
        raise ValueError(f"cache root must be a real directory: {directory}")

    entries = []
    file_count = 0
    file_bytes = 0
    for path in sorted(directory.rglob("*")):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError("cache tree contains a symbolic link")
        if stat.S_ISDIR(metadata.st_mode):
            kind = "directory"
        elif stat.S_ISREG(metadata.st_mode):
            kind = "file"
            file_count += 1
            file_bytes += metadata.st_size
        else:
            raise ValueError("cache tree contains an unsupported filesystem object")
        entries.append(
            {
                "path": path.relative_to(directory).as_posix(),
                "kind": kind,
                "mode": stat.S_IMODE(metadata.st_mode),
                "bytes": metadata.st_size if kind == "file" else 0,
                "mtime_ns": metadata.st_mtime_ns,
            }
        )
    encoded = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    return {
        "exists": True,
        "file_count": file_count,
        "file_bytes": file_bytes,
        "metadata_sha256": hashlib.sha256(encoded).hexdigest(),
    }


def cache_snapshot(cache_home, state_home, stats=None):
    result = {
        "cache": directory_snapshot(cache_home),
        "state": directory_snapshot(state_home),
    }
    if stats is not None:
        result["stats"] = stats
    return result


def xdg_environment(cache_home, state_home):
    environment = os.environ.copy()
    environment["XDG_CACHE_HOME"] = str(cache_home)
    environment["XDG_STATE_HOME"] = str(state_home)
    return environment
