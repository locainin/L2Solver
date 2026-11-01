"""Independently validate refinement case artifacts and summarize their evidence."""

import json
import stat
from pathlib import Path

from .catalogue import hash_file, read_json
from .recovery import _hash_regular_file, _safe_name

CASE_INPUTS = {"near-eof": "near-eof.bin", "encoded": "encoded-gzip.txt",
               "valid-zip": "large-valid.zip", "corrupt-zip": "large-corrupt.zip",
               "output-limit": "output-limit.gz"}
MAX_DOCUMENT = 64 * 1024 * 1024


def _labels(value, key):
    if isinstance(value, dict):
        return ([value[key]] if isinstance(value.get(key), str) else []) + [
            label for item in value.values() for label in _labels(item, key)]
    if isinstance(value, list):
        return [label for item in value for label in _labels(item, key)]
    return []


def _checked_file(path, expected, kind):
    metadata = path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or metadata.st_size != expected.get("length")):
        raise ValueError(f"{kind} is missing, linked, or has the wrong length")
    actual = _hash_regular_file(path, metadata)
    if actual != expected.get("sha256"):
        raise ValueError(f"{kind} digest changed")
    return actual


def _artifacts(output, manifest):
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("artifact list is missing")
    result, names = [], set()
    for artifact in artifacts:
        if not isinstance(artifact, dict) or not _safe_name(artifact.get("file")):
            raise ValueError("artifact has an unsafe name")
        name = artifact["file"]
        if name in names or name in ("manifest.json", "summary.txt"):
            raise ValueError("artifact name is duplicated or reserved")
        names.add(name)
        expected = {"length": artifact.get("byte_length"), "sha256": artifact.get("sha256")}
        if type(expected["length"]) is not int or expected["length"] < 0:
            raise ValueError("artifact length is invalid")
        try:
            digest = _checked_file(output / name, expected, "artifact")
        except OSError as error:
            raise ValueError("artifact is missing") from error
        result.append({"file": name, "length": expected["length"], "sha256": digest,
                       "origins": _labels(artifact.get("origins", []), "kind")})
    if {entry.name for entry in output.iterdir()} != names | {"manifest.json", "summary.txt"}:
        raise ValueError("output has missing or unlisted files")
    return result


def require_cpu_bound(limits):
    quota = limits.get("effective_visible_quota") if isinstance(limits, dict) else None
    if (not isinstance(quota, dict) or type(quota.get("quota_us")) is not int
            or type(quota.get("period_us")) is not int or quota["quota_us"] <= 0
            or quota["period_us"] <= 0 or quota["quota_us"] > quota["period_us"]):
        raise ValueError("visible CPU quota is missing or exceeds one CPU")


def _metadata_digest(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("output metadata is not a regular unlinked file")
    return _hash_regular_file(path, info)


def _case_requirements(case, artifacts, omissions, files):
    digests = {item["sha256"] for item in artifacts}
    first, second = files["first.png"]["sha256"], files["second.png"]["sha256"]
    reason = json.dumps(omissions, sort_keys=True).lower()
    if case in ("near-eof", "corrupt-zip"):
        if first not in digests or "no supported whole-source streaming transformation" not in reason:
            raise ValueError("recovered PNG or unsupported transformation omission is missing")
        if case == "near-eof" and files["embedded.zip"]["sha256"] not in digests:
            raise ValueError("near-EOF embedded ZIP artifact is missing")
        if case == "corrupt-zip" and files["large-corrupt.zip"]["sha256"] in digests:
            raise ValueError("corrupt ZIP was published as a validated artifact")
    elif case == "encoded":
        archive = files["encoded-reference.zip"]["sha256"]
        if (not {first, second}.issubset(digests) or not any(
                item["sha256"] == archive and {"base64_decode", "gzip_decompress"}.issubset(item["origins"])
                for item in artifacts)):
            raise ValueError("decoded ZIP, PNG, or transformation provenance is missing")
    elif case == "valid-zip":
        if files["large-valid.zip"]["sha256"] not in digests:
            raise ValueError("valid ZIP artifact is missing")
        for digest in (first, second):
            if not any(item["sha256"] == digest and "archive_member" in item["origins"] for item in artifacts):
                raise ValueError("ZIP member artifact or provenance is missing")
        if "entry_expanded_byte_limit" not in reason:
            raise ValueError("ZIP member limit omission is missing")
    elif case == "output-limit":
        if "outputlimitexceeded" not in reason or "gzip_decompress" not in reason:
            raise ValueError("gzip output-limit omission is missing")
        if first in digests:
            raise ValueError("bytes beyond the output limit were published")


def _last_counters(path):
    result = None
    with path.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict) and isinstance(event.get("counters"), dict):
                result = event["counters"]
    return result


def validate_case(root, case):
    root = Path(root)
    if case not in CASE_INPUTS:
        raise ValueError("unknown refinement case")
    fixtures = read_json(root / "fixtures.json", MAX_DOCUMENT)
    before = fixtures["files"][CASE_INPUTS[case]]
    source = root / "fixtures" / CASE_INPUTS[case]
    try:
        actual = _checked_file(source, before, "source")
    except OSError as error:
        raise ValueError("source is missing") from error
    receipt_dir, output = root / "receipts" / case, root / "output" / case
    receipt = read_json(receipt_dir / "cgroup.json", MAX_DOCUMENT)
    disk = read_json(receipt_dir / "disk-observation.json", MAX_DOCUMENT)
    if not stat.S_ISDIR(output.lstat().st_mode):
        raise ValueError("output must be a real directory")
    manifest_digest = _metadata_digest(output / "manifest.json")
    summary_digest = _metadata_digest(output / "summary.txt")
    manifest = read_json(output / "manifest.json", MAX_DOCUMENT)
    if receipt.get("exit_code") != 3 or receipt.get("status") is not None or manifest.get("complete") is not False:
        raise ValueError("case did not report a partial result with exit status 3")
    group = receipt["cgroup"]
    if (group.get("memory_max_bytes") != 512 * 1024 * 1024 or group.get("swap_max_bytes") != 0
            or group.get("oom") != 0 or group.get("oom_kill") != 0):
        raise ValueError("cgroup cap, swap, or OOM evidence is invalid")
    require_cpu_bound(group.get("cpu_hierarchy"))
    require_cpu_bound(group.get("cpu_hierarchy_after"))
    if not disk.get("samples") or disk.get("sampling_errors") or disk.get("disk_stop_requested"):
        raise ValueError("disk sampling was incomplete or stopped the workload")
    sources = manifest.get("sources")
    if not isinstance(sources, list) or len(sources) != 1 or sources[0].get("sha256") != actual:
        raise ValueError("manifest source identity is incorrect")
    omissions = sources[0].get("omissions")
    if not isinstance(omissions, list) or not omissions:
        raise ValueError("partial result has no omissions")
    artifacts = _artifacts(output, manifest)
    _case_requirements(case, artifacts, omissions, fixtures["files"])
    monitor = receipt["monitor"]
    if (monitor.get("memory_scope") != "analyzer_process_only"
            or monitor.get("io_measurement_scope") != "linux_procfs_analyzer_process_only"):
        raise ValueError("process observations do not describe the analyzer")
    counters = _last_counters(receipt_dir / "stderr.log") or {}
    reads = counters.get("source_read_bytes")
    io = monitor.get("process_io_bytes") or {}
    rchar = io.get("rchar_bytes")
    if (type(reads) is not int or reads <= 0 or type(rchar) is not int or rchar <= 0
            or monitor.get("peak_sampled_rss_bytes") is None):
        raise ValueError("source-read, analyzer I/O, or RSS measurement is unavailable")
    reason = json.dumps(omissions, sort_keys=True).lower()
    return {"case": case, "source_path": f"fixtures/{CASE_INPUTS[case]}",
            "source_length": before["length"], "source_sha256": actual,
            "exit_code": 3, "manifest_complete": False,
            "duration_seconds": receipt["duration_seconds"],
            "binary_rss_peak_bytes_sampled": monitor["peak_sampled_rss_bytes"],
            "cgroup_peak_bytes": group["peak_bytes"], "cgroup_max_events": group["max_events"],
            "cgroup_oom_events": group["oom"], "cgroup_oom_kill_events": group["oom_kill"],
            "cgroup_memory_max_bytes": group["memory_max_bytes"], "cgroup_swap_max_bytes": group["swap_max_bytes"],
            "visible_cpu_quota": group["cpu_hierarchy"]["effective_visible_quota"],
            "source_read_bytes": reads, "source_read_amplification": reads / before["length"],
            "binary_io": io, "binary_rchar_per_source_byte": rchar / before["length"],
            "disk_observation": disk, "artifacts": [
                {**item, "path": f"output/{case}/{item['file']}"} for item in artifacts],
            "manifest": {"path": f"output/{case}/manifest.json", "sha256": manifest_digest},
            "output_summary": {"path": f"output/{case}/summary.txt", "sha256": summary_digest},
            "omissions": omissions,
            "explicit_corruption_reason": ("corrupt" in reason or "central directory" in reason) if case == "corrupt-zip" else None}


def summarize(root, binary, reports):
    root, binary = Path(root), Path(binary)
    plan = read_json(root / "plan.json", MAX_DOCUMENT)
    digest = hash_file(binary)
    if digest != plan["binary_sha256"]:
        raise ValueError("candidate binary identity changed")
    cases = {}
    for case in CASE_INPUTS:
        report = reports[case]
        if report.get("case") != case:
            raise ValueError("case validation identity changed")
        cases[case] = report
    return {"source_commit": plan["source_commit"], "binary": {"name": binary.name, "sha256": digest},
            "case_checks_passed": True, "cases": cases, "limitations": [
                "Evidence applies to the stated candidate source and binary only; c98ac15 measurements are not final integrated-source qualification",
                "Operating-system page cache is uncontrolled; no cold-cache claim is made",
                "Analyzer RSS and temporary disk peaks are sampled lower bounds, not orchestrator RSS or exact peaks",
                "Source-read counters and analyzer rchar measure different work; derived streams add I/O",
                "All five cases are partial and preserve their reported omissions",
            ]}
