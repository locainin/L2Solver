"""Check captured bytes, bounded searches, and replayed outputs independently."""

import json
import shutil
from pathlib import Path

from benchmarks.runner.catalogue import hash_file
from benchmarks.runner.execution import run_child, write_json_new
from benchmarks.runner.validation import decoded_blobs, validate_case

from .traffic import digest


class Analyzer:
    def __init__(self, binary, directory):
        self.binary = str(Path(binary).resolve(strict=True))
        self.directory = directory
        self.commands = []
        self.binary_sha256 = hash_file(Path(self.binary))
        tshark = shutil.which("tshark")
        self.tshark_executable = Path(tshark).resolve(strict=True) if tshark else None
        self.tshark_sha256 = hash_file(self.tshark_executable) if self.tshark_executable else None
        self.tshark_version = None

    def assert_tshark_unchanged(self):
        if self.tshark_executable and hash_file(self.tshark_executable) != self.tshark_sha256:
            raise ValueError("TShark executable changed during the lab")

    def tshark_command(self, name, arguments):
        if self.tshark_executable is None:
            return False
        self.assert_tshark_unchanged()
        command = [str(self.tshark_executable), *arguments]
        code, failure, error, metrics = run_child(command, self.directory, 30, name)
        self.commands.append({"name": name, "command": command, "exit_code": code,
                              "failure": failure, "error": error, "metrics": metrics})
        self.assert_tshark_unchanged()
        if failure or code != 0:
            raise RuntimeError(f"{name} failed; inspect its saved logs")
        return True

    def tshark_provenance(self):
        if self.tshark_executable is None:
            return {"available": False, "reason": "tshark_not_found"}
        if self.tshark_version is None:
            self.tshark_command("tshark.version", ["-n", "-v"])
            version_output = (self.directory / "tshark.version.stdout.log").read_text(
                encoding="utf-8", errors="replace")
            self.tshark_version = version_output.splitlines()[0] if version_output else "unknown"
        self.assert_tshark_unchanged()
        return {"available": True, "executable": str(self.tshark_executable),
                "sha256": self.tshark_sha256, "version": self.tshark_version}

    def command(self, name, arguments, executable=None):
        if hash_file(Path(self.binary)) != self.binary_sha256:
            raise ValueError("analyzer executable changed during the lab")
        command = [executable or self.binary, *arguments]
        code, failure, error, metrics = run_child(command, self.directory, 30, name)
        self.commands.append({"name": name, "command": command, "exit_code": code,
                              "failure": failure, "error": error, "metrics": metrics})
        if failure or code not in (0, 3):
            raise RuntimeError(f"{name} failed; inspect its saved logs")
        return code

    def read(self, name):
        return json.loads((self.directory / name).read_text(encoding="utf-8"))


def captured_payload(analyzer, sample, receiver):
    if analyzer.tshark_executable is None:
        return None
    analyzer.tshark_provenance()
    protocol = sample.transport
    source = receiver["source"][1]
    destination = receiver["destination"][1]
    expression = (f"ip.src == 127.0.0.1 && ip.dst == 127.0.0.1 && "
                  f"{protocol}.srcport == {source} && {protocol}.dstport == {destination}")
    analyzer.tshark_command(sample.name + ".tshark", ["-n", "-r", "capture.pcapng", "-Y", expression,
                              "-T", "fields", "-e", "frame.number", "-e", protocol + ".payload"])
    records = []
    for line in (analyzer.directory / (sample.name + ".tshark.stdout.log")).read_text().splitlines():
        number, payload = line.split("\t")
        if payload:
            records.append((int(number), bytes.fromhex(payload.replace(":", ""))))
    observed = b"".join(data for _, data in records)
    if observed != sample.wire:
        raise ValueError(f"{sample.name}: capture differs from actual sender and receiver bytes")
    return [number for number, _ in records]


def replay(analyzer, sample, node, candidate, ordinal):
    name = f"{sample.name}.candidate-{ordinal}"
    write_json_new(analyzer.directory / (name + ".recipe.json"), candidate["recipe"])
    analyzer.command(name + ".decode", ["workbench", "decode", "case.json", "--node", str(node),
                     "--recipe", name + ".recipe.json", "--output", name + ".case.json"])
    case = analyzer.read(name + ".case.json")
    outputs = [item for item in case["nodes"] if item["kind"] == "decoding_output"]
    if len(outputs) != 1:
        raise ValueError("candidate replay must produce one explicit output")
    analyzer.command(name + ".export", ["workbench", "export", name + ".case.json", "--node",
                     str(outputs[0]["id"]), "--output", name + ".bin"])
    analyzer.command(name + ".evidence", ["workbench", "query", name + ".case.json", "--format",
                     "html", "--output", name + ".html"])
    output = (analyzer.directory / (name + ".bin")).read_bytes()
    if digest(output) != candidate["output_sha256"]:
        raise ValueError("replayed output differs from search receipt")
    return {"candidate_id": candidate["id"], "recipe": candidate["recipe"],
            "output_sha256": digest(output), "output_file": name + ".bin",
            "equals_withheld_original": output == sample.expected if sample.expected is not None else False}


def examine(analyzer, sample, receiver, case):
    frames = captured_payload(analyzer, sample, receiver)
    kind = "tcp_byte_run" if sample.transport == "tcp" else "udp_payload"
    query = ["workbench", "query", "case.json", "--filter", "kind=" + kind,
             "--filter", "proto=" + sample.transport,
             "--filter", "sport=" + str(receiver["source"][1]),
             "--filter", "dport=" + str(receiver["destination"][1])]
    analyzer.command(sample.name + ".query", [*query, "--output", sample.name + ".query.json"])
    matches = analyzer.read(sample.name + ".query.json")["matches"]
    if len(matches) != 1:
        raise ValueError(f"{sample.name}: expected exactly one complete retained payload")
    match = matches[0]
    if decoded_blobs(case)[match["blob"]] != sample.wire:
        raise ValueError(f"{sample.name}: retained payload differs from independent capture bytes")
    if frames is not None and match["packet_numbers"] != frames:
        raise ValueError(f"{sample.name}: supporting packet list differs from TShark")
    write_json_new(analyzer.directory / (sample.name + ".plan.json"), sample.plan)
    analyzer.command(sample.name + ".search", ["workbench", "search", "case.json", "--node",
                     str(match["node_id"]), "--plan", sample.name + ".plan.json",
                     "--output", sample.name + ".search.json"])
    search = analyzer.read(sample.name + ".search.json")["search"]
    # Replay each distinct satisfying output, rather than choosing one by the hidden answer
    satisfied = [candidate for candidate in search["candidates"]
                 if candidate["status"] == "constraints_satisfied"]
    unique = {}
    for candidate in satisfied:
        unique.setdefault(candidate["output_sha256"], candidate)
    outputs = [replay(analyzer, sample, match["node_id"], candidate, ordinal)
               for ordinal, candidate in enumerate(unique.values(), 1)]
    recovered = any(output["equals_withheld_original"] for output in outputs)
    if sample.expected is not None and not recovered:
        raise ValueError(f"{sample.name}: no satisfying output equals the withheld original")
    if sample.name == "valid-json-control" and not outputs:
        raise ValueError("structural lookalike control unexpectedly failed its structural checks")
    if sample.expected is None and sample.name != "valid-json-control" and outputs:
        raise ValueError(f"{sample.name}: negative control unexpectedly satisfied its requirements")
    differential = {"available": frames is not None,
                    "reason": None if frames is not None else "tshark_not_found",
                    "payload_frames": frames}
    return {"name": sample.name, "transport": sample.transport, "node_id": match["node_id"],
            "source_ranges": match["source_ranges"], "packet_filters": match["packet_filters"],
            "tshark_payload_frames": frames, "tshark_differential": differential,
            "wire_sha256": digest(sample.wire),
            "withheld_original_sha256": digest(sample.expected) if sample.expected is not None else None,
            "candidates": len(search["candidates"]), "satisfying_candidates": len(satisfied),
            "search_exhaustive_within_plan": search["search_exhaustive_within_plan"],
            "limits": search["limits"], "key_tests": search["key_tests"], "outputs": outputs,
            "result": "exact_recovery" if recovered else "structural_match_only" if outputs else
                      "no_match_within_plan" if search["search_exhaustive_within_plan"] else "unresolved"}


def analyze(binary, directory, samples, transport):
    analyzer = Analyzer(binary, directory)
    capture = (directory / "capture.pcapng").read_bytes()
    tshark_provenance = analyzer.tshark_provenance()
    metadata = {"capture_sha256": digest(capture), "capture_bytes": len(capture)}
    code = analyzer.command("build", ["workbench", "build", "capture.pcapng", "--output", "case.json"])
    case = analyzer.read("case.json")
    validation = validate_case(case, capture, metadata, code)
    analyzer.command("evidence", ["workbench", "query", "case.json", "--format", "html",
                     "--output", "evidence.html"])
    results = [examine(analyzer, sample, receiver, case)
               for sample, receiver in zip(samples, transport["receivers"], strict=True)]
    if hash_file(Path(analyzer.binary)) != analyzer.binary_sha256:
        raise ValueError("analyzer executable changed during the lab")
    analyzer.assert_tshark_unchanged()
    result = {"schema_version": 1, "binary_sha256": analyzer.binary_sha256,
              "tshark_differential": tshark_provenance,
              "source": metadata, "transport": transport, "independent_validation": validation,
              "results": results, "commands": analyzer.commands,
              "limitations": ["Only owned IPv4 loopback traffic and the listed bounded search plans were tested",
                              "Known plaintext and structural constraints came from the clear baseline",
                              "Full original hashes were withheld until candidate replay and byte comparison",
                              "Structural matches do not establish plaintext authenticity or malicious intent",
                              "TCP capture-order concatenation is an independent lab check, not a general TCP reassembler"]}
    write_json_new(directory / "result.json", result)
    return result
