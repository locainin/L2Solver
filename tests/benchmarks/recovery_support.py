"""Small export and oracle fixtures shared by recovery benchmark tests."""

import hashlib
import json


def write_export(directory, *, artifact=b"verified", artifact_rows=None):
    directory.mkdir()
    evidence = b'{"source":"capture"}\n'
    if artifact_rows is None:
        artifact_rows = [{"file": "artifact.bin", "bytes": artifact, "provenance": []}]

    manifest_artifacts = []
    for row in artifact_rows:
        data = row["bytes"]
        blob_id = "sha256:" + hashlib.sha256(data).hexdigest()
        for reference in row["provenance"]:
            node = reference.get("node")
            if isinstance(node, dict):
                node.setdefault("blob", blob_id)
        (directory / row["file"]).write_bytes(data)
        manifest_artifacts.append(
            {
                "file": row["file"],
                "byte_length": len(data),
                "provenance": row["provenance"],
            }
        )

    (directory / "evidence.jsonl").write_bytes(evidence)
    (directory / "summary.txt").write_text("complete\n")
    (directory / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "export_status": "complete",
                "evidence": {
                    "file": "evidence.jsonl",
                    "coverage": {"retained_bytes": len(evidence)},
                },
                "artifacts": manifest_artifacts,
            }
        )
        + "\n"
    )


def provenance(case_id, node_id, kind, **details):
    return {
        "case_id": case_id,
        "node": {"id": node_id, "kind": kind, "details": details},
    }


def oracle_artifact(artifact_bytes, members=()):
    return {
        "sha256": hashlib.sha256(artifact_bytes).hexdigest(),
        "byte_length": len(artifact_bytes),
        "members": [
            {
                "member_name": member_name,
                "sha256": hashlib.sha256(member_bytes).hexdigest(),
                "byte_length": len(member_bytes),
            }
            for member_name, member_bytes in members
        ],
    }


def write_oracle(path, artifacts):
    path.write_text(
        json.dumps({"schema_version": 1, "artifacts": artifacts}), encoding="utf-8"
    )
    return path
