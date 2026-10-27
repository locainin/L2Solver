"""Compare bounded recovery artifact receipts with external byte oracles."""

import os
import re
from pathlib import Path

from .catalogue import read_json

DEFAULT_MAX_RECOVERY_ORACLE_BYTES = 1024 * 1024
DEFAULT_MAX_RECOVERY_ARTIFACT_BYTES = 4 * 1024 * 1024 * 1024
MAX_EXPECTED_RECOVERY_ARTIFACTS = 4096
MAX_EXPECTED_RECOVERY_MEMBERS = 65536
_SHA256 = re.compile(r"[0-9a-f]{64}")
_BLOB_ID = re.compile(r"sha256:[0-9a-f]{64}")


def _valid_digest(value):
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _valid_length(value):
    return type(value) is int and 0 <= value <= DEFAULT_MAX_RECOVERY_ARTIFACT_BYTES


def _valid_text(value, maximum_characters):
    if not isinstance(value, str) or not value or len(value) > maximum_characters:
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return "\x00" not in value


def _read_recovery_oracle(value, maximum_bytes):
    if type(maximum_bytes) is not int or maximum_bytes <= 0:
        raise ValueError("recovery oracle byte budget must be positive")
    if isinstance(value, (str, os.PathLike)):
        value = read_json(Path(value), maximum_bytes)
    if not isinstance(value, dict) or set(value) != {"schema_version", "artifacts"}:
        raise ValueError("recovery oracle has an unsupported schema")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ValueError("recovery oracle has an unsupported schema version")

    artifacts = value["artifacts"]
    if (
        not isinstance(artifacts, list)
        or not artifacts
        or len(artifacts) > MAX_EXPECTED_RECOVERY_ARTIFACTS
    ):
        raise ValueError("recovery oracle has an invalid artifact count")

    validated = []
    seen_artifacts = set()
    seen_members = 0
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != {
            "sha256",
            "byte_length",
            "members",
        }:
            raise ValueError("recovery oracle artifact has an unsupported schema")
        digest = artifact["sha256"]
        byte_length = artifact["byte_length"]
        members = artifact["members"]
        if not _valid_digest(digest) or not _valid_length(byte_length):
            raise ValueError("recovery oracle artifact has an invalid identity")
        identity = (digest, byte_length)
        if identity in seen_artifacts:
            raise ValueError("recovery oracle repeats an artifact identity")
        if not isinstance(members, list):
            raise TypeError("recovery oracle artifact members must be an array")
        seen_artifacts.add(identity)

        validated_members = []
        seen_member_identities = set()
        for member in members:
            if not isinstance(member, dict) or set(member) != {
                "member_name",
                "sha256",
                "byte_length",
            }:
                raise ValueError("recovery oracle member has an unsupported schema")
            name = member["member_name"]
            member_digest = member["sha256"]
            member_length = member["byte_length"]
            if (
                not _valid_text(name, 4096)
                or not _valid_digest(member_digest)
                or not _valid_length(member_length)
            ):
                raise ValueError("recovery oracle member has an invalid identity")
            member_identity = (name, member_digest, member_length)
            if member_identity in seen_member_identities:
                raise ValueError("recovery oracle repeats a member identity")
            seen_member_identities.add(member_identity)
            validated_members.append(
                {
                    "member_name": name,
                    "sha256": member_digest,
                    "byte_length": member_length,
                }
            )
            seen_members += 1
            if seen_members > MAX_EXPECTED_RECOVERY_MEMBERS:
                raise ValueError("recovery oracle exceeds the member count limit")
        validated.append(
            {
                "sha256": digest,
                "byte_length": byte_length,
                "members": validated_members,
            }
        )
    return validated


def _receipt_origins(artifact, digest):
    origins = artifact.get("origins")
    if not isinstance(origins, list):
        raise TypeError("validated output receipt has invalid artifact origins")

    valid_origins = []
    for origin in origins:
        if not isinstance(origin, dict):
            raise TypeError("validated output receipt has an invalid artifact origin")
        case_id = origin.get("case_id")
        node_id = origin.get("node_id")
        node_kind = origin.get("node_kind")
        blob_id = origin.get("blob_id")
        if (
            not _valid_text(case_id, 256)
            or type(node_id) is not int
            or not 0 < node_id <= 2**64 - 1
            or not _valid_text(node_kind, 128)
            or not isinstance(blob_id, str)
            or _BLOB_ID.fullmatch(blob_id) is None
        ):
            raise ValueError("validated output receipt has an invalid artifact origin")
        if blob_id != f"sha256:{digest}":
            continue

        valid_origin = {
            "case_id": case_id,
            "node_id": node_id,
            "node_kind": node_kind,
            "blob_id": blob_id,
        }
        if node_kind == "archive_member":
            parent_node_id = origin.get("parent_node_id")
            member_name = origin.get("member_name")
            if (
                type(parent_node_id) is not int
                or not 0 < parent_node_id <= 2**64 - 1
                or not _valid_text(member_name, 4096)
            ):
                raise ValueError(
                    "validated output receipt has an invalid member origin"
                )
            valid_origin["parent_node_id"] = parent_node_id
            valid_origin["member_name"] = member_name
        valid_origins.append(valid_origin)
    return valid_origins


def compare_recovery_artifacts(
    run_record,
    oracle,
    *,
    max_oracle_bytes=DEFAULT_MAX_RECOVERY_ORACLE_BYTES,
):
    """Compare exact artifact bytes and same-case archive-member relationships.

    Oracle schema version 1 lists artifact hashes, lengths, and optional archive members.
    Engine-generated case IDs are taken from the validated output origins.
    """
    if not isinstance(run_record, dict) or not isinstance(
        run_record.get("output"), dict
    ):
        raise TypeError("recovery run is missing a validated output receipt")
    expected = _read_recovery_oracle(oracle, max_oracle_bytes)
    artifacts = run_record["output"].get("artifacts")
    if not isinstance(artifacts, list):
        raise TypeError("validated output receipt is missing artifacts")

    output_by_identity = {}
    origins_by_identity = {}
    members_by_parent = {}
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise TypeError("validated output receipt has an invalid artifact")
        file_name = artifact.get("file")
        digest = artifact.get("sha256")
        byte_length = artifact.get("byte_length")
        if (
            not _valid_text(file_name, 4096)
            or not _valid_digest(digest)
            or not _valid_length(byte_length)
        ):
            raise ValueError(
                "validated output receipt has an invalid artifact identity"
            )
        identity = (digest, byte_length)
        origins = _receipt_origins(artifact, digest)
        output_row = {
            "file": file_name,
            "sha256": digest,
            "byte_length": byte_length,
            "origins": origins,
        }
        output_by_identity.setdefault(identity, []).append(output_row)
        for origin in origins:
            origins_by_identity.setdefault(identity, []).append((output_row, origin))
            if origin["node_kind"] != "archive_member":
                continue
            member_identity = (
                origin["case_id"],
                origin["parent_node_id"],
                origin["member_name"],
                digest,
                byte_length,
            )
            members_by_parent.setdefault(member_identity, []).append(
                {"file": file_name, "origin": origin}
            )

    artifact_matches = []
    member_matches = []
    missing_artifacts = []
    missing_members = []
    expected_member_count = 0
    matched_member_count = 0
    for expected_artifact in expected:
        identity = (expected_artifact["sha256"], expected_artifact["byte_length"])
        matching_artifacts = output_by_identity.get(identity, [])
        if matching_artifacts:
            artifact_matches.extend(matching_artifacts)
        else:
            missing_artifacts.append(
                {"sha256": identity[0], "byte_length": identity[1]}
            )

        parent_origins = origins_by_identity.get(identity, [])
        for member in expected_artifact["members"]:
            expected_member_count += 1
            matched = []
            for parent_row, parent_origin in parent_origins:
                member_identity = (
                    parent_origin["case_id"],
                    parent_origin["node_id"],
                    member["member_name"],
                    member["sha256"],
                    member["byte_length"],
                )
                for member_row in members_by_parent.get(member_identity, []):
                    matched.append(
                        {
                            "case_id": parent_origin["case_id"],
                            "parent_file": parent_row["file"],
                            "parent_node_id": parent_origin["node_id"],
                            "member_name": member["member_name"],
                            "file": member_row["file"],
                            "sha256": member["sha256"],
                            "byte_length": member["byte_length"],
                            "node_id": member_row["origin"]["node_id"],
                        }
                    )
            if matched:
                matched_member_count += 1
                member_matches.extend(matched)
            else:
                missing_members.append(
                    {
                        "sha256": identity[0],
                        "member_name": member["member_name"],
                        "member_sha256": member["sha256"],
                        "byte_length": member["byte_length"],
                    }
                )

    expected_artifact_count = len(expected)
    matched_artifact_count = expected_artifact_count - len(missing_artifacts)
    return {
        "schema_version": 1,
        "accepted": not missing_artifacts and not missing_members,
        "counts": {
            "expected_artifacts": expected_artifact_count,
            "matched_artifacts": matched_artifact_count,
            "expected_members": expected_member_count,
            "matched_members": matched_member_count,
        },
        "artifact_matches": artifact_matches,
        "member_matches": member_matches,
        "missing_artifacts": missing_artifacts,
        "missing_members": missing_members,
    }
