"""Recovery acceptance compares expected bytes with bounded export receipts."""

from benchmarks.runner.recovery import validate_export_output
from benchmarks.runner.recovery_acceptance import compare_recovery_artifacts
from tests.benchmarks.recovery_support import (
    oracle_artifact,
    provenance,
    write_export,
    write_oracle,
)


def run_record(output, *, recovered_artifacts=0):
    return {
        "progress": {"counters": {"recovered_artifacts": recovered_artifacts}},
        "output": validate_export_output(output, exit_code=0),
    }


def test_exact_artifacts_match_without_engine_case_ids_or_progress_counts(tmp_path):
    parent = b"exact archive bytes"
    member = b"exact archive member bytes"
    case_id = "engine-generated-case-id-v2"
    output = tmp_path / "output"
    write_export(
        output,
        artifact_rows=[
            {
                "file": "archive.zip",
                "bytes": parent,
                "provenance": [provenance(case_id, 41, "validated_artifact")],
            },
            {
                "file": "member.bin",
                "bytes": member,
                "provenance": [
                    provenance(
                        case_id,
                        42,
                        "archive_member",
                        archive_node=41,
                        utf8_name="folder/member.bin",
                    )
                ],
            },
        ],
    )
    oracle_path = write_oracle(
        tmp_path / "oracle.json",
        [oracle_artifact(parent, [("folder/member.bin", member)])],
    )

    result = compare_recovery_artifacts(run_record(output), oracle_path)

    assert result["accepted"] is True
    assert result["counts"] == {
        "expected_artifacts": 1,
        "matched_artifacts": 1,
        "expected_members": 1,
        "matched_members": 1,
    }
    assert result["artifact_matches"][0]["origins"] == [
        {
            "case_id": case_id,
            "node_id": 41,
            "node_kind": "validated_artifact",
            "blob_id": "sha256:" + result["artifact_matches"][0]["sha256"],
        }
    ]
    assert result["member_matches"][0]["parent_node_id"] == 41
    assert result["member_matches"][0]["member_name"] == "folder/member.bin"


def test_standalone_artifact_matches_without_members_or_case_id_in_oracle(tmp_path):
    png = b"exact standalone PNG bytes"
    output = tmp_path / "output"
    write_export(
        output,
        artifact_rows=[
            {
                "file": "image.png",
                "bytes": png,
                "provenance": [provenance("current-case-id", 8, "http_body")],
            }
        ],
    )

    result = compare_recovery_artifacts(
        run_record(output), {"schema_version": 1, "artifacts": [oracle_artifact(png)]}
    )

    assert result["accepted"] is True
    assert result["counts"]["matched_artifacts"] == 1
    assert result["counts"]["expected_members"] == 0


def test_wrong_member_bytes_do_not_match(tmp_path):
    parent = b"verified archive"
    expected_member = b"expected member bytes"
    output = tmp_path / "output"
    write_export(
        output,
        artifact_rows=[
            {
                "file": "archive.zip",
                "bytes": parent,
                "provenance": [provenance("case-a", 1, "record_candidate")],
            },
            {
                "file": "member.bin",
                "bytes": b"different member bytes",
                "provenance": [
                    provenance(
                        "case-a",
                        2,
                        "archive_member",
                        archive_node=1,
                        utf8_name="member.bin",
                    )
                ],
            },
        ],
    )

    result = compare_recovery_artifacts(
        run_record(output),
        {
            "schema_version": 1,
            "artifacts": [oracle_artifact(parent, [("member.bin", expected_member)])],
        },
    )

    assert result["accepted"] is False
    assert result["counts"]["matched_artifacts"] == 1
    assert result["counts"]["matched_members"] == 0
    assert result["missing_members"][0]["member_name"] == "member.bin"


def test_missing_expected_member_is_reported(tmp_path):
    parent = b"verified archive"
    member = b"member absent from output"
    output = tmp_path / "output"
    write_export(
        output,
        artifact_rows=[
            {
                "file": "archive.zip",
                "bytes": parent,
                "provenance": [provenance("case-a", 5, "record_candidate")],
            }
        ],
    )

    result = compare_recovery_artifacts(
        run_record(output),
        {
            "schema_version": 1,
            "artifacts": [oracle_artifact(parent, [("missing.txt", member)])],
        },
    )

    assert result["accepted"] is False
    assert result["counts"]["matched_artifacts"] == 1
    assert result["counts"]["matched_members"] == 0
    assert result["missing_members"][0]["member_name"] == "missing.txt"


def test_identical_artifact_bytes_preserve_all_actual_origins(tmp_path):
    parent = b"same archive bytes"
    member = b"same member bytes"
    case_ids = ("case-old", "case-new")
    output = tmp_path / "output"
    write_export(
        output,
        artifact_rows=[
            {
                "file": "archive.zip",
                "bytes": parent,
                "provenance": [
                    provenance(case_ids[0], 10, "record_candidate"),
                    provenance(case_ids[1], 20, "embedded_artifact"),
                ],
            },
            {
                "file": "member.bin",
                "bytes": member,
                "provenance": [
                    provenance(
                        case_ids[0],
                        11,
                        "archive_member",
                        archive_node=10,
                        utf8_name="member.bin",
                    ),
                    provenance(
                        case_ids[1],
                        21,
                        "archive_member",
                        archive_node=20,
                        utf8_name="member.bin",
                    ),
                ],
            },
        ],
    )

    result = compare_recovery_artifacts(
        run_record(output),
        {
            "schema_version": 1,
            "artifacts": [oracle_artifact(parent, [("member.bin", member)])],
        },
    )

    assert result["accepted"] is True
    assert {
        origin["case_id"] for origin in result["artifact_matches"][0]["origins"]
    } == set(case_ids)
    assert {match["case_id"] for match in result["member_matches"]} == set(case_ids)


def test_member_from_a_different_actual_case_cannot_match_parent(tmp_path):
    parent = b"expected archive"
    member = b"matching member bytes"
    output = tmp_path / "output"
    write_export(
        output,
        artifact_rows=[
            {
                "file": "archive.zip",
                "bytes": parent,
                "provenance": [provenance("case-parent", 71, "http_body")],
            },
            {
                "file": "member.bin",
                "bytes": member,
                "provenance": [
                    provenance(
                        "case-child",
                        72,
                        "archive_member",
                        archive_node=71,
                        utf8_name="member.bin",
                    )
                ],
            },
        ],
    )

    result = compare_recovery_artifacts(
        run_record(output),
        {
            "schema_version": 1,
            "artifacts": [oracle_artifact(parent, [("member.bin", member)])],
        },
    )

    assert result["accepted"] is False
    assert result["counts"]["matched_artifacts"] == 1
    assert result["counts"]["matched_members"] == 0
    assert result["missing_members"][0]["member_name"] == "member.bin"


def test_parent_content_mismatch_does_not_match_member_relationship(tmp_path):
    expected_parent = b"oracle archive bytes"
    actual_parent = b"different archive bytes"
    member = b"matching member bytes"
    output = tmp_path / "output"
    write_export(
        output,
        artifact_rows=[
            {
                "file": "archive.zip",
                "bytes": actual_parent,
                "provenance": [provenance("case-a", 71, "record_candidate")],
            },
            {
                "file": "member.bin",
                "bytes": member,
                "provenance": [
                    provenance(
                        "case-a",
                        72,
                        "archive_member",
                        archive_node=71,
                        utf8_name="member.bin",
                    )
                ],
            },
        ],
    )

    result = compare_recovery_artifacts(
        run_record(output),
        {
            "schema_version": 1,
            "artifacts": [oracle_artifact(expected_parent, [("member.bin", member)])],
        },
    )

    assert result["accepted"] is False
    assert result["counts"]["matched_artifacts"] == 0
    assert result["counts"]["matched_members"] == 0
    assert (
        result["missing_artifacts"][0]["sha256"]
        == oracle_artifact(expected_parent)["sha256"]
    )


def test_origin_blob_must_match_artifact_bytes(tmp_path):
    data = b"exact artifact bytes"
    output = tmp_path / "output"
    origin = provenance("case-a", 8, "record_candidate")
    origin["node"]["blob"] = "sha256:" + "0" * 64
    write_export(
        output,
        artifact_rows=[{"file": "archive.zip", "bytes": data, "provenance": [origin]}],
    )

    result = compare_recovery_artifacts(
        run_record(output), {"schema_version": 1, "artifacts": [oracle_artifact(data)]}
    )

    assert result["accepted"] is True
    assert result["artifact_matches"][0]["origins"] == []
