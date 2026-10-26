use l2_workbench::evidence::{Case, EvidenceStatus, Node};
use serde_json::Value;
use std::{collections::BTreeSet, error::Error, io};

type TestResult<T> = Result<T, Box<dyn Error>>;

pub(super) fn assert_exact_raw_handoff(
    case: &Case,
    expected_bytes: &[u8],
    run_node_ids: &[u64],
) -> TestResult<()> {
    let expected_blob_id = format!("sha256:{}", l2_workbench::sha256(expected_bytes));
    let output = case
        .nodes()
        .iter()
        .find(|node| {
            node.kind == "relational_transform_output"
                && node.details.get("representation").and_then(Value::as_str) == Some("raw_bytes")
                && node_bytes(case, node) == Some(expected_bytes)
        })
        .ok_or_else(|| evidence_error("exact raw relational output is missing"))?;
    let report_node_id = required_u64(&output.details, "report_node_id")?;
    let candidate_index = usize::try_from(required_u64(&output.details, "candidate_index")?)
        .map_err(|source| evidence_error(format!("candidate index is out of range: {source}")))?;
    let report_node = required_node(case, report_node_id, "recovery_relational_transform_report")?;
    let report = json_blob(case, report_node)?;
    let source_id = required_string(&report_node.details, "source_id")?;

    assert_report_rule(&report, candidate_index)?;
    assert_aggregate_rejection_is_retained(&report, candidate_index)?;
    assert_relational_output_link(case, report_node_id, output.id)?;

    let frame_ids = required_u64_array(
        output.details.get("input_frame_node_ids"),
        "relational output frame ids",
    )?;
    assert_frame_identity(
        case,
        &frame_ids,
        run_node_ids,
        source_id,
        report_node_id,
        candidate_index,
        output,
    )?;

    let candidate_node_id = required_u64(&output.details, "input_record_candidate")?;
    let candidate = required_node(case, candidate_node_id, "record_candidate")?;
    let receipt_node_id = required_u64(&candidate.details, "receipt_node")?;
    let receipt = required_node(case, receipt_node_id, "record_parse_receipt")?;
    let receipt_json = json_blob(case, receipt)?;
    let schema = assert_parse_receipt(case, &receipt_json, &frame_ids)?;
    assert_schema_selected_from_discovery(
        case,
        receipt_node_id,
        source_id,
        &schema,
        &frame_ids,
        &report,
    )?;
    assert_candidate_and_validation(
        case,
        output,
        candidate,
        receipt_node_id,
        &frame_ids,
        &expected_blob_id,
        expected_bytes.len(),
    )?;

    Ok(())
}

fn assert_report_rule(report: &Value, candidate_index: usize) -> TestResult<()> {
    let rules = report
        .get("retained_rules")
        .and_then(Value::as_array)
        .ok_or_else(|| evidence_error("relational report omitted retained rules"))?;
    let rule = rules
        .get(candidate_index)
        .and_then(|entry| entry.get("rule"))
        .ok_or_else(|| evidence_error("relational output rule is not retained"))?;
    let seed_locator = rule
        .get("seed_locator")
        .ok_or_else(|| evidence_error("retained relational rule omitted its seed locator"))?;
    let declared_length = seed_locator
        .get("declared_length")
        .and_then(Value::as_object)
        .ok_or_else(|| evidence_error("retained seed locator omitted its declared length"))?;

    require(
        seed_locator.get("value_offset").and_then(Value::as_u64) == Some(1)
            && seed_locator.get("value_length").and_then(Value::as_u64) == Some(8)
            && declared_length.get("offset").and_then(Value::as_u64) == Some(0)
            && declared_length.get("width").and_then(Value::as_str) == Some("one_byte"),
        "relational candidate did not retain the fixture's declared-length seed locator",
    )
}

fn assert_aggregate_rejection_is_retained(
    report: &Value,
    candidate_index: usize,
) -> TestResult<()> {
    let candidate_index = u64::try_from(candidate_index)
        .map_err(|source| evidence_error(format!("candidate index is out of range: {source}")))?;
    let application_check = report
        .get("application_evidence_checks")
        .and_then(Value::as_array)
        .and_then(|checks| {
            checks.iter().find(|check| {
                check.get("candidate_index").and_then(Value::as_u64) == Some(candidate_index)
            })
        })
        .ok_or_else(|| evidence_error("relational application check is missing"))?;
    require(
        application_check.get("artifact_validated") == Some(&Value::Bool(false)),
        "pre-assembly aggregate status was changed by later record assembly",
    )?;

    let aggregate_rejected = report
        .get("aggregate_parser_checks")
        .and_then(Value::as_array)
        .is_some_and(|checks| {
            checks.iter().any(|check| {
                check.get("candidate_index").and_then(Value::as_u64) == Some(candidate_index)
                    && check.get("parser_scope").and_then(Value::as_str) == Some("across_sessions")
                    && check.get("accepted") == Some(&Value::Bool(false))
                    && check.get("status").and_then(Value::as_str) == Some("rejected")
            })
        });
    require(
        aggregate_rejected,
        "the original pre-assembly aggregate rejection was not preserved",
    )
}

fn assert_relational_output_link(
    case: &Case,
    report_node_id: u64,
    output_node_id: u64,
) -> TestResult<()> {
    require(
        case.edges().iter().any(|edge| {
            edge.from == report_node_id
                && edge.to == output_node_id
                && edge.relation == "supports_relational_output"
        }),
        "relational report is not linked to its validated raw output",
    )
}

fn assert_frame_identity(
    case: &Case,
    frame_ids: &[u64],
    run_node_ids: &[u64],
    source_id: &str,
    report_node_id: u64,
    candidate_index: usize,
    output: &Node,
) -> TestResult<()> {
    require(
        frame_ids.len() == run_node_ids.len() && frame_ids.len() == 4,
        "the raw output does not name all four decoded session frames",
    )?;
    let frame_id_set = frame_ids.iter().copied().collect::<BTreeSet<_>>();
    let expected_run_ids = run_node_ids.iter().copied().collect::<BTreeSet<_>>();
    require(
        frame_id_set.len() == frame_ids.len() && expected_run_ids.len() == run_node_ids.len(),
        "raw handoff contains duplicate frame or run ids",
    )?;

    let candidate_index = u64::try_from(candidate_index)
        .map_err(|source| evidence_error(format!("candidate index is out of range: {source}")))?;
    let mut session_ids = BTreeSet::new();
    let mut decoded_run_ids = BTreeSet::new();
    let mut session_orders = Vec::new();
    for frame_id in frame_ids {
        let frame = required_node(case, *frame_id, "relational_decoded_frame")?;
        require(
            frame
                .details
                .get("logical_source_id")
                .and_then(Value::as_str)
                == Some(source_id)
                && required_u64(&frame.details, "relational_report_node_id")? == report_node_id
                && required_u64(&frame.details, "relational_candidate_index")? == candidate_index
                && frame
                    .details
                    .get("relational_parser_format")
                    .and_then(Value::as_str)
                    == Some("Png"),
            "decoded frame source or relational candidate identity differs from its report",
        )?;
        let session_id = required_u64(&frame.details, "session_node_id")?;
        require(
            session_ids.insert(session_id),
            "decoded frames do not preserve distinct session ids",
        )?;
        session_orders.push(required_u64(&frame.details, "session_order")?);

        let frame_runs = case
            .edges()
            .iter()
            .filter(|edge| edge.from == *frame_id && edge.relation == "decoded_from")
            .map(|edge| edge.to)
            .filter(|run_id| expected_run_ids.contains(run_id))
            .collect::<BTreeSet<_>>();
        require(
            frame_runs.len() == 1,
            "decoded frame is not tied to exactly one fixture raw run",
        )?;
        let run_id = frame_runs
            .first()
            .copied()
            .ok_or_else(|| evidence_error("decoded frame has no fixture raw run"))?;
        assert_frame_run_ancestry(case, frame, run_id)?;
        decoded_run_ids.insert(run_id);
    }
    require(
        decoded_run_ids == expected_run_ids,
        "decoded frames do not cover the fixture's four raw runs",
    )?;
    require(
        required_u64_array(
            output.details.get("session_orders"),
            "relational output session orders",
        )? == session_orders,
        "relational output session ids do not match its decoded frames",
    )
}

fn assert_frame_run_ancestry(case: &Case, frame: &Node, run_id: u64) -> TestResult<()> {
    required_node(case, run_id, "tcp_byte_run")?;
    let direction_id = unique_observed_parent(case, run_id, "contains")?;
    let episode_id = unique_observed_parent(case, direction_id, "contains")?;
    required_node(case, direction_id, "tcp_direction")?;
    required_node(case, episode_id, "tcp_episode")?;
    require(
        required_u64(&frame.details, "input_frame_node_id")? == run_id
            && required_u64(&frame.details, "direction_node_id")? == direction_id
            && required_u64(&frame.details, "episode_node_id")? == episode_id
            && required_u64(&frame.details, "session_node_id")? == episode_id,
        "decoded frame direction, episode, or session differs from its own raw run ancestry",
    )
}

fn unique_observed_parent(case: &Case, child_id: u64, relation: &str) -> TestResult<u64> {
    let parents = case
        .edges()
        .iter()
        .filter(|edge| {
            edge.to == child_id
                && edge.relation == relation
                && edge.status == EvidenceStatus::Observed
        })
        .map(|edge| edge.from)
        .collect::<Vec<_>>();
    require(
        parents.len() == 1,
        "raw run does not have exactly one observed containment ancestor",
    )?;
    parents
        .first()
        .copied()
        .ok_or_else(|| evidence_error("raw run containment ancestor is missing"))
}

fn assert_parse_receipt(case: &Case, receipt: &Value, frame_ids: &[u64]) -> TestResult<Value> {
    let inputs = receipt
        .get("inputs")
        .and_then(Value::as_array)
        .ok_or_else(|| evidence_error("record parse receipt omitted its inputs"))?;
    require(
        inputs.len() == frame_ids.len(),
        "record parse receipt does not cover every decoded frame",
    )?;
    let mut selected_schema: Option<Value> = None;
    for (input, frame_id) in inputs.iter().zip(frame_ids) {
        require(
            input.get("input_node").and_then(Value::as_u64) == Some(*frame_id),
            "record receipt input order differs from the assembled frame order",
        )?;
        let frame = required_node(case, *frame_id, "relational_decoded_frame")?;
        let frame_blob_id = frame
            .blob
            .as_deref()
            .ok_or_else(|| evidence_error("decoded frame has no retained blob identity"))?;
        let frame_blob = case
            .blob(frame_blob_id)
            .ok_or_else(|| evidence_error("decoded frame blob is unavailable"))?;
        let frame_sha256 = frame_blob_id
            .strip_prefix("sha256:")
            .ok_or_else(|| evidence_error("decoded frame blob id is not a SHA-256 identity"))?;
        require(
            input.get("input_length").and_then(Value::as_u64)
                == u64::try_from(frame_blob.bytes.len()).ok()
                && input.get("input_sha256").and_then(Value::as_str) == Some(frame_sha256)
                && frame.details.get("sha256").and_then(Value::as_str) == Some(frame_sha256),
            "record parse receipt does not bind the exact decoded frame bytes",
        )?;
        let schema = input
            .pointer("/parse/schema")
            .cloned()
            .ok_or_else(|| evidence_error("record parse receipt omitted the strict schema"))?;
        if let Some(expected_schema) = &selected_schema {
            require(
                &schema == expected_schema,
                "record parse receipt applies different schemas to sibling frames",
            )?;
        } else {
            selected_schema = Some(schema);
        }
    }
    selected_schema.ok_or_else(|| evidence_error("record parse receipt has no selected schema"))
}

fn assert_schema_selected_from_discovery(
    case: &Case,
    receipt_node_id: u64,
    source_id: &str,
    schema: &Value,
    frame_ids: &[u64],
    relational_report: &Value,
) -> TestResult<()> {
    let selected_reports = case
        .edges()
        .iter()
        .filter(|edge| edge.to == receipt_node_id && edge.relation == "record_schema_selected_from")
        .filter_map(|edge| case.node(edge.from))
        .filter(|node| node.kind == "recovery_record_discovery_report")
        .collect::<Vec<_>>();
    require(
        !selected_reports.is_empty(),
        "record parse receipt has no discovery report selection edge",
    )?;
    for report_node in selected_reports {
        require(
            report_node.details.get("source_id").and_then(Value::as_str) == Some(source_id),
            "record schema discovery report belongs to a different source",
        )?;
        let report = json_blob(case, report_node)?;
        if !contains_survivor_schema(&report, schema) {
            continue;
        }
        assert_discovery_report_inputs(case, &report, frame_ids, relational_report)?;
        return Ok(());
    }
    Err(evidence_error(
        "selected record schema is not among its discovery report survivors",
    ))
}

fn assert_discovery_report_inputs(
    case: &Case,
    report: &Value,
    frame_ids: &[u64],
    relational_report: &Value,
) -> TestResult<()> {
    let discovery_sessions = required_u64_set(
        relational_report.get("discovery_sessions"),
        "relational discovery sessions",
    )?;
    let heldout_sessions = required_u64_set(
        relational_report.get("heldout_sessions"),
        "relational held-out sessions",
    )?;
    require(
        discovery_sessions.is_disjoint(&heldout_sessions),
        "relational discovery and held-out sessions overlap",
    )?;

    let partition = report
        .get("partition")
        .ok_or_else(|| evidence_error("record discovery report omitted its session partition"))?;
    let training_sessions = required_u64_set(
        partition.get("training_session_nodes"),
        "record discovery training sessions",
    )?;
    let report_heldout_sessions = required_u64_set(
        partition.get("held_out_session_nodes"),
        "record discovery held-out sessions",
    )?;
    require(
        training_sessions == discovery_sessions && report_heldout_sessions == heldout_sessions,
        "record discovery partition differs from the frozen relational session split",
    )?;

    let mut frame_sessions = BTreeSet::new();
    let mut expected_refs = Vec::new();
    for frame_id in frame_ids {
        let frame = required_node(case, *frame_id, "relational_decoded_frame")?;
        let session_id = required_u64(&frame.details, "session_node_id")?;
        frame_sessions.insert(session_id);
        let partition_name = if discovery_sessions.contains(&session_id) {
            "training"
        } else if heldout_sessions.contains(&session_id) {
            "held_out"
        } else {
            return Err(evidence_error(
                "decoded frame session is absent from the relational session split",
            ));
        };
        expected_refs.push(serde_json::json!([frame_id, partition_name]));
    }
    let all_relational_sessions = discovery_sessions
        .union(&heldout_sessions)
        .copied()
        .collect::<BTreeSet<_>>();
    let input_refs = report
        .get("input_frame_refs")
        .and_then(Value::as_array)
        .ok_or_else(|| evidence_error("record discovery report omitted its frame references"))?;
    require(
        frame_sessions == all_relational_sessions && input_refs == &expected_refs,
        "record discovery report inputs differ from the parsed frames or session split",
    )
}

fn required_u64_set(value: Option<&Value>, label: &str) -> TestResult<BTreeSet<u64>> {
    let ids = required_u64_array(value, label)?;
    let set = ids.iter().copied().collect::<BTreeSet<_>>();
    require(
        set.len() == ids.len(),
        "session partition contains duplicate ids",
    )?;
    Ok(set)
}

fn assert_candidate_and_validation(
    case: &Case,
    output: &Node,
    candidate: &Node,
    receipt_node_id: u64,
    frame_ids: &[u64],
    expected_blob_id: &str,
    expected_length: usize,
) -> TestResult<()> {
    assert_candidate_contains_exact_artifact(
        case,
        candidate,
        receipt_node_id,
        expected_blob_id,
        expected_length,
    )?;
    assert_candidate_preserves_frame_ancestry(case, output, candidate, frame_ids)?;
    assert_candidate_has_exact_validation(case, output, candidate, expected_length)
}

fn assert_candidate_contains_exact_artifact(
    case: &Case,
    candidate: &Node,
    receipt_node_id: u64,
    expected_blob_id: &str,
    expected_length: usize,
) -> TestResult<()> {
    require(
        candidate.blob.as_deref() == Some(expected_blob_id)
            && node_bytes(case, candidate).is_some_and(|bytes| bytes.len() == expected_length)
            && candidate
                .details
                .get("output_sha256")
                .and_then(Value::as_str)
                == expected_blob_id.strip_prefix("sha256:")
            && candidate
                .details
                .get("output_length")
                .and_then(Value::as_u64)
                == u64::try_from(expected_length).ok(),
        "record assembly candidate does not contain the exact expected artifact bytes",
    )?;
    require(
        candidate
            .details
            .get("receipt_node")
            .and_then(Value::as_u64)
            == Some(receipt_node_id)
            && candidate.details.get("group_complete") == Some(&Value::Bool(false))
            && candidate
                .details
                .get("terminal_sequence")
                .is_some_and(Value::is_null),
        "record assembly lost its receipt or claimed an unknown terminal sequence",
    )
}

fn assert_candidate_preserves_frame_ancestry(
    case: &Case,
    output: &Node,
    candidate: &Node,
    frame_ids: &[u64],
) -> TestResult<()> {
    let candidate_frame_ids = case
        .edges()
        .iter()
        .filter(|edge| edge.to == candidate.id && edge.relation == "candidate_from")
        .map(|edge| edge.from)
        .filter(|node_id| {
            case.node(*node_id)
                .is_some_and(|node| node.kind == "relational_decoded_frame")
        })
        .collect::<BTreeSet<_>>();
    require(
        candidate_frame_ids == frame_ids.iter().copied().collect()
            && case.edges().iter().any(|edge| {
                edge.from == output.id
                    && edge.to == candidate.id
                    && edge.relation == "validated_record_assembly"
                    && edge.status == EvidenceStatus::Observed
            }),
        "record candidate does not preserve the exact decoded frame ancestry",
    )
}

fn assert_candidate_has_exact_validation(
    case: &Case,
    output: &Node,
    candidate: &Node,
    expected_length: usize,
) -> TestResult<()> {
    let validation = case
        .nodes()
        .iter()
        .find(|node| {
            node.kind == "artifact_validation_receipt"
                && node.details.get("input_node").and_then(Value::as_u64) == Some(candidate.id)
                && node.details.get("status").and_then(Value::as_str) == Some("validated")
                && node.details.get("format").and_then(Value::as_str) == Some("png")
                && node.details.get("boundary").and_then(Value::as_str) == Some("png_iend")
                && node
                    .details
                    .pointer("/range/offset")
                    .and_then(Value::as_u64)
                    == Some(0)
                && node
                    .details
                    .pointer("/range/length")
                    .and_then(Value::as_u64)
                    == u64::try_from(expected_length).ok()
        })
        .ok_or_else(|| evidence_error("record candidate lacks exact whole-range PNG validation"))?;
    require(
        case.edges().iter().any(|edge| {
            edge.from == candidate.id
                && edge.to == validation.id
                && edge.relation == "validated_range"
                && edge.status == EvidenceStatus::Observed
        }),
        "whole-range validation is not linked to the assembled record candidate",
    )?;
    require(
        output
            .details
            .get("terminal_sequence")
            .and_then(Value::as_str)
            == Some("unknown"),
        "relational output did not preserve the unknown terminal sequence",
    )
}

fn contains_survivor_schema(value: &Value, schema: &Value) -> bool {
    [
        "/schema_discovery/surviving",
        "/repeated_boundary_analysis/discovery/surviving",
    ]
    .iter()
    .filter_map(|path| value.pointer(path).and_then(Value::as_array))
    .any(|survivors| {
        survivors
            .iter()
            .any(|candidate| candidate.get("schema") == Some(schema))
    })
}

fn json_blob(case: &Case, node: &Node) -> TestResult<Value> {
    let blob_id = node
        .blob
        .as_deref()
        .ok_or_else(|| evidence_error("evidence node has no JSON blob"))?;
    let blob = case
        .blob(blob_id)
        .ok_or_else(|| evidence_error("evidence JSON blob is unavailable"))?;
    serde_json::from_slice(&blob.bytes).map_err(Into::into)
}

fn node_bytes<'case>(case: &'case Case, node: &Node) -> Option<&'case [u8]> {
    node.blob
        .as_deref()
        .and_then(|blob_id| case.blob(blob_id))
        .map(|blob| blob.bytes.as_slice())
}

fn required_node<'case>(case: &'case Case, node_id: u64, kind: &str) -> TestResult<&'case Node> {
    case.node(node_id)
        .filter(|node| node.kind == kind)
        .ok_or_else(|| evidence_error(format!("evidence node {node_id} is not a {kind}")))
}

fn required_u64(value: &Value, key: &str) -> TestResult<u64> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| evidence_error(format!("evidence field {key} is missing or invalid")))
}

fn required_string<'value>(value: &'value Value, key: &str) -> TestResult<&'value str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| evidence_error(format!("evidence field {key} is missing or invalid")))
}

fn required_u64_array(value: Option<&Value>, label: &str) -> TestResult<Vec<u64>> {
    value
        .and_then(Value::as_array)
        .ok_or_else(|| evidence_error(format!("{label} are missing")))?
        .iter()
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| evidence_error(format!("{label} contain an invalid id")))
        })
        .collect()
}

fn require(condition: bool, message: &str) -> TestResult<()> {
    if condition {
        Ok(())
    } else {
        Err(evidence_error(message))
    }
}

fn evidence_error(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::other(message.into()))
}
