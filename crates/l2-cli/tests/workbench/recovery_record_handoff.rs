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
    assert_application_gate_matches_assembly(
        case,
        &report,
        candidate_index,
        &schema,
        &frame_ids,
        &expected_blob_id,
        expected_bytes.len(),
    )?;
    assert_schema_selected_from_gate(case, receipt_node_id, report_node_id)?;
    assert_gate_input_partition(case, &report, &frame_ids)?;
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
    // Joining raw sessions is a different claim from assembling their records
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

fn assert_application_gate_matches_assembly(
    case: &Case,
    report: &Value,
    candidate_index: usize,
    schema: &Value,
    frame_ids: &[u64],
    expected_blob_id: &str,
    expected_length: usize,
) -> TestResult<()> {
    let candidate_index = u64::try_from(candidate_index)
        .map_err(|source| evidence_error(format!("candidate index is out of range: {source}")))?;
    let check = report
        .get("application_evidence_checks")
        .and_then(Value::as_array)
        .and_then(|checks| {
            checks.iter().find(|check| {
                check.get("candidate_index").and_then(Value::as_u64) == Some(candidate_index)
            })
        })
        .ok_or_else(|| evidence_error("relational application check is missing"))?;
    require(
        check.get("artifact_validated") == Some(&Value::Bool(true))
            && check.get("status").and_then(Value::as_str) == Some("artifact_validated"),
        "record gate did not independently validate the assembled artifact",
    )?;
    let accepted = check
        .get("accepted_record_schema")
        .ok_or_else(|| evidence_error("record gate omitted its accepted schema"))?;
    require(
        accepted.get("schema") == Some(schema)
            && accepted.get("artifact_format").and_then(Value::as_str) == Some("Png")
            && accepted
                .pointer("/artifact_receipt/output_sha256")
                .and_then(Value::as_str)
                == expected_blob_id.strip_prefix("sha256:")
            && accepted
                .pointer("/artifact_receipt/output_length")
                .and_then(Value::as_u64)
                == u64::try_from(expected_length).ok()
            && accepted.pointer("/artifact_receipt/complete") == Some(&Value::Bool(false)),
        "assembly differs from the exact schema and artifact accepted by the record gate",
    )?;

    // Materialized frame nodes keep the identities frozen before publication
    let identities = accepted
        .get("frame_identities")
        .and_then(Value::as_array)
        .ok_or_else(|| evidence_error("record gate omitted its decoded frame identities"))?;
    require(
        identities.len() == frame_ids.len(),
        "record gate and assembly name different numbers of decoded frames",
    )?;
    for (index, (identity, frame_id)) in identities.iter().zip(frame_ids).enumerate() {
        let frame = required_node(case, *frame_id, "relational_decoded_frame")?;
        require(
            identity.get("frame_index").and_then(Value::as_u64) == u64::try_from(index).ok(),
            "record gate frame ordering differs from assembly",
        )?;
        for (identity_field, frame_field) in [
            ("input_node_id", "input_frame_node_id"),
            ("session_order", "session_order"),
            ("stream_offset", "stream_offset"),
            ("frame_byte_length", "length"),
            ("frame_bytes_sha256", "sha256"),
        ] {
            require(
                identity.get(identity_field) == frame.details.get(frame_field),
                "assembly changed a decoded frame identity accepted by the record gate",
            )?;
        }
        assert_gate_message_context(case, identity, frame)?;
    }
    Ok(())
}

fn assert_gate_message_context(case: &Case, identity: &Value, frame: &Node) -> TestResult<()> {
    let episode = required_node(
        case,
        required_u64(&frame.details, "episode_node_id")?,
        "tcp_episode",
    )?;
    let direction = required_node(
        case,
        required_u64(&frame.details, "direction_node_id")?,
        "tcp_direction",
    )?;
    let scope = identity
        .pointer("/context/scope")
        .and_then(Value::as_str)
        .ok_or_else(|| evidence_error("record gate omitted its source scope"))?;
    let scope: Value = serde_json::from_str(scope)?;
    require(
        identity.pointer("/context/source") == frame.details.get("logical_source_id")
            && identity.pointer("/context/session") == frame.details.get("session_node_id")
            && episode.details.get("scope") == Some(&scope),
        "assembly changed the source, session, or scope accepted by the record gate",
    )?;
    // This fixture sends every raw run from the first endpoint to the second
    require(
        identity
            .pointer("/context/direction")
            .and_then(Value::as_str)
            == Some("first_to_second")
            && direction.details.get("source") == episode.details.pointer("/endpoints/0")
            && direction.details.get("destination") == episode.details.pointer("/endpoints/1"),
        "assembly changed the direction accepted by the record gate",
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

fn assert_schema_selected_from_gate(
    case: &Case,
    receipt_node_id: u64,
    report_node_id: u64,
) -> TestResult<()> {
    let selected_report_ids = case
        .edges()
        .iter()
        .filter(|edge| edge.to == receipt_node_id && edge.relation == "record_schema_selected_from")
        .map(|edge| edge.from)
        .collect::<BTreeSet<_>>();
    // The accepted gate already froze the schema, so assembly must use that receipt
    require(
        selected_report_ids == BTreeSet::from([report_node_id]),
        "record parse receipt does not select its exact accepted relational schema report",
    )
}

fn assert_gate_input_partition(case: &Case, report: &Value, frame_ids: &[u64]) -> TestResult<()> {
    let discovery_sessions = required_u64_set(
        report.get("discovery_sessions"),
        "relational discovery sessions",
    )?;
    let heldout_sessions = required_u64_set(
        report.get("heldout_sessions"),
        "relational held-out sessions",
    )?;
    require(
        !discovery_sessions.is_empty()
            && !heldout_sessions.is_empty()
            && discovery_sessions.is_disjoint(&heldout_sessions),
        "relational discovery and held-out sessions are empty or overlap",
    )?;

    let mut frame_sessions = BTreeSet::new();
    let mut original_input_ids = BTreeSet::new();
    for frame_id in frame_ids {
        let frame = required_node(case, *frame_id, "relational_decoded_frame")?;
        let session_id = required_u64(&frame.details, "session_node_id")?;
        frame_sessions.insert(session_id);
        original_input_ids.insert(required_u64(&frame.details, "input_frame_node_id")?);
    }
    let all_relational_sessions = discovery_sessions
        .union(&heldout_sessions)
        .copied()
        .collect::<BTreeSet<_>>();
    let report_input_ids = required_u64_set(
        report.get("input_sample_node_ids"),
        "relational gate input samples",
    )?;
    require(
        frame_sessions == all_relational_sessions && original_input_ids == report_input_ids,
        "assembly inputs differ from the frozen gate inputs or training and held-out sessions",
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
