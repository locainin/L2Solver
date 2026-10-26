use super::{
    ArtifactSourceContext, CaseArtifactIndex, CohortArtifactContextIndex, artifact_packet_summary,
    artifact_provenance, collect_cohort_artifacts, selected_artifact_source_ranges,
};
use crate::workbench::{
    artifact_export::{ArtifactProvenance, ReconstructionStatus, StructuralValidation},
    full_source::CohortAnalysis,
};
use l2_workbench::{
    evidence::{ByteMapping, Case, Edge, EvidenceStatus, SourceRange},
    investigation::BuildResult,
    store::Flow,
};
use serde_json::{Value, json};
use std::{collections::HashMap, error::Error};

#[test]
fn summary_prefers_exact_selected_packet_ranges() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    add_source(&mut case)?;
    let node_id =
        case.add_bytes_node("artifact", b"OBJ", vec![source_range(99, 0, 3)], json!({}))?;
    let provenance = export_provenance(
        case.node(node_id).cloned(),
        Some(json!({
            "source_ranges": [
                source_range(9, 301, 1),
                source_range(10, 400, 2)
            ]
        })),
    );

    assert_eq!(
        artifact_packet_summary(&provenance),
        ("Packets for exact selected bytes", String::from("9-10"))
    );
    Ok(())
}

#[test]
fn summary_falls_back_to_direct_node_packet_ranges() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    add_source(&mut case)?;
    let node_id =
        case.add_bytes_node("artifact", b"OBJ", vec![source_range(21, 0, 3)], json!({}))?;
    let provenance = export_provenance(case.node(node_id).cloned(), None);

    assert_eq!(
        artifact_packet_summary(&provenance),
        ("Packets", String::from("21"))
    );
    Ok(())
}

#[test]
fn retained_case_keeps_direct_ranges_with_its_node() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    add_source(&mut case)?;
    let range = source_range(22, 80, 3);
    let node_id = case.add_bytes_node("artifact", b"OBJ", vec![range.clone()], json!({}))?;
    let provenance = source_provenance(&case, node_id, Some("retained-case"), None)?;

    assert_eq!(
        provenance.node.as_ref().map(|node| node.ranges.as_slice()),
        Some([range].as_slice())
    );
    assert!(provenance.source_ranges.is_empty());
    Ok(())
}

#[test]
fn omitted_case_prefers_verified_selection_ranges_over_node_ranges() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    add_source(&mut case)?;
    let node_range = source_range(23, 100, 3);
    let selected_range = source_range(24, 200, 3);
    let node_id = case.add_bytes_node("artifact", b"OBJ", vec![node_range], json!({}))?;
    let provenance = source_provenance(
        &case,
        node_id,
        None,
        Some(json!({"source_ranges": [selected_range]})),
    )?;

    assert_eq!(
        provenance.source_ranges.as_slice(),
        std::slice::from_ref(&selected_range)
    );
    assert_eq!(
        provenance.canonical_origin.get("source_ranges"),
        Some(&json!([selected_range]))
    );
    assert!(provenance.case_id.is_none());
    assert!(provenance.selected_node_id.is_none());
    assert!(provenance.node.is_none());
    assert!(provenance.selection.is_none());
    Ok(())
}

#[test]
fn omitted_case_without_ranges_does_not_publish_case_local_identity() -> Result<(), Box<dyn Error>>
{
    let mut case = Case::new();
    add_source(&mut case)?;
    let node_id = case.add_bytes_node("artifact", b"OBJ", Vec::new(), json!({}))?;
    let provenance = source_provenance(&case, node_id, None, None)?;

    assert!(provenance.case_id.is_none());
    assert!(provenance.selected_node_id.is_none());
    assert!(provenance.node.is_none());
    assert!(provenance.source_ranges.is_empty());
    assert!(
        provenance
            .canonical_origin
            .get("local_case_identity")
            .is_none_or(Value::is_null)
    );
    assert!(
        provenance
            .canonical_origin
            .get("local_case_scope")
            .is_none_or(Value::is_null)
    );
    Ok(())
}

#[test]
fn selected_artifact_without_verified_ranges_does_not_infer_node_ranges()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    add_source(&mut case)?;
    let node_range = source_range(25, 300, 3);
    let node_id = case.add_bytes_node("artifact", b"OBJ", vec![node_range], json!({}))?;
    let provenance = source_provenance(
        &case,
        node_id,
        None,
        Some(json!({"transform": "nonlinear"})),
    )?;

    assert!(provenance.source_ranges.is_empty());
    assert!(
        provenance
            .canonical_origin
            .get("source_ranges")
            .is_none_or(Value::is_null)
    );
    Ok(())
}

fn export_provenance(
    node: Option<l2_workbench::evidence::Node>,
    selection: Option<serde_json::Value>,
) -> super::ArtifactProvenance {
    super::ArtifactProvenance {
        category: String::from("recovered_artifact"),
        case_id: Some(String::from("case")),
        selected_node_id: node.as_ref().map(|node| node.id),
        validation_node_id: None,
        extension_node_id: None,
        flow: None,
        supporting_flows: Vec::new(),
        cohort_scope: None,
        node,
        description: None,
        selection,
        signature_candidates: Vec::new(),
        source_ranges: Vec::new(),
        canonical_origin: json!({"fixture":"packet summary"}),
    }
}

fn source_provenance(
    case: &Case,
    node_id: u64,
    case_id: Option<&str>,
    selection: Option<Value>,
) -> Result<super::ArtifactProvenance, Box<dyn Error>> {
    let node = case
        .node(node_id)
        .cloned()
        .ok_or("artifact node is missing")?;
    let nodes_by_id = case
        .nodes()
        .iter()
        .map(|node| (node.id, node))
        .collect::<HashMap<_, _>>();
    let context = ArtifactSourceContext {
        flow: None,
        supporting_flows: Vec::new(),
        cohort_scope: None,
        case_id: case_id.map(str::to_owned),
        case_scope: json!({"kind": "flow"}),
    };

    artifact_provenance(
        "recovered_artifact",
        &context,
        Some(node),
        None,
        selection,
        Vec::new(),
        &nodes_by_id,
    )
}

#[test]
fn full_identity_range_keeps_all_direct_source_ranges() -> Result<(), Box<dyn Error>> {
    let bytes = b"complete object";
    let first = source_range(7, 100, u64::try_from(bytes.len())?);
    let mut case = Case::new();
    add_source(&mut case)?;
    let input = case.add_mapped_bytes_node(
        "mapped_input",
        bytes,
        &[ByteMapping {
            offset: 0,
            range: first.clone(),
        }],
        json!({}),
    )?;
    let selected = selected_origin(&mut case, input, bytes, 0, bytes.len())?;
    let index = CaseArtifactIndex::new(&case)?;

    assert_eq!(selected_artifact_source_ranges(&selected, &index)?, [first]);
    Ok(())
}

#[test]
fn single_identity_source_range_clips_a_validated_subobject() -> Result<(), Box<dyn Error>> {
    let input_bytes = b"prefixOBJtail";
    let object = b"OBJ";
    let range = source_range(8, 500, u64::try_from(input_bytes.len())?);
    let mut case = Case::new();
    add_source(&mut case)?;
    let input = case.add_mapped_bytes_node(
        "mapped_input",
        input_bytes,
        &[ByteMapping { offset: 0, range }],
        json!({}),
    )?;
    let selected = selected_origin(&mut case, input, object, 6, object.len())?;
    let index = CaseArtifactIndex::new(&case)?;

    assert_eq!(
        selected_artifact_source_ranges(&selected, &index)?,
        [source_range(8, 506, 3)]
    );
    Ok(())
}

#[test]
fn checked_mapping_receipt_clips_across_source_ranges() -> Result<(), Box<dyn Error>> {
    let input_bytes = b"ABCD";
    let mut case = Case::new();
    add_source(&mut case)?;
    let input = case.add_mapped_bytes_node(
        "mapped_input",
        input_bytes,
        &[
            ByteMapping {
                offset: 0,
                range: source_range(9, 300, 2),
            },
            ByteMapping {
                offset: 2,
                range: source_range(10, 400, 2),
            },
        ],
        json!({}),
    )?;
    let selected = selected_origin(&mut case, input, b"BCD", 1, 3)?;
    let index = CaseArtifactIndex::new(&case)?;

    assert_eq!(
        selected_artifact_source_ranges(&selected, &index)?,
        [source_range(9, 301, 1), source_range(10, 400, 2)]
    );
    Ok(())
}

#[test]
fn mapping_receipt_with_a_gap_has_no_exact_object_range() -> Result<(), Box<dyn Error>> {
    let input_bytes = b"ABCD";
    let mut case = Case::new();
    add_source(&mut case)?;
    let input = case.add_mapped_bytes_node(
        "mapped_input",
        input_bytes,
        &[
            ByteMapping {
                offset: 0,
                range: source_range(11, 500, 1),
            },
            ByteMapping {
                offset: 2,
                range: source_range(12, 600, 2),
            },
        ],
        json!({}),
    )?;
    let selected = selected_origin(&mut case, input, input_bytes, 0, input_bytes.len())?;
    let index = CaseArtifactIndex::new(&case)?;

    assert!(selected_artifact_source_ranges(&selected, &index)?.is_empty());
    Ok(())
}

#[test]
fn transformed_artifact_bytes_do_not_inherit_input_ranges() -> Result<(), Box<dyn Error>> {
    let input_bytes = b"ABCD";
    let mut case = Case::new();
    add_source(&mut case)?;
    let input = case.add_mapped_bytes_node(
        "mapped_input",
        input_bytes,
        &[ByteMapping {
            offset: 0,
            range: source_range(13, 700, 4),
        }],
        json!({}),
    )?;
    let selected = selected_origin(&mut case, input, b"WXYZ", 0, input_bytes.len())?;
    let index = CaseArtifactIndex::new(&case)?;

    assert!(selected_artifact_source_ranges(&selected, &index)?.is_empty());
    Ok(())
}

#[test]
fn only_observed_mapped_by_receipts_provide_subrange_provenance() -> Result<(), Box<dyn Error>> {
    for (relation, status, representation) in [
        (None, None, "json_blob"),
        (
            Some("derived_from"),
            Some(EvidenceStatus::Observed),
            "json_blob",
        ),
        (
            Some("mapped_by"),
            Some(EvidenceStatus::Unresolved),
            "json_blob",
        ),
        (Some("mapped_by"), Some(EvidenceStatus::Observed), "other"),
    ] {
        assert_forged_receipt_is_ignored(relation, status, representation)?;
    }
    Ok(())
}

#[test]
fn duplicate_observed_mapping_receipts_are_rejected_deterministically() -> Result<(), Box<dyn Error>>
{
    let mut case = Case::new();
    add_source(&mut case)?;
    let input = case.add_mapped_bytes_node(
        "mapped_input",
        b"ABCD",
        &[
            ByteMapping {
                offset: 0,
                range: source_range(16, 900, 2),
            },
            ByteMapping {
                offset: 2,
                range: source_range(17, 1_000, 2),
            },
        ],
        json!({}),
    )?;
    let receipt = case
        .nodes()
        .iter()
        .find(|node| node.kind == "byte_mapping_receipt")
        .ok_or("canonical byte mapping receipt is missing")?;
    let receipt_blob_id = receipt
        .blob
        .as_deref()
        .ok_or("canonical byte mapping receipt has no blob")?;
    let receipt_bytes = case
        .blobs()
        .iter()
        .find(|blob| blob.id == receipt_blob_id)
        .ok_or("canonical byte mapping receipt bytes are missing")?
        .bytes
        .clone();
    let receipt_details = receipt.details.clone();
    let duplicate = case.add_bytes_node(
        "byte_mapping_receipt",
        &receipt_bytes,
        Vec::new(),
        receipt_details,
    )?;
    case.add_edge(Edge {
        from: input,
        to: duplicate,
        relation: "mapped_by".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "duplicate test receipt".to_owned(),
    })?;

    let error = CaseArtifactIndex::new(&case)
        .err()
        .ok_or("duplicate mapped receipts must be rejected")?;
    assert_eq!(
        error.to_string(),
        "multiple byte mapping receipts reference one output node"
    );
    Ok(())
}

#[test]
fn cohort_artifact_lookup_is_built_once_for_multiple_artifacts() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut case = Case::new();
    add_source(&mut case)?;
    for (packet, bytes) in [(7, b"first".as_slice()), (8, b"second".as_slice())] {
        case.add_bytes_node(
            "ftp_data_candidate",
            bytes,
            vec![source_range(packet, 0, u64::try_from(bytes.len())?)],
            json!({}),
        )?;
    }
    let cohort = cohort_analysis(case, vec![flow(10), flow(20)], vec![(7, 10), (8, 20)]);
    let mut artifacts =
        super::ArtifactCollection::new(temporary.path(), super::ArtifactLimits::default())?;

    super::COHORT_ARTIFACT_LOOKUP_BUILDS.with(|builds| builds.set(0));
    collect_cohort_artifacts(
        &mut artifacts,
        &cohort,
        Some("cohort-case"),
        &json!({"kind": "cohort"}),
    )?;

    let builds = super::COHORT_ARTIFACT_LOOKUP_BUILDS.with(std::cell::Cell::get);
    assert_eq!(
        builds, 1,
        "one cohort index should serve every artifact context"
    );
    assert_eq!(artifacts.coverage().references_selected, 2);
    Ok(())
}

#[test]
fn cohort_artifact_context_falls_back_when_packet_witnesses_are_incomplete()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    add_source(&mut case)?;
    let incomplete_witness_node_id = case.add_bytes_node(
        "artifact",
        b"artifact",
        vec![source_range(7, 0, 8), source_range(99, 0, 8)],
        json!({}),
    )?;
    let no_witness_node_id =
        case.add_bytes_node("artifact", b"no packet witnesses", Vec::new(), json!({}))?;
    let cohort = cohort_analysis(case, vec![flow(10), flow(20)], vec![(7, 10)]);
    let incomplete_witness_node = cohort
        .result
        .case
        .node(incomplete_witness_node_id)
        .ok_or("artifact with an incomplete packet witness is missing")?;
    let no_witness_node = cohort
        .result
        .case
        .node(no_witness_node_id)
        .ok_or("artifact with no packet witnesses is missing")?;
    let nodes_by_id = cohort
        .result
        .case
        .nodes()
        .iter()
        .map(|node| (node.id, node))
        .collect();
    let context_index = CohortArtifactContextIndex::new(&cohort)?;

    let context = context_index.for_node(
        incomplete_witness_node,
        &nodes_by_id,
        Some("cohort-case"),
        &json!({"kind": "cohort"}),
    )?;

    assert!(context.flow.is_none());
    assert_eq!(context.supporting_flows.len(), 2);
    assert_eq!(supporting_flow_id(&context.supporting_flows, 0), Some(10));
    assert_eq!(supporting_flow_id(&context.supporting_flows, 1), Some(20));
    assert!(context.cohort_scope.is_some());

    let context = context_index.for_node(
        no_witness_node,
        &nodes_by_id,
        Some("cohort-case"),
        &json!({"kind": "cohort"}),
    )?;

    assert!(context.flow.is_none());
    assert_eq!(context.supporting_flows.len(), 2);
    assert_eq!(supporting_flow_id(&context.supporting_flows, 0), Some(10));
    assert_eq!(supporting_flow_id(&context.supporting_flows, 1), Some(20));
    assert!(context.cohort_scope.is_some());
    Ok(())
}

#[test]
fn cohort_artifact_context_uses_single_flow_context_for_one_supported_flow()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    add_source(&mut case)?;
    let node_id = case.add_bytes_node(
        "artifact",
        b"artifact",
        vec![source_range(7, 0, 8)],
        json!({}),
    )?;
    let cohort = cohort_analysis(case, vec![flow(10), flow(20)], vec![(7, 10)]);
    let node = cohort
        .result
        .case
        .node(node_id)
        .ok_or("artifact node is missing")?;
    let nodes_by_id = cohort
        .result
        .case
        .nodes()
        .iter()
        .map(|node| (node.id, node))
        .collect();

    let context = CohortArtifactContextIndex::new(&cohort)?.for_node(
        node,
        &nodes_by_id,
        Some("cohort-case"),
        &json!({"kind": "cohort"}),
    )?;

    assert_eq!(
        context
            .flow
            .as_ref()
            .and_then(|flow| flow.get("id").and_then(Value::as_i64)),
        Some(10)
    );
    assert_eq!(context.supporting_flows.len(), 1);
    assert_eq!(supporting_flow_id(&context.supporting_flows, 0), Some(10));
    assert!(context.cohort_scope.is_none());
    Ok(())
}

#[test]
fn cohort_context_follows_plural_frame_node_references() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    add_source(&mut case)?;
    let first_input = case.add_bytes_node(
        "relational_decoded_frame",
        b"first frame",
        vec![source_range(7, 0, 11)],
        json!({}),
    )?;
    let second_input = case.add_bytes_node(
        "relational_decoded_frame",
        b"second frame",
        vec![source_range(8, 0, 12)],
        json!({}),
    )?;
    let output_node = case.add_bytes_node(
        "relational_transform_output",
        b"relational output",
        Vec::new(),
        json!({"input_frame_node_ids": [first_input, second_input]}),
    )?;
    let cohort = cohort_analysis(
        case,
        vec![flow(10), flow(20), flow(30)],
        vec![(7, 10), (8, 20), (9, 30)],
    );
    let candidate_node = cohort
        .result
        .case
        .node(output_node)
        .cloned()
        .ok_or("relational output node is missing")?;
    let nodes_by_id = cohort
        .result
        .case
        .nodes()
        .iter()
        .map(|node| (node.id, node))
        .collect();
    let context_index = CohortArtifactContextIndex::new(&cohort)?;
    let context = context_index.for_node(
        &candidate_node,
        &nodes_by_id,
        Some("cohort-case"),
        &json!({"kind": "cohort"}),
    )?;

    assert!(context.flow.is_none());
    assert_eq!(
        context
            .supporting_flows
            .iter()
            .filter_map(|flow| flow.get("id").and_then(Value::as_i64))
            .collect::<Vec<_>>(),
        [10, 20]
    );
    assert!(context.cohort_scope.is_some());

    let provenance = artifact_provenance(
        "recovered_artifact",
        &context,
        Some(candidate_node),
        None,
        None,
        Vec::new(),
        &nodes_by_id,
    )?;
    let canonical_inputs = provenance
        .canonical_origin
        .pointer("/node/details/input_frame_node_ids")
        .and_then(Value::as_array)
        .ok_or("canonical plural input references are missing")?;
    assert_eq!(canonical_inputs.len(), 2);
    assert_eq!(
        canonical_inputs[0].get("kind"),
        Some(&json!("relational_decoded_frame"))
    );
    assert_eq!(
        canonical_inputs[0].pointer("/ranges/0/packet"),
        Some(&json!(7))
    );
    assert_eq!(
        canonical_inputs[1].pointer("/ranges/0/packet"),
        Some(&json!(8))
    );
    Ok(())
}

#[test]
fn cohort_context_skips_null_optional_multi_input_references() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    add_source(&mut case)?;
    let receipt = case.add_bytes_node(
        "record_parse_receipt",
        b"{}",
        Vec::new(),
        json!({"input_node": null, "input_count": 2}),
    )?;
    let candidate = case.add_bytes_node(
        "record_candidate",
        b"record candidate",
        Vec::new(),
        json!({"input_node": null, "input_count": 2, "receipt_node": receipt}),
    )?;

    let context = cohort_context_for_node(case, candidate, vec![(7, 10), (8, 20), (9, 30)])?;

    assert!(context.flow.is_none());
    assert_eq!(
        context
            .supporting_flows
            .iter()
            .filter_map(|flow| flow.get("id").and_then(Value::as_i64))
            .collect::<Vec<_>>(),
        [10, 20, 30]
    );
    assert!(context.cohort_scope.is_some());
    Ok(())
}

#[test]
fn cohort_context_rejects_malformed_non_null_node_references() -> Result<(), Box<dyn Error>> {
    assert_node_reference_error(
        "record_candidate",
        json!({"input_node": "not-an-id"}),
        "input_node",
        "string",
    )
}

#[test]
fn cohort_context_rejects_node_references_missing_from_the_case() -> Result<(), Box<dyn Error>> {
    assert_node_reference_error(
        "record_candidate",
        json!({"input_node": u64::MAX}),
        "input_node",
        "number",
    )
}

#[test]
fn cohort_context_rejects_malformed_plural_node_references() -> Result<(), Box<dyn Error>> {
    assert_node_reference_error(
        "relational_transform_output",
        json!({"input_frame_node_ids": ["not-an-id"]}),
        "input_frame_node_ids",
        "string",
    )
}

#[test]
fn cohort_context_rejects_non_array_plural_node_references() -> Result<(), Box<dyn Error>> {
    assert_node_reference_error(
        "relational_transform_output",
        json!({"input_frame_node_ids": "not-an-array"}),
        "input_frame_node_ids",
        "string",
    )
}

#[test]
fn cohort_context_rejects_plural_node_references_missing_from_the_case()
-> Result<(), Box<dyn Error>> {
    assert_node_reference_error(
        "relational_transform_output",
        json!({"input_frame_node_ids": [u64::MAX]}),
        "input_frame_node_ids",
        "number",
    )
}

fn assert_node_reference_error(
    node_kind: &str,
    details: Value,
    expected_key: &str,
    expected_type: &str,
) -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    add_source(&mut case)?;
    let output = case.add_bytes_node(node_kind, b"reference test", Vec::new(), details)?;

    let error = match cohort_context_for_node(case, output, Vec::new()) {
        Ok(_) => return Err("invalid node reference was accepted".into()),
        Err(error) => error,
    };

    assert!(error.to_string().contains(expected_key));
    assert!(error.to_string().contains(expected_type));
    Ok(())
}

fn cohort_analysis(
    case: Case,
    member_flows: Vec<Flow>,
    packet_flow_ids: Vec<(u32, i64)>,
) -> CohortAnalysis {
    CohortAnalysis {
        member_flows,
        packet_flow_ids,
        result: BuildResult {
            case,
            complete: true,
        },
        split: false,
    }
}

fn cohort_context_for_node(
    case: Case,
    node_id: u64,
    packet_flow_ids: Vec<(u32, i64)>,
) -> Result<super::ArtifactSourceContext, Box<dyn Error>> {
    let cohort = cohort_analysis(case, vec![flow(10), flow(20), flow(30)], packet_flow_ids);
    let node = cohort
        .result
        .case
        .node(node_id)
        .ok_or("artifact node is missing")?;
    let nodes_by_id = cohort
        .result
        .case
        .nodes()
        .iter()
        .map(|node| (node.id, node))
        .collect();
    let context_index = CohortArtifactContextIndex::new(&cohort)?;
    Ok(context_index.for_node(
        node,
        &nodes_by_id,
        Some("cohort-case"),
        &json!({"kind": "cohort"}),
    )?)
}

fn flow(id: i64) -> Flow {
    Flow {
        id,
        source_id: format!("source-{id}"),
        scope: Value::Null,
        protocol: 6,
        endpoint_a: std::net::Ipv4Addr::new(192, 0, 2, 1).into(),
        port_a: 10_000,
        endpoint_b: std::net::Ipv4Addr::new(198, 51, 100, 2).into(),
        port_b: 80,
        first_packet: 1,
        last_packet: 10,
        packets: 2,
        frame_bytes: 128,
        payload_bytes: 64,
    }
}

fn supporting_flow_id(supporting_flows: &[Value], index: usize) -> Option<i64> {
    supporting_flows
        .get(index)
        .and_then(|flow| flow.get("id"))
        .and_then(Value::as_i64)
}

fn assert_forged_receipt_is_ignored(
    relation: Option<&str>,
    status: Option<EvidenceStatus>,
    representation: &str,
) -> Result<(), Box<dyn Error>> {
    let input_bytes = b"abcdefgh";
    let first_range = source_range(14, 500, 4);
    let second_range = source_range(15, 800, 4);
    let mut case = Case::new();
    add_source(&mut case)?;
    let input = case.add_bytes_node(
        "unmapped_input",
        input_bytes,
        vec![first_range.clone(), second_range.clone()],
        json!({}),
    )?;
    let forged_mappings = [
        ByteMapping {
            offset: 0,
            range: first_range,
        },
        ByteMapping {
            offset: 4,
            range: second_range,
        },
    ];
    let receipt = case.add_bytes_node(
        "byte_mapping_receipt",
        &serde_json::to_vec(&forged_mappings)?,
        Vec::new(),
        json!({"output_node": input, "representation": representation}),
    )?;
    if let (Some(relation), Some(status)) = (relation, status) {
        case.add_edge(Edge {
            from: input,
            to: receipt,
            relation: relation.to_owned(),
            status,
            reason: "forged test receipt link".to_owned(),
        })?;
    }
    let selected = selected_origin(&mut case, input, b"cde", 2, 3)?;
    let index = CaseArtifactIndex::new(&case)?;

    assert!(selected_artifact_source_ranges(&selected, &index)?.is_empty());
    Ok(())
}

fn selected_origin(
    case: &mut Case,
    input_node: u64,
    artifact_bytes: &[u8],
    offset: usize,
    length: usize,
) -> Result<ArtifactProvenance, Box<dyn Error>> {
    let artifact_node = case.add_bytes_node("artifact", artifact_bytes, Vec::new(), json!({}))?;
    let validation_node = case.add_bytes_node(
        "structure",
        artifact_bytes,
        Vec::new(),
        json!({
            "input_node": input_node,
            "object_range": {"offset": offset, "length": length},
        }),
    )?;
    Ok(ArtifactProvenance {
        id: artifact_node,
        kind: "artifact".to_owned(),
        archive_path: None,
        completion_basis: None,
        reconstruction_status: ReconstructionStatus::Unknown,
        structural_validation: StructuralValidation::Validated {
            format: "structure",
            evidence_node: Some(validation_node),
        },
        extension_evidence_node: None,
    })
}

fn source_range(packet: u64, offset: u64, length: u64) -> SourceRange {
    SourceRange {
        source: format!("sha256:{}", "f".repeat(64)),
        packet: Some(packet),
        offset,
        length,
    }
}

fn add_source(case: &mut Case) -> Result<(), Box<dyn Error>> {
    case.add_source("mapped-input.pcap", "capture", 1_024, &"f".repeat(64), None)?;
    Ok(())
}
