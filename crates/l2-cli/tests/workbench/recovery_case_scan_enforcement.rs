use super::*;
use l2_workbench::{
    evidence::{ByteMapping, Case, Edge, EvidenceStatus, SourceRange},
    protocol::{FramingKind, ProtocolLimits, RecordSchemaProposalLimits},
};
use serde_json::json;
use std::error::Error;

type TestResult<T> = Result<T, Box<dyn Error>>;

#[test]
fn a_scan_one_unit_below_its_safe_bound_is_rejected_before_enumeration() -> TestResult<()> {
    let mut visited = 0_usize;

    let admission = preflight_scan(17, 16, || {
        visited += 1;
        Ok(((), 17))
    })?;

    assert!(matches!(
        admission,
        ScanAdmission::Exhausted { requested: 17 }
    ));
    assert_eq!(visited, 0);
    Ok(())
}

#[test]
fn a_scan_at_its_safe_bound_is_admitted_and_reports_actual_work() -> TestResult<()> {
    let mut visited = 0_usize;

    let admission = preflight_scan(17, 17, || {
        visited += 1;
        Ok(("scan result", 17))
    })?;

    assert_eq!(visited, 1);
    assert!(matches!(
        admission,
        ScanAdmission::Scanned {
            value: "scan result",
            work: 17
        }
    ));
    Ok(())
}

#[test]
fn a_scan_charges_measured_work_when_it_uses_less_than_its_reservation() -> TestResult<()> {
    let admission = preflight_scan(17, 17, || Ok(((), 11)))?;

    assert!(matches!(admission, ScanAdmission::Scanned { work: 11, .. }));
    Ok(())
}

#[test]
fn a_scan_that_exceeds_its_preflight_bound_is_an_invalid_policy() {
    let result = preflight_scan(17, 17, || Ok(((), 18)));

    assert!(matches!(
        result,
        Err(RecoveryExecutionError::InvalidPolicy(_))
    ));
}

#[test]
fn scan_bound_arithmetic_overflow_is_an_invalid_policy() {
    let shape = CaseScanShape {
        nodes: usize::MAX,
        edges: 0,
        blobs: 0,
        sources: 0,
        details_bytes: 0,
        blob_bytes: 0,
        source_ranges: 0,
    };

    assert!(matches!(
        shape.framing_bound(),
        Err(RecoveryExecutionError::InvalidPolicy(_))
    ));
}

#[test]
fn case_scan_bounds_use_constant_time_case_usage_and_cover_their_formula() -> TestResult<()> {
    let mut case = Case::new();
    let blob_id = case.add_blob(b"record bytes")?;
    let first = case.add_node(
        "custom_protocol_frame",
        Some(&blob_id),
        Vec::new(),
        json!({"padding":"x"}),
    )?;
    case.add_edge(Edge {
        from: first,
        to: first,
        relation: "derived_from".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "retained provenance".to_owned(),
    })?;

    let shape = CaseScanShape::from_case(&case);
    let bounds = case_scan_work_bounds(&case)?;
    let usage = case.resource_usage();
    let framed_expected = 2 * usage.details_bytes
        + case.nodes().len() * (64 + std::mem::size_of::<u64>())
        + usage.source_ranges * (CONTENT_ID_BYTES + 4 * std::mem::size_of::<u64>())
        + case.edges().len()
            * (l2_workbench::evidence::MAX_RELATION_BYTES
                + l2_workbench::evidence::MAX_REASON_BYTES
                + 3 * std::mem::size_of::<u64>())
        + case.blobs().len() * (CONTENT_ID_BYTES + std::mem::size_of::<usize>());
    let record_expected = 2 * usage.details_bytes
        + case.nodes().len() * (64 + CONTENT_ID_BYTES + std::mem::size_of::<u64>())
        + usage.source_ranges * (64 + 2 * CONTENT_ID_BYTES)
        + case.blobs().len() * CONTENT_ID_BYTES
        + usage.blob_bytes
        + case.sources().len() * CONTENT_ID_BYTES
        + case.edges().len()
            * (l2_workbench::evidence::MAX_RELATION_BYTES
                + l2_workbench::evidence::MAX_REASON_BYTES
                + 17);

    assert_eq!(bounds.framing, shape.framing_bound()?);
    assert_eq!(bounds.record, shape.record_bound()?);
    assert_eq!(bounds.framing, framed_expected);
    assert_eq!(bounds.record, record_expected);
    Ok(())
}

#[test]
fn safe_bounds_cover_the_actual_framing_and_record_case_scan_work() -> TestResult<()> {
    let mut case = Case::new();
    let blob_id = case.add_blob(b"scan bound evidence")?;
    let node = case.add_node(
        "custom_protocol_frame",
        Some(&blob_id),
        Vec::new(),
        json!({"padding":"evidence details"}),
    )?;
    case.add_edge(Edge {
        from: node,
        to: node,
        relation: "derived_from".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "retained provenance".to_owned(),
    })?;

    let bounds = case_scan_work_bounds(&case)?;
    let framing = super::super::framing_discovery::collect_plan(&case, ProtocolLimits::default())?;
    let record =
        super::super::record_discovery::collect_plan(&case, RecordSchemaProposalLimits::default())?;

    assert!(bounds.framing >= super::super::framing_discovery::scan_work(&framing));
    assert!(bounds.record >= super::super::record_discovery::scan_work(&record));
    Ok(())
}

#[test]
fn retained_case_index_charges_initial_and_appended_entries_once() -> TestResult<()> {
    let mut case = Case::new();
    case.add_bytes_node("imported_source", b"root bytes", Vec::new(), json!({}))?;
    let initial_bound = case_index_scan_bound(&case)?;
    let mut index = super::super::CaseIndex::new(&case)?;
    let initial_charge = index.scan_ledger.charged();
    assert!(initial_charge > 0);
    assert!(initial_charge <= initial_bound);

    index.refresh(&case)?;
    assert_eq!(index.scan_ledger.charged(), initial_charge);

    let appended_kind = "unrelated_evidence";
    case.add_node(appended_kind, None, Vec::new(), json!({}))?;
    let suffix_bound = case_index_suffix_scan_bound(1, 1, 0, &case)?;
    index.refresh(&case)?;
    let appended_charge = index
        .scan_ledger
        .charged()
        .checked_sub(initial_charge)
        .ok_or("index charge must be monotonic")?;
    assert_eq!(
        appended_charge,
        std::mem::size_of::<u64>() + std::mem::size_of::<usize>() + appended_kind.len()
    );
    assert!(appended_charge <= suffix_bound);

    let charged = index.scan_ledger.charged();
    index.refresh(&case)?;
    assert_eq!(index.scan_ledger.charged(), charged);
    Ok(())
}

#[test]
fn retained_case_index_charges_contextual_view_key_bytes_within_both_bounds() -> TestResult<()> {
    let mut case = Case::new();
    let input_node = case.add_bytes_node("source", b"input", Vec::new(), json!({}))?;
    let output_node = case.add_bytes_node("decoding_output", b"output", Vec::new(), json!({}))?;
    let receipt_node = case.add_node("transform_receipt", None, Vec::new(), json!({}))?;
    let other_receipt_node = case.add_node("transform_receipt", None, Vec::new(), json!({}))?;
    let output_blob_id = case
        .nodes()
        .iter()
        .find(|node| node.id == output_node)
        .and_then(|node| node.blob.clone())
        .ok_or("output node must retain its blob")?;
    let first_view = case.add_bytes_node(
        "decoding_output",
        b"output",
        Vec::new(),
        json!({
            "shared_transform_receipt":receipt_node,
            "source_input_node":input_node
        }),
    )?;
    let first_key = (output_blob_id.clone(), receipt_node, input_node);
    let initial_bound = case_index_scan_bound(&case)?;
    let mut index = super::super::CaseIndex::new(&case)?;
    assert_eq!(
        index.contextual_decoding_views.get(&first_key),
        Some(&first_view)
    );
    assert!(index.scan_ledger.charged() <= initial_bound);

    let second_view = case.add_bytes_node(
        "decoding_output",
        b"output",
        Vec::new(),
        json!({
            "shared_transform_receipt":other_receipt_node,
            "source_input_node":input_node
        }),
    )?;
    let suffix_bound = case_index_suffix_scan_bound(
        case.nodes().len() - 1,
        case.blobs().len(),
        case.edges().len(),
        &case,
    )?;
    let previous_charge = index.scan_ledger.charged();
    index.refresh(&case)?;
    let appended_charge = index
        .scan_ledger
        .charged()
        .checked_sub(previous_charge)
        .ok_or("contextual-view index charge must be monotonic")?;
    let expected_charge = std::mem::size_of::<u64>()
        + std::mem::size_of::<usize>()
        + "decoding_output".len()
        + output_blob_id.len()
        + output_blob_id.len()
        + 2 * std::mem::size_of::<u64>();

    assert_eq!(appended_charge, expected_charge);
    assert!(appended_charge <= suffix_bound);
    assert_eq!(
        index
            .contextual_decoding_views
            .get(&(output_blob_id, other_receipt_node, input_node)),
        Some(&second_view)
    );
    Ok(())
}

#[test]
fn retained_case_index_charges_validated_range_reverse_entries_within_all_bounds() -> TestResult<()>
{
    let mut case = Case::new();
    let first_input = case.add_bytes_node("source", b"first input", Vec::new(), json!({}))?;
    let second_input = case.add_bytes_node("source", b"second input", Vec::new(), json!({}))?;
    let validation = case.add_node("artifact_validation", None, Vec::new(), json!({}))?;
    let previous_nodes = case.nodes().len();
    let previous_blobs = case.blobs().len();
    let previous_edges = case.edges().len();
    let empty_edge_bound = case_index_scan_bound(&case)?;
    let mut index = super::super::CaseIndex::new(&case)?;
    let previous_charge = index.scan_ledger.charged();

    for exact_input in [second_input, first_input] {
        case.add_edge(Edge {
            from: exact_input,
            to: validation,
            relation: "validated_range".to_owned(),
            status: EvidenceStatus::Observed,
            reason: "exact bytes passed structural validation".to_owned(),
        })?;
    }

    let per_edge_bound = MAX_RELATION_BYTES
        + MAX_REASON_BYTES
        + 17
        + MAX_NODE_KIND_BYTES
        + INDEX_VALIDATED_RANGE_KEY_VALUE_BYTES;
    let expected_suffix_bound = 2 * per_edge_bound;
    let initial_bound = case_index_scan_bound(&case)?;
    let suffix_bound =
        case_index_suffix_scan_bound(previous_nodes, previous_blobs, previous_edges, &case)?;
    assert_eq!(initial_bound - empty_edge_bound, expected_suffix_bound);
    assert_eq!(suffix_bound, expected_suffix_bound);

    index.refresh(&case)?;
    let appended_charge = index
        .scan_ledger
        .charged()
        .checked_sub(previous_charge)
        .ok_or("validated-range index charge must be monotonic")?;
    let expected_appended_charge = 2
        * ("validated_range".len() + "exact bytes passed structural validation".len() + 17)
        + 3 * std::mem::size_of::<u64>();
    assert_eq!(appended_charge, expected_appended_charge);
    assert!(appended_charge <= suffix_bound);

    let indexed_inputs = index
        .validated_range_inputs(validation)
        .ok_or("validation receipt must have indexed exact inputs")?
        .iter()
        .copied()
        .collect::<Vec<_>>();
    assert_eq!(indexed_inputs, vec![first_input, second_input]);

    let fully_indexed = super::super::CaseIndex::new(&case)?;
    assert!(fully_indexed.scan_ledger.charged() <= case_index_scan_bound(&case)?);
    assert_eq!(
        fully_indexed.scan_ledger.maximum(),
        case_index_work_limit()?
    );

    let node_visit = MAX_NODE_KIND_BYTES
        + 2 * CONTENT_ID_BYTES
        + 3 * std::mem::size_of::<u64>()
        + std::mem::size_of::<usize>();
    let seed_visit = node_visit + MAX_NODE_KIND_BYTES + 2;
    let seed_sort = MAX_NODES * INDEX_RADIX_PASSES * 2 + INDEX_RADIX_PASSES * 256;
    let global_expected = MAX_NODES * (node_visit + seed_visit)
        + MAX_BLOBS * (CONTENT_ID_BYTES + std::mem::size_of::<usize>())
        + MAX_EDGES
            * (MAX_RELATION_BYTES
                + MAX_REASON_BYTES
                + 17
                + MAX_NODE_KIND_BYTES
                + INDEX_VALIDATED_RANGE_KEY_VALUE_BYTES)
        + seed_sort;
    assert_eq!(case_index_work_limit()?, global_expected);
    Ok(())
}

#[test]
fn an_unrelated_case_suffix_reuses_the_record_snapshot_and_charges_only_the_suffix()
-> TestResult<()> {
    let mut case = Case::new();
    case.add_blob(b"initial evidence")?;
    let initial_plan = std::sync::Arc::new(super::super::record_discovery::collect_plan(
        &case,
        RecordSchemaProposalLimits::default(),
    )?);
    let snapshot = RecordDiscoverySnapshot::new(&case, initial_plan);

    case.add_node("unrelated_evidence", None, Vec::new(), json!({}))?;
    let suffix_bound = snapshot.node_suffix_scan_bound(&case)?;
    let admission = preflight_scan(suffix_bound, suffix_bound, || {
        let inspection = snapshot.inspect_case_suffix(&case)?;
        Ok((inspection.0, inspection.1))
    })?;

    let ScanAdmission::Scanned { value, work } = admission else {
        return Err("exact suffix-scan boundary must admit the inspection".into());
    };
    assert!(value);
    assert_eq!(
        work,
        "unrelated_evidence".len() + std::mem::size_of::<u64>()
    );
    assert!(work < case_scan_work_bounds(&case)?.record);
    Ok(())
}

#[test]
fn a_new_materialized_frame_invalidates_the_record_snapshot() -> TestResult<()> {
    let mut case = Case::new();
    let initial_plan = std::sync::Arc::new(super::super::record_discovery::collect_plan(
        &case,
        RecordSchemaProposalLimits::default(),
    )?);
    let snapshot = RecordDiscoverySnapshot::new(&case, initial_plan);
    case.add_node("custom_protocol_frame", None, Vec::new(), json!({}))?;

    let (matches_case, work) = snapshot.inspect_case_suffix(&case)?;

    assert!(!matches_case);
    assert_eq!(
        work,
        "custom_protocol_frame".len() + std::mem::size_of::<u64>()
    );
    Ok(())
}

#[test]
fn a_late_materialization_edge_invalidates_an_existing_record_snapshot() -> TestResult<()> {
    let mut case = case_with_materialized_frame()?;
    let plan = std::sync::Arc::new(super::super::record_discovery::collect_plan(
        &case,
        RecordSchemaProposalLimits::default(),
    )?);
    assert!(super::super::record_discovery::plan_has_inputs(&plan));
    let snapshot = RecordDiscoverySnapshot::new(&case, plan);
    let frame_id = case
        .nodes()
        .iter()
        .find(|node| node.kind == "custom_protocol_frame")
        .ok_or("materialized frame is missing")?
        .id;
    let late_receipt = case.add_node(
        "custom_protocol_framing_receipt",
        None,
        Vec::new(),
        json!({"representation":"late receipt"}),
    )?;
    case.add_edge(Edge {
        from: late_receipt,
        to: frame_id,
        relation: "materialized".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "Late receipt changes frame eligibility".to_owned(),
    })?;

    let suffix_bound = snapshot.node_suffix_scan_bound(&case)?;
    let admission = preflight_scan(suffix_bound, suffix_bound, || {
        let inspection = snapshot.inspect_case_suffix(&case)?;
        Ok((inspection.0, inspection.1))
    })?;

    let ScanAdmission::Scanned { value, work } = admission else {
        return Err("exact edge-suffix boundary must admit inspection".into());
    };
    assert!(!value);
    assert_eq!(
        work,
        "custom_protocol_framing_receipt".len()
            + std::mem::size_of::<u64>()
            + "materialized".len()
            + "Late receipt changes frame eligibility".len()
            + 17
            + "custom_protocol_framing_receipt".len()
            + "custom_protocol_frame".len()
    );
    Ok(())
}

#[test]
fn normal_policy_record_snapshot_is_charged_once_when_execution_reuses_it() -> TestResult<()> {
    let mut case = Case::new();
    case.add_node("unrelated_evidence", None, Vec::new(), json!({}))?;
    let policy = super::super::normal_policy(&case)?;
    let expected_initial_scan = policy
        .record_discovery_snapshot
        .as_ref()
        .ok_or("normal policy must keep its record plan")?
        .scan_work();

    let outcome = super::super::execute(
        &mut case,
        &super::super::RecoveryPlan {
            discover_records: true,
            ..super::super::RecoveryPlan::default()
        },
        &policy,
    )?;

    assert_eq!(
        outcome.resources.record_phase_work_charged,
        expected_initial_scan,
    );
    Ok(())
}

#[test]
fn framing_scan_at_exact_manual_policy_bound_is_admitted() -> TestResult<()> {
    let mut case = Case::new();
    for _ in 0..16 {
        case.add_node("unrelated_evidence", None, Vec::new(), json!({}))?;
    }
    let mut policy = super::super::normal_policy(&case)?;
    let bound = case_scan_work_bounds(&case)?.framing;
    let actual_work = super::super::framing_discovery::scan_work(
        &super::super::framing_discovery::collect_plan(&case, ProtocolLimits::default())?,
    );
    policy.framing_discovery_plan = None;
    policy.record_discovery_snapshot = None;
    policy.resources.max_work_bytes = bound;

    let outcome = super::super::execute(
        &mut case,
        &super::super::RecoveryPlan {
            discover_framing: true,
            ..super::super::RecoveryPlan::default()
        },
        &policy,
    )?;

    assert_eq!(outcome.resources.work_charged_bytes, actual_work);
    assert!(actual_work <= bound);
    assert!(!outcome.omissions.iter().any(|omission| matches!(
        omission,
        super::super::RecoveryOmission::ResourceExhausted {
            task: super::super::RecoveryTask::FramingDiscovery,
            resource: l2_workbench::recovery::RecoveryResource::WorkBytes,
            ..
        }
    )));
    Ok(())
}

#[test]
fn framing_scan_one_below_manual_policy_bound_is_omitted_before_collection() -> TestResult<()> {
    let mut case = Case::new();
    for _ in 0..16 {
        case.add_node("unrelated_evidence", None, Vec::new(), json!({}))?;
    }
    let mut policy = super::super::normal_policy(&case)?;
    let bound = case_scan_work_bounds(&case)?.framing;
    policy.framing_discovery_plan = None;
    policy.record_discovery_snapshot = None;
    policy.resources.max_work_bytes = bound.checked_sub(1).ok_or("bound must be positive")?;

    let outcome = super::super::execute(
        &mut case,
        &super::super::RecoveryPlan {
            discover_framing: true,
            ..super::super::RecoveryPlan::default()
        },
        &policy,
    )?;

    assert_eq!(outcome.resources.work_charged_bytes, 0);
    assert!(outcome.omissions.iter().any(|omission| matches!(
        omission,
        super::super::RecoveryOmission::ResourceExhausted {
            task: super::super::RecoveryTask::FramingDiscovery,
            resource: l2_workbench::recovery::RecoveryResource::WorkBytes,
            used: 0,
            requested,
            ..
        } if *requested == bound
    )));
    Ok(())
}

fn case_with_materialized_frame() -> TestResult<Case> {
    let mut case = Case::new();
    let bytes = b"abcd";
    let blob_id = case.add_blob(bytes)?;
    let source_id = case.add_source(
        "capture.pcap",
        "capture",
        u64::try_from(bytes.len())?,
        &l2_workbench::sha256(bytes),
        Some(&blob_id),
    )?;
    let direction = add_tcp_direction(&mut case)?;
    let run = add_tcp_byte_run(&mut case, bytes, source_id, direction)?;
    super::super::super::framing_materialize::apply_with_basis(
        &mut case,
        run,
        &FramingKind::FixedSize { bytes: 4 },
        super::super::super::framing_materialize::FramingSelectionBasis::CallerSupplied {},
    )?;
    Ok(case)
}

fn add_tcp_direction(case: &mut Case) -> TestResult<u64> {
    let episode = case.add_node(
        "tcp_episode",
        None,
        Vec::new(),
        json!({
            "scope":{"interface":"test","link_type":1},
            "endpoints":[
                {"address":"endpoint-a","port":1000},
                {"address":"endpoint-b","port":2000}
            ],
            "first_packet":1,
            "generation_ambiguous":false
        }),
    )?;
    let direction = case.add_node(
        "tcp_direction",
        None,
        Vec::new(),
        json!({
            "source":{"address":"endpoint-a","port":1000},
            "destination":{"address":"endpoint-b","port":2000},
            "start_known":true,
            "end_observed":true,
            "sequence_ambiguous":false,
            "coverage":{
                "length":4,
                "observed":4,
                "missing":0,
                "conflicting":0,
                "omitted":0,
                "omitted_observations":0
            }
        }),
    )?;
    case.add_edge(Edge {
        from: episode,
        to: direction,
        relation: "contains".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "test direction".to_owned(),
    })?;
    Ok(direction)
}

fn add_tcp_byte_run(
    case: &mut Case,
    bytes: &[u8],
    source_id: String,
    direction: u64,
) -> TestResult<u64> {
    let run = case.add_mapped_bytes_node(
        "tcp_byte_run",
        bytes,
        &[ByteMapping {
            offset: 0,
            range: SourceRange {
                source: source_id,
                packet: Some(1),
                offset: 0,
                length: u64::try_from(bytes.len())?,
            },
        }],
        json!({
            "offset":0,
            "length":4,
            "start_known":true,
            "end_observed":true,
            "generation_ambiguous":false
        }),
    )?;
    case.add_edge(Edge {
        from: direction,
        to: run,
        relation: "contains".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "test byte run".to_owned(),
    })?;
    Ok(run)
}

fn case_with_invalidated_record_snapshot() -> TestResult<(
    Case,
    super::super::RecoveryExecutionPolicy,
    usize,
    usize,
    usize,
    usize,
)> {
    let mut case = Case::new();
    let policy = super::super::normal_policy(&case)?;
    let initial_scan_work = policy
        .record_discovery_snapshot
        .as_ref()
        .ok_or("normal policy must retain its initial record snapshot")?
        .scan_work();
    for _ in 0..128 {
        case.add_node("unrelated_evidence", None, Vec::new(), json!({}))?;
    }
    case.add_node("custom_protocol_frame", None, Vec::new(), json!({}))?;

    let suffix_scan_work = case
        .nodes()
        .iter()
        .map(|node| node.kind.len() + std::mem::size_of::<u64>())
        .sum::<usize>();
    let case_scan_bound = case_scan_work_bounds(&case)?.record;
    let plan =
        super::super::record_discovery::collect_plan(&case, RecordSchemaProposalLimits::default())?;
    let actual_scan_work = super::super::record_discovery::scan_work(&plan);
    assert!(actual_scan_work <= case_scan_bound);

    Ok((
        case,
        policy,
        initial_scan_work,
        suffix_scan_work,
        case_scan_bound,
        actual_scan_work,
    ))
}

#[test]
fn record_case_scan_succeeds_at_the_exact_remaining_safe_bound() -> TestResult<()> {
    let (mut case, mut policy, initial_work, suffix_work, scan_bound, actual_scan_work) =
        case_with_invalidated_record_snapshot()?;
    let limit = initial_work
        .checked_add(suffix_work)
        .and_then(|work| work.checked_add(scan_bound))
        .ok_or("record scan boundary overflowed")?;
    policy.resources.max_work_bytes = limit;
    policy.record_phase_work_limit = limit;

    let outcome = super::super::execute(
        &mut case,
        &super::super::RecoveryPlan {
            discover_records: true,
            ..super::super::RecoveryPlan::default()
        },
        &policy,
    )?;

    assert_eq!(
        outcome.resources.record_phase_work_charged,
        initial_work + suffix_work + actual_scan_work,
    );
    assert!(!outcome.omissions.iter().any(|omission| matches!(
        omission,
        super::super::RecoveryOmission::ResourceExhausted {
            task: super::super::RecoveryTask::RecordDiscovery,
            resource: l2_workbench::recovery::RecoveryResource::WorkBytes,
            ..
        }
    )));
    Ok(())
}

#[test]
fn record_case_scan_one_unit_below_its_safe_bound_is_omitted_before_full_scan() -> TestResult<()> {
    let (mut case, mut policy, initial_work, suffix_work, scan_bound, _) =
        case_with_invalidated_record_snapshot()?;
    let limit = initial_work
        .checked_add(suffix_work)
        .and_then(|work| work.checked_add(scan_bound))
        .and_then(|work| work.checked_sub(1))
        .ok_or("record scan one-below boundary underflowed")?;
    policy.resources.max_work_bytes = limit;
    policy.record_phase_work_limit = limit;

    let outcome = super::super::execute(
        &mut case,
        &super::super::RecoveryPlan {
            discover_records: true,
            ..super::super::RecoveryPlan::default()
        },
        &policy,
    )?;

    assert_eq!(
        outcome.resources.record_phase_work_charged,
        initial_work + suffix_work
    );
    assert!(outcome.omissions.iter().any(|omission| matches!(
        omission,
        super::super::RecoveryOmission::ResourceExhausted {
            task: super::super::RecoveryTask::RecordDiscovery,
            resource: l2_workbench::recovery::RecoveryResource::WorkBytes,
            used,
            requested,
            ..
        } if *used == initial_work + suffix_work && *requested == scan_bound
    )));
    Ok(())
}
