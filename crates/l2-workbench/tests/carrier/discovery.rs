use l2_workbench::{
    carrier::{
        Ambiguity,
        discovery::{
            DiscoveryError, DiscoveryMapping, DiscoveryPlan, DiscoverySample, DiscoveryView,
            ResetMode, SampleOrder, discover, discover_case, discover_case_with_view,
            mapped_node_with_supporting_mappings,
        },
    },
    derivation::{BitRemainder, Constraint},
    evidence::{ByteMapping, Case, Edge, EvidenceStatus, SourceRange},
};
use serde_json::json;
use std::error::Error;

#[path = "discovery/results.rs"]
mod durable_results;

fn sample(
    id: u64,
    session_id: u64,
    sequence: u64,
    bytes: &[u8],
    mappings: Vec<DiscoveryMapping>,
) -> DiscoverySample<'_> {
    DiscoverySample {
        id,
        session_id,
        sequence,
        source_scope: "capture/interface-0/vlan-none".to_owned(),
        direction: "192.0.2.10:40000 -> 192.0.2.20:443".to_owned(),
        local_identity: "192.0.2.10:40000".to_owned(),
        bytes,
        mappings,
        ambiguity: Ambiguity::None,
    }
}

fn fixture_item<T>(items: &[T], index: usize) -> Result<&T, Box<dyn Error>> {
    items
        .get(index)
        .ok_or_else(|| std::io::Error::other("missing expected test fixture item").into())
}

fn mapping(offset: usize, source_offset: u64, length: u64) -> DiscoveryMapping {
    DiscoveryMapping {
        offset,
        range: SourceRange {
            source: format!("sha256:{}", "0".repeat(64)),
            packet: Some(1),
            offset: source_offset,
            length,
        },
    }
}

fn plan() -> DiscoveryPlan {
    DiscoveryPlan {
        widths: vec![1, 2],
        phases: vec![0, 1],
        start_offsets: vec![0],
        reset_modes: vec![
            ResetMode::PerSample,
            ResetMode::PerSession,
            ResetMode::Continuous,
        ],
        sample_orders: vec![SampleOrder::InputOrder, SampleOrder::SequenceAscending],
        remainder: BitRemainder::ZeroFill,
        max_input_bytes: 1024 * 1024,
        max_work_bytes: 16 * 1024 * 1024,
        max_candidates: 128,
        minimum_printable_run_bytes: 4,
        max_report_bytes: 1024 * 1024,
        constraints: vec![Constraint::Length { bytes: 1 }, Constraint::Utf8 {}],
    }
}

struct PacketPayloadFixture {
    case: Case,
    packet_ids: Vec<u64>,
    episode_id: u64,
    plan: DiscoveryPlan,
}

#[test]
fn discovery_enumerates_parameters_separate_controls() -> Result<(), Box<dyn Error>> {
    let bytes = [[0x80, 0x41], [0x01, 0x42], [0x03, 0x43]];
    let samples = [
        sample(1, 20, 2, &bytes[0], vec![mapping(0, 0, 2)]),
        sample(2, 20, 1, &bytes[1], vec![mapping(0, 2, 2)]),
        sample(3, 21, 3, &bytes[2], vec![mapping(0, 4, 2)]),
    ];

    let report = discover(&samples, &plan())?;

    assert_eq!(report.parameter_space_size, 24);
    assert_eq!(report.attempted_parameters, 24);
    assert_eq!(report.candidates.len(), 24);
    assert_eq!(
        report.work_bytes,
        report
            .candidates
            .iter()
            .map(|candidate| candidate.work_bytes)
            .sum::<usize>()
    );
    assert!(report.work_bytes <= report.work_budget_bytes);
    assert!(report.candidates.iter().all(|candidate| {
        candidate
            .discovery
            .as_ref()
            .is_some_and(|summary| summary.unit_count > 0)
            && candidate
                .control
                .as_ref()
                .is_some_and(|summary| summary.unit_count > 0)
    }));
    assert!(
        report
            .candidates
            .iter()
            .any(|candidate| candidate.competitor_count > 1)
    );
    assert!(
        report
            .limitations
            .iter()
            .any(|limitation| limitation.contains("do not establish"))
    );
    assert_eq!(report.sample_receipts.len(), 3);
    assert!(
        report
            .sample_receipts
            .iter()
            .all(|receipt| receipt.mappings.len() == 1)
    );
    Ok(())
}

#[test]
fn discovery_ambiguous_mixed_identity_samples() {
    let input = [0x80, 0x41, 0x01, 0x42];
    let mut sample = sample(1, 1, 1, &input, vec![mapping(0, 0, 2), mapping(3, 2, 1)]);
    assert!(matches!(
        discover(&[sample.clone()], &plan()),
        Err(DiscoveryError::InvalidMapping { sample_id: 1 })
    ));

    sample.mappings = vec![mapping(0, 0, 4)];
    sample.ambiguity = Ambiguity::MultipleCandidates;
    assert!(matches!(
        discover(&[sample.clone()], &plan()),
        Err(DiscoveryError::AmbiguousSample { sample_id: 1 })
    ));

    sample.ambiguity = Ambiguity::None;
    let mut other = sample.clone();
    other.id = 2;
    other.session_id = 2;
    other.direction = "192.0.2.30:40000 -> 192.0.2.20:443".to_owned();
    assert!(matches!(
        discover(&[sample, other], &plan()),
        Err(DiscoveryError::MixedIdentity)
    ));
}

#[test]
fn discovery_rejects_invalid_duplicate_hypotheses() {
    let bytes = [1_u8; 8];
    let samples = [sample(1, 1, 1, &bytes, vec![mapping(0, 0, 8)])];
    let mut invalid = plan();
    invalid.widths = vec![0];
    assert!(matches!(
        discover(&samples, &invalid),
        Err(DiscoveryError::InvalidPlan(_))
    ));

    invalid.widths = vec![1, 1];
    assert!(matches!(
        discover(&samples, &invalid),
        Err(DiscoveryError::InvalidPlan(_))
    ));
}

#[test]
fn discovery_uses_small_search_limits() -> Result<(), Box<dyn Error>> {
    let first_bytes = vec![0x10; 40_000];
    let second_bytes = vec![0x20; 40_000];
    let samples = [
        sample(1, 1, 1, &first_bytes, vec![mapping(0, 0, 40_000)]),
        sample(2, 2, 2, &second_bytes, vec![mapping(0, 40_000, 40_000)]),
    ];
    let plan = DiscoveryPlan {
        widths: vec![1],
        phases: vec![0],
        start_offsets: vec![0],
        reset_modes: vec![ResetMode::PerSample],
        sample_orders: vec![SampleOrder::InputOrder],
        remainder: BitRemainder::Reject,
        max_input_bytes: 80_000,
        max_work_bytes: 1_000_000,
        max_candidates: 1,
        minimum_printable_run_bytes: 4,
        max_report_bytes: 1024,
        constraints: Vec::new(),
    };

    let report = discover(&samples, &plan)?;

    assert_eq!(report.input_bytes, 80_000);
    assert_eq!(report.input_budget_bytes, 80_000);
    assert_eq!(report.attempted_parameters, 1);
    assert_eq!(report.work_budget_bytes, 1_000_000);
    assert!(report.enumeration_complete);
    Ok(())
}

#[test]
fn discovery_sample_uses_explicit_budget() -> Result<(), Box<dyn Error>> {
    let byte = [0x41];
    let samples = (1..=4097)
        .map(|id| sample(id, 1, id, &byte, vec![mapping(0, id - 1, 1)]))
        .collect::<Vec<_>>();
    let plan = DiscoveryPlan {
        widths: vec![8],
        phases: vec![0],
        start_offsets: vec![0],
        reset_modes: vec![ResetMode::PerSample],
        sample_orders: vec![SampleOrder::InputOrder],
        remainder: BitRemainder::Reject,
        max_input_bytes: 4097,
        max_work_bytes: 20_000,
        max_candidates: 1,
        minimum_printable_run_bytes: 4,
        max_report_bytes: 2 * 1024 * 1024,
        constraints: Vec::new(),
    };

    let report = discover(&samples, &plan)?;

    assert_eq!(report.input_bytes, 4097);
    assert_eq!(report.sample_receipts.len(), 4097);
    assert_eq!(report.attempted_transforms, 4097);
    Ok(())
}

#[test]
fn discovery_mapping_uses_input_budgets() -> Result<(), Box<dyn Error>> {
    let length = 131_080_usize;
    let bytes = vec![0x41; length];
    let mappings = (0..length)
        .map(|offset| u64::try_from(offset).map(|source_offset| mapping(offset, source_offset, 1)))
        .collect::<Result<Vec<_>, _>>()?;
    let samples = [sample(1, 1, 1, &bytes, mappings)];
    let plan = DiscoveryPlan {
        widths: vec![8],
        phases: vec![0],
        start_offsets: vec![0],
        reset_modes: vec![ResetMode::PerSample],
        sample_orders: vec![SampleOrder::InputOrder],
        remainder: BitRemainder::Reject,
        max_input_bytes: length,
        max_work_bytes: length * 3,
        max_candidates: 1,
        minimum_printable_run_bytes: usize::MAX,
        max_report_bytes: 64 * 1024 * 1024,
        constraints: Vec::new(),
    };

    let report = discover(&samples, &plan)?;

    assert_eq!(report.input_bytes, length);
    assert_eq!(
        fixture_item(&report.sample_receipts, 0)?.mappings.len(),
        length
    );
    let candidate = fixture_item(&report.candidates, 0)?;
    assert_eq!(
        candidate
            .discovery
            .as_ref()
            .ok_or("missing discovery summary")?
            .output_length,
        length / 8
    );
    Ok(())
}

#[test]
fn discovery_requires_complete_source_receipts() {
    let bytes = [0x41];
    let samples = [sample(1, 1, 1, &bytes, vec![mapping(0, 0, 1)])];
    let mut plan = plan();
    plan.max_candidates = 1;
    plan.max_report_bytes = 1;

    assert!(matches!(
        discover(&samples, &plan),
        Err(DiscoveryError::ReportBudgetExceeded { limit: 1 })
    ));
}

#[test]
fn discovery_printable_receipts_byte_offset() -> Result<(), Box<dyn Error>> {
    let text = b"Q5x!";
    let mut bytes = vec![0x80, 0xff];
    for byte in text {
        for shift in (0..7).rev() {
            bytes.push((byte >> shift) & 1);
        }
    }
    let samples = [sample(
        1,
        1,
        1,
        &bytes,
        vec![mapping(0, 100, u64::try_from(bytes.len())?)],
    )];
    let plan = DiscoveryPlan {
        widths: vec![7],
        phases: vec![7],
        start_offsets: vec![2],
        reset_modes: vec![ResetMode::PerSample],
        sample_orders: vec![SampleOrder::InputOrder],
        remainder: BitRemainder::Reject,
        max_input_bytes: 1024,
        max_work_bytes: 4096,
        max_candidates: 1,
        minimum_printable_run_bytes: 4,
        max_report_bytes: 4096,
        constraints: Vec::new(),
    };

    let report = discover(&samples, &plan)?;
    let candidate = fixture_item(&report.candidates, 0)?;
    let runs = &candidate
        .discovery
        .as_ref()
        .ok_or("missing discovery summary")?
        .printable_runs;
    let run = runs.first().ok_or("missing printable run")?;
    assert_eq!(run.text, "Q5x!");
    assert_eq!(run.candidate_id, 0);
    assert_eq!(run.output_offset, 0);
    assert_eq!(run.source_bit_mappings.len(), 1);
    let source_mapping = fixture_item(&run.source_bit_mappings, 0)?;
    assert_eq!(source_mapping.source.offset, 102);
    assert_eq!(source_mapping.source.length, 28);
    assert_eq!(source_mapping.source_bit_offset, 7);
    assert_eq!(source_mapping.output_bit_start, 0);
    assert_eq!(source_mapping.bit_count, 28);
    assert_eq!(candidate.bit_mapping.start_bit, 16);
    Ok(())
}

#[test]
fn printable_budget_escaping_large_identifiers() -> Result<(), Box<dyn Error>> {
    let text = b"A\"\\BC";
    let bytes: Vec<_> = text
        .iter()
        .flat_map(|byte| (0..7).rev().map(move |shift| (byte >> shift) & 1))
        .collect();
    let source_start = u64::MAX - u64::try_from(bytes.len())?;
    let sample = sample(
        u64::MAX,
        u64::MAX,
        u64::MAX,
        &bytes,
        vec![DiscoveryMapping {
            offset: 0,
            range: SourceRange {
                source: format!("sha256:{}", "f".repeat(64)),
                packet: Some(u64::MAX),
                offset: source_start,
                length: u64::try_from(bytes.len())?,
            },
        }],
    );
    let mut plan = DiscoveryPlan {
        widths: vec![7],
        phases: vec![7],
        start_offsets: vec![0],
        reset_modes: vec![ResetMode::PerSample],
        sample_orders: vec![SampleOrder::InputOrder],
        remainder: BitRemainder::Reject,
        max_input_bytes: 1024,
        max_work_bytes: 4096,
        max_candidates: 1,
        minimum_printable_run_bytes: text.len(),
        max_report_bytes: 16_384,
        constraints: Vec::new(),
    };

    let complete = discover(std::slice::from_ref(&sample), &plan)?;
    let candidate = fixture_item(&complete.candidates, 0)?;
    let run = candidate
        .discovery
        .as_ref()
        .and_then(|summary| summary.printable_runs.first())
        .ok_or("missing escaped printable run")?;
    assert_eq!(run.text, "A\"\\BC");
    let source_receipt_bytes = serde_json::to_vec(&complete.sample_receipts)?.len();
    let omitted_id_bytes = serde_json::to_vec(&complete.omitted_empty_sample_ids)?.len();
    let run_receipt_bytes = serde_json::to_vec(run)?.len();
    let exact_budget = source_receipt_bytes + omitted_id_bytes + run_receipt_bytes;
    assert_eq!(complete.report_bytes, exact_budget);

    plan.max_report_bytes = exact_budget - 1;
    let limited = discover(&[sample], &plan)?;
    let candidate = fixture_item(&limited.candidates, 0)?;
    let summary = candidate
        .discovery
        .as_ref()
        .ok_or("missing limited discovery summary")?;
    assert_eq!(summary.printable_runs.len(), 0);
    assert_eq!(summary.printable_runs_omitted, 1);
    assert!(!limited.printable_runs_complete);
    Ok(())
}

#[test]
fn discovery_input_selection_running_candidates() {
    let bytes = [0x10; 8];
    let samples = [sample(1, 1, 1, &bytes, vec![mapping(0, 0, 8)])];
    let mut plan = plan();
    plan.max_input_bytes = 7;
    assert!(matches!(
        discover(&samples, &plan),
        Err(DiscoveryError::InputBudgetExceeded {
            observed: 8,
            limit: 7
        })
    ));
}

#[test]
fn discovery_candidate_printable_budget_limits() -> Result<(), Box<dyn Error>> {
    let bytes: Vec<_> = b"ABCD"
        .iter()
        .flat_map(|byte| (0..7).rev().map(move |shift| (byte >> shift) & 1))
        .collect();
    let samples = [sample(1, 1, 1, &bytes, vec![mapping(0, 0, 28)])];
    let mut candidate_plan = plan();
    candidate_plan.widths = vec![1, 2];
    candidate_plan.phases = vec![0];
    candidate_plan.reset_modes = vec![ResetMode::PerSample];
    candidate_plan.sample_orders = vec![SampleOrder::InputOrder];
    candidate_plan.max_candidates = 1;
    let candidate_report = discover(&samples, &candidate_plan)?;
    assert_eq!(candidate_report.parameter_space_size, 2);
    assert_eq!(candidate_report.attempted_parameters, 1);
    assert!(!candidate_report.enumeration_complete);
    assert!(
        candidate_report
            .limits
            .contains(&l2_workbench::carrier::discovery::DiscoveryLimit::CandidateCount)
    );

    let mut run_plan = candidate_plan;
    run_plan.widths = vec![7];
    run_plan.phases = vec![7];
    run_plan.max_report_bytes = 700;
    run_plan.minimum_printable_run_bytes = 1;
    let run_report = discover(&samples, &run_plan)?;
    assert_eq!(run_report.attempted_printable_runs, 1);
    assert!(!run_report.printable_runs_complete);
    assert!(
        run_report
            .limits
            .contains(&l2_workbench::carrier::discovery::DiscoveryLimit::PrintableRunReportBytes)
    );
    let candidate = fixture_item(&run_report.candidates, 0)?;
    let summary = candidate
        .discovery
        .as_ref()
        .ok_or("missing discovery summary")?;
    assert_eq!(summary.printable_runs.len(), 0);
    assert_eq!(summary.printable_runs_omitted, 1);
    Ok(())
}

#[test]
fn large_derivation_session_streaming() -> Result<(), Box<dyn Error>> {
    let part = vec![0xff; 600_000];
    let sample_set = [
        sample(1, 1, 1, &part, vec![mapping(0, 0, 600_000)]),
        sample(2, 1, 2, &part, vec![mapping(0, 600_000, 600_000)]),
        sample(3, 1, 3, &part, vec![mapping(0, 1_200_000, 600_000)]),
        sample(4, 1, 4, &part, vec![mapping(0, 1_800_000, 600_000)]),
    ];
    let plan = DiscoveryPlan {
        widths: vec![7],
        phases: vec![0],
        start_offsets: vec![0],
        reset_modes: vec![ResetMode::PerSession],
        sample_orders: vec![SampleOrder::SequenceAscending],
        remainder: BitRemainder::ZeroFill,
        max_input_bytes: 2_400_000,
        max_work_bytes: 4_000_000,
        max_candidates: 1,
        minimum_printable_run_bytes: 4,
        max_report_bytes: 4096,
        constraints: Vec::new(),
    };

    let report = discover(&sample_set, &plan)?;

    assert_eq!(report.input_bytes, 2_400_000);
    let candidate = fixture_item(&report.candidates, 0)?;
    let discovery = candidate
        .discovery
        .as_ref()
        .ok_or("missing discovery summary")?;
    assert_eq!(discovery.unit_count, 1);
    assert_eq!(discovery.failed_units, 0);
    assert_eq!(discovery.lengths.output_minimum, Some(171_429));
    let control = candidate
        .control
        .as_ref()
        .ok_or("missing control summary")?;
    assert_eq!(control.unit_count, 1);
    assert_eq!(control.failed_units, 0);
    Ok(())
}

#[test]
fn case_discovery_exact_mapping_receipts() -> Result<(), Box<dyn Error>> {
    let (case, ids) = native_udp_payload_case()?;
    let report = discover_case(&case, &ids, &plan())?;

    assert_eq!(report.sample_receipts.len(), 2);
    assert_eq!(
        report.identity.direction,
        "udp 192.0.2.10:40000 -> udp 192.0.2.20:443"
    );
    assert_eq!(
        fixture_item(&report.sample_receipts, 0)?.local_identity,
        "udp 192.0.2.10:40000"
    );
    assert_eq!(
        report
            .sample_receipts
            .first()
            .map(|receipt| receipt.mappings.len()),
        Some(2)
    );
    assert_eq!(
        report
            .sample_receipts
            .first()
            .and_then(|receipt| receipt.mappings.first())
            .map(|mapping| mapping.offset),
        Some(0)
    );
    Ok(())
}

#[test]
fn tcp_byte_run_accepts_duplicate_edges_to_same_context_parent() -> Result<(), Box<dyn Error>> {
    let (mut case, run, episode, direction) = tcp_byte_run_case()?;
    case.add_edge(Edge {
        from: direction,
        to: run,
        relation: "contains".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "duplicate edge to the same TCP direction".to_owned(),
    })?;

    let report = discover_case(&case, &[run], &plan())?;
    let receipt = fixture_item(&report.sample_receipts, 0)?;

    assert_eq!(receipt.session_id, episode);
    assert_eq!(receipt.sequence, 0);
    assert_eq!(
        receipt.direction,
        "tcp 192.0.2.10:40000 -> tcp 192.0.2.20:443"
    );
    Ok(())
}

#[test]
fn case_discovery_accepts_duplicate_edges_to_same_mapping_receipt() -> Result<(), Box<dyn Error>> {
    let (mut case, run, _, _) = tcp_byte_run_case()?;
    let receipt_id = case
        .edges()
        .iter()
        .find(|edge| edge.from == run && edge.relation == "mapped_by")
        .map(|edge| edge.to)
        .ok_or("missing mapping receipt edge")?;
    case.add_edge(Edge {
        from: run,
        to: receipt_id,
        relation: "mapped_by".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "duplicate edge to the same mapping receipt".to_owned(),
    })?;

    let report = discover_case(&case, &[run], &plan())?;

    assert_eq!(report.sample_receipts.len(), 1);
    Ok(())
}

#[test]
fn case_discovery_rejects_distinct_mapping_receipts() -> Result<(), Box<dyn Error>> {
    let (mut case, run, _, _) = tcp_byte_run_case()?;
    let receipt_id = case
        .edges()
        .iter()
        .find(|edge| edge.from == run && edge.relation == "mapped_by")
        .map(|edge| edge.to)
        .ok_or("missing mapping receipt edge")?;
    let receipt_blob_id = case
        .nodes()
        .iter()
        .find(|node| node.id == receipt_id)
        .and_then(|node| node.blob.as_deref())
        .ok_or("mapping receipt has no blob")?;
    let receipt_bytes = case
        .blobs()
        .iter()
        .find(|blob| blob.id == receipt_blob_id)
        .map(|blob| blob.bytes.clone())
        .ok_or("mapping receipt blob is missing")?;
    let duplicate_blob_id = case.add_blob(&receipt_bytes)?;
    let other_receipt = case.add_node(
        "byte_mapping_receipt",
        Some(&duplicate_blob_id),
        Vec::new(),
        json!({}),
    )?;
    case.add_edge(Edge {
        from: run,
        to: other_receipt,
        relation: "mapped_by".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "distinct mapping receipt".to_owned(),
    })?;

    let error = discover_case(&case, &[run], &plan())
        .err()
        .ok_or("discovery accepted distinct mapping receipts")?;

    assert!(matches!(
        error,
        DiscoveryError::InvalidCaseMapping { node_id } if node_id == run
    ));
    Ok(())
}

#[test]
fn tcp_byte_run_rejects_multiple_direction_parents() -> Result<(), Box<dyn Error>> {
    let (mut case, run, _episode, _direction) = tcp_byte_run_case()?;
    let other_direction = case.add_node(
        "tcp_direction",
        None,
        Vec::new(),
        json!({
            "source": "192.0.2.11:40000",
            "destination": "192.0.2.20:443",
            "sequence_ambiguous": false,
        }),
    )?;
    case.add_edge(Edge {
        from: other_direction,
        to: run,
        relation: "contains".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "ambiguous direction parent".to_owned(),
    })?;

    let error = discover_case(&case, &[run], &plan())
        .err()
        .ok_or("discovery accepted multiple TCP direction parents")?;

    assert!(matches!(
        error,
        DiscoveryError::UnresolvedCaseContext { node_id } if node_id == run
    ));
    Ok(())
}

#[test]
fn tcp_byte_run_rejects_multiple_episode_parents() -> Result<(), Box<dyn Error>> {
    let (mut case, run, _episode, direction) = tcp_byte_run_case()?;
    let other_episode = case.add_node(
        "tcp_episode",
        None,
        Vec::new(),
        json!({"scope": {"section": 0, "interface": 0, "vlans": []}}),
    )?;
    case.add_edge(Edge {
        from: other_episode,
        to: direction,
        relation: "contains".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "ambiguous episode parent".to_owned(),
    })?;

    let error = discover_case(&case, &[run], &plan())
        .err()
        .ok_or("discovery accepted multiple TCP episode parents")?;

    assert!(matches!(
        error,
        DiscoveryError::UnresolvedCaseContext { node_id } if node_id == run
    ));
    Ok(())
}

fn tcp_byte_run_case() -> Result<(Case, u64, u64, u64), Box<dyn Error>> {
    let mut case = Case::new();
    let bytes = b"AB";
    let source = case.add_source(
        "tcp-byte-run.pcap",
        "capture",
        u64::try_from(bytes.len())?,
        &l2_workbench::sha256(bytes),
        None,
    )?;
    let run = case.add_mapped_bytes_node(
        "tcp_byte_run",
        bytes,
        &[
            ByteMapping {
                offset: 0,
                range: SourceRange {
                    source: source.clone(),
                    packet: Some(1),
                    offset: 0,
                    length: 1,
                },
            },
            ByteMapping {
                offset: 1,
                range: SourceRange {
                    source,
                    packet: Some(1),
                    offset: 1,
                    length: 1,
                },
            },
        ],
        json!({
            "offset": 0,
            "start_known": true,
            "generation_ambiguous": false,
        }),
    )?;
    let scope = json!({"section": 0, "interface": 0, "vlans": []});
    let episode = case.add_node("tcp_episode", None, Vec::new(), json!({"scope": scope}))?;
    let direction = case.add_node(
        "tcp_direction",
        None,
        Vec::new(),
        json!({
            "source": "192.0.2.10:40000",
            "destination": "192.0.2.20:443",
            "sequence_ambiguous": false,
        }),
    )?;
    for (from, to) in [(episode, direction), (direction, run)] {
        case.add_edge(Edge {
            from,
            to,
            relation: "contains".to_owned(),
            status: EvidenceStatus::Observed,
            reason: "TCP context parent".to_owned(),
        })?;
    }
    Ok((case, run, episode, direction))
}

#[test]
fn supporting_byte_mapping_ignores_unrelated_episode_and_parent_edges() -> Result<(), Box<dyn Error>>
{
    let (mut case, run, _, _) = tcp_byte_run_case()?;
    for _ in 0..128 {
        let episode = case.add_node("tcp_episode", None, Vec::new(), json!({}))?;
        case.add_edge(Edge {
            from: run,
            to: episode,
            relation: "supports".to_owned(),
            status: EvidenceStatus::Observed,
            reason: "generated unrelated context".to_owned(),
        })?;
    }
    let mapped = mapped_node_with_supporting_mappings(&case, run)?;
    assert_eq!(mapped.bytes, b"AB");
    assert_eq!(mapped.mappings.len(), 2);
    Ok(())
}

fn native_udp_payload_case() -> Result<(Case, Vec<u64>), Box<dyn Error>> {
    let mut case = Case::new();
    let source_bytes = b"abcd";
    let source_id = case.add_source(
        "capture.pcap",
        "capture",
        u64::try_from(source_bytes.len())?,
        &l2_workbench::sha256(source_bytes),
        None,
    )?;
    let scope = json!({"section": 0, "interface": 0, "vlans": []});
    let first = [0x80, 0x41];
    let first_mappings = [
        ByteMapping {
            offset: 0,
            range: SourceRange {
                source: source_id.clone(),
                packet: Some(1),
                offset: 0,
                length: 1,
            },
        },
        ByteMapping {
            offset: 1,
            range: SourceRange {
                source: source_id.clone(),
                packet: Some(2),
                offset: 3,
                length: 1,
            },
        },
    ];
    case.add_mapped_bytes_node(
        "udp_payload",
        &first,
        &first_mappings,
        json!({
            "scope": scope,
            "source": {"address": {"family": "ipv4", "octets": [192, 0, 2, 10]}, "port": 40000},
            "destination": {"address": {"family": "ipv4", "octets": [192, 0, 2, 20]}, "port": 443},
            "available_at_record": 2,
            "from_fragments": false,
            "identity_ambiguous": false,
        }),
    )?;
    let second = [0x01, 0x42];
    let second_mapping = [ByteMapping {
        offset: 0,
        range: SourceRange {
            source: source_id,
            packet: Some(3),
            offset: 1,
            length: 2,
        },
    }];
    case.add_mapped_bytes_node(
        "udp_payload",
        &second,
        &second_mapping,
        json!({
            "scope": scope,
            "source": {"address": {"family": "ipv4", "octets": [192, 0, 2, 10]}, "port": 40000},
            "destination": {"address": {"family": "ipv4", "octets": [192, 0, 2, 20]}, "port": 443},
            "available_at_record": 3,
            "from_fragments": false,
            "identity_ambiguous": false,
        }),
    )?;

    let ids: Vec<_> = case
        .nodes()
        .iter()
        .filter(|node| node.kind == "udp_payload")
        .map(|node| node.id)
        .collect();
    Ok((case, ids))
}

#[test]
fn packet_payload_ranges_episode_membership() -> Result<(), Box<dyn Error>> {
    let fixture = packet_payload_fixture()?;
    let report = discover_case_with_view(
        &fixture.case,
        &fixture.packet_ids,
        DiscoveryView::Payload,
        &fixture.plan,
    )?;

    assert_eq!(report.sample_receipts.len(), 4);
    assert_eq!(
        fixture_item(&report.sample_receipts, 0)?.session_id,
        fixture.episode_id
    );
    assert_eq!(
        fixture_item(&report.sample_receipts, 1)?.session_id,
        fixture.episode_id
    );
    let first_mapping = fixture_item(&fixture_item(&report.sample_receipts, 0)?.mappings, 0)?;
    assert_eq!(first_mapping.range.offset, 54);
    assert_eq!(first_mapping.range.length, 8);
    let candidate = fixture_item(&report.candidates, 0)?;
    assert_eq!(
        candidate
            .discovery
            .as_ref()
            .map(|summary| summary.unit_count),
        Some(1)
    );
    assert_eq!(
        candidate.control.as_ref().map(|summary| summary.unit_count),
        Some(1)
    );
    Ok(())
}

fn packet_payload_fixture() -> Result<PacketPayloadFixture, Box<dyn Error>> {
    let frames: Vec<_> = (0..4)
        .map(|index| tcp_frame_with_payload(&[0x80 | u8::try_from(index)?; 8]))
        .collect::<Result<_, Box<dyn Error>>>()?;
    let mut case = Case::new();
    let source_bytes: Vec<_> = frames
        .iter()
        .flat_map(|frame| frame.iter().copied())
        .collect();
    let source = case.add_source(
        "payload-view.pcap",
        "capture",
        u64::try_from(source_bytes.len())?,
        &l2_workbench::sha256(&source_bytes),
        None,
    )?;
    let mut ids = Vec::new();
    let mut source_offset = 0_u64;
    for (index, frame) in frames.iter().enumerate() {
        let record = u64::try_from(index + 1)?;
        let blob = case.add_blob(frame)?;
        let node = case.add_node(
            "packet",
            Some(&blob),
            vec![SourceRange {
                source: source.clone(),
                packet: Some(record),
                offset: source_offset,
                length: u64::try_from(frame.len())?,
            }],
            json!({
                "record": record,
                "link_type": 1,
                "scope": {"section": 0, "interface": 0, "vlans": []},
                "source_ip": "192.0.2.10",
                "destination_ip": "192.0.2.20",
                "truncated": false,
                "fragmented": false,
            }),
        )?;
        ids.push(node);
        source_offset = source_offset
            .checked_add(u64::try_from(frame.len())?)
            .ok_or("packet source offset overflow")?;
    }
    let episode = case.add_node(
        "tcp_episode",
        None,
        Vec::new(),
        json!({"scope": {"section": 0, "interface": 0, "vlans": []}}),
    )?;
    for node_id in &ids {
        case.add_edge(Edge {
            from: *node_id,
            to: episode,
            relation: "supports".to_owned(),
            status: EvidenceStatus::Hypothesis,
            reason: "packet is included in the same reconstructed TCP episode".to_owned(),
        })?;
    }
    let plan = DiscoveryPlan {
        widths: vec![1],
        phases: vec![0],
        start_offsets: vec![0],
        reset_modes: vec![ResetMode::PerSession],
        sample_orders: vec![SampleOrder::SequenceAscending],
        remainder: BitRemainder::Reject,
        max_input_bytes: 32,
        max_work_bytes: 1024,
        max_candidates: 1,
        minimum_printable_run_bytes: 4,
        max_report_bytes: 4096,
        constraints: Vec::new(),
    };

    Ok(PacketPayloadFixture {
        case,
        packet_ids: ids,
        episode_id: episode,
        plan,
    })
}

#[test]
fn explicit_service_ports_original_tuple() -> Result<(), Box<dyn Error>> {
    let (case, cohort, empty_payload_ids) = service_cohort_fixture()?;
    let report = discover_case_with_view(
        &case,
        &[cohort],
        DiscoveryView::Payload,
        &service_cohort_plan(),
    )?;

    assert_eq!(report.sample_receipts.len(), 2);
    assert_eq!(report.omitted_empty_sample_ids, empty_payload_ids);
    assert_eq!(report.identity.direction, "tcp to_endpoint 192.0.2.20:443");
    assert_eq!(report.identity.local_identity, "tcp 192.0.2.10");
    assert!(report.sample_receipts.iter().any(|receipt| {
        receipt.direction == "tcp 192.0.2.10:40001 -> tcp 192.0.2.20:443"
            && receipt.local_identity == "tcp 192.0.2.10:40001"
    }));
    assert!(report.sample_receipts.iter().any(|receipt| {
        receipt.direction == "tcp 192.0.2.10:40002 -> tcp 192.0.2.20:443"
            && receipt.local_identity == "tcp 192.0.2.10:40002"
    }));
    let first = fixture_item(&report.sample_receipts, 0)?;
    let second = fixture_item(&report.sample_receipts, 1)?;
    assert_ne!(first.session_id, second.session_id);
    Ok(())
}

fn service_cohort_fixture() -> Result<(Case, u64, Vec<u64>), Box<dyn Error>> {
    let frames = [
        tcp_frame_with_ports(&[], 40_001, 443)?,
        tcp_frame_with_ports(&[0x80; 8], 40_001, 443)?,
        tcp_frame_with_ports(&[], 40_002, 443)?,
        tcp_frame_with_ports(&[0x81; 8], 40_002, 443)?,
    ];
    let mut case = Case::new();
    let source_bytes: Vec<_> = frames
        .iter()
        .flat_map(|frame| frame.iter().copied())
        .collect();
    let source = case.add_source(
        "cohort.pcap",
        "capture",
        u64::try_from(source_bytes.len())?,
        &l2_workbench::sha256(&source_bytes),
        None,
    )?;
    let scope = json!({"section": 0, "interface": 0, "vlan_ids": [], "vlan_aux": null});
    let (series_ids, empty_payload_ids) =
        add_cohort_series_packets(&mut case, &source, &scope, &frames)?;
    let cohort = add_service_cohort(&mut case, &scope, &series_ids)?;
    Ok((case, cohort, empty_payload_ids))
}

fn add_service_cohort(
    case: &mut Case,
    scope: &serde_json::Value,
    series_ids: &[u64],
) -> Result<u64, Box<dyn Error>> {
    let cohort = case.add_node(
        "carrier_endpoint_cohort",
        None,
        Vec::new(),
        json!({
            "scope": scope,
            "endpoint": "192.0.2.20",
            "port": 443,
            "protocol": 6,
            "direction": "to_endpoint",
            "local_address": "192.0.2.10",
        }),
    )?;
    for series in series_ids {
        case.add_edge(Edge {
            from: cohort,
            to: *series,
            relation: "includes_connection".to_owned(),
            status: EvidenceStatus::Hypothesis,
            reason: "Connection shares the exact service cohort key".to_owned(),
        })?;
    }
    Ok(cohort)
}

fn service_cohort_plan() -> DiscoveryPlan {
    DiscoveryPlan {
        widths: vec![1],
        phases: vec![0],
        start_offsets: vec![0],
        reset_modes: vec![ResetMode::PerSession],
        sample_orders: vec![SampleOrder::SequenceAscending],
        remainder: BitRemainder::Reject,
        max_input_bytes: 16,
        max_work_bytes: 1024,
        max_candidates: 1,
        minimum_printable_run_bytes: 4,
        max_report_bytes: 16_384,
        constraints: Vec::new(),
    }
}

fn add_cohort_series_packets(
    case: &mut Case,
    source: &str,
    scope: &serde_json::Value,
    frames: &[Vec<u8>],
) -> Result<(Vec<u64>, Vec<u64>), Box<dyn Error>> {
    let mut series_ids = Vec::new();
    let mut empty_payload_ids = Vec::new();
    let mut source_offset = 0_u64;
    for (index, frame) in frames.iter().enumerate() {
        let packet_number = u64::try_from(index + 1)?;
        let packet = case.add_mapped_bytes_node(
            "packet",
            frame,
            &[ByteMapping {
                offset: 0,
                range: SourceRange {
                    source: source.to_owned(),
                    packet: Some(packet_number),
                    offset: source_offset,
                    length: u64::try_from(frame.len())?,
                },
            }],
            json!({
                "record": packet_number,
                "link_type": 1,
                "scope": scope,
                "source_ip": "192.0.2.10",
                "destination_ip": "192.0.2.20",
                "protocol": 6,
                "truncated": false,
                "fragmented": false,
            }),
        )?;
        if index.is_multiple_of(2) {
            empty_payload_ids.push(packet);
        }
        let episode = case.add_node("tcp_episode", None, Vec::new(), json!({"scope": scope}))?;
        case.add_edge(Edge {
            from: packet,
            to: episode,
            relation: "supports".to_owned(),
            status: EvidenceStatus::Hypothesis,
            reason: "Packet belongs to one candidate connection".to_owned(),
        })?;
        let series = case.add_node(
            "carrier_series",
            None,
            Vec::new(),
            json!({
                "scope": scope,
                "source": {"family": "ipv4", "octets": [192, 0, 2, 10]},
                "destination": {"family": "ipv4", "octets": [192, 0, 2, 20]},
                "ports": [40_001 + u16::try_from(index / 2)?, 443],
                "protocol": 6,
            }),
        )?;
        case.add_edge(Edge {
            from: packet,
            to: series,
            relation: "supports".to_owned(),
            status: EvidenceStatus::Observed,
            reason: "Packet contributes to this exact directional tuple".to_owned(),
        })?;
        series_ids.push(series);
        source_offset = source_offset
            .checked_add(u64::try_from(frame.len())?)
            .ok_or("source offset overflow")?;
    }
    Ok((series_ids, empty_payload_ids))
}

fn tcp_frame_with_payload(payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    tcp_frame_with_ports(payload, 40_000, 443)
}

fn tcp_frame_with_ports(
    payload: &[u8],
    source_port: u16,
    destination_port: u16,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let ip_length = 40_usize
        .checked_add(payload.len())
        .ok_or("IP length overflow")?;
    let mut frame = vec![2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 8, 0];
    frame.extend_from_slice(&[0x45, 0]);
    frame.extend_from_slice(&u16::try_from(ip_length)?.to_be_bytes());
    frame.extend_from_slice(&[0, 1, 0, 0, 64, 6, 0, 0]);
    frame.extend_from_slice(&[192, 0, 2, 10, 192, 0, 2, 20]);
    frame.extend_from_slice(&source_port.to_be_bytes());
    frame.extend_from_slice(&destination_port.to_be_bytes());
    frame.extend_from_slice(&1_u32.to_be_bytes());
    frame.extend_from_slice(&0_u32.to_be_bytes());
    frame.extend_from_slice(&[0x50, 0x18, 0x20, 0, 0, 0, 0, 0]);
    frame.extend_from_slice(payload);
    Ok(frame)
}
