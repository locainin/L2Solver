use super::{FLOW_PAGE_SIZE, acquire_full_source};
use crate::workbench::expand::{ExpansionLimits, ExpansionService};
use l2_workbench::evidence::{Case, EvidenceStatus};
use l2_workbench::reconstruction::Limits;
use std::{error::Error, fs};

#[test]
fn late_png_is_recovered() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture_path = temporary.path().join("late-http.pcap");
    let filler_frame_count =
        Limits::default().bytes / usize::try_from(l2_pcap::MAX_FRAME_LENGTH)? + 1;
    let body = tiny_png()?;
    let capture = capture_with_late_http(filler_frame_count, &body)?;
    fs::write(&capture_path, &capture)?;
    assert!(capture.len() > Limits::default().bytes);

    let mut late_png_recognized = false;
    let coverage = acquire_full_source(&capture_path, Limits::default(), |analysis| {
        assert!(analysis.flow.first_packet > u32::try_from(filler_frame_count)?);
        let Some(body_node) = find_http_body(&analysis.result.case, &body)? else {
            return Ok(());
        };

        let mut case = analysis.result.case;
        assert_late_png_structure(&mut case, body_node, &body)?;
        late_png_recognized = true;
        Ok(())
    })?;

    assert!(late_png_recognized);
    assert_eq!(coverage.source.bytes, u64::try_from(capture.len())?);
    assert_eq!(
        coverage.source.packet_records,
        u64::try_from(filler_frame_count + 2)?
    );
    assert_eq!(
        coverage.source.packets_without_supported_transport,
        u64::try_from(filler_frame_count)?
    );
    assert_eq!(coverage.analysis.flows, 1);
    assert_eq!(coverage.analysis.complete_flows, 1);
    assert_eq!(coverage.analysis.omitted_flow_records, 0);
    Ok(())
}

fn assert_late_png_structure(
    case: &mut Case,
    body_node: u64,
    body: &[u8],
) -> Result<(), Box<dyn Error>> {
    let mut expansion = ExpansionService::new(
        case,
        ExpansionLimits {
            depth: 1,
            objects: 8,
            input_bytes: body.len(),
            archive_entries: 1,
            member_bytes: body.len(),
            zip_work_bytes: body.len(),
            retained_bytes: body.len(),
        },
    );
    let outcome = expansion.expand_selected(body_node)?;
    assert!(outcome.complete);
    let structure = expansion
        .case()
        .nodes()
        .iter()
        .find(|node| {
            node.kind == "png_structure"
                && node
                    .details
                    .get("input_node")
                    .and_then(serde_json::Value::as_u64)
                    == Some(body_node)
        })
        .ok_or("late HTTP body was not expanded as a PNG structure")?;
    assert_eq!(
        structure.details.get("iend_end_offset"),
        Some(&serde_json::json!(body.len()))
    );
    assert_eq!(
        structure.details.get("bytes_after_iend"),
        Some(&serde_json::json!(0))
    );
    let structure_blob_id = structure
        .blob
        .as_deref()
        .ok_or("late PNG structure has no retained bytes")?;
    let structure_blob = expansion
        .case()
        .blobs()
        .iter()
        .find(|blob| blob.id == structure_blob_id)
        .ok_or("late PNG structure bytes are missing")?;
    assert_eq!(structure_blob.bytes, body);
    assert!(expansion.case().edges().iter().any(|edge| {
        edge.from == body_node
            && edge.to == structure.id
            && edge.relation == "parsed_as"
            && edge.status == EvidenceStatus::Observed
    }));
    Ok(())
}

#[test]
fn reports_flow_limit_omissions() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture_path = temporary.path().join("limited-flow.pcap");
    fs::write(&capture_path, capture_with_late_http(0, b"")?)?;
    let limits = Limits {
        frames: 1,
        ..Limits::default()
    };

    let coverage = acquire_full_source(&capture_path, limits, |_analysis| Ok(()))?;

    assert_eq!(coverage.source.packet_records, 2);
    assert_eq!(coverage.analysis.flows, 1);
    assert_eq!(coverage.analysis.incomplete_flows, 1);
    assert_eq!(coverage.analysis.selected_flow_records, 2);
    assert_eq!(coverage.analysis.retained_flow_records, 1);
    assert_eq!(coverage.analysis.omitted_flow_records, 1);
    assert!(coverage.cohort_analysis.is_none());
    Ok(())
}

#[test]
fn format_split_across_supplementary_pages_is_not_promoted() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture_path = temporary.path().join("split-page-object.pcap");
    let body = tiny_png()?;
    let split_at = body.len() / 2;
    let request_header = format!(
        "POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let mut first_payload = request_header.into_bytes();
    first_payload.extend_from_slice(
        body.get(..split_at)
            .ok_or("first PNG page fixture range is missing")?,
    );
    let second_payload = body
        .get(split_at..)
        .ok_or("second PNG page fixture range is missing")?;
    let second_sequence = 101_u32
        .checked_add(u32::try_from(first_payload.len())?)
        .ok_or("synthetic TCP sequence number overflow")?;
    let frames = [
        tcp_frame(100, 0x02, b"")?,
        tcp_frame(101, 0x18, &first_payload)?,
        tcp_frame(second_sequence, 0x18, second_payload)?,
    ];
    fs::write(&capture_path, capture_from_frames(&frames)?)?;
    let limits = Limits {
        frames: 1,
        units: 1,
        ..Limits::default()
    };
    let mut page_cases = Vec::new();

    let coverage = super::acquire_full_source_with_cohorts_in(
        &capture_path,
        temporary.path(),
        limits,
        |item| match item {
            super::FullSourceItem::Flow(_) | super::FullSourceItem::Cohort(_) => Ok(()),
            super::FullSourceItem::FlowPage(page) => {
                let page_complete = page.result.complete;
                let mut case = page.result.case;
                let recovery = crate::workbench::recover_case(&mut case)?;
                assert_eq!(recovery.validated_artifact_count, 0);
                assert!(!page_complete);
                assert!(!case.collection_complete());
                assert!(case.limitations().iter().any(|message| {
                    message.contains(
                        "TCP/session/application state was not joined across page boundaries",
                    )
                }));
                page_cases.push(page.page_index);
                Ok(())
            }
        },
    )?;

    assert_eq!(page_cases, [1, 2]);
    assert_eq!(coverage.analysis.supplementary_pages.pages, 2);
    assert_eq!(coverage.analysis.supplementary_pages.flows, 1);
    assert_eq!(coverage.analysis.supplementary_pages.selected_records, 2);
    assert_eq!(coverage.analysis.supplementary_pages.retained_records, 2);
    assert_eq!(coverage.analysis.supplementary_pages.omitted_records, 0);
    Ok(())
}

#[test]
fn records_supplementary_page_reconstruction_omissions_separately() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture_path = temporary.path().join("supplementary-range-omission.pcap");
    let frames = [
        tcp_frame(100, 0x02, b"")?,
        tcp_frame(101, 0x10, b"")?,
        tcp_frame(101, 0x18, b"A")?,
        tcp_frame(102, 0x18, b"B")?,
        tcp_frame(103, 0x10, b"")?,
        tcp_frame(103, 0x10, b"")?,
    ];
    fs::write(&capture_path, capture_from_frames(&frames)?)?;
    let limits = Limits {
        frames: 2,
        units: 2,
        range_observations: 1,
        ..Limits::default()
    };
    let mut page_cases = 0_u64;

    let coverage = super::acquire_full_source_with_cohorts_in(
        &capture_path,
        temporary.path(),
        limits,
        |item| match item {
            super::FullSourceItem::Flow(_) | super::FullSourceItem::Cohort(_) => Ok(()),
            super::FullSourceItem::FlowPage(page) => {
                page_cases += 1;
                let expected_omission = u64::from(page.page_index == 1);
                assert_page_capture_summary_omissions(&page.result.case, expected_omission)?;
                Ok(())
            }
        },
    )?;

    assert_eq!(page_cases, 2);
    assert_eq!(coverage.analysis.supplementary_pages.pages, 2);
    assert_eq!(coverage.analysis.omitted_tcp_records, 0);
    assert_eq!(coverage.analysis.omitted_fragments, 0);
    assert_eq!(coverage.analysis.omitted_sequence_ranges, 0);
    assert_eq!(coverage.analysis.omitted_tcp_bytes, 0);
    assert_eq!(coverage.analysis.omitted_tcp_observations, 0);
    let serialized = serde_json::to_value(&coverage)?;
    let page_reconstruction = serialized
        .pointer("/analysis/supplementary_pages/reconstruction_omissions")
        .ok_or("supplementary page reconstruction coverage is missing")?;
    for (field, expected) in [
        ("cases", 2),
        ("cases_with_omissions", 1),
        ("omitted_tcp_records", 0),
        ("omitted_fragments", 0),
        ("omitted_sequence_ranges", 1),
        ("omitted_tcp_bytes", 1),
        ("omitted_tcp_observations", 1),
        ("omitted_fragment_bytes", 0),
        ("omitted_fragment_observations", 0),
        ("unmeasured_omitted_ranges", 0),
        ("omitted_state_observations", 0),
    ] {
        assert_eq!(
            page_reconstruction.get(field),
            Some(&serde_json::json!(expected)),
            "unexpected supplementary page reconstruction counter: {field}"
        );
    }
    Ok(())
}

fn assert_page_capture_summary_omissions(
    case: &Case,
    expected_omission: u64,
) -> Result<(), Box<dyn Error>> {
    let summary = case
        .nodes()
        .iter()
        .find(|node| node.kind == "capture_summary")
        .ok_or("supplementary page capture summary is missing")?;
    for (field, expected) in [
        ("omitted_tcp_records", 0),
        ("omitted_fragments", 0),
        ("omitted_sequence_ranges", expected_omission),
        ("omitted_tcp_bytes", expected_omission),
        ("omitted_tcp_observations", expected_omission),
        ("omitted_fragment_bytes", 0),
        ("omitted_fragment_observations", 0),
        ("unmeasured_omitted_ranges", 0),
        ("omitted_state_observations", 0),
    ] {
        assert_eq!(
            summary.details.get(field),
            Some(&serde_json::json!(expected)),
            "unexpected page capture summary counter: {field}"
        );
    }
    Ok(())
}

fn capture_from_frames(frames: &[Vec<u8>]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut capture = pcap_header();
    for (index, frame) in frames.iter().enumerate() {
        append_record(&mut capture, u32::try_from(index)?, frame)?;
    }
    Ok(capture)
}

#[test]
fn reports_skipped_tcp_records_in_flow_coverage() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture_path = temporary.path().join("omitted-tcp-records.pcap");
    let mut capture = pcap_header();
    for (number, sequence, flags, payload) in [
        (0_u32, 100_u32, 0x02_u8, b"".as_slice()),
        (1, 101, 0x18, b"progress".as_slice()),
        (2, 900, 0x02, b"".as_slice()),
    ] {
        append_record(&mut capture, number, &tcp_frame(sequence, flags, payload)?)?;
    }
    fs::write(&capture_path, capture)?;
    let limits = Limits {
        sessions: 1,
        ..Limits::default()
    };

    let coverage = acquire_full_source(&capture_path, limits, |analysis| {
        assert_eq!(
            analysis
                .coverage
                .reconstruction_omissions
                .omitted_tcp_records,
            1
        );
        assert_eq!(
            analysis.coverage.reconstruction_omissions.omitted_fragments,
            0
        );
        assert_eq!(
            analysis
                .coverage
                .reconstruction_omissions
                .omitted_sequence_ranges,
            0
        );
        assert_eq!(
            analysis
                .coverage
                .reconstruction_omissions
                .omitted_state_observations,
            0
        );
        Ok(())
    })?;

    assert_eq!(coverage.analysis.flows, 1);
    assert_eq!(coverage.analysis.reconstruction_omission_flows, 1);
    assert_eq!(coverage.analysis.omitted_tcp_records, 1);
    assert_eq!(coverage.analysis.omitted_fragments, 0);
    assert_eq!(coverage.analysis.omitted_sequence_ranges, 0);
    assert_eq!(coverage.analysis.omitted_state_observations, 0);
    Ok(())
}

#[test]
fn reads_reconstruction_and_tcp_range_omissions_from_case() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    case.add_node(
        "capture_summary",
        None,
        Vec::new(),
        serde_json::json!({
            "omitted_fragments": 2,
            "omitted_tcp_records": 3,
            "omitted_sequence_ranges": 5,
            "omitted_state_observations": 7,
            "omitted_tcp_bytes": 23,
            "omitted_tcp_observations": 11,
            "omitted_fragment_bytes": 13,
            "omitted_fragment_observations": 2,
            "unmeasured_omitted_ranges": 4
        }),
    )?;

    let omissions = super::reconstruction_case_omissions(&case)?;
    assert_case_omission_values(omissions);

    let flow_coverage = super::PerFlowCoverage {
        selected_records: 1,
        retained_records: 1,
        omitted_records: 0,
        retention_limits: Vec::new(),
        reconstruction_omissions: omissions,
        complete: false,
    };
    let mut flow_totals = super::FlowAnalysisCoverage::default();
    super::add_flow_coverage(&mut flow_totals, &flow_coverage)?;
    assert_flow_omission_totals(&flow_totals);

    let mut cohort_totals = super::ReconstructionOmissionCoverage::default();
    cohort_totals.record(omissions)?;
    assert_cohort_omission_totals(cohort_totals);
    Ok(())
}

fn assert_case_omission_values(omissions: super::ReconstructionCaseOmissions) {
    assert_eq!(omissions.omitted_fragments, 2);
    assert_eq!(omissions.omitted_tcp_records, 3);
    assert_eq!(omissions.omitted_sequence_ranges, 5);
    assert_eq!(omissions.omitted_state_observations, 7);
    assert_eq!(omissions.omitted_tcp_bytes, 23);
    assert_eq!(omissions.omitted_tcp_observations, 11);
    assert_eq!(omissions.omitted_fragment_bytes, 13);
    assert_eq!(omissions.omitted_fragment_observations, 2);
    assert_eq!(omissions.unmeasured_omitted_ranges, 4);
}

fn assert_flow_omission_totals(coverage: &super::FlowAnalysisCoverage) {
    assert_eq!(coverage.reconstruction_omission_flows, 1);
    assert_eq!(coverage.omitted_tcp_records, 3);
    assert_eq!(coverage.omitted_fragments, 2);
    assert_eq!(coverage.omitted_sequence_ranges, 5);
    assert_eq!(coverage.omitted_state_observations, 7);
    assert_eq!(coverage.omitted_tcp_bytes, 23);
    assert_eq!(coverage.omitted_tcp_observations, 11);
    assert_eq!(coverage.omitted_fragment_bytes, 13);
    assert_eq!(coverage.omitted_fragment_observations, 2);
    assert_eq!(coverage.unmeasured_omitted_ranges, 4);
}

fn assert_cohort_omission_totals(coverage: super::ReconstructionOmissionCoverage) {
    assert_eq!(coverage.cases, 1);
    assert_eq!(coverage.cases_with_omissions, 1);
    assert_eq!(coverage.omitted_tcp_records, 3);
    assert_eq!(coverage.omitted_fragments, 2);
    assert_eq!(coverage.omitted_sequence_ranges, 5);
    assert_eq!(coverage.omitted_state_observations, 7);
    assert_eq!(coverage.omitted_tcp_bytes, 23);
    assert_eq!(coverage.omitted_tcp_observations, 11);
    assert_eq!(coverage.omitted_fragment_bytes, 13);
    assert_eq!(coverage.omitted_fragment_observations, 2);
    assert_eq!(coverage.unmeasured_omitted_ranges, 4);
}

#[test]
fn reports_each_retention_ceiling_that_omits_a_same_flow_late_http_object()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let body = b"late artifact bytes";
    let capture = capture_with_late_http(0, body)?;
    let request_header = format!(
        "POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let mut request_payload = request_header.into_bytes();
    request_payload.extend_from_slice(body);
    let second_frame_bytes = u64::try_from(tcp_frame(101, 0x18, &request_payload)?.len())?;
    let cases = [
        (
            "frames",
            l2_workbench::reconstruction::RecordRetentionLimit::Frames,
            Limits {
                frames: 1,
                ..Limits::default()
            },
        ),
        (
            "bytes",
            l2_workbench::reconstruction::RecordRetentionLimit::Bytes,
            Limits {
                bytes: usize::try_from(second_frame_bytes)?,
                ..Limits::default()
            },
        ),
        (
            "units",
            l2_workbench::reconstruction::RecordRetentionLimit::Units,
            Limits {
                units: 1,
                ..Limits::default()
            },
        ),
    ];

    for (name, expected_limit, limits) in cases {
        let analysis =
            analyze_late_http_with_limit(&temporary, name, &capture, body, expected_limit, limits)?;
        assert_eq!(analysis.selection_truncated_flows, 1);
        assert_eq!(analysis.frame_limited_flows, u64::from(name == "frames"));
        assert_eq!(analysis.byte_limited_flows, u64::from(name == "bytes"));
        assert_eq!(analysis.unit_limited_flows, u64::from(name == "units"));
    }
    Ok(())
}

fn analyze_late_http_with_limit(
    temporary: &tempfile::TempDir,
    name: &str,
    capture: &[u8],
    body: &[u8],
    expected_limit: l2_workbench::reconstruction::RecordRetentionLimit,
    limits: Limits,
) -> Result<super::FlowAnalysisCoverage, Box<dyn Error>> {
    let capture_path = temporary.path().join(format!("late-http-{name}.pcap"));
    fs::write(&capture_path, capture)?;
    let coverage = acquire_full_source(&capture_path, limits, |analysis| {
        assert_eq!(analysis.flow.packets, 2);
        assert_eq!(analysis.coverage.selected_records, 2);
        assert_eq!(analysis.coverage.retained_records, 1);
        assert_eq!(analysis.coverage.omitted_records, 1);
        assert_eq!(analysis.coverage.retention_limits, [expected_limit]);
        assert_eq!(
            analysis
                .coverage
                .reconstruction_omissions
                .omitted_sequence_ranges,
            0
        );
        assert!(!analysis.coverage.complete);
        assert!(find_http_body(&analysis.result.case, body)?.is_none());
        let selection = analysis
            .result
            .case
            .nodes()
            .iter()
            .find(|node| node.kind == "index_flow_selection")
            .ok_or("flow selection receipt is missing")?;
        assert_eq!(
            selection.details.get("selected_records"),
            Some(&serde_json::json!(2))
        );
        assert_eq!(
            selection.details.get("retained_input_records"),
            Some(&serde_json::json!(1))
        );
        assert_eq!(
            selection.details.get("omitted_records"),
            Some(&serde_json::json!(1))
        );
        assert_eq!(
            selection.details.get("retention_status"),
            Some(&serde_json::json!("resource_truncated_prefix"))
        );
        assert_eq!(
            selection.details.get("retention_limits"),
            Some(&serde_json::json!([name]))
        );
        Ok(())
    })?;

    assert_eq!(coverage.source.bytes, u64::try_from(capture.len())?);
    assert_eq!(coverage.analysis.flows, 1);
    assert_eq!(coverage.analysis.incomplete_flows, 1);
    assert_eq!(coverage.analysis.selected_flow_records, 2);
    assert_eq!(coverage.analysis.retained_flow_records, 1);
    assert_eq!(coverage.analysis.omitted_flow_records, 1);
    Ok(coverage.analysis)
}

#[test]
fn reports_tcp_range_omissions_separately_from_selected_record_truncation()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture_path = temporary.path().join("late-http-range-omission.pcap");
    let body = b"late artifact bytes";
    let capture = capture_with_late_http(0, body)?;
    fs::write(&capture_path, &capture)?;
    let limits = Limits {
        range_observations: 1,
        ..Limits::default()
    };
    let request_header = format!(
        "POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let expected_omitted_tcp_bytes = u64::try_from(request_header.len() + body.len())?;

    let coverage = acquire_full_source(&capture_path, limits, |analysis| {
        assert_eq!(analysis.coverage.selected_records, 2);
        assert_eq!(analysis.coverage.retained_records, 2);
        assert_eq!(analysis.coverage.omitted_records, 0);
        assert!(analysis.coverage.retention_limits.is_empty());
        assert_eq!(
            analysis
                .coverage
                .reconstruction_omissions
                .omitted_sequence_ranges,
            1
        );
        assert_eq!(
            analysis.coverage.reconstruction_omissions.omitted_tcp_bytes,
            expected_omitted_tcp_bytes
        );
        assert_eq!(
            analysis
                .coverage
                .reconstruction_omissions
                .omitted_tcp_observations,
            1
        );
        assert!(!analysis.coverage.complete);
        assert!(find_http_body(&analysis.result.case, body)?.is_none());
        let selection = analysis
            .result
            .case
            .nodes()
            .iter()
            .find(|node| node.kind == "index_flow_selection")
            .ok_or("flow selection receipt is missing")?;
        assert_eq!(
            selection.details.get("retention_status"),
            Some(&serde_json::json!("complete"))
        );
        assert_eq!(
            selection.details.get("retention_limits"),
            Some(&serde_json::json!([]))
        );
        Ok(())
    })?;

    assert_eq!(coverage.analysis.selection_truncated_flows, 0);
    assert_eq!(coverage.analysis.range_omission_flows, 1);
    assert_eq!(coverage.analysis.omitted_sequence_ranges, 1);
    assert_eq!(
        coverage.analysis.omitted_tcp_bytes,
        expected_omitted_tcp_bytes
    );
    assert_eq!(coverage.analysis.omitted_tcp_observations, 1);
    assert_eq!(coverage.analysis.omitted_flow_records, 0);
    Ok(())
}

#[test]
fn reports_rejected_tcp_range_extent_when_case_has_no_range_coverage() -> Result<(), Box<dyn Error>>
{
    let temporary = tempfile::tempdir()?;
    let capture_path = temporary.path().join("late-http-rejected-range.pcap");
    let body = b"range reservation omitted the complete stream";
    fs::write(&capture_path, capture_with_late_http(0, body)?)?;
    let limits = Limits {
        range_bytes: 1,
        ..Limits::default()
    };
    let request_header = format!(
        "POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let expected_omitted_tcp_bytes = u64::try_from(request_header.len() + body.len())?;

    let coverage = acquire_full_source(&capture_path, limits, |analysis| {
        let omissions = analysis.coverage.reconstruction_omissions;
        assert_eq!(omissions.omitted_sequence_ranges, 1);
        assert_eq!(omissions.omitted_tcp_bytes, expected_omitted_tcp_bytes);
        assert_eq!(omissions.omitted_tcp_observations, 0);
        assert_eq!(omissions.unmeasured_omitted_ranges, 1);
        assert!(analysis.result.case.nodes().iter().any(|node| {
            node.kind == "tcp_direction"
                && node
                    .details
                    .get("coverage")
                    .is_some_and(serde_json::Value::is_null)
        }));
        Ok(())
    })?;

    assert_eq!(
        coverage.analysis.omitted_tcp_bytes,
        expected_omitted_tcp_bytes
    );
    assert_eq!(coverage.analysis.omitted_tcp_observations, 0);
    assert_eq!(coverage.analysis.unmeasured_omitted_ranges, 1);
    Ok(())
}

#[test]
fn pair_cohort_groups_related_flows() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture_path = temporary.path().join("ip-pair.pcap");
    let mut capture = pcap_header();
    for (number, ports) in [(0_u32, (40_000, 80)), (1, (41_000, 21))] {
        append_record(
            &mut capture,
            number,
            &tcp_frame_on_ports(ports.0, ports.1, 100, 0x02, b"")?,
        )?;
    }
    fs::write(&capture_path, capture)?;

    let mut cohorts = Vec::new();
    let mut events = Vec::new();
    let coverage = super::acquire_full_source_with_cohorts_in(
        &capture_path,
        temporary.path(),
        Limits::default(),
        |item| match item {
            super::FullSourceItem::Flow(_) => {
                events.push("flow");
                Ok(())
            }
            super::FullSourceItem::FlowPage(_) => Ok(()),
            super::FullSourceItem::Cohort(analysis) => {
                events.push("cohort");
                cohorts.push(
                    analysis
                        .member_flows
                        .iter()
                        .map(|flow| flow.id)
                        .collect::<Vec<_>>(),
                );
                Ok(())
            }
        },
    )?;

    assert_eq!(cohorts.len(), 1);
    assert_eq!(events, ["flow", "flow", "cohort"]);
    assert_eq!(cohorts.first().ok_or("IP-pair cohort is missing")?.len(), 2);
    let cohort_coverage = coverage
        .cohort_analysis
        .ok_or("cohort analysis coverage was not recorded")?;
    assert_eq!(cohort_coverage.multi_flow_groups, 1);
    assert_eq!(cohort_coverage.complete_groups, 1);
    assert_eq!(cohort_coverage.reanalyzed_flows, 2);
    Ok(())
}

#[test]
fn pair_cohort_respects_vlan_scope() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture_path = temporary.path().join("ip-pair-scopes.pcap");
    let mut capture = pcap_header();
    for (number, vlan) in [(0_u32, 7_u16), (1, 8)] {
        let frame = tcp_frame_on_ports(40_000, 80, 100, 0x02, b"")?;
        append_record(&mut capture, number, &vlan_frame(&frame, vlan)?)?;
    }
    fs::write(&capture_path, capture)?;

    let mut cohorts = 0;
    let coverage = super::acquire_full_source_with_cohorts_in(
        &capture_path,
        temporary.path(),
        Limits::default(),
        |item| match item {
            super::FullSourceItem::Flow(_) | super::FullSourceItem::FlowPage(_) => Ok(()),
            super::FullSourceItem::Cohort(_) => {
                cohorts += 1;
                Ok(())
            }
        },
    )?;

    assert_eq!(cohorts, 0);
    assert_eq!(coverage.analysis.flows, 2);
    assert_eq!(
        coverage
            .cohort_analysis
            .ok_or("cohort analysis coverage was not recorded")?
            .multi_flow_groups,
        0
    );
    Ok(())
}

#[test]
fn visits_flows_across_pages() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture_path = temporary.path().join("many-flows.pcap");
    let flow_count = FLOW_PAGE_SIZE + 1;
    fs::write(&capture_path, capture_with_flows(flow_count)?)?;
    let mut visited = 0;

    let coverage = acquire_full_source(&capture_path, Limits::default(), |_analysis| {
        visited += 1;
        Ok(())
    })?;

    assert_eq!(visited, flow_count);
    assert_eq!(coverage.source.packet_records, u64::try_from(flow_count)?);
    assert_eq!(coverage.analysis.flows, u64::try_from(flow_count)?);
    assert_eq!(
        coverage.analysis.selected_flow_records,
        u64::try_from(flow_count)?
    );
    Ok(())
}

fn find_http_body(case: &Case, body: &[u8]) -> Result<Option<u64>, Box<dyn Error>> {
    for node in case.nodes() {
        if node.kind != "http_body"
            || node
                .details
                .get("status")
                .and_then(serde_json::Value::as_str)
                != Some("complete")
            || node
                .details
                .get("framing_complete")
                .and_then(serde_json::Value::as_bool)
                != Some(true)
        {
            continue;
        }
        let blob_id = node.blob.as_deref().ok_or("HTTP body has no byte object")?;
        let blob = case
            .blobs()
            .iter()
            .find(|blob| blob.id == blob_id)
            .ok_or("HTTP body byte object is missing")?;
        if blob.bytes == body {
            return Ok(Some(node.id));
        }
    }
    Ok(None)
}

fn capture_with_late_http(
    filler_frame_count: usize,
    body: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut capture = pcap_header();

    let filler = filler_frame()?;
    for index in 0..filler_frame_count {
        append_record(&mut capture, u32::try_from(index)?, &filler)?;
    }
    let sequence = u32::try_from(filler_frame_count)?;
    append_record(&mut capture, sequence, &tcp_frame(100, 0x02, b"")?)?;
    let mut payload = format!(
        "POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    payload.extend_from_slice(body);
    append_record(
        &mut capture,
        sequence.checked_add(1).ok_or("record number overflow")?,
        &tcp_frame(101, 0x18, &payload)?,
    )?;
    Ok(capture)
}

fn tiny_png() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut bytes, 1, 1);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        encoder.write_header()?.write_image_data(&[1, 2, 3])?;
    }
    Ok(bytes)
}

fn capture_with_flows(flow_count: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut capture = pcap_header();
    for index in 0..flow_count {
        let record = u32::try_from(index)?;
        let client_port = 10_000_u16
            .checked_add(u16::try_from(index)?)
            .ok_or("test flow port overflow")?;
        append_record(
            &mut capture,
            record,
            &tcp_frame_on_ports(client_port, 80, 100, 0x02, b"")?,
        )?;
    }
    Ok(capture)
}

fn pcap_header() -> Vec<u8> {
    let mut capture = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
    capture.extend_from_slice(&[0; 8]);
    capture.extend_from_slice(&l2_pcap::MAX_FRAME_LENGTH.to_le_bytes());
    capture.extend_from_slice(&1_u32.to_le_bytes());
    capture
}

fn filler_frame() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut frame = vec![0; usize::try_from(l2_pcap::MAX_FRAME_LENGTH)?];
    frame
        .get_mut(12..14)
        .ok_or("filler Ethernet frame is too short")?
        .copy_from_slice(&0x88b5_u16.to_be_bytes());
    Ok(frame)
}

fn append_record(capture: &mut Vec<u8>, number: u32, frame: &[u8]) -> Result<(), Box<dyn Error>> {
    capture.extend_from_slice(&1_u32.to_le_bytes());
    capture.extend_from_slice(&number.to_le_bytes());
    let length = u32::try_from(frame.len())?;
    capture.extend_from_slice(&length.to_le_bytes());
    capture.extend_from_slice(&length.to_le_bytes());
    capture.extend_from_slice(frame);
    Ok(())
}

fn vlan_frame(frame: &[u8], vlan: u16) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut tagged = frame.get(..12).ok_or("missing Ethernet prefix")?.to_vec();
    tagged.extend_from_slice(&0x8100_u16.to_be_bytes());
    tagged.extend_from_slice(&vlan.to_be_bytes());
    tagged.extend_from_slice(frame.get(12..).ok_or("missing EtherType")?);
    Ok(tagged)
}

fn tcp_frame(sequence: u32, flags: u8, payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    tcp_frame_on_ports(40_000, 80, sequence, flags, payload)
}

fn tcp_frame_on_ports(
    client_port: u16,
    server_port: u16,
    sequence: u32,
    flags: u8,
    payload: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let tcp_length = 20_usize
        .checked_add(payload.len())
        .ok_or("TCP length overflow")?;
    let ip_length = 20_usize
        .checked_add(tcp_length)
        .ok_or("IPv4 length overflow")?;
    let mut frame = vec![0; 12];
    frame.extend_from_slice(&[0x08, 0x00, 0x45, 0x00]);
    frame.extend_from_slice(&u16::try_from(ip_length)?.to_be_bytes());
    frame.extend_from_slice(&1_u16.to_be_bytes());
    frame.extend_from_slice(&0_u16.to_be_bytes());
    frame.extend_from_slice(&[64, 6, 0, 0]);
    frame.extend_from_slice(&[192, 0, 2, 10, 192, 0, 2, 20]);
    frame.extend_from_slice(&client_port.to_be_bytes());
    frame.extend_from_slice(&server_port.to_be_bytes());
    frame.extend_from_slice(&sequence.to_be_bytes());
    frame.extend_from_slice(&0_u32.to_be_bytes());
    frame.extend_from_slice(&[0x50, flags]);
    frame.extend_from_slice(&1024_u16.to_be_bytes());
    frame.extend_from_slice(&[0; 4]);
    frame.extend_from_slice(payload);
    Ok(frame)
}
