use std::error::Error;

use l2_workbench::{
    derivation::{Base64Alphabet, Base64Padding, DerivationStatus, Operation, run},
    protocol::ByteRange,
    recovery::proposals::{TransformProposalBudget, propose_transforms},
    recovery::regions::{
        RegionCue, RegionCueOrigin, TransformRegionLimits, propose_region_transforms,
        transform_region_scan_work_bound,
    },
};

const fn limits() -> TransformRegionLimits {
    TransformRegionLimits {
        max_scan_bytes: 1024,
        max_cues: 32,
        max_regions: 16,
        max_region_bytes: 256,
        max_total_region_bytes: 1024,
    }
}

const fn proposal_budget() -> TransformProposalBudget {
    TransformProposalBudget {
        max_candidates: 7,
        max_reports: 7,
    }
}

const fn base64_operation() -> Operation {
    Operation::Base64Decode {
        alphabet: Base64Alphabet::Standard,
        padding: Base64Padding::Required,
    }
}

#[test]
fn bounded_region_proposal_decodes_payload_between_binary_headers_and_trailers()
-> Result<(), Box<dyn Error>> {
    let mut input = b"\x01\x02:".to_vec();
    let payload_start = input.len();
    input.extend_from_slice(b"SGVsbG8=");
    let payload_end = input.len();
    input.extend_from_slice(b":\xfe\x03");
    let original = input.clone();

    let whole_buffer = propose_transforms(&input, proposal_budget());
    assert!(whole_buffer.proposals.iter().all(|proposal| {
        proposal
            .recipe
            .steps
            .iter()
            .all(|operation| !matches!(operation, Operation::Slice { .. }))
    }));
    assert!(
        !whole_buffer
            .proposals
            .iter()
            .any(|proposal| { proposal.recipe.steps.contains(&base64_operation()) })
    );

    let report = propose_region_transforms(&input, &[], limits(), proposal_budget());
    let region = report
        .regions
        .iter()
        .find(|region| {
            region.range
                == ByteRange {
                    start: payload_start,
                    end: payload_end,
                }
        })
        .ok_or("maximal Base64 run should be retained at its exact source range")?;
    let proposal = region
        .proposal_report
        .proposals
        .iter()
        .find(|proposal| proposal.recipe.steps.last() == Some(&base64_operation()))
        .ok_or("complete Base64 payload should have one canonical decode recipe")?;

    assert!(matches!(
        proposal.recipe.steps.first(),
        Some(Operation::Slice { start, length: Some(length) })
            if *start == payload_start && *length == payload_end - payload_start
    ));
    let derived = run(&input, &proposal.recipe)?;
    assert_eq!(derived.status, DerivationStatus::Completed);
    assert_eq!(derived.output, b"Hello");
    assert_eq!(
        input, original,
        "region proposals must keep source bytes immutable"
    );
    Ok(())
}

#[test]
fn explicit_record_boundary_cue_is_retained_with_exact_offsets() -> Result<(), Box<dyn Error>> {
    let input = b"\x01header\x02SGVsbG8=\x03trailer\x04";
    let start = input
        .windows(b"SGVsbG8=".len())
        .position(|window| window == b"SGVsbG8=")
        .ok_or("fixture contains the encoded payload")?;
    let cues = [RegionCue {
        range: ByteRange {
            start,
            end: start + b"SGVsbG8=".len(),
        },
        origin: RegionCueOrigin::RecordBoundary { message_index: 7 },
    }];

    let report = propose_region_transforms(input, &cues, limits(), proposal_budget());
    let cue = cues.first().ok_or("explicit boundary cue is missing")?;
    let region = report
        .regions
        .iter()
        .find(|region| region.range == cue.range)
        .ok_or("explicit record boundary should produce a bounded region")?;

    assert!(region.cue_origins.contains(&cue.origin));
    assert!(
        region
            .proposal_report
            .proposals
            .iter()
            .any(|proposal| proposal.recipe.steps.last() == Some(&base64_operation()))
    );
    Ok(())
}

#[test]
fn encoded_payload_ranges_follow_different_header_and_trailer_lengths() {
    let payload = b"SGVsbG8=";
    let fixtures: [(&[u8], &[u8]); 2] = [
        (b"\x01:", b":\xfe"),
        (b"\x02\x03prefix\xff:", b":trailer\x00\x04"),
    ];

    for (header, trailer) in fixtures {
        let input = [header, payload, trailer].concat();
        let start = header.len();
        let end = start + payload.len();
        let report = propose_region_transforms(&input, &[], limits(), proposal_budget());

        assert!(report.regions.iter().any(|region| {
            region.range == ByteRange { start, end }
                && region
                    .proposal_report
                    .proposals
                    .iter()
                    .any(|proposal| proposal.recipe.steps.last() == Some(&base64_operation()))
        }));
    }
}

#[test]
fn whole_buffer_encoding_run_is_assessed_only_by_the_existing_whole_input_path() {
    let input = b"ZGVhZA==";
    let whole_report = propose_transforms(input, proposal_budget());
    let region_report = propose_region_transforms(input, &[], limits(), proposal_budget());

    assert!(!whole_report.proposals.is_empty());
    assert!(region_report.regions.is_empty());
    assert!(region_report.coverage.complete);
}

#[test]
fn malformed_maximal_run_is_not_repaired_or_split_into_substrings() {
    let input = b"\xffSGVsbG8=bad\xfe";
    let report = propose_region_transforms(input, &[], limits(), proposal_budget());

    assert!(report.regions.iter().all(|region| {
        !region
            .proposal_report
            .proposals
            .iter()
            .any(|proposal| proposal.recipe.steps.last() == Some(&base64_operation()))
    }));
    assert!(report.regions.iter().any(|region| {
        region.range
            == ByteRange {
                start: 1,
                end: input.len() - 1,
            }
    }));
}

#[test]
fn region_count_and_scan_limits_report_incomplete_coverage() {
    let encoded = b"SGVsbG8=";
    let mut many_runs = Vec::new();
    for index in 0..5 {
        if index > 0 {
            many_runs.push(0xff);
        }
        many_runs.extend_from_slice(encoded);
    }
    let mut bounded = limits();
    bounded.max_regions = 2;
    let region_limited = propose_region_transforms(&many_runs, &[], bounded, proposal_budget());

    assert_eq!(region_limited.regions.len(), 2);
    assert!(region_limited.coverage.omissions.regions > 0);
    assert!(!region_limited.coverage.complete);

    let large_run = vec![b'A'; 128];
    let mut small_scan = limits();
    small_scan.max_scan_bytes = 32;
    let scan_limited = propose_region_transforms(&large_run, &[], small_scan, proposal_budget());

    assert!(scan_limited.regions.is_empty());
    assert!(scan_limited.coverage.omissions.scan_bytes > 0);
    assert!(!scan_limited.coverage.complete);

    let many_delimiters = b"x|SGVsbG8=|one|V29ybGQ=|two";
    let mut delimiter_limited = limits();
    delimiter_limited.max_regions = 2;
    let delimiter_report =
        propose_region_transforms(many_delimiters, &[], delimiter_limited, proposal_budget());
    assert_eq!(delimiter_report.regions.len(), 2);
    assert!(delimiter_report.coverage.omissions.regions > 0);
    assert!(!delimiter_report.coverage.complete);
}

#[test]
fn explicit_ranges_cannot_exceed_per_region_or_aggregate_budgets() -> Result<(), Box<dyn Error>> {
    let input = b"SGVsbG8=;V29ybGQ=";
    let cues = [
        RegionCue {
            range: ByteRange { start: 0, end: 8 },
            origin: RegionCueOrigin::RecognizedOffset { signature_index: 0 },
        },
        RegionCue {
            range: ByteRange { start: 9, end: 17 },
            origin: RegionCueOrigin::RecognizedOffset { signature_index: 1 },
        },
    ];
    let first_cue = cues.first().ok_or("first explicit cue is missing")?;
    let second_cue = cues.get(1).ok_or("second explicit cue is missing")?;
    let mut bounded = limits();
    bounded.max_total_region_bytes = 8;

    let report = propose_region_transforms(input, &cues, bounded, proposal_budget());

    assert_eq!(report.regions.len(), 1);
    let retained = report
        .regions
        .first()
        .ok_or("first cue should be retained")?;
    assert_eq!(retained.range, first_cue.range);
    assert_eq!(
        report.coverage.omissions.region_bytes,
        second_cue.range.end - second_cue.range.start
    );
    assert!(!report.coverage.complete);

    let mut per_region_limit = limits();
    per_region_limit.max_region_bytes = 4;
    per_region_limit.max_scan_bytes = 0;
    let per_region_report = propose_region_transforms(
        input,
        std::slice::from_ref(first_cue),
        per_region_limit,
        proposal_budget(),
    );
    assert!(per_region_report.regions.is_empty());
    assert_eq!(per_region_report.coverage.omissions.region_bytes, 8);
    Ok(())
}

#[test]
fn region_work_bound_covers_scan_cues_and_all_retained_syntax_passes() {
    let bounded = TransformRegionLimits {
        max_scan_bytes: 100,
        max_cues: 4,
        max_regions: 3,
        max_region_bytes: 50,
        max_total_region_bytes: 200,
    };

    assert_eq!(transform_region_scan_work_bound(bounded), Some(1_622));
}
