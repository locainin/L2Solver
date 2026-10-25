#[path = "../reconstruction/ipv4.rs"]
mod ipv4;
#[path = "../reconstruction/tcp.rs"]
mod tcp;

use l2_workbench::{
    protocol::{
        self, BoundaryStatus, ByteRange, FramingKind, FramingValidationBasis, ProtocolLimits,
        ReconstructedFramingInputOmissionReason, ReconstructedFramingRun,
    },
    reconstruction::{ReconstructionReport, Reconstructor},
};
use std::error::Error;

#[test]
fn reconstructed_delimiter_and_length_prefix_candidates_use_session_holdout()
-> Result<(), Box<dyn Error>> {
    let delimiter_capture = reconstruction(&[b"one\ntwo\n", b"red\nfox\n"])?;
    let delimiter_report = protocol::discover_reconstructed_framing_with_limits(
        "sha256:source",
        &delimiter_capture,
        ProtocolLimits::default(),
    )?;
    let delimiter_bootstrap = delimiter_report
        .bootstrap
        .as_ref()
        .ok_or("delimiter bootstrap is missing")?;
    let delimiter_kind = FramingKind::Delimiter { byte: b'\n' };
    assert!(delimiter_bootstrap.hypotheses.contains(&delimiter_kind));
    assert_eq!(
        delimiter_bootstrap.validation_basis,
        FramingValidationBasis::HeldOutRuns
    );
    let held_out = delimiter_report
        .framing_for_run(
            *delimiter_bootstrap
                .holdout_samples
                .first()
                .ok_or("delimiter holdout sample is missing")?,
        )
        .ok_or("held-out delimiter run is missing")?;
    let candidate = held_out
        .boundaries
        .candidates
        .iter()
        .find(|candidate| candidate.kind == delimiter_kind)
        .ok_or("held-out delimiter candidate is missing")?;
    assert_eq!(candidate.status, BoundaryStatus::Complete);
    assert_eq!(candidate.frame_count, 2);

    let prefixed = reconstruction(&[b"\x04one\x04two", b"\0xyz\0abc"])?;
    let prefix_report = protocol::discover_reconstructed_framing_with_limits(
        "sha256:source",
        &prefixed,
        ProtocolLimits::default(),
    )?;
    let prefix_bootstrap = prefix_report
        .bootstrap
        .as_ref()
        .ok_or("length-prefix bootstrap is missing")?;
    let prefix = FramingKind::LengthPrefix {
        offset: 0,
        width: 1,
        byte_order: protocol::ByteOrder::BigEndian,
        meaning: protocol::LengthMeaning::WholeMessage,
    };
    assert!(prefix_bootstrap.hypotheses.contains(&prefix));
    let held_out = prefix_report
        .framing_for_run(
            *prefix_bootstrap
                .holdout_samples
                .first()
                .ok_or("length-prefix holdout sample is missing")?,
        )
        .ok_or("held-out length-prefix run is missing")?;
    let candidate = held_out
        .boundaries
        .candidates
        .iter()
        .find(|candidate| candidate.kind == prefix)
        .ok_or("held-out length-prefix candidate is missing")?;
    assert_eq!(candidate.status, BoundaryStatus::InvalidCandidate);
    Ok(())
}

#[test]
fn unstructured_fixed_size_false_positives_remain_discovery_only() -> Result<(), Box<dyn Error>> {
    let unstructured = [
        0x02, 0xd7, 0x31, 0x95, 0xa8, 0x4c, 0xef, 0x60, 0xbb, 0x13, 0x72, 0x0e, 0xdc, 0x49, 0x86,
        0xf1,
    ];
    let reconstruction = reconstruction(&[&unstructured])?;
    let report = protocol::discover_reconstructed_framing_with_limits(
        "sha256:source",
        &reconstruction,
        ProtocolLimits::default(),
    )?;
    let bootstrap = report
        .bootstrap
        .as_ref()
        .ok_or("fixed-size bootstrap is missing")?;
    let fixed = FramingKind::FixedSize { bytes: 4 };
    assert!(bootstrap.hypotheses.contains(&fixed));
    assert_eq!(
        bootstrap.validation_basis,
        FramingValidationBasis::DiscoveryOnly
    );
    let run = report
        .framing_for_run(
            *bootstrap
                .discovery_samples
                .first()
                .ok_or("fixed-size discovery sample is missing")?,
        )
        .ok_or("discovery run is missing")?;
    let candidate = run
        .boundaries
        .candidates
        .iter()
        .find(|candidate| candidate.kind == fixed)
        .ok_or("fixed-size candidate is missing")?;
    assert_eq!(candidate.status, BoundaryStatus::Complete);
    assert_eq!(candidate.frame_count, 4);
    assert!(report.is_partial());
    Ok(())
}

#[test]
fn reconstructed_gap_facts_and_frame_origins_remain_exact() -> Result<(), Box<dyn Error>> {
    let mut reconstructor = Reconstructor::new();
    reconstructor.observe_selected(1, &tcp::tcp_ports(false, (40_000, 9_000), 100, 0x02, b"")?)?;
    reconstructor.observe_selected(
        2,
        &tcp::tcp_ports(false, (40_000, 9_000), 101, 0x18, b"a|")?,
    )?;
    reconstructor.observe_selected(
        3,
        &tcp::tcp_ports(false, (40_000, 9_000), 103, 0x18, b"b|")?,
    )?;
    reconstructor.observe_selected(
        4,
        &tcp::tcp_ports(false, (40_000, 9_000), 107, 0x18, b"c|")?,
    )?;
    reconstructor.observe_selected(
        5,
        &tcp::tcp_ports(false, (40_000, 9_000), 109, 0x18, b"d|")?,
    )?;
    let reconstruction = reconstructor.finish()?;
    let report = protocol::discover_reconstructed_framing_with_limits(
        "sha256:source",
        &reconstruction,
        ProtocolLimits::default(),
    )?;

    let [first_run, second_run] = report.runs.as_slice() else {
        return Err("expected two reconstructed byte runs".into());
    };
    assert_eq!(first_run.stream_offset, 0);
    assert_eq!(second_run.stream_offset, 6);
    let stream = report
        .streams
        .get(first_run.stream_index)
        .ok_or("run stream facts are missing")?;
    let coverage = stream
        .stream
        .coverage
        .as_ref()
        .ok_or("stream coverage facts are missing")?;
    assert_eq!(coverage.missing_bytes, 2);
    assert!(coverage.spans.iter().any(|span| {
        span.offset == 4
            && span.length == 2
            && span.status == l2_workbench::tcp_range::SpanStatus::Gap
    }));

    assert_mapped_origin_offsets(first_run)?;
    assert_eq!(
        report
            .bootstrap
            .as_ref()
            .ok_or("gapped bootstrap is missing")?
            .validation_basis,
        FramingValidationBasis::DiscoveryOnly
    );
    Ok(())
}

fn assert_mapped_origin_offsets(run: &ReconstructedFramingRun<'_>) -> Result<(), Box<dyn Error>> {
    let source = run.map_range(ByteRange { start: 1, end: 3 })?;
    assert_eq!(source.stream_range, ByteRange { start: 1, end: 3 });
    assert_eq!(source.origins.len(), 2);
    let first_origin = source
        .origins
        .first()
        .ok_or("first mapped source origin is missing")?;
    let second_origin = source
        .origins
        .get(1)
        .ok_or("second mapped source origin is missing")?;
    assert_eq!(first_origin.packet, 2);
    assert_eq!(first_origin.offset, 1);
    assert_eq!(first_origin.length, 1);
    assert_eq!(second_origin.packet, 3);
    assert_eq!(second_origin.offset, 2);
    assert_eq!(second_origin.length, 1);
    for mapped in &source.origins {
        let original = run
            .origins
            .iter()
            .find(|origin| origin.packet == mapped.packet)
            .ok_or("source mapping has no original stream origin")?;
        let expected_frame_offset = original
            .frame_offset
            .checked_add(mapped.offset - original.offset)
            .ok_or("mapped frame offset overflow")?;
        assert_eq!(mapped.frame_offset, expected_frame_offset);
    }
    Ok(())
}

#[test]
fn candidate_and_input_budget_omissions_are_explicit() -> Result<(), Box<dyn Error>> {
    let reconstruction = reconstruction(&[b"one\ntwo\n", b"red\nfox\n"])?;
    let limits = ProtocolLimits {
        max_samples: 1,
        max_candidates: 1,
        ..ProtocolLimits::default()
    };
    let report = protocol::discover_reconstructed_framing_with_limits(
        "sha256:source",
        &reconstruction,
        limits,
    )?;
    let bootstrap = report
        .bootstrap
        .as_ref()
        .ok_or("budgeted bootstrap is missing")?;

    assert_eq!(report.runs.len(), 1);
    assert_eq!(report.input_omissions.sample_limit, 1);
    assert_eq!(report.input_omissions.examples.len(), 1);
    assert_eq!(
        report
            .input_omissions
            .examples
            .first()
            .ok_or("omission example is missing")?
            .reason,
        ReconstructedFramingInputOmissionReason::SampleLimit
    );
    assert!(bootstrap.omitted_candidates > 0);
    assert!(!bootstrap.search_exhaustive_within_plan);
    assert!(bootstrap.report_details_complete);
    assert!(report.is_partial());
    Ok(())
}

#[test]
fn reconstructed_run_order_is_deterministic() -> Result<(), Box<dyn Error>> {
    let reconstruction = reconstruction(&[b"one\ntwo\n", b"red\nfox\n", b"sun\nday\n"])?;
    let first = protocol::discover_reconstructed_framing_with_limits(
        "sha256:source",
        &reconstruction,
        ProtocolLimits::default(),
    )?;
    let second = protocol::discover_reconstructed_framing_with_limits(
        "sha256:source",
        &reconstruction,
        ProtocolLimits::default(),
    )?;
    let first_bootstrap = first
        .bootstrap
        .as_ref()
        .ok_or("first deterministic bootstrap is missing")?;
    let second_bootstrap = second
        .bootstrap
        .as_ref()
        .ok_or("second deterministic bootstrap is missing")?;

    assert_eq!(
        first.runs.iter().map(|run| run.sample).collect::<Vec<_>>(),
        second.runs.iter().map(|run| run.sample).collect::<Vec<_>>()
    );
    assert_eq!(first_bootstrap.hypotheses, second_bootstrap.hypotheses);
    assert_eq!(
        first_bootstrap.discovery_samples,
        second_bootstrap.discovery_samples
    );
    assert_eq!(
        first_bootstrap.holdout_samples,
        second_bootstrap.holdout_samples
    );
    Ok(())
}

fn reconstruction(payloads: &[&[u8]]) -> Result<ReconstructionReport, Box<dyn Error>> {
    let mut reconstructor = Reconstructor::new();
    for (index, payload) in payloads.iter().enumerate() {
        let index = u16::try_from(index)?;
        let packet = u32::from(index) * 2 + 1;
        let port = 40_000_u16.checked_add(index).ok_or("test port overflow")?;
        let syn = if index == 0 {
            tcp::tcp(false, 100, 0x02, b"")?
        } else {
            tcp::tcp_ports(false, (port, 9_000), 100, 0x02, b"")?
        };
        reconstructor.observe_selected(packet, &syn)?;
        reconstructor.observe_selected(
            packet + 1,
            &tcp::tcp_ports(false, (port, 9_000), 101, 0x18, payload)?,
        )?;
    }
    Ok(reconstructor.finish()?)
}
