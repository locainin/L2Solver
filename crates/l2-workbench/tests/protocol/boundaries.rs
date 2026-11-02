use l2_workbench::protocol::{
    self, BoundaryStatus, ByteRunSample, Direction, FramingKind, LengthMeaning, MessageContext,
    ProtocolLimits,
};
use std::error::Error;

#[test]
fn delimiter_hypothesis_frames_partial_tail() -> Result<(), Box<dyn Error>> {
    let run = ByteRunSample {
        sample: 10,
        bytes: b"one\ntwo\nthree",
        context: Some(context(1, Direction::FirstToSecond)),
    };
    let report = protocol::extract_boundaries(&run, &[FramingKind::Delimiter { byte: b'\n' }])?;
    let [candidate] = report.candidates.as_slice() else {
        return Err("expected one delimiter candidate".into());
    };

    assert_eq!(candidate.status, BoundaryStatus::IncompleteTail);
    assert_eq!(candidate.frame_count, 2);
    let [first, second] = candidate.frames.as_slice() else {
        return Err("expected two retained delimiter frames".into());
    };
    assert_eq!(first.start, 0);
    assert_eq!(first.end, 4);
    assert_eq!(second.start, 4);
    assert_eq!(second.end, 8);
    assert_eq!(
        candidate.trailing,
        Some(protocol::ByteRange { start: 8, end: 13 })
    );
    Ok(())
}

#[test]
fn framing_iterator_visits_all_frames() {
    let bytes = b"x\n".repeat(300);
    let boundaries = protocol::frame_boundaries(&bytes, &FramingKind::Delimiter { byte: b'\n' });

    assert_eq!(boundaries.count(), 300);
}

#[test]
fn framing_iterator_reports_incomplete_tail() {
    let boundaries =
        protocol::frame_boundaries(b"one\ntwo", &FramingKind::Delimiter { byte: b'\n' })
            .collect::<Vec<_>>();

    assert_eq!(
        boundaries,
        [
            protocol::FrameBoundary::Frame(protocol::ByteRange { start: 0, end: 4 }),
            protocol::FrameBoundary::Tail {
                range: protocol::ByteRange { start: 4, end: 7 },
                status: BoundaryStatus::IncompleteTail,
            },
        ]
    );
}

#[test]
fn invalid_rule_yields_tail() {
    let boundaries = protocol::frame_boundaries(b"abc", &FramingKind::FixedSize { bytes: 0 })
        .collect::<Vec<_>>();

    assert_eq!(
        boundaries,
        [protocol::FrameBoundary::Tail {
            range: protocol::ByteRange { start: 0, end: 3 },
            status: BoundaryStatus::InvalidCandidate,
        }]
    );
}

#[test]
fn configured_frame_and_candidate_search_budgets_are_separate() -> Result<(), Box<dyn Error>> {
    let run = ByteRunSample {
        sample: 16,
        bytes: b"a\nb\nc\n",
        context: None,
    };
    let mut limits = ProtocolLimits {
        max_retained_frames: 2,
        ..ProtocolLimits::default()
    };
    let explicit = protocol::extract_boundaries_with_limits(
        &run,
        &[FramingKind::Delimiter { byte: b'\n' }],
        limits,
    )?;
    assert!(explicit.search_exhaustive_within_plan);
    assert!(!explicit.report_details_complete);
    assert_eq!(explicit.omitted_candidates, 0);
    let [candidate] = explicit.candidates.as_slice() else {
        return Err("expected one retained candidate".into());
    };
    assert_eq!(candidate.frame_count, 3);
    assert_eq!(candidate.frames.len(), 2);
    assert_eq!(candidate.omitted_frames, 1);

    limits.max_retained_frames = 256;
    limits.max_candidates = 1;
    let inferred = protocol::infer_run_boundaries_with_limits(&run, limits)?;
    assert!(!inferred.search_exhaustive_within_plan);
    assert!(inferred.report_details_complete);
    assert!(inferred.omitted_candidates > 0);
    assert_eq!(inferred.candidates.len(), 1);
    Ok(())
}

#[test]
fn large_frame_limit_small_report() -> Result<(), Box<dyn Error>> {
    let run = ByteRunSample {
        sample: 17,
        bytes: b"a\n",
        context: None,
    };
    let limits = ProtocolLimits {
        max_samples: 1,
        max_candidates: 1,
        max_retained_frames: 1_000_000,
        max_report_bytes: std::mem::size_of::<protocol::BoundaryCandidate>()
            + std::mem::size_of::<protocol::ByteRange>(),
        ..ProtocolLimits::default()
    };

    let report = protocol::extract_boundaries_with_limits(
        &run,
        &[FramingKind::Delimiter { byte: b'\n' }],
        limits,
    )?;
    assert!(report.report_details_complete);
    let [candidate] = report.candidates.as_slice() else {
        return Err("expected one delimiter candidate".into());
    };
    assert_eq!(candidate.frame_count, 1);
    assert_eq!(candidate.frames.len(), 1);
    assert_eq!(candidate.omitted_frames, 0);
    Ok(())
}

#[test]
fn shared_range_previews_partition_counts() -> Result<(), Box<dyn Error>> {
    let run = ByteRunSample {
        sample: 18,
        bytes: b"a\nb\nc\n",
        context: None,
    };
    let limits = ProtocolLimits {
        max_candidates: 2,
        max_retained_frames: 3,
        max_report_bytes: 2 * std::mem::size_of::<protocol::BoundaryCandidate>()
            + 2 * std::mem::size_of::<protocol::ByteRange>(),
        ..ProtocolLimits::default()
    };
    let report = protocol::extract_boundaries_with_limits(
        &run,
        &[
            FramingKind::Delimiter { byte: b'\n' },
            FramingKind::FixedSize { bytes: 2 },
        ],
        limits,
    )?;

    assert!(!report.report_details_complete);
    let [first, second] = report.candidates.as_slice() else {
        return Err("expected both candidate partitions to be evaluated".into());
    };
    assert_eq!(first.frame_count, 3);
    assert_eq!(first.omitted_frames, 1);
    assert_eq!(first.frames.len(), 2);
    assert_eq!(second.frame_count, 3);
    assert_eq!(second.omitted_frames, 3);
    assert_eq!(second.frames.len(), 0);
    assert_eq!(report.aliases.len(), 0);
    assert_eq!(report.omitted_alias_candidates, 2);
    Ok(())
}

#[test]
fn report_budget_bounds_candidate_and_alias_metadata() -> Result<(), Box<dyn Error>> {
    let run = ByteRunSample {
        sample: 180,
        bytes: b"a\nb\n",
        context: None,
    };
    let candidate_bytes = std::mem::size_of::<protocol::BoundaryCandidate>();
    let range_bytes = std::mem::size_of::<protocol::ByteRange>();
    let alias_bytes = std::mem::size_of::<protocol::BoundaryAliasGroup>();
    let limits = ProtocolLimits {
        max_candidates: 5,
        max_retained_frames: 1,
        max_report_bytes: 2 * candidate_bytes
            + 2 * range_bytes
            + alias_bytes
            + 2 * std::mem::size_of::<usize>(),
        ..ProtocolLimits::default()
    };
    let hypotheses = [
        FramingKind::FixedSize { bytes: 2 },
        FramingKind::FixedSize { bytes: 2 },
        FramingKind::FixedSize { bytes: 2 },
        FramingKind::FixedSize { bytes: 2 },
        FramingKind::FixedSize { bytes: 2 },
    ];

    let report = protocol::extract_boundaries_with_limits(&run, &hypotheses, limits)?;

    assert_eq!(report.evaluated_candidates, hypotheses.len());
    assert_eq!(report.candidates.len(), 2);
    assert_eq!(report.omitted_candidate_details, 3);
    assert_eq!(report.omitted_candidates, 0);
    assert!(report.search_exhaustive_within_plan);
    assert!(!report.report_details_complete);
    let [first, second] = report.candidates.as_slice() else {
        return Err("expected the first two deterministic candidate details".into());
    };
    assert_eq!(first.kind, hypotheses[0]);
    assert_eq!(second.kind, hypotheses[1]);
    assert_eq!(first.omitted_frames, 1);
    assert_eq!(second.omitted_frames, 1);
    let [alias] = report.aliases.as_slice() else {
        return Err("expected one retained alias group".into());
    };
    assert_eq!(alias.candidate_indices, [0, 1]);

    let retained_bytes = report.candidates.len() * candidate_bytes
        + report
            .candidates
            .iter()
            .map(|candidate| candidate.frames.len() * range_bytes)
            .sum::<usize>()
        + report.aliases.len() * alias_bytes
        + report
            .aliases
            .iter()
            .map(|group| group.candidate_indices.len() * std::mem::size_of::<usize>())
            .sum::<usize>();
    assert!(retained_bytes <= limits.max_report_bytes);
    Ok(())
}

#[test]
fn split_messages_single_run() -> Result<(), Box<dyn Error>> {
    let run = ByteRunSample {
        sample: 11,
        bytes: b"\x04one\x04two",
        context: Some(context(1, Direction::FirstToSecond)),
    };
    let report = protocol::extract_boundaries(
        &run,
        &[FramingKind::LengthPrefix {
            offset: 0,
            width: 1,
            byte_order: protocol::ByteOrder::BigEndian,
            meaning: LengthMeaning::WholeMessage,
        }],
    )?;
    let [candidate] = report.candidates.as_slice() else {
        return Err("expected one length candidate".into());
    };

    assert_eq!(candidate.status, BoundaryStatus::Complete);
    assert_eq!(candidate.frame_count, 2);
    let [first, second] = candidate.frames.as_slice() else {
        return Err("expected two retained length-prefixed frames".into());
    };
    assert_eq!(*first, protocol::ByteRange { start: 0, end: 4 });
    assert_eq!(*second, protocol::ByteRange { start: 4, end: 8 });
    assert_eq!(candidate.trailing, None);
    Ok(())
}

#[test]
fn wide_length_prefix_split_messages() -> Result<(), Box<dyn Error>> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&15_u64.to_be_bytes());
    bytes.extend_from_slice(b"first!\n");
    bytes.extend_from_slice(&16_u64.to_be_bytes());
    bytes.extend_from_slice(b"second!\n");
    let run = ByteRunSample {
        sample: 18,
        bytes: &bytes,
        context: None,
    };
    let hypothesis = FramingKind::LengthPrefix {
        offset: 0,
        width: 8,
        byte_order: protocol::ByteOrder::BigEndian,
        meaning: LengthMeaning::WholeMessage,
    };

    let explicit = protocol::extract_boundaries(&run, std::slice::from_ref(&hypothesis))?;
    let inferred = protocol::infer_run_boundaries(&run)?;

    let [candidate] = explicit.candidates.as_slice() else {
        return Err("expected one explicit length candidate".into());
    };
    assert_eq!(candidate.status, BoundaryStatus::Complete);
    assert_eq!(candidate.frame_count, 2);
    assert!(inferred.candidates.iter().any(|candidate| {
        candidate.kind == hypothesis
            && candidate.status == BoundaryStatus::Complete
            && candidate.frame_count == 2
    }));
    Ok(())
}

#[test]
fn inferred_prefix_configured_maximum_offset() -> Result<(), Box<dyn Error>> {
    let mut bytes = vec![0xa5; 48];
    *bytes.get_mut(20).ok_or("missing first length byte")? = 24;
    *bytes.get_mut(44).ok_or("missing second length byte")? = 24;
    let run = ByteRunSample {
        sample: 181,
        bytes: &bytes,
        context: None,
    };
    let limits = ProtocolLimits {
        max_prefix_offset: 20,
        max_candidates: 1_000,
        ..ProtocolLimits::default()
    };

    let report = protocol::infer_run_boundaries_with_limits(&run, limits)?;

    assert!(report.candidates.iter().any(|candidate| {
        candidate.kind
            == FramingKind::LengthPrefix {
                offset: 20,
                width: 1,
                byte_order: protocol::ByteOrder::BigEndian,
                meaning: LengthMeaning::WholeMessage,
            }
            && candidate.status == BoundaryStatus::Complete
            && candidate.frame_count == 2
    }));
    Ok(())
}

#[test]
fn inferred_candidates_aliases_distinct_hypotheses() -> Result<(), Box<dyn Error>> {
    let run = ByteRunSample {
        sample: 12,
        bytes: b"\x04A\nB\x04C\nD",
        context: Some(context(2, Direction::FirstToSecond)),
    };
    let report = protocol::infer_run_boundaries_with_limits(&run, ProtocolLimits::default())?;

    assert_ne!(report.candidates.len(), 0);
    assert!(
        report
            .candidates
            .iter()
            .any(|candidate| candidate.kind == FramingKind::Delimiter { byte: b'\n' })
    );
    assert_ne!(report.next_observation.len(), 0);
    assert_ne!(report.limitations.len(), 0);
    Ok(())
}

#[test]
fn alias_detection_boundaries_retained_examples() -> Result<(), Box<dyn Error>> {
    let mut bytes = vec![2; 519];
    *bytes.get_mut(513).ok_or("missing divergence byte")? = 3;
    *bytes.get_mut(514).ok_or("missing alignment byte")? = 3;
    let run = ByteRunSample {
        sample: 15,
        bytes: &bytes,
        context: None,
    };
    let hypotheses = [
        FramingKind::LengthPrefix {
            offset: 0,
            width: 1,
            byte_order: protocol::ByteOrder::BigEndian,
            meaning: LengthMeaning::WholeMessage,
        },
        FramingKind::LengthPrefix {
            offset: 1,
            width: 1,
            byte_order: protocol::ByteOrder::BigEndian,
            meaning: LengthMeaning::WholeMessage,
        },
    ];

    let report = protocol::extract_boundaries(&run, &hypotheses)?;

    let [first, second] = report.candidates.as_slice() else {
        return Err("expected both length hypotheses".into());
    };
    assert_eq!(first.frame_count, 259);
    assert_eq!(second.frame_count, 259);
    assert_eq!(first.omitted_frames, 3);
    assert_eq!(second.omitted_frames, 3);
    assert_eq!(first.frames, second.frames);
    assert_eq!(report.aliases.len(), 0);
    Ok(())
}

#[test]
fn invalid_oversized_hypotheses_reported_rejected() -> Result<(), Box<dyn Error>> {
    let run = ByteRunSample {
        sample: 13,
        bytes: b"\x00abc",
        context: None,
    };
    let report = protocol::extract_boundaries(
        &run,
        &[FramingKind::LengthPrefix {
            offset: 0,
            width: 1,
            byte_order: protocol::ByteOrder::BigEndian,
            meaning: LengthMeaning::WholeMessage,
        }],
    )?;
    let [candidate] = report.candidates.as_slice() else {
        return Err("expected one invalid length candidate".into());
    };
    assert_eq!(candidate.status, BoundaryStatus::InvalidCandidate);

    let too_large = vec![0; protocol::MAX_PROTOCOL_RUN_BYTES + 1];
    let oversized = ByteRunSample {
        sample: 14,
        bytes: &too_large,
        context: None,
    };
    assert!(matches!(
        protocol::infer_run_boundaries(&oversized),
        Err(protocol::ProtocolError::RunTooLarge { .. })
    ));
    Ok(())
}

fn context(session: u64, direction: Direction) -> MessageContext {
    MessageContext {
        source: "source-a".to_owned(),
        scope: "scope-a".to_owned(),
        session,
        direction,
    }
}
