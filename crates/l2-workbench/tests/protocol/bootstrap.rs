use l2_workbench::protocol::{
    self, BoundaryStatus, ByteOrder, ByteRunSample, Direction, FramingKind, FramingValidationBasis,
    HoldoutBasis, LengthMeaning, MessageContext, ProtocolError, ProtocolLimits,
};
use std::error::Error;

#[test]
fn length_prefix_candidates_bootstrap() -> Result<(), Box<dyn Error>> {
    let runs = [
        run(1, 1, b"\x04one\x04two"),
        run(2, 2, b"\x04red\x04fox"),
        run(3, 3, b"\x04sun\x04day"),
        run(4, 4, b"\x04hot\x04tea"),
    ];

    let report = protocol::bootstrap_framing_with_limits(&runs, ProtocolLimits::default())?;
    let hypothesis = FramingKind::LengthPrefix {
        offset: 0,
        width: 1,
        byte_order: ByteOrder::BigEndian,
        meaning: LengthMeaning::WholeMessage,
    };

    assert!(report.hypotheses.contains(&hypothesis));
    assert_eq!(report.discovery_samples, [1, 2]);
    assert_eq!(report.holdout_samples, [3, 4]);
    assert_eq!(report.validation_basis, FramingValidationBasis::HeldOutRuns);
    assert_eq!(report.discovery.len(), 2);
    assert_eq!(report.holdout.len(), 2);
    for run_report in report.discovery.iter().chain(&report.holdout) {
        let candidate = run_report
            .boundaries
            .candidates
            .iter()
            .find(|candidate| candidate.kind == hypothesis)
            .ok_or("missing materialized length-prefix candidate")?;
        assert_eq!(candidate.status, BoundaryStatus::Complete);
        assert_eq!(candidate.frame_count, 2);
    }
    Ok(())
}

#[test]
fn delimiter_candidates_bootstrap() -> Result<(), Box<dyn Error>> {
    let runs = [
        run(1, 1, b"one\ntwo\n"),
        run(2, 2, b"red\nfox\n"),
        run(3, 3, b"sun\nday\n"),
        run(4, 4, b"hot\ntea\n"),
    ];

    let report = protocol::bootstrap_framing_with_limits(&runs, ProtocolLimits::default())?;
    let hypothesis = FramingKind::Delimiter { byte: b'\n' };
    assert!(report.hypotheses.contains(&hypothesis));
    for run_report in report.discovery.iter().chain(&report.holdout) {
        let candidate = run_report
            .boundaries
            .candidates
            .iter()
            .find(|candidate| candidate.kind == hypothesis)
            .ok_or("missing materialized delimiter candidate")?;
        assert_eq!(candidate.status, BoundaryStatus::Complete);
        assert_eq!(candidate.frame_count, 2);
    }
    Ok(())
}

#[test]
fn aliases_survive_bootstrap() -> Result<(), Box<dyn Error>> {
    let runs = [
        run(1, 1, b"\0\x04ab\0\x04cd"),
        run(2, 2, b"\0\x04ef\0\x04gh"),
        run(3, 3, b"\0\x04ij\0\x04kl"),
        run(4, 4, b"\0\x04mn\0\x04op"),
    ];

    let report = protocol::bootstrap_framing_with_limits(&runs, ProtocolLimits::default())?;
    let discovery = report.discovery.first().ok_or("missing discovery run")?;
    assert!(discovery.boundaries.aliases.iter().any(|group| {
        let aliased_kinds = group
            .candidate_indices
            .iter()
            .filter_map(|index| discovery.boundaries.candidates.get(*index))
            .map(|candidate| &candidate.kind)
            .collect::<Vec<_>>();
        group.candidate_indices.len() >= 2
            && aliased_kinds.iter().any(|kind| {
                **kind
                    == FramingKind::LengthPrefix {
                        offset: 0,
                        width: 2,
                        byte_order: ByteOrder::BigEndian,
                        meaning: LengthMeaning::WholeMessage,
                    }
            })
            && aliased_kinds.iter().any(|kind| {
                **kind
                    == FramingKind::LengthPrefix {
                        offset: 1,
                        width: 1,
                        byte_order: ByteOrder::BigEndian,
                        meaning: LengthMeaning::WholeMessage,
                    }
            })
    }));
    Ok(())
}

#[test]
fn truncated_tails_survive_bootstrap() -> Result<(), Box<dyn Error>> {
    let runs = [
        run(1, 1, b"\x04one\x04two"),
        run(2, 2, b"\x04red\x04fox"),
        run(3, 3, b"\x04sun\x04da"),
        run(4, 4, b"\x04hot\x04te"),
    ];

    let report = protocol::bootstrap_framing_with_limits(&runs, ProtocolLimits::default())?;
    let hypothesis = FramingKind::LengthPrefix {
        offset: 0,
        width: 1,
        byte_order: ByteOrder::BigEndian,
        meaning: LengthMeaning::WholeMessage,
    };
    for run_report in &report.holdout {
        let candidate = run_report
            .boundaries
            .candidates
            .iter()
            .find(|candidate| candidate.kind == hypothesis)
            .ok_or("missing materialized truncated candidate")?;
        assert_eq!(candidate.status, BoundaryStatus::IncompleteTail);
        assert_eq!(
            candidate.trailing,
            Some(protocol::ByteRange { start: 4, end: 7 })
        );
    }
    Ok(())
}

#[test]
fn holdout_contradictions_survive() -> Result<(), Box<dyn Error>> {
    let runs = [
        run(1, 1, b"\x04one\x04two"),
        run(2, 2, b"\x04red\x04fox"),
        run(3, 3, b"\0xyz"),
        run(4, 4, b"\0abc"),
    ];

    let report = protocol::bootstrap_framing_with_limits(&runs, ProtocolLimits::default())?;
    let hypothesis = FramingKind::LengthPrefix {
        offset: 0,
        width: 1,
        byte_order: ByteOrder::BigEndian,
        meaning: LengthMeaning::WholeMessage,
    };
    assert!(report.discovery_samples.iter().all(|sample| *sample <= 2));
    assert!(report.holdout_samples.iter().all(|sample| *sample >= 3));
    for run_report in &report.holdout {
        let candidate = run_report
            .boundaries
            .candidates
            .iter()
            .find(|candidate| candidate.kind == hypothesis)
            .ok_or("missing held-out candidate")?;
        assert_eq!(candidate.status, BoundaryStatus::InvalidCandidate);
        assert_eq!(candidate.issue_offset, Some(0));
        assert_eq!(
            candidate.trailing,
            Some(protocol::ByteRange { start: 0, end: 4 })
        );
    }
    Ok(())
}

#[test]
fn candidate_omissions_are_reported() -> Result<(), Box<dyn Error>> {
    let runs = [
        run(1, 1, b"one\ntwo\n"),
        run(2, 2, b"red\nfox\n"),
        run(3, 3, b"sun\nday\n"),
        run(4, 4, b"hot\ntea\n"),
    ];
    let limits = ProtocolLimits {
        max_candidates: 1,
        ..ProtocolLimits::default()
    };

    let report = protocol::bootstrap_framing_with_limits(&runs, limits)?;

    assert_eq!(report.hypotheses.len(), 1);
    assert!(report.omitted_candidates > 0);
    assert!(!report.search_exhaustive_within_plan);
    assert!(report.report_details_complete);
    assert!(report.discovery.iter().all(|run_report| {
        run_report
            .candidate_generation_omissions
            .is_some_and(|count| count > 0)
    }));
    assert!(
        report
            .holdout
            .iter()
            .all(|run_report| run_report.candidate_generation_omissions.is_none())
    );
    Ok(())
}

#[test]
fn execution_plan_retains_evaluated_hypotheses_when_report_preview_is_empty()
-> Result<(), Box<dyn Error>> {
    let runs = [
        run(1, 1, b"one\ntwo\n"),
        run(2, 2, b"red\nfox\n"),
        run(3, 3, b"sun\nday\n"),
        run(4, 4, b"hot\ntea\n"),
    ];
    let limits = ProtocolLimits {
        max_report_bytes: 1,
        ..ProtocolLimits::default()
    };

    let first = protocol::bootstrap_framing_with_execution_plan(&runs, limits)?;
    let second = protocol::bootstrap_framing_with_execution_plan(&runs, limits)?;

    assert_eq!(first.report.hypotheses.len(), 0);
    assert_eq!(
        first.report.omitted_hypothesis_details,
        first.execution_plan.hypotheses.len()
    );
    assert!(first.report.search_exhaustive_within_plan);
    assert!(!first.report.report_details_complete);
    assert_ne!(first.execution_plan.hypotheses.len(), 0);
    assert_eq!(
        first.execution_plan.hypotheses,
        second.execution_plan.hypotheses
    );
    assert_eq!(
        first.execution_plan.surviving_hypotheses,
        second.execution_plan.surviving_hypotheses
    );
    assert!(
        first
            .report
            .discovery
            .iter()
            .chain(&first.report.holdout)
            .all(|run_report| run_report.boundaries.evaluated_candidates
                == first.execution_plan.hypotheses.len())
    );
    assert!(
        first
            .report
            .discovery
            .iter()
            .chain(&first.report.holdout)
            .all(|run_report| run_report.boundaries.candidates.is_empty())
    );
    Ok(())
}

#[test]
fn execution_plan_survivors_require_complete_boundaries_on_every_run() -> Result<(), Box<dyn Error>>
{
    let runs = [
        run(1, 1, b"\x08a\na\nb\nc\n"),
        run(2, 2, b"\x08a\na\nb\nc\n"),
        run(3, 3, b"\0a\na\nb\nc\n"),
        run(4, 4, b"\0a\na\nb\nc\n"),
    ];
    let limits = ProtocolLimits {
        max_report_bytes: 1,
        ..ProtocolLimits::default()
    };

    let output = protocol::bootstrap_framing_with_execution_plan(&runs, limits)?;
    let newline_delimiter = FramingKind::Delimiter { byte: b'\n' };
    let incomplete_delimiter = FramingKind::Delimiter { byte: b'a' };
    let fixed_size = FramingKind::FixedSize { bytes: 3 };
    let incomplete_length = FramingKind::LengthPrefix {
        offset: 0,
        width: 1,
        byte_order: ByteOrder::BigEndian,
        meaning: LengthMeaning::BytesAfterField,
    };
    let invalid_or_incomplete_length = FramingKind::LengthPrefix {
        offset: 0,
        width: 1,
        byte_order: ByteOrder::BigEndian,
        meaning: LengthMeaning::WholeMessage,
    };

    assert!(
        output
            .report
            .discovery
            .iter()
            .all(|run_report| run_report.boundaries.candidates.is_empty())
    );
    assert!(
        output
            .report
            .holdout
            .iter()
            .all(|run_report| run_report.boundaries.candidates.is_empty())
    );
    for hypothesis in [
        &newline_delimiter,
        &incomplete_delimiter,
        &fixed_size,
        &incomplete_length,
        &invalid_or_incomplete_length,
    ] {
        assert!(output.execution_plan.hypotheses.contains(hypothesis));
    }
    assert!(
        output
            .execution_plan
            .surviving_hypotheses
            .contains(&newline_delimiter)
    );
    assert!(
        output
            .execution_plan
            .surviving_hypotheses
            .contains(&fixed_size)
    );
    assert!(
        !output
            .execution_plan
            .surviving_hypotheses
            .contains(&incomplete_delimiter)
    );
    assert!(
        !output
            .execution_plan
            .surviving_hypotheses
            .contains(&incomplete_length)
    );
    assert!(
        !output
            .execution_plan
            .surviving_hypotheses
            .contains(&invalid_or_incomplete_length)
    );
    Ok(())
}

#[test]
fn execution_plan_does_not_claim_exhaustiveness_after_search_omissions()
-> Result<(), Box<dyn Error>> {
    let runs = [
        run(1, 1, b"one\ntwo\n"),
        run(2, 2, b"red\nfox\n"),
        run(3, 3, b"sun\nday\n"),
        run(4, 4, b"hot\ntea\n"),
    ];
    let limits = ProtocolLimits {
        max_candidates: 1,
        max_report_bytes: 1,
        ..ProtocolLimits::default()
    };

    let output = protocol::bootstrap_framing_with_execution_plan(&runs, limits)?;

    assert_eq!(output.execution_plan.hypotheses.len(), 1);
    assert!(output.report.omitted_candidates > 0);
    assert!(!output.report.search_exhaustive_within_plan);
    assert_eq!(output.report.hypotheses.len(), 0);
    assert_eq!(output.report.omitted_hypothesis_details, 1);
    assert_eq!(
        output.execution_plan.surviving_hypotheses,
        [FramingKind::Delimiter { byte: b'\n' }]
    );
    Ok(())
}

#[test]
fn sessions_stay_together() -> Result<(), Box<dyn Error>> {
    let runs = [
        run(1, 1, b"one\ntwo\n"),
        run(2, 1, b"red\nfox\n"),
        run(3, 2, b"sun\nday\n"),
        run(4, 2, b"hot\ntea\n"),
        run(5, 3, b"old\nnew\n"),
        run(6, 4, b"ice\nbox\n"),
    ];

    let report = protocol::bootstrap_framing_with_limits(&runs, ProtocolLimits::default())?;

    assert_eq!(report.split_basis, HoldoutBasis::CompleteSessions);
    assert_eq!(report.discovery_samples, [1, 2, 3, 4]);
    assert_eq!(report.holdout_samples, [5, 6]);
    Ok(())
}

#[test]
fn candidate_detail_omissions_are_reported() -> Result<(), Box<dyn Error>> {
    let runs = [
        run(1, 1, b"a\nb\nc\n"),
        run(2, 2, b"d\ne\nf\n"),
        run(3, 3, b"g\nh\ni\n"),
        run(4, 4, b"j\nk\nl\n"),
    ];
    let limits = ProtocolLimits {
        max_report_bytes: 4
            * (std::mem::size_of::<protocol::BoundaryCandidate>()
                + 2 * std::mem::size_of::<protocol::ByteRange>()),
        ..ProtocolLimits::default()
    };

    let report = protocol::bootstrap_framing_with_limits(&runs, limits)?;

    assert!(report.search_exhaustive_within_plan);
    assert!(!report.report_details_complete);
    assert!(report.omitted_candidate_details > 0);
    Ok(())
}

#[test]
fn many_short_runs_bound_materialized_candidate_records() -> Result<(), Box<dyn Error>> {
    let mut runs = Vec::new();
    runs.try_reserve_exact(4_096)
        .map_err(|_| "could not reserve scale-test runs")?;
    for sample in 1..=4_096 {
        runs.push(unscoped_run(sample, b"x"));
    }
    let limits = ProtocolLimits::default();

    let report = protocol::bootstrap_framing_with_limits(&runs, limits)?;

    let evaluated_candidates = report
        .discovery
        .iter()
        .chain(&report.holdout)
        .map(|run_report| run_report.boundaries.evaluated_candidates)
        .sum::<usize>();
    let retained_candidates = report
        .discovery
        .iter()
        .chain(&report.holdout)
        .map(|run_report| run_report.boundaries.candidates.len())
        .sum::<usize>();
    assert!(
        report
            .discovery
            .iter()
            .chain(&report.holdout)
            .all(
                |run_report| run_report.boundaries.aliases.iter().all(|group| group
                    .candidate_indices
                    .iter()
                    .all(|index| *index < run_report.boundaries.candidates.len()))
            )
    );
    let retained_bytes = report.hypotheses.len() * std::mem::size_of::<FramingKind>()
        + report
            .discovery
            .iter()
            .chain(&report.holdout)
            .map(|run_report| &run_report.boundaries)
            .map(|boundaries| {
                boundaries.candidates.len() * std::mem::size_of::<protocol::BoundaryCandidate>()
                    + boundaries
                        .candidates
                        .iter()
                        .map(|candidate| {
                            candidate.frames.len() * std::mem::size_of::<protocol::ByteRange>()
                        })
                        .sum::<usize>()
                    + boundaries.aliases.len() * std::mem::size_of::<protocol::BoundaryAliasGroup>()
                    + boundaries
                        .aliases
                        .iter()
                        .map(|group| group.candidate_indices.len() * std::mem::size_of::<usize>())
                        .sum::<usize>()
            })
            .sum::<usize>();

    assert_eq!(report.hypotheses.len(), 224);
    assert_eq!(evaluated_candidates, report.hypotheses.len() * runs.len());
    assert!(evaluated_candidates > 900_000);
    assert!(evaluated_candidates > retained_candidates);
    assert_eq!(
        report.omitted_candidate_details,
        evaluated_candidates - retained_candidates
    );
    assert!(!report.report_details_complete);
    assert!(report.search_exhaustive_within_plan);
    assert!(retained_bytes <= limits.max_report_bytes);
    assert!(retained_candidates < evaluated_candidates / 2);
    Ok(())
}

#[test]
fn unscoped_runs_split_by_order() -> Result<(), Box<dyn Error>> {
    let runs = [
        unscoped_run(1, b"one\ntwo\n"),
        unscoped_run(2, b"red\nfox\n"),
        unscoped_run(3, b"sun\nday\n"),
        unscoped_run(4, b"hot\ntea\n"),
    ];

    let report = protocol::bootstrap_framing_with_limits(&runs, ProtocolLimits::default())?;

    assert_eq!(report.split_basis, HoldoutBasis::SampleOrder);
    assert_eq!(report.discovery_samples, [1, 2]);
    assert_eq!(report.holdout_samples, [3, 4]);
    Ok(())
}

#[test]
fn single_run_reports_no_holdout() -> Result<(), Box<dyn Error>> {
    let runs = [unscoped_run(1, b"one\ntwo\n")];

    let report = protocol::bootstrap_framing_with_limits(&runs, ProtocolLimits::default())?;

    assert_eq!(
        report.validation_basis,
        FramingValidationBasis::DiscoveryOnly
    );
    assert_eq!(report.discovery_samples, [1]);
    assert_eq!(report.holdout_samples.len(), 0);
    assert!(
        report
            .limitations
            .iter()
            .any(|limitation| limitation.contains("independent holdout"))
    );
    Ok(())
}

#[test]
fn empty_runs_report_clear_error() {
    let result = protocol::bootstrap_framing_with_limits(&[], ProtocolLimits::default());

    assert_eq!(result, Err(ProtocolError::InsufficientRuns { count: 0 }));
}

#[test]
fn one_session_reports_no_holdout() -> Result<(), Box<dyn Error>> {
    let runs = [
        run_direction(1, 1, Direction::FirstToSecond, b"one\ntwo\n"),
        run_direction(2, 1, Direction::SecondToFirst, b"red\nfox\n"),
    ];

    let report = protocol::bootstrap_framing_with_limits(&runs, ProtocolLimits::default())?;

    assert_eq!(
        report.validation_basis,
        FramingValidationBasis::DiscoveryOnly
    );
    assert_eq!(report.split_basis, HoldoutBasis::CompleteSessions);
    assert_eq!(report.discovery_samples, [1, 2]);
    assert_eq!(report.holdout_samples.len(), 0);
    Ok(())
}

fn run(sample: u64, session: u64, bytes: &'static [u8]) -> ByteRunSample<'static> {
    ByteRunSample {
        sample,
        context: Some(context(session)),
        bytes,
    }
}

fn run_direction(
    sample: u64,
    session: u64,
    direction: Direction,
    bytes: &'static [u8],
) -> ByteRunSample<'static> {
    ByteRunSample {
        sample,
        context: Some(context_with_direction(session, direction)),
        bytes,
    }
}

const fn unscoped_run(sample: u64, bytes: &'static [u8]) -> ByteRunSample<'static> {
    ByteRunSample {
        sample,
        context: None,
        bytes,
    }
}

fn context(session: u64) -> MessageContext {
    context_with_direction(session, Direction::FirstToSecond)
}

fn context_with_direction(session: u64, direction: Direction) -> MessageContext {
    MessageContext {
        source: "synthetic".to_owned(),
        scope: "capture".to_owned(),
        session,
        direction,
    }
}
