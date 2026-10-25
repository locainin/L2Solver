use l2_workbench::protocol::{
    self, ByteRunSample, Direction, MessageContext, MessageRole, MessageSample, ProtocolLimits,
};

pub(super) fn exercise(input: &[u8]) {
    let half = input.get(..input.len() / 2).unwrap_or_default();
    let samples = [
        MessageSample {
            sample: 1,
            role: MessageRole::Request,
            bytes: input,
            context: Some(context(1, Direction::FirstToSecond)),
        },
        MessageSample {
            sample: 2,
            role: MessageRole::Response,
            bytes: half,
            context: Some(context(1, Direction::SecondToFirst)),
        },
        MessageSample {
            sample: 3,
            role: MessageRole::Request,
            bytes: half,
            context: Some(context(2, Direction::FirstToSecond)),
        },
        MessageSample {
            sample: 4,
            role: MessageRole::Response,
            bytes: input,
            context: Some(context(2, Direction::SecondToFirst)),
        },
    ];
    let report = protocol::infer_framing(&samples)
        .unwrap_or_else(|_| panic!("bounded message samples were rejected"));
    for candidate in report.candidates {
        for fit in [candidate.discovery, candidate.holdout] {
            assert_eq!(
                fit.supported + fit.counterexample_count + fit.untestable_samples,
                fit.sample_count
            );
            assert_eq!(fit.compared, fit.supported + fit.counterexample_count);
        }
    }
    let width = input.first().map_or(1, |byte| usize::from(*byte) % 24 + 1);
    let report = protocol::correlate_fields(&samples, 0, 0, width)
        .unwrap_or_else(|_| panic!("bounded field selection was rejected"));
    for transition in report
        .discovery
        .transitions
        .into_iter()
        .chain(report.holdout.transitions)
    {
        assert!(
            transition
                .request_sample
                .is_none_or(|request| request < transition.response_sample)
        );
    }

    exercise_run_boundaries(input);
}

fn exercise_run_boundaries(input: &[u8]) {
    // Run-boundary limits remain separate from the message-pair inference paths
    let run = ByteRunSample {
        sample: 5,
        context: Some(context(1, Direction::FirstToSecond)),
        bytes: input,
    };
    let limits = ProtocolLimits {
        max_run_bytes: input.len().max(1),
        max_total_bytes: input.len().max(1),
        max_candidates: 32,
        max_retained_frames: 32,
        ..ProtocolLimits::default()
    };
    let report = protocol::infer_run_boundaries_with_limits(&run, limits)
        .unwrap_or_else(|_| panic!("bounded run boundary hypotheses were rejected"));
    assert_eq!(report.prefix_offset_limit, limits.max_prefix_offset);
    assert_eq!(
        report
            .candidates
            .len()
            .checked_add(report.omitted_candidate_details),
        Some(report.evaluated_candidates)
    );
    assert_eq!(
        report.search_exhaustive_within_plan,
        report.omitted_candidates == 0
    );
    for candidate in report.candidates {
        assert!(
            candidate
                .frames
                .iter()
                .all(|range| { range.start <= range.end && range.end <= input.len() })
        );
    }
}

fn context(session: u64, direction: Direction) -> MessageContext {
    MessageContext {
        source: "fuzz-source".to_owned(),
        scope: "fuzz-scope".to_owned(),
        session,
        direction,
    }
}
