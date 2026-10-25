use l2_canary::DecodeError;
use l2_segmentation::PlanError;

#[test]
fn planning_errors_keep_diagnostic_text() {
    // Error text is the only context available when planning stops before a report exists
    assert_eq!(
        PlanError::ProbeCountOverflow.to_string(),
        "planned probe count overflowed"
    );
    assert_eq!(
        PlanError::SequenceOverflow.to_string(),
        "probe sequence material overflowed"
    );
    assert_eq!(
        PlanError::NoDistinctAgentPairs {
            segment: l2_segmentation::SegmentId::new(7),
        }
        .to_string(),
        "same-segment rule SegmentId(7)->SegmentId(7) needs at least two distinct agents"
    );
    assert_eq!(
        l2_segmentation::EvaluationError::Verification(DecodeError::InvalidTag).to_string(),
        "canary observation verification failed: canary authentication tag is invalid"
    );
}
