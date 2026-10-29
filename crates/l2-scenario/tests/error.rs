use l2_scenario::{AdmissionError, RunError};

#[test]
fn errors_describe_the_reason_the_caller_cannot_proceed() {
    // Diagnostics identify the specific budget or scheduling problem
    assert!(AdmissionError::PacketLimit.to_string().contains("packet"));
    assert!(AdmissionError::ByteLimit.to_string().contains("byte"));
    assert!(
        AdmissionError::DurationLimit
            .to_string()
            .contains("duration")
    );
    assert!(
        AdmissionError::DuplicateSequence
            .to_string()
            .contains("duplicat")
    );
    assert!(RunError::StillRunning.to_string().contains("running"));
}
