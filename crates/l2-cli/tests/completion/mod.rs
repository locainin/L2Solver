use crate::completion;

#[test]
fn errors_and_drops_block_completion() {
    assert!(completion::complete(0, 0, 0, 0, [0, 0]));
    for (malformed, invalid, unsupported, truncated, drops) in [
        (1, 0, 0, 0, [0, 0]),
        (0, 1, 0, 0, [0, 0]),
        (0, 0, 1, 0, [0, 0]),
        (0, 0, 0, 1, [0, 0]),
        (0, 0, 0, 0, [1, 0]),
        (0, 0, 0, 0, [0, 1]),
        (u64::MAX, u64::MAX, u64::MAX, u64::MAX, [u32::MAX, u32::MAX]),
    ] {
        assert!(!completion::complete(
            malformed,
            invalid,
            unsupported,
            truncated,
            drops
        ));
    }
}

#[cfg(feature = "live")]
#[test]
fn requires_operator_stop_reason() {
    use completion::LiveCaptureQuality;
    use l2_live::StopReason;
    let packets =
        LiveCaptureQuality::authoritative_for_test(Some(StopReason::PacketLimit), false, 0, 0, 0);
    let duration =
        LiveCaptureQuality::authoritative_for_test(Some(StopReason::Deadline), true, 0, 0, 0);
    assert!(completion::complete_live(0, 0, 0, 0, &packets,));
    assert!(completion::complete_live(0, 0, 0, 0, &duration,));
    let wrong_deadline =
        LiveCaptureQuality::authoritative_for_test(Some(StopReason::Deadline), false, 0, 0, 0);
    assert!(!completion::complete_live(0, 0, 0, 0, &wrong_deadline,));
    let wrong_packets =
        LiveCaptureQuality::authoritative_for_test(Some(StopReason::PacketLimit), true, 0, 0, 0);
    assert!(!completion::complete_live(0, 0, 0, 0, &wrong_packets,));
    let missing = LiveCaptureQuality::authoritative_for_test(None, true, 0, 0, 0);
    assert!(!completion::complete_live(0, 0, 0, 0, &missing));
    assert!(!completion::complete_live(1, 0, 0, 0, &packets,));
}

#[cfg(feature = "live")]
#[test]
fn reported_zero_not_loss_free() {
    let quality = completion::LiveCaptureQuality::reported_for_test(
        completion::LiveStopReason::PacketLimit,
        completion::LiveGoal::Packets,
        17,
        0,
        0,
    );

    assert!(!quality.loss_counters_authoritative());
    assert!(!completion::complete_live(0, 0, 0, 0, &quality));
}
