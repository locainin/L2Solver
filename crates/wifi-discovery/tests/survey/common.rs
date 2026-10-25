use wifi_discovery::{ObservationContext, ObservationStatus, Survey, WirelessInput};

// The two addresses are reused across frame fixtures and inventory assertions
pub const AP: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
pub const STATION: [u8; 6] = [0x02, 0, 0, 0, 0, 2];

// Test timestamps make sequence ordering visible without repeating conversion logic
pub const fn context(sequence: u64) -> ObservationContext {
    ObservationContext::new(sequence, sequence.saturating_mul(1_000))
}

// Keep status failures pointed at the test that supplied the wire input
#[track_caller]
pub fn assert_status(
    survey: &mut Survey,
    input: WirelessInput<'_>,
    sequence: u64,
    expected: ObservationStatus,
) {
    assert_eq!(survey.observe(input, context(sequence)), expected);
}
