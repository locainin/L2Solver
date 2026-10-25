#[path = "../src/replay_time.rs"]
mod replay_time;
use l2_capture::{CaptureTimestamp, TimestampResolution, TimestampSource};

const fn stamp(
    ticks: u64,
    resolution: TimestampResolution,
    offset_seconds: i64,
) -> CaptureTimestamp {
    CaptureTimestamp::new(
        ticks,
        resolution,
        offset_seconds,
        TimestampSource::CaptureFile,
    )
}

#[test]
fn timestamps_bound_offsets_and_precision() -> Result<(), l2_capture::MetadataError> {
    assert_eq!(
        replay_time::nanoseconds(stamp(1234, TimestampResolution::decimal(3)?, -1)),
        234_000_000
    );
    assert_eq!(
        replay_time::nanoseconds(stamp(3, TimestampResolution::binary(1)?, 0)),
        1_500_000_000
    );
    assert_eq!(
        replay_time::nanoseconds(stamp(u64::MAX, TimestampResolution::decimal(127)?, 0,)),
        0
    );
    assert_eq!(
        replay_time::nanoseconds(stamp(u64::MAX, TimestampResolution::binary(127)?, 0,)),
        0
    );
    assert_eq!(
        replay_time::nanoseconds(stamp(1, TimestampResolution::decimal(0)?, i64::MIN)),
        (i128::from(i64::MIN) + 1) * 1_000_000_000
    );
    Ok(())
}
