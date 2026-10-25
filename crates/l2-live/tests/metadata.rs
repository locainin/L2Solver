#[path = "../src/metadata.rs"]
mod metadata;

#[test]
fn rejects_invalid_live_timestamps() {
    assert!(metadata::timestamp(-1, 0).is_err());
    assert!(metadata::timestamp(0, -1).is_err());
    assert!(metadata::timestamp(0, 1_000_000).is_err());
}

#[test]
fn live_timestamp_preserves_microsecond_precision() -> Result<(), Box<dyn std::error::Error>> {
    let time = metadata::timestamp(1, 999_999)?;
    assert_eq!(time.ticks(), 1_999_999);
    assert_eq!(
        time.resolution(),
        l2_capture::TimestampResolution::MICROSECOND
    );
    assert!(metadata::timestamp(i64::MAX, 0).is_err());
    Ok(())
}
