use l2_workbench::tcp_range::{
    MAX_OBSERVATIONS, MAX_RANGE_BYTES, MAX_RETAINED_BYTES, Segment, SpanStatus, TcpRange,
};
use std::error::Error;

const fn segment(sequence: u32, flags: u8, payload: &[u8]) -> Segment<'_> {
    Segment {
        packet_index: 1,
        payload_frame_offset: 54,
        sequence,
        flags,
        payload,
    }
}

#[test]
fn reordered_segments_recover_range() -> Result<(), Box<dyn Error>> {
    let mut range = TcpRange::new(100, 6)?;
    assert!(range.observe(segment(103, 0x10, b"def"))?);
    assert!(range.observe(segment(100, 0x10, b"abc"))?);
    let report = range.finish();
    assert_eq!(report.observed_bytes, 6);
    assert_eq!(report.missing_bytes, 0);
    assert_eq!(report.conflicting_bytes, 0);
    assert!(report.has_unique_coverage());
    assert_eq!(report.spans.len(), 1);
    assert_eq!(
        report.spans.first().map(|span| span.status),
        Some(SpanStatus::Observed)
    );
    assert_eq!(
        report.spans.first().and_then(|span| span.bytes.as_deref()),
        Some(b"abcdef".as_slice())
    );
    Ok(())
}

#[test]
fn identical_overlap_preserves_observations() -> Result<(), Box<dyn Error>> {
    let mut range = TcpRange::new(10, 4)?;
    range.observe(segment(10, 0x10, b"abcd"))?;
    range.observe(Segment {
        packet_index: 2,
        ..segment(11, 0x10, b"bc")
    })?;
    let report = range.finish();
    assert_eq!(report.observations.len(), 2);
    assert_eq!(report.conflicting_bytes, 0);
    assert!(report.has_unique_coverage());
    Ok(())
}

#[test]
fn conflicting_overlap_has_no_winner() -> Result<(), Box<dyn Error>> {
    let mut range = TcpRange::new(10, 4)?;
    range.observe(segment(10, 0x10, b"abcd"))?;
    range.observe(Segment {
        packet_index: 2,
        ..segment(11, 0x10, b"XY")
    })?;
    let report = range.finish();
    assert_eq!(report.conflicting_bytes, 2);
    assert_eq!(report.observed_bytes, 2);
    assert!(!report.has_unique_coverage());
    let conflict = report.spans.get(1).ok_or("missing conflicting span")?;
    assert_eq!(
        (conflict.offset, conflict.length, conflict.status),
        (1, 2, SpanStatus::Conflict)
    );
    assert!(conflict.bytes.is_none());
    assert_eq!(
        report
            .observations
            .get(1)
            .map(|observation| observation.bytes.as_slice()),
        Some(b"XY".as_slice())
    );
    Ok(())
}

#[test]
fn gaps_include_fin_position() -> Result<(), Box<dyn Error>> {
    let mut range = TcpRange::new(20, 5)?;
    range.observe(segment(21, 0x11, b"ab"))?;
    let report = range.finish();
    assert_eq!(report.missing_bytes, 3);
    assert_eq!(report.spans.len(), 3);
    assert_eq!(
        report.spans.first().map(|span| (span.status, span.length)),
        Some((SpanStatus::Gap, 1))
    );
    assert_eq!(
        report.spans.last().map(|span| (span.status, span.length)),
        Some((SpanStatus::Gap, 2))
    );
    assert!(!report.has_unique_coverage());
    Ok(())
}

#[test]
fn syn_consumes_sequence_space() -> Result<(), Box<dyn Error>> {
    let mut range = TcpRange::new(101, 3)?;
    range.observe(segment(100, 0x02, b"abc"))?;
    let report = range.finish();
    assert!(report.has_unique_coverage());
    assert_eq!(
        report
            .observations
            .first()
            .map(|observation| observation.range_offset),
        Some(0)
    );
    Ok(())
}

#[test]
fn segments_cross_sequence_wrap() -> Result<(), Box<dyn Error>> {
    let mut range = TcpRange::new(u32::MAX - 1, 5)?;
    range.observe(segment(0, 0x10, b"cde"))?;
    range.observe(segment(u32::MAX - 2, 0x10, b"zab"))?;
    let report = range.finish();
    assert!(report.has_unique_coverage());
    assert_eq!(
        report.spans.first().and_then(|span| span.bytes.as_deref()),
        Some(b"abcde".as_slice())
    );
    let clipped = report
        .observations
        .get(1)
        .ok_or("missing clipped observation")?;
    assert_eq!(clipped.payload_frame_offset, 55);
    assert_eq!(clipped.bytes, b"ab");
    Ok(())
}

#[test]
fn segments_clip_to_range_boundaries() -> Result<(), Box<dyn Error>> {
    let mut range = TcpRange::new(102, 3)?;
    range.observe(segment(100, 0x10, b"xxabczz"))?;
    let report = range.finish();
    let observation = report.observations.first().ok_or("missing observation")?;
    assert_eq!(observation.bytes, b"abc");
    assert_eq!(observation.payload_frame_offset, 56);
    assert!(report.has_unique_coverage());
    Ok(())
}

#[test]
fn left_clipping_preserves_trailing_gap() -> Result<(), Box<dyn Error>> {
    let mut range = TcpRange::new(100, 4)?;
    range.observe(segment(98, 0x10, b"xxabc"))?;
    let report = range.finish();
    let observation = report.observations.first().ok_or("missing observation")?;
    assert_eq!(observation.bytes, b"abc");
    assert_eq!(observation.range_offset, 0);
    assert_eq!(observation.payload_frame_offset, 56);
    assert_eq!(report.observed_bytes, 3);
    assert_eq!(report.missing_bytes, 1);
    Ok(())
}

#[test]
fn segments_clip_at_range_end() -> Result<(), Box<dyn Error>> {
    let mut range = TcpRange::new(100, 4)?;
    range.observe(segment(102, 0x10, b"abcdef"))?;
    let report = range.finish();
    let observation = report.observations.first().ok_or("missing observation")?;
    assert_eq!(observation.bytes, b"ab");
    assert_eq!(observation.range_offset, 2);
    assert_eq!(observation.payload_frame_offset, 54);
    assert_eq!(report.observed_bytes, 2);
    assert_eq!(report.missing_bytes, 2);
    Ok(())
}

#[test]
fn outside_segments_skip_budget() -> Result<(), Box<dyn Error>> {
    let mut range = TcpRange::new(100, 3)?;
    for sequence in [0, 97, 103, 1_u32 << 31, u32::MAX] {
        assert!(!range.observe(segment(sequence, 0x10, b"abc"))?);
    }
    let report = range.finish();
    assert!(report.observations.is_empty());
    assert_eq!(report.omitted_observations, 0);
    Ok(())
}

#[test]
fn control_flags_without_payload() -> Result<(), Box<dyn Error>> {
    let mut range = TcpRange::new(0, 1)?;
    for flags in [0x02, 0x01, 0x04] {
        assert!(range.observe(segment(999, flags, &[]))?);
    }
    assert!(!range.observe(segment(999, 0x10, &[]))?);
    let report = range.finish();
    assert_eq!(report.observations.len(), 3);
    assert_eq!(report.missing_bytes, 1);
    assert!(
        report
            .observations
            .iter()
            .all(|observation| observation.bytes.is_empty())
    );
    Ok(())
}

#[test]
fn omissions_mark_coverage_incomplete() -> Result<(), Box<dyn Error>> {
    let mut range = TcpRange::new(100, 1)?;
    for _ in 0..MAX_OBSERVATIONS {
        assert!(range.observe(segment(100, 0x10, b"a"))?);
    }
    assert!(!range.observe(segment(100, 0x10, b"X"))?);
    let report = range.finish();
    assert_eq!(report.observations.len(), MAX_OBSERVATIONS);
    assert_eq!(report.omitted_observations, 1);
    assert_eq!(report.observed_bytes, 1);
    assert_eq!(report.omitted_bytes, 1);
    assert!(
        report
            .spans
            .first()
            .is_some_and(|span| span.omitted_observation)
    );
    assert!(!report.has_unique_coverage());
    Ok(())
}

#[test]
fn custom_budget_exceeds_default() -> Result<(), Box<dyn Error>> {
    let mut range = TcpRange::new_with_limits(100, 1, 2, 2)?;
    assert!(range.observe(segment(100, 0x10, b"a"))?);
    assert!(range.observe(Segment {
        packet_index: 2,
        ..segment(100, 0x10, b"a")
    })?);

    let report = range.finish();

    assert_eq!(report.observations.len(), 2);
    assert_eq!(report.omitted_observations, 0);
    assert_eq!(report.observed_bytes, 1);
    Ok(())
}

#[test]
fn omitted_coverage_range_freezes_retention() -> Result<(), Box<dyn Error>> {
    let mut range = TcpRange::new(100, 3)?;
    for _ in 0..MAX_OBSERVATIONS {
        range.observe(segment(100, 0x10, b"a"))?;
    }
    range.observe(segment(101, 0x10, b"b"))?;
    range.observe(segment(102, 0x10, b"c"))?;
    let report = range.finish();
    assert_eq!(report.omitted_observations, 2);
    assert_eq!(report.omitted_bytes, 2);
    assert_eq!(report.missing_bytes, 2);
    assert_eq!(report.observations.len(), MAX_OBSERVATIONS);
    let gap = report.spans.last().ok_or("missing gap")?;
    assert_eq!(
        (gap.offset, gap.length, gap.omitted_observation),
        (1, 2, true)
    );
    Ok(())
}

#[test]
fn retained_byte_shared_across_retransmissions() -> Result<(), Box<dyn Error>> {
    let bytes = vec![0x41; 65_535];
    let mut range = TcpRange::new(0, bytes.len())?;
    let allowed = MAX_RETAINED_BYTES / bytes.len();
    for _ in 0..allowed {
        assert!(range.observe(segment(0, 0x10, &bytes))?);
    }
    assert!(!range.observe(segment(0, 0x10, &bytes))?);
    let report = range.finish();
    assert_eq!(report.observations.len(), allowed);
    assert_eq!(report.omitted_observations, 1);
    assert!(!report.has_unique_coverage());
    Ok(())
}

#[test]
fn clipped_payloads_respect_retention_budget() -> Result<(), Box<dyn Error>> {
    let bytes = vec![0x41; 65_535];
    let mut range = TcpRange::new(32_768, 65_535)?;
    let overlap = bytes.len() - 32_768;
    let allowed = MAX_RETAINED_BYTES / overlap;
    for _ in 0..allowed {
        assert!(range.observe(segment(0, 0x10, &bytes))?);
    }
    assert!(!range.observe(segment(0, 0x10, &bytes))?);
    let report = range.finish();
    assert_eq!(report.observations.len(), allowed);
    assert_eq!(report.observed_bytes, overlap);
    assert_eq!(report.missing_bytes, 32_768);
    assert_eq!(report.omitted_observations, 1);
    Ok(())
}

#[test]
fn range_rejects_invalid_inputs() -> Result<(), Box<dyn Error>> {
    assert!(TcpRange::new(0, 0).is_err());
    assert!(TcpRange::new(0, MAX_RANGE_BYTES + 1).is_err());
    let mut range = TcpRange::new(0, 1)?;
    assert!(range.observe(segment(0, 0x10, &vec![0; 65_536])).is_err());
    assert!(
        range
            .observe(Segment {
                payload_frame_offset: usize::MAX,
                ..segment(0, 0x10, b"ab")
            })
            .is_err()
    );
    Ok(())
}

#[test]
fn range_supports_large_lengths() -> Result<(), Box<dyn Error>> {
    let mut range = TcpRange::new(100, 100_000)?;
    range.observe(segment(90_100, 0x10, b"end"))?;
    let report = range.finish();
    assert_eq!(report.observed_bytes, 3);
    assert_eq!(report.missing_bytes, 99_997);
    assert_eq!(
        report.observations.first().map(|value| value.range_offset),
        Some(90_000)
    );
    Ok(())
}
