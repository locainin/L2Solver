#[path = "reconstruction/handshake.rs"]
mod handshake;
#[path = "reconstruction/limits.rs"]
mod limits;
#[path = "reconstruction/review.rs"]
mod review;
#[path = "reconstruction/selected.rs"]
mod selected;
#[path = "reconstruction/support.rs"]
mod support;
#[path = "reconstruction/workflow.rs"]
mod workflow;

use l2_workbench::reconstruction::{Coverage, InputSelection, Limits, Reconstructor};
use support::{fragment, frame, tcp};

#[test]
fn reordered_tcp_reconstructs_stream() -> Result<(), Box<dyn std::error::Error>> {
    let mut engine = Reconstructor::new();
    engine.observe(1, &tcp(false, 100, 0x02, b"")?)?;
    engine.observe(2, &tcp(false, 104, 0x10, b"def")?)?;
    engine.observe(3, &tcp(false, 101, 0x10, b"abc")?)?;
    engine.observe(4, &tcp(false, 107, 0x11, b"")?)?;
    let report = engine.finish()?;
    assert_eq!(
        report
            .sessions
            .first()
            .and_then(|session| session.initiator.as_ref())
            .map(|endpoint| endpoint.port),
        Some(40000)
    );
    let stream = report
        .sessions
        .first()
        .and_then(|session| session.directions.first())
        .ok_or("missing stream")?;
    assert!(stream.start_known);
    assert!(stream.end_observed);
    assert_eq!(
        stream.runs().first().map(|run| run.bytes),
        Some(b"abcdef".as_slice())
    );
    assert!(stream.coverage.as_ref().is_some_and(Coverage::unique));
    Ok(())
}

#[test]
fn bare_acknowledgements_not_payload_coverage() -> Result<(), Box<dyn std::error::Error>> {
    let mut engine = Reconstructor::new();
    engine.observe(1, &tcp(false, 100, 2, b"")?)?;
    engine.observe(2, &tcp(false, 101, 0x10, b"abc")?)?;
    engine.observe(3, &tcp(false, 10000, 0x10, b"")?)?;
    let report = engine.finish()?;
    assert_eq!(
        report
            .sessions
            .first()
            .and_then(|session| session.directions.first())
            .and_then(|stream| stream.coverage.as_ref())
            .map(|coverage| coverage.length),
        Some(3)
    );
    Ok(())
}

#[test]
fn sequence_limit_reports_omission() -> Result<(), Box<dyn std::error::Error>> {
    let mut engine = Reconstructor::with_limits(Limits {
        range_bytes: 4,
        ..Limits::default()
    })?;
    engine.observe(1, &tcp(false, 100, 2, b"")?)?;
    engine.observe(2, &tcp(false, 101, 0x10, b"abcde")?)?;
    let report = engine.finish()?;
    assert!(!report.complete);
    assert_eq!(report.omitted_ranges, 1);
    assert!(
        report
            .sessions
            .first()
            .and_then(|session| session.directions.first())
            .is_some_and(|stream| stream.coverage.is_none() && stream.sequence_ambiguous)
    );
    Ok(())
}

#[test]
fn reconstruction_rejects_gapped_records() -> Result<(), Box<dyn std::error::Error>> {
    let mut engine = Reconstructor::new();
    let packet = tcp(false, 100, 2, b"")?;
    assert!(engine.observe(0, &packet).is_err());
    engine.observe(1, &packet)?;
    assert!(engine.observe(3, &packet).is_err());
    engine.observe(2, &packet)?;
    let report = engine.finish()?;
    assert_eq!(report.frames, 2);
    assert_eq!(
        report.input_selection,
        Some(InputSelection::ConsecutiveRecords)
    );
    Ok(())
}

#[test]
fn tcp_conflicts_separate_artifacts() -> Result<(), Box<dyn std::error::Error>> {
    let mut engine = Reconstructor::new();
    engine.observe(1, &tcp(false, 100, 0x02, b"")?)?;
    engine.observe(2, &tcp(false, 101, 0x10, b"abc")?)?;
    engine.observe(3, &tcp(false, 102, 0x10, b"X")?)?;
    engine.observe(4, &tcp(false, 106, 0x11, b"f")?)?;
    let report = engine.finish()?;
    let stream = report
        .sessions
        .first()
        .and_then(|session| session.directions.first())
        .ok_or("missing stream")?;
    let coverage = stream.coverage.as_ref().ok_or("missing coverage")?;
    assert_eq!(coverage.conflicting_bytes, 1);
    assert_eq!(coverage.missing_bytes, 2);
    assert_eq!(stream.runs().len(), 3);
    assert!(!coverage.unique());
    Ok(())
}

#[test]
fn tuple_reuse_preserves_generation_ambiguity() -> Result<(), Box<dyn std::error::Error>> {
    let mut engine = Reconstructor::new();
    engine.observe(1, &tcp(false, 100, 0x02, b"")?)?;
    engine.observe(2, &tcp(false, 101, 0x11, b"old")?)?;
    engine.observe(3, &tcp(false, 900, 0x02, b"")?)?;
    engine.observe(4, &tcp(false, 901, 0x10, b"new")?)?;
    let report = engine.finish()?;
    assert_eq!(report.sessions.len(), 2);
    assert!(
        report
            .sessions
            .iter()
            .all(|session| session.generation_ambiguous)
    );
    Ok(())
}

#[test]
fn fragment_recovery_preserves_source_ranges() -> Result<(), Box<dyn std::error::Error>> {
    let mut engine = Reconstructor::new();
    engine.observe(
        1,
        &fragment(0x2000, &[0x9c, 0x40, 0x23, 0x45, 0, 14, 0, 0])?,
    )?;
    engine.observe(2, &fragment(1, b"abcdef")?)?;
    let report = engine.finish()?;
    assert!(report.datagrams.first().is_some_and(|item| item.complete));
    let message = report.udp.first().ok_or("missing recovered UDP")?;
    assert_eq!(message.bytes, b"abcdef");
    assert_eq!(
        message
            .origins
            .first()
            .map(|origin| (origin.packet, origin.frame_offset, origin.length)),
        Some((2, 34, 6))
    );
    Ok(())
}

#[test]
fn fragment_overlap_prevents_transport_recovery() -> Result<(), Box<dyn std::error::Error>> {
    let mut engine = Reconstructor::new();
    engine.observe(
        1,
        &fragment(0x2000, &[0x9c, 0x40, 0x23, 0x45, 0, 14, 0, 0])?,
    )?;
    engine.observe(2, &fragment(1, b"abcdef")?)?;
    engine.observe(3, &fragment(1, b"Xbcdef")?)?;
    let report = engine.finish()?;
    assert!(!report.datagrams.first().is_some_and(|item| item.complete));
    assert!(report.udp.is_empty());
    Ok(())
}

#[test]
fn scope_quota_prevents_unobserved_joins() -> Result<(), Box<dyn std::error::Error>> {
    let mut engine = Reconstructor::with_limits(Limits {
        frames: 2,
        ..Limits::default()
    })?;
    engine.observe(1, &frame(0, &tcp(false, 100, 0x02, b"")?)?)?;
    engine.observe(2, &frame(1, &tcp(false, 101, 0x10, b"abc")?)?)?;
    engine.observe(3, &tcp(false, 104, 0x11, b"")?)?;
    let report = engine.finish()?;
    assert_eq!(report.sessions.len(), 2);
    assert_eq!(report.omitted_frames, 1);
    assert!(!report.complete);
    Ok(())
}

#[test]
fn repeated_syn_candidate_episode() -> Result<(), Box<dyn std::error::Error>> {
    let mut engine = Reconstructor::new();
    for number in 1..=4 {
        engine.observe(number, &tcp(false, 100, 2, b"")?)?;
    }
    engine.observe(5, &tcp(false, 101, 0x10, b"abc")?)?;
    let report = engine.finish()?;
    assert_eq!(report.sessions.len(), 1);
    assert!(
        !report
            .sessions
            .first()
            .is_some_and(|session| session.generation_ambiguous)
    );
    Ok(())
}
