use super::support::{fragment, frame, tcp};
use l2_workbench::reconstruction::{Limits, ReconstructionReport, Reconstructor};
use std::error::Error;

#[test]
fn tcp_observation_global_reconstruction_incomplete() -> Result<(), Box<dyn Error>> {
    let mut engine = Reconstructor::new();
    engine.observe(1, &tcp(false, 100, 2, b"")?)?;
    for offset in 0..u32::try_from(l2_workbench::tcp_range::MAX_OBSERVATIONS)? {
        engine.observe(offset + 2, &tcp(false, 101 + offset, 0x10, b"X")?)?;
    }
    let report = engine.finish()?;
    let coverage = report
        .sessions
        .first()
        .and_then(|session| session.directions.first())
        .and_then(|stream| stream.coverage.as_ref())
        .ok_or("missing coverage")?;
    assert_eq!(coverage.omitted_observations, 1);
    assert!(!report.complete);
    assert_eq!(report.omitted_ranges, 1);
    assert_eq!(report.omitted_tcp_bytes, 1);
    assert_eq!(report.omitted_tcp_observations, 1);
    Ok(())
}

#[test]
fn fragment_observation_global_reconstruction_incomplete() -> Result<(), Box<dyn Error>> {
    let mut engine = Reconstructor::new();
    let header = fragment(0x2000, &[0x9c, 0x40, 0x23, 0x45, 0, 14, 0, 0])?;
    for packet in 1..=u32::try_from(l2_workbench::tcp_range::MAX_OBSERVATIONS)? {
        engine.observe(packet, &header)?;
    }
    engine.observe(
        u32::try_from(l2_workbench::tcp_range::MAX_OBSERVATIONS)? + 1,
        &fragment(1, b"abcdef")?,
    )?;
    let report = engine.finish()?;
    assert!(!report.complete);
    assert_eq!(report.omitted_ranges, 1);
    assert_eq!(report.omitted_fragment_bytes, 6);
    assert_eq!(report.omitted_fragment_observations, 1);
    assert!(report.udp.is_empty());
    Ok(())
}

fn fragmented_udp_report() -> Result<ReconstructionReport, Box<dyn Error>> {
    let mut reconstructor = Reconstructor::new();
    reconstructor.observe(
        1,
        &fragment(0x2000, &[0x9c, 0x40, 0x23, 0x45, 0, 14, 0, 0])?,
    )?;
    reconstructor.observe(2, &fragment(1, b"abcdef")?)?;
    Ok(reconstructor.finish()?)
}

#[test]
fn clipped_payload_not_fragment_provenance() -> Result<(), Box<dyn Error>> {
    let report = fragmented_udp_report()?;
    let message = report.udp.first().ok_or("missing recovered UDP")?;

    assert_eq!(message.fragment_candidate, Some(0));
    assert_eq!(message.bytes, b"abcdef");
    assert_eq!(message.origins.len(), 1);
    Ok(())
}

#[test]
fn complete_fragment_identity_ambiguous_candidate() -> Result<(), Box<dyn Error>> {
    let report = fragmented_udp_report()?;
    let datagram = report
        .datagrams
        .first()
        .ok_or("missing fragment datagram")?;

    assert!(datagram.complete);
    assert!(datagram.identity_ambiguous);
    Ok(())
}

#[test]
fn tcp_episode_without_generation_ambiguous() -> Result<(), Box<dyn Error>> {
    let mut reconstructor = Reconstructor::new();
    reconstructor.observe(1, &tcp(false, 500, 0x10, b"payload")?)?;
    let report = reconstructor.finish()?;
    let session = report.sessions.first().ok_or("missing TCP episode")?;

    assert!(session.generation_ambiguous);
    assert!(
        session
            .directions
            .first()
            .is_some_and(|direction| !direction.start_known)
    );
    Ok(())
}

#[test]
fn same_sequence_new_ambiguous_generation() -> Result<(), Box<dyn Error>> {
    let mut reconstructor = Reconstructor::new();
    reconstructor.observe(1, &tcp(false, 100, 0x02, b"")?)?;
    reconstructor.observe(2, &tcp(false, 101, 0x10, b"old")?)?;
    reconstructor.observe(3, &tcp(false, 104, 0x11, b"")?)?;
    reconstructor.observe(4, &tcp(false, 100, 0x02, b"")?)?;
    reconstructor.observe(5, &tcp(false, 101, 0x10, b"new")?)?;
    let report = reconstructor.finish()?;

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
fn opposite_direction_new_ambiguous_generation() -> Result<(), Box<dyn Error>> {
    let mut reconstructor = Reconstructor::new();
    reconstructor.observe(1, &tcp(true, 500, 0x10, b"observed")?)?;
    reconstructor.observe(2, &tcp(false, 100, 0x02, b"")?)?;
    let report = reconstructor.finish()?;

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
fn session_limit_counts_each_skipped_tcp_record() -> Result<(), Box<dyn Error>> {
    let mut reconstructor = Reconstructor::with_limits(Limits {
        sessions: 1,
        ..Limits::default()
    })?;
    reconstructor.observe(1, &tcp(false, 100, 0x02, b"")?)?;
    reconstructor.observe(2, &tcp(false, 101, 0x10, b"first")?)?;
    reconstructor.observe(3, &tcp(false, 500, 0x02, b"")?)?;
    reconstructor.observe(4, &tcp(false, 501, 0x10, b"later")?)?;
    let report = reconstructor.finish()?;
    let direction = report
        .sessions
        .first()
        .and_then(|session| session.directions.first())
        .ok_or("missing retained TCP episode")?;

    assert_eq!(report.omitted_tcp_records, 2);
    assert_eq!(direction.packets, [1, 2]);
    Ok(())
}

#[test]
fn datagram_limit_fragment_skipped_candidate() -> Result<(), Box<dyn Error>> {
    let mut reconstructor = Reconstructor::with_limits(Limits {
        datagrams: 1,
        ..Limits::default()
    })?;
    let first_candidate_header = fragment(0x2000, &[0x9c, 0x40, 0x23, 0x45, 0, 15, 0, 0])?;
    let first_candidate_tail = fragment(1, b"first!!")?;
    let skipped_candidate_header = frame(
        1,
        &fragment(0x2000, &[0x9c, 0x41, 0x23, 0x46, 0, 15, 0, 0])?,
    )?;
    let skipped_candidate_tail = frame(1, &fragment(1, b"second!")?)?;

    reconstructor.observe(1, &first_candidate_header)?;
    reconstructor.observe(2, &first_candidate_tail)?;
    reconstructor.observe(3, &skipped_candidate_header)?;
    reconstructor.observe(4, &skipped_candidate_tail)?;
    let report = reconstructor.finish()?;

    assert_eq!(report.datagrams.len(), 1);
    assert_eq!(report.omitted_fragments, 2);
    assert!(!report.complete);
    Ok(())
}
