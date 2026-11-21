#[path = "../../../../tests/fixtures/truncated_tcp.rs"]
mod fixture;

use l2_workbench::reconstruction::Reconstructor;
use std::error::Error;

#[test]
fn truncated_retransmit_conflict() -> Result<(), Box<dyn Error>> {
    let payload = b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc";
    let mut conflict = payload.to_vec();
    let body = conflict.len() - 3;
    *conflict.get_mut(body).ok_or("missing body")? = b'x';
    let mut engine = Reconstructor::new();
    engine.observe(1, &fixture::tcp(100, 2, b"", 0)?)?;
    engine.observe(2, &fixture::tcp(101, 0x18, payload, 0)?)?;
    engine.observe(3, &fixture::tcp(101, 0x18, &conflict, 8)?)?;
    engine.observe(
        4,
        &fixture::tcp(101 + u32::try_from(payload.len())?, 0x11, b"", 0)?,
    )?;
    let report = engine.finish()?;
    let stream = report
        .sessions
        .first()
        .ok_or("missing session")?
        .directions
        .first()
        .ok_or("missing stream")?;
    let coverage = stream.coverage.as_ref().ok_or("missing coverage")?;
    assert_eq!(coverage.conflicting_bytes, 1);
    assert_eq!(coverage.missing_bytes, 8);
    assert!(coverage.omitted_bytes >= 8);
    assert!(!report.complete);
    assert!(stream.origins.iter().any(|origin| {
        origin.packet == 3 && origin.frame_offset == 54 && origin.length == conflict.len()
    }));
    Ok(())
}

#[test]
fn truncated_tcp_header_marks_tuple_uncertain() -> Result<(), Box<dyn Error>> {
    let partial = fixture::tcp(101, 0x18, b"payload", 0)?;
    let partial = l2_capture::CapturedFrame::new(
        partial
            .bytes()
            .get(..38)
            .ok_or("missing TCP ports")?
            .to_vec(),
        partial.metadata().clone(),
    )?;
    let mut engine = Reconstructor::new();
    engine.observe(1, &fixture::tcp(100, 2, b"", 0)?)?;
    engine.observe(2, &fixture::tcp(101, 0x18, b"payload", 0)?)?;
    engine.observe(3, &partial)?;
    let report = engine.finish()?;
    let session = report.sessions.first().ok_or("missing session")?;
    assert!(session.generation_ambiguous);
    assert!(!report.complete);
    Ok(())
}

#[test]
fn truncated_header_leaves_other_tuple() -> Result<(), Box<dyn Error>> {
    let partial = fixture::tcp(101, 0x18, b"payload", 0)?;
    let partial = l2_capture::CapturedFrame::new(
        partial
            .bytes()
            .get(..38)
            .ok_or("missing TCP ports")?
            .to_vec(),
        partial.metadata().clone(),
    )?;
    let mut engine = Reconstructor::new();
    engine.observe(1, &fixture::tcp(100, 2, b"", 0)?)?;
    engine.observe(
        2,
        &super::support::tcp_ports(false, (40_001, 9_000), 100, 2, b"")?,
    )?;
    engine.observe(3, &partial)?;
    let report = engine.finish()?;
    assert_eq!(report.sessions.len(), 2);
    let affected = report
        .sessions
        .iter()
        .find(|session| session.endpoints.iter().any(|end| end.port == 40_000))
        .ok_or("missing affected tuple")?;
    let other = report
        .sessions
        .iter()
        .find(|session| session.endpoints.iter().any(|end| end.port == 40_001))
        .ok_or("missing other tuple")?;
    assert!(affected.generation_ambiguous);
    assert!(!other.generation_ambiguous);
    Ok(())
}

#[test]
fn truncated_tail_remains_unresolved() -> Result<(), Box<dyn Error>> {
    let mut engine = Reconstructor::new();
    engine.observe(1, &fixture::tcp(100, 2, b"", 0)?)?;
    engine.observe(2, &fixture::tcp(101, 0x18, b"abc", 2)?)?;
    engine.observe(3, &fixture::tcp(101, 0x18, b"abcde", 0)?)?;
    let report = engine.finish()?;
    let stream = report
        .sessions
        .first()
        .ok_or("missing session")?
        .directions
        .first()
        .ok_or("missing stream")?;
    let coverage = stream.coverage.as_ref().ok_or("missing coverage")?;
    assert_eq!(coverage.missing_bytes, 0);
    assert_eq!(coverage.omitted_bytes, 2);
    assert!(!coverage.unique());
    assert!(!report.complete);
    assert_eq!(
        stream.runs().first().map(|run| run.bytes),
        Some(b"abc".as_slice())
    );
    Ok(())
}
