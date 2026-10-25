use super::support;
use l2_workbench::reconstruction::{Limits, Reconstructor};

#[test]
fn limits_exceed_legacy_default_ceilings() {
    let defaults = Limits::default();
    let expanded = Limits {
        frames: defaults.frames + 1,
        bytes: defaults.bytes + 1,
        units: defaults.units + 1,
        sessions: defaults.sessions + 1,
        datagrams: defaults.datagrams + 1,
        range_bytes: defaults.range_bytes + 1,
        range_observations: defaults.range_observations + 1,
        range_retained_bytes: defaults.range_retained_bytes + 1,
    };

    assert!(Reconstructor::with_limits(expanded).is_ok());
}

#[test]
fn reconstruction_limits_still_zero_budgets() {
    let limits = Limits {
        bytes: 0,
        ..Limits::default()
    };

    assert!(Reconstructor::with_limits(limits).is_err());
}

#[test]
fn large_operator_tcp_extent() -> Result<(), Box<dyn std::error::Error>> {
    const EXTENT: usize = 1_100_000;
    let limits = Limits {
        range_bytes: EXTENT + 1,
        ..Limits::default()
    };
    let mut reconstructor = Reconstructor::with_limits(limits)?;
    reconstructor.observe(1, &support::tcp(false, 100, 0x02, b"")?)?;
    let sequence = 101_u32 + u32::try_from(EXTENT - 1)?;
    reconstructor.observe(2, &support::tcp(false, sequence, 0x10, b"x")?)?;

    let report = reconstructor.finish()?;
    let coverage = report
        .sessions
        .first()
        .and_then(|session| session.directions.first())
        .and_then(|stream| stream.coverage.as_ref())
        .ok_or("large TCP range was not retained")?;

    assert_eq!(coverage.length, EXTENT);
    assert_eq!(coverage.observed_bytes, 1);
    assert_eq!(coverage.missing_bytes, EXTENT - 1);
    Ok(())
}

#[test]
fn rejected_tcp_range_reports_its_extent_and_unmeasured_observations()
-> Result<(), Box<dyn std::error::Error>> {
    let limits = Limits {
        range_bytes: 1,
        ..Limits::default()
    };
    let payload = b"payload";
    let mut reconstructor = Reconstructor::with_limits(limits)?;
    reconstructor.observe(1, &support::tcp(false, 100, 0x02, b"")?)?;
    reconstructor.observe(2, &support::tcp(false, 101, 0x10, payload)?)?;

    let report = reconstructor.finish()?;

    assert_eq!(report.omitted_ranges, 1);
    assert_eq!(report.omitted_tcp_bytes, u64::try_from(payload.len())?);
    assert_eq!(report.omitted_tcp_observations, 0);
    assert_eq!(report.unmeasured_omitted_ranges, 1);
    Ok(())
}

#[test]
fn rejected_fragment_range_reports_its_extent_and_unmeasured_observations()
-> Result<(), Box<dyn std::error::Error>> {
    let limits = Limits {
        range_bytes: 1,
        ..Limits::default()
    };
    let mut reconstructor = Reconstructor::with_limits(limits)?;
    reconstructor.observe(
        1,
        &support::fragment(0x2000, &[0x9c, 0x40, 0x23, 0x45, 0, 14, 0, 0])?,
    )?;
    reconstructor.observe(2, &support::fragment(1, b"abcdef")?)?;

    let report = reconstructor.finish()?;

    assert_eq!(report.omitted_ranges, 1);
    assert_eq!(report.omitted_fragment_bytes, 14);
    assert_eq!(report.omitted_fragment_observations, 0);
    assert_eq!(report.unmeasured_omitted_ranges, 1);
    Ok(())
}

#[test]
fn operator_range_reaches_tcp_assembler() -> Result<(), Box<dyn std::error::Error>> {
    let limits = Limits {
        range_observations: l2_workbench::tcp_range::MAX_OBSERVATIONS + 1,
        ..Limits::default()
    };
    let mut reconstructor = Reconstructor::with_limits(limits)?;
    reconstructor.observe(1, &support::tcp(false, 100, 0x02, b"")?)?;
    for offset in 0..u32::try_from(l2_workbench::tcp_range::MAX_OBSERVATIONS)? {
        reconstructor.observe(offset + 2, &support::tcp(false, 101 + offset, 0x10, b"X")?)?;
    }

    let report = reconstructor.finish()?;
    let coverage = report
        .sessions
        .first()
        .and_then(|session| session.directions.first())
        .and_then(|stream| stream.coverage.as_ref())
        .ok_or("TCP range coverage was not retained")?;

    assert_eq!(
        coverage.observed_bytes,
        l2_workbench::tcp_range::MAX_OBSERVATIONS
    );
    assert_eq!(coverage.omitted_observations, 0);
    assert!(report.complete);
    Ok(())
}
