use super::support::*;
use l2_audit::{ResourceLimit, Survey, SurveyLimits, TrailingProtocol};
use l2_capture::FcsStatus;

const UDP_TRAILER: [u8; 4] = [0, 0x55, 0xaa, 0];

fn ipv4_udp_with_trailer(
    udp_length: u16,
    fragmented: bool,
    outer_padding: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let mut bytes = traffic(SECOND_MAC, ADDRESS);
    bytes
        .get_mut(16..18)
        .ok_or("short Ethernet/IPv4 fixture")?
        .copy_from_slice(&32_u16.to_be_bytes());
    bytes
        .get_mut(38..40)
        .ok_or("short UDP fixture")?
        .copy_from_slice(&udp_length.to_be_bytes());
    if fragmented {
        bytes
            .get_mut(20..22)
            .ok_or("short IPv4 fixture")?
            .copy_from_slice(&0x2000_u16.to_be_bytes());
    }
    bytes.extend_from_slice(&UDP_TRAILER);
    bytes.extend_from_slice(outer_padding);
    Ok(bytes)
}

#[test]
fn nonzero_trailer_exact_captured_range() -> TestResult {
    let mut bytes = traffic(SECOND_MAC, ADDRESS);
    bytes.extend_from_slice(&[0, 0x55, 0xaa, 0]);
    let report = assess([captured_with_fcs(bytes, 0, FcsStatus::Absent)?])?;
    let trailer = report
        .forensics
        .trailing_data
        .first()
        .ok_or("missing trailer")?;
    assert_eq!(
        (trailer.offset, trailer.length, trailer.nonzero_bytes),
        (42, 4, 2)
    );
    assert_eq!(trailer.packet, 1);
    assert_evidence(&report, &[1]);
    assert!(report.findings.is_empty());
    Ok(())
}

#[test]
fn zero_padding_fcs_not_flagged() -> TestResult {
    let mut zero = traffic(SECOND_MAC, ADDRESS);
    zero.resize(60, 0);
    let mut nonzero = traffic(SECOND_MAC, ADDRESS);
    nonzero.extend_from_slice(&[1, 2, 3, 4]);
    let report = assess([
        captured_with_fcs(zero, 0, FcsStatus::Absent)?,
        captured_with_fcs(nonzero.clone(), 0, FcsStatus::Unknown)?,
        captured_with_fcs(nonzero, 0, FcsStatus::present(4)?)?,
    ])?;
    assert_eq!(
        report.forensics.trailing_data,
        [] as [l2_audit::TrailingData; 0]
    );
    assert_eq!(report.forensics.trailer_frames_unchecked, 2);
    Ok(())
}

#[test]
fn udp_length_separate_outer_padding() -> TestResult {
    let bytes = ipv4_udp_with_trailer(8, false, &[0xee, 0])?;
    let report = assess([captured_with_fcs(bytes, 0, FcsStatus::Unknown)?])?;
    let trailer = report
        .forensics
        .trailing_data
        .first()
        .ok_or("missing UDP trailer")?;
    assert_eq!(trailer.protocol, TrailingProtocol::Udp);
    assert_eq!(
        (trailer.offset, trailer.length, trailer.nonzero_bytes),
        (42, 4, 2)
    );
    assert_eq!(trailer.packet, 1);
    assert_eq!(report.forensics.trailer_frames_unchecked, 1);
    assert_evidence(&report, &[1]);
    assert!(report.findings.is_empty());
    Ok(())
}

#[test]
fn invalid_fragmented_not_trailer_fact() -> TestResult {
    let report = assess([
        captured_with_fcs(
            ipv4_udp_with_trailer(13, false, &[])?,
            0,
            FcsStatus::Unknown,
        )?,
        captured_with_fcs(ipv4_udp_with_trailer(8, true, &[])?, 0, FcsStatus::Unknown)?,
    ])?;

    assert_eq!(
        report.forensics.trailing_data,
        [] as [l2_audit::TrailingData; 0]
    );
    assert_eq!(report.forensics.ip_frames_seen, 2);
    assert_eq!(report.forensics.ip_frames_parsed, 2);
    assert_eq!(report.forensics.trailer_frames_unchecked, 0);
    Ok(())
}

#[test]
fn udp_trailer_shared_forensic_quota() -> TestResult {
    let limits = SurveyLimits::default().with_forensic_records(1)?;
    let mut survey = Survey::with_limits(limits);
    survey.observe(&captured_with_fcs(
        ipv4_udp_with_trailer(8, false, &[])?,
        0,
        FcsStatus::Unknown,
    )?)?;

    let report = survey.finish(&l2_audit::Policy::default())?;
    assert_eq!(report.forensics.communications.len(), 1);
    assert_eq!(
        report.forensics.trailing_data,
        [] as [l2_audit::TrailingData; 0]
    );
    assert!(
        report
            .resource_limits
            .is_reached(ResourceLimit::ForensicRecords)
    );
    Ok(())
}
