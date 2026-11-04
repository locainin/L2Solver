#[path = "../../../tests/fixtures/captures.rs"]
pub mod captures;

#[path = "../src/report.rs"]
mod report;

#[test]
fn capture_evidence_protocol_status_separate() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = crate::captures::LLDP
        .get(40..)
        .ok_or("fixture payload missing")?;
    let parsed = report::assess(bytes);
    assert_eq!(parsed.status, report::Status::Parsed);
    assert!(
        parsed
            .network
            .as_ref()
            .and_then(|frame| frame.ethernet())
            .is_some()
    );
    assert!(parsed.lldp.is_some());
    assert!(parsed.diagnostic.is_none());
    assert_eq!(report::assess(&[]).status, report::Status::Malformed);
    let mut unknown = vec![0; 12];
    unknown.extend_from_slice(&0x9999_u16.to_be_bytes());
    assert_eq!(report::assess(&unknown).status, report::Status::Unsupported);
    let mut invalid = vec![0; 12];
    invalid.extend_from_slice(&0x88cc_u16.to_be_bytes());
    invalid.extend_from_slice(&[0, 0]);
    assert_eq!(report::assess(&invalid).status, report::Status::Invalid);
    assert_eq!(
        report::assess_with_link_type(l2_capture::LinkType::ETHERNET, bytes).status,
        report::Status::Parsed
    );
    assert_eq!(
        report::assess_with_link_type(l2_capture::LinkType::IEEE802_11_RADIOTAP, bytes).status,
        report::Status::Unsupported
    );
    Ok(())
}

#[test]
fn stp_unknown_version_is_unsupported() {
    let mut bytes = vec![
        1, 0x80, 0xc2, 0, 0, 0, 2, 0, 0, 0, 0, 1, 0, 7, 0x42, 0x42, 3, 0, 0, 0, 0x80,
    ];
    assert_eq!(report::assess(&bytes).status, report::Status::Parsed);
    assert!(report::assess(&bytes).stp.is_some());
    if let Some(version) = bytes.get_mut(19) {
        *version = 3;
    }
    assert_eq!(report::assess(&bytes).status, report::Status::Unsupported);
}

#[test]
fn stp_dispatch_requires_length_llc() {
    let mut ethernet_ii = vec![0; 12];
    ethernet_ii.extend_from_slice(&[0x08, 0x00, 0x42, 0x42, 3, 0, 0, 0, 0x80]);
    assert_eq!(
        report::assess(&ethernet_ii).status,
        report::Status::Unsupported
    );
    let mut non_stp_llc = vec![0; 12];
    non_stp_llc.extend_from_slice(&[0, 3, 0xaa, 0xaa, 3]);
    assert_eq!(
        report::assess(&non_stp_llc).status,
        report::Status::Unsupported
    );
}
