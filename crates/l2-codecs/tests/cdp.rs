use std::error::Error;

use l2_codecs::{CdpError, CdpLimits, decode_cdp};

const LIMITS: CdpLimits = CdpLimits::new(128, 255);
const GOLDEN: &[u8] = &[
    2, 0x78, 0xe6, 0xbe, 0, 1, 0, 0x0c, b's', b'w', b'i', b't', b'c', b'h', b'-', b'a', 0, 3, 0,
    0x0b, b'G', b'i', b'1', b'/', b'0', b'/', b'1',
];

fn hex(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect()
}

#[test]
fn accepts_independent_cdp_fixture_and_exposes_exact_identity_offsets() -> Result<(), Box<dyn Error>>
{
    let cdp = decode_cdp(GOLDEN, LIMITS)?;
    assert_eq!(cdp.version, 2);
    assert_eq!(cdp.hold_seconds, 120);
    assert_eq!(cdp.device.value, b"switch-a");
    assert_eq!(cdp.port.value, b"Gi1/0/1");
    assert_eq!(
        GOLDEN.get(cdp.device.offset..cdp.device.offset + cdp.device.value.len()),
        Some(cdp.device.value)
    );
    assert_eq!(
        GOLDEN.get(cdp.port.offset..cdp.port.offset + cdp.port.value.len()),
        Some(cdp.port.value)
    );
    assert_eq!(cdp.tlv_count, 2);
    Ok(())
}

#[test]
fn rejects_truncated_checksum_corrupt_and_bad_tlv_frames() -> Result<(), Box<dyn Error>> {
    for length in 0..GOLDEN.len() {
        let prefix = GOLDEN.get(..length).ok_or("missing prefix")?;
        assert!(
            decode_cdp(prefix, LIMITS).is_err(),
            "prefix length {length}"
        );
    }
    let mut corrupt = GOLDEN.to_vec();
    *corrupt.last_mut().ok_or("missing last byte")? ^= 1;
    assert_eq!(decode_cdp(&corrupt, LIMITS), Err(CdpError::InvalidChecksum));
    // Scapy calculated the checksum despite this impossible TLV length
    let invalid_tlv = hex("0278e6c7000100037377697463682d610003000b4769312f302f31")?;
    assert!(matches!(
        decode_cdp(&invalid_tlv, LIMITS),
        Err(CdpError::InvalidTlvLength { .. })
    ));
    Ok(())
}

#[test]
fn rejects_duplicate_missing_or_empty_identity_even_with_valid_checksum()
-> Result<(), Box<dyn Error>> {
    for fixture in [
        "027878fc0001000c7377697463682d610001000c7377697463682d610003000b4769312f302f31",
        "02788fc50001000c7377697463682d61",
        "0278547c000100040003000b4769312f302f31",
    ] {
        assert!(
            decode_cdp(&hex(fixture)?, LIMITS).is_err(),
            "fixture {fixture}"
        );
    }
    Ok(())
}

#[test]
fn caller_controls_tlv_and_identity_budgets() {
    assert!(decode_cdp(GOLDEN, CdpLimits::new(1, 255)).is_err());
    assert!(decode_cdp(GOLDEN, CdpLimits::new(2, 7)).is_err());
    assert!(decode_cdp(GOLDEN, CdpLimits::new(2, 8)).is_ok());
}

#[test]
fn odd_signed_checksum_matches_wireshark_at_0x80_boundary() -> Result<(), Box<dyn Error>> {
    let valid = hex("027899930001000664650003000580")?;
    let scapy = hex("027898930001000664650003000580")?;
    assert_eq!(decode_cdp(&valid, LIMITS)?.port.value, &[0x80]);
    assert_eq!(decode_cdp(&scapy, LIMITS), Err(CdpError::InvalidChecksum));
    Ok(())
}

#[test]
fn reports_checksum_valid_short_tlv_headers_and_values() -> Result<(), Box<dyn Error>> {
    for (fixture, available) in [("0278fd8700", 1), ("0278fd86000100", 3)] {
        assert_eq!(
            decode_cdp(&hex(fixture)?, LIMITS),
            Err(CdpError::TruncatedTlvHeader {
                offset: 4,
                available
            })
        );
    }
    assert_eq!(
        decode_cdp(&hex("0278bc3a0001000a4142")?, LIMITS),
        Err(CdpError::TruncatedTlvValue {
            offset: 4,
            declared: 6,
            available: 2
        })
    );
    Ok(())
}

#[test]
fn retains_identities_after_unknown_well_formed_tlvs() -> Result<(), Box<dyn Error>> {
    let bytes = hex("0278979f010000040001000664650003000570")?;
    let frame = decode_cdp(&bytes, LIMITS)?;
    assert_eq!(frame.tlv_count, 3);
    assert_eq!(
        (frame.device.value, frame.port.value),
        (b"de".as_slice(), b"p".as_slice())
    );
    Ok(())
}

#[test]
fn rejects_oversized_payload_before_attempting_a_checksum() {
    let bytes = vec![0; l2_codecs::MAX_CDP_BYTES + 1];
    assert_eq!(
        decode_cdp(&bytes, LIMITS),
        Err(CdpError::FrameTooLong {
            length: bytes.len(),
            max: l2_codecs::MAX_CDP_BYTES
        })
    );
    assert!(matches!(
        decode_cdp(GOLDEN, CdpLimits::new(0, 255)),
        Err(CdpError::TooManyTlvs { max: 0 })
    ));
    assert!(matches!(
        decode_cdp(GOLDEN, CdpLimits::new(128, 0)),
        Err(CdpError::InvalidIdentity { .. })
    ));
}
