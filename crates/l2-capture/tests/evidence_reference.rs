use std::{error::Error, str::FromStr};

use l2_capture::{EvidenceSourceId, PacketReference};

#[test]
fn source_id_canonical_sha256_text() -> Result<(), Box<dyn Error>> {
    let source = EvidenceSourceId::from_bytes([0x2a; 32]);
    let encoded = source.to_string();

    assert_eq!(encoded, format!("sha256:{}", "2a".repeat(32)));
    assert_eq!(EvidenceSourceId::from_str(&encoded)?, source);
    assert_eq!(source.as_bytes(), &[0x2a; 32]);
    Ok(())
}

#[test]
fn source_id_parser_noncanonical_text() {
    let invalid = [
        "sha1:0000000000000000000000000000000000000000000000000000000000000000",
        "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "sha256:000000000000000000000000000000000000000000000000000000000000000",
        "sha256:00000000000000000000000000000000000000000000000000000000000000000",
        "sha256:000000000000000000000000000000000000000000000000000000000000000g",
    ];

    for value in invalid {
        assert!(
            EvidenceSourceId::from_str(value).is_err(),
            "accepted {value}"
        );
    }
}

#[test]
fn packet_references_numbers_separate_source() -> Result<(), Box<dyn Error>> {
    let first_source = EvidenceSourceId::from_bytes([0x11; 32]);
    let second_source = EvidenceSourceId::from_bytes([0x22; 32]);
    let first = PacketReference::new(first_source, 1)?;
    let second = PacketReference::new(second_source, 1)?;

    assert_ne!(first, second);
    assert_eq!(first.source(), first_source);
    assert_eq!(second.source(), second_source);
    assert_eq!(first.packet_number(), 1);
    assert_eq!(second.packet_number(), 1);
    Ok(())
}

#[test]
fn packet_reference_zero_packet_number() {
    assert!(PacketReference::new(EvidenceSourceId::from_bytes([0x33; 32]), 0).is_err());
}
