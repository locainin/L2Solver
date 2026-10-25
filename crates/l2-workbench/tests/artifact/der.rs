use std::error::Error;

use l2_workbench::artifact::{self, DerError, DerLimits, DerTagClass, FileRange};

#[test]
fn der_inventories_metadata_source_ranges() -> Result<(), Box<dyn Error>> {
    let object = [
        0x30, 0x0d, 0x02, 0x01, 0x05, 0x06, 0x03, 0x2a, 0x03, 0x04, 0x04, 0x03, 0x00, 0xff, 0x11,
    ];
    let mut input = vec![0xa5, 0x5a];
    input.extend_from_slice(&object);
    input.extend_from_slice(&[0x33, 0x44]);
    let boundary = FileRange {
        offset: 2,
        length: object.len(),
    };
    let limits = DerLimits {
        max_value_preview_bytes: 2,
        ..DerLimits::default()
    };
    let report = artifact::parse_der(&input, boundary, limits)?;

    assert_eq!(report.nodes.len(), 4);
    let root = report.nodes.first().ok_or("missing root node")?;
    assert_eq!(root.parent_index, None);
    assert_eq!(root.tag.class, DerTagClass::Universal);
    assert_eq!(root.tag.number, 16);
    assert!(root.tag.constructed);
    assert_eq!(root.encoded_range, boundary);

    let integer = report
        .nodes
        .iter()
        .find(|node| node.integer.is_some())
        .ok_or("missing integer metadata")?;
    assert_eq!(
        integer.integer.as_ref().map(|metadata| metadata.negative),
        Some(false)
    );
    assert_eq!(
        integer
            .integer
            .as_ref()
            .and_then(|metadata| metadata.unsigned_value),
        Some(5)
    );
    assert_eq!(integer.parent_index, Some(0));

    let oid = report
        .nodes
        .iter()
        .find(|node| node.oid.is_some())
        .ok_or("missing OID metadata")?;
    assert_eq!(oid.oid.as_deref(), Some("1.2.3.4"));

    let octets = report
        .nodes
        .iter()
        .find(|node| node.octet_string.is_some())
        .ok_or("missing octet string metadata")?;
    assert_eq!(
        octets.octet_string.as_ref().map(|metadata| metadata.length),
        Some(3)
    );
    assert_eq!(octets.value_preview, [0x00, 0xff]);
    assert!(octets.preview_truncated());
    Ok(())
}

fn assert_invalid_der(encoded: &[u8]) {
    assert!(matches!(
        artifact::parse_der(
            encoded,
            FileRange {
                offset: 0,
                length: encoded.len()
            },
            DerLimits::default()
        ),
        Err(DerError::InvalidDer)
    ));
}

#[test]
fn der_requires_object_requested_boundary() {
    let valid = [0x04, 0x01, 0x7f];
    let mut two_objects = valid.to_vec();
    two_objects.extend_from_slice(&valid);
    assert_invalid_der(&two_objects);

    let nonminimal_length = [0x04, 0x81, 0x01, 0x7f];
    assert_invalid_der(&nonminimal_length);

    let noncanonical_integer = [0x02, 0x02, 0x00, 0x01];
    assert_invalid_der(&noncanonical_integer);

    let malformed_nested_child = [0x30, 0x04, 0x02, 0x02, 0x00, 0x01];
    assert_invalid_der(&malformed_nested_child);

    let noncanonical_oid = [0x06, 0x02, 0x80, 0x2a];
    assert_invalid_der(&noncanonical_oid);

    let unsorted_set = [0x31, 0x05, 0x04, 0x00, 0x02, 0x01, 0x01];
    assert_invalid_der(&unsorted_set);

    let primitive_sequence = [0x10, 0x00];
    assert_invalid_der(&primitive_sequence);
}

#[test]
fn der_requires_validation_universal_primitives() {
    let valid_values: &[&[u8]] = &[
        &[0x01, 0x01, 0xff],
        &[0x02, 0x01, 0x7f],
        &[0x13, 0x03, b'A', b' ', b'9'],
        &[0x16, 0x02, b'O', b'K'],
        &[
            0x17, 0x0d, b'2', b'5', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0',
            b'Z',
        ],
    ];
    for encoded in valid_values {
        assert!(
            artifact::parse_der(
                encoded,
                FileRange {
                    offset: 0,
                    length: encoded.len(),
                },
                DerLimits::default(),
            )
            .is_ok(),
            "expected a supported canonical universal primitive: {encoded:02x?}"
        );
    }

    let unsupported_or_invalid_values: &[&[u8]] = &[
        &[0x09, 0x01, 0xff],       // REAL content does not match a supported DER form
        &[0x09, 0x00],             // Canonical REAL zero remains outside the validated subset
        &[0x0d, 0x01, 0x2a],       // A valid Relative OID is still outside the validated subset
        &[0x0d, 0x01, 0x80],       // Relative OID subidentifier is incomplete
        &[0x12, 0x02, b'1', b' '], // NumericString has no complete decoder in der
        &[0x12, 0x01, b'A'],       // NumericString permits only digits and spaces
        &[0x14, 0x01, b'A'],       // TeletexString is not fully implemented by der
        &[0x15, 0x01, b'A'],       // VideotexString is treated as IA5 by der
        &[0x1a, 0x01, b'A'],       // Valid VisibleString remains outside the validated subset
        &[0x1a, 0x01, 0x80],       // VisibleString is limited to its defined character set
        &[0x1b, 0x01, b'A'],       // GeneralString is not semantically implemented by der
        &[0x1b, 0x01, 0xff],       // GeneralString is not semantically implemented by der
        &[0x1e, 0x02, 0x00, b'A'], // Valid BMPString remains outside the validated subset
        &[0x1e, 0x01, 0x00],       // BMPString content must have complete code units
        &[0x07, 0x00],             // ObjectDescriptor is not supported by the der tag model
        &[0x08, 0x00],             // EXTERNAL is not supported by the der tag model
        &[0x0b, 0x00],             // EmbeddedPDV is not supported by the der tag model
        &[0x0e, 0x00],             // Reserved universal tag
        &[0x0f, 0x00],             // Reserved universal tag
        &[0x19, 0x01, b'A'],       // GraphicString is not supported by the der tag model
        &[0x1c, 0x01, b'A'],       // UniversalString is not supported by the der tag model
        &[0x1f, 0x1f, 0x00], // Unknown universal high-tag form is rejected by the der tag model
        &[0x28, 0x00],       // EXTERNAL requires a constructed schema not handled here
        &[0x2b, 0x00],       // EmbeddedPDV requires a constructed schema not handled here
        &[0x3d, 0x00],       // CHARACTER STRING requires a constructed schema not handled here
        &[0x21, 0x01, 0xff], // BOOLEAN must use primitive form
        &[0x11, 0x00],       // SET must use constructed form
        &[0x24, 0x00],       // OCTET STRING cannot use constructed form in DER
        &[0x01, 0x01, 0x01], // DER BOOLEAN true must use the all-ones octet
        &[0x13, 0x01, b'$'], // Dollar is outside PrintableString's alphabet
    ];
    for encoded in unsupported_or_invalid_values {
        assert!(
            matches!(
                artifact::parse_der(
                    encoded,
                    FileRange {
                        offset: 0,
                        length: encoded.len(),
                    },
                    DerLimits::default(),
                ),
                Err(DerError::InvalidDer)
            ),
            "expected an unsupported or invalid universal primitive to be rejected: {encoded:02x?}"
        );
    }
}

#[test]
fn der_application_private_values_structural() -> Result<(), Box<dyn Error>> {
    let values: &[&[u8]] = &[
        &[0x40, 0x01, 0xff],             // Application primitive with opaque content
        &[0x80, 0x01, 0xff],             // Context-specific primitive with opaque content
        &[0xc0, 0x01, 0xff],             // Private primitive with opaque content
        &[0x60, 0x03, 0x02, 0x01, 0x01], // Application constructed value
        &[0xa0, 0x03, 0x02, 0x01, 0x01], // Context-specific constructed value
        &[0xe0, 0x03, 0x02, 0x01, 0x01], // Private constructed value
        &[0x5f, 0x21, 0x01, 0xff],       // Application primitive high-tag form
        &[0x9f, 0x21, 0x01, 0xff],       // Context-specific primitive high-tag form
        &[0xdf, 0x21, 0x01, 0xff],       // Private primitive high-tag form
        &[0x7f, 0x21, 0x03, 0x02, 0x01, 0x01], // Application constructed high-tag form
        &[0xbf, 0x21, 0x03, 0x02, 0x01, 0x01], // Context-specific constructed high-tag form
        &[0xff, 0x21, 0x03, 0x02, 0x01, 0x01], // Private constructed high-tag form
    ];
    for encoded in values {
        let first_byte = *encoded.first().ok_or("missing encoded tag")?;
        let report = artifact::parse_der(
            encoded,
            FileRange {
                offset: 0,
                length: encoded.len(),
            },
            DerLimits::default(),
        )?;
        assert_eq!(
            report.nodes.len(),
            if first_byte & 0x20 == 0 { 1 } else { 2 }
        );
        let root = report.nodes.first().ok_or("missing tagged root")?;
        assert!(matches!(
            root.tag.class,
            DerTagClass::Application | DerTagClass::ContextSpecific | DerTagClass::Private
        ));
    }

    let malformed_child = [0xa0, 0x02, 0x02, 0x00];
    assert!(matches!(
        artifact::parse_der(
            &malformed_child,
            FileRange {
                offset: 0,
                length: malformed_child.len(),
            },
            DerLimits::default(),
        ),
        Err(DerError::InvalidDer)
    ));
    Ok(())
}

#[test]
fn der_depth_value_preview_limits() -> Result<(), Box<dyn Error>> {
    let nested = [0x30, 0x04, 0x30, 0x02, 0x05, 0x00];
    let boundary = FileRange {
        offset: 0,
        length: nested.len(),
    };
    assert!(matches!(
        artifact::parse_der(
            &nested,
            boundary,
            DerLimits {
                max_depth: 1,
                ..DerLimits::default()
            }
        ),
        Err(DerError::DepthLimitExceeded { .. })
    ));
    assert!(matches!(
        artifact::parse_der(
            &nested,
            boundary,
            DerLimits {
                max_nodes: 2,
                ..DerLimits::default()
            }
        ),
        Err(DerError::NodeLimitExceeded { .. })
    ));

    let octets = [0x04, 0x04, 1, 2, 3, 4];
    let report = artifact::parse_der(
        &octets,
        FileRange {
            offset: 0,
            length: octets.len(),
        },
        DerLimits {
            max_value_preview_bytes: 1,
            ..DerLimits::default()
        },
    )?;
    let root = report.nodes.first().ok_or("missing octet root")?;
    assert_eq!(root.value_preview, [1]);
    assert!(root.preview_truncated());
    Ok(())
}

#[test]
fn der_caller_exceed_library_defaults() -> Result<(), Box<dyn Error>> {
    let object = [0x04, 0x01, 0x7f];
    let report = artifact::parse_der(
        &object,
        FileRange {
            offset: 0,
            length: object.len(),
        },
        DerLimits {
            max_object_bytes: artifact::MAX_DER_OBJECT_BYTES + 1,
            max_depth: artifact::MAX_DER_DEPTH,
            max_nodes: artifact::MAX_DER_NODES + 1,
            max_value_preview_bytes: artifact::MAX_DER_VALUE_PREVIEW_BYTES + 1,
        },
    )?;

    assert_eq!(report.nodes.len(), 1);
    let root = report.nodes.first().ok_or("missing octet root")?;
    assert_eq!(root.value_preview, [0x7f]);
    Ok(())
}

#[test]
fn der_invalid_boundaries_oversized_objects() {
    let object = [0x05, 0x00];
    assert!(matches!(
        artifact::parse_der(
            &object,
            FileRange {
                offset: 1,
                length: 2
            },
            DerLimits::default()
        ),
        Err(DerError::InvalidBoundary { .. })
    ));
    assert!(matches!(
        artifact::parse_der(
            &object,
            FileRange {
                offset: 0,
                length: object.len()
            },
            DerLimits {
                max_object_bytes: 1,
                ..DerLimits::default()
            }
        ),
        Err(DerError::ObjectTooLarge { .. })
    ));
}
