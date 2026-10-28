use super::*;
use crate::protocol::RecordLengthMeaning;

fn test_schema() -> RecordSchema {
    RecordSchema {
        records_offset: 1,
        count: RecordCount::Field {
            field: IntegerField {
                offset: 0,
                width: 1,
                byte_order: crate::protocol::ByteOrder::BigEndian,
            },
        },
        identifier: super::super::model::ByteField {
            offset: 0,
            width: 1,
        },
        sequence: IntegerField {
            offset: 1,
            width: 1,
            byte_order: crate::protocol::ByteOrder::BigEndian,
        },
        length: IntegerField {
            offset: 2,
            width: 1,
            byte_order: crate::protocol::ByteOrder::BigEndian,
        },
        data_offset: 3,
        length_meaning: RecordLengthMeaning::PayloadBytes,
        sequence_base: 0,
        terminal_sequence: None,
    }
}

fn test_frame(payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![1, b'X', 0, u8::try_from(payload.len()).unwrap_or(u8::MAX)];
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn rejected_schema_does_not_compute_full_input_identity() {
    let bytes = test_frame(b"body");
    let input = RecordInput::new(&bytes);
    assert!(input.input_sha256.get().is_none());

    let mut schema = test_schema();
    schema.identifier.width = 0;
    assert!(matches!(
        input.parse(&schema, RecordLimits::default()),
        Err(RecordError::InvalidSchema { field }) if field == "identifier"
    ));
    assert!(input.input_sha256.get().is_none());
}

#[test]
fn successful_parse_rebind_and_assembly_share_one_fresh_identity() -> Result<(), RecordError> {
    let limits = RecordLimits::default();
    let schema = test_schema();
    let original_bytes = test_frame(b"old!");
    let input = RecordInput::new(&original_bytes);
    let report = input.parse(&schema, limits)?;
    let original_identity = input.input_sha256.get().ok_or(RecordError::InvalidReport)?;
    assert_eq!(report.input_sha256(), original_identity);

    let template = report
        .header_only_template(&input, 4, limits)?
        .ok_or(RecordError::InvalidReport)?;
    let changed_bytes = test_frame(b"new!");
    let changed_input = RecordInput::new(&changed_bytes);
    let rebound = template.rebind(&changed_input, limits)?;
    let rebound_identity = changed_input
        .input_sha256
        .get()
        .ok_or(RecordError::InvalidReport)?;
    assert_eq!(rebound.input_sha256(), rebound_identity);
    assert_ne!(rebound.input_sha256(), original_identity);

    let assembly = RecordAssemblyInput::from_input(&changed_input, &rebound)?;
    let trusted_identity = assembly.input_sha256.ok_or(RecordError::InvalidReport)?;
    assert!(std::ptr::eq(trusted_identity, rebound_identity.as_str()));
    assert!(std::ptr::eq(
        changed_input.input_sha256(),
        rebound_identity.as_str()
    ));
    Ok(())
}
