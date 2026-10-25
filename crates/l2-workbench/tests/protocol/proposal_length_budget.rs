use l2_workbench::protocol::{
    ByteOrder, MAX_PROTOCOL_PREFIX_OFFSET, RecordLengthMeaning, RecordSchemaProposalLimits,
    propose_record_schema_space,
};
use std::error::Error;

const INTEGER_WIDTHS: [usize; 4] = [1, 2, 4, 8];
const SINGLE_BYTE_ORDERS: [ByteOrder; 1] = [ByteOrder::BigEndian];
const MULTI_BYTE_ORDERS: [ByteOrder; 2] = [ByteOrder::BigEndian, ByteOrder::LittleEndian];
const LENGTH_MEANINGS: [RecordLengthMeaning; 3] = [
    RecordLengthMeaning::PayloadBytes,
    RecordLengthMeaning::WholeRecord,
    RecordLengthMeaning::BytesAfterLengthField,
];

fn derived_length_check_domain(maximum_offset: usize) -> Option<usize> {
    let mut total = 0_usize;
    for width in INTEGER_WIDTHS {
        let order_count = if width == SINGLE_BYTE_ORDERS.len() {
            SINGLE_BYTE_ORDERS.len()
        } else {
            MULTI_BYTE_ORDERS.len()
        };
        for offset in 0..=maximum_offset {
            let field_end = offset.checked_add(width)?;
            if field_end > maximum_offset {
                continue;
            }
            let boundary_count = maximum_offset.checked_sub(field_end)?.checked_add(1)?;
            let checks = boundary_count
                .checked_mul(order_count)?
                .checked_mul(LENGTH_MEANINGS.len())?;
            total = total.checked_add(checks)?;
        }
    }
    Some(total)
}

fn no_length_candidate_messages() -> Option<(Vec<u8>, Vec<u8>)> {
    let message_length = MAX_PROTOCOL_PREFIX_OFFSET.checked_add(1)?;
    let mut first = Vec::with_capacity(message_length);
    let mut second = Vec::with_capacity(message_length);
    for offset in 0..message_length {
        if offset == 0 {
            first.push(0xe1);
            second.push(0xe1);
        } else {
            first.push(0x80);
            second.push(0xa0);
        }
    }
    Some((first, second))
}

#[test]
fn default_length_budget_matches_the_derived_prefix_domain() -> Result<(), Box<dyn Error>> {
    let derived_maximum = derived_length_check_domain(MAX_PROTOCOL_PREFIX_OFFSET)
        .ok_or("length-check domain size overflowed")?;

    assert_eq!(
        RecordSchemaProposalLimits::default().max_length_checks,
        derived_maximum
    );
    Ok(())
}

#[test]
fn default_length_search_exhausts_a_no_candidate_prefix_domain() -> Result<(), Box<dyn Error>> {
    let (first, second) = no_length_candidate_messages()
        .ok_or("message length overflowed the declared prefix domain")?;
    let report = propose_record_schema_space(
        &[first.as_slice(), second.as_slice()],
        &[],
        RecordSchemaProposalLimits::default(),
    )?;
    let derived_maximum = derived_length_check_domain(MAX_PROTOCOL_PREFIX_OFFSET)
        .ok_or("length-check domain size overflowed")?;

    assert!(report.candidate_space.is_none());
    assert_eq!(report.examined_length_checks, derived_maximum);
    assert_eq!(report.omitted_length_checks, 0);
    assert!(report.search_exhaustive_within_plan);
    Ok(())
}
