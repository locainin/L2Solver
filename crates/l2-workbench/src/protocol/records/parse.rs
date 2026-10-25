use super::{
    ByteField, IntegerField, ParsedRecord, RecordCount, RecordError, RecordLengthMeaning,
    RecordLimits, RecordParseReport, RecordSchema,
};
use crate::integer::decode_unsigned;
use crate::protocol::{ByteOrder, ByteRange};
use crate::sha256;

/// Parse repeated records using a complete explicit schema and default safety limits
///
/// # Errors
/// Rejects invalid layouts, truncated inputs, trailing bytes, overflow, and limit violations
pub fn parse_records(
    bytes: &[u8],
    schema: &RecordSchema,
) -> Result<RecordParseReport, RecordError> {
    parse_records_with_limits(bytes, schema, RecordLimits::default())
}

/// Parse repeated records using a complete explicit schema and caller-selected limits
///
/// Every successful record is bound to exact source ranges and the entire selected input
/// must be consumed so a partial parse cannot be mistaken for complete evidence
///
/// # Errors
/// Rejects invalid layouts, truncated inputs, trailing bytes, overflow, and limit violations
pub fn parse_records_with_limits(
    bytes: &[u8],
    schema: &RecordSchema,
    limits: RecordLimits,
) -> Result<RecordParseReport, RecordError> {
    validate_limits(limits)?;
    validate_schema(schema, limits)?;
    if bytes.len() > limits.max_input_bytes {
        return Err(RecordError::InputTooLarge {
            length: bytes.len(),
            maximum: limits.max_input_bytes,
        });
    }
    if schema.records_offset > bytes.len() {
        return Err(RecordError::TruncatedPreamble {
            needed: schema.records_offset,
            available: bytes.len(),
        });
    }

    // Resolve the declared count before allocating report storage
    let declared_count = declared_count(bytes, schema)?;
    if let Some(count) = declared_count {
        ensure_record_count(count, limits.max_records)?;
    }
    let expected = declared_count
        .map(|count| {
            usize::try_from(count).map_err(|_| RecordError::TooManyRecords {
                count,
                maximum: limits.max_records,
            })
        })
        .transpose()?;
    // Only reserve records that could fit in the selected input
    let remaining_bytes = bytes.len() - schema.records_offset;
    let reserve_count = initial_record_capacity(expected, remaining_bytes, schema, limits)?;
    let mut records = Vec::new();
    records
        .try_reserve_exact(reserve_count)
        .map_err(|_| RecordError::AllocationFailed)?;

    let mut cursor = schema.records_offset;
    match expected {
        Some(count) => {
            for record_index in 0..count {
                let record = parse_one(bytes, schema, record_index, cursor)?;
                cursor = record.record.end;
                push_record(&mut records, record, limits)?;
            }
        }
        None => {
            while cursor < bytes.len() {
                if records.len() == limits.max_records {
                    let count = u64::try_from(records.len())
                        .unwrap_or(u64::MAX)
                        .saturating_add(1);
                    return Err(RecordError::TooManyRecords {
                        count,
                        maximum: limits.max_records,
                    });
                }
                let record = parse_one(bytes, schema, records.len(), cursor)?;
                cursor = record.record.end;
                push_record(&mut records, record, limits)?;
            }
        }
    }

    // Exact consumption prevents a valid prefix from hiding an uninterpreted suffix
    if cursor != bytes.len() {
        return Err(RecordError::TrailingBytes {
            offset: cursor,
            remaining: bytes.len().saturating_sub(cursor),
        });
    }
    Ok(RecordParseReport {
        schema: schema.clone(),
        input_length: bytes.len(),
        input_sha256: sha256(bytes),
        declared_count,
        records,
    })
}

fn initial_record_capacity(
    expected: Option<usize>,
    remaining_bytes: usize,
    schema: &RecordSchema,
    limits: RecordLimits,
) -> Result<usize, RecordError> {
    let Some(count) = expected else {
        return Ok(0);
    };
    let report_bytes =
        record_metadata_bytes(schema.identifier.width, count, limits.max_report_bytes)?;
    if report_bytes > limits.max_report_bytes {
        return Err(RecordError::ReportTooLarge {
            bytes: report_bytes,
            maximum: limits.max_report_bytes,
        });
    }

    // Every valid record consumes at least its configured header width
    let possible_records = remaining_bytes / schema.data_offset;
    Ok(count.min(possible_records))
}

const fn validate_limits(limits: RecordLimits) -> Result<(), RecordError> {
    if limits.max_input_bytes == 0
        || limits.max_records == 0
        || limits.max_identifier_bytes == 0
        || limits.max_report_bytes == 0
        || limits.max_groups == 0
        || limits.max_output_bytes == 0
        || limits.max_issue_examples == 0
    {
        return Err(RecordError::InvalidLimits);
    }
    Ok(())
}

pub(super) const fn validate_assembly_limits(limits: RecordLimits) -> Result<(), RecordError> {
    validate_limits(limits)
}

fn validate_schema(schema: &RecordSchema, limits: RecordLimits) -> Result<(), RecordError> {
    validate_byte_field(schema.identifier, schema.data_offset, "identifier")?;
    if schema.identifier.width > limits.max_identifier_bytes {
        return Err(RecordError::IdentifierTooLarge {
            width: schema.identifier.width,
            maximum: limits.max_identifier_bytes,
        });
    }
    validate_integer_field(schema.sequence, schema.data_offset, "sequence")?;
    validate_integer_field(schema.length, schema.data_offset, "length")?;
    if schema.data_offset == 0 {
        return Err(RecordError::InvalidSchema {
            field: "data_offset",
        });
    }
    if schema
        .terminal_sequence
        .is_some_and(|terminal| terminal < schema.sequence_base)
    {
        return Err(RecordError::InvalidSchema {
            field: "terminal_sequence",
        });
    }
    if let RecordCount::Field { field } = schema.count {
        validate_integer_field(field, schema.records_offset, "count")?;
    }
    Ok(())
}

fn validate_byte_field(
    field: ByteField,
    boundary: usize,
    name: &'static str,
) -> Result<(), RecordError> {
    let end = field
        .offset
        .checked_add(field.width)
        .ok_or(RecordError::InvalidSchema { field: name })?;
    if field.width == 0 || end > boundary {
        return Err(RecordError::InvalidSchema { field: name });
    }
    Ok(())
}

fn validate_integer_field(
    field: IntegerField,
    boundary: usize,
    name: &'static str,
) -> Result<(), RecordError> {
    if !matches!(field.width, 1 | 2 | 4 | 8) {
        return Err(RecordError::InvalidSchema { field: name });
    }
    validate_byte_field(
        ByteField {
            offset: field.offset,
            width: field.width,
        },
        boundary,
        name,
    )
}

fn declared_count(bytes: &[u8], schema: &RecordSchema) -> Result<Option<u64>, RecordError> {
    match schema.count {
        RecordCount::UntilEnd => Ok(None),
        RecordCount::Exact { records } => Ok(Some(records)),
        RecordCount::Field { field } => {
            let end = field
                .offset
                .checked_add(field.width)
                .ok_or(RecordError::InvalidSchema { field: "count" })?;
            let value = bytes
                .get(field.offset..end)
                .ok_or(RecordError::TruncatedPreamble {
                    needed: end,
                    available: bytes.len(),
                })?;
            decode_unsigned(value, field.byte_order == ByteOrder::LittleEndian)
                .map(Some)
                .ok_or(RecordError::InvalidSchema { field: "count" })
        }
    }
}

fn ensure_record_count(count: u64, maximum: usize) -> Result<(), RecordError> {
    if u128::from(count) > maximum as u128 {
        return Err(RecordError::TooManyRecords { count, maximum });
    }
    Ok(())
}

fn parse_one(
    bytes: &[u8],
    schema: &RecordSchema,
    record_index: usize,
    start: usize,
) -> Result<ParsedRecord, RecordError> {
    let header_end = start
        .checked_add(schema.data_offset)
        .ok_or(RecordError::LengthOverflow {
            record: record_index,
        })?;
    if header_end > bytes.len() {
        return Err(RecordError::TruncatedRecord {
            record: record_index,
            offset: start,
            needed: header_end,
            available: bytes.len(),
        });
    }

    let sequence = decode_record_integer(bytes, start, schema.sequence, record_index)?;
    let encoded_length = decode_record_integer(bytes, start, schema.length, record_index)?;
    let relative_end = record_end(schema, encoded_length, record_index)?;
    let end = start
        .checked_add(relative_end)
        .ok_or(RecordError::LengthOverflow {
            record: record_index,
        })?;
    if end > bytes.len() {
        return Err(RecordError::TruncatedRecord {
            record: record_index,
            offset: start,
            needed: end,
            available: bytes.len(),
        });
    }

    let identifier_start =
        start
            .checked_add(schema.identifier.offset)
            .ok_or(RecordError::LengthOverflow {
                record: record_index,
            })?;
    let identifier_end = identifier_start
        .checked_add(schema.identifier.width)
        .ok_or(RecordError::LengthOverflow {
            record: record_index,
        })?;
    let identifier_slice = bytes
        .get(identifier_start..identifier_end)
        .ok_or(RecordError::InvalidReport)?;
    let mut identifier = Vec::new();
    identifier
        .try_reserve_exact(identifier_slice.len())
        .map_err(|_| RecordError::AllocationFailed)?;
    identifier.extend_from_slice(identifier_slice);

    Ok(ParsedRecord {
        index: record_index,
        record: ByteRange { start, end },
        identifier,
        sequence,
        payload: ByteRange {
            start: header_end,
            end,
        },
    })
}

fn decode_record_integer(
    bytes: &[u8],
    record_start: usize,
    field: IntegerField,
    record_index: usize,
) -> Result<u64, RecordError> {
    let start = record_start
        .checked_add(field.offset)
        .ok_or(RecordError::LengthOverflow {
            record: record_index,
        })?;
    let end = start
        .checked_add(field.width)
        .ok_or(RecordError::LengthOverflow {
            record: record_index,
        })?;
    let value = bytes.get(start..end).ok_or(RecordError::TruncatedRecord {
        record: record_index,
        offset: record_start,
        needed: end,
        available: bytes.len(),
    })?;
    decode_unsigned(value, field.byte_order == ByteOrder::LittleEndian)
        .ok_or(RecordError::InvalidSchema { field: "integer" })
}

fn record_end(
    schema: &RecordSchema,
    encoded: u64,
    record_index: usize,
) -> Result<usize, RecordError> {
    let encoded = usize::try_from(encoded).map_err(|_| RecordError::LengthOverflow {
        record: record_index,
    })?;
    let end = match schema.length_meaning {
        RecordLengthMeaning::PayloadBytes => schema.data_offset.checked_add(encoded),
        RecordLengthMeaning::WholeRecord => Some(encoded),
        RecordLengthMeaning::BytesAfterLengthField => schema
            .length
            .offset
            .checked_add(schema.length.width)
            .and_then(|field_end| field_end.checked_add(encoded)),
    }
    .ok_or(RecordError::LengthOverflow {
        record: record_index,
    })?;
    if end < schema.data_offset || end == 0 {
        return Err(RecordError::InvalidRecordLength {
            record: record_index,
            encoded: u64::try_from(encoded).unwrap_or(u64::MAX),
        });
    }
    Ok(end)
}

fn push_record(
    records: &mut Vec<ParsedRecord>,
    record: ParsedRecord,
    limits: RecordLimits,
) -> Result<(), RecordError> {
    let next_count = records
        .len()
        .checked_add(1)
        .ok_or(RecordError::AllocationFailed)?;
    let report_bytes =
        record_metadata_bytes(record.identifier.len(), next_count, limits.max_report_bytes)?;
    if report_bytes > limits.max_report_bytes {
        return Err(RecordError::ReportTooLarge {
            bytes: report_bytes,
            maximum: limits.max_report_bytes,
        });
    }
    records
        .try_reserve(1)
        .map_err(|_| RecordError::AllocationFailed)?;
    records.push(record);
    Ok(())
}

fn record_metadata_bytes(
    identifier_width: usize,
    count: usize,
    maximum: usize,
) -> Result<usize, RecordError> {
    if count == 0 {
        return Ok(0);
    }
    std::mem::size_of::<ParsedRecord>()
        .checked_add(identifier_width)
        .and_then(|per_record| per_record.checked_mul(count))
        .ok_or(RecordError::ReportTooLarge {
            bytes: usize::MAX,
            maximum,
        })
}
