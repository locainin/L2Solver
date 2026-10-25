use super::{
    builder::{Builder, ObservationDraft},
    model::{CarrierError, Field, OmissionReason, Rule, Sample, Value},
    resolve::{ResolvedSample, sample_ranges},
};

const DNS_MAX_NAME_BYTES: usize = 255;
const DNS_MAX_LABEL_BYTES: usize = 63;
const DNS_MAX_LABELS: usize = 127;

pub(super) fn extract_samples(
    builder: &mut Builder,
    rule: &Rule,
    samples: &[Sample<'_>],
    resolved: &[ResolvedSample],
) -> Result<(), CarrierError> {
    for (sample, data) in samples.iter().zip(resolved) {
        let projection = project(rule, data);
        let (component_index, value, start, length) = match projection {
            Ok(projection) => projection,
            Err(reason) => {
                builder.omit(Some(sample.id), rule, reason);
                continue;
            }
        };
        let ranges = sample_ranges(sample, start, length)?;
        builder.observe(ObservationDraft {
            sample_ids: vec![sample.id],
            event_id: data.event_id.clone(),
            rule: rule.clone(),
            component_index,
            value,
            ranges,
            ambiguity: data.ambiguity,
        });
    }
    Ok(())
}

type Projection = Result<(Option<usize>, Value, usize, usize), OmissionReason>;

fn project(rule: &Rule, sample: &ResolvedSample) -> Projection {
    match rule {
        Rule::Bytes => Ok((
            None,
            Value::Bytes {
                bytes: sample.bytes.clone(),
            },
            0,
            sample.bytes.len(),
        )),
        Rule::Bits { order } => project_bits(&sample.bytes, *order),
        Rule::MessageLength => u64::try_from(sample.bytes.len())
            .map(|length| {
                (
                    None,
                    Value::Unsigned { value: length },
                    0,
                    sample.bytes.len(),
                )
            })
            .map_err(|_| OmissionReason::FieldOutOfBounds),
        Rule::LengthField { field, .. } | Rule::OrderField { field } => {
            project_field(&sample.bytes, field)
        }
        Rule::Sequence => sample
            .sequence
            .map(|sequence| {
                (
                    None,
                    Value::Unsigned { value: sequence },
                    0,
                    sample.bytes.len(),
                )
            })
            .ok_or(OmissionReason::MissingSequence),
        Rule::Capitalization => Ok((
            None,
            Value::Capitalization {
                pattern: sample
                    .bytes
                    .iter()
                    .filter(|byte| byte.is_ascii_alphabetic())
                    .map(|byte| u8::from(byte.is_ascii_uppercase()))
                    .collect(),
            },
            0,
            sample.bytes.len(),
        )),
        Rule::Timing | Rule::DnsLabels { .. } => Err(OmissionReason::UnsupportedRule),
    }
}

fn project_bits(bytes: &[u8], order: super::BitOrder) -> Projection {
    let bit_length = bytes
        .len()
        .checked_mul(8)
        .and_then(|length| u64::try_from(length).ok())
        .ok_or(OmissionReason::FieldOutOfBounds)?;
    let mut packed = Vec::with_capacity(bytes.len());
    let mut current = 0_u8;
    let mut used = 0_u8;
    // Source bit order is caller-selected; packed output always fills from its high bit
    for byte in bytes.iter().copied() {
        match order {
            super::BitOrder::MostSignificantFirst => {
                for position in (0..8).rev() {
                    append_bit(&mut packed, &mut current, &mut used, (byte >> position) & 1);
                }
            }
            super::BitOrder::LeastSignificantFirst => {
                for position in 0..8 {
                    append_bit(&mut packed, &mut current, &mut used, (byte >> position) & 1);
                }
            }
        }
    }
    if used != 0 {
        packed.push(current);
    }
    Ok((
        None,
        Value::Bits {
            order,
            bit_length,
            packed,
        },
        0,
        bytes.len(),
    ))
}

fn append_bit(packed: &mut Vec<u8>, current: &mut u8, used: &mut u8, bit: u8) {
    *current |= bit << (7 - *used);
    *used += 1;
    if *used == 8 {
        packed.push(*current);
        *current = 0;
        *used = 0;
    }
}

fn project_field(bytes: &[u8], field: &Field) -> Projection {
    let width = field.width.bytes();
    let end = field
        .offset
        .checked_add(width)
        .ok_or(OmissionReason::FieldOutOfBounds)?;
    let field_bytes = bytes
        .get(field.offset..end)
        .ok_or(OmissionReason::FieldOutOfBounds)?;
    let mut value = 0_u64;
    // Read exactly the requested width so no upper bytes are silently discarded
    match field.byte_order {
        super::NumericByteOrder::BigEndian => {
            for byte in field_bytes.iter().copied() {
                value = value
                    .checked_mul(256)
                    .and_then(|number| number.checked_add(u64::from(byte)))
                    .ok_or(OmissionReason::FieldOutOfBounds)?;
            }
        }
        super::NumericByteOrder::LittleEndian => {
            for (index, byte) in field_bytes.iter().copied().enumerate() {
                let shift = u32::try_from(index)
                    .ok()
                    .and_then(|position| position.checked_mul(8))
                    .ok_or(OmissionReason::FieldOutOfBounds)?;
                value |= u64::from(byte)
                    .checked_shl(shift)
                    .ok_or(OmissionReason::FieldOutOfBounds)?;
            }
        }
    }
    Ok((None, Value::Unsigned { value }, field.offset, width))
}

struct ParsedLabel {
    index: usize,
    offset: usize,
    bytes: Vec<u8>,
}

pub(super) fn extract_dns_labels(
    builder: &mut Builder,
    rule: &Rule,
    name_offset: usize,
    ascii_case_fold: bool,
    samples: &[Sample<'_>],
    resolved: &[ResolvedSample],
) -> Result<(), CarrierError> {
    for (sample, data) in samples.iter().zip(resolved) {
        let labels = match parse_dns_labels(&data.bytes, name_offset) {
            Ok(labels) => labels,
            Err(reason) => {
                builder.omit(Some(sample.id), rule, reason);
                continue;
            }
        };
        if labels.is_empty() {
            builder.omit(Some(sample.id), rule, OmissionReason::EmptyDnsName);
            continue;
        }
        for label in labels {
            let comparison = if ascii_case_fold {
                label.bytes.iter().map(u8::to_ascii_lowercase).collect()
            } else {
                label.bytes.clone()
            };
            let ranges = sample_ranges(sample, label.offset, label.bytes.len())?;
            builder.observe(ObservationDraft {
                sample_ids: vec![sample.id],
                event_id: data.event_id.clone(),
                rule: rule.clone(),
                component_index: Some(label.index),
                value: Value::DnsLabel {
                    raw: label.bytes,
                    comparison,
                },
                ranges,
                ambiguity: data.ambiguity,
            });
        }
    }
    Ok(())
}

fn parse_dns_labels(bytes: &[u8], offset: usize) -> Result<Vec<ParsedLabel>, OmissionReason> {
    let mut cursor = offset;
    let mut consumed = 0_usize;
    let mut labels = Vec::new();
    while consumed < DNS_MAX_NAME_BYTES {
        let length = bytes
            .get(cursor)
            .copied()
            .ok_or(OmissionReason::InvalidDnsName)?;
        if length == 0 {
            return Ok(labels);
        }
        // A compression pointer can refer outside these verified sample bytes
        if length & 0xc0 == 0xc0 {
            return Err(OmissionReason::CompressedDnsName);
        }
        if length & 0xc0 != 0 || usize::from(length) > DNS_MAX_LABEL_BYTES {
            return Err(OmissionReason::InvalidDnsName);
        }
        if labels.len() == DNS_MAX_LABELS {
            return Err(OmissionReason::InvalidDnsName);
        }
        let label_start = cursor
            .checked_add(1)
            .ok_or(OmissionReason::InvalidDnsName)?;
        let label_end = label_start
            .checked_add(usize::from(length))
            .ok_or(OmissionReason::InvalidDnsName)?;
        let consumed_next = consumed
            .checked_add(label_end - cursor)
            .ok_or(OmissionReason::InvalidDnsName)?;
        if consumed_next > DNS_MAX_NAME_BYTES {
            return Err(OmissionReason::InvalidDnsName);
        }
        let label = bytes
            .get(label_start..label_end)
            .ok_or(OmissionReason::InvalidDnsName)?;
        labels.push(ParsedLabel {
            index: labels.len(),
            offset: label_start,
            bytes: label.to_vec(),
        });
        cursor = label_end;
        consumed = consumed_next;
    }
    Err(OmissionReason::InvalidDnsName)
}
