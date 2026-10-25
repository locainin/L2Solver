//! Bounded, endian-aware PCAPNG option parsing

use crate::header::ByteOrder;
use crate::{Error, pcapng_model::PcapNgOption};

const MAX_OPTIONS: u32 = 128;

#[derive(Clone, Copy)]
pub enum OptionScope {
    Section,
    Interface,
    PacketBlock,
    EnhancedPacket,
}

#[derive(Clone, Copy)]
struct OptionRule {
    exact_length: Option<usize>,
    minimum_length: Option<usize>,
    repeatable: bool,
}

struct OptionSpan {
    code: u16,
    length: usize,
    option_end: usize,
    value_end: usize,
    value_start: usize,
}

pub fn parse_options(
    block_type: u32,
    bytes: &[u8],
    scope: OptionScope,
    order: ByteOrder,
) -> Result<Vec<PcapNgOption>, Error> {
    let mut cursor = 0;
    let mut option_count: u32 = 0;
    let mut seen_known = Vec::new();
    let mut output = Vec::new();
    // Count headers before retaining values so empty options still consume the budget
    while cursor < bytes.len() {
        option_count += 1;
        if option_count > MAX_OPTIONS {
            return Err(Error::OptionLimitExceeded { limit: MAX_OPTIONS });
        }
        let span = option_span(bytes, cursor, order)?;
        // The terminator must be final and has its own duplicate rule
        if span.code == 0 {
            validate_terminator(block_type, bytes.len(), &span, &mut seen_known)?;
            break;
        }
        validate_known_option(
            block_type,
            &span,
            option_rule(span.code, scope),
            &mut seen_known,
        )?;
        output.push(PcapNgOption {
            code: span.code,
            value: bytes
                .get(span.value_start..span.value_end)
                .ok_or(Error::InvalidHeaderLayout)?
                .to_vec(),
        });
        cursor = span.option_end;
    }
    Ok(output)
}

fn option_span(bytes: &[u8], cursor: usize, order: ByteOrder) -> Result<OptionSpan, Error> {
    let header_end = cursor.checked_add(4).ok_or(Error::InvalidHeaderLayout)?;
    if header_end > bytes.len() {
        return Err(Error::UnexpectedEof {
            section: "PCAPNG option header",
            expected: header_end,
            received: bytes.len(),
        });
    }
    let code = read_u16(bytes, cursor, order)?;
    let length = usize::from(read_u16(bytes, cursor + 2, order)?);
    // Advertised and aligned lengths are checked independently
    let value_end = header_end
        .checked_add(length)
        .ok_or(Error::InvalidHeaderLayout)?;
    let option_end = header_end
        .checked_add(padded_length(length)?)
        .ok_or(Error::InvalidHeaderLayout)?;
    if option_end > bytes.len() {
        return Err(Error::UnexpectedEof {
            section: "PCAPNG option value",
            expected: option_end,
            received: bytes.len(),
        });
    }
    // Padding is bounded independently from the retained option value
    let _padding = bytes
        .get(value_end..option_end)
        .ok_or(Error::InvalidHeaderLayout)?;
    Ok(OptionSpan {
        code,
        length,
        option_end,
        value_end,
        value_start: header_end,
    })
}

fn validate_terminator(
    block_type: u32,
    input_length: usize,
    span: &OptionSpan,
    seen_known: &mut Vec<u16>,
) -> Result<(), Error> {
    if span.length != 0 {
        return Err(Error::InvalidOptionLength {
            block_type,
            code: span.code,
            length: span.length,
            expected: Some(0),
            minimum: None,
        });
    }
    if seen_known.contains(&span.code) {
        return Err(Error::DuplicateOption {
            block_type,
            code: span.code,
        });
    }
    seen_known.push(span.code);
    if span.option_end != input_length {
        return Err(Error::OptionAfterTerminator { block_type });
    }
    Ok(())
}

fn validate_known_option(
    block_type: u32,
    span: &OptionSpan,
    rule: Option<OptionRule>,
    seen_known: &mut Vec<u16>,
) -> Result<(), Error> {
    // Unknown options remain evidence while known options receive semantic checks
    let Some(rule) = rule else {
        return Ok(());
    };
    if seen_known.contains(&span.code) && !rule.repeatable {
        return Err(Error::DuplicateOption {
            block_type,
            code: span.code,
        });
    }
    if let Some(expected) = rule.exact_length
        && span.length != expected
    {
        return Err(Error::InvalidOptionLength {
            block_type,
            code: span.code,
            length: span.length,
            expected: Some(expected),
            minimum: None,
        });
    }
    if let Some(minimum) = rule.minimum_length
        && span.length < minimum
    {
        return Err(Error::InvalidOptionLength {
            block_type,
            code: span.code,
            length: span.length,
            expected: None,
            minimum: Some(minimum),
        });
    }
    seen_known.push(span.code);
    Ok(())
}

pub fn is_known_option(code: u16, scope: OptionScope) -> bool {
    option_rule(code, scope).is_some()
}

fn option_rule(code: u16, scope: OptionScope) -> Option<OptionRule> {
    // Common option codes keep the same meaning in every supported block
    let common = match code {
        1 => Some(OptionRule {
            exact_length: None,
            minimum_length: None,
            repeatable: true,
        }),
        2988 | 2989 | 19372 | 19373 => Some(OptionRule {
            exact_length: None,
            minimum_length: Some(4),
            repeatable: true,
        }),
        _ => None,
    };
    common.or_else(|| match scope {
        OptionScope::Section => section_rule(code),
        OptionScope::Interface => interface_rule(code),
        OptionScope::PacketBlock => packet_block_rule(code),
        OptionScope::EnhancedPacket => enhanced_packet_rule(code),
    })
}

const fn section_rule(code: u16) -> Option<OptionRule> {
    match code {
        2..=4 => Some(OptionRule {
            exact_length: None,
            minimum_length: None,
            repeatable: false,
        }),
        _ => None,
    }
}

const fn interface_rule(code: u16) -> Option<OptionRule> {
    match code {
        2 | 3 | 12 | 15 | 18 => Some(OptionRule {
            exact_length: None,
            minimum_length: None,
            repeatable: false,
        }),
        4 => Some(OptionRule {
            exact_length: Some(8),
            minimum_length: None,
            repeatable: true,
        }),
        5 => Some(OptionRule {
            exact_length: Some(17),
            minimum_length: None,
            repeatable: true,
        }),
        6 => Some(OptionRule {
            exact_length: Some(6),
            minimum_length: None,
            repeatable: false,
        }),
        7 | 8 | 14 | 16 | 17 => Some(OptionRule {
            exact_length: Some(8),
            minimum_length: None,
            repeatable: false,
        }),
        9 | 13 => Some(OptionRule {
            exact_length: Some(1),
            minimum_length: None,
            repeatable: false,
        }),
        10 => Some(OptionRule {
            exact_length: Some(4),
            minimum_length: None,
            repeatable: false,
        }),
        11 => Some(OptionRule {
            exact_length: None,
            minimum_length: Some(1),
            repeatable: false,
        }),
        _ => None,
    }
}

const fn packet_block_rule(code: u16) -> Option<OptionRule> {
    match code {
        2 => Some(OptionRule {
            exact_length: Some(4),
            minimum_length: None,
            repeatable: false,
        }),
        3 => Some(OptionRule {
            exact_length: None,
            minimum_length: Some(1),
            repeatable: true,
        }),
        _ => None,
    }
}

const fn enhanced_packet_rule(code: u16) -> Option<OptionRule> {
    match code {
        2 | 6 => Some(OptionRule {
            exact_length: Some(4),
            minimum_length: None,
            repeatable: false,
        }),
        3 | 7 => Some(OptionRule {
            exact_length: None,
            minimum_length: Some(1),
            repeatable: true,
        }),
        4 | 5 | 8 => Some(OptionRule {
            exact_length: Some(8),
            minimum_length: None,
            repeatable: false,
        }),
        _ => None,
    }
}

fn padded_length(length: usize) -> Result<usize, Error> {
    // PCAPNG aligns options to four bytes without trusting wraparound
    length
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or_else(|| Error::LengthOverflow {
            length: u32::try_from(length).unwrap_or(u32::MAX),
        })
}

fn read_u16(bytes: &[u8], offset: usize, order: ByteOrder) -> Result<u16, Error> {
    let source = bytes
        .get(offset..offset + 2)
        .ok_or(Error::InvalidHeaderLayout)?;
    let value: [u8; 2] = source.try_into().map_err(|_| Error::InvalidHeaderLayout)?;
    Ok(match order {
        ByteOrder::Little => u16::from_le_bytes(value),
        ByteOrder::Big => u16::from_be_bytes(value),
    })
}
